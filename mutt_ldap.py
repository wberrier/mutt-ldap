#!/usr/bin/env python2
#
# Copyright (C) 2008-2013  W. Trevor King
# Copyright (C) 2012-2013  Wade Berrier
# Copyright (C) 2012       Niels de Vos
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

"LDAP address searches for Mutt"

import ConfigParser as _configparser
import hashlib as _hashlib
import json as _json
import logging as _logging
import os.path as _os_path
import pickle as _pickle
import time as _time

import ldap as _ldap
import ldap.sasl as _ldap_sasl


__version__ = '0.1'


LOG = _logging.getLogger('mutt-ldap')
LOG.addHandler(_logging.StreamHandler())
LOG.setLevel(_logging.ERROR)

CONFIG = _configparser.SafeConfigParser()
CONFIG.add_section('connection')
CONFIG.set('connection', 'server', 'domaincontroller.yourdomain.com')
CONFIG.set('connection', 'port', '389')  # set to 636 for default over SSL
CONFIG.set('connection', 'ssl', 'no')
CONFIG.set('connection', 'starttls', 'no')
CONFIG.set('connection', 'basedn', 'ou=x co.,dc=example,dc=net')
CONFIG.add_section('auth')
CONFIG.set('auth', 'user', '')
CONFIG.set('auth', 'password', '')
CONFIG.set('auth', 'gssapi', 'no')
CONFIG.add_section('query')
CONFIG.set('query', 'filter', '') # only match entries according to this filter
CONFIG.set('query', 'search-fields', 'cn displayName uid mail') # fields to wildcard search
CONFIG.add_section('results')
CONFIG.set('results', 'optional-column', '') # mutt can display one optional column
CONFIG.add_section('cache')
CONFIG.set('cache', 'enable', 'yes') # enable caching by default
CONFIG.set('cache', 'path', '~/.mutt-ldap.cache') # cache results here
CONFIG.set('cache', 'fields', '')  # fields to cache (if empty, setup in the main block)
CONFIG.set('cache', 'longevity-days', '14') # TODO: cache results for 14 days by default
CONFIG.add_section('system')
# HACK: Python 2.x support, see http://bugs.python.org/issue2128
CONFIG.set('system', 'argv-encoding', 'utf-8')

CONFIG.read(_os_path.expanduser('~/.mutt-ldap.rc'))


class LDAPConnection (object):
    """Wrap an LDAP connection supporting the 'with' statement

    See PEP 343 for details.
    """
    def __init__(self, config=None):
        if config is None:
            config = CONFIG
        self.config = config
        self.connection = None

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, type, value, traceback):
        self.unbind()

    def connect(self):
        if self.connection is not None:
            raise RuntimeError('already connected to the LDAP server')
        protocol = 'ldap'
        if self.config.getboolean('connection', 'ssl'):
            protocol = 'ldaps'
        url = '{0}://{1}:{2}'.format(
            protocol,
            self.config.get('connection', 'server'),
            self.config.get('connection', 'port'))
        LOG.info(u'connect to LDAP server at {0}'.format(url))
        self.connection = _ldap.initialize(url)
        if (self.config.getboolean('connection', 'starttls') and
                protocol == 'ldap'):
            self.connection.start_tls_s()
        if self.config.getboolean('auth', 'gssapi'):
            sasl = _ldap_sasl.gssapi()
            self.connection.sasl_interactive_bind_s('', sasl)
        else:
            self.connection.bind(
                self.config.get('auth', 'user'),
                self.config.get('auth', 'password'),
                _ldap.AUTH_SIMPLE)

    def unbind(self):
        if self.connection is None:
            raise RuntimeError('not connected to an LDAP server')
        LOG.info(u'unbind from LDAP server')
        self.connection.unbind()
        self.connection = None

    def search(self, query):
        if self.connection is None:
            raise RuntimeError('connect to the LDAP server before searching')
        post = u''
        if query:
            post = u'*'
        fields = self.config.get('query', 'search-fields').split()
        filterstr = u'(|{0})'.format(
            u' '.join([u'({0}=*{1}{2})'.format(field, query, post) for
                       field in fields]))
        query_filter = self.config.get('query', 'filter')
        if query_filter:
            filterstr = u'(&({0}){1})'.format(query_filter, filterstr)
        LOG.info(u'search for {0}'.format(filterstr))
        msg_id = self.connection.search(
            self.config.get('connection', 'basedn'),
            _ldap.SCOPE_SUBTREE,
            filterstr.encode('utf-8'))
        res_type = None
        while res_type != _ldap.RES_SEARCH_RESULT:
            try:
                res_type, res_data = self.connection.result(
                    msg_id, all=False, timeout=0)
            except _ldap.ADMINLIMIT_EXCEEDED as e:
                LOG.warn(u'could not handle query results: {0}'.format(e))
                break
            if res_data:
                # use `yield from res_data` in Python >= 3.3, see PEP 380
                for entry in res_data:
                    yield entry


class CachedLDAPConnection (LDAPConnection):
    _cache_version = '{0}.0'.format(__version__)

    def connect(self):
        # delay LDAP connection until we actually need it
        self._load_cache()

    def unbind(self):
        if self.connection:
            super(CachedLDAPConnection, self).unbind()
        if self._cache:
            self._save_cache()

    def search(self, query):
        cache_hit, entries = self._cache_lookup(query=query)
        if cache_hit:
            LOG.info(u'return cached entries for {0}'.format(query))
            # use `yield from res_data` in Python >= 3.3, see PEP 380
            for entry in entries:
                yield entry
        else:
            if self.connection is None:
                super(CachedLDAPConnection, self).connect()
            entries = []
            keys = self.config.get('cache', 'fields').split()
            for entry in super(CachedLDAPConnection, self).search(query=query):
                cn,data = entry
                # use dict comprehensions in Python >= 2.7, see PEP 274
                cached_data = dict(
                    [(key, data[key]) for key in keys if key in data])
                entries.append((cn, cached_data))
                yield entry
            self._cache_store(query=query, entries=entries)

    def _load_cache(self):
        path = _os_path.expanduser(self.config.get('cache', 'path'))
        LOG.info(u'load cache from {0}'.format(path))
        self._cache = {}
        try:
            data = _json.load(open(path, 'rb'))
        except IOError as e:  # probably "No such file"
            LOG.warn(u'error reading cache: {0}'.format(e))
        except (ValueError, KeyError) as e:  # probably a corrupt cache file
            LOG.warn(u'error parsing cache: {0}'.format(e))
        else:
            version = data.get('version', None)
            if version == self._cache_version:
                self._cache = data.get('queries', {})
            else:
                LOG.debug(u'drop outdated local cache {0} != {1}'.format(
                        version, self._cache_version))
        self._cull_cache()

    def _save_cache(self):
        path = _os_path.expanduser(self.config.get('cache', 'path'))
        LOG.info(u'save cache to {0}'.format(path))
        data = {
            'queries': self._cache,
            'version': self._cache_version,
            }
        with open(path, 'wb') as f:
            _json.dump(data, f, indent=2, separators=(',', ': '))
            f.write('\n'.encode('utf-8'))

    def _cache_store(self, query, entries):
        self._cache[self._cache_key(query=query)] = {
            'entries': entries,
            'time': _time.time(),
            }

    def _cache_lookup(self, query):
        data = self._cache.get(self._cache_key(query=query), None)
        if data is None:
            return (False, data)
        return (True, data['entries'])

    def _cache_key(self, query):
        return str((self._config_id(), query))

    def _config_id(self):
        """Return a unique ID representing the current configuration
        """
        config_string = _pickle.dumps(self.config)
        return _hashlib.sha1(config_string).hexdigest()

    def _cull_cache(self):
        cull_days = self.config.getint('cache', 'longevity-days')
        day_seconds = 24*60*60
        expire = _time.time() - cull_days * day_seconds
        for key in list(self._cache.keys()):  # cull the cache
            if self._cache[key]['time'] < expire:
                LOG.debug('cull entry from cache: {0}'.format(key))
                self._cache.pop(key)


def _decode_query_data(obj):
    if isinstance(obj, unicode):  # e.g. cached JSON data
        return obj
    return unicode(obj, 'utf-8')

def format_columns(address, data):
    yield _decode_query_data(address)
    yield _decode_query_data(data.get('displayName', data['cn'])[-1])
    optional_column = CONFIG.get('results', 'optional-column')
    if optional_column in data:
        yield _decode_query_data(data[optional_column][-1])

def format_entry(entry):
    cn,data = entry
    if 'mail' in data:
        for m in data['mail']:
            # http://www.mutt.org/doc/manual/manual-4.html#ss4.5
            # Describes the format mutt expects: address\tname
            yield u'\t'.join(format_columns(m, data))


if __name__ == '__main__':
    import sys

    # HACK: convert sys.argv to Unicode (not needed in Python 3)
    argv_encoding = CONFIG.get('system', 'argv-encoding')
    sys.argv = [unicode(arg, argv_encoding) for arg in sys.argv]

    if len(sys.argv) < 2:
        sys.stderr.write(u'{0}: no search string given\n'.format(sys.argv[0]))
        sys.exit(1)

    query = u' '.join(sys.argv[1:])

    if CONFIG.getboolean('cache', 'enable'):
        connection_class = CachedLDAPConnection
        if not CONFIG.get('cache', 'fields'):
            # setup a reasonable default
            fields = ['mail', 'cn', 'displayName']  # used by format_entry()
            optional_column = CONFIG.get('results', 'optional-column')
            if optional_column:
                fields.append(optional_column)
            CONFIG.set('cache', 'fields', ' '.join(fields))
    else:
        connection_class = LDAPConnection

    addresses = []
    with connection_class() as connection:
        entries = connection.search(query=query)
        for entry in entries:
            addresses.extend(format_entry(entry))
    print(u'{0} addresses found:'.format(len(addresses)))
    print(u'\n'.join(addresses))
