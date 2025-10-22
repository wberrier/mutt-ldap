#!/usr/bin/env python3
#
# Copyright (C) 2008-2013  W. Trevor King
# Copyright (C) 2012-2024  Wade Berrier
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

import argparse
import configparser as _configparser
import hashlib as _hashlib
import json as _json
import locale as _locale
import logging as _logging
import os as _os
import os.path as _os_path
import subprocess
import pickle as _pickle
import sys as _sys
import textwrap
import time as _time

import ldap as _ldap
import ldap.sasl as _ldap_sasl

_xdg_import_error = None
try:
    import xdg.BaseDirectory as _xdg_basedirectory
except ImportError as _xdg_import_error:
    _xdg_basedirectory = None


__version__ = '0.1'


LOG = _logging.getLogger('mutt-ldap')
LOG.addHandler(_logging.StreamHandler())
LOG.setLevel(_logging.ERROR)


class Config (_configparser.ConfigParser):
    def load(self, config_path):
        self.read_config_paths = self.read(self._get_config_paths(config_path))
        LOG.info(f'load configuration from {self.read_config_paths}')
        self._setup_defaults()

        # Check for an authorization file and load if found
        self.auth_config = None
        auth_file = self.get('auth', 'file', fallback="")
        if auth_file:
            self.auth_config = _configparser.ConfigParser()
            LOG.info(f'loading authorization file: {auth_file}')
            self.auth_config.read(auth_file)

    def get_connection_class(self):
        return CachedLDAPConnection if self.getboolean('cache', 'enable') else LDAPConnection

    def get_username(self):
        return self.auth_config.get('auth', 'user') if self.auth_config else self.get('auth', 'user')

    def get_password(self):
        # First, try to get the password command
        password_cmd = self.auth_config.get('auth', 'password-cmd', fallback=None) if self.auth_config else self.get('auth', 'password-cmd', fallback=None)
        # If a password command is provided, try to execute it to get the password
        if password_cmd:
            try:
                result = subprocess.run(password_cmd.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
                return result.stdout.strip()
            except subprocess.CalledProcessError as e:
                print(f"An error occurred while executing the password command: {e}")

        # If password command is not provided or fails, fall back to password
        return self.auth_config.get('auth', 'password') if self.auth_config else self.get('auth', 'password')

    def _setup_defaults(self):
        default_encoding = _locale.getpreferredencoding(do_setlocale=True)
        for key in ['output-encoding', 'argv-encoding']:
            self.set('system', key, self.get('system', key, fallback=default_encoding))
        if not self.get('cache', 'path'):
            self.set('cache', 'path', self._get_cache_path())
        if not self.get('cache', 'fields'):
            # setup a reasonable default
            fields = ['mail', 'cn', 'displayName']  # used by format_entry()
            optional_column = self.get('results', 'optional-column', fallback="")
            if optional_column:
                fields.append(optional_column)
            self.set('cache', 'fields', ' '.join(fields))

    def _get_config_paths(self, config_path):
        "Get configuration file paths"
        if config_path:
            return [config_path]
        paths = [_xdg_basedirectory.save_config_path('')] if _xdg_basedirectory else [_os_path.expanduser(_os_path.join('~', '.config'))]
        return [_os_path.join(path, 'mutt-ldap.cfg') for path in paths]

    def _get_cache_path(self):
        "Get the cache file path"

        # Some versions of pyxdg don't have save_cache_path (0.20 and older)
        # See: https://bugs.freedesktop.org/show_bug.cgi?id=26458
        if _xdg_basedirectory and hasattr(_xdg_basedirectory, 'save_cache_path'):
            path = _xdg_basedirectory.save_cache_path('')
        else:
            self._log_xdg_import_error()
            path = _os_path.expanduser(_os_path.join('~', '.cache'))
            if not _os_path.isdir(path):
                _os.makedirs(path)
        return _os_path.join(path, 'mutt-ldap.json')

    def _log_xdg_import_error(self):
        global _xdg_import_error
        if _xdg_import_error:
            LOG.warning('could not import xdg.BaseDirectory '
                'or lacking necessary support')
            LOG.warning(_xdg_import_error)
            _xdg_import_error = None


CONFIG = Config()
CONFIG.add_section('connection')
CONFIG.set('connection', 'server', 'domaincontroller.yourdomain.com')
CONFIG.set('connection', 'port', '389')  # set to 636 for default over SSL
CONFIG.set('connection', 'ssl', 'no')
CONFIG.set('connection', 'starttls', 'no')
CONFIG.set('connection', 'basedn', 'ou=x co.,dc=example,dc=net')
CONFIG.add_section('auth')
CONFIG.set('auth', 'user', '')
CONFIG.set('auth', 'password', '')
CONFIG.set('auth', 'file', '')
CONFIG.set('auth', 'gssapi', 'no')
CONFIG.add_section('query')
CONFIG.set('query', 'filter', '')  # only match entries according to this filter
CONFIG.set('query', 'search-fields', 'cn displayName uid mail')  # fields to wildcard search
CONFIG.add_section('results')
CONFIG.set('results', 'optional-column', '')  # mutt can display one optional column
CONFIG.add_section('cache')
CONFIG.set('cache', 'enable', 'yes')  # enable caching by default
CONFIG.set('cache', 'path', '')  # cache results here, defaults to XDG
CONFIG.set('cache', 'fields', '')  # fields to cache (if empty, setup in the main block)
CONFIG.set('cache', 'longevity-days', '14')  # Days before cache entries are invalidated
CONFIG.add_section('system')
# HACK: Python 2.x support, see http://bugs.python.org/issue13329#msg147475
CONFIG.set('system', 'output-encoding', '')  # match .muttrc's $charset
# HACK: Python 2.x support, see http://bugs.python.org/issue2128
CONFIG.set('system', 'argv-encoding', '')


class LDAPConnection:
    """Wrap an LDAP connection supporting the 'with' statement

    See PEP 343 for details.
    """
    def __init__(self, config=None):
        self.config = config or CONFIG
        self.connection = None

    # Establish LDAP connection
    def __enter__(self):
        self.connect()
        return self

    # Unbind from LDAP server
    def __exit__(self, type, value, traceback):
        self.unbind()

    # Connect to LDAP server
    def connect(self):
        if self.connection is not None:
            raise RuntimeError('Already connected to the LDAP server')
        protocol = 'ldaps' if self.config.getboolean('connection', 'ssl') else 'ldap'
        url = f"{protocol}://{self.config.get('connection', 'server')}:{self.config.get('connection', 'port')}"
        LOG.info(f'connect to LDAP server at {url}')
        self.connection = _ldap.initialize(url)
        if self.config.getboolean('connection', 'starttls') and protocol == 'ldap':
            self.connection.start_tls_s()
        if self.config.getboolean('auth', 'gssapi'):
            sasl = _ldap_sasl.gssapi()
            self.connection.sasl_interactive_bind_s('', sasl)
        else:
            self.connection.bind(self.config.get_username(), self.config.get_password(), _ldap.AUTH_SIMPLE)

    def unbind(self):
        if self.connection is None:
            raise RuntimeError('Not connected to an LDAP server')
        LOG.info('unbind from LDAP server')
        self.connection.unbind()
        self.connection = None

    def search(self, query):
        if self.connection is None:
            raise RuntimeError('Connect to the LDAP server before searching')
        post = '*' if query else ''
        fields = self.config.get('query', 'search-fields').split()
        filterstr = '(|{})'.format(' '.join([f'({field}=*{query}{post})' for field in fields]))
        query_filter = self.config.get('query', 'filter')
        if query_filter:
            filterstr = f'(&({query_filter}){filterstr})'
        LOG.info(f'Searching for {filterstr}')
        msg_id = self.connection.search(self.config.get('connection', 'basedn'), _ldap.SCOPE_SUBTREE, filterstr)
        res_type = None
        while res_type != _ldap.RES_SEARCH_RESULT:
            try:
                res_type, res_data = self.connection.result(msg_id, all=False, timeout=0)
            except _ldap.ADMINLIMIT_EXCEEDED as e:
                LOG.warning(f'Could not handle query results: {e}')
                break
            if res_data:
                # use `yield from res_data` in Python >= 3.3, see PEP 380
                for entry in res_data:
                    yield self._stringify_entry(entry)

    # Convert LDAP entry to string
    def _stringify_entry(self, entry):
        cn, data = entry
        return cn, {k: [item.decode('utf-8') for item in v] for k, v in data.items()}


class CachedLDAPConnection (LDAPConnection):
    _cache_version = f'{__version__}.0'

    # Connect to LDAP server with caching
    def connect(self):
        # delay LDAP connection until we actually need it
        self._load_cache()

    # Unbind from LDAP server and save cache
    def unbind(self):
        if self.connection:
            super().unbind()
        if self._cache:
            self._save_cache()

    # Search LDAP with cache support
    def search(self, query):
        cache_hit, entries = self._cache_lookup(query=query)
        if cache_hit:
            LOG.info(f'Returning cached entries for {query}')
            # use `yield from res_data` in Python >= 3.3, see PEP 380
            for entry in entries:
                yield entry
        else:
            if not self.connection:
                super().connect()
            entries = []
            keys = self.config.get('cache', 'fields').split()
            for entry in super().search(query):
                cn, data = entry
                # use dict comprehensions in Python >= 2.7, see PEP 274
                cached_data = {key: data[key] for key in keys if key in data}
                entries.append((cn, cached_data))
                yield entry
            self._cache_store(query=query, entries=entries)

    # Load cache from file
    def _load_cache(self):
        path = _os_path.expanduser(self.config.get('cache', 'path'))
        LOG.info(f'load cache from {path}')
        self._cache = {}
        try:
            with open(path, encoding=_locale.getpreferredencoding(False)) as f:
                data = _json.load(f)
        except OSError as e:  # probably "No such file"
            LOG.warning(f'Error reading cache: {e}')
        except (ValueError, KeyError) as e:  # probably a corrupt cache file
            LOG.warning(f'Error parsing cache: {e}')
        else:
            if data.get('version') == self._cache_version:
                self._cache = data.get('queries', {})
            else:
                LOG.debug(f'Dropping outdated local cache {data.get("version")} != {self._cache_version}')
        self._cull_cache()

    # Save cache to file
    def _save_cache(self):
        path = _os_path.expanduser(self.config.get('cache', 'path'))
        LOG.info(f'save cache to {path}')
        data = {'queries': self._cache, 'version': self._cache_version}
        with open(path, 'w', encoding=_locale.getpreferredencoding(False)) as f:
            _json.dump(data, f, indent=2, separators=(',', ': '))
            f.write('\n')

    def _cache_store(self, query, entries):
        self._cache[self._cache_key(query)] = {'entries': entries, 'time': _time.time()}

    def _cache_lookup(self, query):
        data = self._cache.get(self._cache_key(query=query), None)
        return (True, data['entries']) if data else (False, None)

    def _cache_key(self, query):
        return str((self._config_id(), query))

    def _config_id(self):
        """Return a unique ID representing the current configuration
        """
        return _hashlib.sha1(_pickle.dumps(self.config)).hexdigest()

    def _cull_cache(self):
        cull_days = self.config.getint('cache', 'longevity-days')
        expire = _time.time() - cull_days * 24 * 60 * 60
        self._cache = {k: v for k, v in self._cache.items() if v['time'] >= expire}


# Format the output columns for Mutt
def format_columns(address, data):
    yield address
    yield data.get('displayName', data['cn'])[-1]
    optional_column = CONFIG.get('results', 'optional-column')
    if optional_column in data:
        yield data[optional_column][-1]


# Format LDAP entry for Mutt
def format_entry(entry):
    cn, data = entry
    if 'mail' in data:
        for m in data['mail']:
            # http://www.mutt.org/doc/manual/manual-4.html#ss4.5
            # Describes the format mutt expects: address\tname
            yield '\t'.join(format_columns(m, data))


def main():
    parser = argparse.ArgumentParser(
        prog='mutt_ldap',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent('''\
            LDAP address searches for Mutt
            --------------------------------
            This script provides an interface to perform LDAP searches
            for email addresses and contact information, formatted
            specifically for use with the Mutt email client.
        '''),
        epilog=textwrap.dedent('''\
            License: GPL-3.0-or-later
            Repository: https://github.com/wberrier/mutt-ldap
            Authors: W. Trevor King, Wade Berrier, Niels de Vos
        ''')
    )
    parser.add_argument('--version', action='version', version=__version__)
    parser.add_argument('query', nargs='+', help='Search query for the LDAP directory')
    parser.add_argument('--config', help='Path to the configuration file')
    parser.add_argument('--verbose', action='store_true', help='Increase output verbosity')
    args = parser.parse_args()

    # Configuration loading and LDAP search logic:
    CONFIG.load(args.config)

    query = ' '.join(args.query)

    connection_class = CONFIG.get_connection_class()
    addresses = []
    with connection_class(CONFIG) as connection:
        entries = connection.search(query)
        for entry in entries:
            addresses.extend(format_entry(entry))
    print(f'{len(addresses)} addresses found:')
    print('\n'.join(addresses))

    if args.verbose:
        print(f"Search query: {query}")


if __name__ == '__main__':
    main()
