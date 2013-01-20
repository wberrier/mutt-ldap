# Copyright (C) 2013 W. Trevor King <wking@tremily.us>
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

from distutils.core import setup as _setup
import os.path as _os_path

import mutt_ldap as _mutt_ldap


_this_dir = _os_path.dirname(__file__)

_setup(
    name='mutt-ldap',
    version=_mutt_ldap.__version__,
    maintainer='W. Trevor King',
    maintainer_email='wking@tremily.us',
    url='http://blog.tremily.us/posts/mutt-ldap/',
    download_url='http://git.tremily.us/?p=mutt-ldap.git;a=snapshot;h=v{};sf=tgz'.format(_mutt_ldap.__version__),
    license = 'GNU General Public License (GPL)',
    platforms = ['all'],
    description = _mutt_ldap.__doc__.splitlines()[0],
    long_description=open(_os_path.join(_this_dir, 'README'), 'r').read(),
    classifiers = [
        'Development Status :: 3 - Alpha',
        'Intended Audience :: End Users/Desktop',
        'Operating System :: OS Independent',
        'License :: OSI Approved :: GNU General Public License (GPL)',
        'License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Topic :: Communications :: Email',
        ],
    py_modules = ['mutt_ldap'],
    scripts = ['mutt_ldap.py'],
    )
