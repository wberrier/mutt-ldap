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

from setuptools import setup
import os

with open(os.path.join(os.path.dirname(__file__), "README.rst"), encoding="utf-8") as f:
    readme = f.read()

setup(
    name="mutt-ldap",
    maintainer="W. Trevor King",
    maintainer_email="wking@tremily.us",
    url='http://blog.tremily.us/posts/mutt-ldap/',
    download_url = f"https://github.com/wberrier/mutt-ldap/archive/refs/tags/v{_mutt_ldap.__version__}.tar.gz"
    license="GNU General Public License (GPL)",
    description="A tool to query an LDAP server for email addresses and names, suitable for use with Mutt.",
    long_description=readme,
    long_description_content_type="text/rst",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: End Users/Desktop",
        "Operating System :: OS Independent",
        "License :: OSI Approved :: GNU General Public License (GPL)",
        "License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)",
        "Programming Language :: Python :: 3",
        "Topic :: Communications :: Email",
    ],
    platforms=['all'],
    packages=[],
    scripts=["mutt_ldap.py"],
    py_modules=["mutt_ldap"],
    install_requires=[
        "python-ldap>=3.0",
    ],
)
