#
# This file is part of Bluepass. Bluepass is Copyright (c) 2012-2013
# Geert Jansen.
#
# Bluepass is free software available under the GNU General Public License,
# version 3. See the file LICENSE distributed with this file for the exact
# licensing terms.

from __future__ import absolute_import, print_function

import os
import sys
import stat
import json
import tempfile
import textwrap
import subprocess

from distutils import dir_util
from setuptools import setup, Extension

# CFFI is needed to call setup() and therefore it needs to be installed before
# this setup script can be run.

try:
    import cffi
except ImportError:
    sys.stderr.write('Error: CFFI (required for setup) is not available.\n')
    sys.stderr.write('Please use "pip install cffi", or equivalent.\n')
    sys.exit(1)

version_info = {
    'name': 'bluepass',
    'version': '0.9.dev',
    'description': 'The Bluepass password manager.',
    'author': 'Geert Jansen',
    'author_email': 'geertj@gmail.com',
    'url': 'http://github.com/geertj/bluepass',
    'license': 'GPLv3',
    'classifiers': [
        'Development Status :: 3 - Alpha',
        'Environment :: X11 Applications :: Qt',
        'Intended Audience :: End Users/Desktop',
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
        'Operating System :: MacOS :: MacOS X',
        'Operating System :: POSIX',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.3',
        'Topic :: Security',
        'Topic :: Utilities'
    ],
}

topdir, _ = os.path.split(os.path.abspath(__file__))


def update_version():
    """Update the _version.py file."""
    fname = os.path.join('bluepass', '_version.py')
    try:
        with open(fname) as fin:
            current = fin.read()
    except IOError:
        current = None
    new = textwrap.dedent("""\
            # This file is autogenerated. Do not edit.
            version_info = {0}
            """.format(json.dumps(version_info)))
    if current == new:
        return
    tmpname = '{0}.{1}-tmp'.format(fname, os.getpid())
    with open(tmpname, 'w') as fout:
        fout.write(new)
    os.rename(tmpname, fname)
    print('updated _version.py')


def update_manifest():
    """Update the MANIFEST.in file from git, if necessary."""
    # It would be more efficient to create MANIFEST directly, rather
    # than creating a MANIFEST.in where every line just includes one file.
    # Unfortunately, setuptools/distribute do not support this (distutils
    # does).
    gitdir = '.git'
    try:
        st = os.stat(gitdir)
    except OSError:
        return
    cmd = subprocess.Popen(['git', 'ls-tree', '-r', 'master', '--name-only'],
                           stdout=subprocess.PIPE)
    stdout, _ = cmd.communicate()
    files = stdout.decode('ascii').splitlines()
    files.append('bluepass/_version.py')
    lines = ['include {0}\n'.format(fname) for fname in files]
    new = ''.join(sorted(lines))
    try:
        with open('MANIFEST.in', 'r') as fin:
            current = fin.read()
    except IOError:
        current = None
    if new == current:
        return
    tmpname = 'MANIFEST.in.{0}-tmp'.format(os.getpid())
    with open(tmpname, 'w') as fout:
        fout.write(new)
    os.rename(tmpname, 'MANIFEST.in')
    print('updated MANIFEST.in')
    # Remove the SOURCES.txt that setuptools maintains. It appears not to
    # accurately regenerate it when MANIFEST.in changes.
    sourcestxt = os.path.join('bluepass.egg-info', 'SOURCES.txt')
    if not os.access(sourcestxt, os.R_OK):
        return
    os.unlink(sourcestxt)
    print('removed {0}'.format(sourcestxt))


def main():
    os.chdir(topdir)
    update_version()
    update_manifest()
    extargs = {}
    if sys.platform == 'darwin':
        # Silence warnings about our RETURN_ERROR macro
        extargs['extra_compile_args'] = ['-Wno-format']
    from bluepass.platform import platform_ffi
    setup(
        packages = ['bluepass', 'bluepass.ext', 'bluepass.platform',
                    'bluepass.frontends', 'bluepass.frontends.qt'],
        ext_modules = [
            Extension('bluepass.ext.openssl', ['bluepass/ext/openssl.c'],
                      libraries=['ssl', 'crypto'], **extargs),
            Extension('bluepass.ext._sslex', ['bluepass/ext/_sslex.c'],
                      libraries=['ssl', 'crypto'], **extargs),
            platform_ffi.ffi.verifier.get_extension()],
        package_data = {'bluepass': ['assets/*/*']},
        install_requires = ['pycparser', 'cffi', 'gruvi', 'six'],
        entry_points = {'console_scripts': ['bluepass = bluepass.main:main']},
        test_suite = 'nose.collector',
        zip_safe = False,
        **version_info
    )


if __name__ == '__main__':
    main()
