#
# This file is part of Bluepass. Bluepass is Copyright (c) 2012
# Geert Jansen. All rights are reserved.

import sys
import os.path
import time
import datetime
import inspect
from subprocess import Popen, PIPE
import socket

from setuptools import setup, Extension
from setuptools.command.build_ext import build_ext
from distutils.command.build import build

# Options for this script
#  --test-build: create a test build
#  --no-build-info: do not include build info

version_info = {
    'name': 'bluepass',
    'version': '0.2.2',
    'description': 'The Bluepass password manager.',
    'author': 'Geert Jansen',
    'author_email': 'geertj@gmail.com',
    'url': 'http://github.com/geertj/bluepass',
    'license': 'Proprietary, all rights reserved',
    'classifiers': [
        'Development Status :: 2 - Pre-Alpha',
        'Environment :: X11 Applications :: Qt',
        'Intended Audience :: End Users/Desktop',
        'License :: Other/Proprietary License',
        'Operating System :: MacOS :: MacOS X',
        'Operating System :: Microsoft :: Windows',
        'Operating System :: POSIX',
        'Topic :: Security',
        'Topic :: Utilities'],
}


def buildroot():
    """Return the top of the source directory."""
    fname = inspect.getfile(sys.modules['__main__'])
    absname = os.path.abspath(fname)
    return os.path.split(absname)[0]


def check_output(command):
    """Python 2.6 does not have a subprocess.check_output()."""
    process = Popen(command, stdout=PIPE)
    output, err = process.communicate()
    status = process.poll()
    if status:
        raise RuntimeError('"%s" exited with status %s', (command, status))
    return output


def create_version(exclude_buildinfo=False):
    """Store the GIT version information in _version.py."""
    fname = os.path.join('lib', 'bluepass', '_version.py')
    fout = file(fname, 'w')
    fout.write('# This is a generated file - do not edit!\n')
    fout.write('version = "%s"\n' % version_info['version'])
    if not exclude_buildinfo:
        command = ['git', 'log', '--pretty=format:%H | %d','--decorate=full', '-1']
        output = check_output(command)
        version, info = output.split('|')
        version = version.strip()
        info = info.strip('()').split(', ')
        tags = [ s[10:] for s in info if s.startswith('refs/tags/') ]
        fout.write('build_version = "%s (%s)"\n' % (version, ', '.join(tags)))
        now = datetime.datetime.now()
        build_date = now.strftime('%a, %d %b %Y %H:%M:%S ')
        build_date += time.tzname[time.daylight]
        fout.write('build_date = "%s"\n' % build_date)
        fout.write('build_host = "%s"\n' % socket.getfqdn())
        command = ['git', 'status', '--porcelain']
        output = check_output(command)
        fout.write('build_changes = [%s]\n' % \
                ', '.join(['"%s"' % line.strip() for line in output.splitlines()]))
    fout.close()
    print 'created %s' % fname


class mybuild(build):

    user_options = [
        ('no-build-info', None, 'do not include build info')
    ] +  build.user_options

    boolean_options = ['no-build-info'] + build.boolean_options

    def initialize_options(self):
        build.initialize_options(self)
        self.no_build_info = False

    def run(self):
        create_version(self.no_build_info)
        build.run(self)


class mybuild_ext(build_ext):

    user_options = [('test-build', None, 'create test build')] + build_ext.user_options
    boolean_options = ['test-build'] + build_ext.boolean_options

    def initialize_options(self):
        build_ext.initialize_options(self)
        self.test_build = False

    def finalize_options(self):
        build_ext.finalize_options(self)
        if self.test_build:
            self.define = [('TEST_BUILD', None)]


os.chdir(buildroot())

setup(
    cmdclass = { 'build': mybuild, 'build_ext': mybuild_ext },
    package_dir = { '': 'lib' },
    packages = ['bluepass', 'bluepass.ext', 'bluepass.util', 'bluepass.test',
                'bluepass.platform', 'bluepass.platform.posix',
                'bluepass.platform.linux', 'bluepass.platform.qt'],
    ext_modules = [
        Extension('bluepass.ext.openssl', ['lib/bluepass/ext/openssl.c'],
                  libraries=['ssl', 'crypto']),
        Extension('bluepass.ext.secmem', ['lib/bluepass/ext/secmem.c']),
        Extension('bluepass.ext._sslex', ['lib/bluepass/ext/_sslex.c'],
                  libraries=['ssl', 'crypto'])
    ],
    install_requires = ['setuptools'],
    entry_points = { 'console_scripts': [ 'bluepass = bluepass.main:main' ] },
    test_suite = 'nose.collector',
    **version_info
)
