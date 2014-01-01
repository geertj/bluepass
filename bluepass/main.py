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
import time
import json
import errno
import socket
import argparse
import subprocess
import binascii

import bluepass
from bluepass import platform, util, logging
from bluepass.factory import singleton
from bluepass.backend import Backend

log = None


def create_parser():
    """Build the command-line parser."""
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--debug', action='store_true',
                        help='Show debugging information.')
    parser.add_argument('-v', '--verbose', action='store_true', help='Be verbose.')
    parser.add_argument('-V', '--version', action='store_true',
                        help='Show version information and exit.')
    parser.add_argument('-f', '--frontend', help='Select frontend to use.')
    parser.add_argument('-c', '--connect', metavar='ADDRSPEC',
                        help='Connect to existing backend (HOST:PORT or PATH)')
    parser.add_argument('--log-stdout', action='store_true',
                        help='Log to stdout even if not on a tty')
    parser.add_argument('--data-dir', metavar='DIRECTORY',
                        help='Specify data directory')
    parser.add_argument('--auth-token', metavar='TOKEN',
                        help='Backend authentication token')
    parser.add_argument('--daemon', action='store_true',
                        help='Do not kill backend on exit')
    parser.add_argument('--list-frontends', action='store_true',
                        help='List available frontends and exit.')
    parser.add_argument('--run-backend', action='store_true', help='Run the backend')
    parser.add_argument('--timeout', type=int, help='Backend timeout', default=2)
    return parser


def start_backend(options):
    args = [sys.executable, '-mbluepass.main', '--run-backend'] + sys.argv[1:]
    process = subprocess.Popen(args)
    log.debug('started backend with pid {}', process.pid)
    return process

def stop_backend(options, process, sock):
    # Try to stop our child. First nicely, then progressively less nice.
    start_time = time.time()
    elapsed = 0
    while elapsed < 3*options.timeout:
        if sock:
            log.debug('sending "stop" command to backend')
            request = { 'id': 'main.1', 'method': 'stop', 'jsonrpc': '2.0' }
            sock.send(json.dumps(request).encode('ascii'))
            sock.close()
            sock = None
        elif elapsed > options.timeout:
            log.debug('calling terminate() on backend')
            process.terminate()
        elif elapsed > 2*options.timeout:
            log.debug('calling kill() on backend')
            process.kill()
        if process.poll() is not None:
            break
        time.sleep(0.1)
        elapsed = time.time() - start_time
    exitstatus = process.returncode
    if exitstatus is None:
        log.error('could not stop backend after {} seconds', elapsed)
        return False
    elif exitstatus:
        log.error('backend exited with status {}', exitstatus)
    else:
        log.debug('backend exited after {} seconds', elapsed)
    return True

def connect_backend(options):
    runfile = os.path.join(options.data_dir, 'backend.run')
    sock = None
    start_time = time.time()
    elapsed = 0
    while elapsed < options.timeout:
        st = util.try_stat(runfile)
        if st is None:
            continue
        with open(runfile) as fin:
            buf = fin.read()
        runinfo = json.loads(buf)
        if not isinstance(runinfo, dict):
            break
        addr = util.paddr(runinfo['listen'])
        try:
            sock = util.create_connection(addr, timeout=0.2)
        except (OSError, IOError) as e:
            if e.errno and e.errno not in (errno.ENOENT, errno.ECONNREFUSED):
                raise
        else:
            break
        time.sleep(0.1)
        elapsed = time.time() - start_time
    log.debug('backed started up in {} seconds', elapsed)
    return sock, runinfo


def create_auth_token():
    """Return a new auth token."""
    return binascii.hexlify(os.urandom(32)).decode('ascii')


def main():
    """Main entry point."""

    # First get the --frontend parameter so that we can its command-line
    # options.

    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('-f', '--frontend', nargs='?')
    options, _ = parser.parse_known_args()

    for fe in platform.get_frontends():
        if fe.name == options.frontend or options.frontend is None:
            Frontend = fe
            break
    else:
        print('Error: no such frontend: {0}'.format(options.frontend), file=sys.stderr)
        print('Use --list-frontends to list available frontends', file=sys.stderr)
        return 1

    # Now build the real parser and parse arguments

    parser = create_parser()
    Frontend.add_options(parser)
    Backend.add_options(parser)
    options = parser.parse_args()

    # Early exits?

    if options.version:
        print('Bluepass version {0}'.format(bluepass.__version__))
        return 0

    if options.list_frontends:
        print('Available frontends:')
        for fe in platform.get_frontends():
            print('* {0:10}: {1}'.format(fe.name, fe.description))
        return 0

    # Check options and fill in defaults

    if options.data_dir is None:
        options.data_dir = platform.get_appdir('bluepass')
    if options.auth_token is None:
        options.auth_token = os.environ.get('BLUEPASS_AUTH_TOKEN')

    if not Frontend.check_options(options):
        return 1
    if not Backend.check_options(options):
        return 1

    if options.connect and options.run_backend:
        print('Error: specify either --connect or --run-backend but not both', file=sys.stderr)
        return 1

    # Unless we are spawning the backend and can create our own auth token,
    # we need the user to specify it.

    startbe = not (options.connect or options.run_backend)
    if options.auth_token is None:
        if not startbe:
            print('Error: --auth-token or $BLUEPASS_AUTH_TOKEN is required',
                        file=sys.stderr)
            return 1
        options.auth_token = create_auth_token()
        os.environ['BLUEPASS_AUTH_TOKEN'] = options.auth_token

    global log
    logging.setup_logging(options)
    log = logging.get_logger(name='main')

    # Need to start up the backend?

    if startbe:
        process = start_backend(options)
        sock, runinfo = connect_backend(options)
        options.connect = runinfo['listen']

    # Run either the front-end or the backend

    if options.run_backend:
        logging.set_default_logger('backend')
        backend = singleton(Backend, options)
        ret = backend.run()
    else:
        logging.set_default_logger('frontend.{0}'.format(fe.name))
        frontend = singleton(Frontend, options)
        ret = frontend.run()

    # Back from frontend or backend.

    if startbe and not options.daemon:
        stop_backend(options, process, sock)

    return ret


if __name__ == '__main__':
    sys.exit(main())
