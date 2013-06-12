#
# This file is part of Bluepass. Bluepass is Copyright (c) 2012-2013
# Geert Jansen.
#
# Bluepass is free software available under the GNU General Public License,
# version 3. See the file LICENSE distributed with this file for the exact
# licensing terms.

import os

# The default resolver for gevent in 1.0b2 is the threadpool resolver.
# This gave me problems with running the tests in test_backend.py. That
# module forks and apparently threads and fork() don't play nicely
# together in gevent. So use the "ares" resolved by default.
os.environ['GEVENT_RESOLVER'] = 'ares'
