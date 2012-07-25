#
# This file is part of Bluepass. Bluepass is Copyright (c) 2012
# Geert Jansen. All rights are reserved.

import sys

from bluepass.factory import create, FactoryError
from bluepass.frontend import Frontend
from bluepass.util.optparse import OptionParserEx


def main():
    """Main entry point."""
    # Parse just enough of the command-line to understand which front-end to
    # load. The frontend will then parse the full options.

    parser = OptionParserEx(allow_unknown_options=True, add_help_option=False)
    parser.add_option('-f', '--frontend')
    opts, args = parser.parse_args()

    try:
        frontend = create(Frontend, opts.frontend)
    except FactoryError:
        sys.stderr.write('Error: could not load frontend "%s"\n'
                         % (opts.frontend or '<default>'))
        sys.exit(1)

    if not frontend.parse_args(sys.argv):
        sys.exit(2)

    sys.exit(frontend.start())
