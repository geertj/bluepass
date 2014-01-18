#
# This file is part of Bluepass. Bluepass is Copyright (c) 2012-2014
# Geert Jansen.
#
# Bluepass is free software available under the GNU General Public License,
# version 3. See the file LICENSE distributed with this file for the exact
# licensing terms.

from __future__ import absolute_import, print_function


class Error(Exception):
    """Base class for Bluepass errors."""

# Shared errors below. Subsystem specific errors are define in their respective
# modules.

class AuthenticationFailed(Error):
    """Authentication failed."""

class ValidationError(Error):
    """An input could not be validated."""

class NotFound(Error):
    """An object was not found."""

class PlatformError(Error):
    """Error calling a platform-specific API."""
