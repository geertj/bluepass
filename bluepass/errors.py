#
# This file is part of Bluepass. Bluepass is Copyright (c) 2012-2014
# Geert Jansen.
#
# Bluepass is free software available under the GNU General Public License,
# version 3. See the file LICENSE distributed with this file for the exact
# licensing terms.

from __future__ import absolute_import, print_function

import re
from collections import namedtuple


# Common exceptions for Bluepass


class Error(Exception):
    """Base class for Bluepass errors."""

class AuthenticationFailed(Error):
    """Authentication failed."""

class ValidationError(Error):
    """An input could not be validated."""

class NotFound(Error):
    """An object was not found."""

class Exists(Error):
    """Object already exists."""

from .validate import ValidationError


# A subset of Bluepass exceptions are considered "safe" to pass through to the
# end user via one of the APIs. These exceptions are defined below. They have
# some extra metadata associated with them which allows us to automaticaly
# generate error responses for HTTP and JSON-RPC. The extra metadata is
# currently:
#
#  * A unique and stable numeric ID. Clients can use the numeric ID to
#    distinghuish between errors.
#  * A unique symbolic name. This is the SCREAMING_SNAKE_CASE version of
#    the CamelCase exception name.
#  * A default textual error message.
#  * An optional list of attributes of the exception that can be copied
#    to the API user.

camel_words = re.compile('([a-z](?=[A-Z])|[A-Z]+(?=[A-Z][a-z]))')

errorcode = {}
errormsg = {}
errordata = {}
errorcls = {}

def add_error(cls, code, fields=None):
    """Register a new API exposable exception *cls*.

    The *code* must be a unique and stable integer identifying the erorr. The
    *fields* argument optionally specifies a list of data fields that will be
    exported to the API user.
    """
    name = camel_words.sub('\\1_', cls.__name__).upper()
    globals()[name] = code
    errorcode[code] = name
    errormsg[code] = cls.__doc__ or ''
    errordata[code] = fields or ()
    errorcls[cls] = name


ErrorInfo = namedtuple('ErrorInfo', ('code', 'name', 'message', 'detail', 'exception'))

def get_error_info(exc):
    """Return error information about an exception."""
    for cls in type(exc).__mro__:
        if cls in errorcls or cls is Exception:
            break
    if cls is Exception:
        return
    name = errorcls[exc]
    code = globals()[name]
    message = exc.args[0] if isinstance(exc, Exception) and exc.args else errormsg[code]
    detail = dict(((name, getattr(exc, name)) for name in errordata.get(cls, [])))
    err = ErrorInfo(code, name, message, detail, cls)
    print('ERR', repr(err))
    return err


# Exception metadata below

add_error(AuthenticationFailed, 10)
add_error(ValidationError, 11)
add_error(NotFound, 12)
add_error(Exists, 13)
