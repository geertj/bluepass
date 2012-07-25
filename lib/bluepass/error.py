#
# This file is part of Bluepass. Bluepass is Copyright (c) 2012
# Geert Jansen. All rights are reserved.

import sys
import logging
import traceback


class Error(Exception):
    """Base class of all exceptions."""


class StructuredError(Error):
    """Structured error.

    Structured errors are used when there may be a need to transport an
    error remotely over one of our APIs (socket API or sync API).

    A structured error has 3 attribute:

     - error_name: a unique string identifying this error
     - error_message: a short phrase describing error_name
     - error_detail: extra dteails

    The error_name attribute is a string that uniquely identifies the error
    and may be used by code to interpret the error. The error_message and
    error_details are human readable strings, may be localized, and should
    never be interpreted.
    """

    # A single table of all error_name's. If a subclass needs a new error, it
    # needs to be added here.

    error_table = \
    {
        'OK': 'No error',
        'Exists': 'Object already exists',
        'NotFound': 'Object not found',
        'Locked': 'Object is locked',
        'InvalidCall': 'Wrong signature for callable object',
        'InvalidArgument': 'Invalid argument',
        'WrongPassword': 'Wrong password',
        'ConsistencyError': 'Internal data inconsistency error',
        'PlatformError': 'Generic platform or operating system error',
        'RemoteError': 'Communications error with a remote peer',
        'UncaughtException': 'An uncaught exception occurred',
        'ProgrammingError': 'Programming error'
    }

    def __init__(self, error_name, error_detail=''):
        """Create a new structured error."""
        self.error_name = error_name
        self.error_message = self._get_error_message(error_name)
        self.error_detail = error_detail
        super(StructuredError, self). \
                __init__(error_name, self.error_message, self.error_detail)

    def _get_error_message(self, name):
        """Return the error message for error `name`."""
        try:
            return self.error_table[name]
        except KeyError:
            pass
        logger = logging.getLogger('bluepass')
        logger.debug('error "%s" unknown, please add it to ' \
                     'StructuredError.error_table', name)
        message = 'Unknown error'
        return message

    def __str__(self):
        """Format this error to a human readable error message."""
        if self.error_detail:
            return '%s: %s' % (self.error_message, self.error_detail)
        else:
            return self.error_message

    def asdict(self):
        """Return the error as a dictionary."""
        d = { 'error_name': self.error_name,
              'error_message': self.error_message,
              'error_detail': self.error_detail }
        return d

    @classmethod
    def uncaught_exception(cls):
        """Return an UncaughtException."""
        detail = traceback.format_exception(*sys.exc_info())
        detail = ''.join(detail)
        return cls('UncaughtException', detail)
