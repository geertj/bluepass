#
# This file is part of Bluepass. Bluepass is Copyright (c) 2012
# Geert Jansen. All rights are reserved.

from __future__ import absolute_import

import logging
from logging import *

__all__ = logging.__all__


class ContextLogger(LoggerAdapter):
    """A LoggerAdapter that prepends a message with some context.

    By using this adapter, we don't need to write really long log repetitive
    log messages every time while still allowing us to make them contain all
    the information we need.

    The context is prepended as a "[context message here]" string.
    """

    def __init__(self, logger, context=None):
        self.logger = logger
        self.context = context

    def process(self, msg, kwargs):
        if self.context is not None:
            msg = '[%s] %s' % (self.context, msg)
        return msg, kwargs

    def setContext(self, context):
        self.context = context
