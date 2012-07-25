#
# This file is part of Bluepass. Bluepass is Copyright (c) 2012
# Geert Jansen. All rights are reserved.

from gevent import core
from gevent.hub import get_hub
from gevent.event import Event
from bluepass.platform import socket


class SelfPipeEvent(Event):
    """An Event that works in a multi-threaded GEvent environment.
    
    This uses the "self pipe" trick to interrupt the gevent event loop
    that is running in another thread.
    """

    def __init__(self):
        """Create a new event."""
        super(SelfPipeEvent, self).__init__()
        # We use a socketpair instead of a pipe because on Windows you
        # cannot sellect() on a pipe.
        self.sockets = socket.socketpair()
        self.sockets[0].setblocking(0)
        self.sockets[1].setblocking(0)
        self._event = get_hub().loop.io(self.sockets[1].fileno(), core.READ)
        self._event.start(self._read_socket)

    def _read_socket(self):
        """INTERNAL: callback that is called when our socket is readable."""
        self.sockets[1].recv(4096)
        super(SelfPipeEvent, self).set()

    def set(self):
        """Set the event."""
        # Interrupt the event loop!
        self.sockets[0].send('x')

    def close(self):
        """Close the file descriptors and events."""
        self._event.stop()
        try:
            self.sockets[0].close()
            self.sockets[1].close()
        except socket.error:
            pass
