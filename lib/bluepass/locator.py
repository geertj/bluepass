#
# This file is part of Bluepass. Bluepass is Copyright (c) 2012
# Geert Jansen. All rights are reserved.

import logging
from bluepass.error import Error


class LocationError(Error):
    pass


class LocationSource(object):
    """A location source."""

    def isavailable(self):
        raise NotImplementedError

    def register(self, node, nodename, vault, vaultname, address):
        raise NotImplementedError

    def set_property(self, node, name, value):
        raise NotImplementedError

    def unregister(self, node):
        raise NotImplementedError

    def add_callback(self, callback):
        raise NotImplementedError


class ZeroconfLocationSource(LocationSource):

    service = '_bluepass._tcp'
    domain = 'local'


class Locator(object):
    """Locator object.

    The locator keeps track of a list of current neighbors across multiple
    location sources.

    A neighbor is uniquely identified by the source identifier and its node ID.
    A node may have multiple addresses even within once location source. Each
    of these addresses are stored in the "addresses" property of a neighbor.

    The method get_neighbors() returns list of all currently known neighbors.
    Each neighbor is represented by a dictionary. An example is given below:

      {
          'source': 'LAN',
          'node': 'uuid',
          'nodename': 'Node Name',
          'vault': 'uuid',
          'vaultname': 'Vault Name',
          'addresses': [ { 'family': 2, 'addr': ['1.2.3.4', 100] } ],
          'properties': { 'visible': True }
      }

    The locator raises the events "NeighborDiscovered" "NeighborUpdated" and
    "NeighborDisappeared" to that users can be notified asynchronously of
    changes to the list of current neighbors.
    """

    def __init__(self):
        """Create a new locator object."""
        self.sources = []
        self.callbacks = []
        self.neighbors = {}
        self.addresses = {}
        self.vaults = set()
        self.logger = logging.getLogger(__name__)

    def raise_event(self, event, *args):
        """Run all registered callbacks."""
        for callback in self.callbacks:
            callback(event, *args)

    def add_callback(self, callback):
        """Add a callback that gets notified when nodes come and go."""
        self.callbacks.append(callback)

    def _source_event(self, event, *args):
        """Callback for source events."""
        logger = self.logger
        neighbor = args[0]
        node = neighbor['node']
        vault = neighbor['vault']
        source = neighbor['source']
        if event == 'NeighborDiscovered':
            if source not in self.neighbors:
                self.neighbors[source] = {}
            if node in self.neighbors[source]:
                logger.error('NeighborDiscovered event for known neighbor')
                return
            self.neighbors[source][node] = neighbor
        elif event == 'NeighborUpdated':
            if source not in self.neighbors or node not in self.neighbors[source]:
                logger.error('NeighborUpdated event for unknown neighbor')
                return
            self.neighbors[source][node] = neighbor
        elif event == 'NeighborDisappeared':
            if source not in self.neighbors or node not in self.neighbors[source]:
                logger.error('NeighborDisappeared event for unknown neighbor')
                return
            del self.neighbors[source][node]
            if not self.neighbors[source]:
                del self.neighbors[source]
        self.raise_event(event, *args)

    def add_source(self, source):
        """Add a new location source."""
        self.sources.append(source)
        source.add_callback(self._source_event)

    def register(self, node, nodename, vault, vaultname, address,
                 properties=None):
        """Register a ourselves with all sources."""
        for source in self.sources:
            source.register(node, nodename, vault, vaultname, address,
                            properties)

    def set_property(self, node, name, value):
        """Set a property on a vault in each location source."""
        for source in self.sources:
            source.set_property(node, name, value)

    def unregister(self, node):
        """Unregister a vault with each location source."""
        for source in self.sources:
            source.unregister(node)

    def get_neighbor(self, node, source):
        """Resolve a single neighbor."""
        return self.neighbors.get(source, {}).get(node)

    def get_neighbors(self):
        """Return the list of neighbors."""
        neighbors = []
        for source in self.neighbors:
            neighbors += self.neighbors[source].values()
        return neighbors
