#
# This file is part of Bluepass. Bluepass is Copyright (c) 2012-2013
# Geert Jansen.
#
# Bluepass is free software available under the GNU General Public License,
# version 3. See the file LICENSE distributed with this file for the exact
# licensing terms.

import time
import logging

import gruvi
from gruvi import Fiber

from bluepass import logging
from bluepass.factory import instance
from bluepass.model import Model
from bluepass.locator import Locator
from bluepass.syncapi import SyncApiClient, SyncApiError


class Syncer(Fiber):
    """Syncer.
    
    The syncer is an component that is responsible for inbound/outbound
    synchronization. The sync jobs are run either periodically, or based on
    certain system events, like a neighbor becoming visible on the network or
    an entry being added.
    """

    interval = 300

    def __init__(self):
        """Constructor."""
        super(Syncer, self).__init__(target=self._run)
        self._log = logging.get_logger(self)
        self.queue = gruvi.Queue()
        self.neighbors = {}
        self.last_sync = {}

    def _event_callback(self, event, *args):
        """Store events and wake up the main loop."""
        self.queue.put((event, args))

    def set_last_sync(self, node, time):
        """Set the last_sync time for `node` to `time`."""
        self.last_sync[node] = time

    def _run(self):
        """This runs the synchronization loop."""
        model = instance(Model)
        model.add_callback(self._event_callback)
        locator = instance(Locator)
        locator.add_callback(self._event_callback)
        neighbors = locator.get_neighbors()
        mynodes = set((v['node'] for v in model.get_vaults()))
        myvaults = set((v['id'] for v in model.get_vaults()))
        while True:
            # Determine how long we need to wait
            now = time.time()
            timeout = self.interval
            for neighbor in neighbors:
                node = neighbor['node']
                vault = neighbor['vault']
                if node in mynodes or vault not in myvaults \
                            or not model.get_certificate(vault, node):
                    continue
                last_sync = self.last_sync.get(node, 0)
                timeout = min(timeout, max(0, last_sync + self.interval - now))
            # Now wait for a timeout, or an event.
            entry = self.queue.get(timeout)
            # Build a list of nodes that we need to sync with.
            #
            # We sync to nodes that are are not ours, whose vault we also
            # have, and where there is a certificate. In addition, at least
            # one of the following three needs to be true:
            #
            # 1. The last sync to this node is > interval seconds ago.
            # 2. A version was added locally to the node's vault
            # 3. The node resides at an address that we are already syncing
            #    with.
            #
            # Regarding #3, we organize the nodes by network address, and try
            # to sync all nodes over a single connection. So the nodes in #3
            # are almost "free" to do so that's they are included.
            now = time.time()
            neighbors = locator.get_neighbors()
            mynodes = set((v['node'] for v in model.get_vaults()))
            myvaults = set((v['id'] for v in model.get_vaults()))
            byaddress = {}
            sync_nodes = set()
            sync_vaults = set()
            # First process events.
            if entry:
                event, args = entry
                if event == 'NeighborDiscovered':
                    neighbor = args[0]
                    # As an optimization do not sync with new neighbors that
                    # are discovered while we are running, because we known
                    # that when they are started up they will sync with us.
                    self.last_sync[neighbor['node']] = now
                elif event == 'VersionsAdded':
                    vault, versions = args
                    # As an optimization, only push out a list of added
                    # versions in case it is generated locally, because we know
                    # the originator will push the update to everybody else.
                    for version in versions:
                        item = model.get_version_item(vault, version['id'])
                        if item['origin']['node'] not in mynodes:
                            continue
                        self._log.debug('local update, syncing to all nodes for vault {}', vault)
                        sync_vaults.add(vault)
                        break
            # Now build a list of nodes including a "byaddress" list.
            for neighbor in neighbors:
                node = neighbor['node']
                vault = neighbor['vault']
                if node in mynodes or vault not in myvaults \
                            or not model.get_certificate(vault, node):
                    # Never sync with these nodes...
                    continue
                last_sync = self.last_sync.get(node, 0)
                timeout = last_sync + self.interval < now
                if timeout or vault in sync_vaults:
                    for addr in neighbor['addresses']:
                        key = addr['id']
                        if key not in byaddress:
                            byaddress[key] = (addr['family'], addr, [])
                        byaddress[key][2].append(neighbor)
                    sync_nodes.add(node)
                    continue
                # See if we are already syncing with an address, and if so,
                # include /that address only/ in the sync job.
                for addr in neighbor['addresses']:
                    key = addr['id']
                    if key in byaddress:
                        byaddress[key][2].append(neighbor)
                        sync_nodes.add(node)
            if not sync_nodes:
                # Nothing to do...
                continue
            self._log.debug('total nodes to sync: {}', len(sync_nodes))
            # Now sync to the nodes. Try to reuse the network connection for
            # multiple nodes. We sort the addresses on location source so that
            # we will be able to give different priorites to different sources
            # later.
            nnodes = nconnections = 0
            addresses = sorted(byaddress.values(), key=lambda x: x[0])
            for source,addr,neighbors in addresses:
                client = None
                for neighbor in neighbors:
                    node = neighbor['node']
                    if node not in sync_nodes:
                        continue  # already synced
                    self._log.debug('syncing with node {}', node)
                    if client is None:
                        client = SyncApiClient()
                        try:
                            client.connect(addr['addr'])
                        except SyncApiError as e:
                            self._log.error('could not connect to {}: {}', addr, str(e))
                            client.close()
                            break
                        self._log.debug('connected to {}', addr)
                        nconnections += 1
                    vault = neighbor['vault']
                    starttime = time.time()
                    try:
                        client.sync(vault, model)
                    except SyncApiError:
                        self._log.error('failed to sync vault {} at {}', vault, addr)
                        client.close()
                        client = None
                    else:
                        self._log.debug('succesfully synced vault {} at {}', vault, addr)
                        nnodes += 1
                        sync_nodes.remove(node)
                        self.last_sync[node] = starttime
                if client:
                    client.close()
                if not sync_nodes:
                    break  # we are done
            self._log.debug('synced to {} nodes using {} network connections', nnodes, nconnections)
            if sync_nodes:
                self._log.debug('failed to sync with {} nodes', len(sync_nodes))
        self._log.debug('syncer loop terminated')
