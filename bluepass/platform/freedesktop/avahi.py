#
# This file is part of Bluepass. Bluepass is Copyright (c) 2012-2013
# Geert Jansen.
#
# Bluepass is free software available under the GNU General Public License,
# version 3. See the file LICENSE distributed with this file for the exact
# licensing terms.

import socket
import logging

import gruvi
from gruvi import txdbus, compat
from gruvi.dbus import DBusClient, DBusError
from bluepass.locator import ZeroconfLocationSource, LocationError

# We do not import "avahi" because it depends on python-dbus which is
# a dependency I do not want to introduce. So redefine these here:

DBUS_NAME = 'org.freedesktop.Avahi'
PATH_SERVER = '/'
IFACE_SERVER = 'org.freedesktop.Avahi.Server'
IFACE_SERVICE_BROWSER = 'org.freedesktop.Avahi.ServiceBrowser'
IFACE_SERVICE_RESOLVER = 'org.freedesktop.Avahi.ServiceResolver'
IFACE_ENTRY_GROUP = 'org.freedesktop.Avahi.EntryGroup'

IFACE_UNSPEC = -1
PROTO_INET = 0
PROTO_INET6 = 1
SERVER_RUNNING = 2


def encode_txt(txt):
    """Encode dictionary of TXT records to the format expected by Avahi."""
    result = []
    for name,value in txt.items():
        item = '{}={}'.format(name, value)
        item = list(bytearray(item.encode('utf8')))
        result.append(item)
    return result

def decode_txt(txt):
    """Decode a list of TXT records that we get from Avahi into a dict."""
    result = {}
    for item in txt:
        item = b''.join(map(lambda x: bytes([x]), item)).decode('utf8')
        name, value = item.split('=')
        result[name] = value
    return result


def signal_handler(interface=None):
    """Annotate a method as a D_BUS signal handler."""
    def _decorate(func):
        func.signal_handler = True
        func.member = func.__name__
        func.interface = interface
        return func
    return _decorate


class DBusHandler(object):
    """DBus message handler."""

    def __init__(self):
        self.signal_handlers = []
        self.local = gruvi.local()
        self._init_handlers()

    def _init_handlers(self):
        for name in vars(self.__class__):
            handler = getattr(self, name)
            if getattr(handler, 'signal_handler', False):
                self.signal_handlers.append(handler)

    @property
    def protocol(self):
        return self.local.protocol

    def __call__(self, message, protocol, transport):
        if not isinstance(message, txdbus.SignalMessage):
            return
        for handler in self.signal_handlers:
            if handler.member != message.member:
                continue
            if handler.interface and message.interface != handler.interface:
                continue
            break
        else:
            return
        self.local.protocol = protocol
        try:
            handler(*message.body)
        finally:
            del self.local.protocol


class AvahiHandler(DBusHandler):
    """DBusHandler that responds to Avahi signals."""

    def __init__(self, callback):
        """Constructor. The callback is notified for all events."""
        super(AvahiHandler, self).__init__()
        self._resolvers = {}
        self._callback = callback
        self.logger = logging.getLogger(__name__)

    def _call_avahi(self, path, method, interface, signature=None, args=None):
        """Call into Avahi."""
        try:
            reply = self.protocol.call_method(DBUS_NAME, path, interface, method,
                                              signature=signature, args=args)
        except DBusError as e:
            self.logger.error('D-BUS error for method %s: %s', method, str(e))
        else:
            return reply

    @signal_handler(interface=IFACE_SERVICE_BROWSER)
    def ItemNew(self, *args):
        resolver = self._call_avahi(PATH_SERVER, 'ServiceResolverNew', IFACE_SERVER,
                                   'iisssiu', args[:5] + (PROTO_INET, 0))
        if not resolver:
            return
        key = '.'.join(map(str, args[:5]))
        self._resolvers[key] = resolver

    @signal_handler(interface=IFACE_SERVICE_BROWSER)
    def ItemRemove(self, *args):
        key = '.'.join(map(str, args[:5]))
        if key not in self._resolvers:
            self.logger.error('ItemRemove signal for unknown service: %s', key)
            return
        resolver = self._resolvers.pop(key)
        self._call_avahi(resolver, 'Free', IFACE_SERVICE_RESOLVER)
        self._callback('ItemRemove', *args)

    @signal_handler(interface=IFACE_SERVICE_RESOLVER)
    def Found(self, *args):
        self._callback('Found', *args)


class AvahiLocationSource(ZeroconfLocationSource):
    """Avahi Zeroconf location source.
    
    This location source provides loation services for a local network
    using DNS-SD. This source is for freedesktop like platforms and uses
    Avahi via its D-BUS interface.

    DNS-SD is used in the following way for vault discovery:

    1. The Bluepass service is registered as a PTR record under:

        _bluepass._tcp.local

    2. The previous PTR record will resolve to a list of SRV and TXT records.
       Instead of using the vault UUID as the service name, this uses the
       vault's node UUID because a vault can be replicated over many Bluepass
       instances and is therefore not unique.

        <node_uuid>._bluepass._tcp.local

       The TXT records specify a set of properteis, with at least a
       "vault" property containing the UUID of the vault. A "visible" property
       may also be set, indicating whether this node currently accepts pairing
       requests.
    """

    name = 'avahi-zeroconf'

    def __init__(self):
        """Constructor."""
        super(AvahiLocationSource, self).__init__()
        handler = AvahiHandler(self._avahi_event)
        self.client = DBusClient(handler)
        self.client.connect('system')
        self.logger = logging.getLogger(__name__)
        self.callbacks = []
        self.neighbors = {}
        self.addresses = {}
        self._browser = None
        self._entry_groups = {}

    def _call_avahi(self, path, method, interface, signature=None, args=None):
        """INTERNAL: call into Avahi."""
        try:
            reply = self.client.call_method(DBUS_NAME, path, interface, method,
                                            signature=signature, args=args)
        except DBusError as e:
            msg = 'Encounted a D-BUS error for method %s: %s'
            self.logger.error(msg, method, str(e))
            raise LocationError(msg % (method, str(e)))
        return reply

    def _run_callbacks(self, event, *args):
        """Run all registered callbacks."""
        for callback in self.callbacks:
            callback(event, *args)

    def _proto_to_family(self, proto):
        """Convert an Avahi protocol ID to an address family."""
        if proto == PROTO_INET:
            family = socket.AF_INET
        elif proto == PROTO_INET6:
            family = socket.AF_INET6
        else:
            family = -1
        return family

    def _avahi_event(self, event, *args):
        """Single unified callback for AvahiHandler."""
        logger = self.logger
        if event == 'Found':
            node = args[2]
            neighbor = { 'node': node, 'source': 'LAN' }
            txt = decode_txt(args[9])
            properties = neighbor['properties'] = {}
            for name,value in txt.items():
                if name in ('nodename', 'vault', 'vaultname'):
                    neighbor[name] = value
                else:
                    properties[name] = value
            for name in ('nodename', 'vault', 'vaultname'):
                if not neighbor.get(name):
                    logger.error('node %s lacks TXT field "%s"', node, name)
                    return
            event = 'NeighborUpdated' if node in self.neighbors else 'NeighborDiscovered'
            family = self._proto_to_family(args[6])
            if family != socket.AF_INET:
                return
            addr = { 'family': family, 'host': args[5], 'addr': (args[7], args[8]) }
            addr['id'] = '%s:%s:%s' % (family, args[7], args[8])
            # There can be multiple addresses per node for different
            # interfaces and/or address families. We keep track of this
            # so we distinghuish address changes from new addresses that
            # become available.
            key = '%d:%d' % (args[0], args[1])
            if node not in self.addresses:
                self.addresses[node] = {}
            self.addresses[node][key] = addr
            neighbor['addresses'] = list(self.addresses[node].values())
            self.neighbors[node] = neighbor
            self._run_callbacks(event, neighbor)
        elif event == 'ItemRemove':
            node = args[2]
            key = '%d:%d' % (args[0], args[1])
            if node not in self.neighbors or key not in self.addresses[node]:
                logger.error('ItemRemove event for unknown node "%s"', node)
                return
            del self.addresses[node][key]
            neighbor = self.neighbors[node]
            neighbor['addresses'] = list(self.addresses[node].values())
            if not neighbor['addresses']:
                del self.addresses[node]
                del self.neighbors[node]
            event = 'NeighbordUpdated' if node in self.neighbors else 'NeighborDisappeared'
            self._run_callbacks(event, neighbor)

    def isavailable(self):
        """Return wheter Avahi is available or not."""
        try:
            version = self._call_avahi(PATH_SERVER, 'GetVersionString', IFACE_SERVER)
        except LocationError:
            return False
        self.logger.info('Found Avahi version %s', version)
        state = self._call_avahi(PATH_SERVER, 'GetState', IFACE_SERVER)
        if state != SERVER_RUNNING:
            self.logger.error('Avahi not in the RUNNING state (instead: %s)', state)
            return False
        return True

    def add_callback(self, callback):
        """Add a callback for this location source. When the first callback is
        added, we start browsing the zeroconf domain."""
        self.callbacks.append(callback)
        if self._browser is not None:
            return
        args = (IFACE_UNSPEC, PROTO_INET, self.service, self.domain, 0)
        self._browser = self._call_avahi(PATH_SERVER, 'ServiceBrowserNew',
                                 IFACE_SERVER, 'iissu', args)

    def register(self, node, nodename, vault, vaultname, address, properties=None):
        """Register a service instance."""
        group = self._call_avahi(PATH_SERVER, 'EntryGroupNew', IFACE_SERVER)
        host = self._call_avahi(PATH_SERVER, 'GetHostNameFqdn', IFACE_SERVER)
        port = address[1]
        properties = properties.copy() if properties else {}
        properties['nodename'] = nodename
        properties['vault'] = vault
        properties['vaultname'] = vaultname
        args = (IFACE_UNSPEC, PROTO_INET, 0, node, self.service, self.domain,
                host, port, encode_txt(properties))
        self._call_avahi(group, 'AddService', IFACE_ENTRY_GROUP, 'iiussssqaay', args)
        self._call_avahi(group, 'Commit', IFACE_ENTRY_GROUP)
        self._entry_groups[node] = (group, properties)

    def set_property(self, node, name, value):
        """Update a property."""
        if node not in self._entry_groups:
            raise RuntimeError('Node is not registered yet')
        group, properties = self._entry_groups[node]
        properties[name] = value
        args = (IFACE_UNSPEC, PROTO_INET, 0, node, self.service, self.domain,
                encode_txt(properties))
        self._call_avahi(group, 'UpdateServiceTxt', IFACE_ENTRY_GROUP, 'iiusssaay', args)

    def unregister(self, node):
        """Release our registration."""
        if node not in self._entry_groups:
            raise RuntimeError('Node is not registered yet')
        group, properties = self._entry_groups[node]
        self._call_avahi(group, 'Free', IFACE_ENTRY_GROUP)
        del self._entry_groups[node]
