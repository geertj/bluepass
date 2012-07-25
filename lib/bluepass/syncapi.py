#
# This file is part of Bluepass. Bluepass is Copyright (c) 2012
# Geert Jansen. All rights are reserved.

import re
import sys
import time
import logging
import traceback
import httplib as http
from httplib import HTTPException
from urlparse import parse_qs

from gevent import socket, local, Greenlet
from gevent.event import Event
from gevent.pywsgi import WSGIHandler, WSGIServer

from bluepass import _version
from bluepass.error import StructuredError
from bluepass.factory import instance
from bluepass.crypto import CryptoProvider, CryptoError, dhparams
from bluepass.model import Model
from bluepass.locator import Locator
from bluepass.messagebus import MessageBusServer
from bluepass.util import json, base64
from bluepass.util.ssl import wrap_socket, HTTPSConnection
from bluepass.util.uuid import check_uuid4
from bluepass.util.logging import ContextLogger

__all__ = ('SyncAPIError', 'SyncAPIClient', 'SyncAPIApplication',
           'SyncAPIServer')


class SyncAPIError(StructuredError):
    """Sync API error."""


def adjust_pin(pin, n):
    """Increment the numerical string `pin` by `n`, wrapping it if needed."""
    mask = int('9' * len(pin)) + 1
    numpin = int(pin) + n
    numpin = numpin % mask
    fmt = '%%0%dd' % len(pin)
    strpin = fmt % numpin
    return strpin


_re_optval = re.compile(r'^([a-zA-Z_][a-zA-Z0-9_-]*)\s*' \
                        r'=\s*([^"]*|"([^\\"]|\\.)*")$')

def parse_option_header(header, sep1=' ', sep2=' '):
    """Parse an option header."""
    options = {}
    p1 = header.find(sep1)
    if p1 == -1:
        return header, options
    head = header[:p1].strip()
    optvals = header[p1+1:].split(sep2)
    for optval in optvals:
        optval = optval.strip()
        mobj = _re_optval.match(optval)
        if mobj is None:
            raise ValueError('Illegal option string')
        key = mobj.group(1)
        value = mobj.group(2)
        if value.startswith('"'):
            value = value[1:-1]
        options[key] = value
    return head, options

def create_option_header(value, sep1=' ', sep2=' ', **kwargs):
    """Create an option header."""
    result = [value]
    for key,value in kwargs.iteritems():
        result.append(sep1)
        result.append(' ' if sep1 != ' ' else '')
        result.append(key)
        result.append('="')
        value = str(value)
        value = value.replace('\\', '\\\\').replace('"', '\\"')
        result.append(value)
        result.append('"')
        sep1 = sep2
    return ''.join(result)


def parse_vector(vector):
    """Parse an up-to-date vector."""
    result = []
    parts = vector.split(',')
    for part in parts:
        uuid, seqno = part.split(':')
        if not check_uuid4(uuid):
            raise ValueError('Illegal UUID')
        seqno = int(seqno)
        result.append((uuid, seqno))
    return result

def dump_vector(vector):
    """Dump an up-to-date vector."""
    return ','.join(['%s:%s' % (uuid, seqno) for (uuid, seqno) in vector])


class SyncAPIClient(object):
    """
    SyncAPI client.

    This classs implements a client to the Bluepass HTTP based synchronization
    API. The two main functions are pairing (pair_step1() and pair_step2())
    and synchronization (sync()).
    """

    def __init__(self, address, **ssl_args):
        """Create a new client for the syncapi API at `address`."""
        self.address = address
        ssl_args.setdefault('dhparams', dhparams['skip2048'])
        ssl_args.setdefault('ciphers', 'ADH+AES')
        self.ssl_args = ssl_args
        self.connection = None
        logger = logging.getLogger(__name__)
        self.logger = ContextLogger(logger)
        self.crypto = CryptoProvider()

    def _make_request(self, method, url, headers=None, body=None):
        """Make an HTTP request to the API.
        
        This returns the HTTPResponse object on success, or None on failure.
        """
        logger = self.logger
        if headers is None:
            headers = []
        headers.append(('User-Agent', 'Bluepass/%s' % _version.version))
        headers.append(('Accept', 'text/json'))
        if body is None:
            body = ''
        else:
            body = json.dumps(body)
            headers.append(('Content-Type', 'text/json'))
        connection = self.connection
        assert connection is not None
        try:
            logger.debug('client request: %s %s', method, url)
            connection.request(method, url, body, dict(headers))
            response = connection.getresponse()
            headers = response.getheaders()
            body = response.read()
        except (socket.error, HTTPException) as e:
            logger.error('error when making HTTP request: %s', str(e))
            return
        ctype = response.getheader('Content-Type')
        if ctype == 'text/json':
            parsed = json.try_loads(body)
            if parsed is None:
                logger.error('response body contains invalid JSON')
                return
            response.entity = parsed
            logger.debug('parsed "%s" request body (%d bytes)', ctype, len(body))
        else:
            response.entity = None
        return response

    def connect(self):
        """Connect to the remote syncapi."""
        ssl_args = { 'dhparams': dhparams['skip2048'], 'ciphers': 'ADH+AES' }
        # Support both dict style addresses for arbitrary address families,
        # as well as (host, port) tuples for IPv4.
        if isinstance(self.address, dict):
            host = self.address['host']; port = None
            sockinfo = self.address
        else:
            host, port = self.address
            sockinfo = None
        connection = HTTPSConnection(host, port, sockinfo=sockinfo, **ssl_args)
        try:
            connection.connect()
        except socket.error as e:
            self.logger.error('could not connect to %s:%d' % self.address)
            raise SyncAPIError('RemoteError', 'Could not connect')
        self.connection = connection

    def close(self):
        """Close the connection."""
        if self.connection is not None:
            try:
                conection.close()
            except Exception:
                pass
        self.connection = None

    def _get_hmac_cb_auth(self, kxid, pin):
        """Return the headers for a client to server HMAC_CB auth."""
        cb = self.connection.sock.get_channel_binding('tls-unique')
        signature = self.crypto.hmac(adjust_pin(pin, +1), cb, 'sha1')
        signature = base64.encode(signature)
        auth = create_option_header('HMAC_CB', kxid=kxid, signature=signature)
        headers = [('Authorization', auth)]
        return headers

    def _check_hmac_cb_auth(self, response, pin):
        """Check a server to client HMAC_CB auth."""
        logger = self.logger
        authinfo = response.getheader('Authentication-Info', '')
        try:
            method, options = parse_option_header(authinfo)
        except ValueError:
            logger.error('illegal Authentication-Info header: %s', authinfo)
            return False
        if 'signature' not in options or not base64.check(options['signature']):
            logger.error('illegal Authentication-Info header: %s', authinfo)
            return False
        signature = base64.decode(options['signature'])
        cb = self.connection.sock.get_channel_binding('tls-unique')
        check = self.crypto.hmac(adjust_pin(pin, -1), cb, 'sha1')
        if check != signature:
            logger.error('HMAC_CB signature did not match')
            return False
        return True

    def pair_step1(self, uuid, name):
        """Perform step 1 in a pairing exchange.
        
        If succesful, this returns a key exchange ID. On error, a SyncAPIError
        exception is raised.
        """
        if self.connection is None:
            raise SyncAPIError('ProgrammingError', 'Not connected')
        logger = self.logger
        logger.setContext('pair step #1')
        url = '/api/vaults/%s/pair' % uuid
        headers = [('Authorization', 'HMAC_CB name=%s' % name)]
        response = self._make_request('POST', url, headers)
        if response is None:
            raise SyncAPIError('RemoteError', 'Could not make HTTP request')
        status = response.status
        if status != 401:
            logger.error('expecting HTTP status 401 (got: %s)', status)
            raise SyncAPIError('RemoteError', response.reason)
        wwwauth = response.getheader('WWW-Authenticate', '')
        try:
            method, options = parse_option_header(wwwauth)
        except ValueError:
            raise SyncAPIError('RemoteError', 'Illegal response')
        if method != 'HMAC_CB' or 'kxid' not in options:
            logger.error('illegal WWW-Authenticate header: %s', wwwauth)
            raise SyncAPIError('RemoteError', 'Illegal response')
        return options['kxid']

    def pair_step2(self, uuid, kxid, pin, certinfo):
        """Perform step 2 in pairing exchange.
        
        If successfull, this returns the peer certificate. On error, a
        SyncAPIError is raised.
        """
        if self.connection is None:
            raise SyncAPIError('ProgrammingError', 'Not connected')
        logger = self.logger
        logger.setContext('pair step #2')
        url = '/api/vaults/%s/pair' % uuid
        headers = self._get_hmac_cb_auth(kxid, pin)
        response = self._make_request('POST', url, headers, certinfo)
        if response is None:
            raise SyncAPIError('RemoteError', 'Could not make syncapi request')
        status = response.status
        if status != 200:
            logger.error('expecting HTTP status 200 (got: %s)', status)
            raise SyncAPIError('RemoteError', response.reason)
        if not self._check_hmac_cb_auth(response, pin):
            raise SyncAPIError('RemoteError', 'Illegal syncapi response')
        peercert = response.entity
        if peercert is None or not isinstance(peercert, dict):
            raise SyncAPIError('RemoteError', 'Illegal syncapi response')
        return peercert

    def _get_rsa_cb_auth(self, uuid, model):
        """Return the headers for RSA_CB authentication."""
        cb = self.connection.sock.get_channel_binding('tls-unique')
        privkey = model.get_auth_key(uuid)
        assert privkey is not None
        signature = self.crypto.rsa_sign(cb, privkey, 'pss-sha1')
        signature = base64.encode(signature)
        vault = model.get_vault(uuid)
        auth = create_option_header('RSA_CB', node=vault['node'], signature=signature)
        headers = [('Authorization', auth)]
        return headers

    def _check_rsa_cb_auth(self, uuid, response, model):
        """Verify RSA_CB authentication."""
        logger = self.logger
        authinfo = response.getheader('Authentication-Info', '')
        try:
            method, options = parse_option_header(authinfo)
        except ValueError:
            logger.error('illegal Authentication-Info header')
            return False
        if 'signature' not in options or 'node' not in options \
                or not base64.check(options['signature']) \
                or not check_uuid4(options['node']):
            logger.error('illegal Authentication-Info header')
            return False
        cb = self.connection.sock.get_channel_binding('tls-unique')
        signature = base64.decode(options['signature'])
        cert = model.get_certificate(uuid, options['node'])
        if cert is None:
            logger.error('unknown node in RSA_CB authentication', node)
            return False
        pubkey = base64.decode(cert['payload']['keys']['auth']['key'])
        try:
            status = self.crypto.rsa_verify(cb, signature, pubkey, 'pss-sha1')
        except CryptoError:
            logger.error('corrupt RSA_CB signature')
            return False
        if not status:
            logger.error('RSA_CB signature did not match')
        return status

    def sync(self, uuid, model, notify=True):
        """Synchronize vault `uuid` with the remote peer."""
        if self.connection is None:
            raise SyncAPIError('ProgrammingError', 'Not connected')
        logger = self.logger
        logger.setContext('sync')
        vault = model.get_vault(uuid)
        if vault is None:
            raise SyncAPIError('NotFound', 'Vault not found')
        vector = model.get_vector(uuid)
        vector = dump_vector(vector)
        url = '/api/vaults/%s/items?vector=%s' % (vault['id'], vector)
        headers = self._get_rsa_cb_auth(uuid, model)
        response = self._make_request('GET', url, headers)
        if not response:
            raise SyncAPIError('RemoteError', 'Could not make HTTP request')
        status = response.status
        if status != 200:
            logger.error('expecting HTTP status 200 (got: %s)', status)
            raise SyncAPIError('RemoteError', 'Illegal syncapi response')
        if not self._check_rsa_cb_auth(uuid, response, model):
            raise SyncAPIError('RemoteError', 'Illegal syncapi response')
        initems = response.entity
        if initems is None or not isinstance(initems, list):
            raise SyncAPIError('RemoteError', 'Illegal syncapi response')
        nitems = model.import_items(uuid, initems, notify=notify)
        logger.debug('imported %d items into model', nitems)
        vector = response.getheader('X-Vector', '')
        try:
            vector = parse_vector(vector)
        except ValueError as e:
            logger.error('illegal X-Vector header: %s (%s)', vector, str(e))
            raise SyncAPIError('RemoteError', 'Invalid response')
        outitems = model.get_items(uuid, vector)
        url = '/api/vaults/%s/items' % uuid
        response = self._make_request('POST', url, headers, outitems)
        if not response:
            raise SyncAPIError('RemoteError', 'Illegal syncapi response')
        if status != 200:
            logger.error('expecting HTTP status 200 (got: %s)', status)
            raise SyncAPIError('RemoteError', 'Illegal syncapi response')
        if not self._check_rsa_cb_auth(uuid, response, model):
            raise SyncAPIError('RemoteError', 'Illegal syncapi response')
        logger.debug('succesfully retrieved %d items from peer', len(initems))
        logger.debug('succesfully pushed %d items to peer', len(outitems))
        return len(initems) + len(outitems)


def expose(path, **kwargs):
    """Decorator to expose a method via a Rails like route."""
    def _f(func):
        func.path = path
        func.kwargs = kwargs
        func.kwargs['handler'] = func.func_name
        return func
    return _f


class HTTPReturn(Exception):
    """When raised, this exception will issue a HTTP return."""

    def __init__(self, status, headers=None):
        self.status = status
        self.headers = headers or []


class WSGIApplication(object):
    """A higher-level handler interface on top of WSGI.
    
    This class implements Rails-like routing and JSON marshaling/
    demarshaling.
    """

    _re_var = re.compile(':([a-z-A-Z_][a-z-A-Z0-9_]*)')

    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.routes = []
        self._init_mapper()
        self.local = local.local()

    def _init_mapper(self):
        """Add all routes that were configured with the @expose() decorator."""
        for name in vars(self.__class__):
            method = getattr(self, name)
            if callable(method) and hasattr(method, 'path'):
                pattern = self._re_var.sub('(?P<\\1>[^/]+)', method.path)
                regex = re.compile(pattern)
                self.routes.append((regex, method.kwargs))

    def _match_routes(self, env):
        """Match a request against the set of routes."""
        url = env['PATH_INFO']
        method = env['REQUEST_METHOD']
        matchvars = { 'method': method }
        for regex,kwargs in self.routes:
            mobj = regex.match(url)
            if mobj is None:
                continue
            nomatch = [ var for var in matchvars
                        if var in kwargs and matchvars[var] != kwargs[var] ]
            if nomatch:
                continue
            match = mobj.groupdict().copy()
            match.update(kwargs)
            return match

    def _get_environ(self):
        return self.local.environ

    environ = property(_get_environ)

    def _get_headers(self):
        return self.local.headers

    headers = property(_get_headers)

    def __call__(self, env, start_response):
        """WSGI entry point."""
        logger = self.logger
        self.local.environ = env
        self.local.headers = []
        self.local.start_response = start_response
        logger.debug('server request: %s %s', env['REQUEST_METHOD'], env['PATH_INFO'])
        match = self._match_routes(env)
        if not match:
            return self._simple_response(http.NOT_FOUND)
        for key in match:
            env['mapper.%s' % key] = match[key]
        ctype = env.get('CONTENT_TYPE')
        if ctype:
            if ctype != 'text/json':
                return self._simple_response(http.UNSUPPORTED_MEDIA_TYPE)
            entity = env['wsgi.input'].read()
            entity = json.try_loads(entity)
            if entity is None:
                return self._simple_response(http.BAD_REQUEST)
            self.entity = entity
        else:
            self.entity = None
        handler = getattr(self,  match['handler'])
        try:
            result = handler(env)
        except HTTPReturn, e:
            return self._simple_response(e.status, e.headers)
        except Exception:
            lines = ['An uncaught exception occurred\n']
            lines += traceback.format_exception(*sys.exc_info())
            self.logger.error(''.join(lines))
            return self._simple_response(http.INTERNAL_SERVER_ERROR)
        if result is not None:
            result = json.dumps(result)
            self.headers.append(('Content-Type', 'text/json'))
        else:
            result = ''
        start_response('200 OK', self.headers)
        return [result]

    def _simple_response(self, status, headers=[]):
        """Return a simple text/plain response."""
        if isinstance(status, int):
            status = '%s %s' % (status, http.responses[status])
        headers.append(('Content-Type', 'text/plain'))
        headers.append(('Content-Length', str(len(status))))
        self.local.start_response(status, headers)
        return [status]


class SyncAPIApplication(WSGIApplication):
    """A WSGI application that implements our SyncAPI."""

    def __init__(self):
        super(SyncAPIApplication, self).__init__()
        self.crypto = CryptoProvider()
        self.allow_pairing = False
        self.key_exchanges = {}

    def _do_auth_hmac_cb(self, uuid):
        """Perform mutual HMAC_CB authentication."""
        wwwauth = create_option_header('HMAC_CB', realm=uuid)
        headers = [('WWW-Authenticate', wwwauth)]
        auth = self.environ.get('HTTP_AUTHORIZATION')
        if auth is None:
            raise HTTPReturn(http.UNAUTHORIZED, headers)
        try:
            method, options = parse_option_header(auth)
        except ValueError:
            raise HTTPReturn(http.UNAUTHORIZED, headers)
        if method != 'HMAC_CB':
            raise HTTPReturn(http.UNAUTHORIZED, headers)
        if 'name' in options:
            # pair step 1 - ask user for permission to pair
            name = options['name']
            if not self.allow_pairing:
                raise HTTPReturn('403 Pairing Disabled')
            bus = instance(MessageBusServer)
            kxid = self.crypto.random(16).encode('hex')
            pin = '%06d' % (self.crypto.randint(bits=31) % 1000000)
            approved = bus.call_method('client-*', 'get_pairing_approval',
                                       name, uuid, pin, kxid, timeout=60)
            if not approved:
                raise HTTPReturn('403 Approval Denied')
            restrictions = {}
            self.key_exchanges[kxid] = (time.time(), restrictions, pin)
            wwwauth = create_option_header('HMAC_CB', kxid=kxid)
            headers = [('WWW-Authenticate', wwwauth)]
            raise HTTPReturn(http.UNAUTHORIZED, headers)
        elif 'kxid' in options:
            # pair step 2 - check auth and do the actual pairing
            kxid = options['kxid']
            if kxid not in self.key_exchanges:
                raise HTTPReturn(http.FORBIDDEN)
            starttime, restrictions, pin = self.key_exchanges.pop(kxid)
            signature = base64.try_decode(options.get('signature', ''))
            if not signature:
                raise HTTPReturn(http.FORBIDDEN)
            now = time.time()
            if now - starttime > 60:
                raise HTTPReturn('403 Request Timeout')
            cb = self.environ['SSL_CHANNEL_BINDING_TLS_UNIQUE']
            check = self.crypto.hmac(adjust_pin(pin, +1), cb, 'sha1')
            if check != signature:
                raise HTTPReturn('403 Invalid PIN')
            bus = instance(MessageBusServer)
            bus.send_signal('client-*', 'PairingComplete', kxid)
            # Prove to the other side we also know the PIN
            signature = self.crypto.hmac(adjust_pin(pin, -1), cb, 'sha1')
            signature = base64.encode(signature)
            authinfo = create_option_header('HMAC_CB', kxid=kxid,
                                            signature=signature)
            self.headers.append(('Authentication-Info', authinfo))
        else:
            raise HTTPReturn(http.UNAUTHORIZED, headers)
 
    def _do_auth_rsa_cb(self, uuid):
        """Perform mutual RSA_CB authentication."""
        wwwauth = create_option_header('RSA_CB', realm=uuid)
        headers = [('WWW-Authenticate', wwwauth)]
        auth = self.environ.get('HTTP_AUTHORIZATION')
        if auth  is None:
            raise HTTPReturn(http.UNAUTHORIZED, headers)
        try:
            method, opts = parse_option_header(auth)
        except ValueError:
            raise HTTPReturn(http.UNAUTHORIZED, headers)
        if method != 'RSA_CB':
            raise HTTPReturn(http.UNAUTHORIZED, headers)
        if 'node' not in opts or not check_uuid4(opts['node']):
            raise HTTPReturn(http.UNAUTHORIZED, headers)
        if 'signature' not in opts or not base64.check(opts['signature']):
            raise HTTPReturn(http.UNAUTHORIZED, headers)
        model = instance(Model)
        cert = model.get_certificate(uuid, opts['node'])
        if cert is None:
            raise HTTPReturn(http.UNAUTHORIZED, headers)
        signature = base64.decode(opts['signature'])
        pubkey = base64.decode(cert['payload']['keys']['auth']['key'])
        cb = self.environ['SSL_CHANNEL_BINDING_TLS_UNIQUE']
        if not self.crypto.rsa_verify(cb, signature, pubkey, 'pss-sha1'):
            raise HTTPReturn(http.UNAUTHORIZED, headers)
        # The peer was authenticated. Authenticate ourselves as well.
        privkey = model.get_auth_key(uuid)
        vault = model.get_vault(uuid)
        node = vault['node']
        signature = self.crypto.rsa_sign(cb, privkey, 'pss-sha1')
        signature = base64.encode(signature)
        auth = create_option_header('RSA_CB', node=node, signature=signature)
        self.headers.append(('Authentication-Info', auth))

    @expose('/api/vaults/:vault/pair', method='POST')
    def pair(self, env):
        uuid = env['mapper.vault']
        if not check_uuid4(uuid):
            raise HTTPReturn(http.NOT_FOUND)
        model = instance(Model)
        vault = model.get_vault(uuid)
        if not vault:
            raise HTTPReturn(http.NOT_FOUND)
        self._do_auth_hmac_cb(uuid)
        # Sign the certificate that was sent to tus
        certinfo = self.entity
        if not certinfo or not isinstance(certinfo, dict):
            raise HTTPReturn(http.BAD_REQUEST)
        model.add_certificate(uuid, certinfo)
        # And send our own certificate in return
        certinfo = { 'node': vault['node'], 'name': socket.gethostname() }
        certkeys = certinfo['keys'] = {}
        for key in vault['keys']:
            certkeys[key] = { 'key': vault['keys'][key]['public'],
                              'keytype': vault['keys'][key]['keytype'] }
        return certinfo

    @expose('/api/vaults/:vault/items', method='GET')
    def sync_outbound(self, env):
        uuid = env['mapper.vault']
        if not check_uuid4(uuid):
            raise HTTPReturn(http.NOT_FOUND)
        model = instance(Model)
        vault = model.get_vault(uuid)
        if vault is None:
            raise HTTPReturn(http.NOT_FOUND)
        self._do_auth_rsa_cb(uuid)
        args = parse_qs(env.get('QUERY_STRING', ''))
        vector = args.get('vector', [''])[0]
        if vector:
            try:
                vector = parse_vector(vector)
            except ValueError:
                raise HTTPReturn(http.BAD_REQUEST)
        items = model.get_items(uuid, vector)
        myvector = model.get_vector(uuid)
        self.headers.append(('X-Vector', dump_vector(myvector)))
        return items

    @expose('/api/vaults/:vault/items', method='POST')
    def sync_inbound(self, env):
        uuid = env['mapper.vault']
        if not check_uuid4(uuid):
            raise HTTPReturn(http.NOT_FOUND)
        model = instance(Model)
        vault = model.get_vault(uuid)
        if vault is None:
            raise HTTPReturn(http.NOT_FOUND)
        self._do_auth_rsa_cb(uuid)
        items = self.entity
        if items is None or not isinstance(items, list):
            raise HTTPReturn(http.BAD_REQUEST)
        model.import_items(uuid, items)


class SyncAPIHandler(WSGIHandler):

    def get_environ(self):
        env = super(SyncAPIHandler, self).get_environ()
        env['SSL_CIPHER'] = self.socket.cipher()
        cb = self.socket.get_channel_binding('tls-unique')
        env['SSL_CHANNEL_BINDING_TLS_UNIQUE'] = cb
        return env


class SyncAPIServer(WSGIServer):
    """The WSGI server that runs the syncapi."""

    handler_class = SyncAPIHandler

    def __init__(self, listener, application, **ssl_args):
        ssl_args.setdefault('dhparams', dhparams['skip2048'])
        ssl_args.setdefault('ciphers', 'ADH+AES')
        super(SyncAPIServer, self).__init__(listener, application, spawn=10,
                                            log=None, **ssl_args)
        self.wrap_socket = wrap_socket


class SyncAPIPublisher(Greenlet):
    """Sync API publisher.

    The Publisher is responsible for publising the location of our syncapi
    via the Locator, and keeping these published locations up to date.

    The publisher needs to make calls to the locator which might block,
    and therefore runs in its own greenlet.
    """

    def __init__(self, server):
        super(SyncAPIPublisher, self).__init__()
        self.server = server
        self.queue = []
        self.queue_notempty = Event()
        self.published_nodes = set()
        self.allow_pairing = False
        self.allow_pairing_until = None
        self.callbacks = []

    def add_callback(self, callback):
        """Add a callback that gets notified of events."""
        self.callbacks.append(callback)

    def raise_event(self, event, *args):
        """Raise an event to all registered callbacks."""
        for callback in self.callbacks:
            callback(event, *args)

    def set_allow_pairing(self, timeout):
        """Allow pairing for up to `timeout` seconds. Use a timeout
        of zero to disable pairing."""
        self.queue.append(('allow_pairing', (timeout,)))
        self.queue_notempty.set()

    def stop(self):
        """Stop the publisher."""
        self.queue.append(('stop', None))
        self.queue_notempty.set()

    def _event_callback(self, event, *args):
        self.queue.append((event, args))
        self.queue_notempty.set()

    def _get_hostname(self):
        name = socket.gethostname()
        pos = name.find('.')
        if pos != -1:
            name = name[:pos]
        return name

    def _run(self):
        """Main execution loop, runs in its own greenlet."""
        logger = logging.getLogger(__name__)
        locator = instance(Locator)
        self.locator = locator
        model = instance(Model)
        model.add_callback(self._event_callback)
        nodename = self._get_hostname()
        vaults = model.get_vaults()
        for vault in vaults:
            locator.register(vault['node'], nodename, vault['id'],
                             vault['name'], self.server.address)
            logger.debug('published node %s', vault['node'])
            self.published_nodes.add(vault['node'])
        stopped = False
        while not stopped:
            timeout = self.allow_pairing_until - time.time() \
                        if self.allow_pairing else None
            self.queue_notempty.wait(timeout)
            self.queue_notempty.clear()
            while self.queue:
                event, args = self.queue.pop(0)
                logger.debug('processing event: %s', event)
                if event == 'allow_pairing':
                    timeout = args[0]
                    if timeout > 0:
                        self.allow_pairing = True
                        self.allow_pairing_until = time.time() + timeout
                        for node in self.published_nodes:
                            locator.set_property(node, 'visible', 'true')
                            logger.debug('make node %s visible', node)
                        instance(SyncAPIApplication).allow_pairing = True
                        self.raise_event('AllowPairingStarted', timeout)
                    else:
                        self.allow_pairing = False
                        self.allow_pairing_until = None
                        for node in self.published_nodes:
                            locator.set_property(node, 'visible', 'false')
                            logger.debug('make node %s invisible (user)', node)
                        instance(SyncAPIApplication).allow_pairing = False
                        self.raise_event('AllowPairingEnded')
                elif event == 'VaultAdded':
                    vault = args[0]
                    node = vault['node']
                    if node in self.published_nodes:
                        logger.error('got VaultAdded signal for published node')
                        continue
                    properties = {}
                    if self.allow_pairing:
                        properties['visible'] = 'true'
                    locator.register(node, nodename, vault['id'], vault['name'],
                                     self.server.address, properties)
                    self.published_nodes.add(node)
                    logger.debug('published node %s', node)
                elif event == 'VaultRemoved':
                    vault = args[0]
                    node = vault['node']
                    if node not in self.published_nodes:
                        logger.error('got VaultRemoved signal for unpublished node')
                        continue
                    locator.unregister(node)
                    self.published_nodes.remove(node)
                    logger.debug('unpublished node %s', node)
                elif event == 'stop':
                    stopped = True
            now = time.time()
            if self.allow_pairing and now >= self.allow_pairing_until:
                for node in self.published_nodes:
                    self.locator.set_property(node, 'visible', 'false')
                    logger.debug('make node %s invisible (timeout)', node)
                self.allow_pairing = False
                self.allow_pairing_until = None
                instance(SyncAPIApplication).allow_pairing = False
                self.raise_event('AllowPairingEnded')
            logger.debug('done processing queue, sleeping')
        logger.debug('shutting down publisher')
