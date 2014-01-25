#
# This file is part of Bluepass. Bluepass is Copyright (c) 2012-2014
# Geert Jansen.
#
# Bluepass is free software available under the GNU General Public License,
# version 3. See the file LICENSE distributed with this file for the exact
# licensing terms.

from __future__ import absolute_import, print_function

import os
import re
import sys
import time
import logging
import binascii
import socket
import ssl

try:
    import httplib as http
    from urlparse import parse_qs
except ImportError:
    from http import client as http
    from urllib.parse import parse_qs

import gruvi
from gruvi import Fiber, compat, util
from gruvi.http import HttpServer, HttpClient

from . import _version, json, base64, uuid4, util, logging, crypto
from .errors import *
from .factory import instance, singleton
from .model import Model
from .locator import Locator
from ._version import version_info

__all__ = ['SyncApiError', 'SyncApiClient', 'SyncApiApplication',
           'SyncApiServer', 'SyncApiPublisher']


class SyncApiError(Error):
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
    for key,value in kwargs.items():
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
        if not uuid4.check(uuid):
            raise ValueError('Illegal UUID')
        seqno = int(seqno)
        result.append((uuid, seqno))
    return result

def dump_vector(vector):
    """Dump an up-to-date vector."""
    vec = ','.join(['%s:%s' % (uuid, seqno) for (uuid, seqno) in vector])
    #if isinstance(vec, unicode):
    #    vec = vec.encode('iso-8859-1')  # XXX: investiage
    return vec


class SyncApiClient(object):
    """
    SyncApi client.

    This classs implements a client to the Bluepass HTTP based synchronization
    API. The two main functions are pairing (pair_step1() and pair_step2())
    and synchronization (sync()).
    """

    def __init__(self):
        """Create a new client for the syncapi API at `address`."""
        self.address = None
        self.connection = None
        self._log = logging.get_logger(self)

    def _make_request(self, method, url, headers=None, body=None):
        """Make an HTTP request to the API.
        
        This returns the HTTPResponse object on success, or None on failure.
        """
        headers = [] if headers is None else headers[:]
        agent = '{0}/{1}'.format(version_info['name'].title(), version_info['version'])
        headers.append(('User-Agent', agent))
        headers.append(('Accept', 'text/json'))
        if body is None:
            body = b''
        else:
            body = json.dumps(body).encode('utf8')
            headers.append(('Content-Type', 'text/json'))
        connection = self.connection
        assert connection is not None
        try:
            self._log.debug('client request: {} {}', method, url)
            connection.request(method, url, headers, body)
            response = connection.getresponse()
            body = response.read()
        except gruvi.Error as e:
            self._log.error('error when making HTTP request: {}', str(e))
            return
        ctype = response.get_header('Content-Type')
        if ctype == 'text/json':
            parsed = json.try_loads(body.decode('utf8'))
            if parsed is None:
                self._log.error('response body contains invalid JSON')
                return
            response.entity = parsed
            self._log.debug('parsed "{}" request body ({} bytes)', ctype, len(body))
        else:
            response.entity = None
        return response

    def connect(self, address):
        """Connect to the remote syncapi."""
        dhparams = util.asset('pem', 'dhparams.pem')
        if compat.PY3:
            context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
            context.set_ciphers('ADH+AES')
            context.load_dh_params(dhparams)
            sslargs = {'context': context}
        else:
            sslargs = {'ciphers': 'ADH+AES', 'dh_params': dhparams}
        connection = HttpClient()
        try:
            connection.connect(address, ssl=True, **sslargs)
        except gruvi.Error as e:
            self._log.error('could not connect to {}:{}' % address)
            raise SyncApiError('Could not connect')
        self.address = address
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
        cb = self.connection.transport.ssl.get_channel_binding('tls-unique')
        signature = crypto.hmac(adjust_pin(pin, +1).encode('ascii'), cb, 'sha1')
        signature = base64.encode(signature)
        auth = create_option_header('HMAC_CB', kxid=kxid, signature=signature)
        headers = [('Authorization', auth)]
        return headers

    def _check_hmac_cb_auth(self, response, pin):
        """Check a server to client HMAC_CB auth."""
        authinfo = response.get_header('Authentication-Info', '')
        try:
            method, options = parse_option_header(authinfo)
        except ValueError:
            self._log.error('illegal Authentication-Info header: {}', authinfo)
            return False
        if 'signature' not in options or not base64.check(options['signature']):
            self._log.error('illegal Authentication-Info header: {}', authinfo)
            return False
        signature = base64.decode(options['signature'])
        cb = self.connection.transport.ssl.get_channel_binding('tls-unique')
        check = crypto.hmac(adjust_pin(pin, -1).encode('ascii'), cb, 'sha1')
        if check != signature:
            self._log.error('HMAC_CB signature did not match')
            return False
        return True

    def pair_step1(self, uuid, name):
        """Perform step 1 in a pairing exchange.
        
        If succesful, this returns a key exchange ID. On error, a SyncApiError
        exception is raised.
        """
        if self.connection is None:
            raise RuntimeError('Not connected')
        url = '/api/vaults/%s/pair' % uuid
        headers = [('Authorization', 'HMAC_CB name=%s' % name)]
        response = self._make_request('POST', url, headers)
        if response is None:
            raise SyncApiError('Could not make HTTP request')
        status = response.status
        if status != 401:
            self._log.error('expecting HTTP status 401 (got: {})', status)
            raise SyncApiError('HTTP {0}'.format(response.status))
        wwwauth = response.get_header('WWW-Authenticate', '')
        try:
            method, options = parse_option_header(wwwauth)
        except ValueError:
            raise SyncApiError('Illegal response')
        if method != 'HMAC_CB' or 'kxid' not in options:
            self._log.error('illegal WWW-Authenticate header: {}', wwwauth)
            raise SyncApiError('Illegal response')
        return options['kxid']

    def pair_step2(self, uuid, kxid, pin, certinfo):
        """Perform step 2 in pairing exchange.
        
        If successfull, this returns the peer certificate. On error, a
        SyncApiError is raised.
        """
        if self.connection is None:
            raise RuntimeError('Not connected')
        url = '/api/vaults/%s/pair' % uuid
        headers = self._get_hmac_cb_auth(kxid, pin)
        response = self._make_request('POST', url, headers, certinfo)
        if response is None:
            raise SyncApiError('Could not make syncapi request')
        status = response.status
        if status != 200:
            self._log.error('expecting HTTP status 200 (got: {})', status)
            raise SyncApiError('HTTP status {0}'.format(response.status))
        if not self._check_hmac_cb_auth(response, pin):
            raise SyncApiError('Illegal syncapi response')
        peercert = response.entity
        if peercert is None or not isinstance(peercert, dict):
            raise SyncApiError('Illegal syncapi response')
        return peercert

    def _get_rsa_cb_auth(self, uuid, model):
        """Return the headers for RSA_CB authentication."""
        cb = self.connection.transport.ssl.get_channel_binding('tls-unique')
        privkey = model.get_auth_key(uuid)
        assert privkey is not None
        signature = crypto.rsa_sign(cb, privkey, 'pss-sha1')
        signature = base64.encode(signature)
        vault = model.get_vault(uuid)
        auth = create_option_header('RSA_CB', node=vault['node'], signature=signature)
        headers = [('Authorization', auth)]
        return headers

    def _check_rsa_cb_auth(self, uuid, response, model):
        """Verify RSA_CB authentication."""
        authinfo = response.get_header('Authentication-Info', '')
        try:
            method, options = parse_option_header(authinfo)
        except ValueError:
            self._log.error('illegal Authentication-Info header')
            return False
        if 'signature' not in options or 'node' not in options \
                or not base64.check(options['signature']) \
                or not uuid4.check(options['node']):
            self._log.error('illegal Authentication-Info header')
            return False
        cb = self.connection.transport.ssl.get_channel_binding('tls-unique')
        signature = base64.decode(options['signature'])
        cert = model.get_certificate(uuid, options['node'])
        if cert is None:
            self._log.error('unknown node {} in RSA_CB authentication', node)
            return False
        pubkey = base64.decode(cert['payload']['keys']['auth']['key'])
        try:
            status = crypto.rsa_verify(cb, signature, pubkey, 'pss-sha1')
        except crypto.Error:
            self._log.error('corrupt RSA_CB signature')
            return False
        if not status:
            self._log.error('RSA_CB signature did not match')
        return status

    def sync(self, uuid, model, notify=True):
        """Synchronize vault `uuid` with the remote peer."""
        if self.connection is None:
            raise RuntimeError('Not connected')
        vault = model.get_vault(uuid)
        if vault is None:
            raise SyncApiError('Vault not found')
        vector = model.get_vector(uuid)
        vector = dump_vector(vector)
        url = '/api/vaults/%s/items?vector=%s' % (vault['id'], vector)
        headers = self._get_rsa_cb_auth(uuid, model)
        response = self._make_request('GET', url, headers)
        if not response:
            raise SyncApiError('Could not make HTTP request')
        status = response.status
        if status != 200:
            self._log.error('expecting HTTP status 200 (got: {})', status)
            raise SyncApiError('Illegal syncapi response')
        if not self._check_rsa_cb_auth(uuid, response, model):
            raise SyncApiError('Illegal syncapi response')
        initems = response.entity
        if initems is None or not isinstance(initems, list):
            raise SyncApiError('Illegal syncapi response')
        nitems = model.import_items(uuid, initems, notify=notify)
        self._log.debug('imported {} items into model', nitems)
        vector = response.get_header('X-Vector', '')
        try:
            vector = parse_vector(vector)
        except ValueError as e:
            self._log.error('illegal X-Vector header: {} ({})', vector, str(e))
            raise SyncApiError('Invalid response')
        outitems = model.get_items(uuid, vector)
        url = '/api/vaults/%s/items' % uuid
        response = self._make_request('POST', url, headers, outitems)
        if not response:
            raise SyncApiError('Illegal syncapi response')
        if status != 200:
            self._log.error('expecting HTTP status 200 (got: {})', status)
            raise SyncApiError('Illegal syncapi response')
        if not self._check_rsa_cb_auth(uuid, response, model):
            raise SyncApiError('Illegal syncapi response')
        self._log.debug('succesfully retrieved {} items from peer', len(initems))
        self._log.debug('succesfully pushed {} items to peer', len(outitems))
        return len(initems) + len(outitems)


def expose(path, **kwargs):
    """Decorator to expose a method via a Rails like route."""
    def _f(func):
        func.path = path
        func.kwargs = kwargs
        func.kwargs['handler'] = func.__name__
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
        self._log = logging.get_logger(self)
        self.routes = []
        self._init_mapper()
        self.local = gruvi.local()

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
        self.local.environ = env
        self.local.headers = []
        self.local.start_response = start_response
        self._log.debug('server request: {} {}', env['REQUEST_METHOD'], env['PATH_INFO'])
        match = self._match_routes(env)
        if not match:
            return self._simple_response(http.NOT_FOUND)
        for key in match:
            env['mapper.%s' % key] = match[key]
        ctype = env.get('CONTENT_TYPE')
        if ctype:
            if ctype != 'text/json':
                return self._simple_response(http.UNSUPPORTED_MEDIA_TYPE)
            body = env['wsgi.input'].read()
            entity = json.try_loads(body.decode('utf8'))
            if entity is None:
                return self._simple_response(http.BAD_REQUEST)
            self.entity = entity
        else:
            self.entity = None
        handler = getattr(self,  match['handler'])
        try:
            result = handler(env)
        except HTTPReturn as e:
            return self._simple_response(e.status, e.headers)
        except Exception:
            self._log.exception('uncaught exception in handler')
            return self._simple_response(http.INTERNAL_SERVER_ERROR)
        if result is not None:
            result = json.dumps(result).encode('utf8')
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


class SyncApiApplication(WSGIApplication):
    """A WSGI application that implements our SyncApi."""

    def __init__(self):
        super(SyncApiApplication, self).__init__()
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
            from bluepass.ctrlapi import ControlApiServer
            bus = instance(ControlApiServer)
            kxid = crypto.random_cookie()
            pin = '{0:06d}'.format(crypto.random_int(1000000))
            for client in bus.clients:
                # XXX: revise this
                if not getattr(client, '_ctrlapi_authenticated', False):
                    continue
                approved = bus.call_method(client, 'get_pairing_approval',
                                           name, uuid, pin, kxid)
                break
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
            check = crypto.hmac(adjust_pin(pin, +1).encode('ascii'), cb, 'sha1')
            if check != signature:
                raise HTTPReturn('403 Invalid PIN')
            from bluepass.ctrlapi import ControlApiServer
            bus = instance(ControlApiServer)
            for client in bus.clients:
                bus.send_notification(client, 'PairingComplete', kxid)
            # Prove to the other side we also know the PIN
            signature = crypto.hmac(adjust_pin(pin, -1).encode('ascii'), cb, 'sha1')
            signature = base64.encode(signature)
            authinfo = create_option_header('HMAC_CB', kxid=kxid, signature=signature)
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
        if 'node' not in opts or not uuid4.check(opts['node']):
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
        if not crypto.rsa_verify(cb, signature, pubkey, 'pss-sha1'):
            raise HTTPReturn(http.UNAUTHORIZED, headers)
        # The peer was authenticated. Authenticate ourselves as well.
        privkey = model.get_auth_key(uuid)
        vault = model.get_vault(uuid)
        node = vault['node']
        signature = crypto.rsa_sign(cb, privkey, 'pss-sha1')
        signature = base64.encode(signature)
        auth = create_option_header('RSA_CB', node=node, signature=signature)
        self.headers.append(('Authentication-Info', auth))

    @expose('/api/vaults/:vault/pair', method='POST')
    def pair(self, env):
        uuid = env['mapper.vault']
        if not uuid4.check(uuid):
            raise HTTPReturn(http.NOT_FOUND)
        model = instance(Model)
        vault = model.get_vault(uuid)
        if not vault:
            raise HTTPReturn(http.NOT_FOUND)
        self._do_auth_hmac_cb(uuid)
        # Sign the certificate request that was sent to tus
        certinfo = self.entity
        if not certinfo or not isinstance(certinfo, dict):
            raise HTTPReturn(http.BAD_REQUEST)
        model.add_certificate(uuid, certinfo)
        # And send our own certificate request in return
        certinfo = { 'node': vault['node'], 'name': socket.gethostname() }
        certkeys = certinfo['keys'] = {}
        vault = model.vaults[vault['id']]  # access 'keys'
        for key in vault['keys']:
            certkeys[key] = { 'key': vault['keys'][key]['public'],
                              'keytype': vault['keys'][key]['keytype'] }
        certinfo['restrictions'] = {}
        return certinfo

    @expose('/api/vaults/:vault/items', method='GET')
    def sync_outbound(self, env):
        uuid = env['mapper.vault']
        if not uuid4.check(uuid):
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
        if not uuid4.check(uuid):
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


class SyncApiServer(HttpServer):
    """The WSGI server that runs the syncapi."""

    def __init__(self):
        handler = singleton(SyncApiApplication)
        super(SyncApiServer, self).__init__(handler)

    def _get_environ(self, transport, message):
        env = super(SyncApiServer, self)._get_environ(transport, message)
        env['SSL_CIPHER'] = transport.ssl.cipher()
        cb = transport.ssl.get_channel_binding('tls-unique')
        env['SSL_CHANNEL_BINDING_TLS_UNIQUE'] = cb
        return env

    def listen(self, address):
        dhparams = util.asset('pem', 'dhparams.pem')
        if compat.PY3:
            context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
            context.set_ciphers('ADH+AES')
            context.load_dh_params(dhparams)
            sslargs = {'context': context}
        else:
            sslargs = {'ciphers': 'ADH+AES', 'dh_params': dhparams}
        super(SyncApiServer, self).listen(address, ssl=True, **sslargs)


class SyncApiPublisher(Fiber):
    """Sync API publisher.

    The Publisher is responsible for publising the location of our syncapi
    via the Locator, and keeping these published locations up to date.

    The publisher needs to make calls to the locator which might block,
    and therefore runs in its own fiber.
    """

    def __init__(self, server):
        super(SyncApiPublisher, self).__init__(target=self._run)
        self.server = server
        self.queue = gruvi.Queue()
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
        self.queue.put(('allow_pairing', (timeout,)))

    def stop(self):
        """Stop the publisher."""
        self.queue.put(('stop', None))

    def _event_callback(self, event, *args):
        self.queue.put((event, args))

    def _get_hostname(self):
        name = socket.gethostname()
        pos = name.find('.')
        if pos != -1:
            name = name[:pos]
        return name

    def _run(self):
        """Main execution loop, runs in its own fiber."""
        log = logging.get_logger(self)
        locator = instance(Locator)
        self.locator = locator
        model = instance(Model)
        model.add_callback(self._event_callback)
        nodename = self._get_hostname()
        vaults = model.get_vaults()
        for vault in vaults:
            addr = gruvi.getsockname(self.server.transport)
            locator.register(vault['node'], nodename, vault['id'], vault['name'], addr)
            log.debug('published node {}', vault['node'])
            self.published_nodes.add(vault['node'])
        stopped = False
        while not stopped:
            timeout = self.allow_pairing_until - time.time() \
                        if self.allow_pairing else None
            entry = self.queue.get(timeout)
            if entry:
                event, args = entry
                log.debug('processing event: {}', event)
                if event == 'allow_pairing':
                    timeout = args[0]
                    if timeout > 0:
                        self.allow_pairing = True
                        self.allow_pairing_until = time.time() + timeout
                        for node in self.published_nodes:
                            locator.set_property(node, 'visible', 'true')
                            log.debug('make node {} visible', node)
                        instance(SyncApiApplication).allow_pairing = True
                        self.raise_event('AllowPairingStarted', timeout)
                    else:
                        self.allow_pairing = False
                        self.allow_pairing_until = None
                        for node in self.published_nodes:
                            locator.set_property(node, 'visible', 'false')
                            log.debug('make node {} invisible (user)', node)
                        instance(SyncApiApplication).allow_pairing = False
                        self.raise_event('AllowPairingEnded')
                elif event == 'VaultAdded':
                    vault = args[0]
                    node = vault['node']
                    if node in self.published_nodes:
                        log.error('got VaultAdded signal for published node')
                        continue
                    properties = {}
                    if self.allow_pairing:
                        properties['visible'] = 'true'
                    addr = gruvi.getsockname(self.server.transport)
                    locator.register(node, nodename, vault['id'], vault['name'],
                                     addr, properties)
                    self.published_nodes.add(node)
                    log.debug('published node {}', node)
                elif event == 'VaultRemoved':
                    vault = args[0]
                    node = vault['node']
                    if node not in self.published_nodes:
                        log.error('got VaultRemoved signal for unpublished node')
                        continue
                    locator.unregister(node)
                    self.published_nodes.remove(node)
                    log.debug('unpublished node {}', node)
                elif event == 'stop':
                    stopped = True
            now = time.time()
            if self.allow_pairing and now >= self.allow_pairing_until:
                for node in self.published_nodes:
                    self.locator.set_property(node, 'visible', 'false')
                    log.debug('make node {} invisible (timeout)', node)
                self.allow_pairing = False
                self.allow_pairing_until = None
                instance(SyncApiApplication).allow_pairing = False
                self.raise_event('AllowPairingEnded')
            log.debug('done processing event')
        log.debug('shutting down publisher')
