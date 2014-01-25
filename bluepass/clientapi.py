#
# This file is part of Bluepass. Bluepass is Copyright (c) 2012-2014
# Geert Jansen.
#
# Bluepass is free software available under the GNU General Public License,
# version 3. See the file LICENSE distributed with this file for the exact
# licensing terms.

from __future__ import absolute_import, print_function

import sys
import six

import pyuv
from gruvi import http
from gruvi.http import HttpServer

from . import platform, util
from .errors import *
from .factory import *
from .model import *
from .httprest import *
from ._version import version_info

_errors = [ValidationError, NotFound, ModelError]


class ClientApiError(Error):
    """Client API error."""


class ClientApiHandler(HttpRestHandler):

    def __init__(self, prefix, model=None, ctrlapi=None):
        super(ClientApiHandler, self).__init__(prefix)
        from .model import Model
        self._model = model or instance(Model)
        from .ctrlapi import ControlApiServer
        self._ctrlapi = ctrlapi or instance(ControlApiServer)

    @property
    def model(self):
        return self._model

    @property
    def ctrlapi(self):
        return self._ctrlapi

    def authenticate(self, env):
        auth = env.get('HTTP_AUTHORIZATION')
        headers = [('WWW-Authenticate', 'Token')]
        if not auth:
            raise HttpReturn(http.UNAUTHORIZED, headers)
        method, options = http.split_header_options(auth, sep=' ')
        if method.lower() != 'token' or 'id' not in options:
            raise HttpReturn(http.UNAUTHORIZED, headers)
        if not self.model.validate_token(options['id'], 'client_api'):
            raise HttpReturn(http.UNAUTHORIZED, headers)

    def create_error(self, exc):
        """Handle an uncaught exception."""
        for error in _errors:
            if isinstance(exc, error):
                break
        else:
            return super(ClientApiHandler, self).create_error(exc)
        message = exc.args[0] if exc.args else exc.__doc__
        entity = {'code': exc.__class__.__name__, 'message': message}
        return self.create_response(http.BAD_REQUEST, entity=entity)

    # General

    @anonymous
    @route('/', method='GET', entity='api')
    def get_root(self):
        info = {}
        info['api_version'] = '1.0'
        impl = info['server_info'] = {}
        impl['name'] = version_info['name'].title()
        impl['version'] = version_info['version']
        impl['license'] = version_info['license']
        impl['python_version'] = '{0}.{1}.{2}'.format(*sys.version_info[:3])
        impl['platform'] = sys.platform
        impl['hostname'] = util.gethostname()
        return self.add_links(info, href=self.get_root, tokens=self.create_token,
                              vaults=self.get_vaults)

    @anonymous
    @route('/tokens', method='POST')
    @validate_entity('{method: str="auth_program", expires: int>=0}')
    def create_token(self):
        transport = self.environ['gruvi.transport']
        info = platform.get_peer_info(transport)
        if info is None:
            self._log.error('could not get peer info')
            raise HttpReturn(http.UNAUTHORIZED)
        request = self.environ['rest.entity']
        request.update(info._asdict())
        request['sha256sum'] = util.file_checksum(info.executable, 'sha256')
        authorized = self.ctrlapi.upcall('approve_client', request)
        if not authorized:
            raise HttpReturn()
        token = {'expires': request['expires'], 'rights': {'client_api': True}}
        self.model.add_token(token)
        token['_type'] = 'token'
        return token

    # Vaults

    @route('/vaults/{id:uuid}', method='GET', entity='vault')
    def get_vault(self, uuid):
        vault = self.model.get_vault(uuid)
        if vault is None:
            raise HttpReturn(http.NOT_FOUND)
        return self.add_links(vault, href=self.get_vault,
                              versions=self.url_for(self.get_versions, vault=uuid))

    @route('/vaults', method='GET')
    def get_vaults(self):
        vaults = self.model.get_vaults()
        return self.add_links(vaults, href=self.get_vault)

    # Versions

    @route('/vaults/{vault:uuid}/versions/{id:uuid}', method='GET', entity='version')
    def get_version(self, vault, uuid):
        vault = self.model.get_version(vault, uuid)
        return self.add_links(version, href=self.get_version)

    @route('/vaults/{vault:uuid}/versions', method='GET')
    def get_versions(self, vault):
        versions = self.model.get_versions(vault)
        return self.add_links(versions, href=self.get_version)

    @route('/vaults/{vault:uuid}/versions', method='POST')
    @validate_entity('{...}')
    def add_version(self, vault, version):
        entity = self.environ['rest.entity']
        version = self.model.add_version(vault, entity)
        self.add_links(version, href=self.get_version)
        self.headers.append(('Content-Location', get_link(version, 'href')))
        self.status = http.CREATED
        return version

    @route('/vaults/{vault:uuid}/versions/{id:uuid}', method='PATCH')
    @validate_entity('{id: uuid, ...}')
    def replace_version(self, vault, version):
        entity = self.environ['rest.entity']
        entity['id'] = version
        version = self.model.replace_version(vault, entity)
        return self.add_links(version, href=self.get_version)


class ClientApiServer(HttpServer):
    """Server class implementing the client API."""

    listen_port_low = 7120
    listen_port_high = 7129

    def __init__(self, **http_args):
        handler = ClientApiHandler('/api')
        super(ClientApiServer, self).__init__(handler, **http_args)

    def listen(self, **listen_args):
        low = self.listen_port_low
        high = self.listen_port_high
        for port in range(low, high+1):
            try:
                super(ClientApiServer, self).listen(('localhost', port), **listen_args)
            except pyuv.error.TCPError as e:
                if e.args[0] != pyuv.errno.UV_EADDRINUSE:
                    six.reraise(*sys.exc_info())
                continue
            else:
                break
        if self.transport is None:
            raise ClientApiError('could not bind to port {0}..{1}'.format(low, high))
