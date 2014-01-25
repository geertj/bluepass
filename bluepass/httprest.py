#
# This file is part of Bluepass. Bluepass is Copyright (c) 2012-2014
# Geert Jansen.
#
# Bluepass is free software available under the GNU General Public License,
# version 3. See the file LICENSE distributed with this file for the exact
# licensing terms.

from __future__ import absolute_import, print_function

import re
import six

import gruvi
from gruvi import http

from . import validate, logging, json
from .errors import *
from ._version import version_info

__all__ = ['anonymous', 'route', 'validate_entity', 'get_link',
           'HttpReturn', 'HttpRestHandler']


def anonymous(func):
    """Decorator to mark a handler as not requiring authentication."""
    func.anonymous = True
    return func

def route(path, method=None, entity=None):
    """Decorator to expose a handler via a Rails like route."""
    def decorate(func):
        func.path = path.rstrip('/')
        func.method = method
        func.entity = entity
        return func
    return decorate

def validate_entity(fmt):
    """Decorator to validate a request entity."""
    def decorate(func):
        func.entity_validator = validate.compile(fmt)
        return func
    return decorate


def get_link(res, rel):
    """Get a HATEOAS link from an entity."""
    if rel == 'href':
        return res.get('_href')
    for link in res.get('_links', []):
        if link.get('rel') == rel:
            return link.get('href')


class HttpReturn(Exception):
    """When raised, this exception will issue a HTTP return."""

    def __init__(self, status, headers=[], body=None):
        super(HttpReturn, self).__init__(status, headers, body)


class HttpRestHandler(object):
    """A RESTful HTTP handler.
    
    This class implements a RESTful nanoframework on top of WSGI. It provides
    Rails-like routing, URL validation, JSON serialization/validation, and
    HATEOAS link generation.
    """

    _re_route_var = re.compile('\{([^:>]+)(:[^}]+)?\}')

    def __init__(self, prefix=None):
        self._prefix = prefix or ''
        self._log = logging.get_logger(self)
        self._init_handlers()
        self._local = gruvi.local()

    def _init_handlers(self):
        """Add all handlers that were configured with the @route() decorator."""
        self._handlers = []
        for name in dir(self):
            try:
                handler = getattr(self, name)
            except AttributeError:
                continue  # property getter fails
            if not callable(handler) or not hasattr(handler, 'path'):
                continue
            pattern = self._re_route_var.sub('(?P<\\1>[^/]+)', handler.path)
            handler.__func__.regex = re.compile('^{0}{1}$'.format(self._prefix, pattern))
            handler.__func__.url_validator = dict(((k, validate.compile(v[1:])) for (k,v) in
                                    self._re_route_var.findall(handler.path) if v))
            if not hasattr(handler, 'entity_validator'):
                handler.__func__.entity_validator = None
            if not hasattr(handler, 'anonymous'):
                handler.__func__.anonymous = False
            self._handlers.append(handler)

    def find_handler(self, path, method):
        """Match a request against the set of routes."""
        altmethods = []
        for handler in self._handlers:
            mobj = handler.regex.match(path)
            if mobj is None:
                continue
            mvars = mobj.groupdict()
            verrors = [v.match(mvars[k]) for k,v in handler.url_validator.items()]
            if False in verrors:
                continue
            if handler.method and handler.method != method:
                if handler.method not in altmethods:
                    altmethods.append(handler.method)
                continue
            return handler, mobj
        return None, altmethods

    def url_for(self, handler, **args):
        def replace_var(mobj):
            name = mobj.group(1)
            return args[name] if name in args else '{{{0}}}'.format(name)
        return self._prefix + self._re_route_var.sub(replace_var, handler.path)

    def add_links(self, res, **links):
        """Add HATEOAS style links to the (list of) resource(s) *res*."""
        if res is None:
            return
        elif isinstance(res, list):
            for elem in res:
                self.add_links(elem, **links)
            return res
        for name,handler in links.items():
            url = self.url_for(handler, **res) if callable(handler) else handler
            if name == 'href':
                if handler.entity:
                    res['_href'] = url
                    res['_type'] = handler.entity
            else:
                if '_links' not in res:
                    res['_links'] = []
                res['_links'].append({'rel': name, 'href': url})
        return res

    def remove_links(self, res):
        """Remove the links added by :meth:`add_links`."""
        if res is None:
            return
        elif isinstance(res, list):
            for elem in res:
                self.remove_links(elem)
            return res
        for attr in ('_type', '_href', '_links'):
            if attr in res:
                del res[attr]
        return res

    @property
    def environ(self):
        return self._local.environ

    def _get_status(self):
        return self._local.status

    def _set_status(self, status):
        self._local.status = status

    status = property(_get_status, _set_status)

    @property
    def headers(self):
        return self._local.headers

    def _new_request(self, env, start_response):
        """Initialize local data for a new request."""
        self._local.environ = env
        self._local.status = '200 OK'
        server = '{0}/{1}'.format(version_info['name'].title(), version_info['version'])
        self._local.headers = [('Server', server)]
        self._local.start_response = start_response

    def __call__(self, env, start_response):
        """WSGI entry point."""
        self._new_request(env, start_response)
        method = env['REQUEST_METHOD']
        path = env['SCRIPT_NAME'] + env['PATH_INFO']
        # Find the handler for our request
        handler, match = self.find_handler(path, method)
        if not handler:
            if method == 'HEAD' and 'GET' in match:
                # Default action for HEAD is GET without the entity
                handler, match = self.find_handler(path, method='GET')
                assert handler is not None
            elif method == 'OPTIONS' or match:
                # Show alternative methods
                headers = [('Allow', ','.join(match + ['OPTIONS']))]
                status = http.NO_CONTENT if method == 'OPTIONS' else http.METHOD_NOT_ALLOWED
                return self.create_response(status, headers)
            else:
                return self.create_response(http.NOT_FOUND)
        # Authenticate
        if not handler.anonymous:
            try:
                self.authenticate(env)
            except Exception as e:
                return self.create_error(e)
        # Try to parse an application/json entity
        ctype = env.get('CONTENT_TYPE')
        if ctype:
            ctype, options = http.split_header_options(ctype)
            if ctype != 'application/json':
                return self.create_response(http.UNSUPPORTED_MEDIA_TYPE)
            charset = options.get('charset', 'UTF-8').lower()
            if charset not in ('utf-8', 'iso-8858-1'):
                return self.create_response(http.BAD_REQUEST)
            body = env['wsgi.input'].read()
            decoded = body.decode(charset)
            entity = json.try_loads(decoded, dict)
            if entity is None:
                return self.create_response(http.BAD_REQUEST)
            self.remove_links(entity)
        else:
            entity = None
        # Validate the entity
        validator = handler.entity_validator
        if validator:
            try:
                validator.validate_raise(entity)
            except ValidationError as e:
                return self.create_error(e)
        env['rest.entity'] = entity
        # Call the handler!
        try:
            result = handler(*match.groups())
        except Exception as e:
            return self.create_error(e)
        return self.create_response(entity=result)

    def create_error(self, exc):
        """Create an error response for exception *exc*."""
        if isinstance(exc, HttpReturn):
            return self.create_response(*exc.args)
        self._log.exception('uncaught exception handling request')
        return self.create_response(http.INTERNAL_SERVER_ERROR)

    def create_response(self, status=None, headers=[], entity=None):
        """Create an http response."""
        status = status or self.status
        if isinstance(status, int):
            status = '{0} {1}'.format(status, http.responses[status])
        headers = self.headers + headers
        if entity is None and status[0] in '45':
            entity = six.u(status + '\n')
        if isinstance(entity, (dict, list)):
            contents = [json.dumps_pretty(entity).encode('utf8')]
            headers.append(('Content-Type', 'application/json; charset=UTF-8'))
            headers.append(('Content-Length', len(contents[0])))
        elif isinstance(entity, six.text_type):
            contents = [entity.encode('utf8')]
            headers.append(('Content-Type', 'text/plain; charset=UTF-8'))
            headers.append(('Content-Length', len(contents[0])))
        elif isinstance(entity, six.binary_type):
            headers.append(('Content-Length', len(contents[0])))
            contents = [entity]
        elif entity is None:
            headers.append(('Content-Length', '0'))
            contents = []
        else:
            contents = entity
        self._local.start_response(status, headers)
        if self.environ['REQUEST_METHOD'] == 'HEAD':
            return []
        return contents
