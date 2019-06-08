"""
This module provides a reverse HTTP proxy. This way, we only expose two
ports: one for HTTP and one for HTTPS.

The other applications (Flask, WebDAV, possibly more in the future) are
bound to a local interface.

This way, it's much easier to handle TLS encryption.
"""

from twisted.internet import reactor, ssl
from twisted.web.proxy import ReverseProxyResource
from twisted.web.server import Site
from twisted.web.resource import Resource

from powerhub.args import args

import logging
log = logging.getLogger(__name__)


class DynamicProxy(Resource):
    isLeaf = False
    allowedMethods = ("GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS")

    def getChild(self, path, request):
        path = path.decode()
        log.debug("Reverse proxy request: %s" % path)
        resource = path.split('/')[0].encode()
        path = '/'.join(path.split('/')[1:])
        host = '127.0.0.1'
        path = path.encode()
        if resource == b"webdav":
            log.info("Forwarding to WebDAV server")
            return ReverseProxyResource(host, args.WEBDAV_PORT, path)
        else:
            log.info("Forwarding to Flask server")
            new_path = b'/%s' % (resource,)
            if path:
                new_path += b'/%s' % path
            return ReverseProxyResource(host, args.FLASK_PORT, new_path)


proxy = DynamicProxy()
site = Site(proxy)
reactor.listenTCP(args.LPORT, site, interface=args.LHOST)
if args.SSL_KEY and args.SSL_CERT:
    reactor.listenSSL(args.SSL_PORT,
                      site,
                      ssl.DefaultOpenSSLContextFactory(
                          args.SSL_KEY.encode(),
                          args.SSL_CERT.encode(),
                      ),
                      interface=args.LHOST,
                      )
