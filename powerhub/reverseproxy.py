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
from powerhub.tools import get_self_signed_cert

import logging
log = logging.getLogger(__name__)


class DynamicProxy(Resource):
    isLeaf = False
    allowedMethods = ("GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS")

    def getChild(self, path, request):
        path = path.decode()
        resource = path.split('/')[0].encode()
        path = '/'.join(path.split('/')[1:])
        host = '127.0.0.1'
        x_forwarded_for = request.client.host
        x_for_host = request.host.host
        x_for_port = request.host.port
        if x_for_port == args.SSL_PORT:
            x_for_proto = "https"
        else:
            x_for_proto = "http"
        for header in [
            ('X-Forwarded-For', x_forwarded_for),
            ('X-Forwarded-Host', x_for_host),
            ('X-Forwarded-Port', x_for_port),
            ('X-Forwarded-Proto', x_for_proto),
        ]:
            request.requestHeaders.addRawHeader(*header)
        path = path.encode()
        if resource == b"webdav":
            log.debug("Forwarding request to WebDAV server")
            return ReverseProxyResource(host, args.WEBDAV_PORT, path)
        else:
            log.debug("Forwarding request to Flask server")
            new_path = b'/%s' % (resource,)
            if path:
                new_path += b'/%s' % path
            return ReverseProxyResource(host, args.FLASK_PORT, new_path)


def run_proxy():
    proxy = DynamicProxy()
    site = Site(proxy)
    reactor.listenTCP(args.LPORT, site, interface=args.LHOST)

    if not args.SSL_KEY or not args.SSL_CERT:
        args.SSL_CERT, args.SSL_KEY = get_self_signed_cert(args.URI_HOST)
    reactor.listenSSL(args.SSL_PORT,
                      site,
                      ssl.DefaultOpenSSLContextFactory(
                          args.SSL_KEY.encode(),
                          args.SSL_CERT.encode(),
                      ),
                      interface=args.LHOST,
                      )
    reactor.run()
