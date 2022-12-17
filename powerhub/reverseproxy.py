"""
This module provides a reverse HTTP proxy. This way, we only expose two
ports: one for HTTP and one for HTTPS.

The other applications (Flask, WebDAV, possibly more in the future) are
bound to a local interface.

This way, it's much easier to handle TLS encryption.
"""
import logging
import ipaddress

from twisted.internet import reactor, ssl
from twisted.web.proxy import ReverseProxyResource
from twisted.web.server import Site
from twisted.web.resource import Resource
from twisted.python.log import PythonLoggingObserver

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

from powerhub.env import powerhub_app as ph_app
from powerhub.tools import get_self_signed_cert

log = logging.getLogger(__name__)


# Override DefaultOpenSSLContextFactory to call ctx.use_certificate_chain_file
# instead of ctx.use_certificate_file and to allow certificate chains to be
# loaded.
# Credit: https://github.com/twonds/punjab/blob/master/punjab/ssl.py
# MIT Licensed: Original Author: Christopher Zorn aka twonds
class OpenSSLContextFactoryChaining(ssl.DefaultOpenSSLContextFactory):
    def __init__(self, *args, **kwargs):
        ssl.DefaultOpenSSLContextFactory.__init__(self, *args, **kwargs)

    def cacheContext(self):
        ctx = self._contextFactory(self.sslmethod)
        ctx.use_certificate_chain_file(self.certificateFileName)
        ctx.use_privatekey_file(self.privateKeyFileName)
        self._context = ctx


class FilteredSite(Site):
    def buildProtocol(self, addr):
        allowlist = ph_app.args.ALLOWLIST
        allow = True

        if allowlist and not addr.host == '127.0.0.1':
            allow = False

            for a in allowlist:
                if (
                    addr.host == a
                    or ipaddress.ip_address(addr.host) in ipaddress.ip_network(a)
                ):
                    allow = True
                    break

            log.warning("Block request from %s" % addr.host)

        if allow:
            return Site.buildProtocol(self, addr)


class DynamicProxy(Resource):
    isLeaf = False
    allowedMethods = ("GET", "POST", "PUT", "DELETE", "HEAD",
                      "PROPFIND", "OPTIONS")

    def getChild(self, path, request):
        path = path.decode()
        log.debug("%s - %s" % (request.client.host, path))
        resource = path.split('/')[0].encode()
        path = '/'.join(path.split('/')[1:])
        host = '127.0.0.1'
        x_forwarded_for = request.client.host
        x_for_host = request.requestHeaders.getRawHeaders('host')
        if x_for_host:
            x_for_host = x_for_host[0].split(':')[0]
        else:
            x_for_host = ""
        x_for_port = request.host.port
        if x_for_port == ph_app.args.SSL_PORT:
            x_for_proto = "https"
        else:
            x_for_proto = "http"
        for header in [
            ('X-Forwarded-For', x_forwarded_for),
            ('X-Forwarded-Host', x_for_host),
            ('X-Forwarded-Port', str(x_for_port)),
            ('X-Forwarded-Proto', x_for_proto),
        ]:
            request.requestHeaders.addRawHeader(*header)
        path = path.encode()
        if resource.startswith(b"webdav"):
            new_path = b'/%s' % (resource,)
            if path:
                new_path += b'/%s' % path
            log.debug("Forwarding request to WebDAV server: %s" %
                      path.decode())
            return ReverseProxyResource(host,
                                        ph_app.args.WEBDAV_PORT,
                                        new_path)
        else:
            log.debug("Forwarding request to Flask server")
            new_path = b'/%s' % (resource,)
            if path:
                new_path += b'/%s' % path
            return ReverseProxyResource(host, ph_app.args.FLASK_PORT, new_path)


def run_proxy():
    # Shut up twisted
    observer = PythonLoggingObserver()
    observer.start()
    logging.getLogger('twisted').setLevel(logging.CRITICAL+1)

    proxy = DynamicProxy()
    site = FilteredSite(proxy)
    reactor.listenTCP(ph_app.args.LPORT, site, interface=ph_app.args.LHOST)

    if not ph_app.args.SSL_KEY or not ph_app.args.SSL_CERT:
        ph_app.args.SSL_CERT, ph_app.args.SSL_KEY = \
                get_self_signed_cert(ph_app.args.URI_HOST)

    pem_data = open(ph_app.args.SSL_CERT, "br").read()
    cert = x509.load_pem_x509_certificate(pem_data, default_backend())

    global FINGERPRINT
    FINGERPRINT = cert.fingerprint(hashes.SHA1()).hex()

    reactor.listenSSL(
        ph_app.args.SSL_PORT,
        site,
        OpenSSLContextFactoryChaining(
            ph_app.args.SSL_KEY.encode(),
            ph_app.args.SSL_CERT.encode(),
        ),
        interface=ph_app.args.LHOST,
    )

    log.info("Web interface accessible on http://%s:%d and https://%s:%d" % (
        ph_app.args.URI_HOST,
        ph_app.args.LPORT,
        ph_app.args.URI_HOST,
        ph_app.args.SSL_PORT,
    ))

    reactor.run()
