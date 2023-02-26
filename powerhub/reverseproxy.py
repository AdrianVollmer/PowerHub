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

from powerhub.tools import get_self_signed_cert
from powerhub.directories import directories

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
    def __init__(self, *args, _args=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.args = _args

    def buildProtocol(self, addr):
        allowlist = self.args.ALLOWLIST
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

        if allow:
            return Site.buildProtocol(self, addr)
        else:
            log.warning("Block request from %s" % addr.host)


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


class DynamicProxy(Resource):
    isLeaf = False
    allowedMethods = ("GET", "POST", "PUT", "DELETE", "HEAD",
                      "PROPFIND", "OPTIONS")

    def __init__(self, *args, _args=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.args = _args

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
        if x_for_port == self.args.SSL_PORT:
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
                                        self.args.WEBDAV_PORT,
                                        new_path)
        else:
            log.debug("Forwarding request to Flask server")
            new_path = b'/%s' % (resource,)
            if path:
                new_path += b'/%s' % path
            return ReverseProxyResource(host, self.args.FLASK_PORT, new_path)


def run_proxy(args):
    # Shut up twisted
    observer = PythonLoggingObserver()
    observer.start()
    logging.getLogger('twisted').setLevel(logging.CRITICAL+1)

    proxy = DynamicProxy(_args=args)
    site = FilteredSite(proxy, _args=args)
    reactor.listenTCP(args.LPORT, site, interface=args.LHOST)

    if not args.SSL_KEY or not args.SSL_CERT:
        cert_dir = directories.CERT_DIR
        args.SSL_CERT, args.SSL_KEY = \
            get_self_signed_cert(args.URI_HOST, cert_dir)

    pem_data = open(args.SSL_CERT, "br").read()
    cert = x509.load_pem_x509_certificate(pem_data, default_backend())

    global FINGERPRINT
    FINGERPRINT = cert.fingerprint(hashes.SHA1()).hex()

    reactor.listenSSL(
        args.SSL_PORT,
        site,
        OpenSSLContextFactoryChaining(
            args.SSL_KEY.encode(),
            args.SSL_CERT.encode(),
        ),
        interface=args.LHOST,
    )

    log.info("Web interface accessible on http://%s:%d and https://%s:%d" % (
        args.URI_HOST,
        args.LPORT,
        args.URI_HOST,
        args.SSL_PORT,
    ))

    reactor.run()
