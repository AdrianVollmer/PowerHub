import argparse

parser = argparse.ArgumentParser(
    description="Leverage PowerShell to load sketchy code over HTTP"
)

parser.add_argument(
    '-p',
    '--lport',
    default=8000,
    dest="LPORT",
    type=int,
    help="the local port to listen on (default: 8000)"
)

parser.add_argument(
    '-wp',
    '--webdav-port',
    default=8001,
    dest="WEBDAV_PORT",
    type=int,
    help="the local port to listen on for the webdav server (default: 8001)"
)


parser.add_argument(
    '-k',
    '--key-file',
    dest="SSL_KEY",
    default=None,
    help="path to a file containing an RSA key in PEM format"
)

parser.add_argument(
    '-c',
    '--cert-file',
    dest="SSL_CERT",
    default=None,
    help="path to a file containing an X.509 certificate in PEM format"
)

parser.add_argument(
    '-rp', '--receiver-port', default=3333,
    dest="REC_PORT",
    type=int,
    help="the local port to listen on for the receiver "
         "(default: %(default)s)"
)

parser.add_argument(
    '-rh', '--receiver-host', default='0.0.0.0',
    dest="REC_HOST",
    type=str,
    help="the local bind address to listen on for the receiver "
         "(default: %(default)s)"
)

parser.add_argument(
    '-l', '--lhost', default='0.0.0.0',
    dest="LHOST",
    type=str,
    help="the local bind address to listen on (default: '0.0.0.0')"
)

parser.add_argument(
    dest="URI_HOST", type=str,
    help="the hostname or IP address where the target can reach the server"
)

parser.add_argument(
    '-u', '--uri-port', dest="URI_PORT", type=int,
    default=0,
    help="the port where the target can reach the server (default: LPORT)"
)

parser.add_argument(
    '--uri-path', dest="URI_PATH", type=str,
    default='',
    help="the URI path where the target can reach the server (default: '')"
)

parser.add_argument(
    '-d', '--debug', dest="DEBUG", default=False, action="store_true",
    help=("show debug messages"))

auth_group = parser.add_mutually_exclusive_group()

auth_group.add_argument(
    '--auth', dest="AUTH", type=str,
    default="",
    help=("define credentials for basic authentication in the form of \
          'user:pass'"))


auth_group.add_argument(
    '--no-auth', dest="NOAUTH", default=False, action="store_true",
    help=("disable basic authentication (not recommended)"))

parser.add_argument(
    '-v', '--version', action='version', version='%(prog)s 1.1'
)

args = parser.parse_args()

if not (args.AUTH or args.NOAUTH):
    print("You need to supply either '--auth <user>:<pass>' (recommended)"
          " or '--no-auth' on the command line")
    exit(1)

if args.URI_PORT == 0:
    args.URI_PORT = args.LPORT

if ((args.SSL_KEY and not args.SSL_CERT)
        or (args.SSL_CERT and not args.SSL_KEY)):
    print("If you supply one of SSL_CERT or SSL_KEY you must also supply "
          "the other")
    exit(1)

if args.SSL_KEY:
    ssl_context = (args.SSL_CERT, args.SSL_KEY)
    args.PROTOCOL = 'https'
else:
    ssl_context = None
    args.PROTOCOL = 'http'
