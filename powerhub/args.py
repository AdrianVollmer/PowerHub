import argparse
from powerhub import __version__

parser = argparse.ArgumentParser(
    description="Leverage PowerShell to load sketchy code over HTTP"
)

parser.add_argument(
    '-v', '--version', action='version', version=__version__
)

parser.add_argument(
    '-d', '--debug', dest="DEBUG", default=False, action="store_true",
    help=("enable debug mode"),
)

parser.add_argument(
    '-w', '--workspace-directory', dest="WORKSPACE_DIR", default=None,
    help="use this directory to store project-related files"
         " (default: $XDG_DATA_HOME/powerhub/workspace)"
)

auth_group = parser.add_mutually_exclusive_group()

auth_group.add_argument(
    '--auth', dest="AUTH", type=str,
    default="",
    help="define credentials for basic authentication in the form of"
         " 'user:pass' (default: powerhub:<random>)"
)

auth_group.add_argument(
    '--no-auth', dest="NOAUTH", default=False, action="store_true",
    help=("disable basic authentication (not recommended)")
)

parser.add_argument(
    '-lh', '--lhost', default='0.0.0.0',
    dest="LHOST",
    type=str,
    help="the local bind address to listen on for the HTTP and HTTPS "
         "services (default: %(default)s)"
)

parser.add_argument(
    '-lp',
    '--lport',
    default=8080,
    dest="LPORT",
    type=int,
    help="the local HTTP port to listen on (default: %(default)s)"
)

parser.add_argument(
    '-sp',
    '--ssl-port',
    default=8443,
    dest="SSL_PORT",
    type=int,
    help="the local HTTPS port to listen on (default: %(default)s)"
)

parser.add_argument(
    '-fp',
    '--flask-port',
    default=5000,
    dest="FLASK_PORT",
    type=int,
    help="the local port to listen on for the Flask app (default: %(default)s)"
)

parser.add_argument(
    '-wp',
    '--webdav-port',
    default=5001,
    dest="WEBDAV_PORT",
    type=int,
    help="the local port to listen on for the webdav server "
         "(default: %(default)s)"
)

parser.add_argument(
    '-wa',
    '--webdav-auth',
    default="",
    dest="WEBDAV_AUTH",
    type=str,
    help="define credentials for the private webdav share in the form of"
         " 'user:pass' (default: powerhub:<random>)"
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
    '-a', '--allow',
    dest='ALLOWLIST',
    default=None,
    help="comma separated value of allowed source IP addresses or address "
         " ranges (leave empty to allow all)"
)

parser.add_argument(
    dest="URI_HOST", type=str,
    help="the hostname or IP address where the target can reach the server"
)

parser.add_argument(
    '-up', '--uri-port', dest="URI_PORT", type=int,
    default=0,
    help="the port where the target can reach the server"
         " (default: LPORT/SSL_PORT)"
)

parser.add_argument(
    '--uri-path', dest="URI_PATH", type=str,
    default='',
    help="the URI path where the target can reach the server (default: '')"
)


def parse_args(argv=None):
    args = parser.parse_args(argv)

    if ((args.SSL_KEY and not args.SSL_CERT)
            or (args.SSL_CERT and not args.SSL_KEY)):
        print("If you supply one of SSL_CERT or SSL_KEY you must also supply "
              "the other")
        exit(1)

    if args.ALLOWLIST:
        args.ALLOWLIST = args.ALLOWLIST.split(',')

    if args.SSL_KEY:
        args.PROTOCOL = 'https'
    else:
        args.PROTOCOL = 'http'
    return args
