from cheroot import wsgi
from wsgidav.wsgidav_app import WsgiDAVApp
from powerhub.directories import WEBDAV_DIR
from powerhub.args import args


config = {
    "host": args.LHOST,
    "port": args.WEBDAV_PORT,
    "provider_mapping": {
        "/": WEBDAV_DIR,
        },
    "verbose": 1,
    }

app = WsgiDAVApp(config)

server_args = {
    "bind_addr": (config["host"], config["port"]),
    "wsgi_app": app,
    }
server = wsgi.Server(**server_args)


def run_webdav():
    try:
        server.start()
    except KeyboardInterrupt:
        print("Caught Ctrl-C, shutting down...")
    finally:
        server.stop()
