from cheroot import wsgi
from wsgidav.wsgidav_app import WsgiDAVApp
from powerhub.directories import WEBDAV_DIR


config = {
    "host": "0.0.0.0",
    "port": 8001,
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
try:
    server.start()
except KeyboardInterrupt:
    print("Caught Ctrl-C, shutting down...")
finally:
    server.stop()
