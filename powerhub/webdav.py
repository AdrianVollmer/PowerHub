import os
import threading
from cheroot import wsgi
from wsgidav.wsgidav_app import WsgiDAVApp
from powerhub.directories import WEBDAV_RO, WEBDAV_BLACKHOLE, \
        UPLOAD_DIR, WEBDAV_DIR
from powerhub.env import powerhub_app as ph_app
import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import logging

logger = logging.getLogger("wsgidav")
logger.propagate = True
logger.setLevel(logging.DEBUG)

config = {
    "host": '127.0.0.1',
    "port": ph_app.args.WEBDAV_PORT,
    "dir_browser": {"enable": True},
    "http_authenticator": {
        # None: dc.simple_dc.SimpleDomainController(user_mapping)
        "domain_controller": None,
        "accept_basic": True,  # Allow basic authentication, True or False
        "accept_digest": True,  # Allow digest authentication, True or False
        "default_to_digest": True,  # True  or False
        # Name of a header field that will be accepted as authorized user
        "trusted_auth_header": None,
    },
    #: Used by SimpleDomainController only
    "simple_dc": {"user_mapping": {"*": True}},
    "provider_mapping": {
        "/webdav_ro": {
            "root": WEBDAV_RO,
            "readonly": True,
            "auth": "anonymous",
        },
        "/webdav/": {
            "root": WEBDAV_DIR,
            "readonly": False,
            "auth": "anonymous",
        },
    },
    "verbose": 1,
    }

app = WsgiDAVApp(config)

server_args = {
    "bind_addr": (config["host"], config["port"]),
    "wsgi_app": app,
    }
server = wsgi.Server(**server_args)


class MyHandler(FileSystemEventHandler):
    """Responsible for copying files from the BLACKHOLE_DIR to the
    UPLOAD_DIR"""
    def on_created(self, event):
        os.rename(
            os.path.join(event.src_path),
            os.path.join(UPLOAD_DIR, os.path.basename(event.src_path)),
        )


def watch_blackhole_folder():
    observer = Observer()
    observer.schedule(MyHandler(), path=WEBDAV_BLACKHOLE, recursive=False)
    observer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()


def run_webdav():
    threading.Thread(
        target=watch_blackhole_folder,
        daemon=True,
    ).start()
    try:
        server.start()
    except KeyboardInterrupt:
        print("Caught Ctrl-C, shutting down...")
    finally:
        server.stop()
