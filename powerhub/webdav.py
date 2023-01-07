import logging
import os
import threading
import time

from cheroot import wsgi
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer
from wsgidav.wsgidav_app import WsgiDAVApp

from powerhub.directories import directories

logger = logging.getLogger("wsgidav")
main_logger = logging.getLogger(__name__)
logger.propagate = True
logger.setLevel(main_logger.getEffectiveLevel())


def init_server(port, user, password):
    config = {
        "host": '127.0.0.1',
        "port": port,
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
        "simple_dc": {
            "user_mapping": {
                "/webdav_ro": True,
                "/webdav": True,
                "*": {
                    user: {
                        "password": password,
                        "roles": ["admin"]
                    },
                },
            },
        },
        "provider_mapping": {
            "/webdav_ro": {
                "root": directories.WEBDAV_RO,
                "readonly": True,
                "auth": "anonymous",
            },
            "/webdav": {
                "root": directories.WEBDAV_DIR,
                "readonly": False,
                "auth": "anonymous",
            },
            "/webdav_private": {
                "root": directories.WEBDAV_PRIVATE,
                "readonly": False,
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

    return server


class MyHandler(FileSystemEventHandler):
    """Responsible for copying files from the BLACKHOLE_DIR to the
    UPLOAD_DIR"""
    def on_created(self, event):
        os.rename(
            os.path.join(event.src_path),
            os.path.join(directories.UPLOAD_DIR, os.path.basename(event.src_path)),
        )


def watch_blackhole_folder():
    observer = Observer()
    observer.schedule(MyHandler(), path=directories.WEBDAV_BLACKHOLE, recursive=False)
    observer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()


def run_webdav(port, user, passwod):
    threading.Thread(
        target=watch_blackhole_folder,
        daemon=True,
    ).start()
    server = init_server(port, user, passwod)
    try:
        server.start()
    except KeyboardInterrupt:
        print("Caught Ctrl-C, shutting down...")
    finally:
        server.stop()
