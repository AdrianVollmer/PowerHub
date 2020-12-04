import os
import signal
import threading

from flask import Flask
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.serving import WSGIRequestHandler, _log
from flask_socketio import SocketIO

from powerhub.args import parse_args
import powerhub.env as env


def signal_handler(sig, frame):
    import powerhub.reverseproxy
    log.info("CTRL-C caught, exiting...")
    powerhub.reverseproxy.reactor.stop()


def start_thread(f, *args):
    threading.Thread(
        target=f,
        args=(*args,),
        daemon=True,
    ).start()


class MyRequestHandler(WSGIRequestHandler):
    def address_string(self):
        if 'x-forwarded-for' in dict(self.headers._headers):
            return dict(self.headers._headers)['x-forwarded-for']
        else:
            return self.client_address[0]

    def log(self, type, message, *largs):
        # don't log datetime again
        if " /socket.io/?" not in largs[0]:
            _log(type, '%s %s\n' % (self.address_string(), message % largs))


class PowerHubApp(object):
    """This is the main app class

    It is a singleton and a reference will be stored in powerhub.env.

    It holds all parameters, settings and "sub apps", such as the flask app,
    the reverse proxy, the database, etc.

    """
    def __init__(self, argv: list = None):
        """
        You can pass arguments to PowerHub by putting them in argv. If
        empty, sys.argv will be used (i.e. the command line arguments).

        """
        assert env.powerhub_app is None, \
            "Instance of PowerHubApp already exists"
        env.powerhub_app = self

        self.args = parse_args(argv)
        # log depends on args, so it must be imported after args have been
        # parsed
        from powerhub.logging import log
        global log
        self.init_flask()
        self.init_db()
        self.init_clipboard()
        self.init_loot()
        self.init_socketio()
        self.init_settings()

    def init_socketio(self):
        self.socketio = SocketIO(
            self.flask_app,
            async_mode="threading",
            cors_allowed_origins=[
                "http://%s:%d" % (
                    self.args.URI_HOST,
                    self.args.LPORT,
                ),
                "https://%s:%d" % (
                    self.args.URI_HOST,
                    self.args.SSL_PORT,
                ),
            ],
        )

    def init_flask(self):
        from powerhub.flask import app as flask_blueprint
        from powerhub.directories import DB_FILENAME
        self.flask_app = Flask(__name__)
        self.flask_app.register_blueprint(flask_blueprint)
        self.flask_app.wsgi_app = ProxyFix(
            self.flask_app.wsgi_app,
            x_proto=1,
            x_host=1,
            x_port=1
        )
        self.flask_app.config.update(
            DEBUG=self.args.DEBUG,
            SECRET_KEY=os.urandom(16),
            SQLALCHEMY_DATABASE_URI='sqlite:///' + DB_FILENAME,
            SQLALCHEMY_TRACK_MODIFICATIONS=False,
        )

    def init_db(self):
        try:
            from flask_sqlalchemy import SQLAlchemy
            from powerhub.sql import init_db
            db = SQLAlchemy(self.flask_app)
            init_db(db)
        except ImportError as e:
            log.error("You have unmet dependencies, "
                      "database will not be available")
            log.exception(e)
            db = None
        self.db = db

    def init_clipboard(self):
        from powerhub.sql import get_clipboard
        self.clipboard = get_clipboard()

    def init_loot(self):
        self.loot = None

    def init_settings(self):
        from powerhub.tools import get_secret_key
        self.key = get_secret_key()

    def run_flask_app(self):
        self.socketio.run(
            self.flask_app,
            port=self.args.FLASK_PORT,
            host='127.0.0.1',
            use_reloader=False,
            request_handler=MyRequestHandler,
        )

    def run(self, background=False):
        import powerhub.reverseproxy
        signal.signal(signal.SIGINT, signal_handler)
        try:
            from powerhub.webdav import run_webdav
            start_thread(run_webdav)
        except ImportError as e:
            print(str(e))
            print("You have unmet dependencies. WebDAV won't be available. "
                  "Consult the README.")
        start_thread(self.run_flask_app)
        if background:
            start_thread(powerhub.reverseproxy.run_proxy)
        else:
            powerhub.reverseproxy.run_proxy()

    def stop(self):
        from powerhub import reverseproxy
        if not reverseproxy.reactor._stopped:
            reverseproxy.reactor.stop()
        env.powerhub_app = None
