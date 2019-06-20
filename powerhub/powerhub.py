#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import threading
import signal

import powerhub.flask
import powerhub.reverseproxy
from powerhub.args import args
from powerhub.logging import log
try:
    from powerhub.webdav import run_webdav
except ImportError as e:
    print(str(e))
    print("You have unmet dependencies. WebDAV won't be available. "
          "Consult the README.")


def signal_handler(sig, frame):
    log.info("CTRL-C caught, exiting...")
    powerhub.reverseproxy.reactor.stop()


def start_thread(f, *args):
    threading.Thread(
        target=f,
        args=(*args,),
        daemon=True,
    ).start()


def main():
    signal.signal(signal.SIGINT, signal_handler)
    try:
        start_thread(run_webdav)
    except NameError:
        pass
    start_thread(powerhub.flask.shell_receiver.run_receiver,
                 args.REC_HOST, args.REC_PORT)
    start_thread(powerhub.flask.shell_receiver.run_provider)
    start_thread(powerhub.flask.run_flask_app)
    powerhub.reverseproxy.run_proxy()
