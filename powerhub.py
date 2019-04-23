#!/usr/bin/env python3
import powerhub.flask
from powerhub.args import args, ssl_context
try:
    from powerhub.webdav import run_webdav
except ImportError as e:
    print(str(e))
    print("You have unmet dependencies. WebDAV won't be available. "
          "Consult the README.")
import threading
import sys
import logging

FORMAT = '%(asctime)-15s %(message)s'
logging.basicConfig(
    stream=sys.stdout,
    level=logging.DEBUG if args.DEBUG else logging.INFO,
    format=FORMAT,
    datefmt="%Y-%m-%d %H:%M:%S",
)

if __name__ == "__main__":
    try:
        threading.Thread(
            target=run_webdav,
            daemon=True,
        ).start()
    except NameError:
        pass
    threading.Thread(
        target=powerhub.flask.shell_receiver.run_receiver,
        args=(args.REC_HOST, args.REC_PORT,),
        daemon=True,
    ).start()
    threading.Thread(
        target=powerhub.flask.shell_receiver.run_provider,
        daemon=True,
    ).start()
    powerhub.flask.app.run(
        debug=args.DEBUG,
        port=args.LPORT,
        host=args.LHOST,
        ssl_context=ssl_context,
        request_handler=powerhub.flask.MyRequestHandler,
    )
