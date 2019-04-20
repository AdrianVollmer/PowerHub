#!/usr/bin/env python3
import powerhub.flask
from powerhub.args import args, ssl_context
try:
    import foo
    from powerhub.webdav import run_webdav
except ImportError as e:
    print(str(e))
    print("You have unmet dependencies. WebDAV won't be available. "
          "Consult the README.")
import threading

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
        daemon=True,
    ).start()
    threading.Thread(
        target=powerhub.flask.shell_receiver.run_provider,
        daemon=True,
    ).start()
    powerhub.flask.app.run(
        debug=False,
        port=args.LPORT,
        host=args.LHOST,
        ssl_context=ssl_context
    )
