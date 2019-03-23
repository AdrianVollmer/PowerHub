#!/usr/bin/env python3
import powerhub.flask
from powerhub.args import args
from powerhub.webdav import run_webdav
import threading

if __name__ == "__main__":
    try:
        threading.Thread(
            target=run_webdav,
            daemon=True,
        ).start()
    except ImportError as e:
        print(str(e))
        print("You have unmet dependencies. WebDAV won't be available. "
              "Consult the README.")
    powerhub.flask.app.run(debug=False, port=args.LPORT, host=args.LHOST)
