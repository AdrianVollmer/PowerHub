#!/usr/bin/env python3
import powerhub.flask
from powerhub.args import args
try:
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
    powerhub.flask.app.run(debug=False, port=args.LPORT, host=args.LHOST)
