#!/usr/bin/env python3
import powerhub.flask
from powerhub.args import args

if __name__ == "__main__":
    powerhub.flask.app.run(debug=True, port=args.LPORT, host=args.LHOST)
