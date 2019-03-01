from functools import wraps
from flask import request, Response
from powerhub.args import args


def check_auth(username, password):
    """This function is called to check if a username /
    password combination is valid.
    """
    print(args.AUTH)
    if args.AUTH:
        user, pwd = args.AUTH.split(':')
        return username == user and password == pwd
    else:
        return True


def authenticate():
    """Sends a 401 response that enables basic auth"""
    return Response('Could not verify your access level for that URL.\n'
                    'You have to login with proper credentials',
                    401,
                    {'WWW-Authenticate': 'Basic realm="Login Required"'})


def requires_auth(f):
    @wraps(f)
    def decorated(*largs, **kwargs):
        auth = request.authorization
        if args.AUTH and (not auth or not check_auth(auth.username,
                                                     auth.password)):
            return authenticate()
        return f(*largs, **kwargs)
    return decorated
