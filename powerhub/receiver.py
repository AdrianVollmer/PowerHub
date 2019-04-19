from powerhub.args import args
import random


class ReverseShell(object):
    def __init__(self, shell_hello, sock):
        self.sock = sock
        self.id = '%x' % random.randrange(16**8)
        self.user = 'SYSTEM'
        self.hostname = 'localhost'
        self.peer_ip = "x.x.x.x"
        self.peer_port = 0
        self.description = "[%s] %s@%s (%s:%d)" % (
            self.id,
            self.user,
            self.hostname,
            self.peer_ip,
            self.peer_port,
        )


shells = []
