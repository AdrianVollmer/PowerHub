from powerhub.args import args
import random


class ReverseShell(object):
    def __init__(self):
        self.id = '%x' % random.randrange(16**8)
        self.description = "Shell #%s from %s (%s:%d)" % (
            self.id,
            "hostname",
            "x.x.x.x",
            0,
        )
