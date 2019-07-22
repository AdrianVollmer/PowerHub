#!/usr/bin/env python3
import argparse
import fcntl
import json
import readline
import os
import socket
import select
import struct
import sys
import threading


parser = argparse.ArgumentParser(
    description="Interact with PowerHub shells"
)

parser.add_argument(
    "ID",
    type=str,
    help="ID of the shell you want to interact with"
)

parser.add_argument(
    "-m", "--edit-mode",
    dest='MODE',
    default='default',
    choices=["vi", "emacs", "default"],
    help="use a special edit mode (default: %(default)s)"
)


# parse args before powerhub does
args = parser.parse_args()
from powerhub.receiver import ShellPacket, T_DICT  # noqa

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_address = ('127.0.0.1', 18157)
sock.connect(server_address)

sock.send(args.ID.encode())

signal_pipe = os.pipe()
fcntl.fcntl(signal_pipe[0], fcntl.F_SETFL, os.O_NONBLOCK)
write_socks = []

prompt = "> "
queue = []
active = True


def flush_queue():
    global prompt, queue
    for p in queue:
        mtype = p["msg_type"]
        if mtype == "PROMPT":
            prompt = p["data"]
            j = {"msg_type": "INT_QUEUE_FLUSHED"}
            os.write(signal_pipe[1], json.dumps(j).encode())
        elif mtype in [
            "OUTPUT",
            "SHELL_HELLO",
        ] or mtype.startswith("STREAM_"):
            print(p.shell_string(), end='')
            sys.stdout.flush()
    queue = []


def listen():
    global write_socks, prompt, queue
    while active:
        r, _, _ = select.select([sock], [], [])
        for s in r:
            p = recv_packet(s)
            queue.append(p)
            if p["msg_type"] == "TABCOMPL":
                os.write(signal_pipe[1], p.serialize())
            elif p["msg_type"] == "PROMPT":
                flush_queue()


def send_packet(p, return_response=False):
    try:
        while True:
            os.read(signal_pipe[0], 1024)  # clear the signal pipe
    except BlockingIOError:
        pass
    _, w, _ = select.select([], [sock], [])
    w[0].send(p.serialize())
    if return_response:
        r, _, _ = select.select([signal_pipe[0]], [], [], 3)
        for s in r:
            p = recv_packet(s)
        return p
    else:
        r, _, _ = select.select([signal_pipe[0]], [], [], 3)
        if r:
            os.read(r[0], 1024)


def recv_packet(sock):
    if isinstance(sock, socket.socket):
        try:
            header = sock.recv(4, socket.MSG_PEEK)
            if not header:
                print("Connection closed")
                os._exit(0)
            packet_length = struct.unpack('<i', header)[0]
            body = sock.recv(packet_length)
        except ConnectionResetError:
            print("Connection reset by peer")
            os._exit(0)
    else:
        header = os.read(sock, 4)
        packet_length = struct.unpack('<i', header)
        body = header + os.read(sock, packet_length-4)
    p = ShellPacket(body)
    return p


def send_command(command):
    json = {
        "msg_type": "COMMAND",
        "data": command,
        "width": columns,
    }
    p = ShellPacket(json, T_DICT)
    send_packet(p)


def complete(text, n):
    global completions
    packet = {
        "msg_type": "TABCOMPL",
        "data": text,
        "n": n,
    }
    if text in completions:
        response = completions[text]
    else:
        p = ShellPacket(packet, T_DICT)
        p = send_packet(p, return_response=True)
        response = p["data"]
        completions[text] = response
    try:
        return response[n]
    except KeyError:
        return None


threading.Thread(
    target=listen,
    daemon=True,
).start()


readline.parse_and_bind('tab: complete')
if not args.MODE == 'default':
    readline.parse_and_bind('set editing-mode %s' % args.MODE)
# in powershell, '-' is not a completion delimiter
old_delims = readline.get_completer_delims()
readline.set_completer_delims(old_delims.replace('-', ''))
# PS is case insensitive
readline.parse_and_bind('set completion-ignore-case On')
readline.set_completer(complete)

while True:
    rows, columns = os.popen('stty size', 'r').read().split()
    completions = {}

    try:
        command = input(prompt)
    except (KeyboardInterrupt, EOFError):
        got_decision = False
        while not got_decision:
            decision = input(
                "\nDo you want to [e]xit, [s]tay, or [k]ill the shell? "
            )
            if decision.lower() == 's':
                command = ""
                break
            elif decision.lower() == 'e':
                active = False
                exit(0)
            elif decision.lower() == 'k':
                packet = {"msg_type": "KILL", "data": ""}
                p = ShellPacket(packet, T_DICT)
                send_packet(p)
                exit(0)
            else:
                print("What do you mean? Please enter e, s or k.")
    if command:
        send_command(command)
