#!/usr/bin/env python3
import argparse
import fcntl
import readline
import os
import socket
import select
import struct
import sys
import threading

from powerhub.receiver import ShellPacket, T_DICT

parser = argparse.ArgumentParser(
    description="Interact with PowerHub shells"
)

parser.add_argument(
    "ID",
    type=str,
    help="ID of the shell you want to interact with"
)

args = parser.parse_args()


sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_address = ('127.0.0.1', 18157)
sock.connect(server_address)

sock.send(args.ID.encode())

out_pipe = os.pipe()
fcntl.fcntl(out_pipe[0], fcntl.F_SETFL, os.O_NONBLOCK)
write_socks = []

prompt = "> "


def listen():
    global write_socks, prompt
    while True:
        r, _, _ = select.select([sock], [], [])
        for s in r:
            try:
                header = s.recv(6)
            except Exception as e:
                print(str(e))
                return
            if not header:
                return
            packet_type, packet_length = struct.unpack('>HI', header)
            body = s.recv(packet_length)
            p = ShellPacket(packet_type, body)
            if p["msg_type"] == "PROMPT":
                prompt = p["data"]
            elif p["msg_type"] in ["OUTPUT", "STREAM_EXCEPTION"]:
                os.write(out_pipe[1], p.shell_string().encode())
            elif p["data"]:
                print(p.shell_string(), end='')
                sys.stdout.flush()


threading.Thread(
    target=listen,
    daemon=True,
).start()


readline.parse_and_bind('tab: complete')
while True:
    try:
        rows, columns = os.popen('stty size', 'r').read().split()

        command = input(prompt)
        json = {
            "msg_type": "COMMAND",
            "data": command,
            "width": columns,
        }
        p = ShellPacket(T_DICT, json)
        _, w, _ = select.select([], [sock], [])
        w[0].send(p.serialize())
        r, _, _ = select.select([out_pipe[0]], [], [], 10)
        response = b''
        while True and r:
            try:
                data = os.read(r[0], 1024)
                response += data
            except OSError:
                break
        print(response.decode(), end='')
    except Exception as e:
        print(str(e))
        break
