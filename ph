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
                os.write(out_pipe[1], b'_' + p.shell_string().encode())
            elif p["msg_type"] in ["TABCOMPL"]:
                os.write(out_pipe[1], p.shell_string().encode())
            elif p["data"]:
                print(p.shell_string(), end='')
                sys.stdout.flush()


def send_packet(p):
    _, w, _ = select.select([], [sock], [])
    w[0].send(p.serialize())
    r, _, _ = select.select([out_pipe[0]], [], [], 1)
    response = b''
    while True and r:
        try:
            data = os.read(r[0], 1024)
            response += data
        except OSError:
            break
    return response


def send_command(command):
    json = {
        "msg_type": "COMMAND",
        "data": command,
        "width": columns,
    }
    p = ShellPacket(T_DICT, json)
    response = send_packet(p)[1:]
    print(response.decode(), end='')


completions = {}


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
        p = ShellPacket(T_DICT, packet)
        response = send_packet(p).decode()
        response = json.loads(response)
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
old_delims = readline.get_completer_delims()
readline.set_completer_delims(old_delims.replace('-', ''))
readline.set_completer(complete)
while True:
    rows, columns = os.popen('stty size', 'r').read().split()
    #  completions = {}

    command = input(prompt)
    send_command(command)
