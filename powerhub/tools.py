import io
import gzip
import os
import random
import string
import itertools

from OpenSSL import crypto

from powerhub.directories import CERT_DIR
from powerhub.sql import get_setting, set_setting
from powerhub.logging import log

FINGERPRINT = ""


def create_self_signed_cert(hostname,
                            cert_file,
                            key_file,
                            ):
    # create a key pair
    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, 2048)

    # create a self-signed cert
    cert = crypto.X509()
    cert.get_subject().O = "PowerHub"  # noqa
    cert.get_subject().CN = hostname
    cert.set_serial_number(random.randint(1, 10000))
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(10*365*24*60*60)
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(k)
    cert.sign(k, 'sha256')
    log.info("Generated a self-signed certifiate for '%s' with SHA-1 "
             "fingerprint: %s" % (hostname, cert.digest("sha1").decode()))

    open(cert_file, "bw+").write(
        crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
    open(key_file, "bw+").write(
        crypto.dump_privatekey(crypto.FILETYPE_PEM, k))


def get_self_signed_cert(hostname):
    file_basename = os.path.join(CERT_DIR, "cert_%s." % hostname)
    cert_file = file_basename + 'cert'
    key_file = file_basename + 'key'
    # check if one already exists
    if not (os.path.isfile(cert_file) and
            os.path.isfile(key_file)):

        log.info("No SSL certificate found, generating a self-signed one...")
        create_self_signed_cert(hostname, cert_file, key_file)
    else:
        f = open(cert_file, "br").read()
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, f)
        log.info("Loaded SSL certificate for '%s' with SHA1 fingerprint: %s"
                 % (hostname, cert.digest("sha1").decode()))
    global FINGERPRINT
    FINGERPRINT = cert.digest("sha1").decode()
    return (cert_file, key_file)


def generate_random_key(n):
    key = ''.join(random.choice(string.ascii_letters) for _ in range(n))
    log.debug("Generated a secret key: %s", key)
    return key


def get_secret_key():
    key = get_setting("secret_key")
    if not key:
        key = generate_random_key(128)
        set_setting("secret_key", key)
    else:
        log.debug("Loaded secret key: %s", key)
    return key


def compress(bytes):
    out = io.BytesIO()
    with gzip.GzipFile(fileobj=out, mode="w") as f:
        f.write(bytes)
    return out.getvalue()


def encrypt(data, key):
    """RC4"""

    S = list(range(256))
    j = 0
    out = []

    for i in range(256):
        j = (j + S[i] + key.encode()[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]

    i = j = 0
    for char in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        out.append(char ^ S[(S[i] + S[j]) % 256])

    return (bytes(out))


def unique(a):
    result = []
    for each in a:
        if each not in result:
            result.append(each)
    return result


def flatten(l):
    flatten = itertools.chain.from_iterable
    return list(flatten(l))


KEY = get_secret_key()
