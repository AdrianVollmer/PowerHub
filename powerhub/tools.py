from powerhub.directories import XDG_DATA_HOME
import io
import gzip
import os
import random
import string

from OpenSSL import crypto


def create_self_signed_cert(hostname,
                            cert_file,
                            key_file,
                            ):
    # create a key pair
    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, 2048)

    # create a self-signed cert
    cert = crypto.X509()
    cert.get_subject().O = "PowerHub"
    cert.get_subject().CN = hostname
    #  cert.set_serial_number(1000)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(10*365*24*60*60)
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(k)
    cert.sign(k, 'sha256')

    open(cert_file, "w+").write(
        crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
    open(key_file, "w+").write(
        crypto.dump_privatekey(crypto.FILETYPE_PEM, k))


def get_self_signed_cert(hostname):
    file_basename = os.path.join(XDG_DATA_HOME, "cert_%s." % hostname)
    cert_file = file_basename + 'cert'
    key_file = file_basename + 'key'
    # check if one already exists
    if not (os.path.isfile(cert_file) and
            os.path.isfile(key_file)):
        create_self_signed_cert(hostname, cert_file, key_file)
    return (cert_file, key_file)


def generate_random_key(n):
    return ''.join(random.choice(string.ascii_letters) for _ in range(n))


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


key = generate_random_key(128)
