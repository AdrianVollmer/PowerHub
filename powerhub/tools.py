import io
import gzip
import os
import random
import string
import itertools
import datetime

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from powerhub.directories import CERT_DIR
from powerhub.sql import get_setting, set_setting
from powerhub.logging import log


def create_self_signed_cert(hostname,
                            cert_file,
                            key_file,
                            ):

    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    subject = x509.Name([
        x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, "PowerHub"),
        x509.NameAttribute(x509.NameOID.COMMON_NAME, hostname)
    ])
    hash_algo = hashes.SHA256()
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        subject
    ).public_key(
        key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=365)
    ).sign(key, hash_algo, default_backend())

    log.info("Generated a self-signed certifiate for '%s' with SHA-1 "
             "fingerprint: %s" % (hostname, cert.fingerprint(hash_algo).hex()))

    with open(cert_file, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(key_file, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))


def get_self_signed_cert(hostname):
    file_basename = os.path.join(CERT_DIR, "cert_%s." % hostname)
    cert_file = file_basename + 'cert'
    key_file = file_basename + 'key'
    # check if one already exists
    if not (os.path.isfile(cert_file) and
            os.path.isfile(key_file)):

        log.info("No SSL certificate found, generating a self-signed one...")
        create_self_signed_cert(hostname, cert_file, key_file)
    pem_data = open(cert_file, "br").read()
    cert = x509.load_pem_x509_certificate(pem_data, default_backend())
    hash_algo = hashes.SHA256()
    log.info("Loaded SSL certificate for '%s' with SHA1 fingerprint: %s"
             % (hostname, cert.fingerprint(hash_algo).hex()))
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


def decrypt_aes(data, key):
    """Decrypt AES128 with IV"""

    def unpad(s):
        return s[:-ord(s[len(s)-1:])]

    BLOCK_SIZE = 16
    iv = data[:BLOCK_SIZE]
    key = key[:BLOCK_SIZE].encode()

    cipher = Cipher(algorithms.AES(key),
                    modes.CBC(iv),
                    backend=default_backend())
    decryptor = cipher.decryptor()
    result = decryptor.update(data[BLOCK_SIZE:]) + decryptor.finalize()

    return unpad(result)


def unique(a):
    result = []
    for each in a:
        if each not in result:
            result.append(each)
    return result


def flatten(lst):
    flatten = itertools.chain.from_iterable
    return list(flatten(lst))
