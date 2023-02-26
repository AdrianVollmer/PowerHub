import base64
import datetime
import gzip
import io
import itertools
import logging
import os
import random
import string

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from powerhub.sql import get_setting, set_setting

log = logging.getLogger(__name__)


def create_self_signed_cert(hostname, cert_file, key_file):
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
        datetime.datetime.utcnow() + datetime.timedelta(days=30)
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


def get_self_signed_cert(hostname, cert_dir):
    file_basename = os.path.join(cert_dir, "cert_%s." % hostname)
    cert_file = file_basename + 'cert'
    key_file = file_basename + 'key'

    # check if one already exists
    if not (os.path.isfile(cert_file) and
            os.path.isfile(key_file)):

        log.info("No SSL certificate found, generating a self-signed one...")
        create_self_signed_cert(hostname, cert_file, key_file)

    pem_data = open(cert_file, "br").read()
    cert = x509.load_pem_x509_certificate(pem_data, default_backend())

    if cert.not_valid_after < datetime.datetime.now():
        log.info("Certificate expired, generating a new one...")
        create_self_signed_cert(hostname, cert_file, key_file)
        pem_data = open(cert_file, "br").read()
        cert = x509.load_pem_x509_certificate(pem_data, default_backend())

    hash_algo = hashes.SHA256()
    log.info("Loaded SSL certificate for '%s' with SHA1 fingerprint: %s"
             % (hostname, cert.fingerprint(hash_algo).hex()))
    return (cert_file, key_file)


def generate_random_key(n):
    key = ''.join(
        random.choice(string.ascii_letters+string.digits)
        for _ in range(n)
    )
    log.debug("Generated a secret key: %s", key)
    return key


def get_secret_key():
    KEY_LENGTH = 32
    key = get_setting("secret_key")

    if not key:
        key = generate_random_key(KEY_LENGTH)
        set_setting("secret_key", key)
    else:
        log.debug("Loaded secret key: %s", key)

    return key


def compress(bytes):
    out = io.BytesIO()
    with gzip.GzipFile(fileobj=out, mode="w") as f:
        f.write(bytes)
    return out.getvalue()


def encrypt_rc4(data, key):
    """RC4"""

    if isinstance(key, str):
        key = key.encode()
    if isinstance(data, str):
        data = data.encode()
        string = True
    else:
        string = False

    S = list(range(256))
    j = 0
    out = []

    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]

    i = j = 0
    for char in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        out.append(char ^ S[(S[i] + S[j]) % 256])

    result = (bytes(out))

    if string:
        result = base64.b64encode(result).decode()

    return result


def encrypt_aes(data, key):
    """Encrypt AES128 with IV"""

    if isinstance(data, str):
        data = data.encode()
        string = True
    else:
        string = False

    # Use PKCS7 padding
    def pad(m):
        return m+bytes([16-len(m) % 16]*(16-len(m) % 16))

    BLOCK_SIZE = 16
    iv = os.urandom(BLOCK_SIZE)
    key = key[:BLOCK_SIZE].encode()

    cipher = Cipher(algorithms.AES(key),
                    modes.CBC(iv),
                    backend=default_backend())
    encryptor = cipher.encryptor()
    data = pad(data)
    result = encryptor.update(data) + encryptor.finalize()

    result = iv + result

    if string:
        result = base64.b64encode(result).decode()

    return result


def decrypt_aes(data, key):
    """Decrypt AES128 with IV"""

    # Use PKCS7 padding
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


class Memoize:
    def __init__(self, f):
        self.f = f
        self.memo = {}

    def __call__(self, *args):
        if args not in self.memo:
            self.memo[args] = self.f(*args)
        return self.memo[args]
