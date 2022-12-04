import base64
import random
import hashlib

from powerhub.tools import encrypt_rc4

DH_ENDPOINT = base64.b64encode(bytes(random.choices(range(256), k=32))).decode().replace('/', '')
# Publicly known
DH_N = random.randint(2**62, 2**64)
DH_G = random.randint(2**62, 2**64)


def dh_kex(client_public, key):
    """Diffie-Hellman key exchange

    Input the public DH key from the client and the symmetric key

    Return the publich DH key from the server and the symmetric key
    encrypted with the shared secret
    """

    # Only server knows this
    server_secret = random.randint(2**32, 2**34)

    # y_secret will be chosen from the powerhub client

    # Server's public key
    server_public = pow(DH_G, server_secret, mod=DH_N)

    shared_secret = pow(client_public, server_secret, mod=DH_N)
    shared_secret = shared_secret.to_bytes(16, byteorder='little')[:8]

    encrypted_key = encrypt_rc4(key, shared_secret)
    encrypted_key = base64.b64encode(encrypted_key).decode()

    print((shared_secret), encrypted_key)
    return str(server_public), encrypted_key


def stretch(key, salt, mod=2**32):
    """Return a large, "pseudo-random" number derived from the key"""

    data = (key + salt).encode()

    m = hashlib.sha256()
    m.update(data)
    result = int.from_bytes(m.digest(), byteorder='big', signed=False)

    return result
