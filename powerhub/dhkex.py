import hashlib
import logging
import random
import string

from cryptography.hazmat.primitives.asymmetric import dh

from powerhub.tools import encrypt_rc4

DH_ENDPOINT = ''.join(random.choices(string.ascii_letters, k=16))
DH_MODULUS = None
DH_G = None
KEY_SIZE = 512

log = logging.getLogger(__name__)


def generate_diffie_hellman_params():
    log.info("Generating new Diffie-Hellman parameters")
    g = 2
    parameters = dh.generate_parameters(generator=g, key_size=KEY_SIZE)
    p = parameters.parameter_numbers()._p

    global DH_MODULUS, DH_G
    DH_MODULUS, DH_G = p, g


def dh_kex(client_public, key):
    """Diffie-Hellman key exchange

    Input the public DH key from the client and the symmetric key

    Return the publich DH key from the server and the symmetric key
    encrypted with the shared secret
    """

    # Only server knows this
    server_secret = random.randint(2**126, 2**128)

    # y_secret will be chosen from the powerhub client

    # Server's public key
    server_public = pow(DH_G, server_secret, mod=DH_MODULUS)

    shared_secret = pow(client_public, server_secret, mod=DH_MODULUS)
    log.debug("Diffie-Hellman shared secret: %s" % shared_secret)
    shared_secret = shared_secret.to_bytes(KEY_SIZE, byteorder='little')[:64]

    encrypted_key = encrypt_rc4(key, shared_secret)

    log.debug("Diffie-Hellman shared secret (bytes): %s" % shared_secret)
    log.debug("Diffie-Hellman server secret: %s" % server_secret)
    log.debug("Diffie-Hellman server public: %s" % server_public)
    log.debug("Diffie-Hellman client public: %s" % client_public)
    log.debug("Diffie-Hellman modulus: %s" % DH_MODULUS)
    log.debug("Diffie-Hellman encrypted key: %s" % encrypted_key)

    return str(server_public), encrypted_key


def stretch(key, salt, mod=2**32):
    """Return a large, "pseudo-random" number derived from the key"""

    data = (key + salt).encode()

    m = hashlib.sha256()
    m.update(data)
    result = int.from_bytes(m.digest(), byteorder='big', signed=False)

    return result


generate_diffie_hellman_params()
