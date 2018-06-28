import io
import gzip
import random
import string


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
