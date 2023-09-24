import random
import hashlib


class RabinSecurityLevel:
    def __init__(self, level):
        self.level = level

    def calculate_bits(self):
        return self.level * 512


class RabinPubKey:
    def __init__(self, n):
        self.n = n


class RabinSig:
    def __init__(self, s, u):
        self.s = s
        self.u = u


def generate_rabin_key_pair(security_level):

    # Generate two large prime numbers.
    p = random.randint(2**security_level, 2**(security_level+1))
    q = random.randint(2**security_level, 2**(security_level+1))

    # Compute the public key.
    n = p * q

    # Compute the private key.
    phi = (p - 1) * (q - 1)
    e = 65537
    d = pow(e, -1, phi)

    return RabinPubKey(n), d


def sign_rabin(msg, priv_key, pub_key):

    # Compute the hash of the message.
    h = hashlib.sha256(msg).digest()

    # Compute the signature.
    s = pow(h, priv_key, pub_key.n)

    # Pad the signature with random bytes.
    u = random.randbytes(security_level.calculate_bits())

    return RabinSig(s, u)


def verify_rabin(msg, sig, pub_key):

    # Compute the hash of the message.
    h = hashlib.sha256(msg).digest()

    # Compute the signature.
    s2 = pow(sig.s, 2, pub_key.n)

    # Check if the signature is valid.
    return s2 == h


if __name__ == '__main__':
    # Create a new RabinSecurityLevel object with the default security level.
    security_level = RabinSecurityLevel(6)

    # Generate a public and private key pair.
    pub_key, priv_key = generate_rabin_key_pair(security_level)

    # Sign a message.
    msg = b'Hello, sCrypt!'
    sig = sign_rabin(msg, priv_key, pub_key)

    # Verify the signature.
    is_valid = verify_rabin(msg, sig, pub_key)

    if is_valid:
        print('Signature is valid.')
    else:
        print('Signature is invalid.')
