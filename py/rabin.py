import hashlib
import sys


def gcd(a, b):
    if b > a:
        a, b = b, a
    while b > 0:
        a, b = b, a % b
    return a


def next_prime(p):
    while p % 4 != 3:
        p = p + 1
    return next_prime_3(p)


def next_prime_3(p):
    m_ = 3 * 5 * 7 * 11 * 13 * 17 * 19 * 23 * 29
    while gcd(p, m_) != 1:
        p = p + 4
    if pow(2, p - 1, p) != 1 or pow(3, p - 1, p) != 1 or pow(5, p - 1, p) != 1 or pow(17, p - 1, p) != 1:
        return next_prime_3(p + 4)
    return p


def hash_to_int(x: bytes) -> int:
    hx = hashlib.sha256(x).digest()
    # Expand to 3072 bits
    for i in range(11):
        hx += hashlib.sha256(hx).digest()
    return int.from_bytes(hx, 'little')


def sign_rabin(p: int, q: int, digest: bytes) -> tuple:
    """
    :param p: part of private key
    :param q: part of private key
    :param digest: message digest to sign
    :return: rabin signature (S: int, padding: int)
    """
    n = p * q
    i = 0
    while True:
        h = hash_to_int(digest + b'\x00' * i) % n
        if (h % p == 0 or pow(h, (p - 1) // 2, p) == 1) and (h % q == 0 or pow(h, (q - 1) // 2, q) == 1):
            break
        i += 1
    lp = q * pow(h, (p + 1) // 4, p) * pow(q, p - 2, p)
    rp = p * pow(h, (q + 1) // 4, q) * pow(p, q - 2, q)
    s = (lp + rp) % n
    return s, i


def verify_rabin(n: int, digest: bytes, s: int, padding: int) -> bool:
    """
    :param n: rabin public key
    :param digest: digest of signed message
    :param s: S of signature
    :param padding: the number of padding bytes
    """
    return hash_to_int(digest + b'\x00' * padding) % n == (s * s) % n


def write_number(number, filename):
    with open(f'{filename}.txt', 'w') as f:
        f.write('%d' % number)


def read_number(filename):
    with open(f'{filename}.txt', 'r') as f:
        return int(f.read())


def sign(hex_message: str):
    p = read_number('p')
    q = read_number('q')
    return sign_rabin(p, q, bytes.fromhex(hex_message))


def verify(hex_message, padding, hex_signature):
    n = read_number('n')
    return verify_rabin(n, bytes.fromhex(hex_message), hex_signature, padding)


if __name__ == '__main__':
    print('\n rabin signature - sCrypt Inc 2020 adapted from Scheerer - all rights reserved')
    print('\n rabin signature - copyright Scheerer Software 2018 - all rights reserved')

    print('\n\nFirst parameter is V (Verify) or S (Sign) or G (Generate)')
    print('\n verify signature (2 parameters):')
    print('   > python rabin.py V <hex message> <padding> <digital signature>')
    print('\n create signature S (2 parameter):')
    print('   > python rabin.py S <hex message>')
    print('\n generate key pair G (2 parameter):')
    print('   > python rabin.py G <hex seed>')

    print(f'\n\nnumber of parameters is {len(sys.argv) - 1}')

    if len(sys.argv) == 5 and sys.argv[1] == 'V':
        print(f'\n result of verification: {verify(sys.argv[2], int(sys.argv[3]), int(sys.argv[4], 16))}')

    if len(sys.argv) == 3 and sys.argv[1] == 'S':
        sig, pad = sign(sys.argv[2])
        print(f'\n padding = {pad}')
        print(f' digital signature = {hex(sig)}')

    if len(sys.argv) == 3 and sys.argv[1] == 'G':
        print('\n generate primes ... ')
        p_rabin = next_prime(hash_to_int(bytes.fromhex(sys.argv[2])) % (2 ** 501 + 1))
        q_rabin = next_prime(hash_to_int(bytes.fromhex(sys.argv[2] + '00')) % (2 ** 501 + 1))
        write_number(p_rabin, 'p')
        write_number(q_rabin, 'q')
        write_number(p_rabin * q_rabin, 'n')
        print(f'\n n_rabin = {hex(p_rabin * q_rabin)}')
