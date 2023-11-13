import rabin

def test_gen_prime_pair():
    # Test prime pair generation
    seed = b'\x01'
    p, q = rabin.gen_prime_pair(seed)
    assert isinstance(p, int) and isinstance(q, int), "p and q should be integers"
    assert p != q, "p and q should be distinct primes"

def test_sign_rabin():
    # Test signing a message
    seed = b'\x01'
    p, q = rabin.gen_prime_pair(seed)
    message = bytes.fromhex('00112233445566778899aabbccddeeff')
    sig, pad = rabin.sign_rabin(p, q, message)
    assert isinstance(sig, int), "Signature should be an integer"
    assert isinstance(pad, int), "Padding should be int"

def test_verify_rabin():
    # Test verifying a signature
    seed = b'\x01'
    p, q = rabin.gen_prime_pair(seed)
    n = p * q
    message = bytes.fromhex('00112233445566778899aabbccddeeff')
    sig, pad = rabin.sign_rabin(p, q, message)
    res = rabin.verify_rabin(n, message, sig, pad)
    assert res is True, "Signature verification failed"

def test_verify_rabin_with_wrong_signature():
    # Test verifying with a wrong signature
    seed = b'\x01'
    p, q = rabin.gen_prime_pair(seed)
    n = p * q
    message = bytes.fromhex('00112233445566778899aabbccddeeff')
    wrong_sig = 12345  # Intentionally wrong signature
    pad = 8  # Intentionally wrong padding
    res = rabin.verify_rabin(n, message, wrong_sig, pad)
    assert res is False, "Verification should fail with wrong signature"

