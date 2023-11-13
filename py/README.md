# A simple Python library for generating Rabin signatures

## Usage

### As a Python module

```python
import rabin


# Generate prime pair
seed = b'\x01'
p, q = rabin.gen_prime_pair(seed)
n = p * q

# Sign message
message = bytes.fromhex('00112233445566778899aabbccddeeff')
sig, pad = rabin.sign_rabin(p, q, message)

# Verify signature
res = rabin.verify_rabin(n, message, sig, pad)
```

### From the command line

1. Generate key pairs with a seed.

```bash
> rabin G 01
generate primes ... 
n_rabin = 0x4dd67a38e65c6d5d0877e892f1453fa09d27313f1431fcea6e703571fd56bf0b8bdd4788d94a7ec79c4232ead62eb34cd4f212e13fddaadf659ac6e45dc32c9
```

2. Sign a message: get number of padding bytes and signature

```bash
> rabin S 00112233445566778899aabbccddeeff
padding = 3
digital signature = 0x420818748a86065611c0e1be3c0bae9c22fe5e515a4a35601be8b4d8bc1049c75775e01e07e2257a689e916ea7751bdfc8b1eeb51d418e2714ae2fc8eadde1b
```

3. Verify signature with results from step 2

```bash
> rabin V 00112233445566778899aabbccddeeff 3 420818748a86065611c0e1be3c0bae9c22fe5e515a4a35601be8b4d8bc1049c75775e01e07e2257a689e916ea7751bdfc8b1eeb51d418e2714ae2fc8eadde1b
result of verification: True
```
