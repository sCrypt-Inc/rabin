/*
A Rabin Signature JavaScript module adapted
from: https://github.com/scrypt-sv/rabin/blob/master/rabin.py
*/
import { toBigIntLE } from 'bigint-buffer';
import { isHexString, bigIntAbsoluteValue } from './utils';
import { createHash, randomBytes } from 'crypto'

/**
 * Rabin signature result
 */
export interface RabinSignature {
  signature: bigint,
  paddingByteCount: number,
}

/**
 * Rabin private key
 */
export interface RabinPrivateKey {
  p: bigint,
  q: bigint,
}

/**
 * Rabin public key
 */
export type RabinPublicKey = bigint

export class Rabin {

  static readonly PaddingBuffer = Buffer.from('00', 'hex')

  securityLevel: number

  /**
   * RabinSignature
   * @param {*} securityLevel : multiple of 512 bits.
   */
  constructor(securityLevel: number = 6) {
    this.securityLevel = securityLevel < 1 ? 1 : securityLevel
  }

  greatestCommonDivisor(a: bigint, b: bigint): bigint {
    a = bigIntAbsoluteValue(a);
    b = bigIntAbsoluteValue(b);
    if (b > a) {
      let t = a;
      a = b;
      b = t;
    }
    while (b > 0) {
      let t = b;
      b = a % b;
      a = t;
    }
    return a;
  }

  // Calculates: base^exponent % modulus
  powerMod(base: bigint, exponent: bigint, modulus: bigint): bigint {
    if (modulus === 1n) return 0n;
    let result = 1n;
    base = base % modulus;
    while (exponent > 0n) {
      if (exponent % 2n === 1n) // odd number
        result = (result * base) % modulus;
      exponent = exponent >> 1n; // divide by 2
      base = (base * base) % modulus;
    }
    return result;
  }


  bin2hash(bytes: Buffer): Buffer {
    const hBytes = createHash('sha256').update(bytes).digest();
    let idx = hBytes.byteLength / 2;
    let hl = createHash('sha256').update(hBytes.slice(0, idx)).digest();
    let hr = createHash('sha256').update(hBytes.slice(idx, hBytes.byteLength)).digest();
    return Buffer.concat([hl, hr]);
  }

  rabinHashBytes(bytes: Buffer): bigint {
    let result = this.bin2hash(bytes)
    for (let i = 0; i < this.securityLevel - 1; i++) {
      result = Buffer.concat([result, this.bin2hash(result)]);
    }
    return toBigIntLE(result);
  }


  calculateNextPrime(p: bigint): bigint {
    const smallPrimesProduct = 3n * 5n * 7n * 11n * 13n * 17n * 19n * 23n * 29n;
    while (this.greatestCommonDivisor(p, smallPrimesProduct) != 1n) {
      p = p + 4n;
    }
    if (this.powerMod(2n, p - 1n, p) != 1n) {
      return this.calculateNextPrime(p + 4n);
    }
    if (this.powerMod(3n, p - 1n, p) != 1n) {
      return this.calculateNextPrime(p + 4n);
    }
    if (this.powerMod(5n, p - 1n, p) != 1n) {
      return this.calculateNextPrime(p + 4n);
    }
    if (this.powerMod(17n, p - 1n, p) != 1n) {
      return this.calculateNextPrime(p + 4n);
    }
    return p;
  }

  getPrimeNumber(p: bigint): bigint {
    while (p % 4n != 3n) {
      p = p + 1n;
    }
    return this.calculateNextPrime(p);
  }


  root(dataBuffer: Buffer, p: bigint, q: bigint, nRabin: bigint): RabinSignature {
    let signature: bigint, x: bigint, paddingByteCount: number = 0;
    while (true) {
      x = this.rabinHashBytes(dataBuffer) % nRabin;
      signature = this.powerMod(p, q - 2n, q) * p * this.powerMod(x, (q + 1n) / 4n, q);
      signature = (this.powerMod(q, p - 2n, p) * q * this.powerMod(x, (p + 1n) / 4n, p) + signature) % (nRabin);
      if (((signature * signature) % nRabin) === x) {
        break;
      }
      dataBuffer = Buffer.concat([dataBuffer, Rabin.PaddingBuffer]);
      paddingByteCount++;
    }
    return { signature, paddingByteCount };
  }

  /**
   * Calculates Rabin public key from private key
   */
  privKeyToPubKey(privKey: RabinPrivateKey): RabinPublicKey {
    const { p, q } = privKey
    return p * q;
  }

  /**
   * Generates Rabin private key
   */
  generatePrivKey(): RabinPrivateKey {
    // Get a seed value from a random buffer and convert it to a BigInt
    let seed = randomBytes(2048);
    return this.generatePrivKeyFromSeed(seed);
  }

  /**
   * Generates Rabin private key from a PRNG seed
   * @param {Buffer} seed
   * @returns {RabinPrivateKey} Rabin private key
   */
  generatePrivKeyFromSeed(seed: Buffer): RabinPrivateKey {
    const range = 2n ** BigInt(256 * this.securityLevel)
    let p = this.getPrimeNumber(this.rabinHashBytes(seed) % range);
    let q = this.getPrimeNumber(this.rabinHashBytes(Buffer.from(seed.toString('hex') + '00', "hex")) % range);
    return { p, q };
  }

  /**
   * Creates a Rabin signature of hexadecimal data with a given private key
   * @param {string} dataHex Hexadecimal data string value
   * @param {RabinPrivateKey} privKey Rabin private key
   * @returns {RabinSignature} Rabin signature result
   */
  sign(dataHex: string, privKey: RabinPrivateKey): RabinSignature {
    // Check if data is valid hex
    if (!isHexString(dataHex))
      throw (`Error: dataHex ${dataHex} should be a hexadecimal String with or without '0x' at the beginning.`);
    // Remove 0x from data if necessary
    dataHex = dataHex.replace('0x', '');
    // Check key parts are correct values
    const { p, q } = privKey
    return this.root(Buffer.from(dataHex, 'hex'), p, q, p * q);
  }

  /**
   * Verifies a Rabin signature of hexadecimal data with the given public key
   * @param {string} dataHex Hexadecimal data string value
   * @param {RabinSignature} sig Rabin signature result
   * @param {RabinPublicKey} pubKey Rabin public key
   * @returns {boolean} If signature is valid or not
   */
  verify(dataHex: string, sig: RabinSignature, pubKey: RabinPublicKey): boolean {
    // Check if data is valid hex
    if (!isHexString(dataHex))
      throw (`Error: Data ${dataHex} should be a hexadecimal String with or without '0x' at the beginning.`);
    // Remove 0x from data if necessary
    dataHex = dataHex.replace('0x', '');

    const { paddingByteCount, signature } = sig
    let dataBuffer = Buffer.from(dataHex, 'hex');
    let paddingBuffer = Buffer.from('00'.repeat(paddingByteCount), 'hex');
    let paddedDataBuffer = Buffer.concat([dataBuffer, paddingBuffer]);
    let dataHash = this.rabinHashBytes(paddedDataBuffer);
    let hashMod = dataHash % pubKey;
    return hashMod === (signature ** 2n % pubKey);
  }

}