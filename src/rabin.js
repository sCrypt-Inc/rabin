/*  
A Rabin Signature JavaScript module adapted
from: https://github.com/scrypt-sv/rabin/blob/master/rabin.py
*/
const { bsv } = require('scrypttest');
const { toBigIntLE } = require('bigint-buffer');
const { BigIntMath } = require('./bigintmath');
const { checkIfValidHexString,
    decimalToHexString,
    hexStringToBigInt } = require('./utils');

function greatestCommonDivisor(a, b) {
    if ((typeof a !== 'bigint') || (typeof b !== 'bigint'))
        throw "Error: Incorrect argument(s) to greatestCommonDivisor()";

    a = BigIntMath.abs(a);
    b = BigIntMath.abs(b);
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
function powerMod(base, exponent, modulus) {
    if (modulus === 1n) return 0n;
    let result = 1n;
    base = base % modulus;
    while (exponent > 0n) {
        if (exponent % 2n === 1n) //odd number
            result = (result * base) % modulus;
        exponent = exponent >> 1n; //divide by 2
        base = (base * base) % modulus;
    }
    return result;
}

function rabinHashBytes(bytes) {
    hBytes = bsv.crypto.Hash.sha256(bytes);
    let idx = hBytes.byteLength / 2;
    let hl = bsv.crypto.Hash.sha256(hBytes.slice(0, idx));
    let hr = bsv.crypto.Hash.sha256(hBytes.slice(idx, hBytes.byteLength));
    return toBigIntLE(Buffer.concat([hl, hr]));
}

function calculateNextPrime(p) {
    smallPrimesProduct = 3n * 5n * 7n * 11n * 13n * 17n * 19n * 23n * 29n;
    while (greatestCommonDivisor(p, smallPrimesProduct) != 1) {
        p = p + 4n;
    }
    if (powerMod(2n, p - 1n, p) != 1n) {
        return calculateNextPrime(p + 4n);
    }
    if (powerMod(3n, p - 1n, p) != 1n) {
        return calculateNextPrime(p + 4n);
    }
    if (powerMod(5n, p - 1n, p) != 1n) {
        return calculateNextPrime(p + 4n);
    }
    if (powerMod(17n, p - 1n, p) != 1n) {
        return calculateNextPrime(p + 4n);
    }
    return p;
}

function getPrimeNumber(p) {
    while (p % 4n != 3n) {
        p = p + 1n;
    }
    return calculateNextPrime(p);
}

const paddingBuffer = Buffer.from('00', 'hex');

function root(dataBuffer, p, q, nRabin) {
    let sig, x, paddingByteCount = 0;
    while (true) {
        let h1 = rabinHashBytes(dataBuffer);
        x = rabinHashBytes(dataBuffer) % nRabin;
        sig = powerMod(p, q - 2n, q) * p * powerMod(x, (q + 1n) / 4n, q);
        sig = (powerMod(q, p - 2n, p) * q * powerMod(x, (p + 1n) / 4n, p) + sig) % (nRabin);
        if (((sig * sig) % nRabin) === x) {
            break;
        }
        dataBuffer = Buffer.concat([dataBuffer, paddingBuffer]);
        paddingByteCount++;
    }
    return {
        "signature": decimalToHexString(sig),
        "paddingByteCount": paddingByteCount
    };
}

function calculateRabinValueFromKeyParts(p,q){
    if((typeof(p) !== 'bigint' && isNaN(p)) || (typeof(q) !== 'bigint' && isNaN(q)))
        throw("Error: Key parts should be numbers.")
    return decimalToHexString(BigInt(p) * BigInt(q));
}

/**
 * Generates Key p, q and nRabin values from a hexadecimal seed
 * @param {String} seed hexadecimal string value
 * @returns {JSON} {'p': String,'q': String, 'nRabin': String} Key p, q and nRabin values in hex
 */
function generateRabinKeyFromSeed(seed) {
    // Check if seed is valid hex
    if (!checkIfValidHexString(seed))
        throw ("Error: Seed %s should be a hexadecimal String with or without '0x' at the beginning.", seed);
    // Remove 0x from seed if necessary
    seed = seed.replace('0x', '');

    let p = getPrimeNumber(rabinHashBytes(Buffer.from(seed, 'hex')) % ((2n ** 501n) + 1n));
    let q = getPrimeNumber(rabinHashBytes(Buffer.from(seed + '00', 'hex')) % ((2n ** 501n) + 1n));
    let nRabin = calculateRabinValueFromKeyParts(p,q);
    return {
        "p": decimalToHexString(p),
        "q": decimalToHexString(q),
        "nRabin": nRabin
    };
}

/**
 * Creates a Rabin signature of hexadecimal data with a given key's values
 * @param {String} dataHex Hexadecimal data string value
 * @param {String} p Key 'p' value
 * @param {String} q Key 'q' value
 * @param {String} nRabin Key nRabin value
 * @returns {JSON} {"signature": String, "paddingByteCount": Number} Signature and padding count
 */
function createRabinSignature(dataHex, p, q, nRabin) {
    // Check if data is valid hex
    if (!checkIfValidHexString(dataHex))
        throw ("Error: dataHex %s should be a hexadecimal String with or without '0x' at the beginning.", dataHex);
    // Remove 0x from data if necessary
    dataHex = dataHex.replace('0x', '');
    return root(Buffer.from(dataHex, 'hex'), hexStringToBigInt(p), hexStringToBigInt(q), hexStringToBigInt(nRabin));
}

/**
 * Verifies a Rabin signature of hexadecimal data with given padding count, signature and key nRabin value
 * @param {String} dataHex Hexadecimal data string value
 * @param {Number} paddingByteCount Padding byte count
 * @param {String} signatureHex Rabin signature hexadecimal string
 * @param {String} nRabinHex Key nRabin value hexadecimal string
 * @returns {Boolean} If signature is valid or not
 */
function verifyRabinSignature(dataHex, paddingByteCount, signatureHex, nRabinHex) {
    // Check if data is valid hex
    if (!checkIfValidHexString(dataHex))
        throw ("Error: Data %s should be a hexadecimal String with or without '0x' at the beginning.", dataHex);
    // Remove 0x from data if necessary
    dataHex = dataHex.replace('0x', '');
    // Check if signature is valid hex
    if (!checkIfValidHexString(signatureHex))
        throw ("Error: Signature %s should be a hexadecimal String with or without '0x' at the beginning.", signatureHex);
    // Remove 0x from signature if necessary
    signatureHex = signatureHex.replace('0x', '');
    // Check if nRabin is valid hex
    if (!checkIfValidHexString(nRabinHex))
        throw ("Error: nRabin %s should be a hexadecimal String with or without '0x' at the beginning.", nRabinHex);
    // Remove 0x from nRabin if necessary
    nRabinHex = nRabinHex.replace('0x', '');
    if(typeof paddingByteCount !== 'number')
        throw ("Error: paddingByteCount should be a number");

    let dataBuffer = Buffer.from(dataHex, 'hex');
    let paddingBuffer = Buffer.from('00'.repeat(paddingByteCount), 'hex');
    let paddedDataBuffer = Buffer.concat([dataBuffer, paddingBuffer]);
    let dataHash = rabinHashBytes(paddedDataBuffer);
    let nRabinBigInt = hexStringToBigInt(nRabinHex);
    let hashMod = dataHash % nRabinBigInt;
    return hashMod === (hexStringToBigInt(signatureHex) ** 2n % nRabinBigInt);
}

module.exports = {
    generateRabinKeyFromSeed,
    createRabinSignature,
    verifyRabinSignature
}
