/*  
A Rabin Signature JavaScript module adapted
from: https://github.com/scrypt-sv/rabin/blob/master/rabin.py
*/
const { bsv } = require('scrypttest');
const { toBigIntLE } = require('bigint-buffer');
const { BigIntMath } = require('./bigintmath'); // Graciously taken from: http://archive.is/th1Vo

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

function checkIfValidHex(hexString) {
    let re = new RegExp('^(0x|0X)?[a-fA-F0-9]+$');
    return re.test(hexString);
}

function hexStringToDecimal(hexString) {
    if (!checkIfValidHex(hexString))
        throw ("Error: hexString %s should be a hexadecimal string with or without '0x' at the beginning.", hexString);
    // Remove 0x from string if necessary
    hexString = hexString.replace('0x', '');

    var i, j, digits = [0],
        carry;
    for (i = 0; i < hexString.length; i += 1) {
        carry = parseInt(hexString.charAt(i), 16);
        for (j = 0; j < digits.length; j += 1) {
            digits[j] = digits[j] * 16 + carry;
            carry = digits[j] / 10 | 0;
            digits[j] %= 10;
        }
        while (carry > 0) {
            digits.push(carry % 10);
            carry = carry / 10 | 0;
        }
    }
    return digits.reverse().join('');
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

function hashBytes(bytes) {
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

/**
 * Generates a key p and q values with a hexadecimal seed
 * @param {String} seed Seed hexadecimal string value
 * @returns {JSON} {"p": p,"q": q} The key's p and q values
 */
function generateKeyFromHexStringSeed(seed) {
    // Check if seed is valid hex
    if (!checkIfValidHex(seed))
        throw ("Error: Seed %s should be a hexadecimal string with or without '0x' at the beginning.", seed);
    // Remove 0x from seed if necessary
    seed = seed.replace('0x', '');

    console.log("Generating key from seed: " + seed);
    let p = getPrimeNumber(hashBytes(Buffer.from(seed, 'hex')) % ((2n ** 501n) + 1n));
    let q = getPrimeNumber(hashBytes(Buffer.from(seed + '00', 'hex')) % ((2n ** 501n) + 1n));
    return {
        "p": p,
        "q": q
    };
}

/**
 * Returns the product of p and q (the rabin value)
 * @param {BigInt|Number} p Key 'p' value
 * @param {BigInt|Number} q Key 'q' value
 * @returns {BigInt} nRabin: The key's rabin value
 */
function calculateRabinValueFromKeyParts(p,q){
    if((typeof(p) !== 'bigint' && isNaN(p)) || (typeof(q) !== 'bigint' && isNaN(q)))
        throw("Error: Key parts should be numbers.")
    return BigInt(p) * BigInt(q);
}

const paddingBuffer = Buffer.from('00', 'hex');

function root(dataBuffer, p, q, nRabin) {
    let sig, x, paddingByteCount = 0;
    while (true) {
        let h1 = hashBytes(dataBuffer);
        x = hashBytes(dataBuffer) % nRabin;
        sig = powerMod(p, q - 2n, q) * p * powerMod(x, (q + 1n) / 4n, q);
        sig = (powerMod(q, p - 2n, p) * q * powerMod(x, (p + 1n) / 4n, p) + sig) % (nRabin);
        if (((sig * sig) % nRabin) === x) {
            break;
        }
        dataBuffer = Buffer.concat([dataBuffer, paddingBuffer]);
        paddingByteCount++;
    }
    return {
        "signature": sig,
        "paddingByteCount": paddingByteCount
    };
}

/**
 * Creates a Rabin signature of hexadecimal data with a given key's values
 * @param {String} dataHexString Hexadecimal data string value
 * @param {BigInt} p Key 'p' value
 * @param {BigInt} q Key 'q' value
 * @param {BigInt} nRabin Key nRabin value
 * @returns {JSON} {"signature": String, "paddingByteCount": Number} Signature and padding count
 */
function createRabinSignature(dataHexString, p, q, nRabin) {
    // Check if data is valid hex
    if (!checkIfValidHex(dataHexString))
        throw ("Error: Data %s should be a hexadecimal string with or without '0x' at the beginning.", messageHex);
    // Remove 0x from data if necessary
    dataHexString = dataHexString.replace('0x', '');
    return root(Buffer.from(dataHexString, 'hex'), p, q, nRabin);
}

/**
 * Verifies a Rabin signature of hexadecimal data with given padding count, signature and key nRabin value
 * @param {String} dataHexString Hexadecimal data string value
 * @param {Number} paddingByteCount Padding byte count
 * @param {String} signatureHexString Rabin signature hexadecimal string
 * @param {String} nRabinHexString Key nRabin value hexadecimal string
 * @returns {Boolean} If signature is valid or not
 */
function verifyRabinSignature(dataHexString, paddingByteCount, signatureHexString, nRabinHexString) {
    // Check if data is valid hex
    if (!checkIfValidHex(dataHexString))
        throw ("Error: Data %s should be a hexadecimal string with or without '0x' at the beginning.", messageHex);
    // Remove 0x from data if necessary
    dataHexString = dataHexString.replace('0x', ''); // Check if data is valid hex
    if (!checkIfValidHex(signatureHexString))
        throw ("Error: Signature %s should be a hexadecimal string with or without '0x' at the beginning.", messageHex);
    // Remove 0x from signature if necessary
    signatureHexString = signatureHexString.replace('0x', '');
    if (!checkIfValidHex(nRabinHexString))
        throw ("Error: nRabin %s should be a hexadecimal string with or without '0x' at the beginning.", messageHex);
    // Remove 0x from signature if necessary
    nRabinHexString = nRabinHexString.replace('0x', '');

    let dataBuffer = Buffer.from(dataHexString, 'hex');
    let paddingBuffer = Buffer.from('00'.repeat(paddingByteCount), 'hex');
    let paddedDataBuffer = Buffer.concat([dataBuffer, paddingBuffer]);
    let dataHash = hashBytes(paddedDataBuffer);
    let nRabinBigInt = BigInt(hexStringToDecimal(nRabinHexString));
    let hashMod = dataHash % nRabinBigInt;
    return hashMod === (BigInt(hexStringToDecimal(signatureHexString)) ** 2n % nRabinBigInt);
}

module.exports = {
    generateKeyFromHexStringSeed,
    calculateRabinValueFromKeyParts,
    createRabinSignature,
    verifyRabinSignature
}