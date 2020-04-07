const { bsv } = require('scrypttest');
const { toBigIntLE } = require('bigint-buffer');
const { BigIntMath } = require('./bigintmath'); // Graciously taken from: http://archive.is/th1Vo

function greatestCommonDivisor(a,b){
    if ((typeof a !== 'bigint') || (typeof b !== 'bigint'))
        throw "Error: Incorrect argument(s) to greatestCommonDivisor()";

    a = BigIntMath.abs(a);
    b = BigIntMath.abs(b);
    if(b>a){
        let t = a;
        a = b;
        b = t;
    }
    while(b>0) {
        let t = b;
        b = a % b;
        a = t;
    }
    return a;
}

function checkIfValidHex(hexString){
    let re = new RegExp('^(0x|0X)?[a-fA-F0-9]+$');
    return re.test(hexString);
}

function decimalToHexString(number)
{
  if (number < 0)
  {
    number = 0xFFFFFFFF + number + 1;
  }
  return number.toString(16);
}

function hexStringToDecimal(hexString) {
    if(!checkIfValidHex(hexString))
        throw("Error: hexString %s should be a hexadecimal string with or without '0x' at the beginning.",hexString);
    // Remove 0x from string if necessary
    hexString = hexString.replace('0x','');

    var i, j, digits = [0], carry;
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
        if (exponent % 2n === 1n)  //odd number
            result = (result * base) % modulus;
        exponent = exponent >> 1n; //divide by 2
        base = (base * base) % modulus;
    }
    return result;
}

function hashBytes(bytes){
    hBytes = bsv.crypto.Hash.sha256(bytes);
    let idx = hBytes.byteLength/2;
    let hl = bsv.crypto.Hash.sha256(hBytes.slice(0,idx));
    let hr = bsv.crypto.Hash.sha256(hBytes.slice(idx,hBytes.byteLength));
    return toBigIntLE(Buffer.concat([hl,hr]));
}

function calculateNextPrime(p){
    smallPrimesProduct = 3n*5n*7n*11n*13n*17n*19n*23n*29n;
    while(greatestCommonDivisor(p,smallPrimesProduct)!=1){
        p=p+4n;
    }
    if(powerMod(2n,p-1n,p)!=1n){
        return calculateNextPrime(p+4n);
    }
    if(powerMod(3n,p-1n,p)!=1n){
        return calculateNextPrime(p+4n);
    }
    if(powerMod(5n,p-1n,p)!=1n){
        return calculateNextPrime(p+4n);
    }
    if(powerMod(17n,p-1n,p)!=1n){
        return calculateNextPrime(p+4n);
    }
    return p;
}

function getPrimeNumber(p){
    while(p%4n!=3n){
        p = p + 1n;
    }
    return calculateNextPrime(p);
}

function generateKeyPartsAndRabinValue(seed){
    // Check if seed is valid hex
    if(!checkIfValidHex(seed))
        throw("Error: Seed %s should be a hexadecimal string with or without '0x' at the beginning.",seed);
    // Remove 0x from seed if necessary
    seed = seed.replace('0x','');

    console.log("Generating key from seed: "+seed);
    let p = getPrimeNumber(hashBytes(Buffer.from(seed, 'hex')) % ((2n**501n) + 1n));
    let q = getPrimeNumber(hashBytes(Buffer.from(seed+'00', 'hex')) % ((2n**501n) + 1n));
    return {"p":p,"q":q,"nrabin":p*q};
}

const paddingBuffer = Buffer.from('00','hex');

function root(dataBuffer,p,q,nrabin){
    let sig, x, paddingByteCount = 0;
    while(true){
        let h1 = hashBytes(dataBuffer);
        x = hashBytes(dataBuffer) % nrabin;
        sig = powerMod(p,q-2n,q) * p * powerMod(x,(q+1n)/4n,q);
        sig = (powerMod(q,p-2n,p) * q * powerMod(x,(p+1n)/4n,p) + sig) % (nrabin);
        if (((sig * sig) % nrabin) === x){
            break;
        }
        dataBuffer = Buffer.concat([dataBuffer, paddingBuffer]);
        paddingByteCount++;
    }
    return {"signature":sig,"paddingByteCount":paddingByteCount};
}

function signData(dataHex,p,q,nrabin){
    // Check if data is valid hex
    if(!checkIfValidHex(dataHex))
        throw ("Error: Data %s should be a hexadecimal string with or without '0x' at the beginning.",messageHex);
    // Remove 0x from data if necessary
    dataHex = dataHex.replace('0x','');
    return root(Buffer.from(dataHex,'hex'),p,q,nrabin);
}
  
function verifySignature(dataHex,paddingByteCount,signatureHex,nRabinHex){
    // Check if data is valid hex
    if(!checkIfValidHex(dataHex))
        throw ("Error: Data %s should be a hexadecimal string with or without '0x' at the beginning.",messageHex);
    // Remove 0x from data if necessary
    dataHex = dataHex.replace('0x','');    // Check if data is valid hex
    if(!checkIfValidHex(signatureHex))
        throw ("Error: Signature %s should be a hexadecimal string with or without '0x' at the beginning.",messageHex);
    // Remove 0x from signature if necessary
    signatureHex = signatureHex.replace('0x','');
    if(!checkIfValidHex(nRabinHex))
        throw ("Error: nRabin %s should be a hexadecimal string with or without '0x' at the beginning.",messageHex);
    // Remove 0x from signature if necessary
    nRabinHex = nRabinHex.replace('0x','');

    let dataBuffer = Buffer.from(dataHex,'hex');
    let paddingBuffer = Buffer.from('00'.repeat(paddingByteCount),'hex');
    let paddedDataBuffer = Buffer.concat([dataBuffer,paddingBuffer]);
    let dataHash = hashBytes(paddedDataBuffer);
    let nRabinBigInt = BigInt(hexStringToDecimal(nRabinHex));
    let hashMod = dataHash % nRabinBigInt;

    return hashMod === (BigInt(hexStringToDecimal(signatureHex))**2n % nRabinBigInt);
}

let randInt = function(max){
    return Math.floor(Math.random() * max);
}

//  random hex string generator
let randHex = function(len) {
    let maxlen = 8,
        min = Math.pow(16,Math.min(len,maxlen)-1) 
        max = Math.pow(16,Math.min(len,maxlen)) - 1,
        n   = Math.floor( Math.random() * (max-min+1) ) + min,
        r   = n.toString(16);
    while ( r.length < len ) {
        r = r + randHex( len - maxlen );
    }
    return r;
}

let keyRabinValues = generateKeyPartsAndRabinValue(randHex(randInt(100)));
console.log("nRabin = 0x"+decimalToHexString(keyRabinValues.nrabin));

let dataHex = Buffer.from(randHex(randInt(100))).toString('hex');
console.log("dataHex = 0x"+dataHex);
let signatureResult = signData(dataHex,keyRabinValues.p,keyRabinValues.q,keyRabinValues.nrabin);
console.log("Signature = 0x"+decimalToHexString(signatureResult.signature));
console.log("Padding Bytes = "+signatureResult.paddingByteCount);

let result = verifySignature(dataHex,signatureResult.paddingByteCount,decimalToHexString(signatureResult.signature),decimalToHexString(keyRabinValues.nrabin));
console.log("Signature Verified = "+result);