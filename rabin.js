const { bsv } = require('scrypttest');
const { toBigIntLE } = require('bigint-buffer');
const { BigIntMath } = require('./bigintmath');

const nrabin = 0x15525796ddab817a3c54c4bea4ef564f090c5909b36818c1c13b9e674cf524aa3387a408f9b63c0d88d11a76471f9f2c3f29c47a637aa60bf5e120d1f5a65221;

function greatestCommonDivisor(a,b){
    if ((typeof a !== 'bigint') || (typeof b !== 'bigint'))
        throw "Error: Incorrect argument(s) to greatestCommonDivisor()";

    a = BigIntMath.abs(a);
    b = BigIntMath.abs(b);
    if(b>a){
        var t = a;
        a = b;
        b = t;
    }
    while(b>0) {
        var t = b;
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

// calculates   base^exponent % modulus
function powerMod(base, exponent, modulus) {
    if (modulus === BigInt(1)) return 0;
    var result = BigInt(1);
    base = base % modulus;
    while (exponent > BigInt(0)) {
        if (exponent % BigInt(2) === BigInt(1))  //odd number
            result = (result * base) % modulus;
        exponent = exponent >> BigInt(1); //divide by 2
        base = (base * base) % modulus;
    }
    return result;
}

function hashBytes(bytes){
    hBytes = bsv.crypto.Hash.sha256(bytes);
    var idx = hBytes.byteLength/2;
    var hl = bsv.crypto.Hash.sha256(hBytes.slice(0,idx));
    var hr = bsv.crypto.Hash.sha256(hBytes.slice(idx,hBytes.byteLength));
    var concatenated = Buffer.concat([hl,hr]);
    var result = toBigIntLE(concatenated);
    return result;
}

function calculateNextPrime(p){
    smallPrimesProduct = BigInt(3*5*7*11*13*17*19*23*29);
    while(greatestCommonDivisor(p,smallPrimesProduct)!=1){
        p=p+BigInt(4);
    }
    if(powerMod(BigInt(2),p-BigInt(1),p)!=1){
        return calculateNextPrime(p+BigInt(4));
    }
    if(powerMod(BigInt(3),p-BigInt(1),p)!=1){
        return calculateNextPrime(p+BigInt(4));
    }
    if(powerMod(BigInt(5),p-BigInt(1),p)!=1){
        return calculateNextPrime(p+BigInt(4));
    }
    if(powerMod(BigInt(17),p-BigInt(1),p)!=1){
        return calculateNextPrime(p+BigInt(4));
    }
    return p;
}

function getPrimeNumber(p){
    while(p%BigInt(4)!=BigInt(3)){
        p = p + BigInt(1);
    }
    return calculateNextPrime(p);
}

function generate(seed){
    // Check if seed is valid hex
    if(!checkIfValidHex(seed)){
        console.log("Seed %s should be a hexadecimal string with or without '0x' at the beginning.",seed)
        return false;
    }
    seed = seed.replace('0x','');
    console.log("Generating primes from seed: "+seed);
    var p1 = hashBytes(Buffer.from(seed, 'hex'));
    var q1 = hashBytes(Buffer.from(seed+'00', 'hex'));
    var p = getPrimeNumber(p1 % ((BigInt(2)**BigInt(501)) + BigInt(1)));
    var q = getPrimeNumber(q1 % ((BigInt(2)**BigInt(501)) + BigInt(1)));
    var result = decimalToHexString(p*q);
    console.log("nrabin = 0x"+result);
}

generate('0x01');
