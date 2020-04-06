const { bsv } = require('scrypttest');
const {toBigIntBE, toBigIntLE, toBufferBE, toBufferLE} = require('bigint-buffer');

const nrabin = 0x15525796ddab817a3c54c4bea4ef564f090c5909b36818c1c13b9e674cf524aa3387a408f9b63c0d88d11a76471f9f2c3f29c47a637aa60bf5e120d1f5a65221;

function greatestCommonDivisor(a,b){
    if ((typeof a !== 'number') || (typeof b !== 'number')) 
        return false;
    a = Math.abs(a);
    b = Math.abs(b);
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
    if (modulus === 1) return 0;
    var result = 1;
    base = base % modulus;
    while (exponent > 0) {
        if (exponent % 2 === 1)  //odd number
            result = (result * base) % modulus;
        exponent = exponent >> 1; //divide by 2
        base = (base * base) % modulus;
    }
    return result;
}
// Get a BigInt from a buffer in big endian format
toBigIntBE(Buffer.from('deadbeef', 'hex'));

function hashBytes(bytes){
    //console.log(bytes);
    hBytes = bsv.crypto.Hash.sha256(bytes);
    //console.log(hBytes);
    var idx = hBytes.byteLength/2;
    //console.log(idx);
    var hl = bsv.crypto.Hash.sha256(hBytes.slice(0,idx));
    //console.log(hl);
    var hr = bsv.crypto.Hash.sha256(hBytes.slice(idx,hBytes.byteLength));
    //console.log(hr);
    var concatenated = Buffer.concat([hl,hr]);
    var result = toBigIntLE(concatenated);
    //console.log("From BYTES: "+result);
    return result;
}

function calculateNextPrime(p){
    /*smallPrimesProduct = 3*5*7*11*13*17*19*23*29;
    while(greatestCommonDivisor(p,smallPrimesProduct)!=1){
        p=p+4;
    }
    if(powerMod(2,p-1,p)!=1){
        return calculateNextPrime(p+4);
    }
    if(powerMod(2,p-1,p)!=1){
        return calculateNextPrime(p+4);
    }
    if(powerMod(5,p-1,p)!=1){
        return calculateNextPrime(p+4);
    }
    if(powerMod(17,p-1,p)!=1){
        return calculateNextPrime(p+4);
    }*/
    return p;
}

function getPrimeNumber(p){
    /*while(p%4!=3){
        p = p + 1;
    }*/
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
    var p = getPrimeNumber(hashBytes(Buffer.from(seed, 'hex')));
    var q = getPrimeNumber(hashBytes(Buffer.from(seed+'00', 'hex')));
    var result = decimalToHexString(p.value*q.value);
    console.log("nrabin = 0x"+result);
}

generate('0x01');
