/*
    Example usage of rabin.js
*/
const { RabinSignature } = require("../src/rabin");
let crypto;
try {
    crypto = require('crypto');
} catch (err) {
    console.log('crypto support is disabled!');
}

const securityLevel = 6 // from 1(512bit) to 6(3072bit)
const rabin = new RabinSignature(securityLevel)

let key = rabin.generatePrivKey();
console.log("key p = " + key.p);
console.log("key q = " + key.q);
let nRabin = rabin.privKeyToPubKey(key);
console.log("key nRabin = " + nRabin);

let dataHex = Buffer.from("msg").toString('hex');
console.log("dataHex = " + dataHex);

let signatureResult = rabin.sign(dataHex, key);
console.log("Signature = " + signatureResult.signature);
console.log("Padding Bytes = " + signatureResult.paddingByteCount);

let result = rabin.verify(dataHex, signatureResult, nRabin);
console.log("Signature Verified = " + result);
