/*
    Example usage of rabin.js
*/
const{ generatePrivKey,
    privKeyToPubKey,
    createSignature,
    verifySignature } = require("../src/rabin");
let crypto;
try {
    crypto = require('crypto');
} catch (err) {
    console.log('crypto support is disabled!');
}

let key = generatePrivKey();
console.log("key p = "+key.p);
console.log("key q = "+key.q);
let nRabin = privKeyToPubKey(key.p, key.q);
console.log("key nRabin = "+nRabin);

let dataHex = Buffer.from("msg").toString('hex');
console.log("dataHex = " + dataHex);

let signatureResult = createSignature(dataHex, key.p, key.q, nRabin);
console.log("Signature = " + signatureResult.signature);
console.log("Padding Bytes = " + signatureResult.paddingByteCount);

let result = verifySignature(dataHex, signatureResult.paddingByteCount, signatureResult.signature, nRabin);
console.log("Signature Verified = " + result);
