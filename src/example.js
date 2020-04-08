/*
    Example usage of rabin.js
*/
const{ generateRabinKeyFromSeed,
    createRabinSignature,
    verifyRabinSignature } = require("../src/rabin");
const { getRandomInt, getRandomHex } = require('../src/utils');

let key = generateRabinKeyFromSeed('0xe8d999619a31a000187075157c2213001893c551e44532003cf52959aa1154');//getRandomHex(getRandomInt(100)));
console.log("key p = "+key.p);
console.log("key q = "+key.q);
console.log("key nRabin = "+key.nRabin);

let dataHex = Buffer.from("msg2").toString('hex');//getRandomHex(getRandomInt(100));
console.log("dataHex = " + dataHex);

let signatureResult = createRabinSignature(dataHex, key.p, key.q, key.nRabin);
console.log("Signature = " + signatureResult.signature);
console.log("Padding Bytes = " + signatureResult.paddingByteCount);

let result = verifyRabinSignature(dataHex, signatureResult.paddingByteCount, signatureResult.signature, key.nRabin);
console.log("Signature Verified = " + result);
