let expect = require("chai").expect;
const{ generatePrivKey,
    privKeyToPubKey,
    createSignature,
    verifySignature } = require("../src/rabin");
const { getRandomInt, getRandomHex } = require('../src/utils');

let defaultKey = generatePrivKey();
let defaultNRabin = privKeyToPubKey(defaultKey.p, defaultKey.q);
let defaultDataHex = Buffer.from("msg").toString('hex');
let defaultNotHexValue = "defaultNotHexValue";
let defaultSignatureResult = createSignature(defaultDataHex, defaultKey.p, defaultKey.q, defaultNRabin);

describe("Create Signature Tests", function() {
    describe("Incorrect Input Tests", function() {
        it("Wrong data value", function() {
          expect(function(){createSignature(defaultNotHexValue, defaultKey.p, defaultKey.q, defaultNRabin);}).to.throw(defaultNotHexValue);
        });
        it("Wrong p value", function() {
          expect(function(){createSignature(defaultDataHex, defaultNotHexValue, defaultKey.q, defaultNRabin);}).to.throw("Error: Key parts (p,q) should be BigInts (denoted by trailing \'n\').");
        });
        it("Wrong q value", function() {
          expect(function(){createSignature(defaultDataHex, defaultKey.p, defaultNotHexValue, defaultNRabin);}).to.throw("Error: Key parts (p,q) should be BigInts (denoted by trailing \'n\').");
        });
        it("Wrong nRabin value", function() {
          expect(function(){createSignature(defaultDataHex, defaultKey.p, defaultKey.q, defaultNotHexValue);}).to.throw("Error: Key parts (p,q) should be BigInts (denoted by trailing \'n\').");
        });
    });
});

describe("Verify Signature Tests", function() {
    describe("Incorrect Input Tests", function() {
        it("Wrong data value", function() {
          expect(function(){verifySignature(defaultNotHexValue, defaultSignatureResult.paddingByteCount, defaultSignatureResult.signature, defaultNRabin);}).to.throw(defaultNotHexValue);
        });
        it("Wrong padding value", function() {
            expect(function(){verifySignature(defaultDataHex, "NaN", defaultSignatureResult.signature, defaultNRabin);}).to.throw("Error: paddingByteCount should be a number");
        });
        it("Wrong signature value", function() {
            expect(function(){verifySignature(defaultNotHexValue, defaultSignatureResult.paddingByteCount, defaultNotHexValue, defaultNRabin);}).to.throw(defaultNotHexValue);
        });
        it("Wrong nRabin value", function() {
            expect(function(){verifySignature(defaultNotHexValue, defaultSignatureResult.paddingByteCount, defaultSignatureResult.signature, defaultNotHexValue);}).to.throw(defaultNotHexValue);
        });
    });
});
let randomValueTestCount = 100;
describe("Random Key Generation, Signature Creation & Verification Tests", function() {
    it("Expecting "+randomValueTestCount+" Passing Tests", function() {
        let verificationCount = 0;
        for(let i = 0; i < randomValueTestCount; i++){
            let key = generatePrivKey();
            let nRabin = privKeyToPubKey(key.p, key.q);
            let dataHex = getRandomHex(getRandomInt(2,100));
            let signatureResult = createSignature(dataHex, key.p, key.q, nRabin);
            let result = verifySignature(dataHex, signatureResult.paddingByteCount, signatureResult.signature, nRabin);
            if(result)
              verificationCount++;
            else
              console.log("Error: Test failing with values: "+{"key":key,"nRabin":nRabin,"dataHex":dataHex});
        }
        expect(verificationCount).to.equal(randomValueTestCount);
    });
});
