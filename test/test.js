let expect = require("chai").expect;
const{ RabinSignature } = require("../src/rabin");
const { getRandomInt, getRandomHex, decimalToHexString } = require('../src/utils');

const securityLevel = 6 //from 1(512bit) to 6(3072bit)
const rabin = new RabinSignature(securityLevel)
let defaultKey = rabin.generatePrivKey();
let defaultNRabin = rabin.privKeyToPubKey(defaultKey.p, defaultKey.q);
let defaultDataHex = Buffer.from("msg").toString('hex');
let defaultNotHexValue = "defaultNotHexValue";
let defaultSignatureResult = rabin.sign(defaultDataHex, defaultKey.p, defaultKey.q, defaultNRabin);

describe("SecurityLevel Tests", function() {
  it("level", function() {
    for(let level = 1; level <=7; level++){
      const rabin = new RabinSignature(level)
      let key = rabin.generatePrivKey();
      let pubkey = rabin.privKeyToPubKey(key.p, key.q);
      expect(decimalToHexString(pubkey).length/2*8).to.greaterThanOrEqual(512*level);
    }
  });
})

describe("Create Signature Tests", function() {
  describe("Incorrect Input Tests", function() {
        it("Wrong data value", function() {
          expect(function(){rabin.sign(defaultNotHexValue, defaultKey.p, defaultKey.q, defaultNRabin);}).to.throw(defaultNotHexValue);
        });
        it("Wrong p value", function() {
          expect(function(){rabin.sign(defaultDataHex, defaultNotHexValue, defaultKey.q, defaultNRabin);}).to.throw("Error: Key parts (p,q) should be BigInts (denoted by trailing \'n\').");
        });
        it("Wrong q value", function() {
          expect(function(){rabin.sign(defaultDataHex, defaultKey.p, defaultNotHexValue, defaultNRabin);}).to.throw("Error: Key parts (p,q) should be BigInts (denoted by trailing \'n\').");
        });
        it("Wrong nRabin value", function() {
          expect(function(){rabin.sign(defaultDataHex, defaultKey.p, defaultKey.q, defaultNotHexValue);}).to.throw("Error: Key parts (p,q) should be BigInts (denoted by trailing \'n\').");
        });
    });
});

describe("Verify Signature Tests", function() {
    describe("Incorrect Input Tests", function() {
        it("Wrong data value", function() {
          expect(function(){rabin.verify(defaultNotHexValue, defaultSignatureResult.paddingByteCount, defaultSignatureResult.signature, defaultNRabin);}).to.throw(defaultNotHexValue);
        });
        it("Wrong padding value", function() {
            expect(function(){rabin.verify(defaultDataHex, "NaN", defaultSignatureResult.signature, defaultNRabin);}).to.throw("Error: paddingByteCount should be a number");
        });
        it("Wrong signature value", function() {
            expect(function(){rabin.verify(defaultNotHexValue, defaultSignatureResult.paddingByteCount, defaultNotHexValue, defaultNRabin);}).to.throw(defaultNotHexValue);
        });
        it("Wrong nRabin value", function() {
            expect(function(){rabin.verify(defaultNotHexValue, defaultSignatureResult.paddingByteCount, defaultSignatureResult.signature, defaultNotHexValue);}).to.throw(defaultNotHexValue);
        });
    });
});
let randomValueTestCount = 10;
describe("Random seed Key Generation, Signature Creation & Verification Tests", function() {
    it("Expecting "+randomValueTestCount+" Passing Tests", function() {
        let verificationCount = 0;
        for(let i = 0; i < randomValueTestCount; i++){
            let key = rabin.generatePrivKey();
            let nRabin = rabin.privKeyToPubKey(key.p, key.q);
            let dataHex = getRandomHex(getRandomInt(2,100));
            let signatureResult = rabin.sign(dataHex, key.p, key.q, nRabin);
            let result = rabin.verify(dataHex, signatureResult.paddingByteCount, signatureResult.signature, nRabin);
            if(result)
              verificationCount++;
            else
              console.log("Error: Test failing with values: "+{"key":key,"nRabin":nRabin,"dataHex":dataHex});
        }
        expect(verificationCount).to.equal(randomValueTestCount);
    });
});

