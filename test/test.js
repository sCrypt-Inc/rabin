let expect = require("chai").expect;
const{ RabinSignature } = require("../src/rabin");
const { getRandomInt, getRandomHex, decimalToHexString } = require('../src/utils');

const securityLevel = 6 //from 1(512bit) to 6(3072bit)
const rabin = new RabinSignature(securityLevel)
let defaultKey = rabin.generatePrivKey();
const keyWrongP = Object.assign({}, defaultKey, { p: 7 });
const keyWrongQ = Object.assign({}, defaultKey, { q: 11 });
let defaultNRabin = rabin.privKeyToPubKey(defaultKey);
let defaultDataHex = Buffer.from("msg").toString('hex');
let defaultNotHexValue = "defaultNotHexValue";
let defaultSignatureResult = rabin.sign(defaultDataHex, defaultKey);
const signatureResultWrongPadding = Object.assign({}, defaultSignatureResult, { paddingByteCount: 'NaN' });
const signatureResultWrongSignature = Object.assign({}, defaultSignatureResult, { signature: defaultNotHexValue });

describe("SecurityLevel Tests", function() {
  it("level", function() {
    for(let level = 1; level <=7; level++){
      const rabin = new RabinSignature(level)
      let key = rabin.generatePrivKey();
      let pubkey = rabin.privKeyToPubKey(key);
      expect(decimalToHexString(pubkey).length/2*8).to.greaterThanOrEqual(512*level);
    }
  });
})

describe("Create Signature Tests", function() {
  describe("Incorrect Input Tests", function() {
        it("Wrong data value", function() {
          expect(function(){rabin.sign(defaultNotHexValue, defaultKey);}).to.throw(defaultNotHexValue);
        });
        it("Wrong p value", function() {
          expect(function(){rabin.sign(defaultDataHex, keyWrongP);}).to.throw("Error: Key parts (p,q) should be BigInts (denoted by trailing \'n\').");
        });
        it("Wrong q value", function() {
          expect(function(){rabin.sign(defaultDataHex, keyWrongQ);}).to.throw("Error: Key parts (p,q) should be BigInts (denoted by trailing \'n\').");
        });
    });
});

describe("Verify Signature Tests", function() {
    describe("Incorrect Input Tests", function() {
        it("Wrong data value", function() {
          expect(function(){rabin.verify(defaultNotHexValue, defaultSignatureResult, defaultNRabin);}).to.throw(defaultNotHexValue);
        });
        it("Wrong padding value", function() {
            expect(function(){rabin.verify(defaultDataHex, signatureResultWrongPadding, defaultNRabin);}).to.throw("Error: paddingByteCount should be a number");
        });
        it("Wrong signature value", function() {
            expect(function(){rabin.verify(defaultNotHexValue, signatureResultWrongSignature, defaultNRabin);}).to.throw(defaultNotHexValue);
        });
        it("Wrong nRabin value", function() {
            expect(function(){rabin.verify(defaultNotHexValue, defaultSignatureResult, defaultNotHexValue);}).to.throw(defaultNotHexValue);
        });
    });
});
let randomValueTestCount = 10;
describe("Random seed Key Generation, Signature Creation & Verification Tests", function() {
    it("Expecting "+randomValueTestCount+" Passing Tests", function() {
        let verificationCount = 0;
        for(let i = 0; i < randomValueTestCount; i++){
            let key = rabin.generatePrivKey();
            let nRabin = rabin.privKeyToPubKey(key);
            let dataHex = getRandomHex(getRandomInt(2,100));
            let signatureResult = rabin.sign(dataHex, key);
            let result = rabin.verify(dataHex, signatureResult, nRabin);
            if(result)
              verificationCount++;
            else
              console.log("Error: Test failing with values: "+{"key":key,"nRabin":nRabin,"dataHex":dataHex});
        }
        expect(verificationCount).to.equal(randomValueTestCount);
    });
});

