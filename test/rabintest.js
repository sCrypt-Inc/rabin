var expect    = require("chai").expect;
const{generateKeyFromHexStringSeed,
    calculateRabinValueFromKeyParts,
    createRabinSignature,
    verifyRabinSignature} = require("../src/rabin");

// Test helper functions
// Get random int up to max value
let randInt = function(max) {
    return Math.floor(Math.random() * max);
}

//  random hex string generator
let randHex = function(len) {
    let maxlen = 8,
        min = Math.pow(16, Math.min(len, maxlen) - 1),
        max = Math.pow(16, Math.min(len, maxlen)) - 1,
        n = Math.floor(Math.random() * (max - min + 1)) + min,
        r = n.toString(16);
    while (r.length < len) {
        r = r + randHex(len - maxlen);
    }
    return r;
}
// Convert a decimal to a hex string
function decimalToHexString(number) {
    if (number < 0) {
        number = 0xFFFFFFFF + number + 1;
    }
    return number.toString(16);
}

/*describe("Section 1", function() {
    describe("Subsection 1", function() {
      it("Test name", function() {
        // Setup test values
        var blah = "";
        expect(something).to.equal(expectedResult);
      });
    });
  
    describe("Subsection 2", function() {
        etc...
    });
  });*/

let key = generateKeyFromHexStringSeed(randHex(randInt(100)));
let nRabin = calculateRabinValueFromKeyParts(key.p,key.q);
console.log("nRabin = 0x" + decimalToHexString(nRabin));

let dataHexString = Buffer.from(randHex(randInt(100))).toString('hex');
console.log("dataHexString = 0x" + dataHexString);
let signatureResult = createRabinSignature(dataHexString, key.p, key.q, nRabin);
console.log("Signature = 0x" + decimalToHexString(signatureResult.signature));
console.log("Padding Bytes = " + signatureResult.paddingByteCount);

let result = verifyRabinSignature(dataHexString, signatureResult.paddingByteCount, decimalToHexString(signatureResult.signature), decimalToHexString(nRabin));
console.log("Signature Verified = " + result);