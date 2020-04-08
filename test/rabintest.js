let expect = require("chai").expect;
const{ generateRabinKeyFromSeed,
    createRabinSignature,
    verifyRabinSignature } = require("../src/rabin");
const { getRandomInt, getRandomHex } = require('../src/utils');

let defaultSeed = '0x01';
let defaultKey = generateRabinKeyFromSeed(defaultSeed);
let defaultWrongKey = generateRabinKeyFromSeed(defaultSeed+'00');
let defaultDataHex = Buffer.from("msg").toString('hex');
let defaultIncorrectHexResultValue = "0xdeadbeef";
let defaultIncorrectInputHexValue = "0x01";
let defaultNotHexValue = "defaultNotHexValue";
let defaultSignatureResult = createRabinSignature(defaultDataHex, defaultKey.p, defaultKey.q, defaultKey.nRabin);

let seed2 = 'e8d999619a31a000187075157c2213001893c551e44532003cf52959aa1154';
let key2 = generateRabinKeyFromSeed(seed2);

describe("Key Generation Tests", function() {
    describe("Correct Result Tests", function() {
        it("Sample Seed 1", function() {
          let key = generateRabinKeyFromSeed(defaultSeed);
          expect(key.p).to.equal("0x1a022b166eeb68c189739189af9718d2b302f08836c8a6dc2ba9de3badb1ef5c712e1ec1eeabd173407bb12ddc1e9fe01f18e96a01f74cbbad94d7a1ed7597");
          expect(key.q).to.equal("0xd1392c7117b81dc7d1cf6176473f4bc03ccc7963449b540fafd8910e448940d78e686d67da0d740365680b7a4ac2bf1202956769efedfb55bfa08b4fa42d7");
          expect(key.nRabin).to.equal("0x1541942cc552a95c4832350ce99c2970f5b3ce9237a09c70c0e867d28039c05209b601105d3b3634cdaee4931809bc0c41d6165a0df16829a3a31202f56003239dd2c6e12297e94ef03e6aa61a147ea2b51c476dc45f5a2406b66d1ece2755c1f3d4144c0a42acc99b599d0643654a4cac392efbcf3db84d4233834afd1");
        });
        it("Sample Seed 2 (no '0x' at start)", function() {
          let key = generateRabinKeyFromSeed(seed2);
          expect(key.p).to.equal("0x1812d7b358b9df6bb91e379143f5829d5b80ee854e445ba33eb71211ab430f019a38d15c2784a4b7ec5ae3ea7750ca9995c4f64ddc724e298ce6c7b9d1cb");
          expect(key.q).to.equal("0x1e1981a467080e1bbff8b94fa35de27aca304916e08e69083cc9e3f11e2da4b1f43b91f5bead915b79f17536e20e329fb3b9996ab38c4c38e6b4b03e34beeb");
          expect(key.nRabin).to.equal("0x2d49b4f095d57a37c0297d5fd2c3b140da581a8475ccd1ef4c38f940b184ddce705520fb9229165cf143242a995b9ad170072af9d5ca1cfc2f61c347556ff67386be7f82c100fb12d2d4eb25b8d914f7a25766212b05a69df2d6bed606e32b6f2aaedaa3f517d0e2fee018dfbaa30825e08bda9b3f59c2a3308843f59");
        });
    });
    describe("Incorrect Result Tests", function() {
        it("Incorrect P Value", function() {
            let key = generateRabinKeyFromSeed(defaultSeed);
            expect(key.p).not.equal(defaultIncorrectHexResultValue);
        });
        it("Incorrect Q Value", function() {
            let key = generateRabinKeyFromSeed(defaultSeed);
            expect(key.q).not.equal(defaultIncorrectHexResultValue);
        });
        it("Incorrect nRabin Value", function() {
            let key = generateRabinKeyFromSeed(defaultSeed);
            expect(key.nRabin).not.equal(defaultIncorrectHexResultValue);
        });
    });
    describe("Incorrect Input Tests", function() {
        it("Sample Wrong Seed", function() {
          expect(function(){generateRabinKeyFromSeed(defaultNotHexValue)}).to.throw(defaultNotHexValue);
        });
    });
});

describe("Create Signature Tests", function() {
    describe("Correct Result Tests", function() {
        it("Sample Seed 1", function() {
          let signatureResult = createRabinSignature(defaultDataHex, defaultKey.p, defaultKey.q, defaultKey.nRabin);
          expect(signatureResult.signature).to.equal("0x2d72c9a75bc88ad2445ac55a7d597524c3df228478144cb784ad762c7a35e9c83aeda3c2180a1b7f2b59033a9d599cbb656f094db636e5bafa296631d0783f1eec0302e977f7b327d7cf85752c0f5c1c6cdeb5bbc8a2f5d8b6ea27cafe261813c5b380a417dbe34d75178655d26f282461a574260ab15dc50fc91bff0e");
          expect(signatureResult.paddingByteCount).to.equal(10);
        });
        it("Sample Seed 1, Message 2", function() {
          let dataHex = Buffer.from("msg2").toString('hex');
          let signatureResult = createRabinSignature(dataHex, defaultKey.p, defaultKey.q, defaultKey.nRabin);
          expect(signatureResult.signature).to.equal("0x127f6ce61da0c33860df5a444466a8772e7c5b04717daecd3e199b301e914ce417570c49da7bbf433c62f7f78ce9dde2c64591c56f1d1c73992c8d7f7fb46f8f8d5148701d05e3d8543a44f27ff9cc7d57a53d721f8c423aa62a1303b487a5a69ca678190cefda4eb1939f068d2b63dc82528741600fc34bd7a9531a43a");
          expect(signatureResult.paddingByteCount).to.equal(2);
        });
        it("Sample Seed 2", function() {
          let signatureResult = createRabinSignature(defaultDataHex, key2.p, key2.q, key2.nRabin);
          expect(signatureResult.signature).to.equal("0x24b7ac0ac4610631555ac4f3e9d20a88bfff6cf1f596b491efd625cfcde93cb54d78492328b09b5f866fe15e39dc0ff49e54d5b1917272d3fb4afa6a2b20a848b7e4e3e6878116094a44f41314a561517b0694483cd27eaf4ab3cc138882de848a58d1b937413d37f5c3d0744ddc02dd84c9119cc45f5583351bc5f67");
          expect(signatureResult.paddingByteCount).to.equal(2);
        });
        it("Sample Seed 2, Message 2", function() {
          let dataHex = Buffer.from("msg2").toString('hex');
          let signatureResult = createRabinSignature(dataHex, key2.p, key2.q, key2.nRabin);
          expect(signatureResult.signature).to.equal("0x2a0936a26083e93c56e75a5cfd32cafd50101bc66b36be464b2794e7442014cd32e6238d2cfb42785ac015866fe333b1b24a3a9407823ba42094760d0c9b8f34ac54fa2d87cc4fa41ddf63215e7e408a0d539945c24a83c47f836e35639706d33fb7fe094fa5b8fb4998deeeefbd12eaaefbeabc828a3c5c432bfad68");
          expect(signatureResult.paddingByteCount).to.equal(10);
        });
    });
    describe("Incorrect Result Tests", function() {
        it("Incorrect From Wrong Data", function() {
          let signatureResult = createRabinSignature(defaultIncorrectInputHexValue, defaultKey.p, defaultKey.q, defaultKey.nRabin);
          expect(signatureResult.signature).not.equal(defaultSignatureResult.signature);
          expect(signatureResult.paddingByteCount).not.equal(defaultSignatureResult.paddingByteCount);
        });
        it("Incorrect From Wrong Key", function() {
          let signatureResult = createRabinSignature(defaultDataHex, defaultWrongKey.p, defaultWrongKey.q, defaultWrongKey.nRabin);
          expect(signatureResult.signature).not.equal(defaultSignatureResult.signature);
          expect(signatureResult.paddingByteCount).not.equal(defaultSignatureResult.paddingByteCount);
        });
    });
    describe("Incorrect Input Tests", function() {
        it("Wrong data value", function() {
          expect(function(){createRabinSignature(defaultNotHexValue, defaultKey.p, defaultKey.q, defaultKey.nRabin);}).to.throw(defaultNotHexValue);
        });
        it("Wrong p value", function() {
          expect(function(){createRabinSignature(defaultDataHex, defaultNotHexValue, defaultKey.q, defaultKey.nRabin);}).to.throw(defaultNotHexValue);
        });
        it("Wrong q value", function() {
          expect(function(){createRabinSignature(defaultDataHex, defaultKey.p, defaultNotHexValue, defaultKey.nRabin);}).to.throw(defaultNotHexValue);
        });
        it("Wrong nRabin value", function() {
          expect(function(){createRabinSignature(defaultDataHex, defaultKey.p, defaultKey.q, defaultNotHexValue);}).to.throw(defaultNotHexValue);
        });
    });
});

describe("Verify Signature Tests", function() {
    describe("Correct Result Tests", function() {
        it("Sample Seed 1", function() {
          let signatureVerificationResult = verifyRabinSignature(defaultDataHex, defaultSignatureResult.paddingByteCount, defaultSignatureResult.signature, defaultKey.nRabin);
          expect(signatureVerificationResult).to.equal(true);
        });
        it("Sample Seed 1, Message 2", function() {
          let dataHex = Buffer.from("msg2").toString('hex');
          let signatureResult = createRabinSignature(dataHex, defaultKey.p, defaultKey.q, defaultKey.nRabin);
          let signatureVerificationResult = verifyRabinSignature(dataHex, 2, signatureResult.signature, defaultKey.nRabin);
          expect(signatureVerificationResult).to.equal(true);
        });
        it("Sample Seed 2", function() {
          let signatureResult = createRabinSignature(defaultDataHex, key2.p, key2.q, key2.nRabin);
          let signatureVerificationResult = verifyRabinSignature(defaultDataHex, signatureResult.paddingByteCount, signatureResult.signature, key2.nRabin);
          expect(signatureVerificationResult).to.equal(true);
        });
        it("Sample Seed 2, Message 2", function() {
          let dataHex = Buffer.from("msg2").toString('hex');
          let signatureResult = createRabinSignature(dataHex, key2.p, key2.q, key2.nRabin);
          let signatureVerificationResult = verifyRabinSignature(dataHex, 10, signatureResult.signature, key2.nRabin);
          expect(signatureVerificationResult).to.equal(true);
        });
    });
    describe("Incorrect Result Tests", function() {
        it("Incorrect From Wrong Data", function() {
            let signatureVerificationResult = verifyRabinSignature(defaultIncorrectInputHexValue, defaultSignatureResult.paddingByteCount, defaultSignatureResult.signature, defaultKey.nRabin);
            expect(signatureVerificationResult).to.equal(false);
        });
        it("Incorrect From Wrong Key nRabin", function() {
          let signatureVerificationResult = verifyRabinSignature(defaultDataHex, defaultSignatureResult.paddingByteCount, defaultSignatureResult.signature, defaultWrongKey.nRabin);
          expect(signatureVerificationResult).to.equal(false);
        });
    });
    describe("Incorrect Input Tests", function() {
        it("Wrong data value", function() {
          expect(function(){verifyRabinSignature(defaultNotHexValue, defaultSignatureResult.paddingByteCount, defaultSignatureResult.signature, defaultKey.nRabin);}).to.throw(defaultNotHexValue);
        });
        it("Wrong padding value", function() {
            expect(function(){verifyRabinSignature(defaultDataHex, "NaN", defaultSignatureResult.signature, defaultKey.nRabin);}).to.throw("Error: paddingByteCount should be a number");
        });
        it("Wrong signature value", function() {
            expect(function(){verifyRabinSignature(defaultNotHexValue, defaultSignatureResult.paddingByteCount, defaultNotHexValue, defaultKey.nRabin);}).to.throw(defaultNotHexValue);
        });
        it("Wrong nRabin value", function() {
            expect(function(){verifyRabinSignature(defaultNotHexValue, defaultSignatureResult.paddingByteCount, defaultSignatureResult.signature, defaultNotHexValue);}).to.throw(defaultNotHexValue);
        });
    });
});
let randomValueTestCount = 10;
describe("Random Key Generation, Signature Creation & Verification Tests", function() {
    it("Expecting 10 Passing Tests", function() {
        let verificationCount = 0;
        for(let i = 0; i < randomValueTestCount; i++){
            let key = generateRabinKeyFromSeed(getRandomHex(getRandomInt(100)));
            let dataHex = getRandomHex(getRandomInt(100));
            let signatureResult = createRabinSignature(dataHex, key.p, key.q, key.nRabin);
            let result = verifyRabinSignature(dataHex, signatureResult.paddingByteCount, signatureResult.signature, key.nRabin);
            if(result===true){
                verificationCount++;
                console.log(verificationCount);
            }
        }
        expect(verificationCount).to.equal(randomValueTestCount);
    });
});