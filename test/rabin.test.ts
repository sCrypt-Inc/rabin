import { RabinPrivateKey, Rabin } from '../src/rabin'
import { expect } from 'chai'
import { bigIntToHexString, getRandomHexString, getRandomInt } from '../src/utils'
const bsv = require('bsv')

describe("SecurityLevel Tests", () => {

  it("level", () => {
    for (let level = 1; level <= 7; level++) {
      const rabin = new Rabin(level)
      let key = rabin.generatePrivKey();
      let pubkey = rabin.privKeyToPubKey(key);
      let pubkeyBitLen = bigIntToHexString(pubkey).length / 2 * 8
      let minBitLen = (512 * (level - 1)) + 1
      expect(pubkeyBitLen).to.greaterThanOrEqual(minBitLen);
    }
  })

})

describe('Rabin sign and verify Tests', () => {

  const rabin = new Rabin()

  const privKey = rabin.generatePrivKey()
  const pubKey = rabin.privKeyToPubKey(privKey)
  const wrongPubKey = rabin.privKeyToPubKey(rabin.generatePrivKey())

  const data = 'hello world'
  const dataHex = Buffer.from(data).toString('hex')
  const wrongDataHex = Buffer.from(data + '.').toString('hex')
  const notHexValue = 'Not Hex Value'

  const sig = rabin.sign(dataHex, privKey)
  const wrongSigSignature = Object.assign({}, sig, { signature: sig.signature + 1n })
  const wrongSigPadding = Object.assign({}, sig, { paddingByteCount: sig.paddingByteCount + 1 })

  it('should throw when signing a not hex data', () => {
    expect(() => {
      rabin.sign(notHexValue, privKey)
    }).to.throw(/should be a hexadecimal String/)
  })

  it('should throw when verifying a not hex data', () => {
    expect(() => {
      rabin.verify(notHexValue, sig, pubKey)
    }).to.throw(/should be a hexadecimal String/)
  })

  it('should pass verification', () => {
    expect(rabin.verify(dataHex, sig, pubKey)).to.equal(true)
  })

  it('should fail verification with wrong dataHex', () => {
    expect(rabin.verify(wrongDataHex, sig, pubKey)).to.equal(false)
  })

  it('should fail verification with wrong sig.paddingByteCount', () => {
    expect(rabin.verify(dataHex, wrongSigPadding, pubKey)).to.equal(false)
  })

  it('should fail verification with wrong sig.signature', () => {
    expect(rabin.verify(dataHex, wrongSigSignature, pubKey)).to.equal(false)
  })

  it('should fail verification with wrong public key', () => {
    expect(rabin.verify(dataHex, sig, wrongPubKey)).to.equal(false)
  })

})

function randomTest(rabin: Rabin, key: RabinPrivateKey): boolean {
  const nRabin = rabin.privKeyToPubKey(key);
  const dataHex = getRandomHexString(getRandomInt(2, 100));
  const sig = rabin.sign(dataHex, key);
  const verified = rabin.verify(dataHex, sig, nRabin);
  if (!verified) {
    console.log("Error: Test failing with values: " + { "key": key, "nRabin": nRabin, "dataHex": dataHex });
  }
  return verified
}

describe("Random seed Key Generation, Signature Creation & Verification Tests", function () {

  const rabin = new Rabin()

  const randomValueTestCount = 10;

  it(`Expecting ${randomValueTestCount} passing tests, Rabin private key generation from a PRNG seed`, function () {
    let verificationCount = 0;
    for (let i = 0; i < randomValueTestCount; i++) {
      const key = rabin.generatePrivKey()
      verificationCount += randomTest(rabin, key) ? 1 : 0
    }
    expect(verificationCount).to.equal(randomValueTestCount);
  })

  it(`Expecting ${randomValueTestCount} passing tests, Rabin private key generation from a BSV PrivateKey`, function () {
    let verificationCount = 0;
    for (let i = 0; i < randomValueTestCount; i++) {
      const seed = new bsv.PrivateKey()
      const key = rabin.generatePrivKeyFromSeed(seed.toBuffer())
      verificationCount += randomTest(rabin, key) ? 1 : 0
    }
    expect(verificationCount).to.equal(randomValueTestCount);
  })

})
