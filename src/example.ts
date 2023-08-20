import { Rabin, RabinPrivateKey, RabinPublicKey, RabinSignature } from "./rabin";

const securityLevel = 6 // from 1(512bit) to 6(3072bit)
const rabin = new Rabin(securityLevel)

const privKey: RabinPrivateKey = rabin.generatePrivKey()
console.log('Rabin private key:', privKey)

const pubKey: RabinPublicKey = rabin.privKeyToPubKey(privKey)
console.log('Rabin public key:', pubKey)

const data = 'Hello sCrypt!'
console.log('data:', data)
const dataHex = Buffer.from(data).toString('hex')
console.log('dataHex:', dataHex)

const sig: RabinSignature = rabin.sign(dataHex, privKey)
console.log('Rabin signature result:', sig)

const verified = rabin.verify(dataHex, sig, pubKey)
console.log('Signature verified:', verified)
