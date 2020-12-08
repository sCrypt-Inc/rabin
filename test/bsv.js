let expect = require( "chai" ).expect;
const { generatePrivKeyFromSeed,
  privKeyToPubKey,
  sign,
  verify } = require( "../src/rabin" );
const { getRandomInt, getRandomHex } = require( '../src/utils' );

const bsv = require( 'bsv' )

const bsvPrivateKey = new bsv.PrivateKey()
let defaultKey = generatePrivKeyFromSeed( bsvPrivateKey.toBuffer() );

let defaultNRabin = privKeyToPubKey( defaultKey.p, defaultKey.q );
let defaultDataHex = Buffer.from( "msg" ).toString( 'hex' );
let defaultNotHexValue = "defaultNotHexValue";
let defaultSignatureResult = sign( defaultDataHex, defaultKey.p, defaultKey.q, defaultNRabin );

describe( "Create Private from BSV PrivateKey", function () {

  describe( "Create Signature Tests", function () {
    describe( "Incorrect Input Tests", function () {
      it( "Wrong data value", function () {
        expect( function () { sign( defaultNotHexValue, defaultKey.p, defaultKey.q, defaultNRabin ); } ).to.throw( defaultNotHexValue );
      } );
      it( "Wrong p value", function () {
        expect( function () { sign( defaultDataHex, defaultNotHexValue, defaultKey.q, defaultNRabin ); } ).to.throw( "Error: Key parts (p,q) should be BigInts (denoted by trailing \'n\')." );
      } );
      it( "Wrong q value", function () {
        expect( function () { sign( defaultDataHex, defaultKey.p, defaultNotHexValue, defaultNRabin ); } ).to.throw( "Error: Key parts (p,q) should be BigInts (denoted by trailing \'n\')." );
      } );
      it( "Wrong nRabin value", function () {
        expect( function () { sign( defaultDataHex, defaultKey.p, defaultKey.q, defaultNotHexValue ); } ).to.throw( "Error: Key parts (p,q) should be BigInts (denoted by trailing \'n\')." );
      } );
    } );
  } );

  describe( "Verify Signature Tests", function () {
    describe( "Incorrect Input Tests", function () {
      it( "Wrong data value", function () {
        expect( function () { verify( defaultNotHexValue, defaultSignatureResult.paddingByteCount, defaultSignatureResult.signature, defaultNRabin ); } ).to.throw( defaultNotHexValue );
      } );
      it( "Wrong padding value", function () {
        expect( function () { verify( defaultDataHex, "NaN", defaultSignatureResult.signature, defaultNRabin ); } ).to.throw( "Error: paddingByteCount should be a number" );
      } );
      it( "Wrong signature value", function () {
        expect( function () { verify( defaultNotHexValue, defaultSignatureResult.paddingByteCount, defaultNotHexValue, defaultNRabin ); } ).to.throw( defaultNotHexValue );
      } );
      it( "Wrong nRabin value", function () {
        expect( function () { verify( defaultNotHexValue, defaultSignatureResult.paddingByteCount, defaultSignatureResult.signature, defaultNotHexValue ); } ).to.throw( defaultNotHexValue );
      } );
    } );
  } );
  let randomValueTestCount = 100;
  describe( "Random Key Generation, Signature Creation & Verification Tests", function () {
    it( "Expecting " + randomValueTestCount + " Passing Tests", function () {
      let verificationCount = 0;
      for ( let i = 0; i < randomValueTestCount; i++ ) {
        const seed = new bsv.PrivateKey()
        let key = generatePrivKeyFromSeed( seed.toBuffer() );
        let nRabin = privKeyToPubKey( key.p, key.q );
        let dataHex = getRandomHex( getRandomInt( 2, 100 ) );
        let signatureResult = sign( dataHex, key.p, key.q, nRabin );
        let result = verify( dataHex, signatureResult.paddingByteCount, signatureResult.signature, nRabin );
        if ( result )
          verificationCount++;
        else
          console.log( "Error: Test failing with values: " + { "key": key, "nRabin": nRabin, "dataHex": dataHex } );
      }
      expect( verificationCount ).to.equal( randomValueTestCount );
    } ).timeout(200000);
  } );

} );
