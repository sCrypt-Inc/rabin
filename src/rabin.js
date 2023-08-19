/*  
A Rabin Signature JavaScript module adapted
from: https://github.com/scrypt-sv/rabin/blob/master/rabin.py
*/
const { toBigIntLE } = require( 'bigint-buffer' );
const { checkIfValidHexString,
  bigIntAbsoluteValue } = require( './utils' );
let crypto;
try {
  crypto = require( 'crypto' );
} catch ( err ) {
  throw ( 'Error: crypto support is disabled!' );
}

const PaddingBuffer = Buffer.from( '00', 'hex' );
class RabinSignature {

  /**
   * RabinSignature
   * @param {*} securityLevel : multiple of 512 bits.
   */
  constructor ( securityLevel = 1 ) {
    if ( securityLevel < 1 ) { 
      this.securityLevel = 1 
    } else {
      this.securityLevel = securityLevel
    }
  }

  greatestCommonDivisor ( a, b ) {
    if ( ( typeof a !== 'bigint' ) || ( typeof b !== 'bigint' ) )
      throw "Error: Incorrect argument(s) to greatestCommonDivisor()";

    a = bigIntAbsoluteValue( a );
    b = bigIntAbsoluteValue( b );
    if ( b > a ) {
      let t = a;
      a = b;
      b = t;
    }
    while ( b > 0 ) {
      let t = b;
      b = a % b;
      a = t;
    }
    return a;
  }

  // Calculates: base^exponent % modulus
  powerMod ( base, exponent, modulus ) {
    if ( modulus === 1n ) return 0n;
    let result = 1n;
    base = base % modulus;
    while ( exponent > 0n ) {
      if ( exponent % 2n === 1n ) //odd number
        result = ( result * base ) % modulus;
      exponent = exponent >> 1n; //divide by 2
      base = ( base * base ) % modulus;
    }
    return result;
  }


  bin2hash ( bytes ) {
    const hBytes = crypto.createHash( 'sha256' ).update( bytes ).digest();
    let idx = hBytes.byteLength / 2;
    let hl = crypto.createHash( 'sha256' ).update( hBytes.slice( 0, idx ) ).digest();
    let hr = crypto.createHash( 'sha256' ).update( hBytes.slice( idx, hBytes.byteLength ) ).digest();
    return Buffer.concat( [ hl, hr ] );
  }

  rabinHashBytes ( bytes ) {
    let result = this.bin2hash( bytes )
    for ( let i = 0; i < this.securityLevel - 1; i++ ) {
      result = Buffer.concat( [ result, this.bin2hash( result ) ] );
    }
    return toBigIntLE( result );
  }


  calculateNextPrime ( p ) {
    const smallPrimesProduct = 3n * 5n * 7n * 11n * 13n * 17n * 19n * 23n * 29n;
    while ( this.greatestCommonDivisor( p, smallPrimesProduct ) != 1 ) {
      p = p + 4n;
    }
    if ( this.powerMod( 2n, p - 1n, p ) != 1n ) {
      return this.calculateNextPrime( p + 4n );
    }
    if ( this.powerMod( 3n, p - 1n, p ) != 1n ) {
      return this.calculateNextPrime( p + 4n );
    }
    if ( this.powerMod( 5n, p - 1n, p ) != 1n ) {
      return this.calculateNextPrime( p + 4n );
    }
    if ( this.powerMod( 17n, p - 1n, p ) != 1n ) {
      return this.calculateNextPrime( p + 4n );
    }
    return p;
  }

  getPrimeNumber ( p ) {
    while ( p % 4n != 3n ) {
      p = p + 1n;
    }
    return this.calculateNextPrime( p );
  }


  root ( dataBuffer, p, q, nRabin ) {
    let sig, x, paddingByteCount = 0;
    while ( true ) {
      x = this.rabinHashBytes( dataBuffer ) % nRabin;
      sig = this.powerMod( p, q - 2n, q ) * p * this.powerMod( x, ( q + 1n ) / 4n, q );
      sig = ( this.powerMod( q, p - 2n, p ) * q * this.powerMod( x, ( p + 1n ) / 4n, p ) + sig ) % ( nRabin );
      if ( ( ( sig * sig ) % nRabin ) === x ) {
        break;
      }
      dataBuffer = Buffer.concat( [ dataBuffer, PaddingBuffer ] );
      paddingByteCount++;
    }
    return {
      "signature": sig,
      "paddingByteCount": paddingByteCount
    };
  }

  /**
   * Calculates Key nRabin (public key) from private key parts p & q
   * @param {BigInt} p Key private key 'p' part
   * @param {BigInt} q Key private key 'q' part
   * @returns {BigInt} Key nRabin (public key) = p * q
   */
  privKeyToPubKey ( privKey ) {
    const { p, q } = privKey
    if ( typeof ( p ) !== 'bigint' || typeof ( q ) !== 'bigint' )
      throw ( "Error: Key parts (p,q) should be BigInts (denoted by trailing 'n')." )
    return p * q;
  }

  /**
   * Generates Private Key p & q parts from a PRNG seed
   * @param {Number} the length of random Seed, default is 2048
   * @returns {JSON} {'p': BigInt,'q': BigInt}
   */
  generatePrivKey () {
    // Get a seed value from a random buffer and convert it to a BigInt
    let seed = crypto.randomBytes( 2048 );
    return this.generatePrivKeyFromSeed( seed );
  }

  /**
   * Generates Private Key p & q parts from Seed
   * @param {Buffer} seed
   * @returns {JSON} {'p': BigInt,'q': BigInt}
   */
  generatePrivKeyFromSeed ( seed ) {
    const range = 2n ** BigInt( 256 * this.securityLevel )
    let p = this.getPrimeNumber( this.rabinHashBytes( seed.toString( 'hex' ) ) % range );
    let q = this.getPrimeNumber( this.rabinHashBytes( seed.toString( 'hex' ) + '00' ) % range );
    return {
      "p": p,
      "q": q
    };
  }

  /**
   * Creates a Rabin signature of hexadecimal data with a given key's values
   * @param {String} dataHex Hexadecimal data string value
   * @param {BigInt} p Key 'p' value
   * @param {BigInt} q Key 'q' value
   * @param {BigInt} nRabin Key nRabin value
   * @returns {JSON} {"signature": BigInt, "paddingByteCount": Number} Signature and padding count
   */
  sign ( dataHex, privKey ) {
    // Check if data is valid hex
    if ( !checkIfValidHexString( dataHex ) )
      throw ( "Error: dataHex %s should be a hexadecimal String with or without '0x' at the beginning.", dataHex );
    // Remove 0x from data if necessary
    dataHex = dataHex.replace( '0x', '' );
    // Check key parts are correct values
    const { p, q } = privKey
    if ( typeof ( p ) !== 'bigint' || typeof ( q ) !== 'bigint' )
      throw ( "Error: Key parts (p,q) should be BigInts (denoted by trailing 'n')." )
    return this.root( Buffer.from( dataHex, 'hex' ), p, q, p * q );
  }

  /**
   * Verifies a Rabin signature of hexadecimal data with given padding count, signature and key nRabin value
   * @param {String} dataHex Hexadecimal data string value
   * @param {Number} paddingByteCount Padding byte count
   * @param {BigInt} signature Rabin signature value
   * @param {BigInt} nRabin Public Key nRabin value
   * @returns {Boolean} If signature is valid or not
   */
  verify ( dataHex, sig, nRabin) {
    // Check if data is valid hex
    if ( !checkIfValidHexString( dataHex ) )
      throw ( "Error: Data %s should be a hexadecimal String with or without '0x' at the beginning.", dataHex );
    // Remove 0x from data if necessary
    dataHex = dataHex.replace( '0x', '' );
    const { paddingByteCount, signature } = sig
    // Ensure padding count is a number
    if ( typeof paddingByteCount !== 'number' )
      throw ( "Error: paddingByteCount should be a number" );
    // Check if signature is a BigInt
    if ( typeof ( signature ) !== 'bigint' )
      throw ( "Error: Signature should be a BigInt (denoted by trailing 'n')." );
    // Check if nRabin is a BigInt
    if ( typeof ( nRabin ) !== 'bigint' )
      throw ( "Error: Public Key nRabin should be a BigInt (denoted by trailing 'n')." );

    let dataBuffer = Buffer.from( dataHex, 'hex' );
    let paddingBuffer = Buffer.from( '00'.repeat( paddingByteCount ), 'hex' );
    let paddedDataBuffer = Buffer.concat( [ dataBuffer, paddingBuffer ] );
    let dataHash = this.rabinHashBytes( paddedDataBuffer );
    let hashMod = dataHash % nRabin;
    return hashMod === ( signature ** 2n % nRabin );
  }


}


module.exports = {
  RabinSignature
}
