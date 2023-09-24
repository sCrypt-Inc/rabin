package main

import (
    "crypto/rand"
    "fmt"
    "hash/sha256"
    "math/big"
)

// RabinSecurityLevel represents the security level for the Rabin signature algorithm.
type RabinSecurityLevel struct {
    Level int
}

// CalculateBits calculates the number of bits in the Rabin signature algorithm.
func (r *RabinSecurityLevel) CalculateBits() int {
    return r.Level * 512
}

// RabinPubKey is the public key for the Rabin signature algorithm.
type RabinPubKey struct {
    N *big.Int
}

// RabinSig is the signature for the Rabin signature algorithm.
type RabinSig struct {
    S *big.Int
    U []byte
}

// GenerateRabinKeyPair generates a public and private key pair for the Rabin signature algorithm.
func GenerateRabinKeyPair(securityLevel *RabinSecurityLevel) (*RabinPubKey, *big.Int, error) {
    // Generate two large prime numbers.
    p, err := rand.Prime(rand.Reader, securityLevel.CalculateBits())
    if err != nil {
        return nil, nil, err
    }

    q, err := rand.Prime(rand.Reader, securityLevel.CalculateBits())
    if err != nil {
        return nil, nil, err
    }

    // Compute the public key.
    n := new(big.Int).Mul(p, q)

    // Compute the private key.
    phi := new(big.Int).Mul(p.Sub(p, big.NewInt(1)), q.Sub(q, big.NewInt(1)))
    e := new(big.Int).SetUint64(65537)
    d := new(big.Int).ModInverse(e, phi)

    return &RabinPubKey{n}, d, nil
}

// SignRabin signs a message using the Rabin signature algorithm.
func SignRabin(msg []byte, privKey *big.Int, pubKey *RabinPubKey) (*RabinSig, error) {
    // Compute the hash of the message.
    h := sha256.Sum256(msg)

    // Compute the signature.
    s := new(big.Int).Exp(new(big.Int).SetBytes(h), privKey, pubKey.N)

    // Pad the signature with random bytes.
    u := make([]byte, securityLevel.CalculateBits())
    rand.Read(u)

    return &RabinSig{s, u}, nil
}

// VerifyRabin verifies a Rabin signature.
func VerifyRabin(msg []byte, sig *RabinSig, pubKey *RabinPubKey) bool {
    // Compute the hash of the message.
    h := sha256.Sum256(msg)

    // Compute the signature.
    s2 := new(big.Int).Mod(new(big.Int).Exp(sig.S, big.NewInt(2), pubKey.N), pubKey.N)

    // Check if the signature is valid.
    return s2.Cmp(new(big.Int).SetBytes(h)) == 0
}

func main() {
    // Create a new RabinSecurityLevel object with the default security level.
    securityLevel := &RabinSecurityLevel{Level: 6}

    // Generate a public and private key pair.
    pubKey, privKey, err := GenerateRabinKeyPair(securityLevel)
    if err != nil {
        fmt.Println(err)
        return
    }

    // Sign a message.
    msg := []byte("Hello, sCrypt!")
    sig, err := SignRabin(msg, privKey, pubKey)
    if err != nil {
        fmt.Println(err)
        return
    }

    // Verify the signature.
    isValid := VerifyRabin(msg, sig, pubKey)
    if isValid {
        fmt.Println("Signature is valid.")
    } else {
        fmt.Println("Signature is invalid.")
    }
}
