// Usage:
//
// var rb = new(Rabin)
// rb.Init(pString, qString)
//

package rabin

import (
	"crypto/sha256"
	"encoding/hex"
	"math/big"
)

type Rabin struct {
	P *big.Int
	Q *big.Int
	N *big.Int

	ONE  *big.Int
	TWO  *big.Int
	FOUR *big.Int

	Qplus1over4 *big.Int
	Pplus1over4 *big.Int

	Qsub2 *big.Int
	Psub2 *big.Int

	PQ *big.Int
	QP *big.Int

	PubKeyHex string
}

func (r *Rabin) Init(pString, qString string) {
	r.P = new(big.Int)
	r.Q = new(big.Int)
	r.P.SetString(pString, 10)
	r.Q.SetString(qString, 10)

	r.N = new(big.Int)
	r.N.Mul(r.P, r.Q)
	r.PubKeyHex = hex.EncodeToString(r.N.Bytes())

	r.ONE = new(big.Int).SetInt64(1)
	r.TWO = new(big.Int).SetInt64(2)
	r.FOUR = new(big.Int).SetInt64(4)

	r.Qplus1over4 = new(big.Int).Add(r.Q, r.ONE)
	r.Qplus1over4.Div(r.Qplus1over4, r.FOUR)

	r.Pplus1over4 = new(big.Int).Add(r.P, r.ONE)
	r.Pplus1over4.Div(r.Pplus1over4, r.FOUR)

	r.Qsub2 = new(big.Int).Sub(r.Q, r.TWO)
	r.Psub2 = new(big.Int).Sub(r.P, r.TWO)

	r.PQ = new(big.Int).Exp(r.P, r.Qsub2, r.Q)
	r.QP = new(big.Int).Exp(r.Q, r.Psub2, r.P)
}

func (r *Rabin) Verify(msg, signature, padding []byte) bool {
	msg = append(msg, padding...)
	hm := new(big.Int).SetBytes(hash(msg))
	hm.Mod(hm, r.N)

	sig := new(big.Int).SetBytes(signature)
	root := new(big.Int).Mul(sig, sig)
	root.Mod(root, r.N)

	if root.Cmp(hm) == 0 {
		return true
	}
	return false
}

func (r *Rabin) Sign(msg []byte) (signature, padding []byte) {
	padding = make([]byte, 2)
	for idx := 0; idx < 256; idx += 1 {
		padding[0] = byte(idx)
		hm := new(big.Int).SetBytes(hash(append(msg, padding...)))
		hm.Mod(hm, r.N)

		hmq := new(big.Int).Exp(hm, r.Qplus1over4, r.Q)
		proot := new(big.Int).Mul(r.PQ, r.P)
		proot.Mul(proot, hmq)

		hmp := new(big.Int).Exp(hm, r.Pplus1over4, r.P)
		qroot := new(big.Int).Mul(r.QP, r.Q)
		qroot.Mul(qroot, hmp)

		sig := new(big.Int).Add(proot, qroot)
		sig.Mod(sig, r.N)

		root := new(big.Int).Mul(sig, sig)
		root.Mod(root, r.N)

		if root.Cmp(hm) == 0 {
			signature = sig.Bytes()
			break
		}
	}
	return signature, padding
}

func hash(data []byte) (hashRev []byte) {
	sha := sha256.New()
	sha.Write(data[:])
	tmp := sha.Sum(nil)

	sha.Reset()
	sha.Write(tmp[:16])
	hashl := sha.Sum(nil)

	sha.Reset()
	sha.Write(tmp[16:])
	hashr := sha.Sum(nil)

	hash := []byte{}
	hash = append(hash, hashl...)
	hash = append(hash, hashr...)

	// little endian
	for _, b := range hash {
		hashRev = append([]byte{b}, hashRev...)
	}
	return
}
