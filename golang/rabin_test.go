package rabin

import (
	"encoding/hex"
	"testing"
)

var (
	pString = "4500086422777284614649185698080302158559082854283623085071286437702609134945108376498504441947235804413771973268603081955797477873992855707579719874199"
	qString = "644767523354888926443294407216811496298090339710859618436800524594486048803150814665399137334438348620190687521269075965377327693448171249204212488583"
	rb      = new(Rabin)
)

func init() {
	rb.Init(pString, qString)
}

func TestSign(t *testing.T) {
	msg := []byte("hello")
	sig, padding := rb.Sign(msg)
	t.Log("msg:", hex.EncodeToString(msg))
	t.Log("sig len:", len(sig))
	t.Log("sig:", hex.EncodeToString(sig))
	t.Log("pad:", hex.EncodeToString(padding))

	ok := rb.Verify(msg, sig, padding)
	t.Log("verify:", ok)
}

func BenchmarkSign(b *testing.B) {
	b.Log("N:", b.N)
	msg := []byte("hello")
	for i := 0; i < b.N; i++ {
		rb.Sign(msg)
	}
}

func BenchmarkVerify(b *testing.B) {
	msg := []byte("hello")
	sig, padding := rb.Sign(msg)
	b.Log("sig len:", len(sig))
	b.Log("sig:", hex.EncodeToString(sig))
	b.Log("pad:", hex.EncodeToString(padding))

	b.Log("N:", b.N)
	for i := 0; i < b.N; i++ {
		rb.Verify(msg, sig, padding)
	}
}
