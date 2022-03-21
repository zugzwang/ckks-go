package negacyclic_test

import (
	"crypto/rand"
	"math/big"
	"testing"

	"ckks/negacyclic"
)

func TestRLWEPrime(t *testing.T) {
	bitLens := []int{11, 100, 1000}
	for _, bitLen := range bitLens {
		n := 1024
		q := negacyclic.RLWEPrime(bitLen, n)
		if !q.ProbablyPrime(32) {
			t.Fatal("not prime")
		}
		if q.BitLen() < bitLen {
			t.Fatal("shorter prime than expected")
		}
	}
}

func TestFindLargeRootOfUnity(t *testing.T) {
	bitLen := 60
	n := 1 << 10
	q := negacyclic.RLWEPrime(bitLen, n)
	g := negacyclic.FindPrimitiveRootOfUnity(n, q)
	shouldBeOne := new(big.Int)
	shouldBeOne.Exp(g, big.NewInt(int64(n)), q)
	if shouldBeOne.Cmp(big.NewInt(1)) != 0 {
		t.Fatal("Failed to find a root of unity")
	}
	shouldBeOne.Exp(g, big.NewInt(int64(n/2)), q)
	if shouldBeOne.Cmp(big.NewInt(1)) == 0 {
		t.Fatal("Root of unity is not primitive")
	}
	newRoot := new(big.Int)
	newRoot.Set(g)
	m := make(map[string]int)
	for i := 0; i < n; i++ {
		newRoot.Mul(newRoot, g).Mod(newRoot, q)
		m[newRoot.String()]++
	}
	for _, value := range m {
		if value != 1 {
			t.Fatal("Root found twice")
		}
	}
	if len(m) != n {
		t.Fatal("Root of unity is not primitive")
	}
}

func TestFindRootOfUnityNewHope(t *testing.T) {
	// Example from https://eprint.iacr.org/2017/727.pdf
	q := big.NewInt(12289)
	n := 1024
	g := negacyclic.FindPrimitiveRootOfUnity(2*n, q)
	shouldBeOne := new(big.Int)
	shouldBeOne.Exp(g, big.NewInt(int64(2*n)), q)
	if shouldBeOne.Cmp(big.NewInt(1)) != 0 {
		t.Fatal("Failed to find a root of unity")
	}
	shouldBeOne.Exp(g, big.NewInt(int64(n)), q)
	if shouldBeOne.Cmp(big.NewInt(1)) == 0 {
		t.Fatal("Root of unity is not primitive")
	}
	newRoot := new(big.Int)
	newRoot.Set(g)
	m := make(map[string]int)
	for i := 0; i < 2*n; i++ {
		newRoot.Mul(newRoot, g).Mod(newRoot, q)
		m[newRoot.String()]++
	}
	for _, value := range m {
		if value != 1 {
			t.Fatal("Root found twice")
		}
	}
	if len(m) != 2048 {
		t.Fatal("Root of unity is not primitive")
	}
	newHopeQ, ok := m["9089"]
	if !ok || newHopeQ != 1 {
		t.Fatal("new hope Q, 9089, not found or found more than once")
	}
}

func TestNTT(t *testing.T) {
	t.Run("NTT_INTT_roundtrip", testNTTRoundtrip)
}

func testNTTRoundtrip(t *testing.T) {
	q := big.NewInt(12289)
	n := 1024
	m := negacyclic.NewMultiplier(n, q)
	x := randomElement(n, q)

	y := negacyclic.NewPolynomial(n)
	for i := 0; i < n; i++ {
		y.Coeffs[i] = new(big.Int)
		y.Coeffs[i].Set(x.Coeffs[i])
	}

	m.NTT(x)
	m.INTT(x)
	for i := 0; i < n; i++ {
		if y.Coeffs[i].Cmp(x.Coeffs[i]) != 0 {
			t.Fail()
		}
	}
}

func BenchmarkNumberTheoreticTransform(b *testing.B) {
	b.Run("newHope", benchNTTNewHope)
	b.Run("2048-100bits", benchNTTMedium)
	b.Run("32768-200bits", benchNTTLarge)
	b.Run("NTT", benchMulNTT)
}

func benchNTTNewHope(b *testing.B) {
	q := big.NewInt(12289)
	n := 1024
	m := negacyclic.NewMultiplier(n, q)
	x := randomElement(n, q)

	for i := 0; i < b.N; i++ {
		m.NTT(x)
	}
}

func benchNTTMedium(b *testing.B) {
	n := 1 << 11
	bitLenQ := 100
	q := negacyclic.RLWEPrime(bitLenQ, 2*n)
	m := negacyclic.NewMultiplier(n, q)
	x := randomElement(n, q)

	for i := 0; i < b.N; i++ {
		m.NTT(x)
	}
}

func benchNTTLarge(b *testing.B) {
	n := 1 << 15
	bitLenQ := 200
	q := negacyclic.RLWEPrime(bitLenQ, 2*n)
	m := negacyclic.NewMultiplier(n, q)
	x := randomElement(n, q)

	for i := 0; i < b.N; i++ {
		m.NTT(x)
	}
}

func randomElement(dim int, q *big.Int) *negacyclic.Polynomial {
	pol := negacyclic.NewPolynomial(dim)
	var err error
	for i := 0; i < dim; i++ {
		pol.Coeffs[i], err = rand.Int(rand.Reader, q)
		if err != nil {
			panic(err)
		}
	}
	return pol
}
