package negacyclic_test

import (
	"testing"

	"ckks/negacyclic"
)

func TestPolynomialCRTMultiplication(t *testing.T) {
	t.Run("nttCRTMedium", testNTTCRTMedium)
}

func testNTTCRTMedium(t *testing.T) {
	n := 1 << 10
	bitLenP := 100
	bitLenQ := 200
	p := negacyclic.RLWEPrime(bitLenP, 2*n)
	q := negacyclic.RLWEPrime(bitLenQ, 2*n)
	m := negacyclic.NewCRTMultiplier(n, p, q)
	x := randomElement(n, m.PQ)
	y := randomElement(n, m.PQ)
	mod := m.PQ
	naivePQ := negacyclic.Karatsuba(x, y)
	naivePQ.Mod(mod)
	nttPQ := m.Mul(x, y)
	nttPQ.Mod(mod)
	for i := range nttPQ.Coeffs {
		if nttPQ.Coeffs[i].Cmp(naivePQ.Coeffs[i]) != 0 {
			t.Fatal("incorrect result modulo pq")
		}
	}
}
