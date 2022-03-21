package negacyclic

import (
	"math/big"
)

// ZMultiplier handles the multiplication in a negacyclic ring of the form
// Z[X]/(X^n+1). Internally, it chooses a prime larger than the expected
// coefficients, and multiplies modulo this prime.
type ZMultiplier struct {
	N int
}

// NewZMultiplier creates and returns a ZMultiplier with the given
// parameters, after proper sanitization.
func NewZMultiplier(n int) *ZMultiplier {
	if !isPowerOfTwo(n) {
		panic("multiplier expects `n` power of two")
	}
	m := new(ZMultiplier)
	m.N = n
	return m
}

// Mul computes the product of x and y in the corresponding negacyclic ring.
func (m *ZMultiplier) Mul(x, y *Polynomial) *Polynomial {
	if x.Deg() != y.Deg() {
		panic("asymmetric multiply call")
	}
	if x.Deg() != m.N {
		panic("bad multiply length")
	}
	prime := big.NewInt(int64(2 * m.N))
	prime.Mul(prime, normInfinite(x)).Mul(prime, normInfinite(y))
	prime.Add(prime, big.NewInt(1))
	for !prime.ProbablyPrime(32) {
		prime.Add(prime, big.NewInt(int64(2*m.N)))
	}
	modM := NewMultiplier(m.N, prime)
	pol := modM.Mul(x, y)
	pol.Mod(prime)
	return pol
}

func normInfinite(pol *Polynomial) *big.Int {
	norm := new(big.Int)
	for _, val := range pol.Coeffs {
		if norm.CmpAbs(val) < 0 {
			norm.Abs(val)
		}
	}
	return norm
}
