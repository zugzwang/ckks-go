package negacyclic

import (
	"math/big"
)

// Multiplier handles the multiplication in a negacyclic ring modulo Mod, where
// Mod is a prime number.
type Multiplier struct {
	N                  int
	Mod                *big.Int
	nInvQ              *big.Int
	rootsBitReverse    []*big.Int
	invRootsBitReverse []*big.Int
}

// NewMultiplier creates and returns a CRTMultiplier with the given parameters,
// after proper sanitization.
func NewMultiplier(n int, mod *big.Int) *Multiplier {
	if !isPowerOfTwo(n) {
		panic("multiplier expects `n` power of two")
	}
	if !mod.ProbablyPrime(32) {
		panic("multiplier expects prime modulus")
	}
	one := new(big.Int)
	if one.Mod(mod, big.NewInt(int64(2*n))).Cmp(big.NewInt(1)) != 0 {
		panic("q != 1 mod 2n")
	}
	m := new(Multiplier)
	m.N = n
	m.Mod = mod

	m.nInvQ = modularInverse(big.NewInt(int64(n)), mod)

	g := FindPrimitiveRootOfUnity(2*n, mod)
	gInv := modularInverse(g, mod)
	m.rootsBitReverse = rootsOfUnityBitReverse(n, g, mod)
	m.invRootsBitReverse = rootsOfUnityBitReverse(n, gInv, mod)
	return m
}

// Mul computes the product of x and y in the corresponding negacyclic ring.
func (mul *Multiplier) Mul(x, y *Polynomial) *Polynomial {
	if x.Deg() != y.Deg() {
		panic("asymmetric multiplication call")
	}
	n := x.Deg()
	a, b := NewPolynomial(n), NewPolynomial(n)
	for i := 0; i < n; i++ {
		a.Coeffs[i], b.Coeffs[i] = new(big.Int), new(big.Int)
		a.Coeffs[i].Set(x.Coeffs[i])
		b.Coeffs[i].Set(y.Coeffs[i])
	}
	mul.NTT(a)
	mul.NTT(b)
	c := mul.Hadamard(a, b)
	mul.INTT(c)
	for _, coeff := range c.Coeffs {
		coeff.Mod(coeff, mul.Mod)
	}
	return c
}
