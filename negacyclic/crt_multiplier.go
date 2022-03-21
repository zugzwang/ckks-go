package negacyclic

import (
	"math/big"
)

// CRTMultiplier handles the multiplication in a negacyclic ring of the form
// Z_{pq}[X]/(X^n+1), where p and q are primes. Internally, it operates modulo
// p and modulo q with NTT, and uses CRT.
type CRTMultiplier struct {
	PQ          *big.Int
	N           int
	pInvQ       *big.Int
	multiplierP *Multiplier
	multiplierQ *Multiplier
}

// NewCRTMultiplier creates and returns a CRTMultiplier with the given
// parameters, after proper sanitization.
func NewCRTMultiplier(n int, p, q *big.Int) *CRTMultiplier {
	if !isPowerOfTwo(n) {
		panic("multiplier expects `n` power of two")
	}
	if !p.ProbablyPrime(32) || !q.ProbablyPrime(32) || p.Cmp(q) == 0 {
		panic("multiplier expects two coprime moduli")
	}
	m := new(CRTMultiplier)
	m.N = n
	m.PQ = new(big.Int).Mul(p, q)
	m.pInvQ = modularInverse(p, q)
	m.multiplierP = NewMultiplier(n, p)
	m.multiplierQ = NewMultiplier(n, q)
	return m
}

// Mul computes the product of x and y in the corresponding negacyclic ring.
func (m *CRTMultiplier) Mul(x, y *Polynomial) *Polynomial {
	a := m.multiplierP.Mul(x, y)
	b := m.multiplierQ.Mul(x, y)

	// Inverse of the larger modulus, modulo the smaller modulus
	// Note z = a + p * [p^-1]_q (b - a) satisfies z = a mod p, z = b mod q.
	p := m.multiplierP.Mod
	z := NewPolynomial(x.Deg())
	for i := range x.Coeffs {
		z.Coeffs[i] = new(big.Int)
		z.Coeffs[i].Sub(b.Coeffs[i], a.Coeffs[i]).Mul(z.Coeffs[i], m.pInvQ)
		z.Coeffs[i].Mul(z.Coeffs[i], p).Add(z.Coeffs[i], a.Coeffs[i])
	}
	return z
}
