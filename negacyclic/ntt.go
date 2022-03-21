package negacyclic

import (
	"math/big"
)

// NTT computes the Number-Theoretic Transform of the input vector (a[0], ...,
// a[n-1) in the field F_q. It mutates the input vector with NTT(a) in
// bit-reversed order. It is assumed that q = 1 mod 2n.
//
// See Longa & Naehrig, SPEEDING UP THE NUMBER THEORETIC TRANSFORM FOR FASTER
// IDEAL LATTICE-BASED CRYPTOGRAPHY.
func (mul *Multiplier) NTT(a *Polynomial) {
	n := mul.N
	q := mul.Mod
	roots := mul.rootsBitReverse

	var t, j1, j2 int
	s, u, v := new(big.Int), new(big.Int), new(big.Int)

	t = n
	for m := 1; m < n; m = 2 * m {
		t /= 2
		for i := 0; i < m; i++ {
			j1 = 2 * i * t
			j2 = j1 + t - 1
			s.Set(roots[m+i])
			for j := j1; j <= j2; j++ {
				u.Set(a.Coeffs[j])
				v.Mul(a.Coeffs[j+t], s)
				a.Coeffs[j].Add(u, v).Mod(a.Coeffs[j], q)
				a.Coeffs[j+t].Sub(u, v).Mod(a.Coeffs[j+t], q)
			}
		}
	}
}

// INTT is the inverse Number-Theoretic Transform based on the GS butterfly.
// The output is in bit-reversed ordering, therefore, INTT(NTT(a)) = a in
// standard ordering.
func (mul *Multiplier) INTT(a *Polynomial) {
	n := mul.N
	q := mul.Mod
	rootsInv := mul.invRootsBitReverse

	var t, h, j1, j2 int
	s, u, v := new(big.Int), new(big.Int), new(big.Int)

	t = 1
	for m := n; m > 1; m /= 2 {
		j1 = 0
		h = m / 2
		for i := 0; i < h; i++ {
			j2 = j1 + t - 1
			s.Set(rootsInv[h+i])
			for j := j1; j <= j2; j++ {
				u.Set(a.Coeffs[j])
				v.Set(a.Coeffs[j+t])
				a.Coeffs[j].Add(u, v).Mod(a.Coeffs[j], q)
				a.Coeffs[j+t].Sub(u, v).Mul(a.Coeffs[j+t], s).Mod(a.Coeffs[j+t], q)
			}
			j1 += 2 * t
		}
		t *= 2
	}
	nInv := mul.nInvQ
	for j := 0; j < n; j++ {
		a.Coeffs[j].Mul(a.Coeffs[j], nInv).Mod(a.Coeffs[j], q)
	}
}

// Hadamard returns a polynomial `c` with `c[i] = a[i] * b[i] mod q`.
func (mul *Multiplier) Hadamard(a, b *Polynomial) *Polynomial {
	if a.Deg() != b.Deg() {
		panic("asymmetric multiplication call")
	}
	c := NewPolynomial(a.Deg())
	for i := range a.Coeffs {
		c.Coeffs[i] = new(big.Int)
		c.Coeffs[i].Mul(a.Coeffs[i], b.Coeffs[i]).Mod(c.Coeffs[i], mul.Mod)
	}
	return c
}
