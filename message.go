package ckks

import (
	"math/big"
	"strconv"

	"ckks/negacyclic"
)

// Plaintext is a native plaintext of the scheme, post encoding.
type Plaintext struct {
	m *negacyclic.Polynomial
}

// Ciphertext contains all the tagged informations for noise management, and
// the encrypted data.
type Ciphertext struct {
	a, b  *negacyclic.Polynomial
	level int
	ql    *big.Int
}

// String is the stringer method of a ciphertext
func (ciph *Ciphertext) String() string {
	str := "----- BEGIN CIPHERTEXT -----\n"
	str += "level:    " + strconv.Itoa(ciph.level) + "\n"
	str += "modulus:  " + ciph.ql.String() + "\n"
	str += "a[0]:     " + ciph.a.Coeffs[0].String() + "\n"
	str += "b[0]:     " + ciph.b.Coeffs[0].String() + "\n"
	str += "----- END CIPHERTEXT -----\n"
	return str
}

// Clone returns a copy of the receiver ciphertext
func (ciph *Ciphertext) Clone() *Ciphertext {
	a := negacyclic.PolynomialFromSlice(ciph.a.Coeffs)
	b := negacyclic.PolynomialFromSlice(ciph.b.Coeffs)
	ql := new(big.Int).Set(ciph.ql)
	level := ciph.level
	return &Ciphertext{
		a:     a,
		b:     b,
		level: level,
		ql:    ql,
	}
}

// NewPlaintextFromNegacyclic returns a plaintext with the given underlying
// polynomial.
func NewPlaintextFromNegacyclic(pol *negacyclic.Polynomial) *Plaintext {
	return &Plaintext{m: pol}
}

// GetPolynomial returns the underlying polynomial of this plaintext.
func (plt *Plaintext) GetPolynomial() *negacyclic.Polynomial {
	return plt.m
}

// Level returns the circuit level of this ciphertext.
func (ciph *Ciphertext) Level() int {
	return ciph.level
}

// Modulus returns the modulus associated to the level of this ciphertext.
func (ciph *Ciphertext) Modulus() *big.Int {
	return new(big.Int).Set(ciph.ql)
}
