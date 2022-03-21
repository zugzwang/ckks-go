package ckks

import (
	"strconv"
)

// Parameters of the CKKS scheme.
type Parameters struct {
	N       int // Dimension of the cyclotomic ring; must be a power of two
	Depth   int // Maximum allowed homomorphic depth
	BitLenP int
	BitLenQ int     // base p > 0 for scaling
	Hamming int     // Hamming weight of secret vector
	Sigma   float64 // Std. deviation for discrete Gaussians
}

func (pars *Parameters) String() string {
	sigma := strconv.FormatFloat(pars.Sigma, 'f', 2, 64)
	str := "  N: " + strconv.Itoa(pars.N) + "\n"
	str += "  Depth: " + strconv.Itoa(pars.Depth) + "\n"
	str += "  BitLen(p): " + strconv.Itoa(pars.BitLenP) + "\n"
	str += "  BitLen(q): " + strconv.Itoa(pars.BitLenQ) + "\n"
	str += "  Hamming (secret key): " + strconv.Itoa(pars.Hamming) + "\n"
	str += "  Std.Dev (Gaussian sampling): " + sigma + "\n"
	return str
}
