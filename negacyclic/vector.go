package negacyclic

import (
	"math/big"
)

// Vector is a slice of integers.
type Vector struct {
	Coeffs []int
}

// NewVector creates a vector of given length.
func NewVector(leng int) *Vector {
	coeffs := make([]int, leng)
	return &Vector{Coeffs: coeffs}
}

// VectorFromSlice creates and returns a vector with the given coordinates.
func VectorFromSlice(slice []int) *Vector {
	return &Vector{Coeffs: slice}
}

// Len returns the length of the vector.
func (v *Vector) Len() int {
	return len(v.Coeffs)
}

// Polynomial creates and returns a negacyclic polynomial with the same
// coefficients as the given vector.
func (v *Vector) Polynomial() *Polynomial {
	coeffs := v.Coeffs
	pol := make([]*big.Int, len(coeffs))
	for i := range pol {
		pol[i] = big.NewInt(int64(coeffs[i]))
	}
	return &Polynomial{Coeffs: pol}
}
