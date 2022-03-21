package negacyclic

import (
	"crypto/rand"
	"errors"
	"math"
	"math/big"
	"math/bits"
	mrand "math/rand"
)

// RLWEPrime samples a prime `q` of given bit length, satisfying the condition q
// = 1 mod n and such that phi(q). This prime is not sampled with a
// cryptographic random generator and MUST NOT be used as a secret value.
func RLWEPrime(bitLen, n int) *big.Int {
	prime := new(big.Int)
	nbits := bitLen - bits.Len(uint(n))
	if nbits < 0 {
		panic("RLWE prime must be >= 2*n (bitLen too small)")
	}
	prime.Exp(big.NewInt(2), big.NewInt(int64(nbits)), nil)
	dim := big.NewInt(int64(n))
	prime.Mul(prime, dim).Add(prime, big.NewInt(1))
	for !prime.ProbablyPrime(32) {
		prime.Add(prime, dim)
	}
	return prime
}

// HWT returns a uniformly sampled vector of {0, ±1}^dim and given hamming weight.
func HWT(dim, hamming int) ([]int, error) {
	if hamming > dim {
		return nil, errors.New("impossible hamming weight")
	}
	vec := make([]int, dim)
	var err error
	for i := 0; i < hamming; i++ {
		randIndex, err := rand.Int(rand.Reader, big.NewInt(int64(dim)))
		if err != nil {
			panic("fatal entropy error:" + err.Error())
		}
		index := randIndex.Int64()
		if vec[index] != 0 {
			i--
			continue
		}
		coin, err := rand.Int(rand.Reader, big.NewInt(2))
		if err != nil {
			panic("fatal entropy error:" + err.Error())
		}
		if coin.Int64() == 0 {
			vec[index] = 1
		}
		vec[index] = -1
	}
	return vec, err
}

// ZO draws a vector from {0, ±1}^dim where each entry is +1, 0 or -1 with
// probability rho/2, 1-rho, and rho/2 respectively.
func ZO(dim int, rho float64) *Vector {
	if rho != .5 {
		panic("optimized for rho = .5. Use ZONaive")
	}
	vec := make([]int, dim)
	// Sample 2*dim bits
	bytes := make([]byte, dim/4)
	mrand.Read(bytes)
	index := 0
	for _, b := range bytes {
		for i := 0; i < 4; i++ {
			if b&0x03 == 0x01 {
				vec[index] = 1
			}
			if b&0x03 == 0x02 {
				vec[index] = -1
			}
			index++
			b >>= 2
		}
	}
	return &Vector{Coeffs: vec}
}

// ZONaive draws a vector from {0, ±1}^dim where each entry is +1, 0 or -1 with
// probability rho/2, 1-rho, and rho/2 respectively.
func ZONaive(dim int, rho float64) *Vector {
	vec := make([]int, dim)
	for i := 0; i < int(rho*float64(dim)); i++ {
		index := mrand.Intn(dim)
		for vec[index] != 0 {
			index = mrand.Intn(dim)
		}
		vec[index] = 1
	}
	for i := 0; i < int(rho*float64(dim)); i++ {
		index := mrand.Intn(dim)
		for vec[index] != 0 {
			index = mrand.Intn(dim)
		}
		vec[index] = -1
	}
	return &Vector{Coeffs: vec}
}

// UniformMod samples a polynomial of given degree with uniform coefficients in
// Z/qZ.
func UniformMod(deg int, q *big.Int) []*big.Int {
	pol := make([]*big.Int, deg)
	var err error
	for i := 0; i < deg; i++ {
		pol[i], err = rand.Int(rand.Reader, q)
		if err != nil {
			panic(err)
		}
	}
	return pol
}

// DG samples a vector in Z^n by drawing each coefficient from
// the discrete Gaussian distribution of mean 0 and the given std. deviation.
func DG(dim int, stdDev float64) []int {
	vec := make([]int, dim)
	for i := 0; i < dim; i++ {
		vec[i] = int(math.Round(mrand.NormFloat64() * math.Sqrt(stdDev)))
	}
	return vec
}

// HammingWeight returns the number of non-zero coordinates of v.
func HammingWeight(v []int) int {
	h := 0
	for i := 0; i < len(v); i++ {
		if v[i] != 0 {
			h++
		}
	}
	return h
}
