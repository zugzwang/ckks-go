package ckks

import (
	"math"
	"math/big"
	"sync"

	"ckks/negacyclic"
)

// Encode maps the given Complex polynomial following the inverse of the
// canonical embedding, into a native plaintext of the scheme, i.e., a
// polynomial in a negacyclic ring. The `delta` parameter controls the error in
// plaintext operations (see sec. 2.2).
// The canonical embedding needs a primitive 2*N-th Complex root of unity,
// already precomputed and sanitized in the instance object (see instance.go).
// Encode returns a non-nil error on malformed input.
func (ins *Instance) Encode(z []complex128, delta *big.Int) (*Plaintext, error) {
	if len(z) != ins.N/2 {
		return nil, ErrBadEncoding
	}
	zExpanded := make([]complex128, 2*len(z))
	for i := 0; i < len(z); i++ {
		zExpanded[i] = z[i]
		zExpanded[2*len(z)-1-i] = complex(real(z[i]), -imag(z[i]))
	}
	pol := VandermondeActionInverse(ins.crtRoots, zExpanded)
	encoded := negacyclic.NewPolynomial(ins.N)
	bigDelta := new(big.Float).SetInt(delta)
	for i := range pol {
		val := big.NewFloat(real(pol[i]))
		val.Mul(val, bigDelta)
		encoded.Coeffs[i] = nearestInteger(val)
	}
	return &Plaintext{m: encoded}, nil
}

// Decode applies the canonical embedding on the plaintext polynomial, to
// produce a vector with Gaussian integers. It is the inverse of the encoding
// procedure.
func (ins *Instance) Decode(plt *Plaintext, delta *big.Int) []complex128 {
	N := ins.N
	zExpanded := make([]complex128, N)
	bigDelta := new(big.Float).SetInt(delta)
	for i := range zExpanded {
		coeff := new(big.Float).SetInt(plt.m.Coeffs[i])
		coeff.Quo(coeff, bigDelta)
		smallCoeff, _ := coeff.Float64()
		zExpanded[i] = complex(float64(smallCoeff), float64(0))
	}
	pol := VandermondeAction(ins.crtRoots, zExpanded)

	z := make([]complex128, N/2)
	var truncRe, truncIm float64
	for i := range z {
		truncRe = nearestIntegerSmall(real(pol[i]))
		truncIm = nearestIntegerSmall(imag(pol[i]))
		z[i] = complex(truncRe, truncIm)
	}
	return z
}

// nearestInteger returns `⌊x⌉ = ⌊x + .5⌋`, the nearest integer of x.
func nearestIntegerSmall(x float64) float64{
	abs := math.Abs(x)
	res := math.Floor(abs + .5)
	if x < 0 {
		res = -res
	}
	return res
}

// nearestInteger returns `⌊x⌉ = ⌊x + .5⌋`, the nearest integer of x.
func nearestInteger(x *big.Float) *big.Int {
	pos := new(big.Float)
	pos.Abs(x)
	pos.Add(pos, big.NewFloat(.5))
	res := new(big.Int)
	pos.Int(res)
	if x.Sign() == -1 {
		res.Neg(res)
	}
	return res
}

// VandermondeActionInverse computes CRT^{-1} * z where CRT is the Vandermonde
// matrix of the 2N-th primitive roots of unity and N is the dimension of z.
// It uses the fact that transpose(CRT) * CRT is a the reflect matrix of n * Id.
func VandermondeActionInverse(roots, z []complex128) []complex128 {
	N := len(z)
	M := 2 * len(z)
	res := make([]complex128, N)
	wg := sync.WaitGroup{}
	wg.Add(N)
	for i := 0; i < N; i++ {
		i := i
		go func(wg *sync.WaitGroup) {
			aux := complex(0, 0)
			for j := 0; j < N; j++ {
				aux += z[N-1-j] * roots[(2*j+1)*i%M]
			}
			res[i] = aux / complex(float64(N), 0)
			wg.Done()
		}(&wg)
	}
	wg.Wait()
	return res
}

// VandermondeAction computes CRT * z where CRT is the Vandermonde matrix of
// the 2N-th primitive roots of unity and N is the dimension of z.
func VandermondeAction(roots, z []complex128) []complex128 {
	N := len(z)
	M := 2 * len(z)
	res := make([]complex128, N)
	wg := sync.WaitGroup{}
	wg.Add(N)
	for i := 0; i < N; i++ {
		i := i
		go func(wg *sync.WaitGroup) {
			aux := complex(0, 0)
			for j := 0; j < N; j++ {
				coeff := z[j] * roots[(2*i+1)*j%M]
				aux += coeff
			}
			res[i] = aux
			wg.Done()
		}(&wg)
	}
	wg.Wait()
	return res
}
