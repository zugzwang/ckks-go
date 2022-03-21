package ckks

import (
	"fmt"
	"math"
	"math/big"

	"ckks/negacyclic"
)

// Instance represents a precomputed context of the CKKS scheme. It contains
// all the necessary parameters for encoding, en/decryption, and homomorphic
// operations.
type Instance struct {
	Parameters // Public, user defined; see parameters.go
	p          *big.Int
	q0         *big.Int
	pEv        *big.Int // modulus for evaluation key, a.k.a. P

	// Encoding:
	crtRoots []complex128 // complex128 primitive Mth roots of unity.

	// Noise handling:
	bClean *big.Int // Bound of the noise of clean ciphertexts (Lemma 1).
	bScale *big.Int // Additive noise of rescaling.

	// Negacyclic ring arithmetic
	multiplier  *negacyclic.CRTMultiplier // modulo p*q
	zMultiplier *negacyclic.ZMultiplier   // integer
}

// NewInstance sets the given parameters and performs precomputations, after
// input is sanitized. An error is returned in case the parameters are
// insecure, and the user is responsible of accepting/rejecting the instance.
func NewInstance(params *Parameters) (*Instance, error) {
	crtRoots := make([]complex128, 2*params.N)
	for i := 0; i < 2*params.N; i++ {
		crtRoots[i] = PrimitiveRootOfUnity(i, 2*params.N)
	}

	// p, q are chosen to be two RLWE primes with p << q.
	p := negacyclic.RLWEPrime(params.BitLenP, 2*params.N)
	q0 := negacyclic.RLWEPrime(params.BitLenQ, 2*params.N)

	// It suffices to assume that P is approximately equal to q_L.
	bitsPEval := params.BitLenP*params.Depth + params.BitLenQ
	pEval := negacyclic.RLWEPrime(bitsPEval, 2*params.N)
	multiplier := negacyclic.NewCRTMultiplier(params.N, p, q0)
	zMultiplier := negacyclic.NewZMultiplier(params.N)

	inst := &Instance{
		Parameters:  *params,
		p:           p,
		q0:          q0,
		pEv:         pEval,
		crtRoots:    crtRoots,
		bClean:      computeBclean(params.Sigma, params.N, params.Hamming),
		bScale:      computeBscale(params.N, params.Hamming),
		multiplier:  multiplier,
		zMultiplier: zMultiplier,
	}
	err := inst.Sanitize()
	if err != nil && err != ErrWarningInsecure {
		return nil, err
	}
	return inst, err
}

func (ins *Instance) String() string {
	moduli := ins.chainOfModuli()
	modStr := "\n"
	for i := range moduli {
		modStr += "  " + moduli[i].String() + "\n"
	}
	str := "\n----- BEGIN PARAMETERS ----- \n\n"
	str += ins.Parameters.String()
	str += "  p: " + ins.p.String() + "\n"
	str += "  q: " + ins.q0.String() + "\n"
	str += "  P: " + ins.pEv.String() + "\n"
	str += "  Complex primitive M-th root of unity: "
	str += fmt.Sprint(ins.crtRoots[1]) + "\n"
	str += "  Moduli:" + modStr
	str += "\n\n----- END PARAMETERS ----- \n"
	return str
}

func (ins *Instance) GetP() *big.Int {
	return ins.p
}

// Sanitize performs sanity-checks and correctness checks on the given instance.
func (ins *Instance) Sanitize() error {
	if (ins.N == 0) || ((ins.N & (ins.N - 1)) != 0) {
		return ErrBadParameters("ring dimension should be a power of 2")
	}
	if ins.N < ins.Hamming {
		return ErrBadParameters("hamming weight is incompatible with ring")
	}
	if ins.N < 1<<8 || ins.Hamming < 64 {
		return ErrWarningInsecure
	}
	return nil
}

// Bclean represents the error introduced by encryption on a level L ciphertext.
func (ins *Instance) Bclean() *big.Int {
	return ins.bClean
}

// Distance returns the default distance of x,y.
func (ins *Instance) Distance(x, y *negacyclic.Polynomial) *big.Int {
	return ins.L1Distance(x, y)
}

// L1Distance returns the L1 distance of x, y.
func (ins *Instance) L1Distance(x, y *negacyclic.Polynomial) *big.Int {
	return negacyclic.L1Distance(x.Coeffs, y.Coeffs)
}

// BMul computes the noise estimation of multiplied ciphertexts at level `l`.
func (ins *Instance) BMul(modulus *big.Int) *big.Int {
	// See Lemma 3 (Addition/Multiplication)
	bKs := float64(8) * ins.Sigma * float64(ins.N) / math.Sqrt(3)
	result := big.NewInt(int64(bKs))
	result.Mul(result, modulus)
	result.Quo(result, ins.pEv)
	result.Add(result, ins.bScale)
	return result
}

// FirstModulus returns `q_0 * p^L`, the modulus of fresh ciphertexts.
func (ins *Instance) FirstModulus() *big.Int {
	mod := new(big.Int).Exp(ins.p, big.NewInt(int64(ins.Depth)), nil)
	return mod.Mul(mod, ins.q0)
}

// LastModulus returns `q_0`, the smallest modulus of the chain.
func (ins *Instance) LastModulus() *big.Int {
	return ins.q0
}

//
// Internal functions
//

// See Lemma 1 (Encoding and Encryption).
func computeBclean(sigma float64, dim, hamming int) *big.Int {
	N := float64(dim)
	h := float64(hamming)
	bClean := 8 * math.Sqrt2 * sigma * N
	bClean += 6 * sigma * math.Sqrt(N)
	bClean += 16 * sigma * math.Sqrt(h*N)
	return big.NewInt(int64(bClean))
}

// See Lemma 2 (Rescaling).
func computeBscale(dim, hamming int) *big.Int {
	N := float64(dim)
	h := float64(hamming)
	bScale := math.Sqrt(N/3) * (3 + h*math.Sqrt(8))
	return big.NewInt(int64(bScale))
}

func (ins *Instance) chainOfModuli() []*big.Int {
	l := ins.Depth
	q0 := ins.q0
	p := ins.p
	res := make([]*big.Int, l+1)
	res[0] = q0
	for i := 1; i <= l; i++ {
		res[i] = new(big.Int)
		res[i].Mul(res[i-1], p)
	}
	return res
}

func PrimitiveRootOfUnity(index, n int) complex128 {
	exp := math.Pi * 2 * float64(index) / float64(n)
	return complex(math.Cos(exp), math.Sin(exp))
}
