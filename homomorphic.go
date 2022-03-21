package ckks

import (
	"math/big"
	"sync"

	"ckks/negacyclic"
)

// Add computes the homomorphic addition of c1 and c2. It rescales ciphertexts
// towards the deeper level if necessary.
func (ins *Instance) Add(c1, c2 *Ciphertext) *Ciphertext {
	ins.Equalize(c1, c2)
	var aAdd, bAdd *negacyclic.Polynomial
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func(wg *sync.WaitGroup) {
		aAdd = negacyclic.Add(c1.a, c2.a)
		aAdd.Mod(c1.ql)
		wg.Done()
	}(&wg)
	wg.Add(1)
	go func(wg *sync.WaitGroup) {
		bAdd = negacyclic.Add(c1.b, c2.b)
		bAdd.Mod(c1.ql)
		wg.Done()
	}(&wg)
	wg.Wait()

	return &Ciphertext{
		a:     aAdd,
		b:     bAdd,
		level: c1.level,
		ql:    c1.ql,
	}
}

// Mul computes a ciphertext that decrypts to the negacyclic product of c1 and
// c2. It rescales ciphertexts towards the deeper level if necessary.
func (ins *Instance) Mul(evk *EvaluationKey, c1, c2 *Ciphertext) (*Ciphertext, error) {
	ins.Equalize(c1, c2)
	level := c1.level
	modulus := c1.ql

	wg := sync.WaitGroup{}
	wg.Add(2)

	var d0, d1, d2 *negacyclic.Polynomial // (b1b2, a1b2 + a2b1, a1a2) (mod ql)

	go func(wg *sync.WaitGroup) {
		d0 = ins.multiplier.Mul(c1.b, c2.b).Mod(modulus)
		wg.Done()
	}(&wg)
	go func(wg *sync.WaitGroup) {
		d1 = ins.multiplier.Mul(c1.a, c2.b)
		aux := ins.multiplier.Mul(c2.a, c1.b)
		d1 = negacyclic.Add(d1, aux).Mod(modulus)
		wg.Done()
	}(&wg)

	d2 = ins.multiplier.Mul(c1.a, c2.a)
	d2.Mod(modulus)

	var d2evkA, d2evkB *negacyclic.Polynomial // ⌊p^{-1} d2 evk⌉ (mod ql)
	var nearestA, nearestB *negacyclic.Polynomial
	wg.Add(2)
	go func(wg *sync.WaitGroup) {
		d2evkA = ins.zMultiplier.Mul(d2, evk.a)
		nearestA = d2evkA.ScaleNearest(ins.pEv)
		wg.Done()
	}(&wg)
	go func(wg *sync.WaitGroup) {
		d2evkB = ins.zMultiplier.Mul(d2, evk.b)
		nearestB = d2evkB.ScaleNearest(ins.pEv)
		wg.Done()
	}(&wg)
	wg.Wait()

	aMul := negacyclic.Add(d1, nearestA).Mod(modulus)
	bMul := negacyclic.Add(d0, nearestB).Mod(modulus)

	c := &Ciphertext{
		a:     aMul,
		b:     bMul,
		level: level,
		ql:    modulus,
	}
	return c, nil
}

// Equalize scales the upper-level ciphertext to the level of the deeper
// ciphertext. It mutates the concerned ciphertext.
func (ins *Instance) Equalize(c1, c2 *Ciphertext) {
	if c1.level == c2.level {
		return
	}
	if c1.level < c2.level {
		ins.RS(c1, c2.level)
	} else {
		ins.RS(c2, c1.level)
	}
}

// RS scales the ciphertext to the intended level. It does nothing if the
// ciphertext is already deeper than or at the level.
func (ins *Instance) RS(ciph *Ciphertext, level int) {
	if ciph.level <= level {
		return
	}
	offset := level - ciph.level // l' - l
	// denom = p ^ {l - l'}
	denom := new(big.Int).Exp(ins.p, big.NewInt(int64(-offset)), nil)
	modulus := new(big.Int).Div(ciph.ql, denom)
	ciph.a = ciph.a.ScaleNearest(denom).Mod(modulus)
	ciph.b = ciph.b.ScaleNearest(denom).Mod(modulus)
	ciph.level = level
	ciph.ql = modulus
}
