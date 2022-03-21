// Package ckks implements the RLWE version of the leveled homomorphic
// encryption scheme described in "HOMOMORPHIC ENCRYPTION FOR ARITHMETIC OF
// APPROXIMATE NUMBERS", by Jung Hee Cheon, Andrey Kim, Miran Kim, and Yongsoo
// Song.
//
// The full paper can be found at https://eprint.iacr.org/2016/421.pdf
//
// Contact: francisco@vialprado.com.
package ckks

import (
	"ckks/negacyclic"

	"sync"
)

// Encrypt encrypts a native plaintext to the given public key.
func (ins *Instance) Encrypt(pk *PublicKey, p *Plaintext) *Ciphertext {
	dim := ins.N
	v := negacyclic.ZO(dim, 0.5).Polynomial()
	modulus := ins.FirstModulus()

	wg := sync.WaitGroup{}
	wg.Add(2)
	var c0, c1 *negacyclic.Polynomial

	go func(wg *sync.WaitGroup) { // c0 = b*v + e0 + m
		e0 := negacyclic.VectorFromSlice(negacyclic.DG(dim, ins.Sigma)).Polynomial()
		c0 = ins.zMultiplier.Mul(pk.b, v)
		c0 = negacyclic.Add(c0, e0)
		c0 = negacyclic.Add(c0, p.m)
		c0.Mod(modulus)
		wg.Done()
	}(&wg)

	go func(wg *sync.WaitGroup) { // c1 = a*v + e1
		e1 := negacyclic.VectorFromSlice(negacyclic.DG(dim, ins.Sigma)).Polynomial()
		c1 = ins.zMultiplier.Mul(pk.a, v)
		c1 = negacyclic.Add(c1, e1)
		c1.Mod(modulus)
		wg.Done()
	}(&wg)

	wg.Wait()

	return &Ciphertext{
		b:     c0,
		a:     c1,
		level: ins.Depth, // a.k.a. L
		ql:    modulus,   // a.k.a. qL
	}
}

// Decrypt decrypts the ciphertext with the given secret key. It is the user's
// responsibility to check if the error bounds claimed in c.nu and c.noise are
// satisfied.
func (ins *Instance) Decrypt(sk *SecretKey, c *Ciphertext) *Plaintext {
	decrypted := negacyclic.MulSimple(c.a, sk.s)
	decrypted = negacyclic.Add(decrypted, c.b)
	decrypted.Mod(c.ql)
	return &Plaintext{m: decrypted}
}
