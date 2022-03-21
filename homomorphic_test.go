package ckks_test

import (
	"math/big"
	"testing"

	"ckks"
)

var precompHomBasic *precomputation

func testHomomorphic(ins *ckks.Instance, t *testing.T) {
	print("Preparing crypto material for basic homomorphic test... ")
	// Generate a key pair
	key := ins.GenerateKey()
	if key == nil {
		t.Fatal("Key generation failed")
	}

	// Create two random ciphertexts
	delta := big.NewInt(1 << 30)
	msgBound := 3
	msgs := make([][]complex128, 2)
	pltxs := make([]*ckks.Plaintext, 2)
	ciphs := make([]*ckks.Ciphertext, 2)
	var err error
	for i := 0; i < 2; i++ {
		msgs[i] = randomMessage(ins, msgBound)
		pltxs[i], err = ins.Encode(msgs[i], delta)
		if err != nil {
			t.Fatal(err)
		}
		ciphs[i] = ins.Encrypt(key.Public, pltxs[i])
	}
	precompHomBasic = &precomputation{
		key:   key,
		delta: delta,
		msgs:  msgs,
		pltxs: pltxs,
		ciphs: ciphs,
	}
	println("OK")
	t.Run("operations", func(t *testing.T) { testHomomorphicOps(ins, t) })
}

func testHomomorphicOps(ins *ckks.Instance, t *testing.T) {
	t.Run("addition", func(t *testing.T) { testAdd(ins, t) })
	t.Run("rescale", func(t *testing.T) { testRS(ins, t) })
	t.Run("multiplication", func(t *testing.T) { testMul(ins, t) })
}

func testAdd(inst *ckks.Instance, t *testing.T) {
	key := precompHomBasic.key
	ciphertext0 := precompHomBasic.ciphs[0].Clone()
	ciphertext1 := precompHomBasic.ciphs[1].Clone()
	msg0 := precompHomBasic.msgs[0]
	msg1 := precompHomBasic.msgs[1]
	msgAddition := make([]complex128, len(msg0))
	for i := range msg0 {
		msgAddition[i] = msg0[i] + msg1[i]
	}

	// Homomorphic add
	cipherAdd := inst.Add(ciphertext0, ciphertext1)

	// Decrypt the addition and check result
	decrypted := inst.Decrypt(key.Secret, cipherAdd)
	decoded := inst.Decode(decrypted, precompHomBasic.delta)
	checkResult(decoded, msgAddition, t)
}

func testRS(inst *ckks.Instance, t *testing.T) {
	ct := precompHomBasic.ciphs[0].Clone()
	oldLevel := ct.Level()
	oldMod := ct.Modulus()
	inst.RS(ct, ct.Level()-1)
	if ct.Level() >= oldLevel {
		t.Errorf("RS did not decrease level")
	}
	if ct.Modulus().Cmp(oldMod) >= 0 {
		t.Errorf("RS did not decrease modulus")
	}
}

func testMul(inst *ckks.Instance, t *testing.T) {
	key := precompHomBasic.key
	msgs := precompHomBasic.msgs
	ciphs := precompHomBasic.ciphs
	delta := precompHomBasic.delta
	msgProd := make([]complex128, len(msgs[0]))
	for i := range msgs[0] {
		msgProd[i] = msgs[0][i] * msgs[1][i]
	}

	// Homomorphic mul
	cipherProd, err := inst.Mul(key.Evaluation, ciphs[0], ciphs[1])
	if err != nil {
		t.Fatal(err)
	}
	// Rescale
	inst.RS(cipherProd, cipherProd.Level() - 1)

	// Decrypt the product and check result
	decrypted := inst.Decrypt(key.Secret, cipherProd)
	decPol := decrypted.GetPolynomial()
	// Rescale produces an encryption of m/p, therefore multiply by p.
	for _, coeff := range decPol.Coeffs {
		coeff.Mul(coeff, inst.GetP())
	}

	delta.Mul(delta, delta)
	decoded := inst.Decode(decrypted, delta)
	checkResult(decoded, msgProd, t)
}

func benchHomomorphic(b *testing.B) {
	b.Run("addition", benchHomAdd)
	b.Run("multiplication", benchHomMul)
}

func benchHomAdd(b *testing.B) {
	for i := 0; i < b.N; i++ {
		instBench.Add(bPrecomp.ciphs[0], bPrecomp.ciphs[0])
	}
}

func benchHomMul(b *testing.B) {
	var err error
	key := bPrecomp.key.Evaluation
	ciph := bPrecomp.ciphs[0]
	for i := 0; i < b.N; i++ {
		if _, err = instBench.Mul(key, ciph, ciph); err != nil {
			panic(nil)
		}
	}
}

func checkResult(got, want []complex128, t *testing.T) {
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %f(...) want %f(...)", got[i], want[i])
		}
	}
}
