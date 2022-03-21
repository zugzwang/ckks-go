package ckks_test

import (
	"math/big"
	"math/rand"
	"testing"

	"ckks"
	"ckks/negacyclic"
)

var precompEncDec *precomputation

func testEncryption(ins *ckks.Instance, t *testing.T) {
	print("Generating crypto material for encrypt/decrypt tests... ")
	// Generate a key pair
	key := ins.GenerateKey()
	if key == nil {
		t.Fatal("Key generation failed")
	}
	// Create a ciphertext
	msgBound := 30
	delta := big.NewInt(1 << 30)
	msg := randomMessage(ins, msgBound)
	plt, err := ins.Encode(msg, delta)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext := ins.Encrypt(key.Public, plt)

	precompEncDec = &precomputation{
		key:   key,
		delta: delta,
		msgs: [][]complex128{msg},
		pltxs: []*ckks.Plaintext{plt},
		ciphs: []*ckks.Ciphertext{ciphertext},
	}
	println("OK")
	t.Run("key_generation", func(t *testing.T) { testKeyGeneration(ins, t) })
	t.Run("encrypt_decrypt_roundtrip", func(t *testing.T) { testEncDec(ins, t) })
}

func testEncDec(inst *ckks.Instance, t *testing.T) {
	key := precompEncDec.key
	ciphertext := precompEncDec.ciphs[0]
	msg := precompEncDec.msgs[0]

	// Decrypt the plaintext
	decrypted := inst.Decrypt(key.Secret, ciphertext)
	decoded := inst.Decode(decrypted, precompEncDec.delta)
	for i := 0; i < len(msg); i++ {
		if msg[i] != decoded[i] {
			t.Errorf("Bad decryption; want %f got %f", msg[i], decoded[i])
		}
	}
}

//
// Helper functions
//

func randomMessage(ins *ckks.Instance, bound int) []complex128 {
	N := ins.N/2
	res := make([]complex128, N)
	for i := 0; i < N; i++ {
		res[i] = complex(
			float64(rand.Intn(bound)-bound/2),
			float64(rand.Intn(bound)-bound/2),
		)
	}
	return res
}

func benchmarkSampling(b *testing.B) {
	b.Run("rlwe_prime", benchRLWEPrime)
	b.Run("hwt", benchHWT)
	b.Run("zo", benchZO)
	b.Run("uniform", benchUniform)
	b.Run("discrete_gaussian", benchDG)
}

func benchRLWEPrime(b *testing.B) {
	for i := 0; i < b.N; i++ {
		negacyclic.RLWEPrime(instBench.BitLenP, instBench.N)
	}
}

func benchHWT(b *testing.B) {
	var err error
	for i := 0; i < b.N; i++ {
		if _, err = negacyclic.HWT(instBench.N, instBench.Hamming); err != nil {
			panic(err)
		}
	}
}

func benchZO(b *testing.B) {
	for i := 0; i < b.N; i++ {
		negacyclic.ZO(instBench.N, .5)
	}
}

func benchUniform(b *testing.B) {
	for i := 0; i < b.N; i++ {
		negacyclic.UniformMod(instBench.N, instBench.FirstModulus())
	}
}

func benchDG(b *testing.B) {
	for i := 0; i < b.N; i++ {
		negacyclic.DG(instBench.N, instBench.Sigma)
	}
}

func benchmarkClassicCrypto(b *testing.B) {
	b.Run("key_generation", benchKeyGen)
	b.Run("encryption", benchEncryption)
	b.Run("decryption", benchDecryption)
}

func benchEncryption(b *testing.B) {
	for i := 0; i < b.N; i++ {
		instBench.Encrypt(bPrecomp.key.Public, bPrecomp.pltxs[0])
	}
}

func benchDecryption(b *testing.B) {
	for i := 0; i < b.N; i++ {
		instBench.Decrypt(bPrecomp.key.Secret, bPrecomp.ciphs[0])
	}
}
