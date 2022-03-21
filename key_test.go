package ckks_test

import (
	"testing"

	"ckks"
)

func testKeyGeneration(ins *ckks.Instance, t *testing.T) {
	t.Run("good_keygen", func(t *testing.T) { kgGood(ins, t) })
}

func kgGood(inst *ckks.Instance, t *testing.T) {
	// Generate a key pair
	key := inst.GenerateKey()
	if key == nil {
		t.Fatal("Key generation failed")
	}
	if key.Secret == nil || key.Public == nil || key.Evaluation == nil {
		t.Fatal("Key generation failed")
	}
}

func benchKeyGen(b *testing.B) {
	for i := 0; i < b.N; i++ {
		instBench.GenerateKey()
	}
}
