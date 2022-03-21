package ckks_test

import (
	"testing"

	"ckks"
)

func testParameters(t *testing.T) {
	t.Run("bad_instance", sanitizeBadInstance)
	t.Run("insecure_instance", sanitizeInsecureInstance)
}

func sanitizeBadInstance(t *testing.T) {
	params := &ckks.Parameters{
		Hamming: 64, // Choose conflicting hamming and dimension
		N:       1 << 5,
		Sigma:   3.4,
		BitLenP: 30,
		BitLenQ: 155,
	}
	inst, err := ckks.NewInstance(params)
	if err == nil {
		t.Error("Expected an error, got nil")
	}
	if inst != nil {
		t.Error("Expected nil instance, but got an instance.")
	}
}

func sanitizeInsecureInstance(t *testing.T) {
	inst, err := ckks.NewInstance(toyParams)
	if err != ckks.ErrWarningInsecure {
		t.Error("Expected a warning message when using insecure parameters")
	}
	if inst == nil {
		t.Error("Expected an instance, but got nil.")
	}
}

func benchPrecomputations(b *testing.B) {
	var err error
	for i := 0; i < b.N; i++ {
		if _, err = ckks.NewInstance(benchParams); err != nil {
			panic(err)
		}
	}
}
