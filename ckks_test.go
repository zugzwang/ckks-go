package ckks_test

import (
	"math/big"
	"testing"

	"ckks"
)

type testInstance struct {
	name   string
	params *ckks.Parameters
	ins    *ckks.Instance
}

type precomputation struct {
	key   *ckks.Key
	delta *big.Int
	msgs [][]complex128
	pltxs []*ckks.Plaintext
	ciphs []*ckks.Ciphertext
}

var testInstances = []*testInstance{
	{"toy", toyParams, nil},
	{"medium", mediumParams, nil},
	{"large", largeParams, nil},
}

func TestCKKS(t *testing.T) {
	precomputeTestData()
	t.Run("parameters", testParameters)
	t.Run("encoding_basic", testEncodingBasic)
	for _, ins := range testInstances {
		ins := ins
		t.Run(ins.name+"//crypto", func(t *testing.T) { testEncryption(ins.ins, t) })
		t.Run(ins.name+"//encoding", func(t *testing.T) { testEncoding(ins.ins, t) })
		t.Run(ins.name+"//homomorphic", func(t *testing.T) { testHomomorphic(ins.ins, t) })
	}
}

func BenchmarkCKKS(b *testing.B) {
	precomputeBenchmarkData()
	b.Run("precomputations", benchPrecomputations)
	b.Run("encoding", benchEncoding)
	b.Run("distributions", benchmarkSampling)
	b.Run("crypto", benchmarkClassicCrypto)
	b.Run("homomorphic", benchHomomorphic)
}

var instBench *ckks.Instance

var (
	toyParams = &ckks.Parameters{
		Hamming: 2,
		N:       1 << 5,
		Sigma:   0.5,
		Depth:   1,
		BitLenP: 30,
		BitLenQ: 150,
	}
	mediumParams = &ckks.Parameters{
		Hamming: 64,
		N:       1 << 10,
		Sigma:   3.4,
		Depth:   1,
		BitLenP: 30,
		BitLenQ: 150,
	}
	largeParams = &ckks.Parameters{
		Hamming: 64,
		N:       1 << 13,
		Sigma:   3.4,
		Depth:   1,
		BitLenP: 30,
		BitLenQ: 155,
	}
	benchParams = &ckks.Parameters{
		Hamming: 64,
		N:       1 << 13,
		Sigma:   3.4,
		Depth:   10,
		BitLenP: 30,
		BitLenQ: 155,
	}
)

func precomputeTestData() {
	print("\nPrecomputing for test instances...\n")
	for _, testIns := range testInstances {
		print(testIns.name)
		ins, err := ckks.NewInstance(testIns.params)
		if err != nil && err != ckks.ErrWarningInsecure {
			panic(err)
		}
		testIns.ins = ins
		print(" OK, ")
	}
	println()
}

// Precomputations for benchmarks, uses "large" setting.
var bPrecomp *precomputation

func precomputeBenchmarkData() {
	print("\nBenchmark test instance...\n")
	var err error
	instBench, err = ckks.NewInstance(benchParams)
	if err != nil && err != ckks.ErrWarningInsecure {
		panic(err)
	}
	print("OK\n")
	println(instBench.String())
	print("\nPrecomputing crypto material for benchmarks...\n")
	key := instBench.GenerateKey()
	msgBound := 30
	delta := big.NewInt(1 << 10)
	msg := randomMessage(instBench, msgBound)
	plt, err := instBench.Encode(msg, delta)
	if err != nil {
		panic(err)
	}
	ciphertext := instBench.Encrypt(key.Public, plt)
	bPrecomp = &precomputation{
		key:   key,
		pltxs: []*ckks.Plaintext{plt},
		ciphs: []*ckks.Ciphertext{ciphertext},
	}
	print("OK\n")
}
