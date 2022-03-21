package ckks_test

import (
	"math/big"
	"math/rand"
	"testing"

	"ckks"
	"ckks/negacyclic"
)

func testEncodingBasic(t *testing.T) {
	t.Run("encode_decode_roundtrip_article_example", testEncodeDecodeArticle)
}

func testEncoding(ins *ckks.Instance, t *testing.T) {
	t.Run("encode_decode_roundtrip", func(t *testing.T) {
		testEncodeRoundtrip(ins, t)
	})
	t.Run("encode_homomorphism", func(t *testing.T) {
		testEncodeHomomorphism(ins, t)
	})
}

func testEncodeDecodeArticle(t *testing.T) {
	params := &ckks.Parameters{
		Hamming: 2,
		N:       1 << 2,
		Sigma:   3.4,
		Depth:   3,
		BitLenP: 30,
		BitLenQ: 100,
	}
	inst, err := ckks.NewInstance(params)
	if err != nil && err != ckks.ErrWarningInsecure {
		panic(err)
	}
	delta := big.NewInt(64)
	z := []complex128{
		complex(3, 4),
		complex(2, -1),
	}
	want := []*big.Int{
		big.NewInt(160),
		big.NewInt(91),
		big.NewInt(160),
		big.NewInt(45),
	}
	plt, err := inst.Encode(z, delta)
	if err != nil {
		t.Fatal(err)
	}
	pol := plt.GetPolynomial()
	for i := range pol.Coeffs {
		if pol.Coeffs[i].Cmp(want[i]) != 0 {
			println(want[i].String())
			println(pol.Coeffs[i].String())
			t.Fail()
		}
	}
	decoded := inst.Decode(plt, delta)
	for i := range decoded {
		if decoded[i] != (z[i]) {
			t.Fail()
		}
	}
}

func testEncodeRoundtrip(inst *ckks.Instance, t *testing.T) {
	delta := big.NewInt(1 << 31)
	z := make([]complex128, inst.N/2)
	boundZ := 30
	for i := range z {
		z[i] = complex(float64(rand.Intn(boundZ)), float64(rand.Intn(boundZ)))
	}
	plt, err := inst.Encode(z, delta)
	if err != nil {
		t.Fatal(err)
	}
	decoded := inst.Decode(plt, delta)
	for i := range decoded {
		if decoded[i] != (z[i]) {
			println(i)
			println(decoded[i])
			println(z[i])
			t.Fatal()
		}
	}
}

func testEncodeHomomorphism(inst *ckks.Instance, t *testing.T) {
	delta := big.NewInt(1 << 20)
	z := make([]complex128, inst.N/2)
	w := make([]complex128, inst.N/2)
	h := make([]complex128, inst.N/2)
	bound := 300
	// Sample two random plaintexts and compute their Hadamard product
	for i := range z {
		z[i] = complex(float64(rand.Intn(bound)), float64(rand.Intn(bound)))
		w[i] = complex(float64(rand.Intn(bound)), float64(rand.Intn(bound)))
		h[i] = z[i] * w[i]
	}

	// Encode them
	pltZ, err := inst.Encode(z, delta)
	if err != nil {
		t.Fatal(err)
	}
	pltW, err := inst.Encode(w, delta)
	if err != nil {
		t.Fatal(err)
	}

	// Multiply them in the ring
	multiplier := negacyclic.NewZMultiplier(inst.N)
	r := multiplier.Mul(pltZ.GetPolynomial(), pltW.GetPolynomial())
	pltProd := ckks.NewPlaintextFromNegacyclic(r)

	// Decode and compare (notice the scaling factor)
	delta.Mul(delta, delta)
	decoded := inst.Decode(pltProd, delta)
	checkResult(decoded, h, t)
}

var z []complex128

func benchEncoding(b *testing.B) {
	z = make([]complex128, instBench.N/2)
	boundZ := 300000
	for i := range z {
		z[i] = complex(float64(rand.Intn(boundZ)), float64(rand.Intn(boundZ)))
	}
	b.Run("encode", benchEncode)
	b.Run("decode", benchDecode)
}

func benchEncode(b *testing.B) {
	var err error
	var delta = big.NewInt(1 << 20)
	for i := 0; i < b.N; i++ {
		if _, err = instBench.Encode(z, delta); err != nil {
			panic(err)
		}
	}
}

func benchDecode(b *testing.B) {
	var delta = big.NewInt(1 << 20)
	for i := 0; i < b.N; i++ {
		instBench.Decode(bPrecomp.pltxs[0], delta)
	}
}
