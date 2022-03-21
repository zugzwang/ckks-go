package examples

import (
	"math/big"
	"math/rand"
	"testing"

	"ckks"
)

func TestBasicDepth2(t *testing.T) {
	// These are secure parameters from the original article
	depth := 2
	params := &ckks.Parameters{
		Hamming: 64,
		N:       1 << 13,
		Sigma:   3.4,
		Depth:   depth,
		BitLenP: 30,
		BitLenQ: 155,
	}
	delta := big.NewInt(1 << 30)
	testDepthNoRescale(params, delta, t)
}

func TestDepth3(t *testing.T) {
	depth := 3
	delta := big.NewInt(1 << 30)
	params := &ckks.Parameters{
		Hamming: 64,
		N:       1 << 13,
		Sigma:   3.4,
		Depth:   depth,
		BitLenP: 30,
		BitLenQ: 280,
	}
	testDepthNoRescale(params, delta, t)

}

func testDepthNoRescale(params *ckks.Parameters, delta *big.Int, t *testing.T) {
	depth := params.Depth
	print("Precomputations...")
	// Instantiate the scheme
	inst, err := ckks.NewInstance(params)
	if err != nil {
		println(err.Error())
	}
	println(inst.String())

	// Generate a key pair
	key := inst.GenerateKey()

	// Sample a random plaintext
	z := make([]complex128, inst.N/2)
	bound := 30
	want := make([]complex128, inst.N/2)
	for i := range z {
		z[i] = complex(float64(rand.Intn(bound)), float64(rand.Intn(bound)))
		// Compute z^K Hadamard-wise
		want[i] = z[i] * z[i]
		for j := 1; j < depth; j++ {
			want[i] *= want[i]
		}
	}
	println("OK")

	print("Encoding and encryption... ")
	// Encode
	plt, err := inst.Encode(z, delta)
	if err != nil {
		t.Fatal(err)
	}

	// Encrypt, Square, Square, ..., Decrypt: ciph^K
	ctx := inst.Encrypt(key.Public, plt)
	println(" ... OK")


	print("Homomorphic computations...")
	for i := depth-1; i >= 0; i-- {
		print(" level "); print(i)
		ctx, err = inst.Mul(key.Evaluation, ctx, ctx)
		if err != nil {
			panic(err)
		}
	}
	println(" ... OK")

	print("Decoding and decryption... ")
	decrypted := inst.Decrypt(key.Secret, ctx)
	decrypted.GetPolynomial().Mod(inst.LastModulus())

	// Tune scaling factor
	for i := 0; i < depth; i++ {
		delta.Mul(delta, delta)
	}
	decoded := inst.Decode(decrypted, delta)
	println(" ... OK")

	// Compare some coefficients:
	println("First coefficients of the result:")
	for i := 0; i < 5; i++ {
		print("i = "); println(i)
		print("(original)  ")
		println(want[i])
		print("(decrypted) ")
		println(decoded[i])
	}
}
