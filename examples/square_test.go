package examples

import (
	"math/big"
	"math/rand"
	"testing"

	"ckks"
)

func TestBasicSquare(t *testing.T) {
	// These are secure parameters from the original article
	params := &ckks.Parameters{
		Hamming: 64,
		N:       1 << 13,
		Sigma:   3.4,
		Depth:   1,
		BitLenP: 30,
		BitLenQ: 155,
	}

	// Instantiate the scheme
	inst, err := ckks.NewInstance(params)
	if err != nil {
		println(err.Error())
	}
	println(inst.String())

	// Generate a key pair
	key := inst.GenerateKey()

	// Sample a random plaintext
	delta := big.NewInt(1 << 20)
	z := make([]complex128, inst.N/2)
	bound := 30
	want := make([]complex128, inst.N/2)
	for i := range z {
		z[i] = complex(float64(rand.Intn(bound)), float64(rand.Intn(bound)))
		want[i] = z[i] * z[i] // Plaintext Hadamard-wise computation
	}

	// Encode
	plt, err := inst.Encode(z, delta)
	if err != nil {
		t.Fatal(err)
	}

	// Encrypt, Square, Decrypt: ciph^2
	ctx := inst.Encrypt(key.Public, plt)
	ctxMul, err := inst.Mul(key.Evaluation, ctx, ctx)
	if err != nil {
		panic(err)
	}
	decrypted := inst.Decrypt(key.Secret, ctxMul)

	// Decode (notice the new scaling factor)
	delta.Mul(delta, delta)
	decoded := inst.Decode(decrypted, delta)

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
