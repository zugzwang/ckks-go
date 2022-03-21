package examples

import (
	"math/big"
	"math/rand"
	"testing"

	"ckks"
)

func TestEncodeRoundtrip(t *testing.T) {
	plaintextBound := int64(1 << 14)
	params := &ckks.Parameters{
		Hamming: 64,
		N:       1 << 10,
		Sigma:   3.4,
		Depth:   3,
		BitLenP: 30,
		BitLenQ: 155,
	}

	// Instantiate the scheme
	inst, err := ckks.NewInstance(params)
	if err != nil {
		println(err.Error())
	}
	println(inst.String())

	// Let z be a random complex polynomial, containing the message.
	delta := big.NewInt(1 << 20)
	z := make([]complex128, inst.N / 2)
	for i := range z {
		z[i] = complex(
			float64(rand.Int63n(plaintextBound)),
			float64(rand.Int63n(plaintextBound)),
		)
	}

	// Encode/decode roundtrip
	plt, err := inst.Encode(z, delta)
	if err != nil {
		panic(err)
	}
	decoded := inst.Decode(plt, delta)

	for i := range decoded {
		if decoded[i] != z[i] {
			println(decoded[i])
			println(z[i])
			panic("encoding/decoding failed!")
		}
	}
	println("Retrieved z")
	println("First coefficients of the result:")
	for i := 0; i < 5; i++ {
		print("i = "); println(i)
		print("(original) ")
		println(z[i])
		print("(decoded)  ")
		println(decoded[i])
	}
}
