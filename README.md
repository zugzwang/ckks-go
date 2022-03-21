## Implementation of the leveled CKKS homomorphic encryption scheme

### Quickstart / How to use this package

#### Setup
Install [Go](https://golang.org). Make sure your `GO111MODULE` env. variable is
on:
```
export GO111MODULE=on
```

Please run the whole test suite with
```
make test
```
and see it pass before continuing (it should take about a minute).

#### Example runs

The following program can be ran with
```
make example-square
```
and computes `x^2 + x` for a random negacyclic polynomial `x`, by encrypting,
squaring, adding, and decrypting.
```
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
```

It should print some parameters, plus some coefficients for comparison:
```
(...)
First coefficients of the result:
i = 0
(original)  -174603788271280449413346825935627813674669
(decrypted) -174603788271280449186563201840283269516108
(...)
```

Run also the encode/decode roundtrip to check correctness of the canonical
embedding implementation, with
```
make example-encoding
```

## Structure of this implementation

#### Package `negacyclic`

The main operation of lattice-based schemes is polynomial multiplication in
carefully selected rings. In the case of CKKS, we need polynomial arithmetic in
```
R = Z[X]/(X^n+1), R_q = Z_q[X]/(X^n+1), and R_{qp^l} = Z_{qp^l}[X]/(X^n+1)
```
for `p` and `q` odd primes. For this, the package `negacyclic` is provided,
with the following objects:
```
negacyclic.Polynomial    // a slice of big.Ints represents coefficients.

negacyclic.Multiplier    // modulo q
negacyclic.CRTMultiplier // modulo qp (and qp^l via Hensel's lemma)
negacyclic.ZMultiplier   // integer
```

Internally, the Number Theoretic Transform is implemented for fast polynomial
multiplication. This imposes the well known `q = 1 mod 2n` condition on the
`Multiplier` (primitive `2n`-th roots of unity need to exist). On creation, a
`Multiplier` checks this condition and panics intentionally if it is not
satisfied. If needed, this can be amended using a `ZMultiplier` (or the
Karatsuba implementation also provided), and performing the desired modular
reduction in the end.

A `CRTMultiplier` modulo `qp^l` internally points to a `Multiplier` modulo `q`,
and a multiplier modulo `p`. It is an easy consequence of Hensel's lemma that
this multiplier handles also `qp^l`.

Additionally, package `negacyclic` handles sampling from the various
distributions required by CKKS, using the package `crypto/rand` for entropy
sampling, which defaults to the cryptographically secure entropy source
available on the device.

The package `negacyclic` also contains the CRT linear maps for the encoding
procedure. For a given polynomial of complex coefficients, the functions
```
func VandermondeAction(roots []*Complex, z []*Complex) []*Complex {
func VandermondeActionInverse(roots []*Complex, z []*Complex) []*Complex {
```
represent the CRT action on `z`. It is defined as the action of the Vandermonde
matrix over the `2n`-th primitive roots of unity, on `z`. In order to compute
this efficiently, Noticed that `(1/N) * transpose(CRT) * CRT` is the reflection
of the identity matrix, therefore, the inverse map (a.k.a. _encoding_ into
CKKS) can be computed in roughly the same time as direct CRT, without the need
to invert matrices.

#### Package `ckks`

This package contains the CKKS implementation. A user first chooses a set of
parameters, defined as
```
// params.go
type Parameters struct {
	N       int     // Dimension of the cyclotomic ring; must be a power of two
	Depth   int     // Maximum allowed homomorphic depth
	BitLenP int
	BitLenQ int
	Hamming int     // Hamming weight of secret vector
	Sigma   float64 // Std. deviation for discrete Gaussians
}
```
With a given set of parameters, the user can instantiate the scheme:
```
type Instance struct {
	Parameters // Public, user defined; see params.go
	p          *big.Int
	q0         *big.Int
	pEv        *big.Int // modulus for evaluation key, a.k.a. P

	// Encoding:
	crtRoots []complex128 // complex128 primitive Mth roots of unity.

	// Noise handling:
	bClean *big.Int // Bound of the noise of clean ciphertexts (Lemma 1).
	bScale *big.Int // Additive noise of rescaling.

	// Negacyclic ring arithmetic
	multiplier  *negacyclic.CRTMultiplier // modulo p*q
	zMultiplier *negacyclic.ZMultiplier   // integer
}
```
When the user calls
```
func NewInstance(params Parameters)
```
all the above fields are precomputed. The instance samples `p` and `q` as RLWE
primes, computes complex roots of unity, and the multipliers are fed with `p,
q`.

With an instance in hand, the user can call `inst.GenerateKey()` generate a key object:
```
type Key struct {
	Public     *PublicKey
	Secret     *SecretKey
	Evaluation *EvaluationKey
}

type PublicKey struct {
	b, a *negacyclic.Polynomial
}

type SecretKey struct {
	s *negacyclic.Vector //  Ternary coefficients
}

type EvaluationKey struct {
	b, a *negacyclic.Polynomial
}

```
The rest of the objects are straightforward: `Plaintext` and `Ciphertext`
contain the tagged informations and the `negacyclic.Polynomial`s.


### Achieved depth
Using a 8-core Intel i7 @4.9 GHz, the depth-3 circuit that computes `x^8` using
the secure parameters from the article was evaluated in 29.80 seconds. (The
times include precomputations, key generation, encryption, and
decryption). This amounts to 1.8 milliseconds per plaintext slot.

You can run this circuit with
```
make example-depth3
```
This produces an homomorphic computation with four significant digits:
```
(...)
First coefficients of the result:
i = 0
(original)  -3777447645432990923556847180112972590279263076988010506027415991232753565
(decrypted) -3777538410681852138293120668986112341451398768126195727672789304638680340
(...)
```

#### Benchmarks

Run the suite of benchmarks in your system with
```
make benchmarks
```

Using the parameters of the original article with depth 10 on 8192 plaintext
slots, the following benchmarks are obtained on an 8-core Intel i7 @ 4.9 GHz.

|          | Total (ms) | Amortized (ms) |
|----------|------------|----------------|
| Encode   | 40562      | 4.95           |
| Decode   | 36014      | 4.4            |
| Encrypt  | 336        | 0.04           |
| Decrypt  | 58         | 0.007          |
| Add      | 2.5        | 0.0003         |
| Multiply | 1917       | 0.23           |
