package negacyclic_test

import (
	"math/big"
	"testing"

	"ckks/negacyclic"
)

func TestPolynomialMultiplication(t *testing.T) {
	t.Run("karatsuba", testKaratsuba)
	t.Run("nttNewHope", testNTT12289)
	t.Run("nttMedium", testNTTMedium)
}

func testKaratsuba(t *testing.T) {
	n := 1 << 8
	bitLenQ := 15
	q := negacyclic.RLWEPrime(bitLenQ, 2*n)
	x := randomElement(n, q)
	y := randomElement(n, q)
	naive := naive(x, y, q)
	naive.Mod(q)
	karat := negacyclic.Karatsuba(x, y)
	karat.Mod(q)
	for i := range karat.Coeffs {
		if naive.Coeffs[i].Cmp(karat.Coeffs[i]) != 0 {
			t.Fatal("incorrect result")
		}
	}
}

func testNTT12289(t *testing.T) {
	n := 1 << 11
	q := big.NewInt(12289)
	m := negacyclic.NewMultiplier(n, q)
	x := randomElement(n, q)
	y := randomElement(n, q)
	naive := naive(x, y, q)
	naive.Mod(q)
	ntt := m.Mul(x, y)
	ntt.Mod(q)
	for i := range ntt.Coeffs {
		if naive.Coeffs[i].Cmp(ntt.Coeffs[i]) != 0 {
			t.Fatal("incorrect result")
		}
	}
}

func testNTTMedium(t *testing.T) {
	n := 1 << 11
	bitLenQ := 100
	q := negacyclic.RLWEPrime(bitLenQ, n)
	m := negacyclic.NewMultiplier(n, q)
	x := randomElement(n, q)
	y := randomElement(n, q)
	naive := naive(x, y, q)
	naive.Mod(q)
	ntt := m.Mul(x, y)
	ntt.Mod(q)
	for i := range ntt.Coeffs {
		if naive.Coeffs[i].Cmp(ntt.Coeffs[i]) != 0 {
			t.Fatal("incorrect result")
		}
	}
}

func BenchmarkNegacyclicMultiplication(b *testing.B) {
	b.Run("naive", benchNaiveMul)
	b.Run("Karatsuba", benchKaratsubaMul)
	b.Run("NTT", benchMulNTT)
}

func benchNaiveMul(b *testing.B) {
	n := 1 << 11
	bitLenQ := 100
	q := negacyclic.RLWEPrime(bitLenQ, n)
	x := randomElement(n, q)
	y := randomElement(n, q)
	for n := 0; n < b.N; n++ {
		naive(x, y, q)
	}
}

func benchKaratsubaMul(b *testing.B) {
	n := 1 << 11
	bitLenQ := 100
	q := negacyclic.RLWEPrime(bitLenQ, n)
	x := randomElement(n, q)
	y := randomElement(n, q)
	for n := 0; n < b.N; n++ {
		negacyclic.Karatsuba(x, y)
	}
}

func benchMulNTT(b *testing.B) {
	n := 1 << 11
	bitLenQ := 100
	q := negacyclic.RLWEPrime(bitLenQ, n)
	m := negacyclic.NewMultiplier(n, q)
	x := randomElement(n, q)
	y := randomElement(n, q)
	for n := 0; n < b.N; n++ {
		m.Mul(x, y)
	}
}

func naive(p, q *negacyclic.Polynomial, mod *big.Int) *negacyclic.Polynomial {
	if p.Deg() != q.Deg() {
		panic("incompatible multiplication")
	}
	dim := p.Deg()
	result := negacyclic.NewPolynomial(p.Deg())

	val := new(big.Int)
	for i, pCoeff := range p.Coeffs {
		for j, qCoeff := range q.Coeffs {
			val.Mul(pCoeff, qCoeff)
			index := i + j
			if i+j < dim {
				result.Coeffs[index].Add(result.Coeffs[index], val)
			} else {
				index = i + j - dim
				result.Coeffs[index].Sub(result.Coeffs[index], val)
			}
			result.Coeffs[i].Mod(result.Coeffs[i], mod)
		}
	}
	return result
}
