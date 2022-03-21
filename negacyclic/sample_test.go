package negacyclic_test

import (
	"math/rand"
	"testing"

	"ckks/negacyclic"
)

func TestDistributions(t *testing.T) {
	t.Run("RLWEprime", testRLWE)
	t.Run("HWT", testHWT)
	t.Run("DG", testDG)
	t.Run("zeroDG", testZeroDG)
}

func testRLWE(t *testing.T) {
	bitLens := []int{11, 100, 1000}
	for _, bitLen := range bitLens {
		n := 1024
		q := negacyclic.RLWEPrime(bitLen, n)
		if !q.ProbablyPrime(32) {
			t.Fatal("not prime")
		}
		if q.BitLen() < bitLen {
			t.Fatal("shorter prime than expected")
		}
	}
}

func testHWT(t *testing.T) {
	n := 1 + rand.Intn(512)
	h := rand.Intn(n)
	pol, err := negacyclic.HWT(n, h)
	gotHam := negacyclic.HammingWeight(pol)
	if h != gotHam {
		t.Errorf("Expected vector with hamming weight %d, got %d", h, gotHam)
	}
	if err != nil {
		t.Error(err)
	}
}

func testDG(t *testing.T) {
	n := 1 + rand.Intn(512)
	sigma := 3.14
	pol := negacyclic.DG(n, sigma)
	for _, val := range pol {
		if val != 0 {
			return
		}
	}
	t.Error("Discrete Gaussian returned zero vector")
}

func testZeroDG(t *testing.T) {
	n := 1 + rand.Intn(512)
	sigma := 0.0
	pol := negacyclic.DG(n, sigma)
	for _, val := range pol {
		if val != 0 {
			t.Fatal("Expected zero vector")
		}
	}
}
