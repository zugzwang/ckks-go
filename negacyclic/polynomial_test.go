package negacyclic_test

import (
	"math"
	"math/big"
	"math/rand"
	"testing"

	"ckks/negacyclic"
)

func TestPolynomialMisc(t *testing.T) {
	t.Run("scale_nearest_integer", testScaleNearest)
}

func testScaleNearest(t *testing.T) {
	p := negacyclic.NewPolynomial(128)
	expect := make([]*big.Int, 128)
	denom := big.NewInt(3)
	for i := 0; i < 128; i++ {
		randInt := rand.Intn(1 << 32)
		p.Coeffs[i] = big.NewInt(int64(randInt))
		expected := int64(math.Floor(float64(randInt)/3 + 0.5)) // ⌊x⌉ = ⌊x + 0.5⌋
		expect[i] = big.NewInt(expected)
	}

	rounded := p.ScaleNearest(denom)
	for i := 0; i < p.Deg(); i++ {
		if rounded.Coeffs[i].Cmp(expect[i]) != 0 {
			t.Errorf("⌊%d/%d⌉ = %d, not %d", p.Coeffs[i], denom, expect[i], rounded.Coeffs[i])
		}
	}
}
