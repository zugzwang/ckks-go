// Package negacyclic implements arithmetic in the negacyclic rings
// `R = Z[X]/(X^N+1)`, `R_p = Z_p[X]/(X^N+1)` and `R_{pq^l} =
// Z_{pq^l}[X]/(X^N+1)` for primes `p, q` such that `p ≡ q ≡ 1 mod 2N` and `N`
// is a power of 2.
//
// It defines the negacyclic.Polynomial object for polynomials with
// arbitrary-precision coefficients, and the negacyclic.Vector object, for
// polynomials with small (e.g. int) coefficients.
//
// Arithmetic in `R_p` is implemented with the Number Theoretic Transform,
// arithmetic in `R_{pq^l}` is implemented with the CRT and Hensel's lifting,
// and arithmetic in `R` supports Karatsuba experimentally, but by default it
// chooses a prime larger than the expected coefficients and uses NTT.
package negacyclic

import (
	"math/big"
)

// Polynomial is a slice of big integers, representing a polynomial in a
// negacyclic ring.
type Polynomial struct {
	Coeffs []*big.Int
}

// Deg returns the degree of p. It returns 0 on the 0 polynomial.
func (p *Polynomial) Deg() int {
	return len(p.Coeffs)
}

// String is the stringer method for `Polynomial`.
func (p *Polynomial) String() string {
	str := "["
	for i := range p.Coeffs {
		str += p.Coeffs[i].String() + " "
	}
	str += "]"
	return str
}

// NewPolynomial allocates and returns a zero polynomial of given degree.
func NewPolynomial(degree int) *Polynomial {
	if !isPowerOfTwo(degree) {
		panic("negacyclic arithmetic only implemented for n a power of 2")
	}
	coeffs := make([]*big.Int, degree)
	for i := 0; i < degree; i++ {
		coeffs[i] = new(big.Int)
	}
	return &Polynomial{Coeffs: coeffs}
}

// PolynomialFromSlice creates and returns a polynomial whose coefficients are
// defined by the given slice.
func PolynomialFromSlice(slice []*big.Int) *Polynomial {
	return &Polynomial{Coeffs: slice}
}

func (p *Polynomial) symmetricModulus(q *big.Int) {
	if q == nil {
		return
	}
	halfMod := new(big.Int).Quo(q, big.NewInt(2))
	negHalfMod := new(big.Int).Neg(halfMod)
	for i, val := range p.Coeffs {
		val.Mod(val, q)
		if val.Cmp(halfMod) > 0 {
			p.Coeffs[i] = val.Sub(val, q)
		} else if val.Cmp(negHalfMod) < 0 {
			p.Coeffs[i] = val.Add(val, q)
		}
	}
}

// ScaleNearest computes ⌊p/scale⌉, the nearest integer polynomial of p/scale
// for a polynomial `p` and an integer `scale`.
func (p *Polynomial) ScaleNearest(scale *big.Int) *Polynomial {
	if scale.Cmp(big.NewInt(0)) == 0 {
		panic("division by zero")
	}
	aux, denom, quo := new(big.Float), new(big.Float), new(big.Float)
	denom.SetInt(scale)
	result := NewPolynomial(p.Deg())

	for i, coeff := range p.Coeffs {
		aux.SetInt(coeff).Abs(aux)
		quo.Quo(aux, denom)
		// ⌊x⌉ = ⌊x + 0.5⌋
		aux.Add(quo, big.NewFloat(0.5))
		result.Coeffs[i], _ = aux.Int(nil)
		if coeff.Sign() == -1 {
			result.Coeffs[i].Neg(result.Coeffs[i])
		}
	}
	return result
}

// Karatsuba returns the multiplication of p and q.
func Karatsuba(p, q *Polynomial) *Polynomial {
	if !isPowerOfTwo(p.Deg()) || !isPowerOfTwo(q.Deg()) {
		panic("Karatsuba only implemented for power of two degrees")
	}
	karat := karatsubaRec(p.Coeffs, q.Coeffs)
	for i := 0; i < p.Deg(); i++ {
		karat[i].Sub(karat[i], karat[i+p.Deg()])
	}
	return &Polynomial{Coeffs: karat[:p.Deg()]}
}

func karatsubaRec(x, y []*big.Int) []*big.Int {
	if len(x) != len(y) {
		panic("asymmetric Karatsuba call")
	}
	if len(x) == 1 {
		return []*big.Int{new(big.Int).Mul(x[0], y[0])}
	}
	l := len(x)
	if !isPowerOfTwo(l) {
		panic("Karatsuba implemented for power of two only")
	}

	xL := x[0 : l/2]
	xR := x[l/2:]
	yL := y[:l/2]
	yR := y[l/2:]

	z0 := karatsubaRec(xL, yL)
	z1 := karatsubaRec(addSlices(xL, xR), addSlices(yL, yR))
	z2 := karatsubaRec(xR, yR)

	crossTerm := subSlices(z1, z2)
	crossTerm = subSlices(crossTerm, z0)
	if len(crossTerm) == 1 {
		return append(append(z0, crossTerm...), append(z2, big.NewInt(0))...)
	}

	crossL := make([]*big.Int, l)
	crossR := make([]*big.Int, l)
	for i := 0; i < l; i++ {
		crossL[i] = big.NewInt(0)
		crossR[i] = big.NewInt(0)
	}

	copy(crossL[l/2:], crossTerm[:l/2])
	copy(crossR[:l/2], crossTerm[l/2:])

	result := append(addSlices(z0, crossL), addSlices(z2, crossR)...)
	return result
}

// MulSimple returns the product of p and q in Z[X]/(X^n+1), when q or both p
// and q are of type negacyclic.Vector. This is faster than interpreting into
// negacyclic.Polynomial and using NTT.
// TODO: Currently, it will accept non ternary vectors and treat them as such.
func MulSimple(p, q interface{}) *Polynomial {
	pPol, pPolOk := p.(*Polynomial)
	pVec, pVecOk := p.(*Vector)
	qVec, qVecOk := q.(*Vector)

	polVec := pPolOk && qVecOk
	vecVec := pVecOk && qVecOk
	if polVec {
		return cycMulNaivePolTerVec(pPol, qVec)
	} else if vecVec {
		return cycMulNaiveTerVecTerVec(pVec, qVec)
	}
	panic("cannot cast multiplication arguments to ring elements")
}

// Negate sets p to -p.
func (p *Polynomial) Negate() {
	for i := range p.Coeffs {
		p.Coeffs[i].Neg(p.Coeffs[i])
	}
}

// Scale sets p to scalar*p.
func (p *Polynomial) Scale(scalar *big.Int) {
	for i := range p.Coeffs {
		p.Coeffs[i].Mul(p.Coeffs[i], scalar)
	}
}

// Sub returns p - q.
func Sub(p, q *Polynomial) *Polynomial {
	if p.Deg() != q.Deg() {
		panic("incompatible subtraction")
	}
	result := NewPolynomial(p.Deg())

	for i := range result.Coeffs {
		result.Coeffs[i] = new(big.Int).Sub(p.Coeffs[i], q.Coeffs[i])
	}
	return result
}

// Mod computes, for a polynomial `p` and a modulus `q`, the representant of p
// mod q where each coefficient lies in the interval (-q/2, q/2]. It mutates
// `p`.
func (p *Polynomial) Mod(mod *big.Int) *Polynomial {
	p.symmetricModulus(mod)
	return p
}

// Add returns p + q interpreted as a polynomial.
func Add(p, q interface{}) *Polynomial {
	pPol, pPolOk := p.(*Polynomial)
	qPol, qPolOk := q.(*Polynomial)
	qVec, qVecOk := q.(*Vector)

	polPol := pPolOk && qPolOk
	if polPol {
		return addPolPol(pPol, qPol)
	}

	polVec := pPolOk && qVecOk
	if polVec {
		return addPolVec(pPol, qVec)
	}
	panic("cannot cast multiplication arguments to ring elements")
}

//
// Internal functions
//

func cycMulNaiveTerVecTerVec(x, y *Vector) *Polynomial {
	if x.Len() != y.Len() {
		panic("incompatible multiplication")
	}
	dim := x.Len()
	result := NewVector(dim)

	for i, xCoeff := range x.Coeffs {
		for j, yCoeff := range y.Coeffs {
			index := i + j
			if i+j < dim {
				result.Coeffs[index] += xCoeff * yCoeff
			} else {
				index = i + j - dim
				result.Coeffs[index] -= xCoeff * yCoeff
			}
		}
	}
	return result.Polynomial()
}

func cycMulNaivePolTerVec(p *Polynomial, v *Vector) *Polynomial {
	if p.Deg() != v.Len() {
		panic("incompatible multiplication")
	}
	dim := p.Deg()
	result := make([]*big.Int, dim)
	for i := 0; i < dim; i++ {
		result[i] = new(big.Int)
	}

	for i, vecCoeff := range v.Coeffs {
		if vecCoeff == 0 {
			continue
		}
		for j, polCoeff := range p.Coeffs {
			index := i + j
			val := new(big.Int)
			val.Set(polCoeff)
			if vecCoeff == -1 {
				val.Neg(val)
			}
			if index < dim {
				result[index].Add(result[index], val)
			} else {
				index -= dim
				result[index].Sub(result[index], val)
			}
		}
	}
	return &Polynomial{Coeffs: result}
}

func addPolPol(p, q *Polynomial) *Polynomial {
	if p.Deg() != q.Deg() {
		panic("incompatible addition")
	}
	result := NewPolynomial(p.Deg())

	for i := range result.Coeffs {
		result.Coeffs[i] = new(big.Int).Add(p.Coeffs[i], q.Coeffs[i])
	}
	return result
}

func addPolVec(p *Polynomial, v *Vector) *Polynomial {
	if p.Deg() != v.Len() {
		panic("incompatible addition")
	}
	dim := p.Deg()
	result := NewPolynomial(dim)

	for i := range result.Coeffs {
		aux := big.NewInt(int64(v.Coeffs[i]))
		result.Coeffs[i] = new(big.Int).Add(p.Coeffs[i], aux)
	}
	return result
}
