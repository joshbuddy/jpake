package jpake

import (
	crypto_rand "crypto/rand"
	"math/big"

	"filippo.io/edwards25519"
)

type CurveParams struct {
	N *big.Int
}

type CurvePoint[P any, S any] interface {
	Add(r1, r2 P) P
	Subtract(r1, r2 P) P
	ScalarBaseMult(scalar S) (P, error)
	ScalarMult(q P, scalar S) (P, error)
	Bytes() []byte
	SetBytes(b []byte) (P, error)
	Equal(q P) int
}

type CurveScalar[S any] interface {
	SetBigInt(*big.Int) (S, error)
	BigInt() *big.Int
	Multiply(S, S) (S, error)
	Bytes() []byte
	SetBytes(b []byte) (S, error)
	Zero() bool
}

type Curve[P CurvePoint[P, S], S CurveScalar[S]] interface {
	Params() *CurveParams
	NewGeneratorPoint() P
	NewRandomScalar(int) (S, error)
	NewScalarFromSecret(int, []byte) (S, error)
	NewPoint() P
	NewScalar() S
	Infinity(P) bool
}

var Curve25519Params = &CurveParams{
	N: bigFromHex("1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed"),
}

type Curve25519Point edwards25519.Point
type Curve25519Scalar edwards25519.Scalar

type Curve25519Curve struct {
	Curve[*Curve25519Point, *Curve25519Scalar]
}

func (c Curve25519Curve) Params() *CurveParams {
	return Curve25519Params
}

func (c Curve25519Curve) NewGeneratorPoint() *Curve25519Point {
	return (*Curve25519Point)(edwards25519.NewGeneratorPoint())
}

func (c Curve25519Curve) NewPoint() *Curve25519Point {
	return (*Curve25519Point)(edwards25519.NewIdentityPoint())
}

func (c Curve25519Curve) NewScalar() *Curve25519Scalar {
	return (*Curve25519Scalar)(edwards25519.NewScalar())
}

func (c Curve25519Curve) NewRandomScalar(l int) (*Curve25519Scalar, error) {
	lower := new(big.Int).SetInt64(int64(l))
	upper := new(big.Int).Set(c.Params().N)
	upper.Sub(upper, lower)
	n, err := crypto_rand.Int(crypto_rand.Reader, upper)
	if err != nil {
		return nil, err
	}
	n.Add(n, lower)
	return c.NewScalar().SetBigInt(n)
}

func (c Curve25519Curve) NewScalarFromSecret(l int, b []byte) (*Curve25519Scalar, error) {
	lower := new(big.Int).SetInt64(int64(l))
	upper := new(big.Int).Set(c.Params().N)
	upper.Sub(upper, lower)
	n := new(big.Int).SetBytes(b)
	n.Mod(n, upper)
	n.Add(n, lower)
	return c.NewScalar().SetBigInt(n)
}

func (c Curve25519Curve) MultiplyScalar(a, b []byte) ([]byte, error) {
	sa := edwards25519.NewScalar()
	if _, err := sa.SetCanonicalBytes(a); err != nil {
		return nil, err
	}
	sb := edwards25519.NewScalar()
	if _, err := sb.SetCanonicalBytes(b); err != nil {
		return nil, err
	}
	sa.Multiply(sa, sb)
	return sa.Bytes(), nil
}

func (c Curve25519Curve) Infinity(p *Curve25519Point) bool {
	return p.Equal(c.NewPoint()) == 1
}

func (p *Curve25519Point) Add(r1, r2 *Curve25519Point) *Curve25519Point {
	return (*Curve25519Point)((*edwards25519.Point)(p).Add((*edwards25519.Point)(r1), (*edwards25519.Point)(r2)))
}

func (p *Curve25519Point) Subtract(r1, r2 *Curve25519Point) *Curve25519Point {
	return (*Curve25519Point)((*edwards25519.Point)(p).Subtract((*edwards25519.Point)(r1), (*edwards25519.Point)(r2)))
}

func (p *Curve25519Point) ScalarBaseMult(s *Curve25519Scalar) (*Curve25519Point, error) {
	return (*Curve25519Point)((*edwards25519.Point)(p).ScalarBaseMult((*edwards25519.Scalar)(s))), nil
}

func (p *Curve25519Point) ScalarMult(q *Curve25519Point, s *Curve25519Scalar) (*Curve25519Point, error) {
	return (*Curve25519Point)((*edwards25519.Point)(p).ScalarMult((*edwards25519.Scalar)(s), (*edwards25519.Point)(q))), nil
}

func (p *Curve25519Point) SetBytes(b []byte) (*Curve25519Point, error) {
	p1, err := ((*edwards25519.Point)(p).SetBytes(b))
	return (*Curve25519Point)(p1), err
}

func (p *Curve25519Point) Bytes() []byte {
	return ((*edwards25519.Point)(p).Bytes())
}

func (p *Curve25519Point) Equal(q *Curve25519Point) int {
	return (*edwards25519.Point)(p).Equal((*edwards25519.Point)(q))
}

func (s *Curve25519Scalar) BigInt() *big.Int {
	var b [32]byte
	copy(b[:], (*edwards25519.Scalar)(s).Bytes())

	for i := 0; i < 16; i++ {
		b[i], b[32-i-1] = b[32-i-1], b[i]
	}
	return new(big.Int).SetBytes(b[:])
}

func (s *Curve25519Scalar) SetBigInt(i *big.Int) (*Curve25519Scalar, error) {
	b := make([]byte, 32)
	i.FillBytes(b)
	for j := 0; j < 16; j++ {
		b[j], b[32-j-1] = b[32-j-1], b[j]
	}
	_, err := (*edwards25519.Scalar)(s).SetCanonicalBytes(b)
	if err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Curve25519Scalar) Multiply(t *Curve25519Scalar, u *Curve25519Scalar) (*Curve25519Scalar, error) {
	return (*Curve25519Scalar)((*edwards25519.Scalar)(s).Multiply((*edwards25519.Scalar)(t), (*edwards25519.Scalar)(u))), nil
}

func (s *Curve25519Scalar) SetBytes(b []byte) (*Curve25519Scalar, error) {
	s1, err := ((*edwards25519.Scalar)(s).SetCanonicalBytes(b))
	return (*Curve25519Scalar)(s1), err
}

func (s *Curve25519Scalar) Bytes() []byte {
	return ((*edwards25519.Scalar)(s).Bytes())
}

func (s *Curve25519Scalar) Zero() bool {
	return s.BigInt().BitLen() == 0
}
