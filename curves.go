package jpake

import (
	crypto_rand "crypto/rand"
	"io"
	"math/big"

	"filippo.io/edwards25519"
)

type CurveParams struct {
	N *big.Int
}

type CurvePoint[P any, S any] interface {
	Add(r1, r2 P) P
	Subtract(r1, r2 P) P
	Bytes() []byte
	ScalarBaseMult(scalar S) (P, error)
	ScalarMult(q P, scalar S) (P, error)
	SetBytes(b []byte) (P, error)
	Equal(q P) int
}

type CurveScalar[S any] interface {
	SetBigInt(*big.Int) S
	BigInt() *big.Int
	Multiply(S, S) (S, error)
}

type Curve[P CurvePoint[P, S], S CurveScalar[S]] interface {
	Params() *CurveParams
	NewGeneratorPoint() P
	NewRandomScalar() (S, error)
	NewScalarFromSecret([]byte) (S, error)
	NewPoint() P
	NewScalar() S
}

var Curve25519Params = &CurveParams{
	N: bigFromHex("1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed"),
}

type Curve25519point edwards25519.Point
type Curve25519scalar edwards25519.Scalar

type Curve25519Curve struct {
	Curve[*Curve25519point, *Curve25519scalar]
}

func (c Curve25519Curve) Params() *CurveParams {
	return Curve25519Params
}

func (c Curve25519Curve) NewGeneratorPoint() *Curve25519point {
	return (*Curve25519point)(edwards25519.NewGeneratorPoint())
}

func (c Curve25519Curve) NewPoint() *Curve25519point {
	return (*Curve25519point)(edwards25519.NewIdentityPoint())
}

func (c Curve25519Curve) NewScalar() *Curve25519scalar {
	return (*Curve25519scalar)(edwards25519.NewScalar())
}

func (c Curve25519Curve) NewRandomScalar() (*Curve25519scalar, error) {
	s := [64]byte{}
	_, err := io.ReadFull(crypto_rand.Reader, s[:])
	if err != nil {
		return nil, err
	}
	scalar := edwards25519.NewScalar()
	if _, err := scalar.SetUniformBytes(s[:]); err != nil {
		return nil, err
	}
	return (*Curve25519scalar)(scalar), nil
}

func (c Curve25519Curve) NewScalarFromSecret(b []byte) (*Curve25519scalar, error) {
	i := new(big.Int).SetBytes(b)
	i.Mod(i, c.Params().N)
	// TODO: check if i is 0

	scalar := (*Curve25519scalar)(edwards25519.NewScalar())
	scalar.SetBigInt(i)
	return scalar, nil
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

func (p *Curve25519point) Add(r1, r2 *Curve25519point) *Curve25519point {
	return (*Curve25519point)((*edwards25519.Point)(p).Add((*edwards25519.Point)(r1), (*edwards25519.Point)(r2)))
}

func (p *Curve25519point) Subtract(r1, r2 *Curve25519point) *Curve25519point {
	return (*Curve25519point)((*edwards25519.Point)(p).Subtract((*edwards25519.Point)(r1), (*edwards25519.Point)(r2)))
}

func (p *Curve25519point) ScalarBaseMult(s *Curve25519scalar) (*Curve25519point, error) {
	return (*Curve25519point)((*edwards25519.Point)(p).ScalarBaseMult((*edwards25519.Scalar)(s))), nil
}

func (p *Curve25519point) ScalarMult(q *Curve25519point, s *Curve25519scalar) (*Curve25519point, error) {
	return (*Curve25519point)((*edwards25519.Point)(p).ScalarMult((*edwards25519.Scalar)(s), (*edwards25519.Point)(q))), nil
}

func (p *Curve25519point) SetBytes(b []byte) (*Curve25519point, error) {
	p1, err := ((*edwards25519.Point)(p).SetBytes(b))
	return (*Curve25519point)(p1), err
}

func (p *Curve25519point) Bytes() []byte {
	return ((*edwards25519.Point)(p).Bytes())
}

func (p *Curve25519point) Equal(q *Curve25519point) int {
	return (*edwards25519.Point)(p).Equal((*edwards25519.Point)(q))
}

func (s *Curve25519scalar) BigInt() *big.Int {
	var b [32]byte
	copy(b[:], (*edwards25519.Scalar)(s).Bytes())

	for i := 0; i < 16; i++ {
		b[i], b[32-i-1] = b[32-i-1], b[i]
	}
	return new(big.Int).SetBytes(b[:])
}

func (s *Curve25519scalar) SetBigInt(i *big.Int) *Curve25519scalar {
	b := make([]byte, 32)
	i.FillBytes(b)
	for j := 0; j < 16; j++ {
		b[j], b[32-j-1] = b[32-j-1], b[j]
	}
	(*edwards25519.Scalar)(s).SetCanonicalBytes(b)
	return s
}

func (s *Curve25519scalar) Multiply(t *Curve25519scalar, u *Curve25519scalar) (*Curve25519scalar, error) {
	return (*Curve25519scalar)((*edwards25519.Scalar)(s).Multiply((*edwards25519.Scalar)(t), (*edwards25519.Scalar)(u))), nil
}
