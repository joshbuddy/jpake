package jpake

import (
	"bytes"
	"crypto/hmac"
	crypto_rand "crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"io"
	"math/big"

	"filippo.io/edwards25519"
)

type CurveParams struct {
	N *big.Int
}

var Curve25519Params = &CurveParams{
	N: bigFromHex("1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed"),
}

type Curve25519point struct {
	*edwards25519.Point
}

type CurvePoint[P any] interface {
	Add(r1, r2 P) P
	Subtract(r1, r2 P) P
	Bytes() []byte
	ScalarBaseMult(scalar []byte) (P, error)
	ScalarMult(q P, scalar []byte) (P, error)
	SetBytes(b []byte) (P, error)
	Equal(q P) int
}

type Curve[P CurvePoint[P]] interface {
	Params() *CurveParams
	NewGeneratorPoint() P
	MultiplyScalar([]byte, []byte) ([]byte, error)
	NewRandomScalar() ([]byte, error)
	NewScalarFromSecret([]byte) ([]byte, error)
	NewPoint() P
	ScalarFromBigInt(b *big.Int) []byte
	BigIntFromScalar(b []byte) *big.Int
}

type curve25519Curve []struct {
	Curve[*Curve25519point]
}

func (c curve25519Curve) Params() *CurveParams {
	return Curve25519Params
}

func (c curve25519Curve) NewGeneratorPoint() *Curve25519point {
	p := edwards25519.NewGeneratorPoint()
	return &Curve25519point{p}
}

func (c curve25519Curve) NewPoint() *Curve25519point {
	p := edwards25519.NewIdentityPoint()
	return &Curve25519point{p}
}

func (c curve25519Curve) NewRandomScalar() ([]byte, error) {
	s := [64]byte{}
	_, err := io.ReadFull(crypto_rand.Reader, s[:])
	if err != nil {
		return nil, err
	}
	scalar := edwards25519.NewScalar()
	if _, err := scalar.SetUniformBytes(s[:]); err != nil {
		return nil, err
	}
	return scalar.Bytes(), nil
}

func (c curve25519Curve) NewScalarFromSecret(b []byte) ([]byte, error) {
	i := new(big.Int).SetBytes(b)
	i.Mod(i, c.Params().N)
	// TODO: check if i is 0

	scalar := edwards25519.NewScalar()
	if _, err := scalar.SetCanonicalBytes(c.ScalarFromBigInt(i)); err != nil {
		return nil, err
	}
	return scalar.Bytes(), nil
}

func (c curve25519Curve) MultiplyScalar(a, b []byte) ([]byte, error) {
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

func (c curve25519Curve) ScalarFromBigInt(b *big.Int) []byte {
	s := make([]byte, 32)
	b.FillBytes(s)
	for i := 0; i < 16; i++ {
		s[i], s[32-i-1] = s[32-i-1], s[i]
	}
	return s
}

func (c curve25519Curve) BigIntFromScalar(b []byte) *big.Int {
	if len(b) != 32 {
		panic("expected b to be 32 len")
	}
	var s [32]byte
	copy(s[:], b)

	for i := 0; i < 16; i++ {
		s[i], s[32-i-1] = s[32-i-1], s[i]
	}
	return new(big.Int).SetBytes(s[:])

}

func (p *Curve25519point) Add(r1, r2 *Curve25519point) *Curve25519point {
	p.Point = p.Point.Add(r1.Point, r2.Point)
	return p
}

func (p *Curve25519point) Subtract(r1, r2 *Curve25519point) *Curve25519point {
	p.Point = p.Point.Subtract(r1.Point, r2.Point)
	return p
}

func (p *Curve25519point) ScalarBaseMult(scalar []byte) (*Curve25519point, error) {
	s := edwards25519.NewScalar()
	_, err := s.SetCanonicalBytes(scalar)
	if err != nil {
		return p, err
	}
	p.Point.ScalarBaseMult(s)
	return p, nil
}

func (p *Curve25519point) ScalarMult(q *Curve25519point, x []byte) (*Curve25519point, error) {
	s := edwards25519.NewScalar()
	_, err := s.SetCanonicalBytes(x)
	if err != nil {
		return p, err
	}
	p.Point = p.Point.ScalarMult(s, q.Point)
	return p, nil
}

func (p *Curve25519point) SetBytes(b []byte) (*Curve25519point, error) {
	_, err := p.Point.SetBytes(b)
	return p, err
}

func (p *Curve25519point) Equal(q *Curve25519point) int {
	return p.Point.Equal(q.Point)
}

type (
	HashFnType func([]byte) []byte
	KDFType    func([]byte) []byte
)

type ZKPMsg[P CurvePoint[P]] struct {
	T P
	R []byte
	C []byte
}

type Pass1Message[P CurvePoint[P]] struct {
	UserID []byte
	X1G    P
	X2G    P
	X1ZKP  ZKPMsg[P]
	X2ZKP  ZKPMsg[P]
}

type Pass2Message[P CurvePoint[P]] struct {
	UserID []byte
	X3G    P
	X4G    P
	B      P
	XsZKP  ZKPMsg[P]
	X3ZKP  ZKPMsg[P]
	X4ZKP  ZKPMsg[P]
}

type Pass3Message[P CurvePoint[P]] struct {
	A     P
	XsZKP ZKPMsg[P]
}

// three pass variant jpake
// https://tools.ietf.org/html/rfc8236#section-4

// EllipticCurve is a general curve which allows other
// elliptic curves to be used with PAKE.
// type EllipticCurve interface {
// 	Add(x1, y1, x2, y2 *big.Int) (*big.Int, *big.Int)
// 	ScalarBaseMult(k []byte) (*big.Int, *big.Int)
// 	ScalarMult(Bx, By *big.Int, k []byte) (*big.Int, *big.Int)
// 	Params() *elliptic.CurveParams
// }

type JPake[P CurvePoint[P]] struct {
	// Variables which can be shared
	X1G    P
	X2G    P
	userID []byte

	// Received Variables, if restoring this, these are the only values you need to set
	Otherx1G    P
	Otherx2G    P
	OtherUserID []byte

	// Calculated values
	x2s        []byte
	sessionKey []byte

	// Private Variables
	x1 []byte
	x2 []byte
	s  []byte

	// configuration
	sessionConfirmationBytes []byte
	hashFn                   HashFnType
	kdf                      KDFType
	curve                    Curve[P]
}

// curve25519Curve{curve[curvePoint[curve25519point]]}

func InitJpake(userID, pw, sessionConfirmationBytes []byte) (*JPake[*Curve25519point], error) {
	return InitJpakeWithCurveAndHashFns[*Curve25519point](userID, pw, sessionConfirmationBytes, curve25519Curve{}, sha256HashFn, hmacsha256KDF)
}

func InitJpakeWithCurve[P CurvePoint[P]](userID, pw, sessionConfirmationBytes []byte, curve Curve[P]) (*JPake[P], error) {
	return InitJpakeWithCurveAndHashFns(userID, pw, sessionConfirmationBytes, curve, sha256HashFn, hmacsha256KDF)
}

func InitJpakeWithCurveAndHashFns[P CurvePoint[P]](userID, pw, sessionConfirmationBytes []byte, curve Curve[P], hashFn HashFnType, kdf KDFType) (*JPake[P], error) {
	jp := new(JPake[P])
	jp.sessionKey = []byte{} // make sure to invalidate the session key
	jp.userID = userID
	jp.sessionConfirmationBytes = sessionConfirmationBytes
	// Generate private random variables
	rand1, err := curve.NewRandomScalar()
	if err != nil {
		return nil, err
	}
	rand2, err := curve.NewRandomScalar()
	if err != nil {
		return nil, err
	}
	jp.x1 = rand1
	jp.x2 = rand2
	// Compute a simple hash of our secret
	jp.s, err = curve.NewScalarFromSecret(hashFn(pw))
	if err != nil {
		return jp, err
	}
	if err := jp.initWithCurveAndHashFns(curve, hashFn, kdf); err != nil {
		return jp, err
	}
	return jp, err
}

func (jp *JPake[P]) initWithCurveAndHashFns(curve Curve[P], hashFn HashFnType, kdf KDFType) error {
	jp.curve = curve
	jp.hashFn = hashFn
	jp.kdf = kdf

	p1, err := jp.curve.NewPoint().ScalarBaseMult(jp.x1)
	if err != nil {
		return err
	}
	jp.X1G = p1
	p2, err := jp.curve.NewPoint().ScalarBaseMult(jp.x2)
	if err != nil {
		return err
	}
	jp.X2G = p2

	jp.x2s, err = curve.MultiplyScalar(jp.x2, jp.s)
	if err != nil {
		return err
	}
	return nil
}

func (jp *JPake[P]) computeZKP(x []byte, generator P, y P) (ZKPMsg[P], error) {
	// Computes a ZKP for x on Generator. We use the Fiat-Shamir heuristic:
	// https://en.wikipedia.org/wiki/Fiat%E2%80%93Shamir_heuristic
	// i.e. prove that we know x such that y = x.Generator
	// Note that we differentiate between the point G on the curve, and the
	// Generator used to compute the ZKP

	// 1. Pick a random v \in Z_q* and compute t = vG
	v, err := jp.curve.NewRandomScalar()
	if err != nil {
		return ZKPMsg[P]{}, err
	}

	t, err := jp.curve.NewPoint().ScalarMult(generator, v)
	if err != nil {
		return ZKPMsg[P]{}, err
	}

	// 2. Compute c = H(g, y, t) where H() is a cryptographic hash fn
	chal := append(generator.Bytes(), t.Bytes()[:]...)
	chal = append(chal, y.Bytes()[:]...)
	chal = append(chal, jp.userID...)
	c := (new(big.Int).SetBytes(jp.hashFn(chal)))
	c = c.Mod(c, jp.curve.Params().N)

	// Need to store the result of Mul(c,x) in a new pointer as we need c later,
	// but we don't need to do the same for v because we don't use it afterwards
	vint := jp.curve.BigIntFromScalar(v)
	xint := jp.curve.BigIntFromScalar(x)
	rIntermediate := vint.Sub(vint, new(big.Int).Mul(c, xint))
	r := rIntermediate.Mod(rIntermediate, jp.curve.Params().N)

	return ZKPMsg[P]{
		T: t,
		R: jp.curve.ScalarFromBigInt(r),
		C: jp.curve.ScalarFromBigInt(c),
	}, err
}

func (jp *JPake[P]) checkZKP(msgObj ZKPMsg[P], generator, y P) bool {
	chal := generator.Bytes()
	chal = append(chal, msgObj.T.Bytes()[:]...)
	chal = append(chal, y.Bytes()[:]...)
	chal = append(chal, jp.OtherUserID...)
	c := (new(big.Int).SetBytes(jp.hashFn(chal)))
	c = c.Mod(c, jp.curve.Params().N)
	// TODO: ensure c is not 0 (i think)

	vcheck, err := jp.curve.NewPoint().ScalarMult(generator, msgObj.R)
	if err != nil {
		return false
	}
	tmp2, err := jp.curve.NewPoint().ScalarMult(y, jp.curve.ScalarFromBigInt(c))
	if err != nil {
		return false
	}
	vcheck.Add(vcheck, tmp2)
	return vcheck.Equal(msgObj.T) == 1
}

func (jp *JPake[P]) Pass1Message() (*Pass1Message[P], error) {
	x1ZKP, err := jp.computeZKP(jp.x1, jp.curve.NewGeneratorPoint(), jp.X1G)
	if err != nil {
		return nil, err
	}
	x2ZKP, err := jp.computeZKP(jp.x2, jp.curve.NewGeneratorPoint(), jp.X2G)
	if err != nil {
		return nil, err
	}

	pass1Message := Pass1Message[P]{
		UserID: jp.userID,
		X1G:    jp.X1G,
		X2G:    jp.X2G,
		X1ZKP:  x1ZKP,
		X2ZKP:  x2ZKP,
	}
	return &pass1Message, nil
}

func (jp *JPake[P]) GetPass2Message(msg Pass1Message[P]) (*Pass2Message[P], error) {
	if subtle.ConstantTimeCompare(msg.UserID, jp.userID) == 1 {
		return nil, errors.New("could not verify the validity of the received message")
	}
	// validate ZKPs
	jp.OtherUserID = msg.UserID

	x1Proof := jp.checkZKP(msg.X1ZKP, jp.curve.NewGeneratorPoint(), msg.X1G)
	x2Proof := jp.checkZKP(msg.X2ZKP, jp.curve.NewGeneratorPoint(), msg.X2G)
	if !(x1Proof && x2Proof) {
		return nil, errors.New("could not verify the validity of the received message")
	}

	jp.Otherx1G = msg.X1G
	jp.Otherx2G = msg.X2G

	x3ZKP, err := jp.computeZKP(jp.x1, jp.curve.NewGeneratorPoint(), jp.X1G)
	if err != nil {
		return nil, err
	}
	x4ZKP, err := jp.computeZKP(jp.x2, jp.curve.NewGeneratorPoint(), jp.X2G)
	if err != nil {
		return nil, err
	}

	// new zkp generator is (G1 + G3 + G4)
	generator := jp.curve.NewPoint().Add(jp.X1G, msg.X1G)
	generator = generator.Add(generator, msg.X2G)
	// B = (G1 + G2 + G3) x [x4*s]
	b, err := jp.curve.NewPoint().ScalarMult(generator, jp.x2s)
	if err != nil {
		return nil, err
	}
	xsZKP, err := jp.computeZKP(jp.x2s, generator, b)
	if err != nil {
		return nil, err
	}

	pass2Msg := Pass2Message[P]{
		UserID: jp.userID,
		X3G:    jp.X1G,
		X4G:    jp.X2G,
		B:      b,
		X3ZKP:  x3ZKP,
		X4ZKP:  x4ZKP,
		XsZKP:  xsZKP,
	}
	return &pass2Msg, nil
}

func (jp *JPake[P]) GetPass3Message(msg Pass2Message[P]) (*Pass3Message[P], error) {
	if subtle.ConstantTimeCompare(msg.UserID, jp.userID) == 1 {
		return nil, errors.New("could not verify the validity of the received message")
	}
	jp.OtherUserID = msg.UserID
	// validate ZKPs
	// new zkp generator is (G1 + G2 + G3)
	zkpGenerator := jp.curve.NewPoint().Add(jp.X1G, jp.X2G)
	zkpGenerator = zkpGenerator.Add(zkpGenerator, msg.X3G)
	x3Proof := jp.checkZKP(msg.X3ZKP, jp.curve.NewGeneratorPoint(), msg.X3G)
	x4Proof := jp.checkZKP(msg.X4ZKP, jp.curve.NewGeneratorPoint(), msg.X4G)
	xsProof := jp.checkZKP(msg.XsZKP, zkpGenerator, msg.B)

	if !(x3Proof && x4Proof && xsProof) {
		return nil, errors.New("could not verify the validity of the received message")
	}

	jp.Otherx1G = msg.X3G
	jp.Otherx2G = msg.X4G

	// A = (G1 + G3 + G4) x [x2*s]
	generator := jp.curve.NewPoint().Add(jp.X1G, jp.Otherx1G)
	generator = generator.Add(generator, jp.Otherx2G)

	a, err := jp.curve.NewPoint().ScalarMult(generator, jp.x2s)
	if err != nil {
		return nil, err
	}
	// if _, err := a.ScalarMult(a, jp.s); err != nil {
	// 	return nil, err
	// }
	xsZKP, err := jp.computeZKP(jp.x2s, generator, a)
	if err != nil {
		return nil, err
	}

	pass3Msg := Pass3Message[P]{
		A:     a,
		XsZKP: xsZKP,
	}
	if err := jp.computeSharedKey(msg.B); err != nil {
		return nil, err
	}
	return &pass3Msg, nil
}

func (jp *JPake[P]) ProcessPass3Message(msg Pass3Message[P]) error {
	// validate ZKPs
	tmp1 := jp.curve.NewPoint().Add(jp.X1G, jp.X2G)
	zkpGenerator := tmp1.Add(tmp1, jp.Otherx1G)
	xsProof := jp.checkZKP(msg.XsZKP, zkpGenerator, msg.A)

	if !xsProof {
		return errors.New("could not verify the validity of the received message")
	}
	if err := jp.computeSharedKey(msg.A); err != nil {
		return err
	}

	return nil
}

func (jp *JPake[P]) SessionConfirmation1() []byte {
	return jp.sessionConfirmation(true)
}

func (jp *JPake[P]) SessionConfirmation2(confirm1 []byte) ([]byte, error) {
	if !bytes.Equal(confirm1, jp.sessionConfirmation(true)) {
		return nil, errors.New("cannot confirm session")
	}
	return jp.sessionConfirmation(false), nil
}

func (jp *JPake[P]) ProcessSessionConfirmation2(confirm2 []byte) error {
	if !bytes.Equal(confirm2, jp.sessionConfirmation(false)) {
		return errors.New("cannot confirm session")
	}
	return nil
}

func (jp *JPake[P]) computeSharedKey(p P) error {
	// compute either
	// (B - (G4 x [x2*s])) x [x2]
	// (A - (G2 x [x4*s])) x [x4]
	otherx2gX2s, err := jp.curve.NewPoint().ScalarMult(jp.Otherx2G, jp.x2s)
	if err != nil {
		return err
	}

	// A - (G2 x [x4*s])
	k := jp.curve.NewPoint().Subtract(p, otherx2gX2s)
	// Kb = (A - (G2 x [x4*s])) x [x4]
	if _, err = k.ScalarMult(k, jp.x2); err != nil {
		return err
	}

	sharedKey := jp.kdf(k.Bytes())
	jp.sessionKey = sharedKey
	return nil
}

func (jp *JPake[P]) sessionConfirmation(second bool) []byte {
	v := append(jp.sessionKey[:], jp.sessionConfirmationBytes...)
	h := jp.hashFn(jp.kdf(v))
	if second {
		h = jp.hashFn(h)
	}
	return h
}

func sha256HashFn(in []byte) []byte {
	hash := sha256.Sum256(in)
	return hash[:]
}

func hmacsha256KDF(input []byte) []byte {
	kdfSecret := []byte("JPAKE_KEY")
	return hmacsha256(input, kdfSecret)
}

func hmacsha256(input []byte, key []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(input)
	return mac.Sum(nil)
}

func bigFromHex(s string) *big.Int {
	b, ok := new(big.Int).SetString(s, 16)
	if !ok {
		panic("crypto/elliptic: internal error: invalid encoding")
	}
	return b
}
