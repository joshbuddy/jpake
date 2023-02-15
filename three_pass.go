package jpake

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"math/big"
)

type ThreePassVariant1[P CurvePoint[P, S], S CurveScalar[S]] struct {
	UserID []byte
	X1G    P
	X2G    P
	X1ZKP  ZKPMsg[P, S]
	X2ZKP  ZKPMsg[P, S]
}

type ThreePassVariant2[P CurvePoint[P, S], S CurveScalar[S]] struct {
	UserID []byte
	X3G    P
	X4G    P
	B      P
	XsZKP  ZKPMsg[P, S]
	X3ZKP  ZKPMsg[P, S]
	X4ZKP  ZKPMsg[P, S]
}

type ThreePassVariant3[P CurvePoint[P, S], S CurveScalar[S]] struct {
	A     P
	XsZKP ZKPMsg[P, S]
}

// three pass variant jpake
// https://tools.ietf.org/html/rfc8236#section-4
type ThreePassJpake[P CurvePoint[P, S], S CurveScalar[S]] struct {
	// Variables which can be shared
	X1G    P
	X2G    P
	userID []byte

	// Received Variables, if restoring this, these are the only values you need to set
	Otherx1G    P
	Otherx2G    P
	OtherUserID []byte

	// Calculated values
	x2s        S
	sessionKey []byte

	// Private Variables
	x1 S
	x2 S
	s  S

	// configuration
	sessionConfirmationBytes []byte
	hashFn                   HashFnType
	kdf                      KDFType
	curve                    Curve[P, S]
}

// curve25519Curve{curve[curvePoint[curve25519point]]}

func InitThreePassJpake(userID, pw, sessionConfirmationBytes []byte) (*ThreePassJpake[*Curve25519point, *Curve25519scalar], error) {
	return InitThreePassJpakeWithCurveAndHashFns[*Curve25519point, *Curve25519scalar](userID, pw, sessionConfirmationBytes, Curve25519Curve{}, sha256HashFn, hmacsha256KDF)
}

func InitThreePassJpakeWithCurve[P CurvePoint[P, S], S CurveScalar[S]](userID, pw, sessionConfirmationBytes []byte, curve Curve[P, S]) (*ThreePassJpake[P, S], error) {
	return InitThreePassJpakeWithCurveAndHashFns(userID, pw, sessionConfirmationBytes, curve, sha256HashFn, hmacsha256KDF)
}

func InitThreePassJpakeWithCurveAndHashFns[P CurvePoint[P, S], S CurveScalar[S]](userID, pw, sessionConfirmationBytes []byte, curve Curve[P, S], hashFn HashFnType, kdf KDFType) (*ThreePassJpake[P, S], error) {
	jp := new(ThreePassJpake[P, S])
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

func (jp *ThreePassJpake[P, S]) initWithCurveAndHashFns(curve Curve[P, S], hashFn HashFnType, kdf KDFType) error {
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

	jp.x2s, err = jp.curve.NewScalar().Multiply(jp.x2, jp.s)
	if err != nil {
		return err
	}
	return nil
}

func (jp *ThreePassJpake[P, S]) computeZKP(x S, generator P, y P) (ZKPMsg[P, S], error) {
	// Computes a ZKP for x on Generator. We use the Fiat-Shamir heuristic:
	// https://en.wikipedia.org/wiki/Fiat%E2%80%93Shamir_heuristic
	// i.e. prove that we know x such that y = x.Generator
	// Note that we differentiate between the point G on the curve, and the
	// Generator used to compute the ZKP

	// 1. Pick a random v \in Z_q* and compute t = vG
	v, err := jp.curve.NewRandomScalar()
	if err != nil {
		return ZKPMsg[P, S]{}, err
	}

	t, err := jp.curve.NewPoint().ScalarMult(generator, v)
	if err != nil {
		return ZKPMsg[P, S]{}, err
	}

	// 2. Compute c = H(g, y, t) where H() is a cryptographic hash fn
	chal := append(generator.Bytes(), t.Bytes()[:]...)
	chal = append(chal, y.Bytes()[:]...)
	chal = append(chal, jp.userID...)
	c := (new(big.Int).SetBytes(jp.hashFn(chal)))
	c = c.Mod(c, jp.curve.Params().N)

	// Need to store the result of Mul(c,x) in a new pointer as we need c later,
	// but we don't need to do the same for v because we don't use it afterwards
	vint := v.BigInt()
	xint := x.BigInt()
	rIntermediate := vint.Sub(vint, new(big.Int).Mul(c, xint))
	r := rIntermediate.Mod(rIntermediate, jp.curve.Params().N)
	rS, err := jp.curve.NewScalar().SetBigInt(r)
	if err != nil {
		return ZKPMsg[P, S]{}, err
	}
	cS, err := jp.curve.NewScalar().SetBigInt(c)
	if err != nil {
		return ZKPMsg[P, S]{}, err
	}
	return ZKPMsg[P, S]{
		T: t,
		R: rS,
		C: cS,
	}, err
}

func (jp *ThreePassJpake[P, S]) checkZKP(msgObj ZKPMsg[P, S], generator, y P) bool {
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
	cS, err := jp.curve.NewScalar().SetBigInt(c)
	if err != nil {
		return false
	}
	tmp2, err := jp.curve.NewPoint().ScalarMult(y, cS)
	if err != nil {
		return false
	}
	vcheck.Add(vcheck, tmp2)
	return vcheck.Equal(msgObj.T) == 1
}

func (jp *ThreePassJpake[P, S]) Pass1Message() (*ThreePassVariant1[P, S], error) {
	x1ZKP, err := jp.computeZKP(jp.x1, jp.curve.NewGeneratorPoint(), jp.X1G)
	if err != nil {
		return nil, err
	}
	x2ZKP, err := jp.computeZKP(jp.x2, jp.curve.NewGeneratorPoint(), jp.X2G)
	if err != nil {
		return nil, err
	}

	pass1Message := ThreePassVariant1[P, S]{
		UserID: jp.userID,
		X1G:    jp.X1G,
		X2G:    jp.X2G,
		X1ZKP:  x1ZKP,
		X2ZKP:  x2ZKP,
	}
	return &pass1Message, nil
}

func (jp *ThreePassJpake[P, S]) GetPass2Message(msg ThreePassVariant1[P, S]) (*ThreePassVariant2[P, S], error) {
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

	pass2Msg := ThreePassVariant2[P, S]{
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

func (jp *ThreePassJpake[P, S]) GetPass3Message(msg ThreePassVariant2[P, S]) (*ThreePassVariant3[P, S], error) {
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

	pass3Msg := ThreePassVariant3[P, S]{
		A:     a,
		XsZKP: xsZKP,
	}
	if err := jp.computeSharedKey(msg.B); err != nil {
		return nil, err
	}
	return &pass3Msg, nil
}

func (jp *ThreePassJpake[P, S]) ProcessPass3Message(msg ThreePassVariant3[P, S]) error {
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

func (jp *ThreePassJpake[P, S]) SessionConfirmation1() []byte {
	return jp.sessionConfirmation(true)
}

func (jp *ThreePassJpake[P, S]) SessionConfirmation2(confirm1 []byte) ([]byte, error) {
	if !bytes.Equal(confirm1, jp.sessionConfirmation(true)) {
		return nil, errors.New("cannot confirm session")
	}
	return jp.sessionConfirmation(false), nil
}

func (jp *ThreePassJpake[P, S]) ProcessSessionConfirmation2(confirm2 []byte) error {
	if !bytes.Equal(confirm2, jp.sessionConfirmation(false)) {
		return errors.New("cannot confirm session")
	}
	return nil
}

func (jp *ThreePassJpake[P, S]) computeSharedKey(p P) error {
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

func (jp *ThreePassJpake[P, S]) sessionConfirmation(second bool) []byte {
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
