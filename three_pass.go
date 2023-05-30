package jpake

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
)

func concat(parts ...[]byte) []byte {
	msg := []byte{}
	for _, m := range parts {
		msg = binary.BigEndian.AppendUint64(msg, uint64(len(m)))
		msg = append(msg, m...)
	}
	return msg
}

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

// Three pass variant jpake https://tools.ietf.org/html/rfc8236#section-4
// If serializing/deserializing, get/set all exported members
type ThreePassJpake[P CurvePoint[P, S], S CurveScalar[S]] struct {
	// Variables which can be shared
	x1G    P
	x2G    P
	userID []byte

	// Received Variables
	OtherX1G    P
	OtherX2G    P
	OtherUserID []byte

	// Calculated values
	x2s        S
	SessionKey []byte

	// Private Variables
	X1 S
	X2 S
	S  S

	// configuration
	Stage  int
	config *Config
	curve  Curve[P, S]
}

// curve25519Curve{curve[curvePoint[curve25519point]]}

func InitThreePassJpake(initiator bool, userID, pw []byte) (*ThreePassJpake[*Curve25519Point, *Curve25519Scalar], error) {
	return InitThreePassJpakeWithConfig(initiator, userID, pw, NewConfig())
}

func InitThreePassJpakeWithConfig(initiator bool, userID, pw []byte, config *Config) (*ThreePassJpake[*Curve25519Point, *Curve25519Scalar], error) {
	return InitThreePassJpakeWithConfigAndCurve[*Curve25519Point, *Curve25519Scalar](initiator, userID, pw, Curve25519Curve{}, config)
}

func InitThreePassJpakeWithConfigAndCurve[P CurvePoint[P, S], S CurveScalar[S]](initiator bool, userID, pw []byte, curve Curve[P, S], config *Config) (*ThreePassJpake[P, S], error) {
	jp := new(ThreePassJpake[P, S])
	jp.SessionKey = []byte{} // make sure to invalidate the session key
	jp.userID = userID
	jp.config = config
	// Generate private random variables
	rand1, err := curve.NewRandomScalar(1)
	if err != nil {
		return nil, err
	}
	rand2, err := curve.NewRandomScalar(1)
	if err != nil {
		return nil, err
	}
	jp.X1 = rand1
	jp.X2 = rand2
	if initiator {
		jp.Stage = 1
	} else {
		jp.Stage = 2
	}
	// Compute a simple hash of our secret
	jp.S, err = curve.NewScalarFromSecret(1, config.generateSecret(pw)) // The value of s falls within [1, n-1].
	if err != nil {
		return jp, err
	}
	if err := jp.initWithCurve(curve); err != nil {
		return jp, err
	}
	return jp, err
}

func RestoreThreePassJpake(stage int, userID, otherUserID, sessionKey []byte, x1, x2, s *Curve25519Scalar, otherX1G, otherX2G *Curve25519Point) (*ThreePassJpake[*Curve25519Point, *Curve25519Scalar], error) {
	return RestoreThreePassJpakeWithConfig(stage, userID, otherUserID, sessionKey, x1, x2, s, otherX1G, otherX2G, NewConfig())
}

func RestoreThreePassJpakeWithConfig(stage int, userID, otherUserID, sessionKey []byte, x1, x2, s *Curve25519Scalar, otherX1G, otherX2G *Curve25519Point, config *Config) (*ThreePassJpake[*Curve25519Point, *Curve25519Scalar], error) {
	return RestoreThreePassJpakeWithCurveAndConfig[*Curve25519Point, *Curve25519Scalar](stage, userID, otherUserID, sessionKey, x1, x2, s, otherX1G, otherX2G, Curve25519Curve{}, config)
}

func RestoreThreePassJpakeWithCurveAndConfig[P CurvePoint[P, S], S CurveScalar[S]](stage int, userID, otherUserID, sessionKey []byte, x1, x2, s S, otherX1G, otherX2G P, curve Curve[P, S], config *Config) (*ThreePassJpake[P, S], error) {
	if x1.Zero() {
		return nil, errors.New("x1 cannot be at zero")
	}
	if x2.Zero() {
		return nil, errors.New("x2 cannot be at zero")
	}
	if s.Zero() {
		return nil, errors.New("s cannot be at zero")
	}

	if stage >= 4 {
		if curve.Infinity(otherX1G) {
			return nil, errors.New("otherx1g cannot be at infinity")
		}
		if curve.Infinity(otherX2G) {
			return nil, errors.New("otherx2g cannot be at infinity")
		}
	}

	jp := new(ThreePassJpake[P, S])
	jp.Stage = stage
	jp.userID = userID
	jp.OtherUserID = otherUserID
	jp.SessionKey = sessionKey
	jp.X1 = x1
	jp.X2 = x2
	jp.S = s
	jp.OtherX1G = otherX1G
	jp.OtherX2G = otherX2G
	jp.config = config
	if err := jp.initWithCurve(curve); err != nil {
		return jp, err
	}
	return jp, nil
}

func (jp *ThreePassJpake[P, S]) initWithCurve(curve Curve[P, S]) error {
	jp.curve = curve

	p1, err := jp.curve.NewPoint().ScalarBaseMult(jp.X1)
	if err != nil {
		return err
	}
	jp.x1G = p1
	p2, err := jp.curve.NewPoint().ScalarBaseMult(jp.X2)
	if err != nil {
		return err
	}
	jp.x2G = p2

	jp.x2s, err = jp.curve.NewScalar().Multiply(jp.X2, jp.S)
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
	v, err := jp.curve.NewRandomScalar(1)
	if err != nil {
		return ZKPMsg[P, S]{}, err
	}

	t, err := jp.curve.NewPoint().ScalarMult(generator, v)
	if err != nil {
		return ZKPMsg[P, S]{}, err
	}

	// 2. Compute c = H(g, y, t) where H() is a cryptographic hash fn
	//    Within the hash function, there must be a clear boundary between any two concatenated items.  It is RECOMMENDED that one should always prepend each item with a 4-byte integer that represents the byte length of that item.  OtherInfo may contain multiple subitems.  In that case, the same rule shall apply to ensure a clear boundary between adjacent subitems.

	chal := concat(generator.Bytes(), t.Bytes(), y.Bytes(), jp.userID)
	c := (new(big.Int).SetBytes(jp.config.hashFn(chal)))
	c.Mod(c, jp.curve.Params().N)

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
	return ZKPMsg[P, S]{
		T: t,
		R: rS,
	}, err
}

func (jp *ThreePassJpake[P, S]) checkZKP(msgObj ZKPMsg[P, S], generator, y P) bool {
	if jp.curve.Infinity(generator) {
		return false
	}
	if jp.curve.Infinity(y) {
		return false
	}
	// validate T is not infinity
	if jp.curve.Infinity(msgObj.T) {
		return false
	}
	// validate R is not zero
	if msgObj.R.Zero() {
		return false
	}

	chal := concat(generator.Bytes(), msgObj.T.Bytes(), y.Bytes(), jp.OtherUserID)
	c := (new(big.Int).SetBytes(jp.config.hashFn(chal)))
	c = c.Mod(c, jp.curve.Params().N)

	// if c is zero
	if c.BitLen() == 0 {
		return false
	}

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
	if jp.Stage != 1 {
		return nil, fmt.Errorf("expected stage 1, was %d", jp.Stage)
	}
	x1ZKP, err := jp.computeZKP(jp.X1, jp.curve.NewGeneratorPoint(), jp.x1G)
	if err != nil {
		return nil, err
	}
	x2ZKP, err := jp.computeZKP(jp.X2, jp.curve.NewGeneratorPoint(), jp.x2G)
	if err != nil {
		return nil, err
	}

	jp.Stage = 3
	pass1Message := ThreePassVariant1[P, S]{
		UserID: jp.userID,
		X1G:    jp.x1G,
		X2G:    jp.x2G,
		X1ZKP:  x1ZKP,
		X2ZKP:  x2ZKP,
	}
	return &pass1Message, nil
}

func (jp *ThreePassJpake[P, S]) GetPass2Message(msg ThreePassVariant1[P, S]) (*ThreePassVariant2[P, S], error) {
	if jp.Stage != 2 {
		return nil, fmt.Errorf("expected stage 2, was %d", jp.Stage)
	}
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

	jp.OtherX1G = msg.X1G
	jp.OtherX2G = msg.X2G
	jp.Stage = 4

	x3ZKP, err := jp.computeZKP(jp.X1, jp.curve.NewGeneratorPoint(), jp.x1G)
	if err != nil {
		return nil, err
	}
	x4ZKP, err := jp.computeZKP(jp.X2, jp.curve.NewGeneratorPoint(), jp.x2G)
	if err != nil {
		return nil, err
	}

	// new zkp generator is (G1 + G3 + G4)
	generator := jp.curve.NewPoint().Add(jp.x1G, msg.X1G)
	generator = generator.Add(generator, msg.X2G)
	if jp.curve.Infinity(generator) {
		return nil, errors.New("could not verify the validity of the received message")
	}

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
		X3G:    jp.x1G,
		X4G:    jp.x2G,
		B:      b,
		X3ZKP:  x3ZKP,
		X4ZKP:  x4ZKP,
		XsZKP:  xsZKP,
	}
	return &pass2Msg, nil
}

func (jp *ThreePassJpake[P, S]) GetPass3Message(msg ThreePassVariant2[P, S]) (*ThreePassVariant3[P, S], error) {
	if jp.Stage != 3 {
		return nil, fmt.Errorf("expected stage 3, was %d", jp.Stage)
	}
	if subtle.ConstantTimeCompare(msg.UserID, jp.userID) == 1 {
		return nil, errors.New("could not verify the validity of the received message")
	}

	jp.OtherUserID = msg.UserID
	// validate ZKPs
	// new zkp generator is (G1 + G2 + G3)
	zkpGenerator := jp.curve.NewPoint().Add(jp.x1G, jp.x2G)
	zkpGenerator = zkpGenerator.Add(zkpGenerator, msg.X3G)
	x3Proof := jp.checkZKP(msg.X3ZKP, jp.curve.NewGeneratorPoint(), msg.X3G)
	x4Proof := jp.checkZKP(msg.X4ZKP, jp.curve.NewGeneratorPoint(), msg.X4G)
	xsProof := jp.checkZKP(msg.XsZKP, zkpGenerator, msg.B)

	if !(x3Proof && x4Proof && xsProof) {
		return nil, errors.New("could not verify the validity of the received message")
	}

	// A = (G1 + G3 + G4) x [x2*s]
	generator := jp.curve.NewPoint().Add(jp.x1G, msg.X3G)
	generator = generator.Add(generator, msg.X4G)
	if jp.curve.Infinity(generator) {
		return nil, errors.New("could not verify the validity of the received message")
	}

	a, err := jp.curve.NewPoint().ScalarMult(generator, jp.x2s)
	if err != nil {
		return nil, err
	}
	xsZKP, err := jp.computeZKP(jp.x2s, generator, a)
	if err != nil {
		return nil, err
	}
	pass3Msg := ThreePassVariant3[P, S]{
		A:     a,
		XsZKP: xsZKP,
	}
	jp.OtherX1G = msg.X3G
	jp.OtherX2G = msg.X4G
	jp.Stage = 5
	if err := jp.computeSharedKey(msg.B); err != nil {
		return nil, err
	}
	return &pass3Msg, nil
}

func (jp *ThreePassJpake[P, S]) ProcessPass3Message(msg ThreePassVariant3[P, S]) ([]byte, error) {
	if jp.Stage != 4 {
		return nil, fmt.Errorf("expected stage 4, was %d", jp.Stage)
	}
	// validate ZKPs
	tmp1 := jp.curve.NewPoint().Add(jp.x1G, jp.x2G)
	zkpGenerator := tmp1.Add(tmp1, jp.OtherX1G)
	xsProof := jp.checkZKP(msg.XsZKP, zkpGenerator, msg.A)
	if !xsProof {
		return nil, errors.New("could not verify the validity of the received message")
	}
	if err := jp.computeSharedKey(msg.A); err != nil {
		return nil, err
	}
	jp.Stage = 6
	// MAC(k', "KC_1_U" || Alice || Bob || G1 || G2 || G3 || G4)
	confirmMsg := concat([]byte("KC_1_U"), jp.userID, jp.OtherUserID, jp.x1G.Bytes(), jp.x2G.Bytes(), jp.OtherX1G.Bytes(), jp.OtherX2G.Bytes())
	return jp.config.generateConfirmationMac(jp.SessionKey[:], confirmMsg), nil
}

func (jp *ThreePassJpake[P, S]) ProcessSessionConfirmation1(confirm1 []byte) ([]byte, error) {
	if jp.Stage != 5 {
		return nil, fmt.Errorf("expected stage 5, was %d", jp.Stage)
	}
	expectedMsg := concat([]byte("KC_1_U"), jp.OtherUserID, jp.userID, jp.OtherX1G.Bytes(), jp.OtherX2G.Bytes(), jp.x1G.Bytes(), jp.x2G.Bytes())
	if subtle.ConstantTimeCompare(confirm1, jp.config.generateConfirmationMac(jp.SessionKey[:], expectedMsg)) != 1 {
		return nil, errors.New("cannot confirm session")
	}
	// MAC(k', "KC_1_U" || Bob || Alice || G3 || G4 || G1 || G2)
	jp.Stage = 7
	msg := concat([]byte("KC_1_U"), jp.userID, jp.OtherUserID, jp.x1G.Bytes(), jp.x2G.Bytes(), jp.OtherX1G.Bytes(), jp.OtherX2G.Bytes())
	return jp.config.generateConfirmationMac(jp.SessionKey[:], msg), nil
}

func (jp *ThreePassJpake[P, S]) ProcessSessionConfirmation2(confirm2 []byte) error {
	if jp.Stage != 6 {
		return fmt.Errorf("expected stage 6, was %d", jp.Stage)
	}
	expectedMsg := concat([]byte("KC_1_U"), jp.OtherUserID, jp.userID, jp.OtherX1G.Bytes(), jp.OtherX2G.Bytes(), jp.x1G.Bytes(), jp.x2G.Bytes())
	if subtle.ConstantTimeCompare(confirm2, jp.config.generateConfirmationMac(jp.SessionKey[:], expectedMsg)) != 1 {
		return errors.New("cannot confirm session")
	}
	jp.Stage = 8
	return nil
}

func (jp *ThreePassJpake[P, S]) computeSharedKey(p P) error {
	// compute either
	// (B - (G4 x [x2*s])) x [x2]
	// (A - (G2 x [x4*s])) x [x4]
	otherx2gX2s, err := jp.curve.NewPoint().ScalarMult(jp.OtherX2G, jp.x2s)
	if err != nil {
		return err
	}

	// A - (G2 x [x4*s])
	k := jp.curve.NewPoint().Subtract(p, otherx2gX2s)
	// Kb = (A - (G2 x [x4*s])) x [x4]
	if _, err = k.ScalarMult(k, jp.X2); err != nil {
		return err
	}

	jp.SessionKey = jp.config.generateSessionKey(k.Bytes())
	return nil
}

func sha256HashFn(in []byte) []byte {
	hash := sha256.Sum256(in)
	return hash[:]
}

func hmacsha256KDF(input, key []byte) []byte {
	return hmacsha256(input, key)
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
