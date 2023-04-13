package jpake

import (
	"bytes"
	"testing"

	"filippo.io/edwards25519"
)

func TestJpake3Pass(t *testing.T) {
	jpake1, err := InitThreePassJpake([]byte("one"), []byte("password"))
	if err != nil {
		t.Fatalf("init jpake: %v", err)
	}
	jpake2, err := InitThreePassJpake([]byte("two"), []byte("password"))
	if err != nil {
		t.Fatalf("init jpake: %v", err)
	}

	msg1, err := jpake1.Pass1Message()
	if err != nil {
		t.Fatalf("init jpake: %v", err)
	}
	msg2, err := jpake2.GetPass2Message(*msg1)
	if err != nil {
		t.Fatalf("init jpake: %v", err)
	}
	msg3, err := jpake1.GetPass3Message(*msg2)
	if err != nil {
		t.Fatalf("init jpake: %v", err)
	}
	err = jpake2.ProcessPass3Message(*msg3)
	if err != nil {
		t.Fatalf("init jpake: %v", err)
	}
	conf1 := jpake1.SessionConfirmation1()
	conf2, err := jpake2.SessionConfirmation2(conf1)
	if err != nil {
		t.Fatalf("init jpake: %v", err)
	}
	err = jpake1.ProcessSessionConfirmation2(conf2)
	if err != nil {
		t.Fatalf("init jpake: %v", err)
	}
	if !bytes.Equal(jpake1.SessionKey, jpake2.SessionKey) {
		t.Fatalf("expected session keys to be equal %x %x", jpake1.SessionKey, jpake2.SessionKey)
	}
}

func TestJpake3PassDifferentPasswords(t *testing.T) {
	jpake1, err := InitThreePassJpake([]byte("one"), []byte("password"))
	if err != nil {
		t.Fatalf("init jpake: %v", err)
	}
	jpake2, err := InitThreePassJpake([]byte("two"), []byte("password2"))
	if err != nil {
		t.Fatalf("init jpake: %v", err)
	}

	msg1, err := jpake1.Pass1Message()
	if err != nil {
		t.Fatalf("init jpake: %v", err)
	}
	msg2, err := jpake2.GetPass2Message(*msg1)
	if err != nil {
		t.Fatalf("init jpake: %v", err)
	}
	msg3, err := jpake1.GetPass3Message(*msg2)
	if err != nil {
		t.Fatalf("init jpake: %v", err)
	}
	err = jpake2.ProcessPass3Message(*msg3)
	if err != nil {
		t.Fatalf("init jpake: %v", err)
	}
	if bytes.Equal(jpake1.SessionKey, jpake2.SessionKey) {
		t.Fatalf("expected session keys to not be equal %x %x", jpake1.SessionKey, jpake2.SessionKey)
	}
}

func TestJpake3PassDifferentConfirmation(t *testing.T) {
	jpake1, err := InitThreePassJpakeWithConfig([]byte("one"), []byte("password"), NewConfig().SetSessionConfirmationBytes([]byte("CONFIRM1")))
	if err != nil {
		t.Fatalf("init jpake: %v", err)
	}
	jpake2, err := InitThreePassJpakeWithConfig([]byte("two"), []byte("password"), NewConfig().SetSessionConfirmationBytes([]byte("CONFIRM2")))
	if err != nil {
		t.Fatalf("init jpake: %v", err)
	}

	msg1, err := jpake1.Pass1Message()
	if err != nil {
		t.Fatalf("init jpake: %v", err)
	}
	msg2, err := jpake2.GetPass2Message(*msg1)
	if err != nil {
		t.Fatalf("init jpake: %v", err)
	}
	msg3, err := jpake1.GetPass3Message(*msg2)
	if err != nil {
		t.Fatalf("init jpake: %v", err)
	}
	err = jpake2.ProcessPass3Message(*msg3)
	if err != nil {
		t.Fatalf("init jpake: %v", err)
	}
	conf1 := jpake1.SessionConfirmation1()
	_, err = jpake2.SessionConfirmation2(conf1)
	if err == nil {
		t.Fatalf("expected error")
	}
	if !bytes.Equal(jpake1.SessionKey, jpake2.SessionKey) {
		t.Fatalf("expected session keys to be equal %x %x", jpake1.SessionKey, jpake2.SessionKey)
	}
}
func TestJpake3PassSameUserIDs(t *testing.T) {
	jpake1, err := InitThreePassJpake([]byte("one"), []byte("password"))
	if err != nil {
		t.Fatalf("init jpake: %v", err)
	}
	jpake2, err := InitThreePassJpake([]byte("one"), []byte("password2"))
	if err != nil {
		t.Fatalf("init jpake: %v", err)
	}

	msg1, err := jpake1.Pass1Message()
	if err != nil {
		t.Fatalf("init jpake: %v", err)
	}
	_, err = jpake2.GetPass2Message(*msg1)
	if err == nil && err.Error() != "could not verify the validity of the received message" {
		t.Fatalf("init jpake: %v", err)
	}
}

func TestJpake3PassWithInfinityX1gPoint(t *testing.T) {
	jpake1, err := InitThreePassJpake([]byte("one"), []byte("password"))
	if err != nil {
		t.Fatalf("init jpake: %v", err)
	}
	jpake2, err := InitThreePassJpake([]byte("two"), []byte("password"))
	if err != nil {
		t.Fatalf("init jpake: %v", err)
	}
	msg1, err := jpake1.Pass1Message()
	if err != nil {
		t.Fatalf("init jpake: %v", err)
	}

	msg1.X1G = (*Curve25519Point)(edwards25519.NewIdentityPoint())

	_, err = jpake2.GetPass2Message(*msg1)
	if err == nil && err.Error() != "could not verify the validity of the received message" {
		t.Fatalf("init jpake: %v", err)
	}
}

func TestJpake3PassWithInfinityX2gPoint(t *testing.T) {
	jpake1, err := InitThreePassJpake([]byte("one"), []byte("password"))
	if err != nil {
		t.Fatalf("init jpake: %v", err)
	}
	jpake2, err := InitThreePassJpake([]byte("two"), []byte("password"))
	if err != nil {
		t.Fatalf("init jpake: %v", err)
	}
	msg1, err := jpake1.Pass1Message()
	if err != nil {
		t.Fatalf("init jpake: %v", err)
	}

	msg1.X2G = (*Curve25519Point)(edwards25519.NewIdentityPoint())

	_, err = jpake2.GetPass2Message(*msg1)
	if err == nil && err.Error() != "could not verify the validity of the received message" {
		t.Fatalf("init jpake: %v", err)
	}
}

func TestJpake3PassWithInfinityX3gPoint(t *testing.T) {
	jpake1, err := InitThreePassJpake([]byte("one"), []byte("password"))
	if err != nil {
		t.Fatalf("init jpake: %v", err)
	}
	jpake2, err := InitThreePassJpake([]byte("two"), []byte("password"))
	if err != nil {
		t.Fatalf("init jpake: %v", err)
	}

	msg1, err := jpake1.Pass1Message()
	if err != nil {
		t.Fatalf("init jpake: %v", err)
	}
	msg2, err := jpake2.GetPass2Message(*msg1)
	if err != nil {
		t.Fatalf("init jpake: %v", err)
	}
	msg2.X3G = (*Curve25519Point)(edwards25519.NewIdentityPoint())
	_, err = jpake1.GetPass3Message(*msg2)
	if err == nil && err.Error() != "could not verify the validity of the received message" {
		t.Fatalf("init jpake: %v", err)
	}
}

func TestJpake3PassWithInfinityX4gPoint(t *testing.T) {
	jpake1, err := InitThreePassJpake([]byte("one"), []byte("password"))
	if err != nil {
		t.Fatalf("init jpake: %v", err)
	}
	jpake2, err := InitThreePassJpake([]byte("two"), []byte("password"))
	if err != nil {
		t.Fatalf("init jpake: %v", err)
	}

	msg1, err := jpake1.Pass1Message()
	if err != nil {
		t.Fatalf("init jpake: %v", err)
	}
	msg2, err := jpake2.GetPass2Message(*msg1)
	if err != nil {
		t.Fatalf("init jpake: %v", err)
	}
	msg2.X4G = (*Curve25519Point)(edwards25519.NewIdentityPoint())
	_, err = jpake1.GetPass3Message(*msg2)
	if err == nil && err.Error() != "could not verify the validity of the received message" {
		t.Fatalf("init jpake: %v", err)
	}
}

func TestJpake3PassWithInfinityTPoint(t *testing.T) {
	jpake1, err := InitThreePassJpake([]byte("one"), []byte("password"))
	if err != nil {
		t.Fatalf("init jpake: %v", err)
	}
	jpake2, err := InitThreePassJpake([]byte("two"), []byte("password"))
	if err != nil {
		t.Fatalf("init jpake: %v", err)
	}
	msg1, err := jpake1.Pass1Message()
	if err != nil {
		t.Fatalf("init jpake: %v", err)
	}

	msg1.X2ZKP.T = (*Curve25519Point)(edwards25519.NewIdentityPoint())

	_, err = jpake2.GetPass2Message(*msg1)
	if err == nil && err.Error() != "could not verify the validity of the received message" {
		t.Fatalf("init jpake: %v", err)
	}
}

func TestJpake3PassWithZeroR(t *testing.T) {
	jpake1, err := InitThreePassJpake([]byte("one"), []byte("password"))
	if err != nil {
		t.Fatalf("init jpake: %v", err)
	}
	jpake2, err := InitThreePassJpake([]byte("two"), []byte("password"))
	if err != nil {
		t.Fatalf("init jpake: %v", err)
	}
	msg1, err := jpake1.Pass1Message()
	if err != nil {
		t.Fatalf("init jpake: %v", err)
	}

	msg1.X2ZKP.R = (*Curve25519Scalar)(edwards25519.NewScalar())

	_, err = jpake2.GetPass2Message(*msg1)
	if err == nil && err.Error() != "could not verify the validity of the received message" {
		t.Fatalf("init jpake: %v", err)
	}
}
