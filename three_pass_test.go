package jpake

import (
	"bytes"
	"testing"
)

func TestJpake3Pass(t *testing.T) {
	jpake1, err := InitThreePassJpake([]byte("one"), []byte("password"))
	if err != nil {
		t.Fatalf("error init jpake1: %v", err)
	}
	jpake2, err := InitThreePassJpake([]byte("two"), []byte("password"))
	if err != nil {
		t.Fatalf("error init jpake2: %v", err)
	}
	msg1, err := jpake1.Pass1Message()
	if err != nil {
		t.Fatalf("error getting pass1: %v", err)
	}
	msg2, err := jpake2.GetPass2Message(*msg1)
	if err != nil {
		t.Fatalf("error getting pass2: %v", err)
	}
	msg3, err := jpake1.GetPass3Message(*msg2)
	if err != nil {
		t.Fatalf("error getting pass3: %v", err)
	}
	err = jpake2.ProcessPass3Message(*msg3)
	if err != nil {
		t.Fatalf("error processing pass3: %v", err)
	}
	conf1 := jpake1.SessionConfirmation1()
	conf2, err := jpake2.SessionConfirmation2(conf1)
	if err != nil {
		t.Fatalf("error getting conf2: %v", err)
	}
	err = jpake1.ProcessSessionConfirmation2(conf2)
	if err != nil {
		t.Fatalf("error confirming conf2: %v", err)
	}
	if !bytes.Equal(jpake1.SessionKey, jpake2.SessionKey) {
		t.Fatalf("expected session key %x to be equal to %x", jpake1.SessionKey, jpake2.SessionKey)
	}
}

func TestJpake3PassDifferentPasswords(t *testing.T) {
	jpake1, err := InitThreePassJpake([]byte("one"), []byte("password"))
	if err != nil {
		t.Fatalf("error init jpake1: %v", err)
	}
	jpake2, err := InitThreePassJpake([]byte("two"), []byte("password2"))
	if err != nil {
		t.Fatalf("error init jpake2: %v", err)
	}
	msg1, err := jpake1.Pass1Message()
	if err != nil {
		t.Fatalf("error getting pass1: %v", err)
	}
	msg2, err := jpake2.GetPass2Message(*msg1)
	if err != nil {
		t.Fatalf("error getting pass2: %v", err)
	}
	msg3, err := jpake1.GetPass3Message(*msg2)
	if err != nil {
		t.Fatalf("error getting pass3: %v", err)
	}
	err = jpake2.ProcessPass3Message(*msg3)
	if err != nil {
		t.Fatalf("error processing pass3: %v", err)
	}
	if bytes.Equal(jpake1.SessionKey, jpake2.SessionKey) {
		t.Fatalf("expected session key %x to not equal %x", jpake1.SessionKey, jpake2.SessionKey)
	}
}

func TestJpake3PassDifferentConfirmation1(t *testing.T) {
	jpake1, err := InitThreePassJpakeWithConfig([]byte("one"), []byte("password"), NewConfig().SetSessionConfirmationBytes([]byte("CONFIRM1")))
	if err != nil {
		t.Fatalf("error init jpake1: %v", err)
	}
	jpake2, err := InitThreePassJpakeWithConfig([]byte("two"), []byte("password"), NewConfig().SetSessionConfirmationBytes([]byte("CONFIRM2")))
	if err != nil {
		t.Fatalf("error init jpake2: %v", err)
	}
	msg1, err := jpake1.Pass1Message()
	if err != nil {
		t.Fatalf("error getting pass1: %v", err)
	}
	msg2, err := jpake2.GetPass2Message(*msg1)
	if err != nil {
		t.Fatalf("error getting pass2: %v", err)
	}
	msg3, err := jpake1.GetPass3Message(*msg2)
	if err != nil {
		t.Fatalf("error getting pass3: %v", err)
	}
	err = jpake2.ProcessPass3Message(*msg3)
	if err != nil {
		t.Fatalf("error processing pass3: %v", err)
	}
	conf1 := jpake1.SessionConfirmation1()
	_, err = jpake2.SessionConfirmation2(conf1)
	if err == nil {
		t.Fatalf("expected error getting conf2, instead got nil")
	}
	if !bytes.Equal(jpake1.SessionKey, jpake2.SessionKey) {
		t.Fatalf("expected session key %s to be equal to %x", jpake1.SessionKey, jpake2.SessionKey)
	}
}

func TestJpake3PassDifferentConfirmation2(t *testing.T) {
	jpake1, err := InitThreePassJpake([]byte("one"), []byte("password"))
	if err != nil {
		t.Fatalf("error init jpake1: %v", err)
	}
	jpake2, err := InitThreePassJpake([]byte("two"), []byte("password"))
	if err != nil {
		t.Fatalf("error init jpake2: %v", err)
	}
	msg1, err := jpake1.Pass1Message()
	if err != nil {
		t.Fatalf("error getting pass1: %v", err)
	}
	msg2, err := jpake2.GetPass2Message(*msg1)
	if err != nil {
		t.Fatalf("error getting pass2: %v", err)
	}
	msg3, err := jpake1.GetPass3Message(*msg2)
	if err != nil {
		t.Fatalf("error getting pass3: %v", err)
	}
	err = jpake2.ProcessPass3Message(*msg3)
	if err != nil {
		t.Fatalf("error processing pass3: %v", err)
	}
	conf1 := jpake1.SessionConfirmation1()
	if _, err := jpake2.SessionConfirmation2(conf1); err != nil {
		t.Fatalf("error getting conf2: %v", err)
	}
	err = jpake1.ProcessSessionConfirmation2([]byte("an incorrect conf2"))
	if err == nil {
		t.Fatalf("expected error processing conf2, instead got nil")
	}
}

func TestJpake3PassSameUserIDsPass2(t *testing.T) {
	jpake1, err := InitThreePassJpake([]byte("one"), []byte("password"))
	if err != nil {
		t.Fatalf("error init jpake1: %v", err)
	}
	jpake2, err := InitThreePassJpake([]byte("one"), []byte("password2"))
	if err != nil {
		t.Fatalf("error init jpake2: %v", err)
	}

	msg1, err := jpake1.Pass1Message()
	if err != nil {
		t.Fatalf("error getting pass1: %v", err)
	}
	_, err = jpake2.GetPass2Message(*msg1)
	if err == nil && err.Error() != "could not verify the validity of the received message" {
		t.Fatalf("expected 'could not verify the validity of the received message' error, instead got: %v", err)
	}
}

func TestJpake3PassSameUserIDsPass3(t *testing.T) {
	jpake1, err := InitThreePassJpake([]byte("one"), []byte("password"))
	if err != nil {
		t.Fatalf("error init jpake1: %v", err)
	}
	jpake2, err := InitThreePassJpake([]byte("two"), []byte("password"))
	if err != nil {
		t.Fatalf("error init jpake2: %v", err)
	}
	msg1, err := jpake1.Pass1Message()
	if err != nil {
		t.Fatalf("error getting pass1: %v", err)
	}
	msg2, err := jpake2.GetPass2Message(*msg1)
	if err != nil {
		t.Fatalf("error getting pass2: %v", err)
	}
	msg2.UserID = []byte("one")
	_, err = jpake1.GetPass3Message(*msg2)
	if err == nil && err.Error() != "could not verify the validity of the received message" {
		t.Fatalf("expected 'could not verify the validity of the received message' error, instead got: %v", err)
	}
}

func TestJpake3PassWithInfinityX1gPoint(t *testing.T) {
	jpake1, err := InitThreePassJpake([]byte("one"), []byte("password"))
	if err != nil {
		t.Fatalf("error init jpake1: %v", err)
	}
	jpake2, err := InitThreePassJpake([]byte("two"), []byte("password"))
	if err != nil {
		t.Fatalf("error init jpake2: %v", err)
	}
	msg1, err := jpake1.Pass1Message()
	if err != nil {
		t.Fatalf("error getting pass1: %v", err)
	}
	msg1.X1G = Curve25519Curve{}.NewPoint()
	_, err = jpake2.GetPass2Message(*msg1)
	if err == nil && err.Error() != "could not verify the validity of the received message" {
		t.Fatalf("expected 'could not verify the validity of the received message' error, instead got: %v", err)
	}
}

func TestJpake3PassWithInfinityX2gPoint(t *testing.T) {
	jpake1, err := InitThreePassJpake([]byte("one"), []byte("password"))
	if err != nil {
		t.Fatalf("error init jpake1: %v", err)
	}
	jpake2, err := InitThreePassJpake([]byte("two"), []byte("password"))
	if err != nil {
		t.Fatalf("error init jpake2: %v", err)
	}
	msg1, err := jpake1.Pass1Message()
	if err != nil {
		t.Fatalf("error getting pass1: %v", err)
	}
	msg1.X2G = Curve25519Curve{}.NewPoint()
	_, err = jpake2.GetPass2Message(*msg1)
	if err == nil && err.Error() != "could not verify the validity of the received message" {
		t.Fatalf("expected 'could not verify the validity of the received message' error, instead got: %v", err)
	}
}

func TestJpake3PassWithInfinityX3gPoint(t *testing.T) {
	jpake1, err := InitThreePassJpake([]byte("one"), []byte("password"))
	if err != nil {
		t.Fatalf("error init jpake1: %v", err)
	}
	jpake2, err := InitThreePassJpake([]byte("two"), []byte("password"))
	if err != nil {
		t.Fatalf("error init jpake2: %v", err)
	}

	msg1, err := jpake1.Pass1Message()
	if err != nil {
		t.Fatalf("error getting pass1: %v", err)
	}
	msg2, err := jpake2.GetPass2Message(*msg1)
	if err != nil {
		t.Fatalf("error getting pass2: %v", err)
	}
	msg2.X3G = Curve25519Curve{}.NewPoint()
	_, err = jpake1.GetPass3Message(*msg2)
	if err == nil && err.Error() != "could not verify the validity of the received message" {
		t.Fatalf("expected 'could not verify the validity of the received message' error, instead got: %v", err)
	}
}

func TestJpake3PassWithInfinityX4gPoint(t *testing.T) {
	jpake1, err := InitThreePassJpake([]byte("one"), []byte("password"))
	if err != nil {
		t.Fatalf("error init jpake1: %v", err)
	}
	jpake2, err := InitThreePassJpake([]byte("two"), []byte("password"))
	if err != nil {
		t.Fatalf("error init jpake2: %v", err)
	}
	msg1, err := jpake1.Pass1Message()
	if err != nil {
		t.Fatalf("error getting pass1: %v", err)
	}
	msg2, err := jpake2.GetPass2Message(*msg1)
	if err != nil {
		t.Fatalf("error getting pass2: %v", err)
	}
	msg2.X4G = Curve25519Curve{}.NewPoint()
	_, err = jpake1.GetPass3Message(*msg2)
	if err == nil && err.Error() != "could not verify the validity of the received message" {
		t.Fatalf("expected 'could not verify the validity of the received message' error, instead got: %v", err)
	}
}

func TestJpake3PassWithInfinityTPoint(t *testing.T) {
	jpake1, err := InitThreePassJpake([]byte("one"), []byte("password"))
	if err != nil {
		t.Fatalf("error init jpake1: %v", err)
	}
	jpake2, err := InitThreePassJpake([]byte("two"), []byte("password"))
	if err != nil {
		t.Fatalf("error init jpake2: %v", err)
	}
	msg1, err := jpake1.Pass1Message()
	if err != nil {
		t.Fatalf("error getting pass1: %v", err)
	}
	msg1.X2ZKP.T = Curve25519Curve{}.NewPoint()
	_, err = jpake2.GetPass2Message(*msg1)
	if err == nil && err.Error() != "could not verify the validity of the received message" {
		t.Fatalf("expected 'could not verify the validity of the received message' error, instead got: %v", err)
	}
}

func TestJpake3PassWithZeroR(t *testing.T) {
	jpake1, err := InitThreePassJpake([]byte("one"), []byte("password"))
	if err != nil {
		t.Fatalf("error init jpake1: %v", err)
	}
	jpake2, err := InitThreePassJpake([]byte("two"), []byte("password"))
	if err != nil {
		t.Fatalf("error init jpake2: %v", err)
	}
	msg1, err := jpake1.Pass1Message()
	if err != nil {
		t.Fatalf("error getting pass1: %v", err)
	}
	msg1.X2ZKP.R = Curve25519Curve{}.NewScalar()
	_, err = jpake2.GetPass2Message(*msg1)
	if err == nil && err.Error() != "could not verify the validity of the received message" {
		t.Fatalf("expected 'could not verify the validity of the received message' error, instead got: %v", err)
	}
}
