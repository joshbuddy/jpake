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

func TestJpake3PassWithInfinityPoint(t *testing.T) {
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

	//setting an uninitialized point as part of the protocol to mimic
	//active attacker during jpake handshake
	g1 := (*Curve25519Point)(edwards25519.NewGeneratorPoint())
	zero_scalar := (*Curve25519Scalar)(edwards25519.NewScalar())
	inf, err := g1.ScalarMult(g1, zero_scalar)
	if err != nil {
		t.Fatalf("init jpake: %v", err)
	}

	g2 := (*Curve25519Point)(edwards25519.NewGeneratorPoint())
	t_new, err := g2.ScalarMult(g2, msg1.X2ZKP.R)
	if err != nil {
		t.Fatalf("init jpake: %v", err)
	}

	msg1.X2ZKP.T = (*Curve25519Point)(t_new)
	msg1.X2G = (*Curve25519Point)(inf)

	_, err = jpake2.GetPass2Message(*msg1)
	if err == nil && err.Error() != "could not verify the validity of the received message" {
		t.Fatalf("init jpake: %v", err)
	}
}
