package uxsp

import (
	"bytes"
	"testing"
)

func TestBindFields(t *testing.T) {
	f1 := []byte("UXSP-1")
	f2 := []byte("hello world")
	bound := BindFields(f1, f2)
	if len(bound) == 0 {
		t.Fatalf("expected non-empty bound fields")
	}
}

func TestSealAndOpenSeal(t *testing.T) {
	sender, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate sender keypair: %v", err)
	}

	recipient, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate recipient keypair: %v", err)
	}

	plaintext := []byte("Post-Quantum Multi-Language UXSP Engine Test")
	env, err := Seal(plaintext, sender, recipient.ExchangePub, recipient.KemPub, "alice", "bob")
	if err != nil {
		t.Fatalf("Seal failed: %v", err)
	}

	if env.SenderID != "alice" || env.RecipientID != "bob" {
		t.Fatalf("envelope metadata mismatch")
	}

	decrypted, err := OpenSeal(env, recipient, sender.SigningPub)
	if err != nil {
		t.Fatalf("OpenSeal failed: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("decrypted plaintext mismatch: got %s, want %s", string(decrypted), string(plaintext))
	}
}
