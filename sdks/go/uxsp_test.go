package uxsp

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestBindFields(t *testing.T) {
	f1 := []byte("UXSP-1")
	f2 := []byte("hello world")
	bound := BindFields(f1, f2)
	if len(bound) != 4+len(f1)+4+len(f2) {
		t.Fatalf("expected length %d, got %d", 4+len(f1)+4+len(f2), len(bound))
	}
}

func TestIdentityAndPublicCard(t *testing.T) {
	id, err := CreateIdentity("alice", "CLIENT")
	if err != nil {
		t.Fatalf("CreateIdentity failed: %v", err)
	}
	if id.Name != "alice" || id.Role != "CLIENT" {
		t.Fatalf("identity metadata mismatch")
	}

	card := id.PublicCard()
	if card.EntityID != id.EntityID {
		t.Fatalf("card entity id mismatch")
	}

	cardJSON, err := card.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON failed: %v", err)
	}

	parsedCard, err := ParsePublicCard(cardJSON)
	if err != nil {
		t.Fatalf("ParsePublicCard failed: %v", err)
	}
	if parsedCard.EntityID != card.EntityID || parsedCard.ExchangePub != card.ExchangePub {
		t.Fatalf("parsed card fields mismatch")
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

	// Test Replay Attack
	_, err = OpenSeal(env, recipient, sender.SigningPub)
	if err == nil {
		t.Fatalf("expected replay attack detection error, got nil")
	}
}

func TestTamperDetection(t *testing.T) {
	sender, _ := GenerateKeyPair()
	recipient, _ := GenerateKeyPair()

	plaintext := []byte("Tamper test payload")
	env, err := Seal(plaintext, sender, recipient.ExchangePub, recipient.KemPub, "alice", "bob")
	if err != nil {
		t.Fatalf("Seal failed: %v", err)
	}

	// Tamper with ciphertext
	ctBytes, _ := hex.DecodeString(env.Ciphertext)
	ctBytes[0] ^= 0xFF
	tamperedEnv := *env
	tamperedEnv.Ciphertext = hex.EncodeToString(ctBytes)

	// Opening tampered envelope must fail
	_, err = OpenSeal(&tamperedEnv, recipient, sender.SigningPub)
	if err == nil {
		t.Fatalf("expected tampering error, got nil")
	}
}

func TestUXSPClient(t *testing.T) {
	alice, err := CreateIdentity("alice", "CLIENT")
	if err != nil {
		t.Fatalf("create alice failed: %v", err)
	}
	bob, err := CreateIdentity("bob", "SERVER")
	if err != nil {
		t.Fatalf("create bob failed: %v", err)
	}

	client := &UXSPClient{}
	plaintext := []byte("UXSP client package test")
	pkg, err := client.CreateEncryptedPackage(alice, bob.PublicCard(), plaintext, "TEXT", map[string]interface{}{"flag": true})
	if err != nil {
		t.Fatalf("CreateEncryptedPackage failed: %v", err)
	}

	pkgJSON, err := pkg.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON failed: %v", err)
	}

	parsedPkg, err := ParseSecurePackage(pkgJSON)
	if err != nil {
		t.Fatalf("ParseSecurePackage failed: %v", err)
	}

	decrypted, err := client.OpenEncryptedPackage(bob, alice.PublicCard(), parsedPkg)
	if err != nil {
		t.Fatalf("OpenEncryptedPackage failed: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("decrypted payload mismatch")
	}

	// Test Headers
	headers := client.BuildHeaders("alice", pkg)
	if headers["X-UXSP-Sender"] != "alice" || headers["Sec-UXSP-Support"] != "v1.2, ml-kem-768" {
		t.Fatalf("invalid headers: %v", headers)
	}

	// Test Response Inspection
	resSupported := client.InspectResponseNegotiation(map[string]string{"Sec-UXSP-Selected": "v1.2"})
	if !resSupported.IsUXSPSupported || resSupported.SelectedVersion != "v1.2" {
		t.Fatalf("negotiation inspection failed")
	}

	resUnsupported := client.InspectResponseNegotiation(map[string]string{"Content-Type": "application/json"})
	if resUnsupported.IsUXSPSupported {
		t.Fatalf("expected unsupported negotiation")
	}
}
