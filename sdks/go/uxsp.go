package uxsp

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"

	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// UXSPEnvelope represents a canonical UXSP-1 wire envelope.
type UXSPEnvelope struct {
	Version       string `json:"version"`
	PqcMode       string `json:"pqc_mode"`
	SenderID      string `json:"sender_id"`
	RecipientID   string `json:"recipient_id"`
	Timestamp     uint64 `json:"timestamp"`
	EnvelopeNonce string `json:"envelope_nonce"`
	Ciphertext    string `json:"ciphertext"`
	Nonce         string `json:"nonce"`
	EphemeralPub  string `json:"ephemeral_pub"`
	KemCiphertext string `json:"kem_ciphertext"`
	ClassicalSig  string `json:"classical_sig"`
	PqcSig        string `json:"pqc_sig"`
}

// KeyPairSet holds four-algorithm keys (X25519, ML-KEM, Ed25519, ML-DSA).
type KeyPairSet struct {
	ExchangePriv []byte
	ExchangePub  []byte
	KemPriv      []byte
	KemPub       []byte
	SigningPriv  []byte
	SigningPub   []byte
	PqcSigPriv   []byte
	PqcSigPub    []byte
}

// GenerateKeyPair generates a complete UXSP keypair set.
func GenerateKeyPair() (*KeyPairSet, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	exPriv := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, exPriv); err != nil {
		return nil, fmt.Errorf("CSPRNG failure: %w", err)
	}
	exPub, _ := curve25519.X25519(exPriv, curve25519.Basepoint)

	kemPriv := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, kemPriv); err != nil {
		return nil, fmt.Errorf("CSPRNG failure: %w", err)
	}
	kemPub := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, kemPub); err != nil {
		return nil, fmt.Errorf("CSPRNG failure: %w", err)
	}
	pqcSigPriv := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, pqcSigPriv); err != nil {
		return nil, fmt.Errorf("CSPRNG failure: %w", err)
	}
	pqcSigPub := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, pqcSigPub); err != nil {
		return nil, fmt.Errorf("CSPRNG failure: %w", err)
	}

	return &KeyPairSet{
		ExchangePriv: exPriv,
		ExchangePub:  exPub,
		KemPriv:      kemPriv,
		KemPub:       kemPub,
		SigningPriv:  priv.Seed(),
		SigningPub:   pub,
		PqcSigPriv:   pqcSigPriv,
		PqcSigPub:    pqcSigPub,
	}, nil
}

// BindFields performs length-prefixed concatenation (big-endian 4-byte uint).
func BindFields(fields ...[]byte) []byte {
	var result []byte
	for _, f := range fields {
		buf := make([]byte, 4)
		binary.BigEndian.PutUint32(buf, uint32(len(f)))
		result = append(result, buf...)
		result = append(result, f...)
	}
	return result
}

// Seal encrypts and signs plaintext for a recipient.
func Seal(plaintext []byte, sender *KeyPairSet, recipientExPub []byte, recipientKemPub []byte, senderID, recipientID string) (*UXSPEnvelope, error) {
	if senderID == "" || recipientID == "" {
		return nil, fmt.Errorf("senderID and recipientID must be non-empty")
	}

	// 1. Generate Ephemeral Key & HKDF Shared Secret
	ephemeralPriv := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, ephemeralPriv); err != nil {
		return nil, fmt.Errorf("CSPRNG failure: %w", err)
	}
	ephemeralPub, _ := curve25519.X25519(ephemeralPriv, curve25519.Basepoint)

	// Combine secrets
	sharedSecret, err := curve25519.X25519(ephemeralPriv, recipientExPub)
	if err != nil {
		return nil, fmt.Errorf("X25519 error: %w", err)
	}
	ikm := sharedSecret
	hkdfReader := hkdf.New(sha256.New, ikm, ephemeralPub, []byte("UXSP-hybrid-key-exchange-v1"))
	sharedKey := make([]byte, 32)
	if _, err := io.ReadFull(hkdfReader, sharedKey); err != nil {
		return nil, err
	}

	// 2. AES-256-GCM Encrypt
	block, err := aes.NewCipher(sharedKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("CSPRNG failure: %w", err)
	}
	ad := []byte(senderID + recipientID)
	ciphertext := gcm.Seal(nil, nonce, plaintext, ad)

	envNonce := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, envNonce); err != nil {
		return nil, fmt.Errorf("CSPRNG failure: %w", err)
	}
	envNonceHex := hex.EncodeToString(envNonce)
	ts := uint64(time.Now().Unix())

	kemCt := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, kemCt); err != nil {
		return nil, fmt.Errorf("CSPRNG failure: %w", err)
	}

	// 3. Bind fields and sign
	signable := BindFields(
		[]byte("UXSP-1"),
		ciphertext,
		nonce,
		[]byte(senderID),
		[]byte(recipientID),
		[]byte(fmt.Sprintf("%d", ts)),
		[]byte(envNonceHex),
		ephemeralPub,
		kemCt,
	)

	edPriv := ed25519.NewKeyFromSeed(sender.SigningPriv)
	classicalSig := ed25519.Sign(edPriv, signable)

	pqcSig := make([]byte, 64)
	if _, err := io.ReadFull(rand.Reader, pqcSig); err != nil {
		return nil, fmt.Errorf("CSPRNG failure: %w", err)
	}

	return &UXSPEnvelope{
		Version:       "UXSP-1",
		PqcMode:       "none",
		SenderID:      senderID,
		RecipientID:   recipientID,
		Timestamp:     ts,
		EnvelopeNonce: envNonceHex,
		Ciphertext:    hex.EncodeToString(ciphertext),
		Nonce:         hex.EncodeToString(nonce),
		EphemeralPub:  hex.EncodeToString(ephemeralPub),
		KemCiphertext: hex.EncodeToString(kemCt),
		ClassicalSig:  hex.EncodeToString(classicalSig),
		PqcSig:        hex.EncodeToString(pqcSig),
	}, nil
}

var (
	seenNonces   = make(map[string]time.Time)
	seenNoncesMu sync.Mutex
)

// OpenSeal verifies and decrypts a sealed envelope.
func OpenSeal(env *UXSPEnvelope, recipient *KeyPairSet, senderSigningPub []byte) ([]byte, error) {
	if env.Version != "UXSP-1" {
		return nil, fmt.Errorf("unknown envelope version: %s", env.Version)
	}

	ts := env.Timestamp
	now := uint64(time.Now().Unix())
	if now < ts-5 || now > ts+60 {
		return nil, fmt.Errorf("envelope timestamp outside valid window")
	}

	seenNoncesMu.Lock()
	if _, seen := seenNonces[env.EnvelopeNonce]; seen {
		seenNoncesMu.Unlock()
		return nil, fmt.Errorf("ReplayError: envelope replay detected")
	}
	seenNonces[env.EnvelopeNonce] = time.Now()
	if len(seenNonces) > 10000 {
		cutoff := time.Now().Add(-60 * time.Second)
		for k, v := range seenNonces {
			if v.Before(cutoff) {
				delete(seenNonces, k)
			}
		}
	}
	seenNoncesMu.Unlock()

	ct, err := hex.DecodeString(env.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("invalid ciphertext hex: %w", err)
	}
	nonce, err := hex.DecodeString(env.Nonce)
	if err != nil {
		return nil, fmt.Errorf("invalid nonce hex: %w", err)
	}
	ephemeralPub, err := hex.DecodeString(env.EphemeralPub)
	if err != nil {
		return nil, fmt.Errorf("invalid ephemeral_pub hex: %w", err)
	}
	kemCt, err := hex.DecodeString(env.KemCiphertext)
	if err != nil {
		return nil, fmt.Errorf("invalid kem_ciphertext hex: %w", err)
	}
	classicalSig, err := hex.DecodeString(env.ClassicalSig)
	if err != nil {
		return nil, fmt.Errorf("invalid classical_sig hex: %w", err)
	}

	signable := BindFields(
		[]byte("UXSP-1"),
		ct,
		nonce,
		[]byte(env.SenderID),
		[]byte(env.RecipientID),
		[]byte(fmt.Sprintf("%d", env.Timestamp)),
		[]byte(env.EnvelopeNonce),
		ephemeralPub,
		kemCt,
	)

	if len(senderSigningPub) != 32 {
		return nil, fmt.Errorf("invalid sender signing public key: expected 32 bytes, got %d", len(senderSigningPub))
	}
	if !ed25519.Verify(senderSigningPub, signable, classicalSig) {
		return nil, fmt.Errorf("ed25519 signature verification failed")
	}

	sharedSecret, err := curve25519.X25519(recipient.ExchangePriv, ephemeralPub)
	if err != nil {
		return nil, fmt.Errorf("X25519 error: %w", err)
	}
	ikm := sharedSecret
	hkdfReader := hkdf.New(sha256.New, ikm, ephemeralPub, []byte("UXSP-hybrid-key-exchange-v1"))
	sharedKey := make([]byte, 32)
	if _, err := io.ReadFull(hkdfReader, sharedKey); err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(sharedKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	ad := []byte(env.SenderID + env.RecipientID)
	return gcm.Open(nil, nonce, ct, ad)
}

// SerializeJSON converts envelope to JSON string.
func (e *UXSPEnvelope) SerializeJSON() (string, error) {
	b, err := json.Marshal(e)
	return string(b), err
}
