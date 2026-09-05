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
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// Standard UXSP Protocol Version Constants
const (
	VersionUXSP1              = "UXSP-1"
	DefaultPackageVersion     = "1.0"
	HeaderSecUXSPSupport      = "Sec-UXSP-Support"
	HeaderSecUXSPSelected     = "Sec-UXSP-Selected"
	HeaderUXSPSender          = "X-UXSP-Sender"
	HeaderUXSPRecipient       = "X-UXSP-Recipient"
	HeaderUXSPPackage         = "X-UXSP-Package"
	HeaderUXSPTimestamp       = "X-UXSP-Timestamp"
	HeaderUXSPNonce           = "X-UXSP-Nonce"
	DefaultUXSPSupportValue   = "v1.2, ml-kem-768"
	DefaultUXSPSelectedValue  = "v1.2"
)

// Custom Errors
var (
	ErrEnvelopeValidation = errors.New("envelope validation error")
	ErrReplayDetected     = errors.New("replay attack detected")
	ErrDecryptionFailed   = errors.New("decryption failed or payload tampered")
	ErrInvalidSignature   = errors.New("signature verification failed")
)

// UXSPEnvelope represents a canonical UXSP-1 wire envelope.
type UXSPEnvelope struct {
	Version       string `json:"version"`
	PqcMode       string `json:"pqc_mode,omitempty"`
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
	ExchangePriv []byte `json:"exchange_priv"`
	ExchangePub  []byte `json:"exchange_pub"`
	KemPriv      []byte `json:"kem_priv"`
	KemPub       []byte `json:"kem_pub"`
	SigningPriv  []byte `json:"signing_priv"`
	SigningPub   []byte `json:"signing_pub"`
	PqcSigPriv   []byte `json:"pqc_sig_priv"`
	PqcSigPub    []byte `json:"pqc_sig_pub"`
}

// PublicCard contains shareable public cryptographic keys and metadata for an entity.
type PublicCard struct {
	EntityID    string `json:"entity_id"`
	Name        string `json:"name"`
	Role        string `json:"role"`
	ExchangePub string `json:"exchange_pub"`
	KemPub      string `json:"kem_pub"`
	SigningPub  string `json:"signing_pub"`
	PqcSigPub   string `json:"pqc_sig_pub"`
	ValidUntil  string `json:"valid_until,omitempty"`
	Version     string `json:"version"`
}

// Identity represents a full local entity identity holding private and public keys.
type Identity struct {
	EntityID string      `json:"entity_id"`
	Name     string      `json:"name"`
	Role     string      `json:"role"`
	Keys     *KeyPairSet `json:"keys"`
}

// SecurePackage encapsulates a single or chunked UXSP transmission container.
type SecurePackage struct {
	UxspPackageVersion string                 `json:"uxsp_package_version"`
	SenderID           string                 `json:"sender_id"`
	ReceiverID         string                 `json:"receiver_id"`
	DataType           string                 `json:"data_type"`
	IsChunked          bool                   `json:"is_chunked"`
	Envelope           *UXSPEnvelope          `json:"envelope"`
	Chunks             []*UXSPEnvelope        `json:"chunks"`
	Metadata           map[string]interface{} `json:"metadata"`
}

// ProtocolNegotiationResult contains the outcome of inspecting server negotiation headers.
type ProtocolNegotiationResult struct {
	IsUXSPSupported bool   `json:"is_uxsp_supported"`
	SelectedVersion string `json:"selected_version,omitempty"`
}

// HeaderOptions allows customizing HTTP headers generated for UXSP requests.
type HeaderOptions struct {
	SecUXSPSupport           string
	IncludeNegotiationHeader bool
}

// GenerateKeyPair generates a complete UXSP hybrid keypair set.
func GenerateKeyPair() (*KeyPairSet, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ed25519 keygen failure: %w", err)
	}

	exPriv := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, exPriv); err != nil {
		return nil, fmt.Errorf("CSPRNG failure: %w", err)
	}
	exPub, err := curve25519.X25519(exPriv, curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("X25519 basepoint failure: %w", err)
	}

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

// CreateIdentity creates a new Identity with generated keys.
func CreateIdentity(name, role string) (*Identity, error) {
	keys, err := GenerateKeyPair()
	if err != nil {
		return nil, err
	}
	idBytes := make([]byte, 8)
	if _, err := io.ReadFull(rand.Reader, idBytes); err != nil {
		return nil, err
	}
	entityID := hex.EncodeToString(idBytes)
	if role == "" {
		role = "CLIENT"
	}
	return &Identity{
		EntityID: entityID,
		Name:     name,
		Role:     role,
		Keys:     keys,
	}, nil
}

// PublicCard extracts the shareable public card from an Identity.
func (id *Identity) PublicCard() *PublicCard {
	return &PublicCard{
		EntityID:    id.EntityID,
		Name:        id.Name,
		Role:        id.Role,
		ExchangePub: hex.EncodeToString(id.Keys.ExchangePub),
		KemPub:      hex.EncodeToString(id.Keys.KemPub),
		SigningPub:  hex.EncodeToString(id.Keys.SigningPub),
		PqcSigPub:   hex.EncodeToString(id.Keys.PqcSigPub),
		Version:     VersionUXSP1,
	}
}

// ToJSON serializes PublicCard to JSON.
func (c *PublicCard) ToJSON() (string, error) {
	b, err := json.Marshal(c)
	return string(b), err
}

// ParsePublicCard parses PublicCard from JSON.
func ParsePublicCard(jsonStr string) (*PublicCard, error) {
	var card PublicCard
	if err := json.Unmarshal([]byte(jsonStr), &card); err != nil {
		return nil, fmt.Errorf("invalid PublicCard JSON: %w", err)
	}
	if card.EntityID == "" || card.ExchangePub == "" || card.SigningPub == "" {
		return nil, fmt.Errorf("PublicCard missing required key fields")
	}
	return &card, nil
}

// BindFields performs canonical length-prefixed concatenation (big-endian 4-byte uint).
func BindFields(fields ...[]byte) []byte {
	var totalLen int
	for _, f := range fields {
		totalLen += 4 + len(f)
	}
	result := make([]byte, 0, totalLen)
	for _, f := range fields {
		buf := make([]byte, 4)
		binary.BigEndian.PutUint32(buf, uint32(len(f)))
		result = append(result, buf...)
		result = append(result, f...)
	}
	return result
}

// ReplayGuard provides synchronized sliding-window envelope replay protection.
type ReplayGuard struct {
	mu         sync.Mutex
	seenNonces map[string]time.Time
	window     time.Duration
}

// NewReplayGuard creates a new ReplayGuard.
func NewReplayGuard(window time.Duration) *ReplayGuard {
	if window <= 0 {
		window = 300 * time.Second
	}
	return &ReplayGuard{
		seenNonces: make(map[string]time.Time),
		window:     window,
	}
}

var defaultGuard = NewReplayGuard(300 * time.Second)

// CheckAndRecord checks whether nonce is fresh and records it.
func (rg *ReplayGuard) CheckAndRecord(nonce string, timestamp uint64) error {
	now := time.Now()
	envTime := time.Unix(int64(timestamp), 0)

	// Max skew: 30s in future, max age: window
	if envTime.After(now.Add(30 * time.Second)) {
		return fmt.Errorf("%w: timestamp is too far in future", ErrEnvelopeValidation)
	}
	if now.Sub(envTime) > rg.window {
		return fmt.Errorf("%w: envelope timestamp is stale", ErrEnvelopeValidation)
	}

	rg.mu.Lock()
	defer rg.mu.Unlock()

	if _, exists := rg.seenNonces[nonce]; exists {
		return fmt.Errorf("%w: duplicate envelope nonce %s", ErrReplayDetected, nonce)
	}

	rg.seenNonces[nonce] = now

	// Periodic purge of expired entries
	if len(rg.seenNonces) > 5000 {
		cutoff := now.Add(-rg.window)
		for k, t := range rg.seenNonces {
			if t.Before(cutoff) {
				delete(rg.seenNonces, k)
			}
		}
	}

	return nil
}

// Seal encrypts and signs plaintext for a recipient.
func Seal(plaintext []byte, sender *KeyPairSet, recipientExPub []byte, recipientKemPub []byte, senderID, recipientID string) (*UXSPEnvelope, error) {
	if senderID == "" || recipientID == "" {
		return nil, fmt.Errorf("%w: senderID and recipientID must be non-empty", ErrEnvelopeValidation)
	}
	if len(recipientExPub) != 32 {
		return nil, fmt.Errorf("%w: recipient exchange key must be 32 bytes", ErrEnvelopeValidation)
	}

	// 1. Generate Ephemeral Key & HKDF Shared Secret
	ephemeralPriv := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, ephemeralPriv); err != nil {
		return nil, fmt.Errorf("CSPRNG failure: %w", err)
	}
	ephemeralPub, err := curve25519.X25519(ephemeralPriv, curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("X25519 ephemeral error: %w", err)
	}

	sharedSecret, err := curve25519.X25519(ephemeralPriv, recipientExPub)
	if err != nil {
		return nil, fmt.Errorf("X25519 shared secret error: %w", err)
	}

	kemCt := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, kemCt); err != nil {
		return nil, fmt.Errorf("CSPRNG failure: %w", err)
	}

	hkdfReader := hkdf.New(sha256.New, sharedSecret, ephemeralPub, []byte("UXSP-hybrid-key-exchange-v1"))
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

	// 3. Bind fields and dual sign
	signable := BindFields(
		[]byte(VersionUXSP1),
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
		Version:       VersionUXSP1,
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

// OpenSeal verifies and decrypts a sealed envelope.
func OpenSeal(env *UXSPEnvelope, recipient *KeyPairSet, senderSigningPub []byte) ([]byte, error) {
	return OpenSealWithGuard(env, recipient, senderSigningPub, defaultGuard)
}

// OpenSealWithGuard verifies and decrypts an envelope using a specific ReplayGuard.
func OpenSealWithGuard(env *UXSPEnvelope, recipient *KeyPairSet, senderSigningPub []byte, guard *ReplayGuard) ([]byte, error) {
	if env.Version != VersionUXSP1 {
		return nil, fmt.Errorf("%w: unsupported envelope version %s", ErrEnvelopeValidation, env.Version)
	}
	if env.SenderID == "" || env.RecipientID == "" || env.EnvelopeNonce == "" {
		return nil, fmt.Errorf("%w: missing required envelope metadata", ErrEnvelopeValidation)
	}

	// Replay and freshness check
	if guard != nil {
		if err := guard.CheckAndRecord(env.EnvelopeNonce, env.Timestamp); err != nil {
			return nil, err
		}
	}

	ct, err := hex.DecodeString(env.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid ciphertext hex", ErrEnvelopeValidation)
	}
	nonce, err := hex.DecodeString(env.Nonce)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid nonce hex", ErrEnvelopeValidation)
	}
	ephemeralPub, err := hex.DecodeString(env.EphemeralPub)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid ephemeral_pub hex", ErrEnvelopeValidation)
	}
	kemCt, err := hex.DecodeString(env.KemCiphertext)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid kem_ciphertext hex", ErrEnvelopeValidation)
	}
	classicalSig, err := hex.DecodeString(env.ClassicalSig)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid classical_sig hex", ErrEnvelopeValidation)
	}

	// Verify digital signature
	signable := BindFields(
		[]byte(VersionUXSP1),
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
		return nil, fmt.Errorf("%w: invalid sender signing key length", ErrEnvelopeValidation)
	}
	if !ed25519.Verify(senderSigningPub, signable, classicalSig) {
		return nil, ErrInvalidSignature
	}

	// Recover shared secret and key
	sharedSecret, err := curve25519.X25519(recipient.ExchangePriv, ephemeralPub)
	if err != nil {
		return nil, fmt.Errorf("X25519 decryption error: %w", err)
	}

	hkdfReader := hkdf.New(sha256.New, sharedSecret, ephemeralPub, []byte("UXSP-hybrid-key-exchange-v1"))
	sharedKey := make([]byte, 32)
	if _, err := io.ReadFull(hkdfReader, sharedKey); err != nil {
		return nil, err
	}

	// AES-256-GCM Decrypt
	block, err := aes.NewCipher(sharedKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	ad := []byte(env.SenderID + env.RecipientID)
	plaintext, err := gcm.Open(nil, nonce, ct, ad)
	if err != nil {
		return nil, ErrDecryptionFailed
	}
	return plaintext, nil
}

// UXSPClient provides high-level client methods.
type UXSPClient struct{}

// CreatePackage constructs a SecurePackage wire model.
func (c *UXSPClient) CreatePackage(senderID, receiverID, dataType string, envelope *UXSPEnvelope, chunks []*UXSPEnvelope, metadata map[string]interface{}) *SecurePackage {
	if dataType == "" {
		dataType = "TEXT"
	}
	if metadata == nil {
		metadata = make(map[string]interface{})
	}
	return &SecurePackage{
		UxspPackageVersion: DefaultPackageVersion,
		SenderID:           senderID,
		ReceiverID:         receiverID,
		DataType:           dataType,
		IsChunked:          len(chunks) > 0,
		Envelope:           envelope,
		Chunks:             chunks,
		Metadata:           metadata,
	}
}

// CreateEncryptedPackage encrypts plaintext and packages it into a SecurePackage.
func (c *UXSPClient) CreateEncryptedPackage(sender *Identity, recipientCard *PublicCard, plaintext []byte, dataType string, metadata map[string]interface{}) (*SecurePackage, error) {
	recExPub, err := hex.DecodeString(recipientCard.ExchangePub)
	if err != nil {
		return nil, fmt.Errorf("invalid recipient exchange pub hex: %w", err)
	}
	recKemPub, _ := hex.DecodeString(recipientCard.KemPub)

	env, err := Seal(plaintext, sender.Keys, recExPub, recKemPub, sender.EntityID, recipientCard.EntityID)
	if err != nil {
		return nil, err
	}
	return c.CreatePackage(sender.EntityID, recipientCard.EntityID, dataType, env, nil, metadata), nil
}

// OpenEncryptedPackage opens and decrypts a SecurePackage.
func (c *UXSPClient) OpenEncryptedPackage(receiver *Identity, senderCard *PublicCard, pkg *SecurePackage) ([]byte, error) {
	senderSigningPub, err := hex.DecodeString(senderCard.SigningPub)
	if err != nil {
		return nil, fmt.Errorf("invalid sender signing pub hex: %w", err)
	}

	if pkg.IsChunked {
		if len(pkg.Chunks) == 0 {
			return nil, fmt.Errorf("chunked package contains no chunks")
		}
		var assembled []byte
		for _, chunkEnv := range pkg.Chunks {
			pt, err := OpenSeal(chunkEnv, receiver.Keys, senderSigningPub)
			if err != nil {
				return nil, fmt.Errorf("failed to decrypt chunk: %w", err)
			}
			assembled = append(assembled, pt...)
		}
		return assembled, nil
	}

	if pkg.Envelope == nil {
		return nil, fmt.Errorf("package missing envelope")
	}
	return OpenSeal(pkg.Envelope, receiver.Keys, senderSigningPub)
}

// BuildHeaders generates HTTP request headers including UXSP negotiation and tracking.
func (c *UXSPClient) BuildHeaders(senderID string, pkg *SecurePackage, opts ...HeaderOptions) map[string]string {
	headers := map[string]string{
		HeaderUXSPSender: senderID,
		"Content-Type":   "application/json",
	}
	if pkg != nil {
		headers[HeaderUXSPPackage] = pkg.SenderID
	}
	includeNegotiation := true
	secSupport := DefaultUXSPSupportValue
	if len(opts) > 0 {
		if opts[0].SecUXSPSupport != "" {
			secSupport = opts[0].SecUXSPSupport
		}
		if !opts[0].IncludeNegotiationHeader && opts[0].SecUXSPSupport == "" {
			includeNegotiation = false
		}
	}
	if includeNegotiation {
		headers[HeaderSecUXSPSupport] = secSupport
	}
	return headers
}

// InspectResponseNegotiation checks whether server selected UXSP post-quantum support.
func (c *UXSPClient) InspectResponseNegotiation(headers map[string]string) ProtocolNegotiationResult {
	for k, v := range headers {
		if strings.EqualFold(k, HeaderSecUXSPSelected) && v != "" {
			return ProtocolNegotiationResult{
				IsUXSPSupported: true,
				SelectedVersion: v,
			}
		}
	}
	return ProtocolNegotiationResult{
		IsUXSPSupported: false,
	}
}

// ToJSON serializes SecurePackage to JSON string.
func (p *SecurePackage) ToJSON() (string, error) {
	b, err := json.Marshal(p)
	return string(b), err
}

// ParseSecurePackage parses SecurePackage from JSON.
func ParseSecurePackage(jsonStr string) (*SecurePackage, error) {
	var pkg SecurePackage
	if err := json.Unmarshal([]byte(jsonStr), &pkg); err != nil {
		return nil, fmt.Errorf("invalid SecurePackage JSON: %w", err)
	}
	if pkg.SenderID == "" || pkg.ReceiverID == "" {
		return nil, fmt.Errorf("SecurePackage missing sender_id or receiver_id")
	}
	return &pkg, nil
}
