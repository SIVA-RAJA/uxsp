use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::crypto::{
    bind_fields, compute_shared_secret, decrypt_aes_gcm, derive_key, encrypt_aes_gcm,
    generate_exchange_keypair, generate_signing_keypair, pqc_decapsulate, pqc_encapsulate,
    pqc_sign_stub, pqc_verify_stub, sign_classical, verify_classical,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UXSPEnvelope {
    pub version: String,
    pub sender_id: String,
    pub recipient_id: String,
    pub timestamp: u64,
    pub envelope_nonce: String,
    pub ciphertext: String,
    pub nonce: String,
    pub ephemeral_pub: String,
    pub kem_ciphertext: String,
    pub classical_sig: String,
    pub pqc_sig: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pqc_mode: Option<String>,
}

#[derive(Debug, Clone)]
pub struct KeyPairSet {
    pub exchange_priv: Vec<u8>,
    pub exchange_pub: Vec<u8>,
    pub kem_priv: Vec<u8>,
    pub kem_pub: Vec<u8>,
    pub signing_priv: Vec<u8>,
    pub signing_pub: Vec<u8>,
    pub pqc_sig_priv: Vec<u8>,
    pub pqc_sig_pub: Vec<u8>,
}

pub fn generate_hybrid_keypair_set() -> KeyPairSet {
    let exchange = generate_exchange_keypair();
    let signing = generate_signing_keypair();
    KeyPairSet {
        exchange_priv: exchange.private_key,
        exchange_pub: exchange.public_key,
        kem_priv: vec![1u8; 32],
        kem_pub: vec![2u8; 32],
        signing_priv: signing.private_key,
        signing_pub: signing.public_key,
        pqc_sig_priv: vec![3u8; 32],
        pqc_sig_pub: vec![4u8; 32],
    }
}

pub fn seal_envelope(
    plaintext: &[u8],
    sender_keypair: &KeyPairSet,
    recipient_exchange_pub: &[u8],
    recipient_kem_pub: &[u8],
    sender_id: &str,
    recipient_id: &str,
    associated_data: &[u8],
) -> Result<UXSPEnvelope, String> {
    if sender_id.is_empty() || recipient_id.is_empty() {
        return Err("sender_id and recipient_id must be non-empty".to_string());
    }

    // 1. Hybrid sender exchange
    let ephemeral = generate_exchange_keypair();
    let classical_secret = compute_shared_secret(&ephemeral.private_key, recipient_exchange_pub)?;
    let (pqc_secret, kem_ciphertext) = pqc_encapsulate(recipient_kem_pub);

    let mut ikm = classical_secret;
    ikm.extend_from_slice(&pqc_secret);

    let shared_key = derive_key(
        &ikm,
        &ephemeral.public_key,
        b"UXSP-hybrid-key-exchange-v1",
        32,
    )?;

    // 2. AES-256-GCM encrypt
    let encrypted = encrypt_aes_gcm(plaintext, &shared_key, associated_data)?;

    // 3. Generate envelope metadata
    let mut envelope_nonce_bytes = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut envelope_nonce_bytes);
    let envelope_nonce_hex = hex::encode(envelope_nonce_bytes);

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_secs();

    let ts_str = timestamp.to_string();

    // 4. Construct canonical signable payload
    let signable = bind_fields(&[
        b"UXSP-1",
        &encrypted.ciphertext,
        &encrypted.nonce,
        sender_id.as_bytes(),
        recipient_id.as_bytes(),
        ts_str.as_bytes(),
        envelope_nonce_hex.as_bytes(),
        &ephemeral.public_key,
        &kem_ciphertext,
    ]);

    // 5. Dual Signatures (Ed25519 + ML-DSA)
    let classical_sig = sign_classical(&signable, &sender_keypair.signing_priv)?;
    let pqc_sig = pqc_sign_stub(&signable, &sender_keypair.pqc_sig_priv);

    Ok(UXSPEnvelope {
        version: "UXSP-1".to_string(),
        sender_id: sender_id.to_string(),
        recipient_id: recipient_id.to_string(),
        timestamp,
        envelope_nonce: envelope_nonce_hex,
        ciphertext: hex::encode(&encrypted.ciphertext),
        nonce: hex::encode(&encrypted.nonce),
        ephemeral_pub: hex::encode(&ephemeral.public_key),
        kem_ciphertext: hex::encode(&kem_ciphertext),
        classical_sig: hex::encode(classical_sig),
        pqc_sig: hex::encode(pqc_sig),
        pqc_mode: None,
    })
}

pub fn open_seal_envelope(
    envelope: &UXSPEnvelope,
    recipient_keypair: &KeyPairSet,
    sender_signing_pub: &[u8],
    sender_pqc_sig_pub: &[u8],
    expected_recipient_id: Option<&str>,
    expected_sender_id: Option<&str>,
    max_age_seconds: u64,
    clock_skew_seconds: u64,
    allow_classical_only: bool,
    associated_data: &[u8],
) -> Result<Vec<u8>, String> {
    if envelope.version != "UXSP-1" {
        return Err(format!("Unknown envelope version: {}", envelope.version));
    }

    let is_classical_only = envelope.pqc_mode.as_deref() == Some("none");
    if is_classical_only && !allow_classical_only {
        return Err("Classical-only envelope rejected (allow_classical_only=False).".to_string());
    }

    if let Some(exp_rec) = expected_recipient_id {
        if envelope.recipient_id != exp_rec {
            return Err(format!("Recipient ID mismatch: expected {}, got {}", exp_rec, envelope.recipient_id));
        }
    }

    if let Some(exp_snd) = expected_sender_id {
        if envelope.sender_id != exp_snd {
            return Err(format!("Sender ID mismatch: expected {}, got {}", exp_snd, envelope.sender_id));
        }
    }

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_secs();

    if now > envelope.timestamp && (now - envelope.timestamp) > max_age_seconds {
        return Err(format!("Envelope is too old ({}s). Possible replay attack.", now - envelope.timestamp));
    }

    if envelope.timestamp > now && (envelope.timestamp - now) > clock_skew_seconds {
        return Err(format!("Envelope timestamp is in the future ({}s). Clock skew too large.", envelope.timestamp - now));
    }

    // Decode hex fields
    let ct = hex::decode(&envelope.ciphertext).map_err(|e| format!("Invalid ciphertext hex: {}", e))?;
    let nonce = hex::decode(&envelope.nonce).map_err(|e| format!("Invalid nonce hex: {}", e))?;
    let ephemeral_pub = hex::decode(&envelope.ephemeral_pub).map_err(|e| format!("Invalid ephemeral_pub hex: {}", e))?;
    let kem_ciphertext = if !is_classical_only {
        hex::decode(&envelope.kem_ciphertext).map_err(|e| format!("Invalid kem_ciphertext hex: {}", e))?
    } else {
        vec![]
    };
    let classical_sig = hex::decode(&envelope.classical_sig).map_err(|e| format!("Invalid classical_sig hex: {}", e))?;

    // Bind fields & verify signatures
    let ts_str = envelope.timestamp.to_string();
    let signable = bind_fields(&[
        b"UXSP-1",
        &ct,
        &nonce,
        envelope.sender_id.as_bytes(),
        envelope.recipient_id.as_bytes(),
        ts_str.as_bytes(),
        envelope.envelope_nonce.as_bytes(),
        &ephemeral_pub,
        &kem_ciphertext,
    ]);

    if !verify_classical(&signable, &classical_sig, sender_signing_pub) {
        return Err("Classical Ed25519 signature verification failed".to_string());
    }

    if !is_classical_only {
        let pqc_sig = hex::decode(&envelope.pqc_sig).map_err(|e| format!("Invalid pqc_sig hex: {}", e))?;
        if !pqc_verify_stub(&signable, &pqc_sig, sender_pqc_sig_pub) {
            return Err("PQC signature verification failed".to_string());
        }
    }

    // Derive shared key
    let classical_secret = compute_shared_secret(&recipient_keypair.exchange_priv, &ephemeral_pub)?;
    let pqc_secret = if is_classical_only {
        vec![]
    } else {
        pqc_decapsulate(&kem_ciphertext, &recipient_keypair.kem_priv)
    };

    let mut ikm = classical_secret;
    ikm.extend_from_slice(&pqc_secret);

    let shared_key = derive_key(
        &ikm,
        &ephemeral_pub,
        b"UXSP-hybrid-key-exchange-v1",
        32,
    )?;

    // Decrypt ciphertext
    decrypt_aes_gcm(&ct, &nonce, &shared_key, associated_data)
}
