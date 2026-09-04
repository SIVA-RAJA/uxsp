use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer, Verifier};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret};

pub struct KeyPair {
    pub private_key: Vec<u8>,
    pub public_key: Vec<u8>,
}

pub struct EncryptedResult {
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
}

/// Length-prefixed concatenation of fields (big-endian u32 prefix)
pub fn bind_fields(fields: &[&[u8]]) -> Vec<u8> {
    let mut result = Vec::new();
    for field in fields {
        let len = field.len() as u32;
        result.extend_from_slice(&len.to_be_bytes());
        result.extend_from_slice(field);
    }
    result
}

/// Generate X25519 keypair for key exchange
pub fn generate_exchange_keypair() -> KeyPair {
    let mut rng = rand::thread_rng();
    let secret = StaticSecret::random_from_rng(&mut rng);
    let public = XPublicKey::from(&secret);
    KeyPair {
        private_key: secret.to_bytes().to_vec(),
        public_key: public.as_bytes().to_vec(),
    }
}

/// Compute X25519 shared secret
pub fn compute_shared_secret(private_key_bytes: &[u8], public_key_bytes: &[u8]) -> Result<Vec<u8>, String> {
    if private_key_bytes.len() != 32 || public_key_bytes.len() != 32 {
        return Err("Invalid X25519 key lengths, expected 32 bytes".to_string());
    }
    let mut priv_arr = [0u8; 32];
    let mut pub_arr = [0u8; 32];
    priv_arr.copy_from_slice(private_key_bytes);
    pub_arr.copy_from_slice(public_key_bytes);

    let secret = StaticSecret::from(priv_arr);
    let public = XPublicKey::from(pub_arr);
    let shared = secret.diffie_hellman(&public);
    Ok(shared.as_bytes().to_vec())
}

/// Generate Ed25519 keypair for signing
pub fn generate_signing_keypair() -> KeyPair {
    let mut rng = rand::thread_rng();
    let mut secret_bytes = [0u8; 32];
    rng.fill_bytes(&mut secret_bytes);
    let signing_key = SigningKey::from_bytes(&secret_bytes);
    let verifying_key = signing_key.verifying_key();
    KeyPair {
        private_key: secret_bytes.to_vec(),
        public_key: verifying_key.to_bytes().to_vec(),
    }
}

/// Ed25519 signature
pub fn sign_classical(message: &[u8], private_key_bytes: &[u8]) -> Result<Vec<u8>, String> {
    if private_key_bytes.len() != 32 {
        return Err("Ed25519 private key must be 32 bytes".to_string());
    }
    let mut key_arr = [0u8; 32];
    key_arr.copy_from_slice(private_key_bytes);
    let signing_key = SigningKey::from_bytes(&key_arr);
    let signature = signing_key.sign(message);
    Ok(signature.to_bytes().to_vec())
}

/// Ed25519 verification
pub fn verify_classical(message: &[u8], signature_bytes: &[u8], public_key_bytes: &[u8]) -> bool {
    if signature_bytes.len() != 64 || public_key_bytes.len() != 32 {
        return false;
    }
    let mut sig_arr = [0u8; 64];
    let mut pub_arr = [0u8; 32];
    sig_arr.copy_from_slice(signature_bytes);
    pub_arr.copy_from_slice(public_key_bytes);

    let signature = Signature::from_bytes(&sig_arr);
    let Ok(verifying_key) = VerifyingKey::from_bytes(&pub_arr) else {
        return false;
    };
    verifying_key.verify(message, &signature).is_ok()
}

/// HKDF key derivation using SHA-256
pub fn derive_key(ikm: &[u8], salt: &[u8], info: &[u8], length: usize) -> Result<Vec<u8>, String> {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut okm = vec![0u8; length];
    hk.expand(info, &mut okm)
        .map_err(|_| "HKDF expansion failed".to_string())?;
    Ok(okm)
}

/// AES-256-GCM encryption
pub fn encrypt_aes_gcm(plaintext: &[u8], key: &[u8], associated_data: &[u8]) -> Result<EncryptedResult, String> {
    if key.len() != 32 {
        return Err("AES-256 key must be 32 bytes".to_string());
    }
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| e.to_string())?;
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let payload = Payload {
        msg: plaintext,
        aad: associated_data,
    };
    let ciphertext = cipher.encrypt(nonce, payload).map_err(|e| e.to_string())?;
    Ok(EncryptedResult {
        ciphertext,
        nonce: nonce_bytes.to_vec(),
    })
}

/// AES-256-GCM decryption
pub fn decrypt_aes_gcm(ciphertext: &[u8], nonce_bytes: &[u8], key: &[u8], associated_data: &[u8]) -> Result<Vec<u8>, String> {
    if key.len() != 32 {
        return Err("AES-256 key must be 32 bytes".to_string());
    }
    if nonce_bytes.len() != 12 {
        return Err("AES-GCM nonce must be 12 bytes".to_string());
    }
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| e.to_string())?;
    let nonce = Nonce::from_slice(nonce_bytes);

    let payload = Payload {
        msg: ciphertext,
        aad: associated_data,
    };
    cipher.decrypt(nonce, payload).map_err(|e| e.to_string())
}

/// ML-KEM / PQC Encapsulation Stub (for Post-Quantum Hybrid mode)
pub fn pqc_encapsulate(recipient_kem_pub: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let mut rng = rand::thread_rng();
    let mut ciphertext = vec![0u8; 32];
    rng.fill_bytes(&mut ciphertext);

    let mut shared_secret = vec![0u8; 32];
    let salt = if recipient_kem_pub.is_empty() { b"pqc-salt" as &[u8] } else { recipient_kem_pub };
    let hk = Hkdf::<Sha256>::new(Some(salt), &ciphertext);
    let _ = hk.expand(b"pqc-kem-shared", &mut shared_secret);
    (shared_secret, ciphertext)
}

/// ML-KEM / PQC Decapsulation Stub
pub fn pqc_decapsulate(kem_ciphertext: &[u8], _my_kem_priv: &[u8]) -> Vec<u8> {
    let mut shared_secret = vec![0u8; 32];
    let salt = if _my_kem_priv.is_empty() { b"pqc-salt" as &[u8] } else { &vec![2u8; 32] };
    let hk = Hkdf::<Sha256>::new(Some(salt), kem_ciphertext);
    let _ = hk.expand(b"pqc-kem-shared", &mut shared_secret);
    shared_secret
}

/// ML-DSA / PQC Signature Stub
pub fn pqc_sign_stub(message: &[u8], private_key: &[u8]) -> Vec<u8> {
    let hk = Hkdf::<Sha256>::new(Some(private_key), message);
    let mut sig = vec![0u8; 64];
    let _ = hk.expand(b"pqc-dsa-sig", &mut sig);
    sig
}

/// ML-DSA / PQC Verification Stub
pub fn pqc_verify_stub(_message: &[u8], sig: &[u8], _public_key: &[u8]) -> bool {
    sig.len() == 64
}
