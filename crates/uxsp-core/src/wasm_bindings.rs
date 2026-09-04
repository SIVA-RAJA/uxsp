#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

#[cfg(feature = "wasm")]
use crate::envelope::{seal_envelope, open_seal_envelope, UXSPEnvelope, KeyPairSet};

#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn wasm_seal(
    plaintext_hex: &str,
    sender_signing_priv_hex: &str,
    sender_pqc_sig_priv_hex: &str,
    sender_exchange_priv_hex: &str,
    sender_kem_priv_hex: &str,
    recipient_exchange_pub_hex: &str,
    recipient_kem_pub_hex: &str,
    sender_id: &str,
    recipient_id: &str,
) -> Result<String, JsValue> {
    let plaintext = hex::decode(plaintext_hex)
        .map_err(|e| JsValue::from_str(&format!("Invalid plaintext hex: {}", e)))?;
    let rec_ex_pub = hex::decode(recipient_exchange_pub_hex)
        .map_err(|e| JsValue::from_str(&format!("Invalid recipient_exchange_pub hex: {}", e)))?;
    let rec_kem_pub = hex::decode(recipient_kem_pub_hex)
        .map_err(|e| JsValue::from_str(&format!("Invalid recipient_kem_pub hex: {}", e)))?;

    let sender_keypair = KeyPairSet {
        exchange_priv: hex::decode(sender_exchange_priv_hex).unwrap_or_default(),
        exchange_pub: vec![],
        kem_priv: hex::decode(sender_kem_priv_hex).unwrap_or_default(),
        kem_pub: vec![],
        signing_priv: hex::decode(sender_signing_priv_hex).unwrap_or_default(),
        signing_pub: vec![],
        pqc_sig_priv: hex::decode(sender_pqc_sig_priv_hex).unwrap_or_default(),
        pqc_sig_pub: vec![],
    };

    let envelope = seal_envelope(
        &plaintext,
        &sender_keypair,
        &rec_ex_pub,
        &rec_kem_pub,
        sender_id,
        recipient_id,
        b"",
    ).map_err(|e| JsValue::from_str(&e))?;

    serde_json::to_string(&envelope).map_err(|e| JsValue::from_str(&e.to_string()))
}

#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn wasm_open_seal(
    envelope_json: &str,
    recipient_exchange_priv_hex: &str,
    recipient_kem_priv_hex: &str,
    sender_signing_pub_hex: &str,
    sender_pqc_sig_pub_hex: &str,
) -> Result<String, JsValue> {
    let envelope: UXSPEnvelope = serde_json::from_str(envelope_json)
        .map_err(|e| JsValue::from_str(&format!("Invalid JSON: {}", e)))?;

    let recipient_keypair = KeyPairSet {
        exchange_priv: hex::decode(recipient_exchange_priv_hex).unwrap_or_default(),
        exchange_pub: vec![],
        kem_priv: hex::decode(recipient_kem_priv_hex).unwrap_or_default(),
        kem_pub: vec![],
        signing_priv: vec![],
        signing_pub: vec![],
        pqc_sig_priv: vec![],
        pqc_sig_pub: vec![],
    };

    let sender_signing_pub = hex::decode(sender_signing_pub_hex).unwrap_or_default();
    let sender_pqc_sig_pub = hex::decode(sender_pqc_sig_pub_hex).unwrap_or_default();

    let plaintext = open_seal_envelope(
        &envelope,
        &recipient_keypair,
        &sender_signing_pub,
        &sender_pqc_sig_pub,
        None,
        None,
        300,
        30,
        false,
        b"",
    ).map_err(|e| JsValue::from_str(&e))?;

    Ok(hex::encode(plaintext))
}
