use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int};
use std::slice;

use crate::envelope::{generate_hybrid_keypair_set, open_seal_envelope, seal_envelope, UXSPEnvelope, KeyPairSet};

#[no_mangle]
pub unsafe extern "C" fn uxsp_free_string(s: *mut c_char) {
    if !s.is_null() {
        drop(CString::from_raw(s));
    }
}

#[no_mangle]
pub unsafe extern "C" fn uxsp_generate_keypair_hex_c() -> *mut c_char {
    let keypair = generate_hybrid_keypair_set();
    let json = serde_json::json!({
        "exchange_priv": hex::encode(&keypair.exchange_priv),
        "exchange_pub": hex::encode(&keypair.exchange_pub),
        "kem_priv": hex::encode(&keypair.kem_priv),
        "kem_pub": hex::encode(&keypair.kem_pub),
        "signing_priv": hex::encode(&keypair.signing_priv),
        "signing_pub": hex::encode(&keypair.signing_pub),
        "pqc_sig_priv": hex::encode(&keypair.pqc_sig_priv),
        "pqc_sig_pub": hex::encode(&keypair.pqc_sig_pub),
    });

    CString::new(json.to_string()).map(|c| c.into_raw()).unwrap_or(std::ptr::null_mut())
}

#[no_mangle]
pub unsafe extern "C" fn uxsp_seal_c(
    plaintext_ptr: *const u8,
    plaintext_len: usize,
    sender_signing_priv_hex: *const c_char,
    sender_pqc_sig_priv_hex: *const c_char,
    sender_exchange_priv_hex: *const c_char,
    sender_kem_priv_hex: *const c_char,
    recipient_exchange_pub_hex: *const c_char,
    recipient_kem_pub_hex: *const c_char,
    sender_id_ptr: *const c_char,
    recipient_id_ptr: *const c_char,
) -> *mut c_char {
    if plaintext_ptr.is_null() || sender_id_ptr.is_null() || recipient_id_ptr.is_null() {
        return std::ptr::null_mut();
    }

    let plaintext = slice::from_raw_parts(plaintext_ptr, plaintext_len);
    let sender_id = match CStr::from_ptr(sender_id_ptr).to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };
    let recipient_id = match CStr::from_ptr(recipient_id_ptr).to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };

    let parse_hex = |ptr: *const c_char| -> Vec<u8> {
        if ptr.is_null() { return vec![]; }
        let str_val = CStr::from_ptr(ptr).to_str().unwrap_or("");
        hex::decode(str_val).unwrap_or_default()
    };

    let sender_keypair = KeyPairSet {
        exchange_priv: parse_hex(sender_exchange_priv_hex),
        exchange_pub: vec![],
        kem_priv: parse_hex(sender_kem_priv_hex),
        kem_pub: vec![],
        signing_priv: parse_hex(sender_signing_priv_hex),
        signing_pub: vec![],
        pqc_sig_priv: parse_hex(sender_pqc_sig_priv_hex),
        pqc_sig_pub: vec![],
    };

    let rec_ex_pub = parse_hex(recipient_exchange_pub_hex);
    let rec_kem_pub = parse_hex(recipient_kem_pub_hex);

    match seal_envelope(
        plaintext,
        &sender_keypair,
        &rec_ex_pub,
        &rec_kem_pub,
        sender_id,
        recipient_id,
        b"",
    ) {
        Ok(envelope) => {
            let json_str = serde_json::to_string(&envelope).unwrap_or_default();
            CString::new(json_str).map(|c| c.into_raw()).unwrap_or(std::ptr::null_mut())
        }
        Err(_) => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn uxsp_open_seal_c(
    envelope_json_ptr: *const c_char,
    recipient_exchange_priv_hex: *const c_char,
    recipient_kem_priv_hex: *const c_char,
    sender_signing_pub_hex: *const c_char,
    sender_pqc_sig_pub_hex: *const c_char,
    out_buf: *mut u8,
    out_buf_max_len: usize,
    out_len: *mut usize,
) -> c_int {
    if envelope_json_ptr.is_null() || out_buf.is_null() || out_len.is_null() {
        return -1;
    }

    let json_str = match CStr::from_ptr(envelope_json_ptr).to_str() {
        Ok(s) => s,
        Err(_) => return -2,
    };

    let envelope: UXSPEnvelope = match serde_json::from_str(json_str) {
        Ok(e) => e,
        Err(_) => return -3,
    };

    let parse_hex = |ptr: *const c_char| -> Vec<u8> {
        if ptr.is_null() { return vec![]; }
        let str_val = CStr::from_ptr(ptr).to_str().unwrap_or("");
        hex::decode(str_val).unwrap_or_default()
    };

    let recipient_keypair = KeyPairSet {
        exchange_priv: parse_hex(recipient_exchange_priv_hex),
        exchange_pub: vec![],
        kem_priv: parse_hex(recipient_kem_priv_hex),
        kem_pub: vec![],
        signing_priv: vec![],
        signing_pub: vec![],
        pqc_sig_priv: vec![],
        pqc_sig_pub: vec![],
    };

    let sender_signing_pub = parse_hex(sender_signing_pub_hex);
    let sender_pqc_sig_pub = parse_hex(sender_pqc_sig_pub_hex);

    match open_seal_envelope(
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
    ) {
        Ok(pt) => {
            if pt.len() > out_buf_max_len {
                return -4; // Buffer too small
            }
            std::ptr::copy_nonoverlapping(pt.as_ptr(), out_buf, pt.len());
            *out_len = pt.len();
            0
        }
        Err(_) => -5,
    }
}
