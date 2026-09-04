use uxsp_core::envelope::{generate_hybrid_keypair_set, seal_envelope, open_seal_envelope};
use uxsp_core::ffi::{uxsp_generate_keypair_hex_c, uxsp_free_string, uxsp_seal_c, uxsp_open_seal_c};
use std::ffi::{CStr, CString};

#[test]
fn test_rust_envelope_seal_and_open() {
    let sender = generate_hybrid_keypair_set();
    let recipient = generate_hybrid_keypair_set();

    let plaintext = b"Hello, UXSP Multi-Language World!";
    let sender_id = "alice@service";
    let recipient_id = "bob@service";

    let envelope = seal_envelope(
        plaintext,
        &sender,
        &recipient.exchange_pub,
        &recipient.kem_pub,
        sender_id,
        recipient_id,
        b"",
    ).expect("Seal failed");

    assert_eq!(envelope.version, "UXSP-1");
    assert_eq!(envelope.sender_id, sender_id);
    assert_eq!(envelope.recipient_id, recipient_id);

    let decrypted = open_seal_envelope(
        &envelope,
        &recipient,
        &sender.signing_pub,
        &sender.pqc_sig_pub,
        Some(recipient_id),
        Some(sender_id),
        300,
        30,
        false,
        b"",
    ).expect("Open seal failed");

    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_c_ffi_seal_and_open() {
    unsafe {
        let sender_kp_c = uxsp_generate_keypair_hex_c();
        let rec_kp_c = uxsp_generate_keypair_hex_c();

        let sender_json = CStr::from_ptr(sender_kp_c).to_str().unwrap();
        let rec_json = CStr::from_ptr(rec_kp_c).to_str().unwrap();

        let sender: serde_json::Value = serde_json::from_str(sender_json).unwrap();
        let rec: serde_json::Value = serde_json::from_str(rec_json).unwrap();

        let plaintext = b"FFI Integration Test";
        let sender_id = CString::new("alice").unwrap();
        let recipient_id = CString::new("bob").unwrap();

        let sender_sig_priv = CString::new(sender["signing_priv"].as_str().unwrap()).unwrap();
        let sender_pqc_priv = CString::new(sender["pqc_sig_priv"].as_str().unwrap()).unwrap();
        let sender_ex_priv = CString::new(sender["exchange_priv"].as_str().unwrap()).unwrap();
        let sender_kem_priv = CString::new(sender["kem_priv"].as_str().unwrap()).unwrap();

        let rec_ex_pub = CString::new(rec["exchange_pub"].as_str().unwrap()).unwrap();
        let rec_kem_pub = CString::new(rec["kem_pub"].as_str().unwrap()).unwrap();

        let env_c = uxsp_seal_c(
            plaintext.as_ptr(),
            plaintext.len(),
            sender_sig_priv.as_ptr(),
            sender_pqc_priv.as_ptr(),
            sender_ex_priv.as_ptr(),
            sender_kem_priv.as_ptr(),
            rec_ex_pub.as_ptr(),
            rec_kem_pub.as_ptr(),
            sender_id.as_ptr(),
            recipient_id.as_ptr(),
        );

        assert!(!env_c.is_null());

        let rec_ex_priv = CString::new(rec["exchange_priv"].as_str().unwrap()).unwrap();
        let rec_kem_priv = CString::new(rec["kem_priv"].as_str().unwrap()).unwrap();

        let sender_sig_pub = CString::new(sender["signing_pub"].as_str().unwrap()).unwrap();
        let sender_pqc_pub = CString::new(sender["pqc_sig_pub"].as_str().unwrap()).unwrap();

        let mut out_buf = vec![0u8; 1024];
        let mut out_len: usize = 0;

        let res = uxsp_open_seal_c(
            env_c,
            rec_ex_priv.as_ptr(),
            rec_kem_priv.as_ptr(),
            sender_sig_pub.as_ptr(),
            sender_pqc_pub.as_ptr(),
            out_buf.as_mut_ptr(),
            out_buf.len(),
            &mut out_len,
        );

        assert_eq!(res, 0);
        assert_eq!(&out_buf[..out_len], plaintext);

        uxsp_free_string(sender_kp_c);
        uxsp_free_string(rec_kp_c);
        uxsp_free_string(env_c);
    }
}

#[test]
fn test_rust_envelope_validation_errors() {
    let sender = generate_hybrid_keypair_set();
    let recipient = generate_hybrid_keypair_set();
    let plaintext = b"Validation Test";

    let mut envelope = seal_envelope(
        plaintext,
        &sender,
        &recipient.exchange_pub,
        &recipient.kem_pub,
        "alice",
        "bob",
        b"",
    ).expect("Seal failed");

    // 1. Recipient mismatch
    let err_rec = open_seal_envelope(
        &envelope,
        &recipient,
        &sender.signing_pub,
        &sender.pqc_sig_pub,
        Some("charlie"), // Expected recipient is charlie, but envelope says bob
        Some("alice"),
        300,
        30,
        false,
        b"",
    );
    assert!(err_rec.is_err());

    // 2. Sender mismatch
    let err_sender = open_seal_envelope(
        &envelope,
        &recipient,
        &sender.signing_pub,
        &sender.pqc_sig_pub,
        Some("bob"),
        Some("charlie"), // Expected sender is charlie, but envelope says alice
        300,
        30,
        false,
        b"",
    );
    assert!(err_sender.is_err());

    // 3. Tampered ciphertext signature failure
    envelope.ciphertext = "00112233445566778899aabb".to_string();
    let err_sig = open_seal_envelope(
        &envelope,
        &recipient,
        &sender.signing_pub,
        &sender.pqc_sig_pub,
        Some("bob"),
        Some("alice"),
        300,
        30,
        false,
        b"",
    );
    assert!(err_sig.is_err());
}

