#[cfg(feature = "python")]
use pyo3::prelude::*;
#[cfg(feature = "python")]
use pyo3::exceptions::PyValueError;
#[cfg(feature = "python")]
use pyo3::types::{PyDict, PyBytes};

#[cfg(feature = "python")]
use crate::envelope::{seal_envelope, open_seal_envelope, generate_hybrid_keypair_set, UXSPEnvelope, KeyPairSet};
#[cfg(feature = "python")]
use crate::crypto::bind_fields as rust_bind_fields;

#[cfg(feature = "python")]
#[pyfunction]
pub fn bind_fields_native<'py>(py: Python<'py>, fields: Vec<Vec<u8>>) -> PyResult<Bound<'py, PyBytes>> {
    let slices: Vec<&[u8]> = fields.iter().map(|f| f.as_slice()).collect();
    let res = rust_bind_fields(&slices);
    Ok(PyBytes::new_bound(py, &res))
}

#[cfg(feature = "python")]
#[pyfunction]
pub fn generate_hybrid_keypair_native<'py>(py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
    let keypair = generate_hybrid_keypair_set();
    let dict = PyDict::new_bound(py);

    let ex = PyDict::new_bound(py);
    ex.set_item("private_key", PyBytes::new_bound(py, &keypair.exchange_priv))?;
    ex.set_item("public_key", PyBytes::new_bound(py, &keypair.exchange_pub))?;
    dict.set_item("exchange", ex)?;

    let kem = PyDict::new_bound(py);
    kem.set_item("private_key", PyBytes::new_bound(py, &keypair.kem_priv))?;
    kem.set_item("public_key", PyBytes::new_bound(py, &keypair.kem_pub))?;
    dict.set_item("kem", kem)?;

    let sig = PyDict::new_bound(py);
    sig.set_item("private_key", PyBytes::new_bound(py, &keypair.signing_priv))?;
    sig.set_item("public_key", PyBytes::new_bound(py, &keypair.signing_pub))?;
    dict.set_item("signing", sig)?;

    let pqc = PyDict::new_bound(py);
    pqc.set_item("private_key", PyBytes::new_bound(py, &keypair.pqc_sig_priv))?;
    pqc.set_item("public_key", PyBytes::new_bound(py, &keypair.pqc_sig_pub))?;
    dict.set_item("pqc_sig", pqc)?;

    Ok(dict)
}

#[cfg(feature = "python")]
#[pyfunction]
pub fn seal_native(
    plaintext: &[u8],
    sender_signing_priv: &[u8],
    sender_pqc_sig_priv: &[u8],
    sender_exchange_priv: &[u8],
    sender_kem_priv: &[u8],
    recipient_exchange_pub: &[u8],
    recipient_kem_pub: &[u8],
    sender_id: &str,
    recipient_id: &str,
) -> PyResult<String> {
    let sender_keypair = KeyPairSet {
        exchange_priv: sender_exchange_priv.to_vec(),
        exchange_pub: vec![],
        kem_priv: sender_kem_priv.to_vec(),
        kem_pub: vec![],
        signing_priv: sender_signing_priv.to_vec(),
        signing_pub: vec![],
        pqc_sig_priv: sender_pqc_sig_priv.to_vec(),
        pqc_sig_pub: vec![],
    };

    let envelope = seal_envelope(
        plaintext,
        &sender_keypair,
        recipient_exchange_pub,
        recipient_kem_pub,
        sender_id,
        recipient_id,
        b"",
    ).map_err(|e| PyValueError::new_err(e))?;

    serde_json::to_string(&envelope).map_err(|e| PyValueError::new_err(e.to_string()))
}

#[cfg(feature = "python")]
#[pyfunction]
pub fn open_seal_native<'py>(
    py: Python<'py>,
    envelope_json: &str,
    recipient_exchange_priv: &[u8],
    recipient_kem_priv: &[u8],
    sender_signing_pub: &[u8],
    sender_pqc_sig_pub: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let envelope: UXSPEnvelope = serde_json::from_str(envelope_json)
        .map_err(|e| PyValueError::new_err(format!("Invalid envelope JSON: {}", e)))?;

    let recipient_keypair = KeyPairSet {
        exchange_priv: recipient_exchange_priv.to_vec(),
        exchange_pub: vec![],
        kem_priv: recipient_kem_priv.to_vec(),
        kem_pub: vec![],
        signing_priv: vec![],
        signing_pub: vec![],
        pqc_sig_priv: vec![],
        pqc_sig_pub: vec![],
    };

    let pt = open_seal_envelope(
        &envelope,
        &recipient_keypair,
        sender_signing_pub,
        sender_pqc_sig_pub,
        None,
        None,
        300,
        30,
        false,
        b"",
    ).map_err(|e| PyValueError::new_err(e))?;

    Ok(PyBytes::new_bound(py, &pt))
}

#[cfg(feature = "python")]
#[pymodule]
pub fn uxsp_core_native(_py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(bind_fields_native, m)?)?;
    m.add_function(wrap_pyfunction!(generate_hybrid_keypair_native, m)?)?;
    m.add_function(wrap_pyfunction!(seal_native, m)?)?;
    m.add_function(wrap_pyfunction!(open_seal_native, m)?)?;
    Ok(())
}
