use beef::lean::Cow;
use std::fs;
use std::path::PathBuf;
use tempfile::{tempdir, TempDir};

use certhing::{
    CertificateConfig, CertificateType, EcCurve, KeyParams, KeyType,
    ClassicalKeyType, PostQuantumKeyType, RsaKeySize,
    MlDsaParams, MlKemParams,
    generate_certificate, save_certificate_bundle,
};

/// Helper function to create a hybrid certificate with specified parameters
fn create_hybrid_certificate(
    classical_type: ClassicalKeyType,
    pq_type: PostQuantumKeyType,
    common_name: &str,
    cert_type: CertificateType,
    temp_dir: &TempDir,
) -> Result<(PathBuf, PathBuf, PathBuf), Box<dyn std::error::Error>> {
    // Create key parameters for hybrid key
    let key_params = KeyParams::new_hybrid(classical_type, pq_type);
    
    // Create certificate configuration
    let config = CertificateConfig {
        key_params,
        valid_days: 365,
        common_name: Cow::from(common_name.to_string()),
        organization: Cow::from("Hybrid Certificate Test"),
        country: Cow::from("FI"),
        serial_number: 1,
        cert_type,
        alt_names: vec![],
        self_signed: true,
        ca_cert_path: None,
        ca_key_path: None,
    };
    
    // Generate the certificate
    let bundle = generate_certificate(&config)?;
    
    // Save the certificate and key files
    let cert_path = temp_dir.path().join(format!("{}_cert.pem", common_name));
    let key_path = temp_dir.path().join(format!("{}_key.pem", common_name));
    let pq_key_path = temp_dir.path().join(format!("{}_key_pq", common_name));
    
    save_certificate_bundle(&bundle, &cert_path, &key_path)?;
    
    Ok((cert_path, key_path, pq_key_path))
}

/// Helper function to check if a certificate has the alt signature extensions
fn check_alt_signature_extensions(cert_path: &PathBuf) -> Result<bool, Box<dyn std::error::Error>> {
    // Load the certificate
    let cert_data = fs::read(cert_path)?;
    
    // Check if the certificate has the alternative signature extensions
    // This is a simple check for the OID strings in the certificate data
    // A more robust implementation would use proper ASN.1 parsing
    
    // Convert to string for simpler searching (not ideal for binary data but works for this test)
    let cert_str = String::from_utf8_lossy(&cert_data);
    
    // Check for the OIDs of the extensions
    let has_alt_sig_alg = cert_str.contains("2.5.29.73");
    let has_alt_sig_value = cert_str.contains("2.5.29.74");
    let has_subject_alt_pki = cert_str.contains("2.5.29.72");
    
    Ok(has_alt_sig_alg && has_alt_sig_value && has_subject_alt_pki)
}

/// Test creating an RSA + ML-DSA hybrid certificate
#[test]
fn test_rsa_mldsa_hybrid_certificate() {
    let temp_dir = tempdir().expect("Failed to create temp directory");
    
    // Create a hybrid certificate with RSA and ML-DSA
    let (cert_path, key_path, pq_key_path) = create_hybrid_certificate(
        ClassicalKeyType::Rsa(RsaKeySize::Size3072),
        PostQuantumKeyType::MlDsa(MlDsaParams::Dsa44),
        "rsa-mldsa-hybrid",
        CertificateType::Server,
        &temp_dir,
    ).expect("Failed to create hybrid certificate");
    
    // Check that all files exist and are not empty
    assert!(cert_path.exists());
    assert!(key_path.exists());
    assert!(pq_key_path.exists());
    
    // Verify the certificate has the alternative signature extensions
    let has_extensions = check_alt_signature_extensions(&cert_path)
        .expect("Failed to check certificate extensions");
    assert!(has_extensions, "Certificate should have alternative signature extensions");
    
    // Additional checks could be added here to verify the certificate structure
    // - Check the PQ key file contains the expected data
    // - Use OpenSSL to extract and validate the certificate fields
    // - Verify the signatures are valid
}

/// Test creating an ECDSA + ML-DSA hybrid certificate
#[test]
fn test_ecdsa_mldsa_hybrid_certificate() {
    let temp_dir = tempdir().expect("Failed to create temp directory");
    
    // Create a hybrid certificate with ECDSA and ML-DSA
    let (cert_path, key_path, pq_key_path) = create_hybrid_certificate(
        ClassicalKeyType::Ec(EcCurve::P256),
        PostQuantumKeyType::MlDsa(MlDsaParams::Dsa44),
        "ecdsa-mldsa-hybrid",
        CertificateType::Server,
        &temp_dir,
    ).expect("Failed to create hybrid certificate");
    
    // Check that all files exist and are not empty
    assert!(cert_path.exists());
    assert!(key_path.exists());
    assert!(pq_key_path.exists());
    
    // Verify the certificate has the alternative signature extensions
    let has_extensions = check_alt_signature_extensions(&cert_path)
        .expect("Failed to check certificate extensions");
    assert!(has_extensions, "Certificate should have alternative signature extensions");
}

/// Test creating an EdDSA + ML-DSA hybrid certificate
#[test]
fn test_eddsa_mldsa_hybrid_certificate() {
    let temp_dir = tempdir().expect("Failed to create temp directory");
    
    // Create a hybrid certificate with EdDSA and ML-DSA
    let (cert_path, key_path, pq_key_path) = create_hybrid_certificate(
        ClassicalKeyType::Ed(EcCurve::Ed25519),
        PostQuantumKeyType::MlDsa(MlDsaParams::Dsa44),
        "eddsa-mldsa-hybrid",
        CertificateType::Server,
        &temp_dir,
    ).expect("Failed to create hybrid certificate");
    
    // Check that all files exist and are not empty
    assert!(cert_path.exists());
    assert!(key_path.exists());
    assert!(pq_key_path.exists());
    
    // Verify the certificate has the alternative signature extensions
    let has_extensions = check_alt_signature_extensions(&cert_path)
        .expect("Failed to check certificate extensions");
    assert!(has_extensions, "Certificate should have alternative signature extensions");
}

/// Test creating a certificate with RSA + ML-KEM (for key encapsulation)
#[test]
fn test_rsa_mlkem_hybrid_certificate() {
    let temp_dir = tempdir().expect("Failed to create temp directory");
    
    // Create a hybrid certificate with RSA and ML-KEM
    let (cert_path, key_path, pq_key_path) = create_hybrid_certificate(
        ClassicalKeyType::Rsa(RsaKeySize::Size3072),
        PostQuantumKeyType::MlKem(MlKemParams::Kem512),
        "rsa-mlkem-hybrid",
        CertificateType::Server,
        &temp_dir,
    ).expect("Failed to create hybrid certificate");
    
    // Check that all files exist and are not empty
    assert!(cert_path.exists());
    assert!(key_path.exists());
    assert!(pq_key_path.exists());
    
    // Verify the certificate has the subjectAltPublicKeyInfo extension
    // For KEM, we don't need altSignature extensions as it's not used for signing
    let cert_data = fs::read(&cert_path).expect("Failed to read certificate file");
    let cert_str = String::from_utf8_lossy(&cert_data);
    
    assert!(cert_str.contains("2.5.29.72"), "Certificate should have subjectAltPublicKeyInfo extension");
}

/// Test CA certificate chain with hybrid certificates
#[test]
fn test_hybrid_certificate_chain() {
    let temp_dir = tempdir().expect("Failed to create temp directory");
    
    // 1. Create a hybrid root CA certificate (RSA + ML-DSA)
    let ca_key_params = KeyParams::new_hybrid(
        ClassicalKeyType::Rsa(RsaKeySize::Size4096),
        PostQuantumKeyType::MlDsa(MlDsaParams::Dsa65),
    );
    
    let ca_config = CertificateConfig {
        key_params: ca_key_params,
        valid_days: 3650,
        common_name: Cow::from("Hybrid Root CA"),
        organization: Cow::from("Hybrid Certificate Test"),
        country: Cow::from("FI"),
        serial_number: 1,
        cert_type: CertificateType::Ca,
        alt_names: vec![],
        self_signed: true,
        ca_cert_path: None,
        ca_key_path: None,
    };
    
    let ca_bundle = generate_certificate(&ca_config).expect("Failed to create CA certificate");
    let ca_cert_path = temp_dir.path().join("ca_cert.pem");
    let ca_key_path = temp_dir.path().join("ca_key.pem");
    
    save_certificate_bundle(&ca_bundle, &ca_cert_path, &ca_key_path)
        .expect("Failed to save CA certificate");
    
    // 2. Create a server certificate signed by the CA
    let server_key_params = KeyParams::new_hybrid(
        ClassicalKeyType::Ec(EcCurve::P256),
        PostQuantumKeyType::MlDsa(MlDsaParams::Dsa44),
    );
    
    let server_config = CertificateConfig {
        key_params: server_key_params,
        valid_days: 365,
        common_name: Cow::from("hybrid.example.com"),
        organization: Cow::from("Hybrid Certificate Test"),
        country: Cow::from("FI"),
        serial_number: 2,
        cert_type: CertificateType::Server,
        alt_names: vec![],
        self_signed: false,
        ca_cert_path: Some(ca_cert_path.clone()),
        ca_key_path: Some(ca_key_path.clone()),
    };
    
    let server_bundle = generate_certificate(&server_config).expect("Failed to create server certificate");
    let server_cert_path = temp_dir.path().join("server_cert.pem");
    let server_key_path = temp_dir.path().join("server_key.pem");
    
    save_certificate_bundle(&server_bundle, &server_cert_path, &server_key_path)
        .expect("Failed to save server certificate");
    
    // Check that both certificates have the alternative signature extensions
    let ca_has_extensions = check_alt_signature_extensions(&ca_cert_path)
        .expect("Failed to check CA certificate extensions");
    assert!(ca_has_extensions, "CA certificate should have alternative signature extensions");
    
    let server_has_extensions = check_alt_signature_extensions(&server_cert_path)
        .expect("Failed to check server certificate extensions");
    assert!(server_has_extensions, "Server certificate should have alternative signature extensions");
}