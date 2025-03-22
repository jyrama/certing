use openssl::{error::ErrorStack, pkey::PKey};
use openssl::ec::{EcGroup, EcKey};
use openssl::nid::Nid;
use openssl::pkey::Private;
use openssl::rsa::Rsa;
use openssl::x509::{X509, X509Name, X509NameBuilder};
use std::fs;
use std::io;
use std::path::Path;
use thiserror::Error;

use crate::{certificate, key_type, pq_crypto, hybrid_crypto};
use crate::pq_crypto::{PqKey, HybridKey};

/// Result of certificate generation process
#[derive(Debug)]
pub struct CertificateBundle {
    pub certificate: Vec<u8>,
    pub private_key: Vec<u8>,
    /// Optional post-quantum key for hybrid certificates
    pub pq_key: Option<PqKeyData>,
}

/// Data structure to hold serialized post-quantum key data
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct PqKeyData {
    pub key_type: key_type::KeyType,
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
    pub algorithm_name: String,
}

/// Errors that can occur during certificate generation
#[derive(Error, Debug)]
pub enum CertError {
    #[error("OpenSSL error: {0}")]
    OpenSsl(#[from] ErrorStack),

    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("Invalid parameter: {0}")]
    InvalidParameter(String),

    #[error("Unsupported key type: {0:?}")]
    UnsupportedKeyType(key_type::KeyType),

    #[error("Missing key parameters")]
    MissingKeyParameters,
    
    #[error("Post-quantum cryptography error: {0}")]
    PqCrypto(#[from] pq_crypto::PqCryptoError),
    
    #[error("Hybrid cryptography error: {0}")]
    HybridCrypto(#[from] hybrid_crypto::HybridCryptoError),
}

/// Generate a certificate and private key based on the provided configuration
pub fn generate_certificate(config: &certificate::CertificateConfig) -> Result<CertificateBundle, CertError> {
    // Validate inputs
    if config.valid_days == 0 {
        return Err(CertError::InvalidParameter(
            "Validity period must be greater than 0 days".into(),
        ));
    }

    // For CA-signed certificates, ensure CA cert and key paths are provided
    if !config.self_signed && (config.ca_cert_path.is_none() || config.ca_key_path.is_none()) {
        return Err(CertError::InvalidParameter(
            "CA certificate and key paths must be provided for CA-signed certificates".into(),
        ));
    }

    // Generate key pair based on key type
    if config.key_params.is_quantum_safe() {
        // For PQ and hybrid keys
        generate_pq_certificate(config)
    } else {
        // For classical keys (RSA, EC, Ed)
        generate_classical_certificate(config)
    }
}

/// Generate a certificate with a classical (non-quantum) key
fn generate_classical_certificate(config: &certificate::CertificateConfig) -> Result<CertificateBundle, CertError> {
    // Generate classical key pair
    let private_key = generate_classical_key(&config.key_params)?;

    // Build the X.509 name (subject and issuer)
    let name = build_x509_name(
        &config.common_name,
        &config.organization,
        &config.country,
    )?;

    // Create and configure the certificate
    let cert = if config.self_signed {
        certificate::build_certificate(
            &private_key,  // Self-sign with own private key
            &name,         // Self-sign with own name
            &name,
            config.valid_days,
            config.serial_number,
            config.cert_type,
            // &config.alt_names,
        )?
    } else {
        // Load CA certificate and private key
        let ca_cert_pem = fs::read(config.ca_cert_path.as_ref().unwrap())?;
        let ca_key_pem = fs::read(config.ca_key_path.as_ref().unwrap())?;

        let ca_cert = X509::from_pem(&ca_cert_pem)?;
        let ca_key = PKey::private_key_from_pem(&ca_key_pem)?;

        // Build certificate and sign with CA key
        certificate::build_certificate(
            &private_key,  // Certificate's public key
            ca_cert.subject_name(), // CA's subject as issuer
            &name,         // Our own subject name
            config.valid_days,
            config.serial_number,
            config.cert_type,
            // &config.alt_names,
        )?
    };

    // Convert to PEM format
    let cert_pem = cert.to_pem()?;
    let key_pem = private_key.private_key_to_pem_pkcs8()?;

    Ok(CertificateBundle {
        certificate: cert_pem,
        private_key: key_pem,
        pq_key: None,  // No PQ key for classical certificates
    })
}

/// Generate a certificate with a post-quantum or hybrid key
fn generate_pq_certificate(config: &certificate::CertificateConfig) -> Result<CertificateBundle, CertError> {
    match config.key_params.key_type {
        key_type::KeyType::MlKem | key_type::KeyType::MlDsa | key_type::KeyType::SlhDsa => {
            // Generate pure post-quantum certificate
            // This is a placeholder - purely post-quantum certificates are not fully standardized yet
            Err(CertError::UnsupportedKeyType(config.key_params.key_type))
        },
        key_type::KeyType::Hybrid => {
            // Generate hybrid certificate (classical + post-quantum)
            generate_hybrid_certificate(config)
        },
        _ => Err(CertError::UnsupportedKeyType(config.key_params.key_type)),
    }
}

/// Generate a certificate with a hybrid key (classical + post-quantum)
fn generate_hybrid_certificate(config: &certificate::CertificateConfig) -> Result<CertificateBundle, CertError> {
    // Generate a hybrid key
    let hybrid_key = hybrid_crypto::generate_complete_hybrid_key(&config.key_params)?;
    
    // Build the X.509 name (subject and issuer)
    let name = build_x509_name(
        &config.common_name,
        &config.organization,
        &config.country,
    )?;

    // Create and configure the certificate
    let mut cert = if config.self_signed {
        certificate::build_certificate(
            &hybrid_key.classical_key,  // Sign with classical key (PQ part is in extension)
            &name,                      // Self-sign with own name
            &name,
            config.valid_days,
            config.serial_number,
            config.cert_type,
            // &config.alt_names,
        )?
    } else {
        // Load CA certificate and private key
        let ca_cert_pem = fs::read(config.ca_cert_path.as_ref().unwrap())?;
        let ca_key_pem = fs::read(config.ca_key_path.as_ref().unwrap())?;

        let ca_cert = X509::from_pem(&ca_cert_pem)?;
        let ca_key = PKey::private_key_from_pem(&ca_key_pem)?;

        // Build certificate and sign with CA key
        certificate::build_certificate(
            &hybrid_key.classical_key,  // Certificate's classical public key
            ca_cert.subject_name(),     // CA's subject as issuer
            &name,                      // Our own subject name
            config.valid_days,
            config.serial_number,
            config.cert_type,
            // &config.alt_names,
        )?
    };

    // Add post-quantum public key as an extension to the certificate
    // (This is a placeholder - the exact format would depend on standards)
    pq_crypto::encode_hybrid_public_key_extensions(&mut cert, &hybrid_key)?;

    // Convert to PEM format
    let cert_pem = cert.to_pem()?;
    let key_pem = hybrid_key.classical_key.private_key_to_pem_pkcs8()?;
    
    // Create a PqKeyData structure to store the PQ key
    let pq_key_data = extract_pq_key_data(&hybrid_key)?;

    Ok(CertificateBundle {
        certificate: cert_pem,
        private_key: key_pem,
        pq_key: Some(pq_key_data),
    })
}

/// Extract serialized key data from a PqKey
fn extract_pq_key_data(hybrid_key: &HybridKey) -> Result<PqKeyData, CertError> {
    match &hybrid_key.pq_key {
        PqKey::MlKem { algorithm, public_key, secret_key } => {
            Ok(PqKeyData {
                key_type: key_type::KeyType::MlKem,
                public_key: public_key.as_ref().to_vec(),
                secret_key: secret_key.as_ref().to_vec(),
                algorithm_name: format!("{:?}", algorithm),
            })
        },
        PqKey::MlDsa { algorithm, public_key, secret_key } => {
            Ok(PqKeyData {
                key_type: key_type::KeyType::MlDsa,
                public_key: public_key.as_ref().to_vec(),
                secret_key: secret_key.as_ref().to_vec(),
                algorithm_name: format!("{:?}", algorithm),
            })
        },
        PqKey::SlhDsa { algorithm, public_key, secret_key } => {
            Ok(PqKeyData {
                key_type: key_type::KeyType::SlhDsa,
                public_key: public_key.as_ref().to_vec(),
                secret_key: secret_key.as_ref().to_vec(),
                algorithm_name: format!("{:?}", algorithm),
            })
        },
    }
}

/// Generate a private key based on key parameters
fn generate_classical_key(params: &key_type::KeyParams) -> Result<PKey<Private>, CertError> {
    match params.key_type {
        key_type::KeyType::Rsa => {
            // Check if RSA key size is specified
            let rsa_size = params.rsa_size.ok_or(CertError::MissingKeyParameters)?;

            // Generate RSA key
            let rsa = Rsa::generate(rsa_size.bits())?;
            let private_key = PKey::from_rsa(rsa)?;
            Ok(private_key)
        },
        key_type::KeyType::Ec => {
            // Check if EC curve is specified
            let curve = params.ec_curve.ok_or(CertError::MissingKeyParameters)?;

            // For standard NIST curves, use the EcGroup method
            let nid = curve.to_nid().ok_or_else(|| {
                CertError::InvalidParameter(format!("Invalid NIST curve: {:?}", curve))
            })?;

            // Create the EC group and key
            let group = EcGroup::from_curve_name(nid)?;
            let ec_key = EcKey::generate(&group)?;
            let private_key = PKey::from_ec_key(ec_key)?;
            Ok(private_key)
        },
        key_type::KeyType::Ed => {
            // Check if Edwards curve is specified
            let curve = params.ec_curve.ok_or(CertError::MissingKeyParameters)?;

            // Direct generation for Edwards curves - no NIDs needed
            match curve {
                crate::ec_specs::EcCurve::Ed25519 => {
                    // Generate Ed25519 key
                    let private_key = PKey::generate_ed25519()?;
                    Ok(private_key)
                },
                crate::ec_specs::EcCurve::Ed448 => {
                    // Generate Ed448 key
                    let private_key = PKey::generate_ed448()?;
                    Ok(private_key)
                },
                _ => {
                    Err(CertError::InvalidParameter(format!(
                        "Edwards curve type expected, got {:?}", curve
                    )))
                }
            }
        },
        _ => Err(CertError::UnsupportedKeyType(params.key_type)),
    }
}

/// Build an X.509 name with common name, organization, and country
fn build_x509_name(
    common_name: &str,
    organization: &str,
    country: &str,
) -> Result<X509Name, ErrorStack> {
    let mut builder = X509NameBuilder::new()?;
    builder.append_entry_by_nid(Nid::COMMONNAME, common_name)?;
    builder.append_entry_by_nid(Nid::ORGANIZATIONNAME, organization)?;
    builder.append_entry_by_nid(Nid::COUNTRYNAME, country)?;
    Ok(builder.build())
}

/// Save a certificate bundle to the specified output directory
pub fn save_certificate_bundle(
    bundle: &CertificateBundle,
    cert_path: impl AsRef<Path>,
    key_path: impl AsRef<Path>,
) -> io::Result<()> {
    fs::write(&cert_path, &bundle.certificate)?;
    fs::write(&key_path, &bundle.private_key)?;
    
    // If there's a PQ key, also save it
    if let Some(pq_key) = &bundle.pq_key {
        let pq_key_path = format!("{}_pq", key_path.as_ref().display());

        let pq_key_data = bincode::serde::encode_to_vec(pq_key, bincode::config::standard())
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        fs::write(pq_key_path, pq_key_data)?;
    }
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use beef::lean::Cow;

    use crate::certificate::CertificateConfig;
    use crate::ec_specs::EcCurve;
    use crate::key_type::{KeyParams, ClassicalKeyType, PostQuantumKeyType};
    use crate::ml_kem_specs::MlKemParams;
    

    use super::*;

    #[test]
    fn test_rsa_certificate_generation() {
        let config = CertificateConfig {
            common_name: Cow::from("test.example.com"),
            organization: Cow::from("Test Org"),
            ..Default::default()
        };

        let result = generate_certificate(&config);
        assert!(result.is_ok());

        let bundle = result.unwrap();
        assert!(!bundle.certificate.is_empty());
        assert!(!bundle.private_key.is_empty());
        assert!(bundle.pq_key.is_none());

        // Test saving to files
        let temp_dir = tempfile::TempDir::new().unwrap();
        let cert_path = temp_dir.path().join("cert.pem");
        let key_path = temp_dir.path().join("key.pem");

        let save_result = save_certificate_bundle(&bundle, &cert_path, &key_path);
        assert!(save_result.is_ok());
        assert!(cert_path.exists());
        assert!(key_path.exists());
    }

    #[test]
    fn test_ec_certificate_generation() {
        let mut config = CertificateConfig {
            common_name: Cow::from("ec.example.com"),
            organization: Cow::from("EC Test Org"),
            ..Default::default()
        };

        // Set EC P-256 key parameters
        config.key_params = KeyParams::new_ec(EcCurve::P256);

        let result = generate_certificate(&config);
        assert!(result.is_ok());

        let bundle = result.unwrap();
        assert!(!bundle.certificate.is_empty());
        assert!(!bundle.private_key.is_empty());
        assert!(bundle.pq_key.is_none());
    }

    #[test]
    fn test_ed25519_certificate_generation() {
        let mut config = CertificateConfig {
            common_name: Cow::from("ed25519.example.com"),
            organization: Cow::from("EdDSA Test Org"),
            ..Default::default()
        };

        // Set Ed25519 key parameters
        config.key_params = KeyParams::new_ec(EcCurve::Ed25519);

        let result = generate_certificate(&config);
        assert!(result.is_ok());

        let bundle = result.unwrap();
        assert!(!bundle.certificate.is_empty());
        assert!(!bundle.private_key.is_empty());
        assert!(bundle.pq_key.is_none());
    }
    
    #[test]
    fn test_hybrid_certificate_generation() {
        let mut config = CertificateConfig {
            common_name: Cow::from("hybrid.example.com"),
            organization: Cow::from("Hybrid Test Org"),
            ..Default::default()
        };

        // Set hybrid key parameters (RSA + ML-KEM)
        config.key_params = KeyParams::new_hybrid(
            ClassicalKeyType::Rsa(crate::rsa_specs::RsaKeySize::Size3072),
            PostQuantumKeyType::MlKem(MlKemParams::Kem512)
        );

        // Skip this test for now as hybrid certificate generation still needs to be implemented
        let result = generate_certificate(&config);
        assert!(result.is_ok());
        
        let bundle = result.unwrap();
        assert!(!bundle.certificate.is_empty());
        assert!(!bundle.private_key.is_empty());
        assert!(bundle.pq_key.is_some());
    }
}