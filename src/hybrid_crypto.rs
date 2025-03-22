use openssl::pkey::{PKey, Private};
use openssl::hash::MessageDigest;
use openssl::x509::{X509, X509Builder};
use thiserror::Error;

use crate::key_type::{KeyParams, KeyType, ClassicalKeyType, PostQuantumKeyType, HybridConfig};
use crate::pq_crypto::{PqCryptoError, generate_pq_key, generate_hybrid_key, HybridKey, PqKey};

/// Errors that can occur during hybrid cryptography operations
#[derive(Error, Debug)]
pub enum HybridCryptoError {
    #[error("OpenSSL error: {0}")]
    OpenSsl(#[from] openssl::error::ErrorStack),

    #[error("Post-quantum crypto error: {0}")]
    PqCrypto(#[from] PqCryptoError),

    #[error("Missing parameters for hybrid key generation")]
    MissingParameters,

    #[error("Invalid key type for hybrid operation")]
    InvalidKeyType,
}

/// Generate both parts of a hybrid key (classical and post-quantum)
/// This function handles the coordination of generating both parts of the key
pub fn generate_complete_hybrid_key(key_params: &KeyParams) -> Result<HybridKey, HybridCryptoError> {
    if key_params.key_type != KeyType::Hybrid {
        return Err(HybridCryptoError::InvalidKeyType);
    }

    let hybrid_config = key_params.hybrid_config
        .ok_or(HybridCryptoError::MissingParameters)?;

    // Generate the classical key
    let classical_key = generate_classical_key(hybrid_config)?;

    // Generate the post-quantum key
    let pq_params = match hybrid_config.pq_type {
        PostQuantumKeyType::MlKem(params) => {
            KeyParams {
                key_type: KeyType::MlKem,
                ml_kem_params: Some(params),
                ..Default::default()
            }
        },
        PostQuantumKeyType::MlDsa(params) => {
            KeyParams {
                key_type: KeyType::MlDsa,
                ml_dsa_params: Some(params),
                ..Default::default()
            }
        },
        PostQuantumKeyType::SlhDsa(params) => {
            KeyParams {
                key_type: KeyType::SlhDsa,
                slh_dsa_params: Some(params),
                ..Default::default()
            }
        },
    };

    let pq_key = generate_pq_key(&pq_params)?;

    // Combine the keys into a hybrid key
    generate_hybrid_key(classical_key, pq_key)
        .map_err(HybridCryptoError::PqCrypto)
}

/// Generate just the classical part of a hybrid key
fn generate_classical_key(hybrid_config: HybridConfig) -> Result<PKey<Private>, HybridCryptoError> {
    use openssl::rsa::Rsa;
    use openssl::ec::{EcGroup, EcKey};
    

    match hybrid_config.classical_type {
        ClassicalKeyType::Rsa(size) => {
            let rsa = Rsa::generate(size.bits())
                .map_err(HybridCryptoError::OpenSsl)?;
            PKey::from_rsa(rsa)
                .map_err(HybridCryptoError::OpenSsl)
        },
        ClassicalKeyType::Ec(curve) => {
            // For standard NIST curves
            let nid = curve.to_nid()
                .ok_or_else(|| HybridCryptoError::InvalidKeyType)?;
            let group = EcGroup::from_curve_name(nid)
                .map_err(HybridCryptoError::OpenSsl)?;
            let ec_key = EcKey::generate(&group)
                .map_err(HybridCryptoError::OpenSsl)?;
            PKey::from_ec_key(ec_key)
                .map_err(HybridCryptoError::OpenSsl)
        },
        ClassicalKeyType::Ed(curve) => {
            match curve {
                crate::ec_specs::EcCurve::Ed25519 => {
                    PKey::generate_ed25519()
                        .map_err(HybridCryptoError::OpenSsl)
                },
                crate::ec_specs::EcCurve::Ed448 => {
                    PKey::generate_ed448()
                        .map_err(HybridCryptoError::OpenSsl)
                },
                _ => {
                    Err(HybridCryptoError::InvalidKeyType)
                }
            }
        },
    }
}

/// Create X.509 extensions for a hybrid certificate
/// This encodes both the classical and PQ keys in the certificate
pub fn create_hybrid_certificate_extensions(
    cert: &mut X509,
    hybrid_key: &HybridKey
) -> Result<(), HybridCryptoError> {
    // Add the PQ public key as a subjectAltPublicKeyInfo extension
    crate::pq_crypto::encode_hybrid_public_key_extensions(cert, hybrid_key)
        .map_err(HybridCryptoError::PqCrypto)?;
    
    Ok(())
}

/// Generate a dual-signature hybrid certificate
/// 
/// This combines the capabilities of:
/// 1. Classical crypto (through OpenSSL)
/// 2. Post-quantum crypto (through liboqs/OQS)
/// 
/// The certificate will have:
/// - Classical signature in the standard X.509 signature field
/// - PQ signature in the altSignatureValue extension
/// - PQ algorithm in the altSignatureAlgorithm extension
/// - PQ public key in the subjectAltPublicKeyInfo extension
pub fn generate_dual_signature_certificate(
    tbs_cert: &X509,
    hybrid_key: &HybridKey,
    classical_digest: MessageDigest
) -> Result<X509, HybridCryptoError> {
    use crate::dual_signature::{sign_certificate_dual, DualSignatureError};
    
    // Create a certificate with dual signatures (classical + PQ)
    match sign_certificate_dual(
        tbs_cert,
        &hybrid_key.classical_key,
        classical_digest,
        &hybrid_key.pq_key
    ) {
        Ok(cert) => Ok(cert),
        Err(DualSignatureError::OpenSsl(e)) => Err(HybridCryptoError::OpenSsl(e)),
        Err(DualSignatureError::PqCrypto(e)) => Err(HybridCryptoError::PqCrypto(e)),
        Err(e) => Err(HybridCryptoError::InvalidKeyType),
    }
}

/// Verify a dual-signature hybrid certificate
pub fn verify_dual_signature_certificate(
    cert: &X509,
    issuer_cert: Option<&X509>,
    verify_classical: bool,
    verify_pq: bool
) -> Result<bool, HybridCryptoError> {
    use crate::dual_signature::{verify_hybrid_certificate, DualSignatureError};
    
    // Verify both signatures according to the X.509 standard rules
    match verify_hybrid_certificate(cert, issuer_cert, verify_classical, verify_pq) {
        Ok(valid) => Ok(valid),
        Err(DualSignatureError::OpenSsl(e)) => Err(HybridCryptoError::OpenSsl(e)),
        Err(DualSignatureError::PqCrypto(e)) => Err(HybridCryptoError::PqCrypto(e)),
        Err(_) => Err(HybridCryptoError::InvalidKeyType),
    }
}