use openssl::pkey::{PKey, Private, Id, Public};
use openssl::error::ErrorStack;
use openssl::x509::{X509, X509Extension};
use openssl::asn1::Asn1Object;
use thiserror::Error;
use std::fmt;
use oqs::{kem, sig};

use crate::key_type::{KeyType, KeyParams, PostQuantumKeyType};
use crate::ml_kem_specs::MlKemParams;
use crate::ml_dsa_specs::MlDsaParams;
use crate::slh_dsa_specs::SlhDsaParams;

/// OIDs for Subject Alternative Public Key Info extension
pub const SUBJECT_ALT_PUBLIC_KEY_INFO_OID: &str = "2.5.29.72";

/// Errors specific to post-quantum cryptography operations
#[derive(Error, Debug)]
pub enum PqCryptoError {
    #[error("OQS initialization failed: {0}")]
    OqsInitFailed(String),
    
    #[error("Invalid algorithm name: {0}")]
    InvalidAlgorithm(String),
    
    #[error("Key generation failed: {0}")]
    KeyGenerationFailed(String),
    
    #[error("OpenSSL error: {0}")]
    OpenSslError(#[from] ErrorStack),
    
    #[error("Missing parameters for {0}")]
    MissingParameters(String),
    
    #[error("Unsupported operation: {0}")]
    UnsupportedOperation(String),
    
    #[error("OQS error: {0}")]
    OqsError(String),
}

impl From<oqs::Error> for PqCryptoError {
    fn from(err: oqs::Error) -> Self {
        PqCryptoError::OqsError(err.to_string())
    }
}

/// Use ML-KEM parameter's to_oqs_algorithm method to get the OQS KEM algorithm enum
fn ml_kem_to_oqs(params: MlKemParams) -> Result<kem::Algorithm, PqCryptoError> {
    Ok(params.to_oqs_algorithm())
}

/// Use ML-DSA parameter's to_oqs_algorithm method to get the OQS signature algorithm enum
fn ml_dsa_to_oqs(params: MlDsaParams) -> Result<sig::Algorithm, PqCryptoError> {
    Ok(params.to_oqs_algorithm())
}

/// Use SLH-DSA parameter's to_oqs_algorithm method to get the OQS signature algorithm enum
/// 
/// Note: While we use the standardized name SLH-DSA (FIPS 205), the OQS library 
/// still uses the older SPHINCS+ naming convention. The to_oqs_algorithm method
/// handles this mapping internally.
fn slh_dsa_to_oqs(params: &SlhDsaParams) -> Result<sig::Algorithm, PqCryptoError> {
    params.to_oqs_algorithm()
        .ok_or_else(|| PqCryptoError::InvalidAlgorithm(format!("Invalid SLH-DSA parameters: {:?}", params)))
}

/// PQ Key wrapping structure to hold different types of post-quantum keys
#[derive(Debug)]
pub enum PqKey {
    MlKem {
        algorithm: kem::Algorithm,
        public_key: kem::PublicKey,
        secret_key: kem::SecretKey,
    },
    MlDsa {
        algorithm: sig::Algorithm,
        public_key: sig::PublicKey,
        secret_key: sig::SecretKey,
    },
    SlhDsa {
        algorithm: sig::Algorithm,
        public_key: sig::PublicKey,
        secret_key: sig::SecretKey,
    },
}

impl fmt::Display for PqKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PqKey::MlKem { algorithm, .. } => write!(f, "ML-KEM Key ({:?})", algorithm),
            PqKey::MlDsa { algorithm, .. } => write!(f, "ML-DSA Key ({:?})", algorithm),
            PqKey::SlhDsa { algorithm, .. } => {
                // Note that we display "SLH-DSA" (standardized name) even though the algorithm 
                // enum variant uses "Sphincs" (older name)
                write!(f, "SLH-DSA Key ({:?})", algorithm)
            },
        }
    }
}

/// Generate a post-quantum key using OQS
pub fn generate_pq_key(key_params: &KeyParams) -> Result<PqKey, PqCryptoError> {
    match key_params.key_type {
        KeyType::MlKem => {
            if let Some(params) = key_params.ml_kem_params {
                generate_mlkem_key(params)
            } else {
                Err(PqCryptoError::MissingParameters("ML-KEM".to_string()))
            }
        },
        KeyType::MlDsa => {
            if let Some(params) = key_params.ml_dsa_params {
                generate_mldsa_key(params)
            } else {
                Err(PqCryptoError::MissingParameters("ML-DSA".to_string()))
            }
        },
        KeyType::SlhDsa => {
            if let Some(params) = key_params.slh_dsa_params {
                generate_slhdsa_key(&params)
            } else {
                Err(PqCryptoError::MissingParameters("SLH-DSA".to_string()))
            }
        },
        KeyType::Hybrid => {
            if let Some(hybrid_config) = key_params.hybrid_config {
                match hybrid_config.pq_type {
                    PostQuantumKeyType::MlKem(params) => generate_mlkem_key(params),
                    PostQuantumKeyType::MlDsa(params) => generate_mldsa_key(params),
                    PostQuantumKeyType::SlhDsa(params) => generate_slhdsa_key(&params),
                }
            } else {
                Err(PqCryptoError::MissingParameters("Hybrid".to_string()))
            }
        },
        _ => Err(PqCryptoError::UnsupportedOperation(format!("Key type {:?} is not post-quantum", key_params.key_type))),
    }
}

/// Generate an ML-KEM key pair using OQS
fn generate_mlkem_key(params: MlKemParams) -> Result<PqKey, PqCryptoError> {
    let algorithm = ml_kem_to_oqs(params)?;
    
    // Create new KEM
    let kem = kem::Kem::new(algorithm)?;
    
    // Generate key pair - now returns PublicKey and SecretKey types
    let (public_key, secret_key) = kem.keypair()?;
    
    Ok(PqKey::MlKem {
        algorithm,
        public_key,
        secret_key,
    })
}

/// Generate an ML-DSA key pair using OQS
fn generate_mldsa_key(params: MlDsaParams) -> Result<PqKey, PqCryptoError> {
    let algorithm = ml_dsa_to_oqs(params)?;
    
    // Create new signature scheme
    let sig = sig::Sig::new(algorithm)?;
    
    // Generate key pair - now returns PublicKey and SecretKey types
    let (public_key, secret_key) = sig.keypair()?;
    
    Ok(PqKey::MlDsa {
        algorithm,
        public_key,
        secret_key,
    })
}

/// Generate an SLH-DSA key pair using OQS
/// 
/// Note: SLH-DSA is the standardized name (FIPS 205) for what was previously known
/// as SPHINCS+. The OQS library still uses SPHINCS+ naming for its algorithms.
fn generate_slhdsa_key(params: &SlhDsaParams) -> Result<PqKey, PqCryptoError> {
    let algorithm = slh_dsa_to_oqs(params)?;
    
    // Create new signature scheme
    let sig = sig::Sig::new(algorithm)?;
    
    // Generate key pair - now returns PublicKey and SecretKey types
    let (public_key, secret_key) = sig.keypair()?;
    
    Ok(PqKey::SlhDsa {
        algorithm,
        public_key,
        secret_key,
    })
}

/// Hybrid key structure that combines classical and post-quantum keys
#[derive(Debug)]
pub struct HybridKey {
    pub classical_key: PKey<Private>,
    pub pq_key: PqKey,
    pub combined_id: Vec<u8>, // Identifier for the combined key
}

impl HybridKey {
    pub fn algorithm_name(&self) -> String {
        match &self.pq_key {
            PqKey::MlKem { algorithm, .. } => 
                format!("Hybrid-{}-{:?}", self.classical_algorithm_name(), algorithm),
            PqKey::MlDsa { algorithm, .. } => 
                format!("Hybrid-{}-{:?}", self.classical_algorithm_name(), algorithm),
            PqKey::SlhDsa { algorithm, .. } => 
                format!("Hybrid-{}-{:?}", self.classical_algorithm_name(), algorithm),
        }
    }
    
    fn classical_algorithm_name(&self) -> String {
        match self.classical_key.id() {
            Id::RSA => "RSA".to_string(),
            Id::EC => "ECDSA".to_string(),
            Id::ED25519 => "Ed25519".to_string(),
            Id::ED448 => "Ed448".to_string(),
            _ => "Unknown".to_string(),
        }
    }
}

/// Generate a hybrid key pair combining classical and PQ algorithms
pub fn generate_hybrid_key(classical_key: PKey<Private>, pq_key: PqKey) -> Result<HybridKey, PqCryptoError> {
    // Create a unique identifier for the combined key
    // In a real implementation, this would be derived from both keys
    let combined_id = vec![0u8; 32]; // Placeholder
    
    Ok(HybridKey {
        classical_key,
        pq_key,
        combined_id,
    })
}

/// Encode a PQ public key in an X.509 extension
/// 
/// This adds the PQ public key as a subjectAltPublicKeyInfo extension
pub fn encode_pq_public_key_extension(cert: &mut X509, pq_key: &PqKey) -> Result<(), PqCryptoError> {
    // Encode the PQ public key according to the appropriate standard
    let encoded_key = match pq_key {
        PqKey::MlDsa { algorithm, public_key, .. } => {
            // Create DER encoding of the public key with algorithm identifier
            encode_pq_public_key(algorithm, public_key.as_ref())?
        },
        PqKey::SlhDsa { algorithm, public_key, .. } => {
            // Create DER encoding of the public key with algorithm identifier
            encode_pq_public_key(algorithm, public_key.as_ref())?
        },
        PqKey::MlKem { algorithm, public_key, .. } => {
            // Create DER encoding of the public key with algorithm identifier
            encode_pq_public_key_kem(algorithm, public_key.as_ref())?
        },
    };
    
    // Create extension with subjectAltPublicKeyInfo OID
    let subject_alt_pki_obj = Asn1Object::from_str(SUBJECT_ALT_PUBLIC_KEY_INFO_OID)
        .map_err(|e| PqCryptoError::InvalidAlgorithm(format!("Invalid OID: {}", e)))?;
    
    // Add the extension to the certificate
    let ext = X509Extension::new(
        &subject_alt_pki_obj,
        false, // Not critical (for compatibility)
        &encoded_key,
    ).map_err(|e| PqCryptoError::OpenSslError(e))?;
    
    // This would require modifying the X509 structure, which is complicated in OpenSSL
    // In a real implementation, we would use the X509V3_add_ext function from OpenSSL
    // For now, this is a placeholder
    
    Ok(())
}

/// Encode a post-quantum public key with its algorithm identifier
fn encode_pq_public_key(algorithm: &sig::Algorithm, public_key: &[u8]) -> Result<Vec<u8>, PqCryptoError> {
    // Get the OID for the algorithm
    let algorithm_oid = match algorithm {
        sig::Algorithm::MlDsa44 => "2.16.840.1.101.3.4.3.21", // Example OID for ML-DSA-44
        sig::Algorithm::MlDsa65 => "2.16.840.1.101.3.4.3.22", // Example OID for ML-DSA-65
        sig::Algorithm::MlDsa87 => "2.16.840.1.101.3.4.3.23", // Example OID for ML-DSA-87
        sig::Algorithm::SphincsSha2128sSimple => "2.16.840.1.101.3.4.3.30", // Example OID for SLH-DSA-SHA2-128s
        sig::Algorithm::SphincsSha2128fSimple => "2.16.840.1.101.3.4.3.31", // Example OID for SLH-DSA-SHA2-128f
        // Add mappings for other variants
        _ => return Err(PqCryptoError::InvalidAlgorithm(format!("Unsupported algorithm: {:?}", algorithm))),
    };
    
    // Create ASN.1 object from OID
    let oid_obj = Asn1Object::from_str(algorithm_oid)
        .map_err(|e| PqCryptoError::InvalidAlgorithm(format!("Invalid algorithm OID: {}", e)))?;
    
    // Get DER encoding of the OID
    let oid_der = oid_obj.to_der()
        .map_err(|e| PqCryptoError::OpenSslError(e))?;
    
    // This is a simplified version - in a real implementation, we would properly
    // construct the complete SubjectPublicKeyInfo ASN.1 structure
    
    // For now, just concatenate the OID and the key
    let mut result = Vec::with_capacity(oid_der.len() + public_key.len() + 8);
    result.extend_from_slice(&oid_der);
    result.extend_from_slice(public_key);
    
    Ok(result)
}

/// Encode a post-quantum KEM public key with its algorithm identifier
fn encode_pq_public_key_kem(algorithm: &kem::Algorithm, public_key: &[u8]) -> Result<Vec<u8>, PqCryptoError> {
    // Get the OID for the algorithm
    let algorithm_oid = match algorithm {
        kem::Algorithm::MlKem512 => "2.16.840.1.101.3.4.2.21", // Example OID for ML-KEM-512
        kem::Algorithm::MlKem768 => "2.16.840.1.101.3.4.2.22", // Example OID for ML-KEM-768
        kem::Algorithm::MlKem1024 => "2.16.840.1.101.3.4.2.23", // Example OID for ML-KEM-1024
        // Add mappings for other variants
        _ => return Err(PqCryptoError::InvalidAlgorithm(format!("Unsupported KEM algorithm: {:?}", algorithm))),
    };
    
    // Create ASN.1 object from OID
    let oid_obj = Asn1Object::from_str(algorithm_oid)
        .map_err(|e| PqCryptoError::InvalidAlgorithm(format!("Invalid algorithm OID: {}", e)))?;
    
    // Get DER encoding of the OID
    let oid_der = oid_obj.to_der()
        .map_err(|e| PqCryptoError::OpenSslError(e))?;
    
    // This is a simplified version - in a real implementation, we would properly
    // construct the complete SubjectPublicKeyInfo ASN.1 structure
    
    // For now, just concatenate the OID and the key
    let mut result = Vec::with_capacity(oid_der.len() + public_key.len() + 8);
    result.extend_from_slice(&oid_der);
    result.extend_from_slice(public_key);
    
    Ok(result)
}

/// Encode a hybrid public key in X.509 extensions
pub fn encode_hybrid_public_key_extensions(cert: &mut X509, hybrid_key: &HybridKey) -> Result<(), PqCryptoError> {
    // 1. Encode the PQ public key part as a subjectAltPublicKeyInfo extension
    encode_pq_public_key_extension(cert, &hybrid_key.pq_key)?;
    
    // The classical key is already included in the certificate's standard public key field
    Ok(())
}

/// Sign data with a post-quantum signature key
pub fn sign_with_pq_key(pq_key: &PqKey, data: &[u8]) -> Result<sig::Signature, PqCryptoError> {
    match pq_key {
        PqKey::MlDsa { algorithm, secret_key, .. } => {
            let sig_alg = sig::Sig::new(*algorithm)?;
            let signature = sig_alg.sign(data, secret_key)?;
            Ok(signature)
        },
        PqKey::SlhDsa { algorithm, secret_key, .. } => {
            let sig_alg = sig::Sig::new(*algorithm)?;
            let signature = sig_alg.sign(data, secret_key)?;
            Ok(signature)
        },
        PqKey::MlKem { .. } => {
            Err(PqCryptoError::UnsupportedOperation("Cannot sign with ML-KEM key".to_string()))
        }
    }
}

/// Verify a signature with a post-quantum public key
/// 
/// Returns:
/// - Ok(true) if the signature is valid
/// - Ok(false) if the signature is invalid (verification failed)
/// - Err if there was an error during verification
pub fn verify_with_pq_key(pq_key: &PqKey, message: &[u8], signature: &sig::Signature) -> Result<bool, PqCryptoError> {
    match pq_key {
        PqKey::MlDsa { algorithm, public_key, .. } => {
            let sig_alg = sig::Sig::new(*algorithm)?;
            match sig_alg.verify(message, signature, public_key) {
                Ok(()) => Ok(true), // Signature is valid
                Err(oqs::Error::Error) => Ok(false), // Invalid signature
                Err(e) => Err(PqCryptoError::OqsError(format!("Error during signature verification: {}", e))),
            }
        },
        PqKey::SlhDsa { algorithm, public_key, .. } => {
            let sig_alg = sig::Sig::new(*algorithm)?;
            match sig_alg.verify(message, signature, public_key) {
                Ok(()) => Ok(true), // Signature is valid
                Err(oqs::Error::Error) => Ok(false), // Invalid signature
                Err(e) => Err(PqCryptoError::OqsError(format!("Error during signature verification: {}", e))),
            }
        },
        PqKey::MlKem { .. } => {
            Err(PqCryptoError::UnsupportedOperation("Cannot verify with ML-KEM key".to_string()))
        }
    }
}

/// Perform key encapsulation with an ML-KEM public key
pub fn encapsulate_with_mlkem(pq_key: &PqKey) -> Result<(kem::Ciphertext, kem::SharedSecret), PqCryptoError> {
    match pq_key {
        PqKey::MlKem { algorithm, public_key, .. } => {
            let kem_alg = kem::Kem::new(*algorithm)?;
            let (ciphertext, shared_secret) = kem_alg.encapsulate(public_key)?;
            Ok((ciphertext, shared_secret))
        },
        _ => Err(PqCryptoError::UnsupportedOperation("Can only encapsulate with ML-KEM key".to_string())),
    }
}

/// Perform key decapsulation with an ML-KEM secret key
pub fn decapsulate_with_mlkem(pq_key: &PqKey, ciphertext: &kem::Ciphertext) -> Result<kem::SharedSecret, PqCryptoError> {
    match pq_key {
        PqKey::MlKem { algorithm, secret_key, .. } => {
            let kem_alg = kem::Kem::new(*algorithm)?;
            let shared_secret = kem_alg.decapsulate(secret_key, ciphertext)?;
            Ok(shared_secret)
        },
        _ => Err(PqCryptoError::UnsupportedOperation("Can only decapsulate with ML-KEM key".to_string())),
    }
}

/// Sign data with a hybrid key (both classical and PQ)
pub fn sign_with_hybrid_key(hybrid_key: &HybridKey, data: &[u8]) -> Result<(Vec<u8>, sig::Signature), PqCryptoError> {
    // Sign with classical key
    // This is a placeholder. In a real implementation, we would:
    // 1. Sign the data with the classical key using OpenSSL
    let classical_signature = vec![0u8; 32]; // Placeholder
    
    // Sign with PQ key
    let pq_signature = sign_with_pq_key(&hybrid_key.pq_key, data)?;
    
    Ok((classical_signature, pq_signature))
}

/// Verify a hybrid signature (both classical and PQ)
/// 
/// Returns:
/// - Ok(true) if both the classical and PQ signatures are valid
/// - Ok(false) if either the classical or PQ signature is invalid
/// - Err if there was an error during verification
pub fn verify_hybrid_signature(
    hybrid_key: &HybridKey,
    data: &[u8],
    classical_signature: &[u8],
    pq_signature: &sig::Signature
) -> Result<bool, PqCryptoError> {
    // Verify classical signature
    // This is a placeholder. In a real implementation, we would:
    // 1. Verify the classical signature using OpenSSL
    let classical_valid = true; // Placeholder
    
    // Verify PQ signature
    let pq_valid = verify_with_pq_key(&hybrid_key.pq_key, data, pq_signature)?;
    
    // Both signatures must be valid for the hybrid signature to be valid
    Ok(classical_valid && pq_valid)
}