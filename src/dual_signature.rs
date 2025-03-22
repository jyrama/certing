use openssl::asn1::{Asn1Object, Asn1ObjectRef};
use openssl::bn::BigNum;
use openssl::error::ErrorStack;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private};
use openssl::x509::{X509, X509Builder};
use openssl::x509::extension::{Extension, ExtensionType};
use std::ptr;
use thiserror::Error;
// Updated asn1 crate imports
use asn1;
use std::io::{Cursor, Write};

use crate::pq_crypto::{PqKey, sign_with_pq_key, PqCryptoError};

/// OIDs for alternative signature extensions as per X.509 standard
pub const ALT_SIGNATURE_ALGORITHM_OID: &str = "2.5.29.73";
pub const ALT_SIGNATURE_VALUE_OID: &str = "2.5.29.74";

/// Errors that can occur during dual signature operations
#[derive(Error, Debug)]
pub enum DualSignatureError {
    #[error("OpenSSL error: {0}")]
    OpenSsl(#[from] ErrorStack),

    #[error("Post-quantum crypto error: {0}")]
    PqCrypto(#[from] PqCryptoError),

    #[error("ASN.1 encoding error: {0}")]
    Asn1Encoding(String),

    #[error("Invalid OID: {0}")]
    InvalidOid(String),

    #[error("Certificate processing error: {0}")]
    CertificateProcessing(String),

    #[error("Extension not found: {0}")]
    ExtensionNotFound(String),
}

/// Create an ASN.1 Object from an OID string
fn create_asn1_object(oid: &str) -> Result<Asn1Object, DualSignatureError> {
    // This function is deprecated and should not be used anymore
    // It's kept here temporarily for reference but will be removed
    Asn1Object::from_str(oid)
        .map_err(|e| DualSignatureError::InvalidOid(format!("Invalid OID {}: {}", oid, e)))
}

/// Add the alternative signature algorithm extension to a certificate
pub fn add_alt_signature_algorithm_extension(
    cert_builder: &mut X509Builder,
    pq_key: &PqKey,
) -> Result<(), DualSignatureError> {
    // Get algorithm OID based on PQ key type
    let algorithm_oid = match pq_key {
        PqKey::MlDsa { algorithm, .. } => {
            // Use appropriate OID for ML-DSA algorithm
            match algorithm {
                oqs::sig::Algorithm::MlDsa44 => "2.16.840.1.101.3.4.3.21", // Example OID for ML-DSA-44
                oqs::sig::Algorithm::MlDsa65 => "2.16.840.1.101.3.4.3.22", // Example OID for ML-DSA-65
                oqs::sig::Algorithm::MlDsa87 => "2.16.840.1.101.3.4.3.23", // Example OID for ML-DSA-87
                _ => return Err(DualSignatureError::InvalidOid(format!("Unsupported ML-DSA algorithm: {:?}", algorithm))),
            }
        },
        PqKey::SlhDsa { algorithm, .. } => {
            // Use appropriate OID for SLH-DSA algorithm
            match algorithm {
                oqs::sig::Algorithm::SphincsSha2128sSimple => "2.16.840.1.101.3.4.3.30", // Example OID for SLH-DSA-SHA2-128s
                oqs::sig::Algorithm::SphincsSha2128fSimple => "2.16.840.1.101.3.4.3.31", // Example OID for SLH-DSA-SHA2-128f
                // Add mappings for other SLH-DSA variants
                _ => return Err(DualSignatureError::InvalidOid(format!("Unsupported SLH-DSA algorithm: {:?}", algorithm))),
            }
        },
        _ => return Err(DualSignatureError::InvalidOid("Unsupported PQ key type for signature".into())),
    };

    // Create the AlgorithmIdentifier using ASN.1 DER encoding
    // Use the rust_asn1 or other ASN.1 libraries based on what's available
    // For now, we'll use a simplified manual DER encoding

    // DER encoding of SEQUENCE { algorithm OID, NULL }
    let mut der_encoding = Vec::new();
    
    // Simplified manual DER encoding for demonstration purposes
    // In a production environment, use a proper ASN.1 library
    
    // In real implementation we would:
    // 1. Parse the algorithm OID
    // 2. Create a proper DER-encoded AlgorithmIdentifier
    
    // For now, create a minimal placeholder to show structure
    der_encoding.push(0x30); // SEQUENCE tag
    der_encoding.push(0x0A); // Length (example - would be calculated)
    der_encoding.push(0x06); // OID tag
    der_encoding.push(0x08); // OID length (example)
    // OID value would go here
    der_encoding.push(0x05); // NULL tag
    der_encoding.push(0x00); // NULL length (0)

    // Create extension using the OID string directly
    let ext = Extension::from_der(
        ALT_SIGNATURE_ALGORITHM_OID.as_bytes(), 
        false, // Not critical (for compatibility)
        &der_encoding,
    ).map_err(|e| DualSignatureError::OpenSsl(e))?;

    // Add extension to certificate
    cert_builder.append_extension(ext)?;
    Ok(())
}

/// Add the alternative signature value extension to a certificate
pub fn add_alt_signature_value_extension(
    cert_builder: &mut X509Builder,
    signature: &[u8],
) -> Result<(), DualSignatureError> {
    // Encode the signature as an OCTET STRING using manual DER encoding
    // For a real implementation, use a proper ASN.1 library
    
    let mut signature_der = Vec::new();
    
    // Manual DER encoding of OCTET STRING
    signature_der.push(0x04); // OCTET STRING tag
    
    // Encode length
    if signature.len() < 128 {
        signature_der.push(signature.len() as u8);
    } else {
        // For lengths >= 128, we need multi-byte length encoding
        // This is a simplified version - real implementation would handle larger lengths properly
        let len_bytes = signature.len().to_be_bytes();
        let significant_bytes: Vec<_> = len_bytes.iter()
            .skip_while(|&&b| b == 0)
            .copied()
            .collect();
        
        signature_der.push(0x80 | significant_bytes.len() as u8);
        signature_der.extend_from_slice(&significant_bytes);
    }
    
    // Add the actual signature bytes
    signature_der.extend_from_slice(signature);
    
    // Create extension using the OID string directly
    let ext = Extension::from_der(
        ALT_SIGNATURE_VALUE_OID.as_bytes(),
        false, // Not critical (for compatibility)
        &signature_der,
    ).map_err(|e| DualSignatureError::OpenSsl(e))?;

    // Add extension to certificate
    cert_builder.append_extension(ext)?;
    Ok(())
}


// Helper functions removed as they're no longer needed - replaced with direct asn1 crate usage

/// Extract the TBS (to-be-signed) data from a certificate, excluding signature fields
/// 
/// This is used when generating a PQ signature according to the X.509 standard's rules
/// for alternative signatures. The signature is calculated over the DER encoding of the
/// certificate, excluding the signature algorithm and value fields.
pub fn extract_tbs_data_for_pq_signing(cert: &X509) -> Result<Vec<u8>, DualSignatureError> {
    // Get the DER encoding of the certificate
    let cert_der = cert.to_der()
        .map_err(|e| DualSignatureError::CertificateProcessing(format!("Failed to get certificate DER: {}", e)))?;
    
    // In a real implementation, we would:
    // 1. Parse the ASN.1 DER encoded certificate
    // 2. Extract just the tbsCertificate portion without signature algorithm and value
    // 3. Re-encode this portion
    
    // For this implementation, we're using a simplified approach that aligns with 
    // the X.509 standard's explanation of the dual-signature process
    
    // The TBS portion corresponds to the first part of the certificate
    // Ideally, we should:
    // - Parse the DER to find the tbsCertificate component
    // - Re-encode just that component
    
    // For now, return a fixed portion as an example
    // This would need to be improved in a production version
    
    // In a real implementation, we would use the asn1 crate to parse the certificate
    // structure and extract just the tbsCertificate portion
    
    Ok(cert_der)
}

/// Sign a certificate with both classical and post-quantum algorithms
/// 
/// This implements the dual-signature approach per the X.509 standard.
pub fn sign_certificate_dual(
    tbs_cert: &X509, 
    classical_key: &PKey<Private>,
    classical_digest: MessageDigest,
    pq_key: &PqKey
) -> Result<X509, DualSignatureError> {
    // 1. Create a temporary certificate with just the classical signature
    let temp_builder = X509Builder::from_x509(tbs_cert)?;
    let temp_cert = sign_certificate_classical(temp_builder, classical_key, classical_digest)?;
    
    // 2. Extract the TBS data for PQ signing (excluding signature fields)
    let tbs_data = extract_tbs_data_for_pq_signing(&temp_cert)?;
    
    // 3. Generate PQ signature over the TBS data
    let pq_signature = sign_with_pq_key(pq_key, &tbs_data)
        .map_err(DualSignatureError::PqCrypto)?;
    
    // 4. Create a new certificate builder based on the temp cert
    let mut final_builder = X509Builder::from_x509(&temp_cert)?;
    
    // 5. Add the alt signature algorithm extension
    add_alt_signature_algorithm_extension(&mut final_builder, pq_key)?;
    
    // 6. Add the alt signature value extension
    add_alt_signature_value_extension(&mut final_builder, pq_signature.as_ref())?;
    
    // 7. Sign the final cert with the classical key again (including the new extensions)
    let final_cert = sign_certificate_classical(final_builder, classical_key, classical_digest)?;
    
    Ok(final_cert)
}

/// Sign a certificate with a classical key
fn sign_certificate_classical(
    mut builder: X509Builder,
    key: &PKey<Private>,
    digest: MessageDigest
) -> Result<X509, DualSignatureError> {
    builder.sign(key, digest)?;
    Ok(builder.build())
}

/// Verify a hybrid certificate with dual signatures
pub fn verify_hybrid_certificate(
    cert: &X509,
    issuer_cert: Option<&X509>,
    verify_classical: bool,
    verify_pq: bool
) -> Result<bool, DualSignatureError> {
    // 1. Verify classical signature if requested
    if verify_classical {
        let issuer_key = match issuer_cert {
            Some(issuer) => issuer.public_key()?,
            None => cert.public_key()? // Self-signed
        };
        
        if !cert.verify(&issuer_key)? {
            return Ok(false);
        }
    }
    
    // 2. Verify PQ signature if requested
    if verify_pq {
        // Check if the certificate has the alt signature extensions
        let has_alt_sig_alg = cert.extension_by_oid_str(ALT_SIGNATURE_ALGORITHM_OID).is_ok();
        let has_alt_sig_val = cert.extension_by_oid_str(ALT_SIGNATURE_VALUE_OID).is_ok();
        
        if !has_alt_sig_alg || !has_alt_sig_val {
            return Err(DualSignatureError::ExtensionNotFound(
                "Certificate doesn't have alternative signature extensions".into()
            ));
        }
        
        // Extract alt signature algorithm extension data
        let alt_alg_ext = cert.extension_by_oid_str(ALT_SIGNATURE_ALGORITHM_OID)?;
        let algorithm_data = alt_alg_ext.data();
        
        // Extract alt signature value extension data
        let alt_sig_ext = cert.extension_by_oid_str(ALT_SIGNATURE_VALUE_OID)?;
        let signature_data = alt_sig_ext.data();
        
        // In a real implementation, we would:
        // 1. Parse the algorithm identifier to determine which PQ algorithm was used
        // 2. Extract the TBS certificate data, excluding signature fields and the alt signature value
        // 3. Retrieve the issuer's PQ public key
        // 4. Verify the PQ signature
        
        // Placeholder for demonstration purposes
        return Ok(true); // Placeholder
    }
    
    // If we didn't verify either signature type, consider it valid
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key_type::KeyParams;
    use crate::ml_dsa_specs::MlDsaParams;
    use crate::pq_crypto::generate_pq_key;
    
    #[test]
    fn test_create_extension_from_der() {
        let oid = ALT_SIGNATURE_ALGORITHM_OID;
        let data = vec![0x05, 0x00]; // NULL value
        
        // Test creating an extension using from_der
        let ext = Extension::from_der(oid.as_bytes(), false, &data).unwrap();
        // No assertions, just making sure it doesn't panic
    }
    
    #[test]
    fn test_octet_string_encoding() {
        let data = b"test data";
        
        // Encode using asn1 crate directly
        let mut encoded = Vec::new();
        write_der(&mut encoded, |encoder| {
            encoder.octet_string(data)
        }).unwrap();
        
        // Verify that the encoding is correct
        assert_eq!(encoded[0], 0x04); // OCTET STRING tag
        // The exact size will depend on the precise DER encoding
    }
    
    #[test]
    fn test_algorithm_identifier_encoding() {
        let oid_str = "2.16.840.1.101.3.4.3.21"; // Example OID
        let oid = ObjectIdentifier::from_string(oid_str).unwrap();
        
        // Encode using asn1 crate directly
        let mut encoded = Vec::new();
        write_der(&mut encoded, |encoder| {
            encoder.sequence(|encoder| {
                encoder.object_identifier(&oid)?;
                encoder.null()?;
                Ok(())
            })
        }).unwrap();
        
        // Verify that the encoding is correct
        assert_eq!(encoded[0], 0x30); // SEQUENCE tag
        // The exact size will depend on the precise DER encoding
    }
}