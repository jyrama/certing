use beef::lean::Cow;
use clap::ValueEnum;
use openssl::hash::MessageDigest;
use openssl::bn::BigNum;
use openssl::error::ErrorStack;
use openssl::pkey::{PKey, Private};
use openssl::x509::extension::BasicConstraints;
use openssl::x509::{X509Name, X509};
use openssl::{
    asn1::Asn1Time,
    x509::X509NameRef,
};
use std::path::PathBuf;

use crate::{certificate, key_type, security_level};

/// Certificate configuration options
#[derive(Debug, Clone)]
pub struct CertificateConfig {
    pub key_params: key_type::KeyParams,
    pub valid_days: u32,
    pub common_name: Cow<'static, str>,
    pub organization: Cow<'static, str>,
    pub country: Cow<'static, str>,
    pub serial_number: u32,
    pub cert_type: certificate::CertificateType,
    pub alt_names: Vec<Cow<'static, str>>,
    pub self_signed: bool,
    pub ca_cert_path: Option<PathBuf>,
    pub ca_key_path: Option<PathBuf>,
}

impl Default for CertificateConfig {
    fn default() -> Self {
        Self {
            key_params: key_type::KeyParams::default(),
            valid_days: 365,
            common_name: Cow::from("example.com"),
            organization: Cow::from("My Organization"),
            country: Cow::from("US"),
            serial_number: 1,
            cert_type: certificate::CertificateType::default(),
            alt_names: Vec::new(),
            self_signed: true,
            ca_cert_path: None,
            ca_key_path: None,
        }
    }
}

/// Certificate type: CA, server, or client
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum CertificateType {
    /// Certificate Authority that can sign other certificates
    Ca,
    /// Server certificate for TLS endpoints
    Server,
    /// Client certificate for authentication
    Client,
}

impl Default for CertificateType {
    fn default() -> Self {
        Self::Server
    }
}

/// Build and sign a certificate using the provided parameters
pub(crate) fn build_certificate(
    private_key: &PKey<Private>,
    issuer_name: &X509NameRef,
    subject_name: &X509Name,
    valid_days: u32,
    serial: u32,
    cert_type: CertificateType,
    // alt_names: &[Cow<'static, str>],
) -> Result<X509, ErrorStack> {
    let mut builder = X509::builder()?;

    // Set certificate metadata
    builder.set_version(2)?; // X.509v3

    // Set serial number
    let serial_bn = BigNum::from_u32(serial)?;
    builder.set_serial_number(serial_bn.to_asn1_integer()?.as_ref())?;

    // Set validity period
    let not_before = Asn1Time::days_from_now(0)?;
    let not_after = Asn1Time::days_from_now(valid_days)?;
    builder.set_not_before(&not_before)?;
    builder.set_not_after(&not_after)?;

    // Set names and key
    builder.set_issuer_name(issuer_name)?;
    builder.set_subject_name(subject_name)?;
    builder.set_pubkey(private_key)?;

    // Add extensions based on certificate type
    // let context = builder.x509v3_context(issuer, conf);

    // Basic constraints - mark CA certificates appropriately
    let basic_constraints = match cert_type {
        CertificateType::Ca => BasicConstraints::new().ca().build()?,
        _ => BasicConstraints::new().build()?,
    };
    builder.append_extension(basic_constraints)?;

    // Add Subject Alternative Names if provided
    // if !alt_names.is_empty() {
    //     let mut san_builder = SubjectAlternativeName::new();

    //     for name in alt_names {
    //         san_builder.dns(name);
    //     }

    //     let san_extension = san_builder.build(&context)?;
    //     builder.append_extension(san_extension)?;
    // }

    // Determine security bits for digest selection
    let security_bits = match private_key.id() {
        openssl::pkey::Id::RSA => {
            let rsa = private_key.rsa()?;
            let size = rsa.size() * 8; // Convert bytes to bits
            security_level::rsa_security_bits(size)
        }
        openssl::pkey::Id::EC => {
            let ec = private_key.ec_key()?;
            let curve_name = ec.group().curve_name();
            security_level::ec_security_bits(curve_name)
        }
        openssl::pkey::Id::ED25519 => {
            security_level::edwards_security_bits(Some("Ed25519"))
        }
        openssl::pkey::Id::ED448 => {
            security_level::edwards_security_bits(Some("Ed448"))
        }
        _ => 128, // Default for other key types
    };

    // Sign the certificate
    // EdDSA algorithms don't use an explicit digest - they have a built-in digest operation
    match private_key.id() {
        openssl::pkey::Id::ED25519 | openssl::pkey::Id::ED448 => {
            // For EdDSA, we don't specify a digest algorithm
            builder.sign(private_key, MessageDigest::null())?;
        },
        _ => {
            // For RSA and ECDSA, we select an appropriate digest based on security level
            let digest = security_level::select_message_digest(security_bits);
            builder.sign(private_key, digest)?;
        }
    }

    Ok(builder.build())
}