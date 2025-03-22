use openssl::hash::MessageDigest;
use openssl::nid::Nid;

/// Finnish national security classification levels
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityLevel {
    /// TL IV - Basic security level (128-bit)
    TlIV,
    /// TL III - Increased security level (192-bit)
    TlIII,
    /// TL II - High security level (256-bit)
    TlII,
    /// Below minimum standards
    BelowStandards,
}

impl SecurityLevel {
    /// Get the security level name
    pub fn name(self) -> &'static str {
        match self {
            Self::TlII => "TL II (High)",
            Self::TlIII => "TL III (Increased)",
            Self::TlIV => "TL IV (Basic)",
            Self::BelowStandards => "Below minimum security standards",
        }
    }

    /// Get the security strength in bits
    pub fn bits(self) -> u32 {
        match self {
            Self::TlII => 256,
            Self::TlIII => 192,
            Self::TlIV => 128,
            Self::BelowStandards => 112,
        }
    }
}

/// Map RSA key size to security bits according to Finnish standards
pub fn rsa_security_bits(key_size: u32) -> u32 {
    match key_size {
        size if size >= 15360 => 256, // TL II
        size if size >= 7680 => 192,  // TL III
        size if size >= 3072 => 128,  // TL IV
        _ => 112,                     // Below standards
    }
}

/// Map EC curve to security bits according to Finnish standards
pub fn ec_security_bits(curve_nid: Option<Nid>) -> u32 {
    match curve_nid {
        Some(nid) => match nid {
            Nid::X9_62_PRIME256V1 => 128, // NIST P-256 (TL IV)
            Nid::SECP384R1 => 192,         // NIST P-384 (TL III)
            Nid::SECP521R1 => 256,         // NIST P-521 (TL II)
            _ => 112,                      // Unknown NIST curve
        },
        None => 112,                       // Undefined curve
    }
}

/// Map Edwards curve to security bits
pub fn edwards_security_bits(curve_type: Option<&str>) -> u32 {
    match curve_type {
        Some("Ed25519") => 128,           // Ed25519 (TL IV)
        Some("Ed448") => 192,             // Ed448 (TL III)
        _ => 112,                         // Unknown Edwards curve
    }
}

/// Get security level from bits
pub fn from_bits(bits: u32) -> SecurityLevel {
    match bits {
        bits if bits >= 256 => SecurityLevel::TlII,
        bits if bits >= 192 => SecurityLevel::TlIII,
        bits if bits >= 128 => SecurityLevel::TlIV,
        _ => SecurityLevel::BelowStandards,
    }
}

/// Get RSA security level from key size
pub fn get_rsa_security_level(key_size: u32) -> SecurityLevel {
    from_bits(rsa_security_bits(key_size))
}

/// Get EC security level from curve
pub fn get_ec_security_level(curve_nid: Option<Nid>) -> SecurityLevel {
    from_bits(ec_security_bits(curve_nid))
}

/// Select the appropriate message digest based on security bits
///
/// According to Finnish cryptographic standards:
/// - TL IV (128-bit security): SHA-256
/// - TL III (192-bit security): SHA-384
/// - TL II (256-bit security): SHA-512
///
/// Note: For EdDSA (Ed25519 and Ed448), this should not be used directly
/// as these algorithms have their own built-in digest operations.
pub fn select_message_digest(security_bits: u32) -> MessageDigest {
    match security_bits {
        bits if bits >= 256 => MessageDigest::sha512(), // TL II
        bits if bits >= 192 => MessageDigest::sha384(), // TL III
        _ => MessageDigest::sha256(),                   // TL IV and below
    }
}