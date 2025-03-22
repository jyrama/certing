use clap::ValueEnum;
use openssl::nid::Nid;

/// Supported elliptic curve types for key generation
#[derive(Debug, Clone, Copy, ValueEnum, PartialEq)]
pub enum EcCurve {
    /// NIST P-256 curve (secp256r1) - TL IV
    P256,
    /// NIST P-384 curve (secp384r1) - TL III
    P384,
    /// NIST P-521 curve (secp521r1) - TL II
    P521,
    /// Ed25519 curve (Edwards 25519) - TL IV
    Ed25519,
    /// Ed448 curve (Edwards 448) - TL III
    Ed448,
}

impl Default for EcCurve {
    fn default() -> Self {
        Self::P256
    }
}

impl EcCurve {
    /// Convert to OpenSSL Nid for NIST curve creation
    /// This should only be called for NIST curves (P-256, P-384, P-521)
    pub fn to_nid(self) -> Option<Nid> {
        match self {
            Self::P256 => Some(Nid::X9_62_PRIME256V1), // same as NIST P-256 / secp256r1
            Self::P384 => Some(Nid::SECP384R1),         // same as NIST P-384
            Self::P521 => Some(Nid::SECP521R1),         // same as NIST P-521
            _ => None, // Edwards curves don't use NIDs for generation in the same way
        }
    }

    /// Get security level in bits according to Finnish standards
    pub fn security_bits(self) -> u32 {
        match self {
            Self::P256 | Self::Ed25519 => 128,    // TL IV
            Self::P384 | Self::Ed448 => 192,      // TL III
            Self::P521 => 256,                    // TL II
        }
    }

    /// Check if curve is an Edwards curve (EdDSA)
    pub fn is_edwards(self) -> bool {
        matches!(self, Self::Ed25519 | Self::Ed448)
    }
    
    /// Get the Edwards curve type as a string if applicable
    pub fn edwards_type(self) -> Option<&'static str> {
        match self {
            Self::Ed25519 => Some("Ed25519"),
            Self::Ed448 => Some("Ed448"),
            _ => None
        }
    }

    /// Get Finnish security classification level
    pub fn security_level(self) -> &'static str {
        match self {
            Self::P256 | Self::Ed25519 => "TL IV (Basic)",
            Self::P384 | Self::Ed448 => "TL III (Increased)",
            Self::P521 => "TL II (High)",
        }
    }
}