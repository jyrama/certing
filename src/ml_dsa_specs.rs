use clap::ValueEnum;
use oqs::sig::Algorithm as SigAlgorithm;

/// ML-DSA (Module-Lattice-Based Digital Signature Algorithm) parameter sets
/// according to NIST FIPS 204
#[derive(Debug, Clone, Copy, ValueEnum, PartialEq)]
pub enum MlDsaParams {
    /// ML-DSA-44 (128-bit security level) - TL IV
    Dsa44,
    /// ML-DSA-65 (192-bit security level) - TL III
    Dsa65,
    /// ML-DSA-87 (256-bit security level) - TL II
    Dsa87,
}

impl Default for MlDsaParams {
    fn default() -> Self {
        Self::Dsa44 // Default to TL IV level
    }
}

impl MlDsaParams {
    /// Get security level in bits according to Finnish standards
    pub fn security_bits(self) -> u32 {
        match self {
            Self::Dsa44 => 128,  // TL IV
            Self::Dsa65 => 192,  // TL III
            Self::Dsa87 => 256,  // TL II
        }
    }

    /// Get Finnish security classification level
    pub fn security_level(self) -> &'static str {
        match self {
            Self::Dsa44 => "TL IV (Basic)",
            Self::Dsa65 => "TL III (Increased)",
            Self::Dsa87 => "TL II (High)",
        }
    }

    /// Convert to OQS signature algorithm enum
    pub fn to_oqs_algorithm(self) -> SigAlgorithm {
        match self {
            Self::Dsa44 => SigAlgorithm::MlDsa44,
            Self::Dsa65 => SigAlgorithm::MlDsa65,
            Self::Dsa87 => SigAlgorithm::MlDsa87,
        }
    }

    /// Get ML-DSA parameter set name as used in standards
    pub fn param_name(self) -> &'static str {
        match self {
            Self::Dsa44 => "ML-DSA-44",
            Self::Dsa65 => "ML-DSA-65",
            Self::Dsa87 => "ML-DSA-87",
        }
    }
}