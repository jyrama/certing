use clap::ValueEnum;
use oqs::kem::Algorithm as KemAlgorithm;

/// ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism) parameter sets
/// according to NIST FIPS 203
#[derive(Debug, Clone, Copy, ValueEnum, PartialEq)]
pub enum MlKemParams {
    /// ML-KEM-512 (128-bit security level) - TL IV
    Kem512,
    /// ML-KEM-768 (192-bit security level) - TL III
    Kem768,
    /// ML-KEM-1024 (256-bit security level) - TL II
    Kem1024,
}

impl Default for MlKemParams {
    fn default() -> Self {
        Self::Kem512 // Default to TL IV level
    }
}

impl MlKemParams {
    /// Get security level in bits according to Finnish standards
    pub fn security_bits(self) -> u32 {
        match self {
            Self::Kem512 => 128,  // TL IV
            Self::Kem768 => 192,  // TL III
            Self::Kem1024 => 256, // TL II
        }
    }

    /// Get Finnish security classification level
    pub fn security_level(self) -> &'static str {
        match self {
            Self::Kem512 => "TL IV (Basic)",
            Self::Kem768 => "TL III (Increased)",
            Self::Kem1024 => "TL II (High)",
        }
    }

    /// Convert to OQS KEM algorithm enum
    pub fn to_oqs_algorithm(self) -> KemAlgorithm {
        match self {
            Self::Kem512 => KemAlgorithm::MlKem512,
            Self::Kem768 => KemAlgorithm::MlKem768,
            Self::Kem1024 => KemAlgorithm::MlKem1024,
        }
    }

    /// Get ML-KEM parameter set name as used in standards
    pub fn param_name(self) -> &'static str {
        match self {
            Self::Kem512 => "ML-KEM-512",
            Self::Kem768 => "ML-KEM-768",
            Self::Kem1024 => "ML-KEM-1024",
        }
    }
}