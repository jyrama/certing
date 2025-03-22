use clap::ValueEnum;

use crate::ec_specs::EcCurve;
use crate::ml_kem_specs::MlKemParams;
use crate::ml_dsa_specs::MlDsaParams;
use crate::slh_dsa_specs::SlhDsaParams;
use crate::rsa_specs::RsaKeySize;

/// Key type for certificate generation
#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum KeyType {
    /// RSA key with specified bit size
    Rsa,
    /// Elliptic Curve key with specified curve (NIST curves: P-256, P-384, P-521)
    Ec,
    /// EdDSA key with Edwards curve (Ed25519, Ed448)
    Ed,
    /// Post-Quantum ML-KEM key (NIST FIPS 203)
    MlKem,
    /// Post-Quantum ML-DSA (lattice-based signature, NIST FIPS 204)
    MlDsa,
    /// Post-Quantum SLH-DSA (hash-based signature, NIST FIPS 205)
    SlhDsa,
    /// Hybrid key combining classical and post-quantum algorithms
    Hybrid,
}

impl Default for KeyType {
    fn default() -> Self {
        Self::Rsa
    }
}

/// Classical algorithm type for hybrid combination
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ClassicalKeyType {
    Rsa(RsaKeySize),
    Ec(EcCurve),
    Ed(EcCurve),
}

/// Post-quantum algorithm type for hybrid combination
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PostQuantumKeyType {
    MlKem(MlKemParams),
    MlDsa(MlDsaParams),
    SlhDsa(SlhDsaParams),
}

/// Configuration for hybrid key generation
#[derive(Debug, Clone, Copy)]
pub struct HybridConfig {
    pub classical_type: ClassicalKeyType,
    pub pq_type: PostQuantumKeyType,
}

/// Parameters for key generation
#[derive(Debug, Clone, Copy)]
pub struct KeyParams {
    pub key_type: KeyType,
    pub rsa_size: Option<RsaKeySize>,
    pub ec_curve: Option<EcCurve>,
    pub ml_kem_params: Option<MlKemParams>,
    pub ml_dsa_params: Option<MlDsaParams>,
    pub slh_dsa_params: Option<SlhDsaParams>,
    pub hybrid_config: Option<HybridConfig>,
}

impl Default for KeyParams {
    fn default() -> Self {
        Self {
            key_type: KeyType::default(),
            rsa_size: Some(RsaKeySize::default()),
            ec_curve: None,
            ml_kem_params: None,
            ml_dsa_params: None,
            slh_dsa_params: None,
            hybrid_config: None,
        }
    }
}

impl KeyParams {
    /// Create new RSA key parameters
    pub fn new_rsa(size: RsaKeySize) -> Self {
        Self {
            key_type: KeyType::Rsa,
            rsa_size: Some(size),
            ec_curve: None,
            ml_kem_params: None,
            ml_dsa_params: None,
            slh_dsa_params: None,
            hybrid_config: None,
        }
    }

    /// Create new EC key parameters - automatically determines whether to use
    /// standard EC (NIST curves) or EdDSA (Edwards curves)
    pub fn new_ec(curve: EcCurve) -> Self {
        let key_type = match curve {
            EcCurve::Ed25519 | EcCurve::Ed448 => KeyType::Ed,
            _ => KeyType::Ec,
        };

        Self {
            key_type,
            rsa_size: None,
            ec_curve: Some(curve),
            ml_kem_params: None,
            ml_dsa_params: None,
            slh_dsa_params: None,
            hybrid_config: None,
        }
    }

    /// Create new ML-KEM key parameters
    pub fn new_ml_kem(params: MlKemParams) -> Self {
        Self {
            key_type: KeyType::MlKem,
            rsa_size: None,
            ec_curve: None,
            ml_kem_params: Some(params),
            ml_dsa_params: None,
            slh_dsa_params: None,
            hybrid_config: None,
        }
    }

    /// Create new ML-DSA key parameters
    pub fn new_ml_dsa(params: MlDsaParams) -> Self {
        Self {
            key_type: KeyType::MlDsa,
            rsa_size: None,
            ec_curve: None,
            ml_kem_params: None,
            ml_dsa_params: Some(params),
            slh_dsa_params: None,
            hybrid_config: None,
        }
    }

    /// Create new SLH-DSA key parameters
    pub fn new_slh_dsa(params: SlhDsaParams) -> Self {
        Self {
            key_type: KeyType::SlhDsa,
            rsa_size: None,
            ec_curve: None,
            ml_kem_params: None,
            ml_dsa_params: None,
            slh_dsa_params: Some(params),
            hybrid_config: None,
        }
    }

    /// Create new hybrid key parameters
    pub fn new_hybrid(classical: ClassicalKeyType, pq: PostQuantumKeyType) -> Self {
        Self {
            key_type: KeyType::Hybrid,
            rsa_size: None,
            ec_curve: None,
            ml_kem_params: None,
            ml_dsa_params: None,
            slh_dsa_params: None,
            hybrid_config: Some(HybridConfig {
                classical_type: classical,
                pq_type: pq,
            }),
        }
    }

    /// Get security strength in bits
    pub fn security_bits(&self) -> u32 {
        match self.key_type {
            KeyType::Rsa => match self.rsa_size {
                Some(size) if size.bits() >= 15360 => 256,
                Some(size) if size.bits() >= 7680 => 192,
                Some(size) if size.bits() >= 3072 => 128,
                _ => 112, // Below recommended minimums
            },
            KeyType::Ec | KeyType::Ed => match self.ec_curve {
                Some(curve) => curve.security_bits(),
                None => 128, // Default to P-256 equivalent
            },
            KeyType::MlKem => match self.ml_kem_params {
                Some(params) => params.security_bits(),
                None => 128, // Default to ML-KEM-512 equivalent
            },
            KeyType::MlDsa => match self.ml_dsa_params {
                Some(params) => params.security_bits(),
                None => 128, // Default to ML-DSA-44 equivalent
            },
            KeyType::SlhDsa => match self.slh_dsa_params {
                Some(params) => params.security_bits(),
                None => 128, // Default to SLH-DSA-128 equivalent
            },
            KeyType::Hybrid => match self.hybrid_config {
                Some(config) => {
                    // Return the minimum security level of the hybrid components
                    let classical_bits = match config.classical_type {
                        ClassicalKeyType::Rsa(size) => {
                            if size.bits() >= 15360 { 256 }
                            else if size.bits() >= 7680 { 192 }
                            else if size.bits() >= 3072 { 128 }
                            else { 112 }
                        },
                        ClassicalKeyType::Ec(curve) | ClassicalKeyType::Ed(curve) => curve.security_bits(),
                    };

                    let pq_bits = match config.pq_type {
                        PostQuantumKeyType::MlKem(params) => params.security_bits(),
                        PostQuantumKeyType::MlDsa(params) => params.security_bits(),
                        PostQuantumKeyType::SlhDsa(params) => params.security_bits(),
                    };

                    classical_bits.min(pq_bits)
                },
                None => 128, // Default to lowest security level
            },
        }
    }

    /// Get Finnish security level designation
    pub fn security_level(&self) -> &'static str {
        match self.key_type {
            KeyType::Rsa => match self.rsa_size {
                Some(size) if size.bits() >= 15360 => "TL II (High)",
                Some(size) if size.bits() >= 7680 => "TL III (Increased)",
                Some(size) if size.bits() >= 3072 => "TL IV (Basic)",
                _ => "Below minimum security standards",
            },
            KeyType::Ec | KeyType::Ed => match self.ec_curve {
                Some(curve) => curve.security_level(),
                None => "TL IV (Basic)", // Default to P-256 equivalent
            },
            KeyType::MlKem => match self.ml_kem_params {
                Some(params) => params.security_level(),
                None => "TL IV (Basic)", // Default to ML-KEM-512 equivalent
            },
            KeyType::MlDsa => match self.ml_dsa_params {
                Some(params) => params.security_level(),
                None => "TL IV (Basic)", // Default to ML-DSA-44 equivalent
            },
            KeyType::SlhDsa => match self.slh_dsa_params {
                Some(params) => params.security_level(),
                None => "TL IV (Basic)", // Default to SLH-DSA-128s equivalent
            },
            KeyType::Hybrid => {
                // Determine security level from security bits
                let bits = self.security_bits();
                if bits >= 256 { "TL II (High)" }
                else if bits >= 192 { "TL III (Increased)" }
                else if bits >= 128 { "TL IV (Basic)" }
                else { "Below minimum security standards" }
            },
        }
    }
    
    /// Check if this is a quantum-safe key type (post-quantum or hybrid)
    pub fn is_quantum_safe(&self) -> bool {
        matches!(
            self.key_type,
            KeyType::MlKem | KeyType::MlDsa | KeyType::SlhDsa | KeyType::Hybrid
        )
    }
    
    /// Check if this key supports the Finnish security level
    pub fn meets_security_level(&self, level: &str) -> bool {
        match level {
            "TL IV (Basic)" | "TL IV" => self.security_bits() >= 128,
            "TL III (Increased)" | "TL III" => self.security_bits() >= 192,
            "TL II (High)" | "TL II" => self.security_bits() >= 256,
            _ => false,
        }
    }
}