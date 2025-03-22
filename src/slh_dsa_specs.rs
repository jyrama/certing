use clap::ValueEnum;
use oqs::sig::Algorithm as SigAlgorithm;

/// Module defining SLH-DSA (formerly SPHINCS+) parameters according to NIST FIPS 205
/// 
/// # Naming Convention Note
/// 
/// While NIST has standardized this algorithm as SLH-DSA (Stateless Hash-Based 
/// Digital Signature Algorithm) in FIPS 205, many libraries including OQS still 
/// refer to it by its original name SPHINCS+. This module uses the standardized 
/// SLH-DSA naming in its API but maps to the SPHINCS+ identifiers when 
/// interfacing with the OQS library.
/// 
/// The specific naming mappings are:
/// - SLH-DSA-SHA2-* → SphincsSha2* (note: not Sha256)
/// - SLH-DSA-SHAKE-* → SphincsShake*
/// - All OQS variants have an additional "Simple" suffix

/// Hash algorithm used in SLH-DSA
#[derive(Debug, Clone, Copy, ValueEnum, PartialEq)]
pub enum SlhDsaHashAlg {
    /// SHA-2 family
    Sha2,
    /// SHAKE family
    Shake,
}

/// Parameter size for SLH-DSA
#[derive(Debug, Clone, Copy, ValueEnum, PartialEq)]
pub enum SlhDsaParamSize {
    /// 128-bit security level - TL IV
    Size128,
    /// 192-bit security level - TL III
    Size192,
    /// 256-bit security level - TL II
    Size256,
}

/// Parameter form for SLH-DSA
#[derive(Debug, Clone, Copy, ValueEnum, PartialEq)]
pub enum SlhDsaForm {
    /// Small form - "s" suffix
    Small,
    /// Fast form - "f" suffix
    Fast,
}

/// SLH-DSA (Stateless Hash-Based Digital Signature Algorithm) parameter sets
/// according to NIST FIPS 205
///
/// Note: NIST standardized this algorithm as SLH-DSA (Stateless Hash-Based Digital Signature 
/// Algorithm), but it was previously known as SPHINCS+. The OQS library still uses the 
/// older SPHINCS+ naming convention in its API. This struct uses the standardized SLH-DSA
/// naming but maps to the SPHINCS+ identifiers when interfacing with the OQS library.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SlhDsaParams {
    pub hash_alg: SlhDsaHashAlg,
    pub param_size: SlhDsaParamSize,
    pub form: SlhDsaForm,
}

impl Default for SlhDsaParams {
    fn default() -> Self {
        Self {
            hash_alg: SlhDsaHashAlg::Sha2,
            param_size: SlhDsaParamSize::Size128,
            form: SlhDsaForm::Small,
        }
    }
}

impl SlhDsaParams {
    /// Create a new SLH-DSA parameter set
    pub fn new(hash_alg: SlhDsaHashAlg, param_size: SlhDsaParamSize, form: SlhDsaForm) -> Self {
        Self {
            hash_alg,
            param_size,
            form,
        }
    }

    /// Get security level in bits according to Finnish standards
    pub fn security_bits(&self) -> u32 {
        match self.param_size {
            SlhDsaParamSize::Size128 => 128, // TL IV
            SlhDsaParamSize::Size192 => 192, // TL III
            SlhDsaParamSize::Size256 => 256, // TL II
        }
    }

    /// Get Finnish security classification level
    pub fn security_level(&self) -> &'static str {
        match self.param_size {
            SlhDsaParamSize::Size128 => "TL IV (Basic)",
            SlhDsaParamSize::Size192 => "TL III (Increased)",
            SlhDsaParamSize::Size256 => "TL II (High)",
        }
    }

    /// Convert to OQS signature algorithm enum
    /// 
    /// NOTE: The OQS library still uses the older SPHINCS+ naming convention instead of
    /// the standardized SLH-DSA name. This mapping translates from our SLH-DSA parameters
    /// to the corresponding SPHINCS+ algorithm variants in the OQS library.
    ///
    /// Mapping:
    /// - SLH-DSA-SHA2-* maps to SphincsSha2* in OQS (not Sha256)
    /// - SLH-DSA-SHAKE-* maps to SphincsShake* in OQS
    /// - The "Simple" suffix is always added in the OQS variant names
    pub fn to_oqs_algorithm(&self) -> Option<SigAlgorithm> {
        match (self.hash_alg, self.param_size, self.form) {
            // SHA2 variants map to SphincsSha2*
            (SlhDsaHashAlg::Sha2, SlhDsaParamSize::Size128, SlhDsaForm::Small) => 
                Some(SigAlgorithm::SphincsSha2128sSimple),
            (SlhDsaHashAlg::Sha2, SlhDsaParamSize::Size128, SlhDsaForm::Fast) => 
                Some(SigAlgorithm::SphincsSha2128fSimple),
            (SlhDsaHashAlg::Sha2, SlhDsaParamSize::Size192, SlhDsaForm::Small) => 
                Some(SigAlgorithm::SphincsSha2192sSimple),
            (SlhDsaHashAlg::Sha2, SlhDsaParamSize::Size192, SlhDsaForm::Fast) => 
                Some(SigAlgorithm::SphincsSha2192fSimple),
            (SlhDsaHashAlg::Sha2, SlhDsaParamSize::Size256, SlhDsaForm::Small) => 
                Some(SigAlgorithm::SphincsSha2256sSimple),
            (SlhDsaHashAlg::Sha2, SlhDsaParamSize::Size256, SlhDsaForm::Fast) => 
                Some(SigAlgorithm::SphincsSha2256fSimple),
                
            // SHAKE variants map to SphincsShake*
            (SlhDsaHashAlg::Shake, SlhDsaParamSize::Size128, SlhDsaForm::Small) => 
                Some(SigAlgorithm::SphincsShake128sSimple),
            (SlhDsaHashAlg::Shake, SlhDsaParamSize::Size128, SlhDsaForm::Fast) => 
                Some(SigAlgorithm::SphincsShake128fSimple),
            (SlhDsaHashAlg::Shake, SlhDsaParamSize::Size192, SlhDsaForm::Small) => 
                Some(SigAlgorithm::SphincsShake192sSimple),
            (SlhDsaHashAlg::Shake, SlhDsaParamSize::Size192, SlhDsaForm::Fast) => 
                Some(SigAlgorithm::SphincsShake192fSimple),
            (SlhDsaHashAlg::Shake, SlhDsaParamSize::Size256, SlhDsaForm::Small) => 
                Some(SigAlgorithm::SphincsShake256sSimple),
            (SlhDsaHashAlg::Shake, SlhDsaParamSize::Size256, SlhDsaForm::Fast) => 
                Some(SigAlgorithm::SphincsShake256fSimple),
        }
    }

    /// Get SLH-DSA parameter set name as used in standards
    pub fn param_name(&self) -> String {
        let hash_name = match self.hash_alg {
            SlhDsaHashAlg::Sha2 => "SHA2",
            SlhDsaHashAlg::Shake => "SHAKE",
        };

        let size_name = match self.param_size {
            SlhDsaParamSize::Size128 => "128",
            SlhDsaParamSize::Size192 => "192",
            SlhDsaParamSize::Size256 => "256",
        };

        let form_name = match self.form {
            SlhDsaForm::Small => "s",
            SlhDsaForm::Fast => "f",
        };

        format!("SLH-DSA-{}-{}{}", hash_name, size_name, form_name)
    }
    
    /// Get all valid SLH-DSA parameter combinations for a given security level
    pub fn get_for_security_level(level: &str) -> Vec<Self> {
        match level {
            "TL IV (Basic)" | "TL IV" => vec![
                Self::new(SlhDsaHashAlg::Sha2, SlhDsaParamSize::Size128, SlhDsaForm::Small),
                Self::new(SlhDsaHashAlg::Shake, SlhDsaParamSize::Size128, SlhDsaForm::Small),
                Self::new(SlhDsaHashAlg::Sha2, SlhDsaParamSize::Size128, SlhDsaForm::Fast),
                Self::new(SlhDsaHashAlg::Shake, SlhDsaParamSize::Size128, SlhDsaForm::Fast),
            ],
            "TL III (Increased)" | "TL III" => vec![
                Self::new(SlhDsaHashAlg::Sha2, SlhDsaParamSize::Size192, SlhDsaForm::Small),
                Self::new(SlhDsaHashAlg::Shake, SlhDsaParamSize::Size192, SlhDsaForm::Small),
                Self::new(SlhDsaHashAlg::Sha2, SlhDsaParamSize::Size192, SlhDsaForm::Fast),
                Self::new(SlhDsaHashAlg::Shake, SlhDsaParamSize::Size192, SlhDsaForm::Fast),
            ],
            "TL II (High)" | "TL II" => vec![
                Self::new(SlhDsaHashAlg::Sha2, SlhDsaParamSize::Size256, SlhDsaForm::Small),
                Self::new(SlhDsaHashAlg::Shake, SlhDsaParamSize::Size256, SlhDsaForm::Small),
                Self::new(SlhDsaHashAlg::Sha2, SlhDsaParamSize::Size256, SlhDsaForm::Fast),
                Self::new(SlhDsaHashAlg::Shake, SlhDsaParamSize::Size256, SlhDsaForm::Fast),
            ],
            _ => vec![],
        }
    }
}