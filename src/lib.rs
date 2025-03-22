// Public modules
pub mod builder;
pub mod certificate;
pub mod ec_specs;
pub mod hybrid_crypto;
pub mod key_type;
pub mod ml_dsa_specs;
pub mod ml_kem_specs;
pub mod pq_crypto;
pub mod rsa_specs;
pub mod security_level;
pub mod slh_dsa_specs;
pub mod dual_signature;
pub mod constants;

// Re-export commonly used types for convenience
pub use builder::{CertificateBundle, CertError, generate_certificate, save_certificate_bundle};
pub use certificate::{CertificateConfig, CertificateType};
pub use ec_specs::EcCurve;
pub use hybrid_crypto::{generate_complete_hybrid_key, HybridCryptoError};
pub use key_type::{KeyParams, KeyType, ClassicalKeyType, PostQuantumKeyType, HybridConfig};
pub use ml_dsa_specs::MlDsaParams;
pub use ml_kem_specs::MlKemParams;
pub use pq_crypto::{
    PqKey, HybridKey, PqCryptoError, 
    generate_pq_key, sign_with_pq_key, verify_with_pq_key,
    encapsulate_with_mlkem, decapsulate_with_mlkem
};
pub use rsa_specs::RsaKeySize;
pub use slh_dsa_specs::{SlhDsaParams, SlhDsaHashAlg, SlhDsaParamSize, SlhDsaForm};