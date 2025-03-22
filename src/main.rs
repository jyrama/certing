mod builder;
mod certificate;
mod ec_specs;
mod hybrid_crypto;
mod key_type;
mod ml_dsa_specs;
mod ml_kem_specs;
mod pq_crypto;
mod rsa_specs;
mod security_level;
mod slh_dsa_specs;

use beef::lean::Cow;
use clap::Parser;
use std::path::PathBuf;

use crate::key_type::{KeyParams, ClassicalKeyType, PostQuantumKeyType};
use crate::slh_dsa_specs::{SlhDsaParams, SlhDsaHashAlg, SlhDsaParamSize, SlhDsaForm};

// Create key parameters based on CLI arguments
fn create_key_params(cli: &Cli) -> KeyParams {
    match cli.key_type {
        key_type::KeyType::Rsa => KeyParams::new_rsa(cli.rsa_key_size),
        key_type::KeyType::Ec | key_type::KeyType::Ed => KeyParams::new_ec(cli.ec_curve),
        key_type::KeyType::MlKem => KeyParams::new_ml_kem(cli.ml_kem_params),
        key_type::KeyType::MlDsa => KeyParams::new_ml_dsa(cli.ml_dsa_params),
        key_type::KeyType::SlhDsa => {
            let slh_params = SlhDsaParams::new(
                cli.slh_dsa_hash_alg,
                cli.slh_dsa_param_size,
                cli.slh_dsa_form,
            );
            KeyParams::new_slh_dsa(slh_params)
        },
        key_type::KeyType::Hybrid => {
            // Create classical key type
            let classical_type = match cli.hybrid_classical_type {
                HybridClassicalType::Rsa => ClassicalKeyType::Rsa(cli.rsa_key_size),
                HybridClassicalType::Ec => ClassicalKeyType::Ec(cli.ec_curve),
                HybridClassicalType::Ed => ClassicalKeyType::Ed(cli.ec_curve),
            };
            
            // Create post-quantum key type
            let pq_type = match cli.hybrid_pq_type {
                HybridPqType::MlKem => PostQuantumKeyType::MlKem(cli.ml_kem_params),
                HybridPqType::MlDsa => PostQuantumKeyType::MlDsa(cli.ml_dsa_params),
                HybridPqType::SlhDsa => {
                    let slh_params = SlhDsaParams::new(
                        cli.slh_dsa_hash_alg,
                        cli.slh_dsa_param_size,
                        cli.slh_dsa_form,
                    );
                    PostQuantumKeyType::SlhDsa(slh_params)
                },
            };
            
            KeyParams::new_hybrid(classical_type, pq_type)
        },
    }
}

/// Classical algorithm choices for hybrid keys
#[derive(clap::ValueEnum, Debug, Clone)]
pub enum HybridClassicalType {
    /// RSA key
    Rsa,
    /// ECDSA key with NIST curve
    Ec,
    /// EdDSA key with Edwards curve
    Ed,
}

/// Post-quantum algorithm choices for hybrid keys
#[derive(clap::ValueEnum, Debug, Clone)]
pub enum HybridPqType {
    /// ML-KEM key encapsulation
    MlKem,
    /// ML-DSA signature
    MlDsa,
    /// SLH-DSA signature
    SlhDsa,
}

/// Command-line interface arguments
#[derive(Parser, Debug, Clone)]
#[command(
    name = "certhing",
    about = "Generate X.509 certificates with classical and post-quantum cryptography",
    version,
    author
)]
pub struct Cli {
    /// Key type to use (RSA, EC, Ed, MlKem, MlDsa, SlhDsa, or Hybrid)
    #[arg(short = 't', long, value_enum, default_value = "rsa")]
    pub key_type: key_type::KeyType,

    /// RSA key size in bits (used when key-type is RSA)
    #[arg(short = 'r', long, value_enum, default_value = "size3072")]
    pub rsa_key_size: rsa_specs::RsaKeySize,

    /// Elliptic curve to use (used when key-type is EC or Ed)
    #[arg(short = 'e', long, value_enum, default_value = "p256")]
    pub ec_curve: ec_specs::EcCurve,
    
    /// ML-KEM parameter set (used when key-type is MlKem)
    #[arg(long, value_enum, default_value = "kem512")]
    pub ml_kem_params: ml_kem_specs::MlKemParams,
    
    /// ML-DSA parameter set (used when key-type is MlDsa)
    #[arg(long, value_enum, default_value = "dsa44")]
    pub ml_dsa_params: ml_dsa_specs::MlDsaParams,
    
    /// SLH-DSA hash algorithm (used when key-type is SlhDsa)
    #[arg(long, value_enum, default_value = "sha2")]
    pub slh_dsa_hash_alg: SlhDsaHashAlg,
    
    /// SLH-DSA parameter size (used when key-type is SlhDsa)
    #[arg(long, value_enum, default_value = "size128")]
    pub slh_dsa_param_size: SlhDsaParamSize,
    
    /// SLH-DSA form (used when key-type is SlhDsa)
    #[arg(long, value_enum, default_value = "small")]
    pub slh_dsa_form: SlhDsaForm,
    
    /// Classical algorithm to use in hybrid mode
    #[arg(long, value_enum, default_value = "rsa")]
    pub hybrid_classical_type: HybridClassicalType,
    
    /// Post-quantum algorithm to use in hybrid mode
    #[arg(long, value_enum, default_value = "mlkem")]
    pub hybrid_pq_type: HybridPqType,
    
    /// Enable quantum-resistant mode (auto-selects appropriate PQ algorithms)
    #[arg(long)]
    pub quantum_resistant: bool,

    /// Validity period in days
    #[arg(short = 'd', long, default_value = "365")]
    pub valid_days: u32,

    /// Common Name (CN) for the certificate
    #[arg(short = 'n', long, default_value = "example.com")]
    pub common_name: String,

    /// Organization Name (O) for the certificate
    #[arg(short = 'o', long, default_value = "My Organization")]
    pub organization: String,

    /// Country Name (C) for the certificate
    #[arg(short = 'c', long, default_value = "US")]
    pub country: String,

    /// Serial number for the certificate
    #[arg(short = 's', long, default_value = "1")]
    pub serial_number: u32,

    /// Output path for the certificate
    #[arg(long, default_value = "certificate.pem")]
    pub cert_path: PathBuf,

    /// Output path for the private key
    #[arg(long, default_value = "private_key.pem")]
    pub key_path: PathBuf,

    /// Certificate type: ca, server, or client
    #[arg(long, default_value = "server")]
    pub cert_type: certificate::CertificateType,

    /// Additional domain names to include as Subject Alternative Names
    #[arg(short = 'a', long, use_value_delimiter = true, value_delimiter = ',')]
    pub alt_names: Vec<String>,

    /// Create a self-signed certificate (default) or a CA-signed certificate
    #[arg(long, default_value = "true")]
    pub self_signed: bool,

    /// Path to CA certificate for signing (required if not self-signed)
    #[arg(long)]
    pub ca_cert_path: Option<PathBuf>,

    /// Path to CA private key for signing (required if not self-signed)
    #[arg(long)]
    pub ca_key_path: Option<PathBuf>,
    
    /// Finnish security level to enforce (TL II, TL III, or TL IV)
    #[arg(long)]
    pub security_level: Option<String>,
}

impl From<Cli> for certificate::CertificateConfig {
    fn from(cli: Cli) -> Self {
        let mut key_params = create_key_params(&cli);
        
        // If quantum_resistant is enabled, automatically upgrade to hybrid mode
        if cli.quantum_resistant && !key_params.is_quantum_safe() {
            // Default to RSA + ML-KEM for encryption or RSA + ML-DSA for signing
            match cli.cert_type {
                certificate::CertificateType::Ca => {
                    // For CA certs, use a signing algorithm hybrid
                    key_params = KeyParams::new_hybrid(
                        ClassicalKeyType::Rsa(cli.rsa_key_size),
                        PostQuantumKeyType::MlDsa(cli.ml_dsa_params),
                    );
                },
                _ => {
                    // For server/client certs, use a KEM+signature hybrid
                    key_params = KeyParams::new_hybrid(
                        ClassicalKeyType::Rsa(cli.rsa_key_size),
                        PostQuantumKeyType::MlKem(cli.ml_kem_params),
                    );
                }
            }
        }
        
        // If a security level is specified, ensure the key meets that level
        if let Some(level) = &cli.security_level {
            if !key_params.meets_security_level(level) {
                panic!("Selected key parameters do not meet the required security level: {}", level);
            }
        }
        
        Self {
            key_params,
            valid_days: cli.valid_days,
            common_name: Cow::from(cli.common_name),
            organization: Cow::from(cli.organization),
            country: Cow::from(cli.country),
            serial_number: cli.serial_number,
            cert_type: cli.cert_type,
            alt_names: cli.alt_names.into_iter().map(Cow::from).collect(),
            self_signed: cli.self_signed,
            ca_cert_path: cli.ca_cert_path,
            ca_key_path: cli.ca_key_path,
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Parse command-line arguments
    let cli = Cli::parse();

    // Convert CLI arguments to certificate configuration
    let config = certificate::CertificateConfig::from(cli.clone());

    // Generate the certificate
    match builder::generate_certificate(&config) {
        Ok(bundle) => {
            // Save the certificate and key to files
            builder::save_certificate_bundle(&bundle, &cli.cert_path, &cli.key_path)?;

            println!("Certificate successfully generated!");
            println!("Certificate saved to: {}", cli.cert_path.display());
            println!("Private key saved to: {}", cli.key_path.display());
            
            // Print PQ key information if present
            if let Some(pq_key) = &bundle.pq_key {
                let pq_key_path = format!("{}_pq", cli.key_path.display());
                println!("Post-quantum key saved to: {}", pq_key_path);
            }
            
            println!("\nCertificate details:");
            println!("  Type: {:?}", config.cert_type);
            println!("  Common Name: {}", config.common_name);
            println!("  Organization: {}", config.organization);
            println!("  Country: {}", config.country);
            println!("  Validity: {} days", config.valid_days);
            
            // Display key details based on key type
            match config.key_params.key_type {
                key_type::KeyType::Rsa => {
                    if let Some(size) = config.key_params.rsa_size {
                        println!("  Key Type: RSA");
                        println!("  Key Size: {} bits", size.bits());
                        println!("  Security Level: {}", config.key_params.security_level());
                    }
                },
                key_type::KeyType::Ec => {
                    if let Some(curve) = config.key_params.ec_curve {
                        println!("  Key Type: ECDSA");
                        println!("  Curve: {:?}", curve);
                        println!("  Security Level: {}", config.key_params.security_level());
                    }
                },
                key_type::KeyType::Ed => {
                    if let Some(curve) = config.key_params.ec_curve {
                        println!("  Key Type: EdDSA");
                        println!("  Curve: {:?}", curve);
                        println!("  Security Level: {}", config.key_params.security_level());
                    }
                },
                key_type::KeyType::MlKem => {
                    if let Some(params) = config.key_params.ml_kem_params {
                        println!("  Key Type: ML-KEM (Post-Quantum)");
                        println!("  Parameter Set: {}", params.param_name());
                        println!("  Security Level: {}", config.key_params.security_level());
                    }
                },
                key_type::KeyType::MlDsa => {
                    if let Some(params) = config.key_params.ml_dsa_params {
                        println!("  Key Type: ML-DSA (Post-Quantum)");
                        println!("  Parameter Set: {}", params.param_name());
                        println!("  Security Level: {}", config.key_params.security_level());
                    }
                },
                key_type::KeyType::SlhDsa => {
                    if let Some(params) = config.key_params.slh_dsa_params {
                        println!("  Key Type: SLH-DSA (Post-Quantum)");
                        println!("  Parameter Set: {}", params.param_name());
                        println!("  Security Level: {}", config.key_params.security_level());
                    }
                },
                key_type::KeyType::Hybrid => {
                    println!("  Key Type: Hybrid (Classical + Post-Quantum)");
                    
                    if let Some(config) = config.key_params.hybrid_config {
                        // Display classical algorithm
                        match config.classical_type {
                            ClassicalKeyType::Rsa(size) => {
                                println!("  Classical: RSA-{}", size.bits());
                            },
                            ClassicalKeyType::Ec(curve) => {
                                println!("  Classical: ECDSA with curve {:?}", curve);
                            },
                            ClassicalKeyType::Ed(curve) => {
                                println!("  Classical: EdDSA with curve {:?}", curve);
                            },
                        }
                        
                        // Display PQ algorithm
                        match config.pq_type {
                            PostQuantumKeyType::MlKem(params) => {
                                println!("  Post-Quantum: ML-KEM ({})", params.param_name());
                            },
                            PostQuantumKeyType::MlDsa(params) => {
                                println!("  Post-Quantum: ML-DSA ({})", params.param_name());
                            },
                            PostQuantumKeyType::SlhDsa(params) => {
                                println!("  Post-Quantum: SLH-DSA ({})", params.param_name());
                            },
                        }
                    }
                    
                    println!("  Security Level: {}", config.key_params.security_level());
                    println!("  Quantum-Resistant: Yes");
                }
            }

            if !config.alt_names.is_empty() {
                println!("  Subject Alternative Names:");
                for name in &config.alt_names {
                    println!("    - {}", name);
                }
            }

            println!(
                "  Self-Signed: {}",
                if config.self_signed { "Yes" } else { "No" }
            );

            Ok(())
        }
        Err(err) => {
            eprintln!("Error generating certificate: {}", err);
            Err(err.into())
        }
    }
}