# Certhing: X.509 Certificate Generator

Certhing is a modern, robust X.509 certificate generator built in Rust. It supports both classical and post-quantum cryptography while adhering to the Finnish national security classification levels (TL II, TL III, TL IV).

## Features

- **Comprehensive Key Types**
  - **RSA keys**: 2048 to 15360 bits
  - **Elliptic Curve**: NIST P-256, P-384, P-521
  - **Edwards Curve (EdDSA)**: Ed25519, Ed448
  - **Post-Quantum**: ML-KEM, ML-DSA, SLH-DSA support (NIST standards)
  - **Hybrid Mode**: Classical + Post-Quantum for transition security

- **Certificate Features**
  - Self-signed and CA-signed X.509 certificates
  - CA, server, and client certificate types
  - Subject Alternative Name (SAN) support
  - Standard-compliant PEM output

- **Security Standards**
  - Full compliance with Finnish Traficom requirements (2024)
  - Detailed security level mapping for all algorithms:
    - **TL IV (Basic)**: 128-bit security
    - **TL III (Increased)**: 192-bit security
    - **TL II (High)**: 256-bit security

- **Developer Experience**
  - Clean CLI interface with full documentation
  - Nix flake support with reproducible builds
  - Comprehensive test suite (Rust unit tests + Bash integration tests)
  - Easy library integration for Rust projects

## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/yourusername/certhing.git
cd certhing

# Build with Cargo
cargo build --release

# The binary will be in target/release/certhing
```

### With Nix

```bash
# Using the flake
nix build github:yourusername/certhing

# Or run directly
nix run github:yourusername/certhing -- --help
```

## Usage Examples

### Generate a default self-signed RSA certificate

```bash
certhing
```

This creates a self-signed certificate with:
- RSA 3072-bit key (TL IV security level)
- 365-day validity
- Server certificate type
- Default "example.com" as Common Name

### Generate an ECDSA certificate with P-384 curve (TL III security level)

```bash
certhing --key-type ec --ec-curve p384 --common-name secure.example.com
```

### Generate an EdDSA certificate with Ed25519 (TL IV security level)

```bash
certhing --key-type ed --ec-curve ed25519 --common-name ed25519.example.com
```

### Create a Certificate Authority (CA)

```bash
certhing --cert-type ca --key-type rsa --rsa-key-size size4096 \
  --common-name "Example Root CA" --organization "Example Inc" \
  --cert-path ca_cert.pem --key-path ca_key.pem
```

### Issue a certificate signed by a CA

```bash
certhing --self-signed false --ca-cert-path ca_cert.pem --ca-key-path ca_key.pem \
  --common-name server.example.com --cert-path server_cert.pem --key-path server_key.pem
```

### Generate a certificate with Subject Alternative Names

```bash
certhing --common-name example.com --alt-names www.example.com,api.example.com,mail.example.com
```

### Generate a high-security certificate (TL II)

```bash
certhing --key-type rsa --rsa-key-size size15360 --common-name secure.example.com
```

Or with elliptic curves:

```bash
certhing --key-type ec --ec-curve p521 --common-name secure.example.com
```

## Finnish Security Classification Levels

This tool supports the Finnish national security classification levels as defined by Traficom:

| Level | Description | RSA Size | EC Curve | EdDSA Curve | ML-KEM | ML-DSA | SLH-DSA |
|-------|-------------|----------|----------|-------------|--------|--------|---------|
| TL II | High        | 15360    | P-521    | -           | 1024   | 87     | 256s/f  |
| TL III| Increased   | 7680     | P-384    | Ed448       | 768    | 65     | 192s/f  |
| TL IV | Basic       | 3072     | P-256    | Ed25519     | 512    | 44     | 128s/f  |

## Development

### Running Tests

Certhing includes both Rust unit tests and Bash integration tests.

#### Using Nix

```bash
# Run Rust unit tests
nix run .#test

# Run Bash script tests
nix run .#script-tests

# Run all tests (Rust + Bash)
nix run .#all-tests

# Generate test coverage report
nix run .#coverage
```

#### Using Cargo

```bash
# Run Rust unit tests
cargo test

# Run Bash script tests (requires certhing binary in PATH)
chmod +x tests/scripts/*.sh
./tests/scripts/basic_tests.sh
./tests/scripts/cert_chain_tests.sh
./tests/scripts/security_level_tests.sh
./tests/scripts/web_server_test.sh
```

### Dependencies

- **Rust 1.70+** (with OpenSSL support)
- **OpenSSL 1.1.1+** or **OpenSSL 3.0+**
- **liboqs** (for post-quantum cryptography support)

## Library Usage

The tool can also be used as a Rust library:

```rust
use certhing::{
    CertificateConfig, KeyParams, EcCurve, CertificateType,
    generate_certificate, save_certificate_bundle,
};
use beef::lean::Cow;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create an EC key with P-256 curve
    let key_params = KeyParams::new_ec(EcCurve::P256);
    
    // Configure the certificate
    let config = CertificateConfig {
        key_params,
        valid_days: 365,
        common_name: Cow::from("api.example.com"),
        organization: Cow::from("Example Inc"),
        country: Cow::from("FI"),
        serial_number: 1,
        cert_type: CertificateType::Server,
        alt_names: vec![Cow::from("api-v2.example.com")],
        self_signed: true,
        ca_cert_path: None,
        ca_key_path: None,
    };
    
    // Generate the certificate
    let bundle = generate_certificate(&config)?;
    
    // Save the certificate and key
    save_certificate_bundle(&bundle, "cert.pem", "key.pem")?;
    
    Ok(())
}
```

## Post-Quantum Cryptography

Certhing supports NIST-standardized post-quantum algorithms:

- **ML-KEM** (Module-Lattice Key Encapsulation Mechanism, FIPS 203)
- **ML-DSA** (Module-Lattice Digital Signature Algorithm, FIPS 204) 
- **SLH-DSA** (Stateless Hash-Based Digital Signature Algorithm, FIPS 205)

These are available in hybrid mode, combining classical and post-quantum cryptography for transition security as recommended by Traficom.

## License

MIT

## Credits

This tool was developed following the Finnish national cryptographic guidelines published by Traficom and incorporates recommendations from the Kansallinen Kryptotyöryhmä (Finnish National Cryptography Working Group).