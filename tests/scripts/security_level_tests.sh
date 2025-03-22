#!/usr/bin/env bash
# Security level tests for the certhing binary according to Finnish standards

set -e # Exit on any error
set -u # Error on undefined variables

# Configure colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test directory
TEST_DIR=$(mktemp -d -t certhing-security-tests-XXXXXX)
echo -e "${YELLOW}Using test directory: ${TEST_DIR}${NC}"
cd "$TEST_DIR"

# Function to clean up test files
cleanup() {
    echo -e "${YELLOW}Cleaning up test directory...${NC}"
    rm -rf "$TEST_DIR"
}

# Register cleanup on exit
trap cleanup EXIT

# Function to run tests
run_test() {
    local test_name="$1"
    local command="$2"
    
    echo -e "${YELLOW}Running test: ${test_name}${NC}"
    
    if eval "$command"; then
        echo -e "${GREEN}✓ Test passed: ${test_name}${NC}"
        return 0
    else
        echo -e "${RED}✗ Test failed: ${test_name}${NC}"
        return 1
    }
}

# Check if certhing is available
if ! command -v certhing &> /dev/null; then
    echo -e "${RED}Error: certhing command not found. Is it installed and in your PATH?${NC}"
    exit 1
fi

# Check if OpenSSL is available
if ! command -v openssl &> /dev/null; then
    echo -e "${RED}Error: OpenSSL command not found. It's required for these tests.${NC}"
    exit 1
fi

# Display certhing version
echo -e "${YELLOW}Certhing version:${NC}"
certhing --version

# Finnish security classification levels tests
echo -e "${BLUE}===== Testing Finnish Security Classification Levels =====\n TL IV: Basic (128-bit) \n TL III: Increased (192-bit) \n TL II: High (256-bit) \n${NC}"

# TL IV level tests (Basic security - 128-bit)
echo -e "${BLUE}===== TL IV (Basic) Security Level Tests =====${NC}"

echo -e "${YELLOW}Creating RSA-3072 certificate (TL IV)...${NC}"
run_test "Create RSA-3072" "certhing --key-type rsa --rsa-key-size size3072 --common-name 'tliv-rsa.example.com' --cert-path tliv_rsa.pem --key-path tliv_rsa_key.pem"
run_test "Verify RSA-3072 Key Size" "openssl x509 -in tliv_rsa.pem -text -noout | grep -q 'RSA Public-Key: (3072 bit)'"

echo -e "${YELLOW}Creating ECDSA P-256 certificate (TL IV)...${NC}"
run_test "Create ECDSA P-256" "certhing --key-type ec --ec-curve p256 --common-name 'tliv-ec.example.com' --cert-path tliv_ec.pem --key-path tliv_ec_key.pem"
run_test "Verify ECDSA P-256 Curve" "openssl x509 -in tliv_ec.pem -text -noout | grep -q 'NIST CURVE: P-256'"

echo -e "${YELLOW}Creating Ed25519 certificate (TL IV)...${NC}"
run_test "Create Ed25519" "certhing --key-type ed --ec-curve ed25519 --common-name 'tliv-ed25519.example.com' --cert-path tliv_ed25519.pem --key-path tliv_ed25519_key.pem"
run_test_result=0
if openssl x509 -in tliv_ed25519.pem -text -noout | grep -q 'ED25519' || openssl x509 -in tliv_ed25519.pem -text -noout | grep -q 'Ed25519'; then
    echo -e "${GREEN}✓ Test passed: Verify Ed25519 Key Type${NC}"
else
    echo -e "${RED}✗ Test failed: Verify Ed25519 Key Type${NC}"
    run_test_result=1
fi

# TL III level tests (Increased security - 192-bit)
echo -e "${BLUE}\n===== TL III (Increased) Security Level Tests =====${NC}"

echo -e "${YELLOW}Creating RSA-7680 certificate (TL III)...${NC}"
run_test "Create RSA-7680" "certhing --key-type rsa --rsa-key-size size7680 --common-name 'tliii-rsa.example.com' --cert-path tliii_rsa.pem --key-path tliii_rsa_key.pem"
run_test "Verify RSA-7680 Key Size" "openssl x509 -in tliii_rsa.pem -text -noout | grep -q 'RSA Public-Key: (7680 bit)'"

echo -e "${YELLOW}Creating ECDSA P-384 certificate (TL III)...${NC}"
run_test "Create ECDSA P-384" "certhing --key-type ec --ec-curve p384 --common-name 'tliii-ec.example.com' --cert-path tliii_ec.pem --key-path tliii_ec_key.pem"
run_test "Verify ECDSA P-384 Curve" "openssl x509 -in tliii_ec.pem -text -noout | grep -q 'NIST CURVE: P-384'"

echo -e "${YELLOW}Creating Ed448 certificate (TL III)...${NC}"
run_test "Create Ed448" "certhing --key-type ed --ec-curve ed448 --common-name 'tliii-ed448.example.com' --cert-path tliii_ed448.pem --key-path tliii_ed448_key.pem"
run_test_result=0
if openssl x509 -in tliii_ed448.pem -text -noout | grep -q 'ED448' || openssl x509 -in tliii_ed448.pem -text -noout | grep -q 'Ed448'; then
    echo -e "${GREEN}✓ Test passed: Verify Ed448 Key Type${NC}"
else
    echo -e "${RED}✗ Test failed: Verify Ed448 Key Type${NC}"
    run_test_result=1
fi

# TL II level tests (High security - 256-bit)
echo -e "${BLUE}\n===== TL II (High) Security Level Tests =====${NC}"

echo -e "${YELLOW}Creating RSA-15360 certificate (TL II)...${NC}"
# Note: This may take a long time due to large key size
echo -e "${YELLOW}Note: RSA-15360 key generation may take several minutes...${NC}"
run_test "Create RSA-15360" "certhing --key-type rsa --rsa-key-size size15360 --common-name 'tlii-rsa.example.com' --cert-path tlii_rsa.pem --key-path tlii_rsa_key.pem"
run_test "Verify RSA-15360 Key Size" "openssl x509 -in tlii_rsa.pem -text -noout | grep -q 'RSA Public-Key: (15360 bit)'"

echo -e "${YELLOW}Creating ECDSA P-521 certificate (TL II)...${NC}"
run_test "Create ECDSA P-521" "certhing --key-type ec --ec-curve p521 --common-name 'tlii-ec.example.com' --cert-path tlii_ec.pem --key-path tlii_ec_key.pem"
run_test "Verify ECDSA P-521 Curve" "openssl x509 -in tlii_ec.pem -text -noout | grep -q 'NIST CURVE: P-521'"

# Verify signature algorithms match security levels
echo -e "${BLUE}\n===== Verifying Signature Algorithms =====${NC}"

# Extract signature algorithms with OpenSSL
echo -e "${YELLOW}Checking signature algorithms...${NC}"
TLIV_RSA_SIG=$(openssl x509 -in tliv_rsa.pem -text -noout | grep "Signature Algorithm" | head -1)
TLIII_RSA_SIG=$(openssl x509 -in tliii_rsa.pem -text -noout | grep "Signature Algorithm" | head -1)
TLII_RSA_SIG=$(openssl x509 -in tlii_rsa.pem -text -noout | grep "Signature Algorithm" | head -1)

TLIV_EC_SIG=$(openssl x509 -in tliv_ec.pem -text -noout | grep "Signature Algorithm" | head -1)
TLIII_EC_SIG=$(openssl x509 -in tliii_ec.pem -text -noout | grep "Signature Algorithm" | head -1)
TLII_EC_SIG=$(openssl x509 -in tlii_ec.pem -text -noout | grep "Signature Algorithm" | head -1)

echo "TL IV RSA signature: $TLIV_RSA_SIG"
echo "TL III RSA signature: $TLIII_RSA_SIG"
echo "TL II RSA signature: $TLII_RSA_SIG"
echo "TL IV EC signature: $TLIV_EC_SIG"
echo "TL III EC signature: $TLIII_EC_SIG"
echo "TL II EC signature: $TLII_EC_SIG"

# Check that the signature algorithms are appropriate for the security levels
# TL IV should use SHA-256, TL III should use SHA-384, TL II should use SHA-512
run_test "TL IV RSA uses SHA-256" "echo '$TLIV_RSA_SIG' | grep -q 'sha256'"
run_test "TL III RSA uses SHA-384" "echo '$TLIII_RSA_SIG' | grep -q 'sha384'"
run_test "TL II RSA uses SHA-512" "echo '$TLII_RSA_SIG' | grep -q 'sha512'"

run_test "TL IV EC uses SHA-256" "echo '$TLIV_EC_SIG' | grep -q 'sha256'"
run_test "TL III EC uses SHA-384" "echo '$TLIII_EC_SIG' | grep -q 'sha384'"
run_test "TL II EC uses SHA-512" "echo '$TLII_EC_SIG' | grep -q 'sha512'"

# Verify all files exist
echo -e "${BLUE}\n===== Checking Certificate Files =====${NC}"
run_test "TL IV Files Exist" "[ -s tliv_rsa.pem ] && [ -s tliv_rsa_key.pem ] && [ -s tliv_ec.pem ] && [ -s tliv_ec_key.pem ] && [ -s tliv_ed25519.pem ] && [ -s tliv_ed25519_key.pem ]"
run_test "TL III Files Exist" "[ -s tliii_rsa.pem ] && [ -s tliii_rsa_key.pem ] && [ -s tliii_ec.pem ] && [ -s tliii_ec_key.pem ] && [ -s tliii_ed448.pem ] && [ -s tliii_ed448_key.pem ]"
run_test "TL II Files Exist" "[ -s tlii_rsa.pem ] && [ -s tlii_rsa_key.pem ] && [ -s tlii_ec.pem ] && [ -s tlii_ec_key.pem ]"

echo -e "${GREEN}All security level tests completed!${NC}"
exit 0