#!/usr/bin/env bash
# Basic functionality tests for the certhing binary

set -e # Exit on any error
set -u # Error on undefined variables

# Configure colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

# Test directory
TEST_DIR=$(mktemp -d -t certhing-basic-tests-XXXXXX)
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

# Display certhing version
echo -e "${YELLOW}Certhing version:${NC}"
certhing --version

# Test 1: Default Certificate Generation
run_test "Default Certificate Generation" "certhing --cert-path default_cert.pem --key-path default_key.pem"

# Test 2: Create RSA Certificate with 4096-bit key
run_test "RSA 4096-bit Certificate" "certhing --key-type rsa --rsa-key-size size4096 --common-name rsa4096.example.com --cert-path rsa4096_cert.pem --key-path rsa4096_key.pem"

# Test 3: Create ECDSA Certificate with P-384 curve
run_test "ECDSA P-384 Certificate" "certhing --key-type ec --ec-curve p384 --common-name ecdsa384.example.com --cert-path ecdsa384_cert.pem --key-path ecdsa384_key.pem"

# Test 4: Create EdDSA Certificate with Ed25519
run_test "EdDSA Ed25519 Certificate" "certhing --key-type ed --ec-curve ed25519 --common-name ed25519.example.com --cert-path ed25519_cert.pem --key-path ed25519_key.pem"

# Test 5: Create a CA Certificate
run_test "CA Certificate" "certhing --cert-type ca --common-name 'Test Root CA' --organization 'Test Organization' --cert-path ca_cert.pem --key-path ca_key.pem"

# Test 6: Create Server Certificate with Alt Names
run_test "Server Certificate with Alt Names" "certhing --common-name server.example.com --alt-names www.example.com,api.example.com --cert-path server_cert.pem --key-path server_key.pem"

# Test 7: Verify certificate contents with OpenSSL if available
if command -v openssl &> /dev/null; then
    run_test "OpenSSL Verification of Default Certificate" "openssl x509 -in default_cert.pem -text -noout | grep -q 'Subject: CN = example.com'"
    run_test "OpenSSL Verification of RSA Key Size" "openssl x509 -in rsa4096_cert.pem -text -noout | grep -q 'RSA Public-Key: (4096 bit)'"
    run_test "OpenSSL Verification of ECDSA Curve" "openssl x509 -in ecdsa384_cert.pem -text -noout | grep -q 'NIST CURVE: P-384'"
    
    # Check cert validity period
    run_test "Certificate Validity Period" "openssl x509 -in default_cert.pem -text -noout | grep -q 'Not After' && openssl x509 -in default_cert.pem -text -noout | grep -q 'Not Before'"
else
    echo -e "${YELLOW}OpenSSL not found, skipping certificate verification tests.${NC}"
fi

# Test 8: Verify files exist and are not empty
run_test "Certificate Files Existence" "[ -s default_cert.pem ] && [ -s default_key.pem ]"
run_test "RSA Certificate Files Existence" "[ -s rsa4096_cert.pem ] && [ -s rsa4096_key.pem ]"
run_test "ECDSA Certificate Files Existence" "[ -s ecdsa384_cert.pem ] && [ -s ecdsa384_key.pem ]"
run_test "EdDSA Certificate Files Existence" "[ -s ed25519_cert.pem ] && [ -s ed25519_key.pem ]"
run_test "CA Certificate Files Existence" "[ -s ca_cert.pem ] && [ -s ca_key.pem ]"
run_test "Server Certificate Files Existence" "[ -s server_cert.pem ] && [ -s server_key.pem ]"

# Test 9: Verify PEM format (contains BEGIN/END markers)
run_test "Certificate PEM Format" "grep -q 'BEGIN CERTIFICATE' default_cert.pem && grep -q 'END CERTIFICATE' default_cert.pem"
run_test "Key PEM Format" "grep -q 'BEGIN PRIVATE KEY' default_key.pem && grep -q 'END PRIVATE KEY' default_key.pem"

echo -e "${GREEN}All basic tests completed!${NC}"
exit 0