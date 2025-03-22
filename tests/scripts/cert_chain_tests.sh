#!/usr/bin/env bash
# Certificate chain tests for the certhing binary

set -e # Exit on any error
set -u # Error on undefined variables

# Configure colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

# Test directory
TEST_DIR=$(mktemp -d -t certhing-chain-tests-XXXXXX)
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

# Step 1: Create a Root CA
echo -e "${YELLOW}Creating Root CA certificate...${NC}"
run_test "Create Root CA" "certhing --cert-type ca --key-type rsa --rsa-key-size size4096 --common-name 'Test Root CA' --organization 'Test Org' --country 'FI' --valid-days 3650 --cert-path root_ca.pem --key-path root_ca_key.pem"

# Step 2: Create an Intermediate CA signed by the Root CA
echo -e "${YELLOW}Creating Intermediate CA certificate...${NC}"
run_test "Create Intermediate CA" "certhing --cert-type ca --key-type rsa --rsa-key-size size4096 --common-name 'Test Intermediate CA' --organization 'Test Org' --country 'FI' --valid-days 1825 --self-signed false --ca-cert-path root_ca.pem --ca-key-path root_ca_key.pem --cert-path intermediate_ca.pem --key-path intermediate_ca_key.pem"

# Step 3: Create a Server Certificate signed by the Intermediate CA
echo -e "${YELLOW}Creating Server certificate...${NC}"
run_test "Create Server Certificate" "certhing --cert-type server --key-type ec --ec-curve p256 --common-name 'server.example.com' --organization 'Test Org' --country 'FI' --valid-days 365 --alt-names www.example.com,api.example.com --self-signed false --ca-cert-path intermediate_ca.pem --ca-key-path intermediate_ca_key.pem --cert-path server_cert.pem --key-path server_key.pem"

# Step 4: Create a Client Certificate signed by the Intermediate CA
echo -e "${YELLOW}Creating Client certificate...${NC}"
run_test "Create Client Certificate" "certhing --cert-type client --key-type ec --ec-curve p256 --common-name 'client@example.com' --organization 'Test Org' --country 'FI' --valid-days 365 --self-signed false --ca-cert-path intermediate_ca.pem --ca-key-path intermediate_ca_key.pem --cert-path client_cert.pem --key-path client_key.pem"

# If OpenSSL is available, perform verification tests
if command -v openssl &> /dev/null; then
    # Create a certificate chain file
    echo -e "${YELLOW}Creating certificate chain file...${NC}"
    cat intermediate_ca.pem root_ca.pem > chain.pem
    
    # Verify the server certificate with the chain
    echo -e "${YELLOW}Verifying server certificate against the chain...${NC}"
    run_test "Server Certificate Chain Verification" "openssl verify -CAfile chain.pem server_cert.pem"
    
    # Verify the client certificate with the chain
    echo -e "${YELLOW}Verifying client certificate against the chain...${NC}"
    run_test "Client Certificate Chain Verification" "openssl verify -CAfile chain.pem client_cert.pem"
    
    # Check the certificate chain
    echo -e "${YELLOW}Checking certificate chain relationships...${NC}"
    run_test "Root CA is self-signed" "openssl x509 -in root_ca.pem -text -noout | grep -q 'Issuer: C = FI, O = Test Org, CN = Test Root CA' && openssl x509 -in root_ca.pem -text -noout | grep -q 'Subject: C = FI, O = Test Org, CN = Test Root CA'"
    run_test "Intermediate CA is signed by Root CA" "openssl x509 -in intermediate_ca.pem -text -noout | grep -q 'Issuer: C = FI, O = Test Org, CN = Test Root CA' && openssl x509 -in intermediate_ca.pem -text -noout | grep -q 'Subject: C = FI, O = Test Org, CN = Test Intermediate CA'"
    run_test "Server cert is signed by Intermediate CA" "openssl x509 -in server_cert.pem -text -noout | grep -q 'Issuer: C = FI, O = Test Org, CN = Test Intermediate CA'"
    run_test "Client cert is signed by Intermediate CA" "openssl x509 -in client_cert.pem -text -noout | grep -q 'Issuer: C = FI, O = Test Org, CN = Test Intermediate CA'"
    
    # Verify CA flags are set correctly
    echo -e "${YELLOW}Checking CA flags...${NC}"
    run_test "Root CA has CA:TRUE" "openssl x509 -in root_ca.pem -text -noout | grep -q 'CA:TRUE'"
    run_test "Intermediate CA has CA:TRUE" "openssl x509 -in intermediate_ca.pem -text -noout | grep -q 'CA:TRUE'"
    run_test "Server cert doesn't have CA:TRUE" "! openssl x509 -in server_cert.pem -text -noout | grep -q 'CA:TRUE'"
    run_test "Client cert doesn't have CA:TRUE" "! openssl x509 -in client_cert.pem -text -noout | grep -q 'CA:TRUE'"
else
    echo -e "${YELLOW}OpenSSL not found, skipping certificate verification tests.${NC}"
fi

# Verify all files exist
run_test "All Certificate Files Exist" "[ -s root_ca.pem ] && [ -s root_ca_key.pem ] && [ -s intermediate_ca.pem ] && [ -s intermediate_ca_key.pem ] && [ -s server_cert.pem ] && [ -s server_key.pem ] && [ -s client_cert.pem ] && [ -s client_key.pem ]"

echo -e "${GREEN}All certificate chain tests completed!${NC}"
exit 0