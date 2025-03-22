{
  description = "X509 Certificate Generator using Rust and OpenSSL with Post-Quantum Cryptography support";
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs = {
        nixpkgs.follows = "nixpkgs";
        flake-utils.follows = "flake-utils";
      };
    };
    naersk = {
      url = "github:nix-community/naersk";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };
  
  outputs = { self, nixpkgs, flake-utils, rust-overlay, naersk }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        # Create custom overlay for liboqs with specific algorithm support
        liboqsOverlay = final: prev: {
          liboqs = prev.liboqs.overrideAttrs (oldAttrs: {
            cmakeFlags = [
              "-DBUILD_SHARED_LIBS=ON"
              "-DOQS_DIST_BUILD=ON"
              "-DOQS_BUILD_ONLY_LIB=ON"
              # Enable only NIST-standardized algorithms
              "-DOQS_ENABLE_KEM_kyber=ON"      # ML-KEM (formerly Kyber)
              "-DOQS_ENABLE_SIG_dilithium=ON"  # ML-DSA (formerly Dilithium)
              "-DOQS_ENABLE_SIG_sphincs=ON"    # SLH-DSA (formerly SPHINCS+)
              # Disable other algorithms
              "-DOQS_ENABLE_KEM_classic_mceliece=OFF"
              "-DOQS_ENABLE_KEM_hqc=OFF"
              "-DOQS_ENABLE_SIG_falcon=OFF"
            ];
          });
        };
        
        overlays = [
          (import rust-overlay)
          liboqsOverlay
        ];
        
        pkgs = import nixpkgs {
          inherit system overlays;
        };
        
        # Explicitly use Rust from Oxalica's overlay
        rustVersion = pkgs.rust-bin.stable.latest.default;
        
        # Configure Rust with OpenSSL support
        rustWithOpenSSL = rustVersion.override {
          extensions = [ "rust-src" "rust-std" ];
          targets = [ ];
        };
        
        # Use the pre-configured liboqs package from nixpkgs with our overlay
        liboqs = pkgs.liboqs;
        
        # Configure naersk to use our Rust from Oxalica
        naersk-lib = naersk.lib."${system}".override {
          cargo = rustWithOpenSSL;
          rustc = rustWithOpenSSL;
        };
        
        # Package name and metadata
        packageName = "certhing";
        version = "0.1.0";
        
        # Common environment variables
        commonEnvVars = {
          OPENSSL_DIR = "${pkgs.openssl.dev}";
          OPENSSL_LIB_DIR = "${pkgs.openssl.out}/lib";
          RUST_BACKTRACE = "1";
          # Add liboqs environment variables
          LIBOQS_INCLUDE_DIR = "${liboqs}/include";
          LIBOQS_LIB_DIR = "${liboqs}/lib";
          # Add pkg-config path to help find liboqs
          PKG_CONFIG_PATH = "${liboqs}/lib/pkgconfig:$PKG_CONFIG_PATH";
          # Add library path for runtime loading
          LD_LIBRARY_PATH = "${liboqs}/lib:${pkgs.openssl.out}/lib";
        };
        
        # Common build inputs
        commonBuildInputs = [
          pkgs.openssl
          pkgs.openssl.dev
          pkgs.pkg-config
          liboqs
          # Add clang dependencies
          pkgs.clang
          pkgs.llvmPackages.libclang
        ];
        
        rustPackage = naersk-lib.buildPackage {
          pname = packageName;
          version = version;
          src = ./.;
          
          nativeBuildInputs = [
            pkgs.pkg-config
            pkgs.cmake  # For building native dependencies
            pkgs.ninja  # For faster builds with cmake
            rustWithOpenSSL
          ];
          
          buildInputs = commonBuildInputs;
          
          # Environment variables to help find OpenSSL and liboqs
          inherit (commonEnvVars) OPENSSL_DIR OPENSSL_LIB_DIR LIBOQS_INCLUDE_DIR LIBOQS_LIB_DIR PKG_CONFIG_PATH;
          
          # Add LIBCLANG_PATH for bindgen if used
          LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";
          
          # Enable test execution during the build phase only
          doCheck = true;
          
          # Let naersk handle the cargo test options with its defaults
          
          # Post-installation steps
          postInstall = ''
            mkdir -p $out/share/doc/${packageName}
            cp README.md $out/share/doc/${packageName}/ || true
          '';
        };
        
      in {
        # Default package
        packages.default = rustPackage;
        
        # Expose the package with its name too
        packages.${packageName} = rustPackage;
        
        # Expose liboqs as a separate package
        packages.liboqs = liboqs;
        
        # For convenience, expose the specific Rust used
        packages.rustToolchain = rustWithOpenSSL;
        
        # Add an explicit test runner that uses the built package
        packages.test = pkgs.writeShellApplication {
          name = "run-tests";
          runtimeInputs = [ rustWithOpenSSL rustPackage ];
          text = ''
            set -e
            cd ${self}
            export ${builtins.concatStringsSep " " (builtins.attrValues (builtins.mapAttrs (name: value: "${name}=${value}") commonEnvVars))}
            
            echo "🧪 Running Rust tests for ${packageName} using the built binary..."
            # Use the built binary in tests
            echo "Using binary: $(which ${packageName})"
            echo "Binary version: $(${packageName} --version)"
            
            # Run tests against the source but with access to the built binary
            cargo test --all --all-features
            
            echo "✅ All tests passed!"
          '';
        };
        
        # Add a script-based test runner
        packages.script-tests = pkgs.writeShellApplication {
          name = "run-script-tests";
          runtimeInputs = [ 
            rustPackage
            pkgs.bash
            pkgs.coreutils
            pkgs.gnugrep
            pkgs.curl
            pkgs.openssl
          ];
          text = ''
            set -e
            cd ${self}
            export PATH="${rustPackage}/bin:$PATH"
            
            # Make scripts executable
            chmod +x tests/scripts/*.sh
            
            echo "🧪 Running bash script tests for ${packageName}..."
            echo "Using binary: $(which ${packageName})"
            echo "Binary version: $(${packageName} --version)"
            
            FAILED_TESTS=0
            
            # Run all test scripts in sequence
            for script in tests/scripts/*.sh; do
              echo ""
              echo "=================================================================================="
              echo "Running $script..."
              echo "=================================================================================="
              if $script; then
                echo "✅ Test script $script passed!"
              else
                echo "❌ Test script $script FAILED!"
                FAILED_TESTS=$((FAILED_TESTS + 1))
              fi
              echo ""
            done
            
            if [ $FAILED_TESTS -eq 0 ]; then
              echo "✅ All script tests passed!"
              exit 0
            else
              echo "❌ $FAILED_TESTS script tests failed!"
              exit 1
            fi
          '';
        };
        
        # Add a comprehensive test runner
        packages.all-tests = pkgs.writeShellApplication {
          name = "run-all-tests";
          runtimeInputs = [ 
            self.packages.${system}.test
            self.packages.${system}.script-tests
          ];
          text = ''
            set -e
            
            echo "🧪 Running all tests for ${packageName}..."
            
            # Run Rust unit tests first
            echo "==== Running Rust unit tests ===="
            run-tests
            
            # Run Bash script tests
            echo "==== Running Bash script tests ===="
            run-script-tests
            
            echo "✅ All tests completed successfully!"
          '';
        };
        
        # Add a coverage runner using cargo-tarpaulin that uses the built package
        packages.coverage = pkgs.writeShellApplication {
          name = "run-coverage";
          runtimeInputs = [ rustWithOpenSSL rustPackage pkgs.cargo-tarpaulin ];
          text = ''
            set -e
            cd ${self}
            export ${builtins.concatStringsSep " " (builtins.attrValues (builtins.mapAttrs (name: value: "${name}=${value}") commonEnvVars))}
            
            echo "📊 Running coverage analysis for ${packageName} using the built binary..."
            echo "Using binary: $(which ${packageName})"
            
            # Generate coverage using cargo-tarpaulin
            cargo tarpaulin --out Xml --output-dir ./target/coverage
            
            echo "✅ Coverage report generated in ./target/coverage"
          '';
        };
        
        # Add a helper to install test scripts
        packages.install-test-scripts = pkgs.writeShellApplication {
          name = "install-test-scripts";
          text = ''
            set -e
            
            # Create bin directory if it doesn't exist
            mkdir -p $out/bin
            
            # Copy and make executable all test scripts
            for script in ${self}/tests/scripts/*.sh; do
              cp "$script" $out/bin/
              chmod +x $out/bin/$(basename "$script")
              echo "Installed $(basename "$script")"
            done
            
            echo "✅ All test scripts installed to $out/bin"
          '';
        };
        
                  # Enhanced development shell with additional tools
        devShells.default = pkgs.mkShell {
          buildInputs = commonBuildInputs ++ [
            rustWithOpenSSL
            pkgs.rust-analyzer
            # Additional development tools
            pkgs.cargo-watch
            pkgs.cargo-audit
            pkgs.cargo-expand
            pkgs.cargo-tarpaulin  # For code coverage
            pkgs.cargo-nextest    # Better test runner
            pkgs.cargo-insta      # Snapshot testing
            pkgs.openssl.dev
            pkgs.cmake
            pkgs.ninja
            # Tools needed for bash scripts
            pkgs.curl
            pkgs.openssl
            # Add more development tools for post-quantum support
            pkgs.llvmPackages.clang
            pkgs.lldb  # For debugging
          ];
          
          # Environment variables for both OpenSSL and liboqs
          inherit (commonEnvVars) OPENSSL_DIR OPENSSL_LIB_DIR LIBOQS_INCLUDE_DIR LIBOQS_LIB_DIR PKG_CONFIG_PATH LD_LIBRARY_PATH RUST_BACKTRACE;
          
          # Add LIBCLANG_PATH for bindgen
          LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";
          
          # Make sure Rust Analyzer uses the same toolchain
          shellHook = ''
            export RUST_SRC_PATH=${rustWithOpenSSL}/lib/rustlib/src/rust/library
            
            # Tell rustc and cargo to use our specific Rust version
            export RUSTC="${rustWithOpenSSL}/bin/rustc"
            export CARGO="${rustWithOpenSSL}/bin/cargo"
            
            echo "🦀 Rust development environment loaded with Oxalica's Rust overlay!"
            echo "Using Rust toolchain: $(${rustWithOpenSSL}/bin/rustc --version)"
            echo ""
            echo "Post-Quantum Cryptography support enabled with liboqs!"
            echo "liboqs include path: $LIBOQS_INCLUDE_DIR"
            echo "liboqs library path: $LIBOQS_LIB_DIR"
            echo ""
            echo "Available commands:"
            echo "  • cargo test        Run all tests"
            echo "  • cargo watch -x test  Run tests on file changes"
            echo "  • cargo audit       Check dependencies for vulnerabilities"
            echo "  • cargo expand      Expand macros for debugging"
            echo "  • cargo tarpaulin   Generate test coverage reports"
            echo "  • cargo insta test  Run snapshot tests"
            echo ""
            echo "Flake commands:"
            echo "  • nix run .#test         Run Rust unit tests"
            echo "  • nix run .#script-tests Run Bash script tests"
            echo "  • nix run .#all-tests    Run all tests (Rust + Bash)"
            echo "  • nix run .#coverage     Generate coverage report"
          '';
        };
        
        # Add checks for CI integration
        checks = {
          # The main package is still built for CI, but tests are kept separate
          inherit rustPackage;
          
          # Run clippy lints
          clippy = pkgs.runCommand "clippy-check" {
            buildInputs = [ rustWithOpenSSL ];
            inherit (commonEnvVars) OPENSSL_DIR OPENSSL_LIB_DIR LIBOQS_INCLUDE_DIR LIBOQS_LIB_DIR PKG_CONFIG_PATH;
          } ''
            cd ${self}
            export PATH="${rustWithOpenSSL}/bin:$PATH"
            cargo clippy -- -D warnings
            touch $out
          '';
          
          # Run rustfmt check
          format = pkgs.runCommand "format-check" {
            buildInputs = [ rustWithOpenSSL ];
          } ''
            cd ${self}
            export PATH="${rustWithOpenSSL}/bin:$PATH"
            cargo fmt -- --check
            touch $out
          '';
        };
        
        # Add apps for easy execution with `nix run`
        apps = {
          default = flake-utils.lib.mkApp {
            drv = rustPackage;
          };
          
          test = flake-utils.lib.mkApp {
            drv = self.packages.${system}.test;
          };
          
          script-tests = flake-utils.lib.mkApp {
            drv = self.packages.${system}.script-tests;
          };
          
          all-tests = flake-utils.lib.mkApp {
            drv = self.packages.${system}.all-tests;
          };
          
          coverage = flake-utils.lib.mkApp {
            drv = self.packages.${system}.coverage;
          };
        };
      }
    );
}