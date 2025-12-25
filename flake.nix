{
  description = "Rust-powered HTTP Request Smuggling Scanner";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, flake-utils, rust-overlay }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs {
          inherit system overlays;
        };

        rustToolchain = pkgs.rust-bin.stable.latest.default;

        rustPlatform = pkgs.makeRustPlatform {
          cargo = rustToolchain;
          rustc = rustToolchain;
        };
      in
      {
        packages = {
          smugglex = rustPlatform.buildRustPackage {
            pname = "smugglex";
            # Note: Version should be updated manually when releasing new versions
            version = "0.1.0";

            src = ./.;

            cargoLock = {
              lockFile = ./Cargo.lock;
            };

            nativeBuildInputs = with pkgs; [
              pkg-config
            ];

            # smugglex uses rustls instead of OpenSSL, so no additional buildInputs needed
            # Only macOS-specific frameworks are required
            buildInputs = pkgs.lib.optionals pkgs.stdenv.isDarwin (with pkgs.darwin.apple_sdk.frameworks; [
              Security
              SystemConfiguration
            ]);

            meta = with pkgs.lib; {
              description = "Rust-powered HTTP Request Smuggling Scanner";
              homepage = "https://github.com/hahwul/smugglex";
              license = licenses.mit;
              maintainers = [ ];
              mainProgram = "smugglex";
            };
          };

          default = self.packages.${system}.smugglex;
        };

        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            rustToolchain
            pkg-config
            cargo-watch
            rust-analyzer
          ];

          shellHook = ''
            echo "smugglex development environment"
            echo "Run 'cargo build' to build the project"
            echo "Run 'cargo run' to run the project"
          '';
        };

        apps = {
          smugglex = flake-utils.lib.mkApp {
            drv = self.packages.${system}.smugglex;
          };
          default = self.apps.${system}.smugglex;
        };
      }
    );
}
