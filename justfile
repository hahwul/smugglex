alias b := build
alias d := dev
alias ds := docs-serve
alias t := test
alias vc := version-check
alias vu := version-update

# List available tasks.
default:
    @just --list

# Build release binary.
[group('build')]
build:
    cargo build --release

# Build debug binary.
[group('build')]
dev:
    cargo build

# Update Nix flake lock.
[group('build')]
nix-update:
    nix flake update

# Serve docs site locally.
[group('documents')]
docs-serve:
    hwaro serve -i docs --base-url="http://localhost:3000"

# Install docs dependencies (macOS).
[group('documents')]
docs-dependencies:
    brew install hahwul/hwaro/hwaro

#[group('development')]
#fix:
#    cargo fmt
#    cargo clippy --fix --allow-dirty

# Report smugglex version across Cargo.toml, Cargo.lock, flake.nix, snap, aur.
[group('release')]
version-check:
    crystal run scripts/version_check.cr

# Bump smugglex version in lockstep across all version-bearing files.
[group('release')]
version-update:
    crystal run scripts/version_update.cr

# Run unit tests.
[group('test')]
test:
    cargo test

# Run all tests including ignored ones.
[group('test')]
test_all:
    cargo test -- --include-ignored

# End-to-end validation against local mock smuggling backends.
[group('test')]
lab:
    # Runs smugglex against local mock backends simulating canonical FP/TP
    # smuggling scenarios. Requires a release build (auto-built if missing).
    cargo build --release
    python3 lab/validate.py
