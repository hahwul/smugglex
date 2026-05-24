default:
    @echo "Listing available tasks..."
    @just --list

test:
    cargo test

test_all:
    cargo test -- --include-ignored

#fix:
#    cargo fmt
#    cargo clippy --fix --allow-dirty

build:
    cargo build --release

dev:
    cargo build

# End-to-end validation: runs smugglex against a set of local mock backends
# that simulate canonical FP and TP smuggling scenarios. Requires a release
# build (auto-built by the harness if missing).
lab:
    cargo build --release
    python3 lab/validate.py
