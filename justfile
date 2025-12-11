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
