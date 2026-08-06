.PHONY: all build release test lint fmt doc clean check

all: lint test doc build

build:
	cargo build

release:
	cargo build --release

check:
	cargo check --all-targets --features test-support

test:
	cargo test --features test-support

lint:
	cargo fmt --check
	cargo clippy --all-targets --features test-support -- -D warnings

fmt:
	cargo fmt

doc:
	RUSTDOCFLAGS="-D warnings" cargo doc --no-deps

clean:
	cargo clean
