# Because we will forget... Makefile requires 'tab' before command line call.

# Test suite, define all our tests here
test: build
	cargo test

# Build all the things
build:
	cargo build
# Upgrade the dependencies
upgrade:
	cargo update --aggressive


clean:
	cargo clean

lint:
	cargo fmt --all
	cargo clippy --fix --allow-dirty -- -W clippy::pedantic