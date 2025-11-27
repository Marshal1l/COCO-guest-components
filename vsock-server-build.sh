
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=aarch64-linux-musl-gcc;
cargo build --package confidential-data-hub --bin vsock-ttrpc-server --target aarch64-unknown-linux-musl --release;
