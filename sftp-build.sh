set -x
CC=aarch64-linux-musl-gcc ARCH=aarch64 LIBC=musl make build TEE_PLATFORM=cca;
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=aarch64-linux-musl-gcc;
cargo build --package confidential-data-hub --bin ttrpc-cdh-tool --target aarch64-unknown-linux-musl --release;
cargo build --package confidential-data-hub --bin vsock-ttrpc-server --target aarch64-unknown-linux-musl --release;
cp ./target/aarch64-unknown-linux-musl/release/api-server-rest ~/cca-sbsa/SFTP_folder/guest-component-bins/
cp ./target/aarch64-unknown-linux-musl/release/confidential-data-hub ~/cca-sbsa/SFTP_folder/guest-component-bins/
cp ./target/aarch64-unknown-linux-musl/release/attestation-agent ~/cca-sbsa/SFTP_folder/guest-component-bins/
cp ./target/aarch64-unknown-linux-musl/release/ttrpc-cdh-tool ~/cca-sbsa/SFTP_folder/guest-component-bins/
cp ./target/aarch64-unknown-linux-musl/release/vsock-ttrpc-server ~/cca-sbsa/SFTP_folder/guest-component-bins/
