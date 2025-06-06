ARCH=aarch64 LIBC=musl RPC=ttrpc make build
cp ~/guest-components/target/aarch64-unknown-linux-musl/release/confidential-data-hub ~/cca/kernelmodules/guest/
cp ~/guest-components/target/aarch64-unknown-linux-musl/release/ttrpc-cdh-tool ~/cca/kernelmodules/guest/
cp ~/guest-components/target/aarch64-unknown-linux-musl/release/guest-image-pull.sh ~/cca/kernelmodules/guest/
cp ~/guest-components/target/aarch64-unknown-linux-musl/release/content-pull.sh ~/cca/kernelmodules/guest/
cp ~/guest-components/target/aarch64-unknown-linux-musl/release/api-server-rest ~/cca/kernelmodules/guest/
cp ~/guest-components/target/aarch64-unknown-linux-musl/release/attestation-agent ~/cca/kernelmodules/guest/
cp ~/guest-components/target/aarch64-unknown-linux-musl/release/attestation-agent.toml ~/cca/kernelmodules/guest/
cp ~/guest-components/target/aarch64-unknown-linux-musl/release/cdh.toml ~/cca/kernelmodules/guest/
cp ~/guest-components/target/aarch64-unknown-linux-musl/release/service.sh ~/cca/kernelmodules/guest/
