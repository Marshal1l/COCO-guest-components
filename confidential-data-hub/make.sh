#!/bin/bash
set -x
ARCH=aarch64 LIBC=musl RPC=ttrpc make build
cp ~/guest-components/target/aarch64-unknown-linux-musl/release/confidential-data-hub ~/cca/kernel-modules/guest/
cp ~/guest-components/target/aarch64-unknown-linux-musl/release/ttrpc-cdh-tool ~/cca/kernel-modules/guest/
cp ~/guest-components/target/aarch64-unknown-linux-musl/release/api-server-rest ~/cca/kernel-modules/guest/
cp ~/guest-components/target/aarch64-unknown-linux-musl/release/attestation-agent ~/cca/kernel-modules/guest/
