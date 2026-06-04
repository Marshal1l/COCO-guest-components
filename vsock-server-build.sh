#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../scripts/lib/coco_paths.sh"

coco_require_cmd cargo "$COCO_MUSL_CC"
(
    cd "$SCRIPT_DIR"
    export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER="$COCO_MUSL_CC"
    cargo build --package confidential-data-hub --bin vsock-ttrpc-server --target "$COCO_RUST_TARGET" --release
)

dst="$COCO_GUEST_COMPONENTS_ARTIFACTS_DIR/bin/vsock-ttrpc-server"
coco_install_exe "$SCRIPT_DIR/target/$COCO_RUST_TARGET/release/vsock-ttrpc-server" "$dst"
coco_strip_exe "$dst"
