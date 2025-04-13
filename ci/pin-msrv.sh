#!/bin/bash

set -x
set -euo pipefail

# Pin dependencies for MSRV

# To pin deps, switch toolchain to MSRV and execute the below updates

# cargo clean
# rustup override set 1.75.0
# rm Cargo.lock
# cargo update

cargo update -p home --precise "0.5.9"
cargo update -p native-tls --precise "0.2.13"
cargo update -p idna_adapter --precise "1.1.0"
cargo update -p minreq --precise "2.13.2"
