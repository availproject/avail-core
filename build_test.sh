#!/bin/bash
set -x

cd core

# Core
cargo check
cargo check --no-default-features
cargo check --no-default-features --features "serde"
cargo check --no-default-features --features "std"
cargo check --no-default-features --features "std, serde"
cargo check --target wasm32-unknown-unknown --no-default-features
cargo check --target wasm32-unknown-unknown --no-default-features --features "serde"
cargo check --target wasm32-unknown-unknown --no-default-features --features "runtime"
cargo check --target wasm32-unknown-unknown --no-default-features --features "runtime, serde"

# Kate
cd ../kate
cargo check
cargo check --no-default-features
cargo check --no-default-features --features "serde"
cargo check --no-default-features --features "std"
cargo check --no-default-features --features "std, serde"
cargo check --target wasm32-unknown-unknown --no-default-features
cargo check --target wasm32-unknown-unknown --no-default-features --features "serde"

# Kate Recovery
cd ../recovery
cargo check
cargo check --no-default-features
cargo check --no-default-features --features "serde"
cargo check --no-default-features --features "std"
cargo check --no-default-features --features "std, serde"
cargo check --target wasm32-unknown-unknown --no-default-features
cargo check --target wasm32-unknown-unknown --no-default-features --features "serde"
