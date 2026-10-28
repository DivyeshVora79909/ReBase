#!/bin/bash
set -eu
cd /workspace/ReBase/rebase-next
RUSTC=/home/agent/.rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu/bin/rustc
DEPS=target/verification-build/release/deps
"$RUSTC" --edition 2021 -O -C debuginfo=0 /tmp/rebase-order-study/embedded.rs -L dependency="$DEPS" --extern redb="$DEPS/libredb-27d19c143e80fe06.rlib" --extern surrealkv="$DEPS/libsurrealkv-3615d5b58c03d5b9.rlib" --extern tokio="$DEPS/libtokio-32caac3ceb404ec1.rlib" -o /tmp/rebase-order-study/embedded
"$RUSTC" --edition 2021 -O -C debuginfo=0 /tmp/rebase-order-study/fdb.rs -L dependency="$DEPS" -L native=target/g7-environment/lib --extern foundationdb="$DEPS/libfoundationdb-15ab8285f6673f88.rlib" --extern futures="$DEPS/libfutures-972f3eb9f1e8a0a3.rlib" -o /tmp/rebase-order-study/fdb
