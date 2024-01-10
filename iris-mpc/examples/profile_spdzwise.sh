#!/usr/bin/env bash

if [[ $# -gt 1 ]]; then
    echo "Usage: run_spdzwise.sh [-s]"
    exit -1
fi

args=""
if [[ $# -eq 1 ]]; then
    if [[ $1 != "-s" ]]; then
        echo "Usage: run_spdzwise.sh [-s]"
        exit -1
    fi
    args="-s"
fi

mkdir -p data
[[ -f data/db2.sqlite ]] || cargo run --release --bin create_sample_data -- -d data/db2.sqlite -i 10000 -m spdzwise

[[ -f "data/key0.der" ]] || cargo run --bin gen_cert -- -k data/key0.der -c data/cert0.der -s localhost -s party0
[[ -f "data/key1.der" ]] || cargo run --bin gen_cert -- -k data/key1.der -c data/cert1.der -s localhost -s party1
[[ -f "data/key2.der" ]] || cargo run --bin gen_cert -- -k data/key2.der -c data/cert2.der -s localhost -s party2

cargo build --profile profiling --example spdzwise
BIN=../target/profiling/examples/spdzwise

$BIN -p 0 -k data/key0.der -c examples/config.yaml -d data/db2.sqlite -i 0 $args &
$BIN -p 1 -k data/key1.der -c examples/config.yaml -d data/db2.sqlite -i 0 $args &
#$BIN -p 2 -k data/key2.der -c examples/config.yaml -d data/db0.sqlite -i 0 $args
#samply record --save-only -- $BIN -p 2 -k data/key2.der -c examples/config.yaml -d data/db0.sqlite -i 0 $args
flamegraph -- $BIN -p 2 -k data/key2.der -c examples/config.yaml -d data/db2.sqlite -i 0 $args
#valgrind --tool=callgrind --dump-instr=yes $BIN -p 2 -k data/key2.der -c examples/config.yaml -d data/db0.sqlite -i 0 $args
