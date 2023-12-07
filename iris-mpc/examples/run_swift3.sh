#!/usr/bin/env bash

if [[ $# -gt 1 ]]; then
    echo "Usage: run_swift3.sh [-s]"
    exit -1
fi

args=""
if [[ $# -eq 1 ]]; then
    if [[ $1 != "-s" ]]; then
        echo "Usage: run_swift3.sh [-s]"
        exit -1
    fi
    args="-s"
fi

mkdir -p data
[[ -f data/db1.sqlite ]] || cargo run --release --bin create_sample_data -- -d data/db1.sqlite -i 10000 -m swift3

[[ -f "data/key0.der" ]] || cargo run --bin gen_cert -- -k data/key0.der -c data/cert0.der -s localhost -s party0
[[ -f "data/key1.der" ]] || cargo run --bin gen_cert -- -k data/key1.der -c data/cert1.der -s localhost -s party1
[[ -f "data/key2.der" ]] || cargo run --bin gen_cert -- -k data/key2.der -c data/cert2.der -s localhost -s party2

cargo run --release --example swift3 -- -p 0 -k data/key0.der -c examples/config.yaml -d data/db1.sqlite -i 0 $args &
cargo run --release --example swift3 -- -p 1 -k data/key1.der -c examples/config.yaml -d data/db1.sqlite -i 0 $args &
cargo run --release --example swift3 -- -p 2 -k data/key2.der -c examples/config.yaml -d data/db1.sqlite -i 0 $args

#RUST_LOG="trace" cargo run --release --example swift3 -- -p 0 -k data/key0.der -c examples/config.yaml -d data/db1.sqlite -i 0 $args | sed -r "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2};?)?)?[mGK]//g" > out0.log&
#RUST_LOG="trace" cargo run --release --example swift3 -- -p 1 -k data/key1.der -c examples/config.yaml -d data/db1.sqlite -i 0 $args | sed -r "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2};?)?)?[mGK]//g"> out1.log&
#RUST_LOG="trace" cargo run --release --example swift3 -- -p 2 -k data/key2.der -c examples/config.yaml -d data/db1.sqlite -i 0 $args | sed -r "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2};?)?)?[mGK]//g"> out2.log
#CARGO_PROFILE_RELEASE_DEBUG=true cargo flamegraph --example swift3 -- -p 2 -k data/key2.der -c examples/config.yaml -d data/db1.sqlite -i 0 $args
