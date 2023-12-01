#!/usr/bin/env bash

mkdir data
[[ -f "data/key0.der" ]] || cargo run --bin gen_cert -- -k data/key0.der -c data/cert0.der -s localhost -s party0
[[ -f "data/key1.der" ]] || cargo run --bin gen_cert -- -k data/key1.der -c data/cert1.der -s localhost -s party1
[[ -f "data/key2.der" ]] || cargo run --bin gen_cert -- -k data/key2.der -c data/cert2.der -s localhost -s party2
cargo run --example aby3 -- -p 0 -k data/key0.der -c examples/config.yaml &
cargo run --example aby3 -- -p 1 -k data/key1.der -c examples/config.yaml &
cargo run --example aby3 -- -p 2 -k data/key2.der -c examples/config.yaml
