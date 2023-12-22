# Experiments for Decentralized Iris Code Membership Protocols using MPC

**Disclaimer: This repository is a heavy work-in-progress and contains unfinished protocols, unoptimized code and minimal documentation.**

This is the repository containing code and benchmarking harnesses for _decentralized iris code membership protocols_ using secure multiparty computation.

## Table of Contents

- [Experiments for Decentralized Iris Code Membership Protocols using MPC](#experiments-for-decentralized-iris-code-membership-protocols-using-mpc)
  - [Table of Contents](#table-of-contents)
  - [Dependencies](#dependencies)
  - [Repository Structure](#repository-structure)
    - [Implemented MPC protocols](#implemented-mpc-protocols)
  - [Examples \& Benchmarks](#examples--benchmarks)
  - [TODOs](#todos)

## Dependencies

- `Rust 1.75` (currently in beta, will release on 28-12-2023)
  - We use this version because we are using `async fn` in traits, which is only stabilized in this version.
  - If you are using cargo & rustup, the included rust-toolchain file will automatically download and use this version.
  - Maybe because this is still in Beta, `rust-analyzer` gets a bit confused and your editor will sometimes report errors where there are none, hopefully this will be better in a few weeks, once it is stable.

## Repository Structure

The repository consists of 3 crates.

- [`iris-mpc`](iris-mpc): Implementation of various base MPC protocol functionality, as well as implementations of iris code membership using said protocols.
- [`plain-reference`](plain-reference): Implementation of the Iris Code Matching functionality in plain Rust, to serve as a comparison point for the MPC functionality.
  - Also contains a binary for genration of test data, which is stored in a SQlite DB for uses in tests/examples.
- [`mpc-net`](mpc-net): Implementation of networking used in the MPC protocols
  - Uses QUIC as the underlying transport protocol, which also captures the overhead of TLS for connections between parties.
  - Also contains a binary for generation of the required self-signed TLS certificates for testing.

### Implemented MPC protocols

We are investigating several different MPC protocols:

- [Semi-honest, honest-majority protocol based on ABY3](iris-mpc/src/aby3/)
  - Most efficient, since there is no overhead for malicious security.
- [Malicious, honest-majority protocol based on SWIFT](iris-mpc/src/swift3/)
  - Has the same amortized asymptotic communication cost as semi-honest ABY3-based.
  - However, the used distributed zero-knowledge proof for malicous security is very computationally intensive.
- [Malicious, honest-majority protocol based on ABY3, with triple sacrificing](iris-mpc/src/aby3_mal/)
  - Computationally more efficient than SWIFT, but larger communication.
- [Malicious, honest-majority protocol based on SPDZ-wise, using MACs](iris-mpc/src/spdzwise)
  - Uses a MAC to lift the semi-honest protocol to malicious security.
  - Working over larger ring for soundness, leading to communication overhead.
  - Additional MAC essentially doubles the communication and computation further.

## Examples & Benchmarks

In [`iris-mpc/examples`](iris-mpc/examples), there are a few end-to-end examples that run the iris code matching for a single incoming iris code with associated mask against a prepared database of iris codes of a certain size.

As an example, executing an iris match against (a database size of 100k, set in the bash script) using the semi-honest implementation of ABY3, using real networking, but running all nodes on the current machine:

```bash
cd iris-mpc
bash examples/run_aby3.sh
```

You will see the output of a single party in the current terminal.

## TODOs

- [ ] Finish and clean up implementations
- [ ] Code documentation
- [ ] Performance optimizations for MPC protocols
- [ ] Multithreading support for MPC protocols
- [ ] Benchmark runs for all protocols in different networking scenarios
