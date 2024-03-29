# Experiments for Decentralized Iris Code Membership Protocols using MPC

**Disclaimer: This repository is intended for experiments only and may contain unfinished protocols, unoptimized code and minimal documentation.**

This is the repository containing code and benchmarking harnesses for _decentralized iris code membership protocols_ using secure multiparty computation.

## Table of Contents

- [Experiments for Decentralized Iris Code Membership Protocols using MPC](#experiments-for-decentralized-iris-code-membership-protocols-using-mpc)
  - [Table of Contents](#table-of-contents)
  - [Report](#report)
  - [Dependencies](#dependencies)
  - [Repository Structure](#repository-structure)
    - [Implemented MPC protocols](#implemented-mpc-protocols)
  - [Examples](#examples)

## Report

A report of the preliminary results of this project is located in ```docs/report/main.pdf```. This report includes a description of the protocol, the most challenging parts for efficient MPC evaluation, discussions of the MPC protocols, as well as benchmarks and potential future work.

## Dependencies

- `Rust 1.75`
  - We use this version because we are using `async fn` in traits, which is only stabilized in this version.

## Repository Structure

The repository consists of 3 crates.

- [`iris-mpc`](iris-mpc): Implementation of various base MPC protocol functionalities, as well as implementations of iris code membership checks using said protocols.
- [`plain-reference`](plain-reference): Implementation of the Iris Code Matching functionality in plain Rust, to serve as a comparison point for the MPC functionality.
  - Also contains a binary for generation of test data, which is stored in a SQlite DB for uses in tests/examples.
- [`mpc-net`](mpc-net): Implementation of networking used in the MPC protocols
  - Uses QUIC as the underlying transport protocol, which also captures the overhead of TLS for connections between parties.
  - Also contains a binary for generation of the required self-signed TLS certificates for testing.

### Implemented MPC protocols

We are investigating several different MPC protocols:

- [Semi-honest, honest-majority protocol based on ABY3](iris-mpc/src/aby3/)
  - Most efficient, since there is no overhead for malicious security.
  - [Publication](https://eprint.iacr.org/2018/403.pdf)
- [Malicious, honest-majority protocol based on SWIFT](iris-mpc/src/swift3/)
  - Has the same amortized asymptotic communication cost as semi-honest ABY3-based.
  - However, the used distributed zero-knowledge proof for malicious security is very computationally intensive.
  - [Publication](https://eprint.iacr.org/2020/592.pdf), modified to use the cleaner sharing scheme as described in [here](https://arxiv.org/pdf/2112.13338.pdf).
  - [Distributed ZK Publication](https://eprint.iacr.org/2019/1390.pdf)
- [Malicious, honest-majority protocol based on ABY3, with triple sacrificing](iris-mpc/src/aby3_mal/)
  - Computationally more efficient than SWIFT, but larger communication.
  - [Publication](https://eprint.iacr.org/2019/1298.pdf)
- [Malicious, honest-majority protocol based on SPDZ-wise, using MACs](iris-mpc/src/spdzwise)
  - Uses a MAC to lift the semi-honest protocol (for arithmetic operations, such as dot-products) to malicious security.
  - Working over larger ring for soundness, leading to communication overhead.
  - Additional MAC essentially doubles the communication and computation further.
  - [Publication](https://eprint.iacr.org/2020/1330.pdf)
  - We use a cut-and-choose protocol to get maliciously secure binary computations.
  - [Publication](https://www.ieee-security.org/TC/SP2017/papers/96.pdf)

As discussed in the report in ```docs/report/main.pdf```, we recommend using SPDZWise MACs in combination with cut-and-choose to achieve malicious security.

## Examples

In [`iris-mpc/examples`](iris-mpc/examples), there are a few end-to-end examples that run the iris code matching for a single incoming iris code with associated mask against a prepared database of iris codes of a certain size.

As an example, executing an iris match against (a database size of 100k, set in the bash script) using the semi-honest implementation of ABY3, using real networking, but running all nodes on the current machine:

```bash
cd iris-mpc
bash examples/run_aby3.sh
```

You will see the output of a single party in the current terminal.
