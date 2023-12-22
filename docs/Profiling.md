# Steps for performance profiling

## Tools

```bash
cargo install flamegraph samply
sudo apt install linux-tools-common
```

enable perf event tracing (globally):

```bash
echo -1 | sudo tee /proc/sys/kernel/perf_event_paranoid
```

## Commands

### Generating a flamegraph

```bash
cargo flamegraph --profile profiling --bench "iris_aby3"
```

## Running E2E examples

```bash
cd iris-mpc
bash examples/run_aby3.sh
```
