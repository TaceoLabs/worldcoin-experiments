FROM lukemathwalker/cargo-chef:latest-rust-1.75 as chef
WORKDIR /app

FROM chef as planner
COPY . .
# Compute a lock-like file for our project
RUN cargo chef prepare --recipe-path recipe.json

FROM chef as builder
COPY --from=planner /app/recipe.json recipe.json
# Build our project dependencies, not our application!
RUN cargo chef cook --release --recipe-path recipe.json
# Up to this point, if our dependency tree stays the same,
# all layers should be cached.
COPY . .
# Build our project
RUN cargo build --bins --examples --release

FROM debian:bookworm-slim AS runtime
RUN apt-get update -y \
    && apt-get install -y --no-install-recommends openssl ca-certificates \
    # Clean up
    && apt-get autoremove -y \
    && apt-get clean -y \
    && rm -rf /var/lib/apt/lists/*
RUN addgroup --system --gid 1001 app
RUN adduser --system --uid 1001 app
RUN mkdir /app && chown app:app /app

FROM runtime as mpc-node
WORKDIR /app
COPY --from=builder --chown=app:app /app/target/release/examples/aby3 mpc-node
RUN mkdir /app/store && chown app:app /app/store
USER app
ENTRYPOINT ["./mpc-node"]
