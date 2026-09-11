# syntax=docker/dockerfile:1
#
# Build context is repository root:
#   docker build -f testing/perf/Dockerfile .
#
# Keep the benchmark binaries in one image so every service in compose runs
# the exact same revision. The source copies are selective: copying `target/`
# would make the Docker build context enormous on a developer machine.
FROM rust:1-bookworm AS build

WORKDIR /src

# `proxy-api` generates its descriptor pool during the build.
RUN apt-get update \
    && apt-get install --yes --no-install-recommends libprotobuf-dev protobuf-compiler pkg-config \
    && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY examples ./examples
COPY testing ./testing
COPY schema ./schema

RUN cargo build --release -p proxy -p mockupstream -p loadgen

FROM debian:bookworm-slim AS runtime

# `curl` backs compose's real HTTP health checks. No shell tooling is used to
# infer readiness from a mere open TCP port.
RUN apt-get update \
    && apt-get install --yes --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /src/target/release/llm-proxy /usr/local/bin/llm-proxy
COPY --from=build /src/target/release/mock-upstream /usr/local/bin/mock-upstream
COPY --from=build /src/target/release/loadgen /usr/local/bin/loadgen
COPY testing/perf/proxy.yaml /etc/llm-proxy/proxy.yaml
