FROM rust:bookworm AS builder

# The operator image runs Dagon zkAPI server, indexer and challenge services.
# The browser SDK and host application build separately.
WORKDIR /app

COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY protocol ./protocol

RUN cargo build --locked --release -p zkapi-cli -p zkapi-indexerd -p zkapi-serverd --bins

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 zkapi

WORKDIR /srv/zkapi

COPY --from=builder /app/target/release/dagon-zkapi /usr/local/bin/dagon-zkapi
COPY --from=builder /app/target/release/dagon-zkapi-indexerd /usr/local/bin/dagon-zkapi-indexerd
COPY --from=builder /app/target/release/dagon-zkapi-challenged /usr/local/bin/dagon-zkapi-challenged
COPY --from=builder /app/protocol/setup/v2 /srv/zkapi/protocol/setup/v2

COPY --chmod=755 docker/aws/run-daemon.sh /usr/local/bin/dagon-zkapi-run

USER zkapi

ENV RUST_LOG=info
VOLUME ["/data"]

ENTRYPOINT ["dagon-zkapi-run"]
CMD ["server"]
