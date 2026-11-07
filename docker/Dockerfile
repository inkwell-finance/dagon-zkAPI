FROM rust:bookworm AS builder

# The operator image runs the Dagon zkAPI server, indexer and challenge services,
# and ships the deploy tool. The browser SDK and host application build separately.
WORKDIR /app

COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY protocol ./protocol
# The vault program crate and the compiled-in profile (solana/profile/*.json).
COPY solana ./solana

RUN cargo build --locked --release \
    -p zkapi-cli -p zkapi-indexerd -p zkapi-serverd -p dagon-zkapi-deploy --bins

FROM debian:bookworm-slim

LABEL org.opencontainers.image.title="dagon-zkapi" \
      org.opencontainers.image.description="Dagon zkAPI Solana operator daemons and deploy tool"

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 zkapi

WORKDIR /srv/zkapi

COPY --from=builder /app/target/release/dagon-zkapi /usr/local/bin/dagon-zkapi
COPY --from=builder /app/target/release/dagon-zkapi-indexerd /usr/local/bin/dagon-zkapi-indexerd
COPY --from=builder /app/target/release/dagon-zkapi-challenged /usr/local/bin/dagon-zkapi-challenged
COPY --from=builder /app/target/release/dagon-zkapi-deploy /usr/local/bin/dagon-zkapi-deploy
COPY --from=builder /app/protocol/setup/v2 /srv/zkapi/protocol/setup/v2
COPY --from=builder /app/solana/profile/mainnet-beta.identity.json /srv/zkapi/solana/profile/mainnet-beta.identity.json

COPY --chmod=755 docker/aws/run-daemon.sh /usr/local/bin/dagon-zkapi-run

USER zkapi

ENV RUST_LOG=info
VOLUME ["/data"]

ENTRYPOINT ["dagon-zkapi-run"]
CMD ["server"]
