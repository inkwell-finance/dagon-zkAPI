# Coordinator for the Dagon zkAPI trusted setup. Not deployed from here; build context is this directory (ceremony/).
#
#   docker build -t dagon-ceremony .
#   docker run --rm -p 8788:8788 -v ceremony-data:/data dagon-ceremony              # serve (after init)
#   docker run --rm -v ceremony-data:/data -v ./r1cs:/in:ro dagon-ceremony init --r1cs-dir /in
#   docker run --rm -v ceremony-data:/data dagon-ceremony close                      # server stopped, before the beacon
#   docker run --rm -v ceremony-data:/data dagon-ceremony finalize                   # server stopped, after applyAfter
# On Railway the start command replaces ENTRYPOINT: use `docker-entrypoint.sh close` / `docker-entrypoint.sh finalize`.
#
# Environment (all optional): DATA_DIR=/data HOST=0.0.0.0 PORT=8788 TRUST_PROXY=1 (behind Railway's proxy)
#   SLOT_MINUTES=25 MAX_QUEUE=100 VERIFY_TIMEOUT_MINUTES=30

# Stage 1: bundle the browser page and the single-file CLI with the pinned dev toolchain.
FROM node:24-slim@sha256:55fb5f5a527ea2c5c4a95f963e48ef90aa38c7b346054fdc8ee9957a2b55d205 AS web
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts
COPY build.mjs contribute.mjs ./
COPY lib ./lib
COPY web ./web
RUN node build.mjs

# Stage 2: runtime. No dev dependencies, no build tools.
FROM node:24-slim@sha256:55fb5f5a527ea2c5c4a95f963e48ef90aa38c7b346054fdc8ee9957a2b55d205
ENV NODE_ENV=production
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts && npm cache clean --force
COPY ceremony.json verify-ceremony.mjs contribute.mjs ./
COPY lib ./lib
COPY coordinator ./coordinator
COPY --from=web /app/web ./web
# The exported circuits (`ceremony_export`, see README.md), gitignored; init verifies their sha256 pins.
COPY r1cs ./r1cs
# State: the Powers of Tau file, circuits, every round and the transcript. Attach a persistent volume at /data (on
# Railway: a Railway volume; Railway rejects the Dockerfile VOLUME instruction).
ENV DATA_DIR=/data HOST=0.0.0.0 PORT=8788
EXPOSE 8788
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||8788)+'/healthz').then(r=>process.exit(r.ok?0:1),()=>process.exit(1))"
# Starts as root only to take ownership of the volume (Railway mounts it root-owned), then drops to the unprivileged
# `node` user before anything else runs.
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod 755 /usr/local/bin/docker-entrypoint.sh
ENTRYPOINT ["docker-entrypoint.sh"]
