FROM rust:1.85-bookworm AS builder

WORKDIR /app

COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY config ./config

RUN cargo build --release -p cityg-api

FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --system --create-home --home-dir /var/lib/cityg --uid 10001 cityg

COPY --from=builder /app/target/release/cityg-api /usr/local/bin/cityg-api

WORKDIR /var/lib/cityg

ENV RUST_LOG=info \
    LOG_FORMAT=json \
    CITYG_SERVER_ADDRESS=0.0.0.0:8080 \
    CITYG_SERVER_WEBSOCKET_CAPACITY=2000 \
    CITYG_SERVER_WINDOW_TTL_SECS=120 \
    CITYG_PROTOCOL_MAX_CONCURRENT_HEADS=32 \
    CITYG_PROTOCOL_WINDOW_DURATION_SECS=120

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=5 \
  CMD curl -fsS http://127.0.0.1:8080/health/ready || exit 1

USER cityg

ENTRYPOINT ["cityg-api"]
