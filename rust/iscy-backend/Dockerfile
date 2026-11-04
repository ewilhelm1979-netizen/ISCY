FROM docker.io/library/rust:1.99.1-bookworm@sha256:9181b56c2a21ab1d5e73cffe04fc762426d30aa7fac3c91141dd033f49a7fc8b AS builder
WORKDIR /build/rust/iscy-backend

COPY rust/iscy-backend/Cargo.toml rust/iscy-backend/Cargo.lock ./
COPY rust/iscy-backend/src ./src
COPY rust/iscy-backend/seeds ./seeds
COPY deploy /build/deploy
COPY flake.lock /build/flake.lock

RUN test "$(rustc --version | cut -d ' ' -f 2)" = "1.98.1" \
    && cargo build --release --locked

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates wget \
    && groupadd --system --gid 10001 iscy \
    && useradd --system --uid 10001 --gid iscy --home-dir /nonexistent --shell /usr/sbin/nologin iscy \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
RUN install -d -o iscy -g iscy /app/media
COPY --from=builder /build/rust/iscy-backend/target/release/iscy-backend /usr/local/bin/iscy-backend
COPY --from=builder /build/rust/iscy-backend/target/release/iscy-canary /usr/local/bin/iscy-canary

ENV RUST_BACKEND_BIND=0.0.0.0:9000
EXPOSE 9000

USER 10001:10001
CMD ["/usr/local/bin/iscy-backend"]
