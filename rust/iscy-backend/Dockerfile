FROM rust:1.88-bookworm AS builder
WORKDIR /build/rust/iscy-backend

COPY rust/iscy-backend/Cargo.toml rust/iscy-backend/Cargo.lock ./
COPY rust/iscy-backend/src ./src
COPY rust/iscy-backend/seeds ./seeds
COPY deploy /build/deploy
COPY flake.lock /build/flake.lock

RUN cargo build --release --locked

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
