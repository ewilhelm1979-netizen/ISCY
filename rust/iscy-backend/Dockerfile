FROM rust:1.96-bookworm AS builder
WORKDIR /build

COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY seeds ./seeds

RUN cargo build --release --locked

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates wget \
    && groupadd --system --gid 10001 iscy \
    && useradd --system --uid 10001 --gid iscy --home-dir /nonexistent --shell /usr/sbin/nologin iscy \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
RUN install -d -o iscy -g iscy /app/media
COPY --from=builder /build/target/release/iscy-backend /usr/local/bin/iscy-backend
COPY --from=builder /build/target/release/iscy-canary /usr/local/bin/iscy-canary

ENV RUST_BACKEND_BIND=0.0.0.0:9000
EXPOSE 9000

USER 10001:10001
CMD ["/usr/local/bin/iscy-backend"]
