FROM rust:1.87-bookworm AS builder
WORKDIR /build

COPY Cargo.toml ./
COPY src ./src

RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates wget \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /build/target/release/iscy-backend /usr/local/bin/iscy-backend
COPY --from=builder /build/target/release/iscy-canary /usr/local/bin/iscy-canary

ENV RUST_BACKEND_BIND=0.0.0.0:9000
EXPOSE 9000

CMD ["/usr/local/bin/iscy-backend"]
