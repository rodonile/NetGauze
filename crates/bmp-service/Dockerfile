FROM rust:1.88 AS builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends cmake pkg-config libssl-dev && \
    rm -rf /var/lib/apt/lists/*

COPY . .
RUN cargo build --release --example print-bmp -p netgauze-bmp-service

FROM debian:bookworm-slim
WORKDIR /app

# Copy the built example binary
COPY --from=builder /app/target/release/examples/print-bmp /usr/local/bin/print-bmp

# Copy entrypoint script
COPY crates/bmp-service/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]