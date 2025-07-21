# TODO: do not run as root user...

FROM rust:1.88 AS builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends cmake pkg-config libssl-dev && \
    rm -rf /var/lib/apt/lists/*

COPY . .
RUN cargo build --profile=release -p netgauze-collector

FROM debian:bookworm-slim
WORKDIR /app

# Copy the binary from the builder stage
COPY --from=builder /app/target/release/netgauze-collector /usr/local/bin/netgauze-collector

# Copy entrypoint script for logging
COPY docker/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
