# Build container
FROM rust:bookworm AS builder

RUN apt-get update && apt-get install -y libssl-dev libpq-dev build-essential pkg-config

ADD ./ ./

RUN cargo build --release

# Deploy container
FROM debian:bookworm

RUN apt-get update && apt-get install -y libpq5 ca-certificates openssl

# Create app directory
WORKDIR /app

# Copy binary to PATH
COPY --from=builder /target/release/kepler /usr/local/bin/

# Copy migrations to the app directory
ADD ./migrations ./migrations

ENTRYPOINT ["kepler", "--migrate"]