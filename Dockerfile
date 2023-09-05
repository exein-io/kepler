# Build container
FROM debian:bookworm AS builder

RUN apt-get update && apt-get install -y curl libssl-dev libpq-dev build-essential pkg-config

RUN curl https://sh.rustup.rs/ -sSf | sh -s -- -y

ENV PATH="/root/.cargo/bin:${PATH}"

ADD . ./

RUN cargo build --release

# Deploy container
FROM debian:bookworm

RUN apt-get update && apt-get install -y libssl-dev libpq-dev ca-certificates

COPY --from=builder \
	/target/release/kepler \
	/usr/local/bin/

WORKDIR /root

ADD ./migrations ./migrations

ENTRYPOINT ["/usr/local/bin/kepler", "--migrate"]
