FROM debian:buster AS builder

RUN apt-get update && apt-get install -y curl libssl-dev libpq-dev build-essential pkg-config
RUN curl https://sh.rustup.rs/ -sSf | \
	sh -s -- -y --default-toolchain nightly

ENV PATH="/root/.cargo/bin:${PATH}"
ADD . ./

RUN cargo build --release

FROM debian:buster
RUN apt-get update && apt-get install -y libssl-dev libpq-dev ca-certificates

COPY --from=builder \
	/target/release/kepler \
	/usr/local/bin/

WORKDIR /root
ENTRYPOINT ["/usr/local/bin/kepler"]
