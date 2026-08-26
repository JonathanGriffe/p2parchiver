FROM rust:slim-bookworm AS builder

RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates/ crates/

RUN cargo build --release --bin ac-server


FROM debian:bookworm-slim

RUN useradd --system --uid 10001 --create-home --home-dir /home/ac ac \
 && mkdir -p /data \
 && chown ac:ac /data

COPY --from=builder /src/target/release/ac-server /usr/local/bin/ac-server

ENV AC_SERVER_HOME=/data
VOLUME ["/data"]

EXPOSE 4001/udp 4001/tcp 4002/udp

USER ac

ENTRYPOINT ["/bin/sh", "-c", "ac-server init && exec ac-server run"]
