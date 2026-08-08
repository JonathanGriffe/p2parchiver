# Build context is the repository root:
#   docker build -f deploy/Dockerfile .

FROM rust:slim-bookworm AS builder

# `rusqlite` is used with its `bundled` feature, so SQLite is compiled from source and a
# C toolchain is required. Nothing else here needs system libraries: TLS is rustls, so
# there is no OpenSSL to link against.
RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates/ crates/

# Only the server. The client binary would double build time and ship code that has no
# business on a machine whose entire job is relaying and directing.
RUN cargo build --release --bin ac-server


FROM debian:bookworm-slim

# Unprivileged. The uid is fixed so that a bind-mounted data directory can be chowned to
# match it from the host — a named volume inherits ownership from the image and needs no
# such help.
RUN useradd --system --uid 10001 --create-home --home-dir /home/ac ac \
 && mkdir -p /data \
 && chown ac:ac /data

COPY --from=builder /src/target/release/ac-server /usr/local/bin/ac-server

# Where the identity key, config and database live. Everything that must survive a
# restart is here, and losing it means every enrolled client has to re-enrol.
ENV AC_SERVER_HOME=/data
VOLUME ["/data"]

# Services (QUIC + TCP) and enrolment (QUIC). Both fixed rather than ephemeral: clients
# are told the service address once, at enrolment, and store it permanently.
EXPOSE 4001/udp 4001/tcp 4002/udp

USER ac

# `init` is idempotent — it keeps an existing identity and never overwrites config — so
# running it every start is safe and makes a fresh volume self-initialising.
ENTRYPOINT ["/bin/sh", "-c", "ac-server init && exec ac-server run"]
