# syntax=docker/dockerfile:1.7
FROM rust:1.97.1-bookworm AS builder
WORKDIR /build
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        clang \
        golang-go \
        libclang-dev \
        libprotobuf-dev \
        protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*
COPY . .
COPY --from=circuit-artifacts /prividium-trust-update-program /sp1-elf/prividium-trust-update-program
COPY --from=circuit-artifacts /prividium-settlement-update-program /sp1-elf/prividium-settlement-update-program
COPY --from=circuit-artifacts /prividium-membership-program /sp1-elf/prividium-membership-program
COPY --from=circuit-artifacts /prividium-non-membership-program /sp1-elf/prividium-non-membership-program
COPY --from=source-profile /source-profile.json /source-profile.json
ENV PRIVIDIUM_SP1_ELF_DIR=/sp1-elf \
    PRIVIDIUM_SOURCE_PROFILE=/source-profile.json
RUN cargo build --manifest-path tooling/proof-api/Cargo.toml --release --locked --features sp1

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bash \
        ca-certificates \
        coreutils \
        findutils \
        jq \
        libstdc++6 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/tooling/proof-api/target/release/prividium-proof-api /usr/local/bin/prividium-proof-api
COPY tooling/proof-api/scripts/start-proof-api.sh /usr/local/bin/start-proof-api.sh
RUN chmod 0755 /usr/local/bin/start-proof-api.sh \
    && install -d -o 65532 -g 65532 -m 0700 /var/lib/prividium-proof-api
ENV PRIVIDIUM_CONTAINER_MODE=true
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/start-proof-api.sh"]
CMD ["/run/secrets/operator.env"]
