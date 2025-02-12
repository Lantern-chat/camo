FROM messense/rust-musl-cross:x86_64-musl AS build
COPY ./ /home/rust/src

# Uncomment if building behind proxy with a custom CA certificate.
#COPY cacert.gitignore.crt /usr/local/share/ca-certificates/proxyca.crt
#RUN update-ca-certificates

RUN --mount=type=cache,target=/home/rust/src/target \
    --mount=type=cache,target=/root/.cargo/registry \
    --mount=type=cache,target=/root/.cargo/git \
    cargo build --release --no-default-features --features 'standalone' --bin standalone && \
    mv /home/rust/src/target/x86_64-unknown-linux-musl/release/standalone /standalone

FROM scratch

LABEL org.opencontainers.image.title="camo-service" \
      org.opencontainers.image.description="Proxies signed requests to preserve user anonymity" \
      org.opencontainers.image.licenses="AGPL-3.0-only" \
      org.opencontainers.image.source="https://github.com/Lantern-chat/camo"

USER 1001:1001
COPY --from=build /standalone /standalone

ENV CAMO_BIND_ADDRESS="127.0.0.1:8050"
# Example key, replace with your own
ENV CAMO_SIGNING_KEY="59d273a2641327d005b255bb7dc89a9f"

EXPOSE 8050/tcp

ENTRYPOINT ["/standalone"]