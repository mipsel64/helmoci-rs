# syntax=docker/dockerfile:1

FROM debian:12-slim AS toolchain
ENV DEBIAN_FRONTEND=noninteractive
WORKDIR /root

RUN apt-get update \
  && apt-get install -y --no-install-recommends \
  build-essential \
  ca-certificates \
  curl \
  libssl-dev \
  pkg-config \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/*

ARG TARGETPLATFORM
RUN case "$TARGETPLATFORM" in \
  "linux/arm64") echo "aarch64-unknown-linux-gnu" > rust_target.txt ;; \
  "linux/amd64") echo "x86_64-unknown-linux-gnu" > rust_target.txt ;; \
  *) exit 1 ;; \
  esac

COPY rust-toolchain.toml rust-toolchain.toml
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
  | sh -s -- -y --target "$(cat rust_target.txt)" \
  --profile minimal --default-toolchain none
ENV PATH="/root/.cargo/bin:$PATH"
RUN rustup toolchain install
RUN rustup target add "$(cat rust_target.txt)"

ARG CARGO_CHEF_VERSION=0.1.77
RUN cargo install cargo-chef --locked --version "$CARGO_CHEF_VERSION"

# The recipe distills the workspace down to its dependency graph, so it only
# changes when a dependency does — not on every source edit.
FROM toolchain AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM toolchain AS build
COPY --from=planner /root/recipe.json recipe.json
# Deliberately not a cache mount: mount contents are never exported to a
# registry or GHA cache, so the compiled dependencies have to live in this
# layer for CI to reuse them.
RUN cargo chef cook --locked --release --target "$(cat rust_target.txt)" --recipe-path recipe.json

COPY Cargo.toml Cargo.lock ./
COPY crates crates
COPY bins bins

# Declared after the cook step: these change every commit, and anything above
# them would lose its cache along with them.
ARG GIT_SHA=unknown
ARG BUILD_TIME=unknown

RUN target="$(cat rust_target.txt)" \
  && GIT_SHA="$GIT_SHA" BUILD_TIME="$BUILD_TIME" \
  cargo build --locked --release --target "$target" -p helmoci \
  && cp "target/$target/release/helmoci" /helmoci

FROM alpine:3.22 AS certs
RUN apk --update add ca-certificates

FROM gcr.io/distroless/cc-debian12:nonroot

LABEL org.opencontainers.image.description="HelmOCI serves charts from classic Helm repositories and configured OCI upstream aliases behind one read-only OCI Distribution endpoint."

WORKDIR /
COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build --chown=nonroot:nonroot /helmoci /usr/local/bin/helmoci
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/helmoci"]
CMD ["--config", "/etc/helmoci/config.yaml"]
