# Token Service Dockerfile Alignment Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make helmoci's container build follow the Meteora Token service's Debian/rustup/multi-platform pattern while retaining helmoci's non-root runtime contract.

**Architecture:** A Debian 12 builder maps BuildKit's target platform to a GNU Rust target and installs the tracked Rust toolchain through rustup. It builds one locked release binary, which is copied with CA certificates into a Debian 12 Distroless non-root image.

**Tech Stack:** Docker BuildKit, Debian 12, rustup, Cargo, Alpine CA certificates, Distroless Debian 12

## Global Constraints

- Track `rust-toolchain.toml` with channel `1.93`.
- Support `linux/amd64` as `x86_64-unknown-linux-gnu` and `linux/arm64` as `aarch64-unknown-linux-gnu`; reject other target platforms.
- Build only package `helmoci` in locked release mode.
- Run the final image as Distroless `nonroot` and preserve port 8080, `/usr/local/bin/helmoci`, and `--config /etc/helmoci/config.yaml`.
- Do not change Rust application behavior or dependencies.

---

### Task 1: Align the container build

**Files:**
- Modify: `Dockerfile`
- Track: `rust-toolchain.toml`
- Modify: `docs/superpowers/plans/2026-08-05-helmoci-rs.md`

**Interfaces:**
- Consumes: BuildKit automatic `TARGETPLATFORM` and `TARGETARCH` arguments.
- Produces: `/usr/local/bin/helmoci` in a Debian 12 Distroless non-root image.

- [ ] **Step 1: Run the pre-change structural check**

Run:

```bash
git ls-files --error-unmatch rust-toolchain.toml
rg -n '^FROM debian:12-slim AS build$|ARG TARGETPLATFORM|rustup target add|FROM alpine:3\.22 AS certs' Dockerfile
```

Expected: the first command fails because the toolchain file is not tracked, and the Dockerfile
search finds none of the required Token service build structure.

- [ ] **Step 2: Replace the Dockerfile**

Use this complete structure:

```dockerfile
# syntax=docker/dockerfile:1

FROM debian:12-slim AS build
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

COPY Cargo.toml Cargo.lock ./
COPY crates crates
COPY bins bins

ARG TARGETARCH
RUN --mount=type=cache,target=/root/.cargo/registry \
  --mount=type=cache,id=helmoci-target-bookworm-${TARGETARCH},target=/root/target \
  target="$(cat rust_target.txt)" \
  && cargo build --locked --release --target "$target" -p helmoci \
  && cp "target/$target/release/helmoci" /helmoci

FROM alpine:3.22 AS certs
RUN apk --update add ca-certificates

FROM gcr.io/distroless/cc-debian12:nonroot
WORKDIR /
COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build --chown=nonroot:nonroot /helmoci /usr/local/bin/helmoci
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/helmoci"]
CMD ["--config", "/etc/helmoci/config.yaml"]
```

Add the existing file to version control unchanged:

```toml
[toolchain]
channel = "1.93"
```

Stage the newly approved file so the tracked-file check can exercise the intended clean-checkout
contract:

```bash
git add rust-toolchain.toml
```

Update Task 22 in the original implementation plan so its file list, Dockerfile listing, and build
description match the tracked toolchain and final Dockerfile.

- [ ] **Step 3: Run structural and Dockerfile checks**

Run:

```bash
git ls-files --error-unmatch rust-toolchain.toml
docker build --check .
git diff --check
```

Expected: all commands pass and Docker reports no warnings.

- [ ] **Step 4: Build and inspect the image**

Run:

```bash
docker build --no-cache -t helmoci:token-dockerfile-check .
docker run --rm helmoci:token-dockerfile-check --help
docker image inspect helmoci:token-dockerfile-check
```

Expected: the clean build and `--help` pass. Inspection reports non-root user `65532`, entrypoint
`/usr/local/bin/helmoci`, command `--config /etc/helmoci/config.yaml`, and exposed port `8080/tcp`.

- [ ] **Step 5: Run the project verification gate**

Run:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo check -p helmoci --bin helmoci
```

Expected: every command passes.

- [ ] **Step 6: Commit**

```bash
git add Dockerfile rust-toolchain.toml docs/superpowers/plans/2026-08-05-helmoci-rs.md
git commit -m "build: align Dockerfile with token service"
```
