# syntax=docker/dockerfile:1

FROM rust:1-slim-bookworm AS builder
WORKDIR /app
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,id=helmoci-target-bookworm,target=/app/target \
    cargo build --locked --release -p helmoci && cp target/release/helmoci /helmoci

FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=builder --chown=nonroot:nonroot /helmoci /usr/local/bin/helmoci
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/helmoci"]
CMD ["--config", "/etc/helmoci/config.yaml"]
