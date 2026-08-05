# Token Service Dockerfile Alignment Design

## Goal

Align helmoci's container build with the local Meteora Token service Dockerfile while retaining
helmoci's existing runtime contract and security requirements.

## Build image

Use `debian:12-slim` as the build stage so its glibc version matches the Debian 12 Distroless
runtime. Install only the native build tools, CA certificates, and rustup prerequisites required to
compile helmoci. Track the existing `rust-toolchain.toml` and let rustup install that declared
toolchain rather than inheriting a floating Rust image.

Map BuildKit's `TARGETPLATFORM` to the corresponding GNU Rust target for `linux/amd64` and
`linux/arm64`, rejecting unsupported platforms. Copy the workspace manifests and source trees,
then build only the `helmoci` binary with `cargo build --locked --release` for the selected target.
Retain BuildKit caches for the Cargo registry and target directory, with a cache identity that
cannot reuse binaries built for an incompatible target or base ABI.

## Runtime image

Use a small Alpine stage only to obtain an up-to-date CA certificate bundle, then copy that bundle
and the compiled binary into `gcr.io/distroless/cc-debian12:nonroot`. The final image continues to
run without root privileges, expose port 8080, execute `/usr/local/bin/helmoci`, and default to
`--config /etc/helmoci/config.yaml`.

## Scope

Change `Dockerfile`, add the approved `rust-toolchain.toml` to version control, and update the
packaging plan or README only if their Docker instructions become inaccurate. Do not change Rust
application behavior or dependencies.

## Verification

Build the image from a clean tracked checkout, run the image with `--help`, and confirm the final
UID, entrypoint, command, and exposed port. Run Dockerfile checks plus formatting, workspace Clippy
with warnings denied, workspace tests, the helmoci binary check, and diff checks. Verify both
supported platform mappings syntactically; build both architectures when the local builder supports
them without requiring publication or emulation setup changes.
