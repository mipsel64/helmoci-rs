# HelmOCI Configuration Loading and Eyre Refactor

**Date:** 2026-08-05

## Context

The current server configuration permits invalid storage combinations: a backend kind is
selected separately from optional backend settings. It also manually scans `${...}` values
and uses `anyhow` for application-level errors. This refactor adopts the local loading pattern
used by methub's `common` crate while keeping helmoci self-contained.

## Goals

- Replace `anyhow` with `eyre` for application and configuration error reporting.
- Model storage as one adjacently tagged enum so invalid backend/settings combinations cannot
  deserialize.
- Keep Clap responsible for the required `--config` argument.
- Read that exact YAML file, expand shell variables, and deserialize it through `config-rs`.
- Preserve typed domain and protocol errors implemented with `thiserror`.
- Migrate every test fixture and project document to the new configuration shape.

## Non-goals

- Do not depend on methub's `common` crate or introduce a generic configuration trait.
- Do not make the config file optional or search for alternate file extensions.
- Do not add a `config::Environment` source or implicit `HELMOCI_*` overrides.
- Do not retain compatibility with the old `storage.backend` representation.
- Do not replace `HelmError`, `StorageError`, or HTTP `AppError` with `eyre` reports.

## Configuration Model

`Config::storage` becomes a `Backend` value:

```rust
#[derive(Debug, serde::Deserialize)]
#[serde(tag = "type", content = "settings", rename_all = "lowercase")]
pub enum Backend {
    R2(R2Config),
    Gcs(GcsConfig),
    Local(LocalConfig),
    Memory,
}
```

The settings structs continue to reject unknown fields. Backend selection and settings are now
one value, so R2, GCS, and local settings are required exactly when their variant is selected.
Memory has no settings.

Examples:

```yaml
storage:
  type: memory
```

```yaml
storage:
  type: local
  settings:
    path: /data/helmoci
```

```yaml
storage:
  type: r2
  settings:
    endpoint: ${R2_ENDPOINT}
    bucket: charts
    access_key_id: ${R2_ACCESS_KEY_ID}
    secret_access_key: ${R2_SECRET_ACCESS_KEY}
```

```yaml
storage:
  type: gcs
  settings:
    bucket: charts
    service_account_key: ${GOOGLE_APPLICATION_CREDENTIALS}
```

`build_storage` accepts `&Backend` and matches each variant directly. The validation branches
that check whether optional settings exist are removed; serde enforces that structurally.

## Loading Pipeline

`load_config(path)` keeps the exact path supplied by Clap and performs this pipeline:

1. Read the YAML file and attach path-specific context with `eyre::WrapErr`.
2. Expand `$VAR` and `${VAR}` with `shellexpand::env_with_context`.
3. When a variable is absent, return `None` from the expansion context so the reference remains
   unexpanded, matching methub's behavior.
4. Add the expanded text to a `config::Config` builder as `FileFormat::Yaml`.
5. Build and `try_deserialize::<Config>()`, attaching separate build and deserialization context.
6. Run existing semantic validation for authentication and aliases, producing `RuntimeConfig`.

The existing string entry point remains available for deterministic unit and integration tests;
it uses the same expansion, `config-rs` deserialization, and validation pipeline as file loading.
There is no environment source layered after the file.

## Error Boundaries

The workspace replaces the `anyhow` dependency with `eyre`. Application-boundary functions,
including config loading, storage construction, HTTP client/state construction, GCP provider
startup, and `main`, return `eyre::Result` and add context with `WrapErr` where useful.

Typed errors remain unchanged where callers branch on their meaning:

- `HelmError` for index/chart operations.
- `StorageError` for the storage trait.
- `AppError` for OCI HTTP status and error-code mapping.

Secrets must not be included in added context, debug output, or logs.

## Migration

- Replace workspace and binary-crate `anyhow` declarations/usages with `eyre`.
- Replace `BackendKind` and `StorageConfig` with `Backend` and update `build_storage`.
- Migrate all inline YAML in unit/integration tests.
- Update the active implementation plan and design documentation so future tasks use the tagged
  storage schema and `eyre` APIs.
- Resume the paused GCP/token task only after this refactor is reviewed and green.

## Verification

Tests will cover:

- Deserialization of memory, local, R2, and GCS variants.
- Rejection of missing settings, settings attached to memory, unknown fields, and the old
  `storage.backend` shape.
- Shell expansion for both `$VAR` and `${VAR}`.
- Preservation of references to missing environment variables.
- Context-rich failures for missing/unreadable files and invalid YAML.
- Memory and local storage construction under the new enum.
- Existing aliases, authentication validation, classic pulls, tags, storage conformance, and
  SSRF protections after fixture migration.

The implementation is complete only when formatting, workspace tests, and clippy with warnings
denied pass, aside from no user-owned untracked files being staged.
