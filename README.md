# helmoci

helmoci serves charts from classic Helm repositories and configured OCI upstream aliases behind one read-only OCI Distribution endpoint. It is a Rust port of [`tuananh/helmoci`](https://github.com/tuananh/helmoci).

## Quick start

Run the server with the local-storage example:

```console
cargo run -p helmoci -- --config examples/config.yaml
```

The example listens on `0.0.0.0:8080`, stores cache entries under `/tmp/helmoci-cache`, and defines the classic `argo` alias. The container uses `/etc/helmoci/config.yaml` by default:

```console
docker build -t helmoci .
docker run --rm -p 8080:8080 \
  -v "$PWD/examples/config.yaml:/etc/helmoci/config.yaml:ro" \
  helmoci
```

## Pull charts

Use a public classic repository directly in host/path form:

```console
helm pull oci://127.0.0.1:8080/argoproj.github.io/argo-helm/argo-cd \
  --version 7.7.0 --plain-http
```

Or use the `argo` alias from the example configuration:

```console
helm pull oci://127.0.0.1:8080/argo/argo-cd \
  --version 7.7.0 --plain-http
```

## Configuration reference

The YAML document has these top-level keys. Unknown keys are rejected.

| Key | Default | Description |
| --- | --- | --- |
| `listen` | `0.0.0.0:8080` | TCP address on which the HTTP server listens. |
| `max_chart_bytes` | `52428800` (50 MiB) | Maximum size for classic chart downloads and buffered OCI responses. |
| `index_cache_ttl_secs` | `600` | Lifetime of classic repository `index.yaml` entries in the in-process cache. |
| `ephemeral_cache.max_bytes` | `268435456` (256 MiB) | Size-weighted capacity of the in-process cache used by classic aliases with `store: false`. |
| `ephemeral_cache.ttl_secs` | `1800` | Lifetime of entries in that ephemeral cache. |
| `storage` | required | Tagged persistent storage backend; see below. |
| `auth.enabled` | `false` | Require a configured pull token on registry paths. |
| `auth.tokens` | `[]` | Accepted pull tokens. Enabling auth requires at least one non-empty token. |
| `aliases` | `{}` | Map of alias names to upstream definitions. |

### Storage backends

`storage` is a tagged value: `type` selects exactly one backend, and backends with settings place them under `settings`.

Memory has no settings and is process-local:

```yaml
storage:
  type: memory
```

Local storage requires a directory path, which helmoci creates if needed:

```yaml
storage:
  type: local
  settings:
    path: /var/lib/helmoci
```

Cloudflare R2 uses the S3-compatible API and requires all four settings:

```yaml
storage:
  type: r2
  settings:
    endpoint: https://example-account.r2.cloudflarestorage.com
    bucket: helmoci-cache
    access_key_id: ${R2_ACCESS_KEY_ID}
    secret_access_key: ${R2_SECRET_ACCESS_KEY}
```

Google Cloud Storage requires `bucket`. `service_account_key` is optional; when present it is a path to a service-account key file, and when omitted the object-store client loads its supported GCS environment credentials.

```yaml
storage:
  type: gcs
  settings:
    bucket: helmoci-cache
    service_account_key: /run/secrets/gcs-service-account.json
```

R2 and GCS credentials belong to the storage backend. They are separate from an OCI alias using `auth: gcp`, which obtains Google Application Default Credentials (ADC) for upstream registry requests.

### Aliases

Each alias supports these fields:

| Key | Default | Description |
| --- | --- | --- |
| `upstream` | required | A classic `https://` or `http://` repository, or an `oci://<registry>/<repo-path>` upstream. An OCI upstream must include a repository path. |
| `store` | `false` | For classic aliases, use persistent storage when true and the bounded ephemeral cache when false. For OCI aliases, cache manifests and eligible blobs when true; pass through without storing when false. OCI tag lists are passed through in either mode. |
| `auth` | `none` | Upstream OCI authentication: `none` starts anonymously and follows a usable bearer challenge; `gcp` uses ADC and is valid only for HTTPS OCI upstreams. Classic aliases cannot use `gcp`. |
| `plain_http` | `false` | Use HTTP instead of HTTPS for an OCI upstream. It cannot be combined with `auth: gcp` and does not control classic repository URLs. |

Alias names must start with an ASCII alphanumeric character and may otherwise contain ASCII alphanumerics, `-`, or `_`; dots are not allowed. A classic alias accepts exactly one chart-name segment after the alias. An OCI alias requires at least one following repository segment and permits nested paths.

### Config file selection and environment expansion

Clap selects the YAML path from the required `--config <PATH>` argument or, when the argument is absent, `HELMOCI_CONFIG`. The binary itself has no filesystem default; the container `CMD` supplies `--config /etc/helmoci/config.yaml`. `config-rs` does not process the CLI.

Before `config-rs` deserializes the selected YAML file, `shellexpand` expands `$NAME` and `${NAME}` references throughout its text. Missing environment variables remain unexpanded, so set credential and token variables before starting helmoci.

## Pull authentication

Pull authentication is disabled by default. To enable it without writing a token directly into the file, set `HELMOCI_PULL_TOKEN` and add:

```yaml
auth:
  enabled: true
  tokens:
    - ${HELMOCI_PULL_TOKEN}
```

Log Helm in with any username and one configured token as the password:

```console
printf '%s' "$HELMOCI_PULL_TOKEN" | \
  helm registry login 127.0.0.1:8080 \
    --username helm --password-stdin --plain-http
```

Registry requests accept the token as either a Basic-auth password or a Bearer token. The exact public paths `/`, `/healthz`, and `/metrics` do not require pull authentication.

## Endpoints

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/` | Human-readable service page. |
| `GET` | `/healthz` | Liveness response (`ok`). |
| `GET` | `/metrics` | Prometheus metrics. |
| `GET`, `HEAD` | `/v2/` | OCI Distribution API version check. |
| `GET`, `HEAD` | `/v2/<name>/manifests/<reference>` | Resolve or proxy a chart manifest by tag or digest. |
| `GET`, `HEAD` | `/v2/<name>/blobs/<digest>` | Read a chart config, layer, or upstream OCI blob. |
| `GET`, `HEAD` | `/v2/<name>/tags/list` | List classic chart versions or proxy an OCI tag list; `n` and `last` pagination parameters are supported. |

## Limits and behavior

The default 50 MiB `max_chart_bytes` limit applies to buffered classic chart downloads, OCI manifests, OCI tag lists, and OCI blobs selected for caching. Registry routes are read-only and support only `GET` and `HEAD`: helmoci does not implement pushes, tag mutation, or the catalog API.

Automatic host/path names are restricted to public-looking DNS hostnames and HTTPS. Localhost, raw IP addresses, bare names, `.local` names, and DNS answers containing non-public addresses are rejected; automatic upstream redirects are not followed. Explicitly configured aliases are the mechanism for trusted upstreams that do not fit that policy.

For an OCI alias with `store: true`, a blob is buffered, digest-verified, and cached only when the upstream supplies a content length at or below `max_chart_bytes`. Blobs with an unknown or larger advertised length intentionally stream from the upstream without entering the cache. OCI manifests and tag lists always remain bounded by the configured limit.

## Manual smoke test

This smoke test contacts the public Argo Helm repository and is intentionally not an automated CI gate:

```console
cargo run -p helmoci -- --config examples/config.yaml &
server_pid=$!

helm pull oci://127.0.0.1:8080/argoproj.github.io/argo-helm/argo-cd \
  --version 7.7.0 --plain-http
helm pull oci://127.0.0.1:8080/argo/argo-cd \
  --version 7.7.0 --plain-http
curl -fsS 127.0.0.1:8080/v2/argo/argo-cd/tags/list | head -c 300
curl -fsS 127.0.0.1:8080/metrics | grep helmoci_http_requests_total

kill "$server_pid"
```
