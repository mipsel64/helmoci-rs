# helmoci

helmoci serves charts from classic Helm repositories and configured OCI upstream aliases behind one read-only OCI Distribution endpoint.

## Credits and relationship to the original

This project is inspired by, and a Rust port of, [**`tuananh/helmoci`**](https://github.com/tuananh/helmoci) by [Tuan Anh Tran](https://github.com/tuananh) — a TypeScript Cloudflare Worker that serves classic Helm chart repositories as a read-only OCI registry and caches the built artifacts in R2. All credit for the original idea, the request flow, and the artifact-building approach belongs there.

The core behavior is deliberately faithful to the original: the same OCI media types, the same manifest/blob/tags endpoints, the same `Chart.yaml` and `Chart.lock` dependency rewriting, the same SSRF guards, and the same descriptive error messages. The storage key layout is **byte-compatible** with the original's R2 bucket (`blobs/sha256:<hex>` and `tags/<proxy-host>/<full-name>/<tag>` with the same camelCase tag-pointer JSON), so a bucket written by the TypeScript worker keeps working unchanged.

What this port extends:

| Extension | Original | This port |
| --- | --- | --- |
| Runtime | Cloudflare Worker | Standalone server (axum/tokio), shipped as a distroless container |
| Storage | R2 only | Pluggable `Storage` trait: R2 (S3-compatible), GCS, local filesystem, in-memory, plus a bounded in-process ephemeral cache |
| Aliases | — | Short names mapping to either a classic Helm repo or an upstream OCI registry |
| OCI pass-through | — | Proxies an upstream `/v2` API with the Docker token flow, optional write-through caching, and Google Artifact Registry support via Application Default Credentials |
| Pull authentication | — | Optional static tokens, accepted as Basic or Bearer, compared in constant time |
| Operations | — | `/healthz`, Prometheus `/metrics`, structured `tracing` logs with credentials kept out of them |

Push support, `_catalog`, and search are out of scope here, exactly as in the original.

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
| `max_expanded_chart_bytes` | `524288000` (500 MiB) | Maximum total uncompressed size of an expanded chart archive. Charts expand well beyond their download size, so this is deliberately larger than `max_chart_bytes` and must never be smaller than it. |
| `max_index_bytes` | `67108864` (64 MiB) | Maximum size of a downloaded classic `index.yaml`. Large public indexes exceed the chart limit, so the index has its own bound. Must be greater than zero. |
| `index_cache_ttl_secs` | `600` | Lifetime of classic repository `index.yaml` entries in the in-process cache. |
| `ephemeral_cache.max_bytes` | `268435456` (256 MiB) | Size-weighted capacity of the in-process cache used by classic aliases with `store: false`. Must be at least `max_chart_bytes`; a smaller cap would silently retain nothing. |
| `ephemeral_cache.ttl_secs` | `1800` | Lifetime of entries in that ephemeral cache. |
| `storage` | required | Tagged persistent storage backend; see below. |
| `auth.enabled` | `false` | Require a configured pull token on registry paths. |
| `auth.tokens` | `[]` | Accepted pull tokens. Enabling auth requires at least one non-empty token. |
| `allow_public_private_upstreams` | `false` | Unsafe opt-in that allows aliases with upstream credentials to be served to anonymous clients; see [Serving credentialed upstreams](#serving-credentialed-upstreams). |
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
| `auth` | `none` | Upstream OCI authentication: `none` starts anonymously and follows a usable bearer challenge; `gcp` uses ADC and is valid only for HTTPS OCI upstreams (in practice Google Artifact Registry). Classic aliases cannot use `gcp`. Any value other than `none` requires pull authentication; see [Serving credentialed upstreams](#serving-credentialed-upstreams). |
| `plain_http` | `false` | Use HTTP instead of HTTPS for an OCI upstream. It cannot be combined with `auth: gcp` and does not control classic repository URLs. |

Alias names must start with an ASCII alphanumeric character and may otherwise contain ASCII alphanumerics, `-`, or `_`; dots are not allowed. A classic alias accepts exactly one chart-name segment after the alias. An OCI alias requires at least one following repository segment and permits nested paths.

### Config file selection and environment expansion

Clap selects the YAML path from the required `--config <PATH>` argument or, when the argument is absent, `HELMOCI_CONFIG`. The binary itself has no filesystem default; the container `CMD` supplies `--config /etc/helmoci/config.yaml`. `config-rs` does not process the CLI.

Before `config-rs` deserializes the selected YAML file, `shellexpand` expands `$NAME` and `${NAME}` references throughout its text. A reference to a variable that is not set stays in the text verbatim, which is harmless for values such as a storage path but never acceptable for a credential. helmoci therefore refuses to start when a still-unexpanded reference to an unset variable survives in `auth.tokens`, `storage.settings.access_key_id`, `storage.settings.secret_access_key`, or `storage.settings.service_account_key`. Without that check, `tokens: ["${PULL_TOKEN}"]` deployed without `PULL_TOKEN` would enable pull authentication whose only valid password is the guessable literal `${PULL_TOKEN}`.

Expansion applies to the whole document, so a literal `$` in a config file has shell semantics: `$NAME` and `${NAME}` are substituted from the server environment and `$$` collapses to a single `$`. Keep literal `$` out of values written into the file and pass such values through an environment variable instead, because values substituted from the environment are inserted as-is and are never re-expanded.

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

Every configured token is equally privileged, and cached blobs and manifests live in one digest-addressed namespace (`blobs/sha256:<hex>`) that is shared by all aliases. Any authenticated client can therefore read any cached digest through any repository name, including digests that were populated by an alias with upstream credentials. helmoci has no per-repository authorization: pull authentication decides who reaches the registry, not which repositories they may read.

### Serving credentialed upstreams

An alias with `auth: gcp` makes helmoci hold the upstream credentials, so anything it serves is republished under helmoci's own auth model. helmoci refuses to start when such an alias is configured while `auth.enabled` is `false`, because it would otherwise serve private upstream content to anonymous clients:

```console
aliases [acme] authenticate to their upstream while auth.enabled is false: ...
```

Enable pull authentication to fix it. If mirroring private charts to anonymous clients is genuinely intended, for example onto a trusted internal network, opt in explicitly:

```yaml
allow_public_private_upstreams: true
```

That flag is unsafe by design: it declares that the private upstream content behind every credentialed alias may be served to anyone who can reach the listener. Note that `store: false` is not a mitigation, since a pure pass-through still serves the same private bytes.

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

## The Host header

helmoci uses the request `Host` header as the proxy host: it appears in rewritten `oci://` dependency URLs inside served charts and it is a segment of the cached tag pointer key (`tags/<proxy-host>/<name>/<tag>`). Requests that carry the authority in the request URI instead of a `Host` header, as HTTP/2 does, use that authority.

The value must be a plausible `host[:port]`: a DNS-style name, an IPv4 literal, or a bracketed IPv6 literal, each with an optional non-zero port. `127.0.0.1:8080` and `localhost:8080` are valid, since running helmoci locally is a normal case. Anything else is rejected with `400 NAME_INVALID` before it can reach storage, and names are compared case-insensitively so `Host: Proxy.Example` and `Host: proxy.example` share one cache entry.

Each distinct `Host` value has its own tag-pointer namespace, so pulls through two different host names rebuild and store separate pointers (the blobs themselves are shared, being digest-addressed). Serve helmoci behind a proxy or ingress that sets one canonical `Host`; otherwise clients can multiply the cached pointer trees in the storage bucket and force repeated upstream rebuilds.

## Limits and behavior

The default 50 MiB `max_chart_bytes` limit applies to buffered classic chart downloads and to OCI blobs selected for caching. Three other limits are independent of it, so tightening the chart cap cannot break unrelated requests: a classic `index.yaml` is bounded by `max_index_bytes`, expanding a downloaded chart archive is bounded by `max_expanded_chart_bytes` (charts compress roughly 10x, so the expansion budget must exceed the download cap), and OCI manifests and tag lists are bounded at 4 MiB each. Registry routes are read-only and support only `GET` and `HEAD`: helmoci does not implement pushes, tag mutation, or the catalog API. Any other method, on registry paths and on `/`, `/healthz`, and `/metrics` alike, returns `405 UNSUPPORTED` with the standard OCI error body.

Automatic host/path names are restricted to public-looking DNS hostnames and HTTPS. Localhost, raw IP addresses, bare names, `.local` names, and DNS answers containing non-public addresses are rejected. Redirects are followed, up to five hops, and every hop is revalidated: a cross-origin hop must itself be public HTTPS, credentials and cookies are stripped, and an HTTPS-to-HTTP downgrade is refused. Explicitly configured aliases are the mechanism for trusted upstreams that do not fit that policy.

For an OCI alias with `store: true`, a blob is buffered, digest-verified, and cached whenever it fits within `max_chart_bytes` — including responses that arrive chunked without an advertised content length. A blob that exceeds the limit streams through to the client without entering the cache, and that skip is counted by `helmoci_oci_blob_cache_skips_total` rather than passing silently.

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
