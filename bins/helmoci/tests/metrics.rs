mod common;

use axum::http::StatusCode;
use helmoci_core::helm::tgz::testutil::build_chart_tgz;
use std::collections::BTreeSet;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const AUTH_CFG: &str = concat!(
    "storage:\n  type: memory\n",
    "auth:\n  enabled: true\n  tokens: [\"server-secret\"]\n",
);

fn route_labels(text: &str) -> BTreeSet<&str> {
    text.lines()
        .filter(|line| line.starts_with("helmoci_http_requests_total{"))
        .filter_map(|line| line.split("route=\"").nth(1))
        .filter_map(|rest| rest.split('"').next())
        .collect()
}

fn counter_value(text: &str, name: &str) -> f64 {
    text.lines()
        .find_map(|line| {
            let value = line.strip_prefix(name)?.strip_prefix(' ')?;
            value.parse().ok()
        })
        .unwrap_or(0.0)
}

#[tokio::test]
async fn metrics_endpoint_reports_requests() {
    let app = common::app(common::MEMORY_CFG);
    let _ = common::send(&app, "GET", "/v2/", "proxy.test").await;
    let (status, _, body) = common::send(&app, "GET", "/metrics", "proxy.test").await;
    assert_eq!(status, StatusCode::OK);
    let text = String::from_utf8_lossy(&body);
    assert!(text.contains("helmoci_http_requests_total"), "{text}");
}

#[tokio::test]
async fn route_labels_are_finite_and_respect_the_v2_boundary() {
    let app = common::app(common::MEMORY_CFG);
    let paths = [
        "/",
        "/healthz",
        "/metrics",
        "/v2",
        "/v2/",
        "/v2/example.test/chart/manifests/latest",
        "/v2/example.test/chart/blobs/sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "/v2/example.test/chart/tags/list",
        "/v2evil/example.test/chart/manifests/latest",
        "/private/raw/path",
    ];
    for path in paths {
        let _ = common::send(&app, "GET", path, "proxy.test").await;
    }

    let (_, _, body) = common::send(&app, "GET", "/metrics", "proxy.test").await;
    let text = String::from_utf8_lossy(&body);
    let labels = route_labels(&text);
    let allowed = BTreeSet::from([
        "api", "blob", "healthz", "home", "manifest", "metrics", "other", "tags",
    ]);
    assert!(
        labels.is_subset(&allowed),
        "unexpected route label: {labels:?}\n{text}"
    );
    assert!(labels.contains("manifest"), "{text}");
    assert!(labels.contains("blob"), "{text}");
    assert!(labels.contains("tags"), "{text}");
    assert!(labels.contains("other"), "{text}");
    assert!(
        text.lines().any(|line| {
            line.starts_with("helmoci_http_requests_total{")
                && line.contains("route=\"other\"")
                && line.contains("status=\"404\"")
        }),
        "/v2evil must be classified as other: {text}"
    );
}

#[tokio::test]
async fn metrics_is_exactly_public_and_counts_auth_rejections() {
    let app = common::app(AUTH_CFG);
    let (status, _, _) = common::send(&app, "GET", "/v2/", "proxy.test").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    for path in ["/metrics/", "/metrics-extra"] {
        let (status, _, _) = common::send(&app, "GET", path, "proxy.test").await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{path}");
    }

    let (status, _, body) = common::send(&app, "GET", "/metrics", "proxy.test").await;
    assert_eq!(status, StatusCode::OK);
    let text = String::from_utf8_lossy(&body);
    assert!(
        text.lines().any(|line| {
            line.starts_with("helmoci_http_requests_total{")
                && line.contains("route=\"api\"")
                && line.contains("status=\"401\"")
        }),
        "auth rejection was not counted: {text}"
    );
}

#[tokio::test]
async fn metrics_include_duration_without_raw_request_data() {
    let app = common::app(common::MEMORY_CFG);
    let sensitive = "top-secret-repository-42";
    let path = format!("/v2evil/{sensitive}/manifests/private-tag?token={sensitive}");
    let _ = common::send(&app, "GET", &path, "secret-host.example").await;

    let (_, _, body) = common::send(&app, "GET", "/metrics", "proxy.test").await;
    let text = String::from_utf8_lossy(&body);
    assert!(
        text.contains("helmoci_http_request_duration_seconds"),
        "{text}"
    );
    for raw in [sensitive, "private-tag", "secret-host.example", "/v2evil/"] {
        assert!(!text.contains(raw), "metrics leaked {raw:?}: {text}");
    }
}

#[tokio::test]
async fn multiple_routers_share_stable_metrics_rendering() {
    let routers = (0..16)
        .map(|_| tokio::spawn(async { common::app(common::MEMORY_CFG) }))
        .collect::<Vec<_>>();
    let mut apps = Vec::new();
    for router in routers {
        apps.push(router.await.unwrap());
    }
    for app in &apps {
        let (status, _, _) = common::send(app, "GET", "/healthz", "proxy.test").await;
        assert_eq!(status, StatusCode::OK);
    }
    let (status, _, first) = common::send(&apps[0], "GET", "/metrics", "proxy.test").await;
    assert_eq!(status, StatusCode::OK);
    let (status, _, second) = common::send(&apps[1], "GET", "/metrics", "proxy.test").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        String::from_utf8_lossy(&second).contains("helmoci_http_requests_total"),
        "{}",
        String::from_utf8_lossy(&second)
    );
    assert!(!first.is_empty());
}

#[tokio::test]
async fn classic_cache_counters_track_successful_fill_and_hits() {
    let server = MockServer::start().await;
    let chart_yaml = "name: demo\nversion: 1.0.0\n";
    let index = format!(
        "entries:\n  demo:\n    - name: demo\n      version: 1.0.0\n      urls: [\"{}/demo-1.0.0.tgz\"]\n",
        server.uri()
    );
    Mock::given(method("GET"))
        .and(path("/index.yaml"))
        .respond_with(ResponseTemplate::new(200).set_body_string(index))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/demo-1.0.0.tgz"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_bytes(build_chart_tgz(&[("demo/Chart.yaml", chart_yaml)])),
        )
        .expect(1)
        .mount(&server)
        .await;
    let cfg = format!(
        "storage:\n  type: memory\nmax_chart_bytes: 65536\naliases:\n  test:\n    upstream: {}\n    store: true\n",
        server.uri()
    );
    let app = common::app(&cfg);
    let (_, _, before) = common::send(&app, "GET", "/metrics", "proxy.test").await;
    let before = String::from_utf8_lossy(&before);
    let baseline = [
        counter_value(&before, "helmoci_index_cache_hits_total"),
        counter_value(&before, "helmoci_index_cache_misses_total"),
        counter_value(&before, "helmoci_manifest_cache_hits_total"),
    ];

    let (status, _, _) =
        common::send(&app, "GET", "/v2/test/demo/manifests/1.0.0", "proxy.test").await;
    assert_eq!(status, StatusCode::OK);
    let (status, _, _) = common::send(&app, "GET", "/v2/test/demo/tags/list", "proxy.test").await;
    assert_eq!(status, StatusCode::OK);
    let (status, _, _) =
        common::send(&app, "GET", "/v2/test/demo/manifests/1.0.0", "proxy.test").await;
    assert_eq!(status, StatusCode::OK);

    let (_, _, after) = common::send(&app, "GET", "/metrics", "proxy.test").await;
    let after = String::from_utf8_lossy(&after);
    assert_eq!(
        counter_value(&after, "helmoci_index_cache_hits_total"),
        baseline[0] + 1.0,
        "{after}"
    );
    assert_eq!(
        counter_value(&after, "helmoci_index_cache_misses_total"),
        baseline[1] + 1.0,
        "{after}"
    );
    assert_eq!(
        counter_value(&after, "helmoci_manifest_cache_hits_total"),
        baseline[2] + 1.0,
        "{after}"
    );
    server.verify().await;
}
