use crate::config::RuntimeConfig;
use helmoci_storage::{EphemeralStorage, Storage};
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::Duration;

pub struct AppState {
    pub cfg: RuntimeConfig,
    pub storage: Arc<dyn Storage>,
    pub ephemeral: Arc<EphemeralStorage>,
    pub http: reqwest::Client,
    pub public_http: reqwest::Client,
    pub token_http: reqwest::Client,
    pub index_cache: moka::future::Cache<String, Arc<String>>,
    pub gcp: Option<Arc<dyn crate::gcp::GcpTokenProvider>>,
    /// Tokens keyed by scheme, auth mode, registry, and repository.
    pub upstream_tokens: moka::future::Cache<String, String>,
}

pub type SharedState = Arc<AppState>;

impl AppState {
    pub fn new(
        cfg: RuntimeConfig,
        storage: Arc<dyn Storage>,
        gcp: Option<Arc<dyn crate::gcp::GcpTokenProvider>>,
    ) -> eyre::Result<SharedState> {
        let http = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(120))
            .build()?;
        let public_http = build_public_http(PublicDnsResolver::new(SystemDnsResolver))?;
        let token_http = build_token_http()?;
        let index_cache = moka::future::Cache::builder()
            .max_capacity(512)
            .time_to_live(Duration::from_secs(cfg.settings.index_cache_ttl_secs))
            .build();
        let upstream_tokens = moka::future::Cache::builder()
            .max_capacity(256)
            .time_to_live(Duration::from_secs(240))
            .build();
        let ephemeral = Arc::new(EphemeralStorage::new(
            cfg.settings.ephemeral_cache.max_bytes,
            Duration::from_secs(cfg.settings.ephemeral_cache.ttl_secs),
        ));
        Ok(Arc::new(AppState {
            cfg,
            storage,
            ephemeral,
            http,
            public_http,
            token_http,
            index_cache,
            gcp,
            upstream_tokens,
        }))
    }
}

// Mirrors the pinned standard library's unstable `is_global` classification.
fn is_public_ipv4(ip: Ipv4Addr) -> bool {
    let [a, b, c, d] = ip.octets();
    !(a == 0
        || ip.is_private()
        || (a == 100 && b & 0b1100_0000 == 0b0100_0000)
        || ip.is_loopback()
        || ip.is_link_local()
        || (a == 192 && b == 0 && c == 0 && d != 9 && d != 10)
        || ip.is_documentation()
        || (a == 198 && b & 0xfe == 18)
        || a >= 240
        || ip.is_broadcast()
        || ip.is_multicast())
}

fn is_public_ipv6(ip: Ipv6Addr) -> bool {
    let segments = ip.segments();
    let value = u128::from_be_bytes(ip.octets());
    let ietf_exception = value == 0x2001_0001_0000_0000_0000_0000_0000_0001
        || value == 0x2001_0001_0000_0000_0000_0000_0000_0002
        || matches!(segments, [0x2001, 3, _, _, _, _, _, _])
        || matches!(segments, [0x2001, 4, 0x112, _, _, _, _, _])
        || matches!(segments, [0x2001, 0x20..=0x3f, _, _, _, _, _, _]);
    let ietf_assignment =
        matches!(segments, [0x2001, b, _, _, _, _, _, _] if b < 0x200) && !ietf_exception;
    let documentation = matches!(segments, [0x2001, 0x0db8, _, _, _, _, _, _])
        || (segments[0] == 0x3fff && segments[1] & 0xf000 == 0);

    !(ip.is_unspecified()
        || ip.is_loopback()
        || matches!(segments, [0, 0, 0, 0, 0, 0xffff, _, _])
        || matches!(segments, [0x64, 0xff9b, 1, _, _, _, _, _])
        || matches!(segments, [0x100, 0, 0, 0, _, _, _, _])
        || ietf_assignment
        || matches!(segments, [0x2002, _, _, _, _, _, _, _])
        || documentation
        || matches!(segments, [0x5f00, ..])
        || segments[0] & 0xfe00 == 0xfc00
        || segments[0] & 0xffc0 == 0xfe80
        || ip.is_multicast())
}

pub(crate) fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => is_public_ipv4(ip),
        IpAddr::V6(ip) => is_public_ipv6(ip),
    }
}

pub(crate) struct PublicDnsResolver<R> {
    inner: R,
}

impl<R> PublicDnsResolver<R> {
    pub(crate) fn new(inner: R) -> Self {
        Self { inner }
    }
}

impl<R: Resolve> Resolve for PublicDnsResolver<R> {
    fn resolve(&self, name: Name) -> Resolving {
        let hostname = name.as_str().to_string();
        let resolving = self.inner.resolve(name);
        Box::pin(async move {
            let addresses: Vec<_> = resolving.await?.collect();
            if addresses.is_empty() || addresses.iter().any(|addr| !is_public_ip(addr.ip())) {
                let error = io::Error::other(format!(
                    "DNS for {hostname} returned no addresses or a non-public address"
                ));
                return Err(Box::new(error) as Box<dyn std::error::Error + Send + Sync>);
            }
            Ok(Box::new(addresses.into_iter()) as Addrs)
        })
    }
}

struct SystemDnsResolver;

impl Resolve for SystemDnsResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let hostname = name.as_str().to_string();
        Box::pin(async move {
            let addresses: Vec<_> = tokio::net::lookup_host((hostname.as_str(), 0))
                .await?
                .collect();
            Ok(Box::new(addresses.into_iter()) as Addrs)
        })
    }
}

fn build_no_redirect_http<R: Resolve + 'static>(resolver: R) -> eyre::Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(120))
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .dns_resolver(Arc::new(resolver))
        .build()?)
}

pub(crate) fn build_public_http<R: Resolve + 'static>(
    resolver: PublicDnsResolver<R>,
) -> eyre::Result<reqwest::Client> {
    build_no_redirect_http(resolver)
}

pub(crate) fn build_token_http() -> eyre::Result<reqwest::Client> {
    build_no_redirect_http(SystemDnsResolver)
}

#[cfg(test)]
pub(crate) fn build_test_no_redirect_http<R: Resolve + 'static>(
    resolver: R,
) -> eyre::Result<reqwest::Client> {
    build_no_redirect_http(resolver)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    struct StaticResolver(SocketAddr);

    impl Resolve for StaticResolver {
        fn resolve(&self, _name: Name) -> Resolving {
            let address = self.0;
            Box::pin(async move { Ok(Box::new(std::iter::once(address)) as Addrs) })
        }
    }

    #[test]
    fn rejects_non_public_address_ranges() {
        for address in [
            "0.1.2.3",
            "10.0.0.1",
            "100.64.0.1",
            "127.0.0.1",
            "169.254.169.254",
            "192.0.0.8",
            "192.0.0.11",
            "192.0.2.1",
            "198.18.0.1",
            "198.51.100.1",
            "203.0.113.1",
            "224.0.0.1",
            "240.0.0.1",
            "255.255.255.255",
            "::",
            "::1",
            "::ffff:192.0.2.1",
            "64:ff9b:1::1",
            "100::1",
            "2001::1",
            "2001:2::1",
            "2001:db8::1",
            "2002::1",
            "3fff::1",
            "5f00::1",
            "fc00::1",
            "fe80::1",
            "ff00::1",
        ] {
            assert!(!is_public_ip(address.parse().unwrap()), "{address}");
        }
        for address in [
            "8.8.8.8",
            "1.1.1.1",
            "192.0.0.9",
            "192.0.0.10",
            "2001:1::1",
            "2001:1::2",
            "2001:3::1",
            "2001:4:112::1",
            "2001:20::1",
            "2606:4700:4700::1111",
        ] {
            assert!(is_public_ip(address.parse().unwrap()), "{address}");
        }
    }

    #[tokio::test]
    async fn validating_resolver_rejects_injected_non_public_answers() {
        for address in ["10.0.0.1:80", "127.0.0.1:80", "169.254.169.254:80"] {
            let resolver = PublicDnsResolver::new(StaticResolver(address.parse().unwrap()));
            let result = resolver.resolve("public.example".parse().unwrap()).await;
            assert!(result.is_err(), "{address}");
        }
    }

    #[tokio::test]
    async fn validating_resolver_returns_the_exact_public_answer() {
        let address = "8.8.8.8:443".parse().unwrap();
        let resolver = PublicDnsResolver::new(StaticResolver(address));

        let result: Vec<_> = resolver
            .resolve("public.example".parse().unwrap())
            .await
            .unwrap()
            .collect();

        assert_eq!(result, vec![address]);
    }
}
