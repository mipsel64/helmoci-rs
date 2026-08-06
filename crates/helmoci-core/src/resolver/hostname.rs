/// Decimal, octal, or `0x…` hex — the label forms an IPv4 address can be written in.
fn is_numeric_label(label: &str) -> bool {
    match label.strip_prefix("0x") {
        Some(hex) => !hex.is_empty() && hex.bytes().all(|b| b.is_ascii_hexdigit()),
        None => !label.is_empty() && label.bytes().all(|b| b.is_ascii_digit()),
    }
}

/// Reject localhost, bare names, raw IPs, and obvious internal hosts.
/// Port of upstream helmoci's isPublicHostname, tightened: upstream only rejects
/// 4-label all-digit hosts, which lets IP short forms like "127.1" through.
pub fn is_public_hostname(host: &str) -> bool {
    let h = host.to_ascii_lowercase();
    if h.is_empty() || h.len() > 253 {
        return false;
    }
    if h == "localhost" || h.ends_with(".localhost") || h.ends_with(".local") {
        return false;
    }
    if h.contains(':') || h.contains(' ') {
        return false;
    }
    // "no raw IPs" has to cover the short and hex forms too: WHATWG and inet_aton
    // both read "127.1", "0x7f.1" and "2130706433" as 127.0.0.1.
    if matches!(
        url::Host::parse(&h),
        Ok(url::Host::Ipv4(_) | url::Host::Ipv6(_))
    ) {
        return false;
    }
    let labels: Vec<&str> = h.split('.').collect();
    if labels.iter().all(|label| is_numeric_label(label)) {
        return false;
    }
    if labels.len() < 2 {
        return false;
    }
    labels.iter().all(|label| {
        !label.is_empty()
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            && !label.starts_with('-')
            && !label.ends_with('-')
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_public_hosts() {
        for h in [
            "example.com",
            "charts.jetstack.io",
            "a-b.c-d.io",
            "EXAMPLE.COM",
            // Only hosts that are numeric all the way through are IP-shaped; a
            // hex-looking label next to a real TLD is just a domain.
            "0xdeadbeef.example.com",
            "127.0.0.1.example.com",
        ] {
            assert!(is_public_hostname(h), "{h} should be public");
        }
    }

    #[test]
    fn rejects_private_and_invalid_hosts() {
        for h in [
            "",
            "localhost",
            "foo.localhost",
            "printer.local",
            "nodot",
            "10.0.0.1",
            "192.168.1.1",
            "a.com:8080",
            "has space.com",
            "-bad.com",
            "bad-.com",
            "under_score.com",
            // WHATWG/inet_aton short and hex forms: `new URL("https://127.1/")`
            // has hostname 127.0.0.1.
            "127.1",
            "192.168.1",
            "0x7f.1",
            "2130706433",
            "0x7f.0x0.0x0.0x1",
            "0177.0.0.1",
        ] {
            assert!(!is_public_hostname(h), "{h} should be rejected");
        }
    }
}
