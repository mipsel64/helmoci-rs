/// Reject localhost, bare names, raw IPs, and obvious internal hosts.
/// Port of upstream helmoci's isPublicHostname.
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
    let labels: Vec<&str> = h.split('.').collect();
    let looks_like_ipv4 = labels.len() == 4
        && labels
            .iter()
            .all(|l| !l.is_empty() && l.len() <= 3 && l.bytes().all(|b| b.is_ascii_digit()));
    if looks_like_ipv4 {
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
        ] {
            assert!(!is_public_hostname(h), "{h} should be rejected");
        }
    }
}
