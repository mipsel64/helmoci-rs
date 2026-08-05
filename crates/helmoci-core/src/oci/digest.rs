use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::fmt;

/// Always the canonical form `sha256:<64 lowercase hex>`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Digest(String);

impl Digest {
    pub fn sha256(data: &[u8]) -> Self {
        Digest(format!("sha256:{}", hex::encode(Sha256::digest(data))))
    }

    pub fn parse(s: &str) -> Option<Self> {
        let hex_part = s.strip_prefix("sha256:")?;
        let canonical = hex_part.len() == 64
            && hex_part
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        canonical.then(|| Digest(s.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<String> for Digest {
    type Error = String;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        Digest::parse(&s).ok_or_else(|| format!("invalid digest: {s}"))
    }
}

impl From<Digest> for String {
    fn from(d: Digest) -> String {
        d.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn computes_sha256() {
        let d = Digest::sha256(b"hello");
        assert_eq!(
            d.as_str(),
            "sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn parses_only_canonical_digests() {
        let ok = "sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
        assert!(Digest::parse(ok).is_some());
        assert!(Digest::parse("sha256:short").is_none());
        assert!(Digest::parse("md5:d41d8cd98f00b204e9800998ecf8427e").is_none());
        assert!(Digest::parse(&ok.to_uppercase()).is_none());
        assert!(Digest::parse("1.2.3").is_none());
    }

    #[test]
    fn serde_round_trip_is_plain_string() {
        let d = Digest::sha256(b"x");
        let json = serde_json::to_string(&d).unwrap();
        assert_eq!(json, format!("\"{}\"", d.as_str()));
        let back: Digest = serde_json::from_str(&json).unwrap();
        assert_eq!(back, d);
    }
}
