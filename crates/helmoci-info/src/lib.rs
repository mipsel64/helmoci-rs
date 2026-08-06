//! Build-time provenance. `GIT_SHA` and `BUILD_TIME` are injected by the
//! release build; a plain `cargo build` leaves them unset and reports
//! "unknown" rather than failing.

use const_format::{concatcp, formatcp};

const SHORT_SHA_LEN: usize = 7;

const GIT_SHA: &str = match option_env!("GIT_SHA") {
    Some(sha) => sha,
    None => "unknown",
};

const BUILD_TIME: &str = match option_env!("BUILD_TIME") {
    Some(time) => time,
    None => "unknown",
};

pub const fn git_sha() -> &'static str {
    GIT_SHA
}

pub const fn short_git_sha() -> &'static str {
    let bytes = GIT_SHA.as_bytes();
    let len = if bytes.len() < SHORT_SHA_LEN {
        bytes.len()
    } else {
        SHORT_SHA_LEN
    };
    match std::str::from_utf8(bytes.split_at(len).0) {
        Ok(sha) => sha,
        Err(_) => "unknown",
    }
}

pub const fn build_time() -> &'static str {
    BUILD_TIME
}

/// Version detail for clap's `--version`, which already prefixes the binary
/// name — hence no product name here.
pub const fn version() -> &'static str {
    formatcp!(
        "{} (commit: {GIT_SHA}) built on {BUILD_TIME}",
        env!("CARGO_PKG_VERSION"),
    )
}

pub const fn user_agent() -> &'static str {
    concatcp!("helmoci/", env!("CARGO_PKG_VERSION"), "-", short_git_sha())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_git_sha_is_a_prefix_of_at_most_seven_chars() {
        let short = short_git_sha();
        assert!(short.len() <= SHORT_SHA_LEN);
        assert!(git_sha().starts_with(short));
    }

    #[test]
    fn version_reports_crate_version_sha_and_build_time() {
        let v = version();
        assert!(v.starts_with(env!("CARGO_PKG_VERSION")));
        assert!(v.contains(git_sha()));
        assert!(v.contains(build_time()));
    }

    #[test]
    fn version_omits_product_name_so_clap_does_not_repeat_it() {
        assert!(!version().contains("helmoci"));
    }

    #[test]
    fn user_agent_carries_version_and_short_sha() {
        let ua = user_agent();
        let prefix = format!("helmoci/{}-", env!("CARGO_PKG_VERSION"));
        assert!(ua.starts_with(&prefix), "{ua} should start with {prefix}");
        assert!(ua.ends_with(short_git_sha()));
    }
}
