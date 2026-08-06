//! `init_logging` must not bridge the `log` facade into tracing. reqwest logs whole
//! request URLs there at debug level ("starting new connection: <url>"), so a bridge
//! would put upstream signed-URL query strings and chart references into the log the
//! moment an operator raised `LOG_LEVEL`. `observability_tracing.rs` asserts helmoci's
//! own events stay redacted; this asserts nobody else's events get in at all.
//!
//! One test in its own binary on purpose: `init_logging` installs a process-wide
//! subscriber, so a second test here would race this one for the single install.

use helmoci::config::{Logging, init_logging};

#[test]
fn init_logging_installs_a_subscriber_without_bridging_the_log_facade() {
    assert!(
        !tracing::dispatcher::has_been_set(),
        "something installed a subscriber before the test ran"
    );

    init_logging(&Logging::default()).expect("first init_logging call must succeed");

    assert!(
        tracing::dispatcher::has_been_set(),
        "init_logging did not install a subscriber, so the assertions below prove nothing"
    );
    assert_eq!(
        log::max_level(),
        log::LevelFilter::Off,
        "a `log` bridge is installed: dependency records now reach the subscriber, \
         and reqwest would leak signed upstream URLs whenever LOG_LEVEL is raised"
    );
    assert!(
        !log::log_enabled!(log::Level::Error),
        "the `log` facade is live even at error level; dependency records must be dropped"
    );

    assert!(
        init_logging(&Logging::default()).is_err(),
        "a second init_logging call silently succeeded; the subscriber is install-once"
    );
}
