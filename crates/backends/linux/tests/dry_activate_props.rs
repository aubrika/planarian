//! Property test for the dry activation's classifier (catch-up coverage,
//! `docs/regression-ledger.md` B6).
//!
//! R10 (`c6347cb`, rule 21): a dry activation that exited nonzero, timed out
//! or was cut short was parsed as a plan anyway. Stated whole: for any
//! output, whatever its text, `dry_activate_failure` gives no plan exactly
//! when the run exited 0, in time, with its whole output, and so a failed
//! run never yields the smaller (or empty) plan its text would parse to.
//! `PROPTEST_CASES` goes deeper.

use planarian_backend_linux::cmd::Output;
use planarian_backend_linux::nixos::dry_activate_failure;
use proptest::prelude::*;
use proptest::test_runner::Config;

fn config() -> Config {
    let cases = std::env::var("PROPTEST_CASES").ok().and_then(|c| c.parse().ok()).unwrap_or(256);
    Config { cases, failure_persistence: None, ..Config::default() }
}

fn text() -> impl Strategy<Value = String> {
    prop_oneof![
        Just(String::new()),
        Just("would restart the following units: sshd.service\n".to_string()),
        Just(
            "would stop the following units: wg-quick-wg0.service\nwould start the following units: x.service\n"
                .to_string()
        ),
        "[ -~\n]{0,80}",
    ]
}

proptest! {
    #![proptest_config(config())]

    #[test]
    fn only_a_clean_whole_run_is_a_plan(
        status in prop_oneof![Just(None), (-2..4i32).prop_map(Some)],
        timed_out in any::<bool>(),
        truncated in any::<bool>(),
        stdout in text(),
        stderr in text(),
    ) {
        let o = Output { status, stdout, stderr, timed_out, truncated };
        let clean = status == Some(0) && !timed_out && !truncated;
        let why = dry_activate_failure(&o);
        prop_assert_eq!(why.is_none(), clean, "{:?} gave {:?}", o, why);
    }
}
