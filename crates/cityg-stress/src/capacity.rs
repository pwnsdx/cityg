//! Final capacity check: after a stress run, run the protocol test that fills
//! a group to `n_max` and checks that the next joiner is refused while every
//! member still agrees on the group state.

/// Full path of the capacity test in the `cityg-core` library tests.
pub const CAPACITY_TEST: &str = "session::tests::full_groups_refuse_joiners";

/// Arguments of the `cargo` invocation that runs [`CAPACITY_TEST`].
#[must_use]
pub fn capacity_test_command() -> [&'static str; 7] {
    [
        "test",
        "-p",
        "cityg-core",
        "--lib",
        CAPACITY_TEST,
        "--",
        "--exact",
    ]
}

/// A test filter that matches nothing exits successfully: check from the
/// harness output that [`CAPACITY_TEST`] ran and passed.
pub fn capacity_test_ran(stdout: &str) -> Result<(), String> {
    if stdout.contains(&format!("test {CAPACITY_TEST} ... ok"))
        && stdout.contains("test result: ok. 1 passed")
    {
        Ok(())
    } else {
        Err(format!("capacity test {CAPACITY_TEST} did not run"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_capacity_test_must_have_run() {
        let ran = format!(
            "running 1 test\ntest {CAPACITY_TEST} ... ok\n\ntest result: ok. 1 passed; 0 failed"
        );
        assert_eq!(capacity_test_ran(&ran), Ok(()));
        let filtered_out = "running 0 tests\n\ntest result: ok. 0 passed; 0 failed";
        assert!(capacity_test_ran(filtered_out).is_err());
        assert!(capacity_test_ran("").is_err());
        assert_eq!(capacity_test_command()[4], CAPACITY_TEST);
    }
}
