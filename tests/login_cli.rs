//! Black-box probes of the offline `slackatui login` exit paths.
//!
//! Every case runs the real binary against a throwaway `HOME` and `TMPDIR`
//! so the user's config and token store are never touched, and every case
//! is guaranteed offline: browser-bound paths always pass `--browser` with
//! a path that does not exist (so no browser is ever launched), and any
//! argument shape that *could* reach the network is additionally fenced by
//! routing all HTTP egress to a dead local proxy. Never add a case here that
//! runs `login` without `--browser <nonexistent>` or that supplies a
//! well-formed `--token` + `--cookie` pair without the proxy fence.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const BIN: &str = env!("CARGO_BIN_EXE_slackatui");

const USAGE: &str =
    "Usage: slackatui login [workspace] [--token T --cookie C] [--browser B] [--timeout SECS]";
const NO_BROWSER_MSG: &str = "No Chromium-family browser found (looked for Brave, Chrome, Chromium, Edge). Pass --browser <path> or use --token/--cookie.";
const COOKIE_ALONE_MSG: &str =
    "--cookie alone needs a workspace: slackatui login <workspace> --cookie ...";
const NONEXISTENT_BROWSER: &str = "/nonexistent/slackatui-probe/browser";
const DEAD_PROXY: &str = "http://127.0.0.1:9";

struct Sandbox {
    home: tempfile::TempDir,
    tmp: tempfile::TempDir,
}

impl Sandbox {
    fn new() -> Self {
        Self {
            home: tempfile::Builder::new()
                .prefix("slackatui-probe-home-")
                .tempdir()
                .expect("temp HOME"),
            tmp: tempfile::Builder::new()
                .prefix("slackatui-probe-tmp-")
                .tempdir()
                .expect("temp TMPDIR"),
        }
    }

    fn run(&self, args: &[&str]) -> Output {
        let mut cmd = Command::new(BIN);
        cmd.arg("login")
            .args(args)
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .env("HOME", self.home.path())
            .env("TMPDIR", self.tmp.path())
            // Belt and braces: even if a case were to reach a network call,
            // it fails locally against a closed port instead of touching Slack.
            .env("HTTPS_PROXY", DEAD_PROXY)
            .env("HTTP_PROXY", DEAD_PROXY)
            .env("https_proxy", DEAD_PROXY)
            .env("http_proxy", DEAD_PROXY)
            .env("ALL_PROXY", DEAD_PROXY);
        cmd.output().expect("spawn slackatui")
    }

    /// Files under the sandbox HOME that look like a token-store write.
    fn store_files(&self) -> Vec<PathBuf> {
        let mut out = Vec::new();
        walk(self.home.path(), &mut out);
        out.into_iter()
            .filter(|p| p.file_name().and_then(|n| n.to_str()) != Some("config"))
            .collect()
    }

    /// Any leftover browser-profile directory from the capture flow.
    fn login_tempdirs(&self) -> Vec<PathBuf> {
        fs::read_dir(self.tmp.path())
            .expect("read TMPDIR")
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .map(|n| n.starts_with("slackatui-login-"))
                    .unwrap_or(false)
            })
            .collect()
    }
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    if let Ok(rd) = fs::read_dir(dir) {
        for e in rd.filter_map(Result::ok) {
            let p = e.path();
            if p.is_dir() {
                walk(&p, out);
            } else {
                out.push(p);
            }
        }
    }
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn assert_exit_1(o: &Output) {
    assert_eq!(
        o.status.code(),
        Some(1),
        "expected exit 1, got {:?}\nstdout:\n{}\nstderr:\n{}",
        o.status.code(),
        stdout(o),
        stderr(o)
    );
}

fn assert_no_store_write(sb: &Sandbox) {
    let files = sb.store_files();
    assert!(files.is_empty(), "unexpected files under HOME: {files:?}");
    let dirs = sb.login_tempdirs();
    assert!(dirs.is_empty(), "leftover slackatui-login-* dirs: {dirs:?}");
}

// --- --cookie alone -------------------------------------------------------

#[test]
fn cookie_alone_without_workspace_is_rejected() {
    let sb = Sandbox::new();
    let o = sb.run(&["--cookie", "xoxd-x"]);
    assert_exit_1(&o);
    let err = stderr(&o);
    assert!(
        err.lines().any(|l| l == COOKIE_ALONE_MSG),
        "stderr lacks the exact --cookie-alone line:\n{err}"
    );
    assert!(stdout(&o).is_empty(), "nothing expected on stdout");
    assert_no_store_write(&sb);
}

#[test]
fn cookie_alone_is_rejected_before_browser_lookup() {
    // A bogus --browser is present, but LoginArgs must be consulted first:
    // the --cookie-alone message wins and the no-browser message never appears.
    let sb = Sandbox::new();
    let o = sb.run(&["--cookie", "xoxd-x", "--browser", NONEXISTENT_BROWSER]);
    assert_exit_1(&o);
    let err = stderr(&o);
    assert!(err.contains(COOKIE_ALONE_MSG), "stderr:\n{err}");
    assert!(
        !err.contains("No Chromium-family browser"),
        "stderr:\n{err}"
    );
    assert_no_store_write(&sb);
}

// --- no browser found -----------------------------------------------------

#[test]
fn nonexistent_browser_override_prints_no_browser_message() {
    let sb = Sandbox::new();
    let o = sb.run(&["--browser", NONEXISTENT_BROWSER]);
    assert_exit_1(&o);
    let err = stderr(&o);
    assert!(
        err.lines().any(|l| l == NO_BROWSER_MSG),
        "stderr lacks the exact no-browser line:\n{err}"
    );
    assert_no_store_write(&sb);
}

#[test]
fn nonexistent_browser_override_with_workspace_and_timeout() {
    // Positional workspace (URL form) and --timeout are accepted; still no
    // fallback to auto-discovery when the override matches nothing.
    let sb = Sandbox::new();
    let o = sb.run(&[
        "https://myteam.slack.com/",
        "--timeout",
        "30",
        "--browser",
        NONEXISTENT_BROWSER,
    ]);
    assert_exit_1(&o);
    assert!(
        stderr(&o).contains(NO_BROWSER_MSG),
        "stderr:\n{}",
        stderr(&o)
    );
    assert_no_store_write(&sb);
}

#[test]
fn empty_browser_override_does_not_fall_back_to_discovery() {
    let sb = Sandbox::new();
    let o = sb.run(&["--browser", ""]);
    assert_exit_1(&o);
    let err = stderr(&o);
    assert!(
        err.contains("--browser must not be empty"),
        "stderr:\n{err}"
    );
    assert!(!err.contains(NO_BROWSER_MSG), "stderr:\n{err}");
    assert_no_store_write(&sb);
}

// --- argument parsing -----------------------------------------------------

#[test]
fn unknown_flag_exits_1_with_usage() {
    let sb = Sandbox::new();
    let o = sb.run(&["--bogus"]);
    assert_exit_1(&o);
    let err = stderr(&o);
    assert!(
        err.contains("--bogus"),
        "should name the offending flag:\n{err}"
    );
    assert!(
        err.lines().any(|l| l == USAGE),
        "stderr lacks usage line:\n{err}"
    );
    assert_no_store_write(&sb);
}

#[test]
fn unknown_flag_does_not_reach_browser_lookup() {
    let sb = Sandbox::new();
    let o = sb.run(&["--bogus", "--browser", NONEXISTENT_BROWSER]);
    assert_exit_1(&o);
    let err = stderr(&o);
    assert!(err.contains(USAGE), "stderr:\n{err}");
    assert!(
        !err.contains("No Chromium-family browser"),
        "stderr:\n{err}"
    );
}

#[test]
fn empty_token_is_rejected() {
    let sb = Sandbox::new();
    let o = sb.run(&["--token", ""]);
    assert_exit_1(&o);
    assert!(stderr(&o).contains(USAGE), "stderr:\n{}", stderr(&o));
    assert_no_store_write(&sb);
}

#[test]
fn whitespace_only_token_is_trimmed_and_rejected() {
    let sb = Sandbox::new();
    let o = sb.run(&["--token", "   \t "]);
    assert_exit_1(&o);
    assert!(stderr(&o).contains(USAGE), "stderr:\n{}", stderr(&o));
    assert_no_store_write(&sb);
}

#[test]
fn empty_token_is_rejected_before_browser_lookup() {
    let sb = Sandbox::new();
    let o = sb.run(&["--token", "", "--browser", NONEXISTENT_BROWSER]);
    assert_exit_1(&o);
    let err = stderr(&o);
    assert!(
        !err.contains("No Chromium-family browser"),
        "stderr:\n{err}"
    );
    assert_no_store_write(&sb);
}

#[test]
fn whitespace_only_cookie_with_token_is_rejected_before_store() {
    // Network is fenced by the dead proxy in Sandbox::run; login must reject
    // the (trimmed) empty cookie before auth.test and before any store write.
    let sb = Sandbox::new();
    let o = sb.run(&["--token", "xoxc-x", "--cookie", "   "]);
    assert_exit_1(&o);
    let err = stderr(&o);
    assert!(
        err.contains("--cookie") && err.contains("empty"),
        "expected an empty-cookie rejection, got:\n{err}"
    );
    assert!(
        !err.to_lowercase().contains("proxy") && !err.to_lowercase().contains("connect"),
        "rejection should happen before any network attempt:\n{err}"
    );
    assert_no_store_write(&sb);
}

#[test]
fn empty_cookie_with_token_is_rejected_before_store() {
    let sb = Sandbox::new();
    let o = sb.run(&["--token", "xoxc-x", "--cookie", ""]);
    assert_exit_1(&o);
    assert!(stderr(&o).contains("--cookie"), "stderr:\n{}", stderr(&o));
    assert_no_store_write(&sb);
}

#[test]
fn flag_missing_value_exits_1_with_usage() {
    for args in [
        &["--token"][..],
        &["myteam", "--cookie"][..],
        &["--browser"][..],
        &["--timeout"][..],
    ] {
        let sb = Sandbox::new();
        let o = sb.run(args);
        assert_exit_1(&o);
        let err = stderr(&o);
        assert!(err.contains(USAGE), "args {args:?} stderr:\n{err}");
        assert!(
            !err.contains("No Chromium-family browser"),
            "args {args:?} stderr:\n{err}"
        );
        assert_no_store_write(&sb);
    }
}

#[test]
fn non_numeric_timeout_exits_1_without_panic() {
    let sb = Sandbox::new();
    let o = sb.run(&["--timeout", "abc", "--browser", NONEXISTENT_BROWSER]);
    assert_exit_1(&o);
    let err = stderr(&o);
    assert!(err.contains("--timeout"), "stderr:\n{err}");
    assert!(!err.contains("panicked"), "stderr:\n{err}");
    assert_no_store_write(&sb);
}

#[test]
fn positional_workspace_after_flags_is_accepted() {
    // `login [workspace]` is a single optional positional; it must be
    // accepted regardless of where it sits relative to the flags.
    let sb = Sandbox::new();
    let o = sb.run(&["--browser", NONEXISTENT_BROWSER, "myteam"]);
    assert_exit_1(&o);
    let err = stderr(&o);
    assert!(err.contains(NO_BROWSER_MSG), "stderr:\n{err}");
    assert!(!err.contains("Unexpected argument"), "stderr:\n{err}");
    assert_no_store_write(&sb);
}

#[test]
fn workspace_with_slack_com_suffix_is_accepted() {
    let sb = Sandbox::new();
    let o = sb.run(&["myteam.slack.com", "--browser", NONEXISTENT_BROWSER]);
    assert_exit_1(&o);
    let err = stderr(&o);
    assert!(err.contains(NO_BROWSER_MSG), "stderr:\n{err}");
    assert!(!err.contains(USAGE), "stderr:\n{err}");
    assert_no_store_write(&sb);
}

#[test]
fn second_positional_is_rejected_with_usage_before_browser_lookup() {
    let sb = Sandbox::new();
    let o = sb.run(&["myteam", "other", "--browser", NONEXISTENT_BROWSER]);
    assert_exit_1(&o);
    let err = stderr(&o);
    assert!(
        err.contains("other"),
        "should name the extra argument:\n{err}"
    );
    assert!(err.contains(USAGE), "stderr:\n{err}");
    assert!(
        !err.contains("No Chromium-family browser"),
        "stderr:\n{err}"
    );
    assert_no_store_write(&sb);
}

// --- non-browser branches never consult the browser -----------------------
//
// These shapes are well-formed and therefore reach the network; the dead
// proxy in `Sandbox::run` guarantees the request fails locally. What is
// pinned here is the exit code, the absence of the no-browser message
// (proving `find_browser` is not reached), and the absence of a store write.

#[test]
fn cookie_with_workspace_does_not_reach_browser_lookup() {
    let sb = Sandbox::new();
    let o = sb.run(&[
        "myteam",
        "--cookie",
        "xoxd-x",
        "--browser",
        NONEXISTENT_BROWSER,
    ]);
    assert_exit_1(&o);
    let err = stderr(&o);
    assert!(
        !err.contains("No Chromium-family browser"),
        "cookie+workspace must not consult the browser:\n{err}"
    );
    assert!(!err.contains(COOKIE_ALONE_MSG), "stderr:\n{err}");
    assert!(!err.contains(USAGE), "stderr:\n{err}");
    assert!(!err.contains("panicked"), "stderr:\n{err}");
    assert!(!err.trim().is_empty(), "failure must be reported on stderr");
    assert_no_store_write(&sb);
}

#[test]
fn token_only_does_not_reach_browser_lookup() {
    let sb = Sandbox::new();
    let o = sb.run(&["--token", "xoxc-x", "--browser", NONEXISTENT_BROWSER]);
    assert_exit_1(&o);
    let err = stderr(&o);
    assert!(
        !err.contains("No Chromium-family browser"),
        "token-only must not consult the browser:\n{err}"
    );
    assert!(!err.contains(USAGE), "stderr:\n{err}");
    assert!(!err.contains("panicked"), "stderr:\n{err}");
    assert!(
        err.contains("Login failed"),
        "auth.test failure should be reported as a login failure:\n{err}"
    );
    assert_no_store_write(&sb);
}

#[test]
fn token_and_cookie_with_failed_auth_test_exits_1_without_store_write() {
    // Offline analogue of the `--token xoxc-bad --cookie xoxd-bad` criterion:
    // auth.test cannot succeed (dead proxy), so nothing may reach the store.
    let sb = Sandbox::new();
    let o = sb.run(&[
        "--token",
        "xoxc-bad",
        "--cookie",
        "xoxd-bad",
        "--browser",
        NONEXISTENT_BROWSER,
    ]);
    assert_exit_1(&o);
    let err = stderr(&o);
    assert!(
        !err.contains("No Chromium-family browser"),
        "stderr:\n{err}"
    );
    assert!(err.contains("Login failed"), "stderr:\n{err}");
    assert!(
        !stdout(&o).contains("Logged in as"),
        "stdout:\n{}",
        stdout(&o)
    );
    assert_no_store_write(&sb);
}

// --- top-level usage ------------------------------------------------------

#[test]
fn top_level_usage_mentions_login_shape() {
    let sb = Sandbox::new();
    let o = Command::new(BIN)
        .arg("not-a-command")
        .env_clear()
        .env("HOME", sb.home.path())
        .env("TMPDIR", sb.tmp.path())
        .output()
        .expect("spawn slackatui");
    assert_exit_1(&o);
    assert!(
        stderr(&o).contains("login [workspace] [--token T --cookie C] [--browser B]"),
        "stderr:\n{}",
        stderr(&o)
    );
}
