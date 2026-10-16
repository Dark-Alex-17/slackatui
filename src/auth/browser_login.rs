use regex::Regex;
use serde_json::Value;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::LazyLock;
use tempfile::TempDir;
use tokio::process::{Child, Command};
use tokio::time::{timeout, Duration};
use tracing::warn;

use super::{wait_for_active_port, BrowserCookie, DevToolsClient, DevToolsError};

pub const NO_BROWSER_MSG: &str = "No Chromium-family browser found (looked for Brave, Chrome, Chromium, Edge). Pass --browser <path> or use --token/--cookie.";
pub const BROWSER_CLOSED_MSG: &str = "Browser closed before login completed.";

const BROWSER_BUNDLES: &[&str] = &[
    "Brave Browser.app/Contents/MacOS/Brave Browser",
    "Google Chrome.app/Contents/MacOS/Google Chrome",
    "Chromium.app/Contents/MacOS/Chromium",
    "Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
];

const DESKTOP_USER_AGENT: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36";
const LOCAL_CONFIG_EXPRESSION: &str = "localStorage.getItem('localConfig_v2')";
const ACTIVE_PORT_TIMEOUT: Duration = Duration::from_secs(20);
const POLL_INTERVAL: Duration = Duration::from_secs(1);
const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);
const EMPTY_PAGE_TICKS_BEFORE_CLOSED: u32 = 5;

static API_TOKEN_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#""api_token"\s*:\s*"(xox[a-z]-[A-Za-z0-9-]+)""#).unwrap());

#[derive(Debug)]
pub enum BrowserLoginError {
    Io(String),
    Launch(String),
    DevTools(String),
    Http(String),
    BrowserClosed,
    Timeout(u64),
    Interrupted,
}

impl std::fmt::Display for BrowserLoginError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BrowserLoginError::Io(msg) => write!(f, "login I/O error: {}", msg),
            BrowserLoginError::Launch(msg) => write!(f, "could not launch browser: {}", msg),
            BrowserLoginError::DevTools(msg) => write!(f, "browser devtools error: {}", msg),
            BrowserLoginError::Http(msg) => write!(f, "HTTP error: {}", msg),
            BrowserLoginError::BrowserClosed => write!(f, "{}", BROWSER_CLOSED_MSG),
            BrowserLoginError::Timeout(secs) => write!(
                f,
                "Timed out after {}s waiting for the Slack sign-in to complete.",
                secs
            ),
            BrowserLoginError::Interrupted => write!(f, "Login cancelled."),
        }
    }
}

impl std::error::Error for BrowserLoginError {}

impl From<DevToolsError> for BrowserLoginError {
    fn from(e: DevToolsError) -> Self {
        match e {
            DevToolsError::Closed => BrowserLoginError::BrowserClosed,
            other => BrowserLoginError::DevTools(other.to_string()),
        }
    }
}

/// What to launch and how long to wait for the sign-in.
#[derive(Debug, Clone)]
pub struct BrowserLoginOptions {
    pub workspace: Option<String>,
    pub browser: PathBuf,
    pub timeout: Duration,
}

/// Credentials captured from a signed-in browser session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapturedSession {
    pub domain: String,
    pub token: String,
    pub cookie: String,
}

/// Reduce `https://myteam.slack.com/`, `myteam.slack.com` or `myteam` to `myteam`.
pub fn normalize_workspace(input: &str) -> String {
    let lowered = input.trim().to_ascii_lowercase();
    let s = lowered.as_str();
    let s = s
        .strip_prefix("https://")
        .or_else(|| s.strip_prefix("http://"))
        .unwrap_or(s);
    let s = s.split('/').next().unwrap_or(s);
    s.strip_suffix(".slack.com").unwrap_or(s).to_string()
}

fn browser_candidates() -> Vec<PathBuf> {
    let mut roots = vec![PathBuf::from("/Applications")];
    if let Some(home) = dirs::home_dir() {
        roots.push(home.join("Applications"));
    }
    roots
        .iter()
        .flat_map(|root| BROWSER_BUNDLES.iter().map(move |bundle| root.join(bundle)))
        .collect()
}

/// Locate a Chromium-family browser binary; `override_` is a path or a bundle name like `chrome`.
pub fn find_browser(override_: Option<&str>) -> Option<PathBuf> {
    find_browser_in(override_, &browser_candidates())
}

fn find_browser_in(override_: Option<&str>, candidates: &[PathBuf]) -> Option<PathBuf> {
    let Some(wanted) = override_ else {
        return candidates.iter().find(|c| c.is_file()).cloned();
    };
    let explicit = Path::new(wanted);
    if explicit.is_file() {
        return Some(explicit.to_path_buf());
    }
    if explicit.is_dir() && explicit.extension().is_some_and(|ext| ext == "app") {
        let exe = explicit
            .join("Contents")
            .join("MacOS")
            .join(explicit.file_stem()?);
        if exe.is_file() {
            return Some(exe);
        }
    }
    let wanted = wanted.trim().to_lowercase();
    let wanted = wanted.strip_suffix(".app").unwrap_or(&wanted);
    if wanted.is_empty() {
        return None;
    }
    candidates
        .iter()
        .filter(|c| bundle_name_matches(c, wanted))
        .find(|c| c.is_file())
        .cloned()
}

fn bundle_name_matches(candidate: &Path, wanted: &str) -> bool {
    candidate
        .components()
        .filter_map(|c| c.as_os_str().to_str())
        .filter_map(|c| c.strip_suffix(".app"))
        .any(|app| app.to_lowercase().contains(wanted))
}

fn teams_with_tokens(local_config_json: &str) -> Option<Vec<(String, String)>> {
    let config: Value = serde_json::from_str(local_config_json).ok()?;
    let teams = config["teams"].as_object()?;
    Some(
        teams
            .values()
            .filter_map(|team| {
                let domain = team["domain"].as_str()?;
                let token = team["token"].as_str()?;
                token
                    .starts_with("xox")
                    .then(|| (domain.to_string(), token.to_string()))
            })
            .collect(),
    )
}

/// `(domain, token)` from a `localConfig_v2` blob: the team matching `workspace` when it
/// has one, otherwise the first team with a token.
pub fn team_token(local_config_json: &str, workspace: Option<&str>) -> Option<(String, String)> {
    let teams = teams_with_tokens(local_config_json)?;
    let requested = workspace.and_then(|ws| teams.iter().position(|(domain, _)| domain == ws));
    let index = requested.unwrap_or(0);
    teams.into_iter().nth(index)
}

/// The `api_token` embedded in a workspace's HTML boot data.
pub fn token_in_html(html: &str) -> Option<String> {
    API_TOKEN_RE.captures(html).map(|caps| caps[1].to_string())
}

/// The value of Slack's `d` session cookie, if present.
pub fn session_cookie(cookies: &[BrowserCookie]) -> Option<String> {
    cookies
        .iter()
        .find(|c| {
            c.name == "d"
                && (c.domain == "slack.com" || c.domain.ends_with(".slack.com"))
                && c.value.starts_with("xoxd-")
        })
        .map(|c| c.value.clone())
}

/// The workspace subdomain from the first `<workspace>.slack.com` page URL.
pub fn infer_domain(page_urls: &[String]) -> Option<String> {
    page_urls.iter().find_map(|page_url| {
        let parsed = url::Url::parse(page_url).ok()?;
        let subdomain = parsed.host_str()?.strip_suffix(".slack.com")?;
        let generic = subdomain.is_empty() || matches!(subdomain, "app" | "www" | "api");
        (!generic).then(|| subdomain.to_string())
    })
}

/// Fetch the workspace home page with the session cookie and pull the token out of its HTML.
pub async fn token_via_html(
    domain: &str,
    cookie: &str,
) -> Result<Option<String>, BrowserLoginError> {
    let response = reqwest::Client::new()
        .get(format!("https://{}.slack.com/", domain))
        .header(reqwest::header::COOKIE, format!("d={}", cookie))
        .header(reqwest::header::USER_AGENT, DESKTOP_USER_AGENT)
        .send()
        .await
        .map_err(|e| BrowserLoginError::Http(e.to_string()))?;
    if !response.status().is_success() {
        return Ok(None);
    }
    let html = response
        .text()
        .await
        .map_err(|e| BrowserLoginError::Http(e.to_string()))?;
    Ok(token_in_html(&html))
}

/// Launch the browser on Slack's sign-in page and wait until a session token and cookie
/// can be read from it. The browser and its temporary profile are removed on every exit path.
pub async fn capture(opts: BrowserLoginOptions) -> Result<CapturedSession, BrowserLoginError> {
    let profile = tempfile::Builder::new()
        .prefix("slackatui-login-")
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
        .map_err(|e| BrowserLoginError::Io(e.to_string()))?;
    let url = match &opts.workspace {
        Some(ws) => format!("https://{}.slack.com/", ws),
        None => "https://slack.com/signin".to_string(),
    };

    let mut cmd = Command::new(&opts.browser);
    cmd.arg("--remote-debugging-port=0")
        .arg(format!("--user-data-dir={}", profile.path().display()))
        .arg("--no-first-run")
        .arg("--no-default-browser-check")
        .arg("--disable-sync")
        .arg("--window-size=1100,800")
        .arg("--new-window")
        .arg(url)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    let mut child = cmd
        .spawn()
        .map_err(|e| BrowserLoginError::Launch(e.to_string()))?;

    let mut cdp = match connect(profile.path(), &mut child).await {
        Ok(cdp) => cdp,
        Err(e) => {
            shutdown(None, &mut child, profile).await;
            return Err(e);
        }
    };

    let result = tokio::select! {
        r = timeout(opts.timeout, poll_for_session(&mut cdp, opts.workspace.as_deref())) => match r {
            Ok(session) => session,
            Err(_) => Err(BrowserLoginError::Timeout(opts.timeout.as_secs())),
        },
        _ = interrupt() => Err(BrowserLoginError::Interrupted),
    };
    shutdown(Some(&mut cdp), &mut child, profile).await;
    result
}

/// Resolves on Ctrl-C. If the handler cannot be installed the default SIGINT disposition
/// stays in force (immediate hard exit, no browser cleanup); only graceful cancellation is lost.
async fn interrupt() {
    match tokio::signal::ctrl_c().await {
        Ok(()) => {}
        Err(e) => {
            warn!("could not install Ctrl-C handler: {}", e);
            std::future::pending::<()>().await;
        }
    }
}

async fn connect(profile: &Path, child: &mut Child) -> Result<DevToolsClient, BrowserLoginError> {
    let connected = async {
        let ws_url = wait_for_active_port(profile, ACTIVE_PORT_TIMEOUT).await?;
        DevToolsClient::connect(&ws_url).await
    }
    .await;
    match connected {
        Ok(cdp) => Ok(cdp),
        // A browser that already exited explains any connect failure better than the
        // socket error does.
        Err(_) if matches!(child.try_wait(), Ok(Some(_))) => Err(BrowserLoginError::BrowserClosed),
        Err(e) => Err(e.into()),
    }
}

async fn poll_for_session(
    cdp: &mut DevToolsClient,
    workspace: Option<&str>,
) -> Result<CapturedSession, BrowserLoginError> {
    let mut empty_page_ticks = 0;
    let mut html_checked_pages: Option<Vec<String>> = None;
    loop {
        let pages = cdp.pages().await?;
        if pages.is_empty() {
            empty_page_ticks += 1;
            if empty_page_ticks >= EMPTY_PAGE_TICKS_BEFORE_CLOSED {
                return Err(BrowserLoginError::BrowserClosed);
            }
        } else {
            empty_page_ticks = 0;
        }

        let cookies = cdp.cookies().await?;
        if let Some(cookie) = session_cookie(&cookies) {
            for (target_id, page_url) in &pages {
                if !page_url.starts_with("https://app.slack.com/") {
                    continue;
                }
                let raw = match cdp.evaluate(target_id, LOCAL_CONFIG_EXPRESSION).await {
                    Ok(value) => value,
                    Err(e) => {
                        warn!("could not read localConfig_v2 from {}: {}", page_url, e);
                        continue;
                    }
                };
                let Some(raw) = raw.as_str() else { continue };
                if let Some((domain, token)) = team_token(raw, workspace) {
                    return Ok(CapturedSession {
                        domain,
                        token,
                        cookie,
                    });
                }
            }

            let page_urls: Vec<String> = pages.iter().map(|(_, u)| u.clone()).collect();
            // The HTML fallback only has new information to work with once the set of open
            // pages changes, so do not re-fetch it on every tick.
            if html_checked_pages.as_ref() != Some(&page_urls) {
                let domain = workspace
                    .map(str::to_string)
                    .or_else(|| infer_domain(&page_urls));
                if let Some(domain) = domain {
                    match token_via_html(&domain, &cookie).await {
                        Ok(Some(token)) => {
                            return Ok(CapturedSession {
                                domain,
                                token,
                                cookie,
                            })
                        }
                        Ok(None) => {}
                        Err(e) => warn!("token lookup via {}.slack.com failed: {}", domain, e),
                    }
                }
                html_checked_pages = Some(page_urls);
            }
        }

        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

async fn shutdown(cdp: Option<&mut DevToolsClient>, child: &mut Child, profile: TempDir) {
    if let Some(cdp) = cdp {
        match timeout(SHUTDOWN_GRACE, cdp.close_browser()).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => warn!("Browser.close failed: {}", e),
            Err(_) => warn!("Browser.close did not answer within {:?}", SHUTDOWN_GRACE),
        }
    }
    if !matches!(timeout(SHUTDOWN_GRACE, child.wait()).await, Ok(Ok(_))) {
        if let Err(e) = child.kill().await {
            warn!("could not kill browser: {}", e);
        }
    }
    // The browser writes to its profile while exiting, so the directory is only
    // removed once the process is gone.
    if let Err(e) = profile.close() {
        warn!("could not remove temporary browser profile: {}", e);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cookie(name: &str, domain: &str, value: &str) -> BrowserCookie {
        BrowserCookie {
            name: name.to_string(),
            domain: domain.to_string(),
            value: value.to_string(),
        }
    }

    const TWO_TEAMS: &str = r#"{"teams": {
        "T1": {"domain": "alpha", "token": "xoxc-alpha"},
        "T2": {"domain": "beta", "token": "xoxc-beta"}
    }}"#;

    #[test]
    fn test_team_token_by_domain() {
        assert_eq!(
            team_token(TWO_TEAMS, Some("beta")),
            Some(("beta".to_string(), "xoxc-beta".to_string()))
        );
    }

    #[test]
    fn test_team_token_falls_back_when_requested_team_absent() {
        assert_eq!(
            team_token(TWO_TEAMS, Some("gamma")),
            Some(("alpha".to_string(), "xoxc-alpha".to_string()))
        );
    }

    #[test]
    fn test_team_token_first_with_token() {
        let json = r#"{"teams": {
            "T1": {"domain": "alpha"},
            "T2": {"domain": "beta", "token": "xoxc-beta"}
        }}"#;
        assert_eq!(
            team_token(json, None),
            Some(("beta".to_string(), "xoxc-beta".to_string()))
        );
    }

    #[test]
    fn test_team_token_none_without_tokens() {
        let json = r#"{"teams": {"T1": {"domain": "alpha", "token": ""}}}"#;
        assert_eq!(team_token(json, None), None);
        assert_eq!(team_token(r#"{"teams": {}}"#, None), None);
        assert_eq!(team_token(r#"{}"#, None), None);
    }

    #[test]
    fn test_team_token_malformed_json() {
        assert_eq!(team_token("not json", None), None);
    }

    #[test]
    fn test_token_in_html_match() {
        let html = r#"<script>boot_data = {"api_token":"xoxc-123-abc", "x": 1}</script>"#;
        assert_eq!(token_in_html(html).as_deref(), Some("xoxc-123-abc"));
    }

    #[test]
    fn test_token_in_html_no_match() {
        assert_eq!(token_in_html("<html></html>"), None);
        assert_eq!(token_in_html(r#"{"api_token":"nope"}"#), None);
    }

    #[test]
    fn test_token_in_html_accepts_xoxb() {
        assert_eq!(
            token_in_html(r#""api_token" : "xoxb-1-2""#).as_deref(),
            Some("xoxb-1-2")
        );
    }

    #[test]
    fn test_session_cookie_ignores_decoys() {
        let cookies = [
            cookie("d-s", ".slack.com", "xoxd-decoy"),
            cookie("d", "example.com", "xoxd-wrong-domain"),
            cookie("d", "notslack.com", "xoxd-wrong-domain"),
            cookie("d", ".slack.com", "not-a-session"),
            cookie("d", ".slack.com", "xoxd-good"),
        ];
        assert_eq!(session_cookie(&cookies).as_deref(), Some("xoxd-good"));
        assert_eq!(session_cookie(&cookies[..4]), None);
    }

    #[test]
    fn test_normalize_workspace() {
        assert_eq!(normalize_workspace("https://myteam.slack.com/"), "myteam");
        assert_eq!(normalize_workspace("myteam.slack.com"), "myteam");
        assert_eq!(normalize_workspace(" myteam "), "myteam");
        assert_eq!(normalize_workspace("MyTeam"), "myteam");
        assert_eq!(normalize_workspace("MyTeam.Slack.com"), "myteam");
        assert_eq!(normalize_workspace("HTTPS://MyTeam.slack.com/"), "myteam");
        assert_eq!(
            normalize_workspace("http://myteam.slack.com/messages"),
            "myteam"
        );
    }

    #[test]
    fn test_infer_domain() {
        let urls = [
            "https://app.slack.com/client/T1".to_string(),
            "https://www.slack.com/".to_string(),
            "https://api.slack.com/methods".to_string(),
            "https://slack.com/signin".to_string(),
            "https://myteam.slack.com/x".to_string(),
        ];
        assert_eq!(infer_domain(&urls).as_deref(), Some("myteam"));
        assert_eq!(infer_domain(&urls[..4]), None);
        assert_eq!(infer_domain(&[]), None);
    }

    #[test]
    fn test_find_browser_nonexistent_override() {
        assert_eq!(find_browser(Some("/nonexistent/path/to/browser")), None);
    }

    #[test]
    fn test_find_browser_in_no_candidates_exist() {
        let candidates = [PathBuf::from(
            "/nonexistent/Chromium.app/Contents/MacOS/Chromium",
        )];
        assert_eq!(find_browser_in(None, &candidates), None);
    }

    #[test]
    fn test_find_browser_in_explicit_path() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let candidates = [PathBuf::from(
            "/nonexistent/Chromium.app/Contents/MacOS/Chromium",
        )];
        assert_eq!(
            find_browser_in(Some(file.path().to_str().unwrap()), &candidates),
            Some(file.path().to_path_buf())
        );
    }

    #[test]
    fn test_find_browser_in_app_bundle_dir() {
        let dir = tempfile::tempdir().unwrap();
        let bundle = dir.path().join("X.app");
        let exe = bundle.join("Contents/MacOS/X");
        std::fs::create_dir_all(exe.parent().unwrap()).unwrap();
        std::fs::write(&exe, b"").unwrap();
        assert_eq!(
            find_browser_in(Some(bundle.to_str().unwrap()), &[]),
            Some(exe)
        );
    }

    #[test]
    fn test_find_browser_in_name_match() {
        let dir = tempfile::tempdir().unwrap();
        let chrome = dir
            .path()
            .join("Google Chrome.app/Contents/MacOS/Google Chrome");
        std::fs::create_dir_all(chrome.parent().unwrap()).unwrap();
        std::fs::write(&chrome, b"").unwrap();
        let candidates = [
            PathBuf::from("/nonexistent/Brave Browser.app/Contents/MacOS/Brave Browser"),
            chrome.clone(),
        ];
        assert_eq!(
            find_browser_in(Some("chrome"), &candidates),
            Some(chrome.clone())
        );
        assert_eq!(
            find_browser_in(Some("Google Chrome.app"), &candidates),
            Some(chrome.clone())
        );
        assert_eq!(find_browser_in(None, &candidates), Some(chrome));
        assert_eq!(find_browser_in(Some("edge"), &candidates), None);
        assert_eq!(find_browser_in(Some("chromium"), &candidates), None);
    }
}
