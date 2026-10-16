#![allow(dead_code)]

mod auth;
mod config;
mod highlight;
mod parse;
mod service;
mod slack;
mod tui;
mod types;

use auth::{
    load_tokens, normalize_workspace, store_tokens, tokens_from_env, BrowserLoginOptions,
    StoreType, StoredTokens, NO_BROWSER_MSG,
};
use config::Config;
use service::SlackService;
use slack::SlackClient;
use std::path::PathBuf;
use std::time::Duration;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    let config_path = config::default_config_path();
    let cfg = match Config::load(&config_path) {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("Error loading config: {}", e);
            std::process::exit(1);
        }
    };

    // Handle subcommands
    if args.len() > 1 {
        match args[1].as_str() {
            "auth" => {
                run_auth(&cfg);
                return;
            }
            "config" => {
                config::run_config_wizard();
                return;
            }
            "login" => {
                run_login(&cfg, &args[2..]);
                return;
            }
            other => {
                eprintln!("Unknown command: {}", other);
                eprintln!("Usage: slackatui [auth|config|login [workspace] [--token T --cookie C] [--browser B] [--timeout SECS]]");
                std::process::exit(1);
            }
        }
    }

    // Load stored token
    let store_type = match StoreType::from_str(&cfg.auth.token_store) {
        Ok(st) => st,
        Err(e) => {
            eprintln!("Invalid token_store config: {}", e);
            std::process::exit(1);
        }
    };

    let tokens = match tokens_from_env() {
        Some(t) => t,
        None => match load_tokens(&cfg.auth.team_id, &store_type) {
            Ok(t) => t,
            Err(_) => {
                eprintln!("No stored tokens found. Run `slackatui auth` first to authenticate.");
                std::process::exit(1);
            }
        },
    };

    // Pick the token to use based on preference
    let token = match cfg.auth.token_preference.as_str() {
        "bot" if !tokens.bot_token.is_empty() => &tokens.bot_token,
        _ if !tokens.user_token.is_empty() => &tokens.user_token,
        _ if !tokens.bot_token.is_empty() => &tokens.bot_token,
        _ => {
            eprintln!("No valid token found. Run `slackatui auth` to re-authenticate.");
            std::process::exit(1);
        }
    };

    let cookie = (!tokens.cookie.is_empty()).then_some(tokens.cookie.as_str());
    let client = SlackClient::with_cookie(token, cookie);
    let svc = SlackService::new(client, cfg.emoji);

    // Run the TUI with the tokio runtime
    let rt = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");
    rt.block_on(async {
        if let Err(e) = tui::run_async(cfg, svc).await {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    });
}

fn run_auth(cfg: &Config) {
    let rt = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");
    rt.block_on(async {
        let oauth_cfg = auth::OAuthConfig {
            client_id: cfg.auth.client_id.clone(),
            client_secret: cfg.auth.client_secret.clone(),
            redirect_uri: cfg.auth.redirect_uri.clone(),
            scopes: Vec::new(),
            user_scopes: auth::DEFAULT_USER_SCOPES
                .iter()
                .map(|s| s.to_string())
                .collect(),
            port: 8888,
        };

        if oauth_cfg.client_id.is_empty() {
            eprintln!("Error: auth.client_id is not set in config.");
            eprintln!("Set it in: {}", config::default_config_path().display());
            std::process::exit(1);
        }

        if oauth_cfg.client_secret.is_empty() {
            eprintln!("Error: auth.client_secret is not set in config.");
            eprintln!(
                "Find it in your Slack App's Basic Information page under \"App Credentials\"."
            );
            eprintln!("Set it in: {}", config::default_config_path().display());
            std::process::exit(1);
        }

        match auth::run_oauth_flow(&mut oauth_cfg.clone()).await {
            Ok(token_resp) => {
                let stored = auth::parse_token_response(&token_resp);
                let store_type = StoreType::from_str(&cfg.auth.token_store)
                    .unwrap_or(StoreType::Keychain);

                if let Err(e) = store_tokens(&stored, &store_type) {
                    eprintln!("Failed to store tokens: {}", e);
                    std::process::exit(1);
                }

                println!("Authentication successful!");
                println!("Team: {}", stored.team_name);
                println!("Tokens stored in: {:?}", store_type);
            }
            Err(e) => {
                eprintln!("OAuth flow failed: {:?}", e);
                std::process::exit(1);
            }
        }
    });
}

const LOGIN_USAGE: &str =
    "Usage: slackatui login [workspace] [--token T --cookie C] [--browser B] [--timeout SECS]";
const DEFAULT_LOGIN_TIMEOUT_SECS: u64 = 300;

#[derive(Debug, PartialEq, Eq, Default)]
struct LoginArgs {
    workspace: Option<String>,
    token: Option<String>,
    cookie: Option<String>,
    browser: Option<String>,
    timeout_secs: Option<u64>,
}

/// Where the credentials for `login` come from.
#[derive(Debug, PartialEq, Eq)]
enum LoginSource {
    Supplied {
        token: String,
        cookie: Option<String>,
    },
    CookieOnly {
        workspace: String,
        cookie: String,
    },
    Browser {
        browser: PathBuf,
        workspace: Option<String>,
        timeout: Duration,
    },
}

fn parse_login_args(args: &[String]) -> Result<LoginArgs, String> {
    let mut parsed = LoginArgs::default();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        let flag = arg.as_str();
        if !flag.starts_with("--") {
            if parsed.workspace.is_some() {
                return Err(format!("Unexpected argument: {}", flag));
            }
            parsed.workspace = Some(normalize_workspace(flag));
            continue;
        }
        let mut value = || {
            iter.next()
                .filter(|v| !v.starts_with("--"))
                .map(|v| v.trim().to_string())
                .ok_or_else(|| format!("{} expects a value", flag))
        };
        match flag {
            "--token" | "--cookie" => {
                let secret = value()?;
                if secret.is_empty() {
                    return Err(format!("{} must not be empty", flag));
                }
                if flag == "--token" {
                    parsed.token = Some(secret);
                } else {
                    parsed.cookie = Some(secret);
                }
            }
            "--browser" => {
                let path = value()?;
                if path.is_empty() {
                    return Err(format!("{} must not be empty", flag));
                }
                parsed.browser = Some(path);
            }
            "--timeout" => {
                let secs = value()?
                    .parse()
                    .map_err(|_| "--timeout expects a number of seconds".to_string())?;
                parsed.timeout_secs = Some(secs);
            }
            other => return Err(format!("Unknown option: {}", other)),
        }
    }
    if parsed.cookie.is_some() && parsed.token.is_none() && parsed.workspace.is_none() {
        return Err(
            "--cookie alone needs a workspace: slackatui login <workspace> --cookie ...".to_string(),
        );
    }
    Ok(parsed)
}

fn plan_login<F: FnOnce(Option<&str>) -> Option<PathBuf>>(
    args: &LoginArgs,
    find_browser: F,
) -> Result<LoginSource, String> {
    if let Some(token) = &args.token {
        return Ok(LoginSource::Supplied {
            token: token.clone(),
            cookie: args.cookie.clone(),
        });
    }
    if let (Some(cookie), Some(workspace)) = (&args.cookie, &args.workspace) {
        return Ok(LoginSource::CookieOnly {
            workspace: workspace.clone(),
            cookie: cookie.clone(),
        });
    }
    let browser = find_browser(args.browser.as_deref()).ok_or_else(|| NO_BROWSER_MSG.to_string())?;
    Ok(LoginSource::Browser {
        browser,
        workspace: args.workspace.clone(),
        timeout: Duration::from_secs(args.timeout_secs.unwrap_or(DEFAULT_LOGIN_TIMEOUT_SECS)),
    })
}

fn prepare_credentials(
    token: &str,
    cookie: Option<&str>,
) -> Result<(String, Option<String>), String> {
    let token = token.trim();
    if token.is_empty() {
        return Err("token must not be empty".to_string());
    }
    let cookie = cookie.map(str::trim);
    if cookie == Some("") {
        return Err("cookie must not be empty".to_string());
    }
    Ok((token.to_string(), cookie.map(str::to_string)))
}

async fn validate_and_store<V, VF, S>(
    token: String,
    cookie: Option<String>,
    auth_test: V,
    store: S,
) -> Result<slack::AuthTestResponse, String>
where
    V: FnOnce(SlackClient) -> VF,
    VF: std::future::Future<Output = Result<slack::AuthTestResponse, slack::SlackError>>,
    S: FnOnce(&StoredTokens) -> Result<(), auth::StoreError>,
{
    let client = SlackClient::with_cookie(&token, cookie.as_deref());
    let identity = auth_test(client)
        .await
        .map_err(|e| format!("Login failed: {}", e))?;
    let stored = StoredTokens {
        user_token: token,
        cookie: cookie.unwrap_or_default(),
        team_id: identity.team_id.clone(),
        team_name: identity.team.clone(),
        user_id: identity.user_id.clone(),
        saved_at: Some(chrono::Utc::now()),
        ..Default::default()
    };
    store(&stored).map_err(|e| format!("Failed to store tokens: {}", e))?;
    Ok(identity)
}

fn team_id_update(configured: &str, logged_in: &str) -> Option<String> {
    if configured == logged_in {
        None
    } else {
        Some(logged_in.to_string())
    }
}

fn run_login(cfg: &Config, args: &[String]) {
    let login_args = match parse_login_args(args) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("{}", e);
            eprintln!("{}", LOGIN_USAGE);
            std::process::exit(1);
        }
    };
    let source = match plan_login(&login_args, auth::find_browser) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{}", e);
            std::process::exit(1);
        }
    };
    let store_type = match StoreType::from_str(&cfg.auth.token_store) {
        Ok(st) => st,
        Err(e) => {
            eprintln!("Invalid token_store config: {}", e);
            std::process::exit(1);
        }
    };

    let rt = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");
    rt.block_on(async {
        let (token, cookie) = match source {
            LoginSource::Supplied { token, cookie } => (token, cookie),
            LoginSource::CookieOnly { workspace, cookie } => {
                match auth::token_via_html(&workspace, &cookie).await {
                    Ok(Some(token)) => (token, Some(cookie)),
                    Ok(None) => {
                        eprintln!(
                            "Could not find a session token for {} with that cookie (expired, or wrong workspace?)",
                            workspace
                        );
                        std::process::exit(1);
                    }
                    Err(e) => {
                        eprintln!("{}", e);
                        std::process::exit(1);
                    }
                }
            }
            LoginSource::Browser {
                browser,
                workspace,
                timeout,
            } => {
                let requested = workspace.clone();
                let opts = BrowserLoginOptions {
                    workspace,
                    browser,
                    timeout,
                };
                match auth::capture(opts).await {
                    Ok(session) => {
                        // capture's ctrl_c() poll left tokio owning SIGINT, so without this the
                        // auth_test and keychain write below could no longer be interrupted.
                        tokio::spawn(async {
                            if tokio::signal::ctrl_c().await.is_ok() {
                                std::process::exit(130);
                            }
                        });
                        if requested.as_deref() != Some(session.domain.as_str()) {
                            println!("Using team {}", session.domain);
                        }
                        (session.token, Some(session.cookie))
                    }
                    Err(e) => {
                        eprintln!("{}", e);
                        std::process::exit(1);
                    }
                }
            }
        };
        let (token, cookie) = match prepare_credentials(&token, cookie.as_deref()) {
            Ok(creds) => creds,
            Err(e) => {
                eprintln!("{}", e);
                std::process::exit(1);
            }
        };

        let identity = match validate_and_store(
            token,
            cookie,
            |c| async move { c.auth_test().await },
            |t| store_tokens(t, &store_type),
        )
        .await
        {
            Ok(identity) => identity,
            Err(e) => {
                eprintln!("{}", e);
                std::process::exit(1);
            }
        };

        if let Some(team_id) = team_id_update(&cfg.auth.team_id, &identity.team_id) {
            let mut updated = cfg.clone();
            updated.auth.team_id = team_id;
            if let Err(e) = updated.save(&config::default_config_path()) {
                eprintln!("Warning: could not save auth.team_id to config: {}", e);
            }
        }

        let store_word = match store_type {
            StoreType::Keychain => "keychain",
            StoreType::File => "file",
        };
        println!(
            "Logged in as @{} in {} (stored in {}).",
            identity.user, identity.team, store_word
        );
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    fn auth_identity() -> slack::AuthTestResponse {
        serde_json::from_value(serde_json::json!({
            "ok": true,
            "url": "https://x.slack.com/",
            "team": "T",
            "user": "u",
            "team_id": "T1",
            "user_id": "U1",
        }))
        .unwrap()
    }

    #[test]
    fn test_parse_login_args_token_only() {
        let parsed = parse_login_args(&args(&["--token", "xoxc-1"])).unwrap();
        assert_eq!(parsed.token.as_deref(), Some("xoxc-1"));
        assert_eq!(parsed.cookie, None);
        assert_eq!(parsed.workspace, None);
    }

    #[test]
    fn test_parse_login_args_token_and_cookie() {
        let parsed =
            parse_login_args(&args(&["--token", "xoxc-1", "--cookie", "xoxd-2"])).unwrap();
        assert_eq!(parsed.token.as_deref(), Some("xoxc-1"));
        assert_eq!(parsed.cookie.as_deref(), Some("xoxd-2"));
    }

    #[test]
    fn test_parse_login_args_cookie_with_workspace() {
        let parsed = parse_login_args(&args(&["myteam", "--cookie", "xoxd-2"])).unwrap();
        assert_eq!(parsed.workspace.as_deref(), Some("myteam"));
        assert_eq!(parsed.cookie.as_deref(), Some("xoxd-2"));
        assert_eq!(parsed.token, None);
    }

    #[test]
    fn test_parse_login_args_cookie_without_workspace() {
        let err = parse_login_args(&args(&["--cookie", "xoxd-2"])).unwrap_err();
        assert_eq!(
            err,
            "--cookie alone needs a workspace: slackatui login <workspace> --cookie ..."
        );
    }

    #[test]
    fn test_parse_login_args_empty() {
        assert_eq!(parse_login_args(&[]).unwrap(), LoginArgs::default());
    }

    #[test]
    fn test_parse_login_args_unknown_flag() {
        let err = parse_login_args(&args(&["--bogus", "x"])).unwrap_err();
        assert_eq!(err, "Unknown option: --bogus");
        let err = parse_login_args(&args(&["--bogus"])).unwrap_err();
        assert_eq!(err, "Unknown option: --bogus");
    }

    #[test]
    fn test_parse_login_args_missing_value() {
        let err = parse_login_args(&args(&["--token"])).unwrap_err();
        assert_eq!(err, "--token expects a value");
        let err = parse_login_args(&args(&["--token", "--cookie", "xoxd-1"])).unwrap_err();
        assert_eq!(err, "--token expects a value");
    }

    #[test]
    fn test_parse_login_args_empty_token() {
        let err = parse_login_args(&args(&["--token", "  "])).unwrap_err();
        assert_eq!(err, "--token must not be empty");
    }

    #[test]
    fn test_parse_login_args_empty_browser() {
        let err = parse_login_args(&args(&["--browser", "  "])).unwrap_err();
        assert_eq!(err, "--browser must not be empty");
    }

    #[test]
    fn test_parse_login_args_timeout() {
        let parsed = parse_login_args(&args(&["--timeout", "30"])).unwrap();
        assert_eq!(parsed.timeout_secs, Some(30));
        let err = parse_login_args(&args(&["--timeout", "abc"])).unwrap_err();
        assert_eq!(err, "--timeout expects a number of seconds");
    }

    #[test]
    fn test_parse_login_args_second_positional() {
        assert!(parse_login_args(&args(&["one", "two"])).is_err());
    }

    #[test]
    fn test_parse_login_args_normalises_workspace_url() {
        let parsed = parse_login_args(&args(&["https://myteam.slack.com/"])).unwrap();
        assert_eq!(parsed.workspace.as_deref(), Some("myteam"));
    }

    #[test]
    fn test_prepare_credentials_trims_both() {
        let (token, cookie) = prepare_credentials("  xoxc-1\n", Some(" xoxd-2 ")).unwrap();
        assert_eq!(token, "xoxc-1");
        assert_eq!(cookie.as_deref(), Some("xoxd-2"));
    }

    #[test]
    fn test_prepare_credentials_empty_token() {
        let err = prepare_credentials("  ", Some("xoxd-2")).unwrap_err();
        assert_eq!(err, "token must not be empty");
    }

    #[test]
    fn test_prepare_credentials_empty_token_no_cookie() {
        let err = prepare_credentials("", None).unwrap_err();
        assert_eq!(err, "token must not be empty");
    }

    #[test]
    fn test_prepare_credentials_blank_cookie() {
        let err = prepare_credentials("xoxc-1", Some("  ")).unwrap_err();
        assert_eq!(err, "cookie must not be empty");
    }

    #[test]
    fn test_prepare_credentials_no_cookie() {
        assert_eq!(
            prepare_credentials("xoxc-1", None).unwrap(),
            ("xoxc-1".to_string(), None)
        );
    }

    #[test]
    fn test_plan_login_supplied_skips_browser_lookup() {
        let called = Cell::new(false);
        let parsed = LoginArgs {
            token: Some("xoxc-1".to_string()),
            cookie: Some("xoxd-2".to_string()),
            ..Default::default()
        };
        let source = plan_login(&parsed, |_| {
            called.set(true);
            None
        })
        .unwrap();
        assert_eq!(
            source,
            LoginSource::Supplied {
                token: "xoxc-1".to_string(),
                cookie: Some("xoxd-2".to_string()),
            }
        );
        assert!(!called.get());
    }

    #[test]
    fn test_plan_login_token_only_skips_browser_lookup() {
        let called = Cell::new(false);
        let parsed = LoginArgs {
            token: Some("xoxc-1".to_string()),
            ..Default::default()
        };
        let source = plan_login(&parsed, |_| {
            called.set(true);
            None
        })
        .unwrap();
        assert_eq!(
            source,
            LoginSource::Supplied {
                token: "xoxc-1".to_string(),
                cookie: None,
            }
        );
        assert!(!called.get());
    }

    #[test]
    fn test_plan_login_cookie_only_skips_browser_lookup() {
        let called = Cell::new(false);
        let parsed = LoginArgs {
            workspace: Some("myteam".to_string()),
            cookie: Some("xoxd-2".to_string()),
            ..Default::default()
        };
        let source = plan_login(&parsed, |_| {
            called.set(true);
            None
        })
        .unwrap();
        assert_eq!(
            source,
            LoginSource::CookieOnly {
                workspace: "myteam".to_string(),
                cookie: "xoxd-2".to_string(),
            }
        );
        assert!(!called.get());
    }

    #[test]
    fn test_plan_login_no_browser_found() {
        let err = plan_login(&LoginArgs::default(), |_| None).unwrap_err();
        assert_eq!(err, NO_BROWSER_MSG);
    }

    #[test]
    fn test_plan_login_browser_found() {
        let parsed = LoginArgs {
            workspace: Some("myteam".to_string()),
            browser: Some("chrome".to_string()),
            ..Default::default()
        };
        let seen = Cell::new(None);
        let source = plan_login(&parsed, |override_| {
            seen.set(override_.map(str::to_string));
            Some(PathBuf::from("/tmp/chrome"))
        })
        .unwrap();
        assert_eq!(seen.take().as_deref(), Some("chrome"));
        assert_eq!(
            source,
            LoginSource::Browser {
                browser: PathBuf::from("/tmp/chrome"),
                workspace: Some("myteam".to_string()),
                timeout: Duration::from_secs(300),
            }
        );
    }

    #[test]
    fn test_validate_and_store_auth_failure_skips_store() {
        let stored = Cell::new(false);
        let err = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(validate_and_store(
                "xoxc-1".to_string(),
                Some("xoxd-2".to_string()),
                |_| async { Err(slack::SlackError::Api("invalid_auth".to_string())) },
                |_| {
                    stored.set(true);
                    Ok(())
                },
            ))
            .unwrap_err();
        assert!(err.contains("invalid_auth"), "{}", err);
        assert!(!stored.get());
    }

    #[test]
    fn test_validate_and_store_success_stores_identity() {
        let captured: RefCell<Option<StoredTokens>> = RefCell::new(None);
        let identity = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(validate_and_store(
                "xoxc-1".to_string(),
                Some("xoxd-2".to_string()),
                |_| async { Ok(auth_identity()) },
                |t| {
                    *captured.borrow_mut() = Some(t.clone());
                    Ok(())
                },
            ))
            .unwrap();
        assert_eq!(identity.user, "u");
        let stored = captured.into_inner().expect("store closure was not called");
        assert_eq!(stored.user_token, "xoxc-1");
        assert_eq!(stored.cookie, "xoxd-2");
        assert_eq!(stored.team_id, "T1");
        assert_eq!(stored.team_name, "T");
        assert_eq!(stored.user_id, "U1");
        assert!(stored.saved_at.is_some());
    }

    #[test]
    fn test_team_id_update() {
        assert_eq!(team_id_update("", "T1"), Some("T1".to_string()));
        assert_eq!(team_id_update("T1", "T1"), None);
        assert_eq!(team_id_update("T1", "T2"), Some("T2".to_string()));
    }
}
