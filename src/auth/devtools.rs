use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use serde_json::{json, Value};
use std::path::Path;
use tokio::net::TcpStream;
use tokio::time::{Duration, Instant};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

const ACTIVE_PORT_FILE: &str = "DevToolsActivePort";
const ACTIVE_PORT_POLL: Duration = Duration::from_millis(100);

#[derive(Debug)]
pub enum DevToolsError {
    Connect(String),
    Protocol(String),
    Closed,
    Timeout(String),
}

impl std::fmt::Display for DevToolsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DevToolsError::Connect(msg) => write!(f, "devtools connect error: {}", msg),
            DevToolsError::Protocol(msg) => write!(f, "devtools protocol error: {}", msg),
            DevToolsError::Closed => write!(f, "the browser closed the connection"),
            DevToolsError::Timeout(msg) => write!(f, "devtools timeout: {}", msg),
        }
    }
}

impl std::error::Error for DevToolsError {}

/// A cookie as reported by `Storage.getCookies`.
#[derive(Debug, Clone, Deserialize)]
pub struct BrowserCookie {
    pub name: String,
    pub domain: String,
    pub value: String,
}

/// Minimal Chrome DevTools Protocol client over a single browser-level websocket.
pub struct DevToolsClient {
    socket: WebSocketStream<MaybeTlsStream<TcpStream>>,
    next_id: u64,
}

impl DevToolsClient {
    /// Connect to the browser endpoint and enable target discovery.
    pub async fn connect(ws_url: &str) -> Result<Self, DevToolsError> {
        let (socket, _) = tokio_tungstenite::connect_async(ws_url)
            .await
            .map_err(|e| DevToolsError::Connect(e.to_string()))?;
        let mut client = Self { socket, next_id: 1 };
        client
            .call("Target.setDiscoverTargets", json!({"discover": true}))
            .await?;
        Ok(client)
    }

    /// Call a browser-level method.
    pub async fn call(&mut self, method: &str, params: Value) -> Result<Value, DevToolsError> {
        self.call_in(None, method, params).await
    }

    /// Call a method, optionally within an attached target session, and return its result.
    pub async fn call_in(
        &mut self,
        session: Option<&str>,
        method: &str,
        params: Value,
    ) -> Result<Value, DevToolsError> {
        let id = self.next_id;
        self.next_id += 1;
        let mut msg = json!({"id": id, "method": method, "params": params});
        if let Some(s) = session {
            msg["sessionId"] = json!(s);
        }
        self.socket
            .send(Message::Text(msg.to_string().into()))
            .await
            .map_err(|_| DevToolsError::Closed)?;

        // Frames whose id does not match are event notifications; skip them.
        loop {
            let Some(frame) = self.socket.next().await else {
                return Err(DevToolsError::Closed);
            };
            let Message::Text(text) = frame.map_err(|_| DevToolsError::Closed)? else {
                continue;
            };
            let reply: Value =
                serde_json::from_str(&text).map_err(|e| DevToolsError::Protocol(e.to_string()))?;
            if reply["id"] != id {
                continue;
            }
            if let Some(err) = reply.get("error") {
                let message = err["message"].as_str().unwrap_or("unknown error");
                return Err(DevToolsError::Protocol(format!("{}: {}", method, message)));
            }
            return Ok(reply["result"].clone());
        }
    }

    /// All cookies known to the browser.
    pub async fn cookies(&mut self) -> Result<Vec<BrowserCookie>, DevToolsError> {
        let result = self.call("Storage.getCookies", json!({})).await?;
        serde_json::from_value(result["cookies"].clone())
            .map_err(|e| DevToolsError::Protocol(e.to_string()))
    }

    /// `(target_id, url)` for every open page target.
    pub async fn pages(&mut self) -> Result<Vec<(String, String)>, DevToolsError> {
        let result = self.call("Target.getTargets", json!({})).await?;
        let infos = result["targetInfos"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        Ok(infos
            .iter()
            .filter(|t| t["type"] == "page")
            .filter_map(|t| {
                Some((
                    t["targetId"].as_str()?.to_string(),
                    t["url"].as_str()?.to_string(),
                ))
            })
            .collect())
    }

    /// Evaluate a JavaScript expression in a page and return its value.
    pub async fn evaluate(
        &mut self,
        target_id: &str,
        expression: &str,
    ) -> Result<Value, DevToolsError> {
        let attached = self
            .call(
                "Target.attachToTarget",
                json!({"targetId": target_id, "flatten": true}),
            )
            .await?;
        let session_id = attached["sessionId"]
            .as_str()
            .ok_or_else(|| {
                DevToolsError::Protocol("Target.attachToTarget returned no sessionId".to_string())
            })?
            .to_string();

        let evaluated = self
            .call_in(
                Some(&session_id),
                "Runtime.evaluate",
                json!({"expression": expression, "returnByValue": true}),
            )
            .await;
        if let Err(e) = self
            .call("Target.detachFromTarget", json!({"sessionId": session_id}))
            .await
        {
            tracing::warn!("Target.detachFromTarget failed: {}", e);
        }
        Ok(evaluated?["result"]["value"].clone())
    }

    /// Ask the browser to exit gracefully.
    pub async fn close_browser(&mut self) -> Result<(), DevToolsError> {
        self.call("Browser.close", json!({})).await.map(|_| ())
    }
}

/// Parse the `DevToolsActivePort` file (port on line 1, browser path on line 2) into a websocket URL.
pub fn parse_active_port(contents: &str) -> Option<String> {
    let mut lines = contents.lines();
    let port: u16 = lines.next()?.trim().parse().ok()?;
    let path = lines.next()?.trim();
    Some(format!("ws://127.0.0.1:{port}{path}"))
}

/// Poll the profile directory until the browser publishes its debugging endpoint.
pub async fn wait_for_active_port(
    profile: &Path,
    timeout: Duration,
) -> Result<String, DevToolsError> {
    let path = profile.join(ACTIVE_PORT_FILE);
    let deadline = Instant::now() + timeout;
    loop {
        if let Ok(contents) = tokio::fs::read_to_string(&path).await {
            if let Some(url) = parse_active_port(&contents) {
                return Ok(url);
            }
        }
        if Instant::now() >= deadline {
            return Err(DevToolsError::Timeout(format!(
                "no {} after {}s",
                ACTIVE_PORT_FILE,
                timeout.as_secs()
            )));
        }
        tokio::time::sleep(ACTIVE_PORT_POLL).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_active_port() {
        assert_eq!(
            parse_active_port("9222\n/devtools/browser/abc\n").as_deref(),
            Some("ws://127.0.0.1:9222/devtools/browser/abc")
        );
    }

    #[test]
    fn test_parse_active_port_missing_path() {
        assert_eq!(parse_active_port("9222\n"), None);
        assert_eq!(parse_active_port(""), None);
    }

    #[test]
    fn test_parse_active_port_non_numeric() {
        assert_eq!(parse_active_port("abc\n/devtools/browser/abc\n"), None);
    }

    #[test]
    fn test_closed_error_message() {
        assert_eq!(
            DevToolsError::Closed.to_string(),
            "the browser closed the connection"
        );
    }
}
