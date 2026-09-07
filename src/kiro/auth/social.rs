//! Kiro IDE Social 登录流程（Portal PKCE OAuth）
//!
//! 复现 Kiro IDE 的 portal-auth-provider 流程：
//! 1. 生成 PKCE code_verifier + code_challenge
//! 2. 启本地 HTTP 回调服务器
//! 3. 返回 portal URL 供用户在浏览器完成登录
//! 4. 捕获回调中的 authorization code
//! 5. 用 code + code_verifier 换取 access_token + refresh_token

use std::net::TcpListener;

use sha2::{Digest, Sha256};
use tokio::sync::oneshot;

use crate::http_client::{ProxyConfig, build_client};
use crate::kiro::model::token_refresh::{SocialCreateTokenRequest, SocialCreateTokenResponse};
use crate::model::config::Config;

/// Portal 认证 URL（Kiro 网页版入口）
pub const KIRO_PORTAL_URL: &str = "https://app.kiro.dev";

/// Kiro auth service 默认端点
pub const KIRO_AUTH_ENDPOINT: &str = "https://prod.us-east-1.auth.desktop.kiro.dev";

/// 与 IDE 一致的本地回调端口候选列表
const CALLBACK_PORTS: &[u16] = &[
    3128, 4649, 6588, 8008, 9091, 49153, 50153, 51153, 52153, 53153,
];

/// OAuth 回调数据
#[derive(Debug, Clone)]
pub struct OAuthCallbackData {
    pub code: String,
    pub login_option: String,
    pub path: String,
    /// OAuth state 参数（用于 CSRF 验证）
    pub state: String,
}

/// 回调服务器关闭句柄
///
/// Drop 时自动向服务器发送关闭信号，服务器退出监听循环并释放端口。
pub struct ServerHandle {
    _shutdown_tx: oneshot::Sender<()>,
}

/// 启动本地回调服务器，返回端口号和关闭句柄
///
/// 关闭句柄 drop 时服务器自动停止。当收到有效的 OAuth 回调时，通过 channel 发送回调数据。
pub fn start_callback_server(
    tx: oneshot::Sender<OAuthCallbackData>,
    expected_state: String,
) -> anyhow::Result<(u16, ServerHandle)> {
    // 直接持有已绑定的 socket，避免 probe-and-bind 的 TOCTOU 竞态
    let (port, std_listener) = bind_available_port()?;

    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

    tokio::spawn(async move {
        run_callback_server(std_listener, tx, shutdown_rx, expected_state).await;
    });

    Ok((
        port,
        ServerHandle {
            _shutdown_tx: shutdown_tx,
        },
    ))
}

fn bind_available_port() -> anyhow::Result<(u16, std::net::TcpListener)> {
    for &port in CALLBACK_PORTS {
        match TcpListener::bind(("127.0.0.1", port)) {
            Ok(listener) => {
                listener.set_nonblocking(true)?;
                return Ok((port, listener));
            }
            Err(_) => continue,
        }
    }
    anyhow::bail!(
        "所有回调端口均被占用，请确保没有其他程序占用 {:?}",
        CALLBACK_PORTS
    )
}

async fn run_callback_server(
    std_listener: std::net::TcpListener,
    tx: oneshot::Sender<OAuthCallbackData>,
    mut shutdown_rx: oneshot::Receiver<()>,
    expected_state: String,
) {
    use axum::{
        Router,
        extract::{OriginalUri, State},
        response::Html,
        routing::get,
    };
    use std::sync::Arc;

    struct CallbackState {
        expected_state: String,
        tx: parking_lot::Mutex<Option<oneshot::Sender<OAuthCallbackData>>>,
    }

    async fn receive(
        State(state): State<Arc<CallbackState>>,
        OriginalUri(uri): OriginalUri,
    ) -> (axum::http::StatusCode, Html<&'static str>) {
        use axum::http::StatusCode;
        let Some(callback) = parse_callback(&uri.to_string()) else {
            return (
                StatusCode::BAD_REQUEST,
                Html("授权未完成，请返回管理后台重新发起登录。"),
            );
        };
        if !crate::common::auth::constant_time_eq(&callback.state, &state.expected_state) {
            return (
                StatusCode::BAD_REQUEST,
                Html("登录 state 不匹配，请使用本次登录的授权链接。"),
            );
        }
        let Some(tx) = state.tx.lock().take() else {
            return (
                StatusCode::GONE,
                Html("授权回调已接收，请返回管理后台查看结果。"),
            );
        };
        let _ = tx.send(callback);
        (
            StatusCode::OK,
            Html(
                "<html><head><meta charset='utf-8'><title>授权已接收</title></head><body style='font-family:sans-serif;text-align:center;padding:60px'><h2>授权已接收</h2><p>请返回 Kiro Admin 管理后台等待凭据保存完成。</p><p>此标签页可以关闭。</p></body></html>",
            ),
        )
    }

    let listener = match tokio::net::TcpListener::from_std(std_listener) {
        Ok(listener) => listener,
        Err(error) => {
            tracing::error!("无法启动登录回调监听: {error}");
            return;
        }
    };
    let app = Router::new()
        .route("/oauth/callback", get(receive))
        .route("/signin/callback", get(receive))
        .with_state(Arc::new(CallbackState {
            expected_state,
            tx: parking_lot::Mutex::new(Some(tx)),
        }));
    let _ = axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            tokio::select! {
                _ = &mut shutdown_rx => {},
                _ = tokio::time::sleep(std::time::Duration::from_secs(600)) => {},
            }
        })
        .await;
}

fn parse_callback(path_and_query: &str) -> Option<OAuthCallbackData> {
    let (path, query) = if let Some(idx) = path_and_query.find('?') {
        (&path_and_query[..idx], &path_and_query[idx + 1..])
    } else {
        return None;
    };

    if path != "/oauth/callback" && path != "/signin/callback" {
        return None;
    }

    let params = parse_query_string(query);

    // 必须有 code 且没有 error
    if params.contains_key("error") {
        return None;
    }

    let code = params
        .get("code")
        .filter(|code| !code.trim().is_empty())?
        .clone();
    let login_option = params.get("login_option").cloned().unwrap_or_default();
    let state = params.get("state").cloned().unwrap_or_default();

    Some(OAuthCallbackData {
        code,
        login_option,
        path: path.to_string(),
        state,
    })
}

/// base64url 编码（无填充），与 Kiro IDE 行为一致
fn base64url_encode(data: &[u8]) -> String {
    // 标准 base64 → 替换 +/= 为 base64url 规范
    let b64 = base64_encode_standard(data);
    b64.replace('+', "-").replace('/', "_").replace('=', "")
}

/// 标准 base64 编码（用于内部转换）
fn base64_encode_standard(data: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity((data.len() + 2) / 3 * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as usize;
        let b1 = if chunk.len() > 1 {
            chunk[1] as usize
        } else {
            0
        };
        let b2 = if chunk.len() > 2 {
            chunk[2] as usize
        } else {
            0
        };
        out.push(CHARS[b0 >> 2] as char);
        out.push(CHARS[((b0 & 3) << 4) | (b1 >> 4)] as char);
        if chunk.len() > 1 {
            out.push(CHARS[((b1 & 0xf) << 2) | (b2 >> 6)] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(CHARS[b2 & 0x3f] as char);
        } else {
            out.push('=');
        }
    }
    out
}

/// 生成 PKCE code_verifier 和 code_challenge
pub fn generate_pkce() -> (String, String) {
    // 通过系统 CSPRNG 获取 PKCE 随机数。
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).expect("操作系统随机数不可用");

    let verifier = base64url_encode(&bytes);

    let mut hasher = Sha256::new();
    hasher.update(verifier.as_bytes());
    let digest = hasher.finalize();
    let challenge = base64url_encode(&digest);

    (verifier, challenge)
}

/// 构建供用户在浏览器中访问的 portal URL
pub fn build_portal_url(state: &str, code_challenge: &str, redirect_uri: &str) -> String {
    let params = format!(
        "state={}&code_challenge={}&code_challenge_method=S256&redirect_uri={}&redirect_from=KiroIDE",
        urlencoding::encode(state),
        urlencoding::encode(code_challenge),
        urlencoding::encode(redirect_uri),
    );
    format!("{}/signin?{}", KIRO_PORTAL_URL, params)
}

/// 简易 query string 解析（不依赖 url crate）
fn parse_query_string(query: &str) -> std::collections::HashMap<String, String> {
    query
        .split('&')
        .filter_map(|pair| {
            let mut iter = pair.splitn(2, '=');
            let key = iter.next()?.to_string();
            let val = iter
                .next()
                .map(|v| {
                    // 简单的 percent-decode（处理 %XX 和 + 号）
                    let with_space = v.replace('+', " ");
                    urlencoding::decode(&with_space)
                        .map(|s| s.into_owned())
                        .unwrap_or_else(|_| with_space)
                })
                .unwrap_or_default();
            Some((key, val))
        })
        .collect()
}

/// 用 authorization code 换取 access_token + refresh_token
pub async fn exchange_code_for_token(
    auth_endpoint: &str,
    code: &str,
    code_verifier: &str,
    full_redirect_uri: &str,
    config: &Config,
    proxy: Option<&ProxyConfig>,
) -> anyhow::Result<SocialCreateTokenResponse> {
    let url = format!("{}/oauth/token", auth_endpoint);
    let client = build_client(proxy, 30, config.tls_backend)?;

    let body = SocialCreateTokenRequest {
        code: code.to_string(),
        code_verifier: code_verifier.to_string(),
        redirect_uri: full_redirect_uri.to_string(),
        invitation_code: None,
    };

    let kiro_version = &config.kiro_version;
    let user_agent = format!("KiroIDE-{}", kiro_version);

    let resp = client
        .post(&url)
        .header("Content-Type", "application/json")
        .header("User-Agent", &user_agent)
        .header("host", auth_endpoint.trim_start_matches("https://"))
        .json(&body)
        .send()
        .await?;

    let status = resp.status();
    if !status.is_success() {
        let body_text = resp.text().await.unwrap_or_default();
        anyhow::bail!("Social token 交换失败 {}: {}", status, body_text);
    }

    resp.json::<SocialCreateTokenResponse>()
        .await
        .map_err(|e| anyhow::anyhow!("解析 Social token 响应失败: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkce_matches_rfc7636_and_generated_values_are_url_safe() {
        let digest = Sha256::digest(b"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");
        assert_eq!(
            base64url_encode(&digest),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
        let (verifier, challenge) = generate_pkce();
        assert_eq!(verifier.len(), 43);
        assert_eq!(
            challenge,
            base64url_encode(&Sha256::digest(verifier.as_bytes()))
        );
        assert!(
            verifier
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        );
        assert_ne!(verifier, generate_pkce().0);
    }

    #[test]
    fn callback_parser_rejects_errors_empty_codes_and_unexpected_paths() {
        for path in [
            "/other?code=x",
            "/oauth/callback?error=denied&code=x",
            "/oauth/callback?code=",
            "/oauth/callback",
        ] {
            assert!(parse_callback(path).is_none());
        }
        let callback =
            parse_callback("/signin/callback?code=a%2Bb&state=test&login_option=github").unwrap();
        assert_eq!(callback.code, "a+b");
        assert_eq!(callback.state, "test");
        assert_eq!(callback.login_option, "github");
    }

    #[tokio::test]
    async fn callback_listener_rejects_wrong_state_without_consuming_valid_callback() {
        let (tx, rx) = oneshot::channel();
        let (port, handle) = start_callback_server(tx, "expected".into()).unwrap();
        let client = reqwest::Client::builder()
            .no_proxy()
            .timeout(std::time::Duration::from_secs(3))
            .build()
            .unwrap();
        let base = format!("http://127.0.0.1:{port}/oauth/callback");
        let response = client
            .get(format!("{base}?code=bad&state=wrong"))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 400);
        let response = client
            .get(format!(
                "{base}?code=good&state=expected&login_option=google"
            ))
            .send()
            .await
            .unwrap();
        assert!(response.status().is_success());
        assert_eq!(rx.await.unwrap().code, "good");
        drop(handle);
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            loop {
                if let Ok(listener) = std::net::TcpListener::bind(("127.0.0.1", port)) {
                    drop(listener);
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("callback port was not released");
    }
}
