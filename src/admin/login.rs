//! 管理后台交互式登录：移植自 kiro.rs 的 Portal PKCE / AWS OIDC 流程。
use std::{collections::HashMap, sync::Arc};

use chrono::{DateTime, Duration, Utc};
use parking_lot::Mutex;
use tokio::sync::{Mutex as AsyncMutex, oneshot};

use super::{AdminService, AdminServiceError};
use crate::{
    admin::types::{
        AddCredentialRequest, PollIdcLoginResponse, StartIdcLoginRequest, StartIdcLoginResponse,
        StartSocialLoginRequest, StartSocialLoginResponse,
    },
    http_client::ProxyConfig,
    kiro::{
        auth::{idc, social},
        model::credentials::KiroCredentials,
    },
};

#[derive(Default)]
pub(super) struct LoginSessions(Arc<Mutex<HashMap<String, Arc<LoginSession>>>>);

struct LoginSession {
    expires_at: DateTime<Utc>,
    state: AsyncMutex<LoginState>,
}

enum LoginState {
    Social(SocialSession),
    Idc(IdcSession),
    Success(u64),
    Failed(String),
    Expired,
}

struct SocialSession {
    state: String,
    verifier: String,
    redirect_uri: String,
    callback_rx: oneshot::Receiver<social::OAuthCallbackData>,
    _server: social::ServerHandle,
    credentials: KiroCredentials,
    proxy: Option<ProxyConfig>,
}

struct IdcSession {
    region: String,
    client_id: String,
    client_secret: String,
    device_code: String,
    interval: u64,
    next_poll: DateTime<Utc>,
    credentials: KiroCredentials,
    proxy: Option<ProxyConfig>,
}

impl LoginSessions {
    fn insert(&self, expires_at: DateTime<Utc>, state: LoginState) -> String {
        let id = uuid::Uuid::new_v4().to_string();
        self.0.lock().insert(
            id.clone(),
            Arc::new(LoginSession {
                expires_at,
                state: AsyncMutex::new(state),
            }),
        );
        // 无浏览器轮询时也会清理 verifier、clientSecret 和本地监听端口。
        let sessions = Arc::downgrade(&self.0);
        let cleanup_id = id.clone();
        tokio::spawn(async move {
            let delay = (expires_at - Utc::now()).to_std().unwrap_or_default();
            tokio::time::sleep(delay).await;
            if let Some(sessions) = sessions.upgrade() {
                sessions.lock().remove(&cleanup_id);
            }
        });
        id
    }

    fn get(&self, id: &str) -> Option<Arc<LoginSession>> {
        let mut sessions = self.0.lock();
        if sessions.get(id).is_some_and(|s| Utc::now() >= s.expires_at) {
            sessions.remove(id);
            return None;
        }
        sessions.get(id).cloned()
    }
}

fn pending(interval: u64) -> PollIdcLoginResponse {
    PollIdcLoginResponse::Pending {
        poll_interval: interval,
    }
}

fn invalid(message: &str) -> AdminServiceError {
    AdminServiceError::InvalidCredential(message.to_string())
}

fn terminal(state: &LoginState) -> Result<PollIdcLoginResponse, AdminServiceError> {
    match state {
        LoginState::Success(id) => Ok(PollIdcLoginResponse::Success { credential_id: *id }),
        LoginState::Failed(message) => Err(AdminServiceError::UpstreamError(message.clone())),
        LoginState::Expired => Ok(PollIdcLoginResponse::Expired),
        _ => Err(invalid("登录会话类型不匹配")),
    }
}

fn login_proxy(
    credentials: &KiroCredentials,
    service: &AdminService,
) -> Result<Option<ProxyConfig>, AdminServiceError> {
    let proxy = credentials.effective_proxy(service.token_manager.proxy().as_ref());
    if let Some(proxy) = &proxy {
        let url = reqwest::Url::parse(&proxy.url).map_err(|_| invalid("代理 URL 无效"))?;
        if !matches!(url.scheme(), "http" | "https" | "socks5" | "socks5h")
            || url.host_str().is_none()
        {
            return Err(invalid("代理 URL 必须使用 http/https/socks5 协议"));
        }
    }
    Ok(proxy)
}

impl AdminService {
    pub async fn start_social_login(
        &self,
        req: StartSocialLoginRequest,
    ) -> Result<StartSocialLoginResponse, AdminServiceError> {
        // Portal 使用固定的官方 token 端点，避免将授权码交给任意地址。
        if req
            .auth_endpoint
            .as_deref()
            .is_some_and(|endpoint| endpoint != social::KIRO_AUTH_ENDPOINT)
        {
            return Err(invalid("仅支持 Kiro 官方认证端点"));
        }
        let credentials = KiroCredentials {
            auth_method: Some("social".into()),
            priority: req.priority,
            email: req.email,
            proxy_url: req.proxy_url,
            ..Default::default()
        };
        let proxy = login_proxy(&credentials, self)?;
        let (verifier, challenge) = social::generate_pkce();
        let state = uuid::Uuid::new_v4().to_string();
        let (tx, rx) = oneshot::channel();
        let (port, server) = social::start_callback_server(tx, state.clone())
            .map_err(|e| AdminServiceError::InternalError(e.to_string()))?;
        let redirect_uri = format!("http://127.0.0.1:{port}");
        let portal_url = social::build_portal_url(&state, &challenge, &redirect_uri);
        let expires_at = Utc::now() + Duration::minutes(10);
        let session_id = self.login_sessions.insert(
            expires_at,
            LoginState::Social(SocialSession {
                state,
                verifier,
                redirect_uri,
                callback_rx: rx,
                _server: server,
                credentials,
                proxy,
            }),
        );
        Ok(StartSocialLoginResponse {
            session_id,
            portal_url,
            expires_at: expires_at.to_rfc3339(),
        })
    }

    pub async fn poll_social_login(
        &self,
        id: &str,
    ) -> Result<PollIdcLoginResponse, AdminServiceError> {
        let Some(session) = self.login_sessions.get(id) else {
            return Ok(PollIdcLoginResponse::Expired);
        };
        let Ok(mut state) = session.state.try_lock() else {
            return Ok(pending(2));
        };
        let callback = match &mut *state {
            LoginState::Social(s) => match s.callback_rx.try_recv() {
                Ok(callback) => callback,
                Err(oneshot::error::TryRecvError::Empty) => return Ok(pending(2)),
                Err(oneshot::error::TryRecvError::Closed) => {
                    *state = LoginState::Failed("登录回调已关闭，请重新发起登录".into());
                    return terminal(&state);
                }
            },
            _ => return terminal(&state),
        };
        self.finish_social_login(&mut state, callback).await
    }

    pub async fn complete_social_login(
        &self,
        id: &str,
        code: String,
        state: String,
        login_option: String,
        path: String,
    ) -> Result<PollIdcLoginResponse, AdminServiceError> {
        let Some(session) = self.login_sessions.get(id) else {
            return Ok(PollIdcLoginResponse::Expired);
        };
        let Ok(mut session_state) = session.state.try_lock() else {
            return Ok(pending(2));
        };
        self.finish_social_login(
            &mut session_state,
            social::OAuthCallbackData {
                code,
                state,
                login_option,
                path,
            },
        )
        .await
    }

    async fn finish_social_login(
        &self,
        state: &mut LoginState,
        callback: social::OAuthCallbackData,
    ) -> Result<PollIdcLoginResponse, AdminServiceError> {
        let LoginState::Social(s) = state else {
            return terminal(state);
        };
        if callback.code.trim().is_empty()
            || !matches!(
                callback.path.as_str(),
                "/oauth/callback" | "/signin/callback"
            )
        {
            return Err(invalid("OAuth 回调地址无效"));
        }
        if !crate::common::auth::constant_time_eq(&callback.state, &s.state) {
            return Err(invalid("OAuth state 不匹配，请粘贴本次登录的回调地址"));
        }
        let redirect = if callback.login_option.is_empty() {
            format!("{}{}", s.redirect_uri, callback.path)
        } else {
            format!(
                "{}{}?login_option={}",
                s.redirect_uri,
                callback.path,
                urlencoding::encode(&callback.login_option)
            )
        };
        let result = async {
            let token = social::exchange_code_for_token(
                social::KIRO_AUTH_ENDPOINT,
                &callback.code,
                &s.verifier,
                &redirect,
                self.token_manager.config(),
                s.proxy.as_ref(),
            )
            .await
            .map_err(|e| AdminServiceError::UpstreamError(e.to_string()))?;
            let mut credentials = s.credentials.clone();
            credentials.access_token = Some(token.access_token);
            credentials.refresh_token = token.refresh_token;
            credentials.profile_arn = token.profile_arn;
            credentials.expires_at = token.expires_at.or_else(|| {
                token
                    .expires_in
                    .and_then(|secs| Utc::now().checked_add_signed(Duration::try_seconds(secs)?))
                    .map(|time| time.to_rfc3339())
            });
            self.save_login_credential(credentials).await
        }
        .await;
        Self::record_login_result(state, result)
    }

    pub async fn start_idc_login(
        &self,
        req: StartIdcLoginRequest,
    ) -> Result<StartIdcLoginResponse, AdminServiceError> {
        let region = req.region.trim();
        // Region 将拼接到主机名，只允许 AWS 区域标识，拒绝 URL 分隔符。
        if region.len() > 40
            || !region.split('-').all(|part| !part.is_empty())
            || region.split('-').count() < 3
            || !region
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            || !region.bytes().last().is_some_and(|b| b.is_ascii_digit())
        {
            return Err(invalid("AWS Region 格式无效"));
        }
        let start_url = req
            .start_url
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or(idc::BUILDER_ID_START_URL);
        let url = reqwest::Url::parse(start_url).map_err(|_| invalid("SSO Start URL 无效"))?;
        if url.scheme() != "https"
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
        {
            return Err(invalid("SSO Start URL 必须是有效的 HTTPS 地址"));
        }
        let mut credentials = KiroCredentials {
            auth_method: Some("idc".into()),
            region: Some(region.to_string()),
            auth_region: Some(region.to_string()),
            priority: req.priority,
            email: req.email,
            proxy_url: req.proxy_url,
            ..Default::default()
        };
        let proxy = login_proxy(&credentials, self)?;
        let config = self.token_manager.config();
        let reg = idc::register_client(region, start_url, config, proxy.as_ref())
            .await
            .map_err(|e| AdminServiceError::UpstreamError(e.to_string()))?;
        let device = idc::start_device_authorization(
            region,
            start_url,
            &reg.client_id,
            &reg.client_secret,
            config,
            proxy.as_ref(),
        )
        .await
        .map_err(|e| AdminServiceError::UpstreamError(e.to_string()))?;
        credentials.client_id = Some(reg.client_id.clone());
        credentials.client_secret = Some(reg.client_secret.clone());
        let expires_at = Utc::now() + Duration::seconds(device.expires_in.clamp(1, 3600));
        let interval = device.interval.clamp(5, 60) as u64;
        let session_id = self.login_sessions.insert(
            expires_at,
            LoginState::Idc(IdcSession {
                region: region.into(),
                client_id: reg.client_id,
                client_secret: reg.client_secret,
                device_code: device.device_code,
                interval,
                next_poll: Utc::now() + Duration::seconds(interval as i64),
                credentials,
                proxy,
            }),
        );
        Ok(StartIdcLoginResponse {
            session_id,
            user_code: device.user_code,
            verification_uri: device.verification_uri,
            verification_uri_complete: device.verification_uri_complete,
            expires_at: expires_at.to_rfc3339(),
            poll_interval: interval as i64,
        })
    }

    pub async fn poll_idc_login(
        &self,
        id: &str,
    ) -> Result<PollIdcLoginResponse, AdminServiceError> {
        let Some(session) = self.login_sessions.get(id) else {
            return Ok(PollIdcLoginResponse::Expired);
        };
        let Ok(mut state) = session.state.try_lock() else {
            return Ok(pending(5));
        };
        let LoginState::Idc(s) = &mut *state else {
            return terminal(&state);
        };
        if Utc::now() < s.next_poll {
            return Ok(pending(s.interval));
        }
        let result = idc::poll_token(
            &s.region,
            &s.client_id,
            &s.client_secret,
            &s.device_code,
            self.token_manager.config(),
            s.proxy.as_ref(),
        )
        .await;
        match result {
            idc::PollResult::Pending | idc::PollResult::SlowDown => {
                if matches!(result, idc::PollResult::SlowDown) {
                    s.interval = (s.interval + 5).min(60);
                }
                s.next_poll = Utc::now() + Duration::seconds(s.interval as i64);
                Ok(pending(s.interval))
            }
            idc::PollResult::Expired => {
                *state = LoginState::Expired;
                Ok(PollIdcLoginResponse::Expired)
            }
            idc::PollResult::Error(e) => Self::record_login_result(
                &mut state,
                Err(AdminServiceError::UpstreamError(e.to_string())),
            ),
            idc::PollResult::Success(token) => {
                let mut credentials = s.credentials.clone();
                credentials.access_token = Some(token.access_token);
                credentials.refresh_token = token.refresh_token;
                credentials.expires_at = token
                    .expires_in
                    .and_then(|secs| Utc::now().checked_add_signed(Duration::try_seconds(secs)?))
                    .map(|time| time.to_rfc3339());
                let result = self.save_login_credential(credentials).await;
                Self::record_login_result(&mut state, result)
            }
        }
    }

    fn record_login_result(
        state: &mut LoginState,
        result: Result<u64, AdminServiceError>,
    ) -> Result<PollIdcLoginResponse, AdminServiceError> {
        match result {
            Ok(id) => {
                *state = LoginState::Success(id);
                Ok(PollIdcLoginResponse::Success { credential_id: id })
            }
            Err(e) => {
                *state = LoginState::Failed(e.to_string());
                Err(e)
            }
        }
    }

    async fn save_login_credential(&self, cred: KiroCredentials) -> Result<u64, AdminServiceError> {
        // 复用本项目的验证、代理池分配、持久化、计费清理及余额获取路径。
        let response = self
            .add_credential(AddCredentialRequest {
                refresh_token: cred.refresh_token,
                auth_method: cred.auth_method.unwrap_or_else(|| "social".into()),
                profile_arn: cred.profile_arn,
                client_id: cred.client_id,
                client_secret: cred.client_secret,
                priority: cred.priority,
                region: cred.region,
                auth_region: cred.auth_region,
                api_region: cred.api_region,
                machine_id: cred.machine_id,
                email: cred.email,
                password: None,
                proxy_url: cred.proxy_url,
                proxy_username: cred.proxy_username,
                proxy_password: cred.proxy_password,
                kiro_api_key: None,
                endpoint: None,
                cooldown_enabled: None,
                cooldown_seconds: None,
                cooldown_max_requests: None,
                auto_allocate_proxy: true,
            })
            .await?;
        Ok(response.credential_id)
    }

    pub fn cancel_login(&self, id: &str) {
        self.login_sessions.0.lock().remove(id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{kiro::token_manager::MultiTokenManager, model::config::Config};
    use serde_json::json;

    fn service() -> AdminService {
        let manager = MultiTokenManager::new(Config::default(), vec![], None, None, true).unwrap();
        AdminService::new(Arc::new(manager), ["ide".to_string()])
    }

    #[tokio::test]
    async fn login_routes_require_admin_key_and_support_session_lifecycle() {
        use crate::admin::{AdminState, create_admin_router};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let app = create_admin_router(AdminState::new("test-admin-key", service()));
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        let base = format!("http://{address}");
        for path in [
            "/auth/social/start",
            "/auth/idc/start",
            "/auth/social/poll/test",
            "/auth/idc/poll/test",
            "/auth/social/complete/test",
        ] {
            let response = client
                .post(format!("{base}{path}"))
                .json(&json!({}))
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), 401, "{path}");
        }
        let response = client
            .delete(format!("{base}/auth/sessions/test"))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 401);
        let start: serde_json::Value = client
            .post(format!("{base}/auth/social/start"))
            .header("x-api-key", "test-admin-key")
            .json(&json!({}))
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap();
        let id = start["sessionId"].as_str().unwrap();
        assert!(
            start["portalUrl"]
                .as_str()
                .unwrap()
                .starts_with("https://app.kiro.dev/signin?")
        );
        let pending: serde_json::Value = client
            .post(format!("{base}/auth/social/poll/{id}"))
            .header("x-api-key", "test-admin-key")
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(pending["status"], "pending");
        let invalid = client
            .post(format!("{base}/auth/social/complete/{id}"))
            .header("x-api-key", "test-admin-key")
            .json(&json!({"code":"test", "state":"wrong"}))
            .send()
            .await
            .unwrap();
        assert_eq!(invalid.status(), 400);
        client
            .delete(format!("{base}/auth/sessions/{id}"))
            .header("x-api-key", "test-admin-key")
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap();
        let expired: serde_json::Value = client
            .post(format!("{base}/auth/social/poll/{id}"))
            .header("x-api-key", "test-admin-key")
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(expired["status"], "expired");
        server.abort();
    }

    #[test]
    fn login_result_matches_frontend_contract() {
        let response = terminal(&LoginState::Success(42)).unwrap();
        assert_eq!(
            serde_json::to_value(response).unwrap(),
            json!({"status":"success", "credentialId":42})
        );
        assert_eq!(
            serde_json::to_value(pending(10)).unwrap(),
            json!({"status":"pending", "pollInterval":10})
        );
    }

    #[tokio::test]
    async fn social_callback_validation_preserves_session_and_cancel_expires_it() {
        let service = service();
        let start = service
            .start_social_login(serde_json::from_value(json!({})).unwrap())
            .await
            .unwrap();
        assert!(matches!(
            service.poll_social_login(&start.session_id).await.unwrap(),
            PollIdcLoginResponse::Pending { .. }
        ));
        let portal = reqwest::Url::parse(&start.portal_url).unwrap();
        let state = portal
            .query_pairs()
            .find(|(k, _)| k == "state")
            .unwrap()
            .1
            .into_owned();
        assert!(
            service
                .complete_social_login(
                    &start.session_id,
                    "code".into(),
                    "wrong".into(),
                    "".into(),
                    "/oauth/callback".into()
                )
                .await
                .is_err()
        );
        assert!(
            service
                .complete_social_login(
                    &start.session_id,
                    "code".into(),
                    state,
                    "".into(),
                    "/unexpected".into()
                )
                .await
                .is_err()
        );
        assert!(matches!(
            service.poll_social_login(&start.session_id).await.unwrap(),
            PollIdcLoginResponse::Pending { .. }
        ));
        service.cancel_login(&start.session_id);
        assert!(matches!(
            service.poll_social_login(&start.session_id).await.unwrap(),
            PollIdcLoginResponse::Expired
        ));
    }

    #[tokio::test]
    async fn sessions_expire_and_success_can_be_polled_again() {
        let service = service();
        let expired = service
            .login_sessions
            .insert(Utc::now() - Duration::seconds(1), LoginState::Expired);
        assert!(matches!(
            service.poll_idc_login(&expired).await.unwrap(),
            PollIdcLoginResponse::Expired
        ));
        let success = service
            .login_sessions
            .insert(Utc::now() + Duration::minutes(1), LoginState::Success(7));
        for _ in 0..2 {
            assert!(matches!(
                service.poll_idc_login(&success).await.unwrap(),
                PollIdcLoginResponse::Success { credential_id: 7 }
            ));
        }
    }

    #[tokio::test]
    async fn rejects_invalid_region_start_url_and_token_endpoint_before_network_access() {
        let service = service();
        for region in [
            "",
            "https://example.com",
            "us-east-1/evil",
            "us-east-1@example.com",
        ] {
            let request = serde_json::from_value(json!({"region": region})).unwrap();
            assert!(service.start_idc_login(request).await.is_err());
        }
        let request = serde_json::from_value(
            json!({"region":"us-east-1", "startUrl":"http://example.com/start"}),
        )
        .unwrap();
        assert!(service.start_idc_login(request).await.is_err());
        let request =
            serde_json::from_value(json!({"authEndpoint":"https://example.com"})).unwrap();
        assert!(service.start_social_login(request).await.is_err());
    }
}
