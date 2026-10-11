//! Token 管理模块
//!
//! 负责 Token 过期检测和刷新，支持 Social 和 IdC 认证方式
//! 支持多凭据 (MultiTokenManager) 管理

use anyhow::bail;
use chrono::{DateTime, Duration, Utc};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::Mutex as TokioMutex;

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration as StdDuration, Instant};

use crate::common::fs_util::write_atomic;
use crate::http_client::{ProxyConfig, build_client};
use crate::kiro::machine_id;
use crate::kiro::model::available_profiles::ListAvailableProfilesResponse;
use crate::kiro::model::credentials::KiroCredentials;
use crate::kiro::model::token_refresh::{
    IdcRefreshRequest, IdcRefreshResponse, RefreshRequest, RefreshResponse,
};
use crate::kiro::model::usage_limits::UsageLimitsResponse;
use crate::model::config::Config;

/// 用量类 REST 接口（getUsageLimits / setUserPreference）固定使用的 Kiro IDE 版本。
///
/// 该版本号只影响 User-Agent。Enterprise / IdC 账号调用这些接口仍需发送真实
/// `profileArn`；BuilderID 占位 ARN 则不能发送。
///
/// 流式端点 `generateAssistantResponse` 不受影响，仍使用 `config.kiro_version`。
pub const USAGE_API_KIRO_VERSION: &str = "0.9.2";

/// 检查 Token 是否在指定时间内过期
pub(crate) fn is_token_expiring_within(
    credentials: &KiroCredentials,
    minutes: i64,
) -> Option<bool> {
    credentials
        .expires_at
        .as_ref()
        .and_then(|expires_at| DateTime::parse_from_rfc3339(expires_at).ok())
        .map(|expires| expires <= Utc::now() + Duration::minutes(minutes))
}

/// 检查 Token 是否已过期（提前 5 分钟判断）
pub(crate) fn is_token_expired(credentials: &KiroCredentials) -> bool {
    is_token_expiring_within(credentials, 5).unwrap_or(true)
}

/// 检查 Token 是否即将过期（10分钟内）
pub(crate) fn is_token_expiring_soon(credentials: &KiroCredentials) -> bool {
    is_token_expiring_within(credentials, 10).unwrap_or(false)
}

fn sha256_hex(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let result = hasher.finalize();
    format!("{:x}", result)
}

/// 生成 API Key 脱敏展示(前 4 + ... + 后 4,长度不足或非 ASCII 回退 ***)
fn mask_api_key(key: &str) -> String {
    if key.is_ascii() && key.len() > 16 {
        format!("{}...{}", &key[..4], &key[key.len() - 4..])
    } else {
        "***".to_string()
    }
}

/// 验证 refreshToken 的基本有效性
pub(crate) fn validate_refresh_token(credentials: &KiroCredentials) -> anyhow::Result<()> {
    let refresh_token = credentials
        .refresh_token
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("缺少 refreshToken"))?;

    if refresh_token.is_empty() {
        bail!("refreshToken 为空");
    }

    if refresh_token.len() < 100 || refresh_token.ends_with("...") || refresh_token.contains("...")
    {
        bail!(
            "refreshToken 已被截断（长度: {} 字符）。\n\
             这通常是 Kiro IDE 为了防止凭证被第三方工具使用而故意截断的。",
            refresh_token.len()
        );
    }

    Ok(())
}

/// Refresh Token 永久失效错误
///
/// 当服务端返回 400 + `invalid_grant` 时，表示 refreshToken 已被撤销或过期，
/// 不应重试，需立即禁用对应凭据。
#[derive(Debug)]
pub(crate) struct RefreshTokenInvalidError {
    pub message: String,
}

impl fmt::Display for RefreshTokenInvalidError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for RefreshTokenInvalidError {}

/// Token 刷新的瞬态错误（网络错误、上游 429/5xx、响应解析失败）
///
/// 与认证类错误区分：瞬态错误不计入 refresh 失败（不会触发不可自愈的
/// `TooManyRefreshFailures`），只按普通失败计数，由调用方退避后重试。
#[derive(Debug)]
pub(crate) struct TransientRefreshError {
    pub message: String,
}

impl fmt::Display for TransientRefreshError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for TransientRefreshError {}

fn transient_refresh_error(context: &str, err: impl fmt::Display) -> anyhow::Error {
    TransientRefreshError {
        message: format!("{}: {}", context, err),
    }
    .into()
}

/// 将刷新结果中的 token 相关字段合并到当前凭据
///
/// 刷新期间（网络 await 最长 60 秒）Admin 可能修改了优先级、代理、订阅信息等，
/// 整体覆盖会把这些修改回滚，因此只合并刷新接口实际返回的字段。
/// `before` 是发起刷新时使用的凭据快照：refresh_token/profile_arn 只有在刷新响应
/// 确实改变了它们时才写回，避免用旧快照覆盖刷新期间回填的 ARN。
fn apply_refreshed_tokens(
    target: &mut KiroCredentials,
    before: &KiroCredentials,
    refreshed: &KiroCredentials,
) {
    target.access_token = refreshed.access_token.clone();
    target.expires_at = refreshed.expires_at.clone();
    if refreshed.refresh_token != before.refresh_token {
        target.refresh_token = refreshed.refresh_token.clone();
    }
    if refreshed.profile_arn != before.profile_arn {
        target.profile_arn = refreshed.profile_arn.clone();
    }
}

/// 刷新响应缺少 expiresIn 时使用的默认有效期（秒）
const DEFAULT_TOKEN_EXPIRES_IN_SECS: i64 = 3600;

/// 可配置时长的上限（1 年），防止 `Instant + Duration` 溢出 panic
const MAX_CONFIG_DURATION_SECS: u64 = 365 * 24 * 3600;

/// 将配置中的秒数转换为 Duration，并截断到安全上限
fn capped_duration_secs(secs: u64) -> StdDuration {
    StdDuration::from_secs(secs.min(MAX_CONFIG_DURATION_SECS))
}

/// Admin 写入时长配置前的上限校验
fn validate_duration_secs(name: &str, secs: u64) -> anyhow::Result<()> {
    if secs > MAX_CONFIG_DURATION_SECS {
        bail!("{}不能超过 {} 秒", name, MAX_CONFIG_DURATION_SECS);
    }
    Ok(())
}

/// 刷新 Token
pub(crate) async fn refresh_token(
    credentials: &KiroCredentials,
    config: &Config,
    proxy: Option<&ProxyConfig>,
) -> anyhow::Result<KiroCredentials> {
    // API Key 凭据不支持 Token 刷新：底层契约级拦截
    // 其他调用点（try_ensure_token / 活跃路径 / add_credential）在调用前已显式分流 API Key；
    // 仅 force_refresh_token_for 未分流，此处 bail 让错误自然传播为 400 BAD_REQUEST。
    if credentials.is_api_key_credential() {
        bail!("API Key 凭据不支持刷新 Token");
    }

    validate_refresh_token(credentials)?;

    // 根据 auth_method 选择刷新方式
    // 如果未指定 auth_method，根据是否有 clientId/clientSecret 自动判断
    let auth_method = credentials.auth_method.as_deref().unwrap_or_else(|| {
        if credentials.client_id.is_some() && credentials.client_secret.is_some() {
            "idc"
        } else {
            "social"
        }
    });

    if auth_method.eq_ignore_ascii_case("idc")
        || auth_method.eq_ignore_ascii_case("builder-id")
        || auth_method.eq_ignore_ascii_case("builderid")
        || auth_method.eq_ignore_ascii_case("enterprise")
        || auth_method.eq_ignore_ascii_case("iam")
    {
        refresh_idc_token(credentials, config, proxy).await
    } else {
        refresh_social_token(credentials, config, proxy).await
    }
}

/// 刷新 Social Token
async fn refresh_social_token(
    credentials: &KiroCredentials,
    config: &Config,
    proxy: Option<&ProxyConfig>,
) -> anyhow::Result<KiroCredentials> {
    tracing::info!("正在刷新 Social Token...");

    let refresh_token = credentials.refresh_token.as_ref().unwrap();
    // 优先级：凭据.auth_region > 凭据.region > config.auth_region > config.region
    let region = credentials.effective_auth_region(config);

    let refresh_url = format!("https://prod.{}.auth.desktop.kiro.dev/refreshToken", region);
    let refresh_domain = format!("prod.{}.auth.desktop.kiro.dev", region);
    let machine_id = machine_id::generate_from_credentials(credentials, config);
    let kiro_version = &config.kiro_version;

    let client = build_client(proxy, 60, config.tls_backend)?;
    let body = RefreshRequest {
        refresh_token: refresh_token.to_string(),
    };

    let response = client
        .post(&refresh_url)
        .header("Accept", "application/json, text/plain, */*")
        .header("Content-Type", "application/json")
        .header(
            "User-Agent",
            format!("KiroIDE-{}-{}", kiro_version, machine_id),
        )
        .header("Accept-Encoding", "gzip, compress, deflate, br")
        .header("host", &refresh_domain)
        .header("Connection", "close")
        .json(&body)
        .send()
        .await
        .map_err(|e| transient_refresh_error("Social Token 刷新请求发送失败", e))?;

    let status = response.status();
    if !status.is_success() {
        let body_text = response.text().await.unwrap_or_default();

        // 400 + invalid_grant + Invalid refresh token provided → refreshToken 永久失效
        if status.as_u16() == 400
            && body_text.contains("\"invalid_grant\"")
            && body_text.contains("Invalid refresh token provided")
        {
            return Err(RefreshTokenInvalidError {
                message: format!("Social refreshToken 已失效 (invalid_grant): {}", body_text),
            }
            .into());
        }

        let error_msg = match status.as_u16() {
            401 => "OAuth 凭证已过期或无效，需要重新认证",
            403 => "权限不足，无法刷新 Token",
            429 => "请求过于频繁，已被限流",
            500..=599 => "服务器错误，AWS OAuth 服务暂时不可用",
            _ => "Token 刷新失败",
        };
        if status.as_u16() == 429 || status.is_server_error() {
            return Err(transient_refresh_error(error_msg, format!("{} {}", status, body_text)));
        }
        bail!("{}: {} {}", error_msg, status, body_text);
    }

    let data: RefreshResponse = response
        .json()
        .await
        .map_err(|e| transient_refresh_error("解析 Social Token 刷新响应失败", e))?;

    let mut new_credentials = credentials.clone();
    new_credentials.access_token = Some(data.access_token);

    if let Some(new_refresh_token) = data.refresh_token {
        new_credentials.refresh_token = Some(new_refresh_token);
    }

    if let Some(profile_arn) = data.profile_arn {
        new_credentials.profile_arn = Some(profile_arn);
    }

    new_credentials.expires_at = Some(new_expires_at(data.expires_in));

    Ok(new_credentials)
}

/// 根据刷新响应的 expiresIn 计算新的过期时间
///
/// 响应缺少 expiresIn（或给出非正数）时使用默认有效期，避免沿用旧的过期时间
/// 导致"刷新后仍过期"被误判为刷新失败。
fn new_expires_at(expires_in: Option<i64>) -> String {
    let secs = match expires_in {
        Some(s) if s > 0 => s,
        _ => {
            tracing::warn!(
                "Token 刷新响应缺少有效 expiresIn，按默认 {}s 计算过期时间",
                DEFAULT_TOKEN_EXPIRES_IN_SECS
            );
            DEFAULT_TOKEN_EXPIRES_IN_SECS
        }
    };
    (Utc::now() + Duration::seconds(secs)).to_rfc3339()
}

/// 刷新 IdC Token (AWS SSO OIDC)
async fn refresh_idc_token(
    credentials: &KiroCredentials,
    config: &Config,
    proxy: Option<&ProxyConfig>,
) -> anyhow::Result<KiroCredentials> {
    tracing::info!("正在刷新 IdC Token...");

    let refresh_token = credentials.refresh_token.as_ref().unwrap();
    let client_id = credentials
        .client_id
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("IdC 刷新需要 clientId"))?;
    let client_secret = credentials
        .client_secret
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("IdC 刷新需要 clientSecret"))?;

    // 优先级：凭据.auth_region > 凭据.region > config.auth_region > config.region
    let region = credentials.effective_auth_region(config);
    let refresh_url = format!("https://oidc.{}.amazonaws.com/token", region);
    let os_name = &config.system_version;
    let node_version = &config.node_version;

    let x_amz_user_agent = "aws-sdk-js/3.980.0 KiroIDE";
    let user_agent = format!(
        "aws-sdk-js/3.980.0 ua/2.1 os/{} lang/js md/nodejs#{} api/sso-oidc#3.980.0 m/E KiroIDE",
        os_name, node_version
    );

    let client = build_client(proxy, 60, config.tls_backend)?;
    let body = IdcRefreshRequest {
        client_id: client_id.to_string(),
        client_secret: client_secret.to_string(),
        refresh_token: refresh_token.to_string(),
        grant_type: "refresh_token".to_string(),
    };

    let response = client
        .post(&refresh_url)
        .header("content-type", "application/json")
        .header("x-amz-user-agent", x_amz_user_agent)
        .header("user-agent", &user_agent)
        .header("host", format!("oidc.{}.amazonaws.com", region))
        .header("amz-sdk-invocation-id", uuid::Uuid::new_v4().to_string())
        .header("amz-sdk-request", "attempt=1; max=4")
        .header("Connection", "close")
        .json(&body)
        .send()
        .await
        .map_err(|e| transient_refresh_error("IdC Token 刷新请求发送失败", e))?;

    let status = response.status();
    if !status.is_success() {
        let body_text = response.text().await.unwrap_or_default();

        // 400 + invalid_grant + Invalid refresh token provided → refreshToken 永久失效
        if status.as_u16() == 400
            && body_text.contains("\"invalid_grant\"")
            && body_text.contains("Invalid refresh token provided")
        {
            return Err(RefreshTokenInvalidError {
                message: format!("IdC refreshToken 已失效 (invalid_grant): {}", body_text),
            }
            .into());
        }

        let error_msg = match status.as_u16() {
            401 => "IdC 凭证已过期或无效，需要重新认证",
            403 => "权限不足，无法刷新 Token",
            429 => "请求过于频繁，已被限流",
            500..=599 => "服务器错误，AWS OIDC 服务暂时不可用",
            _ => "IdC Token 刷新失败",
        };
        if status.as_u16() == 429 || status.is_server_error() {
            return Err(transient_refresh_error(error_msg, format!("{} {}", status, body_text)));
        }
        bail!("{}: {} {}", error_msg, status, body_text);
    }

    let data: IdcRefreshResponse = response
        .json()
        .await
        .map_err(|e| transient_refresh_error("解析 IdC Token 刷新响应失败", e))?;

    let mut new_credentials = credentials.clone();
    new_credentials.access_token = Some(data.access_token);

    if let Some(new_refresh_token) = data.refresh_token {
        new_credentials.refresh_token = Some(new_refresh_token);
    }

    new_credentials.expires_at = Some(new_expires_at(data.expires_in));

    // 同步更新 profile_arn（如果 IdC 响应中包含）
    if let Some(profile_arn) = data.profile_arn {
        new_credentials.profile_arn = Some(profile_arn);
    }

    Ok(new_credentials)
}

/// Kiro 用量类 REST 接口仅在 us-east-1 和 eu-central-1 提供服务。
/// 按 SSO 区域优先选择端点，并将另一区域作为 Enterprise/IdC 的 403 回退。
fn rest_api_region_candidates(sso_region: &str) -> [&'static str; 2] {
    if sso_region == "eu-central-1" || sso_region.starts_with("eu-") {
        ["eu-central-1", "us-east-1"]
    } else {
        ["us-east-1", "eu-central-1"]
    }
}

fn profile_arn_query(profile_arn: Option<&str>) -> String {
    profile_arn
        .map(|arn| format!("&profileArn={}", urlencoding::encode(arn)))
        .unwrap_or_default()
}

/// 先携带真实 ARN，再保留不带 ARN 的兼容请求，最后回退到另一区域。
/// BuilderID 占位 ARN 会被 `effective_profile_arn` 过滤。
fn usage_api_attempts<'a>(
    credentials: &'a KiroCredentials,
    candidates: &[&'static str],
) -> Vec<(&'static str, Option<&'a str>)> {
    let mut attempts = Vec::with_capacity(candidates.len() * 2);
    for region in candidates {
        if let Some(arn) = credentials.effective_profile_arn() {
            attempts.push((*region, Some(arn)));
        }
        attempts.push((*region, None));
    }
    attempts
}

fn usage_limits_url(host: &str, profile_arn: Option<&str>) -> String {
    format!(
        "https://{}/getUsageLimits?origin=AI_EDITOR&resourceType=AGENTIC_REQUEST&isEmailRequired=true{}",
        host,
        profile_arn_query(profile_arn)
    )
}

fn set_user_preference_body(
    credentials: &KiroCredentials,
    overage_status: &str,
) -> serde_json::Value {
    let mut body = serde_json::json!({
        "overageConfiguration": { "overageStatus": overage_status }
    });
    if let Some(profile_arn) = credentials.effective_profile_arn() {
        body["profileArn"] = serde_json::json!(profile_arn);
    }
    body
}

/// 获取使用额度信息
pub(crate) async fn get_usage_limits(
    credentials: &KiroCredentials,
    config: &Config,
    token: &str,
    proxy: Option<&ProxyConfig>,
) -> anyhow::Result<UsageLimitsResponse> {
    tracing::debug!("正在获取使用额度信息...");

    let sso_region = credentials.effective_auth_region(config);
    let candidates = rest_api_region_candidates(sso_region);
    let machine_id = machine_id::generate_from_credentials(credentials, config);
    let kiro_version = USAGE_API_KIRO_VERSION;
    let os_name = &config.system_version;
    let node_version = &config.node_version;

    let user_agent = format!(
        "aws-sdk-js/1.0.0 ua/2.1 os/{} lang/js md/nodejs#{} api/codewhispererruntime#1.0.0 m/N,E KiroIDE-{}-{}",
        os_name, node_version, kiro_version, machine_id
    );
    let amz_user_agent = format!(
        "aws-sdk-js/1.0.0 KiroIDE-{}-{}",
        kiro_version, machine_id
    );
    let client = build_client(proxy, 60, config.tls_backend)?;
    let attempts = usage_api_attempts(credentials, &candidates);
    let mut last_error: Option<String> = None;

    for (idx, (region, profile_arn)) in attempts.iter().enumerate() {
        let host = format!("q.{}.amazonaws.com", region);
        let url = usage_limits_url(&host, *profile_arn);
        let mut request = client
            .get(&url)
            .header("x-amz-user-agent", &amz_user_agent)
            .header("user-agent", &user_agent)
            .header("host", &host)
            .header("amz-sdk-invocation-id", uuid::Uuid::new_v4().to_string())
            .header("amz-sdk-request", "attempt=1; max=1")
            .header("Authorization", format!("Bearer {}", token))
            .header("Connection", "close");

        if credentials.is_api_key_credential() {
            request = request.header("tokentype", "API_KEY");
        }

        let response = request.send().await?;
        let status = response.status();
        if status.is_success() {
            return Ok(response.json().await?);
        }

        let body_text = response.text().await.unwrap_or_default();
        if status.as_u16() == 403 && idx + 1 < attempts.len() {
            tracing::debug!(
                "getUsageLimits 在 {} 返回 403（profileArn={}），尝试下一候选",
                region,
                profile_arn.is_some()
            );
            last_error = Some(format!("{} {}", status, body_text));
            continue;
        }

        let error_msg = match status.as_u16() {
            401 => "认证失败，Token 无效或已过期",
            403 => "权限不足，无法获取使用额度",
            429 => "请求过于频繁，已被限流",
            500..=599 => "服务器错误，AWS 服务暂时不可用",
            _ => "获取使用额度失败",
        };
        bail!("{}: {} {}", error_msg, status, body_text);
    }

    bail!(
        "权限不足，无法获取使用额度: {}",
        last_error.unwrap_or_else(|| "无可用端点".to_string())
    );
}

/// 查询 Enterprise 和 IdC 凭据的真实 profile ARN。
pub(crate) async fn list_available_profiles(
    credentials: &KiroCredentials,
    config: &Config,
    token: &str,
    proxy: Option<&ProxyConfig>,
) -> anyhow::Result<ListAvailableProfilesResponse> {
    let sso_region = credentials.effective_auth_region(config);
    let candidates = rest_api_region_candidates(sso_region);
    let machine_id = machine_id::generate_from_credentials(credentials, config);
    let kiro_version = USAGE_API_KIRO_VERSION;
    let os_name = &config.system_version;
    let node_version = &config.node_version;
    let user_agent = format!(
        "aws-sdk-js/1.0.0 ua/2.1 os/{} lang/js md/nodejs#{} api/codewhispererruntime#1.0.0 m/N,E KiroIDE-{}-{}",
        os_name, node_version, kiro_version, machine_id
    );
    let amz_user_agent = format!(
        "aws-sdk-js/1.0.0 KiroIDE-{}-{}",
        kiro_version, machine_id
    );
    let client = build_client(proxy, 60, config.tls_backend)?;
    let mut last_error: Option<String> = None;
    let mut empty_seen = false;

    for region in candidates {
        let host = format!("q.{}.amazonaws.com", region);
        let mut request = client
            .post(format!("https://{}/", host))
            .header("content-type", "application/x-amz-json-1.0")
            .header(
                "x-amz-target",
                "AmazonCodeWhispererService.ListAvailableProfiles",
            )
            .header("x-amz-user-agent", &amz_user_agent)
            .header("user-agent", &user_agent)
            .header("host", &host)
            .header("amz-sdk-invocation-id", uuid::Uuid::new_v4().to_string())
            .header("amz-sdk-request", "attempt=1; max=1")
            .header("Authorization", format!("Bearer {}", token))
            .header("Connection", "close")
            .body(r#"{"maxResults":10}"#);

        if credentials.is_api_key_credential() {
            request = request.header("tokentype", "API_KEY");
        }

        let response = request.send().await?;
        let status = response.status();
        if status.is_success() {
            let data: ListAvailableProfilesResponse = response.json().await?;
            if data.first_arn().is_some() {
                return Ok(data);
            }
            empty_seen = true;
            continue;
        }

        last_error = Some(format!(
            "{} {}",
            status,
            response.text().await.unwrap_or_default()
        ));
    }

    if empty_seen {
        return Ok(ListAvailableProfilesResponse::default());
    }

    bail!(
        "获取可用 profile 失败: {}",
        last_error.unwrap_or_else(|| "无可用端点".to_string())
    );
}

/// 调用 setUserPreference 设置超额开关
pub(crate) async fn set_user_preference(
    credentials: &KiroCredentials,
    config: &Config,
    token: &str,
    proxy: Option<&ProxyConfig>,
    overage_status: &str,
) -> anyhow::Result<()> {
    let sso_region = credentials.effective_auth_region(config);
    let candidates = rest_api_region_candidates(sso_region);
    let machine_id = machine_id::generate_from_credentials(credentials, config);
    let kiro_version = USAGE_API_KIRO_VERSION;
    let os_name = &config.system_version;
    let node_version = &config.node_version;
    let user_agent = format!(
        "aws-sdk-js/1.0.0 ua/2.1 os/{} lang/js md/nodejs#{} api/codewhispererruntime#1.0.0 m/N,E KiroIDE-{}-{}",
        os_name, node_version, kiro_version, machine_id
    );
    let amz_user_agent = format!(
        "aws-sdk-js/1.0.0 KiroIDE-{}-{}",
        kiro_version, machine_id
    );
    let client = build_client(proxy, 30, config.tls_backend)?;
    let body = set_user_preference_body(credentials, overage_status);
    let mut last_error: Option<String> = None;

    for (idx, region) in candidates.iter().enumerate() {
        let host = format!("q.{}.amazonaws.com", region);
        let mut request = client
            .post(format!("https://{}/setUserPreference", host))
            .header("content-type", "application/json")
            .header("x-amz-user-agent", &amz_user_agent)
            .header("user-agent", &user_agent)
            .header("host", &host)
            .header("amz-sdk-invocation-id", uuid::Uuid::new_v4().to_string())
            .header("amz-sdk-request", "attempt=1; max=1")
            .header("Authorization", format!("Bearer {}", token))
            .header("Connection", "close")
            .json(&body);

        if credentials.is_api_key_credential() {
            request = request.header("tokentype", "API_KEY");
        }

        let response = request.send().await?;
        let status = response.status();
        if status.is_success() {
            return Ok(());
        }

        let body_text = response.text().await.unwrap_or_default();
        if status.as_u16() == 403 && idx + 1 < candidates.len() {
            tracing::debug!(
                "setUserPreference 在 {} 返回 403，尝试备用端点 {}",
                region,
                candidates[idx + 1]
            );
            last_error = Some(format!("{} {}", status, body_text));
            continue;
        }

        bail!("setUserPreference 失败: {} {}", status, body_text);
    }

    bail!(
        "setUserPreference 失败: {}",
        last_error.unwrap_or_else(|| "无可用端点".to_string())
    );
}

// ============================================================================
// 多凭据 Token 管理器
// ============================================================================

/// 单个凭据条目的状态
struct CredentialEntry {
    /// 凭据唯一 ID
    id: u64,
    /// 凭据信息
    credentials: KiroCredentials,
    /// API 调用连续失败次数
    failure_count: u32,
    /// Token 刷新连续失败次数
    refresh_failure_count: u32,
    /// 是否已禁用
    disabled: bool,
    /// 禁用原因（用于区分手动禁用 vs 自动禁用，便于自愈）
    disabled_reason: Option<DisabledReason>,
    /// API 调用成功次数
    success_count: u64,
    /// 最后一次 API 调用时间（RFC3339 格式）
    last_used_at: Option<String>,
    /// 请求分发历史（冷却窗口控制，不持久化）
    dispatch_history: VecDeque<Instant>,
    /// 最后一次 API 请求的 TTFB（毫秒）
    last_ttfb_ms: Option<u64>,
    /// 429 限流累计次数
    rate_limit_count: u64,
    /// 429 冷却截止时间（收到 429 后冷却）
    rate_limit_cooldown_until: Option<Instant>,
    /// 凭据级 429 冷却时长（秒），None 表示跟随全局
    rate_limit_cooldown_secs_override: Option<u64>,
}

/// 禁用原因
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DisabledReason {
    /// Admin API 手动禁用
    Manual,
    /// 连续失败达到阈值后自动禁用
    TooManyFailures,
    /// Token 刷新连续失败达到阈值后自动禁用
    TooManyRefreshFailures,
    /// 额度已用尽（如 MONTHLY_REQUEST_COUNT）
    QuotaExceeded,
    /// Refresh Token 永久失效（服务端返回 invalid_grant）
    InvalidRefreshToken,
    /// 凭据配置无效（如 authMethod=api_key 但缺少 kiroApiKey）
    InvalidConfig,
}

impl DisabledReason {
    fn as_str(self) -> &'static str {
        match self {
            DisabledReason::Manual => "Manual",
            DisabledReason::TooManyFailures => "TooManyFailures",
            DisabledReason::TooManyRefreshFailures => "TooManyRefreshFailures",
            DisabledReason::QuotaExceeded => "QuotaExceeded",
            DisabledReason::InvalidRefreshToken => "InvalidRefreshToken",
            DisabledReason::InvalidConfig => "InvalidConfig",
        }
    }

    /// 从凭据文件中持久化的字符串还原；缺失或未知值按手动禁用处理（与旧版本行为一致）
    fn from_persisted(value: Option<&str>) -> Self {
        match value {
            Some("TooManyFailures") => DisabledReason::TooManyFailures,
            Some("TooManyRefreshFailures") => DisabledReason::TooManyRefreshFailures,
            Some("QuotaExceeded") => DisabledReason::QuotaExceeded,
            Some("InvalidRefreshToken") => DisabledReason::InvalidRefreshToken,
            Some("InvalidConfig") => DisabledReason::InvalidConfig,
            _ => DisabledReason::Manual,
        }
    }
}

/// 统计数据持久化条目
#[derive(Serialize, Deserialize)]
struct StatsEntry {
    success_count: u64,
    last_used_at: Option<String>,
}

// ============================================================================
// Admin API 公开结构
// ============================================================================

/// 凭据条目快照（用于 Admin API 读取）
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialEntrySnapshot {
    /// 凭据唯一 ID
    pub id: u64,
    /// 优先级
    pub priority: u32,
    /// 是否被禁用
    pub disabled: bool,
    /// 连续失败次数
    pub failure_count: u32,
    /// 认证方式
    pub auth_method: Option<String>,
    /// 是否有 Profile ARN
    pub has_profile_arn: bool,
    /// Token 过期时间
    pub expires_at: Option<String>,
    /// refreshToken 的 SHA-256 哈希（仅 OAuth 凭据，用于前端去重）
    pub refresh_token_hash: Option<String>,
    /// kiroApiKey 的 SHA-256 哈希（仅 API Key 凭据，用于前端去重）
    pub api_key_hash: Option<String>,
    /// kiroApiKey 的脱敏展示（仅 API Key 凭据，用于前端显示）
    pub masked_api_key: Option<String>,
    /// 用户邮箱（用于前端显示）
    pub email: Option<String>,
    /// API 调用成功次数
    pub success_count: u64,
    /// 最后一次 API 调用时间（RFC3339 格式）
    pub last_used_at: Option<String>,
    /// 是否配置了凭据级代理
    pub has_proxy: bool,
    /// 代理 URL（用于前端展示）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxy_url: Option<String>,
    /// Token 刷新连续失败次数
    pub refresh_failure_count: u32,
    /// 禁用原因
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disabled_reason: Option<String>,
    /// 端点名称（未显式配置时返回 None，由 Admin 层回退到默认值）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    /// 凭据级冷却限流开关
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cooldown_enabled: Option<bool>,
    /// 凭据级冷却窗口时长（秒）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cooldown_seconds: Option<u64>,
    /// 凭据级冷却窗口内最大请求数
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cooldown_max_requests: Option<u32>,
    /// 该凭据最近 60 秒请求数
    pub rpm: usize,
    /// 最后一次 API 请求的 TTFB（毫秒）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_ttfb_ms: Option<u64>,
    /// 429 限流累计次数
    pub rate_limit_count: u64,
    /// 是否处于 429 冷却中
    pub rate_limit_cooling: bool,
}

/// 凭据管理器状态快照
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ManagerSnapshot {
    /// 凭据条目列表
    pub entries: Vec<CredentialEntrySnapshot>,
    /// 当前活跃凭据 ID
    pub current_id: u64,
    /// 总凭据数量
    pub total: usize,
    /// 可用凭据数量
    pub available: usize,
    /// 最近 60 秒请求数
    pub rpm: usize,
    /// 全局冷却限流是否启用
    pub cooldown_enabled: bool,
    /// 全局冷却窗口时长（秒）
    pub cooldown_seconds: u64,
    /// 全局冷却窗口内最大请求数
    pub cooldown_max_requests: u32,
}

/// 多凭据 Token 管理器
///
/// 超额开启操作结果
#[derive(Debug, Clone, serde::Serialize)]
pub struct OverageResult {
    pub id: u64,
    pub status: String,
    pub message: String,
}

/// 支持多个凭据的管理，实现固定优先级 + 故障转移策略
/// 故障统计基于 API 调用结果，而非 Token 刷新结果
pub struct MultiTokenManager {
    config: Config,
    proxy: Option<ProxyConfig>,
    /// 凭据条目列表
    entries: Mutex<Vec<CredentialEntry>>,
    /// 当前活动凭据 ID
    current_id: Mutex<u64>,
    /// Token 刷新锁，确保同一时间只有一个刷新操作
    refresh_lock: TokioMutex<()>,
    /// 凭据文件路径（用于回写）
    credentials_path: Option<PathBuf>,
    /// 是否为多凭据格式（显式新增凭据成功后会升级旧格式）
    is_multiple_format: AtomicBool,
    /// 负载均衡模式（运行时可修改）
    load_balancing_mode: Mutex<String>,
    /// 全局冷却限流配置（运行时可修改）
    cooldown_enabled: Mutex<bool>,
    cooldown_seconds: Mutex<u64>,
    cooldown_max_requests: Mutex<u32>,
    /// 缓存 token 估算倍率（运行时可修改）
    cache_ratio_creation: Mutex<f64>,
    cache_ratio_read: Mutex<f64>,
    cache_ratio_uncached: Mutex<f64>,
    cache_ratio_first_turn: Mutex<f64>,
    /// 输出 token 估算倍率（运行时可修改）
    cache_ratio_output: Mutex<f64>,
    /// 缓存模式（"fixed" 或 "standard"，运行时可修改）
    cache_mode: Mutex<String>,
    /// 固定模式间歇中断开关
    cache_interrupt_enabled: Mutex<bool>,
    /// 间歇中断最小间隔（秒）
    cache_interrupt_min_secs: Mutex<u64>,
    /// 间歇中断最大间隔（秒）
    cache_interrupt_max_secs: Mutex<u64>,
    /// 间歇中断持续时长（秒）
    cache_interrupt_duration_secs: Mutex<u64>,
    /// 下一次中断开始时刻
    cache_interrupt_next: Mutex<Instant>,
    /// 当前是否处于中断期
    cache_interrupt_active: Mutex<bool>,
    /// 中断期结束时刻
    cache_interrupt_end: Mutex<Instant>,
    /// 标准模式下的逐条前缀哈希缓存（每个 hash → last_seen_time）
    cache_prefix_map: Mutex<HashMap<u64, Instant>>,
    /// 上次清理过期缓存条目的时间
    cache_last_cleanup: Mutex<Instant>,
    /// 模型映射（运行时可修改）
    model_mappings: Mutex<Vec<crate::model::config::ModelMapping>>,
    /// Free 账号的模型映射（运行时可修改）
    free_model_mappings: Mutex<Vec<crate::model::config::ModelMapping>>,
    /// 最近一次统计持久化时间（用于 debounce）
    last_stats_save_at: Mutex<Option<Instant>>,
    /// 统计数据是否有未落盘更新
    stats_dirty: AtomicBool,
    /// 最近 60 秒的请求时间戳（用于计算 RPM）
    request_timestamps: Mutex<VecDeque<Instant>>,
    /// 429 冷却时长（秒，运行时可修改）
    rate_limit_cooldown_secs: Mutex<u64>,
}

/// 每个凭据最大 API 调用失败次数
const MAX_FAILURES_PER_CREDENTIAL: u32 = 3;
/// 统计数据持久化防抖间隔
const STATS_SAVE_DEBOUNCE: StdDuration = StdDuration::from_secs(60);
/// 候选凭据全部处于 429 冷却时，单次请求愿意等待的最长时间
const MAX_RATE_LIMIT_WAIT: StdDuration = StdDuration::from_secs(60);

/// Token 刷新瞬态错误的退避时长（指数退避，上限 4 秒）
fn refresh_retry_delay(attempt: usize) -> StdDuration {
    const BASE_MS: u64 = 500;
    const MAX_MS: u64 = 4_000;
    let exp = BASE_MS.saturating_mul(2u64.saturating_pow(attempt.saturating_sub(1).min(4) as u32));
    StdDuration::from_millis(exp.min(MAX_MS))
}
/// 缓存中断持续时长
/// 在 [min, max] 秒范围内生成随机间隔
fn random_interrupt_delay(min_secs: u64, max_secs: u64) -> StdDuration {
    let secs = if min_secs >= max_secs {
        min_secs
    } else {
        fastrand::u64(min_secs..=max_secs)
    };
    capped_duration_secs(secs)
}

/// 凭据选择结果
enum SelectResult {
    /// 选中一个已冷却的凭据
    Ready(u64, KiroCredentials),
    /// 所有可用凭据都在冷却中，附带最早可用时刻
    CooldownUntil(Instant),
    /// 候选凭据全部处于 429 限流冷却中，附带最早解除冷却的时刻
    RateLimitedUntil(Instant),
    /// 无可用凭据（全部 disabled）
    None,
}

/// 禁用指定凭据并切换到优先级最高的可用凭据（在已持有 entries + current_id 锁时调用）
///
/// 返回是否还有可用凭据
fn disable_entry_and_switch(
    entries: &mut Vec<CredentialEntry>,
    current_id: &mut u64,
    id: u64,
    reason: DisabledReason,
) -> bool {
    if let Some(entry) = entries.iter_mut().find(|e| e.id == id) {
        entry.disabled = true;
        entry.disabled_reason = Some(reason);
    }

    if let Some(next) = entries
        .iter()
        .filter(|e| !e.disabled)
        .min_by_key(|e| e.credentials.priority)
    {
        *current_id = next.id;
        tracing::info!(
            "已切换到凭据 #{}（优先级 {}）",
            next.id,
            next.credentials.priority
        );
        true
    } else {
        tracing::error!("所有凭据均已禁用！");
        false
    }
}

/// API 调用上下文
///
/// 绑定特定凭据的调用上下文，确保 token、credentials 和 id 的一致性
/// 用于解决并发调用时 current_id 竞态问题
#[derive(Clone)]
pub struct CallContext {
    /// 凭据 ID（用于 report_success/report_failure）
    pub id: u64,
    /// 凭据信息（用于构建请求头）
    pub credentials: KiroCredentials,
    /// 访问 Token
    pub token: String,
}

impl MultiTokenManager {
    /// 创建多凭据 Token 管理器
    ///
    /// # Arguments
    /// * `config` - 应用配置
    /// * `credentials` - 凭据列表
    /// * `proxy` - 可选的代理配置
    /// * `credentials_path` - 凭据文件路径（用于回写）
    /// * `is_multiple_format` - 是否为多凭据格式（新增凭据时会将旧格式升级为数组）
    pub fn new(
        config: Config,
        credentials: Vec<KiroCredentials>,
        proxy: Option<ProxyConfig>,
        credentials_path: Option<PathBuf>,
        is_multiple_format: bool,
    ) -> anyhow::Result<Self> {
        // 计算当前最大 ID，为没有 ID 的凭据分配新 ID
        let max_existing_id = credentials.iter().filter_map(|c| c.id).max().unwrap_or(0);
        let mut next_id = max_existing_id + 1;
        let mut has_new_ids = false;
        let mut has_new_machine_ids = false;
        let config_ref = &config;

        let entries: Vec<CredentialEntry> = credentials
            .into_iter()
            .map(|mut cred| {
                cred.canonicalize_auth_method();
                let id = cred.id.unwrap_or_else(|| {
                    let id = next_id;
                    next_id += 1;
                    cred.id = Some(id);
                    has_new_ids = true;
                    id
                });
                if cred.machine_id.is_none() {
                    cred.machine_id =
                        Some(machine_id::generate_from_credentials(&cred, config_ref));
                    has_new_machine_ids = true;
                }
                CredentialEntry {
                    id,
                    credentials: cred.clone(),
                    failure_count: 0,
                    refresh_failure_count: 0,
                    disabled: cred.disabled,
                    // 还原持久化的禁用原因，保证重启后 TooManyFailures 仍可自愈
                    disabled_reason: if cred.disabled {
                        Some(DisabledReason::from_persisted(cred.disabled_reason.as_deref()))
                    } else {
                        None
                    },
                    success_count: 0,
                    last_used_at: None,
                    dispatch_history: VecDeque::new(),
                    last_ttfb_ms: None,
                    rate_limit_count: 0,
                    rate_limit_cooldown_until: None,
                    rate_limit_cooldown_secs_override: None,
                }
            })
            .collect();

        // 校验 API Key 凭据配置完整性：authMethod=api_key 时必须提供 kiroApiKey
        let mut entries = entries;
        for entry in &mut entries {
            if entry.credentials.kiro_api_key.is_none()
                && entry
                    .credentials
                    .auth_method
                    .as_deref()
                    .map(|m| m.eq_ignore_ascii_case("api_key") || m.eq_ignore_ascii_case("apikey"))
                    .unwrap_or(false)
            {
                tracing::warn!(
                    "凭据 #{} 配置了 authMethod=api_key 但缺少 kiroApiKey 字段，已自动禁用",
                    entry.id
                );
                entry.disabled = true;
                entry.disabled_reason = Some(DisabledReason::InvalidConfig);
            }
        }

        // 检测重复 ID
        let mut seen_ids = std::collections::HashSet::new();
        let mut duplicate_ids = Vec::new();
        for entry in &entries {
            if !seen_ids.insert(entry.id) {
                duplicate_ids.push(entry.id);
            }
        }
        if !duplicate_ids.is_empty() {
            anyhow::bail!("检测到重复的凭据 ID: {:?}", duplicate_ids);
        }

        // 选择初始凭据：优先级最高（priority 最小）的可用凭据，无可用凭据时为 0
        let initial_id = entries
            .iter()
            .filter(|e| !e.disabled)
            .min_by_key(|e| e.credentials.priority)
            .map(|e| e.id)
            .unwrap_or(0);

        let load_balancing_mode = config.load_balancing_mode.clone();
        let cooldown_enabled = config.cooldown_enabled;
        let cooldown_seconds = config.cooldown_seconds;
        let cooldown_max_requests = config.cooldown_max_requests;
        let cache_ratio_creation = config.cache_ratio_creation;
        let cache_ratio_read = config.cache_ratio_read;
        let cache_ratio_uncached = config.cache_ratio_uncached;
        let cache_ratio_first_turn = config.cache_ratio_first_turn;
        let cache_ratio_output = config.cache_ratio_output;
        let cache_mode = config.cache_mode.clone();
        let cache_interrupt_enabled = config.cache_interrupt_enabled;
        let cache_interrupt_min_secs = config.cache_interrupt_min_secs;
        let cache_interrupt_max_secs = config.cache_interrupt_max_secs;
        let cache_interrupt_duration_secs = config.cache_interrupt_duration_secs;
        let model_mappings = config.model_mappings.clone();
        let free_model_mappings = config.free_model_mappings.clone();
        let rate_limit_cooldown_secs = config.rate_limit_cooldown_secs;
        let initial_interrupt_delay = random_interrupt_delay(cache_interrupt_min_secs, cache_interrupt_max_secs);
        let manager = Self {
            config,
            proxy,
            entries: Mutex::new(entries),
            current_id: Mutex::new(initial_id),
            refresh_lock: TokioMutex::new(()),
            credentials_path,
            is_multiple_format: AtomicBool::new(is_multiple_format),
            load_balancing_mode: Mutex::new(load_balancing_mode),
            cooldown_enabled: Mutex::new(cooldown_enabled),
            cooldown_seconds: Mutex::new(cooldown_seconds),
            cooldown_max_requests: Mutex::new(cooldown_max_requests),
            cache_ratio_creation: Mutex::new(cache_ratio_creation),
            cache_ratio_read: Mutex::new(cache_ratio_read),
            cache_ratio_uncached: Mutex::new(cache_ratio_uncached),
            cache_ratio_first_turn: Mutex::new(cache_ratio_first_turn),
            cache_ratio_output: Mutex::new(cache_ratio_output),
            cache_mode: Mutex::new(cache_mode),
            cache_interrupt_enabled: Mutex::new(cache_interrupt_enabled),
            cache_interrupt_min_secs: Mutex::new(cache_interrupt_min_secs),
            cache_interrupt_max_secs: Mutex::new(cache_interrupt_max_secs),
            cache_interrupt_duration_secs: Mutex::new(cache_interrupt_duration_secs),
            cache_interrupt_next: Mutex::new(Instant::now() + initial_interrupt_delay),
            cache_interrupt_active: Mutex::new(false),
            cache_interrupt_end: Mutex::new(Instant::now()),
            cache_prefix_map: Mutex::new(HashMap::new()),
            cache_last_cleanup: Mutex::new(Instant::now()),
            model_mappings: Mutex::new(model_mappings),
            free_model_mappings: Mutex::new(free_model_mappings),
            last_stats_save_at: Mutex::new(None),
            stats_dirty: AtomicBool::new(false),
            request_timestamps: Mutex::new(VecDeque::new()),
            rate_limit_cooldown_secs: Mutex::new(rate_limit_cooldown_secs),
        };

        // 如果有新分配的 ID 或新生成的 machineId，立即持久化到配置文件
        if has_new_ids || has_new_machine_ids {
            if let Err(e) = manager.persist_credentials() {
                tracing::warn!("补全凭据 ID/machineId 后持久化失败: {}", e);
            } else {
                tracing::info!("已补全凭据 ID/machineId 并写回配置文件");
            }
        }

        // 加载持久化的统计数据（success_count, last_used_at）
        manager.load_stats();

        Ok(manager)
    }

    /// 获取配置的引用
    pub fn config(&self) -> &Config {
        &self.config
    }

    pub fn proxy(&self) -> Option<ProxyConfig> {
        self.proxy.clone()
    }

    /// 获取凭据总数
    pub fn total_count(&self) -> usize {
        self.entries.lock().len()
    }

    /// 获取可用凭据数量
    pub fn available_count(&self) -> usize {
        self.entries.lock().iter().filter(|e| !e.disabled).count()
    }

    /// 尝试自愈：当所有凭据因连续失败被自动禁用时，重置并重新启用
    ///
    /// 仅对 `TooManyFailures` 执行自愈（等价于重启），
    /// `QuotaExceeded`/`InvalidRefreshToken`/`TooManyRefreshFailures` 等不可自愈。
    fn try_self_heal(&self) -> bool {
        let mut entries = self.entries.lock();
        let has_auto_disabled = entries
            .iter()
            .any(|e| e.disabled && e.disabled_reason == Some(DisabledReason::TooManyFailures));

        if !has_auto_disabled {
            return false;
        }

        tracing::warn!(
            "所有凭据均已被自动禁用，执行自愈：重置失败计数并重新启用（等价于重启）"
        );
        for e in entries.iter_mut() {
            if e.disabled_reason == Some(DisabledReason::TooManyFailures) {
                e.disabled = false;
                e.disabled_reason = None;
                e.failure_count = 0;
            }
        }
        // 自愈结果也要落盘，否则重启后又会读回禁用状态
        if let Err(e) = self.persist_credentials_locked(&entries, false) {
            tracing::warn!("自愈后持久化凭据失败（重启后可能恢复为禁用）: {}", e);
        }
        true
    }

    /// 计算指定凭据的有效冷却配置
    ///
    /// 优先级：凭据级开关 > 全局开关 > 不限流
    /// 返回 Some((窗口时长, 最大请求数)) 或 None（不限流）
    fn effective_cooldown(&self, cred: &KiroCredentials) -> Option<(StdDuration, u32)> {
        let global_enabled = *self.cooldown_enabled.lock();
        let global_seconds = *self.cooldown_seconds.lock();
        let global_max = *self.cooldown_max_requests.lock();

        // 最大请求数为 0 时视为不限流（否则 earliest_available 会下标越界），
        // 窗口时长截断到安全上限（防止 Instant + Duration 溢出）
        let normalize = |secs: u64, max: u32| -> Option<(StdDuration, u32)> {
            if max == 0 || secs == 0 {
                None
            } else {
                Some((capped_duration_secs(secs), max))
            }
        };

        match cred.cooldown_enabled {
            Some(true) => {
                let secs = cred.cooldown_seconds.unwrap_or(global_seconds);
                let max = cred.cooldown_max_requests.unwrap_or(global_max);
                normalize(secs, max)
            }
            Some(false) => None,
            None => {
                if global_enabled {
                    normalize(global_seconds, global_max)
                } else {
                    None
                }
            }
        }
    }

    /// 检查凭据是否已冷却（可接受新请求）
    ///
    /// 返回 true 表示可用，false 表示仍在冷却中
    fn is_cooled(
        history: &VecDeque<Instant>,
        now: Instant,
        window: StdDuration,
        max_requests: u32,
    ) -> bool {
        let count = history.iter().filter(|&&t| now.duration_since(t) < window).count();
        (count as u32) < max_requests
    }

    /// 计算凭据的剩余吞吐容量（requests per second）
    /// 值越大说明可用容量越充裕，应该被优先选中
    fn calc_remaining_capacity(&self, entry: &CredentialEntry, now: Instant) -> f64 {
        match self.effective_cooldown(&entry.credentials) {
            Some((window, max_req)) => {
                let used = entry.dispatch_history.iter()
                    .filter(|&&t| now.duration_since(t) < window)
                    .count() as f64;
                let remaining = (max_req as f64) - used;
                let window_secs = window.as_secs_f64();
                if window_secs > 0.0 { remaining / window_secs } else { remaining }
            }
            None => {
                // 无限流凭据，容量视为极大
                f64::MAX
            }
        }
    }

    /// 计算凭据最早可用时刻
    fn earliest_available(
        history: &VecDeque<Instant>,
        now: Instant,
        window: StdDuration,
        max_requests: u32,
    ) -> Instant {
        // 窗口内的请求按时间排序（VecDeque 本身是按插入顺序排列的）
        let in_window: Vec<Instant> = history
            .iter()
            .filter(|&&t| now.duration_since(t) < window)
            .copied()
            .collect();

        if max_requests == 0 || (in_window.len() as u32) < max_requests {
            return now; // 已经可用（max_requests 为 0 视为不限流）
        }

        // 最早的请求过期后即可腾出一个位置
        // 需要找到第 (len - max_requests + 1) 早的时间戳（排序后从旧到新取第一个需要等待过期的）
        let mut sorted = in_window;
        sorted.sort();
        let wait_idx = sorted.len() - max_requests as usize;
        sorted[wait_idx]
            .checked_add(window)
            .unwrap_or_else(|| now + capped_duration_secs(MAX_CONFIG_DURATION_SECS))
    }

    /// 根据负载均衡模式选择下一个凭据
    ///
    /// - priority 模式：选择优先级最高（priority 最小）的可用凭据
    /// - balanced 模式：均衡选择可用凭据
    ///
    /// # 参数
    /// - `model`: 客户端原始模型名称，Free 使用专属映射，其他账号使用通用映射
    fn select_next_credential(&self, model: Option<&str>) -> SelectResult {
        let regular_model_supported = model.is_none_or(|m| self.resolve_model(m).is_some());
        let mut entries = self.entries.lock();
        let now = Instant::now();
        let free_model_mappings = self.free_model_mappings.lock().clone();

        // 过滤可用凭据索引（未禁用 + 模型匹配 + 不在 429 冷却中）
        // 同时记录"仅因 429 冷却被跳过"的凭据中最早解除冷却的时刻
        let mut earliest_rate_limit_end: Option<Instant> = None;
        let available_indices: Vec<usize> = entries
            .iter()
            .enumerate()
            .filter(|(_, e)| {
                if e.disabled {
                    return false;
                }
                // 模型兼容性检查（Free 账号只支持 free_model_mappings 中配置的模型）
                if let Some(m) = model {
                    if !e.credentials.supports_model(m, &free_model_mappings)
                        || (!e.credentials.is_free() && !regular_model_supported)
                    {
                        return false;
                    }
                }
                // 429 冷却中跳过
                if let Some(until) = e.rate_limit_cooldown_until {
                    if now < until {
                        earliest_rate_limit_end =
                            Some(earliest_rate_limit_end.map_or(until, |t| t.min(until)));
                        return false;
                    }
                }
                true
            })
            .map(|(i, _)| i)
            .collect();

        if available_indices.is_empty() {
            // 候选凭据全部处于 429 冷却：等待冷却结束，而不是当作"无可用凭据"立即失败
            if let Some(until) = earliest_rate_limit_end {
                return SelectResult::RateLimitedUntil(until);
            }
            return SelectResult::None;
        }

        // 在可用凭据中筛选已冷却的
        let cooled_indices: Vec<usize> = available_indices
            .iter()
            .filter(|&&i| {
                match self.effective_cooldown(&entries[i].credentials) {
                    None => true, // 不限流，始终可用
                    Some((window, max_req)) => {
                        Self::is_cooled(&entries[i].dispatch_history, now, window, max_req)
                    }
                }
            })
            .copied()
            .collect();

        if cooled_indices.is_empty() {
            // 所有可用凭据都在冷却中，找最早冷却完毕的时刻
            let earliest = available_indices
                .iter()
                .filter_map(|&i| {
                    self.effective_cooldown(&entries[i].credentials).map(|(window, max_req)| {
                        Self::earliest_available(&entries[i].dispatch_history, now, window, max_req)
                    })
                })
                .min()
                .unwrap_or(now);
            return SelectResult::CooldownUntil(earliest);
        }

        // Free 与付费账号平级，只按配置的优先级或均衡策略调度。
        let mode = self.load_balancing_mode.lock().clone();
        let selected_idx = match mode.as_str() {
            "balanced" => {
                // 按剩余吞吐容量选择：容量越大越优先
                // 容量相等时，选最久没使用的（轮流分配）
                *cooled_indices
                    .iter()
                    .max_by(|&&a, &&b| {
                        let cap_a = self.calc_remaining_capacity(&entries[a], now);
                        let cap_b = self.calc_remaining_capacity(&entries[b], now);
                        let cmp = cap_a.partial_cmp(&cap_b).unwrap_or(std::cmp::Ordering::Equal);
                        if cmp == std::cmp::Ordering::Equal {
                            // 容量相等时，最久没用的优先
                            let last_a = entries[a].dispatch_history.back().copied();
                            let last_b = entries[b].dispatch_history.back().copied();
                            match (last_a, last_b) {
                                (None, Some(_)) => std::cmp::Ordering::Greater, // a 从没用过，优先
                                (Some(_), None) => std::cmp::Ordering::Less,    // b 从没用过，b 优先
                                (None, None) => std::cmp::Ordering::Equal,
                                (Some(ta), Some(tb)) => tb.cmp(&ta), // b 用得晚，a 优先
                            }
                        } else {
                            cmp
                        }
                    })
                    .unwrap()
            }
            _ => {
                *cooled_indices
                    .iter()
                    .min_by_key(|&&i| entries[i].credentials.priority)
                    .unwrap()
            }
        };

        let entry = &mut entries[selected_idx];
        entry.success_count += 1;
        entry.last_used_at = Some(Utc::now().to_rfc3339());
        match self.effective_cooldown(&entry.credentials) {
            Some((window, _)) => {
                entry.dispatch_history.push_back(now);
                while let Some(&front) = entry.dispatch_history.front() {
                    if now.duration_since(front) >= window {
                        entry.dispatch_history.pop_front();
                    } else {
                        break;
                    }
                }
            }
            None => {
                // 无限流时也保留 dispatch_history 用于 RPM 统计（只保留最近 60 秒）
                entry.dispatch_history.push_back(now);
                let cutoff = StdDuration::from_secs(60);
                while let Some(&front) = entry.dispatch_history.front() {
                    if now.duration_since(front) >= cutoff {
                        entry.dispatch_history.pop_front();
                    } else {
                        break;
                    }
                }
            }
        }

        SelectResult::Ready(entry.id, entry.credentials.clone())
    }

    /// 获取 API 调用上下文
    ///
    /// 返回绑定了 id、credentials 和 token 的调用上下文
    /// 确保整个 API 调用过程中使用一致的凭据信息
    ///
    /// 如果 Token 过期或即将过期，会自动刷新
    /// Token 刷新失败会累计到当前凭据，达到阈值后禁用并切换
    ///
    /// # 参数
    /// - `model`: 客户端原始模型名称，Free 使用专属映射，其他账号使用通用映射
    pub async fn acquire_context(&self, model: Option<&str>) -> anyhow::Result<CallContext> {
        let total = self.total_count();
        let max_attempts = (total * MAX_FAILURES_PER_CREDENTIAL as usize).max(1);
        let mut attempt_count = 0;

        loop {
            if attempt_count >= max_attempts {
                anyhow::bail!(
                    "所有凭据均无法获取有效 Token（可用: {}/{}）",
                    self.available_count(),
                    total
                );
            }

            let (id, credentials) = {
                // 每次按当前模型及冷却状态重新比较所有候选，避免低优先级账号一直被复用。
                match self.select_next_credential(model) {
                    SelectResult::Ready(new_id, new_creds) => {
                        *self.current_id.lock() = new_id;
                        (new_id, new_creds)
                    }
                    SelectResult::CooldownUntil(wake_at) => {
                        let wait = wake_at.saturating_duration_since(Instant::now());
                        tokio::time::sleep(wait).await;
                        continue;
                    }
                    SelectResult::RateLimitedUntil(wake_at) => {
                        // 429 只退避不切换：在上限内等待冷却结束，超出上限才报错
                        let wait = wake_at.saturating_duration_since(Instant::now());
                        if wait > MAX_RATE_LIMIT_WAIT {
                            anyhow::bail!(
                                "所有候选凭据均处于 429 限流冷却中，约 {}s 后恢复",
                                wait.as_secs()
                            );
                        }
                        tracing::info!(
                            "所有候选凭据均处于 429 冷却中，等待 {}ms 后重试",
                            wait.as_millis()
                        );
                        tokio::time::sleep(wait).await;
                        continue;
                    }
                    SelectResult::None => {
                        if self.try_self_heal() {
                            continue;
                        }
                        let entries = self.entries.lock();
                        let available = entries.iter().filter(|e| !e.disabled).count();
                        if available > 0 {
                            if let Some(model) = model {
                                anyhow::bail!(
                                    "没有支持请求模型 {model} 的可用凭据（其余凭据可能处于冷却中）"
                                );
                            }
                        }
                        anyhow::bail!("所有凭据均已禁用（{}/{}）", available, total);
                    }
                }
            };

            // 尝试获取/刷新 Token
            match self.try_ensure_token(id, &credentials).await {
                Ok(ctx) => {
                    self.save_stats_debounced();
                    return Ok(ctx);
                }
                Err(e) => {
                    // 瞬态错误（网络抖动、上游 429/5xx）：不计入刷新失败，退避后重试，
                    // 避免一次网络抖动就把凭据（乃至整个池）永久禁用
                    // 按普通失败计数（TooManyFailures 可自愈），持续失败的凭据仍能被故障转移
                    if e.downcast_ref::<TransientRefreshError>().is_some() {
                        tracing::warn!("凭据 #{} Token 刷新遇到瞬态错误，退避后重试: {}", id, e);
                        self.report_failure(id);
                        attempt_count += 1;
                        tokio::time::sleep(refresh_retry_delay(attempt_count)).await;
                        continue;
                    }

                    // refreshToken 永久失效 → 立即禁用，不累计重试
                    let has_available =
                        if e.downcast_ref::<RefreshTokenInvalidError>().is_some() {
                            tracing::warn!("凭据 #{} refreshToken 永久失效: {}", id, e);
                            self.report_refresh_token_invalid(id)
                        } else {
                            tracing::warn!("凭据 #{} Token 刷新失败: {}", id, e);
                            self.report_refresh_failure(id)
                        };
                    attempt_count += 1;
                    if !has_available {
                        anyhow::bail!("所有凭据均已禁用（0/{}）", total);
                    }
                }
            }
        }
    }

    /// 选择优先级最高的未禁用凭据作为当前凭据（内部方法）
    ///
    /// 纯粹按优先级选择，不排除当前凭据，用于优先级变更后立即生效
    fn select_highest_priority(&self) {
        let entries = self.entries.lock();
        let mut current_id = self.current_id.lock();

        // 选择优先级最高的未禁用凭据（不排除当前凭据）
        if let Some(best) = entries
            .iter()
            .filter(|e| !e.disabled)
            .min_by_key(|e| e.credentials.priority)
        {
            if best.id != *current_id {
                tracing::info!(
                    "优先级变更后切换凭据: #{} -> #{}（优先级 {}）",
                    *current_id,
                    best.id,
                    best.credentials.priority
                );
                *current_id = best.id;
            }
        }
    }

    /// 尝试使用指定凭据获取有效 Token
    ///
    /// 使用双重检查锁定模式，确保同一时间只有一个刷新操作
    ///
    /// # Arguments
    /// * `id` - 凭据 ID，用于更新正确的条目
    /// * `credentials` - 凭据信息
    async fn try_ensure_token(
        &self,
        id: u64,
        credentials: &KiroCredentials,
    ) -> anyhow::Result<CallContext> {
        // API Key 凭据直接使用 kiro_api_key 作为 Bearer Token，无需刷新
        if credentials.is_api_key_credential() {
            let token = credentials
                .kiro_api_key
                .clone()
                .ok_or_else(|| anyhow::anyhow!("API Key 凭据缺少 kiroApiKey"))?;
            return Ok(CallContext {
                id,
                credentials: credentials.clone(),
                token,
            });
        }

        // 第一次检查（无锁）：快速判断是否需要刷新
        let needs_refresh = is_token_expired(credentials) || is_token_expiring_soon(credentials);

        let creds = if needs_refresh {
            // 获取刷新锁，确保同一时间只有一个刷新操作
            let _guard = self.refresh_lock.lock().await;

            // 第二次检查：获取锁后重新读取凭据，因为其他请求可能已经完成刷新
            let current_creds = {
                let entries = self.entries.lock();
                entries
                    .iter()
                    .find(|e| e.id == id)
                    .map(|e| e.credentials.clone())
                    .ok_or_else(|| anyhow::anyhow!("凭据 #{} 不存在", id))?
            };

            if is_token_expired(&current_creds) || is_token_expiring_soon(&current_creds) {
                // 确实需要刷新
                let effective_proxy = current_creds.effective_proxy(self.proxy.as_ref());
                let new_creds =
                    refresh_token(&current_creds, &self.config, effective_proxy.as_ref()).await?;

                if is_token_expired(&new_creds) {
                    anyhow::bail!("刷新后的 Token 仍然无效或已过期");
                }

                // 只合并刷新得到的 token 字段，避免覆盖刷新期间 Admin 等写入的其他字段
                let merged = {
                    let mut entries = self.entries.lock();
                    match entries.iter_mut().find(|e| e.id == id) {
                        Some(entry) => {
                            apply_refreshed_tokens(&mut entry.credentials, &current_creds, &new_creds);
                            entry.credentials.clone()
                        }
                        None => new_creds,
                    }
                };

                // 回写凭据到文件（仅多凭据格式），失败只记录警告
                if let Err(e) = self.persist_credentials() {
                    tracing::warn!("Token 刷新后持久化失败（不影响本次请求）: {}", e);
                }

                merged
            } else {
                // 其他请求已经完成刷新，直接使用新凭据
                tracing::debug!("Token 已被其他请求刷新，跳过刷新");
                current_creds
            }
        } else {
            credentials.clone()
        };

        let token = creds
            .access_token
            .clone()
            .ok_or_else(|| anyhow::anyhow!("没有可用的 accessToken"))?;

        {
            let mut entries = self.entries.lock();
            if let Some(entry) = entries.iter_mut().find(|e| e.id == id) {
                entry.refresh_failure_count = 0;
            }
        }

        Ok(CallContext {
            id,
            credentials: creds,
            token,
        })
    }

    /// 将凭据列表回写到源文件
    ///
    /// 仅在以下条件满足时回写：
    /// - 源文件是多凭据格式（数组）
    /// - credentials_path 已设置
    ///
    /// # Returns
    /// - `Ok(true)` - 成功写入文件
    /// - `Ok(false)` - 跳过写入（非多凭据格式或无路径配置）
    /// - `Err(_)` - 写入失败
    fn persist_credentials(&self) -> anyhow::Result<bool> {
        let entries = self.entries.lock();
        self.persist_credentials_locked(&entries, false)
    }

    /// 调用方须持有 entries 锁，保证写盘顺序与内存更新一致。
    /// 显式新增凭据时允许将旧版单对象配置升级为数组，成功后继续按数组回写。
    fn persist_credentials_locked(
        &self,
        entries: &[CredentialEntry],
        allow_format_upgrade: bool,
    ) -> anyhow::Result<bool> {
        use anyhow::Context;

        if !self.is_multiple_format.load(Ordering::Relaxed) && !allow_format_upgrade {
            return Ok(false);
        }

        let path = match &self.credentials_path {
            Some(p) => p,
            None => return Ok(false),
        };

        // 收集所有凭据
        let credentials: Vec<KiroCredentials> = entries
            .iter()
            .map(|e| {
                let mut cred = e.credentials.clone();
                cred.canonicalize_auth_method();
                // 同步 disabled 状态及原因到凭据对象（原因决定重启后能否自愈）
                cred.disabled = e.disabled;
                cred.disabled_reason = if e.disabled {
                    e.disabled_reason.map(|r| r.as_str().to_string())
                } else {
                    None
                };
                cred
            })
            .collect();

        // 序列化为 pretty JSON
        let json = serde_json::to_string_pretty(&credentials).context("序列化凭据失败")?;

        // 写入文件（在 Tokio runtime 内使用 block_in_place 避免阻塞 worker）
        // 原子写入：中途崩溃不会截断凭据文件（refreshToken 轮换后旧值已作废，丢失即不可恢复）
        if tokio::runtime::Handle::try_current().is_ok() {
            tokio::task::block_in_place(|| write_atomic(path, &json))
                .with_context(|| format!("回写凭据文件失败: {:?}", path))?;
        } else {
            write_atomic(path, &json).with_context(|| format!("回写凭据文件失败: {:?}", path))?;
        }

        self.is_multiple_format.store(true, Ordering::Relaxed);
        tracing::debug!("已回写凭据到文件: {:?}", path);
        Ok(true)
    }

    /// 持久化自动封禁状态到凭据文件（失败仅记录警告，不影响当前请求）
    ///
    /// 自动封禁（连续失败 / 额度耗尽 / 刷新失效等）在请求处理过程中触发，
    /// 必须落盘，否则重启后从文件加载会丢失封禁状态、被禁用的凭据又被启用。
    fn persist_disabled_state(&self) {
        if let Err(e) = self.persist_credentials() {
            tracing::warn!("自动封禁状态持久化失败（重启后可能丢失）: {}", e);
        }
    }

    /// 获取缓存目录（凭据文件所在目录）
    pub fn cache_dir(&self) -> Option<PathBuf> {
        self.credentials_path
            .as_ref()
            .and_then(|p| p.parent().map(|d| d.to_path_buf()))
    }

    /// 统计数据文件路径
    fn stats_path(&self) -> Option<PathBuf> {
        self.cache_dir().map(|d| d.join("kiro_stats.json"))
    }

    /// 从磁盘加载统计数据并应用到当前条目
    fn load_stats(&self) {
        let path = match self.stats_path() {
            Some(p) => p,
            None => return,
        };

        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => return, // 首次运行时文件不存在
        };

        let stats: HashMap<String, StatsEntry> = match serde_json::from_str(&content) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!("解析统计缓存失败，将忽略: {}", e);
                return;
            }
        };

        let mut entries = self.entries.lock();
        for entry in entries.iter_mut() {
            if let Some(s) = stats.get(&entry.id.to_string()) {
                entry.success_count = s.success_count;
                entry.last_used_at = s.last_used_at.clone();
            }
        }
        *self.last_stats_save_at.lock() = Some(Instant::now());
        self.stats_dirty.store(false, Ordering::Relaxed);
        tracing::info!("已从缓存加载 {} 条统计数据", stats.len());
    }

    /// 将当前统计数据持久化到磁盘
    fn save_stats(&self) {
        let path = match self.stats_path() {
            Some(p) => p,
            None => return,
        };

        let stats: HashMap<String, StatsEntry> = {
            let entries = self.entries.lock();
            entries
                .iter()
                .map(|e| {
                    (
                        e.id.to_string(),
                        StatsEntry {
                            success_count: e.success_count,
                            last_used_at: e.last_used_at.clone(),
                        },
                    )
                })
                .collect()
        };

        match serde_json::to_string_pretty(&stats) {
            Ok(json) => {
                if let Err(e) = write_atomic(&path, json) {
                    tracing::warn!("保存统计缓存失败: {}", e);
                } else {
                    self.stats_dirty.store(false, Ordering::Relaxed);
                }
                *self.last_stats_save_at.lock() = Some(Instant::now());
            }
            Err(e) => tracing::warn!("序列化统计数据失败: {}", e),
        }
    }

    /// 标记统计数据已更新，并按 debounce 策略决定是否立即落盘
    fn save_stats_debounced(&self) {
        self.stats_dirty.store(true, Ordering::Relaxed);

        let should_flush = {
            let last = *self.last_stats_save_at.lock();
            match last {
                Some(last_saved_at) => last_saved_at.elapsed() >= STATS_SAVE_DEBOUNCE,
                None => true,
            }
        };

        if should_flush {
            self.save_stats();
        }
    }

    /// 报告指定凭据 API 调用成功
    ///
    /// 重置该凭据的失败计数
    pub fn report_success(&self, id: u64) {
        {
            let mut entries = self.entries.lock();
            if let Some(entry) = entries.iter_mut().find(|e| e.id == id) {
                entry.failure_count = 0;
                entry.refresh_failure_count = 0;
                tracing::debug!(
                    "凭据 #{} API 调用成功（累计 {} 次）",
                    id,
                    entry.success_count
                );
            }
        }
        self.request_timestamps.lock().push_back(Instant::now());
        self.save_stats_debounced();
    }

    /// 记录指定凭据的 TTFB（首字节时间，毫秒）
    pub fn report_ttfb(&self, id: u64, ttfb_ms: u64) {
        let mut entries = self.entries.lock();
        if let Some(entry) = entries.iter_mut().find(|e| e.id == id) {
            entry.last_ttfb_ms = Some(ttfb_ms);
        }
    }

    /// 记录指定凭据收到 429 限流，并进入冷却
    pub fn report_rate_limit(&self, id: u64) {
        let global_cooldown_secs = *self.rate_limit_cooldown_secs.lock();
        let mut entries = self.entries.lock();
        if let Some(entry) = entries.iter_mut().find(|e| e.id == id) {
            let cooldown_secs = entry.rate_limit_cooldown_secs_override.unwrap_or(global_cooldown_secs);
            entry.rate_limit_count += 1;
            entry.rate_limit_cooldown_until = Some(Instant::now() + capped_duration_secs(cooldown_secs));
            tracing::info!("凭据 #{} 收到 429，进入 {}s 冷却（累计 {} 次）", id, cooldown_secs, entry.rate_limit_count);
        }
    }

    /// 重置指定凭据的 429 计数和冷却状态
    pub fn reset_rate_limit(&self, id: u64) {
        let mut entries = self.entries.lock();
        if let Some(entry) = entries.iter_mut().find(|e| e.id == id) {
            entry.rate_limit_count = 0;
            entry.rate_limit_cooldown_until = None;
        }
    }

    /// 计算最近 60 秒内的请求数（RPM）
    pub fn rpm(&self) -> usize {
        let mut ts = self.request_timestamps.lock();
        let cutoff = Instant::now() - StdDuration::from_secs(60);
        while ts.front().map_or(false, |&t| t < cutoff) {
            ts.pop_front();
        }
        ts.len()
    }

    /// 报告指定凭据 API 调用失败
    ///
    /// 增加失败计数，达到阈值时禁用凭据并切换到优先级最高的可用凭据
    /// 返回是否还有可用凭据可以重试
    ///
    /// # Arguments
    /// * `id` - 凭据 ID（来自 CallContext）
    pub fn report_failure(&self, id: u64) -> bool {
        let mut disabled_now = false;
        let result = {
            let mut entries = self.entries.lock();
            let mut current_id = self.current_id.lock();

            let entry = match entries.iter_mut().find(|e| e.id == id) {
                Some(e) => e,
                None => return entries.iter().any(|e| !e.disabled),
            };

            if entry.disabled {
                return entries.iter().any(|e| !e.disabled);
            }

            entry.failure_count += 1;
            entry.last_used_at = Some(Utc::now().to_rfc3339());
            let failure_count = entry.failure_count;

            tracing::warn!(
                "凭据 #{} API 调用失败（{}/{}）",
                id,
                failure_count,
                MAX_FAILURES_PER_CREDENTIAL
            );

            if failure_count >= MAX_FAILURES_PER_CREDENTIAL {
                tracing::error!("凭据 #{} 已连续失败 {} 次，已被禁用", id, failure_count);
                disabled_now = true;
                disable_entry_and_switch(
                    &mut entries,
                    &mut current_id,
                    id,
                    DisabledReason::TooManyFailures,
                )
            } else {
                entries.iter().any(|e| !e.disabled)
            }
        };
        if disabled_now {
            self.persist_disabled_state();
        }
        self.save_stats_debounced();
        result
    }

    /// 报告指定凭据额度已用尽
    ///
    /// 用于处理 402 Payment Required 且 reason 为 `MONTHLY_REQUEST_COUNT` 的场景：
    /// - 立即禁用该凭据（不等待连续失败阈值）
    /// - 切换到下一个可用凭据继续重试
    /// - 返回是否还有可用凭据
    pub fn report_quota_exhausted(&self, id: u64) -> bool {
        let result = {
            let mut entries = self.entries.lock();
            let mut current_id = self.current_id.lock();

            let entry = match entries.iter_mut().find(|e| e.id == id) {
                Some(e) => e,
                None => return entries.iter().any(|e| !e.disabled),
            };

            if entry.disabled {
                return entries.iter().any(|e| !e.disabled);
            }

            entry.last_used_at = Some(Utc::now().to_rfc3339());
            entry.failure_count = MAX_FAILURES_PER_CREDENTIAL;

            tracing::error!("凭据 #{} 额度已用尽（MONTHLY_REQUEST_COUNT），已被禁用", id);

            disable_entry_and_switch(
                &mut entries,
                &mut current_id,
                id,
                DisabledReason::QuotaExceeded,
            )
        };
        // 执行到此处必然已发生禁用（其余分支均已提前 return），持久化封禁状态
        self.persist_disabled_state();
        self.save_stats_debounced();
        result
    }

    /// 报告指定凭据刷新 Token 失败。
    ///
    /// 连续刷新失败达到阈值后禁用凭据并切换，阈值内保持当前凭据不切换，
    /// 与 API 401/403 的累计失败策略保持一致。
    pub fn report_refresh_failure(&self, id: u64) -> bool {
        let result = {
            let mut entries = self.entries.lock();
            let mut current_id = self.current_id.lock();

            let entry = match entries.iter_mut().find(|e| e.id == id) {
                Some(e) => e,
                None => return entries.iter().any(|e| !e.disabled),
            };

            if entry.disabled {
                return entries.iter().any(|e| !e.disabled);
            }

            entry.last_used_at = Some(Utc::now().to_rfc3339());
            entry.refresh_failure_count += 1;
            let refresh_failure_count = entry.refresh_failure_count;

            tracing::warn!(
                "凭据 #{} Token 刷新失败（{}/{}）",
                id,
                refresh_failure_count,
                MAX_FAILURES_PER_CREDENTIAL
            );

            if refresh_failure_count < MAX_FAILURES_PER_CREDENTIAL {
                return entries.iter().any(|e| !e.disabled);
            }

            tracing::error!(
                "凭据 #{} Token 已连续刷新失败 {} 次，已被禁用",
                id,
                refresh_failure_count
            );

            disable_entry_and_switch(
                &mut entries,
                &mut current_id,
                id,
                DisabledReason::TooManyRefreshFailures,
            )
        };
        // 执行到此处必然已发生禁用（未达阈值的分支已提前 return），持久化封禁状态
        self.persist_disabled_state();
        self.save_stats_debounced();
        result
    }

    /// 报告指定凭据的 refreshToken 永久失效（invalid_grant）。
    ///
    /// 立即禁用凭据，不累计、不重试。
    /// 返回是否还有可用凭据。
    pub fn report_refresh_token_invalid(&self, id: u64) -> bool {
        let result = {
            let mut entries = self.entries.lock();
            let mut current_id = self.current_id.lock();

            let entry = match entries.iter_mut().find(|e| e.id == id) {
                Some(e) => e,
                None => return entries.iter().any(|e| !e.disabled),
            };

            if entry.disabled {
                return entries.iter().any(|e| !e.disabled);
            }

            entry.last_used_at = Some(Utc::now().to_rfc3339());

            tracing::error!(
                "凭据 #{} refreshToken 已失效 (invalid_grant)，已立即禁用",
                id
            );

            disable_entry_and_switch(
                &mut entries,
                &mut current_id,
                id,
                DisabledReason::InvalidRefreshToken,
            )
        };
        // 执行到此处必然已发生禁用（其余分支均已提前 return），持久化封禁状态
        self.persist_disabled_state();
        self.save_stats_debounced();
        result
    }

    /// 切换到优先级最高的可用凭据
    ///
    /// 返回是否成功切换
    pub fn switch_to_next(&self) -> bool {
        let entries = self.entries.lock();
        let mut current_id = self.current_id.lock();

        // 选择优先级最高的未禁用凭据（排除当前凭据）
        if let Some(next) = entries
            .iter()
            .filter(|e| !e.disabled && e.id != *current_id)
            .min_by_key(|e| e.credentials.priority)
        {
            *current_id = next.id;
            tracing::info!(
                "已切换到凭据 #{}（优先级 {}）",
                next.id,
                next.credentials.priority
            );
            true
        } else {
            // 没有其他可用凭据，检查当前凭据是否可用
            entries.iter().any(|e| e.id == *current_id && !e.disabled)
        }
    }

    // ========================================================================
    // Admin API 方法
    // ========================================================================

    /// 获取管理器状态快照（用于 Admin API）
    pub fn snapshot(&self) -> ManagerSnapshot {
        let entries = self.entries.lock();
        let current_id = *self.current_id.lock();
        let available = entries.iter().filter(|e| !e.disabled).count();
        let now = Instant::now();

        ManagerSnapshot {
            entries: entries
                .iter()
                .map(|e| {
                    // 计算该凭据最近 60 秒的请求数
                    let credential_rpm = e.dispatch_history.iter()
                        .filter(|&t| now.duration_since(*t).as_secs() < 60)
                        .count();
                    CredentialEntrySnapshot {
                    id: e.id,
                    priority: e.credentials.priority,
                    disabled: e.disabled,
                    failure_count: e.failure_count,
                    auth_method: if e.credentials.is_api_key_credential() {
                        Some("api_key".to_string())
                    } else {
                        e.credentials.auth_method.clone()
                    },
                    // 只有真实 ARN 才算「已配置」：空串与 BuilderID 占位符都不算
                    has_profile_arn: e.credentials.effective_profile_arn().is_some(),
                    expires_at: if e.credentials.is_api_key_credential() {
                        None // API Key 凭据本地不维护过期时间（服务端策略未知）
                    } else {
                        e.credentials.expires_at.clone()
                    },
                    refresh_token_hash: if e.credentials.is_api_key_credential() {
                        None
                    } else {
                        e.credentials.refresh_token.as_deref().map(sha256_hex)
                    },
                    api_key_hash: if e.credentials.is_api_key_credential() {
                        e.credentials.kiro_api_key.as_deref().map(sha256_hex)
                    } else {
                        None
                    },
                    masked_api_key: if e.credentials.is_api_key_credential() {
                        e.credentials.kiro_api_key.as_deref().map(mask_api_key)
                    } else {
                        None
                    },
                    email: e.credentials.email.clone(),
                    success_count: e.success_count,
                    last_used_at: e.last_used_at.clone(),
                    has_proxy: e.credentials.proxy_url.is_some(),
                    proxy_url: e.credentials.proxy_url.clone(),
                    refresh_failure_count: e.refresh_failure_count,
                    disabled_reason: e.disabled_reason.map(|r| r.as_str().to_string()),
                    endpoint: e.credentials.endpoint.clone(),
                    cooldown_enabled: e.credentials.cooldown_enabled,
                    cooldown_seconds: e.credentials.cooldown_seconds,
                    cooldown_max_requests: e.credentials.cooldown_max_requests,
                    rpm: credential_rpm,
                    last_ttfb_ms: e.last_ttfb_ms,
                    rate_limit_count: e.rate_limit_count,
                    rate_limit_cooling: e.rate_limit_cooldown_until.map_or(false, |until| now < until),
                }
                })
                .collect(),
            current_id,
            total: entries.len(),
            available,
            rpm: self.rpm(),
            cooldown_enabled: *self.cooldown_enabled.lock(),
            cooldown_seconds: *self.cooldown_seconds.lock(),
            cooldown_max_requests: *self.cooldown_max_requests.lock(),
        }
    }

    /// 设置凭据禁用状态（Admin API）
    pub fn set_disabled(&self, id: u64, disabled: bool) -> anyhow::Result<()> {
        {
            let mut entries = self.entries.lock();
            if !disabled {
                // 先计算可用凭据的最小 success_count（排除目标凭据）
                let min_success_count = entries
                    .iter()
                    .filter(|e| !e.disabled && e.id != id)
                    .map(|e| e.success_count)
                    .min()
                    .unwrap_or(0);
                let entry = entries
                    .iter_mut()
                    .find(|e| e.id == id)
                    .ok_or_else(|| anyhow::anyhow!("凭据不存在: {}", id))?;
                entry.disabled = false;
                entry.failure_count = 0;
                entry.refresh_failure_count = 0;
                entry.disabled_reason = None;
                entry.success_count = min_success_count;
            } else {
                let entry = entries
                    .iter_mut()
                    .find(|e| e.id == id)
                    .ok_or_else(|| anyhow::anyhow!("凭据不存在: {}", id))?;
                entry.disabled = true;
                entry.disabled_reason = Some(DisabledReason::Manual);
            }
        }
        // 持久化更改
        self.persist_credentials()?;
        Ok(())
    }

    /// 设置凭据优先级（Admin API）
    ///
    /// 修改优先级后会立即按新优先级重新选择当前凭据。
    /// 即使持久化失败，内存中的优先级和当前凭据选择也会生效。
    pub fn set_priority(&self, id: u64, priority: u32) -> anyhow::Result<()> {
        {
            let mut entries = self.entries.lock();
            let entry = entries
                .iter_mut()
                .find(|e| e.id == id)
                .ok_or_else(|| anyhow::anyhow!("凭据不存在: {}", id))?;
            entry.credentials.priority = priority;
        }
        // 立即按新优先级重新选择当前凭据（无论持久化是否成功）
        self.select_highest_priority();
        // 持久化更改
        self.persist_credentials()?;
        Ok(())
    }

    /// 重置凭据失败计数并重新启用（Admin API）
    pub fn reset_and_enable(&self, id: u64) -> anyhow::Result<()> {
        {
            let mut entries = self.entries.lock();
            // 先检查是否因配置无效被禁用
            let is_invalid_config = entries
                .iter()
                .find(|e| e.id == id)
                .ok_or_else(|| anyhow::anyhow!("凭据不存在: {}", id))?
                .disabled_reason == Some(DisabledReason::InvalidConfig);
            if is_invalid_config {
                anyhow::bail!(
                    "凭据 #{} 因配置无效被禁用，请修正配置后重启服务",
                    id
                );
            }
            // 先计算可用凭据的最小 success_count（排除目标凭据）
            let min_success_count = entries
                .iter()
                .filter(|e| !e.disabled && e.id != id)
                .map(|e| e.success_count)
                .min()
                .unwrap_or(0);
            let entry = entries
                .iter_mut()
                .find(|e| e.id == id)
                .ok_or_else(|| anyhow::anyhow!("凭据不存在: {}", id))?;
            entry.failure_count = 0;
            entry.refresh_failure_count = 0;
            entry.disabled = false;
            entry.disabled_reason = None;
            entry.success_count = min_success_count;
        }
        // 持久化更改
        self.persist_credentials()?;
        Ok(())
    }

    /// 解析并持久化 Enterprise/IdC 的真实 profile ARN。
    /// BuilderID 凭据无真实 ARN 时保留 `None` 回退路径。
    pub async fn resolve_profile_arn_for(
        &self,
        id: u64,
        token: &str,
    ) -> anyhow::Result<Option<String>> {
        let credentials = {
            let entries = self.entries.lock();
            entries
                .iter()
                .find(|entry| entry.id == id)
                .map(|entry| entry.credentials.clone())
                .ok_or_else(|| anyhow::anyhow!("凭据不存在: {}", id))?
        };

        if credentials.is_api_key_credential() {
            return Ok(None);
        }

        if let Some(arn) = credentials.effective_profile_arn() {
            return Ok(Some(arn.to_string()));
        }

        let effective_proxy = credentials.effective_proxy(self.proxy.as_ref());
        let profiles =
            list_available_profiles(&credentials, &self.config, token, effective_proxy.as_ref())
                .await?;
        let Some(arn) = profiles.first_arn().map(str::to_owned) else {
            return Ok(None);
        };

        {
            let mut entries = self.entries.lock();
            if let Some(entry) = entries.iter_mut().find(|entry| entry.id == id) {
                entry.credentials.profile_arn = Some(arn.clone());
            }
        }
        if let Err(error) = self.persist_credentials() {
            tracing::warn!("profileArn 回填后持久化失败（不影响本次请求）: {}", error);
        }
        tracing::info!("凭据 #{} 已解析并回填真实 profileArn", id);

        Ok(Some(arn))
    }

    /// 获取指定凭据的使用额度（Admin API）
    pub async fn get_usage_limits_for(&self, id: u64) -> anyhow::Result<UsageLimitsResponse> {
        let credentials = {
            let entries = self.entries.lock();
            entries
                .iter()
                .find(|e| e.id == id)
                .map(|e| e.credentials.clone())
                .ok_or_else(|| anyhow::anyhow!("凭据不存在: {}", id))?
        };

        let ctx = self.try_ensure_token(id, &credentials).await?;
        let token = ctx.token;

        let mut credentials = {
            let entries = self.entries.lock();
            entries
                .iter()
                .find(|e| e.id == id)
                .map(|e| e.credentials.clone())
                .ok_or_else(|| anyhow::anyhow!("凭据不存在: {}", id))?
        };

        match self.resolve_profile_arn_for(id, &token).await {
            Ok(Some(arn)) => credentials.profile_arn = Some(arn),
            Ok(None) => {}
            Err(error) => {
                tracing::debug!("凭据 #{} 查询用量前解析 profileArn 失败: {}", id, error)
            }
        }

        let effective_proxy = credentials.effective_proxy(self.proxy.as_ref());
        let usage_limits = get_usage_limits(&credentials, &self.config, &token, effective_proxy.as_ref()).await?;

        // 更新订阅等级和邮箱到凭据（仅在发生变化时持久化）
        let mut changed = false;

        if let Some(subscription_title) = usage_limits.subscription_title() {
            let mut entries = self.entries.lock();
            if let Some(entry) = entries.iter_mut().find(|e| e.id == id) {
                let old_title = entry.credentials.subscription_title.clone();
                if old_title.as_deref() != Some(subscription_title) {
                    entry.credentials.subscription_title =
                        Some(subscription_title.to_string());
                    tracing::info!(
                        "凭据 #{} 订阅等级已更新: {:?} -> {}",
                        id,
                        old_title,
                        subscription_title
                    );
                    changed = true;
                }
            }
        }

        if let Some(email) = usage_limits.user_email() {
            let mut entries = self.entries.lock();
            if let Some(entry) = entries.iter_mut().find(|e| e.id == id) {
                let old_email = entry.credentials.email.clone();
                if old_email.as_deref() != Some(email) {
                    entry.credentials.email = Some(email.to_string());
                    tracing::info!(
                        "凭据 #{} 邮箱已更新: {:?} -> {}",
                        id,
                        old_email,
                        email
                    );
                    changed = true;
                }
            }
        }

        if changed {
            if let Err(e) = self.persist_credentials() {
                tracing::warn!("凭据信息更新后持久化失败（不影响本次请求）: {}", e);
            }
        }

        Ok(usage_limits)
    }

    /// 批量开启超额（Admin API）
    ///
    /// 遍历所有凭据，检测超额状态，未开启的自动开启
    pub async fn enable_overage_all(&self) -> Vec<OverageResult> {
        let credential_ids: Vec<u64> = {
            let entries = self.entries.lock();
            entries.iter().map(|e| e.id).collect()
        };
        self.enable_overage_for_ids(&credential_ids).await
    }

    /// 对指定 ID 列表开启超额
    pub async fn enable_overage_for_ids(&self, ids: &[u64]) -> Vec<OverageResult> {
        let mut results = Vec::new();
        for &id in ids {
            let result = self.enable_overage_for(id).await;
            results.push(result);
        }
        results
    }

    async fn enable_overage_for(&self, id: u64) -> OverageResult {
        let credentials = match self.entries.lock().iter().find(|e| e.id == id).map(|e| e.credentials.clone()) {
            Some(c) => c,
            None => return OverageResult { id, status: "error".into(), message: "凭据不存在".into() },
        };

        // 获取 token
        let token = match self.try_ensure_token(id, &credentials).await {
            Ok(ctx) => ctx.token,
            Err(e) => return OverageResult { id, status: "error".into(), message: format!("获取 token 失败: {}", e) },
        };

        // 重新获取凭据（token 刷新后可能变化）
        let mut credentials = match self.entries.lock().iter().find(|e| e.id == id).map(|e| e.credentials.clone()) {
            Some(c) => c,
            None => return OverageResult { id, status: "error".into(), message: "凭据不存在".into() },
        };

        match self.resolve_profile_arn_for(id, &token).await {
            Ok(Some(arn)) => credentials.profile_arn = Some(arn),
            Ok(None) => {}
            Err(error) => {
                tracing::debug!("凭据 #{} 设置超额前解析 profileArn 失败: {}", id, error)
            }
        }

        let effective_proxy = credentials.effective_proxy(self.proxy.as_ref());

        // 1. 检测超额状态
        let usage = match get_usage_limits(&credentials, &self.config, &token, effective_proxy.as_ref()).await {
            Ok(u) => u,
            Err(e) => return OverageResult { id, status: "error".into(), message: format!("查询失败: {}", e) },
        };

        // 已开启 → 跳过
        if usage.is_overage_enabled() {
            return OverageResult { id, status: "skipped".into(), message: "已开启超额".into() };
        }

        // 无资格 → 跳过
        if !usage.is_overage_capable() {
            return OverageResult { id, status: "skipped".into(), message: "无超额资格(Free账号)".into() };
        }

        // 2. 开启超额
        match set_user_preference(&credentials, &self.config, &token, effective_proxy.as_ref(), "ENABLED").await {
            Ok(()) => OverageResult { id, status: "success".into(), message: "超额已开启".into() },
            Err(e) => OverageResult { id, status: "error".into(), message: format!("开启失败: {}", e) },
        }
    }

    /// 添加新凭据（Admin API）
    ///
    /// # 流程
    /// 1. 验证凭据基本字段（API Key: kiroApiKey 不为空; OAuth: refreshToken 不为空）
    /// 2. 基于 kiroApiKey 或 refreshToken 的 SHA-256 哈希检测重复
    /// 3. OAuth: 尝试刷新 Token 验证凭据有效性; API Key: 跳过
    /// 4. 分配新 ID（当前最大 ID + 1）
    /// 5. 添加到 entries 列表
    /// 6. 持久化到配置文件
    ///
    /// # 返回
    /// - `Ok(u64)` - 新凭据 ID
    /// - `Err(_)` - 验证失败或添加失败
    pub async fn add_credential(&self, new_cred: KiroCredentials) -> anyhow::Result<u64> {
        // 1. 基本验证
        if new_cred.is_api_key_credential() {
            let api_key = new_cred
                .kiro_api_key
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("API Key 凭据缺少 kiroApiKey"))?;
            if api_key.is_empty() {
                anyhow::bail!("kiroApiKey 为空");
            }
        } else {
            validate_refresh_token(&new_cred)?;
        }

        // 2. 基于哈希检测重复
        if new_cred.is_api_key_credential() {
            let new_api_key = new_cred
                .kiro_api_key
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("缺少 kiroApiKey"))?;
            let new_api_key_hash = sha256_hex(new_api_key);
            let duplicate_exists = {
                let entries = self.entries.lock();
                entries.iter().any(|entry| {
                    entry
                        .credentials
                        .kiro_api_key
                        .as_deref()
                        .map(sha256_hex)
                        .as_deref()
                        == Some(new_api_key_hash.as_str())
                })
            };
            if duplicate_exists {
                anyhow::bail!("凭据已存在（kiroApiKey 重复）");
            }
        } else {
            let new_refresh_token = new_cred
                .refresh_token
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("缺少 refreshToken"))?;
            let new_refresh_token_hash = sha256_hex(new_refresh_token);
            let duplicate_exists = {
                let entries = self.entries.lock();
                entries.iter().any(|entry| {
                    entry
                        .credentials
                        .refresh_token
                        .as_deref()
                        .map(sha256_hex)
                        .as_deref()
                        == Some(new_refresh_token_hash.as_str())
                })
            };
            if duplicate_exists {
                anyhow::bail!("凭据已存在（refreshToken 重复）");
            }
        }

        // 3. 验证凭据有效性（API Key 无需网络刷新），并将 token 字段合并回原始凭据
        let mut final_cred = new_cred;
        final_cred.canonicalize_auth_method();

        if !final_cred.is_api_key_credential() {
            let effective_proxy = final_cred.effective_proxy(self.proxy.as_ref());
            let refreshed =
                refresh_token(&final_cred, &self.config, effective_proxy.as_ref()).await?;
            final_cred.access_token = refreshed.access_token;
            if let Some(rt) = refreshed.refresh_token {
                final_cred.refresh_token = Some(rt);
            }
            final_cred.expires_at = refreshed.expires_at;
            if let Some(arn) = refreshed.profile_arn {
                final_cred.profile_arn = Some(arn);
            }
        }

        // 4-6. 分配 ID、插入与持久化在同一锁内完成，保存失败时不发布新凭据。
        let new_id = {
            let mut entries = self.entries.lock();
            let new_id = entries.iter().map(|e| e.id).max().unwrap_or(0) + 1;
            final_cred.id = Some(new_id);

            // balanced 模式下，新凭据从当前最小 success_count 开始，避免 count 落差导致长时间单点倾斜
            let min_success_count = entries
                .iter()
                .filter(|e| !e.disabled)
                .map(|e| e.success_count)
                .min()
                .unwrap_or(0);
            entries.push(CredentialEntry {
                id: new_id,
                credentials: final_cred,
                failure_count: 0,
                refresh_failure_count: 0,
                disabled: false,
                disabled_reason: None,
                success_count: min_success_count,
                last_used_at: None,
                dispatch_history: VecDeque::new(),
                last_ttfb_ms: None,
                rate_limit_count: 0,
                rate_limit_cooldown_until: None,
                rate_limit_cooldown_secs_override: None,
            });
            if let Err(error) = self.persist_credentials_locked(&entries, true) {
                entries.pop();
                return Err(error);
            }
            new_id
        };

        // 清除该 ID 可能残留的计费记录，避免复用已删除凭据 ID 时继承旧费用
        if let Some(billing) = crate::admin::billing::get() {
            billing.reset_credential(new_id);
            billing.force_save();
        }

        tracing::info!("成功添加凭据 #{}", new_id);
        Ok(new_id)
    }

    /// 删除凭据（Admin API）
    ///
    /// # 前置条件
    /// - 凭据必须已禁用（disabled = true）
    ///
    /// # 行为
    /// 1. 验证凭据存在
    /// 2. 验证凭据已禁用
    /// 3. 从 entries 移除
    /// 4. 如果删除的是当前凭据，切换到优先级最高的可用凭据
    /// 5. 如果删除后没有凭据，将 current_id 重置为 0
    /// 6. 持久化到文件
    ///
    /// # 返回
    /// - `Ok(())` - 删除成功
    /// - `Err(_)` - 凭据不存在、未禁用或持久化失败
    pub fn delete_credential(&self, id: u64) -> anyhow::Result<()> {
        let was_current = {
            let mut entries = self.entries.lock();

            // 查找凭据
            let _entry = entries
                .iter()
                .find(|e| e.id == id)
                .ok_or_else(|| anyhow::anyhow!("凭据不存在: {}", id))?;

            // 记录是否是当前凭据
            let current_id = *self.current_id.lock();
            let was_current = current_id == id;

            // 删除凭据
            entries.retain(|e| e.id != id);

            was_current
        };

        // 如果删除的是当前凭据，切换到优先级最高的可用凭据
        if was_current {
            self.select_highest_priority();
        }

        // 如果删除后没有任何凭据，将 current_id 重置为 0（与初始化行为保持一致）
        {
            let entries = self.entries.lock();
            if entries.is_empty() {
                let mut current_id = self.current_id.lock();
                *current_id = 0;
                tracing::info!("所有凭据已删除，current_id 已重置为 0");
            }
        }

        // 持久化更改
        self.persist_credentials()?;

        // 立即回写统计数据，清除已删除凭据的残留条目
        self.save_stats();

        // 清除该凭据的计费记录并立即落盘，避免 ID 被新凭据复用后继承旧费用
        if let Some(billing) = crate::admin::billing::get() {
            billing.reset_credential(id);
            billing.force_save();
        }

        tracing::info!("已删除凭据 #{}", id);
        Ok(())
    }

    /// 强制刷新指定凭据的 Token（Admin API）
    ///
    /// 无条件调用上游 API 重新获取 access token，不检查是否过期。
    /// 适用于排查问题、Token 异常但未过期、主动更新凭据状态等场景。
    pub async fn force_refresh_token_for(&self, id: u64) -> anyhow::Result<()> {
        // 获取刷新锁防止并发刷新
        let _guard = self.refresh_lock.lock().await;

        // 拿锁后再读取凭据：其他请求可能刚完成 refreshToken 轮换，用旧值刷新会 invalid_grant
        let credentials = {
            let entries = self.entries.lock();
            entries
                .iter()
                .find(|e| e.id == id)
                .map(|e| e.credentials.clone())
                .ok_or_else(|| anyhow::anyhow!("凭据不存在: {}", id))?
        };

        // 无条件调用 refresh_token
        let effective_proxy = credentials.effective_proxy(self.proxy.as_ref());
        let new_creds =
            refresh_token(&credentials, &self.config, effective_proxy.as_ref()).await?;

        // 只合并 token 字段到 entries 中对应凭据
        {
            let mut entries = self.entries.lock();
            if let Some(entry) = entries.iter_mut().find(|e| e.id == id) {
                apply_refreshed_tokens(&mut entry.credentials, &credentials, &new_creds);
                entry.refresh_failure_count = 0;
            }
        }

        // 持久化
        if let Err(e) = self.persist_credentials() {
            tracing::warn!("强制刷新 Token 后持久化失败: {}", e);
        }

        tracing::info!("凭据 #{} Token 已强制刷新", id);
        Ok(())
    }

    /// 获取负载均衡模式（Admin API）
    pub fn get_load_balancing_mode(&self) -> String {
        self.load_balancing_mode.lock().clone()
    }

    fn persist_load_balancing_mode(&self, mode: &str) -> anyhow::Result<()> {
        use anyhow::Context;

        let config_path = match self.config.config_path() {
            Some(path) => path.to_path_buf(),
            None => {
                tracing::warn!("配置文件路径未知，负载均衡模式仅在当前进程生效: {}", mode);
                return Ok(());
            }
        };

        let mut config = Config::load(&config_path)
            .with_context(|| format!("重新加载配置失败: {}", config_path.display()))?;
        config.load_balancing_mode = mode.to_string();
        config
            .save()
            .with_context(|| format!("持久化负载均衡模式失败: {}", config_path.display()))?;

        Ok(())
    }

    /// 设置负载均衡模式（Admin API）
    pub fn set_load_balancing_mode(&self, mode: String) -> anyhow::Result<()> {
        // 验证模式值
        if mode != "priority" && mode != "balanced" {
            anyhow::bail!("无效的负载均衡模式: {}", mode);
        }

        let previous_mode = self.get_load_balancing_mode();
        if previous_mode == mode {
            return Ok(());
        }

        *self.load_balancing_mode.lock() = mode.clone();

        if let Err(err) = self.persist_load_balancing_mode(&mode) {
            *self.load_balancing_mode.lock() = previous_mode;
            return Err(err);
        }

        tracing::info!("负载均衡模式已设置为: {}", mode);
        Ok(())
    }

    /// 获取全局冷却限流配置（Admin API）
    pub fn get_cooldown_config(&self) -> (bool, u64, u32) {
        (
            *self.cooldown_enabled.lock(),
            *self.cooldown_seconds.lock(),
            *self.cooldown_max_requests.lock(),
        )
    }

    /// 设置全局冷却限流配置（Admin API）
    pub fn set_cooldown_config(
        &self,
        enabled: bool,
        seconds: u64,
        max_requests: u32,
    ) -> anyhow::Result<()> {
        if seconds == 0 {
            anyhow::bail!("冷却窗口时长不能为 0");
        }
        validate_duration_secs("冷却窗口时长", seconds)?;
        if max_requests == 0 {
            anyhow::bail!("冷却窗口内最大请求数不能为 0");
        }

        let prev_enabled = *self.cooldown_enabled.lock();
        let prev_seconds = *self.cooldown_seconds.lock();
        let prev_max = *self.cooldown_max_requests.lock();

        *self.cooldown_enabled.lock() = enabled;
        *self.cooldown_seconds.lock() = seconds;
        *self.cooldown_max_requests.lock() = max_requests;

        if let Err(err) = self.persist_cooldown_config() {
            *self.cooldown_enabled.lock() = prev_enabled;
            *self.cooldown_seconds.lock() = prev_seconds;
            *self.cooldown_max_requests.lock() = prev_max;
            return Err(err);
        }

        let status = if enabled { "启用" } else { "关闭" };
        tracing::info!(
            "全局冷却限流已{}（{}秒内最多{}个请求）",
            status,
            seconds,
            max_requests
        );
        Ok(())
    }

    fn persist_cooldown_config(&self) -> anyhow::Result<()> {
        use anyhow::Context;

        let config_path = match self.config.config_path() {
            Some(path) => path.to_path_buf(),
            None => {
                tracing::warn!("配置文件路径未知，冷却配置仅在当前进程生效");
                return Ok(());
            }
        };

        let enabled = *self.cooldown_enabled.lock();
        let seconds = *self.cooldown_seconds.lock();
        let max_requests = *self.cooldown_max_requests.lock();

        let mut config = Config::load(&config_path)
            .with_context(|| format!("重新加载配置失败: {}", config_path.display()))?;
        config.cooldown_enabled = enabled;
        config.cooldown_seconds = seconds;
        config.cooldown_max_requests = max_requests;
        config
            .save()
            .with_context(|| format!("持久化冷却配置失败: {}", config_path.display()))?;

        Ok(())
    }

    /// 获取缓存 token 估算倍率（顺序：creation, read, uncached, first_turn）
    pub fn get_cache_ratios(&self) -> (f64, f64, f64, f64, f64) {
        (
            *self.cache_ratio_creation.lock(),
            *self.cache_ratio_read.lock(),
            *self.cache_ratio_uncached.lock(),
            *self.cache_ratio_first_turn.lock(),
            *self.cache_ratio_output.lock(),
        )
    }

    /// 设置缓存 token 估算倍率（Admin API）
    pub fn set_cache_ratios(
        &self,
        creation: f64,
        read: f64,
        uncached: f64,
        first_turn: f64,
        output: f64,
    ) -> anyhow::Result<()> {
        for (name, value) in [
            ("creation", creation),
            ("read", read),
            ("uncached", uncached),
            ("first_turn", first_turn),
            ("output", output),
        ] {
            if !value.is_finite() || value <= 0.0 {
                anyhow::bail!("倍率 {} 必须为正数: {}", name, value);
            }
        }

        let prev = (
            *self.cache_ratio_creation.lock(),
            *self.cache_ratio_read.lock(),
            *self.cache_ratio_uncached.lock(),
            *self.cache_ratio_first_turn.lock(),
            *self.cache_ratio_output.lock(),
        );

        *self.cache_ratio_creation.lock() = creation;
        *self.cache_ratio_read.lock() = read;
        *self.cache_ratio_uncached.lock() = uncached;
        *self.cache_ratio_first_turn.lock() = first_turn;
        *self.cache_ratio_output.lock() = output;

        if let Err(err) = self.persist_cache_ratios() {
            *self.cache_ratio_creation.lock() = prev.0;
            *self.cache_ratio_read.lock() = prev.1;
            *self.cache_ratio_uncached.lock() = prev.2;
            *self.cache_ratio_first_turn.lock() = prev.3;
            *self.cache_ratio_output.lock() = prev.4;
            return Err(err);
        }

        tracing::info!(
            "缓存倍率已更新: creation={}, read={}, uncached={}, first_turn={}, output={}",
            creation,
            read,
            uncached,
            first_turn,
            output
        );
        Ok(())
    }

    fn persist_cache_ratios(&self) -> anyhow::Result<()> {
        use anyhow::Context;

        let config_path = match self.config.config_path() {
            Some(path) => path.to_path_buf(),
            None => {
                tracing::warn!("配置文件路径未知，缓存倍率仅在当前进程生效");
                return Ok(());
            }
        };

        let creation = *self.cache_ratio_creation.lock();
        let read = *self.cache_ratio_read.lock();
        let uncached = *self.cache_ratio_uncached.lock();
        let first_turn = *self.cache_ratio_first_turn.lock();
        let output = *self.cache_ratio_output.lock();

        let mut config = Config::load(&config_path)
            .with_context(|| format!("重新加载配置失败: {}", config_path.display()))?;
        config.cache_ratio_creation = creation;
        config.cache_ratio_read = read;
        config.cache_ratio_uncached = uncached;
        config.cache_ratio_first_turn = first_turn;
        config.cache_ratio_output = output;
        config
            .save()
            .with_context(|| format!("持久化缓存倍率失败: {}", config_path.display()))?;

        Ok(())
    }

    // ============ 缓存模式 ============

    /// 获取缓存模式
    pub fn get_cache_mode(&self) -> String {
        self.cache_mode.lock().clone()
    }

    /// 判断当前是否处于缓存间歇中断期
    fn is_cache_interrupted(&self) -> bool {
        if !*self.cache_interrupt_enabled.lock() {
            return false;
        }
        let now = Instant::now();
        let mut active = self.cache_interrupt_active.lock();
        if *active {
            if now >= *self.cache_interrupt_end.lock() {
                *active = false;
                let min = *self.cache_interrupt_min_secs.lock();
                let max = *self.cache_interrupt_max_secs.lock();
                *self.cache_interrupt_next.lock() = now + random_interrupt_delay(min, max);
            }
            return *active;
        }
        if now >= *self.cache_interrupt_next.lock() {
            *active = true;
            let duration = *self.cache_interrupt_duration_secs.lock();
            *self.cache_interrupt_end.lock() = now + capped_duration_secs(duration);
            return true;
        }
        false
    }

    /// 获取缓存间歇中断配置
    pub fn get_cache_interrupt_config(&self) -> (bool, u64, u64, u64) {
        (
            *self.cache_interrupt_enabled.lock(),
            *self.cache_interrupt_min_secs.lock(),
            *self.cache_interrupt_max_secs.lock(),
            *self.cache_interrupt_duration_secs.lock(),
        )
    }

    /// 设置缓存间歇中断配置
    pub fn set_cache_interrupt_config(&self, enabled: bool, min_secs: u64, max_secs: u64, duration_secs: u64) -> anyhow::Result<()> {
        if min_secs == 0 || max_secs == 0 {
            anyhow::bail!("间隔秒数必须大于 0");
        }
        if min_secs > max_secs {
            anyhow::bail!("最小间隔不能大于最大间隔");
        }
        if duration_secs == 0 {
            anyhow::bail!("中断时长必须大于 0");
        }
        validate_duration_secs("间隔秒数", max_secs)?;
        validate_duration_secs("中断时长", duration_secs)?;
        *self.cache_interrupt_enabled.lock() = enabled;
        *self.cache_interrupt_min_secs.lock() = min_secs;
        *self.cache_interrupt_max_secs.lock() = max_secs;
        *self.cache_interrupt_duration_secs.lock() = duration_secs;
        // 重置中断计时器
        let now = Instant::now();
        *self.cache_interrupt_active.lock() = false;
        *self.cache_interrupt_next.lock() = now + random_interrupt_delay(min_secs, max_secs);
        if let Err(err) = self.persist_cache_interrupt_config(enabled, min_secs, max_secs, duration_secs) {
            return Err(err);
        }
        tracing::info!("缓存间歇中断配置已更新: enabled={}, range={}~{}s, duration={}s", enabled, min_secs, max_secs, duration_secs);
        Ok(())
    }

    fn persist_cache_interrupt_config(&self, enabled: bool, min_secs: u64, max_secs: u64, duration_secs: u64) -> anyhow::Result<()> {
        use anyhow::Context;
        let config_path = match self.config.config_path() {
            Some(path) => path.to_path_buf(),
            None => return Ok(()),
        };
        let content = std::fs::read_to_string(&config_path)
            .with_context(|| format!("读取配置文件失败: {:?}", config_path))?;
        let mut json: serde_json::Value = serde_json::from_str(&content)
            .with_context(|| "解析配置文件 JSON 失败")?;
        json["cacheInterruptEnabled"] = serde_json::Value::Bool(enabled);
        json["cacheInterruptMinSecs"] = serde_json::json!(min_secs);
        json["cacheInterruptMaxSecs"] = serde_json::json!(max_secs);
        json["cacheInterruptDurationSecs"] = serde_json::json!(duration_secs);
        let output = serde_json::to_string_pretty(&json)?;
        write_atomic(&config_path, output)
            .with_context(|| format!("写入配置文件失败: {:?}", config_path))?;
        Ok(())
    }

    /// 设置缓存模式（Admin API）
    pub fn set_cache_mode(&self, mode: String) -> anyhow::Result<()> {
        if mode != "fixed" && mode != "standard" {
            anyhow::bail!("无效的缓存模式: {}", mode);
        }
        let previous = self.get_cache_mode();
        if previous == mode {
            return Ok(());
        }
        *self.cache_mode.lock() = mode.clone();
        self.cache_prefix_map.lock().clear();
        if let Err(err) = self.persist_cache_mode(&mode) {
            *self.cache_mode.lock() = previous;
            return Err(err);
        }
        tracing::info!("缓存模式已设置为: {}", mode);
        Ok(())
    }

    /// 检查前缀缓存命中数（标准模式逐条匹配，固定模式全部命中）
    ///
    /// 返回值: 命中的消息数（从前缀头部开始连续匹配的条数）
    /// 固定模式返回 usize::MAX 表示全部命中（间歇中断期间返回 0）
    pub fn check_prefix_cache(&self, prefix_hashes: &[u64]) -> usize {
        let mode = self.cache_mode.lock().clone();
        if mode == "fixed" {
            if self.is_cache_interrupted() {
                return 0;
            }
            return usize::MAX;
        }

        if prefix_hashes.is_empty() {
            return 0;
        }

        let now = Instant::now();
        let ttl = StdDuration::from_secs(300);
        let mut map = self.cache_prefix_map.lock();

        // 每 30 秒清理一次过期条目，避免高 RPM 下每次请求都全量遍历
        let mut last_cleanup = self.cache_last_cleanup.lock();
        if now.duration_since(*last_cleanup) > StdDuration::from_secs(30) {
            map.retain(|_, last_seen| now.duration_since(*last_seen) <= ttl);
            *last_cleanup = now;
        }

        // 从头开始逐条匹配，找到最长连续命中前缀
        let mut hit_count = 0;
        for hash in prefix_hashes {
            if let Some(&last_seen) = map.get(hash) {
                if now.duration_since(last_seen) <= ttl {
                    hit_count += 1;
                } else {
                    break;
                }
            } else {
                break;
            }
        }

        // 更新所有前缀哈希的时间戳（当前请求建立新的缓存前缀）
        for hash in prefix_hashes {
            map.insert(*hash, now);
        }

        hit_count
    }

    fn persist_cache_mode(&self, mode: &str) -> anyhow::Result<()> {
        use anyhow::Context;

        let config_path = match self.config.config_path() {
            Some(path) => path.to_path_buf(),
            None => {
                tracing::warn!("配置文件路径未知，缓存模式仅在当前进程生效");
                return Ok(());
            }
        };

        let mut config = Config::load(&config_path)
            .with_context(|| format!("重新加载配置失败: {}", config_path.display()))?;
        config.cache_mode = mode.to_string();
        config
            .save()
            .with_context(|| format!("持久化缓存模式失败: {}", config_path.display()))?;

        Ok(())
    }

    // ============ 模型映射 ============

    /// 获取模型映射列表
    pub fn get_model_mappings(&self) -> Vec<crate::model::config::ModelMapping> {
        self.model_mappings.lock().clone()
    }

    /// 读取同一次更新中的两组映射，避免并发保存时返回混合版本。
    pub fn get_model_mapping_tables(&self) -> (
        Vec<crate::model::config::ModelMapping>,
        Vec<crate::model::config::ModelMapping>,
    ) {
        let mappings = self.model_mappings.lock();
        let free_mappings = self.free_model_mappings.lock();
        (mappings.clone(), free_mappings.clone())
    }

    /// 两组映射先一起校验、保存，成功后再发布到内存，避免失败时只更新一组。
    /// 未提供 Free 映射时保留现有规则，显式空数组则清空。
    pub fn set_model_mappings(
        &self,
        mut mappings: Vec<crate::model::config::ModelMapping>,
        mut free_mappings: Option<Vec<crate::model::config::ModelMapping>>,
    ) -> anyhow::Result<()> {
        use anyhow::Context;

        for mapping in mappings.iter_mut().chain(free_mappings.iter_mut().flatten()) {
            mapping.from = mapping.from.trim().to_string();
            mapping.to = mapping.to.trim().to_string();
            if mapping.from.is_empty() || mapping.to.is_empty() {
                anyhow::bail!("模型映射的 from 和 to 不能为空");
            }
        }

        // 所有映射写入按相同顺序持锁，串行完成整组更新。
        let mut current_mappings = self.model_mappings.lock();
        let mut current_free_mappings = self.free_model_mappings.lock();
        let free_mappings = free_mappings.unwrap_or_else(|| current_free_mappings.clone());

        if let Some(config_path) = self.config.config_path() {
            let mut config = Config::load(config_path)
                .with_context(|| format!("重新加载配置失败: {}", config_path.display()))?;
            config.model_mappings = mappings.clone();
            config.free_model_mappings = free_mappings.clone();
            config
                .save()
                .with_context(|| format!("持久化模型映射失败: {}", config_path.display()))?;
        } else {
            tracing::warn!("配置文件路径未知，模型映射仅在当前进程生效");
        }

        tracing::info!(
            "模型映射已更新: 通用 {} 条，Free {} 条",
            mappings.len(),
            free_mappings.len()
        );
        *current_mappings = mappings;
        *current_free_mappings = free_mappings;
        Ok(())
    }

    /// 按配置顺序匹配客户端原始模型名，返回 Free 映射右侧的最终上游模型 ID。
    pub fn resolve_free_model(&self, model: &str) -> Option<String> {
        self.free_model_mappings
            .lock()
            .iter()
            .find(|mapping| mapping.matches_keyword(model))
            .map(|mapping| mapping.to.trim().to_string())
    }

    /// 请求转换前检查模型是否可解析，支持只配置在 Free 映射中的别名。
    /// 最终上游模型仍须在选定凭据后重新解析。
    pub fn resolve_request_model(&self, model: &str) -> Option<String> {
        self.resolve_model(model)
            .or_else(|| self.resolve_free_model(model))
    }

    pub fn resolve_model_for_credential(
        &self,
        model: &str,
        credentials: &KiroCredentials,
    ) -> Option<String> {
        if credentials.is_free() {
            self.resolve_free_model(model)
        } else {
            self.resolve_model(model)
        }
    }

    /// 根据通用映射解析模型 ID
    pub fn resolve_model(&self, model: &str) -> Option<String> {
        let mappings = self.model_mappings.lock();
        let model_lower = model.to_lowercase();

        // 精确匹配（忽略大小写）
        for m in mappings.iter() {
            if m.from.to_lowercase() == model_lower {
                return Some(m.to.clone());
            }
        }

        // 带 -thinking 后缀的匹配
        let base = model_lower.trim_end_matches("-thinking");
        if base != model_lower {
            for m in mappings.iter() {
                if m.from.to_lowercase() == base {
                    return Some(m.to.clone());
                }
            }
        }

        // Fallback 到模式匹配
        drop(mappings);
        crate::anthropic::map_model_fallback(model)
    }

    /// 设置单个凭据的冷却限流配置（Admin API）
    pub fn set_credential_cooldown(
        &self,
        id: u64,
        enabled: Option<bool>,
        seconds: Option<u64>,
        max_requests: Option<u32>,
    ) -> anyhow::Result<()> {
        if let Some(s) = seconds {
            if s == 0 {
                anyhow::bail!("冷却窗口时长不能为 0");
            }
            validate_duration_secs("冷却窗口时长", s)?;
        }
        if let Some(m) = max_requests {
            if m == 0 {
                anyhow::bail!("冷却窗口内最大请求数不能为 0");
            }
        }

        {
            let mut entries = self.entries.lock();
            let entry = entries
                .iter_mut()
                .find(|e| e.id == id)
                .ok_or_else(|| anyhow::anyhow!("凭据不存在: {}", id))?;
            entry.credentials.cooldown_enabled = enabled;
            entry.credentials.cooldown_seconds = seconds;
            entry.credentials.cooldown_max_requests = max_requests;
        }

        self.persist_credentials()?;

        tracing::info!(
            "凭据 #{} 冷却配置已更新: enabled={:?}, seconds={:?}, max_requests={:?}",
            id,
            enabled,
            seconds,
            max_requests
        );
        Ok(())
    }

    /// 设置凭据代理配置（Admin API）
    pub fn set_proxy(
        &self,
        id: u64,
        proxy_url: Option<String>,
        proxy_username: Option<String>,
        proxy_password: Option<String>,
    ) -> anyhow::Result<()> {
        {
            let mut entries = self.entries.lock();
            let entry = entries
                .iter_mut()
                .find(|e| e.id == id)
                .ok_or_else(|| anyhow::anyhow!("凭据不存在: {}", id))?;
            entry.credentials.proxy_url = proxy_url.clone();
            entry.credentials.proxy_username = proxy_username;
            entry.credentials.proxy_password = proxy_password;
        }

        self.persist_credentials()?;

        tracing::info!(
            "凭据 #{} 代理配置已更新: proxy_url={:?}",
            id,
            proxy_url
        );
        Ok(())
    }

    /// 获取凭据的有效代理配置（Admin API - 用于延迟检测）
    pub fn get_credential_proxy(&self, id: u64) -> anyhow::Result<Option<ProxyConfig>> {
        let entries = self.entries.lock();
        let entry = entries
            .iter()
            .find(|e| e.id == id)
            .ok_or_else(|| anyhow::anyhow!("凭据不存在: {}", id))?;
        Ok(entry.credentials.effective_proxy(self.proxy.as_ref()))
    }

    /// 获取所有凭据的代理配置（url, username, password）用于代理池分配判断
    pub fn get_all_proxy_configs(&self) -> Vec<(String, Option<String>, Option<String>)> {
        let entries = self.entries.lock();
        entries
            .iter()
            .filter_map(|e| {
                e.credentials.proxy_url.as_ref().map(|url| {
                    (
                        url.clone(),
                        e.credentials.proxy_username.clone(),
                        e.credentials.proxy_password.clone(),
                    )
                })
            })
            .collect()
    }

    /// 获取所有凭据的代理配置（含凭据 ID）
    pub fn get_all_proxy_configs_with_ids(&self) -> Vec<(String, Option<String>, Option<String>, u64)> {
        let entries = self.entries.lock();
        entries
            .iter()
            .filter_map(|e| {
                e.credentials.proxy_url.as_ref().map(|url| {
                    (
                        url.clone(),
                        e.credentials.proxy_username.clone(),
                        e.credentials.proxy_password.clone(),
                        e.id,
                    )
                })
            })
            .collect()
    }

    /// 获取 429 冷却时长（秒）
    pub fn get_rate_limit_cooldown_secs(&self) -> u64 {
        *self.rate_limit_cooldown_secs.lock()
    }

    /// 设置 429 冷却时长（秒）
    pub fn set_rate_limit_cooldown_secs(&self, secs: u64) {
        // 截断到安全上限，防止超大值落盘后每次 429 都溢出
        let secs = secs.min(MAX_CONFIG_DURATION_SECS);
        *self.rate_limit_cooldown_secs.lock() = secs;
        tracing::info!("429 冷却时长已更新为 {}s", secs);

        // 持久化到配置文件
        if let Some(path) = self.config.config_path() {
            if let Ok(mut config) = Config::load(path) {
                config.rate_limit_cooldown_secs = secs;
                if let Err(e) = config.save() {
                    tracing::warn!("持久化 429 冷却时长失败: {}", e);
                }
            }
        }
    }

    /// 设置单个凭据的 429 冷却时长（None 表示跟随全局）
    pub fn set_credential_rate_limit_cooldown(&self, id: u64, secs: Option<u64>) -> anyhow::Result<()> {
        let mut entries = self.entries.lock();
        let entry = entries
            .iter_mut()
            .find(|e| e.id == id)
            .ok_or_else(|| anyhow::anyhow!("凭据不存在: {}", id))?;
        entry.rate_limit_cooldown_secs_override = secs.map(|s| s.min(MAX_CONFIG_DURATION_SECS));
        tracing::info!("凭据 #{} 429 冷却时长设为: {:?}", id, secs);
        Ok(())
    }
}

impl Drop for MultiTokenManager {
    fn drop(&mut self) {
        if self.stats_dirty.load(Ordering::Relaxed) {
            self.save_stats();
        }
    }
}

#[cfg(test)]
#[path = "tests/model_mapping.rs"]
mod model_mapping_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_token_expired_with_expired_token() {
        let mut credentials = KiroCredentials::default();
        credentials.expires_at = Some("2020-01-01T00:00:00Z".to_string());
        assert!(is_token_expired(&credentials));
    }

    #[test]
    fn test_is_token_expired_with_valid_token() {
        let mut credentials = KiroCredentials::default();
        let future = Utc::now() + Duration::hours(1);
        credentials.expires_at = Some(future.to_rfc3339());
        assert!(!is_token_expired(&credentials));
    }

    #[test]
    fn test_is_token_expired_within_5_minutes() {
        let mut credentials = KiroCredentials::default();
        let expires = Utc::now() + Duration::minutes(3);
        credentials.expires_at = Some(expires.to_rfc3339());
        assert!(is_token_expired(&credentials));
    }

    #[test]
    fn test_is_token_expired_no_expires_at() {
        let credentials = KiroCredentials::default();
        assert!(is_token_expired(&credentials));
    }

    #[test]
    fn test_is_token_expiring_soon_within_10_minutes() {
        let mut credentials = KiroCredentials::default();
        let expires = Utc::now() + Duration::minutes(8);
        credentials.expires_at = Some(expires.to_rfc3339());
        assert!(is_token_expiring_soon(&credentials));
    }

    #[test]
    fn test_is_token_expiring_soon_beyond_10_minutes() {
        let mut credentials = KiroCredentials::default();
        let expires = Utc::now() + Duration::minutes(15);
        credentials.expires_at = Some(expires.to_rfc3339());
        assert!(!is_token_expiring_soon(&credentials));
    }

    #[test]
    fn test_validate_refresh_token_missing() {
        let credentials = KiroCredentials::default();
        let result = validate_refresh_token(&credentials);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_refresh_token_valid() {
        let mut credentials = KiroCredentials::default();
        credentials.refresh_token = Some("a".repeat(150));
        let result = validate_refresh_token(&credentials);
        assert!(result.is_ok());
    }

    #[test]
    fn test_sha256_hex() {
        let result = sha256_hex("test");
        assert_eq!(
            result,
            "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
        );
    }

    #[tokio::test]
    async fn test_refresh_token_rejects_api_key_credential() {
        let config = Config::default();
        let mut credentials = KiroCredentials::default();
        credentials.kiro_api_key = Some("ksk_test_key_123".to_string());
        credentials.auth_method = Some("api_key".to_string());

        let result = refresh_token(&credentials, &config, None).await;

        assert!(result.is_err(), "API Key 凭据应被 refresh_token 拒绝");
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("API Key 凭据不支持刷新"),
            "期望错误消息包含 'API Key 凭据不支持刷新'，实际: {}",
            err_msg
        );
    }

    #[tokio::test]
    async fn test_add_credential_reject_duplicate_refresh_token() {
        let config = Config::default();

        let mut existing = KiroCredentials::default();
        existing.refresh_token = Some("a".repeat(150));

        let manager = MultiTokenManager::new(config, vec![existing], None, None, false).unwrap();

        let mut duplicate = KiroCredentials::default();
        duplicate.refresh_token = Some("a".repeat(150));

        let result = manager.add_credential(duplicate).await;
        assert!(result.is_err());
        assert!(result.err().unwrap().to_string().contains("凭据已存在"));
    }

    #[tokio::test]
    async fn test_add_credential_api_key_success() {
        let config = Config::default();
        let manager = MultiTokenManager::new(config, vec![], None, None, false).unwrap();

        let mut api_key_cred = KiroCredentials::default();
        api_key_cred.kiro_api_key = Some("ksk_test_key_123".to_string());
        api_key_cred.auth_method = Some("api_key".to_string());

        let result = manager.add_credential(api_key_cred).await;
        assert!(result.is_ok());
        let id = result.unwrap();
        assert!(id > 0);
        assert_eq!(manager.total_count(), 1);
        assert_eq!(manager.available_count(), 1);
    }

    mod credential_persistence_tests {
        use super::*;
        use crate::kiro::model::credentials::CredentialsConfig;

        struct TestDirectory(PathBuf);

        impl TestDirectory {
            fn new() -> Self {
                let path = std::env::temp_dir()
                    .join(format!("kiro-credential-persistence-{}", uuid::Uuid::new_v4()));
                std::fs::create_dir(&path).unwrap();
                Self(path)
            }
        }

        impl Drop for TestDirectory {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }

        fn credential(id: u64) -> KiroCredentials {
            KiroCredentials {
                id: Some(id),
                machine_id: Some(format!("test-machine-{id}")),
                kiro_api_key: Some(format!("ksk_persistence_test_{id}")),
                auth_method: Some("api_key".into()),
                ..Default::default()
            }
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn adding_to_legacy_config_survives_reload_and_later_updates() {
            let directory = TestDirectory::new();
            let path = directory.0.join("credentials.json");
            std::fs::write(&path, serde_json::to_string(&credential(1)).unwrap()).unwrap();
            let config = CredentialsConfig::load(&path).unwrap();
            let multiple = config.is_multiple();
            assert!(!multiple);
            let manager = MultiTokenManager::new(
                Config::default(),
                config.into_sorted_credentials(),
                None,
                Some(path.clone()),
                multiple,
            )
            .unwrap();

            let id = manager.add_credential(credential(2)).await.unwrap();
            let saved = CredentialsConfig::load(&path).unwrap();
            assert!(
                saved.is_multiple(),
                "adding must migrate the legacy object to an array"
            );
            assert_eq!(saved.into_sorted_credentials().len(), 2);

            manager.set_disabled(id, true).unwrap();
            let saved = CredentialsConfig::load(&path).unwrap();
            let credentials = saved.into_sorted_credentials();
            assert!(
                credentials
                    .iter()
                    .find(|cred| cred.id == Some(id))
                    .unwrap()
                    .disabled
            );
            assert!(credentials.iter().any(|cred| cred.id == Some(1)));
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn failed_addition_does_not_leave_a_credential_and_can_be_retried() {
            for multiple in [true, false] {
                let directory = TestDirectory::new();
                let path = directory.0.join("credentials.json");
                // A directory at the file path reliably rejects writes on Windows and Unix.
                std::fs::create_dir(&path).unwrap();
                let manager = MultiTokenManager::new(
                    Config::default(),
                    vec![credential(1)],
                    None,
                    Some(path.clone()),
                    multiple,
                )
                .unwrap();

                assert!(manager.add_credential(credential(2)).await.is_err());
                assert_eq!(
                    manager.total_count(),
                    1,
                    "failed addition must be rolled back"
                );
                assert_eq!(manager.available_count(), 1);

                std::fs::remove_dir(&path).unwrap();
                let id = manager.add_credential(credential(2)).await.unwrap();
                assert_eq!(id, 2);
                let saved = CredentialsConfig::load(&path)
                    .unwrap()
                    .into_sorted_credentials();
                assert_eq!(saved.len(), 2);
                assert_eq!(saved.iter().filter(|cred| cred.id == Some(id)).count(), 1);
            }
        }
    }

    #[tokio::test]
    async fn test_add_credential_reject_duplicate_api_key() {
        let config = Config::default();

        let mut existing = KiroCredentials::default();
        existing.kiro_api_key = Some("ksk_existing_key".to_string());
        existing.auth_method = Some("api_key".to_string());

        let manager = MultiTokenManager::new(config, vec![existing], None, None, false).unwrap();

        let mut duplicate = KiroCredentials::default();
        duplicate.kiro_api_key = Some("ksk_existing_key".to_string());
        duplicate.auth_method = Some("api_key".to_string());

        let result = manager.add_credential(duplicate).await;
        assert!(result.is_err());
        assert!(result
            .err()
            .unwrap()
            .to_string()
            .contains("kiroApiKey 重复"));
    }

    #[tokio::test]
    async fn test_add_credential_api_key_empty_rejected() {
        let config = Config::default();
        let manager = MultiTokenManager::new(config, vec![], None, None, false).unwrap();

        let mut cred = KiroCredentials::default();
        cred.kiro_api_key = Some(String::new());
        cred.auth_method = Some("api_key".to_string());

        let result = manager.add_credential(cred).await;
        assert!(result.is_err());
        assert!(result
            .err()
            .unwrap()
            .to_string()
            .contains("kiroApiKey 为空"));
    }

    #[tokio::test]
    async fn test_add_credential_api_key_missing_key_rejected() {
        let config = Config::default();
        let manager = MultiTokenManager::new(config, vec![], None, None, false).unwrap();

        let mut cred = KiroCredentials::default();
        cred.auth_method = Some("api_key".to_string());
        // kiro_api_key is None

        let result = manager.add_credential(cred).await;
        assert!(result.is_err());
        assert!(result
            .err()
            .unwrap()
            .to_string()
            .contains("缺少 kiroApiKey"));
    }

    #[tokio::test]
    async fn test_add_credential_api_key_and_oauth_coexist() {
        let config = Config::default();

        let mut oauth_cred = KiroCredentials::default();
        oauth_cred.refresh_token = Some("a".repeat(150));

        let manager = MultiTokenManager::new(config, vec![oauth_cred], None, None, false).unwrap();

        let mut api_key_cred = KiroCredentials::default();
        api_key_cred.kiro_api_key = Some("ksk_new_key".to_string());
        api_key_cred.auth_method = Some("api_key".to_string());

        let result = manager.add_credential(api_key_cred).await;
        assert!(result.is_ok());
        assert_eq!(manager.total_count(), 2);
        assert_eq!(manager.available_count(), 2);
    }

    // MultiTokenManager 测试

    #[test]
    fn test_multi_token_manager_new() {
        let config = Config::default();
        let mut cred1 = KiroCredentials::default();
        cred1.priority = 0;
        let mut cred2 = KiroCredentials::default();
        cred2.priority = 1;

        let manager =
            MultiTokenManager::new(config, vec![cred1, cred2], None, None, false).unwrap();
        assert_eq!(manager.total_count(), 2);
        assert_eq!(manager.available_count(), 2);
    }

    #[test]
    fn test_multi_token_manager_empty_credentials() {
        let config = Config::default();
        let result = MultiTokenManager::new(config, vec![], None, None, false);
        // 支持 0 个凭据启动（可通过管理面板添加）
        assert!(result.is_ok());
        let manager = result.unwrap();
        assert_eq!(manager.total_count(), 0);
        assert_eq!(manager.available_count(), 0);
    }

    #[test]
    fn test_multi_token_manager_duplicate_ids() {
        let config = Config::default();
        let mut cred1 = KiroCredentials::default();
        cred1.id = Some(1);
        let mut cred2 = KiroCredentials::default();
        cred2.id = Some(1); // 重复 ID

        let result = MultiTokenManager::new(config, vec![cred1, cred2], None, None, false);
        assert!(result.is_err());
        let err_msg = result.err().unwrap().to_string();
        assert!(
            err_msg.contains("重复的凭据 ID"),
            "错误消息应包含 '重复的凭据 ID'，实际: {}",
            err_msg
        );
    }

    #[test]
    fn test_multi_token_manager_api_key_missing_kiro_api_key_auto_disabled() {
        let config = Config::default();

        // auth_method=api_key 但缺少 kiro_api_key → 应被自动禁用
        let mut bad_cred = KiroCredentials::default();
        bad_cred.auth_method = Some("api_key".to_string());
        // kiro_api_key 保持 None

        let mut good_cred = KiroCredentials::default();
        good_cred.refresh_token = Some("valid_token".to_string());

        let manager =
            MultiTokenManager::new(config, vec![bad_cred, good_cred], None, None, false).unwrap();
        assert_eq!(manager.total_count(), 2);
        assert_eq!(manager.available_count(), 1); // bad_cred 被禁用，只剩 1 个可用
    }

    #[test]
    fn test_multi_token_manager_api_key_with_kiro_api_key_not_disabled() {
        let config = Config::default();

        // auth_method=api_key 且有 kiro_api_key → 不应被禁用
        let mut cred = KiroCredentials::default();
        cred.auth_method = Some("api_key".to_string());
        cred.kiro_api_key = Some("ksk_test123".to_string());

        let manager = MultiTokenManager::new(config, vec![cred], None, None, false).unwrap();
        assert_eq!(manager.total_count(), 1);
        assert_eq!(manager.available_count(), 1);
    }

    #[test]
    fn test_multi_token_manager_report_failure() {
        let config = Config::default();
        let cred1 = KiroCredentials::default();
        let cred2 = KiroCredentials::default();

        let manager =
            MultiTokenManager::new(config, vec![cred1, cred2], None, None, false).unwrap();

        // 凭据会自动分配 ID（从 1 开始）
        // 前两次失败不会禁用（使用 ID 1）
        assert!(manager.report_failure(1));
        assert!(manager.report_failure(1));
        assert_eq!(manager.available_count(), 2);

        // 第三次失败会禁用第一个凭据
        assert!(manager.report_failure(1));
        assert_eq!(manager.available_count(), 1);

        // 继续失败第二个凭据（使用 ID 2）
        assert!(manager.report_failure(2));
        assert!(manager.report_failure(2));
        assert!(!manager.report_failure(2)); // 所有凭据都禁用了
        assert_eq!(manager.available_count(), 0);
    }

    #[test]
    fn test_multi_token_manager_report_success() {
        let config = Config::default();
        let cred = KiroCredentials::default();

        let manager = MultiTokenManager::new(config, vec![cred], None, None, false).unwrap();

        // 失败两次（使用 ID 1）
        manager.report_failure(1);
        manager.report_failure(1);

        // 成功后重置计数（使用 ID 1）
        manager.report_success(1);

        // 再失败两次不会禁用
        manager.report_failure(1);
        manager.report_failure(1);
        assert_eq!(manager.available_count(), 1);
    }

    #[test]
    fn test_multi_token_manager_switch_to_next() {
        let config = Config::default();
        let mut cred1 = KiroCredentials::default();
        cred1.refresh_token = Some("token1".to_string());
        let mut cred2 = KiroCredentials::default();
        cred2.refresh_token = Some("token2".to_string());

        let manager =
            MultiTokenManager::new(config, vec![cred1, cred2], None, None, false).unwrap();

        let initial_id = manager.snapshot().current_id;

        // 切换到下一个
        assert!(manager.switch_to_next());
        assert_ne!(manager.snapshot().current_id, initial_id);
    }

    #[test]
    fn test_set_load_balancing_mode_persists_to_config_file() {
        let config_path = std::env::temp_dir().join(format!(
            "kiro-load-balancing-{}.json",
            uuid::Uuid::new_v4()
        ));
        std::fs::write(&config_path, r#"{"loadBalancingMode":"priority"}"#).unwrap();

        let config = Config::load(&config_path).unwrap();
        let manager = MultiTokenManager::new(
            config,
            vec![KiroCredentials::default()],
            None,
            None,
            false,
        )
        .unwrap();

        manager
            .set_load_balancing_mode("balanced".to_string())
            .unwrap();

        let persisted = Config::load(&config_path).unwrap();
        assert_eq!(persisted.load_balancing_mode, "balanced");
        assert_eq!(manager.get_load_balancing_mode(), "balanced");

        std::fs::remove_file(&config_path).unwrap();
    }

    #[tokio::test]
    async fn test_multi_token_manager_acquire_context_auto_recovers_all_disabled() {
        let config = Config::default();
        let mut cred1 = KiroCredentials::default();
        cred1.access_token = Some("t1".to_string());
        cred1.expires_at = Some((Utc::now() + Duration::hours(1)).to_rfc3339());
        let mut cred2 = KiroCredentials::default();
        cred2.access_token = Some("t2".to_string());
        cred2.expires_at = Some((Utc::now() + Duration::hours(1)).to_rfc3339());

        let manager =
            MultiTokenManager::new(config, vec![cred1, cred2], None, None, false).unwrap();

        // 凭据会自动分配 ID（从 1 开始）
        for _ in 0..MAX_FAILURES_PER_CREDENTIAL {
            manager.report_failure(1);
        }
        for _ in 0..MAX_FAILURES_PER_CREDENTIAL {
            manager.report_failure(2);
        }

        assert_eq!(manager.available_count(), 0);

        // 应触发自愈：重置失败计数并重新启用，避免必须重启进程
        let ctx = manager.acquire_context(None).await.unwrap();
        assert!(ctx.token == "t1" || ctx.token == "t2");
        assert_eq!(manager.available_count(), 2);
    }

    #[tokio::test]
    async fn test_multi_token_manager_acquire_context_balanced_retries_until_bad_credential_disabled() {
        let mut config = Config::default();
        config.load_balancing_mode = "balanced".to_string();

        let mut bad_cred = KiroCredentials::default();
        bad_cred.priority = 0;
        bad_cred.refresh_token = Some("bad".to_string());

        let mut good_cred = KiroCredentials::default();
        good_cred.priority = 1;
        good_cred.access_token = Some("good-token".to_string());
        good_cred.expires_at = Some((Utc::now() + Duration::hours(1)).to_rfc3339());

        let manager =
            MultiTokenManager::new(config, vec![bad_cred, good_cred], None, None, false).unwrap();

        let ctx = manager.acquire_context(None).await.unwrap();
        assert_eq!(ctx.id, 2);
        assert_eq!(ctx.token, "good-token");
    }

    #[test]
    fn test_multi_token_manager_report_refresh_failure() {
        let config = Config::default();
        let cred1 = KiroCredentials::default();
        let cred2 = KiroCredentials::default();

        let manager =
            MultiTokenManager::new(config, vec![cred1, cred2], None, None, false).unwrap();

        assert_eq!(manager.available_count(), 2);
        for _ in 0..(MAX_FAILURES_PER_CREDENTIAL - 1) {
            assert!(manager.report_refresh_failure(1));
        }
        assert_eq!(manager.available_count(), 2);

        assert!(manager.report_refresh_failure(1));
        assert_eq!(manager.available_count(), 1);

        let snapshot = manager.snapshot();
        let first = snapshot.entries.iter().find(|e| e.id == 1).unwrap();
        assert!(first.disabled);
        assert_eq!(first.refresh_failure_count, MAX_FAILURES_PER_CREDENTIAL);
        assert_eq!(snapshot.current_id, 2);
    }

    #[tokio::test]
    async fn test_multi_token_manager_refresh_failure_disabled_is_not_auto_recovered() {
        let config = Config::default();
        let cred1 = KiroCredentials::default();
        let cred2 = KiroCredentials::default();

        let manager =
            MultiTokenManager::new(config, vec![cred1, cred2], None, None, false).unwrap();

        for _ in 0..MAX_FAILURES_PER_CREDENTIAL {
            manager.report_refresh_failure(1);
            manager.report_refresh_failure(2);
        }
        assert_eq!(manager.available_count(), 0);

        let err = manager.acquire_context(None).await.err().unwrap().to_string();
        assert!(
            err.contains("所有凭据均已禁用"),
            "错误应提示所有凭据禁用，实际: {}",
            err
        );
    }

    #[test]
    fn test_multi_token_manager_report_quota_exhausted() {
        let config = Config::default();
        let cred1 = KiroCredentials::default();
        let cred2 = KiroCredentials::default();

        let manager =
            MultiTokenManager::new(config, vec![cred1, cred2], None, None, false).unwrap();

        // 凭据会自动分配 ID（从 1 开始）
        assert_eq!(manager.available_count(), 2);
        assert!(manager.report_quota_exhausted(1));
        assert_eq!(manager.available_count(), 1);

        // 再禁用第二个后，无可用凭据
        assert!(!manager.report_quota_exhausted(2));
        assert_eq!(manager.available_count(), 0);
    }

    fn valid_token_credential() -> KiroCredentials {
        let mut cred = KiroCredentials::default();
        cred.access_token = Some("token".to_string());
        cred.expires_at = Some((Utc::now() + Duration::hours(1)).to_rfc3339());
        cred
    }

    #[test]
    fn test_disabled_reason_survives_persistence_round_trip() {
        for reason in [
            DisabledReason::Manual,
            DisabledReason::TooManyFailures,
            DisabledReason::TooManyRefreshFailures,
            DisabledReason::QuotaExceeded,
            DisabledReason::InvalidRefreshToken,
            DisabledReason::InvalidConfig,
        ] {
            assert_eq!(DisabledReason::from_persisted(Some(reason.as_str())), reason);
        }
        // 旧版本文件没有 disabledReason 字段，按手动禁用处理
        assert_eq!(DisabledReason::from_persisted(None), DisabledReason::Manual);
    }

    #[tokio::test]
    async fn test_auto_disabled_credential_self_heals_after_restart() {
        // 模拟重启：凭据文件里记录的是 TooManyFailures 自动禁用
        let mut cred = valid_token_credential();
        cred.disabled = true;
        cred.disabled_reason = Some("TooManyFailures".to_string());

        let manager =
            MultiTokenManager::new(Config::default(), vec![cred], None, None, false).unwrap();
        assert_eq!(manager.available_count(), 0);

        let ctx = manager.acquire_context(None).await.unwrap();
        assert_eq!(ctx.token, "token");
        assert_eq!(manager.available_count(), 1);
    }

    #[tokio::test]
    async fn test_manually_disabled_credential_is_not_healed_after_restart() {
        let mut cred = valid_token_credential();
        cred.disabled = true;

        let manager =
            MultiTokenManager::new(Config::default(), vec![cred], None, None, false).unwrap();
        assert!(manager.acquire_context(None).await.is_err());
        assert_eq!(manager.available_count(), 0);
    }

    #[tokio::test]
    async fn test_acquire_context_waits_for_rate_limit_cooldown() {
        let mut config = Config::default();
        config.rate_limit_cooldown_secs = 1;
        let manager =
            MultiTokenManager::new(config, vec![valid_token_credential()], None, None, false)
                .unwrap();

        manager.report_rate_limit(1);
        let start = Instant::now();
        let ctx = manager.acquire_context(None).await.unwrap();
        assert_eq!(ctx.id, 1);
        assert!(start.elapsed() >= StdDuration::from_millis(900), "应等待 429 冷却结束");
    }

    #[tokio::test]
    async fn test_acquire_context_rejects_long_rate_limit_cooldown_quickly() {
        let mut config = Config::default();
        config.rate_limit_cooldown_secs = MAX_RATE_LIMIT_WAIT.as_secs() + 60;
        let manager =
            MultiTokenManager::new(config, vec![valid_token_credential()], None, None, false)
                .unwrap();

        manager.report_rate_limit(1);
        let err = manager.acquire_context(None).await.err().unwrap().to_string();
        assert!(err.contains("429"), "实际: {}", err);
        // 429 冷却不应被误判为禁用
        assert_eq!(manager.available_count(), 1);
    }

    #[test]
    fn test_huge_rate_limit_cooldown_does_not_panic() {
        let mut config = Config::default();
        config.rate_limit_cooldown_secs = u64::MAX;
        let manager =
            MultiTokenManager::new(config, vec![valid_token_credential()], None, None, false)
                .unwrap();
        manager.report_rate_limit(1);
        manager.set_rate_limit_cooldown_secs(u64::MAX);
        assert_eq!(manager.get_rate_limit_cooldown_secs(), MAX_CONFIG_DURATION_SECS);
    }

    #[test]
    fn test_zero_cooldown_max_requests_does_not_panic() {
        let mut cred = valid_token_credential();
        cred.cooldown_enabled = Some(true);
        cred.cooldown_seconds = Some(60);
        cred.cooldown_max_requests = Some(0);
        let manager =
            MultiTokenManager::new(Config::default(), vec![cred], None, None, false).unwrap();

        for _ in 0..3 {
            assert!(matches!(
                manager.select_next_credential(None),
                SelectResult::Ready(1, _)
            ));
        }
    }

    #[test]
    fn test_earliest_available_with_zero_max_requests() {
        let now = Instant::now();
        let history = VecDeque::new();
        assert_eq!(
            MultiTokenManager::earliest_available(&history, now, StdDuration::from_secs(60), 0),
            now
        );
    }

    #[test]
    fn test_apply_refreshed_tokens_keeps_concurrent_changes() {
        let mut before = KiroCredentials::default();
        before.refresh_token = Some("rt1".to_string());
        before.priority = 5;

        // 刷新期间 Admin 修改了优先级并回填了 ARN
        let mut current = before.clone();
        current.priority = 1;
        current.profile_arn = Some("arn:real".to_string());

        let mut refreshed = before.clone();
        refreshed.access_token = Some("new-at".to_string());
        refreshed.refresh_token = Some("rt2".to_string());
        refreshed.expires_at = Some("2099-01-01T00:00:00Z".to_string());

        apply_refreshed_tokens(&mut current, &before, &refreshed);
        assert_eq!(current.access_token.as_deref(), Some("new-at"));
        assert_eq!(current.refresh_token.as_deref(), Some("rt2"));
        assert_eq!(current.expires_at.as_deref(), Some("2099-01-01T00:00:00Z"));
        assert_eq!(current.priority, 1);
        assert_eq!(current.profile_arn.as_deref(), Some("arn:real"));
    }

    #[test]
    fn test_new_expires_at_defaults_when_missing() {
        for expires_in in [None, Some(0), Some(-5)] {
            let parsed = DateTime::parse_from_rfc3339(&new_expires_at(expires_in)).unwrap();
            let remaining = parsed.with_timezone(&Utc) - Utc::now();
            assert!(remaining > Duration::minutes(55), "expires_in={:?}", expires_in);
        }
    }

    #[tokio::test]
    async fn test_multi_token_manager_quota_disabled_is_not_auto_recovered() {
        let config = Config::default();
        let cred1 = KiroCredentials::default();
        let cred2 = KiroCredentials::default();

        let manager =
            MultiTokenManager::new(config, vec![cred1, cred2], None, None, false).unwrap();

        manager.report_quota_exhausted(1);
        manager.report_quota_exhausted(2);
        assert_eq!(manager.available_count(), 0);

        let err = manager.acquire_context(None).await.err().unwrap().to_string();
        assert!(
            err.contains("所有凭据均已禁用"),
            "错误应提示所有凭据禁用，实际: {}",
            err
        );
        assert_eq!(manager.available_count(), 0);
    }

    // ============ 凭据级 Region 优先级测试 ============

    #[test]
    fn test_credential_region_priority_uses_credential_auth_region() {
        // 凭据配置了 auth_region 时，应使用凭据的 auth_region
        let mut config = Config::default();
        config.region = "us-west-2".to_string();

        let mut credentials = KiroCredentials::default();
        credentials.auth_region = Some("eu-west-1".to_string());

        let region = credentials.effective_auth_region(&config);
        assert_eq!(region, "eu-west-1");
    }

    #[test]
    fn test_credential_region_priority_fallback_to_credential_region() {
        // 凭据未配置 auth_region 但配置了 region 时，应回退到凭据.region
        let mut config = Config::default();
        config.region = "us-west-2".to_string();

        let mut credentials = KiroCredentials::default();
        credentials.region = Some("eu-central-1".to_string());

        let region = credentials.effective_auth_region(&config);
        assert_eq!(region, "eu-central-1");
    }

    #[test]
    fn test_credential_region_priority_fallback_to_config() {
        // 凭据未配置 auth_region 和 region 时，应回退到 config
        let mut config = Config::default();
        config.region = "us-west-2".to_string();

        let credentials = KiroCredentials::default();
        assert!(credentials.auth_region.is_none());
        assert!(credentials.region.is_none());

        let region = credentials.effective_auth_region(&config);
        assert_eq!(region, "us-west-2");
    }

    #[test]
    fn test_multiple_credentials_use_respective_regions() {
        // 多凭据场景下，不同凭据使用各自的 auth_region
        let mut config = Config::default();
        config.region = "ap-northeast-1".to_string();

        let mut cred1 = KiroCredentials::default();
        cred1.auth_region = Some("us-east-1".to_string());

        let mut cred2 = KiroCredentials::default();
        cred2.region = Some("eu-west-1".to_string());

        let cred3 = KiroCredentials::default(); // 无 region，使用 config

        assert_eq!(cred1.effective_auth_region(&config), "us-east-1");
        assert_eq!(cred2.effective_auth_region(&config), "eu-west-1");
        assert_eq!(cred3.effective_auth_region(&config), "ap-northeast-1");
    }

    #[test]
    fn test_idc_oidc_endpoint_uses_credential_auth_region() {
        // 验证 IdC OIDC endpoint URL 使用凭据 auth_region
        let mut config = Config::default();
        config.region = "us-west-2".to_string();

        let mut credentials = KiroCredentials::default();
        credentials.auth_region = Some("eu-central-1".to_string());

        let region = credentials.effective_auth_region(&config);
        let refresh_url = format!("https://oidc.{}.amazonaws.com/token", region);

        assert_eq!(refresh_url, "https://oidc.eu-central-1.amazonaws.com/token");
    }

    #[test]
    fn test_social_refresh_endpoint_uses_credential_auth_region() {
        // 验证 Social refresh endpoint URL 使用凭据 auth_region
        let mut config = Config::default();
        config.region = "us-west-2".to_string();

        let mut credentials = KiroCredentials::default();
        credentials.auth_region = Some("ap-southeast-1".to_string());

        let region = credentials.effective_auth_region(&config);
        let refresh_url = format!("https://prod.{}.auth.desktop.kiro.dev/refreshToken", region);

        assert_eq!(
            refresh_url,
            "https://prod.ap-southeast-1.auth.desktop.kiro.dev/refreshToken"
        );
    }

    #[test]
    fn test_api_call_uses_effective_api_region() {
        // 验证 API 调用使用 effective_api_region
        let mut config = Config::default();
        config.region = "us-west-2".to_string();

        let mut credentials = KiroCredentials::default();
        credentials.region = Some("eu-west-1".to_string());

        // 凭据.region 不参与 api_region 回退链
        let api_region = credentials.effective_api_region(&config);
        let api_host = format!("q.{}.amazonaws.com", api_region);

        assert_eq!(api_host, "q.us-west-2.amazonaws.com");
    }

    #[test]
    fn test_api_call_uses_credential_api_region() {
        // 凭据配置了 api_region 时，API 调用应使用凭据的 api_region
        let mut config = Config::default();
        config.region = "us-west-2".to_string();

        let mut credentials = KiroCredentials::default();
        credentials.api_region = Some("eu-central-1".to_string());

        let api_region = credentials.effective_api_region(&config);
        let api_host = format!("q.{}.amazonaws.com", api_region);

        assert_eq!(api_host, "q.eu-central-1.amazonaws.com");
    }

    #[test]
    fn test_credential_region_empty_string_treated_as_set() {
        // 空字符串 auth_region 被视为已设置（虽然不推荐，但行为应一致）
        let mut config = Config::default();
        config.region = "us-west-2".to_string();

        let mut credentials = KiroCredentials::default();
        credentials.auth_region = Some("".to_string());

        let region = credentials.effective_auth_region(&config);
        // 空字符串被视为已设置，不会回退到 config
        assert_eq!(region, "");
    }

    #[test]
    fn test_auth_and_api_region_independent() {
        // auth_region 和 api_region 互不影响
        let mut config = Config::default();
        config.region = "default".to_string();

        let mut credentials = KiroCredentials::default();
        credentials.auth_region = Some("auth-only".to_string());
        credentials.api_region = Some("api-only".to_string());

        assert_eq!(credentials.effective_auth_region(&config), "auth-only");
        assert_eq!(credentials.effective_api_region(&config), "api-only");
    }

    #[test]
    fn usage_rest_urls_carry_real_profile_arn() {
        let credentials = KiroCredentials {
            profile_arn: Some(
                "arn:aws:codewhisperer:us-east-1:123456789012:profile/REAL123".to_string(),
            ),
            ..Default::default()
        };
        let arn = credentials.effective_profile_arn();
        let host = "q.us-east-1.amazonaws.com";

        assert_eq!(
            usage_limits_url(host, arn),
            "https://q.us-east-1.amazonaws.com/getUsageLimits?origin=AI_EDITOR&resourceType=AGENTIC_REQUEST&isEmailRequired=true&profileArn=arn%3Aaws%3Acodewhisperer%3Aus-east-1%3A123456789012%3Aprofile%2FREAL123"
        );
        assert_eq!(
            usage_api_attempts(&credentials, &["us-east-1", "eu-central-1"]),
            vec![
                ("us-east-1", arn),
                ("us-east-1", None),
                ("eu-central-1", arn),
                ("eu-central-1", None),
            ]
        );
    }

    #[test]
    fn usage_rest_attempts_skip_builder_id_placeholder() {
        use crate::kiro::model::credentials::BUILDER_ID_PROFILE_ARN;

        let credentials = KiroCredentials {
            profile_arn: Some(BUILDER_ID_PROFILE_ARN.to_string()),
            ..Default::default()
        };

        assert_eq!(credentials.effective_profile_arn(), None);
        assert_eq!(
            usage_api_attempts(&credentials, &["us-east-1", "eu-central-1"]),
            vec![("us-east-1", None), ("eu-central-1", None)]
        );
    }

    #[test]
    fn usage_rest_region_candidates_follow_sso_region() {
        assert_eq!(
            rest_api_region_candidates("eu-west-1"),
            ["eu-central-1", "us-east-1"]
        );
        assert_eq!(
            rest_api_region_candidates("ap-southeast-1"),
            ["us-east-1", "eu-central-1"]
        );
    }

    #[test]
    fn set_user_preference_body_uses_only_real_profile_arn() {
        use crate::kiro::model::credentials::BUILDER_ID_PROFILE_ARN;

        let real = KiroCredentials {
            profile_arn: Some("arn:aws:codewhisperer:us-east-1:1:profile/REAL".to_string()),
            ..Default::default()
        };
        assert_eq!(
            set_user_preference_body(&real, "ENABLED"),
            serde_json::json!({
                "overageConfiguration": { "overageStatus": "ENABLED" },
                "profileArn": "arn:aws:codewhisperer:us-east-1:1:profile/REAL",
            })
        );

        let builder = KiroCredentials {
            profile_arn: Some(BUILDER_ID_PROFILE_ARN.to_string()),
            ..Default::default()
        };
        assert_eq!(
            set_user_preference_body(&builder, "DISABLED"),
            serde_json::json!({
                "overageConfiguration": { "overageStatus": "DISABLED" },
            })
        );
    }
}
