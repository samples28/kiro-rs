//! Kiro API Provider
//!
//! 核心组件，负责与 Kiro API 通信
//! 支持流式和非流式请求
//! 支持多凭据故障转移和重试
//! 支持按凭据级 endpoint 切换不同 Kiro API 端点

use reqwest::Client;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::time::sleep;

use crate::common::debug_log::SharedRequestLog;
use crate::http_client::{ProxyConfig, build_streaming_client};
use crate::kiro::endpoint::{KiroEndpoint, RequestContext};
use crate::kiro::machine_id;
use crate::kiro::model::credentials::KiroCredentials;
use crate::kiro::token_manager::{CallContext, MultiTokenManager};
use crate::model::config::TlsBackend;
use parking_lot::Mutex;

/// 每个凭据的最大重试次数
const MAX_RETRIES_PER_CREDENTIAL: usize = 3;

/// 总重试次数硬上限（避免无限重试）
const MAX_TOTAL_RETRIES: usize = 15;

/// 上游空闲读超时（秒）：连续这么久收不到任何数据才判定失败。
/// 不使用整体超时，否则超过 12 分钟的长回答（如长时间 thinking）会被硬切断。
const UPSTREAM_IDLE_TIMEOUT_SECS: u64 = 720;

/// Kiro API Provider
///
/// 核心组件，负责与 Kiro API 通信
/// 支持多凭据故障转移和重试机制
/// 按凭据 `endpoint` 字段选择 [`KiroEndpoint`] 实现
pub struct KiroProvider {
    token_manager: Arc<MultiTokenManager>,
    /// 全局代理配置（用于凭据无自定义代理时的回退）
    global_proxy: Option<ProxyConfig>,
    /// Client 缓存：key = effective proxy config, value = reqwest::Client
    /// 不同代理配置的凭据使用不同的 Client，共享相同代理的凭据复用 Client
    client_cache: Mutex<HashMap<Option<ProxyConfig>, Client>>,
    /// TLS 后端配置
    tls_backend: TlsBackend,
    /// 端点实现注册表（key: endpoint 名称）
    endpoints: HashMap<String, Arc<dyn KiroEndpoint>>,
    /// 默认端点名称（凭据未指定 endpoint 时使用）
    default_endpoint: String,
    /// 已确认不存在真实 profileArn 的凭据身份。
    ///
    /// 纯 BuilderID 凭据没有可用的 Enterprise profile；缓存其空结果，避免每次
    /// 聊天或 MCP 请求都重复调用 ListAvailableProfiles。缓存键包含 refreshToken
    /// 指纹，避免删除最大 ID 后新增凭据复用该 ID 时继承旧的空结果。
    profile_resolution_attempted: Mutex<HashSet<ProfileResolutionCacheKey>>,
}

impl KiroProvider {
    /// 创建带代理配置和端点注册表的 KiroProvider 实例
    ///
    /// # Arguments
    /// * `token_manager` - 多凭据 Token 管理器
    /// * `proxy` - 全局代理配置
    /// * `endpoints` - 端点名 → 实现的注册表（至少包含 `default_endpoint` 对应条目）
    /// * `default_endpoint` - 凭据未显式指定 endpoint 时使用的名称
    pub fn with_proxy(
        token_manager: Arc<MultiTokenManager>,
        proxy: Option<ProxyConfig>,
        endpoints: HashMap<String, Arc<dyn KiroEndpoint>>,
        default_endpoint: String,
    ) -> Self {
        assert!(
            endpoints.contains_key(&default_endpoint),
            "默认端点 {} 未在 endpoints 注册表中",
            default_endpoint
        );
        let tls_backend = token_manager.config().tls_backend;
        // 预热：构建全局代理对应的 Client
        let initial_client = build_streaming_client(proxy.as_ref(), UPSTREAM_IDLE_TIMEOUT_SECS, tls_backend)
            .expect("创建 HTTP 客户端失败");
        let mut cache = HashMap::new();
        cache.insert(proxy.clone(), initial_client);

        Self {
            token_manager,
            global_proxy: proxy,
            client_cache: Mutex::new(cache),
            tls_backend,
            endpoints,
            default_endpoint,
            profile_resolution_attempted: Mutex::new(HashSet::new()),
        }
    }

    /// 获取共享的 MultiTokenManager，handler 用其访问运行时配置（如缓存倍率）
    pub fn token_manager(&self) -> &Arc<MultiTokenManager> {
        &self.token_manager
    }

    /// 根据凭据的代理配置获取（或创建并缓存）对应的 reqwest::Client
    fn client_for(&self, credentials: &KiroCredentials) -> anyhow::Result<Client> {
        let effective = credentials.effective_proxy(self.global_proxy.as_ref());
        let mut cache = self.client_cache.lock();
        if let Some(client) = cache.get(&effective) {
            return Ok(client.clone());
        }
        let client = build_streaming_client(effective.as_ref(), UPSTREAM_IDLE_TIMEOUT_SECS, self.tls_backend)?;
        cache.insert(effective, client.clone());
        Ok(client)
    }

    /// 根据凭据选择 endpoint 实现
    fn endpoint_for(
        &self,
        credentials: &KiroCredentials,
    ) -> anyhow::Result<Arc<dyn KiroEndpoint>> {
        let name = credentials
            .endpoint
            .as_deref()
            .unwrap_or(&self.default_endpoint);
        self.endpoints
            .get(name)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("未知端点: {}", name))
    }

    /// 将 Enterprise / IdC 账号的真实 profileArn 写入本次请求上下文。
    ///
    /// generateAssistantResponse 和 MCP 都会校验 profileArn；缺失或使用 BuilderID
    /// 占位符时，Enterprise / IdC token 会被上游拒绝。查询失败不阻断本次请求，
    /// 这样 BuilderID 及临时网络错误仍沿用既有兼容路径。
    async fn ensure_profile_arn(&self, ctx: &mut CallContext) {
        if !needs_profile_arn_resolution(&ctx.credentials) {
            return;
        }

        let cache_key = profile_resolution_cache_key(ctx.id, &ctx.credentials);
        if self.profile_resolution_attempted.lock().contains(&cache_key) {
            return;
        }

        match self
            .token_manager
            .resolve_profile_arn_for(ctx.id, &ctx.token)
            .await
        {
            Ok(Some(arn)) => {
                ctx.credentials.profile_arn = Some(arn);
            }
            Ok(None) => {
                self.profile_resolution_attempted.lock().insert(cache_key);
            }
            Err(error) => {
                tracing::warn!(
                    "凭据 #{} 解析真实 profileArn 失败（按现有 profileArn 继续）: {}",
                    ctx.id,
                    error
                );
            }
        }
    }

    /// 发送非流式 API 请求
    ///
    /// 支持多凭据故障转移（见 [`Self::call_api_with_retry`]）
    /// 返回 (凭据 ID, Response)
    pub async fn call_api(
        &self,
        request_body: &str,
        original_model: Option<&str>,
        request_log: Option<&SharedRequestLog>,
    ) -> anyhow::Result<(u64, reqwest::Response)> {
        self.call_api_with_retry(request_body, false, original_model, request_log)
            .await
    }

    /// 发送流式 API 请求
    /// 返回 (凭据 ID, Response)
    pub async fn call_api_stream(
        &self,
        request_body: &str,
        original_model: Option<&str>,
        request_log: Option<&SharedRequestLog>,
    ) -> anyhow::Result<(u64, reqwest::Response)> {
        self.call_api_with_retry(request_body, true, original_model, request_log)
            .await
    }

    /// 发送 MCP API 请求（WebSearch 等工具调用）
    pub async fn call_mcp(&self, request_body: &str) -> anyhow::Result<reqwest::Response> {
        self.call_mcp_with_retry(request_body).await
    }

    /// 内部方法：带重试逻辑的 MCP API 调用
    async fn call_mcp_with_retry(&self, request_body: &str) -> anyhow::Result<reqwest::Response> {
        let total_credentials = self.token_manager.total_count();
        let max_retries = (total_credentials * MAX_RETRIES_PER_CREDENTIAL).min(MAX_TOTAL_RETRIES);
        let mut last_error: Option<anyhow::Error> = None;
        let mut force_refreshed: HashSet<u64> = HashSet::new();

        for attempt in 0..max_retries {
            // MCP 调用（WebSearch 等工具）不涉及模型选择，无需按模型过滤凭据
            let mut ctx = match self.token_manager.acquire_context(None).await {
                Ok(c) => c,
                Err(e) => {
                    last_error = Some(e);
                    continue;
                }
            };

            self.ensure_profile_arn(&mut ctx).await;

            let config = self.token_manager.config();
            let machine_id = machine_id::generate_from_credentials(&ctx.credentials, config);

            let endpoint = match self.endpoint_for(&ctx.credentials) {
                Ok(e) => e,
                Err(e) => {
                    last_error = Some(e);
                    // endpoint 解析失败：记为失败，换下一张凭据
                    self.token_manager.report_failure(ctx.id);
                    continue;
                }
            };

            let rctx = RequestContext {
                credentials: &ctx.credentials,
                token: &ctx.token,
                machine_id: &machine_id,
                config,
            };

            let url = endpoint.mcp_url(&rctx);
            let body = endpoint.transform_mcp_body(request_body, &rctx);

            // 代理配置无效（如 URL 无法解析）时计入该凭据失败并换下一张，而不是直接跳出重试循环
            let client = match self.client_for(&ctx.credentials) {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!("凭据 #{} 构建 HTTP 客户端失败（代理配置无效？）: {}", ctx.id, e);
                    last_error = Some(e);
                    self.token_manager.report_failure(ctx.id);
                    continue;
                }
            };
            let base = client
                .post(&url)
                .body(body)
                .header("content-type", "application/json")
                .header("Connection", "close");
            let request = endpoint.decorate_mcp(base, &rctx);

            let response = match request.send().await {
                Ok(resp) => resp,
                Err(e) => {
                    tracing::warn!(
                        "MCP 请求发送失败（尝试 {}/{}）: {}",
                        attempt + 1,
                        max_retries,
                        e
                    );
                    last_error = Some(e.into());
                    if attempt + 1 < max_retries {
                        sleep(Self::retry_delay(attempt)).await;
                    }
                    continue;
                }
            };

            let status = response.status();

            // 成功响应
            if status.is_success() {
                self.token_manager.report_success(ctx.id);
                return Ok(response);
            }

            // 失败响应
            let body = response.text().await.unwrap_or_default();

            // 402 Payment Required：额度/付费限制，禁用凭据并故障转移
            if status.as_u16() == 402 {
                let has_available = self.token_manager.report_quota_exhausted(ctx.id);
                if !has_available {
                    anyhow::bail!("MCP 请求失败（所有凭据已用尽）: {} {}", status, body);
                }
                last_error = Some(anyhow::anyhow!("MCP 请求失败: {} {}", status, body));
                continue;
            }

            // 400 Bad Request
            if status.as_u16() == 400 {
                anyhow::bail!("MCP 请求失败: {} {}", status, body);
            }

            // 401/403 凭据问题
            if matches!(status.as_u16(), 401 | 403) {
                // token 被上游失效：先尝试 force-refresh，每凭据仅一次机会
                if endpoint.is_bearer_token_invalid(&body) && !force_refreshed.contains(&ctx.id) {
                    force_refreshed.insert(ctx.id);
                    tracing::info!("凭据 #{} token 疑似被上游失效，尝试强制刷新", ctx.id);
                    if self.token_manager.force_refresh_token_for(ctx.id).await.is_ok() {
                        tracing::info!("凭据 #{} token 强制刷新成功，重试请求", ctx.id);
                        continue;
                    }
                    tracing::warn!("凭据 #{} token 强制刷新失败，计入失败", ctx.id);
                }

                let has_available = self.token_manager.report_failure(ctx.id);
                if !has_available {
                    anyhow::bail!("MCP 请求失败（所有凭据已用尽）: {} {}", status, body);
                }
                last_error = Some(anyhow::anyhow!("MCP 请求失败: {} {}", status, body));
                continue;
            }

            // 瞬态错误
            if matches!(status.as_u16(), 408 | 429) || status.is_server_error() {
                tracing::warn!(
                    "MCP 请求失败（上游瞬态错误，尝试 {}/{}）: {} {}",
                    attempt + 1,
                    max_retries,
                    status,
                    body
                );
                last_error = Some(anyhow::anyhow!("MCP 请求失败: {} {}", status, body));
                if attempt + 1 < max_retries {
                    sleep(Self::retry_delay(attempt)).await;
                }
                continue;
            }

            // 其他 4xx
            if status.is_client_error() {
                anyhow::bail!("MCP 请求失败: {} {}", status, body);
            }

            // 兜底
            last_error = Some(anyhow::anyhow!("MCP 请求失败: {} {}", status, body));
            if attempt + 1 < max_retries {
                sleep(Self::retry_delay(attempt)).await;
            }
        }

        Err(last_error.unwrap_or_else(|| {
            anyhow::anyhow!("MCP 请求失败：已达到最大重试次数（{}次）", max_retries)
        }))
    }

    /// 内部方法：带重试逻辑的 API 调用
    ///
    /// 重试策略：
    /// - 每个凭据最多重试 MAX_RETRIES_PER_CREDENTIAL 次
    /// - 总重试次数 = min(凭据数量 × 每凭据重试次数, MAX_TOTAL_RETRIES)
    /// - 硬上限 9 次，避免无限重试
    async fn call_api_with_retry(
        &self,
        request_body: &str,
        is_stream: bool,
        original_model: Option<&str>,
        request_log: Option<&SharedRequestLog>,
    ) -> anyhow::Result<(u64, reqwest::Response)> {
        let total_credentials = self.token_manager.total_count();
        let max_retries = (total_credentials * MAX_RETRIES_PER_CREDENTIAL).min(MAX_TOTAL_RETRIES);
        let mut last_error: Option<anyhow::Error> = None;
        let mut force_refreshed: HashSet<u64> = HashSet::new();
        let api_type = if is_stream { "流式" } else { "非流式" };

        // 用原始模型进行凭据调度（free 模型匹配需要原始模型 ID）
        let model = original_model.map(|s| s.to_string())
            .or_else(|| Self::extract_model_from_request(request_body));
        let requested_model = model
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("请求中缺少模型 ID"))?;

        for attempt in 0..max_retries {
            // 获取调用上下文（绑定 index、credentials、token）
            let mut ctx = match self.token_manager.acquire_context(model.as_deref()).await {
                Ok(c) => c,
                Err(e) => {
                    last_error = Some(e);
                    continue;
                }
            };

            // 按本次选中的账号解析模型；切换账号或更新映射后不能沿用上次的目标模型。
            let Some(actual_model) = self
                .token_manager
                .resolve_model_for_credential(requested_model, &ctx.credentials)
            else {
                last_error = Some(anyhow::anyhow!(
                    "凭据 #{} 没有匹配请求模型 {} 的映射",
                    ctx.id,
                    requested_model
                ));
                continue;
            };

            self.ensure_profile_arn(&mut ctx).await;

            let config = self.token_manager.config();
            let machine_id = machine_id::generate_from_credentials(&ctx.credentials, config);

            let endpoint = match self.endpoint_for(&ctx.credentials) {
                Ok(e) => e,
                Err(e) => {
                    last_error = Some(e);
                    self.token_manager.report_failure(ctx.id);
                    continue;
                }
            };

            let rctx = RequestContext {
                credentials: &ctx.credentials,
                token: &ctx.token,
                machine_id: &machine_id,
                config,
            };

            let url = endpoint.api_url(&rctx);
            let mapped_body = Self::rewrite_request_model(request_body, &actual_model)?;
            let body = endpoint.transform_api_body(&mapped_body, &rctx);
            tracing::debug!(
                "凭据 #{}: 请求模型 {}，实际转发模型 {}",
                ctx.id,
                requested_model,
                actual_model
            );
            // 阶段 2：记录本次实际发送的请求，包含账号映射及端点加工后的字段。
            // 重试时覆盖为最新尝试，确保成功和错误日志都对应最后一次上游请求。
            if let Some(log) = request_log {
                let value = serde_json::from_str(&body)
                    .unwrap_or_else(|_| serde_json::Value::String(body.clone()));
                log.lock().set_kiro_request(value);
            }
            tracing::debug!("Kiro request body: {}", body);

            // 代理配置无效（如 URL 无法解析）时计入该凭据失败并换下一张，而不是直接跳出重试循环
            let client = match self.client_for(&ctx.credentials) {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!("凭据 #{} 构建 HTTP 客户端失败（代理配置无效？）: {}", ctx.id, e);
                    last_error = Some(e);
                    self.token_manager.report_failure(ctx.id);
                    continue;
                }
            };
            let base = client
                .post(&url)
                .body(body)
                .header("content-type", "application/json")
                .header("Connection", "close");
            let request = endpoint.decorate_api(base, &rctx);

            let send_start = Instant::now();
            let response = match request.send().await {
                Ok(resp) => {
                    let ttfb_ms = send_start.elapsed().as_millis() as u64;
                    self.token_manager.report_ttfb(ctx.id, ttfb_ms);
                    resp
                }
                Err(e) => {
                    tracing::warn!(
                        "API 请求发送失败（尝试 {}/{}）: {}",
                        attempt + 1,
                        max_retries,
                        e
                    );
                    // 网络错误通常是上游/链路瞬态问题，不应导致"禁用凭据"或"切换凭据"
                    // （否则一段时间网络抖动会把所有凭据都误禁用，需要重启才能恢复）
                    last_error = Some(e.into());
                    if attempt + 1 < max_retries {
                        sleep(Self::retry_delay(attempt)).await;
                    }
                    continue;
                }
            };

            let status = response.status();

            // 成功响应
            if status.is_success() {
                self.token_manager.report_success(ctx.id);
                return Ok((ctx.id, response));
            }

            // 失败响应：读取 body 用于日志/错误信息
            let body = response.text().await.unwrap_or_default();

            // 402 Payment Required：额度/付费限制，禁用凭据并故障转移
            if status.as_u16() == 402 {
                tracing::warn!(
                    "API 请求失败（额度/付费限制，禁用凭据并切换，尝试 {}/{}）: {} {}",
                    attempt + 1,
                    max_retries,
                    status,
                    body
                );

                let has_available = self.token_manager.report_quota_exhausted(ctx.id);
                if !has_available {
                    anyhow::bail!(
                        "{} API 请求失败（所有凭据已用尽）: {} {}",
                        api_type,
                        status,
                        body
                    );
                }

                last_error = Some(anyhow::anyhow!(
                    "{} API 请求失败: {} {}",
                    api_type,
                    status,
                    body
                ));
                continue;
            }

            // 400 Bad Request - 请求问题，重试/切换凭据无意义
            if status.as_u16() == 400 {
                anyhow::bail!("{} API 请求失败: {} {}", api_type, status, body);
            }

            // 401/403 - 更可能是凭据/权限问题：计入失败并允许故障转移
            if matches!(status.as_u16(), 401 | 403) {
                tracing::warn!(
                    "API 请求失败（可能为凭据错误，尝试 {}/{}）: {} {}",
                    attempt + 1,
                    max_retries,
                    status,
                    body
                );

                // token 被上游失效：先尝试 force-refresh，每凭据仅一次机会
                if endpoint.is_bearer_token_invalid(&body) && !force_refreshed.contains(&ctx.id) {
                    force_refreshed.insert(ctx.id);
                    tracing::info!("凭据 #{} token 疑似被上游失效，尝试强制刷新", ctx.id);
                    if self.token_manager.force_refresh_token_for(ctx.id).await.is_ok() {
                        tracing::info!("凭据 #{} token 强制刷新成功，重试请求", ctx.id);
                        continue;
                    }
                    tracing::warn!("凭据 #{} token 强制刷新失败，计入失败", ctx.id);
                }

                let has_available = self.token_manager.report_failure(ctx.id);
                if !has_available {
                    anyhow::bail!(
                        "{} API 请求失败（所有凭据已用尽）: {} {}",
                        api_type,
                        status,
                        body
                    );
                }

                last_error = Some(anyhow::anyhow!(
                    "{} API 请求失败: {} {}",
                    api_type,
                    status,
                    body
                ));
                continue;
            }

            // 429/408/5xx - 瞬态上游错误：重试但不禁用或切换凭据
            // （避免 429 high traffic / 502 high load 等瞬态错误把所有凭据锁死）
            if matches!(status.as_u16(), 408 | 429) || status.is_server_error() {
                if status.as_u16() == 429 {
                    self.token_manager.report_rate_limit(ctx.id);
                }
                tracing::warn!(
                    "API 请求失败（上游瞬态错误，尝试 {}/{}）: {} {}",
                    attempt + 1,
                    max_retries,
                    status,
                    body
                );
                last_error = Some(anyhow::anyhow!(
                    "{} API 请求失败: {} {}",
                    api_type,
                    status,
                    body
                ));
                if attempt + 1 < max_retries {
                    sleep(Self::retry_delay(attempt)).await;
                }
                continue;
            }

            // 其他 4xx - 通常为请求/配置问题：直接返回，不计入凭据失败
            if status.is_client_error() {
                anyhow::bail!("{} API 请求失败: {} {}", api_type, status, body);
            }

            // 兜底：当作可重试的瞬态错误处理（不切换凭据）
            tracing::warn!(
                "API 请求失败（未知错误，尝试 {}/{}）: {} {}",
                attempt + 1,
                max_retries,
                status,
                body
            );
            last_error = Some(anyhow::anyhow!(
                "{} API 请求失败: {} {}",
                api_type,
                status,
                body
            ));
            if attempt + 1 < max_retries {
                sleep(Self::retry_delay(attempt)).await;
            }
        }

        // 所有重试都失败
        Err(last_error.unwrap_or_else(|| {
            anyhow::anyhow!(
                "{} API 请求失败：已达到最大重试次数（{}次）",
                api_type,
                max_retries
            )
        }))
    }

    /// 只改写协议中的模型字段，保留正文、工具参数等内容。
    /// 每次重试都从原始请求体生成，防止 Free 与付费账号切换时残留旧映射。
    fn rewrite_request_model(request_body: &str, model: &str) -> anyhow::Result<String> {
        use anyhow::Context;
        use serde_json::Value;

        let mut body: Value =
            serde_json::from_str(request_body).context("解析模型映射请求体失败")?;
        let current = body
            .pointer_mut("/conversationState/currentMessage/userInputMessage")
            .and_then(Value::as_object_mut)
            .context("模型映射请求体缺少当前用户消息")?;
        current.insert("modelId".into(), Value::String(model.to_string()));

        if let Some(history) = body
            .pointer_mut("/conversationState/history")
            .and_then(Value::as_array_mut)
        {
            for message in history {
                if let Some(user) = message
                    .get_mut("userInputMessage")
                    .and_then(Value::as_object_mut)
                {
                    user.insert("modelId".into(), Value::String(model.to_string()));
                }
            }
        }
        serde_json::to_string(&body).context("序列化模型映射请求体失败")
    }

    /// 从请求体中提取模型信息
    ///
    /// 尝试解析 JSON 请求体，提取 conversationState.currentMessage.userInputMessage.modelId
    fn extract_model_from_request(request_body: &str) -> Option<String> {
        use serde_json::Value;

        let json: Value = serde_json::from_str(request_body).ok()?;

        json.get("conversationState")?
            .get("currentMessage")?
            .get("userInputMessage")?
            .get("modelId")?
            .as_str()
            .map(|s| s.to_string())
    }

    fn retry_delay(attempt: usize) -> Duration {
        // 指数退避 + 少量抖动，避免上游抖动时放大故障
        const BASE_MS: u64 = 200;
        const MAX_MS: u64 = 2_000;
        let exp = BASE_MS.saturating_mul(2u64.saturating_pow(attempt.min(6) as u32));
        let backoff = exp.min(MAX_MS);
        let jitter_max = (backoff / 4).max(1);
        let jitter = fastrand::u64(0..=jitter_max);
        Duration::from_millis(backoff.saturating_add(jitter))
    }
}

fn needs_profile_arn_resolution(credentials: &KiroCredentials) -> bool {
    use crate::kiro::model::credentials::is_placeholder_profile_arn;

    if credentials.is_api_key_credential() {
        return false;
    }

    match credentials.profile_arn.as_deref().map(str::trim) {
        None | Some("") => true,
        Some(arn) => is_placeholder_profile_arn(arn),
    }
}

type ProfileResolutionCacheKey = (u64, String);

/// 用稳定的 refreshToken 指纹区分同一数值 ID 的不同 OAuth 凭据。
///
/// `add_credential` 按当前最大 ID + 1 分配 ID，因此删除最大 ID 后可能复用该值。
/// 不能让新凭据命中旧 BuilderID 的“无 profile”缓存。
fn profile_resolution_cache_key(
    id: u64,
    credentials: &KiroCredentials,
) -> ProfileResolutionCacheKey {
    let mut hasher = Sha256::new();
    hasher.update(
        credentials
            .refresh_token
            .as_deref()
            .unwrap_or_default()
            .as_bytes(),
    );
    (id, format!("{:x}", hasher.finalize()))
}

#[cfg(test)]
#[path = "tests/provider_model_mapping.rs"]
mod model_mapping_tests;

#[cfg(test)]
mod tests {
    use super::{needs_profile_arn_resolution, profile_resolution_cache_key};
    use crate::kiro::model::credentials::{KiroCredentials, BUILDER_ID_PROFILE_ARN};

    #[test]
    fn unresolved_profile_arn_is_resolved_only_for_oauth_credentials() {
        assert!(needs_profile_arn_resolution(&KiroCredentials::default()));

        let blank = KiroCredentials {
            profile_arn: Some("   ".to_string()),
            ..Default::default()
        };
        assert!(needs_profile_arn_resolution(&blank));

        let builder = KiroCredentials {
            profile_arn: Some(BUILDER_ID_PROFILE_ARN.to_string()),
            ..Default::default()
        };
        assert!(needs_profile_arn_resolution(&builder));

        let real = KiroCredentials {
            profile_arn: Some(
                "arn:aws:codewhisperer:us-east-1:123456789012:profile/REAL".to_string(),
            ),
            ..Default::default()
        };
        assert!(!needs_profile_arn_resolution(&real));

        let api_key = KiroCredentials {
            kiro_api_key: Some("ksk_test".to_string()),
            ..Default::default()
        };
        assert!(!needs_profile_arn_resolution(&api_key));
    }

    #[test]
    fn profile_resolution_cache_key_does_not_cross_reused_credential_id() {
        let first = KiroCredentials {
            refresh_token: Some("first-refresh-token".to_string()),
            ..Default::default()
        };
        let replacement = KiroCredentials {
            refresh_token: Some("replacement-refresh-token".to_string()),
            ..Default::default()
        };

        assert_eq!(
            profile_resolution_cache_key(7, &first),
            profile_resolution_cache_key(7, &first)
        );
        assert_ne!(
            profile_resolution_cache_key(7, &first),
            profile_resolution_cache_key(7, &replacement)
        );
        assert_ne!(
            profile_resolution_cache_key(7, &first),
            profile_resolution_cache_key(8, &first)
        );
    }
}
