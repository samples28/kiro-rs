//! Admin API 业务逻辑服务

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;

use chrono::Utc;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

use crate::kiro::model::credentials::KiroCredentials;
use crate::kiro::token_manager::MultiTokenManager;

use super::error::AdminServiceError;
use super::types::{
    AddCredentialRequest, AddCredentialResponse, BalanceResponse, CacheInterruptResponse,
    CacheModeResponse, CacheRatiosResponse, CooldownConfigResponse, CredentialStatusItem,
    CredentialsStatusResponse, LoadBalancingModeResponse, ModelMappingItem,
    ModelMappingsResponse, ModelPriceItem, ModelPricesResponse, ProxyLatencyResponse,
    ProxyPoolItemResponse, ProxyPoolResponse, RateLimitCooldownResponse,
    SetCacheInterruptRequest, SetCacheModeRequest, SetCacheRatiosRequest,
    SetCooldownConfigRequest, SetCredentialCooldownRequest, SetLoadBalancingModeRequest,
    SetModelMappingsRequest, SetModelPricesRequest, SetProxyRequest,
};

/// 余额缓存过期时间（秒），5 分钟
const BALANCE_CACHE_TTL_SECS: i64 = 300;

/// 缓存的余额条目（含时间戳）
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CachedBalance {
    /// 缓存时间（Unix 秒）
    cached_at: f64,
    /// 缓存的余额数据
    data: BalanceResponse,
}

/// Admin 服务
///
/// 封装所有 Admin API 的业务逻辑
pub struct AdminService {
    token_manager: Arc<MultiTokenManager>,
    balance_cache: Mutex<HashMap<u64, CachedBalance>>,
    cache_path: Option<PathBuf>,
    /// 已注册的端点名称集合（用于 add_credential 校验）
    known_endpoints: HashSet<String>,
    /// 代理池
    proxy_pool: super::proxy_pool::ProxyPool,
    /// 代理分配锁：防止并发分配时多个凭据拿到同一个代理
    proxy_alloc_lock: tokio::sync::Mutex<()>,
}

impl AdminService {
    pub fn new(
        token_manager: Arc<MultiTokenManager>,
        known_endpoints: impl IntoIterator<Item = String>,
    ) -> Self {
        let cache_path = token_manager
            .cache_dir()
            .map(|d| d.join("kiro_balance_cache.json"));

        let proxy_pool_path = token_manager
            .cache_dir()
            .map(|d| d.join("proxies.json"));

        let balance_cache = Self::load_balance_cache_from(&cache_path);

        Self {
            token_manager,
            balance_cache: Mutex::new(balance_cache),
            cache_path,
            known_endpoints: known_endpoints.into_iter().collect(),
            proxy_pool: super::proxy_pool::ProxyPool::new(proxy_pool_path),
            proxy_alloc_lock: tokio::sync::Mutex::new(()),
        }
    }

    pub fn token_manager(&self) -> &MultiTokenManager {
        &self.token_manager
    }

    /// 获取所有凭据状态
    pub fn get_all_credentials(&self) -> CredentialsStatusResponse {
        let snapshot = self.token_manager.snapshot();
        let default_endpoint = self.token_manager.config().default_endpoint.clone();

        let mut credentials: Vec<CredentialStatusItem> = snapshot
            .entries
            .into_iter()
            .map(|entry| CredentialStatusItem {
                id: entry.id,
                priority: entry.priority,
                disabled: entry.disabled,
                failure_count: entry.failure_count,
                is_current: entry.id == snapshot.current_id,
                expires_at: entry.expires_at,
                auth_method: entry.auth_method,
                has_profile_arn: entry.has_profile_arn,
                refresh_token_hash: entry.refresh_token_hash,
                api_key_hash: entry.api_key_hash,
                masked_api_key: entry.masked_api_key,
                email: entry.email,
                success_count: entry.success_count,
                last_used_at: entry.last_used_at.clone(),
                has_proxy: entry.has_proxy,
                proxy_url: entry.proxy_url,
                refresh_failure_count: entry.refresh_failure_count,
                disabled_reason: entry.disabled_reason,
                endpoint: entry.endpoint.unwrap_or_else(|| default_endpoint.clone()),
                cooldown_enabled: entry.cooldown_enabled,
                cooldown_seconds: entry.cooldown_seconds,
                cooldown_max_requests: entry.cooldown_max_requests,
                rpm: entry.rpm,
                last_ttfb_ms: entry.last_ttfb_ms,
                rate_limit_count: entry.rate_limit_count,
                rate_limit_cooling: entry.rate_limit_cooling,
            })
            .collect();

        // 按优先级排序（数字越小优先级越高）
        credentials.sort_by_key(|c| c.priority);

        CredentialsStatusResponse {
            total: snapshot.total,
            available: snapshot.available,
            current_id: snapshot.current_id,
            rpm: snapshot.rpm,
            cooldown_enabled: snapshot.cooldown_enabled,
            cooldown_seconds: snapshot.cooldown_seconds,
            cooldown_max_requests: snapshot.cooldown_max_requests,
            credentials,
        }
    }

    /// 设置凭据禁用状态
    pub fn set_disabled(&self, id: u64, disabled: bool) -> Result<(), AdminServiceError> {
        // 先获取当前凭据 ID，用于判断是否需要切换
        let snapshot = self.token_manager.snapshot();
        let current_id = snapshot.current_id;

        self.token_manager
            .set_disabled(id, disabled)
            .map_err(|e| self.classify_error(e, id))?;

        // 只有禁用的是当前凭据时才尝试切换到下一个
        if disabled && id == current_id {
            let _ = self.token_manager.switch_to_next();
        }
        Ok(())
    }

    /// 设置凭据优先级
    pub fn set_priority(&self, id: u64, priority: u32) -> Result<(), AdminServiceError> {
        self.token_manager
            .set_priority(id, priority)
            .map_err(|e| self.classify_error(e, id))
    }

    /// 重置失败计数并重新启用
    pub fn reset_and_enable(&self, id: u64) -> Result<(), AdminServiceError> {
        self.token_manager
            .reset_and_enable(id)
            .map_err(|e| self.classify_error(e, id))
    }

    /// 获取凭据余额（带缓存）
    pub async fn get_balance(&self, id: u64) -> Result<BalanceResponse, AdminServiceError> {
        self.get_balance_with_option(id, false).await
    }

    pub async fn get_balance_with_option(&self, id: u64, force: bool) -> Result<BalanceResponse, AdminServiceError> {
        // 先查缓存（force 时跳过）
        if !force {
            let cache = self.balance_cache.lock();
            if let Some(cached) = cache.get(&id) {
                let now = Utc::now().timestamp() as f64;
                if (now - cached.cached_at) < BALANCE_CACHE_TTL_SECS as f64 {
                    tracing::debug!("凭据 #{} 余额命中缓存", id);
                    return Ok(cached.data.clone());
                }
            }
        }

        // 缓存未命中或已过期，从上游获取
        let balance = self.fetch_balance(id).await?;

        // 更新缓存
        {
            let mut cache = self.balance_cache.lock();
            cache.insert(
                id,
                CachedBalance {
                    cached_at: Utc::now().timestamp() as f64,
                    data: balance.clone(),
                },
            );
        }
        self.save_balance_cache();

        Ok(balance)
    }

    /// 从上游获取余额（无缓存）
    async fn fetch_balance(&self, id: u64) -> Result<BalanceResponse, AdminServiceError> {
        let usage = self
            .token_manager
            .get_usage_limits_for(id)
            .await
            .map_err(|e| self.classify_balance_error(e, id))?;

        let current_usage = usage.current_usage();
        let usage_limit = usage.usage_limit();
        let remaining = (usage_limit - current_usage).max(0.0);
        let usage_percentage = if usage_limit > 0.0 {
            (current_usage / usage_limit * 100.0).min(100.0)
        } else {
            0.0
        };

        Ok(BalanceResponse {
            id,
            subscription_title: usage.subscription_title().map(|s| s.to_string()),
            current_usage,
            usage_limit,
            remaining,
            usage_percentage,
            next_reset_at: usage.next_date_reset,
            email: usage.user_email().map(|s| s.to_string()),
            overage_status: Some(if current_usage > usage_limit {
                "overaging".to_string()
            } else if usage.is_overage_enabled() {
                "enabled".to_string()
            } else {
                "disabled".to_string()
            }),
        })
    }

    /// 添加新凭据
    pub async fn add_credential(
        &self,
        req: AddCredentialRequest,
    ) -> Result<AddCredentialResponse, AdminServiceError> {
        // 校验端点名：未指定则默认合法，指定则必须已注册
        if let Some(ref name) = req.endpoint {
            if !self.known_endpoints.contains(name) {
                let mut known: Vec<&str> =
                    self.known_endpoints.iter().map(|s| s.as_str()).collect();
                known.sort();
                return Err(AdminServiceError::InvalidCredential(format!(
                    "未知端点 \"{}\"，已注册端点: {:?}",
                    name, known
                )));
            }
        }

        // 用锁保护「分配代理 + 写入凭据」，防止并发批量导入时多号分到同一IP
        let (credential_id, assigned_proxy_info) = {
            let _alloc_guard = self.proxy_alloc_lock.lock().await;

            // 自动分配代理（如果请求中未指定且开启了自动分配）
            let (proxy_url, proxy_username, proxy_password) = if req.proxy_url.is_some() {
                (req.proxy_url, req.proxy_username, req.proxy_password)
            } else if req.auto_allocate_proxy {
                if let Some(allocated) = self.allocate_proxy() {
                    (Some(allocated.url), allocated.username, allocated.password)
                } else {
                    (None, None, None)
                }
            } else {
                (None, None, None)
            };

            let proxy_info_for_record = proxy_url.clone().map(|url| {
                (url, proxy_username.clone(), proxy_password.clone())
            });

            // 构建凭据对象
            let new_cred = KiroCredentials {
                id: None,
                access_token: None,
                refresh_token: req.refresh_token,
                profile_arn: None,
                expires_at: None,
                auth_method: Some(req.auth_method),
                client_id: req.client_id,
                client_secret: req.client_secret,
                priority: req.priority,
                region: req.region,
                auth_region: req.auth_region,
                api_region: req.api_region,
                machine_id: req.machine_id,
                email: req.email.clone(),
                password: req.password,
                subscription_title: None,
                proxy_url,
                proxy_username,
                proxy_password,
                disabled: false,
                kiro_api_key: req.kiro_api_key,
                endpoint: req.endpoint,
                cooldown_enabled: req.cooldown_enabled,
                cooldown_seconds: req.cooldown_seconds,
                cooldown_max_requests: req.cooldown_max_requests,
            };

            // 调用 token_manager 添加凭据（在锁内完成，确保下一次分配能看到本次写入）
            let cid = self.token_manager
                .add_credential(new_cred)
                .await
                .map_err(|e| self.classify_add_error(e))?;
            (cid, proxy_info_for_record)
        };

        // 记录代理历史绑定
        if let Some((url, username, password)) = assigned_proxy_info {
            self.proxy_pool.record_assignment(
                &url,
                username.as_deref(),
                password.as_deref(),
                credential_id,
            );
        }

        // 主动获取订阅等级和余额（锁外执行，不阻塞其他分配）
        let balance = match self.get_balance(credential_id).await {
            Ok(b) => Some(b),
            Err(e) => {
                tracing::warn!("添加凭据后获取余额失败（不影响凭据添加）: {}", e);
                None
            }
        };

        let email = balance.as_ref().and_then(|b| b.email.clone()).or(req.email);

        Ok(AddCredentialResponse {
            success: true,
            message: format!("凭据添加成功，ID: {}", credential_id),
            credential_id,
            email,
            balance,
        })
    }

    /// 删除凭据
    pub fn delete_credential(&self, id: u64) -> Result<(), AdminServiceError> {
        self.token_manager
            .delete_credential(id)
            .map_err(|e| self.classify_delete_error(e, id))?;

        // 清理已删除凭据的余额缓存
        {
            let mut cache = self.balance_cache.lock();
            cache.remove(&id);
        }
        self.save_balance_cache();

        Ok(())
    }

    /// 获取负载均衡模式
    pub fn get_load_balancing_mode(&self) -> LoadBalancingModeResponse {
        LoadBalancingModeResponse {
            mode: self.token_manager.get_load_balancing_mode(),
        }
    }

    /// 设置负载均衡模式
    pub fn set_load_balancing_mode(
        &self,
        req: SetLoadBalancingModeRequest,
    ) -> Result<LoadBalancingModeResponse, AdminServiceError> {
        // 验证模式值
        if req.mode != "priority" && req.mode != "balanced" {
            return Err(AdminServiceError::InvalidCredential(
                "mode 必须是 'priority' 或 'balanced'".to_string(),
            ));
        }

        self.token_manager
            .set_load_balancing_mode(req.mode.clone())
            .map_err(|e| AdminServiceError::InternalError(e.to_string()))?;

        Ok(LoadBalancingModeResponse { mode: req.mode })
    }

    /// 强制刷新指定凭据的 Token
    pub async fn force_refresh_token(&self, id: u64) -> Result<(), AdminServiceError> {
        self.token_manager
            .force_refresh_token_for(id)
            .await
            .map_err(|e| self.classify_balance_error(e, id))
    }

    /// 获取全局冷却限流配置
    pub fn get_cooldown_config(&self) -> CooldownConfigResponse {
        let (enabled, seconds, max_requests) = self.token_manager.get_cooldown_config();
        CooldownConfigResponse {
            enabled,
            seconds,
            max_requests,
        }
    }

    /// 设置全局冷却限流配置
    pub fn set_cooldown_config(
        &self,
        req: SetCooldownConfigRequest,
    ) -> Result<CooldownConfigResponse, AdminServiceError> {
        self.token_manager
            .set_cooldown_config(req.enabled, req.seconds, req.max_requests)
            .map_err(|e| AdminServiceError::InvalidCredential(e.to_string()))?;

        Ok(CooldownConfigResponse {
            enabled: req.enabled,
            seconds: req.seconds,
            max_requests: req.max_requests,
        })
    }

    /// 设置单个凭据的冷却限流配置
    pub fn set_credential_cooldown(
        &self,
        id: u64,
        req: SetCredentialCooldownRequest,
    ) -> Result<(), AdminServiceError> {
        self.token_manager
            .set_credential_cooldown(id, req.enabled, req.seconds, req.max_requests)
            .map_err(|e| self.classify_error(e, id))
    }

    /// 获取缓存 token 估算倍率
    pub fn get_cache_ratios(&self) -> CacheRatiosResponse {
        let (creation, read, uncached, first_turn, output) = self.token_manager.get_cache_ratios();
        CacheRatiosResponse { creation, read, uncached, first_turn, output }
    }

    /// 设置缓存 token 估算倍率
    pub fn set_cache_ratios(
        &self,
        req: SetCacheRatiosRequest,
    ) -> Result<CacheRatiosResponse, AdminServiceError> {
        self.token_manager
            .set_cache_ratios(req.creation, req.read, req.uncached, req.first_turn, req.output)
            .map_err(|e| AdminServiceError::InvalidCredential(e.to_string()))?;

        Ok(CacheRatiosResponse {
            creation: req.creation,
            read: req.read,
            uncached: req.uncached,
            first_turn: req.first_turn,
            output: req.output,
        })
    }

    /// 获取缓存模式
    pub fn get_cache_mode(&self) -> CacheModeResponse {
        CacheModeResponse { mode: self.token_manager.get_cache_mode() }
    }

    /// 设置缓存模式
    pub fn set_cache_mode(
        &self,
        req: SetCacheModeRequest,
    ) -> Result<CacheModeResponse, AdminServiceError> {
        self.token_manager
            .set_cache_mode(req.mode.clone())
            .map_err(|e| AdminServiceError::InvalidCredential(e.to_string()))?;
        Ok(CacheModeResponse { mode: req.mode })
    }

    /// 获取缓存间歇中断配置
    pub fn get_cache_interrupt(&self) -> CacheInterruptResponse {
        let (enabled, min_secs, max_secs, duration_secs) = self.token_manager.get_cache_interrupt_config();
        CacheInterruptResponse { enabled, min_secs, max_secs, duration_secs }
    }

    /// 设置缓存间歇中断配置
    pub fn set_cache_interrupt(
        &self,
        req: SetCacheInterruptRequest,
    ) -> Result<CacheInterruptResponse, AdminServiceError> {
        self.token_manager
            .set_cache_interrupt_config(req.enabled, req.min_secs, req.max_secs, req.duration_secs)
            .map_err(|e| AdminServiceError::InvalidCredential(e.to_string()))?;
        Ok(CacheInterruptResponse {
            enabled: req.enabled,
            min_secs: req.min_secs,
            max_secs: req.max_secs,
            duration_secs: req.duration_secs,
        })
    }

    /// 获取模型映射
    pub fn get_model_mappings(&self) -> ModelMappingsResponse {
        let mappings = self.token_manager.get_model_mappings();
        let free_model_mappings = self.token_manager.get_free_model_mappings();
        ModelMappingsResponse {
            mappings: mappings
                .into_iter()
                .map(|m| ModelMappingItem { from: m.from, to: m.to })
                .collect(),
            free_model_mappings: free_model_mappings
                .into_iter()
                .map(|m| ModelMappingItem { from: m.from, to: m.to })
                .collect(),
        }
    }

    /// 设置模型映射
    pub fn set_model_mappings(
        &self,
        req: SetModelMappingsRequest,
    ) -> Result<ModelMappingsResponse, AdminServiceError> {
        let config_mappings: Vec<crate::model::config::ModelMapping> = req
            .mappings
            .iter()
            .map(|m| crate::model::config::ModelMapping {
                from: m.from.clone(),
                to: m.to.clone(),
            })
            .collect();

        self.token_manager
            .set_model_mappings(config_mappings)
            .map_err(|e| AdminServiceError::InvalidCredential(e.to_string()))?;

        // 如果提供了 free_model_mappings，也更新
        if let Some(free_mappings) = &req.free_model_mappings {
            let config_free_mappings: Vec<crate::model::config::ModelMapping> = free_mappings
                .iter()
                .map(|m| crate::model::config::ModelMapping {
                    from: m.from.clone(),
                    to: m.to.clone(),
                })
                .collect();
            self.token_manager
                .set_free_model_mappings(config_free_mappings)
                .map_err(|e| AdminServiceError::InvalidCredential(e.to_string()))?;
        }

        Ok(self.get_model_mappings())
    }

    /// 设置模型价格（持久化到 config.json）
    pub fn set_model_prices(
        &self,
        req: SetModelPricesRequest,
    ) -> Result<ModelPricesResponse, AdminServiceError> {
        use crate::model::config::{Config, ModelPrice};

        let config_path = self.token_manager.config().config_path()
            .ok_or_else(|| AdminServiceError::InternalError("配置文件路径未知".to_string()))?
            .to_path_buf();

        let mut config = Config::load(&config_path)
            .map_err(|e| AdminServiceError::InternalError(e.to_string()))?;

        let new_prices: HashMap<String, ModelPrice> = req.prices.iter()
            .map(|(k, v)| (k.clone(), ModelPrice {
                input: v.input,
                output: v.output,
                cache_read: v.cache_read,
                cache_write: v.cache_write,
            }))
            .collect();

        config.model_prices = new_prices;
        config.save()
            .map_err(|e| AdminServiceError::InternalError(e.to_string()))?;

        let items = req.prices.into_iter()
            .map(|(k, v)| (k, ModelPriceItem { input: v.input, output: v.output, cache_read: v.cache_read, cache_write: v.cache_write }))
            .collect();
        Ok(ModelPricesResponse { prices: items })
    }
    pub fn set_proxy(
        &self,
        id: u64,
        req: SetProxyRequest,
    ) -> Result<(), AdminServiceError> {
        // 获取该凭据的旧代理信息
        let old_proxy_info: Option<(String, Option<String>, Option<String>)> = {
            let configs = self.token_manager.get_all_proxy_configs();
            let snapshot = self.token_manager.snapshot();
            snapshot.entries.iter()
                .find(|e| e.id == id)
                .and_then(|e| e.proxy_url.as_ref())
                .and_then(|old_url| {
                    configs.iter().find(|(u, _, _)| u == old_url).cloned()
                })
        };

        // 空字符串视为清除代理
        let proxy_url = req.proxy_url.filter(|s| !s.trim().is_empty());
        let proxy_username = req.proxy_username.filter(|s| !s.trim().is_empty());
        let proxy_password = req.proxy_password.filter(|s| !s.trim().is_empty());

        // 如果有旧代理且正在切换到不同代理，标记旧代理为有问题
        if let Some((old_url, old_user, old_pass)) = old_proxy_info {
            let is_changing = proxy_url.as_deref() != Some(old_url.as_str());
            if is_changing {
                self.proxy_pool.flag_proxy(&old_url, old_user.as_deref(), old_pass.as_deref());
            }
        }

        // 记录新代理的历史绑定
        if let Some(ref url) = proxy_url {
            self.proxy_pool.record_assignment(
                url,
                proxy_username.as_deref(),
                proxy_password.as_deref(),
                id,
            );
        }

        self.token_manager
            .set_proxy(id, proxy_url, proxy_username, proxy_password)
            .map_err(|e| self.classify_error(e, id))
    }

    /// 代理延迟检测
    pub async fn get_proxy_latency(&self, id: u64) -> Result<ProxyLatencyResponse, AdminServiceError> {
        let proxy = self
            .token_manager
            .get_credential_proxy(id)
            .map_err(|e| self.classify_error(e, id))?;

        let start = std::time::Instant::now();
        let client = crate::http_client::build_client(
            proxy.as_ref(),
            10, // 10秒超时
            self.token_manager.config().tls_backend,
        )
        .map_err(|e| AdminServiceError::InternalError(format!("构建 HTTP 客户端失败: {}", e)))?;

        match client.get("https://q.us-east-1.amazonaws.com").send().await {
            Ok(_) => {
                let latency = start.elapsed().as_millis() as u64;
                Ok(ProxyLatencyResponse {
                    latency_ms: Some(latency),
                    error: None,
                })
            }
            Err(e) => Ok(ProxyLatencyResponse {
                latency_ms: None,
                error: Some(e.to_string()),
            }),
        }
    }

    // ============ 代理池 ============

    /// 获取已使用的代理组合列表（从凭据原始数据获取完整 proxy 信息）
    fn used_proxy_list(&self) -> Vec<(String, Option<String>, Option<String>)> {
        self.token_manager.get_all_proxy_configs()
    }

    /// 获取代理池状态
    pub fn get_proxy_pool(&self) -> ProxyPoolResponse {
        let used = self.used_proxy_list();
        let proxies = self.proxy_pool.list();
        let (total, available) = self.proxy_pool.stats(&used);

        // 构建凭据代理 → ID 映射（按 url+username+password 完整匹配）
        let all_cred_proxies = self.token_manager.get_all_proxy_configs_with_ids();
        let cred_ids: Vec<(String, Option<String>, Option<String>, u64)> = all_cred_proxies;

        let items = proxies
            .into_iter()
            .map(|p| {
                let used_by = cred_ids.iter().find(|(url, user, pass, _)| {
                    *url == p.url && *user == p.username && *pass == p.password
                }).map(|(_, _, _, id)| *id);
                ProxyPoolItemResponse {
                    id: p.id,
                    url: p.url.clone(),
                    username: p.username,
                    password: p.password,
                    used_by_credential_id: used_by,
                    flagged: p.flagged,
                    history_count: p.assigned_credential_ids.len(),
                }
            })
            .collect();

        ProxyPoolResponse {
            total,
            available,
            proxies: items,
        }
    }

    /// 批量导入代理（先测活，不通的跳过）
    pub async fn import_proxies(&self, text: &str) -> (Vec<super::proxy_pool::ProxyEntry>, usize) {
        let parsed = self.proxy_pool.parse_lines(text);
        let mut added = Vec::new();
        let mut failed = 0usize;

        // 10 并发测活
        let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(10));
        let mut handles = Vec::new();

        for entry in parsed {
            let sem = semaphore.clone();
            let proxy_config = crate::http_client::ProxyConfig {
                url: entry.url.clone(),
                username: entry.username.clone(),
                password: entry.password.clone(),
            };
            let tls_backend = self.token_manager.config().tls_backend;

            let handle = tokio::spawn(async move {
                let _permit = sem.acquire().await.unwrap();
                let ok = match crate::http_client::build_client(
                    Some(&proxy_config),
                    10,
                    tls_backend,
                ) {
                    Ok(client) => client.get("http://httpbin.org/status/200").send().await.is_ok(),
                    Err(_) => false,
                };
                (entry, ok)
            });
            handles.push(handle);
        }

        for handle in handles {
            if let Ok((entry, ok)) = handle.await {
                if ok {
                    if self.proxy_pool.add_entry(entry.clone()) {
                        added.push(entry);
                    }
                } else {
                    failed += 1;
                    tracing::info!("代理测活失败，跳过: {}", entry.url);
                }
            } else {
                failed += 1;
            }
        }

        (added, failed)
    }

    /// 删除代理池中的代理
    pub fn delete_pool_proxy(&self, id: u64) -> bool {
        self.proxy_pool.remove(id)
    }

    /// 获取 429 冷却时长
    pub fn get_rate_limit_cooldown(&self) -> RateLimitCooldownResponse {
        RateLimitCooldownResponse {
            seconds: self.token_manager.get_rate_limit_cooldown_secs(),
        }
    }

    /// 设置 429 冷却时长
    pub fn set_rate_limit_cooldown(&self, seconds: u64) -> RateLimitCooldownResponse {
        self.token_manager.set_rate_limit_cooldown_secs(seconds);
        RateLimitCooldownResponse { seconds }
    }

    /// 测试代理池中某个代理的连通性
    pub async fn test_pool_proxy(&self, id: u64) -> Result<ProxyLatencyResponse, AdminServiceError> {
        let proxy_entry = self.proxy_pool.list().into_iter().find(|p| p.id == id)
            .ok_or_else(|| AdminServiceError::InternalError("代理不存在".to_string()))?;

        let proxy_config = crate::http_client::ProxyConfig {
            url: proxy_entry.url,
            username: proxy_entry.username,
            password: proxy_entry.password,
        };

        let start = std::time::Instant::now();
        let client = crate::http_client::build_client(
            Some(&proxy_config),
            10,
            self.token_manager.config().tls_backend,
        )
        .map_err(|e| AdminServiceError::InternalError(format!("构建客户端失败: {}", e)))?;

        match client.get("https://q.us-east-1.amazonaws.com").send().await {
            Ok(_) => {
                let latency = start.elapsed().as_millis() as u64;
                Ok(ProxyLatencyResponse {
                    latency_ms: Some(latency),
                    error: None,
                })
            }
            Err(e) => Ok(ProxyLatencyResponse {
                latency_ms: None,
                error: Some(e.to_string()),
            }),
        }
    }

    /// 分配一个未使用的代理（用于 add_credential 自动分配）
    pub fn allocate_proxy(&self) -> Option<super::proxy_pool::ProxyEntry> {
        let used = self.used_proxy_list();
        self.proxy_pool.allocate_unused(&used)
    }

    // ============ 余额缓存持久化 ============

    fn load_balance_cache_from(cache_path: &Option<PathBuf>) -> HashMap<u64, CachedBalance> {
        let path = match cache_path {
            Some(p) => p,
            None => return HashMap::new(),
        };

        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => return HashMap::new(),
        };

        // 文件中使用字符串 key 以兼容 JSON 格式
        let map: HashMap<String, CachedBalance> = match serde_json::from_str(&content) {
            Ok(m) => m,
            Err(e) => {
                tracing::warn!("解析余额缓存失败，将忽略: {}", e);
                return HashMap::new();
            }
        };

        let now = Utc::now().timestamp() as f64;
        map.into_iter()
            .filter_map(|(k, v)| {
                let id = k.parse::<u64>().ok()?;
                // 丢弃超过 TTL 的条目
                if (now - v.cached_at) < BALANCE_CACHE_TTL_SECS as f64 {
                    Some((id, v))
                } else {
                    None
                }
            })
            .collect()
    }

    fn save_balance_cache(&self) {
        let path = match &self.cache_path {
            Some(p) => p,
            None => return,
        };

        // 持有锁期间完成序列化和写入，防止并发损坏
        let cache = self.balance_cache.lock();
        let map: HashMap<String, &CachedBalance> =
            cache.iter().map(|(k, v)| (k.to_string(), v)).collect();

        match serde_json::to_string_pretty(&map) {
            Ok(json) => {
                if let Err(e) = std::fs::write(path, json) {
                    tracing::warn!("保存余额缓存失败: {}", e);
                }
            }
            Err(e) => tracing::warn!("序列化余额缓存失败: {}", e),
        }
    }

    // ============ 错误分类 ============

    /// 分类简单操作错误（set_disabled, set_priority, reset_and_enable）
    fn classify_error(&self, e: anyhow::Error, id: u64) -> AdminServiceError {
        let msg = e.to_string();
        if msg.contains("不存在") {
            AdminServiceError::NotFound { id }
        } else {
            AdminServiceError::InternalError(msg)
        }
    }

    /// 分类余额查询错误（可能涉及上游 API 调用）
    fn classify_balance_error(&self, e: anyhow::Error, id: u64) -> AdminServiceError {
        let msg = e.to_string();

        // 1. 凭据不存在
        if msg.contains("不存在") {
            return AdminServiceError::NotFound { id };
        }

        // 2. API Key 凭据不支持刷新：客户端请求错误，映射为 400
        if msg.contains("API Key 凭据不支持刷新") {
            return AdminServiceError::InvalidCredential(msg);
        }

        // 3. 上游服务错误特征：HTTP 响应错误或网络错误
        let is_upstream_error =
            // HTTP 响应错误（来自 refresh_*_token 的错误消息）
            msg.contains("凭证已过期或无效") ||
            msg.contains("权限不足") ||
            msg.contains("已被限流") ||
            msg.contains("服务器错误") ||
            msg.contains("Token 刷新失败") ||
            msg.contains("暂时不可用") ||
            // 网络错误（reqwest 错误）
            msg.contains("error trying to connect") ||
            msg.contains("connection") ||
            msg.contains("timeout") ||
            msg.contains("timed out");

        if is_upstream_error {
            AdminServiceError::UpstreamError(msg)
        } else {
            // 4. 默认归类为内部错误（本地验证失败、配置错误等）
            // 包括：缺少 refreshToken、refreshToken 已被截断、无法生成 machineId 等
            AdminServiceError::InternalError(msg)
        }
    }

    /// 分类添加凭据错误
    fn classify_add_error(&self, e: anyhow::Error) -> AdminServiceError {
        let msg = e.to_string();

        // 凭据验证失败（refreshToken 无效、格式错误等）
        let is_invalid_credential = msg.contains("缺少 refreshToken")
            || msg.contains("refreshToken 为空")
            || msg.contains("refreshToken 已被截断")
            || msg.contains("凭据已存在")
            || msg.contains("refreshToken 重复")
            || msg.contains("kiroApiKey 重复")
            || msg.contains("缺少 kiroApiKey")
            || msg.contains("kiroApiKey 为空")
            || msg.contains("凭证已过期或无效")
            || msg.contains("权限不足")
            || msg.contains("已被限流");

        if is_invalid_credential {
            AdminServiceError::InvalidCredential(msg)
        } else if msg.contains("error trying to connect")
            || msg.contains("connection")
            || msg.contains("timeout")
        {
            AdminServiceError::UpstreamError(msg)
        } else {
            AdminServiceError::InternalError(msg)
        }
    }

    /// 分类删除凭据错误
    fn classify_delete_error(&self, e: anyhow::Error, id: u64) -> AdminServiceError {
        let msg = e.to_string();
        if msg.contains("不存在") {
            AdminServiceError::NotFound { id }
        } else if msg.contains("只能删除已禁用的凭据") || msg.contains("请先禁用凭据") {
            AdminServiceError::InvalidCredential(msg)
        } else {
            AdminServiceError::InternalError(msg)
        }
    }
}
