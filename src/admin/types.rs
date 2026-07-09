//! Admin API 类型定义

use serde::{Deserialize, Serialize};

// ============ 凭据状态 ============

/// 所有凭据状态响应
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialsStatusResponse {
    /// 凭据总数
    pub total: usize,
    /// 可用凭据数量（未禁用）
    pub available: usize,
    /// 当前活跃凭据 ID
    pub current_id: u64,
    /// 最近 60 秒请求数（RPM）
    pub rpm: usize,
    /// 全局冷却限流是否启用
    pub cooldown_enabled: bool,
    /// 全局冷却窗口时长（秒）
    pub cooldown_seconds: u64,
    /// 全局冷却窗口内最大请求数
    pub cooldown_max_requests: u32,
    /// 各凭据状态列表
    pub credentials: Vec<CredentialStatusItem>,
}

/// 单个凭据的状态信息
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialStatusItem {
    /// 凭据唯一 ID
    pub id: u64,
    /// 优先级（数字越小优先级越高）
    pub priority: u32,
    /// 是否被禁用
    pub disabled: bool,
    /// 连续失败次数
    pub failure_count: u32,
    /// 是否为当前活跃凭据
    pub is_current: bool,
    /// Token 过期时间（RFC3339 格式）
    pub expires_at: Option<String>,
    /// 认证方式
    pub auth_method: Option<String>,
    /// 是否有 Profile ARN
    pub has_profile_arn: bool,
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
    /// 端点名称（决定该凭据走哪套 Kiro API，已回退到默认端点）
    pub endpoint: String,
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

// ============ 操作请求 ============

/// 启用/禁用凭据请求
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SetDisabledRequest {
    /// 是否禁用
    pub disabled: bool,
}

/// 修改优先级请求
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SetPriorityRequest {
    /// 新优先级值
    pub priority: u32,
}

/// 添加凭据请求
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AddCredentialRequest {
    /// 刷新令牌（OAuth 凭据必填，API Key 凭据不需要）
    pub refresh_token: Option<String>,

    /// 认证方式（可选，默认 social）
    #[serde(default = "default_auth_method")]
    pub auth_method: String,

    /// Profile ARN（IdC/企业版认证需要，可选）
    /// 格式: arn:aws:codewhisperer:{region}:{account}:profile/{id}
    pub profile_arn: Option<String>,

    /// OIDC Client ID（IdC 认证需要）
    pub client_id: Option<String>,

    /// OIDC Client Secret（IdC 认证需要）
    pub client_secret: Option<String>,

    /// 优先级（可选，默认 0）
    #[serde(default)]
    pub priority: u32,

    /// 凭据级 Region 配置（用于 OIDC token 刷新）
    /// 未配置时回退到 config.json 的全局 region
    pub region: Option<String>,

    /// 凭据级 Auth Region（用于 Token 刷新）
    pub auth_region: Option<String>,

    /// 凭据级 API Region（用于 API 请求）
    pub api_region: Option<String>,

    /// 凭据级 Machine ID（可选，64 位字符串）
    /// 未配置时回退到 config.json 的 machineId
    pub machine_id: Option<String>,

    /// 用户邮箱（可选，用于前端显示）
    pub email: Option<String>,

    /// 账号密码（可选，仅存储不参与认证）
    pub password: Option<String>,

    /// 凭据级代理 URL（可选，特殊值 "direct" 表示不使用代理）
    pub proxy_url: Option<String>,

    /// 凭据级代理认证用户名（可选）
    pub proxy_username: Option<String>,

    /// 凭据级代理认证密码（可选）
    pub proxy_password: Option<String>,

    /// Kiro API Key（API Key 凭据必填，格式: ksk_xxxxxxxx）
    /// 设置后直接作为 Bearer Token 使用，无需 refreshToken
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kiro_api_key: Option<String>,

    /// 端点名称（可选，未配置时使用 config.defaultEndpoint）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,

    /// 凭据级冷却限流开关
    pub cooldown_enabled: Option<bool>,

    /// 凭据级冷却窗口时长（秒）
    pub cooldown_seconds: Option<u64>,

    /// 凭据级冷却窗口内最大请求数
    pub cooldown_max_requests: Option<u32>,

    /// 是否自动从代理池分配代理（默认 true）
    #[serde(default = "default_auto_allocate_proxy")]
    pub auto_allocate_proxy: bool,
}

fn default_auto_allocate_proxy() -> bool {
    true
}

fn default_auth_method() -> String {
    "social".to_string()
}

/// 添加凭据成功响应
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AddCredentialResponse {
    pub success: bool,
    pub message: String,
    /// 新添加的凭据 ID
    pub credential_id: u64,
    /// 用户邮箱（如果获取成功）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// 余额信息（如果获取成功）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub balance: Option<BalanceResponse>,
}

// ============ 余额查询 ============

/// 余额查询响应
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BalanceResponse {
    /// 凭据 ID
    pub id: u64,
    /// 订阅类型
    pub subscription_title: Option<String>,
    /// 当前使用量
    pub current_usage: f64,
    /// 使用限额
    pub usage_limit: f64,
    /// 剩余额度
    pub remaining: f64,
    /// 使用百分比
    pub usage_percentage: f64,
    /// 下次重置时间（Unix 时间戳）
    pub next_reset_at: Option<f64>,
    /// 用户邮箱
    pub email: Option<String>,
    /// 超额状态: "overaging"(超额中) / "enabled"(已开启) / "disabled"(未开启)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub overage_status: Option<String>,
}

// ============ 负载均衡配置 ============

/// 负载均衡模式响应
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LoadBalancingModeResponse {
    /// 当前模式（"priority" 或 "balanced"）
    pub mode: String,
}

/// 设置负载均衡模式请求
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SetLoadBalancingModeRequest {
    /// 模式（"priority" 或 "balanced"）
    pub mode: String,
}

// ============ 通用响应 ============

/// 操作成功响应
#[derive(Debug, Serialize)]
pub struct SuccessResponse {
    pub success: bool,
    pub message: String,
}

impl SuccessResponse {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            success: true,
            message: message.into(),
        }
    }
}

/// 错误响应
#[derive(Debug, Serialize)]
pub struct AdminErrorResponse {
    pub error: AdminError,
}

#[derive(Debug, Serialize)]
pub struct AdminError {
    #[serde(rename = "type")]
    pub error_type: String,
    pub message: String,
}

impl AdminErrorResponse {
    pub fn new(error_type: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            error: AdminError {
                error_type: error_type.into(),
                message: message.into(),
            },
        }
    }

    pub fn invalid_request(message: impl Into<String>) -> Self {
        Self::new("invalid_request", message)
    }

    pub fn authentication_error() -> Self {
        Self::new("authentication_error", "Invalid or missing admin API key")
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new("not_found", message)
    }

    pub fn api_error(message: impl Into<String>) -> Self {
        Self::new("api_error", message)
    }

    pub fn internal_error(message: impl Into<String>) -> Self {
        Self::new("internal_error", message)
    }
}

// ============ 冷却限流配置 ============

/// 冷却限流配置响应
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CooldownConfigResponse {
    /// 是否启用
    pub enabled: bool,
    /// 冷却窗口时长（秒）
    pub seconds: u64,
    /// 窗口内最大请求数
    pub max_requests: u32,
}

/// 设置冷却限流配置请求
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SetCooldownConfigRequest {
    /// 是否启用
    pub enabled: bool,
    /// 冷却窗口时长（秒）
    pub seconds: u64,
    /// 窗口内最大请求数
    pub max_requests: u32,
}

/// 设置单个凭据冷却限流请求
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SetCredentialCooldownRequest {
    /// 是否启用（None = 跟随全局）
    pub enabled: Option<bool>,
    /// 冷却窗口时长（秒）
    pub seconds: Option<u64>,
    /// 窗口内最大请求数
    pub max_requests: Option<u32>,
}

// ============ 缓存 token 估算倍率 ============

/// 缓存倍率响应
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CacheRatiosResponse {
    /// 写入缓存倍率（cache_creation_input_tokens）
    pub creation: f64,
    /// 读取缓存倍率（cache_read_input_tokens）
    pub read: f64,
    /// 多轮未缓存输入倍率（多轮 input_tokens）
    pub uncached: f64,
    /// 首轮全量输入倍率（首轮 input_tokens）
    pub first_turn: f64,
    /// 输出倍率（output_tokens）
    pub output: f64,
}

/// 设置缓存倍率请求
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SetCacheRatiosRequest {
    pub creation: f64,
    pub read: f64,
    pub uncached: f64,
    pub first_turn: f64,
    pub output: f64,
}

// ============ 缓存模式 ============

/// 缓存模式响应
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CacheModeResponse {
    pub mode: String,
}

/// 设置缓存模式请求
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SetCacheModeRequest {
    pub mode: String,
}

// ============ 缓存间歇中断 ============

/// 缓存间歇中断配置响应
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CacheInterruptResponse {
    pub enabled: bool,
    pub min_secs: u64,
    pub max_secs: u64,
    pub duration_secs: u64,
}

/// 设置缓存间歇中断配置请求
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SetCacheInterruptRequest {
    pub enabled: bool,
    pub min_secs: u64,
    pub max_secs: u64,
    pub duration_secs: u64,
}

// ============ 模型映射 ============

/// 模型映射响应
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ModelMappingsResponse {
    pub mappings: Vec<ModelMappingItem>,
    pub free_model_mappings: Vec<ModelMappingItem>,
}

/// 模型映射条目
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ModelMappingItem {
    pub from: String,
    pub to: String,
}

/// 设置模型映射请求
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SetModelMappingsRequest {
    pub mappings: Vec<ModelMappingItem>,
    #[serde(default)]
    pub free_model_mappings: Option<Vec<ModelMappingItem>>,
}

// ============ 代理设置 ============

/// 设置代理请求
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SetProxyRequest {
    /// 代理 URL（空字符串或 null 表示清除代理）
    pub proxy_url: Option<String>,
    /// 代理认证用户名
    pub proxy_username: Option<String>,
    /// 代理认证密码
    pub proxy_password: Option<String>,
}

/// 代理延迟检测响应
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProxyLatencyResponse {
    /// 延迟（毫秒），None 表示检测失败
    pub latency_ms: Option<u64>,
    /// 错误信息
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

// ============ 代理池 ============

/// 代理池导入请求
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportProxiesRequest {
    /// 多行文本，每行格式: ip:port:user:pass
    pub text: String,
}

/// 代理池条目（前端展示）
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProxyPoolItemResponse {
    pub id: u64,
    pub url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    /// 被哪个凭据使用（None=未使用）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub used_by_credential_id: Option<u64>,
    /// 是否被标记为有问题
    pub flagged: bool,
    /// 历史绑定过的账号数量
    pub history_count: usize,
}

/// 代理池响应
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProxyPoolResponse {
    pub total: usize,
    pub available: usize,
    pub proxies: Vec<ProxyPoolItemResponse>,
}

// ============ 429 冷却配置 ============

/// 429 冷却配置响应
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RateLimitCooldownResponse {
    pub seconds: u64,
}

/// 设置 429 冷却配置请求
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SetRateLimitCooldownRequest {
    pub seconds: u64,
}

/// 模型价格响应
#[derive(Debug, Serialize, Deserialize)]
pub struct ModelPricesResponse {
    pub prices: std::collections::HashMap<String, ModelPriceItem>,
}

/// 单个模型的价格
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelPriceItem {
    pub input: f64,
    pub output: f64,
    pub cache_read: f64,
    pub cache_write: f64,
}

/// 设置模型价格请求
#[derive(Debug, Deserialize)]
pub struct SetModelPricesRequest {
    pub prices: std::collections::HashMap<String, ModelPriceItem>,
}

/// 计费统计响应
#[derive(Debug, Serialize)]
pub struct BillingStatsResponse {
    pub credentials: std::collections::HashMap<u64, super::billing::CredentialBilling>,
}
