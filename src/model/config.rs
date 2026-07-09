use anyhow::Context;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum TlsBackend {
    Rustls,
    NativeTls,
}

impl Default for TlsBackend {
    fn default() -> Self {
        Self::Rustls
    }
}

/// 模型价格定义（单位：$/1M tokens）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelPrice {
    pub input: f64,
    pub output: f64,
    pub cache_read: f64,
    pub cache_write: f64,
}

/// KNA 应用配置
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Config {
    #[serde(default = "default_host")]
    pub host: String,

    #[serde(default = "default_port")]
    pub port: u16,

    #[serde(default = "default_region")]
    pub region: String,

    /// Auth Region（用于 Token 刷新），未配置时回退到 region
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_region: Option<String>,

    /// API Region（用于 API 请求），未配置时回退到 region
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_region: Option<String>,

    #[serde(default = "default_kiro_version")]
    pub kiro_version: String,

    #[serde(default)]
    pub machine_id: Option<String>,

    #[serde(default)]
    pub api_key: Option<String>,

    #[serde(default = "default_system_version")]
    pub system_version: String,

    #[serde(default = "default_node_version")]
    pub node_version: String,

    #[serde(default = "default_tls_backend")]
    pub tls_backend: TlsBackend,

    /// 外部 count_tokens API 地址（可选）
    #[serde(default)]
    pub count_tokens_api_url: Option<String>,

    /// count_tokens API 密钥（可选）
    #[serde(default)]
    pub count_tokens_api_key: Option<String>,

    /// count_tokens API 认证类型（可选，"x-api-key" 或 "bearer"，默认 "x-api-key"）
    #[serde(default = "default_count_tokens_auth_type")]
    pub count_tokens_auth_type: String,

    /// HTTP 代理地址（可选）
    /// 支持格式: http://host:port, https://host:port, socks5://host:port
    #[serde(default)]
    pub proxy_url: Option<String>,

    /// 代理认证用户名（可选）
    #[serde(default)]
    pub proxy_username: Option<String>,

    /// 代理认证密码（可选）
    #[serde(default)]
    pub proxy_password: Option<String>,

    /// Admin API 密钥（可选，启用 Admin API 功能）
    #[serde(default)]
    pub admin_api_key: Option<String>,

    /// 负载均衡模式（"priority" 或 "balanced"）
    #[serde(default = "default_load_balancing_mode")]
    pub load_balancing_mode: String,

    /// 是否开启非流式响应的 thinking 块提取（默认 true）
    ///
    /// 启用后，非流式响应中的 `<thinking>...</thinking>` 标签会被解析为
    /// 独立的 `{"type": "thinking", ...}` 内容块,与流式响应行为一致。
    #[serde(default = "default_extract_thinking")]
    pub extract_thinking: bool,

    /// 默认端点名称（凭据未显式指定 endpoint 时使用，默认 "ide"）
    #[serde(default = "default_endpoint")]
    pub default_endpoint: String,

    /// 是否启用全局凭据冷却限流（默认 false，关闭时完全不限流）
    #[serde(default)]
    pub cooldown_enabled: bool,

    /// 冷却窗口时长（秒），在此时间窗口内限制每个凭据的请求次数
    #[serde(default = "default_cooldown_seconds")]
    pub cooldown_seconds: u64,

    /// 冷却窗口内每个凭据允许的最大请求数
    #[serde(default = "default_cooldown_max_requests")]
    pub cooldown_max_requests: u32,

    /// 缓存 token 估算倍率（写入缓存场景，对应 cache_creation_input_tokens）
    #[serde(default = "default_cache_ratio_creation")]
    pub cache_ratio_creation: f64,

    /// 缓存 token 估算倍率（读取缓存场景，对应 cache_read_input_tokens）
    #[serde(default = "default_cache_ratio_read")]
    pub cache_ratio_read: f64,

    /// 缓存 token 估算倍率（多轮未缓存场景，对应 input_tokens）
    #[serde(default = "default_cache_ratio_uncached")]
    pub cache_ratio_uncached: f64,

    /// 缓存 token 估算倍率（首轮全量场景，对应 input_tokens）
    #[serde(default = "default_cache_ratio_first_turn")]
    pub cache_ratio_first_turn: f64,

    /// 输出 token 估算倍率（对应 output_tokens）
    #[serde(default = "default_cache_ratio_output")]
    pub cache_ratio_output: f64,

    /// 缓存模式（"fixed" 固定模式 或 "standard" 标准模式）
    #[serde(default = "default_cache_mode")]
    pub cache_mode: String,

    /// 固定模式间歇中断开关
    #[serde(default)]
    pub cache_interrupt_enabled: bool,

    /// 间歇中断最小间隔（秒）
    #[serde(default = "default_cache_interrupt_min")]
    pub cache_interrupt_min_secs: u64,

    /// 间歇中断最大间隔（秒）
    #[serde(default = "default_cache_interrupt_max")]
    pub cache_interrupt_max_secs: u64,

    /// 间歇中断持续时长（秒）
    #[serde(default = "default_cache_interrupt_duration")]
    pub cache_interrupt_duration_secs: u64,

    /// 模型映射配置（用户面向模型 ID → 实际 Kiro 模型 ID）
    #[serde(default = "default_model_mappings")]
    pub model_mappings: Vec<ModelMapping>,

    /// Free 账号的模型映射（用户请求模型 → 实际转发模型）
    /// 不在此列表中的模型不会分配到 Free 凭据
    #[serde(default = "default_free_model_mappings")]
    pub free_model_mappings: Vec<ModelMapping>,

    /// 端点特定的配置
    ///
    /// 键为端点名（如 "ide" / "cli"），值为该端点自由定义的参数对象。
    /// 未在此表出现的端点沿用实现内置默认值。
    #[serde(default)]
    pub endpoints: HashMap<String, serde_json::Value>,

    /// 是否启用 debug JSON 日志保存（默认 false）
    #[serde(default)]
    pub debug_log_enabled: bool,

    /// 错误日志开关（默认 false，开启后错误请求保存到 logs/errors/）
    #[serde(default)]
    pub error_log_enabled: bool,

    /// debug 日志保存目录（默认 "./logs"）
    #[serde(default = "default_debug_log_dir")]
    pub debug_log_dir: String,

    /// 模型价格配置（模型名 → 价格，$/1M tokens）
    #[serde(default = "default_model_prices")]
    pub model_prices: HashMap<String, ModelPrice>,

    /// 429 限流冷却时间（秒），收到 429 后凭据暂停使用的时长
    #[serde(default = "default_rate_limit_cooldown_secs")]
    pub rate_limit_cooldown_secs: u64,

    /// 配置文件路径（运行时元数据，不写入 JSON）
    #[serde(skip)]
    config_path: Option<PathBuf>,
}

fn default_host() -> String {
    "127.0.0.1".to_string()
}

fn default_port() -> u16 {
    8080
}

fn default_region() -> String {
    "us-east-1".to_string()
}

fn default_kiro_version() -> String {
    "0.12.155".to_string()
}

fn default_system_version() -> String {
    const SYSTEM_VERSIONS: &[&str] = &["darwin#24.6.0", "win32#10.0.22631"];
    SYSTEM_VERSIONS[fastrand::usize(..SYSTEM_VERSIONS.len())].to_string()
}

fn default_node_version() -> String {
    "22.22.0".to_string()
}

fn default_count_tokens_auth_type() -> String {
    "x-api-key".to_string()
}

fn default_tls_backend() -> TlsBackend {
    TlsBackend::Rustls
}

fn default_load_balancing_mode() -> String {
    "priority".to_string()
}

fn default_extract_thinking() -> bool {
    true
}

fn default_endpoint() -> String {
    crate::kiro::endpoint::ide::IDE_ENDPOINT_NAME.to_string()
}

fn default_cooldown_seconds() -> u64 {
    10
}

fn default_cooldown_max_requests() -> u32 {
    1
}

fn default_cache_ratio_creation() -> f64 {
    1.20
}

fn default_cache_ratio_read() -> f64 {
    1.10
}

fn default_cache_ratio_uncached() -> f64 {
    1.15
}

fn default_cache_ratio_first_turn() -> f64 {
    1.10
}

fn default_cache_ratio_output() -> f64 {
    1.0
}

fn default_cache_mode() -> String {
    "fixed".to_string()
}

fn default_cache_interrupt_min() -> u64 {
    300
}

fn default_cache_interrupt_max() -> u64 {
    600
}

fn default_cache_interrupt_duration() -> u64 {
    10
}

fn default_debug_log_dir() -> String {
    "./logs".to_string()
}

fn default_model_prices() -> HashMap<String, ModelPrice> {
    let mut m = HashMap::new();
    // Opus 系列: input=$5, output=$25, cache_read=$0.50, cache_write=$6.25
    for name in ["claude-opus-4-8", "claude-opus-4-7", "claude-opus-4-6"] {
        m.insert(name.to_string(), ModelPrice { input: 5.0, output: 25.0, cache_read: 0.5, cache_write: 6.25 });
    }
    // Sonnet 系列: input=$3, output=$15, cache_read=$0.30, cache_write=$3.75
    for name in ["claude-sonnet-4-6", "claude-sonnet-4-5"] {
        m.insert(name.to_string(), ModelPrice { input: 3.0, output: 15.0, cache_read: 0.3, cache_write: 3.75 });
    }
    // Haiku: input=$1, output=$5, cache_read=$0.10, cache_write=$1.25
    m.insert("claude-haiku-4-5".to_string(), ModelPrice { input: 1.0, output: 5.0, cache_read: 0.1, cache_write: 1.25 });
    m
}

fn default_rate_limit_cooldown_secs() -> u64 {
    30
}

/// 模型映射条目
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ModelMapping {
    /// 用户面向的模型 ID（客户端发送的）
    pub from: String,
    /// 实际的 Kiro 模型 ID（发送给上游的）
    pub to: String,
}

fn default_model_mappings() -> Vec<ModelMapping> {
    vec![
        ModelMapping { from: "claude-opus-4-7".into(), to: "claude-opus-4.6".into() },
        ModelMapping { from: "claude-opus-4-6".into(), to: "claude-opus-4.6".into() },
        ModelMapping { from: "claude-opus-4-5".into(), to: "claude-opus-4.5".into() },
        ModelMapping { from: "claude-sonnet-4-6".into(), to: "claude-sonnet-4.6".into() },
        ModelMapping { from: "claude-sonnet-4-5".into(), to: "claude-sonnet-4.5".into() },
        ModelMapping { from: "claude-haiku-4-5".into(), to: "claude-haiku-4.5".into() },
    ]
}

fn default_free_model_mappings() -> Vec<ModelMapping> {
    vec![
        ModelMapping { from: "claude-haiku-4-5".into(), to: "claude-haiku-4.5".into() },
        ModelMapping { from: "claude-sonnet-4-5".into(), to: "claude-sonnet-4.5".into() },
    ]
}

impl Default for Config {
    fn default() -> Self {
        Self {
            host: default_host(),
            port: default_port(),
            region: default_region(),
            auth_region: None,
            api_region: None,
            kiro_version: default_kiro_version(),
            machine_id: None,
            api_key: None,
            system_version: default_system_version(),
            node_version: default_node_version(),
            tls_backend: default_tls_backend(),
            count_tokens_api_url: None,
            count_tokens_api_key: None,
            count_tokens_auth_type: default_count_tokens_auth_type(),
            proxy_url: None,
            proxy_username: None,
            proxy_password: None,
            admin_api_key: None,
            load_balancing_mode: default_load_balancing_mode(),
            extract_thinking: default_extract_thinking(),
            default_endpoint: default_endpoint(),
            endpoints: HashMap::new(),
            cooldown_enabled: false,
            cooldown_seconds: default_cooldown_seconds(),
            cooldown_max_requests: default_cooldown_max_requests(),
            cache_ratio_creation: default_cache_ratio_creation(),
            cache_ratio_read: default_cache_ratio_read(),
            cache_ratio_uncached: default_cache_ratio_uncached(),
            cache_ratio_first_turn: default_cache_ratio_first_turn(),
            cache_ratio_output: default_cache_ratio_output(),
            cache_mode: default_cache_mode(),
            cache_interrupt_enabled: false,
            cache_interrupt_min_secs: default_cache_interrupt_min(),
            cache_interrupt_max_secs: default_cache_interrupt_max(),
            cache_interrupt_duration_secs: default_cache_interrupt_duration(),
            model_mappings: default_model_mappings(),
            free_model_mappings: default_free_model_mappings(),
            debug_log_enabled: false,
            error_log_enabled: false,
            debug_log_dir: default_debug_log_dir(),
            model_prices: default_model_prices(),
            rate_limit_cooldown_secs: default_rate_limit_cooldown_secs(),
            config_path: None,
        }
    }
}

impl Config {
    /// 获取默认配置文件路径
    pub fn default_config_path() -> &'static str {
        "config.json"
    }

    /// 获取有效的 Auth Region（用于 Token 刷新）
    /// 优先使用 auth_region，未配置时回退到 region
    pub fn effective_auth_region(&self) -> &str {
        self.auth_region.as_deref().unwrap_or(&self.region)
    }

    /// 获取有效的 API Region（用于 API 请求）
    /// 优先使用 api_region，未配置时回退到 region
    pub fn effective_api_region(&self) -> &str {
        self.api_region.as_deref().unwrap_or(&self.region)
    }

    /// 从文件加载配置
    pub fn load<P: AsRef<Path>>(path: P) -> anyhow::Result<Self> {
        let path = path.as_ref();
        if !path.exists() {
            // 配置文件不存在，返回默认配置
            let mut config = Self::default();
            config.config_path = Some(path.to_path_buf());
            return Ok(config);
        }

        let content = fs::read_to_string(path)?;
        let mut config: Config = serde_json::from_str(&content)?;
        config.config_path = Some(path.to_path_buf());
        Ok(config)
    }

    /// 获取配置文件路径（如果有）
    pub fn config_path(&self) -> Option<&Path> {
        self.config_path.as_deref()
    }

    /// 将当前配置写回原始配置文件
    pub fn save(&self) -> anyhow::Result<()> {
        let path = self
            .config_path
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("配置文件路径未知，无法保存配置"))?;

        let content = serde_json::to_string_pretty(self).context("序列化配置失败")?;
        fs::write(path, content).with_context(|| format!("写入配置文件失败: {}", path.display()))?;
        Ok(())
    }
}
