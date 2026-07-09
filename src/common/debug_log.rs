//! Debug JSON 日志保存模块
//!
//! 启用后，将每个请求的 4 个阶段数据保存为独立的 JSON 文件：
//! 1. 客户端原始请求
//! 2. 转换后的 Kiro 请求
//! 3. Kiro 原始响应
//! 4. 转换后返回客户端的响应

use std::path::PathBuf;
use std::sync::Arc;
use parking_lot::Mutex;

/// 请求日志的共享引用类型
pub type SharedRequestLog = Arc<Mutex<RequestLog>>;

/// 全局 debug logger 实例
static LOGGER: std::sync::OnceLock<DebugLogger> = std::sync::OnceLock::new();

/// 初始化全局 debug logger
pub fn init(enabled: bool, error_log_enabled: bool, log_dir: impl Into<String>) {
    let log_dir = PathBuf::from(log_dir.into());
    let error_dir = log_dir.join("errors");
    let logger = DebugLogger {
        enabled,
        error_log_enabled,
        log_dir,
        error_dir,
    };
    if logger.enabled {
        if let Err(e) = std::fs::create_dir_all(&logger.log_dir) {
            tracing::error!("创建 debug 日志目录失败: {}", e);
        } else {
            tracing::info!("Debug 日志已启用，保存目录: {:?}", logger.log_dir);
        }
    }
    if logger.error_log_enabled {
        if let Err(e) = std::fs::create_dir_all(&logger.error_dir) {
            tracing::error!("创建错误日志目录失败: {}", e);
        } else {
            tracing::info!("错误日志已启用，保存目录: {:?}", logger.error_dir);
        }
    }
    let _ = LOGGER.set(logger);
}

/// 获取全局 logger 引用（仅 debug 模式启用时返回）
pub fn get() -> Option<&'static DebugLogger> {
    LOGGER.get().filter(|l| l.enabled)
}

/// 获取全局 logger 引用（仅错误日志启用时返回）
pub fn get_error_logger() -> Option<&'static DebugLogger> {
    LOGGER.get().filter(|l| l.error_log_enabled)
}

/// Debug Logger 配置
pub struct DebugLogger {
    enabled: bool,
    error_log_enabled: bool,
    log_dir: PathBuf,
    error_dir: PathBuf,
}

impl DebugLogger {
    /// 创建新的请求日志实例
    pub fn new_request_log(&self) -> SharedRequestLog {
        Arc::new(Mutex::new(RequestLog::new()))
    }
    /// 保存请求日志到文件（debug 模式）
    pub fn save(&self, log: &RequestLog) {
        let prefix = format!("{}_{}", log.timestamp, &log.id[..6]);

        if let Some(ref data) = log.client_request {
            self.write_json_to(&self.log_dir, &prefix, "1_client_request", data);
        }
        if let Some(ref data) = log.kiro_request {
            self.write_json_to(&self.log_dir, &prefix, "2_kiro_request", data);
        }
        if let Some(ref data) = log.kiro_response {
            self.write_json_to(&self.log_dir, &prefix, "3_kiro_response", data);
        }
        if let Some(ref data) = log.client_response {
            self.write_json_to(&self.log_dir, &prefix, "4_client_response", data);
        }
    }

    /// 保存错误请求日志到 errors/ 目录（客户端请求 + Kiro请求 + 响应配对保存）
    pub fn save_error(&self, log: &RequestLog) {
        let prefix = format!("{}_{}", log.timestamp, &log.id[..6]);

        if let Some(ref data) = log.client_request {
            self.write_json_to(&self.error_dir, &prefix, "request", data);
        }
        if let Some(ref data) = log.kiro_request {
            self.write_json_to(&self.error_dir, &prefix, "kiro_request", data);
        }
        if let Some(ref data) = log.client_response {
            self.write_json_to(&self.error_dir, &prefix, "response", data);
        }
    }

    fn write_json_to(&self, dir: &PathBuf, prefix: &str, stage: &str, data: &serde_json::Value) {
        let filename = format!("{}_{}.json", prefix, stage);
        let path = dir.join(&filename);
        match serde_json::to_string_pretty(data) {
            Ok(json) => {
                if let Err(e) = std::fs::write(&path, json) {
                    tracing::warn!("写入日志失败 {}: {}", filename, e);
                }
            }
            Err(e) => {
                tracing::warn!("序列化日志失败 {}: {}", filename, e);
            }
        }
    }
}

/// 单个请求的日志数据
pub struct RequestLog {
    pub id: String,
    pub timestamp: String,
    pub client_request: Option<serde_json::Value>,
    pub kiro_request: Option<serde_json::Value>,
    pub kiro_response: Option<serde_json::Value>,
    pub client_response: Option<serde_json::Value>,
    pub has_error: bool,
}

impl RequestLog {
    fn new() -> Self {
        let now = chrono::Local::now();
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            timestamp: now.format("%Y%m%d_%H%M%S").to_string(),
            client_request: None,
            kiro_request: None,
            kiro_response: None,
            client_response: None,
            has_error: false,
        }
    }

    pub fn set_client_request(&mut self, data: serde_json::Value) {
        self.client_request = Some(data);
    }

    pub fn set_kiro_request(&mut self, data: serde_json::Value) {
        self.kiro_request = Some(data);
    }

    pub fn set_kiro_response(&mut self, data: serde_json::Value) {
        self.kiro_response = Some(data);
    }

    pub fn set_client_response(&mut self, data: serde_json::Value) {
        self.client_response = Some(data);
    }

    pub fn mark_error(&mut self) {
        self.has_error = true;
    }
}
