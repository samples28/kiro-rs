//! 计费统计模块
//!
//! 按凭据跟踪每次请求的费用，支持持久化到文件。

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use crate::model::config::ModelPrice;

/// 单次请求的 token 用量
pub struct RequestUsage {
    pub input_tokens: i32,
    pub output_tokens: i32,
    pub cache_read_tokens: i32,
    pub cache_write_tokens: i32,
}

/// 单个凭据的累计统计
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CredentialBilling {
    /// 总费用（美元）
    pub total_cost: f64,
    /// 总请求数
    pub total_requests: u64,
    /// 按模型分的费用明细
    pub by_model: HashMap<String, ModelBilling>,
}

/// 单个模型的累计统计
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ModelBilling {
    pub cost: f64,
    pub requests: u64,
    pub input_tokens: i64,
    pub output_tokens: i64,
    pub cache_read_tokens: i64,
    pub cache_write_tokens: i64,
}

/// 持久化数据结构
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct BillingData {
    credentials: HashMap<u64, CredentialBilling>,
}

/// 计费统计管理器
pub struct BillingStats {
    data: Mutex<BillingData>,
    file_path: PathBuf,
    last_save: Mutex<Instant>,
}

/// Debounce 间隔（秒）
const SAVE_DEBOUNCE_SECS: u64 = 60;

impl BillingStats {
    /// 创建并从文件加载（文件不存在则初始化空数据）
    pub fn load(path: impl AsRef<Path>) -> Self {
        let path = path.as_ref().to_path_buf();
        let data = if path.exists() {
            match std::fs::read_to_string(&path) {
                Ok(content) => serde_json::from_str(&content).unwrap_or_default(),
                Err(_) => BillingData::default(),
            }
        } else {
            BillingData::default()
        };
        Self {
            data: Mutex::new(data),
            file_path: path,
            last_save: Mutex::new(Instant::now()),
        }
    }

    /// 记录一次请求的费用
    pub fn record(
        &self,
        credential_id: u64,
        model: &str,
        usage: &RequestUsage,
        prices: &HashMap<String, ModelPrice>,
    ) {
        // 查找模型价格（按前缀匹配）
        let price = match find_model_price(model, prices) {
            Some(p) => p,
            None => return, // 模型不在计费列表中，跳过
        };

        // 计算费用
        let cost = (usage.input_tokens as f64 * price.input
            + usage.output_tokens as f64 * price.output
            + usage.cache_read_tokens as f64 * price.cache_read
            + usage.cache_write_tokens as f64 * price.cache_write)
            / 1_000_000.0;

        // 更新统计
        let mut data = self.data.lock().unwrap();
        let cred = data.credentials.entry(credential_id).or_default();
        cred.total_cost += cost;
        cred.total_requests += 1;

        let model_key = normalize_model_name(model);
        let mb = cred.by_model.entry(model_key).or_default();
        mb.cost += cost;
        mb.requests += 1;
        mb.input_tokens += usage.input_tokens as i64;
        mb.output_tokens += usage.output_tokens as i64;
        mb.cache_read_tokens += usage.cache_read_tokens as i64;
        mb.cache_write_tokens += usage.cache_write_tokens as i64;

        // Debounce 保存
        drop(data);
        self.maybe_save();
    }

    /// 获取所有凭据的统计快照
    pub fn snapshot(&self) -> HashMap<u64, CredentialBilling> {
        self.data.lock().unwrap().credentials.clone()
    }

    /// 重置所有统计
    pub fn reset(&self) {
        let mut data = self.data.lock().unwrap();
        data.credentials.clear();
        drop(data);
        self.force_save();
    }

    /// 重置单个凭据的统计
    pub fn reset_credential(&self, credential_id: u64) {
        let mut data = self.data.lock().unwrap();
        data.credentials.remove(&credential_id);
        drop(data);
        self.maybe_save();
    }

    /// 强制保存到文件
    pub fn force_save(&self) {
        let data = self.data.lock().unwrap();
        if let Ok(content) = serde_json::to_string_pretty(&*data) {
            if let Some(parent) = self.file_path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let _ = std::fs::write(&self.file_path, content);
        }
        *self.last_save.lock().unwrap() = Instant::now();
    }

    fn maybe_save(&self) {
        let elapsed = self.last_save.lock().unwrap().elapsed().as_secs();
        if elapsed >= SAVE_DEBOUNCE_SECS {
            self.force_save();
        }
    }
}

/// 将模型名标准化为计费键名
fn normalize_model_name(model: &str) -> String {
    let lower = model.to_lowercase();
    if lower.contains("opus") && (lower.contains("4-8") || lower.contains("4.8")) {
        "claude-opus-4-8".to_string()
    } else if lower.contains("opus") && (lower.contains("4-7") || lower.contains("4.7")) {
        "claude-opus-4-7".to_string()
    } else if lower.contains("opus") && (lower.contains("4-6") || lower.contains("4.6")) {
        "claude-opus-4-6".to_string()
    } else if lower.contains("sonnet") && (lower.contains("4-6") || lower.contains("4.6")) {
        "claude-sonnet-4-6".to_string()
    } else if lower.contains("sonnet") {
        "claude-sonnet-4-5".to_string()
    } else if lower.contains("haiku") {
        "claude-haiku-4-5".to_string()
    } else {
        model.to_string()
    }
}

/// 查找模型对应的价格（按标准化名称匹配）
fn find_model_price<'a>(model: &str, prices: &'a HashMap<String, ModelPrice>) -> Option<&'a ModelPrice> {
    let key = normalize_model_name(model);
    prices.get(&key)
}

/// 全局单例
static BILLING: std::sync::OnceLock<Arc<BillingStats>> = std::sync::OnceLock::new();

/// 初始化全局计费统计
pub fn init(path: impl AsRef<Path>) {
    let stats = Arc::new(BillingStats::load(path));
    let _ = BILLING.set(stats);
}

/// 获取全局计费统计实例
pub fn get() -> Option<&'static Arc<BillingStats>> {
    BILLING.get()
}
