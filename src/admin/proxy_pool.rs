//! 代理池管理模块
//!
//! 独立的代理池，支持批量导入、自动分配给凭据

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

/// 代理池条目
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyEntry {
    pub id: u64,
    pub url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    /// 是否被标记为有问题（切换代理时标记旧代理）
    #[serde(default)]
    pub flagged: bool,
    /// 历史绑定过的凭据 ID 列表（去重）
    #[serde(default)]
    pub assigned_credential_ids: Vec<u64>,
}

/// 代理池
pub struct ProxyPool {
    entries: Mutex<Vec<ProxyEntry>>,
    next_id: AtomicU64,
    file_path: Option<PathBuf>,
}

impl ProxyPool {
    /// 从文件加载或创建空池
    pub fn new(file_path: Option<PathBuf>) -> Self {
        let entries = Self::load_from_file(file_path.as_ref());
        let max_id = entries.iter().map(|e| e.id).max().unwrap_or(0);
        Self {
            entries: Mutex::new(entries),
            next_id: AtomicU64::new(max_id + 1),
            file_path,
        }
    }

    /// 获取所有代理
    pub fn list(&self) -> Vec<ProxyEntry> {
        self.entries.lock().clone()
    }

    /// 批量导入代理（格式: ip:port:user:pass，协议 socks5）
    pub fn import(&self, text: &str) -> Vec<ProxyEntry> {
        let mut added = Vec::new();
        let mut entries = self.entries.lock();

        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            if let Some(entry) = self.parse_proxy_line(line) {
                // 去重：相同 url+username+password 不重复添加
                if entries.iter().any(|e| {
                    e.url == entry.url
                        && e.username == entry.username
                        && e.password == entry.password
                }) {
                    continue;
                }
                entries.push(entry.clone());
                added.push(entry);
            }
        }

        drop(entries);
        self.persist();
        added
    }

    /// 解析文本为代理条目列表（不导入，仅解析）
    pub fn parse_lines(&self, text: &str) -> Vec<ProxyEntry> {
        let mut result = Vec::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            if let Some(entry) = self.parse_proxy_line(line) {
                result.push(entry);
            }
        }
        result
    }

    /// 添加单个代理条目（去重，成功返回 true）
    pub fn add_entry(&self, entry: ProxyEntry) -> bool {
        let mut entries = self.entries.lock();
        if entries.iter().any(|e| {
            e.url == entry.url && e.username == entry.username && e.password == entry.password
        }) {
            return false;
        }
        entries.push(entry);
        drop(entries);
        self.persist();
        true
    }

    /// 标记代理为有问题（通过 url+username+password 匹配）
    pub fn flag_proxy(&self, url: &str, username: Option<&str>, password: Option<&str>) {
        let mut entries = self.entries.lock();
        if let Some(entry) = entries.iter_mut().find(|e| {
            e.url == url
                && e.username.as_deref() == username
                && e.password.as_deref() == password
        }) {
            if !entry.flagged {
                entry.flagged = true;
                tracing::info!("代理已标记为有问题: {}", url);
            }
        }
        drop(entries);
        self.persist();
    }

    /// 删除代理
    pub fn remove(&self, id: u64) -> bool {
        let mut entries = self.entries.lock();
        let before = entries.len();
        entries.retain(|e| e.id != id);
        let removed = entries.len() < before;
        drop(entries);
        if removed {
            self.persist();
        }
        removed
    }

    /// 分配一个未被使用的代理
    /// used_proxies: 当前已被凭据使用的代理 (url, username, password) 组合
    pub fn allocate_unused(&self, used_proxies: &[(String, Option<String>, Option<String>)]) -> Option<ProxyEntry> {
        let entries = self.entries.lock();
        entries
            .iter()
            .find(|e| {
                !used_proxies.iter().any(|(url, user, pass)| {
                    *url == e.url && *user == e.username && *pass == e.password
                })
            })
            .cloned()
    }

    /// 统计：总数和可用数
    pub fn stats(&self, used_proxies: &[(String, Option<String>, Option<String>)]) -> (usize, usize) {
        let entries = self.entries.lock();
        let total = entries.len();
        let available = entries
            .iter()
            .filter(|e| {
                !used_proxies.iter().any(|(url, user, pass)| {
                    *url == e.url && *user == e.username && *pass == e.password
                })
            })
            .count();
        (total, available)
    }

    /// 记录代理被分配给某凭据（历史绑定追踪）
    pub fn record_assignment(&self, proxy_url: &str, proxy_username: Option<&str>, proxy_password: Option<&str>, credential_id: u64) {
        let mut entries = self.entries.lock();
        if let Some(entry) = entries.iter_mut().find(|e| {
            e.url == proxy_url
                && e.username.as_deref() == proxy_username
                && e.password.as_deref() == proxy_password
        }) {
            if !entry.assigned_credential_ids.contains(&credential_id) {
                entry.assigned_credential_ids.push(credential_id);
            }
        }
        drop(entries);
        self.persist();
    }

    fn parse_proxy_line(&self, line: &str) -> Option<ProxyEntry> {
        let parts: Vec<&str> = line.split(':').collect();
        if parts.len() < 2 {
            return None;
        }

        let id = self.next_id.fetch_add(1, Ordering::Relaxed);

        if parts.len() == 4 {
            // ip:port:user:pass
            let url = format!("socks5://{}:{}", parts[0], parts[1]);
            Some(ProxyEntry {
                id,
                url,
                username: Some(parts[2].to_string()),
                password: Some(parts[3].to_string()),
                flagged: false,
                assigned_credential_ids: Vec::new(),
            })
        } else if parts.len() == 2 {
            // ip:port (无认证)
            let url = format!("socks5://{}:{}", parts[0], parts[1]);
            Some(ProxyEntry {
                id,
                url,
                username: None,
                password: None,
                flagged: false,
                assigned_credential_ids: Vec::new(),
            })
        } else if parts.len() >= 4 {
            // 可能是 domain:port:user:pass（domain 含冒号不太可能，按前两段为 host:port）
            let url = format!("socks5://{}:{}", parts[0], parts[1]);
            let user = parts[2..parts.len() - 1].join(":");
            let pass = parts[parts.len() - 1].to_string();
            Some(ProxyEntry {
                id,
                url,
                username: Some(user),
                password: Some(pass),
                flagged: false,
                assigned_credential_ids: Vec::new(),
            })
        } else {
            None
        }
    }

    fn persist(&self) {
        let path = match &self.file_path {
            Some(p) => p,
            None => return,
        };
        let entries = self.entries.lock();
        if let Ok(json) = serde_json::to_string_pretty(&*entries) {
            if let Err(e) = std::fs::write(path, json) {
                tracing::warn!("持久化代理池失败: {}", e);
            }
        }
    }

    fn load_from_file(path: Option<&PathBuf>) -> Vec<ProxyEntry> {
        let path = match path {
            Some(p) => p,
            None => return Vec::new(),
        };
        match std::fs::read_to_string(path) {
            Ok(content) => serde_json::from_str(&content).unwrap_or_default(),
            Err(_) => Vec::new(),
        }
    }
}
