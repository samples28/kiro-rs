//! 缓存 Token 本地计算模块
//!
//! 独立模块，不依赖任何 handler 逻辑。
//!
//! 计算规则（模拟 Anthropic 缓存行为）:
//!   - 首次对话（仅 user 消息，无 assistant）：无缓存，input_tokens = 全部估算 token
//!   - 多轮对话：
//!     InputTokens:              最后一条 user 消息的 token 数（未缓存的新输入）
//!     CacheCreationInputTokens: 倒数第二条 user + 最后一条 assistant 的 token 数（本轮新增缓存）
//!     CacheReadInputTokens:     其余所有消息的 token 数（命中缓存的历史上下文）
//!   - 标准模式下，逐条前缀匹配：匹配到的部分为 cache_read，未匹配的历史为 cache_creation

use std::hash::{Hash, Hasher};
use std::collections::hash_map::DefaultHasher;

use super::types::MessagesRequest;

/// 本地计算的缓存相关 token 用量
#[derive(Debug, Clone, Copy, Default)]
pub struct CacheUsage {
    pub input_tokens: i32,
    pub cache_creation_input_tokens: i32,
    pub cache_read_input_tokens: i32,
}

/// 缓存 token 估算倍率
#[derive(Debug, Clone, Copy)]
pub struct CacheRatios {
    /// 写入缓存倍率（对应 cache_creation_input_tokens）
    pub creation: f64,
    /// 读取缓存倍率（对应 cache_read_input_tokens）
    pub read: f64,
    /// 多轮未缓存输入倍率（对应 input_tokens）
    pub uncached: f64,
    /// 首轮全量输入倍率（无 assistant 历史时使用）
    pub first_turn: f64,
}

/// 逐条计算前缀累积哈希（system → messages 顺序）
///
/// 返回值: Vec<u64>，长度 = messages.len()（不含最后一条 user）
/// 每个元素是从 system 到该条消息为止的累积哈希值
pub fn compute_prefix_hashes(request: &MessagesRequest) -> Vec<u64> {
    let mut hasher = DefaultHasher::new();
    // system prompt 作为基础层
    if let Some(ref system) = request.system {
        for s in system {
            s.text.hash(&mut hasher);
        }
    }

    let msg_count = request.messages.len();
    if msg_count <= 1 {
        return vec![];
    }

    let mut hashes = Vec::with_capacity(msg_count - 1);
    for msg in &request.messages[..msg_count - 1] {
        msg.role.hash(&mut hasher);
        msg.content.to_string().hash(&mut hasher);
        hashes.push(hasher.finish());
    }
    hashes
}

/// 从 Anthropic 请求计算缓存相关 token
///
/// `cache_hit_count`: 标准模式下前缀匹配命中的消息数（0 = 全部未命中）
/// 固定模式传入 usize::MAX 表示全部命中
pub fn calculate(request: &MessagesRequest, ratios: CacheRatios, cache_hit_count: usize) -> CacheUsage {
    // 估算 system 的 token 数
    let system_tokens = request
        .system
        .as_ref()
        .map(|msgs| msgs.iter().map(|m| estimate_tokens(&m.text)).sum::<i32>())
        .unwrap_or(0);

    // 为每条 message 估算 token 数
    struct MsgInfo {
        role: String,
        tokens: i32,
    }
    let msg_tokens: Vec<MsgInfo> = request
        .messages
        .iter()
        .map(|msg| MsgInfo {
            role: msg.role.clone(),
            tokens: estimate_message_tokens(&msg.content),
        })
        .collect();

    // 判断是否有 assistant 消息（无 assistant = 首轮对话）
    let has_assistant = msg_tokens.iter().any(|m| m.role == "assistant");

    // 首次对话：没有 assistant 消息，无缓存
    if !has_assistant {
        let raw_total: i32 = system_tokens + msg_tokens.iter().map(|m| m.tokens).sum::<i32>();
        let total_tokens = (raw_total as f64 * ratios.first_turn).ceil() as i32;
        return CacheUsage {
            input_tokens: total_tokens,
            cache_creation_input_tokens: 0,
            cache_read_input_tokens: 0,
        };
    }

    // 多轮对话：定位关键消息
    let mut last_user_idx: Option<usize> = None;
    let mut second_last_user_idx: Option<usize> = None;
    let mut last_assistant_idx: Option<usize> = None;

    for i in (0..msg_tokens.len()).rev() {
        if msg_tokens[i].role == "user" {
            if last_user_idx.is_none() {
                last_user_idx = Some(i);
            } else if second_last_user_idx.is_none() {
                second_last_user_idx = Some(i);
                break;
            }
        }
    }
    for i in (0..msg_tokens.len()).rev() {
        if msg_tokens[i].role == "assistant" {
            last_assistant_idx = Some(i);
            break;
        }
    }

    // 前缀中除最后一条 user 外的消息数
    let prefix_msg_count = if msg_tokens.is_empty() { 0 } else { msg_tokens.len() - 1 };
    // 实际命中的消息数（不超过前缀长度）
    let hit_count = cache_hit_count.min(prefix_msg_count);

    // 完全未命中：全量 input_tokens，无缓存
    if hit_count == 0 {
        let raw_total: i32 = system_tokens + msg_tokens.iter().map(|m| m.tokens).sum::<i32>();
        let total_tokens = (raw_total as f64 * ratios.first_turn).ceil() as i32;
        return CacheUsage {
            input_tokens: total_tokens,
            cache_creation_input_tokens: 0,
            cache_read_input_tokens: 0,
        };
    }

    // 有缓存命中：区分 cache_read / cache_creation / input_tokens
    let mut raw_input = 0;
    let mut raw_creation = 0;
    let mut raw_read = system_tokens; // system prompt 随前缀命中算 cache_read

    for (i, m) in msg_tokens.iter().enumerate() {
        if Some(i) == last_user_idx {
            // 最后一条 user 始终是 input_tokens
            raw_input += m.tokens;
        } else if Some(i) == second_last_user_idx || Some(i) == last_assistant_idx {
            // 倒数第二条 user + 最后一条 assistant 是本轮新增缓存
            raw_creation += m.tokens;
        } else {
            // 其余历史消息：匹配到的是 cache_read，未匹配的是 cache_creation
            if i < hit_count {
                raw_read += m.tokens;
            } else {
                raw_creation += m.tokens;
            }
        }
    }

    let input_tokens = (raw_input as f64 * ratios.uncached).ceil() as i32;
    let cache_creation = (raw_creation as f64 * ratios.creation).ceil() as i32;
    let cache_read = (raw_read as f64 * ratios.read).ceil() as i32;

    CacheUsage {
        input_tokens,
        cache_creation_input_tokens: cache_creation,
        cache_read_input_tokens: cache_read,
    }
}

/// 估算一条消息全部内容的 token 数（含 text、tool_result 等）
fn estimate_message_tokens(content: &serde_json::Value) -> i32 {
    match content {
        // 纯字符串
        serde_json::Value::String(s) => estimate_tokens(s),
        // content block 数组
        serde_json::Value::Array(blocks) => {
            let mut total = 0;
            for block in blocks {
                let block_type = block.get("type").and_then(|v| v.as_str()).unwrap_or("");
                match block_type {
                    "text" => {
                        if let Some(text) = block.get("text").and_then(|v| v.as_str()) {
                            total += estimate_tokens(text);
                        }
                    }
                    "thinking" => {
                        if let Some(text) = block.get("thinking").and_then(|v| v.as_str()) {
                            total += estimate_tokens(text);
                        }
                    }
                    "image" => {
                        total += estimate_image_tokens(block);
                    }
                    "tool_use" => {
                        let s = serde_json::to_string(block).unwrap_or_default();
                        total += estimate_tokens(&s);
                    }
                    "tool_result" => {
                        if let Some(c) = block.get("content") {
                            total += estimate_tool_result_tokens(c);
                        }
                    }
                    _ => {
                        let s = serde_json::to_string(block).unwrap_or_default();
                        total += estimate_tokens(&s);
                    }
                }
            }
            total
        }
        _ => 0,
    }
}

/// 估算 tool_result 的 content 字段的 token 数
fn estimate_tool_result_tokens(content: &serde_json::Value) -> i32 {
    match content {
        serde_json::Value::String(s) => estimate_tokens(s),
        serde_json::Value::Array(blocks) => {
            let mut total = 0;
            for block in blocks {
                let block_type = block.get("type").and_then(|v| v.as_str()).unwrap_or("");
                match block_type {
                    "image" => total += estimate_image_tokens(block),
                    "text" => {
                        if let Some(text) = block.get("text").and_then(|v| v.as_str()) {
                            total += estimate_tokens(text);
                        }
                    }
                    _ => {
                        if let Some(text) = block.get("text").and_then(|v| v.as_str()) {
                            total += estimate_tokens(text);
                        }
                    }
                }
            }
            total
        }
        _ => {
            let s = serde_json::to_string(content).unwrap_or_default();
            estimate_tokens(&s)
        }
    }
}

/// 估算图片的 token 数
///
/// Anthropic 按像素计算：tokens = (width * height) / 750，最小 1600，最大 8400
fn estimate_image_tokens(block: &serde_json::Value) -> i32 {
    if let Some(data) = block
        .get("source")
        .and_then(|s| s.get("data"))
        .and_then(|d| d.as_str())
    {
        if !data.is_empty() {
            let raw_bytes = data.len() * 3 / 4;
            let estimated_pixels = raw_bytes * 15;
            let tokens = (estimated_pixels / 750) as i32;
            return tokens.clamp(1600, 8400);
        }
    }
    1600
}

/// 检测字符串是否为 base64 编码数据
fn is_likely_base64(text: &str) -> bool {
    if text.len() < 10_000 {
        return false;
    }
    let sample: Vec<u8> = text.bytes().take(200).collect();
    let base64_count = sample
        .iter()
        .filter(|&&b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=')
        .count();
    base64_count * 100 / sample.len() >= 95
}

/// 使用 Claude 权重估算文本的 token 数量
fn estimate_tokens(text: &str) -> i32 {
    if text.is_empty() {
        return 0;
    }

    if is_likely_base64(text) {
        let raw_bytes = text.len() * 3 / 4;
        let estimated_pixels = raw_bytes * 15;
        let tokens = (estimated_pixels / 750) as i32;
        return tokens.clamp(1600, 8400);
    }

    const M_WORD: f64 = 1.13;
    const M_NUMBER: f64 = 1.63;
    const M_CJK: f64 = 1.21;
    const M_SYMBOL: f64 = 0.4;
    const M_MATH_SYMBOL: f64 = 4.52;
    const M_URL_DELIM: f64 = 1.26;
    const M_AT_SIGN: f64 = 2.82;
    const M_EMOJI: f64 = 2.6;
    const M_NEWLINE: f64 = 0.89;
    const M_SPACE: f64 = 0.39;

    #[derive(PartialEq)]
    enum WordType {
        None,
        Latin,
        Number,
    }

    let mut current = WordType::None;
    let mut count: f64 = 0.0;

    for r in text.chars() {
        if r.is_whitespace() {
            current = WordType::None;
            if r == '\n' || r == '\t' {
                count += M_NEWLINE;
            } else {
                count += M_SPACE;
            }
            continue;
        }

        if is_cjk_char(r) {
            current = WordType::None;
            count += M_CJK;
            continue;
        }

        if is_emoji_char(r) {
            current = WordType::None;
            count += M_EMOJI;
            continue;
        }

        if r.is_alphabetic() || r.is_numeric() {
            let new_type = if r.is_numeric() {
                WordType::Number
            } else {
                WordType::Latin
            };
            if current == WordType::None || current != new_type {
                if new_type == WordType::Number {
                    count += M_NUMBER;
                } else {
                    count += M_WORD;
                }
                current = new_type;
            }
            continue;
        }

        current = WordType::None;
        if is_math_symbol_char(r) {
            count += M_MATH_SYMBOL;
        } else if r == '@' {
            count += M_AT_SIGN;
        } else if is_url_delim_char(r) {
            count += M_URL_DELIM;
        } else {
            count += M_SYMBOL;
        }
    }

    count.ceil() as i32
}

fn is_cjk_char(r: char) -> bool {
    let c = r as u32;
    unicode_is_han(r) || (0x3040..=0x30FF).contains(&c) || (0xAC00..=0xD7A3).contains(&c)
}

/// 简易判断是否为汉字
fn unicode_is_han(r: char) -> bool {
    let c = r as u32;
    (0x4E00..=0x9FFF).contains(&c)
        || (0x3400..=0x4DBF).contains(&c)
        || (0x20000..=0x2A6DF).contains(&c)
        || (0x2A700..=0x2B73F).contains(&c)
        || (0x2B740..=0x2B81F).contains(&c)
        || (0x2B820..=0x2CEAF).contains(&c)
        || (0xF900..=0xFAFF).contains(&c)
        || (0x2F800..=0x2FA1F).contains(&c)
}

fn is_emoji_char(r: char) -> bool {
    let c = r as u32;
    (0x1F300..=0x1F9FF).contains(&c)
        || (0x2600..=0x26FF).contains(&c)
        || (0x2700..=0x27BF).contains(&c)
        || (0x1F600..=0x1F64F).contains(&c)
        || (0x1F900..=0x1F9FF).contains(&c)
        || (0x1FA00..=0x1FAFF).contains(&c)
}

fn is_math_symbol_char(r: char) -> bool {
    let c = r as u32;
    (0x2200..=0x22FF).contains(&c)
        || (0x2A00..=0x2AFF).contains(&c)
        || (0x1D400..=0x1D7FF).contains(&c)
}

fn is_url_delim_char(r: char) -> bool {
    matches!(r, '/' | ':' | '?' | '&' | '=' | ';' | '#' | '%')
}
