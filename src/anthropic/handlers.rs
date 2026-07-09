//! Anthropic API Handler 函数

use std::convert::Infallible;

use anyhow::Error;
use crate::kiro::model::events::Event;
use crate::kiro::model::requests::kiro::KiroRequest;
use crate::kiro::parser::decoder::EventStreamDecoder;
use crate::token;
use axum::{
    Json as JsonExtractor,
    body::Body,
    extract::State,
    http::{StatusCode, header},
    response::{IntoResponse, Json, Response},
};
use bytes::Bytes;
use futures::{Stream, StreamExt, stream};
use serde_json::json;
use std::time::Duration;
use tokio::time::interval;
use uuid::Uuid;

use super::cache_usage;
use super::converter::{ConversionError, convert_request};
use super::middleware::AppState;
use super::stream::{SseEvent, StreamContext};
use super::types::{CountTokensRequest, CountTokensResponse, ErrorResponse, MessagesRequest, Model, ModelsResponse, OutputConfig, Thinking};
use super::websearch;
use crate::common::debug_log;

/// 将 KiroProvider 错误映射为 HTTP 响应
fn map_provider_error(err: Error) -> Response {
    map_provider_error_with_log(err, None)
}

fn map_provider_error_with_log(err: Error, debug_log_instance: Option<&debug_log::SharedRequestLog>) -> Response {
    let err_str = err.to_string();

    // 保存错误日志
    if let Some(logger) = debug_log::get_error_logger() {
        if let Some(log) = debug_log_instance {
            let mut guard = log.lock();
            guard.set_client_response(serde_json::json!({
                "error": err_str,
                "type": "provider_error"
            }));
            guard.mark_error();
            logger.save_error(&guard);
        } else {
            let err_log = logger.new_request_log();
            let mut guard = err_log.lock();
            guard.set_client_response(serde_json::json!({
                "error": err_str,
                "type": "provider_error"
            }));
            guard.mark_error();
            logger.save_error(&guard);
        }
    }

    // 上下文窗口满了（对话历史累积超出模型上下文窗口限制）
    if err_str.contains("CONTENT_LENGTH_EXCEEDS_THRESHOLD") {
        tracing::warn!(error = %err, "上游拒绝请求：上下文窗口已满（不应重试）");
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new(
                "invalid_request_error",
                "Context window is full. Reduce conversation history, system prompt, or tools.",
            )),
        )
            .into_response();
    }

    // 单次输入太长（请求体本身超出上游限制）
    if err_str.contains("Input is too long") {
        tracing::warn!(error = %err, "上游拒绝请求：输入过长（不应重试）");
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new(
                "invalid_request_error",
                "Input is too long. Reduce the size of your messages.",
            )),
        )
            .into_response();
    }
    tracing::error!("Kiro API 调用失败: {}", err);
    (
        StatusCode::BAD_GATEWAY,
        Json(ErrorResponse::new(
            "api_error",
            format!("上游 API 调用失败: {}", err),
        )),
    )
        .into_response()
}

/// GET /v1/models
///
/// 返回可用的模型列表
pub async fn get_models(State(state): State<AppState>) -> impl IntoResponse {
    tracing::info!("Received GET /v1/models request");

    let models = if let Some(ref provider) = state.kiro_provider {
        let mappings = provider.token_manager().get_model_mappings();
        let mut models = Vec::with_capacity(mappings.len() * 2);
        for m in &mappings {
            models.push(Model {
                id: m.from.clone(),
                object: "model".to_string(),
                created: 1770163200,
                owned_by: "anthropic".to_string(),
                display_name: m.from.clone(),
                model_type: "chat".to_string(),
                max_tokens: 64000,
            });
            let thinking_id = format!("{}-thinking", m.from);
            models.push(Model {
                id: thinking_id.clone(),
                object: "model".to_string(),
                created: 1770163200,
                owned_by: "anthropic".to_string(),
                display_name: format!("{} (Thinking)", m.from),
                model_type: "chat".to_string(),
                max_tokens: 64000,
            });
        }
        models
    } else {
        Vec::new()
    };

    Json(ModelsResponse {
        object: "list".to_string(),
        data: models,
    })
}

/// POST /v1/messages
///
/// 创建消息（对话）
pub async fn post_messages(
    State(state): State<AppState>,
    JsonExtractor(mut payload): JsonExtractor<MessagesRequest>,
) -> Response {
    tracing::info!(
        model = %payload.model,
        max_tokens = %payload.max_tokens,
        stream = %payload.stream,
        message_count = %payload.messages.len(),
        "Received POST /v1/messages request"
    );
    handle_messages_common(state, &mut payload).await
}

/// 公共消息处理逻辑
async fn handle_messages_common(
    state: AppState,
    payload: &mut MessagesRequest,
) -> Response {
    // 创建日志实例（debug 或 error_log 任一启用时创建）
    let debug_log_instance = debug_log::get()
        .or(debug_log::get_error_logger())
        .map(|l| l.new_request_log());

    // 阶段 1：记录客户端原始请求
    if let Some(ref log) = debug_log_instance {
        if let Ok(val) = serde_json::to_value(&*payload) {
            log.lock().set_client_request(val);
        }
    }

    let provider = match &state.kiro_provider {
        Some(p) => p.clone(),
        None => {
            tracing::error!("KiroProvider 未配置");
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ErrorResponse::new(
                    "service_unavailable",
                    "Kiro API provider not configured",
                )),
            )
                .into_response();
        }
    };

    // 记录用户原始请求是否携带 thinking 字段（在注入前判断）
    let user_requested_thinking = payload
        .thinking
        .as_ref()
        .map(|t| t.is_enabled())
        .unwrap_or(false);

    override_thinking_from_model_name(payload);

    if websearch::has_web_search_tool(payload) {
        tracing::info!("检测到 WebSearch 工具，路由到 WebSearch 处理");
        let input_tokens = token::count_all_tokens(
            payload.model.clone(),
            payload.system.clone(),
            payload.messages.clone(),
            payload.tools.clone(),
        ) as i32;
        return websearch::handle_websearch_request(provider, payload, input_tokens).await;
    }

    // 解析模型映射
    let model_id = match provider.token_manager().resolve_model(&payload.model) {
        Some(id) => id,
        None => {
            tracing::warn!("模型不支持: {}", payload.model);
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse::new(
                    "invalid_request_error",
                    format!("模型不支持: {}", payload.model),
                )),
            )
                .into_response();
        }
    };

    let conversion_result = match convert_request(payload, &model_id) {
        Ok(result) => result,
        Err(e) => {
            let (error_type, message) = match &e {
                ConversionError::EmptyMessages => {
                    ("invalid_request_error", "消息列表为空".to_string())
                }
            };
            tracing::warn!("请求转换失败: {}", e);
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse::new(error_type, message)),
            )
                .into_response();
        }
    };

    let kiro_request = KiroRequest {
        conversation_state: conversion_result.conversation_state,
        profile_arn: None,
    };

    let request_body = match serde_json::to_string(&kiro_request) {
        Ok(body) => body,
        Err(e) => {
            tracing::error!("序列化请求失败: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse::new(
                    "internal_error",
                    format!("序列化请求失败: {}", e),
                )),
            )
                .into_response();
        }
    };

    tracing::debug!("Kiro request body: {}", request_body);

    // 阶段 2：记录转换后的 Kiro 请求
    if let Some(ref log) = debug_log_instance {
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(&request_body) {
            log.lock().set_kiro_request(val);
        }
    }

    let (creation, read, uncached, first_turn, output_ratio) =
        provider.token_manager().get_cache_ratios();
    let cache_usage = {
        let prefix_hashes = cache_usage::compute_prefix_hashes(payload);
        let cache_hit_count = provider.token_manager().check_prefix_cache(&prefix_hashes);
        cache_usage::calculate(
            payload,
            cache_usage::CacheRatios { creation, read, uncached, first_turn },
            cache_hit_count,
        )
    };
    let tool_name_map = conversion_result.tool_name_map;

    if payload.stream {
        handle_stream_request(
            provider, &request_body, &payload.model,
            user_requested_thinking, tool_name_map, cache_usage, output_ratio,
            debug_log_instance,
        ).await
    } else {
        handle_non_stream_request(
            provider, &request_body, &payload.model,
            user_requested_thinking, tool_name_map, cache_usage, output_ratio,
            debug_log_instance,
        ).await
    }
}

/// 处理流式请求
async fn handle_stream_request(
    provider: std::sync::Arc<crate::kiro::provider::KiroProvider>,
    request_body: &str,
    model: &str,
    emit_thinking: bool,
    tool_name_map: std::collections::HashMap<String, String>,
    cache_usage: cache_usage::CacheUsage,
    output_ratio: f64,
    debug_log_instance: Option<debug_log::SharedRequestLog>,
) -> Response {
    // 调用 Kiro API（支持多凭据故障转移）
    let (credential_id, response) = match provider.call_api_stream(request_body, Some(model)).await {
        Ok(resp) => resp,
        Err(e) => return map_provider_error_with_log(e, debug_log_instance.as_ref()),
    };

    // 创建流处理上下文（thinking_enabled 始终 true，emit_thinking 由用户请求决定）
    let mut ctx = StreamContext::new_with_thinking(model, true, emit_thinking, tool_name_map, cache_usage);
    ctx.debug_log = debug_log_instance;
    ctx.credential_id = Some(credential_id);
    ctx.model_prices = Some(provider.token_manager().config().model_prices.clone());
    ctx.output_ratio = output_ratio;

    // 生成初始事件
    let initial_events = ctx.generate_initial_events();

    // 创建 SSE 流
    let stream = create_sse_stream(response, ctx, initial_events);

    // 返回 SSE 响应
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/event-stream")
        .header(header::CACHE_CONTROL, "no-cache")
        .header(header::CONNECTION, "keep-alive")
        .body(Body::from_stream(stream))
        .unwrap()
}

/// Ping 事件间隔（25秒）
const PING_INTERVAL_SECS: u64 = 25;

/// 创建 ping 事件的 SSE 字符串
fn create_ping_sse() -> Bytes {
    Bytes::from("event: ping\ndata: {\"type\": \"ping\"}\n\n")
}

/// 创建 SSE 事件流
fn create_sse_stream(
    response: reqwest::Response,
    ctx: StreamContext,
    initial_events: Vec<SseEvent>,
) -> impl Stream<Item = Result<Bytes, Infallible>> {
    // 先发送初始事件
    let initial_stream = stream::iter(
        initial_events
            .into_iter()
            .map(|e| Ok(Bytes::from(e.to_sse_string()))),
    );

    // 然后处理 Kiro 响应流，同时每25秒发送 ping 保活
    let body_stream = response.bytes_stream();

    let processing_stream = stream::unfold(
        (body_stream, ctx, EventStreamDecoder::new(), false, interval(Duration::from_secs(PING_INTERVAL_SECS))),
        |(mut body_stream, mut ctx, mut decoder, finished, mut ping_interval)| async move {
            if finished {
                return None;
            }

            // 使用 select! 同时等待数据和 ping 定时器
            tokio::select! {
                // 处理数据流
                chunk_result = body_stream.next() => {
                    match chunk_result {
                        Some(Ok(chunk)) => {
                            // 解码事件
                            if let Err(e) = decoder.feed(&chunk) {
                                tracing::warn!("缓冲区溢出: {}", e);
                            }

                            let mut events = Vec::new();
                            for result in decoder.decode_iter() {
                                match result {
                                    Ok(frame) => {
                                        if let Ok(event) = Event::from_frame(frame) {
                                            let sse_events = ctx.process_kiro_event(&event);
                                            events.extend(sse_events);
                                        }
                                    }
                                    Err(e) => {
                                        tracing::warn!("解码事件失败: {}", e);
                                    }
                                }
                            }

                            // 转换为 SSE 字节流
                            let bytes: Vec<Result<Bytes, Infallible>> = events
                                .into_iter()
                                .map(|e| Ok(Bytes::from(e.to_sse_string())))
                                .collect();

                            Some((stream::iter(bytes), (body_stream, ctx, decoder, false, ping_interval)))
                        }
                        Some(Err(e)) => {
                            tracing::error!("读取响应流失败: {}", e);
                            // 发送最终事件并结束
                            let final_events = ctx.generate_final_events();
                            let bytes: Vec<Result<Bytes, Infallible>> = final_events
                                .into_iter()
                                .map(|e| Ok(Bytes::from(e.to_sse_string())))
                                .collect();
                            Some((stream::iter(bytes), (body_stream, ctx, decoder, true, ping_interval)))
                        }
                        None => {
                            // 流结束，发送最终事件
                            let final_events = ctx.generate_final_events();
                            let bytes: Vec<Result<Bytes, Infallible>> = final_events
                                .into_iter()
                                .map(|e| Ok(Bytes::from(e.to_sse_string())))
                                .collect();
                            Some((stream::iter(bytes), (body_stream, ctx, decoder, true, ping_interval)))
                        }
                    }
                }
                // 发送 ping 保活
                _ = ping_interval.tick() => {
                    tracing::trace!("发送 ping 保活事件");
                    let bytes: Vec<Result<Bytes, Infallible>> = vec![Ok(create_ping_sse())];
                    Some((stream::iter(bytes), (body_stream, ctx, decoder, false, ping_interval)))
                }
            }
        },
    )
    .flatten();

    initial_stream.chain(processing_stream)
}


/// 处理非流式请求
async fn handle_non_stream_request(
    provider: std::sync::Arc<crate::kiro::provider::KiroProvider>,
    request_body: &str,
    model: &str,
    emit_thinking: bool,
    tool_name_map: std::collections::HashMap<String, String>,
    cache_usage: cache_usage::CacheUsage,
    output_ratio: f64,
    debug_log_instance: Option<debug_log::SharedRequestLog>,
) -> Response {
    // 调用 Kiro API（支持多凭据故障转移）
    let (credential_id, response) = match provider.call_api(request_body, Some(model)).await {
        Ok(resp) => resp,
        Err(e) => return map_provider_error_with_log(e, debug_log_instance.as_ref()),
    };

    // 读取响应体
    let body_bytes = match response.bytes().await {
        Ok(bytes) => bytes,
        Err(e) => {
            tracing::error!("读取响应体失败: {}", e);
            return (
                StatusCode::BAD_GATEWAY,
                Json(ErrorResponse::new(
                    "api_error",
                    format!("读取响应失败: {}", e),
                )),
            )
                .into_response();
        }
    };

    // 解析事件流
    let mut decoder = EventStreamDecoder::new();
    if let Err(e) = decoder.feed(&body_bytes) {
        tracing::warn!("缓冲区溢出: {}", e);
    }

    // 阶段 3：记录 Kiro 原始响应
    if let Some(ref log) = debug_log_instance {
        let raw_text = String::from_utf8_lossy(&body_bytes);
        log.lock().set_kiro_response(json!({
            "type": "non_stream",
            "raw": raw_text.as_ref()
        }));
    }

    let mut text_content = String::new();
    let mut tool_uses: Vec<serde_json::Value> = Vec::new();
    let mut has_tool_use = false;
    let mut stop_reason = "end_turn".to_string();
    let mut has_error = false;

    // 收集工具调用的增量 JSON
    let mut tool_json_buffers: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();

    for result in decoder.decode_iter() {
        match result {
            Ok(frame) => {
                if let Ok(event) = Event::from_frame(frame) {
                    match event {
                        Event::AssistantResponse(resp) => {
                            text_content.push_str(&resp.content);
                        }
                        Event::ToolUse(tool_use) => {
                            has_tool_use = true;

                            // 累积工具的 JSON 输入
                            let buffer = tool_json_buffers
                                .entry(tool_use.tool_use_id.clone())
                                .or_insert_with(String::new);
                            buffer.push_str(&tool_use.input);

                            // 如果是完整的工具调用，添加到列表
                            if tool_use.stop {
                                let input: serde_json::Value = if buffer.is_empty() {
                                    serde_json::json!({})
                                } else {
                                    serde_json::from_str(buffer)
                                        .unwrap_or_else(|e| {
                                            tracing::warn!(
                                                "工具输入 JSON 解析失败: {}, tool_use_id: {}",
                                                e, tool_use.tool_use_id
                                            );
                                            serde_json::json!({})
                                        })
                                };

                                let original_name = tool_name_map
                                    .get(&tool_use.name)
                                    .cloned()
                                    .unwrap_or_else(|| tool_use.name.clone());

                                tool_uses.push(json!({
                                    "type": "tool_use",
                                    "id": tool_use.tool_use_id,
                                    "name": original_name,
                                    "input": input
                                }));
                            }
                        }
                        Event::ContextUsage(context_usage) => {
                            // 上下文使用量达到 100% 时，设置 stop_reason 为 model_context_window_exceeded
                            if context_usage.context_usage_percentage >= 100.0 {
                                stop_reason = "model_context_window_exceeded".to_string();
                            }
                            tracing::debug!(
                                "收到 contextUsageEvent: {}%",
                                context_usage.context_usage_percentage
                            );
                        }
                        Event::Exception { exception_type, .. } => {
                            if exception_type == "ContentLengthExceededException" {
                                stop_reason = "max_tokens".to_string();
                            } else {
                                has_error = true;
                            }
                        }
                        Event::Error { .. } => {
                            has_error = true;
                        }
                        _ => {}
                    }
                }
            }
            Err(e) => {
                tracing::warn!("解码事件失败: {}", e);
            }
        }
    }

    // 确定 stop_reason
    if has_tool_use && stop_reason == "end_turn" {
        stop_reason = "tool_use".to_string();
    }

    // 构建响应内容
    let mut content: Vec<serde_json::Value> = Vec::new();

    // 始终尝试提取 thinking 块（因为 converter 总会注入 thinking_mode）
    let (thinking, remaining_text) =
        super::stream::extract_thinking_from_complete_text(&text_content);

    // 仅当用户原始请求携带 thinking 字段时，才将 thinking 块返回给客户端
    if emit_thinking && thinking.is_some() {
        content.push(json!({
            "type": "thinking",
            "thinking": thinking.unwrap()
        }));
    }

    let final_text = remaining_text;
    if !final_text.is_empty() {
        content.push(json!({
            "type": "text",
            "text": final_text
        }));
    }

    content.extend(tool_uses);

    // 估算输出 tokens（套用 output 倍率）
    let output_tokens =
        ((token::estimate_output_tokens(&content) as f64) * output_ratio).ceil() as i32;

    // 错误响应且无有效内容时，不计费
    let final_input_tokens = if has_error && content.is_empty() {
        0
    } else {
        cache_usage.input_tokens
    };

    // 记录计费统计
    if !has_error || !content.is_empty() {
        if let Some(billing) = crate::admin::billing::get() {
            let usage = crate::admin::billing::RequestUsage {
                input_tokens: final_input_tokens,
                output_tokens,
                cache_read_tokens: cache_usage.cache_read_input_tokens,
                cache_write_tokens: cache_usage.cache_creation_input_tokens,
            };
            let prices = provider.token_manager().config().model_prices.clone();
            billing.record(credential_id, model, &usage, &prices);
        }
    }

    // 构建 Anthropic 响应
    let response_body = json!({
        "id": format!("msg_{}", Uuid::new_v4().to_string().replace('-', "")),
        "type": "message",
        "role": "assistant",
        "content": content,
        "model": model,
        "stop_reason": stop_reason,
        "stop_sequence": null,
        "usage": {
            "input_tokens": final_input_tokens,
            "output_tokens": output_tokens,
            "cache_creation_input_tokens": cache_usage.cache_creation_input_tokens,
            "cache_read_input_tokens": cache_usage.cache_read_input_tokens
        }
    });

    // 阶段 4：记录返回客户端的响应，并保存
    if let Some(ref log) = debug_log_instance {
        let mut guard = log.lock();
        guard.set_client_response(response_body.clone());
        if has_error {
            guard.mark_error();
        }
        if let Some(logger) = debug_log::get() {
            logger.save(&guard);
        }
        // 错误日志保存（含请求体和响应体）
        if guard.has_error {
            if let Some(logger) = debug_log::get_error_logger() {
                logger.save_error(&guard);
            }
        }
    }

    (StatusCode::OK, Json(response_body)).into_response()
}

/// 检测模型名是否包含 "thinking" 后缀，若包含则覆写 thinking 配置
///
/// - Opus 4.6：adaptive + effort=high
/// - Opus 4.7：adaptive + effort=max
/// - 其他模型：enabled，budget_tokens=20000
fn override_thinking_from_model_name(payload: &mut MessagesRequest) {
    let model_lower = payload.model.to_lowercase();
    if !model_lower.contains("thinking") {
        // 没有 thinking 后缀，但如果是 4.6/4.7/4.8 系列模型且用户没传 thinking，默认注入 adaptive/low
        if payload.thinking.is_none() {
            let is_adaptive_model = model_lower.contains("4-6") || model_lower.contains("4.6")
                || model_lower.contains("4-7") || model_lower.contains("4.7")
                || model_lower.contains("4-8") || model_lower.contains("4.8");
            if is_adaptive_model {
                payload.thinking = Some(Thinking {
                    thinking_type: "adaptive".to_string(),
                    budget_tokens: 20000,
                });
                payload.output_config = Some(OutputConfig {
                    effort: "low".to_string(),
                    format: None,
                });
            }
        }
        return;
    }

    let is_opus_4_6 = model_lower.contains("opus")
        && (model_lower.contains("4-6") || model_lower.contains("4.6"));
    let is_opus_4_7 = model_lower.contains("opus")
        && (model_lower.contains("4-7") || model_lower.contains("4.7"));
    let is_adaptive_opus = is_opus_4_6 || is_opus_4_7;

    let thinking_type = if is_adaptive_opus {
        "adaptive"
    } else {
        "enabled"
    };

    tracing::info!(
        model = %payload.model,
        thinking_type = thinking_type,
        "模型名包含 thinking 后缀，覆写 thinking 配置"
    );

    payload.thinking = Some(Thinking {
        thinking_type: thinking_type.to_string(),
        budget_tokens: 20000,
    });

    if is_adaptive_opus {
        let effort = if is_opus_4_7 { "max" } else { "high" };
        payload.output_config = Some(OutputConfig {
            effort: effort.to_string(),
            format: None,
        });
    }
}

/// POST /v1/messages/count_tokens
///
/// 计算消息的 token 数量
pub async fn count_tokens(
    JsonExtractor(payload): JsonExtractor<CountTokensRequest>,
) -> impl IntoResponse {
    tracing::info!(
        model = %payload.model,
        message_count = %payload.messages.len(),
        "Received POST /v1/messages/count_tokens request"
    );

    let total_tokens = token::count_all_tokens(
        payload.model,
        payload.system,
        payload.messages,
        payload.tools,
    ) as i32;

    Json(CountTokensResponse {
        input_tokens: total_tokens.max(1) as i32,
    })
}
