//! Admin API HTTP 处理器

use axum::{
    Json,
    extract::{Path, Query, State},
    response::IntoResponse,
};

use super::{
    middleware::AdminState,
    types::{
        AddCredentialRequest, ImportProxiesRequest, SetCacheInterruptRequest,
        SetCacheModeRequest, SetCacheRatiosRequest, SetCooldownConfigRequest,
        SetCredentialCooldownRequest, SetDisabledRequest, SetLoadBalancingModeRequest,
        SetModelMappingsRequest, SetModelPricesRequest, SetPriorityRequest, SetProxyRequest,
        SetRateLimitCooldownRequest, SuccessResponse, ModelPricesResponse, ModelPriceItem,
        BillingStatsResponse,
    },
};

/// GET /api/admin/credentials
/// 获取所有凭据状态
pub async fn get_all_credentials(State(state): State<AdminState>) -> impl IntoResponse {
    let response = state.service.get_all_credentials();
    Json(response)
}

/// POST /api/admin/credentials/:id/disabled
/// 设置凭据禁用状态
pub async fn set_credential_disabled(
    State(state): State<AdminState>,
    Path(id): Path<u64>,
    Json(payload): Json<SetDisabledRequest>,
) -> impl IntoResponse {
    match state.service.set_disabled(id, payload.disabled) {
        Ok(_) => {
            let action = if payload.disabled { "禁用" } else { "启用" };
            Json(SuccessResponse::new(format!("凭据 #{} 已{}", id, action))).into_response()
        }
        Err(e) => (e.status_code(), Json(e.into_response())).into_response(),
    }
}

/// POST /api/admin/credentials/:id/priority
/// 设置凭据优先级
pub async fn set_credential_priority(
    State(state): State<AdminState>,
    Path(id): Path<u64>,
    Json(payload): Json<SetPriorityRequest>,
) -> impl IntoResponse {
    match state.service.set_priority(id, payload.priority) {
        Ok(_) => Json(SuccessResponse::new(format!(
            "凭据 #{} 优先级已设置为 {}",
            id, payload.priority
        )))
        .into_response(),
        Err(e) => (e.status_code(), Json(e.into_response())).into_response(),
    }
}

/// POST /api/admin/credentials/:id/reset
/// 重置失败计数并重新启用
pub async fn reset_failure_count(
    State(state): State<AdminState>,
    Path(id): Path<u64>,
) -> impl IntoResponse {
    match state.service.reset_and_enable(id) {
        Ok(_) => Json(SuccessResponse::new(format!(
            "凭据 #{} 失败计数已重置并重新启用",
            id
        )))
        .into_response(),
        Err(e) => (e.status_code(), Json(e.into_response())).into_response(),
    }
}

/// GET /api/admin/credentials/:id/balance
/// 获取指定凭据的余额
pub async fn get_credential_balance(
    State(state): State<AdminState>,
    Path(id): Path<u64>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    let force = params.get("force").map(|v| v == "1" || v == "true").unwrap_or(false);
    match state.service.get_balance_with_option(id, force).await {
        Ok(response) => Json(response).into_response(),
        Err(e) => (e.status_code(), Json(e.into_response())).into_response(),
    }
}

/// POST /api/admin/credentials
/// 添加新凭据
pub async fn add_credential(
    State(state): State<AdminState>,
    Json(payload): Json<AddCredentialRequest>,
) -> impl IntoResponse {
    match state.service.add_credential(payload).await {
        Ok(response) => Json(response).into_response(),
        Err(e) => (e.status_code(), Json(e.into_response())).into_response(),
    }
}

/// DELETE /api/admin/credentials/:id
/// 删除凭据
pub async fn delete_credential(
    State(state): State<AdminState>,
    Path(id): Path<u64>,
) -> impl IntoResponse {
    match state.service.delete_credential(id) {
        Ok(_) => Json(SuccessResponse::new(format!("凭据 #{} 已删除", id))).into_response(),
        Err(e) => (e.status_code(), Json(e.into_response())).into_response(),
    }
}

/// POST /api/admin/credentials/:id/refresh
/// 强制刷新凭据 Token
pub async fn force_refresh_token(
    State(state): State<AdminState>,
    Path(id): Path<u64>,
) -> impl IntoResponse {
    match state.service.force_refresh_token(id).await {
        Ok(_) => Json(SuccessResponse::new(format!(
            "凭据 #{} Token 已强制刷新",
            id
        )))
        .into_response(),
        Err(e) => (e.status_code(), Json(e.into_response())).into_response(),
    }
}

/// GET /api/admin/config/load-balancing
/// 获取负载均衡模式
pub async fn get_load_balancing_mode(State(state): State<AdminState>) -> impl IntoResponse {
    let response = state.service.get_load_balancing_mode();
    Json(response)
}

/// PUT /api/admin/config/load-balancing
/// 设置负载均衡模式
pub async fn set_load_balancing_mode(
    State(state): State<AdminState>,
    Json(payload): Json<SetLoadBalancingModeRequest>,
) -> impl IntoResponse {
    match state.service.set_load_balancing_mode(payload) {
        Ok(response) => Json(response).into_response(),
        Err(e) => (e.status_code(), Json(e.into_response())).into_response(),
    }
}

/// GET /api/admin/config/cooldown
/// 获取冷却限流配置
pub async fn get_cooldown_config(State(state): State<AdminState>) -> impl IntoResponse {
    let response = state.service.get_cooldown_config();
    Json(response)
}

/// PUT /api/admin/config/cooldown
/// 设置冷却限流配置
pub async fn set_cooldown_config(
    State(state): State<AdminState>,
    Json(payload): Json<SetCooldownConfigRequest>,
) -> impl IntoResponse {
    match state.service.set_cooldown_config(payload) {
        Ok(response) => Json(response).into_response(),
        Err(e) => (e.status_code(), Json(e.into_response())).into_response(),
    }
}

/// POST /api/admin/credentials/:id/cooldown
/// 设置单个凭据的冷却限流配置
pub async fn set_credential_cooldown(
    State(state): State<AdminState>,
    Path(id): Path<u64>,
    Json(payload): Json<SetCredentialCooldownRequest>,
) -> impl IntoResponse {
    match state.service.set_credential_cooldown(id, payload) {
        Ok(_) => Json(SuccessResponse::new(format!(
            "凭据 #{} 冷却配置已更新",
            id
        )))
        .into_response(),
        Err(e) => (e.status_code(), Json(e.into_response())).into_response(),
    }
}

/// GET /api/admin/config/cache-ratios
/// 获取缓存 token 估算倍率
pub async fn get_cache_ratios(State(state): State<AdminState>) -> impl IntoResponse {
    Json(state.service.get_cache_ratios())
}

/// PUT /api/admin/config/cache-ratios
/// 设置缓存 token 估算倍率
pub async fn set_cache_ratios(
    State(state): State<AdminState>,
    Json(payload): Json<SetCacheRatiosRequest>,
) -> impl IntoResponse {
    match state.service.set_cache_ratios(payload) {
        Ok(response) => Json(response).into_response(),
        Err(e) => (e.status_code(), Json(e.into_response())).into_response(),
    }
}

/// GET /api/admin/config/cache-mode
pub async fn get_cache_mode(State(state): State<AdminState>) -> impl IntoResponse {
    Json(state.service.get_cache_mode())
}

/// PUT /api/admin/config/cache-mode
pub async fn set_cache_mode(
    State(state): State<AdminState>,
    Json(payload): Json<SetCacheModeRequest>,
) -> impl IntoResponse {
    match state.service.set_cache_mode(payload) {
        Ok(response) => Json(response).into_response(),
        Err(e) => (e.status_code(), Json(e.into_response())).into_response(),
    }
}

/// GET /api/admin/config/cache-interrupt
pub async fn get_cache_interrupt(State(state): State<AdminState>) -> impl IntoResponse {
    Json(state.service.get_cache_interrupt())
}

/// PUT /api/admin/config/cache-interrupt
pub async fn set_cache_interrupt(
    State(state): State<AdminState>,
    Json(payload): Json<SetCacheInterruptRequest>,
) -> impl IntoResponse {
    match state.service.set_cache_interrupt(payload) {
        Ok(response) => Json(response).into_response(),
        Err(e) => (e.status_code(), Json(e.into_response())).into_response(),
    }
}

/// GET /api/admin/config/model-mappings
pub async fn get_model_mappings(State(state): State<AdminState>) -> impl IntoResponse {
    Json(state.service.get_model_mappings())
}

/// PUT /api/admin/config/model-mappings
pub async fn set_model_mappings(
    State(state): State<AdminState>,
    Json(payload): Json<SetModelMappingsRequest>,
) -> impl IntoResponse {
    match state.service.set_model_mappings(payload) {
        Ok(response) => Json(response).into_response(),
        Err(e) => (e.status_code(), Json(e.into_response())).into_response(),
    }
}

/// POST /api/admin/overage/enable
/// 批量开启超额
pub async fn enable_overage(
    State(state): State<AdminState>,
    Json(payload): Json<serde_json::Value>,
) -> impl IntoResponse {
    // 支持传 ids 数组，为空则对所有凭据操作
    let ids: Option<Vec<u64>> = payload.get("ids").and_then(|v| serde_json::from_value(v.clone()).ok());
    let results = if let Some(ids) = ids {
        state.service.token_manager().enable_overage_for_ids(&ids).await
    } else {
        state.service.token_manager().enable_overage_all().await
    };
    Json(serde_json::json!({ "results": results }))
}

/// POST /api/admin/credentials/:id/proxy
/// 设置凭据代理配置
pub async fn set_credential_proxy(
    State(state): State<AdminState>,
    Path(id): Path<u64>,
    Json(payload): Json<SetProxyRequest>,
) -> impl IntoResponse {
    match state.service.set_proxy(id, payload) {
        Ok(_) => Json(SuccessResponse::new(format!(
            "凭据 #{} 代理配置已更新",
            id
        )))
        .into_response(),
        Err(e) => (e.status_code(), Json(e.into_response())).into_response(),
    }
}

/// GET /api/admin/credentials/:id/proxy-latency
/// 检测凭据代理延迟
pub async fn get_proxy_latency(
    State(state): State<AdminState>,
    Path(id): Path<u64>,
) -> impl IntoResponse {
    match state.service.get_proxy_latency(id).await {
        Ok(response) => Json(response).into_response(),
        Err(e) => (e.status_code(), Json(e.into_response())).into_response(),
    }
}

/// GET /api/admin/proxy-pool
/// 获取代理池
pub async fn get_proxy_pool(State(state): State<AdminState>) -> impl IntoResponse {
    Json(state.service.get_proxy_pool())
}

/// POST /api/admin/proxy-pool/import
/// 批量导入代理
pub async fn import_proxies(
    State(state): State<AdminState>,
    Json(payload): Json<ImportProxiesRequest>,
) -> impl IntoResponse {
    let (added, failed) = state.service.import_proxies(&payload.text).await;
    let msg = if failed > 0 {
        format!("成功导入 {} 个代理，{} 个测活失败已跳过", added.len(), failed)
    } else {
        format!("成功导入 {} 个代理", added.len())
    };
    Json(SuccessResponse::new(msg))
}

/// DELETE /api/admin/proxy-pool/:id
/// 删除代理池中的代理
pub async fn delete_pool_proxy(
    State(state): State<AdminState>,
    Path(id): Path<u64>,
) -> impl IntoResponse {
    if state.service.delete_pool_proxy(id) {
        Json(SuccessResponse::new("代理已删除")).into_response()
    } else {
        (axum::http::StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "代理不存在"}))).into_response()
    }
}

/// GET /api/admin/proxy-pool/:id/test
/// 测试代理池中的代理连通性
pub async fn test_pool_proxy(
    State(state): State<AdminState>,
    Path(id): Path<u64>,
) -> impl IntoResponse {
    match state.service.test_pool_proxy(id).await {
        Ok(response) => Json(response).into_response(),
        Err(e) => (e.status_code(), Json(e.into_response())).into_response(),
    }
}

/// GET /api/admin/config/rate-limit-cooldown
pub async fn get_rate_limit_cooldown(State(state): State<AdminState>) -> impl IntoResponse {
    Json(state.service.get_rate_limit_cooldown())
}

/// PUT /api/admin/config/rate-limit-cooldown
pub async fn set_rate_limit_cooldown(
    State(state): State<AdminState>,
    Json(payload): Json<SetRateLimitCooldownRequest>,
) -> impl IntoResponse {
    Json(state.service.set_rate_limit_cooldown(payload.seconds))
}

/// POST /api/admin/reset-rate-limit
/// 批量重置 429 计数
pub async fn reset_rate_limit(
    State(state): State<AdminState>,
    Json(payload): Json<serde_json::Value>,
) -> impl IntoResponse {
    let ids: Vec<u64> = payload.get("ids")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();
    for id in &ids {
        state.service.token_manager().reset_rate_limit(*id);
    }
    Json(SuccessResponse::new(format!("已重置 {} 个凭据的 429 计数", ids.len())))
}

/// POST /api/admin/set-credential-rate-limit-cooldown
/// 批量设置凭据级 429 冷却时长
pub async fn set_credential_rate_limit_cooldown(
    State(state): State<AdminState>,
    Json(payload): Json<serde_json::Value>,
) -> impl IntoResponse {
    let ids: Vec<u64> = payload.get("ids")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();
    let seconds: Option<u64> = payload.get("seconds")
        .and_then(|v| v.as_u64());

    for id in &ids {
        let _ = state.service.token_manager().set_credential_rate_limit_cooldown(*id, seconds);
    }
    let msg = match seconds {
        Some(s) => format!("已设置 {} 个凭据的 429 冷却为 {}s", ids.len(), s),
        None => format!("已设置 {} 个凭据的 429 冷却为跟随全局", ids.len()),
    };
    Json(SuccessResponse::new(msg))
}

/// GET /api/admin/config/model-prices
pub async fn get_model_prices(State(state): State<AdminState>) -> impl IntoResponse {
    let prices = state.service.token_manager().config().model_prices.clone();
    let items: std::collections::HashMap<String, ModelPriceItem> = prices
        .into_iter()
        .map(|(k, v)| (k, ModelPriceItem { input: v.input, output: v.output, cache_read: v.cache_read, cache_write: v.cache_write }))
        .collect();
    Json(ModelPricesResponse { prices: items })
}

/// PUT /api/admin/config/model-prices
pub async fn set_model_prices(
    State(state): State<AdminState>,
    Json(payload): Json<SetModelPricesRequest>,
) -> impl IntoResponse {
    match state.service.set_model_prices(payload) {
        Ok(response) => Json(response).into_response(),
        Err(e) => (e.status_code(), Json(e.into_response())).into_response(),
    }
}

/// GET /api/admin/billing/stats
pub async fn get_billing_stats() -> impl IntoResponse {
    let credentials = super::billing::get()
        .map(|b| b.snapshot())
        .unwrap_or_default();
    Json(BillingStatsResponse { credentials })
}

/// POST /api/admin/billing/reset
pub async fn reset_billing_stats() -> impl IntoResponse {
    if let Some(b) = super::billing::get() {
        b.reset();
    }
    Json(SuccessResponse::new("计费统计已重置"))
}
