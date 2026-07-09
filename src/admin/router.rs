//! Admin API 路由配置

use axum::{
    Router, middleware,
    routing::{delete, get, post, put},
};

use super::{
    handlers::{
        add_credential, delete_credential, delete_pool_proxy, enable_overage,
        force_refresh_token, get_all_credentials, get_billing_stats, get_cache_interrupt,
        get_cache_mode, get_cache_ratios, get_cooldown_config, get_credential_balance,
        get_load_balancing_mode, get_model_mappings, get_model_prices, get_proxy_latency,
        get_proxy_pool, get_rate_limit_cooldown, import_proxies, reset_billing_stats,
        reset_failure_count, reset_rate_limit, set_cache_interrupt, set_cache_mode,
        set_cache_ratios, set_cooldown_config, set_credential_cooldown,
        set_credential_disabled, set_credential_priority, set_credential_proxy,
        set_credential_rate_limit_cooldown, set_load_balancing_mode, set_model_mappings,
        set_model_prices, set_rate_limit_cooldown, test_pool_proxy,
    },
    middleware::{AdminState, admin_auth_middleware},
};

/// 创建 Admin API 路由
///
/// # 端点
/// - `GET /credentials` - 获取所有凭据状态
/// - `POST /credentials` - 添加新凭据
/// - `DELETE /credentials/:id` - 删除凭据
/// - `POST /credentials/:id/disabled` - 设置凭据禁用状态
/// - `POST /credentials/:id/priority` - 设置凭据优先级
/// - `POST /credentials/:id/reset` - 重置失败计数
/// - `POST /credentials/:id/refresh` - 强制刷新 Token
/// - `GET /credentials/:id/balance` - 获取凭据余额
/// - `POST /credentials/:id/cooldown` - 设置凭据冷却限流
/// - `GET /config/load-balancing` - 获取负载均衡模式
/// - `PUT /config/load-balancing` - 设置负载均衡模式
/// - `GET /config/cooldown` - 获取冷却限流配置
/// - `PUT /config/cooldown` - 设置冷却限流配置
///
/// # 认证
/// 需要 Admin API Key 认证，支持：
/// - `x-api-key` header
/// - `Authorization: Bearer <token>` header
pub fn create_admin_router(state: AdminState) -> Router {
    Router::new()
        .route(
            "/credentials",
            get(get_all_credentials).post(add_credential),
        )
        .route("/credentials/{id}", delete(delete_credential))
        .route("/credentials/{id}/disabled", post(set_credential_disabled))
        .route("/credentials/{id}/priority", post(set_credential_priority))
        .route("/credentials/{id}/reset", post(reset_failure_count))
        .route("/credentials/{id}/refresh", post(force_refresh_token))
        .route("/credentials/{id}/balance", get(get_credential_balance))
        .route("/credentials/{id}/cooldown", post(set_credential_cooldown))
        .route("/credentials/{id}/proxy", post(set_credential_proxy))
        .route("/credentials/{id}/proxy-latency", get(get_proxy_latency))
        .route(
            "/config/load-balancing",
            get(get_load_balancing_mode).put(set_load_balancing_mode),
        )
        .route(
            "/config/cooldown",
            get(get_cooldown_config).put(set_cooldown_config),
        )
        .route(
            "/config/cache-ratios",
            get(get_cache_ratios).put(set_cache_ratios),
        )
        .route(
            "/config/cache-mode",
            get(get_cache_mode).put(set_cache_mode),
        )
        .route(
            "/config/cache-interrupt",
            get(get_cache_interrupt).put(set_cache_interrupt),
        )
        .route(
            "/config/model-mappings",
            get(get_model_mappings).put(set_model_mappings),
        )
        .route(
            "/config/rate-limit-cooldown",
            get(get_rate_limit_cooldown).put(set_rate_limit_cooldown),
        )
        .route(
            "/config/model-prices",
            get(get_model_prices).put(set_model_prices),
        )
        .route("/billing/stats", get(get_billing_stats))
        .route("/billing/reset", post(reset_billing_stats))
        .route("/overage/enable", post(enable_overage))
        .route("/reset-rate-limit", post(reset_rate_limit))
        .route("/set-credential-rate-limit-cooldown", post(set_credential_rate_limit_cooldown))
        .route("/proxy-pool", get(get_proxy_pool))
        .route("/proxy-pool/import", post(import_proxies))
        .route("/proxy-pool/{id}", delete(delete_pool_proxy))
        .route("/proxy-pool/{id}/test", get(test_pool_proxy))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            admin_auth_middleware,
        ))
        .with_state(state)
}
