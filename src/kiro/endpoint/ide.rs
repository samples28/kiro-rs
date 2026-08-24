//! Kiro IDE 端点
//!
//! 对应 Kiro IDE 客户端目前使用的 AWS CodeWhisperer 端点：
//! - API: `https://q.{api_region}.amazonaws.com/generateAssistantResponse`
//! - MCP: `https://q.{api_region}.amazonaws.com/mcp`
//!
//! 请求头使用 aws-sdk-js User-Agent 标识。请求体会在根对象上注入 `profileArn`。

use reqwest::RequestBuilder;
use uuid::Uuid;

use super::{KiroEndpoint, RequestContext};

/// Kiro IDE 端点名称
pub const IDE_ENDPOINT_NAME: &str = "ide";

/// Kiro IDE 端点
pub struct IdeEndpoint;

impl IdeEndpoint {
    pub fn new() -> Self {
        Self
    }

    fn api_region<'a>(&self, ctx: &'a RequestContext<'_>) -> &'a str {
        ctx.credentials.effective_api_region(ctx.config)
    }

    fn host(&self, ctx: &RequestContext<'_>) -> String {
        format!("q.{}.amazonaws.com", self.api_region(ctx))
    }

    fn x_amz_user_agent(&self, ctx: &RequestContext<'_>) -> String {
        format!(
            "aws-sdk-js/1.0.34 KiroIDE-{}-{}",
            ctx.config.kiro_version, ctx.machine_id
        )
    }

    fn user_agent(&self, ctx: &RequestContext<'_>) -> String {
        format!(
            "aws-sdk-js/1.0.34 ua/2.1 os/{} lang/js md/nodejs#{} api/codewhispererstreaming#1.0.34 m/E KiroIDE-{}-{}",
            ctx.config.system_version,
            ctx.config.node_version,
            ctx.config.kiro_version,
            ctx.machine_id
        )
    }
}

impl Default for IdeEndpoint {
    fn default() -> Self {
        Self::new()
    }
}

impl KiroEndpoint for IdeEndpoint {
    fn name(&self) -> &'static str {
        IDE_ENDPOINT_NAME
    }

    fn api_url(&self, ctx: &RequestContext<'_>) -> String {
        format!(
            "https://q.{}.amazonaws.com/generateAssistantResponse",
            self.api_region(ctx)
        )
    }

    fn mcp_url(&self, ctx: &RequestContext<'_>) -> String {
        format!("https://q.{}.amazonaws.com/mcp", self.api_region(ctx))
    }

    fn decorate_api(&self, req: RequestBuilder, ctx: &RequestContext<'_>) -> RequestBuilder {
        let mut req = req
            .header("x-amzn-codewhisperer-optout", "true")
            .header("x-amzn-kiro-agent-mode", "vibe")
            .header("x-amz-user-agent", self.x_amz_user_agent(ctx))
            .header("user-agent", self.user_agent(ctx))
            .header("host", self.host(ctx))
            .header("amz-sdk-invocation-id", Uuid::new_v4().to_string())
            .header("amz-sdk-request", "attempt=1; max=3")
            .header("Authorization", format!("Bearer {}", ctx.token));

        if ctx.credentials.is_api_key_credential() {
            req = req.header("tokentype", "API_KEY");
        }
        req
    }

    fn decorate_mcp(&self, req: RequestBuilder, ctx: &RequestContext<'_>) -> RequestBuilder {
        let mut req = req
            .header("x-amz-user-agent", self.x_amz_user_agent(ctx))
            .header("user-agent", self.user_agent(ctx))
            .header("host", self.host(ctx))
            .header("amz-sdk-invocation-id", Uuid::new_v4().to_string())
            .header("amz-sdk-request", "attempt=1; max=3")
            .header("Authorization", format!("Bearer {}", ctx.token));

        // 头部类调用只带真实 ARN：BuilderID 占位符会被上游解析并拒绝
        if let Some(arn) = ctx.credentials.effective_profile_arn() {
            req = req.header("x-amzn-kiro-profile-arn", arn);
        }
        if ctx.credentials.is_api_key_credential() {
            req = req.header("tokentype", "API_KEY");
        }
        req
    }

    fn transform_api_body(&self, body: &str, ctx: &RequestContext<'_>) -> String {
        // 流式端点：按账号类型注入真实 ARN 或占位 ARN。
        // 上游对该端点强制要求 profileArn 存在，缺失会返回
        // 400 {"message":"profileArn is required for this request."}
        // API Key 凭据无 profileArn 概念，返回 None 时不注入。
        inject_profile_arn(body, ctx.credentials.streaming_profile_arn().as_deref())
    }
}

/// 将 profile_arn 注入到请求体 JSON 根对象
fn inject_profile_arn(request_body: &str, profile_arn: Option<&str>) -> String {
    if let Some(arn) = profile_arn {
        if let Ok(mut json) = serde_json::from_str::<serde_json::Value>(request_body) {
            json["profileArn"] = serde_json::Value::String(arn.to_string());
            if let Ok(body) = serde_json::to_string(&json) {
                return body;
            }
        }
    }
    request_body.to_string()
}

#[cfg(test)]
mod tests {
    use super::inject_profile_arn;
    use crate::kiro::model::credentials::{
        KiroCredentials, BUILDER_ID_PROFILE_ARN, SOCIAL_PROFILE_ARN,
    };
    use serde_json::Value;

    #[test]
    fn test_inject_profile_arn_with_some() {
        let body = r#"{"conversationState":{"conversationId":"c1"}}"#;
        let arn = Some("arn:aws:codewhisperer:us-east-1:123:profile/ABC".to_string());
        let result = inject_profile_arn(body, arn.as_deref());
        let json: Value = serde_json::from_str(&result).unwrap();
        assert_eq!(
            json["profileArn"],
            "arn:aws:codewhisperer:us-east-1:123:profile/ABC"
        );
        assert_eq!(json["conversationState"]["conversationId"], "c1");
    }

    #[test]
    fn test_inject_profile_arn_with_none() {
        let body = r#"{"conversationState":{"conversationId":"c1"}}"#;
        let result = inject_profile_arn(body, None);
        let json: Value = serde_json::from_str(&result).unwrap();
        assert!(json.get("profileArn").is_none());
        assert_eq!(json["conversationState"]["conversationId"], "c1");
    }

    #[test]
    fn test_inject_profile_arn_overwrites_existing() {
        let body = r#"{"conversationState":{},"profileArn":"old-arn"}"#;
        let result = inject_profile_arn(body, Some("new-arn"));
        let json: Value = serde_json::from_str(&result).unwrap();
        assert_eq!(json["profileArn"], "new-arn");
    }

    #[test]
    fn test_inject_profile_arn_invalid_json() {
        let body = "not-valid-json";
        let result = inject_profile_arn(body, Some("arn:test"));
        assert_eq!(result, "not-valid-json");
    }

    /// 流式端点：BuilderID 账号（无 ARN）必须注入占位符，否则上游返回
    /// 400 profileArn is required for this request.
    #[test]
    fn test_streaming_injects_builder_id_placeholder() {
        let cred = KiroCredentials::default();
        let body = inject_profile_arn(
            r#"{"conversationState":{}}"#,
            cred.streaming_profile_arn().as_deref(),
        );
        let json: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(json["profileArn"], BUILDER_ID_PROFILE_ARN);
    }

    /// 流式端点：Social 账号（无 ARN）注入 Social 共享 ARN
    #[test]
    fn test_streaming_injects_social_arn_for_social_login() {
        let mut cred = KiroCredentials::default();
        cred.auth_method = Some("social".to_string());
        let body = inject_profile_arn(
            r#"{"conversationState":{}}"#,
            cred.streaming_profile_arn().as_deref(),
        );
        let json: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(json["profileArn"], SOCIAL_PROFILE_ARN);
    }

    /// 提取器导出的 "profileArn": "" 视为未填充，按账号类型推断
    #[test]
    fn test_streaming_treats_empty_arn_as_unset() {
        let mut cred = KiroCredentials::default();
        cred.profile_arn = Some(String::new());
        let body = inject_profile_arn(
            r#"{"conversationState":{}}"#,
            cred.streaming_profile_arn().as_deref(),
        );
        let json: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(json["profileArn"], BUILDER_ID_PROFILE_ARN);
    }

    /// 有真实 ARN 时必须用真实值，不能被占位符覆盖
    #[test]
    fn test_streaming_prefers_real_arn() {
        let mut cred = KiroCredentials::default();
        cred.profile_arn = Some("arn:aws:codewhisperer:us-east-1:1:profile/REAL".to_string());
        let body = inject_profile_arn(
            r#"{"conversationState":{}}"#,
            cred.streaming_profile_arn().as_deref(),
        );
        let json: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(
            json["profileArn"],
            "arn:aws:codewhisperer:us-east-1:1:profile/REAL"
        );
    }

    /// API Key 凭据无 profileArn 概念：不注入
    #[test]
    fn test_streaming_skips_arn_for_api_key_credential() {
        let mut cred = KiroCredentials::default();
        cred.kiro_api_key = Some("ksk_test".to_string());
        let body = inject_profile_arn(
            r#"{"conversationState":{}}"#,
            cred.streaming_profile_arn().as_deref(),
        );
        let json: Value = serde_json::from_str(&body).unwrap();
        assert!(json.get("profileArn").is_none());
    }
}
