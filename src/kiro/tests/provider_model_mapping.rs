use super::*;
use crate::kiro::endpoint::IdeEndpoint;
use crate::model::config::{Config, ModelMapping};
use axum::{Json, Router, extract::State, http::HeaderMap, http::StatusCode, routing::post};
use serde_json::{Value, json};
use std::collections::VecDeque;

#[derive(Clone)]
struct Capture {
    requests: Arc<Mutex<Vec<(u64, Value)>>>,
    statuses: Arc<Mutex<VecDeque<StatusCode>>>,
    pause_next: Arc<Mutex<Option<ResponseGate>>>,
}

#[derive(Clone)]
struct ResponseGate {
    received: Arc<tokio::sync::Notify>,
    release: Arc<tokio::sync::Notify>,
}

struct MockServer {
    capture: Capture,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for MockServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

struct MockEndpoint(String);

impl KiroEndpoint for MockEndpoint {
    fn name(&self) -> &'static str {
        "mock"
    }
    fn api_url(&self, _: &RequestContext<'_>) -> String {
        self.0.clone()
    }
    fn mcp_url(&self, _: &RequestContext<'_>) -> String {
        self.0.clone()
    }
    fn decorate_api(
        &self,
        req: reqwest::RequestBuilder,
        ctx: &RequestContext<'_>,
    ) -> reqwest::RequestBuilder {
        req.header("x-test-credential", ctx.credentials.id.unwrap().to_string())
    }
    fn decorate_mcp(
        &self,
        req: reqwest::RequestBuilder,
        _: &RequestContext<'_>,
    ) -> reqwest::RequestBuilder {
        req
    }
    fn transform_api_body(&self, body: &str, ctx: &RequestContext<'_>) -> String {
        IdeEndpoint::new().transform_api_body(body, ctx)
    }
}

fn credential(id: u64, free: bool) -> KiroCredentials {
    KiroCredentials {
        id: Some(id),
        access_token: Some(format!("local-test-token-{id}")),
        expires_at: Some((chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339()),
        profile_arn: Some(format!(
            "arn:aws:codewhisperer:us-east-1:123456789012:profile/TEST{id}"
        )),
        subscription_title: Some(if free { "KIRO FREE" } else { "KIRO PRO" }.into()),
        priority: id as u32,
        cooldown_enabled: Some(false),
        ..Default::default()
    }
}

async fn setup(
    credentials: Vec<KiroCredentials>,
    statuses: Vec<StatusCode>,
) -> (KiroProvider, MockServer) {
    let capture = Capture {
        requests: Arc::new(Mutex::new(vec![])),
        statuses: Arc::new(Mutex::new(statuses.into())),
        pause_next: Arc::new(Mutex::new(None)),
    };
    let app =
        Router::new()
            .route(
                "/",
                post(
                    |State(capture): State<Capture>,
                     headers: HeaderMap,
                     Json(body): Json<Value>| async move {
                        let id = headers["x-test-credential"]
                            .to_str()
                            .unwrap()
                            .parse()
                            .unwrap();
                        capture.requests.lock().push((id, body));
                        let status = capture
                            .statuses
                            .lock()
                            .pop_front()
                            .unwrap_or(StatusCode::OK);
                        let gate = capture.pause_next.lock().take();
                        if let Some(gate) = gate {
                            gate.received.notify_one();
                            gate.release.notified().await;
                        }
                        (status, Json(json!({"ok": status.is_success()})))
                    },
                ),
            )
            .with_state(capture.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let mut config = Config::default();
    config.free_model_mappings = vec![ModelMapping {
        from: "claude-opus-4-6".into(),
        to: "claude-sonnet-4.5".into(),
    }];
    let manager = Arc::new(MultiTokenManager::new(config, credentials, None, None, false).unwrap());
    let endpoint: Arc<dyn KiroEndpoint> = Arc::new(MockEndpoint(url));
    let provider = KiroProvider::with_proxy(
        manager,
        None,
        HashMap::from([("mock".into(), endpoint)]),
        "mock".into(),
    );
    // Keep every test request on loopback even when the host has a system proxy.
    provider
        .client_cache
        .lock()
        .insert(None, Client::builder().no_proxy().build().unwrap());
    (provider, MockServer { capture, task })
}

fn request_body() -> String {
    json!({
        "conversationState": {
            "conversationId": "test-conversation",
            "currentMessage": {"userInputMessage": {
                "modelId": "claude-opus-4.6",
                "content": "Keep literal claude-opus-4.6 in user text",
                "userInputMessageContext": {
                    "toolResults": [{"content": [{"json": {"modelId": "tool-data"}}]}]
                }
            }},
            "history": [
                {"userInputMessage": {"modelId": "claude-opus-4.6", "content": "earlier"}},
                {"assistantResponseMessage": {"content": "answer", "toolUses": [
                    {"input": {"modelId": "tool-argument"}}
                ]}},
                {"userInputMessage": {"modelId": "claude-opus-4.6", "content": "follow-up"}}
            ]
        }
    })
    .to_string()
}

fn request_log() -> SharedRequestLog {
    Arc::new(Mutex::new(crate::common::debug_log::RequestLog {
        id: "test-request".into(),
        timestamp: "test-time".into(),
        client_request: None,
        kiro_request: None,
        kiro_response: None,
        client_response: None,
        has_error: false,
    }))
}

fn assert_model(body: &Value, expected: &str) {
    assert_eq!(
        body.pointer("/conversationState/currentMessage/userInputMessage/modelId")
            .unwrap(),
        expected
    );
    for index in [0, 2] {
        assert_eq!(
            body["conversationState"]["history"][index]["userInputMessage"]["modelId"],
            expected
        );
    }
    assert_eq!(
        body.pointer("/conversationState/currentMessage/userInputMessage/content")
            .unwrap(),
        "Keep literal claude-opus-4.6 in user text"
    );
    assert_eq!(body.pointer("/conversationState/currentMessage/userInputMessage/userInputMessageContext/toolResults/0/content/0/json/modelId").unwrap(), "tool-data");
    assert_eq!(
        body.pointer(
            "/conversationState/history/1/assistantResponseMessage/toolUses/0/input/modelId"
        )
        .unwrap(),
        "tool-argument"
    );
}

#[tokio::test]
async fn free_only_pool_sends_mapped_model_in_streaming_and_non_streaming_requests() {
    let (provider, server) = setup(vec![credential(1, true)], vec![]).await;
    let body = request_body();
    let log = request_log();
    for stream in [false, true] {
        let result = if stream {
            provider
                .call_api_stream(&body, Some("CLAUDE-OPUS-4-6-thinking"), Some(&log))
                .await
        } else {
            provider
                .call_api(&body, Some("claude-opus-4-6"), Some(&log))
                .await
        }
        .unwrap();
        assert_eq!(result.0, 1);
        assert_eq!(result.1.status(), StatusCode::OK);
    }
    let requests = server.capture.requests.lock();
    assert_eq!(requests.len(), 2);
    assert_eq!(
        log.lock().kiro_request.as_ref().unwrap(),
        &requests.last().unwrap().1
    );
    for (id, body) in requests.iter() {
        assert_eq!(*id, 1);
        assert_model(body, "claude-sonnet-4.5");
        assert!(body["profileArn"].as_str().unwrap().ends_with("TEST1"));
    }
    assert_model(
        &serde_json::from_str::<Value>(&body).unwrap(),
        "claude-opus-4.6",
    );
}

#[tokio::test]
async fn failover_recomputes_model_in_both_directions_and_both_response_modes() {
    for first_is_free in [true, false] {
        for stream in [false, true] {
            let (provider, server) = setup(
                vec![credential(1, first_is_free), credential(2, !first_is_free)],
                vec![StatusCode::PAYMENT_REQUIRED, StatusCode::OK],
            )
            .await;
            let body = request_body();
            let log = request_log();
            let (id, response) = if stream {
                provider
                    .call_api_stream(&body, Some("claude-opus-4-6"), Some(&log))
                    .await
            } else {
                provider
                    .call_api(&body, Some("claude-opus-4-6"), Some(&log))
                    .await
            }
            .unwrap();
            assert_eq!(id, 2);
            assert_eq!(response.status(), StatusCode::OK);
            let requests = server.capture.requests.lock();
            assert_eq!(requests.len(), 2);
            assert_eq!(
                log.lock().kiro_request.as_ref().unwrap(),
                &requests.last().unwrap().1
            );
            for (index, (id, body)) in requests.iter().enumerate() {
                assert_eq!(*id, index as u64 + 1);
                let free = if index == 0 {
                    first_is_free
                } else {
                    !first_is_free
                };
                assert_model(
                    body,
                    if free {
                        "claude-sonnet-4.5"
                    } else {
                        "claude-opus-4.6"
                    },
                );
                assert!(
                    body["profileArn"]
                        .as_str()
                        .unwrap()
                        .ends_with(&format!("TEST{id}"))
                );
            }
        }
    }
}

#[test]
fn malformed_request_cannot_silently_bypass_model_replacement() {
    assert!(KiroProvider::rewrite_request_model("not json", "claude-sonnet-4.5").is_err());
    assert!(KiroProvider::rewrite_request_model("{}", "claude-sonnet-4.5").is_err());
}

#[tokio::test]
async fn failed_requests_log_the_actual_model_of_the_last_account() {
    for stream in [false, true] {
        let (provider, server) = setup(
            vec![credential(1, false), credential(2, true)],
            vec![StatusCode::PAYMENT_REQUIRED, StatusCode::BAD_REQUEST],
        )
        .await;
        let log = request_log();
        let body = request_body();
        let result = if stream {
            provider
                .call_api_stream(&body, Some("claude-opus-4-6"), Some(&log))
                .await
        } else {
            provider
                .call_api(&body, Some("claude-opus-4-6"), Some(&log))
                .await
        };
        assert!(result.is_err());
        let requests = server.capture.requests.lock();
        assert_eq!(requests.len(), 2);
        let logged = log.lock().kiro_request.clone().unwrap();
        assert_model(&logged, "claude-sonnet-4.5");
        assert_eq!(logged, requests.last().unwrap().1);
    }
}

#[tokio::test]
async fn mapping_changes_during_a_request_apply_to_the_next_attempt() {
    for stream in [false, true] {
        let (provider, server) = setup(
            vec![credential(1, true)],
            vec![StatusCode::SERVICE_UNAVAILABLE, StatusCode::OK],
        )
        .await;
        let provider = Arc::new(provider);
        let log = request_log();
        let gate = ResponseGate {
            received: Arc::new(tokio::sync::Notify::new()),
            release: Arc::new(tokio::sync::Notify::new()),
        };
        *server.capture.pause_next.lock() = Some(gate.clone());
        let request = tokio::spawn({
            let provider = provider.clone();
            let log = log.clone();
            async move {
                let body = request_body();
                if stream {
                    provider
                        .call_api_stream(&body, Some("claude-opus-4-6"), Some(&log))
                        .await
                } else {
                    provider
                        .call_api(&body, Some("claude-opus-4-6"), Some(&log))
                        .await
                }
            }
        });
        tokio::time::timeout(Duration::from_secs(3), gate.received.notified())
            .await
            .unwrap();
        assert_model(
            log.lock().kiro_request.as_ref().unwrap(),
            "claude-sonnet-4.5",
        );
        provider
            .token_manager
            .set_model_mappings(
                provider.token_manager.get_model_mappings(),
                Some(vec![ModelMapping {
                    from: "claude-opus-4-6".into(),
                    to: "claude-haiku-4.5".into(),
                }]),
            )
            .unwrap();
        gate.release.notify_one();
        let (id, response) = tokio::time::timeout(Duration::from_secs(3), request)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(id, 1);
        assert_eq!(response.status(), StatusCode::OK);
        let requests = server.capture.requests.lock();
        assert_eq!(requests.len(), 2);
        assert_model(&requests[0].1, "claude-sonnet-4.5");
        assert_model(&requests[1].1, "claude-haiku-4.5");
        assert_eq!(log.lock().kiro_request.as_ref().unwrap(), &requests[1].1);
    }
}

#[tokio::test]
async fn model_catalog_includes_free_aliases_and_has_no_duplicate_ids() {
    let (provider, _upstream) = setup(vec![credential(1, true)], vec![]).await;
    provider
        .token_manager
        .set_model_mappings(
            vec![
                ModelMapping {
                    from: "shared-model".into(),
                    to: "claude-opus-4.6".into(),
                },
                ModelMapping {
                    from: "shared-model-thinking".into(),
                    to: "claude-opus-4.6".into(),
                },
            ],
            Some(vec![
                ModelMapping {
                    from: "work-assistant".into(),
                    to: "claude-sonnet-4.5".into(),
                },
                ModelMapping {
                    from: "SHARED-MODEL".into(),
                    to: "claude-sonnet-4.5".into(),
                },
            ]),
        )
        .unwrap();
    let app =
        crate::anthropic::create_router_with_provider("catalog-test-key", Some(provider), true);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/v1/models", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let response = Client::builder()
        .no_proxy()
        .build()
        .unwrap()
        .get(url)
        .header("x-api-key", "catalog-test-key")
        .send()
        .await
        .unwrap();
    let status = response.status();
    let body: Value = response.json().await.unwrap();
    task.abort();
    assert_eq!(status, StatusCode::OK);
    let ids: Vec<&str> = body["data"]
        .as_array()
        .unwrap()
        .iter()
        .map(|model| model["id"].as_str().unwrap())
        .collect();
    assert!(
        ids.contains(&"work-assistant"),
        "Free-only aliases must be discoverable"
    );
    assert!(ids.contains(&"work-assistant-thinking"));
    assert_eq!(
        ids.iter()
            .filter(|id| id.eq_ignore_ascii_case("shared-model"))
            .count(),
        1
    );
    assert_eq!(
        ids.iter()
            .filter(|id| id.eq_ignore_ascii_case("shared-model-thinking"))
            .count(),
        1
    );
    assert!(!ids.contains(&"shared-model-thinking-thinking"));
}
