use super::*;
use crate::model::config::ModelMapping;

fn credential(id: u64, free: bool, priority: u32) -> KiroCredentials {
    KiroCredentials {
        id: Some(id),
        kiro_api_key: Some(format!("ksk_model_mapping_test_{id}")),
        subscription_title: Some(if free { "KIRO FREE" } else { "KIRO PRO" }.into()),
        priority,
        cooldown_enabled: Some(false),
        ..Default::default()
    }
}

fn config(mode: &str) -> Config {
    let mut config = Config::default();
    config.load_balancing_mode = mode.into();
    config.free_model_mappings = vec![ModelMapping {
        from: "claude-opus-4-6".into(),
        to: "claude-sonnet-4.5".into(),
    }];
    config
}

#[test]
fn priority_selection_treats_free_and_paid_equally() {
    for (free_priority, paid_priority, expected_id) in [(0, 10, 1), (10, 0, 2)] {
        let manager = MultiTokenManager::new(
            config("priority"),
            vec![
                credential(1, true, free_priority),
                credential(2, false, paid_priority),
            ],
            None,
            None,
            false,
        )
        .unwrap();
        let SelectResult::Ready(id, _) = manager.select_next_credential(Some("claude-opus-4-6"))
        else {
            panic!("expected an eligible credential");
        };
        assert_eq!(id, expected_id);
    }
}

#[tokio::test]
async fn balanced_selection_uses_both_subscription_types() {
    let manager = MultiTokenManager::new(
        config("balanced"),
        vec![credential(1, true, 0), credential(2, false, 0)],
        None,
        None,
        false,
    )
    .unwrap();
    let first = manager
        .acquire_context(Some("claude-opus-4-6"))
        .await
        .unwrap();
    let second = manager
        .acquire_context(Some("claude-opus-4-6"))
        .await
        .unwrap();
    assert_ne!(
        first.id, second.id,
        "Free must not take priority over a paid credential"
    );
}

#[tokio::test]
async fn priority_reuse_checks_free_model_eligibility() {
    let manager = MultiTokenManager::new(
        config("priority"),
        vec![credential(1, true, 0), credential(2, false, 1)],
        None,
        None,
        false,
    )
    .unwrap();
    let free = manager
        .acquire_context(Some("claude-opus-4-6"))
        .await
        .unwrap();
    assert_eq!(free.id, 1);
    let paid = manager
        .acquire_context(Some("claude-sonnet-4-6"))
        .await
        .unwrap();
    assert_eq!(
        paid.id, 2,
        "current Free credential has no matching rule for Sonnet 4.6"
    );
    let free_again = manager
        .acquire_context(Some("claude-opus-4-6"))
        .await
        .unwrap();
    assert_eq!(
        free_again.id, 1,
        "reconsider priority when the request model changes"
    );
}

#[tokio::test]
async fn priority_recovers_after_the_higher_priority_account_leaves_cooldown() {
    for first_is_free in [true, false] {
        let manager = MultiTokenManager::new(
            config("priority"),
            vec![
                credential(1, first_is_free, 0),
                credential(2, !first_is_free, 10),
            ],
            None,
            None,
            false,
        )
        .unwrap();
        manager.report_rate_limit(1);
        assert_eq!(
            manager
                .acquire_context(Some("claude-opus-4-6"))
                .await
                .unwrap()
                .id,
            2
        );
        manager.reset_rate_limit(1);
        assert_eq!(
            manager
                .acquire_context(Some("claude-opus-4-6"))
                .await
                .unwrap()
                .id,
            1
        );
    }
}

#[tokio::test]
async fn free_only_pool_rejects_unmapped_requests_without_disabling_the_account() {
    let manager = MultiTokenManager::new(
        config("priority"),
        vec![credential(1, true, 0)],
        None,
        None,
        false,
    )
    .unwrap();
    assert!(
        manager
            .acquire_context(Some("claude-opus-4-6"))
            .await
            .is_ok()
    );
    manager
        .set_model_mappings(manager.get_model_mappings(), Some(vec![]))
        .unwrap();
    let error = manager
        .acquire_context(Some("claude-opus-4-6"))
        .await
        .err()
        .unwrap();
    assert!(error.to_string().contains("没有支持请求模型"));
    assert_eq!(manager.available_count(), 1);
}

#[tokio::test]
async fn alias_defined_only_in_free_mappings_is_not_assigned_to_paid_accounts() {
    let mut config = config("priority");
    config.free_model_mappings[0].from = "work-assistant".into();
    let manager = MultiTokenManager::new(
        config,
        vec![credential(1, false, 0), credential(2, true, 1)],
        None,
        None,
        false,
    )
    .unwrap();
    assert_eq!(manager.resolve_model("work-assistant"), None);
    assert_eq!(
        manager.resolve_request_model("work-assistant").as_deref(),
        Some("claude-sonnet-4.5")
    );
    let ctx = manager
        .acquire_context(Some("work-assistant"))
        .await
        .unwrap();
    assert_eq!(ctx.id, 2);
}

#[test]
fn free_target_uses_the_original_model_and_is_not_remapped_again() {
    let mut config = config("priority");
    config.model_mappings.push(ModelMapping {
        from: "claude-sonnet-4.5".into(),
        to: "claude-haiku-4.5".into(),
    });
    let manager = MultiTokenManager::new(config, vec![], None, None, false).unwrap();
    let requested = "CLAUDE-OPUS-4-6-thinking";
    assert_eq!(
        manager
            .resolve_model_for_credential(requested, &credential(1, true, 0))
            .as_deref(),
        Some("claude-sonnet-4.5")
    );
    assert_eq!(
        manager
            .resolve_model_for_credential(requested, &credential(2, false, 0))
            .as_deref(),
        Some("claude-opus-4.6")
    );
    assert_eq!(
        manager.resolve_model_for_credential("claude-sonnet-4.5", &credential(1, true, 0)),
        None
    );
}

#[test]
fn free_mapping_validation_preserves_existing_rules_and_trims_input() {
    let manager = MultiTokenManager::new(config("priority"), vec![], None, None, false).unwrap();
    for (from, to) in [("", "claude-sonnet-4.5"), ("claude-opus-4-6", "   ")] {
        let invalid = ModelMapping {
            from: from.into(),
            to: to.into(),
        };
        assert!(!invalid.matches_keyword("claude-opus-4-6"));
        assert!(
            manager
                .set_model_mappings(manager.get_model_mappings(), Some(vec![invalid]))
                .is_err()
        );
        assert_eq!(
            manager.resolve_free_model("claude-opus-4-6").as_deref(),
            Some("claude-sonnet-4.5")
        );
    }
    manager
        .set_model_mappings(
            manager.get_model_mappings(),
            Some(vec![ModelMapping {
                from: " claude-opus-4-6 ".into(),
                to: " claude-haiku-4.5 ".into(),
            }]),
        )
        .unwrap();
    assert_eq!(
        manager
            .resolve_free_model("claude-opus-4-6-thinking")
            .as_deref(),
        Some("claude-haiku-4.5")
    );
}
