use super::*;
use crate::model::config::Config;

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("kiro-mapping-save-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn service(path: &std::path::Path) -> AdminService {
    let config = Config::load(path).unwrap();
    config.save().unwrap();
    let manager = MultiTokenManager::new(config, vec![], None, None, false).unwrap();
    AdminService::new(Arc::new(manager), ["ide".into()])
}

fn mapping(from: &str, to: &str) -> ModelMappingItem {
    ModelMappingItem {
        from: from.into(),
        to: to.into(),
    }
}

fn request() -> SetModelMappingsRequest {
    SetModelMappingsRequest {
        mappings: vec![mapping(" claude-opus-4-6 ", " claude-opus-4.6 ")],
        free_model_mappings: Some(vec![mapping(" claude-opus-4-6 ", " claude-sonnet-4.5 ")]),
    }
}

#[test]
fn invalid_free_rule_does_not_partially_save_the_general_rules() {
    let directory = TestDirectory::new();
    let path = directory.0.join("config.json");
    let service = service(&path);
    let before_memory = serde_json::to_value(service.get_model_mappings()).unwrap();
    let before_disk = std::fs::read(&path).unwrap();
    let result = service.set_model_mappings(SetModelMappingsRequest {
        mappings: vec![mapping("claude-opus-4-6", "claude-haiku-4.5")],
        free_model_mappings: Some(vec![mapping("claude-opus-4-6", " ")]),
    });
    assert!(result.is_err());
    assert_eq!(
        serde_json::to_value(service.get_model_mappings()).unwrap(),
        before_memory
    );
    assert_eq!(std::fs::read(&path).unwrap(), before_disk);
}

#[test]
fn saving_both_tables_survives_reload_and_omitted_free_rules_are_preserved() {
    let directory = TestDirectory::new();
    let path = directory.0.join("config.json");
    let service = service(&path);
    let saved = service.set_model_mappings(request()).unwrap();
    assert_eq!(saved.mappings[0].from, "claude-opus-4-6");
    assert_eq!(saved.free_model_mappings[0].to, "claude-sonnet-4.5");
    let reloaded = Config::load(&path).unwrap();
    assert_eq!(reloaded.model_mappings[0].to, "claude-opus-4.6");
    assert_eq!(reloaded.free_model_mappings[0].to, "claude-sonnet-4.5");

    service
        .set_model_mappings(SetModelMappingsRequest {
            mappings: vec![mapping("claude-opus-4-6", "claude-haiku-4.5")],
            free_model_mappings: None,
        })
        .unwrap();
    let reloaded = Config::load(&path).unwrap();
    assert_eq!(reloaded.model_mappings[0].to, "claude-haiku-4.5");
    assert_eq!(reloaded.free_model_mappings[0].to, "claude-sonnet-4.5");

    service
        .set_model_mappings(SetModelMappingsRequest {
            mappings: vec![mapping("claude-opus-4-6", "claude-opus-4.6")],
            free_model_mappings: Some(vec![]),
        })
        .unwrap();
    assert!(Config::load(&path).unwrap().free_model_mappings.is_empty());
    assert!(service.get_model_mappings().free_model_mappings.is_empty());
}

#[test]
fn persistence_failure_keeps_both_tables_and_allows_retry() {
    let directory = TestDirectory::new();
    let path = directory.0.join("config.json");
    let backup = directory.0.join("original.json");
    let service = service(&path);
    let before = serde_json::to_value(service.get_model_mappings()).unwrap();
    std::fs::rename(&path, &backup).unwrap();
    std::fs::create_dir(&path).unwrap();

    assert!(service.set_model_mappings(request()).is_err());
    assert_eq!(
        serde_json::to_value(service.get_model_mappings()).unwrap(),
        before
    );

    std::fs::remove_dir(&path).unwrap();
    std::fs::rename(&backup, &path).unwrap();
    assert!(service.set_model_mappings(request()).is_ok());
    let reloaded = Config::load(&path).unwrap();
    assert_eq!(reloaded.model_mappings[0].to, "claude-opus-4.6");
    assert_eq!(reloaded.free_model_mappings[0].to, "claude-sonnet-4.5");
}

#[test]
fn concurrent_saves_keep_the_two_tables_and_file_consistent() {
    let directory = TestDirectory::new();
    let path = directory.0.join("config.json");
    let service = service(&path);
    let barrier = std::sync::Barrier::new(4);
    std::thread::scope(|scope| {
        for index in 0..4 {
            let service = &service;
            let barrier = &barrier;
            scope.spawn(move || {
                barrier.wait();
                let target = format!("model-{index}");
                let saved = service
                    .set_model_mappings(SetModelMappingsRequest {
                        mappings: vec![mapping("alias", &target)],
                        free_model_mappings: Some(vec![mapping("alias", &target)]),
                    })
                    .unwrap();
                assert_eq!(saved.mappings[0].to, saved.free_model_mappings[0].to);
            });
        }
    });
    let saved = service.get_model_mappings();
    let reloaded = Config::load(&path).unwrap();
    assert_eq!(saved.mappings[0].to, saved.free_model_mappings[0].to);
    assert_eq!(saved.mappings[0].to, reloaded.model_mappings[0].to);
    assert_eq!(
        saved.free_model_mappings[0].to,
        reloaded.free_model_mappings[0].to
    );
}
