use std::collections::HashMap;
use std::path::{Path, PathBuf};

use fabro_environment::{
    EnvironmentDraft, EnvironmentId, EnvironmentStore, EnvironmentStoreError,
    import_legacy_directory_once, seed_default_environment, seed_environments,
};
use fabro_types::settings::InterpString;
use fabro_types::settings::run::{
    DockerfileSource, EnvironmentImageSettings, EnvironmentLifecycleSettings,
    EnvironmentNetworkMode, EnvironmentNetworkSettings, EnvironmentProvider,
    EnvironmentResourcesSettings, EnvironmentSettings,
};
use sqlx::Row as _;
use tokio::fs;

struct TestStore {
    dir:   tempfile::TempDir,
    pool:  fabro_db::DbPool,
    store: EnvironmentStore,
}

async fn test_store(local_enabled: bool) -> anyhow::Result<TestStore> {
    let dir = tempfile::tempdir()?;
    let database = fabro_db::Database::connect(dir.path().join("fabro.sqlite3")).await?;
    database.migrate().await?;
    let pool = database.clone_pool();
    let store = EnvironmentStore::load(pool.clone(), local_enabled).await?;
    Ok(TestStore { dir, pool, store })
}

fn settings(provider: EnvironmentProvider) -> EnvironmentSettings {
    EnvironmentSettings {
        provider,
        cwd: None,
        image: EnvironmentImageSettings::default(),
        resources: EnvironmentResourcesSettings::default(),
        network: EnvironmentNetworkSettings::default(),
        lifecycle: EnvironmentLifecycleSettings::default(),
        labels: HashMap::new(),
        env: HashMap::new(),
        // ACA:
        aca: Default::default(),
    }
}

fn draft(id: &str, provider: EnvironmentProvider) -> EnvironmentDraft {
    EnvironmentDraft {
        id:       EnvironmentId::new(id).expect("test environment id should be valid"),
        settings: settings(provider),
    }
}

#[tokio::test]
async fn new_store_lists_only_synthetic_local_when_enabled() -> anyhow::Result<()> {
    let enabled = test_store(true).await?;
    assert_eq!(
        environment_ids(&enabled.store),
        vec!["local"],
        "local should be synthesized, not persisted"
    );
    assert_eq!(sql_environment_count(&enabled.pool).await?, 0);

    let disabled = test_store(false).await?;
    assert!(disabled.store.list().is_empty());

    Ok(())
}

#[tokio::test]
async fn seed_default_is_idempotent_and_reopen_loads_sql_rows() -> anyhow::Result<()> {
    let test = test_store(true).await?;

    seed_environments(&test.pool).await?;
    seed_environments(&test.pool).await?;

    let reopened = EnvironmentStore::load(test.pool.clone(), true).await?;
    assert_eq!(environment_ids(&reopened), vec!["default", "local"]);
    assert_eq!(sql_environment_count(&test.pool).await?, 1);

    Ok(())
}

#[tokio::test]
async fn create_get_replace_delete_and_reload_round_trip_sql_rows() -> anyhow::Result<()> {
    let test = test_store(true).await?;
    let created = test
        .store
        .create(draft("custom", EnvironmentProvider::Docker))
        .await?;

    assert_eq!(created.id.as_str(), "custom");
    assert_eq!(
        test.store
            .get(&EnvironmentId::new("custom").expect("valid id"))
            .expect("created environment should be cached")
            .revision,
        created.revision
    );

    let reopened = EnvironmentStore::load(test.pool.clone(), true).await?;
    assert_eq!(
        reopened
            .get(&EnvironmentId::new("custom").expect("valid id"))
            .expect("created environment should reload")
            .revision,
        created.revision
    );

    let mut replacement = settings(EnvironmentProvider::Local);
    replacement.cwd = Some("/workspace/custom".to_string());
    replacement
        .labels
        .insert("tier".to_string(), "dev".to_string());
    let replaced = test
        .store
        .replace(&created.id, &created.revision, replacement)
        .await?;
    assert_ne!(replaced.revision, created.revision);
    assert_eq!(replaced.settings.cwd.as_deref(), Some("/workspace/custom"));

    let stale = test
        .store
        .replace(
            &created.id,
            &created.revision,
            settings(EnvironmentProvider::Docker),
        )
        .await
        .expect_err("stale revision should be rejected");
    assert!(matches!(stale, EnvironmentStoreError::StaleRevision { .. }));

    test.store.delete(&created.id, &replaced.revision).await?;
    assert!(test.store.get(&created.id).is_none());
    assert!(
        EnvironmentStore::load(test.pool.clone(), true)
            .await?
            .get(&created.id)
            .is_none()
    );

    Ok(())
}

#[tokio::test]
async fn default_is_deletable() -> anyhow::Result<()> {
    let test = test_store(true).await?;
    seed_default_environment(&test.pool, EnvironmentProvider::Docker).await?;
    let store = EnvironmentStore::load(test.pool.clone(), true).await?;
    let default = store
        .get(&EnvironmentId::new("default").expect("valid id"))
        .expect("default should be seeded");

    store.delete(&default.id, &default.revision).await?;

    assert!(store.get(&default.id).is_none());
    assert_eq!(sql_environment_count(&test.pool).await?, 0);

    Ok(())
}

#[tokio::test]
async fn maps_network_lifecycle_and_inline_dockerfile_round_trip() -> anyhow::Result<()> {
    let test = test_store(true).await?;
    let mut settings = settings(EnvironmentProvider::Daytona);
    settings.image.dockerfile = Some(DockerfileSource::Inline("FROM alpine\n".to_string()));
    settings.resources.cpu = Some(4);
    settings.resources.memory = Some("8GB".parse()?);
    settings.resources.disk = Some("20GB".parse()?);
    settings.network.mode = EnvironmentNetworkMode::CidrAllowList;
    settings.network.allow = vec!["10.0.0.0/8".to_string(), "192.168.0.0/16".to_string()];
    settings.lifecycle.preserve = true;
    settings.lifecycle.stop_on_terminal = false;
    settings.lifecycle.auto_stop = Some("30m".parse()?);
    settings
        .labels
        .insert("team".to_string(), "platform".to_string());
    settings.env.insert(
        "TOKEN".to_string(),
        InterpString::parse("Bearer {{ secrets.API_TOKEN }}"),
    );

    let created = test
        .store
        .create(EnvironmentDraft {
            id: EnvironmentId::new("rich").expect("valid id"),
            settings,
        })
        .await?;
    let reloaded = EnvironmentStore::load(test.pool.clone(), true)
        .await?
        .get(&created.id)
        .expect("rich environment should reload");

    assert_eq!(reloaded.settings, created.settings);

    Ok(())
}

#[tokio::test]
async fn direct_create_rejects_dockerfile_path_without_reading_it() -> anyhow::Result<()> {
    let test = test_store(true).await?;
    let mut settings = settings(EnvironmentProvider::Docker);
    settings.image.dockerfile = Some(DockerfileSource::Path {
        path: test.dir.path().join("Dockerfile").display().to_string(),
    });

    let err = test
        .store
        .create(EnvironmentDraft {
            id: EnvironmentId::new("path").expect("valid id"),
            settings,
        })
        .await
        .expect_err("path Dockerfile should be rejected");

    assert!(matches!(err, EnvironmentStoreError::Validation { .. }));
    assert_eq!(sql_environment_count(&test.pool).await?, 0);

    Ok(())
}

#[tokio::test]
async fn legacy_import_missing_directory_is_noop() -> anyhow::Result<()> {
    let test = test_store(true).await?;
    let report =
        import_legacy_directory_once(&test.pool, test.dir.path().join("environments")).await?;

    assert!(report.is_none());
    assert_eq!(sql_environment_count(&test.pool).await?, 0);

    Ok(())
}

#[tokio::test]
async fn legacy_import_imports_rows_renames_source_and_is_idempotent() -> anyhow::Result<()> {
    let test = test_store(true).await?;
    let environment_dir = test.dir.path().join("environments");
    fs::create_dir(&environment_dir).await?;
    fs::write(
        environment_dir.join("cloud.toml"),
        r#"
provider = "docker"

[resources]
cpu = 3
"#,
    )
    .await?;
    fs::write(
        environment_dir.join("local.toml"),
        r#"
provider = "local"

[resources]
cpu = 99
"#,
    )
    .await?;

    let report = import_legacy_directory_once(&test.pool, &environment_dir)
        .await?
        .expect("legacy directory should import");
    let second = import_legacy_directory_once(&test.pool, &environment_dir).await?;

    assert_eq!(report.imported_rows, 1);
    assert_eq!(report.skipped_rows, 1);
    assert_eq!(report.environment_ids, vec!["cloud"]);
    assert!(second.is_none());
    assert!(!environment_dir.exists());
    assert!(report.backup_path.exists());

    let store = EnvironmentStore::load(test.pool.clone(), true).await?;
    assert_eq!(environment_ids(&store), vec!["cloud", "local"]);
    assert_eq!(
        store
            .get(&EnvironmentId::new("cloud").expect("valid id"))
            .expect("cloud should import")
            .settings
            .resources
            .cpu,
        Some(3)
    );
    assert_eq!(sql_environment_count(&test.pool).await?, 1);

    Ok(())
}

#[tokio::test]
async fn legacy_import_keeps_existing_sql_row_and_inlines_dockerfile_path() -> anyhow::Result<()> {
    let test = test_store(true).await?;
    test.store
        .create(draft("existing", EnvironmentProvider::Local))
        .await?;
    let environment_dir = test.dir.path().join("environments");
    fs::create_dir(&environment_dir).await?;
    fs::write(environment_dir.join("Dockerfile"), "FROM alpine\n").await?;
    fs::write(
        environment_dir.join("existing.toml"),
        r#"
provider = "docker"

[image.dockerfile]
path = "missing.Dockerfile"
"#,
    )
    .await?;
    fs::write(
        environment_dir.join("with-dockerfile.toml"),
        r#"
provider = "docker"

[image.dockerfile]
path = "Dockerfile"
"#,
    )
    .await?;

    let report = import_legacy_directory_once(&test.pool, &environment_dir)
        .await?
        .expect("legacy directory should import");

    assert_eq!(report.imported_rows, 1);
    assert_eq!(report.skipped_rows, 1);
    assert_eq!(report.environment_ids, vec!["with-dockerfile"]);

    let store = EnvironmentStore::load(test.pool.clone(), true).await?;
    assert_eq!(
        store
            .get(&EnvironmentId::new("existing").expect("valid id"))
            .expect("existing row should win")
            .settings
            .provider,
        EnvironmentProvider::Local
    );
    assert_eq!(
        store
            .get(&EnvironmentId::new("with-dockerfile").expect("valid id"))
            .expect("dockerfile row should import")
            .settings
            .image
            .dockerfile,
        Some(DockerfileSource::Inline("FROM alpine\n".to_string()))
    );

    Ok(())
}

// ACA:
#[tokio::test]
async fn aca_environment_round_trips_egress_allow_list() -> anyhow::Result<()> {
    let test = test_store(true).await?;
    let mut settings = settings(EnvironmentProvider::Aca);
    settings.aca.region = Some("northeurope".to_string());
    settings.aca.resource_group = Some("rg-fabro".to_string());
    settings.aca.sandbox_group = Some("sg-fabro".to_string());
    settings.aca.disk = Some("ubuntu".to_string());
    settings.aca.region_override = true;
    settings.aca.egress.allow = vec!["*.github.com".to_string(), "api.anthropic.com".to_string()];
    settings.aca.egress.traffic_inspection = Some("Full".to_string());
    settings.aca.auto_suspend = Some("30m".parse()?);

    let created = test
        .store
        .create(EnvironmentDraft {
            id: EnvironmentId::new("aca-env").expect("valid id"),
            settings,
        })
        .await?;

    let reloaded = EnvironmentStore::load(test.pool.clone(), true)
        .await?
        .get(&created.id)
        .expect("aca environment should reload");

    assert_eq!(
        reloaded.settings.aca.egress.allow,
        vec!["*.github.com".to_string(), "api.anthropic.com".to_string()]
    );
    assert_eq!(
        reloaded.settings.aca.sandbox_group.as_deref(),
        Some("sg-fabro")
    );
    assert_eq!(reloaded.settings.aca.region.as_deref(), Some("northeurope"));
    assert_eq!(reloaded.settings, created.settings);

    Ok(())
}

// ACA: exercises the 2026090801 migration's data-copy half for real, not
// against an empty database. It rewinds the migrated database back to the
// pre-aca `environments` shape (mirroring `rewind_automation_target_migration`
// in fabro-db's own `tests/sqlite.rs`), inserts a genuine environment row and
// a referencing `automations` row using that pre-aca schema, then re-runs
// `Database::migrate` so the `INSERT ... SELECT ... FROM environments` copy
// step in the migration actually executes over real data. It then asserts
// both that the row's columns survived the rebuild unchanged (the copy) and
// that the FK still blocks deleting a referenced environment (the rebuilt
// table's constraint re-resolved by name after the RENAME).
#[tokio::test]
async fn automations_fk_and_data_survive_environments_aca_rebuild() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let database = fabro_db::Database::connect(dir.path().join("fabro.sqlite3")).await?;
    database.migrate().await?;
    rewind_environments_aca_migration(database.pool()).await?;

    insert_pre_aca_environment(database.pool(), "referenced").await?;
    sqlx::query(
        r"
        INSERT INTO automations (
            id, revision, name, api_enabled, target_repository, target_branch,
            target_workflow, environment_id
        ) VALUES (?, ?, ?, 0, ?, ?, ?, ?)
        ",
    )
    .bind("fk-test")
    .bind("0".repeat(64))
    .bind("fk test automation")
    .bind("owner/repo")
    .bind("main")
    .bind("ci.yml")
    .bind("referenced")
    .execute(database.pool())
    .await?;

    // Re-applies just the pending 2026090801 migration: the environment row
    // and the referencing automation row above both predate it, so this is
    // where the migration's own `INSERT ... SELECT ... FROM environments`
    // copy step runs over real data for the first time.
    database.migrate().await?;

    let pool = database.clone_pool();
    let row = sqlx::query(
        r"
        SELECT provider, cwd, image_docker, resources_cpu, resources_memory,
               resources_disk, network_mode, network_allow_json, lifecycle_preserve,
               lifecycle_stop_on_terminal, lifecycle_auto_stop, labels_json, env_json,
               aca_region, aca_region_override, aca_egress_allow_json
        FROM environments WHERE id = 'referenced'
        ",
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(row.get::<String, _>("provider"), "docker", "copy: provider");
    assert_eq!(
        row.get::<String, _>("cwd"),
        "/workspace/referenced",
        "copy: cwd"
    );
    assert_eq!(
        row.get::<String, _>("image_docker"),
        "buildpack-deps:noble",
        "copy: image_docker"
    );
    assert_eq!(row.get::<i64, _>("resources_cpu"), 2, "copy: resources_cpu");
    assert_eq!(
        row.get::<String, _>("resources_memory"),
        "4GB",
        "copy: resources_memory"
    );
    assert_eq!(
        row.get::<String, _>("resources_disk"),
        "20GB",
        "copy: resources_disk"
    );
    assert_eq!(
        row.get::<String, _>("network_mode"),
        "allow_all",
        "copy: network_mode"
    );
    assert_eq!(
        row.get::<String, _>("network_allow_json"),
        r#"["10.0.0.0/8"]"#,
        "copy: network_allow_json"
    );
    assert_eq!(
        row.get::<i64, _>("lifecycle_preserve"),
        1,
        "copy: lifecycle_preserve"
    );
    assert_eq!(
        row.get::<i64, _>("lifecycle_stop_on_terminal"),
        0,
        "copy: lifecycle_stop_on_terminal"
    );
    assert_eq!(
        row.get::<String, _>("lifecycle_auto_stop"),
        "30m",
        "copy: lifecycle_auto_stop"
    );
    assert_eq!(
        row.get::<String, _>("labels_json"),
        r#"{"team":"platform"}"#,
        "copy: labels_json"
    );
    assert_eq!(row.get::<String, _>("env_json"), "{}", "copy: env_json");
    // The migration's new `aca_*` columns are additive: a pre-aca row copied
    // through the rebuild must land on their defaults, not garbage.
    assert_eq!(
        row.get::<Option<String>, _>("aca_region"),
        None,
        "new aca_region column should default to NULL for a pre-aca row"
    );
    assert_eq!(
        row.get::<i64, _>("aca_region_override"),
        0,
        "new aca_region_override column should default to 0"
    );
    assert_eq!(
        row.get::<String, _>("aca_egress_allow_json"),
        "[]",
        "new aca_egress_allow_json column should default to '[]'"
    );

    let store = EnvironmentStore::load(pool.clone(), true).await?;
    let referenced_id = EnvironmentId::new("referenced").expect("valid id");
    let referenced = store
        .get(&referenced_id)
        .expect("environment should survive the migration and reload through the store");

    let err = store
        .delete(&referenced_id, &referenced.revision)
        .await
        .expect_err("deleting an environment referenced by automations should fail");
    assert!(
        matches!(err, EnvironmentStoreError::Db { .. }),
        "expected a FK RESTRICT database error, got: {err:?}"
    );
    assert_eq!(
        sql_environment_count(&pool).await?,
        1,
        "RESTRICT should block the delete, not silently no-op it"
    );

    Ok(())
}

/// Rewinds the 2026090801 migration on an already-fully-migrated, empty
/// database: rebuilds `environments` back to its pre-aca shape (the schema
/// from `2026063002_environments.sql`) and removes the migration's bookkeeping
/// row so `Database::migrate` treats it as pending again. Mirrors
/// `rewind_automation_target_migration` in fabro-db's `tests/sqlite.rs`.
///
/// Runs every statement against one acquired connection: `PRAGMA
/// foreign_keys` is connection-scoped, and the pool may otherwise hand later
/// statements a different physical connection than the one the pragma was
/// set on.
async fn rewind_environments_aca_migration(pool: &fabro_db::DbPool) -> anyhow::Result<()> {
    let mut conn = pool.acquire().await?;
    sqlx::query("PRAGMA foreign_keys=OFF")
        .execute(&mut *conn)
        .await?;
    sqlx::query(
        r"
        CREATE TABLE environments_pre_aca (
            id TEXT PRIMARY KEY NOT NULL,
            revision TEXT NOT NULL,
            provider TEXT NOT NULL,
            cwd TEXT,
            image_docker TEXT,
            image_dockerfile_inline TEXT,
            resources_cpu INTEGER,
            resources_memory TEXT,
            resources_disk TEXT,
            network_mode TEXT NOT NULL,
            network_allow_json TEXT NOT NULL DEFAULT '[]',
            lifecycle_preserve INTEGER NOT NULL,
            lifecycle_stop_on_terminal INTEGER NOT NULL,
            lifecycle_auto_stop TEXT,
            labels_json TEXT NOT NULL DEFAULT '{}',
            env_json TEXT NOT NULL DEFAULT '{}',
            CHECK (length(id) BETWEEN 1 AND 63),
            CHECK (substr(id, 1, 1) GLOB '[a-z0-9]'),
            CHECK (id NOT GLOB '*[^a-z0-9-]*'),
            CHECK (id <> 'local'),
            CHECK (length(revision) = 64),
            CHECK (revision NOT GLOB '*[^0-9a-f]*'),
            CHECK (provider IN ('local', 'docker', 'daytona')),
            CHECK (network_mode IN ('allow_all', 'block', 'cidr_allow_list')),
            CHECK (lifecycle_preserve IN (0, 1)),
            CHECK (lifecycle_stop_on_terminal IN (0, 1)),
            CHECK (json_valid(network_allow_json)),
            CHECK (json_valid(labels_json)),
            CHECK (json_valid(env_json))
        )
        ",
    )
    .execute(&mut *conn)
    .await?;
    sqlx::query(
        r"
        INSERT INTO environments_pre_aca (
            id, revision, provider, cwd, image_docker, image_dockerfile_inline,
            resources_cpu, resources_memory, resources_disk, network_mode,
            network_allow_json, lifecycle_preserve, lifecycle_stop_on_terminal,
            lifecycle_auto_stop, labels_json, env_json
        )
        SELECT
            id, revision, provider, cwd, image_docker, image_dockerfile_inline,
            resources_cpu, resources_memory, resources_disk, network_mode,
            network_allow_json, lifecycle_preserve, lifecycle_stop_on_terminal,
            lifecycle_auto_stop, labels_json, env_json
        FROM environments
        ",
    )
    .execute(&mut *conn)
    .await?;
    sqlx::query("DROP TABLE environments")
        .execute(&mut *conn)
        .await?;
    sqlx::query("ALTER TABLE environments_pre_aca RENAME TO environments")
        .execute(&mut *conn)
        .await?;
    sqlx::query("DELETE FROM _sqlx_migrations WHERE version = 2026090801")
        .execute(&mut *conn)
        .await?;
    sqlx::query("PRAGMA foreign_keys=ON")
        .execute(&mut *conn)
        .await?;
    Ok(())
}

/// Inserts a real, non-default row into the pre-aca `environments` shape
/// produced by [`rewind_environments_aca_migration`], populating every
/// pre-aca column with a recognizable value so the migration's copy step can
/// be verified column-by-column afterward.
async fn insert_pre_aca_environment(pool: &fabro_db::DbPool, id: &str) -> anyhow::Result<()> {
    sqlx::query(
        r"
        INSERT INTO environments (
            id, revision, provider, cwd, image_docker, image_dockerfile_inline,
            resources_cpu, resources_memory, resources_disk, network_mode,
            network_allow_json, lifecycle_preserve, lifecycle_stop_on_terminal,
            lifecycle_auto_stop, labels_json, env_json
        ) VALUES (?, ?, 'docker', ?, ?, NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ",
    )
    .bind(id)
    .bind("0".repeat(64))
    .bind(format!("/workspace/{id}"))
    .bind("buildpack-deps:noble")
    .bind(2_i64)
    .bind("4GB")
    .bind("20GB")
    .bind("allow_all")
    .bind(r#"["10.0.0.0/8"]"#)
    .bind(true)
    .bind(false)
    .bind("30m")
    .bind(r#"{"team":"platform"}"#)
    .bind("{}")
    .execute(pool)
    .await?;
    Ok(())
}

#[tokio::test]
async fn legacy_import_invalid_input_leaves_source_directory_in_place() -> anyhow::Result<()> {
    assert_invalid_legacy_import_leaves_source_directory(
        "invalid filename",
        "Bad.toml",
        r#"provider = "local""#,
        "invalid_filename",
    )
    .await?;
    assert_invalid_legacy_import_leaves_source_directory(
        "invalid toml",
        "broken.toml",
        "provider = [",
        "parse",
    )
    .await?;
    assert_invalid_legacy_import_leaves_source_directory(
        "invalid settings",
        "invalid-settings.toml",
        r#"provider = "bogus""#,
        "validation",
    )
    .await?;

    Ok(())
}

async fn assert_invalid_legacy_import_leaves_source_directory(
    case: &str,
    file_name: &str,
    content: &str,
    expected_kind: &str,
) -> anyhow::Result<()> {
    let test = test_store(true).await?;
    let environment_dir = test.dir.path().join("environments");
    fs::create_dir(&environment_dir).await?;
    fs::write(environment_dir.join(file_name), content).await?;

    let Err(err) = import_legacy_directory_once(&test.pool, &environment_dir).await else {
        panic!("{case} should fail import");
    };

    assert_eq!(err.kind(), expected_kind, "{case} error kind");
    assert!(environment_dir.exists(), "{case} source dir should remain");
    assert!(
        legacy_backups(test.dir.path()).await?.is_empty(),
        "{case} should not create a backup"
    );
    assert_eq!(
        sql_environment_count(&test.pool).await?,
        0,
        "{case} should not import rows"
    );

    Ok(())
}

fn environment_ids(store: &EnvironmentStore) -> Vec<String> {
    store
        .list()
        .into_iter()
        .map(|environment| environment.id.to_string())
        .collect()
}

async fn sql_environment_count(pool: &fabro_db::DbPool) -> anyhow::Result<i64> {
    Ok(sqlx::query_scalar("SELECT COUNT(*) FROM environments")
        .fetch_one(pool)
        .await?)
}

async fn legacy_backups(dir: &Path) -> anyhow::Result<Vec<PathBuf>> {
    let mut entries = fs::read_dir(dir).await?;
    let mut backups = Vec::new();
    while let Some(entry) = entries.next_entry().await? {
        let path = entry.path();
        let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if file_name.starts_with("environments.imported-")
            && path
                .extension()
                .is_some_and(|extension| extension.eq_ignore_ascii_case("bak"))
        {
            backups.push(path);
        }
    }
    backups.sort();
    Ok(backups)
}
