// ACA: real provider — create+egress/get/list/delete driving `AcaClient`.
use std::collections::BTreeMap;
use std::sync::Arc;

use async_trait::async_trait;
// ACA: `aca_account_from_process_env` (used by `SandboxSpec::Aca::build` to
// build its own standalone provider, mirroring the Daytona run-dispatch
// path's own env fallback) reads the same four account-scoping vars the
// server's `aca_account_from_env` reads via `EnvLookup`.
use fabro_static::EnvVars;
use fabro_types::{
    SandboxInfo, SandboxNetwork, SandboxProviderKind, SandboxResources, SandboxState,
    SandboxTimestamps,
};

use crate::aca::{
    AcaClient, AutoSuspendPolicy, CreateDiskImage, CreateResources, CreateSandboxRequest,
    CreateSourcesRef, Lifecycle, SandboxResource, SandboxState as AcaClientState, TokenSource,
};
use crate::provider::{SandboxCreateSpec, SandboxProvider};

/// ACA: default vCPU allotment when a create spec's `AcaConfig` leaves `cpu`
/// unset — matches the capture doc's own zero-flag `aca sandbox create`
/// example (`docs/aca-data-plane-api.md`'s **create** section).
const DEFAULT_ACA_CPU: &str = "1000m";
/// ACA: default memory allotment, paired with [`DEFAULT_ACA_CPU`] — same
/// capture-doc example.
const DEFAULT_ACA_MEMORY: &str = "2048Mi";
/// ACA: default auto-suspend idle interval (seconds) — matches every
/// captured sandbox response's `lifecycle.autoSuspendPolicy.interval`
/// (`docs/aca-data-plane-api.md`). `AcaConfig` has no field for this yet, so
/// it's authored here rather than threaded through from config.
const DEFAULT_AUTO_SUSPEND_INTERVAL_SECS: u64 = 600;

/// ACA: account-level defaults shared by every provider call. `get`/`list`/
/// `delete` only take a sandbox id — not enough to build a data-plane URL on
/// their own (subscription/resourceGroup/sandboxGroup/region are all part of
/// the URL template, see `aca/client.rs`'s `sandboxes_path`) — so the
/// provider carries these as account-level defaults. `create` still prefers
/// its `SandboxCreateSpec::Aca` config's own region/resource-group/
/// sandbox-group when set, falling back to these only when a field is empty.
#[derive(Clone, Debug)]
pub struct AcaAccount {
    pub subscription:   String,
    pub resource_group: String,
    pub sandbox_group:  String,
    pub region:         String,
}

/// Real [`SandboxProvider`] for Azure Container Apps sandboxes, driving
/// [`AcaClient`]'s create/get/list/delete/set_egress endpoints.
pub struct AcaSandboxProvider {
    token:   Arc<dyn TokenSource>,
    http:    fabro_http::HttpClient,
    account: AcaAccount,
    /// ACA: test-only seam. When set, [`Self::client_for`] uses this base
    /// instead of deriving `https://management.<region>.azuredevcompute.io`,
    /// so tests can point every client this provider builds at an httpmock
    /// server — mirroring how `aca/client.rs`'s and `aca/sandbox.rs`'s own
    /// `test_client`/`test_sandbox` helpers inject `server.base_url()`.
    /// Always present (not itself `#[cfg(test)]`-gated) so [`Self::new`]'s
    /// signature matches production exactly; only [`Self::with_base_override`]
    /// (test-only) ever sets it.
    base_override: Option<fabro_http::Url>,
}

impl AcaSandboxProvider {
    pub fn new(
        token: Arc<dyn TokenSource>,
        http: fabro_http::HttpClient,
        account: AcaAccount,
    ) -> Self {
        Self {
            token,
            http,
            account,
            base_override: None,
        }
    }

    #[cfg(test)]
    fn with_base_override(mut self, base: fabro_http::Url) -> Self {
        self.base_override = Some(base);
        self
    }

    /// Build an [`AcaClient`] scoped to `region`/`resource_group`/
    /// `sandbox_group`, with `subscription` always taken from
    /// [`AcaAccount`] (no per-call override exists for it: none of
    /// `SandboxCreateSpec::Aca`'s `AcaConfig`, nor `get`/`list`/`delete`'s
    /// bare id, carry a subscription).
    ///
    /// ACA: `pub(crate)` (not private) so `sandbox_spec.rs`'s
    /// `SandboxSpec::Aca::build` can build a second client scoped to the same
    /// region/resource-group/sandbox-group `create` just used, once it has
    /// the sandbox id `create` returned (see that arm's comment for why one
    /// `AcaClient` can't simply be reused across the two call sites).
    pub(crate) fn client_for(
        &self,
        region: &str,
        resource_group: &str,
        sandbox_group: &str,
    ) -> crate::Result<AcaClient> {
        let base = match &self.base_override {
            Some(base) => base.clone(),
            None => aca_region_base(region)?,
        };
        Ok(AcaClient::new(
            self.http.clone(),
            Arc::clone(&self.token),
            base,
            self.account.subscription.clone(),
            resource_group.to_string(),
            sandbox_group.to_string(),
        ))
    }

    /// [`Self::client_for`] using only [`AcaAccount`]'s defaults — the
    /// shape `get`/`list`/`delete` need, since they take no config of their
    /// own.
    fn account_client(&self) -> crate::Result<AcaClient> {
        self.client_for(
            &self.account.region,
            &self.account.resource_group,
            &self.account.sandbox_group,
        )
    }
}

// ACA: `SandboxSpec::Aca::build` (the run-dispatch path, in `sandbox_spec.rs`)
// has no `EnvLookup`/vault plumbing threaded down to it — unlike the server's
// `build_sandbox_provider_registry`, which reads these same four vars via an
// injected `EnvLookup` for testability. This mirrors `daytona/mod.rs`'s
// `resolve_daytona_api_key`: a standalone construction path falls back to the
// documented process env directly. Returns `None` (not an error) when any of
// the four is unset, exactly like the server's own `aca_account_from_env`;
// the caller turns that into a fail-closed error.
#[expect(
    clippy::disallowed_methods,
    reason = "Standalone ACA sandbox construction falls back to the documented process env vars."
)]
pub(crate) fn aca_account_from_process_env() -> Option<AcaAccount> {
    Some(AcaAccount {
        subscription:   std::env::var(EnvVars::ACA_SUBSCRIPTION_ID).ok()?,
        resource_group: std::env::var(EnvVars::ACA_RESOURCE_GROUP).ok()?,
        sandbox_group:  std::env::var(EnvVars::ACA_SANDBOX_GROUP).ok()?,
        region:         std::env::var(EnvVars::ACA_REGION).ok()?,
    })
}

#[async_trait]
impl SandboxProvider for AcaSandboxProvider {
    fn kind(&self) -> SandboxProviderKind {
        SandboxProviderKind::Aca
    }

    async fn list(&self) -> crate::Result<Vec<SandboxInfo>> {
        let client = self.account_client()?;
        let resources = client.list_sandboxes().await?;
        Ok(resources
            .iter()
            .map(|resource| sandbox_info_from_resource(resource, None))
            .collect())
    }

    async fn get(&self, id: &str) -> crate::Result<Option<SandboxInfo>> {
        let client = self.account_client()?;
        let resource = client.get_sandbox(id).await?;
        Ok(resource
            .as_ref()
            .map(|resource| sandbox_info_from_resource(resource, None)))
    }

    async fn create(&self, spec: SandboxCreateSpec) -> crate::Result<SandboxInfo> {
        // ACA: `github_app`/`run_id`/`clone_origin_url`/`clone_branch` are
        // part of the shared `SandboxCreateSpec` surface (mirroring
        // Daytona/Docker) but unused here — unlike those providers, an ACA
        // sandbox's repo is already present on its disk image, and cloning a
        // fresh run branch onto it is `AcaSandbox::setup_git`'s job later
        // (see `aca/sandbox.rs`), not something this create call performs.
        let SandboxCreateSpec::Aca { config, .. } = spec else {
            return Err(crate::Error::message(
                "ACA sandbox provider can only create ACA sandboxes",
            ));
        };

        let region = non_empty(&config.region).unwrap_or(self.account.region.as_str());
        let resource_group =
            non_empty(&config.resource_group).unwrap_or(self.account.resource_group.as_str());
        let sandbox_group =
            non_empty(&config.sandbox_group).unwrap_or(self.account.sandbox_group.as_str());
        let client = self.client_for(region, resource_group, sandbox_group)?;

        let cpu = config
            .cpu
            .clone()
            .unwrap_or_else(|| DEFAULT_ACA_CPU.to_string());
        let memory = config
            .memory
            .clone()
            .unwrap_or_else(|| DEFAULT_ACA_MEMORY.to_string());

        let request = CreateSandboxRequest {
            lifecycle: Lifecycle {
                auto_suspend_policy: AutoSuspendPolicy {
                    enabled:  true,
                    interval: DEFAULT_AUTO_SUSPEND_INTERVAL_SECS,
                    mode:     "Memory".to_string(),
                },
            },
            resources: CreateResources { cpu, memory },
            sources_ref: CreateSourcesRef {
                disk_image: CreateDiskImage {
                    is_public: true,
                    name:      config.disk.clone(),
                },
            },
        };

        let resource = client.create_sandbox(request).await?;

        let default_action = non_empty(&config.egress.default_action)
            .unwrap_or("Deny")
            .to_string();
        // ACA: a deny-default egress policy must be paired with full
        // traffic inspection, or host-rule matching could be bypassed. This
        // already holds by construction for the environment-settings path
        // (`from_environment.rs`'s `aca_config_from_environment` always
        // pairs `"Deny"` with `"Full"`), but the provider enforces it
        // directly too rather than trusting every `SandboxCreateSpec::Aca`
        // caller to have done so.
        let inspection = if default_action.eq_ignore_ascii_case("deny") {
            "Full".to_string()
        } else {
            non_empty(&config.egress.traffic_inspection)
                .unwrap_or("Full")
                .to_string()
        };

        if let Err(egress_err) = client
            .set_egress(
                &resource.id,
                &default_action,
                &config.egress.rules,
                &inspection,
            )
            .await
        {
            // ACA: `create_sandbox` above already succeeded, so returning
            // `egress_err` as-is here would leak the just-created sandbox —
            // left running and billable with no cleanup or record of it.
            // Mirror `DaytonaSandbox::cleanup_failed_initialization_sandbox`'s
            // intent: best-effort delete it before propagating the original
            // error. The delete's own outcome is only logged, never
            // returned — a failed cleanup must not mask the egress error the
            // caller actually needs to act on.
            if let Err(cleanup_err) = client.delete_sandbox(&resource.id).await {
                tracing::warn!(
                    sandbox_id = %resource.id,
                    cleanup_error = %crate::display_for_log(&cleanup_err),
                    "ACA sandbox created but egress failed; attempted best-effort delete"
                );
            } else {
                tracing::warn!(
                    sandbox_id = %resource.id,
                    "ACA sandbox created but egress failed; attempted best-effort delete"
                );
            }
            return Err(crate::Error::context(
                format!(
                    "sandbox '{}' was created but egress policy failed to apply; attempted cleanup",
                    resource.id
                ),
                egress_err,
            ));
        }

        Ok(sandbox_info_from_resource(
            &resource,
            Some(config.working_dir.clone()),
        ))
    }

    async fn delete(&self, id: &str) -> crate::Result<()> {
        let client = self.account_client()?;
        client.delete_sandbox(id).await
    }
}

/// `None` for an empty string, `Some(value)` otherwise — used for the
/// create-time "config field, falling back to account default" rule.
fn non_empty(value: &str) -> Option<&str> {
    if value.is_empty() { None } else { Some(value) }
}

/// `https://management.<region>.azuredevcompute.io` — the region-specific
/// data-plane host every non-test [`AcaClient`] this provider builds is
/// rooted at (see `aca/client.rs`'s [`AcaClient`] doc comment).
fn aca_region_base(region: &str) -> crate::Result<fabro_http::Url> {
    let raw = format!("https://management.{region}.azuredevcompute.io");
    fabro_http::Url::parse(&raw)
        .map_err(|err| crate::Error::context(format!("Invalid ACA region '{region}'"), err))
}

/// Map a data-plane [`SandboxResource`] to the provider-neutral
/// [`SandboxInfo`] shape, mirroring `details.rs`'s
/// `daytona_info_from_sdk_sandbox`. `working_directory` is only known at
/// create time (from the spec's `AcaConfig`; ACA's API has no such field),
/// so `get`/`list` pass `None`.
fn sandbox_info_from_resource(
    resource: &SandboxResource,
    working_directory: Option<String>,
) -> SandboxInfo {
    let (state, native_state) = match resource.state {
        AcaClientState::Running => (SandboxState::Running, "Running"),
        AcaClientState::Stopped => (SandboxState::Stopped, "Stopped"),
        AcaClientState::Unknown => (SandboxState::Unknown, "Unknown"),
    };

    SandboxInfo {
        provider: SandboxProviderKind::Aca,
        id: resource.id.clone(),
        display_name: None,
        state,
        native_state: Some(native_state.to_string()),
        image: Some(resource.sources_ref.disk_image.id.clone()),
        snapshot: resource.snapshot_id.clone(),
        region: resource.region.clone(),
        web_url: resource.management_url.clone(),
        working_directory,
        resources: SandboxResources {
            cpu_cores:    parse_millicpu(&resource.resources.cpu),
            memory_bytes: parse_mebibytes(&resource.resources.memory),
            disk_bytes:   parse_mebibytes(&resource.resources.disk),
        },
        network: SandboxNetwork::unknown(),
        labels: BTreeMap::new(),
        timestamps: SandboxTimestamps {
            created_at:       parse_rfc3339(&resource.created_at),
            last_activity_at: None,
        },
    }
}

/// Parses a Kubernetes-style millicpu string (e.g. `"1000m"`, per every
/// value [`AcaClient::create_sandbox`]/`get_sandbox`/`list_sandboxes` sends
/// or returns) into whole-core units. `None` for any other shape, rather
/// than failing the whole info mapping over a display-only field.
fn parse_millicpu(value: &str) -> Option<f64> {
    value
        .strip_suffix('m')?
        .parse::<f64>()
        .ok()
        .map(|milli| milli / 1000.0)
}

/// Parses a Kubernetes-style binary-mebibyte string (e.g. `"2048Mi"`) into
/// bytes.
fn parse_mebibytes(value: &str) -> Option<u64> {
    value
        .strip_suffix("Mi")?
        .parse::<u64>()
        .ok()
        .map(|mi| mi * 1024 * 1024)
}

/// Parses an RFC3339 timestamp (e.g. `resource.created_at`) into a UTC
/// `DateTime`, mirroring `details.rs`'s private `parse_rfc3339_utc` (not
/// reachable from here: it's `#[cfg(any(feature = "docker", feature =
/// "daytona"))]`-gated and module-private).
fn parse_rfc3339(value: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    chrono::DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|dt| dt.with_timezone(&chrono::Utc))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use httpmock::Method::{DELETE, GET, POST, PUT};
    use httpmock::MockServer;

    use super::*;
    use crate::aca::{AcaConfig, AcaEgressPolicy};
    use crate::aca::FakeTokenSource;

    const SUBSCRIPTION: &str = "sub-1";
    const RESOURCE_GROUP: &str = "rg-1";
    const SANDBOX_GROUP: &str = "sg-1";
    const REGION: &str = "northeurope";

    fn test_account() -> AcaAccount {
        AcaAccount {
            subscription:   SUBSCRIPTION.to_string(),
            resource_group: RESOURCE_GROUP.to_string(),
            sandbox_group:  SANDBOX_GROUP.to_string(),
            region:         REGION.to_string(),
        }
    }

    fn test_provider(server: &MockServer) -> AcaSandboxProvider {
        AcaSandboxProvider::new(
            Arc::new(FakeTokenSource("test-token".to_string())),
            fabro_test::test_http_client(),
            test_account(),
        )
        .with_base_override(fabro_http::Url::parse(&server.base_url()).expect("parse mock base url"))
    }

    fn test_config() -> AcaConfig {
        AcaConfig {
            region: String::new(),
            resource_group: String::new(),
            sandbox_group: String::new(),
            disk: "ubuntu".to_string(),
            cpu: None,
            memory: None,
            working_dir: "/workspace".to_string(),
            egress: AcaEgressPolicy {
                default_action:     "Deny".to_string(),
                rules:              vec!["github.com:Allow".to_string()],
                traffic_inspection: String::new(),
            },
            region_override: false,
        }
    }

    fn sandboxes_path() -> String {
        format!(
            "/subscriptions/{SUBSCRIPTION}/resourceGroups/{RESOURCE_GROUP}/sandboxGroups/{SANDBOX_GROUP}/sandboxes"
        )
    }

    fn sandbox_path(id: &str) -> String {
        format!("{}/{id}", sandboxes_path())
    }

    fn sandbox_body(id: &str, state: &str) -> serde_json::Value {
        serde_json::json!({
            "id": id,
            "createdAt": "2026-08-01T00:00:00Z",
            "lifecycle": {
                "autoSuspendPolicy": { "enabled": true, "interval": 600, "mode": "Memory" }
            },
            "managementUrl": "https://management.northeurope.azuredevcompute.io",
            "outboundIpAddresses": ["10.0.0.1"],
            "region": REGION,
            "resources": { "cpu": "1000m", "disk": "20480Mi", "memory": "2048Mi" },
            "sourcesRef": { "diskImage": { "id": "img-1", "isPublic": false } },
            "state": state,
            "vmmType": "cloudhypervisor",
        })
    }

    #[tokio::test]
    async fn create_calls_create_then_set_egress_with_full_inspection_when_deny_default() {
        let server = MockServer::start_async().await;
        let create_mock = server
            .mock_async(|when, then| {
                when.method(PUT)
                    .path(sandboxes_path())
                    .json_body(serde_json::json!({
                        "lifecycle": {
                            "autoSuspendPolicy": { "enabled": true, "interval": 600, "mode": "Memory" }
                        },
                        "resources": { "cpu": "1000m", "memory": "2048Mi" },
                        "sourcesRef": { "diskImage": { "isPublic": true, "name": "ubuntu" } }
                    }));
                then.status(200)
                    .header("content-type", "application/json")
                    .json_body(sandbox_body("sbx-new", "Running"));
            })
            .await;
        let egress_mock = server
            .mock_async(|when, then| {
                when.method(POST)
                    .path(format!("{}/egresspolicy", sandbox_path("sbx-new")))
                    .json_body(serde_json::json!({
                        "defaultAction": "Deny",
                        "hostRules": [{ "action": "Allow", "pattern": "github.com" }],
                        "trafficInspection": "Full",
                    }));
                then.status(200)
                    .header("content-type", "application/json")
                    .json_body(serde_json::json!({}));
            })
            .await;
        let provider = test_provider(&server);

        let info = provider
            .create(SandboxCreateSpec::Aca {
                config:           Box::new(test_config()),
                github_app:       None,
                run_id:           None,
                clone_origin_url: None,
                clone_branch:     None,
            })
            .await
            .expect("create should succeed");

        assert_eq!(info.provider, SandboxProviderKind::Aca);
        assert_eq!(info.id, "sbx-new");
        assert_eq!(info.state, SandboxState::Running);
        assert_eq!(info.region.as_deref(), Some(REGION));
        assert_eq!(info.working_directory.as_deref(), Some("/workspace"));
        create_mock.assert_calls_async(1).await;
        egress_mock.assert_calls_async(1).await;
    }

    #[tokio::test]
    async fn create_deletes_sandbox_when_egress_apply_fails() {
        let server = MockServer::start_async().await;
        let create_mock = server
            .mock_async(|when, then| {
                when.method(PUT).path(sandboxes_path());
                then.status(200)
                    .header("content-type", "application/json")
                    .json_body(sandbox_body("sbx-new", "Running"));
            })
            .await;
        let egress_mock = server
            .mock_async(|when, then| {
                when.method(POST)
                    .path(format!("{}/egresspolicy", sandbox_path("sbx-new")));
                then.status(500)
                    .header("content-type", "application/problem+json")
                    .json_body(serde_json::json!({
                        "detail": "Internal error applying egress policy.",
                        "errorCode": 1,
                        "requestId": "req-1",
                        "status": 500,
                        "title": "InternalError",
                        "traceId": "trace-1",
                    }));
            })
            .await;
        let delete_mock = server
            .mock_async(|when, then| {
                when.method(DELETE).path(sandbox_path("sbx-new"));
                then.status(200)
                    .header("content-type", "application/json")
                    .json_body(serde_json::json!({}));
            })
            .await;
        let provider = test_provider(&server);

        let err = provider
            .create(SandboxCreateSpec::Aca {
                config:           Box::new(test_config()),
                github_app:       None,
                run_id:           None,
                clone_origin_url: None,
                clone_branch:     None,
            })
            .await
            .expect_err("create should fail when egress apply fails");

        create_mock.assert_calls_async(1).await;
        egress_mock.assert_calls_async(1).await;
        delete_mock.assert_calls_async(1).await;
        assert!(
            err.to_string().contains("sbx-new"),
            "error should mention the leaked sandbox's id, got: {err}"
        );
    }

    #[tokio::test]
    async fn create_falls_back_to_account_defaults_when_config_scope_is_empty() {
        let server = MockServer::start_async().await;
        let create_mock = server
            .mock_async(|when, then| {
                when.method(PUT).path(sandboxes_path());
                then.status(200)
                    .header("content-type", "application/json")
                    .json_body(sandbox_body("sbx-new", "Running"));
            })
            .await;
        let _egress_mock = server
            .mock_async(|when, then| {
                when.method(POST)
                    .path(format!("{}/egresspolicy", sandbox_path("sbx-new")));
                then.status(200)
                    .header("content-type", "application/json")
                    .json_body(serde_json::json!({}));
            })
            .await;
        let provider = test_provider(&server);

        // test_config() leaves region/resource_group/sandbox_group empty;
        // account defaults must be used to build the request path, which
        // only matches the mock (scoped to SUBSCRIPTION/RESOURCE_GROUP/
        // SANDBOX_GROUP) if the fallback worked.
        provider
            .create(SandboxCreateSpec::Aca {
                config:           Box::new(test_config()),
                github_app:       None,
                run_id:           None,
                clone_origin_url: None,
                clone_branch:     None,
            })
            .await
            .expect("create should succeed using account defaults");

        create_mock.assert_calls_async(1).await;
    }

    #[tokio::test]
    async fn create_preserves_non_full_inspection_when_default_action_is_allow() {
        let server = MockServer::start_async().await;
        let _create_mock = server
            .mock_async(|when, then| {
                when.method(PUT).path(sandboxes_path());
                then.status(200)
                    .header("content-type", "application/json")
                    .json_body(sandbox_body("sbx-new", "Running"));
            })
            .await;
        let egress_mock = server
            .mock_async(|when, then| {
                when.method(POST)
                    .path(format!("{}/egresspolicy", sandbox_path("sbx-new")))
                    .json_body(serde_json::json!({
                        "defaultAction": "Allow",
                        "hostRules": [],
                        "trafficInspection": "None",
                    }));
                then.status(200)
                    .header("content-type", "application/json")
                    .json_body(serde_json::json!({}));
            })
            .await;
        let provider = test_provider(&server);
        let mut config = test_config();
        config.egress = AcaEgressPolicy {
            default_action:     "Allow".to_string(),
            rules:              Vec::new(),
            traffic_inspection: "None".to_string(),
        };

        provider
            .create(SandboxCreateSpec::Aca {
                config:           Box::new(config),
                github_app:       None,
                run_id:           None,
                clone_origin_url: None,
                clone_branch:     None,
            })
            .await
            .expect("create should succeed");

        egress_mock.assert_calls_async(1).await;
    }

    #[tokio::test]
    async fn get_maps_sandbox_resource_to_sandbox_info() {
        let server = MockServer::start_async().await;
        let mock = server
            .mock_async(|when, then| {
                when.method(GET).path(sandbox_path("sbx-1"));
                then.status(200)
                    .header("content-type", "application/json")
                    .json_body(sandbox_body("sbx-1", "Stopped"));
            })
            .await;
        let provider = test_provider(&server);

        let info = provider
            .get("sbx-1")
            .await
            .expect("get should succeed")
            .expect("sandbox should be present");

        assert_eq!(info.provider, SandboxProviderKind::Aca);
        assert_eq!(info.id, "sbx-1");
        assert_eq!(info.state, SandboxState::Stopped);
        assert_eq!(info.native_state.as_deref(), Some("Stopped"));
        assert_eq!(info.image.as_deref(), Some("img-1"));
        assert_eq!(info.region.as_deref(), Some(REGION));
        assert!(info.working_directory.is_none());
        assert_eq!(info.resources.cpu_cores, Some(1.0));
        assert_eq!(info.resources.memory_bytes, Some(2048 * 1024 * 1024));
        assert_eq!(info.resources.disk_bytes, Some(20480 * 1024 * 1024));
        mock.assert_calls_async(1).await;
    }

    #[tokio::test]
    async fn get_returns_none_on_404() {
        let server = MockServer::start_async().await;
        let mock = server
            .mock_async(|when, then| {
                when.method(GET).path(sandbox_path("missing"));
                then.status(404)
                    .header("content-type", "application/problem+json")
                    .json_body(serde_json::json!({
                        "detail": "Requested document not found.",
                        "errorCode": 1,
                        "requestId": "req-1",
                        "status": 404,
                        "title": "SandboxNotFound",
                        "traceId": "trace-1",
                    }));
            })
            .await;
        let provider = test_provider(&server);

        let info = provider.get("missing").await.expect("get should succeed");

        assert!(info.is_none());
        mock.assert_calls_async(1).await;
    }

    #[tokio::test]
    async fn list_maps_every_sandbox_resource() {
        let server = MockServer::start_async().await;
        let mock = server
            .mock_async(|when, then| {
                when.method(GET).path(sandboxes_path());
                then.status(200)
                    .header("content-type", "application/json")
                    .json_body(serde_json::json!([
                        sandbox_body("sbx-1", "Running"),
                        sandbox_body("sbx-2", "Stopped"),
                    ]));
            })
            .await;
        let provider = test_provider(&server);

        let infos = provider.list().await.expect("list should succeed");

        assert_eq!(infos.len(), 2);
        assert_eq!(infos[0].id, "sbx-1");
        assert_eq!(infos[0].state, SandboxState::Running);
        assert_eq!(infos[1].id, "sbx-2");
        assert_eq!(infos[1].state, SandboxState::Stopped);
        mock.assert_calls_async(1).await;
    }

    #[tokio::test]
    async fn delete_calls_delete_sandbox() {
        let server = MockServer::start_async().await;
        let mock = server
            .mock_async(|when, then| {
                when.method(DELETE).path(sandbox_path("sbx-1"));
                then.status(204);
            })
            .await;
        let provider = test_provider(&server);

        provider.delete("sbx-1").await.expect("delete should succeed");

        mock.assert_calls_async(1).await;
    }

    #[test]
    fn kind_is_aca() {
        let server_free_provider = AcaSandboxProvider::new(
            Arc::new(FakeTokenSource("test-token".to_string())),
            fabro_test::test_http_client(),
            test_account(),
        );
        assert_eq!(server_free_provider.kind(), SandboxProviderKind::Aca);
    }
}
