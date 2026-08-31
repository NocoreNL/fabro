//! ACA: typed data-plane REST client for sandbox create/get/list/delete,
//! with HTTP-status -> typed-error mapping.
//!
//! Shapes and endpoints are taken verbatim from the live capture in
//! `docs/aca-data-plane-api.md` (Task 2). Exec/fs/lifecycle/egress
//! endpoints are added in Task 7, reusing [`AcaApiError`] defined here.
#![expect(
    clippy::disallowed_types,
    reason = "the ACA data-plane base/request URLs never carry credentials — auth is a \
              bearer token in the Authorization header, not URL userinfo — so raw url::Url \
              is fine here rather than fabro_redact::DisplaySafeUrl"
)]

use std::sync::Arc;

use fabro_http::{HttpClient, Method, Response, StatusCode, Url};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::aca::auth::TokenSource;

/// `api-version` query parameter every data-plane request sends. Confirmed
/// against the capture doc's header (`docs/aca-data-plane-api.md`, top of
/// file: "Captured against `api-version=2026-02-01-preview`").
const API_VERSION: &str = "2026-02-01-preview";

/// `user-agent` header value. The capture doc notes the reference CLI's
/// user-agent is just an example; client code should send its own.
const USER_AGENT: &str = concat!("fabro-aca/", env!("CARGO_PKG_VERSION"));

// --- request/response shapes (docs/aca-data-plane-api.md) -----------------

/// `lifecycle.autoSuspendPolicy` — shared by the create request and every
/// sandbox response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AutoSuspendPolicy {
    pub enabled:  bool,
    /// Seconds.
    pub interval: u64,
    /// Enum observed: `"Memory"`.
    pub mode:     String,
}

/// `lifecycle` — shared by the create request and every sandbox response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Lifecycle {
    pub auto_suspend_policy: AutoSuspendPolicy,
}

/// `resources` as sent in the create request (no `disk` — that's assigned by
/// the server and only appears in responses, see [`SandboxResources`]).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateResources {
    /// Millicpu, e.g. `"1000m"`.
    pub cpu:    String,
    /// e.g. `"2048Mi"`.
    pub memory: String,
}

/// `resources` as it appears in every sandbox response (adds `disk`).
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SandboxResources {
    pub cpu:    String,
    pub memory: String,
    pub disk:   String,
}

/// `sourcesRef.diskImage` as sent in the create request.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateDiskImage {
    pub is_public: bool,
    pub name:      String,
}

/// `sourcesRef` as sent in the create request.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateSourcesRef {
    pub disk_image: CreateDiskImage,
}

/// Body of `PUT .../sandboxes` (create).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateSandboxRequest {
    pub lifecycle:   Lifecycle,
    pub resources:   CreateResources,
    pub sources_ref: CreateSourcesRef,
}

/// `sourcesRef.diskImage` as it appears in a sandbox response — the server
/// resolves the request's `name` to a concrete `id`, and always reports
/// `isPublic: false` for the resolved private copy (per the capture doc's
/// note under **create**).
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DiskImageRef {
    pub id:        String,
    pub is_public: bool,
}

/// `sourcesRef` as it appears in a sandbox response.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SourcesRef {
    pub disk_image: DiskImageRef,
}

/// `stateDetails`, present once a sandbox has been stopped at least once.
///
/// The capture doc's `snapshotId` is a sibling field on the sandbox
/// resource itself (see the `resume` response), not nested here.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StateDetails {
    pub stopped_at:     Option<String>,
    pub stopped_reason: Option<String>,
}

/// `state` field of a sandbox resource.
///
/// The capture doc only observed `"Running"`/`"Stopped"` and explicitly
/// warns the preview surface may have additional values ("treat every field
/// list as observed present, not necessarily exhaustive"). `Unknown` is a
/// forward-compatible catch-all for any value this client hasn't seen yet
/// (e.g. a transitional state introduced later) so an unrecognized state
/// string fails soft instead of breaking deserialization of the whole
/// response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SandboxState {
    Running,
    Stopped,
    #[serde(other)]
    Unknown,
}

/// The **Sandbox** resource — the common response shape for create/get/list.
///
/// Fields the capture doc shows as always empty in this preview
/// (`connections`, `contentPackageDownloads`, `labels`, `ports`, `volumes`)
/// are intentionally left unmodeled here: `serde` ignores unrecognized
/// response fields by default, so they don't block deserialization, and
/// nothing in create/get/list/delete (this task) or exec/fs/lifecycle
/// (Task 7) needs their contents. A later task can add them if a caller
/// needs them.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SandboxResource {
    pub id:         String,
    pub state:      SandboxState,
    pub region:     String,
    pub created_at: String,
    pub management_url: String,
    pub lifecycle:  Lifecycle,
    pub resources:  SandboxResources,
    pub sources_ref: SourcesRef,
    pub vmm_type:   String,
    /// Absent from the initial `create` response (server assigns egress IPs
    /// after the fact); present on `get`/`list`.
    #[serde(default)]
    pub outbound_ip_addresses: Vec<String>,
    /// Present once the sandbox has been stopped at least once.
    #[serde(default)]
    pub state_details: Option<StateDetails>,
    /// Sibling of `stateDetails` on the sandbox resource (see doc note on
    /// [`StateDetails`]); present once the sandbox has been stopped/resumed.
    #[serde(default)]
    pub snapshot_id: Option<String>,
}

// --- error mapping ----------------------------------------------------

/// Typed classification of an ACA data-plane error response.
///
/// Reused by Task 7's exec/fs/lifecycle/egress endpoints on the same
/// client, so the status-code classification lives in one place.
#[derive(Debug, thiserror::Error)]
pub enum AcaApiError {
    /// HTTP 403. The capture doc doesn't show a 403 body (only 404/409 were
    /// captured live), so this message is authored rather than lifted from
    /// a response — it names the role an operator needs to grant on the
    /// sandbox group for the caller's identity.
    #[error(
        "ACA data-plane request was denied (403) — the caller's identity is missing the \
         'Container Apps SandboxGroup Data Owner' role assignment on the sandbox group"
    )]
    Auth,

    /// HTTP 404 (captured live as `SandboxNotFound`).
    #[error("ACA sandbox not found")]
    NotFound,

    /// HTTP 409 (captured live as `GlobalSandboxNotRunning`).
    #[error("ACA sandbox is not running (GlobalSandboxNotRunning)")]
    NotRunning,

    /// Any other non-success status.
    #[error("ACA data-plane request failed with HTTP {status}: {message}")]
    Other { status: u16, message: String },
}

/// Classify a non-success HTTP status into an [`AcaApiError`].
///
/// `body` is the raw response text; when it parses as the capture doc's
/// `problem+json` shape, `title`/`detail` are folded into
/// [`AcaApiError::Other`]'s message for statuses that don't get a specific
/// variant.
fn map_status(status: StatusCode, body: &str) -> AcaApiError {
    match status {
        StatusCode::FORBIDDEN => AcaApiError::Auth,
        StatusCode::NOT_FOUND => AcaApiError::NotFound,
        StatusCode::CONFLICT => AcaApiError::NotRunning,
        other => AcaApiError::Other {
            status:  other.as_u16(),
            message: extract_problem_message(body).unwrap_or_else(|| body.to_string()),
        },
    }
}

/// Best-effort extraction of `title`/`detail` from a `problem+json` error
/// body (see the capture doc's **error shapes** section).
fn extract_problem_message(body: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(body).ok()?;
    let title = value.get("title").and_then(serde_json::Value::as_str);
    let detail = value.get("detail").and_then(serde_json::Value::as_str);
    match (title, detail) {
        (Some(title), Some(detail)) => Some(format!("{title}: {detail}")),
        (Some(title), None) => Some(title.to_string()),
        (None, Some(detail)) => Some(detail.to_string()),
        (None, None) => None,
    }
}

// --- client -------------------------------------------------------------

/// Typed REST client over the ACA sandbox data plane.
///
/// One instance is scoped to a single subscription/resource-group/
/// sandbox-group triple — every URL template in the capture doc is rooted
/// at that path.
pub struct AcaClient {
    http:           HttpClient,
    token:          Arc<dyn TokenSource>,
    /// `https://management.<region>.azuredevcompute.io` — region-specific
    /// data-plane host (distinct from the region-agnostic token audience,
    /// see the capture doc's **Base host / audience** section).
    base:           Url,
    subscription:   String,
    resource_group: String,
    sandbox_group:  String,
}

impl AcaClient {
    pub fn new(
        http: HttpClient,
        token: Arc<dyn TokenSource>,
        base: Url,
        subscription: impl Into<String>,
        resource_group: impl Into<String>,
        sandbox_group: impl Into<String>,
    ) -> Self {
        Self {
            http,
            token,
            base,
            subscription: subscription.into(),
            resource_group: resource_group.into(),
            sandbox_group: sandbox_group.into(),
        }
    }

    /// `PUT .../sandboxes` — create a sandbox.
    pub async fn create_sandbox(
        &self,
        request: CreateSandboxRequest,
    ) -> crate::Result<SandboxResource> {
        let url = self.sandboxes_url();
        let response = self.send(Method::PUT, url, Some(&request)).await?;
        let body = Self::ok_body(response, "create sandbox").await?;
        Self::decode(&body, "create sandbox")
    }

    /// `GET .../sandboxes/{id}` — returns `Ok(None)` on the captured
    /// `404 SandboxNotFound`, matching the capture doc's note that `get` on
    /// a deleted/never-existent sandbox 404s.
    pub async fn get_sandbox(&self, id: &str) -> crate::Result<Option<SandboxResource>> {
        let url = self.sandbox_url(id);
        let response = self.send::<()>(Method::GET, url, None).await?;
        if response.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let body = Self::ok_body(response, "get sandbox").await?;
        Self::decode(&body, "get sandbox").map(Some)
    }

    /// `GET .../sandboxes` — bare JSON array, `[]` when empty.
    pub async fn list_sandboxes(&self) -> crate::Result<Vec<SandboxResource>> {
        let url = self.sandboxes_url();
        let response = self.send::<()>(Method::GET, url, None).await?;
        let body = Self::ok_body(response, "list sandboxes").await?;
        Self::decode(&body, "list sandboxes")
    }

    /// `DELETE .../sandboxes/{id}`. Deletion is asynchronous server-side
    /// (see the capture doc), so a successful call here only confirms the
    /// delete was accepted, not that the sandbox is gone yet.
    pub async fn delete_sandbox(&self, id: &str) -> crate::Result<()> {
        let url = self.sandbox_url(id);
        let response = self.send::<()>(Method::DELETE, url, None).await?;
        Self::ok_body(response, "delete sandbox").await?;
        Ok(())
    }

    fn sandboxes_path(&self) -> String {
        format!(
            "/subscriptions/{}/resourceGroups/{}/sandboxGroups/{}/sandboxes",
            self.subscription, self.resource_group, self.sandbox_group
        )
    }

    fn sandboxes_url(&self) -> Url {
        let mut url = self.base.clone();
        url.set_path(&self.sandboxes_path());
        url
    }

    fn sandbox_url(&self, id: &str) -> Url {
        let mut url = self.base.clone();
        url.set_path(&format!("{}/{id}", self.sandboxes_path()));
        url
    }

    /// Send one authenticated request. `GET` additionally sends
    /// `accept: application/json` (the capture doc's **Common headers**
    /// section notes `DELETE` captured live did *not* send `accept`, only
    /// `authorization`+`user-agent`+`x-ms-client-request-id`; `PUT`/`POST`
    /// get `content-type: application/json` automatically from `.json()`).
    async fn send<B: Serialize + ?Sized>(
        &self,
        method: Method,
        url: Url,
        body: Option<&B>,
    ) -> crate::Result<Response> {
        let token = self.token.token().await?;
        let mut builder = self
            .http
            .request(method.clone(), url)
            .query(&[("api-version", API_VERSION)])
            .bearer_auth(token)
            .header("x-ms-client-request-id", Uuid::new_v4().to_string())
            .header("user-agent", USER_AGENT);
        if method == Method::GET {
            builder = builder.header("accept", "application/json");
        }
        if let Some(body) = body {
            builder = builder.json(body);
        }
        builder
            .send()
            .await
            .map_err(|err| crate::Error::context("ACA data-plane request failed", err))
    }

    /// Read the response body, mapping a non-success status to a
    /// [`crate::Error`] wrapping the classified [`AcaApiError`].
    async fn ok_body(response: Response, op: &'static str) -> crate::Result<String> {
        let status = response.status();
        let body = response.text().await.map_err(|err| {
            crate::Error::context(format!("Failed to read ACA {op} response body"), err)
        })?;
        if status.is_success() {
            Ok(body)
        } else {
            Err(crate::Error::context(
                format!("ACA {op} request failed"),
                map_status(status, &body),
            ))
        }
    }

    fn decode<T: for<'de> Deserialize<'de>>(body: &str, op: &'static str) -> crate::Result<T> {
        serde_json::from_str(body)
            .map_err(|err| crate::Error::context(format!("Failed to decode ACA {op} response"), err))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use httpmock::Method::{DELETE, GET, PUT};
    use httpmock::MockServer;

    use super::*;
    use crate::aca::auth::FakeTokenSource;

    const SUBSCRIPTION: &str = "sub-1";
    const RESOURCE_GROUP: &str = "rg-1";
    const SANDBOX_GROUP: &str = "sg-1";

    fn sandboxes_path() -> String {
        format!(
            "/subscriptions/{SUBSCRIPTION}/resourceGroups/{RESOURCE_GROUP}/sandboxGroups/{SANDBOX_GROUP}/sandboxes"
        )
    }

    fn sandbox_path(id: &str) -> String {
        format!("{}/{id}", sandboxes_path())
    }

    fn test_client(server: &MockServer) -> AcaClient {
        AcaClient::new(
            fabro_test::test_http_client(),
            Arc::new(FakeTokenSource("test-token".to_string())),
            fabro_http::Url::parse(&server.base_url()).expect("parse mock base url"),
            SUBSCRIPTION,
            RESOURCE_GROUP,
            SANDBOX_GROUP,
        )
    }

    fn sandbox_body(id: &str, state: &str) -> serde_json::Value {
        serde_json::json!({
            "connections": [],
            "contentPackageDownloads": [],
            "createdAt": "2026-08-01T00:00:00Z",
            "id": id,
            "labels": {},
            "lifecycle": {
                "autoSuspendPolicy": { "enabled": true, "interval": 600, "mode": "Memory" }
            },
            "managementUrl": "https://management.northeurope.azuredevcompute.io",
            "outboundIpAddresses": ["10.0.0.1"],
            "ports": [],
            "region": "northeurope",
            "resources": { "cpu": "1000m", "disk": "20480Mi", "memory": "2048Mi" },
            "sourcesRef": { "diskImage": { "id": "img-1", "isPublic": false } },
            "state": state,
            "vmmType": "cloudhypervisor",
            "volumes": []
        })
    }

    fn not_found_body() -> serde_json::Value {
        serde_json::json!({
            "detail": "Requested document not found.",
            "errorCode": 1,
            "requestId": "req-1",
            "status": 404,
            "title": "SandboxNotFound",
            "traceId": "trace-1"
        })
    }

    fn not_running_body() -> serde_json::Value {
        serde_json::json!({
            "title": "GlobalSandboxNotRunning",
            "status": 409,
            "detail": "Sandbox 'sbx-1' is not in Running state",
            "callerMemberName": "Failure",
            "callerFilePath": "/mnt/vss/_work/1/s/src/Adc.Common.Core/Primitives/Result.cs",
            "errorCode": 501,
            "traceId": "trace-1",
            "requestId": "req-1"
        })
    }

    #[tokio::test]
    async fn get_sandbox_parses_running_state_from_200() {
        let server = MockServer::start_async().await;
        let mock = server
            .mock_async(|when, then| {
                when.method(GET)
                    .path(sandbox_path("sbx-1"))
                    .query_param("api-version", API_VERSION)
                    .header("authorization", "Bearer test-token")
                    .header("accept", "application/json");
                then.status(200)
                    .header("content-type", "application/json")
                    .json_body(sandbox_body("sbx-1", "Running"));
            })
            .await;

        let client = test_client(&server);
        let resource = client
            .get_sandbox("sbx-1")
            .await
            .expect("get sandbox should succeed")
            .expect("sandbox should be present");

        assert_eq!(resource.id, "sbx-1");
        assert_eq!(resource.state, SandboxState::Running);
        assert_eq!(resource.region, "northeurope");
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn get_sandbox_returns_none_on_captured_404_sandbox_not_found() {
        let server = MockServer::start_async().await;
        let mock = server
            .mock_async(|when, then| {
                when.method(GET).path(sandbox_path("missing"));
                then.status(404)
                    .header("content-type", "application/problem+json")
                    .json_body(not_found_body());
            })
            .await;

        let client = test_client(&server);
        let resource = client
            .get_sandbox("missing")
            .await
            .expect("404 on get should not be an error");

        assert!(resource.is_none());
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn delete_sandbox_maps_409_global_sandbox_not_running() {
        let server = MockServer::start_async().await;
        let mock = server
            .mock_async(|when, then| {
                when.method(DELETE).path(sandbox_path("sbx-1"));
                then.status(409)
                    .header("content-type", "application/problem+json")
                    .json_body(not_running_body());
            })
            .await;

        let client = test_client(&server);
        let error = client
            .delete_sandbox("sbx-1")
            .await
            .expect_err("409 should be an error");

        let source = std::error::Error::source(&error).expect("error should carry a source");
        let api_error = source
            .downcast_ref::<AcaApiError>()
            .expect("source should be AcaApiError");
        assert!(matches!(api_error, AcaApiError::NotRunning));
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn delete_sandbox_maps_403_to_auth_naming_required_role() {
        let server = MockServer::start_async().await;
        let mock = server
            .mock_async(|when, then| {
                when.method(DELETE).path(sandbox_path("sbx-1"));
                then.status(403)
                    .header("content-type", "application/problem+json")
                    .json_body(serde_json::json!({
                        "title": "Forbidden",
                        "status": 403,
                        "detail": "The caller does not have permission",
                        "errorCode": 999,
                        "traceId": "trace-1",
                        "requestId": "req-1"
                    }));
            })
            .await;

        let client = test_client(&server);
        let error = client
            .delete_sandbox("sbx-1")
            .await
            .expect_err("403 should be an error");

        let source = std::error::Error::source(&error).expect("error should carry a source");
        let api_error = source
            .downcast_ref::<AcaApiError>()
            .expect("source should be AcaApiError");
        assert!(matches!(api_error, AcaApiError::Auth));
        assert!(
            api_error
                .to_string()
                .contains("Container Apps SandboxGroup Data Owner"),
            "Auth error message should name the required role, got: {api_error}"
        );
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn delete_sandbox_maps_404_to_not_found() {
        let server = MockServer::start_async().await;
        let mock = server
            .mock_async(|when, then| {
                when.method(DELETE).path(sandbox_path("missing"));
                then.status(404)
                    .header("content-type", "application/problem+json")
                    .json_body(not_found_body());
            })
            .await;

        let client = test_client(&server);
        let error = client
            .delete_sandbox("missing")
            .await
            .expect_err("404 on delete should be an error");

        let source = std::error::Error::source(&error).expect("error should carry a source");
        let api_error = source
            .downcast_ref::<AcaApiError>()
            .expect("source should be AcaApiError");
        assert!(matches!(api_error, AcaApiError::NotFound));
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn list_sandboxes_parses_array_response() {
        let server = MockServer::start_async().await;
        let mock = server
            .mock_async(|when, then| {
                when.method(GET)
                    .path(sandboxes_path())
                    .query_param("api-version", API_VERSION)
                    .header("authorization", "Bearer test-token");
                then.status(200)
                    .header("content-type", "application/json")
                    .json_body(serde_json::json!([
                        sandbox_body("sbx-1", "Running"),
                        sandbox_body("sbx-2", "Stopped"),
                    ]));
            })
            .await;

        let client = test_client(&server);
        let sandboxes = client
            .list_sandboxes()
            .await
            .expect("list sandboxes should succeed");

        assert_eq!(sandboxes.len(), 2);
        assert_eq!(sandboxes[0].id, "sbx-1");
        assert_eq!(sandboxes[1].state, SandboxState::Stopped);
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn list_sandboxes_handles_empty_array() {
        let server = MockServer::start_async().await;
        let mock = server
            .mock_async(|when, then| {
                when.method(GET).path(sandboxes_path());
                then.status(200)
                    .header("content-type", "application/json")
                    .json_body(serde_json::json!([]));
            })
            .await;

        let client = test_client(&server);
        let sandboxes = client
            .list_sandboxes()
            .await
            .expect("list sandboxes should succeed");

        assert!(sandboxes.is_empty());
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn create_sandbox_sends_request_body_and_parses_response() {
        let server = MockServer::start_async().await;
        let mock = server
            .mock_async(|when, then| {
                when.method(PUT)
                    .path(sandboxes_path())
                    .query_param("api-version", API_VERSION)
                    .header("authorization", "Bearer test-token")
                    .header("content-type", "application/json")
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

        let client = test_client(&server);
        let request = CreateSandboxRequest {
            lifecycle: Lifecycle {
                auto_suspend_policy: AutoSuspendPolicy {
                    enabled:  true,
                    interval: 600,
                    mode:     "Memory".to_string(),
                },
            },
            resources: CreateResources {
                cpu:    "1000m".to_string(),
                memory: "2048Mi".to_string(),
            },
            sources_ref: CreateSourcesRef {
                disk_image: CreateDiskImage {
                    is_public: true,
                    name:      "ubuntu".to_string(),
                },
            },
        };

        let resource = client
            .create_sandbox(request)
            .await
            .expect("create sandbox should succeed");

        assert_eq!(resource.id, "sbx-new");
        assert_eq!(resource.state, SandboxState::Running);
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn every_request_carries_api_version_and_authorization() {
        let server = MockServer::start_async().await;
        let mock = server
            .mock_async(|when, then| {
                when.method(GET)
                    .path(sandbox_path("sbx-1"))
                    .query_param("api-version", API_VERSION)
                    .header("authorization", "Bearer test-token");
                then.status(200)
                    .header("content-type", "application/json")
                    .json_body(sandbox_body("sbx-1", "Running"));
            })
            .await;

        let client = test_client(&server);
        client
            .get_sandbox("sbx-1")
            .await
            .expect("get sandbox should succeed");

        mock.assert_async().await;
    }
}
