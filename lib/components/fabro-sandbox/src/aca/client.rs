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
///
/// `resume`'s response is a full Sandbox resource too (per the capture doc),
/// but [`AcaClient::resume`] follows the Task-7 brief's interface and
/// returns `()` on success rather than parsing it here — a caller that needs
/// the fresh state can follow up with [`AcaClient::get_sandbox`].
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SandboxResource {
    pub id:         String,
    pub state:      SandboxState,
    pub created_at: String,
    pub lifecycle:  Lifecycle,
    pub resources:  SandboxResources,
    pub sources_ref: SourcesRef,
    // Runtime/placement fields: present when Running, but a Stopped sandbox's
    // `get` response omits `region`/`managementUrl`/`vmmType` entirely (only
    // `state`/`resources`/`stateDetails`/`snapshotId` remain). Optional so
    // `activate()`'s state check can decode a Stopped sandbox.
    #[serde(default)]
    pub region:     Option<String>,
    #[serde(default)]
    pub management_url: Option<String>,
    #[serde(default)]
    pub vmm_type:   Option<String>,
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

// --- Task 7: exec/fs/lifecycle/egress shapes --------------------------

/// Body of `POST .../executeShellCommand`.
///
/// `command` is sent exactly as given by the caller — any `/bin/bash -c`
/// wrapping is Task 8's (`AcaSandbox`) responsibility, not this client's
/// (see the capture doc's **exec** section).
#[derive(Debug, Clone, Serialize)]
struct ExecRequest<'a> {
    command: &'a str,
}

/// Response of `POST .../executeShellCommand`.
///
/// Field names are exact per the capture doc's **exec** section: no
/// streaming, a single synchronous/buffered exec.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AcaExecResponse {
    pub stdout:    String,
    pub stderr:    String,
    pub exit_code: i32,
    /// Wall time in milliseconds.
    pub execution_time_ms: u64,
}

/// Per-entry shape returned by both `fs stat` (single entry) and `fs ls`
/// (`entries: array<FileStat>`) — see the capture doc's **fs stat**/**fs
/// ls** sections, which document the identical per-entry shape.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AcaFileStat {
    pub name:          String,
    pub path:          String,
    pub is_dir:        bool,
    pub is_symlink:    bool,
    /// POSIX file mode bits, decimal (e.g. `420` == octal `0644`).
    pub mode:          u32,
    /// Unix epoch **seconds** (per the capture doc; not milliseconds).
    pub modified_time: i64,
    pub size:          u64,
}

/// Body of `GET .../files/list` — `fs ls`'s response wrapper around
/// [`AcaFileStat`] entries. The doc also echoes `path` back but no caller
/// needs it, so — like the unmodeled always-empty [`SandboxResource`]
/// fields — it's left out; unrecognized fields don't block deserialization.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct FsListResponse {
    entries: Vec<AcaFileStat>,
}

/// One `hostRules` entry in an egress-policy request/response (capture
/// doc's **egress set** section).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct EgressHostRule {
    action:  String,
    pattern: String,
}

/// Body of `POST .../egresspolicy`.
///
/// Unlike the *response* (which nests this same shape again under an
/// `http` sub-object per the capture doc), the *request* body is flat —
/// [`AcaClient::set_egress`] doesn't parse the response at all (matching
/// the Task-7 brief's `-> crate::Result<()>` signature), so no `http`
/// nesting needs modeling here.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct EgressSetRequest {
    default_action:     String,
    host_rules:         Vec<EgressHostRule>,
    traffic_inspection: String,
}

/// Empty JSON object body (`{}`) — the capture doc's exact request body for
/// both `stop` and `resume`.
#[expect(
    clippy::empty_structs_with_brackets,
    reason = "the braces are load-bearing: serde serializes a braced empty struct as `{}`, \
              matching the capture doc's exact stop/resume request body, whereas a unit \
              struct (`struct EmptyRequest;`) would serialize as `null` instead"
)]
#[derive(Debug, Clone, Serialize)]
struct EmptyRequest {}

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
        let response = self.send(Method::PUT, url, &[], Some(&request)).await?;
        let body = Self::ok_body(response, "create sandbox").await?;
        Self::decode(&body, "create sandbox")
    }

    /// `GET .../sandboxes/{id}` — returns `Ok(None)` on the captured
    /// `404 SandboxNotFound`, matching the capture doc's note that `get` on
    /// a deleted/never-existent sandbox 404s.
    pub async fn get_sandbox(&self, id: &str) -> crate::Result<Option<SandboxResource>> {
        let url = self.sandbox_url(id);
        let response = self.send::<()>(Method::GET, url, &[], None).await?;
        if response.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let body = Self::ok_body(response, "get sandbox").await?;
        Self::decode(&body, "get sandbox").map(Some)
    }

    /// `GET .../sandboxes` — bare JSON array, `[]` when empty.
    pub async fn list_sandboxes(&self) -> crate::Result<Vec<SandboxResource>> {
        let url = self.sandboxes_url();
        let response = self.send::<()>(Method::GET, url, &[], None).await?;
        let body = Self::ok_body(response, "list sandboxes").await?;
        Self::decode(&body, "list sandboxes")
    }

    /// `DELETE .../sandboxes/{id}`. Deletion is asynchronous server-side
    /// (see the capture doc), so a successful call here only confirms the
    /// delete was accepted, not that the sandbox is gone yet.
    pub async fn delete_sandbox(&self, id: &str) -> crate::Result<()> {
        let url = self.sandbox_url(id);
        let response = self.send::<()>(Method::DELETE, url, &[], None).await?;
        Self::ok_body(response, "delete sandbox").await?;
        Ok(())
    }

    /// `POST .../executeShellCommand` — run a shell command synchronously.
    ///
    /// `command` is sent exactly as given; wrapping it for e.g. `/bin/bash
    /// -c` semantics is Task 8's (`AcaSandbox`) job, not this client's (see
    /// the capture doc's **exec** section and [`ExecRequest`]'s docs).
    pub async fn exec(&self, sandbox_id: &str, command: &str) -> crate::Result<AcaExecResponse> {
        let url = self.sandbox_action_url(sandbox_id, "executeShellCommand");
        let request = ExecRequest { command };
        let response = self.send(Method::POST, url, &[], Some(&request)).await?;
        let body = Self::ok_body(response, "exec").await?;
        Self::decode(&body, "exec")
    }

    /// `PUT .../files?path=...&createDirs=...` — write raw bytes to a file.
    ///
    /// Unlike every other endpoint on this client, the request body here is
    /// **raw octet-stream bytes, not JSON** (capture doc's **fs write**
    /// section), so this bypasses [`Self::send`]'s `.json()` body encoding.
    /// `path`/`createDirs` are query parameters, not part of the body;
    /// `.query()` percent-encodes `path` for us (no need for the `url`
    /// crate here).
    pub async fn fs_write(
        &self,
        sandbox_id: &str,
        path: &str,
        bytes: &[u8],
        create_dirs: bool,
    ) -> crate::Result<()> {
        let url = self.sandbox_action_url(sandbox_id, "files");
        let create_dirs = create_dirs.to_string();
        let query = [("path", path), ("createDirs", create_dirs.as_str())];
        let builder = self
            .authenticated_request(Method::PUT, url, &query)
            .await?;
        let response = builder
            .header("content-type", "application/octet-stream")
            .body(bytes.to_vec())
            .send()
            .await
            .map_err(|err| crate::Error::context("ACA data-plane request failed", err))?;
        Self::ok_body(response, "fs write").await?;
        Ok(())
    }

    /// `GET .../files?path=...` — read a file's raw bytes.
    ///
    /// The response is **raw bytes, not JSON** (capture doc's **fs cat**
    /// section), so this reads `.bytes()` rather than going through
    /// [`Self::ok_body`]'s `.text()`.
    pub async fn fs_cat(&self, sandbox_id: &str, path: &str) -> crate::Result<Vec<u8>> {
        let url = self.sandbox_action_url(sandbox_id, "files");
        let query = [("path", path)];
        let response = self.send::<()>(Method::GET, url, &query, None).await?;
        Self::ok_bytes(response, "fs cat").await
    }

    /// `GET .../files/stat?path=...` — returns `Ok(None)` on 404 (no stable
    /// `SandboxNotFound`-style body was captured for this endpoint, but the
    /// Task-7 brief specifies 404 -> `None` for existence checks).
    pub async fn fs_stat(
        &self,
        sandbox_id: &str,
        path: &str,
    ) -> crate::Result<Option<AcaFileStat>> {
        let url = self.sandbox_action_url(sandbox_id, "files/stat");
        let query = [("path", path)];
        let response = self.send::<()>(Method::GET, url, &query, None).await?;
        if response.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let body = Self::ok_body(response, "fs stat").await?;
        Self::decode(&body, "fs stat").map(Some)
    }

    /// `GET .../files/list?path=...` — list directory entries.
    pub async fn fs_ls(&self, sandbox_id: &str, path: &str) -> crate::Result<Vec<AcaFileStat>> {
        let url = self.sandbox_action_url(sandbox_id, "files/list");
        let query = [("path", path)];
        let response = self.send::<()>(Method::GET, url, &query, None).await?;
        let body = Self::ok_body(response, "fs ls").await?;
        Self::decode::<FsListResponse>(&body, "fs ls").map(|parsed| parsed.entries)
    }

    /// `POST .../egresspolicy` — set the sandbox's network egress policy.
    ///
    /// `rules` entries use the CLI's `pattern:Action` shorthand (e.g.
    /// `"github.com:Allow"`, matching the capture doc's `aca sandbox egress
    /// set --rule=github.com:Allow` example); a rule without a `:` falls
    /// back to `default_action`. The response nests this same policy again
    /// under an `http` sub-object (capture doc's **egress set** section),
    /// but this method doesn't parse the response at all — only the
    /// captured request shape is replicated, per the Task-7 brief's `->
    /// crate::Result<()>` signature.
    pub async fn set_egress(
        &self,
        sandbox_id: &str,
        default_action: &str,
        rules: &[String],
        inspection: &str,
    ) -> crate::Result<()> {
        let url = self.sandbox_action_url(sandbox_id, "egresspolicy");
        let host_rules = rules
            .iter()
            .map(|rule| match rule.split_once(':') {
                Some((pattern, action)) => EgressHostRule {
                    action:  action.to_string(),
                    pattern: pattern.to_string(),
                },
                None => EgressHostRule {
                    action:  default_action.to_string(),
                    pattern: rule.clone(),
                },
            })
            .collect();
        let request = EgressSetRequest {
            default_action: default_action.to_string(),
            host_rules,
            traffic_inspection: inspection.to_string(),
        };
        let response = self.send(Method::POST, url, &[], Some(&request)).await?;
        Self::ok_body(response, "set egress policy").await?;
        Ok(())
    }

    /// `POST .../stop` — suspend the sandbox.
    ///
    /// The response is a **Snapshot** resource, not a Sandbox (capture
    /// doc's **stop (suspend)** section) — this treats any 2xx as success
    /// and never attempts to decode the body as a [`SandboxResource`].
    pub async fn suspend(&self, sandbox_id: &str) -> crate::Result<()> {
        let url = self.sandbox_action_url(sandbox_id, "stop");
        let response = self
            .send(Method::POST, url, &[], Some(&EmptyRequest {}))
            .await?;
        Self::ok_body(response, "suspend sandbox").await?;
        Ok(())
    }

    /// `POST .../resume` — resume a suspended sandbox.
    ///
    /// The response is a full Sandbox resource (capture doc's **resume**
    /// section), but — per the Task-7 brief's `-> crate::Result<()>`
    /// signature — this only confirms success; a caller that needs the
    /// fresh state can follow up with [`Self::get_sandbox`].
    pub async fn resume(&self, sandbox_id: &str) -> crate::Result<()> {
        let url = self.sandbox_action_url(sandbox_id, "resume");
        let response = self
            .send(Method::POST, url, &[], Some(&EmptyRequest {}))
            .await?;
        Self::ok_body(response, "resume sandbox").await?;
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

    /// URL for a sub-resource/action under one sandbox, e.g.
    /// `.../sandboxes/{id}/executeShellCommand` or
    /// `.../sandboxes/{id}/files/stat`.
    fn sandbox_action_url(&self, id: &str, action: &str) -> Url {
        let mut url = self.base.clone();
        url.set_path(&format!("{}/{id}/{action}", self.sandboxes_path()));
        url
    }

    /// Build one authenticated request, with `api-version` plus any
    /// endpoint-specific `extra_query` pairs (e.g. `fs`'s `path`/
    /// `createDirs`) attached. `.query()` percent-encodes values for us, so
    /// callers pass raw (unencoded) strings — no need for the `url` crate
    /// here (Task 6 removed it as an unused dep; this client doesn't need
    /// it back).
    ///
    /// `GET` additionally sends `accept: application/json` (the capture
    /// doc's **Common headers** section notes `DELETE` captured live did
    /// *not* send `accept`, only
    /// `authorization`+`user-agent`+`x-ms-client-request-id`). Callers that
    /// send a body add their own `content-type` — [`Self::send`] uses
    /// `.json()` (sets `application/json`); [`Self::fs_write`] sets
    /// `application/octet-stream` itself, since its body is raw bytes.
    async fn authenticated_request(
        &self,
        method: Method,
        url: Url,
        extra_query: &[(&str, &str)],
    ) -> crate::Result<fabro_http::RequestBuilder> {
        let token = self.token.token().await?;
        let mut builder = self
            .http
            .request(method.clone(), url)
            .query(&[("api-version", API_VERSION)])
            .query(extra_query)
            .bearer_auth(token)
            .header("x-ms-client-request-id", Uuid::new_v4().to_string())
            .header("user-agent", USER_AGENT);
        if method == Method::GET {
            builder = builder.header("accept", "application/json");
        }
        Ok(builder)
    }

    /// Send one authenticated JSON request (or no body, for `GET`/`DELETE`).
    /// See [`Self::authenticated_request`] for the shared header/query
    /// setup.
    async fn send<B: Serialize + ?Sized>(
        &self,
        method: Method,
        url: Url,
        extra_query: &[(&str, &str)],
        body: Option<&B>,
    ) -> crate::Result<Response> {
        let mut builder = self
            .authenticated_request(method, url, extra_query)
            .await?;
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

    /// Like [`Self::ok_body`], but for endpoints whose successful response
    /// is raw bytes rather than text/JSON (`fs cat` — capture doc's **fs
    /// cat** section: `content-type: application/octet-stream`, not JSON).
    /// The error path still reads the body as text, matching every other
    /// endpoint's `problem+json` error shape.
    async fn ok_bytes(response: Response, op: &'static str) -> crate::Result<Vec<u8>> {
        let status = response.status();
        if status.is_success() {
            response
                .bytes()
                .await
                .map(|bytes| bytes.to_vec())
                .map_err(|err| {
                    crate::Error::context(format!("Failed to read ACA {op} response body"), err)
                })
        } else {
            let body = response.text().await.map_err(|err| {
                crate::Error::context(format!("Failed to read ACA {op} response body"), err)
            })?;
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

    use httpmock::Method::{DELETE, GET, POST, PUT};
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

    fn sandbox_action_path(id: &str, action: &str) -> String {
        format!("{}/{action}", sandbox_path(id))
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
        assert_eq!(resource.region.as_deref(), Some("northeurope"));
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

    // --- Task 7: exec/fs/lifecycle/egress -------------------------------

    fn file_stat_body(name: &str, path: &str, is_dir: bool, size: u64) -> serde_json::Value {
        serde_json::json!({
            "isDir": is_dir,
            "isSymlink": false,
            "mode": 420,
            "modifiedTime": 1_788_186_744_i64,
            "name": name,
            "path": path,
            "size": size,
        })
    }

    fn snapshot_body(snapshot_id: &str, sandbox_id: &str) -> serde_json::Value {
        // A **Snapshot** resource — the `stop` response shape (capture doc's
        // **stop (suspend)** section). Deliberately has no `state` field, so
        // a test asserting `suspend()` against this body proves the client
        // never tries to parse it as a `SandboxResource`.
        serde_json::json!({
            "createdAtUtc": "2026-08-01T00:00:00Z",
            "id": snapshot_id,
            "labels": {},
            "resources": { "cpu": "1000m", "disk": "20480Mi", "memory": "2048Mi" },
            "sandboxId": sandbox_id,
            "sizeInMB": 44,
            "vmmType": "cloudhypervisor",
        })
    }

    #[tokio::test]
    async fn exec_sends_command_verbatim_and_parses_response() {
        let server = MockServer::start_async().await;
        let mock = server
            .mock_async(|when, then| {
                when.method(POST)
                    .path(sandbox_action_path("sbx-1", "executeShellCommand"))
                    .query_param("api-version", API_VERSION)
                    .header("authorization", "Bearer test-token")
                    .header("content-type", "application/json")
                    // No `/bin/bash -c` wrapping: the exact command string
                    // is expected verbatim, shell metacharacters and all —
                    // that wrapping is Task 8's job, not this client's.
                    .json_body(serde_json::json!({ "command": "printf hi && echo done" }));
                then.status(200)
                    .header("content-type", "application/json")
                    .json_body(serde_json::json!({
                        "executionTimeMs": 28,
                        "exitCode": 0,
                        "stderr": "",
                        "stdout": "hi\ndone\n",
                    }));
            })
            .await;

        let client = test_client(&server);
        let result = client
            .exec("sbx-1", "printf hi && echo done")
            .await
            .expect("exec should succeed");

        assert_eq!(result.stdout, "hi\ndone\n");
        assert_eq!(result.stderr, "");
        assert_eq!(result.exit_code, 0);
        assert_eq!(result.execution_time_ms, 28);
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn exec_maps_409_to_not_running() {
        let server = MockServer::start_async().await;
        let mock = server
            .mock_async(|when, then| {
                when.method(POST).path(sandbox_action_path("sbx-1", "executeShellCommand"));
                then.status(409)
                    .header("content-type", "application/problem+json")
                    .json_body(not_running_body());
            })
            .await;

        let client = test_client(&server);
        let error = client
            .exec("sbx-1", "true")
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
    async fn fs_write_sends_octet_stream_body_and_query_params() {
        let server = MockServer::start_async().await;
        let mock = server
            .mock_async(|when, then| {
                when.method(PUT)
                    .path(sandbox_action_path("sbx-1", "files"))
                    .query_param("api-version", API_VERSION)
                    .query_param("path", "/workspace/test.txt")
                    .query_param("createDirs", "true")
                    .header("authorization", "Bearer test-token")
                    .header("content-type", "application/octet-stream")
                    .body("hello world");
                then.status(200)
                    .header("content-type", "application/json")
                    .json_body(serde_json::json!({ "bytesWritten": 11, "success": true }));
            })
            .await;

        let client = test_client(&server);
        client
            .fs_write("sbx-1", "/workspace/test.txt", b"hello world", true)
            .await
            .expect("fs write should succeed");

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn fs_cat_returns_raw_bytes_not_json() {
        let server = MockServer::start_async().await;
        let mock = server
            .mock_async(|when, then| {
                when.method(GET)
                    .path(sandbox_action_path("sbx-1", "files"))
                    .query_param("api-version", API_VERSION)
                    .query_param("path", "/workspace/test.txt")
                    .header("authorization", "Bearer test-token");
                then.status(200)
                    .header("content-type", "application/octet-stream")
                    .body("raw file bytes");
            })
            .await;

        let client = test_client(&server);
        let bytes = client
            .fs_cat("sbx-1", "/workspace/test.txt")
            .await
            .expect("fs cat should succeed");

        assert_eq!(bytes, b"raw file bytes".to_vec());
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn fs_stat_returns_some_on_200() {
        let server = MockServer::start_async().await;
        let mock = server
            .mock_async(|when, then| {
                when.method(GET)
                    .path(sandbox_action_path("sbx-1", "files/stat"))
                    .query_param("path", "/workspace/test.txt");
                then.status(200)
                    .header("content-type", "application/json")
                    .json_body(file_stat_body("test.txt", "/workspace/test.txt", false, 24));
            })
            .await;

        let client = test_client(&server);
        let stat = client
            .fs_stat("sbx-1", "/workspace/test.txt")
            .await
            .expect("fs stat should succeed")
            .expect("stat should be present");

        assert_eq!(stat.name, "test.txt");
        assert_eq!(stat.path, "/workspace/test.txt");
        assert!(!stat.is_dir);
        assert!(!stat.is_symlink);
        assert_eq!(stat.mode, 420);
        assert_eq!(stat.modified_time, 1_788_186_744);
        assert_eq!(stat.size, 24);
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn fs_stat_returns_none_on_404() {
        let server = MockServer::start_async().await;
        let mock = server
            .mock_async(|when, then| {
                when.method(GET).path(sandbox_action_path("sbx-1", "files/stat"));
                then.status(404)
                    .header("content-type", "application/problem+json")
                    .json_body(not_found_body());
            })
            .await;

        let client = test_client(&server);
        let stat = client
            .fs_stat("sbx-1", "/workspace/missing.txt")
            .await
            .expect("404 on fs stat should not be an error");

        assert!(stat.is_none());
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn fs_ls_returns_entries() {
        let server = MockServer::start_async().await;
        let mock = server
            .mock_async(|when, then| {
                when.method(GET)
                    .path(sandbox_action_path("sbx-1", "files/list"))
                    .query_param("path", "/workspace");
                then.status(200)
                    .header("content-type", "application/json")
                    .json_body(serde_json::json!({
                        "entries": [file_stat_body("test.txt", "/workspace/test.txt", false, 24)],
                        "path": "/workspace",
                    }));
            })
            .await;

        let client = test_client(&server);
        let entries = client
            .fs_ls("sbx-1", "/workspace")
            .await
            .expect("fs ls should succeed");

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "test.txt");
        assert_eq!(entries[0].size, 24);
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn suspend_treats_snapshot_response_as_success() {
        let server = MockServer::start_async().await;
        let mock = server
            .mock_async(|when, then| {
                when.method(POST)
                    .path(sandbox_action_path("sbx-1", "stop"))
                    .json_body(serde_json::json!({}));
                // The response is a Snapshot, not a Sandbox — no `state`
                // field at all. `suspend()` must not try to decode it as a
                // `SandboxResource`.
                then.status(200)
                    .header("content-type", "application/json")
                    .json_body(snapshot_body("snap-1", "sbx-1"));
            })
            .await;

        let client = test_client(&server);
        client
            .suspend("sbx-1")
            .await
            .expect("suspend should treat the Snapshot 2xx as success");

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn resume_returns_ok_on_200() {
        let server = MockServer::start_async().await;
        let mock = server
            .mock_async(|when, then| {
                when.method(POST)
                    .path(sandbox_action_path("sbx-1", "resume"))
                    .json_body(serde_json::json!({}));
                then.status(200)
                    .header("content-type", "application/json")
                    .json_body(sandbox_body("sbx-1", "Running"));
            })
            .await;

        let client = test_client(&server);
        client.resume("sbx-1").await.expect("resume should succeed");

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn set_egress_sends_traffic_inspection_and_nested_host_rules() {
        let server = MockServer::start_async().await;
        let mock = server
            .mock_async(|when, then| {
                when.method(POST)
                    .path(sandbox_action_path("sbx-1", "egresspolicy"))
                    .header("authorization", "Bearer test-token")
                    .json_body(serde_json::json!({
                        "defaultAction": "Deny",
                        "hostRules": [ { "action": "Allow", "pattern": "github.com" } ],
                        "trafficInspection": "Full",
                    }));
                // The response nests the same policy again under `http`
                // (capture doc's **egress set** section) — `set_egress`
                // doesn't parse this, only the request shape is asserted.
                then.status(200)
                    .header("content-type", "application/json")
                    .json_body(serde_json::json!({
                        "defaultAction": "Deny",
                        "hostRules": [ { "action": "Allow", "pattern": "github.com" } ],
                        "http": {
                            "defaultAction": "Deny",
                            "hostRules": [ { "action": "Allow", "pattern": "github.com" } ],
                            "trafficInspection": "Full",
                        },
                        "trafficInspection": "Full",
                    }));
            })
            .await;

        let client = test_client(&server);
        client
            .set_egress("sbx-1", "Deny", &["github.com:Allow".to_string()], "Full")
            .await
            .expect("set egress should succeed");

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn set_egress_rule_without_colon_falls_back_to_default_action() {
        let server = MockServer::start_async().await;
        let mock = server
            .mock_async(|when, then| {
                when.method(POST)
                    .path(sandbox_action_path("sbx-1", "egresspolicy"))
                    .json_body(serde_json::json!({
                        "defaultAction": "Allow",
                        "hostRules": [ { "action": "Allow", "pattern": "example.com" } ],
                        "trafficInspection": "None",
                    }));
                then.status(200)
                    .header("content-type", "application/json")
                    .json_body(serde_json::json!({}));
            })
            .await;

        let client = test_client(&server);
        client
            .set_egress("sbx-1", "Allow", &["example.com".to_string()], "None")
            .await
            .expect("set egress should succeed");

        mock.assert_async().await;
    }
}
