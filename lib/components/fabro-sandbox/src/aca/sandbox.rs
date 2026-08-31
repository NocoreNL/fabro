//! ACA: `Sandbox` trait implementation.
//!
//! Task 8 began the `impl Sandbox for AcaSandbox` block: command execution
//! (wrapped as non-login `/bin/bash -c`), buffered-then-replay streaming, and
//! the shared `BASH_PROBE_SCRIPT` readiness gate. Task 9 adds file
//! operations (delegating to [`AcaClient`]'s `fs_*` endpoints) and `grep`
//! (via exec, since ACA has no native search endpoint). `cleanup`/git/setup
//! remain stubbed here and land in Tasks 10-11.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use fabro_types::CommandTermination;
use tokio::sync::OnceCell;
use tokio::{fs, time};
use tokio_util::sync::CancellationToken;

use crate::aca::{AcaClient, AcaConfig};
use crate::sandbox::{
    BASH_ENV_VAR, BASH_PROBE_SCRIPT, BASH_PROBE_TIMEOUT_MS, replay_exec_result, resolve_path,
    validate_bash_probe,
};
use crate::{
    DirEntry, ExecResult, ExecStreamingRequest, ExecStreamingResult, GrepOptions, Sandbox,
    shell_quote,
};

/// Remediation shown when an ACA sandbox has no usable Bash.
const ACA_BASH_REMEDIATION: &str = "ACA sandboxes require /bin/bash for every command, with no \
     `sh` fallback; use a disk image that provides bash, such as `ubuntu`.";

/// Message returned by every trait method this task leaves unimplemented.
/// Tasks 10-11 replace these stubs with real cleanup/git/setup behavior.
const NOT_YET_IMPLEMENTED: &str = "aca: not yet implemented (task 10/11)";

/// `Sandbox` implementation over the ACA data-plane REST client
/// ([`AcaClient`]).
///
/// Runtime identity (`sandbox_id`) lives on this struct rather than in
/// [`AcaConfig`]: the config is the immutable creation intent (mirroring
/// `DaytonaConfig`'s role), while this struct is the live handle to an
/// already-provisioned sandbox resource.
pub struct AcaSandbox {
    client:     Arc<AcaClient>,
    sandbox_id: String,
    config:     AcaConfig,
    /// Cached result of probing `rg --version` via exec, so [`Sandbox::grep`]
    /// only pays for the probe once per sandbox instance. Mirrors
    /// `daytona/mod.rs`'s `rg_available` field.
    rg_available: OnceCell<bool>,
}

impl AcaSandbox {
    pub fn new(client: Arc<AcaClient>, sandbox_id: String, config: AcaConfig) -> Self {
        Self {
            client,
            sandbox_id,
            config,
            rg_available: OnceCell::const_new(),
        }
    }

    /// Resolve `path` against [`Sandbox::working_directory`]: relative paths
    /// are joined onto it, absolute paths pass through unchanged. Shared with
    /// the Daytona/Docker sandboxes via `crate::sandbox::resolve_path`.
    fn resolve_path(&self, path: &str) -> String {
        resolve_path(path, self.working_directory())
    }

    /// Build the exact `command` string sent to ACA's `executeShellCommand`.
    ///
    /// ACA's exec endpoint takes only `{ "command": string }` — no separate
    /// `cwd` or `env` channel (see `docs/aca-data-plane-api.md`'s **exec**
    /// section) — so both `working_dir` and `env_vars` are folded into one
    /// shell command line here, ahead of the actual Bash invocation:
    ///
    /// `env -u BASH_ENV [KEY=VALUE ...] /bin/bash -c '<cd dir &&> command'`
    ///
    /// `env -u BASH_ENV` guarantees the *inner* Bash never picks up an
    /// ambient `BASH_ENV` startup file from whatever shell ACA itself uses to
    /// interpret this outer command line — setting `BASH_ENV` from inside the
    /// `-c` script would be too late, since Bash reads it once at its own
    /// startup, before the script body runs. Any caller-supplied `BASH_ENV`
    /// entry in `env_vars` is dropped for the same reason: it would just be
    /// re-introducing what `-u` removes.
    fn wrap_command(
        command: &str,
        working_dir: Option<&str>,
        env_vars: Option<&HashMap<String, String>>,
    ) -> String {
        let script = working_dir.map_or_else(
            || command.to_string(),
            |dir| format!("cd {} && {command}", shell_quote(dir)),
        );

        let mut prefix = format!("env -u {BASH_ENV_VAR}");
        let mut entries: Vec<(&String, &String)> = env_vars
            .into_iter()
            .flatten()
            .filter(|(key, _)| key.as_str() != BASH_ENV_VAR)
            .collect();
        entries.sort_by_key(|(key, _)| key.as_str());
        for (key, value) in entries {
            let _ = write!(prefix, " {key}={}", shell_quote(value));
        }

        format!("{prefix} /bin/bash -c {}", shell_quote(&script))
    }

    /// Verify the sandbox evaluates commands as non-login Bash, via the same
    /// `/bin/bash -c` transport [`Sandbox::exec_command`] uses. Called from
    /// `initialize()` and `start()` so a sandbox is never reported usable
    /// with a broken or non-Bash interpreter.
    async fn run_bash_probe(&self) -> crate::Result<()> {
        let result = self
            .exec_command(BASH_PROBE_SCRIPT, BASH_PROBE_TIMEOUT_MS, None, None, None)
            .await
            .map_err(|err| crate::Error::context(ACA_BASH_REMEDIATION, err))?;
        validate_bash_probe(result, ACA_BASH_REMEDIATION)
    }
}

#[async_trait]
impl Sandbox for AcaSandbox {
    async fn exec_command(
        &self,
        command: &str,
        timeout_ms: u64,
        working_dir: Option<&str>,
        env_vars: Option<&HashMap<String, String>>,
        cancel_token: Option<CancellationToken>,
    ) -> crate::Result<ExecResult> {
        let wrapped = Self::wrap_command(command, working_dir, env_vars);
        let start = Instant::now();
        let token = cancel_token.unwrap_or_default();

        tokio::select! {
            result = self.client.exec(&self.sandbox_id, &wrapped) => {
                let response = result?;
                Ok(ExecResult {
                    stdout: response.stdout,
                    stderr: response.stderr,
                    exit_code: Some(response.exit_code),
                    termination: CommandTermination::Exited,
                    duration_ms: response.execution_time_ms,
                })
            }
            () = time::sleep(Duration::from_millis(timeout_ms)) => {
                let duration_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
                Ok(ExecResult {
                    stdout: String::new(),
                    stderr: "Command timed out".to_string(),
                    exit_code: None,
                    termination: CommandTermination::TimedOut,
                    duration_ms,
                })
            }
            () = token.cancelled() => {
                let duration_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
                Ok(ExecResult {
                    stdout: String::new(),
                    stderr: "Command cancelled".to_string(),
                    exit_code: None,
                    termination: CommandTermination::Cancelled,
                    duration_ms,
                })
            }
        }
    }

    /// ACA's exec endpoint is synchronous/buffered only — the capture doc
    /// notes "No streaming — this is a synchronous, buffered exec" — so this
    /// replays the completed [`Sandbox::exec_command`] result through the
    /// output callback rather than streaming live chunks. Live per-chunk
    /// streaming is deferred.
    async fn exec_command_streaming(
        &self,
        request: ExecStreamingRequest<'_>,
    ) -> crate::Result<ExecStreamingResult> {
        if request.stdin.is_some() {
            return Err(crate::Error::message(
                "This sandbox does not support standard input for streaming commands",
            ));
        }
        let timeout_ms = request.timeout_ms.unwrap_or(u64::MAX);
        let result = self
            .exec_command(
                request.command,
                timeout_ms,
                request.working_dir,
                request.env_vars,
                request.cancel_token,
            )
            .await?;
        replay_exec_result(
            result,
            true,
            request.output_callback.as_ref(),
            request.stream_output_bytes_cap,
        )
        .await
    }

    async fn initialize(&self) -> crate::Result<()> {
        self.run_bash_probe().await
    }

    async fn start(&self) -> crate::Result<()> {
        self.run_bash_probe().await
    }

    fn working_directory(&self) -> &str {
        &self.config.working_dir
    }

    fn platform(&self) -> &'static str {
        "linux"
    }

    fn os_version(&self) -> String {
        format!("Linux (ACA {})", self.config.disk)
    }

    fn sandbox_info(&self) -> String {
        self.sandbox_id.clone()
    }

    async fn read_file_bytes(&self, path: &str) -> crate::Result<Vec<u8>> {
        let resolved = self.resolve_path(path);
        self.client.fs_cat(&self.sandbox_id, &resolved).await
    }

    async fn write_file(&self, path: &str, content: &str) -> crate::Result<()> {
        let resolved = self.resolve_path(path);
        // `create_dirs=true` matches the capture doc's note that the
        // reference CLI always sends `true` for `fs write`; ACA's endpoint
        // creates missing parent directories server-side, so — unlike
        // Daytona — no separate `create_folder` call is needed first.
        self.client
            .fs_write(&self.sandbox_id, &resolved, content.as_bytes(), true)
            .await
    }

    /// ACA's data-plane capture (`docs/aca-data-plane-api.md`) documents only
    /// 12 endpoints — write/cat/stat/ls/cp, exec, lifecycle, egress — and
    /// explicitly notes `fs cp` has "no dedicated ... REST endpoint; it's a
    /// CLI-side convenience wrapper" over write/cat. No file-delete endpoint
    /// was ever captured. Rather than fabricate an unverified REST shape,
    /// this deletes via the same exec transport `grep` uses below, the same
    /// call-a-real-command approach the capture doc itself takes for `cp`.
    async fn delete_file(&self, path: &str) -> crate::Result<()> {
        let resolved = self.resolve_path(path);
        let cmd = format!("rm -f -- {}", shell_quote(&resolved));
        let result = self.exec_command(&cmd, 30_000, None, None, None).await?;
        if result.is_success() {
            Ok(())
        } else {
            Err(crate::Error::message(format!(
                "Failed to delete file {resolved} (exit {}): {}",
                result.display_exit_code(),
                result.stderr
            )))
        }
    }

    async fn file_exists(&self, path: &str) -> crate::Result<bool> {
        let resolved = self.resolve_path(path);
        Ok(self
            .client
            .fs_stat(&self.sandbox_id, &resolved)
            .await?
            .is_some())
    }

    /// ACA's `files/list` endpoint (capture doc's **fs ls** section) is
    /// single-level only — it takes just `path`, with no recursion/depth
    /// query parameter observed — so this always returns immediate children,
    /// matching `depth`'s `None`/`Some(1)` semantics. Deeper values are not
    /// honored (no verified endpoint shape to recurse with); this is a
    /// documented limitation, not a bug.
    async fn list_directory(
        &self,
        path: &str,
        _depth: Option<usize>,
    ) -> crate::Result<Vec<DirEntry>> {
        let resolved = self.resolve_path(path);
        let entries = self.client.fs_ls(&self.sandbox_id, &resolved).await?;
        Ok(entries
            .into_iter()
            .map(|entry| DirEntry {
                name:   entry.name,
                is_dir: entry.is_dir,
                size:   if entry.is_dir { None } else { Some(entry.size) },
            })
            .collect())
    }

    /// ACA has no native search endpoint, so this shells out via
    /// [`Sandbox::exec_command`]: `rg` when available (probed once and
    /// cached in `rg_available`), falling back to `grep -rn`. Mirrors
    /// `daytona/mod.rs`'s `grep` exactly.
    async fn grep(
        &self,
        pattern: &str,
        path: &str,
        options: &GrepOptions,
    ) -> crate::Result<Vec<String>> {
        let resolved = self.resolve_path(path);

        let use_rg = *self
            .rg_available
            .get_or_init(|| async {
                let result = self
                    .exec_command("rg --version", 10_000, None, None, None)
                    .await;
                matches!(result, Ok(r) if r.is_success())
            })
            .await;

        let cmd = if use_rg {
            let mut cmd = "rg --line-number --no-heading".to_string();
            if options.case_insensitive {
                cmd.push_str(" -i");
            }
            if let Some(ref glob_filter) = options.glob_filter {
                let _ = write!(cmd, " --glob {}", shell_quote(glob_filter));
            }
            if let Some(max) = options.max_results {
                let _ = write!(cmd, " --max-count {max}");
            }
            let _ = write!(
                cmd,
                " -- {} {}",
                shell_quote(pattern),
                shell_quote(&resolved)
            );
            cmd
        } else {
            let mut cmd = "grep -rn".to_string();
            if options.case_insensitive {
                cmd.push_str(" -i");
            }
            if let Some(ref glob_filter) = options.glob_filter {
                let _ = write!(cmd, " --include {}", shell_quote(glob_filter));
            }
            if let Some(max) = options.max_results {
                let _ = write!(cmd, " -m {max}");
            }
            let _ = write!(
                cmd,
                " -- {} {}",
                shell_quote(pattern),
                shell_quote(&resolved)
            );
            cmd
        };

        let result = self.exec_command(&cmd, 30_000, None, None, None).await?;

        if result.exit_code == Some(1) {
            // Both rg and grep exit 1 for no matches.
            return Ok(Vec::new());
        }
        if !result.is_success() {
            return Err(crate::Error::message(format!(
                "grep failed (exit {}): {}",
                result.display_exit_code(),
                result.stderr
            )));
        }

        Ok(result.stdout.lines().map(String::from).collect())
    }

    async fn download_file_to_local(
        &self,
        remote_path: &str,
        local_path: &Path,
    ) -> crate::Result<()> {
        let resolved = self.resolve_path(remote_path);
        let bytes = self.client.fs_cat(&self.sandbox_id, &resolved).await?;

        if let Some(parent) = local_path.parent() {
            fs::create_dir_all(parent)
                .await
                .map_err(|e| crate::Error::context("Failed to create parent dirs", e))?;
        }
        fs::write(local_path, &bytes).await.map_err(|e| {
            crate::Error::context(format!("Failed to write {}", local_path.display()), e)
        })?;

        Ok(())
    }

    async fn upload_file_from_local(
        &self,
        local_path: &Path,
        remote_path: &str,
    ) -> crate::Result<()> {
        let resolved = self.resolve_path(remote_path);
        let bytes = fs::read(local_path).await.map_err(|e| {
            crate::Error::context(format!("Failed to read {}", local_path.display()), e)
        })?;

        self.client
            .fs_write(&self.sandbox_id, &resolved, &bytes, true)
            .await
    }

    // --- stub: real behavior lands in Task 10 ---

    async fn cleanup(&self) -> crate::Result<()> {
        Err(crate::Error::message(NOT_YET_IMPLEMENTED))
    }
}

#[cfg(test)]
#[expect(
    clippy::disallowed_types,
    reason = "the mock server base URL used to build a test AcaClient never carries \
              credentials — same rationale as aca/client.rs's own `test_client` helper, which \
              this mirrors"
)]
mod tests {
    use std::sync::Arc;

    use httpmock::Method::{GET, POST, PUT};
    use httpmock::MockServer;

    use super::*;
    use crate::aca::AcaEgressPolicy;
    use crate::aca::auth::FakeTokenSource;

    const SUBSCRIPTION: &str = "sub-1";
    const RESOURCE_GROUP: &str = "rg-1";
    const SANDBOX_GROUP: &str = "sg-1";
    const SANDBOX_ID: &str = "sbx-1";

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

    fn test_config() -> AcaConfig {
        AcaConfig {
            region: "northeurope".to_string(),
            resource_group: RESOURCE_GROUP.to_string(),
            sandbox_group: SANDBOX_GROUP.to_string(),
            disk: "ubuntu".to_string(),
            cpu: None,
            memory: None,
            working_dir: "/workspace".to_string(),
            egress: AcaEgressPolicy::default(),
            region_override: false,
        }
    }

    fn test_sandbox(server: &MockServer) -> AcaSandbox {
        AcaSandbox::new(
            Arc::new(test_client(server)),
            SANDBOX_ID.to_string(),
            test_config(),
        )
    }

    fn exec_path() -> String {
        action_path("executeShellCommand")
    }

    fn action_path(action: &str) -> String {
        format!(
            "/subscriptions/{SUBSCRIPTION}/resourceGroups/{RESOURCE_GROUP}/sandboxGroups/{SANDBOX_GROUP}/sandboxes/{SANDBOX_ID}/{action}"
        )
    }

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

    async fn mock_exec_expecting<'a>(
        server: &'a MockServer,
        expected_command: &'a str,
        stdout: &'a str,
        stderr: &'a str,
        exit_code: i32,
    ) -> httpmock::Mock<'a> {
        server
            .mock_async(|when, then| {
                when.method(POST)
                    .path(exec_path())
                    .json_body(serde_json::json!({ "command": expected_command }));
                then.status(200)
                    .header("content-type", "application/json")
                    .json_body(serde_json::json!({
                        "executionTimeMs": 12,
                        "exitCode": exit_code,
                        "stderr": stderr,
                        "stdout": stdout,
                    }));
            })
            .await
    }

    #[tokio::test]
    async fn exec_command_wraps_as_non_login_bash_with_clean_env() {
        let server = MockServer::start_async().await;
        let mock = mock_exec_expecting(
            &server,
            "env -u BASH_ENV /bin/bash -c 'echo hi; echo e 1>&2; exit 7'",
            "hi\n",
            "e\n",
            7,
        )
        .await;
        let sandbox = test_sandbox(&server);

        let result = sandbox
            .exec_command("echo hi; echo e 1>&2; exit 7", 5_000, None, None, None)
            .await
            .expect("exec_command should succeed");

        assert_eq!(result.stdout, "hi\n");
        assert_eq!(result.stderr, "e\n");
        assert_eq!(result.exit_code, Some(7));
        assert_eq!(result.termination, CommandTermination::Exited);
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn exec_command_prefixes_working_dir_with_cd() {
        let server = MockServer::start_async().await;
        let mock = mock_exec_expecting(
            &server,
            "env -u BASH_ENV /bin/bash -c 'cd /workspace/sub && pwd'",
            "/workspace/sub\n",
            "",
            0,
        )
        .await;
        let sandbox = test_sandbox(&server);

        let result = sandbox
            .exec_command("pwd", 5_000, Some("/workspace/sub"), None, None)
            .await
            .expect("exec_command should succeed");

        assert_eq!(result.stdout, "/workspace/sub\n");
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn exec_command_removes_bash_env_and_forwards_other_env_vars() {
        let server = MockServer::start_async().await;
        let mut env_vars = HashMap::new();
        env_vars.insert("BASH_ENV".to_string(), "/etc/evil-profile".to_string());
        env_vars.insert("FOO".to_string(), "bar".to_string());

        let mock = mock_exec_expecting(
            &server,
            "env -u BASH_ENV FOO=bar /bin/bash -c 'echo ok'",
            "ok\n",
            "",
            0,
        )
        .await;
        let sandbox = test_sandbox(&server);

        sandbox
            .exec_command("echo ok", 5_000, None, Some(&env_vars), None)
            .await
            .expect("exec_command should succeed");

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn exec_command_streaming_rejects_stdin() {
        let server = MockServer::start_async().await;
        let sandbox = test_sandbox(&server);

        let request = ExecStreamingRequest {
            stdin: Some(b"hello".to_vec()),
            ..ExecStreamingRequest::new("true")
        };

        let error = sandbox
            .exec_command_streaming(request)
            .await
            .expect_err("streaming with stdin should be rejected");
        assert!(error.to_string().contains("standard input"));
    }

    #[tokio::test]
    async fn exec_command_streaming_replays_buffered_result() {
        let server = MockServer::start_async().await;
        let mock = mock_exec_expecting(
            &server,
            "env -u BASH_ENV /bin/bash -c 'echo hi'",
            "hi\n",
            "",
            0,
        )
        .await;
        let sandbox = test_sandbox(&server);

        let streaming_result = sandbox
            .exec_command_streaming(ExecStreamingRequest::new("echo hi"))
            .await
            .expect("streaming exec should succeed");

        assert!(!streaming_result.live_streaming);
        assert_eq!(streaming_result.result.stdout, "hi\n");
        assert_eq!(streaming_result.result.exit_code, Some(0));
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn initialize_errors_when_probe_marker_missing() {
        let server = MockServer::start_async().await;
        let _mock = mock_exec_expecting(
            &server,
            &format!("env -u BASH_ENV /bin/bash -c {}", shell_quote(BASH_PROBE_SCRIPT)),
            "not-ready\n",
            "",
            0,
        )
        .await;
        let sandbox = test_sandbox(&server);

        let error = sandbox
            .initialize()
            .await
            .expect_err("probe without the marker should fail readiness");
        assert!(error.to_string().contains("bash"));
    }

    #[tokio::test]
    async fn initialize_succeeds_when_probe_marker_present() {
        let server = MockServer::start_async().await;
        let _mock = mock_exec_expecting(
            &server,
            &format!("env -u BASH_ENV /bin/bash -c {}", shell_quote(BASH_PROBE_SCRIPT)),
            "fabro-bash-ready\n",
            "",
            0,
        )
        .await;
        let sandbox = test_sandbox(&server);

        sandbox
            .initialize()
            .await
            .expect("probe with the marker should pass readiness");
    }

    #[tokio::test]
    async fn start_also_runs_the_bash_probe() {
        let server = MockServer::start_async().await;
        let _mock = mock_exec_expecting(
            &server,
            &format!("env -u BASH_ENV /bin/bash -c {}", shell_quote(BASH_PROBE_SCRIPT)),
            "fabro-bash-ready\n",
            "",
            0,
        )
        .await;
        let sandbox = test_sandbox(&server);

        sandbox.start().await.expect("start should pass readiness");
    }

    #[tokio::test]
    async fn cleanup_errors_instead_of_panicking() {
        let server = MockServer::start_async().await;
        let sandbox = test_sandbox(&server);

        assert!(sandbox.cleanup().await.is_err());
    }

    #[tokio::test]
    async fn write_file_resolves_relative_path_and_sends_create_dirs_true() {
        let server = MockServer::start_async().await;
        let mock = server
            .mock_async(|when, then| {
                when.method(PUT)
                    .path(action_path("files"))
                    .query_param("path", "/workspace/sub/test.txt")
                    .query_param("createDirs", "true")
                    .header("content-type", "application/octet-stream")
                    .body("hello world");
                then.status(200)
                    .header("content-type", "application/json")
                    .json_body(serde_json::json!({ "bytesWritten": 11, "success": true }));
            })
            .await;
        let sandbox = test_sandbox(&server);

        sandbox
            .write_file("sub/test.txt", "hello world")
            .await
            .expect("write_file should succeed");

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn read_file_bytes_returns_fs_cat_bytes_for_absolute_path() {
        let server = MockServer::start_async().await;
        let mock = server
            .mock_async(|when, then| {
                when.method(GET)
                    .path(action_path("files"))
                    .query_param("path", "/workspace/test.txt");
                then.status(200)
                    .header("content-type", "application/octet-stream")
                    .body("raw file bytes");
            })
            .await;
        let sandbox = test_sandbox(&server);

        let bytes = sandbox
            .read_file_bytes("/workspace/test.txt")
            .await
            .expect("read_file_bytes should succeed");

        assert_eq!(bytes, b"raw file bytes".to_vec());
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn file_exists_true_when_fs_stat_returns_some() {
        let server = MockServer::start_async().await;
        let mock = server
            .mock_async(|when, then| {
                when.method(GET)
                    .path(action_path("files/stat"))
                    .query_param("path", "/workspace/test.txt");
                then.status(200)
                    .header("content-type", "application/json")
                    .json_body(file_stat_body("test.txt", "/workspace/test.txt", false, 24));
            })
            .await;
        let sandbox = test_sandbox(&server);

        let exists = sandbox
            .file_exists("test.txt")
            .await
            .expect("file_exists should succeed");

        assert!(exists);
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn file_exists_false_when_fs_stat_returns_404() {
        let server = MockServer::start_async().await;
        let mock = server
            .mock_async(|when, then| {
                when.method(GET).path(action_path("files/stat"));
                then.status(404)
                    .header("content-type", "application/problem+json")
                    .json_body(serde_json::json!({
                        "detail": "not found",
                        "errorCode": 1,
                        "requestId": "req-1",
                        "status": 404,
                        "title": "SandboxNotFound",
                        "traceId": "trace-1",
                    }));
            })
            .await;
        let sandbox = test_sandbox(&server);

        let exists = sandbox
            .file_exists("missing.txt")
            .await
            .expect("404 should not be an error");

        assert!(!exists);
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn list_directory_maps_fs_ls_entries_to_dir_entry() {
        let server = MockServer::start_async().await;
        let mock = server
            .mock_async(|when, then| {
                when.method(GET)
                    .path(action_path("files/list"))
                    .query_param("path", "/workspace");
                then.status(200)
                    .header("content-type", "application/json")
                    .json_body(serde_json::json!({
                        "entries": [
                            file_stat_body("test.txt", "/workspace/test.txt", false, 24),
                            file_stat_body("sub", "/workspace/sub", true, 4096),
                        ],
                        "path": "/workspace",
                    }));
            })
            .await;
        let sandbox = test_sandbox(&server);

        let entries = sandbox
            .list_directory("/workspace", None)
            .await
            .expect("list_directory should succeed");

        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name, "test.txt");
        assert!(!entries[0].is_dir);
        assert_eq!(entries[0].size, Some(24));
        assert_eq!(entries[1].name, "sub");
        assert!(entries[1].is_dir);
        assert_eq!(entries[1].size, None);
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn delete_file_runs_rm_dash_f_via_exec() {
        let server = MockServer::start_async().await;
        let mock = mock_exec_expecting(
            &server,
            "env -u BASH_ENV /bin/bash -c 'rm -f -- /workspace/test.txt'",
            "",
            "",
            0,
        )
        .await;
        let sandbox = test_sandbox(&server);

        sandbox
            .delete_file("test.txt")
            .await
            .expect("delete_file should succeed");

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn delete_file_errors_on_nonzero_exit() {
        let server = MockServer::start_async().await;
        let _mock = mock_exec_expecting(
            &server,
            "env -u BASH_ENV /bin/bash -c 'rm -f -- /workspace/test.txt'",
            "",
            "rm: permission denied\n",
            1,
        )
        .await;
        let sandbox = test_sandbox(&server);

        let error = sandbox
            .delete_file("test.txt")
            .await
            .expect_err("nonzero exit should be an error");
        assert!(error.to_string().contains("permission denied"));
    }

    #[tokio::test]
    async fn download_file_to_local_writes_fs_cat_bytes_to_a_new_nested_path() {
        let server = MockServer::start_async().await;
        let mock = server
            .mock_async(|when, then| {
                when.method(GET)
                    .path(action_path("files"))
                    .query_param("path", "/workspace/remote.bin");
                then.status(200)
                    .header("content-type", "application/octet-stream")
                    .body("binary\0content");
            })
            .await;
        let sandbox = test_sandbox(&server);
        let tempdir = tempfile::tempdir().expect("tempdir should be created");
        let local_path = tempdir.path().join("nested").join("out.bin");

        sandbox
            .download_file_to_local("remote.bin", &local_path)
            .await
            .expect("download_file_to_local should succeed");

        let written = fs::read(&local_path)
            .await
            .expect("downloaded file should exist");
        assert_eq!(written, b"binary\0content".to_vec());
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn upload_file_from_local_sends_local_bytes_via_fs_write() {
        let server = MockServer::start_async().await;
        let tempdir = tempfile::tempdir().expect("tempdir should be created");
        let local_path = tempdir.path().join("in.bin");
        fs::write(&local_path, b"local bytes")
            .await
            .expect("local file should be written");

        let mock = server
            .mock_async(|when, then| {
                when.method(PUT)
                    .path(action_path("files"))
                    .query_param("path", "/workspace/remote.bin")
                    .query_param("createDirs", "true")
                    .body("local bytes");
                then.status(200)
                    .header("content-type", "application/json")
                    .json_body(serde_json::json!({ "bytesWritten": 11, "success": true }));
            })
            .await;
        let sandbox = test_sandbox(&server);

        sandbox
            .upload_file_from_local(&local_path, "remote.bin")
            .await
            .expect("upload_file_from_local should succeed");

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn grep_parses_ripgrep_output_when_rg_is_available() {
        let server = MockServer::start_async().await;
        let _rg_probe = mock_exec_expecting(
            &server,
            "env -u BASH_ENV /bin/bash -c 'rg --version'",
            "ripgrep 14.0.0\n",
            "",
            0,
        )
        .await;
        let search_mock = mock_exec_expecting(
            &server,
            "env -u BASH_ENV /bin/bash -c 'rg --line-number --no-heading -- needle /workspace'",
            "/workspace/a.txt:3:needle here\n/workspace/b.txt:1:needle again\n",
            "",
            0,
        )
        .await;
        let sandbox = test_sandbox(&server);

        let matches = sandbox
            .grep("needle", "/workspace", &GrepOptions::default())
            .await
            .expect("grep should succeed");

        assert_eq!(matches, vec![
            "/workspace/a.txt:3:needle here".to_string(),
            "/workspace/b.txt:1:needle again".to_string(),
        ]);
        search_mock.assert_async().await;
    }

    #[tokio::test]
    async fn grep_falls_back_to_grep_when_rg_is_unavailable() {
        let server = MockServer::start_async().await;
        let _rg_probe = mock_exec_expecting(
            &server,
            "env -u BASH_ENV /bin/bash -c 'rg --version'",
            "",
            "command not found: rg\n",
            127,
        )
        .await;
        // `*.rs` contains a shell metacharacter, so `shell_quote` wraps it in
        // quotes — build the expected command the same way production code
        // does rather than hand-guessing the escaping.
        let inner = format!(
            "grep -rn -i --include {} -m 5 -- {} {}",
            shell_quote("*.rs"),
            shell_quote("needle"),
            shell_quote("/workspace")
        );
        let expected = format!("env -u BASH_ENV /bin/bash -c {}", shell_quote(&inner));
        let search_mock = mock_exec_expecting(
            &server,
            &expected,
            "/workspace/a.rs:2:needle\n",
            "",
            0,
        )
        .await;
        let sandbox = test_sandbox(&server);

        let options = GrepOptions {
            glob_filter:      Some("*.rs".to_string()),
            case_insensitive: true,
            max_results:      Some(5),
        };
        let matches = sandbox
            .grep("needle", "/workspace", &options)
            .await
            .expect("grep should succeed");

        assert_eq!(matches, vec!["/workspace/a.rs:2:needle".to_string()]);
        search_mock.assert_async().await;
    }

    #[tokio::test]
    async fn grep_returns_empty_vec_on_exit_code_one_no_matches() {
        let server = MockServer::start_async().await;
        let _rg_probe = mock_exec_expecting(
            &server,
            "env -u BASH_ENV /bin/bash -c 'rg --version'",
            "ripgrep 14.0.0\n",
            "",
            0,
        )
        .await;
        let _search_mock = mock_exec_expecting(
            &server,
            "env -u BASH_ENV /bin/bash -c 'rg --line-number --no-heading -- needle /workspace'",
            "",
            "",
            1,
        )
        .await;
        let sandbox = test_sandbox(&server);

        let matches = sandbox
            .grep("needle", "/workspace", &GrepOptions::default())
            .await
            .expect("exit code 1 should not be an error");

        assert!(matches.is_empty());
    }

    #[tokio::test]
    async fn working_directory_platform_and_os_version_report_config() {
        let server = MockServer::start_async().await;
        let sandbox = test_sandbox(&server);

        assert_eq!(sandbox.working_directory(), "/workspace");
        assert_eq!(sandbox.platform(), "linux");
        assert_eq!(sandbox.os_version(), "Linux (ACA ubuntu)");
        assert_eq!(sandbox.sandbox_info(), SANDBOX_ID);
    }
}
