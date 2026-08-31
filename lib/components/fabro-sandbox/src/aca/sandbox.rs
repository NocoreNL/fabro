//! ACA: `Sandbox` trait implementation.
//!
//! Task 8 begins the `impl Sandbox for AcaSandbox` block: command execution
//! (wrapped as non-login `/bin/bash -c`), buffered-then-replay streaming, and
//! the shared `BASH_PROBE_SCRIPT` readiness gate. File/grep/cleanup/etc. are
//! stubbed here and land in Tasks 9-11.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use fabro_types::CommandTermination;
use tokio::time;
use tokio_util::sync::CancellationToken;

use crate::aca::{AcaClient, AcaConfig};
use crate::sandbox::{
    BASH_ENV_VAR, BASH_PROBE_SCRIPT, BASH_PROBE_TIMEOUT_MS, replay_exec_result,
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
/// Tasks 9-11 replace these stubs with real file/grep/cleanup behavior.
const NOT_YET_IMPLEMENTED: &str = "aca: not yet implemented (task 9/10/11)";

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
}

impl AcaSandbox {
    pub fn new(client: Arc<AcaClient>, sandbox_id: String, config: AcaConfig) -> Self {
        Self {
            client,
            sandbox_id,
            config,
        }
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

    // --- stubs: real behavior lands in Tasks 9-11 ---

    async fn read_file_bytes(&self, _path: &str) -> crate::Result<Vec<u8>> {
        Err(crate::Error::message(NOT_YET_IMPLEMENTED))
    }

    async fn write_file(&self, _path: &str, _content: &str) -> crate::Result<()> {
        Err(crate::Error::message(NOT_YET_IMPLEMENTED))
    }

    async fn delete_file(&self, _path: &str) -> crate::Result<()> {
        Err(crate::Error::message(NOT_YET_IMPLEMENTED))
    }

    async fn file_exists(&self, _path: &str) -> crate::Result<bool> {
        Err(crate::Error::message(NOT_YET_IMPLEMENTED))
    }

    async fn list_directory(
        &self,
        _path: &str,
        _depth: Option<usize>,
    ) -> crate::Result<Vec<DirEntry>> {
        Err(crate::Error::message(NOT_YET_IMPLEMENTED))
    }

    async fn grep(
        &self,
        _pattern: &str,
        _path: &str,
        _options: &GrepOptions,
    ) -> crate::Result<Vec<String>> {
        Err(crate::Error::message(NOT_YET_IMPLEMENTED))
    }

    async fn download_file_to_local(
        &self,
        _remote_path: &str,
        _local_path: &Path,
    ) -> crate::Result<()> {
        Err(crate::Error::message(NOT_YET_IMPLEMENTED))
    }

    async fn upload_file_from_local(
        &self,
        _local_path: &Path,
        _remote_path: &str,
    ) -> crate::Result<()> {
        Err(crate::Error::message(NOT_YET_IMPLEMENTED))
    }

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

    use httpmock::Method::POST;
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
        format!(
            "/subscriptions/{SUBSCRIPTION}/resourceGroups/{RESOURCE_GROUP}/sandboxGroups/{SANDBOX_GROUP}/sandboxes/{SANDBOX_ID}/executeShellCommand"
        )
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
    async fn stubbed_methods_error_instead_of_panicking() {
        let server = MockServer::start_async().await;
        let sandbox = test_sandbox(&server);

        assert!(sandbox.read_file_bytes("/x").await.is_err());
        assert!(sandbox.write_file("/x", "y").await.is_err());
        assert!(sandbox.delete_file("/x").await.is_err());
        assert!(sandbox.file_exists("/x").await.is_err());
        assert!(sandbox.list_directory("/x", None).await.is_err());
        assert!(
            sandbox
                .grep("pat", "/x", &GrepOptions::default())
                .await
                .is_err()
        );
        assert!(sandbox.cleanup().await.is_err());
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
