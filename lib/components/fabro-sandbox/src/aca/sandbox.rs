//! ACA: `Sandbox` trait implementation.
//!
//! Task 8 began the `impl Sandbox for AcaSandbox` block: command execution
//! (wrapped as non-login `/bin/bash -c`), buffered-then-replay streaming, and
//! the shared `BASH_PROBE_SCRIPT` readiness gate. Task 9 adds file
//! operations (delegating to [`AcaClient`]'s `fs_*` endpoints) and `grep`
//! (via exec, since ACA has no native search endpoint). Task 10 adds the
//! lifecycle methods (`activate`/`start`/`stop`/`cleanup`) and the
//! `with_running_retry` 409-\>resume-\>retry-once guard (spec rule 3). Task 11
//! completes the block with `setup_git`/`git_push_ref`, delegating to the
//! crate's shared exec-based git helpers (this provider has no managed push
//! credentials yet, so pushes run with whatever the remote already carries).

use std::collections::HashMap;
use std::fmt::Write as _;
use std::future::Future;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use fabro_types::{CommandTermination, SandboxProviderKind};
use tokio::sync::OnceCell;
use tokio::{fs, time};
use tokio_util::sync::CancellationToken;

use crate::aca::client::SandboxState;
use crate::aca::{AcaApiError, AcaClient, AcaConfig};
// ACA: clone-on-initialize reuses `git_retry`/`push_credentials`, the same
// shared helpers Docker's `clone_github_repo` does — see
// `clone_if_configured`/`clone_github_repo` below. `clone_source` (Docker's
// owner/repo-layout + tag/commit-pinning helper module) is deliberately NOT
// reused here: it is feature-gated to `docker`/`daytona` only, and ACA needs
// just GitHub-origin validation/normalization, not the owner/repo layout or
// pinned-revision machinery that make up most of that module — widening its
// feature gate would compile that unused machinery (and its dead-code
// warnings) into aca-only builds for a handful of lines' worth of reuse.
use crate::git_retry::{self, CredentialContext};
use crate::push_credentials::{self, PushCredentialState};
use crate::redact::redact_auth_url;
use crate::sandbox::{
    BASH_ENV_VAR, BASH_PROBE_SCRIPT, BASH_PROBE_TIMEOUT_MS, git_push_via_exec, resolve_path,
    setup_git_via_exec, validate_bash_probe,
};
use crate::{
    DirEntry, ExecResult, ExecStreamingRequest, GitRunInfo, GitSetupIntent, GrepOptions,
    PushError, PushReport, RetryPlan, Sandbox, shell_quote,
};

/// Remediation shown when an ACA sandbox has no usable Bash.
const ACA_BASH_REMEDIATION: &str = "ACA sandboxes require /bin/bash for every command, with no \
     `sh` fallback; use a disk image that provides bash, such as `ubuntu`.";

/// Timeout for the single `git clone` exec issued by
/// [`AcaSandbox::clone_github_repo`]. ACA has no per-request `clone_depth`
/// knob (unlike `DockerSandboxOptions`), so this is a flat budget rather than
/// Docker's shared multi-step deadline.
const ACA_CLONE_TIMEOUT_MS: u64 = 5 * 60 * 1_000;

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
    // ACA: clone-on-initialize state, mirroring `DockerSandbox`'s
    // `clone_origin_url`/`clone_branch`/`push_credentials` fields — see
    // `clone_if_configured`/`clone_github_repo`.
    clone_origin_url: Option<String>,
    clone_branch:     Option<String>,
    push_credentials: PushCredentialState,
    /// Whether `initialize()` cloned a repository into `config.working_dir`.
    /// Unset until `initialize()` runs. Mirrors `DockerSandbox`'s
    /// `repo_cloned` field; gates [`Sandbox::setup_git`] the same way.
    repo_cloned: OnceCell<bool>,
    /// Cached result of probing `rg --version` via exec, so [`Sandbox::grep`]
    /// only pays for the probe once per sandbox instance. Mirrors
    /// `daytona/mod.rs`'s `rg_available` field.
    rg_available: OnceCell<bool>,
}

impl AcaSandbox {
    /// `github_app`/`clone_origin_url`/`clone_branch` mirror
    /// `DockerSandbox::new`'s parameters: `github_app` (plus the origin) build
    /// the clone-time token source, and `clone_origin_url`/`clone_branch`
    /// tell `initialize()` what to clone. Fallible for the same reason
    /// Docker's constructor is: building the token source can fail (e.g. an
    /// unparseable origin).
    pub fn new(
        client: Arc<AcaClient>,
        sandbox_id: String,
        config: AcaConfig,
        github_app: Option<&fabro_github::GitHubCredentials>,
        clone_origin_url: Option<String>,
        clone_branch: Option<String>,
    ) -> crate::Result<Self> {
        let push_credentials = PushCredentialState::new(push_credentials::build_token_source(
            github_app,
            clone_origin_url.as_deref(),
        )?);
        Ok(Self {
            client,
            sandbox_id,
            config,
            clone_origin_url,
            clone_branch,
            push_credentials,
            repo_cloned: OnceCell::new(),
            rg_available: OnceCell::const_new(),
        })
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

    /// Spec rule 3's per-op 409 guard: run `op` once; if it fails with ACA's
    /// `GlobalSandboxNotRunning` 409 (an [`AcaApiError::NotRunning`]
    /// somewhere in the error's source chain), `resume` the sandbox and run
    /// `op` **exactly one more time**, propagating a second failure as-is.
    ///
    /// This is a single-shot retry, not a loop, and it is deliberately the
    /// only place that reacts to a mid-session suspend: [`Self::activate`]
    /// remains the one explicit resume at acquisition time, so callers must
    /// not add a `get_sandbox` round-trip before every operation (that's the
    /// anti-pattern spec rule 3 forbids).
    async fn with_running_retry<T, F, Fut>(&self, op: F) -> crate::Result<T>
    where
        F: Fn() -> Fut,
        Fut: Future<Output = crate::Result<T>>,
    {
        match op().await {
            Ok(value) => Ok(value),
            Err(error) if Self::is_not_running_error(&error) => {
                self.client.resume(&self.sandbox_id).await?;
                op().await
            }
            Err(error) => Err(error),
        }
    }

    /// Walk `error`'s source chain for [`AcaApiError::NotRunning`], the same
    /// downcast [`AcaClient`]'s own tests perform (`error.source()`, then
    /// `downcast_ref::<AcaApiError>()`) generalized to tolerate any extra
    /// layers of `crate::Error::Context` wrapping between the client and
    /// this call site.
    fn is_not_running_error(error: &crate::Error) -> bool {
        let mut current: Option<&(dyn std::error::Error + 'static)> = Some(error);
        while let Some(err) = current {
            if matches!(
                err.downcast_ref::<AcaApiError>(),
                Some(AcaApiError::NotRunning)
            ) {
                return true;
            }
            current = err.source();
        }
        false
    }

    /// Whether `initialize()` cloned a repository into `config.working_dir`.
    /// Mirrors `docker.rs`'s `repo_cloned()`.
    fn repo_cloned(&self) -> bool {
        self.repo_cloned.get().copied().unwrap_or(false)
    }

    /// Decide whether `initialize()` has anything to clone, and clone it if
    /// so. ACA has no `skip_clone` knob (`AcaConfig` doesn't carry one — see
    /// `SandboxSpec::Aca`'s doc comment) and no tag/commit pinning, so this
    /// only needs the GitHub-origin validation/normalization slice of
    /// Docker's `clone_source::decide_clone` — inlined here rather than
    /// reused (see the `clone_source` import comment above).
    async fn clone_if_configured(&self) -> crate::Result<()> {
        let Some(origin_url) = self
            .clone_origin_url
            .as_deref()
            .filter(|url| !url.trim().is_empty())
        else {
            tracing::warn!(
                provider = "aca",
                "no clone source was present; creating an empty workspace without repository \
                 files"
            );
            let _ = self.repo_cloned.set(false);
            return Ok(());
        };

        let origin_url = fabro_github::normalize_repo_origin_url(origin_url);
        if let Err(err) = fabro_github::parse_github_owner_repo(&origin_url) {
            return Err(crate::Error::message(format!(
                "Clone-based sandboxes currently support GitHub repository origins only: {err}"
            )));
        }
        let branch = self
            .clone_branch
            .as_deref()
            .filter(|branch| !branch.trim().is_empty())
            .map(str::to_string);

        self.clone_github_repo(origin_url, branch).await
    }

    /// Clone `origin_url` into `config.working_dir` via
    /// [`Sandbox::exec_command`] (the `/bin/bash -c` transport, so it
    /// inherits the bash contract and egress). Mirrors `docker.rs`'s
    /// `clone_github_repo` (mint a clone-scoped token → embed it in the URL →
    /// run the clone → record the embedded token), but without Docker's
    /// owner/repo layout, symlink, or tag/commit pinning: an ACA sandbox has
    /// one flat working directory and `SandboxSpec::Aca` carries no pinned-
    /// revision fields (see its doc comment). `--branch` alone checks out the
    /// branch, so no separate checkout step is needed for the (only)
    /// unpinned-branch case.
    async fn clone_github_repo(
        &self,
        origin_url: String,
        branch: Option<String>,
    ) -> crate::Result<()> {
        // The clone mints its own token (never a warm-cache reuse) and seeds
        // the shared source, so the first refresh compares against the clone
        // token instead of believing nothing was ever embedded.
        let resolved_token = match self.push_credentials.source() {
            Some(source) => Some(source.mint_for_clone().await.map_err(|err| {
                crate::Error::context_anyhow("Failed to get GitHub App credentials for clone", err)
            })?),
            None => None,
        };
        let clone_credential_context =
            CredentialContext::from_snapshot(resolved_token.as_ref().map(|token| &token.snapshot));

        let auth_url = match &resolved_token {
            Some(token) => Some(
                fabro_github::embed_token_in_url(&origin_url, token.token.expose()).map_err(
                    |err| {
                        crate::Error::context_anyhow(
                            "Failed to build authenticated GitHub clone URL",
                            err,
                        )
                    },
                )?,
            ),
            None => None,
        };
        let clone_url = auth_url
            .as_ref()
            .map_or(origin_url.as_str(), |url| url.as_raw_url().as_str());

        let command = aca_git_clone_command(clone_url, branch.as_deref(), &self.config.working_dir);

        let plan = git_retry::RetryPlan::clone_default(None);
        git_retry::retry_git_operation(
            SandboxProviderKind::Aca,
            "clone",
            &plan,
            |_attempt| async {
                match self
                    .exec_command(&command, ACA_CLONE_TIMEOUT_MS, None, None, None)
                    .await
                {
                    Ok(result) if result.is_success() => Ok(()),
                    Ok(result) => {
                        let retry_reason = git_retry::classify_output(
                            &result.stderr,
                            &result.stdout,
                            clone_credential_context,
                        )
                        .retry_reason();
                        Err(AcaCloneFailure {
                            error: self.clone_failure_error(
                                result,
                                "ACA git clone",
                                auth_url.as_ref(),
                            ),
                            retry_reason,
                        })
                    }
                    Err(error) => Err(AcaCloneFailure {
                        error: crate::Error::context("ACA git clone transport failed", error),
                        retry_reason: None,
                    }),
                }
            },
            |failure: &AcaCloneFailure| failure.retry_reason,
        )
        .await
        .map_err(|failure| failure.error)?;

        if let Some(token) = resolved_token {
            // The clone URL embedded this token in `origin`; record it so a
            // future push refresh compares against the clone generation.
            self.push_credentials.record_embedded(token).await;
        }
        let _ = self.repo_cloned.set(true);
        Ok(())
    }

    /// Preserve a failed clone's exec result while masking the auth URL.
    /// Mirrors `docker.rs`'s `clone_failure_error`.
    fn clone_failure_error(
        &self,
        result: ExecResult,
        label: &'static str,
        auth_url: Option<&fabro_redact::DisplaySafeUrl>,
    ) -> crate::Error {
        let error =
            result.into_exec_error_with_redactor(label, |output| redact_auth_url(output, auth_url));
        let message = if self.push_credentials.source().is_none() {
            "Git clone failed. If this is a private repository, configure a GitHub App with \
             `fabro install` and install it for your organization."
        } else {
            "Failed to clone repository into ACA sandbox"
        };
        crate::Error::context(message, error)
    }
}

/// What a failed clone attempt tells the retry loop. Mirrors `docker.rs`'s
/// `DockerCloneFailure`.
struct AcaCloneFailure {
    error:        crate::Error,
    retry_reason: Option<git_retry::GitRetryReason>,
}

/// Build the `git clone` command for the (only) case ACA supports: an
/// unpinned branch clone straight into `checkout_path`. Mirrors `docker.rs`'s
/// `git_clone_command`, minus the `--depth` argument: `AcaConfig` has no
/// `clone_depth` knob to plumb through, so every ACA clone fetches full
/// history.
fn aca_git_clone_command(clone_url: &str, branch: Option<&str>, checkout_path: &str) -> String {
    let mut command = format!("{} clone", crate::sandbox::GIT);
    if let Some(branch) = branch {
        command.push_str(" --branch ");
        command.push_str(&shell_quote(branch));
        command.push_str(" --single-branch");
    }
    command.push_str(" --no-tags -- ");
    command.push_str(&shell_quote(clone_url));
    command.push(' ');
    command.push_str(&shell_quote(checkout_path));
    command
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
            result = self.with_running_retry(|| self.client.exec(&self.sandbox_id, &wrapped)) => {
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

    // ACA's exec endpoint is synchronous/buffered only — the capture doc
    // notes "No streaming — this is a synchronous, buffered exec" — so
    // `exec_command_streaming` has no ACA-specific behavior beyond what the
    // trait default already does (replay the completed `exec_command` result
    // through the output callback rather than streaming live chunks); the
    // default is used as-is rather than restating it here.

    // ACA: clone-based (`is_clone_based()` includes `Aca`), but ACA's create
    // call ignores `clone_origin_url` (unlike Docker/Daytona), so nothing
    // clones the repo unless this does it — the missing-clone gap this fix
    // closes. Runs after the readiness probe so a clone never races an
    // unready bash.
    async fn initialize(&self) -> crate::Result<()> {
        self.run_bash_probe().await?;
        self.clone_if_configured().await
    }

    /// Idempotent resume-if-`Stopped`: fetch current state and call `resume`
    /// only when it's `Stopped`. An already-`Running` sandbox (or one whose
    /// state can't be determined) is left alone — no unconditional resume.
    /// This is the ONE explicit resume at acquisition time; the per-op 409
    /// guard is [`Self::with_running_retry`], not a repeat of this check
    /// before every call.
    async fn activate(&self) -> crate::Result<()> {
        let resource = self.client.get_sandbox(&self.sandbox_id).await?;
        if matches!(resource.map(|r| r.state), Some(SandboxState::Stopped)) {
            self.client.resume(&self.sandbox_id).await?;
        }
        Ok(())
    }

    async fn start(&self) -> crate::Result<()> {
        self.activate().await?;
        self.run_bash_probe().await
    }

    async fn stop(&self) -> crate::Result<()> {
        self.client.suspend(&self.sandbox_id).await
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

    /// `Sandbox::delete`'s default forwards here, so this one override
    /// covers both `cleanup()` and `delete()`.
    async fn cleanup(&self) -> crate::Result<()> {
        self.client.delete_sandbox(&self.sandbox_id).await
    }

    /// ACA is clone-based ([`fabro_types::SandboxProviderKind::is_clone_based`]
    /// includes `Aca`), so — unlike the trait default's "no git" `Ok(None)`
    /// — this sets up a run branch via the same exec transport
    /// [`Sandbox::exec_command`] uses, when `initialize()` actually cloned a
    /// repository. Mirrors `docker.rs`'s `setup_git`, including its
    /// `repo_cloned()` guard: an ACA sandbox with no `clone_origin_url`
    /// configured has no repository to branch inside.
    async fn setup_git(&self, intent: &GitSetupIntent) -> crate::Result<Option<GitRunInfo>> {
        if !self.repo_cloned() {
            return Ok(None);
        }
        setup_git_via_exec(self, intent).await.map(Some)
    }

    /// Pushes via the shared exec-based helper. `credentials` is `None`:
    /// `push_credentials` (added for clone-time token minting — see
    /// `clone_github_repo`) is not yet wired into push-time credential
    /// refresh, so the push runs with whatever the remote already carries.
    async fn git_push_ref(
        &self,
        refspec: &str,
        plan: &RetryPlan,
    ) -> Result<PushReport, PushError> {
        git_push_via_exec(self, None, refspec, plan).await
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
    use std::sync::atomic::{AtomicUsize, Ordering};

    use httpmock::Method::{DELETE, GET, POST, PUT};
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
            None,
            None,
            None,
        )
        .expect("test sandbox construction should succeed")
    }

    /// A fake PAT — never a real token — so `clone_github_repo` mints a
    /// clone-scoped credential without any network mint call
    /// (`GitHubCredentials::Pat` resolves statically; see
    /// `push_credentials.rs`'s own tests for the same pattern).
    const FAKE_CLONE_PAT: &str = "ghp_fake_test_token_do_not_use";

    fn test_sandbox_with_clone(
        server: &MockServer,
        clone_origin_url: Option<&str>,
        clone_branch: Option<&str>,
    ) -> AcaSandbox {
        AcaSandbox::new(
            Arc::new(test_client(server)),
            SANDBOX_ID.to_string(),
            test_config(),
            Some(&fabro_github::GitHubCredentials::Pat(
                FAKE_CLONE_PAT.to_string(),
            )),
            clone_origin_url.map(str::to_string),
            clone_branch.map(str::to_string),
        )
        .expect("test sandbox construction should succeed")
    }

    fn exec_path() -> String {
        action_path("executeShellCommand")
    }

    fn action_path(action: &str) -> String {
        format!(
            "/subscriptions/{SUBSCRIPTION}/resourceGroups/{RESOURCE_GROUP}/sandboxGroups/{SANDBOX_GROUP}/sandboxes/{SANDBOX_ID}/{action}"
        )
    }

    /// Plain `.../sandboxes/{id}` path (no trailing action) — used by
    /// `get_sandbox`/`delete_sandbox`, mirroring `client.rs` tests'
    /// `sandbox_path` helper.
    fn sandbox_path() -> String {
        format!(
            "/subscriptions/{SUBSCRIPTION}/resourceGroups/{RESOURCE_GROUP}/sandboxGroups/{SANDBOX_GROUP}/sandboxes/{SANDBOX_ID}"
        )
    }

    /// Minimal-but-complete `SandboxResource` body, mirroring `client.rs`
    /// tests' `sandbox_body` helper (every field the type requires, with
    /// only `state` varying per test).
    fn sandbox_resource_body(state: &str) -> serde_json::Value {
        serde_json::json!({
            "id": SANDBOX_ID,
            "createdAt": "2026-08-01T00:00:00Z",
            "lifecycle": {
                "autoSuspendPolicy": { "enabled": true, "interval": 600, "mode": "Memory" }
            },
            "managementUrl": "https://management.northeurope.azuredevcompute.io",
            "region": "northeurope",
            "resources": { "cpu": "1000m", "disk": "20480Mi", "memory": "2048Mi" },
            "sourcesRef": { "diskImage": { "id": "img-1", "isPublic": false } },
            "state": state,
            "vmmType": "cloudhypervisor",
        })
    }

    /// `problem+json` body for ACA's captured 409 `GlobalSandboxNotRunning`,
    /// mirroring `client.rs` tests' `not_running_body` helper.
    fn not_running_body() -> serde_json::Value {
        serde_json::json!({
            "title": "GlobalSandboxNotRunning",
            "status": 409,
            "detail": "Sandbox 'sbx-1' is not in Running state",
            "errorCode": 501,
            "traceId": "trace-1",
            "requestId": "req-1",
        })
    }

    async fn mock_get_sandbox<'a>(server: &'a MockServer, state: &'a str) -> httpmock::Mock<'a> {
        server
            .mock_async(|when, then| {
                when.method(GET).path(sandbox_path());
                then.status(200)
                    .header("content-type", "application/json")
                    .json_body(sandbox_resource_body(state));
            })
            .await
    }

    async fn mock_resume(server: &MockServer) -> httpmock::Mock<'_> {
        server
            .mock_async(|when, then| {
                when.method(POST).path(action_path("resume"));
                then.status(200)
                    .header("content-type", "application/json")
                    .json_body(sandbox_resource_body("Running"));
            })
            .await
    }

    async fn mock_suspend(server: &MockServer) -> httpmock::Mock<'_> {
        server
            .mock_async(|when, then| {
                when.method(POST).path(action_path("stop"));
                then.status(200)
                    .header("content-type", "application/json")
                    .json_body(serde_json::json!({ "id": "snap-1" }));
            })
            .await
    }

    async fn mock_delete_sandbox(server: &MockServer) -> httpmock::Mock<'_> {
        server
            .mock_async(|when, then| {
                when.method(DELETE).path(sandbox_path());
                then.status(204);
            })
            .await
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

    /// `clone_origin_url = None` (the local/no-clone case) — `initialize()`
    /// must not attempt any clone, only the readiness probe. Registers a
    /// mock for what a clone `git` exec would look like and asserts it never
    /// fires.
    #[tokio::test]
    async fn initialize_does_not_clone_when_no_origin_is_configured() {
        let server = MockServer::start_async().await;
        let _probe_mock = mock_exec_expecting(
            &server,
            &format!("env -u BASH_ENV /bin/bash -c {}", shell_quote(BASH_PROBE_SCRIPT)),
            "fabro-bash-ready\n",
            "",
            0,
        )
        .await;
        let clone_mock = server
            .mock_async(|when, then| {
                when.method(POST)
                    .path(exec_path())
                    .body_includes("git -c maintenance.auto=0 -c gc.auto=0 clone");
                then.status(200)
                    .header("content-type", "application/json")
                    .json_body(serde_json::json!({
                        "executionTimeMs": 1,
                        "exitCode": 0,
                        "stderr": "",
                        "stdout": "",
                    }));
            })
            .await;
        let sandbox = test_sandbox(&server);

        sandbox
            .initialize()
            .await
            .expect("initialize with no clone origin should still succeed");

        clone_mock.assert_calls_async(0).await;
    }

    /// `initialize()` with a `clone_origin_url` configured clones the repo
    /// via exec after the readiness probe: mints a token from the (fake,
    /// test-only) GitHub credential, embeds it in the clone URL, and execs
    /// `git clone` straight into `config.working_dir`. Asserts the exec
    /// request body carries the clone command and the working dir, and that
    /// SOME token is embedded — never a real one (`FAKE_CLONE_PAT` is a fake
    /// test-only credential, never a real one).
    #[tokio::test]
    async fn initialize_clones_the_configured_repo_with_an_embedded_token() {
        let server = MockServer::start_async().await;
        let _probe_mock = mock_exec_expecting(
            &server,
            &format!("env -u BASH_ENV /bin/bash -c {}", shell_quote(BASH_PROBE_SCRIPT)),
            "fabro-bash-ready\n",
            "",
            0,
        )
        .await;
        let auth_url =
            fabro_github::embed_token_in_url("https://github.com/acme/widgets", FAKE_CLONE_PAT)
                .expect("embed fake token in clone url");
        let clone_command =
            aca_git_clone_command(auth_url.as_raw_url().as_str(), Some("main"), "/workspace");
        let clone_command_wrapped =
            format!("env -u BASH_ENV /bin/bash -c {}", shell_quote(&clone_command));
        let clone_mock = mock_exec_expecting(&server, &clone_command_wrapped, "", "", 0).await;
        let sandbox = test_sandbox_with_clone(
            &server,
            Some("https://github.com/acme/widgets"),
            Some("main"),
        );

        sandbox
            .initialize()
            .await
            .expect("initialize should clone the configured repo");

        // The mock only matches the exact command built with the fake
        // token embedded — this proves both the clone command shape (git
        // clone into /workspace) and that a token was embedded, without ever
        // asserting on a real credential.
        clone_mock.assert_async().await;
    }

    #[tokio::test]
    async fn start_also_runs_the_bash_probe() {
        let server = MockServer::start_async().await;
        // `start` now runs `activate` first; a `Running` state means no
        // resume call is expected before the probe.
        let _get_mock = mock_get_sandbox(&server, "Running").await;
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
    async fn activate_resumes_sandbox_when_state_is_stopped() {
        let server = MockServer::start_async().await;
        let get_mock = mock_get_sandbox(&server, "Stopped").await;
        let resume_mock = mock_resume(&server).await;
        let sandbox = test_sandbox(&server);

        sandbox
            .activate()
            .await
            .expect("activate should succeed for a stopped sandbox");

        get_mock.assert_calls_async(1).await;
        resume_mock.assert_calls_async(1).await;
    }

    #[tokio::test]
    async fn activate_does_not_resume_sandbox_when_state_is_running() {
        let server = MockServer::start_async().await;
        let get_mock = mock_get_sandbox(&server, "Running").await;
        // Registered but expected to receive zero hits: activate() must not
        // resume an already-running sandbox unconditionally.
        let resume_mock = mock_resume(&server).await;
        let sandbox = test_sandbox(&server);

        sandbox
            .activate()
            .await
            .expect("activate should succeed for a running sandbox");

        get_mock.assert_calls_async(1).await;
        resume_mock.assert_calls_async(0).await;
    }

    #[tokio::test]
    async fn stop_calls_suspend() {
        let server = MockServer::start_async().await;
        let suspend_mock = mock_suspend(&server).await;
        let sandbox = test_sandbox(&server);

        sandbox.stop().await.expect("stop should succeed");

        suspend_mock.assert_calls_async(1).await;
    }

    #[tokio::test]
    async fn cleanup_calls_delete_sandbox() {
        let server = MockServer::start_async().await;
        let delete_mock = mock_delete_sandbox(&server).await;
        let sandbox = test_sandbox(&server);

        sandbox.cleanup().await.expect("cleanup should succeed");

        delete_mock.assert_calls_async(1).await;
    }

    #[tokio::test]
    async fn delete_forwards_to_delete_sandbox_via_the_default_cleanup_call() {
        let server = MockServer::start_async().await;
        let delete_mock = mock_delete_sandbox(&server).await;
        let sandbox = test_sandbox(&server);

        sandbox.delete().await.expect("delete should succeed");

        delete_mock.assert_calls_async(1).await;
    }

    /// Spec rule 3: a single `GlobalSandboxNotRunning` 409 on the first exec
    /// attempt triggers exactly one `resume`, then exactly one retried exec,
    /// which succeeds. The 409 mock uses a shared counter in a custom
    /// matcher so it only matches the FIRST request; the second request
    /// falls through to the always-matching success mock — this is how
    /// httpmock simulates "fails once, then succeeds" for two requests with
    /// an otherwise-identical body.
    #[tokio::test]
    async fn exec_command_resumes_once_and_retries_after_a_409_then_succeeds() {
        let server = MockServer::start_async().await;
        let attempts = Arc::new(AtomicUsize::new(0));
        let first_attempt = Arc::clone(&attempts);
        let not_running_mock = server
            .mock_async(move |when, then| {
                when.method(POST)
                    .path(exec_path())
                    .json_body(
                        serde_json::json!({ "command": "env -u BASH_ENV /bin/bash -c 'echo ok'" }),
                    )
                    .is_true(move |_req| first_attempt.fetch_add(1, Ordering::SeqCst) == 0);
                then.status(409)
                    .header("content-type", "application/problem+json")
                    .json_body(not_running_body());
            })
            .await;
        let resume_mock = mock_resume(&server).await;
        let success_mock = mock_exec_expecting(
            &server,
            "env -u BASH_ENV /bin/bash -c 'echo ok'",
            "ok\n",
            "",
            0,
        )
        .await;
        let sandbox = test_sandbox(&server);

        let result = sandbox
            .exec_command("echo ok", 5_000, None, None, None)
            .await
            .expect("exec_command should succeed after resume+retry");

        assert_eq!(result.exit_code, Some(0));
        assert_eq!(result.stdout, "ok\n");
        not_running_mock.assert_calls_async(1).await;
        resume_mock.assert_calls_async(1).await;
        success_mock.assert_calls_async(1).await;
    }

    /// A persistent 409 must fail after exactly one retry — no loop: two
    /// total exec attempts, one resume, then the second failure propagates.
    #[tokio::test]
    async fn exec_command_fails_after_one_retry_when_409_persists() {
        let server = MockServer::start_async().await;
        let not_running_mock = server
            .mock_async(|when, then| {
                when.method(POST).path(exec_path());
                then.status(409)
                    .header("content-type", "application/problem+json")
                    .json_body(not_running_body());
            })
            .await;
        let resume_mock = mock_resume(&server).await;
        let sandbox = test_sandbox(&server);

        let error = sandbox
            .exec_command("true", 5_000, None, None, None)
            .await
            .expect_err("a persistent 409 should fail after exactly one retry");

        assert!(error.to_string().contains("ACA exec request failed"));
        not_running_mock.assert_calls_async(2).await;
        resume_mock.assert_calls_async(1).await;
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

    /// `setup_git_via_exec` issues three git commands in sequence — read the
    /// current branch, resolve the base SHA for a `NewRun` intent, then
    /// `checkout -B` the new run branch — all through the same `exec`
    /// transport as every other `AcaSandbox` command. `setup_git` only does
    /// this once `initialize()` actually cloned a repository (the
    /// `repo_cloned()` guard — see its doc comment), so this drives a real
    /// clone through `initialize()` first, proving `setup_git` proceeds
    /// against the repository the clone step just produced.
    #[tokio::test]
    async fn setup_git_creates_a_run_branch_via_exec_and_returns_git_run_info() {
        let server = MockServer::start_async().await;
        let _probe_mock = mock_exec_expecting(
            &server,
            &format!("env -u BASH_ENV /bin/bash -c {}", shell_quote(BASH_PROBE_SCRIPT)),
            "fabro-bash-ready\n",
            "",
            0,
        )
        .await;
        let auth_url = fabro_github::embed_token_in_url(
            "https://github.com/acme/widgets",
            FAKE_CLONE_PAT,
        )
            .expect("embed fake token in clone url");
        let clone_command =
            aca_git_clone_command(auth_url.as_raw_url().as_str(), Some("main"), "/workspace");
        let _clone_mock = mock_exec_expecting(
            &server,
            &format!("env -u BASH_ENV /bin/bash -c {}", shell_quote(&clone_command)),
            "",
            "",
            0,
        )
        .await;
        let _branch_mock = mock_exec_expecting(
            &server,
            "env -u BASH_ENV /bin/bash -c 'git rev-parse --abbrev-ref HEAD'",
            "main\n",
            "",
            0,
        )
        .await;
        let _sha_mock = mock_exec_expecting(
            &server,
            "env -u BASH_ENV /bin/bash -c 'git rev-parse HEAD'",
            "abc123\n",
            "",
            0,
        )
        .await;
        let checkout_mock = mock_exec_expecting(
            &server,
            "env -u BASH_ENV /bin/bash -c 'git checkout -B fabro/run/run-1 abc123'",
            "",
            "",
            0,
        )
        .await;
        let sandbox = test_sandbox_with_clone(
            &server,
            Some("https://github.com/acme/widgets"),
            Some("main"),
        );
        sandbox
            .initialize()
            .await
            .expect("initialize should clone the configured repo");

        let info = sandbox
            .setup_git(&GitSetupIntent::NewRun {
                run_id: "run-1".to_string(),
            })
            .await
            .expect("setup_git should succeed")
            .expect("a cloned sandbox should always set up a run branch");

        assert_eq!(info.base_sha, "abc123");
        assert_eq!(info.run_branch, "fabro/run/run-1");
        assert_eq!(info.base_branch, Some("main".to_string()));
        checkout_mock.assert_async().await;
    }

    /// `setup_git` returns `Ok(None)` instead of running git commands when
    /// `initialize()` found no clone source (`repo_cloned()` is false) — a
    /// sandbox with nothing cloned has no repository to branch inside.
    #[tokio::test]
    async fn setup_git_returns_none_when_nothing_was_cloned() {
        let server = MockServer::start_async().await;
        let sandbox = test_sandbox(&server);

        let info = sandbox
            .setup_git(&GitSetupIntent::NewRun {
                run_id: "run-1".to_string(),
            })
            .await
            .expect("setup_git should succeed even with nothing cloned");

        assert!(info.is_none());
    }

    /// `git_push_via_exec` with `credentials: None` issues exactly one `git
    /// push` exec and reports success with no token/credential action —
    /// this provider has no managed push-credential state yet.
    #[tokio::test]
    async fn git_push_ref_pushes_via_exec_without_managed_credentials() {
        let server = MockServer::start_async().await;
        let push_mock = mock_exec_expecting(
            &server,
            "env -u BASH_ENV /bin/bash -c 'git -c maintenance.auto=0 -c gc.auto=0 push origin \
             refs/heads/fabro/run/run-1'",
            "",
            "",
            0,
        )
        .await;
        let sandbox = test_sandbox(&server);

        let report = sandbox
            .git_push_ref("refs/heads/fabro/run/run-1", &RetryPlan::checkpoint_push())
            .await
            .expect("git_push_ref should succeed");

        assert_eq!(report.attempts.len(), 1);
        assert!(report.attempts[0].success);
        assert_eq!(report.attempts[0].token, None);
        assert_eq!(report.attempts[0].credential_action, None);
        push_mock.assert_async().await;
    }

    // ACA: live end-to-end smoke test (Task 15). Ignored + env-gated: only runs
    // under `ACA_SMOKE=1` against real Azure with a pre-provisioned sandbox
    // group and a throwaway `ACA_SMOKE_PAT` (contents:write on the scratch repo).
    // Exercises the REAL provider + sandbox: create + egress -> BASH_PROBE +
    // exit-code/stream fidelity -> authenticated git clone+push through the
    // Deny/Full egress -> suspend/resume -> delete (teardown always runs).
    #[tokio::test]
    #[ignore = "live smoke: set ACA_SMOKE=1 + ACA_* env + ACA_SMOKE_PAT and run --ignored"]
    async fn live_smoke_create_exec_clone_push_lifecycle_delete() {
        if std::env::var("ACA_SMOKE").is_err() {
            return;
        }
        let sub = std::env::var("ACA_SUBSCRIPTION_ID").expect("ACA_SUBSCRIPTION_ID");
        let rg = std::env::var("ACA_RESOURCE_GROUP").expect("ACA_RESOURCE_GROUP");
        let group = std::env::var("ACA_SANDBOX_GROUP").expect("ACA_SANDBOX_GROUP");
        let region = std::env::var("ACA_REGION").expect("ACA_REGION");
        let pat = std::env::var("ACA_SMOKE_PAT").expect("ACA_SMOKE_PAT");
        let tag = std::env::var("ACA_SMOKE_TAG").unwrap_or_else(|_| "run".to_string());

        let audience = "https://management.azuredevcompute.io";
        let token: Arc<dyn crate::aca::auth::TokenSource> =
            Arc::new(crate::aca::auth::EntraTokenSource::new(audience).expect("entra token source"));
        let http = fabro_http::http_client().expect("http client");

        let egress = AcaEgressPolicy {
            default_action:     "Deny".to_string(),
            rules:              vec![
                "github.com:Allow".to_string(),
                "*.github.com:Allow".to_string(),
            ],
            traffic_inspection: "Full".to_string(),
        };
        let config = AcaConfig {
            region:          region.clone(),
            resource_group:  rg.clone(),
            sandbox_group:   group.clone(),
            disk:            "ubuntu".to_string(),
            cpu:             Some("1000m".to_string()),
            memory:          Some("2048Mi".to_string()),
            working_dir:     "/workspace".to_string(),
            egress:          egress,
            region_override: false,
        };

        let provider = crate::provider::aca::AcaSandboxProvider::new(
            token.clone(),
            http.clone(),
            crate::provider::aca::AcaAccount {
                subscription:   sub.clone(),
                resource_group: rg.clone(),
                sandbox_group:  group.clone(),
                region:         region.clone(),
            },
        );

        // Create (validates the k8s resource-unit body + egress apply live).
        let info = <crate::provider::aca::AcaSandboxProvider as crate::SandboxProvider>::create(
            &provider,
            crate::SandboxCreateSpec::Aca {
                config:           Box::new(config.clone()),
                github_app:       None,
                run_id:           None,
                clone_origin_url: None,
                clone_branch:     None,
            },
        )
        .await
        .expect("create ACA sandbox");
        let sandbox_id = info.id.clone();
        eprintln!("[smoke] created sandbox {sandbox_id} (state {:?})", info.state);

        // Run the real flow; capture the result so teardown always runs.
        let outcome = async {
            let base = fabro_http::Url::parse(&format!(
                "https://management.{region}.azuredevcompute.io"
            ))
            .expect("region base url");
            let client = Arc::new(AcaClient::new(
                http.clone(),
                token.clone(),
                base,
                sub.clone(),
                rg.clone(),
                group.clone(),
            ));
            let sandbox =
                AcaSandbox::new(client, sandbox_id.clone(), config.clone(), None, None, None)
                    .expect("build AcaSandbox");

            // Readiness: BASH_PROBE gate.
            sandbox.initialize().await.expect("initialize (bash probe)");

            // Exec fidelity: separated streams + exit code.
            let r = sandbox
                .exec_command("echo out; echo err 1>&2; exit 7", 60_000, None, None, None)
                .await
                .expect("exec");
            assert!(r.stdout.contains("out"), "stdout: {}", r.stdout);
            assert!(r.stderr.contains("err"), "stderr: {}", r.stderr);
            assert_eq!(r.exit_code, Some(7), "exit code");

            // Authenticated clone + commit + push through the Deny/Full egress.
            // The PAT lives only in this runtime-built command string; it is
            // never asserted on or logged.
            let git = format!(
                "set -e; rm -rf /tmp/r; \
                 git clone https://x-access-token:{pat}@github.com/NocoreNL/aca-smoke-scratch /tmp/r; \
                 cd /tmp/r; echo \"smoke {tag}\" > smoke-{tag}.txt; \
                 git -c user.email=smoke@nocore.nl -c user.name=smoke add -A; \
                 git -c user.email=smoke@nocore.nl -c user.name=smoke commit -m \"smoke {tag}\"; \
                 git push origin HEAD:refs/heads/smoke-{tag}"
            );
            let g = sandbox
                .exec_command(&git, 180_000, None, None, None)
                .await
                .expect("git flow");
            assert!(g.is_success(), "git clone/push failed (exit {:?})", g.exit_code);

            // Lifecycle: suspend then resume.
            sandbox.stop().await.expect("stop/suspend");
            sandbox.start().await.expect("start/resume");
            Ok::<(), String>(())
        }
        .await;

        // Teardown (always).
        let _ = <crate::provider::aca::AcaSandboxProvider as crate::SandboxProvider>::delete(
            &provider,
            &sandbox_id,
        )
        .await;
        eprintln!("[smoke] deleted sandbox {sandbox_id}");
        outcome.expect("smoke flow");
    }
}
