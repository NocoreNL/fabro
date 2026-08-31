use std::path::PathBuf;
use std::sync::Arc;

#[cfg(feature = "docker")]
use anyhow::Context as _;
#[cfg(any(feature = "docker", feature = "daytona", feature = "aca"))]
use fabro_github::GitHubCredentials;
#[allow(
    unused_imports,
    reason = "Daytona-enabled builds persist RunId in the sandbox spec."
)]
use fabro_types::{RunId, RunSandboxInstance, RunSandboxRuntime, SandboxProviderKind};

// ACA:
#[cfg(feature = "aca")]
use crate::aca::{AcaConfig, AcaSandbox, EntraTokenSource, ACA_TOKEN_AUDIENCE};
#[cfg(any(feature = "docker", feature = "daytona"))]
use crate::clone_source;
#[cfg(feature = "daytona")]
use crate::daytona::{self, DaytonaConfig, DaytonaSandbox};
#[cfg(feature = "docker")]
use crate::docker::{self, DockerSandbox, DockerSandboxOptions};
use crate::local::LocalSandbox;
// ACA:
#[cfg(feature = "aca")]
use crate::provider::aca::{AcaSandboxProvider, aca_account_from_process_env};
#[cfg(feature = "aca")]
use crate::provider::{SandboxCreateSpec, SandboxProvider};
use crate::{Sandbox, SandboxEventCallback};

/// Options for sandbox initialization and construction.
pub enum SandboxSpec {
    Local {
        working_directory: PathBuf,
    },
    #[cfg(feature = "docker")]
    Docker {
        config:           DockerSandboxOptions,
        github_app:       Option<GitHubCredentials>,
        run_id:           Option<RunId>,
        clone_origin_url: Option<String>,
        clone_branch:     Option<String>,
        clone_tag:        Option<String>,
        clone_commit_sha: Option<String>,
    },
    #[cfg(feature = "daytona")]
    Daytona {
        config:           Box<DaytonaConfig>,
        github_app:       Option<GitHubCredentials>,
        run_id:           Option<RunId>,
        clone_origin_url: Option<String>,
        clone_branch:     Option<String>,
        clone_tag:        Option<String>,
        clone_commit_sha: Option<String>,
        api_key:          Option<String>,
    },
    // ACA: mirrors `SandboxCreateSpec::Aca`'s field shape (no `api_key` — ACA
    // authenticates via `azure_identity`, not a bearer token) rather than
    // `Daytona`'s: `AcaConfig` has no `skip_clone`, and no `AcaSandbox` field
    // stores clone metadata (its disk image already has a repo baked in;
    // there is no per-create clone step to pin a tag/commit against), so
    // `clone_tag`/`clone_commit_sha` would have nothing to do here. Callers
    // reject a pinned-revision request for this provider before constructing
    // this variant (see `start.rs`'s `RunSession::new`).
    #[cfg(feature = "aca")]
    Aca {
        config:           Box<AcaConfig>,
        github_app:       Option<GitHubCredentials>,
        run_id:           Option<RunId>,
        clone_origin_url: Option<String>,
        clone_branch:     Option<String>,
    },
}

impl SandboxSpec {
    pub fn provider(&self) -> SandboxProviderKind {
        match self {
            Self::Local { .. } => SandboxProviderKind::Local,
            #[cfg(feature = "docker")]
            Self::Docker { .. } => SandboxProviderKind::Docker,
            #[cfg(feature = "daytona")]
            Self::Daytona { .. } => SandboxProviderKind::Daytona,
            // ACA:
            #[cfg(feature = "aca")]
            Self::Aca { .. } => SandboxProviderKind::Aca,
        }
    }

    pub fn provider_name(&self) -> &'static str {
        match self.provider() {
            SandboxProviderKind::Local => "local",
            SandboxProviderKind::Docker => "docker",
            SandboxProviderKind::Daytona => "daytona",
            // ACA:
            SandboxProviderKind::Aca => "aca",
        }
    }

    /// Build initialized sandbox metadata for persistence.
    pub fn to_run_sandbox_instance(
        &self,
        sandbox: &dyn Sandbox,
        run_id: RunId,
    ) -> RunSandboxInstance {
        let working_directory = sandbox.working_directory().to_string();
        let id = {
            let info = sandbox.sandbox_info();
            if info.is_empty() {
                format!("local:{run_id}")
            } else {
                info
            }
        };

        match self {
            #[cfg(feature = "docker")]
            Self::Docker {
                config,
                clone_origin_url,
                clone_branch,
                ..
            } => {
                let repo_cloned = clone_source::repo_cloned_for_record(
                    config.skip_clone,
                    clone_origin_url.as_deref(),
                );
                let layout = runtime_layout_metadata(
                    repo_cloned,
                    clone_origin_url.as_deref(),
                    docker::WORKING_DIRECTORY,
                    docker::REPOS_ROOT,
                );
                RunSandboxInstance {
                    provider: self.provider(),
                    image:    (!config.image.is_empty()).then(|| config.image.clone()),
                    snapshot: None,
                    runtime:  RunSandboxRuntime {
                        id,
                        working_directory: working_directory.clone(),
                        repo_cloned,
                        clone_origin_url: clone_source::clean_clone_origin_for_record(
                            clone_origin_url.as_deref(),
                        ),
                        clone_branch: clone_branch.clone(),
                        workspace_root: Some(docker::WORKING_DIRECTORY.to_string()),
                        repos_root: Some(docker::REPOS_ROOT.to_string()),
                        primary_repo_path: layout
                            .as_ref()
                            .map(|layout| layout.primary_repo_path.clone()),
                        primary_repo_link: layout
                            .as_ref()
                            .map(|layout| layout.primary_repo_link.clone()),
                    },
                }
            }
            #[cfg(feature = "daytona")]
            Self::Daytona {
                config,
                clone_origin_url,
                clone_branch,
                ..
            } => {
                let repo_cloned = clone_source::repo_cloned_for_record(
                    config.skip_clone,
                    clone_origin_url.as_deref(),
                );
                let layout = runtime_layout_metadata(
                    repo_cloned,
                    clone_origin_url.as_deref(),
                    daytona::WORKING_DIRECTORY,
                    daytona::REPOS_ROOT,
                );
                RunSandboxInstance {
                    provider: self.provider(),
                    image:    None,
                    snapshot: sandbox.snapshot_info(),
                    runtime:  RunSandboxRuntime {
                        id,
                        working_directory: working_directory.clone(),
                        repo_cloned,
                        clone_origin_url: clone_source::clean_clone_origin_for_record(
                            clone_origin_url.as_deref(),
                        ),
                        clone_branch: clone_branch.clone(),
                        workspace_root: Some(daytona::WORKING_DIRECTORY.to_string()),
                        repos_root: Some(daytona::REPOS_ROOT.to_string()),
                        primary_repo_path: layout
                            .as_ref()
                            .map(|layout| layout.primary_repo_path.clone()),
                        primary_repo_link: layout
                            .as_ref()
                            .map(|layout| layout.primary_repo_link.clone()),
                    },
                }
            }
            _ => RunSandboxInstance {
                provider: self.provider(),
                image:    None,
                snapshot: None,
                runtime:  RunSandboxRuntime {
                    id,
                    working_directory,
                    repo_cloned: None,
                    clone_origin_url: None,
                    clone_branch: None,
                    workspace_root: None,
                    repos_root: None,
                    primary_repo_path: None,
                    primary_repo_link: None,
                },
            },
        }
    }

    #[allow(
        clippy::unused_async,
        reason = "Only Daytona and Aca construction await; local and Docker builds share the \
                  async API."
    )]
    pub async fn build(
        &self,
        event_callback: Option<SandboxEventCallback>,
    ) -> Result<Arc<dyn Sandbox>, anyhow::Error> {
        match self {
            Self::Local { working_directory } => {
                let mut sandbox = LocalSandbox::new(working_directory.clone());
                if let Some(callback) = event_callback {
                    sandbox.set_event_callback(callback);
                }
                Ok(Arc::new(sandbox))
            }
            #[cfg(feature = "docker")]
            Self::Docker {
                config,
                github_app,
                run_id,
                clone_origin_url,
                clone_branch,
                clone_tag,
                clone_commit_sha,
            } => {
                let mut sandbox = DockerSandbox::new(
                    config.clone(),
                    github_app.as_ref(),
                    *run_id,
                    clone_origin_url.clone(),
                    clone_branch.clone(),
                    clone_tag.clone(),
                    clone_commit_sha.clone(),
                )
                .context("Failed to create Docker sandbox")?;
                if let Some(callback) = event_callback {
                    sandbox.set_event_callback(callback);
                }
                Ok(Arc::new(sandbox))
            }
            #[cfg(feature = "daytona")]
            Self::Daytona {
                config,
                github_app,
                run_id,
                clone_origin_url,
                clone_branch,
                clone_tag,
                clone_commit_sha,
                api_key,
            } => {
                let mut sandbox = DaytonaSandbox::new(
                    config.as_ref().clone(),
                    github_app.clone(),
                    *run_id,
                    clone_origin_url.clone(),
                    clone_branch.clone(),
                    clone_tag.clone(),
                    clone_commit_sha.clone(),
                    api_key.clone(),
                )
                .await
                .map_err(anyhow::Error::new)?;
                if let Some(callback) = event_callback {
                    sandbox.set_event_callback(callback);
                }
                Ok(Arc::new(sandbox))
            }
            // ACA: unlike Daytona's lazy `OnceCell`-backed sandbox (created on
            // first use), an `AcaSandbox` is a live handle over an
            // *already-provisioned* sandbox id (see its doc comment in
            // `aca/sandbox.rs`) — so the real sandbox must be created here,
            // eagerly, before `AcaSandbox::new` can be built at all. Rather
            // than re-implementing `AcaSandboxProvider::create`'s
            // create-then-egress-then-cleanup-on-failure dance, this builds a
            // standalone provider (env-resolved account + Entra credential,
            // mirroring Daytona's own env-resolved API key fallback just
            // above) and calls into it, so every `provider="aca"` run reaches
            // the exact same `AcaSandboxProvider::create` the managed-sandbox
            // registry uses. `event_callback` is unused: `AcaSandbox` has no
            // `set_event_callback` (ACA's exec transport is synchronous/
            // buffered only, per `aca/sandbox.rs`'s streaming note; there is
            // no event stream to attach a callback to).
            #[cfg(feature = "aca")]
            Self::Aca {
                config,
                github_app,
                run_id,
                clone_origin_url,
                clone_branch,
            } => {
                let account = aca_account_from_process_env().ok_or_else(|| {
                    anyhow::anyhow!(
                        "ACA sandbox provider requires ACA_SUBSCRIPTION_ID, ACA_RESOURCE_GROUP, \
                         ACA_SANDBOX_GROUP, and ACA_REGION to be set"
                    )
                })?;
                let http = fabro_http::http_client().map_err(anyhow::Error::new)?;
                let token_source =
                    EntraTokenSource::new(ACA_TOKEN_AUDIENCE).map_err(anyhow::Error::new)?;
                let provider = AcaSandboxProvider::new(Arc::new(token_source), http, account.clone());

                let create_spec = SandboxCreateSpec::Aca {
                    config:           config.clone(),
                    github_app:       github_app.clone(),
                    run_id:           *run_id,
                    clone_origin_url: clone_origin_url.clone(),
                    clone_branch:     clone_branch.clone(),
                };
                let info = provider
                    .create(create_spec)
                    .await
                    .map_err(anyhow::Error::new)?;

                // The same config-wins/account-falls-back scoping
                // `AcaSandboxProvider::create` just applied internally;
                // `SandboxInfo` doesn't carry resource_group/sandbox_group
                // back out, so this is re-derived rather than reused.
                let region = if config.region.is_empty() {
                    account.region.as_str()
                } else {
                    config.region.as_str()
                };
                let resource_group = if config.resource_group.is_empty() {
                    account.resource_group.as_str()
                } else {
                    config.resource_group.as_str()
                };
                let sandbox_group = if config.sandbox_group.is_empty() {
                    account.sandbox_group.as_str()
                } else {
                    config.sandbox_group.as_str()
                };
                let client = provider
                    .client_for(region, resource_group, sandbox_group)
                    .map_err(anyhow::Error::new)?;

                let sandbox = AcaSandbox::new(Arc::new(client), info.id, config.as_ref().clone());
                Ok(Arc::new(sandbox))
            }
        }
    }
}

#[cfg(any(feature = "docker", feature = "daytona"))]
fn runtime_layout_metadata(
    repo_cloned: Option<bool>,
    clone_origin_url: Option<&str>,
    workspace_root: &str,
    repos_root: &str,
) -> Option<clone_source::GitHubRepoLayout> {
    if repo_cloned != Some(true) {
        return None;
    }
    clone_source::github_repo_layout(clone_origin_url?, workspace_root, repos_root).ok()
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "docker")]
    use fabro_types::RunId;

    #[cfg(feature = "docker")]
    use super::*;
    #[cfg(feature = "docker")]
    use crate::test_support::MockSandbox;

    #[cfg(feature = "docker")]
    #[test]
    fn docker_run_sandbox_persists_layout_metadata_for_cloned_repo() {
        let spec = SandboxSpec::Docker {
            config:           DockerSandboxOptions::default(),
            github_app:       None,
            run_id:           None,
            clone_origin_url: Some("git@github.com:brynary/rack-test.git".to_string()),
            clone_branch:     Some("main".to_string()),
            clone_tag:        None,
            clone_commit_sha: None,
        };
        let mut sandbox = MockSandbox::linux();
        sandbox.working_dir = "/workspace/rack-test";

        let run_id: RunId = "01HY0000000000000000000000".parse().unwrap();
        let record = spec.to_run_sandbox_instance(&sandbox, run_id);
        let runtime = record.runtime;

        assert_eq!(runtime.working_directory, "/workspace/rack-test");
        assert_eq!(runtime.repo_cloned, Some(true));
        assert_eq!(
            runtime.clone_origin_url.as_deref(),
            Some("https://github.com/brynary/rack-test")
        );
        assert_eq!(runtime.workspace_root.as_deref(), Some("/workspace"));
        assert_eq!(runtime.repos_root.as_deref(), Some("/repos"));
        assert_eq!(
            runtime.primary_repo_path.as_deref(),
            Some("/repos/brynary/rack-test")
        );
        assert_eq!(
            runtime.primary_repo_link.as_deref(),
            Some("/workspace/rack-test")
        );
        let runtime_json = serde_json::to_value(&runtime).expect("runtime should serialize");
        assert!(runtime_json.get("clone_commit_sha").is_none());
    }

    #[cfg(feature = "docker")]
    #[tokio::test]
    async fn invalid_exact_checkout_spec_fails_before_provider_connection() {
        let spec = SandboxSpec::Docker {
            config:           DockerSandboxOptions::default(),
            github_app:       None,
            run_id:           None,
            clone_origin_url: Some("https://github.com/acme/widgets".to_string()),
            clone_branch:     Some("main".to_string()),
            clone_tag:        None,
            clone_commit_sha: Some("not-a-sha".to_string()),
        };

        let error = spec
            .build(None)
            .await
            .err()
            .expect("spec validation should run before Docker connection");
        assert!(
            error
                .to_string()
                .contains("Failed to create Docker sandbox")
        );
        assert!(format!("{error:#}").contains("40 ASCII hexadecimal"));
        assert!(!format!("{error:#}").contains("Docker daemon"));
    }

    #[cfg(feature = "docker")]
    #[test]
    fn docker_run_sandbox_omits_primary_repo_metadata_for_empty_workspace() {
        let spec = SandboxSpec::Docker {
            config:           DockerSandboxOptions {
                skip_clone: true,
                ..DockerSandboxOptions::default()
            },
            github_app:       None,
            run_id:           None,
            clone_origin_url: Some("https://gitlab.com/acme/widgets".to_string()),
            clone_branch:     None,
            clone_tag:        None,
            clone_commit_sha: None,
        };
        let mut sandbox = MockSandbox::linux();
        sandbox.working_dir = "/workspace";

        let run_id: RunId = "01HY0000000000000000000000".parse().unwrap();
        let record = spec.to_run_sandbox_instance(&sandbox, run_id);
        let runtime = record.runtime;

        assert_eq!(runtime.working_directory, "/workspace");
        assert_eq!(runtime.repo_cloned, Some(false));
        assert_eq!(runtime.workspace_root.as_deref(), Some("/workspace"));
        assert_eq!(runtime.repos_root.as_deref(), Some("/repos"));
        assert!(runtime.primary_repo_path.is_none());
        assert!(runtime.primary_repo_link.is_none());
    }
}
