//! Convert resolved [`RunEnvironmentSettings`] into runtime sandbox configs.
//!
//! These mappings are consumed by both the workflow run-start path and the
//! server preflight path, so they live here next to their destination types.

use std::path::{Path, PathBuf};

#[cfg(feature = "docker")]
use fabro_types::settings::ResolveError;
#[cfg(feature = "daytona")]
use fabro_types::settings::run::DockerfileSource as ResolvedDockerfileSource;
// ACA: RunEnvironmentSettings is used unconditionally (aca_config_from_environment
// takes it too); EnvironmentNetworkMode/RunCloneSettings are only used by the
// docker/daytona mappers below.
#[cfg(any(feature = "docker", feature = "daytona"))]
use fabro_types::settings::run::{EnvironmentNetworkMode, RunCloneSettings};
use fabro_types::settings::run::RunEnvironmentSettings;

#[cfg(feature = "aca")]
use crate::aca::{AcaConfig, AcaEgressPolicy, validate_aca_region};
#[cfg(feature = "daytona")]
use crate::config::{
    DaytonaNetwork, DaytonaSnapshotSettings, DaytonaSnapshotSource,
    DockerfileSource as SandboxDockerfileSource,
};
#[cfg(feature = "daytona")]
use crate::daytona::DaytonaConfig;
#[cfg(feature = "docker")]
use crate::docker::DockerSandboxOptions;

// ACA: the sandbox provider's OS image when the environment doesn't set
// `[aca].disk`; mirrors the shipped default environment TOML.
#[cfg(feature = "aca")]
const DEFAULT_ACA_DISK: &str = "ubuntu";
// ACA: matches the working-directory convention used across the other
// sandbox providers (see `docker::WORKING_DIRECTORY`).
#[cfg(feature = "aca")]
const DEFAULT_ACA_WORKING_DIR: &str = "/workspace";
// ACA: the outbound traffic-inspection posture when `[aca.egress]` doesn't
// set one; "Full" is the ACA egress-lockdown baseline this spike settled on.
#[cfg(feature = "aca")]
const DEFAULT_ACA_TRAFFIC_INSPECTION: &str = "Full";

#[cfg(feature = "aca")]
#[must_use]
pub fn aca_config_from_environment(settings: &RunEnvironmentSettings) -> AcaConfig {
    let region = settings.aca.region.clone().unwrap_or_default();
    validate_aca_region(&region, settings.aca.region_override);

    AcaConfig {
        region,
        resource_group: settings.aca.resource_group.clone().unwrap_or_default(),
        sandbox_group: settings.aca.sandbox_group.clone().unwrap_or_default(),
        disk: settings
            .aca
            .disk
            .clone()
            .unwrap_or_else(|| DEFAULT_ACA_DISK.to_string()),
        cpu: settings.resources.cpu.map(aca_cpu_string),
        memory: settings
            .resources
            .memory
            .map(|size| aca_memory_string(size.as_bytes())),
        working_dir: settings
            .cwd
            .clone()
            .unwrap_or_else(|| DEFAULT_ACA_WORKING_DIR.to_string()),
        egress: AcaEgressPolicy {
            // ACA: sandboxes deny egress by default; the `[aca.egress].allow`
            // domain list (not the generic CIDR-based `network.allow`, which
            // ACA doesn't use) is the only way out.
            default_action:     "Deny".to_string(),
            rules:              settings.aca.egress.allow.clone(),
            traffic_inspection: settings
                .aca
                .egress
                .traffic_inspection
                .clone()
                .unwrap_or_else(|| DEFAULT_ACA_TRAFFIC_INSPECTION.to_string()),
        },
        region_override: settings.aca.region_override,
    }
}

// ACA: the data-plane create body's `resources.cpu` wants a Kubernetes-style
// millicpu string (e.g. "1000m"), per `docs/aca-data-plane-api.md`'s
// **create** section and `provider/aca.rs`'s `parse_millicpu`/
// `DEFAULT_ACA_CPU` — not the Azure CLI's `--cpu` flag units this used to
// emit ("2.0"), which the data-plane client's `CreateResources` rejects
// outright (its response parsers require the "m" suffix). `resources.cpu`
// is a whole core count today, so this multiplies out to millicpu with no
// fractional-core loss.
#[cfg(feature = "aca")]
fn aca_cpu_string(cpu: i32) -> String {
    let millicpu = i64::from(cpu) * 1000;
    format!("{millicpu}m")
}

// ACA: mirrors `aca_cpu_string`'s unit fix — the create body's
// `resources.memory` wants a Kubernetes-style mebibyte string (e.g.
// "2048Mi"), per the same capture doc and `provider/aca.rs`'s
// `parse_mebibytes`/`DEFAULT_ACA_MEMORY` — not the Azure CLI's `--memory`
// flag units this used to emit ("4Gi"). `resources.memory` is typically
// authored as a round decimal size (e.g. "4GB") or a binary size (e.g.
// "4GiB"), so this rounds to the nearest whole MiB rather than requiring an
// exact multiple (4_000_000_000 bytes ~= 3814.7 MiB, which rounds to
// "3815Mi" for what the operator wrote as "4GB"; an operator who instead
// writes "4GiB" gets an exact "4096Mi", matching the provider's own
// "2048Mi" (=2 GiB) default convention).
#[cfg(feature = "aca")]
fn aca_memory_string(bytes: u64) -> String {
    const MIB: f64 = (1024 * 1024) as f64;
    let mib = (bytes as f64 / MIB).round() as u64;
    format!("{mib}Mi")
}

#[cfg(feature = "daytona")]
#[must_use]
pub fn daytona_config_from_environment(
    settings: &RunEnvironmentSettings,
    clone: &RunCloneSettings,
) -> DaytonaConfig {
    // fabro-config rejects Daytona environments that set both image.docker
    // and image.dockerfile. If both still arrive here, the image wins, which
    // matches how the Docker provider treats the pair.
    let source = match (&settings.image.docker, &settings.image.dockerfile) {
        (Some(image), _) => Some(DaytonaSnapshotSource::Image(image.clone())),
        (None, Some(ResolvedDockerfileSource::Inline(text))) => Some(
            DaytonaSnapshotSource::Dockerfile(SandboxDockerfileSource::Inline(text.clone())),
        ),
        (None, Some(ResolvedDockerfileSource::Path { path })) => Some(
            DaytonaSnapshotSource::Dockerfile(SandboxDockerfileSource::Path { path: path.clone() }),
        ),
        (None, None) => None,
    };
    let snapshot = source.map(|source| DaytonaSnapshotSettings {
        cpu: settings.resources.cpu,
        memory: settings
            .resources
            .memory
            .map(|size| size_to_gb_i32(size.as_bytes())),
        disk: settings
            .resources
            .disk
            .map(|size| size_to_gb_i32(size.as_bytes())),
        source,
    });

    DaytonaConfig {
        auto_stop_interval: settings
            .lifecycle
            .auto_stop
            .map(|duration| duration_to_minutes_i32(duration.as_std())),
        labels: (!settings.labels.is_empty()).then(|| settings.labels.clone()),
        snapshot,
        network: Some(match settings.network.mode {
            EnvironmentNetworkMode::Block => DaytonaNetwork::Block,
            EnvironmentNetworkMode::AllowAll => DaytonaNetwork::AllowAll,
            EnvironmentNetworkMode::CidrAllowList => {
                DaytonaNetwork::AllowList(settings.network.allow.clone())
            }
        }),
        clone_depth: clone.depth_limit(),
        skip_clone: !clone.enabled,
    }
}

#[cfg(feature = "docker")]
#[must_use]
pub fn docker_config_from_environment(
    settings: &RunEnvironmentSettings,
    clone: &RunCloneSettings,
) -> DockerSandboxOptions {
    // No vault is available on this path (server preflight / manifest), so a
    // `{{ secrets.* }}` value keeps its source form. Nothing else is left to
    // resolve: `{{ vars.* }}` is substituted at run creation.
    #[expect(
        clippy::disallowed_methods,
        reason = "preflight has no vault, so an unresolved secret token is carried in source \
                  form; the real value is resolved by docker_config_from_environment_with_secrets"
    )]
    let env = settings
        .env
        .iter()
        .map(|(key, value)| (key.clone(), value.as_source()))
        .collect();
    docker_config_from_environment_env(settings, clone, env)
}

#[cfg(feature = "docker")]
pub fn docker_config_from_environment_with_secrets(
    settings: &RunEnvironmentSettings,
    clone: &RunCloneSettings,
    secrets_lookup: impl FnMut(&str) -> Option<String>,
) -> Result<DockerSandboxOptions, ResolveError> {
    let env = settings.resolve_env(secrets_lookup)?;
    Ok(docker_config_from_environment_env(settings, clone, env))
}

#[cfg(feature = "docker")]
fn docker_config_from_environment_env(
    settings: &RunEnvironmentSettings,
    clone: &RunCloneSettings,
    env: std::collections::HashMap<String, String>,
) -> DockerSandboxOptions {
    let mut env_vars = env
        .into_iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>();
    env_vars.sort();
    let default_options = DockerSandboxOptions::default();

    DockerSandboxOptions {
        image: settings
            .image
            .docker
            .clone()
            .unwrap_or(default_options.image),
        network_mode: match settings.network.mode {
            EnvironmentNetworkMode::Block => Some("none".to_string()),
            EnvironmentNetworkMode::AllowAll | EnvironmentNetworkMode::CidrAllowList => {
                default_options.network_mode
            }
        },
        memory_limit: settings
            .resources
            .memory
            .and_then(|size| i64::try_from(size.as_bytes()).ok()),
        cpu_quota: settings
            .resources
            .cpu
            .map(|cpu| i64::from(cpu).saturating_mul(100_000)),
        env_vars,
        clone_depth: clone
            .depth_limit()
            .and_then(|depth| usize::try_from(depth).ok()),
        skip_clone: !clone.enabled,
        ..DockerSandboxOptions::default()
    }
}

pub fn local_working_directory_from_environment(
    settings: &RunEnvironmentSettings,
    source_directory: Option<&Path>,
) -> crate::Result<PathBuf> {
    if let Some(cwd) = settings.cwd.as_deref() {
        return Ok(PathBuf::from(cwd));
    }

    let Some(source_directory) = source_directory else {
        return Err(crate::Error::message(
            "local environment requires a server-side working directory; configure `environment.cwd = \"/absolute/path\"` on the selected local environment",
        ));
    };

    if source_directory.is_dir() {
        return Ok(source_directory.to_path_buf());
    }

    Err(crate::Error::message(format!(
        "local environment source_directory does not exist or is not a directory on this server: {}. Configure `environment.cwd = \"/absolute/path\"` on the selected local environment for remote client/server deployments.",
        source_directory.display()
    )))
}

#[cfg(feature = "daytona")]
fn duration_to_minutes_i32(duration: std::time::Duration) -> i32 {
    let minutes = duration.as_secs() / 60;
    i32::try_from(minutes).unwrap_or(i32::MAX)
}

#[cfg(feature = "daytona")]
fn size_to_gb_i32(bytes: u64) -> i32 {
    let gb = bytes / 1_000_000_000;
    i32::try_from(gb).unwrap_or(i32::MAX)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::path::{Path, PathBuf};

    use fabro_types::settings::run::{
        EnvironmentImageSettings, EnvironmentLifecycleSettings, EnvironmentNetworkSettings,
        EnvironmentProvider, EnvironmentResourcesSettings,
    };

    use super::*;

    fn run_environment(provider: EnvironmentProvider) -> RunEnvironmentSettings {
        RunEnvironmentSettings {
            id: "host".to_string(),
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

    #[test]
    fn local_working_directory_prefers_environment_cwd() {
        let mut settings = run_environment(EnvironmentProvider::Local);
        settings.cwd = Some("/srv/fabro/workspaces/team-a".to_string());
        let missing_source = Path::new("/path/that/should/not/exist");

        let resolved = local_working_directory_from_environment(&settings, Some(missing_source))
            .expect("configured cwd should be accepted");

        assert_eq!(resolved, PathBuf::from("/srv/fabro/workspaces/team-a"));
        assert!(!missing_source.exists());
    }

    #[test]
    fn local_working_directory_uses_existing_source_directory_without_cwd() {
        let settings = run_environment(EnvironmentProvider::Local);
        let dir = tempfile::tempdir().unwrap();

        let resolved = local_working_directory_from_environment(&settings, Some(dir.path()))
            .expect("existing source directory should be accepted");

        assert_eq!(resolved, dir.path());
    }

    #[test]
    fn local_working_directory_rejects_missing_source_directory_without_cwd() {
        let settings = run_environment(EnvironmentProvider::Local);
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("client-only");

        let err = local_working_directory_from_environment(&settings, Some(&missing))
            .expect_err("missing source directory without cwd should fail");

        let message = err.to_string();
        assert!(
            message.contains("environment.cwd") && message.contains("does not exist"),
            "unexpected error: {message}"
        );
        assert!(!missing.exists());
    }

    #[cfg(feature = "daytona")]
    #[test]
    fn daytona_config_maps_docker_image_to_snapshot() {
        let mut settings = run_environment(EnvironmentProvider::Daytona);
        settings.image.docker = Some("ubuntu:24.04".to_string());
        settings.resources.cpu = Some(2);

        let config = daytona_config_from_environment(&settings, &RunCloneSettings::default());
        let snapshot = config.snapshot.expect("image should configure a snapshot");

        assert_eq!(
            snapshot.source,
            DaytonaSnapshotSource::Image("ubuntu:24.04".to_string())
        );
        assert_eq!(snapshot.cpu, Some(2));
    }

    #[cfg(feature = "aca")]
    #[test]
    fn aca_config_maps_region_resources_and_egress() {
        use fabro_types::settings::run::{AcaEgressSettings, AcaEnvironmentSettings};

        let mut settings = run_environment(EnvironmentProvider::Aca);
        settings.resources.cpu = Some(2);
        settings.resources.memory = Some(fabro_types::settings::Size::from_gigabytes(4));
        settings.aca = AcaEnvironmentSettings {
            region:          Some("northeurope".to_string()),
            resource_group:  Some("rg-fabro-sandboxes".to_string()),
            sandbox_group:   Some("sbg-fabro".to_string()),
            disk:            Some("ubuntu".to_string()),
            region_override: false,
            egress:          AcaEgressSettings {
                allow:              vec!["*.github.com".to_string(), "api.anthropic.com".to_string()],
                traffic_inspection: Some("Full".to_string()),
            },
            auto_suspend:    None,
        };

        let config = aca_config_from_environment(&settings);

        assert_eq!(config.region, "northeurope");
        assert_eq!(config.resource_group, "rg-fabro-sandboxes");
        assert_eq!(config.sandbox_group, "sbg-fabro");
        assert_eq!(config.disk, "ubuntu");
        // ACA: k8s units, not CLI-flag units — 2 cores -> "2000m"; 4GB
        // (decimal, 4_000_000_000 bytes) -> 3814.697.. MiB, rounded to
        // "3815Mi" (see `aca_memory_string`'s doc comment).
        assert_eq!(config.cpu.as_deref(), Some("2000m"));
        assert_eq!(config.memory.as_deref(), Some("3815Mi"));
        assert_eq!(
            config.egress.rules,
            vec!["*.github.com".to_string(), "api.anthropic.com".to_string()]
        );
        assert_eq!(config.egress.traffic_inspection, "Full");
        assert_eq!(config.egress.default_action, "Deny");
        assert!(!config.region_override);
    }

    // ACA: boundary/round-trip test pinning the seam the per-task reviews
    // missed — `provider/aca.rs`'s `CreateResources` (the data-plane create
    // body) serializes `AcaConfig.cpu`/`.memory` verbatim, and its response
    // parsers `parse_millicpu`/`parse_mebibytes` strictly require the "m"/
    // "Mi" suffixes asserted below. Those parsers are private to
    // `provider::aca` (not reachable from this module), so this mirrors
    // their exact parsing logic rather than calling them directly, and also
    // checks the mapping is exact (no rounding drift) at binary-unit inputs
    // that match the provider's own defaults' convention
    // (`DEFAULT_ACA_CPU` = "1000m", `DEFAULT_ACA_MEMORY` = "2048Mi" = 2 GiB).
    #[cfg(feature = "aca")]
    #[test]
    fn aca_config_resources_are_k8s_units_that_round_trip_through_provider_parsers() {
        let mut settings = run_environment(EnvironmentProvider::Aca);
        settings.resources.cpu = Some(2);
        settings.resources.memory = Some("4GiB".parse().expect("4GiB should parse as a Size"));

        let config = aca_config_from_environment(&settings);

        let cpu = config.cpu.expect("cpu should be set");
        let memory = config.memory.expect("memory should be set");

        // Exact values at a clean binary-unit input.
        assert_eq!(cpu, "2000m");
        assert_eq!(memory, "4096Mi");

        // Round-trip: mirrors `provider/aca.rs`'s `parse_millicpu`.
        let millicpu: f64 = cpu
            .strip_suffix('m')
            .expect("cpu string should have the 'm' suffix parse_millicpu requires")
            .parse()
            .expect("millicpu portion should be numeric");
        assert_eq!(millicpu / 1000.0, 2.0);

        // Round-trip: mirrors `provider/aca.rs`'s `parse_mebibytes`.
        let mebibytes: u64 = memory
            .strip_suffix("Mi")
            .expect("memory string should have the 'Mi' suffix parse_mebibytes requires")
            .parse()
            .expect("mebibyte portion should be numeric");
        assert_eq!(mebibytes * 1024 * 1024, 4 * 1024 * 1024 * 1024);
    }

    #[cfg(feature = "aca")]
    #[test]
    fn aca_config_defaults_disk_and_working_dir_when_unset() {
        let settings = run_environment(EnvironmentProvider::Aca);

        let config = aca_config_from_environment(&settings);

        assert_eq!(config.disk, "ubuntu");
        assert_eq!(config.working_dir, "/workspace");
        assert_eq!(config.egress.traffic_inspection, "Full");
    }

    #[cfg(feature = "aca")]
    #[test]
    fn aca_config_accepts_unknown_region_without_erroring() {
        use fabro_types::settings::run::AcaEnvironmentSettings;

        let mut settings = run_environment(EnvironmentProvider::Aca);
        settings.aca = AcaEnvironmentSettings {
            region: Some("not-a-real-region".to_string()),
            ..AcaEnvironmentSettings::default()
        };

        // Warn-don't-fail: an unrecognized region is accepted verbatim, not
        // rejected or silently replaced.
        let config = aca_config_from_environment(&settings);

        assert_eq!(config.region, "not-a-real-region");
    }

    #[cfg(feature = "aca")]
    #[test]
    fn aca_config_honors_region_override() {
        use fabro_types::settings::run::AcaEnvironmentSettings;

        let mut settings = run_environment(EnvironmentProvider::Aca);
        settings.aca = AcaEnvironmentSettings {
            region:          Some("not-a-real-region".to_string()),
            region_override: true,
            ..AcaEnvironmentSettings::default()
        };

        let config = aca_config_from_environment(&settings);

        assert_eq!(config.region, "not-a-real-region");
        assert!(config.region_override);
    }

    #[cfg(feature = "aca")]
    #[test]
    fn aca_region_helpers_classify_known_and_unknown_regions() {
        assert!(crate::aca::is_known_aca_region("northeurope"));
        assert!(crate::aca::is_known_aca_region("WESTUS2"));
        assert!(!crate::aca::is_known_aca_region("not-a-real-region"));

        // Neither call panics or otherwise errors; the check is advisory.
        crate::aca::validate_aca_region("not-a-real-region", false);
        crate::aca::validate_aca_region("not-a-real-region", true);
    }
}
