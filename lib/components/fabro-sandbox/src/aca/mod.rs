//! Azure Container Apps (ACA) Sandboxes provider.
#![allow(dead_code)] // scaffolding; removed as the module fills in

mod auth;
pub use auth::{EntraTokenSource, TokenSource};
// ACA: `FakeTokenSource` is test-only (see its doc comment in `auth.rs`),
// but Task 13's provider tests (`provider/aca.rs`) build an `AcaClient`
// through `AcaSandboxProvider` from outside `crate::aca`, so it needs to be
// reachable crate-wide in test builds, not just from sibling `aca::*` test
// modules.
#[cfg(test)]
pub(crate) use auth::FakeTokenSource;

mod client;
pub use client::{AcaClient, AcaApiError};
// ACA: Task 13's provider builds `CreateSandboxRequest` literals and maps
// `SandboxResource`/`SandboxState` responses to `fabro_types::SandboxInfo`
// directly (see `provider/aca.rs`), so those client-internal shapes need to
// be nameable outside `crate::aca` too, not just `AcaClient` itself.
pub use client::{
    AutoSuspendPolicy, CreateDiskImage, CreateResources, CreateSandboxRequest, CreateSourcesRef,
    Lifecycle, SandboxResource, SandboxState,
};

mod sandbox;
pub use sandbox::AcaSandbox;

// ACA: fixed data-plane token audience (Task 2's capture doc), distinct from
// the region-specific data-plane host `AcaClient` talks to. Shared (not
// duplicated) between `SandboxSpec::Aca::build` (`sandbox_spec.rs`, the
// run-dispatch path) and `fabro-server`'s `build_sandbox_provider_registry`
// (the managed-sandboxes registry path), which both need to build an
// `EntraTokenSource` for the exact same audience.
pub const ACA_TOKEN_AUDIENCE: &str = "https://management.azuredevcompute.io";

// ACA: creation params for an ACA sandbox. Mirrors `DaytonaConfig`'s role;
// `AcaSandbox::new` builds the live handle from these (see `sandbox.rs`).
#[derive(Clone, Debug)]
pub struct AcaConfig {
    pub region:          String,
    pub resource_group:  String,
    pub sandbox_group:   String,
    pub disk:            String,
    pub cpu:             Option<String>,
    pub memory:          Option<String>,
    pub working_dir:     String,
    pub egress:          AcaEgressPolicy,
    pub region_override: bool,
}

// ACA: network egress policy for an ACA sandbox's container app environment.
#[derive(Clone, Debug, Default)]
pub struct AcaEgressPolicy {
    pub default_action:     String,
    pub rules:              Vec<String>,
    pub traffic_inspection: String,
}

// ACA: Container Apps data-plane region list, from the `aca` CLI's
// supported-region warning observed during the SP4 spike (see
// `.superpowers/sdd/2026-08-28-sp4-aca-provider/` spike notes) — NOT the
// full ARM `az account list-locations` list, which includes regions with no
// ACA Sandboxes data-plane support. Azure adds regions over time, so this
// list needs periodic refresh; a miss here only produces a warning (see
// [`validate_aca_region`]), it never blocks sandbox creation.
pub const ACA_DATA_PLANE_REGIONS: &[&str] = &[
    "australiaeast",
    "brazilsouth",
    "canadacentral",
    "centralus",
    "eastasia",
    "eastus2",
    "francecentral",
    "japaneast",
    "koreacentral",
    "mexicocentral",
    "northcentralus",
    "northeurope",
    "norwayeast",
    "polandcentral",
    "southafricanorth",
    "southeastasia",
    "southindia",
    "spaincentral",
    "swedencentral",
    "switzerlandnorth",
    "uksouth",
    "westcentralus",
    "westus",
    "westus2",
    "westus3",
];

/// True when `region` (case-insensitive) appears in
/// [`ACA_DATA_PLANE_REGIONS`].
#[must_use]
pub fn is_known_aca_region(region: &str) -> bool {
    ACA_DATA_PLANE_REGIONS
        .iter()
        .any(|known| known.eq_ignore_ascii_case(region))
}

/// Warn-don't-fail region check: logs a warning when `region` is outside
/// [`ACA_DATA_PLANE_REGIONS`] and `region_override` is not set. Never
/// blocks — callers always proceed with `region` as configured.
pub fn validate_aca_region(region: &str, region_override: bool) {
    if region_override || is_known_aca_region(region) {
        return;
    }
    tracing::warn!(
        region,
        "configured ACA region is not in the known data-plane region list; proceeding anyway \
         (set region_override to silence this warning)"
    );
}
