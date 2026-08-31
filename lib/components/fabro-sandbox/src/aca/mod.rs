//! Azure Container Apps (ACA) Sandboxes provider.
#![allow(dead_code)] // scaffolding; removed as the module fills in

mod auth;
pub use auth::{EntraTokenSource, TokenSource};

mod client;
pub use client::{AcaClient, AcaApiError};

mod sandbox;
pub use sandbox::AcaSandbox;

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
