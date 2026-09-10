//! ACA: TokenSource seam — yields an Entra bearer token for the ACA data-plane
//! audience. Later ACA tasks (client, provider) depend on the trait only, so
//! their tests never touch Entra.

use std::sync::Arc;

use azure_core::credentials::TokenCredential;
use azure_identity::{DeveloperToolsCredential, ManagedIdentityCredential};

/// Yields a bearer token for the ACA data-plane audience.
///
/// Production code goes through [`EntraTokenSource`]; tests use a fake so
/// they never touch Entra.
#[async_trait::async_trait]
pub trait TokenSource: Send + Sync {
    /// A bearer token string for the ACA data-plane audience.
    async fn token(&self) -> crate::Result<String>;
}

/// Production [`TokenSource`] backed by `azure_identity`, selecting between
/// two credential chains via the `ACA_AUTH_MODE` env var:
///
/// - `ACA_AUTH_MODE=managed` — [`ManagedIdentityCredential`] (system-assigned,
///   via IMDS/App Service, no client id). Use this when the process itself
///   runs as an Azure-hosted workload (e.g. the Fabro server on an Azure VM)
///   and must authenticate to the ACA data plane as that VM's identity.
/// - anything else, including unset — [`DeveloperToolsCredential`] (Azure
///   CLI, then Azure Developer CLI), for local `az login` development.
///
/// `azure_identity` 1.x removed `DefaultAzureCredential` in favor of these
/// audience-specific credential types (see the crate's CHANGELOG: "Replaced
/// `DefaultAzureCredential` with `DeveloperToolsCredential`").
pub struct EntraTokenSource {
    credential: Arc<dyn TokenCredential>,
    audience:   String,
}

impl EntraTokenSource {
    /// Builds a token source for the given audience/scope string.
    ///
    /// The audience is caller-supplied rather than hardcoded here; Task 2's
    /// capture doc (`docs/aca-data-plane-api.md`) confirms the real value.
    pub fn new(audience: impl Into<String>) -> crate::Result<Self> {
        // ACA_AUTH_MODE=managed -> ManagedIdentityCredential (system-assigned via
        // IMDS/App Service, no client id). Anything else (incl. unset) keeps the
        // developer-tools credential for local `az login` dev.
        let mode = std::env::var("ACA_AUTH_MODE").unwrap_or_default();
        let credential: Arc<dyn TokenCredential> = if mode.eq_ignore_ascii_case("managed") {
            ManagedIdentityCredential::new(None).map_err(|e| {
                crate::Error::context("Failed to build Entra managed-identity credential", e)
            })?
        } else {
            DeveloperToolsCredential::new(None).map_err(|e| {
                crate::Error::context("Failed to build Entra developer-tools credential", e)
            })?
        };
        Ok(Self {
            credential,
            audience: audience.into(),
        })
    }
}

#[async_trait::async_trait]
impl TokenSource for EntraTokenSource {
    async fn token(&self) -> crate::Result<String> {
        // Azure AD v2 (`get_token`) takes an OAuth *scope*, not a bare
        // resource. For a resource audience the scope is `<resource>/.default`
        // (all of the resource's statically-consented permissions). Passing the
        // bare resource makes the CLI credential append `openid profile
        // offline_access`, which AAD rejects with AADSTS70011. Append
        // `/.default` unless the caller already supplied it.
        let scope = if self.audience.ends_with("/.default") {
            self.audience.clone()
        } else {
            format!("{}/.default", self.audience.trim_end_matches('/'))
        };
        let access_token = self
            .credential
            .get_token(&[scope.as_str()], None)
            .await
            .map_err(|e| {
                crate::Error::context("Failed to acquire Entra token for ACA audience", e)
            })?;
        Ok(access_token.token.secret().to_string())
    }
}

/// Test-only [`TokenSource`] that returns a fixed token string.
#[allow(
    unreachable_pub,
    reason = "intentionally not re-exported from aca::mod; reachable within \
              the crate for sibling aca::* test modules, not part of the \
              public API"
)]
pub struct FakeTokenSource(pub String);

#[async_trait::async_trait]
impl TokenSource for FakeTokenSource {
    async fn token(&self) -> crate::Result<String> {
        Ok(self.0.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn fake_token_source_returns_token() {
        let ts = FakeTokenSource("test-token".to_string());
        assert_eq!(ts.token().await.unwrap(), "test-token");
    }

    #[test]
    fn new_selects_credential_by_aca_auth_mode() {
        // developer mode (default) builds a source
        std::env::remove_var("ACA_AUTH_MODE");
        assert!(EntraTokenSource::new("https://management.azuredevcompute.io").is_ok());
        // managed mode builds a source too (IMDS is only hit on token(), not new())
        std::env::set_var("ACA_AUTH_MODE", "managed");
        assert!(EntraTokenSource::new("https://management.azuredevcompute.io").is_ok());
        std::env::remove_var("ACA_AUTH_MODE");
    }
}
