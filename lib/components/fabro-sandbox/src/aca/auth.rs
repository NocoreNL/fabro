//! ACA: TokenSource seam — yields an Entra bearer token for the ACA data-plane
//! audience. Later ACA tasks (client, provider) depend on the trait only, so
//! their tests never touch Entra.

use std::sync::Arc;

use azure_core::credentials::TokenCredential;
use azure_identity::DeveloperToolsCredential;

/// Yields a bearer token for the ACA data-plane audience.
///
/// Production code goes through [`EntraTokenSource`]; tests use a fake so
/// they never touch Entra.
#[async_trait::async_trait]
pub trait TokenSource: Send + Sync {
    /// A bearer token string for the ACA data-plane audience.
    async fn token(&self) -> crate::Result<String>;
}

/// Production [`TokenSource`] backed by `azure_identity`'s developer-tools
/// credential chain (Azure CLI, then Azure Developer CLI).
///
/// `azure_identity` 1.x removed `DefaultAzureCredential` in favor of
/// audience-specific credential types (see the crate's CHANGELOG: "Replaced
/// `DefaultAzureCredential` with `DeveloperToolsCredential`"). This picks
/// `DeveloperToolsCredential` as the closest equivalent available today.
/// It does not include `ManagedIdentityCredential`, so it won't authenticate
/// when this process itself runs as an Azure-hosted workload — revisit once
/// the deployment model for the ACA data-plane client is settled.
pub struct EntraTokenSource {
    credential: Arc<DeveloperToolsCredential>,
    audience:   String,
}

impl EntraTokenSource {
    /// Builds a token source for the given audience/scope string.
    ///
    /// The audience is caller-supplied rather than hardcoded here; Task 2's
    /// capture doc (`docs/aca-data-plane-api.md`) confirms the real value.
    pub fn new(audience: impl Into<String>) -> crate::Result<Self> {
        let credential = DeveloperToolsCredential::new(None).map_err(|e| {
            crate::Error::context("Failed to build Entra developer-tools credential", e)
        })?;
        Ok(Self {
            credential,
            audience: audience.into(),
        })
    }
}

#[async_trait::async_trait]
impl TokenSource for EntraTokenSource {
    async fn token(&self) -> crate::Result<String> {
        let access_token = self
            .credential
            .get_token(&[self.audience.as_str()], None)
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
}
