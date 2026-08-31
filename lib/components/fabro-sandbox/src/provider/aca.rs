// ACA: stub provider. Real sandbox lifecycle logic lands in Task 13.
use async_trait::async_trait;
use fabro_types::{SandboxInfo, SandboxProviderKind};

use crate::provider::{SandboxCreateSpec, SandboxProvider};

#[derive(Default)]
pub struct AcaSandboxProvider {}

impl AcaSandboxProvider {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl SandboxProvider for AcaSandboxProvider {
    fn kind(&self) -> SandboxProviderKind {
        SandboxProviderKind::Aca
    }

    async fn list(&self) -> crate::Result<Vec<SandboxInfo>> {
        Err(crate::Error::message("aca provider not yet implemented"))
    }

    async fn get(&self, _id: &str) -> crate::Result<Option<SandboxInfo>> {
        Err(crate::Error::message("aca provider not yet implemented"))
    }

    async fn create(&self, _spec: SandboxCreateSpec) -> crate::Result<SandboxInfo> {
        Err(crate::Error::message("aca provider not yet implemented"))
    }

    async fn delete(&self, _id: &str) -> crate::Result<()> {
        Err(crate::Error::message("aca provider not yet implemented"))
    }
}
