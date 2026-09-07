//! Sandbox configuration runtime types.
//!
//! These types are the runtime shape that the sandbox providers consume.
//!
//! The `DaytonaSettings`/`DaytonaSnapshotSettings` names are kept for
//! backward compatibility with the old import path; [`crate::daytona`]
//! continues to re-export them under `DaytonaConfig`/`DaytonaSnapshotConfig`
//! aliases.

use std::collections::HashMap;

use serde::de::{self, MapAccess, Visitor};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
pub struct DaytonaSettings {
    pub auto_stop_interval: Option<i32>,
    pub labels:             Option<HashMap<String, String>>,
    pub snapshot:           Option<DaytonaSnapshotSettings>,
    pub network:            Option<DaytonaNetwork>,
    /// Git history depth for the repository clone; `None` clones full
    /// history.
    pub clone_depth:        Option<i32>,
    #[serde(default)]
    pub skip_clone:         bool,
}

#[derive(Clone, Debug, PartialEq)]
pub enum DaytonaNetwork {
    Block,
    AllowAll,
    AllowList(Vec<String>),
}

impl Serialize for DaytonaNetwork {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Self::Block => serializer.serialize_str("block"),
            Self::AllowAll => serializer.serialize_str("allow_all"),
            Self::AllowList(cidrs) => {
                use serde::ser::SerializeMap;
                let mut map = serializer.serialize_map(Some(1))?;
                map.serialize_entry("allow_list", cidrs)?;
                map.end()
            }
        }
    }
}

impl<'de> Deserialize<'de> for DaytonaNetwork {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct DaytonaNetworkVisitor;

        impl<'de> Visitor<'de> for DaytonaNetworkVisitor {
            type Value = DaytonaNetwork;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(
                    formatter,
                    r#""block", "allow_all", or {{ allow_list = [...] }}"#
                )
            }

            fn visit_str<E: de::Error>(self, value: &str) -> Result<DaytonaNetwork, E> {
                match value {
                    "block" => Ok(DaytonaNetwork::Block),
                    "allow_all" => Ok(DaytonaNetwork::AllowAll),
                    other => Err(de::Error::custom(format!(
                        "unknown network mode \"{other}\": expected \"block\" or \"allow_all\""
                    ))),
                }
            }

            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<DaytonaNetwork, M::Error> {
                let Some(key) = map.next_key::<String>()? else {
                    return Err(de::Error::custom(
                        "empty table: expected { allow_list = [...] }",
                    ));
                };

                if key != "allow_list" {
                    return Err(de::Error::custom(format!(
                        "unknown key \"{key}\": expected \"allow_list\""
                    )));
                }

                let cidrs: Vec<String> = map.next_value()?;

                if cidrs.is_empty() {
                    return Err(de::Error::custom("allow_list must not be empty"));
                }

                if let Some(extra) = map.next_key::<String>()? {
                    return Err(de::Error::custom(format!(
                        "unexpected key \"{extra}\": allow_list table must have exactly one key"
                    )));
                }

                Ok(DaytonaNetwork::AllowList(cidrs))
            }
        }

        deserializer.deserialize_any(DaytonaNetworkVisitor)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum DockerfileSource {
    Inline(String),
    Path { path: String },
}

/// Where a custom Daytona snapshot is built from.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub enum DaytonaSnapshotSource {
    /// A pullable image reference such as `ubuntu:24.04`.
    Image(String),
    /// A Dockerfile that Daytona builds into the snapshot.
    Dockerfile(DockerfileSource),
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct DaytonaSnapshotSettings {
    pub cpu:    Option<i32>,
    pub memory: Option<i32>,
    pub disk:   Option<i32>,
    pub source: DaytonaSnapshotSource,
}

// ACA: settings consumed by `aca_config_from_environment`
// (`from_environment.rs`) to build an `AcaConfig`. Unlike `DaytonaSettings`
// above — a fabro-sandbox-local type never fed by the environment TOML,
// only ever constructed by its mapper — ACA's region/resource_group/
// sandbox_group/disk/egress knobs *are* per-environment TOML data (parsed
// via `fabro_config::EnvironmentLayer`'s `[aca]` table into
// `EnvironmentSettings`/`RunEnvironmentSettings`), so the canonical struct
// lives in `fabro_types::settings::run` alongside `RunEnvironmentSettings`.
// This re-export keeps an `AcaSettings` name available from this module for
// callers, mirroring where `DaytonaSettings` is found.
pub use fabro_types::settings::run::{AcaEgressSettings, AcaEnvironmentSettings as AcaSettings};
