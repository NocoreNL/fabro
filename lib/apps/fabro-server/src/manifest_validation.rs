use std::collections::HashMap;
use std::path::PathBuf;

use anyhow::{Result, anyhow};
use fabro_api::types;
use fabro_config::{RunLayer, WorkflowSettingsBuilder};
use fabro_manifest::CollectedWorkflowClosure;
use fabro_workflow::operations::{ValidateInput, WorkflowInput, validate};
use fabro_workflow::pipeline::TEMPLATE_UNDEFINED_VARIABLE_RULE;

use crate::{run_intent, run_manifest};

/// Validate a manifest without a model catalog.
///
/// Every caller is a client — the CLI, an MCP server, a run worker — and a
/// client's catalog is its own, not the server's. Judging model and provider
/// availability here would reject workflows the server can run, so that is
/// left to the server on create.
pub fn validate_manifest(
    manifest_run_defaults: &RunLayer,
    manifest: &types::RunManifest,
) -> Result<types::ValidateResponse> {
    let prepared = run_manifest::prepare_manifest_with_environment_defaults(
        manifest_run_defaults,
        &fabro_environment::seeded_catalog_layer(),
        &HashMap::new(),
        manifest,
    )?;
    let validated = run_manifest::validate_prepared_manifest_structural(&prepared)
        .map_err(anyhow::Error::new)?;
    Ok(run_manifest::validate_response(&prepared, &validated))
}

/// Validate an already collected local workflow before any version upload.
///
/// The supplied run layer is complete, including any already resolved inline
/// goal. Validation uses only seeded environment defaults, immutable workflow
/// settings, and explicit inputs; it performs no store, HTTP, user-settings,
/// project-settings, or model-catalog operation. Undefined template variables
/// are promoted to errors before the response is returned.
pub fn validate_collected_workflow(
    closure: &CollectedWorkflowClosure,
    run_overrides: Option<&RunLayer>,
    input_overrides: &HashMap<String, toml::Value>,
) -> Result<types::ValidateResponse> {
    let lowered = run_intent::lower_collected_workflow_closure(closure)?;
    let workflow = lowered
        .workflow_bundle
        .into_workflows()
        .remove(&lowered.entrypoint)
        .ok_or_else(|| anyhow!("lowered root workflow is missing from its bundle"))?;
    let mut builder = WorkflowSettingsBuilder::new()
        .server_manifest_defaults(
            RunLayer::default(),
            fabro_environment::seeded_catalog_layer(),
        )
        .server_mcp_catalog(HashMap::new());
    if let Some(run) = run_overrides {
        builder = builder.run_overrides(run.clone());
    }
    if let Some(layer) = lowered.workflow_layer {
        builder = builder.workflow_layer(layer);
    }
    let mut settings = builder.build().map_err(anyhow::Error::new)?;
    settings.run.inputs.extend(input_overrides.clone());
    let validated = validate(ValidateInput {
        workflow: WorkflowInput::Bundled(workflow),
        settings,
        vars: HashMap::new(),
        cwd: PathBuf::from("/workspace"),
        custom_transforms: Vec::new(),
    })
    .map_err(anyhow::Error::new)?;
    let mut response = types::ValidateResponse {
        ok:       !validated.has_errors(),
        workflow: run_manifest::workflow_summary(&validated, lowered.entrypoint.as_path()),
    };
    promote_template_undefined_variables_to_errors(&mut response);
    Ok(response)
}

pub fn promote_template_undefined_variables_to_errors(response: &mut types::ValidateResponse) {
    let mut promoted = false;
    for diagnostic in &mut response.workflow.diagnostics {
        if diagnostic.rule == TEMPLATE_UNDEFINED_VARIABLE_RULE {
            diagnostic.severity = types::WorkflowDiagnosticSeverity::Error;
            promoted = true;
        }
    }
    if promoted {
        response.ok = false;
    }
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::disallowed_methods,
        reason = "collected-validation tests write isolated workflow fixtures synchronously"
    )]

    use std::fs;
    use std::path::{Path, PathBuf};

    use fabro_config::RunGoalLayer;
    use fabro_types::settings::InterpString;

    use super::*;

    fn write(root: &Path, path: &str, content: &str) {
        let path = root.join(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, content).unwrap();
    }

    fn write_complete_fixture(root: &Path) -> PathBuf {
        write(
            root,
            "root/workflow.toml",
            r#"_version = 1
[workflow]
graph = "workflow.fabro"
[run.goal]
file = "goal.md"
[run.environment.image]
dockerfile = { path = "Dockerfile" }
"#,
        );
        write(
            root,
            "root/workflow.fabro",
            r#"digraph Root {
                start [shape=Mdiamond]
                imported [import="imports/shared.fabro"]
                task [prompt="@prompts/task.md", model="future-provider/future-model"]
                child [stack.child_workflow="../child/workflow.fabro"]
                exit [shape=Msquare]
                start -> imported -> task -> child -> exit
            }"#,
        );
        write(
            root,
            "root/imports/shared.fabro",
            "digraph Shared { start [shape=Mdiamond] shared [prompt=\"shared\"] exit \
             [shape=Msquare] start -> shared -> exit }",
        );
        write(
            root,
            "root/prompts/task.md",
            "Hello {{ inputs.owner }}. {% include \"detail.md\" %}",
        );
        write(root, "root/prompts/detail.md", "detail");
        write(root, "root/goal.md", "workflow goal");
        write(root, "root/Dockerfile", "FROM alpine\n");
        write(
            root,
            "child/workflow.fabro",
            "digraph Child { start [shape=Mdiamond] exit [shape=Msquare] start -> exit }",
        );
        root.join("root/workflow.toml")
    }

    fn owner_input() -> HashMap<String, toml::Value> {
        HashMap::from([("owner".to_string(), toml::Value::String("Ada".to_string()))])
    }

    fn run_overrides(goal: &str) -> RunLayer {
        RunLayer {
            goal: Some(RunGoalLayer::Inline(InterpString::parse(goal))),
            ..RunLayer::default()
        }
    }

    #[test]
    fn collected_validation_matches_legacy_response_for_equivalent_inputs() {
        let temp = tempfile::tempdir().unwrap();
        let workflow = write_complete_fixture(temp.path());
        let run = run_overrides("inline goal");
        let inputs = owner_input();
        let package = fabro_manifest::resolve_local_workflow_package(
            &workflow,
            temp.path(),
            Some(temp.path()),
        )
        .unwrap();
        let manifest = fabro_manifest::build_run_manifest(fabro_manifest::ManifestBuildInput {
            workflow,
            cwd: temp.path().to_path_buf(),
            run_overrides: Some(run.clone()),
            input_overrides: inputs.clone(),
            args: Some(types::ManifestArgs {
                input: vec!["owner=Ada".to_string()],
                ..types::ManifestArgs::default()
            }),
            environment_defaults: fabro_environment::seeded_catalog_layer(),
            ..fabro_manifest::ManifestBuildInput::default()
        })
        .unwrap();

        let mut legacy = validate_manifest(&RunLayer::default(), &manifest.manifest).unwrap();
        promote_template_undefined_variables_to_errors(&mut legacy);
        let collected =
            validate_collected_workflow(package.closure(), Some(&run), &inputs).unwrap();

        assert_eq!(
            serde_json::to_value(collected).unwrap(),
            serde_json::to_value(legacy).unwrap(),
        );
    }

    #[test]
    fn collected_validation_promotes_undefined_inputs_and_accepts_explicit_values() {
        let temp = tempfile::tempdir().unwrap();
        let workflow = write_complete_fixture(temp.path());
        let package = fabro_manifest::resolve_local_workflow_package(
            &workflow,
            temp.path(),
            Some(temp.path()),
        )
        .unwrap();

        let missing =
            validate_collected_workflow(package.closure(), None, &HashMap::new()).unwrap();
        assert!(!missing.ok);
        assert!(missing.workflow.diagnostics.iter().any(|diagnostic| {
            diagnostic.rule == TEMPLATE_UNDEFINED_VARIABLE_RULE
                && diagnostic.severity == types::WorkflowDiagnosticSeverity::Error
        }));

        let present = validate_collected_workflow(
            package.closure(),
            Some(&run_overrides("resolved inline goal")),
            &owner_input(),
        )
        .unwrap();
        assert!(
            present
                .workflow
                .diagnostics
                .iter()
                .all(|diagnostic| { diagnostic.rule != TEMPLATE_UNDEFINED_VARIABLE_RULE })
        );
        assert!(present.ok);
        assert_eq!(present.workflow.goal, "resolved inline goal");
        assert!(present.workflow.diagnostics.iter().all(|diagnostic| {
            !diagnostic.message.contains("future-provider")
                && !diagnostic.message.contains("future-model")
        }));
    }
}
