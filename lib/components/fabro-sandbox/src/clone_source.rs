use crate::sandbox;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum CloneDecision {
    EmptyWorkspace {
        reason: EmptyWorkspaceReason,
    },
    GitHub {
        origin_url: String,
        branch:     Option<String>,
        tag:        Option<String>,
        commit_sha: Option<String>,
    },
}

// The owner/repo checkout layout is Docker/Daytona-only; ACA reuses this
// module for `decide_clone` and the pinned-revision helpers but has a single
// flat working directory, so gate the layout out of aca-only builds (`test`
// keeps this module's own unit tests compiling).
#[cfg(any(feature = "docker", feature = "daytona", test))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct GitHubRepoLayout {
    pub(crate) owner:               String,
    pub(crate) repo:                String,
    pub(crate) repos_owner_path:    String,
    pub(crate) primary_repo_path:   String,
    pub(crate) primary_repo_link:   String,
    pub(crate) execution_directory: String,
}

#[cfg(any(feature = "docker", feature = "daytona", test))]
pub(crate) fn github_repo_layout(
    origin_url: &str,
    workspace_root: &str,
    repos_root: &str,
) -> crate::Result<GitHubRepoLayout> {
    let origin_url = fabro_github::normalize_repo_origin_url(origin_url);
    let (owner, repo) = fabro_github::parse_github_owner_repo(&origin_url).map_err(|err| {
        crate::Error::message(format!(
            "Clone-based sandboxes currently support GitHub repository origins only: {err}"
        ))
    })?;
    validate_path_component("owner", &owner)?;
    validate_path_component("repository", &repo)?;
    let workspace_root = trim_root(workspace_root);
    let repos_root = trim_root(repos_root);
    let repos_owner_path = sandbox::join_sandbox_path(repos_root, &owner);
    let primary_repo_path = sandbox::join_sandbox_path(&repos_owner_path, &repo);
    let primary_repo_link = sandbox::join_sandbox_path(workspace_root, &repo);

    Ok(GitHubRepoLayout {
        owner,
        repo,
        repos_owner_path,
        primary_repo_path,
        execution_directory: primary_repo_link.clone(),
        primary_repo_link,
    })
}

#[cfg(any(feature = "docker", feature = "daytona", test))]
fn validate_path_component(label: &str, component: &str) -> crate::Result<()> {
    let is_safe = !matches!(component, "." | "..")
        && component
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'));
    if !is_safe {
        return Err(crate::Error::message(format!(
            "GitHub {label} is not a safe repository path component"
        )));
    }
    Ok(())
}

#[cfg(any(feature = "docker", feature = "daytona", test))]
pub(crate) fn repo_symlink_command(layout: &GitHubRepoLayout) -> String {
    format!(
        "ln -s {} {}",
        sandbox::shell_quote(&layout.primary_repo_path),
        sandbox::shell_quote(&layout.primary_repo_link),
    )
}

#[cfg(any(feature = "docker", feature = "aca", test))]
pub(crate) fn exact_repository_init_command(clone_url: &str, checkout_path: &str) -> String {
    format!(
        "{git} init -- {path} && git -C {path} remote add origin {origin}",
        git = sandbox::GIT,
        path = sandbox::shell_quote(checkout_path),
        origin = sandbox::shell_quote(clone_url),
    )
}

/// A revision the checkout is pinned to instead of the branch's current HEAD.
///
/// The working branch names the checkout the run works on; it never constrains
/// which revision is fetched. No layer proves branch/revision ancestry, and an
/// unavailable revision fails without falling back to branch HEAD.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PinnedRevision {
    /// An exact commit SHA, already normalized by
    /// [`normalize_exact_commit_sha`].
    Commit(String),
    /// A bare tag name, fetched as `refs/tags/<tag>` so a same-named branch is
    /// never consulted.
    Tag(String),
}

impl PinnedRevision {
    /// An exact commit is authoritative over a tag; the tag stays on the run
    /// target as durable identity but does not drive the checkout.
    pub(crate) fn from_selectors(tag: Option<&str>, commit_sha: Option<&str>) -> Option<Self> {
        match (commit_sha, tag) {
            (Some(sha), _) => Some(Self::Commit(sha.to_string())),
            (None, Some(tag)) => Some(Self::Tag(tag.to_string())),
            (None, None) => None,
        }
    }

    /// Human-readable prefix for error messages.
    pub(crate) fn label(&self) -> &'static str {
        match self {
            Self::Commit(_) => "Exact commit checkout",
            Self::Tag(_) => "Tag checkout",
        }
    }

    /// The refspec handed to `git fetch`.
    pub(crate) fn fetch_refspec(&self) -> String {
        match self {
            Self::Commit(sha) => sha.clone(),
            Self::Tag(tag) => tag_ref(tag),
        }
    }

    /// The commit HEAD must resolve to after checkout, when one is known.
    pub(crate) fn expected_sha(&self) -> Option<&str> {
        match self {
            Self::Commit(sha) => Some(sha),
            Self::Tag(_) => None,
        }
    }

    /// Validate the `rev-parse HEAD` output of a pinned checkout and return the
    /// resolved commit ID.
    pub(crate) fn verify_head(&self, output: &str) -> crate::Result<String> {
        let actual_sha = verify_resolved_head(output)?;
        if self
            .expected_sha()
            .is_some_and(|expected| expected != actual_sha)
        {
            return Err(crate::Error::message(
                "Exact checkout HEAD did not match the requested commit",
            ));
        }
        Ok(actual_sha)
    }
}

/// Fully-qualified ref for a bare tag name.
pub(crate) fn tag_ref(tag: &str) -> String {
    format!("refs/tags/{tag}")
}

/// Fetch a single pinned refspec with the same history depth a branch clone
/// gets, so both paths can reach the same number of parent commits.
///
/// The fetch names the revision directly rather than the branch, and
/// `--no-tags` keeps unrelated tags from being pulled alongside it.
#[cfg(any(feature = "docker", feature = "aca", test))]
pub(crate) fn pinned_fetch_command(
    checkout_path: &str,
    fetch_source: &str,
    refspec: &str,
    depth: Option<usize>,
) -> String {
    let depth_arg = depth_argument(depth);
    format!(
        "{git} -C {} fetch{depth_arg} --no-tags {} -- {}",
        sandbox::shell_quote(checkout_path),
        sandbox::shell_quote(fetch_source),
        sandbox::shell_quote(refspec),
        git = sandbox::GIT,
    )
}

/// Leading-space ` --depth N` fragment for a Git command, or empty when
/// `depth` is `None` to fetch full history.
#[cfg(any(feature = "docker", feature = "aca", test))]
pub(crate) fn depth_argument(depth: Option<usize>) -> String {
    depth.map_or_else(String::new, |depth| format!(" --depth {depth}"))
}

/// Point the admitted branch at `revision` and attach HEAD to it.
///
/// The checkout attaches to a real branch instead of detaching so callers that
/// read the current branch back out of the workspace still see the admitted
/// branch name.
pub(crate) fn exact_branch_checkout_command(
    checkout_path: &str,
    branch: &str,
    revision: &str,
) -> String {
    format!(
        "{git} -C {path} checkout -B {branch} {revision}",
        path = sandbox::shell_quote(checkout_path),
        branch = sandbox::shell_quote(branch),
        revision = sandbox::shell_quote(revision),
        git = sandbox::GIT,
    )
}

/// Print the current HEAD commit and nothing else, for
/// [`PinnedRevision::verify_head`].
pub(crate) fn exact_head_revision_command(checkout_path: &str) -> String {
    format!(
        "{git} -C {path} rev-parse HEAD",
        path = sandbox::shell_quote(checkout_path),
        git = sandbox::GIT,
    )
}

/// Check out the admitted branch and print the resulting HEAD in one shell
/// command; stdout is the `rev-parse HEAD` output for
/// [`PinnedRevision::verify_head`].
#[cfg(any(feature = "docker", feature = "aca", test))]
pub(crate) fn exact_checkout_verify_command(
    checkout_path: &str,
    branch: &str,
    revision: &str,
) -> String {
    format!(
        "{} && {}",
        exact_branch_checkout_command(checkout_path, branch, revision),
        exact_head_revision_command(checkout_path),
    )
}

/// The peeled commit behind whatever `git fetch` just wrote to `FETCH_HEAD`;
/// a commit peels to itself, an annotated tag to the commit it points at.
#[cfg(any(feature = "docker", feature = "aca", test))]
pub(crate) const FETCH_HEAD_COMMIT: &str = "FETCH_HEAD^{commit}";

/// Validate that a `rev-parse HEAD` output is a single commit ID and return it
/// normalized.
pub(crate) fn verify_resolved_head(output: &str) -> crate::Result<String> {
    normalize_exact_commit_sha(output.trim()).map_err(|err| {
        crate::Error::context("Pinned checkout produced an invalid HEAD commit ID", err)
    })
}

#[cfg(any(feature = "docker", feature = "daytona", test))]
fn trim_root(root: &str) -> &str {
    let trimmed = root.trim_end_matches('/');
    if trimmed.is_empty() { "/" } else { trimmed }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum EmptyWorkspaceReason {
    SkipClone,
    MissingOrigin,
}

impl EmptyWorkspaceReason {
    pub(crate) fn message(self) -> &'static str {
        match self {
            Self::SkipClone => "clone disabled; creating an empty workspace",
            Self::MissingOrigin => {
                "no clone source was present; creating an empty workspace without repository files"
            }
        }
    }
}

pub(crate) fn decide_clone(
    skip_clone: bool,
    clone_origin_url: Option<&str>,
    clone_branch: Option<&str>,
    clone_tag: Option<&str>,
    clone_commit_sha: Option<&str>,
) -> crate::Result<CloneDecision> {
    if clone_tag.is_some_and(|tag| tag.trim().is_empty()) {
        return Err(crate::Error::message(
            "Tag checkout requires a non-empty tag",
        ));
    }
    let tag = clone_tag.map(str::to_string);
    let commit_sha = clone_commit_sha
        .map(normalize_exact_commit_sha)
        .transpose()?;

    if let Some(pin) = PinnedRevision::from_selectors(tag.as_deref(), commit_sha.as_deref()) {
        let selector = pin.label();
        if skip_clone {
            return Err(crate::Error::message(format!(
                "{selector} requires cloning to be enabled"
            )));
        }
        if clone_origin_url.is_none_or(|url| url.trim().is_empty()) {
            return Err(crate::Error::message(format!(
                "{selector} requires a repository origin"
            )));
        }
        // The branch names the checkout the run works on; it is not used to
        // constrain which commits may be fetched. No layer proves branch/SHA
        // ancestry, and an unavailable exact commit fails without falling back
        // to branch HEAD.
        if clone_branch.is_none_or(|branch| branch.trim().is_empty()) {
            return Err(crate::Error::message(format!(
                "{selector} requires a repository branch"
            )));
        }
    }

    if skip_clone {
        return Ok(CloneDecision::EmptyWorkspace {
            reason: EmptyWorkspaceReason::SkipClone,
        });
    }

    let Some(origin_url) = clone_origin_url.filter(|url| !url.trim().is_empty()) else {
        return Ok(CloneDecision::EmptyWorkspace {
            reason: EmptyWorkspaceReason::MissingOrigin,
        });
    };

    let origin_url = fabro_github::normalize_repo_origin_url(origin_url);
    if let Err(err) = fabro_github::parse_github_owner_repo(&origin_url) {
        return Err(crate::Error::message(format!(
            "Clone-based sandboxes currently support GitHub repository origins only: {err}"
        )));
    }

    Ok(CloneDecision::GitHub {
        origin_url,
        branch: clone_branch
            .filter(|branch| !branch.trim().is_empty())
            .map(str::to_string),
        tag,
        commit_sha,
    })
}

fn normalize_exact_commit_sha(commit_sha: &str) -> crate::Result<String> {
    fabro_types::normalize_git_commit_sha(commit_sha).ok_or_else(|| {
        crate::Error::message("Exact commit SHA must be exactly 40 ASCII hexadecimal characters")
    })
}

#[cfg(any(feature = "docker", feature = "daytona", test))]
pub(crate) fn clean_clone_origin_for_record(clone_origin_url: Option<&str>) -> Option<String> {
    clone_origin_url
        .filter(|url| !url.trim().is_empty())
        .map(fabro_github::normalize_repo_origin_url)
}

// Unlike the layout/record helpers above, this one has no clone_source unit
// test of its own — its only callers are the Docker/Daytona record arms — so
// it excludes `test` to avoid being dead code in an aca-only test build.
#[cfg(any(feature = "docker", feature = "daytona"))]
pub(crate) fn repo_cloned_for_record(
    skip_clone: bool,
    clone_origin_url: Option<&str>,
) -> Option<bool> {
    Some(matches!(
        decide_clone(skip_clone, clone_origin_url, None, None, None).ok()?,
        CloneDecision::GitHub { .. }
    ))
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;
    use std::process::{Command, Output};

    use super::*;

    fn isolated_command(command: &mut Command) -> Output {
        command
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_AUTHOR_NAME", "Fabro Test")
            .env("GIT_AUTHOR_EMAIL", "fabro-test@example.com")
            .env("GIT_COMMITTER_NAME", "Fabro Test")
            .env("GIT_COMMITTER_EMAIL", "fabro-test@example.com")
            .output()
            .expect("test command should start")
    }

    #[expect(
        clippy::disallowed_methods,
        reason = "hermetic Git proof intentionally runs the local git executable synchronously"
    )]
    fn run_git(cwd: &Path, args: &[&str]) -> String {
        let output = isolated_command(Command::new("git").current_dir(cwd).args(args));
        assert!(
            output.status.success(),
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).expect("git output should be UTF-8")
    }

    fn run_shell(cwd: &Path, command: &str) -> String {
        let output = run_shell_output(cwd, command);
        assert!(
            output.status.success(),
            "command failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).expect("command output should be UTF-8")
    }

    #[expect(
        clippy::disallowed_methods,
        reason = "hermetic command-builder proof intentionally runs local Bash synchronously"
    )]
    fn run_shell_output(cwd: &Path, command: &str) -> Output {
        isolated_command(Command::new("/bin/bash").current_dir(cwd).args([
            "--noprofile",
            "--norc",
            "-c",
            command,
        ]))
    }

    #[test]
    fn skip_clone_overrides_present_origin() {
        assert_eq!(
            decide_clone(
                true,
                Some("https://gitlab.com/acme/widgets.git"),
                Some("main"),
                None,
                None,
            )
            .unwrap(),
            CloneDecision::EmptyWorkspace {
                reason: EmptyWorkspaceReason::SkipClone,
            }
        );
    }

    #[test]
    fn missing_origin_creates_empty_workspace() {
        assert_eq!(
            decide_clone(false, None, None, None, None).unwrap(),
            CloneDecision::EmptyWorkspace {
                reason: EmptyWorkspaceReason::MissingOrigin,
            }
        );
    }

    #[test]
    fn github_origin_is_normalized_with_branch() {
        assert_eq!(
            decide_clone(
                false,
                Some("git@github.com:acme/widgets.git"),
                Some("feature/work"),
                None,
                None,
            )
            .unwrap(),
            CloneDecision::GitHub {
                origin_url: "https://github.com/acme/widgets".to_string(),
                branch:     Some("feature/work".to_string()),
                tag:        None,
                commit_sha: None,
            }
        );
    }

    #[test]
    fn tag_clone_keeps_working_branch_and_bare_tag_distinct() {
        assert_eq!(
            decide_clone(
                false,
                Some("https://github.com/acme/widgets"),
                Some("release"),
                Some("v1.2.3"),
                None,
            )
            .unwrap(),
            CloneDecision::GitHub {
                origin_url: "https://github.com/acme/widgets".to_string(),
                branch:     Some("release".to_string()),
                tag:        Some("v1.2.3".to_string()),
                commit_sha: None,
            }
        );
    }

    #[test]
    fn pinned_revision_prefers_exact_commit_and_qualifies_tags() {
        let sha = "0123456789abcdef0123456789abcdef01234567";
        assert_eq!(PinnedRevision::from_selectors(None, None), None);
        let tag = PinnedRevision::from_selectors(Some("release/v1"), None).unwrap();
        assert_eq!(tag.fetch_refspec(), "refs/tags/release/v1");
        assert_eq!(tag.expected_sha(), None);
        let commit = PinnedRevision::from_selectors(Some("release/v1"), Some(sha)).unwrap();
        assert_eq!(commit.fetch_refspec(), sha);
        assert_eq!(commit.expected_sha(), Some(sha));
        assert_eq!(
            pinned_fetch_command(
                "/repos/acme/widgets",
                "origin",
                &tag.fetch_refspec(),
                Some(10)
            ),
            "git -c maintenance.auto=0 -c gc.auto=0 -C /repos/acme/widgets fetch --depth 10 --no-tags origin -- refs/tags/release/v1"
        );
        assert_eq!(
            exact_checkout_verify_command("/repos/acme/widgets", "release", FETCH_HEAD_COMMIT),
            "git -c maintenance.auto=0 -c gc.auto=0 -C /repos/acme/widgets checkout -B release FETCH_HEAD'^{commit}' && git -c maintenance.auto=0 -c gc.auto=0 -C /repos/acme/widgets rev-parse HEAD"
        );
    }

    #[test]
    fn non_github_origin_fails_without_skip_clone() {
        let error = decide_clone(
            false,
            Some("https://gitlab.com/acme/widgets.git"),
            None,
            None,
            None,
        )
        .expect_err("non-GitHub origins should fail");
        assert!(error.to_string().contains("GitHub repository origins only"));
    }

    #[test]
    fn exact_commit_sha_is_validated_and_normalized() {
        let lowercase = "0123456789abcdef0123456789abcdef01234567";
        let uppercase = "ABCDEF0123456789ABCDEF0123456789ABCDEF01";

        assert_eq!(
            decide_clone(
                false,
                Some("https://github.com/acme/widgets"),
                Some("moving-branch"),
                Some("release"),
                Some(lowercase),
            )
            .unwrap(),
            CloneDecision::GitHub {
                origin_url: "https://github.com/acme/widgets".to_string(),
                branch:     Some("moving-branch".to_string()),
                tag:        Some("release".to_string()),
                commit_sha: Some(lowercase.to_string()),
            }
        );
        assert_eq!(
            decide_clone(
                false,
                Some("https://github.com/acme/widgets"),
                Some("main"),
                None,
                Some(uppercase),
            )
            .unwrap(),
            CloneDecision::GitHub {
                origin_url: "https://github.com/acme/widgets".to_string(),
                branch:     Some("main".to_string()),
                tag:        None,
                commit_sha: Some(uppercase.to_ascii_lowercase()),
            }
        );
    }

    #[test]
    fn exact_commit_sha_rejects_noncanonical_inputs() {
        for sha in [
            "",
            "0123456789abcdef0123456789abcdef0123456",
            "0123456789abcdef0123456789abcdef012345678",
            "0123456789abcdef0123456789abcdef0123456g",
            " 0123456789abcdef0123456789abcdef01234567",
            "0123456789abcdef0123456789abcdef01234567 ",
            "0123456789abcdef0123456789abcdef012345é",
        ] {
            let error = decide_clone(
                false,
                Some("https://github.com/acme/widgets"),
                None,
                None,
                Some(sha),
            )
            .expect_err("invalid exact commit SHA should fail");
            assert!(
                error.to_string().contains("40 ASCII hexadecimal"),
                "unexpected error for {sha:?}: {error}"
            );
        }
    }

    #[test]
    fn pinned_checkout_requires_clone_origin_and_branch() {
        let sha = "0123456789abcdef0123456789abcdef01234567";
        for (tag, commit_sha) in [(None, Some(sha)), (Some("v1"), None)] {
            let skip_error = decide_clone(
                true,
                Some("https://github.com/acme/widgets"),
                Some("main"),
                tag,
                commit_sha,
            )
            .expect_err("pinned checkout with skip-clone should fail");
            assert!(skip_error.to_string().contains("requires cloning"));

            for origin in [None, Some(""), Some("   ")] {
                let error = decide_clone(false, origin, Some("main"), tag, commit_sha)
                    .expect_err("pinned checkout without an origin should fail");
                assert!(error.to_string().contains("requires a repository origin"));
            }

            for branch in [None, Some(""), Some("   ")] {
                let error = decide_clone(
                    false,
                    Some("https://github.com/acme/widgets"),
                    branch,
                    tag,
                    commit_sha,
                )
                .expect_err("pinned checkout without a branch should fail");
                assert!(error.to_string().contains("requires a repository branch"));
            }
        }
    }

    #[test]
    fn tag_checkout_rejects_empty_tag() {
        let empty_tag = decide_clone(
            false,
            Some("https://github.com/acme/widgets"),
            Some("main"),
            Some(""),
            None,
        )
        .expect_err("empty tags should fail");
        assert!(empty_tag.to_string().contains("non-empty tag"));
    }

    #[test]
    fn docker_exact_checkout_commands_quote_inputs() {
        let sha = "0123456789abcdef0123456789abcdef01234567";
        let init = exact_repository_init_command(
            "https://token@example.com/acme/widgets.git?x=a b",
            "/repos/acme's widgets",
        );
        let fetch = pinned_fetch_command(
            "/repos/acme's widgets",
            "https://token@example.com/acme/widgets.git?x=a b",
            sha,
            Some(10),
        );
        let checkout =
            exact_checkout_verify_command("/repos/acme's widgets", "feature/a b", "FETCH_HEAD");

        assert_eq!(
            init,
            "git -c maintenance.auto=0 -c gc.auto=0 init -- \"/repos/acme's widgets\" && git -C \"/repos/acme's widgets\" remote add origin 'https://token@example.com/acme/widgets.git?x=a b'"
        );
        assert_eq!(
            fetch,
            "git -c maintenance.auto=0 -c gc.auto=0 -C \"/repos/acme's widgets\" fetch --depth 10 --no-tags 'https://token@example.com/acme/widgets.git?x=a b' -- 0123456789abcdef0123456789abcdef01234567"
        );
        assert_eq!(
            checkout,
            "git -c maintenance.auto=0 -c gc.auto=0 -C \"/repos/acme's widgets\" checkout -B 'feature/a b' FETCH_HEAD && git -c maintenance.auto=0 -c gc.auto=0 -C \"/repos/acme's widgets\" rev-parse HEAD"
        );
    }

    #[test]
    fn pinned_fetch_omits_depth_for_full_history() {
        assert_eq!(
            pinned_fetch_command(
                "/repos/acme/widgets",
                "origin",
                "0123456789abcdef0123456789abcdef01234567",
                None,
            ),
            "git -c maintenance.auto=0 -c gc.auto=0 -C /repos/acme/widgets fetch --no-tags origin -- 0123456789abcdef0123456789abcdef01234567"
        );
    }

    #[test]
    fn exact_checkout_verification_rejects_invalid_or_mismatched_head() {
        let expected = "0123456789abcdef0123456789abcdef01234567";
        let pin = PinnedRevision::Commit(expected.to_string());
        pin.verify_head("0123456789ABCDEF0123456789ABCDEF01234567\n")
            .expect("uppercase command output should normalize");

        let invalid = pin
            .verify_head("fatal: not a revision")
            .expect_err("non-SHA output should fail verification");
        assert!(invalid.to_string().contains("invalid HEAD commit ID"));
        assert!(!invalid.to_string().contains("fatal: not a revision"));

        let mismatched = pin
            .verify_head("1123456789abcdef0123456789abcdef01234567")
            .expect_err("mismatched SHA should fail verification");
        assert!(mismatched.to_string().contains("did not match"));
    }

    #[test]
    #[expect(
        clippy::disallowed_methods,
        reason = "hermetic Git proof uses isolated synchronous temp-repository I/O"
    )]
    fn exact_checkout_fetches_admitted_commit_after_branch_and_tag_advance() {
        let temp = tempfile::tempdir().expect("tempdir");
        let remote = temp.path().join("remote.git");
        let source = temp.path().join("source");
        let checkout = temp.path().join("exact checkout");
        fs::create_dir(&source).expect("source directory");

        run_git(temp.path(), &[
            "init",
            "--bare",
            remote.to_str().expect("UTF-8 remote path"),
        ]);
        run_git(&source, &["init"]);
        fs::write(source.join("revision.txt"), "A\n").expect("write commit A");
        run_git(&source, &["add", "revision.txt"]);
        run_git(&source, &["commit", "-m", "commit A"]);
        run_git(&source, &["branch", "-M", "main"]);
        run_git(&source, &[
            "remote",
            "add",
            "origin",
            remote.to_str().expect("UTF-8 remote path"),
        ]);
        run_git(&source, &["push", "-u", "origin", "main"]);
        let admitted_sha = run_git(&source, &["rev-parse", "HEAD"]).trim().to_string();
        run_git(&source, &["tag", "release"]);
        run_git(&source, &["push", "origin", "refs/tags/release"]);

        fs::write(source.join("revision.txt"), "B\n").expect("write commit B");
        run_git(&source, &["commit", "-am", "commit B"]);
        run_git(&source, &["push", "origin", "main"]);
        run_git(&source, &["tag", "-f", "release"]);
        run_git(&source, &["push", "--force", "origin", "refs/tags/release"]);
        let advanced_sha = run_git(&source, &["rev-parse", "HEAD"]).trim().to_string();
        assert_ne!(admitted_sha, advanced_sha);

        let remote_path = remote.to_str().expect("UTF-8 remote path");
        let checkout_path = checkout.to_str().expect("UTF-8 checkout path");
        run_shell(
            temp.path(),
            &exact_repository_init_command(remote_path, checkout_path),
        );
        run_shell(
            temp.path(),
            &pinned_fetch_command(checkout_path, remote_path, &admitted_sha, Some(10)),
        );
        let checked_out_sha = run_shell(
            temp.path(),
            &exact_checkout_verify_command(checkout_path, "main", FETCH_HEAD_COMMIT),
        );

        assert_eq!(checked_out_sha.trim(), admitted_sha);
        assert_eq!(
            fs::read_to_string(checkout.join("revision.txt")).expect("checked-out contents"),
            "A\n"
        );
        assert_eq!(
            run_git(&checkout, &["symbolic-ref", "HEAD"]).trim(),
            "refs/heads/main",
            "HEAD should stay attached to the admitted branch"
        );
        assert_eq!(
            run_git(&checkout, &["rev-parse", "--abbrev-ref", "HEAD"]).trim(),
            "main"
        );
        assert_eq!(
            run_git(temp.path(), &[
                "--git-dir",
                remote_path,
                "rev-parse",
                "refs/heads/main",
            ],)
            .trim(),
            advanced_sha
        );
    }

    #[test]
    #[expect(
        clippy::disallowed_methods,
        reason = "hermetic Git proof uses isolated synchronous temp-repository I/O"
    )]
    fn tag_checkout_peels_lightweight_and_annotated_tags_without_branch_fallback() {
        let temp = tempfile::tempdir().expect("tempdir");
        let remote = temp.path().join("remote.git");
        let source = temp.path().join("source");
        fs::create_dir(&source).expect("source directory");

        run_git(temp.path(), &[
            "init",
            "--bare",
            remote.to_str().expect("UTF-8 remote path"),
        ]);
        run_git(&source, &["init"]);
        fs::write(source.join("revision.txt"), "release\n").expect("write release commit");
        run_git(&source, &["add", "revision.txt"]);
        run_git(&source, &["commit", "-m", "release"]);
        run_git(&source, &["branch", "-M", "main"]);
        let release_sha = run_git(&source, &["rev-parse", "HEAD"]).trim().to_string();
        run_git(&source, &["tag", "lightweight"]);
        run_git(&source, &["tag", "-a", "annotated", "-m", "annotated"]);
        run_git(&source, &[
            "remote",
            "add",
            "origin",
            remote.to_str().expect("UTF-8 remote path"),
        ]);
        run_git(&source, &["push", "origin", "main", "--tags"]);

        let remote_path = remote.to_str().expect("UTF-8 remote path");
        for tag in ["lightweight", "annotated"] {
            let checkout = temp.path().join(format!("checkout-{tag}"));
            let checkout_path = checkout.to_str().expect("UTF-8 checkout path");
            run_shell(
                temp.path(),
                &exact_repository_init_command(remote_path, checkout_path),
            );
            run_shell(
                temp.path(),
                &pinned_fetch_command(checkout_path, "origin", &tag_ref(tag), Some(10)),
            );
            let head = run_shell(
                temp.path(),
                &exact_checkout_verify_command(checkout_path, "release-work", FETCH_HEAD_COMMIT),
            );

            assert_eq!(verify_resolved_head(&head).unwrap(), release_sha);
            assert_eq!(
                run_git(&checkout, &["symbolic-ref", "HEAD"]).trim(),
                "refs/heads/release-work"
            );
        }

        let missing = temp.path().join("missing");
        let missing_path = missing.to_str().expect("UTF-8 checkout path");
        run_shell(
            temp.path(),
            &exact_repository_init_command(remote_path, missing_path),
        );
        let output = run_shell_output(
            temp.path(),
            &pinned_fetch_command(missing_path, "origin", &tag_ref("main"), Some(10)),
        );
        assert!(
            !output.status.success(),
            "a branch must not satisfy a tag fetch"
        );
        assert!(!missing.join("revision.txt").exists());
    }

    #[test]
    fn github_layout_maps_ssh_origin_to_repos_checkout_and_workspace_link() {
        let layout = github_repo_layout(
            "git@github.com:brynary/rack-test.git",
            "/workspace",
            "/repos",
        )
        .unwrap();

        assert_eq!(layout.owner, "brynary");
        assert_eq!(layout.repo, "rack-test");
        assert_eq!(layout.repos_owner_path, "/repos/brynary");
        assert_eq!(layout.primary_repo_path, "/repos/brynary/rack-test");
        assert_eq!(layout.primary_repo_link, "/workspace/rack-test");
        assert_eq!(layout.execution_directory, "/workspace/rack-test");
    }

    #[test]
    fn github_layout_normalizes_https_origin_and_trims_roots() {
        let layout = github_repo_layout(
            "https://github.com/fabro-sh/fabro.git/",
            "/workspace/",
            "/repos/",
        )
        .unwrap();

        assert_eq!(layout.owner, "fabro-sh");
        assert_eq!(layout.repo, "fabro");
        assert_eq!(layout.repos_owner_path, "/repos/fabro-sh");
        assert_eq!(layout.primary_repo_path, "/repos/fabro-sh/fabro");
        assert_eq!(layout.primary_repo_link, "/workspace/fabro");
        assert_eq!(layout.execution_directory, "/workspace/fabro");
    }

    #[test]
    fn github_layout_rejects_path_traversal_components() {
        for origin in [
            "https://github.com/../widgets",
            "https://github.com/acme/..",
            "https://github.com/%2e%2e/widgets",
        ] {
            let error = github_repo_layout(origin, "/workspace", "/repos")
                .expect_err("unsafe path component should fail");
            assert!(
                error.to_string().contains("safe repository path component"),
                "got {error} for {origin}"
            );
        }
    }

    #[test]
    fn repo_symlink_command_quotes_both_paths() {
        let layout = github_repo_layout(
            "https://github.com/fabro-sh/fabro",
            "/work space",
            "/repo root",
        )
        .unwrap();

        assert_eq!(
            repo_symlink_command(&layout),
            "ln -s '/repo root/fabro-sh/fabro' '/work space/fabro'"
        );
    }

    #[test]
    fn record_origin_strips_credentials() {
        assert_eq!(
            clean_clone_origin_for_record(Some(
                "https://x-access-token:secret@github.com/acme/widgets.git"
            )),
            Some("https://github.com/acme/widgets".to_string())
        );
    }
}
