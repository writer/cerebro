use std::path::PathBuf;
use std::process::Command;

fn git_output(repo_root: &PathBuf, arguments: &[&str]) -> Option<String> {
    let output = Command::new("git")
        .args(arguments)
        .current_dir(repo_root)
        .output()
        .ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn main() {
    let manifest_dir = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap_or_default());
    let repo_root = manifest_dir.join("../..");
    let commit_sha = git_output(&repo_root, &["rev-parse", "--verify", "HEAD"])
        .filter(|value| value.len() == 40)
        .unwrap_or_else(|| "unknown".into());
    let tracked_status = git_output(
        &repo_root,
        &["status", "--porcelain", "--untracked-files=no"],
    );
    let tree_clean = tracked_status.as_deref() == Some("");

    println!("cargo:rustc-env=CEREBRO_GIT_COMMIT_SHA={commit_sha}");
    println!(
        "cargo:rustc-env=CEREBRO_GIT_TREE_CLEAN={}",
        if tree_clean { "1" } else { "0" }
    );

    if let Some(git_dir) = git_output(&repo_root, &["rev-parse", "--absolute-git-dir"]) {
        println!("cargo:rerun-if-changed={git_dir}/HEAD");
        println!("cargo:rerun-if-changed={git_dir}/index");
    }
    println!("cargo:rerun-if-changed=build.rs");
}
