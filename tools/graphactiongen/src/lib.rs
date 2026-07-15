use serde::Deserialize;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

pub const DEFAULT_CATALOG_PATH: &str = "internal/graphactions/action_catalog.yaml";
pub const DEFAULT_OUTPUT_PATH: &str = "internal/graphactions/registry_gen.go";
pub const MAX_GENERATED_FILE_BYTES: usize = 4 << 20;

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Debug, Deserialize)]
pub struct ActionCatalog {
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub actions: Vec<ActionCatalogEntry>,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct ActionCatalogEntry {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub const_name: String,
    #[serde(default)]
    pub provider: String,
    #[serde(default)]
    pub provider_const: String,
    #[serde(default)]
    pub provider_action: String,
    #[serde(default)]
    pub provider_action_const: String,
    #[serde(default)]
    pub target_kind: String,
    #[serde(default)]
    pub target_kind_const: String,
    #[serde(default)]
    pub target_resolver: String,
    #[serde(default)]
    pub eligibility_checker: String,
    #[serde(default)]
    pub effect: String,
    #[serde(default)]
    pub destructive: bool,
    #[serde(default)]
    pub reversible_by: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct StringConstant {
    name: String,
    value: String,
}

pub fn generate(root: &Path, catalog_path: &Path) -> Result<Vec<u8>, String> {
    let path = root.join(catalog_path);
    let content = read_bounded_file(&path)
        .map_err(|err| format!("read catalog {}: {err}", catalog_path.display()))?;
    let catalog: ActionCatalog = serde_saphyr::from_slice(&content)
        .map_err(|err| format!("decode catalog {}: {err}", catalog_path.display()))?;
    validate_catalog(&catalog)?;
    render_catalog(&catalog)
}

pub fn validate_catalog(catalog: &ActionCatalog) -> Result<(), String> {
    if catalog.version.trim() != "graph-actions.cerebro/v1alpha1" {
        return Err(format!("unsupported catalog version {:?}", catalog.version));
    }
    if catalog.actions.is_empty() {
        return Err("catalog has no actions".to_owned());
    }

    let mut ids = HashSet::new();
    let mut const_names = HashSet::new();
    let mut provider_const_values = HashMap::<&str, &str>::new();
    let mut provider_action_const_values = HashMap::<&str, &str>::new();
    let mut target_kind_const_values = HashMap::<&str, &str>::new();

    for (index, action) in catalog.actions.iter().enumerate() {
        validate_action(index, action)?;
        if !ids.insert(action.id.as_str()) {
            return Err(format!("duplicate action id {:?}", action.id));
        }
        if !const_names.insert(action.const_name.as_str()) {
            return Err(format!(
                "duplicate action const_name {:?}",
                action.const_name
            ));
        }
        insert_consistent(
            &mut provider_const_values,
            action.provider_const.as_str(),
            action.provider.as_str(),
            &action.id,
            "provider_const",
        )?;
        insert_consistent(
            &mut provider_action_const_values,
            action.provider_action_const.as_str(),
            action.provider_action.as_str(),
            &action.id,
            "provider_action_const",
        )?;
        insert_consistent(
            &mut target_kind_const_values,
            action.target_kind_const.as_str(),
            action.target_kind.as_str(),
            &action.id,
            "target_kind_const",
        )?;
    }

    for action in &catalog.actions {
        if !action.reversible_by.is_empty() && !ids.contains(action.reversible_by.as_str()) {
            return Err(format!(
                "action {:?} reversible_by references unknown action {:?}",
                action.id, action.reversible_by
            ));
        }
    }
    Ok(())
}

fn insert_consistent<'a>(
    values: &mut HashMap<&'a str, &'a str>,
    constant: &'a str,
    value: &'a str,
    action_id: &str,
    field: &str,
) -> Result<(), String> {
    if let Some(prior) = values.get(constant)
        && *prior != value
    {
        return Err(format!(
            "action {action_id:?}: {field} {constant:?} maps to both {prior:?} and {value:?}"
        ));
    }
    values.insert(constant, value);
    Ok(())
}

fn validate_action(index: usize, action: &ActionCatalogEntry) -> Result<(), String> {
    let required = [
        ("id", action.id.as_str()),
        ("const_name", action.const_name.as_str()),
        ("provider", action.provider.as_str()),
        ("provider_const", action.provider_const.as_str()),
        ("provider_action", action.provider_action.as_str()),
        (
            "provider_action_const",
            action.provider_action_const.as_str(),
        ),
        ("target_kind", action.target_kind.as_str()),
        ("target_kind_const", action.target_kind_const.as_str()),
        ("target_resolver", action.target_resolver.as_str()),
        ("eligibility_checker", action.eligibility_checker.as_str()),
        ("effect", action.effect.as_str()),
    ];
    for (field, value) in required {
        if value.trim().is_empty() {
            return Err(format!("actions[{index}].{field} is required"));
        }
    }

    let identifiers = [
        ("const_name", action.const_name.as_str()),
        ("provider_const", action.provider_const.as_str()),
        (
            "provider_action_const",
            action.provider_action_const.as_str(),
        ),
        ("target_kind_const", action.target_kind_const.as_str()),
        ("target_resolver", action.target_resolver.as_str()),
        ("eligibility_checker", action.eligibility_checker.as_str()),
    ];
    for (field, value) in identifiers {
        if !is_go_identifier(value) {
            return Err(format!(
                "actions[{index}].{field} = {value:?} is not a Go identifier"
            ));
        }
    }
    Ok(())
}

fn is_go_identifier(value: &str) -> bool {
    let mut bytes = value.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    (first == b'_' || first.is_ascii_alphabetic())
        && bytes.all(|byte| byte == b'_' || byte.is_ascii_alphanumeric())
}

pub fn render_catalog(catalog: &ActionCatalog) -> Result<Vec<u8>, String> {
    let mut output = String::new();
    output.push_str("// Code generated by make graph-action-generate; DO NOT EDIT.\n\n");
    output.push_str("package graphactions\n\n");
    write_string_constants(
        &mut output,
        "Action IDs",
        &action_constants(&catalog.actions),
    );
    write_string_constants(
        &mut output,
        "Target kinds",
        &target_kind_constants(&catalog.actions),
    );
    write_string_slice(
        &mut output,
        "generatedActionIDs",
        &action_constants(&catalog.actions),
    );
    write_string_slice(
        &mut output,
        "generatedProviderIDs",
        &provider_constants(&catalog.actions),
    );
    write_string_slice(
        &mut output,
        "generatedTargetKinds",
        &target_kind_constants(&catalog.actions),
    );
    output.push_str(
        "func DefaultRegistry() Registry {\n\
\tactions := make(map[string]ActionSpec, len(generatedActionSpecs))\n\
\tfor _, spec := range generatedActionSpecs {\n\
\t\tactions[spec.ID] = spec\n\
\t}\n\
\treturn Registry{actions: actions}\n\
}\n\n\
func KnownActionSpecs() []ActionSpec {\n\
\tout := make([]ActionSpec, len(generatedActionSpecs))\n\
\tcopy(out, generatedActionSpecs)\n\
\treturn out\n\
}\n\n\
func KnownActionMetadata() []ActionMetadata {\n\
\tout := make([]ActionMetadata, 0, len(generatedActionSpecs))\n\
\tfor _, spec := range generatedActionSpecs {\n\
\t\tout = append(out, spec.Metadata())\n\
\t}\n\
\treturn out\n\
}\n\n\
func KnownActionIDs() []string {\n\
\tout := make([]string, len(generatedActionIDs))\n\
\tcopy(out, generatedActionIDs)\n\
\treturn out\n\
}\n\n\
func KnownProviderIDs() []string {\n\
\tout := make([]string, len(generatedProviderIDs))\n\
\tcopy(out, generatedProviderIDs)\n\
\treturn out\n\
}\n\n\
func KnownTargetKinds() []string {\n\
\tout := make([]string, len(generatedTargetKinds))\n\
\tcopy(out, generatedTargetKinds)\n\
\treturn out\n\
}\n\n\
var generatedActionSpecs = []ActionSpec{\n",
    );
    for action in &catalog.actions {
        output.push_str("\t{\n");
        output.push_str(&format!("\t\tID: {},\n", action.const_name));
        output.push_str(&format!("\t\tProvider: {},\n", action.provider_const));
        output.push_str(&format!(
            "\t\tProviderAction: {},\n",
            action.provider_action_const
        ));
        output.push_str(&format!("\t\tTargetKind: {},\n", action.target_kind_const));
        output.push_str(&format!("\t\tEffect: {},\n", go_quote(&action.effect)?));
        output.push_str(&format!("\t\tDestructive: {},\n", action.destructive));
        output.push_str(&format!(
            "\t\tReversibleBy: {},\n",
            go_quote(&action.reversible_by)?
        ));
        output.push_str(&format!("\t\tResolveTarget: {},\n", action.target_resolver));
        output.push_str(&format!(
            "\t\tCheckEligibility: {},\n",
            action.eligibility_checker
        ));
        output.push_str("\t},\n");
    }
    output.push_str("}\n");
    gofmt(output.as_bytes())
}

fn go_quote(value: &str) -> Result<String, String> {
    serde_json::to_string(value).map_err(|err| format!("quote Go string: {err}"))
}

fn gofmt(content: &[u8]) -> Result<Vec<u8>, String> {
    let mut child = Command::new("gofmt")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| format!("start gofmt: {err}"))?;
    child
        .stdin
        .take()
        .ok_or_else(|| "open gofmt stdin".to_owned())?
        .write_all(content)
        .map_err(|err| format!("write gofmt input: {err}"))?;
    let result = child
        .wait_with_output()
        .map_err(|err| format!("wait for gofmt: {err}"))?;
    if !result.status.success() {
        return Err(format!(
            "format generated Go: {}\n{}",
            String::from_utf8_lossy(&result.stderr).trim(),
            String::from_utf8_lossy(content)
        ));
    }
    Ok(result.stdout)
}

fn action_constants(actions: &[ActionCatalogEntry]) -> Vec<StringConstant> {
    actions
        .iter()
        .map(|action| StringConstant {
            name: action.const_name.clone(),
            value: action.id.clone(),
        })
        .collect()
}

fn provider_constants(actions: &[ActionCatalogEntry]) -> Vec<StringConstant> {
    let values: BTreeMap<_, _> = actions
        .iter()
        .map(|action| (action.provider_const.clone(), action.provider.clone()))
        .collect();
    values
        .into_iter()
        .map(|(name, value)| StringConstant { name, value })
        .collect()
}

fn target_kind_constants(actions: &[ActionCatalogEntry]) -> Vec<StringConstant> {
    let values: BTreeMap<_, _> = actions
        .iter()
        .map(|action| (action.target_kind_const.clone(), action.target_kind.clone()))
        .collect();
    values
        .into_iter()
        .map(|(name, value)| StringConstant { name, value })
        .collect()
}

fn write_string_constants(output: &mut String, title: &str, constants: &[StringConstant]) {
    if constants.is_empty() {
        return;
    }
    output.push_str(&format!("// {title}.\nconst (\n"));
    for constant in constants {
        output.push_str(&format!(
            "\t{} = {}\n",
            constant.name,
            serde_json::to_string(&constant.value).expect("string serialization cannot fail")
        ));
    }
    output.push_str(")\n\n");
}

fn write_string_slice(output: &mut String, name: &str, constants: &[StringConstant]) {
    if constants.is_empty() {
        return;
    }
    output.push_str(&format!("var {name} = []string{{\n"));
    for constant in constants {
        output.push_str(&format!("\t{},\n", constant.name));
    }
    output.push_str("}\n\n");
}

fn read_bounded_file(path: &Path) -> Result<Vec<u8>, String> {
    let file = File::open(path).map_err(|err| err.to_string())?;
    read_limited(file, "file")
}

pub fn read_generated_file(path: &Path) -> Result<Vec<u8>, String> {
    reject_symlink(path)?;
    let file = open_no_follow(path)?;
    read_limited(file, "generated graph action file")
}

fn read_limited(file: File, label: &str) -> Result<Vec<u8>, String> {
    let mut content = Vec::new();
    file.take((MAX_GENERATED_FILE_BYTES + 1) as u64)
        .read_to_end(&mut content)
        .map_err(|err| err.to_string())?;
    if content.len() > MAX_GENERATED_FILE_BYTES {
        return Err(format!("{label} exceeds {MAX_GENERATED_FILE_BYTES} bytes"));
    }
    Ok(content)
}

#[cfg(unix)]
fn open_no_follow(path: &Path) -> Result<File, String> {
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|err| {
            if err.raw_os_error() == Some(libc::ELOOP) {
                "symlinked generated graph action files are not allowed".to_owned()
            } else {
                err.to_string()
            }
        })
}

#[cfg(not(unix))]
fn open_no_follow(path: &Path) -> Result<File, String> {
    File::open(path).map_err(|err| err.to_string())
}

fn reject_symlink(path: &Path) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            Err("symlinked generated graph action files are not allowed".to_owned())
        }
        Ok(_) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err.to_string()),
    }
}

pub fn write_generated_file(path: &Path, content: &[u8]) -> Result<(), String> {
    reject_symlink(path)?;
    let directory = path
        .parent()
        .ok_or_else(|| format!("{} has no parent directory", path.display()))?;
    fs::create_dir_all(directory).map_err(|err| err.to_string())?;
    let temp_path = temporary_path(path);
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o644);
    }
    let result = (|| {
        let mut file = options.open(&temp_path).map_err(|err| err.to_string())?;
        file.write_all(content).map_err(|err| err.to_string())?;
        file.sync_all().map_err(|err| err.to_string())?;
        fs::set_permissions(&temp_path, permissions_0644()?).map_err(|err| err.to_string())?;
        fs::rename(&temp_path, path).map_err(|err| err.to_string())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp_path);
    }
    result
}

fn temporary_path(path: &Path) -> PathBuf {
    let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("generated");
    path.with_file_name(format!(
        ".{file_name}.tmp-{}-{sequence}",
        std::process::id()
    ))
}

fn permissions_0644() -> Result<fs::Permissions, String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        Ok(fs::Permissions::from_mode(0o644))
    }
    #[cfg(not(unix))]
    {
        Err("graph action generation requires Unix file permissions".to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestDir(PathBuf);

    impl TestDir {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "cerebro-graphactiongen-test-{}-{}",
                std::process::id(),
                TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn action(
        id: &str,
        const_name: &str,
        target_kind: &str,
        target_kind_const: &str,
    ) -> ActionCatalogEntry {
        ActionCatalogEntry {
            id: id.to_owned(),
            const_name: const_name.to_owned(),
            provider: "access-approvals".to_owned(),
            provider_const: "ProviderAccessApprovals".to_owned(),
            provider_action: "suspend".to_owned(),
            provider_action_const: "AccessApprovalsActionSuspend".to_owned(),
            target_kind: target_kind.to_owned(),
            target_kind_const: target_kind_const.to_owned(),
            target_resolver: "OktaUserTargetForFinding".to_owned(),
            eligibility_checker: "FindingAllowsAction".to_owned(),
            effect: "deny_access".to_owned(),
            ..Default::default()
        }
    }

    #[test]
    fn rejects_unknown_reversible_action() {
        let mut entry = action(
            "identity.okta.suspend_user",
            "ActionIdentityOktaSuspendUser",
            "identity.okta.user",
            "TargetKindOktaUser",
        );
        entry.reversible_by = "identity.okta.unsuspend_user".to_owned();
        let error = validate_catalog(&ActionCatalog {
            version: "graph-actions.cerebro/v1alpha1".to_owned(),
            actions: vec![entry],
        })
        .unwrap_err();
        assert!(error.contains("unknown action"), "{error}");
    }

    #[test]
    fn rejects_conflicting_target_kind_constant() {
        let error = validate_catalog(&ActionCatalog {
            version: "graph-actions.cerebro/v1alpha1".to_owned(),
            actions: vec![
                action(
                    "identity.okta.suspend_user",
                    "ActionIdentityOktaSuspendUser",
                    "identity.okta.user",
                    "TargetKindOktaUser",
                ),
                action(
                    "identity.okta.disable_user",
                    "ActionIdentityOktaDisableUser",
                    "identity.okta.account",
                    "TargetKindOktaUser",
                ),
            ],
        })
        .unwrap_err();
        assert!(error.contains("target_kind_const"), "{error}");
    }

    #[test]
    fn rejects_conflicting_provider_constants() {
        let first = action(
            "identity.okta.suspend_user",
            "ActionIdentityOktaSuspendUser",
            "identity.okta.user",
            "TargetKindOktaUser",
        );
        let mut second = action(
            "identity.generic.lock_user",
            "ActionIdentityGenericLockUser",
            "identity.generic.user",
            "TargetKindGenericUser",
        );
        second.provider = "generic-idp".to_owned();
        second.provider_const = first.provider_const.clone();
        let error = validate_catalog(&ActionCatalog {
            version: "graph-actions.cerebro/v1alpha1".to_owned(),
            actions: vec![first, second],
        })
        .unwrap_err();
        assert!(error.contains("provider_const"), "{error}");
    }

    #[test]
    fn rejects_conflicting_provider_action_constants() {
        let first = action(
            "identity.okta.suspend_user",
            "ActionIdentityOktaSuspendUser",
            "identity.okta.user",
            "TargetKindOktaUser",
        );
        let mut second = action(
            "identity.okta.disable_user",
            "ActionIdentityOktaDisableUser",
            "identity.okta.user",
            "TargetKindOktaUser",
        );
        second.provider_action = "disable".to_owned();
        second.provider_action_const = first.provider_action_const.clone();
        let error = validate_catalog(&ActionCatalog {
            version: "graph-actions.cerebro/v1alpha1".to_owned(),
            actions: vec![first, second],
        })
        .unwrap_err();
        assert!(error.contains("provider_action_const"), "{error}");
    }

    #[test]
    fn rejects_duplicate_action_ids_and_invalid_go_identifiers() {
        let first = action(
            "identity.okta.suspend_user",
            "ActionIdentityOktaSuspendUser",
            "identity.okta.user",
            "TargetKindOktaUser",
        );
        let mut duplicate = first.clone();
        duplicate.const_name = "ActionIdentityOktaSuspendUserAgain".to_owned();
        let error = validate_catalog(&ActionCatalog {
            version: "graph-actions.cerebro/v1alpha1".to_owned(),
            actions: vec![first.clone(), duplicate],
        })
        .unwrap_err();
        assert!(error.contains("duplicate action id"), "{error}");

        let mut invalid = first;
        invalid.target_resolver = "not-a-go-identifier".to_owned();
        let error = validate_catalog(&ActionCatalog {
            version: "graph-actions.cerebro/v1alpha1".to_owned(),
            actions: vec![invalid],
        })
        .unwrap_err();
        assert!(error.contains("not a Go identifier"), "{error}");
    }

    #[test]
    fn rejects_oversized_catalog() {
        let root = TestDir::new();
        let path = root.0.join(DEFAULT_CATALOG_PATH);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, vec![b'x'; MAX_GENERATED_FILE_BYTES + 1]).unwrap();
        let error = generate(&root.0, Path::new(DEFAULT_CATALOG_PATH)).unwrap_err();
        assert!(error.contains("exceeds"), "{error}");
    }

    #[cfg(unix)]
    #[test]
    fn generated_file_io_rejects_symlinks() {
        use std::os::unix::fs::symlink;

        let root = TestDir::new();
        let target = root.0.join("target.go");
        fs::write(&target, b"package p\n").unwrap();
        let link = root.0.join("registry_gen.go");
        symlink(&target, &link).unwrap();
        let write_error = write_generated_file(&link, b"package graphactions\n").unwrap_err();
        assert!(write_error.contains("symlink"), "{write_error}");
        let read_error = read_generated_file(&link).unwrap_err();
        assert!(read_error.contains("symlink"), "{read_error}");
    }

    #[cfg(unix)]
    #[test]
    fn generated_file_write_is_atomic_and_sets_mode() {
        use std::os::unix::fs::PermissionsExt;

        let root = TestDir::new();
        let path = root.0.join("nested/registry_gen.go");
        write_generated_file(&path, b"package graphactions\n").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"package graphactions\n");
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o644
        );
        let leftovers = fs::read_dir(path.parent().unwrap())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().contains(".tmp-"))
            .count();
        assert_eq!(leftovers, 0);
    }

    #[test]
    fn checked_in_catalog_matches_generated_registry() {
        let root = Path::new("../..");
        let generated = generate(root, Path::new(DEFAULT_CATALOG_PATH)).unwrap();
        let existing = fs::read(root.join(DEFAULT_OUTPUT_PATH)).unwrap();
        assert_eq!(trim_ascii(&existing), trim_ascii(&generated));
    }

    fn trim_ascii(value: &[u8]) -> &[u8] {
        let start = value
            .iter()
            .position(|byte| !byte.is_ascii_whitespace())
            .unwrap_or(value.len());
        let end = value
            .iter()
            .rposition(|byte| !byte.is_ascii_whitespace())
            .map_or(start, |index| index + 1);
        &value[start..end]
    }
}
