use cerebro_migrator::{GoPackageGraph, MigratorError};

const MODULE: &str = "github.com/writer/cerebro";

fn package(path: &str, imports: &[&str], files: &[&str]) -> String {
    serde_json::json!({
        "Dir": format!("/repo/{path}"),
        "ImportPath": path,
        "Module": {"Path": MODULE},
        "Imports": imports,
        "GoFiles": files,
    })
    .to_string()
}

#[test]
fn ingests_repository_packages_and_condenses_import_cycles() {
    let packages = [
        package(
            "github.com/writer/cerebro/a",
            &["github.com/writer/cerebro/b", "fmt"],
            &["a.go"],
        ),
        package(
            "github.com/writer/cerebro/b",
            &["github.com/writer/cerebro/a"],
            &["b.go", "b_test.go"],
        ),
        package(
            "github.com/writer/cerebro/c",
            &["github.com/writer/cerebro/b"],
            &["c.go"],
        ),
        serde_json::json!({"ImportPath":"fmt", "Standard":true}).to_string(),
        serde_json::json!({
            "Dir":"/external/x",
            "ImportPath":"example.com/x",
            "Module":{"Path":"example.com/x"},
            "GoFiles":["x.go"]
        })
        .to_string(),
    ];
    let stream = packages.join("\n");

    let graph = GoPackageGraph::from_go_list_json(stream.as_bytes(), Some(MODULE)).unwrap();
    assert_eq!(graph.packages().len(), 3);
    assert_eq!(
        graph.packages()["github.com/writer/cerebro/a"].imports(),
        &["github.com/writer/cerebro/b"]
    );

    let condensed = graph.condense().unwrap();
    assert_eq!(condensed.components().len(), 2);
    let cycle = condensed
        .components()
        .iter()
        .find(|component| component.packages().len() == 2)
        .unwrap();
    assert_eq!(
        cycle.packages(),
        &["github.com/writer/cerebro/a", "github.com/writer/cerebro/b"]
    );
    assert_eq!(cycle.source_file_count(), 3);
    let caller = condensed
        .components()
        .iter()
        .find(|component| component.packages() == ["github.com/writer/cerebro/c"])
        .unwrap();
    assert_eq!(caller.dependencies(), &[cycle.id()]);
}

#[test]
fn graph_and_condensation_are_independent_of_input_order() {
    let a = package(
        "github.com/writer/cerebro/a",
        &["github.com/writer/cerebro/b"],
        &["a.go"],
    );
    let b = package("github.com/writer/cerebro/b", &[], &["b.go"]);
    let first =
        GoPackageGraph::from_go_list_json(format!("{a}\n{b}").as_bytes(), Some(MODULE)).unwrap();
    let second =
        GoPackageGraph::from_go_list_json(format!("{b}\n{a}").as_bytes(), Some(MODULE)).unwrap();
    assert_eq!(first.graph_digest(), second.graph_digest());
    assert_eq!(first.condense().unwrap(), second.condense().unwrap());
}

#[test]
fn go_list_errors_fail_closed() {
    let input = serde_json::json!({
        "ImportPath":"github.com/writer/cerebro/broken",
        "Error":{"Err":"missing generated package"}
    })
    .to_string();
    let error = GoPackageGraph::from_go_list_json(input.as_bytes(), Some(MODULE)).unwrap_err();
    assert_eq!(
        error,
        MigratorError::GoListPackage {
            package: "github.com/writer/cerebro/broken".to_owned(),
            error: "missing generated package".to_owned(),
        }
    );
}
