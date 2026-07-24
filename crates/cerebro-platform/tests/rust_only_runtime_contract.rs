#![forbid(unsafe_code)]

const DOCKERFILE: &str = include_str!("../../../Dockerfile.rust");
const WORKFLOW: &str = include_str!("../../../.github/workflows/rust-only-candidate.yml");

#[test]
fn rust_runtime_image_has_no_go_executable_path() {
    for forbidden in [
        "actions/setup-go",
        "COPY --from=source --chmod=0755 /src/.dist/cerebro",
        "ENTRYPOINT [\"/usr/local/bin/cerebro\"]",
        "Dockerfile.runtime",
    ] {
        assert!(
            !DOCKERFILE.contains(forbidden),
            "Rust runtime Dockerfile contains forbidden Go path {forbidden:?}"
        );
    }
    assert!(
        !contains_word_pair(DOCKERFILE, "go", "build"),
        "Rust runtime Dockerfile invokes go build"
    );
    for required in [
        "cerebro-platform --bin cerebro-platform",
        "/usr/local/bin/cerebro-event-admission-worker",
        "/usr/local/bin/cerebro-platform",
        "ENTRYPOINT [\"/usr/local/bin/cerebro-platform\"]",
        "CMD [\"serve-neo4j-consumer\"]",
        "http://127.0.0.1:8080/readyz",
    ] {
        assert!(
            DOCKERFILE.contains(required),
            "Rust runtime Dockerfile is missing {required:?}"
        );
    }
}

fn contains_word_pair(input: &str, first: &str, second: &str) -> bool {
    input
        .split_whitespace()
        .collect::<Vec<_>>()
        .windows(2)
        .any(|pair| pair == [first, second])
}

#[test]
fn rust_candidate_build_never_invokes_go_or_emulation() {
    for forbidden in [
        "actions/setup-go",
        "go build",
        "go test",
        "Dockerfile.runtime",
        "docker/setup-qemu-action",
        "--entrypoint /usr/local/bin/cerebro-platform",
    ] {
        assert!(
            !WORKFLOW.contains(forbidden),
            "Rust-only candidate workflow contains forbidden path {forbidden:?}"
        );
    }
    for required in [
        "name: Rust-only Candidate",
        "runner: ubuntu-24.04-arm",
        "file: Dockerfile.rust",
        "ghcr.io/${{ github.repository_owner }}/cerebro-rust",
        "Assert the candidate contains no Go server",
        "Run the candidate through its declared Rust entrypoint",
        "cerebro.rust-only-e2e/v1",
        "cerebro.rust-only-candidate/v1",
    ] {
        assert!(
            WORKFLOW.contains(required),
            "Rust-only candidate workflow is missing {required:?}"
        );
    }
}
