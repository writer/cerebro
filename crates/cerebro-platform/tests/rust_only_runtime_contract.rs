#![forbid(unsafe_code)]

const DOCKERFILE: &str = include_str!("../../../Dockerfile.rust");
const WORKFLOW: &str = include_str!("../../../.github/workflows/rust-only-candidate.yml");
const REPLACEMENT_WORKFLOW: &str =
    include_str!("../../../.github/workflows/rust-graph-replacement.yml");
const PLATFORM_SOURCE: &str = include_str!("../src/main.rs");
const REPLACEMENT_DRIVER: &str = include_str!("../examples/organizational_graph_e2e.rs");
const WORKSPACE_MANIFEST: &str = include_str!("../../../Cargo.toml");
const WORKSPACE_LOCK: &str = include_str!("../../../Cargo.lock");
const MAKEFILE: &str = include_str!("../../../Makefile");
const RUST_CODEGEN: &str = include_str!("../../../buf.gen.rust.yaml");
const QUALIFICATION_SCRIPT: &str = include_str!("../../../scripts/qualify-rust-graph.sh");
const CONNECTRPC_REVISION: &str = "8b3c3b05d3b54af547477a9e3b3a77d62f68e229";
const BUFFA_VERSION: &str = "0.9.1";

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
        "ADD --checksum=sha256:e5bb2084ccf45087bda1c9bffdea0eb15ee67f0b91646106e466714f9de3c7e3",
        "https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem",
        "apk add --no-cache ca-certificates openssl",
        "/usr/local/share/ca-certificates/aws-rds-root-%03d.crt",
        "if (certificate != 108) exit 1",
        "test \"${subject#subject=}\" = \"${issuer#issuer=}\" || exit 1",
        "openssl verify -CAfile \"${certificate}\" \"${certificate}\" || exit 1",
        "CN=Amazon RDS \"*\" Root CA RSA2048 G1",
        "CN=Amazon RDS \"*\" Root CA RSA4096 G1",
        "CN=Amazon RDS \"*\" Root CA ECC384 G1",
        "update-ca-certificates",
        "/usr/local/bin/cerebro-event-admission-worker",
        "/usr/local/bin/cerebro-platform",
        "ENTRYPOINT [\"/usr/local/bin/cerebro-platform\"]",
        "CMD [\"serve-neo4j-consumer\"]",
        "http://127.0.0.1:8080/healthz",
    ] {
        assert!(
            DOCKERFILE.contains(required),
            "Rust runtime Dockerfile is missing {required:?}"
        );
    }
    for forbidden in [
        "danger_accept_invalid_certs",
        "danger_accept_invalid_hostnames",
        "sslmode=disable",
    ] {
        assert!(
            !DOCKERFILE.contains(forbidden),
            "Rust runtime Dockerfile weakens TLS verification with {forbidden:?}"
        );
    }
    assert_eq!(
        DOCKERFILE.matches("-nameopt RFC2253)\" || exit 1").count(),
        2,
        "Rust runtime must fail closed when either certificate identity cannot be parsed"
    );
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
        "test ! -e /usr/local/go/bin/go",
        "test ! -e /usr/bin/go",
        "test ! -e /bin/go",
        "Run the candidate through its declared Rust entrypoint",
        "cargo +1.93.1 run --locked -p cerebro-platform --example organizational_graph_e2e -- seed",
        "cargo +1.93.1 run --locked -p cerebro-platform --example organizational_graph_e2e -- verify",
        r#"test "$(jq -r .sources <<<"${summary}")" -eq 799"#,
        r#"test "$(jq -r .families <<<"${summary}")" -eq 3973"#,
        r#"evidence:"799 sources and 3973 families loaded""#,
        "cerebro.rust-only-e2e/v1",
        "cerebro.rust-only-candidate/v1",
    ] {
        assert!(
            WORKFLOW.contains(required),
            "Rust-only candidate workflow is missing {required:?}"
        );
    }
}

#[test]
fn graph_qualification_stays_on_retired_rust_authority_path() {
    for required in [
        "export CEREBRO_RUST_READ_MODE=authority",
        "cmp \"${output_dir}/authority-graph-response-after-restart.canonical.json\"",
        "assert_status 503 graph-authority-without-rust",
    ] {
        assert!(
            QUALIFICATION_SCRIPT.contains(required),
            "Rust graph qualification is missing retired authority setup {required:?}"
        );
    }
    for forbidden in [
        "CEREBRO_RUST_READ_MODE=canary",
        "CEREBRO_RUST_SHADOW_PERCENT",
        "CEREBRO_RUST_AUTHORITY_PERCENT",
        "CEREBRO_RUST_CANARY_VERIFY_PERCENT",
        "go_canary",
        "rust_canary",
        "CEREBRO_RUST_CANARY_API_KEYS",
        "stable_authority_canary",
        "verified_canary_restart",
        "canary_legacy_isolation",
        "canary_rust_fail_closed",
    ] {
        assert!(
            !QUALIFICATION_SCRIPT.contains(forbidden),
            "Rust graph qualification retained removed Go canary setup {forbidden:?}"
        );
    }
}

#[test]
fn replacement_proof_is_a_native_rust_product_path() {
    for forbidden in [
        "actions/setup-go",
        "go build",
        "go test",
        "make build-go",
        "./bin/cerebro serve",
        "CEREBRO_GRAPH_STORE_DRIVER",
        "CEREBRO_NEO4J_DATABASE",
        "TestQueryStoreAgainstLiveRustGraph",
    ] {
        assert!(
            !REPLACEMENT_WORKFLOW.contains(forbidden),
            "Rust replacement workflow contains forbidden non-Rust path {forbidden:?}"
        );
    }
    for required in [
        "name: Rust-only persisted product read",
        "--target replacement-test-runtime",
        "test ! -e /usr/local/bin/cerebro",
        "test ! -e /usr/local/go/bin/go",
        "test ! -e /usr/bin/go",
        "test ! -e /bin/go",
        "--entrypoint /usr/local/bin/organizational-graph-e2e",
        "CEREBRO_ORGANIZATIONAL_CONSUMER_DELIVER_POLICY=by_start_sequence",
        "CEREBRO_ORGANIZATIONAL_CONSUMER_START_SEQUENCE=1",
        "docker restart cerebro-rust-graph-platform",
        "receipt.json)\" -eq 14",
    ] {
        assert!(
            REPLACEMENT_WORKFLOW.contains(required),
            "Rust replacement workflow is missing proof {required:?}"
        );
    }
    for required in [
        "\"/platform/graph/neighborhood\"",
        "get(product_neighborhood_route)",
        "normalize_product_neighborhood_limit",
        "product_urn_tenant",
        "invalid_product_neighborhood",
    ] {
        assert!(
            PLATFORM_SOURCE.contains(required),
            "Rust platform is missing product boundary {required:?}"
        );
    }
    for required in [
        "product_http_contract",
        "rust_service_runtime",
        "require_product_neighborhood",
    ] {
        assert!(
            REPLACEMENT_DRIVER.contains(required),
            "Rust replacement driver is missing runtime assertion {required:?}"
        );
    }
}

#[test]
fn functional_recovery_driver_does_not_inspect_the_runner_runtime() {
    for forbidden in [
        "prove_rust_only_runtime",
        "\"/usr/local/bin/cerebro\"",
        "\"/usr/local/go/bin/go\"",
        "\"/usr/bin/go\"",
        "\"/bin/go\"",
    ] {
        assert!(
            !REPLACEMENT_DRIVER.contains(forbidden),
            "functional recovery driver inspects its execution host via {forbidden:?}"
        );
    }
}

#[test]
fn generated_rpc_runtime_and_codegen_are_pinned_together() {
    for required in [
        &format!(
            "connectrpc = {{ git = \"https://github.com/connectrpc/connect-rust.git\", rev = \"{CONNECTRPC_REVISION}\""
        ),
        &format!("buffa = {{ version = \"={BUFFA_VERSION}\""),
        &format!("buffa-types = {{ version = \"={BUFFA_VERSION}\""),
    ] {
        assert!(
            WORKSPACE_MANIFEST.contains(required),
            "Rust workspace manifest is missing exact RPC dependency pin {required:?}"
        );
    }
    for required in [
        &format!("CONNECTRPC_CODEGEN_REV := {CONNECTRPC_REVISION}"),
        &format!("--version {BUFFA_VERSION}"),
        "--rev $(CONNECTRPC_CODEGEN_REV)",
        "--template buf.gen.rust.yaml",
    ] {
        assert!(
            MAKEFILE.contains(required),
            "Rust RPC codegen is missing exact generator pin {required:?}"
        );
    }
    for required in [
        "local: protoc-gen-buffa",
        "local: protoc-gen-connect-rust",
        "buffa_module=crate::rpc::proto",
    ] {
        assert!(
            RUST_CODEGEN.contains(required),
            "Rust RPC codegen invokes an unapproved generator path or is missing {required:?}"
        );
    }
    assert!(
        WORKSPACE_LOCK.contains(&format!(
            "source = \"git+https://github.com/connectrpc/connect-rust.git?rev={CONNECTRPC_REVISION}#{CONNECTRPC_REVISION}\""
        )),
        "Cargo.lock does not resolve ConnectRPC to the generator commit"
    );
    for package in ["buffa", "buffa-types"] {
        let marker = format!(
            "name = \"{package}\"\nversion = \"{BUFFA_VERSION}\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\""
        );
        assert!(
            WORKSPACE_LOCK.contains(&marker),
            "Cargo.lock does not resolve {package} to {BUFFA_VERSION}"
        );
    }
}
