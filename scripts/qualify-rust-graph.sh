#!/usr/bin/env bash

set -euo pipefail

: "${CEREBRO_IMAGE:?set CEREBRO_IMAGE to the exact Go candidate}"
: "${CEREBRO_RUST_IMAGE:?set CEREBRO_RUST_IMAGE to the exact Rust candidate}"
: "${CEREBRO_QUALIFICATION_SHA:?set CEREBRO_QUALIFICATION_SHA to the exact source commit}"

readonly repository_root="${CEREBRO_REPOSITORY_ROOT:-$(pwd)}"
readonly output_dir="${CEREBRO_QUALIFICATION_OUTPUT:-${repository_root}/.dist/pr-rust-graph}"
readonly compose_project="${COMPOSE_PROJECT_NAME:-cerebro-rust-graph-${RANDOM}}"
readonly soak_seconds="${SOAK_SECONDS:-60}"
readonly rust_graph_port="${CEREBRO_RUST_PORT:-18081}"
readonly rust_graph_base="http://127.0.0.1:${rust_graph_port}"
readonly go_api_base="http://127.0.0.1:8080"
readonly graph_tenant="rust-e2e"
graph_secret="$(openssl rand -hex 32)"
readonly graph_secret
readonly auth_header_name="Authorization"
readonly auth_scheme="Bearer"
readonly checkpoint="${output_dir}/checkpoint.json"
readonly organizational_receipt="${output_dir}/organizational-receipt.json"
readonly qualification_receipt="${output_dir}/receipt.json"
readonly portable_smoke_receipt="${output_dir}/smoke-receipt.json"
readonly service_logs="${output_dir}/service-logs.txt"
readonly compose_files=(-f "${repository_root}/docker-compose.yml" -f "${repository_root}/docker-compose.rust.yml")

source "${repository_root}/scripts/lib/rust-tenant-auth.sh"
graph_bearer="$(cerebro_rust_tenant_bearer "${graph_secret}" "${graph_tenant}")"
readonly graph_bearer

if ! [[ "${CEREBRO_QUALIFICATION_SHA}" =~ ^[0-9a-f]{40}$ ]]; then
  echo "CEREBRO_QUALIFICATION_SHA must be an exact 40-character commit" >&2
  exit 1
fi
if ! [[ "${soak_seconds}" =~ ^[0-9]+$ ]] || ((soak_seconds < 60 || soak_seconds > 1800)); then
  echo "SOAK_SECONDS must be between 60 and 1800" >&2
  exit 1
fi
if ! [[ "${rust_graph_port}" =~ ^[0-9]+$ ]] ||
  ((rust_graph_port < 1 || rust_graph_port > 65535)); then
  echo "CEREBRO_RUST_PORT must be a valid TCP port" >&2
  exit 1
fi

mkdir -p "${output_dir}"
export COMPOSE_PROJECT_NAME="${compose_project}"
export CEREBRO_RUST_COMMAND=serve-neo4j-consumer
export CEREBRO_RUST_READ_MODE=authority
export CEREBRO_RUST_GRAPH_SECRET="${graph_secret}"
export CEREBRO_RUST_PORT="${rust_graph_port}"

cleanup() {
  local exit_code=$?
  docker compose "${compose_files[@]}" unpause >/dev/null 2>&1 || true
  docker compose "${compose_files[@]}" logs --no-color >"${service_logs}" 2>&1 || true
  docker compose "${compose_files[@]}" down --volumes --remove-orphans >/dev/null 2>&1 || true
  return "${exit_code}"
}
trap cleanup EXIT

docker compose "${compose_files[@]}" up -d --wait --wait-timeout 180

runtime_image_id="$(docker image inspect --format '{{.Id}}' "${CEREBRO_RUST_IMAGE}")"
if ! [[ "${runtime_image_id}" =~ ^sha256:[0-9a-f]{64}$ ]]; then
  echo "Rust runtime image ID is not a digest: ${runtime_image_id}" >&2
  exit 1
fi

run_harness() {
  local operation="$1"
  CEREBRO_TEST_POSTGRES_DSN='postgres://cerebro:cerebro@127.0.0.1:5432/cerebro?sslmode=disable' \
  CEREBRO_TEST_NEO4J_URI='bolt://127.0.0.1:7687' \
  CEREBRO_TEST_NEO4J_USERNAME=neo4j \
  CEREBRO_TEST_NEO4J_PASSWORD=local-password \
  CEREBRO_TEST_NATS_URL='nats://127.0.0.1:4222' \
  CEREBRO_TEST_GRAPH_URL="${rust_graph_base}" \
  CEREBRO_ORGANIZATIONAL_GRAPH_SHARED_SECRET="${graph_secret}" \
  CEREBRO_TEST_COMMIT="${CEREBRO_QUALIFICATION_SHA}" \
  CEREBRO_TEST_IMAGE="${CEREBRO_RUST_IMAGE}" \
  CEREBRO_TEST_IMAGE_DIGEST="${runtime_image_id}" \
  CEREBRO_TEST_RUNTIME_IMAGE_ID="${runtime_image_id}" \
  CEREBRO_TEST_PLATFORM="${CEREBRO_QUALIFICATION_PLATFORM:-linux/arm64}" \
  CEREBRO_TEST_CHECKPOINT="${checkpoint}" \
  CEREBRO_TEST_RECEIPT="${organizational_receipt}" \
  CEREBRO_REPOSITORY_ROOT="${repository_root}" \
    cargo +1.93.1 run --locked --manifest-path "${repository_root}/Cargo.toml" \
      -p cerebro-platform --example organizational_graph_e2e -- "${operation}"
}

run_harness seed

validate_entity_id() {
  local label="$1"
  local value="$2"
  if [ "${value}" = "null" ] ||
    ((${#value} == 0 || ${#value} > 256)) ||
    ! [[ "${value}" =~ ^[A-Za-z0-9._:/-]+$ ]]; then
    echo "${label} is not a valid organizational entity ID" >&2
    return 1
  fi
}

root_id="$(jq -er '.okta_identity_id | select(type == "string")' "${checkpoint}")"
canonical_id="$(jq -er '.canonical_identity_id | select(type == "string")' "${checkpoint}")"
validate_entity_id okta_identity_id "${root_id}"
validate_entity_id canonical_identity_id "${canonical_id}"
root_urn="urn:cerebro:rust-e2e:organizational_entity:${root_id}"
canonical_urn="urn:cerebro:rust-e2e:organizational_entity:${canonical_id}"
encoded_root="$(jq -rn --arg value "${root_urn}" '$value|@uri')"
graph_url="${rust_graph_base}/platform/graph/neighborhood?root_urn=${encoded_root}&limit=10"
retired_go_graph_url="${go_api_base}/platform/graph/neighborhood?root_urn=${encoded_root}&limit=10"

neo4j_container="$(docker compose "${compose_files[@]}" ps -q neo4j)"
test -n "${neo4j_container}"
docker exec "${neo4j_container}" cypher-shell -u neo4j -p local-password \
  --param "root_urn => '${root_urn}'" \
  --param "canonical_urn => '${canonical_urn}'" \
  'MERGE (root:Entity {urn: $root_urn})
   SET root.tenant_id = "rust-e2e",
       root.entity_type = "identity",
       root.label = "Person One"
   MERGE (canonical:Entity {urn: $canonical_urn})
   SET canonical.tenant_id = "rust-e2e",
       canonical.entity_type = "person",
       canonical.label = "Person One"
   MERGE (root)-[relation:RELATION {relation: "represents"}]->(canonical)
   SET relation.attributes_json =
     "{\"identity_binding\":\"true\",\"source_runtime_id\":\"okta-e2e\"}"'

request_status() {
  local output="$1"
  local url="$2"
  local api_key="${3:-local-dev-key}"
  local tenant="${4:-}"
  local headers=(--header "${auth_header_name}: ${auth_scheme} ${api_key}")
  if [[ -n "${tenant}" ]]; then
    headers+=(--header "X-Cerebro-Tenant: ${tenant}")
  fi
  : >"${output}"
  curl --max-time 10 --silent --show-error --output "${output}" \
    --write-out '%{http_code} %{time_total}' \
    "${headers[@]}" \
    "${url}"
}

assert_status() {
  local expected="$1"
  local label="$2"
  local output="$3"
  local url="$4"
  local api_key="${5:-local-dev-key}"
  local tenant="${6:-}"
  local observed
  observed="$(request_status "${output}" "${url}" "${api_key}" "${tenant}" || true)"
  echo "${label}: ${observed}"
  if [[ "${observed%% *}" != "${expected}" ]]; then
    cat "${output}" >&2 || true
    return 1
  fi
}

assert_status 200 readiness-before "${output_dir}/readiness.json" "${go_api_base}/health"
assert_status 404 retired-go-graph-before "${output_dir}/retired-go-graph-response.txt" \
  "${retired_go_graph_url}"
assert_status 200 graph-before "${output_dir}/graph-response.json" "${graph_url}" \
  "${graph_bearer}" "${graph_tenant}"
jq -e --arg root "${root_urn}" '
  .root.urn == $root
  and ([.relations[] | select(.relation == "represents")] | length) >= 1
' "${output_dir}/graph-response.json" >/dev/null
jq -S . "${output_dir}/graph-response.json" >"${output_dir}/authority-graph-response.json"

deadline=$((SECONDS + soak_seconds))
request_count=0
: >"${output_dir}/authority-statuses.txt"
while ((SECONDS < deadline)); do
  seq 1 2 | xargs -P 2 -I{} curl \
    --max-time 10 \
    --silent \
    --show-error \
    --output /dev/null \
    --write-out '%{http_code}\n' \
    --header "${auth_header_name}: ${auth_scheme} ${graph_bearer}" \
    --header "X-Cerebro-Tenant: ${graph_tenant}" \
    "${graph_url}" >>"${output_dir}/authority-statuses.txt" || true
  request_count=$((request_count + 2))
  sleep 1
done
observed_count="$(wc -l <"${output_dir}/authority-statuses.txt" | tr -d ' ')"
matching_count="$(grep -c '^200$' "${output_dir}/authority-statuses.txt" || true)"
test "${observed_count}" -eq "${request_count}"
test "${matching_count}" -eq "${request_count}"

rust_container="$(docker compose "${compose_files[@]}" ps -q rust-platform)"
test -n "${rust_container}"
docker restart "${rust_container}" >/dev/null
for attempt in $(seq 1 36); do
  if docker inspect --format '{{.State.Health.Status}}' "${rust_container}" | grep -qx healthy; then
    break
  fi
  test "${attempt}" -lt 36
  sleep 5
done
assert_status 200 readiness-after-restart "${output_dir}/readiness.json" "${go_api_base}/health"
assert_status 200 graph-after-restart \
  "${output_dir}/authority-graph-response-after-restart.json" "${graph_url}" \
  "${graph_bearer}" "${graph_tenant}"
jq -S . "${output_dir}/authority-graph-response-after-restart.json" \
  >"${output_dir}/authority-graph-response-after-restart.canonical.json"
cmp "${output_dir}/authority-graph-response.json" \
  "${output_dir}/authority-graph-response-after-restart.canonical.json"

run_harness verify
test "$(jq -r .schema_version "${organizational_receipt}")" = \
  "cerebro.rust-organizational-e2e/v1"
test "$(jq -r .status "${organizational_receipt}")" = passed
test "$(jq '[.checks[] | select(.status == "passed")] | length' "${organizational_receipt}")" -eq 14

export CEREBRO_RUST_READ_MODE=authority
docker compose "${compose_files[@]}" up -d --force-recreate --wait cerebro
assert_status 200 readiness-authority "${output_dir}/readiness.json" "${go_api_base}/health"
assert_status 200 graph-authority "${output_dir}/authority-graph-response.json" "${graph_url}" \
  "${graph_bearer}" "${graph_tenant}"
jq -S . "${output_dir}/authority-graph-response.json" \
  >"${output_dir}/authority-graph-response.canonical.json"
cmp "${output_dir}/authority-graph-response-after-restart.canonical.json" \
  "${output_dir}/authority-graph-response.canonical.json"

rust_container="$(docker compose "${compose_files[@]}" ps -q rust-platform)"
test -n "${rust_container}"
docker stop "${rust_container}" >/dev/null
assert_status 503 readiness-authority-without-rust \
  "${output_dir}/readiness.json" "${go_api_base}/health"
assert_status 000 rust-graph-authority-without-rust \
  "${output_dir}/graph-response.json" "${graph_url}" "${graph_bearer}" "${graph_tenant}"
assert_status 404 retired-go-graph-without-rust \
  "${output_dir}/retired-go-graph-response.txt" "${retired_go_graph_url}"

jq \
  --arg schema_version "cerebro.pr-rust-graph/v1" \
  --argjson authority_requests "${request_count}" \
  '.schema_version = $schema_version
   | .authority_requests = $authority_requests
   | .checks += [
       {
         name: "rust_authority_soak",
         status: "passed",
         evidence: (($authority_requests | tostring) + " direct Rust-authority product graph reads returned 200")
       },
       {
         name: "rust_authority_restart",
         status: "passed",
         evidence: "the direct Rust product response remained identical after a Rust process restart"
       },
       {
         name: "authority_fail_closed",
         status: "passed",
         evidence: "Go readiness returned 503, the Rust product listener was unavailable, and the retired Go graph route remained 404 when Rust authority was stopped"
       }
     ]' "${organizational_receipt}" >"${qualification_receipt}"

test "$(jq -r .schema_version "${qualification_receipt}")" = "cerebro.pr-rust-graph/v1"
test "$(jq -r .status "${qualification_receipt}")" = passed
test "$(jq '[.checks[] | select(.status == "passed")] | length' "${qualification_receipt}")" -eq 17

if [ -n "${CEREBRO_SMOKE_RUNTIME_IMAGE:-}" ]; then
  CEREBRO_SMOKE_SOURCE_RECEIPT="${qualification_receipt}" \
  CEREBRO_SMOKE_OUTPUT="${portable_smoke_receipt}" \
  CEREBRO_SMOKE_CANDIDATE_COMMIT="${CEREBRO_QUALIFICATION_SHA}" \
  CEREBRO_SMOKE_SOAK_SECONDS="${soak_seconds}" \
    "${repository_root}/scripts/release/render_smoke_receipt.sh"
fi
echo "Rust PR graph qualification passed with ${request_count} authority reads"
