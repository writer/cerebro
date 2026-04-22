#!/usr/bin/env bash
set -euo pipefail

export PATH="${GOPATH:-$HOME/go}/bin:$PATH"

STAGED_PATHS=()
while IFS= read -r path; do
  if [ -n "$path" ]; then
    STAGED_PATHS+=("$path")
  fi
done <<< "$(git diff --cached --name-only --diff-filter=ACM | grep -v '^vendor/' || true)"

STAGED_FILES=()
while IFS= read -r path; do
  if [ -n "$path" ]; then
    STAGED_FILES+=("$path")
  fi
done <<< "$(git diff --cached --name-only --diff-filter=ACM -- '*.go' | grep -v '^vendor/' || true)"

GRAPH_ID_SAFETY_FILES=()
if [ "${#STAGED_FILES[@]}" -gt 0 ]; then
  for path in "${STAGED_FILES[@]}"; do
    if [[ "$path" == *_test.go ]]; then
      continue
    fi
    GRAPH_ID_SAFETY_FILES+=("$path")
  done
fi

has_staged_path_matching() {
  local pattern="$1"
  if [ "${#STAGED_PATHS[@]}" -eq 0 ]; then
    return 1
  fi
  printf '%s\n' "${STAGED_PATHS[@]}" | grep -Eq "$pattern"
}

run_without_git_local_env() {
  local env_cmd=(env)
  local git_var
  while IFS= read -r git_var; do
    if [ -n "$git_var" ]; then
      env_cmd+=("-u" "$git_var")
    fi
  done < <(git rev-parse --local-env-vars)
  "${env_cmd[@]}" "$@"
}

if [ "${#STAGED_FILES[@]}" -gt 0 ]; then
  UNFORMATTED=$(gofmt -l "${STAGED_FILES[@]}" 2>/dev/null || true)
  if [ -n "$UNFORMATTED" ]; then
    echo "gofmt: fixing staged Go files..."
    gofmt -w ${UNFORMATTED}
    git add ${UNFORMATTED}
  fi

  STAGED_PACKAGE_DIRS=()
  for file in "${STAGED_FILES[@]}"; do
    dir="$(dirname "$file")"
    if [ "$dir" = "." ]; then
      dir="./"
    elif [[ "$dir" != ./* && "$dir" != /* ]]; then
      dir="./$dir"
    fi
    STAGED_PACKAGE_DIRS+=("$dir")
  done

  UNIQUE_PACKAGE_DIRS=()
  while IFS= read -r dir; do
    if [ -n "$dir" ]; then
      UNIQUE_PACKAGE_DIRS+=("$dir")
    fi
  done <<< "$(printf '%s\n' "${STAGED_PACKAGE_DIRS[@]}" | sort -u)"
  STAGED_PACKAGE_DIRS=("${UNIQUE_PACKAGE_DIRS[@]}")

  FILTERED_PACKAGE_DIRS=()
  for dir in "${STAGED_PACKAGE_DIRS[@]}"; do
    list_dir="$dir"
    if [[ "$list_dir" != ./* && "$list_dir" != /* ]]; then
      list_dir="./$list_dir"
    fi
    if output=$(run_without_git_local_env go list "$list_dir" 2>&1); then
      FILTERED_PACKAGE_DIRS+=("$list_dir")
      continue
    fi
    if [[ "$output" == *"build constraints exclude all Go files"* ]]; then
      continue
    fi
    # Nested Go modules (e.g. tools/linters) are intentionally outside
    # the main module. Skip them here; they are validated via their own
    # make targets (see Makefile: check-structural).
    if [[ "$output" == *"main module ("*") does not contain package"* ]]; then
      continue
    fi
    echo "$output"
    exit 1
  done

  if [ "${#FILTERED_PACKAGE_DIRS[@]}" -gt 0 ]; then
    echo "go vet: running on staged package directories..."
    run_without_git_local_env go vet "${FILTERED_PACKAGE_DIRS[@]}"

    echo "go test: running on staged package directories..."
    run_without_git_local_env go test "${FILTERED_PACKAGE_DIRS[@]}"

    if ! command -v golangci-lint >/dev/null 2>&1; then
      echo "golangci-lint not found. Install with: go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest"
      exit 1
    fi

    echo "golangci-lint: running fast checks on staged Go files..."
    run_without_git_local_env golangci-lint run --fast-only --timeout 2m "${FILTERED_PACKAGE_DIRS[@]}"
  fi

  if [ "${#GRAPH_ID_SAFETY_FILES[@]}" -gt 0 ]; then
    echo "graph-id-safety: checking staged Go files..."
    run_without_git_local_env go run ./scripts/check_graph_id_safety/main.go -- "${GRAPH_ID_SAFETY_FILES[@]}"
  fi
fi

echo "contract-compat: checking API contract..."
run_without_git_local_env go run ./scripts/check_api_contract_compat/main.go

echo "contract-compat: checking CloudEvents contract..."
run_without_git_local_env go run ./scripts/check_cloudevents_contract_compat/main.go

echo "contract-compat: checking report contract..."
run_without_git_local_env go run ./scripts/check_report_contract_compat/main.go

echo "contract-compat: checking entity facet contract..."
run_without_git_local_env go run ./scripts/check_entity_facet_compat/main.go

echo "contract-compat: checking agent SDK contract..."
run_without_git_local_env go run ./scripts/check_agent_sdk_contract_compat/main.go

echo "graph-ontology: checking mapper guardrails..."
run_without_git_local_env go test ./internal/graphingest -run 'TestMapperContractFixtures|TestMapperSourceDomainCoverageGuardrails' -count=1
