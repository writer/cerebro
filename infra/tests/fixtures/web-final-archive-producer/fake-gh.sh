#!/usr/bin/env bash

set -euo pipefail

[[ "$#" == 2 && "$1" == "api" ]] || exit 64
[[ -d "${FAKE_GH_FIXTURE_DIR:-}" ]] || exit 65
if [[ -n "${FAKE_GH_CALL_LOG:-}" ]]; then
  printf '%s\t%s\n' "$1" "$2" >>"${FAKE_GH_CALL_LOG}"
fi

case "$2" in
  "repos/writer/cerebro-web"|"repos/WriterInternal/cerebro-web") file="source-repository.json" ;;
  "repos/writer/cerebro-web/git/ref/heads/main"|"repos/WriterInternal/cerebro-web/git/ref/heads/main") file="source-ref.json" ;;
  "repos/writer/cerebro-web/git/commits/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"|"repos/WriterInternal/cerebro-web/git/commits/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") file="source-commit.json" ;;
  "repos/writer/cerebro-web/pulls?state=open&per_page=1"|"repos/WriterInternal/cerebro-web/pulls?state=open&per_page=1") file="pulls.json" ;;
  "repos/writer/cerebro-web/issues?state=open&per_page=1"|"repos/WriterInternal/cerebro-web/issues?state=open&per_page=1") file="issues.json" ;;
  "repos/writer/cerebro-web/contents/.github/workflows/legacy-freeze.yml?ref=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"|"repos/WriterInternal/cerebro-web/contents/.github/workflows/legacy-freeze.yml?ref=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") file="freeze-workflow.json" ;;
  "repos/writer/cerebro-web/rulesets"|"repos/WriterInternal/cerebro-web/rulesets") file="rulesets.json" ;;
  "repos/writer/cerebro-web/rulesets/1"|"repos/WriterInternal/cerebro-web/rulesets/1") file="ruleset.json" ;;
  "repos/writer/cerebro-web/commits/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/status"|"repos/WriterInternal/cerebro-web/commits/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/status") file="status.json" ;;
  "repos/writer/cerebro-web/git/trees/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb?recursive=1"|"repos/WriterInternal/cerebro-web/git/trees/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb?recursive=1") file="source-tree.json" ;;
  "repos/writer/cerebro") file="public-target-repository.json" ;;
  "repos/writer/cerebro/git/ref/heads/main") file="public-target-ref.json" ;;
  "repos/writer/cerebro/git/commits/cccccccccccccccccccccccccccccccccccccccc"|"repos/writer/cerebro/git/commits/9999999999999999999999999999999999999999") file="public-target-commit.json" ;;
  "repos/WriterInternal/cerebro") file="private-target-repository.json" ;;
  "repos/WriterInternal/cerebro/git/ref/heads/main") file="private-target-ref.json" ;;
  "repos/WriterInternal/cerebro/git/commits/dddddddddddddddddddddddddddddddddddddddd") file="private-target-commit.json" ;;
  *) exit 66 ;;
esac

[[ -f "${FAKE_GH_FIXTURE_DIR}/${file}" ]] || exit 67
command cat "${FAKE_GH_FIXTURE_DIR}/${file}"
