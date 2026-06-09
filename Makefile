.DEFAULT_GOAL := help

.PHONY: help droid-review-preflight droid-review-sast droid-ci-context droid-review-context droid-feedback

DROID_REVIEW_BASE ?= origin/main
DROID_REVIEW_HEAD ?= HEAD
DROID_PREFLIGHT_JSON_OUT ?= tmp/droid-preflight.json
DROID_PR ?=
DROID_FEEDBACK_OUT ?= tmp/droid-feedback.md
DROID_FEEDBACK_JSON_OUT ?= tmp/droid-feedback.json
DROID_SAST_OUT ?= tmp/droid-sast-context.md
DROID_SAST_JSON_OUT ?= tmp/droid-sast-context.json
DROID_CI_OUT ?= tmp/droid-ci-context.md
DROID_CI_JSON_OUT ?= tmp/droid-ci-context.json
DROID_CONTEXT_OUT ?= tmp/droid-review-context.md
DROID_CONTEXT_JSON_OUT ?= tmp/droid-review-context.json
DROID_SAST_POST_COMMENT ?= false

help: ## Show this help message.
	@awk 'BEGIN {FS = ":.*##"; printf "Available targets:\n"} /^[a-zA-Z0-9_.-]+:.*##/ {printf "  %-28s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

droid-review-preflight: ## Build Droid review preflight context.
	python3 scripts/droid_preflight_context.py --base "$(DROID_REVIEW_BASE)" --head "$(DROID_REVIEW_HEAD)" --json-out "$(DROID_PREFLIGHT_JSON_OUT)"

droid-review-sast: ## Build Droid security scanner context.
	python3 scripts/droid_sast_context.py --base "$(DROID_REVIEW_BASE)" --head "$(DROID_REVIEW_HEAD)" --markdown-out "$(DROID_SAST_OUT)" --json-out "$(DROID_SAST_JSON_OUT)" $(if $(filter true,$(DROID_SAST_POST_COMMENT)),--post-comment,)

droid-ci-context: ## Build Droid CI context from the current head.
	python3 scripts/droid_ci_context.py --head "$(DROID_REVIEW_HEAD)" --markdown-out "$(DROID_CI_OUT)" --json-out "$(DROID_CI_JSON_OUT)"

droid-review-context: ## Combine Droid review context inputs.
	python3 scripts/droid_review_context.py --base "$(DROID_REVIEW_BASE)" --head "$(DROID_REVIEW_HEAD)" --preflight-json "$(DROID_PREFLIGHT_JSON_OUT)" --sast-json "$(DROID_SAST_JSON_OUT)" --ci-json "$(DROID_CI_JSON_OUT)" --feedback-json "$(DROID_FEEDBACK_JSON_OUT)" --markdown-out "$(DROID_CONTEXT_OUT)" --json-out "$(DROID_CONTEXT_JSON_OUT)"

droid-feedback: ## Fetch and normalize Droid feedback for DROID_PR.
	@if [ -z "$(DROID_PR)" ]; then echo "DROID_PR is required, e.g. make droid-feedback DROID_PR=997" >&2; exit 2; fi
	python3 scripts/droid_feedback_harness.py "$(DROID_PR)" $(if $(DROID_FEEDBACK_OUT),--markdown-out "$(DROID_FEEDBACK_OUT)") --json-out "$(DROID_FEEDBACK_JSON_OUT)"
