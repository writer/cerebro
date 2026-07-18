# Slack host ownership

`services/slack-companion` is the canonical Slack host source. Application code, tests, Docker build inputs, and operator documentation change in this repository.

The deployment repository owns environment configuration, cloud resources, promotion policy, release receipts, and rollback actions. It consumes an exact commit from this repository and must not carry a second copy of the Slack host source.

## Release sequence

1. Merge a validated Slack host change here.
2. Build and test the host at the exact merged commit.
3. Verify the signed Cerebro product manifest for that commit.
4. Let the deployment repository consume the exact source commit and signed product artifacts.
5. Run the deployment preflight, steady-state check, runtime canary, Slack check, and rollback check.
6. Record the deployed commit, image digest, workflow run, and terminal release state.

## Rollback

The deployment repository restores the last verified source commit and image digest. Source history remains here; environment credentials and deployment state remain outside this repository.
