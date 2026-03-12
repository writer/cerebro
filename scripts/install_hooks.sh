#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
git_common_dir="$(git rev-parse --git-common-dir)"
git_common_dir="$(cd "$git_common_dir" && pwd)"

cd "$repo_root"

mkdir -p "$git_common_dir/hooks"

for hook in pre-commit pre-push; do
	if [ ! -f ".githooks/$hook" ]; then
		echo "missing tracked hook: .githooks/$hook" >&2
		exit 1
	fi

	chmod +x ".githooks/$hook"

	cat >"$git_common_dir/hooks/$hook" <<EOF
#!/usr/bin/env bash
set -euo pipefail

repo_root="\$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
hook_path="\${repo_root}/.githooks/$hook"

if [ ! -x "\$hook_path" ]; then
	echo "missing tracked hook: \$hook_path" >&2
	exit 1
fi

exec "\$hook_path" "\$@"
EOF

	chmod +x "$git_common_dir/hooks/$hook"
done

git config core.hooksPath .githooks
echo "Git hooks installed (.githooks/) and fallback shims refreshed ($git_common_dir/hooks)"
