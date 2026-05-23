from __future__ import annotations

import ast
import sys
from pathlib import Path


DEFAULT_TEST_PATH = Path(__file__).resolve().parents[1] / "tests" / "test_validate_stack_config.py"


def _eval_string(node: ast.AST | None, env: dict[str, str]) -> str | None:
    if node is None:
        return None
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Name):
        return env.get(node.id)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _eval_string(node.left, env)
        right = _eval_string(node.right, env)
        if left is not None and right is not None:
            return left + right
    if isinstance(node, ast.JoinedStr):
        parts: list[str] = []
        for value in node.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                parts.append(value.value)
            elif isinstance(value, ast.FormattedValue):
                part = _eval_string(value.value, env)
                if part is None:
                    return None
                parts.append(part)
            else:
                return None
        return "".join(parts)
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and not node.args and not node.keywords:
        value = _eval_string(node.func.value, env)
        if value is not None and node.func.attr in {"strip", "lstrip", "rstrip"}:
            return getattr(value, node.func.attr)()
    return None


def _string_environment(tree: ast.AST) -> dict[str, str]:
    env: dict[str, str] = {}
    if not isinstance(tree, ast.Module):
        return env
    for node in tree.body:
        if isinstance(node, ast.Assign):
            value = _eval_string(node.value, env)
            if value is None:
                continue
            for target in node.targets:
                if isinstance(target, ast.Name):
                    env[target.id] = value
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            value = _eval_string(node.value, env)
            if value is not None:
                env[node.target.id] = value
    return env


def _base_stack_text(tree: ast.AST, env: dict[str, str]) -> str | None:
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == "BASE_STACK" for target in node.targets
        ):
            return _eval_string(node.value, env)
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.target.id == "BASE_STACK":
            return _eval_string(node.value, env)
    return None


def _is_base_stack_derived(node: ast.AST) -> bool:
    if isinstance(node, ast.Name) and node.id == "BASE_STACK":
        return True
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "replace"
    ):
        return _is_base_stack_derived(node.func.value)
    return False


def check_file(path: Path) -> list[str]:
    source = path.read_text()
    tree = ast.parse(source, filename=str(path))
    env = _string_environment(tree)
    base_stack = _base_stack_text(tree, env)
    if base_stack is None:
        return [f"{path}: BASE_STACK assignment was not found"]

    errors: list[str] = []
    for node in ast.walk(tree):
        if not (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "replace"
            and _is_base_stack_derived(node.func.value)
            and node.args
        ):
            continue

        old = _eval_string(node.args[0], env)
        if old and old not in base_stack:
            errors.append(
                f"{path}:{node.lineno}: BASE_STACK.replace anchor is not present in BASE_STACK: {old!r}"
            )
    return errors


def main(argv: list[str]) -> int:
    paths = [Path(arg) for arg in argv] or [DEFAULT_TEST_PATH]
    errors: list[str] = []
    for path in paths:
        errors.extend(check_file(path))
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
