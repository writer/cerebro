"""
Code Reading Tool

Enables agents to read source code, find functions/classes, and understand implementation details.
"""

import ast
from pathlib import Path
from typing import List, Optional
import structlog
from pydantic import BaseModel, Field

from cerebro.agents.tools.base import (
    StructuredTool,
    ToolResult,
    AgentContext,
    ToolPermissionLevel,
)

logger = structlog.get_logger(__name__)


# ==================== Input/Output Schemas ====================


class ReadCodeInput(BaseModel):
    """Input for read_code tool."""

    file_path: str = Field(
        description="Path to code file (relative to repo root or absolute)",
        min_length=1,
    )
    symbol_name: Optional[str] = Field(
        default=None,
        description="Optional: specific function/class name to find",
    )
    line_start: Optional[int] = Field(
        default=None,
        description="Optional: start line number (1-indexed)",
        ge=1,
    )
    line_end: Optional[int] = Field(
        default=None,
        description="Optional: end line number (1-indexed)",
        ge=1,
    )


class SymbolInfo(BaseModel):
    """Information about a code symbol (function/class)."""

    name: str
    type: str  # function, class, method
    line_number: int
    docstring: Optional[str]
    code: str
    signature: Optional[str]


class ReadCodeOutput(BaseModel):
    """Output for read_code tool."""

    success: bool
    file_path: str
    total_lines: int
    code: Optional[str] = None
    symbol: Optional[SymbolInfo] = None
    symbols_found: List[str] = []  # All symbols if analyzing full file
    language: str
    message: str


class SearchCodeInput(BaseModel):
    """Input for search_code tool."""

    search_term: str = Field(
        description="Term to search for in code (function name, class name, etc.)",
        min_length=1,
    )
    file_pattern: Optional[str] = Field(
        default="*.py",
        description="File pattern to search (e.g. *.py, *.ts)",
    )
    directory: Optional[str] = Field(
        default=None,
        description="Directory to search in (relative to repo root)",
    )


class SearchResult(BaseModel):
    """A code search result."""

    file_path: str
    line_number: int
    line_content: str
    symbol_type: Optional[str] = None  # function, class, variable


class SearchCodeOutput(BaseModel):
    """Output for search_code tool."""

    success: bool
    search_term: str
    total_matches: int
    results: List[SearchResult]
    searched_files: int
    message: str


# ==================== Helper Functions ====================


def find_python_symbol(code: str, symbol_name: str) -> Optional[SymbolInfo]:
    """Parse Python AST to find a specific symbol."""
    try:
        tree = ast.parse(code)

        for node in ast.walk(tree):
            # Find function definitions
            if isinstance(node, ast.FunctionDef) and node.name == symbol_name:
                # Extract function code
                func_lines = code.split("\n")[node.lineno - 1 : node.end_lineno]
                func_code = "\n".join(func_lines)

                # Extract docstring
                docstring = ast.get_docstring(node)

                # Build signature
                args = [arg.arg for arg in node.args.args]
                signature = f"def {node.name}({', '.join(args)})"

                return SymbolInfo(
                    name=node.name,
                    type="function",
                    line_number=node.lineno,
                    docstring=docstring,
                    code=func_code,
                    signature=signature,
                )

            # Find class definitions
            elif isinstance(node, ast.ClassDef) and node.name == symbol_name:
                # Extract class code
                class_lines = code.split("\n")[node.lineno - 1 : node.end_lineno]
                class_code = "\n".join(class_lines)

                # Extract docstring
                docstring = ast.get_docstring(node)

                # Find base classes
                bases = [ast.unparse(base) for base in node.bases] if node.bases else []
                signature = (
                    f"class {node.name}({', '.join(bases)})"
                    if bases
                    else f"class {node.name}"
                )

                return SymbolInfo(
                    name=node.name,
                    type="class",
                    line_number=node.lineno,
                    docstring=docstring,
                    code=class_code,
                    signature=signature,
                )

    except SyntaxError as e:
        logger.warning("Failed to parse Python code", error=str(e))
        return None

    return None


def extract_all_symbols(code: str, language: str) -> List[str]:
    """Extract all top-level symbols from code."""
    symbols = []

    if language == "python":
        try:
            tree = ast.parse(code)
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
                    if node.col_offset == 0:  # Top-level only
                        symbols.append(node.name)
        except SyntaxError:
            pass

    return symbols


def detect_language(file_path: str) -> str:
    """Detect programming language from file extension."""
    ext = Path(file_path).suffix.lower()
    lang_map = {
        ".py": "python",
        ".ts": "typescript",
        ".tsx": "typescript",
        ".js": "javascript",
        ".jsx": "javascript",
        ".go": "go",
        ".rs": "rust",
        ".java": "java",
        ".c": "c",
        ".cpp": "cpp",
        ".h": "c",
        ".hpp": "cpp",
    }
    return lang_map.get(ext, "unknown")


def find_repo_root() -> Optional[Path]:
    """Find the repository root by looking for common markers."""
    current = Path.cwd()

    # Look for repo markers
    markers = [".git", "pyproject.toml", "package.json", "go.mod", "Cargo.toml"]

    while current != current.parent:
        for marker in markers:
            if (current / marker).exists():
                return current
        current = current.parent

    return None


# ==================== Tools ====================


class ReadCodeTool(StructuredTool):
    """
    Read source code files and extract specific functions/classes.

    Examples:
    - "Show me the JWT validation logic" → read_code(file_path="auth/jwt.py", symbol_name="validate_token")
    - "What does the User class look like?" → read_code(file_path="models/user.py", symbol_name="User")
    - "Read the entire findings module" → read_code(file_path="findings/service.py")
    """

    tool_name = "read_code"
    tool_description = """Read source code files to understand implementation details.
Can extract specific functions/classes or read entire files. Supports Python, TypeScript, JavaScript, and more."""

    tool_version = "1.0.0"
    input_model = ReadCodeInput
    output_model = ReadCodeOutput
    required_permission = ToolPermissionLevel.READ_ONLY

    async def _run(  # type: ignore[override]
        self,
        context: AgentContext,
        file_path: str,
        symbol_name: Optional[str] = None,
        line_start: Optional[int] = None,
        line_end: Optional[int] = None,
    ) -> ToolResult:
        """Read code from a file."""

        try:
            # Find repo root for relative paths
            repo_root = find_repo_root()
            if repo_root and not Path(file_path).is_absolute():
                full_path = repo_root / file_path
            else:
                full_path = Path(file_path)

            # Check file exists
            if not full_path.exists():
                output = ReadCodeOutput(
                    success=False,
                    file_path=file_path,
                    total_lines=0,
                    language="unknown",
                    message=f"File not found: {file_path}",
                )
                return ToolResult(
                    success=False,
                    data=output.model_dump(),
                    metadata={"error": "file_not_found"},
                )

            # Read file
            try:
                with open(full_path, "r", encoding="utf-8") as f:
                    code = f.read()
            except UnicodeDecodeError:
                output = ReadCodeOutput(
                    success=False,
                    file_path=file_path,
                    total_lines=0,
                    language="binary",
                    message=f"Cannot read binary file: {file_path}",
                )
                return ToolResult(
                    success=False,
                    data=output.model_dump(),
                    metadata={"error": "binary_file"},
                )

            lines = code.split("\n")
            total_lines = len(lines)
            language = detect_language(file_path)

            # Extract specific symbol if requested
            symbol_info = None
            if symbol_name and language == "python":
                symbol_info = find_python_symbol(code, symbol_name)
                if symbol_info:
                    output = ReadCodeOutput(
                        success=True,
                        file_path=file_path,
                        total_lines=total_lines,
                        symbol=symbol_info,
                        language=language,
                        message=f"Found {symbol_info.type} '{symbol_name}' at line {symbol_info.line_number}",
                    )
                    return ToolResult(
                        success=True,
                        data=output.model_dump(),
                        metadata={
                            "symbol_type": symbol_info.type,
                            "line_number": symbol_info.line_number,
                        },
                    )
                else:
                    output = ReadCodeOutput(
                        success=False,
                        file_path=file_path,
                        total_lines=total_lines,
                        language=language,
                        message=f"Symbol '{symbol_name}' not found in {file_path}",
                    )
                    return ToolResult(
                        success=False,
                        data=output.model_dump(),
                        metadata={"error": "symbol_not_found"},
                    )

            # Extract line range if requested
            if line_start is not None or line_end is not None:
                start = (line_start - 1) if line_start else 0
                end = line_end if line_end else total_lines
                extracted_code = "\n".join(lines[start:end])
            else:
                extracted_code = code

            # Extract all symbols for context
            symbols_found = extract_all_symbols(code, language)

            output = ReadCodeOutput(
                success=True,
                file_path=file_path,
                total_lines=total_lines,
                code=extracted_code,
                symbols_found=symbols_found,
                language=language,
                message=f"Read {total_lines} lines from {file_path}",
            )

            logger.info(
                "Code read successfully",
                file_path=file_path,
                total_lines=total_lines,
                symbol_name=symbol_name,
                symbols_count=len(symbols_found),
            )

            return ToolResult(
                success=True,
                data=output.model_dump(),
                metadata={
                    "total_lines": total_lines,
                    "symbols_count": len(symbols_found),
                },
            )

        except Exception as e:
            logger.exception("Failed to read code", error=str(e), file_path=file_path)

            output = ReadCodeOutput(
                success=False,
                file_path=file_path,
                total_lines=0,
                language="unknown",
                message=f"Failed to read code: {str(e)}",
            )

            return ToolResult(
                success=False,
                data=output.model_dump(),
                metadata={"error": str(e)},
            )


class SearchCodeTool(StructuredTool):
    """
    Search for code symbols across the repository.

    Examples:
    - "Where is the authenticate function?" → search_code(search_term="authenticate")
    - "Find User class definition" → search_code(search_term="class User")
    - "Where is JWT validation?" → search_code(search_term="validate_token", file_pattern="*.py")
    """

    tool_name = "search_code"
    tool_description = """Search for functions, classes, or code patterns across the repository.
Useful for finding where specific logic is implemented."""

    tool_version = "1.0.0"
    input_model = SearchCodeInput
    output_model = SearchCodeOutput
    required_permission = ToolPermissionLevel.READ_ONLY

    async def _run(  # type: ignore[override]
        self,
        context: AgentContext,
        search_term: str,
        file_pattern: str = "*.py",
        directory: Optional[str] = None,
    ) -> ToolResult:
        """Search for code across repository."""

        try:
            # Find repo root
            repo_root = find_repo_root()
            if not repo_root:
                output = SearchCodeOutput(
                    success=False,
                    search_term=search_term,
                    total_matches=0,
                    results=[],
                    searched_files=0,
                    message="Could not find repository root",
                )
                return ToolResult(
                    success=False,
                    data=output.model_dump(),
                    metadata={"error": "no_repo_root"},
                )

            # Determine search directory
            search_dir = repo_root
            if directory:
                search_dir = repo_root / directory
                if not search_dir.exists():
                    output = SearchCodeOutput(
                        success=False,
                        search_term=search_term,
                        total_matches=0,
                        results=[],
                        searched_files=0,
                        message=f"Directory not found: {directory}",
                    )
                    return ToolResult(
                        success=False,
                        data=output.model_dump(),
                        metadata={"error": "directory_not_found"},
                    )

            # Search for files matching pattern
            files = list(search_dir.rglob(file_pattern))

            # Exclude common non-code directories
            exclude_dirs = {
                "__pycache__",
                "node_modules",
                ".git",
                "venv",
                "env",
                ".venv",
                "dist",
                "build",
            }
            files = [
                f
                for f in files
                if not any(excluded in f.parts for excluded in exclude_dirs)
            ]

            results = []
            searched_files = 0

            for file_path in files[:100]:  # Limit to 100 files
                try:
                    with open(file_path, "r", encoding="utf-8") as f:
                        lines = f.readlines()
                        searched_files += 1

                        for line_num, line in enumerate(lines, 1):
                            if search_term.lower() in line.lower():
                                # Determine symbol type
                                symbol_type = None
                                if "def " in line:
                                    symbol_type = "function"
                                elif "class " in line:
                                    symbol_type = "class"

                                results.append(
                                    SearchResult(
                                        file_path=str(file_path.relative_to(repo_root)),
                                        line_number=line_num,
                                        line_content=line.strip(),
                                        symbol_type=symbol_type,
                                    )
                                )

                                # Limit results
                                if len(results) >= 50:
                                    break

                        if len(results) >= 50:
                            break

                except (UnicodeDecodeError, PermissionError):
                    continue

            output = SearchCodeOutput(
                success=True,
                search_term=search_term,
                total_matches=len(results),
                results=results,
                searched_files=searched_files,
                message=f"Found {len(results)} matches in {searched_files} files",
            )

            logger.info(
                "Code search completed",
                search_term=search_term,
                matches=len(results),
                files_searched=searched_files,
            )

            return ToolResult(
                success=True,
                data=output.model_dump(),
                metadata={
                    "matches": len(results),
                    "files_searched": searched_files,
                },
            )

        except Exception as e:
            logger.exception(
                "Code search failed", error=str(e), search_term=search_term
            )

            output = SearchCodeOutput(
                success=False,
                search_term=search_term,
                total_matches=0,
                results=[],
                searched_files=0,
                message=f"Search failed: {str(e)}",
            )

            return ToolResult(
                success=False,
                data=output.model_dump(),
                metadata={"error": str(e)},
            )
