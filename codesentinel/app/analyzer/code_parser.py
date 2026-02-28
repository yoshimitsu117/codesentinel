"""CodeSentinel — AST-Based Code Parser."""

from __future__ import annotations

import ast
import logging
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class FunctionInfo:
    """Information about a parsed function."""

    name: str
    lineno: int
    end_lineno: int | None
    args: list[str]
    decorators: list[str]
    docstring: str | None
    complexity: int
    nested_depth: int
    return_count: int
    is_async: bool


@dataclass
class ClassInfo:
    """Information about a parsed class."""

    name: str
    lineno: int
    end_lineno: int | None
    bases: list[str]
    methods: list[FunctionInfo]
    docstring: str | None


@dataclass
class ImportInfo:
    """Information about an import statement."""

    module: str
    names: list[str]
    lineno: int
    is_from_import: bool


@dataclass
class CodeAnalysis:
    """Complete static analysis result."""

    total_lines: int
    blank_lines: int
    comment_lines: int
    functions: list[FunctionInfo] = field(default_factory=list)
    classes: list[ClassInfo] = field(default_factory=list)
    imports: list[ImportInfo] = field(default_factory=list)
    global_variables: list[str] = field(default_factory=list)
    avg_complexity: float = 0.0
    max_complexity: int = 0
    has_main_guard: bool = False
    syntax_valid: bool = True
    syntax_error: str | None = None


class CodeParser:
    """AST-based Python code parser for static analysis."""

    def parse(self, code: str, filename: str = "<code>") -> CodeAnalysis:
        """Parse Python code and extract structural information.

        Args:
            code: Python source code string.
            filename: Filename for error reporting.

        Returns:
            CodeAnalysis with all extracted information.
        """
        lines = code.split("\n")
        analysis = CodeAnalysis(
            total_lines=len(lines),
            blank_lines=sum(1 for line in lines if not line.strip()),
            comment_lines=sum(1 for line in lines if line.strip().startswith("#")),
        )

        try:
            tree = ast.parse(code, filename=filename)
        except SyntaxError as e:
            analysis.syntax_valid = False
            analysis.syntax_error = f"Line {e.lineno}: {e.msg}"
            logger.warning(f"Syntax error in {filename}: {e}")
            return analysis

        # Walk the AST
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if not self._is_method(node, tree):
                    analysis.functions.append(self._parse_function(node))

            elif isinstance(node, ast.ClassDef):
                analysis.classes.append(self._parse_class(node))

            elif isinstance(node, ast.Import):
                for alias in node.names:
                    analysis.imports.append(
                        ImportInfo(
                            module=alias.name,
                            names=[alias.asname or alias.name],
                            lineno=node.lineno,
                            is_from_import=False,
                        )
                    )

            elif isinstance(node, ast.ImportFrom):
                analysis.imports.append(
                    ImportInfo(
                        module=node.module or "",
                        names=[a.name for a in node.names],
                        lineno=node.lineno,
                        is_from_import=True,
                    )
                )

        # Check for if __name__ == "__main__" guard
        for node in ast.iter_child_nodes(tree):
            if isinstance(node, ast.If):
                analysis.has_main_guard = self._is_main_guard(node)
                if analysis.has_main_guard:
                    break

        # Calculate complexity stats
        all_complexities = [f.complexity for f in analysis.functions]
        for cls in analysis.classes:
            all_complexities.extend([m.complexity for m in cls.methods])

        if all_complexities:
            analysis.avg_complexity = sum(all_complexities) / len(all_complexities)
            analysis.max_complexity = max(all_complexities)

        logger.info(
            f"Parsed {filename}: {len(analysis.functions)} functions, "
            f"{len(analysis.classes)} classes, complexity={analysis.avg_complexity:.1f}"
        )

        return analysis

    def _parse_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> FunctionInfo:
        """Extract information from a function node."""
        return FunctionInfo(
            name=node.name,
            lineno=node.lineno,
            end_lineno=getattr(node, "end_lineno", None),
            args=[arg.arg for arg in node.args.args],
            decorators=[self._get_decorator_name(d) for d in node.decorator_list],
            docstring=ast.get_docstring(node),
            complexity=self._calculate_complexity(node),
            nested_depth=self._max_nesting_depth(node),
            return_count=sum(
                1 for n in ast.walk(node) if isinstance(n, ast.Return)
            ),
            is_async=isinstance(node, ast.AsyncFunctionDef),
        )

    def _parse_class(self, node: ast.ClassDef) -> ClassInfo:
        """Extract information from a class node."""
        methods = []
        for item in node.body:
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                methods.append(self._parse_function(item))

        return ClassInfo(
            name=node.name,
            lineno=node.lineno,
            end_lineno=getattr(node, "end_lineno", None),
            bases=[self._get_name(b) for b in node.bases],
            methods=methods,
            docstring=ast.get_docstring(node),
        )

    def _calculate_complexity(self, node: ast.AST) -> int:
        """Calculate cyclomatic complexity of a node."""
        complexity = 1  # Base complexity

        for child in ast.walk(node):
            if isinstance(child, (ast.If, ast.While, ast.For, ast.AsyncFor)):
                complexity += 1
            elif isinstance(child, ast.ExceptHandler):
                complexity += 1
            elif isinstance(child, ast.BoolOp):
                complexity += len(child.values) - 1
            elif isinstance(child, ast.Assert):
                complexity += 1

        return complexity

    def _max_nesting_depth(self, node: ast.AST, depth: int = 0) -> int:
        """Calculate maximum nesting depth."""
        max_depth = depth
        nesting_nodes = (ast.If, ast.While, ast.For, ast.AsyncFor, ast.With, ast.Try)

        for child in ast.iter_child_nodes(node):
            if isinstance(child, nesting_nodes):
                child_depth = self._max_nesting_depth(child, depth + 1)
                max_depth = max(max_depth, child_depth)
            else:
                child_depth = self._max_nesting_depth(child, depth)
                max_depth = max(max_depth, child_depth)

        return max_depth

    def _is_method(self, node: ast.FunctionDef, tree: ast.Module) -> bool:
        """Check if a function is a method (inside a class)."""
        for cls_node in ast.walk(tree):
            if isinstance(cls_node, ast.ClassDef):
                for item in cls_node.body:
                    if item is node:
                        return True
        return False

    def _is_main_guard(self, node: ast.If) -> bool:
        """Check if an If node is `if __name__ == '__main__'`."""
        try:
            test = node.test
            if isinstance(test, ast.Compare):
                if (
                    isinstance(test.left, ast.Name)
                    and test.left.id == "__name__"
                    and isinstance(test.comparators[0], ast.Constant)
                    and test.comparators[0].value == "__main__"
                ):
                    return True
        except (AttributeError, IndexError):
            pass
        return False

    @staticmethod
    def _get_decorator_name(node: ast.expr) -> str:
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            return f"{CodeParser._get_name(node.value)}.{node.attr}"
        elif isinstance(node, ast.Call):
            return CodeParser._get_decorator_name(node.func)
        return "<unknown>"

    @staticmethod
    def _get_name(node: ast.expr) -> str:
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            return f"{CodeParser._get_name(node.value)}.{node.attr}"
        elif isinstance(node, ast.Constant):
            return str(node.value)
        return "<unknown>"
