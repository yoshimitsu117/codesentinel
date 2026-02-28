"""CodeSentinel — Security Vulnerability Scanner."""

from __future__ import annotations

import ast
import re
import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class SecurityFinding:
    """A security vulnerability finding."""

    rule_id: str
    severity: str  # critical, high, medium, low
    title: str
    description: str
    lineno: int
    code_snippet: str
    recommendation: str


class SecurityScanner:
    """Static security analysis for Python code.

    Detects common security vulnerabilities and unsafe patterns.
    """

    def scan(self, code: str, filename: str = "<code>") -> list[SecurityFinding]:
        """Scan code for security vulnerabilities.

        Args:
            code: Python source code.
            filename: Filename for reporting.

        Returns:
            List of security findings.
        """
        findings: list[SecurityFinding] = []
        lines = code.split("\n")

        # AST-based checks
        try:
            tree = ast.parse(code)
            findings.extend(self._check_eval_exec(tree, lines))
            findings.extend(self._check_pickle(tree, lines))
            findings.extend(self._check_subprocess_shell(tree, lines))
            findings.extend(self._check_assert_security(tree, lines))
        except SyntaxError:
            pass  # Skip AST checks for invalid code

        # Regex-based checks
        findings.extend(self._check_hardcoded_secrets(lines))
        findings.extend(self._check_sql_injection(lines))
        findings.extend(self._check_debug_flags(lines))

        logger.info(f"Security scan of {filename}: {len(findings)} findings")
        return findings

    def _check_eval_exec(
        self, tree: ast.Module, lines: list[str]
    ) -> list[SecurityFinding]:
        """Detect usage of eval() and exec()."""
        findings = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func_name = ""
                if isinstance(node.func, ast.Name):
                    func_name = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    func_name = node.func.attr

                if func_name in ("eval", "exec"):
                    findings.append(
                        SecurityFinding(
                            rule_id="SEC001",
                            severity="critical",
                            title=f"Use of {func_name}()",
                            description=(
                                f"`{func_name}()` executes arbitrary code and is a "
                                "major security risk, especially with user input."
                            ),
                            lineno=node.lineno,
                            code_snippet=lines[node.lineno - 1].strip() if node.lineno <= len(lines) else "",
                            recommendation=(
                                f"Replace `{func_name}()` with safer alternatives. "
                                "Use `ast.literal_eval()` for parsing literals, or "
                                "implement a proper parser for complex expressions."
                            ),
                        )
                    )
        return findings

    def _check_pickle(
        self, tree: ast.Module, lines: list[str]
    ) -> list[SecurityFinding]:
        """Detect unsafe pickle usage."""
        findings = []
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module == "pickle":
                for alias in node.names:
                    if alias.name in ("load", "loads"):
                        findings.append(
                            SecurityFinding(
                                rule_id="SEC002",
                                severity="high",
                                title="Unsafe pickle deserialization",
                                description=(
                                    "Pickle can execute arbitrary code during "
                                    "deserialization. Never unpickle untrusted data."
                                ),
                                lineno=node.lineno,
                                code_snippet=lines[node.lineno - 1].strip() if node.lineno <= len(lines) else "",
                                recommendation="Use JSON or other safe serialization formats.",
                            )
                        )
        return findings

    def _check_subprocess_shell(
        self, tree: ast.Module, lines: list[str]
    ) -> list[SecurityFinding]:
        """Detect subprocess calls with shell=True."""
        findings = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func_name = ""
                if isinstance(node.func, ast.Attribute):
                    func_name = node.func.attr
                elif isinstance(node.func, ast.Name):
                    func_name = node.func.id

                if func_name in ("call", "Popen", "run", "check_output"):
                    for kw in node.keywords:
                        if kw.arg == "shell" and isinstance(kw.value, ast.Constant):
                            if kw.value.value is True:
                                findings.append(
                                    SecurityFinding(
                                        rule_id="SEC003",
                                        severity="high",
                                        title="Subprocess with shell=True",
                                        description=(
                                            "Using shell=True with subprocess is "
                                            "vulnerable to shell injection attacks."
                                        ),
                                        lineno=node.lineno,
                                        code_snippet=lines[node.lineno - 1].strip() if node.lineno <= len(lines) else "",
                                        recommendation=(
                                            "Use shell=False and pass arguments as a list."
                                        ),
                                    )
                                )
        return findings

    def _check_assert_security(
        self, tree: ast.Module, lines: list[str]
    ) -> list[SecurityFinding]:
        """Detect assert used for security checks."""
        findings = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Assert):
                snippet = lines[node.lineno - 1].strip() if node.lineno <= len(lines) else ""
                security_words = ["auth", "permission", "admin", "login", "token", "secret"]
                if any(word in snippet.lower() for word in security_words):
                    findings.append(
                        SecurityFinding(
                            rule_id="SEC004",
                            severity="medium",
                            title="Assert used for security check",
                            description=(
                                "Assert statements are removed when Python runs "
                                "with optimization (-O flag). Security checks "
                                "must use proper if/raise patterns."
                            ),
                            lineno=node.lineno,
                            code_snippet=snippet,
                            recommendation="Replace with `if not condition: raise PermissionError(...)`",
                        )
                    )
        return findings

    def _check_hardcoded_secrets(self, lines: list[str]) -> list[SecurityFinding]:
        """Detect hardcoded secrets, passwords, and API keys."""
        findings = []
        secret_patterns = [
            (r'(?:password|passwd|pwd)\s*=\s*["\'][^"\']+["\']', "Hardcoded password"),
            (r'(?:api_key|apikey|api_secret)\s*=\s*["\'][^"\']+["\']', "Hardcoded API key"),
            (r'(?:secret_key|secret)\s*=\s*["\'][^"\']{8,}["\']', "Hardcoded secret"),
            (r'(?:token)\s*=\s*["\'][^"\']{10,}["\']', "Hardcoded token"),
            (r'sk-[a-zA-Z0-9]{20,}', "OpenAI API key"),
            (r'AKIA[0-9A-Z]{16}', "AWS Access Key"),
        ]

        for lineno, line in enumerate(lines, 1):
            for pattern, title in secret_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(
                        SecurityFinding(
                            rule_id="SEC005",
                            severity="critical",
                            title=title,
                            description="Credentials should never be hardcoded in source code.",
                            lineno=lineno,
                            code_snippet=line.strip()[:100],
                            recommendation="Use environment variables or a secrets manager.",
                        )
                    )
                    break  # One finding per line

        return findings

    def _check_sql_injection(self, lines: list[str]) -> list[SecurityFinding]:
        """Detect potential SQL injection patterns."""
        findings = []
        sql_patterns = [
            r'(?:execute|cursor\.execute)\s*\(\s*f["\']',
            r'(?:execute|cursor\.execute)\s*\(\s*["\'].*%s',
            r'(?:execute|cursor\.execute)\s*\(\s*.*\.format\(',
            r'(?:execute|cursor\.execute)\s*\(\s*.*\+\s*',
        ]

        for lineno, line in enumerate(lines, 1):
            for pattern in sql_patterns:
                if re.search(pattern, line):
                    findings.append(
                        SecurityFinding(
                            rule_id="SEC006",
                            severity="critical",
                            title="Potential SQL injection",
                            description="String interpolation in SQL queries is vulnerable to injection.",
                            lineno=lineno,
                            code_snippet=line.strip()[:100],
                            recommendation="Use parameterized queries with placeholders.",
                        )
                    )
                    break

        return findings

    def _check_debug_flags(self, lines: list[str]) -> list[SecurityFinding]:
        """Detect debug flags left in code."""
        findings = []
        for lineno, line in enumerate(lines, 1):
            if re.search(r'(?:DEBUG|debug)\s*=\s*True', line):
                findings.append(
                    SecurityFinding(
                        rule_id="SEC007",
                        severity="low",
                        title="Debug mode enabled",
                        description="Debug flags should be disabled in production code.",
                        lineno=lineno,
                        code_snippet=line.strip(),
                        recommendation="Use environment variables for debug configuration.",
                    )
                )
        return findings
