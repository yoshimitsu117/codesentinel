"""Tests for CodeSentinel analyzer."""

import pytest
from app.analyzer.code_parser import CodeParser
from app.analyzer.security import SecurityScanner


class TestCodeParser:
    """Tests for AST-based code parser."""

    def test_parse_simple_function(self):
        code = '''
def hello(name):
    """Greet someone."""
    return f"Hello, {name}!"
'''
        parser = CodeParser()
        result = parser.parse(code)
        assert result.syntax_valid
        assert len(result.functions) == 1
        assert result.functions[0].name == "hello"
        assert result.functions[0].docstring == "Greet someone."

    def test_parse_class(self):
        code = '''
class MyClass:
    """A test class."""

    def __init__(self):
        self.value = 0

    def get_value(self):
        return self.value
'''
        parser = CodeParser()
        result = parser.parse(code)
        assert len(result.classes) == 1
        assert result.classes[0].name == "MyClass"
        assert len(result.classes[0].methods) == 2

    def test_complexity_calculation(self):
        code = '''
def complex_func(x, y):
    if x > 0:
        if y > 0:
            for i in range(x):
                if i % 2 == 0:
                    return i
    elif x < 0:
        while y > 0:
            y -= 1
    return 0
'''
        parser = CodeParser()
        result = parser.parse(code)
        assert result.functions[0].complexity > 1
        assert result.max_complexity > 3

    def test_syntax_error_handling(self):
        code = "def broken(:\n    pass"
        parser = CodeParser()
        result = parser.parse(code)
        assert not result.syntax_valid
        assert result.syntax_error is not None

    def test_async_function(self):
        code = '''
async def fetch_data(url):
    return await get(url)
'''
        parser = CodeParser()
        result = parser.parse(code)
        assert result.functions[0].is_async

    def test_main_guard_detection(self):
        code = '''
def main():
    pass

if __name__ == "__main__":
    main()
'''
        parser = CodeParser()
        result = parser.parse(code)
        assert result.has_main_guard

    def test_import_detection(self):
        code = '''
import os
from pathlib import Path
import json
'''
        parser = CodeParser()
        result = parser.parse(code)
        assert len(result.imports) == 3

    def test_line_counting(self):
        code = '''# Comment
x = 1

# Another comment
y = 2
'''
        parser = CodeParser()
        result = parser.parse(code)
        assert result.comment_lines == 2
        assert result.blank_lines >= 1


class TestSecurityScanner:
    """Tests for security vulnerability scanner."""

    def test_detect_eval(self):
        code = 'result = eval(user_input)'
        scanner = SecurityScanner()
        findings = scanner.scan(code)
        assert any(f.rule_id == "SEC001" for f in findings)
        assert any(f.severity == "critical" for f in findings)

    def test_detect_exec(self):
        code = 'exec(code_string)'
        scanner = SecurityScanner()
        findings = scanner.scan(code)
        assert any(f.rule_id == "SEC001" for f in findings)

    def test_detect_hardcoded_password(self):
        code = 'password = "my_secret_pass123"'
        scanner = SecurityScanner()
        findings = scanner.scan(code)
        assert any(f.rule_id == "SEC005" for f in findings)

    def test_detect_hardcoded_api_key(self):
        code = 'api_key = "sk-abcdefghijklmnopqrstuvwxyz"'
        scanner = SecurityScanner()
        findings = scanner.scan(code)
        assert len(findings) > 0

    def test_detect_subprocess_shell(self):
        code = 'subprocess.run(cmd, shell=True)'
        scanner = SecurityScanner()
        findings = scanner.scan(code)
        assert any(f.rule_id == "SEC003" for f in findings)

    def test_detect_debug_flag(self):
        code = 'DEBUG = True'
        scanner = SecurityScanner()
        findings = scanner.scan(code)
        assert any(f.rule_id == "SEC007" for f in findings)

    def test_clean_code_no_findings(self):
        code = '''
import os

def get_data():
    return os.environ.get("DATA_DIR", "/tmp")
'''
        scanner = SecurityScanner()
        findings = scanner.scan(code)
        assert len(findings) == 0

    def test_sql_injection_detection(self):
        code = 'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")'
        scanner = SecurityScanner()
        findings = scanner.scan(code)
        assert any(f.rule_id == "SEC006" for f in findings)
