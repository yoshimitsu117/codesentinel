"""CodeSentinel — Review Report Generator."""

from __future__ import annotations

import uuid
import logging
from dataclasses import asdict

from app.analyzer.code_parser import CodeParser
from app.analyzer.security import SecurityScanner
from app.analyzer.reviewer import CodeReviewer
from app.models.schemas import ReviewReport
from app.config import get_settings

logger = logging.getLogger(__name__)


class ReportGenerator:
    """Orchestrates all analysis components and generates a unified report."""

    def __init__(self):
        self.parser = CodeParser()
        self.security = SecurityScanner()
        self.reviewer = CodeReviewer()
        self.settings = get_settings()

    def generate(
        self,
        code: str,
        filename: str = "code.py",
        enable_security: bool = True,
        enable_llm_review: bool = True,
    ) -> ReviewReport:
        """Generate a complete review report.

        Args:
            code: Python source code.
            filename: Filename for context.
            enable_security: Whether to run security scan.
            enable_llm_review: Whether to run LLM review.

        Returns:
            Complete ReviewReport.
        """
        report_id = str(uuid.uuid4())[:8]

        # 1. AST Analysis
        analysis = self.parser.parse(code, filename)
        code_stats = {
            "total_lines": analysis.total_lines,
            "blank_lines": analysis.blank_lines,
            "comment_lines": analysis.comment_lines,
            "functions": len(analysis.functions),
            "classes": len(analysis.classes),
            "imports": len(analysis.imports),
            "avg_complexity": round(analysis.avg_complexity, 2),
            "max_complexity": analysis.max_complexity,
            "has_main_guard": analysis.has_main_guard,
            "syntax_valid": analysis.syntax_valid,
        }

        # 2. Security Scan
        security_findings = []
        if enable_security:
            findings = self.security.scan(code, filename)
            security_findings = [asdict(f) for f in findings]

        # 3. LLM Review
        llm_review = None
        if enable_llm_review:
            llm_review = self.reviewer.review(code, filename)

        # 4. Calculate overall score
        total_issues = len(security_findings)
        if llm_review:
            total_issues += len(llm_review.issues)

        # Score: start at LLM score, deduct for security findings
        base_score = llm_review.score if llm_review else 5
        security_penalty = sum(
            {"critical": 3, "high": 2, "medium": 1, "low": 0.5}.get(
                f.get("severity", "low"), 0
            )
            for f in security_findings
        )
        overall_score = max(0, min(10, int(base_score - security_penalty)))

        report = ReviewReport(
            report_id=report_id,
            filename=filename,
            llm_review=llm_review,
            security_findings=security_findings,
            code_stats=code_stats,
            overall_score=overall_score,
            total_issues=total_issues,
        )

        logger.info(
            f"Report {report_id} generated for {filename}: "
            f"score={overall_score}/10, issues={total_issues}"
        )

        return report
