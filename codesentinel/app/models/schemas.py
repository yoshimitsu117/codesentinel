"""CodeSentinel — Pydantic Review Schemas."""

from __future__ import annotations

from pydantic import BaseModel, Field


class ReviewIssue(BaseModel):
    """A single code review issue."""

    category: str = Field(description="bug_risk, security, complexity, style, performance, architecture")
    severity: str = Field(description="critical, high, medium, low")
    title: str
    description: str
    lineno: int | None = None
    suggestion: str = ""


class ReviewResult(BaseModel):
    """Complete review result from LLM analysis."""

    summary: str
    issues: list[ReviewIssue] = []
    score: int = Field(ge=0, le=10, description="Overall code quality score 0-10")
    improvements: list[str] = []


class ReviewRequest(BaseModel):
    """API request for code review."""

    code: str = Field(..., description="Source code to review")
    filename: str = Field(default="code.py")
    language: str = Field(default="python")
    enable_security: bool = True
    enable_complexity: bool = True


class ReviewReport(BaseModel):
    """Full review report combining all analyses."""

    report_id: str
    filename: str
    llm_review: ReviewResult | None = None
    security_findings: list[dict] = []
    code_stats: dict = {}
    overall_score: int = 0
    total_issues: int = 0
