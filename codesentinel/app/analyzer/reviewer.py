"""CodeSentinel — LLM-Powered Code Reviewer."""

from __future__ import annotations

import json
import logging

import openai

from app.config import get_settings
from app.models.schemas import ReviewResult, ReviewIssue
from app.models.prompts import CODE_REVIEW_PROMPT

logger = logging.getLogger(__name__)


class CodeReviewer:
    """LLM-powered code review with structured output."""

    def __init__(self):
        settings = get_settings()
        self.client = openai.OpenAI(api_key=settings.openai_api_key)
        self.model = settings.openai_model

    def review(self, code: str, filename: str = "<code>") -> ReviewResult:
        """Review code using LLM analysis.

        Args:
            code: Source code to review.
            filename: Filename for context.

        Returns:
            Structured review result.
        """
        prompt = CODE_REVIEW_PROMPT.format(
            filename=filename,
            code=code[:10000],  # Limit for token budget
        )

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.1,
                response_format={"type": "json_object"},
            )

            content = response.choices[0].message.content or "{}"
            data = json.loads(content)

            issues = []
            for item in data.get("issues", []):
                issues.append(
                    ReviewIssue(
                        category=item.get("category", "general"),
                        severity=item.get("severity", "medium"),
                        title=item.get("title", "Issue"),
                        description=item.get("description", ""),
                        lineno=item.get("lineno"),
                        suggestion=item.get("suggestion", ""),
                    )
                )

            result = ReviewResult(
                summary=data.get("summary", "Review complete."),
                issues=issues,
                score=data.get("score", 5),
                improvements=data.get("improvements", []),
            )

            logger.info(
                f"LLM review of {filename}: {len(issues)} issues, "
                f"score={result.score}/10"
            )
            return result

        except Exception as e:
            logger.error(f"LLM review failed: {e}")
            return ReviewResult(
                summary=f"Review failed: {str(e)}",
                issues=[],
                score=0,
                improvements=[],
            )
