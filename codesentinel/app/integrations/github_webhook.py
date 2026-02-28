"""CodeSentinel — GitHub Webhook Handler."""

from __future__ import annotations

import hashlib
import hmac
import logging
from dataclasses import dataclass

from app.config import get_settings

logger = logging.getLogger(__name__)


@dataclass
class WebhookEvent:
    """Parsed GitHub webhook event."""

    action: str
    repo_name: str
    pr_number: int | None
    sender: str
    files_changed: list[dict]


class GitHubWebhookHandler:
    """Handle incoming GitHub webhook events for PR code review."""

    def __init__(self):
        self.settings = get_settings()

    def verify_signature(self, payload: bytes, signature: str) -> bool:
        """Verify the webhook signature using the shared secret.

        Args:
            payload: Raw request body.
            signature: X-Hub-Signature-256 header value.

        Returns:
            True if signature is valid.
        """
        if not self.settings.github_webhook_secret:
            logger.warning("No webhook secret configured — skipping verification")
            return True

        expected = (
            "sha256="
            + hmac.new(
                self.settings.github_webhook_secret.encode(),
                payload,
                hashlib.sha256,
            ).hexdigest()
        )

        return hmac.compare_digest(expected, signature)

    def parse_event(self, payload: dict) -> WebhookEvent | None:
        """Parse a GitHub webhook payload into a structured event.

        Args:
            payload: Parsed JSON webhook payload.

        Returns:
            WebhookEvent or None if not a relevant event.
        """
        action = payload.get("action", "")

        # We only care about PR events
        pr = payload.get("pull_request")
        if not pr:
            logger.info(f"Ignoring non-PR event: action={action}")
            return None

        if action not in ("opened", "synchronize", "reopened"):
            logger.info(f"Ignoring PR action: {action}")
            return None

        repo = payload.get("repository", {})

        event = WebhookEvent(
            action=action,
            repo_name=repo.get("full_name", ""),
            pr_number=pr.get("number"),
            sender=payload.get("sender", {}).get("login", ""),
            files_changed=[],  # Would be fetched from GH API in production
        )

        logger.info(
            f"Parsed webhook: {event.repo_name} PR #{event.pr_number} ({event.action})"
        )
        return event
