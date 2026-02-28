"""CodeSentinel — FastAPI Application.

AI-Powered Code Review Agent for CI/CD Pipelines.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse

from app.config import get_settings
from app.models.schemas import ReviewRequest, ReviewReport
from app.reports.generator import ReportGenerator
from app.integrations.github_webhook import GitHubWebhookHandler
from app.integrations.formatter import format_markdown

logger = logging.getLogger(__name__)

# Store reports
_reports: dict[str, ReviewReport] = {}
_generator: ReportGenerator | None = None
_webhook_handler: GitHubWebhookHandler | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _generator, _webhook_handler
    settings = get_settings()
    logging.basicConfig(
        level=getattr(logging, settings.log_level),
        format="%(asctime)s | %(name)s | %(levelname)s | %(message)s",
    )
    logger.info(f"Starting {settings.app_name} v{settings.app_version}")
    _generator = ReportGenerator()
    _webhook_handler = GitHubWebhookHandler()
    yield
    logger.info("Shutting down CodeSentinel")


app = FastAPI(
    title="CodeSentinel API",
    description="AI-Powered Code Review Agent",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
async def health_check():
    settings = get_settings()
    return {
        "status": "healthy",
        "app": settings.app_name,
        "version": settings.app_version,
        "reports_generated": len(_reports),
    }


@app.post("/api/v1/review")
async def review_code(request: ReviewRequest):
    """Review a code snippet."""
    settings = get_settings()

    if len(request.code) > settings.max_code_length:
        raise HTTPException(
            status_code=400,
            detail=f"Code exceeds maximum length of {settings.max_code_length} characters.",
        )

    try:
        report = _generator.generate(
            code=request.code,
            filename=request.filename,
            enable_security=request.enable_security,
            enable_llm_review=True,
        )

        _reports[report.report_id] = report

        return report.model_dump()

    except Exception as e:
        logger.error(f"Review failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/review/file")
async def review_file(file: UploadFile = File(...)):
    """Upload and review a Python file."""
    if not file.filename or not file.filename.endswith(".py"):
        raise HTTPException(status_code=400, detail="Only .py files are supported.")

    content = await file.read()
    code = content.decode("utf-8", errors="replace")

    try:
        report = _generator.generate(
            code=code,
            filename=file.filename,
            enable_security=True,
            enable_llm_review=True,
        )

        _reports[report.report_id] = report
        return report.model_dump()

    except Exception as e:
        logger.error(f"File review failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/reports/{report_id}")
async def get_report(report_id: str, format: str = "json"):
    """Get a review report."""
    report = _reports.get(report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found.")

    if format == "markdown":
        md = format_markdown(report)
        return PlainTextResponse(content=md, media_type="text/markdown")

    return report.model_dump()


@app.post("/api/v1/webhook/github")
async def github_webhook(request: Request):
    """Handle GitHub webhook events."""
    payload = await request.json()
    signature = request.headers.get("X-Hub-Signature-256", "")

    body = await request.body()
    if not _webhook_handler.verify_signature(body, signature):
        raise HTTPException(status_code=401, detail="Invalid signature.")

    event = _webhook_handler.parse_event(payload)
    if not event:
        return {"message": "Event ignored"}

    return {
        "message": f"Received PR #{event.pr_number} from {event.repo_name}",
        "action": event.action,
        "status": "queued_for_review",
    }
