"""FastAPI web application for the CTI Agents pipeline."""
from __future__ import annotations

import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List, Optional

from fastapi import BackgroundTasks, FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from web import storage
from web import feed_store
from pipeline import run_pipeline

STATIC_DIR = Path(__file__).parent / "static"

app = FastAPI(title="CTI Agents", version="1.0.0")

# Thread pool for running the synchronous pipeline without blocking the event loop
_executor = ThreadPoolExecutor(max_workers=4)


# ── Static files ───────────────────────────────────────────────────────────────

app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/", include_in_schema=False)
async def index():
    return FileResponse(str(STATIC_DIR / "index.html"))


# ── Feed management endpoints ──────────────────────────────────────────────────

@app.get("/api/feeds")
async def list_feeds():
    return feed_store.get_all_feeds()


@app.post("/api/feeds/rss", status_code=201)
async def add_rss_feed(name: str = Form(...), url: str = Form(...)):
    return feed_store.add_rss_feed(name, url)


@app.post("/api/feeds/api", status_code=201)
async def add_api_feed(
    name: str = Form(...),
    url: str = Form(...),
    method: str = Form("GET"),
):
    return feed_store.add_api_feed(name, url, method)


@app.delete("/api/feeds/{feed_id}")
async def delete_feed(feed_id: str):
    deleted = feed_store.delete_feed(feed_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Custom feed not found (built-ins cannot be deleted)")
    return {"deleted": feed_id}


# ── Run endpoints ──────────────────────────────────────────────────────────────

@app.get("/api/runs")
async def list_runs():
    return storage.list_runs()


@app.get("/api/runs/{run_id}")
async def get_run(run_id: str):
    record = storage.get_run(run_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Run not found")
    return record


@app.get("/api/runs/{run_id}/status")
async def get_run_status(run_id: str):
    record = storage.get_run(run_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Run not found")
    return {
        "run_id": run_id,
        "status": record.get("status"),
        "log": record.get("log", []),
        "final_score": record.get("final_score"),
        "total_iterations": record.get("total_iterations"),
        "error": record.get("error"),
        "name": record.get("name"),
        "feed_types": record.get("feed_types", []),
        "created_at": record.get("created_at"),
        "has_documents": record.get("has_documents", False),
        "document_names": record.get("document_names", []),
        "time_range": record.get("time_range"),
        "report": record.get("report"),
    }


@app.post("/api/runs", status_code=202)
async def start_run(
    background_tasks: BackgroundTasks,
    name: str = Form(...),
    feed_types: str = Form("rss,api"),
    max_iterations: int = Form(3),
    quality_threshold: int = Form(7),
    stix_url: Optional[str] = Form(None),
    selected_rss: Optional[str] = Form(None),
    selected_api: Optional[str] = Form(None),
    files: List[UploadFile] = File(default=[]),
    time_range: str = Form("7d"),
    date_from: Optional[str] = Form(None),
    date_to: Optional[str] = Form(None),
    hunt_refinement_iters: int = Form(2),
):
    run_id = str(uuid.uuid4())
    parsed_feeds = [f.strip() for f in feed_types.split(",") if f.strip()]
    if not parsed_feeds:
        parsed_feeds = ["rss", "api"]

    # Compute time_from / time_to from time_range preset or custom dates
    now = datetime.now(timezone.utc)
    time_from: datetime | None = None
    time_to: datetime | None = None
    if time_range == "24h":
        time_from, time_to = now - timedelta(hours=24), now
    elif time_range == "7d":
        time_from, time_to = now - timedelta(days=7), now
    elif time_range == "30d":
        time_from, time_to = now - timedelta(days=30), now
    elif time_range == "custom":
        if date_from:
            time_from = datetime.strptime(date_from, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        if date_to:
            time_to = datetime.strptime(date_to, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    # "all" → both remain None

    # Resolve per-feed selections to full feed dicts
    all_feeds = feed_store.get_all_feeds()

    selected_rss_feeds: list[dict] | None = None
    if selected_rss is not None:
        rss_ids = {s.strip() for s in selected_rss.split(",") if s.strip()}
        selected_rss_feeds = [f for f in all_feeds["rss"] if f["id"] in rss_ids]

    selected_api_feeds: list[dict] | None = None
    if selected_api is not None:
        api_ids = {s.strip() for s in selected_api.split(",") if s.strip()}
        selected_api_feeds = [f for f in all_feeds["api"] if f["id"] in api_ids]

    # Read file bytes NOW (UploadFile stream closes after endpoint returns)
    uploads: list[dict] = []
    doc_names: list[str] = []
    for uf in files:
        if not uf.filename:
            continue
        data = await uf.read()
        if data:
            uploads.append(
                {
                    "filename": uf.filename,
                    "content_type": uf.content_type or "",
                    "bytes": data,
                }
            )
            doc_names.append(uf.filename)

    storage.create_run(
        run_id=run_id,
        name=name,
        feed_types=parsed_feeds,
        has_documents=bool(uploads),
        document_names=doc_names,
        time_range=time_range,
    )

    background_tasks.add_task(
        _run_pipeline_task,
        run_id=run_id,
        feed_types=parsed_feeds,
        max_iterations=max_iterations,
        quality_threshold=quality_threshold,
        stix_url=stix_url or None,
        uploads=uploads,
        selected_rss_feeds=selected_rss_feeds,
        selected_api_feeds=selected_api_feeds,
        time_from=time_from,
        time_to=time_to,
        hunt_refinement_iters=hunt_refinement_iters,
    )

    return {"run_id": run_id, "status": "pending"}


@app.delete("/api/runs/{run_id}")
async def delete_run(run_id: str):
    deleted = storage.delete_run(run_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Run not found")
    return {"deleted": run_id}


# ── Background task ────────────────────────────────────────────────────────────

def _run_pipeline_task(
    run_id: str,
    feed_types: list[str],
    max_iterations: int,
    quality_threshold: int,
    stix_url: str | None,
    uploads: list[dict],
    selected_rss_feeds: list[dict] | None = None,
    selected_api_feeds: list[dict] | None = None,
    time_from: datetime | None = None,
    time_to: datetime | None = None,
    hunt_refinement_iters: int = 2,
) -> None:
    """Runs the synchronous pipeline in the background and persists results."""
    storage.update_run_status(run_id, "running")

    def _cb(token: str) -> None:
        storage.append_log(run_id, token)

    try:
        report = run_pipeline(
            feed_types=feed_types,
            max_iterations=max_iterations,
            quality_threshold=quality_threshold,
            stix_url=stix_url,
            document_uploads=uploads if uploads else None,
            progress_callback=_cb,
            selected_rss_feeds=selected_rss_feeds,
            selected_api_feeds=selected_api_feeds,
            time_from=time_from,
            time_to=time_to,
            hunt_refinement_iters=hunt_refinement_iters,
        )
        storage.complete_run(run_id, report)
    except Exception as exc:
        storage.fail_run(run_id, str(exc))
