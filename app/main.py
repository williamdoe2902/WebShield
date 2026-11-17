from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from app.scanner import scan_target, validate_target


ROOT = Path(__file__).resolve().parent
app = FastAPI(title="WebShield", docs_url=None, redoc_url=None)
app.mount("/static", StaticFiles(directory=ROOT / "static"), name="static")
templates = Jinja2Templates(directory=ROOT / "templates")
scans: dict[str, dict[str, Any]] = {}
scan_order: list[str] = []
monitors: dict[str, dict[str, Any]] = {}
MONITOR_INTERVAL_SECONDS = 5 * 60
monitor_task: asyncio.Task[None] | None = None


class ScanRequest(BaseModel):
    target: str
    authorized: bool = False


class MonitorRequest(BaseModel):
    target: str
    authorized: bool = False


def _local_client(request: Request) -> bool:
    client = request.client.host if request.client else ""
    try:
        import ipaddress
        return ipaddress.ip_address(client).is_loopback
    except ValueError:
        return False


def _check_origin(request: Request) -> None:
    if not _local_client(request):
        raise HTTPException(status_code=403, detail="Dashboard access is restricted to this machine.")
    origin = request.headers.get("origin")
    if origin:
        dashboard_origin = f"{request.url.scheme}://{request.headers.get('host', '')}"
        if origin.rstrip("/") != dashboard_origin.rstrip("/"):
            raise HTTPException(status_code=403, detail="Cross-origin scan requests are not accepted.")


async def _run_scan(scan_id: str, target: str) -> None:
    scans[scan_id]["status"] = "running"

    def update_progress(pages_scanned: int, pages_visited: int, current_url: str) -> None:
        scans[scan_id].update({
            "pages_scanned": pages_scanned,
            "pages_visited": pages_visited,
            "current_url": current_url,
        })

    try:
        result = await asyncio.to_thread(scan_target, target, True, on_progress=update_progress)
        scans[scan_id].update(result)
        scans[scan_id]["status"] = "complete"
    except Exception as error:
        scans[scan_id]["status"] = "failed"
        scans[scan_id]["error"] = str(error)
    finally:
        scans[scan_id]["finished_at"] = datetime.now(timezone.utc).isoformat()


def _create_scan_record(target: str) -> str:
    scan_id = uuid.uuid4().hex[:12]
    scans[scan_id] = {
        "id": scan_id,
        "target": target,
        "status": "queued",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "pages_scanned": 0,
        "pages_visited": 0,
        "pages": [],
        "findings": [],
    }
    scan_order.insert(0, scan_id)
    del scan_order[50:]
    return scan_id


def _finding_keys(findings: list[dict[str, Any]]) -> set[tuple[str, str, str]]:
    return {
        (finding["title"], finding["url"], finding["severity"])
        for finding in findings
    }


async def _run_monitor_scan(monitor_id: str) -> None:
    monitor = monitors.get(monitor_id)
    if monitor is None or monitor["status"] == "checking":
        return
    monitor["status"] = "checking"
    scan_id = _create_scan_record(monitor["target"])
    monitor["scan_id"] = scan_id
    await _run_scan(scan_id, monitor["target"])
    monitor = monitors.get(monitor_id)
    if monitor is None:
        return
    monitor["last_checked_at"] = scans[scan_id].get("finished_at")
    monitor["status"] = scans[scan_id]["status"]
    if scans[scan_id]["status"] == "complete":
        findings = scans[scan_id]["findings"]
        current_keys = _finding_keys(findings)
        previous_keys = monitor.get("finding_keys")
        monitor["new_findings"] = [
            finding for finding in findings
            if previous_keys is None
            or (finding["title"], finding["url"], finding["severity"]) not in previous_keys
        ]
        monitor["finding_keys"] = current_keys
        monitor["finding_count"] = len(findings)


async def _monitor_loop() -> None:
    while True:
        await asyncio.sleep(MONITOR_INTERVAL_SECONDS)
        for monitor_id in list(monitors):
            await _run_monitor_scan(monitor_id)


@app.on_event("startup")
async def start_monitor_loop() -> None:
    global monitor_task
    monitor_task = asyncio.create_task(_monitor_loop())


@app.on_event("shutdown")
async def stop_monitor_loop() -> None:
    if monitor_task:
        monitor_task.cancel()
        try:
            await monitor_task
        except asyncio.CancelledError:
            pass


@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    return templates.TemplateResponse(request, "index.html", {"scans": [scans[key] for key in scan_order]})


@app.post("/api/scans", status_code=202)
async def create_scan(payload: ScanRequest, request: Request):
    _check_origin(request)
    try:
        target = validate_target(payload.target, payload.authorized)
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    scan_id = _create_scan_record(target)
    asyncio.create_task(_run_scan(scan_id, target))
    return {"id": scan_id, "status": "queued"}


@app.get("/api/monitors")
async def list_monitors():
    return [
        {key: value for key, value in monitor.items() if key != "finding_keys"}
        for monitor in monitors.values()
    ]


@app.post("/api/monitors", status_code=202)
async def create_monitor(payload: MonitorRequest, request: Request):
    _check_origin(request)
    try:
        target = validate_target(payload.target, payload.authorized)
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    if any(monitor["target"] == target for monitor in monitors.values()):
        raise HTTPException(status_code=409, detail="This target is already being monitored.")
    monitor_id = uuid.uuid4().hex[:12]
    monitor = {
        "id": monitor_id,
        "target": target,
        "interval_seconds": MONITOR_INTERVAL_SECONDS,
        "status": "queued",
        "added_at": datetime.now(timezone.utc).isoformat(),
        "last_checked_at": None,
        "finding_count": 0,
        "new_findings": [],
        "scan_id": None,
    }
    monitors[monitor_id] = monitor
    asyncio.create_task(_run_monitor_scan(monitor_id))
    return monitor


@app.delete("/api/monitors/{monitor_id}", status_code=204)
async def delete_monitor(monitor_id: str, request: Request):
    _check_origin(request)
    if monitor_id not in monitors:
        raise HTTPException(status_code=404, detail="Monitor not found.")
    del monitors[monitor_id]


@app.get("/api/scans")
async def list_scans():
    return [{key: value for key, value in scans[scan_id].items() if key not in {"pages"}} for scan_id in scan_order]


@app.get("/api/scans/{scan_id}")
async def scan_status(scan_id: str):
    if scan_id not in scans:
        raise HTTPException(status_code=404, detail="Scan not found.")
    return scans[scan_id]


@app.get("/reports/{scan_id}", response_class=HTMLResponse)
async def scan_report(request: Request, scan_id: str):
    if scan_id not in scans:
        raise HTTPException(status_code=404, detail="Scan not found.")
    return templates.TemplateResponse(request, "report.html", {"scan": scans[scan_id]})