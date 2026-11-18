"""HTTP API and static web interface for Asli Link.

Privacy: pasted text is checked in memory and is never stored or logged. The server makes no
outbound requests; links are parsed, never opened.
"""

from __future__ import annotations

import logging
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from asli import __version__
from asli.checker import Checker
from asli.registry import RegistryError, default_registry
from asli.urls import MAX_TEXT_CHARS, LinkError

STATIC_DIR = Path(__file__).resolve().parent / "static"
logger = logging.getLogger("asli_link")

try:
    REGISTRY = default_registry()
except RegistryError as exc:  # fail closed: refuse to start rather than answer with an empty registry
    raise SystemExit(f"Asli Link cannot start: {exc}") from exc

CHECKER = Checker(REGISTRY)

app = FastAPI(
    title="Asli Link API",
    version=__version__,
    description="Checks whether links belong to the Indian bank or government office they claim to be. "
    "Answers come from official namespaces (.bank.in, .gov.in, .nic.in) and a curated registry; "
    "nothing is fetched and nothing you send is stored.",
)

SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; "
    "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "X-Frame-Options": "DENY",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cache-Control": "no-store",
}


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    for name, value in SECURITY_HEADERS.items():
        response.headers.setdefault(name, value)
    return response


class CheckRequest(BaseModel):
    text: str = Field(
        ...,
        min_length=1,
        max_length=MAX_TEXT_CHARS,
        description="A link, or a whole SMS/WhatsApp message containing links.",
    )


@app.get("/api/health")
def health() -> dict:
    return {"status": "ok", "registry_version": REGISTRY.version}


@app.post("/api/check")
def check(body: CheckRequest) -> dict:
    try:
        return CHECKER.check_message(body.text).to_dict()
    except LinkError as exc:
        raise HTTPException(422, str(exc)) from exc
    except Exception:  # never echo user text into logs
        logger.exception("check failed")
        raise HTTPException(500, "The check could not be completed.") from None


@app.get("/api/registry")
def registry_info() -> dict:
    return {
        "version": REGISTRY.version,
        "sha256": REGISTRY.sha256,
        "namespaces": [ns.__dict__ for ns in REGISTRY.namespaces],
        "entities": [
            {
                "id": e.id,
                "kind": e.kind,
                "name": e.name,
                "bank_in": list(e.bank_in),
                "other_official": list(e.other_official),
            }
            for e in REGISTRY.entities
        ],
        "observed_bank_in_count": len(REGISTRY.observed_bank_in),
        "observed_source": REGISTRY.observed_source,
    }


@app.exception_handler(404)
async def not_found(request: Request, exc) -> JSONResponse:
    return JSONResponse({"detail": "Not found"}, status_code=404)


@app.get("/", include_in_schema=False)
def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
