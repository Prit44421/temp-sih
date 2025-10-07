"""FastAPI application exposing the Kavach backend."""
from __future__ import annotations

from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException
from fastapi.security import APIKeyHeader
from fastapi.staticfiles import StaticFiles

from .api import endpoints


FRONTEND_PATH = Path(__file__).resolve().parents[2] / "frontend"

app = FastAPI(title="Kavach API")

API_TOKEN_NAME = "X-Kavach-Token"
api_key_header = APIKeyHeader(name=API_TOKEN_NAME, auto_error=False)


async def get_api_key(token: str = Depends(api_key_header)) -> str:
    """Validate that the provided token matches the TUI-issued credential."""

    if getattr(app.state, "token", None) == token:
        return token
    raise HTTPException(status_code=403, detail="Could not validate credentials")


app.include_router(endpoints.router, prefix="/api", dependencies=[Depends(get_api_key)])


@app.get("/")
def read_root() -> dict:
    """Basic health endpoint for the API."""

    return {"message": "Kavach backend is running", "web_ui": "/ui"}


if FRONTEND_PATH.exists():
    app.mount("/ui", StaticFiles(directory=str(FRONTEND_PATH), html=True), name="web-ui")

