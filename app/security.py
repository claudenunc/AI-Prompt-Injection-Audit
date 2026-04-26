import os
import threading
import time

from fastapi import Header, HTTPException, Request, status
from fastapi.responses import JSONResponse


PROTECTED_PATHS = {"/firewall", "/history"}
RATE_LIMIT_STATE: dict[str, list[float]] = {}
RATE_LIMIT_LOCK = threading.Lock()


def get_api_key() -> str | None:
    return os.getenv("FIREWALL_API_KEY")


def require_api_key(x_api_key: str | None = Header(default=None)) -> None:
    configured_key = get_api_key()
    if not configured_key:
        return

    if x_api_key != configured_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key.",
        )


def get_rate_limit_requests() -> int:
    return int(os.getenv("RATE_LIMIT_REQUESTS", "30"))


def get_rate_limit_window_seconds() -> int:
    return int(os.getenv("RATE_LIMIT_WINDOW_SECONDS", "60"))


def reset_rate_limit_state() -> None:
    with RATE_LIMIT_LOCK:
        RATE_LIMIT_STATE.clear()


async def rate_limit_middleware(request: Request, call_next):
    if request.url.path not in PROTECTED_PATHS:
        return await call_next(request)

    now = time.time()
    window_seconds = get_rate_limit_window_seconds()
    max_requests = get_rate_limit_requests()
    client_host = request.client.host if request.client else "unknown"
    route_key = f"{client_host}:{request.url.path}"

    with RATE_LIMIT_LOCK:
        timestamps = RATE_LIMIT_STATE.get(route_key, [])
        timestamps = [ts for ts in timestamps if now - ts < window_seconds]

        if len(timestamps) >= max_requests:
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={
                    "detail": "Rate limit exceeded.",
                    "limit": max_requests,
                    "window_seconds": window_seconds,
                },
            )

        timestamps.append(now)
        RATE_LIMIT_STATE[route_key] = timestamps

    return await call_next(request)
