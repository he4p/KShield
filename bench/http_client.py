from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any


class HttpError(RuntimeError):
    pass


def _read_body(resp: Any) -> bytes:
    data = resp.read()
    return data if isinstance(data, (bytes, bytearray)) else bytes(data)


def request_json(method: str, url: str, payload: Any | None = None, timeout_s: float = 5.0) -> Any:
    body: bytes | None = None
    headers = {"Accept": "application/json"}
    if payload is not None:
        body = json.dumps(payload, ensure_ascii=True).encode("utf-8")
        headers["Content-Type"] = "application/json"

    req = urllib.request.Request(url, data=body, headers=headers, method=method.upper())
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            raw = _read_body(resp)
    except urllib.error.HTTPError as exc:
        raw = exc.read() if hasattr(exc, "read") else b""
        raise HttpError(f"{method} {url} -> HTTP {exc.code}: {raw[:300]!r}") from exc
    except urllib.error.URLError as exc:
        raise HttpError(f"{method} {url} -> {exc}") from exc

    if not raw:
        return None
    try:
        return json.loads(raw.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise HttpError(f"{method} {url} -> invalid JSON: {raw[:300]!r}") from exc

