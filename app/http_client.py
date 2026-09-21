"""Bounded JSON transport shared by GitHub and AI providers."""

import json
import logging
import urllib.error
import urllib.request

from .errors import ScanError

logger = logging.getLogger("agents_be_safe.http_client")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ScanError("Upstream redirect refused. Use the canonical repository URL.")


def request_json(url, payload=None, token=None, limit=4_000_000, timeout=180):
    headers = {"Accept": "application/json", "User-Agent": "AgentsBeSafe/0.1"}
    if token:
        headers["Authorization"] = "Bearer " + token
    data = None
    if payload is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(payload).encode()
    logger.info(
        "HTTP request -> %s (payload_bytes=%s, timeout=%ss)", url, len(data) if data else 0, timeout
    )
    try:
        with urllib.request.build_opener(NoRedirect).open(
            urllib.request.Request(url, data=data, headers=headers), timeout=timeout
        ) as response:
            raw = response.read(limit + 1)
        if len(raw) > limit:
            raise ScanError("Upstream response exceeded the scan size limit.")
        result = json.loads(raw)
        if not isinstance(result, dict):
            raise ScanError("Upstream response was not an object.")
        logger.info("HTTP response <- %s (status=200, bytes=%d)", url, len(raw))
        return result
    except urllib.error.HTTPError as exc:
        code = exc.code
        detail = ""
        try:
            err_body = exc.read(4096).decode("utf-8", errors="replace")
            err_json = json.loads(err_body)
            if isinstance(err_json, dict):
                msg = err_json.get("detail") or err_json.get("message") or err_json.get("error")
                if isinstance(msg, dict):
                    msg = msg.get("error_type") or msg.get("message") or str(msg)
                if msg:
                    detail = f": {msg}"
            elif err_body:
                detail = f": {err_body[:200]}"
        except Exception:
            pass
        finally:
            exc.close()
        logger.warning("HTTP error <- %s (status=%d%s)", url, code, detail)
        raise ScanError(
            f"Upstream service returned HTTP {code}{detail}; check access, credentials, and rate limits."
        ) from None
    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
        reason = getattr(exc, "reason", str(exc))
        detail = f": {reason}" if reason else ""
        logger.warning("HTTP connection error <- %s: %s%s", url, type(exc).__name__, detail)
        raise ScanError(
            f"Upstream service was unavailable or returned invalid JSON{detail}."
        ) from None
