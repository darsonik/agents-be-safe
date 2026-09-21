"""Bounded JSON transport shared by GitHub and AI providers."""

import json
import urllib.error
import urllib.request

from .errors import ScanError


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ScanError("Upstream redirect refused. Use the canonical repository URL.")


def request_json(url, payload=None, token=None, limit=4_000_000):
    headers = {"Accept": "application/json", "User-Agent": "AgentsBeSafe/0.1"}
    if token:
        headers["Authorization"] = "Bearer " + token
    data = None
    if payload is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(payload).encode()
    try:
        with urllib.request.build_opener(NoRedirect).open(
            urllib.request.Request(url, data=data, headers=headers), timeout=90
        ) as response:
            raw = response.read(limit + 1)
        if len(raw) > limit:
            raise ScanError("Upstream response exceeded the scan size limit.")
        result = json.loads(raw)
        if not isinstance(result, dict):
            raise ScanError("Upstream response was not an object.")
        return result
    except urllib.error.HTTPError as exc:
        code = exc.code
        exc.close()
        raise ScanError(
            f"Upstream service returned HTTP {code}; check access, credentials, and rate limits."
        ) from None
    except urllib.error.URLError, TimeoutError, OSError, ValueError:
        raise ScanError("Upstream service was unavailable or returned invalid JSON.") from None
