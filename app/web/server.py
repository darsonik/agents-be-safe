"""Local HTTP routes and composition root; all scan work is delegated."""

from __future__ import annotations

import json
import logging
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from app.config import Settings
from app.errors import ScanError
from app.scanning.assessment import AssessmentService
from app.scanning.repository import parse_repo

from .jobs import JobManager

logger = logging.getLogger("agents_be_safe.server")

STATIC = Path(__file__).resolve().parents[2] / "static"


class Handler(BaseHTTPRequestHandler):
    server: ApplicationServer

    def setup(self):
        super().setup()
        self.connection.settimeout(15)

    def log_message(self, *_):
        pass

    def send(self, status, body, content_type="application/json"):
        raw = json.dumps(body).encode() if content_type == "application/json" else body
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
        )
        self.end_headers()
        self.wfile.write(raw)

    def trusted(self):
        port = self.server.server_port
        hosts = {f"localhost:{port}", f"127.0.0.1:{port}"}
        origin = self.headers.get("Origin")
        return self.headers.get("Host") in hosts and (
            origin is None or origin in {"http://" + host for host in hosts}
        )

    def do_GET(self):
        if not self.trusted():
            return self.send(403, {"error": "Local access only"})
        if self.path == "/api/config":
            return self.send(200, self.server.settings.provider_status)
        if self.path.startswith("/api/scans/"):
            job = self.server.jobs.get(self.path.removeprefix("/api/scans/"))
            return self.send(200 if job else 404, job or {"error": "Report not found or expired"})
        assets = {
            "/": ("index.html", "text/html; charset=utf-8"),
            "/app.js": ("app.js", "text/javascript; charset=utf-8"),
            "/style.css": ("style.css", "text/css; charset=utf-8"),
        }
        if self.path in assets:
            name, mime = assets[self.path]
            return self.send(200, (STATIC / name).read_bytes(), mime)
        self.send(404, {"error": "Not found"})

    def do_POST(self):
        if not self.trusted() or self.headers.get("Content-Type") != "application/json":
            return self.send(403, {"error": "Only same-origin JSON requests are accepted"})
        if self.path != "/api/scans":
            return self.send(404, {"error": "Not found"})
        try:
            size = int(self.headers.get("Content-Length", "0"))
            if not 0 < size <= 2048:
                raise ScanError("Invalid request size")
            payload = json.loads(self.rfile.read(size))
            if not isinstance(payload, dict):
                raise ScanError("Expected a JSON object")
            demo = payload.get("demo") is True
            url = payload.get("url", "")
            if not demo:
                parse_repo(url)
        except (ValueError, ScanError) as exc:
            return self.send(400, {"error": str(exc)})
        job_id = self.server.jobs.submit(url, demo)
        if job_id is None:
            return self.send(429, {"error": "Two scans are running. Try again shortly."})
        self.send(202, {"id": job_id})


class ApplicationServer(ThreadingHTTPServer):
    allow_reuse_address = sys.platform != "win32"

    def __init__(self, address: tuple[str, int], settings: Settings):
        self.settings = settings
        self.jobs = JobManager(settings, AssessmentService.from_settings(settings))
        super().__init__(address, Handler)


def create_server(
    settings: Settings | None = None, *, port: int | None = None
) -> ApplicationServer:
    """Construct an isolated server. Tests may pass port=0 for a free port."""
    settings = settings if settings is not None else Settings.from_env()
    return ApplicationServer(("127.0.0.1", settings.port if port is None else port), settings)


def serve() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )
    server = create_server()
    logger.info("Agents Be Safe starting at http://127.0.0.1:%s", server.server_port)
    logger.info(
        "Configured providers: Fireworks=%s (%s), Jev=%s (%s), GitHub Token=%s",
        server.settings.provider_status["fireworks"],
        server.settings.fireworks_model or "none",
        server.settings.provider_status["jev"],
        server.settings.typesafe_model,
        bool(server.settings.github_token),
    )
    print(f"Agents Be Safe is running at http://127.0.0.1:{server.server_port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
