"""Loopback-only development server with bounded background jobs."""
import json
import os
import secrets
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from .scanner import ScanError, assess, collect, demo_snapshot, parse_repo

STATIC = Path(__file__).resolve().parent.parent / "static"
JOBS = {}
LOCK = threading.Lock()
SLOTS = threading.BoundedSemaphore(2)

def run_job(job_id, url, demo):
    def update(message):
        with LOCK:
            JOBS[job_id]["message"] = message
    try:
        snapshot = demo_snapshot() if demo else collect(url, update)
        report = assess(snapshot, "demo" if demo else "live", update)
        with LOCK:
            JOBS[job_id].update(status="completed", report=report, message="Report ready")
    except Exception as exc:
        with LOCK:
            JOBS[job_id].update(status="failed", message=str(exc) if isinstance(exc, ScanError) else "Scan failed unexpectedly. Please try again.")
    finally:
        SLOTS.release()

class Handler(BaseHTTPRequestHandler):
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
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
        self.end_headers()
        self.wfile.write(raw)

    def trusted(self):
        port = self.server.server_port
        hosts = {f"localhost:{port}", f"127.0.0.1:{port}"}
        origin = self.headers.get("Origin")
        return self.headers.get("Host") in hosts and (origin is None or origin in {"http://" + host for host in hosts})

    def do_GET(self):
        if not self.trusted():
            return self.send(403, {"error": "Local access only"})
        if self.path == "/api/config":
            return self.send(200, {"fireworks": bool(os.getenv("FIREWORKS_API_KEY") and os.getenv("FIREWORKS_MODEL")), "jev": bool(os.getenv("TYPESAFE_API_KEY"))})
        if self.path.startswith("/api/scans/"):
            with LOCK:
                job = dict(JOBS.get(self.path.removeprefix("/api/scans/"), {}))
            return self.send(200 if job else 404, job or {"error": "Report not found or expired"})
        assets = {"/": ("index.html", "text/html; charset=utf-8"), "/app.js": ("app.js", "text/javascript; charset=utf-8"), "/style.css": ("style.css", "text/css; charset=utf-8")}
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
        if not SLOTS.acquire(blocking=False):
            return self.send(429, {"error": "Two scans are running. Try again shortly."})
        job_id = secrets.token_urlsafe(24)
        with LOCK:
            expired = [key for key, value in JOBS.items() if value["status"] != "running" and time.time() - value["started"] > 3600]
            for key in expired:
                del JOBS[key]
            completed = [key for key, value in JOBS.items() if value["status"] != "running"]
            for key in completed[:-18]:
                del JOBS[key]
            JOBS[job_id] = {"status": "running", "message": "Preparing scan", "started": time.time()}
        threading.Thread(target=run_job, args=(job_id, url, demo), daemon=True).start()
        self.send(202, {"id": job_id})

def serve():
    port = int(os.getenv("PORT", "8000"))
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"Agents Be Safe is running at http://127.0.0.1:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.server_close()
