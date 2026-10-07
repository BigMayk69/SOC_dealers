"""Tiny dependency-free static server with .env support for the SOC frontend."""
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import os
import json

ROOT = Path(__file__).resolve().parent

def read_env_file():
    env_file = ROOT / ".env"
    if not env_file.exists():
        return
    for line in env_file.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))

class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(ROOT), **kwargs)

    def do_GET(self):
        if self.path.split("?", 1)[0] == "/_config.js":
            api_url = os.environ.get("SOC_API_BASE_URL", "http://localhost:8000").rstrip("/")
            body = f"window.SOC_API_BASE_URL = {json.dumps(api_url)};\n".encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/javascript; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path == "/":
            self.path = "/index.html"
        return super().do_GET()

if __name__ == "__main__":
    read_env_file()
    port = int(os.environ.get("FRONTEND_PORT", "5173"))
    print(f"Dealers SOC frontend: http://localhost:{port}")
    print(f"Backend API: {os.environ.get('SOC_API_BASE_URL', 'http://localhost:8000')}")
    ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()
