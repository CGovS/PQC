"""Loopback-only interactive lab. Serves an explicit public asset allowlist."""
import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit
from maze.lab import create_challenge

DEMO = Path(__file__).resolve().parents[1] / 'demo'
ASSETS = {'/': ('index.html', 'text/html'), '/index.html': ('index.html', 'text/html'),
          '/style.css': ('style.css', 'text/css'), '/app.js': ('app.js', 'text/javascript'),
          '/quantum.js': ('quantum.js', 'text/javascript'), '/worker.js': ('worker.js', 'text/javascript')}

class Handler(BaseHTTPRequestHandler):
    def respond(self, status, body, kind='application/json'):
        self.send_response(status)
        self.send_header('Content-Type', kind + '; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Content-Security-Policy', "default-src 'self'; style-src 'self'; script-src 'self'; worker-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'")
        self.end_headers()
        self.wfile.write(body)

    def local_request(self):
        allowed = {f'localhost:{self.server.server_port}', f'127.0.0.1:{self.server.server_port}'}
        host = self.headers.get('Host', '')
        origin = self.headers.get('Origin')
        return host in allowed and (origin is None or origin == 'http://' + host)

    def do_GET(self):
        if not self.local_request():
            return self.respond(403, b'{"error":"local requests only"}')
        path = urlsplit(self.path).path
        if path == '/favicon.ico':
            return self.respond(204, b'')
        if path == '/api/health':
            return self.respond(200, b'{"service":"pqc-lab","version":"3.0.0"}')
        if path not in ASSETS:
            return self.respond(404, b'{"error":"not found"}')
        name, kind = ASSETS[path]
        return self.respond(200, (DEMO / name).read_bytes(), kind)

    def do_POST(self):
        if not self.local_request():
            return self.respond(403, b'{"error":"local requests only"}')
        if self.path != '/api/run':
            return self.respond(404, b'{"error":"not found"}')
        # No user input is needed; bound request bodies and never evaluate code.
        if self.headers.get('Content-Length', '0') != '0' or self.headers.get('Transfer-Encoding'):
            self.close_connection = True
            return self.respond(400, b'{"error":"request must be empty"}')
        try:
            data = create_challenge()
            return self.respond(200, json.dumps(data).encode())
        except Exception:
            self.log_error('challenge generation failed')
            return self.respond(500, b'{"error":"Encryption or verification failed. Check the local server."}')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', type=int, default=8765)
    args = parser.parse_args()
    with ThreadingHTTPServer(('127.0.0.1', args.port), Handler) as server:
        print(f'PQC lab: http://localhost:{args.port}', flush=True)
        server.serve_forever()

if __name__ == '__main__':
    main()
