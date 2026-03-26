#!/usr/bin/env python3
"""
Fast HTTP server for testing
"""
from http.server import HTTPServer, BaseHTTPRequestHandler
import time

class FastHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(b"OK")
    
    def log_message(self, format, *args):
        # Minimal logging
        pass

def run_server(port=8080):
    server = HTTPServer(('0.0.0.0', port), FastHandler)
    print(f"Fast server listening on port {port}")
    print("Press Ctrl+C to stop")
    server.serve_forever()

if __name__ == '__main__':
    run_server()
