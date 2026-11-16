#!/usr/bin/env python3
"""No external connections: synthetic HTML origin at 127.0.0.1:5207."""
from http.server import ThreadingHTTPServer,BaseHTTPRequestHandler
class H(BaseHTTPRequestHandler):
 def do_GET(self):
  data=b'<!doctype html><html><head><title>Public CORS lab</title></head><body>Lab origin</body></html>'
  self.send_response(200)
  self.send_header("Content-Type","text/html; charset=utf-8")
  self.send_header("Cache-Control","no-store")
  self.send_header("Content-Length",str(len(data)))
  self.end_headers();self.wfile.write(data)
 def log_message(self,*args):pass
ThreadingHTTPServer(("127.0.0.1",5207),H).serve_forever()
