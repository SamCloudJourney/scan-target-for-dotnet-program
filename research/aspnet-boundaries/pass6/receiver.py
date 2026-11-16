#!/usr/bin/env python3
"""Second, distinct LOOPBACK host records only names, marker and referrer."""
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
import json
events=[]
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/_events":
            body=json.dumps({"events":events},indent=2).encode()
        else:
            events.append({
               "path":self.path,
               "host":self.headers.get("Host"),
               "referer":self.headers.get("Referer"),
               "cookie_names":[x.split("=",1)[0] for x in
                   (self.headers.get("Cookie") or "").split("; ") if "=" in x]
            })
            body=b"SECOND-LOOPBACK-ORIGIN-REACHED"
        self.send_response(200)
        self.send_header("Content-Type","application/json" if self.path=="/_events" else "text/plain")
        self.send_header("Content-Length",str(len(body)))
        self.end_headers(); self.wfile.write(body)
    def log_message(self,*args):pass
ThreadingHTTPServer(("127.0.0.2",5207),Handler).serve_forever()
