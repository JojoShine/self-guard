from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
import os
import re
os.chdir('/opt/self-guard/public/acme')
class Handler(SimpleHTTPRequestHandler):
    def setup(self):
        super().setup()
        self.connection.settimeout(10)
    def do_GET(self):
        if re.fullmatch(r'/\.well-known/acme-challenge/[A-Za-z0-9_-]{1,256}', self.path):
            super().do_GET()
        else:
            self.send_error(503)
    def do_HEAD(self):
        self.send_error(503)
    def log_message(self, *args):
        pass
class ChallengeServer(ThreadingHTTPServer):
    request_queue_size = 128
    daemon_threads = True
ChallengeServer(('0.0.0.0', 80), Handler).serve_forever()
