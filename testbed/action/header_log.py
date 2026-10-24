# Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
# SPDX-License-Identifier: AGPL-3.0-only

"""Serve a folder on 127.0.0.1 and log every request's headers.

action-test.yml scans this server through the Action's headers and
cookie inputs, then reads the log to check each header arrived whole
("Name: value with spaces") instead of split into words.

    python3 header_log.py <port> <folder> <log file>
"""

import functools
import http.server
import sys


class Handler(http.server.SimpleHTTPRequestHandler):
    """A static file handler that appends request headers to a log."""

    log_path = ""

    def _log_headers(self):
        with open(self.log_path, "a", encoding="utf-8") as log:
            for name, value in self.headers.items():
                log.write(f"{name}: {value}\n")

    def do_GET(self):
        self._log_headers()
        super().do_GET()

    def do_HEAD(self):
        self._log_headers()
        super().do_HEAD()

    def log_message(self, format, *args):
        pass


def main():
    port, folder, log_path = int(sys.argv[1]), sys.argv[2], sys.argv[3]
    Handler.log_path = log_path
    handler = functools.partial(Handler, directory=folder)
    http.server.ThreadingHTTPServer(("127.0.0.1", port), handler).serve_forever()


if __name__ == "__main__":
    main()
