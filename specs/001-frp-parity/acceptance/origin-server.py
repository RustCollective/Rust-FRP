#!/usr/bin/env python3
"""验收用的内网 origin：`/` 回显收到的请求头，`/big?n=N` 回 N 字节。

用法：`python3 origin-server.py 18000`

- `/` 回显请求头是为了在真实链路上验证 X-Forwarded-For / X-Forwarded-Proto 是否
  真的到达内网服务，以及 h2 路径下的 Host 是否被补回。
- `/big?n=N` 用于流式转发的内存/正确性观测（SC-007）：先跑小 N 再跑大 N，
  比较上游 rfps 的 RSS 增量是否同量级；同时用收到的字节数与 N 比对是否被截断。

参考：specs/001-frp-parity/acceptance/2026-10-12-real-link.md
"""
import http.server
import json
import sys

CHUNK = 64 * 1024


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):  # noqa: N802
        if self.path.startswith("/big"):
            n = 1024 * 1024
            if "=" in self.path:
                try:
                    n = int(self.path.split("=", 1)[1])
                except ValueError:
                    pass
            self.send_response(200)
            self.send_header("Content-Length", str(n))
            self.send_header("Content-Type", "application/octet-stream")
            self.end_headers()
            chunk = b"\0" * CHUNK
            sent = 0
            while sent < n:
                m = min(CHUNK, n - sent)
                self.wfile.write(chunk[:m])
                sent += m
            return

        body = json.dumps(
            {k.lower(): v for k, v in self.headers.items()}, ensure_ascii=False
        ).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        # 静默：避免访问日志污染验收输出
        pass


if __name__ == "__main__":
    port = int(sys.argv[1])
    http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()
