#!/usr/bin/env python3
"""Visma HIVE MCP bridge: a local stdio MCP server that forwards to the HIVE server over
mutual TLS.

Claude Code's HTTP MCP client cannot present a TLS client certificate, and the Visma HIVE
server only accepts connections that do. This bridge runs as a stdio MCP server (started
by the plugin's .mcp.json), reads one JSON-RPC message per line from stdin, POSTs it to the
server's /mcp endpoint with the agent's client certificate, and writes the reply to stdout.
The Mcp-Session-Id the server returns is carried on every later request.

No API key or password is read or sent: the certificate is the agent's identity. The
certificate, key, optional CA and server address are the same settings the wake monitor
uses (see hive_wake.py). The MCP URL is HIVE_MCP_URL, else derived from HIVE_WS_URL
(wss://host/ws -> https://host/mcp).
"""
import http.client
import json
import os
import ssl
import sys
from urllib.parse import urlparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import hive_wake as hw  # noqa: E402  (same directory; shares the config + TLS rules)

TIMEOUT_S = 90


def mcp_url(env=None, conf=None):
    """The server's MCP endpoint (https://…/mcp), or "" when none is configured."""
    env = os.environ if env is None else env
    conf = hw.load_config(env) if conf is None else conf
    url = (env.get("HIVE_MCP_URL") or conf.get("HIVE_MCP_URL") or "").strip()
    if url:
        return url
    ws = hw.ws_url(env, conf)
    if not ws:
        return ""
    p = urlparse(ws)
    if p.scheme != "wss":
        return ""
    path = p.path[: -len("/ws")] if p.path.endswith("/ws") else p.path.rstrip("/")
    return f"https://{p.netloc}{path}/mcp"


def ssl_context(opts):
    """A client TLS context presenting the agent's certificate (opts from tls_options)."""
    ctx = ssl.create_default_context(cafile=opts.get("ca_certs"))
    ctx.load_cert_chain(opts["certfile"], opts["keyfile"])
    return ctx


def error_reply(msg_id, text):
    return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": -32000, "message": f"Visma HIVE bridge: {text}"}}


class Bridge:
    """Forwards JSON-RPC messages over one kept-alive HTTPS connection."""

    def __init__(self, url, ctx, connection_factory=http.client.HTTPSConnection):
        p = urlparse(url)
        if p.scheme != "https":
            raise hw.TlsConfigError("HIVE_MCP_URL must start with https://")
        self.host, self.port, self.path = p.hostname, p.port or 443, p.path or "/mcp"
        self.ctx, self.factory = ctx, connection_factory
        self.conn, self.session_id = None, None

    def _connection(self):
        if self.conn is None:
            self.conn = self.factory(self.host, self.port, context=self.ctx, timeout=TIMEOUT_S)
        return self.conn

    def post(self, body):
        """(status, response bytes) for one JSON-RPC body; reconnects once on a dropped link."""
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if self.session_id:
            headers["Mcp-Session-Id"] = self.session_id
        for attempt in (1, 2):
            try:
                conn = self._connection()
                conn.request("POST", self.path, body=body, headers=headers)
                resp = conn.getresponse()
                data = resp.read()
                sid = resp.getheader("Mcp-Session-Id")
                if sid:
                    self.session_id = sid
                return resp.status, data
            except (http.client.HTTPException, OSError):
                self.conn = None
                if attempt == 2:
                    raise
        raise RuntimeError("unreachable")

    def handle(self, line):
        """The line to write to stdout for one stdin line, or None (notification / blank)."""
        line = line.strip()
        if not line:
            return None
        try:
            msg = json.loads(line)
        except ValueError:
            return json.dumps(error_reply(None, "invalid JSON on stdin"))
        msg_id = msg.get("id") if isinstance(msg, dict) else None
        try:
            status, data = self.post(line.encode())
        except Exception as e:  # noqa: BLE001
            return json.dumps(error_reply(msg_id, f"cannot reach the server ({type(e).__name__})")) if msg_id is not None else None
        if msg_id is None:  # notification: the server answers 202 with no body
            return None
        if status in (401, 403):
            return json.dumps(error_reply(msg_id, f"refused ({status}): check that the agent's certificate is valid"))
        if status >= 400 or not data:
            return json.dumps(error_reply(msg_id, f"HTTP {status} from the server"))
        try:
            return json.dumps(json.loads(data))  # one line per message on stdout
        except ValueError:
            return json.dumps(error_reply(msg_id, "the server sent a non-JSON reply"))


def main():
    conf = hw.load_config()
    url = mcp_url(conf=conf)
    try:
        if not url:
            raise hw.TlsConfigError(f"no server address (set HIVE_WS_URL or HIVE_MCP_URL in {hw.CONFIG_FILE})")
        bridge = Bridge(url, ssl_context(hw.tls_options(conf=conf)))
    except (hw.TlsConfigError, ssl.SSLError, OSError) as bad:
        # Stay up and answer every request with the reason, so the session sees it.
        reason = str(bad)
        for line in sys.stdin:
            try:
                msg_id = json.loads(line).get("id")
            except (ValueError, AttributeError):
                continue
            if msg_id is not None:
                sys.stdout.write(json.dumps(error_reply(msg_id, reason)) + "\n")
                sys.stdout.flush()
        return
    for line in sys.stdin:
        out = bridge.handle(line)
        if out is not None:
            sys.stdout.write(out + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
