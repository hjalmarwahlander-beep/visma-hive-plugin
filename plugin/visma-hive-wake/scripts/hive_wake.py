#!/usr/bin/env python3
"""Visma HIVE wake monitor for a Claude Code session.

Holds one WebSocket to the Visma HIVE server for this session's agent and prints one line
per direct message or @mention. Run by the visma-hive-wake plugin as a session-long
monitor, so each printed line wakes the session, even when it sits idle at its prompt.

Nothing is marked read here. The woken session reads its mail with its usual hive poll,
so "one agent_name = one reader" holds.

Authentication is the TLS client certificate issued to this agent (mutual TLS). There is
no API key or password: the server derives the agent's identity from the certificate.

Configuration (first match wins; the project file overrides the user file):
  files       <project>/.claude/visma-hive-wake.env, then ~/.config/visma-hive/wake.env
  agent name  HIVE_AGENT (env, project file, user file), else "**Agent Name**: <name>"
              in HIVE-RULES.md (several different names = no guess)
  server      HIVE_WS_URL, must be wss:// (no built-in default)
  certificate HIVE_TLS_CERT and HIVE_TLS_KEY (PEM paths), default
              ~/.config/visma-hive/client.crt and client.key; optional HIVE_TLS_CA
  wake list   HIVE_WAKE_CHANNELS: comma-separated channels where EVERY message wakes the
              session, e.g. "magic,deploys". "*" = every subscribed channel. Default:
              none, so only DMs and @mentions wake.
All values come from the instructions shown when the certificate is issued.

The last seen message rowid is kept per agent, so a reconnect asks the server to replay
what arrived meanwhile (since_rowid). The server never replays mail the agent already read.
"""
import json
import os
import re
import socket
import stat
import sys
import time
from pathlib import Path
from urllib.parse import urlparse

CONFIG_FILE = "~/.config/visma-hive/wake.env"
PROJECT_ENV = ".claude/visma-hive-wake.env"
DEFAULT_TLS_CERT = "~/.config/visma-hive/client.crt"
DEFAULT_TLS_KEY = "~/.config/visma-hive/client.key"
# A refused handshake (4xx) never heals by retrying; report it again after this long.
REFUSED_REPORT_EVERY_S = 600
# After a working connection drops (a server restart, say), stay quiet this long before
# reporting that the server cannot be reached.
UNREACHABLE_REPORT_AFTER_S = 300
# At most this many wake lines per replay burst; the rest are summed up in one line.
REPLAY_LINE_CAP = 10
PREVIEW_CHARS = 200

_AGENT_RE = re.compile(r"\*\*Agent Name\*\*:\s*`?([A-Za-z0-9_.-]+)`?")


def read_env_file(path=CONFIG_FILE):
    """KEY=VALUE pairs from the config file ({} when it is missing). Quotes are stripped."""
    out = {}
    try:
        with open(os.path.expanduser(path)) as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                out[k.strip()] = v.strip().strip("'\"")
    except OSError:
        pass
    return out


def _start_dir(env, cwd=None):
    # Start from the session's project dir (where Claude Code was started), not the shell's
    # cwd: a session working inside another repo must not take that repo's settings.
    return Path(cwd or env.get("HIVE_PROJECT_DIR") or os.getcwd()).resolve()


def project_config(env=None, cwd=None):
    """The nearest <dir>/.claude/visma-hive-wake.env walking up from the project dir ({})."""
    env = os.environ if env is None else env
    here = _start_dir(env, cwd)
    for d in [here, *here.parents]:
        conf = read_env_file(str(d / PROJECT_ENV))
        if conf:
            return conf
    return {}


def load_config(env=None, cwd=None):
    """User file overlaid with the project file (the project wins)."""
    env = os.environ if env is None else env
    return {**read_env_file(), **project_config(env, cwd)}


class AmbiguousAgent(Exception):
    """HIVE-RULES.md names several different agents and none was selected."""


def agent_name(env=None, cwd=None, conf=None):
    """This session's HIVE agent name, or None.

    Order: HIVE_AGENT in the environment, then HIVE_AGENT in the config files (project file
    over user file), then "**Agent Name**: <name>" in the nearest HIVE-RULES.md walking up
    from the session's project dir (HIVE_PROJECT_DIR, set by the plugin from
    ${CLAUDE_PROJECT_DIR}), else the cwd. A HIVE-RULES.md that names several different
    agents raises AmbiguousAgent instead of guessing.
    """
    env = os.environ if env is None else env
    name = (env.get("HIVE_AGENT") or "").strip()
    if name:
        return name
    conf = load_config(env, cwd) if conf is None else conf
    name = (conf.get("HIVE_AGENT") or "").strip()
    if name:
        return name
    here = _start_dir(env, cwd)
    for d in [here, *here.parents]:
        rules = d / "HIVE-RULES.md"
        try:
            text = rules.read_text(errors="replace")
        except OSError:
            continue
        names = list(dict.fromkeys(_AGENT_RE.findall(text)))
        if len(names) > 1:
            raise AmbiguousAgent(str(rules), names)
        if names:
            return names[0]
    return None


def ws_url(env=None, conf=None):
    """The server's WebSocket URL, or "" when none is configured. There is no default."""
    env = os.environ if env is None else env
    conf = load_config(env) if conf is None else conf
    return (env.get("HIVE_WS_URL") or conf.get("HIVE_WS_URL") or "").strip()


class TlsConfigError(Exception):
    """The TLS client certificate cannot be used (missing, unreadable, or not wss://)."""


def tls_options(env=None, conf=None, url=None):
    """sslopt for websocket-client: the client certificate, its key, and an optional CA.

    Raises TlsConfigError naming what to fix. The key file must not be readable by group or
    others. Never reads or sends an API key: the certificate is the agent's identity.
    """
    env = os.environ if env is None else env
    conf = load_config(env) if conf is None else conf
    if url is not None and urlparse(url).scheme != "wss":
        raise TlsConfigError("HIVE_WS_URL must start with wss:// (the server only accepts TLS)")
    get = lambda k, d=None: (env.get(k) or conf.get(k) or d or "").strip()  # noqa: E731
    cert = os.path.expanduser(get("HIVE_TLS_CERT", DEFAULT_TLS_CERT))
    key = os.path.expanduser(get("HIVE_TLS_KEY", DEFAULT_TLS_KEY))
    for label, path in (("certificate", cert), ("key", key)):
        if not os.path.isfile(path):
            raise TlsConfigError(f"no TLS {label} at {path} (set HIVE_TLS_{'CERT' if label == 'certificate' else 'KEY'})")
    if os.stat(key).st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise TlsConfigError(f"TLS key {key} is readable by others; run: chmod 600 {key}")
    opts = {"certfile": cert, "keyfile": key}
    ca = get("HIVE_TLS_CA")
    if ca:
        opts["ca_certs"] = os.path.expanduser(ca)
    return opts


def state_path(agent, env=None):
    """Where the last seen rowid for `agent` is kept."""
    env = os.environ if env is None else env
    base = env.get("CLAUDE_PLUGIN_DATA") or os.path.expanduser("~/.local/state/visma-hive-wake")
    return Path(base) / f"{agent}.rowid"


def load_rowid(path):
    """Last seen rowid, or 0 (replay everything still unread) when there is none yet."""
    try:
        return max(0, int(Path(path).read_text().strip()))
    except (OSError, ValueError):
        return 0


def save_rowid(path, rowid):
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_name(p.name + ".tmp")
    tmp.write_text(str(rowid))
    os.replace(tmp, p)


def connect_url(base, agent, since_rowid):
    """agent_name and since_rowid only; identity comes from the TLS client certificate."""
    sep = "&" if "?" in base else "?"
    return f"{base}{sep}agent_name={agent}&since_rowid={since_rowid}"


def wake_channels(env=None, conf=None):
    """Channels where every message wakes the session (lowercase, no '#'). '*' = all."""
    env = os.environ if env is None else env
    conf = load_config(env) if conf is None else conf
    raw = env.get("HIVE_WAKE_CHANNELS") or conf.get("HIVE_WAKE_CHANNELS") or ""
    return {c.strip().lstrip("#").lower() for c in raw.split(",") if c.strip()}


def wake_line(frame, agent, channels=frozenset()):
    """The line to print for one decoded frame, or None when it is no reason to wake `agent`.

    DMs to `agent` and messages naming it always wake. A channel message also wakes when
    its channel is in `channels` (or `channels` contains "*").
    """
    if not isinstance(frame, dict) or frame.get("type") != "message":
        return None
    sender = frame.get("from_agent")
    if sender == agent:
        return None
    text = " ".join(str(frame.get("content", "")).split())
    if frame.get("channel") == "dm":
        if frame.get("to_agent") != agent:
            return None
        where = "DM"
    elif re.search(rf"(?<![\w-]){re.escape(agent)}(?![\w-])", text):
        where = f"#{frame.get('channel')}"
    elif "*" in channels or str(frame.get("channel", "")).lower() in channels:
        where = f"#{frame.get('channel')}"
    else:
        return None
    preview = text if len(text) <= PREVIEW_CHARS else text[:PREVIEW_CHARS] + "…"
    return f"HIVE {where} from {sender}: {preview} (read it with your hive poll)"


class ReplayGate:
    """Caps the wake lines printed during one replay burst."""

    def __init__(self, cap=REPLAY_LINE_CAP):
        self.cap = cap
        self.in_replay = False
        self.shown = 0
        self.hidden = 0

    def start(self):
        self.in_replay, self.shown, self.hidden = True, 0, 0

    def offer(self, line, replayed):
        """The line to print now, or None when it is folded into the summary."""
        if not (replayed and self.in_replay):
            return line
        if self.shown < self.cap:
            self.shown += 1
            return line
        self.hidden += 1
        return None

    def finish(self):
        """Summary line for folded replay lines, or None."""
        self.in_replay = False
        if self.hidden:
            n, self.hidden = self.hidden, 0
            return f"HIVE: {n} more message(s) arrived while disconnected (read them with your hive poll)"
        return None


def refused_report(exc, agent, now, last_report):
    """(stdout line or None, new last-report time) for one failed connect."""
    status = getattr(exc, "status_code", None)
    if not isinstance(status, int) or not 400 <= status < 500:
        return None, last_report
    if last_report is not None and now - last_report < REFUSED_REPORT_EVERY_S:
        return None, last_report
    return f"HIVE wake: connection refused ({status}) for {agent}: check the agent name and that its certificate is valid", now


def unreachable_report(exc, base, now, failing_since, ever_connected, last_report):
    """(stdout line or None, new last-report time) when the server cannot be reached.

    Reports at once if this process has never connected (a wrong or unresolvable
    server address), otherwise only after UNREACHABLE_REPORT_AFTER_S of failures,
    and then at most every REFUSED_REPORT_EVERY_S.
    """
    resolve = isinstance(exc, socket.gaierror) or type(exc).__name__ == "WebSocketAddressException"
    if not resolve and not isinstance(exc, OSError):
        return None, last_report
    if ever_connected and (failing_since is None or now - failing_since < UNREACHABLE_REPORT_AFTER_S):
        return None, last_report
    if last_report is not None and now - last_report < REFUSED_REPORT_EVERY_S:
        return None, last_report
    host = urlparse(base).netloc or base
    if resolve:
        return f"HIVE wake: cannot resolve {host}; set HIVE_WS_URL in {CONFIG_FILE}; retrying", now
    return f"HIVE wake: cannot reach {host} ({type(exc).__name__}); retrying", now


def handle_frame(frame, agent, gate, last_rowid, channels=frozenset()):
    """(lines to print, new last rowid) for one decoded frame."""
    lines = []
    if isinstance(frame, dict) and frame.get("type") == "replay_complete":
        s = gate.finish()
        return ([s] if s else []), last_rowid
    rowid = frame.get("rowid") if isinstance(frame, dict) else None
    if isinstance(rowid, int):
        if rowid <= last_rowid:
            return [], last_rowid  # at-least-once delivery: already seen
        last_rowid = rowid
    line = wake_line(frame, agent, channels)
    if line:
        out = gate.offer(line, bool(frame.get("replay")))
        if out:
            lines.append(out)
    return lines, last_rowid


def main():
    try:
        import websocket  # websocket-client; imported here so the helpers are testable without it
    except ImportError:
        print(f"HIVE wake: python module websocket-client is missing for {sys.executable}; run "
              f"'{sys.executable} -m pip install --user websocket-client', then restart the session",
              flush=True)
        sys.exit(3)

    try:
        agent = agent_name()
    except AmbiguousAgent as amb:
        print(f"HIVE wake: {amb.args[0]} names several agents ({', '.join(amb.args[1])}); "
              f"set HIVE_AGENT in {PROJECT_ENV} or the session environment", flush=True)
        sys.exit(2)
    if not agent:
        print(f"HIVE wake: no agent name (set HIVE_AGENT in {CONFIG_FILE} or the session environment)",
              flush=True)
        sys.exit(2)
    spath = state_path(agent)
    last_rowid = load_rowid(spath)
    gate = ReplayGate()
    delay, last_refused, last_config_msg = 2, None, None
    base, ever_connected, failing_since, last_unreachable = "", False, None, None
    # Never exit: a plugin monitor that dies is not restarted until the session restarts.
    while True:
        try:
            # Re-read on every attempt, so a fixed config file takes effect without a restart.
            conf = load_config()
            base = ws_url(conf=conf)
            channels = wake_channels(conf=conf)
            try:
                if not base:
                    raise TlsConfigError(f"no server address (set HIVE_WS_URL in {CONFIG_FILE})")
                sslopt = tls_options(conf=conf, url=base)
            except TlsConfigError as bad:
                msg = f"HIVE wake: {bad}; retrying"
                if msg != last_config_msg:
                    print(msg, flush=True)
                    last_config_msg = msg
                raise
            last_config_msg = None
            ws = websocket.create_connection(connect_url(base, agent, last_rowid), timeout=90,
                                             sslopt=sslopt)
            delay, last_refused = 2, None
            ever_connected, failing_since, last_unreachable = True, None, None
            gate.start()
            while True:
                try:
                    raw = ws.recv()
                except websocket.WebSocketTimeoutException:
                    ws.ping()  # silence watchdog: a dead link raises here and we reconnect
                    channels = wake_channels()  # pick up wake-list edits without a restart
                    continue
                try:
                    frame = json.loads(raw)
                except ValueError:
                    continue
                lines, new_rowid = handle_frame(frame, agent, gate, last_rowid, channels)
                if new_rowid != last_rowid:
                    last_rowid = new_rowid
                    save_rowid(spath, last_rowid)
                for line in lines:
                    print(line, flush=True)
        except Exception as e:  # noqa: BLE001 - report refusals, reconnect on everything
            now = time.monotonic()
            if failing_since is None:
                failing_since = now
            line, last_refused = refused_report(e, agent, now, last_refused)
            if line:
                print(line, flush=True)
            if base:
                line, last_unreachable = unreachable_report(e, base, now, failing_since, ever_connected,
                                                            last_unreachable)
                if line:
                    print(line, flush=True)
            print(f"(hive wake: reconnect in {delay}s: {type(e).__name__})", file=sys.stderr, flush=True)
            time.sleep(delay)
            delay = min(delay * 2, 60)


if __name__ == "__main__":
    main()
