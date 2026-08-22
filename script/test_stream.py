#!/usr/bin/env python3
"""Regression harness for the ngx_brotli filter module.

script/run-tests.sh already covers Accept-Encoding parsing against static
files. This harness covers the two areas it does not:

  * streaming responses, where Content-Length is unknown and the body reaches
    the filter as a chunked stream (the proxy_pass case), and
  * the lifetime of the BrotliEncoderState instance, which owns heap memory
    that the request pool does not release on its own.

The memory tests read the encoder's own allocator tracing out of the debug
log, so they need an nginx built --with-debug; they are skipped otherwise.

Usage:
    python3 script/test_stream.py [--nginx PATH] [--keep] [-v]

nginx is looked up in --nginx, then $NGINX, then ./nginx/objs/nginx (where
script/build.sh puts it). Exits with the number of failed tests, so
it can be chained after the existing suite.
"""

from __future__ import annotations  # so "str | None" parses before Python 3.10

import argparse
import contextlib
import http.client
import os
import random
import re
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONF = os.path.join(ROOT, "script", "test_stream.conf")

PORT = 8899
UPSTREAM_PORT = 8901

# The compiled-in brotli_window default, which test_stream.conf deliberately
# does not override.
FULL_WINDOW = 64 * 1024

PASS, FAIL, SKIP = "PASS", "FAIL", "SKIP"


# ---------------------------------------------------------------------------
# Test registry
# ---------------------------------------------------------------------------

REGISTRY = []


def test(name, needs_decoder=False, needs_debug=False, needs_corpus=False):
    """Registers a test. The body raises Failure to report a failure."""

    def register(fn):
        REGISTRY.append(
            {
                "name": name,
                "fn": fn,
                "needs_decoder": needs_decoder,
                "needs_debug": needs_debug,
                "needs_corpus": needs_corpus,
            }
        )
        return fn

    return register


class Failure(Exception):
    pass


def check(condition, message):
    if not condition:
        raise Failure(message)


# ---------------------------------------------------------------------------
# Environment discovery
# ---------------------------------------------------------------------------


def locate_nginx(explicit):
    candidates = [
        explicit,
        os.environ.get("NGINX"),
        os.path.join(ROOT, "nginx", "objs", "nginx"),
    ]
    for candidate in candidates:
        if candidate and os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    looked_at = ", ".join(c for c in candidates if c)
    raise SystemExit(
        f"error: nginx binary not found.\n"
        f"  Looked at: {looked_at}\n"
        f"  Build one with script/build.sh, or pass --nginx PATH."
    )


def nginx_build_info(nginx):
    """Returns (version_line, has_debug). nginx -V reports on stderr."""
    done = subprocess.run([nginx, "-V"], capture_output=True, text=True, check=False)
    text = (done.stderr or "") + (done.stdout or "")
    version = next(
        (line for line in text.splitlines() if line.startswith("nginx version")),
        "unknown version",
    )
    return version, "--with-debug" in text


def locate_decoder():
    """Returns a callable bytes->bytes, or None if brotli cannot be decoded."""
    try:
        import brotli  # type: ignore

        return brotli.decompress
    except ImportError:
        pass

    bundled = os.path.join(ROOT, "deps", "brotli", "out", "brotli")
    cli = shutil.which("brotli")
    if not cli and os.path.isfile(bundled) and os.access(bundled, os.X_OK):
        cli = bundled
    if not cli:
        return None

    def decode_with_cli(data):
        # The CLI is happiest with a real file; this also keeps us clear of
        # stdin-buffering differences between brotli releases.
        with tempfile.NamedTemporaryFile(suffix=".br", delete=False) as handle:
            handle.write(data)
            path = handle.name
        try:
            return subprocess.run(
                [cli, "-d", "-c", path], capture_output=True, check=True
            ).stdout
        finally:
            os.unlink(path)

    return decode_with_cli


def locate_encoder():
    """Returns a callable bytes->bytes, or None if brotli cannot be encoded.

    Only the brotli_static tests need this: they have to lay down a real ".br"
    sibling for the module to find, and nginx will not make one for them.
    """
    try:
        import brotli  # type: ignore

        return brotli.compress
    except ImportError:
        pass

    bundled = os.path.join(ROOT, "deps", "brotli", "out", "brotli")
    cli = shutil.which("brotli")
    if not cli and os.path.isfile(bundled) and os.access(bundled, os.X_OK):
        cli = bundled
    if not cli:
        return None

    def encode_with_cli(data):
        with tempfile.NamedTemporaryFile(delete=False) as handle:
            handle.write(data)
            path = handle.name
        try:
            return subprocess.run(
                [cli, "-c", path], capture_output=True, check=True
            ).stdout
        finally:
            os.unlink(path)

    return encode_with_cli


def port_is_free(port):
    with socket.socket() as probe:
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            probe.bind(("127.0.0.1", port))
            return True
        except OSError:
            return False


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

# Comfortably over the default brotli_min_length, so a status code is the
# only thing that can stop these responses being compressed.
STATUS_BODY = ("<html><body>" + "status guard body " * 40 + "</body></html>").encode()

# Same, for the Vary dedupe cases below.
VARY_BODY = ("<html><body>" + "vary dedupe body " * 40 + "</body></html>").encode()

# Headers the upstream sends so ngx_http_brotli_check_vary can be reached with
# something to compare against. The module adds "Vary: Accept-Encoding" itself,
# so what each case checks is whether it recognises what is already there.
#
# "short" and "long" sit one character either side of "Accept-Encoding" and so
# probe the length guard from both directions. "etag" is the case that matters
# most: its key is four characters and its value fifteen, exactly like
# "Vary: Accept-Encoding", so it clears both length guards and only the string
# comparison can reject it. An inversion of that comparison shipped a response
# with no Vary at all, and no fixture at the time noticed.
VARY_CASES = {
    "ae": ("Vary", "Accept-Encoding"),
    "mixed": ("Vary", "accept-encoding"),
    "lang": ("Vary", "Accept-Language"),
    "short": ("Vary", "Accept-Encodin"),
    "long": ("Vary", "Accept-Encodings"),
    "etag": ("ETag", '"0123456789abc"'),
    "none": None,
}

WORDS = [
    "brotli",
    "nginx",
    "filter",
    "compression",
    "encoder",
    "stream",
    "buffer",
    "request",
    "response",
    "module",
    "window",
    "quality",
]


def make_text(word_count, seed):
    rng = random.Random(seed)
    return " ".join(rng.choice(WORDS) for _ in range(word_count))


# Real-world files, checked in under script/corpus. Everything else here is
# make_text() output, which is a poor stand-in for the web: random words drawn
# from a small list repeat at long range, so they compress far better and far
# more predictably than real markup or code. See corpus/PROVENANCE.md.
CORPUS = os.path.join(ROOT, "script", "corpus")
CORPUS_FILES = ("wiki.html", "site.css", "app.js", "app.min.js", "prose.txt")


def load_corpus():
    """Returns {name: bytes}, or {} if the corpus is not present."""
    corpus = {}
    for name in CORPUS_FILES:
        path = os.path.join(CORPUS, name)
        try:
            with open(path, "rb") as handle:
                corpus[name] = handle.read()
        except FileNotFoundError:
            return {}
    return corpus


def build_fixtures(work):
    html = os.path.join(work, "html")
    os.makedirs(html, exist_ok=True)
    os.makedirs(os.path.join(work, "logs"), exist_ok=True)

    files = {
        # Large enough to span many meta-blocks, so the encoder performs the
        # short-lived per-block allocations the memory tests care about, and
        # large enough that lg_win is not reduced below brotli_window.
        "big.html": f"<html><body>{make_text(200000, 1)}</body></html>",
        # Over brotli_min_length, but small enough that a known Content-Length
        # drives lg_win well below brotli_window.
        "small.html": f"<html><body>{make_text(200, 2)}</body></html>",
        # Under any sane brotli_min_length.
        "tiny.html": "<html>hi</html>",
        # Bracket the compiled-in brotli_min_length default: the first must be
        # too small to be worth compressing, the second comfortably worth it.
        "under_min.html": ("<html><body>" + "x" * 176 + "</body></html>"),
        "over_min.html": ("<html><body>" + "y" * 376 + "</body></html>"),
        # Not in brotli_types.
        "data.bin": make_text(500, 3),
    }
    for name, content in files.items():
        with open(os.path.join(html, name), "w") as handle:
            handle.write(content)

    fixtures = {name: content.encode() for name, content in files.items()}

    # A pre-compressed sibling for brotli_static to find. Written only when an
    # encoder is available; the tests skip otherwise.
    encode = locate_encoder()
    if encode:
        precompressed = f"<html><body>{make_text(2000, 5)}</body></html>".encode()
        with open(os.path.join(html, "precompressed.html"), "wb") as handle:
            handle.write(precompressed)
        with open(os.path.join(html, "precompressed.html.br"), "wb") as handle:
            handle.write(encode(precompressed))
        fixtures["precompressed.html"] = precompressed
        # No ".br" sibling, so brotli_static has to fall through to it.
        with open(os.path.join(html, "plain_only.html"), "wb") as handle:
            handle.write(precompressed)
        fixtures["plain_only.html"] = precompressed

    for name, blob in load_corpus().items():
        with open(os.path.join(html, name), "wb") as handle:
            handle.write(blob)
        fixtures[name] = blob

    return fixtures


def render_conf(work, port, upstream_port):
    with open(CONF) as handle:
        conf = handle.read()
    conf = conf.replace(str(PORT), str(port)).replace(
        str(UPSTREAM_PORT), str(upstream_port)
    )
    path = os.path.join(work, "nginx.conf")
    with open(path, "w") as handle:
        handle.write(conf)
    return path


# ---------------------------------------------------------------------------
# Test upstream
# ---------------------------------------------------------------------------


class Upstream:
    """Backend that answers with Transfer-Encoding: chunked and no
    Content-Length, so responses reach the filter as streams of unknown size.

    /stream/<name>  sends that fixture in chunks and completes.
    /slow           sends a little, then holds the connection open forever,
                    parking the filter in its "waiting for more input" return.
                    That is the only way a client disconnect can terminate the
                    request without the body filter running again, which is
                    the path the pool cleanup handler exists for.
    """

    def __init__(self, port, payloads):
        self.port = port
        self.payloads = payloads
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", port))
        self.sock.listen(16)
        self.stop = threading.Event()
        self.clients = []
        self.thread = threading.Thread(target=self._serve, daemon=True)

    def start(self):
        self.thread.start()

    def _serve(self):
        while not self.stop.is_set():
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            self.clients.append(conn)
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    @staticmethod
    def _chunk(payload):
        return b"%x\r\n" % len(payload) + payload + b"\r\n"

    def _handle(self, conn):
        try:
            request = conn.recv(65536).decode("latin-1")
            path = request.split(" ")[1] if " " in request else "/"

            # Must come before the chunked 200 below - these replies write
            # their own status line.
            if path.startswith("/dribble"):
                self._dribble(conn)
                return

            if path.startswith("/status/"):
                self._status(conn, int(path.rsplit("/", 1)[-1]))
                return

            if path.startswith("/vary/"):
                self._vary(conn, path.rsplit("/", 1)[-1])
                return

            conn.sendall(
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: text/html\r\n"
                b"Transfer-Encoding: chunked\r\n\r\n"
            )

            if path.startswith("/slow"):
                filler = b"<html>" + b"brotli nginx filter stream " * 400
                for _ in range(3):
                    conn.sendall(self._chunk(filler))
                    time.sleep(0.2)
                self.stop.wait()  # park until shutdown
                return

            payload = self.payloads.get(path.rsplit("/", 1)[-1], b"")
            for start in range(0, len(payload), 16384):
                conn.sendall(self._chunk(payload[start : start + 16384]))
            conn.sendall(b"0\r\n\r\n")
        except OSError:
            pass
        finally:
            with contextlib.suppress(OSError):
                conn.close()

    def _dribble(self, conn):
        """Sends a chunk every 50 ms without ever setting a flush marker, so
        the encoder decides on its own when to emit. Used to check that the
        filter does not sit on the whole response."""
        conn.sendall(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
            b"Transfer-Encoding: chunked\r\n\r\n"
        )
        chunk = b"<html><body>" + b"dribbled brotli payload " * 340
        for _ in range(20):
            conn.sendall(self._chunk(chunk))
            time.sleep(0.05)
        conn.sendall(b"0\r\n\r\n")

    def _status(self, conn, code):
        """Replies with `code`, in the shape that used to defeat the filter.

        204 and 304 are sent without a Content-Length, since with one the
        min-length check masks the bug; 206 carries a Content-Range that a
        compressed body would contradict.
        """
        body = STATUS_BODY
        if code in (204, 304):
            conn.sendall(
                f"HTTP/1.1 {code} Status\r\nContent-Type: text/html\r\n\r\n".encode()
            )
            return
        extra = ""
        if code == 206:
            extra = f"Content-Range: bytes 0-{len(body) - 1}/{len(body) * 4}\r\n"
        conn.sendall(
            (
                f"HTTP/1.1 {code} Status\r\nContent-Type: text/html\r\n"
                f"{extra}Content-Length: {len(body)}\r\n\r\n"
            ).encode()
            + body
        )

    def _vary(self, conn, case):
        """Replies carrying the header named by VARY_CASES[case], if any.

        Content-Length rather than chunked: what is under test is the header
        filter's dedupe, and a known length keeps the response out of the
        deferral path so a failure here can only be about headers.
        """
        header = VARY_CASES.get(case)
        extra = f"{header[0]}: {header[1]}\r\n" if header else ""
        conn.sendall(
            (
                f"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
                f"{extra}Content-Length: {len(VARY_BODY)}\r\n\r\n"
            ).encode()
            + VARY_BODY
        )

    def shutdown(self):
        self.stop.set()
        for conn in self.clients:
            with contextlib.suppress(OSError):
                conn.close()
        with contextlib.suppress(OSError):
            self.sock.close()


# ---------------------------------------------------------------------------
# Server lifecycle
# ---------------------------------------------------------------------------


class Nginx:
    def __init__(self, binary, work, conf, port):
        self.binary = binary
        self.work = work
        self.conf = conf
        self.port = port
        self.proc = None
        self.error_log = os.path.join(work, "logs", "error.log")

    def start(self):
        self.proc = subprocess.Popen(
            [self.binary, "-p", self.work, "-c", self.conf],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        deadline = time.time() + 15
        while time.time() < deadline:
            if self.proc.poll() is not None:
                assert self.proc.stdout is not None
                raise SystemExit(
                    "error: nginx exited during startup:\n" + self.proc.stdout.read()
                )
            try:
                with socket.create_connection(("127.0.0.1", self.port), 0.25):
                    return
            except OSError:
                time.sleep(0.1)
        raise SystemExit(f"error: nginx never listened on port {self.port}")

    def stop(self):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=5)

    def truncate_log(self):
        # nginx holds the log open with O_APPEND, so truncating here is safe
        # and everything read back belongs to the test that follows.
        with open(self.error_log, "w"):
            pass

    def read_log(self):
        try:
            with open(self.error_log, errors="replace") as handle:
                return handle.read()
        except FileNotFoundError:
            return ""


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------


def fetch(port, path, accept_encoding: str | None = "br", method="GET", timeout=30):
    """Returns (status, lowercased headers, raw body). No auto-decompression.

    accept_encoding of None sends no Accept-Encoding header at all, which is a
    different case from sending an empty one.
    """
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    try:
        headers = {"Host": "localhost"}
        if accept_encoding is not None:
            headers["Accept-Encoding"] = accept_encoding
        conn.request(method, path, headers=headers)
        response = conn.getresponse()
        body = response.read()
        return (response.status, {k.lower(): v for k, v in response.getheaders()}, body)
    finally:
        conn.close()


def fetch_repeated(port, path, name, accept_encoding="br", timeout=30):
    """Returns (status, every value sent for `name`, the collapsed headers).

    fetch() folds the headers into a dict, which is exactly wrong here: one
    "Vary: Accept-Encoding" and two of them collapse to the same entry, and
    the difference between those is what the dedupe is for.
    """
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    try:
        headers = {"Host": "localhost"}
        if accept_encoding is not None:
            headers["Accept-Encoding"] = accept_encoding
        conn.request("GET", path, headers=headers)
        response = conn.getresponse()
        response.read()
        pairs = response.getheaders()
        repeated = [v for k, v in pairs if k.lower() == name.lower()]
        return (response.status, repeated, {k.lower(): v for k, v in pairs})
    finally:
        conn.close()


def fetch_and_abort(port, path, settle=1.5):
    """Starts a request, reads a little, then resets the connection.

    SO_LINGER with a zero timeout makes close() emit an RST rather than a FIN,
    which is what makes nginx terminate the request outright instead of
    draining it through the body filter.
    """
    sock = socket.create_connection(("127.0.0.1", port), timeout=10)
    try:
        sock.sendall(
            (
                f"GET {path} HTTP/1.1\r\nHost: localhost\r\nAccept-Encoding: br\r\n\r\n"
            ).encode()
        )
        time.sleep(settle)
        sock.settimeout(5)
        with contextlib.suppress(TimeoutError, OSError):
            sock.recv(65536)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    finally:
        sock.close()


# ---------------------------------------------------------------------------
# Debug log analysis
# ---------------------------------------------------------------------------

ALLOC_RE = re.compile(r"\*(\d+) brotli alloc: (?:0x)?([0-9A-Fa-f]+), size:(\d+)")
FREE_RE = re.compile(r"\*(\d+) brotli free: (?:0x)?([0-9A-Fa-f]+)")
CLOSE_RE = re.compile(r"\*(\d+) http close request")
INIT_RE = re.compile(r"\*(\d+) brotli encoder initialized: lvl:(-?\d+) win:(\d+)")


def encoder_windows(log):
    """Returns [window_size] in the order encoders were initialized."""
    return [int(match.group(3)) for match in INIT_RE.finditer(log)]


def allocator_events(log):
    """Replays the encoder's allocator trace, per connection.

    Tracks whether every pointer came back exactly once, the peak
    simultaneously-live byte count, and where frees sit relative to
    "http close request" - which nginx logs on entry to ngx_http_free_request,
    before the pool cleanup handlers run inside ngx_destroy_pool.
    """
    stats = {}

    def slot(conn):
        return stats.setdefault(
            conn,
            {
                "allocs": 0,
                "frees": 0,
                "null_frees": 0,
                "live": {},
                "live_bytes": 0,
                "peak_bytes": 0,
                "double_alloc": False,
                "unmatched_free": False,
                "closed": False,
                "frees_after_close": 0,
            },
        )

    for line in log.splitlines():
        match = ALLOC_RE.search(line)
        if match:
            entry = slot(match.group(1))
            ptr, size = match.group(2).lstrip("0"), int(match.group(3))
            entry["allocs"] += 1
            if ptr in entry["live"]:
                entry["double_alloc"] = True
            entry["live"][ptr] = size
            entry["live_bytes"] += size
            entry["peak_bytes"] = max(entry["peak_bytes"], entry["live_bytes"])
            continue

        match = FREE_RE.search(line)
        if match:
            entry = slot(match.group(1))
            ptr = match.group(2).lstrip("0")
            if not ptr:  # free(NULL); brotli does this for unset fields
                entry["null_frees"] += 1
                continue
            entry["frees"] += 1
            if entry["closed"]:
                entry["frees_after_close"] += 1
            if ptr in entry["live"]:
                entry["live_bytes"] -= entry["live"].pop(ptr)
            else:
                entry["unmatched_free"] = True
            continue

        match = CLOSE_RE.search(line)
        if match:
            slot(match.group(1))["closed"] = True

    return stats


def wait_for_encoder_release(nginx, timeout=10.0):
    """Polls the debug log until every traced request has been torn down.

    A client can hold the whole response before the worker has released the
    encoder. The last output block is written to the socket from inside the
    body filter's output branch, and the encoder is only destroyed on the loop
    iteration after that - once BrotliEncoderIsFinished is reached with no
    output outstanding. It cannot be destroyed any earlier: ctx->out_buf points
    into memory owned by the encoder, handed out by BrotliEncoderTakeOutput.

    So reading the log the instant fetch() returns races the teardown. The race
    is almost never lost on an idle machine and lost regularly on a loaded CI
    runner, which is what made this look like an intermittent leak.

    Waits for "http close request" as well as for the allocation counts to
    balance, because the abort path frees the encoder from the pool cleanup
    handler - that is, inside ngx_destroy_pool, after that line is logged.

    Returns the stats either way: on a real leak this times out, and the
    caller's assertions then report what actually went wrong.
    """
    deadline = time.time() + timeout
    while True:
        stats = allocator_events(nginx.read_log())
        active = [entry for entry in stats.values() if entry["allocs"]]
        settled = active and all(
            entry["closed"] and entry["allocs"] == entry["frees"] and not entry["live"]
            for entry in active
        )
        if settled or time.time() >= deadline:
            return stats
        time.sleep(0.05)


def assert_balanced(stats, label):
    active = {conn: entry for conn, entry in stats.items() if entry["allocs"]}
    check(active, f"{label}: no encoder allocations were traced at all")
    for conn, entry in sorted(active.items()):
        check(
            not entry["double_alloc"],
            f"{label}: connection *{conn} handed out the same pointer twice",
        )
        check(
            not entry["unmatched_free"],
            f"{label}: connection *{conn} freed a pointer it never allocated",
        )
        check(
            entry["allocs"] == entry["frees"],
            f"{label}: connection *{conn} leaked - "
            f"{entry['allocs']} allocs vs {entry['frees']} frees",
        )
        check(
            not entry["live"],
            f"{label}: connection *{conn} still holds {len(entry['live'])} "
            f"live allocations ({entry['live_bytes']} bytes)",
        )
    return active


# ---------------------------------------------------------------------------
# Correctness
# ---------------------------------------------------------------------------


@test("static file round-trips through the encoder", needs_decoder=True)
def test_static_roundtrip(ctx):
    status, headers, body = fetch(ctx.port, "/big.html")
    check(status == 200, f"expected 200, got {status}")
    check(
        headers.get("content-encoding") == "br",
        f"expected Content-Encoding: br, got {headers.get('content-encoding')!r}",
    )
    original = ctx.fixtures["big.html"]
    check(
        len(body) < len(original),
        f"compressed body ({len(body)}) is not smaller than the original "
        f"({len(original)})",
    )
    check(ctx.decode(body) == original, "decoded body differs from the original")


def check_corpus_roundtrip(ctx, name, path=None):
    """Fetches one corpus file, and checks it compressed and decodes back."""
    path = path or f"/{name}"
    original = ctx.fixtures[name]

    status, headers, body = fetch(ctx.port, path)
    check(status == 200, f"{path}: expected 200, got {status}")
    check(
        headers.get("content-encoding") == "br",
        f"{path}: expected Content-Encoding: br, got "
        f"{headers.get('content-encoding')!r}",
    )
    check(
        len(body) < len(original),
        f"{path}: compressed body ({len(body)}) is not smaller than the "
        f"original ({len(original)})",
    )
    check(ctx.decode(body) == original, f"{path}: decoded body differs")


@test("brotli_static serves a pre-compressed sibling", needs_decoder=True)
def test_static_module_serves_br(ctx):
    if "precompressed.html" not in ctx.fixtures:
        raise Failure("no brotli encoder available to build the .br fixture")

    status, headers, body = fetch(ctx.port, "/static/precompressed.html")
    check(status == 200, f"expected 200, got {status}")
    check(
        headers.get("content-encoding") == "br",
        f"brotli_static did not serve the .br sibling; headers: {headers!r}",
    )
    check(
        ctx.decode(body) == ctx.fixtures["precompressed.html"],
        "the served .br did not decode back to the original",
    )
    # Twice, so the second request is answered from open_file_cache. That is
    # the path that hashes the constructed name over its length.
    status, headers, body = fetch(ctx.port, "/static/precompressed.html")
    check(status == 200, f"cached request: expected 200, got {status}")
    check(
        ctx.decode(body) == ctx.fixtures["precompressed.html"],
        "the cached .br did not decode back to the original",
    )


@test("brotli_static declines a client that will not take br")
def test_static_module_declines_plain_client(ctx):
    if "precompressed.html" not in ctx.fixtures:
        raise Failure("no brotli encoder available to build the .br fixture")

    status, headers, body = fetch(
        ctx.port, "/static/precompressed.html", accept_encoding=None
    )
    check(status == 200, f"expected 200, got {status}")
    check(
        "content-encoding" not in headers,
        f"a client that sent no Accept-Encoding got {headers!r}",
    )
    check(
        body == ctx.fixtures["precompressed.html"],
        "the plain client did not receive the uncompressed file",
    )


@test("brotli_static falls through when there is no .br sibling")
def test_static_module_without_sibling(ctx):
    if "plain_only.html" not in ctx.fixtures:
        raise Failure("no brotli encoder available to build the fixtures")

    status, headers, body = fetch(ctx.port, "/static/plain_only.html")
    check(status == 200, f"expected 200, got {status}")
    check(
        "content-encoding" not in headers,
        f"a file with no .br sibling was served as {headers!r}",
    )
    check(
        body == ctx.fixtures["plain_only.html"],
        "the fallback did not serve the original file",
    )


def check_vary_dedupe(ctx, case, expected):
    """Fetches /vary/<case> and returns every Vary line it came back with.

    The compression check is not incidental. set_vary runs only on a response
    the filter accepted, so if these ever stopped being compressed the Vary
    assertions below would still pass while covering nothing at all.
    """
    status, vary, headers = fetch_repeated(ctx.port, f"/vary/{case}", "Vary")
    check(status == 200, f"/vary/{case}: expected 200, got {status}")
    check(
        headers.get("content-encoding") == "br",
        f"/vary/{case} came back uncompressed, so set_vary never ran and this "
        f"test proves nothing; headers: {headers!r}",
    )
    check(
        len(vary) == expected,
        f"/vary/{case}: expected {expected} Vary header(s), got {len(vary)}: "
        f"{vary!r}",
    )
    return vary


@test("an upstream Vary: Accept-Encoding is not duplicated")
def test_vary_not_duplicated(ctx):
    vary = check_vary_dedupe(ctx, "ae", 1)
    check(
        vary[0].lower() == "accept-encoding",
        f"the surviving Vary was {vary[0]!r}",
    )


@test("an upstream Vary is recognised whatever its case")
def test_vary_case_insensitive(ctx):
    check_vary_dedupe(ctx, "mixed", 1)


@test("an unrelated Vary is kept and ours added beside it")
def test_vary_unrelated_kept(ctx):
    vary = check_vary_dedupe(ctx, "lang", 2)
    lowered = [v.lower() for v in vary]
    check(
        "accept-language" in lowered,
        f"the upstream's own Vary was dropped: {vary!r}",
    )
    check(
        "accept-encoding" in lowered,
        f"our Vary was not added: {vary!r}",
    )


@test("a Vary one character short of ours is not treated as a match")
def test_vary_near_miss_short(ctx):
    check_vary_dedupe(ctx, "short", 2)


@test("a Vary one character long is not treated as a match")
def test_vary_near_miss_long(ctx):
    check_vary_dedupe(ctx, "long", 2)


@test("a same-shaped header that is not Vary does not suppress ours")
def test_vary_lookalike_header(ctx):
    # ETag's key is four characters and this value fifteen, so both length
    # guards pass and only the string comparison stands between it and a
    # false match. When that comparison was once inverted, this response
    # went out with no Vary at all - a cache would then serve the Brotli
    # body to a client that never asked for one.
    vary = check_vary_dedupe(ctx, "etag", 1)
    check(
        vary[0].lower() == "accept-encoding",
        f"the Vary that survived was {vary[0]!r}",
    )


@test("a response with no upstream Vary still gets exactly one")
def test_vary_added_when_absent(ctx):
    check_vary_dedupe(ctx, "none", 1)


@test("real HTML round-trips", needs_decoder=True, needs_corpus=True)
def test_corpus_html(ctx):
    check_corpus_roundtrip(ctx, "wiki.html")


@test("real CSS round-trips", needs_decoder=True, needs_corpus=True)
def test_corpus_css(ctx):
    check_corpus_roundtrip(ctx, "site.css")


@test("real JavaScript round-trips", needs_decoder=True, needs_corpus=True)
def test_corpus_js(ctx):
    check_corpus_roundtrip(ctx, "app.js")


@test("real minified JavaScript round-trips", needs_decoder=True, needs_corpus=True)
def test_corpus_min_js(ctx):
    check_corpus_roundtrip(ctx, "app.min.js")


@test("real prose round-trips", needs_decoder=True, needs_corpus=True)
def test_corpus_prose(ctx):
    check_corpus_roundtrip(ctx, "prose.txt")


@test(
    "the whole corpus round-trips as streams of unknown length",
    needs_decoder=True,
    needs_corpus=True,
)
def test_corpus_streamed(ctx):
    # The static path above sizes the window from a known Content-Length and
    # feeds the encoder whole buffers. Unknown-length responses take neither
    # route, so real content has to cross that path too.
    for name in CORPUS_FILES:
        check_corpus_roundtrip(ctx, name, path=f"/stream/{name}")


@test("streamed response of unknown length round-trips", needs_decoder=True)
def test_stream_roundtrip(ctx):
    status, headers, body = fetch(ctx.port, "/stream/big.html")
    check(status == 200, f"expected 200, got {status}")
    check(
        headers.get("content-encoding") == "br",
        f"expected Content-Encoding: br, got {headers.get('content-encoding')!r}",
    )
    check(
        "content-length" not in headers,
        "a streamed response should not carry a Content-Length",
    )
    check(
        ctx.decode(body) == ctx.fixtures["big.html"],
        "decoded stream differs from the original",
    )


@test("small-but-eligible response round-trips", needs_decoder=True)
def test_small_roundtrip(ctx):
    _, headers, body = fetch(ctx.port, "/small.html")
    check(headers.get("content-encoding") == "br", "small.html was not compressed")
    check(
        ctx.decode(body) == ctx.fixtures["small.html"],
        "decoded small.html differs from the original",
    )


@test("response below brotli_min_length is left alone")
def test_min_length(ctx):
    _, headers, body = fetch(ctx.port, "/tiny.html")
    check(
        "content-encoding" not in headers,
        f"tiny.html should not be compressed, got Content-Encoding: "
        f"{headers.get('content-encoding')}",
    )
    check(body == ctx.fixtures["tiny.html"], "tiny.html body was altered")


@test("default brotli_min_length leaves a 200 byte response alone")
def test_min_length_default_lower(ctx):
    """Guards the compiled-in default, which the test config deliberately does
    not override. A response this small costs more to compress than it saves."""
    body_len = len(ctx.fixtures["under_min.html"])
    _, headers, body = fetch(ctx.port, "/under_min.html")
    check(
        "content-encoding" not in headers,
        f"a {body_len} byte response was compressed; brotli_min_length has "
        f"dropped below it",
    )
    check(body == ctx.fixtures["under_min.html"], "under_min.html was altered")


@test(
    "default brotli_min_length still compresses a 400 byte response", needs_decoder=True
)
def test_min_length_default_upper(ctx):
    body_len = len(ctx.fixtures["over_min.html"])
    _, headers, body = fetch(ctx.port, "/over_min.html")
    check(
        headers.get("content-encoding") == "br",
        f"a {body_len} byte response was not compressed; brotli_min_length has "
        f"risen above it",
    )
    check(
        ctx.decode(body) == ctx.fixtures["over_min.html"],
        "decoded over_min.html differs from the original",
    )


@test("a slowly-produced response starts arriving before it finishes")
def test_ttfb_on_buffered_stream(ctx):
    """With proxy_buffering on nothing sets a flush marker, so left alone the
    encoder holds everything until a 64 KB block fills - which for a trickling
    upstream means the client waits. The filter asks the encoder to flush when
    the caller wants progress, so the first bytes should arrive early rather
    than near the end.

    Timing based, deliberately with a wide margin: unfixed this was ~50% of
    total elapsed, fixed it is a few percent.
    """
    sock = socket.create_connection(("127.0.0.1", ctx.port), timeout=60)
    try:
        started = time.perf_counter()
        sock.sendall(
            b"GET /dribble HTTP/1.1\r\nHost: localhost\r\n"
            b"Connection: close\r\nAccept-Encoding: br\r\n\r\n"
        )
        head, first_body, total = b"", None, 0
        while True:
            data = sock.recv(65536)
            if not data:
                break
            now = time.perf_counter()
            if first_body is None:
                head += data
                if b"\r\n\r\n" in head:
                    body = head.split(b"\r\n\r\n", 1)[1]
                    if body:
                        first_body = now
                        total += len(body)
            else:
                total += len(data)
        finished = time.perf_counter()
    finally:
        sock.close()

    check(first_body is not None, "no body ever arrived")
    ttfb = first_body - started  # type: ignore
    elapsed = finished - started
    check(
        ttfb < elapsed * 0.4,
        f"first byte took {ttfb * 1000:.0f} ms of {elapsed * 1000:.0f} ms "
        f"total ({100 * ttfb / elapsed:.0f}%); the encoder is sitting on the "
        f"response instead of flushing when asked for progress",
    )


@test("brotli_min_length applies to responses of unknown length too")
def test_min_length_on_stream(ctx):
    """The header filter cannot compare against min_length when it has no
    Content-Length, so it holds the headers until the body has answered the
    question. Without that, a tiny chunked response still built a full
    encoder - about 575 KB to compress 200 bytes."""
    _, headers, body = fetch(ctx.port, "/buffered/under_min.html")
    check(
        "content-encoding" not in headers,
        f"a {len(ctx.fixtures['under_min.html'])} byte streamed response was "
        f"compressed; min_length is not being applied without a Content-Length",
    )
    check(
        body == ctx.fixtures["under_min.html"],
        "the uncompressed streamed body was altered",
    )


@test("a streamed response over min_length is still compressed", needs_decoder=True)
def test_min_length_on_stream_upper(ctx):
    _, headers, body = fetch(ctx.port, "/buffered/over_min.html")
    check(
        headers.get("content-encoding") == "br",
        f"a {len(ctx.fixtures['over_min.html'])} byte streamed response should "
        f"be compressed, got {headers.get('content-encoding')!r}",
    )
    check(
        ctx.decode(body) == ctx.fixtures["over_min.html"],
        "decoded streamed body differs from the original",
    )


@test("bodyless and ranged statuses are not given a Content-Encoding")
def test_status_guard(ctx):
    """204 and 304 have no body to encode, and a 206 body is a byte range whose
    Content-Range still describes the uncompressed entity. Labelling any of
    them "br" corrupts the response."""
    for code in (204, 304, 206):
        status, headers, _ = fetch(ctx.port, f"/status/{code}")
        check(status == code, f"expected {code} to reach the client, got {status}")
        check(
            "content-encoding" not in headers,
            f"a {code} response was labelled "
            f"{headers.get('content-encoding')!r}; it must not be compressed",
        )


@test("other statuses are still compressed", needs_decoder=True)
def test_status_guard_not_too_broad(ctx):
    """The guard replaced an allow list that also excluded these. They are
    ordinary compressible responses and must stay compressed."""
    for code in (200, 201, 403, 404, 422, 500):
        status, headers, body = fetch(ctx.port, f"/status/{code}")
        check(status == code, f"expected {code} to reach the client, got {status}")
        check(
            headers.get("content-encoding") == "br",
            f"a {code} response should still be compressed, got "
            f"{headers.get('content-encoding')!r}",
        )
        check(
            ctx.decode(body) == STATUS_BODY,
            f"the {code} body did not decode back to the original",
        )


@test("MIME type outside brotli_types is left alone")
def test_mime_filtering(ctx):
    _, headers, body = fetch(ctx.port, "/data.bin")
    check(
        "content-encoding" not in headers,
        "data.bin is not in brotli_types but was compressed",
    )
    check(body == ctx.fixtures["data.bin"], "data.bin body was altered")


@test("client without Accept-Encoding gets plain bytes")
def test_no_accept_encoding(ctx):
    _, headers, body = fetch(ctx.port, "/big.html", accept_encoding=None)
    check(
        "content-encoding" not in headers,
        "compressed for a client that did not ask for it",
    )
    check(body == ctx.fixtures["big.html"], "uncompressed body was altered")


@test("Accept-Encoding: br;q=0 is honoured")
def test_q_zero(ctx):
    for value in [
        "br;q=0",
        "br;q=0.0",
        "br;q=0.00",
        "br;q=0.000",
        "br ; q = 0.00",
        "br\t;\tq\t=\t0",
        "gzip, br;q=0",
    ]:
        _, headers, _ = fetch(ctx.port, "/big.html", accept_encoding=value)
        check(
            "content-encoding" not in headers,
            f"{value!r} should decline brotli, but the response was compressed",
        )


@test("tokens that merely contain 'br' do not select brotli")
def test_partial_token(ctx):
    for value in ["bro", "brotli", "bar", "b", "gzip, deflate", "x-br", "br-x"]:
        _, headers, _ = fetch(ctx.port, "/big.html", accept_encoding=value)
        check(
            "content-encoding" not in headers,
            f"{value!r} should not select brotli, but the response was compressed",
        )


@test("Accept-Encoding lists that do select brotli", needs_decoder=True)
def test_encoding_lists(ctx):
    for value in [
        "br",
        "gzip, br",
        "gzip, br, deflate",
        "gzip, br;q=1, deflate",
        "br;q=0.001",
        "identity, br",
        # Relative weights are ignored: naming br at all is enough, even when
        # something else is weighted higher.
        "gzip;q=1.0, br;q=0.1",
        "gzip;q=0.9, br;q=0.2, deflate",
        # Tab is valid optional whitespace around a list separator.
        "br\t,gzip",
        "gzip,\tbr",
        "gzip, br ",
        # Token matching is case-insensitive.
        "BR",
        "Br",
    ]:
        _, headers, body = fetch(ctx.port, "/small.html", accept_encoding=value)
        check(
            headers.get("content-encoding") == "br",
            f"{value!r} should select brotli, got {headers.get('content-encoding')!r}",
        )
        check(
            ctx.decode(body) == ctx.fixtures["small.html"],
            f"{value!r} produced a body that does not decode to the original",
        )


@test("HTTP/1.0 clients are not served Brotli")
def test_http_version_gate(ctx):
    """Mirrors gzip_http_version, whose default is 1.1. Declining still leaves
    Vary advertised, as the gzip filter does, so a cache in front keeps the
    responses apart."""

    def raw(version):
        sock = socket.create_connection(("127.0.0.1", ctx.port), timeout=30)
        try:
            sock.sendall(
                f"GET /big.html HTTP/{version}\r\nHost: localhost\r\n"
                f"Accept-Encoding: br\r\nConnection: close\r\n\r\n".encode()
            )
            data = b""
            while True:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                data += chunk
        finally:
            sock.close()
        head = data.split(b"\r\n\r\n", 1)[0].decode("latin-1")
        lower = [line.lower() for line in head.split("\r\n")]
        return (
            any(line.startswith("content-encoding: br") for line in lower),
            any(line.startswith("vary:") for line in lower),
        )

    compressed, vary = raw("1.0")
    check(not compressed, "an HTTP/1.0 request was served Brotli")
    check(vary, "Vary was dropped for the declined HTTP/1.0 request")

    compressed, _ = raw("1.1")
    check(compressed, "an HTTP/1.1 request was not served Brotli")


@test("Vary: Accept-Encoding is advertised to every client")
def test_vary(ctx):
    for accept in ["br", "gzip", None]:
        _, headers, _ = fetch(ctx.port, "/big.html", accept_encoding=accept)
        vary = headers.get("vary", "")
        check(
            "accept-encoding" in vary.lower(),
            f"Vary: Accept-Encoding missing for Accept-Encoding={accept!r} "
            f"(got {vary!r})",
        )


@test("HEAD request produces headers and no body")
def test_head(ctx):
    status, _, body = fetch(ctx.port, "/big.html", method="HEAD")
    check(status == 200, f"expected 200, got {status}")
    check(body == b"", f"HEAD returned a {len(body)} byte body")


# ---------------------------------------------------------------------------
# Encoder window selection (debug builds only)
# ---------------------------------------------------------------------------


@test("buffered stream shrinks the window once the size is known", needs_debug=True)
def test_deferred_window_for_buffered_stream(ctx):
    """A small response of unknown length still reaches the filter whole, just
    without last_buf on the first call. Holding it briefly lets the filter size
    the window from the real total instead of falling back to brotli_window."""
    ctx.nginx.truncate_log()
    fetch(ctx.port, "/buffered/small.html")
    windows = encoder_windows(ctx.nginx.read_log())

    check(len(windows) == 1, f"expected one encoder, saw {windows!r}")
    check(
        windows[0] < FULL_WINDOW,
        f"a small buffered stream should size its window from the response, "
        f"got the full {windows[0]}; the encoder was created before the whole "
        f"body arrived",
    )


@test("buffered stream still round-trips", needs_decoder=True)
def test_buffered_stream_roundtrip(ctx):
    status, headers, body = fetch(ctx.port, "/buffered/big.html")
    check(status == 200, f"expected 200, got {status}")
    check(
        headers.get("content-encoding") == "br",
        f"expected Content-Encoding: br, got {headers.get('content-encoding')!r}",
    )
    check(
        ctx.decode(body) == ctx.fixtures["big.html"],
        "decoded buffered stream differs from the original",
    )


@test("large buffered stream still uses the full window", needs_debug=True)
def test_deferred_falls_back_for_large(ctx):
    """Deferral must give up once enough input has accumulated: the response
    may be huge, and a window sized from a partial prefix would cost ratio."""
    ctx.nginx.truncate_log()
    fetch(ctx.port, "/buffered/big.html")
    windows = encoder_windows(ctx.nginx.read_log())

    check(len(windows) == 1, f"expected one encoder, saw {windows!r}")
    check(
        windows[0] == FULL_WINDOW,
        f"a large stream must fall back to the full {FULL_WINDOW} window, got "
        f"{windows[0]} - a window sized from a prefix would hurt compression",
    )


@test("known Content-Length shrinks the encoder window", needs_debug=True)
def test_window_tuning(ctx):
    ctx.nginx.truncate_log()
    fetch(ctx.port, "/small.html")
    small = encoder_windows(ctx.nginx.read_log())

    ctx.nginx.truncate_log()
    fetch(ctx.port, "/big.html")
    big = encoder_windows(ctx.nginx.read_log())

    check(
        len(small) == 1 and len(big) == 1,
        f"expected one encoder per request, saw {small!r} and {big!r}",
    )
    check(
        small[0] < big[0],
        f"a small response chose window {small[0]}, the same or larger than "
        f"the {big[0]} chosen for a large one; the Content-Length tuning "
        f"has regressed",
    )
    check(
        big[0] == FULL_WINDOW,
        f"a response larger than brotli_window should use the full "
        f"{FULL_WINDOW} window, got {big[0]}",
    )


@test("stream of unknown length falls back to the full window", needs_debug=True)
def test_stream_uses_full_window(ctx):
    """Same payload as test_window_tuning's small case, but delivered chunked.
    With no Content-Length to tune from, the filter must use brotli_window -
    which is also what proves this really is the unknown-length path."""
    ctx.nginx.truncate_log()
    fetch(ctx.port, "/stream/small.html")
    windows = encoder_windows(ctx.nginx.read_log())

    check(len(windows) == 1, f"expected one encoder, saw {windows!r}")
    check(
        windows[0] == FULL_WINDOW,
        f"a streamed response should use the full {FULL_WINDOW} window, got "
        f"{windows[0]} - the response probably carried a Content-Length "
        f"after all, so this test is not exercising the streaming path",
    )


# ---------------------------------------------------------------------------
# Encoder memory (debug builds only)
# ---------------------------------------------------------------------------


@test("encoder allocations balance on a static response", needs_debug=True)
def test_alloc_balance_static(ctx):
    ctx.nginx.truncate_log()
    fetch(ctx.port, "/big.html")
    assert_balanced(wait_for_encoder_release(ctx.nginx), "static")


@test("encoder allocations balance on a streamed response", needs_debug=True)
def test_alloc_balance_stream(ctx):
    ctx.nginx.truncate_log()
    fetch(ctx.port, "/stream/big.html")
    assert_balanced(wait_for_encoder_release(ctx.nginx), "stream")


@test("repeated requests neither leak nor drift", needs_debug=True)
def test_alloc_soak(ctx):
    rounds = 25
    ctx.nginx.truncate_log()
    for _ in range(rounds):
        fetch(ctx.port, "/big.html")
    active = assert_balanced(wait_for_encoder_release(ctx.nginx), "soak")

    check(
        len(active) == rounds, f"expected {rounds} traced requests, saw {len(active)}"
    )
    counts = {entry["allocs"] for entry in active.values()}
    check(
        len(counts) == 1,
        f"allocation count drifts between identical requests: {sorted(counts)}",
    )


@test("aborted request still releases the encoder", needs_debug=True)
def test_cleanup_handler_on_abort(ctx):
    ctx.nginx.truncate_log()
    fetch_and_abort(ctx.port, "/slow")
    # Polls rather than sleeping a fixed 2.5s for nginx to notice the reset:
    # faster here, and it does not give up early on a loaded runner.
    active = assert_balanced(wait_for_encoder_release(ctx.nginx), "abort")

    # The point of this test. The encoder must be released by the pool cleanup
    # handler, which runs inside ngx_destroy_pool - after nginx has logged
    # "http close request". If every free landed before that line, the request
    # drained through ngx_http_brotli_filter_close instead, and the cleanup
    # handler went untested even though the balance check passed.
    check(
        any(entry["frees_after_close"] for entry in active.values()),
        'no connection freed the encoder after "http close request": the '
        "abort was absorbed by the normal close path, so this test did not "
        "exercise the cleanup handler",
    )


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------


class Context:
    """Everything a test needs: the server, the port, the fixture bytes and a
    brotli decoder."""

    def __init__(self, port, decode, fixtures, nginx):
        self.port = port
        self.decode = decode
        self.fixtures = fixtures
        self.nginx = nginx


def main():
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--nginx", help="path to the nginx binary under test")
    parser.add_argument("--port", type=int, default=PORT)
    parser.add_argument("--upstream-port", type=int, default=UPSTREAM_PORT)
    parser.add_argument(
        "--keep",
        action="store_true",
        help="keep the work directory even when everything passes",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="dump the tail of the error log when tests fail",
    )
    args = parser.parse_args()

    nginx_bin = locate_nginx(args.nginx)
    version, has_debug = nginx_build_info(nginx_bin)
    decode = locate_decoder()
    has_corpus = bool(load_corpus())

    for port in (args.port, args.upstream_port):
        if not port_is_free(port):
            raise SystemExit(f"error: port {port} is already in use")

    print(f"nginx:   {nginx_bin}")
    print(f"build:   {version}{'' if has_debug else '   (no --with-debug)'}")
    print(f"decoder: {'available' if decode else 'MISSING'}")
    print(f"corpus:  {'present' if has_corpus else 'MISSING (script/corpus)'}")
    if not has_debug:
        print("         window and memory tests need --with-debug; skipping them.")
    if not decode:
        print(
            "         round-trip tests need a brotli decoder: install the "
            "python 'brotli'\n         module, or build the CLI with\n"
            "           cd deps/brotli && mkdir -p out && cd out && "
            "cmake .. && make brotli"
        )
    print()

    work = tempfile.mkdtemp(prefix="ngx-brotli-test-")
    fixtures = build_fixtures(work)
    conf = render_conf(work, args.port, args.upstream_port)

    upstream = Upstream(args.upstream_port, fixtures)
    upstream.start()
    ctx = Context(args.port, decode, fixtures, Nginx(nginx_bin, work, conf, args.port))
    ctx.nginx.start()

    results = []
    try:
        width = max(len(entry["name"]) for entry in REGISTRY)
        for entry in REGISTRY:
            name = entry["name"]
            if entry["needs_decoder"] and not decode:
                results.append((SKIP, name, "no brotli decoder available"))
            elif entry["needs_debug"] and not has_debug:
                results.append((SKIP, name, "nginx lacks --with-debug"))
            elif entry["needs_corpus"] and not has_corpus:
                results.append((SKIP, name, "script/corpus is missing"))
            else:
                try:
                    entry["fn"](ctx)
                    results.append((PASS, name, ""))
                except Failure as failure:
                    results.append((FAIL, name, str(failure)))
                # A test that raises anything else - a socket timeout, a
                # decoder failure - is a failed test, not a reason to abandon
                # the run and leave nginx behind.
                except Exception as error:  # noqa: BLE001
                    results.append((FAIL, name, f"{type(error).__name__}: {error}"))
            status, _, detail = results[-1]
            print(f"{status:<5} {name:<{width}} {detail}")
    finally:
        ctx.nginx.stop()
        upstream.shutdown()

    failed = sum(1 for status, _, _ in results if status == FAIL)
    skipped = sum(1 for status, _, _ in results if status == SKIP)
    passed = sum(1 for status, _, _ in results if status == PASS)
    print(f"\n{passed} passed, {failed} failed, {skipped} skipped")

    if failed or args.keep:
        print(f"work directory kept at {work}")
        if args.verbose:
            print(ctx.nginx.read_log()[-4000:])
    else:
        shutil.rmtree(work, ignore_errors=True)

    return failed


if __name__ == "__main__":
    sys.exit(main())
