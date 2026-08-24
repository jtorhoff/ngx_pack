#!/usr/bin/env python3
"""Regression harness for the ngx_zstd filter module.

script/run-tests.sh already covers Accept-Encoding parsing against static
files. This harness covers the two areas it does not:

  * streaming responses, where Content-Length is unknown and the body reaches
    the filter as a chunked stream (the proxy_pass case), and
  * the lifetime of the ZSTD_CCtx instance, which owns heap memory
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

# The compiled-in zstd_window default, which test_stream.conf deliberately
# does not override.
FULL_WINDOW = 64 * 1024

# Little-endian 0xFD2FB528, the magic a zstd frame opens with.
ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"

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
    """Returns a callable bytes->bytes, or None if zstd cannot be decoded."""
    bundled = os.path.join(ROOT, "deps", "zstd", "out", "programs", "zstd")
    cli = shutil.which("zstd")
    if not cli and os.path.isfile(bundled) and os.access(bundled, os.X_OK):
        cli = bundled
    if not cli:
        return None

    def decode_with_cli(data):
        # The CLI is happiest with a real file; this also keeps us clear of
        # stdin-buffering differences between zstd releases.
        with tempfile.NamedTemporaryFile(suffix=".zst", delete=False) as handle:
            handle.write(data)
            path = handle.name
        try:
            return subprocess.run(
                [cli, "-d", "-c", "-f", path], capture_output=True, check=True
            ).stdout
        finally:
            os.unlink(path)

    return decode_with_cli


def locate_encoder():
    """Returns a callable bytes->bytes, or None if zstd cannot be encoded.

    Only the zstd_static tests need this: they have to lay down a real
    ".zst" sibling for the module to find, and nginx will not make one for
    them.
    """
    bundled = os.path.join(ROOT, "deps", "zstd", "out", "programs", "zstd")
    cli = shutil.which("zstd")
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
                [cli, "-c", "-f", path], capture_output=True, check=True
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

# Comfortably over the default zstd_min_length, so a status code is the
# only thing that can stop these responses being compressed.
STATUS_BODY = ("<html><body>" + "status guard body " * 40 + "</body></html>").encode()

# Same, for the Vary dedupe cases below.
VARY_BODY = ("<html><body>" + "vary dedupe body " * 40 + "</body></html>").encode()

# Headers the upstream sends so ngx_http_zstd_check_vary can be reached with
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
    "zstd",
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
        # Large enough to span many blocks, so the encoder performs the
        # short-lived per-block allocations the memory tests care about, and
        # large enough that windowLog is not reduced below zstd_window.
        "big.html": f"<html><body>{make_text(200000, 1)}</body></html>",
        # Over zstd_min_length, but small enough that a known Content-Length
        # drives windowLog well below zstd_window.
        "small.html": f"<html><body>{make_text(200, 2)}</body></html>",
        # Under any sane zstd_min_length.
        "tiny.html": "<html>hi</html>",
        # Bracket the compiled-in zstd_min_length default: the first must be
        # too small to be worth compressing, the second comfortably worth it.
        "under_min.html": ("<html><body>" + "x" * 176 + "</body></html>"),
        "over_min.html": ("<html><body>" + "y" * 376 + "</body></html>"),
        # Not in zstd_types.
        "data.bin": make_text(500, 3),
    }
    for name, content in files.items():
        with open(os.path.join(html, name), "w") as handle:
            handle.write(content)

    fixtures = {name: content.encode() for name, content in files.items()}

    # A pre-compressed sibling for zstd_static to find. Written only when an
    # encoder is available; the tests skip otherwise.
    encode = locate_encoder()
    if encode:
        precompressed = f"<html><body>{make_text(2000, 5)}</body></html>".encode()
        with open(os.path.join(html, "precompressed.html"), "wb") as handle:
            handle.write(precompressed)
        with open(os.path.join(html, "precompressed.html.zst"), "wb") as handle:
            handle.write(encode(precompressed))
        fixtures["precompressed.html"] = precompressed
        # No ".zst" sibling, so zstd_static has to fall through to it.
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

            if path.startswith("/burst"):
                self._burst(conn)
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
                filler = b"<html>" + b"zstd nginx filter stream " * 400
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

    # Small enough that all BURST_CHUNKS fit in one proxy buffer, so nginx
    # reads the whole burst at once and the chunked filter builds one chain
    # rather than several.
    BURST_CHUNKS = 12
    BURST_TEXT = b"<p>zstd flush coalescing burst chunk payload</p>"

    def _burst(self, conn):
        """Writes every chunk in a single send.

        nginx then reads them together and ngx_http_proxy_chunked_filter
        appends one buffer per chunk, each with flush set, into one chain -
        the case NGX_HTTP_ZSTD_FLUSH_COALESCE exists for. Sending them as
        separate writes would let nginx read them one at a time, and the
        chain would hold a single flush marker with nothing to fold.
        """
        body = b"".join(
            self._chunk(b"%d %s" % (i, self.BURST_TEXT))
            for i in range(self.BURST_CHUNKS)
        )
        conn.sendall(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
            b"Transfer-Encoding: chunked\r\n\r\n" + body + b"0\r\n\r\n"
        )

    def _dribble(self, conn):
        """Sends a chunk every 50 ms without ever setting a flush marker, so
        the encoder decides on its own when to emit. Used to check that the
        filter does not sit on the whole response."""
        conn.sendall(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
            b"Transfer-Encoding: chunked\r\n\r\n"
        )
        chunk = b"<html><body>" + b"dribbled zstd payload " * 340
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
        self.log_mark = 0

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

    def mark_log(self):
        """Remembers how far the log has got, so read_log() returns only
        what follows.

        This used to truncate instead. That gave each test an isolated
        view at the cost of destroying every earlier test's output, which
        makes a late failure much harder to explain and quietly
        invalidates any measurement taken across the whole run - a probe
        counting events over a suite reads zero for everything a later
        truncation erased. Marking costs nothing and keeps the file.
        """
        try:
            self.log_mark = os.path.getsize(self.error_log)
        except FileNotFoundError:
            self.log_mark = 0

    def read_log(self, whole=False):
        """Everything logged since the last mark_log(), or the lot."""
        try:
            with open(self.error_log, "rb") as handle:
                if not whole:
                    handle.seek(self.log_mark)
                return handle.read().decode(errors="replace")
        except FileNotFoundError:
            return ""


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------


def fetch(port, path, accept_encoding: str | None = "zstd", method="GET", timeout=30):
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


def fetch_repeated(port, path, name, accept_encoding="zstd", timeout=30):
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
                f"GET {path} HTTP/1.1\r\nHost: localhost\r\nAccept-Encoding: zstd\r\n\r\n"
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

ALLOC_RE = re.compile(r"\*(\d+) zstd alloc: (?:0x)?([0-9A-Fa-f]+), size:(\d+)")
FREE_RE = re.compile(r"\*(\d+) zstd free: (?:0x)?([0-9A-Fa-f]+)")
CLOSE_RE = re.compile(r"\*(\d+) http close request")
INIT_RE = re.compile(r"\*(\d+) zstd encoder initialized: lvl:(-?\d+) win:(\d+)")
OUT_RE = re.compile(r"\*(\d+) zstd out: (?:0x)?[0-9A-Fa-f]+, size:(\d+)")
BUF_RE = re.compile(
    r"\*(\d+) zstd buffer created: (?:0x)?[0-9A-Fa-f]+, total:(\d+)"
)


def buffers_created(log):
    """Most output buffers any one response was seen to create."""
    return max((int(m.group(2)) for m in BUF_RE.finditer(log)), default=0)


def encoder_count(log):
    """How many encoders were built, in this slice of the log."""
    return len(INIT_RE.findall(log))


def frame_window(data):
    """The window size the encoder declared, read from the zstd frame header.

    RFC 8878 section 3.1.1. Deliberately taken from the frame rather than
    from the module's "zstd encoder initialized" line: that line reports the
    zstd_window ceiling and the pledged length, because zstd picks the real
    window from both when compression starts and offers no call that reports
    it back. Reading the frame asserts what the encoder did instead of what
    this module intended, so it also holds if zstd's own sizing changes.
    """
    return _frame_header(data)[0]


def frame_blocks(data):
    """How many blocks the first frame is made of.

    This is the observable behind flush coalescing. A flush ends the block
    it interrupts, so a chain of N flush-marked buffers produces N blocks
    where one would otherwise do, and folding them shows up here and
    nowhere else - the decoded bytes are identical either way.
    """
    pos = _frame_header(data)[1]
    blocks = 0

    while True:
        if pos + 3 > len(data):
            raise Failure("frame ends inside a block header")
        header = data[pos] | data[pos + 1] << 8 | data[pos + 2] << 16
        pos += 3

        last = header & 1
        block_type = (header >> 1) & 3
        if block_type == 3:
            raise Failure("reserved block type in frame")

        blocks += 1
        # An RLE block stores one byte and repeats it Block_Size times;
        # raw and compressed blocks store Block_Size bytes.
        pos += 1 if block_type == 1 else header >> 3

        if last:
            return blocks


def frame_declares_size(data):
    """Whether the frame header carries a Frame_Content_Size.

    zstd writes one when, and only when, it was told the size before the
    frame was written, so from the outside this is what tells the pledged
    path apart from the hinted one. RFC 8878 section 3.1.1.1.2: the size is
    present when Frame_Content_Size_flag is non-zero, and additionally when
    Single_Segment_flag is set, which forces a one-byte field.
    """
    if data[:4] != ZSTD_MAGIC:
        raise Failure("response body does not start with a zstd frame")

    descriptor = data[4]
    return bool(descriptor >> 6) or bool((descriptor >> 5) & 1)


def _frame_header(data):
    """(window size, length of the frame header) for the frame at data[0]."""
    if data[:4] != ZSTD_MAGIC:
        raise Failure("response body does not start with a zstd frame")

    descriptor = data[4]
    fcs_flag = descriptor >> 6
    single_segment = (descriptor >> 5) & 1
    did_flag = descriptor & 3
    pos = 5

    window = None
    if not single_segment:
        exponent, mantissa = data[pos] >> 3, data[pos] & 7
        base = 1 << (10 + exponent)
        window = base + (base // 8) * mantissa
        pos += 1

    pos += (0, 1, 2, 4)[did_flag]

    # Present unless the flag says zero width, which Single_Segment_flag
    # overrides - there the content size is what gives the window.
    width = (1 if single_segment else 0, 2, 4, 8)[fcs_flag]
    if width:
        value = int.from_bytes(data[pos : pos + width], "little")
        pos += width
        if window is None:
            window = value + 256 if width == 2 else value

    if window is None:
        raise Failure("frame header declares neither a window nor a size")

    return window, pos


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
            if not ptr:  # free(NULL), if the allocator ever does that
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


REQUEST_LINE_RE = re.compile(r"\*(\d+) http request line")


def allocator_timeline(log):
    """Replays the allocator trace in order instead of grouping by connection.

    allocator_events() sums per connection, which is what a test opening one
    connection per request wants. On a keep-alive connection every request
    shares a single id, so summing tells you nothing about whether an encoder
    was released before the next request began - only walking the log in order
    and recording live bytes at each request line does.
    """
    live, live_bytes, peak = {}, 0, 0
    allocs = frees = unmatched = 0
    at_request_start = []
    connections = set()

    for line in log.splitlines():
        match = REQUEST_LINE_RE.search(line)
        if match:
            connections.add(match.group(1))
            at_request_start.append(live_bytes)
            continue

        match = ALLOC_RE.search(line)
        if match:
            ptr, size = match.group(2).lstrip("0"), int(match.group(3))
            live[ptr] = size
            live_bytes += size
            peak = max(peak, live_bytes)
            allocs += 1
            continue

        match = FREE_RE.search(line)
        if match:
            ptr = match.group(2).lstrip("0")
            if not ptr:
                continue
            frees += 1
            if ptr in live:
                live_bytes -= live.pop(ptr)
            else:
                unmatched += 1

    return {
        "allocs": allocs,
        "frees": frees,
        "unmatched": unmatched,
        "peak": peak,
        "live_at_end": live_bytes,
        "blocks_at_end": len(live),
        "at_request_start": at_request_start,
        "connections": connections,
    }


def wait_for_encoder_release(nginx, timeout=10.0):
    """Polls the debug log until every traced request has been torn down.

    A client can hold the whole response before the worker has released the
    encoder. The last output block is written to the socket from inside the
    body filter's output branch, and the encoder is only destroyed on the loop
    iteration after that - once ctx->output is back to IDLE (the filters below
    have taken everything) and a fresh call finds ctx->frame_closed already
    set. It is not destroyed any earlier even though, unlike Brotli's
    BrotliEncoderTakeOutput, out_buf here is memory the filter allocated
    itself rather than encoder-owned memory: out_chain still has to reach
    the filters below intact, and closing early would tear it down under
    them.

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
        headers.get("content-encoding") == "zstd",
        f"expected Content-Encoding: zstd, got {headers.get('content-encoding')!r}",
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
        headers.get("content-encoding") == "zstd",
        f"{path}: expected Content-Encoding: zstd, got "
        f"{headers.get('content-encoding')!r}",
    )
    check(
        len(body) < len(original),
        f"{path}: compressed body ({len(body)}) is not smaller than the "
        f"original ({len(original)})",
    )
    check(ctx.decode(body) == original, f"{path}: decoded body differs")


@test("zstd_static serves a pre-compressed sibling", needs_decoder=True)
def test_static_module_serves_zst(ctx):
    if "precompressed.html" not in ctx.fixtures:
        raise Failure("no zstd encoder available to build the .zst fixture")

    status, headers, body = fetch(ctx.port, "/static/precompressed.html")
    check(status == 200, f"expected 200, got {status}")
    check(
        headers.get("content-encoding") == "zstd",
        f"zstd_static did not serve the .zst sibling; headers: {headers!r}",
    )
    check(
        ctx.decode(body) == ctx.fixtures["precompressed.html"],
        "the served .zst did not decode back to the original",
    )
    # Twice, so the second request is answered from open_file_cache. That is
    # the path that hashes the constructed name over its length.
    status, headers, body = fetch(ctx.port, "/static/precompressed.html")
    check(status == 200, f"cached request: expected 200, got {status}")
    check(
        ctx.decode(body) == ctx.fixtures["precompressed.html"],
        "the cached .zst did not decode back to the original",
    )


@test("zstd_static declines a client that will not take zstd")
def test_static_module_declines_plain_client(ctx):
    if "precompressed.html" not in ctx.fixtures:
        raise Failure("no zstd encoder available to build the .zst fixture")

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


@test("zstd_static falls through when there is no .zst sibling")
def test_static_module_without_sibling(ctx):
    if "plain_only.html" not in ctx.fixtures:
        raise Failure("no zstd encoder available to build the fixtures")

    status, headers, body = fetch(ctx.port, "/static/plain_only.html")
    check(status == 200, f"expected 200, got {status}")
    check(
        "content-encoding" not in headers,
        f"a file with no .zst sibling was served as {headers!r}",
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
        headers.get("content-encoding") == "zstd",
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
    # went out with no Vary at all - a cache would then serve the Zstandard
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
        headers.get("content-encoding") == "zstd",
        f"expected Content-Encoding: zstd, got {headers.get('content-encoding')!r}",
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
    check(headers.get("content-encoding") == "zstd", "small.html was not compressed")
    check(
        ctx.decode(body) == ctx.fixtures["small.html"],
        "decoded small.html differs from the original",
    )


@test("response below zstd_min_length is left alone")
def test_min_length(ctx):
    _, headers, body = fetch(ctx.port, "/tiny.html")
    check(
        "content-encoding" not in headers,
        f"tiny.html should not be compressed, got Content-Encoding: "
        f"{headers.get('content-encoding')}",
    )
    check(body == ctx.fixtures["tiny.html"], "tiny.html body was altered")


@test("default zstd_min_length leaves a 200 byte response alone")
def test_min_length_default_lower(ctx):
    """Guards the compiled-in default, which the test config deliberately does
    not override. A response this small costs more to compress than it saves."""
    body_len = len(ctx.fixtures["under_min.html"])
    _, headers, body = fetch(ctx.port, "/under_min.html")
    check(
        "content-encoding" not in headers,
        f"a {body_len} byte response was compressed; zstd_min_length has "
        f"dropped below it",
    )
    check(body == ctx.fixtures["under_min.html"], "under_min.html was altered")


@test(
    "default zstd_min_length still compresses a 400 byte response", needs_decoder=True
)
def test_min_length_default_upper(ctx):
    body_len = len(ctx.fixtures["over_min.html"])
    _, headers, body = fetch(ctx.port, "/over_min.html")
    check(
        headers.get("content-encoding") == "zstd",
        f"a {body_len} byte response was not compressed; zstd_min_length has "
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
            b"Connection: close\r\nAccept-Encoding: zstd\r\n\r\n"
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


@test("zstd_min_length applies to a buffered stream of unknown length")
def test_min_length_on_stream(ctx):
    """The header filter cannot compare against min_length when it has no
    Content-Length, so it holds the headers until the body has answered the
    question. Without that, a tiny chunked response still built a full
    encoder - about 575 KB to compress 200 bytes.

    Buffered specifically: see the unbuffered case below, where the answer
    is the opposite.
    """
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


@test("zstd_min_length is bypassed when a buffer asks to be flushed")
def test_min_length_not_applied_when_urgent(ctx):
    """The same body as the buffered case above, and the opposite outcome.

    With proxy_buffering off every buffer carries a flush marker, and the
    filter treats one as "something downstream is waiting": it decides
    immediately rather than holding the headers any longer, and deciding
    immediately means compressing. So zstd_min_length does not hold for an
    unbuffered proxied response - a 200 byte body is compressed even though
    the setting is 256.

    That is deliberate, but it is the kind of thing a configuration is
    written against, so it is asserted rather than left to be discovered.
    Change this test only alongside the "urgent" branch in
    ngx_http_zstd_filter_prepare.
    """
    body = ctx.fixtures["under_min.html"]
    check(
        len(body) < 256,
        f"fixture is {len(body)} bytes, which no longer sits under the "
        f"compiled-in zstd_min_length of 256 this test depends on",
    )
    _, headers, _ = fetch(ctx.port, "/stream/under_min.html")
    check(
        headers.get("content-encoding") == "zstd",
        f"a {len(body)} byte unbuffered response was not compressed; the "
        f"flush marker should have short-circuited zstd_min_length",
    )


@test("a streamed response over min_length is still compressed", needs_decoder=True)
def test_min_length_on_stream_upper(ctx):
    _, headers, body = fetch(ctx.port, "/buffered/over_min.html")
    check(
        headers.get("content-encoding") == "zstd",
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
    them "zstd" corrupts the response."""
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
            headers.get("content-encoding") == "zstd",
            f"a {code} response should still be compressed, got "
            f"{headers.get('content-encoding')!r}",
        )
        check(
            ctx.decode(body) == STATUS_BODY,
            f"the {code} body did not decode back to the original",
        )


@test("MIME type outside zstd_types is left alone")
def test_mime_filtering(ctx):
    _, headers, body = fetch(ctx.port, "/data.bin")
    check(
        "content-encoding" not in headers,
        "data.bin is not in zstd_types but was compressed",
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


@test("Accept-Encoding: zstd;q=0 is honoured")
def test_q_zero(ctx):
    for value in [
        "zstd;q=0",
        "zstd;q=0.0",
        "zstd;q=0.00",
        "zstd;q=0.000",
        "zstd ; q = 0.00",
        "zstd\t;\tq\t=\t0",
        "gzip, zstd;q=0",
    ]:
        _, headers, _ = fetch(ctx.port, "/big.html", accept_encoding=value)
        check(
            "content-encoding" not in headers,
            f"{value!r} should decline zstd, but the response was compressed",
        )


@test("tokens that merely contain 'zstd' do not select zstd")
def test_partial_token(ctx):
    for value in ["zstdx", "zstdlib", "bar", "b", "gzip, deflate", "x-zstd", "zstd-x"]:
        _, headers, _ = fetch(ctx.port, "/big.html", accept_encoding=value)
        check(
            "content-encoding" not in headers,
            f"{value!r} should not select zstd, but the response was compressed",
        )


@test("Accept-Encoding lists that do select zstd", needs_decoder=True)
def test_encoding_lists(ctx):
    for value in [
        "zstd",
        "gzip, zstd",
        "gzip, zstd, deflate",
        "gzip, zstd;q=1, deflate",
        "zstd;q=0.001",
        "identity, zstd",
        # Relative weights are ignored: naming zstd at all is enough, even
        # when something else is weighted higher.
        "gzip;q=1.0, zstd;q=0.1",
        "gzip;q=0.9, zstd;q=0.2, deflate",
        # Tab is valid optional whitespace around a list separator.
        "zstd\t,gzip",
        "gzip,\tzstd",
        "gzip, zstd ",
        # Token matching is case-insensitive.
        "ZSTD",
        "Zstd",
    ]:
        _, headers, body = fetch(ctx.port, "/small.html", accept_encoding=value)
        check(
            headers.get("content-encoding") == "zstd",
            f"{value!r} should select zstd, got {headers.get('content-encoding')!r}",
        )
        check(
            ctx.decode(body) == ctx.fixtures["small.html"],
            f"{value!r} produced a body that does not decode to the original",
        )


@test("HTTP/1.0 clients are not served Zstandard")
def test_http_version_gate(ctx):
    """Mirrors gzip_http_version, whose default is 1.1. Declining still leaves
    Vary advertised, as the gzip filter does, so a cache in front keeps the
    responses apart."""

    def raw(version):
        sock = socket.create_connection(("127.0.0.1", ctx.port), timeout=30)
        try:
            sock.sendall(
                f"GET /big.html HTTP/{version}\r\nHost: localhost\r\n"
                f"Accept-Encoding: zstd\r\nConnection: close\r\n\r\n".encode()
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
            any(line.startswith("content-encoding: zstd") for line in lower),
            any(line.startswith("vary:") for line in lower),
        )

    compressed, vary = raw("1.0")
    check(not compressed, "an HTTP/1.0 request was served Zstandard")
    check(vary, "Vary was dropped for the declined HTTP/1.0 request")

    compressed, _ = raw("1.1")
    check(compressed, "an HTTP/1.1 request was not served Zstandard")


@test("Vary: Accept-Encoding is advertised to every client")
def test_vary(ctx):
    for accept in ["zstd", "gzip", None]:
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
# Output buffers
# ---------------------------------------------------------------------------

# module/filter/ngx_http_zstd_filter_module.c, the zstd_buffers default.
DEFAULT_BUFFERS = 4


def stall_a_response(port, path, seconds=0.6):
    """Asks for a rate-limited response and deliberately does not read it.

    Reading it would let the write filter drain, which is exactly what must
    not happen: the encoder only reaches for a second buffer once the first
    is still outstanding. Returns once nginx has had time to fill what it
    is going to fill.
    """
    sock = socket.create_connection(("127.0.0.1", port), timeout=5)
    try:
        sock.sendall(
            f"GET {path} HTTP/1.1\r\nHost: localhost\r\n"
            f"Accept-Encoding: zstd\r\n\r\n".encode()
        )
        time.sleep(seconds)
    finally:
        sock.close()


@test("a stalled write does not stop the encoder", needs_debug=True)
def test_multiple_output_buffers(ctx):
    """With one buffer the encoder had to stop until it came back, so a slow
    client throttled compression as well as delivery. Several buffers let it
    run on, and zstd_buffers is the bound on how far."""
    ctx.nginx.mark_log()
    stall_a_response(ctx.port, "/throttled/wiki.html")
    created = buffers_created(ctx.nginx.read_log())

    check(
        created > 1,
        f"a stalled response created {created} output buffer(s), so the "
        f"encoder still stops on the first one and zstd_buffers buys "
        f"nothing",
    )
    check(
        created <= DEFAULT_BUFFERS,
        f"a stalled response created {created} output buffers, past the "
        f"zstd_buffers default of {DEFAULT_BUFFERS}",
    )


@test("zstd_buffers 1 holds the encoder to a single buffer", needs_debug=True)
def test_buffers_directive_is_honoured(ctx):
    """The same stall against a location that allows only one buffer. This is
    what tells a failure of the test above apart: if this one also reports
    more than one, the directive is being ignored rather than the stall
    failing to happen."""
    ctx.nginx.mark_log()
    stall_a_response(ctx.port, "/throttled-one/wiki.html")
    created = buffers_created(ctx.nginx.read_log())

    check(
        created == 1,
        f"zstd_buffers 1 still created {created} output buffers",
    )


# ---------------------------------------------------------------------------
# Flush coalescing
# ---------------------------------------------------------------------------

# module/filter/ngx_http_zstd_filter_module.c
FLUSH_COALESCE = 4


@test("a burst of flush-marked chunks folds into fewer blocks", needs_decoder=True)
def test_flush_coalescing(ctx):
    """The upstream writes every chunk in one send, so the chunked filter
    hands the module a single chain of flush markers - one per chunk. Only
    the last of a fold has to cut a block, and the cap on how many fold is
    what bounds it.

    Asserting a bound rather than an exact count: how much nginx reads at
    once is not ours to fix, so a burst may still arrive as more than one
    chain, and each chain folds separately.
    """
    chunks = Upstream.BURST_CHUNKS
    _, headers, body = fetch(ctx.port, "/burst")

    check(
        headers.get("content-encoding") == "zstd",
        f"burst was not compressed, got "
        f"{headers.get('content-encoding')!r} - a flush marker is supposed "
        f"to short-circuit zstd_min_length",
    )

    blocks = frame_blocks(body)
    ceiling = -(-chunks // FLUSH_COALESCE) + 2

    check(
        blocks < chunks,
        f"{chunks} flush-marked chunks produced {blocks} blocks, so every "
        f"flush still cut its own block and nothing was folded",
    )
    check(
        blocks <= ceiling,
        f"{chunks} flush-marked chunks produced {blocks} blocks, more than "
        f"the {ceiling} a fold of {FLUSH_COALESCE} allows",
    )


@test("a folded flush still delivers every byte", needs_decoder=True)
def test_flush_coalescing_roundtrip(ctx):
    """Folding may not lose or reorder anything: the point is that only the
    framing changes."""
    expected = b"".join(
        b"%d %s" % (i, Upstream.BURST_TEXT) for i in range(Upstream.BURST_CHUNKS)
    )
    _, _, body = fetch(ctx.port, "/burst")

    check(
        ctx.decode(body) == expected,
        "decoded burst differs from what the upstream sent",
    )


# ---------------------------------------------------------------------------
# Encoder window selection (debug builds only)
# ---------------------------------------------------------------------------


@test("buffered stream shrinks the window once the size is known", needs_debug=True)
def test_deferred_window_for_buffered_stream(ctx):
    """A small response of unknown length still reaches the filter whole, just
    without last_buf on the first call. Holding it briefly lets the filter size
    the window from the real total instead of falling back to zstd_window."""
    ctx.nginx.mark_log()
    _, _, body = fetch(ctx.port, "/buffered/small.html")
    count = encoder_count(ctx.nginx.read_log())
    window = frame_window(body)

    check(count == 1, f"expected one encoder, saw {count}")
    check(
        window < FULL_WINDOW,
        f"a small buffered stream should size its window from the response, "
        f"got the full {window}; the encoder was created before the whole "
        f"body arrived",
    )


@test("buffered stream still round-trips", needs_decoder=True)
def test_buffered_stream_roundtrip(ctx):
    status, headers, body = fetch(ctx.port, "/buffered/big.html")
    check(status == 200, f"expected 200, got {status}")
    check(
        headers.get("content-encoding") == "zstd",
        f"expected Content-Encoding: zstd, got {headers.get('content-encoding')!r}",
    )
    check(
        ctx.decode(body) == ctx.fixtures["big.html"],
        "decoded buffered stream differs from the original",
    )


@test("large buffered stream still uses the full window", needs_debug=True)
def test_deferred_falls_back_for_large(ctx):
    """Deferral must give up once enough input has accumulated: the response
    may be huge, and a window sized from a partial prefix would cost ratio."""
    ctx.nginx.mark_log()
    _, _, body = fetch(ctx.port, "/buffered/big.html")
    count = encoder_count(ctx.nginx.read_log())
    window = frame_window(body)

    check(count == 1, f"expected one encoder, saw {count}")
    check(
        window == FULL_WINDOW,
        f"a large stream must fall back to the full {FULL_WINDOW} window, got "
        f"{window} - a window sized from a prefix would hurt compression",
    )


@test("known Content-Length shrinks the encoder window", needs_debug=True)
def test_window_tuning(ctx):
    """Asserts the property, not the mechanism, and cannot tell the two apart.

    Both fixtures reach the filter whole, so zstd derives a pledged size from
    the single ZSTD_e_end call even when the module sets none - measured: with
    ZSTD_CCtx_setPledgedSrcSize disabled this test still passes, and only
    test_deferred_window_for_buffered_stream, whose body arrives across
    several calls, notices. Keep both.
    """
    ctx.nginx.mark_log()
    _, _, small_body = fetch(ctx.port, "/small.html")
    small_count = encoder_count(ctx.nginx.read_log())

    ctx.nginx.mark_log()
    _, _, big_body = fetch(ctx.port, "/big.html")
    big_count = encoder_count(ctx.nginx.read_log())

    small, big = frame_window(small_body), frame_window(big_body)

    check(
        small_count == 1 and big_count == 1,
        f"expected one encoder per request, saw {small_count} and {big_count}",
    )
    check(
        small < big,
        f"a small response chose window {small}, the same or larger than "
        f"the {big} chosen for a large one; the Content-Length tuning "
        f"has regressed",
    )
    check(
        big == FULL_WINDOW,
        f"a response larger than zstd_window should use the full "
        f"{FULL_WINDOW} window, got {big}",
    )


@test("stream of unknown length falls back to the full window", needs_debug=True)
def test_stream_uses_full_window(ctx):
    """Same payload as test_window_tuning's small case, but delivered chunked.
    With no Content-Length to tune from, the filter must use zstd_window -
    which is also what proves this really is the unknown-length path."""
    ctx.nginx.mark_log()
    _, _, body = fetch(ctx.port, "/stream/small.html")
    count = encoder_count(ctx.nginx.read_log())
    window = frame_window(body)

    check(count == 1, f"expected one encoder, saw {count}")
    check(
        window == FULL_WINDOW,
        f"a streamed response should use the full {FULL_WINDOW} window, got "
        f"{window} - the response probably carried a Content-Length "
        f"after all, so this test is not exercising the streaming path",
    )


# ---------------------------------------------------------------------------
# Encoder memory (debug builds only)
# ---------------------------------------------------------------------------


@test("encoder allocations balance on a static response", needs_debug=True)
def test_alloc_balance_static(ctx):
    ctx.nginx.mark_log()
    fetch(ctx.port, "/big.html")
    assert_balanced(wait_for_encoder_release(ctx.nginx), "static")


@test("encoder allocations balance on a streamed response", needs_debug=True)
def test_alloc_balance_stream(ctx):
    ctx.nginx.mark_log()
    fetch(ctx.port, "/stream/big.html")
    assert_balanced(wait_for_encoder_release(ctx.nginx), "stream")


def peak_encoder_bytes(ctx, path):
    """(peak simultaneously-live encoder bytes, body) for one request.

    The body comes back so the caller can read out of the frame which sizing
    path the encoder actually took, rather than assuming it from the URL.
    """
    ctx.nginx.mark_log()
    _, headers, body = fetch(ctx.port, path)
    check(
        headers.get("content-encoding") == "zstd",
        f"{path} came back uncompressed, so there is no encoder to measure",
    )
    stats = wait_for_encoder_release(ctx.nginx)
    active = [entry for entry in stats.values() if entry["allocs"]]
    check(active, f"no encoder allocation was traced for {path}")
    return max(entry["peak_bytes"] for entry in active), body


@test("a stream costs no more memory than the same body of known length",
      needs_debug=True)
def test_stream_memory_ceiling(ctx):
    """Pins ZSTD_c_srcSizeHint, which nothing else here would notice.

    A known Content-Length reaches ZSTD_CCtx_setPledgedSrcSize, which sizes
    the encoder's match-finder tables to the body. Without it zstd sizes them
    for the worst case the window allows, and a response of unknown length
    used to pay for that: the same body cost 2.95 MB streamed against 1.07 MB
    static at level 6, and 640.90 MB against 1.90 MB at level 22. The hint is
    the non-binding form of the pledge and is what closes that.

    The suite passed 51/51 both before and after the hint was added, so the
    other memory tests here do not cover this. They check that allocations
    balance and do not drift, which is a different property: a leak-free
    encoder three times larger than it needs to be passes all of them.

    Deliberately a ratio rather than a byte count. The absolute figures move
    with the libzstd in deps/zstd and with zstd_comp_level, but "a stream
    should not cost materially more than the same bytes with a length on
    them" holds across both. 1.5x leaves room for the two paths genuinely
    differing - the hint is a guess where the pledge is exact, so they need
    not land on the same tables - while a regression here is a 2.75x at the
    level this suite runs.

    Being a comparison, it would prove nothing if both sides quietly ended up
    on the same path - if /stream stopped being a stream, or if the pledge
    went missing so that both merely guessed. Neither side is taken on trust
    for that reason: a frame carries a Frame_Content_Size only when the
    encoder knew the size up front, so the frames themselves are asked which
    path they came from before the peaks are compared.
    """
    known, known_body = peak_encoder_bytes(ctx, "/big.html")
    streamed, streamed_body = peak_encoder_bytes(ctx, "/stream/big.html")

    check(
        frame_declares_size(known_body),
        "/big.html produced a frame with no content size, so it was not "
        "given a pledged length and is not the known-length yardstick this "
        "comparison needs",
    )
    check(
        not frame_declares_size(streamed_body),
        "/stream/big.html produced a frame carrying a content size, so it "
        "was compressed with a known length after all - both sides of this "
        "comparison took the same path and it proves nothing",
    )
    check(
        streamed <= known * 1.5,
        f"a streamed response peaked at {streamed / 1024:.0f} KB against "
        f"{known / 1024:.0f} KB for the same body with a known length "
        f"({streamed / known:.2f}x). The encoder is sizing its tables to the "
        f"window rather than to the response - ZSTD_c_srcSizeHint is most "
        f"likely no longer reaching it",
    )


@test("repeated requests neither leak nor drift", needs_debug=True)
def test_alloc_soak(ctx):
    rounds = 25
    ctx.nginx.mark_log()
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


def keepalive_soak(ctx, paths, rounds):
    """Drives `rounds` passes over `paths` down one connection."""
    conn = http.client.HTTPConnection("127.0.0.1", ctx.port, timeout=60)
    try:
        for _ in range(rounds):
            for path in paths:
                conn.request(
                    "GET",
                    path,
                    headers={"Host": "localhost", "Accept-Encoding": "zstd"},
                )
                response = conn.getresponse()
                response.read()
                check(response.status == 200, f"{path} -> {response.status}")
    finally:
        conn.close()
    wait_for_encoder_release(ctx.nginx)
    return allocator_timeline(ctx.nginx.read_log())


@test("one connection serving many requests holds nothing between them",
      needs_debug=True)
def test_keepalive_allocation_balance(ctx):
    """The encoder's lifetime is the request, not the connection.

    Every other memory test here opens a fresh connection per request,
    so all of them would still pass if that were the other way round -
    with one request per connection the request pool and the connection
    pool are indistinguishable. This one puts thirty requests down a
    single connection, and asks whether live memory is back to zero as
    each of them starts.

    Allocating out_start or the context from r->connection->pool, or
    registering the cleanup handler there, is what it would catch:
    each holds every request's encoder until the connection closes,
    which on a keep-alive connection can be a very long time and many
    megabytes. The peak is measured against one request of the most
    expensive kind rather than a fixed figure, so it stays honest if
    the vendored zstd changes what an encoder costs.
    """
    paths = ["/big.html", "/buffered/big.html", "/under_min.html"]

    # what a single streamed response costs, as the yardstick
    ctx.nginx.mark_log()
    alone = keepalive_soak(ctx, ["/buffered/big.html"], 1)
    check(alone["peak"] > 0, "no encoder allocation traced for one request")

    rounds = 10
    ctx.nginx.mark_log()
    soak = keepalive_soak(ctx, paths, rounds)

    check(
        len(soak["connections"]) == 1,
        f"the {rounds * len(paths)} requests used "
        f"{len(soak['connections'])} connections, so keep-alive did not "
        f"hold and this test proved nothing",
    )
    check(
        soak["allocs"] == soak["frees"] and soak["unmatched"] == 0,
        f"{soak['allocs']} allocations against {soak['frees']} frees "
        f"({soak['unmatched']} unmatched)",
    )
    check(
        soak["blocks_at_end"] == 0,
        f"{soak['blocks_at_end']} blocks ({soak['live_at_end']} bytes) "
        f"still live once the connection closed",
    )

    held = [n for n in soak["at_request_start"] if n != 0]
    check(
        not held,
        f"{len(held)} of {len(soak['at_request_start'])} requests began "
        f"with encoder memory still live from an earlier one - largest "
        f"{max(held) if held else 0} bytes; the encoder is being held for "
        f"the connection rather than the request",
    )
    check(
        soak["peak"] <= alone["peak"] * 1.25,
        f"peak live memory over {rounds * len(paths)} requests was "
        f"{soak['peak'] / 1024:.0f} KB against {alone['peak'] / 1024:.0f} KB "
        f"for a single one, so cost is accumulating across the connection",
    )


@test("aborted request still releases the encoder", needs_debug=True)
def test_cleanup_handler_on_abort(ctx):
    ctx.nginx.mark_log()
    fetch_and_abort(ctx.port, "/slow")
    # Polls rather than sleeping a fixed 2.5s for nginx to notice the reset:
    # faster here, and it does not give up early on a loaded runner.
    active = assert_balanced(wait_for_encoder_release(ctx.nginx), "abort")

    # The point of this test. The encoder must be released by the pool cleanup
    # handler, which runs inside ngx_destroy_pool - after nginx has logged
    # "http close request". If every free landed before that line, the request
    # drained through ngx_http_zstd_filter_close instead, and the cleanup
    # handler went untested even though the balance check passed.
    check(
        any(entry["frees_after_close"] for entry in active.values()),
        'no connection freed the encoder after "http close request": the '
        "abort was absorbed by the normal close path, so this test did not "
        "exercise the cleanup handler",
    )


@test("committed output rounds account for every byte of the body", needs_debug=True)
def test_output_rounds_account_for_the_body(ctx):
    """The filter owns one output buffer and refills it round after round.

    Every refill is logged with the size committed, so the trace says exactly
    how the body was cut up on the way out. Summing it is the accounting
    check on the partial-drain path: that a round which only half-empties the
    buffer neither drops bytes nor sends any of them twice.

    Deliberately calibrated from the trace rather than against a hard-coded
    16 KB, so that the same test tightens rather than breaks under
    script/test-small-buffer.sh, where a 64-byte buffer makes almost every
    round a partial one and this count goes from single digits to ~1500.
    """
    ctx.nginx.mark_log()
    status, headers, body = fetch(ctx.port, "/big.html")
    check(status == 200, f"expected 200, got {status}")
    check(headers.get("content-encoding") == "zstd", "response was not compressed")

    rounds = {}
    for conn, size in OUT_RE.findall(ctx.nginx.read_log()):
        rounds.setdefault(conn, []).append(int(size))
    check(len(rounds) == 1, f"expected one traced request, saw {len(rounds)}")
    sizes = next(iter(rounds.values()))

    check(
        sum(sizes) == len(body),
        f"the filter committed {sum(sizes)} bytes over {len(sizes)} rounds "
        f"but the client received {len(body)}",
    )
    check(
        len(sizes) > 1,
        "the whole body was committed in a single round, so the multi-round "
        "path this test exists for never ran",
    )

    # Only meaningful when the caller has said what the build should have.
    # It is what stops the small-buffer run from passing as a plain re-run of
    # the suite if -DNGX_HTTP_ZSTD_OUT_SIZE ever stops reaching the compiler.
    cap = max(sizes)
    if ctx.max_out_size is not None:
        check(
            cap <= ctx.max_out_size,
            f"largest committed round was {cap} bytes, above the "
            f"{ctx.max_out_size} this build was meant to be limited to: "
            f"NGX_HTTP_ZSTD_OUT_SIZE did not reach the compiler",
        )


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------


class Context:
    """Everything a test needs: the server, the port, the fixture bytes and a
    zstd decoder."""

    def __init__(self, port, decode, fixtures, nginx, max_out_size=None):
        self.port = port
        self.decode = decode
        self.fixtures = fixtures
        self.nginx = nginx
        # What NGX_HTTP_ZSTD_OUT_SIZE was built with, when the caller knows;
        # None means "whatever the default is", and the check is skipped.
        self.max_out_size = max_out_size


def main():
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--nginx", help="path to the nginx binary under test")
    parser.add_argument("--port", type=int, default=PORT)
    parser.add_argument("--upstream-port", type=int, default=UPSTREAM_PORT)
    parser.add_argument(
        "--max-out-size",
        type=int,
        help="assert the module's output buffer is at most this many bytes, "
        "i.e. that -DNGX_HTTP_ZSTD_OUT_SIZE reached the build "
        "(see script/test-small-buffer.sh)",
    )
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
    if args.max_out_size is not None:
        print(f"buffer:  asserting at most {args.max_out_size} bytes per round")
    if not has_debug:
        print("         window and memory tests need --with-debug; skipping them.")
    if not decode:
        print(
            "         round-trip tests need a zstd decoder: install the "
            "zstd CLI, or build the bundled one with\n"
            "           script/build.sh"
        )
    print()

    work = tempfile.mkdtemp(prefix="ngx-zstd-test-")
    fixtures = build_fixtures(work)
    conf = render_conf(work, args.port, args.upstream_port)

    upstream = Upstream(args.upstream_port, fixtures)
    upstream.start()
    ctx = Context(
        args.port,
        decode,
        fixtures,
        Nginx(nginx_bin, work, conf, args.port),
        args.max_out_size,
    )
    ctx.nginx.start()

    results = []
    try:
        width = max(len(entry["name"]) for entry in REGISTRY)
        for entry in REGISTRY:
            name = entry["name"]
            if entry["needs_decoder"] and not decode:
                results.append((SKIP, name, "no zstd decoder available"))
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
            print(ctx.nginx.read_log(whole=True)[-4000:])
    else:
        shutil.rmtree(work, ignore_errors=True)

    return failed


if __name__ == "__main__":
    sys.exit(main())
