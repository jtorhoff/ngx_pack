#!/usr/bin/env python3
"""Regression harness for the ngx_zstd filter module.

Covers Accept-Encoding parsing, static file serving, and the areas a
plain curl-and-cmp suite cannot reach:

  * streaming responses, where Content-Length is unknown and the body reaches
    the filter as a chunked stream (the proxy_pass case),
  * the lifetime of the ZSTD_CCtx instance, which owns heap memory
    that the request pool does not release on its own, and
  * one HTTP/2 smoke check, so the --with-http_v2_module path every
    build compiles in is not left completely unexercised.

The memory tests read the encoder's own allocator tracing out of the debug
log, so they need an nginx built --with-debug; they are skipped otherwise.
The HTTP/2 check shells out to curl, since neither http.client nor
anything else already in use here speaks HTTP/2; it is skipped when
curl is not on PATH.

Usage:
    python3 script/tests/stream/test_stream.py [--nginx PATH] [--keep] [-v]

nginx is looked up in --nginx, then $NGINX, then ./nginx/objs/nginx (where
script/build/build.sh puts it). Exits with the number of failed tests, so
it can be chained after the existing suite.
"""

from __future__ import annotations

import argparse
import contextlib
import gzip
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

from collections.abc import Callable, Sequence
from typing import TypedDict

# One floor for every script here, stated once: the four others in
# this directory import this module, so they inherit it. The runners
# carry 3.12 and no job pins a version, so without this a script that
# happened to work on something older locally would be running
# somewhere CI never goes.
if sys.version_info < (3, 12):
    raise SystemExit(
        f"python 3.12 or newer is required, this is "
        f"{sys.version_info.major}.{sys.version_info.minor}"
    )

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
CONF = os.path.join(ROOT, "script", "tests", "stream", "test_stream.conf")

PORT = 8899
UPSTREAM_PORT = 8901

# The compiled-in pack_zstd_window default, which test_stream.conf deliberately
# does not override.
FULL_WINDOW = 16 * 1024

# Little-endian 0xFD2FB528, the magic a zstd frame opens with.
ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"

PASS, FAIL, SKIP = "PASS", "FAIL", "SKIP"


# ---------------------------------------------------------------------------
# Codecs
# ---------------------------------------------------------------------------


class Codec:
    """One encoder, and everything the suite needs in order to address it.

    The two filters are the same machinery with a different library
    underneath, so a structural test - buffers, stalls, teardown, allocator
    balance - is the same test twice. Everything that differs between the
    two is here: the token a client asks for, the prefix its locations
    carry in test_stream.conf, the directive name its messages use, and
    the word its debug log puts in front of an allocation.

    What is deliberately NOT here is anything read out of the compressed
    bytes. zstd states its window in the frame header and Brotli does not,
    so the window tests stay zstd-only rather than growing a "does this
    codec support it" flag per assertion.
    """

    def __init__(
        self,
        name: str,
        token: str,
        ext: str,
        directive: str,
        prefix: str,
        log_tag: str,
        superstrings: tuple[str, ...],
        continue_step: int,
    ) -> None:
        self.name = name
        self.token = token
        self.ext = ext
        self.directive = directive
        self.prefix = prefix
        self.log_tag = log_tag

        # Tokens that contain this one but are not it, and that a
        # client might really send. The negotiation tests below build
        # the rest of their near-miss list from the token itself, but
        # these cannot be derived: "brotli" is a word, not a pattern.
        # It is also the case that matters most - "br" is two
        # characters and a prefix of it, so the boundary check is the
        # only thing keeping "Accept-Encoding: brotli" from selecting
        # Brotli.
        self.superstrings = superstrings

        # What this encoder's step enum calls "go round again", which the
        # round trace logs as a number. The two are not the same: zstd's
        # enum opens with a READY member Brotli has no use for, so its
        # CONTINUE sits one later. Checked against the header by
        # test_rounds_make_progress, so a reordered enum fails loudly
        # rather than quietly making that assertion vacuous.
        self.continue_step = continue_step

        # Filled in by main(). None when no decoder for this codec is
        # installed, which is what makes needs_decoder skip rather than
        # fail - so it is declared optional rather than given a stub,
        # the None being what the runner reads.
        self.decode: Callable[[bytes], bytes] | None = None

        self.alloc_re = re.compile(
            rf"\*(\d+) {log_tag} alloc: (?:0x)?([0-9A-Fa-f]+), size: (\d+)"
        )
        self.free_re = re.compile(rf"\*(\d+) {log_tag} free: (?:0x)?([0-9A-Fa-f]+)")
        self.out_re = re.compile(
            rf"\*(\d+) {log_tag} out: (?:0x)?[0-9A-Fa-f]+, size: (\d+)"
        )
        self.buf_re = re.compile(
            rf"\*(\d+) {log_tag} buffer created: (?:0x)?[0-9A-Fa-f]+, "
            rf"total: (\d+)"
        )
        # One line per turn of the encoder, whether or not it produced a
        # buffer. The commit trace above cannot stand in for it: a round
        # that writes nothing releases its buffer and logs nothing at
        # all, which is exactly the round that would spin.
        self.round_re = re.compile(
            rf"\*(\d+) {log_tag} round: consumed: (\d+), written: (\d+), "
            rf"step: (\d+)"
        )
        self.init_re = re.compile(
            rf"\*(\d+) {log_tag} encoder instance created and configured"
        )

    def path(self, location: str, name: str = "") -> str:
        """Where this codec's twin of `location` lives.

        zstd carries no prefix, so every path it has always used is
        unchanged and the conf did not have to be rewritten around the
        parameterisation; Brotli's twins sit beside them under "br-".
        """
        return f"/{self.prefix}{location}/{name}"

    def file(self, name: str) -> str:
        """A plain static file this codec's filter compresses.

        zstd's is the server root, which the http block already has
        pack_zstd on for; Brotli needs a location of its own to turn its
        filter on, so the two are not the same shape and this hides the
        difference.
        """
        return f"/{name}" if not self.prefix else f"/{self.prefix}static/{name}"

    def __repr__(self) -> str:
        return self.name


ZSTD = Codec(
    "zstd", "zstd", ".zst", "pack_zstd", "", "zstd", ("zstdlib",),
    continue_step=1,
)
BROTLI = Codec(
    "brotli", "br", ".br", "pack_brotli", "br-", "brotli", ("brotli",),
    continue_step=0,
)


# What a test line is prefixed with: the tag clipped to four characters
# and right-aligned in that width, so all are six columns with their
# brackets and the names beside them line up - "[zstd]", "[brot]",
# "[stat]", " [all]". Nothing collides at four. Built from log_tag, not
# log_tag from it: that string goes into the allocator regexes below,
# where "[zstd]" would be a character class matching nothing.
def tag_for(text: str) -> str:
    pad = 4 - len(text)
    return f"{' ' * (pad)}[{text[:4]}]"


CODECS = [ZSTD, BROTLI]


# ---------------------------------------------------------------------------
# Test registry
# ---------------------------------------------------------------------------

class RegistryEntry(TypedDict):
    """One row of REGISTRY: what main() needs to run a test and report on
    it. "fn" always takes just (ctx,) by the time it is stored here - a
    codec-parameterised test is wrapped into that shape in register()
    below, so main() never has to know which kind it is calling."""

    name: str
    fn: Callable[["Context"], None]
    codec: Codec
    needs_decoder: bool
    needs_debug: bool
    needs_corpus: bool
    needs_curl: bool


REGISTRY: list[RegistryEntry] = []


def test(
    name: str,
    needs_decoder: bool = False,
    needs_debug: bool = False,
    needs_corpus: bool = False,
    needs_curl: bool = False,
    codecs: list[Codec] | None = None,
    only: Codec | None = None,
    label: str | None = None,
) -> Callable[[Callable[..., None]], Callable[..., None]]:
    """Registers a test. The body raises Failure to report a failure.

    "codecs" is what makes a test structural: given a list, it is
    registered once per codec and its body takes (ctx, codec) instead of
    (ctx), reaching every path and directive through that codec rather
    than naming zstd. The registered name gets the codec appended, so a
    failure still says which one broke.

    Left None the test runs once against zstd and takes (ctx) alone -
    which is what every test that reads the compressed bytes has to do,
    zstd's frame header being the only one this suite can parse.

    "only" names the codec a test that is not parameterised drives, so
    it is tagged like any other rather than reading as untagged. It also
    binds entry["codec"], which is what decides whether a missing
    decoder skips the test.

    "label" tags a test that is about neither filter - "static" for the
    pack_static ones, which serve pre-compressed siblings for all three
    encodings and share no code with the encoders.

    Every tag is a bracketed prefix, so a run sorts and scans by what
    each test covers rather than by the first word of its sentence.
    """
    if only and label:
        raise ValueError("a test is tagged by one of only= or label=")

    if only:
        tag = tag_for(only.log_tag)
    elif label:
        tag = tag_for(label)
    else:
        tag = ""

    def register(fn: Callable[..., None]) -> Callable[..., None]:
        if codecs is None:
            REGISTRY.append(
                {
                    "name": f"{tag} {name}" if tag else name,
                    "fn": fn,
                    "codec": only or ZSTD,
                    "needs_decoder": needs_decoder,
                    "needs_debug": needs_debug,
                    "needs_corpus": needs_corpus,
                    "needs_curl": needs_curl,
                }
            )
            return fn

        for codec in codecs:
            REGISTRY.append(
                {
                    "name": f"{tag_for(codec.log_tag)} {name}",
                    # Bound now rather than read from the closure: every
                    # entry shares one function, and a late read would
                    # give them all the last codec in the list.
                    "fn": (lambda ctx, _fn=fn, _codec=codec: _fn(ctx, _codec)),
                    "codec": codec,
                    "needs_decoder": needs_decoder,
                    "needs_debug": needs_debug,
                    "needs_corpus": needs_corpus,
                    "needs_curl": needs_curl,
                }
            )
        return fn

    return register


class Failure(Exception):
    pass


def check(condition: object, message: str) -> None:
    if not condition:
        raise Failure(message)


# ---------------------------------------------------------------------------
# Environment discovery
# ---------------------------------------------------------------------------


def locate_nginx(explicit: str | None) -> str:
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
        f"  Build one with script/build/build.sh, or pass --nginx PATH."
    )


def nginx_build_info(nginx: str) -> tuple[str, bool]:
    """Returns (version_line, has_debug). nginx -V reports on stderr."""
    done = subprocess.run([nginx, "-V"], capture_output=True, text=True, check=False)
    text = (done.stderr or "") + (done.stdout or "")
    version = next(
        (line for line in text.splitlines() if line.startswith("nginx version")),
        "unknown version",
    )
    return version, "--with-debug" in text


# Where each codec's own command line tool is built, when the vendored
# one was built at all. script/build/build.sh asks for zstd's; Brotli's is off
# by default there, since nothing but this needs it, so that path is
# usually a miss and the system CLI is what answers.
BUNDLED_DECODERS = {
    "zstd": ("deps", "zstd", "out", "programs", "zstd"),
    "brotli": ("deps", "brotli", "out", "brotli"),
}


def locate_decoder(codec: Codec = ZSTD) -> Callable[[bytes], bytes] | None:
    """Returns a callable bytes->bytes, or None if `codec` cannot be decoded."""
    bundled = os.path.join(ROOT, *BUNDLED_DECODERS[codec.name])
    cli = shutil.which(codec.name)
    if not cli and os.path.isfile(bundled) and os.access(bundled, os.X_OK):
        cli = bundled
    if not cli:
        return None

    def decode_with_cli(data: bytes) -> bytes:
        # The CLI is happiest with a real file; this also keeps us clear of
        # stdin-buffering differences between zstd releases.
        with tempfile.NamedTemporaryFile(suffix=codec.ext, delete=False) as handle:
            handle.write(data)
            path = handle.name
        try:
            return subprocess.run(
                [cli, "-d", "-c", "-f", path], capture_output=True, check=True
            ).stdout
        finally:
            os.unlink(path)

    return decode_with_cli


def locate_encoder() -> Callable[[bytes], bytes] | None:
    """Returns a callable bytes->bytes, or None if zstd cannot be encoded.

    Only the pack_static tests need this: they have to lay down a real
    ".zst" sibling for the module to find, and nginx will not make one for
    them.
    """
    bundled = os.path.join(ROOT, "deps", "zstd", "out", "programs", "zstd")
    cli = shutil.which("zstd")
    if not cli and os.path.isfile(bundled) and os.access(bundled, os.X_OK):
        cli = bundled
    if not cli:
        return None

    def encode_with_cli(data: bytes) -> bytes:
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


def encode_with_command(argv: list[str]) -> Callable[[bytes], bytes] | None:
    """Returns a callable bytes->bytes running argv, or None if argv[0] is
    not on PATH."""
    cli = shutil.which(argv[0])
    if not cli:
        return None

    def encode(data: bytes) -> bytes:
        return subprocess.run(
            [cli, *argv[1:]], input=data, capture_output=True, check=True
        ).stdout

    return encode


# One row per encoding pack_static knows, in the order the module probes
# them, which is what the preference tests below assert.
#
# The module never decodes what it serves: it copies the sibling and
# labels it, so a sibling only has to be distinguishable for the choice
# to be provable. A real encoder is used wherever one is to hand, so the
# bytes are also genuinely decodable by a client; where none is
# installed a marker body stands in, and the tests still prove which
# file was chosen because they compare against the bytes on disk.
SIBLING_ENCODINGS: list[
    tuple[str, str, Callable[[], Callable[[bytes], bytes] | None]]
] = [
    ("br", ".br", lambda: encode_with_command(["brotli", "-c", "-q", "5"])),
    ("gzip", ".gz", lambda: (lambda data: gzip.compress(data))),
    ("zstd", ".zst", locate_encoder),
]


def write_siblings(
    html: str, stem: str, body: bytes, encodings: Sequence[str]
) -> dict[str, bytes]:
    """Writes "stem" and a sibling per named encoding, returning a dict of
    the exact bytes each file received."""
    written = {stem: body}
    with open(os.path.join(html, stem), "wb") as handle:
        handle.write(body)

    for name, ext, locate in SIBLING_ENCODINGS:
        if name not in encodings:
            continue
        encode = locate()
        if encode:
            blob = encode(body)
        else:
            # Not real "name" data, which the module cannot tell and does
            # not care about. Distinct per encoding so a wrong choice is
            # visible in the assertion rather than merely in the label.
            blob = b"placeholder for " + name.encode() + b" of " + stem.encode()
        with open(os.path.join(html, stem + ext), "wb") as handle:
            handle.write(blob)
        written[stem + ext] = blob

    return written


def port_is_free(port: int) -> bool:
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

# Comfortably over the default pack_zstd_min_length, so a status code is the
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


def make_text(word_count: int, seed: int) -> str:
    rng = random.Random(seed)
    return " ".join(rng.choice(WORDS) for _ in range(word_count))


def make_dense_text(length: int, seed: int) -> str:
    """`length` characters that barely compress.

    make_text() repeats a small vocabulary and so compresses away to almost
    nothing; drawing every character independently leaves the compressed body
    close to its raw size, which is what a test comparing output buffer sizes
    needs to see.
    """
    rng = random.Random(seed)
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    return "".join(rng.choice(alphabet) for _ in range(length))


# Real-world files, checked in under script/corpus. Everything else here is
# make_text() output, which is a poor stand-in for the web: random words drawn
# from a small list repeat at long range, so they compress far better and far
# more predictably than real markup or code. See corpus/PROVENANCE.md.
CORPUS = os.path.join(ROOT, "script", "corpus")
CORPUS_FILES = (
    "wiki.html",
    "site.css",
    "app.js",
    "app.min.js",
    "prose.txt",
    "api.json",
    "feed.pb",
)


def load_corpus() -> dict[str, bytes]:
    """Returns {name: bytes}, or {} if the corpus is not present."""
    corpus: dict[str, bytes] = {}
    for name in CORPUS_FILES:
        path = os.path.join(CORPUS, name)
        try:
            with open(path, "rb") as handle:
                corpus[name] = handle.read()
        except FileNotFoundError:
            return {}
    return corpus


def build_fixtures(work: str) -> dict[str, bytes]:
    html = os.path.join(work, "html")
    os.makedirs(html, exist_ok=True)
    os.makedirs(os.path.join(work, "logs"), exist_ok=True)

    files = {
        # Large enough to span many blocks, so the encoder performs the
        # short-lived per-block allocations the memory tests care about, and
        # large enough that windowLog is not reduced below pack_zstd_window.
        "big.html": f"<html><body>{make_text(200000, 1)}</body></html>",
        # What big.html is for, at a tenth of its compressed size: still
        # past the 128 KB block maximum and far past any window either
        # codec defaults to, so an encoder built for it is the full-sized
        # one, but an order of magnitude cheaper to serve under
        # script/tests/stream/test-small-buffer.sh. Every 64 bytes of compressed output
        # is a round there, and nginx logs several lines per round, so a
        # test that only needs "a real encoder, many times over" pays for
        # big.html's extra megabyte in debug log rather than in coverage.
        "medium.html": f"<html><body>{make_text(24000, 11)}</body></html>",
        # Over pack_zstd_min_length, but small enough that a known Content-Length
        # drives windowLog well below pack_zstd_window.
        "small.html": f"<html><body>{make_text(200, 2)}</body></html>",
        # Under any sane pack_zstd_min_length.
        "tiny.html": "<html>hi</html>",
        # Bracket the compiled-in pack_zstd_min_length default: the first must be
        # too small to be worth compressing, the second comfortably worth it.
        "under_min.html": ("<html><body>" + "x" * 176 + "</body></html>"),
        "over_min.html": ("<html><body>" + "y" * 376 + "</body></html>"),
        # Not in pack_zstd_types.
        "data.bin": make_text(500, 3),
        # Deliberately close to incompressible, unlike everything above:
        # make_text() draws on a small vocabulary and compresses ~130x, so
        # even a megabyte of it lands under 16k compressed - too small to
        # tell one output buffer size from another. Random characters keep
        # the compressed body roughly its raw size, which is what lets
        # test_buffer_size_is_honoured see a round larger than the default
        # buffer could hold.
        "dense.html": make_dense_text(200000, 4),
    }
    for name, content in files.items():
        with open(os.path.join(html, name), "w") as handle:
            handle.write(content)

    fixtures = {name: content.encode() for name, content in files.items()}

    # A pre-compressed sibling for pack_static to find. Written only when an
    # encoder is available; the tests skip otherwise.
    encode = locate_encoder()
    if encode:
        precompressed = f"<html><body>{make_text(2000, 5)}</body></html>".encode()
        with open(os.path.join(html, "precompressed.html"), "wb") as handle:
            handle.write(precompressed)
        with open(os.path.join(html, "precompressed.html.zst"), "wb") as handle:
            handle.write(encode(precompressed))
        fixtures["precompressed.html"] = precompressed
        # No ".zst" sibling, so pack_static has to fall through to it.
        with open(os.path.join(html, "plain_only.html"), "wb") as handle:
            handle.write(precompressed)
        fixtures["plain_only.html"] = precompressed

    # The default pack_static_encodings is every encoding the module knows,
    # and the /static/ location leaves it at that, so these exercise the
    # shipped default rather than a narrowed set.
    body = f"<html><body>{make_text(3000, 7)}</body></html>".encode()
    # All three siblings: which one comes back pins the probe order.
    fixtures.update(write_siblings(html, "multi.html", body, ("br", "zstd", "gzip")))
    # Only the last candidate in probe order exists, so the two ahead of it
    # have to miss and be stepped over.
    fixtures.update(write_siblings(html, "gz_only.html", body, ("gzip",)))
    # Only the middle one.
    fixtures.update(write_siblings(html, "zst_only.html", body, ("zstd",)))

    # Siblings that exist but cannot be served. Each must be stepped over
    # like a missing one, leaving the plain file to be served - a stray
    # file with the right suffix must not take the resource down with it.
    for stem in ("odd_dir.html", "odd_fifo.html", "odd_perm.html", "odd_loop.html"):
        with open(os.path.join(html, stem), "wb") as handle:
            handle.write(body)
        fixtures[stem] = body

    os.makedirs(os.path.join(html, "odd_dir.html.br"), exist_ok=True)

    fifo = os.path.join(html, "odd_fifo.html.br")
    if hasattr(os, "mkfifo") and not os.path.exists(fifo):
        os.mkfifo(fifo)

    # Unreadable, which root would read anyway - the test skips there.
    perm = os.path.join(html, "odd_perm.html.br")
    with open(perm, "wb") as handle:
        handle.write(b"unreadable")
    os.chmod(perm, 0o000)

    # A symlink to itself: opening it fails ELOOP, the one open_sibling
    # outcome none of the shapes above reach.
    loop = os.path.join(html, "odd_loop.html.br")
    if hasattr(os, "symlink") and not os.path.lexists(loop):
        os.symlink(loop, loop)

    # The body of an SSI include is spliced into its parent, so it can
    # carry no Content-Encoding of its own.
    with open(os.path.join(html, "include.shtml"), "w") as handle:
        handle.write('BEGIN<!--# include virtual="/subreq/multi.html" -->END')

    # Exactly the bytes the /burst endpoint streams, as a plain file.
    # Serving the same content both ways is what makes flush folding
    # measurable without reading the compressed format: the file is the
    # floor an encoder reaches when nothing interrupts it, and the burst
    # is what a chain of flush-marked buffers costs against that. zstd
    # can be checked by counting blocks in its frame header instead, but
    # Brotli states nothing of the sort, so this is the observable the
    # two have in common.
    burst = b"".join(
        b"%d %s" % (i, Upstream.BURST_TEXT) for i in range(Upstream.BURST_CHUNKS)
    )
    with open(os.path.join(html, "burst.html"), "wb") as handle:
        handle.write(burst)
    fixtures["burst.html"] = burst

    for name, blob in load_corpus().items():
        with open(os.path.join(html, name), "wb") as handle:
            handle.write(blob)
        fixtures[name] = blob

    return fixtures


def render_conf(work: str, port: int, upstream_port: int) -> str:
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

    def __init__(self, port: int, payloads: dict[str, bytes]) -> None:
        self.port = port
        self.payloads = payloads
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", port))
        self.sock.listen(16)
        self.stop = threading.Event()
        self.clients: list[socket.socket] = []
        self.thread = threading.Thread(target=self._serve, daemon=True)

    def start(self) -> None:
        self.thread.start()

    def _serve(self) -> None:
        while not self.stop.is_set():
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            self.clients.append(conn)
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    @staticmethod
    def _chunk(payload: bytes) -> bytes:
        return b"%x\r\n" % len(payload) + payload + b"\r\n"

    def _handle(self, conn: socket.socket) -> None:
        try:
            request = conn.recv(65536).decode("latin-1")
            path = request.split(" ")[1] if " " in request else "/"

            # Must come before the chunked 200 below - these replies write
            # their own status line.
            if path.startswith("/dribble"):
                self._dribble(conn)
                return

            if path.startswith("/burst"):
                self._burst(conn, wide="wide" in path)
                return

            if path.startswith("/status/"):
                self._status(conn, int(path.rsplit("/", 1)[-1]))
                return

            if path.startswith("/cc/"):
                self._cache_control(conn, path.rsplit("/", 1)[-1])
                return

            if path.startswith("/enc/"):
                self._encoded(conn, path.rsplit("/", 1)[-1])
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
    BURST_TEXT = b"<p>zstd flush folding burst chunk payload</p>"

    # The wide burst carries more than the fold is allowed to hold, so the
    # bound has to cut it; /burst-wide/ raises proxy_buffer_size to match,
    # since the point is a single oversized chain rather than several.
    WIDE_CHUNKS = 128
    WIDE_CHUNK_SIZE = 1024

    def _burst(self, conn: socket.socket, wide: bool = False) -> None:
        """Writes every chunk in a single send.

        nginx then reads them together and ngx_http_proxy_chunked_filter
        appends one buffer per chunk, each with flush set, into one chain -
        the case flush folding exists for. Sending them as separate writes
        would let nginx read them one at a time, and the chain would hold a
        single flush marker with nothing to fold.
        """
        if wide:
            pieces = [
                b"%08d " % i + make_dense_text(self.WIDE_CHUNK_SIZE - 9, i).encode()
                for i in range(self.WIDE_CHUNKS)
            ]
        else:
            pieces = [b"%d %s" % (i, self.BURST_TEXT) for i in range(self.BURST_CHUNKS)]

        body = b"".join(self._chunk(piece) for piece in pieces)
        conn.sendall(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
            b"Transfer-Encoding: chunked\r\n\r\n" + body + b"0\r\n\r\n"
        )

    def _dribble(self, conn: socket.socket) -> None:
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

    def _status(self, conn: socket.socket, code: int) -> None:
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

    # Long enough to clear every min_length this suite configures, so a
    # response declined here was declined for the header and not its size.
    TRANSFORM_BODY = b"<html><body>" + b"no-transform payload " * 60 + b"</body></html>"

    def _cache_control(self, conn: socket.socket, directives: str) -> None:
        """Replies with the given Cache-Control, or none for "plain"."""
        extra = (
            ""
            if directives == "plain"
            else f"Cache-Control: {directives.replace('+', ', ')}\r\n"
        )
        conn.sendall(
            (
                f"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
                f"{extra}Content-Length: {len(self.TRANSFORM_BODY)}\r\n\r\n"
            ).encode()
            + self.TRANSFORM_BODY
        )

    def _encoded(self, conn: socket.socket, value: str) -> None:
        """Replies already carrying Content-Encoding: `value`.

        An origin that compressed its own response first - or merely
        claims to have - must be left alone: labelling it a second time
        would hand the client a body claiming one encoding while
        actually carrying two.
        """
        conn.sendall(
            (
                f"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
                f"Content-Encoding: {value}\r\n"
                f"Content-Length: {len(self.TRANSFORM_BODY)}\r\n\r\n"
            ).encode()
            + self.TRANSFORM_BODY
        )

    def _vary(self, conn: socket.socket, case: str) -> None:
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

    def shutdown(self) -> None:
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
    def __init__(self, binary: str, work: str, conf: str, port: int) -> None:
        self.binary = binary
        self.work = work
        self.conf = conf
        self.port = port
        self.proc: subprocess.Popen[str] | None = None
        self.error_log = os.path.join(work, "logs", "error.log")
        self.log_mark = 0

    def start(self) -> None:
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

    def stop(self) -> None:
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=5)

    def mark_log(self) -> None:
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

    def read_log(self, whole: bool = False) -> str:
        """Everything logged since the last mark_log(), or the lot."""
        try:
            with open(self.error_log, "rb") as handle:
                if not whole:
                    handle.seek(self.log_mark)
                return handle.read().decode(errors="replace")
        except FileNotFoundError:
            return ""

    def read_log_from(self, offset: int) -> tuple[str, int]:
        """(text, next offset) for whole lines logged after "offset".

        For a caller reading the same growing log repeatedly. The tail is
        cut at the last newline and left for the next call, so a line
        caught half-written is never handed out in two pieces - which
        would lose whichever field the split fell inside.
        """
        try:
            with open(self.error_log, "rb") as handle:
                handle.seek(offset)
                raw = handle.read()
        except FileNotFoundError:
            return "", offset

        cut = raw.rfind(b"\n") + 1
        if not cut:
            return "", offset
        return raw[:cut].decode(errors="replace"), offset + cut


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------


def fetch(
    port: int,
    path: str,
    accept_encoding: str | None = "zstd",
    method: str = "GET",
    timeout: float = 30,
    headers: dict[str, str] | None = None,
) -> tuple[int, dict[str, str], bytes]:
    """Returns (status, lowercased headers, raw body). No auto-decompression.

    accept_encoding of None sends no Accept-Encoding header at all, which is a
    different case from sending an empty one.

    "headers" adds request headers the caller needs - "Via", for the
    proxied gate - and is applied after Accept-Encoding, so a caller can
    override that too.
    """
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    try:
        request_headers = {"Host": "localhost"}
        if accept_encoding is not None:
            request_headers["Accept-Encoding"] = accept_encoding
        if headers:
            request_headers.update(headers)
        conn.request(method, path, headers=request_headers)
        response = conn.getresponse()
        body = response.read()
        return (response.status, {k.lower(): v for k, v in response.getheaders()}, body)
    finally:
        conn.close()


def fetch_repeated(
    port: int,
    path: str,
    name: str,
    accept_encoding: str | None = "zstd",
    timeout: float = 30,
) -> tuple[int, list[str], dict[str, str]]:
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


def fetch_and_abort(
    port: int, path: str, accept_encoding: str = "zstd", settle: float = 1.5
) -> None:
    """Starts a request, reads a little, then resets the connection.

    SO_LINGER with a zero timeout makes close() emit an RST rather than a FIN,
    which is what makes nginx terminate the request outright instead of
    draining it through the body filter.
    """
    sock = socket.create_connection(("127.0.0.1", port), timeout=10)
    try:
        sock.sendall(
            (
                f"GET {path} HTTP/1.1\r\nHost: localhost\r\n"
                f"Accept-Encoding: {accept_encoding}\r\n\r\n"
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

CLOSE_RE = re.compile(r"\*(\d+) http close request")

# The zstd codec's own patterns, kept under their original names: every
# helper below takes a codec and defaults to this one, so a test that
# never mentions a codec still reads and behaves exactly as it did.
ALLOC_RE = ZSTD.alloc_re
FREE_RE = ZSTD.free_re
INIT_RE = ZSTD.init_re
OUT_RE = ZSTD.out_re
BUF_RE = ZSTD.buf_re


def buffers_created(log: str, codec: Codec = ZSTD) -> int:
    """Most output buffers any one response was seen to create."""
    return max((int(m.group(2)) for m in codec.buf_re.finditer(log)), default=0)


def encoder_count(log: str, codec: Codec = ZSTD) -> int:
    """How many encoders were built, in this slice of the log."""
    return len(codec.init_re.findall(log))


def frame_window(data: bytes) -> int:
    """The window size the encoder declared, read from the zstd frame header.

    RFC 8878 section 3.1.1. Deliberately taken from the frame rather than
    from anything the module reports: zstd picks the real window from the
    pack_zstd_window ceiling and the pledged length together when compression
    starts, and offers no call that reports the result back, so the module
    could only ever log what it asked for. Reading the frame asserts what
    the encoder did instead of what this module intended, so it also holds
    if zstd's own sizing changes.
    """
    return _frame_header(data)[0]


def frame_blocks(data: bytes) -> int:
    """How many blocks the first frame is made of.

    This is the observable behind flush folding. A flush ends the block
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


def frame_declares_size(data: bytes) -> bool:
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


def _frame_header(data: bytes) -> tuple[int, int]:
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


class AllocatorEntry(TypedDict):
    """One connection's slot in an allocator_events() result.

    Named for the same reason Timeline is: the values are not one type,
    and "live" is itself a dict, so nothing here can be indexed or
    compared without the shape being stated somewhere.
    """

    allocs: int
    frees: int
    null_frees: int
    live: dict[str, int]
    live_bytes: int
    peak_bytes: int
    double_alloc: bool
    unmatched_free: bool
    closed: bool
    frees_after_close: int


def allocator_events(
    log: str,
    codec: Codec = ZSTD,
    into: dict[str, AllocatorEntry] | None = None,
) -> dict[str, AllocatorEntry]:
    """Replays the encoder's allocator trace, per connection.

    Tracks whether every pointer came back exactly once, the peak
    simultaneously-live byte count, and where frees sit relative to
    "http close request" - which nginx logs on entry to ngx_http_free_request,
    before the pool cleanup handlers run inside ngx_destroy_pool.

    "into" continues an earlier call rather than starting over. Every
    branch below only ever adds to a connection's slot, so replaying the
    log in successive pieces gives what one pass over the whole of it
    would - as long as the pieces break on line boundaries, which is
    what Nginx.read_log_from guarantees. wait_for_encoder_release uses
    it to avoid re-reading megabytes on every poll.
    """
    stats: dict[str, AllocatorEntry] = {} if into is None else into

    def slot(conn: str) -> AllocatorEntry:
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
        match = codec.alloc_re.search(line)
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

        match = codec.free_re.search(line)
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


class Timeline(TypedDict):
    """What allocator_timeline returns.

    Spelled out because the values are not one type - three of these are
    counts, one is a list and one a set - and a plain dict collapses them
    into a union that nothing can be indexed out of. Naming the shape is
    also the only way len(soak["connections"]) can be checked at all.
    """

    allocs: int
    frees: int
    unmatched: int
    peak: int
    live_at_end: int
    blocks_at_end: int
    at_request_start: list[int]
    connections: set[str]


def allocator_timeline(log: str, codec: "Codec" = ZSTD) -> Timeline:
    """Replays the allocator trace in order instead of grouping by connection.

    allocator_events() sums per connection, which is what a test opening one
    connection per request wants. On a keep-alive connection every request
    shares a single id, so summing tells you nothing about whether an encoder
    was released before the next request began - only walking the log in order
    and recording live bytes at each request line does.
    """
    live: dict[str, int] = {}
    live_bytes = peak = 0
    allocs = frees = unmatched = 0
    at_request_start: list[int] = []
    connections: set[str] = set()

    for line in log.splitlines():
        match = REQUEST_LINE_RE.search(line)
        if match:
            connections.add(match.group(1))
            at_request_start.append(live_bytes)
            continue

        match = codec.alloc_re.search(line)
        if match:
            ptr, size = match.group(2).lstrip("0"), int(match.group(3))
            live[ptr] = size
            live_bytes += size
            peak = max(peak, live_bytes)
            allocs += 1
            continue

        match = codec.free_re.search(line)
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


# Every wait_for_encoder_release call that gave up, as (codec, timeout).
# The runner reads the length either side of a test to tell whether that
# test spent its time waiting rather than working.
TEARDOWN_TIMEOUTS: list[tuple[str, float]] = []


def wait_for_encoder_release(
    nginx: Nginx, timeout: float = 10.0, codec: Codec = ZSTD
) -> dict[str, AllocatorEntry]:
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

    Giving up is recorded in TEARDOWN_TIMEOUTS rather than kept quiet.
    A test whose assertions pass anyway is otherwise indistinguishable
    from one that settled at once, except that it took the whole
    timeout - which reads as a hung suite rather than as the signal it
    is.
    """
    deadline = time.time() + timeout
    # Nothing traced at all is a different answer from not settled yet.
    # A response the filter declined - one under min_length, say - never
    # builds an encoder, so waiting the whole timeout for one to appear
    # turns a legitimate pass into a stall. The allocation is logged
    # before any of the body reaches the client, so a short grace is
    # enough to tell "declined" from "the log has not caught up".
    empty_deadline = time.time() + 0.5

    # Read the log forward rather than from the mark each time. A debug
    # build writes megabytes for a soak of any size, and re-reading and
    # re-parsing all of it on every poll costs more than the wait it is
    # measuring - the reason this loop showed up as minutes on a slower
    # runner while taking a second here.
    offset = nginx.log_mark
    stats: dict[str, AllocatorEntry] = {}
    delay = 0.02
    while True:
        chunk, offset = nginx.read_log_from(offset)
        if chunk:
            allocator_events(chunk, codec, into=stats)

        active = [entry for entry in stats.values() if entry["allocs"]]
        settled = active and all(
            entry["closed"] and entry["allocs"] == entry["frees"] and not entry["live"]
            for entry in active
        )
        if settled:
            return stats
        if not active and time.time() >= empty_deadline:
            return stats
        if time.time() >= deadline:
            TEARDOWN_TIMEOUTS.append((codec.name, timeout))
            return stats

        # Backs off so a long wait costs a handful of polls rather than
        # one every 50ms, while a teardown that lands immediately is
        # still noticed within a couple of hundredths.
        time.sleep(delay)
        delay = min(delay * 1.5, 0.25)


def assert_balanced(
    stats: dict[str, AllocatorEntry], label: str
) -> dict[str, AllocatorEntry]:
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


@test("static file round-trips through the encoder", needs_decoder=True, only=ZSTD)
def test_static_roundtrip(ctx: Context) -> None:
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
    decode = must_decode(ctx)
    check(decode(body) == original, "decoded body differs from the original")


def must_decode(carrier: Codec | Context) -> Callable[[bytes], bytes]:
    """Narrows an optional decoder to a callable.

    Every caller of this is registered needs_decoder, so the runner skips a
    test rather than run it when there is nothing to decode with - "decode"
    cannot really be None here. Said out loud rather than assumed: if that
    ever stops holding, this names the reason instead of raising "NoneType
    is not callable" from the middle of an assertion.
    """
    if carrier.decode is None:
        raise Failure("no decoder available; this test should have been skipped")
    return carrier.decode


def check_corpus_roundtrip(
    ctx: Context, name: str, path: str | None = None, codec: Codec = ZSTD
) -> None:
    """Fetches one corpus file, and checks it compressed and decodes back."""
    path = path or codec.file(name)
    original = ctx.fixtures[name]

    status, headers, body = fetch(ctx.port, path, codec.token)
    check(status == 200, f"{path}: expected 200, got {status}")
    check(
        headers.get("content-encoding") == codec.token,
        f"{path}: expected Content-Encoding: {codec.token}, got "
        f"{headers.get('content-encoding')!r}",
    )
    check(
        len(body) < len(original),
        f"{path}: compressed body ({len(body)}) is not smaller than the "
        f"original ({len(original)})",
    )

    decode = must_decode(codec)
    check(decode(body) == original, f"{path}: decoded body differs")


@test("pack_static serves a pre-compressed sibling", needs_decoder=True, label="static")
def test_static_module_serves_zst(ctx: Context) -> None:
    if "precompressed.html" not in ctx.fixtures:
        raise Failure("no zstd encoder available to build the .zst fixture")

    status, headers, body = fetch(ctx.port, "/static/precompressed.html")
    check(status == 200, f"expected 200, got {status}")
    check(
        headers.get("content-encoding") == "zstd",
        f"pack_static did not serve the .zst sibling; headers: {headers!r}",
    )
    decode = must_decode(ctx)
    check(
        decode(body) == ctx.fixtures["precompressed.html"],
        "the served .zst did not decode back to the original",
    )
    # Twice, so the second request is answered from open_file_cache. That is
    # the path that hashes the constructed name over its length.
    status, headers, body = fetch(ctx.port, "/static/precompressed.html")
    check(status == 200, f"cached request: expected 200, got {status}")
    check(
        decode(body) == ctx.fixtures["precompressed.html"],
        "the cached .zst did not decode back to the original",
    )


@test("pack_static declines a client that will not take zstd", label="static")
def test_static_module_declines_plain_client(ctx: Context) -> None:
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


@test("pack_static ignores a method other than GET or HEAD", label="static")
def test_static_method_guard(ctx: Context) -> None:
    """POST and the rest are core's own static handler to answer for -
    a location cannot decide whether a method is allowed, only whether
    pack_static itself has anything to say about this response."""
    status, headers, _ = fetch(ctx.port, "/static/multi.html", "br", method="POST")
    check(status == 405, f"expected 405 for POST, got {status}")
    check(
        "content-encoding" not in headers,
        f"a rejected method still got {headers.get('content-encoding')!r}",
    )


@test("pack_static declines a URI naming a directory", label="static")
def test_static_directory_guard(ctx: Context) -> None:
    """A trailing slash names a directory, not a file pack_static could
    have a sibling for - core's own directory handling answers instead,
    autoindex being off."""
    status, headers, _ = fetch(ctx.port, "/static/", "br")
    check(status == 403, f"expected 403 for a directory URI, got {status}")
    check(
        "content-encoding" not in headers,
        f"a directory response still got {headers.get('content-encoding')!r}",
    )


@test("a request carrying Via is not served a sibling under \"on\"", label="static")
def test_static_proxied_guard(ctx: Context) -> None:
    """"Via" means another proxy already handled this request - the same
    signal test_proxied_gate checks for the two filters, but pack_static's
    own accepts() has no pack_*_proxied of its own to relax it with yet, so
    "on" declines every proxied request outright."""
    via = {"Via": "1.1 upstream-cache"}
    _, headers, _ = fetch(ctx.port, "/static/multi.html", "br", headers=via)
    check(
        "content-encoding" not in headers,
        f"a request carrying Via was served a sibling anyway: {headers!r}",
    )

    # Same request without Via: proves the decline above is the header's
    # doing and not the file lacking a sibling.
    _, headers, _ = fetch(ctx.port, "/static/multi.html", "br")
    check(
        headers.get("content-encoding") == "br",
        f"the same request without Via was not served a sibling: {headers!r}",
    )


@test("HEAD on a sibling gets its headers and no body", label="static")
def test_static_head_request(ctx: Context) -> None:
    status, headers, body = fetch(ctx.port, "/static/multi.html", "br", method="HEAD")
    check(status == 200, f"expected 200, got {status}")
    check(
        headers.get("content-encoding") == "br",
        f"HEAD was not served the sibling: {headers!r}",
    )
    check(body == b"", f"HEAD returned a {len(body)} byte body")


@test("a broken path below a sibling is declined, not a failure", label="static")
def test_static_sibling_broken_path(ctx: Context) -> None:
    """open_sibling's ENOTDIR and ENAMETOOLONG cases: a path component
    that names a plain file rather than a directory, and one longer than
    the filesystem allows. Neither is this module's problem to solve -
    both are declines, the same as a sibling that is simply missing, and
    core's own static handler is what turns either into the 404."""
    cases = [
        (
            "/static/multi.html/x.html",
            "a path component that is a file, not a directory",
        ),
        (
            "/static/" + "a" * 300 + ".html",
            "a path component past the filesystem's name limit",
        ),
    ]
    for path, shape in cases:
        status, headers, _ = fetch(ctx.port, path, "br")
        check(status == 404, f"{shape}: expected 404, got {status}")
        check(
            "content-encoding" not in headers,
            f"{shape}: served a sibling anyway: {headers.get('content-encoding')!r}",
        )


@test("every response from a pack_static location says it varies", label="static")
def test_static_vary_is_unconditional(ctx: Context) -> None:
    """ "pack_static on" is what makes the body depend on Accept-Encoding,
    and that is a property of the location rather than of the file, so the
    header goes out whether or not this client is served a sibling and
    whether or not one exists. A cache that stored the plain response
    without it could hand that response to a client the module would have
    served a sibling.

    "always" is the exception, and the case that keeps this honest: it
    serves the encoded file to everyone whatever they asked for, so
    nothing about the response varies with Accept-Encoding."""
    if "precompressed.html" not in ctx.fixtures:
        raise Failure("no zstd encoder available to build the .zst fixture")

    # A sibling exists and this client cannot take it.
    _, headers, _ = fetch(ctx.port, "/static/precompressed.html", accept_encoding=None)
    check(
        headers.get("vary") == "Accept-Encoding",
        f"declined client, sibling on disk: {headers!r}",
    )

    # A sibling exists and this client is served it.
    _, headers, _ = fetch(ctx.port, "/static/precompressed.html")
    check(
        headers.get("vary") == "Accept-Encoding",
        f"served client: {headers!r}",
    )

    # No sibling at all: the location still varies, even though this
    # particular file could only ever be served one way.
    _, headers, _ = fetch(ctx.port, "/static/plain_only.html", accept_encoding=None)
    check(
        headers.get("vary") == "Accept-Encoding",
        f"no sibling on disk: {headers!r}",
    )

    # "always" ignores Accept-Encoding, so it must not claim to vary.
    _, headers, _ = fetch(ctx.port, "/subreq/multi.html", accept_encoding=None)
    check(
        "vary" not in headers,
        f'"always" serves one file to everyone, so nothing varies; got {headers!r}',
    )


def check_sibling_served(
    ctx: Context,
    stem: str,
    accept_encoding: str | None,
    encoding: str | None,
    prefix: str = "static",
) -> dict[str, str]:
    """Fetches "stem" and asserts which sibling came back.

    The body is compared against the bytes actually written to that
    sibling, so a wrong choice fails on content and not only on the
    label - the label alone would still pass if the module served the
    right name from the wrong file.
    """
    path = f"/{prefix}/{stem}"
    status, headers, body = fetch(ctx.port, path, accept_encoding=accept_encoding)
    check(status == 200, f"{path} {accept_encoding!r}: expected 200, got {status}")

    got = headers.get("content-encoding")
    if encoding is None:
        check(
            got is None,
            f"{path} {accept_encoding!r}: expected no Content-Encoding, got {got!r}",
        )
        want = ctx.fixtures[stem]
    else:
        check(
            got == encoding,
            f"{path} {accept_encoding!r}: expected Content-Encoding {encoding!r}, "
            f"got {got!r}",
        )
        want = ctx.fixtures[stem + SIBLING_EXTS[encoding]]

    check(
        body == want,
        f"{path} {accept_encoding!r}: served {len(body)} bytes, which are not "
        f"the {encoding or 'plain'} file's {len(want)}",
    )
    return headers


SIBLING_EXTS = {name: ext for name, ext, _ in SIBLING_ENCODINGS}


@test("pack_static serves every encoding the default config allows", label="static")
def test_static_all_encodings(ctx: Context) -> None:
    """The default pack_static_encodings is br, gzip and zstd together, and
    the /static/ location does not narrow it. A client naming exactly one of
    them must get that one."""
    for encoding in ("br", "zstd", "gzip"):
        check_sibling_served(ctx, "multi.html", encoding, encoding)


@test("pack_static probes in the order pack_static_encodings named", label="static")
def test_static_directive_order(ctx: Context) -> None:
    """Two locations list the same three encodings in opposite orders. A
    client offering all three gets the first one the directive named, so the
    same request is answered differently by each - which is only possible if
    the order the admin wrote survives into the probe.

    This is what a bitmask could not do: ngx_conf_set_bitmask_slot ORs the
    values together and the order is gone by the time the handler runs."""
    for prefix, expected in [("order-bgz", "br"), ("order-zgb", "zstd")]:
        for accept in ["br, gzip, zstd", "zstd, gzip, br", "gzip, br, zstd"]:
            check_sibling_served(ctx, "multi.html", accept, expected, prefix=prefix)


@test("the client's own order does not override the directive's", label="static")
def test_static_client_order_ignored(ctx: Context) -> None:
    """Accept-Encoding is read as a set of what the client will take, not as
    a ranking. Whatever order it lists them in, the directive decides."""
    # The same two encodings offered in either order. br is not among
    # them, so each location falls to the first of the two its own
    # directive named: gzip for "br gzip zstd", zstd for "zstd gzip br".
    for accept in ["gzip, zstd", "zstd, gzip"]:
        check_sibling_served(ctx, "multi.html", accept, "gzip", prefix="order-bgz")
        check_sibling_served(ctx, "multi.html", accept, "zstd", prefix="order-zgb")


@test("pack_static serves only the encodings the directive named", label="static")
def test_static_directive_subset(ctx: Context) -> None:
    """A narrowed list still keeps its order, and an encoding left out of it
    is not served even when the client asks for it and the sibling is on
    disk."""
    check_sibling_served(ctx, "multi.html", "br, gzip, zstd", "zstd", prefix="order-zg")
    check_sibling_served(ctx, "multi.html", "gzip, zstd", "zstd", prefix="order-zg")
    check_sibling_served(ctx, "multi.html", "gzip", "gzip", prefix="order-zg")
    # br is on disk and the client wants it, but the directive omits it.
    check_sibling_served(ctx, "multi.html", "br", None, prefix="order-zg")


@test("pack_static defaults to every encoding it knows, in table order", label="static")
def test_static_default_order(ctx: Context) -> None:
    """/static/ leaves pack_static_encodings unwritten, so the default
    stands: all three, in the order the module's table lists them."""
    for accept, expected in [
        ("br, gzip, zstd", "br"),
        ("gzip, zstd", "gzip"),
        ("zstd", "zstd"),
        ("br, gzip", "br"),
        ("zstd, br", "br"),
        # A browser's real header, in the order browsers send it.
        ("gzip, deflate, br, zstd", "br"),
    ]:
        check_sibling_served(ctx, "multi.html", accept, expected)


@test("pack_static steps over the candidates that have no sibling", label="static")
def test_static_probe_fallthrough(ctx: Context) -> None:
    """Only one sibling exists, and the client accepts all three, so the
    module has to miss on the candidates ahead of it and keep going rather
    than decline at the first ENOENT."""
    check_sibling_served(ctx, "gz_only.html", "br, gzip, zstd", "gzip")
    check_sibling_served(ctx, "zst_only.html", "br, gzip, zstd", "zstd")
    # And with the one that does exist left out of Accept-Encoding, every
    # candidate misses and the plain file is served.
    check_sibling_served(ctx, "gz_only.html", "br, zstd", None)
    check_sibling_served(ctx, "zst_only.html", "br, gzip", None)


@test("pack_static skips an encoding the client refused with q=0", label="static")
def test_static_zero_weight(ctx: Context) -> None:
    """A zero weight takes that encoding out of the running without taking
    the request with it: the probe carries on to the next candidate."""
    check_sibling_served(ctx, "multi.html", "br;q=0, gzip, zstd", "gzip")
    check_sibling_served(ctx, "multi.html", "br;q=0, gzip;q=0, zstd", "zstd")
    check_sibling_served(ctx, "multi.html", "br;q=0, zstd;q=0, gzip;q=0", None)


@test("pack_static ignores encodings it does not know", label="static")
def test_static_unknown_encodings(ctx: Context) -> None:
    for accept in ["deflate", "compress", "identity", "*", "x-gzip", "brotli"]:
        check_sibling_served(ctx, "multi.html", accept, None)


@test(
    "every sibling is served byte for byte and cached by its own name", label="static"
)
def test_static_siblings_distinct(ctx: Context) -> None:
    """Each encoding names a different file, and the three differ in length,
    so this also covers the constructed path being hashed over the right
    length: open_file_cache is on for this location, and ".br" and ".zst"
    are not the same number of characters."""
    seen: dict[str, bytes] = {}
    for encoding in ("br", "zstd", "gzip"):
        # Twice, so the second answer comes from open_file_cache.
        for _ in range(2):
            check_sibling_served(ctx, "multi.html", encoding, encoding)
        seen[encoding] = ctx.fixtures["multi.html" + SIBLING_EXTS[encoding]]

    check(
        len(set(seen.values())) == len(seen),
        f"the three siblings are not distinct, so serving the wrong one "
        f"would not be visible: { {k: len(v) for k, v in seen.items()} }",
    )


@test("a sibling that cannot be served is stepped over, not fatal", label="static")
def test_static_odd_siblings(ctx: Context) -> None:
    """A sibling is an optimization, so anything wrong with one means only
    that it is not taken. gzip_static answers 404 for a file that is not
    regular, which is right where the odd file IS the resource asked for
    and wrong here, where it merely sits beside it: a stray fifo named
    "a.html.br" would take "a.html" down with it.

    Three shapes, each of which opens successfully or fails in its own
    way, and each of which must leave the plain file served."""
    cases = [
        ("odd_dir.html", "a directory"),
        ("odd_fifo.html", "a fifo"),
        ("odd_loop.html", "a symlink loop"),
    ]

    # Root reads a mode-000 file regardless, so the sibling would be
    # served and the case would prove nothing.
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        cases.append(("odd_perm.html", "unreadable"))

    for stem, shape in cases:
        if not os.path.lexists(os.path.join(ctx.nginx.work, "html", stem + ".br")):
            continue
        status, headers, body = fetch(ctx.port, f"/static/{stem}", "br")
        check(
            status == 200,
            f"{stem} ({shape} sibling): expected 200, got {status}",
        )
        check(
            headers.get("content-encoding") is None,
            f"{stem} ({shape} sibling): served it anyway as "
            f"{headers.get('content-encoding')!r}",
        )
        check(
            body == ctx.fixtures[stem],
            f"{stem} ({shape} sibling): body is not the plain file",
        )


@test("a subrequest is never served a sibling", label="static")
def test_static_subrequest_declined(ctx: Context) -> None:
    """An SSI include splices the child's body into the parent, so a
    sibling served there would put compressed bytes mid-page under a
    Content-Type that says text.

    The include target is a "pack_static always" location, which is the
    only setting a subrequest can reach the probe under: "on" goes
    through ngx_http_pack_claim_request, which turns a subrequest away
    before preflight's check would matter. Pointing this at an "on"
    location would pass whether or not that check exists."""
    status, headers, body = fetch(ctx.port, "/ssi/include.shtml", "br, gzip, zstd")
    check(status == 200, f"/ssi/include.shtml: expected 200, got {status}")

    want = b"BEGIN" + ctx.fixtures["multi.html"] + b"END"
    check(
        body == want,
        f"the include spliced {len(body)} bytes, not the plain file's "
        f"{len(want)} - a sibling reached the parent's body",
    )
    check(
        headers.get("content-encoding") is None,
        f"the parent carries Content-Encoding {headers.get('content-encoding')!r}",
    )


AMBIGUOUS_WARNING = "serves whatever is found first"


def ambiguity_warnings(ctx: Context, http_block: str) -> int:
    """Runs "nginx -t" over a configuration and counts the ambiguity
    warnings it produced. Everything else in the suite drives a running
    server; this is the only thing that reads what nginx says at
    configuration time, which is where merge_conf's warning lives."""
    path = os.path.join(ctx.nginx.work, "conf-test.conf")
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(
            "daemon off;\n"
            "error_log stderr notice;\n"
            "events { worker_connections 64; }\n" + http_block + "\n"
        )

    done = subprocess.run(
        [ctx.nginx.binary, "-p", ctx.nginx.work, "-c", path, "-t"],
        capture_output=True,
        text=True,
        check=False,
    )
    text = (done.stderr or "") + (done.stdout or "")
    check("syntax is ok" in text, f"configuration was refused:\n{text}")
    return text.count(AMBIGUOUS_WARNING)


# "pack_static always" skips the Accept-Encoding test, so with more than
# one encoding configured the client gets whichever sibling the probe
# reaches first. Each of these writes that combination once; the warning
# has to name it once, wherever in the block hierarchy it was written.
AMBIGUITY_CASES = [
    (
        "both directives at http{}",
        """http { pack_static always; pack_static_encodings br gzip;
             server { listen 127.0.0.1:8999; location /a/ { } } }""",
        1,
    ),
    (
        "both at server{}",
        """http { server { listen 127.0.0.1:8999;
             pack_static always; pack_static_encodings br gzip;
             location /a/ { } } }""",
        1,
    ),
    (
        "both at location{}",
        """http { server { listen 127.0.0.1:8999;
             location /a/ { pack_static always;
                            pack_static_encodings br gzip; } } }""",
        1,
    ),
    (
        # No list written, so the default of all three applies and the
        # combination only becomes ambiguous once the merge fills it in.
        "always at http{}, encodings defaulted",
        """http { pack_static always;
             server { listen 127.0.0.1:8999; location /a/ { } } }""",
        1,
    ),
    (
        # Six merges see the same ambiguous parent. Still one warning:
        # the setting was written once.
        "http{} inherited by four locations across two servers",
        """http { pack_static always; pack_static_encodings br gzip;
             server { listen 127.0.0.1:8999;
               location /a/ { } location /b/ { } location /c/ { } }
             server { listen 127.0.0.1:8998; location /d/ { } } }""",
        1,
    ),
    (
        "http{} and server{} both write it",
        """http { pack_static always; pack_static_encodings br gzip;
             server { listen 127.0.0.1:8999;
               pack_static always; pack_static_encodings br gzip;
               location /a/ { } } }""",
        1,
    ),
    (
        # Neither half of the pair is ambiguous on its own.
        "always with a single encoding",
        """http { pack_static always; pack_static_encodings br;
             server { listen 127.0.0.1:8999; location /a/ { } } }""",
        0,
    ),
    (
        "on with several encodings",
        """http { pack_static on; pack_static_encodings br gzip;
             server { listen 127.0.0.1:8999; location /a/ { } } }""",
        0,
    ),
    (
        "one ambiguous location beside a plain one",
        """http { server { listen 127.0.0.1:8999; pack_static on;
             location /a/ { pack_static always;
                            pack_static_encodings br gzip; }
             location /b/ { } } }""",
        1,
    ),
    (
        "a nested location narrows it to on",
        """http { pack_static always; pack_static_encodings br gzip;
             server { listen 127.0.0.1:8999;
               location /a/ { pack_static on;
                 location /a/n/ { } } } }""",
        1,
    ),
]


@test("the ambiguous combination is warned about exactly once", label="static")
def test_static_ambiguity_warned_once(ctx: Context) -> None:
    """merge_conf runs once per block, so an ambiguous setting written in
    an enclosing block is seen again by every block that inherits it. The
    warning has to land where the combination takes effect and stay quiet
    down the rest of the tree - and http{}, which nginx only ever passes
    as a parent and never as a child, has to be reported too."""
    for label, http_block, expected in AMBIGUITY_CASES:
        got = ambiguity_warnings(ctx, http_block)
        check(
            got == expected,
            f"{label}: expected {expected} warning(s), got {got}",
        )


@test("a block that re-creates the ambiguity is warned about again", label="static")
def test_static_ambiguity_recreated(ctx: Context) -> None:
    """Suppressing the repeat cannot be done by marking a block reported
    and trusting that mark further down: a location can turn the
    combination off and one nested inside it can write it again, which is
    a fresh decision by the admin and a second thing to say.

    The control below is the same shape with an http{} that was never
    ambiguous, so only the innermost block is - if both answer 1, the
    suppression is keying on the wrong thing."""
    recreated = """http { pack_static always; pack_static_encodings br gzip;
      server { listen 127.0.0.1:8999;
        location /a/ { pack_static on;
          location /a/n/ { pack_static always; } } } }"""
    control = """http { pack_static on; pack_static_encodings br gzip;
      server { listen 127.0.0.1:8999;
        location /a/ { pack_static on;
          location /a/n/ { pack_static always; } } } }"""

    got = ambiguity_warnings(ctx, recreated)
    check(got == 2, f"http{{}} and the nested location: expected 2, got {got}")

    got = ambiguity_warnings(ctx, control)
    check(got == 1, f"the nested location alone: expected 1, got {got}")


@test("pack_static_encodings cannot be written twice in one block", label="static")
def test_static_encodings_duplicate_directive(ctx: Context) -> None:
    """Written twice in the same block, the setter's own conf pointer sees
    the first call's count and refuses the second - the "is duplicate" nginx
    reports back is this module's own string, not core's."""
    accepted, text = config_accepted(
        ctx, "pack_static_encodings br;\n  pack_static_encodings gzip;"
    )
    check(not accepted, f"a directive repeated in one block was accepted:\n{text}")
    check(
        "is duplicate" in text,
        f"expected the duplicate-directive refusal, got:\n{text}",
    )


@test("pack_static_encodings refuses a name none of the three rows carry", label="static")
def test_static_encodings_unknown_value(ctx: Context) -> None:
    accepted, text = config_accepted(ctx, "pack_static_encodings bogus;")
    check(not accepted, f"an unknown encoding was accepted:\n{text}")
    check(
        'invalid value "bogus"' in text,
        f"expected the unknown-value refusal, got:\n{text}",
    )


@test(
    "pack_static_encodings warns about and skips a name repeated within "
    "one directive",
    label="static",
)
def test_static_encodings_duplicate_value(ctx: Context) -> None:
    """Unlike the same directive written twice, the same name written
    twice within one directive is only a warning: the second "br" is
    dropped and the first stands."""
    accepted, text = config_accepted(ctx, "pack_static_encodings br br;")
    check(accepted, f"a value repeated within one directive should only warn:\n{text}")
    check(
        'duplicate value "br"' in text,
        f"expected the duplicate-value warning, got:\n{text}",
    )


@test("pack_static falls through when there is no .zst sibling", label="static")
def test_static_module_without_sibling(ctx: Context) -> None:
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


def check_vary_dedupe(ctx: Context, case: str, expected: int) -> list[str]:
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
        f"/vary/{case}: expected {expected} Vary header(s), got {len(vary)}: {vary!r}",
    )
    return vary


@test("an upstream Vary: Accept-Encoding is not duplicated", only=ZSTD)
def test_vary_not_duplicated(ctx: Context) -> None:
    vary = check_vary_dedupe(ctx, "ae", 1)
    check(
        vary[0].lower() == "accept-encoding",
        f"the surviving Vary was {vary[0]!r}",
    )


@test("an upstream Vary is recognised whatever its case", only=ZSTD)
def test_vary_case_insensitive(ctx: Context) -> None:
    check_vary_dedupe(ctx, "mixed", 1)


@test("an unrelated Vary is kept and ours added beside it", only=ZSTD)
def test_vary_unrelated_kept(ctx: Context) -> None:
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


@test("a Vary one character short of ours is not treated as a match", only=ZSTD)
def test_vary_near_miss_short(ctx: Context) -> None:
    check_vary_dedupe(ctx, "short", 2)


@test("a Vary one character long is not treated as a match", only=ZSTD)
def test_vary_near_miss_long(ctx: Context) -> None:
    check_vary_dedupe(ctx, "long", 2)


@test("a same-shaped header that is not Vary does not suppress ours", only=ZSTD)
def test_vary_lookalike_header(ctx: Context) -> None:
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


@test("a response with no upstream Vary still gets exactly one", only=ZSTD)
def test_vary_added_when_absent(ctx: Context) -> None:
    check_vary_dedupe(ctx, "none", 1)


@test("real HTML round-trips", needs_decoder=True, needs_corpus=True, codecs=CODECS)
def test_corpus_html(ctx: Context, codec: Codec) -> None:
    check_corpus_roundtrip(ctx, "wiki.html", codec=codec)


@test("real CSS round-trips", needs_decoder=True, needs_corpus=True, codecs=CODECS)
def test_corpus_css(ctx: Context, codec: Codec) -> None:
    check_corpus_roundtrip(ctx, "site.css", codec=codec)


@test(
    "real JavaScript round-trips", needs_decoder=True, needs_corpus=True, codecs=CODECS
)
def test_corpus_js(ctx: Context, codec: Codec) -> None:
    check_corpus_roundtrip(ctx, "app.js", codec=codec)


@test(
    "real minified JavaScript round-trips",
    needs_decoder=True,
    needs_corpus=True,
    codecs=CODECS,
)
def test_corpus_min_js(ctx: Context, codec: Codec) -> None:
    check_corpus_roundtrip(ctx, "app.min.js", codec=codec)


@test("real prose round-trips", needs_decoder=True, needs_corpus=True, codecs=CODECS)
def test_corpus_prose(ctx: Context, codec: Codec) -> None:
    check_corpus_roundtrip(ctx, "prose.txt", codec=codec)


# Not text/*, so it is also what checks that a type reaches the filter
# through pack_*_types rather than through the always-compressed text/html
# the text fixtures lean on. feed.pb below covers the same ground in binary.
@test("real JSON round-trips", needs_decoder=True, needs_corpus=True, codecs=CODECS)
def test_corpus_json(ctx: Context, codec: Codec) -> None:
    check_corpus_roundtrip(ctx, "api.json", codec=codec)


# The only corpus file that is not text at all. Everything else here is
# characters, where a byte that decompressed wrongly would likely still
# decode; this is protobuf wire format, so the round-trip is checked
# against bytes that have no such slack.
@test("real protobuf round-trips", needs_decoder=True, needs_corpus=True, codecs=CODECS)
def test_corpus_protobuf(ctx: Context, codec: Codec) -> None:
    check_corpus_roundtrip(ctx, "feed.pb", codec=codec)


@test(
    "the whole corpus round-trips as streams of unknown length",
    needs_decoder=True,
    needs_corpus=True,
    only=ZSTD,
)
def test_corpus_streamed(ctx: Context) -> None:
    # The static path above sizes the window from a known Content-Length and
    # feeds the encoder whole buffers. Unknown-length responses take neither
    # route, so real content has to cross that path too.
    for name in CORPUS_FILES:
        check_corpus_roundtrip(ctx, name, path=f"/stream/{name}")


@test(
    "streamed response of unknown length round-trips", needs_decoder=True, codecs=CODECS
)
def test_stream_roundtrip(ctx: Context, codec: Codec) -> None:
    path = codec.path("stream", "big.html")
    status, headers, body = fetch(ctx.port, path, codec.token)
    check(status == 200, f"expected 200, got {status}")
    check(
        headers.get("content-encoding") == codec.token,
        f"expected Content-Encoding: {codec.token}, got "
        f"{headers.get('content-encoding')!r}",
    )
    check(
        "content-length" not in headers,
        "a streamed response should not carry a Content-Length",
    )
    decode = must_decode(codec)
    check(
        decode(body) == ctx.fixtures["big.html"],
        "decoded stream differs from the original",
    )


@test("small-but-eligible response round-trips", needs_decoder=True, codecs=CODECS)
def test_small_roundtrip(ctx: Context, codec: Codec) -> None:
    _, headers, body = fetch(ctx.port, codec.file("small.html"), codec.token)
    check(
        headers.get("content-encoding") == codec.token,
        "small.html was not compressed",
    )
    decode = must_decode(codec)
    check(
        decode(body) == ctx.fixtures["small.html"],
        "decoded small.html differs from the original",
    )


@test("a response below the min_length default is left alone", codecs=CODECS)
def test_min_length(ctx: Context, codec: Codec) -> None:
    _, headers, body = fetch(ctx.port, codec.file("tiny.html"), codec.token)
    check(
        "content-encoding" not in headers,
        f"tiny.html should not be compressed, got Content-Encoding: "
        f"{headers.get('content-encoding')}",
    )
    check(body == ctx.fixtures["tiny.html"], "tiny.html body was altered")


@test("the min_length default leaves a 200 byte response alone", codecs=CODECS)
def test_min_length_default_lower(ctx: Context, codec: Codec) -> None:
    """Guards the compiled-in default, which the test config deliberately does
    not override. A response this small costs more to compress than it saves."""
    body_len = len(ctx.fixtures["under_min.html"])
    _, headers, body = fetch(ctx.port, codec.file("under_min.html"), codec.token)
    check(
        "content-encoding" not in headers,
        f"a {body_len} byte response was compressed; "
        f"{codec.directive}_min_length has dropped below it",
    )
    check(body == ctx.fixtures["under_min.html"], "under_min.html was altered")


@test(
    "default pack_zstd_min_length still compresses a 400 byte response",
    needs_decoder=True,
    only=ZSTD,
)
def test_min_length_default_upper(ctx: Context) -> None:
    body_len = len(ctx.fixtures["over_min.html"])
    _, headers, body = fetch(ctx.port, "/over_min.html")
    check(
        headers.get("content-encoding") == "zstd",
        f"a {body_len} byte response was not compressed; pack_zstd_min_length has "
        f"risen above it",
    )
    decode = must_decode(ctx)
    check(
        decode(body) == ctx.fixtures["over_min.html"],
        "decoded over_min.html differs from the original",
    )


@test(
    "a slowly-produced response starts arriving before it finishes",
    codecs=CODECS,
)
def test_ttfb_on_buffered_stream(ctx: Context, codec: Codec) -> None:
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
            (
                f"GET {codec.path('dribble', '')} HTTP/1.1\r\n"
                f"Host: localhost\r\nConnection: close\r\n"
                f"Accept-Encoding: {codec.token}\r\n\r\n"
            ).encode()
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

    if first_body is None:
        raise Failure("no body ever arrived")
    ttfb = first_body - started
    elapsed = finished - started
    check(
        ttfb < elapsed * 0.4,
        f"first byte took {ttfb * 1000:.0f} ms of {elapsed * 1000:.0f} ms "
        f"total ({100 * ttfb / elapsed:.0f}%); the encoder is sitting on the "
        f"response instead of flushing when asked for progress",
    )


@test("min_length applies to a buffered stream of unknown length", codecs=CODECS)
def test_min_length_on_stream(ctx: Context, codec: Codec) -> None:
    """The header filter cannot compare against min_length when it has no
    Content-Length, so it holds the headers until the body has answered
    the question. Without that, a tiny chunked response still builds a
    full encoder.

    Buffered specifically: see the unbuffered case below, where the answer
    is the opposite. Each filter carries its own copy of this deferral,
    and committing headers is a decision neither can take back.
    """
    _, headers, body = fetch(
        ctx.port, codec.path("buffered", "under_min.html"), codec.token
    )
    check(
        "content-encoding" not in headers,
        f"a {len(ctx.fixtures['under_min.html'])} byte streamed response was "
        f"compressed; {codec.directive}_min_length is not being applied "
        f"without a Content-Length",
    )
    check(
        body == ctx.fixtures["under_min.html"],
        "the uncompressed streamed body was altered",
    )


@test("min_length is bypassed when a buffer asks to be flushed", codecs=CODECS)
def test_min_length_not_applied_when_urgent(ctx: Context, codec: Codec) -> None:
    """The same body as the buffered case above, and the opposite outcome.

    With proxy_buffering off every buffer carries a flush marker, which
    the filter reads as "something downstream is waiting": it decides
    immediately rather than holding the headers, and deciding immediately
    means compressing. So min_length does not hold for an unbuffered
    proxied response.

    Deliberate, but the kind of thing a configuration is written against,
    so it is asserted rather than left to be discovered. Change this only
    alongside the "urgent" branch in either filter's prepare.
    """
    body = ctx.fixtures["under_min.html"]
    check(
        len(body) < 256,
        f"fixture is {len(body)} bytes, which no longer sits under the "
        f"compiled-in {codec.directive}_min_length of 256 this test "
        f"depends on",
    )
    _, headers, _ = fetch(ctx.port, codec.path("stream", "under_min.html"), codec.token)
    check(
        headers.get("content-encoding") == codec.token,
        f"a {len(body)} byte unbuffered response was not compressed; the "
        f"flush marker should have short-circuited "
        f"{codec.directive}_min_length",
    )


@test(
    "a streamed response over min_length is still compressed",
    needs_decoder=True,
    codecs=CODECS,
)
def test_min_length_on_stream_upper(ctx: Context, codec: Codec) -> None:
    """The counterweight to the two above: the deferral has to release the
    response as well as hold it back."""
    _, headers, body = fetch(
        ctx.port, codec.path("buffered", "over_min.html"), codec.token
    )
    check(
        headers.get("content-encoding") == codec.token,
        f"a {len(ctx.fixtures['over_min.html'])} byte streamed response should "
        f"be compressed, got {headers.get('content-encoding')!r}",
    )
    decode = must_decode(codec)
    check(
        decode(body) == ctx.fixtures["over_min.html"],
        "decoded streamed body differs from the original",
    )


@test("bodyless and ranged statuses are not given a Content-Encoding", codecs=CODECS)
def test_status_guard(ctx: Context, codec: Codec) -> None:
    """204 and 304 have no body to encode, and a 206 body is a byte range whose
    Content-Range still describes the uncompressed entity. Labelling any of
    them corrupts the response."""
    for code in (204, 304, 206):
        status, headers, _ = fetch(
            ctx.port, codec.path("status", str(code)), codec.token
        )
        check(status == code, f"expected {code} to reach the client, got {status}")
        check(
            "content-encoding" not in headers,
            f"a {code} response was labelled "
            f"{headers.get('content-encoding')!r}; it must not be compressed",
        )


@test("other statuses are still compressed", needs_decoder=True, codecs=CODECS)
def test_status_guard_not_too_broad(ctx: Context, codec: Codec) -> None:
    """The guard replaced an allow list that also excluded these. They are
    ordinary compressible responses and must stay compressed."""
    for code in (200, 201, 403, 404, 422, 500):
        status, headers, body = fetch(
            ctx.port, codec.path("status", str(code)), codec.token
        )
        check(status == code, f"expected {code} to reach the client, got {status}")
        check(
            headers.get("content-encoding") == codec.token,
            f"a {code} response should still be compressed, got "
            f"{headers.get('content-encoding')!r}",
        )
        decode = must_decode(codec)
        check(
            decode(body) == STATUS_BODY,
            f"the {code} body did not decode back to the original",
        )


@test(
    "an upstream response already carrying Content-Encoding is left alone",
    codecs=CODECS,
)
def test_content_encoding_guard(ctx: Context, codec: Codec) -> None:
    """An origin that compressed its own response, or merely claims to
    have, must not be compressed again: the client would be handed a
    body claiming one encoding while actually carrying two.

    A nonsense value proves the point more sharply than a real codec
    name would: this module has to trust the header at face value
    rather than checking whether it recognises what is in it."""
    _, headers, body = fetch(ctx.port, "/enc/identity", codec.token)
    check(
        headers.get("content-encoding") == "identity",
        f"expected the upstream's own Content-Encoding to survive, got "
        f"{headers.get('content-encoding')!r}",
    )
    check(
        body == Upstream.TRANSFORM_BODY,
        "the body was altered although Content-Encoding was already set",
    )


@test(
    "an empty Content-Encoding value does not count as already encoded",
    needs_decoder=True,
    codecs=CODECS,
)
def test_empty_content_encoding_not_guarded(ctx: Context, codec: Codec) -> None:
    """The guard above checks value.len as well as the header's presence:
    an origin that sent "Content-Encoding:" with nothing after it is not
    claiming an encoding, so the response is still ours to compress."""
    _, headers, body = fetch(ctx.port, "/enc/", codec.token)
    check(
        headers.get("content-encoding") == codec.token,
        f"expected the response to still be compressed, got "
        f"{headers.get('content-encoding')!r}",
    )
    decode = must_decode(codec)
    check(
        decode(body) == Upstream.TRANSFORM_BODY,
        "the decoded body does not match the upstream's",
    )


@test("a MIME type outside the types directive is left alone", codecs=CODECS)
def test_mime_filtering(ctx: Context, codec: Codec) -> None:
    _, headers, body = fetch(ctx.port, codec.file("data.bin"), codec.token)
    check(
        "content-encoding" not in headers,
        f"data.bin is not in {codec.directive}_types but was compressed",
    )
    check(body == ctx.fixtures["data.bin"], "data.bin body was altered")


@test("client without Accept-Encoding gets plain bytes", codecs=CODECS)
def test_no_accept_encoding(ctx: Context, codec: Codec) -> None:
    _, headers, body = fetch(ctx.port, codec.file("big.html"), accept_encoding=None)
    check(
        "content-encoding" not in headers,
        "compressed for a client that did not ask for it",
    )
    check(body == ctx.fixtures["big.html"], "uncompressed body was altered")


@test("a zero weight on the token is honoured", codecs=CODECS)
def test_q_zero(ctx: Context, codec: Codec) -> None:
    tok = codec.token
    for value in [
        f"{tok};q=0",
        f"{tok};q=0.",
        f"{tok};q=0.0",
        f"{tok};q=0.00",
        f"{tok};q=0.000",
        f"{tok} ; q = 0.00",
        f"{tok}\t;\tq\t=\t0",
        f"gzip, {tok};q=0",
    ]:
        _, headers, _ = fetch(ctx.port, codec.file("big.html"), accept_encoding=value)
        check(
            "content-encoding" not in headers,
            f"{value!r} should decline {tok}, but the response was compressed",
        )


@test("tokens that merely contain the token do not select it", codecs=CODECS)
def test_partial_token(ctx: Context, codec: Codec) -> None:
    """The near misses are built from the token, except the superstrings,
    which cannot be derived - see Codec. "brotli" is the one that matters:
    it is a word a client may really send, and "br" is a prefix of it."""
    tok = codec.token
    values = [f"{tok}x", f"x-{tok}", f"{tok}-x", "bar", "b", "gzip, deflate"]
    values.extend(codec.superstrings)
    for value in values:
        _, headers, _ = fetch(ctx.port, codec.file("big.html"), accept_encoding=value)
        check(
            "content-encoding" not in headers,
            f"{value!r} should not select {tok}, but the response was compressed",
        )


@test(
    "Accept-Encoding lists that do select the token", needs_decoder=True, codecs=CODECS
)
def test_encoding_lists(ctx: Context, codec: Codec) -> None:
    tok = codec.token
    for value in [
        tok,
        f"gzip, {tok}",
        f"gzip, {tok}, deflate",
        f"gzip, {tok};q=1, deflate",
        f"{tok};q=0.001",
        f"identity, {tok}",
        # Relative weights are ignored: naming the token at all is enough,
        # even when something else is weighted higher.
        f"gzip;q=1.0, {tok};q=0.1",
        f"gzip;q=0.9, {tok};q=0.2, deflate",
        # Tab is valid optional whitespace around a list separator.
        f"{tok}\t,gzip",
        f"gzip,\t{tok}",
        f"gzip, {tok} ",
        # Token matching is case-insensitive.
        tok.upper(),
        tok.capitalize(),
    ]:
        _, headers, body = fetch(
            ctx.port, codec.file("small.html"), accept_encoding=value
        )
        check(
            headers.get("content-encoding") == tok,
            f"{value!r} should select {tok}, got {headers.get('content-encoding')!r}",
        )
        decode = must_decode(codec)
        check(
            decode(body) == ctx.fixtures["small.html"],
            f"{value!r} produced a body that does not decode to the original",
        )


# What /all/ answers with, for a client that takes some combination of
# the three. The single-token rows are not ordering cases: they are what
# proves each filter is switched on at that location, without which
# every row above them would pass just as well against a server that
# had never heard of the codec it claims to have passed over.
PRECEDENCE_CASES = [
    ("gzip, br, zstd", "zstd"),
    ("zstd, br, gzip", "zstd"),
    ("gzip, zstd", "zstd"),
    ("gzip, br", "br"),
    ("br, gzip", "br"),
    # Weights are read only for an explicit zero, so preferring one
    # loudly does not move it up the chain.
    ("gzip;q=1.0, br;q=0.9, zstd;q=0.1", "zstd"),
    ("zstd;q=0, gzip, br", "br"),
    ("zstd;q=0, br;q=0, gzip", "gzip"),
    ("zstd", "zstd"),
    ("br", "br"),
    ("gzip", "gzip"),
]


# Against /always/ rather than /all/: pack_brotli is "always" there,
# not "on", so Brotli claims every one of these - None sends no
# Accept-Encoding header at all, and the last two rows name "br" with
# an explicit zero weight, which "always" does not read as a refusal
# either. zstd is unchanged, so it still wins whenever a client
# actually names it, ahead of Brotli in the chain the same way /all/
# is - the only thing that still keeps a request from getting Brotli
# here.
ALWAYS_PRECEDENCE_CASES = [
    (None, "br"),
    ("gzip", "br"),
    ("zstd", "zstd"),
    ("gzip, zstd", "zstd"),
    ("zstd;q=0", "br"),
    ("zstd;q=0, gzip", "br"),
    ("br;q=0", "br"),
    ("zstd;q=0, br;q=0", "br"),
]


# What the upstream sends as Cache-Control, and whether the response
# may then be compressed. "+" becomes ", " on the way out.
NO_TRANSFORM_CASES = [
    ("plain", True),
    ("max-age=60", True),
    ("no-transform", False),
    ("public+no-transform", False),
    ("no-transform+max-age=60", False),
    # A token that merely starts the same way is a different directive.
    ("no-transform-x", True),
    ("NO-TRANSFORM", False),
]


# proxy_buffer_size values the suite names rather than inherits.
# nginx derives the default from the page size, so an inherited one is
# 4k on Linux and 16k on Apple Silicon.
DELIVERY_SIZES = ("1k", "4k", "16k")


@test(
    "delivery in pieces of any size gives the same bytes",
    needs_decoder=True,
    codecs=CODECS,
)
def test_delivery_shape(ctx: Context, codec: Codec) -> None:
    """How a proxied body is cut into buffers must not change what the
    client receives.

    It is not obvious that it would not. Brotli sizes its one-pass hash
    table from how much input a single call brings, so the same
    response costs a quarter of the memory when it arrives in small
    pieces; zstd folds flush markers, and every proxy buffer carries
    one. Both mean the encoder does measurably different work for the
    same body, and the framing it emits differs with it.

    What must not differ is the body. The suite would otherwise only
    ever see one shape per host, because proxy_buffer_size defaults to
    the page size: 4k on Linux, 16k on Apple Silicon. That difference
    is what made test_keepalive_allocation_balance pass here and fail
    on CI, and adding an arm64 runner does not cover it - Ubuntu on
    arm64 uses 4k pages too.
    """
    expected = ctx.fixtures["big.html"]
    decoded: dict[str, bytes] = {}

    for size in DELIVERY_SIZES:
        path = codec.path(f"bufsize-{size}", "big.html")
        _, headers, body = fetch(ctx.port, path, codec.token)

        check(
            headers.get("content-encoding") == codec.token,
            f"proxy_buffer_size {size} answered "
            f"{headers.get('content-encoding')!r}, so this compared nothing",
        )
        decode = must_decode(codec)
        decoded[size] = decode(body)
        check(
            decoded[size] == expected,
            f"proxy_buffer_size {size} produced {len(decoded[size])} bytes "
            f"that differ from the {len(expected)} sent",
        )

    # Stated separately from the per-size checks above: those could all
    # be wrong in the same way against a fixture that changed underfoot.
    check(
        len(set(decoded.values())) == 1,
        "the three delivery shapes decoded to different bodies: "
        + ", ".join(f"{s} {len(d)} bytes" for s, d in decoded.items()),
    )


@test("no-transform on the response is honoured", codecs=CODECS)
def test_no_transform(ctx: Context, codec: Codec) -> None:
    """RFC 9111 section 5.2.2.6: an origin sending "no-transform" is
    saying its payload must reach the client as it left, and
    compressing it is exactly the transformation that forbids.

    nginx's own gzip filter does not look at this, so this is a
    deliberate departure rather than parity.

    The accepting rows are not decoration. Without them a gate that
    declined every response carrying any Cache-Control at all would
    pass, and so would one that matched "no-transform" as a substring
    of a longer directive.
    """
    for directives, want_compressed in NO_TRANSFORM_CASES:
        _, headers, _ = fetch(ctx.port, f"/cc/{directives}", codec.token)
        got = headers.get("content-encoding")
        check(
            (got == codec.token) == want_compressed,
            f"Cache-Control: {directives.replace('+', ', ')!r} was answered "
            f"with {got!r}; expected "
            f"{'compression' if want_compressed else 'none'}",
        )


@test("a proxied request is declined unless proxied is any", codecs=CODECS)
def test_proxied_gate(ctx: Context, codec: Codec) -> None:
    """A "Via" header means another proxy already handled this request.

    gzip_proxied defaults to off and declines those, so an operator
    moving from gzip would otherwise find responses being compressed
    that were previously passed through - a change nobody asked for,
    and one that shows up as cache behaviour rather than an error.

    Only off and any are offered. gzip's other settings key off
    response headers - expired, no-cache, no-store, private, auth - and
    "any" is what most configurations that care reach for anyway.

    Sent as a plain request too, since a rule that declined everything
    would satisfy the first assertion on its own.
    """
    via = {"Via": "1.1 upstream-cache"}

    _, headers, _ = fetch(
        ctx.port, "/proxied-default/small.html", codec.token, headers=via
    )
    check(
        "content-encoding" not in headers,
        f"a request carrying Via was compressed with "
        f"{headers.get('content-encoding')!r} at the default setting",
    )

    # Same location, no Via: proves the decline above is the header's
    # doing and not the location refusing everything.
    _, headers, _ = fetch(ctx.port, "/proxied-default/small.html", codec.token)
    check(
        headers.get("content-encoding") == codec.token,
        f"the same location without Via answered "
        f"{headers.get('content-encoding')!r}, so the test above proves "
        f"nothing about Via",
    )

    _, headers, _ = fetch(ctx.port, "/proxied-any/small.html", codec.token, headers=via)
    check(
        headers.get("content-encoding") == codec.token,
        f"{codec.directive}_proxied any still declined a request "
        f"carrying Via, answering {headers.get('content-encoding')!r}",
    )


@test("zstd, then br, then gzip claims a response", label="all")
def test_codec_precedence(ctx: Context) -> None:
    """Which filter takes a response several would accept is settled by
    chain order, not by the client and not by configuration.

    Each filter prepends itself to the header chain, so whichever
    registers last runs first. In objs/ngx_modules.c that is gzip, then
    Brotli, then zstd - so the chain runs them in reverse, zstd first.
    The one that runs first labels the response and the rest see a
    Content-Encoding already set and pass through.

    Nothing states that preference. For our two it falls out of the
    order the root config walks the subdirectories, and gzip is below
    both only because nginx registers its own filters before any addon.
    Reordering either would flip the answer silently.

    The client has no say: weights are read only for an explicit zero,
    which is why the q=0 rows move down the chain and the q=1.0 row
    does not move up.
    """
    for accept, expected in PRECEDENCE_CASES:
        _, headers, _ = fetch(ctx.port, "/all/small.html", accept)
        check(
            headers.get("content-encoding") == expected,
            f"Accept-Encoding: {accept!r} was answered with "
            f"{headers.get('content-encoding')!r}, not {expected!r}; "
            f"the filters have changed places in the chain, or one of "
            f"them is not enabled at /all/",
        )


@test("pack_brotli always yields only to zstd, never to the client", label="all")
def test_brotli_always_precedence(ctx: Context) -> None:
    """/always/ carries the same "pack_zstd on" as /all/ but "pack_brotli
    always" in place of "pack_brotli on": zstd still runs first in the
    chain and still only claims a response a client actually asked
    for, but Brotli's own turn no longer reads Accept-Encoding at all -
    not even to see whether "br" was refused outright.

    So a client is served zstd if it named zstd, Brotli otherwise -
    whether or not it ever mentioned Brotli, whether or not it named
    gzip instead (also on at this location, and would otherwise have
    taken an unclaimed response), and even if it named "br" with an
    explicit zero weight. The only thing that still keeps a request
    from getting Brotli here is zstd claiming it first.
    """
    for accept, expected in ALWAYS_PRECEDENCE_CASES:
        _, headers, _ = fetch(ctx.port, "/always/small.html", accept)
        check(
            headers.get("content-encoding") == expected,
            f"Accept-Encoding: {accept!r} was answered with "
            f"{headers.get('content-encoding')!r}, not {expected!r}",
        )


# No header at all, an empty one, tokens naming only other encodings,
# a bare wildcard (check_encoding reads Accept-Encoding for the
# literal substring "br", so "*" is never a match for it either), a
# token list weighted toward other encodings, and - the case that
# actually distinguishes "always" from merely tolerating silence -
# "br" named with an explicit zero weight. Every one of these still
# gets Brotli.
BROTLI_ALWAYS_IGNORES = [
    None,
    "",
    "identity",
    "deflate",
    "gzip, deflate",
    "*",
    "unknown-token-xyz",
    "gzip;q=1.0, deflate;q=0.5",
    "br;q=0",
    "zstd;q=0.9, br;q=0",
]


@test("pack_brotli always ignores Accept-Encoding entirely", label="all")
def test_brotli_always_ignores_accept_encoding(ctx: Context) -> None:
    """/brotli-always/ turns pack_zstd off and leaves gzip at its
    default off, so Brotli's own "always" claim is the only thing
    that can put a Content-Encoding on this response - proving the
    directive on its own terms, not mixed with the codec-precedence
    question test_brotli_always_precedence answers at /always/.

    Every case in BROTLI_ALWAYS_IGNORES gets Brotli, including an
    outright "br;q=0": "always" was asked to mean Brotli unconditionally,
    not merely Brotli when the client stays quiet about it, so an
    explicit refusal carries no more weight than silence does.
    """
    for accept in BROTLI_ALWAYS_IGNORES:
        _, headers, _ = fetch(ctx.port, "/brotli-always/small.html", accept)
        check(
            headers.get("content-encoding") == "br",
            f"Accept-Encoding: {accept!r} was answered with "
            f"{headers.get('content-encoding')!r}, not 'br'",
        )


# zstd's mirror of BROTLI_ALWAYS_IGNORES: the same shape of cases, the
# token swapped for "zstd" throughout.
ZSTD_ALWAYS_IGNORES = [
    None,
    "",
    "identity",
    "deflate",
    "gzip, deflate",
    "*",
    "unknown-token-xyz",
    "gzip;q=1.0, deflate;q=0.5",
    "zstd;q=0",
    "br;q=0.9, zstd;q=0",
]


@test("pack_zstd always ignores Accept-Encoding entirely", label="all")
def test_zstd_always_ignores_accept_encoding(ctx: Context) -> None:
    """zstd's mirror of test_brotli_always_ignores_accept_encoding:
    /zstd-always/ turns pack_brotli off, so zstd's own "always" claim
    is the only thing that can put a Content-Encoding on this
    response.

    Every case in ZSTD_ALWAYS_IGNORES gets zstd, including an
    outright "zstd;q=0" - the same unconditional floor Brotli's
    "always" gives, not merely zstd when the client stays quiet about
    it.
    """
    for accept in ZSTD_ALWAYS_IGNORES:
        _, headers, _ = fetch(ctx.port, "/zstd-always/small.html", accept)
        check(
            headers.get("content-encoding") == "zstd",
            f"Accept-Encoding: {accept!r} was answered with "
            f"{headers.get('content-encoding')!r}, not 'zstd'",
        )


# Every one of these still answers "zstd", including a client that
# asked only for "br" and one that explicitly refused zstd outright -
# see test_zstd_always_shadows_brotli for why.
ZSTD_ALWAYS_SHADOWS_BROTLI_CASES = [
    None,
    "br",
    "gzip, br",
    "br;q=1.0",
    "zstd;q=0",
    "zstd;q=0, br",
]


@test("pack_zstd always claims a response before Brotli ever sees it", label="all")
def test_zstd_always_shadows_brotli(ctx: Context) -> None:
    """/zstd-always-brotli-on/ carries "pack_brotli on" and "pack_zstd
    always" - the roles /always/ tests are reversed, not just zstd
    swapped for Brotli.

    /always/ works because zstd runs first in the chain: a client that
    named zstd gets zstd, and Brotli's "always" only ever gets a turn
    once zstd has already declined. Put "always" on zstd instead and
    that ordering stops being incidental and starts being decisive -
    zstd claims every eligible response before Brotli's header filter
    is even reached, so a client that asked only for "br" and never
    mentioned zstd still gets zstd, not the encoding it actually
    asked for. Brotli being "on" rather than "off" here is the point:
    it is enabled and would gladly serve that client, and its own
    accept check is simply never reached to find that out.
    """
    for accept in ZSTD_ALWAYS_SHADOWS_BROTLI_CASES:
        _, headers, _ = fetch(
            ctx.port, "/zstd-always-brotli-on/small.html", accept
        )
        check(
            headers.get("content-encoding") == "zstd",
            f"Accept-Encoding: {accept!r} was answered with "
            f"{headers.get('content-encoding')!r}, not 'zstd'",
        )


@test("pack_zstd always and pack_brotli always refuse to coexist", label="all")
def test_both_always_refused(ctx: Context) -> None:
    """Only one of the two can actually be the unconditional default a
    request always gets - zstd, since it runs first in the chain - so
    both directives set to "always" for the same scope is a config
    mistake nginx should refuse outright rather than silently letting
    the chain order settle it.

    Checked both directly in a server{} block, where the name nginx
    itself would report is empty, and nested under a location{},
    where it names that location - see
    ngx_http_pack_zstd_filter.c's merge_conf for where this actually
    happens and why it has to be zstd's merge_conf and not Brotli's.
    """
    accepted, text = config_accepted(
        ctx, "pack_zstd always;\n  pack_brotli always;"
    )
    check(
        not accepted,
        f"both filters set to \"always\" in the same block was accepted:\n{text}",
    )
    check(
        "cannot both apply here" in text,
        f"expected the server-block wording, got:\n{text}",
    )

    accepted, text = config_accepted(
        ctx,
        "location /both/ { pack_zstd always; pack_brotli always; }",
    )
    check(
        not accepted,
        f"both filters set to \"always\" in one location was accepted:\n{text}",
    )
    check(
        'cannot both apply to location "/both/"' in text,
        f"expected the named-location wording, got:\n{text}",
    )

    # The two directives not agreeing is not an error: only one codec
    # can be "always" at once, and this module's own precedence
    # already settles which one wins whenever both are merely "on".
    accepted, text = config_accepted(
        ctx, "pack_zstd always;\n  pack_brotli on;"
    )
    check(accepted, f"zstd always with brotli on was refused:\n{text}")

    accepted, text = config_accepted(
        ctx, "pack_brotli always;\n  pack_zstd on;"
    )
    check(accepted, f"brotli always with zstd on was refused:\n{text}")


@test(
    "a response is compressed correctly over HTTP/2 too",
    needs_decoder=True,
    needs_curl=True,
    codecs=CODECS,
)
def test_http2_smoke(ctx: Context, codec: Codec) -> None:
    """Every other check here goes through http.client, which cannot
    speak HTTP/2 - so nothing in the suite has ever run a request
    through the --with-http_v2_module path every build compiles in.
    Accept-Encoding parsing and filter registration are protocol-
    agnostic code already exercised in depth over HTTP/1.1 above; this
    is only the proof that the same code runs at all when nginx is
    talking HTTP/2, via curl since nothing already in use here can.
    """
    fd, out = tempfile.mkstemp(prefix="ngx-zstd-h2-")
    os.close(fd)
    try:
        done = subprocess.run(
            [
                "curl",
                "--http2-prior-knowledge",
                "-s",
                "-D",
                "-",
                "-o",
                out,
                "-H",
                f"Accept-Encoding: {codec.token}",
                f"http://127.0.0.1:{ctx.port}/all/small.html",
            ],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        check(
            done.returncode == 0,
            f"curl failed (exit {done.returncode}): {done.stderr}",
        )
        header_text = done.stdout.lower()
        check(
            "http/2 200" in header_text,
            f"expected an HTTP/2 200 status line, got:\n{done.stdout}",
        )
        check(
            f"content-encoding: {codec.token}" in header_text,
            f"expected content-encoding: {codec.token}, got:\n{done.stdout}",
        )
        with open(out, "rb") as handle:
            body = handle.read()
        decode = must_decode(codec)
        check(
            decode(body) == ctx.fixtures["small.html"],
            "the HTTP/2 response body did not decode back to the original",
        )
    finally:
        os.remove(out)


@test("HTTP/1.0 clients are not served a compressed body", codecs=CODECS)
def test_http_version_gate(ctx: Context, codec: Codec) -> None:
    """Mirrors gzip_http_version, whose default is 1.1. Declining still leaves
    Vary advertised, as the gzip filter does, so a cache in front keeps the
    responses apart."""

    def raw(version: str) -> tuple[bool, bool]:
        sock = socket.create_connection(("127.0.0.1", ctx.port), timeout=30)
        try:
            sock.sendall(
                f"GET {codec.file('big.html')} HTTP/{version}\r\n"
                f"Host: localhost\r\n"
                f"Accept-Encoding: {codec.token}\r\n"
                f"Connection: close\r\n\r\n".encode()
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
            any(line.startswith(f"content-encoding: {codec.token}") for line in lower),
            any(line.startswith("vary:") for line in lower),
        )

    compressed, vary = raw("1.0")
    check(
        not compressed,
        f"an HTTP/1.0 request was served {codec.token}",
    )
    check(vary, "Vary was dropped for the declined HTTP/1.0 request")

    compressed, _ = raw("1.1")
    check(
        compressed,
        f"an HTTP/1.1 request was not served {codec.token}",
    )


@test("Vary: Accept-Encoding is advertised to every client", codecs=CODECS)
def test_vary(ctx: Context, codec: Codec) -> None:
    for accept in [codec.token, "gzip", None]:
        _, headers, _ = fetch(ctx.port, codec.file("big.html"), accept_encoding=accept)
        vary = headers.get("vary", "")
        check(
            "accept-encoding" in vary.lower(),
            f"Vary: Accept-Encoding missing for Accept-Encoding={accept!r} "
            f"(got {vary!r})",
        )


@test("HEAD request produces headers and no body", codecs=CODECS)
def test_head(ctx: Context, codec: Codec) -> None:
    status, _, body = fetch(
        ctx.port, codec.file("big.html"), codec.token, method="HEAD"
    )
    check(status == 200, f"expected 200, got {status}")
    check(body == b"", f"HEAD returned a {len(body)} byte body")


# ---------------------------------------------------------------------------
# Directive bounds
# ---------------------------------------------------------------------------


def config_accepted(ctx: Context, directive: str) -> tuple[bool, str]:
    """Whether "nginx -t" takes a configuration carrying one directive,
    and what it said about it.

    ambiguity_warnings insists the configuration was accepted, because
    what it measures is a warning. These directives are checked for the
    opposite: refusing a value is the whole behaviour, and a refusal has
    to be a startup error rather than a silent clamp, or an operator who
    mistyped a window gets a server that runs with something they did
    not ask for."""
    path = os.path.join(ctx.nginx.work, "conf-bounds.conf")
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(
            "daemon off;\n"
            "error_log stderr notice;\n"
            "events { worker_connections 64; }\n"
            "http { server { listen 127.0.0.1:8999;\n"
            f"  {directive}\n"
            "  location /a/ { } } }\n"
        )

    done = subprocess.run(
        [ctx.nginx.binary, "-p", ctx.nginx.work, "-c", path, "-t"],
        capture_output=True,
        text=True,
        check=False,
    )
    text = (done.stderr or "") + (done.stdout or "")
    return done.returncode == 0 and "syntax is ok" in text, text


# Every window the directive takes, and the sizes on either side of the
# range. The accepted list is exhaustive rather than a sample: the
# parser walks a loop from WINDOW_BITS_MIN to WINDOW_BITS_MAX comparing
# against 1 << bits, so an off-by-one at either end is exactly the
# mistake it can make.
def window_sizes(ctx: Context, codec: Codec = ZSTD) -> list[str]:
    """The window sizes this nginx accepts, read out of its own refusal.

    The refusal is generated from NGX_HTTP_PACK_ZSTD_WINDOW_BITS_MIN/MAX, so
    reading it back is what keeps this test from having to be edited every
    time a bound moves - and comparing it against what is actually accepted
    below is what would catch the list and the parser disagreeing.
    """
    _, text = config_accepted(ctx, f"{codec.directive}_window 1500;")
    listed = re.search(r"must be (.+?) in ", text)
    check(listed is not None, f"no size list in the refusal:\n{text}")

    assert listed is not None
    sizes = [
        size.strip() for size in listed.group(1).replace(", or ", ", ").split(", ")
    ]
    check(len(sizes) > 1, f"only one size listed:\n{text}")
    return sizes


@test(
    "the window directive takes every power of two it lists, and no more", codecs=CODECS
)
def test_window_bounds(ctx: Context, codec: Codec) -> None:
    """The directive has a parser of its own rather than
    ngx_conf_num_bounds_t, so nothing checks it but this. Both ends matter:
    the floor and the ceiling are what keep a window from costing more
    memory per request in flight than this module is willing to spend."""
    sizes = window_sizes(ctx, codec)
    accepted = [parse_size(size) for size in sizes]

    cases = [(size, True) for size in sizes]
    cases += [(str(value), True) for value in accepted]
    cases += [
        (str(min(accepted) // 2), False),  # one bit below the floor
        (str(max(accepted) * 2), False),  # one bit above the ceiling
        ("128m", False),  # far past the ceiling
        ("1500", False),  # in range, but not a power of two
        ("0", False),
    ]

    for size, want in cases:
        got, text = config_accepted(ctx, f"{codec.directive}_window {size};")
        check(
            got == want,
            f"{codec.directive}_window {size}: expected "
            f"{'accepted' if want else 'refused'}, got the opposite"
            f"{'' if want else chr(10) + text}",
        )


@test(
    "the window directive names the sizes it takes when it refuses one", codecs=CODECS
)
def test_window_message(ctx: Context, codec: Codec) -> None:
    """The refusal is all the operator gets, so it has to list the values
    rather than say the size was wrong. Every one it names has to be a
    power of two, in ascending order, and none may be past the ceiling."""
    sizes = window_sizes(ctx, codec)
    values = [parse_size(size) for size in sizes]

    for size, value in zip(sizes, values):
        check(
            value and (value & (value - 1)) == 0,
            f"the refusal offers {size}, which is not a power of two:\n{sizes}",
        )
    check(
        values == sorted(values),
        f"the refusal lists its sizes out of order: {sizes}",
    )
    check(
        parse_size("128m") not in values,
        f"the refusal still offers 128m, which is no longer taken: {sizes}",
    )


# The two ranges differ at both ends, which is why the cases are read
# out of the binary rather than written down: zstd starts at 1 because
# it exposes none of libzstd's lower or negative levels, Brotli at 0
# because quality 0 is a real setting with a fast path of its own.
def level_bounds(ctx: Context, codec: Codec) -> tuple[int, int]:
    """(floor, ceiling) the level directive enforces, from its refusal."""
    _, text = config_accepted(ctx, f"{codec.directive}_level 99;")
    found = re.search(r"must be between (-?\d+) and (-?\d+)", text)
    check(found is not None, f"no level bounds in the refusal:\n{text}")
    assert found is not None
    return int(found.group(1)), int(found.group(2))


@test("the level directive is held to the range it reports", codecs=CODECS)
def test_level_bounds(ctx: Context, codec: Codec) -> None:
    """Both ends, and both sides of both ends. The ceiling is the half
    that had nothing checking it: pack_brotli_level's was moved to 5
    and no test would have noticed had it been wrong."""
    floor, ceiling = level_bounds(ctx, codec)

    cases = [
        (str(floor), True),
        (str(ceiling), True),
        (str((floor + ceiling) // 2), True),
        (str(floor - 1), False),
        (str(ceiling + 1), False),
        ("-1", floor <= -1),
        ("99", False),
    ]

    for level, want in cases:
        got, text = config_accepted(ctx, f"{codec.directive}_level {level};")
        check(
            got == want,
            f"{codec.directive}_level {level}: expected "
            f"{'accepted' if want else 'refused'}, got the opposite"
            f"{'' if want else chr(10) + text}",
        )


HINT_CASES = [
    ("none", True),  # the word: no hint at all
    ("16k", True),  # the floor itself
    ("1m", True),
    ("8k", False),  # under the floor
    ("0", False),  # a size of zero is not the word, and is held to the floor
    # Four characters, like "none", but not it - value->len == none.len is
    # true and the strncmp still has to fail this one rather than match.
    ("zero", False),
    # Above NGX_MAX_INT32_VALUE: ZSTD_CCtx_setParameter takes the hint as
    # a plain int, so anything wider is refused here rather than wrapped.
    ("3000000000", False),
]


@test('pack_zstd_hint takes a size at or above its floor, or "none"', only=ZSTD)
def test_hint_bounds(ctx: Context) -> None:
    """The word and the floor are separate rules, and the point is that
    they stay separate.

    "none" means no hint rather than a small one, so it deliberately
    does not pass through the floor - while "0", which is a size and not
    the word, still does. Those two lines are one "else" apart in
    ngx_http_pack_zstd_set_hint, and swapping them would be invisible
    without this: a "none" clamped up to 16k and a "0" quietly accepted
    both leave a server that runs."""
    for size, want in HINT_CASES:
        got, text = config_accepted(ctx, f"pack_zstd_hint {size};")
        check(
            got == want,
            f"pack_zstd_hint {size}: expected "
            f"{'accepted' if want else 'refused'}, got the opposite"
            f"{'' if want else chr(10) + text}",
        )

    # Checked before the size/word split, the same way ngx_conf_set_size_slot
    # itself refuses two sizes: the slot is still unset the second time
    # around, so a second "none" has to be caught here instead.
    accepted, text = config_accepted(ctx, "pack_zstd_hint 1m;\npack_zstd_hint 2m;")
    check(not accepted, f"a duplicate pack_zstd_hint was accepted:\n{text}")
    check(
        "duplicate" in text,
        f"a duplicate pack_zstd_hint was refused for the wrong reason:\n{text}",
    )

    # The refusal is the only place an operator who wanted no hint
    # finds out the word exists.
    _, text = config_accepted(ctx, "pack_zstd_hint 8k;")
    check(
        "none" in text,
        f"a refused size did not mention the word:\n{text}",
    )


def parse_size(text: str) -> int:
    """ "16k" to 16384, the units ngx_parse_size accepts."""
    if text.endswith("k"):
        return int(text[:-1]) * 1024
    if text.endswith("m"):
        return int(text[:-1]) * 1024 * 1024
    return int(text)


def buffer_bounds(
    ctx: Context, codec: Codec = ZSTD
) -> tuple[int, int, int, int]:
    """(count_min, count_max, size_min, size_max) this nginx enforces.

    Read out of the binary rather than spelled out here, so a bound that
    moves in the module is picked up instead of needing this suite edited
    alongside it - and so the tests below cannot drift out of step with
    what the module actually accepts.

    Reading them from the refusals checks something worth checking on the
    way past: that what the module reports matches what it enforces.
    """
    _, text = config_accepted(ctx, f"{codec.directive}_buffers 1 1;")
    sizes = re.search(r"buffer size must be between (\S+) and (\S+)", text)
    check(sizes is not None, f"no buffer size bounds in the refusal:\n{text}")

    assert sizes is not None
    _, text = config_accepted(
        ctx, f"{codec.directive}_buffers 100000 {sizes.group(1)};"
    )
    counts = re.search(r"number of buffers must be between (\d+) and (\d+)", text)
    check(counts is not None, f"no buffer count bounds in the refusal:\n{text}")

    assert counts is not None
    return (
        int(counts.group(1)),
        int(counts.group(2)),
        parse_size(sizes.group(1)),
        parse_size(sizes.group(2)),
    )


@test(
    "the buffers directive holds both parameters to the bounds it reports",
    codecs=CODECS,
)
def test_buffers_bounds(ctx: Context, codec: Codec) -> None:
    """One buffer is enough to be correct - the filter stalls until the
    filters below take it - so the count floor is 1. Every case here is
    built from the bounds the binary names in its own refusals, so what
    is checked is that each end is enforced, not what the ends are.

    Both parameters are required, as with gzip_buffers, so a lone count
    is a configuration error rather than a count with the default size.
    """
    num_min, num_max, size_min, size_max = buffer_bounds(ctx, codec)

    cases = [
        (f"{num_min} {size_min}", True),
        (f"{num_max} {size_min}", True),
        (f"{num_min} {size_max}", True),
        (f"{num_min - 1} {size_min}", False),
        (f"{num_max + 1} {size_min}", False),
        (f"-1 {size_min}", False),
        (f"{num_min} {size_min - 1}", False),
        (f"{num_min} {size_max + 1}", False),
        (f"{num_min} 0", False),
        (f"{num_min} nonsense", False),
        (f"{num_min}", False),
        (f"{num_min} {size_min} {num_min}", False),
    ]

    for parameters, want in cases:
        got, text = config_accepted(ctx, f"{codec.directive}_buffers {parameters};")
        check(
            got == want,
            f"{codec.directive}_buffers {parameters}: expected "
            f"{'accepted' if want else 'refused'}, got the opposite"
            f"{'' if want else chr(10) + text}",
        )


# A fragment of the warning set_buffers logs for a count of 1, not the
# whole sentence: what the test is for is that the operator is told,
# so a reword should not have to come here to be allowed.
ONE_BUFFER_WARNING = "multiple buffers are recommended"


@test(
    "the buffers directive warns when a count of 1 gives up the run-ahead",
    codecs=CODECS,
)
def test_buffers_one_warns(ctx: Context, codec: Codec) -> None:
    """A count of 1 is legal, and costs the thing the directive
    exists to buy: the encoder stops after each buffer until the filters
    below give it back. Nothing else says so - the configuration is
    accepted and the server runs - so the warning is the only notice an
    operator gets, and it has to be a warning rather than a refusal.

    The count above the floor is the control: without it a warning
    emitted unconditionally would pass just as well."""
    num_min, _, size_min, _ = buffer_bounds(ctx, codec)

    accepted, text = config_accepted(
        ctx, f"{codec.directive}_buffers {num_min} {size_min};"
    )
    check(accepted, f"a count of {num_min} was refused:\n{text}")
    check(
        ONE_BUFFER_WARNING in text,
        f"a count of {num_min} drew no warning:\n{text}",
    )
    check(
        "[warn]" in text,
        f"the notice was not logged at warn level:\n{text}",
    )

    accepted, text = config_accepted(
        ctx, f"{codec.directive}_buffers {num_min + 1} {size_min};"
    )
    check(accepted, f"a count of {num_min + 1} was refused:\n{text}")
    check(
        ONE_BUFFER_WARNING not in text,
        f"a count of {num_min + 1} drew the one-buffer warning:\n{text}",
    )


# ---------------------------------------------------------------------------
# Output buffers
# ---------------------------------------------------------------------------


def stall_a_response(
    port: int, path: str, accept_encoding: str = "zstd", seconds: float = 0.6
) -> None:
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
            f"Accept-Encoding: {accept_encoding}\r\n\r\n".encode()
        )
        time.sleep(seconds)
    finally:
        sock.close()


@test(
    "a stalled write does not stop the encoder",
    needs_debug=True,
    codecs=CODECS,
)
def test_multiple_output_buffers(ctx: Context, codec: Codec) -> None:
    """With one buffer the encoder had to stop until it came back, so a slow
    client throttled compression as well as delivery. Several buffers let it
    run on, and the first parameter of the buffers directive is the bound on
    how far."""
    # The ceiling the binary reports, not the default count: nothing the
    # module prints names the default, and a stalled response is bounded
    # by the ceiling either way. Checking against the looser of the two
    # is what keeps this from restating a constant it cannot read.
    _, max_buffers, _, _ = buffer_bounds(ctx, codec)

    ctx.nginx.mark_log()
    stall_a_response(ctx.port, codec.path("throttled", "wiki.html"), codec.token)
    created = buffers_created(ctx.nginx.read_log(), codec)

    check(
        created > 1,
        f"a stalled response created {created} output buffer(s), so the "
        f"encoder still stops on the first one and "
        f"{codec.directive}_buffers buys nothing",
    )
    check(
        created <= max_buffers,
        f"a stalled response created {created} output buffers, past the "
        f"{codec.directive}_buffers ceiling of {max_buffers}",
    )


@test(
    "buffers 1 holds the encoder to a single buffer",
    needs_debug=True,
    codecs=CODECS,
)
def test_buffers_directive_is_honoured(ctx: Context, codec: Codec) -> None:
    """The same stall against a location that allows only one buffer. This is
    what tells a failure of the test above apart: if this one also reports
    more than one, the directive is being ignored rather than the stall
    failing to happen."""
    ctx.nginx.mark_log()
    stall_a_response(ctx.port, codec.path("throttled-one", "wiki.html"), codec.token)
    created = buffers_created(ctx.nginx.read_log(), codec)

    check(
        created == 1,
        f"{codec.directive}_buffers 1 still created {created} output buffers",
    )


# script/tests/stream/test_stream.conf, the size /wide-buffers/ asks for, and the
# compiled-in default it has to be told apart from. Larger rather than
# smaller because the size floor and the default are both 16k: the
# smallest a config may ask for is the default itself, so only a bigger
# size proves the directive reached the encoder.
WIDE_BUFFER_SIZE = 64 * 1024
DEFAULT_BUFFER_SIZE = 16 * 1024


@test(
    "the pack_zstd_buffers size bounds what one round commits",
    needs_debug=True,
    only=ZSTD,
)
def test_buffer_size_is_honoured(ctx: Context) -> None:
    """The second parameter, checked by what the encoder does with it.

    A round can commit at most one buffer's worth, so a location asking for
    64k buffers can log a round the 16k default never could - which is what
    tells a working directive apart from one that is parsed and ignored.
    """
    ctx.nginx.mark_log()
    status, headers, body = fetch(ctx.port, "/wide-buffers/dense.html")
    check(status == 200, f"expected 200, got {status}")
    check(headers.get("content-encoding") == "zstd", "response was not compressed")

    sizes = [int(size) for _, size in OUT_RE.findall(ctx.nginx.read_log())]
    check(sizes != [], "no committed rounds were traced")
    check(
        max(sizes) <= WIDE_BUFFER_SIZE,
        f"a round committed {max(sizes)} bytes against a "
        f"{WIDE_BUFFER_SIZE}-byte buffer, which is more than one buffer holds",
    )
    check(
        max(sizes) > DEFAULT_BUFFER_SIZE,
        f"the largest round was {max(sizes)} bytes, within what the "
        f"{DEFAULT_BUFFER_SIZE}-byte default could have committed, so the "
        f"configured size did not reach the encoder",
    )
    check(
        sum(sizes) == len(body),
        f"the filter committed {sum(sizes)} bytes over {len(sizes)} rounds "
        f"but the client received {len(body)}",
    )


# ---------------------------------------------------------------------------
# Flush folding
# ---------------------------------------------------------------------------

# module/filter/zstd/ngx_http_pack_zstd_encoder.c, the bound on both the fold
# and the flush the filter makes on its own.
FLUSH_AFTER = 32 * 1024


# What a burst may cost against the same bytes uninterrupted.
# Deliberately loose: measured, folding brings zstd to +2.0% and Brotli
# to +0.0%, while Brotli without folding was +123.6%. So this catches
# folding being lost outright, which is the thing worth catching,
# without pinning a ratio that moves whenever either library is bumped.
FOLD_COST_LIMIT = 1.25


@test(
    "a burst of flush-marked chunks costs little against the same bytes",
    needs_decoder=True,
    codecs=CODECS,
)
def test_flush_folding_cost(ctx: Context, codec: Codec) -> None:
    """Flush folding, measured the one way both encoders allow.

    nginx's chunked proxy filter marks every upstream chunk with
    "flush", so a burst arrives as a chain of flush-marked buffers.
    Taken literally each one ends a block, and the per-block overhead is
    paid over and over - for Brotli that means a set of Huffman tables
    apiece, which is why it suffered more than zstd here.

    The zstd tests below count blocks in the frame header, which is
    exact but has no Brotli equivalent. This compares the burst against
    a file of identical bytes instead: same content, no flush markers,
    so the file is the floor and the gap is what folding failed to
    recover.
    """
    _, flat_headers, flat = fetch(ctx.port, codec.file("burst.html"), codec.token)
    check(
        flat_headers.get("content-encoding") == codec.token,
        "the static burst fixture was not compressed",
    )

    _, headers, body = fetch(ctx.port, codec.path("burst", ""), codec.token)
    check(
        headers.get("content-encoding") == codec.token,
        f"burst was not compressed, got {headers.get('content-encoding')!r}",
    )

    decode = must_decode(codec)
    check(
        decode(body) == ctx.fixtures["burst.html"],
        "the burst did not decode to the same bytes as the file",
    )
    check(
        len(body) <= len(flat) * FOLD_COST_LIMIT,
        f"the burst compressed to {len(body)} bytes against {len(flat)} "
        f"for the same bytes uninterrupted "
        f"({100.0 * (len(body) - len(flat)) / len(flat):+.1f}%): the "
        f"flush-marked chunks are ending a block each instead of being "
        f"folded into one",
    )


# The encoder logs one line per folded flush, since Brotli's format
# states no block structure to read back.
BROTLI_FOLD_LINE = "brotli flush folded"


@test(
    "a burst of flush-marked chunks takes the Brotli fold path",
    needs_debug=True,
    only=BROTLI,
)
def test_brotli_flush_folding(ctx: Context) -> None:
    """The Brotli half of what test_flush_folding asserts for zstd, and
    it has to be asserted differently.

    zstd states a block count in its frame header, so that test reads
    the answer out of the response. Brotli's format carries no such
    structure, so the encoder logs the decision instead and this counts
    the lines. What that proves is narrower and worth naming: the fold
    path was taken, not that Brotli emitted fewer meta-blocks. The
    second is what test_flush_folding_cost measures, by comparing the
    burst against a file of identical bytes.

    The burst arrives as one chain of flush-marked buffers, and every
    flush but the last can fold - the last has nothing after it to push
    its bytes out, so it must cut. Asserting a bound rather than an
    exact count, since how much nginx reads at once is not ours to fix
    and the burst may arrive as more than one chain.

    /br-burst/ names quality 4 deliberately. At the compiled-in default
    Brotli takes its fast path, where every call becomes a meta-block
    whatever this decides.
    """
    chunks = Upstream.BURST_CHUNKS

    ctx.nginx.mark_log()
    _, headers, _body = fetch(ctx.port, BROTLI.path("burst", ""), BROTLI.token)
    check(
        headers.get("content-encoding") == BROTLI.token,
        f"burst was not compressed, got "
        f"{headers.get('content-encoding')!r} - a flush marker is supposed "
        f"to short-circuit pack_brotli_min_length",
    )

    folds = ctx.nginx.read_log().count(BROTLI_FOLD_LINE)

    check(
        folds > 0,
        f"{chunks} flush-marked chunks folded none, so every flush cut a "
        f"meta-block of its own",
    )
    check(
        folds >= chunks - 2,
        f"only {folds} of {chunks} flush-marked chunks folded; the last "
        f"cannot, so anything below {chunks - 2} means the fold gave up "
        f"early",
    )


@test(
    "a burst of flush-marked chunks folds into fewer blocks",
    needs_decoder=True,
    only=ZSTD,
)
def test_flush_folding(ctx: Context) -> None:
    """The upstream writes every chunk in one send, so the chunked filter
    hands the module a single chain of flush markers - one per chunk. Only
    the last of a fold has to cut a block.

    This burst is far smaller than the fold is allowed to hold, so what it
    checks is that folding happens at all; test_flush_folding_bounded is
    what checks where it stops. Asserting a bound rather than an exact
    count, since how much nginx reads at once is not ours to fix and a
    burst may still arrive as more than one chain.
    """
    chunks = Upstream.BURST_CHUNKS
    _, headers, body = fetch(ctx.port, "/burst")

    check(
        headers.get("content-encoding") == "zstd",
        f"burst was not compressed, got "
        f"{headers.get('content-encoding')!r} - a flush marker is supposed "
        f"to short-circuit pack_zstd_min_length",
    )

    blocks = frame_blocks(body)

    check(
        blocks < chunks,
        f"{chunks} flush-marked chunks produced {blocks} blocks, so every "
        f"flush still cut its own block and nothing was folded",
    )


@test(
    "flush folding stops at the bound rather than swallowing a burst",
    needs_decoder=True,
    only=ZSTD,
)
def test_flush_folding_bounded(ctx: Context) -> None:
    """The other end of the fold, and the one a count of buffers could not
    express: a chain carrying more than FLUSH_AFTER has to be cut, however
    many buffers those bytes arrive in.

    Both directions are checked because either alone is satisfied by a
    mistake. A ceiling alone passes if nothing folds alone; a floor alone
    passes if the fold is unbounded and one block covers everything. The
    payload is close to incompressible so the input, not the output, is
    what reaches the bound, and the location raises proxy_buffer_size so
    the burst really does arrive as one chain.
    """
    raw = Upstream.WIDE_CHUNKS * Upstream.WIDE_CHUNK_SIZE
    _, headers, body = fetch(ctx.port, "/burst-wide/x")

    check(
        headers.get("content-encoding") == "zstd",
        f"wide burst was not compressed, got {headers.get('content-encoding')!r}",
    )
    decode = must_decode(ctx)
    check(
        len(decode(body)) == raw,
        f"expected {raw} bytes back, got {len(decode(body))}",
    )

    blocks = frame_blocks(body)
    floor = raw // FLUSH_AFTER

    check(
        blocks >= floor,
        f"{raw} bytes of flush-marked input produced {blocks} block(s), "
        f"fewer than the {floor} a {FLUSH_AFTER}-byte fold bound allows - "
        f"the fold ran past where it should stop",
    )
    check(
        blocks < Upstream.WIDE_CHUNKS,
        f"{Upstream.WIDE_CHUNKS} flush-marked chunks produced {blocks} "
        f"blocks, so nothing was folded at all",
    )


@test("a folded flush still delivers every byte", needs_decoder=True, codecs=CODECS)
def test_flush_folding_roundtrip(ctx: Context, codec: Codec) -> None:
    """Folding may not lose or reorder anything: the point is that only the
    framing changes. Both encoders fold, each with its own chain walk, and
    dropping bytes is exactly what that operation can do wrong.

    Brotli's location asks for a quality where folding is not inert -
    quality 0 and 1 give every call a meta-block of its own, so there is
    nothing to merge and the assertion would pass vacuously."""
    expected = b"".join(
        b"%d %s" % (i, Upstream.BURST_TEXT) for i in range(Upstream.BURST_CHUNKS)
    )
    _, headers, body = fetch(ctx.port, codec.path("burst", ""), codec.token)

    check(
        headers.get("content-encoding") == codec.token,
        f"the burst came back {headers.get('content-encoding')!r}, so this "
        f"decoded nothing the encoder produced",
    )
    decode = must_decode(codec)
    check(
        decode(body) == expected,
        "decoded burst differs from what the upstream sent",
    )


# ---------------------------------------------------------------------------
# Encoder window selection (debug builds only)
# ---------------------------------------------------------------------------


@test(
    "buffered stream shrinks the window once the size is known",
    needs_debug=True,
    only=ZSTD,
)
def test_deferred_window_for_buffered_stream(ctx: Context) -> None:
    """A small response of unknown length still reaches the filter whole, just
    without last_buf on the first call. Holding it briefly lets the filter size
    the window from the real total instead of falling back to pack_zstd_window."""
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


@test("buffered stream still round-trips", needs_decoder=True, only=ZSTD)
def test_buffered_stream_roundtrip(ctx: Context) -> None:
    status, headers, body = fetch(ctx.port, "/buffered/big.html")
    check(status == 200, f"expected 200, got {status}")
    check(
        headers.get("content-encoding") == "zstd",
        f"expected Content-Encoding: zstd, got {headers.get('content-encoding')!r}",
    )
    decode = must_decode(ctx)
    check(
        decode(body) == ctx.fixtures["big.html"],
        "decoded buffered stream differs from the original",
    )


@test("large buffered stream still uses the full window", needs_debug=True, only=ZSTD)
def test_deferred_falls_back_for_large(ctx: Context) -> None:
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


@test("known Content-Length shrinks the encoder window", needs_debug=True, only=ZSTD)
def test_window_tuning(ctx: Context) -> None:
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
        f"a response larger than pack_zstd_window should use the full "
        f"{FULL_WINDOW} window, got {big}",
    )


@test(
    "stream of unknown length falls back to the full window",
    needs_debug=True,
    only=ZSTD,
)
def test_stream_uses_full_window(ctx: Context) -> None:
    """Same payload as test_window_tuning's small case, but delivered chunked.
    With no Content-Length to tune from, the filter must use pack_zstd_window -
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


# Short on purpose. A deadlock shows up as a response that never ends,
# so the only way this test can fail is by waiting - and waiting the
# default 30s per codec would make a regression look like a hung suite
# rather than a failure. Anything this size compresses in milliseconds.
DEADLOCK_TIMEOUT = 8


@test(
    "the smallest window still finishes the response",
    needs_decoder=True,
    codecs=CODECS,
)
def test_small_window_does_not_deadlock(ctx: Context, codec: Codec) -> None:
    """A regression test for a deadlock between the encoder and the write
    filter, at the smallest window each codec allows.

    Brotli at a 1k window emits blocks of a few hundred bytes. nginx's
    write filter holds a buffer that small until postpone_output (1460
    bytes by default) has accumulated - and while it held one, an encoder
    whose only output buffer was that buffer could not produce the bytes
    being waited for. Neither side moved again: the worker sat at 0.0%
    CPU and the client timed out. Every corpus file hung at 1k and four
    of five at 4k.

    What keeps it away is the "recycled" flag on the output buffers,
    which tells the write filter the memory has to come back rather
    than be sat on.

    Be clear about what this test does and does not prove. Since
    pack_brotli_window's floor rose to 16k, no configuration can
    produce a block short enough to reach the condition - dropping
    "recycled" was measured here and every response still completed.
    So this is a smallest-window smoke test, and the real cover for
    the deadlock is script/tests/stream/test-small-buffer.sh, where a 64-byte
    buffer does reach it: dropping the flag there hangs a plain static
    response while zstd carries on unaffected.

    Still worth running for both codecs. An encoder that cannot finish
    a response at its own smallest window is a bug whichever library
    is underneath, and this fails by timing out - hence the
    deliberately short timeout.

    The whole body is checked, not just the arrival of a response: a
    deadlock that merely truncated would otherwise read as a pass.

    The fixture is load-bearing. What has to be true is that a block's
    worth of output lands under postpone_output, and since the window
    floor rose to 16k that only holds for a body which compresses
    hard - big.html manages about 130x, where dense.html would come
    out far too big to reach the condition at all.
    """
    path = codec.path("tiny-window", "big.html")
    try:
        _, headers, body = fetch(ctx.port, path, codec.token, timeout=DEADLOCK_TIMEOUT)
    except TimeoutError as exc:
        raise Failure(
            f"{path} did not finish within {DEADLOCK_TIMEOUT}s ({exc}). "
            f"The encoder and the write filter are deadlocked: each output "
            f"block is below postpone_output, so the write filter holds it "
            f"while the encoder waits for it back."
        ) from exc

    check(
        headers.get("content-encoding") == codec.token,
        f"{path} came back as "
        f"{headers.get('content-encoding')!r}, so nothing was compressed "
        f"and the deadlock could not have been reached either way",
    )
    decode = must_decode(codec)
    check(
        decode(body) == ctx.fixtures["big.html"],
        f"{path}: decoded body differs from the original",
    )


@test(
    "encoder allocations balance on a static response",
    needs_debug=True,
    codecs=CODECS,
)
def test_alloc_balance_static(ctx: Context, codec: Codec) -> None:
    ctx.nginx.mark_log()
    fetch(ctx.port, codec.file("big.html"), codec.token)
    assert_balanced(wait_for_encoder_release(ctx.nginx, codec=codec), "static")


@test(
    "encoder allocations balance on a streamed response",
    needs_debug=True,
    codecs=CODECS,
)
def test_alloc_balance_stream(ctx: Context, codec: Codec) -> None:
    ctx.nginx.mark_log()
    fetch(ctx.port, codec.path("stream", "big.html"), codec.token)
    assert_balanced(wait_for_encoder_release(ctx.nginx, codec=codec), "stream")


def peak_encoder_bytes(ctx: Context, path: str) -> tuple[int, bytes]:
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


@test(
    "a stream costs no more memory than the same body of known length",
    needs_debug=True,
    only=ZSTD,
)
def test_stream_memory_ceiling(ctx: Context) -> None:
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
    with the libzstd in deps/zstd and with pack_zstd_level, but "a stream
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


@test("pack_zstd_hint reaches the encoder", needs_debug=True, only=ZSTD)
def test_hint_directive_reaches_encoder(ctx: Context) -> None:
    """/small-hint/ is /big-hint/ with pack_zstd_hint pulled to its floor.

    Both take the same unknown-length path through the same upstream, so a
    difference between them can only be the directive - unlike
    test_stream_memory_ceiling, which shows the hint exists at all but not
    that it is configurable.
    """
    default_peak, default_body = peak_encoder_bytes(ctx, "/big-hint/big.html")
    small_peak, small_body = peak_encoder_bytes(ctx, "/small-hint/big.html")

    check(
        not frame_declares_size(default_body) and not frame_declares_size(small_body),
        "one of the two took the pledge path rather than the hint path, so "
        "this does not compare what it means to",
    )
    check(
        small_peak < default_peak,
        f"the smaller hint peaked at {small_peak / 1024:.0f} KB, not below "
        f"the {default_peak / 1024:.0f} KB the compiled-in default peaked "
        f"at - the directive is parsed but not reaching the encoder",
    )


@test(
    "repeated requests neither leak nor drift",
    needs_debug=True,
    codecs=CODECS,
)
def test_alloc_soak(ctx: Context, codec: Codec) -> None:
    # What this asks is whether identical requests allocate identically
    # and give it all back, which any repetition answers - drift shows
    # between the first two that differ. The count is a cost, not a
    # confidence level, and so is the body: at the 64-byte output buffer
    # script/tests/stream/test-small-buffer.sh builds, every 64 bytes of compressed
    # output is a logged round, and medium.html builds the same
    # full-sized encoder big.html would for a tenth of them.
    rounds = 8
    ctx.nginx.mark_log()
    for _ in range(rounds):
        fetch(ctx.port, codec.file("medium.html"), codec.token)
    active = assert_balanced(wait_for_encoder_release(ctx.nginx, codec=codec), "soak")

    check(
        len(active) == rounds, f"expected {rounds} traced requests, saw {len(active)}"
    )
    counts = {entry["allocs"] for entry in active.values()}
    check(
        len(counts) == 1,
        f"allocation count drifts between identical requests: {sorted(counts)}",
    )


def keepalive_soak(
    ctx: "Context",
    paths: Sequence[str],
    rounds: int,
    codec: "Codec" = ZSTD,
) -> Timeline:
    """Drives `rounds` passes over `paths` down one connection."""
    conn = http.client.HTTPConnection("127.0.0.1", ctx.port, timeout=60)
    try:
        for _ in range(rounds):
            for path in paths:
                conn.request(
                    "GET",
                    path,
                    headers={
                        "Host": "localhost",
                        "Accept-Encoding": codec.token,
                    },
                )
                response = conn.getresponse()
                response.read()
                check(response.status == 200, f"{path} -> {response.status}")
    finally:
        conn.close()
    wait_for_encoder_release(ctx.nginx, codec=codec)
    return allocator_timeline(ctx.nginx.read_log(), codec)


@test(
    "one connection serving many requests holds nothing between them",
    needs_debug=True,
    codecs=CODECS,
)
def test_keepalive_allocation_balance(ctx: Context, codec: Codec) -> None:
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
    buffered = codec.path("buffered", "medium.html")
    paths = [
        codec.file("medium.html"),
        buffered,
        codec.file("under_min.html"),
    ]

    # The dearest single request, measured rather than assumed.
    #
    # This used to take the buffered path alone, on the reasoning that a
    # response of unknown length is the expensive kind. That holds for
    # zstd and does not hold for Brotli, whose one-pass hash table is
    # sized from how much input a single call brings - "use smaller hash
    # table when input.size() is smaller", GetHashTable in
    # deps/brotli/c/enc/encode.c. A static file arrives in one large
    # piece and takes the full table; a proxied one arrives in pieces
    # the size of a proxy buffer, which derive from the page size, so
    # the same request is dearer on a 16k-page host than a 4k one. On
    # Linux the yardstick came in at a third of the static path and this
    # test reported accumulation that was not there.
    #
    # Taking the maximum keeps what the test is for - the soak must not
    # exceed the dearest thing in it - without needing to know which of
    # the paths that is on the platform underneath.
    singles: dict[str, int] = {}
    for path in paths:
        ctx.nginx.mark_log()
        singles[path] = keepalive_soak(ctx, [path], 1, codec)["peak"]

    dearest = max(singles, key=lambda path: singles[path])
    alone_peak = singles[dearest]
    check(
        alone_peak > 0,
        f"no encoder allocation traced for any of {', '.join(paths)}",
    )

    # Enough repetition to make accumulation unmistakable and no more.
    # An encoder held for the connection rather than the request shows
    # up on the second one - at_request_start below reports every
    # request that began with live memory - and by the twelfth the peak
    # would be an order of magnitude past the 1.25x this allows.
    #
    # Neither the count nor the body is free: script/tests/stream/test-small-buffer.sh
    # drives this at a 64-byte output buffer, where every 64 bytes of
    # compressed output is a logged round. medium.html rather than
    # big.html for that reason - both build the same full-sized encoder,
    # so the peaks this compares are identical either way, and the extra
    # megabyte only ever became debug log.
    rounds = 4
    ctx.nginx.mark_log()
    soak = keepalive_soak(ctx, paths, rounds, codec)

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
        soak["peak"] <= alone_peak * 1.25,
        f"peak live memory over {rounds * len(paths)} requests was "
        f"{soak['peak'] / 1024:.0f} KB against {alone_peak / 1024:.0f} KB "
        f"for the dearest single request ({dearest}), so cost is "
        f"accumulating across the connection. Single-request peaks were "
        + ", ".join(f"{p} {n:,}" for p, n in singles.items()),
    )


@test(
    "aborted request still releases the encoder",
    needs_debug=True,
    codecs=CODECS,
)
def test_cleanup_handler_on_abort(ctx: Context, codec: Codec) -> None:
    ctx.nginx.mark_log()
    fetch_and_abort(ctx.port, codec.path("slow", ""), codec.token)
    # Polls rather than sleeping a fixed 2.5s for nginx to notice the reset:
    # faster here, and it does not give up early on a loaded runner.
    active = assert_balanced(wait_for_encoder_release(ctx.nginx, codec=codec), "abort")

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


# One of each shape the encoder can be built on: a length known when the
# headers were written, and one the filter had to wait for.
def released_early_paths(codec: Codec) -> tuple[str, str]:
    return (codec.file("big.html"), codec.path("stream", "big.html"))


@test(
    "a finished response releases the encoder before the request closes",
    needs_debug=True,
    codecs=CODECS,
)
def test_encoder_released_before_close(ctx: Context, codec: Codec) -> None:
    """The mirror of the abort test above, and the only cover for the close
    in ngx_http_pack_zstd_finish.

    Both routes end with the encoder freed and the counts balanced, so
    assert_balanced cannot tell them apart - a response that reached the
    pool cleanup handler instead looks exactly as healthy. What separates
    them is where the frees sit: nginx logs "http close request" on entry
    to ngx_http_free_request and destroys the pool, cleanup handlers and
    all, some eighty lines later. Freeing before that line is what keeps an
    encoder's memory from outliving the response, which is the whole reason
    finish() closes rather than leaving it to the pool.
    """
    for path in released_early_paths(codec):
        ctx.nginx.mark_log()
        _, headers, _ = fetch(ctx.port, path, codec.token)
        check(
            headers.get("content-encoding") == codec.token,
            f"{path} was not compressed, so no encoder was built to release",
        )

        active = assert_balanced(
            wait_for_encoder_release(ctx.nginx, codec=codec),
            f"finished {path}",
        )

        late = sum(entry["frees_after_close"] for entry in active.values())
        check(
            late == 0,
            f"{path}: {late} of the encoder's allocations were freed after "
            f'"http close request", so the request left them to the pool '
            f"cleanup handler rather than releasing them when the frame "
            f"closed",
        )


# What one request may cost, per pack_zstd_window and pack_zstd_level,
# with the encoder capping hashLog and chainLog at the window - see
# ngx_http_pack_zstd_derive_tables.
#
# Each ceiling sits between what the capped encoder actually takes and
# what it took before, so dropping the cap fails the test. Measured
# against the vendored libzstd, which the submodule pins - a bump that
# moves these is worth re-measuring rather than widening.
#
#   window  level      capped    uncapped    ceiling
#      16k      3    261.1 KB    325.1 KB     300 KB
#      16k      6    261.1 KB    325.1 KB     300 KB
#      64k      6    777.3 KB   1097.3 KB     900 KB
#     256k      3   1438.7 KB   1438.7 KB    1600 KB   (unchanged)
#     256k      6   2206.7 KB   3486.7 KB    2600 KB
TABLE_CEILINGS = (
    ("/tables-16k-3/", 300 * 1024),
    ("/tables-16k-6/", 300 * 1024),
    ("/tables-64k-6/", 900 * 1024),
    ("/tables-256k-3/", 1600 * 1024),
    ("/tables-256k-6/", 2600 * 1024),
)


@test(
    "the encoder sizes its tables to the window, not to the level",
    needs_debug=True,
    only=ZSTD,
)
def test_table_sizing(ctx: Context) -> None:
    """Nothing in the frame says what tables made it, so this measures
    the only thing visible from outside - what the encoder allocated -
    against ceilings a build without the cap exceeds. The 256k level 3
    case is the opposite: zstd is already under the window there, so it
    fails if capping ever raises what a request costs.
    """
    for path, ceiling in TABLE_CEILINGS:
        ctx.nginx.mark_log()
        _, headers, _body = fetch(ctx.port, path + "wiki.html")
        check(
            headers.get("content-encoding") == "zstd",
            f"{path} was not compressed, so no encoder was built",
        )

        active = assert_balanced(wait_for_encoder_release(ctx.nginx), f"tables {path}")
        peak = max(entry["peak_bytes"] for entry in active.values())

        check(
            peak <= ceiling,
            f"{path}: the encoder peaked at {peak / 1024:.1f} KB against a "
            f"{ceiling / 1024:.0f} KB ceiling - its tables are sized to "
            f"the level rather than to the window",
        )


def continue_ordinal(codec: Codec) -> int:
    """The value of this codec's STEP_CONTINUE, read out of its header.

    The trace logs the step as a number, so a test that reads it has to
    know which number means "go round again". Parsed rather than repeated
    so that reordering the enum fails here, loudly, instead of quietly
    making the assertion below vacuous.
    """
    header = os.path.join(
        ROOT, "module", "filter", codec.name,
        f"ngx_http_pack_{codec.name}_encoder.h",
    )
    with open(header) as handle:
        body = handle.read()

    block = re.search(r"typedef enum \{(.*?)\}", body, re.S)
    if block is None:
        raise Failure(f"no step enum found in {header}")

    value, seen = 0, dict[str, int]()
    for line in block.group(1).split("\n"):
        m = re.match(r"\s*(NGX_HTTP_PACK_\w+?_STEP_(\w+))\s*(?:=\s*(\d+))?\s*,", line)
        if not m:
            continue
        if m.group(3) is not None:
            value = int(m.group(3))
        seen[m.group(2)] = value
        value += 1

    if "CONTINUE" not in seen:
        raise Failure(f"no STEP_CONTINUE in {header}, only {sorted(seen)}")
    return seen["CONTINUE"]


@test(
    "every round that goes again has moved something",
    needs_debug=True,
    codecs=CODECS,
)
def test_rounds_make_progress(ctx: Context, codec: Codec) -> None:
    """The invariant the pump loop's termination rests on.

    Both encoders answer CONTINUE to mean "go round again", and both loop
    on that answer without counting. So a CONTINUE round that consumed no
    input and wrote no byte would be repeated on identical state until the
    worker was killed. Each encoder guards against it - zstd in
    made_progress, Brotli by returning CONTINUE only after movement - but
    a guard on a path nothing reaches is a guard nobody has seen work.

    This is the other half: not that the guard fires, but that on ordinary
    traffic it never needs to. Under script/tests/stream/test-small-buffer.sh the same
    assertion covers thousands of rounds per response rather than a
    handful, which is where it has real teeth.

    A round that moves nothing is not always wrong - completing a flush of
    an empty block moves neither input nor output, and is legitimate. What
    makes it safe is that such a round does not answer CONTINUE, and that
    is exactly what this checks.
    """
    expected = continue_ordinal(codec)
    check(
        expected == codec.continue_step,
        f"{codec.name}'s STEP_CONTINUE is {expected} in the header but the "
        f"suite was told {codec.continue_step}; the enum moved",
    )

    ctx.nginx.mark_log()
    status, headers, _ = fetch(ctx.port, codec.file("medium.html"), codec.token)
    check(status == 200, f"expected 200, got {status}")
    check(
        headers.get("content-encoding") == codec.token,
        "response was not compressed, so no round ran",
    )

    rounds = codec.round_re.findall(ctx.nginx.read_log())
    check(len(rounds) > 1, f"expected several rounds, traced {len(rounds)}")

    going_again = [r for r in rounds if int(r[3]) == codec.continue_step]
    check(
        going_again,
        f"none of the {len(rounds)} rounds answered CONTINUE, so the loop "
        f"never went round and this proved nothing",
    )

    stalled = [
        (conn, consumed, written)
        for conn, consumed, written, _ in going_again
        if int(consumed) == 0 and int(written) == 0
    ]
    check(
        not stalled,
        f"{len(stalled)} of {len(going_again)} CONTINUE rounds took no input "
        f"and wrote no byte, so the loop would repeat them unchanged: "
        f"{stalled[:3]}",
    )


@test(
    "committed output rounds account for every byte of the body",
    needs_debug=True,
    codecs=CODECS,
)
def test_output_rounds_account_for_the_body(ctx: Context, codec: Codec) -> None:
    """The filter refills its output buffers round after round.

    Every refill is logged with the size committed, so the trace says exactly
    how the body was cut up on the way out. Summing it is the accounting
    check on the partial-drain path: that a round which only half-empties the
    buffer neither drops bytes nor sends any of them twice.

    Deliberately calibrated from the trace rather than against a hard-coded
    16 KB, so that the same test tightens rather than breaks under
    script/tests/stream/test-small-buffer.sh, where a 64-byte buffer makes almost every
    round a partial one and this count goes from single digits to ~1500.

    Under that script this is also the only thing standing between a real
    stress run and a silent second run of the ordinary suite, for either
    encoder: the buffer size is checked below against what the caller said
    the build was limited to.
    """
    ctx.nginx.mark_log()
    status, headers, body = fetch(ctx.port, codec.file("big.html"), codec.token)
    check(status == 200, f"expected 200, got {status}")
    check(
        headers.get("content-encoding") == codec.token,
        "response was not compressed",
    )

    rounds: dict[str, list[int]] = {}
    for conn, size in codec.out_re.findall(ctx.nginx.read_log()):
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
    # It is what stops the small-buffer run from passing as a plain re-run
    # of the suite if the -D for this codec stops reaching the compiler.
    # Checked once per codec, so one flag arriving and the other not is a
    # failure rather than a half-covered run.
    cap = max(sizes)
    if ctx.max_out_size is not None:
        macro = f"NGX_HTTP_PACK_{codec.name.upper()}_BUFFER_SIZE_DEFAULT"
        check(
            cap <= ctx.max_out_size,
            f"largest committed round was {cap} bytes, above the "
            f"{ctx.max_out_size} this build was meant to be limited to: "
            f"{macro} did not reach the compiler",
        )


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------


class Context:
    """Everything a test needs: the server, the port, the fixture bytes and a
    zstd decoder."""

    def __init__(
        self,
        port: int,
        decode: Callable[[bytes], bytes] | None,
        fixtures: dict[str, bytes],
        nginx: "Nginx",
        max_out_size: int | None = None,
    ) -> None:
        self.port = port
        self.decode = decode
        self.fixtures = fixtures
        self.nginx = nginx
        # What NGX_HTTP_PACK_ZSTD_BUFFER_SIZE_DEFAULT was built with, when the
        # caller knows; None means "whatever the default is", and the check is
        # skipped.
        self.max_out_size = max_out_size


def main() -> int:
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
        "i.e. that -DNGX_HTTP_PACK_ZSTD_BUFFER_SIZE_DEFAULT reached the build "
        "(see script/tests/stream/test-small-buffer.sh)",
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
    for codec in CODECS:
        codec.decode = locate_decoder(codec)

    # The zstd one still has a name of its own: it is what ctx.decode
    # hands the tests that read the compressed bytes directly.
    decode = ZSTD.decode
    has_corpus = bool(load_corpus())
    has_curl = shutil.which("curl") is not None

    for port in (args.port, args.upstream_port):
        if not port_is_free(port):
            raise SystemExit(f"error: port {port} is already in use")

    print(f"nginx:   {nginx_bin}")
    print(f"build:   {version}{'' if has_debug else '   (no --with-debug)'}")
    print(
        "decoder: "
        + ", ".join(
            f"{codec.name} {'available' if codec.decode else 'MISSING'}"
            for codec in CODECS
        )
    )
    print(f"corpus:  {'present' if has_corpus else 'MISSING (script/corpus)'}")
    if args.max_out_size is not None:
        print(f"buffer:  asserting at most {args.max_out_size} bytes per round")
    if not has_debug:
        print("         window and memory tests need --with-debug; skipping them.")
    if not decode:
        print(
            "         round-trip tests need a zstd decoder: install the "
            "zstd CLI, or build the bundled one with\n"
            "           script/build/build.sh"
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

    results: list[tuple[str, str, str]] = []
    try:
        width = max(len(entry["name"]) for entry in REGISTRY)
        for entry in REGISTRY:
            name = entry["name"]
            codec = entry["codec"]
            waits = len(TEARDOWN_TIMEOUTS)
            started = time.time()
            if entry["needs_decoder"] and codec.decode is None:
                results.append((SKIP, name, f"no {codec.name} decoder available"))
            elif entry["needs_debug"] and not has_debug:
                results.append((SKIP, name, "nginx lacks --with-debug"))
            elif entry["needs_corpus"] and not has_corpus:
                results.append((SKIP, name, "script/corpus is missing"))
            elif entry["needs_curl"] and not has_curl:
                results.append((SKIP, name, "curl not found"))
            else:
                try:
                    entry["fn"](ctx)
                    results.append((PASS, name, ""))
                except Failure as failure:
                    results.append((FAIL, name, str(failure)))
                # A test that raises anything else - a socket timeout, a
                # decoder failure - is a failed test, not a reason to abandon
                # the run and leave nginx behind.
                except Exception as error:
                    results.append((FAIL, name, f"{type(error).__name__}: {error}"))
            elapsed = time.time() - started

            status, _, detail = results[-1]
            # A test that passed only after waiting out an encoder teardown
            # says so. Without this the wait is invisible: the assertions
            # can still hold, and all that shows is a suite that seems to
            # stall somewhere near here.
            gave_up = len(TEARDOWN_TIMEOUTS) - waits
            if gave_up:
                detail = (
                    f"{detail} " if detail else ""
                ) + f"[{gave_up} encoder teardown wait(s) timed out]"
            line = f"{status:<5} {name:<{width}} {detail}".rstrip()
            print(f"{line}, {elapsed:.1f}s")
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
