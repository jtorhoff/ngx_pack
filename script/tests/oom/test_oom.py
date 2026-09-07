#!/usr/bin/env python3
"""What the filter does when libzstd cannot get memory.

Every other suite here exercises paths that succeed. These are the ones
that run out: ngx_http_pack_zstd_alloc refuses, and the branches that
handle it - which nothing else reaches, because a test cannot make
malloc fail on its own.

The behaviour asserted is deliberate rather than aspirational. The
response is dropped, not degraded: "Content-Encoding: zstd" is committed
before the encoder is built, in both the known-length and the
unknown-length path, so by the time an allocation is refused the headers
have gone and NGX_ERROR is the only honest answer left. Compressing
uncompressed bytes into a frame the client was promised is not an
option, and neither is retracting the header.

What must hold is everything around that:

  * the worker survives - a location with pack_zstd off keeps serving,
  * the reason is logged at alert level, naming this module,
  * nothing is leaked, whether the refusal came before the context
    existed or after.

script/tests/oom/test-oom.sh builds the nginx these need, with
NGX_HTTP_PACK_ZSTD_FAULT_INJECT defined. A shipping binary has none of
this compiled in.

Reuses test_stream's fixtures and server plumbing, so this file is only
the part that differs.
"""

from __future__ import annotations

import os
import socket
import sys
import time
from collections.abc import Callable

sys.path.insert(
    0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "stream")
)

import test_stream as T


def tag_for(text: str) -> str:
    pad = 4 - len(text)
    return f"{' ' * (pad)}[{text[:4]}]"


# Every scenario here drives zstd alone - PACK_ZSTD_FAULT_AFTER has no
# Brotli equivalent - so the tag is fixed rather than read per-test.
TAG = tag_for(T.ZSTD.log_tag)

CONF = os.path.join(T.ROOT, "script", "tests", "oom", "test_oom.conf")
PORT = T.PORT

# What the module logs when it cannot build an encoder, and what the
# hook logs when it refuses. Fragments rather than whole lines, so a
# reworded message does not have to come here to be allowed.
REFUSED = "zstd fault injection: refusing"
NO_ENCODER = "encoder instance creation failed"

failures: list[str] = []
passes = 0


def check(condition: bool, message: str) -> None:
    if not condition:
        raise T.Failure(message)


def scenario(
    name: str,
) -> Callable[[Callable[[T.Nginx], None]], Callable[[T.Nginx], None]]:
    def wrap(fn: Callable[[T.Nginx], None]) -> Callable[[T.Nginx], None]:
        def run(nginx: T.Nginx) -> None:
            global passes
            try:
                fn(nginx)
            except T.Failure as exc:
                failures.append(name)
                print(f"FAIL  {name:<52} {exc}")
            else:
                passes += 1
                print(f"PASS  {name}")

        return run

    return wrap


def raw_get(path: str, timeout: float = 10) -> bytes:
    """One request over a fresh connection, returning whatever came back.

    Not T.fetch: http.client raises when the peer closes without a
    complete response, and that is the case under test rather than an
    error to propagate.
    """
    sock = socket.create_connection(("127.0.0.1", PORT), timeout=timeout)
    try:
        sock.sendall(
            f"GET {path} HTTP/1.1\r\nHost: localhost\r\n"
            f"Connection: close\r\nAccept-Encoding: zstd\r\n\r\n".encode()
        )
        chunks: list[bytes] = []
        while True:
            try:
                data = sock.recv(65536)
            except (TimeoutError, ConnectionResetError):
                break
            if not data:
                break
            chunks.append(data)
    finally:
        sock.close()

    return b"".join(chunks)


def assert_worker_healthy(nginx: T.Nginx) -> None:
    """The control: a location needing no encoder still answers."""
    check(
        nginx.proc is not None and nginx.proc.poll() is None,
        "the worker exited - an allocation failure should not end the process",
    )

    body = raw_get("/plain/a.html")
    check(
        b"200" in body.split(b"\r\n", 1)[0],
        f"a location with pack_zstd off did not answer after a refused "
        f"allocation: {body[:80]!r}",
    )


def assert_no_leak(nginx: T.Nginx) -> None:
    """Whatever libzstd did get hold of came back.

    The refusal itself allocates nothing, so the interesting case is a
    context that was built and then could not grow: it has to be freed
    on the way out rather than left to the request pool's cleanup with
    its own allocations still live.
    """
    stats = T.wait_for_encoder_release(nginx)
    for conn, entry in sorted(stats.items()):
        check(
            not entry["live"],
            f"connection *{conn} still holds {len(entry['live'])} live "
            f"allocations ({entry['live_bytes']} bytes) after the "
            f"refusal",
        )
        check(
            entry["allocs"] == entry["frees"],
            f"connection *{conn}: {entry['allocs']} allocs against "
            f"{entry['frees']} frees after the refusal",
        )


@scenario(f"{TAG} a refused first allocation drops the response, not the worker")
def test_refuse_creation(nginx: T.Nginx) -> None:
    """PACK_ZSTD_FAULT_AFTER=1: the context cannot be built at all."""
    nginx.mark_log()
    body = raw_get("/zstd/a.html")
    log = nginx.read_log()

    check(REFUSED in log, "the hook never refused an allocation")
    check(
        NO_ENCODER in log,
        f"nothing logged the failure to build an encoder:\n{log[-400:]}",
    )
    check(
        b"200 OK" not in body,
        f"a response was completed although the encoder could not be "
        f"built: {body[:120]!r}",
    )

    assert_worker_healthy(nginx)
    assert_no_leak(nginx)


@scenario(f"{TAG} a refused later allocation frees the context it already had")
def test_refuse_workspace(nginx: T.Nginx) -> None:
    """PACK_ZSTD_FAULT_AFTER=2: the context exists, and then cannot
    grow. The path that matters is the one out - what libzstd already
    holds has to be released rather than stranded."""
    nginx.mark_log()
    body = raw_get("/zstd/a.html")
    log = nginx.read_log()

    check(REFUSED in log, "the hook never refused an allocation")
    check(
        b"200 OK" not in body or b"\r\n\r\n" not in body,
        f"a response completed although an allocation was refused: {body[:120]!r}",
    )

    assert_worker_healthy(nginx)
    assert_no_leak(nginx)


@scenario(f"{TAG} the hook is inert when nothing asks it to refuse")
def test_inert(nginx: T.Nginx) -> None:
    """The control on the control: with PACK_ZSTD_FAULT_AFTER unset the
    binary has to behave exactly like a shipping one, or the two
    scenarios above prove nothing about the module."""
    nginx.mark_log()
    body = raw_get("/zstd/a.html")
    log = nginx.read_log()

    check(REFUSED not in log, "the hook refused an allocation unasked")
    check(b"200 OK" in body, f"the response failed: {body[:120]!r}")
    check(
        b"content-encoding: zstd" in body.lower(),
        f"the response was not compressed: {body[:200]!r}",
    )


SCENARIOS: tuple[tuple[Callable[[T.Nginx], None], str | None], ...] = (
    (test_inert, None),
    (test_refuse_creation, "1"),
    (test_refuse_workspace, "2"),
)


def main() -> int:
    nginx_bin = T.locate_nginx(sys.argv[1] if len(sys.argv) > 1 else None)
    version, has_debug = T.nginx_build_info(nginx_bin)
    if not has_debug:
        raise SystemExit(
            "error: this suite reads the encoder's allocator trace, so it "
            "needs an nginx configured --with-debug"
        )

    print(f"nginx: {nginx_bin}\n{version.strip()}\n")

    work = T.tempfile.mkdtemp(prefix="ngx-zstd-oom-")
    os.makedirs(os.path.join(work, "logs"), exist_ok=True)
    T.build_fixtures(work)

    with open(CONF) as handle:
        conf_text = handle.read()
    conf = os.path.join(work, "nginx.conf")
    with open(conf, "w") as handle:
        handle.write(conf_text.replace("8899", str(PORT)))

    # A body big enough that libzstd has to reach for its tables, and
    # compressible enough to be worth encoding at all.
    with open(os.path.join(work, "html", "a.html"), "w") as handle:
        handle.write("<html><body>" + "compress me " * 4000 + "</body></html>")

    for fn, after in SCENARIOS:
        # Read once per worker, so each scenario needs its own nginx.
        if after is None:
            os.environ.pop("PACK_ZSTD_FAULT_AFTER", None)
        else:
            os.environ["PACK_ZSTD_FAULT_AFTER"] = after

        nginx = T.Nginx(nginx_bin, work, conf, PORT)
        nginx.start()
        try:
            fn(nginx)
        finally:
            nginx.stop()
            time.sleep(0.1)

    print(f"\n{passes} passed, {len(failures)} failed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
