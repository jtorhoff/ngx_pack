#!/usr/bin/env python3
"""Covers the one branch no stock nginx module can reach.

ngx_http_zstd_filter_prepare calls send_headers only while the response
length is still unknown, and handles three outcomes from it: NGX_ERROR,
a status greater than NGX_OK, and success. The middle one needs a header
filter below this module to return a status, which nothing in nginx's
tree does on a response of unknown length - ngx_http_image_filter_module
is the only stock header filter that returns a status at all, and only
when Content-Length is known.

script/fault_filter is a test-only module that does exactly that, and
script/test-header-status.sh builds an nginx carrying both.

Reuses test_stream's fixtures, upstream and server plumbing so this file
is only the part that differs.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import test_stream as T

CONF = os.path.join(T.ROOT, "script", "test_header_status.conf")
PORT, UPSTREAM_PORT = T.PORT, T.UPSTREAM_PORT


def render_conf(work):
    with open(CONF) as handle:
        conf = handle.read()
    path = os.path.join(work, "test_header_status.conf")
    with open(path, "w") as handle:
        handle.write(conf)
    return path


def check(condition, message):
    if not condition:
        raise T.Failure(message)


def main():
    import shutil
    import tempfile

    nginx_bin = T.locate_nginx(sys.argv[1] if len(sys.argv) > 1 else None)
    version, has_debug = T.nginx_build_info(nginx_bin)
    print(f"nginx:   {nginx_bin}")
    print(f"build:   {version}{'' if has_debug else '   (no --with-debug)'}")

    for port in (PORT, UPSTREAM_PORT):
        if not T.port_is_free(port):
            raise SystemExit(f"error: port {port} is already in use")

    work = tempfile.mkdtemp(prefix="ngx-zstd-hdr-")
    fixtures = T.build_fixtures(work)
    conf = render_conf(work)

    upstream = T.Upstream(UPSTREAM_PORT, fixtures)
    upstream.start()
    nginx = T.Nginx(nginx_bin, work, conf, PORT)
    nginx.start()

    results = []

    def record(name, fn):
        try:
            fn()
            results.append((T.PASS, name, ""))
        except T.Failure as failure:
            results.append((T.FAIL, name, str(failure)))
        except Exception as error:
            results.append((T.FAIL, name, f"{type(error).__name__}: {error}"))
        status, _, detail = results[-1]
        print(f"{status:<5} {name:<52} {detail}", flush=True)

    def control_still_compresses():
        """The same upstream without the fault filter must be unaffected."""
        status, headers, _ = T.fetch(PORT, "/stream/big.html")
        check(status == 200, f"expected 200, got {status}")
        check(
            headers.get("content-encoding") == "zstd",
            "control request was not compressed, so the fixture is wrong "
            "rather than the branch under test",
        )

    def request_terminates_promptly():
        """The request must end, rather than hang until the client gives up.

        The status itself cannot reach the client: it is a header
        filter's return value, and by this point the response is in the
        body phase, whose callers do not understand one - nginx's
        non-buffered upstream path tests only for NGX_ERROR
        (ngx_http_upstream.c, "if (rc == NGX_ERROR)") and treats
        anything else as success. Returning the status therefore
        finalized nothing and the request sat until the client timed
        out. What is achievable, and what this asserts, is that it ends
        quickly and definitively.
        """
        import time

        started = time.time()
        try:
            T.fetch(PORT, "/fault/big.html", timeout=8)
        except Exception:
            pass  # a reset or an empty reply is a fine way to end
        elapsed = time.time() - started
        check(
            elapsed < 5,
            f"the rejected request took {elapsed:.1f}s to end, so it hung "
            f"rather than being finalized",
        )

    def context_is_closed():
        """The encoder must not be left live behind the rejected response.

        With ctx left open, a later body filter call finds closed == 0,
        headers_postponed already cleared and initialized still 0, so it
        falls through and builds an encoder for a response the chain has
        already replaced. The allocator trace is where that shows.
        """
        if not has_debug:
            raise T.Failure("needs --with-debug to read the allocator trace")
        nginx.mark_log()
        try:
            T.fetch(PORT, "/fault/big.html", timeout=8)
        except Exception:
            pass  # the connection closing without a reply is the point
        stats = T.wait_for_encoder_release(nginx)
        for conn, entry in stats.items():
            check(
                entry["allocs"] == entry["frees"],
                f"connection {conn}: {entry['allocs']} allocations against "
                f"{entry['frees']} frees - the encoder outlived the "
                f"rejected response",
            )

    def no_frame_reaches_the_wire():
        """The held body must not be emitted once the response is replaced.

        This is the sharp one. With the context left open, a later body
        filter call built an encoder for the replaced response and put
        the held body out compressed, so a client saw a zstd frame
        where a status line belonged - a response smuggled onto a
        request that was supposed to have been rejected.

        It fires intermittently, which is why it repeats. Against the
        unfixed build a standalone probe smuggled a frame on 3 attempts
        in 10, and in suite order the rate falls to about 1 in 12 -
        enough that twelve attempts catch it, not enough that one
        would. Treat the hang check above as the deterministic
        discriminator and this as the one that names the consequence.

        Reading the socket directly is deliberate either way: an HTTP
        client library raises on the malformed reply and loses the
        evidence.
        """
        import socket

        ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"
        ATTEMPTS = 12
        smuggled = 0

        for _ in range(ATTEMPTS):
            sock = socket.create_connection(("127.0.0.1", PORT), timeout=3)
            data = b""
            try:
                sock.sendall(
                    b"GET /fault/big.html HTTP/1.1\r\n"
                    b"Host: localhost\r\n"
                    b"Accept-Encoding: zstd\r\n\r\n"
                )
                while len(data) < (1 << 16):
                    chunk = sock.recv(8192)
                    if not chunk:
                        break
                    data += chunk
            except OSError:
                pass  # nginx closing without a reply is the correct outcome
            finally:
                sock.close()
            smuggled += ZSTD_MAGIC in data

        check(
            smuggled == 0,
            f"{smuggled} of {ATTEMPTS} rejected requests were answered with "
            f"a zstd frame - the held body was compressed and written for a "
            f"response the filter chain had already replaced",
        )

    try:
        record(
            "control: the same stream without the fault compresses",
            control_still_compresses,
        )
        record(
            "a rejected response ends instead of hanging", request_terminates_promptly
        )
        record("the encoder does not outlive the rejected response", context_is_closed)
        record(
            "no compressed frame reaches the wire after rejection",
            no_frame_reaches_the_wire,
        )
    finally:
        nginx.stop()
        upstream.shutdown()

    failed = sum(1 for status, _, _ in results if status == T.FAIL)
    passed = len(results) - failed
    print(f"\n{passed} passed, {failed} failed")
    if failed:
        print(f"work directory kept at {work}")
        print(nginx.read_log(whole=True)[-3000:])
    else:
        shutil.rmtree(work, ignore_errors=True)
    return failed


if __name__ == "__main__":
    sys.exit(main())
