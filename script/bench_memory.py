#!/usr/bin/env python3
"""Peak encoder memory against the real-world corpus in script/corpus.

The companion to bench_corpus.py: that one measures what a setting costs in
bytes on the wire and CPU per request, this one measures what it costs in
heap held per request in flight. Together they are what a pack_zstd_window
or pack_zstd_level default has to be argued from - window is very nearly a
pure memory-for-ratio trade, so neither number decides it alone.

Like bench_corpus.py this is a measurement tool, not a test: a peak has no
pass or fail, and the numbers move with the linked zstd version. Run it by
hand when tuning a default, and put the table in the commit message.
test_stream.py is what asserts the allocator actually balances.

The measurement is the encoder's own allocator tracing, replayed out of the
debug log by test_stream.allocator_events() - the same source the memory
tests read. "Peak" is the most bytes live at once within one response, not
the sum of everything it allocated.

Three traps worth knowing before trusting any number this prints:

  * This needs a --with-debug nginx, and refuses to run without one. The
    trace comes from ngx_log_debug, so a release build emits nothing and
    every peak here would be zero. That is the opposite of bench_corpus.py,
    whose timings need a release build - the two want different binaries.

  * These are pledged-length responses, so they are a floor, not a
    ceiling. Serving from disk gives the filter a Content-Length, and zstd
    shrinks windowLog to fit it: a response smaller than the window costs
    less than the window would suggest. A response of unknown length is
    sized from pack_zstd_hint instead and pays the configured window in
    full however small it turns out, which on a proxied site is most of
    the traffic. Measured at level 3, a 16 KB body costs 332,945 bytes
    with its length known and 992,569 chunked at the 64k window.

  * Peak steps with the pledged length, not just the window. Content that
    fits in one 128 KB zstd block (ZSTD_BLOCKSIZE_MAX) skips 32,768 bytes
    of input buffering, so one corpus file can sit a step below the rest
    for reasons that have nothing to do with the setting under test.

Usage:
    python3 script/bench_memory.py --nginx /path/to/debug/nginx
    python3 script/bench_memory.py --level 1,3 --window 16k,32k,64k
"""

import argparse
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import test_stream as T


def render_conf(work, port, levels, windows):
    """One location per (level, window) pair, so a sweep needs one nginx."""
    locations = []
    for level in levels:
        for window in windows:
            window_directive = f"pack_zstd_window {window};" if window else ""
            locations.append(
                f"    location /q{level}w{window or 'default'}/ {{\n"
                f"      root html;\n"
                f"      pack_zstd_level {level};\n"
                f"      {window_directive}\n"
                f"    }}"
            )

    conf = f"""
daemon off;
master_process off;

# "debug" is the whole point here, and the one difference from
# bench_corpus.py's config: the allocator trace this reads is written by
# ngx_log_debug, so a quieter level measures nothing at all.
error_log logs/error.log debug;
pid logs/nginx.pid;

events {{ worker_connections 64; }}

http {{
  access_log off;

  types {{
    text/html html;
    text/css css;
    application/javascript js;
    text/plain txt;
  }}
  default_type application/octet-stream;

  pack_zstd on;
  pack_zstd_types text/html text/css application/javascript text/plain;

  server {{
    listen 127.0.0.1:{port};
    root html;

{chr(10).join(locations)}
  }}
}}
"""
    path = os.path.join(work, "nginx.conf")
    with open(path, "w") as handle:
        handle.write(conf)
    return path


def measure(nginx, port, path):
    """What one response allocated, or None if it came back uncompressed.

    fetch() opens its own connection per request, so the connection id the
    trace is keyed by identifies this response and nothing else.

    wait_for_encoder_release() rather than reading the log straight after
    fetch(): the encoder outlives the last byte the client sees by one
    filter-loop iteration, so reading immediately races teardown and counts
    a free that has not happened yet as a leak.
    """
    nginx.mark_log()
    _, headers, body = T.fetch(port, path)
    if headers.get("content-encoding") != "zstd":
        return None

    stats = T.wait_for_encoder_release(nginx)
    active = [entry for entry in stats.values() if entry["allocs"]]
    if len(active) != 1:
        raise SystemExit(
            f"error: expected one traced connection for {path}, got "
            f"{len(active)}. Something else is serving on this port."
        )

    entry = active[0]
    return {
        "peak": entry["peak_bytes"],
        "allocs": entry["allocs"],
        "leaked": entry["live_bytes"],
        "window": T.frame_window(body),
        # Every size the encoder asked for, in order. The peak alone says
        # how much; this says what of - a constant context shell plus one
        # workspace that carries all the variation, at the time of writing.
        "sizes": [int(m.group(3)) for m in T.ALLOC_RE.finditer(nginx.read_log())],
    }


def main():
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--nginx", help="path to the nginx binary under test")
    parser.add_argument("--port", type=int, default=T.PORT)
    parser.add_argument(
        "--level",
        default="3",
        help="comma-separated pack_zstd_level values (default: 3)",
    )
    parser.add_argument(
        "--window",
        default="",
        help="comma-separated pack_zstd_window values; empty means the compiled-in default",
    )
    args = parser.parse_args()

    corpus = T.load_corpus()
    if not corpus:
        raise SystemExit(
            f"error: no corpus in {T.CORPUS}. It is checked in; a partial "
            f"clone or a stray delete is the usual cause."
        )

    levels = [lv.strip() for lv in args.level.split(",") if lv.strip()]
    windows = [w.strip() for w in args.window.split(",")] if args.window else [""]

    nginx_bin = T.locate_nginx(args.nginx)
    version, has_debug = T.nginx_build_info(nginx_bin)
    if not has_debug:
        raise SystemExit(
            f"error: {nginx_bin} is a release build. The allocator trace this "
            f"reads is written by ngx_log_debug, so every peak would be zero. "
            f"Build with WITH_DEBUG=1 (the default) and pass --nginx."
        )
    if not T.port_is_free(args.port):
        raise SystemExit(f"error: port {args.port} is already in use")

    print(f"nginx: {nginx_bin}")
    print(f"build: {version}")
    print()

    work = tempfile.mkdtemp(prefix="ngx-zstd-mem-")
    html = os.path.join(work, "html")
    os.makedirs(os.path.join(work, "logs"), exist_ok=True)
    for level in levels:
        for window in windows:
            directory = os.path.join(html, f"q{level}w{window or 'default'}")
            os.makedirs(directory, exist_ok=True)
            for name, blob in corpus.items():
                with open(os.path.join(directory, name), "wb") as handle:
                    handle.write(blob)

    conf = render_conf(work, args.port, levels, windows)
    nginx = T.Nginx(nginx_bin, work, conf, args.port)
    nginx.start()

    names = sorted(corpus)
    try:
        for level in levels:
            for window in windows:
                label = f"pack_zstd_level {level}"
                if window:
                    label += f", pack_zstd_window {window}"
                print(f"### {label}")
                print(
                    f"{'file':>12} {'raw':>9} {'frame win':>10} {'allocs':>7} "
                    f"{'peak':>10}   allocations"
                )
                print("-" * 76)
                for name in names:
                    path = f"/q{level}w{window or 'default'}/{name}"
                    result = measure(nginx, args.port, path)
                    if result is None:
                        print(f"{name:>12}   not compressed - check pack_zstd_types")
                        continue
                    print(
                        f"{name:>12} {len(corpus[name]):>9,} {result['window']:>10,} "
                        f"{result['allocs']:>7} {result['peak']:>10,}   "
                        f"{' + '.join(f'{s:,}' for s in result['sizes'])}"
                    )
                    # Not an assertion - test_stream.py owns that - but a peak
                    # measured over a response that never gave its memory back
                    # is not the number this claims to print.
                    if result["leaked"]:
                        print(
                            f"{'':>12}   warning: {result['leaked']:,} bytes still "
                            f"live at teardown; see test_stream.py"
                        )
                print()
    finally:
        nginx.stop()


if __name__ == "__main__":
    main()
