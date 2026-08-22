#!/usr/bin/env python3
"""Compression benchmark against the real-world corpus in script/corpus.

Reports what the filter actually achieves on real HTML, CSS, JavaScript and
prose - compressed size, ratio, and time per request - optionally across a
range of brotli_comp_level and brotli_window settings.

This is a measurement tool, not a test: a compression ratio has no pass or
fail, and the numbers move with the vendored Brotli version. Run it by hand
when tuning a default, and put the table in the commit message. test_stream.py
is what asserts correctness.

Two traps worth knowing before trusting any number this prints:

  * Never measure ratio on synthetic fixtures. test_stream.py's make_text()
    output is random words from a small list, which repeat at long range and
    compress far better than anything real. Measured against this corpus, a
    synthetic one overstated a ratio change roughly fourfold.

  * Never measure CPU on a --with-debug nginx. That build logs a line per
    encoder allocation, which swamps the compression itself; a change that
    costs 3-9% in a release build measured +50% under debug. This script
    forces error_log to "crit" for that reason, but a debug build still pays
    for the branches, so prefer a release build for timings.

Usage:
    python3 script/bench_corpus.py
    python3 script/bench_corpus.py --quality 4,5,6 --window 16k,64k
    python3 script/bench_corpus.py --nginx /path/to/nginx --repeat 40
"""

import argparse
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import test_stream as T  # noqa: E402


MIME = {
    ".html": "text/html",
    ".css": "text/css",
    ".js": "application/javascript",
    ".txt": "text/plain",
}


def render_conf(work, port, qualities, windows):
    """One location per (quality, window) pair, so a sweep needs one nginx."""
    locations = []
    for quality in qualities:
        for window in windows:
            window_directive = f"brotli_window {window};" if window else ""
            locations.append(
                f"    location /q{quality}w{window or 'default'}/ {{\n"
                f"      root html;\n"
                f"      brotli_comp_level {quality};\n"
                f"      {window_directive}\n"
                f"    }}"
            )

    conf = f"""
daemon off;
master_process off;

# "crit" is deliberate, see the module docstring: a debug error_log records
# every encoder allocation and would dominate the timings below.
error_log logs/error.log crit;
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

  brotli on;
  brotli_types text/html text/css application/javascript text/plain;

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


def bench_once(port, path, repeat):
    """Milliseconds per request, best of five batches."""
    for _ in range(min(8, repeat)):
        T.fetch(port, path)
    samples = []
    for _ in range(5):
        start = time.perf_counter()
        for _ in range(repeat):
            T.fetch(port, path)
        samples.append((time.perf_counter() - start) / repeat * 1000)
    return min(samples)


def main():
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--nginx", help="path to the nginx binary under test")
    parser.add_argument("--port", type=int, default=T.PORT)
    parser.add_argument(
        "--quality",
        default="6",
        help="comma-separated brotli_comp_level values (default: 6)",
    )
    parser.add_argument(
        "--window",
        default="",
        help="comma-separated brotli_window values; empty means the "
        "compiled-in default",
    )
    parser.add_argument(
        "--repeat",
        type=int,
        default=20,
        help="requests per timing batch (default: 20)",
    )
    args = parser.parse_args()

    corpus = T.load_corpus()
    if not corpus:
        raise SystemExit(
            f"error: no corpus in {T.CORPUS}. It is checked in; a partial "
            f"clone or a stray delete is the usual cause."
        )

    qualities = [q.strip() for q in args.quality.split(",") if q.strip()]
    windows = [w.strip() for w in args.window.split(",")] if args.window else [""]

    nginx_bin = T.locate_nginx(args.nginx)
    version, has_debug = T.nginx_build_info(nginx_bin)
    if not T.port_is_free(args.port):
        raise SystemExit(f"error: port {args.port} is already in use")

    print(f"nginx: {nginx_bin}")
    print(f"build: {version}")
    if has_debug:
        print(
            "       this is a --with-debug build; timings below are indicative\n"
            "       only, use a release build to compare CPU."
        )
    print()

    work = tempfile.mkdtemp(prefix="ngx-brotli-bench-")
    html = os.path.join(work, "html")
    os.makedirs(os.path.join(work, "logs"), exist_ok=True)
    for quality in qualities:
        for window in windows:
            directory = os.path.join(html, f"q{quality}w{window or 'default'}")
            os.makedirs(directory, exist_ok=True)
            for name, blob in corpus.items():
                with open(os.path.join(directory, name), "wb") as handle:
                    handle.write(blob)

    conf = render_conf(work, args.port, qualities, windows)
    nginx = T.Nginx(nginx_bin, work, conf, args.port)
    nginx.start()

    names = sorted(corpus, key=lambda n: MIME.get(os.path.splitext(n)[1], ""))
    try:
        for quality in qualities:
            for window in windows:
                label = f"brotli_comp_level {quality}"
                if window:
                    label += f", brotli_window {window}"
                print(f"### {label}")
                print(
                    f"{'file':>12} {'raw':>9} {'compressed':>11} "
                    f"{'ratio':>7} {'ms':>8}"
                )
                print("-" * 52)
                total_raw = total_out = 0
                for name in names:
                    path = f"/q{quality}w{window or 'default'}/{name}"
                    _, headers, body = T.fetch(args.port, path)
                    if headers.get("content-encoding") != "br":
                        print(f"{name:>12}   not compressed - check brotli_types")
                        continue
                    raw = len(corpus[name])
                    total_raw += raw
                    total_out += len(body)
                    elapsed = bench_once(args.port, path, args.repeat)
                    print(
                        f"{name:>12} {raw:>9,} {len(body):>11,} "
                        f"{raw / len(body):>6.2f}x {elapsed:>7.2f}"
                    )
                if total_out:
                    print(
                        f"{'total':>12} {total_raw:>9,} {total_out:>11,} "
                        f"{total_raw / total_out:>6.2f}x"
                    )
                print()
    finally:
        nginx.stop()


if __name__ == "__main__":
    main()
