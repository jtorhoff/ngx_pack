#!/usr/bin/env python3
"""Compression benchmark against the real-world corpus in script/corpus.

Reports what either filter actually achieves on real HTML, CSS, JavaScript
and prose - compressed size, ratio, and time per request - optionally across
a range of level and window settings, and for one codec or both.

This is a measurement tool, not a test: a compression ratio has no pass or
fail, and the numbers move with the linked library version. Run it by hand
when tuning a default, and put the table in the commit message. test_stream.py
is what asserts correctness.

The two codecs do not share a level range - pack_zstd_level starts at 1 and
pack_brotli_level at 0, and their ceilings are set separately - so a value
one accepts may be refused by the other. Each codec therefore gets an nginx
of its own: a refusal then costs that codec's table rather than the whole
run, and neither codec's first measurement pays for warming a worker the
other has already warmed.

Three traps worth knowing before trusting any number this prints:

  * Never measure ratio on synthetic fixtures. test_stream.py's make_text()
    output is random words from a small list, which repeat at long range and
    compress far better than anything real. Measured against this corpus, a
    synthetic one overstated a ratio change roughly fourfold.

  * Never measure CPU on a --with-debug nginx. That build logs a line per
    encoder allocation, which swamps the compression itself; a change that
    costs 3-9% in a release build measured +50% under debug. This script
    forces error_log to "crit" for that reason, but a debug build still pays
    for the branches, so prefer a release build for timings.

  * These are steady-state figures: every path is warmed before it is timed,
    and the best of five batches is what gets printed. The first request a
    fresh worker serves costs substantially more, and nothing here shows it.

Usage:
    python3 script/bench/bench_corpus.py
    python3 script/bench/bench_corpus.py --codec brotli --level 0,2,5
    python3 script/bench/bench_corpus.py --level 1,3,6 --window 16k,64k
    python3 script/bench/bench_corpus.py --nginx /path/to/nginx --repeat 40
"""

import argparse
import json
import os
import sys
import tempfile
import time

# test_stream.py lives in script/tests/stream, a sibling of this
# directory's parent, and carries the fixtures, the nginx wrapper and
# the allocator-trace parser these tools are built on.
sys.path.insert(
    0,
    os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tests", "stream"
    ),
)

import test_stream as T

MIME = {
    ".html": "text/html",
    ".css": "text/css",
    ".js": "application/javascript",
    ".txt": "text/plain",
    ".json": "application/json",
    ".pb": "application/x-protobuf",
}


def location(codec, level, window):
    """The path a (level, window) pair is served under, codec included.

    Named rather than numbered so a failure in the middle of a sweep says
    which configuration produced it."""
    return f"/{codec.name}-q{level or 'default'}w{window or 'default'}/"


def render_conf(work, port, codec, levels, windows):
    """One location per (level, window) pair, for this codec alone."""
    locations = []
    for level in levels:
        for window in windows:
            body = ["      root html;"]
            if level:
                body.append(f"      {codec.directive}_level {level};")
            if window:
                body.append(f"      {codec.directive}_window {window};")
            locations.append(
                f"    location {location(codec, level, window)} {{\n"
                + "\n".join(body)
                + "\n    }"
            )

    # The other codec is turned off by name rather than left unmentioned:
    # both filters see every response, and an explicit "off" is what keeps
    # a table headed "brotli" from measuring whichever one won the chain.
    others = "\n  ".join(
        f"{other.directive} off;" for other in T.CODECS if other is not codec
    )

    # The same corpus with this codec switched off. Every figure above is
    # read against it - a ratio is free to look good on a filter that has
    # tripled the time to first byte - and measuring it here rather than in a
    # second server keeps it the same binary, the same files and the same
    # request pattern.
    locations.append(
        f"    location /plain/ {{\n"
        f"      root html;\n"
        f"      {codec.directive} off;\n"
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
    application/json json;
    application/x-protobuf pb;
  }}
  default_type application/octet-stream;

  {codec.directive} on;
  # text/html is deliberately absent: it is always compressed, and naming
  # it draws a "duplicate MIME type" warning into output meant for a
  # commit message.
  {codec.directive}_types text/css application/javascript text/plain
                        application/json application/x-protobuf;
  {others}

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


def bench_once(port, path, token, repeat):
    """Milliseconds per request, best of five batches."""
    for _ in range(min(8, repeat)):
        T.fetch(port, path, token)
    samples = []
    for _ in range(5):
        start = time.perf_counter()
        for _ in range(repeat):
            T.fetch(port, path, token)
        samples.append((time.perf_counter() - start) / repeat * 1000)
    return min(samples)


def label_for(codec, level, window):
    parts = []
    if level:
        parts.append(f"{codec.directive}_level {level}")
    else:
        parts.append(f"{codec.name}, compiled-in level")
    if window:
        parts.append(f"{codec.directive}_window {window}")
    return ", ".join(parts)


def run_codec(codec, args, corpus, names, nginx_bin, summary):
    """Measures every (level, window) pair for one codec, in its own nginx."""
    levels = [lv.strip() for lv in args.level.split(",") if lv.strip()] or [""]
    windows = [w.strip() for w in args.window.split(",")] if args.window else [""]

    work = tempfile.mkdtemp(prefix=f"ngx-bench-{codec.name}-")
    html = os.path.join(work, "html")
    os.makedirs(os.path.join(work, "logs"), exist_ok=True)
    for level in levels:
        for window in windows:
            directory = os.path.join(html, location(codec, level, window).strip("/"))
            os.makedirs(directory, exist_ok=True)
            for name, blob in corpus.items():
                with open(os.path.join(directory, name), "wb") as handle:
                    handle.write(blob)

    plain = os.path.join(html, "plain")
    os.makedirs(plain, exist_ok=True)
    for name, blob in corpus.items():
        with open(os.path.join(plain, name), "wb") as handle:
            handle.write(blob)

    conf = render_conf(work, args.port, codec, levels, windows)
    nginx = T.Nginx(nginx_bin, work, conf, args.port)
    nginx.start()

    try:
        print(f"### {codec.name}, filter off - the floor every figure below is "
              f"read against")
        print(f"{'file':>12} {'bytes':>9} {'ms':>8}")
        print("-" * 32)
        base_ms = base_bytes = 0
        for name in names:
            path = "/plain/" + name
            _, headers, body = T.fetch(args.port, path, codec.token)
            # Asserted rather than assumed: a baseline that quietly came back
            # compressed would make every comparison here flattering.
            if headers.get("content-encoding") is not None:
                raise SystemExit(
                    f"error: {path} came back {headers['content-encoding']}-encoded, "
                    f"so this is not a baseline"
                )
            if len(body) != len(corpus[name]):
                raise SystemExit(
                    f"error: {path} returned {len(body)} bytes against "
                    f"{len(corpus[name])} on disk"
                )
            elapsed = bench_once(args.port, path, codec.token, args.repeat)
            base_ms += elapsed
            base_bytes += len(body)
            print(f"{name:>12} {len(body):>9,} {elapsed:>7.2f}")
        print("-" * 32)
        print(f"{'total':>12} {base_bytes:>9,} {base_ms:>7.2f}\n")
        summary.append(
            {
                "codec": "none",
                "level": "off",
                "window": "-",
                "raw": base_bytes,
                "out": base_bytes,
                "ms": base_ms,
                "measured_with": codec.name,
            }
        )

        for level in levels:
            for window in windows:
                print(f"### {label_for(codec, level, window)}")
                print(
                    f"{'file':>12} {'raw':>9} {'compressed':>11} {'ratio':>7} {'ms':>8}"
                )
                print("-" * 52)

                total_raw = total_out = 0
                total_ms = 0.0
                for name in names:
                    path = location(codec, level, window) + name
                    _, headers, body = T.fetch(args.port, path, codec.token)
                    if headers.get("content-encoding") != codec.token:
                        print(
                            f"{name:>12}   not compressed - check "
                            f"{codec.directive}_types"
                        )
                        continue
                    raw = len(corpus[name])
                    total_raw += raw
                    total_out += len(body)
                    elapsed = bench_once(args.port, path, codec.token, args.repeat)
                    total_ms += elapsed
                    print(
                        f"{name:>12} {raw:>9,} {len(body):>11,} "
                        f"{raw / len(body):>6.2f}x {elapsed:>7.2f}"
                    )

                if total_out:
                    print(
                        f"{'total':>12} {total_raw:>9,} {total_out:>11,} "
                        f"{total_raw / total_out:>6.2f}x {total_ms:>7.2f}"
                    )
                    summary.append(
                        {
                            "codec": codec.name,
                            "level": level or "default",
                            "window": window or "default",
                            "raw": total_raw,
                            "out": total_out,
                            "ms": total_ms,
                        }
                    )
                print()
    finally:
        nginx.stop()


def print_summary(rows):
    """Every configuration on one page, for pasting into a commit message."""
    print("### summary")
    print(
        f"{'codec':>8} {'level':>8} {'window':>8} {'bytes':>11} {'ratio':>7} {'ms':>8}"
    )
    print("-" * 54)
    for row in rows:
        print(
            f"{row['codec']:>8} {row['level']:>8} {row['window']:>8} "
            f"{row['out']:>11,} {row['raw'] / row['out']:>6.2f}x "
            f"{row['ms']:>7.2f}"
        )
    print()


def write_json(path, nginx_bin, version, rows, args):
    """The summary rows, for a reader that is not a person.

    Everything needed to tell one run from another goes in beside them: a
    latency is only comparable against another measured on the same binary,
    with the same repeat count, on the same machine.
    """
    with open(path, "w") as handle:
        json.dump(
            {
                "tool": "bench_corpus",
                "nginx": nginx_bin,
                "build": version,
                "repeat": args.repeat,
                "rows": rows,
            },
            handle,
            indent=2,
        )
    print(f"wrote {path}")


def main():
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--nginx", help="path to the nginx binary under test")
    parser.add_argument("--port", type=int, default=T.PORT)
    parser.add_argument(
        "--codec",
        default=",".join(c.name for c in T.CODECS),
        help="comma-separated codecs to measure (default: all of them)",
    )
    parser.add_argument(
        "--level",
        default="",
        help="comma-separated level values; empty means the compiled-in "
        "default. The two codecs accept different ranges",
    )
    parser.add_argument(
        "--window",
        default="",
        help="comma-separated window values; empty means the compiled-in default",
    )
    parser.add_argument(
        "--json",
        metavar="PATH",
        help="also write the summary rows to PATH as JSON. make_svg.py reads "
        "this, so a chart is drawn from a real run rather than from figures "
        "copied out of a terminal",
    )
    parser.add_argument(
        "--repeat",
        type=int,
        default=20,
        help="requests per timing batch (default: 20)",
    )
    args = parser.parse_args()

    by_name = {c.name: c for c in T.CODECS}
    wanted = [name.strip() for name in args.codec.split(",") if name.strip()]
    unknown = [name for name in wanted if name not in by_name]
    if unknown:
        raise SystemExit(
            f"error: no such codec {', '.join(unknown)}. Known: {', '.join(by_name)}"
        )
    codecs = [by_name[name] for name in wanted]

    corpus = T.load_corpus()
    if not corpus:
        raise SystemExit(
            f"error: no corpus in {T.CORPUS}. It is checked in; a partial "
            f"clone or a stray delete is the usual cause."
        )

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

    names = sorted(corpus, key=lambda n: MIME.get(os.path.splitext(n)[1], ""))

    summary = []
    for codec in codecs:
        run_codec(codec, args, corpus, names, nginx_bin, summary)

    # One codec at its compiled-in default is a single row, and the table
    # above already said everything it would.
    if len(summary) > 1:
        print_summary(summary)

    if args.json:
        write_json(args.json, nginx_bin, version, summary, args)


if __name__ == "__main__":
    main()
