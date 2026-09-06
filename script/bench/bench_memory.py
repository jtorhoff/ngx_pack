#!/usr/bin/env python3
"""Peak encoder memory against the real-world corpus in script/corpus.

The companion to bench_corpus.py: that one measures what a setting costs in
bytes on the wire and CPU per request, this one measures what it costs in
heap held per request in flight. Together they are what a window or level
default has to be argued from - window is very nearly a pure
memory-for-ratio trade, so neither number decides it alone.

Like bench_corpus.py this is a measurement tool, not a test: a peak has no
pass or fail, and the numbers move with the linked library version. Run it
by hand when tuning a default, and put the table in the commit message.
test_stream.py is what asserts the allocator actually balances.

The measurement is the encoder's own allocator tracing, replayed out of the
debug log by test_stream.allocator_events() - the same source the memory
tests read, and codec-aware because each filter tags its trace with its own
name. "Peak" is the most bytes live at once within one response, not the sum
of everything it allocated.

Both codecs are measured unless --codec says otherwise, and each gets an
nginx of its own: their level ranges differ, so a value one accepts the
other refuses at startup.

Four traps worth knowing before trusting any number this prints:

  * This needs a --with-debug nginx, and refuses to run without one. The
    trace comes from ngx_log_debug, so a release build emits nothing and
    every peak here would be zero. That is the opposite of bench_corpus.py,
    whose timings need a release build - the two want different binaries.

  * These are pledged-length responses, so for zstd they are a floor, not a
    ceiling. Serving from disk gives the filter a Content-Length and zstd
    shrinks windowLog to fit it, so a response smaller than the window costs
    less than the window would suggest; one of unknown length pays the
    configured window in full however small it turns out, which on a proxied
    site is most of the traffic. Brotli does not have this second case in
    the same way - BROTLI_PARAM_SIZE_HINT does not shrink its window - so
    its numbers here travel further than zstd's do.

  * Peak steps with the pledged length, not just the window. For zstd,
    content that fits in one 128 KB block (ZSTD_BLOCKSIZE_MAX) skips 32,768
    bytes of input buffering, so one corpus file can sit a step below the
    rest for reasons that have nothing to do with the setting under test.

  * The frame window column is zstd only. zstd states its window in the
    frame header, so the effective setting can be read back out of the
    response and checked against what was asked for; Brotli's stream does
    not carry it, and there is nothing to read.

Usage:
    python3 script/bench/bench_memory.py --nginx /path/to/debug/nginx
    python3 script/bench/bench_memory.py --codec brotli --window 16k,32k,64k
    python3 script/bench/bench_memory.py --level 1,3 --window 16k,32k,64k
"""

import argparse
import json
import os
import sys
import tempfile

# test_stream.py lives in script/, one level up from this directory, and
# carries the fixtures, the nginx wrapper and the allocator-trace parser
# these tools are built on.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import test_stream as T


def location(codec, level, window):
    """The path a (level, window) pair is served under, codec included."""
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
    # both filters see every response, and the trace is read per codec, so
    # a stray second encoder would be counted as a second connection.
    others = "\n  ".join(
        f"{other.directive} off;" for other in T.CODECS if other is not codec
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


def measure(nginx, port, path, codec):
    """What one response allocated, or None if it came back uncompressed.

    fetch() opens its own connection per request, so the connection id the
    trace is keyed by identifies this response and nothing else.

    wait_for_encoder_release() rather than reading the log straight after
    fetch(): the encoder outlives the last byte the client sees by one
    filter-loop iteration, so reading immediately races teardown and counts
    a free that has not happened yet as a leak.
    """
    nginx.mark_log()
    _, headers, body = T.fetch(port, path, codec.token)
    if headers.get("content-encoding") != codec.token:
        return None

    stats = T.wait_for_encoder_release(nginx, codec=codec)
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
        # zstd states its window in the frame header, so the effective
        # setting can be read back and checked. Brotli's stream does not
        # carry it; see the module docstring.
        "window": T.frame_window(body) if codec is T.ZSTD else None,
        # Every size the encoder asked for, in order. The peak alone says
        # how much; this says what of - a constant context shell plus one
        # workspace that carries all the variation, at the time of writing.
        "sizes": [int(m.group(3)) for m in codec.alloc_re.finditer(nginx.read_log())],
    }


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

    work = tempfile.mkdtemp(prefix=f"ngx-mem-{codec.name}-")
    html = os.path.join(work, "html")
    os.makedirs(os.path.join(work, "logs"), exist_ok=True)
    for level in levels:
        for window in windows:
            directory = os.path.join(html, location(codec, level, window).strip("/"))
            os.makedirs(directory, exist_ok=True)
            for name, blob in corpus.items():
                with open(os.path.join(directory, name), "wb") as handle:
                    handle.write(blob)

    conf = render_conf(work, args.port, codec, levels, windows)
    nginx = T.Nginx(nginx_bin, work, conf, args.port)
    nginx.start()

    try:
        for level in levels:
            for window in windows:
                print(f"### {label_for(codec, level, window)}")
                print(
                    f"{'file':>12} {'raw':>9} {'frame win':>10} "
                    f"{'allocs':>7} {'peak':>10}   allocations"
                )
                print("-" * 76)

                worst = 0
                for name in names:
                    path = location(codec, level, window) + name
                    result = measure(nginx, args.port, path, codec)
                    if result is None:
                        print(
                            f"{name:>12}   not compressed - check "
                            f"{codec.directive}_types"
                        )
                        continue

                    worst = max(worst, result["peak"])
                    shown = (
                        f"{result['window']:>10,}"
                        if result["window"] is not None
                        else f"{'-':>10}"
                    )
                    print(
                        f"{name:>12} {len(corpus[name]):>9,} {shown} "
                        f"{result['allocs']:>7} {result['peak']:>10,}   "
                        f"{' + '.join(f'{s:,}' for s in result['sizes'])}"
                    )
                    # Not an assertion - test_stream.py owns that - but a
                    # peak measured over a response that never gave its
                    # memory back is not the number this claims to print.
                    if result["leaked"]:
                        print(
                            f"{'':>12}   warning: {result['leaked']:,} bytes "
                            f"still live at teardown; see test_stream.py"
                        )

                if worst:
                    summary.append(
                        {
                            "codec": codec.name,
                            "level": level or "default",
                            "window": window or "default",
                            "peak": worst,
                        }
                    )
                print()
    finally:
        nginx.stop()


def print_summary(rows):
    """The worst peak each configuration reached, which is the number a
    server sizing itself for concurrent responses has to budget from."""
    print("### summary - highest peak over the corpus")
    print(f"{'codec':>8} {'level':>8} {'window':>8} {'peak':>12}")
    print("-" * 40)
    for row in rows:
        print(
            f"{row['codec']:>8} {row['level']:>8} {row['window']:>8} {row['peak']:>12,}"
        )
    print()


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

    names = sorted(corpus)

    summary = []
    for codec in codecs:
        run_codec(codec, args, corpus, names, nginx_bin, summary)

    if len(summary) > 1:
        print_summary(summary)

    if args.json:
        with open(args.json, "w") as handle:
            json.dump(
                {
                    "tool": "bench_memory",
                    "nginx": nginx_bin,
                    "build": version,
                    "rows": summary,
                },
                handle,
                indent=2,
            )
        print(f"wrote {args.json}")


if __name__ == "__main__":
    main()
