#!/usr/bin/env python3
"""Draws the corpus level charts as stand-alone SVGs, chart and legend together.

Two charts on identical axes, so they can be read side by side. Latency runs
left to right and compression level up the side in both; what differs is the
marks. "ratio" sizes and labels each by the compression it achieved, "memory"
by the peak the encoder held.

Nothing is measured here. The numbers come from the JSON that bench_corpus.py
and bench_memory.py write with --json, so a chart is drawn from a run that
actually happened rather than from figures copied out of a terminal, and
redrawing costs nothing:

    python3 script/bench/bench_corpus.py --nginx nginx-bench/objs/nginx \\
        --codec zstd --level 1,2,3,4,5,6 \\
        --json script/bench/results-corpus-zstd.json
    python3 script/bench/bench_memory.py --nginx nginx/objs/nginx \\
        --codec zstd --level 1,2,3,4,5,6 \\
        --json script/bench/results-memory-zstd.json
    python3 script/bench/make_svg.py

Note the two --nginx: latency needs a release build, because a --with-debug one
logs a line per encoder allocation and swamps what is being timed, and peak
memory needs a --with-debug build, because it is read from that same tracing.
Each codec takes a run of its own, the level ranges not being the same.

Every colour is resolved rather than left to a CSS variable and every font
carries a fallback stack, so a file stands on its own in an editor, a viewer,
or an <img>.

    python3 script/bench/make_svg.py [--results DIR] [--out DIR]
"""

from __future__ import annotations

import argparse
import glob
import json
import math
import os
import sys
from collections.abc import Callable
from typing import TypedDict

# One measured (codec, level) pair: latency, the ratio achieved and the
# peak encoder memory it cost. What load() assembles and build() draws.
Point = tuple[str, int, float, float, float]


class Mode(TypedDict):
    """One chart's disagreement with the other - see modes()."""

    radius: Callable[[Point], float]
    label: Callable[[Point], str]
    rule_head: str
    rule_sub: str
    key: str
    key_lo: str
    key_hi: str
    title: str
    desc: str


W, H = 1000, 616
L, R, T, B = 74, 952, 44, 424
MS_MAX, LV_LO, LV_HI = 21, -0.5, 6.5

SANS = ("IBM Plex Sans, ui-sans-serif, system-ui, -apple-system, Segoe UI, "
        "Helvetica, Arial, sans-serif")
MONO = "IBM Plex Mono, ui-monospace, SFMono-Regular, Menlo, Consolas, monospace"

THEMES = {
    "light": dict(panel="#ffffff", ink="#131a21", ink_soft="#45535f", muted="#6b7c8a",
                  rule="#d7dee4", grid="#e4eaef", band="#f1f3f5",
                  zstd="#1f6f8b", brotli="#c0602a"),
    "dark":  dict(panel="#151d23", ink="#e6edf2", ink_soft="#b0c0cc", muted="#8095a4",
                  rule="#26333c", grid="#1f2b33", band="#1b242b",
                  zstd="#56b6d4", brotli="#f0904f"),
}

# Which levels each filter ships with, so the chart can ring them. Read from
# the sources rather than repeated here, since a default that moved and left
# this behind would mislabel the chart rather than break it.
DEFAULT_LEVEL_DEFINE = {
    "zstd": ("module/filter/zstd/ngx_http_pack_zstd_filter.c",
             "NGX_HTTP_PACK_ZSTD_LEVEL_DEFAULT"),
    "brotli": ("module/filter/brotli/ngx_http_pack_brotli_filter.c",
               "NGX_HTTP_PACK_BROTLI_LEVEL_DEFAULT"),
}


def read_defaults(root: str) -> dict[str, int]:
    out: dict[str, int] = {}
    for codec, (path, define) in DEFAULT_LEVEL_DEFINE.items():
        try:
            for line in open(os.path.join(root, path)):
                if line.startswith(f"#define {define}"):
                    out[codec] = int(line.split()[2])
                    break
        except OSError:
            pass
    return out


def load(results_dir: str) -> tuple[list[Point], float, float, dict[str, str]]:
    """Merges the bench JSON into one point per codec and level.

    Latency and ratio come from bench_corpus, peak memory from bench_memory,
    and a point is only drawn where both were measured - a chart with a mark
    missing one of its two dimensions would be quietly wrong rather than
    visibly incomplete.
    """
    points: dict[tuple[str, int], dict[str, float]] = {}
    baselines: list[float] = []
    meta: dict[str, str] = {}

    for path in sorted(glob.glob(os.path.join(results_dir, "results-corpus-*.json"))):
        blob = json.load(open(path))
        meta["corpus"] = blob.get("build", "?")
        for row in blob["rows"]:
            if row["codec"] == "none":
                baselines.append(row["ms"])
                continue
            key = (row["codec"], int(row["level"]))
            points.setdefault(key, {}).update(
                ms=row["ms"], ratio=row["raw"] / row["out"], out=row["out"]
            )

    for path in sorted(glob.glob(os.path.join(results_dir, "results-memory-*.json"))):
        blob = json.load(open(path))
        meta["memory"] = blob.get("build", "?")
        for row in blob["rows"]:
            key = (row["codec"], int(row["level"]))
            points.setdefault(key, {}).update(peak=row["peak"])

    if not points:
        raise SystemExit(
            f"error: no results in {results_dir}. Run bench_corpus.py and "
            f"bench_memory.py with --json first; see the module docstring."
        )

    partial = sorted(k for k, v in points.items() if {"ms", "ratio", "peak"} - set(v))
    if partial:
        missing = ", ".join(f"{c} {lv}" for c, lv in partial)
        raise SystemExit(
            f"error: {missing} was measured by one tool but not the other. "
            f"Both bench_corpus.py and bench_memory.py have to cover the same "
            f"levels, or a mark would be drawn from half a measurement."
        )

    if not baselines:
        raise SystemExit(
            "error: no uncompressed baseline in the corpus results. It is the "
            "row bench_corpus.py writes with codec \"none\"; re-run it."
        )

    # One per codec measured, being the same quantity twice. Averaged, with the
    # spread reported, since two runs of the same thing never land identically.
    baseline = sum(baselines) / len(baselines)
    spread = (
        (max(baselines) - min(baselines)) / baseline if len(baselines) > 1 else 0.0
    )

    data = sorted(
        ((c, lv, v["ms"], v["ratio"], v["peak"]) for (c, lv), v in points.items()),
        key=lambda d: (d[0] != "zstd", d[1]),
    )
    return data, baseline, spread, meta


def bytes_label(n: float) -> str:
    return f"{n / 1048576:.2f} MB" if n >= 1048576 else f"{round(n / 1024)} KB"


def modes(data: list[Point], baseline: float) -> dict[str, Mode]:
    """What the two charts disagree about, and nothing else.

    "ratio" takes its area from ratio - 1 rather than ratio. 1x is a response
    the filter did not shrink, which is the meaningful zero, and anchoring
    there is what makes the span visible: scaled from zero ratio, every mark
    would fall within a fifth of every other.

    "memory" needs no such trick. Zero bytes is a real zero and the span is an
    order of magnitude, so area is proportional to the figure itself.
    """
    ratios: list[float] = [d[3] for d in data]
    peaks: list[float] = [d[4] for d in data]
    return {
        "ratio": Mode(
            radius=lambda d: 8.5 * math.sqrt(d[3] - 1),
            label=lambda d: f"{d[3]:.2f}&#215;",
            rule_head="no compression", rule_sub=f"{baseline:.2f} ms",
            key="mark area &#8733; compression achieved, measured from 1&#215; &#8212; ",
            key_lo=f"{min(ratios):.2f}&#215;", key_hi=f"{max(ratios):.2f}&#215;",
            title="Compression level against latency, zstd and brotli",
            desc="Mark area is proportional to the compression achieved.",
        ),
        "memory": Mode(
            radius=lambda d: 0.0195 * math.sqrt(d[4]),
            label=lambda d: bytes_label(d[4]),
            rule_head="no encoder", rule_sub="0 bytes",
            key="mark area &#8733; peak encoder memory &#8212; ",
            key_lo=bytes_label(min(peaks)), key_hi=bytes_label(max(peaks)),
            title="Peak encoder memory against latency, zstd and brotli",
            desc="Mark area is proportional to the peak memory one response held.",
        ),
    }


def x(ms: float) -> float:
    return L + (ms / MS_MAX) * (R - L)


def y_lev(lv: float) -> float:
    return B - ((lv - LV_LO) / (LV_HI - LV_LO)) * (B - T)


def esc(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def build(
    mode: str,
    m: Mode,
    theme: str,
    data: list[Point],
    baseline: float,
    defaults: dict[str, int],
) -> str:
    c = THEMES[theme]
    o: list[str] = []
    a = o.append

    a(f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" width="{W}" '
      f'height="{H}" font-family="{esc(SANS)}" role="img">')
    a(f'  <title>{m["title"]}</title>')
    a(f'  <desc>Latency for the whole corpus on the horizontal axis, compression level on '
      f'the vertical. {m["desc"]} A vertical rule at {baseline:.2f} ms marks the same '
      f'server with compression switched off.</desc>')
    a(f'  <rect width="{W}" height="{H}" fill="{c["panel"]}"/>')

    a(f'  <rect x="{L}" y="{T}" width="{x(baseline) - L:.1f}" height="{B - T}" '
      f'fill="{c["band"]}"/>')
    for ms in range(0, MS_MAX + 1, 5):
        a(f'  <line x1="{x(ms):.1f}" y1="{T}" x2="{x(ms):.1f}" y2="{B}" '
          f'stroke="{c["grid"]}" stroke-width="1"/>')
        a(f'  <text x="{x(ms):.1f}" y="{B + 22}" text-anchor="middle" '
          f'font-family="{esc(MONO)}" font-size="12" fill="{c["muted"]}">{ms}</text>')
    for lv in range(7):
        a(f'  <line x1="{L}" y1="{y_lev(lv):.1f}" x2="{R}" y2="{y_lev(lv):.1f}" '
          f'stroke="{c["grid"]}" stroke-width="1"/>')
        a(f'  <text x="{L - 12}" y="{y_lev(lv) + 4:.1f}" text-anchor="end" '
          f'font-family="{esc(MONO)}" font-size="12" fill="{c["muted"]}">{lv}</text>')
    a(f'  <line x1="{L}" y1="{B}" x2="{R}" y2="{B}" stroke="{c["rule"]}" stroke-width="1.5"/>')
    a(f'  <line x1="{L}" y1="{T}" x2="{L}" y2="{B}" stroke="{c["rule"]}" stroke-width="1.5"/>')

    a(f'  <line x1="{x(baseline):.1f}" y1="{T}" x2="{x(baseline):.1f}" y2="{B}" '
      f'stroke="{c["ink_soft"]}" stroke-width="2"/>')
    a(f'  <text x="{x(baseline) + 10:.1f}" y="{T + 15}" font-size="12" font-weight="600" '
      f'fill="{c["ink_soft"]}">{m["rule_head"]}</text>')
    a(f'  <text x="{x(baseline) + 10:.1f}" y="{T + 32}" font-family="{esc(MONO)}" '
      f'font-size="12" fill="{c["muted"]}">{m["rule_sub"]}</text>')

    a(f'  <text x="{(L + R) / 2:.1f}" y="482" text-anchor="middle" font-size="12.5" '
      f'font-weight="600" fill="{c["ink_soft"]}">latency for the whole corpus, ms '
      f'&#8212; lower is better</text>')
    a(f'  <text x="18" y="{(T + B) / 2:.1f}" text-anchor="middle" font-size="12.5" '
      f'font-weight="600" fill="{c["ink_soft"]}" '
      f'transform="rotate(-90 18 {(T + B) / 2:.1f})">compression level</text>')

    for codec in ("zstd", "brotli"):
        pts = [d for d in data if d[0] == codec]
        if not pts:
            continue
        col = c[codec]
        line = " ".join(f"{x(d[2]):.1f},{y_lev(d[1]):.1f}" for d in pts)
        a(f'  <polyline points="{line}" fill="none" stroke="{col}" stroke-width="2" '
          f'opacity="0.45"/>')
        for d in pts:
            r = m["radius"](d)
            cx, cy = x(d[2]), y_lev(d[1])
            a(f'  <circle cx="{cx:.1f}" cy="{cy:.1f}" r="{r:.2f}" fill="{col}" '
              f'fill-opacity="0.85" stroke="{c["panel"]}" stroke-width="1.5"/>')
            a(f'  <text x="{cx:.1f}" y="{cy - r - 8:.1f}" text-anchor="middle" '
              f'font-family="{esc(MONO)}" font-size="11.5" font-weight="500" '
              f'fill="{col}">{m["label"](d)}</text>')
            if defaults.get(codec) == d[1]:
                a(f'  <circle cx="{cx:.1f}" cy="{cy:.1f}" r="{r + 5:.2f}" fill="none" '
                  f'stroke="{col}" stroke-width="1" stroke-dasharray="2 2" opacity="0.85"/>')
                a(f'  <text x="{cx:.1f}" y="{cy + r + 18:.1f}" text-anchor="middle" '
                  f'font-family="{esc(MONO)}" font-size="10" font-weight="500" '
                  f'fill="{c["muted"]}">default</text>')

    # Legend, on two rows so the size key is never crowded to fit.
    a(f'  <line x1="{L}" y1="516" x2="{R}" y2="516" stroke="{c["rule"]}" stroke-width="1"/>')
    row1, row2 = 546, 588

    def key_text(tx: float, ty: float, bold: str, rest: str) -> None:
        a(f'  <text x="{tx}" y="{ty}" font-size="13" fill="{c["ink_soft"]}">'
          f'<tspan font-weight="600" fill="{c["ink"]}">{bold}</tspan>{esc(rest)}</text>')

    for cx0, codec in ((L, "zstd"), (L + 210, "brotli")):
        pts = [d for d in data if d[0] == codec]
        if not pts:
            continue
        lo, hi = min(d[1] for d in pts), max(d[1] for d in pts)
        col = c[codec]
        a(f'  <line x1="{cx0}" y1="{row1 - 4}" x2="{cx0 + 26}" y2="{row1 - 4}" '
          f'stroke="{col}" stroke-width="2"/>')
        a(f'  <circle cx="{cx0 + 13}" cy="{row1 - 4}" r="5.5" fill="{col}"/>')
        key_text(cx0 + 36, row1, codec, f" · levels {lo}–{hi}")

    bx = L + 440
    a(f'  <line x1="{bx + 10}" y1="{row1 - 12}" x2="{bx + 10}" y2="{row1 + 4}" '
      f'stroke="{c["ink_soft"]}" stroke-width="2"/>')
    key_text(bx + 26, row1, "no compression", f" · {baseline:.2f} ms")

    # Size key, drawn at the sizes this chart actually uses.
    lo = min(m["radius"](d) for d in data)
    hi = max(m["radius"](d) for d in data)
    a(f'  <circle cx="{L + lo:.1f}" cy="{row2 - 5}" r="{lo:.2f}" fill="none" '
      f'stroke="{c["muted"]}" stroke-width="1.5"/>')
    a(f'  <circle cx="{L + 2 * lo + hi + 14:.1f}" cy="{row2 - 5}" r="{hi:.2f}" fill="none" '
      f'stroke="{c["muted"]}" stroke-width="1.5"/>')
    a(f'  <text x="{L + 2 * lo + 2 * hi + 28:.1f}" y="{row2}" font-size="13" '
      f'fill="{c["ink_soft"]}">{m["key"]}'
      f'<tspan font-weight="600" fill="{c["ink"]}">{m["key_lo"]}</tspan> to '
      f'<tspan font-weight="600" fill="{c["ink"]}">{m["key_hi"]}</tspan></text>')

    a("</svg>")
    return "\n".join(o) + "\n"


def main() -> None:
    here = os.path.dirname(os.path.abspath(__file__))
    root = os.path.dirname(os.path.dirname(here))
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--results", default=here,
                        help="directory holding the bench JSON (default: this one)")
    parser.add_argument("--out", default=here,
                        help="directory to write the SVGs to (default: this one)")
    args = parser.parse_args()

    data, baseline, spread, meta = load(args.results)
    defaults = read_defaults(root)

    print(f"{len(data)} points from {meta.get('corpus', '?')}")
    print(f"baseline {baseline:.2f} ms" + (
        f", the two measurements {spread:.1%} apart" if spread else ""))
    if spread > 0.10:
        print("  warning: that is a wide spread for the same quantity measured\n"
              "  twice; something else was probably using the machine.", file=sys.stderr)
    if defaults:
        print("defaults ringed: " + ", ".join(f"{k} {v}" for k, v in sorted(defaults.items())))

    for mode, m in modes(data, baseline).items():
        for theme in THEMES:
            svg = build(mode, m, theme, data, baseline, defaults)
            path = os.path.join(args.out, f"codec-{mode}-{theme}.svg")
            with open(path, "w") as fh:
                fh.write(svg)
            print(f"  {path}  {len(svg):,} bytes")


if __name__ == "__main__":
    main()
