#!/bin/bash
#
# Re-runs both suites against a build whose output buffer is far
# smaller than anything the module would ship with.
#
# The filter owns one output buffer and refills it round after round,
# so how often a round only partly drains before the next filter
# takes over depends on how big that buffer is. At the compiled-in
# 16 KB a large response takes single-digit rounds and the
# partial-drain, resend and mid-flush paths are reached rarely; at 64
# bytes the same response takes ~1500 and almost every round is a
# partial one. Same code, roughly two hundred times the density of
# the states that are hardest to get right - which is why this runs
# the suites unchanged rather than asserting anything new: their
# round-trip and allocator-balance checks are the assertions, and
# this only changes the conditions they run under.
#
# Note that it does NOT check the compressed bytes against those of a
# normal build. They are not stable enough to compare: a streamed
# response's flush points follow socket timing, so two runs of the
# *same* binary can differ by a few dozen bytes. What must hold, and
# what the suites check, is that whatever comes out decompresses to
# the original.
#
# Required:
#   NGINX_REF   git ref of nginx to build against, as script/build.sh
#
# Overridable:
#   OUT_SIZE    bytes for NGX_HTTP_PACK_ZSTD_OUT_SIZE (default: 64)
#   SANITIZE    1 to build with AddressSanitizer (default: 0)
#   JOBS        parallelism (default: number of processors)
#
set -eux

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [ -z "${NGINX_REF:-}" ]; then
	echo "NGINX_REF must be set, e.g. NGINX_REF=stable-1.30 $0" >&2
	exit 1
fi
OUT_SIZE="${OUT_SIZE:-64}"
SANITIZE="${SANITIZE:-0}"
JOBS="${JOBS:-$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)}"

# A tree of its own, so this never overwrites the objects the normal
# suites run against: the two builds differ only by a -D, and a
# stress binary left sitting in nginx/objs would be invisible.
BUILD="$ROOT/nginx-small-buffer"

# script/build.sh puts libzstd here and nginx links it from there.
if [ ! -f "$ROOT/deps/zstd/out/lib/libzstd.a" ]; then
	echo "build libzstd first: NGINX_REF=$NGINX_REF script/build.sh" >&2
	exit 1
fi

if [ ! -d "$BUILD" ]; then
	git clone --depth 1 --branch "$NGINX_REF" \
		https://github.com/nginx/nginx.git "$BUILD"
fi

# NGX_HTTP_PACK_ZSTD_OUT_SIZE is #ifndef-guarded purely so this can
# reach it. It is not a configuration knob and there is no directive
# behind it - see the comment on the constant.
CC_OPT="-DNGX_HTTP_PACK_ZSTD_OUT_SIZE=$OUT_SIZE"
LD_OPT=""
if [ "$SANITIZE" = "1" ]; then
	CC_OPT="$CC_OPT -fsanitize=address -fno-omit-frame-pointer -g -O1"
	LD_OPT="-fsanitize=address"
fi

# Where the headers and libraries live on this machine; empty
# everywhere they are already on the search path. See the file.
# shellcheck disable=SC1091
. "$ROOT/script/toolchain.sh"
if [ -n "$PACK_CC_OPT" ]; then
	CC_OPT="$CC_OPT $PACK_CC_OPT"
fi
if [ -n "$PACK_LD_OPT" ]; then
	LD_OPT="$LD_OPT $PACK_LD_OPT"
fi

cd "$BUILD"
# --with-debug as in script/build.sh: the streaming suite reads the
# encoder's allocator tracing, and the output-round accounting this
# script exists to stress, out of the debug log.
./auto/configure \
	--prefix="$ROOT/script/test" \
	--with-http_v2_module \
	--with-debug \
	--with-cc-opt="$CC_OPT" \
	--with-ld-opt="$LD_OPT" \
	--add-module="$ROOT"
make -j "$JOBS"

cd "$ROOT"
NGINX_BIN="$BUILD/objs/nginx" script/run-tests.sh
# --max-out-size turns "the -D reached the compiler" into a checked
# precondition. Without it a plumbing regression would silently
# degrade this whole script into a second run of the normal suite.
python3 script/test_stream.py \
	--nginx "$BUILD/objs/nginx" \
	--max-out-size "$OUT_SIZE"
