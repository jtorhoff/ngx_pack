#!/bin/bash
#
# Re-runs both suites against a build whose output buffers are far
# smaller than anything either filter would ship with.
#
# The filters refill their output buffers round after round, so how
# often a round only partly drains before the next filter takes over
# depends on how big those buffers are. At the compiled-in 16 KB a
# large response takes single-digit rounds and the partial-drain,
# resend and mid-flush paths are reached rarely; at 64 bytes the same
# response takes ~1500 and almost every round is a partial one. Same
# code, roughly two hundred times the density of the states that are
# hardest to get right - which is why this runs the suites unchanged
# rather than asserting anything new: their round-trip and
# allocator-balance checks are the assertions, and this only changes
# the conditions they run under.
#
# Both encoders are shrunk in the one build, rather than a tree
# apiece: the two -D flags are independent, the suite covers both
# codecs in a single run, and a second nginx build would double the
# slowest part of this for nothing.
#
# For Brotli this is the only cover left for one specific failure.
# A committed buffer shorter than nginx's postpone_output (1460
# bytes) is held by the write filter until more arrives; if the
# encoder cannot refill in the meantime, neither side moves and the
# response hangs. The output buffers carry "recycled" to prevent
# exactly that. Since pack_brotli_window's floor rose to 16k no
# configuration can produce blocks that small any more, so a 64-byte
# buffer here is what still reaches the condition - drop "recycled"
# and this run hangs where the ordinary suite passes.
#
# Note that it does NOT check the compressed bytes against those of a
# normal build. They are not stable enough to compare: a streamed
# response's flush points follow socket timing, so two runs of the
# *same* binary can differ by a few dozen bytes. What must hold, and
# what the suites check, is that whatever comes out decompresses to
# the original.
#
# Required:
#   NGINX_REF   git ref of nginx to build against, as script/build/build.sh
#
# Overridable:
#   OUT_SIZE    bytes for both encoders' BUFFER_SIZE_DEFAULT
#               (default: 64)
#   SANITIZE    1 to build with AddressSanitizer (default: 0)
#   JOBS        parallelism (default: number of processors)
#
set -eux

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
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

# script/build/build.sh puts both libraries here and nginx links them from
# there. Checked separately so the message names the one that is
# missing rather than sending you to rebuild what you already have.
if [ ! -f "$ROOT/deps/zstd/out/lib/libzstd.a" ]; then
	echo "build libzstd first: NGINX_REF=$NGINX_REF script/build/build.sh" >&2
	exit 1
fi
if [ ! -f "$ROOT/deps/brotli/out/libbrotlienc.a" ]; then
	echo "build libbrotlienc first: NGINX_REF=$NGINX_REF script/build/build.sh" >&2
	exit 1
fi

if [ ! -d "$BUILD" ]; then
	git clone --depth 1 --branch "$NGINX_REF" \
		https://github.com/nginx/nginx.git "$BUILD"
fi

# Both BUFFER_SIZE_DEFAULTs are #ifndef-guarded purely so this can
# reach them. They move what the buffers directives fall back to,
# rather than what those directives can say: 64 bytes is far below the
# 16k floor each one enforces, and deliberately so - the bounds are on
# what a configuration may ask for, and this replaces the value no
# configuration named. A location that does name a size still gets the
# size it named, which is why the suite's own config leaves the default
# alone almost everywhere.
CC_OPT="-DNGX_HTTP_PACK_ZSTD_BUFFER_SIZE_DEFAULT=$OUT_SIZE"
CC_OPT="$CC_OPT -DNGX_HTTP_PACK_BROTLI_BUFFER_SIZE_DEFAULT=$OUT_SIZE"
LD_OPT=""
if [ "$SANITIZE" = "1" ]; then
	CC_OPT="$CC_OPT -fsanitize=address -fno-omit-frame-pointer -g -O1"
	LD_OPT="-fsanitize=address"
fi

# Where the headers and libraries live on this machine; empty
# everywhere they are already on the search path. See the file.
# shellcheck disable=SC1091
. "$ROOT/script/build/toolchain.sh"
if [ -n "$PACK_CC_OPT" ]; then
	CC_OPT="$CC_OPT $PACK_CC_OPT"
fi
if [ -n "$PACK_LD_OPT" ]; then
	LD_OPT="$LD_OPT $PACK_LD_OPT"
fi

cd "$BUILD"
# --with-debug as in script/build/build.sh: the streaming suite reads the
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
NGINX_BIN="$BUILD/objs/nginx" script/tests/basic/run-tests.sh
# --max-out-size turns "the -D reached the compiler" into a checked
# precondition. Without it a plumbing regression would silently
# degrade this whole script into a second run of the normal suite.
python3 script/tests/stream/test_stream.py \
	--nginx "$BUILD/objs/nginx" \
	--max-out-size "$OUT_SIZE"
