#!/bin/bash
#
# Builds one nginx carrying every fault hook and clang's source-based
# coverage instrumentation, runs every suite against it, builds a
# second nginx instrumented the same way but with both encoders' output
# buffers shrunk to OUT_SIZE, runs the streaming suite against that one
# too, and reports per-file coverage for the module alone over the
# combined profile. Report-only: nothing here fails the build, and
# printing the numbers is the whole job. Whether to gate on any of them
# is a separate decision, made once there is a real number to look at.
#
# One ordinary binary rather than one per suite: the header-status
# filter only activates for a directive the other suites' confs never
# set, and the OOM hook only refuses an allocation when
# PACK_ZSTD_FAULT_AFTER is set, which only test_oom.py's own scenarios
# do - so carrying both costs the ordinary suites nothing, and every
# request from every suite lands in the same profile.
#
# The small-buffer binary is a second tree rather than a third -D on
# the first: BUFFER_SIZE_DEFAULT is read at compile time (see
# script/tests/stream/test-small-buffer.sh, which this mirrors), so an
# ordinary-size run and a shrunk one cannot share a binary. It is worth
# the extra build anyway - the repeat-directive path in both encoders,
# where a flush or end call does not finish in one output round and
# has to resume the next, needs many more rounds per response than an
# ordinary-size buffer ever produces, and stays unreached without it.
#
# Required:
#   NGINX_REF   git ref of nginx to build against, as script/build/build.sh
#
# Overridable:
#   OUT_SIZE       bytes for both encoders' BUFFER_SIZE_DEFAULT in the
#                  second build (default: 64, as test-small-buffer.sh)
#   JOBS           parallelism (default: number of processors)
#   LLVM_PROFDATA  tool to merge raw profiles with (default: llvm-profdata)
#   LLVM_COV       tool to report coverage with (default: llvm-cov)
#
set -eu

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
if [ -z "${NGINX_REF:-}" ]; then
	echo "NGINX_REF must be set, e.g. NGINX_REF=stable-1.30 $0" >&2
	exit 1
fi
OUT_SIZE="${OUT_SIZE:-64}"
JOBS="${JOBS:-$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)}"
LLVM_PROFDATA="${LLVM_PROFDATA:-llvm-profdata}"
LLVM_COV="${LLVM_COV:-llvm-cov}"

BUILD="$ROOT/nginx-coverage"
BUILD_SMALL="$ROOT/nginx-coverage-small"
COV="$ROOT/coverage-data"

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
if [ ! -d "$BUILD_SMALL" ]; then
	git clone --depth 1 --branch "$NGINX_REF" \
		https://github.com/nginx/nginx.git "$BUILD_SMALL"
fi

rm -rf "$COV"
mkdir -p "$COV"

BASE_CC_OPT="-fprofile-instr-generate -fcoverage-mapping"
BASE_LD_OPT="-fprofile-instr-generate"

# Where the headers and libraries live on this machine; empty
# everywhere they are already on the search path. See the file.
# shellcheck disable=SC1091
. "$ROOT/script/build/toolchain.sh"
if [ -n "$PACK_CC_OPT" ]; then
	BASE_CC_OPT="$BASE_CC_OPT $PACK_CC_OPT"
fi
if [ -n "$PACK_LD_OPT" ]; then
	BASE_LD_OPT="$BASE_LD_OPT $PACK_LD_OPT"
fi

cd "$BUILD"
# CC must be a clang whose compiler-rt profile runtime is installed -
# the same requirement script/fuzz/build.sh has for its sanitizers,
# and the same fix (libclang-rt-dev on Debian and Ubuntu).
CC="${CC:-clang}" ./auto/configure \
	--prefix="$ROOT/script/test" \
	--with-http_v2_module \
	--with-debug \
	--with-cc-opt="-DNGX_HTTP_PACK_ZSTD_FAULT_INJECT=1 $BASE_CC_OPT" \
	--with-ld-opt="$BASE_LD_OPT" \
	--add-module="$ROOT/script/tests/header_status/fault_filter" \
	--add-module="$ROOT"
make -j "$JOBS"

# The second tree, buffers shrunk - see the comment at the top for
# why this cannot share a binary with the one above. Neither the OOM
# hook nor the header-status filter is needed here: this one only
# ever runs the streaming suite.
cd "$BUILD_SMALL"
SMALL_CC_OPT="-DNGX_HTTP_PACK_ZSTD_BUFFER_SIZE_DEFAULT=$OUT_SIZE"
SMALL_CC_OPT="$SMALL_CC_OPT -DNGX_HTTP_PACK_BROTLI_BUFFER_SIZE_DEFAULT=$OUT_SIZE"
CC="${CC:-clang}" ./auto/configure \
	--prefix="$ROOT/script/test" \
	--with-http_v2_module \
	--with-debug \
	--with-cc-opt="$SMALL_CC_OPT $BASE_CC_OPT" \
	--with-ld-opt="$BASE_LD_OPT" \
	--add-module="$ROOT"
make -j "$JOBS"

cd "$ROOT"
NGINX_BIN="$BUILD/objs/nginx"
NGINX_BIN_SMALL="$BUILD_SMALL/objs/nginx"

echo "### streaming responses and encoder lifetime"
LLVM_PROFILE_FILE="$COV/stream-%p.profraw" \
	python3 script/tests/stream/test_stream.py --nginx "$NGINX_BIN"

echo "### streaming responses at a $OUT_SIZE-byte output buffer"
LLVM_PROFILE_FILE="$COV/stream-small-%p.profraw" \
	python3 script/tests/stream/test_stream.py \
		--nginx "$NGINX_BIN_SMALL" --max-out-size "$OUT_SIZE"

echo "### out-of-memory paths"
LLVM_PROFILE_FILE="$COV/oom-%p.profraw" \
	python3 script/tests/oom/test_oom.py "$NGINX_BIN"

echo "### rejected-header handling"
LLVM_PROFILE_FILE="$COV/header_status-%p.profraw" \
	python3 script/tests/header_status/test_header_status.py "$NGINX_BIN"

"$LLVM_PROFDATA" merge -sparse "$COV"/*.profraw -o "$COV/merged.profdata"

# --with-cc-opt applies to every file nginx compiles, so its own ~150
# carry mapping data too; naming just the five this repository owns
# is what keeps the report to what it is actually about, the same
# philosophy script/build/analyze.sh uses for the static analyser.
echo
echo "### coverage - module sources only"
"$LLVM_COV" report "$NGINX_BIN" -instr-profile="$COV/merged.profdata" \
	"$ROOT/module/filter/zstd/ngx_http_pack_zstd_filter.c" \
	"$ROOT/module/filter/zstd/ngx_http_pack_zstd_encoder.c" \
	"$ROOT/module/filter/brotli/ngx_http_pack_brotli_filter.c" \
	"$ROOT/module/filter/brotli/ngx_http_pack_brotli_encoder.c" \
	"$ROOT/module/static/ngx_http_pack_static.c"
