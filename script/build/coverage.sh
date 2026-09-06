#!/bin/bash
#
# Builds one nginx carrying every fault hook and clang's source-based
# coverage instrumentation, runs every suite against it, and reports
# per-file coverage for the module alone. Report-only: nothing here
# fails the build, and printing the numbers is the whole job. Whether
# to gate on any of them is a separate decision, made once there is a
# real number to look at.
#
# One binary rather than one per suite: the header-status filter only
# activates for a directive the other suites' confs never set, and
# the OOM hook only refuses an allocation when PACK_ZSTD_FAULT_AFTER
# is set, which only test_oom.py's own scenarios do - so carrying
# both costs the ordinary suites nothing, and every request from every
# suite lands in the same profile.
#
# Not covered: script/tests/stream/test-small-buffer.sh, which needs
# its own -D flags for both encoders' buffer size and would need a
# build of its own to instrument alongside these.
#
# Required:
#   NGINX_REF   git ref of nginx to build against, as script/build/build.sh
#
# Overridable:
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
JOBS="${JOBS:-$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)}"
LLVM_PROFDATA="${LLVM_PROFDATA:-llvm-profdata}"
LLVM_COV="${LLVM_COV:-llvm-cov}"

BUILD="$ROOT/nginx-coverage"
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

rm -rf "$COV"
mkdir -p "$COV"

CC_OPT="-DNGX_HTTP_PACK_ZSTD_FAULT_INJECT=1"
CC_OPT="$CC_OPT -fprofile-instr-generate -fcoverage-mapping"
LD_OPT="-fprofile-instr-generate"

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
# CC must be a clang whose compiler-rt profile runtime is installed -
# the same requirement script/fuzz/build.sh has for its sanitizers,
# and the same fix (libclang-rt-dev on Debian and Ubuntu).
CC="${CC:-clang}" ./auto/configure \
	--prefix="$ROOT/script/test" \
	--with-http_v2_module \
	--with-debug \
	--with-cc-opt="$CC_OPT" \
	--with-ld-opt="$LD_OPT" \
	--add-module="$ROOT/script/tests/header_status/fault_filter" \
	--add-module="$ROOT"
make -j "$JOBS"

cd "$ROOT"
NGINX_BIN="$BUILD/objs/nginx"

script/tests/basic/prepare-tests.sh

echo "### static files and Accept-Encoding"
LLVM_PROFILE_FILE="$COV/basic-%p.profraw" NGINX_BIN="$NGINX_BIN" \
	script/tests/basic/run-tests.sh

echo "### streaming responses and encoder lifetime"
LLVM_PROFILE_FILE="$COV/stream-%p.profraw" \
	python3 script/tests/stream/test_stream.py --nginx "$NGINX_BIN"

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
