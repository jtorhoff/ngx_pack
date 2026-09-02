#!/bin/bash
#
# Builds an nginx carrying this module with its allocation-fault hook
# compiled in, and runs script/test_oom.py against it.
#
# The hook is guarded by NGX_HTTP_PACK_ZSTD_FAULT_INJECT and defined
# nowhere else - script/build.sh does not define it, so a shipping
# binary has none of this in it. Without the hook the out-of-memory
# branches cannot be reached: a test has no way to make malloc fail
# for one module and not the rest of the worker.
#
# --with-debug because the suite reads the encoder's allocator trace to
# see that a refused allocation leaves nothing behind.
#
# Required:
#   NGINX_REF   git ref of nginx to build against, as script/build.sh
#
# Overridable:
#   JOBS        parallelism (default: number of processors)
#
set -eux

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [ -z "${NGINX_REF:-}" ]; then
	echo "NGINX_REF must be set, e.g. NGINX_REF=stable-1.30 $0" >&2
	exit 1
fi
JOBS="${JOBS:-$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)}"

BUILD="$ROOT/nginx-oom"

if [ ! -f "$ROOT/deps/zstd/out/lib/libzstd.a" ]; then
	echo "build libzstd first: NGINX_REF=$NGINX_REF script/build.sh" >&2
	exit 1
fi

if [ ! -d "$BUILD" ]; then
	git clone --depth 1 --branch "$NGINX_REF" \
		https://github.com/nginx/nginx.git "$BUILD"
fi

cd "$BUILD"

CC_OPT="-DNGX_HTTP_PACK_ZSTD_FAULT_INJECT=1"

# Where the headers and libraries live on this machine; empty
# everywhere they are already on the search path. See the file.
# shellcheck disable=SC1091
. "$ROOT/script/toolchain.sh"
if [ -n "$PACK_CC_OPT" ]; then
	CC_OPT="$CC_OPT $PACK_CC_OPT"
fi

configure_opts=(
	--prefix="$ROOT/script/test"
	--with-http_v2_module
	--with-debug
	--with-cc-opt="$CC_OPT"
	--add-module="$ROOT"
)
if [ -n "$PACK_LD_OPT" ]; then
	configure_opts+=(--with-ld-opt="$PACK_LD_OPT")
fi

./auto/configure "${configure_opts[@]}"
make -j "$JOBS"

cd "$ROOT"
python3 script/test_oom.py "$BUILD/objs/nginx"
