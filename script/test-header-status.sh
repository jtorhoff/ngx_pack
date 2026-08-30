#!/bin/bash
#
# Builds an nginx carrying this module plus the test-only filter in
# script/fault_filter, and runs script/test_header_status.py against
# it.
#
# The fault filter returns an HTTP status from its header filter, which
# no stock nginx module does on a response of unknown length - so
# without it, ngx_http_zstd_filter_prepare's "header_rc > NGX_OK"
# branch cannot be reached, and cannot be tested.
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

BUILD="$ROOT/nginx-fault"

if [ ! -f "$ROOT/deps/zstd/out/lib/libzstd.a" ]; then
	echo "build libzstd first: NGINX_REF=$NGINX_REF script/build.sh" >&2
	exit 1
fi

if [ ! -d "$BUILD" ]; then
	git clone --depth 1 --branch "$NGINX_REF" \
		https://github.com/nginx/nginx.git "$BUILD"
fi

cd "$BUILD"
# --with-debug so the test can read the encoder's allocator trace out
# of the debug log, which is how it sees whether the context was left
# live behind the rejected response.
#
# The fault filter is added first only for tidiness; its own config
# moves it into place in HTTP_FILTER_MODULES regardless of the order
# the two addons are given in.
configure_opts=(
	--prefix="$ROOT/script/test"
	--with-http_v2_module
	--with-debug
	--add-module="$ROOT/script/fault_filter"
	--add-module="$ROOT"
)

# Where the headers and libraries live on this machine; empty
# everywhere they are already on the search path. See the file.
# shellcheck disable=SC1091
. "$ROOT/script/toolchain.sh"
if [ -n "$PACK_CC_OPT" ]; then
	configure_opts+=(--with-cc-opt="$PACK_CC_OPT")
fi
if [ -n "$PACK_LD_OPT" ]; then
	configure_opts+=(--with-ld-opt="$PACK_LD_OPT")
fi

./auto/configure "${configure_opts[@]}"
make -j "$JOBS"

cd "$ROOT"
python3 script/test_header_status.py "$BUILD/objs/nginx"
