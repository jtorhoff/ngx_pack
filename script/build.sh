#!/bin/bash
#
# Builds nginx with both zstd modules.
#
# Required:
#   NGINX_REF   git ref of nginx to build against, e.g.
#               stable-1.30. Deliberately without a default, so
#               the ref is named in exactly one place: the
#               workflow-level env in .github/workflows/ci.yml.
#
# Overridable:
#   JOBS        parallelism (default: number of processors)
#   WITH_DEBUG  1 (default) to configure --with-debug; 0 for a
#               release build - see the configure call below
#
set -eux

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Checked here rather than left to git, which reports an unset ref
# as the baffling "fatal: Remote branch  not found in upstream
# origin".
if [ -z "${NGINX_REF:-}" ]; then
	echo "NGINX_REF must be set, e.g. NGINX_REF=stable-1.30 $0" >&2
	exit 1
fi
JOBS="${JOBS:-$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)}"

# zstd first: nginx links -lzstd out of deps/zstd/out, so the
# library has to exist before nginx is built. Static, to keep the
# test runs free of LD_LIBRARY_PATH handling; multithreading and
# legacy-format decoding are both off, since neither is used here -
# see PORTING.md. The "zstd" target pulls in the library and adds the
# command line tool, which the shell suite decompresses responses
# with.
cmake -S "$ROOT/deps/zstd/build/cmake" -B "$ROOT/deps/zstd/out" \
	-DCMAKE_BUILD_TYPE=Release \
	-DZSTD_BUILD_STATIC=ON -DZSTD_BUILD_SHARED=OFF \
	-DZSTD_BUILD_PROGRAMS=ON \
	-DZSTD_MULTITHREAD_SUPPORT=OFF \
	-DZSTD_LEGACY_SUPPORT=OFF
cmake --build "$ROOT/deps/zstd/out" --target zstd -j "$JOBS"

if [ ! -d "$ROOT/nginx" ]; then
	git clone --depth 1 --branch "$NGINX_REF" \
		https://github.com/nginx/nginx.git "$ROOT/nginx"
fi

cd "$ROOT/nginx"
# --with-debug is the default, and deliberate: without it the
# streaming suite skips its window and memory checks, which read the
# encoder's allocator tracing out of the debug log.
#
# WITH_DEBUG=0 drops it, which is the only way to compile the code
# that NGX_DEBUG hides. ngx_log_debug* expands to nothing there, so a
# variable read only by a debug call becomes set-but-unused and
# -Werror rejects it - a break every --with-debug build in CI would
# wave through. The release job in .github/workflows/ci.yml exists
# for exactly that, and this is how it asks for it.
debug_flag="--with-debug"
if [ "${WITH_DEBUG:-1}" = "0" ]; then
	debug_flag=""
fi
# Unquoted on purpose: empty must expand to no argument at all, not
# to an empty one, which configure would reject.
# shellcheck disable=SC2086
./auto/configure \
	--prefix="$ROOT/script/test" \
	--with-http_v2_module \
	$debug_flag \
	--add-module="$ROOT"
make -j "$JOBS"
