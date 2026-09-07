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
#   DEPS_ONLY   1 to build the vendored libraries and stop, leaving
#               nginx alone. For a caller that needs nginx configured
#               its own way - the sanitizer jobs in
#               .github/workflows/ci.yml - which would otherwise carry
#               a second copy of how the libraries are built. That
#               copy is what made a Brotli submodule invisible to
#               those jobs once already. NGINX_REF is not required
#               here, nothing being cloned.
#
set -eux

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DEPS_ONLY="${DEPS_ONLY:-0}"
# Checked here rather than left to git, which reports an unset ref
# as the baffling "fatal: Remote branch  not found in upstream
# origin".
if [ "$DEPS_ONLY" != 1 ] && [ -z "${NGINX_REF:-}" ]; then
	echo "NGINX_REF must be set, e.g. NGINX_REF=stable-1.30 $0" >&2
	exit 1
fi
JOBS="${JOBS:-$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)}"

# Both libraries below are built by cmake, and on macOS cmake itself
# may be an Intel binary - Homebrew installs one under /usr/local on
# an Apple Silicon machine. Running under Rosetta it hands that same
# x86_64 personality to the compiler it spawns, so an unqualified
# build produces an Intel library on an arm64 host, and nginx then
# silently links whatever the system happens to provide instead. Ask
# the compiler nginx will use rather than the kernel: uname reports
# the personality, cc -dumpmachine reports the truth.
CMAKE_ARCH=()
if [ "$(uname -s)" = "Darwin" ]; then
	CMAKE_ARCH=(-DCMAKE_OSX_ARCHITECTURES="$(cc -dumpmachine | cut -d- -f1)")
fi

# zstd first: nginx links -lzstd out of deps/zstd/out, so the
# library has to exist before nginx is built. Static, to keep the
# test runs free of LD_LIBRARY_PATH handling; multithreading and
# legacy-format decoding are both off, since neither is used here:
# ZSTD_c_nbWorkers is pinned to 0 by the filter, and nothing this
# serves predates the modern frame format. The "zstd" target pulls in
# the library and adds the command line tool, which the shell suite
# decompresses responses with.
cmake -S "$ROOT/deps/zstd/build/cmake" -B "$ROOT/deps/zstd/out" \
	"${CMAKE_ARCH[@]}" \
	-DCMAKE_BUILD_TYPE=Release \
	-DZSTD_BUILD_STATIC=ON -DZSTD_BUILD_SHARED=OFF \
	-DZSTD_BUILD_PROGRAMS=ON \
	-DZSTD_MULTITHREAD_SUPPORT=OFF \
	-DZSTD_LEGACY_SUPPORT=OFF
cmake --build "$ROOT/deps/zstd/out" --target zstd -j "$JOBS"

# Brotli, on the same terms as zstd above: static, release, and no
# command line tools, since nothing here shells out to one. Building
# "brotlienc" pulls in brotlicommon, which is the other half of what
# the filter links. "brotlidec" is not something the filter itself
# ever needs - this module only ever compresses - but
# script/fuzz/fuzz_brotli_encoder.c's round-trip oracle does, the
# same way the "zstd" target above carries the CLI the shell suite
# decompresses with.
cmake -S "$ROOT/deps/brotli" -B "$ROOT/deps/brotli/out" \
	"${CMAKE_ARCH[@]}" \
	-DCMAKE_BUILD_TYPE=Release \
	-DBUILD_SHARED_LIBS=OFF \
	-DBROTLI_BUILD_TOOLS=OFF \
	-DBROTLI_DISABLE_TESTS=ON
cmake --build "$ROOT/deps/brotli/out" --target brotlienc brotlidec -j "$JOBS"

if [ "$DEPS_ONLY" = 1 ]; then
	exit 0
fi

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
#
# Collected into an array rather than a string so that an option
# either appears or does not: an empty one expands to an empty
# argument, which configure rejects.
configure_opts=(
	--prefix="$ROOT/script/test"
	--with-http_v2_module
	--add-module="$ROOT"
)
if [ "${WITH_DEBUG:-1}" != "0" ]; then
	configure_opts+=(--with-debug)
fi

# Where the headers and libraries live on this machine; empty
# everywhere they are already on the search path. See the file.
# shellcheck disable=SC1091
. "$ROOT/script/build/toolchain.sh"
if [ -n "$PACK_CC_OPT" ]; then
	configure_opts+=(--with-cc-opt="$PACK_CC_OPT")
fi
if [ -n "$PACK_LD_OPT" ]; then
	configure_opts+=(--with-ld-opt="$PACK_LD_OPT")
fi

./auto/configure "${configure_opts[@]}"
make -j "$JOBS"
