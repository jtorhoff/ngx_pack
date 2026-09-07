#!/bin/bash
#
# Builds the libFuzzer targets in this directory.
#
# Requires nginx to have been configured already, because the
# targets include nginx's headers and compile its ngx_string.c -
# script/build/build.sh does that.
#
# Overridable:
#   CC        clang to build with. Must be a clang whose libFuzzer
#             runtime is installed - Apple's does not ship one at
#             all (brew install llvm), and on Debian and Ubuntu it
#             is packaged apart from the compiler
#             (libclang-rt-dev).
#   NGX_OBJS  nginx build directory to take the generated headers
#             from (default: nginx/objs)
#
set -eu

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT="$ROOT/script/fuzz/out"
NGX="$ROOT/nginx"
NGX_OBJS="${NGX_OBJS:-$NGX/objs}"

if [ ! -f "$NGX_OBJS/ngx_auto_config.h" ]; then
	echo "no nginx build in $NGX_OBJS; run script/build/build.sh first" >&2
	exit 1
fi

# ngx_string.c is compiled from source rather than taken as a
# prebuilt object from $NGX_OBJS. AddressSanitizer finds an overread
# by instrumenting the load that performs it, so a function linked
# in uninstrumented is invisible to it - and ngx_strlcasestrn, where
# a bad bound would actually bite, lives here.
STRING_C="$NGX/src/core/ngx_string.c"
if [ ! -f "$STRING_C" ]; then
	echo "no $STRING_C; run script/build/build.sh first" >&2
	exit 1
fi

CC="${CC:-clang}"
EXTRA_LDFLAGS=""
UNAME="$(uname -s)"

# A real target, not an empty translation unit: libFuzzer supplies
# main() and needs LLVMFuzzerTestOneInput, so linking nothing always
# fails and would make the probe report "no libFuzzer" everywhere.
probe="$(mktemp -t ngxzstdfuzz.XXX).c"
cat >"$probe" <<'PROBE'
#include <stddef.h>
#include <stdint.h>
int LLVMFuzzerTestOneInput(const uint8_t *d, size_t s)
{
	(void) d;
	(void) s;
	return 0;
}
PROBE
trap 'rm -f "$probe" "$probe.out"' EXIT

if ! "$CC" -fsanitize=fuzzer "$probe" -o "$probe.out" >/dev/null 2>&1
then
	# Homebrew's libFuzzer runtime is built against Homebrew's own
	# libc++ and will not link against the system one, so point the
	# linker at it.
	found=""
	for llvm in /opt/homebrew/opt/llvm /usr/local/opt/llvm; do
		[ -x "$llvm/bin/clang" ] || continue
		if "$llvm/bin/clang" -fsanitize=fuzzer "$probe" -o "$probe.out" \
			-L"$llvm/lib/c++" -Wl,-rpath,"$llvm/lib/c++" >/dev/null 2>&1; then
			CC="$llvm/bin/clang"
			EXTRA_LDFLAGS="-L$llvm/lib/c++ -Wl,-rpath,$llvm/lib/c++"
			found=yes
			break
		fi
	done
	if [ -z "$found" ]; then
		# Show what actually went wrong rather than guessing at it: the
		# compiler accepts -fsanitize=fuzzer whether or not the runtime is
		# installed, and only says so at link time. Capped because a libc++
		# mismatch on macOS reports every unresolved symbol, mangled, and
		# would bury the advice below under hundreds of lines.
		echo "$CC cannot link a libFuzzer target:" >&2
		probe_err="$("$CC" -fsanitize=fuzzer "$probe" \
			-o "$probe.out" 2>&1 || true)"
		echo "$probe_err" | head -6 | sed 's/^/  /' >&2
		if [ "$(echo "$probe_err" | wc -l)" -gt 6 ]; then
			echo "  ... (truncated)" >&2
		fi
		case "$UNAME" in
		Linux)
			echo "The runtime is packaged apart from the compiler; on" >&2
			echo "Debian and Ubuntu it is libclang-rt-dev." >&2
			;;
		Darwin)
			echo "Apple's clang does not ship libFuzzer at all:" >&2
			echo "brew install llvm." >&2
			;;
		esac
		echo "Otherwise set CC to a clang that has it." >&2
		exit 1
	fi
fi

INCS="-I $NGX_OBJS \
 -I $NGX/src/core -I $NGX/src/event -I $NGX/src/event/modules \
 -I $NGX/src/event/quic -I $NGX/src/os/unix -I $NGX/src/http \
 -I $NGX/src/http/modules -I $NGX/src/http/v2 \
 -I $ROOT/module/filter/zstd -I $ROOT/module/filter/brotli \
 -I $ROOT/deps/zstd/lib -I $ROOT/deps/brotli/c/include"

# ngx_palloc.c, ngx_buf.c and ngx_alloc.c: what
# fuzz_zstd_encoder.c and fuzz_brotli_encoder.c need for a real pool
# and real buffer chains around the two encoders - see those files'
# own comments for why a stand-in pool would test the wrong thing,
# the same reasoning ngx_string.c below already follows.
# ngx_log_stub.c stands in for ngx_log.c itself: the real
# ngx_log_error_core is one function in a file whose others
# (ngx_log_set_log, ngx_log_open_default) reach ngx_conf_file.c and
# ngx_syslog.c, and the linker cannot take one function without the
# rest - see ngx_log_stub.c for why never actually calling it is
# fine. Built into every target rather than picked per target:
# nothing here references what it does not use, and it keeps this
# loop the one place a new fuzz_*.c has to be dropped to build.
CORE_SRCS="$NGX/src/core/ngx_palloc.c $NGX/src/core/ngx_buf.c"
CORE_SRCS="$CORE_SRCS $NGX/src/os/unix/ngx_alloc.c"
CORE_SRCS="$CORE_SRCS $ROOT/script/fuzz/ngx_log_stub.c"
ENCODER_SRCS="$ROOT/module/filter/zstd/ngx_http_pack_zstd_encoder.c"
ENCODER_SRCS="$ENCODER_SRCS $ROOT/module/filter/brotli/ngx_http_pack_brotli_encoder.c"
ENCODER_LIBS="$ROOT/deps/zstd/out/lib/libzstd.a"
ENCODER_LIBS="$ENCODER_LIBS $ROOT/deps/brotli/out/libbrotlienc.a"
# libbrotlidec.a: nothing the filter itself links, only
# fuzz_brotli_encoder.c's round-trip oracle - see that file and
# script/build/build.sh for why this is the one place it is built.
ENCODER_LIBS="$ENCODER_LIBS $ROOT/deps/brotli/out/libbrotlidec.a"
ENCODER_LIBS="$ENCODER_LIBS $ROOT/deps/brotli/out/libbrotlicommon.a"

# These come from nginx's own build rather than from the headers, so
# a target compiled with its own flags has to repeat them. Without
# _GNU_SOURCE glibc leaves struct in6_pktinfo incomplete, and
# ngx_event_udp.h holds one as a field, so the include chain does
# not compile at all:
#
#   error: field has incomplete type 'struct in6_pktinfo'
#
# See auto/os/linux, which passes both. Darwin declares the struct
# unconditionally and needs neither, which is why this only bites
# on CI.
case "$UNAME" in
Linux) PLATFORM_DEFS="-D_GNU_SOURCE -D_FILE_OFFSET_BITS=64" ;;
*) PLATFORM_DEFS="" ;;
esac

# PCRE and OpenSSL headers reach ngx_core.h on some builds; ask
# pkg-config and shrug if it is not there.
INCS="$INCS $(pkg-config --cflags libpcre2-8 openssl 2>/dev/null ||
	true)"
for p in /opt/homebrew/opt/pcre2 /opt/homebrew/opt/openssl@3 \
	/usr/local/opt/pcre2 /usr/local/opt/openssl@3; do
	[ -d "$p/include" ] && INCS="$INCS -I$p/include"
done

# -g for symbolized stacks; ASan and UBSan are what actually decide
# whether an input was a finding. Undefined behaviour is fatal so it
# cannot pass silently.
SAN="-fsanitize=fuzzer,address,undefined"
SAN="$SAN -fno-sanitize-recover=undefined"

# macOS's newer linker (default since Xcode 15) rejects some debug
# info a sufficiently new Homebrew clang emits when several
# translation units are linked together - "invalid r_symbolnum=N" at
# link time, nothing wrong in any one object file on its own. The
# classic linker still accepts it; deprecated, but there is no other
# workaround short of stripping -g. A no-op everywhere else, since
# only Apple's linker understands the flag at all.
LD_WORKAROUND=""
if [ "$UNAME" = "Darwin" ]; then
	LD_WORKAROUND="-Wl,-ld_classic"
fi

mkdir -p "$OUT"
for src in "$ROOT"/script/fuzz/fuzz_*.c; do
	name="$(basename "$src" .c)"

	# CORE_SRCS and friends are for the encoder targets alone:
	# fuzz_accept_encoding.c predates them and carries its own
	# minimal ngx_alloc/ngx_pnalloc stand-ins, which would collide
	# with the real ones these link in ("duplicate symbol"). Matched
	# by name rather than linking both into everything, so a target
	# that does not want this stays exactly as it was.
	EXTRA_SRCS=""
	EXTRA_LIBS=""
	case "$name" in
	*_encoder)
		EXTRA_SRCS="$CORE_SRCS $ENCODER_SRCS"
		EXTRA_LIBS="$ENCODER_LIBS"
		;;
	esac

	echo "building $name with $CC"
	# shellcheck disable=SC2086
	"$CC" $SAN -g -O1 -fno-omit-frame-pointer $PLATFORM_DEFS $INCS \
		-Wno-deprecated-declarations $LD_WORKAROUND \
		-o "$OUT/$name" "$src" "$STRING_C" $EXTRA_SRCS $EXTRA_LIBS \
		$EXTRA_LDFLAGS
done

echo
echo "built into script/fuzz/out. Run one with, for example:"
echo
echo "  mkdir -p script/fuzz/out/corpus"
echo "  script/fuzz/out/fuzz_accept_encoding -max_total_time=60 \\"
echo "    -dict=script/fuzz/accept_encoding.dict \\"
echo "    script/fuzz/out/corpus script/fuzz/corpus"
echo
echo "The first directory is the one libFuzzer writes new inputs"
echo "into, so keep it ahead of script/fuzz/corpus - passing the"
echo "seeds first would have a run rewrite the curated set."
