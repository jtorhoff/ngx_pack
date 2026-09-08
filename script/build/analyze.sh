#!/bin/bash
#
# Runs LLVM's static analyzer over this module's sources and fails if it
# reports anything.
#
# Not scan-build over the whole nginx build, deliberately. That analyses
# nginx's ~150 files as well as these six, and nginx's own findings would
# either drown ours or have to be filtered out of a report by path - and a
# filter that silently stops matching is how a job like this rots into
# always-green. Analysing only the files this repository owns means every
# finding is ours by construction.
#
# The flags come from nginx's generated objs/Makefile rather than being
# written out again here, so the analyser sees the same defines, warnings
# and include paths the compiler does. A module analysed under different
# flags from the ones it ships with is analysing something else.
#
# Required:
#   a configured nginx tree, which script/build/build.sh leaves behind
#
# Overridable:
#   NGINX_DIR  the tree to take flags from (default: nginx)
#   CLANG      the compiler to analyse with (default: clang)
#
set -eu

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
NGINX_DIR="${NGINX_DIR:-$ROOT/nginx}"
CLANG="${CLANG:-clang}"

if [ ! -f "$NGINX_DIR/objs/Makefile" ]; then
	echo "no configured nginx at $NGINX_DIR - run script/build/build.sh first" >&2
	exit 1
fi

# Pull one make variable out, following the backslash continuations the
# generated Makefile wraps long lists in.
extract() {
	awk -v key="$1" '
		$0 ~ "^" key " *=" { collecting = 1; sub("^" key " *= *", "") }
		collecting {
			cont = sub(/\\$/, "")
			gsub(/\t/, " ")
			printf "%s ", $0
			if (!cont) exit
		}
	' "$NGINX_DIR/objs/Makefile"
}

CFLAGS="$(extract CFLAGS)"
ALL_INCS="$(extract ALL_INCS)"

if [ -z "$ALL_INCS" ]; then
	echo "could not read ALL_INCS from $NGINX_DIR/objs/Makefile" >&2
	exit 1
fi

# The sources this repository owns. The headers are analysed with them,
# being included; deps/ is vendored and is not ours to answer for.
SOURCES=(
	"$ROOT"/module/pack/ngx_http_pack_module.c
	"$ROOT"/module/filter/zstd/ngx_http_pack_zstd_filter.c
	"$ROOT"/module/filter/zstd/ngx_http_pack_zstd_encoder.c
	"$ROOT"/module/filter/brotli/ngx_http_pack_brotli_filter.c
	"$ROOT"/module/filter/brotli/ngx_http_pack_brotli_encoder.c
	"$ROOT"/module/static/ngx_http_pack_static.c
)

echo "analysing with $("$CLANG" --version | head -1)"
echo

findings=0
for src in "${SOURCES[@]}"; do
	# -o /dev/null because --analyze emits a report, not an object; the
	# exit status and the diagnostics on stderr are what matter.
	#
	# Run from the nginx tree: ALL_INCS carries relative paths like
	# "-I src/core", which only resolve from there.
	#
	# shellcheck disable=SC2086
	if output=$(cd "$NGINX_DIR" && "$CLANG" --analyze \
		-Xclang -analyzer-output=text \
		$CFLAGS $ALL_INCS -I "$ROOT/module/common" \
		"$src" -o /dev/null 2>&1) && [ -z "$output" ]; then
		echo "  clean  ${src#"$ROOT"/}"
	else
		echo "  FOUND  ${src#"$ROOT"/}"
		echo "$output"
		findings=$((findings + 1))
	fi
done

echo
if [ "$findings" -ne 0 ]; then
	echo "static analysis reported problems in $findings file(s)" >&2
	exit 1
fi
echo "static analysis clean across ${#SOURCES[@]} files"
