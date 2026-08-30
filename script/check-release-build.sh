#!/bin/bash
#
# Compiles the module sources the way a release build would, and
# nothing else - no linking, no binary, no touching the tree the
# other suites run against.
#
# Every build here is --with-debug, and ngx_log_debug* expands to
# nothing without it. A local read only by a debug call therefore
# becomes set-but-unused, which -Werror rejects - in the release
# build alone. A debug build compiles it happily, so the break is
# invisible until the release job in .github/workflows/ci.yml runs,
# which is long after the change that caused it. This is that check,
# in about a second.
#
# Required: a configured nginx tree, i.e. script/build.sh has run.
# The flags come out of its objs/Makefile rather than being repeated
# here, so this stays honest about however that tree was configured.
#
# Overridable:
#   NGINX_BUILD  tree to take the flags from (default: nginx)
#
# WITH_DEBUG=0 script/build.sh is still what produces an actual
# release nginx. It also overwrites the debug one every other suite
# needs, which is why this exists beside it rather than instead.
set -eu

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD="${NGINX_BUILD:-$ROOT/nginx}"

if [ ! -f "$BUILD/objs/Makefile" ]; then
	echo "no configured nginx at $BUILD;" >&2
	echo "run NGINX_REF=... script/build.sh first" >&2
	exit 1
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# ngx_config.h includes ngx_auto_config.h by name, so a directory of
# our own ahead of objs on the include path is enough to turn
# NGX_DEBUG off without reconfiguring the tree or writing into it.
#
# Appended rather than edited in place: #undef first means this works
# whether the tree defines NGX_DEBUG or not, so a tree already
# configured without --with-debug is checked rather than rejected.
cp "$BUILD/objs/ngx_auto_config.h" "$WORK/ngx_auto_config.h"
cat >>"$WORK/ngx_auto_config.h" <<'END'

/* Appended by script/check-release-build.sh - see that file. */
#undef NGX_DEBUG
#define NGX_DEBUG 0
END

# ngx_config.h pulls this in too, and it has to come from the same
# directory or the copy above is never the one found.
cp "$BUILD/objs/ngx_auto_headers.h" "$WORK/"

# Asked of make rather than parsed out: ALL_INCS is a continued line,
# and both it and CFLAGS carry whatever ./auto/configure was given -
# --with-cc-opt, the addon's own -I, the lot.
cat >"$WORK/print.mk" <<'END'
include objs/Makefile

print-flags:
	@printf '%s\n' "$(CC)" "$(CFLAGS)" "$(ALL_INCS)"
END

cd "$BUILD"
{
	IFS= read -r CC
	IFS= read -r CFLAGS
	IFS= read -r ALL_INCS
} < <(make -s -f "$WORK/print.mk" print-flags)

status=0
for src in "$ROOT"/module/*/*.c; do
	echo "release: $(basename "$src")"
	# -I "$WORK" first, so its ngx_auto_config.h wins over objs's.
	# Word splitting on the flags is intended: they are a command
	# line, not one argument.
	# shellcheck disable=SC2086
	if ! "$CC" -c $CFLAGS -I "$WORK" $ALL_INCS -o /dev/null "$src"; then
		status=1
	fi
done

if [ "$status" -ne 0 ]; then
	echo "release build failed - see above" >&2
	exit 1
fi

echo "release build clean"
