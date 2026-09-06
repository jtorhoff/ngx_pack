#!/bin/bash
#
# Sourced by the scripts that run ./auto/configure, to work out the
# flags this machine needs on top of whatever the caller passes.
#
# nginx looks for PCRE and zlib in the compiler's default search
# paths. macOS ships neither header, Homebrew installs them under a
# prefix of its own - /opt/homebrew on Apple silicon, /usr/local on
# Intel - and nothing puts that prefix on the search path, so
# configure stops at:
#
#   ./auto/configure: error: the HTTP rewrite module requires the
#   PCRE library.
#
# Worth a shared file rather than a note in the README because that
# failure is destructive. configure writes objs/ngx_auto_config.h and
# the top-level Makefile in stages and appends the rest as it goes, so
# aborting part way leaves both truncated: the tree that built a
# moment ago now dies with "use of undeclared identifier NGX_USER",
# and the only way out is a full reconfigure. A first run loses
# nothing, but a rerun in a working tree destroys it.
#
# Sets PACK_CC_OPT and PACK_LD_OPT, both empty where nothing is
# needed. Linux takes that path, so CI - which installs
# libpcre3-dev and zlib1g-dev into the system paths - is unaffected.
#
# SC2034 is disabled for the file: both are read by whatever sources
# it, which shellcheck cannot see from here.
# shellcheck disable=SC2034

PACK_CC_OPT=""
PACK_LD_OPT=""

if [ "$(uname -s)" = "Darwin" ]; then
	# Homebrew's prefix is fixed by architecture, and both can be
	# installed side by side on an Apple silicon machine - Rosetta
	# runs the Intel one. So the arch has to pick, and "brew" on PATH
	# must not: this machine answers /usr/local to "brew --prefix"
	# while needing /opt/homebrew, because the Intel brew is the one
	# earlier in PATH.
	#
	# Getting that wrong is not a clean failure either. Both prefixes
	# carry a pcre2.h, so the header probe passes against the Intel
	# one and only the link probe fails, leaving configure to report
	# the library as simply "not found".
	# Asked of the compiler, not of uname: uname answers for the
	# shell running this, which need not be what the build targets.
	# "bash" on PATH here is the Intel Homebrew's x86_64-only build
	# while /bin/bash runs native, so the same script answers
	# differently depending on how it was started - and the compiler
	# follows suit, which is what the libraries actually have to
	# match.
	pack_target="$(${CC:-cc} -dumpmachine 2>/dev/null || uname -m)"
	case "$pack_target" in
	arm64* | aarch64*) pack_prefixes="/opt/homebrew /usr/local" ;;
	*) pack_prefixes="/usr/local /opt/homebrew" ;;
	esac

	# brew --prefix last, and only as a way to find a relocated
	# install: it is the least trustworthy answer here, for the
	# reason above.
	for pack_prefix in $pack_prefixes "$(brew --prefix 2>/dev/null || true)"; do
		[ -n "$pack_prefix" ] || continue
		[ -d "$pack_prefix/include" ] || continue

		PACK_CC_OPT="-I$pack_prefix/include"
		PACK_LD_OPT="-L$pack_prefix/lib"
		break
	done
	unset pack_prefix pack_prefixes pack_target
fi
