#!/bin/bash
#
# Lays out the fixtures the shell suite serves.
# script/test_stream.py needs none of this - it generates its own.
#
set -eux

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FILES="$ROOT/script/test"

mkdir -p "$FILES/logs"

echo "Kot lomom kolol slona!" >"$FILES/small.txt"
echo "<html>Kot lomom kolol slona!</html>" >"$FILES/small.html"

# A few megabytes of real prose, for the rate-limited transfer
# test. Project Gutenberg is the original source, but it rate-limits
# and blocks automated fetches often enough to make a build depend
# on luck, so fall back to the vendored Brotli sources - real text,
# deterministic, already on disk.
if [ ! -s "$FILES/war-and-peace.txt" ]; then
	if ! curl --compressed --fail --silent --show-error --location \
		--retry 2 --max-time 60 -o "$FILES/war-and-peace.txt" \
		https://www.gutenberg.org/files/2600/2600-0.txt; then
		echo "corpus download failed; generating one from the" \
			"Brotli sources" >&2
		rm -f "$FILES/war-and-peace.txt"
		find "$ROOT/deps/brotli/c" -name '*.c' -o -name '*.h' |
			sort | xargs cat >>"$FILES/war-and-peace.txt"
		# Repeat until it is big enough to be worth rate limiting.
		while [ "$(wc -c <"$FILES/war-and-peace.txt")" -lt 3000000 ]; do
			cat "$FILES/war-and-peace.txt" "$FILES/war-and-peace.txt" \
				>"$FILES/war-and-peace.txt.tmp"
			mv "$FILES/war-and-peace.txt.tmp" "$FILES/war-and-peace.txt"
		done
	fi
fi

wc -c "$FILES/war-and-peace.txt" "$FILES/small.txt" \
	"$FILES/small.html"
