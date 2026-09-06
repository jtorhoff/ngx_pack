#!/bin/bash
#
# Static-file and Accept-Encoding suite, over HTTP/1.1 and HTTP/2.
# Run script/build/build.sh and script/tests/basic/prepare-tests.sh first.
#
# Overridable:
#   NGINX_BIN  nginx binary to exercise (default: the one
#              script/build/build.sh makes)
#   ZSTD       zstd CLI used to decompress (default: the one
#              script/build/build.sh makes, else PATH)
#
# Note NGINX_BIN rather than NGINX: nginx reserves the NGINX
# environment variable for socket inheritance, and reads a binary
# path there as a list of socket numbers.
#
# Exits with the number of failed tests.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
NGINX="${NGINX_BIN:-$ROOT/nginx/objs/nginx}"
ZSTD="${ZSTD:-$ROOT/deps/zstd/out/programs/zstd}"
SERVER=http://localhost:8080
FILES=$ROOT/script/test
HR="-----------------------------------------------------------------"

if [ ! -x "$NGINX" ]; then
	echo "no nginx at $NGINX; run script/build/build.sh or set NGINX" >&2
	exit 1
fi
if [ ! -x "$ZSTD" ]; then
	ZSTD="$(command -v zstd || true)"
fi
if [ -z "$ZSTD" ] || [ ! -x "$ZSTD" ]; then
	echo "no zstd CLI; install it or set ZSTD" >&2
	exit 1
fi

cd "$ROOT" || exit
mkdir -p tmp
rm -f tmp/*

add_result() {
	echo "$1" >&2
	echo "$1" >>tmp/results.log
}

get_failed() {
	# "|| true": grep -c exits 1 when it counts nothing, i.e. when
	# every test passed, which would abort the caller under set -e.
	grep -v -c OK tmp/results.log || true
}

get_count() {
	# grep -c rather than wc -l: BSD wc pads its output, and the count is
	# interpolated into the result line.
	grep -c '' tmp/results.log
}

expect_equal() {
	expected=$1
	actual=$2
	if cmp "$expected" "$actual"; then
		add_result "OK"
	else
		add_result "FAIL (equality)"
	fi
}

expect_zst_equal() {
	expected=$1
	actual_zst=$2
	if $ZSTD -dfk "./${actual_zst}.zst"; then
		expect_equal "$expected" "$actual_zst"
	else
		add_result "FAIL (decompression)"
	fi
}

######################################################################

# Start default server.
echo "Starting NGINX"
$NGINX -p "$FILES" -c "$ROOT/script/tests/basic/test.conf"
# Fetch vanilla 404 response.
curl -s -o tmp/notfound.txt "$SERVER/notfound"

CURL="curl -s"

# Run tests.
echo $HR

echo "Test: long file with rate limit"
$CURL -H 'Accept-encoding: zstd' -o tmp/war-and-peace.zst \
	--limit-rate 300K $SERVER/war-and-peace.txt
expect_zst_equal "$FILES/war-and-peace.txt" tmp/war-and-peace

echo "Test: compressed 404"
$CURL -H 'Accept-encoding: zstd' -o tmp/notfound.zst $SERVER/notfound
expect_zst_equal tmp/notfound.txt tmp/notfound

echo "Test: A-E: 'gzip, zstd'"
$CURL -H 'Accept-encoding: gzip, zstd' -o tmp/ae-01.zst $SERVER/small.txt
expect_zst_equal "$FILES/small.txt" tmp/ae-01

echo "Test: A-E: 'gzip, zstd, deflate'"
$CURL -H 'Accept-encoding: gzip, zstd, deflate' -o tmp/ae-02.zst \
	$SERVER/small.txt
expect_zst_equal "$FILES/small.txt" tmp/ae-02

echo "Test: A-E: 'gzip, zstd;q=1, deflate'"
$CURL -H 'Accept-encoding: gzip, zstd;q=1, deflate' -o tmp/ae-03.zst \
	$SERVER/small.txt
expect_zst_equal "$FILES/small.txt" tmp/ae-03

echo "Test: A-E: 'zstd;q=0.001'"
$CURL -H 'Accept-encoding: zstd;q=0.001' -o tmp/ae-04.zst \
	$SERVER/small.txt
expect_zst_equal "$FILES/small.txt" tmp/ae-04

echo "Test: A-E: 'zstdx'"
$CURL -H 'Accept-encoding: zstdx' -o tmp/ae-05.txt $SERVER/small.txt
expect_equal "$FILES/small.txt" tmp/ae-05.txt

echo "Test: A-E: 'zsdt'"
$CURL -H 'Accept-encoding: zsdt' -o tmp/ae-06.txt $SERVER/small.txt
expect_equal "$FILES/small.txt" tmp/ae-06.txt

echo "Test: A-E: 'zstd;q=0'"
$CURL -H 'Accept-encoding: zstd;q=0' -o tmp/ae-07.txt $SERVER/small.txt
expect_equal "$FILES/small.txt" tmp/ae-07.txt

echo "Test: A-E: 'zstd;q=0.'"
$CURL -H 'Accept-encoding: zstd;q=0.' -o tmp/ae-08.txt $SERVER/small.txt
expect_equal "$FILES/small.txt" tmp/ae-08.txt

echo "Test: A-E: 'zstd;q=0.0'"
$CURL -H 'Accept-encoding: zstd;q=0.0' -o tmp/ae-09.txt \
	$SERVER/small.txt
expect_equal "$FILES/small.txt" tmp/ae-09.txt

echo "Test: A-E: 'zstd;q=0.00'"
$CURL -H 'Accept-encoding: zstd;q=0.00' -o tmp/ae-10.txt \
	$SERVER/small.txt
expect_equal "$FILES/small.txt" tmp/ae-10.txt

echo "Test: A-E: 'zstd ; q = 0.000'"
$CURL -H 'Accept-encoding: zstd ; q = 0.000' -o tmp/ae-11.txt \
	$SERVER/small.txt
expect_equal "$FILES/small.txt" tmp/ae-11.txt

echo "Test: A-E: 'bar'"
$CURL -H 'Accept-encoding: bar' -o tmp/ae-12.txt $SERVER/small.html
expect_equal "$FILES/small.html" tmp/ae-12.txt

echo "Test: A-E: 'b'"
$CURL -H 'Accept-encoding: b' -o tmp/ae-13.txt $SERVER/small.html
expect_equal "$FILES/small.html" tmp/ae-13.txt

echo $HR
echo "Stopping default NGINX"
# Stop server.
$NGINX -p "$FILES" -c "$ROOT/script/tests/basic/test.conf" -s stop

######################################################################

# Start default server.
echo "Starting h2 NGINX"
$NGINX -p "$FILES" -c "$ROOT/script/tests/basic/test_h2.conf"

CURL="curl --http2-prior-knowledge -s"

# Run tests.
echo $HR

echo "Test: long file with rate limit"
$CURL -H 'Accept-encoding: zstd' -o tmp/h2-war-and-peace.zst \
	--limit-rate 300K $SERVER/war-and-peace.txt
expect_zst_equal "$FILES/war-and-peace.txt" tmp/h2-war-and-peace

echo "Test: A-E: 'gzip, zstd'"
$CURL -H 'Accept-encoding: gzip, zstd' -o tmp/h2-ae-01.zst \
	$SERVER/small.txt
expect_zst_equal "$FILES/small.txt" tmp/h2-ae-01

echo "Test: A-E: 'b'"
$CURL -H 'Accept-encoding: b' -o tmp/h2-ae-13.txt $SERVER/small.html
expect_equal "$FILES/small.html" tmp/h2-ae-13.txt

echo $HR
echo "Stopping h2 NGINX"
# Stop server.
$NGINX -p "$FILES" -c "$ROOT/script/tests/basic/test_h2.conf" -s stop

######################################################################

# Report.

FAILED=$(get_failed)
COUNT=$(get_count)
echo $HR
echo "Results: $FAILED of $COUNT tests failed"

# Restore status-quo.
cd "$ROOT" || exit

exit "$FAILED"
