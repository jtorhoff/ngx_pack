#!/bin/bash
#
# Static-file and Accept-Encoding suite, over HTTP/1.1 and HTTP/2.
# Run script/build.sh and script/prepare-tests.sh first.
#
# Overridable:
#   NGINX_BIN  nginx binary to exercise (default: the one
#              script/build.sh makes)
#   BROTLI     brotli CLI used to decompress (default: the one it
#              makes, else PATH)
#
# Note NGINX_BIN rather than NGINX: nginx reserves the NGINX
# environment variable for socket inheritance, and reads a binary
# path there as a list of socket numbers.
#
# Exits with the number of failed tests.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NGINX="${NGINX_BIN:-$ROOT/nginx/objs/nginx}"
BROTLI="${BROTLI:-$ROOT/deps/brotli/out/brotli}"
SERVER=http://localhost:8080
FILES=$ROOT/script/test
HR="-----------------------------------------------------------------"

if [ ! -x "$NGINX" ]; then
	echo "no nginx at $NGINX; run script/build.sh or set NGINX" >&2
	exit 1
fi
if [ ! -x "$BROTLI" ]; then
	BROTLI="$(command -v brotli || true)"
fi
if [ -z "$BROTLI" ] || [ ! -x "$BROTLI" ]; then
	echo "no brotli CLI; run script/build.sh or set BROTLI" >&2
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

expect_br_equal() {
	expected=$1
	actual_br=$2
	if $BROTLI -dfk "./${actual_br}.br"; then
		expect_equal "$expected" "$actual_br"
	else
		add_result "FAIL (decompression)"
	fi
}

######################################################################

# Start default server.
echo "Starting NGINX"
$NGINX -p "$FILES" -c "$ROOT/script/test.conf"
# Fetch vanilla 404 response.
curl -s -o tmp/notfound.txt "$SERVER/notfound"

CURL="curl -s"

# Run tests.
echo $HR

echo "Test: long file with rate limit"
$CURL -H 'Accept-encoding: br' -o tmp/war-and-peace.br \
	--limit-rate 300K $SERVER/war-and-peace.txt
expect_br_equal "$FILES/war-and-peace.txt" tmp/war-and-peace

echo "Test: compressed 404"
$CURL -H 'Accept-encoding: br' -o tmp/notfound.br $SERVER/notfound
expect_br_equal tmp/notfound.txt tmp/notfound

echo "Test: A-E: 'gzip, br'"
$CURL -H 'Accept-encoding: gzip, br' -o tmp/ae-01.br $SERVER/small.txt
expect_br_equal "$FILES/small.txt" tmp/ae-01

echo "Test: A-E: 'gzip, br, deflate'"
$CURL -H 'Accept-encoding: gzip, br, deflate' -o tmp/ae-02.br \
	$SERVER/small.txt
expect_br_equal "$FILES/small.txt" tmp/ae-02

echo "Test: A-E: 'gzip, br;q=1, deflate'"
$CURL -H 'Accept-encoding: gzip, br;q=1, deflate' -o tmp/ae-03.br \
	$SERVER/small.txt
expect_br_equal "$FILES/small.txt" tmp/ae-03

echo "Test: A-E: 'br;q=0.001'"
$CURL -H 'Accept-encoding: br;q=0.001' -o tmp/ae-04.br \
	$SERVER/small.txt
expect_br_equal "$FILES/small.txt" tmp/ae-04

echo "Test: A-E: 'bro'"
$CURL -H 'Accept-encoding: bro' -o tmp/ae-05.txt $SERVER/small.txt
expect_equal "$FILES/small.txt" tmp/ae-05.txt

echo "Test: A-E: 'bo'"
$CURL -H 'Accept-encoding: bo' -o tmp/ae-06.txt $SERVER/small.txt
expect_equal "$FILES/small.txt" tmp/ae-06.txt

echo "Test: A-E: 'br;q=0'"
$CURL -H 'Accept-encoding: br;q=0' -o tmp/ae-07.txt $SERVER/small.txt
expect_equal "$FILES/small.txt" tmp/ae-07.txt

echo "Test: A-E: 'br;q=0.'"
$CURL -H 'Accept-encoding: br;q=0.' -o tmp/ae-08.txt $SERVER/small.txt
expect_equal "$FILES/small.txt" tmp/ae-08.txt

echo "Test: A-E: 'br;q=0.0'"
$CURL -H 'Accept-encoding: br;q=0.0' -o tmp/ae-09.txt \
	$SERVER/small.txt
expect_equal "$FILES/small.txt" tmp/ae-09.txt

echo "Test: A-E: 'br;q=0.00'"
$CURL -H 'Accept-encoding: br;q=0.00' -o tmp/ae-10.txt \
	$SERVER/small.txt
expect_equal "$FILES/small.txt" tmp/ae-10.txt

echo "Test: A-E: 'br ; q = 0.000'"
$CURL -H 'Accept-encoding: br ; q = 0.000' -o tmp/ae-11.txt \
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
$NGINX -p "$FILES" -c "$ROOT/script/test.conf" -s stop

######################################################################

# Start default server.
echo "Starting h2 NGINX"
$NGINX -p "$FILES" -c "$ROOT/script/test_h2.conf"

CURL="curl --http2-prior-knowledge -s"

# Run tests.
echo $HR

echo "Test: long file with rate limit"
$CURL -H 'Accept-encoding: br' -o tmp/h2-war-and-peace.br \
	--limit-rate 300K $SERVER/war-and-peace.txt
expect_br_equal "$FILES/war-and-peace.txt" tmp/h2-war-and-peace

echo "Test: A-E: 'gzip, br'"
$CURL -H 'Accept-encoding: gzip, br' -o tmp/h2-ae-01.br \
	$SERVER/small.txt
expect_br_equal "$FILES/small.txt" tmp/h2-ae-01

echo "Test: A-E: 'b'"
$CURL -H 'Accept-encoding: b' -o tmp/h2-ae-13.txt $SERVER/small.html
expect_equal "$FILES/small.html" tmp/h2-ae-13.txt

echo $HR
echo "Stopping h2 NGINX"
# Stop server.
$NGINX -p "$FILES" -c "$ROOT/script/test_h2.conf" -s stop

######################################################################

# Report.

FAILED=$(get_failed)
COUNT=$(get_count)
echo $HR
echo "Results: $FAILED of $COUNT tests failed"

# Restore status-quo.
cd "$ROOT" || exit

exit "$FAILED"
