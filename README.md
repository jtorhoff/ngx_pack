# ngx_zstd

[Zstandard](https://facebook.github.io/zstd/) is a lossless compression
algorithm combining a modern LZ77 match finder with finite state entropy coding.
It reaches compression ratios in the range of deflate and better, at a fraction
of the encoder cost: measured level for level against
[zlib-ng](https://github.com/zlib-ng/zlib-ng) over `script/corpus`, it produces
output of the same size or smaller for roughly half the CPU.

ngx_zstd is a set of two nginx modules:

- ngx_zstd filter module - used to compress responses on-the-fly,
- ngx_zstd static module - used to serve pre-compressed files.

These modules are based on my fork of
[Brotli modules for nginx by Google](https://github.com/jtorhoff/ngx_brotli).
The Brotli fork was refactored with the help of Claude Code and the modules in
this repo follow the general structure of that fork. This is why the original
license is kept (BSD-2-Clause) with the attributions to Igor Sysoev,
Nginx, Inc., and Google Inc.

This work adapts and extends the original test harness of the Brotli fork
including CI that compiles the modules with both GCC and Clang. The tests are
executed against the latest stable branch of nginx
(1.30.x at the time of writing).


## Filter module

Compresses responses as they are produced, labelling them
`Content-Encoding: zstd`. It handles both responses of known length and
responses that are still being streamed, and creates one encoder per request
that it releases as soon as the frame closes.

Responses of any status are compressed, with the exception of those that carry
no body (`1xx`, `204`, `304`) or whose body is a byte range (`206`), since
labelling those with a `Content-Encoding` would corrupt the response. Requests
below HTTP/1.1 are never compressed, matching the `gzip_http_version` default;
`Vary: Accept-Encoding` is still advertised to them so a cache in front keeps
the two answers apart.


### `pack_zstd`

- **syntax**: `pack_zstd on|off`
- **default**: `off`
- **context**: `http`, `server`, `location`, `if in location`

Enables or disables on-the-fly compression of responses.


### `pack_zstd_types`

- **syntax**: `pack_zstd_types <mime_type> [..]`
- **default**: `text/html`
- **context**: `http`, `server`, `location`

Enables on-the-fly compression of responses for the specified MIME types in
addition to `text/html`. The special value `*` matches any MIME type.
Responses with the `text/html` MIME type are always compressed.


### `pack_zstd_level`

- **syntax**: `pack_zstd_level <level>`
- **default**: `3`
- **context**: `http`, `server`, `location`

Sets the compression `level`. Acceptable values are in the range from `1` to
`22`. Zstandard's negative levels are not exposed through this directive.


### `pack_zstd_window`

- **syntax**: `pack_zstd_window <size>`
- **default**: `64k`
- **context**: `http`, `server`, `location`

Sets the compression window `size`. Acceptable values are `1k`, `2k`, `4k`,
`8k`, `16k`, `32k`, `64k`, `128k`, `256k`, `512k`, `1m`, `2m`, `4m`, `8m`,
`16m`, `32m`, `64m` and `128m`. The ceiling is what a decoder accepts without
being asked to opt into more - a larger window would produce responses some
clients simply refuse to decode.


### `pack_zstd_nbuffers`

- **syntax**: `pack_zstd_nbuffers <number>`
- **default**: `4`
- **context**: `http`, `server`, `location`

Sets the maximum `number` of output buffers (between `1` and `64`)
one response may fill before it has to wait for the client to take
them. Their size is fixed at 16k and is not configurable. This is a
ceiling rather than an allocation: buffers are created
only as the encoder actually runs out of free ones, so most responses
never reach it. Most deployments have no reason to change this.
See notes below.


### `pack_zstd_min_length`

- **syntax**: `pack_zstd_min_length <length>`
- **default**: `256`
- **context**: `http`, `server`, `location`

Sets the minimum `length` of a response that will be compressed. The length is
taken from the `Content-Length` response header field. Some responses
are compressed regardless of this setting. See notes below.


### Notes on above settings

`pack_zstd_level`: A high level costs mostly CPU, and only mildly memory.
The module tells the encoder what to expect: the exact size where a
`Content-Length` gives one, and a fixed guess where it does not
(fixed at `256k`). Chunked body at the `64k` default costs 0.95 MB at level
`3`, 1.07 MB at `6` and `9` alike, and 1.90 MB at `22` - a ceiling that
holds across the whole directive range, and at or below what the same body
costs with its length known.


`pack_zstd_window` is the main influence on what a request costs in memory.
Measured against `script/corpus` at level `3`, compressed bytes against peak
per-request encoder memory: 265,093 / 0.32 MB at `16k`, 241,626 / 1.20 MB at
the `64k` default, 234,205 / 1.62 MB at `128k`, 230,211 / 1.74 MB at `256k`
and 230,210 / 2.49 MB at `1m`.


`pack_zstd_nbuffers` only matters when the socket will not take output as fast as
the encoder produces it - a slow client, a congested link, or `limit_rate`.
Short of that the encoder keeps refilling the one buffer it already has, so a
response that never outruns its client costs 16k whatever this is set to:
measured on a 1.5 MB response, a fast client creates a single buffer at both
the `4` default and at `32`. Under `limit_rate 8k` that same response creates
4 buffers (64k) at the default, 1 (16k) at `pack_zstd_nbuffers 1`, and 24 (384k)
when allowed 32. Raising it therefore costs nothing on responses that keep up,
and lets the ones that stall carry on compressing instead of stopping after
every buffer; `1` makes the encoder wait for each buffer to be written before
producing the next.


`pack_zstd_min_length`: A response of unknown length is held briefly so the
setting can still be applied to it, rather than being compressed
regardless. Once the end of the response is in hand its real size is known,
and the setting is applied normally.

The exception is a buffer marked for flushing that arrives *before* that
point, which is what `proxy_pass` with `proxy_buffering off` produces:
something downstream is waiting on bytes the filter is sitting on, so it
decides at once rather than holding the headers any longer, and deciding
without knowing the size means compressing. `pack_zstd_min_length` therefore does
not hold on an unbuffered proxied response - a 202 byte body is compressed
even at the `256` default, where the same body over a buffered `proxy_pass`,
or as a static file, is left alone.


## Static module

Serves a pre-compressed `.zst` file from disk in place of the original,
without creating an encoder. The request costs neither compression CPU nor
encoder memory, so prefer it wherever the content is static.


### `pack_static`

- **syntax**: `pack_static on|off|always`
- **default**: `off`
- **context**: `http`, `server`, `location`

Enables or disables checking for the existence of a pre-compressed file with
the `.zst` extension.

With `on`, the file is served only to a client whose `Accept-Encoding` takes
Zstandard, and `Vary: Accept-Encoding` is set whether or not this module ends
up serving the request - what varies is the resource, not the one request.

With `always`, the pre-compressed file is used in all cases, without checking
whether the client supports it. Nothing is added to `Vary`, since every client
receives the same bytes.


### Notes on the static module

Every eligible request probes for `<path>.zst`. When that file does not exist
the probe reaches the filesystem **on every request** unless negative results
are cached too. Caching both requires the following directives:

```nginx
open_file_cache        max=1000 inactive=60s;
open_file_cache_errors on; # without this the miss is never cached
```

`open_file_cache` on its own is not enough. Second directive caches the misses
in addition to cache hits, so that nginx doesn't have to check the filesystem
on every request.
