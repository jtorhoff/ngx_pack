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

If you're interested how this fork was created off the Brotli fork,
check out [PORTING.md](PORTING.md).


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


### `zstd`

- **syntax**: `zstd on|off`
- **default**: `off`
- **context**: `http`, `server`, `location`, `if in location`

Enables or disables on-the-fly compression of responses.


### `zstd_types`

- **syntax**: `zstd_types <mime_type> [..]`
- **default**: `text/html`
- **context**: `http`, `server`, `location`

Enables on-the-fly compression of responses for the specified MIME types in
addition to `text/html`. The special value `*` matches any MIME type.
Responses with the `text/html` MIME type are always compressed.


### `zstd_comp_level`

- **syntax**: `zstd_comp_level <level>`
- **default**: `3`
- **context**: `http`, `server`, `location`

Sets the compression `level`. Acceptable values are in the range from `1` to
`22`. Zstandard's negative levels are not exposed through this directive.


### `zstd_window`

- **syntax**: `zstd_window <size>`
- **default**: `64k`
- **context**: `http`, `server`, `location`

Sets the compression window `size`. Acceptable values are `1k`, `2k`, `4k`,
`8k`, `16k`, `32k`, `64k`, `128k`, `256k`, `512k`, `1m`, `2m`, `4m`, `8m`,
`16m`, `32m`, `64m` and `128m`. The ceiling is what a decoder accepts without
being asked to opt into more - a larger window would produce responses some
clients simply refuse to decode.


### `zstd_min_length`

- **syntax**: `zstd_min_length <length>`
- **default**: `256`
- **context**: `http`, `server`, `location`

Sets the minimum `length` of a response that will be compressed. The length is
taken from the `Content-Length` response header field, or, where there is
none, from the body itself once enough of it has arrived to answer the
question - except on a response whose buffers ask to be flushed, which is
compressed whatever its size. See the notes below.


### Notes on above settings and performance

`zstd_comp_level` of `3` is where the ratio-versus-CPU elbow actually sits,
rather than being merely zstd's own default carried over. Over `script/corpus`,
level `3` compresses to 27.3% of the original; `6` reaches 24.9% for about three
times the encoder time, and past `9` the curve flattens hard - `19` spends
nearly sixty times level `3`'s CPU to gain a further 1.2 points.

Levels above `9` are affordable only where the response length is known. On a
response of unknown length nothing caps the encoder's match-finder tables, and
peak memory climbs steeply - 1.2 MB at level `3`, 2.95 MB at `6`, 10.45 MB at
`9`, and 640 MB at `22` even with the default window.

`zstd_window` is the main influence on what a request costs in memory.
Measured against `script/corpus` at level `3`, compressed bytes against peak
per-request encoder memory: 265,093 / 0.32 MB at `16k`, 241,626 / 1.20 MB at
the `64k` default, 234,205 / 1.62 MB at `128k`, 230,211 / 1.74 MB at `256k`
and 230,210 / 2.49 MB at `1m`.

While the default for `zstd_window` is set to `64k`, `128k` is the alternative
worth knowing about: it buys 3.1% in ratio for +0.42 MB per request, and is the
largest window still free in block terms, since a Zstandard block is
`min(zstd_window, 128k)` and past that the window buffer grows on its own.

*When the response length is known the module already lowers the window to fit
the body, `zstd_window` mainly affects streamed responses and bodies larger
than the window.*

`zstd_min_length`: Below roughly 90 to 106 bytes a small JSON-shaped response
comes out larger than it started (default settings), and `256` clears that with
a margin once the `Content-Encoding` header's own cost is counted.

A response of unknown length is held briefly so the setting can still be
applied to it, rather than being compressed regardless. The exception is a
buffer marked for flushing, which is what `proxy_pass` with
`proxy_buffering off` produces for every buffer: something downstream is
waiting, so the filter decides at once instead of holding the headers any
longer, and deciding at once means compressing. `zstd_min_length` therefore
does not hold on an unbuffered proxied response - a 200 byte body is
compressed even at the `256` default.


## Static module

Serves a pre-compressed `.zst` file from disk in place of the original,
without creating an encoder. The request costs neither compression CPU nor
encoder memory, so prefer it wherever the content is static.


### `zstd_static`

- **syntax**: `zstd_static on|off|always`
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
