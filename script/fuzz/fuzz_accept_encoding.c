/*
   Copyright (C) Google Inc.
   Copyright (C) 2026 Juri Torhoff
 */

/* libFuzzer target for the Accept-Encoding parser in
   module/common/ngx_http_pack_headers.h.

   That parser is the only code in this repository that reads attacker
   controlled bytes. It walks the header with ngx_strlcasestrn,
   indexes backwards from a match (cursor[-1]), steps forwards past
   it, and hands the remainder to a weight parser - all over a buffer
   that is NOT NUL terminated, because nginx does not terminate header
   values. The header's own comment records that the static module's
   copy had once "lost the length guard", so this is a bug class the
   file has seen before.

   The whole point of the harness is the allocation below: the header
   value is a heap block sized to the input exactly, so a single byte
   read past the end is a heap-buffer-overflow that AddressSanitizer
   stops on. A static buffer would hide precisely the bug worth
   finding.

   The real ngx_strlcasestrn is linked in rather than reimplemented -
   the interaction between its bounds and ours is where a defect would
   live, so a stand-in would test the wrong thing.

   What this does NOT cover: the filter module itself, which needs a
   request, a pool and a buffer chain to do anything.
   script/tests/stream/test_stream.py covers that at the integration level.

   Build and run: script/fuzz/build.sh, then
   script/fuzz/out/fuzz_accept_encoding
 */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "../../module/common/ngx_http_pack_headers.h"

/* ngx_string.c is linked for ngx_strlcasestrn and refers to these.
   Nothing on the path under test reaches them; they exist to satisfy
   the linker. */
ngx_cycle_t volatile *ngx_cycle;

void *
ngx_alloc(size_t size, ngx_log_t *log)
{
    (void) log;
    return malloc(size);
}

void *
ngx_pnalloc(ngx_pool_t *pool, size_t size)
{
    (void) pool;
    return malloc(size);
}

/* Every token this parser is ever handed: the zstd filter passes
   "zstd", the Brotli filter "br", and the static module all three as
   it walks pack_static_encodings. */
static ngx_str_t const encodings[] = {
    ngx_string("br"),
    ngx_string("gzip"),
    ngx_string("zstd"),
};

int
LLVMFuzzerTestOneInput(uint8_t const *data, size_t size)
{
    ngx_http_request_t r;
    ngx_table_elt_t    accept_encoding;
    ngx_str_t          encoding;
    u_char            *value;
    size_t             idx;

    /* An nginx header value is a length and a pointer, with no
       terminator. Copy into a block of exactly "size" bytes so that
       the sanitizer owns both edges: reading data[-1] or data[size]
       traps here, where in a server it would quietly read whatever
       the pool happened to hold. */
    value = malloc(size ? size : 1);
    if (value == NULL) {
        return 0;
    }
    if (size) {
        memcpy(value, data, size);
    }

    ngx_memzero(&r, sizeof(ngx_http_request_t));
    ngx_memzero(&accept_encoding, sizeof(ngx_table_elt_t));

    accept_encoding.value.data = value;
    accept_encoding.value.len  = size;

    /* claim_request declines subrequests and anything below HTTP/1.1
       before it parses, so set both up to reach the parser. */
    r.main                       = &r;
    r.http_version               = NGX_HTTP_VERSION_11;
    r.headers_in.accept_encoding = &accept_encoding;

    /* Every token the parser is ever asked for, against the same
       input. The needle is not part of the input format on purpose:
       spending an input byte to choose one would reinterpret the
       first character of every seed already in corpus/, and the
       parser is cheap enough that running it three times costs less
       than losing them.

       "br" is the one that matters most here, and it is not the
       obvious one. The boundary check only runs where
       ngx_strlcasestrn finds the needle, so a four-character token
       leaves most inputs returning NULL without reaching the guard
       at all, while a two-character one reaches it constantly - and
       the reject path, which steps the cursor past a match and
       searches again, is only stressed when matches cluster the way
       short needles make them.

       It is also the only token with a superstring anyone writes:
       "brotli" starts with "br", and the "after" test is the sole
       thing keeping "Accept-Encoding: brotli" from selecting it.
       Getting that wrong sends a client a coding it never asked for
       and may not decode. Nothing standard begins with "zstd" or
       "gzip", so their substring cases are invented; this one is
       not. */
    for (idx = 0; idx < sizeof(encodings) / sizeof(encodings[0]);
         idx++) {
        encoding = encodings[idx];
        ngx_http_pack_claim_request(&r, &encoding);
    }

    free(value);

    return 0;
}
