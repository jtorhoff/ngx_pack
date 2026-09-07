/*
   Copyright (C) 2026 Juri Torhoff
 */

/* libFuzzer target for the round loop in
   module/filter/zstd/ngx_http_pack_zstd_encoder.c: encoder_create,
   repeated encoder_step, and the pending/drained/busy/has_free/
   frame_closed bookkeeping around it. Modelled directly on the loop
   in ngx_http_pack_zstd_filter.c's ngx_http_pack_zstd_pump.

   What this reaches that script/tests/stream/test_stream.py cannot:
   the encoder only ever sees what a real proxied response happens to
   produce, one round's worth of buffers at a time as they arrive off
   the wire. This harness can hand it several buffers at once with any
   combination of "flush" and "last_buf" set, which is what
   ngx_http_pack_zstd_may_fold_flush's lookahead needs to take its
   "last_buf without flush" branch - a shape ordinary HTTP timing
   essentially never produces.

   What it does NOT reach: everything gated behind an nginx pool
   allocation failing, or libzstd rejecting a parameter this module's
   own directive validation already guarantees is legal. Both need
   fault injection on a success path, which varying the input cannot
   produce - see NGX_HTTP_PACK_ZSTD_FAULT_INJECT and test_oom.py for
   the one allocator this module does own.

   The encoder is opaque by design (see its header) and touches
   exactly two things through the request it is handed: r->pool and
   r->connection->log. Confirmed by grep, not assumed - nothing else
   here is a real nginx request. ngx_palloc.c, ngx_buf.c, ngx_log.c
   and ngx_times.c are linked in for real (see build.sh) rather than
   stubbed, the same reasoning script/fuzz/build.sh already gives for
   linking ngx_string.c into fuzz_accept_encoding: an uninstrumented
   stand-in would test the wrong thing.

   The oracle is two-fold: ASan and UBSan catch memory bugs and UB the
   same way they do for fuzz_accept_encoding, and every round's output
   is fed to a real ZSTD_DCtx and compared against what went in - a
   silent correctness bug (dropped bytes, a corrupted frame) fails the
   round-trip even when nothing crashes.

   Build and run: script/fuzz/build.sh, then
   script/fuzz/out/fuzz_zstd_encoder
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <zstd.h>

#include "ngx_http_pack_zstd_encoder.h"

typedef ngx_http_pack_zstd_encoder_conf_t conf_t;

#define MAX_ROUNDS       32
#define MAX_BUFS_PER_RND 4
#define MAX_BUF_SIZE     4096
/* Generous rather than exact: total input across every round is
   bounded well under this by MAX_ROUNDS * MAX_BUFS_PER_RND *
   MAX_BUF_SIZE, and output can only be larger than input in
   pathological cases libzstd itself bounds. */
#define ACCUM_CAP (MAX_ROUNDS * MAX_BUFS_PER_RND * MAX_BUF_SIZE + 65536)

/* Bytes consumed off the front of the fuzz input to make decisions -
   never randomness of our own, so a crash replays byte for byte. */
typedef struct {
    const uint8_t *pos;
    const uint8_t *end;
} cursor_t;

static uint8_t
next_byte(cursor_t *c)
{
    if (c->pos >= c->end) {
        return 0;
    }
    return *c->pos++;
}

static size_t
next_range(cursor_t *c, size_t lo, size_t hi)
{
    /* hi inclusive; lo == hi is allowed and returns it directly. */
    if (hi <= lo) {
        return lo;
    }
    return lo + (size_t) next_byte(c) % (hi - lo + 1);
}

static ngx_uint_t
next_bit(cursor_t *c)
{
    return next_byte(c) & 1;
}

static const ngx_int_t LEVELS[]       = {1, 2, 3, 4, 5, 6};
static const size_t    WINDOW_BITS[]  = {14, 15, 16, 17, 18, 19, 20};
static const size_t    BUFFER_SIZES[] = {64, 256, 1024, 4096, 16384};
static const ngx_int_t NBUFFERS[]     = {1, 2, 4, 8};

#define ARRAY_LEN(a) (sizeof(a) / sizeof((a)[0]))

/* One buffer this run of the encoder will be fed. */
typedef struct {
    size_t     size;
    ngx_uint_t flush;
    ngx_uint_t last_buf;
} planned_buf_t;

/* One call to encoder_step: however many buffers land in the same
   chain at once - more than one is what gives may_fold_flush's
   lookahead something to scan across - and whether the round's
   output is taken immediately or left busy, mirroring a downstream
   that keeps up versus one applying backpressure. */
typedef struct {
    ngx_uint_t    nbufs;
    planned_buf_t bufs[MAX_BUFS_PER_RND];
    ngx_uint_t    drain_immediately;
} planned_round_t;

typedef struct {
    conf_t          conf;
    planned_round_t rounds[MAX_ROUNDS];
    ngx_uint_t      nrounds;
} plan_t;

/* Reads the whole plan off the front of the fuzz input: the conf and
   every round's buffer shapes. Whatever the cursor has left
   afterwards becomes buffer content in the caller, cycled rather
   than truncated so a small corpus entry still fills every buffer.
   last_buf is forced onto the very last buffer of the very last
   round regardless of what was fuzzed for it, which is the only way
   to guarantee exactly one and at the true end. */
static void
build_plan(cursor_t *c, plan_t *plan)
{
    ngx_uint_t last_round;
    ngx_uint_t last_buf_idx;

    memset(plan, 0, sizeof(*plan));

    plan->conf.level = LEVELS[next_range(c, 0, ARRAY_LEN(LEVELS) - 1)];
    plan->conf.window_bits =
        WINDOW_BITS[next_range(c, 0, ARRAY_LEN(WINDOW_BITS) - 1)];
    plan->conf.nbuffers =
        NBUFFERS[next_range(c, 0, ARRAY_LEN(NBUFFERS) - 1)];
    plan->conf.buffer_size =
        BUFFER_SIZES[next_range(c, 0, ARRAY_LEN(BUFFER_SIZES) - 1)];
    /* NGX_HTTP_PACK_ZSTD_HINT_MIN is 16k; 0 is "no hint", which is
       what conf->hint defaults to when the directive is unset. */
    plan->conf.src_size_hint =
        next_bit(c) ? 0 : next_range(c, 16 * 1024, 1024 * 1024);

    plan->nrounds = (ngx_uint_t) next_range(c, 1, MAX_ROUNDS);

    for (ngx_uint_t ri = 0; ri < plan->nrounds; ri++) {
        planned_round_t *round = &plan->rounds[ri];

        round->nbufs = (ngx_uint_t) next_range(c, 0, MAX_BUFS_PER_RND);
        round->drain_immediately = next_bit(c);

        for (ngx_uint_t bi = 0; bi < round->nbufs; bi++) {
            round->bufs[bi].size  = next_range(c, 0, MAX_BUF_SIZE);
            round->bufs[bi].flush = next_bit(c);
        }
    }

    /* At least one round must carry at least one buffer, or there is
       nothing to close the frame - back the last round's count up to
       1 if the fuzzer chose all zeros. */
    last_round = plan->nrounds - 1;
    if (plan->rounds[last_round].nbufs == 0) {
        plan->rounds[last_round].nbufs = 1;
        plan->rounds[last_round].bufs[0].size  = next_range(c, 0, 256);
        plan->rounds[last_round].bufs[0].flush = 0;
    }
    last_buf_idx = plan->rounds[last_round].nbufs - 1;
    plan->rounds[last_round].bufs[last_buf_idx].last_buf = 1;

    /* content_length: unknown, exactly what will be fed (the only
       shape a real response ever has - nginx enforces that a body
       matches its own Content-Length), or deliberately wrong - not
       reachable through this module's own contract, but cheap
       insurance that a future miscount elsewhere fails safely rather
       than corrupting output. Decided from the total now that every
       round's sizes are fixed. */
    {
        size_t total = 0;
        for (ngx_uint_t ri = 0; ri < plan->nrounds; ri++) {
            for (ngx_uint_t bi = 0; bi < plan->rounds[ri].nbufs; bi++) {
                total += plan->rounds[ri].bufs[bi].size;
            }
        }
        switch (next_range(c, 0, 2)) {
            case 0:
                plan->conf.content_length = -1;
                break;
            case 1:
                plan->conf.content_length = (off_t) total;
                break;
            default:
                plan->conf.content_length =
                    (off_t) next_range(c, 0, 2 * ACCUM_CAP);
                break;
        }
    }
}

/* Everything this harness owns instead of a real request/connection.
   See the file comment: r->pool and r->connection->log are the only
   two fields the encoder ever reaches through r. */
typedef struct {
    ngx_log_t           log;
    ngx_connection_t    connection;
    ngx_http_request_t  request;
} fake_request_t;

static void
fake_request_init(fake_request_t *fr, ngx_pool_t *pool)
{
    memset(fr, 0, sizeof(*fr));
    /* 0 is below every real level (ngx_log_error's "log_level >=
       level" guard), so every ngx_log_error call this run might make
       is silently skipped rather than dereferencing a log file this
       harness never opens. */
    fr->log.log_level      = 0;
    fr->connection.log     = &fr->log;
    fr->request.pool       = pool;
    fr->request.connection = &fr->connection;
}

/* The round-trip oracle: every byte the encoder ever emitted, fed to
   a real ZSTD_DCtx once the run is over, compared against every byte
   it was fed. A streaming decoder rather than one-shot decompression,
   for the same reason the encoder is streaming - nothing here should
   assume the frame arrived as a single block. Traps rather than
   returning a bool: that is what turns a mismatch into a libFuzzer
   finding the same way ASan or UBSan would. */
static void
check_roundtrip(
    uint8_t const *compressed, size_t compressed_len,
    uint8_t const *original, size_t original_len)
{
    ZSTD_DStream  *dctx;
    ZSTD_inBuffer  in;
    ZSTD_outBuffer out;
    uint8_t        outbuf[65536];
    uint8_t       *decoded;
    size_t         decoded_cap;
    size_t         decoded_len;
    size_t         rc;

    if (compressed_len == 0) {
        if (original_len != 0) {
            __builtin_trap();
        }
        return;
    }

    dctx = ZSTD_createDStream();
    if (dctx == NULL) {
        return;
    }

    decoded_cap = original_len + 1;
    decoded     = malloc(decoded_cap);
    if (decoded == NULL) {
        ZSTD_freeDStream(dctx);
        return;
    }
    decoded_len = 0;

    in.src  = compressed;
    in.size = compressed_len;
    in.pos  = 0;

    for (;;) {
        out.dst  = outbuf;
        out.size = sizeof(outbuf);
        out.pos  = 0;

        rc = ZSTD_decompressStream(dctx, &out, &in);
        if (ZSTD_isError(rc)) {
            free(decoded);
            ZSTD_freeDStream(dctx);
            __builtin_trap();
        }

        if (out.pos > 0) {
            if (decoded_len + out.pos > decoded_cap) {
                /* More decoded bytes than were ever fed in: zstd
                   invented data, or nothing should have grown past
                   what was fed. Either way, a real bug. */
                free(decoded);
                ZSTD_freeDStream(dctx);
                __builtin_trap();
            }
            memcpy(decoded + decoded_len, outbuf, out.pos);
            decoded_len += out.pos;
        }

        if (rc == 0 || (in.pos == in.size && out.pos == 0)) {
            break;
        }
    }

    ZSTD_freeDStream(dctx);

    if (decoded_len != original_len ||
        (original_len > 0 && memcmp(decoded, original, original_len) != 0))
    {
        fprintf(stderr, "MISMATCH decoded_len=%zu original_len=%zu\n",
                decoded_len, original_len);
        if (decoded_len == original_len) {
            for (size_t i = 0; i < original_len; i++) {
                if (decoded[i] != original[i]) {
                    fprintf(stderr, "  first diff at %zu: got %02x want %02x\n",
                            i, decoded[i], original[i]);
                    break;
                }
            }
        }
        free(decoded);
        __builtin_trap();
    }

    free(decoded);
}

int
LLVMFuzzerTestOneInput(uint8_t const *data, size_t size)
{
    cursor_t     cursor;
    plan_t       plan;
    ngx_log_t    boot_log;
    ngx_pool_t  *pool;
    fake_request_t fr;
    ngx_http_pack_zstd_encoder_t *enc;
    uint8_t     *fed;
    size_t       fed_len;
    uint8_t     *produced;
    size_t       produced_len;
    ngx_chain_t *in;

    cursor.pos = data;
    cursor.end = data + size;
    build_plan(&cursor, &plan);

    boot_log.log_level = 0;
    pool = ngx_create_pool(16384, &boot_log);
    if (pool == NULL) {
        return 0;
    }
    fake_request_init(&fr, pool);

    enc = ngx_http_pack_zstd_encoder_create(&fr.request, &plan.conf);
    if (enc == NULL) {
        ngx_destroy_pool(pool);
        return 0;
    }

    fed      = malloc(ACCUM_CAP);
    produced = malloc(ACCUM_CAP);
    if (fed == NULL || produced == NULL) {
        free(fed);
        free(produced);
        ngx_http_pack_zstd_encoder_close(enc);
        ngx_destroy_pool(pool);
        return 0;
    }
    fed_len      = 0;
    produced_len = 0;
    /* Whatever a round's do-while below did not consume - the
       encoder advances *in itself as it takes buffers, so anything
       left over is real unfinished business, not something a new
       round may silently replace. Pool-allocated rather than on the
       stack, so a chain link built in an earlier iteration is still
       valid once this one appends to its tail. */
    in = NULL;

    for (ngx_uint_t ri = 0; ri < plan.nrounds; ri++) {
        planned_round_t          *round = &plan.rounds[ri];
        ngx_chain_t               *pending;
        ngx_http_pack_zstd_step_e  step;
        ngx_chain_t              **tail;

        /* Appends this round's planned buffers after whatever the
           previous round left unconsumed, rather than after the
           carry chain's own tail - encoder_step is free to leave
           *in pointing anywhere along the chain it was given, not
           only at an unconsumed final link. */
        tail = &in;
        while (*tail != NULL) {
            tail = &(*tail)->next;
        }

        for (ngx_uint_t bi = 0; bi < round->nbufs; bi++) {
            planned_buf_t *pb = &round->bufs[bi];
            u_char        *content;
            ngx_buf_t     *buf;
            ngx_chain_t   *link;

            content = ngx_pnalloc(pool, pb->size > 0 ? pb->size : 1);
            link    = ngx_alloc_chain_link(pool);
            buf     = ngx_calloc_buf(pool);
            if (content == NULL || link == NULL || buf == NULL) {
                goto out;
            }
            for (size_t k = 0; k < pb->size; k++) {
                content[k] = (cursor.pos < cursor.end)
                                 ? *cursor.pos++
                                 : (u_char) (k & 0xff);
            }

            if (fed_len + pb->size <= ACCUM_CAP) {
                memcpy(fed + fed_len, content, pb->size);
                fed_len += pb->size;
            }

            buf->start = buf->pos = content;
            buf->end = buf->last  = content + pb->size;
            buf->temporary = 1;
            buf->flush     = pb->flush;
            buf->last_buf  = pb->last_buf;

            link->buf  = buf;
            link->next = NULL;
            *tail = link;
            tail  = &link->next;
        }

        do {
            step = ngx_http_pack_zstd_encoder_step(enc, &in, in == NULL);
        } while (step == NGX_HTTP_PACK_ZSTD_STEP_CONTINUE);

        if (step == NGX_HTTP_PACK_ZSTD_STEP_FAILED) {
            /* Reachable only through a pool allocation failing or
               libzstd rejecting an already-validated parameter - see
               the file comment. Not a finding on its own. */
            goto out;
        }

        pending = ngx_http_pack_zstd_encoder_pending(enc);
        for (ngx_chain_t *l = pending; l != NULL; l = l->next) {
            size_t n_out = (size_t) ngx_buf_size(l->buf);
            if (n_out > 0 && produced_len + n_out <= ACCUM_CAP) {
                memcpy(produced + produced_len, l->buf->pos, n_out);
                produced_len += n_out;
            }
            if (round->drain_immediately) {
                l->buf->pos = l->buf->last;
            }
        }
        ngx_http_pack_zstd_encoder_drained(enc);

        if (ngx_http_pack_zstd_encoder_frame_closed(enc) &&
            !ngx_http_pack_zstd_encoder_busy(enc))
        {
            break;
        }
    }

    /* Whatever backpressure left uncollected still counts once the
       plan runs out of rounds - a real body filter chain keeps
       calling until nothing is busy, which this loop stops doing
       once it is out of planned rounds. One last unconditional drain
       is that final call. */
    {
        ngx_chain_t *pending = ngx_http_pack_zstd_encoder_pending(enc);
        for (ngx_chain_t *l = pending; l != NULL; l = l->next) {
            size_t n_out = (size_t) ngx_buf_size(l->buf);
            if (n_out > 0 && produced_len + n_out <= ACCUM_CAP) {
                memcpy(produced + produced_len, l->buf->pos, n_out);
                produced_len += n_out;
            }
            l->buf->pos = l->buf->last;
        }
        ngx_http_pack_zstd_encoder_drained(enc);
    }

    if (ngx_http_pack_zstd_encoder_frame_closed(enc)) {
        check_roundtrip(produced, produced_len, fed, fed_len);
    }
    /* Not closed: a round budget cut the run short before the frame
       ended, same as a real response a client aborted mid-stream -
       nothing to check a partial frame against. */

out:
    free(fed);
    free(produced);
    ngx_http_pack_zstd_encoder_close(enc);
    ngx_destroy_pool(pool);
    return 0;
}
