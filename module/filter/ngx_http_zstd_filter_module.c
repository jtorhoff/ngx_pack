/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) Google Inc.
 * Copyright (C) 2026 Juri Torhoff
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

/* Needed for ZSTD_createCCtx_advanced (the custom allocator), the
   ZSTD_WINDOWLOG_* / ZSTD_WINDOWLOG_LIMIT_DEFAULT bounds, and
   ZSTD_c_srcSizeHint. The symbols this unlocks are already exported
   with default visibility in a normal (dynamically linked) libzstd -
   "static linking only" is a promise about API stability across
   releases, not a linker restriction - so this does not commit the
   module to actually linking libzstd statically. See PORTING.md.

   ZSTD_c_srcSizeHint is the one of those that is genuinely
   experimental rather than merely gated: it is a numbered slot
   (ZSTD_c_experimentalParam7), so a release that reassigned that
   number would have this silently set some other parameter, which no
   compile-time check would catch. Acceptable here only because
   deps/zstd is vendored and pinned, so the number is fixed by the
   tree rather than by whatever libzstd a host happens to carry. A
   build against a system libzstd should re-check it. */
#define ZSTD_STATIC_LINKING_ONLY
#include <zstd.h>

#include "../common/ngx_http_zstd_headers.h"


/* Tells nginx to wait for output.
   Zstandard and GZip never stack, i.e. when one of them sets
   "Content-Encoding" the other becomes a pass-through filter.
   This is why it's safe to re-use the constant here. */
#define NGX_HTTP_ZSTD_BUFFERED NGX_HTTP_GZIP_BUFFERED

/* The most input that may be held back while waiting to learn the
   response size. There is no point deferring longer than the window
   the encoder would use anyway - zstd_window's compiled-in default,
   below - since committing beyond it cannot change the window choice
   any further.

   That also happens to be one zstd block: a block is
   MIN(windowSize, ZSTD_BLOCKSIZE_MAX) and the window default is the
   smaller of the two, so at 64 KB the two coincide. Brotli's
   equivalent constant was derived from its fixed internal block size
   and this one is derived from the window, but they land on the same
   bound. Both follow zstd_window, so move them together. */
#define NGX_HTTP_ZSTD_MAX_HELD_INPUT (64 * 1024)

/* The largest windowLog zstd_window accepts. ZSTD_WINDOWLOG_MAX is
   the codec's own ceiling (31 bits on a 64-bit build); capped at
   ZSTD_WINDOWLOG_LIMIT_DEFAULT (27, i.e. 128 MB) because that is the
   size a decoder accepts without being asked to opt into more - most
   notably browsers, which is what this module serves. A window
   beyond it would produce a response some clients simply refuse to
   decode. */
#define NGX_HTTP_ZSTD_MAX_WINDOW_BITS                                \
    (ZSTD_WINDOWLOG_MAX < ZSTD_WINDOWLOG_LIMIT_DEFAULT               \
            ? ZSTD_WINDOWLOG_MAX                                     \
            : ZSTD_WINDOWLOG_LIMIT_DEFAULT)

/* Size of the buffer the module allocates and hands ZSTD_outBuffer.
   zstd has no equivalent of Brotli's BrotliEncoderTakeOutput, which
   returned a pointer into encoder-owned memory and so needed no
   buffer of the filter's own - see PORTING.md - so this exists
   purely because we now own that memory.

   Deliberately far below ZSTD_CStreamOutSize(), and not for memory
   reasons alone: that value is 128.5 KB because it is sized from
   ZSTD_BLOCKSIZE_MAX rather than from the window actually set, and a
   block is MIN(windowSize, ZSTD_BLOCKSIZE_MAX), so at the 64 KB
   window default one block needs ZSTD_compressBound(64 KB) = 64.3 KB
   at worst - half the recommendation.

   Raising it does not buy throughput. zstd emits at most one block
   per ZSTD_compressStream2 call, so the number of rounds the encoder
   needs has a floor the buffer cannot lower: measured on
   script/corpus prose.txt (five 64 KB blocks) the count falls 28 ->
   15 -> 8 as this goes 4K -> 8K -> 16K, then sits at 5 for 32K, 64K
   and 128.5K alike. Past 32K it also costs CPU - 64.3K measured ~10%
   slower per request than 16K across repeated release-build runs,
   most likely cache residency against the encoder's own tables.
   16K is therefore a choice, not a placeholder. Re-measure if
   zstd_window's default moves, since the block size follows the
   window and the plateau follows the block.

   How many buffers of this size a response may hold at once is
   zstd_buffers, and that one is configurable; this is the size of
   each. Overridable at build time only so that the test suite can
   shrink it far below anything sane - see
   script/test-small-buffer.sh, which uses 64 bytes to force the
   partial-drain paths that a 16 KB buffer reaches only rarely. Not a
   configuration knob: there is no directive behind this, and nothing
   but the stress build should set it. */
#ifndef NGX_HTTP_ZSTD_OUT_SIZE
#define NGX_HTTP_ZSTD_OUT_SIZE (16 * 1024)
#endif

/* How many buffers carrying "flush" may share one zstd block.

   A flush cuts the block short, and a short block is expensive twice
   over. Measured on script/corpus at level 3 with input arriving in
   4 KB buffers: flushing every buffer costs 57-72% more encoder time
   than not flushing at all, and up to 3% more bytes. A flush landing
   on a 64 KB boundary costs nothing, because a block is
   MIN(windowSize, ZSTD_BLOCKSIZE_MAX) and that is where the encoder
   was going to end one anyway.

   Several flush-marked buffers do arrive together, and routinely:
   ngx_http_proxy_chunked_filter appends one buffer per parsed chunk
   and sets flush on every one, so a read carrying several chunks of a
   proxy_buffering-off response becomes a single chain of flush
   markers. Only the last of them needs to cut a block - nothing has
   been written out between them, so the client cannot tell the
   difference.

   Bounded rather than unlimited because the bytes behind a folded
   flush stay inside the encoder until the fold ends, and a flush
   marker is a request to push data out now. Four holds the usual
   burst in one block while keeping the deferral short. */
#define NGX_HTTP_ZSTD_MAX_FOLDED_FLUSHES 4

/* What the encoder is told to expect from a response whose length is
   never learned - see ZSTD_c_srcSizeHint at the call site.

   Unlike ZSTD_CCtx_setPledgedSrcSize this is a guess, not a promise:
   it is not written to the frame header and not checked at the end of
   the frame, so it may be wrong in either direction. That is the
   whole reason it can be used here at all. A pledge cannot: it is
   "controlled at end of frame, and trigger an error if not respected"
   (zstd.h), so pledging a fixed size for a stream would fail every
   response that did not happen to be exactly that long, with
   "Src size is incorrect".

   Without one of the two, zstd sizes its match-finder tables for the
   worst case the window allows, which is what makes a stream cost
   several times what the same body costs when its length is known -
   see the pledge below. Measured on script/corpus prose.txt at level
   6, peak live encoder bytes with no hint / with this one:
   3,089,713 -> 1,123,633 at the 64 KB zstd_window default, and
   3,532,305 -> 2,221,585, 3,925,521 -> 3,663,377, 5,498,385 ->
   3,663,377 at 128 KB, 512 KB and 2 MB. At every one of those it
   matches or beats what the exact pledge achieves.

   256 KB rather than the window, which was the first guess and is
   wrong twice over: at the default it is the one value that costs
   ratio (97,500 bytes against 95,881 here, the "regress
   significantly if guess considerably underestimates" zstd.h warns
   of), and above 256 KB it stops capping the tables at all. Nor
   smaller: 128 KB does cut memory further, to 1,566,225, but at
   96,462 bytes - 3.0% worse output for memory this module does not
   need. 256 KB is the smallest hint measured to cost no ratio
   (0.17% at the default window, nothing at all above it) while still
   bounding the tables at every window setting. Re-measure if
   zstd_window's default moves. */
#define NGX_HTTP_ZSTD_SRC_SIZE_HINT (256 * 1024)

#define NGX_HTTP_ZSTD_LEVEL_MIN 1
#define NGX_HTTP_ZSTD_LEVEL_MAX 22

/* Module configuration. */
typedef struct {
    ngx_flag_t enable;

    /* Supported MIME types. */
    ngx_hash_t   types;
    ngx_array_t *types_keys;

    /* Minimal required length for compression (if known). */
    ssize_t min_length;

    /* zstd encoder parameter: ZSTD_c_compressionLevel */
    ngx_int_t level;

    /* zstd encoder parameter: (max) ZSTD_c_windowLog, in bits */
    size_t window_bits;

    /* How many output buffers one response may have in flight. Their
       size is not configurable - see NGX_HTTP_ZSTD_OUT_SIZE. */
    ngx_int_t buffers;
} ngx_http_zstd_conf_t;

/* What one turn of the encoder decided to do next. The loop owns the
   returns; a step only says which one. */
typedef enum {
    /* Made progress; go round again. */
    NGX_HTTP_ZSTD_STEP_CONTINUE = 0,
    /* The encoder has nothing more to give until it is fed again. */
    NGX_HTTP_ZSTD_STEP_DONE,
    /* Stopped for want of a free output buffer, with work still to
       do. Whether that can be resolved depends on what the filters
       below hand back, so the loop decides. */
    NGX_HTTP_ZSTD_STEP_AGAIN,
    /* Unrecoverable; the loop closes the stream and returns
       NGX_ERROR. */
    NGX_HTTP_ZSTD_STEP_FAILED
} ngx_http_zstd_step_e;

/* What the body filter should do once ngx_http_zstd_filter_prepare
   has settled the decisions that come before the encoder.

   Only OK carries on; the other three end the call and return "rc",
   which every one of them sets. The caller therefore tests against
   OK alone and does not branch on which of the three it got - they
   are apart for the reader, and so that a future caller can tell a
   response that was handed on from one that failed. */
typedef enum {
    /* Carry on into the encoder loop. */
    NGX_HTTP_ZSTD_OK = 0,
    /* Not yet: too little of the body has arrived to answer the
       question zstd_min_length asks, or its size is still unknown
       and worth waiting a moment to learn before the encoder window
       is fixed. The input stays in ctx->in and a later call decides,
       so this may still end in compression. "rc" is NGX_OK. */
    NGX_HTTP_ZSTD_DEFER,
    /* Settled, and not compressed: the response is too small to be
       worth it, so the held input has already been handed to the
       filters below untouched. "rc" is what that call returned, and
       the response goes out intact - no "Content-Encoding" of ours
       for the filters below to defer to, so gzip may still take it.
     */
    NGX_HTTP_ZSTD_PASS,

    /* Settled, and failed: the encoder is closed and "rc" is
       NGX_ERROR. Reached when committing the held headers fails, or
       when a filter below replaced the response with a status - see
       ngx_http_zstd_filter_prepare, which explains why that has to
       become NGX_ERROR rather than travel as the status itself. */
    NGX_HTTP_ZSTD_ERROR
} ngx_http_zstd_prepare_e;

/* The response's flags, in the order a request sets them: the header
   filter decides, send_headers commits, the body filter records what
   it was called with, the encoder is built, input accumulates inside
   it, the frame ends, the instance closes. Two are assigned a test
   rather than a literal 1 - accepted_for_compression may take a
   min_length comparison, caller_wants_output takes (in == NULL) - and
   sit where they are assigned at all.

   The order follows the path where the length is known up front.
   With no Content-Length the decision moves into
   ngx_http_zstd_filter_prepare, so caller_wants_output is assigned
   before the first two rather than after them.

   Kept together so they stay one contiguous bitfield run wherever
   the context puts them: split across the members between their
   first uses they would take a storage unit each, 128 bytes against
   104. Embedded by value, never by pointer - ngx_pcalloc then zeroes
   every flag along with the rest of the context, which is what lets
   "not yet" be the starting state. */
typedef struct {
    /* 1 if this response has been accepted for compression. Decided
       either in the header filter, when the length is known up front,
       or in ngx_http_zstd_filter_prepare once enough of the body has
       arrived to judge it; ngx_http_zstd_filter_send_headers reads it
       to know which kind of header to commit. */
    unsigned accepted_for_compression : 1;

    /* 1 once the response headers have been committed. Zero until
       then, which is what ngx_pcalloc leaves and what the header
       filter depends on: with no Content-Length there is nothing to
       compare against zstd_min_length yet, so it holds the headers
       back by leaving this zero and lets the body decide.

       Set only where compressed headers are committed, so the
       uncompressed exit from ngx_http_zstd_filter_send_headers
       leaves it zero even though it too sends the headers on. That
       is safe only because the same branch closes the context, and
       a closed context never reaches ngx_http_zstd_filter_prepare
       again - were it to stop closing, the headers would be
       committed a second time. */
    unsigned headers_sent : 1;

    /* 1 if this call of the body filter arrived with no new data,
       i.e. nginx is asking for progress on what it has already handed
       over rather than adding to it. Set once on entry and read by
       both ngx_http_zstd_filter_prepare and
       ngx_http_zstd_filter_compress. */
    unsigned caller_wants_output : 1;

    /* 1 if the encoder, output chain and buffer are allocated. */
    unsigned initialized : 1;

    /* 1 if input has been handed to the encoder under ZSTD_e_continue
       that it may still be holding, unflushed. zstd gives no query
       for "is anything buffered" the way Brotli's
       BrotliEncoderHasMoreOutput did, so this tracks it: set when a
       continue call consumes bytes, cleared once a flush fully
       drains. */
    unsigned unflushed_input : 1;

    /* 1 once ZSTD_compressStream2(..., ZSTD_e_end) has reported
       "fully flushed" (a return of 0). */
    unsigned frame_closed : 1;

    /* 1 if compression is finished / failed. */
    unsigned closed : 1;
} ngx_http_zstd_ctx_state_t;

typedef struct {
    /* zstd compression context instance. */
    ZSTD_CCtx *cctx;

    /* The directive a round with no input left has to repeat, or
       ZSTD_e_continue for "nothing owed".

       A flush or an end that returns a nonzero "remaining" has not
       finished; it has to be called again, with empty input, until
       it returns 0. Repeating it is not conditional on the caller
       asking for output: a flush the caller did not ask for (an
       input buffer arriving with the "flush" flag set) still has to
       be drained once started, or the bytes it owes downstream stay
       stuck inside the encoder indefinitely. Reaching the end of the
       input is the same situation - the buffer carrying last_buf is
       compressed under ZSTD_e_end, and until that reports 0 the
       frame is still open - which is why one field covers both
       rather than a bit each.

       ZSTD_e_continue is 0, so ngx_pcalloc starts this right. */
    ZSTD_EndDirective repeat_mode;
} ngx_http_zstd_ctx_z_t;

/* Instance context. The request and the two grouped sub-states lead;
   the rest follows the path a response takes through the filter -
   what is known about it, the input chain, the output chains, the
   buffers behind them, and the block being built. */
typedef struct {
    ngx_http_request_t *request;

    ngx_http_zstd_ctx_state_t state;

    ngx_http_zstd_ctx_z_t z;

    /* Payload length; -1, if unknown. */
    off_t content_length;

    /* Input buffer chain. */
    ngx_chain_t *in;

    /* Output buffers, in the three states nginx's chain helpers keep
       them in. Unlike the Brotli filter these point at memory *we*
       allocated, not at anything the encoder owns - see PORTING.md.

       "out" holds what has been filled this call and not yet handed
       on, "busy" what has been handed on and not yet fully consumed,
       and "free" what has come back and may be refilled.
       ngx_chain_update_chains moves links from busy to free as the
       filters below drain them, which is the whole reason a response
       can have more than one buffer in flight: with a single buffer
       the encoder has to stop until that one comes back. */
    ngx_chain_t  *out;
    ngx_chain_t **last_out;
    ngx_chain_t  *busy;
    ngx_chain_t  *free;

    /* How many buffers have been created so far, against
       zstd_buffers. Created on demand rather than up front, so a
       response that never needs a second one never pays for it. */
    ngx_uint_t buffers;
    size_t     out_size;

    /* How many flush-marked buffers have been folded into the block
       still being built - see NGX_HTTP_ZSTD_MAX_FOLDED_FLUSHES. Reset
       whenever a flush or the end of the frame completes, since that
       is what starts the next block. */
    ngx_uint_t folded_flushes;
} ngx_http_zstd_ctx_t;

/* Forward declarations. What each of these does is documented at its
   definition, not here, so the explanation sits with the code. */

static void ngx_http_zstd_filter_close(ngx_http_zstd_ctx_t *ctx);

static void *ngx_http_zstd_filter_alloc(void *opaque, size_t size);
static void ngx_http_zstd_filter_free(void *opaque, void *address);
static void ngx_http_zstd_filter_cleanup(void *data);

static ngx_int_t ngx_http_zstd_filter_send_headers(
    ngx_http_zstd_ctx_t *ctx);

static ngx_uint_t ngx_http_zstd_filter_may_fold_flush(
    ngx_chain_t *rest, ngx_uint_t folded);
static ngx_int_t ngx_http_zstd_filter_release_buf(
    ngx_http_zstd_ctx_t *ctx, ngx_buf_t *buf);

static void *ngx_http_zstd_create_conf(ngx_conf_t *cf);
static char *ngx_http_zstd_merge_conf(
    ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t ngx_http_zstd_filter_init(ngx_conf_t *cf);

static char *ngx_http_zstd_parse_window(
    ngx_conf_t *cf, void *post, void *data);

/* Configuration literals. */

/* 1 and 22 are zstd's own documented stable range (ZSTD_minCLevel()
   and ZSTD_maxCLevel() are runtime functions, not compile-time
   constants, so they cannot fill an ngx_conf_num_bounds_t literal the
   way Brotli's BROTLI_MIN/MAX_QUALITY macros could); negative levels
   are a real part of zstd's range but are not exposed through this
   directive. */
static ngx_conf_num_bounds_t ngx_http_zstd_comp_level_bounds = {
    ngx_conf_check_num_bounds, NGX_HTTP_ZSTD_LEVEL_MIN,
    NGX_HTTP_ZSTD_LEVEL_MAX};

/* One buffer is enough to be correct - the filter simply stalls until
   the filters below have taken it - so the floor is 1 rather than
   anything larger. The ceiling is arbitrary but not unbounded: each
   buffer costs NGX_HTTP_ZSTD_OUT_SIZE for the lifetime of the
   response, and past a handful the win is gone anyway. */
static ngx_conf_num_bounds_t ngx_http_zstd_buffers_bounds = {
    ngx_conf_check_num_bounds, 1, 64};

static ngx_conf_post_handler_pt ngx_http_zstd_parse_window_p =
    ngx_http_zstd_parse_window;

static ngx_command_t ngx_http_zstd_filter_commands[] = {
    {ngx_string("zstd"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
            NGX_HTTP_LIF_CONF | NGX_CONF_FLAG,
        ngx_conf_set_flag_slot, NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_zstd_conf_t, enable), NULL},

    {ngx_string("zstd_types"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
            NGX_CONF_1MORE,
        ngx_http_types_slot, NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_zstd_conf_t, types_keys),
        &ngx_http_html_default_types[0]},

    {ngx_string("zstd_comp_level"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
            NGX_CONF_TAKE1,
        ngx_conf_set_num_slot, NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_zstd_conf_t, level),
        &ngx_http_zstd_comp_level_bounds},

    {ngx_string("zstd_window"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
            NGX_CONF_TAKE1,
        ngx_conf_set_size_slot, NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_zstd_conf_t, window_bits),
        &ngx_http_zstd_parse_window_p},

    {ngx_string("zstd_buffers"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
            NGX_CONF_TAKE1,
        ngx_conf_set_num_slot, NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_zstd_conf_t, buffers),
        &ngx_http_zstd_buffers_bounds},

    {ngx_string("zstd_min_length"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
            NGX_CONF_TAKE1,
        ngx_conf_set_size_slot, NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_zstd_conf_t, min_length), NULL},

    ngx_null_command};

/* Module context hooks. */
static ngx_http_module_t ngx_http_zstd_filter_module_ctx = {
    NULL,                      /* pre-configuration */
    ngx_http_zstd_filter_init, /* post-configuration */

    NULL,                      /* create main configuration */
    NULL,                      /* init main configuration */

    NULL,                      /* create server configuration */
    NULL,                      /* merge server configuration */

    ngx_http_zstd_create_conf, /* create location configuration */
    ngx_http_zstd_merge_conf   /* merge location configuration */
};

/* Module descriptor. */
ngx_module_t ngx_http_zstd_filter_module = {NGX_MODULE_V1,
    &ngx_http_zstd_filter_module_ctx, /* module context */
    ngx_http_zstd_filter_commands,    /* module directives */
    NGX_HTTP_MODULE,                  /* module type */
    NULL,                             /* init master */
    NULL,                             /* init module */
    NULL,                             /* init process */
    NULL,                             /* init thread */
    NULL,                             /* exit thread */
    NULL,                             /* exit process */
    NULL,                             /* exit master */
    NGX_MODULE_V1_PADDING};

/* Next filter in the filter chain. */
static ngx_http_output_header_filter_pt ngx_http_next_header_filter;
static ngx_http_output_body_filter_pt   ngx_http_next_body_filter;

/* Process headers and decide if request is eligible for zstd
   compression. */
static ngx_int_t
ngx_http_zstd_header_filter(ngx_http_request_t *r)
{
    ngx_http_zstd_conf_t *conf;
    ngx_http_zstd_ctx_t  *ctx;

    conf =
        ngx_http_get_module_loc_conf(r, ngx_http_zstd_filter_module);

    /* Filter only if enabled. */
    if (!conf->enable) {
        return ngx_http_next_header_filter(r);
    }

    /* Bypass "header only" responses. */
    if (r->header_only) {
        return ngx_http_next_header_filter(r);
    }

    /* Bypass statuses that either carry no body, or carry one that
       must not be re-encoded. 1xx/204/304 have no body to compress;
       a 206 body is a byte range, and the "Content-Range" beside it
       still describes the original entity, so compressing it
       corrupts the response. */
    if (r->headers_out.status < NGX_HTTP_OK ||
        r->headers_out.status == NGX_HTTP_NO_CONTENT ||
        r->headers_out.status == NGX_HTTP_PARTIAL_CONTENT ||
        r->headers_out.status == NGX_HTTP_NOT_MODIFIED) {
        return ngx_http_next_header_filter(r);
    }

    /* Bypass already compressed responses. */
    if (r->headers_out.content_encoding &&
        r->headers_out.content_encoding->value.len) {
        return ngx_http_next_header_filter(r);
    }

    /* If response size is known, do not compress tiny responses. */
    if (r->headers_out.content_length_n != -1 &&
        r->headers_out.content_length_n < conf->min_length) {
        return ngx_http_next_header_filter(r);
    }

    /* Compress only certain MIME-typed responses. */
    if (ngx_http_test_content_type(r, &conf->types) == NULL) {
        return ngx_http_next_header_filter(r);
    }

    /* Before the Accept-Encoding test, not after: the response varies
       whether or not this particular client is served Zstandard. */
    if (ngx_http_zstd_set_vary(r) != NGX_OK) {
        return NGX_ERROR;
    }

    /* Check if client supports zstd encoding. */
    if (ngx_http_zstd_claim_request(r) != NGX_OK) {
        return ngx_http_next_header_filter(r);
    }

    /* Prepare instance context. */
    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_zstd_ctx_t));
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ctx->request        = r;
    ctx->content_length = r->headers_out.content_length_n;
    ngx_http_set_ctx(r, ctx, ngx_http_zstd_filter_module);

    r->main_filter_need_in_memory = 1;

    /* When the length is unknown there is nothing yet to compare
       against zstd_min_length, and committing the headers here would
       settle the question for good. Hold them instead. */
    if (ctx->content_length < 0) {
        return NGX_OK;
    }

    ctx->state.accepted_for_compression = 1;

    return ngx_http_zstd_filter_send_headers(ctx);
}

/* Commits headers that ngx_http_zstd_header_filter held back. If the
   response was accepted it is labelled and the encoder will run; if
   not it passes through untouched, leaving no "Content-Encoding" for
   the filters below to defer to, so gzip may still take it.

   Which of the two it is comes from ctx->accepted_for_compression,
   set by whichever caller made the decision. */
static ngx_int_t
ngx_http_zstd_filter_send_headers(ngx_http_zstd_ctx_t *ctx)
{
    ngx_http_request_t *r;
    ngx_int_t           rc;

    r = ctx->request;

    if (!ctx->state.accepted_for_compression) {
        /* Nothing has been allocated yet on this path - the headers
           are only held while the encoder does not exist - so this
           closes an empty instance.

           Closing is also what lets headers_sent stay zero here. The
           headers do go out, so the flag understates what happened;
           it is never read again because its only reader is
           ngx_http_zstd_filter_prepare, and the body filter returns
           on ctx->closed before it gets there. The two belong
           together - dropping the close would leave a context that
           reports unsent headers and commits them a second time. */
        ngx_http_zstd_filter_close(ctx);
        return ngx_http_next_header_filter(r);
    }

    /* Tell the filters below that the body is compressed. */
    if (ngx_http_zstd_set_content_encoding(r) != NGX_OK) {
        return NGX_ERROR;
    }

    ngx_http_clear_content_length(r);
    ngx_http_clear_accept_ranges(r);
    ngx_http_weak_etag(r);

    rc = ngx_http_next_header_filter(r);

    ctx->state.headers_sent = 1;

    return rc;
}

/* Hands back a buffer to compress into.

   NGX_OK with "*out" set, NGX_DECLINED when every buffer this
   response is allowed is already in flight, or NGX_ERROR. DECLINED is
   not a failure: it means the encoder has to wait for the filters
   below to give one back, which is what the loop turns into a send.

   Buffers are created on demand and then recycled through ctx->free
   for the rest of the response, so a response that only ever needs
   one never allocates a second. */
static ngx_int_t
ngx_http_zstd_filter_get_buf(
    ngx_http_zstd_ctx_t *ctx, ngx_buf_t **out)
{
    ngx_http_request_t   *r;
    ngx_chain_t          *link;
    ngx_http_zstd_conf_t *conf;
    ngx_buf_t            *buf;

    r = ctx->request;

    if (ctx->free != NULL) {
        link      = ctx->free;
        ctx->free = link->next;
        buf       = link->buf;

        ngx_free_chain(r->pool, link);

        /* ngx_chain_update_chains has already rewound pos and last to
           start; the flags are this filter's to set per round. */
        *out = buf;
        return NGX_OK;
    }

    conf =
        ngx_http_get_module_loc_conf(r, ngx_http_zstd_filter_module);
    if ((ngx_int_t) ctx->buffers >= conf->buffers) {
        return NGX_DECLINED;
    }

    buf = ngx_create_temp_buf(r->pool, ctx->out_size);
    if (buf == NULL) {
        return NGX_ERROR;
    }

    /* The tag is what lets ngx_chain_update_chains tell our buffers
       apart from anything else on the busy list and hand them back
       rather than dropping the link. "recycled" tells the filters
       below that this memory is going to be reused, so they must not
       sit on it. */
    buf->tag      = (ngx_buf_tag_t) &ngx_http_zstd_filter_module;
    buf->recycled = 1;

    ctx->buffers++;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
        "zstd buffer created: %p, total:%ui", buf, ctx->buffers);

    *out = buf;
    return NGX_OK;
}

/* Runs the encoder once and, if it produced anything, appends a
   buffer to ctx->out. This is where the Brotli module's take_output
   and feed_encoder merge into one step: ZSTD_compressStream2 moves
   input and output in a single call, so there is no separate "does
   the encoder have output ready" phase to ask about first - see
   PORTING.md section 3. */
static ngx_http_zstd_step_e
ngx_http_zstd_filter_compress(ngx_http_zstd_ctx_t *ctx)
{
    ngx_http_request_t *r;
    ngx_uint_t          folded;
    ZSTD_EndDirective   zmode;
    ZSTD_inBuffer       zin;
    ngx_buf_t          *buf;
    ngx_chain_t        *link;
    ngx_buf_t          *out_buf;
    ngx_int_t           rc;
    ZSTD_outBuffer      zout;
    size_t              zremaining;

    r = ctx->request;

    folded = 0;

    /* Tested ahead of the input, not inside the branch that finds
       none left. A closed frame means the response is over whatever
       is still queued: anything after the buffer carrying last_buf
       would otherwise be compressed into a second frame and committed
       with last_buf set again, since that flag is copied from
       frame_closed. nginx does not produce a chain like that, so this
       guards an assumption rather than an observed case.

       Closing the encoder is the loop's job rather than this one's:
       the buffer carrying last_buf may still be sitting in ctx->out
       or ctx->busy, and the encoder is not done with the response
       until the filters below have taken it. */
    if (ctx->state.frame_closed) {
        return NGX_HTTP_ZSTD_STEP_DONE;
    }

    if (ctx->in == NULL) {
        if (ctx->z.repeat_mode != ZSTD_e_continue) {
            /* Finishing what was started takes priority over asking
               whether the caller wants output - see repeat_mode. */
            zmode = ctx->z.repeat_mode;
        } else if (ctx->state.caller_wants_output &&
                   ctx->state.unflushed_input) {
            zmode = ZSTD_e_flush;
        } else {
            /* Nothing to do; wait for more input. */
            return NGX_HTTP_ZSTD_STEP_DONE;
        }

        zin.src  = NULL;
        zin.size = 0;
        zin.pos  = 0;
    } else {
        buf = ctx->in->buf;

        /* Only what is in memory can be compressed, and zin.src can
           only be the memory pointer - so the length has to come from
           the same place. ngx_buf_size() would not: for a buffer
           backed by a file it reports the file range, which paired
           with buf->pos describes nothing. nginx's own gzip filter
           takes "last - pos" for exactly this reason.

           A buffer holding file bytes and none in memory should not
           reach us at all: the header filter sets
           main_filter_need_in_memory, and the copy filter above us in
           the chain honours it. If one does, something between the
           two ignored it, and there is nothing here that can encode
           it - so say so rather than hand zstd a pointer that does
           not describe the data. */
        if (buf->in_file && !ngx_buf_in_memory(buf)) {
            ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                "zstd got a buffer with file bytes and none in "
                "memory: main_filter_need_in_memory was not "
                "honoured");

            return NGX_HTTP_ZSTD_STEP_FAILED;
        }

        /* An empty buffer carries nothing to compress, but one
           marked last or flush still has to reach the encoder to
           close the stream or the block. Anything else is dropped. */
        if (ngx_buf_size(buf) == 0 && !buf->last_buf && !buf->flush) {
            link    = ctx->in;
            ctx->in = link->next;

            ngx_free_chain(r->pool, link);

            return NGX_HTTP_ZSTD_STEP_CONTINUE;
        }

        if (buf->last_buf) {
            zmode = ZSTD_e_end;
        } else if (buf->flush) {
            /* Counted below rather than here: acquiring an output
               buffer can still fail, and a fold recorded on a round
               that never reached the encoder would spend part of the
               allowance on nothing. */
            folded = ngx_http_zstd_filter_may_fold_flush(
                ctx->in->next, ctx->folded_flushes);

            if (folded) {
                zmode = ZSTD_e_continue;
            } else {
                zmode = ZSTD_e_flush;
            }
        } else {
            zmode = ZSTD_e_continue;
        }

        zin.src = buf->pos;
        /* "last > pos" as well as the in-memory test: the subtraction
           is unsigned, so an inverted buffer would become an enormous
           length and read far past the allocation. */
        if (ngx_buf_in_memory(buf) && buf->last > buf->pos) {
            zin.size = (size_t) (buf->last - buf->pos);
        } else {
            zin.size = 0;
        }
        zin.pos = 0;
    }

    /* Last thing before the encoder runs, and nothing above it has
       touched the input or the fold count yet, so giving up here
       costs nothing and can simply be repeated once a buffer comes
       back. */
    rc = ngx_http_zstd_filter_get_buf(ctx, &out_buf);
    if (rc == NGX_ERROR) {
        return NGX_HTTP_ZSTD_STEP_FAILED;
    }

    if (rc == NGX_DECLINED) {
        return NGX_HTTP_ZSTD_STEP_AGAIN;
    }

    zout.dst  = out_buf->start;
    zout.size = ctx->out_size;
    zout.pos  = 0;

    zremaining =
        ZSTD_compressStream2(ctx->z.cctx, &zout, &zin, zmode);
    if (ZSTD_isError(zremaining)) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
            "ZSTD_compressStream2() failed: %s",
            ZSTD_getErrorName(zremaining));

        return NGX_HTTP_ZSTD_STEP_FAILED;
    }

    if (folded) {
        ctx->folded_flushes++;
    }

    /* Record progress in the chain itself. It cannot be kept in
       "in.pos" alone, which does not survive returning to nginx.
       "in.pos" is the right amount to advance by whatever the mode:
       a flush or an end call may also leave input partially
       unconsumed if the output buffer filled first - see the doc
       comment on ZSTD_compressStream2. */
    if (ctx->in != NULL) {
        buf = ctx->in->buf;

        /* Guarded, not just for tidiness: a special buffer carries no
           memory, so pos is NULL, and advancing a null pointer by
           zero is undefined even though every compiler does the
           obvious thing. UBSan reports it on the last_buf that
           ngx_http_send_special emits. */
        if (zin.pos > 0) {
            buf->pos += zin.pos;
        }

        if (ngx_buf_size(buf) == 0) {
            link    = ctx->in;
            ctx->in = link->next;

            ngx_free_chain(r->pool, link);
        }
    }

    if (zmode == ZSTD_e_continue) {
        if (zin.pos > 0) {
            ctx->state.unflushed_input = 1;
        }
    } else if (zremaining != 0) {
        /* Not finished, whichever of the two it was: repeat it once
           the input in hand has been consumed. */
        ctx->z.repeat_mode = zmode;
    } else {
        ctx->z.repeat_mode = ZSTD_e_continue;

        /* Either directive ends the block, so the next one starts
           with nothing folded into it. */
        ctx->folded_flushes = 0;

        if (zmode == ZSTD_e_flush) {
            ctx->state.unflushed_input = 0;
        } else { /* ZSTD_e_end */
            ctx->state.frame_closed = 1;
        }
    }

    /* Draining with no input left, and the call neither wrote a byte
       nor finished: the next round repeats it with the same state and
       the worker spins. zstd should never do this - a flush or an end
       against a whole free output buffer either writes or reports
       nothing remaining - so this is a guard against a spin, which is
       a far worse way to fail than an error. */
    if (ctx->in == NULL && zout.pos == 0 && zremaining != 0) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
            "ZSTD_compressStream2() made no progress: mode:%d "
            "remaining:%uz",
            (int) zmode, zremaining);

        return NGX_HTTP_ZSTD_STEP_FAILED;
    }

    /* Nothing produced this round, and not finished: go round again
       rather than returning - a flush or an end still being drained
       has to be retried, and the caller is otherwise not owed a
       return yet. The buffer goes back unused, or the round would
       spend one out of zstd_buffers on nothing. */
    if (zout.pos == 0 && !ctx->state.frame_closed) {
        if (ngx_http_zstd_filter_release_buf(ctx, out_buf) !=
            NGX_OK) {
            return NGX_HTTP_ZSTD_STEP_FAILED;
        }

        return NGX_HTTP_ZSTD_STEP_CONTINUE;
    }

    /* Reached even when out.pos is 0: should the call that finally
       drives "remaining" to 0 ever not write new bytes, the last_buf
       marker still has to land on some buffer or nginx never learns
       the response ended.

       That empty buffer has to be a *special* one, which is why
       "temporary" is set here per round rather than once at
       initialization. ngx_buf_special() is false for anything
       ngx_buf_in_memory() accepts, and ngx_http_write_filter rejects
       a zero-size non-special buffer outright - it logs "zero size
       buf in writer" and returns NGX_ERROR, truncating the response
       rather than merely complaining. So a buffer carrying no bytes
       must claim no memory either.

       Measured before being written: across 3360 combinations of
       output capacity, input length, level and chunk size, zstd
       never once returned 0 from ZSTD_e_end while writing 0 bytes,
       and the full suite at a 64-byte output buffer never reached
       this branch. It is defence against a contract change, not a
       case seen in practice. */
    out_buf->pos       = out_buf->start;
    out_buf->last      = out_buf->start + zout.pos;
    out_buf->temporary = (zout.pos > 0);
    out_buf->sync      = (zout.pos == 0);
    out_buf->flush     = (zmode == ZSTD_e_flush);
    out_buf->last_buf  = ctx->state.frame_closed;

    link = ngx_alloc_chain_link(r->pool);
    if (link == NULL) {
        return NGX_HTTP_ZSTD_STEP_FAILED;
    }

    link->buf      = out_buf;
    link->next     = NULL;
    *ctx->last_out = link;
    ctx->last_out  = &link->next;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
        "zstd out: %p, size:%O", out_buf, ngx_buf_size(out_buf));

    return NGX_HTTP_ZSTD_STEP_CONTINUE;
}

/* Puts an unused buffer back where get_buf will find it again. */
static ngx_int_t
ngx_http_zstd_filter_release_buf(
    ngx_http_zstd_ctx_t *ctx, ngx_buf_t *buf)
{
    ngx_chain_t *link;

    link = ngx_alloc_chain_link(ctx->request->pool);
    if (link == NULL) {
        return NGX_ERROR;
    }

    link->buf  = buf;
    link->next = ctx->free;
    ctx->free  = link;

    return NGX_OK;
}

/* Whether the flush on the buffer at the head of the chain may be
   folded into the block being built rather than cutting one here.
   "rest" is what follows that buffer, "folded" how many flushes have
   already gone into this block.

   Two conditions, and the first is what makes this safe: the chain
   must already hold a later buffer that flushes or ends the stream,
   so the flush being deferred is certain to be honoured in the same
   batch. Nothing here may swallow one - a flush marker deferred past
   the input in hand would leave bytes sitting in the encoder with
   nothing scheduled to push them out. The second is the cap, which
   bounds the fold and, with it, this scan. */
static ngx_uint_t
ngx_http_zstd_filter_may_fold_flush(
    ngx_chain_t *rest, ngx_uint_t folded)
{
    ngx_uint_t   lookahead;
    ngx_chain_t *link;

    if (folded + 1 >= NGX_HTTP_ZSTD_MAX_FOLDED_FLUSHES) {
        return 0;
    }

    lookahead = NGX_HTTP_ZSTD_MAX_FOLDED_FLUSHES - 1 - folded;

    for (link = rest; link != NULL && lookahead > 0;
        link  = link->next) {
        if (link->buf->flush || link->buf->last_buf) {
            return 1;
        }

        lookahead--;
    }

    return 0;
}

/* Totals the unconsumed input, reporting whether the chain closes the
   response ("complete") and whether anything in it demands to be
   pushed out now ("urgent"). */
static size_t
ngx_http_zstd_filter_pending_input(
    ngx_chain_t *in, ngx_uint_t *complete, ngx_uint_t *urgent)
{
    size_t total;

    *complete = 0;
    *urgent   = 0;

    total = 0;
    for (; in; in = in->next) {
        total += ngx_buf_size(in->buf);
        if (in->buf->last_buf) {
            *complete = 1;
        }

        if (in->buf->flush) {
            *urgent = 1;
        }
    }

    return total;
}

/* Everything that has to be settled before the encoder can run:
   committing headers the header filter held back, and deciding
   whether to go on holding input while the response size is still
   unknown. */
static ngx_http_zstd_prepare_e
ngx_http_zstd_filter_prepare(ngx_http_zstd_ctx_t *ctx, ngx_int_t *rc)
{
    size_t                pending;
    ngx_uint_t            complete;
    ngx_uint_t            urgent;
    ngx_http_zstd_conf_t *conf;
    ngx_int_t             header_rc;
    ngx_chain_t          *link;

    /* The steady state: the headers are away and the encoder exists,
       so there is nothing to settle. */
    if (ctx->state.headers_sent && ctx->state.initialized) {
        return NGX_HTTP_ZSTD_OK;
    }

    pending = ngx_http_zstd_filter_pending_input(
        ctx->in, &complete, &urgent);

    /* Headers held back because the length was unknown. Decide as
       soon as the body answers the only question zstd_min_length
       asks - is it at least that big. A flush marker means something
       downstream is waiting, so decide immediately and compress. */
    if (!ctx->state.headers_sent) {
        conf = ngx_http_get_module_loc_conf(
            ctx->request, ngx_http_zstd_filter_module);

        if (complete) {
            ctx->state.accepted_for_compression =
                (pending >= (size_t) conf->min_length);
        } else if (urgent || pending >= (size_t) conf->min_length) {
            ctx->state.accepted_for_compression = 1;
        } else {
            *rc = NGX_OK;
            return NGX_HTTP_ZSTD_DEFER;
        }

        header_rc = ngx_http_zstd_filter_send_headers(ctx);

        /* An error, or a filter below replacing the response with a
           status. Not "!= NGX_OK": that would catch NGX_AGAIN too,
           which only means the header is queued and the body must
           still be produced. nginx spells the test this way as well.

           Return NGX_ERROR rather than the status, since a body
           filter's callers only understand NGX_ERROR and treat a
           status as success - which left the request hanging. Close,
           or a later call builds an encoder for the replaced response
           and puts the held body on the wire. Both covered by
           script/test-header-status.sh. */
        if (header_rc == NGX_ERROR || header_rc > NGX_OK) {
            ngx_http_zstd_filter_close(ctx);

            *rc = NGX_ERROR;
            return NGX_HTTP_ZSTD_ERROR;
        }

        if (!ctx->state.accepted_for_compression) {
            /* Pass the held input through untouched. */
            link    = ctx->in;
            ctx->in = NULL;

            ctx->request->connection->buffered &=
                ~NGX_HTTP_ZSTD_BUFFERED;

            *rc = ngx_http_next_body_filter(ctx->request, link);
            return NGX_HTTP_ZSTD_PASS;
        }
    }

    /* Choosing the encoder window costs memory that scales with the
       window, so when the response size is unknown it is worth
       waiting a moment to see if the whole thing turns up. */
    if (!ctx->state.initialized) {
        if (complete) {
            if (ctx->content_length < 0) {
                ctx->content_length = (off_t) pending;
            }
        } else if (!ctx->state.caller_wants_output && !urgent &&
                   ctx->content_length < 0 &&
                   pending < NGX_HTTP_ZSTD_MAX_HELD_INPUT) {
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP,
                ctx->request->connection->log, 0,
                "zstd deferring encoder: pending:%uz", pending);

            *rc = NGX_OK;
            return NGX_HTTP_ZSTD_DEFER;
        }
    }

    return NGX_HTTP_ZSTD_OK;
}

/* Initializes encoder, output chain and buffer, if necessary. */
static ngx_int_t
ngx_http_zstd_filter_ensure_stream_init(ngx_http_zstd_ctx_t *ctx)
{
    ngx_http_request_t   *r;
    ngx_http_zstd_conf_t *conf;
    ngx_pool_cleanup_t   *cln;
    ZSTD_customMem        zmem;
    ngx_log_t            *log;
    size_t                zrc;

    if (ctx->state.initialized) {
        return NGX_OK;
    }

    r = ctx->request;
    conf =
        ngx_http_get_module_loc_conf(r, ngx_http_zstd_filter_module);

    /* Encoder memory is not owned by the pool, so arrange for it to
       be released even if the request is aborted mid-stream.
       Registered before the encoder exists, so that a failure here
       cannot strand an allocated instance. */
    cln = ngx_pool_cleanup_add(r->pool, 0);
    if (cln == NULL) {
        return NGX_ERROR;
    }

    cln->handler = ngx_http_zstd_filter_cleanup;
    cln->data    = ctx;

    zmem.customAlloc = ngx_http_zstd_filter_alloc;
    zmem.customFree  = ngx_http_zstd_filter_free;
    zmem.opaque      = r->pool;

    log = r->connection->log;

    ctx->z.cctx = ZSTD_createCCtx_advanced(zmem);
    if (ctx->z.cctx == NULL) {
        ngx_log_error(
            NGX_LOG_ALERT, log, 0, "OOM / ZSTD_createCCtx_advanced");

        return NGX_ERROR;
    }

    zrc = ZSTD_CCtx_setParameter(
        ctx->z.cctx, ZSTD_c_compressionLevel, (int) conf->level);
    if (ZSTD_isError(zrc)) {
        ngx_log_error(NGX_LOG_ALERT, log, 0,
            "ZSTD_CCtx_setParameter(compressionLevel, %i) failed: %s",
            conf->level, ZSTD_getErrorName(zrc));

        return NGX_ERROR;
    }

    /* A ceiling, not a target. Sizing the window down to a known
       response was once done here by hand, which was work zstd
       already does: ZSTD_adjustCParams_internal runs after
       ZSTD_overrideCParams and lowers windowLog to ceil(log2(pledged
       size)) - the same value the loop computed, and it lowers
       hashLog and chainLog to match, which the loop did not. Checked
       across 208 combinations of window ceiling, level and body size:
       identical frame window descriptor and identical peak encoder
       allocation either way. So the ceiling is all this has to set,
       and the pledge below does the rest. */
    zrc = ZSTD_CCtx_setParameter(
        ctx->z.cctx, ZSTD_c_windowLog, (int) conf->window_bits);
    if (ZSTD_isError(zrc)) {
        ngx_log_error(NGX_LOG_ALERT, log, 0,
            "ZSTD_CCtx_setParameter(windowLog, %uz) failed: %s",
            conf->window_bits, ZSTD_getErrorName(zrc));

        return NGX_ERROR;
    }

    /* nginx already parallelises across worker processes, one per
       core, so a per-request thread pool would only oversubscribe -
       see PORTING.md. 0 is the library default, set explicitly so a
       vendored update cannot change it under us. */
    zrc = ZSTD_CCtx_setParameter(ctx->z.cctx, ZSTD_c_nbWorkers, 0);
    if (ZSTD_isError(zrc)) {
        ngx_log_error(NGX_LOG_ALERT, log, 0,
            "ZSTD_CCtx_setParameter(nbWorkers, 0) failed: %s",
            ZSTD_getErrorName(zrc));

        return NGX_ERROR;
    }

    /* Writes the size into the frame header when it is known, which
       helps the decoder allocate. Brotli has no equivalent - see
       PORTING.md.

       It does more than help the decoder, and is worth keeping for
       the other reason: told the source size, zstd sizes its own
       match-finder tables to the body rather than to the window, so
       this call is what keeps a high zstd_comp_level affordable.
       Measured on script/corpus, peak encoder memory plateaus at
       1.07 MB across levels 5, 6 and 9 with it, where the same body
       with nothing said about its size at all costs 2.95, 2.95 and
       10.45 MB - and 640.90 MB at level 22.

       Which is what the else branch covers, so the two are not
       redundant and neither replaces the other: this one is exact,
       is checked at the end of the frame, and reaches the decoder
       through the frame header; that one is a guess that does none
       of those things and is all a response of unknown length can
       offer. Leaving the else empty would be safe in the sense that
       ZSTD_CONTENTSIZE_UNKNOWN is the default for a fresh context,
       and expensive in every other sense.

       The cast must stay 64-bit: content_length is an off_t, and
       "unsigned" would truncate a body over 4 GiB into a pledge zstd
       then rejects. */
    if (ctx->content_length >= 0) {
        zrc = ZSTD_CCtx_setPledgedSrcSize(
            ctx->z.cctx, (uint64_t) ctx->content_length);
        if (ZSTD_isError(zrc)) {
            ngx_log_error(NGX_LOG_ALERT, log, 0,
                "ZSTD_CCtx_setPledgedSrcSize(%O) failed: %s",
                ctx->content_length, ZSTD_getErrorName(zrc));

            return NGX_ERROR;
        }

    } else {
        /* No length to pledge, so give the guess instead - which is
           the difference between tables sized to the body and tables
           sized to the worst case the window allows. See
           NGX_HTTP_ZSTD_SRC_SIZE_HINT for what it costs and why it
           is that number.

           Fatal like the parameters above rather than skipped on
           error, deliberately: libzstd is vendored and pinned (see
           deps/zstd), so a rejection here is a broken build and not
           a library that merely happens to be older, and failing
           loudly beats every stream quietly costing three times the
           memory it should. */
        zrc = ZSTD_CCtx_setParameter(ctx->z.cctx, ZSTD_c_srcSizeHint,
            NGX_HTTP_ZSTD_SRC_SIZE_HINT);
        if (ZSTD_isError(zrc)) {
            ngx_log_error(NGX_LOG_ALERT, log, 0,
                "ZSTD_CCtx_setParameter(srcSizeHint, %d) failed: %s",
                NGX_HTTP_ZSTD_SRC_SIZE_HINT, ZSTD_getErrorName(zrc));

            return NGX_ERROR;
        }
    }

    /* The buffers themselves are created on demand by get_buf, up to
       zstd_buffers of them; most responses never need a second. Only
       the tail pointer has to exist before the first one is
       committed, and ngx_pcalloc cannot set it. */
    ctx->out_size = NGX_HTTP_ZSTD_OUT_SIZE;
    ctx->last_out = &ctx->out;

    /* Last, so that the flag means what it says. */
    ctx->state.initialized = 1;

    /* The ceiling and the pledge, not the window zstd settles on:
       that is chosen from both when compression starts, and the
       library offers no call that reports it back. Read it from the
       frame header instead - script/test_stream.py's frame_window()
       does exactly that. */
    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, log, 0,
        "zstd encoder initialized: lvl:%i win:%uz len:%O",
        conf->level, (size_t) 1 << conf->window_bits,
        ctx->content_length);

    return NGX_OK;
}

/* Response body filtration (compression). */
static ngx_int_t
ngx_http_zstd_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    ngx_http_zstd_ctx_t *ctx;
    ngx_int_t            rc;
    ngx_http_zstd_step_e step;

    ctx = ngx_http_get_module_ctx(r, ngx_http_zstd_filter_module);

    /* r->connection->log inline rather than through a local: this is
       the only use in the function, and ngx_log_debug0 compiles to
       nothing without --with-debug, so a local would be set and never
       read - which -Wunused-but-set-variable rejects under -Werror in
       a release build. */
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
        "http zstd filter");

    if (ctx == NULL || ctx->state.closed || r->header_only) {
        return ngx_http_next_body_filter(r, in);
    }

    /* Recorded before "in" is folded into ctx->in: ctx->in running
       dry says the filter has nothing left to compress, this says
       the caller brought nothing new. */
    ctx->state.caller_wants_output = (in == NULL);

    if (in) {
        if (ngx_chain_add_copy(r->pool, &ctx->in, in) != NGX_OK) {
            ngx_http_zstd_filter_close(ctx);
            return NGX_ERROR;
        }
        r->connection->buffered |= NGX_HTTP_ZSTD_BUFFERED;
    }

    /* prepare sets rc on every path that does not accept, and this is
       what those paths return. Seeded anyway: it is an out-parameter,
       so a path that forgot would return whatever the stack held, and
       being passed by pointer puts it beyond what
       -Wconditional-uninitialized can see. */
    rc = NGX_ERROR;

    if (ngx_http_zstd_filter_prepare(ctx, &rc) != NGX_HTTP_ZSTD_OK) {
        return rc;
    }

    if (ngx_http_zstd_filter_ensure_stream_init(ctx) != NGX_OK) {
        ngx_http_zstd_filter_close(ctx);
        return NGX_ERROR;
    }

    /* Main loop, two phases per turn: fill every output buffer the
       encoder can, then push the lot down in one chain.

       Running the encoder to a standstill before sending is the point
       of having more than one buffer. With a single buffer the two
       phases had to alternate, so a response was compressed and
       written one buffer at a time; here a stalled write only costs
       the encoder its remaining buffers, not its next byte. */
    for (;;) {
        do {
            step = ngx_http_zstd_filter_compress(ctx);
        } while (step == NGX_HTTP_ZSTD_STEP_CONTINUE);

        if (step == NGX_HTTP_ZSTD_STEP_FAILED) {
            ngx_http_zstd_filter_close(ctx);
            return NGX_ERROR;
        }

        /* Nothing new to send and nothing outstanding: the encoder is
           waiting for input rather than for the filters below. */
        if (ctx->out == NULL && ctx->busy == NULL) {
            return NGX_OK;
        }

        /* A NULL chain here is not a no-op: it is what asks the
           filters below to make progress on buffers they are already
           holding, which is the only way a busy buffer comes back. */
        rc = ngx_http_next_body_filter(r, ctx->out);
        if (rc == NGX_ERROR) {
            ngx_http_zstd_filter_close(ctx);
            return NGX_ERROR;
        }

        ngx_chain_update_chains(r->pool, &ctx->free, &ctx->busy,
            &ctx->out, (ngx_buf_tag_t) &ngx_http_zstd_filter_module);
        ctx->last_out = &ctx->out;

        /* What nginx has to be told to come back for. Buffers the
           filters below still hold count, and so does input not yet
           compressed: drop the bit while either is outstanding and a
           stalled last write can be finalized as complete, truncating
           the tail - on a socket too full to take it, which loopback
           tests will not reproduce. */
        if (ctx->busy != NULL || ctx->in != NULL) {
            r->connection->buffered |= NGX_HTTP_ZSTD_BUFFERED;
        } else {
            r->connection->buffered &= ~NGX_HTTP_ZSTD_BUFFERED;
        }

        if (step == NGX_HTTP_ZSTD_STEP_DONE) {
            /* The frame is closed and its last buffer has been taken,
               so the encoder has nothing left to do for this
               response. Freeing here rather than waiting for the
               request pool to be destroyed is what keeps its memory
               from outliving the response - see PORTING.md section 1.
             */
            if (ctx->state.frame_closed && ctx->busy == NULL) {
                ngx_http_zstd_filter_close(ctx);
            }

            /* Buffers still outstanding mean the response is not
               finished, whatever the encoder has to say about it. */
            if (ctx->busy != NULL) {
                return NGX_AGAIN;
            }

            return NGX_OK;
        }

        /* Stopped for want of a buffer. If the send handed one back,
           go round; if not, the filters below are full and there is
           nothing more this call can do. */
        if (ctx->free == NULL) {
            return NGX_AGAIN;
        }
    }

    /* Unreachable: the loop above either returns or goes round
       again. */
}

/* The encoder allocates from the heap, not from the request pool. Its
   allocations vary widely in size and lifetime across the encoder's
   internal state, and ngx_pfree only reclaims "large" blocks, so
   pool-backed ones would pile up until the request ends. "opaque" is
   still the pool, but only for logging. */
static void *
ngx_http_zstd_filter_alloc(void *opaque, size_t size)
{
    ngx_pool_t *pool;
    ngx_log_t  *log;
    void       *p;

    pool = opaque;
    log  = pool->log;
    p    = ngx_alloc(size, log);

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, log, 0,
        "zstd alloc: %p, size:%uz", p, size);

    return p;
}

static void
ngx_http_zstd_filter_free(void *opaque, void *address)
{
#if (NGX_DEBUG)
    ngx_pool_t *pool;
    ngx_log_t  *log;

    pool = opaque;
    log  = pool->log;

    ngx_log_debug1(
        NGX_LOG_DEBUG_HTTP, log, 0, "zstd free: %p", address);
#endif

    ngx_free(address);
}

/* Releases the encoder if the request is terminated before
   compression is finished, i.e. when ngx_http_zstd_filter_close is
   never reached. */
static void
ngx_http_zstd_filter_cleanup(void *data)
{
    ngx_http_zstd_ctx_t *ctx = data;

    /* Takes void * because that is what ngx_pool_cleanup_pt is.
       Declaring the argument typed and casting the function pointer
       at the registration compiles, and works on every ABI this
       targets, but it is undefined behaviour and it turns off the
       one check that would catch the signature drifting.

       Normally the encoder is already gone:
       ngx_http_zstd_filter_close resets the field.
       This is the abort path. */
    if (ctx->z.cctx != NULL) {
        ZSTD_freeCCtx(ctx->z.cctx);
        ctx->z.cctx = NULL;
    }
}

/* Marks instance as closed and performs cleanup. */
static void
ngx_http_zstd_filter_close(ngx_http_zstd_ctx_t *ctx)
{
    ctx->state.closed = 1;

    /* Closed means this instance owes the connection nothing, so the
       bit goes with it - left set it tells nginx output is still
       pending from a filter that has stopped producing any. */
    ctx->request->connection->buffered &= ~NGX_HTTP_ZSTD_BUFFERED;

    ngx_http_zstd_filter_cleanup(ctx);

    /* The buffers and their links point into the request pool:
       nothing to hand back, dropping them is the cleanup. Dropped
       rather than left stale so that a use after close faults instead
       of quietly writing into memory the pool still owns -
       ensure_stream_init guards on "initialized", which close does
       not reset. out_size goes too, to keep it coherent with them.

       "busy" is dropped along with the rest, which is safe because
       nothing here owns those buffers any more:
       ngx_http_write_filter copies the chain links it is given, so
       what is downstream survives this. The list exists only to know
       which buffers may be refilled, and after close none may. */
    ctx->out      = NULL;
    ctx->last_out = &ctx->out;
    ctx->busy     = NULL;
    ctx->free     = NULL;
    ctx->buffers  = 0;
    ctx->out_size = 0;
}

static void *
ngx_http_zstd_create_conf(ngx_conf_t *cf)
{
    ngx_http_zstd_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_zstd_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /* ngx_pcalloc fills result with zeros ->
         conf->types = { NULL };
         conf->types_keys = NULL; */

    conf->enable      = NGX_CONF_UNSET;
    conf->level       = NGX_CONF_UNSET;
    conf->window_bits = NGX_CONF_UNSET_SIZE;
    conf->buffers     = NGX_CONF_UNSET;
    conf->min_length  = NGX_CONF_UNSET;

    return conf;
}

static char *
ngx_http_zstd_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_zstd_conf_t *prev;
    ngx_http_zstd_conf_t *conf;

    prev = parent;
    conf = child;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);

    /* zstd's own documented default (ZSTD_CLEVEL_DEFAULT). Measured
       against script/corpus with a --with-debug build (see
       script/bench_corpus.py): level 3 compresses the corpus to
       241,626 bytes for 0.65 ms of encoder time per request, against
       220,262 bytes / 1.87 ms at level 6 - 8.8% smaller for roughly
       3x the CPU. Past level 9 the curve flattens hard: 214,466 bytes
       at 12 costs 6.1 ms, and 205,167 at 19 costs 33.5 ms for another
       4% - a bad trade under the same "CPU over ratio" reasoning
       Brotli's quality-4 default used. Level 3 also is not the
       cheapest available: level 1 saves little time (256,640 bytes /
       0.58 ms) while giving up 6% ratio, so 3 is where the elbow
       actually sits, not just zstd's own default landing there by
       coincidence. */
    ngx_conf_merge_value(conf->level, prev->level, 3);

    /* 16 bits (64 KB), matching the Brotli filter's compiled-in
       default and for the same reason: per-request memory outranks
       compression ratio - see PORTING.md section 1. Confirmed rather
       than assumed, since zstd's memory climbs with the window where
       Brotli's own curve was flat. Against script/corpus at level 3,
       compressed bytes versus peak live encoder bytes: 265,093 /
       0.32 MB at 16 KB, 241,626 / 1.20 MB here, 234,205 / 1.62 MB at
       128 KB, 230,211 / 1.74 MB at 256 KB, 230,210 / 2.49 MB at 1 MB.

       So 128 KB would buy 3.1% in ratio for +0.42 MB per request -
       1.2 GB against 1.6 GB at a thousand concurrent requests, which
       section 1 decides against. It is the one alternative worth
       knowing about, being the largest window that is still free in
       block terms: a block is MIN(window, ZSTD_BLOCKSIZE_MAX), so
       past 128 KB the window buffer grows alone. The apparent
       flattening past 256 KB is an artifact of corpus files being
       110-270 KB, not a property of zstd. */
    ngx_conf_merge_size_value(
        conf->window_bits, prev->window_bits, 16);

    /* Four rather than nginx's gzip default of 32. The buffers exist
       so that a stalled write does not stop the encoder, and past a
       handful they stop buying that: zstd emits at most one block per
       ZSTD_compressStream2 call, so at the 64 KB window default four
       16 KB buffers already cover a whole block with room to spare.
       They also cost - 4 x NGX_HTTP_ZSTD_OUT_SIZE, held for the life
       of the response, against a per-request encoder that section 1
       worked to keep near 1 MB - and gzip's 32 x 4K would be 128 KB
       per response for a case this module does not have. */
    ngx_conf_merge_value(conf->buffers, prev->buffers, 4);

    /* zstd's per-frame overhead is a handful of bytes against
       Brotli's roughly 560 KB encoder-instance cost, so the crossover
       point where compression starts winning was re-measured rather
       than assumed to be the same number: realistic small JSON-shaped
       text starts coming out smaller once compressed (at level 3)
       somewhere around 90-106 bytes. 256 clears that with the same
       margin Brotli's own default left, once the "Content-Encoding"
       header's own cost is counted too. */
    ngx_conf_merge_value(conf->min_length, prev->min_length, 256);

    if (ngx_http_merge_types(cf, &conf->types_keys, &conf->types,
            &prev->types_keys, &prev->types,
            ngx_http_html_default_types) != NGX_CONF_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

/* Prepend to filter chain. */
static ngx_int_t
ngx_http_zstd_filter_init(ngx_conf_t *cf)
{
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter  = ngx_http_zstd_header_filter;

    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter  = ngx_http_zstd_body_filter;

    return NGX_OK;
}

/* Translate "window size" to windowLog (log2), and check bounds. */
static char *
ngx_http_zstd_parse_window(ngx_conf_t *cf, void *post, void *data)
{
    size_t *parameter;
    size_t  bits;
    size_t  wsize;

    parameter = data;

    for (bits = ZSTD_WINDOWLOG_MIN;
        bits <= NGX_HTTP_ZSTD_MAX_WINDOW_BITS; bits++) {
        /* size_t rather than "1u", which would evaluate the shift in
           32 bits. */
        wsize = (size_t) 1 << bits;
        if (*parameter == wsize) {
            *parameter = bits;
            return NGX_CONF_OK;
        }
    }

    return "must be 1k, 2k, 4k, 8k, 16k, 32k, 64k, 128k, 256k, 512k, "
           "1m, 2m, 4m, 8m, 16m, 32m, 64m or 128m";
}
