/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) Google Inc.
 * Copyright (C) 2026 Juri Torhoff
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

/* Needed for ZSTD_createCCtx_advanced (the custom allocator) and the
   ZSTD_WINDOWLOG_* / ZSTD_WINDOWLOG_LIMIT_DEFAULT bounds. The symbols
   this unlocks are already exported with default visibility in a
   normal (dynamically linked) libzstd - "static linking only" is a
   promise about API stability across releases, not a linker
   restriction - so this does not commit the module to actually
   linking libzstd statically. See PORTING.md. */
#define ZSTD_STATIC_LINKING_ONLY
#include <zstd.h>

#include "../common/ngx_http_zstd_headers.h"


/* Zstandard and GZip never stack, i.e. when one of them sets
   "Content-Encoding" the other becomes a pass-through filter.
   Consequently, it is almost legal to reuse this "buffered" bit. */
#define NGX_HTTP_ZSTD_BUFFERED NGX_HTTP_GZIP_BUFFERED

/* How much input may be held back while waiting to learn the
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
#define NGX_HTTP_ZSTD_DEFER_INPUT (64 * 1024)

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
   per ZSTD_compressStream2 call, so the number of trips through
   send_output has a floor the buffer cannot lower: measured on
   script/corpus prose.txt (five 64 KB blocks) the count falls 28 ->
   15 -> 8 as this goes 4K -> 8K -> 16K, then sits at 5 for 32K, 64K
   and 128.5K alike. Past 32K it also costs CPU - 64.3K measured ~10%
   slower per request than 16K across repeated release-build runs,
   most likely cache residency against the encoder's own tables.
   16K is therefore a choice, not a placeholder. Re-measure if
   zstd_window's default moves, since the block size follows the
   window and the plateau follows the block. */
#define NGX_HTTP_ZSTD_OUT_SIZE (16 * 1024)

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
} ngx_http_zstd_conf_t;

/* What, if anything, the single output buffer is currently holding.
   The three states are exclusive: output is taken from the encoder
   only while the buffer is idle, and committing it moves it straight
   from ready to busy. */
typedef enum {
    /* Nothing held; the encoder may be asked for more. */
    NGX_HTTP_ZSTD_OUTPUT_IDLE = 0,
    /* Filled from the encoder, not yet handed to the next filter. */
    NGX_HTTP_ZSTD_OUTPUT_READY,
    /* Handed on, and not yet fully consumed. */
    NGX_HTTP_ZSTD_OUTPUT_BUSY
} ngx_http_zstd_output_e;

/* What one turn of the body filter's loop decided to do next. The
   loop owns the returns; a step only says which one. */
typedef enum {
    /* Made progress; go round again. */
    NGX_HTTP_ZSTD_STEP_CONTINUE = 0,
    /* Nothing more to do this call; return NGX_OK. */
    NGX_HTTP_ZSTD_STEP_DONE,
    /* Blocked on the next filter; return NGX_AGAIN. */
    NGX_HTTP_ZSTD_STEP_AGAIN,
    /* Unrecoverable; the loop closes the stream and returns
       NGX_ERROR. */
    NGX_HTTP_ZSTD_STEP_FAILED
} ngx_http_zstd_step_e;

/* What the body filter should do once ngx_http_zstd_filter_prepare
   has settled the decisions that come before the encoder.

   The caller treats DEFER and REJECT alike - both end the call and
   return "rc" - so they are separate for the reader rather than for
   the control flow. */
typedef enum {
    /* Accepted for encoding: carry on into the encoder loop. */
    NGX_HTTP_ZSTD_PRE_ACCEPT = 0,
    /* Not yet: too little of the body has arrived to answer the
       question zstd_min_length asks, or its size is still unknown
       and worth waiting a moment to learn before the encoder window
       is fixed. The input stays in ctx->in and a later call decides,
       so this may still end in compression. "rc" is NGX_OK. */
    NGX_HTTP_ZSTD_PRE_DEFER,
    /* Settled, and not encoded here. "rc" holds what the body filter
       should return. */
    NGX_HTTP_ZSTD_PRE_REJECT
} ngx_http_zstd_prepare_e;

/* Instance context. */
typedef struct {
    /* zstd encoder instance. */
    ZSTD_CCtx *cctx;

    /* Payload length; -1, if unknown. */
    off_t content_length;

    /* Input buffer chain. */
    ngx_chain_t *in;

    /* Output chain: a single link wrapping out_buf. */
    ngx_chain_t *out_chain;
    /* Output buffer. Unlike the Brotli filter this points at memory
       *we* allocated (out_start/out_size below), not at anything the
       encoder owns - see PORTING.md. */
    ngx_buf_t *out_buf;
    u_char    *out_start;
    size_t     out_size;

    /* 1 if the response headers are still ours to send. Set when the
       response length is unknown, so that zstd_min_length can be
       applied once enough of the body has been seen to judge it. */
    unsigned headers_postponed : 1;
    /* 1 if this response has been accepted for compression. */
    unsigned accepted_for_compression : 1;

    /* 1 if the encoder, output chain and buffer are allocated. */
    unsigned initialized : 1;
    /* 1 if compression is finished / failed. */
    unsigned closed : 1;

    /* 1 once a buffer marked last_buf has been handed to the
       encoder. Never cleared: input cannot resume. */
    unsigned end_of_input : 1;
    /* 1 once ZSTD_compressStream2(..., ZSTD_e_end) has reported
       "fully flushed" (a return of 0). */
    unsigned frame_closed : 1;
    /* 1 if input has been handed to the encoder under ZSTD_e_continue
       that it may still be holding, unflushed. zstd gives no query
       for "is anything buffered" the way Brotli's
       BrotliEncoderHasMoreOutput did, so this tracks it: set when a
       continue call consumes bytes, cleared once a flush fully
       drains (see draining_flush). */
    unsigned unflushed_input : 1;
    /* 1 while a ZSTD_e_flush is still being drained, i.e. the last
       call returned a nonzero "remaining" and has to be repeated with
       empty input until it returns 0. Doing this unconditionally,
       rather than only when the caller wants output, matters: a
       flush the caller did not ask for (an input buffer arriving
       with the "flush" flag set) still has to be drained to
       completion once started. */
    unsigned draining_flush : 1;
    /* 1 if this call of the body filter arrived with no new data,
       i.e. nginx is asking for progress on what it has already
       handed over rather than adding to it. */
    unsigned caller_wants_output : 1;

    /* State of out_buf. ngx_pcalloc starts it at IDLE. */
    ngx_http_zstd_output_e output;

    ngx_http_request_t *request;
} ngx_http_zstd_ctx_t;

/* Forward declarations. What each of these does is documented at its
   definition, not here, so the explanation sits with the code. */

static void ngx_http_zstd_filter_close(ngx_http_zstd_ctx_t *ctx);

static void *ngx_http_zstd_filter_alloc(void *opaque, size_t size);
static void ngx_http_zstd_filter_free(void *opaque, void *address);
static void ngx_http_zstd_filter_cleanup(void *data);

static ngx_int_t ngx_http_zstd_filter_send_headers(
    ngx_http_zstd_ctx_t *ctx);

static void *ngx_http_zstd_create_conf(ngx_conf_t *cf);
static char *ngx_http_zstd_merge_conf(ngx_conf_t *cf, void *parent,
    void *child);
static ngx_int_t ngx_http_zstd_filter_init(ngx_conf_t *cf);

static char *ngx_http_zstd_parse_window(ngx_conf_t *cf, void *post,
    void *data);

/* Configuration literals. */

/* 1 and 22 are zstd's own documented stable range (ZSTD_minCLevel()
   and ZSTD_maxCLevel() are runtime functions, not compile-time
   constants, so they cannot fill an ngx_conf_num_bounds_t literal the
   way Brotli's BROTLI_MIN/MAX_QUALITY macros could); negative levels
   are a real part of zstd's range but are not exposed through this
   directive. */
static ngx_conf_num_bounds_t ngx_http_zstd_comp_level_bounds = {
    ngx_conf_check_num_bounds, 1, 22};

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
    ngx_http_zstd_ctx_t  *ctx;
    ngx_http_zstd_conf_t *conf;

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

    ctx->request = r;
    ctx->content_length = r->headers_out.content_length_n;
    ngx_http_set_ctx(r, ctx, ngx_http_zstd_filter_module);

    r->main_filter_need_in_memory = 1;

    /* When the length is unknown there is nothing yet to compare
       against zstd_min_length, and committing the headers here would
       settle the question for good. Hold them instead. */
    if (ctx->content_length < 0) {
        ctx->headers_postponed = 1;
        return NGX_OK;
    }

    ctx->accepted_for_compression = 1;

    return ngx_http_zstd_filter_send_headers(ctx);
}

/* Commits headers that ngx_http_zstd_header_filter held back. If the
   response was accepted it is labelled and the encoder will run; if
   not it passes through untouched, leaving no "Content-Encoding" for
   the filters below to defer to, so gzip may still take it. */
static ngx_int_t
ngx_http_zstd_filter_send_headers(ngx_http_zstd_ctx_t *ctx)
{
    ngx_http_request_t *r = ctx->request;

    ctx->headers_postponed = 0;

    if (!ctx->accepted_for_compression) {
        /* Nothing has been allocated yet on this path - headers are
           only postponed while the encoder does not exist - so this
           closes an empty instance. */
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

    return ngx_http_next_header_filter(r);
}

/* Hands the committed output buffer to the next filter, and reports
   whether the encoder may be touched again. The encoder must not be
   while any of its output is still outstanding: out_buf is the one
   buffer this filter owns, and it cannot be refilled while the
   filters below still hold a reference to what is in it. */
static ngx_http_zstd_step_e
ngx_http_zstd_filter_send_output(ngx_http_zstd_ctx_t *ctx)
{
    ngx_int_t           rc;
    ngx_uint_t          resend;
    off_t               outstanding;
    ngx_chain_t        *to_send;
    ngx_http_request_t *r;

    r = ctx->request;

    /* READY: freshly filled, so hand the chain over. BUSY: handed
       over once already and not yet fully consumed, so offer nothing
       new and see whether the filters below have moved any of it. */
    resend = (ctx->output == NGX_HTTP_ZSTD_OUTPUT_BUSY);
    to_send = resend ? NULL : ctx->out_chain;
    outstanding = ngx_buf_size(ctx->out_buf);

    rc = ngx_http_next_body_filter(r, to_send);

    if (!resend) {
        ctx->output = NGX_HTTP_ZSTD_OUTPUT_BUSY;
    }

    if (ngx_buf_size(ctx->out_buf) == 0) {
        ctx->output = NGX_HTTP_ZSTD_OUTPUT_IDLE;
    }

    if (rc == NGX_OK) {
        /* A resend that moved nothing means the filters below are
           holding the buffer and will not take more of it now. */
        if (resend && ctx->output == NGX_HTTP_ZSTD_OUTPUT_BUSY &&
            ngx_buf_size(ctx->out_buf) == outstanding) {
            r->connection->buffered |= NGX_HTTP_ZSTD_BUFFERED;
            return NGX_HTTP_ZSTD_STEP_AGAIN;
        }

        return NGX_HTTP_ZSTD_STEP_CONTINUE;
    }

    if (rc == NGX_AGAIN) {
        if (ctx->output == NGX_HTTP_ZSTD_OUTPUT_BUSY) {
            if (ctx->in != NULL) {
                r->connection->buffered |= NGX_HTTP_ZSTD_BUFFERED;
            }
            return NGX_HTTP_ZSTD_STEP_AGAIN;
        }
        /* Inner filter gave up, but we can carry on. */
        return NGX_HTTP_ZSTD_STEP_CONTINUE;
    }

    return NGX_HTTP_ZSTD_STEP_FAILED;
}

/* Runs the encoder once and, if it produced anything, wraps it in
   out_buf. This is where the Brotli module's take_output and
   feed_encoder merge into one step: ZSTD_compressStream2 moves input
   and output in a single call, so there is no separate "does the
   encoder have output ready" phase to ask about first - see
   PORTING.md section 3. */
static ngx_http_zstd_step_e
ngx_http_zstd_filter_compress(ngx_http_zstd_ctx_t *ctx)
{
    ZSTD_inBuffer       in;
    ZSTD_outBuffer      out;
    ZSTD_EndDirective   mode;
    size_t              remaining;
    ngx_buf_t          *b;
    ngx_chain_t        *link;
    ngx_http_request_t *r;

    r = ctx->request;

    if (ctx->in == NULL) {
        if (ctx->frame_closed) {
            /* The final buffer - the one carrying last_buf - has
               already been handed to the next filter by the time
               this is reached: it is only reachable once ctx->output
               is back to IDLE, and send_output does not clear it
               until the filters below have taken everything. Freeing
               here rather than waiting for the request pool to be
               destroyed is what keeps the encoder's memory from
               outliving the response it belongs to - see PORTING.md
               section 1. */
            ngx_http_zstd_filter_close(ctx);
            return NGX_HTTP_ZSTD_STEP_DONE;
        }

        if (ctx->end_of_input) {
            mode = ZSTD_e_end;
        } else if (ctx->draining_flush || (ctx->caller_wants_output &&
                                              ctx->unflushed_input)) {
            /* Draining a flush already in progress takes priority
               over asking whether the caller wants output: once
               started, a flush has to reach "fully drained"
               (remaining == 0) regardless of who asked for it, or
               bytes it owed downstream stay stuck in the encoder's
               internal buffer indefinitely. */
            mode = ZSTD_e_flush;
        } else {
            /* Nothing to do; wait for more input. */
            return NGX_HTTP_ZSTD_STEP_DONE;
        }

        in.src = NULL;
        in.size = 0;
        in.pos = 0;
    } else {
        b = ctx->in->buf;

        /* An empty buffer carries nothing to compress, but one
           marked last or flush still has to reach the encoder to
           close the stream or the block. Anything else is dropped. */
        if (ngx_buf_size(b) == 0 && !b->last_buf && !b->flush) {
            link = ctx->in;
            ctx->in = link->next;
            ngx_free_chain(r->pool, link);
            return NGX_HTTP_ZSTD_STEP_CONTINUE;
        }

        if (b->last_buf) {
            mode = ZSTD_e_end;
        } else if (b->flush) {
            mode = ZSTD_e_flush;
        } else {
            mode = ZSTD_e_continue;
        }

        in.src = b->pos;
        in.size = ngx_buf_size(b);
        in.pos = 0;
    }

    out.dst = ctx->out_start;
    out.size = ctx->out_size;
    out.pos = 0;

    remaining = ZSTD_compressStream2(ctx->cctx, &out, &in, mode);
    if (ZSTD_isError(remaining)) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
            "ZSTD_compressStream2() failed: %s",
            ZSTD_getErrorName(remaining));
        return NGX_HTTP_ZSTD_STEP_FAILED;
    }

    r->connection->buffered |= NGX_HTTP_ZSTD_BUFFERED;

    /* Record progress in the chain itself. It cannot be kept in
       "in.pos" alone, which does not survive returning to nginx.
       "in.pos" is the right amount to advance by whatever the mode:
       a flush or an end call may also leave input partially
       unconsumed if the output buffer filled first - see the doc
       comment on ZSTD_compressStream2. */
    if (ctx->in != NULL) {
        b = ctx->in->buf;
        b->pos += in.pos;

        if (ngx_buf_size(b) == 0) {
            link = ctx->in;
            if (link->buf->last_buf) {
                ctx->end_of_input = 1;
            }
            ctx->in = link->next;
            ngx_free_chain(r->pool, link);
        }
    }

    if (mode == ZSTD_e_continue) {
        if (in.pos > 0) {
            ctx->unflushed_input = 1;
        }
    } else if (mode == ZSTD_e_flush) {
        ctx->draining_flush = (remaining != 0);
        if (!ctx->draining_flush) {
            ctx->unflushed_input = 0;
        }
    } else { /* ZSTD_e_end */
        if (remaining == 0) {
            ctx->frame_closed = 1;
        }
    }

    /* Nothing produced this round, and not finished: go round again
       rather than returning - a flush or an end still being drained
       has to be retried, and the caller is otherwise not owed a
       return yet. */
    if (out.pos == 0 && !ctx->frame_closed) {
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
    ctx->out_buf->start = ctx->out_start;
    ctx->out_buf->pos = ctx->out_start;
    ctx->out_buf->last = ctx->out_start + out.pos;
    ctx->out_buf->end = ctx->out_start + ctx->out_size;
    ctx->out_buf->temporary = (out.pos > 0);
    ctx->out_buf->sync = (out.pos == 0);
    ctx->out_buf->flush = (mode == ZSTD_e_flush);
    ctx->out_buf->last_buf = ctx->frame_closed;
    ctx->output = NGX_HTTP_ZSTD_OUTPUT_READY;

    if (ctx->frame_closed) {
        r->connection->buffered &= ~NGX_HTTP_ZSTD_BUFFERED;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
        "zstd out: %p, size:%uz", ctx->out_buf,
        ngx_buf_size(ctx->out_buf));

    return NGX_HTTP_ZSTD_STEP_CONTINUE;
}

/* Totals the unconsumed input, reporting whether the chain closes the
   response ("complete") and whether anything in it demands to be
   pushed out now ("urgent"). */
static size_t
ngx_http_zstd_filter_pending_input(ngx_chain_t *in,
    ngx_uint_t *complete, ngx_uint_t *urgent)
{
    size_t total = 0;

    *complete = 0;
    *urgent = 0;

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
    ngx_int_t             header_rc;
    ngx_http_request_t   *r;
    ngx_http_zstd_conf_t *conf;
    size_t                pending;
    ngx_uint_t            complete;
    ngx_uint_t            urgent;
    ngx_chain_t          *link;

    /* The steady state: the headers are away and the encoder exists,
       so there is nothing to settle. */
    if (!ctx->headers_postponed && ctx->initialized) {
        return NGX_HTTP_ZSTD_PRE_ACCEPT;
    }

    r = ctx->request;

    pending = ngx_http_zstd_filter_pending_input(ctx->in, &complete,
        &urgent);

    /* Headers held back because the length was unknown. Decide as
       soon as the body answers the only question zstd_min_length
       asks - is it at least that big. A flush marker means something
       downstream is waiting, so decide immediately and compress. */
    if (ctx->headers_postponed) {
        conf = ngx_http_get_module_loc_conf(r,
            ngx_http_zstd_filter_module);

        if (complete) {
            ctx->accepted_for_compression =
                (pending >= (size_t) conf->min_length);
        } else if (urgent || pending >= (size_t) conf->min_length) {
            ctx->accepted_for_compression = 1;
        } else {
            *rc = NGX_OK;
            return NGX_HTTP_ZSTD_PRE_DEFER;
        }

        header_rc = ngx_http_zstd_filter_send_headers(ctx);
        if (header_rc == NGX_ERROR) {
            ngx_http_zstd_filter_close(ctx);
            *rc = NGX_ERROR;
            return NGX_HTTP_ZSTD_PRE_REJECT;
        }
        if (header_rc > NGX_OK) {
            *rc = header_rc;
            return NGX_HTTP_ZSTD_PRE_REJECT;
        }

        if (!ctx->accepted_for_compression) {
            /* Pass the held input through untouched. */
            link = ctx->in;
            ctx->in = NULL;
            r->connection->buffered &= ~NGX_HTTP_ZSTD_BUFFERED;
            *rc = ngx_http_next_body_filter(r, link);
            return NGX_HTTP_ZSTD_PRE_REJECT;
        }
    }

    /* Choosing the encoder window costs memory that scales with the
       window, so when the response size is unknown it is worth
       waiting a moment to see if the whole thing turns up. */
    if (!ctx->initialized) {
        if (complete) {
            if (ctx->content_length < 0) {
                ctx->content_length = (off_t) pending;
            }
        } else if (!ctx->caller_wants_output && !urgent &&
                   ctx->content_length < 0 &&
                   pending < NGX_HTTP_ZSTD_DEFER_INPUT) {
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "zstd deferring encoder: pending:%uz", pending);

            *rc = NGX_OK;
            return NGX_HTTP_ZSTD_PRE_DEFER;
        }
    }

    return NGX_HTTP_ZSTD_PRE_ACCEPT;
}

/* Initializes encoder, output chain and buffer, if necessary. */
static ngx_int_t
ngx_http_zstd_filter_ensure_stream_inited(ngx_http_zstd_ctx_t *ctx)
{
    ngx_http_request_t   *r;
    ngx_http_zstd_conf_t *conf;
    ngx_pool_cleanup_t   *cln;
    ZSTD_customMem        zmem;
    size_t                wbits;
    size_t                zrc;

    if (ctx->initialized) {
        return NGX_OK;
    }

    r = ctx->request;
    conf =
        ngx_http_get_module_loc_conf(r, ngx_http_zstd_filter_module);

    /* Tune windowLog, if size is known. */
    if (ctx->content_length > 0) {
        wbits = ZSTD_WINDOWLOG_MIN;
        while (wbits < conf->window_bits &&
               ctx->content_length > (off_t) ((size_t) 1 << wbits)) {
            wbits++;
        }
    } else {
        wbits = conf->window_bits;
    }

    /* Encoder memory is not owned by the pool, so arrange for it to
       be released even if the request is aborted mid-stream.
       Registered before the encoder exists, so that a failure here
       cannot strand an allocated instance. */
    cln = ngx_pool_cleanup_add(r->pool, 0);
    if (cln == NULL) {
        return NGX_ERROR;
    }

    cln->handler = ngx_http_zstd_filter_cleanup;
    cln->data = ctx;

    zmem.customAlloc = ngx_http_zstd_filter_alloc;
    zmem.customFree = ngx_http_zstd_filter_free;
    zmem.opaque = r->pool;

    ctx->cctx = ZSTD_createCCtx_advanced(zmem);
    if (ctx->cctx == NULL) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
            "OOM / ZSTD_createCCtx_advanced");
        return NGX_ERROR;
    }

    zrc = ZSTD_CCtx_setParameter(ctx->cctx, ZSTD_c_compressionLevel,
        (int) conf->level);
    if (ZSTD_isError(zrc)) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
            "ZSTD_CCtx_setParameter(compressionLevel, %i) failed: %s",
            conf->level, ZSTD_getErrorName(zrc));
        return NGX_ERROR;
    }

    zrc = ZSTD_CCtx_setParameter(ctx->cctx, ZSTD_c_windowLog,
        (int) wbits);
    if (ZSTD_isError(zrc)) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
            "ZSTD_CCtx_setParameter(windowLog, %uz) failed: %s",
            wbits, ZSTD_getErrorName(zrc));
        return NGX_ERROR;
    }

    /* nginx already parallelises across worker processes, one per
       core, so a per-request thread pool would only oversubscribe -
       see PORTING.md. 0 is the library default, set explicitly so a
       vendored update cannot change it under us. */
    zrc = ZSTD_CCtx_setParameter(ctx->cctx, ZSTD_c_nbWorkers, 0);
    if (ZSTD_isError(zrc)) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
            "ZSTD_CCtx_setParameter(nbWorkers, 0) failed: %s",
            ZSTD_getErrorName(zrc));
        return NGX_ERROR;
    }

    /* Writes the size into the frame header when it is known, which
       helps the decoder allocate. Brotli has no equivalent - see
       PORTING.md. Safe to skip otherwise: ZSTD_CONTENTSIZE_UNKNOWN
       is the default for a fresh context.

       It does more than help the decoder, and is worth keeping for
       the other reason: told the source size, zstd sizes its own
       match-finder tables to the body rather than to the window, so
       this call is what keeps a high zstd_comp_level affordable.
       Measured on script/corpus, peak encoder memory plateaus at
       1.07 MB across levels 5, 6 and 9 with it, where the same
       levels on a stream of unknown length cost 1.20, 2.95 and
       10.45 MB. Dropping it would not merely cost the decoder a
       hint; it would remove the ceiling. */
    if (ctx->content_length >= 0) {
        zrc = ZSTD_CCtx_setPledgedSrcSize(ctx->cctx,
            (unsigned long long) ctx->content_length);
        if (ZSTD_isError(zrc)) {
            ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                "ZSTD_CCtx_setPledgedSrcSize(%O) failed: %s",
                ctx->content_length, ZSTD_getErrorName(zrc));
            return NGX_ERROR;
        }
    }

    ctx->out_size = NGX_HTTP_ZSTD_OUT_SIZE;
    ctx->out_start = ngx_palloc(r->pool, ctx->out_size);
    if (ctx->out_start == NULL) {
        return NGX_ERROR;
    }

    ctx->out_buf = ngx_calloc_buf(r->pool);
    if (ctx->out_buf == NULL) {
        return NGX_ERROR;
    }

    /* "temporary" is deliberately not set here: which of temporary
       and sync the buffer carries depends on whether a given round
       produced any bytes, so zstd_filter_compress sets both every
       time it commits output. ngx_calloc_buf has zeroed them, and
       nothing reads the buffer before that first commit. */
    ctx->out_chain = ngx_alloc_chain_link(r->pool);
    if (ctx->out_chain == NULL) {
        return NGX_ERROR;
    }

    ctx->out_chain->buf = ctx->out_buf;
    ctx->out_chain->next = NULL;

    /* Last, so that the flag means what it says. */
    ctx->initialized = 1;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
        "zstd encoder initialized: lvl:%i win:%uz", conf->level,
        (size_t) 1 << wbits);

    return NGX_OK;
}

/* Response body filtration (compression). */
static ngx_int_t
ngx_http_zstd_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    ngx_int_t            rc;
    ngx_http_zstd_ctx_t *ctx;
    ngx_http_zstd_step_e step;

    ctx = ngx_http_get_module_ctx(r, ngx_http_zstd_filter_module);

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
        "http zstd filter");

    if (ctx == NULL || ctx->closed || r->header_only) {
        return ngx_http_next_body_filter(r, in);
    }

    /* Recorded before "in" is folded into ctx->in: ctx->in running
       dry says the filter has nothing left to compress, this says
       the caller brought nothing new. */
    ctx->caller_wants_output = (in == NULL);

    if (in) {
        if (ngx_chain_add_copy(r->pool, &ctx->in, in) != NGX_OK) {
            ngx_http_zstd_filter_close(ctx);
            return NGX_ERROR;
        }
        r->connection->buffered |= NGX_HTTP_ZSTD_BUFFERED;
    }

    if (ngx_http_zstd_filter_prepare(ctx, &rc) !=
        NGX_HTTP_ZSTD_PRE_ACCEPT) {
        return rc;
    }

    if (ngx_http_zstd_filter_ensure_stream_inited(ctx) != NGX_OK) {
        ngx_http_zstd_filter_close(ctx);
        return NGX_ERROR;
    }

    /* Main loop, one phase per turn:
       - output still outstanding - push it down, and do not touch
       the encoder until it has all been consumed
       - otherwise - run the encoder once: it advances the input,
       fills out_buf if it produced anything, and reports whether the
       stream just closed

       Each phase returns what to do next rather than returning from
       here itself. */
    for (;;) {
        if (ctx->output != NGX_HTTP_ZSTD_OUTPUT_IDLE) {
            step = ngx_http_zstd_filter_send_output(ctx);
        } else {
            step = ngx_http_zstd_filter_compress(ctx);
        }

        switch (step) {
            case NGX_HTTP_ZSTD_STEP_CONTINUE:
                break;

            case NGX_HTTP_ZSTD_STEP_DONE:
                return NGX_OK;

            case NGX_HTTP_ZSTD_STEP_AGAIN:
                return NGX_AGAIN;

            default:
                ngx_http_zstd_filter_close(ctx);
                return NGX_ERROR;
        }
    }

    /* Unreachable: the switch above either returns or goes round
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
    ngx_pool_t *pool = opaque;
    void       *p;

    p = ngx_alloc(size, pool->log);

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, pool->log, 0,
        "zstd alloc: %p, size:%uz", p, size);

    return p;
}

static void
ngx_http_zstd_filter_free(void *opaque, void *address)
{
#if (NGX_DEBUG)
    ngx_pool_t *pool = opaque;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pool->log, 0, "zstd free: %p",
        address);
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

    /* Normally the encoder is already gone:
       ngx_http_zstd_filter_close resets the field. This is the abort
       path. */
    if (ctx->cctx != NULL) {
        ZSTD_freeCCtx(ctx->cctx);
        ctx->cctx = NULL;
    }
}

/* Marks instance as closed and performs cleanup. */
static void
ngx_http_zstd_filter_close(ngx_http_zstd_ctx_t *ctx)
{
    ctx->closed = 1;
    if (ctx->cctx) {
        ZSTD_freeCCtx(ctx->cctx);
        ctx->cctx = NULL;
    }

    if (ctx->out_chain) {
        ngx_free_chain(ctx->request->pool, ctx->out_chain);
        ctx->out_chain = NULL;
    }
    /* out_buf and out_start are pool memory: nothing to hand back
       explicitly. Dropping the pointer is the whole of the cleanup;
       they die with the pool. */
    ctx->out_buf = NULL;
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

    conf->enable = NGX_CONF_UNSET;

    conf->level = NGX_CONF_UNSET;
    conf->window_bits = NGX_CONF_UNSET_SIZE;
    conf->min_length = NGX_CONF_UNSET;

    return conf;
}

static char *
ngx_http_zstd_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_zstd_conf_t *prev = parent;
    ngx_http_zstd_conf_t *conf = child;
    char                 *rc;

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
    ngx_conf_merge_size_value(conf->window_bits, prev->window_bits,
        16);

    /* zstd's per-frame overhead is a handful of bytes against
       Brotli's roughly 560 KB encoder-instance cost, so the crossover
       point where compression starts winning was re-measured rather
       than assumed to be the same number: realistic small JSON-shaped
       text starts coming out smaller once compressed (at level 3)
       somewhere around 90-106 bytes. 256 clears that with the same
       margin Brotli's own default left, once the "Content-Encoding"
       header's own cost is counted too. */
    ngx_conf_merge_value(conf->min_length, prev->min_length, 256);

    rc = ngx_http_merge_types(cf, &conf->types_keys, &conf->types,
        &prev->types_keys, &prev->types, ngx_http_html_default_types);
    if (rc != NGX_CONF_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

/* Prepend to filter chain. */
static ngx_int_t
ngx_http_zstd_filter_init(ngx_conf_t *cf)
{
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_zstd_header_filter;

    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_zstd_body_filter;

    return NGX_OK;
}

/* Translate "window size" to windowLog (log2), and check bounds. */
static char *
ngx_http_zstd_parse_window(ngx_conf_t *cf, void *post, void *data)
{
    size_t *parameter = data;
    size_t  bits;
    size_t  wsize;

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
