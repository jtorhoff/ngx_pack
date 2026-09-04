/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) Google Inc.
 * Copyright (C) 2026 Juri Torhoff
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "../../common/ngx_http_pack_headers.h"
#include "ngx_http_pack_brotli_encoder.h"


static ngx_str_t const ENCODING = ngx_string("br");

/* Tells nginx to wait for output.
   Brotli and gzip never stack, i.e. when one of them sets
   "Content-Encoding" the other becomes a pass-through filter.
   This is why it's safe to re-use the constant here. */
#define MASK_BUFFERED NGX_HTTP_GZIP_BUFFERED

/* The most input held back while learning the response size. Matches
   Brotli's own input block size at the qualities that use one: the
   encoder would have buffered that much internally without emitting
   anything, so holding it here is not observable. Below quality 4
   Brotli's block is 16k, smaller than this, which costs nothing
   today because the holding almost always ends earlier - when the
   caller asks for progress with a NULL chain - but it is why this is
   a ceiling rather than a target. */
#define NGX_HTTP_PACK_BROTLI_HELD_INPUT (64 * 1024)

/* Compression level, spelled out rather than taken from
   BROTLI_MIN_QUALITY and BROTLI_MAX_QUALITY so that this file needs
   no Brotli header: what the encoder is made of is its own business.
   The encoder rejects anything the library will not take, so these
   only have to be no wider than Brotli's own range. */
#define NGX_HTTP_PACK_BROTLI_LEVEL_MIN 0
#define NGX_HTTP_PACK_BROTLI_LEVEL_MAX 11

/* 4 rather than the 6 this module used to default to. Measured
   against script/corpus with a release build: the corpus compresses
   to 228,062 bytes at quality 4 against 212,327 at 6 - 7.4% larger -
   for 10.0 ms of encoder time against 18.6, a little over half.
   Unlike the window below this buys nothing in memory: peak live
   encoder bytes are flat across the range, 1.94 MB at 4 against 1.93
   MB at 6. It trades ratio for CPU, and only that.

   Worth knowing before moving it again: 4 is not the knee of the
   curve. Quality 5 costs 0.8% in ratio against 6 and saves 20% of the
   time, where the further step down to 4 costs another 6.6% in ratio
   to save another 33%. Most of the CPU is available at 5 for almost
   none of the bytes; going to 4 is a deliberate choice to spend bytes
   on latency. */
#define NGX_HTTP_PACK_BROTLI_LEVEL_DEFAULT 4

/* Window, in bits. The ceiling is memory - encoder memory scales with
   the window, paid per request in flight - and stops at Brotli's own
   BROTLI_MAX_WINDOW_BITS; the larger windows behind
   BROTLI_PARAM_LARGE_WINDOW are deliberately not offered, since a
   decoder has to opt into them. */
#define NGX_HTTP_PACK_BROTLI_WINDOW_BITS_MIN 10
#define NGX_HTTP_PACK_BROTLI_WINDOW_BITS_MAX 24

/* 16 bits (64k) rather than the 19 (512k) this module used to default
   to. Brotli picks a much cheaper hasher at lg_win <= 16, so 64k is
   the largest window before encoder memory jumps: measured against
   script/corpus, a streamed response peaks near 0.99 MB here against
   4.0 MB at 512k. What that costs in ratio depends on the content,
   since it only bites where a match would have reached back beyond
   64 KB - +0.04% on CSS, +0.4% on JS, +1.0% on minified JS, +2.2% on
   prose, +2.7% on HTML, +1.6% over the corpus as a whole. Those are
   at quality 6, which was the default when they were taken; at the
   current default of 4 the same change costs +1.1% over the corpus
   and +2.4% at its worst, a lower quality having fewer long-range
   matches to give up. 32k and 16k cost the same memory as 64k while
   compressing worse, so 64k is the useful floor rather than the
   smallest possible value. */
#define NGX_HTTP_PACK_BROTLI_WINDOW_BITS_DEFAULT 16

/* 20 is the gzip module's default, but Brotli is a far worse deal on
   tiny responses: an encoder instance costs ~560 KB regardless of how
   little it is asked to compress, and measured against realistic JSON
   the compressed body only starts beating the original around 96
   bytes - closer to 128 once the "Content-Encoding" header is paid
   for. 256 clears that with room to spare. */
#define NGX_HTTP_PACK_BROTLI_MIN_LENGTH_DEFAULT 256

/* Bounds on pack_brotli_buffers' count, and its default. One buffer
   is enough to be correct - the filter simply stalls until the
   filters below have taken it - so the floor is 1. The ceiling is
   where more stop helping: at the default size, 8 buffers already
   cover the largest block Brotli hands back at any window. The same
   three numbers as pack_zstd_buffers, deliberately: the two encoders
   differ in what they cost per buffer, not in how many a response
   can usefully keep moving. */
#define NGX_HTTP_PACK_BROTLI_BUFFER_NUM_MIN 1
#define NGX_HTTP_PACK_BROTLI_BUFFER_NUM_MAX 8
#define NGX_HTTP_PACK_BROTLI_BUFFER_NUM_DEFAULT 4

/* Bounds on pack_brotli_buffers' size. The ceiling is where a larger
   buffer stops helping; the floor is where a round's fixed cost
   starts to outweigh the bytes it carries. Correctness needs neither:
   Brotli writes into whatever it is given and comes back for another
   buffer when it runs out. */
#define NGX_HTTP_PACK_BROTLI_BUFFER_SIZE_MIN (16 * 1024)
#define NGX_HTTP_PACK_BROTLI_BUFFER_SIZE_MAX (128 * 1024)

/* pack_brotli_buffers' default size. 16 KB rather than nearer the
   ceiling: a response that keeps up with its client only ever refills
   one buffer, so a larger size goes unused. Overridable at build time
   only, below what the directive itself permits, so a test can force
   rare partial-drain paths. */
#ifndef NGX_HTTP_PACK_BROTLI_BUFFER_SIZE_DEFAULT
#define NGX_HTTP_PACK_BROTLI_BUFFER_SIZE_DEFAULT (16 * 1024)
#endif


/* Module configuration. */
typedef struct {
    ngx_flag_t enable;

    /* Supported MIME types. */
    ngx_hash_t   types;
    ngx_array_t *types_keys;

    /* Minimal required length for compression (if known). */
    ssize_t min_length;

    /* Brotli encoder parameter: BROTLI_PARAM_QUALITY */
    ngx_int_t level;

    /* Brotli encoder parameter: (max) BROTLI_PARAM_LGWIN, in bits */
    size_t window_bits;

    /* How many output buffers one response may have in flight, and
       how big each of them is: the two parameters of
       pack_brotli_buffers, kept in the pair nginx parses them into.
     */
    ngx_bufs_t bufs;
} conf_t;


/* What the body filter should do once ngx_http_pack_brotli_prepare
   has settled the decisions that come before the encoder. Only OK
   carries on; the other three end the call and return "rc", which
   every one of them sets - kept apart so a future caller can tell a
   response handed on from one that failed. */
typedef enum {
    /* Carry on into the encoder loop. */
    NGX_HTTP_PACK_BROTLI_OK = 0,

    /* Not yet: pack_brotli_min_length can't be answered, or the size
       is still worth waiting on before the window is fixed. Input
       stays in ctx->in for a later call to decide; "rc" is NGX_OK. */
    NGX_HTTP_PACK_BROTLI_DEFER,

    /* Settled, uncompressed: too small to be worth it, so the held
       input already went to the filters below untouched. "rc" is what
       that call returned; no "Content-Encoding" of ours, so gzip may
       still take it. */
    NGX_HTTP_PACK_BROTLI_PASS,

    /* Settled, and failed: the encoder is closed and "rc" is
       NGX_ERROR, or a filter below replaced the response with a
       status of its own. */
    NGX_HTTP_PACK_BROTLI_ERROR
} prepare_e;


/* What the filter has settled about this response, in the order it
   settles them: accepted, headers away, finished. Held by value so
   ngx_pcalloc zeroes every flag before first read, and kept in one
   struct so they share a single bitfield run rather than a storage
   unit each. */
typedef struct {
    /* 1 if this response has been accepted for compression. Decided
       either in the header filter, when the length is known up front,
       or in ngx_http_pack_brotli_prepare once enough of the body has
       arrived to judge it; ngx_http_pack_brotli_send_headers reads it
       to know which kind of header to commit. */
    unsigned accepted_for_compression: 1;

    /* 1 once headers are committed; zero (ngx_pcalloc's default) lets
       the header filter hold them back with no Content-Length yet to
       compare against pack_brotli_min_length. */
    unsigned headers_sent: 1;

    /* 1 if this call arrived with no new data - nginx asking for
       progress on what it already holds. Set once on entry, read by
       prepare and by the encoder's own step. */
    unsigned caller_wants_output: 1;

    /* 1 if compression is finished / failed. */
    unsigned closed: 1;
} filter_state_t;


/* Instance context. Members follow the path a request takes through
   the module: the request, what the filter has settled, what the
   encoder owns, then what the header filter learned. */
typedef struct {
    /* The request, and the pool and log reached through it. */
    ngx_http_request_t *request;

    /* The state of the filter: what is decided, done, and pending. */
    filter_state_t state;

    /* The encoder, or NULL until one is built. Opaque: everything the
       filter needs of it goes through
       ngx_http_pack_brotli_encoder_*. */
    ngx_http_pack_brotli_encoder_t *encoder;

    /* Payload length; -1, if unknown. */
    off_t content_length;

    /* Input buffer chain. What nginx handed us and the encoder has
       not taken yet - the only chain here the encoder does not own.
     */
    ngx_chain_t *in;
} ctx_t;


static void *ngx_http_pack_brotli_create_conf(ngx_conf_t *cf);
static char *ngx_http_pack_brotli_merge_conf(
    ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t ngx_http_pack_brotli_init(ngx_conf_t *cf);
static char *ngx_http_pack_brotli_parse_window(
    ngx_conf_t *cf, void *post, void *data);
static char *ngx_http_pack_brotli_set_buffers(
    ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_str_t
ngx_http_pack_brotli_human_size(ngx_pool_t *pool, size_t bytes);


/* Configuration literals. */

static ngx_conf_num_bounds_t ngx_http_pack_brotli_level_bounds = {
    ngx_conf_check_num_bounds,
    NGX_HTTP_PACK_BROTLI_LEVEL_MIN,
    NGX_HTTP_PACK_BROTLI_LEVEL_MAX};

static ngx_conf_post_handler_pt ngx_http_pack_brotli_parse_window_p =
    ngx_http_pack_brotli_parse_window;

static ngx_command_t ngx_http_pack_brotli_commands[] = {
    {ngx_string("pack_brotli"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
         NGX_HTTP_LIF_CONF | NGX_CONF_FLAG,
     ngx_conf_set_flag_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(conf_t, enable),
     NULL},

    {ngx_string("pack_brotli_types"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
         NGX_CONF_1MORE,
     ngx_http_types_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(conf_t, types_keys),
     &ngx_http_html_default_types[0]},

    {ngx_string("pack_brotli_level"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
         NGX_CONF_TAKE1,
     ngx_conf_set_num_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(conf_t, level),
     &ngx_http_pack_brotli_level_bounds},

    {ngx_string("pack_brotli_window"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
         NGX_CONF_TAKE1,
     ngx_conf_set_size_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(conf_t, window_bits),
     &ngx_http_pack_brotli_parse_window_p},

    {ngx_string("pack_brotli_min_length"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
         NGX_CONF_TAKE1,
     ngx_conf_set_size_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(conf_t, min_length),
     NULL},

    {ngx_string("pack_brotli_buffers"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
         NGX_CONF_TAKE2,
     ngx_http_pack_brotli_set_buffers,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(conf_t, bufs),
     NULL},

    ngx_null_command};

/* Module context hooks. */
static ngx_http_module_t ngx_http_pack_brotli_module_ctx = {
    NULL,                      /* pre-configuration */
    ngx_http_pack_brotli_init, /* post-configuration */

    NULL,                      /* create main configuration */
    NULL,                      /* init main configuration */

    NULL,                      /* create server configuration */
    NULL,                      /* merge server configuration */

    ngx_http_pack_brotli_create_conf, /* create location conf */
    ngx_http_pack_brotli_merge_conf   /* merge location conf */
};

/* Module descriptor. */
ngx_module_t ngx_http_pack_brotli_module = {
    NGX_MODULE_V1,
    &ngx_http_pack_brotli_module_ctx, /* module context */
    ngx_http_pack_brotli_commands,    /* module directives */
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


/* Marks the instance closed and releases the encoder. The only thing
   that sets state.closed, so the flag cannot come to mean two
   things. */
static void
ngx_http_pack_brotli_close(ctx_t *const ctx)
{
    ctx->state.closed = 1;

    if (ctx->encoder != NULL) {
        ngx_http_pack_brotli_encoder_close(ctx->encoder);
        ctx->encoder = NULL;
    }
}


/* Commits headers that the header filter held back. If the response
   was accepted it is labelled and the encoder will run; if not it
   passes through untouched, leaving no "Content-Encoding" for the
   filters below to defer to, so gzip may still take it. The caller
   sets state.accepted_for_compression before calling, since it is the
   decision these headers announce. */
static ngx_int_t
ngx_http_pack_brotli_send_headers(ctx_t *const ctx)
{
    ngx_http_request_t *r = ctx->request;

    ctx->state.headers_sent = 1;

    if (!ctx->state.accepted_for_compression) {
        /* Nothing has been allocated yet on this path - headers are
           only held while the encoder does not exist - so this closes
           an empty instance. */
        ngx_http_pack_brotli_close(ctx);
        return ngx_http_next_header_filter(r);
    }

    /* Tell the filters below that the body is compressed. */
    if (ngx_http_pack_set_encoding(r, &ENCODING) != NGX_OK) {
        return NGX_ERROR;
    }

    ngx_http_clear_content_length(r);
    ngx_http_clear_accept_ranges(r);
    ngx_http_weak_etag(r);

    return ngx_http_next_header_filter(r);
}


/* Whether this response is one this module should touch at all.
   Everything here is settled from the headers alone, before any body
   has arrived. */
static ngx_int_t
ngx_http_pack_brotli_preflight(ngx_http_request_t *const r)
{
    conf_t *conf;

    conf = ngx_http_get_module_loc_conf(
        r, ngx_http_pack_brotli_module);

    if (!conf->enable) {
        return NGX_DECLINED;
    }

    if (r->header_only) {
        return NGX_DECLINED;
    }

    /* Bypass statuses that either carry no body, or carry one that
       must not be re-encoded. 1xx/204/304 have no body to compress,
       so all they would get is a "Content-Encoding" describing
       nothing - which a client is entitled to apply to the next body
       it associates with the response. A 206 body is a byte range,
       and the "Content-Range" beside it still describes the original
       entity, so compressing it corrupts the response.

       This is deliberately a deny list: an allow list also excludes
       perfectly compressible responses such as 201, 422 and 500. */
    if (r->headers_out.status < NGX_HTTP_OK ||
        r->headers_out.status == NGX_HTTP_NO_CONTENT ||
        r->headers_out.status == NGX_HTTP_PARTIAL_CONTENT ||
        r->headers_out.status == NGX_HTTP_NOT_MODIFIED) {
        return NGX_DECLINED;
    }

    /* Bypass already compressed responses. */
    if (r->headers_out.content_encoding &&
        r->headers_out.content_encoding->value.len) {
        return NGX_DECLINED;
    }

    /* If response size is known, do not compress tiny responses. */
    if (r->headers_out.content_length_n != -1 &&
        r->headers_out.content_length_n < conf->min_length) {
        return NGX_DECLINED;
    }

    /* Compress only certain MIME-typed responses. */
    if (ngx_http_test_content_type(r, &conf->types) == NULL) {
        return NGX_DECLINED;
    }

    return NGX_OK;
}


/* Process headers and decide if the request is eligible for Brotli
   compression. */
static ngx_int_t
ngx_http_pack_brotli_header_filter(ngx_http_request_t *const r)
{
    ctx_t *ctx;

    if (ngx_http_pack_brotli_preflight(r) != NGX_OK) {
        return ngx_http_next_header_filter(r);
    }

    /* Before the Accept-Encoding test, not after: the response varies
       whether or not this particular client is served Brotli, and a
       cache that only heard about it from the clients that were is no
       use. */
    if (ngx_http_pack_set_vary(r) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_http_pack_claim_request(r, &ENCODING) != NGX_OK) {
        return ngx_http_next_header_filter(r);
    }

    ctx = ngx_pcalloc(r->pool, sizeof(ctx_t));
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ctx->request        = r;
    ctx->content_length = r->headers_out.content_length_n;
    ngx_http_set_ctx(r, ctx, ngx_http_pack_brotli_module);

    r->main_filter_need_in_memory = 1;

    /* When the length is unknown there is nothing yet to compare
       against pack_brotli_min_length, and committing the headers here
       would settle the question for good. Hold them instead: the body
       filter sends them as soon as it has seen enough of the body to
       decide, which takes only min_length bytes rather than the whole
       response. */
    if (ctx->content_length < 0) {
        return NGX_OK;
    }

    ctx->state.accepted_for_compression = 1;

    return ngx_http_pack_brotli_send_headers(ctx);
}


typedef struct {
    /* Unconsumed bytes across the whole chain. */
    size_t pending;

    /* 1 if the chain closes the response. */
    ngx_uint_t complete;

    /* 1 if anything in it demands to be pushed out now. */
    ngx_uint_t urgent;
} pending_input_result;

/* Totals the unconsumed input, reporting whether the chain closes the
   response and whether anything in it is waiting on a push. */
static pending_input_result
ngx_http_pack_brotli_pending_input(ngx_chain_t *in)
{
    pending_input_result result = {
        .pending  = 0,
        .complete = 0,
        .urgent   = 0,
    };

    for (; in != NULL; in = in->next) {
        result.pending += ngx_buf_size(in->buf);

        if (in->buf->last_buf) {
            result.complete = 1;
        }

        if (in->buf->flush) {
            result.urgent = 1;
        }
    }

    return result;
}


typedef struct {
    ctx_t *ctx;

    /* What the body filter should return, when the outcome is not
       OK. */
    ngx_int_t *rc;
} prepare_args;

/* Everything that has to be settled before the encoder can run:
   committing headers the header filter held back, and deciding
   whether to go on holding input while the response size is still
   unknown. Both questions only arise before the steady state, and
   both are answered from one walk of the input chain. */
static prepare_e
ngx_http_pack_brotli_prepare(prepare_args *const args)
{
    ctx_t               *ctx = args->ctx;
    ngx_http_request_t  *r;
    conf_t              *conf;
    ngx_int_t            header_rc;
    ngx_chain_t         *link;
    pending_input_result input;

    /* The steady state: the headers are away and the encoder exists,
       so there is nothing to settle and the input chain need not be
       walked at all. */
    if (ctx->state.headers_sent && ctx->encoder != NULL) {
        return NGX_HTTP_PACK_BROTLI_OK;
    }

    r = ctx->request;

    /* Both decisions below ask the chain the same three questions,
       and neither touches it, so they share one walk. */
    input = ngx_http_pack_brotli_pending_input(ctx->in);

    /* Headers held back because the length was unknown. Decide as
       soon as the body answers the only question min_length asks -
       is it at least that big - which needs min_length bytes, not the
       whole response, so this costs no meaningful latency. A flush
       marker means something downstream is waiting, so decide
       immediately and compress, since the total is still unknown. */
    if (!ctx->state.headers_sent) {
        conf = ngx_http_get_module_loc_conf(
            r, ngx_http_pack_brotli_module);

        if (input.complete) {
            /* Whole response in hand, so the comparison is exact. */
            ctx->state.accepted_for_compression =
                (input.pending >= (size_t) conf->min_length);
        } else if (
            input.urgent ||
            input.pending >= (size_t) conf->min_length) {
            ctx->state.accepted_for_compression = 1;
        } else {
            /* Too little to judge, and nothing waiting on it. */
            *args->rc = NGX_OK;
            return NGX_HTTP_PACK_BROTLI_DEFER;
        }

        header_rc = ngx_http_pack_brotli_send_headers(ctx);
        if (header_rc == NGX_ERROR) {
            ngx_http_pack_brotli_close(ctx);
            *args->rc = NGX_ERROR;
            return NGX_HTTP_PACK_BROTLI_ERROR;
        }

        /* A special response was substituted below us; the body we
           hold is no longer the one being sent. Must be checked
           before handing anything on. */
        if (header_rc > NGX_OK) {
            *args->rc = header_rc;
            return NGX_HTTP_PACK_BROTLI_ERROR;
        }

        if (!ctx->state.accepted_for_compression) {
            /* Pass the held input through untouched; state.closed
               makes every later call a straight hand-off. */
            link                     = ctx->in;
            ctx->in                  = NULL;
            r->connection->buffered &= ~MASK_BUFFERED;
            *args->rc = ngx_http_next_body_filter(r, link);
            return NGX_HTTP_PACK_BROTLI_PASS;
        }
    }

    /* Choosing the encoder window costs memory that scales with the
       window, so when the response size is unknown it is worth
       waiting a moment to see if the whole thing turns up. Brotli
       emits nothing for non-flush input below its block size anyway,
       so holding it here costs no latency. */
    if (ctx->encoder == NULL) {
        if (input.complete) {
            /* Whole response in hand: size the window from it
               exactly. */
            if (ctx->content_length < 0) {
                ctx->content_length = (off_t) input.pending;
            }
        } else if (
            !ctx->state.caller_wants_output && !input.urgent &&
            ctx->content_length < 0 &&
            input.pending < NGX_HTTP_PACK_BROTLI_HELD_INPUT) {
            /* Still might be a small response. Wait for the rest
               rather than commit to the configured window. Either the
               caller asking for output, or "urgent" meaning a filter
               downstream is waiting on these bytes, stops the holding
               and starts the encoding. */
            ngx_log_debug1(
                NGX_LOG_DEBUG_HTTP,
                r->connection->log,
                0,
                "brotli deferring encoder: pending: %uz",
                input.pending);

            *args->rc = NGX_OK;
            return NGX_HTTP_PACK_BROTLI_DEFER;
        }
    }

    return NGX_HTTP_PACK_BROTLI_OK;
}


/* Hands what the encoder produced to the filters below, then takes
   account of what came back. A NULL pending chain is not a no-op: it
   is what asks those filters to make progress on the buffer they
   already hold - the only way a busy buffer is ever returned. */
static ngx_int_t
ngx_http_pack_brotli_drain(ctx_t *const ctx)
{
    ngx_chain_t *pending;
    ngx_int_t    rc;

    pending = ngx_http_pack_brotli_encoder_pending(ctx->encoder);
    rc      = ngx_http_next_body_filter(ctx->request, pending);
    if (rc == NGX_ERROR) {
        return NGX_ERROR;
    }

    ngx_http_pack_brotli_encoder_drained(ctx->encoder);

    /* What nginx has to be told to come back for. Buffers the filters
       below still hold count, and so does uncompressed input: drop
       the bit while either is outstanding, or a stalled last write
       can be finalized as complete and truncate the tail. */
    if (ngx_http_pack_brotli_encoder_busy(ctx->encoder) ||
        ctx->in != NULL) {
        ctx->request->connection->buffered |= MASK_BUFFERED;
    } else {
        ctx->request->connection->buffered &= ~MASK_BUFFERED;
    }

    return NGX_OK;
}


/* The encoder has nothing left to do for this response. Freeing here
   rather than waiting for the request pool to be destroyed is what
   keeps its memory from outliving the response - but only once the
   last buffer has been taken, since a buffer still outstanding means
   the response is not finished whatever the encoder says. */
static ngx_int_t
ngx_http_pack_brotli_finish(ctx_t *const ctx)
{
    ngx_uint_t busy;
    ngx_uint_t stream_closed;

    /* Read before the close below, which drops the chain this answers
       about: asking again afterwards would be answering about a torn
       down encoder. */
    busy          = ngx_http_pack_brotli_encoder_busy(ctx->encoder);
    stream_closed = ngx_http_pack_brotli_encoder_stream_closed(
        ctx->encoder);

    if (!busy && stream_closed) {
        ngx_http_pack_brotli_close(ctx);
    }

    if (busy) {
        return NGX_AGAIN;
    }

    return NGX_OK;
}


/* Builds the encoder on first use, translating the directives into
   what ngx_http_pack_brotli_encoder_create wants. Nothing here
   reaches into the encoder: what it is made of is its own business,
   and this is the only place the two vocabularies meet. */
static ngx_int_t
ngx_http_pack_brotli_ensure_encoder(ctx_t *const ctx)
{
    conf_t *conf;

    if (ctx->encoder != NULL) {
        return NGX_OK;
    }

    conf = ngx_http_get_module_loc_conf(
        ctx->request, ngx_http_pack_brotli_module);

    ctx->encoder = ngx_http_pack_brotli_encoder_create(
        ctx->request,
        &(ngx_http_pack_brotli_encoder_conf_t) {
            .quality        = conf->level,
            .window_bits    = conf->window_bits,
            .nbuffers       = conf->bufs.num,
            .buffer_size    = conf->bufs.size,
            .content_length = ctx->content_length,
        });

    if (ctx->encoder == NULL) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


/* Everything the body filter does once the encoder exists. Each turn
   runs the encoder to a standstill, then pushes down whatever it
   produced. */
static ngx_int_t
ngx_http_pack_brotli_pump(ctx_t *const ctx)
{
    ngx_http_pack_brotli_step_e step;
    ngx_uint_t                  stream_closed;
    ngx_chain_t                *pending;
    ngx_uint_t                  busy;

    for (;;) {
        do {
            step = ngx_http_pack_brotli_encoder_step(
                ctx->encoder,
                &ctx->in,
                ctx->state.caller_wants_output);
        } while (step == NGX_HTTP_PACK_BROTLI_STEP_CONTINUE);

        if (step == NGX_HTTP_PACK_BROTLI_STEP_FAILED) {
            ngx_http_pack_brotli_close(ctx);
            return NGX_ERROR;
        }

        stream_closed = ngx_http_pack_brotli_encoder_stream_closed(
            ctx->encoder);
        pending = ngx_http_pack_brotli_encoder_pending(ctx->encoder);
        busy    = ngx_http_pack_brotli_encoder_busy(ctx->encoder);

        /* Nothing new to send and nothing outstanding: the encoder
           waits for input, not the filters below. A closed stream is
           excluded on purpose - this is the one path past finish(),
           which releases the encoder once the last buffer is taken,
           or it would strand until the pool is destroyed. */
        if (!stream_closed && pending == NULL && !busy) {
            return NGX_OK;
        }

        if (ngx_http_pack_brotli_drain(ctx) != NGX_OK) {
            ngx_http_pack_brotli_close(ctx);
            return NGX_ERROR;
        }

        if (step == NGX_HTTP_PACK_BROTLI_STEP_DONE) {
            return ngx_http_pack_brotli_finish(ctx);
        }

        /* Stopped for want of the buffer. If the send handed it back,
           go round; if not, the filters below are full and there is
           nothing more this call can do. */
        if (!ngx_http_pack_brotli_encoder_has_free(ctx->encoder)) {
            return NGX_AGAIN;
        }
    }

    /* Unreachable: the loop above either returns or goes round
       again. */
}


/* Response body filtration (compression). */
static ngx_int_t
ngx_http_pack_brotli_body_filter(
    ngx_http_request_t *const r, ngx_chain_t *const in)
{
    ctx_t    *ctx;
    ngx_int_t rc;

    ctx = ngx_http_get_module_ctx(r, ngx_http_pack_brotli_module);

    ngx_log_debug0(
        NGX_LOG_DEBUG_HTTP,
        r->connection->log,
        0,
        "http brotli filter");

    if (ctx == NULL || ctx->state.closed || r->header_only) {
        return ngx_http_next_body_filter(r, in);
    }

    /* Recorded before "in" is folded into ctx->in, which is what
       makes the two distinguishable further down: ctx->in running dry
       says the filter has nothing left to compress, this says the
       caller brought nothing new. */
    ctx->state.caller_wants_output = (in == NULL);

    if (in != NULL) {
        if (ngx_chain_add_copy(r->pool, &ctx->in, in) != NGX_OK) {
            ngx_http_pack_brotli_close(ctx);
            return NGX_ERROR;
        }
        r->connection->buffered |= MASK_BUFFERED;
    }

    if (ngx_http_pack_brotli_prepare(&(prepare_args) {
            .ctx = ctx,
            .rc  = &rc,
        }) != NGX_HTTP_PACK_BROTLI_OK) {
        return rc;
    }

    if (ngx_http_pack_brotli_ensure_encoder(ctx) != NGX_OK) {
        ngx_http_pack_brotli_close(ctx);
        return NGX_ERROR;
    }

    return ngx_http_pack_brotli_pump(ctx);
}


static void *
ngx_http_pack_brotli_create_conf(ngx_conf_t *const cf)
{
    conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /* ngx_pcalloc fills the result with zeros ->
         conf->types = { NULL };
         conf->types_keys = NULL; */

    conf->enable = NGX_CONF_UNSET;

    conf->level       = NGX_CONF_UNSET;
    conf->window_bits = NGX_CONF_UNSET_SIZE;
    conf->min_length  = NGX_CONF_UNSET;

    return conf;
}


static char *
ngx_http_pack_brotli_merge_conf(
    ngx_conf_t *const cf, void *const parent, void *const child)
{
    conf_t *prev = parent;
    conf_t *conf = child;
    char   *rc;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);

    /* See the constant block above for why each of these three is
       what it is; the reasoning is long enough to belong beside the
       value rather than here. */
    ngx_conf_merge_value(
        conf->level, prev->level, NGX_HTTP_PACK_BROTLI_LEVEL_DEFAULT);

    ngx_conf_merge_size_value(
        conf->window_bits,
        prev->window_bits,
        NGX_HTTP_PACK_BROTLI_WINDOW_BITS_DEFAULT);

    ngx_conf_merge_value(
        conf->min_length,
        prev->min_length,
        NGX_HTTP_PACK_BROTLI_MIN_LENGTH_DEFAULT);

    /* Both halves move together, so a count inherited from an
       unrelated size cannot arise. */
    ngx_conf_merge_bufs_value(
        conf->bufs,
        prev->bufs,
        NGX_HTTP_PACK_BROTLI_BUFFER_NUM_DEFAULT,
        NGX_HTTP_PACK_BROTLI_BUFFER_SIZE_DEFAULT);

    rc = ngx_http_merge_types(
        cf,
        &conf->types_keys,
        &conf->types,
        &prev->types_keys,
        &prev->types,
        ngx_http_html_default_types);
    if (rc != NGX_CONF_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


/* Prepend to the filter chain. */
static ngx_int_t
ngx_http_pack_brotli_init(ngx_conf_t *const cf)
{
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter  = ngx_http_pack_brotli_header_filter;

    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter  = ngx_http_pack_brotli_body_filter;

    return NGX_OK;
}


/* Translates a window size into window bits (log2), and checks the
   bounds. The directive takes a size because that is what an operator
   thinks in; the encoder wants the exponent. */
static char *
ngx_http_pack_brotli_parse_window(
    ngx_conf_t *const cf, void *const post, void *const data)
{
    size_t *parameter = data;
    size_t  bits;
    size_t  wsize;

    for (bits = NGX_HTTP_PACK_BROTLI_WINDOW_BITS_MIN;
         bits <= NGX_HTTP_PACK_BROTLI_WINDOW_BITS_MAX;
         bits++) {
        /* size_t rather than "1u", which would evaluate the shift in
           32 bits: the ceiling is Brotli's, and a vendored update
           raising it past 31 would make that undefined. */
        wsize = (size_t) 1 << bits;
        if (*parameter == wsize) {
            *parameter = bits;
            return NGX_CONF_OK;
        }
    }

    return "must be 1k, 2k, 4k, 8k, 16k, 32k, 64k, 128k, 256k, 512k, "
           "1m, 2m, 4m, 8m or 16m";
}


/* Parses pack_brotli_buffers and checks both parameters. The slot
   takes no post handler, so bounds are checked here rather than in
   the merge: the message then names the file and line the value came
   from, and the compiled-in default is never held to it. */
static char *
ngx_http_pack_brotli_set_buffers(
    ngx_conf_t *const cf, ngx_command_t *const cmd, void *const conf)
{
    char       *rv;
    ngx_bufs_t *bufs;
    ngx_str_t   min;
    ngx_str_t   max;

    rv = ngx_conf_set_bufs_slot(cf, cmd, conf);
    if (rv != NGX_CONF_OK) {
        return rv;
    }

    /* Where the slot just wrote, reached the same way it reached it:
       the offset is a byte count into the configuration struct, so
       the arithmetic has to happen on a char *. */
    bufs = (ngx_bufs_t *) ((char *) conf + cmd->offset);

    if (bufs->num < NGX_HTTP_PACK_BROTLI_BUFFER_NUM_MIN ||
        bufs->num > NGX_HTTP_PACK_BROTLI_BUFFER_NUM_MAX) {

        ngx_conf_log_error(
            NGX_LOG_EMERG,
            cf,
            0,
            "number of buffers must be between %i and %i",
            NGX_HTTP_PACK_BROTLI_BUFFER_NUM_MIN,
            NGX_HTTP_PACK_BROTLI_BUFFER_NUM_MAX);

        return NGX_CONF_ERROR;
    }

    if (bufs->size < NGX_HTTP_PACK_BROTLI_BUFFER_SIZE_MIN ||
        bufs->size > NGX_HTTP_PACK_BROTLI_BUFFER_SIZE_MAX) {

        min = ngx_http_pack_brotli_human_size(
            cf->pool, NGX_HTTP_PACK_BROTLI_BUFFER_SIZE_MIN);
        max = ngx_http_pack_brotli_human_size(
            cf->pool, NGX_HTTP_PACK_BROTLI_BUFFER_SIZE_MAX);

        ngx_conf_log_error(
            NGX_LOG_EMERG,
            cf,
            0,
            "buffer size must be between %V and %V",
            &min,
            &max);

        return NGX_CONF_ERROR;
    }

    /* Legal, and rarely what an operator wants: with nothing to run
       ahead into, the encoder waits for each buffer to be written
       before producing the next. */
    if (bufs->num == 1) {
        ngx_conf_log_error(
            NGX_LOG_WARN,
            cf,
            0,
            "multiple buffers are recommended so that the encoder "
            "does not have to wait for one buffer to be consumed by "
            "a slow client");
    }

    return NGX_CONF_OK;
}


/* The inverse of ngx_parse_size: 4096 back to "4k". Exact rather than
   rounded: a size this module ever prints is one of its own byte
   constants, so it either divides evenly by 1k/1m or it does not, and
   only those two are worth answering since that is all
   ngx_parse_size itself accepts back. */
static ngx_str_t
ngx_http_pack_brotli_human_size(
    ngx_pool_t *const pool, size_t const bytes)
{
    /* nginx's own bound on how many characters a size_t can need. */
    enum { max_str_len = NGX_SIZE_T_LEN + sizeof("k") - 1 };

    size_t  value;
    u_char  unit;
    u_char *data;
    size_t  end;

    data = ngx_pnalloc(pool, max_str_len);
    if (data == NULL) {
        return (ngx_str_t) ngx_null_string;
    }

    if (bytes != 0 && bytes % (1024 * 1024) == 0) {
        value = bytes / (1024 * 1024);
        unit  = 'm';
    } else if (bytes != 0 && bytes % 1024 == 0) {
        value = bytes / 1024;
        unit  = 'k';
    } else {
        value = bytes;
        unit  = 0;
    }

    end = (size_t) (ngx_sprintf(data, "%uz", value) - data);
    if (unit) {
        data[end]  = unit;
        end       += 1;
    }

    return (ngx_str_t) {
        .data = data,
        .len  = end,
    };
}
