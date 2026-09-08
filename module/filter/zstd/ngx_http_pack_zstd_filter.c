/*
   Copyright (C) Igor Sysoev
   Copyright (C) Nginx, Inc.
   Copyright (C) Google Inc.
   Copyright (C) 2026 Juri Torhoff
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "../../common/ngx_http_pack_headers.h"
#include "../../common/ngx_http_pack_helpers.h"
#include "ngx_http_pack_zstd_encoder.h"

/* Only when the Brotli filter is actually compiled in - the two are
   addable independently, and this module must still build and link
   on its own without it. Guards every use below too, not just this
   include. */
#if (NGX_HTTP_PACK_BROTLI_FILTER_MODULE)
#include "../brotli/ngx_http_pack_brotli_filter.h"
#endif


static ngx_str_t const ENCODING = ngx_string("zstd");

/* Tells nginx to wait for output.
   zstd and gzip never stack, i.e. when one of them sets
   "Content-Encoding" the other becomes a pass-through filter.
   This is why it's safe to re-use the constant here. */
#define MASK_BUFFERED NGX_HTTP_GZIP_BUFFERED

/* The most input held back while learning the response size. Arriving
   inside it earns an exact pledge, which sizes zstd's tables to the
   body rather than the window. Fixed rather than page-derived: at
   ngx_pagesize it would equal proxy_buffer_size, and the first
   delivery would fill it. */
#define NGX_HTTP_PACK_ZSTD_HELD_INPUT (32 * 1024)

/* Floor on pack_zstd_hint. Fixed rather than page-derived: a hint is
   a compression parameter, not an allocation, so a config naming one
   should not become invalid on a host with larger pages. It binds
   sizes only - "none" asks for no hint at all, which is a different
   thing from a small one. */
#define NGX_HTTP_PACK_ZSTD_HINT_MIN (16 * 1024)

/* No hint unless one is asked for. A hint only shrinks windowLog to
   fit, and at the window default there is nothing left to shrink, so
   all it still moves is zstd's choice of compression parameters -
   which a directive describing the body's size has no business
   steering. Worth setting where the window is configured wide. */
#define NGX_HTTP_PACK_ZSTD_HINT_DEFAULT 0

/* Applies to a response of unknown length too, once its end is in
   hand - the exception is a flush marker arriving first, which
   compresses whatever the size. See merge_conf for why 256. */
#define NGX_HTTP_PACK_ZSTD_MIN_LENGTH_DEFAULT 256

/* pack_zstd. "always" claims every eligible response outright,
   Accept-Encoding unread - not even an explicit "zstd;q=0" declines
   it, since an operator reaching for "always" wants zstd as the
   unconditional floor, not a stronger negotiation. */
enum {
    NGX_HTTP_PACK_ZSTD_OFF = 0,
    NGX_HTTP_PACK_ZSTD_ON,
    NGX_HTTP_PACK_ZSTD_ALWAYS,
};

/* pack_zstd_proxied. Matches gzip_proxied's default of "off": a
   request carrying "Via" reached us through another proxy, and
   compressing there is the operator's call, not ours. Only these two
   of gzip's settings - the rest key off response headers this filter
   would have to re-read, and "any" covers what they are reached for.
 */
enum {
    NGX_HTTP_PACK_ZSTD_PROXIED_OFF = 0,
    NGX_HTTP_PACK_ZSTD_PROXIED_ANY,
};

/* The ceiling is memory - encoder memory scales
   with the window, paid per request in flight. */
#define NGX_HTTP_PACK_ZSTD_WINDOW_BITS_MIN 14
#define NGX_HTTP_PACK_ZSTD_WINDOW_BITS_MAX 20

/* The floor, chosen for memory rather than ratio: the window is very
   nearly the only parameter deciding what an encoder costs per
   request in flight, and moving it barely shifts CPU. Compression is
   what pays - a smaller window finds fewer matches - so an operator
   who would rather spend the memory raises the directive. */
#define NGX_HTTP_PACK_ZSTD_WINDOW_BITS_DEFAULT 14

/* Compression level. */
#define NGX_HTTP_PACK_ZSTD_LEVEL_MIN 1
#define NGX_HTTP_PACK_ZSTD_LEVEL_MAX 6

/* The floor here too, and for the other axis: level is what trades
   CPU for size, where the window trades memory for it. Raising it
   buys ratio and costs time, at the same memory.
   script/bench/bench_corpus.py measures both halves. */
#define NGX_HTTP_PACK_ZSTD_LEVEL_DEFAULT 1

/* Bounds on pack_zstd_buffers' count. One buffer is enough to be
   correct - the filter simply stalls until the filters below have
   taken it - so the floor is 1. The ceiling is where more stop
   helping: at the default size, 8 buffers already cover the largest
   block zstd can hand back at any pack_zstd_window setting. */
#define NGX_HTTP_PACK_ZSTD_BUFFER_NUM_MIN 1
#define NGX_HTTP_PACK_ZSTD_BUFFER_NUM_MAX 8
#define NGX_HTTP_PACK_ZSTD_BUFFER_NUM_DEFAULT 4

/* Bounds on pack_zstd_buffers' size. The ceiling is where a larger
   buffer stops helping: a block is MIN(windowSize,
   ZSTD_BLOCKSIZE_MAX), so 128 KB covers the largest one zstd ever
   hands back. The floor is where a round's fixed cost starts to
   outweigh the bytes it carries; correctness needs none. */
#define NGX_HTTP_PACK_ZSTD_BUFFER_SIZE_MIN (16 * 1024)
#define NGX_HTTP_PACK_ZSTD_BUFFER_SIZE_MAX (128 * 1024)

/* pack_zstd_buffers' default size. 16 KB rather than nearer the
   ceiling: a response that keeps up with its client only ever
   refills one buffer, so a larger size goes unused. Overridable at
   build time only, below what the directive itself permits, so
   script/tests/stream/test-small-buffer.sh can force rare
   partial-drain paths. */
#ifndef NGX_HTTP_PACK_ZSTD_BUFFER_SIZE_DEFAULT
#define NGX_HTTP_PACK_ZSTD_BUFFER_SIZE_DEFAULT (16 * 1024)
#endif


typedef struct {
    /* pack_zstd: off, on, or always - one of the NGX_HTTP_PACK_ZSTD_*
       constants above. */
    ngx_uint_t enable;

    /* Supported MIME types. */
    ngx_hash_t   types;
    ngx_array_t *types_keys;

    /* Minimal required length for compression (if known). */
    ssize_t min_length;

    /* zstd encoder parameter: ZSTD_c_compressionLevel */
    ngx_int_t level;

    /* zstd encoder parameter: (max) ZSTD_c_windowLog, in bits */
    size_t window_bits;

    /* How many output buffers one response may have in flight, and
       how big each of them is: the two parameters of
       pack_zstd_buffers, kept in the pair nginx parses them into. */
    ngx_bufs_t bufs;

    /* pack_zstd_hint: what ZSTD_c_srcSizeHint is set to for a
       response NGX_HTTP_PACK_ZSTD_HELD_INPUT gave up waiting on - see
       the encoder's own ngx_http_pack_zstd_encoder_conf_t, which this
       is copied into. */
    size_t hint;

    /* pack_zstd_proxied: whether a request that arrived through
       another proxy may be compressed. */
    ngx_uint_t proxied;
} conf_t;

/* What the body filter should do once ngx_http_pack_zstd_prepare
   has settled the decisions that come before the encoder. Only OK
   carries on; the other three end the call and return "rc", which
   every one of them sets - kept apart so a future caller can tell a
   response handed on from one that failed. */
typedef enum {
    /* Carry on into the encoder loop. */
    NGX_HTTP_PACK_ZSTD_OK = 0,

    /* Not yet: pack_zstd_min_length can't be answered, or the size is
       still worth waiting on before the window is fixed. Input stays
       in ctx->in for a later call to decide; "rc" is NGX_OK. */
    NGX_HTTP_PACK_ZSTD_DEFER,

    /* Settled, uncompressed: too small to be worth it, so the held
       input already went to the filters below untouched. "rc" is
       what that call returned; no "Content-Encoding" of ours, so
       gzip may still take it. */
    NGX_HTTP_PACK_ZSTD_PASS,

    /* Settled, and failed: the encoder is closed and "rc" is
       NGX_ERROR. Reached when committing the held headers fails, or
       when a filter below replaced the response with a status - see
       ngx_http_pack_zstd_prepare, which explains why that has to
       become NGX_ERROR rather than travel as the status itself. */
    NGX_HTTP_PACK_ZSTD_ERROR
} prepare_e;


/* What the filter has settled about this response, in the order it
   settles them: accepted, headers away, finished. Two members take a
   test rather than a literal 1. Held by value so ngx_pcalloc zeroes
   every flag before first read, and kept in one struct so they share
   a single bitfield run rather than a storage unit each. */
typedef struct {
    /* 1 if this response has been accepted for compression. Decided
       either in the header filter, when the length is known up front,
       or in ngx_http_pack_zstd_prepare once enough of the body has
       arrived to judge it; ngx_http_pack_zstd_send_headers reads it
       to know which kind of header to commit. */
    unsigned accepted_for_compression: 1;

    /* 1 once headers are committed; zero (ngx_pcalloc's default)
       lets the header filter hold them back with no Content-Length
       yet to compare against pack_zstd_min_length. Left zero on the
       uncompressed and failing exits too, since both close the
       context, which is what stops a second commit. */
    unsigned headers_sent: 1;

    /* 1 if this call arrived with no new data - nginx asking for
       progress on what it already holds. Set once on entry, read by
       prepare and next_input. Stays in the struct rather than an
       args parameter because its second reader sits three frames
       down, past two functions that take a bare ctx today. */
    unsigned caller_wants_output: 1;

    /* 1 if compression is finished / failed. */
    unsigned closed: 1;
} filter_state_t;


/* Instance context. Members follow the path a request takes through
   the module: the request, what the filter has settled, what the
   encoder owns, then what the header filter learned. Sub-structs are
   members rather than pointers: they live exactly as long as the
   context and are never shared or reseated. */
typedef struct {
    /* The request, and the pool and log reached through it. */
    ngx_http_request_t *request;

    /* The state of the filter: what is decided, done, and pending. */
    filter_state_t state;

    /* The encoder, or NULL until one is built. Opaque: everything
       the filter needs of it goes through
       ngx_http_pack_zstd_encoder_*. */
    ngx_http_pack_zstd_encoder_t *encoder;

    /* Payload length; -1, if unknown. */
    off_t content_length;

    /* Input buffer chain. What nginx handed us and the encoder has
       not taken yet - the only chain here the encoder does not own.
     */
    ngx_chain_t *in;
} ctx_t;


static void *ngx_http_pack_zstd_create_conf(ngx_conf_t *cf);
static char *ngx_http_pack_zstd_merge_conf(
    ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t ngx_http_pack_zstd_init(ngx_conf_t *cf);

static char *ngx_http_pack_zstd_parse_window(
    ngx_conf_t *cf, void *post, void *data);
static char *
ngx_http_pack_zstd_check_hint(ngx_conf_t *cf, void *post, void *data);
static char *ngx_http_pack_zstd_set_hint(
    ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_pack_zstd_set_buffers(
    ngx_conf_t *cf, ngx_command_t *cmd, void *conf);


/* Narrower than zstd's own stable range (1 to 22, plus negatives,
   none exposed here). Past this ceiling, levels reach for zstd's
   slowest match-finding strategies for a ratio gain that shrinks as
   the level climbs; script/bench/bench_corpus.py is what would
   justify raising NGX_HTTP_PACK_ZSTD_LEVEL_MAX instead. */
static ngx_conf_num_bounds_t const ngx_http_pack_zstd_levels = {
    ngx_conf_check_num_bounds,
    NGX_HTTP_PACK_ZSTD_LEVEL_MIN,
    NGX_HTTP_PACK_ZSTD_LEVEL_MAX,
};

static ngx_conf_enum_t const ngx_http_pack_zstd_enable[] = {
    {
        .name  = ngx_string("off"),
        .value = NGX_HTTP_PACK_ZSTD_OFF,
    },
    {
        .name  = ngx_string("on"),
        .value = NGX_HTTP_PACK_ZSTD_ON,
    },
    {
        .name  = ngx_string("always"),
        .value = NGX_HTTP_PACK_ZSTD_ALWAYS,
    },
    {
        .name  = ngx_null_string,
        .value = 0,
    },
};

static ngx_conf_enum_t const ngx_http_pack_zstd_proxied[] = {
    {
        .name  = ngx_string("off"),
        .value = NGX_HTTP_PACK_ZSTD_PROXIED_OFF,
    },
    {
        .name  = ngx_string("any"),
        .value = NGX_HTTP_PACK_ZSTD_PROXIED_ANY,
    },
    {
        .name  = ngx_null_string,
        .value = 0,
    },
};

static ngx_conf_post_handler_pt const
    ngx_http_pack_zstd_parse_window_p =
        ngx_http_pack_zstd_parse_window;

static ngx_conf_post_handler_pt const
    ngx_http_pack_zstd_check_hint_p = ngx_http_pack_zstd_check_hint;

static ngx_command_t const ngx_http_pack_zstd_commands[] = {
    {
        ngx_string("pack_zstd"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
            NGX_HTTP_LIF_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_enum_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(conf_t, enable),
        (void *) &ngx_http_pack_zstd_enable,
    },
    {
        ngx_string("pack_zstd_types"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
            NGX_CONF_1MORE,
        ngx_http_types_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(conf_t, types_keys),
        &ngx_http_html_default_types[0],
    },
    {
        ngx_string("pack_zstd_level"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
            NGX_CONF_TAKE1,
        ngx_conf_set_num_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(conf_t, level),
        (void *) &ngx_http_pack_zstd_levels,
    },
    {
        ngx_string("pack_zstd_window"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
            NGX_CONF_TAKE1,
        ngx_conf_set_size_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(conf_t, window_bits),
        (void *) &ngx_http_pack_zstd_parse_window_p,
    },
    {
        ngx_string("pack_zstd_hint"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
            NGX_CONF_TAKE1,
        ngx_http_pack_zstd_set_hint,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(conf_t, hint),
        (void *) &ngx_http_pack_zstd_check_hint_p,
    },
    {
        ngx_string("pack_zstd_buffers"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
            NGX_CONF_TAKE2,
        ngx_http_pack_zstd_set_buffers,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(conf_t, bufs),
        NULL,
    },
    {
        ngx_string("pack_zstd_min_length"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
            NGX_CONF_TAKE1,
        ngx_conf_set_size_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(conf_t, min_length),
        NULL,
    },

    {
        ngx_string("pack_zstd_proxied"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
            NGX_CONF_TAKE1,
        ngx_conf_set_enum_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(conf_t, proxied),
        (void *) &ngx_http_pack_zstd_proxied,
    },
    ngx_null_command,
};

static ngx_http_module_t const ngx_http_pack_zstd_module_ctx = {
    NULL,                           /* pre-configuration */
    ngx_http_pack_zstd_init,        /* post-configuration */
    NULL,                           /* create main conf */
    NULL,                           /* init main conf */
    NULL,                           /* create server conf */
    NULL,                           /* merge server conf */
    ngx_http_pack_zstd_create_conf, /* create location conf */
    ngx_http_pack_zstd_merge_conf   /* merge location conf */
};

ngx_module_t ngx_http_pack_zstd_module = {
    NGX_MODULE_V1,
    (void *) &ngx_http_pack_zstd_module_ctx, /* module context */
    (void *) ngx_http_pack_zstd_commands,    /* module directives */
    NGX_HTTP_MODULE,                         /* module type */
    NULL,                                    /* init master */
    NULL,                                    /* init module */
    NULL,                                    /* init process */
    NULL,                                    /* init thread */
    NULL,                                    /* exit thread */
    NULL,                                    /* exit process */
    NULL,                                    /* exit master */
    NGX_MODULE_V1_PADDING,
};

/* Next filter in the filter chain. */
static ngx_http_output_header_filter_pt ngx_http_next_header_filter;
static ngx_http_output_body_filter_pt   ngx_http_next_body_filter;


/* Marks instance as closed and performs cleanup. */
static void
ngx_http_pack_zstd_close(ctx_t *const ctx)
{
    ctx->state.closed = 1;

    /* Closed means this instance owes the connection nothing, so the
       bit goes with it - left set it tells nginx output is still
       pending from a filter that has stopped producing any. */
    ctx->request->connection->buffered &= ~MASK_BUFFERED;

    /* Releasing libzstd and its buffer chains is the encoder's own
       business. The pointer is left as it is rather than cleared:
       nothing asks again, since a closed context never reaches
       ensure_encoder - the body filter returns on
       ctx->state.closed first. */
    if (ctx->encoder != NULL) {
        ngx_http_pack_zstd_encoder_close(ctx->encoder);
    }
}

typedef struct {
    ngx_int_t status;
} send_headers_result;

/* Commits headers that ngx_http_pack_zstd_header_filter held back,
   per ctx->accepted_for_compression. If accepted, it is labelled and
   the encoder will run; if not, it passes through untouched with no
   "Content-Encoding" of ours, so gzip may still take it. */
static send_headers_result
ngx_http_pack_zstd_send_headers(ctx_t *const ctx)
{
    ngx_http_request_t *r;
    ngx_int_t           rc;

    r = ctx->request;

    if (!ctx->state.accepted_for_compression) {
        /* Nothing has been allocated yet on this path, so this closes
           an empty instance - which also lets headers_sent stay
           zero, safely, since its only reader is prepare() and a
           closed context never reaches it. */
        ngx_http_pack_zstd_close(ctx);

        return (send_headers_result) {
            .status = ngx_http_next_header_filter(r),
        };
    }

    /* Tell the filters below that the body is compressed. */
    if (ngx_http_pack_set_encoding(r, &ENCODING) != NGX_OK) {
        return (send_headers_result) {
            .status = NGX_ERROR,
        };
    }

    ngx_http_clear_content_length(r);
    ngx_http_clear_accept_ranges(r);
    ngx_http_weak_etag(r);

    rc = ngx_http_next_header_filter(r);
    if (rc == NGX_ERROR || rc > NGX_OK) {
        return (send_headers_result) {
            .status = rc,
        };
    }

    ctx->state.headers_sent = 1;

    /* NGX_OK or NGX_AGAIN. */
    return (send_headers_result) {
        .status = rc,
    };
}

typedef struct {
    ngx_int_t status;
} preflight_result;

/* Everything that disqualifies a response on its own terms. None of
   the six checks allocates or records anything, so DECLINE alone
   answers for all. Accept-Encoding is deliberately not among them -
   checked later, since the response varies regardless of whether
   this client gets zstd. */
static preflight_result
ngx_http_pack_zstd_preflight(ngx_http_request_t *const r)
{
    conf_t *conf;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_pack_zstd_module);

    /* Filter only if enabled. */
    if (conf->enable == NGX_HTTP_PACK_ZSTD_OFF) {
        return (preflight_result) {
            .status = NGX_DECLINED,
        };
    }

    /* Bypass "header only" responses. */
    if (r->header_only) {
        return (preflight_result) {
            .status = NGX_DECLINED,
        };
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
        return (preflight_result) {
            .status = NGX_DECLINED,
        };
    }

    /* A "Via" header means the request reached us through another
       proxy. gzip_proxied's default declines those, and an operator
       moving from gzip should not silently start compressing what
       they were passing through. */
    if (r->headers_in.via != NULL &&
        conf->proxied == NGX_HTTP_PACK_ZSTD_PROXIED_OFF) {
        return (preflight_result) {
            .status = NGX_DECLINED,
        };
    }

    /* An origin that sent "Cache-Control: no-transform" has asked for
       its payload to arrive as it left. */
    if (ngx_http_pack_transform_allowed(r) != NGX_OK) {
        return (preflight_result) {
            .status = NGX_DECLINED,
        };
    }

    /* Bypass already compressed responses. */
    if (r->headers_out.content_encoding &&
        r->headers_out.content_encoding->value.len) {
        return (preflight_result) {
            .status = NGX_DECLINED,
        };
    }

    /* If response size is known, do not compress tiny responses. */
    if (r->headers_out.content_length_n != -1 &&
        r->headers_out.content_length_n < conf->min_length) {
        return (preflight_result) {
            .status = NGX_DECLINED,
        };
    }

    /* Compress only certain MIME-typed responses. */
    if (ngx_http_test_content_type(r, &conf->types) == NULL) {
        return (preflight_result) {
            .status = NGX_DECLINED,
        };
    }

    return (preflight_result) {
        .status = NGX_OK,
    };
}

/* Process headers and decide if request is eligible for zstd
   compression. */
static ngx_int_t
ngx_http_pack_zstd_header_filter(ngx_http_request_t *const r)
{
    conf_t   *conf;
    ctx_t    *ctx;
    ngx_int_t claimed;

    if (ngx_http_pack_zstd_preflight(r).status != NGX_OK) {
        return ngx_http_next_header_filter(r);
    }

    /* Before the Accept-Encoding test, not after: this filter's own
       decision no longer depends on Accept-Encoding under "always",
       but it cannot know whether Brotli or another codec at the same
       location still does - and a cache that heard about this
       response only from a Brotli client is no use to one that only
       speaks zstd. */
    if (ngx_http_pack_set_vary(r) != NGX_OK) {
        return NGX_ERROR;
    }

    conf = ngx_http_get_module_loc_conf(r, ngx_http_pack_zstd_module);

    /* Check if client supports zstd encoding, unless pack_zstd always
       says not to bother asking. */
    claimed = conf->enable == NGX_HTTP_PACK_ZSTD_ALWAYS
                  ? ngx_http_pack_claim_request_always(r)
                  : ngx_http_pack_claim_request(r, &ENCODING);
    if (claimed != NGX_OK) {
        return ngx_http_next_header_filter(r);
    }

    /* One allocation, two jobs: every flag starts at zero, per
       filter_state_t's comment, and the encoder pointer starts NULL,
       which is what "no encoder built yet" means. */
    ctx = ngx_pcalloc(r->pool, sizeof(ctx_t));
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ctx->request        = r;
    ctx->content_length = r->headers_out.content_length_n;
    ngx_http_set_ctx(r, ctx, ngx_http_pack_zstd_module);

    r->main_filter_need_in_memory = 1;

    /* When the length is unknown there is nothing yet to compare
       against pack_zstd_min_length, and committing the headers here
       would settle the question for good. Hold them instead. */
    if (ctx->content_length < 0) {
        return NGX_OK;
    }

    ctx->state.accepted_for_compression = 1;

    return ngx_http_pack_zstd_send_headers(ctx).status;
}


typedef struct {
    ngx_chain_t *in;
} pending_input_args;

typedef struct {
    /* Bytes of input not yet handed to the encoder. */
    size_t total;
    /* Whether the chain closes the response. */
    ngx_uint_t complete;
    /* Whether anything in it demands to be pushed out now. */
    ngx_uint_t urgent;
} pending_input_result;

/* Totals the unconsumed input, reporting whether the chain closes the
   response and whether anything in it demands to be pushed out now.
   Counts only what is in memory, which is what the encoder will take:
   ngx_buf_size would report a file range instead, and this total both
   answers pack_zstd_min_length and becomes the pledge. */
static pending_input_result
ngx_http_pack_zstd_pending_input(pending_input_args *const args)
{
    pending_input_result result;
    ngx_chain_t         *in;
    ngx_buf_t           *buf;

    result = (pending_input_result) {
        .total    = 0,
        .complete = 0,
        .urgent   = 0,
    };

    in = args->in;
    for (;;) {
        if (in == NULL) {
            break;
        }

        buf = in->buf;

        if (ngx_buf_in_memory(buf) && buf->last > buf->pos) {
            result.total += (size_t) (buf->last - buf->pos);
        }

        if (buf->last_buf) {
            result.complete = 1;
        }

        if (buf->flush) {
            result.urgent = 1;
        }

        in = in->next;
    }

    return result;
}

typedef struct {
    ctx_t     *ctx;
    size_t     pending;
    ngx_uint_t complete;
    ngx_uint_t urgent;
} commit_headers_args;

/* "verdict" is what the caller branches on; "rc" is what the body
   filter returns, and is set on every verdict but OK. */
typedef struct {
    prepare_e verdict;
    ngx_int_t rc;
} commit_headers_result;

/* Headers held back because the length was unknown. Decide as soon as
   the body answers the only question pack_zstd_min_length asks - is
   it at least that big. A flush marker means something downstream is
   waiting, so decide immediately and compress. */
static commit_headers_result
ngx_http_pack_zstd_commit_headers(commit_headers_args *const args)
{
    ctx_t       *ctx;
    conf_t      *conf;
    ngx_int_t    header_rc;
    ngx_chain_t *link;

    ctx  = args->ctx;
    conf = ngx_http_get_module_loc_conf(
        ctx->request, ngx_http_pack_zstd_module);

    if (args->complete) {
        ctx->state.accepted_for_compression =
            (args->pending >= (size_t) conf->min_length);
    } else if (
        args->urgent || args->pending >= (size_t) conf->min_length) {
        ctx->state.accepted_for_compression = 1;
    } else {
        return (commit_headers_result) {
            .verdict = NGX_HTTP_PACK_ZSTD_DEFER,
            .rc      = NGX_OK,
        };
    }

    header_rc = ngx_http_pack_zstd_send_headers(ctx).status;

    /* An error, or a filter below replacing the response with a
       status. Returns NGX_ERROR rather than the status, since a body
       filter's callers treat any status as success.
       See script/tests/header_status/test-header-status.sh. */
    if (header_rc == NGX_ERROR || header_rc > NGX_OK) {
        ngx_http_pack_zstd_close(ctx);

        return (commit_headers_result) {
            .verdict = NGX_HTTP_PACK_ZSTD_ERROR,
            .rc      = NGX_ERROR,
        };
    }

    if (ctx->state.accepted_for_compression) {
        return (commit_headers_result) {
            .verdict = NGX_HTTP_PACK_ZSTD_OK,
        };
    }

    /* Pass the held input through untouched. */
    link    = ctx->in;
    ctx->in = NULL;

    ctx->request->connection->buffered &= ~MASK_BUFFERED;

    return (commit_headers_result) {
        .verdict = NGX_HTTP_PACK_ZSTD_PASS,
        .rc      = ngx_http_next_body_filter(ctx->request, link),
    };
}

typedef struct {
    ctx_t *ctx;
} prepare_args;

/* As commit_headers_result: "verdict" decides, "rc" is what the body
   filter returns when the verdict is not OK. */
typedef struct {
    prepare_e verdict;
    ngx_int_t rc;
} prepare_result;

/* Everything that has to be settled before the encoder can run:
   committing headers the header filter held back, and deciding
   whether to go on holding input while the response size is still
   unknown. */
static prepare_result
ngx_http_pack_zstd_prepare(prepare_args *const args)
{
    ctx_t                *ctx;
    pending_input_result  pending;
    commit_headers_result committed;

    ctx = args->ctx;

    /* The steady state: the headers are away and the encoder exists,
       so there is nothing to settle. */
    if (ctx->state.headers_sent && ctx->encoder != NULL) {
        return (prepare_result) {
            .verdict = NGX_HTTP_PACK_ZSTD_OK,
        };
    }

    pending = ngx_http_pack_zstd_pending_input(
        &((pending_input_args) {
            .in = ctx->in,
        }));

    if (!ctx->state.headers_sent) {
        committed = ngx_http_pack_zstd_commit_headers(
            &(commit_headers_args) {
                .ctx      = ctx,
                .pending  = pending.total,
                .complete = pending.complete,
                .urgent   = pending.urgent,
            });

        if (committed.verdict != NGX_HTTP_PACK_ZSTD_OK) {
            return (prepare_result) {
                .verdict = committed.verdict,
                .rc      = committed.rc,
            };
        }
    }

    if (ctx->encoder != NULL) {
        return (prepare_result) {
            .verdict = NGX_HTTP_PACK_ZSTD_OK,
        };
    }

    /* The whole body is in hand, so its size is no longer a
       question. */
    if (pending.complete) {
        if (ctx->content_length < 0) {
            ctx->content_length = (off_t) pending.total;
        }

        return (prepare_result) {
            .verdict = NGX_HTTP_PACK_ZSTD_OK,
        };
    }

    /* Choosing the encoder window costs memory that scales with the
       window, so when the response size is unknown it is worth
       waiting a moment to see if the whole thing turns up. */
    if (!ctx->state.caller_wants_output && !pending.urgent &&
        ctx->content_length < 0 &&
        pending.total < NGX_HTTP_PACK_ZSTD_HELD_INPUT) {

        ngx_log_debug1(
            NGX_LOG_DEBUG_HTTP,
            ctx->request->connection->log,
            0,
            "zstd deferring encoder, pending: %uz",
            pending.total);

        return (prepare_result) {
            .verdict = NGX_HTTP_PACK_ZSTD_DEFER,
            .rc      = NGX_OK,
        };
    }

    return (prepare_result) {
        .verdict = NGX_HTTP_PACK_ZSTD_OK,
    };
}


typedef struct {
    ngx_int_t status;
} drain_result;

/* Hands what the encoder produced to the filters below, then takes
   account of what came back. A NULL pending chain is not a no-op:
   it is what asks those filters to make progress on buffers they
   already hold - the only way a busy buffer is ever returned. */
static drain_result
ngx_http_pack_zstd_drain(ctx_t *const ctx)
{
    ngx_chain_t *pending;
    ngx_int_t    rc;
    ngx_uint_t   busy;

    pending = ngx_http_pack_zstd_encoder_pending(ctx->encoder);
    rc      = ngx_http_next_body_filter(ctx->request, pending);
    if (rc == NGX_ERROR) {
        return (drain_result) {
            .status = NGX_ERROR,
        };
    }

    ngx_http_pack_zstd_encoder_drained(ctx->encoder);

    /* What nginx has to be told to come back for. Buffers the
       filters below still hold count, and so does uncompressed
       input: drop the bit while either is outstanding, or a
       stalled last write can be finalized as complete and
       truncate the tail. */
    busy = ngx_http_pack_zstd_encoder_busy(ctx->encoder);
    if (busy || ctx->in != NULL) {
        ctx->request->connection->buffered |= MASK_BUFFERED;
    } else {
        ctx->request->connection->buffered &= ~MASK_BUFFERED;
    }

    return (drain_result) {
        .status = NGX_OK,
    };
}

typedef struct {
    ngx_int_t status;
} finish_result;

/* The encoder has nothing left to do for this response. Freeing here
   rather than waiting for the request pool to be destroyed is what
   keeps its memory from outliving the response - but only once the
   last buffer has been taken, since buffers still outstanding mean
   the response is not finished whatever the encoder says. */
static finish_result
ngx_http_pack_zstd_finish(ctx_t *const ctx)
{
    ngx_uint_t busy;
    ngx_uint_t frame_closed;

    /* Read before the close below, which drops the chains this
       answers about: asking again afterwards would be answering
       about a torn-down encoder. */
    busy         = ngx_http_pack_zstd_encoder_busy(ctx->encoder);
    frame_closed = ngx_http_pack_zstd_encoder_frame_closed(
        ctx->encoder);

    if (!busy && frame_closed) {
        ngx_http_pack_zstd_close(ctx);
    }

    if (busy) {
        return (finish_result) {
            .status = NGX_AGAIN,
        };
    }

    return (finish_result) {
        .status = NGX_OK,
    };
}

typedef struct {
    ngx_int_t status;
} ensure_encoder_result;

/* Builds the encoder on first use, translating the directives into
   what ngx_http_pack_zstd_encoder_create wants. Nothing here reaches
   into the encoder: what it is made of is its own business, and this
   is the only place the two vocabularies meet. */
static ensure_encoder_result
ngx_http_pack_zstd_ensure_encoder(ctx_t *const ctx)
{
    conf_t *conf;

    if (ctx->encoder != NULL) {
        return (ensure_encoder_result) {
            .status = NGX_OK,
        };
    }

    conf = ngx_http_get_module_loc_conf(
        ctx->request, ngx_http_pack_zstd_module);

    ctx->encoder = ngx_http_pack_zstd_encoder_create(
        ctx->request,
        &(ngx_http_pack_zstd_encoder_conf_t) {
            .level          = conf->level,
            .window_bits    = conf->window_bits,
            .nbuffers       = conf->bufs.num,
            .buffer_size    = conf->bufs.size,
            .content_length = ctx->content_length,
            .src_size_hint  = conf->hint,
        });

    if (ctx->encoder == NULL) {
        return (ensure_encoder_result) {
            .status = NGX_ERROR,
        };
    }

    return (ensure_encoder_result) {
        .status = NGX_OK,
    };
}

typedef struct {
    ngx_int_t status;
} pump_result;

/* Everything the body filter does once the encoder exists. Each turn
   fills every output buffer the encoder can, then pushes the lot
   down in one chain - running it to a standstill first is the point
   of having more than one buffer, so a stalled write only costs the
   remaining buffers, not the next byte. */
static pump_result
ngx_http_pack_zstd_pump(ctx_t *const ctx)
{
    ngx_http_pack_zstd_step_e step;
    ngx_uint_t                frame_closed;
    ngx_chain_t              *pending;
    ngx_uint_t                busy;
    ngx_int_t                 drain;
    ngx_int_t                 finish;
    ngx_uint_t                has_free;

    for (;;) {
        do {
            step = ngx_http_pack_zstd_encoder_step(
                ctx->encoder,
                &ctx->in,
                ctx->state.caller_wants_output);
        } while (step == NGX_HTTP_PACK_ZSTD_STEP_CONTINUE);

        if (step == NGX_HTTP_PACK_ZSTD_STEP_FAILED) {
            ngx_http_pack_zstd_close(ctx);
            return (pump_result) {
                .status = NGX_ERROR,
            };
        }

        frame_closed = ngx_http_pack_zstd_encoder_frame_closed(
            ctx->encoder);
        pending = ngx_http_pack_zstd_encoder_pending(ctx->encoder);
        busy    = ngx_http_pack_zstd_encoder_busy(ctx->encoder);
        /* Nothing new to send and nothing outstanding: the
           encoder waits for input, not the filters below. A
           closed frame is excluded because this is the one path
           past finish(), which closes the encoder once the last
           buffer is taken. */
        if (!frame_closed && pending == NULL && !busy) {
            return (pump_result) {
                .status = NGX_OK,
            };
        }

        drain = ngx_http_pack_zstd_drain(ctx).status;
        if (drain != NGX_OK) {
            ngx_http_pack_zstd_close(ctx);
            return (pump_result) {
                .status = NGX_ERROR,
            };
        }

        if (step == NGX_HTTP_PACK_ZSTD_STEP_DONE) {
            finish = ngx_http_pack_zstd_finish(ctx).status;
            return (pump_result) {
                .status = finish,
            };
        }

        has_free = ngx_http_pack_zstd_encoder_has_free(ctx->encoder);
        /* Stopped for want of a buffer. If the send handed one back,
           go round; if not, the filters below are full and there is
           nothing more this call can do. */
        if (!has_free) {
            return (pump_result) {
                .status = NGX_AGAIN,
            };
        }
    }

    /* Unreachable: the loop above either returns
       or goes round again. */
}

/* Response body filtration (compression). */
static ngx_int_t
ngx_http_pack_zstd_body_filter(
    ngx_http_request_t *const r, ngx_chain_t *const in)
{
    ctx_t         *ctx;
    ngx_int_t      chain_status;
    prepare_result prepared;

    ctx = ngx_http_get_module_ctx(r, ngx_http_pack_zstd_module);

    ngx_log_debug0(
        NGX_LOG_DEBUG_HTTP,
        r->connection->log,
        0,
        "http zstd filter");

    if (ctx == NULL || ctx->state.closed || r->header_only) {
        return ngx_http_next_body_filter(r, in);
    }

    /* Recorded before "in" is folded into ctx->in: ctx->in running
       dry says the filter has nothing left to compress, this says
       the caller brought nothing new. */
    ctx->state.caller_wants_output = (in == NULL);

    if (in) {
        chain_status = ngx_chain_add_copy(r->pool, &ctx->in, in);
        if (chain_status != NGX_OK) {
            ngx_http_pack_zstd_close(ctx);
            return NGX_ERROR;
        }

        r->connection->buffered |= MASK_BUFFERED;
    }

    prepared = ngx_http_pack_zstd_prepare(&(prepare_args) {
        .ctx = ctx,
    });

    if (prepared.verdict != NGX_HTTP_PACK_ZSTD_OK) {
        return prepared.rc;
    }

    if (ngx_http_pack_zstd_ensure_encoder(ctx).status != NGX_OK) {
        ngx_http_pack_zstd_close(ctx);
        return NGX_ERROR;
    }

    return ngx_http_pack_zstd_pump(ctx).status;
}


static void *
ngx_http_pack_zstd_create_conf(ngx_conf_t *const cf)
{
    conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /* ngx_pcalloc zeroes types, types_keys and bufs. "bufs" has no
       NGX_CONF_UNSET of its own: a zero count is what both
       ngx_conf_set_bufs_slot and ngx_conf_merge_bufs_value read as
       "not set here", and the slot rejects a configured 0 before it
       can be confused with one. */

    conf->enable      = NGX_CONF_UNSET_UINT;
    conf->level       = NGX_CONF_UNSET;
    conf->window_bits = NGX_CONF_UNSET_SIZE;
    conf->hint        = NGX_CONF_UNSET_SIZE;
    conf->min_length  = NGX_CONF_UNSET;
    conf->proxied     = NGX_CONF_UNSET_UINT;

    return conf;
}

static char *
ngx_http_pack_zstd_merge_conf(
    ngx_conf_t *const cf, void *const parent, void *const child)
{
    conf_t *prev;
    conf_t *conf;

    prev = parent;
    conf = child;

    ngx_conf_merge_uint_value(
        conf->enable, prev->enable, NGX_HTTP_PACK_ZSTD_OFF);

    /* Both filters set to "always" for one location is a config
       mistake: each would unconditionally claim every response, and
       only zstd - running first in the chain - actually could.
       Checked here rather than in Brotli's merge_loc_conf because
       this module's merge always runs after Brotli's, so its
       "enable" is already settled by the time this reads it. */
#if (NGX_HTTP_PACK_BROTLI_FILTER_MODULE)
    if (conf->enable == NGX_HTTP_PACK_ZSTD_ALWAYS &&
        ngx_http_pack_brotli_is_always(cf)) {
        ngx_http_core_loc_conf_t *clcf;

        clcf = ngx_http_conf_get_module_loc_conf(
            cf, ngx_http_core_module);

        /* clcf->name is empty for the block's own directives, i.e.
           both set directly in a server{} rather than under a nested
           location{} - "location \"\"" would read as a typo rather
           than as what it is. */
        if (clcf->name.len != 0) {
            ngx_conf_log_error(
                NGX_LOG_EMERG,
                cf,
                0,
                "\"pack_zstd always\" and \"pack_brotli always\" "
                "cannot both apply to location \"%V\" - it would be "
                "ambiguous which one is meant to be the "
                "unconditional default",
                &clcf->name);
        } else {
            ngx_conf_log_error(
                NGX_LOG_EMERG,
                cf,
                0,
                "\"pack_zstd always\" and \"pack_brotli always\" "
                "cannot both apply here - it would be ambiguous "
                "which one is meant to be the unconditional default");
        }

        return NGX_CONF_ERROR;
    }
#endif

    /* Off, as gzip_proxied is: a response reached through another
       proxy is not this server's to transform by default. */
    ngx_conf_merge_uint_value(
        conf->proxied, prev->proxied, NGX_HTTP_PACK_ZSTD_PROXIED_OFF);

    /* Not zstd's own default, which is 3 (ZSTD_CLEVEL_DEFAULT):
       chosen rather than kept, see the constant.
       script/bench/bench_corpus.py is what would justify moving it
       for a given corpus. */
    ngx_conf_merge_value(
        conf->level, prev->level, NGX_HTTP_PACK_ZSTD_LEVEL_DEFAULT);

    /* 16 bits (64 KB): per-request memory outranks compression ratio
       here, and zstd's memory climbs with the window - multiply any
       increase by the concurrent requests a worker carries. 128 KB
       would be the largest window still free in block terms; the
       same ordering decides against going that far. */
    ngx_conf_merge_size_value(
        conf->window_bits,
        prev->window_bits,
        NGX_HTTP_PACK_ZSTD_WINDOW_BITS_DEFAULT);

    /* See the constant block for why the default is none. Both bounds
       belong to the post handler - a floor of this module's own, and
       the ceiling libzstd imposes - and neither is consulted for
       none, which is the absence of a size rather than one. */
    ngx_conf_merge_size_value(
        conf->hint, prev->hint, NGX_HTTP_PACK_ZSTD_HINT_DEFAULT);

    /* One buffer already spans a whole block at the window default;
       the other three are run-ahead, so a stalled write costs the
       remaining buffers rather than the next byte. A fixed pair
       rather than gzip's page-derived one, so a count cannot be
       inherited from a size chosen for another reason. */
    ngx_conf_merge_bufs_value(
        conf->bufs,
        prev->bufs,
        NGX_HTTP_PACK_ZSTD_BUFFER_NUM_DEFAULT,
        NGX_HTTP_PACK_ZSTD_BUFFER_SIZE_DEFAULT);

    /* Below this a response is not worth encoding: the frame's own
       overhead and the "Content-Encoding" header can together cost
       more than the body saves. 256 sits clear of the length where
       the two balance for small text bodies. */
    ngx_conf_merge_value(
        conf->min_length,
        prev->min_length,
        NGX_HTTP_PACK_ZSTD_MIN_LENGTH_DEFAULT);

    if (ngx_http_merge_types(
            cf,
            &conf->types_keys,
            &conf->types,
            &prev->types_keys,
            &prev->types,
            ngx_http_html_default_types) != NGX_CONF_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

/* Prepend to filter chain. */
static ngx_int_t
ngx_http_pack_zstd_init(ngx_conf_t *const cf)
{
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter  = ngx_http_pack_zstd_header_filter;

    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter  = ngx_http_pack_zstd_body_filter;

    return NGX_OK;
}

/* Translate "window size" to windowLog (log2), and check bounds. */
static char *
ngx_http_pack_zstd_parse_window(
    ngx_conf_t *const cf, void *const post, void *const data)
{
    size_t *parameter;
    size_t  bits;
    size_t  wsize;

    parameter = data;

    for (bits = NGX_HTTP_PACK_ZSTD_WINDOW_BITS_MIN;
         bits <= NGX_HTTP_PACK_ZSTD_WINDOW_BITS_MAX;
         bits++) {
        wsize = (size_t) 1 << bits;
        if (*parameter == wsize) {
            *parameter = bits;
            return NGX_CONF_OK;
        }
    }

    return "must be 16k, 32k, 64k, 128k, 256k, 512k, or 1m";
}

/* Checks pack_zstd_hint's parsed size: a floor, and the one ceiling
   that is not this module's to set. NGX_MAX_INT32_VALUE rather than
   letting the value overflow silently: it travels to
   ZSTD_CCtx_setParameter as a plain int, so anything wider must be
   refused here, not wrapped at request time. */
static char *
ngx_http_pack_zstd_check_hint(
    ngx_conf_t *const cf, void *const post, void *const data)
{
    size_t   *hint;
    ngx_str_t limit;

    hint = data;

    if (*hint < NGX_HTTP_PACK_ZSTD_HINT_MIN) {
        limit = ngx_http_pack_format_size(
            cf->pool, NGX_HTTP_PACK_ZSTD_HINT_MIN);

        /* Naming the word here as well: an operator who wrote a size
           below the floor may have wanted no hint rather than a
           small one, and this refusal is where that is discoverable.
         */
        ngx_conf_log_error(
            NGX_LOG_EMERG,
            cf,
            0,
            "must be at least %V, or \"none\"",
            &limit);

        return NGX_CONF_ERROR;
    }

    if (*hint > NGX_MAX_INT32_VALUE) {
        limit = ngx_http_pack_format_size(
            cf->pool, NGX_MAX_INT32_VALUE);

        ngx_conf_log_error(
            NGX_LOG_EMERG, cf, 0, "must not exceed %V", &limit);

        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

/* Parses pack_zstd_hint, which takes a size or the word "none".
   ngx_conf_set_size_slot cannot spell the second, so the word is
   handled here and everything else handed to it unchanged. "none"
   deliberately skips the floor: clamping it up would grant the
   opposite of what was written. */
static char *
ngx_http_pack_zstd_set_hint(
    ngx_conf_t *const cf, ngx_command_t *const cmd, void *const conf)
{
    static ngx_str_t const none = ngx_string("none");

    size_t    *hint;
    ngx_str_t *value;

    hint = (size_t *) ((char *) conf + cmd->offset);

    /* Checked before the word is, so "none" twice is refused the way
       two sizes would be. ngx_conf_set_size_slot repeats this for the
       size path, where the slot is still unset by the time it runs.
     */
    if (*hint != NGX_CONF_UNSET_SIZE) {
        return "is duplicate";
    }

    /* Cast before the arithmetic: "elts" is void *, so adding to it
       directly would step one byte rather than one ngx_str_t. */
    value = ((ngx_str_t *) cf->args->elts) + 1;
    if (value->len == none.len &&
        !ngx_strncmp(value->data, none.data, none.len)) {
        *hint = NGX_HTTP_PACK_ZSTD_HINT_DEFAULT;
        return NGX_CONF_OK;
    }

    return ngx_conf_set_size_slot(cf, cmd, conf);
}

/* Parses pack_zstd_buffers and checks both parameters. The slot
   takes no post handler, so bounds are checked here rather than in
   the merge: the message then names the file and line the value
   came from, and the compiled-in default - moved below the floor on
   purpose by script/tests/stream/test-small-buffer.sh - is never
   held to it. */
static char *
ngx_http_pack_zstd_set_buffers(
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

    if (bufs->num < NGX_HTTP_PACK_ZSTD_BUFFER_NUM_MIN ||
        bufs->num > NGX_HTTP_PACK_ZSTD_BUFFER_NUM_MAX) {

        ngx_conf_log_error(
            NGX_LOG_EMERG,
            cf,
            0,
            "number of buffers must be between %i and %i",
            NGX_HTTP_PACK_ZSTD_BUFFER_NUM_MIN,
            NGX_HTTP_PACK_ZSTD_BUFFER_NUM_MAX);

        return NGX_CONF_ERROR;
    }

    if (bufs->size < NGX_HTTP_PACK_ZSTD_BUFFER_SIZE_MIN ||
        bufs->size > NGX_HTTP_PACK_ZSTD_BUFFER_SIZE_MAX) {

        min = ngx_http_pack_format_size(
            cf->pool, NGX_HTTP_PACK_ZSTD_BUFFER_SIZE_MIN);
        max = ngx_http_pack_format_size(
            cf->pool, NGX_HTTP_PACK_ZSTD_BUFFER_SIZE_MAX);

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
