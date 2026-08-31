/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) Google Inc.
 * Copyright (C) 2026 Juri Torhoff
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

/* Needed for ZSTD_createCCtx_advanced (the custom allocator) and
   ZSTD_c_srcSizeHint. The symbols this unlocks are already exported
   with default visibility in a normal (dynamically linked) libzstd -
   "static linking only" is a promise about API stability across
   releases, not a linker restriction - so this does not commit the
   module to actually linking libzstd statically.

   ZSTD_c_srcSizeHint is the one of those that is genuinely
   experimental rather than merely gated: it is a numbered slot
   (ZSTD_c_experimentalParam7), so a release that reassigned that
   number would have this silently set some other parameter, which no
   compile-time check would catch. Acceptable here only because
   deps/zstd is vendored and pinned, so the number is fixed by the
   tree rather than by whatever libzstd a host happens to carry. A
   build against a system libzstd should re-check it. */

#include "../common/ngx_http_pack_headers.h"
#include "ngx_http_pack_zstd_encoder.h"


static ngx_str_t const ENCODING = ngx_string("zstd");

/* Tells nginx to wait for output.
   Zstandard and GZip never stack, i.e. when one of them sets
   "Content-Encoding" the other becomes a pass-through filter.
   This is why it's safe to re-use the constant here. */
#define NGX_HTTP_PACK_ZSTD_BUFFERED NGX_HTTP_GZIP_BUFFERED

/* The most input that may be held back while waiting to learn the
   response size. There is no point deferring longer than the window
   the encoder would use anyway - pack_zstd_window's compiled-in
   default, below - since committing beyond it cannot change the
   window choice any further.

   That also happens to be one zstd block: a block is
   MIN(windowSize, ZSTD_BLOCKSIZE_MAX) and the window default is the
   smaller of the two, so at 64 KB the two coincide. It is derived
   from the window, so move it if pack_zstd_window's default moves. */
#define NGX_HTTP_PACK_ZSTD_MAX_HELD_INPUT (64 * 1024)

/* windowLog bounds for pack_zstd_window: 1 KB to 1 MB. The floor is
   zstd's own (ZSTD_WINDOWLOG_MIN). The ceiling is memory, not
   compatibility - zstd allows 27 bits and decoders accept it, but
   encoder memory scales with the window and a server pays that per
   request in flight. Nothing served over HTTP earns more than 1 MB.
 */
#define NGX_HTTP_PACK_ZSTD_WINDOW_BITS_MIN 10
#define NGX_HTTP_PACK_ZSTD_WINDOW_BITS_MAX 20


#define NGX_HTTP_PACK_ZSTD_LEVEL_MIN 1
#define NGX_HTTP_PACK_ZSTD_LEVEL_MAX 22

#define NGX_HTTP_PACK_ZSTD_NBUFFERS_MIN 1
#define NGX_HTTP_PACK_ZSTD_NBUFFERS_MAX 64


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
       size is not configurable - see NGX_HTTP_PACK_ZSTD_OUT_SIZE. */
    ngx_int_t nbuffers;
} conf_t;

/* What the body filter should do once ngx_http_pack_zstd_prepare
   has settled the decisions that come before the encoder.

   Only OK carries on; the other three end the call and return "rc",
   which every one of them sets. The caller therefore tests against
   OK alone and does not branch on which of the three it got - they
   are apart for the reader, and so that a future caller can tell a
   response that was handed on from one that failed. */
typedef enum {
    /* Carry on into the encoder loop. */
    NGX_HTTP_PACK_ZSTD_OK = 0,
    /* Not yet: too little of the body has arrived to answer the
       question pack_zstd_min_length asks, or its size is still
       unknown and worth waiting a moment to learn before the encoder
       window is fixed. The input stays in ctx->in and a later call
       decides, so this may still end in compression. "rc" is NGX_OK.
     */
    NGX_HTTP_PACK_ZSTD_DEFER,
    /* Settled, and not compressed: the response is too small to be
       worth it, so the held input has already been handed to the
       filters below untouched. "rc" is what that call returned, and
       the response goes out intact - no "Content-Encoding" of ours
       for the filters below to defer to, so gzip may still take it.
     */
    NGX_HTTP_PACK_ZSTD_PASS,

    /* Settled, and failed: the encoder is closed and "rc" is
       NGX_ERROR. Reached when committing the held headers fails, or
       when a filter below replaced the response with a status - see
       ngx_http_pack_zstd_prepare, which explains why that has to
       become NGX_ERROR rather than travel as the status itself. */
    NGX_HTTP_PACK_ZSTD_ERROR
} prepare_e;


/* What the filter has settled about this response, in the order it
   settles them: accepted, headers away, and finished. What each call
   brings sits among them, since that is where it is read. Anything
   the encoder settles for itself lives in encoder_t instead. Two
   take a test rather than a literal 1 - accepted_for_compression may
   take a min_length comparison, and caller_wants_output takes
   (in == NULL).

   Held inside the context by value, so the ngx_pcalloc that makes
   the context has zeroed every flag before any of them is read: "not
   yet" is the starting state, with no constructor needed to say so.
   That the flags share a struct at all is what keeps them one
   contiguous bitfield run - scattered through the context between
   their first uses they would take a storage unit each. */
typedef struct {
    /* 1 if this response has been accepted for compression. Decided
       either in the header filter, when the length is known up front,
       or in ngx_http_pack_zstd_prepare once enough of the body has
       arrived to judge it; ngx_http_pack_zstd_send_headers reads it
       to know which kind of header to commit. */
    unsigned accepted_for_compression: 1;

    /* 1 once the response headers have been committed. Zero until
       then, which is what ngx_pcalloc leaves and what the header
       filter depends on: with no Content-Length there is nothing to
       compare against pack_zstd_min_length yet, so it holds the
       headers back by leaving this zero and lets the body decide.

       Set only where compressed headers are committed, so the
       uncompressed exit from ngx_http_pack_zstd_send_headers
       leaves it zero even though it too sends the headers on. That
       is safe only because the same branch closes the context, and
       a closed context never reaches ngx_http_pack_zstd_prepare
       again - were it to stop closing, the headers would be
       committed a second time.

       The failing exit leaves it zero as well, and there the closing
       is the caller's: commit_headers closes on an error or on a
       status a filter below substituted, and header_filter hands the
       error to nginx, which abandons the request. The same guarantee,
       kept by a different party. */
    unsigned headers_sent: 1;

    /* 1 if this call of the body filter arrived with no new data,
       i.e. nginx is asking for progress on what it has already handed
       over rather than adding to it. Set once on entry and read by
       ngx_http_pack_zstd_prepare and ngx_http_pack_zstd_next_input.

       The one flag here that belongs to the call rather than to the
       response, which is why it sits where the struct comment says
       "what each call brings". It stays in the struct because the
       second reader is three frames down - body_filter, pump,
       compress, next_input - and passing it would put an args struct
       on pump and compress, both of which take a bare ctx today. */
    unsigned caller_wants_output: 1;

    /* 1 if compression is finished / failed. */
    unsigned closed: 1;
} filter_state_t;


/* Instance context. Members follow the path a request takes through
   the module: the request itself, what the filter has settled about
   it, what the encoder owns on its behalf, then what the header
   filter learned and the chain the body filter takes in.

   The sub-structs are members rather than pointers: they are made
   with the context, live exactly as long as it, and are never shared
   or reseated. */
typedef struct {
    /* The request, and the pool and log reached through it. */
    ngx_http_request_t *request;

    /* The state of the filter: what is decided, done, and pending. */
    filter_state_t state;

    /* The encoder, or NULL until one is built. Opaque: everything
       the filter needs of it goes through
       ngx_http_pack_zstd_encoder_*. Its being non-NULL is what
       "initialized" used to mean. */
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


/* 1 and 22 are zstd's own documented stable range (ZSTD_minCLevel()
   and ZSTD_maxCLevel() are runtime functions, not compile-time
   constants, so they cannot fill an ngx_conf_num_bounds_t literal);
   negative levels are a real part of zstd's range but are not
   exposed through this directive. */
static ngx_conf_num_bounds_t const ngx_http_pack_zstd_levels = {
    ngx_conf_check_num_bounds,
    NGX_HTTP_PACK_ZSTD_LEVEL_MIN,
    NGX_HTTP_PACK_ZSTD_LEVEL_MAX,
};

/* One buffer is enough to be correct - the filter simply stalls until
   the filters below have taken it - so the floor is 1 rather than
   anything larger. The ceiling is arbitrary but not unbounded: each
   buffer costs NGX_HTTP_PACK_ZSTD_OUT_SIZE for the lifetime of the
   response. */
static ngx_conf_num_bounds_t const ngx_http_pack_zstd_nbuffers = {
    ngx_conf_check_num_bounds,
    NGX_HTTP_PACK_ZSTD_NBUFFERS_MIN,
    NGX_HTTP_PACK_ZSTD_NBUFFERS_MAX,
};

static ngx_conf_post_handler_pt const
    ngx_http_pack_zstd_parse_window_p =
        ngx_http_pack_zstd_parse_window;

static ngx_command_t const ngx_http_pack_zstd_commands[] = {
    {
        ngx_string("pack_zstd"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
            NGX_HTTP_LIF_CONF | NGX_CONF_FLAG,
        ngx_conf_set_flag_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(conf_t, enable),
        NULL,
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
        ngx_string("pack_zstd_nbuffers"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
            NGX_CONF_TAKE1,
        ngx_conf_set_num_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(conf_t, nbuffers),
        (void *) &ngx_http_pack_zstd_nbuffers,
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
    ctx->request->connection->buffered &=
        ~NGX_HTTP_PACK_ZSTD_BUFFERED;

    /* Releasing libzstd and dropping the buffer chains is the
       encoder's own business, including why that is safe with buffers
       still downstream.

       The pointer is left as it is rather than cleared, so it still
       reads as "an encoder exists" afterwards. Nothing asks again: a
       closed context never reaches ngx_http_pack_zstd_ensure_encoder,
       because the body filter returns on ctx->state.closed first.
       That is the bargain "initialized" used to make, in the one
       field that replaced it. */
    if (ctx->encoder != NULL) {
        ngx_http_pack_zstd_encoder_close(ctx->encoder);
    }
}

/* Commits headers that ngx_http_pack_zstd_header_filter held back. If
   the response was accepted it is labelled and the encoder will run;
   if not it passes through untouched, leaving no "Content-Encoding"
   for the filters below to defer to, so gzip may still take it.

   Which of the two it is comes from ctx->accepted_for_compression,
   set by whichever caller made the decision. */
static ngx_int_t
ngx_http_pack_zstd_send_headers(ctx_t *const ctx)
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
           ngx_http_pack_zstd_prepare, and the body filter returns
           on ctx->closed before it gets there. The two belong
           together - dropping the close would leave a context that
           reports unsent headers and commits them a second time. */
        ngx_http_pack_zstd_close(ctx);

        return ngx_http_next_header_filter(r);
    }

    /* Tell the filters below that the body is compressed. */
    if (ngx_http_pack_set_encoding(r, &ENCODING) != NGX_OK) {
        return NGX_ERROR;
    }

    ngx_http_clear_content_length(r);
    ngx_http_clear_accept_ranges(r);
    ngx_http_weak_etag(r);

    rc = ngx_http_next_header_filter(r);
    if (rc == NGX_ERROR || rc > NGX_OK) {
        return rc;
    }

    ctx->state.headers_sent = 1;
    return rc; /* NGX_OK or NGX_AGAIN */
}

/* Everything that disqualifies a response on its own terms: the
   directive, the status, what the response already is, and what it
   is made of.

   All six end the same way, so the caller says so once rather than
   six times. None of them allocates or records anything, which is
   what lets a verdict alone answer for them: DECLINE leaves nothing
   behind to undo.

   The client's Accept-Encoding is deliberately not among them. It is
   asked after ngx_http_pack_set_vary, since the response varies
   whether or not this particular client is served Zstandard, and a
   bypass from here has to leave that header alone. */
static ngx_int_t
ngx_http_pack_zstd_preflight(ngx_http_request_t *const r)
{
    conf_t *conf;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_pack_zstd_module);

    /* Filter only if enabled. */
    if (!conf->enable) {
        return NGX_DECLINED;
    }

    /* Bypass "header only" responses. */
    if (r->header_only) {
        return NGX_DECLINED;
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

/* Process headers and decide if request is eligible for zstd
   compression. */
static ngx_int_t
ngx_http_pack_zstd_header_filter(ngx_http_request_t *const r)
{
    ctx_t *ctx;

    if (ngx_http_pack_zstd_preflight(r) != NGX_OK) {
        return ngx_http_next_header_filter(r);
    }

    /* Before the Accept-Encoding test, not after: the response varies
       whether or not this particular client is served Zstandard. */
    if (ngx_http_pack_set_vary(r) != NGX_OK) {
        return NGX_ERROR;
    }

    /* Check if client supports zstd encoding. */
    if (ngx_http_pack_claim_request(r, &ENCODING) != NGX_OK) {
        return ngx_http_next_header_filter(r);
    }

    /* One allocation, and ngx_pcalloc does two jobs with it: every
       flag starts at zero, which is what filter_state_t's comment
       depends on, and the encoder pointer starts NULL, which is what
       "no encoder built yet" means now that no flag says so. What
       libzstd owns is zeroed by the encoder's own allocation
       instead. */
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

    return ngx_http_pack_zstd_send_headers(ctx);
}


typedef struct {
    ngx_chain_t *in;
    ngx_uint_t  *complete;
    ngx_uint_t  *urgent;
} pending_input_args;

/* Totals the unconsumed input, reporting whether the chain closes the
   response ("complete") and whether anything in it demands to be
   pushed out now ("urgent"). */
static size_t
ngx_http_pack_zstd_pending_input(pending_input_args *const args)
{
    ngx_chain_t *in;
    size_t       total;

    in = args->in;

    *args->complete = 0;
    *args->urgent   = 0;

    total = 0;
    for (; in; in = in->next) {
        total += ngx_buf_size(in->buf);
        if (in->buf->last_buf) {
            *args->complete = 1;
        }

        if (in->buf->flush) {
            *args->urgent = 1;
        }
    }

    return total;
}

typedef struct {
    ctx_t     *ctx;
    size_t     pending;
    ngx_uint_t complete;
    ngx_uint_t urgent;
    ngx_int_t *rc;
} commit_headers_args;

/* Headers held back because the length was unknown. Decide as soon as
   the body answers the only question pack_zstd_min_length asks - is
   it at least that big. A flush marker means something downstream is
   waiting, so decide immediately and compress. */
static prepare_e
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
        *args->rc = NGX_OK;
        return NGX_HTTP_PACK_ZSTD_DEFER;
    }

    header_rc = ngx_http_pack_zstd_send_headers(ctx);

    /* An error, or a filter below replacing the response with a
       status. Not "!= NGX_OK": that would catch NGX_AGAIN too, which
       only means the header is queued and the body must still be
       produced. nginx spells the test this way as well.

       Return NGX_ERROR rather than the status, since a body filter's
       callers only understand NGX_ERROR and treat a status as success
       - which left the request hanging. Close, or a later call builds
       an encoder for the replaced response and puts the held body on
       the wire. Both covered by script/test-header-status.sh. */
    if (header_rc == NGX_ERROR || header_rc > NGX_OK) {
        ngx_http_pack_zstd_close(ctx);

        *args->rc = NGX_ERROR;
        return NGX_HTTP_PACK_ZSTD_ERROR;
    }

    if (ctx->state.accepted_for_compression) {
        return NGX_HTTP_PACK_ZSTD_OK;
    }

    /* Pass the held input through untouched. */
    link    = ctx->in;
    ctx->in = NULL;

    ctx->request->connection->buffered &=
        ~NGX_HTTP_PACK_ZSTD_BUFFERED;

    *args->rc = ngx_http_next_body_filter(ctx->request, link);

    return NGX_HTTP_PACK_ZSTD_PASS;
}

typedef struct {
    ctx_t     *ctx;
    ngx_int_t *rc;
} prepare_args;

/* Everything that has to be settled before the encoder can run:
   committing headers the header filter held back, and deciding
   whether to go on holding input while the response size is still
   unknown. */
static prepare_e
ngx_http_pack_zstd_prepare(prepare_args *const args)
{
    ctx_t     *ctx;
    size_t     pending;
    ngx_uint_t complete;
    ngx_uint_t urgent;
    prepare_e  verdict;

    ctx = args->ctx;

    /* The steady state: the headers are away and the encoder exists,
       so there is nothing to settle. */
    if (ctx->state.headers_sent && ctx->encoder != NULL) {
        return NGX_HTTP_PACK_ZSTD_OK;
    }

    pending = ngx_http_pack_zstd_pending_input(&(pending_input_args) {
        .in       = ctx->in,
        .complete = &complete,
        .urgent   = &urgent,
    });

    if (!ctx->state.headers_sent) {
        verdict = ngx_http_pack_zstd_commit_headers(
            &(commit_headers_args) {
                .ctx      = ctx,
                .pending  = pending,
                .complete = complete,
                .urgent   = urgent,
                .rc       = args->rc,
            });

        if (verdict != NGX_HTTP_PACK_ZSTD_OK) {
            return verdict;
        }
    }

    if (ctx->encoder != NULL) {
        return NGX_HTTP_PACK_ZSTD_OK;
    }

    /* The whole body is in hand, so its size is no longer a
       question. */
    if (complete) {
        if (ctx->content_length < 0) {
            ctx->content_length = (off_t) pending;
        }

        return NGX_HTTP_PACK_ZSTD_OK;
    }

    /* Choosing the encoder window costs memory that scales with the
       window, so when the response size is unknown it is worth
       waiting a moment to see if the whole thing turns up. */
    if (!ctx->state.caller_wants_output && !urgent &&
        ctx->content_length < 0 &&
        pending < NGX_HTTP_PACK_ZSTD_MAX_HELD_INPUT) {
        ngx_log_debug1(
            NGX_LOG_DEBUG_HTTP,
            ctx->request->connection->log,
            0,
            "zstd deferring encoder: pending:%uz",
            pending);

        *args->rc = NGX_OK;
        return NGX_HTTP_PACK_ZSTD_DEFER;
    }

    return NGX_HTTP_PACK_ZSTD_OK;
}


/* Hands what the encoder produced to the filters below, then takes
   account of what came back.

   A NULL pending chain is not a no-op: it is what asks those filters
   to make progress on buffers they are already holding, which is the
   only way a busy buffer is ever returned. */
static ngx_int_t
ngx_http_pack_zstd_drain(ctx_t *const ctx)
{
    ngx_int_t rc;

    rc = ngx_http_next_body_filter(
        ctx->request,
        ngx_http_pack_zstd_encoder_pending(ctx->encoder));
    if (rc == NGX_ERROR) {
        return NGX_ERROR;
    }

    ngx_http_pack_zstd_encoder_drained(ctx->encoder);

    /* What nginx has to be told to come back for. Buffers the filters
       below still hold count, and so does input not yet compressed:
       drop the bit while either is outstanding and a stalled last
       write can be finalized as complete, truncating the tail - on a
       socket too full to take it, which loopback tests will not
       reproduce. */
    if (ngx_http_pack_zstd_encoder_busy(ctx->encoder) ||
        ctx->in != NULL) {
        ctx->request->connection->buffered |=
            NGX_HTTP_PACK_ZSTD_BUFFERED;
    } else {
        ctx->request->connection->buffered &=
            ~NGX_HTTP_PACK_ZSTD_BUFFERED;
    }

    return NGX_OK;
}

/* The encoder has nothing left to do for this response. Freeing here
   rather than waiting for the request pool to be destroyed is what
   keeps its memory from outliving the response - but only once the
   last buffer has been taken, since buffers still outstanding mean
   the response is not finished whatever the encoder says. */
static ngx_int_t
ngx_http_pack_zstd_finish(ctx_t *const ctx)
{
    if (ngx_http_pack_zstd_encoder_frame_closed(ctx->encoder) &&
        !ngx_http_pack_zstd_encoder_busy(ctx->encoder)) {
        ngx_http_pack_zstd_close(ctx);
    }

    if (ngx_http_pack_zstd_encoder_busy(ctx->encoder)) {
        return NGX_AGAIN;
    }

    return NGX_OK;
}

/* Builds the encoder on first use, translating the directives into
   what ngx_http_pack_zstd_encoder_create wants. Nothing here reaches
   into the encoder: what it is made of is its own business, and this
   is the only place the two vocabularies meet. */
static ngx_int_t
ngx_http_pack_zstd_ensure_encoder(ctx_t *const ctx)
{
    conf_t *conf;

    if (ctx->encoder != NULL) {
        return NGX_OK;
    }

    conf = ngx_http_get_module_loc_conf(
        ctx->request, ngx_http_pack_zstd_module);

    ctx->encoder = ngx_http_pack_zstd_encoder_create(
        ctx->request,
        &(ngx_http_pack_zstd_encoder_conf_t) {
            .level          = conf->level,
            .window_bits    = conf->window_bits,
            .nbuffers       = conf->nbuffers,
            .content_length = ctx->content_length,
        });

    if (ctx->encoder == NULL) {
        return NGX_ERROR;
    }

    return NGX_OK;
}

/* Everything the body filter does once the encoder exists, and what
   it returns.

   Each turn has two phases: fill every output buffer the encoder can,
   then push the lot down in one chain. Running the encoder to a
   standstill before sending is the point of having more than one
   buffer. With a single buffer the two phases had to alternate, so a
   response was compressed and written one buffer at a time; here a
   stalled write only costs the encoder its remaining buffers, not its
   next byte.

   The loop is here rather than split with the caller so that the one
   condition that turns it - a buffer having come back from below -
   sits with the four that end it. */
static ngx_int_t
ngx_http_pack_zstd_pump(ctx_t *const ctx)
{
    ngx_http_pack_zstd_step_e step;

    for (;;) {
        do {
            step = ngx_http_pack_zstd_encoder_step(
                ctx->encoder,
                &ctx->in,
                ctx->state.caller_wants_output);
        } while (step == NGX_HTTP_PACK_ZSTD_STEP_CONTINUE);

        if (step == NGX_HTTP_PACK_ZSTD_STEP_FAILED) {
            ngx_http_pack_zstd_close(ctx);

            return NGX_ERROR;
        }

        /* Nothing new to send and nothing outstanding: the encoder is
           waiting for input rather than for the filters below.

           A closed frame is excluded rather than covered by "nothing
           outstanding", because this return is the one path past
           ngx_http_pack_zstd_finish - and finish is what closes the
           encoder once the last buffer has been taken. Leaving here
           with the frame closed would strand it until the request
           pool is destroyed.

           That cannot happen as the code stands: the round that
           closes the frame commits a buffer, so "out" is not NULL on
           that pass, and on any later call "busy" is what made finish
           answer NGX_AGAIN rather than close. Both are consequences
           of how commit_buf and finish happen to be written, neither
           is stated anywhere, and the cost of one of them changing is
           an encoder leak that no test would see. Cheaper to not
           depend on them: with the frame closed this falls through to
           a drain of nothing and then to finish, which is where it
           belongs. */
        if (!ngx_http_pack_zstd_encoder_frame_closed(ctx->encoder) &&
            ngx_http_pack_zstd_encoder_pending(ctx->encoder) ==
                NULL &&
            !ngx_http_pack_zstd_encoder_busy(ctx->encoder)) {
            return NGX_OK;
        }

        if (ngx_http_pack_zstd_drain(ctx) != NGX_OK) {
            ngx_http_pack_zstd_close(ctx);

            return NGX_ERROR;
        }

        if (step == NGX_HTTP_PACK_ZSTD_STEP_DONE) {
            return ngx_http_pack_zstd_finish(ctx);
        }

        /* Stopped for want of a buffer. If the send handed one back,
           go round; if not, the filters below are full and there is
           nothing more this call can do. */
        if (!ngx_http_pack_zstd_encoder_has_free(ctx->encoder)) {
            return NGX_AGAIN;
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
    ctx_t *ctx;
    /* What this function returns. Set by respective handler below. */
    ngx_int_t rc;
    /* Status dictates what this function decides to do next. */
    ngx_int_t chain_status;
    prepare_e prepare_status;

    ctx = ngx_http_get_module_ctx(r, ngx_http_pack_zstd_module);

    /* r->connection->log inline rather than through a local: this is
       the only use in the function, and ngx_log_debug0 compiles to
       nothing without --with-debug, so a local would be set and never
       read - which -Wunused-but-set-variable rejects under -Werror in
       a release build. */
    ngx_log_debug0(
        NGX_LOG_DEBUG_HTTP,
        r->connection->log,
        0,
        "http zstd filter");

    if (ctx == NULL || ctx->state.closed || r->header_only) {
        return ngx_http_next_body_filter(r, in);
    }

    rc = NGX_ERROR;

    /* Recorded before "in" is folded into ctx->in: ctx->in running
       dry says the filter has nothing left to compress, this says
       the caller brought nothing new. */
    ctx->state.caller_wants_output = (in == NULL);

    if (in) {
        chain_status = ngx_chain_add_copy(r->pool, &ctx->in, in);
        if (chain_status != NGX_OK) {
            ngx_http_pack_zstd_close(ctx);
            return rc;
        }

        r->connection->buffered |= NGX_HTTP_PACK_ZSTD_BUFFERED;
    }

    prepare_status = ngx_http_pack_zstd_prepare(&(prepare_args) {
        .ctx = ctx,
        .rc  = &rc,
    });

    if (prepare_status != NGX_HTTP_PACK_ZSTD_OK) {
        return rc;
    }

    if (ngx_http_pack_zstd_ensure_encoder(ctx) != NGX_OK) {
        ngx_http_pack_zstd_close(ctx);
        return NGX_ERROR;
    }

    return ngx_http_pack_zstd_pump(ctx);
}


static void *
ngx_http_pack_zstd_create_conf(ngx_conf_t *const cf)
{
    conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /* ngx_pcalloc fills result with zeros ->
         conf->types = { NULL };
         conf->types_keys = NULL; */

    conf->enable      = NGX_CONF_UNSET;
    conf->level       = NGX_CONF_UNSET;
    conf->window_bits = NGX_CONF_UNSET_SIZE;
    conf->nbuffers    = NGX_CONF_UNSET;
    conf->min_length  = NGX_CONF_UNSET;

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

    ngx_conf_merge_value(conf->enable, prev->enable, 0);

    /* zstd's own documented default (ZSTD_CLEVEL_DEFAULT). Kept
       rather than chosen: script/bench_corpus.py is what would
       justify moving it for a given corpus. */
    ngx_conf_merge_value(conf->level, prev->level, 3);

    /* 16 bits (64 KB), because per-request memory outranks
       compression ratio here and zstd's memory climbs with the
       window. Multiply any increase by the concurrent requests a
       worker carries before taking it.

       128 KB is the one alternative worth knowing about, being the
       largest window still free in block terms: a block is
       MIN(window, ZSTD_BLOCKSIZE_MAX), so past 128 KB the window
       buffer grows on its own. The same ordering decides against
       it. */
    ngx_conf_merge_size_value(
        conf->window_bits, prev->window_bits, 16);

    /* Four rather than nginx's gzip default of 32. The buffers exist
       so that a stalled write does not stop the encoder, and past a
       handful they stop buying that: zstd emits at most one block per
       ZSTD_compressStream2 call, so at the 64 KB window default four
       16 KB buffers already cover a whole block with room to spare.
       They also cost - 4 x NGX_HTTP_PACK_ZSTD_OUT_SIZE, held for the
       life of the response - and gzip's 32 x 4K would be 128 KB per
       response for a case this module does not have. */
    ngx_conf_merge_value(conf->nbuffers, prev->nbuffers, 4);

    /* Below this a response is not worth encoding: the frame's own
       overhead and the "Content-Encoding" header can together cost
       more than the body saves. 256 sits clear of the length where
       the two balance for small text bodies. */
    ngx_conf_merge_value(conf->min_length, prev->min_length, 256);

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
        /* size_t rather than "1u", which would evaluate the shift in
           32 bits. */
        wsize = (size_t) 1 << bits;
        if (*parameter == wsize) {
            *parameter = bits;
            return NGX_CONF_OK;
        }
    }

    return "must be 1k, 2k, 4k, 8k, 16k, 32k, "
           "64k, 128k, 256k, 512k, or 1m";
}
