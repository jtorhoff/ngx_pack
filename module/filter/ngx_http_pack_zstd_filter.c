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
#define ZSTD_STATIC_LINKING_ONLY
#include <zstd.h>

#include "../common/ngx_http_pack_headers.h"


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

/* Size of the buffer the module allocates and hands ZSTD_outBuffer.

   Deliberately far below ZSTD_CStreamOutSize(): that value is sized
   from ZSTD_BLOCKSIZE_MAX rather than from the window actually set,
   and a block is MIN(windowSize, ZSTD_BLOCKSIZE_MAX), so at the 64 KB
   window default one block never needs more than
   ZSTD_compressBound(64 KB). zstd emits at most one block per
   ZSTD_compressStream2 call, so past the size of a block a larger
   buffer cannot reduce the number of rounds the encoder needs.

   How many buffers of this size a response may hold at once is
   pack_zstd_nbuffers, and that one is configurable; this is the size
   of each. Overridable at build time only so that the test suite can
   shrink it far below anything sane - see
   script/test-small-buffer.sh, which uses 64 bytes to force the
   partial-drain paths that a 16 KB buffer reaches only rarely. Not a
   configuration knob: there is no directive behind this, and nothing
   but the stress build should set it. */
#ifndef NGX_HTTP_PACK_ZSTD_OUT_SIZE
#define NGX_HTTP_PACK_ZSTD_OUT_SIZE (16 * 1024)
#endif

/* How many buffers carrying "flush" may share one zstd block.

   A flush cuts the block short, which costs both encoder time and
   output size. A flush landing on a 64 KB boundary costs nothing,
   because a block is MIN(windowSize, ZSTD_BLOCKSIZE_MAX) and that is
   where the encoder was going to end one anyway.

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
#define NGX_HTTP_PACK_ZSTD_FLUSH_FOLD 4

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
   see the pledge below.

   256 KB rather than the window, which was the first guess and is
   wrong in both directions: at the default window it is small enough
   to cost ratio, the "regress significantly if guess considerably
   underestimates" zstd.h warns of, and above 256 KB it stops capping
   the tables at all. A smaller hint bounds the tables further but
   gives up output size for memory this module does not need. */
#define NGX_HTTP_PACK_ZSTD_SRC_SIZE_HINT (256 * 1024)

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

/* What one turn of the encoder decided to do next. The loop owns the
   returns; a step only says which one.

   Its own type, as prepare_e is, because both outlive the call that
   made them - this one is written by next_input, returned by compress
   and then held across pump's loop and the three tests after it. Zero
   means "carry on" in either type, so one spelled in nginx's codes
   and tested against the other's constant would compile and behave;
   typed, -Wenum-compare rejects it. A verdict consumed where it is
   produced is owed none of that, which is why preflight and
   made_progress answer in nginx's codes instead.

   Two callers read this type and they do not carry on at the same
   value: next_input's is STEP_READY, the loop's is STEP_CONTINUE. */
typedef enum {
    /* Not a step at all: what ngx_http_pack_zstd_next_input says when
       it has settled nothing and the encoder should run. It goes no
       further than ngx_http_pack_zstd_compress, which turns it into
       an actual step by running the round - so the loop never sees
       this one. Here rather than in a type of its own so that
       next_input answers on one channel instead of a code beside an
       out-parameter. */
    NGX_HTTP_PACK_ZSTD_STEP_READY = 0,

    /* Made progress; go round again. */
    NGX_HTTP_PACK_ZSTD_STEP_CONTINUE,

    /* Stopped for want of a free output buffer, with work still to
       do. Whether that can be resolved depends on what the filters
       below hand back, so the loop decides. */
    NGX_HTTP_PACK_ZSTD_STEP_AGAIN,

    /* The encoder has nothing more to give until it is fed again. */
    NGX_HTTP_PACK_ZSTD_STEP_DONE,

    /* Unrecoverable; the loop closes the stream and returns
       NGX_ERROR. */
    NGX_HTTP_PACK_ZSTD_STEP_FAILED
} step_e;

/* The response's flags, in the order the response passes through
   them: decided, committed, the encoder built, then what each call
   brings and what the encoder is still holding, and last the two
   ways it ends. Two take a test rather than a literal 1 -
   accepted_for_compression may take a min_length comparison, and
   caller_wants_output takes (in == NULL).

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

    /* 1 if the encoder, output chain and buffer are allocated. */
    unsigned initialized: 1;

    /* 1 if this call of the body filter arrived with no new data,
       i.e. nginx is asking for progress on what it has already handed
       over rather than adding to it. Set once on entry and read by
       both ngx_http_pack_zstd_prepare and
       ngx_http_pack_zstd_compress. */
    unsigned caller_wants_output: 1;

    /* 1 if input has been handed to the encoder under ZSTD_e_continue
       that it may still be holding, unflushed. zstd gives no query
       for "is anything buffered", so this tracks it: set when a
       continue call consumes bytes, cleared once a flush fully
       drains. */
    unsigned unflushed_input: 1;

    /* 1 once ZSTD_compressStream2(..., ZSTD_e_end) has reported
       "fully flushed" (a return of 0). */
    unsigned frame_closed: 1;

    /* 1 if compression is finished / failed. */
    unsigned closed: 1;
} state_t;

/* What libzstd owns on this response's behalf: the encoder itself,
   and the directive still owed to it. Held inside the context by
   value like the flags above, so both are zeroed before the first
   read - which ZSTD_e_continue being 0 depends on, see repeat_mode.

   A struct of its own even so, because the pool cleanup that frees
   the encoder on an aborted request is handed exactly this much and
   no more: &ctx->encoder, not the context, so nothing in the handler
   can reach a request that may already be gone. */
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
} zctx_t;

/* Instance context. Members follow the path a request takes through
   the module: the request itself and the two sub-structs that track
   what becomes of it, then what the header filter learns, the chain
   the body filter takes in, the buffers drawn and filled, and the
   filled ones handed on.

   The sub-structs are members rather than pointers: they are made
   with the context, live exactly as long as it, and are never shared
   or reseated.

   Two groups sit at the position of their earliest member rather
   than being split across it, since one comment covers each. */
typedef struct {
    /* The request, and the pool and log reached through it. */
    ngx_http_request_t *request;

    /* The state of the filter: what is decided, done, and pending. */
    state_t state;

    /* The encoder and what is owed to it; see zctx_t. */
    zctx_t encoder;

    /* Payload length; -1, if unknown. */
    off_t content_length;

    /* Input buffer chain. */
    ngx_chain_t *in;

    /* How many buffers have been created so far, against
       pack_zstd_nbuffers. Created on demand rather than up front, so
       a response that never needs a second one never pays for it. */
    ngx_uint_t nbuffers;
    size_t     out_size;

    /* Output buffers, in the three states nginx's chain helpers keep
       them in. These point at memory *we* allocated, not at anything
       the encoder owns.

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

    /* How many flush-marked buffers have been folded into the block
       still being built - see NGX_HTTP_PACK_ZSTD_FLUSH_FOLD.
       Reset whenever a flush or the end of the frame completes, since
       that is what starts the next block. */
    ngx_uint_t folded_flushes;
} ctx_t;


static void *ngx_http_pack_zstd_alloc(void *opaque, size_t size);
static void ngx_http_pack_zstd_free(void *opaque, void *address);
static void ngx_http_pack_zstd_cleanup(void *data);


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

    ngx_http_pack_zstd_cleanup(&ctx->encoder);

    /* The buffers and their links point into the request pool:
       nothing to hand back, dropping them is the cleanup. Dropped
       rather than left stale so that a use after close faults instead
       of quietly writing into memory the pool still owns -
       ensure_stream guards on "initialized", which close does not
       reset. out_size goes too, to keep it coherent with them.

       "busy" is dropped along with the rest, which is safe because
       nothing here owns those buffers any more:
       ngx_http_write_filter copies the chain links it is given, so
       what is downstream survives this. The list exists only to know
       which buffers may be refilled, and after close none may. */
    ctx->out      = NULL;
    ctx->last_out = NULL;
    ctx->busy     = NULL;
    ctx->free     = NULL;

    ctx->nbuffers = 0;
    ctx->out_size = 0;
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

    /* Prepare instance context, the response's flags and what libzstd
       owns, in one allocation: the flags and the encoder handle live
       inside the context by value, so this zeroes all three at once.
       Every flag reading zero and repeat_mode reading ZSTD_e_continue
       are what the two structs' comments depend on. */
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
    ctx_t      *ctx;
    ngx_buf_t **out;
} get_buf_args;

/* Hands back a buffer to compress into.

   NGX_OK with "*out" set, NGX_DECLINED when every buffer this
   response is allowed is already in flight, or NGX_ERROR. DECLINED is
   not a failure: it means the encoder has to wait for the filters
   below to give one back, which is what the loop turns into a send.

   Buffers are created on demand and then recycled through ctx->free
   for the rest of the response, so a response that only ever needs
   one never allocates a second. */
static ngx_int_t
ngx_http_pack_zstd_get_buf(get_buf_args *const args)
{
    ctx_t              *ctx;
    ngx_http_request_t *r;
    ngx_chain_t        *link;
    ngx_buf_t          *buf;
    conf_t             *conf;

    ctx = args->ctx;
    r   = ctx->request;

    if (ctx->free != NULL) {
        link      = ctx->free;
        buf       = link->buf;
        ctx->free = link->next;

        ngx_free_chain(r->pool, link);

        /* ngx_chain_update_chains has already rewound pos and last to
           start; the flags are this filter's to set per round. */
        *args->out = buf;
        return NGX_OK;
    }

    conf = ngx_http_get_module_loc_conf(r, ngx_http_pack_zstd_module);
    if ((ngx_int_t) ctx->nbuffers >= conf->nbuffers) {
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
    buf->tag      = (ngx_buf_tag_t) &ngx_http_pack_zstd_module;
    buf->recycled = 1;

    ctx->nbuffers++;

    ngx_log_debug2(
        NGX_LOG_DEBUG_HTTP,
        r->connection->log,
        0,
        "zstd buffer created: %p, total:%ui",
        buf,
        ctx->nbuffers);

    *args->out = buf;
    return NGX_OK;
}

typedef struct {
    ctx_t            *ctx;
    ngx_buf_t        *buf;
    size_t            written;
    ZSTD_EndDirective mode;
} commit_buf_args;

/* Hands the round's output buffer to ctx->out.

   Reached even when nothing was written: should the call that finally
   drives "remaining" to 0 ever not write new bytes, the last_buf
   marker still has to land on some buffer or nginx never learns the
   response ended.

   That empty buffer has to be a *special* one, which is why
   "temporary" is set here per round rather than once at
   initialization. ngx_buf_special() is false for anything
   ngx_buf_in_memory() accepts, and ngx_http_write_filter rejects a
   zero-size non-special buffer outright - it logs "zero size buf in
   writer" and returns NGX_ERROR, truncating the response rather than
   merely complaining. So a buffer carrying no bytes must claim no
   memory either.

   That case is defence against a contract change rather than one seen
   in practice: zstd is not known to report a fully flushed frame from
   ZSTD_e_end while writing no bytes. */
static ngx_int_t
ngx_http_pack_zstd_commit_buf(commit_buf_args *const args)
{
    ngx_buf_t   *buf;
    ngx_chain_t *link;

    buf = args->buf;

    buf->pos       = (buf->start);
    buf->last      = (buf->start + args->written);
    buf->temporary = (args->written > 0);
    buf->sync      = (args->written == 0);
    buf->flush     = (args->mode == ZSTD_e_flush);
    buf->last_buf  = (args->ctx->state.frame_closed);

    link = ngx_alloc_chain_link(args->ctx->request->pool);
    if (link == NULL) {
        return NGX_ERROR;
    }

    link->buf            = buf;
    link->next           = NULL;
    *args->ctx->last_out = link;
    args->ctx->last_out  = &link->next;

    ngx_log_debug2(
        NGX_LOG_DEBUG_HTTP,
        args->ctx->request->connection->log,
        0,
        "zstd out: %p, size:%O",
        buf,
        ngx_buf_size(buf));

    return NGX_OK;
}

typedef struct {
    ctx_t     *ctx;
    ngx_buf_t *buf;
} release_buf_args;

/* Puts an unused buffer back where get_buf will find it again. */
static ngx_int_t
ngx_http_pack_zstd_release_buf(release_buf_args *const args)
{
    ctx_t       *ctx;
    ngx_chain_t *link;

    ctx  = args->ctx;
    link = ngx_alloc_chain_link(ctx->request->pool);
    if (link == NULL) {
        return NGX_ERROR;
    }

    link->buf  = args->buf;
    link->next = ctx->free;
    ctx->free  = link;

    return NGX_OK;
}

/* Takes the head buffer off the *input* chain - the one nginx handed
   us, not the output buffers the three above deal with - there being
   no further reason to hold it: either it never carried anything to
   compress, or the encoder has taken every byte it had.

   The link goes back to the pool's own free list rather than being
   abandoned to the request, which is what keeps a long response's
   chain links a fixed cost instead of one allocation per buffer.

   The caller has already established that ctx->in is not NULL - both
   reach the head buffer before they can decide to drop it. */
static void
ngx_http_pack_zstd_discard_head_buf(ctx_t *const ctx)
{
    ngx_chain_t *link;

    link    = ctx->in;
    ctx->in = link->next;

    ngx_free_chain(ctx->request->pool, link);
}

typedef struct {
    ngx_chain_t *rest;
    ngx_uint_t   folded;
} may_fold_flush_args;

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
ngx_http_pack_zstd_may_fold_flush(may_fold_flush_args *const args)
{
    ngx_uint_t   lookahead;
    ngx_chain_t *link;

    /* Can't fold any more. */
    if (args->folded + 1 >= NGX_HTTP_PACK_ZSTD_FLUSH_FOLD) {
        return 0;
    }

    /* Look ahead for the flush or the end buffer. */
    {
        lookahead = NGX_HTTP_PACK_ZSTD_FLUSH_FOLD - 1 - args->folded;

        link = args->rest;
        for (;;) {
            if (link == NULL || lookahead == 0) {
                break;
            }

            if (link->buf->flush || link->buf->last_buf) {
                return 1;
            }

            link = link->next;
            lookahead--;
        }
    }

    /* Couldn't find any, so this flush cuts a block here. */
    return 0;
}

typedef struct {
    ZSTD_EndDirective mode;
    ngx_uint_t        folded;
} select_mode_result;

/* Which directive the buffer at the head of the chain calls for, and
   whether its flush is being folded into the block being built.

   The head buffer is taken from ctx rather than passed in, since the
   fold below reads the chain behind it either way and one source for
   both cannot disagree with itself. next_input has established that
   ctx->in is not NULL before it can want a mode at all.

   The fold is reported rather than counted here: acquiring an output
   buffer can still fail, and a fold recorded on a round that never
   reached the encoder would spend part of the allowance on nothing.
 */
static select_mode_result
ngx_http_pack_zstd_select_mode(ctx_t *const ctx)
{
    ngx_buf_t *buf;
    ngx_uint_t folded;

    buf    = ctx->in->buf;
    folded = 0;

    if (buf->last_buf) {
        return (select_mode_result) {
            .mode   = ZSTD_e_end,
            .folded = folded,
        };
    }

    if (!buf->flush) {
        return (select_mode_result) {
            .mode   = ZSTD_e_continue,
            .folded = folded,
        };
    }

    folded = ngx_http_pack_zstd_may_fold_flush(
        &(may_fold_flush_args) {
            .rest   = ctx->in->next,
            .folded = ctx->folded_flushes,
        });

    if (folded) {
        return (select_mode_result) {
            .mode   = ZSTD_e_continue,
            .folded = folded,
        };
    }

    return (select_mode_result) {
        .mode   = ZSTD_e_flush,
        .folded = folded,
    };
}

typedef struct {
    ctx_t             *ctx;
    ZSTD_EndDirective *mode;
    ZSTD_inBuffer     *in;
    ngx_uint_t        *folded;
} next_input_args;

/* Settles what the encoder is asked to do this round and what it is
   handed to do it with: the directive, the input window, and whether
   this round's flush is being folded into the block being built.

   NGX_HTTP_PACK_ZSTD_STEP_READY means carry on into the encoder.
   Anything else is a round that is over before it starts, and is the
   step the caller returns. */
static step_e
ngx_http_pack_zstd_next_input(next_input_args *const args)
{
    ctx_t              *ctx;
    ngx_http_request_t *r;
    ngx_buf_t          *buf;
    select_mode_result  selected;

    ctx = args->ctx;
    r   = ctx->request;

    /* Covers the branch below, which settles a round with no input of
       its own and never reaches select_mode to be told there is
       nothing folded. */
    *args->folded = 0;

    if (ctx->in == NULL) {
        if (ctx->encoder.repeat_mode != ZSTD_e_continue) {
            /* Finishing what was started takes priority over asking
               whether the caller wants output - see repeat_mode. */
            *args->mode = ctx->encoder.repeat_mode;
        } else if (
            ctx->state.caller_wants_output &&
            ctx->state.unflushed_input) {
            *args->mode = ZSTD_e_flush;
        } else {
            /* Nothing to do; wait for more input. */
            return NGX_HTTP_PACK_ZSTD_STEP_DONE;
        }

        args->in->src  = NULL;
        args->in->size = 0;
        args->in->pos  = 0;

        return NGX_HTTP_PACK_ZSTD_STEP_READY;
    }

    buf = ctx->in->buf;

    /* Only what is in memory can be compressed, and zin.src can only
       be the memory pointer - so the length has to come from the same
       place. ngx_buf_size() would not: for a buffer backed by a file
       it reports the file range, which paired with buf->pos describes
       nothing. nginx's own gzip filter takes "last - pos" for exactly
       this reason.

       A buffer holding file bytes and none in memory should not reach
       us at all: the header filter sets main_filter_need_in_memory,
       and the copy filter above us in the chain honours it. If one
       does, something between the two ignored it, and there is
       nothing here that can encode it - so say so rather than hand
       zstd a pointer that does not describe the data. */
    if (buf->in_file && !ngx_buf_in_memory(buf)) {
        ngx_log_error(
            NGX_LOG_ALERT,
            r->connection->log,
            0,
            "zstd got a buffer with file bytes and none in memory");

        return NGX_HTTP_PACK_ZSTD_STEP_FAILED;
    }

    /* An empty buffer carries nothing to compress, but one marked
       last or flush still has to reach the encoder to close the
       stream or the block. Anything else is dropped. */
    if (ngx_buf_size(buf) == 0 && !buf->last_buf && !buf->flush) {
        ngx_http_pack_zstd_discard_head_buf(ctx);

        return NGX_HTTP_PACK_ZSTD_STEP_CONTINUE;
    }

    selected      = ngx_http_pack_zstd_select_mode(ctx);
    *args->mode   = selected.mode;
    *args->folded = selected.folded;

    args->in->src = buf->pos;
    /* "last > pos" as well as the in-memory test: the subtraction is
       unsigned, so an inverted buffer would become an enormous length
       and read far past the allocation. */
    if (ngx_buf_in_memory(buf) && buf->last > buf->pos) {
        args->in->size = (size_t) (buf->last - buf->pos);
    } else {
        args->in->size = 0;
    }
    args->in->pos = 0;

    return NGX_HTTP_PACK_ZSTD_STEP_READY;
}

typedef struct {
    ctx_t *ctx;
    size_t consumed;
} advance_input_args;

/* Records progress in the chain itself. It cannot be kept in the
   ZSTD_inBuffer's "pos" alone, which does not survive returning to
   nginx. That pos is the right amount to advance by whatever the
   mode: a flush or an end call may also leave input partially
   unconsumed if the output buffer filled first - see the doc comment
   on ZSTD_compressStream2. */
static void
ngx_http_pack_zstd_advance_input(advance_input_args *const args)
{
    ctx_t     *ctx;
    ngx_buf_t *buf;

    ctx = args->ctx;

    if (ctx->in == NULL) {
        return;
    }

    buf = ctx->in->buf;

    /* Guarded, not just for tidiness: a special buffer carries no
       memory, so pos is NULL, and advancing a null pointer by zero is
       undefined even though every compiler does the obvious thing.
       UBSan reports it on the last_buf that ngx_http_send_special
       emits. */
    if (args->consumed > 0) {
        buf->pos += args->consumed;
    }

    if (ngx_buf_size(buf) == 0) {
        ngx_http_pack_zstd_discard_head_buf(ctx);
    }
}

typedef struct {
    ctx_t            *ctx;
    ZSTD_EndDirective mode;
    size_t            consumed;
    size_t            remaining;
} record_round_args;

/* What this round leaves behind for the next one: whether the encoder
   is still holding input nobody has asked it to flush, whether the
   directive has to be repeated, and whether the frame is closed. */
static void
ngx_http_pack_zstd_record_round(record_round_args *const args)
{
    if (args->mode == ZSTD_e_continue) {
        if (args->consumed > 0) {
            args->ctx->state.unflushed_input = 1;
        }

        return;
    }

    if (args->remaining != 0) {
        /* Not finished, whichever of the two it was: repeat it once
           the input in hand has been consumed. */
        args->ctx->encoder.repeat_mode = args->mode;

        return;
    }

    args->ctx->encoder.repeat_mode = ZSTD_e_continue;

    /* Either directive ends the block, so the next one starts with
       nothing folded into it. */
    args->ctx->folded_flushes = 0;

    if (args->mode == ZSTD_e_flush) {
        args->ctx->state.unflushed_input = 0;
    } else { /* ZSTD_e_end */
        args->ctx->state.frame_closed = 1;
    }
}

typedef struct {
    ctx_t            *ctx;
    ZSTD_EndDirective mode;
    size_t            written;
    size_t            remaining;
} made_progress_args;

/* Whether the round moved anything. The one case where it did not is
   draining with no input left, and a call that neither wrote a byte
   nor finished: repeating that would leave every input unchanged and
   the worker spinning.

   NGX_OK when the round got somewhere, NGX_ERROR when it did not.
   An error rather than anything retryable, deliberately: retrying is
   the very thing that spins, and a spin is a far worse way to fail
   than an error.

   zstd should never do this - a flush or an end against a whole free
   output buffer either writes or reports nothing remaining - so this
   guards an assumption rather than an observed case, and says so in
   the log if it is ever wrong.

   Answers only; the caller owns what to do about it. */
static ngx_int_t
ngx_http_pack_zstd_made_progress(made_progress_args *const args)
{
    ngx_chain_t *in;
    size_t       written;
    size_t       remaining;

    in        = args->ctx->in;
    written   = args->written;
    remaining = args->remaining;

    if (in == NULL && written == 0 && remaining != 0) {
        ngx_log_error(
            NGX_LOG_ALERT,
            args->ctx->request->connection->log,
            0,
            "zstd compress made no progress: mode:%d "
            "remaining:%uz",
            (int) args->mode,
            remaining);

        return NGX_ERROR;
    }

    return NGX_OK;
}

typedef struct {
    size_t written;
    size_t remaining;
} compress_buf_result;

typedef struct {
    ctx_t               *ctx;
    ngx_buf_t           *buf;
    ZSTD_EndDirective    mode;
    ZSTD_inBuffer       *in;
    compress_buf_result *result;
} compress_buf_args;

/* Runs the encoder once, into the buffer this round drew.

   The ZSTD_outBuffer lives and dies here. Nothing above needs it once
   the call returns, only how many bytes landed in it, so the window
   is built and dropped in one place rather than kept alive across the
   rest of the round.

   "in" is advanced rather than copied: ZSTD_compressStream2 moves its
   "pos", and the caller reads that to learn what was consumed.

   NGX_OK with *result filled, or NGX_ERROR with the reason logged. */
static ngx_int_t
ngx_http_pack_zstd_compress_buf(compress_buf_args *const args)
{
    ctx_t         *ctx;
    ZSTD_outBuffer out;
    size_t         remaining;

    ctx = args->ctx;

    out.dst  = args->buf->start;
    out.size = ctx->out_size;
    out.pos  = 0;

    remaining = ZSTD_compressStream2(
        ctx->encoder.cctx, &out, args->in, args->mode);
    if (ZSTD_isError(remaining)) {
        ngx_log_error(
            NGX_LOG_ALERT,
            ctx->request->connection->log,
            0,
            "zstd compress failed: %s",
            ZSTD_getErrorName(remaining));

        return NGX_ERROR;
    }

    args->result->written   = out.pos;
    args->result->remaining = remaining;

    return NGX_OK;
}

typedef struct {
    ctx_t            *ctx;
    ngx_buf_t        *buf;
    size_t            written;
    ZSTD_EndDirective mode;
} dispose_buf_args;

/* What becomes of the round's output buffer, which is one of only two
   things: handed back to be filled again, or committed to ctx->out.

   Nothing produced and the frame still open is the first. It means go
   round again rather than return - a flush or an end still being
   drained has to be retried, and the caller is otherwise not owed a
   return yet. The buffer goes back unused, or the round would spend
   one out of pack_zstd_nbuffers on nothing.

   Anything else is the second, an empty buffer included: see
   ngx_http_pack_zstd_commit_buf for why the last_buf marker has to
   land on one even when no bytes were written. */
static step_e
ngx_http_pack_zstd_dispose_buf(dispose_buf_args *const args)
{
    ctx_t    *ctx;
    ngx_int_t rc;

    ctx = args->ctx;

    if (args->written == 0 && !ctx->state.frame_closed) {
        rc = ngx_http_pack_zstd_release_buf(&(release_buf_args) {
            .ctx = ctx,
            .buf = args->buf,
        });

        if (rc != NGX_OK) {
            return NGX_HTTP_PACK_ZSTD_STEP_FAILED;
        }

        return NGX_HTTP_PACK_ZSTD_STEP_CONTINUE;
    }

    rc = ngx_http_pack_zstd_commit_buf(&(commit_buf_args) {
        .ctx     = ctx,
        .buf     = args->buf,
        .written = args->written,
        .mode    = args->mode,
    });

    if (rc != NGX_OK) {
        return NGX_HTTP_PACK_ZSTD_STEP_FAILED;
    }

    return NGX_HTTP_PACK_ZSTD_STEP_CONTINUE;
}

/* Runs the encoder once and, if it produced anything, appends a
   buffer to ctx->out. ZSTD_compressStream2 moves input and output in
   a single call, so there is no separate "does the encoder have
   output ready" phase to ask about first. */
static step_e
ngx_http_pack_zstd_compress(ctx_t *const ctx)
{
    step_e              step;
    ZSTD_EndDirective   zmode;
    ZSTD_inBuffer       zin;
    ngx_uint_t          folded;
    ngx_int_t           rc;
    ngx_buf_t          *out_buf;
    compress_buf_result zresult;

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
        return NGX_HTTP_PACK_ZSTD_STEP_DONE;
    }

    step = ngx_http_pack_zstd_next_input(&(next_input_args) {
        .ctx    = ctx,
        .mode   = &zmode,
        .in     = &zin,
        .folded = &folded,
    });

    if (step != NGX_HTTP_PACK_ZSTD_STEP_READY) {
        return step;
    }

    /* Last thing before the encoder runs, and nothing above it has
       touched the input or the fold count yet, so giving up here
       costs nothing and can simply be repeated once a buffer comes
       back. */
    rc = ngx_http_pack_zstd_get_buf(&(get_buf_args) {
        .ctx = ctx,
        .out = &out_buf,
    });

    if (rc == NGX_ERROR) {
        return NGX_HTTP_PACK_ZSTD_STEP_FAILED;
    }

    if (rc == NGX_DECLINED) {
        return NGX_HTTP_PACK_ZSTD_STEP_AGAIN;
    }

    rc = ngx_http_pack_zstd_compress_buf(&(compress_buf_args) {
        .ctx    = ctx,
        .buf    = out_buf,
        .mode   = zmode,
        .in     = &zin,
        .result = &zresult,
    });

    if (rc != NGX_OK) {
        return NGX_HTTP_PACK_ZSTD_STEP_FAILED;
    }

    if (folded) {
        ctx->folded_flushes++;
    }

    ngx_http_pack_zstd_advance_input(&(advance_input_args) {
        .ctx      = ctx,
        .consumed = zin.pos,
    });

    ngx_http_pack_zstd_record_round(&(record_round_args) {
        .ctx       = ctx,
        .mode      = zmode,
        .consumed  = zin.pos,
        .remaining = zresult.remaining,
    });

    rc = ngx_http_pack_zstd_made_progress(&(made_progress_args) {
        .ctx       = ctx,
        .mode      = zmode,
        .written   = zresult.written,
        .remaining = zresult.remaining,
    });

    if (rc != NGX_OK) {
        return NGX_HTTP_PACK_ZSTD_STEP_FAILED;
    }

    return ngx_http_pack_zstd_dispose_buf(&(dispose_buf_args) {
        .ctx     = ctx,
        .buf     = out_buf,
        .written = zresult.written,
        .mode    = zmode,
    });
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
    if (ctx->state.headers_sent && ctx->state.initialized) {
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

    if (ctx->state.initialized) {
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

/* Brings the encoder into existence with the request pool behind its
   allocator, and arranges for it to be released even if the request
   is aborted mid-stream - the encoder's memory is not the pool's, so
   nothing else would. The cleanup is registered first, deliberately:
   a failure there must not be able to strand an allocated instance.
 */
static ngx_int_t
ngx_http_pack_zstd_init_encoder(ctx_t *const ctx)
{
    ngx_pool_cleanup_t *cln;
    ZSTD_customMem      zmem;

    cln = ngx_pool_cleanup_add(ctx->request->pool, 0);
    if (cln == NULL) {
        return NGX_ERROR;
    }

    cln->handler = ngx_http_pack_zstd_cleanup;
    cln->data    = &ctx->encoder;

    zmem.customAlloc = ngx_http_pack_zstd_alloc;
    zmem.customFree  = ngx_http_pack_zstd_free;
    zmem.opaque      = ctx->request->pool;

    ctx->encoder.cctx = ZSTD_createCCtx_advanced(zmem);
    if (ctx->encoder.cctx == NULL) {
        ngx_log_error(
            NGX_LOG_ALERT,
            ctx->request->connection->log,
            0,
            "zstd encoder instance creation failed: "
            "out of memory?");

        return NGX_ERROR;
    }

    return NGX_OK;
}

typedef struct {
    ctx_t           *ctx;
    ZSTD_cParameter  param;
    int32_t          value;
    ngx_str_t const *name;
} set_param_args;

/* One ZSTD_CCtx_setParameter call with its failure handled the same
   way as every other. "name" is the parameter as zstd.h spells it:
   the enum carries no name at runtime, and the number alone would
   make the log line useless to whoever reads it. */
static ngx_int_t
ngx_http_pack_zstd_set_param(set_param_args *const args)
{
    size_t zrc;

    zrc = ZSTD_CCtx_setParameter(
        args->ctx->encoder.cctx, args->param, args->value);
    if (ZSTD_isError(zrc)) {
        ngx_log_error(
            NGX_LOG_ALERT,
            args->ctx->request->connection->log,
            0,
            "zstd error while trying to set %V=%D: %s",
            args->name,
            args->value,
            ZSTD_getErrorName(zrc));

        return NGX_ERROR;
    }

    return NGX_OK;
}

static ngx_int_t
ngx_http_pack_zstd_set_pledged_size(ctx_t *const ctx)
{
    size_t zrc;

    zrc = ZSTD_CCtx_setPledgedSrcSize(
        ctx->encoder.cctx, ctx->content_length);
    if (ZSTD_isError(zrc)) {
        ngx_log_error(
            NGX_LOG_ALERT,
            ctx->request->connection->log,
            0,
            "zstd error while trying to set pledgedSrcSize=%O: %s",
            ctx->content_length,
            ZSTD_getErrorName(zrc));

        return NGX_ERROR;
    }

    return NGX_OK;
}

/* Tells the encoder what the directives asked for and what to expect
   of the body. Every rejection here is fatal rather than skipped:
   libzstd is vendored and pinned (see deps/zstd), so one means a
   broken build and not a host carrying an older library. */
static ngx_int_t
ngx_http_pack_zstd_configure_encoder(ctx_t *const ctx)
{
    static ngx_str_t const level    = ngx_string("compressionLevel");
    static ngx_str_t const window   = ngx_string("windowLog");
    static ngx_str_t const workers  = ngx_string("nbWorkers");
    static ngx_str_t const sizeHint = ngx_string("srcSizeHint");

    enum { nparams = 3 };

    conf_t        *conf;
    set_param_args params[nparams];
    ngx_uint_t     idx;
    ngx_int_t      rc;

    conf = ngx_http_get_module_loc_conf(
        ctx->request, ngx_http_pack_zstd_module);

    /* Straight from pack_zstd_level, the one of these an operator is
       meant to tune: it trades CPU for size. Held to 1..22 when the
       directive is parsed, so nothing here rechecks it. */
    params[0] = (set_param_args) {
        .ctx   = ctx,
        .param = ZSTD_c_compressionLevel,
        .value = conf->level,
        .name  = &level,
    };

    /* A ceiling, not a target. Sizing the window down to a known
       response was once done here by hand, which was work zstd
       already does: ZSTD_adjustCParams_internal runs after
       ZSTD_overrideCParams and lowers windowLog to
       ceil(log2(pledged size)) - the same value the loop computed,
       and it lowers hashLog and chainLog to match, which the loop
       did not. Checked across 208 combinations of window ceiling,
       level and body size: identical frame window descriptor and
       identical peak encoder allocation either way. So the ceiling
       is all this has to set, and the pledge below does the rest. */
    params[1] = (set_param_args) {
        .ctx   = ctx,
        .param = ZSTD_c_windowLog,
        .value = conf->window_bits,
        .name  = &window,
    };

    /* nginx already parallelises across worker processes, one per
       core, so a per-request thread pool would only oversubscribe.
       0 is the library default, set explicitly so a vendored update
       cannot change it under us. */
    params[2] = (set_param_args) {
        .ctx   = ctx,
        .param = ZSTD_c_nbWorkers,
        .value = 0,
        .name  = &workers,
    };

    for (idx = 0; idx < nparams; idx++) {
        if (ngx_http_pack_zstd_set_param(&params[idx]) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    /* Writes the size into the frame header when it is known, which
       helps the decoder allocate.

       It does more than help the decoder, and is worth keeping for
       the other reason: told the source size, zstd sizes its own
       match-finder tables to the body rather than to the window,
       which is what bounds per-request memory at a high
       pack_zstd_level.

       Which is what the else branch covers, so the two are not
       redundant and neither replaces the other: this one is exact,
       is checked at the end of the frame, and reaches the decoder
       through the frame header; that one is a guess that does none
       of those things and is all a response of unknown length can
       offer. Leaving the else empty would be safe in the sense that
       ZSTD_CONTENTSIZE_UNKNOWN is the default for a fresh context,
       and expensive in every other sense.

       content_length reaches ZSTD_CCtx_setPledgedSrcSize as it
       stands, off_t to unsigned long long, both 64-bit. Nothing may
       narrow it on the way: a body over 4 GiB passed through 32 bits
       becomes a pledge zstd then rejects at the end of the frame,
       having compressed the whole response first. */
    if (ctx->content_length >= 0) {
        rc = ngx_http_pack_zstd_set_pledged_size(ctx);
        if (rc != NGX_OK) {
            return NGX_ERROR;
        }
    } else {
        /* No length to pledge, so give the guess instead - which is
           the difference between tables sized to the body and tables
           sized to the worst case the window allows. See
           NGX_HTTP_PACK_ZSTD_SRC_SIZE_HINT for what it costs and why
           it is that number. */
        rc = ngx_http_pack_zstd_set_param(&(set_param_args) {
            .ctx   = ctx,
            .param = ZSTD_c_srcSizeHint,
            .value = NGX_HTTP_PACK_ZSTD_SRC_SIZE_HINT,
            .name  = &sizeHint,
        });

        if (rc != NGX_OK) {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}

/* Builds the encoder and the output chain's tail, once per response.
   No output buffer yet - get_buf creates those on demand, up to
   pack_zstd_nbuffers of them, and most responses never need a second.
 */
static ngx_int_t
ngx_http_pack_zstd_ensure_stream(ctx_t *const ctx)
{
    ngx_int_t rc;

    if (ctx->state.initialized) {
        return NGX_OK;
    }

    rc = ngx_http_pack_zstd_init_encoder(ctx);
    if (rc != NGX_OK) {
        return NGX_ERROR;
    }

    rc = ngx_http_pack_zstd_configure_encoder(ctx);
    if (rc != NGX_OK) {
        return NGX_ERROR;
    }

    /* Only the tail pointer has to exist before the first buffer is
       committed, and ngx_pcalloc cannot set it. */
    ctx->out_size = NGX_HTTP_PACK_ZSTD_OUT_SIZE;
    ctx->last_out = &ctx->out;

    /* Last, so that the flag means what it says. */
    ctx->state.initialized = 1;

    /* Both halves are done, which is what the line says and why it is
       here rather than at the end of either one. script/
       test_stream.py counts it to know how many encoders a slice of
       the log built. */
    ngx_log_debug0(
        NGX_LOG_DEBUG_HTTP,
        ctx->request->connection->log,
        0,
        "zstd encoder instance created and configured");

    return NGX_OK;
}

/* Hands what the encoder produced to the filters below, then takes
   account of what came back.

   A NULL ctx->out is not a no-op: it is what asks those filters to
   make progress on buffers they are already holding, which is the
   only way a busy buffer is ever returned. */
static ngx_int_t
ngx_http_pack_zstd_drain(ctx_t *const ctx)
{
    ngx_int_t rc;

    rc = ngx_http_next_body_filter(ctx->request, ctx->out);
    if (rc == NGX_ERROR) {
        return NGX_ERROR;
    }

    ngx_chain_update_chains(
        ctx->request->pool,
        &ctx->free,
        &ctx->busy,
        &ctx->out,
        (ngx_buf_tag_t) &ngx_http_pack_zstd_module);

    ctx->last_out = &ctx->out;

    /* What nginx has to be told to come back for. Buffers the filters
       below still hold count, and so does input not yet compressed:
       drop the bit while either is outstanding and a stalled last
       write can be finalized as complete, truncating the tail - on a
       socket too full to take it, which loopback tests will not
       reproduce. */
    if (ctx->busy != NULL || ctx->in != NULL) {
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
    if (ctx->state.frame_closed && ctx->busy == NULL) {
        ngx_http_pack_zstd_close(ctx);
    }

    if (ctx->busy != NULL) {
        return NGX_AGAIN;
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
    step_e step;

    for (;;) {
        do {
            step = ngx_http_pack_zstd_compress(ctx);
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
        if (!ctx->state.frame_closed && ctx->out == NULL &&
            ctx->busy == NULL) {
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
        if (ctx->free == NULL) {
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
    ngx_int_t init_status;

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

    init_status = ngx_http_pack_zstd_ensure_stream(ctx);
    if (init_status != NGX_OK) {
        ngx_http_pack_zstd_close(ctx);
        return NGX_ERROR;
    }

    return ngx_http_pack_zstd_pump(ctx);
}

/* The encoder allocates from the heap, not from the request pool. Its
   allocations vary widely in size and lifetime across the encoder's
   internal state, and ngx_pfree only reclaims "large" blocks, so
   pool-backed ones would pile up until the request ends. "opaque" is
   still the pool, but only for logging. */
static void *
ngx_http_pack_zstd_alloc(void *const opaque, size_t const size)
{
    ngx_pool_t *pool;
    ngx_log_t  *log;
    void       *p;

    pool = opaque;
    log  = pool->log;
    p    = ngx_alloc(size, log);

    ngx_log_debug2(
        NGX_LOG_DEBUG_HTTP,
        log,
        0,
        "zstd alloc: %p, size:%uz",
        p,
        size);

    return p;
}

static void
ngx_http_pack_zstd_free(void *const opaque, void *const address)
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
   compression is finished, i.e. when ngx_http_pack_zstd_close is
   never reached. */
static void
ngx_http_pack_zstd_cleanup(void *const data)
{
    zctx_t *zctx = data;
    /* Normally the encoder is already gone:
       ngx_http_pack_zstd_close resets the field.
       This is the abort path. */
    if (zctx->cctx != NULL) {
        ZSTD_freeCCtx(zctx->cctx);
        zctx->cctx = NULL;
    }
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
