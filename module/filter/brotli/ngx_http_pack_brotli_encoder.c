/*
   Copyright (C) Igor Sysoev
   Copyright (C) Nginx, Inc.
   Copyright (C) Google Inc.
   Copyright (C) 2026 Juri Torhoff
 */

#include <ngx_config.h>
#include <ngx_core.h>

#include "ngx_http_pack_brotli_encoder.h"

#include <brotli/encode.h>


/* Marks a buffer as ours on the busy list. Only the address matters -
   ngx_chain_update_chains does nothing but compare it - so the
   encoder needs to know nothing about the module it is compiled into.
 */
static ngx_int_t encoder_tag;

/* How much input a meta-block may hold, and how far flush-marked
   buffers fold into one. nginx's chunked proxy filter flushes every
   upstream chunk, which taken literally ends a meta-block per chunk,
   each carrying its own Huffman tables. Past this bound there is
   nothing left to recover, and a held block only costs latency. */
#define NGX_HTTP_PACK_BROTLI_FLUSH_AFTER (32 * 1024)

/* The header spells this out in full; inside the encoder the short
   name is the one the code was written against. */
typedef ngx_http_pack_brotli_encoder_t      encoder_t;
typedef ngx_http_pack_brotli_encoder_conf_t conf_t;
typedef ngx_http_pack_brotli_step_e         step_e;


/* What the encoder has settled for itself: fed, holding, done. A
   struct of its own so the bitfields share one storage unit. */
typedef struct {
    /* 1 once a buffer marked last_buf has been handed to Brotli.
       Never cleared: input cannot resume. Read to choose FINISH over
       FLUSH when nothing new is arriving, and to know the stream may
       be closed once Brotli says it is finished. */
    unsigned end_of_input: 1;

    /* 1 once BROTLI_OPERATION_FINISH has completed and Brotli reports
       the stream finished. */
    unsigned stream_closed: 1;
} encoder_state_t;


/* Everything the encoder owns on this response's behalf. Nothing
   copies this struct, and nothing may: "last_out" points at this
   struct's own "out", so a copy would keep appending to the
   original's chain while reporting the copy's. */
struct ngx_http_pack_brotli_encoder_s {
    /* The request, for its pool and its log. */
    ngx_http_request_t *request;

    /* What the directives settled; see the header. */
    conf_t conf;

    /* Brotli's own instance, and the only part the pool cleanup is
       handed. */
    BrotliEncoderState *brotli;

    /* Output buffers, in the three states nginx's chain helpers keep
       them in: filled this call, handed on and not yet consumed, come
       back and free to refill. ngx_chain_update_chains moves links
       between them as the filters below drain, which is what lets a
       response have more than one buffer in flight. */
    ngx_chain_t  *out;
    ngx_chain_t **last_out;
    ngx_chain_t  *busy;
    ngx_chain_t  *free;

    /* How many buffers exist so far, against conf.nbuffers. Created
       on demand, so a response that never needs a second never pays
       for it. */
    ngx_uint_t nbuffers;

    /* Input taken under BROTLI_OPERATION_PROCESS since the last
       meta-block ended, a folded flush included. Reset when a flush
       or the stream completes, since that starts the next block. A
       count rather than a flag: folding has to know how much room is
       left in the block, not merely whether anything is in it. */
    size_t unflushed_bytes;

    /* Fed, holding, done; see encoder_state_t. */
    encoder_state_t state;
};


/* The encoder allocates from the heap, not from the request pool.
   Brotli makes frequent short-lived sub-page allocations (e.g. one
   per meta-block), and ngx_pfree only reclaims "large" blocks, so
   pool-backed ones would pile up until the request ends. "opaque" is
   still the pool, but only for logging. */
static void *
ngx_http_pack_brotli_alloc(void *const opaque, size_t const size)
{
    ngx_pool_t *pool = opaque;
    void       *p;

    p = ngx_alloc(size, pool->log);

    ngx_log_debug2(
        NGX_LOG_DEBUG_HTTP,
        pool->log,
        0,
        "brotli alloc: %p, size: %uz",
        p,
        size);

    return p;
}


static void
ngx_http_pack_brotli_free(void *const opaque, void *const address)
{
#if (NGX_DEBUG)
    ngx_pool_t *pool = opaque;

    ngx_log_debug1(
        NGX_LOG_DEBUG_HTTP, pool->log, 0, "brotli free: %p", address);
#endif

    ngx_free(address);
}


/* Releases Brotli's allocations if the request is terminated before
   compression finishes, i.e. when close() is never reached. */
static void
ngx_http_pack_brotli_cleanup(void *const data)
{
    encoder_t *enc = data;

    /* Normally the encoder is already gone: close() resets the
       field. This is the abort path. */
    if (enc->brotli != NULL) {
        BrotliEncoderDestroyInstance(enc->brotli);
        enc->brotli = NULL;
    }
}


typedef struct {
    encoder_t *enc;
} get_buf_args;

typedef struct {
    /* Set only when status is NGX_OK. */
    ngx_buf_t *buf;
    ngx_int_t  status;
} get_buf_result;

/* Hands back a buffer to compress into. NGX_DECLINED is not a
   failure: every buffer this response is allowed is already in
   flight, so the encoder has to wait for one to come back, which is
   what the loop turns into a send. */
static get_buf_result
ngx_http_pack_brotli_get_buf(get_buf_args *const args)
{
    encoder_t          *enc;
    ngx_http_request_t *r;
    ngx_chain_t        *link;
    ngx_buf_t          *buf;

    enc = args->enc;
    r   = enc->request;

    if (enc->free != NULL) {
        link      = enc->free;
        buf       = link->buf;
        enc->free = link->next;

        ngx_free_chain(r->pool, link);

        /* ngx_chain_update_chains has already rewound pos and last to
           start; the flags are this filter's to set per round. */
        return (get_buf_result) {
            .buf    = buf,
            .status = NGX_OK,
        };
    }

    if (enc->nbuffers >= (ngx_uint_t) enc->conf.nbuffers) {
        return (get_buf_result) {
            .status = NGX_DECLINED,
        };
    }

    buf = ngx_create_temp_buf(r->pool, enc->conf.buffer_size);
    if (buf == NULL) {
        return (get_buf_result) {
            .status = NGX_ERROR,
        };
    }

    /* The tag lets ngx_chain_update_chains tell our buffers apart on
       the busy list. "recycled" is load-bearing: without it the write
       filter holds a block shorter than postpone_output while the
       encoder waits for that same buffer, and the response
       deadlocks. Only script/test-small-buffer.sh still reaches it.
     */
    buf->tag      = (ngx_buf_tag_t) &encoder_tag;
    buf->recycled = 1;

    enc->nbuffers++;

    ngx_log_debug2(
        NGX_LOG_DEBUG_HTTP,
        r->connection->log,
        0,
        "brotli buffer created: %p, total: %ui",
        buf,
        enc->nbuffers);

    return (get_buf_result) {
        .buf    = buf,
        .status = NGX_OK,
    };
}


typedef struct {
    encoder_t *enc;
    ngx_buf_t *buf;
    size_t     written;

    /* 1 when this buffer ends a meta-block the filters below should
       push out rather than hold for more. */
    ngx_uint_t flush;
} commit_buf_args;

typedef struct {
    ngx_int_t status;
} commit_buf_result;

/* Hands the round's output buffer to enc->out. Reached even when
   nothing was written: the last_buf marker still has to land on some
   buffer or nginx never learns the response ended. An empty one must
   claim no memory either - ngx_http_write_filter rejects a zero-size
   non-special buffer and truncates. */
static commit_buf_result
ngx_http_pack_brotli_commit_buf(commit_buf_args *const args)
{
    ngx_buf_t   *buf;
    ngx_chain_t *link;

    buf = args->buf;

    buf->pos       = (buf->start);
    buf->last      = (buf->start + args->written);
    buf->temporary = (args->written > 0);
    buf->sync      = (args->written == 0);
    buf->flush     = (args->flush);
    buf->last_buf  = (args->enc->state.stream_closed);

    link = ngx_alloc_chain_link(args->enc->request->pool);
    if (link == NULL) {
        return (commit_buf_result) {
            .status = NGX_ERROR,
        };
    }

    link->buf            = buf;
    link->next           = NULL;
    *args->enc->last_out = link;
    args->enc->last_out  = &link->next;

    ngx_log_debug2(
        NGX_LOG_DEBUG_HTTP,
        args->enc->request->connection->log,
        0,
        "brotli out: %p, size: %O",
        buf,
        ngx_buf_size(buf));

    return (commit_buf_result) {
        .status = NGX_OK,
    };
}


typedef struct {
    encoder_t *enc;
    ngx_buf_t *buf;
} release_buf_args;

typedef struct {
    ngx_int_t status;
} release_buf_result;

/* Puts an unused buffer back where get_buf will find it again. */
static release_buf_result
ngx_http_pack_brotli_release_buf(release_buf_args *const args)
{
    encoder_t   *enc;
    ngx_chain_t *link;

    enc  = args->enc;
    link = ngx_alloc_chain_link(enc->request->pool);
    if (link == NULL) {
        return (release_buf_result) {
            .status = NGX_ERROR,
        };
    }

    link->buf  = args->buf;
    link->next = enc->free;
    enc->free  = link;

    return (release_buf_result) {
        .status = NGX_OK,
    };
}


typedef struct {
    encoder_t   *enc;
    ngx_chain_t *chain;
} discard_head_buf_args;

typedef struct {
    /* The chain with its head taken off. */
    ngx_chain_t *chain;
} discard_head_buf_result;

/* Takes the head buffer off the *input* chain, there being no further
   reason to hold it: either it never carried anything to compress, or
   the encoder has taken every byte it had. The link goes back to the
   pool's own free list, which keeps a long response's chain links a
   fixed cost instead of one allocation per buffer. */
static discard_head_buf_result
ngx_http_pack_brotli_discard_head_buf(
    discard_head_buf_args *const args)
{
    ngx_chain_t *link;
    ngx_chain_t *rest;

    link = args->chain;
    rest = link->next;

    ngx_free_chain(args->enc->request->pool, link);

    return (discard_head_buf_result) {
        .chain = rest,
    };
}


typedef struct {
    /* The chain after the flush-marked buffer being decided on. */
    ngx_chain_t *rest;

    /* What the block being built already holds. */
    size_t unflushed;
} may_fold_flush_args;

typedef struct {
    ngx_uint_t folded;
} may_fold_flush_result;

/* Whether the flush at the head of the chain may be folded into the
   meta-block being built rather than ending one here. Safe only
   because a later buffer already flushes or ends the stream: a flush
   deferred past the input in hand would leave bytes inside Brotli
   with nothing scheduled to push them out. */
static may_fold_flush_result
ngx_http_pack_brotli_may_fold_flush(may_fold_flush_args *const args)
{
    size_t       budget;
    ngx_chain_t *link;

    /* The block already holds what it should; let this flush end it.
     */
    if (args->unflushed >= NGX_HTTP_PACK_BROTLI_FLUSH_AFTER) {
        return (may_fold_flush_result) {
            .folded = 0,
        };
    }

    budget = NGX_HTTP_PACK_BROTLI_FLUSH_AFTER - args->unflushed;

    /* Look ahead for the flush or the end that will push these bytes
       out, no further than the room left in the block: the fold stops
       there whatever is found, and that is what keeps this scan short
       when the buffers are small. */
    for (link = args->rest; link != NULL; link = link->next) {
        size_t size;

        if (link->buf->flush || link->buf->last_buf) {
            return (may_fold_flush_result) {
                .folded = 1,
            };
        }

        size = (size_t) ngx_buf_size(link->buf);
        if (size >= budget) {
            break;
        }

        budget -= size;
    }

    /* Couldn't find any, so this flush ends a block here. */
    return (may_fold_flush_result) {
        .folded = 0,
    };
}


typedef struct {
    encoder_t    *enc;
    ngx_chain_t **in;
    ngx_uint_t    wants_output;
} select_mode_args;

typedef struct {
    BrotliEncoderOperation operation;

    /* The buffer the input comes from, or NULL for a round that
       carries none. */
    ngx_buf_t *from;

    /* 1 when there is nothing for this round to do at all. */
    ngx_uint_t idle;
} select_mode_result;

/* Which Brotli operation this round runs, and where its input comes
   from. Split out because the answer depends on three things at once
   - whether input is waiting, whether it has ended, and whether the
   caller asked for output - and reads badly inline. */
static select_mode_result
ngx_http_pack_brotli_select_mode(select_mode_args *const args)
{
    encoder_t *enc = args->enc;
    ngx_buf_t *head;

    /* Nothing may be fed while Brotli is still holding output.
       BrotliEncoderCompressStream refuses any call carrying input
       unless the stream is back in PROCESSING, and a flush that has
       not drained sits in FLUSH_REQUESTED until its output is taken.
       So drain first, with no input, which is always accepted. The
       zstd encoder's repeat_mode answers the same problem. */
    if (BrotliEncoderHasMoreOutput(enc->brotli)) {
        return (select_mode_result) {
            .operation = enc->state.end_of_input
                             ? BROTLI_OPERATION_FINISH
                             : BROTLI_OPERATION_PROCESS,
        };
    }

    if (*args->in != NULL && !enc->state.end_of_input) {
        head = (*args->in)->buf;

        if (head->last_buf) {
            return (select_mode_result) {
                .operation = BROTLI_OPERATION_FINISH,
                .from      = head,
            };
        }

        if (head->flush) {
            /* Fold it into the block being built when something
               later will push these bytes out anyway. Left alone,
               every chunk of a chunked upstream ends a meta-block of
               its own, and each of those carries its own Huffman
               tables. */
            if (ngx_http_pack_brotli_may_fold_flush(
                    &(may_fold_flush_args) {
                        .rest      = (*args->in)->next,
                        .unflushed = enc->unflushed_bytes,
                    })
                    .folded) {

                /* Logged because nothing in the output says it
                   happened: Brotli states no block structure a test
                   can read back, where zstd's frame header carries a
                   block count. Debug only, so a release build pays
                   nothing for it. */
                ngx_log_debug1(
                    NGX_LOG_DEBUG_HTTP,
                    enc->request->connection->log,
                    0,
                    "brotli flush folded, block holds: %uz",
                    enc->unflushed_bytes);

                return (select_mode_result) {
                    .operation = BROTLI_OPERATION_PROCESS,
                    .from      = head,
                };
            }

            return (select_mode_result) {
                .operation = BROTLI_OPERATION_FLUSH,
                .from      = head,
            };
        }

        return (select_mode_result) {
            .operation = BROTLI_OPERATION_PROCESS,
            .from      = head,
        };
    }

    /* No input left to give. The stream still has to be closed if it
       has ended, and a part-filled block still has to be released if
       the caller is waiting on output. */
    if (enc->state.end_of_input) {
        return (select_mode_result) {
            .operation = BROTLI_OPERATION_FINISH,
        };
    }

    if (args->wants_output && enc->unflushed_bytes > 0) {
        return (select_mode_result) {
            .operation = BROTLI_OPERATION_FLUSH,
        };
    }

    return (select_mode_result) {
        .idle = 1,
    };
}


typedef struct {
    encoder_t             *enc;
    ngx_chain_t          **in;
    ngx_buf_t             *from;
    BrotliEncoderOperation operation;
    size_t                 consumed;
    size_t                 input_size;
} advance_input_args;

/* Takes account of what Brotli consumed: how far into the head buffer
   it got, whether that ended the input, and whether anything is left
   sitting in a part-filled block. */
static void
ngx_http_pack_brotli_advance_input(advance_input_args *const args)
{
    encoder_t *enc = args->enc;

    /* A round with no input of its own settles only the block: FLUSH
       and FINISH both empty it, PROCESS cannot have added to it. */
    if (args->from == NULL) {
        if (args->operation != BROTLI_OPERATION_PROCESS) {
            enc->unflushed_bytes = 0;
        }
        return;
    }

    args->from->pos += args->consumed;

    if (args->operation == BROTLI_OPERATION_PROCESS) {
        /* Adds to the block being built, a folded flush included -
           folding is what turns one of those into a process. */
        enc->unflushed_bytes += args->consumed;
    } else {
        /* A flush or a finish ends the block, so the next one starts
           empty. */
        enc->unflushed_bytes = 0;
    }

    if (args->consumed != args->input_size) {
        /* Partially consumed: the rest goes in next time round. */
        return;
    }

    if (args->from->last_buf) {
        enc->state.end_of_input = 1;
    }

    *args->in = ngx_http_pack_brotli_discard_head_buf(
                    &(discard_head_buf_args) {
                        .enc   = enc,
                        .chain = *args->in,
                    })
                    .chain;
}


typedef struct {
    encoder_t *enc;
    ngx_buf_t *buf;
    size_t     written;
    ngx_uint_t flush;
} deliver_buf_args;

/* Sends the round's buffer on, or puts it back. It is worth sending
   when it holds bytes, when it carries a flush the filters below are
   waiting for, or when it is the one that has to carry last_buf -
   and in that last case only, worth sending empty. */
static ngx_int_t
ngx_http_pack_brotli_deliver_buf(deliver_buf_args *const args)
{
    if (args->written > 0 || args->flush ||
        args->enc->state.stream_closed) {

        return ngx_http_pack_brotli_commit_buf(
                   &(commit_buf_args) {
                       .enc     = args->enc,
                       .buf     = args->buf,
                       .written = args->written,
                       .flush   = args->flush,
                   })
            .status;
    }

    return ngx_http_pack_brotli_release_buf(&(release_buf_args) {
                                                .enc = args->enc,
                                                .buf = args->buf,
                                            })
        .status;
}


encoder_t *
ngx_http_pack_brotli_encoder_create(
    ngx_http_request_t *const r, conf_t *const conf)
{
    encoder_t          *enc;
    ngx_pool_cleanup_t *cln;
    BROTLI_BOOL         ok;

    enc = ngx_pcalloc(r->pool, sizeof(*enc));
    if (enc == NULL) {
        return NULL;
    }

    enc->request  = r;
    enc->conf     = *conf;
    enc->last_out = &enc->out;

    /* Brotli's memory is not owned by the pool, so arrange for it to
       be released even if the request is aborted mid-stream.
       Registered before the encoder exists, so that a failure here
       cannot strand an allocated instance. */
    cln = ngx_pool_cleanup_add(r->pool, 0);
    if (cln == NULL) {
        return NULL;
    }

    cln->handler = ngx_http_pack_brotli_cleanup;
    cln->data    = enc;

    enc->brotli = BrotliEncoderCreateInstance(
        ngx_http_pack_brotli_alloc,
        ngx_http_pack_brotli_free,
        r->pool);
    if (enc->brotli == NULL) {
        ngx_log_error(
            NGX_LOG_ALERT,
            r->connection->log,
            0,
            "BrotliEncoderCreateInstance() failed");
        return NULL;
    }

    ok = BrotliEncoderSetParameter(
        enc->brotli, BROTLI_PARAM_QUALITY, (uint32_t) conf->quality);
    if (!ok) {
        ngx_log_error(
            NGX_LOG_ALERT,
            r->connection->log,
            0,
            "BrotliEncoderSetParameter(QUALITY, %uD) failed",
            (uint32_t) conf->quality);
        return NULL;
    }

    ok = BrotliEncoderSetParameter(
        enc->brotli,
        BROTLI_PARAM_LGWIN,
        (uint32_t) conf->window_bits);
    if (!ok) {
        ngx_log_error(
            NGX_LOG_ALERT,
            r->connection->log,
            0,
            "BrotliEncoderSetParameter(LGWIN, %uD) failed",
            (uint32_t) conf->window_bits);
        return NULL;
    }

    ngx_log_debug2(
        NGX_LOG_DEBUG_HTTP,
        r->connection->log,
        0,
        "brotli encoder instance created and configured: "
        "quality: %i, window: %uz",
        conf->quality,
        (size_t) 1 << conf->window_bits);

    return enc;
}


step_e
ngx_http_pack_brotli_encoder_step(
    encoder_t *const    enc,
    ngx_chain_t **const in,
    ngx_uint_t const    wants_output)
{
    get_buf_result     got;
    select_mode_result mode;
    ngx_buf_t         *buf;
    size_t             available_in;
    size_t             available_out;
    size_t             input_size;
    size_t             consumed;
    size_t             written;
    uint8_t const     *next_in;
    uint8_t           *next_out;
    BROTLI_BOOL        ok;
    ngx_uint_t         flush_done;
    step_e             step;

    mode = ngx_http_pack_brotli_select_mode(&(select_mode_args) {
        .enc          = enc,
        .in           = in,
        .wants_output = wants_output,
    });

    if (mode.idle) {
        return NGX_HTTP_PACK_BROTLI_STEP_DONE;
    }

    /* An empty buffer carries nothing to compress, but one marked
       last or flush still has to reach Brotli to close the stream or
       the block. Anything else is dropped without a round. */
    if (mode.from != NULL && ngx_buf_size(mode.from) == 0 &&
        !mode.from->last_buf && !mode.from->flush) {
        *in = ngx_http_pack_brotli_discard_head_buf(
                  &(discard_head_buf_args) {
                      .enc   = enc,
                      .chain = *in,
                  })
                  .chain;
        return NGX_HTTP_PACK_BROTLI_STEP_CONTINUE;
    }

    got = ngx_http_pack_brotli_get_buf(&(get_buf_args) {
        .enc = enc,
    });

    if (got.status == NGX_DECLINED) {
        /* Every buffer is downstream; the loop turns this into a
           send, and comes back when one is returned. */
        return NGX_HTTP_PACK_BROTLI_STEP_AGAIN;
    }

    if (got.status != NGX_OK) {
        return NGX_HTTP_PACK_BROTLI_STEP_FAILED;
    }

    buf = got.buf;

    input_size   = mode.from != NULL ? ngx_buf_size(mode.from) : 0;
    available_in = input_size;
    next_in = mode.from != NULL ? (uint8_t const *) mode.from->pos
                                : NULL;
    available_out = enc->conf.buffer_size;
    next_out      = buf->start;

    /* Brotli writes straight into our buffer rather than storage of
       its own, which BrotliEncoderTakeOutput would hand back instead.
       Taking that would pin the encoder until the filters below
       released the memory: one buffer in flight at most, and a
       deadlock below postpone_output. */
    ok = BrotliEncoderCompressStream(
        enc->brotli,
        mode.operation,
        &available_in,
        mode.from != NULL ? &next_in : NULL,
        &available_out,
        &next_out,
        NULL);

    if (!ok) {
        ngx_http_pack_brotli_release_buf(&(release_buf_args) {
            .enc = enc,
            .buf = buf,
        });
        return NGX_HTTP_PACK_BROTLI_STEP_FAILED;
    }

    written  = enc->conf.buffer_size - available_out;
    consumed = input_size - available_in;

    ngx_http_pack_brotli_advance_input(&(advance_input_args) {
        .enc        = enc,
        .in         = in,
        .from       = mode.from,
        .operation  = mode.operation,
        .consumed   = consumed,
        .input_size = input_size,
    });

    if (enc->state.end_of_input &&
        BrotliEncoderIsFinished(enc->brotli)) {
        enc->state.stream_closed = 1;
    }

    /* A flush has landed once Brotli is holding nothing back. Only
       then may the buffer carry the marker, or the filters below push
       out half a meta-block and wait for the rest. */
    flush_done = (mode.operation == BROTLI_OPERATION_FLUSH) &&
                 !BrotliEncoderHasMoreOutput(enc->brotli) &&
                 !enc->state.stream_closed;

    if (ngx_http_pack_brotli_deliver_buf(&(deliver_buf_args) {
            .enc     = enc,
            .buf     = buf,
            .written = written,
            .flush   = flush_done,
        }) != NGX_OK) {
        return NGX_HTTP_PACK_BROTLI_STEP_FAILED;
    }

    if (enc->state.stream_closed) {
        step = NGX_HTTP_PACK_BROTLI_STEP_DONE;

    } else if (written > 0 || consumed > 0) {
        step = NGX_HTTP_PACK_BROTLI_STEP_CONTINUE;

    } else if (mode.operation == BROTLI_OPERATION_FINISH) {
        /* Nothing moved. A finish that cannot finish would spin here,
           so it is reported rather than retried. */
        step = NGX_HTTP_PACK_BROTLI_STEP_FAILED;

    } else {
        /* Nothing moved either, but an encoder with no work left
           until it is fed again rather than one that is stuck. */
        step = NGX_HTTP_PACK_BROTLI_STEP_DONE;
    }

    /* One line per round, which is what makes the loop's own
       invariant checkable from outside: a round answering CONTINUE
       has to have moved something, or the next round repeats it. The
       suite asserts exactly that. */
    ngx_log_debug3(
        NGX_LOG_DEBUG_HTTP,
        enc->request->connection->log,
        0,
        "brotli round: consumed: %uz, written: %uz, step: %d",
        consumed,
        written,
        (int32_t) step);

    return step;
}


ngx_chain_t *
ngx_http_pack_brotli_encoder_pending(encoder_t *const enc)
{
    return enc->out;
}


void
ngx_http_pack_brotli_encoder_drained(encoder_t *const enc)
{
    ngx_chain_update_chains(
        enc->request->pool,
        &enc->free,
        &enc->busy,
        &enc->out,
        (ngx_buf_tag_t) &encoder_tag);

    enc->last_out = &enc->out;
}


ngx_uint_t
ngx_http_pack_brotli_encoder_busy(encoder_t *const enc)
{
    return enc->busy != NULL;
}


ngx_uint_t
ngx_http_pack_brotli_encoder_has_free(encoder_t *const enc)
{
    return enc->free != NULL;
}


ngx_uint_t
ngx_http_pack_brotli_encoder_stream_closed(encoder_t *const enc)
{
    return enc->state.stream_closed;
}


void
ngx_http_pack_brotli_encoder_close(encoder_t *const enc)
{
    if (enc->brotli != NULL) {
        BrotliEncoderDestroyInstance(enc->brotli);
        enc->brotli = NULL;
    }

    /* The buffers are pool memory and the links are the pool's own,
       so there is nothing to hand back that outlives the request.
       Dropping the chains is the whole of the cleanup; anything the
       filters below still hold points at pool memory they copied the
       links for. */
    enc->out      = NULL;
    enc->last_out = &enc->out;
    enc->busy     = NULL;
    enc->free     = NULL;
}
