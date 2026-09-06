/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) Google Inc.
 * Copyright (C) 2026 Juri Torhoff
 */

#include <ngx_config.h>
#include <ngx_core.h>

#include "ngx_http_pack_zstd_encoder.h"

/* Needed for ZSTD_createCCtx_advanced (the custom allocator) and
   ZSTD_c_srcSizeHint. */
#define ZSTD_STATIC_LINKING_ONLY
#include <zstd.h>


/* Marks a buffer as ours on the busy list. Only the address matters -
   ngx_chain_update_chains does nothing but compare it - so the
   encoder needs to know nothing about the module it is compiled into.
 */
static ngx_int_t encoder_tag;

/* The header spells this out in full; inside the encoder the short
   name is the one the code was written against. */
typedef ngx_http_pack_zstd_step_e         step_e;
typedef ngx_http_pack_zstd_encoder_t      encoder_t;
typedef ngx_http_pack_zstd_encoder_conf_t conf_t;

static void *ngx_http_pack_zstd_alloc(void *opaque, size_t size);
static void ngx_http_pack_zstd_free(void *opaque, void *address);
static void ngx_http_pack_zstd_cleanup(void *data);


/* How much input a block may hold - how far ZSTD_e_continue runs, and
   how far flush-marked buffers fold into one. Left alone a block ends
   only when it fills, and nothing asks the filter to do better:
   ngx_event_pipe passes a NULL chain only once its own buffers reach
   proxy_busy_buffers_size, which this filter never causes. */
#define NGX_HTTP_PACK_ZSTD_FLUSH_AFTER (32 * 1024)

/* What libzstd owns on this response's behalf. A struct of its own so
   the pool cleanup that frees the encoder on an aborted request can
   be handed exactly this much and no more - not the context, so
   nothing in the handler can reach a request that may already be
   gone. */
typedef struct {
    /* zstd compression context instance. */
    ZSTD_CCtx *cctx;

    /* The directive a round with no input left has to repeat, or
       ZSTD_e_continue for "nothing owed". A flush or an end returning
       nonzero must be called again until it returns 0, or the bytes
       it owes downstream stay stuck inside the encoder.
       ZSTD_e_continue is 0, so ngx_pcalloc starts this right. */
    ZSTD_EndDirective repeat_mode;
} zctx_t;

/* What the encoder has settled for itself: built, holding, done. A
   struct of its own so the bitfields share one storage unit. */
typedef struct {
    /* 1 if the encoder may still be holding input handed to it under
       ZSTD_e_continue. zstd gives no query for "is anything
       buffered", so this tracks it. */
    unsigned unflushed_input: 1;

    /* 1 once ZSTD_compressStream2(..., ZSTD_e_end) has reported
       "fully flushed" (a return of 0). */
    unsigned frame_closed: 1;
} encoder_state_t;

/* Everything the encoder owns on this response's behalf. Nothing
   copies this struct, and nothing may: "last_out" points at this
   struct's own "out", so a copy would keep appending to the
   original's chain while reporting the copy's. */
struct ngx_http_pack_zstd_encoder_s {
    /* The request, for its pool and its log. */
    ngx_http_request_t *request;

    /* What the directives settled; see the header. */
    conf_t conf;

    /* libzstd's own, and the only part the pool cleanup is handed. */
    zctx_t zstd;

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

    /* Input taken under ZSTD_e_continue since the last block ended -
       a folded flush included, that being a continue too. Reset when
       a flush or the frame completes, since that starts the next
       block. Bounds both the fold and the flush the filter makes on
       its own; see NGX_HTTP_PACK_ZSTD_FLUSH_AFTER. */
    size_t unflushed_bytes;

    /* Built, holding, done; see encoder_state_t. */
    encoder_state_t state;
};

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
ngx_http_pack_zstd_get_buf(get_buf_args *const args)
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

    /* The tag is what lets ngx_chain_update_chains tell our buffers
       apart on the busy list and hand them back. "recycled" tells the
       filters below this memory is reused, so they must not sit on
       it. */
    buf->tag      = (ngx_buf_tag_t) &encoder_tag;
    buf->recycled = 1;

    enc->nbuffers++;

    ngx_log_debug2(
        NGX_LOG_DEBUG_HTTP,
        r->connection->log,
        0,
        "zstd buffer created: %p, total: %ui",
        buf,
        enc->nbuffers);

    return (get_buf_result) {
        .buf    = buf,
        .status = NGX_OK,
    };
}

typedef struct {
    encoder_t        *enc;
    ngx_buf_t        *buf;
    size_t            written;
    ZSTD_EndDirective mode;
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
    buf->last_buf  = (args->enc->state.frame_closed);

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
        "zstd out: %p, size: %O",
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
ngx_http_pack_zstd_release_buf(release_buf_args *const args)
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
ngx_http_pack_zstd_discard_head_buf(discard_head_buf_args *const args)
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
    ngx_chain_t *rest;
    /* What the block being built already holds. */
    size_t unflushed;
} may_fold_flush_args;

typedef struct {
    ngx_uint_t folded;
} may_fold_flush_result;

/* Whether the flush at the head of the chain may be folded into the
   block being built rather than cutting one here. Safe only because a
   later buffer already flushes or ends the stream: a flush deferred
   past the input in hand would leave bytes in the encoder with
   nothing scheduled to push them out. */
static may_fold_flush_result
ngx_http_pack_zstd_may_fold_flush(may_fold_flush_args *const args)
{
    size_t       budget;
    ngx_chain_t *link;

    /* The block already holds what it should; let this flush end it.
     */
    if (args->unflushed >= NGX_HTTP_PACK_ZSTD_FLUSH_AFTER) {
        return (may_fold_flush_result) {
            .folded = 0,
        };
    }

    budget = NGX_HTTP_PACK_ZSTD_FLUSH_AFTER - args->unflushed;

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

    /* Couldn't find any, so this flush cuts a block here. */
    return (may_fold_flush_result) {
        .folded = 0,
    };
}

typedef struct {
    encoder_t   *enc;
    ngx_chain_t *in;
} select_mode_args;

typedef struct {
    ZSTD_EndDirective mode;
} select_mode_result;

/* Which directive the head buffer calls for, and whether its flush is
   folded into the block being built. Both answers come from what the
   block already holds, which record_round counts only once the
   encoder has taken the bytes - so a round that gives up early spends
   none of the allowance. */
static select_mode_result
ngx_http_pack_zstd_select_mode(select_mode_args *const args)
{
    ngx_buf_t *buffer;

    buffer = args->in->buf;

    if (buffer->last_buf) {
        return (select_mode_result) {
            .mode = ZSTD_e_end,
        };
    }

    if (!buffer->flush) {
        /* Nothing is asking for this block to end, so zstd would
           carry on until one fills. End it here once enough has gone
           in - see NGX_HTTP_PACK_ZSTD_FLUSH_AFTER for why waiting is
           not free. */
        if (args->enc->unflushed_bytes >=
            NGX_HTTP_PACK_ZSTD_FLUSH_AFTER) {

            return (select_mode_result) {
                .mode = ZSTD_e_flush,
            };
        }

        return (select_mode_result) {
            .mode = ZSTD_e_continue,
        };
    }

    if (ngx_http_pack_zstd_may_fold_flush(
            &(may_fold_flush_args) {
                .rest      = args->in->next,
                .unflushed = args->enc->unflushed_bytes,
            })
            .folded) {

        return (select_mode_result) {
            .mode = ZSTD_e_continue,
        };
    }

    return (select_mode_result) {
        .mode = ZSTD_e_flush,
    };
}

typedef struct {
    encoder_t *enc;
    /* The caller's input chain. What is left of it comes back in
       next_input_result. */
    ngx_chain_t *chain;
    /* Whether this call brought no new data; see the header. */
    ngx_uint_t wants_output;
} next_input_args;

/* "step" is the verdict and the only field always meaningful. Read it
   first: it is a step_e where "mode" is a ZSTD_EndDirective, and the
   two would compare equal against a wrong constant without a word
   from the compiler. */
typedef struct {
    step_e            step;
    ZSTD_EndDirective mode;
    ZSTD_inBuffer     in;
    /* What is left of the caller's chain. Always set, including on
       the paths that settle the round without running the encoder -
       one of those drops a buffer. */
    ngx_chain_t *chain;
} next_input_result;

/* Settles what the encoder is asked to do this round and what it runs
   on. STEP_READY means carry on into the encoder; anything else is a
   round that is over before it starts, and is the step the caller
   returns. */
static next_input_result
ngx_http_pack_zstd_next_input(next_input_args *const args)
{
    encoder_t              *enc;
    ngx_http_request_t     *r;
    ngx_buf_t              *buf;
    discard_head_buf_result dropped;
    select_mode_result      selected;
    ZSTD_inBuffer           window;

    enc = args->enc;
    r   = enc->request;

    if (args->chain == NULL) {
        ZSTD_EndDirective mode;

        if (enc->zstd.repeat_mode != ZSTD_e_continue) {
            /* Finishing what was started takes priority over asking
               whether the caller wants output - see repeat_mode. */
            mode = enc->zstd.repeat_mode;
        } else if (args->wants_output && enc->state.unflushed_input) {
            mode = ZSTD_e_flush;
        } else {
            /* Nothing to do; wait for more input. */
            return (next_input_result) {
                .step  = NGX_HTTP_PACK_ZSTD_STEP_DONE,
                .chain = args->chain,
            };
        }

        /* No input of its own: the round is the directive alone. */
        return (next_input_result) {
            .step  = NGX_HTTP_PACK_ZSTD_STEP_READY,
            .mode  = mode,
            .chain = args->chain,
        };
    }

    buf = args->chain->buf;

    /* The length has to come from the same place as the source
       pointer: ngx_buf_size() reports the file range for a
       file-backed buffer, which paired with buf->pos describes
       nothing. One with no memory at all should never arrive - the
       header filter sets main_filter_need_in_memory. */
    if (buf->in_file && !ngx_buf_in_memory(buf)) {
        ngx_log_error(
            NGX_LOG_ALERT,
            r->connection->log,
            0,
            "zstd got a buffer with file bytes and none in memory");

        return (next_input_result) {
            .step  = NGX_HTTP_PACK_ZSTD_STEP_FAILED,
            .chain = args->chain,
        };
    }

    /* An empty buffer carries nothing to compress, but one marked
       last or flush still has to reach the encoder to close the
       stream or the block. Anything else is dropped. */
    if (ngx_buf_size(buf) == 0 && !buf->last_buf && !buf->flush) {
        dropped = ngx_http_pack_zstd_discard_head_buf(
            &(discard_head_buf_args) {
                .enc   = enc,
                .chain = args->chain,
            });

        return (next_input_result) {
            .step  = NGX_HTTP_PACK_ZSTD_STEP_CONTINUE,
            .chain = dropped.chain,
        };
    }

    selected = ngx_http_pack_zstd_select_mode(&(select_mode_args) {
        .enc = enc,
        .in  = args->chain,
    });

    window.src = buf->pos;
    /* "last > pos" as well as the in-memory test: the subtraction is
       unsigned, so an inverted buffer would become an enormous length
       and read far past the allocation. */
    if (ngx_buf_in_memory(buf) && buf->last > buf->pos) {
        window.size = (size_t) (buf->last - buf->pos);
    } else {
        window.size = 0;
    }
    window.pos = 0;

    return (next_input_result) {
        .step  = NGX_HTTP_PACK_ZSTD_STEP_READY,
        .mode  = selected.mode,
        .in    = window,
        .chain = args->chain,
    };
}

typedef struct {
    encoder_t *enc;
    size_t     consumed;
    /* The caller's input chain. What is left of it comes back in
       advance_input_result. */
    ngx_chain_t *chain;
} advance_input_args;

typedef struct {
    ngx_chain_t *chain;
} advance_input_result;

/* Records progress in the chain itself: the ZSTD_inBuffer's "pos"
   does not survive returning to nginx. That pos is the right amount
   whatever the mode - a flush or an end may also leave input partly
   unconsumed if the output buffer filled first. */
static advance_input_result
ngx_http_pack_zstd_advance_input(advance_input_args *const args)
{
    encoder_t *enc;
    ngx_buf_t *buf;

    enc = args->enc;

    if (args->chain == NULL) {
        return (advance_input_result) {
            .chain = args->chain,
        };
    }

    buf = args->chain->buf;

    /* Guarded, not for tidiness: a special buffer carries no memory,
       so pos is NULL, and advancing a null pointer by zero is
       undefined. UBSan reports it on the last_buf that
       ngx_http_send_special emits. */
    if (args->consumed > 0) {
        buf->pos += args->consumed;
    }

    if (ngx_buf_size(buf) == 0) {
        return (advance_input_result) {
            .chain = ngx_http_pack_zstd_discard_head_buf(
                         &(discard_head_buf_args) {
                             .enc   = enc,
                             .chain = args->chain,
                         })
                         .chain,
        };
    }

    return (advance_input_result) {
        .chain = args->chain,
    };
}

typedef struct {
    encoder_t        *enc;
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
            args->enc->state.unflushed_input  = 1;
            args->enc->unflushed_bytes       += args->consumed;
        }

        return;
    }

    if (args->remaining != 0) {
        /* Not finished, whichever of the two it was: repeat it once
           the input in hand has been consumed. */
        args->enc->zstd.repeat_mode = args->mode;

        return;
    }

    args->enc->zstd.repeat_mode = ZSTD_e_continue;

    /* Either directive ends the block, so the next one starts empty.
     */
    args->enc->unflushed_bytes = 0;

    if (args->mode == ZSTD_e_flush) {
        args->enc->state.unflushed_input = 0;
    } else { /* ZSTD_e_end */
        args->enc->state.frame_closed = 1;
    }
}

typedef struct {
    encoder_t        *enc;
    ZSTD_EndDirective mode;
    size_t            consumed;
    size_t            written;
    size_t            remaining;
    /* Read, never advanced. */
    ngx_chain_t *chain;
} made_progress_args;

typedef struct {
    ngx_int_t status;
} made_progress_result;

/* Whether the round moved anything, and the whole of why the loop
   above it terminates. Called before the buffer is disposed of, which
   is what lets it speak first: dispose_buf answers CONTINUE whenever
   nothing was written, so without this a round that wrote nothing
   would be repeated on identical inputs for as long as the worker
   lives.
 *
 * Three things count as movement: input taken, a byte written, or a
 * directive completed - the last because record_round then clears
 * unflushed_input or sets frame_closed, so the next round differs
 * whatever this one produced. An empty flush of an empty block is
 * that third case, and legitimate.
 *
 * An error rather than anything retryable, deliberately: retrying is
 * the very thing that spins. */
static made_progress_result
ngx_http_pack_zstd_made_progress(made_progress_args *const args)
{
    ngx_chain_t *in;
    size_t       consumed;
    size_t       written;
    size_t       remaining;
    ngx_uint_t   completed_directive;

    in        = args->chain;
    consumed  = args->consumed;
    written   = args->written;
    remaining = args->remaining;

    completed_directive = args->mode != ZSTD_e_continue &&
                          remaining == 0;

    /* Nothing taken, nothing written, nothing settled. The chain
       still holds what it held - advance_input moves it by "consumed"
       and retires it only when empty - so the next round would be
       this one again. */
    if (consumed == 0 && written == 0 && !completed_directive) {
        ngx_log_error(
            NGX_LOG_ALERT,
            args->enc->request->connection->log,
            0,
            "zstd compress moved nothing: mode: %d "
            "remaining: %uz input: %s",
            (int32_t) args->mode,
            remaining,
            in == NULL ? "none" : "waiting");

        return (made_progress_result) {
            .status = NGX_ERROR,
        };
    }

    /* Draining with the input exhausted and a directive still
       unfinished. Distinct from the above, which this does not cover:
       the round may have consumed the last of the chain and still be
       unable to finish. */
    if (in == NULL && written == 0 && remaining != 0) {
        ngx_log_error(
            NGX_LOG_ALERT,
            args->enc->request->connection->log,
            0,
            "zstd compress made no progress: mode: %d "
            "remaining: %uz",
            (int32_t) args->mode,
            remaining);

        return (made_progress_result) {
            .status = NGX_ERROR,
        };
    }

    return (made_progress_result) {
        .status = NGX_OK,
    };
}

typedef struct {
    encoder_t        *enc;
    ngx_buf_t        *buf;
    ZSTD_EndDirective mode;
    /* By value: the encoder advances its own copy, and "consumed"
       below is the only part of that the caller wants back. */
    ZSTD_inBuffer in;
} compress_buf_args;

typedef struct {
    size_t    consumed;
    size_t    written;
    size_t    remaining;
    ngx_int_t status;
} compress_buf_result;

/* Runs the encoder once, into the buffer this round drew. The
   ZSTD_outBuffer lives and dies here: nothing above needs it once the
   call returns, only how many bytes landed in it. "in" is advanced
   rather than copied, since ZSTD_compressStream2 moves its "pos" and
   the caller reads that to learn what was consumed. */
static compress_buf_result
ngx_http_pack_zstd_compress_buf(compress_buf_args *const args)
{
    encoder_t     *enc;
    ZSTD_inBuffer  in;
    ZSTD_outBuffer out;
    size_t         remaining;

    enc = args->enc;
    in  = args->in;

    out.dst  = args->buf->start;
    out.size = enc->conf.buffer_size;
    out.pos  = 0;

    remaining = ZSTD_compressStream2(
        enc->zstd.cctx, &out, &in, args->mode);
    if (ZSTD_isError(remaining)) {
        ngx_log_error(
            NGX_LOG_ALERT,
            enc->request->connection->log,
            0,
            "zstd compress failed: %s",
            ZSTD_getErrorName(remaining));

        return (compress_buf_result) {
            .status = NGX_ERROR,
        };
    }

    return (compress_buf_result) {
        .consumed  = in.pos,
        .written   = out.pos,
        .remaining = remaining,
        .status    = NGX_OK,
    };
}

typedef struct {
    encoder_t        *enc;
    ngx_buf_t        *buf;
    size_t            written;
    ZSTD_EndDirective mode;
} dispose_buf_args;

typedef struct {
    step_e step;
} dispose_buf_result;

/* What becomes of the round's output buffer: handed back to be filled
   again, or committed to enc->out. Nothing produced with the frame
   still open is the first, or the round would spend one of the
   response's few buffers on nothing. Anything else is the second,
   empty included. */
static dispose_buf_result
ngx_http_pack_zstd_dispose_buf(dispose_buf_args *const args)
{
    encoder_t *enc;
    ngx_int_t  rc;

    enc = args->enc;

    if (args->written == 0 && !enc->state.frame_closed) {
        rc = ngx_http_pack_zstd_release_buf(&(release_buf_args) {
                                                .enc = enc,
                                                .buf = args->buf,
                                            })
                 .status;

        if (rc != NGX_OK) {
            return (dispose_buf_result) {
                .step = NGX_HTTP_PACK_ZSTD_STEP_FAILED,
            };
        }

        return (dispose_buf_result) {
            .step = NGX_HTTP_PACK_ZSTD_STEP_CONTINUE,
        };
    }

    rc = ngx_http_pack_zstd_commit_buf(&(commit_buf_args) {
                                           .enc     = enc,
                                           .buf     = args->buf,
                                           .written = args->written,
                                           .mode    = args->mode,
                                       })
             .status;

    if (rc != NGX_OK) {
        return (dispose_buf_result) {
            .step = NGX_HTTP_PACK_ZSTD_STEP_FAILED,
        };
    }

    return (dispose_buf_result) {
        .step = NGX_HTTP_PACK_ZSTD_STEP_CONTINUE,
    };
}

typedef struct {
    encoder_t *enc;
    /* The caller's input chain. What is left of it comes back in
       compress_result. */
    ngx_chain_t *chain;
    /* Whether this call brought no new data; see the header. */
    ngx_uint_t wants_output;
} compress_args;

typedef struct {
    step_e step;
    /* What is left of the caller's chain, whatever the step. */
    ngx_chain_t *chain;
} compress_result;

/* Runs the encoder once and, if it produced anything, appends a
   buffer to enc->out. ZSTD_compressStream2 moves input and output in
   a single call, so there is no separate "is there output ready"
   phase. */
static compress_result
ngx_http_pack_zstd_compress(compress_args *const args)
{
    encoder_t           *enc;
    next_input_result    input;
    get_buf_result       drawn;
    compress_buf_result  zresult;
    advance_input_result advanced;
    ngx_int_t            rc;

    enc = args->enc;

    /* Tested ahead of the input: a closed frame means the response is
       over whatever is still queued, and anything after last_buf
       would be compressed into a second frame and committed with
       last_buf set again. Closing the encoder is the loop's job -
       that buffer may still be in enc->out or enc->busy. */
    if (enc->state.frame_closed) {
        return (compress_result) {
            .step  = NGX_HTTP_PACK_ZSTD_STEP_DONE,
            .chain = args->chain,
        };
    }

    input = ngx_http_pack_zstd_next_input(&(next_input_args) {
        .enc          = enc,
        .chain        = args->chain,
        .wants_output = args->wants_output,
    });

    /* "step" and not "mode": see next_input_result. */
    if (input.step != NGX_HTTP_PACK_ZSTD_STEP_READY) {
        return (compress_result) {
            .step  = input.step,
            .chain = input.chain,
        };
    }

    /* Last thing before the encoder runs: nothing above has touched
       the input or the fold count yet, so giving up here costs
       nothing and can be repeated once a buffer comes back. */
    drawn = ngx_http_pack_zstd_get_buf(&(get_buf_args) {
        .enc = enc,
    });

    if (drawn.status == NGX_ERROR) {
        return (compress_result) {
            .step  = NGX_HTTP_PACK_ZSTD_STEP_FAILED,
            .chain = input.chain,
        };
    }

    if (drawn.status == NGX_DECLINED) {
        return (compress_result) {
            .step  = NGX_HTTP_PACK_ZSTD_STEP_AGAIN,
            .chain = input.chain,
        };
    }

    zresult = ngx_http_pack_zstd_compress_buf(&(compress_buf_args) {
        .enc  = enc,
        .buf  = drawn.buf,
        .mode = input.mode,
        .in   = input.in,
    });

    if (zresult.status != NGX_OK) {
        return (compress_result) {
            .step  = NGX_HTTP_PACK_ZSTD_STEP_FAILED,
            .chain = input.chain,
        };
    }

    advanced = ngx_http_pack_zstd_advance_input(
        &(advance_input_args) {
            .enc      = enc,
            .chain    = input.chain,
            .consumed = zresult.consumed,
        });

    ngx_http_pack_zstd_record_round(&(record_round_args) {
        .enc       = enc,
        .mode      = input.mode,
        .consumed  = zresult.consumed,
        .remaining = zresult.remaining,
    });

    rc = ngx_http_pack_zstd_made_progress(
             &(made_progress_args) {
                 .chain     = advanced.chain,
                 .enc       = enc,
                 .mode      = input.mode,
                 .consumed  = zresult.consumed,
                 .written   = zresult.written,
                 .remaining = zresult.remaining,
             })
             .status;

    if (rc != NGX_OK) {
        return (compress_result) {
            .step  = NGX_HTTP_PACK_ZSTD_STEP_FAILED,
            .chain = advanced.chain,
        };
    }

    return (compress_result) {
        .chain = advanced.chain,
        .step  = ngx_http_pack_zstd_dispose_buf(
                    &(dispose_buf_args) {
                         .enc     = enc,
                         .buf     = drawn.buf,
                         .written = zresult.written,
                         .mode    = input.mode,
                    })
                    .step,
    };
}

typedef struct {
    ngx_int_t status;
} init_encoder_result;

/* Brings the encoder into existence with the request pool behind its
   allocator, and arranges for it to be released even if the request
   is aborted - the encoder's memory is not the pool's, so nothing
   else would. The cleanup is registered first so a failure there
   cannot strand an allocated instance. */
static init_encoder_result
ngx_http_pack_zstd_init_encoder(encoder_t *const enc)
{
    ngx_pool_cleanup_t *cln;
    ZSTD_customMem      zmem;

    cln = ngx_pool_cleanup_add(enc->request->pool, 0);
    if (cln == NULL) {
        return (init_encoder_result) {
            .status = NGX_ERROR,
        };
    }

    cln->handler = ngx_http_pack_zstd_cleanup;
    cln->data    = &enc->zstd;

    zmem.customAlloc = ngx_http_pack_zstd_alloc;
    zmem.customFree  = ngx_http_pack_zstd_free;
    zmem.opaque      = enc->request->pool;

    enc->zstd.cctx = ZSTD_createCCtx_advanced(zmem);
    if (enc->zstd.cctx == NULL) {
        ngx_log_error(
            NGX_LOG_ALERT,
            enc->request->connection->log,
            0,
            "zstd encoder instance creation failed: "
            "out of memory?");

        return (init_encoder_result) {
            .status = NGX_ERROR,
        };
    }

    return (init_encoder_result) {
        .status = NGX_OK,
    };
}

typedef struct {
    encoder_t       *enc;
    ZSTD_cParameter  param;
    int32_t          value;
    ngx_str_t const *name;
} set_param_args;

typedef struct {
    ngx_int_t status;
} set_param_result;

/* One ZSTD_CCtx_setParameter call with its failure handled like every
   other. "name" is the parameter as zstd.h spells it: the enum
   carries no name at runtime, and the number alone makes the log
   useless. */
static set_param_result
ngx_http_pack_zstd_set_param(set_param_args *const args)
{
    size_t zrc;

    zrc = ZSTD_CCtx_setParameter(
        args->enc->zstd.cctx, args->param, args->value);
    if (ZSTD_isError(zrc)) {
        ngx_log_error(
            NGX_LOG_ALERT,
            args->enc->request->connection->log,
            0,
            "zstd error while trying to set %V=%D: %s",
            args->name,
            args->value,
            ZSTD_getErrorName(zrc));

        return (set_param_result) {
            .status = NGX_ERROR,
        };
    }

    return (set_param_result) {
        .status = NGX_OK,
    };
}

typedef struct {
    encoder_t *enc;
    uint64_t   size;
} set_pledged_size_args;

typedef struct {
    ngx_int_t status;
} set_pledged_size_result;

static set_pledged_size_result
ngx_http_pack_zstd_set_pledged_size(set_pledged_size_args *const args)
{
    size_t zrc;

    zrc = ZSTD_CCtx_setPledgedSrcSize(
        args->enc->zstd.cctx, args->size);
    if (ZSTD_isError(zrc)) {
        ngx_log_error(
            NGX_LOG_ALERT,
            args->enc->request->connection->log,
            0,
            "zstd error while trying to set pledgedSrcSize=%O: %s",
            args->size,
            ZSTD_getErrorName(zrc));

        return (set_pledged_size_result) {
            .status = NGX_ERROR,
        };
    }

    return (set_pledged_size_result) {
        .status = NGX_OK,
    };
}

typedef struct {
    encoder_t *enc;
    int32_t    hint;
} set_src_hint_args;

typedef struct {
    ngx_int_t status;
} set_src_hint_result;

static set_src_hint_result
ngx_http_pack_zstd_set_src_hint(set_src_hint_args *const args)
{
    static ngx_str_t const sizeHint = ngx_string("srcSizeHint");

    ngx_int_t rc;

    rc = (ngx_http_pack_zstd_set_param(&(set_param_args) {
              .enc   = args->enc,
              .param = ZSTD_c_srcSizeHint,
              .value = args->hint,
              .name  = &sizeHint,
          }))
             .status;

    return (set_src_hint_result) {
        .status = rc,
    };
}

typedef struct {
    ngx_int_t status;
} configure_encoder_result;

typedef struct {
    ngx_int_t level;
    size_t    window_bits;
    /* What the encoder is about to be told to expect: the pledge when
       the length is known, the hint when it is not. */
    uint64_t expected;
} derive_tables_args;

typedef struct {
    int32_t hash_log;
    int32_t chain_log;
} derive_tables_result;

/* How big the match finder's tables should be. zstd derives them from
   the level alone, which says nothing about the window: at the floor
   it asks for a hash table several times the window it indexes.
   Capped a bit below the window, that bit halving the largest
   allocation here for almost nothing on the wire, where the next one
   costs. */
static derive_tables_result
ngx_http_pack_zstd_derive_tables(derive_tables_args *const args)
{
    ZSTD_compressionParameters cparams;
    uint32_t                   cap;

    /* pack_zstd_window's floor is 14, so this never approaches
       ZSTD_HASHLOG_MIN. */
    cap     = (uint32_t) args->window_bits - 1;
    cparams = ZSTD_getCParams(
        (int32_t) args->level, args->expected, 0);

    cparams.windowLog = (uint32_t) args->window_bits;
    cparams = ZSTD_adjustCParams(cparams, args->expected, 0);

    return (derive_tables_result) {
        .hash_log  = (int32_t) ngx_min(cparams.hashLog, cap),
        .chain_log = (int32_t) ngx_min(cparams.chainLog, cap),
    };
}

/* Tells the encoder what the directives asked for and what to expect
   of the body. Every rejection is fatal rather than skipped: libzstd
   is vendored and pinned (see deps/zstd), so one means a broken build
   and not a host carrying an older library. */
static configure_encoder_result
ngx_http_pack_zstd_configure_encoder(encoder_t *const enc)
{
    static ngx_str_t const level    = ngx_string("compressionLevel");
    static ngx_str_t const window   = ngx_string("windowLog");
    static ngx_str_t const workers  = ngx_string("nbWorkers");
    static ngx_str_t const hash     = ngx_string("hashLog");
    static ngx_str_t const chain    = ngx_string("chainLog");
    static ngx_str_t const checksum = ngx_string("checksumFlag");

    enum { nparams = 6 };

    set_param_args       params[nparams];
    ngx_uint_t           idx;
    ngx_int_t            rc;
    derive_tables_result tables;

    /* The figure the encoder is about to be given, so the tables are
       sized against the same expectation. */
    tables = ngx_http_pack_zstd_derive_tables(&(derive_tables_args) {
        .level       = enc->conf.level,
        .window_bits = enc->conf.window_bits,
        .expected    = enc->conf.content_length >= 0
                           ? (uint64_t) enc->conf.content_length
                           : (uint64_t) enc->conf.src_size_hint,
    });

    /* The one of these an operator is meant to tune: it trades CPU
       for size. Bounded where pack_zstd_level is parsed, so nothing
       here rechecks it. */
    params[0] = (set_param_args) {
        .enc   = enc,
        .param = ZSTD_c_compressionLevel,
        .value = enc->conf.level,
        .name  = &level,
    };

    /* A ceiling, not a target: sizing the window down to a known
       response is zstd's own work. ZSTD_adjustCParams_internal lowers
       windowLog to fit the pledge below, and lowers hashLog and
       chainLog with it, so the ceiling is all this has to set. */
    params[1] = (set_param_args) {
        .enc   = enc,
        .param = ZSTD_c_windowLog,
        .value = enc->conf.window_bits,
        .name  = &window,
    };

    /* nginx already parallelises across worker processes, so a
       per-request thread pool would only oversubscribe. 0 is the
       library default, set explicitly so a vendored update cannot
       change it under us. */
    params[2] = (set_param_args) {
        .enc   = enc,
        .param = ZSTD_c_nbWorkers,
        .value = 0,
        .name  = &workers,
    };

    /* See ngx_http_pack_zstd_derive_tables. */
    params[3] = (set_param_args) {
        .enc   = enc,
        .param = ZSTD_c_hashLog,
        .value = tables.hash_log,
        .name  = &hash,
    };

    params[4] = (set_param_args) {
        .enc   = enc,
        .param = ZSTD_c_chainLog,
        .value = tables.chain_log,
        .name  = &chain,
    };

    /* No trailing content checksum. HTTP has already framed and
       verified the body by the time a decoder sees it, so the four
       bytes buy nothing and every response pays them. Set explicitly
       rather than left at the library default, for the same reason
       nbWorkers is: a vendored update cannot change it under us. */
    params[5] = (set_param_args) {
        .enc   = enc,
        .param = ZSTD_c_checksumFlag,
        .value = 0,
        .name  = &checksum,
    };

    for (idx = 0; idx < nparams; idx++) {
        rc = ngx_http_pack_zstd_set_param(&params[idx]).status;
        if (rc != NGX_OK) {
            return (configure_encoder_result) {
                .status = NGX_ERROR,
            };
        }
    }

    /* Writes the size into the frame header and sizes the
       match-finder tables to the body rather than the window, which
       is what bounds per-request memory at a high level. Nothing may
       narrow content_length on the way: a body over 4 GiB through 32
       bits becomes a pledge zstd rejects after compressing the
       response. */
    if (enc->conf.content_length >= 0) {
        rc = ngx_http_pack_zstd_set_pledged_size(
                 &(set_pledged_size_args) {
                     .enc  = enc,
                     .size = enc->conf.content_length,
                 })
                 .status;

        if (rc != NGX_OK) {
            return (configure_encoder_result) {
                .status = NGX_ERROR,
            };
        }
    } else {
        /* No length to pledge, so give the guess instead: a pledge is
           "controlled at end of frame" (zstd.h) and would fail every
           response not exactly that long. pack_zstd_hint defaults to
           none, which is 0 - what libzstd reads as no hint - so this
           path serves both without a branch. */
        rc = ngx_http_pack_zstd_set_src_hint(
                 &(set_src_hint_args) {
                     .enc  = enc,
                     .hint = (int32_t) enc->conf.src_size_hint,
                 })
                 .status;

        if (rc != NGX_OK) {
            return (configure_encoder_result) {
                .status = NGX_ERROR,
            };
        }
    }

    return (configure_encoder_result) {
        .status = NGX_OK,
    };
}

typedef struct {
    ngx_int_t status;
} ensure_stream_result;

/* Builds the encoder and the output chain's tail, once per response.
   No output buffer yet - get_buf creates those on demand, up to
   conf.nbuffers of them, and most responses never need a second. */
static ensure_stream_result
ngx_http_pack_zstd_ensure_stream(encoder_t *const enc)
{
    ngx_int_t rc;

    rc = ngx_http_pack_zstd_init_encoder(enc).status;
    if (rc != NGX_OK) {
        return (ensure_stream_result) {
            .status = NGX_ERROR,
        };
    }

    rc = ngx_http_pack_zstd_configure_encoder(enc).status;
    if (rc != NGX_OK) {
        return (ensure_stream_result) {
            .status = NGX_ERROR,
        };
    }

    /* Only the tail pointer has to exist before the first buffer is
       committed, and ngx_pcalloc cannot set it. */
    enc->last_out = &enc->out;

    /* Both halves are done, which is why the line is here rather than
       at the end of either. script/test_stream.py counts it to know
       how many encoders a slice of the log built. */
    ngx_log_debug0(
        NGX_LOG_DEBUG_HTTP,
        enc->request->connection->log,
        0,
        "zstd encoder instance created and configured");

    return (ensure_stream_result) {
        .status = NGX_OK,
    };
}


#if (NGX_HTTP_PACK_ZSTD_FAULT_INJECT)
/* Test-only, and never in a shipping binary: script/build.sh does not
   define NGX_HTTP_PACK_ZSTD_FAULT_INJECT. Refuses the Nth libzstd
   allocation and every one after, so the out-of-memory branches can
   be reached on demand. N comes from the environment so one binary
   covers every case script/test_oom.py drives; absent or zero refuses
   none. */
static ngx_uint_t ngx_http_pack_zstd_fault_read;
static ngx_uint_t ngx_http_pack_zstd_fault_after;
static ngx_uint_t ngx_http_pack_zstd_fault_seen;

static ngx_uint_t
ngx_http_pack_zstd_fault_refuses(void)
{
    char     *spec;
    ngx_int_t after;

    if (!ngx_http_pack_zstd_fault_read) {
        ngx_http_pack_zstd_fault_read = 1;

        spec = getenv("PACK_ZSTD_FAULT_AFTER");
        if (spec != NULL) {
            after = ngx_atoi((u_char *) spec, ngx_strlen(spec));
            if (after > 0) {
                ngx_http_pack_zstd_fault_after = (ngx_uint_t) after;
            }
        }
    }

    if (ngx_http_pack_zstd_fault_after == 0) {
        return 0;
    }

    return ++ngx_http_pack_zstd_fault_seen >=
           ngx_http_pack_zstd_fault_after;
}
#endif


/* The encoder allocates from the heap, not the request pool: its
   allocations vary widely in size and lifetime, and ngx_pfree only
   reclaims "large" blocks, so pool-backed ones would pile up until
   the request ends. "opaque" is still the pool, but only for logging.
 */
static void *
ngx_http_pack_zstd_alloc(void *const opaque, size_t const size)
{
    ngx_pool_t *pool;
    ngx_log_t  *log;
    void       *ptr;

    pool = opaque;
    log  = pool->log;

#if (NGX_HTTP_PACK_ZSTD_FAULT_INJECT)
    if (ngx_http_pack_zstd_fault_refuses()) {
        ngx_log_error(
            NGX_LOG_ALERT,
            log,
            0,
            "zstd fault injection: refusing %uz bytes",
            size);

        return NULL;
    }
#endif

    ptr = ngx_alloc(size, log);

    ngx_log_debug2(
        NGX_LOG_DEBUG_HTTP,
        log,
        0,
        "zstd alloc: %p, size: %uz",
        ptr,
        size);

    return ptr;
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

/* Releases the encoder when the request is terminated before
   compression finishes, so close is never reached. */
static void
ngx_http_pack_zstd_cleanup(void *const data)
{
    zctx_t *zctx = data;
    /* Normally already gone - ngx_http_pack_zstd_encoder_close resets
       the field. This is the abort path. */
    if (zctx->cctx != NULL) {
        ZSTD_freeCCtx(zctx->cctx);
        zctx->cctx = NULL;
    }
}


/* --- Everything above is private; this is what the filter sees. ---
 */

encoder_t *
ngx_http_pack_zstd_encoder_create(
    ngx_http_request_t *const r, conf_t *const conf)
{
    encoder_t *enc;

    enc = ngx_pcalloc(r->pool, sizeof(*enc));
    if (enc == NULL) {
        return NULL;
    }

    enc->request = r;
    enc->conf    = *conf;

    if (ngx_http_pack_zstd_ensure_stream(enc).status != NGX_OK) {
        return NULL;
    }

    return enc;
}


step_e
ngx_http_pack_zstd_encoder_step(
    encoder_t *const    enc,
    ngx_chain_t **const in,
    ngx_uint_t const    wants_output)
{
    compress_result round;

    round = ngx_http_pack_zstd_compress(&(compress_args) {
        .enc          = enc,
        .chain        = *in,
        .wants_output = wants_output,
    });

    *in = round.chain;

    return round.step;
}


ngx_chain_t *
ngx_http_pack_zstd_encoder_pending(encoder_t *const enc)
{
    return enc->out;
}


void
ngx_http_pack_zstd_encoder_drained(encoder_t *const enc)
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
ngx_http_pack_zstd_encoder_busy(encoder_t *const enc)
{
    return enc->busy != NULL;
}


ngx_uint_t
ngx_http_pack_zstd_encoder_has_free(encoder_t *const enc)
{
    return enc->free != NULL;
}


ngx_uint_t
ngx_http_pack_zstd_encoder_frame_closed(encoder_t *const enc)
{
    return enc->state.frame_closed;
}


/* The chains are dropped rather than handed back: they point into the
   request pool, and ngx_http_write_filter copied whatever links it
   was given, so what is downstream survives this. */
void
ngx_http_pack_zstd_encoder_close(encoder_t *const enc)
{
    ngx_http_pack_zstd_cleanup(&enc->zstd);

    enc->out      = NULL;
    enc->last_out = NULL;
    enc->busy     = NULL;
    enc->free     = NULL;
    enc->nbuffers = 0;
}
