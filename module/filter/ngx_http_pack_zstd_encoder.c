/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) Google Inc.
 * Copyright (C) 2026 Juri Torhoff
 */

#include "ngx_http_pack_zstd_encoder.h"
#include "ngx_config.h"
#include "ngx_core.h"

/* Needed for ZSTD_createCCtx_advanced (the custom allocator) and
   ZSTD_c_srcSizeHint. */
#define ZSTD_STATIC_LINKING_ONLY
#include <zstd.h>


/* What marks a buffer as ours on the busy list. Only its address
   matters - ngx_chain_update_chains does nothing but compare it - so
   a file-local object serves, and the encoder needs to know nothing
   about the module it is compiled into. */
static ngx_int_t encoder_tag;

/* The header spells this out in full; inside the encoder the short
   name is the one the code was written against. */
typedef ngx_http_pack_zstd_step_e         step_e;
typedef ngx_http_pack_zstd_encoder_t      encoder_t;
typedef ngx_http_pack_zstd_encoder_conf_t conf_t;

static void *ngx_http_pack_zstd_alloc(void *opaque, size_t size);
static void ngx_http_pack_zstd_free(void *opaque, void *address);
static void ngx_http_pack_zstd_cleanup(void *data);


/* How many buffers carrying "flush" may share one zstd block.

   A flush cuts the block short, which costs both encoder time and
   output size. A flush landing on a 32 KB boundary - the block size
   at pack_zstd_window's compiled-in default - costs nothing, because
   a block is MIN(windowSize, ZSTD_BLOCKSIZE_MAX) and that is where
   the encoder was going to end one anyway.

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

/* What libzstd owns on this response's behalf: the encoder itself,
   and the directive still owed to it. Held inside the context by
   value like the flags above, so both are zeroed before the first
   read - which ZSTD_e_continue being 0 depends on, see repeat_mode.

   A struct of its own even so, because the pool cleanup that frees
   the encoder on an aborted request is handed exactly this much and
   no more: &ctx->encoder.zctx, not the context, so nothing in the
   handler can reach a request that may already be gone. */
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

/* What the encoder has settled for itself, as filter_state_t is for
   the filter: built, holding, done. Apart from that struct because
   nothing outside encoder_t sets any of them, and a run of its own
   keeps the bitfields packed the same way. */
typedef struct {
    /* 1 if input has been handed to the encoder under ZSTD_e_continue
       that it may still be holding, unflushed. zstd gives no query
       for "is anything buffered", so this tracks it: set when a
       continue call consumes bytes, cleared once a flush fully
       drains. */
    unsigned unflushed_input: 1;

    /* 1 once ZSTD_compressStream2(..., ZSTD_e_end) has reported
       "fully flushed" (a return of 0). */
    unsigned frame_closed: 1;
} encoder_state_t;

/* Everything the encoder owns on this response's behalf: libzstd's
   own state, the buffers its output goes into, and what each round
   leaves for the next. Held by value like filter_state_t, so
   ngx_pcalloc has zeroed all of it before any field is read.

   Nothing copies this struct, and nothing may: "last_out" points at
   this struct's own "out", so a copy would keep appending to the
   original's chain while reporting the copy's. */
struct ngx_http_pack_zstd_encoder_s {
    /* The request, for its pool and its log. */
    ngx_http_request_t *request;

    /* What the directives settled; see the header. */
    conf_t conf;

    /* libzstd's own, and the only part the pool cleanup is handed. */
    zctx_t zstd;

    /* Output buffers, in the three states nginx's chain helpers keep
       them in. These point at memory *we* allocated, not at anything
       libzstd owns.

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
       conf.nbuffers. Created on demand rather than up front, so a
       response that never needs a second one never pays for it. */
    ngx_uint_t nbuffers;

    /* How many flush-marked buffers have been folded into the block
       still being built - see NGX_HTTP_PACK_ZSTD_FLUSH_FOLD.
       Reset whenever a flush or the end of the frame completes, since
       that is what starts the next block. */
    ngx_uint_t folded_flushes;

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

/* Hands back a buffer to compress into.

   NGX_OK with "buf" set, NGX_DECLINED when every buffer this
   response is allowed is already in flight, or NGX_ERROR. DECLINED is
   not a failure: it means the encoder has to wait for the filters
   below to give one back, which is what the loop turns into a send.

   Buffers are created on demand and then recycled through
   enc->free for the rest of the response, so a response that
   only ever needs one never allocates a second. */
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
       apart from anything else on the busy list and hand them back
       rather than dropping the link. "recycled" tells the filters
       below that this memory is going to be reused, so they must not
       sit on it. */
    buf->tag      = (ngx_buf_tag_t) &encoder_tag;
    buf->recycled = 1;

    enc->nbuffers++;

    ngx_log_debug2(
        NGX_LOG_DEBUG_HTTP,
        r->connection->log,
        0,
        "zstd buffer created: %p, total:%ui",
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

/* Hands the round's output buffer to enc->out.

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
        "zstd out: %p, size:%O",
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

/* Takes the head buffer off the *input* chain - the one nginx handed
   us, not the output buffers the three above deal with - there being
   no further reason to hold it: either it never carried anything to
   compress, or the encoder has taken every byte it had.

   The link goes back to the pool's own free list rather than being
   abandoned to the request, which is what keeps a long response's
   chain links a fixed cost instead of one allocation per buffer.

   The caller has already established that *in is not NULL - both
   reach the head buffer before they can decide to drop it. */
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
    ngx_uint_t   folded;
} may_fold_flush_args;

typedef struct {
    ngx_uint_t folded;
} may_fold_flush_result;

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
static may_fold_flush_result
ngx_http_pack_zstd_may_fold_flush(may_fold_flush_args *const args)
{
    ngx_uint_t   lookahead;
    ngx_chain_t *link;

    /* Can't fold any more. */
    if (args->folded + 1 >= NGX_HTTP_PACK_ZSTD_FLUSH_FOLD) {
        return (may_fold_flush_result) {
            .folded = 0,
        };
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
                return (may_fold_flush_result) {
                    .folded = 1,
                };
            }

            link = link->next;
            lookahead--;
        }
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
    ngx_uint_t        folded;
} select_mode_result;

/* Which directive the buffer at the head of the chain calls for, and
   whether its flush is being folded into the block being built.

   The head buffer comes in as "in" rather than being reached for,
   since the fold below reads the chain behind it either way and one
   source for both cannot disagree with itself. next_input has
   established that it is not NULL before it can want a mode at all.

   The fold is reported rather than counted here: acquiring an output
   buffer can still fail, and a fold recorded on a round that never
   reached the encoder would spend part of the allowance on nothing.
 */
static select_mode_result
ngx_http_pack_zstd_select_mode(select_mode_args *const args)
{
    ngx_buf_t *buffer;
    ngx_uint_t folded;

    buffer = args->in->buf;
    folded = 0;

    if (buffer->last_buf) {
        return (select_mode_result) {
            .mode   = ZSTD_e_end,
            .folded = folded,
        };
    }

    if (!buffer->flush) {
        return (select_mode_result) {
            .mode   = ZSTD_e_continue,
            .folded = folded,
        };
    }

    folded = ngx_http_pack_zstd_may_fold_flush(
                 &(may_fold_flush_args) {
                     .rest   = args->in->next,
                     .folded = args->enc->folded_flushes,
                 })
                 .folded;

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
    encoder_t *enc;
    /* The caller's input chain. What is left of it comes back in
       next_input_result. */
    ngx_chain_t *chain;
    /* Whether this call brought no new data; see the header. */
    ngx_uint_t wants_output;
} next_input_args;

/* "step" is the verdict and the only field always meaningful; the
   other three are what the round runs on and are set when it is
   STEP_READY. Read "step" first - it is a step_e, where "mode" is a
   ZSTD_EndDirective, and the two would compare equal against a wrong
   constant without a word from the compiler. */
typedef struct {
    step_e            step;
    ZSTD_EndDirective mode;
    ZSTD_inBuffer     in;
    ngx_uint_t        folded;
    /* What is left of the caller's chain. Always set, including on
       the paths that settle the round without running the encoder -
       one of those drops a buffer. */
    ngx_chain_t *chain;
} next_input_result;

/* Settles what the encoder is asked to do this round and what it is
   handed to do it with: the directive, the input window, and whether
   this round's flush is being folded into the block being built.

   NGX_HTTP_PACK_ZSTD_STEP_READY means carry on into the encoder.
   Anything else is a round that is over before it starts, and is the
   step the caller returns. */
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
        .step   = NGX_HTTP_PACK_ZSTD_STEP_READY,
        .mode   = selected.mode,
        .in     = window,
        .folded = selected.folded,
        .chain  = args->chain,
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

/* Records progress in the chain itself. It cannot be kept in the
   ZSTD_inBuffer's "pos" alone, which does not survive returning to
   nginx. That pos is the right amount to advance by whatever the
   mode: a flush or an end call may also leave input partially
   unconsumed if the output buffer filled first - see the doc comment
   on ZSTD_compressStream2. */
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

    /* Guarded, not just for tidiness: a special buffer carries no
       memory, so pos is NULL, and advancing a null pointer by zero is
       undefined even though every compiler does the obvious thing.
       UBSan reports it on the last_buf that ngx_http_send_special
       emits. */
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
            args->enc->state.unflushed_input = 1;
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

    /* Either directive ends the block, so the next one starts with
       nothing folded into it. */
    args->enc->folded_flushes = 0;

    if (args->mode == ZSTD_e_flush) {
        args->enc->state.unflushed_input = 0;
    } else { /* ZSTD_e_end */
        args->enc->state.frame_closed = 1;
    }
}

typedef struct {
    encoder_t        *enc;
    ZSTD_EndDirective mode;
    size_t            written;
    size_t            remaining;
    /* Read, never advanced. */
    ngx_chain_t *chain;
} made_progress_args;

typedef struct {
    ngx_int_t status;
} made_progress_result;

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
static made_progress_result
ngx_http_pack_zstd_made_progress(made_progress_args *const args)
{
    ngx_chain_t *in;
    size_t       written;
    size_t       remaining;

    in        = args->chain;
    written   = args->written;
    remaining = args->remaining;

    if (in == NULL && written == 0 && remaining != 0) {
        ngx_log_error(
            NGX_LOG_ALERT,
            args->enc->request->connection->log,
            0,
            "zstd compress made no progress: mode:%d "
            "remaining:%uz",
            (int) args->mode,
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

/* Runs the encoder once, into the buffer this round drew.

   The ZSTD_outBuffer lives and dies here. Nothing above needs it once
   the call returns, only how many bytes landed in it, so the window
   is built and dropped in one place rather than kept alive across the
   rest of the round.

   "in" is advanced rather than copied: ZSTD_compressStream2 moves its
   "pos", and the caller reads that to learn what was consumed.

   NGX_OK with *result filled, or NGX_ERROR with the reason logged. */
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

/* What becomes of the round's output buffer, which is one of only two
   things: handed back to be filled again, or committed to
   enc->out.

   Nothing produced and the frame still open is the first. It means go
   round again rather than return - a flush or an end still being
   drained has to be retried, and the caller is otherwise not owed a
   return yet. The buffer goes back unused, or the round would spend
   one of the response's few buffers on nothing.

   Anything else is the second, an empty buffer included: see
   ngx_http_pack_zstd_commit_buf for why the last_buf marker has to
   land on one even when no bytes were written. */
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
   buffer to enc->out. ZSTD_compressStream2 moves input and
   output in a single call, so there is no separate "does the encoder
   have output ready" phase to ask about first. */
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

    /* Tested ahead of the input, not inside the branch that finds
       none left. A closed frame means the response is over whatever
       is still queued: anything after the buffer carrying last_buf
       would otherwise be compressed into a second frame and committed
       with last_buf set again, since that flag is copied from
       frame_closed. nginx does not produce a chain like that, so this
       guards an assumption rather than an observed case.

       Closing the encoder is the loop's job rather than this one's:
       the buffer carrying last_buf may still be sitting in
       enc->out or enc->busy, and the encoder is not
       done with the response until the filters below have taken it.
     */
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

    /* Last thing before the encoder runs, and nothing above it has
       touched the input or the fold count yet, so giving up here
       costs nothing and can simply be repeated once a buffer comes
       back. */
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

    if (input.folded) {
        enc->folded_flushes++;
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
   is aborted mid-stream - the encoder's memory is not the pool's, so
   nothing else would. The cleanup is registered first, deliberately:
   a failure there must not be able to strand an allocated instance.
 */
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

/* One ZSTD_CCtx_setParameter call with its failure handled the same
   way as every other. "name" is the parameter as zstd.h spells it:
   the enum carries no name at runtime, and the number alone would
   make the log line useless to whoever reads it. */
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
    ngx_int_t status;
} set_pledged_size_result;

static set_pledged_size_result
ngx_http_pack_zstd_set_pledged_size(encoder_t *const enc)
{
    size_t zrc;

    zrc = ZSTD_CCtx_setPledgedSrcSize(
        enc->zstd.cctx, enc->conf.content_length);
    if (ZSTD_isError(zrc)) {
        ngx_log_error(
            NGX_LOG_ALERT,
            enc->request->connection->log,
            0,
            "zstd error while trying to set pledgedSrcSize=%O: %s",
            enc->conf.content_length,
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
    ngx_int_t status;
} configure_encoder_result;

/* Tells the encoder what the directives asked for and what to expect
   of the body. Every rejection here is fatal rather than skipped:
   libzstd is vendored and pinned (see deps/zstd), so one means a
   broken build and not a host carrying an older library. */
static configure_encoder_result
ngx_http_pack_zstd_configure_encoder(encoder_t *const enc)
{
    static ngx_str_t const level    = ngx_string("compressionLevel");
    static ngx_str_t const window   = ngx_string("windowLog");
    static ngx_str_t const workers  = ngx_string("nbWorkers");
    static ngx_str_t const sizeHint = ngx_string("srcSizeHint");

    enum { nparams = 3 };

    set_param_args params[nparams];
    ngx_uint_t     idx;
    ngx_int_t      rc;

    /* Straight from pack_zstd_level, the one of these an operator is
       meant to tune: it trades CPU for size. Held to 1..22 when the
       directive is parsed, so nothing here rechecks it. */
    params[0] = (set_param_args) {
        .enc   = enc,
        .param = ZSTD_c_compressionLevel,
        .value = enc->conf.level,
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
        .enc   = enc,
        .param = ZSTD_c_windowLog,
        .value = enc->conf.window_bits,
        .name  = &window,
    };

    /* nginx already parallelises across worker processes, one per
       core, so a per-request thread pool would only oversubscribe.
       0 is the library default, set explicitly so a vendored update
       cannot change it under us. */
    params[2] = (set_param_args) {
        .enc   = enc,
        .param = ZSTD_c_nbWorkers,
        .value = 0,
        .name  = &workers,
    };

    for (idx = 0; idx < nparams; idx++) {
        if (ngx_http_pack_zstd_set_param(&params[idx]).status !=
            NGX_OK) {
            return (configure_encoder_result) {
                .status = NGX_ERROR,
            };
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
    if (enc->conf.content_length >= 0) {
        rc = ngx_http_pack_zstd_set_pledged_size(enc).status;
        if (rc != NGX_OK) {
            return (configure_encoder_result) {
                .status = NGX_ERROR,
            };
        }
    } else {
        /* No length to pledge, so give the guess instead - which is
           the difference between tables sized to the body and tables
           sized to the worst case the window allows.

           Unlike ZSTD_CCtx_setPledgedSrcSize this is a guess, not a
           promise: it is not written to the frame header and not
           checked at the end of the frame, so it may be wrong in
           either direction. That is the whole reason it can be used
           here at all - a pledge cannot, since it is "controlled at
           end of frame, and trigger an error if not respected"
           (zstd.h), and would fail every response that did not
           happen to be exactly that long.

           pack_zstd_hint is what an operator sets it to; see the
           constant block in the filter for the compiled-in default
           and why it is that number. */
        rc = ngx_http_pack_zstd_set_param(
                 &(set_param_args) {
                     .enc   = enc,
                     .param = ZSTD_c_srcSizeHint,
                     .value = (int32_t) enc->conf.src_size_hint,
                     .name  = &sizeHint,
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

    /* Both halves are done, which is what the line says and why it is
       here rather than at the end of either one. script/
       test_stream.py counts it to know how many encoders a slice of
       the log built. */
    ngx_log_debug0(
        NGX_LOG_DEBUG_HTTP,
        enc->request->connection->log,
        0,
        "zstd encoder instance created and configured");

    return (ensure_stream_result) {
        .status = NGX_OK,
    };
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
