/*
 * Copyright (C) 2026 Juri Torhoff
 */

#ifndef NGX_HTTP_PACK_ZSTD_ENCODER_H_INCLUDED_
#define NGX_HTTP_PACK_ZSTD_ENCODER_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


/* A streaming Zstandard encoder and the output buffers it fills.
 *
 * Opaque on purpose: the filter hands it input and takes finished
 * buffers back, so the rules about which chain a buffer may be on,
 * when a directive has to be repeated, and when the frame is closed
 * stay on this side of the line.
 */
typedef struct ngx_http_pack_zstd_encoder_s
    ngx_http_pack_zstd_encoder_t;


/* What one turn of the encoder decided to do next. The caller's loop
 * owns the returns; a step only says which one.
 */
typedef enum {
    /* Not a step at all, and never returned by
       ngx_http_pack_zstd_encoder_step: what the round's own input
       stage says when it has settled nothing and the encoder should
       run. It is here because that stage answers in this type. */
    NGX_HTTP_PACK_ZSTD_STEP_READY = 0,

    /* Made progress; go round again. */
    NGX_HTTP_PACK_ZSTD_STEP_CONTINUE,

    /* Stopped for want of a free output buffer, with work still to
       do. Whether that can be resolved depends on what the filters
       below hand back, so the loop decides. */
    NGX_HTTP_PACK_ZSTD_STEP_AGAIN,

    /* The encoder has nothing more to give until it is fed again. */
    NGX_HTTP_PACK_ZSTD_STEP_DONE,

    /* Unrecoverable. The caller should close the stream. */
    NGX_HTTP_PACK_ZSTD_STEP_FAILED
} ngx_http_pack_zstd_step_e;


/* What the directives settle before an encoder can exist. Passed in
 * rather than read from the location configuration, so nothing here
 * has to know nginx has directives at all. "window_bits" is a
 * windowLog, not a size; "nbuffers" a ceiling, not an allocation;
 * "content_length" -1 when the size is unknown, which is what decides
 * between a pledge and "src_size_hint"; that hint is 0 when there is
 * none to give, which libzstd reads as the parameter never having
 * been set.
 */
typedef struct {
    ngx_int_t level;
    size_t    window_bits;
    ngx_int_t nbuffers;
    size_t    buffer_size;
    off_t     content_length;
    size_t    src_size_hint;
} ngx_http_pack_zstd_encoder_conf_t;


/* Builds an encoder on the request's pool and registers the cleanup
 * that frees libzstd's allocations if the request is aborted. NULL on
 * failure, with the reason logged - a non-NULL return is what "the
 * encoder exists" means, there being no separate initialised flag.
 */
ngx_http_pack_zstd_encoder_t *ngx_http_pack_zstd_encoder_create(
    ngx_http_request_t *r, ngx_http_pack_zstd_encoder_conf_t *conf);


/* Runs one round: takes what it can from "*in", compresses it, and
 * appends whatever came out to the pending chain. "*in" is advanced
 * as buffers are consumed, so the caller's chain head moves.
 * "wants_output" says this call brought no new data - it belongs to
 * the call, not the response, which is why it is not state.
 */
ngx_http_pack_zstd_step_e ngx_http_pack_zstd_encoder_step(
    ngx_http_pack_zstd_encoder_t *enc,
    ngx_chain_t                 **in,
    ngx_uint_t                    wants_output);


/* The buffers filled since the last send. NULL when the round
 * produced nothing, which is not the same as nothing to do: sending
 * NULL is how the filters below are asked to make progress on what
 * they hold.
 */
ngx_chain_t *
ngx_http_pack_zstd_encoder_pending(ngx_http_pack_zstd_encoder_t *enc);


/* Takes account of what the filters below consumed, moving finished
 * buffers back where the encoder can refill them. Call once after
 * each send, whatever the send returned.
 */
void
ngx_http_pack_zstd_encoder_drained(ngx_http_pack_zstd_encoder_t *enc);


/* Whether buffers handed downstream have yet to come back. While this
 * holds, the connection still owes output however done the encoder
 * is.
 */
ngx_uint_t
ngx_http_pack_zstd_encoder_busy(ngx_http_pack_zstd_encoder_t *enc);


/* Whether a buffer is free for the next round. False means the
 * filters below are holding everything this response is allowed.
 */
ngx_uint_t ngx_http_pack_zstd_encoder_has_free(
    ngx_http_pack_zstd_encoder_t *enc);


/* Whether ZSTD_e_end has completed, so the frame is closed and no
 * further round can produce anything.
 */
ngx_uint_t ngx_http_pack_zstd_encoder_frame_closed(
    ngx_http_pack_zstd_encoder_t *enc);


/* Releases libzstd's allocations and drops the buffer chains. Safe to
 * call more than once, and with buffers still downstream: those point
 * into the request pool, and the filters below copied their links.
 */
void
ngx_http_pack_zstd_encoder_close(ngx_http_pack_zstd_encoder_t *enc);


#endif /* NGX_HTTP_PACK_ZSTD_ENCODER_H_INCLUDED_ */
