/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) Google Inc.
 * Copyright (C) 2026 Juri Torhoff
 */

#ifndef NGX_HTTP_PACK_BROTLI_ENCODER_H_INCLUDED_
#define NGX_HTTP_PACK_BROTLI_ENCODER_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


/* A streaming Brotli encoder and the buffers it hands back, opaque so
 * the chain rules stay on this side of the line. The buffers are its
 * own and marked "recycled", which stops a deadlock: a block under
 * postpone_output would otherwise sit in the write filter while the
 * encoder waits for it. BrotliEncoderTakeOutput would not allow that.
 */
typedef struct ngx_http_pack_brotli_encoder_s
    ngx_http_pack_brotli_encoder_t;


/* What one turn of the encoder decided to do next. The caller's loop
 * owns the returns; a step only says which one.
 */
typedef enum {
    /* Made progress; go round again. */
    NGX_HTTP_PACK_BROTLI_STEP_CONTINUE = 0,

    /* Stopped because the output buffer is still outstanding, with
       work left to do. Whether that can be resolved depends on what
       the filters below hand back, so the loop decides. */
    NGX_HTTP_PACK_BROTLI_STEP_AGAIN,

    /* The encoder has nothing more to give until it is fed again. */
    NGX_HTTP_PACK_BROTLI_STEP_DONE,

    /* Unrecoverable. The caller should close the stream. */
    NGX_HTTP_PACK_BROTLI_STEP_FAILED
} ngx_http_pack_brotli_step_e;


/* What the directives settle before an encoder can exist. Passed in
 * rather than read from the location configuration, so nothing here
 * has to know nginx has directives at all. "window_bits" is an
 * lg_win, not a size; "content_length" -1 when unknown, and used only
 * to decide whether anything is pledged - Brotli sizes its own
 * buffers from the input it is handed, so a known length does not
 * narrow them.
 */
typedef struct {
    ngx_int_t quality;
    size_t    window_bits;

    /* How many output buffers one response may have in flight, and
       how big each of them is: the two parameters of
       pack_brotli_buffers. "nbuffers" is a ceiling, not an
       allocation - buffers are created on demand. */
    ngx_int_t nbuffers;
    size_t    buffer_size;

    off_t content_length;
} ngx_http_pack_brotli_encoder_conf_t;


/* Builds an encoder on the request's pool and registers the cleanup
 * that frees Brotli's allocations if the request is aborted. NULL on
 * failure, with the reason logged - a non-NULL return is what "the
 * encoder exists" means, there being no separate initialised flag.
 */
ngx_http_pack_brotli_encoder_t *ngx_http_pack_brotli_encoder_create(
    ngx_http_request_t *r, ngx_http_pack_brotli_encoder_conf_t *conf);


/* Runs one round: takes what it can from "*in", compresses it, and
 * makes whatever came out available through pending(). "*in" is
 * advanced as buffers are consumed, so the caller's chain head moves.
 * "wants_output" turns a part-filled block into output rather than
 * leaving it to wait; it belongs to the call, not the response.
 */
ngx_http_pack_brotli_step_e ngx_http_pack_brotli_encoder_step(
    ngx_http_pack_brotli_encoder_t *enc,
    ngx_chain_t                   **in,
    ngx_uint_t                      wants_output);


/* The buffers filled since the last send, or NULL when there are none
 * to offer. Sending NULL is not a no-op: it is how the filters below
 * are asked to make progress on buffers they already hold, which is
 * the only way an outstanding one is ever released.
 */
ngx_chain_t *ngx_http_pack_brotli_encoder_pending(
    ngx_http_pack_brotli_encoder_t *enc);


/* Takes account of what the filters below consumed, freeing the
 * buffer for refilling once they have taken all of it. Call once
 * after each send, whatever the send returned.
 */
void ngx_http_pack_brotli_encoder_drained(
    ngx_http_pack_brotli_encoder_t *enc);


/* Whether any buffer handed downstream has yet to come back. While
 * this holds, the connection still owes output however done the
 * encoder is.
 */
ngx_uint_t ngx_http_pack_brotli_encoder_busy(
    ngx_http_pack_brotli_encoder_t *enc);


/* Whether a buffer is free for the next round. False means the
 * filters below are holding everything this response is allowed.
 */
ngx_uint_t ngx_http_pack_brotli_encoder_has_free(
    ngx_http_pack_brotli_encoder_t *enc);


/* Whether the input has ended and Brotli has emitted the last of the
 * stream, so no further round can produce anything.
 */
ngx_uint_t ngx_http_pack_brotli_encoder_stream_closed(
    ngx_http_pack_brotli_encoder_t *enc);


/* Releases Brotli's allocations and drops the buffer chains. Safe to
 * call more than once, and with buffers still downstream: those point
 * into the request pool, and the filters below copied their links.
 */
void ngx_http_pack_brotli_encoder_close(
    ngx_http_pack_brotli_encoder_t *enc);


#endif /* NGX_HTTP_PACK_BROTLI_ENCODER_H_INCLUDED_ */
