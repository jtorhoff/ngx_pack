/*
   Copyright (C) 2026 Juri Torhoff
 */

#ifndef NGX_HTTP_PACK_MODULE_H_INCLUDED_
#define NGX_HTTP_PACK_MODULE_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


/* Which codec a caller is asking ngx_http_pack_status about. Fixed at
   two, unlike the directive's own token table, because these are the
   two filters that read it - a third would add a value here, not
   change the shape. */
typedef enum {
    NGX_HTTP_PACK_ZSTD = 0,
    NGX_HTTP_PACK_BROTLI,
} ngx_http_pack_codec_e;

/* What a filter needs to know about its own place in this location's
   "pack" directive, resolved once here rather than by either filter
   picking apart the raw ordered list itself. */
typedef struct {
    /* 1 if this codec is named in "pack" here at all - "off", or the
       other codec named alone, both leave it 0. */
    unsigned listed: 1;

    /* 1 if this codec is the one "pack" marked "=always". */
    unsigned always: 1;

    /* 1 if the other codec is listed and ranked ahead of this one -
       the one thing zstd's header filter reads this for, since it is
       the one that always runs first regardless of what "pack" says.
       Brotli never reads it: running second, it already declines
       whatever zstd has already claimed. */
    unsigned deferred: 1;
} ngx_http_pack_status_t;

ngx_http_pack_status_t ngx_http_pack_status(
    ngx_http_request_t *r, ngx_http_pack_codec_e codec);

/* Wraps ngx_http_test_content_type against pack_types, so neither
   filter keeps a MIME hash of its own - one list decides whether a
   response is worth compressing, before either codec is chosen. */
u_char *ngx_http_pack_test_content_type(ngx_http_request_t *r);

#endif /* NGX_HTTP_PACK_MODULE_H_INCLUDED_ */
