/*
   Copyright (C) 2026 Juri Torhoff
 */

#ifndef NGX_HTTP_PACK_BROTLI_FILTER_H_INCLUDED_
#define NGX_HTTP_PACK_BROTLI_FILTER_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


/* Whether Brotli would claim "r" right now - preflight-eligible, and
   either "pack" marked it "=always" or the client actually asked for
   it. The one thing outside this file that needs it: zstd's header
   filter, the one codec that always runs first in the chain
   regardless of what "pack" says, asking whether it should defer to
   Brotli before deciding anything of its own. A pure read; nothing
   here is committed until Brotli's own header filter actually runs.
 */
ngx_flag_t ngx_http_pack_brotli_would_claim(ngx_http_request_t *r);


#endif /* NGX_HTTP_PACK_BROTLI_FILTER_H_INCLUDED_ */
