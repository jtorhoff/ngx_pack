/*
   Copyright (C) 2026 Juri Torhoff
 */

#ifndef NGX_HTTP_PACK_BROTLI_FILTER_H_INCLUDED_
#define NGX_HTTP_PACK_BROTLI_FILTER_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


/* Whether Brotli would claim "r" right now. zstd's header filter is
   the one caller: it always runs first regardless of what "pack"
   says, so this is how it asks whether to defer before deciding
   anything of its own. A pure read - nothing is committed until
   Brotli's own header filter actually runs. */
ngx_flag_t ngx_http_pack_brotli_would_claim(ngx_http_request_t *r);


#endif /* NGX_HTTP_PACK_BROTLI_FILTER_H_INCLUDED_ */
