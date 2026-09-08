/*
   Copyright (C) 2026 Juri Torhoff
 */

#ifndef NGX_HTTP_PACK_BROTLI_FILTER_H_INCLUDED_
#define NGX_HTTP_PACK_BROTLI_FILTER_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


/* Whether pack_brotli is "always" for the location cf->ctx currently
   names - the one bit of this module's config zstd's merge_loc_conf
   needs, to refuse setting both filters to "always" at once. Valid
   only once Brotli's own merge_loc_conf has already run for that
   location, which the fixed module order guarantees. */
ngx_flag_t ngx_http_pack_brotli_is_always(ngx_conf_t *cf);


#endif /* NGX_HTTP_PACK_BROTLI_FILTER_H_INCLUDED_ */
