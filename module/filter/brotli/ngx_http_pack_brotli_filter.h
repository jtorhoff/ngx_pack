/*
   Copyright (C) 2026 Juri Torhoff
 */

#ifndef NGX_HTTP_PACK_BROTLI_FILTER_H_INCLUDED_
#define NGX_HTTP_PACK_BROTLI_FILTER_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


/* Whether pack_brotli is "always" for the location cf->ctx currently
   names. The one thing outside this file that needs to know it: the
   zstd filter's own merge_loc_conf, refusing a config that sets both
   filters to "always" at once - see the comment beside that check for
   why, and module/filter/zstd/config for why this can be called at
   all only once pack_zstd's merge has run, which the module order
   both config scripts already rely on guarantees.

   conf_t itself stays private to ngx_http_pack_brotli_filter.c; this
   is the one bit of it another module has a reason to read. */
ngx_flag_t ngx_http_pack_brotli_is_always(ngx_conf_t *cf);


#endif
