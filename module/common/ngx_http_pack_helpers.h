/*
   Copyright (C) 2026 Juri Torhoff
 */

/* Small helpers shared by the two filters, kept apart from
   ngx_http_pack_headers.h so a module that wants neither includes
   neither: a static function in a header is an unused-function error
   in any translation unit that does not call it.
 */

#ifndef NGX_HTTP_PACK_HELPERS_H_INCLUDED_
#define NGX_HTTP_PACK_HELPERS_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


/* The inverse of ngx_parse_size: 4096 back to "4k". Exact rather than
   rounded: a size this module ever prints is one of its own byte
   constants, so it either divides evenly by 1k/1m or it does not, and
   only those two are worth answering since that is all
   ngx_parse_size itself accepts back. */
static ngx_str_t
ngx_http_pack_format_size(ngx_pool_t *const pool, size_t const bytes)
{
    /* nginx's own bound on how many characters a size_t can need. */
    enum { max_str_len = NGX_SIZE_T_LEN + sizeof("k") - 1 };

    size_t  value;
    u_char  unit;
    u_char *data;
    size_t  end;

    data = ngx_pnalloc(pool, max_str_len);
    if (data == NULL) {
        return (ngx_str_t) ngx_null_string;
    }

    if (bytes != 0 && bytes % (1024 * 1024) == 0) {
        value = bytes / (1024 * 1024);
        unit  = 'm';
    } else if (bytes != 0 && bytes % 1024 == 0) {
        value = bytes / 1024;
        unit  = 'k';
    } else {
        value = bytes;
        unit  = 0;
    }

    end = (size_t) (ngx_sprintf(data, "%uz", value) - data);
    if (unit) {
        data[end]  = unit;
        end       += 1;
    }

    return (ngx_str_t) {
        .data = data,
        .len  = end,
    };
}

/* Whether the response may be re-encoded at all. "no-transform" is
   the origin saying its payload must reach the client as it left, and
   compressing it is the transformation that forbids - RFC 9111
   section 5.2.2.6. Found with nginx's multi-header walk, since the
   directive may be repeated or sit beside others and "no-transform-x"
   is not it. NGX_OK when compression is allowed, else NGX_DECLINED.
 */
static ngx_int_t
ngx_http_pack_transform_allowed(ngx_http_request_t *const r)
{
    static ngx_str_t const no_transform = ngx_string("no-transform");

    if (r->headers_out.cache_control == NULL) {
        return NGX_OK;
    }

    if (ngx_http_parse_multi_header_lines(
            r,
            r->headers_out.cache_control,
            (ngx_str_t *) &no_transform,
            NULL) != NULL) {
        return NGX_DECLINED;
    }

    return NGX_OK;
}

#endif /* NGX_HTTP_PACK_HELPERS_H_INCLUDED_ */
