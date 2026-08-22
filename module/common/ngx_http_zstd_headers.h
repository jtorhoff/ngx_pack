/*
 * Copyright (C) Google Inc.
 */

/* HTTP header handling shared by the filter and the static module:
 * reading Accept-Encoding to decide whether a client will take
 * Zstandard, and labelling a response that carries it.
 *
 * Both modules have to answer the same questions, and previously each
 * carried its own copy of the answers. The copies drifted: the static
 * module's Accept-Encoding parser had lost the length guard, and a
 * fix to one did not reach the other.
 *
 * The functions are static and live in the header rather than in a
 * source file of their own, so that neither module's "config" has to
 * grow a second entry in ngx_module_srcs. Each module is a separate
 * translation unit, and a separate shared object in a dynamic build,
 * so each simply gets its own copy - with no duplicate symbols and no
 * build changes.
 */

#ifndef NGX_HTTP_ZSTD_HEADERS_H_INCLUDED_
#define NGX_HTTP_ZSTD_HEADERS_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


/* Optional whitespace, as RFC 9110 defines it for list separators. */
static ngx_uint_t
ngx_http_zstd_is_whitespace(u_char c)
{
    return c == ' ' || c == '\t';
}

static u_char *
ngx_http_zstd_skip_whitespace(u_char *cursor, u_char *end)
{
    while (cursor < end && ngx_http_zstd_is_whitespace(*cursor)) {
        cursor++;
    }
    return cursor;
}

/* Given the text following an encoding token, reports whether its
   parameters set the quality to zero, i.e. ";q=0", ";q=0.0",
   ";q=0.00" or ";q=0.000". Anything else - a different weight, an
   unrecognised parameter, no parameters at all - counts as
   acceptable. */
static ngx_uint_t
ngx_http_zstd_is_zero_weighted(u_char *cursor, u_char *end)
{
    ngx_uint_t digits;

    cursor = ngx_http_zstd_skip_whitespace(cursor, end);
    if (cursor == end || *cursor++ != ';') {
        return 0;
    }
    cursor = ngx_http_zstd_skip_whitespace(cursor, end);
    if (cursor == end || (*cursor != 'q' && *cursor != 'Q')) {
        return 0;
    }
    cursor++;
    cursor = ngx_http_zstd_skip_whitespace(cursor, end);
    if (cursor == end || *cursor++ != '=') {
        return 0;
    }
    cursor = ngx_http_zstd_skip_whitespace(cursor, end);
    /* Any weight not starting with "0" is non-zero. */
    if (cursor == end || *cursor++ != '0') {
        return 0;
    }
    /* "q=0" with nothing after it, or with no fraction. */
    if (cursor == end || *cursor != '.') {
        return 1;
    }
    cursor++;
    /* RFC 9110 permits at most three digits after the point. */
    for (digits = 0; digits < 3; digits++) {
        if (cursor == end) {
            return 1; /* "q=0." */
        }
        if (*cursor < '0' || *cursor > '9') {
            return 1;
        }
        if (*cursor > '0') {
            return 0; /* a non-zero digit */
        }
        cursor++;
    }
    return 1;
}

/* Decides whether the client will accept Zstandard.

   "zstd" is taken whenever it appears as a token in Accept-Encoding,
   whatever weight it carries, with the single exception of an
   explicit zero - which RFC 9110 defines as "not acceptable". A
   wildcard ("*") is taken on the same terms, since RFC 9110 says it
   covers any coding not explicitly listed. Relative weights are
   deliberately ignored, so "gzip;q=1.0, zstd;q=0.1" still selects
   Zstandard. */
static ngx_int_t
ngx_http_zstd_check_accept_encoding(ngx_http_request_t *r)
{
    ngx_table_elt_t *accept_encoding_entry;
    ngx_str_t       *accept_encoding;
    u_char          *start;
    u_char          *cursor;
    u_char          *end;
    u_char           before;
    u_char           after;
    u_char          *token;
    size_t           token_len;
    ngx_uint_t       pass;

    accept_encoding_entry = r->headers_in.accept_encoding;
    if (accept_encoding_entry == NULL) {
        return NGX_DECLINED;
    }
    accept_encoding = &accept_encoding_entry->value;

    start = accept_encoding->data;
    end = start + accept_encoding->len;

    /* Pass 0 looks for "zstd", pass 1 for the wildcard - either is
       enough to accept. */
    for (pass = 0; pass < 2; pass++) {
        if (pass == 0) {
            token = (u_char *) "zstd";
            token_len = 4;
        } else {
            token = (u_char *) "*";
            token_len = 1;
        }

        if (accept_encoding->len < token_len) {
            continue;
        }

        cursor = start;
        for (;;) {
            /* Bounded search, so a header without a terminating NUL
               can not be run off the end of. */
            cursor =
                ngx_strlcasestrn(cursor, end, token, token_len - 1);
            if (cursor == NULL) {
                break;
            }

            /* The token has to stand alone; reject a match inside a
               longer one such as "zstd" or "x-br". A match at
               either edge of the header is treated as if a separator
               sat beside it. */
            if (cursor == start) {
                before = ',';
            } else {
                before = cursor[-1];
            }

            cursor += token_len;
            if (cursor == end) {
                after = ',';
            } else {
                after = *cursor;
            }

            if (before != ',' &&
                !ngx_http_zstd_is_whitespace(before)) {
                continue;
            }

            if (after != ',' && after != ';' &&
                !ngx_http_zstd_is_whitespace(after)) {
                continue;
            }

            if (!ngx_http_zstd_is_zero_weighted(cursor, end)) {
                return NGX_OK;
            }
        }
    }

    return NGX_DECLINED;
}

/* Decides whether this request should be served Zstandard at all.
   Shared by both modules, which had identical copies of this.

   Returns NGX_OK only for a main request from a client that named
   "zstd" and speaks at least HTTP/1.1. The 1.1 floor matches
   gzip_http_version's default for the same reason it has one: some
   HTTP/1.0 clients and intermediaries mishandle a compressed
   response.

   Nothing here touches gzip. Where both modules could compress a
   response, the one whose header filter runs first sets
   "Content-Encoding" and the other declines on seeing it - which is
   Zstandard, since its filter is ordered ahead of gzip's. Reaching
   into r->gzip_tested and r->gzip_ok to force that outcome only
   restated an order the filter chain already fixes. */
static ngx_int_t
ngx_http_zstd_claim_request(ngx_http_request_t *r)
{
    if (r != r->main) {
        return NGX_DECLINED;
    }

    if (r->http_version < NGX_HTTP_VERSION_11) {
        return NGX_DECLINED;
    }

    if (ngx_http_zstd_check_accept_encoding(r) != NGX_OK) {
        return NGX_DECLINED;
    }

    return NGX_OK;
}

/* Checks whether the given header is "Vary: Accept-Encoding".
   Returns NGX_OK on a match, NGX_DECLINED otherwise. */
static ngx_int_t
ngx_http_zstd_check_vary(ngx_table_elt_t *header)
{
    static const u_char vary[] = "Vary";
    static const u_char encoding[] = "Accept-Encoding";

    ngx_str_t *key;
    ngx_str_t *val;

    key = &header->key;
    val = &header->value;

    if (key->len != sizeof(vary) - 1 ||
        val->len != sizeof(encoding) - 1) {
        return NGX_DECLINED;
    }

    if (ngx_strncasecmp(key->data, (u_char *) vary, key->len) ||
        ngx_strncasecmp(val->data, (u_char *) encoding, val->len)) {
        return NGX_DECLINED;
    }

    return NGX_OK;
}

/* Advertises that the body depends on Accept-Encoding, so that a
   shared cache cannot hand a Zstandard-encoded response to a client
   that never asked for one.

   nginx has r->gzip_vary for this, but it is the gzip module's: the
   field only exists under NGX_HTTP_GZIP, and the header filter emits
   nothing unless the gzip_vary directive is also on. Whether a
   Zstandard response is cacheable should not turn on a gzip setting,
   so where that flag will not produce the header this writes one
   itself.

   Repeated Vary fields combine as one comma-separated list under RFC
   9110, so an upstream "Vary: Accept-Language" is left where it is
   and this is added beside it. Only an entry already saying exactly
   this is redundant, and that is the one case skipped.

   Returns NGX_ERROR only if the header list could not be grown. */
static ngx_int_t
ngx_http_zstd_set_vary(ngx_http_request_t *r)
{
    ngx_uint_t       i;
    ngx_list_part_t *part;
    ngx_table_elt_t *header;
    ngx_table_elt_t *vary;

#if (NGX_HTTP_GZIP)
    ngx_http_core_loc_conf_t *clcf;

    /* Where nginx is already going to write the line, raise its flag
       instead of writing a second one. It emits once however many
       modules ask, so on a response Zstandard declines and gzip then
       takes, this is what keeps the two of us from producing "Vary:
       Accept-Encoding" twice. With the directive off nginx writes
       nothing and clears the flag again, which is the case the header
       below exists for. */
    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
    if (clcf->gzip_vary) {
        r->gzip_vary = 1;
        return NGX_OK;
    }
#endif

    part = &r->headers_out.headers.part;
    header = part->elts;

    for (i = 0; /* void */; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            header = part->elts;
            i = 0;
        }

        /* hash 0 marks an entry the filters below are to ignore. */
        if (header[i].hash == 0) {
            continue;
        }

        if (ngx_http_zstd_check_vary(&header[i]) == NGX_OK) {
            return NGX_OK;
        }
    }

    vary = ngx_list_push(&r->headers_out.headers);
    if (vary == NULL) {
        return NGX_ERROR;
    }

    vary->hash = 1;
#if nginx_version >= 1023000
    vary->next = NULL;
#endif
    ngx_str_set(&vary->key, "Vary");
    ngx_str_set(&vary->value, "Accept-Encoding");

    return NGX_OK;
}

/* Labels the response as Zstandard-encoded. Both modules set exactly
   this pair of headers and previously each built the list entry
   itself, so the version guard below had to be kept in step by hand
   in two places.

   Returns NGX_ERROR only if the header list could not be grown. The
   callers report that differently - the filter as NGX_ERROR, the
   static handler as a 500 - so the mapping is left to them. */
static ngx_int_t
ngx_http_zstd_set_content_encoding(ngx_http_request_t *r)
{
    ngx_table_elt_t *entry;

    entry = ngx_list_push(&r->headers_out.headers);
    if (entry == NULL) {
        return NGX_ERROR;
    }

    entry->hash = 1;
#if nginx_version >= 1023000
    /* Since 1.23.0 the headers_out entries are linked, so a pushed
       entry has to terminate its own list. */
    entry->next = NULL;
#endif
    ngx_str_set(&entry->key, "Content-Encoding");
    ngx_str_set(&entry->value, "zstd");
    r->headers_out.content_encoding = entry;

    return NGX_OK;
}

#endif /* NGX_HTTP_ZSTD_HEADERS_H_INCLUDED_ */
