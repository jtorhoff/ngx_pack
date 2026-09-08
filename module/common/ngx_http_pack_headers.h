/*
   Copyright (C) Google Inc.
   Copyright (C) 2026 Juri Torhoff
 */

/* HTTP header handling shared by the filter and the static module:
   reading Accept-Encoding to decide whether a client will take a
   given encoding, and labelling a response that carries one.
 */

#ifndef NGX_HTTP_PACK_HEADERS_H_INCLUDED_
#define NGX_HTTP_PACK_HEADERS_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


/* Optional whitespace, as RFC 9110 defines it for list separators. */
static ngx_uint_t
ngx_http_pack_is_whitespace(u_char const c)
{
    return c == ' ' || c == '\t';
}

static u_char *
ngx_http_pack_skip_whitespace(u_char *const cursor, u_char *const end)
{
    u_char *pos;

    pos = cursor;
    while (pos < end && ngx_http_pack_is_whitespace(*pos)) {
        pos++;
    }

    return pos;
}

/* Given the text following an encoding token, reports whether its
   parameters set the quality to zero, i.e. ";q=0", ";q=0.0",
   ";q=0.00" or ";q=0.000". Anything else - a different weight, an
   unrecognised parameter, no parameters at all - counts as
   acceptable. */
static ngx_uint_t
ngx_http_pack_is_zero_weighted(
    u_char *const cursor, u_char *const end)
{
    u_char    *pos;
    ngx_uint_t digits;

    pos = cursor;
    pos = ngx_http_pack_skip_whitespace(pos, end);
    if (pos == end || *pos++ != ';') {
        return 0;
    }

    pos = ngx_http_pack_skip_whitespace(pos, end);
    if (pos == end || (*pos != 'q' && *pos != 'Q')) {
        return 0;
    }

    pos++;
    pos = ngx_http_pack_skip_whitespace(pos, end);
    if (pos == end || *pos++ != '=') {
        return 0;
    }

    /* Any weight not starting with "0" is non-zero. */
    pos = ngx_http_pack_skip_whitespace(pos, end);
    if (pos == end || *pos++ != '0') {
        return 0;
    }

    /* "q=0" with nothing after it, or with no fraction. */
    if (pos == end || *pos != '.') {
        return 1;
    }

    pos++;
    /* RFC 9110 permits at most three digits after the point. */
    for (digits = 0; digits < 3; digits++) {
        if (pos == end) {
            return 1; /* "q=0." */
        }

        if (*pos < '0' || *pos > '9') {
            return 1;
        }

        if (*pos > '0') {
            return 0; /* a non-zero digit */
        }

        pos++;
    }

    return 1;
}

/* The three ways Accept-Encoding can leave one encoding: named with a
   non-zero weight, named with an explicit zero weight ("not
   acceptable" per RFC 9110), or never named at all - which
   ngx_http_pack_check_encoding folds into a plain accept/reject
   answer, and the "always" claim below tells apart: silence is not
   the same as a client that named the encoding to rule it out. */
typedef enum {
    NGX_HTTP_PACK_ENCODING_ACCEPTED,
    NGX_HTTP_PACK_ENCODING_REFUSED,
    NGX_HTTP_PACK_ENCODING_UNLISTED,
} encoding_verdict_e;

/* The scan behind both ngx_http_pack_check_encoding and the "always"
   claim path: reads Accept-Encoding as a comma-separated token list
   and reports which of the three ways above it leaves "encoding" in.
   The weight is read only for an explicit zero; "*" is ignored. */
static encoding_verdict_e
ngx_http_pack_check_encoding_verdict(
    ngx_http_request_t *const r, ngx_str_t const *const encoding)
{
    ngx_table_elt_t *entry;
    u_char          *start;
    u_char          *end;
    u_char          *cursor;
    u_char           before;
    u_char           after;
    ngx_uint_t       refused;

    entry = r->headers_in.accept_encoding;
    if (entry == NULL) {
        return NGX_HTTP_PACK_ENCODING_UNLISTED;
    }

    refused = 0;

    start  = entry->value.data;
    end    = start + entry->value.len;
    cursor = start;
    for (;;) {
        /* Bounded search, so a header without a terminating NUL
           can not be run off the end of. */
        cursor = ngx_strlcasestrn(
            cursor, end, encoding->data, encoding->len - 1);
        if (cursor == NULL) {
            break;
        }

        /* The token has to stand alone; reject a match inside a
           longer one - "zstd" must not match "zstdandard" or
           "x-zstd", nor "br" match "brotli". A match at either edge
           of the header is treated as if a separator sat beside
           it. */
        if (cursor == start) {
            before = ',';
        } else {
            before = cursor[-1];
        }

        cursor += encoding->len;
        if (cursor == end) {
            after = ',';
        } else {
            after = *cursor;
        }

        if (before != ',' && !ngx_http_pack_is_whitespace(before)) {
            continue;
        }

        /* ";" ends the token as surely as a comma does: what follows
           is the weight, read below only for an explicit zero. */
        if (after != ',' && after != ';' &&
            !ngx_http_pack_is_whitespace(after)) {
            continue;
        }

        /* A zero weight rejects this token, but not the header: the
           same encoding may be named again further along, so keep
           searching - noted here and not decided until the search
           runs out, since a later occurrence may still accept it. */
        if (!ngx_http_pack_is_zero_weighted(cursor, end)) {
            return NGX_HTTP_PACK_ENCODING_ACCEPTED;
        }

        refused = 1;
    }

    return refused ? NGX_HTTP_PACK_ENCODING_REFUSED
                   : NGX_HTTP_PACK_ENCODING_UNLISTED;
}

/* Decides whether the client will accept a given "encoding". NGX_OK
   only for NGX_HTTP_PACK_ENCODING_ACCEPTED, NGX_DECLINED for either
   of the other two verdicts - the ordinary claim path has no need to
   tell a refusal from silence. */
static ngx_int_t
ngx_http_pack_check_encoding(
    ngx_http_request_t *const r, ngx_str_t const *const encoding)
{
    return ngx_http_pack_check_encoding_verdict(r, encoding) ==
                   NGX_HTTP_PACK_ENCODING_ACCEPTED
               ? NGX_OK
               : NGX_DECLINED;
}

/* Sets the Content-Encoding header with the given encoding.
   Returns NGX_OK on success, NGX_ERROR otherwise. */
static ngx_int_t
ngx_http_pack_set_encoding(
    ngx_http_request_t *const r, ngx_str_t const *const encoding)
{
    ngx_table_elt_t *entry;

    entry = ngx_list_push(&r->headers_out.headers);
    if (entry == NULL) {
        return NGX_ERROR;
    }

    entry->hash = 1;
    entry->next = NULL;

    ngx_str_set(&entry->key, "Content-Encoding");
    entry->value = *encoding;

    r->headers_out.content_encoding = entry;

    return NGX_OK;
}

/* Decides whether this request should be served "encoding" at all.

   Returns NGX_OK only for a main request from a client that named
   the encoding and speaks at least HTTP/1.1, NGX_DECLINED otherwise.
   */
static ngx_int_t
ngx_http_pack_claim_request(
    ngx_http_request_t *const r, ngx_str_t const *const encoding)
{
    if (r != r->main) {
        return NGX_DECLINED;
    }

    if (r->http_version < NGX_HTTP_VERSION_11) {
        return NGX_DECLINED;
    }

    if (ngx_http_pack_check_encoding(r, encoding) != NGX_OK) {
        return NGX_DECLINED;
    }

    return NGX_OK;
}

/* The "always" counterpart to ngx_http_pack_claim_request: a client
   that never mentioned "encoding" is claimed anyway, on the theory
   that silence is not refusal - but a client that named it with an
   explicit zero weight still means what that says, so that case alone
   still declines. The main-request and HTTP-version guards are
   unchanged; those are not about what the client will accept. */
static inline ngx_int_t
ngx_http_pack_claim_request_always(
    ngx_http_request_t *const r, ngx_str_t const *const encoding)
{
    if (r != r->main) {
        return NGX_DECLINED;
    }

    if (r->http_version < NGX_HTTP_VERSION_11) {
        return NGX_DECLINED;
    }

    if (ngx_http_pack_check_encoding_verdict(r, encoding) ==
        NGX_HTTP_PACK_ENCODING_REFUSED) {
        return NGX_DECLINED;
    }

    return NGX_OK;
}

/* Checks whether the given header is "Vary: Accept-Encoding".
   Returns NGX_OK on a match, NGX_DECLINED otherwise. */
static ngx_int_t
ngx_http_pack_check_vary(ngx_table_elt_t *const header)
{
    static u_char const vary[]     = "Vary";
    static u_char const encoding[] = "Accept-Encoding";

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
   shared cache cannot hand an encoded response to a client that
   never asked for one.
   Returns NGX_OK on success, NGX_ERROR otherwise. */
static ngx_int_t
ngx_http_pack_set_vary(ngx_http_request_t *const r)
{
    ngx_list_part_t *part;
    ngx_table_elt_t *header;
    ngx_uint_t       idx;
    ngx_table_elt_t *vary;

#if (NGX_HTTP_GZIP)
    ngx_http_core_loc_conf_t *clcf;

    /* This keeps the two modules (this and gzip) from producing
       "Vary: Accept-Encoding" twice. With the directive off nginx
       writes nothing and clears the flag again, which is the case
       the header below exists for. */
    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
    if (clcf->gzip_vary) {
        r->gzip_vary = 1;
        return NGX_OK;
    }
#endif

    part   = &r->headers_out.headers.part;
    header = part->elts;

    for (idx = 0; /* void */; idx++) {
        if (idx >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part   = part->next;
            header = part->elts;
            idx    = 0;
        }

        /* hash 0 marks an entry the filters below are to ignore. */
        if (header[idx].hash == 0) {
            continue;
        }

        if (ngx_http_pack_check_vary(&header[idx]) == NGX_OK) {
            return NGX_OK;
        }
    }

    vary = ngx_list_push(&r->headers_out.headers);
    if (vary == NULL) {
        return NGX_ERROR;
    }

    vary->hash = 1;
    vary->next = NULL;

    ngx_str_set(&vary->key, "Vary");
    ngx_str_set(&vary->value, "Accept-Encoding");

    return NGX_OK;
}

#endif /* NGX_HTTP_PACK_HEADERS_H_INCLUDED_ */
