/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) Google Inc.
 * Copyright (C) 2026 Juri Torhoff
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "../common/ngx_http_pack_headers.h"


enum {
    NGX_HTTP_PACK_STATIC_OFF = 0,
    NGX_HTTP_PACK_STATIC_ON,
    NGX_HTTP_PACK_STATIC_ALWAYS
};

/* Which pre-compressed siblings the module may serve. One bit each,
   rather than the counting values above, because the directive takes
   several at once and ngx_conf_set_bitmask_slot ORs them together.
   Spelled out in hex as nginx spells its own bitmasks, so that
   adding a fourth is visibly the next bit rather than the next
   number.

   Deliberately not sharing the NGX_HTTP_PACK_STATIC_ prefix's
   counting values: NGX_HTTP_PACK_STATIC_ON and a first bit would
   both be 1, and the two are never interchangeable. */
enum {
    NGX_HTTP_PACK_STATIC_ENCODING_BR   = 0x0001,
    NGX_HTTP_PACK_STATIC_ENCODING_GZIP = 0x0002,
    NGX_HTTP_PACK_STATIC_ENCODING_ZSTD = 0x0004
};

typedef struct {
    ngx_uint_t enable;
    ngx_uint_t encodings;
} ngx_http_pack_static_conf_t;

static ngx_conf_enum_t ngx_http_pack_static[] = {
    {ngx_string("off"),    .value = NGX_HTTP_PACK_STATIC_OFF   },
    {ngx_string("on"),     .value = NGX_HTTP_PACK_STATIC_ON    },
    {ngx_string("always"), .value = NGX_HTTP_PACK_STATIC_ALWAYS},
    {ngx_null_string,      0                                   }
};

static ngx_conf_bitmask_t ngx_http_pack_static_encodings[] = {
    {ngx_string("br"),   NGX_HTTP_PACK_STATIC_ENCODING_BR  },
    {ngx_string("gzip"), NGX_HTTP_PACK_STATIC_ENCODING_GZIP},
    {ngx_string("zstd"), NGX_HTTP_PACK_STATIC_ENCODING_ZSTD},
    {ngx_null_string,    0                                 }
};

/* One row per encoding the module knows: the bit that selects it,
   the token it goes by in Accept-Encoding and Content-Encoding, and
   the suffix its pre-compressed sibling carries.

   Probed in the order written here, which is fixed rather than the
   order the directive named them in - ngx_conf_set_bitmask_slot
   hands back a set, so what the admin typed is not recoverable.
   Smallest output first, so a client that takes several is served
   the tightest sibling that exists rather than the first one
   configured.

   Kept in step with ngx_http_pack_static_encodings by hand. The two
   are separate because the directive needs an ngx_conf_bitmask_t and
   that type has nowhere to put a suffix. */
typedef struct {
    ngx_uint_t bit;
    ngx_str_t  name;
    ngx_str_t  extension;
} ngx_http_pack_static_sibling_t;

static ngx_http_pack_static_sibling_t
    ngx_http_pack_static_siblings[] = {
        {NGX_HTTP_PACK_STATIC_ENCODING_BR,   ngx_string("br"),
         ngx_string(".br") },
        {NGX_HTTP_PACK_STATIC_ENCODING_ZSTD, ngx_string("zstd"),
         ngx_string(".zst")},
        {NGX_HTTP_PACK_STATIC_ENCODING_GZIP, ngx_string("gzip"),
         ngx_string(".gz") }
};

#define NGX_HTTP_PACK_STATIC_NSIBLINGS                               \
    (sizeof(ngx_http_pack_static_siblings) /                         \
        sizeof(ngx_http_pack_static_siblings[0]))

static ngx_int_t ngx_http_pack_static_handler(ngx_http_request_t *r);
static void *ngx_http_pack_static_create_conf(ngx_conf_t *cf);
static char *ngx_http_pack_static_merge_conf(
    ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t ngx_http_pack_static_init(ngx_conf_t *cf);

/* Kept by hand: AlignArrayOfStructures would pad these rows past
   the column limit. See .clang-format. */
/* clang-format off */
static ngx_command_t ngx_http_pack_static_commands[] = {
    {ngx_string("pack_static"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
            NGX_CONF_TAKE1,
        ngx_conf_set_enum_slot, NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_pack_static_conf_t, enable),
        &ngx_http_pack_static},

    /* 1MORE rather than TAKE123: the count is already bounded by the
       mask having three entries, and a repeated one is a warning
       from ngx_conf_set_bitmask_slot rather than an error, so a
       fourth argument is caught either way - with a message naming
       the offending value instead of counting arguments. */
    {ngx_string("pack_static_encodings"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
            NGX_CONF_1MORE,
        ngx_conf_set_bitmask_slot, NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_pack_static_conf_t, encodings),
        &ngx_http_pack_static_encodings},

    ngx_null_command};
/* clang-format on */

static ngx_http_module_t ngx_http_pack_static_module_ctx = {
    NULL,                             /* preconfiguration */
    ngx_http_pack_static_init,        /* postconfiguration */

    NULL,                             /* create main conf */
    NULL,                             /* init main conf */

    NULL,                             /* create server conf */
    NULL,                             /* merge server conf */

    ngx_http_pack_static_create_conf, /* create location conf */
    ngx_http_pack_static_merge_conf   /* merge location conf */
};

ngx_module_t ngx_http_pack_static_module = {NGX_MODULE_V1,
    &ngx_http_pack_static_module_ctx, /* module context */
    ngx_http_pack_static_commands,    /* module directives */
    NGX_HTTP_MODULE,                  /* module type */
    NULL,                             /* init master */
    NULL,                             /* init module */
    NULL,                             /* init process */
    NULL,                             /* init thread */
    NULL,                             /* exit thread */
    NULL,                             /* exit process */
    NULL,                             /* exit master */
    NGX_MODULE_V1_PADDING};

static ngx_int_t
ngx_http_pack_static_handler(ngx_http_request_t *r)
{
    ngx_http_pack_static_conf_t    *conf;
    ngx_http_pack_static_sibling_t *sibling;
    ngx_http_pack_static_sibling_t *found;
    u_char                         *last;
    u_char                         *suffix;
    ngx_str_t                       path;
    size_t                          root_len;
    size_t                          reserve;
    ngx_uint_t                      i;
    ngx_log_t                      *log;
    ngx_http_core_loc_conf_t       *core_conf;
    ngx_open_file_info_t            file_info;
    ngx_int_t                       rc;
    ngx_uint_t                      level;
    ngx_buf_t                      *buf;
    ngx_chain_t                     out;

    /* Only GET and HEAD requests are supported. */
    if (!(r->method & (NGX_HTTP_GET | NGX_HTTP_HEAD))) {
        return NGX_DECLINED;
    }

    /* A URI ending in "/" names a directory, not a file to serve. */
    if (r->uri.data[r->uri.len - 1] == '/') {
        return NGX_DECLINED;
    }

    conf = ngx_http_get_module_loc_conf(
        r, ngx_http_pack_static_module);
    if (conf->enable == NGX_HTTP_PACK_STATIC_OFF) {
        return NGX_DECLINED;
    }

    log       = r->connection->log;
    core_conf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    /* Set once, before any Accept-Encoding test, and left in place
       even when this handler declines: what varies is the resource,
       not this one request. "always" needs none of it, serving the
       same bytes to everyone. */
    if (conf->enable == NGX_HTTP_PACK_STATIC_ON &&
        ngx_http_pack_set_vary(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Room for the longest suffix any candidate might need. The path
       is mapped once and each candidate's suffix is written over the
       last, so the reservation has to cover the widest of them rather
       than the first. */
    reserve = 0;
    for (i = 0; i < NGX_HTTP_PACK_STATIC_NSIBLINGS; i++) {
        if (ngx_http_pack_static_siblings[i].extension.len >
            reserve) {
            reserve = ngx_http_pack_static_siblings[i].extension.len;
        }
    }

    /* Get the path. ngx_http_map_uri_to_path leaves path.len holding
       the size of the buffer it allocated - the path, the room asked
       for here, and a terminating zero - not the length of the string
       in it. So the length has to come from the write pointer, as
       nginx's own gzip_static does; adding the suffix length to what
       it returned would overshoot the string and the allocation.
       ngx_cpystrn returns the terminating zero it wrote, which is
       that pointer. */
    last = ngx_http_map_uri_to_path(r, &path, &root_len, reserve);
    if (last == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Where every candidate's suffix goes, one after another. */
    suffix = last;

    found = NULL;
    for (i = 0; i < NGX_HTTP_PACK_STATIC_NSIBLINGS; i++) {
        sibling = &ngx_http_pack_static_siblings[i];

        if (!(conf->encodings & sibling->bit)) {
            continue;
        }

        /* "always" serves whatever sibling is on disk whatever the
           request said about encodings, so only "on" has to ask. */
        if (conf->enable == NGX_HTTP_PACK_STATIC_ON &&
            ngx_http_pack_claim_request(r, &sibling->name) !=
                NGX_OK) {
            continue;
        }

        last     = ngx_cpystrn(suffix, sibling->extension.data,
                sibling->extension.len + 1);
        path.len = last - path.data;

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
            "http filename: \"%s\"", path.data);

        /* Prepare to read the file. Re-zeroed per candidate:
           ngx_open_cached_file both reads this and writes its result
           back into it, so carrying one candidate's fields into the
           next would test the wrong file. */
        ngx_memzero(&file_info, sizeof(ngx_open_file_info_t));

        file_info.read_ahead = core_conf->read_ahead;
        file_info.directio   = core_conf->directio;
        file_info.valid      = core_conf->open_file_cache_valid;
        file_info.min_uses   = core_conf->open_file_cache_min_uses;
        file_info.errors     = core_conf->open_file_cache_errors;
        file_info.events     = core_conf->open_file_cache_events;

        rc = ngx_http_set_disable_symlinks(
            r, core_conf, &path, &file_info);
        if (rc != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        /* Try to fetch file and process errors. The "continue"s below
           belong to the for, not to the switch - a missing sibling is
           the ordinary case here, and the next candidate is still
           worth a look. */
        rc = ngx_open_cached_file(
            core_conf->open_file_cache, &path, &file_info, r->pool);
        if (rc != NGX_OK) {
            switch (file_info.err) {
                case 0:
                    return NGX_HTTP_INTERNAL_SERVER_ERROR;

                case NGX_ENOENT:
                case NGX_ENOTDIR:
                case NGX_ENAMETOOLONG:
                    continue;

#if (NGX_HAVE_OPENAT)
                case NGX_EMLINK:
                case NGX_ELOOP:
#endif
                case NGX_EACCES:
                    level = NGX_LOG_ERR;
                    break;

                default:
                    level = NGX_LOG_CRIT;
                    break;
            }

            ngx_log_error(level, log, file_info.err,
                "%s \"%s\" failed", file_info.failed, path.data);

            continue;
        }

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
            "http static fd: %d", file_info.fd);

        /* The suffixed path is not a file we can serve. */
        if (file_info.is_dir) {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, log, 0, "http dir");
            continue;
        }
#if !(NGX_WIN32)
        if (!file_info.is_file) {
            ngx_log_error(NGX_LOG_CRIT, log, 0,
                "\"%s\" is not a regular file", path.data);
            return NGX_HTTP_NOT_FOUND;
        }
#endif

        found = sibling;
        break;
    }

    /* No encoding the client would take had a sibling on disk, so
       leave the request to the static handler behind this one. */
    if (found == NULL) {
        return NGX_DECLINED;
    }

    /* Discard the request body, then describe the response. */
    r->root_tested = !r->error_page;

    rc = ngx_http_discard_request_body(r);
    if (rc != NGX_OK) {
        return rc;
    }

    log->action = "sending response to client";

    r->headers_out.status             = NGX_HTTP_OK;
    r->headers_out.content_length_n   = file_info.size;
    r->headers_out.last_modified_time = file_info.mtime;

    rc = ngx_http_set_etag(r);
    if (rc != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    rc = ngx_http_set_content_type(r);
    if (rc != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Set "Content-Encoding" header. */
    if (ngx_http_pack_set_encoding(r, &found->name) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Setup response body. */
    buf = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
    if (buf == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    buf->file = ngx_pcalloc(r->pool, sizeof(ngx_file_t));
    if (buf->file == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    buf->file_pos       = 0;
    buf->file_last      = file_info.size;
    buf->in_file        = buf->file_last ? 1 : 0;
    buf->last_buf       = (r == r->main) ? 1 : 0;
    buf->last_in_chain  = 1;
    buf->file->fd       = file_info.fd;
    buf->file->name     = path;
    buf->file->log      = log;
    buf->file->directio = file_info.is_directio;

    out.buf  = buf;
    out.next = NULL;

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    return ngx_http_output_filter(r, &out);
}

static void *
ngx_http_pack_static_create_conf(ngx_conf_t *cf)
{
    ngx_http_pack_static_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_pack_static_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->enable = NGX_CONF_UNSET_UINT;

    /* conf->encodings is deliberately left at the zero ngx_pcalloc
       wrote. A bitmask has no spare value to mean "unset" - every bit
       is a legal encoding - so nginx reserves the empty set for it,
       and that is what ngx_conf_merge_bitmask_value tests for.
       Setting NGX_CONF_UNSET_UINT here would read as every bit set
       and inherit nothing. */

    return conf;
}

/* Whether this pair leaves the served encoding up to whichever
   sibling happens to exist. "always" skips the Accept-Encoding test,
   so with more than one encoding configured the client gets whatever
   the probe reaches first, with no say in it.

   "n & (n - 1)" clears the lowest set bit: what is left is non-zero
   only if some other bit was set too. It reads an unset mask, zero,
   as not ambiguous, which is what the caller below wants of a parent
   that named no encodings. */
static ngx_uint_t
ngx_http_pack_static_is_ambiguous(
    ngx_uint_t enable, ngx_uint_t encodings)
{
    return enable == NGX_HTTP_PACK_STATIC_ALWAYS &&
           (encodings & (encodings - 1)) != 0;
}

static char *
ngx_http_pack_static_merge_conf(
    ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_pack_static_conf_t *prev;
    ngx_http_pack_static_conf_t *conf;
    ngx_uint_t                   inherited;

    prev = parent;
    conf = child;

    /* Whether the block above was already ambiguous, so that the
       warning below lands where the combination first takes effect
       rather than repeating down every block that inherits it.
       nginx runs a merge per location, and the enclosing http{} is
       only ever a parent - it is never passed as a child - so asking
       "did this block write it" would miss a setting made there
       entirely. Asking what the parent already meant does not. */
    inherited = ngx_http_pack_static_is_ambiguous(
        prev->enable, prev->encodings);

    ngx_conf_merge_uint_value(
        conf->enable, prev->enable, NGX_HTTP_PACK_STATIC_OFF);

    ngx_conf_merge_bitmask_value(conf->encodings, prev->encodings,
        NGX_HTTP_PACK_STATIC_ENCODING_BR |
            NGX_HTTP_PACK_STATIC_ENCODING_GZIP |
            NGX_HTTP_PACK_STATIC_ENCODING_ZSTD);

    /* Warned about rather than rejected, since the combination is
       servable - a location whose clients are all known to take the
       same encoding is a fair use of it. */
    if (!inherited && ngx_http_pack_static_is_ambiguous(
                          conf->enable, conf->encodings)) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
            "\"pack_static always\" with more than one encoding in "
            "\"pack_static_encodings\" serves whatever is found "
            "first to every client");
    }

    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_pack_static_init(ngx_conf_t *cf)
{
    ngx_http_core_main_conf_t *main_conf;
    ngx_http_handler_pt       *handler_slot;

    main_conf = ngx_http_conf_get_module_main_conf(
        cf, ngx_http_core_module);

    handler_slot = ngx_array_push(
        &main_conf->phases[NGX_HTTP_CONTENT_PHASE].handlers);
    if (handler_slot == NULL) {
        return NGX_ERROR;
    }

    *handler_slot = ngx_http_pack_static_handler;

    return NGX_OK;
}
