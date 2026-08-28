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
    NGX_HTTP_PACK_STATIC_ALWAYS,
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
    NGX_HTTP_PACK_STATIC_ENCODING_ZSTD = 0x0004,
};

typedef struct {
    ngx_uint_t enable;
    ngx_uint_t encodings;
} pack_conf_t;

static ngx_conf_enum_t ngx_http_pack_static[] = {
    {
        .name  = ngx_string("off"),
        .value = NGX_HTTP_PACK_STATIC_OFF,
    },
    {
        .name  = ngx_string("on"),
        .value = NGX_HTTP_PACK_STATIC_ON,
    },
    {
        .name  = ngx_string("always"),
        .value = NGX_HTTP_PACK_STATIC_ALWAYS,
    },
    {
        .name  = ngx_null_string,
        .value = 0,
    },
};

static ngx_conf_bitmask_t ngx_http_pack_static_encodings[] = {
    {
        .name = ngx_string("br"),
        .mask = NGX_HTTP_PACK_STATIC_ENCODING_BR,
    },
    {
        .name = ngx_string("gzip"),
        .mask = NGX_HTTP_PACK_STATIC_ENCODING_GZIP,
    },
    {
        .name = ngx_string("zstd"),
        .mask = NGX_HTTP_PACK_STATIC_ENCODING_ZSTD,
    },
    {
        .name = ngx_null_string,
        .mask = 0,
    },
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
    ngx_uint_t mask;
    ngx_str_t  name;
    ngx_str_t  ext;
} pack_sibling_t;

static pack_sibling_t const ngx_http_pack_static_siblings[] = {
    {
        .mask = NGX_HTTP_PACK_STATIC_ENCODING_BR,
        .name = ngx_string("br"),
        .ext  = ngx_string(".br"),
    },
    {
        .mask = NGX_HTTP_PACK_STATIC_ENCODING_GZIP,
        .name = ngx_string("gzip"),
        .ext  = ngx_string(".gz"),
    },
    {
        .mask = NGX_HTTP_PACK_STATIC_ENCODING_ZSTD,
        .name = ngx_string("zstd"),
        .ext  = ngx_string(".zst"),
    },
};

#define NGX_HTTP_PACK_STATIC_NSIBLINGS                               \
    (sizeof(ngx_http_pack_static_siblings) / sizeof(pack_sibling_t))

/* clang-format off */
static ngx_int_t ngx_http_pack_static_handler(
    ngx_http_request_t *r
);
static void *ngx_http_pack_static_create_conf(
    ngx_conf_t *cf
);
static char *ngx_http_pack_static_merge_conf(
    ngx_conf_t *cf,
    void *parent,
    void *child
);
static ngx_int_t ngx_http_pack_static_init(
    ngx_conf_t *cf
);
/* clang-format on */

/* Fenced for the contexts below, which are written one per line so
   that adding or dropping one is a one-line diff. clang-format would
   pack them back together; the trailing commas that hold the tables
   above in shape do not reach inside an expression. */
static ngx_command_t ngx_http_pack_static_commands[] = {
    {
        ngx_string("pack_static"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
            NGX_CONF_TAKE1,
        ngx_conf_set_enum_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(pack_conf_t, enable),
        &ngx_http_pack_static,
    },
    /* 1MORE rather than TAKE123: the mask has three entries, so the
       count is already bounded, and a repeated value is a warning
       from ngx_conf_set_bitmask_slot rather than an error. A fourth
       argument is caught either way, with a message naming the
       offending value instead of counting arguments. */
    {
        ngx_string("pack_static_encodings"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
            NGX_CONF_1MORE,
        ngx_conf_set_bitmask_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(pack_conf_t, encodings),
        &ngx_http_pack_static_encodings,
    },
    ngx_null_command,
};

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

ngx_module_t ngx_http_pack_static_module = {
    NGX_MODULE_V1,
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
    NGX_MODULE_V1_PADDING,
};

typedef struct {
    ngx_http_request_t *request;
    ngx_str_t          *path;
    u_char            **suffix;
} pack_preflight_args_t;

/* Settles everything that holds for the request as a whole, before
   any one encoding is considered: whether this handler has business
   here at all, the Vary the answer will carry either way, and the
   path buffer the candidates are written into.

   Returns NGX_OK with path mapped and suffix pointing at the room
   reserved after it, NGX_DECLINED to leave the request to the handler
   behind this one, or an HTTP status that finishes it. */
static ngx_int_t
ngx_http_pack_static_preflight(pack_preflight_args_t *const args)
{
    ngx_http_request_t *r;
    pack_conf_t        *conf;
    size_t              reserved;
    ngx_uint_t          idx;
    pack_sibling_t     *sibling;
    size_t              root_len;

    r = args->request;

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
    reserved = 0;
    for (idx = 0; idx < NGX_HTTP_PACK_STATIC_NSIBLINGS; idx++) {
        sibling =
            (pack_sibling_t *) &ngx_http_pack_static_siblings[idx];
        if (sibling->ext.len > reserved) {
            reserved = sibling->ext.len;
        }
    }

    /* Get the path. ngx_http_map_uri_to_path leaves path.len holding
       the size of the buffer it allocated - the path, the room asked
       for here, and a terminating zero - not the length of the string
       in it. So the length has to come from the write pointer, as
       nginx's own gzip_static does; adding the suffix length to what
       it returned would overshoot the string and the allocation. The
       pointer it returns is where every candidate's suffix goes, one
       after another, and each sets path.len to match. */
    *args->suffix = ngx_http_map_uri_to_path(
        r, args->path, &root_len, reserved);
    if (*args->suffix == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    return NGX_OK;
}

typedef struct {
    ngx_http_core_loc_conf_t *conf;
    ngx_open_file_info_t     *file_info;
} pack_prepare_file_info_args_t;

/* Fills in what ngx_open_cached_file consults before it opens
   anything: the read-ahead and directio thresholds, and the terms the
   open file cache is to be used on.

   Zeroed first because one struct serves every candidate in turn and
   ngx_open_cached_file writes its result back into the same fields it
   reads. Carrying one candidate's over would describe the wrong
   file. */
static void
ngx_http_pack_static_prepare_file_info(
    pack_prepare_file_info_args_t *const args)
{
    ngx_memzero(args->file_info, sizeof(ngx_open_file_info_t));

    args->file_info->read_ahead = args->conf->read_ahead;
    args->file_info->directio   = args->conf->directio;

    args->file_info->events   = args->conf->open_file_cache_events;
    args->file_info->errors   = args->conf->open_file_cache_errors;
    args->file_info->min_uses = args->conf->open_file_cache_min_uses;
    args->file_info->valid    = args->conf->open_file_cache_valid;
}

typedef struct {
    ngx_http_request_t       *request;
    ngx_http_core_loc_conf_t *conf;
    ngx_str_t                *path;
    ngx_open_file_info_t     *file_info;
} pack_stat_args_t;

/* Opens whatever the path now names and says whether it can be
   served. The name understates it: ngx_open_cached_file returns a
   descriptor, not just the stat that decides.

   Returns NGX_OK with file_info describing an open file, NGX_DECLINED
   when there is nothing usable there - a missing sibling being the
   ordinary case rather than a failure - or an HTTP status that
   finishes the request. What an operator would want to know about is
   logged first, then declined like the rest. */
static ngx_int_t
ngx_http_pack_static_stat(pack_stat_args_t *const args)
{
    ngx_int_t  rc;
    ngx_uint_t level;

    rc = ngx_http_set_disable_symlinks(
        args->request, args->conf, args->path, args->file_info);
    if (rc != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    rc = ngx_open_cached_file(args->conf->open_file_cache, args->path,
        args->file_info, args->request->pool);
    if (rc == NGX_OK) {
        return NGX_OK;
    }

    switch (args->file_info->err) {
        case 0:
            return NGX_HTTP_INTERNAL_SERVER_ERROR;

        case NGX_ENOENT:
        case NGX_ENOTDIR:
        case NGX_ENAMETOOLONG:
            return NGX_DECLINED;

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

    ngx_log_error(level, args->request->connection->log,
        args->file_info->err, "%s \"%s\" failed",
        args->file_info->failed, args->path->data);

    return NGX_DECLINED;
}

typedef struct {
    ngx_http_request_t   *request;
    pack_sibling_t       *sibling;
    ngx_str_t            *path;
    u_char               *suffix;
    ngx_open_file_info_t *file_info;
} pack_try_sibling_args_t;

/* Tries one encoding: writes its suffix over "suffix", which points
   into the room ngx_http_map_uri_to_path reserved, and opens what
   that names.

   Three outcomes, so the caller can stay a loop. NGX_OK means the
   sibling is open and servable, with file_info describing it and path
   naming it. NGX_DECLINED means this encoding is not on offer or has
   no sibling worth serving, and the next candidate is still worth a
   look. Anything else is an HTTP status that finishes the request. */
static ngx_int_t
ngx_http_pack_static_try_sibling(pack_try_sibling_args_t *const args)
{
    pack_conf_t              *conf;
    ngx_http_core_loc_conf_t *core_conf;
    u_char                   *last;
    ngx_log_t                *log;
    ngx_int_t                 rc;

    conf = ngx_http_get_module_loc_conf(
        args->request, ngx_http_pack_static_module);
    if (!(conf->encodings & args->sibling->mask)) {
        return NGX_DECLINED;
    }

    /* "always" serves whatever is on disk to everyone, so only
       "on" has to ask whether this client takes the encoding. */
    if (conf->enable == NGX_HTTP_PACK_STATIC_ON &&
        ngx_http_pack_claim_request(
            args->request, &args->sibling->name) != NGX_OK) {
        return NGX_DECLINED;
    }

    core_conf = ngx_http_get_module_loc_conf(
        args->request, ngx_http_core_module);

    /* ngx_cpystrn returns the terminating zero it wrote, which is
       where the string now ends. */
    last = ngx_cpystrn(args->suffix, args->sibling->ext.data,
        args->sibling->ext.len + 1);

    args->path->len = last - args->path->data;

    log = args->request->connection->log;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
        "http filename: \"%s\"", args->path->data);

    ngx_http_pack_static_prepare_file_info(
        &(pack_prepare_file_info_args_t) {
            .conf      = core_conf,
            .file_info = args->file_info,
        });

    rc = ngx_http_pack_static_stat(&(pack_stat_args_t) {
        .request   = args->request,
        .conf      = core_conf,
        .path      = args->path,
        .file_info = args->file_info,
    });
    if (rc != NGX_OK) {
        return rc;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0, "http static fd: %d",
        args->file_info->fd);

    /* The suffixed path is not a file we can serve. */
    if (args->file_info->is_dir) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, log, 0, "http dir");
        return NGX_DECLINED;
    }
#if !(NGX_WIN32)
    if (!args->file_info->is_file) {
        ngx_log_error(NGX_LOG_CRIT, log, 0,
            "\"%s\" is not a regular file", args->path->data);
        return NGX_HTTP_NOT_FOUND;
    }
#endif

    return NGX_OK;
}

typedef struct {
    ngx_http_request_t   *request;
    ngx_open_file_info_t *file_info;
    ngx_str_t            *encoding;
} pack_set_headers_args_t;

/* Sends the open sibling as the whole response body: one buffer that
   is the file itself, which the output filters turn into a sendfile
   or a read, so nothing is copied through the worker.

   The headers have been described by the caller and go out here.
   Returns whatever the filter chain returns, which the handler passes
   straight back to nginx. */
/* Describes the response the found sibling will be: its size and
   mtime, the ETag and Content-Type derived from them, and the
   Content-Encoding that says which sibling this is. Nothing goes out
   yet - ngx_http_pack_static_send sends the headers along with the
   body, once the buffer for it exists.

   Returns NGX_OK, or NGX_HTTP_INTERNAL_SERVER_ERROR if a header list
   could not be grown. */
static ngx_int_t
ngx_http_pack_static_set_headers(pack_set_headers_args_t *const args)
{
    ngx_http_request_t *r;

    r = args->request;

    r->connection->log->action = "sending response to client";

    r->headers_out.status             = NGX_HTTP_OK;
    r->headers_out.content_length_n   = args->file_info->size;
    r->headers_out.last_modified_time = args->file_info->mtime;

    if (ngx_http_set_etag(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (ngx_http_set_content_type(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Set "Content-Encoding" header. */
    if (ngx_http_pack_set_encoding(r, args->encoding) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Offers byte ranges over the sibling, which the range filter
       declines to do for anyone who has not said so. The ranges count
       in the bytes actually sent - the encoded ones - which is what a
       client resuming an interrupted download of this response asks
       for. Both of nginx's own file handlers set it here; without it
       a Range request is answered with the whole body and a 200. */
    r->allow_ranges = 1;

    return NGX_OK;
}

typedef struct {
    ngx_http_request_t   *request;
    ngx_open_file_info_t *file_info;
    ngx_str_t            *path;
} pack_send_args_t;

static ngx_int_t
ngx_http_pack_static_send(pack_send_args_t *const args)
{
    ngx_http_request_t *r;
    ngx_buf_t          *buf;
    ngx_chain_t         out;
    ngx_int_t           rc;

    r = args->request;

    buf = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
    if (buf == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    buf->file = ngx_pcalloc(r->pool, sizeof(ngx_file_t));
    if (buf->file == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    buf->file_pos  = 0;
    buf->file_last = args->file_info->size;

    buf->in_file = buf->file_last ? 1 : 0;

    buf->last_buf      = (r == r->main) ? 1 : 0;
    buf->last_in_chain = 1;

    buf->file->fd       = args->file_info->fd;
    buf->file->name     = *args->path;
    buf->file->directio = args->file_info->is_directio;
    buf->file->log      = r->connection->log;

    out.buf  = buf;
    out.next = NULL;

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    return ngx_http_output_filter(r, &out);
}

static ngx_int_t
ngx_http_pack_static_handler(ngx_http_request_t *const r)
{
    ngx_int_t            rc;
    ngx_str_t            path;
    u_char              *suffix;
    pack_sibling_t      *found;
    ngx_uint_t           idx;
    pack_sibling_t      *sibling;
    ngx_open_file_info_t file_info;

    rc = ngx_http_pack_static_preflight(&(pack_preflight_args_t) {
        .request = r,
        .path    = &path,
        .suffix  = &suffix,
    });
    if (rc != NGX_OK) {
        return rc;
    }

    found = NULL;
    for (idx = 0; idx < NGX_HTTP_PACK_STATIC_NSIBLINGS; idx++) {
        sibling =
            (pack_sibling_t *) &ngx_http_pack_static_siblings[idx];

        rc = ngx_http_pack_static_try_sibling(
            &(pack_try_sibling_args_t) {
                .request   = r,
                .sibling   = sibling,
                .path      = &path,
                .suffix    = suffix,
                .file_info = &file_info,
            });
        if (rc == NGX_OK) {
            found = sibling;
            break;
        }

        /* Anything but "try the next one" ends the request here. */
        if (rc != NGX_DECLINED) {
            return rc;
        }
    }

    /* No encoding the client would take had a sibling on disk, so
       leave the request to the static handler behind this one. */
    if (found == NULL) {
        return NGX_DECLINED;
    }

    /* Records that the document root has been shown to exist, which
       opening the sibling above just did. Its one reader is the log
       module, which stats the root before writing an access_log whose
       path contains a variable; the flag saves it that stat.

       Not simply 1: an error page can redirect the request into a
       location with a different root, and what was proven about this
       one says nothing about that one. */
    r->root_tested = !r->error_page;

    /* Discard the request body, then describe the response. */
    rc = ngx_http_discard_request_body(r);
    if (rc != NGX_OK) {
        return rc;
    }

    rc = ngx_http_pack_static_set_headers(&(pack_set_headers_args_t) {
        .request   = r,
        .file_info = &file_info,
        .encoding  = &found->name,
    });
    if (rc != NGX_OK) {
        return rc;
    }

    return ngx_http_pack_static_send(&(pack_send_args_t) {
        .request   = r,
        .path      = &path,
        .file_info = &file_info,
    });
}

static void *
ngx_http_pack_static_create_conf(ngx_conf_t *const cf)
{
    pack_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(pack_conf_t));
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

typedef struct {
    ngx_uint_t enable;
    ngx_uint_t encodings;
} pack_is_ambiguous_args_t;
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
    pack_is_ambiguous_args_t *const args)
{
    return (args->enable == NGX_HTTP_PACK_STATIC_ALWAYS) &&
           (args->encodings & (args->encodings - 1)) != 0;
}

static char *
ngx_http_pack_static_merge_conf(
    ngx_conf_t *const cf, void *const parent, void *const child)
{
    pack_conf_t *prev;
    pack_conf_t *conf;
    ngx_uint_t   inherited;

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
        &(pack_is_ambiguous_args_t) {
            .enable    = prev->enable,
            .encodings = prev->encodings,
        });

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
                          &(pack_is_ambiguous_args_t) {
                              .enable    = conf->enable,
                              .encodings = conf->encodings,
                          })) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
            "\"pack_static always\" with more than one encoding in "
            "\"pack_static_encodings\" serves whatever is found "
            "first to every client");
    }

    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_pack_static_init(ngx_conf_t *const cf)
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
