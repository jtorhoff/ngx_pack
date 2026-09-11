/*
   Copyright (C) Igor Sysoev
   Copyright (C) Nginx, Inc.
   Copyright (C) Google Inc.
   Copyright (C) 2026 Juri Torhoff
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

typedef struct {
    ngx_str_t name;
    ngx_str_t ext;
} encoding_t;

/* One row per encoding the module knows: the token it goes by in
   Accept-Encoding and Content-Encoding, and the suffix its
   pre-compressed sibling carries. */
static encoding_t const ngx_http_pack_static_encodings[] = {
    {
        .name = ngx_string("br"),
        .ext  = ngx_string(".br"),
    },
    {
        .name = ngx_string("zstd"),
        .ext  = ngx_string(".zst"),
    },
};

#define NGX_HTTP_PACK_STATIC_NENCODINGS                              \
    (sizeof(ngx_http_pack_static_encodings) / sizeof(encoding_t))

/* Rows of the table above, in the order the directive named them.
   A count of zero means it was not written in this block. */
typedef struct {
    ngx_uint_t enable;
    ngx_uint_t nencodings;
    /* Encodings specified at configuration processing time. */
    encoding_t const *encodings[NGX_HTTP_PACK_STATIC_NENCODINGS];
    /* Bookkeeping for merge_conf rather than configuration. */
    ngx_uint_t _warned;
} conf_t;

static ngx_conf_enum_t const ngx_http_pack_static_mode[] = {
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

/* Reads pack_static_encodings, keeping the order it was written in.
   An unknown value refuses the whole configuration; a repeat is a
   warning and then ignored. */
static char *
ngx_http_pack_static_set_encodings(
    ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    conf_t           *pcf;
    ngx_str_t        *value;
    ngx_uint_t        arg;
    encoding_t const *sibling_encoding;
    ngx_uint_t        idx;
    ngx_str_t const  *lhs;
    ngx_str_t const  *rhs;

    pcf = conf;
    /* Checks whether the pack_static_encodings directive has been
       specified in the same block already. */
    if (pcf->nencodings != 0) {
        return "is duplicate";
    }

    /* The dedupe is what bounds the count. NGX_CONF_1MORE sets no
       upper limit on arguments, but there are only three rows and
       each can be added once, so the fixed array cannot overflow. */
    value = cf->args->elts;
    for (arg = 1; arg < cf->args->nelts; arg++) {
        sibling_encoding = NULL;
        for (idx = 0; idx < NGX_HTTP_PACK_STATIC_NENCODINGS; idx++) {
            lhs = &ngx_http_pack_static_encodings[idx].name;
            rhs = &value[arg];

            if (lhs->len != rhs->len) {
                continue;
            }

            /* The directive's arguments are case-sensitive.
               Accept-Encoding is not: ngx_http_pack_check_encoding
               matches case-insensitively, as per RFC 9110. */
            if (ngx_strncmp(lhs->data, rhs->data, lhs->len)) {
                continue;
            }

            sibling_encoding = &ngx_http_pack_static_encodings[idx];
            break;
        }

        if (sibling_encoding == NULL) {
            ngx_conf_log_error(
                NGX_LOG_EMERG,
                cf,
                0,
                "invalid value \"%V\"",
                &value[arg]);
            return NGX_CONF_ERROR;
        }

        /* Checks whether the given encoding has been specified
           already. Logs a warning in this case. */
        {
            for (idx = 0; idx < pcf->nencodings; idx++) {
                if (pcf->encodings[idx] == sibling_encoding) {
                    break;
                }
            }

            if (idx != pcf->nencodings) {
                ngx_conf_log_error(
                    NGX_LOG_WARN,
                    cf,
                    0,
                    "duplicate value \"%V\"",
                    &value[arg]);
                continue;
            }
        }

        pcf->encodings[pcf->nencodings++] = sibling_encoding;
    }

    return NGX_CONF_OK;
}

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

static ngx_command_t const ngx_http_pack_static_commands[] = {
    {
        ngx_string("pack_static"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
            NGX_CONF_TAKE1,
        ngx_conf_set_enum_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(conf_t, enable),
        (void *) &ngx_http_pack_static_mode,
    },
    /* 1MORE rather than TAKE123: the setter names the offending
       value where an argument count could not, and the table's three
       rows bound the list anyway. Offset and post stay empty because
       that setter reaches the conf itself. */
    {
        ngx_string("pack_static_encodings"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
            NGX_CONF_1MORE,
        ngx_http_pack_static_set_encodings,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL,
    },
    ngx_null_command,
};

static ngx_http_module_t const ngx_http_pack_static_module_ctx = {
    NULL,                             /* pre-configuration */
    ngx_http_pack_static_init,        /* post-configuration */
    NULL,                             /* create main conf */
    NULL,                             /* init main conf */
    NULL,                             /* create server conf */
    NULL,                             /* merge server conf */
    ngx_http_pack_static_create_conf, /* create location conf */
    ngx_http_pack_static_merge_conf   /* merge location conf */
};

/* Not const, though the two tables above are: nginx writes into this
   struct at startup - ngx_preinit_modules sets "index" and "name",
   ngx_count_modules sets "ctx_index" - so a read-only placement dies
   with SIGBUS before the first request. */
ngx_module_t ngx_http_pack_static_module = {
    NGX_MODULE_V1,
    (void *) &ngx_http_pack_static_module_ctx, /* module context */
    (void *) ngx_http_pack_static_commands,    /* module directives */
    NGX_HTTP_MODULE,                           /* module type */
    NULL,                                      /* init master */
    NULL,                                      /* init module */
    NULL,                                      /* init process */
    NULL,                                      /* init thread */
    NULL,                                      /* exit thread */
    NULL,                                      /* exit process */
    NULL,                                      /* exit master */
    NGX_MODULE_V1_PADDING,
};

typedef struct {
    ngx_http_request_t *request;
} preflight_args;

typedef struct {
    ngx_int_t status;
    /* Both set only when status is NGX_OK: the mapped path, and
       where in its buffer a suffix may be written. */
    ngx_str_t path;
    u_char   *suffix;
} preflight_result;

/* Settles what holds for the request as a whole, so the loop below
   repeats none of it.

   NGX_OK leaves path mapped and suffix pointing at the reserved room;
   NGX_DECLINED leaves the request to the handler behind this one. */
static preflight_result
ngx_http_pack_static_preflight(preflight_args *const args)
{
    ngx_http_request_t *r;
    conf_t             *conf;
    size_t              reserved;
    ngx_uint_t          idx;
    encoding_t const   *sibling_encoding;
    u_char             *suffix;
    ngx_str_t           path;
    size_t              root_len;

    r = args->request;

    /* Only GET and HEAD requests are supported. */
    if (!(r->method & (NGX_HTTP_GET | NGX_HTTP_HEAD))) {
        return (preflight_result) {
            .status = NGX_DECLINED,
        };
    }

    /* A URI ending in "/" names a directory, not a file to serve. */
    if (r->uri.len > 0 && r->uri.data[r->uri.len - 1] == '/') {
        return (preflight_result) {
            .status = NGX_DECLINED,
        };
    }

    /* A subrequest's body is spliced into its parent's, so it has no
       headers to say what encoding it is in - compressed bytes would
       land mid-response labelled as nothing. claim_request refuses
       one too, but only under "on"; asked here, "always" cannot skip
       it either. */
    if (r != r->main) {
        return (preflight_result) {
            .status = NGX_DECLINED,
        };
    }

    conf = ngx_http_get_module_loc_conf(
        r, ngx_http_pack_static_module);
    if (conf->enable == NGX_HTTP_PACK_STATIC_OFF) {
        return (preflight_result) {
            .status = NGX_DECLINED,
        };
    }

    /* The path is mapped once and each candidate's suffix is written
       over the last, so the room reserved has to cover the widest
       suffix rather than the first. */
    reserved = 0;
    for (idx = 0; idx < NGX_HTTP_PACK_STATIC_NENCODINGS; idx++) {
        sibling_encoding = &ngx_http_pack_static_encodings[idx];
        if (sibling_encoding->ext.len > reserved) {
            reserved = sibling_encoding->ext.len;
        }
    }

    /* ngx_http_map_uri_to_path leaves path.len holding the size of
       the buffer it allocated, not the length of the string in it, so
       every candidate's length comes from the write pointer instead.
       Adding a suffix length to what it returned would overshoot both
       the string and the allocation. */
    suffix = ngx_http_map_uri_to_path(r, &path, &root_len, reserved);
    if (suffix == NULL) {
        return (preflight_result) {
            .status = NGX_HTTP_INTERNAL_SERVER_ERROR,
        };
    }

    return (preflight_result) {
        .status = NGX_OK,
        .path   = path,
        .suffix = suffix,
    };
}

typedef struct {
    ngx_http_core_loc_conf_t *conf;
} set_file_info_args;

typedef struct {
    ngx_open_file_info_t file_info;
} set_file_info_result;

/* Zeroed first because one struct serves every candidate in turn and
   ngx_open_cached_file writes its result back into the same fields it
   reads - carrying one candidate's over would describe the wrong
   file. */
static set_file_info_result
ngx_http_pack_static_set_file_info(set_file_info_args *const args)
{
    ngx_open_file_info_t file_info;

    ngx_memzero(&file_info, sizeof(ngx_open_file_info_t));

    file_info.read_ahead = args->conf->read_ahead;
    file_info.directio   = args->conf->directio;

    file_info.events   = args->conf->open_file_cache_events;
    file_info.errors   = args->conf->open_file_cache_errors;
    file_info.min_uses = args->conf->open_file_cache_min_uses;
    file_info.valid    = args->conf->open_file_cache_valid;

    return (set_file_info_result) {
        .file_info = file_info,
    };
}

typedef struct {
    ngx_http_request_t       *request;
    ngx_http_core_loc_conf_t *conf;
    ngx_str_t                 path;
    /* The settings ngx_http_pack_static_set_file_info chose; what
       ngx_open_cached_file makes of them comes back in the result. */
    ngx_open_file_info_t file_info;
} open_sibling_args;

typedef struct {
    ngx_int_t            status;
    ngx_open_file_info_t file_info;
} open_sibling_result;

/* Opens what the path now names.

   NGX_DECLINED covers a missing sibling, the ordinary case rather
   than a failure. What an operator would want to know about is logged
   first and then declined like the rest. */
static open_sibling_result
ngx_http_pack_static_open_sibling(open_sibling_args *const args)
{
    ngx_str_t            path;
    ngx_open_file_info_t file_info;
    ngx_int_t            rc;
    ngx_uint_t           level;

    path      = args->path;
    file_info = args->file_info;

    rc = ngx_http_set_disable_symlinks(
        args->request, args->conf, &path, &file_info);
    if (rc != NGX_OK) {
        return (open_sibling_result) {
            .status    = NGX_HTTP_INTERNAL_SERVER_ERROR,
            .file_info = file_info,
        };
    }

    rc = ngx_open_cached_file(
        args->conf->open_file_cache,
        &path,
        &file_info,
        args->request->pool);
    if (rc == NGX_OK) {
        return (open_sibling_result) {
            .status    = NGX_OK,
            .file_info = file_info,
        };
    }

    switch (file_info.err) {
        case 0:
            return (open_sibling_result) {
                .status    = NGX_HTTP_INTERNAL_SERVER_ERROR,
                .file_info = file_info,
            };

        case NGX_ENOENT:
        case NGX_ENOTDIR:
        case NGX_ENAMETOOLONG:
            return (open_sibling_result) {
                .status    = NGX_DECLINED,
                .file_info = file_info,
            };

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

    ngx_log_error(
        level,
        args->request->connection->log,
        file_info.err,
        "%s \"%s\" failed",
        file_info.failed,
        path.data);

    return (open_sibling_result) {
        .status    = NGX_DECLINED,
        .file_info = file_info,
    };
}

typedef struct {
    ngx_http_request_t *request;
    encoding_t const   *encoding;
} accepts_args;

typedef struct {
    ngx_uint_t accepted;
} accepts_result;

/* Whether this client may be served the sibling. "always" asks
   nothing, which the short circuit is. Under "on" the client has to
   name the encoding, and it must not have reached us through a proxy:
   a "Via" header is what nginx's "gzip_proxied off" turns away, and
   what it defaults to. No directive relaxes that yet. */
static accepts_result
ngx_http_pack_static_accepts(accepts_args *const args)
{
    conf_t *conf;

    conf = ngx_http_get_module_loc_conf(
        args->request, ngx_http_pack_static_module);
    if (conf->enable == NGX_HTTP_PACK_STATIC_ALWAYS) {
        return (accepts_result) {
            .accepted = 1,
        };
    }

    if (args->request->headers_in.via != NULL) {
        return (accepts_result) {
            .accepted = 0,
        };
    }

    if (ngx_http_pack_claim_request(
            args->request, &args->encoding->name) != NGX_OK) {
        return (accepts_result) {
            .accepted = 0,
        };
    }

    return (accepts_result) {
        .accepted = 1,
    };
}

typedef struct {
    ngx_http_request_t *request;
    encoding_t const   *encoding;
    /* The mapped path, with room after it for a suffix. The suffix
       this candidate writes there comes back in the result: the
       buffer is shared between candidates, so only the length
       differs between them. */
    ngx_str_t path;
    u_char   *suffix;
} try_sibling_args;

typedef struct {
    ngx_int_t status;
    ngx_str_t path;
    /* Meaningful only when status is NGX_OK. */
    ngx_open_file_info_t file_info;
} try_sibling_result;

/* Tries one encoding: writes its suffix into the room reserved after
   the path and opens what that names. Only ever called for an
   encoding this client would take, so a hit is a response. Three
   outcomes so the caller can stay a loop - NGX_DECLINED means only
   that the next candidate is worth a look, anything else finishes the
   request. */
static try_sibling_result
ngx_http_pack_static_try_sibling(try_sibling_args *const args)
{
    ngx_str_t                 path;
    ngx_http_core_loc_conf_t *core_conf;
    u_char                   *last;
    ngx_log_t                *log;
    open_sibling_result       opened;
    ngx_int_t                 rc;

    path = args->path;

    core_conf = ngx_http_get_module_loc_conf(
        args->request, ngx_http_core_module);

    /* ngx_cpystrn returns the terminating zero it wrote, which is
       where the string now ends. */
    last = ngx_cpystrn(
        args->suffix,
        args->encoding->ext.data,
        args->encoding->ext.len + 1);

    path.len = last - path.data;

    log = args->request->connection->log;

    ngx_log_debug1(
        NGX_LOG_DEBUG_HTTP,
        log,
        0,
        "http filename: \"%s\"",
        path.data);

    opened = ngx_http_pack_static_open_sibling(&(open_sibling_args) {
        .request   = args->request,
        .conf      = core_conf,
        .path      = path,
        .file_info = ngx_http_pack_static_set_file_info(
                         &(set_file_info_args) {
                             .conf = core_conf,
                         })
                         .file_info,
    });

    rc = opened.status;

    if (rc != NGX_OK) {
        return (try_sibling_result) {
            .status = rc,
            .path   = path,
        };
    }

    ngx_log_debug1(
        NGX_LOG_DEBUG_HTTP,
        log,
        0,
        "http static fd: %d",
        opened.file_info.fd);

    if (opened.file_info.is_dir) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, log, 0, "http dir");
        return (try_sibling_result) {
            .status = NGX_DECLINED,
            .path   = path,
        };
    }
    /* Declined rather than refused, which is where this parts company
       with gzip_static: there the odd file is the resource asked for,
       so 404 is the answer, but here it is only a sibling. A fifo
       left lying about named "a.txt.br" must not take "a.txt" down
       with it. Still logged - nothing should be creating one. */
#if !(NGX_WIN32)
    if (!opened.file_info.is_file) {
        ngx_log_error(
            NGX_LOG_CRIT,
            log,
            0,
            "\"%s\" is not a regular file",
            path.data);
        return (try_sibling_result) {
            .status = NGX_DECLINED,
            .path   = path,
        };
    }
#endif

    return (try_sibling_result) {
        .status    = NGX_OK,
        .path      = path,
        .file_info = opened.file_info,
    };
}

typedef struct {
    ngx_http_request_t *request;
    /* Read, never written. */
    ngx_open_file_info_t file_info;
    ngx_str_t const     *encoding;
} set_headers_args;

typedef struct {
    ngx_int_t status;
} set_headers_result;

/* Describes the response without sending it: nothing goes out until
   ngx_http_pack_static_send has a buffer for the body, which has to
   be allocated while a 500 is still possible. */
static set_headers_result
ngx_http_pack_static_set_headers(set_headers_args *const args)
{
    ngx_http_request_t *r;

    r = args->request;

    r->connection->log->action = "sending response to client";

    r->headers_out.status             = NGX_HTTP_OK;
    r->headers_out.content_length_n   = args->file_info.size;
    r->headers_out.last_modified_time = args->file_info.mtime;

    if (ngx_http_set_etag(r) != NGX_OK) {
        return (set_headers_result) {
            .status = NGX_HTTP_INTERNAL_SERVER_ERROR,
        };
    }

    if (ngx_http_set_content_type(r) != NGX_OK) {
        return (set_headers_result) {
            .status = NGX_HTTP_INTERNAL_SERVER_ERROR,
        };
    }

    if (ngx_http_pack_set_encoding(r, args->encoding) != NGX_OK) {
        return (set_headers_result) {
            .status = NGX_HTTP_INTERNAL_SERVER_ERROR,
        };
    }

    /* The range filter offers nothing to a handler that has not said
       so: without this a Range request is answered with the whole
       body and a 200. Ranges count in the encoded bytes, which is
       what a client resuming this response asks for. */
    r->allow_ranges = 1;

    return (set_headers_result) {
        .status = NGX_OK,
    };
}

typedef struct {
    ngx_http_request_t *request;
    /* Both read, never written. */
    ngx_open_file_info_t file_info;
    ngx_str_t            path;
} send_args;

typedef struct {
    ngx_int_t status;
} send_result;

/* Sends the headers, then the sibling as one buffer. The body is
   described rather than read, so sendfile can hand the file to the
   kernel untouched, and closing the descriptor belongs to the cleanup
   ngx_open_cached_file put on the request pool - which is why no path
   out of here closes anything. */
static send_result
ngx_http_pack_static_send(send_args *const args)
{
    ngx_http_request_t *r;
    ngx_buf_t          *buf;
    ngx_chain_t         out;
    ngx_int_t           rc;

    r = args->request;

    buf = ngx_calloc_buf(r->pool);
    if (buf == NULL) {
        return (send_result) {
            .status = NGX_HTTP_INTERNAL_SERVER_ERROR,
        };
    }

    buf->file = ngx_pcalloc(r->pool, sizeof(ngx_file_t));
    if (buf->file == NULL) {
        return (send_result) {
            .status = NGX_HTTP_INTERNAL_SERVER_ERROR,
        };
    }

    buf->file_pos  = 0;
    buf->file_last = args->file_info.size;

    buf->in_file = buf->file_last ? 1 : 0;

    buf->last_buf      = (r == r->main) ? 1 : 0;
    buf->last_in_chain = 1;

    /* An empty body would leave a buffer with no data, no file and
       no last_buf, which the write filter treats as a bug: "zero size
       buf" at alert level, and a debug_point that aborts the worker
       under "debug_points abort". "sync" says it is deliberate. */
    buf->sync = (buf->last_buf || buf->in_file) ? 0 : 1;

    buf->file->directio = args->file_info.is_directio;
    buf->file->fd       = args->file_info.fd;
    buf->file->name     = args->path;
    buf->file->log      = r->connection->log;

    out.buf  = buf;
    out.next = NULL;

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return (send_result) {
            .status = rc,
        };
    }

    return (send_result) {
        .status = ngx_http_output_filter(r, &out),
    };
}

static ngx_int_t
ngx_http_pack_static_handler(ngx_http_request_t *const r)
{
    preflight_result   prepared;
    ngx_str_t          path;
    u_char            *suffix;
    conf_t            *conf;
    encoding_t const  *found;
    try_sibling_result tried;
    ngx_uint_t         idx;
    encoding_t const  *sibling_encoding;
    ngx_int_t          rc;

    prepared = ngx_http_pack_static_preflight(&(preflight_args) {
        .request = r,
    });

    if (prepared.status != NGX_OK) {
        return prepared.status;
    }

    path   = prepared.path;
    suffix = prepared.suffix;

    conf = ngx_http_get_module_loc_conf(
        r, ngx_http_pack_static_module);

    /* Said for every response this location serves, before anything
       is known about what is on disk: "on" is what makes the body
       depend on Accept-Encoding, and that is true of the location,
       not the file. A cache storing the plain response without this
       could hand it to a client that would have been served a
       sibling. Under "always" nothing varies, so it is left out. */
    if (conf->enable == NGX_HTTP_PACK_STATIC_ON &&
        ngx_http_pack_set_vary(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Only the encodings this client would take are probed, in the
       order pack_static_encodings named them, so the admin decides
       which sibling a client taking several is served. */
    found = NULL;

    /* Seeded so that the loop not running at all still leaves
       something defined behind it. Only "found" decides whether the
       rest of it is worth reading. */
    tried = (try_sibling_result) {
        .status = NGX_DECLINED,
        .path   = path,
    };

    for (idx = 0; idx < conf->nencodings; idx++) {
        sibling_encoding = conf->encodings[idx];

        if (!ngx_http_pack_static_accepts(
                 &(accepts_args) {
                     .request  = r,
                     .encoding = sibling_encoding,
                 })
                 .accepted) {
            continue;
        }

        tried = ngx_http_pack_static_try_sibling(&(try_sibling_args) {
            .request  = r,
            .encoding = sibling_encoding,
            .path     = path,
            .suffix   = suffix,
        });

        /* The suffix this candidate wrote, and its length. */
        path = tried.path;
        rc   = tried.status;

        if (rc == NGX_OK) {
            found = sibling_encoding;
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

    /* Saves the log module a stat of the document root, which
       opening the sibling just proved exists. Not simply 1: an error
       page can redirect into a location with a different root, and
       what was proven about this one says nothing about that one. */
    r->root_tested = !r->error_page;

    rc = ngx_http_discard_request_body(r);
    if (rc != NGX_OK) {
        return rc;
    }

    rc = ngx_http_pack_static_set_headers(
             &(set_headers_args) {
                 .request   = r,
                 .file_info = tried.file_info,
                 .encoding  = &found->name,
             })
             .status;
    if (rc != NGX_OK) {
        return rc;
    }

    return ngx_http_pack_static_send(&(send_args) {
                                         .request   = r,
                                         .path      = path,
                                         .file_info = tried.file_info,
                                     })
        .status;
}

static void *
ngx_http_pack_static_create_conf(ngx_conf_t *const cf)
{
    conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->enable = NGX_CONF_UNSET_UINT;

    /* nencodings stays at the zero ngx_pcalloc wrote: that is what
       merge_conf reads as "not set here", and a count has no spare
       value to mean unset the way an ngx_uint_t does. */

    return conf;
}

typedef struct {
    ngx_uint_t enable;
    ngx_uint_t nencodings;
} is_ambiguous_args;

typedef struct {
    ngx_uint_t ambiguous;
} is_ambiguous_result;

/* "always" skips the Accept-Encoding test, so with more than one
   encoding the client gets whatever the probe reaches first, with no
   say in it. A count of zero reads as not ambiguous, which is what
   the caller wants of a parent that named no encodings. */
static is_ambiguous_result
ngx_http_pack_static_is_ambiguous(is_ambiguous_args *const args)
{
    return (is_ambiguous_result) {
        .ambiguous = args->enable == NGX_HTTP_PACK_STATIC_ALWAYS &&
                     args->nencodings > 1,
    };
}

/* At most once for any one block. Warned about rather than rejected:
   a location whose clients are all known to take the same encoding is
   a fair use of the combination. */
typedef struct {
    ngx_uint_t ambiguous;
} warn_ambiguous_result;

static warn_ambiguous_result
ngx_http_pack_static_warn_ambiguous(
    ngx_conf_t *const cf, conf_t *const conf)
{
    ngx_uint_t is_ambiguous;

    is_ambiguous = ngx_http_pack_static_is_ambiguous(
                       &(is_ambiguous_args) {
                           .enable     = conf->enable,
                           .nencodings = conf->nencodings,
                       })
                       .ambiguous;

    if (is_ambiguous && !conf->_warned) {
        conf->_warned = 1;
        ngx_conf_log_error(
            NGX_LOG_WARN,
            cf,
            0,
            "\"pack_static always\" with more than one encoding in "
            "\"pack_static_encodings\" serves whatever is found "
            "first to every client");
    }

    return (warn_ambiguous_result) {
        .ambiguous = is_ambiguous,
    };
}

static char *
ngx_http_pack_static_merge_conf(
    ngx_conf_t *const cf, void *const parent, void *const child)
{
    conf_t    *prev;
    conf_t    *conf;
    ngx_uint_t inherited;
    ngx_uint_t i;

    prev = parent;
    conf = child;

    /* http{} never gets a merge of its own - nginx merges a parent
       into a child, and http{} is only ever the parent - so it is
       reported here. Every other block has already passed through as
       a child by now, so this call speaks for http{} alone. */
    inherited =
        ngx_http_pack_static_warn_ambiguous(cf, prev).ambiguous;

    ngx_conf_merge_uint_value(
        conf->enable, prev->enable, NGX_HTTP_PACK_STATIC_OFF);

    /* No ngx_conf_merge_* covers a list, so the two cases the macros
       would have handled are written out: inherit the enclosing
       block's order, or - if it had none either - default to every
       encoding the module knows, in table order. */
    if (conf->nencodings == 0) {
        if (prev->nencodings == 0) {
            for (i = 0; i < NGX_HTTP_PACK_STATIC_NENCODINGS; i++) {
                conf->encodings[i] =
                    &ngx_http_pack_static_encodings[i];
            }
            conf->nencodings = NGX_HTTP_PACK_STATIC_NENCODINGS;
        } else {
            ngx_memcpy(
                conf->encodings,
                prev->encodings,
                sizeof(conf->encodings));
            conf->nencodings = prev->nencodings;
        }
    }

    /* An inherited ambiguity has been spoken for by the block above,
       so this one counts as reported without anything being said -
       which is also what keeps the blocks below it quiet. */
    conf->_warned = inherited;

    ngx_http_pack_static_warn_ambiguous(cf, conf);

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
