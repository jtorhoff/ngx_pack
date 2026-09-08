/*
   Copyright (C) 2026 Juri Torhoff
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "ngx_http_pack_module.h"


/* Slot values for conf_t.codecs[]; distinct from
   ngx_http_pack_codec_e, which is the query API's own vocabulary and
   has no "empty slot" value of its own. */
enum {
    NGX_HTTP_PACK_CONF_NONE = 0,
    NGX_HTTP_PACK_CONF_ZSTD,
    NGX_HTTP_PACK_CONF_BROTLI,
};

typedef struct {
    /* codecs[0] outranks codecs[1], left-packed - a real codec never
       sits at [1] while [0] is NGX_HTTP_PACK_CONF_NONE, which is what
       lets ngx_http_pack_status read "found at index 1" as "the other
       codec is ranked ahead" with no need to check codecs[0] too.
       NGX_CONF_UNSET in codecs[0] means "pack" was never written for
       this location - not even "off" - and it should inherit. */
    ngx_int_t codecs[2];

    /* Which slot is "=always", or -1 for neither. */
    ngx_int_t always_slot;

    /* pack_types: MIME types eligible for either codec. One list
       rather than one per filter - a response either is or is not
       worth compressing, regardless of which codec would do it. */
    ngx_hash_t   types;
    ngx_array_t *types_keys;
} conf_t;


static void *ngx_http_pack_create_conf(ngx_conf_t *cf);
static char *
ngx_http_pack_merge_conf(ngx_conf_t *cf, void *parent, void *child);
static char *
ngx_http_pack_set(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);


static ngx_command_t const ngx_http_pack_commands[] = {
    {
        ngx_string("pack"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
            NGX_HTTP_LIF_CONF | NGX_CONF_1MORE,
        ngx_http_pack_set,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL,
    },
    {
        ngx_string("pack_types"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
            NGX_CONF_1MORE,
        ngx_http_types_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(conf_t, types_keys),
        &ngx_http_html_default_types[0],
    },
    ngx_null_command,
};

static ngx_http_module_t const ngx_http_pack_module_ctx = {
    NULL,                      /* pre-configuration */
    NULL,                      /* post-configuration */
    NULL,                      /* create main conf */
    NULL,                      /* init main conf */
    NULL,                      /* create server conf */
    NULL,                      /* merge server conf */
    ngx_http_pack_create_conf, /* create location conf */
    ngx_http_pack_merge_conf,  /* merge location conf */
};

/* Not const: nginx writes into this struct at startup - see the same
   note beside ngx_http_pack_static_module. */
ngx_module_t ngx_http_pack_module = {
    NGX_MODULE_V1,
    (void *) &ngx_http_pack_module_ctx, /* module context */
    (void *) ngx_http_pack_commands,    /* module directives */
    NGX_HTTP_MODULE,                    /* module type */
    NULL,                               /* init master */
    NULL,                               /* init module */
    NULL,                               /* init process */
    NULL,                               /* init thread */
    NULL,                               /* exit thread */
    NULL,                               /* exit process */
    NULL,                               /* exit master */
    NGX_MODULE_V1_PADDING,
};


static void *
ngx_http_pack_create_conf(ngx_conf_t *const cf)
{
    conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->codecs[0]   = NGX_CONF_UNSET;
    conf->codecs[1]   = NGX_CONF_UNSET;
    conf->always_slot = NGX_CONF_UNSET;

    return conf;
}


static char *
ngx_http_pack_merge_conf(
    ngx_conf_t *const cf, void *const parent, void *const child)
{
    conf_t *prev = parent;
    conf_t *conf = child;

    /* Field-wise, not "*conf = *prev": pack_types can be set here
       independently of "pack", and a whole-struct copy would discard
       it whenever "pack" itself was left to inherit. */
    if (conf->codecs[0] == NGX_CONF_UNSET) {
        conf->codecs[0]   = prev->codecs[0];
        conf->codecs[1]   = prev->codecs[1];
        conf->always_slot = prev->always_slot;
    }

    /* Never written anywhere in the chain up to here: off, matching
       pack_zstd's and pack_brotli's own prior default. */
    if (conf->codecs[0] == NGX_CONF_UNSET) {
        conf->codecs[0]   = NGX_HTTP_PACK_CONF_NONE;
        conf->codecs[1]   = NGX_HTTP_PACK_CONF_NONE;
        conf->always_slot = -1;
    }

    if (ngx_http_merge_types(
            cf,
            &conf->types_keys,
            &conf->types,
            &prev->types_keys,
            &prev->types,
            ngx_http_html_default_types) != NGX_CONF_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


/* Parses one token into a codec id, and reports whether it carried
   "=always" - splitting "br=always" is this function's job so
   ngx_http_pack_set only ever compares whole names. */
static ngx_int_t
ngx_http_pack_parse_token(
    ngx_conf_t *const cf,
    ngx_str_t         token,
    ngx_uint_t *const is_always)
{
    u_char *eq;

    *is_always = 0;

    eq = ngx_strlchr(token.data, token.data + token.len, '=');
    if (eq != NULL) {
        ngx_str_t suffix;

        suffix.data = eq + 1;
        suffix.len = (ngx_uint_t) (token.data + token.len - (eq + 1));

        if (suffix.len != sizeof("always") - 1 ||
            ngx_strncmp(suffix.data, "always", suffix.len) != 0) {
            ngx_conf_log_error(
                NGX_LOG_EMERG,
                cf,
                0,
                "unknown modifier in \"%V\", expected \"=always\"",
                &token);
            return NGX_ERROR;
        }

        *is_always = 1;
        token.len  = (ngx_uint_t) (eq - token.data);
    }

    if (token.len == sizeof("zstd") - 1 &&
        ngx_strncmp(token.data, "zstd", token.len) == 0) {
        return NGX_HTTP_PACK_CONF_ZSTD;
    }

    if (token.len == sizeof("br") - 1 &&
        ngx_strncmp(token.data, "br", token.len) == 0) {
        return NGX_HTTP_PACK_CONF_BROTLI;
    }

    ngx_conf_log_error(
        NGX_LOG_EMERG,
        cf,
        0,
        "unknown codec \"%V\", expected \"zstd\" or \"br\"",
        &token);
    return NGX_ERROR;
}


static char *
ngx_http_pack_set(
    ngx_conf_t *const cf, ngx_command_t *const cmd, void *const conf)
{
    conf_t    *pcf = conf;
    ngx_str_t *value;
    ngx_uint_t i;
    ngx_int_t  always_slot;
    ngx_uint_t n;

    if (pcf->codecs[0] != NGX_CONF_UNSET) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (cf->args->nelts == 2 && value[1].len == sizeof("off") - 1 &&
        ngx_strncmp(value[1].data, "off", value[1].len) == 0) {
        pcf->codecs[0]   = NGX_HTTP_PACK_CONF_NONE;
        pcf->codecs[1]   = NGX_HTTP_PACK_CONF_NONE;
        pcf->always_slot = -1;
        return NGX_CONF_OK;
    }

    if (cf->args->nelts > 3) {
        ngx_conf_log_error(
            NGX_LOG_EMERG,
            cf,
            0,
            "\"pack\" takes at most two codecs, or \"off\"");
        return NGX_CONF_ERROR;
    }

    always_slot = -1;

    for (i = 1, n = 0; i < cf->args->nelts; i++, n++) {
        ngx_uint_t is_always;
        ngx_int_t  codec;

        codec = ngx_http_pack_parse_token(cf, value[i], &is_always);
        if (codec == NGX_ERROR) {
            return NGX_CONF_ERROR;
        }

        if (n == 1 && codec == pcf->codecs[0]) {
            ngx_conf_log_error(
                NGX_LOG_EMERG,
                cf,
                0,
                "\"%V\" is named twice",
                &value[i]);
            return NGX_CONF_ERROR;
        }

        if (is_always) {
            if (always_slot != -1) {
                ngx_conf_log_error(
                    NGX_LOG_EMERG,
                    cf,
                    0,
                    "only one codec may be \"=always\"");
                return NGX_CONF_ERROR;
            }

            always_slot = (ngx_int_t) n;
        }

        pcf->codecs[n] = codec;
    }

    /* "=always" on the first of two codecs would make the second one
       dead weight: the first would claim every eligible response
       outright and the ranking that names a second codec at all
       would never be consulted. Only the last codec named - the one
       actually reached when an earlier one declines - may carry it.
     */
    if (n == 2 && always_slot == 0) {
        ngx_conf_log_error(
            NGX_LOG_EMERG,
            cf,
            0,
            "\"=always\" is only legal on the last codec named");
        return NGX_CONF_ERROR;
    }

    if (n == 1) {
        pcf->codecs[1] = NGX_HTTP_PACK_CONF_NONE;
    }

    pcf->always_slot = always_slot;

    return NGX_CONF_OK;
}


ngx_http_pack_status_t
ngx_http_pack_status(
    ngx_http_request_t *const r, ngx_http_pack_codec_e const codec)
{
    conf_t                *conf;
    ngx_http_pack_status_t status;
    ngx_int_t              want;
    ngx_uint_t             idx;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_pack_module);

    status.listed   = 0;
    status.always   = 0;
    status.deferred = 0;

    want = (codec == NGX_HTTP_PACK_ZSTD) ? NGX_HTTP_PACK_CONF_ZSTD
                                         : NGX_HTTP_PACK_CONF_BROTLI;

    for (idx = 0; idx < 2; idx++) {
        if (conf->codecs[idx] == want) {
            status.listed   = 1;
            status.always   = (conf->always_slot == (ngx_int_t) idx);
            status.deferred = idx == 1;
            break;
        }
    }

    return status;
}


u_char *
ngx_http_pack_test_content_type(ngx_http_request_t *const r)
{
    conf_t *conf;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_pack_module);

    return ngx_http_test_content_type(r, &conf->types);
}
