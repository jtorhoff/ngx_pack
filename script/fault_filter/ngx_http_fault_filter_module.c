/*
 * Copyright (C) 2026 Juri Torhoff
 */

/* Test-only header filter. It returns a configured HTTP status from
 * its header filter and does nothing else.
 *
 * It exists because that behaviour is otherwise unreachable here. A
 * header filter below the zstd filter returning a status - rather
 * than NGX_OK, NGX_AGAIN or NGX_ERROR - is what
 * ngx_http_zstd_filter_prepare's "header_rc > NGX_OK" branch handles,
 * and no stock nginx module can produce it on the path that branch
 * lives on: ngx_http_image_filter_module is the only one in the tree
 * that returns a status from a header filter at all, and it does so
 * only when Content-Length is known, while that branch is reachable
 * only while the length is still unknown.
 *
 * The config beside this file places the module below the zstd filter
 * in the chain, so what it returns is what zstd's send_headers sees.
 *
 * Never built into a shipping binary. script/build.sh does not add
 * it; only script/test-header-status.sh does.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

typedef struct {
    /* The status to return, or NGX_CONF_UNSET for "pass through". */
    ngx_int_t status;
} ngx_http_fault_conf_t;

static ngx_int_t ngx_http_fault_header_filter(ngx_http_request_t *r);
static void     *ngx_http_fault_create_conf(ngx_conf_t *cf);
static char     *ngx_http_fault_merge_conf(ngx_conf_t *cf, void *parent,
    void *child);
static ngx_int_t ngx_http_fault_init(ngx_conf_t *cf);

static ngx_command_t ngx_http_fault_commands[] = {
    {ngx_string("fault_header_status"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
            NGX_CONF_TAKE1,
        ngx_conf_set_num_slot, NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_fault_conf_t, status), NULL},

    ngx_null_command};

static ngx_http_module_t ngx_http_fault_filter_module_ctx = {
    NULL,                       /* pre-configuration */
    ngx_http_fault_init,        /* post-configuration */

    NULL,                       /* create main configuration */
    NULL,                       /* init main configuration */

    NULL,                       /* create server configuration */
    NULL,                       /* merge server configuration */

    ngx_http_fault_create_conf, /* create location configuration */
    ngx_http_fault_merge_conf   /* merge location configuration */
};

ngx_module_t ngx_http_fault_filter_module = {NGX_MODULE_V1,
    &ngx_http_fault_filter_module_ctx, /* module context */
    ngx_http_fault_commands,           /* module directives */
    NGX_HTTP_MODULE,                   /* module type */
    NULL,                              /* init master */
    NULL,                              /* init module */
    NULL,                              /* init process */
    NULL,                              /* init thread */
    NULL,                              /* exit thread */
    NULL,                              /* exit process */
    NULL,                              /* exit master */
    NGX_MODULE_V1_PADDING};

static ngx_http_output_header_filter_pt ngx_http_next_header_filter;

static ngx_int_t
ngx_http_fault_header_filter(ngx_http_request_t *r)
{
    ngx_http_fault_conf_t *conf;

    conf =
        ngx_http_get_module_loc_conf(r, ngx_http_fault_filter_module);

    /* A status, not NGX_OK/NGX_AGAIN/NGX_ERROR - which is the whole
       point of this module. Everything above us in the chain sees it
       come back from its own ngx_http_next_header_filter() call. */
    if (conf->status > NGX_OK) {
        return conf->status;
    }

    return ngx_http_next_header_filter(r);
}

static void *
ngx_http_fault_create_conf(ngx_conf_t *cf)
{
    ngx_http_fault_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_fault_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->status = NGX_CONF_UNSET;

    return conf;
}

static char *
ngx_http_fault_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_fault_conf_t *prev = parent;
    ngx_http_fault_conf_t *conf = child;

    ngx_conf_merge_value(conf->status, prev->status, 0);

    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_fault_init(ngx_conf_t *cf)
{
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_fault_header_filter;

    return NGX_OK;
}
