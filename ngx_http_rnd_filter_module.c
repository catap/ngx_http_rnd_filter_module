
/*
 * Copyright (C) Kirill A. Korinskiy
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef struct {
    ngx_str_t                  match;

    ngx_flag_t                 once;

    ngx_flag_t                 cached;

    ngx_hash_t                 types;
    ngx_array_t               *types_keys;
} ngx_http_rnd_loc_conf_t;


typedef enum {
    rnd_start_state = 0,
    rnd_match_state,
} ngx_http_rnd_state_e;


typedef struct {
    ngx_str_t                  match;

    ngx_uint_t                 once;

    ngx_str_t                  rnd;

    ngx_buf_t                 *buf;

    u_char                    *pos;
    u_char                    *copy_start;
    u_char                    *copy_end;

    ngx_chain_t               *in;
    ngx_chain_t               *out;
    ngx_chain_t              **last_out;
    ngx_chain_t               *busy;
    ngx_chain_t               *free;

    ngx_uint_t                 state;
    size_t                     saved;
    size_t                     looked;
} ngx_http_rnd_ctx_t;


static ngx_int_t ngx_http_rnd_output(ngx_http_request_t *r,
    ngx_http_rnd_ctx_t *ctx);
static ngx_int_t ngx_http_rnd_parse(ngx_http_request_t *r,
    ngx_http_rnd_ctx_t *ctx);

static void *ngx_http_rnd_create_conf(ngx_conf_t *cf);
static char *ngx_http_rnd_merge_conf(ngx_conf_t *cf,
    void *parent, void *child);
static ngx_int_t ngx_http_rnd_filter_init(ngx_conf_t *cf);

static ngx_int_t ngx_http_rnd_add_variables(ngx_conf_t *cf);
static ngx_int_t ngx_http_rnd_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_rnd_cached_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);


static ngx_command_t  ngx_http_rnd_filter_commands[] = {

    { ngx_string("rnd_filter"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_rnd_loc_conf_t, match),
      NULL },

    { ngx_string("rnd_filter_types"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_types_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_rnd_loc_conf_t, types_keys),
      &ngx_http_html_default_types[0] },

    { ngx_string("rnd_filter_once"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_rnd_loc_conf_t, once),
      NULL },

    { ngx_string("rnd_filter_cached"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_rnd_loc_conf_t, cached),
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_rnd_filter_module_ctx = {
    ngx_http_rnd_add_variables,            /* preconfiguration */
    ngx_http_rnd_filter_init,              /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_rnd_create_conf,              /* create location configuration */
    ngx_http_rnd_merge_conf                /* merge location configuration */
};


ngx_module_t  ngx_http_rnd_filter_module = {
    NGX_MODULE_V1,
    &ngx_http_rnd_filter_module_ctx,       /* module context */
    ngx_http_rnd_filter_commands,          /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_http_variable_t  ngx_http_rnd_vars[] = {

    { ngx_string("rnd"), NULL,
      ngx_http_rnd_variable, 0,
      NGX_HTTP_VAR_NOHASH|NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("rnd_cached"), NULL,
      ngx_http_rnd_cached_variable, 0,
      NGX_HTTP_VAR_NOHASH, 0 },

    { ngx_null_string, NULL, NULL, 0, 0, 0 }
};


static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;
static ngx_http_output_body_filter_pt    ngx_http_next_body_filter;


static ngx_int_t
ngx_http_rnd_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t  *var, *v;

    for (v = ngx_http_rnd_vars; v->name.len; v++) {
        var = ngx_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_rnd_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;

    v->data = ngx_pnalloc(r->pool, NGX_INT_T_LEN);
    if (v->data == NULL) {
        return NGX_ERROR;
    }

    v->len = ngx_sprintf(v->data, "%d", ngx_random()) - v->data;

    return NGX_OK;
}


static ngx_int_t
ngx_http_rnd_cached_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_rnd_ctx_t        *ctx;

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    ctx = ngx_http_get_module_ctx(r, ngx_http_rnd_filter_module);

    if (ctx == NULL) {
	ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_rnd_ctx_t));
	if (ctx == NULL) {
	    return NGX_ERROR;
	}

	ngx_http_set_ctx(r, ctx, ngx_http_rnd_filter_module);
    }

    if (ctx->rnd.len == 0) {
	ctx->rnd.data = ngx_palloc(r->pool, NGX_INT_T_LEN);
	if (ctx->rnd.data == NULL) {
	    return NGX_ERROR;
	}

	ctx->rnd.len = ngx_sprintf(ctx->rnd.data,
				   "%d", ngx_random()) - ctx->rnd.data;
    }

    v->data = ctx->rnd.data;
    v->len = ctx->rnd.len;

    return NGX_OK;
}


static ngx_int_t
ngx_http_rnd_header_filter(ngx_http_request_t *r)
{
    ngx_http_rnd_ctx_t        *ctx;
    ngx_http_rnd_loc_conf_t  *conf;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_rnd_filter_module);

    if (conf->match.len == 0
        || r->headers_out.content_length_n == 0
        || ngx_http_test_content_type(r, &conf->types) == NULL)
    {
        return ngx_http_next_header_filter(r);
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_rnd_filter_module);

    if (ctx == NULL) {
	ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_rnd_ctx_t));
	if (ctx == NULL) {
	    return NGX_ERROR;
	}

	ngx_http_set_ctx(r, ctx, ngx_http_rnd_filter_module);
    }

    ctx->match = conf->match;
    ctx->last_out = &ctx->out;

    r->filter_need_in_memory = 1;

    if (r == r->main) {
        ngx_http_clear_content_length(r);
        ngx_http_clear_last_modified(r);
    }

    return ngx_http_next_header_filter(r);
}


static ngx_int_t
ngx_http_rnd_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    ngx_int_t                  rc;
    ngx_buf_t                 *b;
    ngx_chain_t               *cl;
    ngx_http_rnd_ctx_t        *ctx;
    ngx_http_rnd_loc_conf_t   *conf;

    ctx = ngx_http_get_module_ctx(r, ngx_http_rnd_filter_module);

    if (ctx == NULL) {
        return ngx_http_next_body_filter(r, in);
    }

    if ((in == NULL
         && ctx->buf == NULL
         && ctx->in == NULL
         && ctx->busy == NULL))
    {
        return ngx_http_next_body_filter(r, in);
    }

    if (ctx->once && (ctx->buf == NULL || ctx->in == NULL)) {

        if (ctx->busy) {
            if (ngx_http_rnd_output(r, ctx) == NGX_ERROR) {
                return NGX_ERROR;
            }
        }

        return ngx_http_next_body_filter(r, in);
    }

    if (in) {
        if (ngx_chain_add_copy(r->pool, &ctx->in, in) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http rnd filter \"%V\"", &r->uri);

    while (ctx->in || ctx->buf) {

        if (ctx->buf == NULL ){
            ctx->buf = ctx->in->buf;
            ctx->in = ctx->in->next;
            ctx->pos = ctx->buf->pos;
        }

        if (ctx->state == rnd_start_state) {
            ctx->copy_start = ctx->pos;
            ctx->copy_end = ctx->pos;
        }

        b = NULL;

        while (ctx->pos < ctx->buf->last) {

            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "saved: %d state: %d", ctx->saved, ctx->state);

            rc = ngx_http_rnd_parse(r, ctx);

            ngx_log_debug4(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "parse: %d, looked: %d %p-%p",
                           rc, ctx->looked, ctx->copy_start, ctx->copy_end);

            if (rc == NGX_ERROR) {
                return rc;
            }

            if (ctx->copy_start != ctx->copy_end) {

                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "saved: %d", ctx->saved);

                if (ctx->saved) {

                    if (ctx->free) {
                        cl = ctx->free;
                        ctx->free = ctx->free->next;
                        b = cl->buf;
                        ngx_memzero(b, sizeof(ngx_buf_t));

                    } else {
                        b = ngx_calloc_buf(r->pool);
                        if (b == NULL) {
                            return NGX_ERROR;
                        }

                        cl = ngx_alloc_chain_link(r->pool);
                        if (cl == NULL) {
                            return NGX_ERROR;
                        }

                        cl->buf = b;
                    }

                    b->memory = 1;
                    b->pos = ctx->match.data;
                    b->last = ctx->match.data + ctx->saved;

                    *ctx->last_out = cl;
                    ctx->last_out = &cl->next;

                    ctx->saved = 0;
                }

                if (ctx->free) {
                    cl = ctx->free;
                    ctx->free = ctx->free->next;
                    b = cl->buf;

                } else {
                    b = ngx_alloc_buf(r->pool);
                    if (b == NULL) {
                        return NGX_ERROR;
                    }

                    cl = ngx_alloc_chain_link(r->pool);
                    if (cl == NULL) {
                        return NGX_ERROR;
                    }

                    cl->buf = b;
                }

                ngx_memcpy(b, ctx->buf, sizeof(ngx_buf_t));

                b->pos = ctx->copy_start;
                b->last = ctx->copy_end;
                b->shadow = NULL;
                b->last_buf = 0;
                b->recycled = 0;

                if (b->in_file) {
                    b->file_last = b->file_pos + (b->last - ctx->buf->pos);
                    b->file_pos += b->pos - ctx->buf->pos;
                }

                cl->next = NULL;
                *ctx->last_out = cl;
                ctx->last_out = &cl->next;
            }

            if (ctx->state == rnd_start_state) {
                ctx->copy_start = ctx->pos;
                ctx->copy_end = ctx->pos;

            } else {
                ctx->copy_start = NULL;
                ctx->copy_end = NULL;
            }

            if (rc == NGX_AGAIN) {
                continue;
            }


            /* rc == NGX_OK */

            b = ngx_calloc_buf(r->pool);
            if (b == NULL) {
                return NGX_ERROR;
            }

            cl = ngx_alloc_chain_link(r->pool);
            if (cl == NULL) {
                return NGX_ERROR;
            }

            conf = ngx_http_get_module_loc_conf(r, ngx_http_rnd_filter_module);

	    b->memory = 1;

	    if (conf->cached) {
		if (ctx->rnd.len == 0) {
		    ctx->rnd.data = ngx_palloc(r->pool, NGX_INT_T_LEN);
		    if (ctx->rnd.data == NULL) {
			return NGX_ERROR;
		    }

		    ctx->rnd.len = ngx_sprintf(ctx->rnd.data,
					       "%d", ngx_random()) - ctx->rnd.data;
		}

		b->pos = ctx->rnd.data;
		b->last = ctx->rnd.data + ctx->rnd.len;
	    } else {
		b->pos = ngx_palloc(r->pool, NGX_INT_T_LEN);
		if (b->pos == NULL) {
		    return NGX_ERROR;
		}

		b->last = ngx_sprintf(b->pos, "%d", ngx_random());
	    }

            cl->buf = b;
            cl->next = NULL;
            *ctx->last_out = cl;
            ctx->last_out = &cl->next;

            ctx->once = conf->once;

            continue;
        }

        if (ctx->buf->last_buf || ngx_buf_in_memory(ctx->buf)) {
            if (b == NULL) {
                if (ctx->free) {
                    cl = ctx->free;
                    ctx->free = ctx->free->next;
                    b = cl->buf;
                    ngx_memzero(b, sizeof(ngx_buf_t));

                } else {
                    b = ngx_calloc_buf(r->pool);
                    if (b == NULL) {
                        return NGX_ERROR;
                    }

                    cl = ngx_alloc_chain_link(r->pool);
                    if (cl == NULL) {
                        return NGX_ERROR;
                    }

                    cl->buf = b;
                }

                b->sync = 1;

                cl->next = NULL;
                *ctx->last_out = cl;
                ctx->last_out = &cl->next;
            }

            b->last_buf = ctx->buf->last_buf;
            b->shadow = ctx->buf;

            b->recycled = ctx->buf->recycled;
        }

        ctx->buf = NULL;

        ctx->saved = ctx->looked;
    }

    if (ctx->out == NULL && ctx->busy == NULL) {
        return NGX_OK;
    }

    return ngx_http_rnd_output(r, ctx);
}


static ngx_int_t
ngx_http_rnd_output(ngx_http_request_t *r, ngx_http_rnd_ctx_t *ctx)
{
    ngx_int_t     rc;
    ngx_buf_t    *b;
    ngx_chain_t  *cl;

    b = NULL;
    for (cl = ctx->out; cl; cl = cl->next) {
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "rnd out: %p %p", cl->buf, cl->buf->pos);
        if (cl->buf == b) {
            ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                          "the same buf was used in rnd");
            ngx_debug_point();
            return NGX_ERROR;
        }
        b = cl->buf;
    }

    rc = ngx_http_next_body_filter(r, ctx->out);

    if (ctx->busy == NULL) {
        ctx->busy = ctx->out;

    } else {
        for (cl = ctx->busy; cl->next; cl = cl->next) { /* void */ }
        cl->next = ctx->out;
    }

    ctx->out = NULL;
    ctx->last_out = &ctx->out;

    while (ctx->busy) {

        cl = ctx->busy;
        b = cl->buf;

        if (ngx_buf_size(b) != 0) {
            break;
        }

        if (b->shadow) {
            b->shadow->pos = b->shadow->last;
        }

        ctx->busy = cl->next;

        if (ngx_buf_in_memory(b) || b->in_file) {
            /* add data bufs only to the free buf chain */

            cl->next = ctx->free;
            ctx->free = cl;
        }
    }

    if (ctx->in || ctx->buf) {
        r->buffered |= NGX_HTTP_SUB_BUFFERED;

    } else {
        r->buffered &= ~NGX_HTTP_SUB_BUFFERED;
    }

    return rc;
}


static ngx_int_t
ngx_http_rnd_parse(ngx_http_request_t *r, ngx_http_rnd_ctx_t *ctx)
{
    u_char                *p, *last, *copy_end, ch, match;
    size_t                 looked;
    ngx_http_rnd_state_e   state;

    if (ctx->once) {
        ctx->copy_start = ctx->pos;
        ctx->copy_end = ctx->buf->last;
        ctx->pos = ctx->buf->last;
        ctx->looked = 0;

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "once");

        return NGX_AGAIN;
    }

    state = ctx->state;
    looked = ctx->looked;
    last = ctx->buf->last;
    copy_end = ctx->copy_end;

    for (p = ctx->pos; p < last; p++) {

        ch = *p;
        ch = ngx_tolower(ch);

        if (state == rnd_start_state) {

            match = ctx->match.data[0];

            for ( ;; ) {
                if (ch == match) {
                    copy_end = p;
                    looked = 1;
                    state = rnd_match_state;

                    goto match_started;
                }

                if (++p == last) {
                    break;
                }

                ch = *p;
                ch = ngx_tolower(ch);
            }

            ctx->state = state;
            ctx->pos = p;
            ctx->looked = looked;
            ctx->copy_end = p;

            if (ctx->copy_start == NULL) {
                ctx->copy_start = ctx->buf->pos;
            }

            return NGX_AGAIN;

        match_started:

            continue;
        }

        if (ch == ctx->match.data[looked]) {
            looked++;

            if (looked == ctx->match.len) {
                if ((size_t) (p - ctx->pos) < looked) {
                    ctx->saved = 0;
                }

                ctx->state = rnd_start_state;
                ctx->pos = p + 1;
                ctx->looked = 0;
                ctx->copy_end = copy_end;

                if (ctx->copy_start == NULL && copy_end) {
                    ctx->copy_start = ctx->buf->pos;
                }

                return NGX_OK;
            }

        } else if (ch == ctx->match.data[0]) {
            copy_end = p;
            looked = 1;

        } else {
            copy_end = p;
            looked = 0;
            state = rnd_start_state;
        }
    }

    ctx->state = state;
    ctx->pos = p;
    ctx->looked = looked;

    ctx->copy_end = (state == rnd_start_state) ? p : copy_end;

    if (ctx->copy_start == NULL && ctx->copy_end) {
        ctx->copy_start = ctx->buf->pos;
    }

    return NGX_AGAIN;
}


static void *
ngx_http_rnd_create_conf(ngx_conf_t *cf)
{
    ngx_http_rnd_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_rnd_loc_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->match = { 0, NULL };
     *     conf->types = { NULL };
     *     conf->types_keys = NULL;
     */

    conf->once = NGX_CONF_UNSET;
    conf->cached = NGX_CONF_UNSET;

    return conf;
}


static char *
ngx_http_rnd_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_rnd_loc_conf_t *prev = parent;
    ngx_http_rnd_loc_conf_t *conf = child;

    ngx_conf_merge_value(conf->once, prev->once, 1);
    ngx_conf_merge_value(conf->cached, prev->cached, 0);
    ngx_conf_merge_str_value(conf->match, prev->match, "");

    if (ngx_http_merge_types(cf, &conf->types_keys, &conf->types,
                             &prev->types_keys, &prev->types,
                             ngx_http_html_default_types)
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_rnd_filter_init(ngx_conf_t *cf)
{
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_rnd_header_filter;

    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_rnd_body_filter;

    return NGX_OK;
}
