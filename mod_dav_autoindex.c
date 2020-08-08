/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


/*
 * The Apache mod_dav_autoindex module adds an index to collections in a
 * WebDAV server.
 *
 *  Author: Graham Leggett
 *
 * At it's most basic, when a GET request is made on a collection, this is
 * translated into a PROPFIND request and the response returned to the
 * browser. The response can be filtered with an optional XSLT transform.
 *
 * Basic configuration:
 *
 * <Location />
 *   Dav on
 *   DavAutoindex on
 *
 *   DavAutoindexProperty displayname
 *   DavAutoindexProperty urn:ietf:params:xml:ns:caldav calendar-timezone
 *   DavAutoindexStylesheet index.xsl
 * </Location>
 *
 */
#include <apr_lib.h>
#include <apr_escape.h>
#include <apr_strings.h>
#include "apr_sha1.h"
#include "apr_encode.h"
#include "apr_tables.h"

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"
#include "util_script.h"

#include <libical/ical.h>

#include "mod_dav.h"

#undef PACKAGE_BUGREPORT
#undef PACKAGE_NAME
#undef PACKAGE_STRING
#undef PACKAGE_TARNAME
#undef PACKAGE_VERSION
#include "config.h"

module AP_MODULE_DECLARE_DATA dav_autoindex_module;

#define DAV_AUTOINDEX_HANDLER "httpd/dav-autoindex"

#define DAV_XML_NAMESPACE "DAV:"

typedef struct
{
    int dav_autoindex_set :1;
    int stylesheet_set :1;
    int dav_autoindex;
    apr_array_header_t *properties;
    ap_expr_info_t *stylesheet;
} dav_autoindex_config_rec;

typedef struct dav_autoindex_ctx {
    dav_walk_params w;
    request_rec *r;
    apr_bucket_brigade *bb;
    dav_error *err;
    apr_xml_doc *doc;
    apr_sha1_ctx_t *sha1;

    /* for PROPFIND operations */
    int propfind_type;
#define DAV_PROPFIND_IS_ALLPROP     1
#define DAV_PROPFIND_IS_PROPNAME    2
#define DAV_PROPFIND_IS_PROP        3

    apr_text *propstat_404;         /* (cached) propstat giving a 404 error */

    apr_pool_t *scratchpool;
} dav_autoindex_ctx;

static void *create_dav_autoindex_dir_config(apr_pool_t *p, char *d)
{
    dav_autoindex_config_rec *conf = apr_pcalloc(p, sizeof(dav_autoindex_config_rec));

    conf->properties = apr_array_make(p, 2, sizeof(dav_prop_name));

    return conf;
}

static void *merge_dav_autoindex_dir_config(apr_pool_t *p, void *basev, void *addv)
{
    dav_autoindex_config_rec *new = (dav_autoindex_config_rec *) apr_pcalloc(p,
            sizeof(dav_autoindex_config_rec));
    dav_autoindex_config_rec *add = (dav_autoindex_config_rec *) addv;
    dav_autoindex_config_rec *base = (dav_autoindex_config_rec *) basev;

    new->dav_autoindex = (add->dav_autoindex_set == 0) ? base->dav_autoindex : add->dav_autoindex;
    new->dav_autoindex_set = add->dav_autoindex_set || base->dav_autoindex_set;

    new->stylesheet = (add->stylesheet_set == 0) ? base->stylesheet : add->stylesheet;
    new->stylesheet_set = add->stylesheet_set || base->stylesheet_set;

    new->properties = apr_array_append(p, add->properties, base->properties);

    return new;
}

static const char *set_dav_autoindex(cmd_parms *cmd, void *dconf, int flag)
{
    dav_autoindex_config_rec *conf = dconf;

    conf->dav_autoindex = flag;
    conf->dav_autoindex_set = 1;

    return NULL;
}

static const char *add_dav_autoindex_property(cmd_parms *cmd, void *dconf, const char *namespace, const char *name)
{
    dav_autoindex_config_rec *conf = dconf;

    dav_prop_name *prop = apr_array_push(conf->properties);

    if (name) {
        prop->name = name;
        prop->ns = namespace;
    }
    else {
        prop->name = namespace;
        prop->ns = DAV_XML_NAMESPACE;
    }

    return NULL;
}

static const char *set_dav_autoindex_stylesheet(cmd_parms *cmd, void *dconf, const char *stylesheet)
{
    dav_autoindex_config_rec *conf = dconf;
    const char *expr_err = NULL;

    conf->stylesheet = ap_expr_parse_cmd(cmd, stylesheet, AP_EXPR_FLAG_STRING_RESULT,
            &expr_err, NULL);

    if (expr_err) {
        return apr_pstrcat(cmd->temp_pool,
                "Cannot parse expression '", stylesheet, "': ",
                expr_err, NULL);
    }

    conf->stylesheet_set = 1;

    return NULL;
}

static const command_rec dav_autoindex_cmds[] =
{
    AP_INIT_FLAG("DavAutoindex",
        set_dav_autoindex, NULL, RSRC_CONF | ACCESS_CONF,
        "When enabled, the URL space will support autoindexes."),
    AP_INIT_TAKE12("DavAutoindexProperty", add_dav_autoindex_property, NULL, RSRC_CONF | ACCESS_CONF,
        "Set the property namespace and name to request while autoindexing."),
    AP_INIT_TAKE1("DavAutoindexStylesheet", set_dav_autoindex_stylesheet, NULL, RSRC_CONF | ACCESS_CONF,
        "Set the XSLT stylesheet to be used when rendering the output."),
    { NULL }
};

/*
 * dav_log_err()
 *
 * Write error information to the log.
 */
static void dav_log_err(request_rec *r, dav_error *err, int level)
{
    dav_error *errscan;

    /* Log the errors */
    /* ### should have a directive to log the first or all */
    for (errscan = err; errscan != NULL; errscan = errscan->prev) {
        if (errscan->desc == NULL)
            continue;

        /* Intentional no APLOGNO */
        ap_log_rerror(APLOG_MARK, level, errscan->aprerr, r, "%s  [%d, #%d]",
                      errscan->desc, errscan->status, errscan->error_id);
    }
}

static int dav_autoindex_type_checker(request_rec *r)
{
    /*
     * Short circuit other modules that want to overwrite the content type
     * as soon as they detect a directory.
     */
    if (r->content_type && !strcmp(r->content_type, DAV_AUTOINDEX_HANDLER)) {
        return OK;
    }

    return DECLINED;
}

/* Use POOL to temporarily construct a dav_response object (from WRES
   STATUS, and PROPSTATS) and stream it via WRES's ctx->brigade. */
static void dav_stream_response(dav_walk_resource *wres,
                                int status,
                                dav_get_props_result *propstats,
                                apr_pool_t *pool)
{
    dav_response resp = { 0 };
    dav_autoindex_ctx *ctx = wres->walk_ctx;

    resp.href = wres->resource->uri;
    resp.status = status;
    if (propstats) {
        resp.propresult = *propstats;
    }

    dav_send_one_response(&resp, ctx->bb, ctx->r, pool);
}

static void dav_cache_badprops(dav_autoindex_ctx *ctx)
{
    const apr_xml_elem *elem;
    apr_text_header hdr = { 0 };

    /* just return if we built the thing already */
    if (ctx->propstat_404 != NULL) {
        return;
    }

    apr_text_append(ctx->w.pool, &hdr,
                    "<D:propstat>" DEBUG_CR
                    "<D:prop>" DEBUG_CR);

    elem = dav_find_child(ctx->doc->root, "prop");
    for (elem = elem->first_child; elem; elem = elem->next) {
        apr_text_append(ctx->w.pool, &hdr,
                        apr_xml_empty_elem(ctx->w.pool, elem));
    }

    apr_text_append(ctx->w.pool, &hdr,
                    "</D:prop>" DEBUG_CR
                    "<D:status>HTTP/1.1 404 Not Found</D:status>" DEBUG_CR
                    "</D:propstat>" DEBUG_CR);

    ctx->propstat_404 = hdr.first;
}

static dav_error * dav_autoindex_get_walker(dav_walk_resource *wres, int calltype)
{
    dav_autoindex_ctx *ctx = wres->walk_ctx;
    dav_error *err;
    dav_propdb *propdb;
    dav_get_props_result propstats = { 0 };
    request_rec *rr;

    /* check for any method preconditions */
    if (dav_run_method_precondition(ctx->r, NULL, wres->resource, ctx->doc, &err) != DECLINED
            && err) {
        apr_pool_clear(ctx->scratchpool);
        return NULL;
    }

    /* are we allowed to walk this resource? */
    rr = ap_sub_req_method_uri(ctx->r->method, wres->resource->uri, ctx->r, NULL);
    if (rr->status != HTTP_OK) {
        err = dav_new_error(rr->pool, rr->status, 0, 0,
                            apr_psprintf(rr->pool,
                            "DAV subrequest not allowed for %s",
                            ap_escape_html(rr->pool, rr->uri)));
        dav_log_err(rr, err, APLOG_DEBUG);
        ap_destroy_sub_req(rr);
        apr_pool_clear(ctx->scratchpool);
        return NULL;
    }
    ap_destroy_sub_req(rr);

    /*
    ** Note: ctx->doc can only be NULL for DAV_PROPFIND_IS_ALLPROP. Since
    ** dav_get_allprops() does not need to do namespace translation,
    ** we're okay.
    **
    ** Note: we cast to lose the "const". The propdb won't try to change
    ** the resource, however, since we are opening readonly.
    */
    err = dav_popen_propdb(ctx->scratchpool,
                           ctx->r, ctx->w.lockdb, wres->resource, 1,
                           ctx->doc ? ctx->doc->namespaces : NULL, &propdb);
    if (err != NULL) {
        /* ### do something with err! */

        if (ctx->propfind_type == DAV_PROPFIND_IS_PROP) {
            dav_get_props_result badprops = { 0 };

            /* some props were expected on this collection/resource */
            dav_cache_badprops(ctx);
            badprops.propstats = ctx->propstat_404;
            dav_stream_response(wres, 0, &badprops, ctx->scratchpool);
        }
        else {
            /* no props on this collection/resource */
            dav_stream_response(wres, HTTP_OK, NULL, ctx->scratchpool);
        }

        apr_pool_clear(ctx->scratchpool);
        return NULL;
    }
    /* ### what to do about closing the propdb on server failure? */

    if (ctx->propfind_type == DAV_PROPFIND_IS_PROP) {
        propstats = dav_get_props(propdb, ctx->doc);
    }
    else {
        dav_prop_insert what = ctx->propfind_type == DAV_PROPFIND_IS_ALLPROP
                                 ? DAV_PROP_INSERT_VALUE
                                 : DAV_PROP_INSERT_NAME;
        propstats = dav_get_allprops(propdb, what);
    }
    dav_stream_response(wres, 0, &propstats, ctx->scratchpool);

    dav_close_propdb(propdb);

    /* at this point, ctx->scratchpool has been used to stream a
       single response.  this function fully controls the pool, and
       thus has the right to clear it for the next iteration of this
       callback. */
    apr_pool_clear(ctx->scratchpool);

    return NULL;
}

/* Factorized helper function: prep request_rec R for a multistatus
   response and write <multistatus> tag into BB, destined for
   R->output_filters.  Use xml NAMESPACES in initial tag, if
   non-NULL. */
static void dav_begin_multistatus_stylesheet(apr_bucket_brigade *bb,
                                             request_rec *r, int status,
                                             apr_array_header_t *namespaces)
{
    dav_autoindex_config_rec *conf = ap_get_module_config(r->per_dir_config,
            &dav_autoindex_module);

    /* Set the correct status and Content-Type */
    r->status = status;
    ap_set_content_type(r, DAV_XML_CONTENT_TYPE);

    /* send the stylesheet */
    ap_fputs(r->output_filters, bb, DAV_XML_HEADER DEBUG_CR);

    if (conf->stylesheet) {
        const char *err = NULL, *stylesheet;

        stylesheet = ap_expr_str_exec(r, conf->stylesheet, &err);
        if (err) {
            ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
                            "Failure while evaluating the stylesheet URL expression for '%s', "
                            "stylesheet ignored: %s", r->uri, err);
        }
        else {
            ap_fputs(r->output_filters, bb, "<?xml-stylesheet type=\"text/xsl\" href=\"");
            ap_fputs(r->output_filters, bb, ap_escape_html(r->pool, stylesheet));
            ap_fputs(r->output_filters, bb, "\"?>" DEBUG_CR);
        }

    }

    /* Send the headers and actual multistatus response now... */
    ap_fputs(r->output_filters, bb, "<D:multistatus xmlns:D=\"DAV:\"");

    if (namespaces != NULL) {
       int i;

       for (i = namespaces->nelts; i--; ) {
           ap_fprintf(r->output_filters, bb, " xmlns:ns%d=\"%s\"", i,
                      APR_XML_GET_URI_ITEM(namespaces, i));
       }
    }

    ap_fputs(r->output_filters, bb, ">" DEBUG_CR);
}

static int dav_autoindex_handle_get(request_rec *r)
{
    dav_error *err;
    const dav_provider *provider;
    dav_resource *resource = NULL;
    dav_autoindex_ctx ctx = { { 0 } };
    dav_response *multi_status;
    const char *etag;
    int depth = 1;
    int status;

    dav_autoindex_config_rec *conf = ap_get_module_config(r->per_dir_config,
            &dav_autoindex_module);

    /* for us? */
    if (!r->handler || strcmp(r->handler, DIR_MAGIC_TYPE)) {
        return DECLINED;
    }

    /* find the dav provider */
    provider = dav_get_provider(r);
    if (provider == NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                 "DAV not enabled for %s, ignoring GET request",
                 ap_escape_html(r->pool, r->uri));
        return DECLINED;
    }

    /* resolve autoindex resource */
    if ((err = provider->repos->get_resource(r, NULL, NULL, 0, &resource))) {
        return dav_handle_err(r, err, NULL);
    }

    /* not existing or not a collection? not for us */
    if (!resource->exists || !resource->collection) {
        return DECLINED;
    }

    ctx.w.walk_type = DAV_WALKTYPE_NORMAL | DAV_WALKTYPE_AUTH;
    ctx.w.walk_ctx = &ctx;
    ctx.w.func = dav_autoindex_get_walker;
    ctx.w.pool = r->pool;
    ctx.w.root = resource;

    if (conf->properties->nelts) {
        ctx.propfind_type = DAV_PROPFIND_IS_PROP;
    }
    else {
        ctx.propfind_type = DAV_PROPFIND_IS_ALLPROP;
    }

    if (conf->properties->nelts) {
        apr_xml_elem *propfind, *prop, *elem;
        apr_xml_doc *doc;
        int i;

        ctx.doc = doc = apr_palloc(r->pool, sizeof(apr_xml_doc));
        doc->namespaces = apr_array_make(r->pool, 5, sizeof(const char *));
        apr_xml_insert_uri(doc->namespaces, DAV_XML_NAMESPACE);

        propfind = doc->root = apr_pcalloc(r->pool, sizeof(apr_xml_elem));
        propfind->name = "propfind";

        prop = apr_pcalloc(r->pool, sizeof(apr_xml_elem));
        prop->name = "prop";
        doc->root->first_child = doc->root->last_child = prop;

        prop = doc->root->first_child;

        for (i = 0; i < conf->properties->nelts; ++i) {
            dav_prop_name *name = &APR_ARRAY_IDX(conf->properties, i, dav_prop_name);

            elem = apr_pcalloc(r->pool, sizeof(apr_xml_elem));

            elem->name = name->name;
            elem->ns = apr_xml_insert_uri(doc->namespaces,
                            name->ns);

            /* set up the child/sibling links */
            if (prop->last_child == NULL) {
                /* no first child either */
                prop->first_child = prop->last_child = elem;
            }
            else {
                /* hook onto the end of the parent's children */
                prop->last_child->next = elem;
                prop->last_child = elem;
            }
        }

    }

    ctx.r = r;
    ctx.bb = apr_brigade_create(r->pool, r->connection->bucket_alloc);
    apr_pool_create(&ctx.scratchpool, r->pool);
    apr_pool_tag(ctx.scratchpool, "mod_dav-scratch");


    /* ### should open read-only */
    if ((err = dav_open_lockdb(r, 0, &ctx.w.lockdb)) != NULL) {
        err = dav_push_error(r->pool, err->status, 0,
                             "The lock database could not be opened, "
                             "preventing access to the various lock "
                             "properties for the autoindex GET.",
                             err);
        return dav_handle_err(r, err, NULL);
    }
    if (ctx.w.lockdb != NULL) {
        /* if we have a lock database, then we can walk locknull resources */
        ctx.w.walk_type |= DAV_WALKTYPE_LOCKNULL;
    }

    /* Have the provider walk the resource. */
    etag = (*resource->hooks->getetag)(resource);

    if (etag) {
        apr_table_set(r->headers_out, "ETag", etag);
    }

    /* handle conditional requests */
    status = ap_meets_conditions(r);
    if (status) {
        return status;
    }

    /* send <multistatus> tag, with all doc->namespaces attached.  */

    /* NOTE: we *cannot* leave out the doc's namespaces from the
       initial <multistatus> tag.  if a 404 was generated for an HREF,
       then we need to spit out the doc's namespaces for use by the
       404. Note that <response> elements will override these ns0,
       ns1, etc, but NOT within the <response> scope for the
       badprops. */
    dav_begin_multistatus_stylesheet(ctx.bb, r, HTTP_MULTI_STATUS,
            ctx.doc ? ctx.doc->namespaces : NULL);

    /* Have the provider walk the resource. */
    err = (*resource->hooks->walk)(&ctx.w, depth, &multi_status);

    if (ctx.w.lockdb != NULL) {
        (*ctx.w.lockdb->hooks->close_lockdb)(ctx.w.lockdb);
    }

    if (err != NULL) {
        /* If an error occurred during the resource walk, there's
           basically nothing we can do but abort the connection and
           log an error.  This is one of the limitations of HTTP; it
           needs to "know" the entire status of the response before
           generating it, which is just impossible in these streamy
           response situations. */
        err = dav_push_error(r->pool, err->status, 0,
                             "Provider encountered an error while streaming"
                             " a multistatus PROPFIND response.", err);
        dav_log_err(r, err, APLOG_ERR);
        r->connection->aborted = 1;
        return DONE;
    }

    dav_finish_multistatus(r, ctx.bb);

    /* the response has been sent. */
    return DONE;
}

static int dav_autoindex_handler(request_rec *r)
{
    dav_autoindex_config_rec *conf = ap_get_module_config(r->per_dir_config,
            &dav_autoindex_module);

    if (!conf || !conf->dav_autoindex) {
        return DECLINED;
    }

    if (r->method_number == M_GET) {
        return dav_autoindex_handle_get(r);
    }

    return DECLINED;
}

static void register_hooks(apr_pool_t *p)
{
    static const char * const aszSucc[]={ "mod_autoindex.c",
                                          "mod_userdir.c",
                                          "mod_vhost_alias.c", NULL };

    ap_hook_type_checker(dav_autoindex_type_checker, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_handler(dav_autoindex_handler, NULL, aszSucc, APR_HOOK_MIDDLE);

}

AP_DECLARE_MODULE(dav_autoindex) =
{
    STANDARD20_MODULE_STUFF,
    create_dav_autoindex_dir_config, /* dir config creater */
    merge_dav_autoindex_dir_config,  /* dir merger --- default is to override */
    NULL,                            /* server config */
    NULL,                            /* merge server config */
    dav_autoindex_cmds,              /* command apr_table_t */
    register_hooks                   /* register hooks */
};
