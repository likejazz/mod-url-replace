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
 * mod_url_replace.c: Replace OLD urls to NEW urls based on mod_substitute.c
 *
 * Jul 2015
 * Sang-Kil Park
 */

#include "httpd.h"
#include "http_config.h"
#include "http_log.h"
#include "http_core.h"
#include "apr_strings.h"
#include "apr_strmatch.h"

static const char filter_name[] = "URL-REPLACE";

module AP_MODULE_DECLARE_DATA url_replace_module;

typedef struct subst_pattern_t {
    const apr_strmatch_pattern *pattern;
    const char *replacement;
    apr_size_t replen;
    apr_size_t patlen;
} subst_pattern_t;

typedef struct {
    apr_array_header_t *patterns;
} subst_dir_conf;

typedef struct {
    apr_bucket_brigade *linebb;
    apr_bucket_brigade *linesbb;
    apr_bucket_brigade *passbb;
    apr_bucket_brigade *pattbb;
    apr_pool_t *tpool;
} substitute_module_ctx;

static void *add_pattern(apr_pool_t *p, void *cfg, char *from, char *to) {
    subst_pattern_t *script;

    script = apr_array_push(((subst_dir_conf *) cfg)->patterns);

    script->patlen = strlen(from);
    script->pattern = apr_strmatch_precompile(p, from, 0); // case-insensitive

    script->replacement = to;
    script->replen = strlen(to);

    return NULL;
}

static void *create_substitute_dcfg(apr_pool_t *p, char *d)
{
    subst_dir_conf *dcfg =
    (subst_dir_conf *) apr_pcalloc(p, sizeof(subst_dir_conf));

    dcfg->patterns = apr_array_make(p, 10, sizeof(subst_pattern_t));

    /* ------------------------- ADD PATTERNS HERE -------------------------- */

    char *spdy_addr = "//t99.search.daumcdn.net/";

    add_pattern(p, dcfg, "//t1.search.daumcdn.net/", spdy_addr);
    add_pattern(p, dcfg, "//t2.search.daumcdn.net/", spdy_addr);
    add_pattern(p, dcfg, "//t3.search.daumcdn.net/", spdy_addr);
    add_pattern(p, dcfg, "//t4.search.daumcdn.net/", spdy_addr);

    /* ---------------------------------------------------------------------- */

    return dcfg;
}

#define AP_MAX_BUCKETS 1000

#define SEDSCAT(s1, s2, pool, buff, blen, repl) do { \
    if (!s1) {                                       \
        s1 = apr_pstrmemdup(pool, buff, blen);       \
    }                                                \
    else {                                           \
        s2 = apr_pstrmemdup(pool, buff, blen);       \
        s1 = apr_pstrcat(pool, s1, s2, NULL);        \
    }                                                \
    s1 = apr_pstrcat(pool, s1, repl, NULL);          \
} while (0)


static void do_pattmatch(ap_filter_t *f, apr_bucket *inb,
                         apr_bucket_brigade *mybb,
                         apr_pool_t *tmp_pool)
{
    int i;
    apr_size_t bytes;
    apr_size_t len;
    const char *buff;
    const char *repl;
    char *s1;
    char *s2;
    apr_bucket *b;
    apr_bucket *tmp_b;

    subst_dir_conf *cfg =
    (subst_dir_conf *) ap_get_module_config(f->r->per_dir_config,
                                             &url_replace_module);
    subst_pattern_t *script;

    APR_BRIGADE_INSERT_TAIL(mybb, inb);
    
    script = (subst_pattern_t *) cfg->patterns->elts;

    for (i = 0; i < cfg->patterns->nelts; i++) {
        for (b = APR_BRIGADE_FIRST(mybb);
             b != APR_BRIGADE_SENTINEL(mybb);
             b = APR_BUCKET_NEXT(b)) {
            if (APR_BUCKET_IS_METADATA(b)) {
                /*
                 * we should NEVER see this, because we should never
                 * be passed any, but "handle" it just in case.
                 */
                continue;
            }
            if (apr_bucket_read(b, &buff, &bytes, APR_BLOCK_READ)
                    == APR_SUCCESS) {
                s1 = NULL;
                while ((repl = apr_strmatch(script->pattern, buff, bytes)))
                {
                    /* get offset into buff for pattern */
                    len = (apr_size_t) (repl - buff);
                    /*
                     * We are flattening the buckets here, meaning
                     * that we don't do the fast bucket splits.
                     * Instead we copy over what the buckets would
                     * contain and use them. This is slow, since we
                     * are constanting allocing space and copying
                     * strings.
                     */
                    SEDSCAT(s1, s2, tmp_pool, buff, len, script->replacement);

                    /* now we need to adjust buff for all these changes */
                    len += script->patlen;
                    bytes -= len;
                    buff += len;
                }

                if (s1) {
                    /*
                     * we've finished looking at the bucket, so remove the
                     * old one and add in our new one
                     */
                    s2 = apr_pstrmemdup(tmp_pool, buff, bytes);
                    s1 = apr_pstrcat(tmp_pool, s1, s2, NULL);
                    tmp_b = apr_bucket_transient_create(s1, strlen(s1),
                                        f->r->connection->bucket_alloc);
                    APR_BUCKET_INSERT_BEFORE(b, tmp_b);
                    apr_bucket_delete(b);
                    b = tmp_b;
                }

            }
        }
        script++;
    }

    return;
}



static apr_status_t url_replace_filter(ap_filter_t *f, apr_bucket_brigade *bb)
{
    /*
     * Running log
     *
     * ap_log_error(APLOG_MARK, APLOG_ERR, OK, f->r->server, "url_replace_filter");
     */

    apr_size_t bytes;
    apr_size_t len;
    apr_size_t fbytes;
    const char *buff;
    const char *nl = NULL;
    char *bflat;
    apr_bucket *b;
    apr_bucket *tmp_b;
    apr_bucket_brigade *tmp_bb = NULL;
    apr_status_t rv;

    substitute_module_ctx *ctx = f->ctx;

    /*
     * First time around? Create the saved bb that we used for each pass
     * through. Note that we can also get here when we explicitly clear ctx,
     * for error handling
     */
    if (!ctx) {
        f->ctx = ctx = apr_pcalloc(f->r->pool, sizeof(*ctx));
        /*
         * Create all the temporary brigades we need and reuse them to avoid
         * creating them over and over again from r->pool which would cost a
         * lot of memory in some cases.
         */
        ctx->linebb = apr_brigade_create(f->r->pool, f->c->bucket_alloc);
        ctx->linesbb = apr_brigade_create(f->r->pool, f->c->bucket_alloc);
        ctx->pattbb = apr_brigade_create(f->r->pool, f->c->bucket_alloc);
        /*
         * Everything to be passed to the next filter goes in
         * here, our pass brigade.
         */
        ctx->passbb = apr_brigade_create(f->r->pool, f->c->bucket_alloc);
        /* Create our temporary pool only once */
        apr_pool_create(&(ctx->tpool), f->r->pool);
        apr_table_unset(f->r->headers_out, "Content-Length");
    }

    /*
     * Shortcircuit processing
     */
    if (APR_BRIGADE_EMPTY(bb))
        return APR_SUCCESS;

    /*
     * Here's the concept:
     *  Read in the data and look for newlines. Once we
     *  find a full "line", add it to our working brigade.
     *  If we've finished reading the brigade and we have
     *  any left over data (not a "full" line), store that
     *  for the next pass.
     *
     * Note: anything stored in ctx->linebb for sure does not have
     * a newline char, so we don't concat that bb with the
     * new bb, since we would spending time searching for the newline
     * in data we know it doesn't exist. So instead, we simply scan
     * our current bb and, if we see a newline, prepend ctx->linebb
     * to the front of it. This makes the code much less straight-
     * forward (otherwise we could APR_BRIGADE_CONCAT(ctx->linebb, bb)
     * and just scan for newlines and not bother with needing to know
     * when ctx->linebb needs to be reset) but also faster. We'll take
     * the speed.
     *
     * Note: apr_brigade_split_line would be nice here, but we
     * really can't use it since we need more control and we want
     * to re-use already read bucket data.
     *
     * See mod_include if still confused :)
     */

    while ((b = APR_BRIGADE_FIRST(bb)) && (b != APR_BRIGADE_SENTINEL(bb))) {
        if (APR_BUCKET_IS_EOS(b)) {
            /*
             * if we see the EOS, then we need to pass along everything we
             * have. But if the ctx->linebb isn't empty, then we need to add
             * that to the end of what we'll be passing.
             */
            if (!APR_BRIGADE_EMPTY(ctx->linebb)) {
                rv = apr_brigade_pflatten(ctx->linebb, &bflat,
                                          &fbytes, ctx->tpool);
                tmp_b = apr_bucket_transient_create(bflat, fbytes,
                                                f->r->connection->bucket_alloc);
                do_pattmatch(f, tmp_b, ctx->pattbb, ctx->tpool);
                APR_BRIGADE_CONCAT(ctx->passbb, ctx->pattbb);
            }
            apr_brigade_cleanup(ctx->linebb);
            APR_BUCKET_REMOVE(b);
            APR_BRIGADE_INSERT_TAIL(ctx->passbb, b);
        }
        /*
         * No need to handle FLUSH buckets separately as we call
         * ap_pass_brigade anyway at the end of the loop.
         */
        else if (APR_BUCKET_IS_METADATA(b)) {
            APR_BUCKET_REMOVE(b);
            APR_BRIGADE_INSERT_TAIL(ctx->passbb, b);
        }
        else {
            /*
             * We have actual "data" so read in as much as we can and start
             * scanning and splitting from our read buffer
             */
            rv = apr_bucket_read(b, &buff, &bytes, APR_BLOCK_READ);
            if (rv != APR_SUCCESS || bytes == 0) {
                apr_bucket_delete(b);
            }
            else {
                int num = 0;
                while (bytes > 0) {
                    nl = memchr(buff, APR_ASCII_LF, bytes);
                    if (nl) {
                        len = (apr_size_t) (nl - buff) + 1;
                        /* split *after* the newline */
                        apr_bucket_split(b, len);
                        /*
                         * We've likely read more data, so bypass rereading
                         * bucket data and continue scanning through this
                         * buffer
                         */
                        bytes -= len;
                        buff += len;
                        /*
                         * we need b to be updated for future potential
                         * splitting
                         */
                        tmp_b = APR_BUCKET_NEXT(b);
                        APR_BUCKET_REMOVE(b);
                        /*
                         * Hey, we found a newline! Don't forget the old
                         * stuff that needs to be added to the front. So we
                         * add the split bucket to the end, flatten the whole
                         * bb, morph the whole shebang into a bucket which is
                         * then added to the tail of the newline bb.
                         */
                        if (!APR_BRIGADE_EMPTY(ctx->linebb)) {
                            APR_BRIGADE_INSERT_TAIL(ctx->linebb, b);
                            rv = apr_brigade_pflatten(ctx->linebb, &bflat,
                                                      &fbytes, ctx->tpool);
                            b = apr_bucket_transient_create(bflat, fbytes,
                                            f->r->connection->bucket_alloc);
                            apr_brigade_cleanup(ctx->linebb);
                        }
                        do_pattmatch(f, b, ctx->pattbb, ctx->tpool);
                        /*
                         * Count how many buckets we have in ctx->passbb
                         * so far. Yes, this is correct we count ctx->passbb
                         * and not ctx->pattbb as we do not reset num on every
                         * iteration.
                         */
                        for (b = APR_BRIGADE_FIRST(ctx->pattbb);
                             b != APR_BRIGADE_SENTINEL(ctx->pattbb);
                             b = APR_BUCKET_NEXT(b)) {
                            num++;
                        }
                        APR_BRIGADE_CONCAT(ctx->passbb, ctx->pattbb);
                        /*
                         * If the number of buckets in ctx->passbb reaches an
                         * "insane" level, we consume much memory for all the
                         * buckets as such. So lets flush them down the chain
                         * in this case and thus clear ctx->passbb. This frees
                         * the buckets memory for further processing.
                         * Usually this condition should not become true, but
                         * it is a safety measure for edge cases.
                         */
                        if (num > AP_MAX_BUCKETS) {
                            b = apr_bucket_flush_create(
                                                f->r->connection->bucket_alloc);
                            APR_BRIGADE_INSERT_TAIL(ctx->passbb, b);
                            rv = ap_pass_brigade(f->next, ctx->passbb);
                            apr_brigade_cleanup(ctx->passbb);
                            num = 0;
                            apr_pool_clear(ctx->tpool);
                            if (rv != APR_SUCCESS)
                                return rv;
                        }
                        b = tmp_b;
                    }
                    else {
                        /*
                         * no newline in whatever is left of this buffer so
                         * tuck data away and get next bucket
                         */
                        APR_BUCKET_REMOVE(b);
                        APR_BRIGADE_INSERT_TAIL(ctx->linebb, b);
                        bytes = 0;
                    }
                }
            }
        }
        if (!APR_BRIGADE_EMPTY(ctx->passbb)) {
            rv = ap_pass_brigade(f->next, ctx->passbb);
            apr_brigade_cleanup(ctx->passbb);
            if (rv != APR_SUCCESS) {
                apr_pool_clear(ctx->tpool);
                return rv;
            }
        }
        apr_pool_clear(ctx->tpool);
    }

    /* Anything left we want to save/setaside for the next go-around */
    if (!APR_BRIGADE_EMPTY(ctx->linebb)) {
        /*
         * Provide ap_save_brigade with an existing empty brigade
         * (ctx->linesbb) to avoid creating a new one.
         */
        ap_save_brigade(f, &(ctx->linesbb), &(ctx->linebb), f->r->pool);
        tmp_bb = ctx->linebb;
        ctx->linebb = ctx->linesbb;
        ctx->linesbb = tmp_bb;
    }

    return APR_SUCCESS;
}

static void register_hooks(apr_pool_t *pool)
{
    ap_register_output_filter(filter_name, url_replace_filter,
                              NULL, AP_FTYPE_RESOURCE);
}


module AP_MODULE_DECLARE_DATA url_replace_module = {
    STANDARD20_MODULE_STUFF,
    create_substitute_dcfg,     /* dir config creater */
    NULL,                       /* dir merger --- default is to override */
    NULL,                       /* server config */
    NULL,                       /* merge server config */
    NULL,                       /* command table */
    register_hooks              /* register hooks */
};
