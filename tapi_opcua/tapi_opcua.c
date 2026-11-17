/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Interpretica, Unipessoal Lda. All rights reserved. */
/** @file
 * @brief OPC UA TAPI: connections, values and data access
 *
 * Builds the "key=value" option strings the agent expects, calls the
 * opcua_* RPCs through rpc_opcua_call(), and parses the text results.
 * A connection, a subscription and a simulated server are each a small
 * integer handle on the agent; the handle structs here hold it with the
 * RPC server to reach it. The last failure class and StatusCode of a
 * connection are kept in a side table so a test can ask why a connect
 * failed without threading them through every call.
 */

#define TE_LGR_USER     "TAPI OPCUA"

#include "te_config.h"

#include <stdlib.h>
#include <string.h>

#include "te_defs.h"
#include "te_errno.h"
#include "te_string.h"
#include "te_alloc.h"
#include "logger_api.h"

#include "tapi_opcua.h"

/* The last failure of each connection, kept out of the handle struct so
 * the struct stays a plain {rpcs, id}. Keyed by (rpcs, id). */
#define FAILTAB_SIZE 256
static struct {
    rcf_rpc_server *rpcs;
    int             id;
    tapi_opcua_fail fail;
    uint32_t        status;
} failtab[FAILTAB_SIZE];

static void
remember_fail(const tapi_opcua_conn *conn, const tapi_opcua_rpc_res *res)
{
    unsigned int i;
    int free_slot = -1;

    for (i = 0; i < FAILTAB_SIZE; i++)
    {
        if (failtab[i].rpcs == conn->rpcs && failtab[i].id == conn->id)
        {
            failtab[i].fail = (tapi_opcua_fail)res->fail_cls;
            failtab[i].status = res->status;
            return;
        }
        if (free_slot < 0 && failtab[i].rpcs == NULL)
            free_slot = (int)i;
    }
    if (free_slot >= 0)
    {
        failtab[free_slot].rpcs = conn->rpcs;
        failtab[free_slot].id = conn->id;
        failtab[free_slot].fail = (tapi_opcua_fail)res->fail_cls;
        failtab[free_slot].status = res->status;
    }
}

tapi_opcua_fail
tapi_opcua_last_fail(const tapi_opcua_conn *conn)
{
    unsigned int i;

    for (i = 0; i < FAILTAB_SIZE; i++)
        if (failtab[i].rpcs == conn->rpcs && failtab[i].id == conn->id)
            return failtab[i].fail;
    return TAPI_OPCUA_FAIL_NONE;
}

uint32_t
tapi_opcua_last_status(const tapi_opcua_conn *conn)
{
    unsigned int i;

    for (i = 0; i < FAILTAB_SIZE; i++)
        if (failtab[i].rpcs == conn->rpcs && failtab[i].id == conn->id)
            return failtab[i].status;
    return 0;
}

/* ---- key-value parsing -------------------------------------------- */

static void
kv_add(tapi_opcua_kv *kv, const char *k, size_t klen, const char *v,
       size_t vlen)
{
    kv->keys = TE_REALLOC(kv->keys, (kv->n + 1) * sizeof(char *));
    kv->vals = TE_REALLOC(kv->vals, (kv->n + 1) * sizeof(char *));
    kv->keys[kv->n] = TE_STRNDUP(k, klen);
    kv->vals[kv->n] = TE_STRNDUP(v, vlen);
    kv->n++;
}

static void
kv_parse_sep(const char *text, char sep, tapi_opcua_kv *kv)
{
    const char *p = text;

    if (text == NULL)
        return;
    while (*p != '\0')
    {
        const char *end = p;
        const char *eq;

        while (*end != '\0' && *end != sep)
            end++;
        eq = memchr(p, '=', (size_t)(end - p));
        if (eq != NULL)
            kv_add(kv, p, (size_t)(eq - p), eq + 1, (size_t)(end - eq - 1));
        if (*end == '\0')
            break;
        p = end + 1;
    }
}

void
tapi_opcua_kv_parse(const char *text, tapi_opcua_kv *kv)
{
    kv_parse_sep(text, '\n', kv);
}

void
tapi_opcua_kv_parse_record(const char *record, tapi_opcua_kv *kv)
{
    kv_parse_sep(record, '\t', kv);
}

const char *
tapi_opcua_kv_get(const tapi_opcua_kv *kv, const char *key)
{
    size_t i;

    for (i = 0; i < kv->n; i++)
        if (strcmp(kv->keys[i], key) == 0)
            return kv->vals[i];
    return NULL;
}

int64_t
tapi_opcua_kv_get_int(const tapi_opcua_kv *kv, const char *key, int64_t dflt)
{
    const char *v = tapi_opcua_kv_get(kv, key);

    return v != NULL ? (int64_t)strtoll(v, NULL, 0) : dflt;
}

void
tapi_opcua_kv_free(tapi_opcua_kv *kv)
{
    size_t i;

    for (i = 0; i < kv->n; i++)
    {
        free(kv->keys[i]);
        free(kv->vals[i]);
    }
    free(kv->keys);
    free(kv->vals);
    kv->keys = NULL;
    kv->vals = NULL;
    kv->n = 0;
}

char *
tapi_opcua_report_next(const char *report, size_t *offset)
{
    const char *p;
    const char *nl;

    if (report == NULL)
        return NULL;
    p = report + *offset;
    if (*p == '\0')
        return NULL;
    nl = strchr(p, '\n');
    if (nl == NULL)
    {
        *offset += strlen(p);
        return TE_STRDUP(p);
    }
    *offset += (size_t)(nl - p) + 1;
    return TE_STRNDUP(p, (size_t)(nl - p));
}

/* ---- value parsing ------------------------------------------------ */

/* Parse "<Type>:<payload>" / "<Type>[<n>]:..." into @p value. */
static void
value_parse(const char *raw, tapi_opcua_value *value)
{
    const char *colon = raw != NULL ? strchr(raw, ':') : NULL;
    size_t tlen;
    char *tname;

    memset(value, 0, sizeof(*value));
    value->type = TAPI_OPCUA_NULL;
    if (colon == NULL)
    {
        value->type_name = TE_STRDUP("Null");
        value->raw = TE_STRDUP(raw != NULL ? raw : "");
        return;
    }
    tlen = (size_t)(colon - raw);
    tname = TE_STRNDUP(raw, tlen);
    value->raw = TE_STRDUP(colon + 1);

    {
        char *br = strchr(tname, '[');

        if (br != NULL)
        {
            value->is_array = true;
            value->array_len = (size_t)strtoul(br + 1, NULL, 10);
            *br = '\0';
        }
    }
    value->type_name = tname;

    if (strcmp(tname, "Null") == 0)
        value->type = TAPI_OPCUA_NULL;
    else if (strcmp(tname, "Boolean") == 0)
    {
        value->type = TAPI_OPCUA_BOOL;
        value->data.b = strcmp(value->raw, "true") == 0;
    }
    else if (strcmp(tname, "Float") == 0 || strcmp(tname, "Double") == 0)
    {
        value->type = TAPI_OPCUA_DOUBLE;
        value->data.f64 = strtod(value->raw, NULL);
    }
    else if (strcmp(tname, "SByte") == 0 || strcmp(tname, "Int16") == 0 ||
             strcmp(tname, "Int32") == 0 || strcmp(tname, "Int64") == 0)
    {
        value->type = TAPI_OPCUA_INT;
        value->data.i64 = (int64_t)strtoll(value->raw, NULL, 10);
    }
    else if (strcmp(tname, "Byte") == 0 || strcmp(tname, "UInt16") == 0 ||
             strcmp(tname, "UInt32") == 0 || strcmp(tname, "UInt64") == 0)
    {
        value->type = TAPI_OPCUA_UINT;
        value->data.u64 = (uint64_t)strtoull(value->raw, NULL, 10);
    }
    else if (strcmp(tname, "String") == 0 ||
             strcmp(tname, "LocalizedText") == 0 ||
             strcmp(tname, "XmlElement") == 0)
        value->type = TAPI_OPCUA_STRING;
    else if (strcmp(tname, "ByteString") == 0)
        value->type = TAPI_OPCUA_BYTES;
    else if (strcmp(tname, "DateTime") == 0)
    {
        value->type = TAPI_OPCUA_DATETIME;
        value->data.i64 = (int64_t)strtoll(value->raw, NULL, 10);
    }
    else if (strcmp(tname, "StatusCode") == 0)
    {
        value->type = TAPI_OPCUA_STATUSCODE;
        value->data.u64 = (uint64_t)strtoull(value->raw, NULL, 0);
    }
    else if (strcmp(tname, "NodeId") == 0)
        value->type = TAPI_OPCUA_NODEID;
    else
        value->type = TAPI_OPCUA_OTHER;
}

/* Fill a value from a read/notification record's fields. */
static void
value_from_record(const char *record, tapi_opcua_value *value)
{
    tapi_opcua_kv kv = TAPI_OPCUA_KV_INIT;
    const char *v;

    tapi_opcua_kv_parse_record(record, &kv);
    value_parse(tapi_opcua_kv_get(&kv, "value"), value);
    v = tapi_opcua_kv_get(&kv, "status");
    if (v != NULL)
        value->status = (uint32_t)strtoul(v, NULL, 0);
    v = tapi_opcua_kv_get(&kv, "source_ts");
    if (v != NULL && strcmp(v, "none") != 0)
    {
        value->has_source_ts = true;
        value->source_ts = (int64_t)strtoll(v, NULL, 10);
    }
    v = tapi_opcua_kv_get(&kv, "server_ts");
    if (v != NULL && strcmp(v, "none") != 0)
    {
        value->has_server_ts = true;
        value->server_ts = (int64_t)strtoll(v, NULL, 10);
    }
    tapi_opcua_kv_free(&kv);
}

void
tapi_opcua_value_free(tapi_opcua_value *value)
{
    free(value->type_name);
    free(value->raw);
    value->type_name = NULL;
    value->raw = NULL;
}

/* ---- capability --------------------------------------------------- */

bool
tapi_opcua_available(rcf_rpc_server *rpcs)
{
    tapi_opcua_rpc_args a = { 0 };
    tapi_opcua_rpc_res res = TAPI_OPCUA_RPC_RES_INIT;
    te_errno rc;

    rc = rpc_opcua_call(rpcs, TAPI_OPCUA_OP_AVAILABLE, &a, 0, &res);
    tapi_opcua_rpc_res_free(&res);
    return rc == 0;
}

te_errno
tapi_opcua_get_capabilities(rcf_rpc_server *rpcs, unsigned int *features,
                            te_string *versions)
{
    tapi_opcua_rpc_args a = { 0 };
    tapi_opcua_rpc_res res = TAPI_OPCUA_RPC_RES_INIT;
    te_errno rc;

    rc = rpc_opcua_call(rpcs, TAPI_OPCUA_OP_AVAILABLE, &a, 0, &res);
    if (features != NULL)
        *features = res.features;
    if (versions != NULL)
        te_string_append(versions, "%s", res.result.ptr != NULL ?
                         res.result.ptr : "");
    tapi_opcua_rpc_res_free(&res);
    return rc;
}

/* ---- connect ------------------------------------------------------ */

static const char *
mode_str(tapi_opcua_mode m)
{
    switch (m)
    {
        case TAPI_OPCUA_MODE_NONE: return "none";
        case TAPI_OPCUA_MODE_SIGN: return "sign";
        case TAPI_OPCUA_MODE_SIGN_ENCRYPT: return "signencrypt";
        default: return "any";
    }
}

/* Append "key=value\n" unless the value is NULL/empty. */
static void
opt_add(te_string *p, const char *key, const char *val)
{
    if (val != NULL && *val != '\0')
        te_string_append(p, "%s=%s\n", key, val);
}

static void
opt_add_int(te_string *p, const char *key, int val)
{
    if (val != 0)
        te_string_append(p, "%s=%d\n", key, val);
}

te_errno
tapi_opcua_connect(rcf_rpc_server *rpcs, const tapi_opcua_connect_opt *opt,
                   tapi_opcua_conn *conn)
{
    te_string params = TE_STRING_INIT;
    tapi_opcua_rpc_args a = { 0 };
    tapi_opcua_rpc_res res = TAPI_OPCUA_RPC_RES_INIT;
    te_errno rc;

    conn->rpcs = rpcs;
    conn->id = 0;
    opt_add(&params, "security_policy", opt->security_policy);
    te_string_append(&params, "security_mode=%s\n",
                     mode_str(opt->security_mode));
    opt_add(&params, "auth", opt->auth);
    opt_add(&params, "user", opt->user);
    opt_add(&params, "password", opt->password);
    opt_add(&params, "user_cert", opt->user_cert);
    opt_add(&params, "user_key", opt->user_key);
    opt_add(&params, "cert", opt->cert);
    opt_add(&params, "key", opt->key);
    opt_add(&params, "trust", opt->trust);
    opt_add(&params, "crl", opt->crl);
    opt_add(&params, "app_uri", opt->app_uri);
    opt_add_int(&params, "connect_timeout_ms", opt->connect_timeout_ms);
    opt_add_int(&params, "session_timeout_ms", opt->session_timeout_ms);
    opt_add_int(&params, "request_timeout_ms", opt->request_timeout_ms);
    opt_add_int(&params, "channel_lifetime_ms", opt->channel_lifetime_ms);
    if (opt->no_reconnect)
        te_string_append(&params, "no_reconnect=1\n");

    a.arg = opt->endpoint;
    a.params = params.ptr;
    rc = rpc_opcua_call(rpcs, TAPI_OPCUA_OP_CONNECT, &a, 0, &res);
    conn->id = res.handle;
    remember_fail(conn, &res);
    if (rc != 0 && res.errmsg.ptr != NULL)
        RING("opcua connect: %s", res.errmsg.ptr);
    te_string_free(&params);
    tapi_opcua_rpc_res_free(&res);
    return rc;
}

static te_errno
simple_op(tapi_opcua_conn *conn, tapi_opcua_op op, const char *arg,
          const char *params, const char *data, tapi_opcua_rpc_res *res)
{
    tapi_opcua_rpc_args a = { 0 };

    a.h1 = conn->id;
    a.arg = arg;
    a.params = params;
    a.data = data;
    return rpc_opcua_call(conn->rpcs, op, &a, 0, res);
}

te_errno
tapi_opcua_disconnect(tapi_opcua_conn *conn)
{
    tapi_opcua_rpc_res res = TAPI_OPCUA_RPC_RES_INIT;
    te_errno rc;

    if (conn->id == 0)
        return 0;
    rc = simple_op(conn, TAPI_OPCUA_OP_DISCONNECT, NULL, NULL, NULL, &res);
    conn->id = 0;
    tapi_opcua_rpc_res_free(&res);
    return rc;
}

te_errno
tapi_opcua_reconnect(tapi_opcua_conn *conn)
{
    tapi_opcua_rpc_res res = TAPI_OPCUA_RPC_RES_INIT;
    te_errno rc;

    rc = simple_op(conn, TAPI_OPCUA_OP_RECONNECT, NULL, NULL, NULL, &res);
    remember_fail(conn, &res);
    tapi_opcua_rpc_res_free(&res);
    return rc;
}

bool
tapi_opcua_is_connected(tapi_opcua_conn *conn)
{
    tapi_opcua_rpc_res res = TAPI_OPCUA_RPC_RES_INIT;
    tapi_opcua_kv kv = TAPI_OPCUA_KV_INIT;
    bool connected = false;
    const char *v;

    if (simple_op(conn, TAPI_OPCUA_OP_STATE, NULL, NULL, NULL, &res) == 0)
    {
        tapi_opcua_kv_parse(res.result.ptr, &kv);
        v = tapi_opcua_kv_get(&kv, "connected");
        connected = v != NULL && strcmp(v, "1") == 0;
        tapi_opcua_kv_free(&kv);
    }
    tapi_opcua_rpc_res_free(&res);
    return connected;
}

te_errno
tapi_opcua_get_session_info(tapi_opcua_conn *conn, tapi_opcua_kv *info)
{
    tapi_opcua_rpc_res res = TAPI_OPCUA_RPC_RES_INIT;
    te_errno rc;

    rc = simple_op(conn, TAPI_OPCUA_OP_STATE, NULL, NULL, NULL, &res);
    if (info != NULL)
        tapi_opcua_kv_parse(res.result.ptr, info);
    tapi_opcua_rpc_res_free(&res);
    return rc;
}

te_errno
tapi_opcua_wait_session(tapi_opcua_conn *conn, int timeout_ms)
{
    te_string params = TE_STRING_INIT;
    tapi_opcua_rpc_res res = TAPI_OPCUA_RPC_RES_INIT;
    te_errno rc;

    te_string_append(&params, "timeout_ms=%d\n", timeout_ms);
    rc = simple_op(conn, TAPI_OPCUA_OP_WAIT_SESSION, NULL, params.ptr, NULL,
                   &res);
    remember_fail(conn, &res);
    te_string_free(&params);
    tapi_opcua_rpc_res_free(&res);
    return rc;
}

/* ---- data access -------------------------------------------------- */

te_errno
tapi_opcua_read_attribute(tapi_opcua_conn *conn, const char *node,
                          const char *attribute, tapi_opcua_value *value)
{
    te_string params = TE_STRING_INIT;
    tapi_opcua_rpc_res res = TAPI_OPCUA_RPC_RES_INIT;
    te_errno rc;

    if (attribute != NULL)
        te_string_append(&params, "attribute=%s\n", attribute);
    rc = simple_op(conn, TAPI_OPCUA_OP_READ, NULL, params.ptr, node, &res);
    remember_fail(conn, &res);
    memset(value, 0, sizeof(*value));
    if (rc == 0 && res.report.ptr != NULL && *res.report.ptr != '\0')
    {
        size_t off = 0;
        char *rec = tapi_opcua_report_next(res.report.ptr, &off);

        if (rec != NULL)
            value_from_record(rec, value);
        free(rec);
    }
    else
    {
        value->type_name = TE_STRDUP("Null");
        value->raw = TE_STRDUP("");
    }
    te_string_free(&params);
    tapi_opcua_rpc_res_free(&res);
    return rc;
}

te_errno
tapi_opcua_read(tapi_opcua_conn *conn, const char *node,
                tapi_opcua_value *value)
{
    return tapi_opcua_read_attribute(conn, node, NULL, value);
}

te_errno
tapi_opcua_read_many(tapi_opcua_conn *conn, const char *nodes,
                     tapi_opcua_value **values, size_t *n)
{
    tapi_opcua_rpc_res res = TAPI_OPCUA_RPC_RES_INIT;
    te_errno rc;
    size_t off = 0;
    char *rec;

    *values = NULL;
    *n = 0;
    rc = simple_op(conn, TAPI_OPCUA_OP_READ, NULL, NULL, nodes, &res);
    remember_fail(conn, &res);
    while ((rec = tapi_opcua_report_next(res.report.ptr, &off)) != NULL)
    {
        *values = TE_REALLOC(*values, (*n + 1) * sizeof(**values));
        value_from_record(rec, &(*values)[*n]);
        (*n)++;
        free(rec);
    }
    tapi_opcua_rpc_res_free(&res);
    return rc;
}

te_errno
tapi_opcua_write(tapi_opcua_conn *conn, const char *node, const char *value,
                 uint32_t *status)
{
    te_string data = TE_STRING_INIT;
    tapi_opcua_rpc_res res = TAPI_OPCUA_RPC_RES_INIT;
    te_errno rc;

    te_string_append(&data, "%s\t%s", node, value);
    rc = simple_op(conn, TAPI_OPCUA_OP_WRITE, NULL, NULL, data.ptr, &res);
    remember_fail(conn, &res);
    if (status != NULL)
        *status = res.status;
    te_string_free(&data);
    tapi_opcua_rpc_res_free(&res);
    return rc;
}

te_errno
tapi_opcua_write_many(tapi_opcua_conn *conn, const char *data,
                      tapi_opcua_kv *statuses)
{
    tapi_opcua_rpc_res res = TAPI_OPCUA_RPC_RES_INIT;
    te_errno rc;

    rc = simple_op(conn, TAPI_OPCUA_OP_WRITE, NULL, NULL, data, &res);
    remember_fail(conn, &res);
    if (statuses != NULL && res.report.ptr != NULL)
    {
        size_t off = 0;
        char *rec;

        while ((rec = tapi_opcua_report_next(res.report.ptr, &off)) != NULL)
        {
            tapi_opcua_kv kv = TAPI_OPCUA_KV_INIT;
            const char *nid;
            const char *st;

            tapi_opcua_kv_parse_record(rec, &kv);
            nid = tapi_opcua_kv_get(&kv, "node");
            st = tapi_opcua_kv_get(&kv, "status");
            if (nid != NULL && st != NULL)
                kv_add(statuses, nid, strlen(nid), st, strlen(st));
            tapi_opcua_kv_free(&kv);
            free(rec);
        }
    }
    tapi_opcua_rpc_res_free(&res);
    return rc;
}

/* ---- method calls ------------------------------------------------- */

te_errno
tapi_opcua_call(tapi_opcua_conn *conn, const char *object, const char *method,
                const char *inputs, te_string *outputs, uint32_t *status)
{
    te_string params = TE_STRING_INIT;
    tapi_opcua_rpc_args a = { 0 };
    tapi_opcua_rpc_res res = TAPI_OPCUA_RPC_RES_INIT;
    te_errno rc;

    te_string_append(&params, "object=%s\n", object);
    a.h1 = conn->id;
    a.arg = method;
    a.params = params.ptr;
    a.data = inputs;
    rc = rpc_opcua_call(conn->rpcs, TAPI_OPCUA_OP_CALL, &a, 0, &res);
    remember_fail(conn, &res);
    if (status != NULL)
        *status = res.status;
    if (outputs != NULL && res.report.ptr != NULL)
        te_string_append(outputs, "%s", res.report.ptr);
    te_string_free(&params);
    tapi_opcua_rpc_res_free(&res);
    return rc;
}

/* ---- performance -------------------------------------------------- */

te_errno
tapi_opcua_perf(tapi_opcua_conn *conn, const char *op, const char *node,
                int count, te_string *samples, tapi_opcua_kv *summary)
{
    te_string params = TE_STRING_INIT;
    tapi_opcua_rpc_res res = TAPI_OPCUA_RPC_RES_INIT;
    te_errno rc;

    te_string_append(&params, "op=%s\ncount=%d\n", op, count);
    if (node != NULL)
        te_string_append(&params, "node=%s\n", node);
    rc = simple_op(conn, TAPI_OPCUA_OP_PERF, NULL, params.ptr, NULL, &res);
    if (samples != NULL && res.report.ptr != NULL)
        te_string_append(samples, "%s", res.report.ptr);
    if (summary != NULL)
        tapi_opcua_kv_parse(res.result.ptr, summary);
    te_string_free(&params);
    tapi_opcua_rpc_res_free(&res);
    return rc;
}

te_errno
tapi_opcua_stats(rcf_rpc_server *rpcs, tapi_opcua_kv *stats)
{
    tapi_opcua_rpc_args a = { 0 };
    tapi_opcua_rpc_res res = TAPI_OPCUA_RPC_RES_INIT;
    te_errno rc;

    rc = rpc_opcua_call(rpcs, TAPI_OPCUA_OP_STATS, &a, 0, &res);
    if (stats != NULL)
        tapi_opcua_kv_parse(res.result.ptr, stats);
    tapi_opcua_rpc_res_free(&res);
    return rc;
}
