/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Interpretica, Unipessoal Lda. All rights reserved. */
/** @file
 * @brief OPC UA core: the simulated server (test equipment)
 *
 * An optional controllable OPC UA server running in its own thread, for
 * deterministic integration and fault-injection tests. It is test
 * equipment, never part of a deployment: it hides nothing and lives
 * only as long as the test keeps it.
 *
 * Nodes are addressed by browse name in namespace 1. A method's
 * behaviour is one of a small fixed set (echo, sum, delay, fail,
 * counter) so a test can exercise the call path without compiling
 * anything on the agent. User accounts are configured as
 * "name:password:role"; the password is used to build the login table
 * and then wiped, and never logged.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <open62541/server_config_default.h>
#include <open62541/plugin/accesscontrol_default.h>
#include <open62541/plugin/log_stdout.h>

#include "ta_opcua_int.h"

struct ta_opcua_server {
    UA_Server      *ua;
    pthread_t       thread;
    pthread_mutex_t lock;
    volatile UA_Boolean running;
    UA_UInt16       ns;
    char           *endpoint;
    uint64_t        calls;
    uint64_t        writes;
};

static void
quiet_log(void *ctx, UA_LogLevel level, UA_LogCategory cat,
          const char *msg, va_list args)
{
    (void)ctx; (void)level; (void)cat; (void)msg; (void)args;
}

static void
quiet_clear(UA_Logger *logger)
{
    (void)logger;
}

static UA_Logger quiet_logger = { quiet_log, NULL, quiet_clear };

/* ---- method behaviours -------------------------------------------- */

static UA_StatusCode
method_echo(UA_Server *s, const UA_NodeId *sid, void *sctx,
            const UA_NodeId *mid, void *mctx, const UA_NodeId *oid,
            void *octx, size_t inSize, const UA_Variant *in,
            size_t outSize, UA_Variant *out)
{
    (void)s; (void)sid; (void)sctx; (void)mid; (void)mctx; (void)oid;
    (void)octx;
    if (inSize >= 1 && outSize >= 1)
        UA_Variant_copy(&in[0], &out[0]);
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
method_sum(UA_Server *s, const UA_NodeId *sid, void *sctx,
           const UA_NodeId *mid, void *mctx, const UA_NodeId *oid,
           void *octx, size_t inSize, const UA_Variant *in,
           size_t outSize, UA_Variant *out)
{
    double acc = 0;
    size_t i;

    (void)s; (void)sid; (void)sctx; (void)mid; (void)mctx; (void)oid;
    (void)octx;
    for (i = 0; i < inSize; i++)
    {
        if (UA_Variant_hasScalarType(&in[i], &UA_TYPES[UA_TYPES_DOUBLE]))
            acc += *(UA_Double *)in[i].data;
        else if (UA_Variant_hasScalarType(&in[i], &UA_TYPES[UA_TYPES_INT32]))
            acc += *(UA_Int32 *)in[i].data;
    }
    if (outSize >= 1)
        UA_Variant_setScalarCopy(&out[0], &acc, &UA_TYPES[UA_TYPES_DOUBLE]);
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
method_delay(UA_Server *s, const UA_NodeId *sid, void *sctx,
             const UA_NodeId *mid, void *mctx, const UA_NodeId *oid,
             void *octx, size_t inSize, const UA_Variant *in,
             size_t outSize, UA_Variant *out)
{
    long ms = 500;

    (void)s; (void)sid; (void)sctx; (void)mid; (void)mctx; (void)oid;
    (void)octx; (void)outSize; (void)out;
    if (inSize >= 1 && UA_Variant_hasScalarType(&in[0],
            &UA_TYPES[UA_TYPES_INT32]))
        ms = *(UA_Int32 *)in[0].data;
    {
        struct timespec ts = { ms / 1000, (ms % 1000) * 1000000L };

        nanosleep(&ts, NULL);
    }
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
method_fail(UA_Server *s, const UA_NodeId *sid, void *sctx,
            const UA_NodeId *mid, void *mctx, const UA_NodeId *oid,
            void *octx, size_t inSize, const UA_Variant *in,
            size_t outSize, UA_Variant *out)
{
    (void)s; (void)sid; (void)sctx; (void)mid; (void)mctx; (void)oid;
    (void)octx; (void)inSize; (void)in; (void)outSize; (void)out;
    return UA_STATUSCODE_BADUSERACCESSDENIED;
}

/* ---- server thread ------------------------------------------------ */

static void *
server_thread(void *arg)
{
    ta_opcua_server *s = arg;

    UA_Server_run_startup(s->ua);
    while (s->running)
    {
        pthread_mutex_lock(&s->lock);
        UA_Server_run_iterate(s->ua, false);
        pthread_mutex_unlock(&s->lock);
        {
            struct timespec ts = { 0, 5 * 1000000L };

            nanosleep(&ts, NULL);
        }
    }
    UA_Server_run_shutdown(s->ua);
    return NULL;
}

/* ---- start / stop ------------------------------------------------- */

int
ta_opcua_server_start(const char *params, ta_opcua_server **srv,
                      ta_opcua_out *out)
{
    ta_opcua_server *s;
    UA_ServerConfig *cfg;
    UA_UInt16 port = (UA_UInt16)ta_opcua_opt_int(params, "port", 4840);
    char *app_uri = ta_opcua_opt(params, "app_uri");
    char *app_name = ta_opcua_opt(params, "app_name");
    char *ns = ta_opcua_opt(params, "namespace");
    char *users = ta_opcua_opt(params, "users");
    bool anon = ta_opcua_opt_bool(params, "anonymous", true);
    UA_StatusCode st;
    UA_UsernamePasswordLogin *logins = NULL;
    size_t nlogins = 0;

    s = calloc(1, sizeof(*s));
    if (s == NULL)
        return out_err(out, TA_OPCUA_ENOMEM, "oom");
    pthread_mutex_init(&s->lock, NULL);
    s->ua = UA_Server_new();
    if (s->ua == NULL)
    {
        free(s);
        return out_err(out, TA_OPCUA_ENOMEM, "UA_Server_new");
    }
    cfg = UA_Server_getConfig(s->ua);
    cfg->logging = &quiet_logger;
    st = UA_ServerConfig_setMinimal(cfg, port, NULL);
    if (st != UA_STATUSCODE_GOOD)
    {
        UA_Server_delete(s->ua);
        free(s);
        return out_err(out, TA_OPCUA_EFAIL, "server config: %s",
                       UA_StatusCode_name(st));
    }
    if (app_uri != NULL && *app_uri != '\0')
    {
        UA_String_clear(&cfg->applicationDescription.applicationUri);
        cfg->applicationDescription.applicationUri = UA_STRING_ALLOC(app_uri);
    }

    /* User accounts: "name:password:role" entries. */
    if (users != NULL && *users != '\0')
    {
        char *copy = strdup(users);
        char *tok;
        char *save = NULL;

        for (tok = strtok_r(copy, ",", &save); tok != NULL;
             tok = strtok_r(NULL, ",", &save))
        {
            char *colon = strchr(tok, ':');
            char *colon2;
            UA_UsernamePasswordLogin *nl;

            if (colon == NULL)
                continue;
            *colon = '\0';
            colon2 = strchr(colon + 1, ':');
            if (colon2 != NULL)
                *colon2 = '\0';
            nl = realloc(logins, (nlogins + 1) * sizeof(*logins));
            if (nl == NULL)
                break;
            logins = nl;
            logins[nlogins].username = UA_STRING_ALLOC(tok);
            logins[nlogins].password = UA_STRING_ALLOC(colon + 1);
            nlogins++;
        }
        /* Wipe the plaintext before freeing. */
        memset(copy, 0, strlen(copy));
        free(copy);
    }

    UA_AccessControl_default(cfg, anon, NULL,
                             nlogins, logins);
    {
        size_t i;

        for (i = 0; i < nlogins; i++)
        {
            UA_String_clear(&logins[i].username);
            /* Scrub the password copy. */
            if (logins[i].password.data != NULL)
                memset(logins[i].password.data, 0, logins[i].password.length);
            UA_String_clear(&logins[i].password);
        }
        free(logins);
    }

    s->ns = UA_Server_addNamespace(s->ua,
            ns != NULL && *ns != '\0' ? ns : "urn:tsf-opcua:sim");

    s->running = true;
    if (pthread_create(&s->thread, NULL, server_thread, s) != 0)
    {
        s->running = false;
        UA_Server_delete(s->ua);
        pthread_mutex_destroy(&s->lock);
        free(s);
        return out_err(out, TA_OPCUA_EFAIL, "server thread");
    }

    {
        ta_opcua_buf b = TA_OPCUA_BUF_INIT;
        char url[128];

        snprintf(url, sizeof(url), "opc.tcp://localhost:%u", port);
        s->endpoint = strdup(url);
        buf_kv(&b, "endpoint_url", url);
        buf_kvf(&b, "namespace_index", "%u", s->ns);
        out->result = buf_take(&b);
    }
    (void)app_name;
    free(app_uri);
    free(app_name);
    free(ns);
    free(users);
    *srv = s;
    return TA_OPCUA_OK;
}

void
ta_opcua_server_stop(ta_opcua_server *s)
{
    if (s == NULL)
        return;
    if (s->running)
    {
        s->running = false;
        pthread_join(s->thread, NULL);
    }
    if (s->ua != NULL)
        UA_Server_delete(s->ua);
    pthread_mutex_destroy(&s->lock);
    free(s->endpoint);
    free(s);
}

/* ---- add nodes ---------------------------------------------------- */

int
ta_opcua_server_add(ta_opcua_server *s, const char *params, ta_opcua_out *out)
{
    char *kind = ta_opcua_opt(params, "kind");
    char *name = ta_opcua_opt(params, "name");
    char *value = ta_opcua_opt(params, "value");
    char *access = ta_opcua_opt(params, "access");
    char *behaviour = ta_opcua_opt(params, "behaviour");
    UA_StatusCode st = UA_STATUSCODE_GOOD;
    UA_NodeId parent = UA_NODEID_NUMERIC(0, UA_NS0ID_OBJECTSFOLDER);
    UA_NodeId outId;
    ta_opcua_buf b = TA_OPCUA_BUF_INIT;
    int rc = TA_OPCUA_OK;

    if (name == NULL)
    {
        rc = out_err(out, TA_OPCUA_EINVAL, "add needs a name");
        goto out;
    }
    UA_NodeId_init(&outId);

    pthread_mutex_lock(&s->lock);
    if (kind == NULL || strcmp(kind, "variable") == 0)
    {
        UA_VariableAttributes attr = UA_VariableAttributes_default;
        UA_Variant v;

        UA_Variant_init(&v);
        if (value != NULL && *value != '\0')
            val_parse(value, &v);
        else
        {
            UA_Int32 zero = 0;

            UA_Variant_setScalarCopy(&v, &zero, &UA_TYPES[UA_TYPES_INT32]);
        }
        attr.value = v;
        attr.dataType = v.type != NULL ? v.type->typeId :
            UA_TYPES[UA_TYPES_INT32].typeId;
        attr.accessLevel = UA_ACCESSLEVELMASK_READ;
        if (access != NULL && strcmp(access, "rw") == 0)
            attr.accessLevel |= UA_ACCESSLEVELMASK_WRITE;
        attr.displayName = UA_LOCALIZEDTEXT("en-US", name);
        st = UA_Server_addVariableNode(s->ua,
                UA_NODEID_STRING(s->ns, name), parent,
                UA_NODEID_NUMERIC(0, UA_NS0ID_ORGANIZES),
                UA_QUALIFIEDNAME(s->ns, name),
                UA_NODEID_NUMERIC(0, UA_NS0ID_BASEDATAVARIABLETYPE),
                attr, NULL, &outId);
        UA_Variant_clear(&v);
    }
    else if (strcmp(kind, "object") == 0)
    {
        UA_ObjectAttributes attr = UA_ObjectAttributes_default;

        attr.displayName = UA_LOCALIZEDTEXT("en-US", name);
        st = UA_Server_addObjectNode(s->ua,
                UA_NODEID_STRING(s->ns, name), parent,
                UA_NODEID_NUMERIC(0, UA_NS0ID_ORGANIZES),
                UA_QUALIFIEDNAME(s->ns, name),
                UA_NODEID_NUMERIC(0, UA_NS0ID_BASEOBJECTTYPE),
                attr, NULL, &outId);
    }
    else if (strcmp(kind, "method") == 0)
    {
        UA_MethodAttributes attr = UA_MethodAttributes_default;
        UA_MethodCallback cb = method_echo;
        UA_Argument inargs[2];
        UA_Argument outarg;
        long long nin = ta_opcua_opt_int(params, "inputs", 2);
        size_t i;

        attr.displayName = UA_LOCALIZEDTEXT("en-US", name);
        attr.executable = true;
        attr.userExecutable = true;
        if (behaviour != NULL)
        {
            if (strcmp(behaviour, "sum") == 0) cb = method_sum;
            else if (strcmp(behaviour, "delay") == 0) cb = method_delay;
            else if (strcmp(behaviour, "fail") == 0) cb = method_fail;
        }
        if (nin < 0) nin = 0;
        if (nin > 2) nin = 2;
        for (i = 0; i < 2; i++)
        {
            UA_Argument_init(&inargs[i]);
            inargs[i].dataType = UA_TYPES[UA_TYPES_DOUBLE].typeId;
            inargs[i].valueRank = UA_VALUERANK_SCALAR;
            inargs[i].name = UA_STRING(i == 0 ? "a" : "b");
        }
        UA_Argument_init(&outarg);
        outarg.dataType = UA_TYPES[UA_TYPES_DOUBLE].typeId;
        outarg.valueRank = UA_VALUERANK_SCALAR;
        outarg.name = UA_STRING("out");
        st = UA_Server_addMethodNode(s->ua, UA_NODEID_STRING(s->ns, name),
                parent, UA_NODEID_NUMERIC(0, UA_NS0ID_HASCOMPONENT),
                UA_QUALIFIEDNAME(s->ns, name), attr, cb,
                (size_t)nin, inargs, 1, &outarg, NULL, &outId);
    }
    else
    {
        pthread_mutex_unlock(&s->lock);
        rc = out_err(out, TA_OPCUA_EINVAL, "unknown kind");
        goto out;
    }
    pthread_mutex_unlock(&s->lock);

    out->status = st;
    if (st != UA_STATUSCODE_GOOD)
    {
        rc = out_err(out, TA_OPCUA_ESTATUS, "add node: %s",
                     UA_StatusCode_name(st));
    }
    else
    {
        char *nid = nodeid_print(&outId);

        buf_kv(&b, "node", nid);
        out->result = buf_take(&b);
        free(nid);
    }
    UA_NodeId_clear(&outId);
out:
    free(kind);
    free(name);
    free(value);
    free(access);
    free(behaviour);
    return rc;
}

int
ta_opcua_server_set(ta_opcua_server *s, const char *node, const char *value,
                    ta_opcua_out *out)
{
    UA_Variant v;
    UA_StatusCode st;
    UA_NodeId id;

    if (node == NULL)
        return out_err(out, TA_OPCUA_EINVAL, "no node");
    /* A bare name is a string NodeId in namespace 1. */
    if (strchr(node, '=') != NULL)
    {
        if (nodeid_parse(node, &id) != TA_OPCUA_OK)
            return out_err(out, TA_OPCUA_EINVAL, "bad node id");
    }
    else
    {
        id = UA_NODEID_STRING_ALLOC(s->ns, node);
    }
    UA_Variant_init(&v);
    if (val_parse(value, &v) != TA_OPCUA_OK)
    {
        UA_NodeId_clear(&id);
        return out_err(out, TA_OPCUA_EINVAL, "bad value");
    }
    pthread_mutex_lock(&s->lock);
    st = UA_Server_writeValue(s->ua, id, v);
    s->writes++;
    pthread_mutex_unlock(&s->lock);
    out->status = st;
    UA_Variant_clear(&v);
    UA_NodeId_clear(&id);
    return st == UA_STATUSCODE_GOOD ? TA_OPCUA_OK :
           out_err(out, TA_OPCUA_ESTATUS, "write: %s",
                   UA_StatusCode_name(st));
}

int
ta_opcua_server_event(ta_opcua_server *s, const char *params,
                      ta_opcua_out *out)
{
#ifdef UA_ENABLE_SUBSCRIPTIONS_EVENTS
    UA_StatusCode st;
    char *msg = ta_opcua_opt(params, "message");
    char *source = ta_opcua_opt(params, "source");
    UA_UInt16 sev = (UA_UInt16)ta_opcua_opt_int(params, "severity", 100);
    UA_LocalizedText m = UA_LOCALIZEDTEXT("en-US",
            msg != NULL ? msg : "event");
    UA_NodeId src = UA_NODEID_NUMERIC(0, UA_NS0ID_SERVER);
    bool src_alloc = false;

    if (source != NULL && *source != '\0')
    {
        if (strchr(source, '=') != NULL)
            nodeid_parse(source, &src);
        else
            src = UA_NODEID_STRING_ALLOC(s->ns, source);
        src_alloc = true;
    }

    pthread_mutex_lock(&s->lock);
    /* open62541 1.5 one-shot event: fields given inline, emitted at the
     * source node, bubbling up to the Server object. */
    st = UA_Server_createEvent(s->ua, src,
            UA_NODEID_NUMERIC(0, UA_NS0ID_BASEEVENTTYPE), sev, m,
            NULL, NULL, NULL);
    pthread_mutex_unlock(&s->lock);
    if (src_alloc)
        UA_NodeId_clear(&src);
    free(msg);
    free(source);
    out->status = st;
    return st == UA_STATUSCODE_GOOD ? TA_OPCUA_OK :
           out_err(out, TA_OPCUA_ESTATUS, "event: %s",
                   UA_StatusCode_name(st));
#else
    (void)s; (void)params;
    return out_err(out, TA_OPCUA_ENOTSUP, "events not compiled in");
#endif
}

int
ta_opcua_server_info(ta_opcua_server *s, ta_opcua_out *out)
{
    ta_opcua_buf b = TA_OPCUA_BUF_INIT;

    pthread_mutex_lock(&s->lock);
    buf_kv(&b, "endpoint_url", s->endpoint);
    buf_kvf(&b, "namespace_index", "%u", s->ns);
    buf_kvf(&b, "writes", "%" PRIu64, s->writes);
    buf_kvf(&b, "calls", "%" PRIu64, s->calls);
    buf_kv(&b, "running", s->running ? "1" : "0");
    pthread_mutex_unlock(&s->lock);
    out->result = buf_take(&b);
    return TA_OPCUA_OK;
}
