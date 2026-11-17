/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Interpretica, Unipessoal Lda. All rights reserved. */
/** @file
 * @brief OPC UA TAPI: the simulated server
 */

#define TE_LGR_USER     "TAPI OPCUA"

#include "te_config.h"

#include <string.h>

#include "te_defs.h"
#include "te_errno.h"
#include "te_string.h"

#include "tapi_opcua.h"

te_errno
tapi_opcua_server_start(rcf_rpc_server *rpcs,
                        const tapi_opcua_server_opt *opt,
                        tapi_opcua_server *srv, tapi_opcua_kv *info)
{
    te_string params = TE_STRING_INIT;
    tapi_opcua_rpc_args a = { 0 };
    tapi_opcua_rpc_res res = TAPI_OPCUA_RPC_RES_INIT;
    te_errno rc;

    srv->rpcs = rpcs;
    srv->id = 0;
    if (opt != NULL)
    {
        if (opt->port > 0)
            te_string_append(&params, "port=%d\n", opt->port);
        if (opt->app_uri != NULL)
            te_string_append(&params, "app_uri=%s\n", opt->app_uri);
        if (opt->app_name != NULL)
            te_string_append(&params, "app_name=%s\n", opt->app_name);
        if (opt->namespace_uri != NULL)
            te_string_append(&params, "namespace=%s\n", opt->namespace_uri);
        te_string_append(&params, "anonymous=%d\n", opt->no_anonymous ? 0 : 1);
        if (opt->users != NULL)
            te_string_append(&params, "users=%s\n", opt->users);
        if (opt->cert != NULL)
            te_string_append(&params, "cert=%s\n", opt->cert);
        if (opt->key != NULL)
            te_string_append(&params, "key=%s\n", opt->key);
    }
    a.params = params.ptr;
    rc = rpc_opcua_call(rpcs, TAPI_OPCUA_OP_SERVER_START, &a, 0, &res);
    srv->id = res.handle;
    if (info != NULL)
        tapi_opcua_kv_parse(res.result.ptr, info);
    te_string_free(&params);
    tapi_opcua_rpc_res_free(&res);
    return rc;
}

static te_errno
server_op(tapi_opcua_server *srv, tapi_opcua_op op, const char *arg,
          const char *params, const char *data, te_string *result)
{
    tapi_opcua_rpc_args a = { 0 };
    tapi_opcua_rpc_res res = TAPI_OPCUA_RPC_RES_INIT;
    te_errno rc;

    a.h1 = srv->id;
    a.arg = arg;
    a.params = params;
    a.data = data;
    rc = rpc_opcua_call(srv->rpcs, op, &a, 0, &res);
    if (result != NULL && res.result.ptr != NULL)
        te_string_append(result, "%s", res.result.ptr);
    tapi_opcua_rpc_res_free(&res);
    return rc;
}

te_errno
tapi_opcua_server_stop(tapi_opcua_server *srv)
{
    te_errno rc;

    if (srv->id == 0)
        return 0;
    rc = server_op(srv, TAPI_OPCUA_OP_SERVER_STOP, NULL, NULL, NULL, NULL);
    srv->id = 0;
    return rc;
}

te_errno
tapi_opcua_server_add_variable(tapi_opcua_server *srv, const char *name,
                               const char *value, bool writable,
                               te_string *node_id)
{
    te_string params = TE_STRING_INIT;
    te_errno rc;

    te_string_append(&params, "kind=variable\nname=%s\naccess=%s\n", name,
                     writable ? "rw" : "r");
    if (value != NULL)
        te_string_append(&params, "value=%s\n", value);
    rc = server_op(srv, TAPI_OPCUA_OP_SERVER_ADD, NULL, params.ptr, NULL,
                   node_id);
    te_string_free(&params);
    return rc;
}

te_errno
tapi_opcua_server_add_method(tapi_opcua_server *srv, const char *name,
                             const char *behaviour, te_string *node_id)
{
    te_string params = TE_STRING_INIT;
    te_errno rc;

    te_string_append(&params, "kind=method\nname=%s\n", name);
    if (behaviour != NULL)
        te_string_append(&params, "behaviour=%s\n", behaviour);
    rc = server_op(srv, TAPI_OPCUA_OP_SERVER_ADD, NULL, params.ptr, NULL,
                   node_id);
    te_string_free(&params);
    return rc;
}

te_errno
tapi_opcua_server_set_value(tapi_opcua_server *srv, const char *node,
                            const char *value)
{
    return server_op(srv, TAPI_OPCUA_OP_SERVER_SET, node, NULL, value, NULL);
}

te_errno
tapi_opcua_server_event(tapi_opcua_server *srv, const char *source,
                        unsigned int severity, const char *msg)
{
    te_string params = TE_STRING_INIT;
    te_errno rc;

    te_string_append(&params, "severity=%u\n", severity);
    if (source != NULL)
        te_string_append(&params, "source=%s\n", source);
    if (msg != NULL)
        te_string_append(&params, "message=%s\n", msg);
    rc = server_op(srv, TAPI_OPCUA_OP_SERVER_EVENT, NULL, params.ptr, NULL,
                   NULL);
    te_string_free(&params);
    return rc;
}

te_errno
tapi_opcua_server_info(tapi_opcua_server *srv, tapi_opcua_kv *info)
{
    te_string result = TE_STRING_INIT;
    te_errno rc;

    rc = server_op(srv, TAPI_OPCUA_OP_SERVER_INFO, NULL, NULL, NULL, &result);
    if (info != NULL)
        tapi_opcua_kv_parse(result.ptr, info);
    te_string_free(&result);
    return rc;
}
