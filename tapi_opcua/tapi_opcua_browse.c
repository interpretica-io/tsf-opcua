/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Interpretica, Unipessoal Lda. All rights reserved. */
/** @file
 * @brief OPC UA TAPI: address-space browsing
 */

#define TE_LGR_USER     "TAPI OPCUA"

#include "te_config.h"

#include <string.h>

#include "te_defs.h"
#include "te_errno.h"
#include "te_string.h"

#include "tapi_opcua.h"

static te_errno
browse_op(tapi_opcua_conn *conn, tapi_opcua_op op, const char *arg,
          const char *params, const char *data, te_string *report,
          te_string *result)
{
    tapi_opcua_rpc_args a = { 0 };
    tapi_opcua_rpc_res res = TAPI_OPCUA_RPC_RES_INIT;
    te_errno rc;

    a.h1 = conn->id;
    a.arg = arg;
    a.params = params;
    a.data = data;
    rc = rpc_opcua_call(conn->rpcs, op, &a, 0, &res);
    if (report != NULL && res.report.ptr != NULL)
        te_string_append(report, "%s", res.report.ptr);
    if (result != NULL && res.result.ptr != NULL)
        te_string_append(result, "%s", res.result.ptr);
    tapi_opcua_rpc_res_free(&res);
    return rc;
}

te_errno
tapi_opcua_browse(tapi_opcua_conn *conn, const char *node, int max_refs,
                  te_string *refs, te_string *cont)
{
    te_string params = TE_STRING_INIT;
    te_string result = TE_STRING_INIT;
    te_errno rc;

    if (max_refs > 0)
        te_string_append(&params, "max_refs=%d\n", max_refs);
    rc = browse_op(conn, TAPI_OPCUA_OP_BROWSE, node, params.ptr, NULL, refs,
                   &result);
    if (cont != NULL)
    {
        tapi_opcua_kv kv = TAPI_OPCUA_KV_INIT;
        const char *cp;

        tapi_opcua_kv_parse(result.ptr, &kv);
        cp = tapi_opcua_kv_get(&kv, "continuation_point");
        if (cp != NULL)
            te_string_append(cont, "%s", cp);
        tapi_opcua_kv_free(&kv);
    }
    te_string_free(&params);
    te_string_free(&result);
    return rc;
}

te_errno
tapi_opcua_browse_next(tapi_opcua_conn *conn, const char *cont,
                       te_string *refs)
{
    return browse_op(conn, TAPI_OPCUA_OP_BROWSE_NEXT, cont, NULL, NULL, refs,
                     NULL);
}

te_errno
tapi_opcua_translate_browse_path(tapi_opcua_conn *conn, const char *start,
                                 const char *path, te_string *targets)
{
    return browse_op(conn, TAPI_OPCUA_OP_TRANSLATE, start, NULL, path, targets,
                     NULL);
}

te_errno
tapi_opcua_read_node_info(tapi_opcua_conn *conn, const char *node,
                          tapi_opcua_kv *info)
{
    te_string result = TE_STRING_INIT;
    te_errno rc;

    rc = browse_op(conn, TAPI_OPCUA_OP_NODE_INFO, node, NULL, NULL, NULL,
                   &result);
    if (info != NULL)
        tapi_opcua_kv_parse(result.ptr, info);
    te_string_free(&result);
    return rc;
}

te_errno
tapi_opcua_namespaces(tapi_opcua_conn *conn, te_string *namespaces)
{
    return browse_op(conn, TAPI_OPCUA_OP_NAMESPACES, NULL, NULL, NULL,
                     namespaces, NULL);
}

bool
tapi_opcua_refs_have(const char *refs, const char *browse_name)
{
    size_t off = 0;
    char *rec;
    bool found = false;

    while (!found && (rec = tapi_opcua_report_next(refs, &off)) != NULL)
    {
        tapi_opcua_kv kv = TAPI_OPCUA_KV_INIT;
        const char *bn;

        tapi_opcua_kv_parse_record(rec, &kv);
        bn = tapi_opcua_kv_get(&kv, "browse_name");
        if (bn != NULL && strcmp(bn, browse_name) == 0)
            found = true;
        tapi_opcua_kv_free(&kv);
        free(rec);
    }
    return found;
}
