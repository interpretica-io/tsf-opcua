/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Interpretica, Unipessoal Lda. All rights reserved. */
/** @file
 * @brief OPC UA TAPI: subscriptions, monitored items, events
 */

#define TE_LGR_USER     "TAPI OPCUA"

#include "te_config.h"

#include <string.h>

#include "te_defs.h"
#include "te_errno.h"
#include "te_string.h"

#include "tapi_opcua.h"

te_errno
tapi_opcua_subscribe(tapi_opcua_conn *conn, const tapi_opcua_sub_opt *opt,
                     tapi_opcua_sub *sub, tapi_opcua_kv *revised)
{
    te_string params = TE_STRING_INIT;
    tapi_opcua_rpc_args a = { 0 };
    tapi_opcua_rpc_res res = TAPI_OPCUA_RPC_RES_INIT;
    te_errno rc;

    sub->rpcs = conn->rpcs;
    sub->id = 0;
    if (opt != NULL)
    {
        if (opt->publishing_interval_ms > 0)
            te_string_append(&params, "publishing_interval_ms=%.3f\n",
                             opt->publishing_interval_ms);
        if (opt->lifetime_count > 0)
            te_string_append(&params, "lifetime_count=%u\n",
                             opt->lifetime_count);
        if (opt->max_keepalive_count > 0)
            te_string_append(&params, "max_keepalive_count=%u\n",
                             opt->max_keepalive_count);
        if (opt->max_notifications > 0)
            te_string_append(&params, "max_notifications=%u\n",
                             opt->max_notifications);
        if (opt->priority > 0)
            te_string_append(&params, "priority=%u\n", opt->priority);
        if (opt->publishing_disabled)
            te_string_append(&params, "publishing_enabled=0\n");
    }
    a.h1 = conn->id;
    a.params = params.ptr;
    rc = rpc_opcua_call(conn->rpcs, TAPI_OPCUA_OP_SUB_CREATE, &a, 0, &res);
    sub->id = res.handle;
    if (revised != NULL)
        tapi_opcua_kv_parse(res.result.ptr, revised);
    te_string_free(&params);
    tapi_opcua_rpc_res_free(&res);
    return rc;
}

te_errno
tapi_opcua_unsubscribe(tapi_opcua_sub *sub)
{
    tapi_opcua_rpc_args a = { 0 };
    tapi_opcua_rpc_res res = TAPI_OPCUA_RPC_RES_INIT;
    te_errno rc;

    if (sub->id == 0)
        return 0;
    a.h2 = sub->id;
    rc = rpc_opcua_call(sub->rpcs, TAPI_OPCUA_OP_SUB_DELETE, &a, 0, &res);
    sub->id = 0;
    tapi_opcua_rpc_res_free(&res);
    return rc;
}

te_errno
tapi_opcua_monitor(tapi_opcua_sub *sub, const char *node,
                   const tapi_opcua_monitor_opt *opt, uint32_t *item_id,
                   tapi_opcua_kv *revised)
{
    te_string params = TE_STRING_INIT;
    tapi_opcua_rpc_args a = { 0 };
    tapi_opcua_rpc_res res = TAPI_OPCUA_RPC_RES_INIT;
    te_errno rc;

    if (opt != NULL)
    {
        if (opt->attribute != NULL)
            te_string_append(&params, "attribute=%s\n", opt->attribute);
        if (opt->sampling_interval_ms > 0)
            te_string_append(&params, "sampling_interval_ms=%.3f\n",
                             opt->sampling_interval_ms);
        if (opt->queue_size > 0)
            te_string_append(&params, "queue_size=%u\n", opt->queue_size);
        if (opt->discard_newest)
            te_string_append(&params, "discard_oldest=0\n");
        if (opt->mode != NULL)
            te_string_append(&params, "mode=%s\n", opt->mode);
        if (opt->deadband != NULL)
        {
            te_string_append(&params, "deadband=%s\n", opt->deadband);
            te_string_append(&params, "deadband_value=%.6f\n",
                             opt->deadband_value);
        }
    }
    /* The client is resolved from the subscription handle on the agent. */
    a.h2 = sub->id;
    a.arg = node;
    a.params = params.ptr;
    rc = rpc_opcua_call(sub->rpcs, TAPI_OPCUA_OP_MONITOR, &a, 0, &res);
    if (item_id != NULL)
        *item_id = (uint32_t)res.handle;
    if (revised != NULL)
        tapi_opcua_kv_parse(res.result.ptr, revised);
    te_string_free(&params);
    tapi_opcua_rpc_res_free(&res);
    return rc;
}

te_errno
tapi_opcua_event_subscribe(tapi_opcua_sub *sub, const char *node,
                           const tapi_opcua_event_opt *opt, uint32_t *item_id)
{
    te_string params = TE_STRING_INIT;
    tapi_opcua_rpc_args a = { 0 };
    tapi_opcua_rpc_res res = TAPI_OPCUA_RPC_RES_INIT;
    te_errno rc;

    te_string_append(&params, "kind=event\n");
    if (opt != NULL)
    {
        if (opt->fields != NULL)
            te_string_append(&params, "fields=%s\n", opt->fields);
        if (opt->min_severity > 0)
            te_string_append(&params, "min_severity=%u\n", opt->min_severity);
    }
    a.h2 = sub->id;
    a.arg = node;
    a.params = params.ptr;
    rc = rpc_opcua_call(sub->rpcs, TAPI_OPCUA_OP_MONITOR, &a, 0, &res);
    if (item_id != NULL)
        *item_id = (uint32_t)res.handle;
    te_string_free(&params);
    tapi_opcua_rpc_res_free(&res);
    return rc;
}

te_errno
tapi_opcua_unmonitor(tapi_opcua_sub *sub, uint32_t item_id)
{
    te_string params = TE_STRING_INIT;
    tapi_opcua_rpc_args a = { 0 };
    tapi_opcua_rpc_res res = TAPI_OPCUA_RPC_RES_INIT;
    te_errno rc;

    te_string_append(&params, "item=%u\n", item_id);
    a.h2 = sub->id;
    a.params = params.ptr;
    rc = rpc_opcua_call(sub->rpcs, TAPI_OPCUA_OP_UNMONITOR, &a, 0, &res);
    te_string_free(&params);
    tapi_opcua_rpc_res_free(&res);
    return rc;
}

te_errno
tapi_opcua_collect(tapi_opcua_sub *sub, unsigned int min, unsigned int max,
                   int timeout_ms, te_string *notes, tapi_opcua_kv *state)
{
    te_string params = TE_STRING_INIT;
    tapi_opcua_rpc_args a = { 0 };
    tapi_opcua_rpc_res res = TAPI_OPCUA_RPC_RES_INIT;
    te_errno rc;

    te_string_append(&params, "min=%u\nmax=%u\ntimeout_ms=%d\n", min, max,
                     timeout_ms);
    a.h2 = sub->id;
    a.params = params.ptr;
    rc = rpc_opcua_call(sub->rpcs, TAPI_OPCUA_OP_COLLECT, &a, 0, &res);
    if (notes != NULL && res.report.ptr != NULL)
        te_string_append(notes, "%s", res.report.ptr);
    if (state != NULL)
        tapi_opcua_kv_parse(res.result.ptr, state);
    te_string_free(&params);
    tapi_opcua_rpc_res_free(&res);
    return rc;
}

te_errno
tapi_opcua_event_collect(tapi_opcua_sub *sub, unsigned int min,
                         int timeout_ms, te_string *events,
                         tapi_opcua_kv *state)
{
    return tapi_opcua_collect(sub, min, 0, timeout_ms, events, state);
}

te_errno
tapi_opcua_event_unsubscribe(tapi_opcua_sub *sub, uint32_t item_id)
{
    return tapi_opcua_unmonitor(sub, item_id);
}

unsigned int
tapi_opcua_notes_count(const char *notes)
{
    unsigned int n = 0;
    size_t off = 0;
    char *rec;

    while ((rec = tapi_opcua_report_next(notes, &off)) != NULL)
    {
        n++;
        free(rec);
    }
    return n;
}
