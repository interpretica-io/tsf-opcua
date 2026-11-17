/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Interpretica, Unipessoal Lda. All rights reserved. */
/** @file
 * @brief OPC UA RPC server library
 *
 * The opcua_* RPCs (see opcua_rpc.x.m4) on top of ta_opcua. Both RPCs
 * have the same shape, so each is one plain C function that forwards to
 * ta_opcua_rpc() and the TARPC_FUNC_STATIC() wrapper after it, which
 * moves the strings ta_opcua_rpc() returns straight into the out struct
 * (XDR frees them after sending). The OPC UA work happens on the agent,
 * in the RPC server process.
 *
 * Nothing here logs an argument: a connection secret passes through the
 * params field and must not reach a log.
 */

#define TE_LGR_USER     "RPC OPCUA"

#include "te_config.h"

#include <string.h>

#include "te_defs.h"
#include "te_errno.h"
#include "rpc_server.h"

#include "ta_opcua.h"

static te_errno
opcua_do(int op, int h1, int h2, const char *arg, const char *params,
         const char *data, int *handle, unsigned int *features,
         unsigned int *status, int *fail_cls, char **result, char **report,
         char **errmsg)
{
    return ta_opcua_rpc((ta_opcua_op)op, h1, h2, arg, params, data, handle,
                        features, status, fail_cls, result, report, errmsg);
}

static te_errno
opcua_available(int op, int h1, int h2, const char *arg, const char *params,
                const char *data, int *handle, unsigned int *features,
                unsigned int *status, int *fail_cls, char **result,
                char **report, char **errmsg)
{
    return opcua_do(op, h1, h2, arg, params, data, handle, features, status,
                    fail_cls, result, report, errmsg);
}

TARPC_FUNC_STATIC(opcua_available, {},
{
    int handle = 0;
    unsigned int features = 0;
    unsigned int status = 0;
    int fail_cls = 0;

    MAKE_CALL(out->retval = func(in->op, in->h1, in->h2, in->arg, in->params,
                                 in->data, &handle, &features, &status,
                                 &fail_cls, &out->result, &out->report,
                                 &out->errmsg));
    out->handle = handle;
    out->features = features;
    out->status = status;
    out->fail_cls = fail_cls;
    out->common.errno_changed = false;
})

static te_errno
opcua_call(int op, int h1, int h2, const char *arg, const char *params,
           const char *data, int *handle, unsigned int *features,
           unsigned int *status, int *fail_cls, char **result, char **report,
           char **errmsg)
{
    return opcua_do(op, h1, h2, arg, params, data, handle, features, status,
                    fail_cls, result, report, errmsg);
}

TARPC_FUNC_STATIC(opcua_call, {},
{
    int handle = 0;
    unsigned int features = 0;
    unsigned int status = 0;
    int fail_cls = 0;

    MAKE_CALL(out->retval = func(in->op, in->h1, in->h2, in->arg, in->params,
                                 in->data, &handle, &features, &status,
                                 &fail_cls, &out->result, &out->report,
                                 &out->errmsg));
    out->handle = handle;
    out->features = features;
    out->status = status;
    out->fail_cls = fail_cls;
    out->common.errno_changed = false;
})
