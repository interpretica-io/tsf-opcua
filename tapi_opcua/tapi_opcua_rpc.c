/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Interpretica, Unipessoal Lda. All rights reserved. */
/** @file
 * @brief OPC UA TAPI: RPC client layer
 *
 * The rcf_rpc_call() boilerplate behind tapi_opcua. opcua_available is
 * its own RPC (so a suite can discover features on an agent that has no
 * handles yet); every other operation goes through opcua_call, selected
 * by the op code. An RPC transport failure is mapped to TE_ECORRUPTED.
 */

#define TE_LGR_USER     "TAPI OPCUA RPC"

#include "te_config.h"

#include <string.h>

#include "te_defs.h"
#include "te_errno.h"
#include "te_string.h"
#include "logger_api.h"
#include "tapi_rpc_internal.h"
#include "tarpc.h"

#include "tapi_opcua_rpc.h"

#define CHECK_RPC_ERRNO_UNCHANGED(_func, _var) \
    CHECK_RETVAL_VAR_ERR_COND(_func, _var, false,                    \
                              TE_RC(TE_TAPI, TE_ECORRUPTED), false)

void
tapi_opcua_rpc_res_free(tapi_opcua_rpc_res *res)
{
    te_string_free(&res->result);
    te_string_free(&res->report);
    te_string_free(&res->errmsg);
}

static char *
s(const char *v)
{
    return (char *)(v != NULL ? v : "");
}

static void
take(te_string *dst, const char *src)
{
    if (src != NULL && *src != '\0')
        te_string_append(dst, "%s", src);
}

#define OPCUA_RPC(_name) \
static te_errno                                                         \
call_##_name(rcf_rpc_server *rpcs, int op, const tapi_opcua_rpc_args *a,\
             tapi_opcua_rpc_res *r)                                     \
{                                                                       \
    tarpc_##_name##_in in;                                             \
    tarpc_##_name##_out out;                                           \
                                                                        \
    memset(&in, 0, sizeof(in));                                        \
    memset(&out, 0, sizeof(out));                                      \
    in.op = op;                                                        \
    in.h1 = a->h1;                                                     \
    in.h2 = a->h2;                                                     \
    in.arg = s(a->arg);                                                \
    in.params = s(a->params);                                          \
    in.data = s(a->data);                                              \
                                                                        \
    rcf_rpc_call(rpcs, #_name, &in, &out);                             \
    CHECK_RPC_ERRNO_UNCHANGED(_name, out.retval);                      \
    TAPI_RPC_LOG(rpcs, _name, "op=%d h1=%d h2=%d %s", "%r handle=%d",  \
                 op, a->h1, a->h2, s(a->arg), out.retval, out.handle); \
    r->handle = out.handle;                                            \
    r->features = out.features;                                        \
    r->status = out.status;                                            \
    r->fail_cls = out.fail_cls;                                        \
    take(&r->result, out.result);                                      \
    take(&r->report, out.report);                                      \
    take(&r->errmsg, out.errmsg);                                      \
                                                                        \
    RETVAL_TE_ERRNO(_name, out.retval);                                \
}

OPCUA_RPC(opcua_available)
OPCUA_RPC(opcua_call)

/** Default timeout: a connect or a collect may wait seconds. */
#define TAPI_OPCUA_RPC_TIMEOUT_MS (2 * 60 * 1000)

te_errno
rpc_opcua_call(rcf_rpc_server *rpcs, tapi_opcua_op op,
               const tapi_opcua_rpc_args *args, unsigned int timeout_ms,
               tapi_opcua_rpc_res *res)
{
    rpcs->timeout = timeout_ms != 0 ? timeout_ms : TAPI_OPCUA_RPC_TIMEOUT_MS;
    RPC_AWAIT_ERROR(rpcs);
    if (op == TAPI_OPCUA_OP_AVAILABLE)
        return call_opcua_available(rpcs, (int)op, args, res);
    return call_opcua_call(rpcs, (int)op, args, res);
}
