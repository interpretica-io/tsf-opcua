/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Interpretica, Unipessoal Lda. All rights reserved. */
/** @file
 * @brief OPC UA TAPI: RPC client layer
 *
 * One entry point for both opcua_* RPCs (see ta_opcua/opcua_rpc.x.m4).
 * Both RPCs share the same text-in, text-out shape, so they share one
 * argument and one result structure and one call that names the
 * operation. Tests use tapi_opcua.h; this is the layer beneath it.
 */

#ifndef __TAPI_OPCUA_RPC_H__
#define __TAPI_OPCUA_RPC_H__

#include "te_defs.h"
#include "te_errno.h"
#include "te_string.h"
#include "rcf_rpc.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Operation code; mirrors ta_opcua_op on the agent. */
typedef enum tapi_opcua_op {
    TAPI_OPCUA_OP_AVAILABLE = 0,
    TAPI_OPCUA_OP_CONNECT,
    TAPI_OPCUA_OP_DISCONNECT,
    TAPI_OPCUA_OP_RECONNECT,
    TAPI_OPCUA_OP_STATE,
    TAPI_OPCUA_OP_WAIT_SESSION,
    TAPI_OPCUA_OP_GET_ENDPOINTS,
    TAPI_OPCUA_OP_FIND_SERVERS,
    TAPI_OPCUA_OP_BROWSE,
    TAPI_OPCUA_OP_BROWSE_NEXT,
    TAPI_OPCUA_OP_TRANSLATE,
    TAPI_OPCUA_OP_NODE_INFO,
    TAPI_OPCUA_OP_NAMESPACES,
    TAPI_OPCUA_OP_READ,
    TAPI_OPCUA_OP_WRITE,
    TAPI_OPCUA_OP_CALL,
    TAPI_OPCUA_OP_METHOD_INFO,
    TAPI_OPCUA_OP_SUB_CREATE,
    TAPI_OPCUA_OP_SUB_DELETE,
    TAPI_OPCUA_OP_MONITOR,
    TAPI_OPCUA_OP_UNMONITOR,
    TAPI_OPCUA_OP_COLLECT,
    TAPI_OPCUA_OP_SERVER_START,
    TAPI_OPCUA_OP_SERVER_STOP,
    TAPI_OPCUA_OP_SERVER_ADD,
    TAPI_OPCUA_OP_SERVER_SET,
    TAPI_OPCUA_OP_SERVER_EVENT,
    TAPI_OPCUA_OP_SERVER_INFO,
    TAPI_OPCUA_OP_CERT_MAKE,
    TAPI_OPCUA_OP_CERT_INFO,
    TAPI_OPCUA_OP_CRL_MAKE,
    TAPI_OPCUA_OP_PERF,
    TAPI_OPCUA_OP_STATS,
} tapi_opcua_op;

/** Arguments of an opcua_* RPC; NULL strings travel as "". */
typedef struct tapi_opcua_rpc_args {
    int         h1;
    int         h2;
    const char *arg;
    const char *params;
    const char *data;
} tapi_opcua_rpc_args;

/** Results of an opcua_* RPC. Initialise with TAPI_OPCUA_RPC_RES_INIT. */
typedef struct tapi_opcua_rpc_res {
    int             handle;
    unsigned int    features;
    unsigned int    status;      /**< OPC UA StatusCode. */
    int             fail_cls;    /**< Connection failure class. */
    te_string       result;
    te_string       report;
    te_string       errmsg;
} tapi_opcua_rpc_res;

#define TAPI_OPCUA_RPC_RES_INIT \
    { 0, 0, 0, 0, TE_STRING_INIT, TE_STRING_INIT, TE_STRING_INIT }

/** Free the strings of a result. */
extern void tapi_opcua_rpc_res_free(tapi_opcua_rpc_res *res);

/**
 * Call an opcua_* RPC. The RPC's own failure is returned, not jumped
 * on: a connection that is refused, a service that answers Bad, are
 * findings for the test to judge.
 *
 * @param timeout_ms  Timeout of this call, 0 for the TAPI default.
 */
extern te_errno rpc_opcua_call(rcf_rpc_server *rpcs, tapi_opcua_op op,
                               const tapi_opcua_rpc_args *args,
                               unsigned int timeout_ms,
                               tapi_opcua_rpc_res *res);

#ifdef __cplusplus
} /* extern "C" */
#endif
#endif /* !__TAPI_OPCUA_RPC_H__ */
