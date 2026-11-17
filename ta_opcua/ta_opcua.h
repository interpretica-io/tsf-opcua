/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Interpretica, Unipessoal Lda. All rights reserved. */
/** @file
 * @brief Agent-side OPC UA operations for the RPC server
 *
 * The TE-typed face of the OPC UA engine. The engine itself is the
 * plain-C core in ta_opcua_core.h (over open62541); this layer keeps
 * the registries of live objects - a client, a subscription, a
 * simulated server each live on the agent and are named to an RPC
 * client by a small integer handle - and maps the core's return codes
 * to te_errno.
 *
 * Every operation is "text in, text out": a client/server handle, a
 * subscription handle, an operation code, up to three text arguments
 * (@c arg a node/endpoint/target, @c params options as "key=value"
 * lines, @c data a payload), and back a return code, a new handle, a
 * feature bitmask, an OPC UA StatusCode, a failure class and three
 * strings - the result ("key=value" lines), the report (records) and
 * the reason of a failure. tapi_opcua on the engine parses them.
 * Nothing crosses the RPC but these bounded strings; the session, the
 * secure channel and the subscription queues stay on the agent.
 */

#ifndef __TA_OPCUA_H__
#define __TA_OPCUA_H__

#include "te_defs.h"
#include "te_errno.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Operations of ta_opcua_rpc(). Wire values; the RPCs map onto them. */
typedef enum ta_opcua_op {
    TA_OPCUA_OP_AVAILABLE = 0,  /**< features + versions */
    TA_OPCUA_OP_CONNECT,        /**< arg=endpoint, params; -> client handle */
    TA_OPCUA_OP_DISCONNECT,     /**< h1=client */
    TA_OPCUA_OP_RECONNECT,      /**< h1=client */
    TA_OPCUA_OP_STATE,          /**< h1=client */
    TA_OPCUA_OP_WAIT_SESSION,   /**< h1=client, params=timeout_ms */
    TA_OPCUA_OP_GET_ENDPOINTS,  /**< arg=url (no handle) */
    TA_OPCUA_OP_FIND_SERVERS,   /**< arg=url (no handle) */
    TA_OPCUA_OP_BROWSE,         /**< h1=client, arg=node */
    TA_OPCUA_OP_BROWSE_NEXT,    /**< h1=client, arg=continuation point */
    TA_OPCUA_OP_TRANSLATE,      /**< h1=client, arg=start, data=path */
    TA_OPCUA_OP_NODE_INFO,      /**< h1=client, arg=node */
    TA_OPCUA_OP_NAMESPACES,     /**< h1=client */
    TA_OPCUA_OP_READ,           /**< h1=client, data=nodes (one a line) */
    TA_OPCUA_OP_WRITE,          /**< h1=client, data="node\tvalue" lines */
    TA_OPCUA_OP_CALL,           /**< h1=client, arg=method, data=inputs */
    TA_OPCUA_OP_METHOD_INFO,    /**< h1=client, arg=method */
    TA_OPCUA_OP_SUB_CREATE,     /**< h1=client; -> subscription handle */
    TA_OPCUA_OP_SUB_DELETE,     /**< h1=client, h2=sub */
    TA_OPCUA_OP_MONITOR,        /**< h1=client, h2=sub, arg=node; ->item id */
    TA_OPCUA_OP_UNMONITOR,      /**< h1=client, h2=sub, params=item=<id> */
    TA_OPCUA_OP_COLLECT,        /**< h1=client, h2=sub */
    TA_OPCUA_OP_SERVER_START,   /**< params; -> server handle */
    TA_OPCUA_OP_SERVER_STOP,    /**< h1=server */
    TA_OPCUA_OP_SERVER_ADD,     /**< h1=server, params */
    TA_OPCUA_OP_SERVER_SET,     /**< h1=server, arg=node, data=value */
    TA_OPCUA_OP_SERVER_EVENT,   /**< h1=server, params */
    TA_OPCUA_OP_SERVER_INFO,    /**< h1=server */
    TA_OPCUA_OP_CERT_MAKE,      /**< params */
    TA_OPCUA_OP_CERT_INFO,      /**< arg=path */
    TA_OPCUA_OP_CRL_MAKE,       /**< params */
    TA_OPCUA_OP_PERF,           /**< h1=client, arg=target, params, data */
    TA_OPCUA_OP_STATS,          /**< registry counters */
} ta_opcua_op;

/**
 * Run one operation.
 *
 * @param op        What to do.
 * @param h1        Client or server handle (most operations), or 0.
 * @param h2        Subscription handle (subscription operations), or 0.
 * @param arg       A node id, endpoint/url, method, path or file, else "".
 * @param params    Options, "key=value" lines.
 * @param data      A payload (nodes, write values, inputs), else "".
 * @param handle    New handle (connect, sub_create, server_start).
 * @param features  Feature bits (available).
 * @param status    OPC UA StatusCode of the operation.
 * @param fail_cls  Connection failure class (TA_OPCUA_FAIL_* mirror), 0.
 * @param result    Result lines (heap, never NULL; caller frees).
 * @param report    Report records (heap, never NULL; caller frees).
 * @param errmsg    Failure reason (heap, never NULL; caller frees).
 */
extern te_errno ta_opcua_rpc(ta_opcua_op op, int h1, int h2, const char *arg,
                             const char *params, const char *data, int *handle,
                             unsigned int *features, unsigned int *status,
                             int *fail_cls, char **result, char **report,
                             char **errmsg);

#ifdef __cplusplus
} /* extern "C" */
#endif
#endif /* !__TA_OPCUA_H__ */
