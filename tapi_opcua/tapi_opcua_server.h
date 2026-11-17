/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Interpretica, Unipessoal Lda. All rights reserved. */
/** @file
 * @brief OPC UA TAPI: the simulated server (test equipment)
 *
 * @addtogroup tapi_opcua
 * @{
 *
 * An optional, controllable OPC UA server on the agent, for
 * deterministic integration and fault-injection tests: start it, add
 * variables and methods, change values the way a device would, emit
 * events, read its counters, stop it. It is test equipment, not a
 * production deployment, and lives only as long as the test keeps it.
 * For conformance testing, point the client at an independently
 * validated reference server instead.
 *
 * A node is addressed by its browse name in namespace 1 (the functions
 * accept a bare name or a full NodeId). A method's behaviour is one of a
 * fixed set (echo, sum, delay, fail). User accounts are
 * "name:password:role" entries; the password is never logged.
 */

#ifndef __TAPI_OPCUA_SERVER_H__
#define __TAPI_OPCUA_SERVER_H__

#include "tapi_opcua.h"

#ifdef __cplusplus
extern "C" {
#endif

/** A simulated-server handle. */
typedef tapi_opcua_handle tapi_opcua_server;

/** Server options. */
typedef struct tapi_opcua_server_opt {
    int          port;                  /**< Default 4840. */
    const char  *app_uri;
    const char  *app_name;
    const char  *namespace_uri;         /**< Default "urn:tsf-opcua:sim". */
    bool         no_anonymous;          /**< Default allows anonymous. */
    const char  *users;                 /**< "name:pw:role" comma list. */
    const char  *cert;                  /**< Server certificate (agent path). */
    const char  *key;
} tapi_opcua_server_opt;

/** Start a server on the agent. The endpoint URL and namespace index are
 *  in @p info (NULL to ignore). */
extern te_errno tapi_opcua_server_start(rcf_rpc_server *rpcs,
                                        const tapi_opcua_server_opt *opt,
                                        tapi_opcua_server *srv,
                                        tapi_opcua_kv *info);

/** Stop and free a simulated server. */
extern te_errno tapi_opcua_server_stop(tapi_opcua_server *srv);

/** Add a variable node. @p value is a wire-form value or NULL (Int32 0).
 *  @p writable makes it read/write. @p node_id out (NULL ok). */
extern te_errno tapi_opcua_server_add_variable(tapi_opcua_server *srv,
                                               const char *name,
                                               const char *value,
                                               bool writable,
                                               te_string *node_id);

/** Add a method with a built-in @p behaviour ("echo"/"sum"/"delay"/"fail"). */
extern te_errno tapi_opcua_server_add_method(tapi_opcua_server *srv,
                                             const char *name,
                                             const char *behaviour,
                                             te_string *node_id);

/** Set a variable's value as the device would (@p value is wire form). */
extern te_errno tapi_opcua_server_set_value(tapi_opcua_server *srv,
                                            const char *node,
                                            const char *value);

/** Emit an event from @p source (NULL = Server) with @p severity/@p msg. */
extern te_errno tapi_opcua_server_event(tapi_opcua_server *srv,
                                        const char *source,
                                        unsigned int severity,
                                        const char *msg);

/** Read the server's counters (endpoint, writes, calls...). */
extern te_errno tapi_opcua_server_info(tapi_opcua_server *srv,
                                       tapi_opcua_kv *info);

#ifdef __cplusplus
} /* extern "C" */
#endif
/**@} */
#endif /* !__TAPI_OPCUA_SERVER_H__ */
