/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Interpretica, Unipessoal Lda. All rights reserved. */
/** @file
 * @brief OPC UA TAPI: connections, values and data access
 *
 * @defgroup tapi_opcua OPC UA testing (tapi_opcua)
 * @{
 *
 * Engine-side API for exercising OPC UA servers and applications
 * through a Test Agent. The agent runs an open62541 client (and,
 * optionally, a simulated server); this API drives it over the opcua_*
 * RPCs. A connection, a subscription and a simulated server each live
 * on the agent and are named here by an opaque handle. Values cross as
 * text and are parsed into ::tapi_opcua_value.
 *
 * What is where:
 *  - connections, values, data access, method calls: this header;
 *  - the address space: tapi_opcua_browse.h;
 *  - subscriptions, monitored items, events: tapi_opcua_subscription.h;
 *  - the simulated server: tapi_opcua_server.h;
 *  - discovery and security checks: tapi_opcua_security.h.
 *
 * A call's own OPC UA failure (a refused connection, a Bad status) is
 * returned, not jumped on with CHECK_RC: it is a finding for the test
 * to judge. A transport or usage error is returned as a TE errno.
 */

#ifndef __TAPI_OPCUA_H__
#define __TAPI_OPCUA_H__

#include "te_defs.h"
#include "te_errno.h"
#include "te_string.h"
#include "rcf_rpc.h"

#include "tapi_opcua_rpc.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Feature bits of ::tapi_opcua_get_capabilities (mirror of the core). */
#define TAPI_OPCUA_FEAT_ENCRYPTION  (1u << 0)
#define TAPI_OPCUA_FEAT_EVENTS      (1u << 1)
#define TAPI_OPCUA_FEAT_HISTORY     (1u << 2)
#define TAPI_OPCUA_FEAT_CERTGEN     (1u << 3)

/** Phase a connection attempt failed in (mirror of TA_OPCUA_FAIL_*). */
typedef enum tapi_opcua_fail {
    TAPI_OPCUA_FAIL_NONE = 0,
    TAPI_OPCUA_FAIL_DNS,
    TAPI_OPCUA_FAIL_TCP,
    TAPI_OPCUA_FAIL_ENDPOINT,
    TAPI_OPCUA_FAIL_CHANNEL,
    TAPI_OPCUA_FAIL_CERT,
    TAPI_OPCUA_FAIL_AUTH,
    TAPI_OPCUA_FAIL_SESSION_CREATE,
    TAPI_OPCUA_FAIL_SESSION_ACTIVATE,
    TAPI_OPCUA_FAIL_TIMEOUT,
} tapi_opcua_fail;

/** Message security mode. */
typedef enum tapi_opcua_mode {
    TAPI_OPCUA_MODE_ANY = 0,  /**< Let the client pick any endpoint. */
    TAPI_OPCUA_MODE_NONE,     /**< No signing, no encryption. */
    TAPI_OPCUA_MODE_SIGN,
    TAPI_OPCUA_MODE_SIGN_ENCRYPT,
} tapi_opcua_mode;

/** A handle to an object on the agent (a connection, a subscription). */
typedef struct tapi_opcua_handle {
    rcf_rpc_server *rpcs;       /**< The agent's RPC server. */
    int             id;         /**< Handle id, >0 when live. */
} tapi_opcua_handle;

/** A connection. */
typedef tapi_opcua_handle tapi_opcua_conn;

/** Options for ::tapi_opcua_connect. NULL/0 fields take a default. */
typedef struct tapi_opcua_connect_opt {
    const char       *endpoint;         /**< opc.tcp URL (required). */
    const char       *app_uri;          /**< Client ApplicationUri. */
    const char       *security_policy;  /**< "none", "basic256sha256"... */
    tapi_opcua_mode   security_mode;
    const char       *auth;             /**< "anonymous"/"username"/"x509". */
    const char       *user;
    const char       *password;         /**< Never logged. */
    const char       *user_cert;        /**< x509 auth: paths on the agent. */
    const char       *user_key;
    const char       *cert;             /**< Client certificate (agent path). */
    const char       *key;              /**< Its private key. */
    const char       *trust;            /**< Comma list of trusted certs. */
    const char       *crl;              /**< Comma list of CRLs. */
    int               connect_timeout_ms;
    int               session_timeout_ms;
    int               request_timeout_ms;
    int               channel_lifetime_ms;
    bool              no_reconnect;
} tapi_opcua_connect_opt;

/** The parsed type of a value on the wire. */
typedef enum tapi_opcua_vtype {
    TAPI_OPCUA_NULL = 0,
    TAPI_OPCUA_BOOL,
    TAPI_OPCUA_INT,         /**< Any signed integer type. */
    TAPI_OPCUA_UINT,        /**< Any unsigned integer type. */
    TAPI_OPCUA_DOUBLE,      /**< Float or Double. */
    TAPI_OPCUA_STRING,      /**< String, LocalizedText, XmlElement. */
    TAPI_OPCUA_BYTES,       /**< ByteString (hex in @c raw). */
    TAPI_OPCUA_DATETIME,    /**< UA ticks in @c i64. */
    TAPI_OPCUA_STATUSCODE,
    TAPI_OPCUA_NODEID,
    TAPI_OPCUA_OTHER,       /**< Something else; see @c type and @c raw. */
} tapi_opcua_vtype;

/** A read value: the OPC UA DataValue, parsed. */
typedef struct tapi_opcua_value {
    tapi_opcua_vtype type;       /**< Coarse kind for the union. */
    char            *type_name;  /**< OPC UA type name ("Double"...). */
    char            *raw;        /**< Wire payload of the (scalar) value. */
    bool             is_array;
    size_t           array_len;
    union {
        bool     b;
        int64_t  i64;
        uint64_t u64;
        double   f64;
    } data;                      /**< Set for a scalar of a known kind. */
    uint32_t         status;     /**< The value's StatusCode. */
    bool             has_source_ts;
    int64_t          source_ts;  /**< UA ticks, valid iff has_source_ts. */
    bool             has_server_ts;
    int64_t          server_ts;
} tapi_opcua_value;

/** Release a value. */
extern void tapi_opcua_value_free(tapi_opcua_value *value);

/** A parsed "key=value" result set (lines from result/report records). */
typedef struct tapi_opcua_kv {
    char **keys;
    char **vals;
    size_t n;
} tapi_opcua_kv;

#define TAPI_OPCUA_KV_INIT { NULL, NULL, 0 }

/** Parse "key=value" lines (one field a line) into @p kv. */
extern void tapi_opcua_kv_parse(const char *text, tapi_opcua_kv *kv);
/** Parse one tab-separated record's fields into @p kv. */
extern void tapi_opcua_kv_parse_record(const char *record, tapi_opcua_kv *kv);
extern const char *tapi_opcua_kv_get(const tapi_opcua_kv *kv, const char *key);
extern int64_t tapi_opcua_kv_get_int(const tapi_opcua_kv *kv, const char *key,
                                     int64_t dflt);
extern void tapi_opcua_kv_free(tapi_opcua_kv *kv);

/** Iterate a report's records: @p start in/out, returns the next record
 *  (malloc'ed, caller frees) or NULL at the end. */
extern char *tapi_opcua_report_next(const char *report, size_t *offset);

/* ---- capability discovery ----------------------------------------- */

/** Is the OPC UA engine (open62541) present on @p rpcs? */
extern bool tapi_opcua_available(rcf_rpc_server *rpcs);

/** Compiled-in features (TAPI_OPCUA_FEAT_*); @p versions may be NULL. */
extern te_errno tapi_opcua_get_capabilities(rcf_rpc_server *rpcs,
                                            unsigned int *features,
                                            te_string *versions);

/* ---- connection --------------------------------------------------- */

/**
 * Open a connection (SecureChannel + Session) on the agent.
 *
 * The RPC's own failure is reported through @p conn being left dead and
 * the return value: a refused or rejected connection returns a TE errno
 * and ::tapi_opcua_last_fail / ::tapi_opcua_last_status say why. A usage
 * error (bad option) also returns non-zero.
 */
extern te_errno tapi_opcua_connect(rcf_rpc_server *rpcs,
                                   const tapi_opcua_connect_opt *opt,
                                   tapi_opcua_conn *conn);

/** Close a connection (and every subscription on it). */
extern te_errno tapi_opcua_disconnect(tapi_opcua_conn *conn);

/** Disconnect and connect again with the same configuration. */
extern te_errno tapi_opcua_reconnect(tapi_opcua_conn *conn);

/** Is the session currently activated? */
extern bool tapi_opcua_is_connected(tapi_opcua_conn *conn);

/** Session/channel state and counters, as a key-value set. */
extern te_errno tapi_opcua_get_session_info(tapi_opcua_conn *conn,
                                            tapi_opcua_kv *info);

/** Wait up to @p timeout_ms for the session to be active again. */
extern te_errno tapi_opcua_wait_session(tapi_opcua_conn *conn,
                                        int timeout_ms);

/** The failure class / StatusCode of the most recent call on @p conn. */
extern tapi_opcua_fail tapi_opcua_last_fail(const tapi_opcua_conn *conn);
extern uint32_t tapi_opcua_last_status(const tapi_opcua_conn *conn);

/* ---- data access -------------------------------------------------- */

/** Read the Value attribute of @p node into @p value. */
extern te_errno tapi_opcua_read(tapi_opcua_conn *conn, const char *node,
                                tapi_opcua_value *value);

/** Read a named attribute ("value","datatype","accesslevel"...). */
extern te_errno tapi_opcua_read_attribute(tapi_opcua_conn *conn,
                                          const char *node,
                                          const char *attribute,
                                          tapi_opcua_value *value);

/** Read several nodes at once. @p nodes: NodeIds, one a line. @p values
 *  and @p n are allocated (free each value, then the array). */
extern te_errno tapi_opcua_read_many(tapi_opcua_conn *conn, const char *nodes,
                                     tapi_opcua_value **values, size_t *n);

/** Write @p value (wire form "<Type>:<payload>") to @p node. */
extern te_errno tapi_opcua_write(tapi_opcua_conn *conn, const char *node,
                                 const char *value, uint32_t *status);

/** Write several: @p data is "node<TAB>value" lines. */
extern te_errno tapi_opcua_write_many(tapi_opcua_conn *conn, const char *data,
                                      tapi_opcua_kv *statuses);

/* ---- method calls ------------------------------------------------- */

/**
 * Call @p method on @p object. @p inputs are wire-form values, one a
 * line (NULL for none). The outputs are returned as a report of
 * "index=..\tvalue=.." records in @p outputs (caller frees).
 */
extern te_errno tapi_opcua_call(tapi_opcua_conn *conn, const char *object,
                                const char *method, const char *inputs,
                                te_string *outputs, uint32_t *status);

/* ---- measurement -------------------------------------------------- */

/**
 * Time @p count calls of operation @p op ("read"/"browse") against
 * @p node on the agent. The per-call report ("seq\tus\tstatus") is put
 * in @p samples (caller frees); summary stats land in @p summary.
 */
extern te_errno tapi_opcua_perf(tapi_opcua_conn *conn, const char *op,
                                const char *node, int count,
                                te_string *samples, tapi_opcua_kv *summary);

/** Registry counters of the agent (open clients, subscriptions...). */
extern te_errno tapi_opcua_stats(rcf_rpc_server *rpcs, tapi_opcua_kv *stats);

#ifdef __cplusplus
} /* extern "C" */
#endif

/* The facet headers build on the types above. */
#include "tapi_opcua_browse.h"
#include "tapi_opcua_subscription.h"
#include "tapi_opcua_server.h"
#include "tapi_opcua_security.h"

/**@} <!-- tapi_opcua --> */
#endif /* !__TAPI_OPCUA_H__ */
