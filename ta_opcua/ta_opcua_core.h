/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Interpretica, Unipessoal Lda. All rights reserved. */
/** @file
 * @brief OPC UA core: clients, subscriptions, simulated server
 *
 * The plain-C core of ta_opcua over open62541. It includes no Test
 * Environment header, so ci/ builds and drives it on its own (with the
 * sanitizers) and ta_opcua.c is only the TE face of it: the registry of
 * handles and the mapping of return codes to te_errno.
 *
 * Every operation is "text in, text out":
 *
 *  - options are "key=value" lines;
 *  - a result is "key=value" lines;
 *  - a report is newline-separated records of tab-separated
 *    "key=value" fields.
 *
 * In every key, value and field, '%', ',', '|', TAB, CR and LF are
 * written as %XX (ta_opcua_esc()), so a line never breaks inside a
 * field and a list never breaks inside an element.
 *
 * A value (Variant) is written as "<Type>:<payload>" for a scalar and
 * "<Type>[<n>]:<e1>,<e2>,..." for a one-dimensional array; see
 * ta_opcua_util.c for every type. No float crosses the wire as a float.
 *
 * Secrets (a password, a private key) arrive in options and go nowhere
 * else: no log, no message, no command line.
 */

#ifndef __TA_OPCUA_CORE_H__
#define __TA_OPCUA_CORE_H__

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Return codes of the core. */
enum {
    TA_OPCUA_OK = 0,
    TA_OPCUA_EINVAL,     /**< Bad argument or option. */
    TA_OPCUA_ENOENT,     /**< No such object (handle, file, node). */
    TA_OPCUA_ENOMEM,
    TA_OPCUA_ENOTSUP,    /**< Not compiled in (e.g. no encryption). */
    TA_OPCUA_ESTATUS,    /**< The service answered with a Bad status. */
    TA_OPCUA_ECONN,      /**< Connection could not be established. */
    TA_OPCUA_ETIMEDOUT,  /**< Deadline passed. */
    TA_OPCUA_EBUSY,      /**< Already running / in use. */
    TA_OPCUA_EFAIL,
};

/**
 * Phase in which a connection attempt failed (out->cls). Wire values,
 * mirrored by TAPI_OPCUA_FAIL_* on the engine.
 */
enum {
    TA_OPCUA_FAIL_NONE = 0,
    TA_OPCUA_FAIL_DNS,            /**< Host name does not resolve. */
    TA_OPCUA_FAIL_TCP,            /**< TCP connect refused / unreachable. */
    TA_OPCUA_FAIL_ENDPOINT,       /**< No endpoint matches the request. */
    TA_OPCUA_FAIL_CHANNEL,        /**< SecureChannel not opened. */
    TA_OPCUA_FAIL_CERT,           /**< Certificate validation. */
    TA_OPCUA_FAIL_AUTH,           /**< User identity rejected. */
    TA_OPCUA_FAIL_SESSION_CREATE,
    TA_OPCUA_FAIL_SESSION_ACTIVATE,
    TA_OPCUA_FAIL_TIMEOUT,        /**< A service did not answer in time. */
};

/** What an operation hands back. Strings are malloc'ed or NULL. */
typedef struct ta_opcua_out {
    uint32_t status;    /**< OPC UA StatusCode of the operation. */
    int      cls;       /**< TA_OPCUA_FAIL_* for a connection failure. */
    char    *result;    /**< "key=value" lines. */
    char    *report;    /**< Records. */
    char    *errmsg;    /**< Why it failed. */
} ta_opcua_out;

/** Release the strings of @p out (not @p out itself). */
extern void ta_opcua_out_clear(ta_opcua_out *out);

/* ---- feature discovery -------------------------------------------- */

/** Feature bits (ta_opcua_features()). */
enum {
    TA_OPCUA_FEAT_ENCRYPTION = 1 << 0,  /**< Secure policies. */
    TA_OPCUA_FEAT_EVENTS     = 1 << 1,  /**< Event monitored items. */
    TA_OPCUA_FEAT_HISTORY    = 1 << 2,  /**< Historizing compiled in. */
    TA_OPCUA_FEAT_CERTGEN    = 1 << 3,  /**< Certificate generation. */
};

/** Compiled-in features and library versions ("open62541=1.5.10"). */
extern int ta_opcua_features(unsigned int *features, ta_opcua_out *out);

/* ---- client ------------------------------------------------------- */

typedef struct ta_opcua_client ta_opcua_client;

/**
 * Connect a client and keep it running in its own thread.
 *
 * Options: security_policy (none, basic256sha256, aes128_sha256_rsaoaep,
 * aes256_sha256_rsapss, basic128rsa15, basic256, or a full URI),
 * security_mode (none, sign, signencrypt, any), auth (anonymous,
 * username, x509), user, password, user_cert, user_key, cert, key,
 * trust (comma-separated DER/PEM paths), crl (likewise), app_uri,
 * connect_timeout_ms, session_timeout_ms, request_timeout_ms,
 * channel_lifetime_ms, no_reconnect (0/1), iterate_ms.
 *
 * On failure out->cls says in which phase, out->status the StatusCode.
 */
extern int ta_opcua_client_connect(const char *endpoint, const char *params,
                                   ta_opcua_client **client,
                                   ta_opcua_out *out);

/** Disconnect and free a client (its subscriptions with it). */
extern void ta_opcua_client_free(ta_opcua_client *client);

/** Disconnect and connect again with the same configuration. */
extern int ta_opcua_client_reconnect(ta_opcua_client *client,
                                     const char *params, ta_opcua_out *out);

/**
 * Connection state: channel/session state, policy, mode, endpoint,
 * server identity, counters (channels_opened, sessions_created,
 * sessions_activated, session_changes, publish_responses).
 */
extern int ta_opcua_client_state(ta_opcua_client *client, ta_opcua_out *out);

/** Wait up to timeout_ms (option) for the session to be active again. */
extern int ta_opcua_client_wait_session(ta_opcua_client *client,
                                        const char *params,
                                        ta_opcua_out *out);

/* Discovery; no client needed. Records go to out->report. */
extern int ta_opcua_get_endpoints(const char *url, const char *params,
                                  ta_opcua_out *out);
extern int ta_opcua_find_servers(const char *url, const char *params,
                                 ta_opcua_out *out);

/* Address space. */
extern int ta_opcua_browse(ta_opcua_client *client, const char *node,
                           const char *params, ta_opcua_out *out);
extern int ta_opcua_browse_next(ta_opcua_client *client, const char *cp,
                                const char *params, ta_opcua_out *out);
extern int ta_opcua_translate(ta_opcua_client *client, const char *start,
                              const char *path, ta_opcua_out *out);
extern int ta_opcua_node_info(ta_opcua_client *client, const char *node,
                              const char *params, ta_opcua_out *out);
extern int ta_opcua_namespaces(ta_opcua_client *client, ta_opcua_out *out);

/* Data access. @p nodes is one NodeId a line (attribute=... in params). */
extern int ta_opcua_read(ta_opcua_client *client, const char *nodes,
                         const char *params, ta_opcua_out *out);
/** @p data: "<node>\t<value>" lines. */
extern int ta_opcua_write(ta_opcua_client *client, const char *data,
                          const char *params, ta_opcua_out *out);

/** Call @p method on object (option object=), inputs one value a line. */
extern int ta_opcua_call(ta_opcua_client *client, const char *method,
                         const char *params, const char *inputs,
                         ta_opcua_out *out);
/** Input/output argument descriptions of a method. */
extern int ta_opcua_method_info(ta_opcua_client *client, const char *method,
                                ta_opcua_out *out);

/* ---- subscriptions ------------------------------------------------ */

typedef struct ta_opcua_sub ta_opcua_sub;

/**
 * Create a subscription. Options: publishing_interval_ms, lifetime_count,
 * max_keepalive_count, max_notifications, priority, publishing_enabled.
 * The result carries the server-revised values.
 */
extern int ta_opcua_sub_create(ta_opcua_client *client, const char *params,
                               ta_opcua_sub **sub, ta_opcua_out *out);
extern int ta_opcua_sub_delete(ta_opcua_sub *sub, ta_opcua_out *out);

/** The client a subscription belongs to (for registry cleanup). */
extern ta_opcua_client *ta_opcua_sub_client(ta_opcua_sub *sub);

/**
 * Add a monitored item. Options: attribute, sampling_interval_ms,
 * queue_size, discard_oldest, mode (reporting, sampling, disabled),
 * trigger (status, value, value_timestamp), deadband (none, absolute,
 * percent), deadband_value. Events: kind=event, fields (comma list of
 * browse names, default EventType,SourceNode,Severity,Message,Time),
 * min_severity. Result: item id, revised sampling and queue.
 */
extern int ta_opcua_monitor(ta_opcua_sub *sub, const char *node,
                            const char *params, uint32_t *item,
                            ta_opcua_out *out);
extern int ta_opcua_unmonitor(ta_opcua_sub *sub, uint32_t item,
                              ta_opcua_out *out);

/**
 * Take the queued notifications. Options: min (wait for at least this
 * many), timeout_ms, max. Records: item, kind, seq, batch, value,
 * status, source_ts, server_ts, recv_us, and event fields. The result
 * carries the subscription state and counters.
 */
extern int ta_opcua_collect(ta_opcua_sub *sub, const char *params,
                            ta_opcua_out *out);

/* ---- simulated server -------------------------------------------- */

typedef struct ta_opcua_server ta_opcua_server;

/**
 * Start a server in its own thread. Options: port, app_uri, app_name,
 * policies (comma list), modes (comma list), anonymous (0/1), users
 * ("name:password:role" comma list; secrets are never logged), cert,
 * key, trust, allow_any_client_cert, namespace (URI),
 * max_session_timeout_ms, min_publishing_ms.
 */
extern int ta_opcua_server_start(const char *params, ta_opcua_server **srv,
                                 ta_opcua_out *out);
extern void ta_opcua_server_stop(ta_opcua_server *srv);

/**
 * Add a node. kind=variable (name, parent, value, access=r|rw,
 * read_roles, write_roles, node), kind=object, kind=method (name,
 * behaviour=echo|sum|delay|fail|counter, roles).
 */
extern int ta_opcua_server_add(ta_opcua_server *srv, const char *params,
                               ta_opcua_out *out);
/** Set a variable's value (data) as the device would. */
extern int ta_opcua_server_set(ta_opcua_server *srv, const char *node,
                               const char *value, ta_opcua_out *out);
/** Emit an event: source, severity, message, type. */
extern int ta_opcua_server_event(ta_opcua_server *srv, const char *params,
                                 ta_opcua_out *out);
/** Counters: sessions, writes, calls, endpoint url, namespace index. */
extern int ta_opcua_server_info(ta_opcua_server *srv, ta_opcua_out *out);

/* ---- certificates ------------------------------------------------- */

/**
 * Generate a key and an X.509 certificate (DER) for test use. Options:
 * cert, key (output paths), app_uri, cn, dns, not_before_s,
 * not_after_s (offsets from now), ca_cert, ca_key (sign with that CA
 * instead of self-signing), is_ca, bits.
 */
extern int ta_opcua_cert_make(const char *params, ta_opcua_out *out);
/** Certificate metadata: subject, issuer, validity, URI, key size. */
extern int ta_opcua_cert_info(const char *path, ta_opcua_out *out);
/** Write a CRL (DER) of ca_cert/ca_key revoking the serials given. */
extern int ta_opcua_crl_make(const char *params, ta_opcua_out *out);

/* ---- measurement -------------------------------------------------- */

/**
 * Run a service in a loop on the agent and time each call: op=read,
 * write, call, browse, connect; count; node; value. The report holds one
 * record per call (seq, us, status) so the engine draws it.
 */
extern int ta_opcua_perf(ta_opcua_client *client, const char *target,
                         const char *params, const char *data,
                         ta_opcua_out *out);

/* ---- utilities (ta_opcua_util.c) ---------------------------------- */

/** Escaped copy of @p s (malloc'ed). */
extern char *ta_opcua_esc(const char *s);
/** Unescape in place; returns @p s. */
extern char *ta_opcua_unesc(char *s);

/** Option @p key of "key=value" lines, malloc'ed, or NULL. */
extern char *ta_opcua_opt(const char *params, const char *key);
extern long long ta_opcua_opt_int(const char *params, const char *key,
                                  long long dflt);
extern double ta_opcua_opt_dbl(const char *params, const char *key,
                               double dflt);
extern bool ta_opcua_opt_bool(const char *params, const char *key,
                              bool dflt);

/** Monotonic microseconds. */
extern uint64_t ta_opcua_now_us(void);

#ifdef __cplusplus
} /* extern "C" */
#endif
#endif /* !__TA_OPCUA_CORE_H__ */
