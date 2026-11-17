/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Interpretica, Unipessoal Lda. All rights reserved. */
/** @file
 * @brief OPC UA TAPI: discovery and security checks
 *
 * @defgroup tapi_opcua_security Security checks (tapi_opcua_security)
 * @ingroup tapi_opcua
 * @{
 *
 * What an OPC UA server looks like to someone who should not be trusted
 * with it: an insecure endpoint left enabled, Message Security Mode
 * None where it is prohibited, anonymous access to protected data, a
 * write that should have been refused, an invalid or untrusted
 * certificate accepted against policy, a privileged method anyone can
 * call.
 *
 * The default is read-only: ::tapi_opcua_audit_endpoints and
 * ::tapi_opcua_audit_anonymous only read the server's advertised
 * endpoints and read protected nodes. The active checks -
 * ::tapi_opcua_audit_unauthorized_write and
 * ::tapi_opcua_audit_bad_cert - act only on what the test hands them
 * and must be enabled explicitly; a write audit restores the original
 * value when it can.
 *
 * Findings carry a stable check id, a subject and a severity, the model
 * of tsf-cybersec; tapi_opcua_cybersec.h moves a report into a
 * tapi_cybersec_report for a suite that builds tsf-cybersec.
 * tapi_opcua itself does not depend on it.
 *
 * A check that could not look (an endpoint that would not answer) says
 * so with a @c *.not-assessed finding rather than passing.
 *
 * Authorized use only: run these against servers you own or are engaged
 * to test.
 */

#ifndef __TAPI_OPCUA_SECURITY_H__
#define __TAPI_OPCUA_SECURITY_H__

#include "tapi_opcua.h"

#ifdef __cplusplus
extern "C" {
#endif

/** How much a finding matters (the scale of tsf-cybersec). */
typedef enum tapi_opcua_severity {
    TAPI_OPCUA_SEV_INFO = 0,
    TAPI_OPCUA_SEV_LOW,
    TAPI_OPCUA_SEV_MEDIUM,
    TAPI_OPCUA_SEV_HIGH,
    TAPI_OPCUA_SEV_CRITICAL,
} tapi_opcua_severity;

/** One thing a check found. */
typedef struct tapi_opcua_finding {
    tapi_opcua_severity severity;
    char               *check;    /**< Stable id, e.g. "opcua.endpoint.none". */
    char               *subject;  /**< What it is about; stable. */
    char               *detail;   /**< Free text for the log. */
} tapi_opcua_finding;

/** Everything the checks found. */
typedef struct tapi_opcua_report {
    tapi_opcua_finding *items;
    unsigned int        n;
} tapi_opcua_report;

#define TAPI_OPCUA_REPORT_INIT { NULL, 0 }

extern void tapi_opcua_report_add(tapi_opcua_report *report,
                                  tapi_opcua_severity severity,
                                  const char *check, const char *subject,
                                  const char *detail_fmt, ...)
                                  TE_LIKE_PRINTF(5, 6);
extern unsigned int tapi_opcua_report_count(const tapi_opcua_report *report,
                                            tapi_opcua_severity min_severity);
extern bool tapi_opcua_report_has(const tapi_opcua_report *report,
                                  const char *check);
extern void tapi_opcua_report_log(const tapi_opcua_report *report);
extern bool tapi_opcua_report_verdict(const tapi_opcua_report *report,
                                      tapi_opcua_severity min_severity,
                                      te_string *dest);
extern void tapi_opcua_report_free(tapi_opcua_report *report);
extern const char *tapi_opcua_severity2str(tapi_opcua_severity severity);

/* ---- discovery (no connection needed) ----------------------------- */

/** Get the endpoints advertised by @p url as a report (one a record). */
extern te_errno tapi_opcua_get_endpoints(rcf_rpc_server *rpcs,
                                         const char *url,
                                         te_string *endpoints);
/** Get the servers registered at @p url. */
extern te_errno tapi_opcua_find_servers(rcf_rpc_server *rpcs,
                                        const char *url, te_string *servers);
/** Server identity from its first endpoint (application/product uri). */
extern te_errno tapi_opcua_get_server_info(rcf_rpc_server *rpcs,
                                           const char *url,
                                           tapi_opcua_kv *info);

/* ---- audits ------------------------------------------------------- */

/**
 * Read the endpoints of @p url and record a finding for each insecure
 * one: a SecurityMode None endpoint, a None SecurityPolicy, a username
 * token offered over an unencrypted channel. @p require_secure: when
 * true, the presence of any None endpoint is a finding.
 */
extern te_errno tapi_opcua_audit_endpoints(rcf_rpc_server *rpcs,
                                           const char *url,
                                           bool require_secure,
                                           tapi_opcua_report *report);

/**
 * Connect anonymously to @p url and try to read each node in @p nodes
 * (one a line). A node that reads Good anonymously is a finding
 * (protected data readable without authorization). A node that is
 * absent or refuses is not.
 */
extern te_errno tapi_opcua_audit_anonymous(rcf_rpc_server *rpcs,
                                           const char *url,
                                           const char *nodes,
                                           tapi_opcua_report *report);

/**
 * On an existing connection, try to write @p value to @p node and judge
 * the result: a Good write by an identity that should not be allowed is
 * a finding (unauthorized write). The original value is read first and
 * restored when the write succeeded and @p restore is true.
 */
extern te_errno tapi_opcua_audit_unauthorized_write(tapi_opcua_conn *conn,
                                                    const char *node,
                                                    const char *value,
                                                    bool restore,
                                                    tapi_opcua_report *report);

/**
 * Try to connect to @p url with the certificate @p cert / @p key, which
 * the test has made invalid in @p how ("expired", "untrusted",
 * "uri-mismatch"). A connection that is accepted against policy is a
 * finding; a rejection is the expected, safe result.
 */
extern te_errno tapi_opcua_audit_bad_cert(rcf_rpc_server *rpcs,
                                          const char *url, const char *cert,
                                          const char *key, const char *how,
                                          tapi_opcua_report *report);

/* ---- certificate helpers (test material) -------------------------- */

/** Make a key + self-signed cert on the agent. @p params: cn, app_uri,
 *  dns, expires_in_days, bits; @p cert_path/@p key_path are agent paths. */
extern te_errno tapi_opcua_make_cert(rcf_rpc_server *rpcs,
                                     const char *cert_path,
                                     const char *key_path,
                                     const char *params);
/** Read a certificate's metadata (subject, expiry, expired, key size). */
extern te_errno tapi_opcua_cert_info(rcf_rpc_server *rpcs, const char *path,
                                     tapi_opcua_kv *info);

#ifdef __cplusplus
} /* extern "C" */
#endif
/**@} */
#endif /* !__TAPI_OPCUA_SECURITY_H__ */
