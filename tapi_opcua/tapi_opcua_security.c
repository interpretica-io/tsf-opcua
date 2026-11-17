/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Interpretica, Unipessoal Lda. All rights reserved. */
/** @file
 * @brief OPC UA TAPI: discovery and security checks
 *
 * The findings model (the tsf-cybersec severity scale and a stable
 * check id per finding) plus the discovery helpers and the audits. The
 * audits read what the agent discovered or what a connection returns
 * and turn a dangerous answer into a finding; a check that could not
 * look records a @c *.not-assessed finding rather than passing.
 */

#define TE_LGR_USER     "TAPI OPCUA"

#include "te_config.h"

#include <stdarg.h>
#include <string.h>

#include "te_defs.h"
#include "te_errno.h"
#include "te_string.h"
#include "te_alloc.h"
#include "logger_api.h"

#include "tapi_opcua.h"

/* ---- report model ------------------------------------------------- */

static const char *sev_names[] = {
    "INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"
};

const char *
tapi_opcua_severity2str(tapi_opcua_severity severity)
{
    if ((unsigned)severity < TE_ARRAY_LEN(sev_names))
        return sev_names[severity];
    return "?";
}

void
tapi_opcua_report_add(tapi_opcua_report *report, tapi_opcua_severity severity,
                      const char *check, const char *subject,
                      const char *detail_fmt, ...)
{
    tapi_opcua_finding *f;
    va_list ap;
    te_string d = TE_STRING_INIT;

    report->items = TE_REALLOC(report->items,
                               (report->n + 1) * sizeof(*report->items));
    f = &report->items[report->n];
    f->severity = severity;
    f->check = TE_STRDUP(check);
    f->subject = TE_STRDUP(subject != NULL ? subject : "");
    va_start(ap, detail_fmt);
    te_string_append_va(&d, detail_fmt, ap);
    va_end(ap);
    f->detail = d.ptr != NULL ? d.ptr : TE_STRDUP("");
    report->n++;
}

unsigned int
tapi_opcua_report_count(const tapi_opcua_report *report,
                        tapi_opcua_severity min_severity)
{
    unsigned int i;
    unsigned int n = 0;

    for (i = 0; i < report->n; i++)
        if (report->items[i].severity >= min_severity)
            n++;
    return n;
}

bool
tapi_opcua_report_has(const tapi_opcua_report *report, const char *check)
{
    unsigned int i;

    for (i = 0; i < report->n; i++)
        if (strcmp(report->items[i].check, check) == 0)
            return true;
    return false;
}

void
tapi_opcua_report_log(const tapi_opcua_report *report)
{
    int sev;
    unsigned int i;

    for (sev = TAPI_OPCUA_SEV_CRITICAL; sev >= TAPI_OPCUA_SEV_INFO; sev--)
    {
        for (i = 0; i < report->n; i++)
        {
            if ((int)report->items[i].severity != sev)
                continue;
            RING("[%s] %s (%s): %s",
                 tapi_opcua_severity2str(report->items[i].severity),
                 report->items[i].check, report->items[i].subject,
                 report->items[i].detail);
        }
    }
}

bool
tapi_opcua_report_verdict(const tapi_opcua_report *report,
                          tapi_opcua_severity min_severity, te_string *dest)
{
    int sev;
    unsigned int i;
    bool any = false;

    for (sev = TAPI_OPCUA_SEV_CRITICAL; sev >= (int)min_severity; sev--)
    {
        for (i = 0; i < report->n; i++)
        {
            if ((int)report->items[i].severity != sev)
                continue;
            te_string_append(dest, "%s%s", any ? "; " : "",
                             report->items[i].check);
            any = true;
        }
    }
    return any;
}

void
tapi_opcua_report_free(tapi_opcua_report *report)
{
    unsigned int i;

    for (i = 0; i < report->n; i++)
    {
        free(report->items[i].check);
        free(report->items[i].subject);
        free(report->items[i].detail);
    }
    free(report->items);
    report->items = NULL;
    report->n = 0;
}

/* ---- discovery ---------------------------------------------------- */

static te_errno
disc_op(rcf_rpc_server *rpcs, tapi_opcua_op op, const char *url,
        te_string *report, te_string *result)
{
    tapi_opcua_rpc_args a = { 0 };
    tapi_opcua_rpc_res res = TAPI_OPCUA_RPC_RES_INIT;
    te_errno rc;

    a.arg = url;
    rc = rpc_opcua_call(rpcs, op, &a, 0, &res);
    if (report != NULL && res.report.ptr != NULL)
        te_string_append(report, "%s", res.report.ptr);
    if (result != NULL && res.result.ptr != NULL)
        te_string_append(result, "%s", res.result.ptr);
    tapi_opcua_rpc_res_free(&res);
    return rc;
}

te_errno
tapi_opcua_get_endpoints(rcf_rpc_server *rpcs, const char *url,
                         te_string *endpoints)
{
    return disc_op(rpcs, TAPI_OPCUA_OP_GET_ENDPOINTS, url, endpoints, NULL);
}

te_errno
tapi_opcua_find_servers(rcf_rpc_server *rpcs, const char *url,
                        te_string *servers)
{
    return disc_op(rpcs, TAPI_OPCUA_OP_FIND_SERVERS, url, servers, NULL);
}

te_errno
tapi_opcua_get_server_info(rcf_rpc_server *rpcs, const char *url,
                           tapi_opcua_kv *info)
{
    te_string report = TE_STRING_INIT;
    te_errno rc;
    size_t off = 0;
    char *rec;

    rc = disc_op(rpcs, TAPI_OPCUA_OP_GET_ENDPOINTS, url, &report, NULL);
    rec = tapi_opcua_report_next(report.ptr, &off);
    if (rec != NULL && info != NULL)
        tapi_opcua_kv_parse_record(rec, info);
    free(rec);
    te_string_free(&report);
    return rc;
}

/* ---- audits ------------------------------------------------------- */

te_errno
tapi_opcua_audit_endpoints(rcf_rpc_server *rpcs, const char *url,
                           bool require_secure, tapi_opcua_report *report)
{
    te_string eps = TE_STRING_INIT;
    te_errno rc;
    size_t off = 0;
    char *rec;
    unsigned int seen = 0;

    rc = tapi_opcua_get_endpoints(rpcs, url, &eps);
    if (rc != 0)
    {
        tapi_opcua_report_add(report, TAPI_OPCUA_SEV_INFO,
                              "opcua.endpoint.not-assessed", url,
                              "could not read endpoints: %r", rc);
        te_string_free(&eps);
        return rc;
    }
    while ((rec = tapi_opcua_report_next(eps.ptr, &off)) != NULL)
    {
        tapi_opcua_kv kv = TAPI_OPCUA_KV_INIT;
        const char *policy;
        const char *mode;
        unsigned int i;

        seen++;
        tapi_opcua_kv_parse_record(rec, &kv);
        policy = tapi_opcua_kv_get(&kv, "security_policy");
        mode = tapi_opcua_kv_get(&kv, "security_mode");
        if (mode != NULL && strcmp(mode, "none") == 0)
            tapi_opcua_report_add(report,
                    require_secure ? TAPI_OPCUA_SEV_HIGH :
                    TAPI_OPCUA_SEV_MEDIUM,
                    "opcua.endpoint.mode-none", url,
                    "endpoint offers MessageSecurityMode None");
        if (policy != NULL && strcmp(policy, "none") == 0)
            tapi_opcua_report_add(report,
                    require_secure ? TAPI_OPCUA_SEV_HIGH :
                    TAPI_OPCUA_SEV_MEDIUM,
                    "opcua.endpoint.policy-none", url,
                    "endpoint offers SecurityPolicy None");
        /* A username token on an unencrypted endpoint sends the password
         * without protection. */
        for (i = 0; i < kv.n; i++)
        {
            if (strcmp(kv.keys[i], "token") == 0 &&
                strcmp(kv.vals[i], "username") == 0 &&
                mode != NULL && strcmp(mode, "signencrypt") != 0)
                tapi_opcua_report_add(report, TAPI_OPCUA_SEV_HIGH,
                        "opcua.endpoint.username-unencrypted", url,
                        "username token offered without encryption");
        }
        tapi_opcua_kv_free(&kv);
        free(rec);
    }
    if (seen == 0)
        tapi_opcua_report_add(report, TAPI_OPCUA_SEV_INFO,
                              "opcua.endpoint.not-assessed", url,
                              "no endpoints advertised");
    te_string_free(&eps);
    return rc;
}

te_errno
tapi_opcua_audit_anonymous(rcf_rpc_server *rpcs, const char *url,
                           const char *nodes, tapi_opcua_report *report)
{
    tapi_opcua_conn conn;
    tapi_opcua_connect_opt opt;
    tapi_opcua_value *values = NULL;
    size_t n = 0;
    size_t i;
    te_errno rc;

    memset(&opt, 0, sizeof(opt));
    opt.endpoint = url;
    opt.security_policy = "none";
    opt.security_mode = TAPI_OPCUA_MODE_NONE;
    opt.auth = "anonymous";
    rc = tapi_opcua_connect(rpcs, &opt, &conn);
    if (rc != 0)
    {
        /* Anonymous connect refused: that is the safe outcome, recorded
         * as info, not a finding. */
        tapi_opcua_report_add(report, TAPI_OPCUA_SEV_INFO,
                              "opcua.anonymous.refused", url,
                              "anonymous connection refused");
        return 0;
    }
    rc = tapi_opcua_read_many(&conn, nodes, &values, &n);
    for (i = 0; i < n; i++)
    {
        if (values[i].status == 0 /* Good */ &&
            values[i].type != TAPI_OPCUA_NULL)
            tapi_opcua_report_add(report, TAPI_OPCUA_SEV_HIGH,
                    "opcua.anonymous.read", url,
                    "protected data readable anonymously (value %s)",
                    values[i].raw != NULL ? values[i].raw : "");
        tapi_opcua_value_free(&values[i]);
    }
    free(values);
    tapi_opcua_disconnect(&conn);
    return rc;
}

te_errno
tapi_opcua_audit_unauthorized_write(tapi_opcua_conn *conn, const char *node,
                                    const char *value, bool restore,
                                    tapi_opcua_report *report)
{
    tapi_opcua_value before = { 0 };
    uint32_t status = 0xFFFFFFFF;
    te_errno rc;

    tapi_opcua_read(conn, node, &before);
    rc = tapi_opcua_write(conn, node, value, &status);
    if (rc == 0 && status == 0 /* Good */)
    {
        tapi_opcua_report_add(report, TAPI_OPCUA_SEV_CRITICAL,
                "opcua.write.unauthorized", node,
                "write accepted (StatusCode Good) by this identity");
        if (restore && before.raw != NULL && before.type != TAPI_OPCUA_NULL)
        {
            te_string orig = TE_STRING_INIT;

            te_string_append(&orig, "%s:%s", before.type_name, before.raw);
            tapi_opcua_write(conn, node, orig.ptr, NULL);
            te_string_free(&orig);
        }
    }
    tapi_opcua_value_free(&before);
    return 0;
}

te_errno
tapi_opcua_audit_bad_cert(rcf_rpc_server *rpcs, const char *url,
                          const char *cert, const char *key, const char *how,
                          tapi_opcua_report *report)
{
    tapi_opcua_conn conn;
    tapi_opcua_connect_opt opt;
    te_errno rc;

    memset(&opt, 0, sizeof(opt));
    opt.endpoint = url;
    opt.security_policy = "basic256sha256";
    opt.security_mode = TAPI_OPCUA_MODE_SIGN_ENCRYPT;
    opt.cert = cert;
    opt.key = key;
    rc = tapi_opcua_connect(rpcs, &opt, &conn);
    if (rc == 0 && tapi_opcua_is_connected(&conn))
    {
        tapi_opcua_report_add(report, TAPI_OPCUA_SEV_CRITICAL,
                "opcua.cert.accepted", url,
                "server accepted a %s certificate against policy", how);
        tapi_opcua_disconnect(&conn);
    }
    else
    {
        /* Rejection is the safe, expected result. */
        RING("bad-cert (%s) rejected as expected: fail=%d status=0x%08x",
             how, tapi_opcua_last_fail(&conn), tapi_opcua_last_status(&conn));
    }
    return 0;
}

/* ---- certificate helpers ------------------------------------------ */

te_errno
tapi_opcua_make_cert(rcf_rpc_server *rpcs, const char *cert_path,
                     const char *key_path, const char *params)
{
    te_string p = TE_STRING_INIT;
    tapi_opcua_rpc_args a = { 0 };
    tapi_opcua_rpc_res res = TAPI_OPCUA_RPC_RES_INIT;
    te_errno rc;

    te_string_append(&p, "cert=%s\nkey=%s\n", cert_path, key_path);
    if (params != NULL && *params != '\0')
        te_string_append(&p, "%s%s", params,
                         params[strlen(params) - 1] == '\n' ? "" : "\n");
    a.params = p.ptr;
    rc = rpc_opcua_call(rpcs, TAPI_OPCUA_OP_CERT_MAKE, &a, 0, &res);
    te_string_free(&p);
    tapi_opcua_rpc_res_free(&res);
    return rc;
}

te_errno
tapi_opcua_cert_info(rcf_rpc_server *rpcs, const char *path,
                     tapi_opcua_kv *info)
{
    tapi_opcua_rpc_args a = { 0 };
    tapi_opcua_rpc_res res = TAPI_OPCUA_RPC_RES_INIT;
    te_errno rc;

    a.arg = path;
    rc = rpc_opcua_call(rpcs, TAPI_OPCUA_OP_CERT_INFO, &a, 0, &res);
    if (info != NULL)
        tapi_opcua_kv_parse(res.result.ptr, info);
    tapi_opcua_rpc_res_free(&res);
    return rc;
}
