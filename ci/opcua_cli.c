/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Interpretica, Unipessoal Lda. All rights reserved. */
/** @file
 * @brief Standalone driver for the tsf-opcua core (no Test Environment)
 *
 * Builds against the ta_opcua core and open62541 only, so ci/ can start
 * a simulated server, drive a client against it under the sanitizers,
 * and check the result lines - the fast loop that proves the engine
 * before a full suite run. Usage:
 *
 *   opcua_cli features
 *   opcua_cli selftest          (server + client round trip)
 *
 * selftest exits non-zero on the first broken contract.
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "ta_opcua_core.h"

static void
dump(const char *tag, ta_opcua_out *o, int rc)
{
    fprintf(stderr, "%s: rc=%d status=0x%08x\n", tag, rc, o->status);
    if (o->result != NULL && *o->result != '\0')
        fprintf(stderr, "  result:\n%s", o->result);
    if (o->report != NULL && *o->report != '\0')
        fprintf(stderr, "  report:\n%s", o->report);
    if (o->errmsg != NULL && *o->errmsg != '\0')
        fprintf(stderr, "  err: %s\n", o->errmsg);
}

static int failures;

#define CHECK(_cond, ...) do {                                  \
    if (!(_cond)) {                                             \
        fprintf(stderr, "FAIL: ");                             \
        fprintf(stderr, __VA_ARGS__);                          \
        fprintf(stderr, "\n");                                 \
        failures++;                                            \
    } else {                                                   \
        fprintf(stderr, "ok: ");                              \
        fprintf(stderr, __VA_ARGS__);                          \
        fprintf(stderr, "\n");                                 \
    }                                                          \
} while (0)

/* First "key=value" field anywhere in @p text (fields are separated by
 * TAB or newline); returns a malloc'ed copy of the value or NULL. */
static char *
field(const char *text, const char *key)
{
    size_t klen = strlen(key);
    const char *p = text;

    while (p != NULL && *p != '\0')
    {
        bool at_start = p == text || p[-1] == '\n' || p[-1] == '\t';

        if (at_start && strncmp(p, key, klen) == 0 && p[klen] == '=')
        {
            const char *v = p + klen + 1;
            size_t n = strcspn(v, "\t\n");

            return strndup(v, n);
        }
        p++;
    }
    return NULL;
}

static int
count_records(const char *report)
{
    int n = 0;
    const char *p = report;

    while (p != NULL && *p != '\0')
    {
        n++;
        p = strchr(p, '\n');
        if (p != NULL)
            p++;
    }
    return n;
}

static int
cmd_features(void)
{
    ta_opcua_out o = { 0 };
    unsigned int f = 0;
    int rc = ta_opcua_features(&f, &o);

    printf("%s", o.result != NULL ? o.result : "");
    ta_opcua_out_clear(&o);
    return rc == 0 ? 0 : 1;
}

static int
cmd_selftest(void)
{
    ta_opcua_server *srv = NULL;
    ta_opcua_client *cli = NULL;
    ta_opcua_sub *sub = NULL;
    ta_opcua_out o = { 0 };
    char endpoint[128];
    char *epurl;
    char nodes[256];
    char writebuf[256];
    uint32_t item = 0;
    int rc;

    /* 1. Start the simulated server. */
    rc = ta_opcua_server_start("port=48401\nanonymous=1", &srv, &o);
    CHECK(rc == 0, "server starts");
    if (rc != 0)
    {
        dump("server_start", &o, rc);
        ta_opcua_out_clear(&o);
        return 1;
    }
    epurl = field(o.result, "endpoint_url");
    snprintf(endpoint, sizeof(endpoint), "%s",
             epurl != NULL ? epurl : "opc.tcp://localhost:48401");
    free(epurl);
    ta_opcua_out_clear(&o);

    rc = ta_opcua_server_add(srv,
            "kind=variable\nname=Temperature\nvalue=Double:21.5\naccess=rw",
            &o);
    CHECK(rc == 0, "add Temperature");
    ta_opcua_out_clear(&o);

    rc = ta_opcua_server_add(srv,
            "kind=method\nname=Sum\nbehaviour=sum", &o);
    CHECK(rc == 0, "add Sum method");
    ta_opcua_out_clear(&o);

    /* 2. Connect a client. */
    rc = ta_opcua_client_connect(endpoint,
            "security_policy=none\nrequest_timeout_ms=5000", &cli, &o);
    CHECK(rc == 0, "client connects");
    if (rc != 0)
    {
        dump("connect", &o, rc);
        ta_opcua_out_clear(&o);
        ta_opcua_server_stop(srv);
        return 1;
    }
    ta_opcua_out_clear(&o);

    rc = ta_opcua_client_wait_session(cli, "timeout_ms=5000", &o);
    CHECK(rc == 0, "session activates");
    ta_opcua_out_clear(&o);

    /* 3. Discovery: the endpoint we connected to is advertised. */
    rc = ta_opcua_get_endpoints(endpoint, "", &o);
    CHECK(rc == 0 && count_records(o.report) >= 1,
          "getEndpoints returns at least one endpoint");
    ta_opcua_out_clear(&o);

    /* 4. Read the variable we set. */
    snprintf(nodes, sizeof(nodes), "ns=2;s=Temperature");
    rc = ta_opcua_read(cli, nodes, "", &o);
    {
        char *v = o.report != NULL ? field(o.report, "value") : NULL;

        CHECK(rc == 0 && v != NULL && strcmp(v, "Double:21.5") == 0,
              "read Temperature == 21.5 (got %s)", v != NULL ? v : "(null)");
        free(v);
    }
    ta_opcua_out_clear(&o);

    /* 5. Browse the Objects folder: Temperature is there. */
    rc = ta_opcua_browse(cli, "i=85", "", &o);
    CHECK(rc == 0 && o.report != NULL && strstr(o.report, "Temperature") != NULL,
          "browse Objects shows Temperature");
    ta_opcua_out_clear(&o);

    /* 6. Write a new value and read it back. */
    snprintf(writebuf, sizeof(writebuf), "ns=2;s=Temperature\tDouble:30");
    rc = ta_opcua_write(cli, writebuf, "", &o);
    CHECK(rc == 0, "write Temperature");
    ta_opcua_out_clear(&o);
    rc = ta_opcua_read(cli, nodes, "", &o);
    {
        char *v = o.report != NULL ? field(o.report, "value") : NULL;

        CHECK(v != NULL && strcmp(v, "Double:30") == 0,
              "read back 30 (got %s)", v != NULL ? v : "(null)");
        free(v);
    }
    ta_opcua_out_clear(&o);

    /* 7. Call the Sum method. */
    rc = ta_opcua_call(cli, "ns=2;s=Sum", "object=i=85",
                       "Double:2\nDouble:3", &o);
    {
        char *v = o.report != NULL ? field(o.report, "value") : NULL;

        CHECK(rc == 0 && v != NULL && strcmp(v, "Double:5") == 0,
              "Sum(2,3) == 5 (got %s)", v != NULL ? v : "(null)");
        if (v == NULL || strcmp(v, "Double:5") != 0)
            dump("call", &o, rc);
        free(v);
    }
    ta_opcua_out_clear(&o);

    /* 8. Subscribe, monitor, collect the initial value. */
    rc = ta_opcua_sub_create(cli, "publishing_interval_ms=100", &sub, &o);
    CHECK(rc == 0, "subscription created");
    ta_opcua_out_clear(&o);

    if (sub != NULL)
    {
        rc = ta_opcua_monitor(sub, "ns=2;s=Temperature",
                              "sampling_interval_ms=100\nqueue_size=10",
                              &item, &o);
        CHECK(rc == 0, "monitored item created");
        ta_opcua_out_clear(&o);

        rc = ta_opcua_collect(sub, "min=1\ntimeout_ms=3000", &o);
        CHECK(rc == 0 && count_records(o.report) >= 1,
              "collect gets the initial data change");
        ta_opcua_out_clear(&o);

        /* Change the value on the server, collect the notification. */
        rc = ta_opcua_server_set(srv, "Temperature", "Double:42", &o);
        ta_opcua_out_clear(&o);
        rc = ta_opcua_collect(sub, "min=1\ntimeout_ms=3000", &o);
        {
            char *v = o.report != NULL ? field(o.report, "value") : NULL;

            CHECK(o.report != NULL && strstr(o.report, "Double:42") != NULL,
                  "value change delivered as a notification (got %s)",
                  v != NULL ? v : "(null)");
            free(v);
        }
        ta_opcua_out_clear(&o);

        rc = ta_opcua_sub_delete(sub, &o);
        ta_opcua_out_clear(&o);
    }

    ta_opcua_client_free(cli);
    ta_opcua_server_stop(srv);

    fprintf(stderr, "%d failure(s)\n", failures);
    return failures == 0 ? 0 : 1;
}

int
main(int argc, char **argv)
{
    if (argc < 2)
    {
        fprintf(stderr, "usage: %s features|selftest\n", argv[0]);
        return 2;
    }
    if (strcmp(argv[1], "features") == 0)
        return cmd_features();
    if (strcmp(argv[1], "selftest") == 0)
        return cmd_selftest();
    fprintf(stderr, "unknown command %s\n", argv[1]);
    return 2;
}
