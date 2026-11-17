/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Interpretica, Unipessoal Lda. All rights reserved. */
/** @file
 * @brief Agent-side OPC UA operations: handle registries and TE adapter
 *
 * The live objects of the OPC UA engine - clients, subscriptions,
 * simulated servers - live here, in the RPC server process, each keyed
 * by a small integer handle. RPCs are synchronous, but the registries
 * are guarded by a mutex all the same, as several RPC server threads may
 * share the process. The iterate thread inside each client runs
 * independently of this lock.
 *
 * This file holds no OPC UA logic: it dispatches an operation to the
 * core (ta_opcua_core.h), resolves handles and maps return codes to
 * te_errno.
 */

#define TE_LGR_USER     "TA OPCUA"

#include "te_config.h"

#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#include "te_defs.h"
#include "te_errno.h"
#include "logger_api.h"

#include "ta_opcua.h"
#include "ta_opcua_core.h"

#define MAX_CLIENTS 128
#define MAX_SUBS    256
#define MAX_SERVERS 32

static pthread_mutex_t reg_lock = PTHREAD_MUTEX_INITIALIZER;

static ta_opcua_client *clients[MAX_CLIENTS + 1];
static ta_opcua_sub    *subs[MAX_SUBS + 1];
static ta_opcua_server *servers[MAX_SERVERS + 1];
static unsigned int n_clients;
static unsigned int n_subs;
static unsigned int n_servers;
static uint64_t n_ops;

static te_errno
map_rc(int rc)
{
    switch (rc)
    {
        case TA_OPCUA_OK: return 0;
        case TA_OPCUA_EINVAL: return TE_RC(TE_TA_UNIX, TE_EINVAL);
        case TA_OPCUA_ENOENT: return TE_RC(TE_TA_UNIX, TE_ENOENT);
        case TA_OPCUA_ENOMEM: return TE_RC(TE_TA_UNIX, TE_ENOMEM);
        case TA_OPCUA_ENOTSUP: return TE_RC(TE_TA_UNIX, TE_EOPNOTSUPP);
        case TA_OPCUA_ESTATUS: return TE_RC(TE_TA_UNIX, TE_EPROTO);
        case TA_OPCUA_ECONN: return TE_RC(TE_TA_UNIX, TE_ECONNREFUSED);
        case TA_OPCUA_ETIMEDOUT: return TE_RC(TE_TA_UNIX, TE_ETIMEDOUT);
        case TA_OPCUA_EBUSY: return TE_RC(TE_TA_UNIX, TE_EBUSY);
        default: return TE_RC(TE_TA_UNIX, TE_EFAIL);
    }
}

static char *
nn(char *s)
{
    return s != NULL ? s : strdup("");
}

/* Allocate a slot in a handle table; returns the 1-based index or 0. */
static int
slot_alloc(void **tab, int max)
{
    int i;

    for (i = 1; i <= max; i++)
    {
        if (tab[i] == NULL)
            return i;
    }
    return 0;
}

static ta_opcua_client *
client_get(int h)
{
    if (h < 1 || h > MAX_CLIENTS)
        return NULL;
    return clients[h];
}

static ta_opcua_sub *
sub_get(int h)
{
    if (h < 1 || h > MAX_SUBS)
        return NULL;
    return subs[h];
}

static ta_opcua_server *
server_get(int h)
{
    if (h < 1 || h > MAX_SERVERS)
        return NULL;
    return servers[h];
}

static void
stats(ta_opcua_out *out)
{
    char buf[128];

    snprintf(buf, sizeof(buf),
             "clients=%u\nsubscriptions=%u\nservers=%u\nops=%llu\n",
             n_clients, n_subs, n_servers, (unsigned long long)n_ops);
    out->result = strdup(buf);
}

te_errno
ta_opcua_rpc(ta_opcua_op op, int h1, int h2, const char *arg,
             const char *params, const char *data, int *handle,
             unsigned int *features, unsigned int *status, int *fail_cls,
             char **result, char **report, char **errmsg)
{
    ta_opcua_out out;
    ta_opcua_client *c = NULL;
    ta_opcua_sub *s = NULL;
    ta_opcua_server *srv = NULL;
    int rc = TA_OPCUA_OK;
    int slot;

    memset(&out, 0, sizeof(out));
    pthread_mutex_lock(&reg_lock);
    n_ops++;

    /* Resolve the handles the operation needs. */
    switch (op)
    {
        case TA_OPCUA_OP_DISCONNECT:
        case TA_OPCUA_OP_RECONNECT:
        case TA_OPCUA_OP_STATE:
        case TA_OPCUA_OP_WAIT_SESSION:
        case TA_OPCUA_OP_BROWSE:
        case TA_OPCUA_OP_BROWSE_NEXT:
        case TA_OPCUA_OP_TRANSLATE:
        case TA_OPCUA_OP_NODE_INFO:
        case TA_OPCUA_OP_NAMESPACES:
        case TA_OPCUA_OP_READ:
        case TA_OPCUA_OP_WRITE:
        case TA_OPCUA_OP_CALL:
        case TA_OPCUA_OP_METHOD_INFO:
        case TA_OPCUA_OP_SUB_CREATE:
        case TA_OPCUA_OP_PERF:
            c = client_get(h1);
            if (c == NULL)
            {
                rc = TA_OPCUA_EINVAL;
                out.errmsg = strdup("no such client handle");
            }
            break;
        case TA_OPCUA_OP_SUB_DELETE:
        case TA_OPCUA_OP_MONITOR:
        case TA_OPCUA_OP_UNMONITOR:
        case TA_OPCUA_OP_COLLECT:
            s = sub_get(h2);
            if (s == NULL)
            {
                rc = TA_OPCUA_EINVAL;
                out.errmsg = strdup("no such subscription handle");
            }
            break;
        case TA_OPCUA_OP_SERVER_STOP:
        case TA_OPCUA_OP_SERVER_ADD:
        case TA_OPCUA_OP_SERVER_SET:
        case TA_OPCUA_OP_SERVER_EVENT:
        case TA_OPCUA_OP_SERVER_INFO:
            srv = server_get(h1);
            if (srv == NULL)
            {
                rc = TA_OPCUA_EINVAL;
                out.errmsg = strdup("no such server handle");
            }
            break;
        default:
            break;
    }
    if (rc != TA_OPCUA_OK)
        goto done;

    switch (op)
    {
        case TA_OPCUA_OP_AVAILABLE:
            rc = ta_opcua_features(features, &out);
            break;

        case TA_OPCUA_OP_CONNECT:
            slot = slot_alloc((void **)clients, MAX_CLIENTS);
            if (slot == 0)
            {
                rc = TA_OPCUA_EBUSY;
                out.errmsg = strdup("too many clients");
                break;
            }
            rc = ta_opcua_client_connect(arg, params, &c, &out);
            if (rc == TA_OPCUA_OK)
            {
                clients[slot] = c;
                n_clients++;
                *handle = slot;
            }
            break;

        case TA_OPCUA_OP_DISCONNECT:
            for (slot = 1; slot <= MAX_CLIENTS; slot++)
                if (clients[slot] == c)
                    break;
            /* Unlock around the join: the iterate thread may need the
             * registry-independent locks, and free() can block. */
            clients[slot <= MAX_CLIENTS ? slot : 0] = NULL;
            if (slot <= MAX_CLIENTS)
                n_clients--;
            /* Delete any subscriptions that belonged to this client. */
            {
                int i;

                for (i = 1; i <= MAX_SUBS; i++)
                {
                    if (subs[i] != NULL &&
                        ta_opcua_sub_client(subs[i]) == c)
                    {
                        subs[i] = NULL;
                        n_subs--;
                    }
                }
            }
            pthread_mutex_unlock(&reg_lock);
            ta_opcua_client_free(c);
            pthread_mutex_lock(&reg_lock);
            break;

        case TA_OPCUA_OP_RECONNECT:
            rc = ta_opcua_client_reconnect(c, params, &out);
            break;
        case TA_OPCUA_OP_STATE:
            rc = ta_opcua_client_state(c, &out);
            break;
        case TA_OPCUA_OP_WAIT_SESSION:
            rc = ta_opcua_client_wait_session(c, params, &out);
            break;
        case TA_OPCUA_OP_GET_ENDPOINTS:
            rc = ta_opcua_get_endpoints(arg, params, &out);
            break;
        case TA_OPCUA_OP_FIND_SERVERS:
            rc = ta_opcua_find_servers(arg, params, &out);
            break;
        case TA_OPCUA_OP_BROWSE:
            rc = ta_opcua_browse(c, arg, params, &out);
            break;
        case TA_OPCUA_OP_BROWSE_NEXT:
            rc = ta_opcua_browse_next(c, arg, params, &out);
            break;
        case TA_OPCUA_OP_TRANSLATE:
            rc = ta_opcua_translate(c, arg, data, &out);
            break;
        case TA_OPCUA_OP_NODE_INFO:
            rc = ta_opcua_node_info(c, arg, params, &out);
            break;
        case TA_OPCUA_OP_NAMESPACES:
            rc = ta_opcua_namespaces(c, &out);
            break;
        case TA_OPCUA_OP_READ:
            rc = ta_opcua_read(c, data, params, &out);
            break;
        case TA_OPCUA_OP_WRITE:
            rc = ta_opcua_write(c, data, params, &out);
            break;
        case TA_OPCUA_OP_CALL:
            rc = ta_opcua_call(c, arg, params, data, &out);
            break;
        case TA_OPCUA_OP_METHOD_INFO:
            rc = ta_opcua_method_info(c, arg, &out);
            break;
        case TA_OPCUA_OP_PERF:
            rc = ta_opcua_perf(c, arg, params, data, &out);
            break;

        case TA_OPCUA_OP_SUB_CREATE:
            slot = slot_alloc((void **)subs, MAX_SUBS);
            if (slot == 0)
            {
                rc = TA_OPCUA_EBUSY;
                out.errmsg = strdup("too many subscriptions");
                break;
            }
            rc = ta_opcua_sub_create(c, params, &s, &out);
            if (rc == TA_OPCUA_OK)
            {
                subs[slot] = s;
                n_subs++;
                *handle = slot;
            }
            break;

        case TA_OPCUA_OP_SUB_DELETE:
            for (slot = 1; slot <= MAX_SUBS; slot++)
                if (subs[slot] == s)
                    break;
            if (slot <= MAX_SUBS)
            {
                subs[slot] = NULL;
                n_subs--;
            }
            rc = ta_opcua_sub_delete(s, &out);
            break;

        case TA_OPCUA_OP_MONITOR:
        {
            uint32_t item = 0;

            rc = ta_opcua_monitor(s, arg, params, &item, &out);
            if (rc == TA_OPCUA_OK)
                *handle = (int)item;
            break;
        }
        case TA_OPCUA_OP_UNMONITOR:
        {
            char *item_s = ta_opcua_opt(params, "item");

            rc = ta_opcua_unmonitor(s,
                    (uint32_t)(item_s != NULL ? strtoul(item_s, NULL, 0) : 0),
                    &out);
            free(item_s);
            break;
        }
        case TA_OPCUA_OP_COLLECT:
            rc = ta_opcua_collect(s, params, &out);
            break;

        case TA_OPCUA_OP_SERVER_START:
            slot = slot_alloc((void **)servers, MAX_SERVERS);
            if (slot == 0)
            {
                rc = TA_OPCUA_EBUSY;
                out.errmsg = strdup("too many servers");
                break;
            }
            rc = ta_opcua_server_start(params, &srv, &out);
            if (rc == TA_OPCUA_OK)
            {
                servers[slot] = srv;
                n_servers++;
                *handle = slot;
            }
            break;
        case TA_OPCUA_OP_SERVER_STOP:
            for (slot = 1; slot <= MAX_SERVERS; slot++)
                if (servers[slot] == srv)
                    break;
            if (slot <= MAX_SERVERS)
            {
                servers[slot] = NULL;
                n_servers--;
            }
            pthread_mutex_unlock(&reg_lock);
            ta_opcua_server_stop(srv);
            pthread_mutex_lock(&reg_lock);
            break;
        case TA_OPCUA_OP_SERVER_ADD:
            rc = ta_opcua_server_add(srv, params, &out);
            break;
        case TA_OPCUA_OP_SERVER_SET:
            rc = ta_opcua_server_set(srv, arg, data, &out);
            break;
        case TA_OPCUA_OP_SERVER_EVENT:
            rc = ta_opcua_server_event(srv, params, &out);
            break;
        case TA_OPCUA_OP_SERVER_INFO:
            rc = ta_opcua_server_info(srv, &out);
            break;

        case TA_OPCUA_OP_CERT_MAKE:
            rc = ta_opcua_cert_make(params, &out);
            break;
        case TA_OPCUA_OP_CERT_INFO:
            rc = ta_opcua_cert_info(arg, &out);
            break;
        case TA_OPCUA_OP_CRL_MAKE:
            rc = ta_opcua_crl_make(params, &out);
            break;

        case TA_OPCUA_OP_STATS:
            stats(&out);
            break;

        default:
            rc = TA_OPCUA_EINVAL;
            out.errmsg = strdup("unknown operation");
            break;
    }

done:
    *status = out.status;
    *fail_cls = out.cls;
    *result = nn(out.result);
    *report = nn(out.report);
    *errmsg = nn(out.errmsg);
    pthread_mutex_unlock(&reg_lock);
    return map_rc(rc);
}
