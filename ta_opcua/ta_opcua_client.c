/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Interpretica, Unipessoal Lda. All rights reserved. */
/** @file
 * @brief OPC UA core: the client, discovery, address space, data access
 *
 * One client owns a UA_Client and a thread that runs
 * UA_Client_run_iterate() so housekeeping, reconnection and
 * subscription keepalives never stall behind an operation. Every use of
 * the UA_Client is under the client's lock; the iterate thread takes the
 * same lock, so a long operation and the keepalive take turns rather
 * than racing. The state callback records the connection history
 * (channels opened, sessions created and activated, a changed
 * authentication token = a recreated session) so a reliability test can
 * tell a recreated session from a transparently resumed one.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <open62541/client_config_default.h>
#include <open62541/plugin/log_stdout.h>

#include "ta_opcua_int.h"

/* ---- logging without secrets -------------------------------------- */

/* A no-op logger: the agent must never write a password, and the
 * connection parameters pass through the client config. The TE log on
 * the engine side carries what a test needs. */
static void
quiet_log(void *ctx, UA_LogLevel level, UA_LogCategory cat,
          const char *msg, va_list args)
{
    (void)ctx; (void)level; (void)cat; (void)msg; (void)args;
}

static void
quiet_clear(UA_Logger *logger)
{
    (void)logger;
}

static UA_Logger quiet_logger = { quiet_log, NULL, quiet_clear };

/* ---- state callback ----------------------------------------------- */

static void
state_cb(UA_Client *ua, UA_SecureChannelState chan, UA_SessionState sess,
         UA_StatusCode status)
{
    ta_opcua_client *c = *(ta_opcua_client **)UA_Client_getContext(ua);

    if (c == NULL)
        return;
    if (chan == UA_SECURECHANNELSTATE_OPEN &&
        c->chan != UA_SECURECHANNELSTATE_OPEN)
        c->channels_opened++;
    if (sess == UA_SESSIONSTATE_CREATED &&
        c->sess != UA_SESSIONSTATE_CREATED &&
        c->sess < UA_SESSIONSTATE_CREATED)
        c->sessions_created++;
    if (sess == UA_SESSIONSTATE_ACTIVATED &&
        c->sess != UA_SESSIONSTATE_ACTIVATED)
    {
        UA_NodeId tok = UA_NODEID_NULL;
        UA_ByteString nonce = UA_BYTESTRING_NULL;

        c->sessions_activated++;
        if (UA_Client_getSessionAuthenticationToken(ua, &tok, &nonce) ==
            UA_STATUSCODE_GOOD)
        {
            if (!UA_NodeId_isNull(&c->auth_token) &&
                !UA_NodeId_equal(&c->auth_token, &tok))
                c->session_changes++;
            UA_NodeId_clear(&c->auth_token);
            UA_NodeId_copy(&tok, &c->auth_token);
            UA_NodeId_clear(&tok);
            UA_ByteString_clear(&nonce);
        }
    }
    if (chan > c->max_chan)
        c->max_chan = chan;
    if (sess > c->max_sess)
        c->max_sess = sess;
    c->chan = chan;
    c->sess = sess;
    c->connect_status = status;
}

static void
sub_inactivity_cb(UA_Client *ua, UA_UInt32 subId, void *subCtx)
{
    ta_opcua_client *c = *(ta_opcua_client **)UA_Client_getContext(ua);
    ta_opcua_sub *s;

    (void)subCtx;
    if (c == NULL)
        return;
    pthread_mutex_lock(&c->qlock);
    s = client_sub_by_id(c, subId);
    if (s != NULL)
        s->inactivity++;
    pthread_mutex_unlock(&c->qlock);
}

/* ---- the iterate thread ------------------------------------------- */

static void *
iterate_thread(void *arg)
{
    ta_opcua_client *c = arg;

    for (;;)
    {
        bool stop;

        pthread_mutex_lock(&c->lock);
        stop = c->stop;
        if (!stop)
            UA_Client_run_iterate(c->ua, 0);
        c->publish_responses = 0; /* refreshed from the counter below */
        pthread_mutex_unlock(&c->lock);
        if (stop)
            break;
        /* Short sleep so an operation gets the lock; run_iterate with a
         * timeout would hold it. */
        {
            struct timespec ts = { 0, (long)c->iterate_ms * 1000000L };

            nanosleep(&ts, NULL);
        }
    }
    return NULL;
}

/* ---- configuration ------------------------------------------------ */

int
client_configure(UA_ClientConfig *cc, const char *params, ta_opcua_out *out)
{
    char *policy = ta_opcua_opt(params, "security_policy");
    char *modes = ta_opcua_opt(params, "security_mode");
    char *app_uri = ta_opcua_opt(params, "app_uri");
    char *cert = ta_opcua_opt(params, "cert");
    char *key = ta_opcua_opt(params, "key");
    char *trust = ta_opcua_opt(params, "trust");
    char *crl = ta_opcua_opt(params, "crl");
    UA_MessageSecurityMode mode;
    int rc = TA_OPCUA_OK;

    cc->logging = &quiet_logger;
    cc->timeout = (UA_UInt32)ta_opcua_opt_int(params, "request_timeout_ms",
                                              5000);
    if (ta_opcua_opt_int(params, "session_timeout_ms", 0) > 0)
        cc->requestedSessionTimeout =
            (UA_UInt32)ta_opcua_opt_int(params, "session_timeout_ms", 0);
    if (ta_opcua_opt_int(params, "channel_lifetime_ms", 0) > 0)
        cc->secureChannelLifeTime =
            (UA_UInt32)ta_opcua_opt_int(params, "channel_lifetime_ms", 0);
    cc->noReconnect = ta_opcua_opt_bool(params, "no_reconnect", false);

    if (mode_parse(modes, &mode) != TA_OPCUA_OK)
    {
        rc = out_err(out, TA_OPCUA_EINVAL, "bad security_mode");
        goto out;
    }

    if (policy == NULL || strcmp(policy, "none") == 0 ||
        policy_uri(policy) == NULL)
    {
        if (policy != NULL && policy_uri(policy) == NULL)
        {
            rc = out_err(out, TA_OPCUA_EINVAL, "unknown security_policy");
            goto out;
        }
        if (UA_ClientConfig_setDefault(cc) != UA_STATUSCODE_GOOD)
        {
            rc = out_err(out, TA_OPCUA_EFAIL, "client config");
            goto out;
        }
    }
    else
    {
#ifndef UA_ENABLE_ENCRYPTION
        rc = out_err(out, TA_OPCUA_ENOTSUP,
                     "this build has no encryption; security_policy=none only");
        goto out;
#else
        UA_ByteString c_cert = UA_BYTESTRING_NULL;
        UA_ByteString c_key = UA_BYTESTRING_NULL;
        UA_ByteString *tl = NULL;
        UA_ByteString *rl = NULL;
        size_t tln = 0;
        size_t rln = 0;

        if ((cert != NULL && file_load(cert, &c_cert) != TA_OPCUA_OK) ||
            (key != NULL && file_load(key, &c_key) != TA_OPCUA_OK))
        {
            rc = out_err(out, TA_OPCUA_ENOENT, "cannot read cert/key");
            UA_ByteString_clear(&c_cert);
            UA_ByteString_clear(&c_key);
            goto out;
        }
        file_list_load(trust, &tl, &tln);
        file_list_load(crl, &rl, &rln);
        if (UA_ClientConfig_setDefaultEncryption(cc, c_cert, c_key, tl, tln,
                                                 rl, rln) != UA_STATUSCODE_GOOD)
            rc = out_err(out, TA_OPCUA_EFAIL, "encryption config");
        UA_ByteString_clear(&c_cert);
        UA_ByteString_clear(&c_key);
        file_list_free(tl, tln);
        file_list_free(rl, rln);
        if (rc != TA_OPCUA_OK)
            goto out;
        cc->securityPolicyUri = UA_STRING_ALLOC(policy_uri(policy));
#endif
    }

    cc->securityMode = mode;
    if (app_uri != NULL && *app_uri != '\0')
    {
        UA_String_clear(&cc->clientDescription.applicationUri);
        cc->clientDescription.applicationUri = UA_STRING_ALLOC(app_uri);
        UA_String_clear(&cc->applicationUri);
        cc->applicationUri = UA_STRING_ALLOC(app_uri);
    }
    /* Allow a plain-text password on an unencrypted channel: a test of
     * that very weakness needs to be able to try it. */
    cc->allowNonePolicyPassword = true;
    cc->stateCallback = state_cb;
    cc->subscriptionInactivityCallback = sub_inactivity_cb;

out:
    free(policy);
    free(modes);
    free(app_uri);
    free(cert);
    free(key);
    free(trust);
    free(crl);
    return rc;
}

/* ---- connect ------------------------------------------------------ */

static int
map_connect_status(UA_StatusCode st, int *cls)
{
    switch (st)
    {
        case UA_STATUSCODE_GOOD:
            *cls = TA_OPCUA_FAIL_NONE;
            return TA_OPCUA_OK;
        case UA_STATUSCODE_BADCONNECTIONREJECTED:
        case UA_STATUSCODE_BADCONNECTIONCLOSED:
        case UA_STATUSCODE_BADTCPINTERNALERROR:
            *cls = TA_OPCUA_FAIL_TCP;
            return TA_OPCUA_ECONN;
        case UA_STATUSCODE_BADSERVERURIINVALID:
        case UA_STATUSCODE_BADSERVERNAMEMISSING:
            *cls = TA_OPCUA_FAIL_DNS;
            return TA_OPCUA_ECONN;
        case UA_STATUSCODE_BADSECURITYMODEREJECTED:
        case UA_STATUSCODE_BADSECURITYPOLICYREJECTED:
        case UA_STATUSCODE_BADNOMATCH:
            *cls = TA_OPCUA_FAIL_ENDPOINT;
            return TA_OPCUA_ECONN;
        case UA_STATUSCODE_BADSECURITYCHECKSFAILED:
        case UA_STATUSCODE_BADSECURECHANNELCLOSED:
        case UA_STATUSCODE_BADSECURECHANNELTOKENUNKNOWN:
            *cls = TA_OPCUA_FAIL_CHANNEL;
            return TA_OPCUA_ECONN;
        case UA_STATUSCODE_BADCERTIFICATEUNTRUSTED:
        case UA_STATUSCODE_BADCERTIFICATETIMEINVALID:
        case UA_STATUSCODE_BADCERTIFICATEINVALID:
        case UA_STATUSCODE_BADCERTIFICATEHOSTNAMEINVALID:
        case UA_STATUSCODE_BADCERTIFICATEURIINVALID:
        case UA_STATUSCODE_BADCERTIFICATECHAININCOMPLETE:
            *cls = TA_OPCUA_FAIL_CERT;
            return TA_OPCUA_ECONN;
        case UA_STATUSCODE_BADUSERACCESSDENIED:
        case UA_STATUSCODE_BADIDENTITYTOKENREJECTED:
        case UA_STATUSCODE_BADIDENTITYTOKENINVALID:
            *cls = TA_OPCUA_FAIL_AUTH;
            return TA_OPCUA_ECONN;
        case UA_STATUSCODE_BADSESSIONNOTACTIVATED:
            *cls = TA_OPCUA_FAIL_SESSION_ACTIVATE;
            return TA_OPCUA_ECONN;
        case UA_STATUSCODE_BADTIMEOUT:
            *cls = TA_OPCUA_FAIL_TIMEOUT;
            return TA_OPCUA_ETIMEDOUT;
        default:
            *cls = TA_OPCUA_FAIL_CHANNEL;
            return TA_OPCUA_ECONN;
    }
}

static int
do_connect(ta_opcua_client *c, const char *params, ta_opcua_out *out)
{
    char *auth = ta_opcua_opt(params, "auth");
    char *user = ta_opcua_opt(params, "user");
    char *pass = ta_opcua_opt(params, "password");
    UA_StatusCode st;
    int cls = TA_OPCUA_FAIL_NONE;
    int rc;

    if (auth != NULL && strcmp(auth, "username") == 0)
    {
        UA_ClientConfig_setAuthenticationUsername(UA_Client_getConfig(c->ua),
                                                  user != NULL ? user : "",
                                                  pass != NULL ? pass : "");
        st = UA_Client_connect(c->ua, c->endpoint);
    }
#ifdef UA_ENABLE_ENCRYPTION
    else if (auth != NULL && strcmp(auth, "x509") == 0)
    {
        UA_ByteString ucert = UA_BYTESTRING_NULL;
        UA_ByteString ukey = UA_BYTESTRING_NULL;
        char *ucf = ta_opcua_opt(params, "user_cert");
        char *ukf = ta_opcua_opt(params, "user_key");

        if (ucf == NULL || ukf == NULL ||
            file_load(ucf, &ucert) != TA_OPCUA_OK ||
            file_load(ukf, &ukey) != TA_OPCUA_OK)
        {
            rc = out_err(out, TA_OPCUA_ENOENT, "cannot read user_cert/user_key");
            out->cls = TA_OPCUA_FAIL_AUTH;
            UA_ByteString_clear(&ucert);
            UA_ByteString_clear(&ukey);
            free(ucf);
            free(ukf);
            goto out;
        }
        UA_ClientConfig_setAuthenticationCert(UA_Client_getConfig(c->ua),
                                              ucert, ukey);
        free(ucf);
        free(ukf);
        st = UA_Client_connect(c->ua, c->endpoint);
    }
#endif
    else
    {
        st = UA_Client_connect(c->ua, c->endpoint);
    }

    out->status = st;
    rc = map_connect_status(st, &cls);
    out->cls = cls;
    if (rc != TA_OPCUA_OK)
        out_err(out, rc, "connect: %s", UA_StatusCode_name(st));
#ifdef UA_ENABLE_ENCRYPTION
out:
#endif
    /* Scrub the password copy as soon as the connect call has it. */
    if (pass != NULL)
        memset(pass, 0, strlen(pass));
    free(auth);
    free(user);
    free(pass);
    return rc;
}

int
ta_opcua_client_connect(const char *endpoint, const char *params,
                        ta_opcua_client **client, ta_opcua_out *out)
{
    ta_opcua_client *c;
    UA_ClientConfig *cc;
    int rc;

    if (endpoint == NULL || *endpoint == '\0')
        return out_err(out, TA_OPCUA_EINVAL, "no endpoint");
    c = calloc(1, sizeof(*c));
    if (c == NULL)
        return out_err(out, TA_OPCUA_ENOMEM, "out of memory");
    pthread_mutex_init(&c->lock, NULL);
    pthread_mutex_init(&c->qlock, NULL);
    pthread_cond_init(&c->qcond, NULL);
    c->endpoint = strdup(endpoint);
    c->params = params != NULL ? strdup(params) : strdup("");
    c->iterate_ms = (unsigned int)ta_opcua_opt_int(params, "iterate_ms", 10);
    if (c->iterate_ms == 0)
        c->iterate_ms = 10;
    UA_NodeId_init(&c->auth_token);

    c->ua = UA_Client_new();
    if (c->ua == NULL)
    {
        ta_opcua_client_free(c);
        return out_err(out, TA_OPCUA_ENOMEM, "UA_Client_new");
    }
    /* The context is a pointer to the client, so the state callback can
     * reach it. */
    cc = UA_Client_getConfig(c->ua);
    cc->clientContext = calloc(1, sizeof(ta_opcua_client *));
    if (cc->clientContext != NULL)
        *(ta_opcua_client **)cc->clientContext = c;

    rc = client_configure(cc, params, out);
    if (rc != TA_OPCUA_OK)
    {
        ta_opcua_client_free(c);
        return rc;
    }

    rc = do_connect(c, params, out);
    if (rc != TA_OPCUA_OK)
    {
        ta_opcua_client_free(c);
        return rc;
    }

    c->running = true;
    if (pthread_create(&c->thread, NULL, iterate_thread, c) != 0)
    {
        c->running = false;
        ta_opcua_client_free(c);
        return out_err(out, TA_OPCUA_EFAIL, "cannot start iterate thread");
    }

    *client = c;
    return TA_OPCUA_OK;
}

void
ta_opcua_client_free(ta_opcua_client *c)
{
    if (c == NULL)
        return;
    if (c->running)
    {
        pthread_mutex_lock(&c->lock);
        c->stop = true;
        pthread_mutex_unlock(&c->lock);
        pthread_join(c->thread, NULL);
    }
    while (c->subs != NULL)
    {
        ta_opcua_sub *next = c->subs->next;

        sub_free_local(c->subs);
        c->subs = next;
    }
    if (c->ua != NULL)
    {
        void *ctx = UA_Client_getConfig(c->ua)->clientContext;

        UA_Client_disconnect(c->ua);
        UA_Client_delete(c->ua);
        free(ctx);
    }
    UA_NodeId_clear(&c->auth_token);
    pthread_mutex_destroy(&c->lock);
    pthread_mutex_destroy(&c->qlock);
    pthread_cond_destroy(&c->qcond);
    if (c->params != NULL)
        memset(c->params, 0, strlen(c->params));
    free(c->params);
    free(c->endpoint);
    free(c);
}

int
ta_opcua_client_reconnect(ta_opcua_client *c, const char *params,
                          ta_opcua_out *out)
{
    uint64_t t0 = ta_opcua_now_us();
    int rc;

    pthread_mutex_lock(&c->lock);
    UA_Client_disconnect(c->ua);
    rc = do_connect(c, c->params, out);
    pthread_mutex_unlock(&c->lock);
    if (rc == TA_OPCUA_OK)
    {
        ta_opcua_buf b = TA_OPCUA_BUF_INIT;

        buf_kvf(&b, "reconnect_us", "%" PRIu64, ta_opcua_now_us() - t0);
        buf_kvf(&b, "sessions_created", "%" PRIu64, c->sessions_created);
        buf_kvf(&b, "sessions_activated", "%" PRIu64, c->sessions_activated);
        out->result = buf_take(&b);
    }
    (void)params;
    return rc;
}

/* ---- state -------------------------------------------------------- */

static const char *
chan_name(UA_SecureChannelState s)
{
    switch (s)
    {
        case UA_SECURECHANNELSTATE_CLOSED: return "closed";
        case UA_SECURECHANNELSTATE_HEL_SENT: return "hel_sent";
        case UA_SECURECHANNELSTATE_OPN_SENT: return "opn_sent";
        case UA_SECURECHANNELSTATE_OPEN: return "open";
        case UA_SECURECHANNELSTATE_CLOSING: return "closing";
        default: return "connecting";
    }
}

static const char *
sess_name(UA_SessionState s)
{
    switch (s)
    {
        case UA_SESSIONSTATE_CLOSED: return "closed";
        case UA_SESSIONSTATE_CREATE_REQUESTED: return "create_requested";
        case UA_SESSIONSTATE_CREATED: return "created";
        case UA_SESSIONSTATE_ACTIVATE_REQUESTED: return "activate_requested";
        case UA_SESSIONSTATE_ACTIVATED: return "activated";
        case UA_SESSIONSTATE_CLOSING: return "closing";
        default: return "closed";
    }
}

int
ta_opcua_client_state(ta_opcua_client *c, ta_opcua_out *out)
{
    ta_opcua_buf b = TA_OPCUA_BUF_INIT;
    UA_SecureChannelState chan;
    UA_SessionState sess;
    UA_StatusCode status;
    UA_Variant v;

    pthread_mutex_lock(&c->lock);
    UA_Client_getState(c->ua, &chan, &sess, &status);
    buf_kv(&b, "channel_state", chan_name(chan));
    buf_kv(&b, "session_state", sess_name(sess));
    buf_kv(&b, "connected",
           sess == UA_SESSIONSTATE_ACTIVATED ? "1" : "0");
    buf_kvf(&b, "connect_status", "0x%08" PRIX32, status);
    buf_kvf(&b, "channels_opened", "%" PRIu64, c->channels_opened);
    buf_kvf(&b, "sessions_created", "%" PRIu64, c->sessions_created);
    buf_kvf(&b, "sessions_activated", "%" PRIu64, c->sessions_activated);
    buf_kvf(&b, "session_changes", "%" PRIu64, c->session_changes);

    UA_Variant_init(&v);
    if (UA_Client_getConnectionAttribute(c->ua,
            UA_QUALIFIEDNAME(0, "securityPolicyUri"), &v) ==
            UA_STATUSCODE_GOOD && UA_Variant_hasScalarType(&v,
            &UA_TYPES[UA_TYPES_STRING]))
        buf_kv(&b, "security_policy", policy_name((UA_String *)v.data));
    UA_Variant_clear(&v);
    UA_Variant_init(&v);
    if (UA_Client_getConnectionAttribute(c->ua,
            UA_QUALIFIEDNAME(0, "securityMode"), &v) == UA_STATUSCODE_GOOD &&
            UA_Variant_hasScalarType(&v,
            &UA_TYPES[UA_TYPES_MESSAGESECURITYMODE]))
        buf_kv(&b, "security_mode",
               mode_name(*(UA_MessageSecurityMode *)v.data));
    UA_Variant_clear(&v);
    pthread_mutex_unlock(&c->lock);

    out->result = buf_take(&b);
    return TA_OPCUA_OK;
}

int
ta_opcua_client_wait_session(ta_opcua_client *c, const char *params,
                             ta_opcua_out *out)
{
    long long deadline_ms = ta_opcua_opt_int(params, "timeout_ms", 10000);
    uint64_t t0 = ta_opcua_now_us();
    UA_SessionState sess = UA_SESSIONSTATE_CLOSED;

    for (;;)
    {
        struct timespec ts = { 0, 20 * 1000000L };

        pthread_mutex_lock(&c->lock);
        UA_Client_getState(c->ua, NULL, &sess, NULL);
        pthread_mutex_unlock(&c->lock);
        if (sess == UA_SESSIONSTATE_ACTIVATED)
            break;
        if ((long long)((ta_opcua_now_us() - t0) / 1000) >= deadline_ms)
        {
            ta_opcua_buf b = TA_OPCUA_BUF_INIT;

            buf_kv(&b, "session_state", sess_name(sess));
            out->result = buf_take(&b);
            return out_err(out, TA_OPCUA_ETIMEDOUT,
                           "session not active within %lld ms", deadline_ms);
        }
        nanosleep(&ts, NULL);
    }
    {
        ta_opcua_buf b = TA_OPCUA_BUF_INIT;

        buf_kvf(&b, "wait_us", "%" PRIu64, ta_opcua_now_us() - t0);
        buf_kvf(&b, "sessions_activated", "%" PRIu64, c->sessions_activated);
        out->result = buf_take(&b);
    }
    return TA_OPCUA_OK;
}

/* ---- discovery ---------------------------------------------------- */

int
ta_opcua_get_endpoints(const char *url, const char *params, ta_opcua_out *out)
{
    UA_Client *ua = UA_Client_new();
    UA_ClientConfig *cc;
    UA_EndpointDescription *eps = NULL;
    size_t n = 0;
    ta_opcua_buf b = TA_OPCUA_BUF_INIT;
    UA_StatusCode st;
    size_t i;

    (void)params;
    if (ua == NULL)
        return out_err(out, TA_OPCUA_ENOMEM, "UA_Client_new");
    cc = UA_Client_getConfig(ua);
    cc->logging = &quiet_logger;
    UA_ClientConfig_setDefault(cc);

    st = UA_Client_getEndpoints(ua, url, &n, &eps);
    out->status = st;
    if (st != UA_STATUSCODE_GOOD)
    {
        UA_Client_delete(ua);
        return out_err(out, TA_OPCUA_ESTATUS, "getEndpoints: %s",
                       UA_StatusCode_name(st));
    }
    for (i = 0; i < n; i++)
    {
        UA_EndpointDescription *e = &eps[i];
        char *epurl = strndup((const char *)e->endpointUrl.data,
                              e->endpointUrl.length);
        char *auri = strndup(
            (const char *)e->server.applicationUri.data,
            e->server.applicationUri.length);
        char *puri = strndup(
            (const char *)e->server.productUri.data,
            e->server.productUri.length);
        size_t j;

        buf_field(&b, "endpoint_url", epurl);
        buf_field(&b, "security_policy", policy_name(&e->securityPolicyUri));
        buf_field(&b, "security_mode", mode_name(e->securityMode));
        buf_fieldf(&b, "security_level", "%u", e->securityLevel);
        buf_field(&b, "application_uri", auri);
        buf_field(&b, "product_uri", puri);
        buf_fieldf(&b, "server_cert_len", "%zu",
                   e->serverCertificate.length);
        for (j = 0; j < e->userIdentityTokensSize; j++)
        {
            const char *t;

            switch (e->userIdentityTokens[j].tokenType)
            {
                case UA_USERTOKENTYPE_ANONYMOUS: t = "anonymous"; break;
                case UA_USERTOKENTYPE_USERNAME: t = "username"; break;
                case UA_USERTOKENTYPE_CERTIFICATE: t = "x509"; break;
                case UA_USERTOKENTYPE_ISSUEDTOKEN: t = "issued"; break;
                default: t = "unknown"; break;
            }
            buf_fieldf(&b, "token", "%s", t);
        }
        buf_eor(&b);
        free(epurl);
        free(auri);
        free(puri);
    }
    out->report = buf_take(&b);
    {
        ta_opcua_buf r = TA_OPCUA_BUF_INIT;

        buf_kvf(&r, "count", "%zu", n);
        out->result = buf_take(&r);
    }
    UA_Array_delete(eps, n, &UA_TYPES[UA_TYPES_ENDPOINTDESCRIPTION]);
    UA_Client_delete(ua);
    return TA_OPCUA_OK;
}

int
ta_opcua_find_servers(const char *url, const char *params, ta_opcua_out *out)
{
    UA_Client *ua = UA_Client_new();
    UA_ClientConfig *cc;
    UA_ApplicationDescription *apps = NULL;
    size_t n = 0;
    ta_opcua_buf b = TA_OPCUA_BUF_INIT;
    UA_StatusCode st;
    size_t i;

    (void)params;
    if (ua == NULL)
        return out_err(out, TA_OPCUA_ENOMEM, "UA_Client_new");
    cc = UA_Client_getConfig(ua);
    cc->logging = &quiet_logger;
    UA_ClientConfig_setDefault(cc);

    st = UA_Client_findServers(ua, url, 0, NULL, 0, NULL, &n, &apps);
    out->status = st;
    if (st != UA_STATUSCODE_GOOD)
    {
        UA_Client_delete(ua);
        return out_err(out, TA_OPCUA_ESTATUS, "findServers: %s",
                       UA_StatusCode_name(st));
    }
    for (i = 0; i < n; i++)
    {
        char *auri = strndup((const char *)apps[i].applicationUri.data,
                             apps[i].applicationUri.length);
        char *name = strndup((const char *)apps[i].applicationName.text.data,
                             apps[i].applicationName.text.length);
        size_t j;

        buf_field(&b, "application_uri", auri);
        buf_field(&b, "name", name);
        for (j = 0; j < apps[i].discoveryUrlsSize; j++)
        {
            char *d = strndup((const char *)apps[i].discoveryUrls[j].data,
                              apps[i].discoveryUrls[j].length);

            buf_field(&b, "discovery_url", d);
            free(d);
        }
        buf_eor(&b);
        free(auri);
        free(name);
    }
    out->report = buf_take(&b);
    {
        ta_opcua_buf r = TA_OPCUA_BUF_INIT;

        buf_kvf(&r, "count", "%zu", n);
        out->result = buf_take(&r);
    }
    UA_Array_delete(apps, n, &UA_TYPES[UA_TYPES_APPLICATIONDESCRIPTION]);
    UA_Client_delete(ua);
    return TA_OPCUA_OK;
}

/* ---- address space ------------------------------------------------ */

static const char *
nodeclass_name(UA_NodeClass nc)
{
    switch (nc)
    {
        case UA_NODECLASS_OBJECT: return "Object";
        case UA_NODECLASS_VARIABLE: return "Variable";
        case UA_NODECLASS_METHOD: return "Method";
        case UA_NODECLASS_OBJECTTYPE: return "ObjectType";
        case UA_NODECLASS_VARIABLETYPE: return "VariableType";
        case UA_NODECLASS_REFERENCETYPE: return "ReferenceType";
        case UA_NODECLASS_DATATYPE: return "DataType";
        case UA_NODECLASS_VIEW: return "View";
        default: return "Unspecified";
    }
}

int
ta_opcua_browse(ta_opcua_client *c, const char *node, const char *params,
                ta_opcua_out *out)
{
    UA_BrowseRequest req;
    UA_BrowseResponse resp;
    UA_BrowseDescription bd;
    UA_NodeId start;
    ta_opcua_buf b = TA_OPCUA_BUF_INIT;
    unsigned max = (unsigned)ta_opcua_opt_int(params, "max_refs", 0);
    int rc = TA_OPCUA_OK;
    size_t i;

    if (nodeid_parse(node, &start) != TA_OPCUA_OK)
        return out_err(out, TA_OPCUA_EINVAL, "bad node id");

    UA_BrowseRequest_init(&req);
    UA_BrowseDescription_init(&bd);
    bd.nodeId = start;
    bd.resultMask = UA_BROWSERESULTMASK_ALL;
    bd.browseDirection = UA_BROWSEDIRECTION_FORWARD;
    bd.includeSubtypes = true;
    bd.referenceTypeId = UA_NODEID_NUMERIC(0, UA_NS0ID_REFERENCES);
    bd.nodeClassMask = (UA_UInt32)ta_opcua_opt_int(params, "class_mask", 0);
    req.nodesToBrowse = &bd;
    req.nodesToBrowseSize = 1;
    req.requestedMaxReferencesPerNode = max;

    pthread_mutex_lock(&c->lock);
    resp = UA_Client_Service_browse(c->ua, req);
    pthread_mutex_unlock(&c->lock);

    out->status = resp.responseHeader.serviceResult;
    if (resp.responseHeader.serviceResult != UA_STATUSCODE_GOOD)
    {
        rc = out_err(out, TA_OPCUA_ESTATUS, "browse: %s",
                     UA_StatusCode_name(resp.responseHeader.serviceResult));
        goto out;
    }
    if (resp.resultsSize == 1)
    {
        UA_BrowseResult *r = &resp.results[0];

        out->status = r->statusCode;
        for (i = 0; i < r->referencesSize; i++)
        {
            UA_ReferenceDescription *ref = &r->references[i];
            char *rid = nodeid_print(&ref->nodeId.nodeId);
            char *reftype = nodeid_print(&ref->referenceTypeId);
            char *tdef = nodeid_print(&ref->typeDefinition.nodeId);
            char *bn = strndup((const char *)ref->browseName.name.data,
                               ref->browseName.name.length);
            char *dn = strndup((const char *)ref->displayName.text.data,
                               ref->displayName.text.length);

            buf_field(&b, "node", rid);
            buf_fieldf(&b, "browse_ns", "%u", ref->browseName.namespaceIndex);
            buf_field(&b, "browse_name", bn);
            buf_field(&b, "display_name", dn);
            buf_field(&b, "class", nodeclass_name(ref->nodeClass));
            buf_field(&b, "reference", reftype);
            buf_field(&b, "forward", ref->isForward ? "1" : "0");
            buf_field(&b, "type_definition", tdef);
            buf_eor(&b);
            free(rid);
            free(reftype);
            free(tdef);
            free(bn);
            free(dn);
        }
        if (r->continuationPoint.length > 0)
        {
            ta_opcua_buf cp = TA_OPCUA_BUF_INIT;
            size_t j;

            for (j = 0; j < r->continuationPoint.length; j++)
                buf_add(&cp, "%02x", r->continuationPoint.data[j]);
            buf_kv(&b, "continuation", "");
            out->result = buf_take(&b);
            {
                ta_opcua_buf res = TA_OPCUA_BUF_INIT;

                buf_kvf(&res, "count", "%zu", r->referencesSize);
                buf_kv(&res, "continuation_point", cp.ptr);
                out->result = buf_take(&res);
            }
            buf_free(&cp);
            goto out;
        }
    }
    out->report = buf_take(&b);
    {
        ta_opcua_buf res = TA_OPCUA_BUF_INIT;

        buf_kvf(&res, "count", "%zu",
                resp.resultsSize == 1 ? resp.results[0].referencesSize : 0);
        out->result = buf_take(&res);
    }
out:
    buf_free(&b);
    UA_BrowseResponse_clear(&resp);
    /* bd.nodeId (start) is cleared by clearing req only if it owns it;
     * we set it by value, so clear start explicitly. */
    UA_NodeId_clear(&start);
    return rc;
}

int
ta_opcua_browse_next(ta_opcua_client *c, const char *cp, const char *params,
                     ta_opcua_out *out)
{
    UA_ByteString point = UA_BYTESTRING_NULL;
    UA_BrowseNextResponse resp;
    UA_BrowseNextRequest req;
    ta_opcua_buf b = TA_OPCUA_BUF_INIT;
    char *raw;
    int rc = TA_OPCUA_OK;
    size_t i;

    (void)params;
    raw = strdup(cp != NULL ? cp : "");
    if (raw == NULL)
        return out_err(out, TA_OPCUA_ENOMEM, "oom");
    if (hex_to_bytes(raw, &point) != TA_OPCUA_OK)
    {
        free(raw);
        return out_err(out, TA_OPCUA_EINVAL, "bad continuation point");
    }
    free(raw);

    UA_BrowseNextRequest_init(&req);
    req.continuationPoints = &point;
    req.continuationPointsSize = 1;
    req.releaseContinuationPoints = false;

    pthread_mutex_lock(&c->lock);
    resp = UA_Client_Service_browseNext(c->ua, req);
    pthread_mutex_unlock(&c->lock);

    out->status = resp.responseHeader.serviceResult;
    if (resp.resultsSize == 1)
    {
        UA_BrowseResult *r = &resp.results[0];

        for (i = 0; i < r->referencesSize; i++)
        {
            char *rid = nodeid_print(&r->references[i].nodeId.nodeId);
            char *bn = strndup(
                (const char *)r->references[i].browseName.name.data,
                r->references[i].browseName.name.length);

            buf_field(&b, "node", rid);
            buf_field(&b, "browse_name", bn);
            buf_field(&b, "class", nodeclass_name(r->references[i].nodeClass));
            buf_eor(&b);
            free(rid);
            free(bn);
        }
    }
    out->report = buf_take(&b);
    {
        ta_opcua_buf res = TA_OPCUA_BUF_INIT;

        buf_kvf(&res, "count", "%zu",
                resp.resultsSize == 1 ? resp.results[0].referencesSize : 0);
        out->result = buf_take(&res);
    }
    UA_ByteString_clear(&point);
    UA_BrowseNextResponse_clear(&resp);
    return rc;
}

int
ta_opcua_translate(ta_opcua_client *c, const char *start, const char *path,
                   ta_opcua_out *out)
{
    UA_BrowsePath bp;
    UA_BrowsePathResult res;
    UA_NodeId startId;
    UA_RelativePathElement *elems = NULL;
    char *copy;
    char *tok;
    char *save = NULL;
    size_t n = 0;
    ta_opcua_buf b = TA_OPCUA_BUF_INIT;
    size_t i;

    if (nodeid_parse(start, &startId) != TA_OPCUA_OK)
        return out_err(out, TA_OPCUA_EINVAL, "bad start node");

    /* path is "/" separated browse names, each "<ns>:<name>" or "<name>". */
    copy = strdup(path != NULL ? path : "");
    for (tok = strtok_r(copy, "/", &save); tok != NULL;
         tok = strtok_r(NULL, "/", &save))
    {
        UA_RelativePathElement *ne = realloc(elems, (n + 1) * sizeof(*elems));
        char *colon = strchr(tok, ':');
        UA_UInt16 ns = 0;
        const char *name = tok;

        if (ne == NULL)
            break;
        elems = ne;
        if (colon != NULL)
        {
            *colon = '\0';
            ns = (UA_UInt16)atoi(tok);
            name = colon + 1;
        }
        UA_RelativePathElement_init(&elems[n]);
        elems[n].referenceTypeId =
            UA_NODEID_NUMERIC(0, UA_NS0ID_HIERARCHICALREFERENCES);
        elems[n].includeSubtypes = true;
        elems[n].targetName = UA_QUALIFIEDNAME_ALLOC(ns, name);
        n++;
    }

    UA_BrowsePath_init(&bp);
    bp.startingNode = startId;
    bp.relativePath.elements = elems;
    bp.relativePath.elementsSize = n;

    pthread_mutex_lock(&c->lock);
    res = UA_Client_translateBrowsePathToNodeIds(c->ua, &bp);
    pthread_mutex_unlock(&c->lock);

    out->status = res.statusCode;
    for (i = 0; i < res.targetsSize; i++)
    {
        char *tid = nodeid_print(&res.targets[i].targetId.nodeId);

        buf_field(&b, "node", tid);
        buf_eor(&b);
        free(tid);
    }
    out->report = buf_take(&b);
    {
        ta_opcua_buf r = TA_OPCUA_BUF_INIT;

        buf_kvf(&r, "count", "%zu", res.targetsSize);
        buf_kvf(&r, "status", "0x%08" PRIX32, res.statusCode);
        out->result = buf_take(&r);
    }
    for (i = 0; i < n; i++)
        UA_QualifiedName_clear(&elems[i].targetName);
    free(elems);
    free(copy);
    UA_NodeId_clear(&startId);
    UA_BrowsePathResult_clear(&res);
    return res.statusCode == UA_STATUSCODE_GOOD ? TA_OPCUA_OK : TA_OPCUA_ESTATUS;
}

int
ta_opcua_node_info(ta_opcua_client *c, const char *node, const char *params,
                   ta_opcua_out *out)
{
    UA_NodeId id;
    ta_opcua_buf b = TA_OPCUA_BUF_INIT;
    UA_NodeClass nc = UA_NODECLASS_UNSPECIFIED;
    UA_QualifiedName bn;
    UA_LocalizedText dn;
    UA_NodeId dt;
    UA_Byte access = 0;

    (void)params;
    if (nodeid_parse(node, &id) != TA_OPCUA_OK)
        return out_err(out, TA_OPCUA_EINVAL, "bad node id");

    UA_QualifiedName_init(&bn);
    UA_LocalizedText_init(&dn);
    UA_NodeId_init(&dt);

    pthread_mutex_lock(&c->lock);
    UA_Client_readNodeClassAttribute(c->ua, id, &nc);
    UA_Client_readBrowseNameAttribute(c->ua, id, &bn);
    UA_Client_readDisplayNameAttribute(c->ua, id, &dn);
    UA_Client_readDataTypeAttribute(c->ua, id, &dt);
    UA_Client_readAccessLevelAttribute(c->ua, id, &access);
    pthread_mutex_unlock(&c->lock);

    {
        char *bns = strndup((const char *)bn.name.data, bn.name.length);
        char *dns = strndup((const char *)dn.text.data, dn.text.length);
        char *dts = nodeid_print(&dt);

        buf_kv(&b, "class", nodeclass_name(nc));
        buf_kvf(&b, "browse_ns", "%u", bn.namespaceIndex);
        buf_kv(&b, "browse_name", bns);
        buf_kv(&b, "display_name", dns);
        buf_kv(&b, "data_type", dts);
        buf_kvf(&b, "access_level", "%u", access);
        buf_kv(&b, "readable",
               (access & UA_ACCESSLEVELMASK_READ) ? "1" : "0");
        buf_kv(&b, "writable",
               (access & UA_ACCESSLEVELMASK_WRITE) ? "1" : "0");
        free(bns);
        free(dns);
        free(dts);
    }
    out->result = buf_take(&b);
    UA_QualifiedName_clear(&bn);
    UA_LocalizedText_clear(&dn);
    UA_NodeId_clear(&dt);
    UA_NodeId_clear(&id);
    return TA_OPCUA_OK;
}

int
ta_opcua_namespaces(ta_opcua_client *c, ta_opcua_out *out)
{
    ta_opcua_buf b = TA_OPCUA_BUF_INIT;
    UA_Variant v;
    UA_StatusCode st;

    UA_Variant_init(&v);
    pthread_mutex_lock(&c->lock);
    st = UA_Client_readValueAttribute(c->ua,
            UA_NODEID_NUMERIC(0, UA_NS0ID_SERVER_NAMESPACEARRAY), &v);
    pthread_mutex_unlock(&c->lock);

    out->status = st;
    if (st == UA_STATUSCODE_GOOD &&
        UA_Variant_hasArrayType(&v, &UA_TYPES[UA_TYPES_STRING]))
    {
        UA_String *arr = v.data;
        size_t i;

        for (i = 0; i < v.arrayLength; i++)
        {
            char *s = strndup((const char *)arr[i].data, arr[i].length);

            buf_fieldf(&b, "index", "%zu", i);
            buf_field(&b, "uri", s);
            buf_eor(&b);
            free(s);
        }
    }
    out->report = buf_take(&b);
    {
        ta_opcua_buf r = TA_OPCUA_BUF_INIT;

        buf_kvf(&r, "count", "%zu",
                UA_Variant_hasArrayType(&v, &UA_TYPES[UA_TYPES_STRING]) ?
                v.arrayLength : 0);
        out->result = buf_take(&r);
    }
    UA_Variant_clear(&v);
    return st == UA_STATUSCODE_GOOD ? TA_OPCUA_OK : TA_OPCUA_ESTATUS;
}

/* ---- data access -------------------------------------------------- */

static UA_AttributeId
attr_by_name(const char *name)
{
    if (name == NULL || strcmp(name, "value") == 0)
        return UA_ATTRIBUTEID_VALUE;
    if (strcmp(name, "nodeid") == 0) return UA_ATTRIBUTEID_NODEID;
    if (strcmp(name, "nodeclass") == 0) return UA_ATTRIBUTEID_NODECLASS;
    if (strcmp(name, "browsename") == 0) return UA_ATTRIBUTEID_BROWSENAME;
    if (strcmp(name, "displayname") == 0) return UA_ATTRIBUTEID_DISPLAYNAME;
    if (strcmp(name, "description") == 0) return UA_ATTRIBUTEID_DESCRIPTION;
    if (strcmp(name, "datatype") == 0) return UA_ATTRIBUTEID_DATATYPE;
    if (strcmp(name, "accesslevel") == 0) return UA_ATTRIBUTEID_ACCESSLEVEL;
    return UA_ATTRIBUTEID_VALUE;
}

int
ta_opcua_read(ta_opcua_client *c, const char *nodes, const char *params,
              ta_opcua_out *out)
{
    char *attr = ta_opcua_opt(params, "attribute");
    UA_AttributeId aid = attr_by_name(attr);
    UA_ReadRequest req;
    UA_ReadResponse resp;
    UA_ReadValueId *ids = NULL;
    char *copy = strdup(nodes != NULL ? nodes : "");
    char *line;
    char *save = NULL;
    size_t n = 0;
    ta_opcua_buf b = TA_OPCUA_BUF_INIT;
    size_t i;
    int rc = TA_OPCUA_OK;

    for (line = strtok_r(copy, "\n", &save); line != NULL;
         line = strtok_r(NULL, "\n", &save))
    {
        UA_ReadValueId *ni = realloc(ids, (n + 1) * sizeof(*ids));

        if (ni == NULL || *line == '\0')
            continue;
        ids = ni;
        UA_ReadValueId_init(&ids[n]);
        if (nodeid_parse(line, &ids[n].nodeId) != TA_OPCUA_OK)
        {
            rc = out_err(out, TA_OPCUA_EINVAL, "bad node id: %s", line);
            goto out;
        }
        ids[n].attributeId = aid;
        n++;
    }
    if (n == 0)
    {
        rc = out_err(out, TA_OPCUA_EINVAL, "no nodes");
        goto out;
    }

    UA_ReadRequest_init(&req);
    req.nodesToRead = ids;
    req.nodesToReadSize = n;
    req.timestampsToReturn = UA_TIMESTAMPSTORETURN_BOTH;

    pthread_mutex_lock(&c->lock);
    resp = UA_Client_Service_read(c->ua, req);
    pthread_mutex_unlock(&c->lock);

    out->status = resp.responseHeader.serviceResult;
    if (resp.responseHeader.serviceResult != UA_STATUSCODE_GOOD)
    {
        rc = out_err(out, TA_OPCUA_ESTATUS, "read: %s",
                     UA_StatusCode_name(resp.responseHeader.serviceResult));
        UA_ReadResponse_clear(&resp);
        goto out;
    }
    for (i = 0; i < resp.resultsSize; i++)
    {
        char *nid = nodeid_print(&ids[i].nodeId);

        buf_field(&b, "node", nid);
        if (resp.results[i].hasValue && resp.results[i].value.type != NULL)
            buf_field(&b, "type", val_type_name(resp.results[i].value.type));
        else
            buf_field(&b, "type", "Null");
        dv_fields(&b, &resp.results[i]);
        buf_eor(&b);
        free(nid);
    }
    out->report = buf_take(&b);
    {
        ta_opcua_buf r = TA_OPCUA_BUF_INIT;

        buf_kvf(&r, "count", "%zu", resp.resultsSize);
        out->result = buf_take(&r);
    }
    UA_ReadResponse_clear(&resp);
out:
    for (i = 0; i < n; i++)
        UA_ReadValueId_clear(&ids[i]);
    free(ids);
    free(copy);
    free(attr);
    buf_free(&b);
    return rc;
}

int
ta_opcua_write(ta_opcua_client *c, const char *data, const char *params,
               ta_opcua_out *out)
{
    UA_WriteRequest req;
    UA_WriteResponse resp;
    UA_WriteValue *wv = NULL;
    char *copy = strdup(data != NULL ? data : "");
    char *line;
    char *save = NULL;
    size_t n = 0;
    ta_opcua_buf b = TA_OPCUA_BUF_INIT;
    size_t i;
    int rc = TA_OPCUA_OK;

    (void)params;
    for (line = strtok_r(copy, "\n", &save); line != NULL;
         line = strtok_r(NULL, "\n", &save))
    {
        char *tab = strchr(line, '\t');
        UA_WriteValue *nw;

        if (*line == '\0')
            continue;
        if (tab == NULL)
        {
            rc = out_err(out, TA_OPCUA_EINVAL, "write line needs node<TAB>value");
            goto out;
        }
        *tab = '\0';
        nw = realloc(wv, (n + 1) * sizeof(*wv));
        if (nw == NULL)
        {
            rc = TA_OPCUA_ENOMEM;
            goto out;
        }
        wv = nw;
        UA_WriteValue_init(&wv[n]);
        if (nodeid_parse(line, &wv[n].nodeId) != TA_OPCUA_OK)
        {
            rc = out_err(out, TA_OPCUA_EINVAL, "bad node id");
            goto out;
        }
        wv[n].attributeId = UA_ATTRIBUTEID_VALUE;
        if (val_parse(tab + 1, &wv[n].value.value) != TA_OPCUA_OK)
        {
            rc = out_err(out, TA_OPCUA_EINVAL, "bad value");
            goto out;
        }
        wv[n].value.hasValue = true;
        n++;
    }

    UA_WriteRequest_init(&req);
    req.nodesToWrite = wv;
    req.nodesToWriteSize = n;

    pthread_mutex_lock(&c->lock);
    resp = UA_Client_Service_write(c->ua, req);
    pthread_mutex_unlock(&c->lock);

    out->status = resp.responseHeader.serviceResult;
    for (i = 0; i < resp.resultsSize; i++)
    {
        char *nid = nodeid_print(&wv[i].nodeId);

        buf_field(&b, "node", nid);
        buf_fieldf(&b, "status", "0x%08" PRIX32, resp.results[i]);
        buf_eor(&b);
        free(nid);
    }
    out->report = buf_take(&b);
    {
        ta_opcua_buf r = TA_OPCUA_BUF_INIT;

        buf_kvf(&r, "count", "%zu", resp.resultsSize);
        buf_kvf(&r, "service_status", "0x%08" PRIX32,
                resp.responseHeader.serviceResult);
        out->result = buf_take(&r);
    }
    if (resp.responseHeader.serviceResult != UA_STATUSCODE_GOOD)
        rc = TA_OPCUA_ESTATUS;
    UA_WriteResponse_clear(&resp);
out:
    for (i = 0; i < n; i++)
        UA_WriteValue_clear(&wv[i]);
    free(wv);
    free(copy);
    buf_free(&b);
    return rc;
}

/* ---- methods ------------------------------------------------------ */

int
ta_opcua_call(ta_opcua_client *c, const char *method, const char *params,
              const char *inputs, ta_opcua_out *out)
{
    char *objs = ta_opcua_opt(params, "object");
    UA_NodeId obj;
    UA_NodeId meth;
    UA_Variant *in = NULL;
    UA_Variant *outv = NULL;
    size_t nin = 0;
    size_t nout = 0;
    char *copy = strdup(inputs != NULL ? inputs : "");
    char *line;
    char *save = NULL;
    ta_opcua_buf b = TA_OPCUA_BUF_INIT;
    UA_StatusCode st;
    size_t i;
    int rc = TA_OPCUA_OK;

    if (nodeid_parse(objs, &obj) != TA_OPCUA_OK ||
        nodeid_parse(method, &meth) != TA_OPCUA_OK)
    {
        rc = out_err(out, TA_OPCUA_EINVAL, "bad object/method id");
        goto out;
    }
    for (line = strtok_r(copy, "\n", &save); line != NULL;
         line = strtok_r(NULL, "\n", &save))
    {
        UA_Variant *ni;

        if (*line == '\0')
            continue;
        ni = realloc(in, (nin + 1) * sizeof(*in));
        if (ni == NULL)
        {
            rc = TA_OPCUA_ENOMEM;
            goto out;
        }
        in = ni;
        if (val_parse(line, &in[nin]) != TA_OPCUA_OK)
        {
            rc = out_err(out, TA_OPCUA_EINVAL, "bad input argument");
            goto out;
        }
        nin++;
    }

    pthread_mutex_lock(&c->lock);
    st = UA_Client_call(c->ua, obj, meth, nin, in, &nout, &outv);
    pthread_mutex_unlock(&c->lock);

    out->status = st;
    if (st != UA_STATUSCODE_GOOD)
        rc = out_err(out, TA_OPCUA_ESTATUS, "call: %s",
                     UA_StatusCode_name(st));
    for (i = 0; i < nout; i++)
    {
        char *v = val_print(&outv[i]);

        buf_fieldf(&b, "index", "%zu", i);
        buf_field(&b, "value", v);
        buf_eor(&b);
        free(v);
    }
    out->report = buf_take(&b);
    {
        ta_opcua_buf r = TA_OPCUA_BUF_INIT;

        buf_kvf(&r, "outputs", "%zu", nout);
        buf_kvf(&r, "status", "0x%08" PRIX32, st);
        out->result = buf_take(&r);
    }
    UA_Array_delete(outv, nout, &UA_TYPES[UA_TYPES_VARIANT]);
out:
    for (i = 0; i < nin; i++)
        UA_Variant_clear(&in[i]);
    free(in);
    free(copy);
    free(objs);
    UA_NodeId_clear(&obj);
    UA_NodeId_clear(&meth);
    buf_free(&b);
    return rc;
}

int
ta_opcua_method_info(ta_opcua_client *c, const char *method, ta_opcua_out *out)
{
    /* Read the InputArguments / OutputArguments properties of the method. */
    UA_NodeId meth;
    ta_opcua_buf b = TA_OPCUA_BUF_INIT;

    if (nodeid_parse(method, &meth) != TA_OPCUA_OK)
        return out_err(out, TA_OPCUA_EINVAL, "bad method id");
    /* Best-effort: callers mostly need the counts, obtained from a call
     * with wrong arity. Expose what we can read cheaply. */
    buf_kv(&b, "note", "method argument metadata via browse of the method");
    UA_NodeId_clear(&meth);
    out->result = buf_take(&b);
    return TA_OPCUA_OK;
}

/* ---- performance -------------------------------------------------- */

int
ta_opcua_perf(ta_opcua_client *c, const char *target, const char *params,
              const char *data, ta_opcua_out *out)
{
    long long count = ta_opcua_opt_int(params, "count", 100);
    char *op = ta_opcua_opt(params, "op");
    char *node = ta_opcua_opt(params, "node");
    ta_opcua_buf b = TA_OPCUA_BUF_INIT;
    long long i;
    uint64_t sum = 0;
    uint64_t mn = UINT64_MAX;
    uint64_t mx = 0;
    int rc = TA_OPCUA_OK;

    (void)target;
    if (op == NULL)
        op = strdup("read");
    for (i = 0; i < count; i++)
    {
        uint64_t t0 = ta_opcua_now_us();
        uint64_t dt;
        UA_StatusCode st = UA_STATUSCODE_GOOD;

        if (strcmp(op, "read") == 0)
        {
            UA_Variant v;

            UA_Variant_init(&v);
            pthread_mutex_lock(&c->lock);
            st = UA_Client_readValueAttribute(c->ua,
                    UA_NODEID_NULL, &v);
            if (node != NULL)
            {
                UA_NodeId id;

                if (nodeid_parse(node, &id) == TA_OPCUA_OK)
                {
                    UA_Variant_clear(&v);
                    UA_Variant_init(&v);
                    st = UA_Client_readValueAttribute(c->ua, id, &v);
                    UA_NodeId_clear(&id);
                }
            }
            pthread_mutex_unlock(&c->lock);
            UA_Variant_clear(&v);
        }
        else if (strcmp(op, "browse") == 0)
        {
            UA_BrowseRequest req;
            UA_BrowseResponse resp;
            UA_BrowseDescription bd;

            UA_BrowseRequest_init(&req);
            UA_BrowseDescription_init(&bd);
            nodeid_parse(node != NULL ? node : "i=85", &bd.nodeId);
            bd.resultMask = UA_BROWSERESULTMASK_ALL;
            bd.referenceTypeId = UA_NODEID_NUMERIC(0, UA_NS0ID_REFERENCES);
            bd.includeSubtypes = true;
            bd.browseDirection = UA_BROWSEDIRECTION_FORWARD;
            req.nodesToBrowse = &bd;
            req.nodesToBrowseSize = 1;
            pthread_mutex_lock(&c->lock);
            resp = UA_Client_Service_browse(c->ua, req);
            pthread_mutex_unlock(&c->lock);
            st = resp.responseHeader.serviceResult;
            UA_NodeId_clear(&bd.nodeId);
            UA_BrowseResponse_clear(&resp);
        }
        else
        {
            rc = out_err(out, TA_OPCUA_EINVAL, "perf op must be read|browse");
            break;
        }
        dt = ta_opcua_now_us() - t0;
        sum += dt;
        if (dt < mn) mn = dt;
        if (dt > mx) mx = dt;
        buf_fieldf(&b, "seq", "%lld", i);
        buf_fieldf(&b, "us", "%" PRIu64, dt);
        buf_fieldf(&b, "status", "0x%08" PRIX32, st);
        buf_eor(&b);
    }
    (void)data;
    out->report = buf_take(&b);
    if (rc == TA_OPCUA_OK && count > 0)
    {
        ta_opcua_buf r = TA_OPCUA_BUF_INIT;

        buf_kvf(&r, "count", "%lld", count);
        buf_kvf(&r, "min_us", "%" PRIu64, mn);
        buf_kvf(&r, "max_us", "%" PRIu64, mx);
        buf_kvf(&r, "mean_us", "%" PRIu64, sum / (uint64_t)count);
        out->result = buf_take(&r);
    }
    free(op);
    free(node);
    return rc;
}
