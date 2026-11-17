/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Interpretica, Unipessoal Lda. All rights reserved. */
/** @file
 * @brief OPC UA core: subscriptions, monitored items, events
 *
 * A subscription lives on the client and in the server; its monitored
 * items deliver into a queue the collect operation drains. The data and
 * event callbacks run on the iterate thread (under the client lock), so
 * they only append to the queue under qlock and signal; collect waits
 * on qcond. Every notification record carries the local delivery
 * ordinal (seq), the PublishResponse batch it arrived in, and the
 * Overflow info bit, so a test can tell a missing notification from a
 * late one from one discarded by the server's queue policy - the loss
 * is never inferred from a gap in values alone.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ta_opcua_int.h"

/* ---- queue helpers (qlock held) ----------------------------------- */

ta_opcua_client *
ta_opcua_sub_client(ta_opcua_sub *s)
{
    return s->client;
}

ta_opcua_sub *
client_sub_by_id(ta_opcua_client *c, uint32_t id)
{
    ta_opcua_sub *s;

    for (s = c->subs; s != NULL; s = s->next)
    {
        if (s->id == id)
            return s;
    }
    return NULL;
}

static ta_opcua_item *
sub_item_by_id(ta_opcua_sub *s, uint32_t id)
{
    ta_opcua_item *it;

    for (it = s->items; it != NULL; it = it->next)
    {
        if (it->id == id)
            return it;
    }
    return NULL;
}

/** At most this many undrained notifications before the local queue
 *  overflows (counted, never silent). */
#define TA_OPCUA_QUEUE_MAX 65536

static void
queue_push(ta_opcua_sub *s, char *record)
{
    ta_opcua_note *note;

    if (s->queued >= TA_OPCUA_QUEUE_MAX)
    {
        s->dropped++;
        free(record);
        return;
    }
    note = calloc(1, sizeof(*note));
    if (note == NULL)
    {
        s->dropped++;
        free(record);
        return;
    }
    note->record = record;
    if (s->tail != NULL)
        s->tail->next = note;
    else
        s->head = note;
    s->tail = note;
    s->queued++;
}

void
sub_free_local(ta_opcua_sub *s)
{
    ta_opcua_item *it = s->items;
    ta_opcua_note *n = s->head;
    size_t i;

    while (it != NULL)
    {
        ta_opcua_item *next = it->next;

        for (i = 0; i < it->nfields; i++)
            free(it->fields[i]);
        free(it->fields);
        free(it);
        it = next;
    }
    while (n != NULL)
    {
        ta_opcua_note *next = n->next;

        free(n->record);
        free(n);
        n = next;
    }
    free(s);
}

/* ---- callbacks (iterate thread, client lock held) ----------------- */

static void
data_change_cb(UA_Client *ua, UA_UInt32 subId, void *subCtx,
               UA_UInt32 monId, void *monCtx, UA_DataValue *value)
{
    ta_opcua_client *c = *(ta_opcua_client **)UA_Client_getContext(ua);
    ta_opcua_buf b = TA_OPCUA_BUF_INIT;
    ta_opcua_sub *s;
    ta_opcua_item *it;

    (void)subCtx; (void)monCtx;
    if (c == NULL)
        return;
    pthread_mutex_lock(&c->qlock);
    s = client_sub_by_id(c, subId);
    if (s == NULL)
    {
        pthread_mutex_unlock(&c->qlock);
        return;
    }
    it = sub_item_by_id(s, monId);
    s->seq++;
    buf_fieldf(&b, "item", "%u", monId);
    buf_field(&b, "kind", "data");
    buf_fieldf(&b, "seq", "%" PRIu64, s->seq);
    buf_fieldf(&b, "batch", "%" PRIu64, c->publish_responses);
    buf_fieldf(&b, "recv_us", "%" PRIu64, ta_opcua_now_us());
    dv_fields(&b, value);
    if (value->hasStatus &&
        (value->status & UA_STATUSCODE_INFOBITS_OVERFLOW))
    {
        buf_field(&b, "overflow", "1");
        if (it != NULL)
            it->overflows++;
    }
    else
    {
        buf_field(&b, "overflow", "0");
    }
    if (it != NULL)
        it->delivered++;
    queue_push(s, buf_take(&b));
    pthread_cond_broadcast(&c->qcond);
    pthread_mutex_unlock(&c->qlock);
}

static void
event_cb(UA_Client *ua, UA_UInt32 subId, void *subCtx, UA_UInt32 monId,
         void *monCtx, const UA_KeyValueMap fields)
{
    ta_opcua_client *c = *(ta_opcua_client **)UA_Client_getContext(ua);
    ta_opcua_buf b = TA_OPCUA_BUF_INIT;
    ta_opcua_sub *s;
    ta_opcua_item *it;
    size_t i;

    (void)subCtx; (void)monCtx;
    if (c == NULL)
        return;
    pthread_mutex_lock(&c->qlock);
    s = client_sub_by_id(c, subId);
    if (s == NULL)
    {
        pthread_mutex_unlock(&c->qlock);
        return;
    }
    it = sub_item_by_id(s, monId);
    s->seq++;
    buf_fieldf(&b, "item", "%u", monId);
    buf_field(&b, "kind", "event");
    buf_fieldf(&b, "seq", "%" PRIu64, s->seq);
    buf_fieldf(&b, "batch", "%" PRIu64, c->publish_responses);
    buf_fieldf(&b, "recv_us", "%" PRIu64, ta_opcua_now_us());
    if (it != NULL)
    {
        for (i = 0; i < it->nfields; i++)
        {
            UA_QualifiedName qn = UA_QUALIFIEDNAME(0, it->fields[i]);
            const UA_Variant *v = UA_KeyValueMap_get(&fields, qn);
            char *vs;

            if (v == NULL)
            {
                buf_fieldf(&b, it->fields[i], "%s", "");
                continue;
            }
            vs = val_print(v);
            buf_field(&b, it->fields[i], vs);
            free(vs);
        }
        it->delivered++;
    }
    queue_push(s, buf_take(&b));
    pthread_cond_broadcast(&c->qcond);
    pthread_mutex_unlock(&c->qlock);
}

static void
status_change_cb(UA_Client *ua, UA_UInt32 subId, void *subCtx,
                 UA_StatusChangeNotification *note)
{
    ta_opcua_client *c = *(ta_opcua_client **)UA_Client_getContext(ua);
    ta_opcua_sub *s;

    (void)subCtx;
    if (c == NULL)
        return;
    pthread_mutex_lock(&c->qlock);
    s = client_sub_by_id(c, subId);
    if (s != NULL)
        s->last_status = note->status;
    pthread_mutex_unlock(&c->qlock);
}

static void
delete_sub_cb(UA_Client *ua, UA_UInt32 subId, void *subCtx)
{
    ta_opcua_client *c = *(ta_opcua_client **)UA_Client_getContext(ua);
    ta_opcua_sub *s;

    (void)subCtx;
    if (c == NULL)
        return;
    pthread_mutex_lock(&c->qlock);
    s = client_sub_by_id(c, subId);
    if (s != NULL)
        s->deleted = true;
    pthread_mutex_unlock(&c->qlock);
}

/* ---- create / delete ---------------------------------------------- */

int
ta_opcua_sub_create(ta_opcua_client *c, const char *params,
                    ta_opcua_sub **sub, ta_opcua_out *out)
{
    UA_CreateSubscriptionRequest req =
        UA_CreateSubscriptionRequest_default();
    UA_CreateSubscriptionResponse resp;
    ta_opcua_sub *s;
    ta_opcua_buf b = TA_OPCUA_BUF_INIT;

    req.requestedPublishingInterval =
        ta_opcua_opt_dbl(params, "publishing_interval_ms", 250.0);
    req.requestedLifetimeCount =
        (UA_UInt32)ta_opcua_opt_int(params, "lifetime_count", 10000);
    req.requestedMaxKeepAliveCount =
        (UA_UInt32)ta_opcua_opt_int(params, "max_keepalive_count", 10);
    req.maxNotificationsPerPublish =
        (UA_UInt32)ta_opcua_opt_int(params, "max_notifications", 0);
    req.priority = (UA_Byte)ta_opcua_opt_int(params, "priority", 0);
    req.publishingEnabled = ta_opcua_opt_bool(params, "publishing_enabled",
                                              true);

    s = calloc(1, sizeof(*s));
    if (s == NULL)
        return out_err(out, TA_OPCUA_ENOMEM, "oom");
    s->client = c;

    pthread_mutex_lock(&c->lock);
    resp = UA_Client_Subscriptions_create(c->ua, req, NULL,
                                          status_change_cb, delete_sub_cb);
    pthread_mutex_unlock(&c->lock);

    out->status = resp.responseHeader.serviceResult;
    if (resp.responseHeader.serviceResult != UA_STATUSCODE_GOOD)
    {
        free(s);
        return out_err(out, TA_OPCUA_ESTATUS, "create subscription: %s",
                       UA_StatusCode_name(resp.responseHeader.serviceResult));
    }
    s->id = resp.subscriptionId;
    pthread_mutex_lock(&c->qlock);
    s->next = c->subs;
    c->subs = s;
    pthread_mutex_unlock(&c->qlock);

    buf_kvf(&b, "subscription_id", "%u", resp.subscriptionId);
    buf_kvf(&b, "revised_publishing_interval_ms", "%.3f",
            resp.revisedPublishingInterval);
    buf_kvf(&b, "revised_lifetime_count", "%u", resp.revisedLifetimeCount);
    buf_kvf(&b, "revised_max_keepalive_count", "%u",
            resp.revisedMaxKeepAliveCount);
    out->result = buf_take(&b);
    *sub = s;
    return TA_OPCUA_OK;
}

int
ta_opcua_sub_delete(ta_opcua_sub *s, ta_opcua_out *out)
{
    ta_opcua_client *c = s->client;
    UA_StatusCode st;
    ta_opcua_sub **pp;

    pthread_mutex_lock(&c->lock);
    st = UA_Client_Subscriptions_deleteSingle(c->ua, s->id);
    pthread_mutex_unlock(&c->lock);
    out->status = st;

    pthread_mutex_lock(&c->qlock);
    for (pp = &c->subs; *pp != NULL; pp = &(*pp)->next)
    {
        if (*pp == s)
        {
            *pp = s->next;
            break;
        }
    }
    pthread_mutex_unlock(&c->qlock);
    sub_free_local(s);
    return st == UA_STATUSCODE_GOOD ? TA_OPCUA_OK : TA_OPCUA_ESTATUS;
}

/* ---- monitor ------------------------------------------------------ */

static UA_MonitoringMode
mode_from_name(const char *s)
{
    if (s == NULL || strcmp(s, "reporting") == 0)
        return UA_MONITORINGMODE_REPORTING;
    if (strcmp(s, "sampling") == 0)
        return UA_MONITORINGMODE_SAMPLING;
    return UA_MONITORINGMODE_DISABLED;
}

int
ta_opcua_monitor(ta_opcua_sub *s, const char *node, const char *params,
                 uint32_t *item, ta_opcua_out *out)
{
    ta_opcua_client *c = s->client;
    char *kind = ta_opcua_opt(params, "kind");
    char *attr = ta_opcua_opt(params, "attribute");
    char *deadband = ta_opcua_opt(params, "deadband");
    UA_NodeId id;
    UA_MonitoredItemCreateRequest req;
    UA_MonitoredItemCreateResult res;
    ta_opcua_item *it;
    ta_opcua_buf b = TA_OPCUA_BUF_INIT;
    bool is_event = kind != NULL && strcmp(kind, "event") == 0;
    int rc = TA_OPCUA_OK;

    if (nodeid_parse(node, &id) != TA_OPCUA_OK)
    {
        rc = out_err(out, TA_OPCUA_EINVAL, "bad node id");
        goto out;
    }

    UA_MonitoredItemCreateRequest_init(&req);
    req.itemToMonitor.nodeId = id;
    req.monitoringMode = mode_from_name(ta_opcua_opt(params, "mode"));
    req.requestedParameters.samplingInterval =
        ta_opcua_opt_dbl(params, "sampling_interval_ms", 250.0);
    req.requestedParameters.queueSize =
        (UA_UInt32)ta_opcua_opt_int(params, "queue_size", 1);
    req.requestedParameters.discardOldest =
        ta_opcua_opt_bool(params, "discard_oldest", true);

    it = calloc(1, sizeof(*it));
    if (it == NULL)
    {
        rc = out_err(out, TA_OPCUA_ENOMEM, "oom");
        UA_NodeId_clear(&id);
        goto out;
    }
    it->sub = s;
    it->event = is_event;

    if (is_event)
    {
        char *fields = ta_opcua_opt(params, "fields");
        char *list = fields != NULL ? fields :
            strdup("EventType,SourceNode,Severity,Message,Time");
        UA_EventFilter *filter = UA_EventFilter_new();
        char *tok;
        char *save = NULL;
        size_t n = 0;
        char *copy = strdup(list);

        req.itemToMonitor.attributeId = UA_ATTRIBUTEID_EVENTNOTIFIER;
        UA_EventFilter_init(filter);
        for (tok = strtok_r(copy, ",", &save); tok != NULL;
             tok = strtok_r(NULL, ",", &save))
        {
            char **nf = realloc(it->fields, (n + 1) * sizeof(char *));
            UA_SimpleAttributeOperand *no;

            if (nf == NULL)
                break;
            it->fields = nf;
            it->fields[n] = strdup(tok);
            no = realloc(filter->selectClauses,
                         (n + 1) * sizeof(UA_SimpleAttributeOperand));
            if (no == NULL)
                break;
            filter->selectClauses = no;
            UA_SimpleAttributeOperand_init(&filter->selectClauses[n]);
            filter->selectClauses[n].typeDefinitionId =
                UA_NODEID_NUMERIC(0, UA_NS0ID_BASEEVENTTYPE);
            filter->selectClauses[n].browsePathSize = 1;
            filter->selectClauses[n].browsePath =
                UA_QualifiedName_new();
            *filter->selectClauses[n].browsePath =
                UA_QUALIFIEDNAME_ALLOC(0, tok);
            filter->selectClauses[n].attributeId = UA_ATTRIBUTEID_VALUE;
            n++;
        }
        it->nfields = n;
        filter->selectClausesSize = n;
        req.requestedParameters.filter.content.decoded.type =
            &UA_TYPES[UA_TYPES_EVENTFILTER];
        req.requestedParameters.filter.content.decoded.data = filter;
        req.requestedParameters.filter.encoding = UA_EXTENSIONOBJECT_DECODED;
        free(copy);
        free(fields);

        pthread_mutex_lock(&c->lock);
        res = UA_Client_MonitoredItems_createEvent(c->ua, s->id,
                UA_TIMESTAMPSTORETURN_BOTH, req, it, event_cb, NULL);
        pthread_mutex_unlock(&c->lock);
    }
    else
    {
        req.itemToMonitor.attributeId =
            attr != NULL && strcmp(attr, "value") != 0 ?
            UA_ATTRIBUTEID_VALUE : UA_ATTRIBUTEID_VALUE;
        if (deadband != NULL && strcmp(deadband, "none") != 0)
        {
            UA_DataChangeFilter *dcf = UA_DataChangeFilter_new();

            UA_DataChangeFilter_init(dcf);
            dcf->trigger = UA_DATACHANGETRIGGER_STATUSVALUE;
            dcf->deadbandType = strcmp(deadband, "percent") == 0 ?
                UA_DEADBANDTYPE_PERCENT : UA_DEADBANDTYPE_ABSOLUTE;
            dcf->deadbandValue = ta_opcua_opt_dbl(params, "deadband_value",
                                                  0.0);
            req.requestedParameters.filter.content.decoded.type =
                &UA_TYPES[UA_TYPES_DATACHANGEFILTER];
            req.requestedParameters.filter.content.decoded.data = dcf;
            req.requestedParameters.filter.encoding =
                UA_EXTENSIONOBJECT_DECODED;
        }
        pthread_mutex_lock(&c->lock);
        res = UA_Client_MonitoredItems_createDataChange(c->ua, s->id,
                UA_TIMESTAMPSTORETURN_BOTH, req, it, data_change_cb, NULL);
        pthread_mutex_unlock(&c->lock);
    }

    out->status = res.statusCode;
    if (res.statusCode != UA_STATUSCODE_GOOD)
    {
        size_t i;

        for (i = 0; i < it->nfields; i++)
            free(it->fields[i]);
        free(it->fields);
        free(it);
        rc = out_err(out, TA_OPCUA_ESTATUS, "monitor: %s",
                     UA_StatusCode_name(res.statusCode));
        UA_MonitoredItemCreateResult_clear(&res);
        UA_MonitoredItemCreateRequest_clear(&req);
        goto out;
    }
    it->id = res.monitoredItemId;
    pthread_mutex_lock(&c->qlock);
    it->next = s->items;
    s->items = it;
    pthread_mutex_unlock(&c->qlock);
    *item = res.monitoredItemId;

    buf_kvf(&b, "item_id", "%u", res.monitoredItemId);
    buf_kvf(&b, "revised_sampling_interval_ms", "%.3f",
            res.revisedSamplingInterval);
    buf_kvf(&b, "revised_queue_size", "%u", res.revisedQueueSize);
    out->result = buf_take(&b);
    UA_MonitoredItemCreateResult_clear(&res);
    UA_MonitoredItemCreateRequest_clear(&req);
out:
    free(kind);
    free(attr);
    free(deadband);
    return rc;
}

int
ta_opcua_unmonitor(ta_opcua_sub *s, uint32_t item, ta_opcua_out *out)
{
    ta_opcua_client *c = s->client;
    UA_StatusCode st;
    ta_opcua_item **pp;

    pthread_mutex_lock(&c->lock);
    st = UA_Client_MonitoredItems_deleteSingle(c->ua, s->id, item);
    pthread_mutex_unlock(&c->lock);
    out->status = st;

    pthread_mutex_lock(&c->qlock);
    for (pp = &s->items; *pp != NULL; pp = &(*pp)->next)
    {
        if ((*pp)->id == item)
        {
            ta_opcua_item *dead = *pp;
            size_t i;

            *pp = dead->next;
            for (i = 0; i < dead->nfields; i++)
                free(dead->fields[i]);
            free(dead->fields);
            free(dead);
            break;
        }
    }
    pthread_mutex_unlock(&c->qlock);
    return st == UA_STATUSCODE_GOOD ? TA_OPCUA_OK : TA_OPCUA_ESTATUS;
}

/* ---- collect ------------------------------------------------------ */

int
ta_opcua_collect(ta_opcua_sub *s, const char *params, ta_opcua_out *out)
{
    ta_opcua_client *c = s->client;
    long long want = ta_opcua_opt_int(params, "min", 0);
    long long timeout_ms = ta_opcua_opt_int(params, "timeout_ms", 1000);
    long long max = ta_opcua_opt_int(params, "max", 0);
    ta_opcua_buf b = TA_OPCUA_BUF_INIT;
    uint64_t deadline = ta_opcua_now_us() + (uint64_t)timeout_ms * 1000;
    long long got = 0;

    pthread_mutex_lock(&c->qlock);
    while ((long long)s->queued < want)
    {
        struct timespec ts;
        uint64_t now = ta_opcua_now_us();
        uint64_t left;

        if (now >= deadline)
            break;
        left = deadline - now;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += (time_t)(left / 1000000);
        ts.tv_nsec += (long)((left % 1000000) * 1000);
        if (ts.tv_nsec >= 1000000000L)
        {
            ts.tv_sec++;
            ts.tv_nsec -= 1000000000L;
        }
        pthread_cond_timedwait(&c->qcond, &c->qlock, &ts);
    }
    while (s->head != NULL && (max == 0 || got < max))
    {
        ta_opcua_note *n = s->head;

        buf_add(&b, "%s\n", n->record);
        s->head = n->next;
        if (s->head == NULL)
            s->tail = NULL;
        s->queued--;
        free(n->record);
        free(n);
        got++;
    }
    out->report = buf_take(&b);
    {
        ta_opcua_buf r = TA_OPCUA_BUF_INIT;

        buf_kvf(&r, "collected", "%lld", got);
        buf_kvf(&r, "queued", "%zu", s->queued);
        buf_kvf(&r, "total_seq", "%" PRIu64, s->seq);
        buf_kvf(&r, "batches", "%" PRIu64, s->batches);
        buf_kvf(&r, "dropped_local", "%" PRIu64, s->dropped);
        buf_kvf(&r, "inactivity", "%" PRIu64, s->inactivity);
        buf_kvf(&r, "status_change", "0x%08" PRIX32, s->last_status);
        buf_kv(&r, "deleted", s->deleted ? "1" : "0");
        out->result = buf_take(&r);
    }
    pthread_mutex_unlock(&c->qlock);
    return TA_OPCUA_OK;
}
