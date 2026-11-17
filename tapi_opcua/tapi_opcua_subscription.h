/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Interpretica, Unipessoal Lda. All rights reserved. */
/** @file
 * @brief OPC UA TAPI: subscriptions, monitored items, events
 *
 * @addtogroup tapi_opcua
 * @{
 *
 * The asynchronous side of OPC UA. A subscription and its monitored
 * items live on the agent, whose client thread keeps the publish cycle
 * running; the test takes delivered notifications with
 * ::tapi_opcua_collect and judges them.
 *
 * Reliability semantics are explicit. Each collected notification
 * record carries the local delivery ordinal (@c seq), the
 * PublishResponse batch it came in (@c batch), the server/source
 * timestamps and the Overflow info bit (@c overflow). The collect
 * result reports the subscription's counters - total delivered,
 * notifications still queued, StatusChange code, inactivity callbacks,
 * and whether the subscription was deleted. A missing notification is
 * therefore distinguishable from a late one and from one discarded by
 * the server's queue policy; loss is never inferred from a gap in
 * values alone.
 */

#ifndef __TAPI_OPCUA_SUBSCRIPTION_H__
#define __TAPI_OPCUA_SUBSCRIPTION_H__

#include "tapi_opcua.h"

#ifdef __cplusplus
extern "C" {
#endif

/** A subscription handle. */
typedef tapi_opcua_handle tapi_opcua_sub;

/** Subscription parameters. 0 = the TAPI/server default. */
typedef struct tapi_opcua_sub_opt {
    double       publishing_interval_ms;
    unsigned int lifetime_count;
    unsigned int max_keepalive_count;
    unsigned int max_notifications;
    unsigned int priority;
    bool         publishing_disabled;   /**< Default is enabled. */
} tapi_opcua_sub_opt;

/** Monitored-item parameters. */
typedef struct tapi_opcua_monitor_opt {
    const char  *attribute;              /**< Default "value". */
    double       sampling_interval_ms;
    unsigned int queue_size;
    bool         discard_newest;         /**< Default discards oldest. */
    const char  *mode;                   /**< "reporting"/"sampling"/... */
    const char  *deadband;               /**< "none"/"absolute"/"percent". */
    double       deadband_value;
} tapi_opcua_monitor_opt;

/** Event monitored-item parameters. */
typedef struct tapi_opcua_event_opt {
    const char  *fields;      /**< Comma list of select browse names. */
    unsigned int min_severity;
} tapi_opcua_event_opt;

/** Create a subscription. @p opt may be NULL for defaults. The server's
 *  revised parameters are in @p revised (NULL to ignore). */
extern te_errno tapi_opcua_subscribe(tapi_opcua_conn *conn,
                                     const tapi_opcua_sub_opt *opt,
                                     tapi_opcua_sub *sub,
                                     tapi_opcua_kv *revised);

/** Delete a subscription. */
extern te_errno tapi_opcua_unsubscribe(tapi_opcua_sub *sub);

/** Add a data-change monitored item on @p node; @p item_id out (NULL ok). */
extern te_errno tapi_opcua_monitor(tapi_opcua_sub *sub, const char *node,
                                   const tapi_opcua_monitor_opt *opt,
                                   uint32_t *item_id, tapi_opcua_kv *revised);

/** Add an event monitored item on an event-notifier @p node. */
extern te_errno tapi_opcua_event_subscribe(tapi_opcua_sub *sub,
                                           const char *node,
                                           const tapi_opcua_event_opt *opt,
                                           uint32_t *item_id);

/** Remove a monitored item. */
extern te_errno tapi_opcua_unmonitor(tapi_opcua_sub *sub, uint32_t item_id);

/**
 * Collect queued notifications. Waits up to @p timeout_ms for at least
 * @p min of them (0 = take whatever is there now), at most @p max
 * (0 = all). The records go to @p notes (caller frees); the
 * subscription counters go to @p state (NULL to ignore).
 */
extern te_errno tapi_opcua_collect(tapi_opcua_sub *sub, unsigned int min,
                                   unsigned int max, int timeout_ms,
                                   te_string *notes, tapi_opcua_kv *state);

/** Collect events the same way (events and data changes share the queue;
 *  this is ::tapi_opcua_collect under an event-shaped name). */
extern te_errno tapi_opcua_event_collect(tapi_opcua_sub *sub,
                                         unsigned int min, int timeout_ms,
                                         te_string *events,
                                         tapi_opcua_kv *state);

/** End an event subscription's monitored item (alias of unmonitor). */
extern te_errno tapi_opcua_event_unsubscribe(tapi_opcua_sub *sub,
                                             uint32_t item_id);

/** Count the records (notifications) in a collect report. */
extern unsigned int tapi_opcua_notes_count(const char *notes);

#ifdef __cplusplus
} /* extern "C" */
#endif
/**@} */
#endif /* !__TAPI_OPCUA_SUBSCRIPTION_H__ */
