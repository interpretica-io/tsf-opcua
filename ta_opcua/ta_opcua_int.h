/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Interpretica, Unipessoal Lda. All rights reserved. */
/** @file
 * @brief OPC UA core: internals shared by the core units
 *
 * Not part of any interface: the growable text buffer, the value codec
 * over open62541 types, and the structures of a client and its
 * subscriptions (the subscription unit fills what the client unit
 * owns).
 */

#ifndef __TA_OPCUA_INT_H__
#define __TA_OPCUA_INT_H__

#include <inttypes.h>
#include <pthread.h>
#include <stdarg.h>
#include <time.h>

#include <open62541/client.h>
#include <open62541/client_highlevel.h>
#include <open62541/client_subscriptions.h>
#include <open62541/server.h>

#include "ta_opcua_core.h"

/* ---- text buffer -------------------------------------------------- */

typedef struct ta_opcua_buf {
    char   *ptr;
    size_t  len;
    size_t  size;
} ta_opcua_buf;

#define TA_OPCUA_BUF_INIT { NULL, 0, 0 }

extern void buf_add(ta_opcua_buf *b, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));
extern void buf_addv(ta_opcua_buf *b, const char *fmt, va_list ap);
/** Append "key=<escaped value>\n". */
extern void buf_kv(ta_opcua_buf *b, const char *key, const char *val);
extern void buf_kvf(ta_opcua_buf *b, const char *key, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));
/** Append "\tkey=<escaped value>" (or without the tab at line start). */
extern void buf_field(ta_opcua_buf *b, const char *key, const char *val);
extern void buf_fieldf(ta_opcua_buf *b, const char *key, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));
/** End a report record. */
extern void buf_eor(ta_opcua_buf *b);
/** Hand the buffer over (never NULL). */
extern char *buf_take(ta_opcua_buf *b);
extern void buf_free(ta_opcua_buf *b);

/** Set out->errmsg (printf) and return @p rc. */
extern int out_err(ta_opcua_out *out, int rc, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));

/* ---- value codec -------------------------------------------------- */

/** Wire form of a Variant (malloc'ed). */
extern char *val_print(const UA_Variant *v);
/** Parse the wire form into a Variant (cleared by the caller). */
extern int val_parse(const char *s, UA_Variant *v);
/** Name of a builtin type as used on the wire, "Opaque" otherwise. */
extern const char *val_type_name(const UA_DataType *t);
/** Builtin type by wire name, or NULL. */
extern const UA_DataType *val_type_by_name(const char *name);

/** NodeId text form (malloc'ed); "" for the null NodeId. */
extern char *nodeid_print(const UA_NodeId *id);
/** Parse "ns=2;s=x", "i=85", "ns=1;g=...", "ns=1;b=<base64>". */
extern int nodeid_parse(const char *s, UA_NodeId *id);
/** UA DateTime as wire text ("none" for 0). */
extern void ts_print(ta_opcua_buf *b, const char *key, UA_DateTime t,
                     bool has);
/** Add the DataValue fields (value, status, timestamps) as record fields. */
extern void dv_fields(ta_opcua_buf *b, const UA_DataValue *dv);

/** Policy short name or URI -> URI (static); NULL when unknown. */
extern const char *policy_uri(const char *name);
/** Policy URI -> short name (static). */
extern const char *policy_name(const UA_String *uri);
extern const char *mode_name(UA_MessageSecurityMode m);
extern int mode_parse(const char *s, UA_MessageSecurityMode *m);

/** Decode a lower/upper-case hex string into a ByteString. */
extern int hex_to_bytes(const char *s, UA_ByteString *bs);

/** Read a whole file into a ByteString. */
extern int file_load(const char *path, UA_ByteString *bs);
/** Load a comma list of files into an array of ByteStrings. */
extern int file_list_load(const char *list, UA_ByteString **arr,
                          size_t *n);
extern void file_list_free(UA_ByteString *arr, size_t n);

/* ---- client and subscription state -------------------------------- */

/** One notification waiting to be collected. */
typedef struct ta_opcua_note {
    struct ta_opcua_note *next;
    char *record;              /**< Report record without the newline. */
} ta_opcua_note;

/** A monitored item known to the core. */
typedef struct ta_opcua_item {
    struct ta_opcua_item *next;
    struct ta_opcua_sub  *sub;
    uint32_t  id;              /**< Server MonitoredItemId. */
    bool      event;
    size_t    nfields;         /**< Event select clauses. */
    char    **fields;          /**< Their names. */
    uint64_t  delivered;
    uint64_t  overflows;       /**< Values with the Overflow info bit. */
} ta_opcua_item;

struct ta_opcua_sub {
    struct ta_opcua_sub *next;
    ta_opcua_client *client;
    uint32_t  id;              /**< Server SubscriptionId. */
    bool      deleted;         /**< Deleted by us or by the server. */
    uint32_t  last_status;     /**< Last StatusChangeNotification. */
    uint64_t  seq;             /**< Local delivery ordinal. */
    uint64_t  batches;         /**< PublishResponses that carried data. */
    uint64_t  last_batch;      /**< Client publish counter at last data. */
    uint64_t  inactivity;      /**< Inactivity callbacks. */
    ta_opcua_item *items;
    ta_opcua_note *head;
    ta_opcua_note *tail;
    size_t    queued;
    uint64_t  dropped;         /**< Local queue overflow (never silent). */
};

struct ta_opcua_client {
    UA_Client      *ua;
    pthread_mutex_t lock;      /**< Every use of ua. */
    pthread_mutex_t qlock;     /**< Notification queues. */
    pthread_cond_t  qcond;     /**< Signalled on a new notification. */
    pthread_t       thread;
    bool            running;
    bool            stop;
    unsigned int    iterate_ms;
    char           *endpoint;
    char           *params;    /**< Kept for reconnect; holds secrets. */

    /* Connection history, filled by the state callback. */
    UA_SecureChannelState chan;
    UA_SessionState       sess;
    UA_StatusCode         connect_status;
    unsigned int max_chan;     /**< Furthest channel state reached. */
    unsigned int max_sess;     /**< Furthest session state reached. */
    uint64_t  channels_opened;
    uint64_t  sessions_created;
    uint64_t  sessions_activated;
    uint64_t  session_changes; /**< Authentication token changed. */
    uint64_t  publish_responses;
    UA_NodeId auth_token;      /**< Of the active session. */

    ta_opcua_sub *subs;
};

/** Find the subscription with server id @p id (qlock held). */
extern ta_opcua_sub *client_sub_by_id(ta_opcua_client *c, uint32_t id);
/** Free a subscription's queue and items (no server call). */
extern void sub_free_local(ta_opcua_sub *s);

/** Build the client config from options (client unit, also perf). */
extern int client_configure(UA_ClientConfig *cc, const char *params,
                            ta_opcua_out *out);

#endif /* !__TA_OPCUA_INT_H__ */
