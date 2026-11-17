/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Interpretica, Unipessoal Lda. All rights reserved. */
/** @file
 * @brief OPC UA TAPI: address-space browsing
 *
 * @addtogroup tapi_opcua
 * @{
 *
 * Inspecting the server's address space: browse a node's references,
 * continue a bounded browse, translate a browse path to a NodeId, read
 * a node's attributes, and read the namespace array. Each returns a
 * report of records the test reads with ::tapi_opcua_report_next and
 * ::tapi_opcua_kv_parse_record. NodeIds are text ("ns=2;s=Temperature",
 * "i=85"); namespace indices are not assumed stable across restarts, so
 * a test should resolve a URI or a browse path rather than hard-code an
 * index.
 */

#ifndef __TAPI_OPCUA_BROWSE_H__
#define __TAPI_OPCUA_BROWSE_H__

#include "tapi_opcua.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Browse the references of @p node. @p refs gets a record per
 * reference (node, browse_name, display_name, class, reference,
 * forward, type_definition); when the server returns a continuation
 * point, it is in the result of the call, obtained through @p cont
 * (NULL to ignore). @p max_refs 0 = server default.
 */
extern te_errno tapi_opcua_browse(tapi_opcua_conn *conn, const char *node,
                                  int max_refs, te_string *refs,
                                  te_string *cont);

/** Continue a browse from a continuation point (hex, from a browse). */
extern te_errno tapi_opcua_browse_next(tapi_opcua_conn *conn,
                                       const char *cont, te_string *refs);

/**
 * Translate a browse @p path (slash-separated "<ns>:<name>" elements,
 * e.g. "2:Boiler/2:Temperature") from @p start to its target NodeIds,
 * returned as a report in @p targets.
 */
extern te_errno tapi_opcua_translate_browse_path(tapi_opcua_conn *conn,
                                                 const char *start,
                                                 const char *path,
                                                 te_string *targets);

/** Read a node's attributes (class, browse/display name, data type,
 *  access) into @p info. */
extern te_errno tapi_opcua_read_node_info(tapi_opcua_conn *conn,
                                          const char *node,
                                          tapi_opcua_kv *info);

/** The server's namespace array, as a report (index, uri records). */
extern te_errno tapi_opcua_namespaces(tapi_opcua_conn *conn,
                                      te_string *namespaces);

/** Does the report @p refs name a node with browse name @p browse_name?
 *  (A convenience over ::tapi_opcua_report_next.) */
extern bool tapi_opcua_refs_have(const char *refs, const char *browse_name);

#ifdef __cplusplus
} /* extern "C" */
#endif
/**@} */
#endif /* !__TAPI_OPCUA_BROWSE_H__ */
