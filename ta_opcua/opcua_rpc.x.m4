/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Interpretica, Unipessoal Lda. All rights reserved. */
/** @file
 * @brief RPC for OPC UA
 *
 * The RPCs of rpcs_opcua, a thin layer over ta_opcua (see ta_opcua.h),
 * which keeps OPC UA clients, subscriptions and simulated servers in
 * the agent's RPC server process and talks to servers over open62541.
 * Add this file to the rpcxdr definitions of the engine platform and of
 * the agent platform:
 *
 *   TE_LIB_PARMS([rpcxdr], [<platform>], [],
 *                [--with-rpcdefs=tarpc_job.x.m4,../ta_opcua/opcua_rpc.x.m4])
 *
 * Every RPC has the same shape: two handles (h1 a client or server, h2
 * a subscription), three text arguments (arg a node/endpoint/method/
 * path, params options as "key=value" lines, data a payload) and back a
 * return code, a new handle, a feature bitmask, an OPC UA StatusCode, a
 * connection failure class and three strings - result ("key=value"
 * lines), report (records of tab-separated fields) and errmsg. XDR
 * carries no portable floating point and no NodeId; both travel inside
 * the text, which tapi_opcua parses. Sessions, secure channels and
 * subscription queues stay on the agent; only bounded samples and
 * reports cross the wire.
 *
 * A connection secret (sql-style: the password, a private key) is
 * carried inside @c params and nowhere else: the agent never logs it.
 *
 * Field names avoid the RPC language's keywords ("version", "program",
 * "string").
 */

/* opcua_available(): which open62541 features are in this agent; the
 * feature bitmask is in @c features and the versions in @c result. */
struct tarpc_opcua_available_in {
    struct tarpc_in_arg common;

    tarpc_int       op;
    tarpc_int       h1;
    tarpc_int       h2;
    string          arg<>;
    string          params<>;
    string          data<>;
};

struct tarpc_opcua_available_out {
    struct tarpc_out_arg common;

    tarpc_int       retval;
    tarpc_int       handle;
    tarpc_uint      features;
    tarpc_uint      status;
    tarpc_int       fail_cls;
    string          result<>;
    string          report<>;
    string          errmsg<>;
};

/* opcua_call(): every other operation. The op field (ta_opcua_op)
 * selects it; the arguments and results are the same as above. */
struct tarpc_opcua_call_in {
    struct tarpc_in_arg common;

    tarpc_int       op;
    tarpc_int       h1;
    tarpc_int       h2;
    string          arg<>;
    string          params<>;
    string          data<>;
};

struct tarpc_opcua_call_out {
    struct tarpc_out_arg common;

    tarpc_int       retval;
    tarpc_int       handle;
    tarpc_uint      features;
    tarpc_uint      status;
    tarpc_int       fail_cls;
    string          result<>;
    string          report<>;
    string          errmsg<>;
};

program opcua
{
    version ver0
    {
        RPC_DEF(opcua_available)
        RPC_DEF(opcua_call)
    } = 1;
} = 47;
