# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Interpretica, Unipessoal Lda. All rights reserved.
#
# External TE library (see TE_EXT_REPO): engine-side TAPI for OPC UA on
# agents. Built as a shared library on the engine platform. It needs the
# opcua_* RPCs in rpcxdr, so add ../ta_opcua/opcua_rpc.x.m4 to the
# rpcxdr definitions of the engine platform.

if get_option('engine')
    build_lib_shared = true
endif
build_lib_static = not get_option('engine')
install_lib = install_dev

headers += files(
    'tapi_opcua.h',
    'tapi_opcua_browse.h',
    'tapi_opcua_subscription.h',
    'tapi_opcua_server.h',
    'tapi_opcua_security.h',
    'tapi_opcua_cybersec.h',
    'tapi_opcua_rpc.h',
)

sources += files(
    'tapi_opcua.c',
    'tapi_opcua_browse.c',
    'tapi_opcua_subscription.c',
    'tapi_opcua_server.c',
    'tapi_opcua_security.c',
    'tapi_opcua_rpc.c',
)

te_libs += [
    'tapi',
    'tapi_rpc',
    'rcfrpc',
    'confapi',
    'rcfapi',
    'rpcxdr',
    'logger_core',
    'tools',
]
