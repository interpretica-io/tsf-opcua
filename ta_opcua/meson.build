# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Interpretica, Unipessoal Lda. All rights reserved.
#
# External TE library (see TE_EXT_REPO): agent-side OPC UA. The engine
# is a plain-C core (no TE header, testable on its own through ci/) over
# open62541's C API - a client that runs its own event-loop thread, the
# subscription machinery, an optional simulated server and test
# certificate helpers. It is linked and called in-process in the agent's
# RPC server: nothing is spawned, no OPC UA command-line tool is run, and
# nothing of a session leaves the agent but bounded reports.

headers += files(
    'ta_opcua.h',
)

sources += files(
    'ta_opcua.c',
    'ta_opcua_util.c',
    'ta_opcua_client.c',
    'ta_opcua_subscription.c',
    'ta_opcua_server.c',
    'ta_opcua_cert.c',
)

te_libs += [
    'logger_core',
    'tools',
]

cc = meson.get_compiler('c')

# open62541 (Debian trixie: libopen62541-1.4-dev; built from source on
# older releases). Required - without it ta_opcua cannot be built, and a
# suite that needs OPC UA has nothing to run against.
opcua_dep = dependency('open62541', required: false)
if not opcua_dep.found()
    opcua_dep = cc.find_library('open62541', required: true)
endif
deps += [ opcua_dep ]
deps += [ dependency('threads') ]

# Some open62541 pkg-config files emit OpenSSL as "-l/abs/path/lib.so"
# (a full path carrying a stray -l) which the linker then cannot find.
# When open62541 was found through pkg-config, re-expose its OpenSSL
# dependency cleanly so the agent application links.
if opcua_dep.type_name() == 'pkgconfig'
    foreach lib : [ 'ssl', 'crypto' ]
        d = cc.find_library(lib, required: false)
        if d.found()
            deps += [ d ]
        endif
    endforeach
endif
