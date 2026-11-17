#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Interpretica, Unipessoal Lda. All rights reserved.
#
# Build the tsf-opcua core and ci/opcua_cli without Test Environment,
# with AddressSanitizer and UndefinedBehaviorSanitizer, against an
# installed open62541 (pkg-config name open62541). Output:
# ${OUT:-build-ci}/opcua_cli.
set -euo pipefail
cd "$(dirname "$0")/.."
OUT="${OUT:-build-ci}"
SAN="${SAN--fsanitize=address,undefined -fno-omit-frame-pointer}"
mkdir -p "$OUT"

if ! pkg-config --exists open62541; then
    echo "open62541 not found by pkg-config" >&2
    exit 1
fi
CFLAGS="-std=c11 -D_GNU_SOURCE -O1 -g -Wall -Wextra -Werror \
        -Wno-unused-parameter $SAN $(pkg-config --cflags open62541)"
# Some open62541 pkg-config files list OpenSSL as "-l/abs/path/libssl.so"
# (a full path with a stray -l). Turn each such token back into a plain
# path the linker accepts.
LIBS="$(pkg-config --libs open62541 | sed -E 's#-l(/[^ ]+)#\1#g') -lpthread"

objs=()
for f in ta_opcua/ta_opcua_util.c ta_opcua/ta_opcua_client.c \
         ta_opcua/ta_opcua_subscription.c ta_opcua/ta_opcua_server.c \
         ta_opcua/ta_opcua_cert.c ci/opcua_cli.c; do
    o="$OUT/$(basename "${f%.c}").o"
    cc $CFLAGS -Ita_opcua -c "$f" -o "$o"
    objs+=("$o")
done
cc $SAN "${objs[@]}" $LIBS -o "$OUT/opcua_cli"
echo "built $OUT/opcua_cli"
