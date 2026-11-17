#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Interpretica, Unipessoal Lda. All rights reserved.
#
# Contract test of the tsf-opcua core without Test Environment: build
# ci/opcua_cli with the sanitizers (ci/build-core.sh), then run its
# selftest, which starts the simulated OPC UA server and drives a client
# against it (connect, discover, browse, read, write, call, subscribe,
# collect a value change). Exits non-zero on the first broken contract.
set -euo pipefail
cd "$(dirname "$0")/.."
OUT="${OUT:-build-ci}"
case "$OUT" in /*) ;; *) OUT="$PWD/$OUT" ;; esac
OUT="$OUT" ./ci/build-core.sh

export LSAN_OPTIONS="suppressions=$PWD/ci/lsan.supp:print_suppressions=0"
export ASAN_OPTIONS="abort_on_error=1:detect_leaks=1"
echo "== features =="
"$OUT/opcua_cli" features
echo "== selftest =="
"$OUT/opcua_cli" selftest
echo "all core contracts hold"
