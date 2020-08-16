#!/bin/bash

cd "$(dirname "$0")"
set -xe

cd cmake-build
if [[ "$OSTYPE" == "darwin"* ]]; then
    binary='iblessing-darwin'
else
    binary='iblessing-linux'
fi

./${binary} -m scan -i objc-msg-xref -f ../iblessing/iblessing/tests/benchmark/iblessing-sample.benchmark
./${binary} -m test
