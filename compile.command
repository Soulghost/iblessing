#!/bin/bash

# todo: use fakeroot
cd "$(dirname "$0")"

set -xe
cd submodules/capstone
make
cd ../..

cd submodules/unicorn
UNICORN_ARCHS="arm aarch64 x86" ./make.sh
cd ../..

cd submodules/keystone
mkdir -p build
cd build
../make-lib.sh
cd ../../..

cp submodules/capstone/libcapstone.a                iblessing/iblessing/vendor/libs/
cp submodules/unicorn/libunicorn.a                  iblessing/iblessing/vendor/libs/
cp submodules/keystone/build/llvm/lib/libkeystone.a iblessing/iblessing/vendor/libs/

cd iblessing
xcodebuild archive -target iblessing -configuration Release
cd ..
mkdir -p build
mv iblessing/build/UninstalledProducts/macosx/iblessing build/
