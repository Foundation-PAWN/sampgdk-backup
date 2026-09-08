#!/bin/bash
set -e

SDK_DIR="$PWD/build/samp-plugin-sdk"
rm -rf "$SDK_DIR"

git clone --depth 1 https://github.com/maddinat0r/samp-plugin-sdk.git "$SDK_DIR"

cmake \
    -S "$PWD" \
    -B "$PWD/build" \
    -DSAMP_SDK_ROOT="$SDK_DIR" \
    -DSAMPGDK_BUILD_AMALGAMATION=ON \
    -DCMAKE_BUILD_TYPE="$CONFIG"

cmake --build "$PWD/build"
