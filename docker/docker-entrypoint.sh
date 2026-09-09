#!/bin/bash
set -e

if [[ ! "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "ERROR: Invalid VERSION: $VERSION"
    echo "Expected format: MAJOR.MINOR.PATCH"
    exit 1
fi

IFS=. read -r version_major version_minor version_patch <<< "$VERSION"

echo "Building sampgdk version ${version_major}.${version_minor}.${version_patch}"

SDK_DIR="$PWD/build/samp-plugin-sdk"
rm -rf "$SDK_DIR"

git clone --depth 1 https://github.com/maddinat0r/samp-plugin-sdk.git "$SDK_DIR"

cmake \
    -S "$PWD" \
    -B "$PWD/build" \
    -DSAMP_SDK_ROOT="$SDK_DIR" \
    -DSAMPGDK_BUILD_AMALGAMATION=ON \
    -DSAMPGDK_VERSION_MAJOR="$version_major" \
    -DSAMPGDK_VERSION_MINOR="$version_minor" \
    -DSAMPGDK_VERSION_PATCH="$version_patch" \
    -DCMAKE_BUILD_TYPE="$CONFIG"

cmake --build "$PWD/build"
