#!/bin/bash
set -e

# Available configs: Release
[[ -z "$CONFIG" ]] \
&& config=Release \
|| config="$CONFIG"
# Available container runtimes: [docker], podman, other 
[[ -z "$CONTAINER_RUNTIME" ]] \
&& container_runtime=docker \
|| container_runtime="$CONTAINER_RUNTIME"
[[ "$container_runtime" == "podman" ]] \
&& volume_suffix=":Z" \
|| volume_suffix=""
[[ "$container_runtime" == "podman" ]] \
&& userns_option="--userns=keep-id" \
|| userns_option=""
# Available build names: sampgdk
[[ -z "$BUILDNAME" ]] \
&& buildname=sampgdk \
|| buildname="$BUILDNAME"

# Detect where this script is located at regardless of from where it is launched
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

"$container_runtime" build -t "${buildname}/build:ubuntu-20.04" "$SCRIPT_DIR" || exit 1

BUILD_DIR="$SCRIPT_DIR/../build"
if [[ ! -d "$BUILD_DIR" ]]; then
    mkdir "$BUILD_DIR"
fi

# Determine uid/gid so we can run the container with our own uid/gid
USER_UID="$(id -u)"
USER_GID="$(id -g)"

"$container_runtime" run \
    --rm \
    $userns_option \
    --user "$USER_UID:$USER_GID" \
    -t \
    -w /code \
    -v "$SCRIPT_DIR/..:/code${volume_suffix}" \
    -e "CONFIG=${config}" \
    "${buildname}/build:ubuntu-20.04"
