#!/usr/bin/env bash

set -eo pipefail

script_path=$(cd -P -- "$(dirname -- "$0")" && pwd -P)
cd "${script_path}/.."

if [ -z "${MARKDOWN_CHECK_BINARY:-}" ] ; then
    if ! [ -d Build/lagom/ ] ; then
        echo "Directory Build/lagom/ does not exist. Skipping markdown check."
        exit 0
    fi
    if ! [ -r Build/lagom/bin/markdown-check ] ; then
        echo "Lagom executable markdown-check was not built. Skipping markdown check."
        echo "To enable this check, you may need to run './Meta/serenity.sh build lagom' first."
        exit 0
    fi
    MARKDOWN_CHECK_BINARY="Build/lagom/bin/markdown-check"
fi

if [ -z "$SERENITY_SOURCE_DIR" ] ; then
    SERENITY_SOURCE_DIR=$(pwd -P)
    export SERENITY_SOURCE_DIR
fi

# shellcheck disable=SC2086 # Word splitting is intentional here
find AK Base Documentation Meta Tests Userland -path Tests/LibWeb/WPT/wpt -prune -o -type f -name '*.md' -print0 | xargs -0 "${MARKDOWN_CHECK_BINARY}" -b "${SERENITY_SOURCE_DIR}/Base" $EXTRA_MARKDOWN_CHECK_ARGS README.md CONTRIBUTING.md
