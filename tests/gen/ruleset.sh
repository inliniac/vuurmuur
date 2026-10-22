#!/bin/sh
# Golden tests over the ruleset generation. Update the goldens with
#   make check UPDATE=--update

set -e

if [ -z "${abs_srcdir}" ]; then
    echo "1..0 # SKIP abs_srcdir not set"
    exit 0
fi

# The artifact carries translated strings on the audit lines, so the corpus must
# not depend on the locale of whoever ran make check.
LC_ALL=C
export LC_ALL

CASES="${abs_srcdir}/cases"
GOLDEN="${abs_srcdir}/golden"

names=""
for dir in "${CASES}"/*/; do
    name=$(basename "${dir}")
    # common holds the fixtures every case builds on
    [ "${name}" = common ] && continue
    [ -d "${dir}" ] || continue
    names="${names} ${name}"
done

exec ./gen/ruleset "${CASES}" "${GOLDEN}" ${names} ${UPDATE-}
