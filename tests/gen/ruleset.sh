#!/bin/sh
# Golden tests over the ruleset generation. Update the goldens with
#   make check UPDATE=--update

set -e

# Running this by hand leaves abs_srcdir unset. Skipping then reports a plan of
# zero, which is green, and green is the wrong answer for a suite that compared
# nothing: the corpus cannot be located without that path.
if [ -z "${abs_srcdir}" ]; then
    echo "1..1"
    echo "not ok 1 - abs_srcdir not set: run this through 'make check'"
    exit 1
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

# Both sides of the corpus have to be walked: the driver only generates the
# cases it is handed, so a golden whose case was renamed or deleted is compared
# against nothing and the suite stays green.
for f in "${GOLDEN}"/*.txt; do
    [ -e "${f}" ] || continue
    name=$(basename "${f}" .txt)
    case " ${names} " in
        *" ${name} "*) ;;
        *)
            echo "not ok - golden ${name}.txt has no case under ${CASES}"
            exit 1
            ;;
    esac
done

exec ./gen/ruleset "${CASES}" "${GOLDEN}" ${names} ${UPDATE-}
