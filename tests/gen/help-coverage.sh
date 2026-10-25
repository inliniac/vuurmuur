#!/bin/sh
# Every help key the GUI offers must have text in the English help file.
#
# The keys are :[KEY]: patterns in the vuurmuur_conf sources - comments included,
# deliberately, since over-demanding help is the safe direction - and the text
# lives in help/vuurmuur.hlp. Nothing in the build links the two, so a screen can
# gain a help key and quietly show a blank screen: VUURMUUR:INTERFACES:TCPMSS was
# reachable from the interface editor for years with no section behind it.
#
# Keys held in struct fields are covered too: statevent.c:910-921 assigns the
# :[KEY]: literals to ctl->help_overview / ctl->help_actions, which the
# print_help(ctl->help_*) call sites then pass through.

set -e

if [ -z "${abs_srcdir}" ]; then
    echo "1..1"
    echo "not ok 1 - abs_srcdir not set: run this through 'make check'"
    exit 1
fi

LC_ALL=C
export LC_ALL

TOP="${abs_srcdir}/.."
CONF="${TOP}/vuurmuur_conf"
HELP="${TOP}/help/vuurmuur.hlp"

if [ ! -d "${CONF}" ] || [ ! -f "${HELP}" ]; then
    echo "1..1"
    echo "not ok 1 - cannot locate ${CONF} or ${HELP}"
    exit 1
fi

# Every :[KEY]: pattern in the GUI sources, minus the section terminator the
# parser in help.c compares against. help.c holds the literal, so the scan finds
# it; a terminator names no screen, and the body test below would never pass it.
keys=$(awk 'match($0, /:\[[A-Za-z0-9_:]+\]:/) {
        print substr($0, RSTART + 2, RLENGTH - 4)
    }' "${CONF}"/*.c | sort -u | grep -vx END || true)

# The sections the help file can actually serve: a header alone is not enough,
# because read_helpfile() (help.c:208-214) breaks at the terminator without
# reading a line, so an empty section draws the same blank window as no section.
# The terminator has to be tested first: :[END]: matches the header pattern too,
# so letting that rule win would name every section END and serve nothing.
secs=$(awk '
    /^:\[END\]:$/ { if (key != "" && body) print key; key = ""; next }
    /^:\[[A-Za-z0-9_:]+\]:$/ { key = substr($0, 3, length($0) - 4); body = 0; next }
    key != "" && NF { body = 1 }
' "${HELP}" | sort -u)

n=$(printf '%s\n' "${keys}" | grep -c . || true)
if [ "${n}" -eq 0 ]; then
    echo "1..1"
    echo "not ok 1 - no help keys found in ${CONF}: the scan matched nothing"
    exit 1
fi

echo "1..${n}"

i=0
fails=0
for key in ${keys}; do
    i=$((i + 1))
    if printf '%s\n' "${secs}" | grep -qx -- "${key}"; then
        echo "ok ${i} - ${key}"
    else
        echo "not ok ${i} - ${key} has no text in help/vuurmuur.hlp"
        fails=$((fails + 1))
    fi
done

# Never exit ${fails}: automake reads 77 as SKIP and >=128 as XFAIL/ERROR, so a
# failure count can land on a status the harness reports as not-a-failure.
if [ "${fails}" -gt 0 ]; then
    echo "# failed ${fails} of ${n}" >&2
    exit 1
fi
exit 0
