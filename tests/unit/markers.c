/*
 * vuurmuur - linux firewall management tool
 *
 * the fixture problem channel: a marker recorded during setup has to reach the
 * artifact, and one case must not inherit the complaints of the previous one.
 * The generation driver resets the command log between the load and the apply
 * phase, which is where the walkers' markers used to disappear.
 *
 * (c) Victor Julien <victor@vuurmuur.org>
 */

#include "config.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <limits.h>

#include "vuurmuur.h"

#include "../lib/tap.h"
#include "../lib/vrmr_test.h"
#include "../lib/sandbox.h"

static void t_ok(int cond, const char *fmt, ...)
{
    char msg[512];
    va_list args;

    va_start(args, fmt);
    (void)vsnprintf(msg, sizeof(msg), fmt, args);
    va_end(args);

    tap_ok(cond, msg);
}

static const char *cases_root(char *buf, size_t size)
{
    const char *src = getenv("abs_srcdir");

    (void)snprintf(buf, size, "%s/cases", src != NULL ? src : ".");

    return buf;
}

#define MARKER "# selftest: recorded before the reset"

static int rendered(char *out, size_t size)
{
    int len = vrmr_test_render(out, size);

    return len > 0 ? len : -1;
}

static void test_marker_lifetime(void)
{
    char root[PATH_MAX];
    char *out = malloc(64 * 1024);
    int len;

    if (out == NULL) {
        t_ok(0, "out of memory");
        return;
    }

    if (vrmr_test_sandbox_setup(cases_root(root, sizeof(root)), "simple") != 0) {
        t_ok(0, "sandbox setup failed");
        free(out);
        return;
    }

    /* this is the position dyn_fixtures and proc_add_device are in: setup has
     * not finished, so nothing has been rendered yet */
    vrmr_test_fixture_problem(MARKER);

    len = rendered(out, 64 * 1024);
    t_ok(len > 0 && strstr(out, MARKER) != NULL,
            "a marker recorded during setup reaches the artifact");

    /* generate_once() separates loading from applying with exactly this call */
    vrmr_test_effects_reset();

    len = rendered(out, 64 * 1024);
    t_ok(len > 0 && strstr(out, MARKER) != NULL,
            "the mid-case command-log reset keeps the markers");

    vrmr_test_sandbox_teardown();

    /* and the next case must start clean, or a stale marker would fail a green
     * corpus forever after the one problem that produced it */
    if (vrmr_test_sandbox_setup(cases_root(root, sizeof(root)), "simple") != 0) {
        t_ok(0, "sandbox setup failed (second case)");
        free(out);
        return;
    }

    len = rendered(out, 64 * 1024);
    t_ok(len > 0 && strstr(out, "# selftest") == NULL,
            "setup clears the previous case's markers");

    vrmr_test_sandbox_teardown();

    free(out);
}

/* The guard is pure mechanism: no case can trip it, because no fixture path is
 * long enough. Deleting the check leaves the corpus at 6/6 and the plans
 * unchanged, so it is pinned here rather than by a golden.
 */
static void test_join_guard(void)
{
    char root[PATH_MAX];
    char big[2 * PATH_MAX];
    char small[16];
    char *out = malloc(64 * 1024);
    int len;

    if (out == NULL) {
        t_ok(0, "out of memory");
        return;
    }

    if (vrmr_test_sandbox_setup(cases_root(root, sizeof(root)), "simple") != 0) {
        t_ok(0, "sandbox setup failed (guard)");
        free(out);
        return;
    }

    /* positive control: the helper is not just a failure channel */
    t_ok(vrmr_test_join_path(small, sizeof(small), "/tmp", "a")
            && strcmp(small, "/tmp/a") == 0,
            "a join that fits is built and reported as good (%s)", small);

    (void)snprintf(big, sizeof(big), "%s/%s", root,
            "a-name-that-cannot-possibly-fit-in-the-destination");

    small[0] = '\0';
    t_ok(!vrmr_test_join_path(small, sizeof(small), big, "x"),
            "a destination that cannot hold its sources is refused");

    /* and refusing is not enough: the caller has to be able to find out later
     * what was lost, which is the marker channel this file exists for
     */
    len = rendered(out, 64 * 1024);
    t_ok(len > 0 && strstr(out, "# too large:") != NULL,
            "the refusal is recorded, not just returned");

    small[0] = '\0';
    t_ok(!vrmr_test_cat_path(small, sizeof(small), big, "/iptables"),
            "cat_path refuses what join_path refuses");

    vrmr_test_sandbox_teardown();

    free(out);
}

int main(void)
{
    if (vrmr_test_setup() != 0) {
        fprintf(stderr, "ctx setup failed\n");
        return 1;
    }

    test_marker_lifetime();
    test_join_guard();

    return (tap_finish() != 0) ? 1 : 0;
}
