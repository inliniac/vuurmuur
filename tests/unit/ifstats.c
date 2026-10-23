/*
 * vuurmuur - linux firewall management tool
 *
 * vrmr_get_iface_stats_from_ipt(): the counters of the first rules in a chain
 * must be readable, and a listing that cannot be anchored must not read as
 * zero traffic.
 *
 * (c) Victor Julien <victor@vuurmuur.org>
 */

#include "config.h"

#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <inttypes.h>
#include <limits.h>

#include "vuurmuur.h"

#include "../lib/tap.h"
#include "../lib/vrmr_test.h"
#include "../lib/sandbox.h"

/* printf-style wrapper over tap_ok, as in the generation driver */
static void t_ok(int cond, const char *fmt, ...)
{
    char msg[512];
    va_list args;

    va_start(args, fmt);
    (void)vsnprintf(msg, sizeof(msg), fmt, args);
    va_end(args);

    tap_ok(cond, msg);
}

/* abs_srcdir is exported by AM_TESTS_ENVIRONMENT */
static const char *cases_root(char *buf, size_t size)
{
    const char *src = getenv("abs_srcdir");

    (void)snprintf(buf, size, "%s/cases", src != NULL ? src : ".");

    return buf;
}

static const char *fixtures_root(char *buf, size_t size)
{
    const char *src = getenv("abs_srcdir");

    (void)snprintf(buf, size, "%s/unit/fixtures", src != NULL ? src : ".");

    return buf;
}

static void test_forward_counters(void)
{
    char root[PATH_MAX];
    struct vrmr_config cfg;
    uint64_t rx_packets = 0, rx_bytes = 0, tx_packets = 0, tx_bytes = 0;
    int r;

    memset(&cfg, 0, sizeof(cfg));
    (void)strlcpy(cfg.iptables_location, "/sbin/iptables",
            sizeof(cfg.iptables_location));

    if (vrmr_test_sandbox_setup(cases_root(root, sizeof(root)), "counters") != 0) {
        t_ok(0, "sandbox setup failed");
        return;
    }

    /* the fixture puts the eth1 accounting pair in the first two rule lines,
     * which is where a fixed line-count skip never looks */
    r = vrmr_get_iface_stats_from_ipt(&cfg, "eth1", "FORWARD",
            &rx_packets, &rx_bytes, &tx_packets, &tx_bytes);

    t_ok(r == 0 && rx_packets == 111 && rx_bytes == 1110 &&
            tx_packets == 222 && tx_bytes == 2220,
            "counters of the first rules in the chain are read "
            "(r=%d rx=%" PRIu64 "/%" PRIu64 " tx=%" PRIu64 "/%" PRIu64 ")",
            r, rx_packets, rx_bytes, tx_packets, tx_bytes);

    vrmr_test_sandbox_teardown();
}

static void test_headerless_listing(void)
{
    char root[PATH_MAX];
    struct vrmr_config cfg;
    uint64_t a = 0, b = 0;
    int r;

    memset(&cfg, 0, sizeof(cfg));
    (void)strlcpy(cfg.iptables_location, "/sbin/iptables",
            sizeof(cfg.iptables_location));

    if (vrmr_test_sandbox_setup(fixtures_root(root, sizeof(root)), "headerless") != 0) {
        t_ok(0, "sandbox setup failed");
        return;
    }

    /* cap_read refuses such a fixture and hands over an empty answer, so what
     * is being pinned here is that the parser reads that as a failure and not
     * as zero traffic: a kernel without the table also answers empty, and the
     * two must not be conflated by the caller */
    r = vrmr_get_iface_stats_from_ipt(&cfg, "eth1", "FORWARD", &a, &b, &a, &b);
    t_ok(r < 0, "a listing without a column header fails instead of zeroing (%d)", r);

    vrmr_test_sandbox_teardown();
}

int main(void)
{
    if (vrmr_test_setup() != 0) {
        fprintf(stderr, "ctx setup failed\n");
        return 1;
    }

    test_forward_counters();
    test_headerless_listing();

    return (tap_finish() != 0) ? 1 : 0;
}
