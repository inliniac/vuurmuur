/*
 *   Copyright (C) 2002-2026 by Victor Julien / vuurmuur.org
 *
 *   Tests vrmr_log_record_get_names() (lib/log.c), which decides what a resolved
 *   and an unresolved service look like in traffic.log. The man page now states
 *   that notation as a public contract (man/en/vuurmuur_log.8, FILES), so every
 *   assertion here is a byte compare against one of the five renderings the
 *   function actually has.
 *
 *   No iptables, no /etc/vuurmuur, no /proc, no network. Both hash tables are
 *   real tables built in this file, because the production callbacks are static
 *   to the backend; the entries are only ever reached through get_names().
 */

#include "config.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "vuurmuur.h"

#include "../lib/tap.h"
#include "../lib/vrmr_test.h"

/* ------------------------------------------------------------------ tables */

/*
 * The tables are built with the callbacks the daemon itself installs
 * (lib/config.c:1771 and :1778): vrmr_hash_port/vrmr_compare_ports for services,
 * vrmr_hash_ipaddress/vrmr_compare_ipaddress for zones. Nothing here is a
 * simplified stand-in for a matching rule, which matters because the whole point
 * of these assertions is which of the five renderings a lookup decision picks.
 *
 * Two details of those callbacks are load-bearing. vrmr_hash_search() decides
 * with `if (hash_table->compare_func(table_data, search_data))`, so NONZERO means
 * match - the opposite of the qsort habit. And vrmr_compare_ports() reads one
 * node off each list: the request's is built by lib/hash.c, an entry's must be
 * appended here, because a service with no port range never matches at all
 * (lib/hash.c:233).
 */
static void t_ok(int cond, const char *fmt, ...);

static struct vrmr_hash_table zone_hash, service_hash;

/* the key is a small port or protocol number, so rows only spread it a little */
#define HASH_ROWS 16

static int tables_setup(void)
{
    if (vrmr_hash_setup(&service_hash, HASH_ROWS, vrmr_hash_port,
                    vrmr_compare_ports, NULL) != 0)
        return (0);
    if (vrmr_hash_setup(&zone_hash, HASH_ROWS, vrmr_hash_ipaddress,
                    vrmr_compare_ipaddress, NULL) != 0)
        return (0);
    return (1);
}

static void tables_teardown(void)
{
    struct vrmr_list_node *d_node = NULL;
    void *data = NULL;
    unsigned int row = 0;

    /* the tables were set up with no free callback, so the entries are ours */
    for (row = 0; row < HASH_ROWS; row++) {
        for (d_node = service_hash.table[row].top; d_node != NULL;
                d_node = d_node->next) {
            struct vrmr_service *s = d_node->data;
            struct vrmr_list_node *p_node = NULL;

            /*
             * vrmr_service_malloc() only allocates and zeroes; the free() on
             * PortrangeList is installed by the creators this fixture skips
             * (lib/services.c:215, :722). With free_func NULL, cleanup releases
             * the nodes and not the ranges, and ASan aborts on the leak. The
             * daemon leaks nothing here.
             */
            for (p_node = s->PortrangeList.top; p_node != NULL;
                    p_node = p_node->next)
                free(p_node->data);
            (void)vrmr_list_cleanup(&s->PortrangeList);
            free(s);
        }
        (void)vrmr_list_cleanup(&service_hash.table[row]);
        for (d_node = zone_hash.table[row].top; d_node != NULL;
                d_node = d_node->next) {
            data = d_node->data;
            (void)vrmr_list_cleanup(&((struct vrmr_zone *)data)->GroupList);
            free(data);
        }
        (void)vrmr_list_cleanup(&zone_hash.table[row]);
    }
}

/*
 * One service entry. hash_port is what the library buckets on; the range is
 * matched against the ports of the record. high == 0 means a single port rather
 * than a range, which is how the product spells an exact match, and a wildcard
 * source is 1..65535 because 0/0 would ask for an exact source of zero.
 */
static void add_service(int hash_port, const char *name, int protocol,
        int src_low, int src_high, int dst_low, int dst_high)
{
    struct vrmr_service *s = vrmr_service_malloc();
    struct vrmr_portdata *pd = malloc(sizeof(*pd));
    char msg[160];

    if (s == NULL || pd == NULL) {
        t_ok(0, "service %s allocated", name);
        return;
    }
    snprintf(s->name, sizeof(s->name), "%s", name);
    s->vrmr_hash_port = hash_port;
    pd->protocol = protocol;
    pd->src_low = src_low;
    pd->src_high = src_high;
    pd->dst_low = dst_low;
    pd->dst_high = dst_high;
    if (vrmr_list_append(&s->PortrangeList, pd) == NULL) {
        t_ok(0, "service %s port range appended", name);
        free(pd);
        free(s);
        return;
    }
    snprintf(msg, sizeof(msg), "service \"%s\" filed at hash port %d", name,
            hash_port);
    t_ok(vrmr_hash_insert(&service_hash, s) == 0, msg);
}

/*
 * A service with an empty PortrangeList. vrmr_compare_ports() bails on these before
 * it even looks at the protocol (lib/hash.c:233-234), which is a claim the file used
 * to make in a comment without ever testing it. hash_port is the record's dst port,
 * so the entry must be filed under the dst it should not answer.
 */
static void add_service_no_range(int hash_port, const char *name)
{
    struct vrmr_service *s = vrmr_service_malloc();
    char msg[160];

    if (s == NULL) {
        t_ok(0, "service %s allocated", name);
        return;
    }
    snprintf(s->name, sizeof(s->name), "%s", name);
    s->vrmr_hash_port = hash_port;
    snprintf(msg, sizeof(msg), "service \"%s\" filed with no port range", name);
    tap_ok(vrmr_hash_insert(&service_hash, s) == 0, msg);
}

/* one zone entry: an address, a name, and the type get_names() tests for firewall */
static void add_zone(const char *ip, const char *name, int type)
{
    struct vrmr_zone *z = vrmr_zone_malloc();
    char msg[128];

    if (z == NULL) {
        snprintf(msg, sizeof(msg), "zone for %s allocated", ip);
        tap_ok(0, msg);
        return;
    }
    snprintf(z->ipv4.ipaddress, sizeof(z->ipv4.ipaddress), "%s", ip);
    snprintf(z->name, sizeof(z->name), "%s", name);
    z->type = type;
    snprintf(msg, sizeof(msg), "zone \"%s\" filed for %s", name, ip);
    tap_ok(vrmr_hash_insert(&zone_hash, z) == 0, msg);
}

/* -------------------------------------------------------------- the record */

static void t_ok(int cond, const char *fmt, ...)
{
    char msg[256];
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);
    tap_ok(cond, msg);
}

/* only the fields get_names() reads; everything else plays no part here */
static void mk(struct vrmr_log_record *lr, int protocol, int src, int dst,
        int icmp_type, int icmp_code)
{
    memset(lr, 0, sizeof(*lr));
    lr->protocol = protocol;
    lr->src_port = src;
    lr->dst_port = dst;
    lr->icmp_type = icmp_type;
    lr->icmp_code = icmp_code;
    snprintf(lr->src_ip, sizeof(lr->src_ip), "%s", "192.0.2.1");
    snprintf(lr->dst_ip, sizeof(lr->dst_ip), "%s", "198.51.100.2");
    lr->ser_name[0] = '\0';
}

/* run get_names() on a filled record and compare the service name it wrote */
static void expect_service(struct vrmr_log_record *lr, const char *want)
{
    int rc = vrmr_log_record_get_names(lr, &zone_hash, &service_hash);
    char msg[192], desc[192];

    snprintf(msg, sizeof(msg), "proto %d ports %d/%d type %d code %d -> 1",
            lr->protocol, lr->src_port, lr->dst_port, lr->icmp_type,
            lr->icmp_code);
    tap_ok(rc == 1, msg);

    snprintf(desc, sizeof(desc), "ser_name for proto %d ports %d/%d type %d code %d",
            lr->protocol, lr->src_port, lr->dst_port, lr->icmp_type,
            lr->icmp_code);
    tap_str_eq(desc, lr->ser_name, want);
}

/* run it and compare what it decided the two ends of the line are called */
static void expect_names(struct vrmr_log_record *lr, const char *from,
        const char *to)
{
    char desc[128];

    snprintf(desc, sizeof(desc), "from_name with the table as configured");
    tap_str_eq(desc, lr->from_name, from);
    snprintf(desc, sizeof(desc), "to_name with the table as configured");
    tap_str_eq(desc, lr->to_name, to);
}

/* ------------------------------------------------------------------- parts */

/*
 * The five renderings of the service name, in the order the function reaches
 * them. The man page names one of them; this is all five.
 */
static void service_renderings(void)
{
    struct vrmr_log_record lr;

    /* 1 - unresolved tcp, both lookups miss: the port pair with the word tcp */
    mk(&lr, 6, 12345, 54321, -1, -1);
    expect_service(&lr, "12345->54321(tcp)");

    /* 2 - unresolved udp, same shape, different tag */
    mk(&lr, 17, 5353, 4444, -1, -1);
    expect_service(&lr, "5353->4444(udp)");

    /*
     * 3 - a protocol that is none of tcp, udp or icmp, with ports: the pair with
     * the protocol as a NUMBER. This is the only rendering the man page used to
     * give, and the rarest one an operator will ever see.
     */
    mk(&lr, 47, 1234, 5678, -1, -1);
    expect_service(&lr, "1234*5678(47)");

    /* 4 - the same protocol with neither port set */
    mk(&lr, 50, 0, 0, -1, -1);
    expect_service(&lr, "proto-50");

    /* 5 - a service that IS in the table: its name, copied */
    add_service(80, "http", 6, 1, 65535, 80, 0);
    mk(&lr, 6, 443, 80, -1, -1);
    expect_service(&lr, "http");

    /*
     * The reverse lookup, which is the reason a reply direction resolves: the
     * forward search keys on dst_port, finds nothing, and the reverse one keys on
     * src_port, where the service lives.
     */
    add_service(110, "pop3", 6, 1, 65535, 110, 0);
    mk(&lr, 6, 110, 9999, -1, -1);
    expect_service(&lr, "pop3");

    add_service(53, "dns", 17, 1, 65535, 53, 0);
    mk(&lr, 17, 53, 4445, -1, -1);
    expect_service(&lr, "dns");

    /*
     * A service that names a source port as well as a destination resolves only
     * in the direction it was written. This is the one record shape where the
     * reverse lookup's ARGUMENT ORDER is observable: the forward search keys on
     * dst_port and misses, the reverse keys on src_port with the ports swapped
     * into the request, and passing them the other way round falls back to the
     * numeric form. Without this case an argument swap in lib/log.c is invisible.
     */
    add_service(7, "echo-src", 6, 8080, 0, 7, 0);
    mk(&lr, 6, 7, 8080, -1, -1);
    expect_service(&lr, "echo-src");

    /*
     * The forward twin, in the direction the entry was written in: it must resolve
     * from lib/log.c:498 without ever reaching the reverse pass. This is the case
     * the file was missing - the bucket is keyed on dst_port alone
     * (lib/hash.c:574) and every entry but echo-src carries a wildcard source
     * range, so swapping the first two arguments of the forward call used to cost
     * the suite nothing at all across 36 calls.
     */
    mk(&lr, 6, 8080, 7, -1, -1);
    expect_service(&lr, "echo-src");

    /*
     * An entry with nothing in its PortrangeList must never resolve. The compare
     * bails before the protocol test, so this is the one service shape where
     * matching depends on an absence: make that bail a match and the name below
     * turns into "no-ranges".
     */
    add_service_no_range(9, "no-ranges");
    mk(&lr, 6, 9, 9, -1, -1);
    expect_service(&lr, "9->9(tcp)");

    /* the widest values the shapes can carry, which is where truncation would
     * first show up: 65535*65535(47) is 15 bytes into a 32 byte buffer */
    mk(&lr, 47, 65535, 65535, -1, -1);
    expect_service(&lr, "65535*65535(47)");
}

/*
 * The icmp path. The numeric form lib/log.c writes first is always overwritten
 * by vrmr_get_icmp_name_short(), which writes its buffer on every one of its
 * return paths, so "%d.%d(icmp)" never reaches traffic.log.
 */
static void icmp_names(void)
{
    struct vrmr_log_record lr;

    /* types with no codes are just the short name */
    mk(&lr, 1, 0, 0, 8, 0);
    expect_service(&lr, "echo");

    mk(&lr, 1, 0, 0, 0, 0);
    expect_service(&lr, "echo-reply");

    /* a type with codes, a code the table knows, and one it does not */
    mk(&lr, 1, 0, 0, 3, 3);
    expect_service(&lr, "dest-unreach(port)");

    mk(&lr, 1, 0, 0, 3, 1);
    expect_service(&lr, "dest-unreach(host)");

    mk(&lr, 1, 0, 0, 3, 44);
    expect_service(&lr, "dest-unreach(err:44)");

    /* code -1 asks for the type alone; the daemon never passes it, a re-read can */
    mk(&lr, 1, 0, 0, 3, -1);
    expect_service(&lr, "dest-unreach");

    /* a type the table does not have, at the one place that can reach it: the
     * loop runs to the end only for types 0..40, and 37 and 38 are the holes in
     * the IPv4 rows */
    mk(&lr, 1, 0, 0, 37, 0);
    expect_service(&lr, "unknown icmp (37.0)");

    /* the last IPv4 row, which has codes: code 0 is named, -1 asks type only */
    mk(&lr, 1, 0, 0, 40, 0);
    expect_service(&lr, "photuris(bad-spi)");

    mk(&lr, 1, 0, 0, 40, -1);
    expect_service(&lr, "photuris");

    /*
     * Above 40 the guard answers, and it answers in EVERY build: the branch is
     * `#ifndef HAVE_IPV6` (lib/icmp.c:37) while configure defines IPV6_ENABLED
     * (configure.ac:45), and nothing in the tree defines HAVE_IPV6 at all - a
     * git grep finds four hits, all of them this pair of guards and their twins
     * in lib/icmp.h. So the guard is always taken, "unknown icmp" is unreachable
     * above 40, and the icmpv6 rows in lib/icmp.h sit behind an #ifdef that never
     * resolves true, which is product issue #27. Pinned as-found, not as-intended:
     * when #27 lands these three assertions go red and the values become
     * echo-request / echo-reply / neigh-sollicit.
     */
    mk(&lr, 1, 0, 0, 41, 0);
    expect_service(&lr, "reserved icmp (41.0)");

    mk(&lr, 1, 0, 0, 200, 0);
    expect_service(&lr, "reserved icmp (200.0)");

    mk(&lr, 1, 0, 0, 255, 7);
    expect_service(&lr, "reserved icmp (255.7)");

    /* out of range types are refused by the first guard, which still writes a name */
    mk(&lr, 1, 0, 0, -1, 0);
    expect_service(&lr, "illegal icmp (-1.0)");

    mk(&lr, 1, 0, 0, 300, 0);
    expect_service(&lr, "illegal icmp (300.0)");

    /* icmpv6 through protocol 58: the names the table would give are compiled out */
    mk(&lr, 58, 0, 0, 128, 0);
    expect_service(&lr, "reserved icmp (128.0)");

    mk(&lr, 58, 0, 0, 135, 0);
    expect_service(&lr, "reserved icmp (135.0)");

    /*
     * For protocol 1 the service key the library builds is the TYPE, so a service
     * filed at hash port 8 answers for every echo request; the next assertion is
     * that entry doing exactly that.
     */
    add_service(8, "ping", 1, 1, 65535, 8, 0);
    mk(&lr, 1, 0, 0, 8, 0);
    expect_service(&lr, "ping");

    /*
     * For protocol 58 the service key the library builds is the PROTOCOL NUMBER,
     * not the type: lib/hash.c:583 is what runs, because 58 is neither 6, 17 nor 1
     * in that function. So one entry filed under 58 would answer for every icmpv6
     * record whatever its type - and today it would matter less than it looks,
     * because the guard above returns "reserved icmp" before the name is ever
     * consulted. Both facts are pinned here so #27 cannot fix one and lose the
     * other quietly. Nothing is installed at 58 in this file.
     */
    mk(&lr, 58, 0, 0, 129, 0);
    expect_service(&lr, "reserved icmp (129.0)");

    /*
     * An icmpv6 record resolves against whatever service is filed for protocol
     * 58, and the match ignores ports entirely: vrmr_compare_ports() ends with
     * "all other protos use no ports, so a proto match is a full match"
     * (lib/hash.c:284-287), so a table hit does not look at the type or the code
     * at all - one entry for 58 answers every icmpv6 record whatever it defines.
     * That is not the issue #27 bug; it is the same shape as the protocol-1 case
     * above, where the type at least is part of the key.
     */
    add_service(58, "sixtyeight", 58, 1, 65535, 0, 0);
    mk(&lr, 58, 0, 0, 128, 0);
    expect_service(&lr, "sixtyeight");
}

/* What the two ends of the line are called, which is the zone half. */
static void zone_names(void)
{
    struct vrmr_log_record lr;

    /* nothing behind either address: both names are the addresses themselves */
    mk(&lr, 6, 443, 80, -1, -1);
    t_ok(vrmr_log_record_get_names(&lr, &zone_hash, &service_hash) == 1,
            "a record with no zone behind it still returns 1");
    expect_names(&lr, "192.0.2.1", "198.51.100.2");

    /* an address that is in a zone of its own: the zone name is used */
    add_zone("192.0.2.1", "guest", VRMR_TYPE_ZONE);
    mk(&lr, 6, 443, 80, -1, -1);
    t_ok(vrmr_log_record_get_names(&lr, &zone_hash, &service_hash) == 1,
            "a record whose source is in a zone returns 1");
    expect_names(&lr, "guest", "198.51.100.2");

    /*
     * A network object is reported as the firewall whatever it is called - but only
     * for a table the daemon could not have built: the single path into a zone hash
     * admits VRMR_TYPE_HOST and VRMR_TYPE_FIREWALL and nothing else
     * (lib/hash.c:539-541), and even broadcast entries are retyped firewall
     * (lib/zones.c:891). So this pins the branch, not a line a user will read.
     */
    add_zone("198.51.100.2", "internal", VRMR_TYPE_NETWORK);
    mk(&lr, 6, 443, 80, -1, -1);
    t_ok(vrmr_log_record_get_names(&lr, &zone_hash, &service_hash) == 1,
            "a record whose destination is a hand-inserted network returns 1");
    expect_names(&lr, "guest", "firewall");

    /*
     * The overwrite is duplicated for the source side (lib/log.c:435-437 vs
     * 456-458), so the case above leaves that copy unrun; asserting one half of a
     * pair says nothing about the other. Same caveat: hand-inserted type, no path
     * from a running daemon.
     */
    add_zone("203.0.113.9", "edge", VRMR_TYPE_NETWORK);
    mk(&lr, 6, 1234, 22, -1, -1);
    snprintf(lr.src_ip, sizeof(lr.src_ip), "%s", "203.0.113.9");
    snprintf(lr.dst_ip, sizeof(lr.dst_ip), "%s", "192.0.2.1");
    t_ok(vrmr_log_record_get_names(&lr, &zone_hash, &service_hash) == 1,
            "a record whose source is a hand-inserted network returns 1");
    expect_names(&lr, "firewall", "guest");

    /*
     * The reachable naming, stated as the manual now states it: the name is the
     * object whose address equals the packet's, so a firewall's own address reads
     * firewall(<interface>) - the string is built at lib/interfaces.c:931 and typed
     * FIREWALL at :955, which is what lets it through the hash filter that stops a
     * network. The fixture files the finished string, exactly as the daemon would.
     */
    add_zone("203.0.113.11", "firewall(wan0)", VRMR_TYPE_FIREWALL);
    mk(&lr, 6, 1234, 22, -1, -1);
    snprintf(lr.src_ip, sizeof(lr.src_ip), "%s", "203.0.113.11");
    snprintf(lr.dst_ip, sizeof(lr.dst_ip), "%s", "192.0.2.1");
    t_ok(vrmr_log_record_get_names(&lr, &zone_hash, &service_hash) == 1,
            "a record from the firewall's own address returns 1");
    expect_names(&lr, "firewall(wan0)", "guest");

    /* a network's broadcast address arrives typed firewall, named <net>(broadcast) */
    add_zone("203.0.113.255", "outside(broadcast)", VRMR_TYPE_FIREWALL);
    mk(&lr, 6, 1234, 22, -1, -1);
    snprintf(lr.src_ip, sizeof(lr.src_ip), "%s", "203.0.113.255");
    snprintf(lr.dst_ip, sizeof(lr.dst_ip), "%s", "192.0.2.1");
    t_ok(vrmr_log_record_get_names(&lr, &zone_hash, &service_hash) == 1,
            "a record from a broadcast address returns 1");
    expect_names(&lr, "outside(broadcast)", "guest");

    /*
     * And the one that is easy to get wrong: an address *inside* a defined network
     * with no object of its own names nothing. Matching is string equality on the
     * stored address (lib/hash.c:304), with no range test, so 198.51.100.77 stays
     * numeric even though 198.51.100.0/24 is configured. Replace strcmp with a
     * prefix compare and this is the case that fails.
     */
    mk(&lr, 6, 1234, 22, -1, -1);
    snprintf(lr.src_ip, sizeof(lr.src_ip), "%s", "198.51.100.77");
    snprintf(lr.dst_ip, sizeof(lr.dst_ip), "%s", "192.0.2.1");
    t_ok(vrmr_log_record_get_names(&lr, &zone_hash, &service_hash) == 1,
            "an address inside a network with no object returns 1");
    expect_names(&lr, "198.51.100.77", "guest");

    /*
     * An ipv6 record skips every lookup: lib/log.c:411 copies src_ip and dst_ip
     * and says so in a comment. This pins a stub, not a naming policy, and should
     * be rewritten rather than defended when address objects arrive for v6.
     */
    mk(&lr, 6, 443, 80, -1, -1);
    lr.ipv6 = 1;
    snprintf(lr.src_ip, sizeof(lr.src_ip), "%s", "2001:db8::1");
    snprintf(lr.dst_ip, sizeof(lr.dst_ip), "%s", "2001:db8::2");
    t_ok(vrmr_log_record_get_names(&lr, &zone_hash, &service_hash) == 1,
            "an ipv6 record returns 1");
    expect_names(&lr, "2001:db8::1", "2001:db8::2");
}

/* The edges a caller can put in a record, and what the function does with them. */
static void edges(void)
{
    struct vrmr_log_record lr;
    char desc[128];

    /*
     * get_names() has one error return that is not a buffer guard: the icmp
     * helper failing. It cannot - every path writes a name and returns 0 - so a
     * record with an absurd type still yields a name and 1 rather than -1.
     */
    mk(&lr, 1, 0, 0, 999999, 0);
    expect_service(&lr, "illegal icmp (999999.0)");

    /* an empty protocol is not tcp, udp or icmp, so it takes the numeric branch */
    mk(&lr, 0, 7, 9, -1, -1);
    expect_service(&lr, "7*9(0)");

    /* protocol 0 with no ports at all is the proto-0 name */
    mk(&lr, 0, 0, 0, -1, -1);
    expect_service(&lr, "proto-0");

    /* the guards that would call vrmr_error cannot be provoked from here: an
     * overflow needs a value longer than the destination, and every destination
     * is copied from a field of the same size or larger */
    t_ok(sizeof(lr.ser_name) == VRMR_MAX_SERVICE,
            "ser_name is the size the guards assume (%u)",
            (unsigned int)sizeof(lr.ser_name));
    t_ok(sizeof(lr.from_name) == VRMR_MAX_HOST_NET_ZONE,
            "from_name is the size its guard assumes (%u)",
            (unsigned int)sizeof(lr.from_name));

    /* a name longer than ser_name would truncate rather than fail: 32 bytes */
    memset(&lr, 0, sizeof(lr));
    add_service(9999, "a-service-name-that-is-far-too-long-to-fit-anywhere",
            6, 1, 65535, 9999, 0);
    mk(&lr, 6, 1, 9999, -1, -1);
    (void)vrmr_log_record_get_names(&lr, &zone_hash, &service_hash);
    t_ok(strlen(lr.ser_name) < sizeof(lr.ser_name),
            "an over-long resolved name cannot walk off ser_name: \"%s\"",
            lr.ser_name);
    snprintf(desc, sizeof(desc), "and it is the truncated head of the name");
    tap_str_eq(desc, lr.ser_name, "a-service-name-that-is-far-too-");
}

/* -------------------------------------------------------------------- main */

int main(void)
{
    if (vrmr_test_setup() != 0) {
        fprintf(stderr, "vrmr_test_setup failed\n");
        return (1);
    }

    t_ok(tables_setup(), "both hash tables set up over %u rows",
            (unsigned int)HASH_ROWS);

    service_renderings();
    icmp_names();
    zone_names();
    edges();

    tables_teardown();
    vrmr_test_teardown();

    return (tap_finish());
}
