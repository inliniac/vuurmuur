/*
 * vuurmuur - linux firewall management tool
 *
 * vrmr_log_record_parse_prefix() and vrmr_log_record_build_line(): what an
 * operator reads during an incident. The prefixes parsed here are the ones the
 * rule emitter actually writes, taken from the goldens, so a new prefix cannot
 * arrive without being checked against the decoder.
 *
 * (c) Victor Julien <victor@vuurmuur.org>
 */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <dirent.h>
#include <ctype.h>
#include <inttypes.h>
#include <limits.h>

#include "vuurmuur.h"

#include "../lib/tap.h"
#include "../lib/vrmr_test.h"

#define GOLDEN_MAX 64
#define PREFIX_MAX 128

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
static char *golden_path(char *buf, size_t size, const char *name)
{
    const char *src = getenv("abs_srcdir");

    if (src == NULL)
        return NULL;

    if (name == NULL)
        (void)snprintf(buf, size, "%s/golden", src);
    else
        (void)snprintf(buf, size, "%s/golden/%s", src, name);

    return buf;
}

/* create_logprefix_string() in vuurmuur/rules.c rewrites a handful of targets
 * before it writes the prefix (TCPRESET->REJECT, MASQUERADE->MASQ, the NEW*
 * aliases, DNAT*->PORTFW/DNAT/BOUNCE); every other action passes through
 * verbatim, so this names what the mapping can produce - a floor, not a
 * ceiling. Membership is reported, not asserted: the assertion a new rule type
 * must not trip is the shape check below.
 */
static const char *const mapped_action[] = {"ACCEPT", "DROP", "REJECT",
        "SREJECT", "TARPIT", "NFQUEUE", "NFLOG", "RETURN", "MASQ", "QUEUE",
        "PORTFW", "DNAT", "BOUNCE", NULL};

/* the corpus words that are not in the mapped set, i.e. pass-through targets */
#define PASSTHROUGH_MAX 16
static char passthrough[PASSTHROUGH_MAX][32];
static size_t passthrough_num;

static void note_unmapped_action(const char *action)
{
    size_t i;

    for (i = 0; mapped_action[i] != NULL; i++)
        if (strcmp(action, mapped_action[i]) == 0)
            return;

    for (i = 0; i < passthrough_num; i++)
        if (strcmp(passthrough[i], action) == 0)
            return;

    if (passthrough_num < PASSTHROUGH_MAX) {
        (void)strlcpy(passthrough[passthrough_num], action,
                sizeof(passthrough[0]));
        passthrough_num++;
    }
}

/* what a decoded action must never be: empty, a marker remnant ("vrmr:"), an
 * angle-bracketed fallback or anything holding a separator
 */
static int is_target_word(const char *action)
{
    size_t i;

    if (action[0] == '\0' || action[0] == '<')
        return 0;

    for (i = 0; action[i] != '\0'; i++)
        if (!isalnum((unsigned char)action[i]) && action[i] != '_' &&
                action[i] != '-')
            return 0;

    return 1;
}

/* "vrmr: <action> <kind>" -> what the decoder must give back */
static void expect_prefix(const char *prefix, char *action, size_t asize,
        char *kind, size_t ksize)
{
    const char *p = strstr(prefix, "vrmr: ");
    size_t i = 0;

    action[0] = '\0';
    kind[0] = '\0';

    if (p == NULL)
        return;

    p += 6;
    while (*p != '\0' && *p != ' ' && i < asize - 1)
        action[i++] = *p++;
    action[i] = '\0';

    if (*p != '\0')
        p++;
    while (*p == ' ')
        p++;

    (void)strlcpy(kind, p, ksize);
}

static void check_prefix(const char *prefix, int *seen)
{
    struct vrmr_log_record lr;
    char want_action[16], want_kind[64];

    expect_prefix(prefix, want_action, sizeof(want_action), want_kind,
            sizeof(want_kind));

    memset(&lr, 0, sizeof(lr));
    vrmr_log_record_parse_prefix(&lr, prefix);

    /* a prefix the emitter wrote must never decode as unknown or external */
    t_ok(lr.action[0] != '\0' && strcmp(lr.action, "<unknown>") != 0 &&
                    strcmp(lr.action, "<exteral>") != 0,
            "prefix \"%s\" decodes to a real action, not \"%s\"", prefix,
            lr.action);
    t_ok(strcmp(lr.action, want_action) == 0, "prefix \"%s\" -> action \"%s\" "
                                              "(decoder expects \"%s\")",
            prefix, lr.action, want_action);
    t_ok(is_target_word(lr.action), "prefix \"%s\" decodes to a target word, "
                                    "not a remnant: %s", prefix, lr.action);
    note_unmapped_action(lr.action);
    t_ok(strchr(lr.action, ' ') == NULL, "action \"%s\" carries no space",
            lr.action);
    t_ok(strchr(lr.action, '"') == NULL, "action \"%s\" carries no quote",
            lr.action);
    t_ok(lr.logprefix[0] != '\0' && lr.logprefix[0] != ' ',
            "kind of \"%s\" starts at the kind, not at a space: \"%s\"", prefix,
            lr.logprefix);
    t_ok(strncmp(lr.logprefix, want_kind, strlen(want_kind)) == 0,
            "prefix \"%s\" -> kind \"%s\" (decoder expects \"%s\")", prefix,
            lr.logprefix, want_kind);

    (*seen)++;
}

/* the corpus repeats the same prefix on many rules; checking each one twice
 * would only inflate the plan. The table caps at PREFIX_MAX distinct entries;
 * the corpus holds 24 today, so it would have to grow 5x before the cap bites
 * (asserted, because past the cap every prefix counts as new again).
 */
static char seen_prefixes[PREFIX_MAX][PREFIX_MAX];
static size_t seen_prefixes_num;

static int prefix_is_new(const char *prefix)
{
    size_t i;

    for (i = 0; i < seen_prefixes_num; i++)
        if (strcmp(seen_prefixes[i], prefix) == 0)
            return 0;

    if (seen_prefixes_num < PREFIX_MAX) {
        (void)strlcpy(seen_prefixes[seen_prefixes_num], prefix, PREFIX_MAX);
        seen_prefixes_num++;
    }

    return 1;
}

static void scan_line(const char *line, int *seen)
{
    const char *p = strstr(line, "--nflog-prefix \"");
    const char *end;
    char prefix[PREFIX_MAX];
    size_t n;

    if (p == NULL)
        return;

    p += (sizeof("--nflog-prefix \"") - 1);
    end = strchr(p, '"');
    if (end == NULL)
        return;

    n = (size_t)(end - p);
    if (n >= sizeof(prefix))
        n = sizeof(prefix) - 1;

    memcpy(prefix, p, n);
    prefix[n] = '\0';

    if (!prefix_is_new(prefix))
        return;

    check_prefix(prefix, seen);
}

static int name_cmp(const void *a, const void *b)
{
    return strcmp(*(const char *const *)a, *(const char *const *)b);
}

/* the corpus is walked in sorted order so the run is reproducible */
static void scan_goldens(void)
{
    DIR *dir;
    struct dirent *de;
    char *names[GOLDEN_MAX];
    size_t num = 0;
    size_t i;
    char path[PATH_MAX];
    FILE *fp;
    char line[2048];
    int seen = 0;

    if (golden_path(path, sizeof(path), NULL) == NULL) {
        t_ok(0, "abs_srcdir is not set: run this through 'make check'");
        return;
    }

    dir = opendir(path);
    if (dir == NULL) {
        t_ok(0, "the golden directory could not be opened");
        return;
    }

    while ((de = readdir(dir)) != NULL) {
        size_t len = strlen(de->d_name);

        if (len < 4 || strcmp(de->d_name + len - 4, ".txt") != 0)
            continue;
        if (num < GOLDEN_MAX)
            names[num++] = strdup(de->d_name);
    }
    (void)closedir(dir);

    qsort(names, num, sizeof(names[0]), name_cmp);

    for (i = 0; i < num; i++) {
        if (golden_path(path, sizeof(path), names[i]) == NULL) {
            t_ok(0, "abs_srcdir is not set: run this through 'make check'");
            return;
        }

        fp = fopen(path, "r");
        if (fp == NULL) {
            t_ok(0, "golden %s could not be read", names[i]);
            continue;
        }

        while (fgets(line, sizeof(line), fp) != NULL)
            scan_line(line, &seen);

        (void)fclose(fp);
        free(names[i]);
    }

    t_ok(seen_prefixes_num < PREFIX_MAX,
            "the dedupe table still has room (%zu of %d used)",
            (size_t)seen_prefixes_num, PREFIX_MAX);

    if (passthrough_num > 0) {
        char list[512] = "";
        size_t i;

        for (i = 0; i < passthrough_num; i++) {
            if (strlen(list) + strlen(passthrough[i]) + 3 > sizeof(list))
                break;
            (void)strlcat(list, passthrough[i], sizeof(list));
            (void)strlcat(list, " ", sizeof(list));
        }
        (void)tap_note("actions reaching the log verbatim, not written by the "
                "mapping in create_logprefix_string(): %s", list);
    }

    /* vacuum guard: an emitter that stopped writing prefixes would otherwise
     * leave this file asserting nothing at all. The floor sits below today's
     * corpus (24) but high enough that losing most of it is a failure.
     */
    t_ok(seen >= 20, "the goldens yielded %d distinct nflog prefixes to decode",
            seen);
}

static void fill(struct vrmr_log_record *lr)
{
    memset(lr, 0, sizeof(*lr));

    (void)strlcpy(lr->month, "Oct", sizeof(lr->month));
    lr->day = 3;
    lr->hour = 12;
    lr->minute = 34;
    lr->second = 56;

    (void)strlcpy(lr->action, "DROP", sizeof(lr->action));
    (void)strlcpy(lr->logprefix, "policy", sizeof(lr->logprefix));
    (void)strlcpy(lr->ser_name, "tcp/80", sizeof(lr->ser_name));
    (void)strlcpy(lr->from_name, "lan", sizeof(lr->from_name));
    (void)strlcpy(lr->to_name, "wan", sizeof(lr->to_name));

    /* as vuurmuur_log/nflog.c writes them: a trailing space each */
    (void)strlcpy(lr->from_int, "in: eth0 ", sizeof(lr->from_int));
    (void)strlcpy(lr->to_int, "out: eth1 ", sizeof(lr->to_int));

    (void)strlcpy(lr->src_ip, "192.0.2.1", sizeof(lr->src_ip));
    (void)strlcpy(lr->dst_ip, "192.0.2.2", sizeof(lr->dst_ip));
    lr->src_port = 443;
    lr->dst_port = 80;
    lr->packet_len = 52;
    lr->ttl = 64;

    lr->icmp_type = 8;
    lr->icmp_code = 0;

    /* SYN and ACK only; the buffer is left garbage on purpose, the builder
     * derives the string from the bits
     */
    lr->syn = 1;
    lr->ack = 1;
    (void)strlcpy(lr->tcpflags, "ZZZZZZ", sizeof(lr->tcpflags));
}

static void build_lines(void)
{
    struct vrmr_log_record lr;
    char out[2048];
    char small[32];

    fill(&lr);
    lr.protocol = 6;
    (void)vrmr_log_record_build_line(&lr, out, sizeof(out));
    tap_str_eq("the TCP log line is as pinned", out,
            "Oct  3 12:34:56: DROP service tcp/80 from lan to wan, "
            "prefix: \"policy\" (in: eth0 out: eth1 192.0.2.1:443 -> "
            "192.0.2.2:80 TCP flags: *A**S* len:52 ttl:64)\n");

    fill(&lr);
    lr.protocol = 17;
    (void)vrmr_log_record_build_line(&lr, out, sizeof(out));
    tap_str_eq("the UDP log line is as pinned (no ports in the flags slot)", out,
            "Oct  3 12:34:56: DROP service tcp/80 from lan to wan, "
            "prefix: \"policy\" (in: eth0 out: eth1 192.0.2.1:443 -> "
            "192.0.2.2:80 UDP len:52 ttl:64)\n");

    fill(&lr);
    lr.protocol = 1;
    (void)vrmr_log_record_build_line(&lr, out, sizeof(out));
    tap_str_eq("the ICMP log line is as pinned, ports gone", out,
            "Oct  3 12:34:56: DROP service tcp/80 from lan to wan, "
            "prefix: \"policy\" (in: eth0 out: eth1 192.0.2.1 -> "
            "192.0.2.2 ICMP type 8 code 0 len:52 ttl:64)\n");

    /* the four branches nobody reads on a v4-only box: no ports slot at all */
    fill(&lr);
    lr.protocol = 47;
    (void)vrmr_log_record_build_line(&lr, out, sizeof(out));
    tap_str_eq("GRE logs without ports", out,
            "Oct  3 12:34:56: DROP service tcp/80 from lan to wan, "
            "prefix: \"policy\" (in: eth0 out: eth1 192.0.2.1 -> "
            "192.0.2.2 GRE len:52 ttl:64)\n");

    fill(&lr);
    lr.protocol = 50;
    (void)vrmr_log_record_build_line(&lr, out, sizeof(out));
    tap_str_eq("ESP logs without ports", out,
            "Oct  3 12:34:56: DROP service tcp/80 from lan to wan, "
            "prefix: \"policy\" (in: eth0 out: eth1 192.0.2.1 -> "
            "192.0.2.2 ESP len:52 ttl:64)\n");

    fill(&lr);
    lr.protocol = 51;
    (void)vrmr_log_record_build_line(&lr, out, sizeof(out));
    tap_str_eq("AH logs without ports", out,
            "Oct  3 12:34:56: DROP service tcp/80 from lan to wan, "
            "prefix: \"policy\" (in: eth0 out: eth1 192.0.2.1 -> "
            "192.0.2.2 AH len:52 ttl:64)\n");

    fill(&lr);
    lr.protocol = 58;
    (void)vrmr_log_record_build_line(&lr, out, sizeof(out));
    tap_str_eq("ICMPv6 logs type and code, not ports", out,
            "Oct  3 12:34:56: DROP service tcp/80 from lan to wan, "
            "prefix: \"policy\" (in: eth0 out: eth1 192.0.2.1 -> "
            "192.0.2.2 ICMPv6 type 8 code 0 len:52 ttl:64)\n");

    fill(&lr);
    lr.protocol = 255;
    (void)vrmr_log_record_build_line(&lr, out, sizeof(out));
    t_ok(strstr(out, "PROTO 255") != NULL,
            "an unknown protocol is named by number, not dropped:\n    got  %s",
            out);

    /* the flags column is derived from the bits, so a stale buffer cannot
     * survive into the line
     */
    fill(&lr);
    lr.protocol = 6;
    lr.fin = 1;
    lr.psh = 1;
    (void)vrmr_log_record_build_line(&lr, out, sizeof(out));
    t_ok(strstr(out, "TCP flags: *AP*SF") != NULL,
            "flags F and P appear, the garbage in the buffer does not:\n"
            "    got  %s",
            out);

    /* a destination too small truncates the line silently: build_line() only
     * ever returns 0, while the caller in vuurmuur_log/vuurmuur_log.c's main
     * loop tests it for an error - so a truncated line is written as if it
     * were whole
     */
    fill(&lr);
    lr.protocol = 6;
    (void)memset(small, 'x', sizeof(small));
    t_ok(vrmr_log_record_build_line(&lr, small, sizeof(small)) == 0,
            "a 32 byte destination reports success (the caller cannot tell)");
    t_ok(strlen(small) < sizeof(small), "and stays inside the buffer");
}

static void edge_cases(void)
{
    struct vrmr_log_record lr;

    /* the fall-through cases are pinned as they behave today. "<exteral>" is
     * a product typo in operator-visible text, not a design decision: it is
     * pinned so a change is a deliberate edit here, never an accident
     */
    memset(&lr, 0, sizeof(lr));
    vrmr_log_record_parse_prefix(&lr, NULL);
    t_ok(strcmp(lr.action, "<exteral>") == 0 &&
                    strcmp(lr.logprefix, "none") == 0,
            "a NULL prefix reads as external: \"%s\"/\"%s\"", lr.action,
            lr.logprefix);

    memset(&lr, 0, sizeof(lr));
    vrmr_log_record_parse_prefix(&lr, "vrmr: ");
    t_ok(strcmp(lr.action, "<exteral>") == 0,
            "an empty vrmr prefix reads as external: \"%s\"", lr.action);

    memset(&lr, 0, sizeof(lr));
    vrmr_log_record_parse_prefix(&lr, "kernel: something else");
    t_ok(strcmp(lr.action, "<unknown>") == 0 &&
                    strcmp(lr.logprefix, "none") == 0,
            "a foreign prefix keeps the action unknown: \"%s\"/\"%s\"",
            lr.action, lr.logprefix);

    memset(&lr, 0, sizeof(lr));
    vrmr_log_record_parse_prefix(&lr, "vrmr:  DROP fw policy ");
    /* a stray space after "vrmr: " ends the action token immediately, so the
     * action is lost and the kind inherits it: the format is a contract with
     * vuurmuur/createrule.c, which writes "vrmr: <target> "
     */
    t_ok(strcmp(lr.action, "<unknown>") == 0 &&
                    strcmp(lr.logprefix, "DROP fw policy ") == 0,
            "a space after the marker loses the action to the kind: "
            "\"%s\"/\"%s\"",
            lr.action, lr.logprefix);

    memset(&lr, 0, sizeof(lr));
    vrmr_log_record_parse_prefix(&lr,
            "vrmr: ANEXTREMELYLONGACTIONNAME tail text here that is long");
    t_ok(strlen(lr.action) == sizeof(lr.action) - 1 &&
                    lr.action[sizeof(lr.action) - 1] == '\0',
            "an over-long action truncates without running over: \"%s\"",
            lr.action);
    t_ok(strcmp(lr.logprefix, "tail text here that is long") == 0 ||
                    strlen(lr.logprefix) == sizeof(lr.logprefix) - 1,
            "the kind still starts after the action: \"%s\"", lr.logprefix);

    memset(&lr, 0, sizeof(lr));
    vrmr_log_record_parse_prefix(&lr, "vrmr: DROP");
    t_ok(strcmp(lr.action, "DROP") == 0 && strcmp(lr.logprefix, "none") == 0,
            "a prefix with no kind keeps none: \"%s\"/\"%s\"", lr.action,
            lr.logprefix);
}

int main(void)
{
    if (vrmr_test_setup() != 0) {
        (void)fprintf(stderr, "vrmr_test_setup failed\n");
        return (1);
    }

    scan_goldens();
    build_lines();
    edge_cases();

    vrmr_test_teardown();

    return (tap_finish());
}
