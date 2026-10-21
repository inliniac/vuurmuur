/***************************************************************************
 *   Copyright (C) 2002-2026 by Victor Julien                              *
 *   victor@vuurmuur.org                                                   *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU General Public License     *
 *   along with this program; if not, write to the                         *
 *   Free Software Foundation, Inc.,                                       *
 *   59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.             *
 ***************************************************************************/

/* Tier 0: the rule options grammar (vrmr_rules_read_options/parse_option). */

#include "config.h"
#include "vuurmuur.h"

#include "../lib/tap.h"
#include "../lib/vrmr_test.h"

/* Read one options string into a fresh struct, hand it to check(), free it. */
static void with_options(const char *optstr, int expected,
        void (*check)(struct vrmr_rule_options *, const char *),
        const char *what)
{
    struct vrmr_rule_options *opt = vrmr_test_opt_new();
    int result = 0;

    if (opt == NULL) {
        (void)tap_note("%s: no options struct", what);
        return;
    }

    result = vrmr_test_opt_read(opt, optstr);
    (void)tap_int_eq(what, result, expected);

    if (result == expected)
        check(opt, what);

    vrmr_rules_free_options(opt);
}

static void check_empty(struct vrmr_rule_options *opt, const char *what)
{
    (void)what;
    (void)tap_int_eq("options: empty string sets no logging", opt->rule_log, 0);
    (void)tap_int_eq("options: empty string sets no limit", opt->limit, 0);
}

static void check_log(struct vrmr_rule_options *opt, const char *what)
{
    (void)what;
    (void)tap_int_eq("options: log sets rule_log", opt->rule_log, 1);
}

static void check_random(struct vrmr_rule_options *opt, const char *what)
{
    (void)what;
    (void)tap_int_eq("options: random sets random", opt->random, 1);
}

static void check_loglimit(struct vrmr_rule_options *opt, const char *what)
{
    (void)what;
    (void)tap_int_eq("options: loglimit value", opt->loglimit, 25);
    /* the burst is derived, not parsed */
    (void)tap_int_eq("options: logburst is twice loglimit", opt->logburst, 50);
}

static void check_limit_sec(struct vrmr_rule_options *opt, const char *what)
{
    (void)what;
    (void)tap_int_eq("options: limit value", opt->limit, 10);
    (void)tap_str_eq("options: limit unit", opt->limit_unit, "sec");
}

static void check_limit_bare(struct vrmr_rule_options *opt, const char *what)
{
    (void)what;
    (void)tap_int_eq("options: limit without unit keeps value", opt->limit, 7);
    (void)tap_str_eq("options: limit without unit defaults to sec",
            opt->limit_unit, "sec");
}

static void check_none(struct vrmr_rule_options *opt, const char *what)
{
    (void)opt;
    (void)what;
}

static void check_burst(struct vrmr_rule_options *opt, const char *what)
{
    (void)what;
    (void)tap_int_eq("options: burst value", opt->burst, 30);
}

static void check_in_int(struct vrmr_rule_options *opt, const char *what)
{
    (void)what;
    (void)tap_str_eq("options: in_int needs quoting", opt->in_int, "eth0");
}

static void check_in_int_broken(struct vrmr_rule_options *opt, const char *what)
{
    (void)what;
    /* the value is read from two characters past the key, so an unquoted eth0
     * arrives as th: exact, because a loose predicate here also passes on "",
     * "t" and "th0" */
    (void)tap_str_eq("options: unquoted in_int loses two characters",
            opt->in_int, "th");
}

/* read_options splits on commas outside quotes, so an unquoted list value is
 * really two options and the second is silently dropped as unknown. */
static void check_port_comma_split(struct vrmr_rule_options *opt,
        const char *what)
{
    struct vrmr_portdata *port = NULL;

    (void)what;
    (void)tap_int_eq("options: remoteport flag set", opt->remoteport, 1);
    (void)tap_int_eq("options: unquoted comma ends the list",
            opt->RemoteportList.len, 1);

    port = vrmr_test_port_first(&opt->RemoteportList);
    (void)tap_non_null("options: first port survives", port);
    if (port != NULL) {
        (void)tap_int_eq("options: first port value", port->dst_low, 80);
        (void)tap_int_eq("options: range marker is lost", port->dst_high, -1);
    }
}

static void check_out_via_int(struct vrmr_rule_options *opt, const char *what)
{
    (void)what;
    (void)tap_str_eq("options: out_int", opt->out_int, "eth1");
    (void)tap_str_eq("options: via_int", opt->via_int, "ppp0");
}

static void check_comment(struct vrmr_rule_options *opt, const char *what)
{
    (void)what;
    (void)tap_str_eq(
            "options: comment with spaces", opt->comment, "web server");
    (void)tap_int_eq("options: comment flag", opt->rule_comment, 1);
}

static void check_comment_comma(struct vrmr_rule_options *opt, const char *what)
{
    (void)what;
    (void)tap_str_eq("options: comma inside quotes stays in the value",
            opt->comment, "a,b");
}

static void check_logprefix(struct vrmr_rule_options *opt, const char *what)
{
    (void)what;
    (void)tap_str_eq("options: logprefix", opt->logprefix, "WEB");
    (void)tap_int_eq("options: logprefix flag", opt->rule_logprefix, 1);
}

static void check_logprefix_truncated(
        struct vrmr_rule_options *opt, const char *what)
{
    (void)what;
    /* the copy caps at 12 characters, so the "too long" branch below it can
     * never see more than 14: long prefixes are truncated in silence */
    (void)tap_str_eq("options: long logprefix is cut at 12", opt->logprefix,
            "012345678901");
    (void)tap_int_eq("options: truncated logprefix stays enabled",
            opt->rule_logprefix, 1);
}

static void check_nums(struct vrmr_rule_options *opt, const char *what)
{
    (void)what;
    (void)tap_int_eq("options: nfmark", opt->nfmark, 42);
    (void)tap_int_eq("options: nfqueuenum", opt->nfqueue_num, 3);
    (void)tap_int_eq("options: nflognum", opt->nflog_num, 5);
    (void)tap_int_eq("options: prio", opt->prio, 5);
}

static void check_chain(struct vrmr_rule_options *opt, const char *what)
{
    (void)what;
    (void)tap_str_eq("options: custom chain name", opt->chain, "MYCHAIN");
}

static void check_redirectport(struct vrmr_rule_options *opt, const char *what)
{
    (void)what;
    (void)tap_int_eq("options: redirectport", opt->redirectport, 8080);
}

static void check_reject_type(struct vrmr_rule_options *opt, const char *what)
{
    (void)what;
    (void)tap_int_eq("options: rejecttype flag", opt->reject_option, 1);
    (void)tap_str_eq(
            "options: rejecttype value", opt->reject_type, "tcp-reset");
}

static void check_bw(struct vrmr_rule_options *opt, const char *what)
{
    (void)what;
    (void)tap_int_eq("options: in_max rate", opt->bw_in_max, 10);
    (void)tap_str_eq("options: in_max unit", opt->bw_in_max_unit, "mbit");
    (void)tap_int_eq("options: in_min rate", opt->bw_in_min, 2);
    (void)tap_str_eq("options: in_min unit", opt->bw_in_min_unit, "kbit");
    (void)tap_int_eq("options: out_max rate", opt->bw_out_max, 5);
    (void)tap_str_eq("options: out_max unit", opt->bw_out_max_unit, "kbps");
    (void)tap_int_eq("options: out_min rate", opt->bw_out_min, 1);
    (void)tap_str_eq("options: out_min unit", opt->bw_out_min_unit, "mbps");
}

static void check_ports(struct vrmr_rule_options *opt, const char *what)
{
    struct vrmr_portdata *port = NULL;

    (void)what;
    (void)tap_int_eq("options: remoteport flag", opt->remoteport, 1);
    (void)tap_int_eq(
            "options: remoteport list length", opt->RemoteportList.len, 2);

    port = vrmr_test_port_first(&opt->RemoteportList);
    (void)tap_non_null("options: remoteport first entry", port);
    if (port != NULL)
        (void)tap_int_eq("options: remoteport first port", port->dst_low, 80);

    (void)tap_int_eq("options: listenport flag", opt->listenport, 1);
    (void)tap_int_eq(
            "options: listenport list length", opt->ListenportList.len, 1);

    port = vrmr_test_port_first(&opt->ListenportList);
    (void)tap_non_null("options: listenport first entry", port);
    if (port != NULL) {
        (void)tap_int_eq("options: listenport range low", port->dst_low, 8000);
        (void)tap_int_eq(
                "options: listenport range high", port->dst_high, 8100);
    }
}

static void check_multiple(struct vrmr_rule_options *opt, const char *what)
{
    (void)what;
    (void)tap_int_eq("options: combined log", opt->rule_log, 1);
    (void)tap_int_eq("options: combined limit", opt->limit, 10);
    (void)tap_str_eq("options: combined in_int", opt->in_int, "eth0");
}

static void test_options(void)
{
    with_options("", 0, check_empty, "options: empty string parses");
    with_options("log", 0, check_log, "options: log parses");
    with_options("random", 0, check_random, "options: random parses");
    with_options("loglimit=25", 0, check_loglimit, "options: loglimit parses");
    with_options("limit=10/sec", 0, check_limit_sec, "options: limit parses");
    with_options("limit=7", 0, check_limit_bare,
            "options: limit without a unit parses");
    with_options("limit=3/wobble", -1, check_none,
            "options: unknown limit unit is refused");
    with_options("burst=30", 0, check_burst, "options: burst parses");
    with_options("in_int=\"eth0\"", 0, check_in_int, "options: in_int parses");
    with_options("in_int=eth0", 0, check_in_int_broken,
            "options: unquoted in_int parses");
    with_options("out_int=\"eth1\",via_int=\"ppp0\"", 0, check_out_via_int,
            "options: interface pair parses");
    with_options("comment=\"web server\"", 0, check_comment,
            "options: comment parses");
    with_options("comment=\"a,b\",log", 0, check_comment_comma,
            "options: quoted comma does not split");
    with_options("logprefix=\"WEB\"", 0, check_logprefix,
            "options: logprefix parses");
    with_options("logprefix=\"01234567890123456789\"", 0,
            check_logprefix_truncated, "options: oversized logprefix parses");
    with_options("nfmark=42,nfqueuenum=3,nflognum=5,prio=5", 0, check_nums,
            "options: numeric fields parse");
    with_options("chain=\"MYCHAIN\"", 0, check_chain, "options: chain parses");
    with_options("redirectport=8080", 0, check_redirectport,
            "options: redirectport parses");
    with_options("rejecttype=tcp-reset", 0, check_reject_type,
            "options: rejecttype parses");
    with_options("rejecttype=nonsense", -1, check_none,
            "options: unknown rejecttype is refused");
    with_options("redirectport=0", -1, check_none,
            "options: redirectport 0 is refused");
    with_options("in_max=10mbit,in_min=2kbit,out_max=5kbps,out_min=1mbps", 0,
            check_bw, "options: shaping rates parse");
    with_options("in_max=10wobble", -1, check_none,
            "options: unknown shaping unit is refused");
    with_options("remoteport=\"80,443\",listenport=\"8000:8100\"", 0,
            check_ports, "options: port lists parse");
    with_options(
            "remoteport=0", -1, check_none, "options: remoteport 0 is refused");
    with_options("remoteport=80,443:500", 0, check_port_comma_split,
            "options: unquoted port list is cut at the comma");
    with_options("log,limit=10/sec,in_int=\"eth0\"", 0, check_multiple,
            "options: mixed list parses");

    /* obsolete and unsupported input must not fail the load */
    with_options("markiptstate", 0, check_none,
            "options: obsolete markiptstate is ignored");
    with_options("queue", 0, check_none, "options: retired queue is ignored");
    with_options("frobnicate=1", 0, check_none,
            "options: unknown option is ignored");
}

/* A failing option must stop the whole list, so nothing after it is applied. */
static void test_partial_failure(void)
{
    struct vrmr_rule_options *opt = vrmr_test_opt_new();

    if (opt == NULL) {
        (void)tap_note("partial: no options struct");
        return;
    }

    (void)tap_int_eq("options: failure in the middle is reported",
            vrmr_test_opt_read(opt, "log,limit=3/wobble,in_int=\"eth0\""), -1);
    (void)tap_int_eq("options: earlier option was applied", opt->rule_log, 1);
    (void)tap_str_eq("options: later option was not applied", opt->in_int, "");

    vrmr_rules_free_options(opt);
}

int main(void)
{
    if (vrmr_test_setup() < 0) {
        (void)fprintf(stdout, "Bail out! vrmr_test_setup failed\n");
        return EXIT_FAILURE;
    }

    test_options();
    test_partial_failure();

    vrmr_test_teardown();

    return tap_finish();
}
