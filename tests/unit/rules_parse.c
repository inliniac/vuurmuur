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

/* Tier 0: the rules.conf line parser. No filesystem, no root, no iptables. */

#include "config.h"
#include "vuurmuur.h"

#include <stddef.h> /* offsetof, for the over-long token table */

#include "../lib/tap.h"
#include "../lib/vrmr_test.h"

static void test_basic_line(void)
{
    struct vrmr_rule *rule =
            vrmr_test_rule_parse("accept service http from lan to dmz.host1\n");

    tap_non_null("parse: accept line is accepted", rule);
    if (rule == NULL)
        return;

    tap_int_eq("parse: action is accept", rule->action, VRMR_AT_ACCEPT);
    tap_int_eq("parse: rule is active", rule->active, TRUE);
    tap_str_eq("parse: service", rule->service, "http");
    tap_str_eq("parse: from", rule->from, "lan");
    tap_str_eq("parse: to", rule->to, "dmz.host1");
    tap_is_null("parse: no options means no opt struct", rule->opt);

    vrmr_test_rule_free(rule);
}

static void test_inactive_line(void)
{
    struct vrmr_rule *rule =
            vrmr_test_rule_parse(";accept service http from lan to dmz\n");

    tap_non_null("parse: inactive line is accepted", rule);
    if (rule == NULL)
        return;

    tap_int_eq("parse: inactive flag from leading ;", rule->active, FALSE);
    tap_int_eq("parse: action of inactive rule", rule->action, VRMR_AT_ACCEPT);
    tap_str_eq("parse: service of inactive rule", rule->service, "http");

    vrmr_test_rule_free(rule);
}

static void test_separator(void)
{
    struct vrmr_rule *rule = vrmr_test_rule_parse("separator\n");

    tap_non_null("parse: separator line is accepted", rule);
    if (rule == NULL)
        return;

    tap_int_eq("parse: separator action", rule->action, VRMR_AT_SEPARATOR);
    tap_is_null("parse: separator has no options", rule->opt);

    vrmr_test_rule_free(rule);
}

static const struct {
    const char *name;
    int action;
} action_names[] = {
        {"accept", VRMR_AT_ACCEPT},
        {"drop", VRMR_AT_DROP},
        {"reject", VRMR_AT_REJECT},
        {"log", VRMR_AT_LOG},
        {"portfw", VRMR_AT_PORTFW},
        {"redirect", VRMR_AT_REDIRECT},
        {"snat", VRMR_AT_SNAT},
        {"masq", VRMR_AT_MASQ},
        {"chain", VRMR_AT_CHAIN},
        {"dnat", VRMR_AT_DNAT},
        {"bounce", VRMR_AT_BOUNCE},
        {"nfqueue", VRMR_AT_NFQUEUE},
        {"nflog", VRMR_AT_NFLOG},
        {"protect", VRMR_AT_PROTECT},
        {"separator", VRMR_AT_SEPARATOR},
        {"sepparator", VRMR_AT_SEPARATOR},
        {"ACCEPT", VRMR_AT_ACCEPT},
};

static void test_action_names(void)
{
    char desc[128] = "";
    size_t i = 0;

    for (i = 0; i < sizeof(action_names) / sizeof(action_names[0]); i++) {
        char line[256] = "";

        /*
            the table is the claim, so every row has to assert: the two
            special actions are skipped below, not here
        */
        (void)snprintf(
                desc, sizeof(desc), "actiontoi: %s", action_names[i].name);
        (void)tap_ok(vrmr_rules_actiontoi(action_names[i].name) ==
                action_names[i].action, desc);

        /* protect needs against and separator never appears in this form:
         * both are pinned by their own cases further down */
        if (action_names[i].action == VRMR_AT_SEPARATOR ||
                action_names[i].action == VRMR_AT_PROTECT)
            continue;

        /* the line form must round trip through the action table */
        (void)snprintf(line, sizeof(line), "%s service http from lan to dmz",
                action_names[i].name);
        struct vrmr_rule *rule = vrmr_test_rule_parse(line);

        (void)snprintf(desc, sizeof(desc), "parse: action of '%s' line",
                action_names[i].name);
        if (rule == NULL) {
            (void)tap_ok(0, desc);
            continue;
        }
        (void)tap_int_eq(desc, rule->action, action_names[i].action);

        /* and back out again through itoaction */
        (void)snprintf(desc, sizeof(desc), "itoaction: %s is its own name",
                action_names[i].name);
        const char *back = vrmr_rules_itoaction(rule->action);
        (void)tap_ok(
                back != NULL && strcasecmp(back, action_names[i].name) == 0,
                desc);

        vrmr_test_rule_free(rule);
    }

    /* 'queue' was replaced by nfqueue, so it must be refused by name */
    tap_int_eq("actiontoi: queue is refused", vrmr_rules_actiontoi("queue"),
            VRMR_AT_ERROR);
    tap_int_eq("actiontoi: unknown action", vrmr_rules_actiontoi("frobnicate"),
            VRMR_AT_ERROR);
    tap_int_eq(
            "itoaction: negative index", vrmr_rules_itoaction(-1) == NULL, 1);
}

static const struct {
    const char *line;
    int ruletype;
    const char *what;
} ruletypes[] = {
        {"accept service ssh from firewall to lan", VRMR_RT_OUTPUT,
                "ruletype: firewall as source is output"},
        {"accept service ssh from lan to firewall", VRMR_RT_INPUT,
                "ruletype: firewall as destination is input"},
        {"accept service ssh from lan to dmz", VRMR_RT_FORWARD,
                "ruletype: zone to zone is forward"},
        {"masq service http from lan to internet.address", VRMR_RT_MASQ,
                "ruletype: masq keeps its own chain"},
        {"snat service http from lan to internet.address", VRMR_RT_SNAT,
                "ruletype: snat keeps its own chain"},
        {"portfw service http from internet.address to dmz.host1",
                VRMR_RT_PORTFW, "ruletype: portfw is prerouting"},
        {"redirect service http from lan to dmz.host1", VRMR_RT_REDIRECT,
                "ruletype: redirect is prerouting"},
        {"dnat service http from internet.address to dmz.host1", VRMR_RT_DNAT,
                "ruletype: dnat is prerouting"},
        {"bounce service http from lan.host1 to dmz.host1", VRMR_RT_BOUNCE,
                "ruletype: bounce is dnat plus snat"},
};

static void test_ruletypes(void)
{
    size_t i = 0;

    for (i = 0; i < sizeof(ruletypes) / sizeof(ruletypes[0]); i++) {
        struct vrmr_rule *rule = vrmr_test_rule_parse(ruletypes[i].line);

        tap_non_null(ruletypes[i].what, rule);
        if (rule == NULL)
            continue;

        (void)tap_int_eq(ruletypes[i].what, vrmr_rules_determine_ruletype(rule),
                ruletypes[i].ruletype);

        vrmr_test_rule_free(rule);
    }
}

static void test_protect_lines(void)
{
    struct vrmr_rule *rule = vrmr_test_rule_parse("protect against synflood\n");

    tap_non_null("protect: system protect rule parses", rule);
    if (rule != NULL) {
        (void)tap_int_eq("protect: action", rule->action, VRMR_AT_PROTECT);
        (void)tap_str_eq("protect: no zone means empty who", rule->who, "");
        (void)tap_str_eq("protect: danger", rule->danger, "synflood");
        vrmr_test_rule_free(rule);
    }

    rule = vrmr_test_rule_parse("protect lan against portscan\n");
    tap_non_null("protect: zone protect rule parses", rule);
    if (rule != NULL) {
        (void)tap_str_eq("protect: who is the zone", rule->who, "lan");
        (void)tap_str_eq(
                "protect: danger of zone rule", rule->danger, "portscan");
        (void)tap_str_eq(
                "protect: unused source stays empty", rule->source, "");
        vrmr_test_rule_free(rule);
    }

    rule = vrmr_test_rule_parse(
            "protect dmz against spoofing from dmz.host1\n");
    tap_non_null("protect: spoofing rule parses", rule);
    if (rule != NULL) {
        (void)tap_str_eq("protect: spoofing danger", rule->danger, "spoofing");
        (void)tap_str_eq("protect: spoofing source", rule->source, "dmz.host1");
        vrmr_test_rule_free(rule);
    }
}

static const struct {
    const char *line;
    const char *what;
} bad_lines[] = {
        {"accept http from lan to dmz", "syntax: service keyword required"},
        {"accept service http lan to dmz", "syntax: from keyword required"},
        {"accept service http from lan dmz", "syntax: to keyword required"},
        {"accept service http from lan", "syntax: destination required"},
        {"frobnicate service http from lan to dmz",
                "syntax: unknown action is refused"},
        {"accept service ht!tp from lan to dmz",
                "syntax: invalid service name is refused"},
        {"accept service http from l&n to dmz",
                "syntax: invalid zone name is refused"},
        {"accept service http from lan to dmz.host1.sub.sub",
                "syntax: zone names stop at three parts"},
        {"accept service this-name-is-way-too-long-for-a-service-name from lan "
         "to dmz",
                "syntax: service name longer than 32 is refused"},
        {"protect lan portscan", "syntax: protect needs 'against'"},
        {"", "syntax: an empty line is refused"},
        {"\n", "syntax: a bare newline is refused"},
        {"accept service http from lan to dmz options comment=\"unbalanced",
                "options: unbalanced quote is refused"},
};

/*
    The keyword is "options " with a trailing space. Written as options= the
    line is accepted and every option in it is dropped without a word, which is
    the highest-impact behaviour in this file and needs no fixture to pin.
*/
static void test_options_keyword(void)
{
    struct vrmr_rule *rule = NULL;

    rule = vrmr_test_rule_parse(
            "accept service http from lan to dmz options=limit=5/sec");
    if (rule != NULL) {
        (void)tap_ok(rule->opt == NULL,
                "options: options= is accepted and drops the options");
        vrmr_test_rule_free(rule);
    } else {
        (void)tap_ok(0, "options: options= is accepted and drops the options");
    }

    rule = vrmr_test_rule_parse(
            "accept service http from lan to dmz options limit=5/sec");
    if (rule != NULL) {
        (void)tap_ok(rule->opt != NULL,
                "options: options with a space is read");
        vrmr_test_rule_free(rule);
    } else {
        (void)tap_ok(0, "options: options with a space is read");
    }
}

/*
    One over-long token per destination field, so the clamps are load-bearing for the
    suite and not just for one field. Reverting a listed site to
    `field[var_pos] = '\0';` makes `make check` fail under --with-sanitizers, site by
    site: the guard in AM_TESTS_ENVIRONMENT turns the finding into an abort. Twelve
    sites are listed. Three are not, because their loops cannot reach the end of what
    they write - the action buffer stops at `sizeof(action_str) - 1`, the 'against' and
    'from' keyword copies at the length of those words - so the clamp there is
    defensive rather than load-bearing.
*/
static void test_overlong_tokens(void)
{
    static const struct {
        const char *what;
        const char *fmt;
        size_t off;
        size_t size;
        int accepted;
    } cases[] = {
            { "who", "protect %s against portscan",
                    offsetof(struct vrmr_rule, who),
                    sizeof(((struct vrmr_rule *)0)->who), 0 },
            { "danger", "protect lan against %s",
                    offsetof(struct vrmr_rule, danger),
                    sizeof(((struct vrmr_rule *)0)->danger), 1 },
            { "against keyword", "protect against %s",
                    offsetof(struct vrmr_rule, danger),
                    sizeof(((struct vrmr_rule *)0)->danger), 1 },
            { "source", "protect lan against spoofing from %s",
                    offsetof(struct vrmr_rule, source),
                    sizeof(((struct vrmr_rule *)0)->source), 1 },
            { "service keyword", "accept %s from lan to dmz",
                    offsetof(struct vrmr_rule, service),
                    sizeof(((struct vrmr_rule *)0)->service), 0 },
            { "service value", "accept service %s from lan to dmz",
                    offsetof(struct vrmr_rule, service),
                    sizeof(((struct vrmr_rule *)0)->service), 0 },
            { "from keyword", "accept service http %s to dmz",
                    offsetof(struct vrmr_rule, from),
                    sizeof(((struct vrmr_rule *)0)->from), 0 },
            { "from value", "accept service http from %s to dmz",
                    offsetof(struct vrmr_rule, from),
                    sizeof(((struct vrmr_rule *)0)->from), 0 },
            { "to keyword", "accept service http from lan %s dmz",
                    offsetof(struct vrmr_rule, to),
                    sizeof(((struct vrmr_rule *)0)->to), 0 },
            { "to value", "accept service http from lan to %s",
                    offsetof(struct vrmr_rule, to),
                    sizeof(((struct vrmr_rule *)0)->to), 0 },
            { "options keyword", "accept service http from lan to dmz %s",
                    0, 256, 1 },
            { "options value", "accept service http from lan to dmz options %s",
                    0, 256, 1 },
            { "action", "%s service http from lan to dmz", 0, 32, 0 },
    };
    size_t i = 0;

    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        char token[VRMR_MAX_RULE_LENGTH];
        char line[VRMR_MAX_RULE_LENGTH];
        char name[96] = "";
        struct vrmr_rule *rule = vrmr_rule_malloc();
        int rc;

        if (rule == NULL) {
            (void)tap_note("bounds: vrmr_rule_malloc failed");
            return;
        }

        memset(token, (int)('a' + (i % 26)), cases[i].size + 8);
        token[cases[i].size + 8] = '\0';
        (void)snprintf(line, sizeof(line), cases[i].fmt, token);

        rc = vrmr_rules_parse_line(line, rule, &vrmr_test_ctx.reg);

        (void)snprintf(name, sizeof(name), "bounds: %s token %s", cases[i].what,
                cases[i].accepted ? "still parses" : "is refused");
        tap_int_eq(name, rc < 0, cases[i].accepted ? 0 : 1);

        if (cases[i].off != 0) {
            char *field = (char *)rule + cases[i].off;

            (void)snprintf(name, sizeof(name), "bounds: %s stays a string",
                    cases[i].what);
            tap_int_eq(name, strlen(field) < cases[i].size, 1);
        }

        vrmr_test_rule_free(rule);
    }
}

static void test_bad_lines(void)
{
    size_t i = 0;

    for (i = 0; i < sizeof(bad_lines) / sizeof(bad_lines[0]); i++) {
        struct vrmr_rule *rule = vrmr_test_rule_parse(bad_lines[i].line);

        tap_is_null(bad_lines[i].what, rule);
        vrmr_test_rule_free(rule);
    }

    /* the parser works on a VRMR_MAX_RULE_LENGTH buffer, so an overlong line
     * must be refused instead of parsed truncated */
    char *longline = malloc(VRMR_MAX_RULE_LENGTH + 256);
    tap_non_null("bounds: long line buffer", longline);
    if (longline != NULL) {
        memset(longline, 'a', VRMR_MAX_RULE_LENGTH + 255);
        longline[VRMR_MAX_RULE_LENGTH + 255] = '\0';

        struct vrmr_rule *rule = vrmr_rule_malloc();
        tap_non_null("bounds: long line rule", rule);
        if (rule != NULL) {
            (void)tap_int_eq("bounds: overlong line is refused",
                    vrmr_rules_parse_line(longline, rule, &vrmr_test_ctx.reg) <
                            0,
                    1);
            vrmr_test_rule_free(rule);
        }
        free(longline);
    }

    /* a 32 character zone part is still valid */
    struct vrmr_rule *rule =
            vrmr_test_rule_parse("accept service http from "
                                 "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa to dmz\n");
    tap_non_null("bounds: 32 character zone name parses", rule);
    vrmr_test_rule_free(rule);
}

static void test_encode_decode(void)
{
    char buf[512] = "";
    const char *plain =
            "accept service http from lan to dmz options comment=\"hello\"";
    char original[512] = "";

    (void)strlcpy(original, plain, sizeof(original));

    (void)strlcpy(buf, plain, sizeof(buf));
    tap_int_eq("encode: no error", vrmr_rules_encode_rule(buf, sizeof(buf)), 0);
    tap_non_null("encode: quote is escaped", strstr(buf, "\\\""));

    tap_int_eq("decode: no error", vrmr_rules_decode_rule(buf, sizeof(buf)), 0);
    tap_str_eq("codec: round trip restores the line", buf, original);

    /* encoding twice must not escape the escape */
    (void)strlcpy(buf, plain, sizeof(buf));
    (void)vrmr_rules_encode_rule(buf, sizeof(buf));
    char once[512] = "";
    (void)strlcpy(once, buf, sizeof(once));
    (void)vrmr_rules_encode_rule(buf, sizeof(buf));
    tap_str_eq("codec: encoding is idempotent", buf, once);

    /* decoding a line that was never encoded leaves it alone */
    (void)strlcpy(buf, "accept service http from lan to dmz", sizeof(buf));
    (void)strlcpy(once, buf, sizeof(once));
    (void)vrmr_rules_decode_rule(buf, sizeof(buf));
    tap_str_eq("codec: decode of plain line is a no-op", buf, once);
}

static void test_assemble_roundtrip(void)
{
    char *line1 = NULL, *line2 = NULL;
    struct vrmr_rule *rule =
            vrmr_test_rule_parse("accept service http from lan to dmz.host1 "
                                 "options limit=10/sec,in_int=\"eth0\"\n");

    tap_non_null("assemble: rule with options parses", rule);
    if (rule == NULL)
        return;

    line1 = vrmr_rules_assemble_rule(rule);
    tap_non_null("assemble: produces a line", line1);

    struct vrmr_rule *again =
            line1 != NULL ? vrmr_test_rule_parse(line1) : NULL;
    tap_non_null("assemble: output parses again", again);
    if (again != NULL) {
        (void)tap_int_eq(
                "assemble: action survives", again->action, rule->action);
        (void)tap_str_eq(
                "assemble: service survives", again->service, rule->service);
        (void)tap_str_eq("assemble: from survives", again->from, rule->from);
        (void)tap_str_eq("assemble: to survives", again->to, rule->to);
        tap_non_null("assemble: options survive", again->opt);
        if (again->opt != NULL) {
            (void)tap_int_eq(
                    "assemble: limit value survives", again->opt->limit, 10u);
            (void)tap_str_eq("assemble: limit unit survives",
                    again->opt->limit_unit, "sec");
            (void)tap_str_eq(
                    "assemble: in_int survives", again->opt->in_int, "eth0");
        }

        /* second pass must be a fixed point */
        line2 = vrmr_rules_assemble_rule(again);
        (void)tap_str_eq("assemble: assembling is stable", line2, line1);
        free(line2);
        vrmr_test_rule_free(again);
    }

    free(line1);
    vrmr_test_rule_free(rule);
}

int main(void)
{
    if (vrmr_test_setup() < 0) {
        (void)fprintf(stdout, "Bail out! vrmr_test_setup failed\n");
        return EXIT_FAILURE;
    }

    test_basic_line();
    test_inactive_line();
    test_separator();
    test_action_names();
    test_ruletypes();
    test_protect_lines();
    test_bad_lines();
    test_options_keyword();
    test_overlong_tokens();
    test_encode_decode();
    test_assemble_roundtrip();

    vrmr_test_teardown();

    return tap_finish();
}
