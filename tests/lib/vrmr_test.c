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

#include "config.h"
#include "vuurmuur.h"

#include "tap.h"
#include "vrmr_test.h"

struct vrmr_ctx vrmr_test_ctx;

/* The library printers default to stdout, which would mix parser complaints
 * into the TAP stream, so send everything to the test log instead. */

static int test_print_error(int errorcode, const char *head, char *fmt, ...)
        ATTR_FMT_PRINTF(3, 4);
static int test_print_error(int errorcode, const char *head, char *fmt, ...)
{
    va_list ap;

    (void)fprintf(stderr, "# lib error (%d) %s: ", errorcode,
            head == NULL ? "" : head);
    va_start(ap, fmt);
    (void)vfprintf(stderr, fmt, ap);
    va_end(ap);
    (void)fprintf(stderr, "\n");

    return 0;
}

static int test_print_msg(const char *head, char *fmt, ...)
        ATTR_FMT_PRINTF(2, 3);
static int test_print_msg(const char *head, char *fmt, ...)
{
    va_list ap;

    (void)fprintf(stderr, "# lib %s: ", head == NULL ? "msg" : head);
    va_start(ap, fmt);
    (void)vfprintf(stderr, fmt, ap);
    va_end(ap);
    (void)fprintf(stderr, "\n");

    return 0;
}

static int test_print_audit(char *fmt, ...) ATTR_FMT_PRINTF(1, 2);
static int test_print_audit(char *fmt, ...)
{
    va_list ap;

    (void)fprintf(stderr, "# lib audit: ");
    va_start(ap, fmt);
    (void)vfprintf(stderr, fmt, ap);
    va_end(ap);
    (void)fprintf(stderr, "\n");

    return 0;
}

int vrmr_test_setup(void)
{
    if (vrmr_init(&vrmr_test_ctx, "unit") < 0) {
        (void)tap_note("vrmr_init failed");
        return -1;
    }

    vrprint.error = test_print_error;
    vrprint.warning = test_print_msg;
    vrprint.info = test_print_msg;
    vrprint.debug = test_print_msg;
    vrprint.audit = test_print_audit;

    return 0;
}

void vrmr_test_teardown(void)
{
    vrmr_deinit(&vrmr_test_ctx);
}

struct vrmr_rule *vrmr_test_rule_parse(const char *line)
{
    char buf[VRMR_MAX_RULE_LENGTH + 2] = "";
    struct vrmr_rule *rule = NULL;

    if (strlcpy(buf, line, sizeof(buf)) >= sizeof(buf)) {
        (void)tap_note("test case line does not fit in the rule buffer");
        return NULL;
    }

    rule = vrmr_rule_malloc();
    if (rule == NULL) {
        (void)tap_note("vrmr_rule_malloc failed");
        return NULL;
    }

    if (vrmr_rules_parse_line(buf, rule, &vrmr_test_ctx.reg) < 0) {
        free(rule);
        return NULL;
    }

    return rule;
}

void vrmr_test_rule_free(struct vrmr_rule *rule)
{
    if (rule == NULL)
        return;

    /* frees the struct held by rule->opt as well */
    vrmr_rules_free_options(rule->opt);
    free(rule);
}

struct vrmr_rule_options *vrmr_test_opt_new(void)
{
    struct vrmr_rule_options *opt = vrmr_rule_option_malloc();

    if (opt == NULL)
        (void)tap_note("vrmr_rule_option_malloc failed");

    return opt;
}

int vrmr_test_opt_read(struct vrmr_rule_options *opt, const char *optstr)
{
    if (opt == NULL)
        return -1;

    return vrmr_rules_read_options(optstr, opt);
}

struct vrmr_portdata *vrmr_test_port_first(struct vrmr_list *list)
{
    if (list == NULL || list->top == NULL)
        return NULL;

    return list->top->data;
}
