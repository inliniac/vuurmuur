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

/* Tier 0: vrmr_blocklist_init_list() over a backend that stops answering. The
 * loop asked until ask() was not 1, so a read that failed part way through read
 * exactly like the end of the file - and the caller then saved the short list
 * as the whole list, which un-blocks everything below the failure. No root, no
 * firewall: the answers are stubs. */

#include "config.h"
#include "vuurmuur.h"

#include <stdlib.h>
#include <string.h>

#include "../lib/tap.h"
#include "../lib/vrmr_test.h"

/* 1 for each rule line, then the value the stub was loaded with */
static int ask_answer[4] = {0};
static int ask_pos = 0;
static int add_calls = 0;

static int stub_ask(void *backend ATTR_UNUSED, const char *name ATTR_UNUSED,
        const char *question, char *answer, size_t max_answer,
        enum vrmr_objecttypes type ATTR_UNUSED, int multi ATTR_UNUSED)
{
    int r;

    if (strcmp(question, "RULE") != 0 || ask_pos >= 4)
        return (-1);

    r = ask_answer[ask_pos++];

    if (r == 1) {
        (void)strlcpy(answer, "block 10.0.0.9\n", max_answer);
    }

    return r;
}

static char *stub_list(void *backend ATTR_UNUSED, char *name ATTR_UNUSED,
        int *zonetype ATTR_UNUSED, enum vrmr_backend_types type ATTR_UNUSED)
{
    /* no rules listed: init_list will add() the blocklist rule and read on */
    return NULL;
}

static int stub_add(void *backend ATTR_UNUSED, const char *name ATTR_UNUSED,
        enum vrmr_objecttypes type ATTR_UNUSED)
{
    add_calls++;

    return 0;
}

static struct vrmr_plugin_data stub_rf = {
        .ask = stub_ask,
        .tell = NULL,
        .list = stub_list,
        .add = stub_add,
};

static int read_once(const int *answers)
{
    struct vrmr_blocklist blocklist;

    (void)memcpy(ask_answer, answers, sizeof(ask_answer));
    ask_pos = 0;
    add_calls = 0;

    memset(&blocklist, 0, sizeof(blocklist));

    int r = vrmr_blocklist_init_list(
            &vrmr_test_ctx, &vrmr_test_ctx.conf, &vrmr_test_ctx.zones,
            &blocklist, 1, 1);

    /* the list owns strdup'd ips and there is no blocklist teardown to call */
    (void)vrmr_list_cleanup(&blocklist.list);

    return r;
}

int main(void)
{
    if (vrmr_test_setup() < 0) {
        (void)fprintf(stdout, "Bail out! vrmr_test_setup failed\n");
        return EXIT_FAILURE;
    }

    vrmr_test_ctx.rf = &stub_rf;

    (void)tap_int_eq("a blocklist that ends reads as the whole list",
            read_once((const int[]){1, 1, 0, 0}), 0);
    (void)tap_int_eq("an empty blocklist reads as the whole list",
            read_once((const int[]){0, 0, 0, 0}), 0);
    (void)tap_int_eq("a read that fails part way is not the end of it",
            read_once((const int[]){1, 1, -1, 0}), -1);
    (void)tap_int_eq("a failure before anything is read is an error",
            read_once((const int[]){-1, 0, 0, 0}), -1);

    vrmr_test_teardown();

    return tap_finish();
}
