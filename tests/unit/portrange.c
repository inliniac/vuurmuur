/***************************************************************************
 *   Copyright (C) 2002-2026 by Victor Julien                              *
 *   victor@vuurmuur.org                                                   *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,         *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU General Public License     *
 *   along with this program; if not, write to the                         *
 *   Free Software Foundation, Inc.,                                       *
 *   59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.             *
 ***************************************************************************/

/* Tier 0: vrmr_process_portrange(), the parser behind every portrange= line in
 * a service definition. It wrote each part of an entry into fixed stack
 * buffers without bounding itself to them, so one long line in a service file
 * overwrote the return address. Plain strings, no root, no UI. */

#include "config.h"
#include "vuurmuur.h"

#include <stdlib.h>
#include <string.h>

#include "../lib/tap.h"
#include "../lib/vrmr_test.h"

static void list_free(struct vrmr_list *list)
{
    (void)vrmr_list_cleanup(list);
}

/* one call, one service: what it returns, how many entries it made */
static int parse(const char *proto, const char *portrange, size_t *count)
{
    struct vrmr_service svc;
    struct vrmr_list_node *d_node = NULL;
    int r = 0;

    memset(&svc, 0, sizeof(svc));
    vrmr_list_setup(&svc.PortrangeList, free);

    r = vrmr_process_portrange(proto, portrange, &svc);

    *count = 0;
    for (d_node = svc.PortrangeList.top; d_node != NULL; d_node = d_node->next)
        (*count)++;

    list_free(&svc.PortrangeList);

    return r;
}

/* the first entry the call produced */
static void parse_first(
        const char *proto, const char *portrange, struct vrmr_portdata *out)
{
    struct vrmr_service svc;
    int r = 0;

    memset(out, 0, sizeof(*out));
    memset(&svc, 0, sizeof(svc));
    vrmr_list_setup(&svc.PortrangeList, free);

    r = vrmr_process_portrange(proto, portrange, &svc);
    if (r == 0 && svc.PortrangeList.top != NULL)
        memcpy(out, svc.PortrangeList.top->data, sizeof(*out));

    list_free(&svc.PortrangeList);
}

int main(void)
{
    struct vrmr_portdata pd;
    size_t count = 0;
    char long_entry[128];

    if (vrmr_test_setup() < 0) {
        (void)fprintf(stdout, "Bail out! vrmr_test_setup failed\n");
        return EXIT_FAILURE;
    }

    /* the documented form: dst*src */
    parse_first("TCP", "1024:65535*445", &pd);
    (void)tap_int_eq("portrange: dst low", pd.dst_low, 1024);
    (void)tap_int_eq("portrange: dst high", pd.dst_high, 65535);
    (void)tap_int_eq("portrange: src port", pd.src_low, 445);
    (void)tap_int_eq("portrange: protocol is TCP", pd.protocol, 6);

    /* a list of them */
    (void)tap_int_eq("portrange: comma separated entries",
            parse("TCP", "445*1024:65535,135:139*1024:65535", &count), 0);
    (void)tap_int_eq("portrange: both entries are there", (long)count, 2);

    /* an entry longer than the 32 byte scratch buffer used to run off the end
     * of it */
    memset(long_entry, '9', sizeof(long_entry) - 1);
    long_entry[sizeof(long_entry) - 1] = '\0';
    (void)tap_int_eq("portrange: an over-long entry is refused",
            parse("TCP", long_entry, &count), -1);
    (void)tap_int_eq("portrange: nothing half parsed is kept", (long)count, 0);

    /* the source half of an entry, same thing in smaller print: it fits the
     * 32 byte scratch buffer but not the 16 byte half it is split into */
    char src_case[64] = "";
    (void)snprintf(src_case, sizeof(src_case), "80*%s", "12345678901234567890");
    (void)tap_int_eq("portrange: an over-long source half is refused",
            parse("TCP", src_case, &count), -1);

    /* a trailing comma is not a port range, and used to answer with 0/0 */
    (void)tap_int_eq("portrange: a trailing comma is refused",
            parse("TCP", "80:90,", &count), -1);

    /* RANGE entries lead with the protocol number */
    parse_first("RANGE", "6;80:90*1:2", &pd);
    (void)tap_int_eq("portrange: RANGE protocol", pd.protocol, 6);
    (void)tap_int_eq("portrange: RANGE dst low", pd.dst_low, 80);

    /* not a number: atoi() answered 0, which is IP, and kept the entry */
    (void)tap_int_eq("portrange: RANGE with a junk protocol is refused",
            parse("RANGE", "abc;80:90", &count), -1);

    /* no ';' at all: the parse used to walk past the end of the entry */
    (void)tap_int_eq("portrange: RANGE without a separator is refused",
            parse("RANGE", "6*80:90", &count), -1);

    vrmr_test_teardown();

    return tap_finish();
}
