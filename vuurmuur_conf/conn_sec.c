/***************************************************************************
 *   Copyright (C) 2003-2021 by Victor Julien                              *
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

#include "main.h"

struct conntrack conntrack;

/* internal stuff */
static int fromzone_width = 0, tozone_width = 0, service_width = 0;

/* taken from suricata:src/util-device.c
 * turn long string abcdefghi into "abc~ghi"
 * if output_size is even (so available space odd because of nul byte,
 * we prefer the start: "abcd~ghi"
 */
void shorten_name(const char *input, char *output, size_t output_size)
{
    const size_t str_len = StrLen(input);
    const size_t half = (output_size - 1) / 2;
    size_t lhalf = half;       // left half
    const size_t rhalf = half; // right half

    /* If the output size is an even number */
    if (half * 2 == (output_size - 1)) {
        lhalf--;
    }

    /* Add the first half to the new string */
    snprintf(output, lhalf + 1, "%s", input);

    /* Add the amount of spaces wanted */
    size_t length = strlcat(output, "~", output_size);

    snprintf(output + length, rhalf + 1, "%s", input + (str_len - rhalf));
}

/* wrapper for strlcpy, that truncates a string a little nicer */
static void copy_name(char *dst, char *src, size_t size)
{
    size_t srclen = StrLen(src);
    if (srclen < size) {
        (void)strlcpy(dst, src, size);
        /* pad with spaces */
        size_t left = size - srclen + 1;
        while (left) {
            strlcat(dst, " ", size);
            left--;
        }
    } else {
        shorten_name(src, dst, size);
    }
}

static int get_space(WINDOW *w, int size)
{
    int _y, x;
    getyx(w, _y, x);
    (void)_y;
    const int left = size - x;
    return left;
}

/**
 *  \param acct print accounting is enabled
 */
static int print_connection(WINDOW *local_win,
        struct vrmr_conntrack_entry *cd_ptr,
        struct vrmr_conntrack_request *connreq, int max_onscreen, int cnt,
        const int screen_width, int acct)
{
    int start_print = 0;
    char printline[256] = "";
    const int printline_max = MIN((int)sizeof(printline), screen_width);
    int printline_width = printline_max;
    char servicename[32] = "";
    char zonename[46] = "";
    char bw_str[9] = "";
    const bool start_with_service = (connreq->group_conns == FALSE);

    /* determine the position where we are going to write */
    if (connreq->sort_conn_status) {
        if (cd_ptr->connect_status == VRMR_CONN_CONNECTING) {
            start_print = (max_onscreen / 4) * 2 + 1 + cnt;
        } else if (cd_ptr->connect_status == VRMR_CONN_DISCONNECTING) {
            start_print = (max_onscreen / 4) * 3 + 1 + cnt;
        } else {
            start_print = cnt + 3;
        }
    } else if (connreq->sort_in_out_fwd) {
        if (cd_ptr->direction_status == VRMR_CONN_IN) {
            start_print = (max_onscreen / 3) + 3 + 1 + cnt;
        } else if (cd_ptr->direction_status == VRMR_CONN_OUT) {
            start_print = (max_onscreen / 3) * 2 + 2 + 1 + cnt;
        } else {
            start_print = cnt + 3;
        }
    } else {
        start_print = cnt;
    }

    if (connreq->group_conns == TRUE) {
        /* display count */
        wattron(local_win, vccnf.color_bgd_yellow | A_BOLD);
        snprintf(printline, printline_width, "%4d: ", cd_ptr->cnt);
        mvwprintw(local_win, start_print, 0, "%s", printline);
        wattroff(local_win, vccnf.color_bgd_yellow | A_BOLD);

        printline_width = get_space(local_win, printline_max);
        if (printline_width <= 0)
            return (1);
    }

    /* SERVICE name */
    wattron(local_win, vccnf.color_bgd_cyan | A_BOLD);
    copy_name(servicename, cd_ptr->sername, service_width);
    strlcpy(printline, servicename, printline_width);
    if (start_with_service) {
        mvwprintw(local_win, start_print, 0, "%s ", printline);
    } else {
        wprintw(local_win, "%s ", printline);
    }
    wattroff(local_win, vccnf.color_bgd_cyan | A_BOLD);

    /* FROM name */
    printline_width = get_space(local_win, printline_max);
    if (printline_width <= 0)
        return (1);
    if (strncmp(cd_ptr->fromname, "firewall", 8) == 0)
        wattron(local_win, vccnf.color_bgd_yellow | A_BOLD);
    else
        wattron(local_win, vccnf.color_bgd | A_BOLD);
    copy_name(zonename, cd_ptr->fromname, fromzone_width);
    strlcpy(printline, zonename, printline_width);
    wprintw(local_win, "%s ", printline);
    if (strncmp(cd_ptr->fromname, "firewall", 8) == 0)
        wattroff(local_win, vccnf.color_bgd_yellow | A_BOLD);
    else
        wattroff(local_win, vccnf.color_bgd | A_BOLD);

    /* ARROW */
    printline_width = get_space(local_win, printline_max);
    if (printline_width <= 0)
        return (1);
    snprintf(printline, printline_width, "->");
    wprintw(local_win, "%s ", printline);

    /* TO name */
    printline_width = get_space(local_win, printline_max);
    if (printline_width <= 0)
        return (1);
    if (strncmp(cd_ptr->toname, "firewall", 8) == 0)
        wattron(local_win, vccnf.color_bgd_yellow | A_BOLD);
    else
        wattron(local_win, vccnf.color_bgd | A_BOLD);
    copy_name(zonename, cd_ptr->toname, tozone_width);
    strlcpy(printline, zonename, printline_width);
    wprintw(local_win, "%s ", printline);
    if (strncmp(cd_ptr->toname, "firewall", 8) == 0)
        wattroff(local_win, vccnf.color_bgd_yellow | A_BOLD);
    else
        wattroff(local_win, vccnf.color_bgd | A_BOLD);

    printline_width = get_space(local_win, printline_max);
    if (printline_width <= 0)
        return (1);

    /* Connection status */
    if (!connreq->sort_conn_status) {
        if (cd_ptr->connect_status == VRMR_CONN_CONNECTING) {
            wattron(local_win, vccnf.color_bgd_green | A_BOLD);

            /* TRANSLATORS: max 4 chars: CONNECTING, like building a new
             * connection. */
            snprintf(printline, printline_width, "%-4s", gettext("CONN"));
            wprintw(local_win, "%s ", printline);

            wattroff(local_win, vccnf.color_bgd_green | A_BOLD);
        } else if (cd_ptr->connect_status == VRMR_CONN_CONNECTED) {
            wattron(local_win, vccnf.color_bgd_yellow | A_BOLD);

            /* TRANSLATORS: max 4 chars: ESTABLISHED, an existing connection. */
            snprintf(printline, printline_width, "%-4s", gettext("ESTA"));
            wprintw(local_win, "%s ", printline);

            wattroff(local_win, vccnf.color_bgd_yellow | A_BOLD);
        } else if (cd_ptr->connect_status == VRMR_CONN_DISCONNECTING) {
            wattron(local_win, vccnf.color_bgd_red | A_BOLD);

            /* TRANSLATORS: max 4 chars: DISCONNECTING, an existing connection
             * is shutting down. */
            snprintf(printline, printline_width, "%-4s", gettext("DISC"));
            wprintw(local_win, "%s ", printline);

            wattroff(local_win, vccnf.color_bgd_red | A_BOLD);
        } else {
            wprintw(local_win, "%-4s ", "-");
        }
    }

    printline_width = get_space(local_win, printline_max);
    if (printline_width <= 0)
        return (1);

    if (!connreq->sort_in_out_fwd) {
        if (cd_ptr->direction_status == VRMR_CONN_IN) {
            wattron(local_win, vccnf.color_bgd_cyan | A_BOLD);

            /* TRANSLATORS: max 3 chars: INCOMING, an incoming connection. */
            snprintf(printline, printline_width, "%-4s", gettext("IN"));
            wprintw(local_win, "%s", printline);
            wattroff(local_win, vccnf.color_bgd_cyan | A_BOLD);
        } else if (cd_ptr->direction_status == VRMR_CONN_OUT) {
            wattron(local_win, vccnf.color_bgd_cyan | A_BOLD);
            /* TRANSLATORS: max 3 chars: OUTGOING, an outgoing connection. */
            snprintf(printline, printline_width, "%-4s", gettext("OUT"));
            wprintw(local_win, "%s", printline);
            wattroff(local_win, vccnf.color_bgd_cyan | A_BOLD);
        } else if (cd_ptr->direction_status == VRMR_CONN_FW) {
            wattron(local_win, vccnf.color_bgd_yellow | A_BOLD);
            /* TRANSLATORS: max 3 chars: FORWARDING, an forwarding connection.
             */
            snprintf(printline, printline_width, "%-4s", gettext("FWD"));
            wprintw(local_win, "%s", printline);
            wattroff(local_win, vccnf.color_bgd_yellow | A_BOLD);
        }
    }

    printline_width = get_space(local_win, printline_max);
    if (printline_width <= 0)
        return (1);

    if (connreq->draw_acc_data == TRUE && acct == TRUE) {
        if (cd_ptr->use_acc == FALSE)
            snprintf(bw_str, sizeof(bw_str), "  n/a");
        else if (cd_ptr->to_src_bytes == 0)
            snprintf(bw_str, sizeof(bw_str), "  0 b");
        /* 1 byte - 999 bytes */
        else if (cd_ptr->to_src_bytes > 0 && cd_ptr->to_src_bytes < 1000)
            snprintf(bw_str, sizeof(bw_str), "%3u b",
                    (unsigned int)cd_ptr->to_src_bytes);
        /* 1kb - 999kb */
        else if (cd_ptr->to_src_bytes >= 1000 && cd_ptr->to_src_bytes < 1000000)
            snprintf(bw_str, sizeof(bw_str), "%3.0f k",
                    (float)cd_ptr->to_src_bytes / 1024);
        /* 1mb - 10mb */
        else if (cd_ptr->to_src_bytes >= 1000000 &&
                 cd_ptr->to_src_bytes < 10000000)
            snprintf(bw_str, sizeof(bw_str), "%1.1f M",
                    (float)cd_ptr->to_src_bytes / (1024 * 1024));
        /* 10mb - 1000mb */
        else if (cd_ptr->to_src_bytes >= 10000000 &&
                 cd_ptr->to_src_bytes < 1000000000)
            snprintf(bw_str, sizeof(bw_str), "%3.0f M",
                    (float)cd_ptr->to_src_bytes / (1024 * 1024));
        else if (cd_ptr->to_src_bytes >= 1000000000 &&
                 cd_ptr->to_src_bytes < 10000000000ULL)
            snprintf(bw_str, sizeof(bw_str), "%1.1f G",
                    (float)cd_ptr->to_src_bytes / (1024 * 1024 * 1024));
        else if (cd_ptr->to_src_bytes >= 10000000000ULL &&
                 cd_ptr->to_src_bytes < 100000000000ULL)
            snprintf(bw_str, sizeof(bw_str), "%3.0f G",
                    (float)cd_ptr->to_src_bytes / (1024 * 1024 * 1024));
        else
            snprintf(bw_str, sizeof(bw_str), "%3.0f G",
                    (float)cd_ptr->to_src_bytes / (1024 * 1024 * 1024));

        snprintf(printline, printline_width, "<- %-5s ", bw_str);
        wprintw(local_win, "%s", printline);

        printline_width = get_space(local_win, printline_max);
        if (printline_width <= 0)
            return (1);

        if (cd_ptr->use_acc == FALSE)
            snprintf(bw_str, sizeof(bw_str), "  n/a");
        else if (cd_ptr->to_dst_bytes == 0)
            snprintf(bw_str, sizeof(bw_str), "  0 b");
        /* 1 byte - 999 bytes */
        else if (cd_ptr->to_dst_bytes > 0 && cd_ptr->to_dst_bytes < 1000)
            snprintf(bw_str, sizeof(bw_str), "%3u b",
                    (unsigned int)cd_ptr->to_dst_bytes);
        /* 1kb - 999kb */
        else if (cd_ptr->to_dst_bytes >= 1000 && cd_ptr->to_dst_bytes < 1000000)
            snprintf(bw_str, sizeof(bw_str), "%3.0f k",
                    (float)cd_ptr->to_dst_bytes / 1024);
        /* 1mb - 10mb */
        else if (cd_ptr->to_dst_bytes >= 1000000 &&
                 cd_ptr->to_dst_bytes < 10000000)
            snprintf(bw_str, sizeof(bw_str), "%1.1f M",
                    (float)cd_ptr->to_dst_bytes / (1024 * 1024));
        /* 10mb - 1000mb */
        else if (cd_ptr->to_dst_bytes >= 10000000 &&
                 cd_ptr->to_dst_bytes < 1000000000)
            snprintf(bw_str, sizeof(bw_str), "%3.0f M",
                    (float)cd_ptr->to_dst_bytes / (1024 * 1024));
        else if (cd_ptr->to_dst_bytes >= 1000000000 &&
                 cd_ptr->to_dst_bytes < 10000000000ULL)
            snprintf(bw_str, sizeof(bw_str), "%1.1f G",
                    (float)cd_ptr->to_dst_bytes / (1024 * 1024 * 1024));
        else if (cd_ptr->to_dst_bytes >= 10000000000ULL &&
                 cd_ptr->to_dst_bytes < 100000000000ULL)
            snprintf(bw_str, sizeof(bw_str), "%3.0f G",
                    (float)cd_ptr->to_dst_bytes / (1024 * 1024 * 1024));
        else
            snprintf(bw_str, sizeof(bw_str), "%3.0f G",
                    (float)cd_ptr->to_dst_bytes / (1024 * 1024 * 1024));

        snprintf(printline, printline_width, "%5s -> ", bw_str);
        wprintw(local_win, "%s", printline);
    }

    printline_width = get_space(local_win, printline_max);
    if (printline_width < 10) {
        return (1);
    }

    if (connreq->draw_details == TRUE) {
        if (cd_ptr->src_port == 0 && cd_ptr->dst_port == 0) {
            snprintf(printline, printline_width, "%s -> %s PROTO %d",
                    cd_ptr->src_ip, cd_ptr->dst_ip, cd_ptr->protocol);
        } else if (cd_ptr->cnt > 1) {
            snprintf(printline, printline_width, "%s -> %s:%d %s",
                    cd_ptr->src_ip, cd_ptr->dst_ip, cd_ptr->dst_port,
                    cd_ptr->protocol == IPPROTO_TCP ? "TCP" : "UDP");
        } else {
            if (cd_ptr->protocol == IPPROTO_TCP) {
                snprintf(printline, printline_width,
                        "%s:%d -> %s:%d TCP state:%s %s%s", cd_ptr->src_ip,
                        cd_ptr->src_port, cd_ptr->dst_ip, cd_ptr->dst_port,
                        cd_ptr->state_string,
                        strlen(cd_ptr->helper) ? "helper:" : "",
                        cd_ptr->helper);
            } else if (cd_ptr->protocol == IPPROTO_UDP) {
                snprintf(printline, printline_width, "%s:%d -> %s:%d UDP",
                        cd_ptr->src_ip, cd_ptr->src_port, cd_ptr->dst_ip,
                        cd_ptr->dst_port);
            } else {
                snprintf(printline, printline_width, "%s:%d -> %s:%d (%d) ",
                        cd_ptr->src_ip, cd_ptr->src_port, cd_ptr->dst_ip,
                        cd_ptr->dst_port, cd_ptr->protocol);
            }
        }
        wprintw(local_win, "%s", printline);
    }
    return (1);
}

static void update_draw_size(
        int width, int service_request, int from_request, int to_request)
{
    /* max: cnt sp ser sp from sp arrow sp to sp stat sp dir
     *        5  1   15 1   46  1     2  1 46  1    5  1   4 = 129 */
#define FIXED 20
    int left = width - FIXED;
    int serw = left * 0.3;
    serw = MIN(serw, service_request);
    left -= serw;

    int fromw = left * 0.4;
    fromw = MIN(fromw, from_request);
    left -= fromw;

    int tow = left;
    tow = MIN(tow, to_request);
    left -= tow;
    (void)left;

    service_width = serw;
    fromzone_width = fromw;
    tozone_width = tow;
}

void conn_free_ct(struct conntrack **ct, struct vrmr_zones *zones)
{
    /* zones may be NULL if we have multiple ct's */
    if (zones != NULL) {
        /*  remove the interfaces inserted as VRMR_TYPE_FIREWALL's into the
           zonelist this also removes zones added by
           vrmr_add_broadcasts_zonelist()
        */
        vrmr_fatal_if(vrmr_rem_iface_from_zonelist(&zones->list) < 0);
    }

    /* cleanup */
    vrmr_list_cleanup(&(*ct)->network_list);
    /* destroy hashtables */
    vrmr_hash_cleanup(&(*ct)->zone_hash);
    vrmr_hash_cleanup(&(*ct)->service_hash);
    free(*ct);
}

struct conntrack *ATTR_RETURNS_NONNULL conn_init_ct(struct vrmr_zones *zones,
        struct vrmr_interfaces *interfaces, struct vrmr_services *services)
{
    struct conntrack *ct = calloc(1, sizeof(*ct));
    vrmr_fatal_alloc("calloc", ct);

    /*  insert the interfaces as VRMR_TYPE_FIREWALL's into the zonelist
        as 'firewall', so this appears in to the connections */
    vrmr_fatal_if(
            vrmr_ins_iface_into_zonelist(&interfaces->list, &zones->list) < 0);

    /*  do the same for broadcasts. These are removed by:
        vrmr_rem_iface_from_zonelist() (see below) */
    vrmr_fatal_if(vrmr_add_broadcasts_zonelist(zones) < 0);

    /* create hashtables */
    vrmr_fatal_if(vrmr_init_zonedata_hashtable(zones->list.len * 3,
                          &zones->list, vrmr_hash_ipaddress,
                          vrmr_compare_ipaddress, &ct->zone_hash) < 0);

    /*  the hashtable size may seem very big, but some services have
        really a lot items. e.g. 137->1024:65535 */
    vrmr_fatal_if(vrmr_init_services_hashtable(services->list.len * 500,
                          &services->list, vrmr_hash_port, vrmr_compare_ports,
                          &ct->service_hash) < 0);

    /*  initialize this list with destroy is null, because it only
        points to zonedatalist nodes */
    vrmr_list_setup(&ct->network_list, NULL);
    vrmr_zonelist_to_networklist(zones, &ct->network_list);

    /* initialize the prev size because it is used in get_connections */
    ct->prev_list_size = 500;
    return (ct);
}

static int conn_sort_by_cnt(const void *a, const void *b)
{
    /* we're sorting an array of pointers, so we need to deref
     * our input to get to the good stuff. */
    const struct vrmr_conntrack_entry *s0 =
            *(const struct vrmr_conntrack_entry **)a;
    const struct vrmr_conntrack_entry *s1 =
            *(const struct vrmr_conntrack_entry **)b;
    if (s1->cnt == s0->cnt)
        return 0;
    else
        return s0->cnt > s1->cnt ? -1 : 1;
}

int conn_ct_get_connections(struct vrmr_config *cnf, struct conntrack *ct,
        struct vrmr_conntrack_request *req)
{
    ct->conn_stats.fromname_max = ct->conn_stats.toname_max =
            ct->conn_stats.sername_max = 0;

    vrmr_list_setup(&ct->conn_list, NULL);

#ifdef IPV6_ENABLED
    req->ipv6 = 1;
#endif

    /* get the connections from the proc */
    if (vrmr_conn_get_connections(cnf, ct->prev_list_size, &ct->service_hash,
                &ct->zone_hash, &ct->conn_list, &ct->network_list, req,
                &ct->conn_stats) < 0) {
        vrmr_error(-1, VR_ERR, gettext("getting the connections failed."));
        return (-1);
    }

    if (ct->conn_list.len == 0)
        return (0);

    /* fill the array and sort it */

    vrmr_fatal_if(ct->conn_array);
    ct->conn_array =
            calloc(ct->conn_list.len, sizeof(struct vrmr_conntrack_entry *));
    vrmr_fatal_alloc("calloc", ct->conn_array);

    struct vrmr_list_node *d_node;
    unsigned int x = 0;
    for (d_node = ct->conn_list.top; d_node != NULL; d_node = d_node->next) {
        vrmr_fatal_if_null(d_node->data);
        ct->conn_array[x] = d_node->data;
        x++;
    }
    qsort(ct->conn_array, ct->conn_list.len,
            sizeof(struct vrmr_conntrack_entry *), conn_sort_by_cnt);

    return (0);
}

void conn_ct_clear_connections(struct conntrack *ct)
{
    /* store prev list size */
    ct->prev_list_size = ct->conn_list.len;
    vrmr_conn_list_cleanup(&ct->conn_list);
    free(ct->conn_array);
    ct->conn_array = NULL;
}

int connections_section(struct vrmr_ctx *vctx, struct vrmr_config *cnf,
        struct vrmr_zones *zones, struct vrmr_interfaces *interfaces,
        struct vrmr_services *services, struct vrmr_blocklist *blocklist)
{
    int retval = 0;
    WINDOW *conn_win = NULL;
    PANEL *my_panels[1];
    int quit = 0, ch = 0;

    int max_onscreen = 0, max_height = 0, max_width = 0, connecting = 0,
        connected = 0, disconnecting = 0, max_connecting = 0, max_connected = 0,
        max_disconnecting = 0, incoming = 0, forwarding = 0, outgoing = 0,
        max_incoming = 0, max_forwarding = 0, max_outgoing = 0;

    struct {
        char print; /* do we print to screen this run? */
        char sleep; /* do we sleep this run */
        char pause; /* are we in pause mode? 0 no, 1 yes */
    } control = {
            0,
            0,
            0,
    };

    int update_interval =
            1000000;            /* weird, in pratice this seems to be two sec */
    int slept_so_far = 1000000; /* time slept since last update */

    /* top menu */
    const char *key_choices[] = {
            "F12", "m", "i", "c", "g", "u", "f", "a", "d", "F10"};
    int key_choices_n = 10;
    const char *cmd_choices[] = {gettext("help"), gettext("manage"),
            gettext("in/out/fw"), gettext("connect"), gettext("grp"),
            gettext("unknown ip"), gettext("filter"), gettext("account"),
            gettext("details"), gettext("back")};
    int cmd_choices_n = 10;

    struct conntrack *ct = NULL;
    struct vrmr_conntrack_request connreq;
    int printed = 0;
    int print_accounting = 0;

    /* init filter */
    vrmr_connreq_setup(&connreq);
    connreq.group_conns = TRUE;
    connreq.unknown_ip_as_net = TRUE;
    /* sorting, relevant for grouping */
    connreq.sort_in_out_fwd = FALSE;
    connreq.sort_conn_status = FALSE;
    /* drawing */
    connreq.draw_acc_data = TRUE;
    connreq.draw_details = TRUE;

    /* set up & create the logwin */
    getmaxyx(stdscr, max_height, max_width);
    max_onscreen = max_height - 8;
    conn_win = newwin(max_height - 8, max_width - 2, 4, 1);
    wbkgd(conn_win, vccnf.color_bgd);
    my_panels[0] = new_panel(conn_win);
    keypad(conn_win, TRUE);
    /* make sure wgetch doesn't block the printing of the screen */
    nodelay(conn_win, TRUE);
    /* dont display the cursor */
    curs_set(0);

    ct = conn_init_ct(zones, interfaces, services);
    vrmr_fatal_if_null(ct);

    draw_top_menu(top_win, gettext("Connections"), key_choices_n, key_choices,
            cmd_choices_n, cmd_choices);

    /* the main loop */
    while (quit == 0) {
        control.sleep = 1;

        if (control.pause)
            control.print = 0;
        else
            control.print = 1;

        /* check if we have slept long enough */
        if (slept_so_far >= update_interval && !control.pause) {
            vrmr_debug(LOW, "now update: slept_so_far '%d'.", slept_so_far);

            /* reset the wait counter */
            slept_so_far = 0;

            /* TODO retval */
            conn_ct_get_connections(cnf, ct, &connreq);

            if (ct->conn_stats.accounting == 1)
                print_accounting = 1;
            else
                print_accounting = 0;

            update_draw_size(max_width - 2, ct->conn_stats.sername_max + 1,
                    ct->conn_stats.fromname_max + 1,
                    ct->conn_stats.toname_max + 1);

            /* determine how many lines we can draw for each section */
            if (connreq.sort_conn_status) {
                /* connected get half the screen, connecting and disconnecting
                 * both 1/4 */
                max_connecting = (max_onscreen / 4) - 1;
                max_connected = (max_onscreen / 4) * 2 - 1 - 2;
                max_disconnecting = (max_onscreen / 4) - 1;

                connecting = 0;
                connected = 0;
                disconnecting = 0;
            } else if (connreq.sort_in_out_fwd) {
                /* three equal parts */
                max_incoming = (max_onscreen / 3) - 2;
                max_forwarding = (max_onscreen / 3);
                max_outgoing = (max_onscreen / 3) - 3;

                incoming = 0;
                forwarding = 0;
                outgoing = 0;
            }

            /* clear screen */
            if (control.print)
                werase(conn_win);

            /* dump connections to screen */
            if (control.print && ct->conn_array != NULL) {
                const unsigned int array_size = ct->conn_list.len;
                unsigned int idx = 0;

                for (printed = 0; printed < max_onscreen && idx < array_size;
                        idx++) {
                    struct vrmr_conntrack_entry *cd_ptr = ct->conn_array[idx];
                    vrmr_fatal_if_null(cd_ptr);

                    if (connreq.sort_conn_status) {
                        if (cd_ptr->connect_status == VRMR_CONN_CONNECTING) {
                            if (connecting < max_connecting) {
                                if (print_connection(conn_win, cd_ptr, &connreq,
                                            max_onscreen, connecting,
                                            max_width - 2,
                                            print_accounting) == 1) {
                                    connecting++;
                                    printed++;
                                }
                            }
                        } else if (cd_ptr->connect_status ==
                                   VRMR_CONN_DISCONNECTING) {
                            if (disconnecting < max_disconnecting) {
                                if (print_connection(conn_win, cd_ptr, &connreq,
                                            max_onscreen, disconnecting,
                                            max_width - 2,
                                            print_accounting) == 1) {
                                    disconnecting++;
                                    printed++;
                                }
                            }
                        } else {
                            if (connected < max_connected) {
                                if (print_connection(conn_win, cd_ptr, &connreq,
                                            max_onscreen, connected,
                                            max_width - 2,
                                            print_accounting) == 1) {
                                    connected++;
                                    printed++;
                                }
                            }
                        }

                        /* check if it usefull to continue the loop */
                        if (connecting == max_connecting &&
                                disconnecting == max_disconnecting &&
                                connected == max_connected) {
                            break;
                        }
                    } else if (connreq.sort_in_out_fwd) {
                        if (cd_ptr->direction_status == VRMR_CONN_IN) {
                            if (incoming < max_incoming) {
                                if (print_connection(conn_win, cd_ptr, &connreq,
                                            max_onscreen, incoming,
                                            max_width - 2,
                                            print_accounting) == 1) {
                                    incoming++;
                                    printed++;
                                }
                            }
                        } else if (cd_ptr->direction_status == VRMR_CONN_OUT) {
                            if (outgoing < max_outgoing) {
                                if (print_connection(conn_win, cd_ptr, &connreq,
                                            max_onscreen, outgoing,
                                            max_width - 2,
                                            print_accounting) == 1) {
                                    outgoing++;
                                    printed++;
                                }
                            }
                        } else {
                            if (forwarding < max_forwarding) {
                                if (print_connection(conn_win, cd_ptr, &connreq,
                                            max_onscreen, forwarding,
                                            max_width - 2,
                                            print_accounting) == 1) {
                                    forwarding++;
                                    printed++;
                                }
                            }
                        }

                        /* check if it usefull to continue the loop */
                        if (incoming == max_incoming &&
                                outgoing == max_outgoing &&
                                forwarding == max_forwarding) {
                            break;
                        }
                    } else {
                        if (print_connection(conn_win, cd_ptr, &connreq,
                                    max_onscreen, printed, max_width - 2,
                                    print_accounting) == 1) {
                            printed++;
                        }

                        /* check if it usefull to continue the loop */
                        if (printed == max_onscreen)
                            break;
                    }
                }
            }
            if (control.print) {
                /* print the seperators */
                if (connreq.sort_conn_status) {
                    wattron(conn_win, vccnf.color_bgd_green | A_BOLD);
                    mvwprintw(conn_win, 0, 4, "%s:", gettext("Connections"));
                    mvwprintw(conn_win, 0, 20, "%s:", gettext("Total"));
                    mvwprintw(conn_win, 0, 40, "%s:", gettext("Incoming"));
                    mvwprintw(conn_win, 0, 64, "%s:", gettext("Forwarding"));
                    mvwprintw(conn_win, 1, 40, "%s:", gettext("Outgoing"));

                    mvwprintw(
                            conn_win, 0, 34, "%4d", ct->conn_stats.conn_total);
                    mvwprintw(conn_win, 0, 58, "%4d", ct->conn_stats.conn_in);
                    mvwprintw(conn_win, 0, 78, "%4d", ct->conn_stats.conn_fw);
                    mvwprintw(conn_win, 1, 58, "%4d", ct->conn_stats.conn_out);

                    wattroff(conn_win, vccnf.color_bgd_green | A_BOLD);

                    //
                    mvwhline(conn_win, 2, 0, ACS_HLINE, max_width - 2);
                    wattron(conn_win, vccnf.color_bgd_yellow | A_BOLD);
                    mvwprintw(conn_win, 2, 3, " %s ",
                            gettext("Established Connections"));
                    mvwprintw(conn_win, 2, max_width - 11, " (%d) ",
                            ct->conn_stats.stat_estab);
                    wattroff(conn_win, vccnf.color_bgd_yellow | A_BOLD);

                    // print at the half of the screen
                    mvwhline(conn_win, (max_onscreen / 4) * 2, 0, ACS_HLINE,
                            max_width - 2);
                    wattron(conn_win, vccnf.color_bgd_green | A_BOLD);
                    mvwprintw(conn_win, (max_onscreen / 4) * 2, 3, " %s ",
                            gettext("Connections Initializing"));
                    mvwprintw(conn_win, (max_onscreen / 4) * 2, max_width - 11,
                            " (%d) ", ct->conn_stats.stat_connect);
                    wattroff(conn_win, vccnf.color_bgd_green | A_BOLD);

                    mvwhline(conn_win, (max_onscreen / 4) * 3, 0, ACS_HLINE,
                            max_width - 2);
                    wattron(conn_win, vccnf.color_bgd_red | A_BOLD);
                    mvwprintw(conn_win, (max_onscreen / 4) * 3, 3, " %s ",
                            gettext("Connections Closing"));
                    mvwprintw(conn_win, (max_onscreen / 4) * 3, max_width - 11,
                            " (%d) ", ct->conn_stats.stat_closing);
                    wattroff(conn_win, vccnf.color_bgd_red | A_BOLD);

                    // move the cursor a bit out of sight
                    mvwprintw(conn_win, max_onscreen - 1, max_width - 3, " ");
                }

                if (connreq.sort_in_out_fwd) {
                    wattron(conn_win, vccnf.color_bgd_green | A_BOLD);
                    mvwprintw(conn_win, 0, 4, "%s:", gettext("Connections"));
                    mvwprintw(conn_win, 0, 20, "%s:", gettext("Total"));
                    mvwprintw(conn_win, 0, 40, "%s:", gettext("Connecting"));
                    mvwprintw(conn_win, 0, 64, "%s:", gettext("Established"));
                    mvwprintw(conn_win, 1, 40, "%s:", gettext("Disconnecting"));

                    mvwprintw(
                            conn_win, 0, 34, "%4d", ct->conn_stats.conn_total);
                    mvwprintw(conn_win, 0, 58, "%4d",
                            ct->conn_stats.stat_connect);
                    mvwprintw(
                            conn_win, 0, 78, "%4d", ct->conn_stats.stat_estab);
                    mvwprintw(conn_win, 1, 58, "%4d",
                            ct->conn_stats.stat_closing);
                    wattroff(conn_win, vccnf.color_bgd_green | A_BOLD);

                    /* */
                    mvwhline(conn_win, 2, 0, ACS_HLINE, max_width - 2);
                    wattron(conn_win, vccnf.color_bgd_yellow | A_BOLD);
                    mvwprintw(conn_win, 2, 3, " %s ",
                            gettext("Forwarded Connections"));
                    mvwprintw(conn_win, 2, max_width - 11, " (%d) ",
                            ct->conn_stats.conn_fw);
                    wattroff(conn_win, vccnf.color_bgd_yellow | A_BOLD);

                    /* print at the one third of the screen */
                    mvwhline(conn_win, (max_onscreen / 3) + 3, 0, ACS_HLINE,
                            max_width - 2);
                    wattron(conn_win, vccnf.color_bgd_green | A_BOLD);
                    mvwprintw(conn_win, (max_onscreen / 3) + 3, 3, " %s ",
                            gettext("Incoming Connections"));
                    mvwprintw(conn_win, (max_onscreen / 3) + 3, max_width - 11,
                            " (%d) ", ct->conn_stats.conn_in);
                    wattroff(conn_win, vccnf.color_bgd_green | A_BOLD);

                    mvwhline(conn_win, (max_onscreen / 3) * 2 + 2, 0, ACS_HLINE,
                            max_width - 2);
                    wattron(conn_win, vccnf.color_bgd_red | A_BOLD);
                    mvwprintw(conn_win, (max_onscreen / 3) * 2 + 2, 3, " %s ",
                            gettext("Outgoing Connections"));
                    mvwprintw(conn_win, (max_onscreen / 3) * 2 + 2,
                            max_width - 11, " (%d) ", ct->conn_stats.conn_out);
                    wattroff(conn_win, vccnf.color_bgd_red | A_BOLD);

                    /* move the cursor a bit out of sight */
                    mvwprintw(conn_win, max_onscreen - 1, max_width - 3, " ");
                }

                wrefresh(conn_win);
            }

            conn_ct_clear_connections(ct);
        }

        /*
            //////// HANDLE KEYBOARD //////////
        */
        ch = wgetch(conn_win);
        switch (ch) {
            /* QUIT */
            case 27:
            case 'q':
            case 'Q':
            case KEY_F(10):
                quit = 1;
                control.sleep = 0;
                break;

            case 'u':
                if (connreq.unknown_ip_as_net == TRUE) {
                    connreq.unknown_ip_as_net = FALSE;
                } else {
                    connreq.unknown_ip_as_net = TRUE;
                }

                control.sleep = 0;
                break;

            case 'g':
                if (connreq.group_conns == TRUE) {
                    connreq.group_conns = FALSE;
                } else {
                    connreq.group_conns = TRUE;
                }

                control.sleep = 0;
                break;

            case 'c':
                if (connreq.sort_conn_status == TRUE) {
                    connreq.sort_conn_status = FALSE;
                } else {
                    connreq.sort_conn_status = TRUE;
                    connreq.sort_in_out_fwd = FALSE;
                }

                control.sleep = 0;
                break;

            case 'i':
                if (connreq.sort_in_out_fwd == TRUE) {
                    connreq.sort_in_out_fwd = FALSE;
                } else {
                    connreq.sort_in_out_fwd = TRUE;
                    connreq.sort_conn_status = FALSE;
                }

                control.sleep = 0;
                break;

            case 'a':
                if (connreq.draw_acc_data == TRUE) {
                    connreq.draw_acc_data = FALSE;
                } else {
                    connreq.draw_acc_data = TRUE;
                }

                control.sleep = 0;
                break;

            case 'd':
                if (connreq.draw_details == TRUE) {
                    connreq.draw_details = FALSE;
                } else {
                    connreq.draw_details = TRUE;
                }

                control.sleep = 0;
                break;

            // PAUSE
            case 'p':
            case 32: // space

                if (control.pause == 1) {
                    status_print(status_win, "%s", "");
                    control.pause = 0;
                } else {
                    control.pause = 1;
                    status_print(status_win,
                            "*** PAUSED *** (press 'p' to continue)");
                }

                control.sleep = 0;
                break;

            case 'f':
            case 'F':
            case 10:

                if (ch != 10) {
                    filter_input_box(&connreq.filter);
                } else {
                    vrmr_filter_cleanup(&connreq.filter);
                }

                if (connreq.filter.reg_active == TRUE) {
                    status_print(status_win,
                            gettext("Active filter: '%s' (press 'enter' to "
                                    "clear)."),
                            connreq.filter.str);
                    connreq.use_filter = TRUE;
                } else if (connreq.use_filter == TRUE &&
                           connreq.filter.reg_active == FALSE) {
                    status_print(status_win, gettext("Filter removed."));
                    connreq.use_filter = FALSE;
                }

                break;

            /* manage / kill */
            case 'm':
            case 'M':
            case 'k':

                conn_ct_get_connections(cnf, ct, &connreq);
                statevent(vctx, cnf, STATEVENTTYPE_CONN, &ct->conn_list, ct,
                        &connreq, zones, blocklist, interfaces, services);
                conn_ct_clear_connections(ct);

                draw_top_menu(top_win, gettext("Connections"), key_choices_n,
                        key_choices, cmd_choices_n, cmd_choices);
                break;

            case KEY_F(12):
            case 'h':
            case 'H':
            case '?':
                print_help(":[VUURMUUR:CONNECTIONS]:");
                break;
        }

        /* now sleep! */
        if (control.sleep == 1) {
            usleep(10000);
            slept_so_far = slept_so_far + 10000;
        } else {
            slept_so_far = update_interval;

            vrmr_debug(LOW,
                    "control.sleep = 0: set slept_so_far to update_interval.");
        }
    }

    conn_free_ct(&ct, zones);

    /* filter clean up */
    vrmr_connreq_cleanup(&connreq);

    nodelay(conn_win, FALSE);
    del_panel(my_panels[0]);
    destroy_win(conn_win);
    /* display the cursor again */
    curs_set(1);
    update_panels();
    doupdate();
    return (retval);
}

/* protocol numbers */
enum
{
    VR_PROTO_ICMP = 1,
    VR_PROTO_TCP = 6,
    VR_PROTO_UDP = 17,
    VR_PROTO_GRE = 47,
    VR_PROTO_ESP = 50,
    VR_PROTO_AH = 51
};

int kill_connection(
        const char *srcip, const char *dstip, int proto, int sp, int dp)
{
    int family = AF_INET;
    const char *v6 = strchr(srcip, ':');
    if (v6)
        family = AF_INET6;

    int result =
            vrmr_conn_kill_connection_api(family, srcip, dstip, sp, dp, proto);

    /* TRANSLATORS: example "killed connection: 1.2.3.4:5678 -> 8.7.6.5:4321
     * (6)" */
    vrmr_audit("%s: %s:%d -> %s:%d (%d)",
            result ? gettext("failed to kill connection")
                   : gettext("killed connection"),
            srcip, sp, dstip, dp, proto);
    return result;
}

int kill_connections_by_name(struct conntrack *ct, char *srcname, char *dstname,
        char *sername, char connect_status)
{
    struct vrmr_list_node *d_node = NULL;
    int cnt = 0, failed = 0;

    for (d_node = ct->conn_list.top; d_node; d_node = d_node->next) {
        vrmr_fatal_if_null(d_node->data);
        struct vrmr_conntrack_entry *cd_ptr = d_node->data;

        vrmr_debug(LOW, "ct: s:%s d:%s s:%s (%d)", cd_ptr->fromname,
                cd_ptr->toname, cd_ptr->sername, cd_ptr->cnt);

        if (srcname == NULL || strcmp(srcname, cd_ptr->fromname) == 0) {
            if (dstname == NULL || strcmp(dstname, cd_ptr->toname) == 0) {
                /* for DNATted connections we use the
                   orig_dst_ip */
                const char *dip = cd_ptr->orig_dst_ip[0] ? cd_ptr->orig_dst_ip
                                                         : cd_ptr->dst_ip;

                if (sername == NULL || strcmp(sername, cd_ptr->sername) == 0) {
                    if (connect_status == VRMR_CONN_UNUSED ||
                            connect_status == cd_ptr->connect_status) {
                        if (kill_connection(cd_ptr->src_ip, dip,
                                    cd_ptr->protocol, cd_ptr->src_port,
                                    cd_ptr->dst_port) == -1) {
                            failed++;
                        }

                        cnt++;
                    }
                }
            }
        }
    }

    if (cnt == 0)
        vrmr_warning(
                VR_WARN, gettext("all connections already gone, none killed."));
    else if (failed > 0 && failed != cnt)
        vrmr_warning(VR_WARN,
                gettext("killing of %d out of %d connections failed."), failed,
                cnt);
    else if (failed > 0)
        vrmr_warning(VR_WARN, gettext("killing of all %d connections failed."),
                failed);
    else
        vrmr_info(VR_INFO, "%d connection(s) killed.", cnt);

    return (0);
}

int kill_connections_by_ip(struct conntrack *ct, char *srcip, char *dstip,
        char *sername, char connect_status)
{
    struct vrmr_list_node *d_node = NULL;
    int cnt = 0, failed = 0;

    for (d_node = ct->conn_list.top; d_node; d_node = d_node->next) {
        vrmr_fatal_if_null(d_node->data);
        struct vrmr_conntrack_entry *cd_ptr = d_node->data;

        if (srcip == NULL || strcmp(srcip, cd_ptr->src_ip) == 0) {
            if (dstip == NULL ||
                    (cd_ptr->orig_dst_ip[0] == '\0' &&
                            strcmp(dstip, cd_ptr->dst_ip) == 0) ||
                    (cd_ptr->orig_dst_ip[0] != '\0' &&
                            strcmp(dstip, cd_ptr->orig_dst_ip) == 0)) {
                /* for DNATted connections we use the orig_dst_ip */
                const char *dip = cd_ptr->orig_dst_ip[0] ? cd_ptr->orig_dst_ip
                                                         : cd_ptr->dst_ip;

                if (sername == NULL || strcmp(sername, cd_ptr->sername) == 0) {
                    if (connect_status == VRMR_CONN_UNUSED ||
                            connect_status == cd_ptr->connect_status) {
                        if (kill_connection(cd_ptr->src_ip, dip,
                                    cd_ptr->protocol, cd_ptr->src_port,
                                    cd_ptr->dst_port) == -1) {
                            failed++;
                        }

                        cnt++;
                    }
                }
            }
        }
    }

    if (cnt == 0)
        vrmr_warning(
                VR_WARN, gettext("all connections already gone, none killed."));
    else if (failed > 0 && failed != cnt)
        vrmr_warning(VR_WARN,
                gettext("killing of %d out of %d connections failed."), failed,
                cnt);
    else if (failed > 0)
        vrmr_warning(VR_WARN, gettext("killing of all %d connections failed."),
                failed);
    else
        vrmr_info(VR_INFO, "%d connection(s) killed.", cnt);

    return (0);
}

/*
    Steps:
    1. check if the ipaddress doesn't belong to one of our own interfaces
    2. add ip to blocklist
    3. save blocklist
    4. apply changes so the newly saved blocklist gets into effect
    5. kill all connections for this ip

    We first add it to the blocklist and apply changes to prevent
    new connections to be established.
*/
int block_and_kill(struct vrmr_ctx *vctx, struct conntrack *ct,
        struct vrmr_zones *zones, struct vrmr_blocklist *blocklist,
        struct vrmr_interfaces *interfaces, char *ip)
{
    struct vrmr_interface *iface_ptr = NULL;

    VrBusyWinShow();

    iface_ptr = vrmr_search_interface_by_ip(interfaces, ip);
    if (iface_ptr != NULL) {
        vrmr_error(-1, VR_ERR,
                gettext("ipaddress belongs to "
                        "interface '%s'. It will not be added to the "
                        "blocklist."),
                iface_ptr->name);
        VrBusyWinHide();
        return (-1);
    }

    /* add to list */
    if (vrmr_blocklist_add_one(zones, blocklist, /*load_ips*/ FALSE,
                /*no_refcnt*/ FALSE, ip) < 0) {
        vrmr_error(-1, VR_INTERR, "blocklist_add_one() failed");
        VrBusyWinHide();
        return (-1);
    }

    /* save the list */
    if (vrmr_blocklist_save_list(vctx, &vctx->conf, blocklist) < 0) {
        vrmr_error(-1, VR_INTERR, "blocklist_save_list() failed");
        VrBusyWinHide();
        return (-1);
    }

    /* audit logging */
    vrmr_audit("%s '%s' %s.", STR_IPADDRESS, ip,
            STR_HAS_BEEN_ADDED_TO_THE_BLOCKLIST);

    /* apply the changes */
    vc_apply_changes(vctx);

    /* kill all connections for this ip */
    kill_connections_by_ip(ct, NULL, ip, NULL, VRMR_CONN_UNUSED);
    kill_connections_by_ip(ct, ip, NULL, NULL, VRMR_CONN_UNUSED);

    VrBusyWinHide();
    return (0);
}
