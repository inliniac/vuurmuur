/***************************************************************************
 *   Copyright (C) 2006-2019 by Victor Julien                              *
 *   victor@inliniac.net                                                   *
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

struct stat_event_generic {
    int type;
    int filtered;
};

struct stat_event_log {
    int type;
    int filtered;

    char ser[VRMR_MAX_SERVICE];
    char src[VRMR_VRMR_MAX_HOST_NET_ZONE];
    char dst[VRMR_VRMR_MAX_HOST_NET_ZONE];

    char src_ip[46];
    char dst_ip[46];
    int protocol;
    int dst_port;
    int src_port;

    /* specifics for logging */

    char timedate_str[32];

    char action[16];
    char prefix[32];
    char details[128];
};

struct stat_event_conn {
    int type;
    int filtered;

    char ser[VRMR_MAX_SERVICE];
    char src[VRMR_VRMR_MAX_HOST_NET_ZONE];
    char dst[VRMR_VRMR_MAX_HOST_NET_ZONE];

    char src_ip[46];
    char dst_ip[46];
    int protocol;
    int dst_port;
    int src_port;

    /* specifics for connections */

    /* counter */
    int cnt;

    /* connection status - 0 for unused */
    int connect_status;
    /* do we use connect_status */
    int direction_status;

    /* accounting data */
    char use_acc;
    uint64_t to_src_packets;
    uint64_t to_src_bytes;
    uint64_t to_dst_packets;
    uint64_t to_dst_bytes;
};

struct stat_event_ctx {
    int type;

    void *data;

    /* "object" functions */
    char *(*print2str)(struct stat_event_generic *, size_t);
    void (*remove)(void *data);

    char (*convert)(struct stat_event_ctx *);
    /* ptr to interactive menu function */
    void (*menu)(struct vrmr_ctx *, struct vrmr_config *,
            struct stat_event_ctx *, struct conntrack *,
            struct vrmr_conntrack_request *, struct vrmr_zones *,
            struct vrmr_blocklist *, struct vrmr_interfaces *,
            struct vrmr_services *, struct stat_event_generic *);
    // build menu func?

    /* GUI names and texts */
    const char *title_str;
    const char *options_str;
    const char *warn_no_data_str;

    /* GUI helpfiles */
    const char *help_overview; /* menu with connections/logs overview */
    const char *help_actions;  /* actions menu */

    /* data storage */
    struct vrmr_list list;
};

/*
    functions
*/

static struct stat_event_conn *ATTR_RETURNS_NONNULL statevent_init_conn(void)
{
    struct stat_event_conn *conn = malloc(sizeof(struct stat_event_conn));
    vrmr_fatal_alloc("malloc", conn);
    memset(conn, 0, sizeof(struct stat_event_conn));

    conn->type = STATEVENTTYPE_CONN;
    return (conn);
}

static struct stat_event_log *ATTR_RETURNS_NONNULL statevent_init_log(void)
{
    struct stat_event_log *log = malloc(sizeof(struct stat_event_log));
    vrmr_fatal_alloc("malloc", log);
    memset(log, 0, sizeof(struct stat_event_log));

    log->type = STATEVENTTYPE_LOG;
    return (log);
}

static char *statevent_print2str_log(struct stat_event_generic *evt, size_t len)
{
    struct stat_event_log *log = (struct stat_event_log *)evt;

    vrmr_fatal_if_null(evt);
    vrmr_fatal_if(evt->type != STATEVENTTYPE_LOG);

    char *str =
            vrmr_get_len_string(len, "%s %s %s %s -> %s %s", log->timedate_str,
                    log->action, log->ser, log->src, log->dst, log->details);
    return (str);
}

static char *statevent_print2str_conn(
        struct stat_event_generic *evt, size_t len)
{
    struct stat_event_conn *conn = (struct stat_event_conn *)evt;
    char src[64] = "", dst[64] = "";
    char *str = NULL;

    vrmr_fatal_if_null(evt);
    vrmr_fatal_if(evt->type != STATEVENTTYPE_CONN);

    /* non TCP and UDP */
    if (conn->src_port == 0 && conn->dst_port == 0) {
        snprintf(src, sizeof(src), "%s", conn->src_ip);
        snprintf(dst, sizeof(dst), "%s", conn->dst_ip);
        /* group on dst port */
    } else if (conn->cnt > 1) {
        snprintf(src, sizeof(src), "%s", conn->src_ip);
        snprintf(dst, sizeof(dst), "%s:%d", conn->dst_ip, conn->dst_port);
        /* single TCP or UDP */
    } else {
        snprintf(src, sizeof(src), "%s:%d", conn->src_ip, conn->src_port);
        snprintf(dst, sizeof(dst), "%s:%d", conn->dst_ip, conn->dst_port);
    }

    /* get the string */
    str = vrmr_get_len_string(len, "[%3u] %s  %s -> %s  %s -> %s (%u)",
            conn->cnt, conn->ser, conn->src, conn->dst, src, dst,
            conn->protocol);
    return (str);
}

/* convert struct vrmr_conntrack_entry to struct stat_event_conn */
static char statevent_convert_conn(struct stat_event_ctx *ctl)
{
    struct conntrack *ct = ctl->data;

    unsigned int array_size = ct->conn_list.len;
    for (unsigned int x = 0; x < array_size; x++) {
        struct vrmr_conntrack_entry *cd_ptr = ct->conn_array[x];
        struct stat_event_conn *conn = statevent_init_conn();
        vrmr_fatal_if_null(conn);

        strlcpy(conn->ser, cd_ptr->sername, sizeof(conn->ser));
        strlcpy(conn->src, cd_ptr->fromname, sizeof(conn->src));
        strlcpy(conn->dst, cd_ptr->toname, sizeof(conn->dst));
        strlcpy(conn->src_ip, cd_ptr->src_ip, sizeof(conn->src_ip));
        strlcpy(conn->dst_ip, cd_ptr->dst_ip, sizeof(conn->dst_ip));
        conn->protocol = cd_ptr->protocol;
        conn->src_port = cd_ptr->src_port;
        conn->dst_port = cd_ptr->dst_port;
        conn->cnt = cd_ptr->cnt;

        vrmr_fatal_if(vrmr_list_append(&ctl->list, conn) == NULL);
    }

    return (TRUE);
}

static char parse_log_srcdst(const char *str_in, char *ret_ip, size_t ip_size,
        char *ret_mac, size_t mac_size, int *ret_port)
{
    vrmr_debug(MEDIUM, "str_in '%s'", str_in);

    char str[256];
    strlcpy(str, str_in, sizeof(str));

    /* find last : that separates the port, but make sure we're not
     * already inside the mac address */
    char *mac = strrchr(str, ')');
    char *port = strrchr(str, ':');
    if (port != NULL && port > mac) {
        *port = '\0';
        port++;
        *ret_port = atoi(port);
    }

    char *mac_start = strchr(str, '(');
    if (mac_start != NULL) {
        *mac_start = '\0';
        mac_start++;

        char *mac_end = strchr(mac_start, ')');
        if (mac_end == NULL) {
            return FALSE;
        }
        *mac_end = '\0';
        strlcpy(ret_mac, mac_start, mac_size);
    }
    strlcpy(ret_ip, str, ip_size);
    return TRUE;
}

/* convert struct LogRule to struct stat_event_log
 */
static char statevent_convert_log(struct stat_event_ctx *ctl)
{
    struct vrmr_list_node *d_node = NULL;
    struct vrmr_list *loglist = ctl->data;

    for (d_node = loglist->top; d_node; d_node = d_node->next) {
        vrmr_fatal_if_null(d_node->data);
        struct log_record *log_record = d_node->data;

        struct stat_event_log *log = statevent_init_log();
        vrmr_fatal_if_null(log);

        strlcpy(log->ser, log_record->service, sizeof(log->ser));
        strlcpy(log->src, log_record->from, sizeof(log->src));
        strlcpy(log->dst, log_record->to, sizeof(log->dst));
        strlcpy(log->details, log_record->details, sizeof(log->details));
        strlcpy(log->action, log_record->action, sizeof(log->action));
        strlcpy(log->prefix, log_record->prefix, sizeof(log->prefix));

        snprintf(log->timedate_str, sizeof(log->timedate_str), "%s %s %s",
                log_record->month, log_record->date, log_record->time);

        log->filtered = log_record->filtered;

        /* parse the details :-S */
        // vrprint.error(-1, "Details", "%s", log_record->details);

        /*  TCP, UDP, ICMP, GRE examples

            (in: eth1 192.168.2.1:138 -> 192.168.2.255:138 UDP len:211 ttl:64)
            (in: eth0 out: ppp0 192.168.1.2:41719 -> 64.156.11.200:80 TCP flags:
           ****S* len:60 ttl:63) (in: eth0 out: ppp0 192.168.1.2 ->
           194.109.21.51 ICMP type 8 code 0 len:84 ttl:63) (in: ppp0 out: eth0
           194.109.5.241 -> 192.168.1.64 (41) len:76 ttl:26)
        */
        const char *s = log_record->details;
#define MAX_TOK 32
        char store[MAX_TOK][128];

        /* split the tokens */
        for (int x = 0, y = 0, z = 0; x < (int)strlen(s); x++) {
            /* copy char */
            store[y][z] = s[x];

            if (store[y][z] == ' ') {
                store[y][z] = '\0';

                y++;
                z = 0;

                if (y == MAX_TOK)
                    break;
            } else {
                z++;
            }
        }

        int next = 0;

        if (strcmp(store[0], "(in:") == 0) {
            next = 2;
        } else if (strcmp(store[0], "(out:") == 0) {
            next = 2;
        }
        if (strcmp(store[next], "out:") == 0) {
            next += 2;
        }

        /* ip or ip+port */
        char *src = store[next];
        next++;

        /* arrow */
        next++;

        /* ip or ip+port */
        char *dst = store[next];
        next++;

        /*  parse src and dst

            TCP/UDP:
            193.93.236.7:47974
            193.93.236.7(00:05:5f:54:8f:fc):47974

            REST:
            193.93.236.7
            193.93.236.7(00:05:5f:54:8f:fc)


        */
        char mac[18] = "";

        parse_log_srcdst(src, log->src_ip, sizeof(log->src_ip), mac,
                sizeof(mac), &log->src_port);

        parse_log_srcdst(dst, log->dst_ip, sizeof(log->dst_ip), mac,
                sizeof(mac), &log->dst_port);

        if (strcmp(store[next], "TCP") == 0) {
            log->protocol = 6;
        } else if (strcmp(store[next], "UDP") == 0) {
            log->protocol = 17;
        } else if (strcmp(store[next], "ICMP") == 0) {
            log->protocol = 1;
        } else if (strcmp(store[next], "GRE") == 0) {
            log->protocol = 47;
        } else if (strcmp(store[next], "ESP") == 0) {
            log->protocol = 50;
        } else if (strcmp(store[next], "AH") == 0) {
            log->protocol = 51;
        } else if (strcmp(store[next], "PROTO") == 0) {
            log->protocol = atoi(store[next + 1]);
            next++;
        } else {
            vrmr_debug(NONE, "no match '%s'", store[next]);
        }

        vrmr_fatal_if(vrmr_list_append(&ctl->list, log) == NULL);
    }

    return (TRUE);
}

/* wrapper around ip and name killing */
static int kill_connections(struct vrmr_conntrack_request *connreq,
        struct conntrack *ct, struct stat_event_conn *conn)
{
    if (connreq->unknown_ip_as_net) {
        return (kill_connections_by_name(
                ct, conn->src, conn->dst, conn->ser, conn->connect_status));
    } else {
        return (kill_connections_by_ip(ct, conn->src_ip, conn->dst_ip,
                conn->ser, conn->connect_status));
    }
}

/*  Display the menu that allows the user to act
    on a connection.

*/
static void statevent_interactivemenu_conn(struct vrmr_ctx *vctx,
        struct vrmr_config *cnf, struct stat_event_ctx *ctl,
        struct conntrack *ct, struct vrmr_conntrack_request *connreq,
        struct vrmr_zones *zones, struct vrmr_blocklist *blocklist,
        struct vrmr_interfaces *interfaces, struct vrmr_services *services,
        struct stat_event_generic *gen_ptr)
{
    struct vrmr_gui_win *win = NULL;
    struct vrmr_gui_menu *menu = NULL;
    int ch = 0;
    int menu_items = 10;
    const char *str = NULL;
    const int width = 70;
    /* top menu */
    const char *key_choices[] = {"F12", "F10"};
    int key_choices_n = 2;
    const char *cmd_choices[] = {gettext("help"), gettext("back")};
    int cmd_choices_n = 2;
    struct stat_event_conn *con = (struct stat_event_conn *)gen_ptr;
    struct conntrack *privct = NULL;
    char ungroup_conns = FALSE;
    const char *title = gettext("Manage Connection");

    /* if needed get our own private ungrouped ct */
    if (connreq->group_conns == TRUE) {
        ungroup_conns = TRUE; /* we are ungrouping the list */
        connreq->group_conns = FALSE;

        privct = conn_init_ct(zones, interfaces, services);
        vrmr_fatal_if_null(privct);

        conn_ct_get_connections(cnf, privct, connreq);
        ct = privct;
    }

    /* create the window and put it in the middle of the screen */
    win = VrNewWin(menu_items + 2, width, 0, 0, vccnf.color_win);
    vrmr_fatal_if_null(win);
    VrWinSetTitle(win, title);

    menu = VrNewMenu(menu_items, width - 2, 1, 1, menu_items, vccnf.color_win,
            vccnf.color_win_rev);
    vrmr_fatal_if_null(menu);
    VrMenuSetDescFreeFunc(menu, free);
    VrMenuSetupNameList(menu);
    VrMenuSetupDescList(menu);

    /* setup menu items */
    if (con->cnt == 1)
        str = vrmr_get_string(gettext("Kill this connection"));
    else
        str = vrmr_get_string(gettext("Kill all %u connections with this "
                                      "service/source/destination"),
                con->cnt);
    VrMenuAddItem(menu, "1", str);

    str = vrmr_get_string("--- %s ---", gettext("Kill options"));
    VrMenuAddSepItem(menu, str);
    str = vrmr_get_string(
            gettext("Kill all connections with source %s"), con->src_ip);
    VrMenuAddItem(menu, "2", str);
    str = vrmr_get_string(
            gettext("Kill all connections with destination %s"), con->dst_ip);
    VrMenuAddItem(menu, "3", str);
    str = vrmr_get_string(gettext("Kill all connections of %s"), con->src_ip);
    VrMenuAddItem(menu, "4", str);
    str = vrmr_get_string(gettext("Kill all connections of %s"), con->dst_ip);
    VrMenuAddItem(menu, "5", str);
    str = vrmr_get_string("--- %s ---", gettext("BlockList options"));
    VrMenuAddSepItem(menu, str);
    str = vrmr_get_string(gettext("Add source %s to BlockList"), con->src_ip);
    VrMenuAddItem(menu, "6", str);
    str = vrmr_get_string(
            gettext("Add destination %s to BlockList"), con->dst_ip);
    VrMenuAddItem(menu, "7", str);
    str = vrmr_get_string(
            gettext("Add both source and destination to BlockList"));
    VrMenuAddItem(menu, "8", str);
    VrMenuConnectToWin(menu, win);
    VrMenuPost(menu);

    draw_top_menu(top_win, title, key_choices_n, key_choices, cmd_choices_n,
            cmd_choices);
    update_panels();
    doupdate();

    /* user input */
    char quit = FALSE;
    while (quit == FALSE) {
        ch = VrWinGetch(win);

        switch (ch) {
            case 27:
            case 'q':
            case 'Q':
            case KEY_F(10):
                quit = TRUE;
                break;

            case 10: {
                ITEM *cur = current_item(menu->m);
                vrmr_fatal_if_null(cur);
                int act = atoi((char *)item_name(cur));
                switch (act) {
                    case 1: /* kill */
                    {
                        /* check if the conntrack tool is set */
                        if (con->cnt == 1) {
                            if (confirm(gettext("Kill connection"),
                                        gettext("Are you sure?"),
                                        vccnf.color_win_note,
                                        vccnf.color_win_note_rev | A_BOLD,
                                        1) == 1) {
                                kill_connection(con->src_ip, con->dst_ip,
                                        con->protocol, con->src_port,
                                        con->dst_port);
                            }
                        } else {
                            vrmr_debug(NONE,
                                    "cnt %u, src %s srcip %s dst %s dstip %s "
                                    "ser %s",
                                    con->cnt, con->src, con->src_ip, con->dst,
                                    con->dst_ip, con->ser);

                            if (confirm(gettext("Kill connections"),
                                        gettext("Are you sure?"),
                                        vccnf.color_win_note,
                                        vccnf.color_win_note_rev | A_BOLD,
                                        1) == 1) {
                                kill_connections(connreq, ct, con);
                            }
                        }
                        break;
                    }

                    case 2: /* kill all src ip */
                        /* check if the conntrack tool is set */
                        if (confirm(gettext("Kill connections"),
                                    gettext("Are you sure?"),
                                    vccnf.color_win_note,
                                    vccnf.color_win_note_rev | A_BOLD,
                                    1) == 1) {
                            kill_connections_by_ip(ct, con->src_ip, NULL, NULL,
                                    VRMR_CONN_UNUSED);
                        }
                        break;

                    case 3: /* kill all dst ip */
                        if (confirm(gettext("Kill connections"),
                                    gettext("Are you sure?"),
                                    vccnf.color_win_note,
                                    vccnf.color_win_note_rev | A_BOLD,
                                    1) == 1) {
                            kill_connections_by_ip(ct, NULL, con->dst_ip, NULL,
                                    VRMR_CONN_UNUSED);
                        }
                        break;

                    case 4:
                        /* check if the conntrack tool is set */
                        if (confirm(gettext("Kill connections"),
                                    gettext("Are you sure?"),
                                    vccnf.color_win_note,
                                    vccnf.color_win_note_rev | A_BOLD,
                                    1) == 1) {
                            kill_connections_by_ip(ct, NULL, con->src_ip, NULL,
                                    VRMR_CONN_UNUSED);
                            kill_connections_by_ip(ct, con->src_ip, NULL, NULL,
                                    VRMR_CONN_UNUSED);
                        }
                        break;

                    case 5:
                        /* check if the conntrack tool is set */
                        if (confirm(gettext("Kill connections"),
                                    gettext("Are you sure?"),
                                    vccnf.color_win_note,
                                    vccnf.color_win_note_rev | A_BOLD,
                                    1) == 1) {
                            kill_connections_by_ip(ct, NULL, con->dst_ip, NULL,
                                    VRMR_CONN_UNUSED);
                            kill_connections_by_ip(ct, con->dst_ip, NULL, NULL,
                                    VRMR_CONN_UNUSED);
                        }
                        break;

                    case 6:
                        if (confirm(gettext("Add to BlockList and Apply "
                                            "Changes"),
                                    gettext("Are you sure?"),
                                    vccnf.color_win_note,
                                    vccnf.color_win_note_rev | A_BOLD,
                                    1) == 1) {
                            block_and_kill(vctx, ct, zones, blocklist,
                                    interfaces, con->src_ip);
                        }
                        break;

                    case 7:
                        if (confirm(gettext("Add to BlockList and Apply "
                                            "Changes"),
                                    gettext("Are you sure?"),
                                    vccnf.color_win_note,
                                    vccnf.color_win_note_rev | A_BOLD,
                                    1) == 1) {
                            block_and_kill(vctx, ct, zones, blocklist,
                                    interfaces, con->dst_ip);
                        }
                        break;

                    case 8:
                        if (confirm(gettext("Add to BlockList and Apply "
                                            "Changes"),
                                    gettext("Are you sure?"),
                                    vccnf.color_win_note,
                                    vccnf.color_win_note_rev | A_BOLD,
                                    1) == 1) {
                            block_and_kill(vctx, ct, zones, blocklist,
                                    interfaces, con->src_ip);
                            block_and_kill(vctx, ct, zones, blocklist,
                                    interfaces, con->dst_ip);
                        }
                        break;

                    default:
                        break;
                }
                break;
            }
            case KEY_F(12):
            case 'h':
            case 'H':
            case '?':
                print_help(ctl->help_actions);
                break;

            default:
                (void)VrMenuDefaultNavigation(menu, ch);
                break;
        }
    }

    VrDelMenu(menu);
    VrDelWin(win);
    update_panels();
    doupdate();

    /* we have ungrouped the list, clean up here. */
    if (ungroup_conns == TRUE) {
        connreq->group_conns = TRUE;
        conn_ct_clear_connections(privct);
        conn_free_ct(&privct, NULL);
    }
}

/*  Display the menu that allows the user to act
    on a connection.

*/
static void statevent_interactivemenu_log(struct vrmr_ctx *vctx,
        struct vrmr_config *cnf, struct stat_event_ctx *ctl,
        struct conntrack *ct ATTR_UNUSED,
        struct vrmr_conntrack_request *connreqnull ATTR_UNUSED,
        struct vrmr_zones *zones, struct vrmr_blocklist *blocklist,
        struct vrmr_interfaces *interfaces, struct vrmr_services *services,
        struct stat_event_generic *gen_ptr)
{
    struct vrmr_gui_win *win = NULL;
    struct vrmr_gui_menu *menu = NULL;
    int ch = 0;
    int menu_items = 10;
    char *str = NULL;
    const int width = 70;
    /* top menu */
    const char *key_choices[] = {"F12", "F10"};
    int key_choices_n = 2;
    const char *cmd_choices[] = {gettext("help"), gettext("back")};
    int cmd_choices_n = 2;
    struct stat_event_log *log = (struct stat_event_log *)gen_ptr;

    struct conntrack *ctr = NULL;
    struct vrmr_conntrack_request connreq;
    const char *title = gettext("Manage Log");

    /* number labels */
    char *nums[9] = {"1", "2", "3", "4", "5", "6", "7", "8", NULL};
    int n = 0;
    int action = 0;

    VrBusyWinShow();

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

    /* get the connections for killing them later if the user chooses to */
    ctr = conn_init_ct(zones, interfaces, services);
    conn_ct_get_connections(cnf, ctr, &connreq);

    action = vrmr_rules_actiontoi(log->action);
    if (action == VRMR_AT_DROP || action == VRMR_AT_REJECT)
        menu_items--;

    /* create the window and put it in the middle of the screen */
    win = VrNewWin(menu_items + 2, width, 0, 0, vccnf.color_win);
    vrmr_fatal_if_null(win);
    VrWinSetTitle(win, title);

    menu = VrNewMenu(menu_items, width - 2, 1, 1, menu_items, vccnf.color_win,
            vccnf.color_win_rev);
    vrmr_fatal_if_null(menu);
    VrMenuSetDescFreeFunc(menu, free);
    VrMenuSetupNameList(menu);
    VrMenuSetupDescList(menu);

    if (action != VRMR_AT_DROP && action != VRMR_AT_REJECT) {
        /* setup menu items */
        str = vrmr_get_string(gettext("Kill this connection"));
        VrMenuAddItem(menu, nums[n], str);
        n++;
    }
    str = vrmr_get_string("--- %s ---", gettext("Kill options"));
    VrMenuAddSepItem(menu, str);
    str = vrmr_get_string(
            gettext("Kill all connections with source %s"), log->src_ip);
    VrMenuAddItem(menu, nums[n++], str);
    str = vrmr_get_string(
            gettext("Kill all connections with destination %s"), log->dst_ip);
    VrMenuAddItem(menu, nums[n++], str);
    str = vrmr_get_string(gettext("Kill all connections of %s"), log->src_ip);
    VrMenuAddItem(menu, nums[n++], str);
    str = vrmr_get_string(gettext("Kill all connections of %s"), log->dst_ip);
    VrMenuAddItem(menu, nums[n++], str);
    str = vrmr_get_string("--- %s ---", gettext("BlockList options"));
    VrMenuAddSepItem(menu, str);
    str = vrmr_get_string(gettext("Add source %s to BlockList"), log->src_ip);
    VrMenuAddItem(menu, nums[n++], str);
    str = vrmr_get_string(
            gettext("Add destination %s to BlockList"), log->dst_ip);
    VrMenuAddItem(menu, nums[n++], str);
    str = vrmr_get_string(
            gettext("Add both source and destination to BlockList"));
    VrMenuAddItem(menu, nums[n], str); /* n != n++ */
    VrMenuConnectToWin(menu, win);
    VrMenuPost(menu);

    draw_top_menu(top_win, title, key_choices_n, key_choices, cmd_choices_n,
            cmd_choices);
    update_panels();
    doupdate();
    VrBusyWinHide();

    /* user input */
    char quit = FALSE;
    while (quit == FALSE) {
        ch = VrWinGetch(win);
        switch (ch) {
            case 27:
            case 'q':
            case 'Q':
            case KEY_F(10):
                quit = TRUE;
                break;

            case 10: {
                ITEM *cur = current_item(menu->m);
                vrmr_fatal_if_null(cur);
                int act = atoi((char *)item_name(cur));
                switch (act) {
                    case 1: /* kill */
                    {
                        if (confirm(gettext("Kill connections"),
                                    gettext("Are you sure?"),
                                    vccnf.color_win_note,
                                    vccnf.color_win_note_rev | A_BOLD,
                                    1) == 1) {
                            kill_connections_by_ip(ctr, log->src_ip,
                                    log->dst_ip, log->ser, VRMR_CONN_UNUSED);
                        }
                        break;
                    }

                    case 2: /* kill all src ip */
                        if (confirm(gettext("Kill connections"),
                                    gettext("Are you sure?"),
                                    vccnf.color_win_note,
                                    vccnf.color_win_note_rev | A_BOLD,
                                    1) == 1) {
                            kill_connections_by_ip(ctr, log->src_ip, NULL, NULL,
                                    VRMR_CONN_UNUSED);
                        }
                        break;

                    case 3: /* kill all dst ip */
                        if (confirm(gettext("Kill connections"),
                                    gettext("Are you sure?"),
                                    vccnf.color_win_note,
                                    vccnf.color_win_note_rev | A_BOLD,
                                    1) == 1) {
                            kill_connections_by_ip(ctr, NULL, log->dst_ip, NULL,
                                    VRMR_CONN_UNUSED);
                        }
                        break;

                    case 4:
                        if (confirm(gettext("Kill connections"),
                                    gettext("Are you sure?"),
                                    vccnf.color_win_note,
                                    vccnf.color_win_note_rev | A_BOLD,
                                    1) == 1) {
                            kill_connections_by_ip(ctr, NULL, log->src_ip, NULL,
                                    VRMR_CONN_UNUSED);
                            kill_connections_by_ip(ctr, log->src_ip, NULL, NULL,
                                    VRMR_CONN_UNUSED);
                        }
                        break;

                    case 5:
                        if (confirm(gettext("Kill connections"),
                                    gettext("Are you sure?"),
                                    vccnf.color_win_note,
                                    vccnf.color_win_note_rev | A_BOLD,
                                    1) == 1) {
                            kill_connections_by_ip(ctr, NULL, log->dst_ip, NULL,
                                    VRMR_CONN_UNUSED);
                            kill_connections_by_ip(ctr, log->dst_ip, NULL, NULL,
                                    VRMR_CONN_UNUSED);
                        }
                        break;

                    case 6:
                        if (confirm(gettext("Add to BlockList and Apply "
                                            "Changes"),
                                    gettext("Are you sure?"),
                                    vccnf.color_win_note,
                                    vccnf.color_win_note_rev | A_BOLD,
                                    1) == 1) {
                            block_and_kill(vctx, ctr, zones, blocklist,
                                    interfaces, log->src_ip);
                        }
                        break;

                    case 7:
                        if (confirm(gettext("Add to BlockList and Apply "
                                            "Changes"),
                                    gettext("Are you sure?"),
                                    vccnf.color_win_note,
                                    vccnf.color_win_note_rev | A_BOLD,
                                    1) == 1) {
                            block_and_kill(vctx, ctr, zones, blocklist,
                                    interfaces, log->dst_ip);
                        }
                        break;

                    case 8:
                        if (confirm(gettext("Add to BlockList and Apply "
                                            "Changes"),
                                    gettext("Are you sure?"),
                                    vccnf.color_win_note,
                                    vccnf.color_win_note_rev | A_BOLD,
                                    1) == 1) {
                            block_and_kill(vctx, ctr, zones, blocklist,
                                    interfaces, log->src_ip);
                            block_and_kill(vctx, ctr, zones, blocklist,
                                    interfaces, log->dst_ip);
                        }
                        break;

                    default:
                        break;
                }
                break;
            }
            case KEY_F(12):
            case 'h':
            case 'H':
            case '?':
                print_help(ctl->help_actions);
                break;

            default:
                (void)VrMenuDefaultNavigation(menu, ch);
                break;
        }
    }

    conn_ct_clear_connections(ctr);
    conn_free_ct(&ctr, zones);

    VrDelMenu(menu);
    VrDelWin(win);
    update_panels();
    doupdate();
}

static struct stat_event_ctx *ATTR_RETURNS_NONNULL statevent_init_ctl(int type)
{
    struct stat_event_ctx *ctl = malloc(sizeof(struct stat_event_ctx));
    vrmr_fatal_alloc("malloc", ctl);
    memset(ctl, 0, sizeof(struct stat_event_ctx));

    ctl->type = type;

    if (ctl->type == STATEVENTTYPE_CONN) {
        ctl->print2str = statevent_print2str_conn;
        ctl->remove = free;
        ctl->menu = statevent_interactivemenu_conn;
        ctl->convert = statevent_convert_conn;
        ctl->title_str = gettext("Manage Connections");
        ctl->options_str = gettext("connection actions");
        ctl->warn_no_data_str = gettext("No connections to act on.");
        ctl->help_overview = ":[VUURMUUR:CONNECTIONS:MANAGE]:";
        ctl->help_actions = ":[VUURMUUR:CONNECTIONS:ACTIONS]:";
    } else if (ctl->type == STATEVENTTYPE_LOG) {
        ctl->print2str = statevent_print2str_log;
        ctl->remove = free;
        ctl->menu = statevent_interactivemenu_log;
        ctl->convert = statevent_convert_log;
        ctl->title_str = gettext("Manage Logging");
        ctl->options_str = gettext("logging actions");
        ctl->warn_no_data_str = gettext("No logs to act on.");
        ctl->help_overview = ":[VUURMUUR:LOGVIEW:MANAGE]:";
        ctl->help_actions = ":[VUURMUUR:LOGVIEW:ACTIONS]:";
    }

    vrmr_list_setup(&ctl->list, ctl->remove);
    return (ctl);
}

static void statevent_free_ctl(struct stat_event_ctx **ctl)
{
    vrmr_list_cleanup(&(*ctl)->list);
    memset(*ctl, 0, sizeof(struct stat_event_ctx));
    free(*ctl);
    *ctl = NULL;
}

static int statevent_menu(struct vrmr_ctx *vctx, struct vrmr_config *cnf,
        struct stat_event_ctx *ctl, struct conntrack *ct,
        struct vrmr_conntrack_request *connreq, struct vrmr_zones *zones,
        struct vrmr_blocklist *blocklist, struct vrmr_interfaces *interfaces,
        struct vrmr_services *services)
{
    struct vrmr_gui_win *win = NULL;
    struct vrmr_gui_menu *menu = NULL;
    int ch = 0;
    struct vrmr_list_node *d_node = NULL;
    struct stat_event_generic *gen_ptr = NULL;

    /* top menu */
    const char *key_choices[] = {"F12", "enter", "F10"};
    int key_choices_n = 3;
    const char *cmd_choices[] = {
            gettext("help"), ctl->options_str, gettext("back")};
    int cmd_choices_n = 3;

    /* print a warning if we have no data */
    if (ctl->list.len == 0) {
        vrmr_warning(VR_WARN, "%s", ctl->warn_no_data_str);
        return (0);
    }

    win = VrNewWin(LINES - 6, COLS - 2, 3, 1, vccnf.color_win_rev);
    vrmr_fatal_if_null(win);
    VrWinSetTitle(win, ctl->title_str);
    draw_top_menu(top_win, ctl->title_str, key_choices_n, key_choices,
            cmd_choices_n, cmd_choices);

    menu = VrNewMenu(LINES - 8, COLS - 4, 1, 1, ctl->list.len,
            vccnf.color_win_rev, vccnf.color_win);
    vrmr_fatal_if_null(menu);
    VrMenuSetNameFreeFunc(menu, free);
    VrMenuSetDescFreeFunc(menu, free);
    VrMenuSetupNameList(menu);
    VrMenuSetupDescList(menu);

    unsigned int num = 1;
    for (d_node = ctl->list.top; d_node; d_node = d_node->next) {
        vrmr_fatal_if_null(d_node->data);
        gen_ptr = d_node->data;

        vrmr_debug(MEDIUM, "gen_ptr->filtered %d", gen_ptr->filtered);

        if (gen_ptr->filtered == 0) {
            char *desc_str = NULL;
            char *name_str = NULL;
            char strtmp[512] = "";
            size_t name_len = 0, desc_len = 0;

            if (ctl->list.len <= 9)
                snprintf(strtmp, sizeof(strtmp), "%u", num);
            else if (ctl->list.len <= 99)
                snprintf(strtmp, sizeof(strtmp), "%2u", num);
            else if (ctl->list.len <= 999)
                snprintf(strtmp, sizeof(strtmp), "%3u", num);
            else if (ctl->list.len <= 9999)
                snprintf(strtmp, sizeof(strtmp), "%4u", num);
            else if (ctl->list.len <= 99999)
                snprintf(strtmp, sizeof(strtmp), "%5u", num);
            else if (ctl->list.len <= 999999)
                snprintf(strtmp, sizeof(strtmp), "%6u", num);
            else
                snprintf(strtmp, sizeof(strtmp), "%10u", num);

            name_len = strlen(strtmp) + 1;
            name_str = malloc(name_len);
            vrmr_fatal_alloc("malloc", name_str);
            strlcpy(name_str, strtmp, name_len);

            /* get the str that will form the desc */
            desc_len = win->width - 2 - name_len;
            desc_str = ctl->print2str(gen_ptr, desc_len);
            vrmr_fatal_if_null(desc_str);

            num++;

            /* add the item to the menu */
            VrMenuAddItem(menu, name_str, desc_str);
        }
    }
    /* check if we didn't add any item (if all was filtered) */
    if (num == 1) {
        vrmr_warning(VR_WARN, "%s", ctl->warn_no_data_str);
        VrDelMenu(menu);
        VrDelWin(win);
        update_panels();
        doupdate();
        return (0);
    }

    VrMenuConnectToWin(menu, win);
    VrMenuPost(menu);
    VrBusyWinHide();
    update_panels();
    doupdate();

    /* user input */
    char quit = FALSE;
    while (quit == FALSE) {
        ch = VrWinGetch(win);

        switch (ch) {
            case 27:
            case 'q':
            case 'Q':
            case KEY_F(10):
                quit = TRUE;
                break;

            case 10: {
                ITEM *cur = current_item(menu->m);
                vrmr_fatal_if_null(cur);
                int i = atoi((char *)item_name(cur));
                unsigned int u = 1;
                gen_ptr = NULL;

                /* get the current event: handle
                 * filtered events as well
                 */
                for (d_node = ctl->list.top; d_node;
                        d_node = d_node->next, u++) {
                    vrmr_fatal_if_null(d_node->data);
                    gen_ptr = d_node->data;

                    if (!gen_ptr->filtered) {
                        if (u == (unsigned int)i)
                            break;
                    } else {
                        u--;
                    }

                    gen_ptr = NULL;
                }
                if (gen_ptr != NULL) {
                    /* call the interactive menu
                       function */
                    ctl->menu(vctx, cnf, ctl, ct, connreq, zones, blocklist,
                            interfaces, services, gen_ptr);

                    /* when done, restore the title
                       and options */
                    draw_top_menu(top_win, ctl->title_str, key_choices_n,
                            key_choices, cmd_choices_n, cmd_choices);
                }
                break;
            }
            case KEY_F(12):
            case 'h':
            case 'H':
            case '?':
                print_help(ctl->help_overview);
                break;

            default:
                (void)VrMenuDefaultNavigation(menu, ch);
                break;
        }
    }

    VrDelMenu(menu);
    VrDelWin(win);
    update_panels();
    doupdate();

    return (0);
}

void statevent(struct vrmr_ctx *vctx, struct vrmr_config *cnf, int type,
        struct vrmr_list *list, struct conntrack *ct,
        struct vrmr_conntrack_request *connreq, struct vrmr_zones *zones,
        struct vrmr_blocklist *blocklist, struct vrmr_interfaces *interfaces,
        struct vrmr_services *services)
{

    VrBusyWinShow();

    struct stat_event_ctx *ctl = statevent_init_ctl(type);
    vrmr_fatal_if_null(ctl);
    if (ctl->type == STATEVENTTYPE_CONN)
        ctl->data = ct;
    else if (ctl->type == STATEVENTTYPE_LOG)
        ctl->data = list;

    /* convert datatypes list to our own type */
    if (ctl->convert(ctl) == FALSE) {
        vrmr_error(-1, VR_ERR, "loading data failed.");
    }

    statevent_menu(vctx, cnf, ctl, ct, connreq, zones, blocklist, interfaces,
            services);

    statevent_free_ctl(&ctl);

    // hide if not already hidden
    VrBusyWinHide();
}
