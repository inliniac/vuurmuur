/***************************************************************************
 *   Copyright (C) 2006 by Victor Julien                                   *
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


typedef struct StatEventGen_
{
    int type;
    int filtered;

} StatEventGen;

typedef struct StatEventLog_
{
    int type;
    int filtered;

    char ser[MAX_SERVICE];
    char src[MAX_HOST_NET_ZONE];
    char dst[MAX_HOST_NET_ZONE];

    char src_ip[16];
    char dst_ip[16];
    int  protocol;
    int  dst_port;
    int  src_port;

    /* specifics for logging */

    char timedate_str[32];

    char action[16];
    char prefix[32];
    char details[128];

} StatEventLog;

typedef struct StatEventConn_
{
    int type;
    int filtered;

    char ser[MAX_SERVICE];
    char src[MAX_HOST_NET_ZONE];
    char dst[MAX_HOST_NET_ZONE];

    char src_ip[16];
    char dst_ip[16];
    int  protocol;
    int  dst_port;
    int  src_port;

    /* specifics for connections */

    /* counter */
    int                     cnt;

    /* connection status - 0 for unused */
    int                     connect_status;
    /* do we use connect_status */
    int                     direction_status;

    /* accounting data */
    char                    use_acc;
    unsigned long long      to_src_packets;
    unsigned long long      to_src_bytes;
    unsigned long long      to_dst_packets;
    unsigned long long      to_dst_bytes;

} StatEventConn;

typedef struct StatEventCtl_
{
    int type;

    /* "object" functions */
    char * (*print2str )(const int, StatEventGen *, size_t);
    void   (*remove    )(void *data);

    char   (*convert   )(const int debuglvl, struct StatEventCtl_ *, d_list *);
    /* ptr to interactive menu function */
    void   (*menu      )(const int debuglvl, struct vuurmuur_config *, struct StatEventCtl_ *, Conntrack *, VR_ConntrackRequest *, Zones *, struct vrmr_blocklist *, struct vrmr_interfaces *, struct vrmr_services *, StatEventGen *);
    //build menu func?

    /* GUI names and texts */
    char    *title_str;
    char    *options_str;
    char    *warn_no_data_str;

    /* GUI helpfiles */
    char    *help_overview; /* menu with connections/logs overview */
    char    *help_actions;  /* actions menu */

    /* data storage */
    d_list  list;

} StatEventCtl;


/*
    functions
*/

StatEventConn *
statevent_init_conn(const int debuglvl)
{
    StatEventConn *conn = NULL;

    conn = malloc(sizeof(StatEventConn));
    if(conn == NULL)
        return(NULL);

    memset(conn, 0, sizeof(StatEventConn));

    conn->type = STATEVENTTYPE_CONN;

    return(conn);
}

StatEventLog *
statevent_init_log(const int debuglvl)
{
    StatEventLog *log = NULL;

    log = malloc(sizeof(StatEventLog));
    if(log == NULL)
        return(NULL);

    memset(log, 0, sizeof(StatEventLog));

    log->type = STATEVENTTYPE_LOG;

    return(log);
}

static char *
statevent_print2str_log(const int debuglvl, StatEventGen *evt, size_t len)
{
    StatEventLog *log = (StatEventLog *) evt;
    char *str = NULL;

    if(evt->type != STATEVENTTYPE_LOG) {
        (void)vrprint.error(-1, VR_INTERR, "parameter problem (in: %s:%d).",
            __FUNC__,__LINE__);
        return(NULL);
    }

    str = vrmr_get_len_string(len, "%s %s %s %s -> %s %s",
        log->timedate_str, log->action, log->ser, log->src, log->dst,
        log->details);

    return(str);
}

static char *
statevent_print2str_conn(const int debuglvl, StatEventGen *evt, size_t len)
{
    StatEventConn   *conn = (StatEventConn *) evt;
    char            src[22] = "",
                    dst[22] = "";
    char            *str = NULL;

    if(evt->type != STATEVENTTYPE_CONN) {
        (void)vrprint.error(-1, VR_INTERR, "parameter problem (in: %s:%d).",
            __FUNC__,__LINE__);
        return(NULL);
    }

    /* non TCP and UDP */
    if(conn->src_port == 0 && conn->dst_port == 0) {
        snprintf(src, sizeof(src), "%s", conn->src_ip);
        snprintf(dst, sizeof(dst), "%s", conn->dst_ip);
    /* group on dst port */
    } else if (conn->cnt > 1) {
        snprintf(src, sizeof(src), "%s", conn->src_ip);
        snprintf(dst, sizeof(dst), "%s:%u", conn->dst_ip, conn->dst_port);
    /* single TCP or UDP */
    } else {
        snprintf(src, sizeof(src), "%s:%u", conn->src_ip, conn->src_port);
        snprintf(dst, sizeof(dst), "%s:%u", conn->dst_ip, conn->dst_port);
    }

    /* get the string */
    str = vrmr_get_len_string(len, "[%3u] %s  %s -> %s  %s -> %s (%u)",
        conn->cnt, conn->ser, conn->src, conn->dst,
        src, dst, conn->protocol);

    return(str);
}

/* convert struct ConntrackData to StatEventConn */
static char
statevent_convert_conn(const int debuglvl, StatEventCtl *ctl, d_list *list)
{
    d_list_node             *d_node = NULL;
    struct ConntrackData    *cd_ptr = NULL;
    StatEventConn           *conn = NULL;

    for(d_node = list->top; d_node; d_node = d_node->next)
    {
        cd_ptr = d_node->data;

        conn = statevent_init_conn(debuglvl);
        if(conn == NULL)
            return(FALSE);

        strlcpy(conn->ser, cd_ptr->sername, sizeof(conn->ser));
        strlcpy(conn->src, cd_ptr->fromname, sizeof(conn->src));
        strlcpy(conn->dst, cd_ptr->toname, sizeof(conn->dst));

        strlcpy(conn->src_ip, cd_ptr->src_ip, sizeof(conn->src_ip));
        strlcpy(conn->dst_ip, cd_ptr->dst_ip, sizeof(conn->dst_ip));
        conn->protocol = cd_ptr->protocol;
        conn->src_port = cd_ptr->src_port;
        conn->dst_port = cd_ptr->dst_port;
        conn->cnt = cd_ptr->cnt;

        if(d_list_append(debuglvl, &ctl->list, conn) == NULL)
            return(FALSE);
    }

    return(TRUE);
}

static char
parse_log_srcdst(const int debuglvl, char *str, char *ret_ip, size_t ip_size,
            char *ret_mac, size_t mac_size, int *ret_port)
{
    if (debuglvl >= MEDIUM)
        (void)vrprint.debug(__FUNC__, "str     '%s'", str);

    int s = 0; /* string */
    int i = 0; /* ip */
    int m = 0; /* mac */
    int p = 0; /* port */

    char what = 0; // 0 ip 1 mac 2 port

    char ip[16] = "";
    char mac[18] = "";
    char port[6] = "";

    for (s = 0; s < strlen(str); s++)
    {
        if(what == 0) {
            ip[i] = str[s];

            if(str[s] == '(' || (i + 1) == sizeof(ip)) {
                what++;
                ip[i] = '\0';
            } else if(str[s] == ':') {
                what += 2;
                ip[i] = '\0';
            } else
                i++;
        } else if(what == 1) {
            mac[m] = str[s];

            if(str[s] == ')' || (m + 1) == sizeof(mac)) {
                what++;
                mac[m] = '\0';

                s++; /* skip past : */
            } else
                m++;
        } else if(what == 2) {
            port[p] = str[s];
            if ((p + 1) == sizeof(port)) {
                port[p] = '\0';
                break;
            }

            p++;
        }
    }

    /* term all */
    ip[i] = '\0';
    mac[m] = '\0';
    port[p] = '\0';

    if (debuglvl >= MEDIUM) {
        (void)vrprint.debug(__FUNC__, "src ip   '%s'", ip);
        (void)vrprint.debug(__FUNC__, "src mac  '%s'", mac);
        (void)vrprint.debug(__FUNC__, "src port '%s'", port);
    }

    strlcpy(ret_ip, ip, ip_size);
    strlcpy(ret_mac, mac, mac_size);
    *ret_port = atoi(port);

    return(TRUE);
}

/* convert struct LogRule to StatEventLog
*/
static char
statevent_convert_log(const int debuglvl, StatEventCtl *ctl, d_list *list)
{
    d_list_node     *d_node = NULL;
    LogRule         *logrule_ptr = NULL;
    StatEventLog    *log = NULL;

    char *s = NULL;

#define MAX_TOK 32
    char store[MAX_TOK][42]; /* max: ip + mac + port + :() and \0 =
                    15 + 18 + 5 + 4 = 42 */
    int x = 0, y = 0, z = 0;

    for(d_node = list->top; d_node; d_node = d_node->next)
    {
        logrule_ptr = d_node->data;

        log = statevent_init_log(debuglvl);
        if(log == NULL)
            return(FALSE);

        strlcpy(log->ser, logrule_ptr->service, sizeof(log->ser));
        strlcpy(log->src, logrule_ptr->from, sizeof(log->src));
        strlcpy(log->dst, logrule_ptr->to, sizeof(log->dst));

        strlcpy(log->details, logrule_ptr->details, sizeof(log->details));
        strlcpy(log->action, logrule_ptr->action, sizeof(log->action));
        strlcpy(log->prefix, logrule_ptr->prefix, sizeof(log->prefix));

        snprintf(log->timedate_str, sizeof(log->timedate_str), "%s %s %s",
            logrule_ptr->month, logrule_ptr->date, logrule_ptr->time);

        log->filtered = logrule_ptr->filtered;

        /* parse the details :-S */
        //vrprint.error(-1, "Details", "%s", logrule_ptr->details);

        /*  TCP, UDP, ICMP, GRE examples

            (in: eth1 192.168.2.1:138 -> 192.168.2.255:138 UDP len:211 ttl:64)
            (in: eth0 out: ppp0 192.168.1.2:41719 -> 64.156.11.200:80 TCP flags: ****S* len:60 ttl:63)
            (in: eth0 out: ppp0 192.168.1.2 -> 194.109.21.51 ICMP type 8 code 0 len:84 ttl:63)
            (in: ppp0 out: eth0 194.109.5.241 -> 192.168.1.64 (41) len:76 ttl:26)
        */
        s = logrule_ptr->details;

        /* split the tokens */
        for(x = 0, y = 0, z = 0; x < strlen(s); x++)
        {
            /* copy char */
            store[y][z] = s[x];

            if(store[y][z] == ' ') {
                store[y][z] = '\0';

                y++;
                z = 0;

                if(y == MAX_TOK)
                    break;
            } else
                z++;
        }

        int next = 0;

        if (strcmp(store[0],"(in:") == 0) {
            vrprint.debug(__FUNC__, "in = %s", store[1]);
            next = 2;
        } else if(strcmp(store[0],"(out:") == 0) {
            vrprint.debug(__FUNC__, "out = %s", store[1]);
            next = 2;
        }
        if(strcmp(store[next],"out:") == 0) {
            vrprint.debug(__FUNC__, "out = %s", store[3]);
            next +=2;
        }

        /* ip or ip+port */
        vrprint.debug(__FUNC__, "src ip/ip+port %s", store[next]);
        char *src = store[next];
        next++;

        /* arrow */
        vrprint.debug(__FUNC__, "arrow %s", store[next]);
        next++;

        /* ip or ip+port */
        vrprint.debug(__FUNC__, "dst ip/ip+port %s", store[next]);
        char *dst = store[next];
        next++;

        vrprint.debug(__FUNC__, "store[next] %s", store[next]);

        /*  parse src and dst

            TCP/UDP:
            193.93.236.7:47974
            193.93.236.7(00:05:5f:54:8f:fc):47974

            REST:
            193.93.236.7
            193.93.236.7(00:05:5f:54:8f:fc)


        */
        char mac[18] = "";

        parse_log_srcdst(debuglvl, src, log->src_ip,
                sizeof(log->src_ip), mac, sizeof(mac),
                &log->src_port);

        parse_log_srcdst(debuglvl, dst, log->dst_ip,
                sizeof(log->dst_ip), mac, sizeof(mac),
                &log->dst_port);


        if(strcmp(store[next],"TCP") == 0) {
            log->protocol = 6;
        } else if (strcmp(store[next],"UDP") == 0) {
            log->protocol = 17;
        } else if (strcmp(store[next],"ICMP") == 0) {
            log->protocol = 1;
        } else if (strcmp(store[next],"GRE") == 0) {
            log->protocol = 47;
        } else if (strcmp(store[next],"ESP") == 0) {
            log->protocol = 50;
        } else if (strcmp(store[next],"AH") == 0) {
            log->protocol = 51;
        } else {
            vrprint.debug(__FUNC__, "no match '%s'", store[next]);
        }

        //vrprint.debug(__FUNC__, "x = %d, y = %d, z = %d", x,y,z);

        if(d_list_append(debuglvl, &ctl->list, log) == NULL) {
            (void)vrprint.error(-1, VR_INTERR, "d_list_append failed "
                "(in: %s:%d).", __FUNC__, __LINE__);
            return(FALSE);
        }
    }

    return(TRUE);
}

/* wrapper around ip and name killing */
int kill_connections(const int debuglvl, struct vuurmuur_config *cnf,
        VR_ConntrackRequest *connreq, Conntrack *ct, StatEventConn *conn) {
    if (connreq->unknown_ip_as_net) {
        return (kill_connections_by_name(debuglvl, cnf, ct, conn->src,
            conn->dst, conn->ser, conn->connect_status));
    } else {
        return (kill_connections_by_ip(debuglvl, cnf, ct, conn->src_ip,
            conn->dst_ip, conn->ser, conn->connect_status));
    }
}


/*  Display the menu that allows the user to act
    on a connection.

*/
static void
statevent_interactivemenu_conn( const int debuglvl, struct vuurmuur_config *cnf,
                                StatEventCtl *ctl, Conntrack *ct,
                                VR_ConntrackRequest *connreq, Zones *zones,
                                struct vrmr_blocklist *blocklist, struct vrmr_interfaces *interfaces,
                                struct vrmr_services *services, StatEventGen *gen_ptr)
{
    VrWin           *win = NULL;
    VrMenu          *menu = NULL;
    int             ch = 0;
    int             menu_items = 10;
    char            *str = NULL;
    const int       width = 70;
    /* top menu */
    char            *key_choices[] =    {   "F12",
                                            "F10"};
    int             key_choices_n = 2;
    char            *cmd_choices[] =    {   gettext("help"),
                                            gettext("back")};
    int             cmd_choices_n = 2;
    StatEventConn   *con = (StatEventConn *)gen_ptr;
    Conntrack       *privct = NULL;
    char            ungroup_conns = FALSE;
    char            *title = gettext("Manage Connection");

    /* if needed get our own private ungrouped ct */
    if(connreq->group_conns == TRUE)
    {
        ungroup_conns = TRUE; /* we are ungrouping the list */

        connreq->group_conns = FALSE;

        privct = conn_init_ct(debuglvl, zones, interfaces,
            services, blocklist);
        if(privct == NULL)
            return;

        conn_ct_get_connections(debuglvl, cnf, privct, connreq);

        ct = privct;
    }

    /* create the window and put it in the middle of the screen */
    win = VrNewWin(menu_items + 2,width,0,0,vccnf.color_win);
    if(win == NULL)
    {
        (void)vrprint.error(-1, VR_ERR, "VrNewWin failed");
        return;
    }
    VrWinSetTitle(win, title);

    menu = VrNewMenu(menu_items, width - 2, 1,1, menu_items,vccnf.color_win,vccnf.color_win_rev);
    if(menu == NULL)
    {
        (void)vrprint.error(-1, VR_ERR, "VrNewMenu failed");
        return;
    }

    VrMenuSetDescFreeFunc(menu, free);
    VrMenuSetupNameList(debuglvl, menu);
    VrMenuSetupDescList(debuglvl, menu);

    /* setup menu items */
    if(con->cnt == 1)   str = vrmr_get_string(gettext("Kill this connection"));
    else                str = vrmr_get_string(gettext("Kill all connections with this service/source/destination"),con->cnt);
    VrMenuAddItem(debuglvl, menu, "1", str);

    str = vrmr_get_string("--- %s ---", gettext("Kill options"));
    VrMenuAddSepItem(debuglvl, menu, str);

    str = vrmr_get_string(gettext("Kill all connections with source %s"), con->src_ip);
    VrMenuAddItem(debuglvl, menu, "2", str);

    str = vrmr_get_string(gettext("Kill all connections with destination %s"), con->dst_ip);
    VrMenuAddItem(debuglvl, menu, "3", str);

    str = vrmr_get_string(gettext("Kill all connections of %s"), con->src_ip);
    VrMenuAddItem(debuglvl, menu, "4", str);

    str = vrmr_get_string(gettext("Kill all connections of %s"), con->dst_ip);
    VrMenuAddItem(debuglvl, menu, "5", str);

    str = vrmr_get_string("--- %s ---", gettext("BlockList options"));
    VrMenuAddSepItem(debuglvl, menu, str);

    str = vrmr_get_string(gettext("Add source %s to BlockList"), con->src_ip);
    VrMenuAddItem(debuglvl, menu, "6", str);

    str = vrmr_get_string(gettext("Add destination %s to BlockList"), con->dst_ip);
    VrMenuAddItem(debuglvl, menu, "7", str);

    str = vrmr_get_string(gettext("Add both source and destination to BlockList"));
    VrMenuAddItem(debuglvl, menu, "8", str);

    VrMenuConnectToWin(debuglvl, menu, win);
    VrMenuPost(debuglvl, menu);

    draw_top_menu(debuglvl, top_win, title, key_choices_n,
            key_choices, cmd_choices_n, cmd_choices);

    update_panels();
    doupdate();

    /* user input */
    char quit = FALSE;
    while(quit == FALSE)
    {
        ch = VrWinGetch(win);

        switch(ch)
        {
            case 27:
            case 'q':
            case 'Q':
            case KEY_F(10):
                quit = TRUE;
                break;

            case 10:
            {
                ITEM *cur = current_item(menu->m);
                if(cur != NULL)
                {
                    int act = atoi((char *)item_name(cur));
                    switch(act)
                    {
                        case 1: /* kill */
                        {
                            /* check if the conntrack tool is set */
                            if(conf.conntrack_location[0] == '\0')
                            {
                                (void)vrprint.error(-1, VR_ERR, STR_CONNTRACK_LOC_NOT_SET);
                            }
                            else if(con->cnt == 1)
                            {
                                if(confirm(gettext("Kill connection"),gettext("Are you sure?"),
                                    vccnf.color_win_note, vccnf.color_win_note_rev|A_BOLD, 1) == 1)
                                {
                                    kill_connection(debuglvl, conf.conntrack_location,
                                        con->src_ip, con->dst_ip, con->protocol,
                                        con->src_port, con->dst_port);
                                }
                            }
                            else
                            {
                                vrprint.debug(__FUNC__, "cnt %u, src %s srcip %s dst %s dstip %s ser %s",
                                        con->cnt, con->src, con->src_ip, con->dst,
                                        con->dst_ip, con->ser);

                                if(confirm(gettext("Kill connections"),gettext("Are you sure?"),
                                    vccnf.color_win_note, vccnf.color_win_note_rev|A_BOLD, 1) == 1)
                                {
                                    kill_connections(debuglvl, &conf, connreq, ct, con);
                                }
                            }
                            break;
                        }

                        case 2: /* kill all src ip */
                            /* check if the conntrack tool is set */
                            if(conf.conntrack_location[0] == '\0')
                            {
                                (void)vrprint.error(-1, VR_ERR, STR_CONNTRACK_LOC_NOT_SET);
                            }
                            else if(confirm(gettext("Kill connections"),gettext("Are you sure?"),
                                vccnf.color_win_note, vccnf.color_win_note_rev|A_BOLD, 1) == 1)
                            {
                                kill_connections_by_ip(debuglvl, &conf, ct, con->src_ip, NULL, NULL, CONN_UNUSED);
                            }
                            break;

                        case 3: /* kill all dst ip */
                            /* check if the conntrack tool is set */
                            if(conf.conntrack_location[0] == '\0')
                            {
                                (void)vrprint.error(-1, VR_ERR, STR_CONNTRACK_LOC_NOT_SET);
                            }
                            else if(confirm(gettext("Kill connections"),gettext("Are you sure?"),
                                vccnf.color_win_note, vccnf.color_win_note_rev|A_BOLD, 1) == 1)
                            {
                                kill_connections_by_ip(debuglvl, &conf, ct, NULL, con->dst_ip, NULL, CONN_UNUSED);
                            }
                            break;

                        case 4:
                            /* check if the conntrack tool is set */
                            if(conf.conntrack_location[0] == '\0')
                            {
                                (void)vrprint.error(-1, VR_ERR, STR_CONNTRACK_LOC_NOT_SET);
                            }
                            else if(confirm(gettext("Kill connections"),gettext("Are you sure?"),
                                vccnf.color_win_note, vccnf.color_win_note_rev|A_BOLD, 1) == 1)
                            {
                                kill_connections_by_ip(debuglvl, &conf, ct, NULL, con->src_ip, NULL, CONN_UNUSED);
                                kill_connections_by_ip(debuglvl, &conf, ct, con->src_ip, NULL, NULL, CONN_UNUSED);
                            }
                            break;

                        case 5:
                            /* check if the conntrack tool is set */
                            if(conf.conntrack_location[0] == '\0')
                            {
                                (void)vrprint.error(-1, VR_ERR, STR_CONNTRACK_LOC_NOT_SET);
                            }
                            else if(confirm(gettext("Kill connections"),gettext("Are you sure?"),
                                vccnf.color_win_note, vccnf.color_win_note_rev|A_BOLD, 1) == 1)
                            {
                                kill_connections_by_ip(debuglvl, &conf, ct, NULL, con->dst_ip, NULL, CONN_UNUSED);
                                kill_connections_by_ip(debuglvl, &conf, ct, con->dst_ip, NULL, NULL, CONN_UNUSED);
                            }
                            break;


                        case 6:
                            if(confirm(gettext("Add to BlockList and Apply Changes"),gettext("Are you sure?"),
                                vccnf.color_win_note, vccnf.color_win_note_rev|A_BOLD, 1) == 1)
                            {
                                block_and_kill(debuglvl, ct, zones, blocklist, interfaces, con->src_ip);
                            }
                            break;

                        case 7:
                            if(confirm(gettext("Add to BlockList and Apply Changes"),gettext("Are you sure?"),
                                vccnf.color_win_note, vccnf.color_win_note_rev|A_BOLD, 1) == 1)
                            {
                                block_and_kill(debuglvl, ct, zones, blocklist, interfaces, con->dst_ip);
                            }
                            break;

                        case 8:
                            if(confirm(gettext("Add to BlockList and Apply Changes"),gettext("Are you sure?"),
                                vccnf.color_win_note, vccnf.color_win_note_rev|A_BOLD, 1) == 1)
                            {
                                block_and_kill(debuglvl, ct, zones, blocklist, interfaces, con->src_ip);
                                block_and_kill(debuglvl, ct, zones, blocklist, interfaces, con->dst_ip);
                            }
                            break;

                        default:
                            break;
                    }
                }

                break;
            }

            case KEY_F(12):
            case 'h':
            case 'H':
            case '?':
                print_help(debuglvl, ctl->help_actions);
                break;

            default:
                (void)VrMenuDefaultNavigation(debuglvl, menu, ch);
                break;
        }
    }

    VrDelMenu(debuglvl, menu);
    VrDelWin(win);
    update_panels();
    doupdate();

    /* we have ungrouped the list, clean up here. */
    if(ungroup_conns == TRUE)
    {
        connreq->group_conns = TRUE;

        conn_ct_clear_connections(debuglvl, privct);
        conn_free_ct(debuglvl, &privct, NULL);
    }

    return;
}

/*  Display the menu that allows the user to act
    on a connection.

*/
static void
statevent_interactivemenu_log(  const int debuglvl, struct vuurmuur_config *cnf,
                                StatEventCtl *ctl, Conntrack *ct,
                                VR_ConntrackRequest *connreqnull, Zones *zones,
                                struct vrmr_blocklist *blocklist, struct vrmr_interfaces *interfaces,
                                struct vrmr_services *services, StatEventGen *gen_ptr)
{
    VrWin               *win = NULL;
    VrMenu              *menu = NULL;
    int                 ch = 0;
    int                 menu_items = 10;
    char                *str = NULL;
    const int           width = 70;
    /* top menu */
    char                *key_choices[] =    {   "F12",
                                                "F10"};
    int                 key_choices_n = 2;
    char                *cmd_choices[] =    {   gettext("help"),
                                                gettext("back")};
    int                 cmd_choices_n = 2;
    StatEventLog        *log = (StatEventLog *)gen_ptr;

    Conntrack           *ctr = NULL;
    VR_ConntrackRequest connreq;
    char                *title = gettext("Manage Log");

    /* number labels */
    char *nums[9] = { "1", "2", "3", "4", "5", "6", "7", "8", NULL };
    int n = 0;
    int action = 0;

    VrBusyWinShow();

    /* init filter */
    VR_connreq_setup(debuglvl, &connreq);
    connreq.group_conns = TRUE;
    connreq.unknown_ip_as_net = TRUE;
    /* sorting, relevant for grouping */
    connreq.sort_in_out_fwd = FALSE;
    connreq.sort_conn_status = FALSE;
    /* drawing */
    connreq.draw_acc_data = TRUE;
    connreq.draw_details = TRUE;

    /* get the connections for killing them later if the user chooses to */
    ctr = conn_init_ct(debuglvl, zones, interfaces, services, blocklist);
    conn_ct_get_connections(debuglvl, cnf, ctr, &connreq);

    action = rules_actiontoi(log->action);
    if(action == AT_DROP || action == AT_REJECT)
        menu_items--;

    /* create the window and put it in the middle of the screen */
    win = VrNewWin(menu_items + 2,width,0,0,vccnf.color_win);
    if(win == NULL)
    {
        (void)vrprint.error(-1, VR_ERR, "VrNewWin failed");
        return;
    }
    VrWinSetTitle(win, title);

    menu = VrNewMenu(menu_items, width - 2, 1,1, menu_items,vccnf.color_win,vccnf.color_win);
    if(menu == NULL)
    {
        (void)vrprint.error(-1, VR_ERR, "VrNewMenu failed");
        return;
    }

    VrMenuSetDescFreeFunc(menu, free);
    VrMenuSetupNameList(debuglvl, menu);
    VrMenuSetupDescList(debuglvl, menu);

    if(action != AT_DROP && action != AT_REJECT)
    {
        /* setup menu items */
        str = vrmr_get_string(gettext("Kill this connection"));
        VrMenuAddItem(debuglvl, menu, nums[n], str); n++;
    }

    str = vrmr_get_string("--- %s ---", gettext("Kill options"));
    VrMenuAddSepItem(debuglvl, menu, str);

    str = vrmr_get_string(gettext("Kill all connections with source %s"), log->src_ip);
    VrMenuAddItem(debuglvl, menu, nums[n++], str);

    str = vrmr_get_string(gettext("Kill all connections with destination %s"), log->dst_ip);
    VrMenuAddItem(debuglvl, menu, nums[n++], str);

    str = vrmr_get_string(gettext("Kill all connections of %s"), log->src_ip);
    VrMenuAddItem(debuglvl, menu, nums[n++], str);

    str = vrmr_get_string(gettext("Kill all connections of %s"), log->dst_ip);
    VrMenuAddItem(debuglvl, menu, nums[n++], str);

    str = vrmr_get_string("--- %s ---", gettext("BlockList options"));
    VrMenuAddSepItem(debuglvl, menu, str);

    str = vrmr_get_string(gettext("Add source %s to BlockList"), log->src_ip);
    VrMenuAddItem(debuglvl, menu, nums[n++], str);

    str = vrmr_get_string(gettext("Add destination %s to BlockList"), log->dst_ip);
    VrMenuAddItem(debuglvl, menu, nums[n++], str);

    str = vrmr_get_string(gettext("Add both source and destination to BlockList"));
    VrMenuAddItem(debuglvl, menu, nums[n], str); /* n != n++ */

    VrMenuConnectToWin(debuglvl, menu, win);
    VrMenuPost(debuglvl, menu);

    draw_top_menu(debuglvl, top_win, title, key_choices_n,
            key_choices, cmd_choices_n, cmd_choices);

    update_panels();
    doupdate();

    VrBusyWinHide();

    /* user input */
    char quit = FALSE;
    while(quit == FALSE)
    {
        ch = VrWinGetch(win);

        switch(ch)
        {
            case 27:
            case 'q':
            case 'Q':
            case KEY_F(10):
                quit = TRUE;
                break;

            case 10:
            {
                ITEM *cur = current_item(menu->m);
                if(cur != NULL)
                {
                    int act = atoi((char *)item_name(cur));
                    switch(act)
                    {
                        case 1: /* kill */
                        {
                            /* check if the conntrack tool is set */
                            if(conf.conntrack_location[0] == '\0')
                            {
                                (void)vrprint.error(-1, VR_ERR, STR_CONNTRACK_LOC_NOT_SET);
                            }
                            else
                            {
                                if(confirm(gettext("Kill connections"),gettext("Are you sure?"),
                                    vccnf.color_win_note, vccnf.color_win_note_rev|A_BOLD, 1) == 1)
                                {
                                    kill_connections_by_ip(debuglvl, &conf, ctr,
                                        log->src_ip, log->dst_ip, log->ser, CONN_UNUSED);
                                }
                            }
                            break;
                        }

                        case 2: /* kill all src ip */
                            /* check if the conntrack tool is set */
                            if(conf.conntrack_location[0] == '\0')
                            {
                                (void)vrprint.error(-1, VR_ERR, STR_CONNTRACK_LOC_NOT_SET);
                            }
                            else if(confirm(gettext("Kill connections"),gettext("Are you sure?"),
                                vccnf.color_win_note, vccnf.color_win_note_rev|A_BOLD, 1) == 1)
                            {
                                kill_connections_by_ip(debuglvl, &conf, ctr, log->src_ip, NULL, NULL, CONN_UNUSED);
                            }
                            break;

                        case 3: /* kill all dst ip */
                            /* check if the conntrack tool is set */
                            if(conf.conntrack_location[0] == '\0')
                            {
                                (void)vrprint.error(-1, VR_ERR, STR_CONNTRACK_LOC_NOT_SET);
                            }
                            else if(confirm(gettext("Kill connections"),gettext("Are you sure?"),
                                vccnf.color_win_note, vccnf.color_win_note_rev|A_BOLD, 1) == 1)
                            {
                                kill_connections_by_ip(debuglvl, &conf, ctr, NULL, log->dst_ip, NULL, CONN_UNUSED);
                            }
                            break;

                        case 4:
                            /* check if the conntrack tool is set */
                            if(conf.conntrack_location[0] == '\0')
                            {
                                (void)vrprint.error(-1, VR_ERR, STR_CONNTRACK_LOC_NOT_SET);
                            }
                            else if(confirm(gettext("Kill connections"),gettext("Are you sure?"),
                                vccnf.color_win_note, vccnf.color_win_note_rev|A_BOLD, 1) == 1)
                            {
                                kill_connections_by_ip(debuglvl, &conf, ctr, NULL, log->src_ip, NULL, CONN_UNUSED);
                                kill_connections_by_ip(debuglvl, &conf, ctr, log->src_ip, NULL, NULL, CONN_UNUSED);
                            }
                            break;
                
                        case 5:
                            /* check if the conntrack tool is set */
                            if(conf.conntrack_location[0] == '\0')
                            {
                                (void)vrprint.error(-1, VR_ERR, STR_CONNTRACK_LOC_NOT_SET);
                            }
                            else if(confirm(gettext("Kill connections"),gettext("Are you sure?"),
                                vccnf.color_win_note, vccnf.color_win_note_rev|A_BOLD, 1) == 1)
                            {
                                kill_connections_by_ip(debuglvl, &conf, ctr, NULL, log->dst_ip, NULL, CONN_UNUSED);
                                kill_connections_by_ip(debuglvl, &conf, ctr, log->dst_ip, NULL, NULL, CONN_UNUSED);
                            }
                            break;


                        case 6:
                            if(confirm(gettext("Add to BlockList and Apply Changes"),gettext("Are you sure?"),
                                vccnf.color_win_note, vccnf.color_win_note_rev|A_BOLD, 1) == 1)
                            {
                                block_and_kill(debuglvl, ctr, zones, blocklist, interfaces, log->src_ip);
                            }
                            break;

                        case 7:
                            if(confirm(gettext("Add to BlockList and Apply Changes"),gettext("Are you sure?"),
                                vccnf.color_win_note, vccnf.color_win_note_rev|A_BOLD, 1) == 1)
                            {
                                block_and_kill(debuglvl, ctr, zones, blocklist, interfaces, log->dst_ip);
                            }
                            break;

                        case 8:
                            if(confirm(gettext("Add to BlockList and Apply Changes"),gettext("Are you sure?"),
                                vccnf.color_win_note, vccnf.color_win_note_rev|A_BOLD, 1) == 1)
                            {
                                block_and_kill(debuglvl, ctr, zones, blocklist, interfaces, log->src_ip);
                                block_and_kill(debuglvl, ctr, zones, blocklist, interfaces, log->dst_ip);
                            }
                            break;

                        default:
                            break;
                    }
                }

                break;
            }

            case KEY_F(12):
            case 'h':
            case 'H':
            case '?':
                print_help(debuglvl, ctl->help_actions);
                break;

            default:
                (void)VrMenuDefaultNavigation(debuglvl, menu, ch);
                break;
        }
    }

    conn_ct_clear_connections(debuglvl, ctr);
    conn_free_ct(debuglvl, &ctr, zones);

    VrDelMenu(debuglvl, menu);
    VrDelWin(win);
    update_panels();
    doupdate();

    return;
}


static StatEventCtl *
statevent_init_ctl(const int debuglvl, int type)
{
    StatEventCtl *ctl = NULL;

    ctl = malloc(sizeof(StatEventCtl));
    if(ctl == NULL)
        return(NULL);

    memset(ctl, 0, sizeof(StatEventCtl));

    ctl->type = type;

    if(ctl->type == STATEVENTTYPE_CONN) {
        ctl->print2str        = statevent_print2str_conn;
        ctl->remove           = free;
        ctl->menu             = statevent_interactivemenu_conn;
        ctl->convert          = statevent_convert_conn;
        ctl->title_str        = gettext("Manage Connections");
        ctl->options_str      = gettext("connection actions");
        ctl->warn_no_data_str = gettext("No connections to act on.");
        ctl->help_overview    = ":[VUURMUUR:CONNECTIONS:MANAGE]:";
        ctl->help_actions     = ":[VUURMUUR:CONNECTIONS:ACTIONS]:";
    } else if (ctl->type == STATEVENTTYPE_LOG) {
        ctl->print2str        = statevent_print2str_log;
        ctl->remove           = free;
        ctl->menu             = statevent_interactivemenu_log;
        ctl->convert          = statevent_convert_log;
        ctl->title_str        = gettext("Manage Logging");
        ctl->options_str      = gettext("logging actions");
        ctl->warn_no_data_str = gettext("No logs to act on.");
        ctl->help_overview    = ":[VUURMUUR:LOGVIEW:MANAGE]:";
        ctl->help_actions     = ":[VUURMUUR:LOGVIEW:ACTIONS]:";
    }

    d_list_setup(debuglvl, &ctl->list, ctl->remove);

    return(ctl);
}

static void
statevent_free_ctl(const int debuglvl, StatEventCtl **ctl)
{
    d_list_cleanup(debuglvl, &(*ctl)->list);
    memset(*ctl, 0, sizeof(StatEventCtl));
    free(*ctl);
    *ctl = NULL;
}


int
statevent_menu(const int debuglvl, struct vuurmuur_config *cnf, int type,
        StatEventCtl *ctl, Conntrack *ct,
        VR_ConntrackRequest *connreq, Zones *zones, struct vrmr_blocklist *blocklist,
        struct vrmr_interfaces *interfaces, struct vrmr_services *services)
{
    VrWin           *win = NULL;
    VrMenu          *menu = NULL;
    int             ch = 0;
    d_list_node     *d_node = NULL;
    StatEventGen    *gen_ptr = NULL;

    /* top menu */
    char            *key_choices[] =    {   "F12",
                                            "enter",
                                            "F10"};
    int             key_choices_n = 3;
    char            *cmd_choices[] =    {   gettext("help"),
                                            ctl->options_str,
                                            gettext("back")};
    int             cmd_choices_n = 3;

    /* print a warning if we have no data */
    if(ctl->list.len == 0)
    {
        (void)vrprint.warning(VR_WARN, ctl->warn_no_data_str);
        return(0);
    }

    win = VrNewWin(LINES - 6,COLS - 2,3,1,vccnf.color_win);
    if(win == NULL)
    {
        (void)vrprint.error(-1, VR_ERR, "VrNewWin failed");
        return(-1);
    }

    VrWinSetTitle(win, ctl->title_str);
    draw_top_menu(debuglvl, top_win, ctl->title_str, key_choices_n,
            key_choices, cmd_choices_n, cmd_choices);

    menu = VrNewMenu(LINES - 8,COLS - 4,1,1,ctl->list.len,
            vccnf.color_win,vccnf.color_win_rev);
    if(menu == NULL)
    {
        (void)vrprint.error(-1, VR_ERR, "VrNewMenu failed");
        return(-1);
    }
    
    VrMenuSetNameFreeFunc(menu, free);
    VrMenuSetDescFreeFunc(menu, free);
    VrMenuSetupNameList(debuglvl, menu);
    VrMenuSetupDescList(debuglvl, menu);

    unsigned int num = 1;

    for(d_node = ctl->list.top; d_node; d_node = d_node->next)
    {
        gen_ptr = d_node->data;

        if(debuglvl >= MEDIUM)
            (void)vrprint.debug(__FUNC__, "gen_ptr->filtered %d",
                    gen_ptr->filtered);

        if(gen_ptr->filtered == 0)
        {
            char    *desc_str = NULL;
            char    *name_str = NULL;
            char    strtmp[512] = "";
            size_t  name_len = 0,
                    desc_len = 0;

            if(ctl->list.len <= 9)
                snprintf(strtmp, sizeof(strtmp), "%u", num);
            else if(ctl->list.len <= 99)
                snprintf(strtmp, sizeof(strtmp), "%2u", num);
            else if(ctl->list.len <= 999)
                snprintf(strtmp, sizeof(strtmp), "%3u", num);
            else if(ctl->list.len <= 9999)
                snprintf(strtmp, sizeof(strtmp), "%4u", num);
            else if(ctl->list.len <= 99999)
                snprintf(strtmp, sizeof(strtmp), "%5u", num);
            else if(ctl->list.len <= 999999)
                snprintf(strtmp, sizeof(strtmp), "%6u", num);
            else
                snprintf(strtmp, sizeof(strtmp), "%10u", num);

            name_len = strlen(strtmp) + 1;
            name_str = malloc(name_len);
            strlcpy(name_str, strtmp, name_len);

            /* get the str that will form the desc */
            desc_len = win->width - 2 - name_len;
            desc_str = ctl->print2str(debuglvl, gen_ptr, desc_len);

            num++;

            /* add the item to the menu */
            VrMenuAddItem(debuglvl, menu, name_str, desc_str);
        }
    }
    /* check if we didn't add any item (if all was filtered) */
    if(num == 1)
    {
        (void)vrprint.warning(VR_WARN, ctl->warn_no_data_str);
        VrDelMenu(debuglvl, menu);
        VrDelWin(win);
        update_panels();
        doupdate();
        return(0);
    }

    VrMenuConnectToWin(debuglvl, menu, win);
    VrMenuPost(debuglvl, menu);

    VrBusyWinHide();

    update_panels();
    doupdate();

    /* user input */
    char quit = FALSE;
    while(quit == FALSE)
    {
        ch = VrWinGetch(win);

        switch(ch)
        {
            case 27:
            case 'q':
            case 'Q':
            case KEY_F(10):
                quit = TRUE;
                break;

            case 10:
            {
                ITEM *cur = current_item(menu->m);
                if(cur != NULL)
                {
                    int i = atoi((char *)item_name(cur));
                    unsigned int u = 1;
                    gen_ptr = NULL;

                    /* get the current event: handle
                     * filtered events as well
                     */
                    for(d_node = ctl->list.top; d_node;
                        d_node = d_node->next, u++)
                    {
                        gen_ptr = d_node->data;

                        if(!gen_ptr->filtered) {
                            if(u == (unsigned int)i)
                                break;
                        } else {
                            u--;
                        }

                        gen_ptr = NULL;
                    }
                    if(gen_ptr == NULL)
                    {
                        // error
                        return(-1);
                    }
                    else
                    {
                        /* call the interactive menu
                           function */
                        ctl->menu(debuglvl, cnf, ctl, ct,
                            connreq, zones, blocklist,
                            interfaces, services,
                            gen_ptr);

                        /* when done, restore the title
                           and options */
                        draw_top_menu(debuglvl, top_win,
                                ctl->title_str,
                                key_choices_n,
                                key_choices,
                                cmd_choices_n,
                                cmd_choices);
                    }
                }
                break;
            }
            case KEY_F(12):
            case 'h':
            case 'H':
            case '?':
                print_help(debuglvl, ctl->help_overview);
                break;

            default:
                (void)VrMenuDefaultNavigation(debuglvl, menu, ch);
                break;
        }
    }
    
    VrDelMenu(debuglvl, menu);
    VrDelWin(win);
    update_panels();
    doupdate();

    return(0);
}

void
statevent(const int debuglvl, struct vuurmuur_config *cnf, int type,
        d_list *list, Conntrack *ct,
        VR_ConntrackRequest *connreq, Zones *zones,
        struct vrmr_blocklist *blocklist, struct vrmr_interfaces *interfaces,
        struct vrmr_services *services)
{
    StatEventCtl    *ctl = NULL;

    VrBusyWinShow();

    ctl = statevent_init_ctl(debuglvl, type);
    if(ctl == NULL) {
        return;
    }

    //vrprint.warning(VR_WARN,"list %u", ctl->list.len);
    /* convert datatypes list to our own type */
    if(ctl->convert(debuglvl, ctl, list) == FALSE)
    {
        (void)vrprint.error(-1, VR_ERR, "loading data failed.");
    }
    //vrprint.warning(VR_WARN,"list %u", ctl->list.len);

    statevent_menu(debuglvl, cnf, type, ctl, ct, connreq, zones, blocklist,
            interfaces, services);

    statevent_free_ctl(debuglvl, &ctl);
    
    // hide if not already hidden
    VrBusyWinHide();
}
