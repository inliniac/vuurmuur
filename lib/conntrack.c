/***************************************************************************
 *   Copyright (C) 2002-2017 by Victor Julien                              *
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
#include "conntrack.h"
#include "vuurmuur.h"

struct vrmr_conntrack_line {
    int protocol;
    int ipv6;
    int ttl;
    int state;
    char src_ip[46];
    char dst_ip[46];
    char alt_src_ip[46];
    char alt_dst_ip[46];
    char orig_dst_ip[46];
    int src_port;
    int dst_port;
    int alt_src_port;
    int alt_dst_port;
    uint64_t to_src_packets;
    uint64_t to_src_bytes;
    uint64_t to_dst_packets;
    uint64_t to_dst_bytes;
    char to_src_packets_str[16];
    char to_src_bytes_str[16];
    char to_dst_packets_str[16];
    char to_dst_bytes_str[16];
    char status[16];
    char use_acc;
};

static void free_conntrack_entry(struct vrmr_conntrack_entry *ce)
{
    if (ce->from == NULL)
        free(ce->fromname);
    if (ce->to == NULL)
        free(ce->toname);
    if (ce->service == NULL)
        free(ce->sername);

    free(ce);
}

/*

    Returncodes:
        0: not filtered
        1: filtered

        In case of error we return 0.
*/
static int filtered_connection(
        struct vrmr_conntrack_entry *cd_ptr, struct vrmr_filter *filter)
{
    char line[512] = "";

    assert(cd_ptr && filter);

    snprintf(line, sizeof(line), "%d %s %s %s %d %d %d %s %s", cd_ptr->cnt,
            cd_ptr->sername, cd_ptr->fromname, cd_ptr->toname, cd_ptr->src_port,
            cd_ptr->dst_port, cd_ptr->protocol, cd_ptr->src_ip, cd_ptr->dst_ip);

    /*  check the regex

        If the regex matches, the line is not filtered, so we return 0.
    */
    if (regexec(&filter->reg, line, 0, NULL, 0) == 0) {
        if (filter->neg == FALSE)
            return (0);
        else
            return (1);
    } else {
        if (filter->neg == FALSE)
            return (1);
        else
            return (0);
    }
}

//- print_dlist
void vrmr_conn_print_dlist(const struct vrmr_list *dlist)
{
    struct vrmr_list_node *d_node = NULL;
    struct vrmr_conntrack_entry *cd_ptr = NULL;
    char status[16] = "";
    char direction[16] = "";

    assert(dlist);

    for (d_node = dlist->top; d_node; d_node = d_node->next) {
        cd_ptr = d_node->data;

        if (cd_ptr->connect_status == VRMR_CONN_UNUSED)
            strcpy(status, "");
        else if (cd_ptr->connect_status == VRMR_CONN_CONNECTING)
            strcpy(status, "CONNECTING");
        else if (cd_ptr->connect_status == VRMR_CONN_CONNECTED)
            strcpy(status, "CONNECTED");
        else if (cd_ptr->connect_status == VRMR_CONN_DISCONNECTING)
            strcpy(status, "DISCONNECTING");
        else
            strcpy(status, "UNKNOWN");

        if (cd_ptr->direction_status == VRMR_CONN_UNUSED)
            strcpy(direction, "");
        else if (cd_ptr->direction_status == VRMR_CONN_IN)
            strcpy(direction, "INCOMING");
        else if (cd_ptr->direction_status == VRMR_CONN_OUT)
            strcpy(direction, "OUTGOING");
        else if (cd_ptr->direction_status == VRMR_CONN_FW)
            strcpy(direction, "FORWARDING");

        fprintf(stdout, "%4d: service %s from %s to %s %s %s\n", cd_ptr->cnt,
                cd_ptr->sername, cd_ptr->fromname, cd_ptr->toname, status,
                direction);
    }

    return;
}

/*  conntrack_line_to_data

    This function analyzes the line supplied through the connline_ptr.
    It should never fail, unless we have a serious problem: malloc failure
    or parameter problems.

    Returncodes:
         0: ok
        -1: (serious) error
*/
static int conn_line_to_data(struct vrmr_conntrack_line *connline_ptr,
        struct vrmr_conntrack_entry *conndata_ptr,
        struct vrmr_hash_table *serhash, struct vrmr_hash_table *zonehash,
        struct vrmr_list *zonelist, struct vrmr_conntrack_request *req)
{
    char service_name[VRMR_MAX_SERVICE] = "", *zone_name_ptr = NULL;

    assert(connline_ptr && conndata_ptr && serhash && zonehash && req);

    if (req->unknown_ip_as_net && zonelist == NULL) {
        vrmr_error(-1, "Internal Error", "parameter problem");
        return (-1);
    }

    conndata_ptr->ipv6 = connline_ptr->ipv6;

    /* first the service name */
    conndata_ptr->service = vrmr_search_service_in_hash(connline_ptr->src_port,
            connline_ptr->dst_port, connline_ptr->protocol, serhash);
    if (conndata_ptr->service == NULL) {
        /* do a reverse lookup. This will prevent connections that
         * have been picked up by conntrack midstream to look
         * unrecognized  */
        if ((conndata_ptr->service = vrmr_search_service_in_hash(
                     connline_ptr->dst_port, connline_ptr->src_port,
                     connline_ptr->protocol, serhash)) == NULL) {
            if (connline_ptr->protocol == 6 || connline_ptr->protocol == 17)
                snprintf(service_name, sizeof(service_name), "%d -> %d",
                        connline_ptr->src_port, connline_ptr->dst_port);
            else if (connline_ptr->protocol == 1)
                snprintf(service_name, sizeof(service_name), "%d:%d",
                        connline_ptr->src_port, connline_ptr->dst_port);
            else
                snprintf(service_name, sizeof(service_name), "proto %d",
                        connline_ptr->protocol);

            if (!(conndata_ptr->sername = strdup(service_name))) {
                vrmr_error(-1, "Error", "strdup() failed: %s", strerror(errno));
                return (-1);
            }
        } else {
            /* found! */
            conndata_ptr->sername = conndata_ptr->service->name;
        }
    } else {
        conndata_ptr->sername = conndata_ptr->service->name;
    }

    /* for hashing and display */

    /* if the dst port and alt_dst_port don't match, it is
        a portfw rule with the remoteport option set. */
    if (connline_ptr->dst_port == connline_ptr->alt_src_port)
        conndata_ptr->dst_port = connline_ptr->dst_port;
    else
        conndata_ptr->dst_port = connline_ptr->alt_src_port;

    conndata_ptr->protocol = connline_ptr->protocol;
    conndata_ptr->src_port = connline_ptr->src_port;

    /* src ip */
    if (strlcpy(conndata_ptr->src_ip, connline_ptr->src_ip,
                sizeof(conndata_ptr->src_ip)) >= sizeof(conndata_ptr->src_ip)) {
        vrmr_error(-1, "Internal Error", "string overflow");
        return (-1);
    }

    /* then the from name */
    if (!(conndata_ptr->ipv6))
        conndata_ptr->from = vrmr_search_zone_in_hash_with_ipv4(
                connline_ptr->src_ip, zonehash);
    if (conndata_ptr->from == NULL) {
        vrmr_debug(HIGH, "unknown ip: '%s'.", connline_ptr->src_ip);

        if (req->unknown_ip_as_net == FALSE) {
            if (!(conndata_ptr->fromname = strdup(connline_ptr->src_ip))) {
                vrmr_error(-1, "Error",
                        "strdup() "
                        "failed: %s",
                        strerror(errno));
                return (-1);
            }
        } else {
            if (!(zone_name_ptr = vrmr_get_network_for_ipv4(
                          connline_ptr->src_ip, zonelist))) {
                if (!(conndata_ptr->fromname = strdup(connline_ptr->src_ip))) {
                    vrmr_error(-1, "Internal Error", "malloc failed: %s",
                            strerror(errno));
                    return (-1);
                }
            } else {
                if (!(conndata_ptr->fromname = strdup(zone_name_ptr))) {
                    vrmr_error(-1, "Internal Error", "strdup failed: %s",
                            strerror(errno));
                    free(zone_name_ptr);
                    return (-1);
                }

                free(zone_name_ptr);
            }
        }
    } else {
        conndata_ptr->fromname = conndata_ptr->from->name;
    }

    /* dst ip */
    strlcpy(conndata_ptr->dst_ip, connline_ptr->dst_ip,
            sizeof(conndata_ptr->dst_ip));
    /* dst ip */
    strlcpy(conndata_ptr->orig_dst_ip, connline_ptr->orig_dst_ip,
            sizeof(conndata_ptr->orig_dst_ip));
    /* then the to name */
    if (!(conndata_ptr->ipv6))
        conndata_ptr->to = vrmr_search_zone_in_hash_with_ipv4(
                connline_ptr->dst_ip, zonehash);
    if (conndata_ptr->to == NULL) {
        if (req->unknown_ip_as_net == FALSE) {
            if (!(conndata_ptr->toname = strdup(connline_ptr->dst_ip))) {
                vrmr_error(-1, "Internal Error", "strdup failed: %s",
                        strerror(errno));
                return (-1);
            }
        } else {
            if (!(zone_name_ptr = vrmr_get_network_for_ipv4(
                          connline_ptr->dst_ip, zonelist))) {
                if (!(conndata_ptr->toname = strdup(connline_ptr->dst_ip))) {
                    vrmr_error(-1, "Internal Error", "strdup failed: %s",
                            strerror(errno));
                    return (-1);
                }
            } else {
                if (!(conndata_ptr->toname = strdup(zone_name_ptr))) {
                    vrmr_error(-1, "Internal Error", "strdup failed: %s",
                            strerror(errno));

                    free(zone_name_ptr);
                    return (-1);
                }

                free(zone_name_ptr);
            }
        }
    } else {
        conndata_ptr->toname = conndata_ptr->to->name;
    }

    switch (connline_ptr->state) {
        case VRMR_STATE_SYN_SENT:
        case VRMR_STATE_SYN_RECV:
        case VRMR_STATE_UNREPLIED:
            conndata_ptr->connect_status = VRMR_CONN_CONNECTING;
            break;
        case VRMR_STATE_TCP_ESTABLISHED:
        case VRMR_STATE_UDP_ESTABLISHED:
            conndata_ptr->connect_status = VRMR_CONN_CONNECTED;
            break;
        case VRMR_STATE_FIN_WAIT:
        case VRMR_STATE_TIME_WAIT:
        case VRMR_STATE_CLOSE:
        case VRMR_STATE_CLOSE_WAIT:
        case VRMR_STATE_LAST_ACK:
            conndata_ptr->connect_status = VRMR_CONN_DISCONNECTING;
            break;
        default:
            conndata_ptr->connect_status = VRMR_CONN_UNUSED;
            break;
    }

    if (conndata_ptr->from != NULL &&
            conndata_ptr->from->type == VRMR_TYPE_FIREWALL)
        conndata_ptr->direction_status = VRMR_CONN_OUT;
    else if (conndata_ptr->to != NULL &&
             conndata_ptr->to->type == VRMR_TYPE_FIREWALL)
        conndata_ptr->direction_status = VRMR_CONN_IN;
    else
        conndata_ptr->direction_status = VRMR_CONN_FW;

    /* transfer the acc data */
    conndata_ptr->use_acc = connline_ptr->use_acc;
    conndata_ptr->to_src_packets = connline_ptr->to_src_packets;
    conndata_ptr->to_src_bytes = connline_ptr->to_src_bytes;
    conndata_ptr->to_dst_packets = connline_ptr->to_dst_packets;
    conndata_ptr->to_dst_bytes = connline_ptr->to_dst_bytes;

    return (0);
}

/* tcp      6 431999 ESTABLISHED src=192.168.1.2 dst=192.168.1.16 sport=51359
 * dport=22 packets=80969 bytes=7950474 src=192.168.1.16 dst=192.168.1.2
 * sport=22 dport=51359 packets=117783 bytes=123061993 [ASSURED] mark=0 use=1*/
/* tcp      6 118 SYN_SENT src=192.168.1.4 dst=92.122.217.72 sport=36549
 * dport=80 packets=1 bytes=60 [UNREPLIED] src=92.122.217.72 dst=192.168.1.4
 * sport=80 dport=36549 packets=0 bytes=0 mark=0 secmark=0 */
static int parse_tcp_line(
        const char *line, struct vrmr_conntrack_line *connline_ptr)
{
    int result = 0;
    char source_port[16] = "", dest_port[16] = "", alt_source_port[16] = "",
         alt_dest_port[16] = "", tmp[16] = "";

    if (connline_ptr->use_acc == TRUE) {
        result = sscanf(line,
                "%15s %d %d %15s src=%15s dst=%15s "
                "sport=%15s dport=%15s packets=%15s "
                "bytes=%15s src=%15s dst=%15s "
                "sport=%15s dport=%15s packets=%15s "
                "bytes=%15s",
                tmp, &connline_ptr->protocol, &connline_ptr->ttl,
                connline_ptr->status, connline_ptr->src_ip,
                connline_ptr->dst_ip, source_port, dest_port,
                connline_ptr->to_dst_packets_str,
                connline_ptr->to_dst_bytes_str, connline_ptr->alt_src_ip,
                connline_ptr->alt_dst_ip, alt_source_port, alt_dest_port,
                connline_ptr->to_src_packets_str,
                connline_ptr->to_src_bytes_str);
        if (result != 16) {
            /* unreplied */
            result = sscanf(line,
                    "%15s %d %d %15s src=%15s dst=%15s "
                    "sport=%15s dport=%15s packets=%15s "
                    "bytes=%15s %15s src=%15s dst=%15s "
                    "sport=%15s dport=%15s packets=%15s "
                    "bytes=%15s",
                    tmp, &connline_ptr->protocol, &connline_ptr->ttl,
                    connline_ptr->status, connline_ptr->src_ip,
                    connline_ptr->dst_ip, source_port, dest_port, tmp,
                    connline_ptr->to_dst_packets_str,
                    connline_ptr->to_dst_bytes_str, connline_ptr->alt_src_ip,
                    connline_ptr->alt_dst_ip, alt_source_port, alt_dest_port,
                    connline_ptr->to_src_packets_str,
                    connline_ptr->to_src_bytes_str);
            if (result != 17) {
                vrmr_debug(NONE, "parse error: '%s'", line);
                return (-1);
            }
        }

        vrmr_debug(LOW, "to dst: %sP %sB to src: %sP %sB",
                connline_ptr->to_dst_packets_str,
                connline_ptr->to_dst_bytes_str,
                connline_ptr->to_src_packets_str,
                connline_ptr->to_src_bytes_str);
    } else {
        result = sscanf(line,
                "%15s %d %d %15s src=%15s dst=%15s "
                "sport=%15s dport=%15s src=%15s "
                "dst=%15s sport=%15s dport=%15s",
                tmp, &connline_ptr->protocol, &connline_ptr->ttl,
                connline_ptr->status, connline_ptr->src_ip,
                connline_ptr->dst_ip, source_port, dest_port,
                connline_ptr->alt_src_ip, connline_ptr->alt_dst_ip,
                alt_source_port, alt_dest_port);
        if (result != 12) {
            result = sscanf(line,
                    "%15s %d %d %15s src=%15s dst=%15s "
                    "sport=%15s dport=%15s %15s src=%15s "
                    "dst=%15s sport=%15s dport=%15s",
                    tmp, &connline_ptr->protocol, &connline_ptr->ttl,
                    connline_ptr->status, connline_ptr->src_ip,
                    connline_ptr->dst_ip, source_port, dest_port, tmp,
                    connline_ptr->alt_src_ip, connline_ptr->alt_dst_ip,
                    alt_source_port, alt_dest_port);
            if (result != 13) {
                vrmr_debug(NONE, "parse error: '%s'", line);
                return (-1);
            }
        }
    }

    connline_ptr->src_port = atoi(source_port);
    if (connline_ptr->src_port <= 0 || connline_ptr->src_port > 65535)
        connline_ptr->src_port = 0;

    connline_ptr->dst_port = atoi(dest_port);
    if (connline_ptr->dst_port <= 0 || connline_ptr->dst_port > 65535)
        connline_ptr->dst_port = 0;

    connline_ptr->alt_src_port = atoi(alt_source_port);
    if (connline_ptr->alt_src_port <= 0 || connline_ptr->alt_src_port > 65535)
        connline_ptr->alt_src_port = 0;

    connline_ptr->alt_dst_port = atoi(alt_dest_port);
    if (connline_ptr->alt_dst_port <= 0 || connline_ptr->alt_dst_port > 65535)
        connline_ptr->alt_dst_port = 0;

    return (0);
}

/* tcp      6 57 CLOSE_WAIT src=xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx
 * dst=xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx sport=37424 dport=443
 * src=xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx
 * dst=xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx sport=443 dport=37424 [ASSURED]
 * mark=0 zone=0 use=2 */
static int parse_tcp_line_ipv6(
        const char *line, struct vrmr_conntrack_line *connline_ptr)
{
    int result = 0;
    char source_port[16] = "", dest_port[16] = "", alt_source_port[16] = "",
         alt_dest_port[16] = "", tmp[16] = "";

    if (connline_ptr->use_acc == TRUE) {
        result = sscanf(line,
                "%15s %d %d %15s src=%45s dst=%45s "
                "sport=%15s dport=%15s packets=%15s "
                "bytes=%15s src=%45s dst=%45s "
                "sport=%15s dport=%15s packets=%15s "
                "bytes=%15s",
                tmp, &connline_ptr->protocol, &connline_ptr->ttl,
                connline_ptr->status, connline_ptr->src_ip,
                connline_ptr->dst_ip, source_port, dest_port,
                connline_ptr->to_dst_packets_str,
                connline_ptr->to_dst_bytes_str, connline_ptr->alt_src_ip,
                connline_ptr->alt_dst_ip, alt_source_port, alt_dest_port,
                connline_ptr->to_src_packets_str,
                connline_ptr->to_src_bytes_str);
        if (result != 16) {
            /* unreplied */
            result = sscanf(line,
                    "%15s %d %d %15s src=%45s dst=%45s "
                    "sport=%15s dport=%15s packets=%15s "
                    "bytes=%15s %15s src=%45s dst=%45s "
                    "sport=%15s dport=%15s packets=%15s "
                    "bytes=%15s",
                    tmp, &connline_ptr->protocol, &connline_ptr->ttl,
                    connline_ptr->status, connline_ptr->src_ip,
                    connline_ptr->dst_ip, source_port, dest_port, tmp,
                    connline_ptr->to_dst_packets_str,
                    connline_ptr->to_dst_bytes_str, connline_ptr->alt_src_ip,
                    connline_ptr->alt_dst_ip, alt_source_port, alt_dest_port,
                    connline_ptr->to_src_packets_str,
                    connline_ptr->to_src_bytes_str);
            if (result != 17) {
                vrmr_debug(NONE, "parse error: '%s'", line);
                return (-1);
            }
        }

        vrmr_debug(LOW, "to dst: %sP %sB to src: %sP %sB",
                connline_ptr->to_dst_packets_str,
                connline_ptr->to_dst_bytes_str,
                connline_ptr->to_src_packets_str,
                connline_ptr->to_src_bytes_str);
    } else {
        result = sscanf(line,
                "%15s %d %d %15s src=%45s dst=%45s "
                "sport=%15s dport=%15s src=%45s "
                "dst=%45s sport=%15s dport=%15s",
                tmp, &connline_ptr->protocol, &connline_ptr->ttl,
                connline_ptr->status, connline_ptr->src_ip,
                connline_ptr->dst_ip, source_port, dest_port,
                connline_ptr->alt_src_ip, connline_ptr->alt_dst_ip,
                alt_source_port, alt_dest_port);
        if (result != 12) {
            result = sscanf(line,
                    "%15s %d %d %15s src=%45s dst=%45s "
                    "sport=%15s dport=%15s %15s src=%45s "
                    "dst=%45s sport=%15s dport=%15s",
                    tmp, &connline_ptr->protocol, &connline_ptr->ttl,
                    connline_ptr->status, connline_ptr->src_ip,
                    connline_ptr->dst_ip, source_port, dest_port, tmp,
                    connline_ptr->alt_src_ip, connline_ptr->alt_dst_ip,
                    alt_source_port, alt_dest_port);
            if (result != 13) {
                vrmr_debug(NONE, "parse error: '%s'", line);
                return (-1);
            }
        }
    }

    connline_ptr->src_port = atoi(source_port);
    if (connline_ptr->src_port <= 0 || connline_ptr->src_port > 65535)
        connline_ptr->src_port = 0;

    connline_ptr->dst_port = atoi(dest_port);
    if (connline_ptr->dst_port <= 0 || connline_ptr->dst_port > 65535)
        connline_ptr->dst_port = 0;

    connline_ptr->alt_src_port = atoi(alt_source_port);
    if (connline_ptr->alt_src_port <= 0 || connline_ptr->alt_src_port > 65535)
        connline_ptr->alt_src_port = 0;

    connline_ptr->alt_dst_port = atoi(alt_dest_port);
    if (connline_ptr->alt_dst_port <= 0 || connline_ptr->alt_dst_port > 65535)
        connline_ptr->alt_dst_port = 0;

    return (0);
}

/* udp      17 23 src=192.168.1.2 dst=192.168.1.1 sport=38009 dport=53
 * packets=20 bytes=1329 src=192.168.1.1 dst=192.168.1.2 sport=53 dport=38009
 * packets=20 bytes=3987 [ASSURED] mark=0 use=1 */
/* udp      17 12 src=192.168.1.2 dst=192.168.1.255 sport=137 dport=137
 * [UNREPLIED] src=192.168.1.255 dst=192.168.1.2 sport=137 dport=137 use=1*/
/* udp      17 29 src=192.168.1.4 dst=192.168.1.1 sport=57902 dport=53 packets=1
 * bytes=69 [UNREPLIED] src=192.168.1.1 dst=192.168.1.4 sport=53 dport=57902
 * packets=0 bytes=0 mark=0 secmark=0 use=2 */
static int parse_udp_line(
        const char *line, struct vrmr_conntrack_line *connline_ptr)
{
    int result = 0;
    char source_port[16] = "", dest_port[16] = "", alt_source_port[16] = "",
         alt_dest_port[16] = "", tmp[16] = "";

    if (connline_ptr->use_acc == TRUE) {
        result = sscanf(line,
                "%15s %d %d src=%15s dst=%15s "
                "sport=%15s dport=%15s packets=%15s "
                "bytes=%15s src=%15s dst=%15s "
                "sport=%15s dport=%15s packets=%15s "
                "bytes=%15s",
                tmp, &connline_ptr->protocol, &connline_ptr->ttl,
                connline_ptr->src_ip, connline_ptr->dst_ip, source_port,
                dest_port, connline_ptr->to_dst_packets_str,
                connline_ptr->to_dst_bytes_str, connline_ptr->alt_src_ip,
                connline_ptr->alt_dst_ip, alt_source_port, alt_dest_port,
                connline_ptr->to_src_packets_str,
                connline_ptr->to_src_bytes_str);

        if (result != 15) {
            result = sscanf(line,
                    "%15s %d %d src=%15s dst=%15s "
                    "sport=%15s dport=%15s packets=%15s "
                    "bytes=%15s %15s src=%15s dst=%15s "
                    "sport=%15s dport=%15s packets=%15s "
                    "bytes=%15s",
                    tmp, &connline_ptr->protocol, &connline_ptr->ttl,
                    connline_ptr->src_ip, connline_ptr->dst_ip, source_port,
                    dest_port, connline_ptr->to_dst_packets_str,
                    connline_ptr->to_dst_bytes_str, connline_ptr->status,
                    connline_ptr->alt_src_ip, connline_ptr->alt_dst_ip,
                    alt_source_port, alt_dest_port,
                    connline_ptr->to_src_packets_str,
                    connline_ptr->to_src_bytes_str);
            if (result != 16) {
                vrmr_debug(NONE, "parse error: '%s', result %d", line, result);
                return (-1);
            }
        }

        strlcpy(connline_ptr->status, "UDP_ESTABLISHED",
                sizeof(connline_ptr->status));

        vrmr_debug(LOW, "to dst: %sP %sB to src: %sP %sB",
                connline_ptr->to_dst_packets_str,
                connline_ptr->to_dst_bytes_str,
                connline_ptr->to_src_packets_str,
                connline_ptr->to_src_bytes_str);
    } else {
        result = sscanf(line,
                "%15s %d %d src=%15s dst=%15s "
                "sport=%15s dport=%15s src=%15s "
                "dst=%15s sport=%15s dport=%15s",
                tmp, &connline_ptr->protocol, &connline_ptr->ttl,
                connline_ptr->src_ip, connline_ptr->dst_ip, source_port,
                dest_port, connline_ptr->alt_src_ip, connline_ptr->alt_dst_ip,
                alt_source_port, alt_dest_port);
        if (result != 11) {
            result = sscanf(line,
                    "%15s %d %d src=%15s dst=%15s "
                    "sport=%15s dport=%15s %15s "
                    "src=%15s dst=%15s "
                    "sport=%15s dport=%15s",
                    tmp, &connline_ptr->protocol, &connline_ptr->ttl,
                    connline_ptr->src_ip, connline_ptr->dst_ip, source_port,
                    dest_port, connline_ptr->status, connline_ptr->alt_src_ip,
                    connline_ptr->alt_dst_ip, alt_source_port, alt_dest_port);
            if (result != 12) {
                vrmr_debug(NONE, "parse error: '%s'", line);
                return (-1);
            }
        }

        strlcpy(connline_ptr->status, "UDP_ESTABLISHED",
                sizeof(connline_ptr->status));
    }

    connline_ptr->src_port = atoi(source_port);
    if (connline_ptr->src_port <= 0 || connline_ptr->src_port > 65535)
        connline_ptr->src_port = 0;

    connline_ptr->dst_port = atoi(dest_port);
    if (connline_ptr->dst_port <= 0 || connline_ptr->dst_port > 65535)
        connline_ptr->dst_port = 0;

    connline_ptr->alt_src_port = atoi(alt_source_port);
    if (connline_ptr->alt_src_port <= 0 || connline_ptr->alt_src_port > 65535)
        connline_ptr->alt_src_port = 0;

    connline_ptr->alt_dst_port = atoi(alt_dest_port);
    if (connline_ptr->alt_dst_port <= 0 || connline_ptr->alt_dst_port > 65535)
        connline_ptr->alt_dst_port = 0;

    return (0);
}

static int parse_udp_line_ipv6(
        const char *line, struct vrmr_conntrack_line *connline_ptr)
{
    int result = 0;
    char source_port[16] = "", dest_port[16] = "", alt_source_port[16] = "",
         alt_dest_port[16] = "", tmp[16] = "";

    if (connline_ptr->use_acc == TRUE) {
        result = sscanf(line,
                "%15s %d %d src=%46s dst=%46s "
                "sport=%15s dport=%15s packets=%15s "
                "bytes=%15s src=%46s dst=%46s "
                "sport=%15s dport=%15s packets=%15s "
                "bytes=%15s",
                tmp, &connline_ptr->protocol, &connline_ptr->ttl,
                connline_ptr->src_ip, connline_ptr->dst_ip, source_port,
                dest_port, connline_ptr->to_dst_packets_str,
                connline_ptr->to_dst_bytes_str, connline_ptr->alt_src_ip,
                connline_ptr->alt_dst_ip, alt_source_port, alt_dest_port,
                connline_ptr->to_src_packets_str,
                connline_ptr->to_src_bytes_str);

        if (result != 15) {
            result = sscanf(line,
                    "%15s %d %d src=%46s dst=%46s "
                    "sport=%15s dport=%15s packets=%15s "
                    "bytes=%15s %15s src=%46s dst=%46s "
                    "sport=%15s dport=%15s packets=%15s "
                    "bytes=%15s",
                    tmp, &connline_ptr->protocol, &connline_ptr->ttl,
                    connline_ptr->src_ip, connline_ptr->dst_ip, source_port,
                    dest_port, connline_ptr->to_dst_packets_str,
                    connline_ptr->to_dst_bytes_str, connline_ptr->status,
                    connline_ptr->alt_src_ip, connline_ptr->alt_dst_ip,
                    alt_source_port, alt_dest_port,
                    connline_ptr->to_src_packets_str,
                    connline_ptr->to_src_bytes_str);
            if (result != 16) {
                vrmr_debug(NONE, "parse error: '%s', result %d", line, result);
                return (-1);
            }
        }

        strlcpy(connline_ptr->status, "UDP_ESTABLISHED",
                sizeof(connline_ptr->status));

        vrmr_debug(LOW, "to dst: %sP %sB to src: %sP %sB",
                connline_ptr->to_dst_packets_str,
                connline_ptr->to_dst_bytes_str,
                connline_ptr->to_src_packets_str,
                connline_ptr->to_src_bytes_str);
    } else {
        result = sscanf(line,
                "%15s %d %d src=%46s dst=%46s "
                "sport=%15s dport=%15s src=%46s "
                "dst=%46s sport=%15s dport=%15s",
                tmp, &connline_ptr->protocol, &connline_ptr->ttl,
                connline_ptr->src_ip, connline_ptr->dst_ip, source_port,
                dest_port, connline_ptr->alt_src_ip, connline_ptr->alt_dst_ip,
                alt_source_port, alt_dest_port);
        if (result != 11) {
            result = sscanf(line,
                    "%15s %d %d src=%46s dst=%46s "
                    "sport=%15s dport=%15s %15s "
                    "src=%46s dst=%46s "
                    "sport=%15s dport=%15s",
                    tmp, &connline_ptr->protocol, &connline_ptr->ttl,
                    connline_ptr->src_ip, connline_ptr->dst_ip, source_port,
                    dest_port, connline_ptr->status, connline_ptr->alt_src_ip,
                    connline_ptr->alt_dst_ip, alt_source_port, alt_dest_port);
            if (result != 12) {
                vrmr_debug(NONE, "parse error: '%s'", line);
                return (-1);
            }
        }

        strlcpy(connline_ptr->status, "UDP_ESTABLISHED",
                sizeof(connline_ptr->status));
    }

    connline_ptr->src_port = atoi(source_port);
    if (connline_ptr->src_port <= 0 || connline_ptr->src_port > 65535)
        connline_ptr->src_port = 0;

    connline_ptr->dst_port = atoi(dest_port);
    if (connline_ptr->dst_port <= 0 || connline_ptr->dst_port > 65535)
        connline_ptr->dst_port = 0;

    connline_ptr->alt_src_port = atoi(alt_source_port);
    if (connline_ptr->alt_src_port <= 0 || connline_ptr->alt_src_port > 65535)
        connline_ptr->alt_src_port = 0;

    connline_ptr->alt_dst_port = atoi(alt_dest_port);
    if (connline_ptr->alt_dst_port <= 0 || connline_ptr->alt_dst_port > 65535)
        connline_ptr->alt_dst_port = 0;

    return (0);
}

// icmp     1 29 src=192.168.0.2 dst=194.109.6.11 type=8 code=0 id=57376
// [UNREPLIED] src=194.109.6.11 dst=192.168.0.2 type=0 code=0 id=57376 use=1
// icmp 1 30 src=192.168.1.2 dst=192.168.1.64 type=8 code=0 id=64811 packets=1
// bytes=84 [UNREPLIED] src=192.168.1.64 dst=192.168.1.2 type=0 code=0 id=64811
// packets=0 bytes=0 mark=0 use=1 icmp     1 4 src=xx.xx.xx.xx dst=194.109.21.51
// type=8 code=0 id=28193 packets=1 bytes=84 src=194.109.21.51 dst=xx.xx.xx.xx
// type=0 code=0 id=28193 packets=1 bytes=84 mark=0 secmark=0 use=2
static int parse_icmp_line(
        const char *line, struct vrmr_conntrack_line *connline_ptr)
{
    int result = 0;
    char source_port[16] = "", dest_port[16] = "", tmp[16] = "";

    if (connline_ptr->use_acc == TRUE) {
        result = sscanf(line,
                "%15s %d %d src=%15s dst=%15s "
                "type=%15s code=%15s id=%15s "
                "packets=%15s bytes=%15s %15s src=%15s "
                "dst=%15s type=%15s code=%15s id=%15s "
                "packets=%15s bytes=%15s",
                tmp, &connline_ptr->protocol, &connline_ptr->ttl,
                connline_ptr->src_ip, connline_ptr->dst_ip, source_port,
                dest_port, tmp, connline_ptr->to_dst_packets_str,
                connline_ptr->to_dst_bytes_str, connline_ptr->status,
                connline_ptr->alt_src_ip, connline_ptr->alt_dst_ip, tmp, tmp,
                tmp, connline_ptr->to_src_packets_str,
                connline_ptr->to_src_bytes_str);
        if (result != 18) {
            result = sscanf(line,
                    "%15s %d %d src=%15s dst=%15s "
                    "type=%15s code=%15s id=%15s "
                    "packets=%15s bytes=%15s src=%15s "
                    "dst=%15s type=%15s code=%15s id=%15s "
                    "packets=%15s bytes=%15s",
                    tmp, &connline_ptr->protocol, &connline_ptr->ttl,
                    connline_ptr->src_ip, connline_ptr->dst_ip, source_port,
                    dest_port, tmp, connline_ptr->to_dst_packets_str,
                    connline_ptr->to_dst_bytes_str, connline_ptr->alt_src_ip,
                    connline_ptr->alt_dst_ip, tmp, tmp, tmp,
                    connline_ptr->to_src_packets_str,
                    connline_ptr->to_src_bytes_str);
            if (result != 17) {
                vrmr_debug(NONE, "parse error: '%s'", line);
                return (-1);
            }
        }

        vrmr_debug(LOW, "to dst: %sP %sB to src: %sP %sB",
                connline_ptr->to_dst_packets_str,
                connline_ptr->to_dst_bytes_str,
                connline_ptr->to_src_packets_str,
                connline_ptr->to_src_bytes_str);
    } else {
        result = sscanf(line,
                "%15s %d %d src=%15s dst=%15s "
                "type=%15s code=%15s id=%15s %15s "
                "src=%15s dst=%15s",
                tmp, &connline_ptr->protocol, &connline_ptr->ttl,
                connline_ptr->src_ip, connline_ptr->dst_ip, source_port,
                dest_port, tmp, connline_ptr->status, connline_ptr->alt_src_ip,
                connline_ptr->alt_dst_ip);
        if (result != 11) {
            vrmr_debug(NONE, "parse error: '%s'", line);
            return (-1);
        }
    }

    connline_ptr->src_port = atoi(source_port);
    if (connline_ptr->src_port <= 0 || connline_ptr->src_port > 65535)
        connline_ptr->src_port = 0;

    connline_ptr->dst_port = atoi(dest_port);
    if (connline_ptr->dst_port <= 0 || connline_ptr->dst_port > 65535)
        connline_ptr->dst_port = 0;

    return (0);
}

static int parse_icmp_line_ipv6(
        const char *line, struct vrmr_conntrack_line *connline_ptr)
{
    int result = 0;
    char source_port[16] = "", dest_port[16] = "", tmp[16] = "";

    if (connline_ptr->use_acc == TRUE) {
        result = sscanf(line,
                "%15s %d %d src=%46s dst=%46s "
                "type=%15s code=%15s id=%15s "
                "packets=%15s bytes=%15s %15s src=%46s "
                "dst=%46s type=%15s code=%15s id=%15s "
                "packets=%15s bytes=%15s",
                tmp, &connline_ptr->protocol, &connline_ptr->ttl,
                connline_ptr->src_ip, connline_ptr->dst_ip, source_port,
                dest_port, tmp, connline_ptr->to_dst_packets_str,
                connline_ptr->to_dst_bytes_str, connline_ptr->status,
                connline_ptr->alt_src_ip, connline_ptr->alt_dst_ip, tmp, tmp,
                tmp, connline_ptr->to_src_packets_str,
                connline_ptr->to_src_bytes_str);
        if (result != 18) {
            result = sscanf(line,
                    "%15s %d %d src=%46s dst=%46s "
                    "type=%15s code=%15s id=%15s "
                    "packets=%15s bytes=%15s src=%46s "
                    "dst=%46s type=%15s code=%15s id=%15s "
                    "packets=%15s bytes=%15s",
                    tmp, &connline_ptr->protocol, &connline_ptr->ttl,
                    connline_ptr->src_ip, connline_ptr->dst_ip, source_port,
                    dest_port, tmp, connline_ptr->to_dst_packets_str,
                    connline_ptr->to_dst_bytes_str, connline_ptr->alt_src_ip,
                    connline_ptr->alt_dst_ip, tmp, tmp, tmp,
                    connline_ptr->to_src_packets_str,
                    connline_ptr->to_src_bytes_str);
            if (result != 17) {
                vrmr_debug(NONE, "parse error: '%s'", line);
                return (-1);
            }
        }

        vrmr_debug(LOW, "to dst: %sP %sB to src: %sP %sB",
                connline_ptr->to_dst_packets_str,
                connline_ptr->to_dst_bytes_str,
                connline_ptr->to_src_packets_str,
                connline_ptr->to_src_bytes_str);
    } else {
        result = sscanf(line,
                "%15s %d %d src=%46s dst=%46s "
                "type=%15s code=%15s id=%15s %15s "
                "src=%46s dst=%46s",
                tmp, &connline_ptr->protocol, &connline_ptr->ttl,
                connline_ptr->src_ip, connline_ptr->dst_ip, source_port,
                dest_port, tmp, connline_ptr->status, connline_ptr->alt_src_ip,
                connline_ptr->alt_dst_ip);
        if (result != 11) {
            result = sscanf(line,
                    "%15s %d %d src=%46s dst=%46s "
                    "type=%15s code=%15s id=%15s src=%46s dst=%46s",
                    tmp, &connline_ptr->protocol, &connline_ptr->ttl,
                    connline_ptr->src_ip, connline_ptr->dst_ip, source_port,
                    dest_port, tmp, connline_ptr->alt_src_ip,
                    connline_ptr->alt_dst_ip);
            if (result != 10) {
                vrmr_debug(NONE, "parse error: '%s'", line);
                return (-1);
            }
        }
    }

    connline_ptr->src_port = atoi(source_port);
    if (connline_ptr->src_port <= 0 || connline_ptr->src_port > 65535)
        connline_ptr->src_port = 0;

    connline_ptr->dst_port = atoi(dest_port);
    if (connline_ptr->dst_port <= 0 || connline_ptr->dst_port > 65535)
        connline_ptr->dst_port = 0;

    return (0);
}

/*
    unknown  41 585 src=<ip> dst=<ip> src=<ip> dst=<ip> use=1
    unknown  47 599 src=<ip> dst=<ip> src=<ip> dst=<ip> use=1
        unknown 41 575 src=<ip> dst=<ip> packets=6 bytes=600 [UNREPLIED]
   src=<ip> dst=<ip> packets=0 bytes=0 mark=0 use=1
*/
static int parse_unknown_line(
        const char *line, struct vrmr_conntrack_line *connline_ptr)
{
    int result = 0;
    char tmp[16] = "";

    if (connline_ptr->use_acc == TRUE) {
        result = sscanf(line,
                "%15s %d %d src=%15s dst=%15s "
                "packets=%15s bytes=%15s src=%15s "
                "dst=%15s packets=%15s bytes=%15s",
                tmp, &connline_ptr->protocol, &connline_ptr->ttl,
                connline_ptr->src_ip, connline_ptr->dst_ip,
                connline_ptr->to_dst_packets_str,
                connline_ptr->to_dst_bytes_str, connline_ptr->alt_src_ip,
                connline_ptr->alt_dst_ip, connline_ptr->to_src_packets_str,
                connline_ptr->to_src_bytes_str);
        if (result != 11) {
            result = sscanf(line,
                    "%15s %d %d src=%15s dst=%15s "
                    "packets=%15s bytes=%15s %15s src=%15s "
                    "dst=%15s packets=%15s bytes=%15s",
                    tmp, &connline_ptr->protocol, &connline_ptr->ttl,
                    connline_ptr->src_ip, connline_ptr->dst_ip,
                    connline_ptr->to_dst_packets_str,
                    connline_ptr->to_dst_bytes_str, connline_ptr->status,
                    connline_ptr->alt_src_ip, connline_ptr->alt_dst_ip,
                    connline_ptr->to_src_packets_str,
                    connline_ptr->to_src_bytes_str);
            if (result != 12) {
                vrmr_debug(NONE, "parse error: '%s'", line);
                return (-1);
            }
        }

        vrmr_debug(LOW, "to dst: %sP %sB to src: %sP %sB",
                connline_ptr->to_dst_packets_str,
                connline_ptr->to_dst_bytes_str,
                connline_ptr->to_src_packets_str,
                connline_ptr->to_src_bytes_str);
    } else {
        result = sscanf(line,
                "%15s %d %d src=%15s dst=%15s "
                "src=%15s dst=%15s",
                tmp, &connline_ptr->protocol, &connline_ptr->ttl,
                connline_ptr->src_ip, connline_ptr->dst_ip,
                connline_ptr->alt_src_ip, connline_ptr->alt_dst_ip);
        if (result != 7) {
            result = sscanf(line,
                    "%15s %d %d src=%15s dst=%15s %15s "
                    "src=%15s dst=%15s",
                    tmp, &connline_ptr->protocol, &connline_ptr->ttl,
                    connline_ptr->src_ip, connline_ptr->dst_ip,
                    connline_ptr->status, connline_ptr->alt_src_ip,
                    connline_ptr->alt_dst_ip);
            if (result != 8) {
                vrmr_debug(NONE, "parse error: '%s'", line);
                return (-1);
            }
        }
    }

    strlcpy(connline_ptr->status, "none", sizeof(connline_ptr->status));
    connline_ptr->src_port = 0;
    connline_ptr->dst_port = 0;

    return (0);
}

static int parse_unknown_line_ipv6(
        const char *line, struct vrmr_conntrack_line *connline_ptr)
{
    int result = 0;
    char tmp[16] = "";

    if (connline_ptr->use_acc == TRUE) {
        result = sscanf(line,
                "%15s %d %d src=%46s dst=%46s "
                "packets=%15s bytes=%15s src=%46s "
                "dst=%46s packets=%15s bytes=%15s",
                tmp, &connline_ptr->protocol, &connline_ptr->ttl,
                connline_ptr->src_ip, connline_ptr->dst_ip,
                connline_ptr->to_dst_packets_str,
                connline_ptr->to_dst_bytes_str, connline_ptr->alt_src_ip,
                connline_ptr->alt_dst_ip, connline_ptr->to_src_packets_str,
                connline_ptr->to_src_bytes_str);
        if (result != 11) {
            result = sscanf(line,
                    "%15s %d %d src=%46s dst=%46s "
                    "packets=%15s bytes=%15s %15s src=%46s "
                    "dst=%46s packets=%15s bytes=%15s",
                    tmp, &connline_ptr->protocol, &connline_ptr->ttl,
                    connline_ptr->src_ip, connline_ptr->dst_ip,
                    connline_ptr->to_dst_packets_str,
                    connline_ptr->to_dst_bytes_str, connline_ptr->status,
                    connline_ptr->alt_src_ip, connline_ptr->alt_dst_ip,
                    connline_ptr->to_src_packets_str,
                    connline_ptr->to_src_bytes_str);
            if (result != 12) {
                vrmr_debug(NONE, "parse error: '%s'", line);
                return (-1);
            }
        }

        vrmr_debug(LOW, "to dst: %sP %sB to src: %sP %sB",
                connline_ptr->to_dst_packets_str,
                connline_ptr->to_dst_bytes_str,
                connline_ptr->to_src_packets_str,
                connline_ptr->to_src_bytes_str);
    } else {
        result = sscanf(line,
                "%15s %d %d src=%46s dst=%46s "
                "src=%46s dst=%46s",
                tmp, &connline_ptr->protocol, &connline_ptr->ttl,
                connline_ptr->src_ip, connline_ptr->dst_ip,
                connline_ptr->alt_src_ip, connline_ptr->alt_dst_ip);
        if (result != 7) {
            result = sscanf(line,
                    "%15s %d %d src=%46s dst=%46s %15s "
                    "src=%46s dst=%46s",
                    tmp, &connline_ptr->protocol, &connline_ptr->ttl,
                    connline_ptr->src_ip, connline_ptr->dst_ip,
                    connline_ptr->status, connline_ptr->alt_src_ip,
                    connline_ptr->alt_dst_ip);
            if (result != 8) {
                vrmr_debug(NONE, "parse error: '%s'", line);
                return (-1);
            }
        }
    }

    strlcpy(connline_ptr->status, "none", sizeof(connline_ptr->status));
    connline_ptr->src_port = 0;
    connline_ptr->dst_port = 0;

    return (0);
}

/*  process one line from the conntrack file */
static int conn_process_one_conntrack_line_ipv6(
        const char *line, struct vrmr_conntrack_line *connline_ptr)
{
    char protocol[16] = "";

    /* check if we need to read packets as well */
    if (strstr(line, "packets"))
        connline_ptr->use_acc = TRUE;
    else
        connline_ptr->use_acc = FALSE;

    connline_ptr->ipv6 = 1;

    /* first determine protocol */
    sscanf(line, "%s", protocol);
    vrmr_debug(LOW, "protocol %s", protocol);

    if (strcmp(protocol, "tcp") == 0) {
        if (parse_tcp_line_ipv6(line, connline_ptr) < 0)
            return (0);
    } else if (strcmp(protocol, "udp") == 0) {
        if (parse_udp_line_ipv6(line, connline_ptr) < 0)
            return (0);
    } else if (strcmp(protocol, "icmpv6") == 0) {
        if (parse_icmp_line_ipv6(line, connline_ptr) < 0)
            return (0);
    } else if (strcmp(protocol, "unknown") == 0) {
        if (parse_unknown_line_ipv6(line, connline_ptr) < 0)
            return (0);
    } else {
        strcpy(connline_ptr->status, "none");
        connline_ptr->protocol = 0;
        strcpy(connline_ptr->src_ip, "PARSE-ERROR");
        strcpy(connline_ptr->dst_ip, "PARSE-ERROR");
        connline_ptr->src_port = 0;
        connline_ptr->dst_port = 0;
    }

    /* now, for snat and dnat some magic is required */
    if (strcmp(connline_ptr->src_ip, connline_ptr->alt_dst_ip) == 0 &&
            strcmp(connline_ptr->dst_ip, connline_ptr->alt_src_ip) == 0) {
        /* normal line */
    } else if (strcmp(connline_ptr->src_ip, connline_ptr->alt_dst_ip) == 0) {
        /* store the original dst_ip as orig_dst_ip */
        if (strlcpy(connline_ptr->orig_dst_ip, connline_ptr->dst_ip,
                    sizeof(connline_ptr->orig_dst_ip)) >=
                sizeof(connline_ptr->orig_dst_ip)) {
            vrmr_error(-1, "Internal Error", "string overflow");
            return (-1);
        }
        /* DNAT, we use alt_source_ip as dest */
        if (strlcpy(connline_ptr->dst_ip, connline_ptr->alt_src_ip,
                    sizeof(connline_ptr->dst_ip)) >=
                sizeof(connline_ptr->dst_ip)) {
            vrmr_error(-1, "Internal Error", "string overflow");
            return (-1);
        }
    } else if (strcmp(connline_ptr->src_ip, connline_ptr->alt_src_ip) != 0 &&
               strcmp(connline_ptr->dst_ip, connline_ptr->alt_dst_ip) != 0) {
        /* store the original dst_ip as orig_dst_ip */
        if (strlcpy(connline_ptr->orig_dst_ip, connline_ptr->dst_ip,
                    sizeof(connline_ptr->orig_dst_ip)) >=
                sizeof(connline_ptr->orig_dst_ip)) {
            vrmr_error(-1, "Internal Error", "string overflow");
            return (-1);
        }
        /* DNAT, we use alt_source_ip as dest */
        if (strlcpy(connline_ptr->dst_ip, connline_ptr->alt_src_ip,
                    sizeof(connline_ptr->dst_ip)) >=
                sizeof(connline_ptr->dst_ip)) {
            vrmr_error(-1, "Internal Error", "string overflow");
            return (-1);
        }
    }
    /*
        portfw rule

        tcp      6 431950 ESTABLISHED
                    src=192.168.166.2 dst=192.168.166.10
                    sport=1241 dport=80 packets=3 bytes=128
                    src=192.168.166.9 dst=192.168.166.10
                    sport=22 dport=1241 packets=2 bytes=123
                        [ASSURED] mark=0 use=1

        firewall    192.168.166.10
        target      192.168.166.9
        source      192.168.166.2

        We see that dst = alt_dst and src != alt_src.
    */
    else if (strcmp(connline_ptr->src_ip, connline_ptr->alt_src_ip) != 0 &&
             strcmp(connline_ptr->dst_ip, connline_ptr->alt_dst_ip) == 0) {
        /* store the original dst_ip as orig_dst_ip */
        if (strlcpy(connline_ptr->orig_dst_ip, connline_ptr->dst_ip,
                    sizeof(connline_ptr->orig_dst_ip)) >=
                sizeof(connline_ptr->orig_dst_ip)) {
            vrmr_error(-1, "Internal Error", "string overflow");
            return (-1);
        }
        /* DNAT, we use alt_source_ip as dest */
        if (strlcpy(connline_ptr->dst_ip, connline_ptr->alt_src_ip,
                    sizeof(connline_ptr->dst_ip)) >=
                sizeof(connline_ptr->dst_ip)) {
            vrmr_error(-1, "Internal Error", "string overflow");
            return (-1);
        }
    }

    /* process status */
    if (strcmp(connline_ptr->status, "none") == 0)
        connline_ptr->state = VRMR_STATE_NONE;
    else if (strcmp(connline_ptr->status, "ESTABLISHED") == 0)
        connline_ptr->state = VRMR_STATE_TCP_ESTABLISHED;
    else if (strcmp(connline_ptr->status, "UDP_ESTABLISHED") == 0)
        connline_ptr->state = VRMR_STATE_UDP_ESTABLISHED;
    else if (strcmp(connline_ptr->status, "SYN_SENT") == 0)
        connline_ptr->state = VRMR_STATE_SYN_SENT;
    else if (strcmp(connline_ptr->status, "SYN_RECV") == 0)
        connline_ptr->state = VRMR_STATE_SYN_RECV;
    else if (strcmp(connline_ptr->status, "FIN_WAIT") == 0)
        connline_ptr->state = VRMR_STATE_FIN_WAIT;
    else if (strcmp(connline_ptr->status, "TIME_WAIT") == 0)
        connline_ptr->state = VRMR_STATE_TIME_WAIT;
    else if (strcmp(connline_ptr->status, "CLOSE") == 0)
        connline_ptr->state = VRMR_STATE_CLOSE;
    else if (strcmp(connline_ptr->status, "CLOSE_WAIT") == 0)
        connline_ptr->state = VRMR_STATE_CLOSE_WAIT;
    else if (strcmp(connline_ptr->status, "LAST_ACK") == 0)
        connline_ptr->state = VRMR_STATE_LAST_ACK;
    else if (strcmp(connline_ptr->status, "[UNREPLIED]") == 0)
        connline_ptr->state = VRMR_STATE_UNREPLIED;
    else
        connline_ptr->state = VRMR_STATE_UNDEFINED;

    if (connline_ptr->use_acc == TRUE) {
        connline_ptr->to_src_packets =
                strtoull(connline_ptr->to_src_packets_str, NULL, 10);
        connline_ptr->to_src_bytes =
                strtoull(connline_ptr->to_src_bytes_str, NULL, 10);
        connline_ptr->to_dst_packets =
                strtoull(connline_ptr->to_dst_packets_str, NULL, 10);
        connline_ptr->to_dst_bytes =
                strtoull(connline_ptr->to_dst_bytes_str, NULL, 10);
    }

    return (1);
}

/*  process one line from the conntrack file */
static int conn_process_one_conntrack_line(
        const char *line, struct vrmr_conntrack_line *connline_ptr)
{
    char protocol[16] = "";

    /* check if we need to read packets as well */
    if (strstr(line, "packets"))
        connline_ptr->use_acc = TRUE;
    else
        connline_ptr->use_acc = FALSE;

    /* first determine protocol */
    sscanf(line, "%s", protocol);
    vrmr_debug(LOW, "protocol %s", protocol);

    if (strcmp(protocol, "tcp") == 0) {
        if (parse_tcp_line(line, connline_ptr) < 0)
            return (0);
    } else if (strcmp(protocol, "udp") == 0) {
        if (parse_udp_line(line, connline_ptr) < 0)
            return (0);
    } else if (strcmp(protocol, "icmp") == 0) {
        if (parse_icmp_line(line, connline_ptr) < 0)
            return (0);
    } else if (strcmp(protocol, "unknown") == 0) {
        if (parse_unknown_line(line, connline_ptr) < 0)
            return (0);
    } else if (strcmp(protocol, "ipv4") == 0) {
        /* with nf_conntrack in some configurations we have
         * to deal with lines starting with 'ipv4    2'
         * Here we get a pointer, point it beyond that, and
         * pass the result to this same function again...
         * Ugly, yeah... the whole parsing could use a big
         * rewrite... */
        size_t i = 0;
        char *ptr = (char *)line + 4; /* set past 'ipv4'*/

        /* look for next alpha char since we expect 'tcp', 'udp', etc */
        while ((!isalpha(ptr[i]) && i < strlen(ptr)))
            i++;

        /* set ptr past the nf_conntrack prepend */
        ptr += i;

        return (conn_process_one_conntrack_line(ptr, connline_ptr));
    } else if (strcmp(protocol, "ipv6") == 0) {
        /* with nf_conntrack in some configurations we have
         * to deal with lines starting with 'ipv4    2'
         * Here we get a pointer, point it beyond that, and
         * pass the result to this same function again...
         * Ugly, yeah... the whole parsing could use a big
         * rewrite... */
        size_t i = 0;
        char *ptr = (char *)line + 4; /* set past 'ipv4'*/

        /* look for next alpha char since we expect 'tcp', 'udp', etc */
        while ((!isalpha(ptr[i]) && i < strlen(ptr)))
            i++;

        /* set ptr past the nf_conntrack prepend */
        ptr += i;

        return (conn_process_one_conntrack_line_ipv6(ptr, connline_ptr));
    } else {
        strcpy(connline_ptr->status, "none");
        connline_ptr->protocol = 0;
        strcpy(connline_ptr->src_ip, "PARSE-ERROR");
        strcpy(connline_ptr->dst_ip, "PARSE-ERROR");
        connline_ptr->src_port = 0;
        connline_ptr->dst_port = 0;
    }

    /* now, for snat and dnat some magic is required */
    if (strcmp(connline_ptr->src_ip, connline_ptr->alt_dst_ip) == 0 &&
            strcmp(connline_ptr->dst_ip, connline_ptr->alt_src_ip) == 0) {
        /* normal line */
    } else if (strcmp(connline_ptr->src_ip, connline_ptr->alt_dst_ip) == 0) {
        /* store the original dst_ip as orig_dst_ip */
        if (strlcpy(connline_ptr->orig_dst_ip, connline_ptr->dst_ip,
                    sizeof(connline_ptr->orig_dst_ip)) >=
                sizeof(connline_ptr->orig_dst_ip)) {
            vrmr_error(-1, "Internal Error", "string overflow");
            return (-1);
        }
        /* DNAT, we use alt_source_ip as dest */
        if (strlcpy(connline_ptr->dst_ip, connline_ptr->alt_src_ip,
                    sizeof(connline_ptr->dst_ip)) >=
                sizeof(connline_ptr->dst_ip)) {
            vrmr_error(-1, "Internal Error", "string overflow");
            return (-1);
        }
    } else if (strcmp(connline_ptr->src_ip, connline_ptr->alt_src_ip) != 0 &&
               strcmp(connline_ptr->dst_ip, connline_ptr->alt_dst_ip) != 0) {
        /* store the original dst_ip as orig_dst_ip */
        if (strlcpy(connline_ptr->orig_dst_ip, connline_ptr->dst_ip,
                    sizeof(connline_ptr->orig_dst_ip)) >=
                sizeof(connline_ptr->orig_dst_ip)) {
            vrmr_error(-1, "Internal Error", "string overflow");
            return (-1);
        }
        /* DNAT, we use alt_source_ip as dest */
        if (strlcpy(connline_ptr->dst_ip, connline_ptr->alt_src_ip,
                    sizeof(connline_ptr->dst_ip)) >=
                sizeof(connline_ptr->dst_ip)) {
            vrmr_error(-1, "Internal Error", "string overflow");
            return (-1);
        }
    }
    /*
        portfw rule

        tcp      6 431950 ESTABLISHED
                    src=192.168.166.2 dst=192.168.166.10
                    sport=1241 dport=80 packets=3 bytes=128
                    src=192.168.166.9 dst=192.168.166.10
                    sport=22 dport=1241 packets=2 bytes=123
                        [ASSURED] mark=0 use=1

        firewall    192.168.166.10
        target      192.168.166.9
        source      192.168.166.2

        We see that dst = alt_dst and src != alt_src.
    */
    else if (strcmp(connline_ptr->src_ip, connline_ptr->alt_src_ip) != 0 &&
             strcmp(connline_ptr->dst_ip, connline_ptr->alt_dst_ip) == 0) {
        /* store the original dst_ip as orig_dst_ip */
        if (strlcpy(connline_ptr->orig_dst_ip, connline_ptr->dst_ip,
                    sizeof(connline_ptr->orig_dst_ip)) >=
                sizeof(connline_ptr->orig_dst_ip)) {
            vrmr_error(-1, "Internal Error", "string overflow");
            return (-1);
        }
        /* DNAT, we use alt_source_ip as dest */
        if (strlcpy(connline_ptr->dst_ip, connline_ptr->alt_src_ip,
                    sizeof(connline_ptr->dst_ip)) >=
                sizeof(connline_ptr->dst_ip)) {
            vrmr_error(-1, "Internal Error", "string overflow");
            return (-1);
        }
    }

    /* process status */
    if (strcmp(connline_ptr->status, "none") == 0)
        connline_ptr->state = VRMR_STATE_NONE;
    else if (strcmp(connline_ptr->status, "ESTABLISHED") == 0)
        connline_ptr->state = VRMR_STATE_TCP_ESTABLISHED;
    else if (strcmp(connline_ptr->status, "UDP_ESTABLISHED") == 0)
        connline_ptr->state = VRMR_STATE_UDP_ESTABLISHED;
    else if (strcmp(connline_ptr->status, "SYN_SENT") == 0)
        connline_ptr->state = VRMR_STATE_SYN_SENT;
    else if (strcmp(connline_ptr->status, "SYN_RECV") == 0)
        connline_ptr->state = VRMR_STATE_SYN_RECV;
    else if (strcmp(connline_ptr->status, "FIN_WAIT") == 0)
        connline_ptr->state = VRMR_STATE_FIN_WAIT;
    else if (strcmp(connline_ptr->status, "TIME_WAIT") == 0)
        connline_ptr->state = VRMR_STATE_TIME_WAIT;
    else if (strcmp(connline_ptr->status, "CLOSE") == 0)
        connline_ptr->state = VRMR_STATE_CLOSE;
    else if (strcmp(connline_ptr->status, "CLOSE_WAIT") == 0)
        connline_ptr->state = VRMR_STATE_CLOSE_WAIT;
    else if (strcmp(connline_ptr->status, "LAST_ACK") == 0)
        connline_ptr->state = VRMR_STATE_LAST_ACK;
    else if (strcmp(connline_ptr->status, "[UNREPLIED]") == 0)
        connline_ptr->state = VRMR_STATE_UNREPLIED;
    else
        connline_ptr->state = VRMR_STATE_UNDEFINED;

    if (connline_ptr->use_acc == TRUE) {
        connline_ptr->to_src_packets =
                strtoull(connline_ptr->to_src_packets_str, NULL, 10);
        connline_ptr->to_src_bytes =
                strtoull(connline_ptr->to_src_bytes_str, NULL, 10);
        connline_ptr->to_dst_packets =
                strtoull(connline_ptr->to_dst_packets_str, NULL, 10);
        connline_ptr->to_dst_bytes =
                strtoull(connline_ptr->to_dst_bytes_str, NULL, 10);
    }

    return (1);
}

/*  vrmr_conn_hash_name

    Very simple string hashing function. It just adds up
    all chars.
*/
unsigned int vrmr_conn_hash_name(const void *key)
{
    unsigned int hash = 0;

    assert(key);

    char *name = (char *)key;

    size_t len = strlen(name);
    while (len) {
        hash = hash + name[len];
        len--;
    }

    return (hash);
}

// TODO silly names
int vrmr_conn_match_name(const void *ser1, const void *ser2)
{
    assert(ser1 && ser2);

    if (strcmp((char *)ser1, (char *)ser2) == 0)
        return 1;
    else
        return 0;
}

//- print_list -
void vrmr_conn_list_print(const struct vrmr_list *conn_list)
{
    struct vrmr_list_node *d_node = NULL;
    struct vrmr_conntrack_entry *item_ptr = NULL;

    // Display the linked list.
    fprintf(stdout, "List len is %u\n", conn_list->len);

    for (d_node = conn_list->top; d_node; d_node = d_node->next) {
        item_ptr = d_node->data;

        fprintf(stdout, "sername: %s, fromname: %s, toname: %s\n",
                item_ptr->sername, item_ptr->fromname, item_ptr->toname);
    }

    return;
}

/*  hash_conntrackdata

    Hashes conntrackdata. It does this by creating seperate
    hashes for sername, fromname and toname.

    Returns the hash.
*/
static unsigned int conn_hash_conntrackdata(const void *key)
{
    assert(key);

    struct vrmr_conntrack_entry *cd_ptr = (struct vrmr_conntrack_entry *)key;

    /*  from and to have different weight, so firewall -> internet
        is not the same as internet -> firewall
    */
    unsigned int retval = vrmr_conn_hash_name(cd_ptr->sername);
    retval = retval + vrmr_conn_hash_name(cd_ptr->fromname) / 2;
    retval = retval + vrmr_conn_hash_name(cd_ptr->toname) / 3;
    return (retval);
}

/*  match_conntrackdata

*/
static int conn_match_conntrackdata(const void *check, const void *hash)
{
    assert(check && hash);

    struct vrmr_conntrack_entry *check_cd =
            (struct vrmr_conntrack_entry *)check;
    struct vrmr_conntrack_entry *hash_cd = (struct vrmr_conntrack_entry *)hash;

    if (strncmp(check_cd->sername, hash_cd->sername, VRMR_MAX_SERVICE) == 0) {
        // service matches
        if (strncmp(check_cd->fromname, hash_cd->fromname,
                    VRMR_VRMR_MAX_HOST_NET_ZONE) == 0) {
            // from host also matches
            if (strncmp(check_cd->toname, hash_cd->toname,
                        VRMR_VRMR_MAX_HOST_NET_ZONE) == 0) {
                if (check_cd->connect_status == hash_cd->connect_status) {
                    // they all match-> return 1
                    return (1);
                }
            }
        }
    }

    // sorry, no match
    return (0);
}

/*  conn_dlist_destroy

    Destroys the list.
*/
void vrmr_conn_list_cleanup(struct vrmr_list *conn_dlist)
{
    struct vrmr_list_node *d_node = NULL;
    struct vrmr_conntrack_entry *cd_ptr = NULL;

    for (d_node = conn_dlist->top; d_node; d_node = d_node->next) {
        cd_ptr = d_node->data;

        if (cd_ptr->from == NULL)
            free(cd_ptr->fromname);
        if (cd_ptr->to == NULL)
            free(cd_ptr->toname);
        if (cd_ptr->service == NULL)
            free(cd_ptr->sername);

        free(cd_ptr);
    }

    vrmr_list_cleanup(conn_dlist);
}

static void update_stats(const struct vrmr_conntrack_entry *ce,
        struct vrmr_conntrack_stats *connstat_ptr)
{
    assert(ce);
    assert(connstat_ptr);

    connstat_ptr->conn_total++;

    if (ce->from != NULL && ce->from->type == VRMR_TYPE_FIREWALL)
        connstat_ptr->conn_out++;
    else if (ce->to != NULL && ce->to->type == VRMR_TYPE_FIREWALL)
        connstat_ptr->conn_in++;
    else
        connstat_ptr->conn_fw++;

    if (ce->connect_status == VRMR_CONN_CONNECTING)
        connstat_ptr->stat_connect++;
    else if (ce->connect_status == VRMR_CONN_DISCONNECTING)
        connstat_ptr->stat_closing++;
    else if (ce->connect_status == VRMR_CONN_CONNECTED)
        connstat_ptr->stat_estab++;
    else
        connstat_ptr->stat_other++;

    if (strlen(ce->sername) > connstat_ptr->sername_max)
        connstat_ptr->sername_max = strlen(ce->sername);
    if (strlen(ce->fromname) > connstat_ptr->fromname_max)
        connstat_ptr->fromname_max = strlen(ce->fromname);
    if (strlen(ce->toname) > connstat_ptr->toname_max)
        connstat_ptr->toname_max = strlen(ce->toname);

    if (ce->use_acc == 1)
        connstat_ptr->accounting = 1;
}

/*  vrmr_conn_get_connections

    Assembles all conntrack connections in one list, and counts all items.

    prev_conn_cnt is used to determine the size of the hashtable which is
    used. It is based on the size of the list of the last time we ran this
    function. If it is zero, we use a default.

    TODO:   intergrate with get stats
        group results on:   network when unknown host - done
                                fw, in, out
                                connected, connecting, disconnecting

        make sorting better by check if current cd is bigger than
        the top 3

    Do this by the way we create a hash, so set the options into the
    cd struct
*/
static int vrmr_conn_get_connections_do(struct vrmr_config *cnf,
        struct vrmr_hash_table *serv_hash, struct vrmr_hash_table *zone_hash,
        struct vrmr_list *conn_dlist, struct vrmr_hash_table *conn_hash,
        struct vrmr_list *zone_list, struct vrmr_conntrack_request *req,
        struct vrmr_conntrack_stats *connstat_ptr, int ipver)
{
    int retval = 0;

    char line[1024] = "";
    FILE *fp = NULL;

    char tmpfile[] = "/tmp/vuurmuur-conntrack-XXXXXX";
    int conntrack_cmd = 0;

    assert(serv_hash && zone_hash && cnf);

    if (ipver != 0) {
        conntrack_cmd = 1;

        /* create the tempfile */
        int fd = vrmr_create_tempfile(tmpfile);
        if (fd == -1)
            return (-1);
        else
            close(fd);

        char *outputs[] = {tmpfile, "/dev/null", NULL};
        if (ipver == VRMR_IPV4) {
            char *args[] = {cnf->conntrack_location, "-L", "-f", "ipv4", NULL};
            int result = libvuurmuur_exec_command(
                    cnf, cnf->conntrack_location, args, outputs);
            if (result == -1) {
                vrmr_error(-1, "Error", "unable to execute conntrack: %s",
                        strerror(errno));
                return (-1);
            }
        } else {
            char *args[] = {cnf->conntrack_location, "-L", "-f", "ipv6", NULL};
            int result = libvuurmuur_exec_command(
                    cnf, cnf->conntrack_location, args, outputs);
            if (result == -1) {
                vrmr_error(-1, "Error", "unable to execute conntrack: %s",
                        strerror(errno));
                return (-1);
            }
        }

        fp = fopen(tmpfile, "r");
        if (fp == NULL) {
            vrmr_error(-1, "Error", "unable to open proc conntrack: %s",
                    strerror(errno));
            return (-1);
        }
    }
    /* open conntrack file (fopen)... default to nf_conntrack */
    if (fp == NULL) {
        /* shortcut to ipconntrack for repeated calls */
        if (cnf->use_ipconntrack == TRUE) {
            fp = fopen(VRMR_PROC_IPCONNTRACK, "r");
        }
        if (fp == NULL) {
            fp = fopen(VRMR_PROC_NFCONNTRACK, "r");
            if (fp == NULL) {
                fp = fopen(VRMR_PROC_IPCONNTRACK, "r");
                if (fp != NULL) {
                    cnf->use_ipconntrack = TRUE;
                }
            }
        }
    }
    if (fp == NULL) {
        vrmr_error(-1, "Error", "unable to open proc conntrack: %s",
                strerror(errno));
        return (-1);
    }

    while ((fgets(line, (int)sizeof(line), fp) != NULL)) {
        struct vrmr_conntrack_line cl;
        /* start with a clean slate */
        memset(&cl, 0, sizeof(cl));

        /* parse the line */
        int r;
        if (ipver == 0 || ipver == VRMR_IPV4)
            r = conn_process_one_conntrack_line(line, &cl);
        else
            r = conn_process_one_conntrack_line_ipv6(line, &cl);
        if (r < 0) {
            vrmr_error(-1, "Internal Error",
                    "conn_process_one_conntrack_line() failed");
            retval = -1;
            goto end;
        } else if (r == 0) {
            /* invalid line */
            continue;
        }

        /* allocate memory for the data */
        struct vrmr_conntrack_entry *cd_ptr = NULL;
        if (!(cd_ptr = (struct vrmr_conntrack_entry *)calloc(
                      1, sizeof(struct vrmr_conntrack_entry)))) {
            vrmr_error(-1, "Error", "calloc() failed: %s", strerror(errno));
            retval = -1;
            goto end;
        }

        /* analyse it */
        if (conn_line_to_data(
                    &cl, cd_ptr, serv_hash, zone_hash, zone_list, req) < 0) {
            vrmr_error(-1, "Error", "conn_line_to_data() failed");
            free(cd_ptr);
            retval = -1;
            goto end;
        }

        /*  we ignore the local loopback connections
            and connections that are filtered */
        if ((strncmp(cd_ptr->fromname, "127.", 4) == 0 ||
                    strncmp(cd_ptr->toname, "127.", 4) == 0 ||
                    (req->use_filter == TRUE &&
                            filtered_connection(cd_ptr, &req->filter) == 1))) {
            free_conntrack_entry(cd_ptr);
            continue;
        }

        /* update counters */
        update_stats(cd_ptr, connstat_ptr);

        /* now check if the cd is already in the list */
        struct vrmr_conntrack_entry *found = NULL;
        if (req->group_conns == TRUE &&
                (found = vrmr_hash_search(conn_hash, (void *)cd_ptr)) != NULL) {
            /*  FOUND in the hash. Transfer the acc data */
            found->to_src_packets += cd_ptr->to_src_packets;
            found->to_src_bytes += cd_ptr->to_src_bytes;
            found->to_dst_packets += cd_ptr->to_dst_packets;
            found->to_dst_bytes += cd_ptr->to_dst_bytes;
            found->cnt++;

            free_conntrack_entry(cd_ptr);
        } else {
            /*  NOT found in the hash */

            /* append the new cd to the list */
            if (vrmr_list_append(conn_dlist, cd_ptr) == NULL) {
                vrmr_error(-1, "Internal Error", "unable to append into list");
                retval = -1;
                goto end;
            }

            /* and insert it into the hash */
            if (vrmr_hash_insert(conn_hash, cd_ptr) != 0) {
                vrmr_error(-1, "Internal Error", "unable to insert into hash");
                retval = -1;
                goto end;
            }

            cd_ptr->cnt = 1;
        }
    }

end:
    /* close the file */
    if (fclose(fp) < 0)
        retval = -1;

    if (conntrack_cmd) {
        /* remove the file */
        if (unlink(tmpfile) == -1) {
            vrmr_error(-1, "Error", "removing '%s' failed (unlink): %s",
                    tmpfile, strerror(errno));
            retval = -1;
        }
    }
    return (retval);
}

static int vrmr_conn_get_connections_cmd(struct vrmr_config *cnf,
        struct vrmr_hash_table *serv_hash, struct vrmr_hash_table *zone_hash,
        struct vrmr_list *conn_dlist, struct vrmr_hash_table *conn_hash,
        struct vrmr_list *zone_list, struct vrmr_conntrack_request *req,
        struct vrmr_conntrack_stats *connstat_ptr, int ipver)
{
    return vrmr_conn_get_connections_do(cnf, serv_hash, zone_hash, conn_dlist,
            conn_hash, zone_list, req, connstat_ptr, ipver);
}

static int vrmr_conn_get_connections_proc(struct vrmr_config *cnf,
        struct vrmr_hash_table *serv_hash, struct vrmr_hash_table *zone_hash,
        struct vrmr_list *conn_dlist, struct vrmr_hash_table *conn_hash,
        struct vrmr_list *zone_list, struct vrmr_conntrack_request *req,
        struct vrmr_conntrack_stats *connstat_ptr)
{
    return vrmr_conn_get_connections_do(cnf, serv_hash, zone_hash, conn_dlist,
            conn_hash, zone_list, req, connstat_ptr, 0);
}

void vrmr_connreq_setup(struct vrmr_conntrack_request *connreq)
{
    assert(connreq);

    vrmr_filter_setup(&connreq->filter);

    memset(connreq, 0, sizeof(struct vrmr_conntrack_request));
}

void vrmr_connreq_cleanup(struct vrmr_conntrack_request *connreq)
{
    assert(connreq);

    vrmr_filter_cleanup(&connreq->filter);

    memset(connreq, 0, sizeof(struct vrmr_conntrack_request));
}

#ifdef HAVE_LIBNETFILTER_CONNTRACK
#include <libmnl/libmnl.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#include <assert.h>
#include <inttypes.h>
#include <sys/time.h>
#include <linux/netfilter/nf_conntrack_tcp.h>

struct vrmr_conntrack_api_entry {
    uint32_t status;
    uint8_t family;
    uint8_t protocol;
    uint16_t sp;
    uint16_t alt_sp;
    uint16_t dp;
    uint16_t alt_dp;
    uint32_t nfmark;
    uint32_t age_s; /**< age in seconds */

    uint8_t tcp_state;
    uint8_t tcp_flags_ts;
    uint8_t tcp_flags_tc;

    char src_ip[46];
    char dst_ip[46];
    char orig_dst_ip[46];

    uint64_t toserver_packets;
    uint64_t toserver_bytes;
    uint64_t toclient_packets;
    uint64_t toclient_bytes;
};

/*
    This function analyzes the api entry supplied through the 'ae' ptr.
    It should never fail, unless we have a serious problem: malloc failure
    or parameter problems.

    Returncodes:
         0: ok
        -1: (serious) error
*/
static int conn_data_to_entry(const struct vrmr_conntrack_api_entry *cae,
        struct vrmr_conntrack_entry *ce, struct vrmr_hash_table *serhash,
        struct vrmr_hash_table *zonehash, struct vrmr_list *zonelist,
        struct vrmr_conntrack_request *req)
{
    char service_name[VRMR_MAX_SERVICE] = "", *zone_name_ptr = NULL;

    assert(cae && ce && serhash && zonehash && req);

    if (req->unknown_ip_as_net && zonelist == NULL) {
        vrmr_error(-1, "Internal Error", "parameter problem");
        return (-1);
    }

    ce->ipv6 = (cae->family == AF_INET6);

    /* first the service name */
    ce->service = vrmr_search_service_in_hash(
            cae->sp, cae->dp, cae->protocol, serhash);
    if (ce->service == NULL) {
        /* do a reverse lookup. This will prevent connections that
         * have been picked up by conntrack midstream to look
         * unrecognized  */
        if ((ce->service = vrmr_search_service_in_hash(
                     cae->dp, cae->sp, cae->protocol, serhash)) == NULL) {
            if (cae->protocol == 6 || cae->protocol == 17)
                snprintf(service_name, sizeof(service_name), "%d -> %d",
                        cae->sp, cae->dp);
            else if (cae->protocol == 1)
                snprintf(service_name, sizeof(service_name), "%d:%d", cae->sp,
                        cae->dp);
            else
                snprintf(service_name, sizeof(service_name), "proto %d",
                        cae->protocol);

            if (!(ce->sername = strdup(service_name))) {
                vrmr_error(-1, "Error", "strdup() failed: %s", strerror(errno));
                return (-1);
            }
        } else {
            /* found! */
            ce->sername = ce->service->name;
        }
    } else {
        ce->sername = ce->service->name;
    }

    /* for hashing and display */

    /* if the dst port and alt_dst_port don't match, it is
        a portfw rule with the remoteport option set. */
    if (cae->dp == cae->alt_sp)
        ce->dst_port = cae->dp;
    else
        ce->dst_port = cae->alt_sp;

    ce->protocol = cae->protocol;
    ce->src_port = cae->sp;

    /* src ip */
    if (strlcpy(ce->src_ip, cae->src_ip, sizeof(ce->src_ip)) >=
            sizeof(ce->src_ip)) {
        vrmr_error(-1, "Internal Error", "string overflow");
        return (-1);
    }

    /* then the from name */
    if (!(ce->ipv6))
        ce->from = vrmr_search_zone_in_hash_with_ipv4(ce->src_ip, zonehash);
    if (ce->from == NULL) {
        vrmr_debug(HIGH, "unknown ip: '%s'.", ce->src_ip);

        if (req->unknown_ip_as_net == FALSE) {
            if (!(ce->fromname = strdup(ce->src_ip))) {
                vrmr_error(-1, "Error",
                        "strdup() "
                        "failed: %s",
                        strerror(errno));
                return (-1);
            }
        } else {
            if (!(zone_name_ptr = vrmr_get_network_for_ipv4(
                          ce->src_ip, zonelist))) {
                if (!(ce->fromname = strdup(ce->src_ip))) {
                    vrmr_error(-1, "Internal Error", "malloc failed: %s",
                            strerror(errno));
                    return (-1);
                }
            } else {
                if (!(ce->fromname = strdup(zone_name_ptr))) {
                    vrmr_error(-1, "Internal Error", "strdup failed: %s",
                            strerror(errno));
                    free(zone_name_ptr);
                    return (-1);
                }

                free(zone_name_ptr);
            }
        }
    } else {
        ce->fromname = ce->from->name;
    }

    /* dst ip */
    strlcpy(ce->dst_ip, cae->dst_ip, sizeof(ce->dst_ip));
    /* dst ip */
    strlcpy(ce->orig_dst_ip, cae->orig_dst_ip, sizeof(ce->orig_dst_ip));
    /* then the to name */
    if (!(ce->ipv6))
        ce->to = vrmr_search_zone_in_hash_with_ipv4(ce->dst_ip, zonehash);
    if (ce->to == NULL) {
        if (req->unknown_ip_as_net == FALSE) {
            if (!(ce->toname = strdup(ce->dst_ip))) {
                vrmr_error(-1, "Internal Error", "strdup failed: %s",
                        strerror(errno));
                return (-1);
            }
        } else {
            if (!(zone_name_ptr = vrmr_get_network_for_ipv4(
                          ce->dst_ip, zonelist))) {
                if (!(ce->toname = strdup(ce->dst_ip))) {
                    vrmr_error(-1, "Internal Error", "strdup failed: %s",
                            strerror(errno));
                    return (-1);
                }
            } else {
                if (!(ce->toname = strdup(zone_name_ptr))) {
                    vrmr_error(-1, "Internal Error", "strdup failed: %s",
                            strerror(errno));

                    free(zone_name_ptr);
                    return (-1);
                }

                free(zone_name_ptr);
            }
        }
    } else {
        ce->toname = ce->to->name;
    }

    vrmr_debug(NONE, "status cae->status %u", cae->status);

    if ((cae->status & IPS_SEEN_REPLY) == 0) {
        ce->connect_status = VRMR_CONN_CONNECTING;
    } else {
        switch (cae->tcp_state) {
            case TCP_CONNTRACK_SYN_SENT:
            case TCP_CONNTRACK_SYN_SENT2:
            case TCP_CONNTRACK_SYN_RECV:
            case TCP_CONNTRACK_NONE:
                ce->connect_status = VRMR_CONN_CONNECTING;
                break;
            case TCP_CONNTRACK_ESTABLISHED:
                ce->connect_status = VRMR_CONN_CONNECTED;
                break;
            case TCP_CONNTRACK_FIN_WAIT:
            case TCP_CONNTRACK_CLOSE_WAIT:
            case TCP_CONNTRACK_LAST_ACK:
            case TCP_CONNTRACK_TIME_WAIT:
            case TCP_CONNTRACK_CLOSE:
                ce->connect_status = VRMR_CONN_DISCONNECTING;
                break;
        }
    }

    if (ce->from != NULL && ce->from->type == VRMR_TYPE_FIREWALL)
        ce->direction_status = VRMR_CONN_OUT;
    else if (ce->to != NULL && ce->to->type == VRMR_TYPE_FIREWALL)
        ce->direction_status = VRMR_CONN_IN;
    else
        ce->direction_status = VRMR_CONN_FW;

    /* transfer the acc data */
    ce->to_src_packets = cae->toclient_packets;
    ce->to_src_bytes = cae->toclient_bytes;
    ce->to_dst_packets = cae->toserver_packets;
    ce->to_dst_bytes = cae->toserver_bytes;
    ce->use_acc = (ce->to_src_packets || ce->to_dst_packets);
    return (0);
}

/**
 * \retval 1 ok
 * \retval 0 skipped
 */
int vrmr_conntrack_ct2ae(uint32_t type ATTR_UNUSED, struct nf_conntrack *ct,
        struct vrmr_conntrack_api_entry *lr)
{
    uint64_t ts_start = nfct_get_attr_u64(ct, ATTR_TIMESTAMP_START);
    uint64_t ts_stop = nfct_get_attr_u64(ct, ATTR_TIMESTAMP_STOP);
    uint64_t ts_delta = ts_stop - ts_start;
    uint32_t ts_delta_sec = ts_delta / 1000000000UL;

    lr->age_s = ts_delta_sec;

    struct nfct_attr_grp_ctrs ctrs = {0, 0};

    nfct_get_attr_grp(ct, ATTR_GRP_ORIG_COUNTERS, &ctrs);
    lr->toserver_packets = ctrs.packets;
    lr->toserver_bytes = ctrs.bytes;

    nfct_get_attr_grp(ct, ATTR_GRP_REPL_COUNTERS, &ctrs);
    lr->toclient_packets = ctrs.packets;
    lr->toclient_bytes = ctrs.bytes;

    uint8_t ipv = nfct_get_attr_u8(ct, ATTR_L3PROTO);
    switch (ipv) {
        case AF_INET: {
            uint32_t src_ip = nfct_get_attr_u32(ct, ATTR_IPV4_SRC);
            uint32_t dst_ip = nfct_get_attr_u32(ct, ATTR_IPV4_DST);
            uint32_t repl_src_ip = nfct_get_attr_u32(ct, ATTR_REPL_IPV4_SRC);
            uint32_t repl_dst_ip = nfct_get_attr_u32(ct, ATTR_REPL_IPV4_DST);

            inet_ntop(AF_INET, &src_ip, lr->src_ip, sizeof(lr->src_ip));
            inet_ntop(AF_INET, &dst_ip, lr->dst_ip, sizeof(lr->dst_ip));

            if (src_ip == repl_dst_ip && dst_ip == repl_src_ip) {
                /* normal line */
            } else if (src_ip == repl_dst_ip) {
                inet_ntop(
                        AF_INET, &repl_src_ip, lr->dst_ip, sizeof(lr->dst_ip));
                inet_ntop(AF_INET, &dst_ip, lr->orig_dst_ip,
                        sizeof(lr->orig_dst_ip));
            } else if (src_ip != repl_src_ip && dst_ip != repl_dst_ip) {
                inet_ntop(
                        AF_INET, &repl_src_ip, lr->dst_ip, sizeof(lr->dst_ip));
                inet_ntop(AF_INET, &dst_ip, lr->orig_dst_ip,
                        sizeof(lr->orig_dst_ip));
            }
            inet_ntop(AF_INET, &src_ip, lr->src_ip, sizeof(lr->src_ip));

            if (strncmp(lr->src_ip, "127.", 4) == 0)
                goto skip;
            break;
        }
        case AF_INET6: {
            struct nfct_attr_grp_ipv6 addrs;
            memset(&addrs, 0, sizeof(addrs));
            nfct_get_attr_grp(ct, ATTR_GRP_ORIG_IPV6, &addrs);

            inet_ntop(AF_INET6, &addrs.src, lr->src_ip, sizeof(lr->src_ip));
            inet_ntop(AF_INET6, &addrs.dst, lr->dst_ip, sizeof(lr->dst_ip));
            break;
        }
        default:
            abort();
    }
    lr->family = ipv;

    lr->protocol = nfct_get_attr_u8(ct, ATTR_L4PROTO);
    switch (lr->protocol) {
        case IPPROTO_TCP:
        case IPPROTO_UDP:
            lr->sp = ntohs(nfct_get_attr_u16(ct, ATTR_PORT_SRC));
            lr->dp = ntohs(nfct_get_attr_u16(ct, ATTR_PORT_DST));
            lr->alt_sp = ntohs(nfct_get_attr_u16(ct, ATTR_REPL_PORT_SRC));
            lr->alt_dp = ntohs(nfct_get_attr_u16(ct, ATTR_REPL_PORT_DST));
            break;
    }

    if (lr->protocol == IPPROTO_TCP) {
        lr->tcp_state = nfct_get_attr_u8(ct, ATTR_TCP_STATE);
        lr->tcp_flags_ts = nfct_get_attr_u8(ct, ATTR_TCP_FLAGS_ORIG);
        lr->tcp_flags_tc = nfct_get_attr_u8(ct, ATTR_TCP_FLAGS_REPL);
    }

    lr->nfmark = nfct_get_attr_u32(ct, ATTR_MARK);
    lr->status = nfct_get_attr_u32(ct, ATTR_STATUS);
    return 1;
skip:
    return 0;
}

/**
 * \retval 1 ok
 * \retval 0 skipped
 */
int vrmr_conntrack_ct2lr(
        uint32_t type, struct nf_conntrack *ct, struct vrmr_log_record *lr)
{
    memset(lr, 0, sizeof(*lr));

    switch (type) {
        case NFCT_T_NEW:
            lr->conn_rec.type = VRMR_LOG_CONN_NEW;
            break;
        case NFCT_T_DESTROY: {
            lr->conn_rec.type = VRMR_LOG_CONN_COMPLETED;

            uint64_t ts_start = nfct_get_attr_u64(ct, ATTR_TIMESTAMP_START);
            uint64_t ts_stop = nfct_get_attr_u64(ct, ATTR_TIMESTAMP_STOP);
            uint64_t ts_delta = ts_stop - ts_start;
            uint32_t ts_delta_sec = ts_delta / 1000000000UL;

            lr->conn_rec.age_s = ts_delta_sec;

            struct nfct_attr_grp_ctrs ctrs = {0, 0};

            nfct_get_attr_grp(ct, ATTR_GRP_ORIG_COUNTERS, &ctrs);
            lr->conn_rec.toserver_packets = ctrs.packets;
            lr->conn_rec.toserver_bytes = ctrs.bytes;

            nfct_get_attr_grp(ct, ATTR_GRP_REPL_COUNTERS, &ctrs);
            lr->conn_rec.toclient_packets = ctrs.packets;
            lr->conn_rec.toclient_bytes = ctrs.bytes;
            break;
        }
    }

    uint8_t ipv = nfct_get_attr_u8(ct, ATTR_L3PROTO);
    switch (ipv) {
        case AF_INET: {
            uint32_t src_ip = nfct_get_attr_u32(ct, ATTR_IPV4_SRC);
            uint32_t dst_ip = nfct_get_attr_u32(ct, ATTR_IPV4_DST);
            uint32_t repl_src_ip = nfct_get_attr_u32(ct, ATTR_REPL_IPV4_SRC);
            inet_ntop(AF_INET, &src_ip, lr->src_ip, sizeof(lr->src_ip));
            /* DNAT has the ip we care about as repl_src_ip */
            if (repl_src_ip != dst_ip)
                dst_ip = repl_src_ip;
            inet_ntop(AF_INET, &dst_ip, lr->dst_ip, sizeof(lr->dst_ip));

            if (strncmp(lr->src_ip, "127.", 4) == 0)
                goto skip;
            break;
        }
        case AF_INET6: {
            lr->ipv6 = TRUE;

            struct nfct_attr_grp_ipv6 addrs;
            memset(&addrs, 0, sizeof(addrs));
            nfct_get_attr_grp(ct, ATTR_GRP_ORIG_IPV6, &addrs);

            inet_ntop(AF_INET6, &addrs.src, lr->src_ip, sizeof(lr->src_ip));
            inet_ntop(AF_INET6, &addrs.dst, lr->dst_ip, sizeof(lr->dst_ip));
            break;
        }
        default:
            abort();
    }

    lr->protocol = nfct_get_attr_u8(ct, ATTR_L4PROTO);
    switch (lr->protocol) {
        case IPPROTO_TCP:
        case IPPROTO_UDP: {
            lr->src_port = ntohs(nfct_get_attr_u16(ct, ATTR_PORT_SRC));
            lr->dst_port = ntohs(nfct_get_attr_u16(ct, ATTR_PORT_DST));
            break;
        }
    }

    lr->conn_rec.mark = nfct_get_attr_u32(ct, ATTR_MARK);
    return 1;
skip:
    return 0;
}

struct dump_cb_ctx {
    struct vrmr_config *cnf;
    struct vrmr_hash_table *serhash;
    struct vrmr_hash_table *zonehash;
    struct vrmr_list *zonelist;
    struct vrmr_conntrack_request *req;
    struct vrmr_conntrack_stats *connstat_ptr;
    struct vrmr_list *conn_dlist;
    struct vrmr_hash_table *conn_hash;
};

static int dump_cb(
        enum nf_conntrack_msg_type type, struct nf_conntrack *ct, void *data)
{
    assert(ct);
    assert(data);

    struct vrmr_conntrack_api_entry cae;
    memset(&cae, 0, sizeof(cae));

    struct dump_cb_ctx *ctx = data;
    if (vrmr_conntrack_ct2ae(type, ct, &cae)) {
        struct vrmr_conntrack_entry *ce = NULL;
        if (!(ce = calloc(1, sizeof(*ce)))) {
            vrmr_error(-1, "Error", "calloc() failed: %s", strerror(errno));
            return NFCT_CB_STOP;
        }

        if (conn_data_to_entry(&cae, ce, ctx->serhash, ctx->zonehash,
                    ctx->zonelist, ctx->req) < 0) {
            vrmr_error(-1, "Error", "conn_data_to_entry() failed");
            free(ce);
            return NFCT_CB_STOP;
        }

        /*  we ignore the local loopback connections
            and connections that are filtered */
        if ((strncmp(ce->fromname, "127.", 4) == 0 ||
                    strncmp(ce->toname, "127.", 4) == 0 ||
                    (ctx->req->use_filter == TRUE &&
                            filtered_connection(ce, &ctx->req->filter) == 1))) {
            free_conntrack_entry(ce);
            return NFCT_CB_CONTINUE;
        }

        /* update counters */
        update_stats(ce, ctx->connstat_ptr);

        /* now check if the cd is already in the list */
        struct vrmr_conntrack_entry *found = NULL;
        if (ctx->req->group_conns == TRUE &&
                (found = vrmr_hash_search(ctx->conn_hash, (void *)ce)) !=
                        NULL) {
            /*  FOUND in the hash. Transfer the acc data */
            found->to_src_packets += ce->to_src_packets;
            found->to_src_bytes += ce->to_src_bytes;
            found->to_dst_packets += ce->to_dst_packets;
            found->to_dst_bytes += ce->to_dst_bytes;
            found->cnt++;

            free_conntrack_entry(ce);
        } else {
            /*  NOT found in the hash */

            /* append the new cd to the list */
            if (vrmr_list_append(ctx->conn_dlist, ce) == NULL) {
                vrmr_error(-1, "Internal Error", "unable to append into list");
                free_conntrack_entry(ce);
                return NFCT_CB_STOP;
            }

            /* and insert it into the hash */
            if (vrmr_hash_insert(ctx->conn_hash, ce) != 0) {
                vrmr_error(-1, "Internal Error", "unable to insert into hash");
                free_conntrack_entry(ce);
                return NFCT_CB_STOP;
            }

            ce->cnt = 1;
        }
    }
    return NFCT_CB_CONTINUE;
}

static int vrmr_conn_get_connections_api(struct vrmr_config *cnf,
        struct vrmr_hash_table *serv_hash, struct vrmr_hash_table *zone_hash,
        struct vrmr_list *conn_dlist, struct vrmr_hash_table *conn_hash,
        struct vrmr_list *zone_list, struct vrmr_conntrack_request *req,
        struct vrmr_conntrack_stats *connstat_ptr)
{
    assert(cnf);
    assert(serv_hash);
    assert(zone_hash);
    assert(req);

    int retval = 0;

    struct nf_conntrack *ct = nfct_new();
    if (ct == NULL) {
        vrmr_error(-1, "Error", "nfct_new failed");
        return -1;
    }

    struct nfct_handle *h = nfct_open(CONNTRACK, 0);
    if (h == NULL) {
        vrmr_error(-1, "Error", "nfct_open failed");
        nfct_destroy(ct);
        return -1;
    }

    struct dump_cb_ctx ctx = {
            .cnf = cnf,
            .serhash = serv_hash,
            .zonehash = zone_hash,
            .conn_dlist = conn_dlist,
            .zonelist = zone_list,
            .req = req,
            .connstat_ptr = connstat_ptr,
            .conn_hash = conn_hash,
    };

    nfct_callback_register(h, NFCT_T_ALL, dump_cb, &ctx);
    int ret = nfct_query(h, NFCT_Q_DUMP, ct);
    if (ret != 0) {
        vrmr_error(-1, "Error", "nfct_query failed: %d", ret);
        retval = -1;
    }

    nfct_close(h);
    nfct_destroy(ct);
    return retval;
}
#endif

int vrmr_conn_get_connections(struct vrmr_config *cnf,
        const unsigned int prev_conn_cnt, struct vrmr_hash_table *serv_hash,
        struct vrmr_hash_table *zone_hash, struct vrmr_list *conn_dlist,
        struct vrmr_list *zone_list, struct vrmr_conntrack_request *req,
        struct vrmr_conntrack_stats *connstat_ptr)
{
    int retval = 0;

    /* set stat counters to zero */
    connstat_ptr->conn_total = 0, connstat_ptr->conn_in = 0,
    connstat_ptr->conn_out = 0, connstat_ptr->conn_fw = 0;

    connstat_ptr->stat_connect = 0, connstat_ptr->stat_estab = 0,
    connstat_ptr->stat_closing = 0, connstat_ptr->stat_other = 0;

    connstat_ptr->accounting = 0;

    /* connection hash: if the prev_conn_cnt supplied by
     * the user is bigger than 0, use it. */
    uint32_t hashtbl_size = prev_conn_cnt ? prev_conn_cnt : 256;
    struct vrmr_hash_table conn_hash;
    if (vrmr_hash_setup(&conn_hash, hashtbl_size, conn_hash_conntrackdata,
                conn_match_conntrackdata, NULL) != 0) {
        vrmr_error(-1, "Internal Error", "vrmr_hash_setup() failed");
        return (-1);
    }

#ifdef HAVE_LIBNETFILTER_CONNTRACK
    retval = vrmr_conn_get_connections_api(cnf, serv_hash, zone_hash,
            conn_dlist, &conn_hash, zone_list, req, connstat_ptr);
    if (retval == 0) {
        vrmr_hash_cleanup(&conn_hash);
        return (retval);
    }
#endif

    if (strlen(cnf->conntrack_location) > 0) {
        retval = vrmr_conn_get_connections_cmd(cnf, serv_hash, zone_hash,
                conn_dlist, &conn_hash, zone_list, req, connstat_ptr,
                VRMR_IPV4);
        if (retval == 0 && req->ipv6) {
            retval = vrmr_conn_get_connections_cmd(cnf, serv_hash, zone_hash,
                    conn_dlist, &conn_hash, zone_list, req, connstat_ptr,
                    VRMR_IPV6);
        }
    } else {
        retval = vrmr_conn_get_connections_proc(cnf, serv_hash, zone_hash,
                conn_dlist, &conn_hash, zone_list, req, connstat_ptr);
    }

    vrmr_hash_cleanup(&conn_hash);
    return (retval);
}
