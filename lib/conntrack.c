/***************************************************************************
 *   Copyright (C) 2002-2019 by Victor Julien                              *
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

static const char *state_to_string(enum tcp_conntrack tcp_state)
{
    switch (tcp_state) {
        case TCP_CONNTRACK_NONE:
            return "none";
        case TCP_CONNTRACK_SYN_SENT2:
            return "syn_sent2";
        case TCP_CONNTRACK_SYN_SENT:
            return "syn_sent";
        case TCP_CONNTRACK_SYN_RECV:
            return "syn_recv";
        case TCP_CONNTRACK_ESTABLISHED:
            return "established";
        case TCP_CONNTRACK_FIN_WAIT:
            return "fin_wait";
        case TCP_CONNTRACK_TIME_WAIT:
            return "time_wait";
        case TCP_CONNTRACK_LAST_ACK:
            return "last_ack";
        case TCP_CONNTRACK_CLOSE_WAIT:
            return "close_wait";
        case TCP_CONNTRACK_CLOSE:
            return "close";
        case TCP_CONNTRACK_MAX:
        case TCP_CONNTRACK_IGNORE:
        case TCP_CONNTRACK_RETRANS:
        case TCP_CONNTRACK_UNACK:
        case TCP_CONNTRACK_TIMEOUT_MAX:
            return "weird"; // TODO
    }
    return "unknown";
}

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

    char helper[30];
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
        if (cae->protocol != IPPROTO_TCP) {
            ce->connect_status = VRMR_CONN_CONNECTED;
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
    }
    if (cae->protocol == IPPROTO_TCP) {
        ce->state_string = state_to_string(cae->tcp_state);
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

    strlcpy(ce->helper, cae->helper, sizeof(ce->helper));
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

    const char *helper = nfct_get_attr(ct, ATTR_HELPER_NAME);
    if (helper) {
        strlcpy(lr->helper, helper, sizeof(lr->helper));
    }

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

    const char *helper = nfct_get_attr(ct, ATTR_HELPER_NAME);
    if (helper) {
        strlcpy(lr->helper, helper, sizeof(lr->helper));
    }

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

    retval = vrmr_conn_get_connections_api(cnf, serv_hash, zone_hash,
            conn_dlist, &conn_hash, zone_list, req, connstat_ptr);
    if (retval == 0) {
        vrmr_hash_cleanup(&conn_hash);
        return (retval);
    }

    vrmr_hash_cleanup(&conn_hash);
    return (retval);
}

int vrmr_conn_kill_connection_api(const int family, const char *src_ip,
        const char *dst_ip, uint16_t sp, uint16_t dp, uint8_t protocol)
{
    assert(family == AF_INET || family == AF_INET6);

    int retval = 0;

    struct nf_conntrack *ct = nfct_new();
    if (ct == NULL) {
        vrmr_error(-1, "Error", "nfct_new failed");
        return -1;
    }

    nfct_set_attr_u8(ct, ATTR_L4PROTO, protocol);
    if (protocol == IPPROTO_TCP || protocol == IPPROTO_UDP) {
        nfct_set_attr_u16(ct, ATTR_PORT_SRC, htons(sp));
        nfct_set_attr_u16(ct, ATTR_PORT_DST, htons(dp));
    }
    if (family == AF_INET) {
        nfct_set_attr_u8(ct, ATTR_L3PROTO, AF_INET);
        nfct_set_attr_u32(ct, ATTR_IPV4_SRC, inet_addr(src_ip));
        nfct_set_attr_u32(ct, ATTR_IPV4_DST, inet_addr(dst_ip));
    } else {
        nfct_set_attr_u8(ct, ATTR_L3PROTO, AF_INET6);
    }

    struct nfct_handle *h = nfct_open(CONNTRACK, 0);
    if (h == NULL) {
        vrmr_error(-1, "Error", "nfct_open failed");
        nfct_destroy(ct);
        return -1;
    }

    int ret = nfct_query(h, NFCT_Q_DESTROY, ct);
    if (ret != 0) {
        vrmr_error(-1, "Error", "nfct_query failed: %d", ret);
        retval = -1;
    }

    nfct_close(h);
    nfct_destroy(ct);
    return retval;
}

static int stub_cb(enum nf_conntrack_msg_type type ATTR_UNUSED,
        struct nf_conntrack *ct ATTR_UNUSED, void *data ATTR_UNUSED)
{
    return NFCT_CB_CONTINUE;
}

bool vrmr_conn_check_api(void)
{
    bool retval = true;

    struct nf_conntrack *ct = nfct_new();
    if (ct == NULL) {
        vrmr_error(-1, "Error", "nfct_new failed");
        return false;
    }

    struct nfct_handle *h = nfct_open(CONNTRACK, 0);
    if (h == NULL) {
        vrmr_error(-1, "Error", "nfct_open failed");
        nfct_destroy(ct);
        return false;
    }

    nfct_callback_register(h, NFCT_T_ALL, stub_cb, NULL);
    int ret = nfct_query(h, NFCT_Q_DUMP, ct);
    if (ret != 0) {
        vrmr_error(-1, "Error", "nfct_query failed: %d", ret);
        retval = false;
    }

    nfct_close(h);
    nfct_destroy(ct);
    return retval;
}

struct count_cb_ctx {
    uint32_t tcp;
    uint32_t udp;
    uint32_t other;
};

static int count_cb(enum nf_conntrack_msg_type type ATTR_UNUSED,
        struct nf_conntrack *ct, void *data)
{
    struct count_cb_ctx *ctx = data;
    uint8_t protocol = nfct_get_attr_u8(ct, ATTR_L4PROTO);
    switch (protocol) {
        case IPPROTO_TCP:
            ctx->tcp++;
            break;
        case IPPROTO_UDP:
            ctx->udp++;
            break;
        default:
            ctx->other++;
            break;
    }
    return NFCT_CB_CONTINUE;
}

int vrmr_conn_count_connections_api(
        uint32_t *tcp, uint32_t *udp, uint32_t *other)
{
    int retval = 0;
    struct count_cb_ctx ctx = {.tcp = 0, .udp = 0, .other = 0};

    *tcp = 0;
    *udp = 0;
    *other = 0;

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

    nfct_callback_register(h, NFCT_T_ALL, count_cb, &ctx);
    int ret = nfct_query(h, NFCT_Q_DUMP, ct);
    if (ret != 0) {
        vrmr_error(-1, "Error", "nfct_query failed: %d", ret);
        retval = -1;
    }

    nfct_close(h);
    nfct_destroy(ct);

    if (retval == 0) {
        *tcp = ctx.tcp;
        *udp = ctx.udp;
        *other = ctx.other;
    }
    return retval;
}
