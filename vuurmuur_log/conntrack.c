/***************************************************************************
 *   Copyright (C) 2003-2017 by Victor Julien                              *
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

#include <vuurmuur.h>
#include "vuurmuur_log.h"

#ifdef HAVE_LIBNETFILTER_CONNTRACK
#include <libmnl/libmnl.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#include <assert.h>
#include <inttypes.h>
#include <sys/time.h>

#include "conntrack.h"

static int g_debuglvl = 0; //TODO
static struct mnl_socket *nl = NULL;
extern struct vrmr_hash_table zone_htbl;
extern struct vrmr_hash_table service_htbl;
extern FILE *g_connections_log_fp;
extern FILE *g_conn_new_log_fp;

/* process one record */
static int process_connrecord(struct vrmr_log_record *lr) {
    char line[1024] = "";
    FILE *fp;

    int result = vrmr_log_record_get_names(g_debuglvl, lr, &zone_htbl, &service_htbl);
    if (result < 0) {
        vrmr_debug(__FUNC__, "vrmr_log_record_get_names returned %d", result);
        exit(EXIT_FAILURE);
    }

    char s[256];
    struct timeval tv;
    memset(&tv, 0, sizeof(tv));
    gettimeofday (&tv, NULL);
    time_t when = tv.tv_sec;
    struct tm *tm = localtime(&when);
    strftime (s, 256, "%b %d %T", tm);

    if (sscanf (s, "%3s %2d %2d:%2d:%2d", lr->month, &lr->day,
        &lr->hour, &lr->minute, &lr->second) != 5) {
        vrmr_debug(__FUNC__, "did not find properly formatted timestamp");
        return -1;
    }

    snprintf(line, sizeof(line), "%s %2d %02d:%02d:%02d: %s service %s from %s to %s (",
            lr->month, lr->day, lr->hour, lr->minute, lr->second,
            lr->conn_rec.type == VRMR_LOG_CONN_COMPLETED ? "COMPLETED" : "NEW",
            lr->ser_name, lr->from_name, lr->to_name);

    if (lr->protocol == IPPROTO_TCP || lr->protocol == IPPROTO_UDP) {
        char addrports[256];
        snprintf(addrports, sizeof(addrports), "%s:%u -> %s:%u %s",
                lr->src_ip, lr->src_port, lr->dst_ip, lr->dst_port,
                lr->protocol == IPPROTO_TCP ? "TCP" : "UDP");
        strlcat(line, addrports, sizeof(line));
    } else {
        char addr[256];
        snprintf(addr, sizeof(addr), "%s -> %s PROTO %u",
                lr->src_ip, lr->dst_ip, lr->protocol);
        strlcat(line, addr, sizeof(line));
    }

    if (lr->conn_rec.type == VRMR_LOG_CONN_COMPLETED) {
        char extra[1024];
        snprintf(extra, sizeof(extra), " age:%us pkts_ts:%"PRIu64" bytes_ts:%"PRIu64" pkts_tc:%"PRIu64" bytes_tc:%"PRIu64"",
                lr->conn_rec.age_s,
                lr->conn_rec.toserver_packets, lr->conn_rec.toserver_bytes,
                lr->conn_rec.toclient_packets, lr->conn_rec.toclient_bytes);
        strlcat(line, extra, sizeof(line));
    }

    if (lr->conn_rec.type == VRMR_LOG_CONN_COMPLETED) {
        fp = g_connections_log_fp;
    } else {
        fp = g_conn_new_log_fp;
    }
    assert(fp);

    fprintf(fp, "%s)\n", line);
    fflush(fp);

    return 0;
}
static int record_cb(const struct nlmsghdr *nlh, void *data)
{
    uint32_t type = NFCT_T_UNKNOWN;
    struct vrmr_log_record *lr = (struct vrmr_log_record *)data;

    switch (nlh->nlmsg_type & 0xFF) {
        case IPCTNL_MSG_CT_NEW:
            if (nlh->nlmsg_flags & (NLM_F_CREATE|NLM_F_EXCL))
                type = NFCT_T_NEW;
            else
                type = NFCT_T_UPDATE;
            break;
        case IPCTNL_MSG_CT_DELETE:
            type = NFCT_T_DESTROY;
            break;
        default:
            abort();
            break;
    }

    struct nf_conntrack *ct = nfct_new();
    if (ct == NULL)
        return MNL_CB_OK;
    nfct_nlmsg_parse(nlh, ct);

    memset(lr, 0, sizeof(*lr));

    switch (type) {
        case NFCT_T_NEW:
            lr->conn_rec.type = VRMR_LOG_CONN_NEW;
            break;
        case NFCT_T_DESTROY:
        {
            lr->conn_rec.type = VRMR_LOG_CONN_COMPLETED;

            uint64_t ts_start = nfct_get_attr_u64(ct, ATTR_TIMESTAMP_START);
            uint64_t ts_stop = nfct_get_attr_u64(ct, ATTR_TIMESTAMP_STOP);
            uint64_t ts_delta = ts_stop - ts_start;
            uint32_t ts_delta_sec = ts_delta / 1000000000UL;

            lr->conn_rec.age_s = ts_delta_sec;

            struct nfct_attr_grp_ctrs ctrs = { 0, 0 };

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
        case AF_INET:
        {
            uint32_t src_ip = nfct_get_attr_u32(ct, ATTR_IPV4_SRC);
            uint32_t dst_ip = nfct_get_attr_u32(ct, ATTR_IPV4_DST);

            uint32_t repl_src_ip = nfct_get_attr_u32(ct, ATTR_REPL_IPV4_SRC);
            //uint32_t repl_dst_ip = nfct_get_attr_u32(ct, ATTR_REPL_IPV4_DST);

            inet_ntop(AF_INET, &src_ip, lr->src_ip, sizeof(lr->src_ip));

            /* DNAT has the ip we care about as repl_src_ip */
            if (repl_src_ip != dst_ip)
                dst_ip = repl_src_ip;
            inet_ntop(AF_INET, &dst_ip, lr->dst_ip, sizeof(lr->dst_ip));

            if (strncmp(lr->src_ip, "127.", 4) == 0)
                goto skip;
            break;
        }
        case AF_INET6:
        {
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
        case IPPROTO_UDP:
        {
            lr->src_port = ntohs(nfct_get_attr_u16(ct, ATTR_PORT_SRC));
            lr->dst_port = ntohs(nfct_get_attr_u16(ct, ATTR_PORT_DST));
            break;
        }
    }
    process_connrecord(lr);

skip:
    nfct_destroy(ct);
    return MNL_CB_OK;
}

int conntrack_subscribe(struct vrmr_log_record *lr)
{
    assert(!nl);
    assert(lr);

    nl = mnl_socket_open(NETLINK_NETFILTER);
    if (nl == NULL) {
        vrmr_error(-1, "Error", "mnl_socket_open failed: %s",
            strerror(errno));
        return -1;
    }
    if (mnl_socket_bind(nl, NF_NETLINK_CONNTRACK_NEW |
                NF_NETLINK_CONNTRACK_DESTROY,
                MNL_SOCKET_AUTOPID) < 0) {
        vrmr_error(-1, "Error", "mnl_socket_bind failed: %s",
            strerror(errno));
        mnl_socket_close(nl);
        return -1;
    }

    /* set a timeout to the socket so we can check for a signal
     * in case we don't get packets for a longer period. */
    struct timeval timev;
    timev.tv_sec = 0;
    timev.tv_usec = 1000;

    if (mnl_socket_setsockopt(nl, SO_RCVTIMEO, &timev, sizeof(timev)) == -1) {
        vrmr_warning(__FUNC__,  "can't set socket "
                "timeout: %s", strerror(errno));
    }
    return 0;
}

int conntrack_disconnect(void)
{
    assert(nl);
    mnl_socket_close(nl);
    return 0;
}

int conntrack_read(struct vrmr_log_record *lr)
{
    assert(nl);
    assert(lr);

    vrmr_info(__FUNC__, "calling mnl_socket_recvfrom()");

    char buf[MNL_SOCKET_BUFFER_SIZE];
    int ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
    if (ret == -1) {
        vrmr_warning("Warning", "mnl_socket_recvfrom failed: %s",
                strerror(errno));
        return -1;
    }

    ret = mnl_cb_run(buf, ret, 0, 0, record_cb, (void *)lr);
    if (ret == -1) {
        vrmr_warning("Warning", "mnl_cb_run failed: %s",
                strerror(errno));
        return -1;
    }
    return 0;
}
#endif
