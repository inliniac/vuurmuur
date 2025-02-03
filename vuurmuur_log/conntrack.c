/***************************************************************************
 *   Copyright (C) 2003-2019 by Victor Julien                              *
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

#include <libmnl/libmnl.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#include <assert.h>
#include <inttypes.h>
#include <sys/time.h>
#include <linux/netfilter/nf_conntrack_tcp.h>

#include "conntrack.h"

static struct mnl_socket *nl = NULL;
extern struct vrmr_hash_table zone_htbl;
extern struct vrmr_hash_table service_htbl;
extern FILE *g_connections_log_fp;
extern FILE *g_conn_new_log_fp;

static void bytes2str(const uint64_t bytes, char *str, size_t size)
{
    if (bytes == 0)
        snprintf(str, size, "0b");
    /* 1 byte - 999 bytes */
    else if (bytes > 0 && bytes < 1000)
        snprintf(str, size, "%ub", (unsigned int)bytes);
    /* 1kb - 999kb */
    else if (bytes >= 1000 && bytes < 1000000)
        snprintf(str, size, "%.1fk", (float)bytes / 1024);
    /* 1mb - 10mb */
    else if (bytes >= 1000000 && bytes < 10000000)
        snprintf(str, size, "%1.1fM", (float)bytes / (1024 * 1024));
    /* 10mb - 1000mb */
    else if (bytes >= 10000000 && bytes < 1000000000)
        snprintf(str, size, "%.0fM", (float)bytes / (1024 * 1024));
    else if (bytes >= 1000000000 && bytes < 10000000000ULL)
        snprintf(str, size, "%1.1fG", (float)bytes / (1024 * 1024 * 1024));
    else if (bytes >= 10000000000ULL && bytes < 100000000000ULL)
        snprintf(str, size, "%.0fG", (float)bytes / (1024 * 1024 * 1024));
    else
        snprintf(str, size, "%.0fG", (float)bytes / (1024 * 1024 * 1024));
}

static void mark2str(const uint32_t mark, char *str, size_t size)
{
    if (mark == 1) {
        strlcpy(str, "ACCEPT", size);
    } else if (mark >= 3 && mark < 65536) {
        snprintf(str, size, "NFQUEUE(%u)", mark - 3);
    } else if (mark > 65536) {
        snprintf(str, size, "NFLOG(%u)",
                mark - (65536 + 3)); // see vuurmuur/main.h
    } else {
        strlcpy(str, "COMPLETE", size);
    }
}

/* process one record */
static int process_connrecord(struct vrmr_log_record *lr)
{
    char line[1024] = "";
    FILE *fp;

    int result = vrmr_log_record_get_names(lr, &zone_htbl, &service_htbl);
    if (result < 0) {
        vrmr_debug(NONE, "vrmr_log_record_get_names returned %d", result);
        exit(EXIT_FAILURE);
    }

    char s[256];
    struct timeval tv;
    memset(&tv, 0, sizeof(tv));
    gettimeofday(&tv, NULL);
    time_t when = tv.tv_sec;
    struct tm *tm = localtime(&when);
    strftime(s, 256, "%b %d %T", tm);

    if (sscanf(s, "%3s %2d %2d:%2d:%2d", lr->month, &lr->day, &lr->hour,
                &lr->minute, &lr->second) != 5) {
        vrmr_debug(NONE, "did not find properly formatted timestamp");
        return -1;
    }

    char action[32];
    if (lr->conn_rec.type == VRMR_LOG_CONN_COMPLETED)
        mark2str(lr->conn_rec.mark, action, sizeof(action));
    else
        strlcpy(action, "NEW", sizeof(action));

    snprintf(line, sizeof(line),
            "%s %2d %02d:%02d:%02d: %s service %s from %s to %s (", lr->month,
            lr->day, lr->hour, lr->minute, lr->second, action, lr->ser_name,
            lr->from_name, lr->to_name);

    if (lr->conn_rec.type == VRMR_LOG_CONN_COMPLETED) {
        char ts[64];
        char tc[64];

        bytes2str(lr->conn_rec.toserver_bytes, ts, sizeof(ts));
        bytes2str(lr->conn_rec.toclient_bytes, tc, sizeof(tc));

        char extra[1024];
        snprintf(extra, sizeof(extra), "%us %s><%s ", lr->conn_rec.age_s, ts,
                tc);
        strlcat(line, extra, sizeof(line));
    }

    if (lr->protocol == IPPROTO_TCP || lr->protocol == IPPROTO_UDP) {
        char addrports[256];
        snprintf(addrports, sizeof(addrports), "%s:%d -> %s:%d %s", lr->src_ip,
                lr->src_port, lr->dst_ip, lr->dst_port,
                lr->protocol == IPPROTO_TCP ? "TCP" : "UDP");
        strlcat(line, addrports, sizeof(line));
    } else {
        char addr[256];
        snprintf(addr, sizeof(addr), "%s -> %s PROTO %d", lr->src_ip,
                lr->dst_ip, lr->protocol);
        strlcat(line, addr, sizeof(line));
    }

    if (lr->conn_rec.type == VRMR_LOG_CONN_COMPLETED) {
        if (lr->conn_rec.mark > 0) {
            char mark[32];
            snprintf(mark, sizeof(mark), " mark:%u", lr->conn_rec.mark);
            strlcat(line, mark, sizeof(line));
        }

#if 0 // looks like this is not available in a DESTROY record :-(
        if (lr->protocol == IPPROTO_TCP) {
            char tcp[256];
            char *tcp_state = "none";
            switch ((enum tcp_conntrack)lr->conn_rec.tcp_state) {
                case TCP_CONNTRACK_NONE:
                    tcp_state = "none";
                    break;
                case TCP_CONNTRACK_SYN_SENT2:
                    tcp_state = "syn_sent2";
                    break;
                case TCP_CONNTRACK_SYN_SENT:
                    tcp_state = "syn_sent";
                    break;
                case TCP_CONNTRACK_SYN_RECV:
                    tcp_state = "syn_recv";
                    break;
                case TCP_CONNTRACK_ESTABLISHED:
                    tcp_state = "established";
                    break;
                case TCP_CONNTRACK_FIN_WAIT:
                    tcp_state = "fin_wait";
                    break;
                case TCP_CONNTRACK_TIME_WAIT:
                    tcp_state = "time_wait";
                    break;
                case TCP_CONNTRACK_LAST_ACK:
                    tcp_state = "last_ack";
                    break;
                case TCP_CONNTRACK_CLOSE_WAIT:
                    tcp_state = "close_wait";
                    break;
                case TCP_CONNTRACK_CLOSE:
                    tcp_state = "close";
                    break;
                case TCP_CONNTRACK_MAX:
                case TCP_CONNTRACK_IGNORE:
                case TCP_CONNTRACK_RETRANS:
                case TCP_CONNTRACK_UNACK:
                case TCP_CONNTRACK_TIMEOUT_MAX:
                    tcp_state = "weird"; //TODO
                    break;
            }
            snprintf(tcp, sizeof(tcp), " tcp_state:%s tcp_flags_ts:%02x tcp_flags_tc:%02x",
                tcp_state, lr->conn_rec.tcp_flags_ts, lr->conn_rec.tcp_flags_tc);
            strlcat(line, tcp, sizeof(line));
        }
#endif
    }
    if (strlen(lr->helper)) {
        char helper[64];
        snprintf(helper, sizeof(helper), " helper:%s", lr->helper);
        strlcat(line, helper, sizeof(line));
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
            if (nlh->nlmsg_flags & (NLM_F_CREATE | NLM_F_EXCL))
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

    vrmr_conntrack_ct2lr(type, ct, lr);

    process_connrecord(lr);

    nfct_destroy(ct);
    return MNL_CB_OK;
}

int conntrack_subscribe(struct vrmr_log_record *lr)
{
    assert(!nl);
    assert(lr);

    nl = mnl_socket_open(NETLINK_NETFILTER);
    if (nl == NULL) {
        vrmr_error(-1, "Error", "mnl_socket_open failed: %s", strerror(errno));
        return -1;
    }
    if (mnl_socket_bind(nl,
                NF_NETLINK_CONNTRACK_NEW | NF_NETLINK_CONNTRACK_DESTROY,
                MNL_SOCKET_AUTOPID) < 0) {
        vrmr_error(-1, "Error", "mnl_socket_bind failed: %s", strerror(errno));
        mnl_socket_close(nl);
        return -1;
    }

    /* set a timeout to the socket so we can check for a signal
     * in case we don't get packets for a longer period. */
    struct timeval timev;
    timev.tv_sec = 0;
    timev.tv_usec = 1000;

    if (mnl_socket_setsockopt(nl, SO_RCVTIMEO, &timev, sizeof(timev)) == -1) {
        vrmr_warning(
                "Warning", "can't set mnl socket timeout: %s", strerror(errno));
    }

    /* set timeout on the socket itself as well. W/o it it would still
     * block on reads. */
    int fd = mnl_socket_get_fd(nl);
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timev, sizeof(timev)) == -1) {
        vrmr_warning(
                "Warning", "can't set raw socket timeout: %s", strerror(errno));
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

    errno = 0;
    char buf[MNL_SOCKET_BUFFER_SIZE];
    int ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
    if (ret == -1) {
        if (errno == EAGAIN) {
            return 0;
        }
        vrmr_warning(
                "Warning", "mnl_socket_recvfrom failed: %s", strerror(errno));
        return -1;
    }

    ret = mnl_cb_run(buf, ret, 0, 0, record_cb, (void *)lr);
    if (ret == -1) {
        vrmr_warning("Warning", "mnl_cb_run failed: %s", strerror(errno));
        return -1;
    }
    return 0;
}
