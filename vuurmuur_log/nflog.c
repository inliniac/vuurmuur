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

/** \file
 *  nflog.c implements functions to communicate with the NFLOG iptables target.
 */

#include "vuurmuur_log.h"

#ifdef HAVE_LIBNETFILTER_LOG

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <linux/icmp.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <libnetfilter_log/libnetfilter_log.h>
#include <sys/time.h>

#include "nflog.h"

#ifdef IPV6_ENABLED
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#endif /* IPV6_ENABLED */

static int fd = -1;
static struct nflog_handle *h;

union ipv4_adress {
    uint8_t a[4];
    uint32_t saddr;
};

static char *mac2str(char *mac, char *strmac, size_t len)
{
    snprintf(strmac, len, "%02x:%02x:%02x:%02x:%02x:%02x", (uint8_t)mac[0],
            (uint8_t)mac[1], (uint8_t)mac[2], (uint8_t)mac[3], (uint8_t)mac[4],
            (uint8_t)mac[5]);
    return strmac;
}

/**
 * \brief createlogrule_callback (struct nflog_g_handle *gh, struct nfgenmsg
 * *nfmsg, struct nflog_data *nfa, void *data)
 *
 * NFLOG callback to transform the data in the received package into structured
 * data required by writing the traffic log in the main program. Taken initially
 * from nfulnl.c in the ulogd2 source code.
 *
 * \pre the callback should have been registered with 'data' pointing to a
 * struct logrule * \post the struct pointed to by 'data' contains properly
 * fmt'ed fields \param[in] gh: \param[in] nfgenmsg: \param[in] nfa:
 * \param[in,out] data A pointer to the result struct
 * \return 0
 * \retval n.a.
 * \note n.a.
 */
static int createlogrule_callback(struct nflog_g_handle *gh ATTR_UNUSED,
        struct nfgenmsg *nfmsg ATTR_UNUSED, struct nflog_data *nfa, void *data)
{
    struct nfulnl_msg_packet_hdr *ph;
    char *hwhdr;
    char macstr[20];
    uint32_t indev;
    uint32_t outdev;
    void *protoh;
    struct tcphdr *tcph;
    struct udphdr *udph;
    struct icmphdr *icmph;
    char *prefix;
    char *payload;
    int payload_len;
    struct timeval tv;
    struct vrmr_log_record *log_record = data;
    time_t when;
    char s[256];
    union ipv4_adress ip;

    memset(log_record, 0, sizeof(struct vrmr_log_record));

    /* Check first if this pkt comes from a vuurmuur logrule */
    prefix = nflog_get_prefix(nfa);
    vrmr_log_record_parse_prefix(log_record, prefix);

    /* Copy hostname in log_rule struct, seems kind of silly to do this every
     * time */
    if (gethostname(log_record->hostname, HOST_NAME_MAX) == -1) {
        vrmr_debug(NONE, "Error getting hostname");
        return -1;
    }

    /* Alright, get the nflog packet header and determine what hw_protocol we're
     * dealing with */
    if (!(ph = nflog_get_msg_packet_hdr(nfa))) {
        vrmr_error(-1, "Error", "Can't get packet header");
        return -1;
    }

    /* Convert MAC src and dst to strings and copy into log_record */
    if (nflog_get_msg_packet_hwhdrlen(nfa)) {
        hwhdr = nflog_get_msg_packet_hwhdr(nfa);
        if (hwhdr != NULL) {
            mac2str(hwhdr, macstr, sizeof(macstr));
            snprintf(log_record->dst_mac, sizeof(log_record->dst_mac), "(%s)",
                    macstr);
            mac2str(hwhdr + 6, macstr, sizeof(macstr));
            snprintf(log_record->src_mac, sizeof(log_record->src_mac), "(%s)",
                    macstr);
        }
    }

    /* Find indev idx for pkg and translate to interface name */
    indev = nflog_get_indev(nfa);
    if (indev) {
        if_indextoname(indev, log_record->interface_in);
        snprintf(log_record->from_int, sizeof(log_record->from_int), "in: %s ",
                log_record->interface_in);
    } else {
        *log_record->interface_in = 0;
        *log_record->from_int = 0;
    }

    /* Find outdev idx for pkg and translate to interface name */
    outdev = nflog_get_outdev(nfa);
    if (outdev) {
        if_indextoname(outdev, log_record->interface_out);
        snprintf(log_record->to_int, sizeof(log_record->to_int), "out: %s ",
                log_record->interface_out);
    } else {
        *log_record->interface_out = 0;
        *log_record->to_int = 0;
    }

    /* Put packet's timestamp in log_rule struct */
    /* If not in pkt, generate it ourselves */
    if (nflog_get_timestamp(nfa, &tv) == -1) {
        gettimeofday(&tv, NULL);
    }
    when = tv.tv_sec;
    struct tm *tm = localtime(&when);
    strftime(s, 256, "%b %d %T", tm);
    if (sscanf(s, "%3s %2d %2d:%2d:%2d", log_record->month, &log_record->day,
                &log_record->hour, &log_record->minute,
                &log_record->second) != 5) {
        vrmr_debug(NONE, "did not find properly formatted timestamp");
        return -1;
    }

    /* Now we still need to look into the packet itself for source/dest ports */
    if ((payload_len = nflog_get_payload(nfa, &payload)) == -1) {
        vrmr_error(-1, "Error", "Can't get payload");
        return -1;
    } else {
        uint16_t hw_protocol = ntohs(ph->hw_protocol);
        if (hw_protocol == 0x0000) {
            struct iphdr *iph = (struct iphdr *)payload;
#ifdef IPV6_ENABLED
            struct ip6_hdr *ip6h = (struct ip6_hdr *)payload;
#endif
            if (payload_len >= (int)sizeof(struct iphdr) && iph->version == 4) {
                vrmr_debug(NONE, "IPv4");
                hw_protocol = ETH_P_IP;
#ifdef IPV6_ENABLED
            } else if (payload_len >= (int)sizeof(struct ip6_hdr) &&
                       ((ip6h->ip6_vfc & 0xf0) >> 4) == 6) {
                vrmr_debug(NONE, "IPv6");
                hw_protocol = ETH_P_IPV6;
#endif
            }

            vrmr_debug(NONE, "hw_protocol 0x%04X", hw_protocol);
        }

        switch (hw_protocol) {
            /* netfilter not always sets the hw_protocol */
            case 0x0000:
                /* we tried, but failed */
                break;
            case ETH_P_IP: {
                if (payload_len < (int)sizeof(struct iphdr))
                    break;

                struct iphdr *iph = (struct iphdr *)payload;
                protoh = (uint32_t *)iph + iph->ihl;
                log_record->protocol = iph->protocol;
                log_record->packet_len = ntohs(iph->tot_len) - iph->ihl * 4;
                switch (log_record->protocol) {
                    case IPPROTO_TCP:
                        tcph = (struct tcphdr *)protoh;
                        log_record->src_port = ntohs(tcph->source);
                        log_record->dst_port = ntohs(tcph->dest);
                        log_record->syn = tcph->syn;
                        log_record->fin = tcph->fin;
                        log_record->rst = tcph->rst;
                        log_record->ack = tcph->ack;
                        log_record->psh = tcph->psh;
                        log_record->urg = tcph->urg;
                        break;
                    case IPPROTO_ICMP:
                        icmph = (struct icmphdr *)protoh;
                        log_record->icmp_type = icmph->type;
                        log_record->icmp_code = icmph->code;
                        break;
                    case IPPROTO_UDP:
                        udph = (struct udphdr *)protoh;
                        log_record->src_port = ntohs(udph->source);
                        log_record->dst_port = ntohs(udph->dest);
                        break;
                }
                ip.saddr = iph->saddr;
                snprintf(log_record->src_ip, sizeof(log_record->src_ip),
                        "%u.%u.%u.%u", ip.a[0], ip.a[1], ip.a[2], ip.a[3]);
                ip.saddr = iph->daddr;
                snprintf(log_record->dst_ip, sizeof(log_record->dst_ip),
                        "%u.%u.%u.%u", ip.a[0], ip.a[1], ip.a[2], ip.a[3]);
                log_record->ttl = iph->ttl;
                break;
            }
            case ETH_P_IPV6: {
#ifdef IPV6_ENABLED
                vrmr_debug(NONE, "hw proto said IPv6, lets try to decode.");

                if (payload_len < (int)sizeof(struct ip6_hdr))
                    break;

                struct ip6_hdr *ip6h = (struct ip6_hdr *)payload;
                payload += sizeof(struct ip6_hdr);
                payload_len -= sizeof(struct ip6_hdr);

                inet_ntop(AF_INET6, (const void *)&ip6h->ip6_src,
                        log_record->src_ip, sizeof(log_record->src_ip));
                inet_ntop(AF_INET6, (const void *)&ip6h->ip6_dst,
                        log_record->dst_ip, sizeof(log_record->dst_ip));

                log_record->ttl = ip6h->ip6_hlim;
                log_record->packet_len = 40 + ntohs(ip6h->ip6_plen);

                /* just the next header, might not be the protocol we care about
                 */
                log_record->protocol = ip6h->ip6_nxt;
                switch (log_record->protocol) {
                    case IPPROTO_ICMPV6:
                        if (payload_len >= (int)sizeof(struct icmp6_hdr)) {
                            struct icmp6_hdr *icmp6h =
                                    (struct icmp6_hdr *)payload;
                            log_record->icmp_type = icmp6h->icmp6_type;
                            log_record->icmp_code = icmp6h->icmp6_code;
                            vrmr_debug(NONE, "ICMPv6: type %u code %u",
                                    log_record->icmp_type,
                                    log_record->icmp_code);
                        }
                        break;
                    case IPPROTO_TCP:
                        if (payload_len >= (int)sizeof(struct tcphdr)) {
                            tcph = (struct tcphdr *)payload;
                            log_record->src_port = ntohs(tcph->source);
                            log_record->dst_port = ntohs(tcph->dest);
                            log_record->syn = tcph->syn;
                            log_record->fin = tcph->fin;
                            log_record->rst = tcph->rst;
                            log_record->ack = tcph->ack;
                            log_record->psh = tcph->psh;
                            log_record->urg = tcph->urg;
                        }
                        break;
                    case IPPROTO_UDP:
                        if (payload_len >= (int)sizeof(struct tcphdr)) {
                            udph = (struct udphdr *)payload;
                            log_record->src_port = ntohs(udph->source);
                            log_record->dst_port = ntohs(udph->dest);
                        }
                        break;
                }

                log_record->ipv6 = 1;

                vrmr_debug(NONE, "IPV6 %s -> %s (%u)", log_record->src_ip,
                        log_record->dst_ip, log_record->protocol);
#endif /* IPV6_ENABLED */
                break;
            }
            default:
                vrmr_debug(NONE, "unknown HW Protocol: 0x%04x", hw_protocol);
                break;
        }
    }

    /* process the record */
    process_logrecord(log_record);
    return 0; /* success */
}

/**
 * \brief subscribe_nflog sets up the nflog handles and callback
 *
 * And a more detailed description of the function that doesn't fit
 * on 1 line
 *
 * \pre The preconditions of the function, which should be checked by the
 * function \post The postconditions of the function \param[in] var1 The value
 * that is used to devide \param[in,out] var2 A pointer to the result, and ...
 * \return The function returns the value of the calculation.
 * \retval -1 When var1 or var2 is 0
 * \note A note that applies to the function
 */
int subscribe_nflog(
        const struct vrmr_config *conf, struct vrmr_log_record *log_record)
{
    struct nflog_g_handle *qh;

    h = nflog_open();
    if (!h) {
        vrmr_error(-1, "Internal Error", "nflog_open error (in: %s:%d).",
                __FUNC__, __LINE__);
        return (-1);
    }

    if (nflog_bind_pf(h, AF_INET) < 0) {
        vrmr_error(-1, "Internal Error", "nflog_bind_pf error (in: %s:%d).",
                __FUNC__, __LINE__);
        return (-1);
    }

    qh = nflog_bind_group(h, conf->nfgrp);
    if (!qh) {
        vrmr_error(-1, "Internal Error",
                "nflog_bind_group(%p, %d) error, other process attached? %s "
                "(in: %s:%d).",
                h, conf->nfgrp, strerror(errno), __FUNC__, __LINE__);
        return (-1);
    }

    if (nflog_set_mode(qh, NFULNL_COPY_PACKET, 0xffff) < 0) {
        vrmr_error(-1, "Internal Error", "nflog_set_mode error %s (in; %s:%d).",
                strerror(errno), __FUNC__, __LINE__);
        return (-1);
    }

    nflog_callback_register(qh, &createlogrule_callback, log_record);

    fd = nflog_fd(h);

    vrmr_info("Info", "subscribed to nflog group %u", conf->nfgrp);
    return 0;
}

int readnflog(void)
{
    int rv;
    char buf[4096];

    if ((rv = recv(fd, buf, sizeof(buf), MSG_DONTWAIT)) == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return 0;
        } else if (errno == ENOBUFS) {
            vrmr_error(-1, "Error",
                    "ENOBUFS on recv, may need to "
                    "increase netlink_socket_buffer_size (in; %s:%d)",
                    __FUNC__, __LINE__);
            return -1;
        } else {
            vrmr_error(-1, "Internal Error",
                    "cannot recv: "
                    "%s (in; %s:%d)",
                    strerror(errno), __FUNC__, __LINE__);
            return -1;
        }
    }

    rv = nflog_handle_packet(h, buf, rv);
    if (rv != 0) {
        vrmr_debug(NONE,
                "nflog_handle_packet() "
                "returned %d",
                rv);
        return (2); /* invalid record */
    }
    return (1);
}

#endif /* HAVE_LIBNETFILTER_LOG */
