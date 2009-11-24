/***************************************************************************
 *   Copyright (C) 2003-2008 by Victor Julien                              *
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
 * nflog.c implements functions to communicate with the NFLOG iptables target. */

#include "vuurmuur_log.h"
#include "nflog.h"

#include <libnetfilter_log/libnetfilter_log.h>
#include <net/if.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>

static int fd;
static struct nflog_handle *h;

static char *
mac2str (unsigned char *mac, char *strmac) {
    char *buf_cur = strmac;
    int i;
    for (i=0; i<6; i++) {
        buf_cur += sprintf (buf_cur, "%02x%c", mac[i], 
            i == 5 ? 0 : ':');
    }
    return strmac;
}

/**
 * \brief createlogrule_callback (struct nflog_g_handle *gh, struct nfgenmsg *nfmsg, struct nflog_data *nfa, void *data)
 *
 * NFLOG callback to transform the data in the received package into structured data
 * required by writing the traffic log in the main program. Taken initially from nfulnl.c
 * in the ulogd2 source code.
 *
 * \pre the callback should have been registered with 'data' pointing to a struct logrule *
 * \post the struct pointed to by 'data' contains properly fmt'ed fields
 * \param[in] gh: 
 * \param[in] nfgenmsg: 
 * \param[in] nfa: 
 * \param[in,out] data A pointer to the result struct
 * \return 0
 * \retval n.a.
 * \note n.a.
 */
static int 
createlogrule_callback(struct nflog_g_handle *gh, struct nfgenmsg *nfmsg,
        struct nflog_data *nfa, void *data)
{
    char dbgline[1024] = "";
    struct nfulnl_msg_packet_hdr *ph;
    struct nfulnl_msg_packet_hw *hw;
    char *hwhdr;
    char macstr[20];
    u_int32_t mark;
    u_int32_t indev;
    u_int32_t outdev;
    struct protoent *pe;
    struct sk_buf *skb;
    struct iphdr *iph;
    char *prefix;
    char *payload;
    int payload_len;
    struct timeval tv;
    struct log_rule *logrule_ptr = data;
    time_t when;
    char    s[256];
    char    *c;
    int     i;
    union ip_adress ip;

    memset(logrule_ptr, 0, sizeof(struct log_rule));

    /* Copy hostname in log_rule struct */
    if (gethostname (logrule_ptr->hostname, HOST_NAME_MAX) == -1) {
        (void)vrprint.debug(__FUNC__, "Error getting hostname");
        return -1;
    }

    if (!(ph = nflog_get_msg_packet_hdr (nfa))) {
        (void)vrprint.error (-1, "Error", "Can't get packet header");
        return -1;
    }


    switch (ntohs (ph->hw_protocol)) {
        case ETH_P_IP:
            (void)vrprint.debug (__FUNC__, "IPv4 packet");
            break;
        case ETH_P_ARP:
            (void)vrprint.debug (__FUNC__, "ARP packet");
            break;
        case ETH_P_IPV6:
            (void)vrprint.debug (__FUNC__, "IPv6 packet");
            break;
        default:
            (void)vrprint.debug (__FUNC__, "Protocol: 0x%04x", ntohs(ph->hw_protocol));
            break;
    }

    /* Convert MAC src and dst to strings and copy into logrule_ptr */
    if (nflog_get_msg_packet_hwhdrlen (nfa)) {
        hwhdr = nflog_get_msg_packet_hwhdr (nfa);
        mac2str (hwhdr, macstr);
        snprintf (logrule_ptr->dst_mac, sizeof (logrule_ptr->dst_mac), "[%s]", macstr);
        mac2str (hwhdr + 6, macstr);
        snprintf (logrule_ptr->src_mac, sizeof (logrule_ptr->src_mac), "[%s]", macstr);
        (void)vrprint.debug (__FUNC__, "Got hwhdrlen %u (src: %s dst: %s)", nflog_get_msg_packet_hwhdrlen (nfa), logrule_ptr->src_mac, logrule_ptr->dst_mac);
    }
    /* Copy prefix and action in log_rule struct */
    prefix = nflog_get_prefix (nfa);
    strncpy (logrule_ptr->logprefix, "vrmr:", 5);
    if (!strncmp (prefix, logrule_ptr->logprefix, 5)) {
        for (c = prefix + 6, i = 0; *c != ' '; c++, i++)
            logrule_ptr->action[i] = *c;
    } else {
        (void)vrprint.debug(__FUNC__, "Not a vrmr: prefix");
        return -1;
    }

    /* Find indev idx for pkg and translate to interface name */
    if ((indev = nflog_get_indev (nfa)) == -1) {
        (void)vrprint.error (-1, "Error", "Can't get indev idx");
        return -1;
    } else {
        if_indextoname (indev, logrule_ptr->interface_in);
        snprintf(logrule_ptr->from_int, sizeof(logrule_ptr->from_int), "in: %s", logrule_ptr->interface_out);
        (void)vrprint.debug (__FUNC__, "Found indev '%s' for idx %u", logrule_ptr->interface_in, indev);
    }

    /* Find outdev idx for pkg and translate to interface name */
    if ((outdev = nflog_get_outdev (nfa)) == -1) {
        (void)vrprint.error (-1, "Error", "Can't get outdev idx");
        return -1;
    } else {
        if_indextoname (outdev, logrule_ptr->interface_out);
        snprintf(logrule_ptr->to_int, sizeof(logrule_ptr->to_int), "out: %s", logrule_ptr->interface_out);
        (void)vrprint.debug (__FUNC__, "Found outdev '%s' for idx %u", logrule_ptr->interface_out, outdev);
    }


    if ((mark = nflog_get_nfmark (nfa)) == -1) {
        (void)vrprint.error (-1, "Error", "Can't get nfmark");
        return -1;
    } else {
        (void)vrprint.debug (__FUNC__, "Found mark: %u", mark);
    }

    if ((payload_len = nflog_get_payload (nfa, &payload)) == -1) {
        (void)vrprint.error (-1, "Error", "Can't get payload");
        return -1;
    } else {
        i = ip_hdrlen_U(payload);
        (void)vrprint.debug (__FUNC__, "Found %u bytes of payload, header length %u", payload_len, ntohs(i));
        logrule_ptr->protocol = ip_hdr_U(payload)->protocol;
        ip.saddr = ip_hdr_U(payload)->saddr;
        snprintf (logrule_ptr->src_ip, sizeof(logrule_ptr->src_ip), "%u.%u.%u.%u", ip.a[0], ip.a[1], ip.a[2], ip.a[3]);
        ip.saddr = ip_hdr_U(payload)->daddr;
        snprintf (logrule_ptr->dst_ip, sizeof(logrule_ptr->dst_ip), "%u.%u.%u.%u", ip.a[0], ip.a[1], ip.a[2], ip.a[3]);
        logrule_ptr->ttl = ip_hdr_U(payload)->ttl;
    }

    /* Put packet's timestamp in log_rule struct */
    if (nflog_get_timestamp (nfa, &tv) == -1) {
        (void)vrprint.debug (__FUNC__, "Can't get timestamp on packet: %s", strerror (errno));
        return -1;
    }
    when = tv.tv_sec;
    struct tm *tm = localtime(&when);
    strftime (s, 256, "%b %d %T", tm);
    if (sscanf (s, "%3s %2d %2d:%2d:%2d", logrule_ptr->month, &logrule_ptr->day, 
        &logrule_ptr->hour, &logrule_ptr->minute, &logrule_ptr->second) != 5) {
        (void)vrprint.debug(__FUNC__, "did not find properly formatted timestamp");
        return -1;
    }

    return 0;       /* success */
}

/**
 * \brief subscribe_nflog sets up the nflog handles and callback
 *
 * And a more detailed description of the function that doesn't fit
 * on 1 line
 *
 * \pre The preconditions of the function, which should be checked by the function
 * \post The postconditions of the function
 * \param[in] var1 The value that is used to devide
 * \param[in,out] var2 A pointer to the result, and ...
 * \return The function returns the value of the calculation.
 * \retval -1 When var1 or var2 is 0
 * \note A note that applies to the function
 */
int
subscribe_nflog (const int debuglvl, const struct vuurmuur_config *conf, struct log_rule *logrule_ptr)
{
    struct nflog_g_handle *qh;

    h = nflog_open ();
    if (!h)
    {
        (void)vrprint.error(-1, "Internal Error", "nflog_open error (in: %s:%d).", __FUNC__, __LINE__);
        return (-1);
    }

    if (nflog_bind_pf (h, AF_INET) < 0)
    {
        (void)vrprint.error(-1, "Internal Error", "nflog_bind_pf error (in: %s:%d).", __FUNC__, __LINE__);
        return (-1);
    }

    qh = nflog_bind_group (h, conf->nfgrp);
    if (!qh) {
        (void)vrprint.error(-1, "Internal Error", "nflog_bind_group error, other process attached? (in: %s:%d).", __FUNC__, __LINE__);
        return (-1);
    }

    if (nflog_set_mode (qh, NFULNL_COPY_PACKET, 0xffff) < 0)
    {
        (void)vrprint.error(-1, "Internal Error", "nflog_set_mode error %s (in; %s:%d).", strerror (errno), __FUNC__, __LINE__);
        return (-1);
    }

    nflog_callback_register (qh, &createlogrule_callback, logrule_ptr);

    fd = nflog_fd (h);

    return 0;
}

int
readnflog ()
{
    int rv;
    char buf[4096];

    if ((rv = recv (fd, buf, sizeof (buf), MSG_DONTWAIT)) == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return 0;
        } else if (errno == ENOBUFS) {
            (void)vrprint.error (-1, "ENOBUFS on recv, may need to increase netlink_socket_buffer_size (in; %s:%d)", __FUNC__, __LINE__);
            return -1;
        } else {
            (void)vrprint.error (-1, "Internal Error", "cannot recv: %s (in; %s:%d)", strerror (errno), __FUNC__, __LINE__);
            return -1;
        }
    }

    rv = nflog_handle_packet (h, buf, rv);
    (void)vrprint.debug(__FUNC__, "nflog_handle_packet returned %i", rv);
    return (1);
}
