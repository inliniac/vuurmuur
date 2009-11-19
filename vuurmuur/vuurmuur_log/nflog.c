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

static int fd;
static struct nflog_handle *h;

static int 
cb(struct nflog_g_handle *gh, struct nfgenmsg *nfmsg,
        struct nflog_data *nfa, void *data)
{
    char dbgline[1024] = "";
    struct nfulnl_msg_packet_hdr *ph;
    u_int32_t mark;
    u_int32_t indev;
    u_int32_t outdev;
    char *prefix;
    char *payload;
    int payload_len;
    struct logrule *logrule_ptr = data;

    memset(logrule_ptr, 0, sizeof(struct log_rule));

    ph = nflog_get_msg_packet_hdr (nfa);

    mark = nflog_get_nfmark (nfa);

    indev = nflog_get_indev (nfa);

    outdev = nflog_get_outdev (nfa);

    prefix = nflog_get_prefix (nfa);

    payload_len = nflog_get_payload (nfa, &payload);

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

    nflog_callback_register (qh, &cb, logrule_ptr);

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
            (void)vrprint.debug(__FUNC__, "wouldblock");
            return 0;
        } else if (errno == ENOBUFS) {
            (void)vrprint.error (-1, "ENOBUFS on recv, may need to increase netlink_socket_buffer_size (in; %s:%d)", __FUNC__, __LINE__);
            return -1;
        } else {
            (void)vrprint.error (-1, "Internal Error", "cannot recv: %s (in; %s:%d)", strerror (errno), __FUNC__, __LINE__);
            return -1;
        }
    }

    nflog_handle_packet (h, buf, rv);
    return (1);
}
