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

#include <libnetfilter_log/libnetfilter_log.h>

static int 
print_pkt(struct nflog_data *ldata)
{
    struct nfulnl_msg_packet_hdr *ph = nflog_get_msg_packet_hdr(ldata);
    u_int32_t mark = nflog_get_nfmark(ldata);
    u_int32_t indev = nflog_get_indev(ldata);
    u_int32_t outdev = nflog_get_outdev(ldata);
    char *prefix = nflog_get_prefix(ldata);
    void *payload;
    int payload_len = nflog_get_payload(ldata, payload);

    if (ph) {
        printf("hw_protocol=0x%04x hook=%u ",
            ntohs(ph->hw_protocol), ph->hook);
    }

    printf("mark=%u ", mark);

    if (indev > 0)
        printf("indev=%u ", indev);

    if (outdev > 0)
        printf("outdev=%u ", outdev);


    if (prefix) {
        printf("prefix=\"%s\" ", prefix);
    }
    if (payload_len >= 0)
        printf("payload_len=%d ", payload_len);

    fputc('\n', stdout);
    return 0;
}

static int 
cb(struct nflog_g_handle *gh, struct nfgenmsg *nfmsg,
        struct nflog_data *nfa, void *data)
{
    print_pkt(nfa);
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
subscribe_nflog (const int debuglvl, const struct vuurmuur_config *conf)
{
    struct nflog_handle *h;
    struct nflog_g_handle *qh;

    (void)vrprint.debug(__FUNC__, "Calling nflog_open");

    if (!(h = nflog_open()))
    {
        (void)vrprint.error(-1, "Internal Error", "nflog_open error (in: %s:%d).", __FUNC__, __LINE__);
        return (-1);
    }

    (void)vrprint.debug(__FUNC__, "Calling nflog_bind_ph");

    if (nflog_bind_pf(h, AF_INET) < 0)
    {
        (void)vrprint.error(-1, "Internal Error", "nflog_bind_pf error (in: %s:%d).", __FUNC__, __LINE__);
        return (-1);
    }

    (void)vrprint.debug(__FUNC__, "nflog_bind_group to %u", conf->nfgrp);
    if (!(qh = nflog_bind_group (h, conf->nfgrp))) {
        (void)vrprint.error(-1, "Internal Error", "nflog_bind_group error (in: %s:%d).", __FUNC__, __LINE__);
        return (-1);
    }

    return 0;
}

int
readnflog ()
{
    return (-1);
}
