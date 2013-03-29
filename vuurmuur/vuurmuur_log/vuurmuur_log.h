/***************************************************************************
 *   Copyright (C) 2003-2011 by Victor Julien                              *
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

#ifndef __VUURMUUR_LOG_H__
#define __VUURMUUR_LOG_H__

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <string.h>
#include <vuurmuur.h>
#include <signal.h>

#define _GNU_SOURCE
#include <getopt.h>

#include "../vuurmuur/version.h"

#define PIDFILE         "/var/run/vuurmuur_log.pid"
#define SVCNAME         "vuurmuur_log"

#ifndef HOST_NAME_MAX
#define HOST_NAME_MAX   255
#endif

/* the line starts at position 0 */
#define LINE_START      0

/*  The maximum time to wait for the next line: if the time is reached, we close the logfiles,
    and open them again. This is to prevent the program from getting confused because of
    log rotation.

    NOTE: the time is in 10th's of a second!
*/
#define MAX_WAIT_TIME   600


/* define these here so converting to gettext will be easier */
#define VR_ERR          "Error"
#define VR_INTERR       "Internal Error"
#define VR_INFO         "Info"
#define VR_WARN         "Warning"

struct log_rule
{
    char            month[4];
    int             day;

    int             hour;
    int             minute;
    int             second;

    char            hostname[HOST_NAME_MAX];
    char            logger[32];

    char            action[16];

    char            logprefix[32];

    char            interface_in[16];
    char            interface_out[16];

#ifndef IPV6_ENABLED
    char            src_ip[16];
    char            dst_ip[16];
#else
    char            src_ip[46];
    char            dst_ip[46];
    int             ipv6;
#endif /* IPV6_ENABLED */

    int             protocol;
    int             src_port;
    int             dst_port;
    int             icmp_type;
    int             icmp_code;

    char            src_mac[20]; /* 17 for mac addr, 2 for brackets, 1 for \0 */
    char            dst_mac[20];

    unsigned int    packet_len; /* length of the logged packet */

    char            syn;        /* is syn-bit set? 0: no, 1: yes */
    char            fin;        /* is fin-bit set? 0: no, 1: yes */
    char            rst;        /* is rst-bit set? 0: no, 1: yes */
    char            ack;        /* is ack-bit set? 0: no, 1: yes */
    char            psh;        /* is psh-bit set? 0: no, 1: yes */
    char            urg;        /* is urg-bit set? 0: no, 1: yes */

    unsigned int    ttl;

    char            from_name[MAX_HOST_NET_ZONE];
    char            to_name[MAX_HOST_NET_ZONE];
    char            ser_name[MAX_SERVICE];
    char            from_int[MAX_INTERFACE+5];  /* 'in: ' */
    char            to_int[MAX_INTERFACE+6];    /* 'out: ' */

    char            tcpflags[7];
};


int reopen_logfiles(const int, FILE **, FILE **);
int open_logfiles(const int, const struct vuurmuur_config *cnf, FILE **, FILE **);

int process_logrecord(struct log_rule *logrule_ptr);

/* semaphore id */
int         sem_id;
char        version_string[128];
struct vuurmuur_config conf;

#endif /* __VUURMUUR_LOG_H__ */
