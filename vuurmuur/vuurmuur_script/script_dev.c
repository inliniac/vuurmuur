/***************************************************************************
 *   Copyright (C) 2006 by Victor Julien                                   *
 *   victor@nk.nl                                                          *
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

#include "vuurmuur_script.h"
#include <net/if.h>     /* used for getting interface info from the system */
#include <sys/ioctl.h>  /* used for getting interface info from the system */


/* create_broadcast_ip

    For broadcasting protocols we need an ipaddress to broadcast to.
    This function creates this ipaddress.

    Returncodes:
     0: ok
    -1: error
*/
int
create_network_ip(const int debuglvl, char *ipaddress, char *netmask, char *network_ip, size_t size)
{
    int retval=0;

    struct in_addr ip;
    struct in_addr net;     /* the network address against we want to check */
    struct in_addr mask;    /* the netmask of the network */
//    struct in_addr broad;   /* the broadcast address of this network */

    unsigned long int netmaskvalue=0;
//    unsigned long int networkvalue=0;

    if(inet_aton(netmask, &mask) == 0)
    {
        (void)vrprint.error(-1, "Error", "invalid netmask: '%s' "
            "(in: %s:%d).", netmask, __FUNC__, __LINE__);
        return(-1);
    }

    netmaskvalue = ntohl(mask.s_addr);

    if(debuglvl >= HIGH)
        (void)vrprint.debug(__FUNC__, "netmask = %s", inet_ntoa(mask));

    if(inet_aton(ipaddress, &ip) == 0)
    {
        (void)vrprint.error(-1, "Error", "invalid ipaddress: '%s' "
            "(in: %s:%d).", netmask, __FUNC__, __LINE__);
        return(-1);
    }

    if(debuglvl >= HIGH)
        (void)vrprint.debug(__FUNC__, "ipaddress = %s", inet_ntoa(ip));

    net = ip;
    net.s_addr &= ntohl(netmaskvalue);

    if(debuglvl >= HIGH)
        (void)vrprint.debug(__FUNC__, "network = %s", inet_ntoa(net));

    if(strlcpy(network_ip, inet_ntoa(net), size) >= size)
    {
        (void)vrprint.error(-1, "Internal Error", "string overflow "
            "(in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    return(retval);
}


/*  get_dynamic_ip

    partly ripped from Net-tools 1.60 (c) Phil Blundell philb@gnu.org and
    Bernd Eckenfels net-tools@lina.inka.de

    Returncodes:
        1: ok
        0: not found
        -1: error
 */
int
script_list_devices(const int debuglvl)
{
    int                 numreqs = 30;
    struct ifconf       ifc;
    struct ifreq        *ifr_ptr = NULL,
                        ifr_struct;
    int                 n;
    int                 sockfd = 0;
    char                ipaddress[16] = "",
                        netmask[16] = "",
                        broadcast[16] = "",
                        network[16] = "";
    struct sockaddr     *sa = NULL;
    struct sockaddr_in  *sin = NULL;

    /* open a socket for ioctl */
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if(sockfd == -1)
    {
        (void)vrprint.error(-1, "Error", "couldn't open socket: %s "
            "(in: %s:%d).", strerror(errno), __FUNC__, __LINE__);
        return(-1);
    }

    /* initialize the buf otherwise realloc will freak out (read segv) */
    ifc.ifc_buf = NULL;
    for (;;)
    {
        ifc.ifc_len = (int)(sizeof(struct ifreq) * numreqs);
        /* get some mem */
        if(!(ifc.ifc_buf = realloc(ifc.ifc_buf, (size_t)ifc.ifc_len)))
        {
            (void)vrprint.error(-1, "Error", "realloc failed: %s "
                "(in: %s:%d).", strerror(errno),
                __FUNC__, __LINE__);
            (void)close(sockfd);

            return(-1);
        }

        /* get the interfaces from the system */
        if(ioctl(sockfd, SIOCGIFCONF, &ifc) < 0)
        {
            (void)vrprint.error(-1, "Error", "ioctl(SIOCGIFCONF) "
                "failed: %s (in: %s:%d).", strerror(errno),
                __FUNC__, __LINE__);
            free(ifc.ifc_buf);
            (void)close(sockfd);

            return(-1);
        }
        if(ifc.ifc_len == (int)(sizeof(struct ifreq) * numreqs))
        {
            /* assume it overflowed and try again */
            numreqs += 10;
            continue;
        }
        break;
    }

    ifr_ptr = ifc.ifc_req;
    for(n = 0; n < ifc.ifc_len; n += sizeof(struct ifreq))
    {
        if(debuglvl >= HIGH)
            (void)vrprint.debug(__FUNC__, "ifr_ptr->ifr_name: '%s'.", ifr_ptr->ifr_name);

        if(strlcpy(ifr_struct.ifr_name, ifr_ptr->ifr_name, sizeof(ifr_struct.ifr_name)) >= sizeof(ifr_struct.ifr_name))
        {
            (void)vrprint.error(-1, "Error", "buffer overflow "
                "(in: %s:%d).", __FUNC__, __LINE__);
            (void)close(sockfd);
            free(ifc.ifc_buf);
            return(-1);
        }

        printf("%s ", ifr_ptr->ifr_name);

        /* we only care about IPv4 */
        ifr_struct.ifr_addr.sa_family = AF_INET;

        /* cast to a socketaddr */
        sa = &ifr_struct.ifr_addr;

        /* get the ipaddress */
        if(ioctl(sockfd, SIOCGIFADDR, &ifr_struct) == 0)
        {
            sin = (struct sockaddr_in *)sa;

            /* get the ipaddress into a string */
            if(inet_ntop(AF_INET, &sin->sin_addr, ipaddress, (socklen_t)sizeof(ipaddress)) == NULL)
            {
                (void)vrprint.error(-1, "Error", "getting "
                    "ipaddress for device '%s' failed: %s "
                    "(in: %s:%d).", ifr_ptr->ifr_name,
                    strerror(errno), __FUNC__, __LINE__);

                (void)close(sockfd);
                free(ifc.ifc_buf);

                return(-1);
            }

            /* print to the screen */
            printf("%s ", ipaddress);
        }
        else
        {
            /* print to the screen */
            printf("error ");
        }

        /* netmask */
        if(ioctl(sockfd, SIOCGIFNETMASK, &ifr_struct) == 0)
        {
            sin = (struct sockaddr_in *)sa;

            /* get the ipaddress into a string */
            if(inet_ntop(AF_INET, &sin->sin_addr, netmask, (socklen_t)sizeof(ipaddress)) == NULL)
            {
                (void)vrprint.error(-1, "Error", "getting "
                    "ipaddress for device '%s' failed: %s "
                    "(in: %s:%d).", ifr_ptr->ifr_name,
                    strerror(errno), __FUNC__, __LINE__);

                (void)close(sockfd);
                free(ifc.ifc_buf);

                return(-1);
            }

            /* print to the screen */
            printf("%s ", netmask);
        }
        else
        {
            /* print to the screen */
            printf("error ");
        }

        /* network address */
        if(create_network_ip(debuglvl, ipaddress, netmask, network, sizeof(network)) == 0)
        {
            /* print to the screen */
            printf("%s ", network);
        }
        else
        {
            /* print to the screen */
            printf("error ");
        }

        /* broadcast */
        if(ioctl(sockfd, SIOCGIFBRDADDR, &ifr_struct) == 0)
        {
            sin = (struct sockaddr_in *)sa;

            /* get the ipaddress into a string */
            if(inet_ntop(AF_INET, &sin->sin_addr, broadcast, (socklen_t)sizeof(ipaddress)) == NULL)
            {
                (void)vrprint.error(-1, "Error", "getting "
                    "broadcast for device '%s' failed: %s "
                    "(in: %s:%d).", ifr_ptr->ifr_name,
                    strerror(errno), __FUNC__, __LINE__);

                (void)close(sockfd);
                free(ifc.ifc_buf);

                return(-1);
            }

            /* print to the screen */
            printf("%s ", broadcast);
        }
        else
        {
            /* print to the screen */
            printf("error ");
        }

        /* newline char */
        printf("\n");

        ifr_ptr++;
    }

    (void)close(sockfd);
    free(ifc.ifc_buf);
    return(0);
}
