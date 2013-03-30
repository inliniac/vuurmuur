/***************************************************************************
 *   Copyright (C) 2002-2007 by Victor Julien                              *
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
#include "vuurmuur.h"


static int
vrmr_insert_service_list(const int debuglvl, struct vrmr_services *services, const struct vrmr_service *ser_ptr)
{
    struct vrmr_service    *check_ser_ptr = NULL;
    int                     result = 0;
    int                     insert_here = 0;
    struct vrmr_list_node             *d_node = NULL;

    /*
        check our input
    */
    if(services == NULL || ser_ptr == NULL)
    {
        (void)vrprint.error(-1, "Internal Error", "parameter problem (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    if(services->list.len == 0)
    {
        insert_here = 1;
    }
    else
    {
        for(d_node = services->list.top; d_node && insert_here == 0; d_node = d_node->next)
        {
            if(!(check_ser_ptr = d_node->data))
            {
                (void)vrprint.error(-1, "Internal Error", "NULL pointer (in: %s).", __FUNC__);
                return(-1);
            }

            if(debuglvl >= HIGH)
                (void)vrprint.debug(__FUNC__, "ser_ptr->name: %s, check_ser_ptr->name: %s", ser_ptr->name, check_ser_ptr->name);

            result = strcmp(ser_ptr->name, check_ser_ptr->name);
            if(result <= 0)
            {
                if(debuglvl >= HIGH)
                    (void)vrprint.debug(__FUNC__, "insert here.");

                insert_here = 1;
                break;
            }
        }
    }

    if(insert_here == 1 && d_node == NULL)
    {
        if(debuglvl >= HIGH)
            (void)vrprint.debug(__FUNC__, "prepend %s", ser_ptr->name);

        /* prepend if an empty list */
        if(!(vrmr_list_prepend(debuglvl, &services->list, ser_ptr)))
        {
            (void)vrprint.error(-1, "Internal Error", "vrmr_list_prepend() failed (in: %s:%d).", __FUNC__, __LINE__);
            return(-1);
        }
    }
    else if(insert_here == 1 && d_node != NULL)
    {
        if(debuglvl >= HIGH)
            (void)vrprint.debug(__FUNC__, "insert %s", ser_ptr->name);

        /*
            insert before the current node
        */
        if(!(vrmr_list_insert_before(debuglvl, &services->list, d_node, ser_ptr)))
        {
            (void)vrprint.error(-1, "Internal Error", "vrmr_list_insert_before() failed (in: %s:%d).", __FUNC__, __LINE__);
            return(-1);
        }
    }
    else
    {
        if(debuglvl >= HIGH)
            (void)vrprint.debug(__FUNC__, "append %s", ser_ptr->name);

        /*
            append if we were bigger than all others
        */
        if(!(vrmr_list_append(debuglvl, &services->list, ser_ptr)))
        {
            (void)vrprint.error(-1, "Internal Error", "vrmr_list_append() failed (in: %s:%d).", __FUNC__, __LINE__);
            return(-1);
        }
    }

    return(0);
}


/*  vrmr_insert_service

    Inserts the service 'name' into the linked-list.

    Returncodes:
        -1: error
         0: succes
         1: service failed (maybe it is inactive?)

    The difference between error and failed is that with failed we mean an usererror,
    and by error an internal program error.
*/
int
vrmr_insert_service(const int debuglvl, struct vrmr_services *services, char *name)
{
    int                     retval = 0,
                            result = 0;
    struct vrmr_service    *ser_ptr = NULL;


    /* check our input */
    if(services == NULL || name == NULL)
    {
        (void)vrprint.error(-1, "Internal Error", "parameter problem (in: %s:%d).",
                __FUNC__, __LINE__);
        return(-1);
    }

    /* claiming the memory we need */
    if(!(ser_ptr = vrmr_service_malloc()))
    {
        (void)vrprint.error(-1, "Internal Error", "vrmr_service_malloc() failed: %s (in: %s:%d).",
                strerror(errno), __FUNC__, __LINE__);
        return(-1);
    }

    /* reading the service information */
    result = vrmr_read_service(debuglvl, name, ser_ptr);
    if(result == -1)
    {
        (void)vrprint.error(-1, "Internal Error", "vrmr_read_service() failed (in: %s:%d).",
                __FUNC__, __LINE__);
        return(-1);
    }

    /* insert into the list (sorted) */
    if(vrmr_insert_service_list(debuglvl, services, ser_ptr) < 0)
        return(-1);

    /* set the status */
    ser_ptr->status = ST_KEEP;

    if(debuglvl >= HIGH)
        (void)vrprint.debug(__FUNC__, "** end **, retval=%d", retval);

    return(retval);
}


/*  vrmr_search_service

    Function to search the ServicesList.

    It returns the pointer or a NULL-pointer if not found.
*/
void *
vrmr_search_service(const int debuglvl, const struct vrmr_services *services, char *servicename)
{
    struct vrmr_list_node             *d_node = NULL;
    struct vrmr_service    *service_ptr = NULL;


    /* safety */
    if(services == NULL || servicename == NULL)
    {
        (void)vrprint.error(-1, "Internal Error", "parameter problem (in: %s:%d).",
                __FUNC__, __LINE__);
        return(NULL);
    }

    if(debuglvl >= MEDIUM)
        (void)vrprint.debug(__FUNC__, "looking for service '%s'.", servicename);

    /* loop the list and compare */
    for(d_node = services->list.top; d_node ; d_node = d_node->next)
    {
        if(!(service_ptr = d_node->data))
        {
            (void)vrprint.error(-1, "Internal Error", "NULL pointer (in: %s:%d).",
                    __FUNC__, __LINE__);
            return(NULL);
        }

        if(strcmp(service_ptr->name, servicename) == 0)
        {
            if(debuglvl >= HIGH)
                (void)vrprint.debug(__FUNC__, "service %s found at address: %p",
                        servicename, service_ptr);

            /* return the pointer */
            return(service_ptr);
        }
    }

    /* if the value wasn't found tell the debuglog */
    if(debuglvl >= LOW)
        (void)vrprint.debug(__FUNC__, "service '%s' not found.", servicename);

    /* if we get here we didn't find what we were looking for, so return NULL */
    return(NULL);
}


/*  vrmr_read_service

    This function takes the service 'sername', and reads the info from the service.
    It ask the data from 'ask_backend', and then analyses it, splits it and puts them into the
    'struct vrmr_service_' structure.

    Returncodes:
         0: succes
        -1: error
*/
int
vrmr_read_service(const int debuglvl, char *sername, struct vrmr_service *service_ptr)
{
    int     retval = 0,
            result = 0;

    char    portrange[512] = "",    /* string in which we store the line from the backend */
            broadcast[4] = "";      /* max: 'yes' */

    /* safety check */
    if(sername == NULL || service_ptr == NULL)
    {
        (void)vrprint.error(-1, "Internal Error", "parameter problem (in: %s:%d).",
                __FUNC__, __LINE__);
        return(-1);
    }

    /* set the name in the structure */
    if(strlcpy(service_ptr->name, sername, sizeof(service_ptr->name)) >= sizeof(service_ptr->name))
    {
        (void)vrprint.error(-1, "Internal Error", "buffer overflow (in: %s:%d).",
                __FUNC__, __LINE__);
        return(-1);
    }

    /* first the active check */
    result = vrmr_check_active(debuglvl, sername, TYPE_SERVICE);
    if(result == 1)
    {
        /* active */
        service_ptr->active = TRUE;
    }
    else if(result == 0)
    {
        service_ptr->active = FALSE;
    }
    else
    {
        (void)vrprint.error(-1, "Internal Error", "vrmr_check_active() failed (in: %s:%d).",
                __FILE__, __LINE__);
        return(-1);
    }

    if(vrmr_list_setup(debuglvl, &service_ptr->PortrangeList, free) < 0)
        return(-1);

    /* first check RANGE */
    while((result = sf->ask(debuglvl, serv_backend, sername, "RANGE", portrange, sizeof(portrange), TYPE_SERVICE, 1)) == 1)
    {
        /* process */
        if(vrmr_process_portrange(debuglvl, "RANGE", portrange, service_ptr) < 0)
            retval = -1;
    }
    if(result < 0)
    {
        (void)vrprint.error(-1, "Internal Error", "sf->ask() failed (in: %s:%d).",
                __FILE__, __LINE__);
        return(-1);
    }
    /* no ranges, fallback to old behavior */
    if (service_ptr->PortrangeList.len == 0) {
        /* first check TCP */
        while((result = sf->ask(debuglvl, serv_backend, sername, "TCP", portrange, sizeof(portrange), TYPE_SERVICE, 1)) == 1)
        {
            /* process */
            if(vrmr_process_portrange(debuglvl, "TCP", portrange, service_ptr) < 0)
                retval = -1;
        }
        if(result < 0)
        {
            (void)vrprint.error(-1, "Internal Error", "sf->ask() failed (in: %s:%d).",
                    __FILE__, __LINE__);
            return(-1);
        }

        /* then check udp */
        while((result = sf->ask(debuglvl, serv_backend, sername, "UDP", portrange, sizeof(portrange), TYPE_SERVICE, 1)) == 1)
        {
            /* process */
            if(vrmr_process_portrange(debuglvl, "UDP", portrange, service_ptr) < 0)
                retval = -1;
        }
        if(result < 0)
        {
            (void)vrprint.error(-1, "Internal Error", "sf->ask() failed (in: %s:%d).",
                    __FILE__, __LINE__);
            return(-1);
        }

        /* then check icmp */
        while((result = sf->ask(debuglvl, serv_backend, sername, "ICMP", portrange, sizeof(portrange), TYPE_SERVICE, 1)) == 1)
        {
            /* process */
            if(vrmr_process_portrange(debuglvl, "ICMP", portrange, service_ptr) < 0)
                retval = -1;
        }
        if(result < 0)
        {
            (void)vrprint.error(-1, "Internal Error", "sf->ask() failed (in: %s:%d).",
                    __FILE__, __LINE__);
            return(-1);
        }

        /* then check gre */
        while((result = sf->ask(debuglvl, serv_backend, sername, "GRE", portrange, sizeof(portrange), TYPE_SERVICE, 1)) == 1)
        {
            /* process */
            if(vrmr_process_portrange(debuglvl, "GRE", portrange, service_ptr) < 0)
                retval = -1;
        }
        if(result < 0)
        {
            (void)vrprint.error(-1, "Internal Error", "sf->ask() failed (in: %s:%d).",
                    __FILE__, __LINE__);
            return(-1);
        }

        /* then check ah */
        while((result = sf->ask(debuglvl, serv_backend, sername, "AH", portrange, sizeof(portrange), TYPE_SERVICE, 1)) == 1)
        {
            /* process */
            if(vrmr_process_portrange(debuglvl, "AH", portrange, service_ptr) < 0)
                retval = -1;
        }
        if(result < 0)
        {
            (void)vrprint.error(-1, "Internal Error", "sf->ask() failed (in: %s:%d).",
                    __FILE__, __LINE__);
            return(-1);
        }

        /* then check esp */
        while((result = sf->ask(debuglvl, serv_backend, sername, "ESP", portrange, sizeof(portrange), TYPE_SERVICE, 1)) == 1)
        {
            /* process */
            if(vrmr_process_portrange(debuglvl, "ESP", portrange, service_ptr) < 0)
                retval = -1;
        }
        if(result < 0)
        {
            (void)vrprint.error(-1, "Internal Error", "sf->ask() failed (in: %s:%d).",
                    __FILE__, __LINE__);
            return(-1);
        }

        /* then check protocol 41 */
        while((result = sf->ask(debuglvl, serv_backend, sername, "PROTO_41", portrange, sizeof(portrange), TYPE_SERVICE, 1)) == 1)
        {
            /* process */
            if(vrmr_process_portrange(debuglvl, "PROTO_41", portrange, service_ptr) < 0)
                retval = -1;
        }
        if(result < 0)
        {
            (void)vrprint.error(-1, "Internal Error", "sf->ask() failed (in: %s:%d).",
                    __FILE__, __LINE__);
            return(-1);
        }
    }

    /* see if we need a helper */
    result = sf->ask(debuglvl, serv_backend, sername, "HELPER", service_ptr->helper, sizeof(service_ptr->helper), TYPE_SERVICE, 0);
    if(result < 0)
    {
        (void)vrprint.error(-1, "Internal Error", "sf->ask() failed (in: %s:%d).",
                __FILE__, __LINE__);
        return(-1);
    }

    /* check if the protocol is broadcasting */
    result=sf->ask(debuglvl, serv_backend, sername, "BROADCAST", broadcast, sizeof(broadcast), TYPE_SERVICE, 0);
    if(result < 0)
    {
        (void)vrprint.error(-1, "Internal Error", "sf->ask() failed (in: %s:%d).",
                __FILE__, __LINE__);
        return(-1);
    }
    else if(result == 0)
    {
        service_ptr->broadcast = FALSE;
    }
    else
    {
        if(strncasecmp(broadcast, "yes", 3) == 0)
        {
            if(debuglvl >= LOW)
                (void)vrprint.debug(__FUNC__, "%s is broadcasting protocol.", sername);

            service_ptr->broadcast = TRUE;
        }
        else
        {
            service_ptr->broadcast = FALSE;
        }
    }

    return(retval);
}


/* debug function */
void
vrmr_services_print_list(const struct vrmr_services *services)
{
    struct vrmr_list_node             *d_node = NULL;
    struct vrmr_service    *ser_ptr = NULL;

    fprintf(stdout, "list size: %u\n", services->list.len);

    for(d_node = services->list.top; d_node ; d_node = d_node->next)
    {
        ser_ptr = d_node->data;

        fprintf(stdout, "service: %12s, status: %2d, broadcast: %2d (%-3s), active: %2d (%-3s)\n", ser_ptr->name, ser_ptr->status, ser_ptr->broadcast, ser_ptr->broadcast ? "Yes" : "No", ser_ptr->active, ser_ptr->active ? "Yes" : "No");
    }

    return;
}


/* debug function */
void
vrmr_portrange_print_dlist(const struct vrmr_list *dlist)
{
    struct vrmr_list_node     *d_node = NULL;
    struct vrmr_portdata *port_ptr = NULL;

    // Display the linked list.
    fprintf(stdout, "list size: %u\n", dlist->len);

    for(d_node = dlist->top; d_node ; d_node = d_node->next)
    {
        port_ptr = d_node->data;

        fprintf(stdout, "protocol: %2d, dst_low: %5d, dst_high: %5d, src_low: %5d, src_high: %5d\n", port_ptr->protocol, port_ptr->dst_low, port_ptr->dst_high, port_ptr->src_low, port_ptr->src_high);
    }

    return;
}


/*  vrmr_split_portrange

    Splits a portrange like 135:139 into two integers.

    Returncodes:
         0: ok
        -1: error
*/
int
vrmr_split_portrange(char *portrange, int *lowport, int *highport)
{
    int     retval=0;
    char    range = FALSE;
    int     lp = 0, /* low port */
            hp = 0; /* high port */
    size_t  count=0,
            low_count=0,
            high_count=0;
    char    low[6] = "",
            high[6] = "";

    /* safety */
    if(portrange == NULL)
    {
        (void)vrprint.error(-1, "Internal Error", "parameter problem (in: %s:%d).",
                __FUNC__, __LINE__);
        return(-1);
    }

    /* first initialize the ports */
    *lowport = 0;
    *highport = 0;

    /* now split */
    for(; count < strlen(portrange) && low_count < sizeof(low) && high_count < sizeof(high); count++)
    {
        if (portrange[count] != ':' && !isdigit(portrange[count]))
            continue;
           
        if(portrange[count] == ':')
        {
            range = TRUE;
            low[count] = '\0';
            continue;
        }

        if(range == FALSE)
        {
            low[low_count] = portrange[count];
            low_count++;
        }
        else
        {
            high[high_count] = portrange[count];
            high_count++;
        }
    }

    low[low_count]='\0';
    high[high_count]='\0';

    /*
       convert and check. port 0 is allowed
       */
    lp = atoi(low);
    if(lp >= 0 && lp <= 65535)
        *lowport = lp;
    else
    {
        *lowport = 0;
        retval=-1;
    }

    hp = atoi(high);
    if(hp >= 0 && hp <= 65535)
        *highport = hp;
    else
    {
        *highport = 0;
        retval=-1;
    }

    return(retval);
}


/*  vrmr_process_portrange

    Splits up a portranges string and inserts the portranges into the portranges list
    of the service.

    Example portrange: 135:139*1024:65535,445*1024:65535

    You need to supply the protocol as well, so we know what ports we are talking about.

    Returncodes:
         0: ok
        -1: error
*/
int
vrmr_process_portrange(const int debuglvl, const char *proto, const char *portrange, struct vrmr_service *ser_ptr)
{
    int                 port=0,
                        range=0;

    char                current_portrange[32] = "",   /* 3+1+5+1+5+1+5+1+5+1 eg. 6,12345:56789*12345:56789 */
                        src_portrange[16] = "",
                        dst_portrange[16] = "";

    struct vrmr_portdata     *portrange_ptr = NULL;

    size_t              cur_pos=0, /* current position in the protocol string */
                        port_pos=0; /* position in portrange string */

    /*
        safety
    */
    if(!portrange || !proto || !ser_ptr)
    {
        (void)vrprint.error(-1, "Internal Error", "parameter problem (in: %s:%d).",
                __FUNC__, __LINE__);
        return(-1);
    }

    /*
        loop trough the portrange
    */
    while(strlen(portrange) >= port_pos)
    {
        current_portrange[cur_pos] = portrange[port_pos];
        cur_pos++;

        /* next portrange */
        if((portrange[port_pos] == ',') || (portrange[port_pos] == '\0'))
        {
            /* terminate current_portrange */
            current_portrange[cur_pos-1]='\0';

            /* alloc memory */
            if(!(portrange_ptr = malloc(sizeof(struct vrmr_portdata))))
            {
                (void)vrprint.error(-1, "Internal Error", "malloc() failed: %s (in: %s:%d).",
                        strerror(errno), __FUNC__, __LINE__);
                return(-1);
            }
            /* init */
            memset(portrange_ptr, 0, sizeof(struct vrmr_portdata));

            range = 0;
            /* parse new RANGE format first */
            if (strncasecmp(proto, "RANGE", 5) == 0) {
                char protostr[4] = "";
                range = 0;
                int i = 0;
                while (range < strlen(current_portrange) &&
                        i < sizeof(protostr) &&
                        current_portrange[range] != ';')
                {
                    protostr[i] = current_portrange[range];
                    i++; range++;
                }
                protostr[i] = '\0';
                portrange_ptr->protocol = atoi(protostr);
                if (portrange_ptr->protocol < 0 || portrange_ptr->protocol > 65535) {
                    (void)vrprint.error(-1, "Error", "invalid protocol '%s' (in: %s:%d).",
                            protostr, __FUNC__, __LINE__);
                }

                range++;

            } else if(strncasecmp(proto, "TCP", 3) == 0)
            {
                portrange_ptr->protocol = 6;
            }
            else if(strncasecmp(proto, "UDP", 3) == 0)
            {
                portrange_ptr->protocol = 17;
            }
            else if(strncasecmp(proto, "GRE", 3) == 0)
            {
                portrange_ptr->protocol = 47;
            }
            else if(strncasecmp(proto, "AH", 2) == 0)
            {
                portrange_ptr->protocol = 51;
            }
            else if(strncasecmp(proto, "ESP", 3) == 0)
            {
                portrange_ptr->protocol = 50;
            }
            else if(strncasecmp(proto, "ICMP", 4) == 0)
            {
                portrange_ptr->protocol = 1;
            }
            else if(strncasecmp(proto, "PROTO_41", 8) == 0)
            {
                portrange_ptr->protocol = 41;
            }
            /*
                this should never happen
            */
            else
            {
                (void)vrprint.error(-1, "Internal Error", "unknown protocol '%s' (in: %s:%d).",
                        proto, __FUNC__, __LINE__);
                return(-1);
            }

            /*
                split current_portrange to dst_portrange and src_portrange, and split both of them
            */
            port=0;
            while (range < strlen(current_portrange) &&
                    port < sizeof(dst_portrange) &&
                    current_portrange[range] != '*')
            {
                dst_portrange[port]=current_portrange[range];
                range++; port++;
            }
            dst_portrange[port]='\0';

            if(vrmr_split_portrange(dst_portrange, &portrange_ptr->dst_low, &portrange_ptr->dst_high) < 0)
            {
                free(portrange_ptr);
                return(-1);
            }

            /*
                reset port and add one to range because of the ':' in the range
            */
            port=0, range++;
            while( (current_portrange[range] != '\0') && (current_portrange[range] != '\n') )
            {
                src_portrange[port]=current_portrange[range];
                range++; port++;
            }
            src_portrange[port]='\0';

            if(vrmr_split_portrange(src_portrange, &portrange_ptr->src_low, &portrange_ptr->src_high) < 0)
            {
                free(portrange_ptr);
                return(-1);
            }

            /*
                if all went well, insert the portrange into the list, and update the counter
                now insert the entry into the list
            */
            if(vrmr_list_append(debuglvl, &ser_ptr->PortrangeList, portrange_ptr) == NULL)
            {
                (void)vrprint.error(-1, "Internal Error", "vrmr_list_append() failed (in: %s:%d).",
                        __FUNC__, __LINE__);
                return(-1);
            }

            if(debuglvl >= HIGH)
                (void)vrprint.debug(__FUNC__, "proto: %s, dl: %d, dh: %d, sl: %d, sh: %d",
                        proto, portrange_ptr->dst_low,
                        portrange_ptr->dst_high, portrange_ptr->src_low,
                        portrange_ptr->src_high);

            /* reset cur_pos */
            cur_pos = 0;
        }

        port_pos++;
    }

    return(0);
}


/*  vrmr_destroy_serviceslist

*/
void
vrmr_destroy_serviceslist(const int debuglvl, struct vrmr_services *services)
{
    struct vrmr_list_node             *d_node = NULL;
    struct vrmr_service    *ser_ptr = NULL;

    /* safety */
    if(!services)
    {
        (void)vrprint.error(-1, "Internal Error", "parameter problem (in: %s:%d).",
                __FUNC__, __LINE__);
        return;
    }

    /* first destroy all PortrangeLists */
    for(d_node = services->list.top; d_node ; d_node = d_node->next)
    {
        if(!(ser_ptr = d_node->data))
        {
            (void)vrprint.error(-1, "Internal Error", "NULL pointer (in: %s:%d).",
                    __FUNC__, __LINE__);
            return;
        }

        vrmr_list_cleanup(debuglvl, &ser_ptr->PortrangeList);
    }

    /* then the list itself */
    vrmr_list_cleanup(debuglvl, &services->list);
}


/*  vrmr_new_service

    Creates a new service.

    Returncodes:
         0: ok
        -1: error
*/
int
vrmr_new_service(const int debuglvl, struct vrmr_services *services, char *sername, int sertype)
{
    int                     retval = 0,
                            result = 0;
    struct vrmr_service    *ser_ptr = NULL;

    /* safety */
    if(!sername || !services)
    {
        (void)vrprint.error(-1, "Internal Error", "parameter problem (in: %s:%d).",
                __FUNC__, __LINE__);
        return(-1);
    }

    if((vrmr_search_service(debuglvl, services, sername) != NULL))
    {
        (void)vrprint.error(-1, "Internal Error", "service %s already exists (in: %s:%d).",
                sername, __FUNC__, __LINE__);
        return(-1);
    }

    if(!(ser_ptr = vrmr_service_malloc()))
        return(-1);

    /* set the bare minimum */
    if(strlcpy(ser_ptr->name, sername, sizeof(ser_ptr->name)) > sizeof(ser_ptr->name))
    {
        (void)vrprint.error(-1, "Internal Error", "buffer overflow (in: %s:%d).",
                __FUNC__, __LINE__);
        return(-1);
    }
    if(vrmr_list_setup(debuglvl, &ser_ptr->PortrangeList, free))
        return(-1);

    /* insert into the list */
    if(vrmr_insert_service_list(debuglvl, services, ser_ptr) < 0)
    {
        (void)vrprint.error(-1, "Internal Error", "vrmr_insert_service_list() failed (in: %s:%d).",
                __FUNC__, __LINE__);
        return(-1);
    }

    if(debuglvl >= MEDIUM)
        (void)vrprint.debug(__FUNC__, "calling sf->add for '%s'.", sername);

    /* add to the backend */
    result = sf->add(debuglvl, serv_backend, sername, sertype);
    if(result < 0)
    {
        (void)vrprint.error(-1, "Internal Error", "sf->add() failed (in: %s:%d).",
                __FUNC__, __LINE__);
        return(-1);
    }

    if(debuglvl >= HIGH)
        (void)vrprint.debug(__FUNC__, "calling sf->add for '%s' succes.", sername);

    /* set active and broadcast */
    result = sf->tell(debuglvl, serv_backend, ser_ptr->name, "ACTIVE", ser_ptr->active ? "Yes" : "No", 1, TYPE_SERVICE);
    if(result < 0)
    {
        (void)vrprint.error(-1, "Internal Error", "sf->tell() failed (in: %s:%d).",
                __FUNC__, __LINE__);
        return(-1);
    }
    result = sf->tell(debuglvl, serv_backend, ser_ptr->name, "BROADCAST", ser_ptr->broadcast ? "Yes" : "No", 1, TYPE_SERVICE);
    if(result < 0)
    {
        (void)vrprint.error(-1, "Internal Error", "sf->tell() failed (in: %s:%d).",
                __FUNC__, __LINE__);
        return(-1);
    }

    return(retval);
}


/*  vrmr_delete_service

    Deletes a service from the backend and from memory.

    Returncodes:
         0: ok
        -1: error

    TODO: memory is not freed?
*/
int
vrmr_delete_service(const int debuglvl, struct vrmr_services *services, char *sername, int sertype)
{
    struct vrmr_service *ser_list_ptr = NULL;
    struct vrmr_list_node *d_node = NULL;

    /* safety */
    if(!sername || !services)
    {
        (void)vrprint.error(-1, "Internal Error", "parameter problem (in: %s:%d).",
                __FUNC__, __LINE__);
        return(-1);
    }

    /* this is a bit overkill right now, but when we start using hash-searching, it wont be */
    if((vrmr_search_service(debuglvl, services, sername) == NULL))
    {
        (void)vrprint.error(-1, "Internal Error", "service %s not found in memory (in: %s:%d).",
                sername, __FUNC__, __LINE__);
        return(-1);
    }

    /* delete from backend */
    if(sf->del(debuglvl, serv_backend, sername, sertype, 1) < 0)
        return(-1);

    /* now look for the service in the list */
    for(d_node = services->list.top; d_node; d_node = d_node->next)
    {
        if(!(ser_list_ptr = d_node->data))
        {
            (void)vrprint.error(-1, "Internal Error", "NULL pointer (in: %s:%d).",
                    __FUNC__, __LINE__);
            return(-1);
        }

        if(strcmp(sername, ser_list_ptr->name) == 0)
        {
            if(vrmr_list_remove_node(debuglvl, &services->list, d_node) < 0)
            {
                (void)vrprint.error(-1, "Internal Error", "vrmr_list_remove_node() failed (in: %s:%d).",
                        __FUNC__, __LINE__);
                return(-1);
            }

            /* we're done */
            return(0);
        }
    }

    /* we should never get here */
    (void)vrprint.error(-1, "Internal Error", "service %s not found in memory (in: %s:%d).",
            sername, __FUNC__, __LINE__);
    return(-1);
}


int
vrmr_validate_servicename(const int debuglvl, const char *servicename, regex_t *reg_ex, char quiet)
{
    /* safety */
    if(servicename == NULL || reg_ex == NULL)
    {
        (void)vrprint.error(-1, "Internal Error", "parameter problem (in: %s:%d).",
                __FUNC__, __LINE__);
        return(-1);
    }

    if(debuglvl >= MEDIUM)
        (void)vrprint.debug(__FUNC__, "checking: %s", servicename);

    /* exec the regex */
    if(regexec(reg_ex, servicename, 0, NULL, 0) != 0)
    {
        if(debuglvl >= MEDIUM)
            (void)vrprint.debug(__FUNC__, "%s is invalid", servicename);

        return(-1);
    }

    /* ignore make files in the services dir */
    if (strncasecmp(servicename, "Makefile", 8) == 0) {
        if(debuglvl >= MEDIUM)
            (void)vrprint.debug(__FUNC__, "%s is invalid", servicename);
        return(-1);
    }

    if(debuglvl >= MEDIUM)
        (void)vrprint.debug(__FUNC__, "%s is valid", servicename);

    return(0);
}


int
vrmr_services_save_portranges(const int debuglvl, struct vrmr_service *ser_ptr)
{
    struct vrmr_portdata *port_ptr = NULL;
    char            prot_format[32] = "",
                    frmt_src[16] = "",
                    frmt_dst[16] = "";
    struct vrmr_list_node     *d_node = NULL;
    char            overwrite = 1;

    /* safety */
    if(ser_ptr == NULL)
    {
        (void)vrprint.error(-1, "Internal Error", "parameter problem (in: %s:%d).",
                __FUNC__, __LINE__);
        return(-1);
    }

    /* empty list, so clear all */
    if(ser_ptr->PortrangeList.len == 0)
    {
        if(sf->tell(debuglvl, serv_backend, ser_ptr->name, "RANGE", "", 1, TYPE_SERVICE) < 0)
        {
            (void)vrprint.error(-1, "Internal Error", "sf->tell() failed (in: %s:%d).",
                    __FUNC__, __LINE__);
            return(-1);
        }
    }
    else
    {
        /* safe the ports */
        for(d_node = ser_ptr->PortrangeList.top; d_node; d_node = d_node->next)
        {
            if(!(port_ptr = d_node->data))
            {
                (void)vrprint.error(-1, "Internal Error", "NULL pointer (in: %s:%d).",
                        __FUNC__, __LINE__);
                return(-1);
            }

            snprintf(prot_format, sizeof(prot_format), "%d;", port_ptr->protocol);

            /* tcp and udp*/
            if(port_ptr->protocol == 6 || port_ptr->protocol == 17)
            {
                /* assemble the string */
                if(port_ptr->dst_high == 0)
                    snprintf(frmt_dst, sizeof(frmt_dst), "%d", port_ptr->dst_low);
                else
                    snprintf(frmt_dst, sizeof(frmt_dst), "%d:%d", port_ptr->dst_low, port_ptr->dst_high);

                if(port_ptr->src_high == 0)
                    snprintf(frmt_src, sizeof(frmt_src), "%d", port_ptr->src_low);
                else
                    snprintf(frmt_src, sizeof(frmt_src), "%d:%d", port_ptr->src_low, port_ptr->src_high);

                if(strlcat(prot_format, frmt_dst, sizeof(prot_format)) >= sizeof(prot_format))
                {
                    (void)vrprint.error(-1, "Internal Error", "string "
                            "overflow (in: %s:%d).", __FUNC__, __LINE__);
                    return(-1);
                }
                if(strlcat(prot_format, "*", sizeof(prot_format)) >= sizeof(prot_format))
                {
                    (void)vrprint.error(-1, "Internal Error", "string "
                            "overflow (in: %s:%d).", __FUNC__, __LINE__);
                    return(-1);
                }
                if(strlcat(prot_format, frmt_src, sizeof(prot_format)) >= sizeof(prot_format))
                {
                    (void)vrprint.error(-1, "Internal Error", "string "
                            "overflow (in: %s:%d).", __FUNC__, __LINE__);
                    return(-1);
                }

                /* write to the backend */
                if(sf->tell(debuglvl, serv_backend, ser_ptr->name, "RANGE", prot_format, overwrite, TYPE_SERVICE) < 0)
                {
                    (void)vrprint.error(-1, "Internal Error", "sf->tell() failed (in: %s:%d).",
                            __FUNC__, __LINE__);
                    return(-1);
                }
            }
            /* icmp */
            else if(port_ptr->protocol == 1)
            {
                /* assemble the string */
                if(port_ptr->dst_high == -1)
                    snprintf(frmt_dst, sizeof(frmt_dst), "%d", port_ptr->dst_low);
                else
                    snprintf(frmt_dst, sizeof(frmt_dst), "%d:%d", port_ptr->dst_low, port_ptr->dst_high);

                if(port_ptr->src_high == -1)
                    snprintf(frmt_src, sizeof(frmt_src), "%d", port_ptr->src_low);
                else
                    snprintf(frmt_src, sizeof(frmt_src), "%d:%d", port_ptr->src_low, port_ptr->src_high);

                if(strlcat(prot_format, frmt_dst, sizeof(prot_format)) >= sizeof(prot_format))
                {
                    (void)vrprint.error(-1, "Internal Error", "string "
                            "overflow (in: %s:%d).", __FUNC__, __LINE__);
                    return(-1);
                }
                if(strlcat(prot_format, "*",      sizeof(prot_format)) >= sizeof(prot_format))
                {
                    (void)vrprint.error(-1, "Internal Error", "string "
                            "overflow (in: %s:%d).", __FUNC__, __LINE__);
                    return(-1);
                }
                if(strlcat(prot_format, frmt_src, sizeof(prot_format)) >= sizeof(prot_format))
                {
                    (void)vrprint.error(-1, "Internal Error", "string "
                            "overflow (in: %s:%d).", __FUNC__, __LINE__);
                    return(-1);
                }

                /* write to the backend */
                if(sf->tell(debuglvl, serv_backend, ser_ptr->name, "RANGE", prot_format, overwrite, TYPE_SERVICE) < 0)
                {
                    (void)vrprint.error(-1, "Internal Error", "sf->tell() failed (in: %s:%d).",
                            __FUNC__, __LINE__);
                    return(-1);
                }
            }
            else
            {
                /* assemble the string */
                if(strlcat(prot_format, "0*0", sizeof(prot_format)) >= sizeof(prot_format))
                {
                    (void)vrprint.error(-1, "Internal Error", "string "
                            "overflow (in: %s:%d).", __FUNC__, __LINE__);
                    return(-1);
                }

                /* write to the backend */
                if(sf->tell(debuglvl, serv_backend, ser_ptr->name, "RANGE", prot_format, overwrite, TYPE_SERVICE) < 0)
                {
                    (void)vrprint.error(-1, "Internal Error", "sf->tell() failed (in: %s:%d).",
                            __FUNC__, __LINE__);
                    return(-1);
                }
            }

            overwrite = 0;
        }
    }

    return(0);
}


/*
    returns 0 if invalid
        1 if valid
*/
int
vrmr_valid_tcpudp_port(const int debuglvl, int port)
{
    if(port < 0 || port > 65535)
        return(0);

    return(1);
}


/*  vrmr_init_services

    Loads all services in memory.

    Returncodes:
         0: succes
        -1: error
*/
int
vrmr_init_services(const int debuglvl, struct vrmr_services *services, struct vrmr_regex *reg)
{
    int     retval=0,
            result=0;
    char    name[MAX_SERVICE]="";
    int     zonetype=0;

    /* safety */
    if(services == NULL || reg == NULL)
    {
        (void)vrprint.error(-1, "Internal Error", "parameter problem (in: %s:%d).",
                __FUNC__, __LINE__);
        return(-1);
    }
    /* init */
    memset(services, 0, sizeof(*services));

    /* setup the list */
    if(vrmr_list_setup(debuglvl, &services->list, free) < 0)
    {
        (void)vrprint.error(-1, "Internal Error", "vrmr_list_setup() failed (in: %s:%d).",
                __FUNC__, __LINE__);
        return(-1);
    }

    /*
        now loop trough the list and insert
    */
    while(sf->list(debuglvl, serv_backend, name, &zonetype, CAT_SERVICES) != NULL)
    {
        if(debuglvl >= MEDIUM)
            (void)vrprint.debug(__FUNC__, "loading service '%s' ...", name);

        /* but first validate the name */
        if(vrmr_validate_servicename(debuglvl, name, reg->servicename, VALNAME_VERBOSE) == 0)
        {
            /* now call vrmr_insert_service, which will gather the info and insert it into the list */
            result = vrmr_insert_service(debuglvl, services, name);
            if(result == 0)
            {
                if(debuglvl >= LOW)
                    (void)vrprint.debug(__FUNC__, "loading service succes: '%s'.", name);
            }
            else if(result == 1)
            {
                /* we failed, but non-fatal (e.g. inactive) */
                if(debuglvl >= LOW)
                    (void)vrprint.debug(__FUNC__, "loading service failed with a non fatal failure: '%s'.", name);
            }
            else
            {
                /* failed with fatal error */
                (void)vrprint.error(-1, "Internal Error", "vrmr_insert_service() failed (in: %s:%d).",
                        __FUNC__, __LINE__);
                return(-1);
            }
        }
    }

    return(retval);
}


/*
    returncodes:
         1: ok
         0: warning (set inactive)
        -1: error
*/
int
vrmr_services_check(const int debuglvl, struct vrmr_service *ser_ptr)
{
    int retval = 1;

    /* safety first */
    if(ser_ptr == NULL)
    {
        (void)vrprint.error(-1, "Internal Error", "parameter problem (in: %s:%d).",
                __FUNC__, __LINE__);
        return(-1);
    }

    if(ser_ptr->PortrangeList.len == 0)
    {
        (void)vrprint.warning("Warning", "no portranges/protocols defined in service '%s'.",
                ser_ptr->name);
        retval = 0;
    }

    return(retval);
}


/*  load_services

    calls vrmr_init_services and does some checking

    returncodes:
         0: ok
        -1: error
*/
int
vrmr_services_load(const int debuglvl, struct vrmr_services *services, struct vrmr_regex *reg)
{
    int                     result = 0;
    struct vrmr_list_node             *d_node = NULL;
    struct vrmr_service    *ser_ptr = NULL;


    (void)vrprint.info("Info", "Loading services...");

    result = vrmr_init_services(debuglvl, services, reg);
    if(result == -1)
    {
        (void)vrprint.error(-1, "Error", "Loading services failed.");
        return(-1);
    }

    for(d_node = services->list.top; d_node; d_node = d_node->next)
    {
        ser_ptr = d_node->data;
        if(ser_ptr == NULL)
        {
            (void)vrprint.error(-1, "Internal Error", "NULL pointer (in: %s:%d).",
                    __FUNC__, __LINE__);
            return(-1);
        }

        result = vrmr_services_check(debuglvl, ser_ptr);
        if(result == -1)
            return(-1);
        else if(result == 0)
        {
            (void)vrprint.info("Info", "Service '%s' has been deactivated because of errors while checking it.",
                    ser_ptr->name);
            ser_ptr->active = FALSE;
        }
    }

    (void)vrprint.info("Info", "Loading services succesfull.");
    return(0);
}
