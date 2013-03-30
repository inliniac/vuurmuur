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
vrmr_insert_interface_list(const int debuglvl, struct vrmr_interfaces *interfaces,
            const struct vrmr_interface *iface_ptr)
{
    struct vrmr_interface   *check_iface_ptr = NULL;
    int                     result = 0;
    int                     insert_here = 0;
    struct vrmr_list_node             *d_node = NULL;

    /* check our input */
    if(interfaces == NULL || iface_ptr == NULL)
    {
        (void)vrprint.error(-1, "Internal Error", "parameter problem "
                "(in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    if(interfaces->list.len == 0)
    {
        insert_here = 1;
    }
    else
    {
        for(    d_node = interfaces->list.top;
                d_node && insert_here == 0;
                d_node = d_node->next)
        {
            if(!(check_iface_ptr = d_node->data))
            {
                (void)vrprint.error(-1, "Internal Error",
                        "NULL pointer (in: %s:%d).",
                        __FUNC__, __LINE__);
                return(-1);
            }

            if(debuglvl >= HIGH)
                (void)vrprint.debug(__FUNC__, "iface_ptr->name: %s, "
                        "check_iface_ptr->name: %s",
                        iface_ptr->name, check_iface_ptr->name);

            result = strcmp(iface_ptr->name, check_iface_ptr->name);
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
            (void)vrprint.debug(__FUNC__, "prepend %s", iface_ptr->name);

        /* prepend if an empty list */
        if(!(vrmr_list_prepend(debuglvl, &interfaces->list, iface_ptr)))
        {
            (void)vrprint.error(-1, "Internal Error",
                    "vrmr_list_prepend() failed (in: %s:%d).",
                    __FUNC__, __LINE__);
            return(-1);
        }
    }
    else if(insert_here == 1 && d_node != NULL)
    {
        if(debuglvl >= HIGH)
            (void)vrprint.debug(__FUNC__, "insert %s", iface_ptr->name);

        /*
            insert before the current node
        */
        if(!(vrmr_list_insert_before(debuglvl, &interfaces->list, d_node, iface_ptr)))
        {
            (void)vrprint.error(-1, "Internal Error",
                    "vrmr_list_insert_before() failed (in: %s:%d).",
                    __FUNC__, __LINE__);
            return(-1);
        }
    }
    else
    {
        if(debuglvl >= HIGH)
            (void)vrprint.debug(__FUNC__, "append %s", iface_ptr->name);

        /*
            append if we were bigger than all others
        */
        if(!(vrmr_list_append(debuglvl, &interfaces->list, iface_ptr)))
        {
            (void)vrprint.error(-1, "Internal Error",
                    "vrmr_list_append() failed (in: %s:%d).",
                    __FUNC__, __LINE__);
            return(-1);
        }
    }

    return(0);
}


/*  search_interface

    Function to search the InterfacesList. This is a very slow
    function. It worst case performance is O(n) where 'n' is the
    size of the list.

    It returns the pointer or a NULL-pointer if not found.
*/
void *
vrmr_search_interface(const int debuglvl, const struct vrmr_interfaces *interfaces, const char *name)
{
    struct vrmr_list_node             *d_node = NULL;
    struct vrmr_interface   *iface_ptr = NULL;

    /* safety check */
    if(name == NULL || interfaces == NULL)
    {
        (void)vrprint.error(-1, "Internal Error", "parameter problem "
            "(in: %s:%d).", __FUNC__, __LINE__);
        return(NULL);
    }

    if(debuglvl >= HIGH)
        (void)vrprint.debug(__FUNC__, "looking for "
            "interface '%s'.", name);

    /*
        dont bother searching a empty list
    */
    if(interfaces->list.len == 0)
        return(NULL);

    /*
        loop trough the list and compare the names
    */
    for(d_node = interfaces->list.top; d_node; d_node = d_node->next)
    {
        if(!(iface_ptr = d_node->data))
        {
            (void)vrprint.error(-1, "Internal Error", "NULL "
                    "pointer (in: %s:%d).", __FUNC__, __LINE__);
            return(NULL);
        }

        if(strcmp(iface_ptr->name, name) == 0)
        {
            /* Found! */
            if(debuglvl >= HIGH)
                (void)vrprint.debug(__FUNC__, "Interface '%s' "
                        "found!", name);

            /* return the pointer we found */
            return(iface_ptr);
        }
    }

    /* if we get here, the interface was not found, so return NULL */
    if(debuglvl >= LOW)
        (void)vrprint.debug(__FUNC__, "interface '%s' not found.", name);

    return(NULL);
}


/*

*/
void *
vrmr_search_interface_by_ip(const int debuglvl, struct vrmr_interfaces *interfaces, const char *ip)
{
    struct vrmr_list_node             *d_node = NULL;
    struct vrmr_interface   *iface_ptr = NULL;

    /* safety check */
    if(ip == NULL || interfaces == NULL)
    {
        (void)vrprint.error(-1, "Internal Error", "parameter problem "
            "(in: %s:%d).", __FUNC__, __LINE__);
        return(NULL);
    }

    if(debuglvl >= HIGH)
        (void)vrprint.debug(__FUNC__, "looking for interface "
            "with ip '%s'.", ip);

    /*
        dont bother searching a empty list
    */
    if(interfaces->list.len == 0)
        return(NULL);

    /*
        loop trough the list and compare the names
    */
    for(d_node = interfaces->list.top; d_node; d_node = d_node->next)
    {
        if(!(iface_ptr = d_node->data))
        {
            (void)vrprint.error(-1, "Internal Error", "NULL "
                    "pointer (in: %s:%d).", __FUNC__, __LINE__);
            return(NULL);
        }

        if(strcmp(iface_ptr->ipv4.ipaddress, ip) == 0)
        {
            /* Found! */
            if(debuglvl >= HIGH)
                (void)vrprint.debug(__FUNC__, "Interface with "
                        "ip '%s' found!", ip);

            /* return the pointer we found */
            return(iface_ptr);
        }
    }

    /* if we get here, the interface was not found, so return NULL */
    if(debuglvl >= LOW)
        (void)vrprint.debug(__FUNC__, "interface with ip '%s' "
            "not found.", ip);

    return(NULL);
}


/*- print_list -

    Prints the interface list to stdout
*/
void
vrmr_interfaces_print_list(const struct vrmr_interfaces *interfaces)
{
    struct vrmr_list_node             *d_node = NULL;
    struct vrmr_interface   *iface_ptr = NULL;

    if(!interfaces)
        return;

    if(interfaces->list.len > 0)
        fprintf(stdout, "list len is %u\n", interfaces->list.len);
    else
    {
        fprintf(stdout, "list is empty.\n");
        return;
    }

    for(d_node = interfaces->list.top; d_node ; d_node = d_node->next)
    {
        iface_ptr = d_node->data;
        fprintf(stdout, "iface: %s, active: %d, device: %s, ipaddress: %s\n",
                iface_ptr->name, iface_ptr->active,
                iface_ptr->device, iface_ptr->ipv4.ipaddress);
    }

    return;
}


/*

    Currently only checks for a ':'.

    returns:
        1: valid
        0: not a valid name
*/
int
vrmr_interface_check_devicename(const int debuglvl, char *devicename)
{
    size_t  i = 0;

    if(!devicename)
        return(0);

    for(i = 0; i < strlen(devicename); i++)
    {
        if(devicename[i] == ':')
            return(0);
    }

    return(1);
}

#ifdef IPV6_ENABLED
/** \brief See if an interface is IPv6-enabled.
 *  \retval 1 yes
 *  \retval 0 no
 */
int
vrmr_interface_ipv6_enabled(const int debuglvl, struct vrmr_interface *iface_ptr) {
    if (iface_ptr != NULL && iface_ptr->ipv6.cidr6 != -1) {
        return 1;
    }
    return 0;
}
#endif

/*  vrmr_read_interface_info

    Gets the info from the backend:
    Active
    Interface
    Ipaddress

    Returncodes:
    -1: error
     0: ok

    This function will not fail because of missing or malformed data in the
    backend. It will issue an error but set the interface to inactive.
*/
int
vrmr_read_interface_info(const int debuglvl, struct vrmr_interface *iface_ptr)
{
    int     result = 0;
    char    yesno[4] = "";
    char    bw_str[11] = ""; /* 32 bit string, so max 4294967296 */


    /* safety first */
    if(iface_ptr == NULL)
    {
        (void)vrprint.error(-1, "Internal Error", "parameter problem (in: %s:%d).",
                __FUNC__, __LINE__);
        return(-1);
    }

    if(debuglvl >= HIGH)
        (void)vrprint.debug(__FUNC__, "start: name: %s", iface_ptr->name);

    /* check if the interface is active */
    result = vrmr_check_active(debuglvl, iface_ptr->name, TYPE_INTERFACE);
    if(result == 1)
    {
        iface_ptr->active = TRUE;
    }
    else if(result == 0)
    {
        iface_ptr->active = FALSE;
    }
    else
    {
        (void)vrprint.error(-1, "Internal Error", "vrmr_check_active() failed (in: %s:%d).",
                __FUNC__, __LINE__);
        return(-1);
    }


    /* ask the backend about the possible virtualness of the device */
    result = af->ask(debuglvl, ifac_backend, iface_ptr->name, "VIRTUAL", yesno, sizeof(yesno), TYPE_INTERFACE, 0);
    if(result == 1)
    {
        if(strcasecmp(yesno, "yes") == 0)
            iface_ptr->device_virtual = TRUE;
        else
            iface_ptr->device_virtual = FALSE;
    }
    else if(result == 0)
    {
        /* if the interface is undefined, issue a warning and set inactive */
        if(debuglvl >= LOW)
            (void)vrprint.debug(__FUNC__, "no VIRTUAL defined for interface '%s', assuming not virtual.",
                    iface_ptr->name);

        iface_ptr->device_virtual = FALSE;
    }
    else
    {
        (void)vrprint.error(-1, "Internal Error", "af->ask() failed (in: %s:%d).",
                __FUNC__, __LINE__);
        return(-1);
    }


    /* ask the backend about the interface of this interface. Get it? */
    result = af->ask(debuglvl, ifac_backend, iface_ptr->name, "DEVICE", iface_ptr->device, sizeof(iface_ptr->device), TYPE_INTERFACE, 0);
    if(result == 1)
    {
        if(debuglvl >= HIGH)
            (void)vrprint.debug(__FUNC__, "device: %s.", iface_ptr->device);

        if(iface_ptr->device_virtual == TRUE)
        {
            if(vrmr_interface_check_devicename(debuglvl, iface_ptr->device) == 0)
            {
                /* set oldstyle (eth0:0) which is not supported by iptables */
                iface_ptr->device_virtual_oldstyle = TRUE;
            }
        }
    }
    else if(result == 0)
    {
        /* if the interface is undefined, issue a warning and set inactive */
        if(debuglvl >= LOW)
            (void)vrprint.debug(__FUNC__, "no DEVICE defined for interface '%s', trying pre-0.5.68s INTERFACE.",
                    iface_ptr->name);

        result = af->ask(debuglvl, ifac_backend, iface_ptr->name, "INTERFACE", iface_ptr->device, sizeof(iface_ptr->device), TYPE_INTERFACE, 0);
        if(result == 1)
        {
            if(debuglvl >= HIGH)
                (void)vrprint.debug(__FUNC__, "device: %s.", iface_ptr->device);

            if(iface_ptr->device_virtual == TRUE)
            {
                if(vrmr_interface_check_devicename(debuglvl, iface_ptr->device) == 0)
                {
                    /* set oldstyle (eth0:0) which is not supported by iptables */
                    iface_ptr->device_virtual_oldstyle = TRUE;
                }
            }
        }
        else if(result == 0)
        {
            /* if the interface is undefined, issue a warning and set inactive */
            if(debuglvl >= LOW)
                (void)vrprint.debug(__FUNC__, "no INTERFACE defined for interface '%s', assuming not virtual.",
                        iface_ptr->name);
        }
        else
        {
            (void)vrprint.error(-1, "Internal Error", "af->ask() failed (in: %s:%d).",
                    __FUNC__, __LINE__);
            return(-1);
        }
    }
    else
    {
        (void)vrprint.error(-1, "Internal Error", "af->ask() failed (in: %s:%d).",
                __FUNC__, __LINE__);
        return(-1);
    }


    /* ask the ipaddress of this interface */
    result = af->ask(debuglvl, ifac_backend, iface_ptr->name, "IPADDRESS", iface_ptr->ipv4.ipaddress, sizeof(iface_ptr->ipv4.ipaddress), TYPE_INTERFACE, 0);
    if(result == 1)
    {
        if(debuglvl >= HIGH)
            (void)vrprint.debug(__FUNC__, "ipaddress: %s.", iface_ptr->ipv4.ipaddress);

        /* check if ip is dynamic */
        if(strcmp(iface_ptr->ipv4.ipaddress, "dynamic") == 0)
        {
            iface_ptr->dynamic = TRUE;

        }
    }
    else if(result == 0)
    {
        if(debuglvl >= LOW)
            (void)vrprint.debug(__FUNC__, "no IPADDRESS defined for interface '%s', assuming not virtual.",
                    iface_ptr->name);
    }
    else
    {
        (void)vrprint.error(-1, "Internal Error", "af->ask() failed (in: %s:%d).",
                __FUNC__, __LINE__);
        return(-1);
    }

#ifdef IPV6_ENABLED
    /* ask the ipv6 address of this interface */
    result = af->ask(debuglvl, ifac_backend, iface_ptr->name, "IPV6ADDRESS", iface_ptr->ipv6.ip6, sizeof(iface_ptr->ipv6.ip6), TYPE_INTERFACE, 0);
    if(result == 1)
    {
        if(debuglvl >= HIGH)
            (void)vrprint.debug(__FUNC__, "ipaddress: %s.", iface_ptr->ipv6.ip6);

        /* check if ip is dynamic */
        if(strcmp(iface_ptr->ipv6.ip6, "dynamic") == 0)
        {
            iface_ptr->dynamic = TRUE;
        }

        iface_ptr->ipv6.cidr6 = 128;
    }
    else if(result == 0)
    {
        if(debuglvl >= LOW)
            (void)vrprint.debug(__FUNC__, "no IPV6ADDRESS defined for interface '%s', assuming not virtual.",
                    iface_ptr->name);
    }
    else
    {
        (void)vrprint.error(-1, "Internal Error", "af->ask() failed (in: %s:%d).",
                __FUNC__, __LINE__);
        return(-1);
    }
#endif /* IPV6_ENABLED */

    /* lookup if we need shaping */
    result = af->ask(debuglvl, ifac_backend, iface_ptr->name, "SHAPE", yesno, sizeof(yesno), TYPE_INTERFACE, 0);
    if(result == 1)
    {
        if(strcasecmp(yesno, "yes") == 0)
            iface_ptr->shape = TRUE;
        else
            iface_ptr->shape = FALSE;
    }
    else if(result == 0)
    {
        /* if the interface is undefined, issue a warning and set inactive */
        if(debuglvl >= LOW)
            (void)vrprint.debug(__FUNC__, "no SHAPE defined for interface '%s', assuming no shaping.",
                    iface_ptr->name);

        iface_ptr->shape = FALSE;
    }
    else
    {
        (void)vrprint.error(-1, "Internal Error", "af->ask() failed (in: %s:%d).",
                __FUNC__, __LINE__);
        return(-1);
    }

    /* ask the BW_IN of this interface */
    result = af->ask(debuglvl, ifac_backend, iface_ptr->name, "BW_IN", bw_str, sizeof(bw_str), TYPE_INTERFACE, 0);
    if(result == 1)
    {
        if(debuglvl >= HIGH)
            (void)vrprint.debug(__FUNC__, "raw bw_str: %s.", bw_str);

        iface_ptr->bw_in = atoi(bw_str);
    }
    else if(result == 0)
    {
        if(debuglvl >= LOW)
            (void)vrprint.debug(__FUNC__, "no BW_IN defined for interface '%s', setting to 0.",
                    iface_ptr->name);
        iface_ptr->bw_in = 0;
    }
    else
    {
        (void)vrprint.error(-1, "Internal Error", "af->ask() failed (in: %s:%d).",
                __FUNC__, __LINE__);
        return(-1);
    }
    /* ask the BW_IN_UNIT of this interface */
    result = af->ask(debuglvl, ifac_backend, iface_ptr->name, "BW_IN_UNIT", iface_ptr->bw_in_unit, sizeof(iface_ptr->bw_in_unit), TYPE_INTERFACE, 0);
    if(result == 1)
    {
        if(debuglvl >= HIGH)
            (void)vrprint.debug(__FUNC__, "raw bw_str (unit): %s.", iface_ptr->bw_in_unit);

        if (strcasecmp(iface_ptr->bw_in_unit, "kbit") == 0) {
            /* okay do nothing */
        } else if (strcasecmp(iface_ptr->bw_in_unit, "mbit") == 0)  {
            /* okay do nothing */
        } else {
            /* XXX default/error? */
        }
    }
    else if(result == 0)
    {
        if(debuglvl >= LOW)
            (void)vrprint.debug(__FUNC__, "no BW_IN_UNIT defined for interface '%s', setting to 0.",
                    iface_ptr->name);
        iface_ptr->bw_in = 0;
    }
    else
    {
        (void)vrprint.error(-1, "Internal Error", "af->ask() failed (in: %s:%d).",
                __FUNC__, __LINE__);
        return(-1);
    }


    /* ask the BW_OUT of this interface */
    result = af->ask(debuglvl, ifac_backend, iface_ptr->name, "BW_OUT", bw_str, sizeof(bw_str), TYPE_INTERFACE, 0);
    if(result == 1)
    {
        if(debuglvl >= HIGH)
            (void)vrprint.debug(__FUNC__, "raw bw_str: %s.", bw_str);

        iface_ptr->bw_out = atoi(bw_str);
    }
    else if(result == 0)
    {
        if(debuglvl >= LOW)
            (void)vrprint.debug(__FUNC__, "no BW_OUT defined for interface '%s', setting to 0.",
                    iface_ptr->name);
        iface_ptr->bw_out = 0;
    }
    else
    {
        (void)vrprint.error(-1, "Internal Error", "af->ask() failed (in: %s:%d).",
                __FUNC__, __LINE__);
        return(-1);
    }
    /* ask the BW_OUT_UNIT of this interface */
    result = af->ask(debuglvl, ifac_backend, iface_ptr->name, "BW_OUT_UNIT", iface_ptr->bw_out_unit, sizeof(iface_ptr->bw_out_unit), TYPE_INTERFACE, 0);
    if(result == 1)
    {
        if(debuglvl >= HIGH)
            (void)vrprint.debug(__FUNC__, "raw bw_str (unit): %s.", iface_ptr->bw_out_unit);

        if (strcasecmp(iface_ptr->bw_out_unit, "kbit") == 0) {
            /* okay do nothing */
        } else if (strcasecmp(iface_ptr->bw_out_unit, "mbit") == 0)  {
            /* okay do nothing */
        }
    }
    else if(result == 0)
    {
        if(debuglvl >= LOW)
            (void)vrprint.debug(__FUNC__, "no BW_OUT_UNIT defined for interface '%s', setting to 0.",
                    iface_ptr->name);
        iface_ptr->bw_out = 0;
    }
    else
    {
        (void)vrprint.error(-1, "Internal Error", "af->ask() failed (in: %s:%d).",
                __FUNC__, __LINE__);
        return(-1);
    }


    if(iface_ptr->device_virtual == FALSE)
    {
        /* get the rules */
        if(vrmr_interfaces_get_rules(debuglvl, iface_ptr) < 0)
        {
            (void)vrprint.error(-1, "Internal Error", "vrmr_interfaces_get_rules() failed (in: %s:%d).",
                    __FUNC__, __LINE__);
            return(-1);
        }
    }

    /* lookup if we need tcpmss */
    result = af->ask(debuglvl, ifac_backend, iface_ptr->name, "TCPMSS", yesno, sizeof(yesno), TYPE_INTERFACE, 0);
    if(result == 1)
    {
        if(strcasecmp(yesno, "yes") == 0)
            iface_ptr->tcpmss_clamp = TRUE;
        else
            iface_ptr->tcpmss_clamp = FALSE;
    }
    else if(result == 0)
    {
        /* if the interface is undefined, issue a warning and set inactive */
        if(debuglvl >= LOW)
            (void)vrprint.debug(__FUNC__, "no TCPMSS defined for interface '%s', assuming no tcpmss setting.",
                    iface_ptr->name);

        iface_ptr->tcpmss_clamp = FALSE;
    }
    else
    {
        (void)vrprint.error(-1, "Internal Error", "af->ask() failed (in: %s:%d).",
                __FUNC__, __LINE__);
        return(-1);
    }


    if(iface_ptr->device_virtual_oldstyle == FALSE)
    {
        /* now check if the interface is currently up */
        result = vrmr_get_iface_stats(debuglvl, iface_ptr->device, NULL, NULL, NULL, NULL);
        if(result == 0)
        {
            if(debuglvl >= HIGH)
                (void)vrprint.debug(__FUNC__, "interface '%s' is up.", iface_ptr->name);

            iface_ptr->up = TRUE;
        }
        else if(result == 1)
        {
            if(debuglvl >= HIGH)
                (void)vrprint.debug(__FUNC__, "interface '%s' is down.", iface_ptr->name);

            iface_ptr->up = FALSE;
        }
        else
        {
            (void)vrprint.error(-1, "Internal Error", "vrmr_get_iface_stats() failed (in: %s:%d).",
                    __FUNC__, __LINE__);
            return(-1);
        }
    }

    if(debuglvl >= HIGH)
        (void)vrprint.debug(__FUNC__, "end: succes. name: %s.", iface_ptr->name);

    return(0);
}


/*  insert_interface

    Inserts the interface 'name' into the linked-list.

    Returncodes:
        -1: error
         0: succes
         1: interface failed, maybe it is inactive
*/
int
vrmr_insert_interface(const int debuglvl, struct vrmr_interfaces *interfaces, char *name)
{
    struct vrmr_interface   *iface_ptr = NULL;

    if(debuglvl >= HIGH)
        (void)vrprint.debug(__FUNC__, "start: name: %s.", name);


    /* safety */
    if(name == NULL || interfaces == NULL)
    {
        (void)vrprint.error(-1, "Internal Error", "parameter problem (in: %s:%d).",
                __FUNC__, __LINE__);
        return(-1);
    }


    /* claiming the memory we need */
    iface_ptr = vrmr_interface_malloc(debuglvl);
    if(iface_ptr == NULL)
    {
        (void)vrprint.error(-1, "Internal Error", "malloc() failed: %s (in: %s:%d).",
                strerror(errno), __FUNC__, __LINE__);
        return(-1);
    }


    /* set the name in the new structure */
    if(strlcpy(iface_ptr->name, name, sizeof(iface_ptr->name)) >= sizeof(iface_ptr->name))
    {
        (void)vrprint.error(-1, "Internal Error", "buffer overflow (in: %s:%d).",
                __FUNC__, __LINE__);
        return(-1);
    }


    /* call vrmr_read_interface_info. here the info is read. */
    if(vrmr_read_interface_info(debuglvl, iface_ptr) < 0)
    {
        (void)vrprint.error(-1, "Internal Error", "vrmr_read_interface_info() failed (in: %s:%d).",
                __FUNC__, __LINE__);
        return(-1);
    }


    /* insert into the list (sorted) */
    if(vrmr_insert_interface_list(debuglvl, interfaces, iface_ptr) < 0)
        return(-1);


    /* update status */
    iface_ptr->status = ST_ADDED;


    /* update the interfaces */
    if(iface_ptr->active == TRUE)
        interfaces->active_interfaces = TRUE;
    if(iface_ptr->dynamic == TRUE)
        interfaces->dynamic_interfaces = TRUE;


    if(debuglvl >= HIGH)
        (void)vrprint.debug(__FUNC__, "end: succes.");

    return(0);
}


/*  init_interfaces

    Loads all interfaces in memory.

    Returncodes:
         0: succes
        -1: error
*/
int
vrmr_init_interfaces(const int debuglvl, struct vrmr_interfaces *interfaces)
{
    int     result = 0,
            counter = 0,
            zonetype = 0;
    char    ifacname[VRMR_MAX_INTERFACE] = "";

    if(debuglvl >= HIGH)
        (void)vrprint.debug(__FUNC__, "start");


    /* safety */
    if(interfaces == NULL)
    {
        (void)vrprint.error(-1, "Internal Error", "parameter problem (in: %s:%d).",
                __FUNC__, __LINE__);
        return(-1);
    }


    /* init */
    memset(interfaces, 0, sizeof(struct vrmr_interfaces));
    /* setup the list */
    if(vrmr_list_setup(debuglvl, &interfaces->list, NULL) < 0)
        return(-1);


    /* get the list from the backend */
    while(af->list(debuglvl, ifac_backend, ifacname, &zonetype, CAT_INTERFACES) != NULL)
    {
        if(debuglvl >= MEDIUM)
            (void)vrprint.debug(__FUNC__, "loading interface %s", ifacname);

        result = vrmr_insert_interface(debuglvl, interfaces, ifacname);
        if(result < 0)
        {
            (void)vrprint.error(-1, "Internal Error", "insert_interface() failed (in: %s:%d).",
                    __FUNC__, __LINE__);
            return(-1);
        }
        else
        {
            counter++;

            if(debuglvl >= LOW)
                (void)vrprint.debug(__FUNC__, "loading interface succes: '%s'.", ifacname);
        }
    }

    if(debuglvl >= HIGH)
        (void)vrprint.debug(__FUNC__, "end");

    return(0);
}


/*  vrmr_interfaces_save_rules

    Save the rules to the backend.

    Returncodes:
         0: ok
        -1: error
*/
int
vrmr_interfaces_save_rules(const int debuglvl, struct vrmr_interface *iface_ptr)
{
    struct vrmr_list_node         *d_node = NULL;
    struct vrmr_rule    *rule_ptr = NULL;
    char                rule_str[VRMR_MAX_RULE_LENGTH] = "";

    /* safety */
    if(iface_ptr == NULL)
    {
        (void)vrprint.error(-1, "Internal Error", "parameter problem (in: %s:%d).",
                __FUNC__, __LINE__);
        return(-1);
    }

    /* write to backend */
    if(iface_ptr->ProtectList.len == 0)
    {
        /* clear */
        if(af->tell(debuglvl, ifac_backend, iface_ptr->name, "RULE", "", 1, TYPE_INTERFACE) < 0)
        {
            (void)vrprint.error(-1, "Internal Error", "af->tell() failed (in: %s:%d).",
                    __FUNC__, __LINE__);
            return(-1);
        }
    }
    else
    {
        /* write to backend */
        for(d_node = iface_ptr->ProtectList.top; d_node; d_node = d_node->next)
        {
            if(!(rule_ptr = d_node->data))
            {
                (void)vrprint.error(-1, "Internal Error", "NULL pointer (in: %s:%d).",
                        __FUNC__, __LINE__);
                return(-1);
            }

            snprintf(rule_str, sizeof(rule_str), "protect against %s", rule_ptr->danger);

            if(d_node == iface_ptr->ProtectList.top)
            {
                /* save to backend */
                if(af->tell(debuglvl, ifac_backend, iface_ptr->name, "RULE", rule_str, 1, TYPE_INTERFACE) < 0)
                {
                    (void)vrprint.error(-1, "Internal Error", "af->tell() failed (in: %s:%d).",
                            __FUNC__, __LINE__);
                    return(-1);
                }
            }
            else
            {
                /* save to backend */
                if(af->tell(debuglvl, ifac_backend, iface_ptr->name, "RULE", rule_str, 0, TYPE_INTERFACE) < 0)
                {
                    (void)vrprint.error(-1, "Internal Error", "af->tell() failed (in: %s:%d).",
                            __FUNC__, __LINE__);
                    return(-1);
                }
            }
        }
    }

    return(0);
}


int
vrmr_new_interface(const int debuglvl, struct vrmr_interfaces *interfaces, char *iface_name)
{
    int                     result = 0;
    struct vrmr_interface   *iface_ptr = NULL;
    struct vrmr_rule        *rule_ptr = NULL;


    /* safety */
    if(iface_name == NULL || interfaces == NULL)
    {
        (void)vrprint.error(-1, "Internal Error", "parameter problem (in: %s:%d).",
                __FUNC__, __LINE__);
        return(-1);
    }


    /* claim memory */
    iface_ptr = vrmr_interface_malloc(debuglvl);
    if(iface_ptr == NULL)
    {
        (void)vrprint.error(-1, "Internal Error", "malloc() failed: %s (in: %s:%d).",
                strerror(errno), __FUNC__, __LINE__);
        return(-1);
    }

    /* copy name */
    if(strlcpy(iface_ptr->name, iface_name, sizeof(iface_ptr->name)) >= sizeof(iface_ptr->name))
    {
        (void)vrprint.error(-1, "Internal Error", "buffer overflow (in: %s:%d).",
                __FUNC__, __LINE__);
        return(-1);
    }

    /* insert into the list (sorted) */
    if(vrmr_insert_interface_list(debuglvl, interfaces, iface_ptr) < 0)
        return(-1);


    /* add to the backend */
    if(debuglvl >= HIGH)
        (void)vrprint.debug(__FUNC__, "calling af->add for '%s'.", iface_name);

    result = af->add(debuglvl, ifac_backend, iface_name, TYPE_INTERFACE);
    if(result < 0)
    {
        (void)vrprint.error(-1, "Internal Error", "af->add() failed (in: %s:%d).",
                __FUNC__, __LINE__);
        return(-1);
    }

    if(debuglvl >= HIGH)
        (void)vrprint.debug(__FUNC__, "calling af->add for '%s' success.", iface_name);

    /* set active */
    result = af->tell(debuglvl, ifac_backend, iface_ptr->name, "ACTIVE", iface_ptr->active ? "Yes" : "No", 1, TYPE_INTERFACE);
    if(result < 0)
    {
        (void)vrprint.error(-1, "Internal Error", "af->tell() failed (in: %s:%d).",
                __FUNC__, __LINE__);
        return(-1);
    }

    /* set virtual */
    result = af->tell(debuglvl, ifac_backend, iface_ptr->name, "VIRTUAL", iface_ptr->device_virtual ? "Yes" : "No", 1, TYPE_INTERFACE);
    if(result < 0)
    {
        (void)vrprint.error(-1, "Internal Error", "af->tell() failed (in: %s:%d).",
                __FUNC__, __LINE__);
        return(-1);
    }

    /* interface protection options are 'on' by default */
    if(!(rule_ptr = rules_create_protect_rule(debuglvl, "protect", iface_ptr->name, "source-routed-packets", NULL)))
    {
        (void)vrprint.error(-1, "Internal Error", "rules_create_protect_rule() failed (in: %s:%d).",
                __FUNC__, __LINE__);
        return(-1);
    }
    if(vrmr_list_append(debuglvl, &iface_ptr->ProtectList, rule_ptr) == NULL)
    {
        (void)vrprint.error(-1, "Internal Error", "vrmr_list_append() failed (in: %s:%d).",
                __FUNC__, __LINE__);
        return(-1);
    }

    if(!(rule_ptr = rules_create_protect_rule(debuglvl, "protect", iface_ptr->name, "icmp-redirect", NULL)))
    {
        (void)vrprint.error(-1, "Internal Error", "rules_create_protect_rule() failed (in: %s:%d).",
                __FUNC__, __LINE__);
        return(-1);
    }
    if(vrmr_list_append(debuglvl, &iface_ptr->ProtectList, rule_ptr) == NULL)
    {
        (void)vrprint.error(-1, "Internal Error", "vrmr_list_append() failed (in: %s:%d).",
                __FUNC__, __LINE__);
        return(-1);
    }

    if(!(rule_ptr = rules_create_protect_rule(debuglvl, "protect", iface_ptr->name, "send-redirect", NULL)))
    {
        (void)vrprint.error(-1, "Internal Error", "rules_create_protect_rule() failed (in: %s:%d).",
                __FUNC__, __LINE__);
        return(-1);
    }
    if(vrmr_list_append(debuglvl, &iface_ptr->ProtectList, rule_ptr) == NULL)
    {
        (void)vrprint.error(-1, "Internal Error", "vrmr_list_append() failed (in: %s:%d).",
                __FUNC__, __LINE__);
        return(-1);
    }

    if(!(rule_ptr = rules_create_protect_rule(debuglvl, "protect", iface_ptr->name, "rp-filter", NULL)))
    {
        (void)vrprint.error(-1, "Internal Error", "rules_create_protect_rule() failed (in: %s:%d).",
                __FUNC__, __LINE__);
        return(-1);
    }
    if(vrmr_list_append(debuglvl, &iface_ptr->ProtectList, rule_ptr) == NULL)
    {
        (void)vrprint.error(-1, "Internal Error", "vrmr_list_append() failed (in: %s:%d).",
                __FUNC__, __LINE__);
        return(-1);
    }

    if(!(rule_ptr = rules_create_protect_rule(debuglvl, "protect", iface_ptr->name, "log-martians", NULL)))
    {
        (void)vrprint.error(-1, "Internal Error", "rules_create_protect_rule() failed (in: %s:%d).",
                __FUNC__, __LINE__);
        return(-1);
    }
    if(vrmr_list_append(debuglvl, &iface_ptr->ProtectList, rule_ptr) == NULL)
    {
        (void)vrprint.error(-1, "Internal Error", "vrmr_list_append() failed (in: %s:%d).",
                __FUNC__, __LINE__);
        return(-1);
    }

    /* now let try to write this to the backend */
    if(vrmr_interfaces_save_rules(debuglvl, iface_ptr) < 0)
    {
        (void)vrprint.error(-1, "Internal Error", "interfaces_save_protectrules() failed (in: %s:%d).",
                __FUNC__, __LINE__);
        return(-1);
    }


    return(0);
}


/*  vrmr_delete_interface

    Deletes an interface from the list, from memory and from
    the backend.

    Returncodes:
         0: ok
        -1: error
*/
int
vrmr_delete_interface(const int debuglvl, struct vrmr_interfaces *interfaces, char *iface_name)
{
    struct vrmr_interface   *iface_ptr = NULL;
    struct vrmr_list_node             *d_node = NULL;

    /* safety */
    if(iface_name == NULL || interfaces == NULL)
    {
        (void)vrprint.error(-1, "Internal Error", "parameter problem (in: %s:%d).",
                __FUNC__, __LINE__);
        return(-1);
    }

    /* first search the interface in the list */
    if(!(iface_ptr = vrmr_search_interface(debuglvl, interfaces, iface_name)))
    {
        (void)vrprint.error(-1, "Internal Error", "interface '%s' not found in memory (in: %s:%d).",
                iface_name, __FUNC__, __LINE__);
        return(-1);
    }

    /* check the refernce counters */
    if(iface_ptr->refcnt_network > 0)
    {
        (void)vrprint.error(-1, "Internal Error", "interface '%s' is still attached to %u network(s).",
                iface_ptr->name, iface_ptr->refcnt_network);
        return(-1);
    }

    iface_ptr = NULL;

    /* remove the interface from the backend */
    if(af->del(debuglvl, ifac_backend, iface_name, TYPE_INTERFACE, 1) < 0)
    {
        (void)vrprint.error(-1, "Internal Error", "af->del() failed (in: %s:%d).",
                __FUNC__, __LINE__);
        return(-1);
    }

    /* now search the interface again to remove it */
    for(d_node = interfaces->list.top; d_node; d_node = d_node->next)
    {
        if(!(iface_ptr = d_node->data))
        {
            (void)vrprint.error(-1, "Internal Error", "NULL pointer (in: %s:%d).",
                    __FUNC__, __LINE__);
            return(-1);
        }

        if(strcmp(iface_name, iface_ptr->name) == 0)
        {
            /*  this is the interface

                now remove it from the list
            */
            if(vrmr_list_remove_node(debuglvl, &interfaces->list, d_node) < 0)
            {
                (void)vrprint.error(-1, "Internal Error", "vrmr_list_remove_node() failed (in: %s:%d).",
                        __FUNC__, __LINE__);
                return(-1);
            }

            /* finally free the memory */
            free(iface_ptr);

            return(0);
        }
    }

    /* if we get here the interface was not found in the list */
    return(-1);
}


/*  vrmr_ins_iface_into_zonelist

    load the insertfaces into the zoneslist

    Returncodes
         0: ok
        -1: error
*/
int
vrmr_ins_iface_into_zonelist(const int debuglvl, struct vrmr_list *ifacelist, struct vrmr_list *zonelist)
{
    struct vrmr_interface   *iface_ptr = NULL;
    struct vrmr_zone        *zone_ptr = NULL;
    struct vrmr_list_node             *iface_node = NULL;
    char                    name[VRMR_MAX_INTERFACE + 8 + 2 + 1]; // 32 max iface length, 8 firewall, 2 () and 1 \0

    if(debuglvl >= HIGH)
        (void)vrprint.debug(__FUNC__, "start.");


    /* safety check */
    if(!ifacelist || !zonelist)
    {
        (void)vrprint.error(-1, "Internal Error", "parameter problem (in: %s:%d).",
                __FUNC__, __LINE__);
        return(-1);
    }


    /* dont bother an empty interface list */
    if(ifacelist->len == 0)
        return(0);


    /* loop trough the interface list */
    for(iface_node = ifacelist->top; iface_node; iface_node = iface_node->next)
    {
        if(!(iface_ptr = iface_node->data))
        {
            (void)vrprint.error(-1, "Internal Error", "NULL pointer (in: %s:%d).",
                    __FUNC__, __LINE__);
            return(-1);
        }

        /*
            we dont care about an interface without an ipaddress
        */
        if(strcmp(iface_ptr->ipv4.ipaddress, "") != 0)
        {
            /*
                pretty name
            */
            if(snprintf(name, sizeof(name), "firewall(%s)", iface_ptr->name) >= (int)sizeof(name))
            {
                (void)vrprint.error(-1, "Internal Error", "buffer overflow (in: %s:%d).",
                        __FUNC__, __LINE__);
                return(-1);
            }

            /*
                alloc mem for the temp zone
            */
            if(!(zone_ptr = vrmr_zone_malloc(debuglvl)))
            {
                (void)vrprint.error(-1, "Internal Error", "vrmr_zone_malloc() failed (in: %s:%d).",
                        __FUNC__, __LINE__);
                return(-1);
            }

            /*
                copy the name
            */
            if(strlcpy(zone_ptr->name, name, sizeof(zone_ptr->name)) >= sizeof(zone_ptr->name))
            {
                (void)vrprint.error(-1, "Internal Error", "buffer overflow (in: %s:%d).",
                        __FUNC__, __LINE__);
                return(-1);
            }

            /*
                copy the ipaddress
            */
            if(strlcpy(zone_ptr->ipv4.ipaddress, iface_ptr->ipv4.ipaddress, sizeof(zone_ptr->ipv4.ipaddress)) >= sizeof(zone_ptr->ipv4.ipaddress))
            {
                (void)vrprint.error(-1, "Internal Error", "buffer overflow (in: %s:%d).",
                        __FUNC__, __LINE__);
                return(-1);
            }

            /*
                set the type to firewall, so we can recognize the interface in an easy way
            */
            zone_ptr->type = TYPE_FIREWALL;

            /*
                append to the zoneslist
            */
            if(vrmr_list_append(debuglvl, zonelist, zone_ptr) == NULL)
            {
                (void)vrprint.error(-1, "Internal Error", "vrmr_list_append() failed (in: %s:%d).",
                        __FUNC__, __LINE__);

                free(zone_ptr);
                return(-1);
            }

            if(debuglvl >= HIGH)
                (void)vrprint.debug(__FUNC__, "inserted '%s' into zonelist.", zone_ptr->name);

        }
    }

    return(0);
}


/*  vrmr_rem_iface_from_zonelist

    Removes all zones with type TYPE_FIREWALL from the zoneslist.
    This normally are interfaces and network broadcast addresses
    which were included in this list by vrmr_ins_iface_into_zonelist.

    Returncodes:
         0: ok
        -1: error
*/
int
vrmr_rem_iface_from_zonelist(const int debuglvl, struct vrmr_list *zonelist)
{
    struct vrmr_zone    *zone_ptr = NULL;
    struct vrmr_list_node         *d_node = NULL,
                        *next_node = NULL;
    int                 i = 0;

    if(debuglvl >= HIGH)
        (void)vrprint.debug(__FUNC__, "start.");

    /*
        safety
    */
    if(!zonelist)
    {
        (void)vrprint.error(-1, "Internal Error", "parameter problem (in: %s:%d).",
                __FUNC__, __LINE__);
        return(-1);
    }

    for(d_node = zonelist->top; d_node; d_node = next_node)
    {
        if(!(zone_ptr = d_node->data))
        {
            (void)vrprint.error(-1, "Internal Error", "NULL pointer (in: %s:%d).",
                    __FUNC__, __LINE__);
            return(-1);
        }

        /*
            we use next_node here because when a d_node is
            removed from the list it is also free'd from
            memory. So we have to determine the next
            node before that happens.
        */
        next_node = d_node->next;

        if(zone_ptr->type == TYPE_FIREWALL)
        {
            if(debuglvl >= HIGH)
                (void)vrprint.debug(__FUNC__, "type: TYPE_FIREWALL '%s'.", zone_ptr->name);

            /*
                remove the node from the list
            */
            if(vrmr_list_remove_node(debuglvl, zonelist, d_node) < 0)
            {
                (void)vrprint.error(-1, "Internal Error", "vrmr_list_remove_node() failed (in: %s:%d).",
                        __FUNC__, __LINE__);
                return(-1);
            }

            /*
                free the memory, but only if the remove function
                in the list is NULL. Otherwise it is already free'd
                by vrmr_list_remove_node.
            */
            if(zonelist->remove == NULL)
                free(zone_ptr);

            i++;
        }
    }

    if(debuglvl >= HIGH)
        (void)vrprint.debug(__FUNC__, "%d interfaces/broadcasts removed.", i);

    return(0);
}


/*  vrmr_get_iface_stats

    Gets information about an interface from /proc/net/dev. It can also be used to check if an interface
    is up.

    Returncodes:
         0: ok
        -1: error
         1: int not found
*/
int
vrmr_get_iface_stats(    const int debuglvl,
                    const char *iface_name,
                    unsigned long *recv_bytes,
                    unsigned long *recv_packets,
                    unsigned long *trans_bytes,
                    unsigned long *trans_packets)
{
    char    proc_net_dev[] = "/proc/net/dev",
            line[256] = "",

            /*
                NOTE: if you change the length of the interface, also change it in
                sscanf!!!!
            */
            interface[32] = "",
            recv_byte_str[32] = "";

    int     copy_bytes = 0,
            i = 0,
            k = 0,
            found = 0;  /* indicates that the interface was found */

    FILE    *fp = NULL;

    struct
    {
        unsigned long bytes;    /* a long because otherwise it would max handle 2gb */
        unsigned long packets;
        int errors;
        int drop;
        int fifo;
        int frame;
        int comp;
        int multi;
    }   recv  = {0, 0, 0, 0, 0, 0, 0, 0},
        trans = {0, 0, 0, 0, 0, 0, 0, 0};


    /* first reset */
    if(recv_bytes != NULL)      *recv_bytes = 0;
    if(trans_bytes != NULL)     *trans_bytes = 0;
    if(recv_packets != NULL)    *recv_packets = 0;
    if(trans_packets != NULL)   *trans_packets = 0;

    /* open the proc entry */
    if(!(fp = fopen(proc_net_dev, "r")))
    {
        (void)vrprint.error(-1, "Internal Error", "unable to open '%s': %s (in: %s:%d).",
                proc_net_dev, strerror(errno), __FUNC__, __LINE__);
        return(-1);
    }

    /* loop trough the file */
    while(fgets(line, (int)sizeof(line), fp) != NULL)
    {
        /*  first scan only the first string, here you can see why (from the file):
            lo: 3335005   17735 ...
            eth0:1055472756 4679465 ...

            notice that with eth0 there is no space between the semicolon and the number.
            Thats where we test for.
        */
        sscanf(line, "%32s", interface);
        if(strncmp(interface, iface_name, strlen(iface_name)) == 0)
        {
            found = 1;

            /* if only want to know if the device is up break out now */
            if(!recv_bytes && !trans_bytes && !recv_packets && !trans_packets)
                break;

            /* if we have an semicolon at the end */
            if(interface[strlen(interface)-1] == ':')
            {
                sscanf(line, "%32s %lud %lu %d %d %d %d %d %d %lu %lu %d %d %d %d %d %d",
                        interface, &recv.bytes, &recv.packets, &recv.errors,
                        &recv.drop, &recv.fifo, &recv.frame, &recv.comp, &recv.multi,
                        &trans.bytes, &trans.packets, &trans.errors, &trans.drop, &trans.fifo,
                        &trans.frame, &trans.comp, &trans.multi);
            }
            /* else the recv bytes is very big */
            else
            {
                /* okay, lets split up */
                for(i=0, k=0; (i < (int)strlen(interface) && k < (int)sizeof(recv_byte_str)); i++)
                {
                    if(copy_bytes == 1)
                    {
                        recv_byte_str[k] = interface[i];
                        k++;
                    }

                    if(interface[i] == ':')
                        copy_bytes = 1;
                }
                recv_byte_str[k] = '\0';

                /* now convert to unsigned long */
                recv.bytes = strtoul(recv_byte_str, (char **)NULL, 10);
                if(debuglvl >= HIGH)
                    (void)vrprint.debug(__FUNC__, "recv_byte_str: '%s', recv.bytes: '%lu'.",
                            recv_byte_str,
                            recv.bytes);

                sscanf(line, "%32s %lu %d %d %d %d %d %d %lu %lu %d %d %d %d %d %d",
                        interface, &recv.packets, &recv.errors, &recv.drop, &recv.fifo,
                        &recv.frame, &recv.comp, &recv.multi, &trans.bytes, &trans.packets,
                        &trans.errors, &trans.drop, &trans.fifo, &trans.frame, &trans.comp, &trans.multi);
            }

            /* pass back to the calling function */
            if(recv_bytes != NULL)
                *recv_bytes = recv.bytes;
            if(trans_bytes != NULL)
                *trans_bytes = trans.bytes;
            if(recv_packets != NULL)
                *recv_packets = recv.packets;
            if(trans_packets != NULL)
                *trans_packets = trans.packets;
        }
    }

    if(fclose(fp) < 0)
        return(-1);

    /*
        is not found, return 1
    */
    if(found == 0)
        return(1);

    return(0);
}


/*  vrmr_get_iface_stats_from_ipt

    Get interface counters (packets and bytes) from iptables.

    Value-result function.

    Returncode:
         0: ok
        -1: error
*/
int
vrmr_get_iface_stats_from_ipt(const int debuglvl,
                            struct vrmr_config *cfg,
                            const char *iface_name,
                            const char *chain,
                            unsigned long long *recv_packets,
                            unsigned long long *recv_bytes,
                            unsigned long long *trans_packets,
                            unsigned long long *trans_bytes)
{
    char                line[256] = "",
                        interface_in[32] = "",
                        interface_out[32] = "",
                        command[128] = "",
                        proto[16] = "",
                        target[32] = "",
                        options[16] = "",
                        source[36] = "",
                        dest[36] = "";
    FILE                *p = NULL;
    int                 line_count = 0;

    unsigned long long  packets = 0,
                        bytes = 0;
    char                trans_done = 0,
                        recv_done = 0;

    *trans_bytes = 0;
    *recv_bytes = 0;
    *trans_packets = 0;
    *recv_packets = 0;

    /* if we are looking for the input or output numbers we can skip one direction,
       if we need FORWARD, we need both */
    if(strcmp(chain, "INPUT") == 0)
        trans_done = 1;
    else if(strcmp(chain, "OUTPUT") == 0)
        recv_done = 1;

    /* set the command to get the data from iptables */
    snprintf(command, sizeof(command), "%s -vnL %s --exact 2> /dev/null", cfg->iptables_location, chain);
    if(debuglvl >= HIGH)
        (void)vrprint.debug(__FUNC__, "command: '%s'.", command);

    /* open the pipe to the command */
    if(!(p = popen(command, "r")))
    {
        (void)vrprint.error(-1, "Internal Error", "pipe failed: %s (in: %s:%d).", strerror(errno), __FUNC__, __LINE__);
        return(-1);
    }

    /* loop through the result */
    while(fgets(line, (int)sizeof(line), p) != NULL &&
        (!recv_done || !trans_done))
    {
//        if(line[strlen(line)-1] == '\n')
//            line[strlen(line)-1] = '\0';
//        (void)vrprint.debug(__FUNC__, "line: '%s'.", line);

        /* we start looking after the first two lines */
        if(line_count >= 4)
        {
            /*            pack byte tg pr op in ou sr ds */
            sscanf(line, "%llu %llu %s %s %s %s %s %s %s", &packets, &bytes, target, proto, options, interface_in, interface_out, source, dest);

            if(debuglvl >= HIGH)
                (void)vrprint.debug(__FUNC__, "%s: tgt %s: iin: %s oin: %s packets: %llu, bytes: %llu", iface_name, target, interface_in, interface_out, packets, bytes);

            if( strcmp(source, "0.0.0.0/0") == 0 &&
                strcmp(dest, "0.0.0.0/0") == 0 &&
                (strcmp(proto, "all") == 0 || strcmp(proto, "0") == 0) &&
                (interface_in[0] == '*' || interface_out[0] == '*'))
            {
                /* outgoing */
                if(interface_in[0] == '*' && strcmp(interface_out, iface_name) == 0)
                {
                    *trans_packets = packets;
                    *trans_bytes = bytes;
                    trans_done = 1;

                    if(debuglvl >= HIGH)
                        (void)vrprint.debug(__FUNC__, "%s: trans: %llu (%llu) (trans done)",
                                iface_name,
                                *trans_bytes,
                                bytes);
                }
                /* incoming */
                else if(interface_out[0] == '*' && strcmp(interface_in, iface_name) == 0)
                {
                    *recv_packets = packets;
                    *recv_bytes = bytes;
                    recv_done = 1;

                    if(debuglvl >= HIGH)
                        (void)vrprint.debug(__FUNC__, "%s: recv: %llu (%llu) (recv done)",
                                iface_name,
                                *recv_bytes,
                                bytes);
                }
            }
        }

        line_count++;
    }

    /* finally close the pipe */
    pclose(p);

    return(0);
}


/*  vrmr_validate_interfacename

    Returncodes:
        0: ok
        -1: error
*/
int
vrmr_validate_interfacename(const int debuglvl, const char *interfacename, regex_t *reg_ex)
{
    /* safety */
    if(interfacename == NULL || reg_ex == NULL)
    {
        (void)vrprint.error(-1, "Internal Error", "parameter problem (in: %s:%d).",
                __FUNC__, __LINE__);
        return(-1);
    }

    if(debuglvl >= HIGH)
        (void)vrprint.debug(__FUNC__, "checking: %s", interfacename);

    /*
        run the regex
    */
    if(regexec(reg_ex, interfacename, 0, NULL, 0) != 0)
    {
        if(debuglvl >= HIGH)
            (void)vrprint.debug(__FUNC__, "'%s' is invalid", interfacename);

        return(-1);
    }

    if(debuglvl >= HIGH)
        (void)vrprint.debug(__FUNC__, "'%s' is valid", interfacename);

    return(0);
}


/*  vrmr_destroy_interfaceslist

*/
void
vrmr_destroy_interfaceslist(const int debuglvl, struct vrmr_interfaces *interfaces)
{
    struct vrmr_list_node             *d_node = NULL;
    struct vrmr_interface   *iface_ptr = NULL;


    /* safety */
    if(!interfaces)
    {
        (void)vrprint.error(-1, "Internal Error", "parameter problem (in: %s:%d).",
                __FUNC__, __LINE__);
        return;
    }


    /* first destroy all PortrangeLists */
    for(d_node = interfaces->list.top; d_node ; d_node = d_node->next)
    {
        if(!(iface_ptr = d_node->data))
        {
            (void)vrprint.error(-1, "Internal Error", "NULL pointer (in: %s:%d).",
                    __FUNC__, __LINE__);
            return;
        }

        vrmr_list_cleanup(debuglvl, &iface_ptr->ProtectList);

        free(iface_ptr);
        iface_ptr = NULL;
    }

    /* then the list itself */
    vrmr_list_cleanup(debuglvl, &interfaces->list);
}


/*  vrmr_interfaces_analyze_rule

    Function for gathering the info for creation of the rule
    and for sanity checking the rule.

    Returncodes:
         0: ok
        -1: error
 */
int
vrmr_interfaces_analyze_rule(const int debuglvl,
            struct vrmr_rule *rule_ptr,
            struct vrmr_rule_cache *create,
            struct vrmr_interfaces *interfaces,
            struct vrmr_config *cnf)
{
    int result = 0;


    /* safety */
    if( rule_ptr == NULL || create == NULL || interfaces == NULL)
    {
        (void)vrprint.error(-1, "Internal Error", "parameter problem (in: %s:%d).",
                __FUNC__, __LINE__);
        return(-1);
    }

    /* if were on bash mode, alloc mem for the description */
    if(cnf->bash_out == TRUE)
    {
        if(!(create->description = malloc(VRMR_MAX_BASH_DESC)))
        {
            (void)vrprint.error(-1, "Error", "malloc failed: %s (in: %s:%d).",
                    strerror(errno), __FUNC__, __LINE__);
            return(-1);
        }
    }
    else
    {
        create->description = NULL;
    }

    /* first the protect rule */
    if(rule_ptr->action == VRMR_AT_PROTECT)
    {
        if(debuglvl >= LOW)
            (void)vrprint.debug(__FUNC__, "action: %s, who: %s, danger: %s, source: %s",
                    vrmr_rules_itoaction(rule_ptr->action), rule_ptr->who,
                    rule_ptr->danger, rule_ptr->source);

        /* description */
        if(cnf->bash_out && create->description != NULL)
        {
            snprintf(create->description, VRMR_MAX_BASH_DESC, "rule: action: %s, who: %s, danger: %s, source: %s",
                    vrmr_rules_itoaction(rule_ptr->action), rule_ptr->who,
                    rule_ptr->danger, rule_ptr->source);
        }

        /* get who */
        if(strcmp(rule_ptr->who, "") != 0)
        {
            if(rule_ptr->type == VRMR_PROT_PROC_INT)
            {
                create->who = NULL;
                create->who_int = NULL;

                if(!(create->who_int = vrmr_search_interface(debuglvl, interfaces, rule_ptr->who)))
                {
                    (void)vrprint.error(-1, "Error", "interface '%s' not found (in: %s).", rule_ptr->who, __FUNC__);
                    return(-1);
                }
            }
            else
            {
                create->who = NULL;
                (void)vrprint.error(-1, "Error", "don't know what to do with '%s' for rule type '%d' (in: %s).", rule_ptr->who, rule_ptr->type, __FUNC__);
                return(-1);
            }
        }

        if(debuglvl >= MEDIUM)
            (void)vrprint.debug(__FUNC__, "calling vrmr_get_danger_info() for danger...");

        result = vrmr_get_danger_info(debuglvl, rule_ptr->danger, rule_ptr->source, &create->danger);
        if(result == 0)
        {
            if(debuglvl >= HIGH)
                (void)vrprint.debug(__FUNC__, "vrmr_get_danger_info successfull.");
        }
        else
        {
            (void)vrprint.error(-1, "Error", "getting danger '%s' failed (in: %s).",
                    rule_ptr->danger, __FUNC__);
            return(-1);
        }

        /* set the action */
        if(strlcpy(create->action, "protect", sizeof(create->action)) > sizeof(create->action))
        {
            (void)vrprint.error(-1, "Error", "buffer overflow (in: %s:%d).",
                    __FUNC__, __LINE__);
            return(-1);
        }
    }

    return(0);
}


/*  vrmr_rules_parse_line

    Returncodes:
        0: ok
        -1: error
*/
int
vrmr_interfaces_rule_parse_line(const int debuglvl, const char *line, struct vrmr_rule *rule_ptr)
{
    size_t  line_pos = 0,   /* position in line */
            var_pos = 0;    /* position in varible */
    char    against_keyw[32] = "";
    char    action_str[32] = "";


    /* safety first */
    if(line == NULL || rule_ptr == NULL)
    {
        (void)vrprint.error(-1, "Internal Error", "parameter problem (in: %s:%d).",
                __FUNC__, __LINE__);
        return(-1);
    }

    /* this should not happen, but it can't hurt to check, right? */
    if(strlen(line) > VRMR_MAX_RULE_LENGTH)
    {
        (void)vrprint.error(-1, "Internal Error", "rule is too long (in: %s:%d).",
                __FUNC__, __LINE__);
        return(-1);
    }

    /* get the action */
    for(;   line_pos < sizeof(action_str)-1 &&
            line[line_pos] != ' ' &&
            line[line_pos] != '\0' &&
            line[line_pos] != '\n';
            line_pos++, var_pos++)
    {
        action_str[var_pos] = line[line_pos];
    }
    action_str[var_pos] = '\0';

    rule_ptr->action = vrmr_rules_actiontoi(action_str);
    if(rule_ptr->action <= VRMR_AT_ERROR || rule_ptr->action >= VRMR_AT_TOO_BIG)
        return(-1);

    /* now we analyze the action */
    if(rule_ptr->action == VRMR_AT_PROTECT)
    {
        /* get the 'against' */
        for(line_pos++, var_pos = 0; var_pos < sizeof(against_keyw) && line[line_pos] != ' ' && line[line_pos] != '\0' && line[line_pos] != '\n'; line_pos++, var_pos++)
        {
            against_keyw[var_pos] = line[line_pos];
        }
        against_keyw[var_pos] = '\0';

        /*
            now check what kind of rule we have
        */
        if(strcasecmp(against_keyw, "against") != 0)
        {
            (void)vrprint.error(-1, "Internal Error", "expected keyword 'against', got '%s' (in: %s:%d).",
                    against_keyw, __FUNC__, __LINE__);
            return(-1);
        }

        /*
            okay, now lets see what kind of danger we are talking about
        */
        for(line_pos++, var_pos = 0; var_pos < sizeof(rule_ptr->danger) && line[line_pos] != ' ' && line[line_pos] != '\0' && line[line_pos] != '\n'; line_pos++, var_pos++)
        {
            rule_ptr->danger[var_pos] = line[line_pos];
        }
        rule_ptr->danger[var_pos] = '\0';

        if(debuglvl >= HIGH)
            (void)vrprint.debug(__FUNC__, "protect: danger: '%s'", rule_ptr->danger);

        rule_ptr->type = VRMR_PROT_PROC_INT;
    }
    else
    {
        (void)vrprint.error(-1, "Error", "expected action 'protect', got '%s' (in: %s:%d).",
                action_str, __FUNC__, __LINE__);
        return(-1);
    }

    return(0);
}


int
vrmr_interfaces_get_rules(const int debuglvl, struct vrmr_interface *iface_ptr)
{
    char                currule[VRMR_MAX_RULE_LENGTH] = "";
    struct vrmr_rule    *rule_ptr = NULL;
    struct vrmr_list_node         *d_node = NULL;


    /* safety */
    if(iface_ptr == NULL)
    {
        (void)vrprint.error(-1, "Internal Error", "parameter problem (in: %s:%d).",
                __FUNC__, __LINE__);
        return(-1);
    }

    /* get all rules from the backend */
    while((af->ask(debuglvl, ifac_backend, iface_ptr->name, "RULE", currule, sizeof(currule), TYPE_INTERFACE, 1)) == 1)
    {
        /* get mem */
        if(!(rule_ptr = vrmr_rule_malloc()))
            return(-1);

        /* copy name */
        if(strlcpy(rule_ptr->who, iface_ptr->name, sizeof(rule_ptr->who)) >= sizeof(rule_ptr->who))
        {
            (void)vrprint.error(-1, "Internal Error", "buffer too small (in: %s:%d).",
                    __FUNC__, __LINE__);
            free(rule_ptr);
            return(-1);
        }

        if(debuglvl >= HIGH)
            (void)vrprint.debug(__FUNC__, "currule: '%s'.", currule);

        /* parse the line */
        if(vrmr_interfaces_rule_parse_line(debuglvl, currule, rule_ptr) < 0)
        {
            (void)vrprint.error(-1, "Internal Error", "vrmr_interfaces_rule_parse_line() failed (in: %s:%d).",
                    __FUNC__, __LINE__);
            free(rule_ptr);
        }
        else
        {
            /* append to list */
            if(vrmr_list_append(debuglvl, &iface_ptr->ProtectList, rule_ptr) == NULL)
            {
                (void)vrprint.error(-1, "Internal Error", "vrmr_list_append() failed (in: %s:%d).",
                        __FUNC__, __LINE__);
                free(rule_ptr);
                return(-1);
            }
        }
    }

    for(d_node = iface_ptr->ProtectList.top; d_node; d_node = d_node->next)
    {
        if(!(rule_ptr = d_node->data))
        {
            return(-1);
        }

        if(debuglvl >= HIGH)
            (void)vrprint.debug(__FUNC__, "a: %s, w: %s, d: %s, s: %s.", vrmr_rules_itoaction(rule_ptr->action), rule_ptr->who, rule_ptr->danger, rule_ptr->source);
    }

    return(0);
}

/*
    returncodes:
         1: ok
         0: warning (set inactive)
        -1: error
*/
int
vrmr_interfaces_check(const int debuglvl, struct vrmr_interface *iface_ptr)
{
    int     retval = 1;
    int     ipresult = 0;
    char    ipaddress[16] = "";

    /* safety first */
    if(iface_ptr == NULL)
    {
        (void)vrprint.error(-1, "Internal Error", "parameter problem (in: %s:%d).",
                __FUNC__, __LINE__);
        return(-1);
    }

    if(iface_ptr->device[0] == '\0')
    {
        (void)vrprint.warning("Warning", "the interface '%s' does not have a device.",
                iface_ptr->name);
        retval = 0;
    }

    if(iface_ptr->dynamic == TRUE)
    {
        /* now try to get the dynamic ipaddress */
        ipresult = vrmr_get_dynamic_ip(debuglvl, iface_ptr->device, iface_ptr->ipv4.ipaddress, sizeof(iface_ptr->ipv4.ipaddress));
        if(ipresult == 0)
        {
            /* set iface to down */
            iface_ptr->up = FALSE;

            /* clear the ip field */
            memset(iface_ptr->ipv4.ipaddress, 0, sizeof(iface_ptr->ipv4.ipaddress));

            (void)vrprint.info("Info", "interface '%s' is down.", iface_ptr->name);
        }
        else if(ipresult < 0)
        {
            (void)vrprint.error(-1, "Internal Error", "vrmr_get_dynamic_ip() failed (in: %s:%d).",
                    __FUNC__, __LINE__);
            return(-1);
        }
    }

    /* check the ip if we have one */
    if(iface_ptr->ipv4.ipaddress[0] != '\0')
    {
        if(vrmr_check_ipv4address(debuglvl, NULL, NULL, iface_ptr->ipv4.ipaddress, 0) != 1)
        {
            (void)vrprint.warning("Warning", "the ipaddress '%s' of interface '%s' (%s) is invalid.",
                    iface_ptr->ipv4.ipaddress, iface_ptr->name, iface_ptr->device);

            retval = 0;
        }
    }

    /* if the interface is up check the ipaddress with the ipaddress we know */
    if( iface_ptr->up == TRUE       &&
        iface_ptr->active == TRUE   &&
        iface_ptr->device_virtual == FALSE)
    {
        ipresult = vrmr_get_dynamic_ip(debuglvl, iface_ptr->device, ipaddress, sizeof(ipaddress));
        if(ipresult < 0)
        {
            (void)vrprint.error(-1, "Internal Error", "vrmr_get_dynamic_ip() failed (in: %s:%d).",
                    __FUNC__, __LINE__);
            return(-1);
        }
        else if(ipresult == 0)
        {
            /* down after all */
            iface_ptr->up = FALSE;

            if(debuglvl >= MEDIUM)
                (void)vrprint.debug(__FUNC__, "interface '%s' is down after all.", iface_ptr->name);
        }
        else
        {
            if(strcmp(ipaddress, iface_ptr->ipv4.ipaddress) != 0)
            {
                (void)vrprint.warning("Warning", "the ipaddress '%s' of interface '%s' (%s) does not match the ipaddress of the actual interface (%s).",
                        iface_ptr->ipv4.ipaddress, iface_ptr->name, iface_ptr->device, ipaddress);

                retval = 0;
            }
        }
    }

    return(retval);
}


/*  load_interfaces

    calls init_interfaces and does some checking

    returncodes:
         0: ok
        -1: error
*/
int
vrmr_interfaces_load(const int debuglvl, struct vrmr_interfaces *interfaces)
{
    struct vrmr_interface   *iface_ptr = NULL;
    struct vrmr_list_node             *d_node = NULL;
    int                     result = 0;

    (void)vrprint.info("Info", "Loading interfaces...");


    /* load the interfaces into memory */
    result = vrmr_init_interfaces(debuglvl, interfaces);
    if(result == -1)
    {
        (void)vrprint.error(-1, "Error", "Loading interfaces failed.");
        return(-1);
    }


    /* loop through the interfaces */
    for(d_node = interfaces->list.top; d_node; d_node = d_node->next)
    {
        iface_ptr = d_node->data;
        if(iface_ptr == NULL)
        {
            (void)vrprint.error(-1, "Internal Error", "NULL pointer (in: %s:%d).",
                    __FUNC__, __LINE__);
            return(-1);
        }

        result = vrmr_interfaces_check(debuglvl, iface_ptr);
        if(result == -1)
            return(-1);
        else if(result == 0)
        {
            (void)vrprint.info("Info", "Interface '%s' has been deactivated because of errors while checking it.",
                    iface_ptr->name);
            iface_ptr->active = FALSE;
        }
    }

    (void)vrprint.info("Info", "Loading interfaces succesfull.");
    return(0);
}

int
vrmr_interfaces_iface_up(const int debuglvl, struct vrmr_interface *iface_ptr)
{
    char    ipaddress[16] = "";

    /* safety first */
    if(iface_ptr == NULL)
    {
        (void)vrprint.error(-1, "Internal Error", "parameter problem (in: %s:%d).",
                __FUNC__, __LINE__);
        return(-1);
    }

    if(vrmr_get_dynamic_ip(debuglvl, iface_ptr->device, ipaddress, sizeof(ipaddress)) == 1)
        return(1);

    return(0);
}
