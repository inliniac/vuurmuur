/***************************************************************************
 *   Copyright (C) 2003-2007 by Victor Julien                              *
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

/***************************************************************************
 *   In this file most of the zonedata manipulation functions reside       *
 ***************************************************************************/

#include "config.h"
#include "vuurmuur.h"


/*  zones_split_zonename

    This function splits up the 'name' into host, network
    and zone data.

    this also sets up the parent pointers

    Returncodes:
        -1: error
         0: ok
 */
int
zones_split_zonename(const int debuglvl, struct vrmr_zones *zones,
            struct vrmr_zone *zone_ptr, regex_t *reg_ex)
{
    int     arg_count = 0;
    char    check_str[VRMR_VRMR_MAX_HOST_NET_ZONE] = "";
    char    zonename[VRMR_MAX_ZONE] = "",
            netname[VRMR_MAX_NETWORK] = "",
            hostname[VRMR_MAX_HOST] = "";

    /* safety */
    if(zone_ptr == NULL || zones == NULL || reg_ex == NULL)
    {
        (void)vrprint.error(-1, "Interal Error", "parameter problem "
                "(in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    if(debuglvl >= MEDIUM)
        (void)vrprint.debug(__FUNC__, "start: zone_ptr->name = '%s'",
                zone_ptr->name);

    /* validate and split up */
    if(vrmr_validate_zonename(debuglvl, zone_ptr->name, 0, zonename, netname,
        hostname, reg_ex, VALNAME_VERBOSE) != 0)
    {
        (void)vrprint.error(-1, "Internal Error", "name '%s' not "
                "valid (in: %s:%d).", zone_ptr->name,
                __FUNC__, __LINE__);
        return(-1);
    }

    arg_count = 2;

    if(hostname[0] == '\0')
        arg_count = 1;
    if(netname[0] == '\0')
        arg_count = 0;
    if(zonename[0] == '\0')
        return(-1);

    /* zone or firewall */
    if(arg_count == 0)
    {
        if(strlcpy(zone_ptr->zone_name, zonename,
           sizeof(zone_ptr->zone_name)) >= sizeof(zone_ptr->zone_name))
        {
            (void)vrprint.error(-1, "Internal Error", "string "
                    "overflow (in: %s:%d).", __FUNC__, __LINE__);
            return(-1);
        }
    }

    /* network */
    if(arg_count == 1)
    {
        if(strlcpy(zone_ptr->network_name, netname,
           sizeof(zone_ptr->network_name)) >= sizeof(zone_ptr->network_name))
        {
            (void)vrprint.error(-1, "Internal Error", "string "
                    "overflow (in: %s:%d).", __FUNC__, __LINE__);
            return(-1);
        }
        if(strlcpy(zone_ptr->zone_name, zonename,
           sizeof(zone_ptr->zone_name)) >= sizeof(zone_ptr->zone_name))
        {
            (void)vrprint.error(-1, "Internal Error", "string "
                    "overflow (in: %s:%d).", __FUNC__, __LINE__);
            return(-1);
        }

        zone_ptr->zone_parent = vrmr_search_zonedata(debuglvl, zones, zone_ptr->zone_name);
        if(zone_ptr->zone_parent == NULL)
        {
            (void)vrprint.error(-1, "Error", "unable to find the "
                    "zone '%s' in memory.", zone_ptr->zone_name);
            return(-1);
        }
    }

    /* host or group */
    if(arg_count == 2)
    {
        if(strlcpy(zone_ptr->host_name, hostname,
           sizeof(zone_ptr->host_name)) >= sizeof(zone_ptr->host_name))
        {
            (void)vrprint.error(-1, "Internal Error", "string "
                    "overflow (in: %s:%d).", __FUNC__, __LINE__);
            return(-1);
        }
        if(strlcpy(zone_ptr->network_name, netname,
           sizeof(zone_ptr->network_name)) >= sizeof(zone_ptr->network_name))
        {
            (void)vrprint.error(-1, "Internal Error", "string "
                    "overflow (in: %s:%d).", __FUNC__, __LINE__);
            return(-1);
        }
        if(strlcpy(zone_ptr->zone_name, zonename,
           sizeof(zone_ptr->zone_name)) >= sizeof(zone_ptr->zone_name))
        {
            (void)vrprint.error(-1, "Internal Error", "string "
                    "overflow (in: %s:%d).", __FUNC__, __LINE__);
            return(-1);
        }

        zone_ptr->zone_parent = vrmr_search_zonedata(debuglvl, zones, zone_ptr->zone_name);
        if(zone_ptr->zone_parent == NULL)
        {
            (void)vrprint.error(-1, "Error", "unable to find the "
                    "zone '%s' in memory.", zone_ptr->zone_name);
            return(-1);
        }

        snprintf(check_str, sizeof(check_str), "%s.%s",
             zone_ptr->network_name, zone_ptr->zone_name);

        zone_ptr->network_parent = vrmr_search_zonedata(debuglvl, zones, check_str);
        if(zone_ptr->network_parent == NULL)
        {
            (void)vrprint.error(-1, "Error", "Unable to find the "
                    "network '%s' in memory.", check_str);
            return(-1);
        }
    }

    return(0);
}


/*  vrmr_vrmr_insert_zonedata_list

    Inserts a zone into the list. It sorts by name. It makes sure the datastructure is
    preserved:
        zone dd
            network ee
                host    aa
                host    bb
                host    zz
                group   cc
                group   xx
            network gg
        zone ee
            etc.

    Returncodes:
         0: ok
        -1: (serious) error
*/
int
vrmr_vrmr_insert_zonedata_list(const int debuglvl, struct vrmr_zones *zones,
             const struct vrmr_zone *zone_ptr)
{
    struct vrmr_zone    *check_zone_ptr = NULL,
                        *cur_zone = NULL,
                        *cur_network = NULL;
    int                 insert_here = 0,
                        in_the_right_scope = 0;
    struct vrmr_list_node         *d_node = NULL;


    /* safety first */
    if(zones == NULL || zone_ptr == NULL) {
        (void)vrprint.error(-1, "Internal Error", "parameter problem "
                "(in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    /* if the list is empty, just insert */
    if(zones->list.len == 0)
        insert_here = 1;
    else
    {
        /* loop trough the existing list to see where to insert */
        for(d_node = zones->list.top; d_node && !insert_here; d_node = d_node->next)
        {
            if(!(check_zone_ptr = d_node->data))
            {
                (void)vrprint.error(-1, "Internal Error",
                        "NULL pointer (in: %s:%d).",
                        __FUNC__, __LINE__);
                return(-1);
            }

            if(debuglvl >= HIGH)
                (void)vrprint.debug(__FUNC__, "check_zone_ptr: "
                        "name: %s, type: %d.",
                        check_zone_ptr->name,
                        check_zone_ptr->type);

            /* store the last zone and network so we can determine the scope */
            if(check_zone_ptr->type == TYPE_ZONE)
                cur_zone = check_zone_ptr;
            else if(check_zone_ptr->type == TYPE_NETWORK)
                cur_network = check_zone_ptr;

            /* see if we are in the right scope: this means that a host is in its 'own' network, a network in its 'own' zone, etc. */
            if( (zone_ptr->type == TYPE_ZONE) ||
                (zone_ptr->type == TYPE_NETWORK && cur_zone && strcmp(cur_zone->zone_name, zone_ptr->zone_name) == 0) ||
                (zone_ptr->type == TYPE_HOST    && cur_zone && strcmp(cur_zone->zone_name, zone_ptr->zone_name) == 0  && cur_network && strcmp(cur_network->network_name, zone_ptr->network_name) == 0) ||
                (zone_ptr->type == TYPE_GROUP   && cur_zone && strcmp(cur_zone->zone_name, zone_ptr->zone_name) == 0  && cur_network && strcmp(cur_network->network_name, zone_ptr->network_name) == 0)
            )
            {
                if(debuglvl >= HIGH)
                    (void)vrprint.debug(__FUNC__, "in the "
                            "right scope %s", zone_ptr->name);

                /* we are in the right scope */
                in_the_right_scope = 1;

                /* only compare with our own type (racists! ;) */
                if(zone_ptr->type == check_zone_ptr->type)
                {
                    if(debuglvl >= HIGH)
                        (void)vrprint.debug(__FUNC__,
                                "same type %s", zone_ptr->name);

                    /*  now compare the name.

                        if the name is the same (should never happen) or 'smaller', insert
                        before the current item
                    */
                    if(strcmp(zone_ptr->name, check_zone_ptr->name) <= 0)
                    {
                        if(debuglvl >= HIGH)
                            (void)vrprint.debug(__FUNC__, "insert here %s", zone_ptr->name);

                        insert_here = 1;
                        break;
                    }
                }
            }
            /*  if were not in the right scope anymore, we need to insert right now!
                This makes sure the data is inserted in our scope. We get here when
                for example inserting the first host in a network. It can never match the
                type comparison above.
            */
            else if(in_the_right_scope)
            {
                insert_here = 1;
                break;
            }
        }
    }

    /* is d_node is untouched (NULL) we prepend. */
    if(insert_here && !d_node)
    {
        /* prepend */
        if(debuglvl >= HIGH)
            (void)vrprint.debug(__FUNC__, "prepend %s", zone_ptr->name);

        if(vrmr_list_prepend(debuglvl, &zones->list, zone_ptr) < 0)
        {
            (void)vrprint.error(-1, "Internal Error",
                    "vrmr_list_prepend() failed (in: %s:%d).",
                    __FUNC__, __LINE__);
            return(-1);
        }
    }
    else if(insert_here && d_node)
    {
        /* insert before */
        if(debuglvl >= HIGH)
            (void)vrprint.debug(__FUNC__, "insert %s", zone_ptr->name);

        if(vrmr_list_insert_before(debuglvl, &zones->list, d_node, zone_ptr) < 0)
        {
            (void)vrprint.error(-1, "Internal Error",
                    "vrmr_list_insert_before() failed (in: %s:%d).",
                    __FUNC__, __LINE__);
            return(-1);
        }
    }
    else
    {
        /* append */
        if(debuglvl >= HIGH)
            (void)vrprint.debug(__FUNC__, "append %s", zone_ptr->name);

        if(vrmr_list_append(debuglvl, &zones->list, zone_ptr) == NULL)
        {
            (void)vrprint.error(-1, "Internal Error",
                    "vrmr_list_append() failed (in: %s:%d).",
                    __FUNC__, __LINE__);
            return(-1);
        }
    }

    /* for debugging, print the entire list to the log */
    if(debuglvl >= HIGH)
    {
        for(d_node = zones->list.top; d_node; d_node = d_node->next)
        {
            if(!(check_zone_ptr = d_node->data))
            {
                (void)vrprint.error(-1, "Internal Error",
                        "NULL pointer (in: %s:%d).", __FUNC__, __LINE__);
                return(-1);
            }

            (void)vrprint.debug(__FUNC__, "list: check_zone_ptr: "
                    "name: %s, type: %d.", check_zone_ptr->name,
                    check_zone_ptr->type);
        }
    }

    return(0);
}


/*  vrmr_insert_zonedata

    Inserts the zonedata 'name' into the linked-list.

    Returncodes:
        -1: error
         0: succes
*/
int
vrmr_insert_zonedata(const int debuglvl, struct vrmr_zones *zones, struct vrmr_interfaces *interfaces,
        char *name, int type, struct vrmr_regex *reg)
{
    struct vrmr_zone    *zone_ptr = NULL;

    /* please put on your safetybelt */
    if(zones == NULL || name == NULL || reg == NULL || interfaces == NULL) {
        (void)vrprint.error(-1, "Internal Error", "parameter problem "
                "(in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    /* claiming the memory we need, in case of error
       vrmr_zone_malloc will tell the user
    */
    if(!(zone_ptr = vrmr_zone_malloc(debuglvl)))
        return(-1);

    /*
        read the data for this zone
    */
    if(vrmr_read_zonedata(debuglvl, zones, interfaces, name, type, zone_ptr, reg) < 0)
    {
        free(zone_ptr);
        return(-1);
    }

    /*
        now insert into the list
    */
    if(vrmr_vrmr_insert_zonedata_list(debuglvl, zones, zone_ptr) < 0)
    {
        (void)vrprint.error(-1, "Internal Error",
                "vrmr_vrmr_insert_zonedata_list() failed (in: %s:%d).",
                __FUNC__, __LINE__);
        return(-1);
    }

    zone_ptr->status = ST_ADDED;

    return(0);
}


/*  vrmr_read_zonedata

    Reads all the info for a zone.

    Returncodes:
         0: ok
        -1: error
*/
int
vrmr_read_zonedata(const int debuglvl, struct vrmr_zones *zones, struct vrmr_interfaces *interfaces,
          char *name, int type, struct vrmr_zone *zone_ptr, struct vrmr_regex *reg)
{
    int     result = 0;

    /* safety */
    if(name == NULL || zone_ptr == NULL || zones == NULL || reg == NULL ||
          interfaces == NULL) {
        (void)vrprint.error(-1, "Internal Error", "parameter problem "
                "(in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    if( type != TYPE_ZONE && type != TYPE_NETWORK &&
        type != TYPE_HOST && type != TYPE_GROUP)
    {
        (void)vrprint.error(-1, "Interal Error", "wrong zonetype %d "
                "(in: %s:%d).", type, __FUNC__, __LINE__);
        return(-1);
    }

    if(vrmr_validate_zonename(debuglvl, name, 1, NULL, NULL, NULL, reg->zonename, VALNAME_VERBOSE) != 0)
    {
        (void)vrprint.error(-1, "Internal Error", "invalid zonename "
                "'%s' (in: %s:%d).", name, __FUNC__, __LINE__);
        return(-1);
    }

    /* copy the name to the structure */
    if(strlcpy(zone_ptr->name, name, sizeof(zone_ptr->name)) >= sizeof(zone_ptr->name))
    {
        (void)vrprint.error(-1, "Internal Error", "buffer overflow "
                "(in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    /* set the type */
    zone_ptr->type = type;

    /* split and check */
    result = zones_split_zonename(debuglvl, zones, zone_ptr, reg->zonename);
    if(result < 0)
    {
        /* error */
        (void)vrprint.error(-1, "Internal Error", "zones_split_zonename() "
                "failed (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    /* get the active */
    result = vrmr_check_active(debuglvl, zone_ptr->name, zone_ptr->type);
    if(result == -1)
    {
        /* set false to be sure */
        zone_ptr->active = FALSE;

        /* error */
        (void)vrprint.error(-1, "Internal Error", "vrmr_check_active() "
                "failed (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }
    else if(result == 1)
        zone_ptr->active = TRUE;
    else
        zone_ptr->active = FALSE;


    if(zone_ptr->type != TYPE_ZONE && zone_ptr->type != TYPE_GROUP)
    {
        if(zone_ptr->type == TYPE_NETWORK)
        {
            result = vrmr_zones_network_get_interfaces(debuglvl, zone_ptr, interfaces);
            if(result < 0)
            {
                (void)vrprint.error(-1, "Internal Error",
                        "vrmr_zones_network_get_interfaces() "
                        "failed (in: %s:%d).", __FUNC__, __LINE__);
                return(-1);
            }

            result = vrmr_zones_network_get_protectrules(debuglvl, zone_ptr);
            if(result < 0)
            {
                (void)vrprint.error(-1, "Internal Error",
                        "vrmr_zones_network_get_protectrules() "
                        "failed (in: %s:%d).", __FUNC__, __LINE__);
                return(-1);
            }
        }

        /*
            get ip and mask
        */
        result = vrmr_get_ip_info(debuglvl, name, zone_ptr, reg);
        if(result != 0)
        {
            (void)vrprint.error(-1, "Internal Error", "get_ip_info() "
                    "failed (in: %s:%d).", __FUNC__, __LINE__);
            return(-1);
        }
    }
    else if(zone_ptr->type == TYPE_GROUP)
    {
        /* get group info */
        result = vrmr_get_group_info(debuglvl, zones, name, zone_ptr);
        if(result != 0)
        {
            (void)vrprint.error(-1, "Internal Error", "vrmr_get_group_info() "
                    "failed (in: %s:%d).", __FUNC__, __LINE__);
            return(-1);
        }
    }

    return(0);
}


/*  vrmr_search_zonedata

    Function to search the ServicesList.

    It returns the pointer or a NULL-pointer if not found.
*/
void *
vrmr_search_zonedata(const int debuglvl, const struct vrmr_zones *zones, char *name)
{
    struct vrmr_list_node         *d_node = NULL;
    struct vrmr_zone    *zonedata_ptr = NULL;


    /* safety */
    if(name == NULL || zones == NULL)
    {
        (void)vrprint.error(-1, "Internal Error", "parameter problem "
                "(in: %s:%d).", __FUNC__, __LINE__);
        return(NULL);
    }


    /* now search */
    for(d_node = zones->list.top; d_node ; d_node = d_node->next)
    {
        if(!(zonedata_ptr = d_node->data))
        {
            (void)vrprint.error(-1, "Internal Error", "NULL pointer "
                    "(in: %s:%d).", __FUNC__, __LINE__);
            return(NULL);
        }

        if(strcmp(zonedata_ptr->name, name) == 0)
        {
            if(debuglvl >= HIGH)
                (void)vrprint.debug(__FUNC__, "zone '%s' found.",
                        name);

            /* found, return */
            return(zonedata_ptr);
        }
    }

    if(debuglvl >= LOW)
        (void)vrprint.debug(__FUNC__, "zone '%s' not found.",
                name);

    /* return NULL pointer */
    return(NULL);
}


/*- print_list - */
void
vrmr_zonedata_print_list(const struct vrmr_zones *zones)
{
    struct vrmr_list_node         *d_node = NULL;
    struct vrmr_zone    *zone_ptr = NULL;

    // print size
    fprintf(stdout, "ZonedataList size: %u\n", zones->list.len);

    for(d_node = zones->list.top; d_node ; d_node = d_node->next)
    {
        zone_ptr = d_node->data;

        fprintf(stdout, "zone: %s, status: %d, active: %d, type: %d\n",
            zone_ptr->name, zone_ptr->status, zone_ptr->active, zone_ptr->type);
    }

    return;
}


/*  vrmr_init_zonedata

    Loads all zonedata in memory.

    returncodes:
         0: succes
         1: succes with one or more zonedata entries failed
        -1: error
*/
int
vrmr_init_zonedata(const int debuglvl, struct vrmr_zones *zones, struct vrmr_interfaces *interfaces, struct vrmr_regex *reg)
{
    int     retval = 0,
            result = 0,
            zonetype = 0;
    char    zonename[VRMR_VRMR_MAX_HOST_NET_ZONE] = "";

    /* safety */
    if(zones == NULL || interfaces == NULL || reg == NULL)
    {
        (void)vrprint.error(-1, "Internal Error", "parameter problem (in: %s:%d).",
                __FUNC__, __LINE__);
        return(-1);
    }

    /* init */
    memset(zones, 0, sizeof(*zones));

    /* create the list */
    if(vrmr_list_setup(debuglvl, &zones->list, NULL) < 0)
        return(-1);

    /* get the info from the backend */
    while(zf->list(debuglvl, zone_backend, zonename, &zonetype, CAT_ZONES) != NULL)
    {
        if(debuglvl >= MEDIUM)
            (void)vrprint.debug(__FUNC__, "loading zone: '%s', "
                    "type: %d", zonename, zonetype);

        if(vrmr_validate_zonename(debuglvl, zonename, 1, NULL, NULL, NULL, reg->zonename, VALNAME_VERBOSE) == 0)
        {
            result = vrmr_insert_zonedata(debuglvl, zones, interfaces, zonename, zonetype, reg);
            if(result < 0)
            {
                (void)vrprint.error(-1, "Internal Error",
                        "vrmr_insert_zonedata() failed (in: %s:%d).",
                        __FUNC__, __LINE__);
                return(-1);
            }
            else
            {
                if(debuglvl >= LOW)
                    (void)vrprint.debug(__FUNC__, "loading "
                            "zone succes: '%s' (type %d).",
                            zonename, zonetype);
            }
        }
    }

    if(debuglvl >= HIGH)
        (void)vrprint.debug(__FUNC__, "** end **, retval=%d", retval);

    return(retval);
}


void
vrmr_destroy_zonedatalist(const int debuglvl, struct vrmr_zones *zones)
{
    struct vrmr_list_node         *d_node = NULL;
    struct vrmr_zone    *zone_ptr = NULL;

    if(!zones)
        return;

    for(d_node = zones->list.top; d_node ; d_node = d_node->next)
    {
        if(!(zone_ptr = d_node->data))
        {
            (void)vrprint.error(-1, "Internal Error", "NULL "
                    "pointer (in: %s:%d).", __FUNC__, __LINE__);
            return;
        }

        vrmr_zone_free(debuglvl, zone_ptr);
    }

    vrmr_list_cleanup(debuglvl, &zones->list);
}


int
vrmr_delete_zone(const int debuglvl, struct vrmr_zones *zones, char *zonename, int zonetype)
{
    struct vrmr_zone        *zone_ptr = NULL,
                            *zone_list_ptr = NULL;
    struct vrmr_list_node             *d_node = NULL;
    char                    name[VRMR_VRMR_MAX_HOST_NET_ZONE] = "";
    struct vrmr_interface   *iface_ptr = NULL;

    /* safety */
    if(zonename == NULL || zones == NULL)
    {
        (void)vrprint.error(-1, "Internal Error", "parameter problem "
                "(in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    /* copy the name to an array so we can display the name after
       the deletion is complete */
    if(strlcpy(name, zonename, sizeof(name)) >= sizeof(name))
    {
        (void)vrprint.error(-1, "Internal Error", "string "
            "overflow (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    /* check zonetype */
    if(zonetype != TYPE_ZONE && zonetype != TYPE_NETWORK &&
          zonetype != TYPE_HOST && zonetype != TYPE_GROUP)
    {
        (void)vrprint.error(-1, "Internal Error", "expected a zone, "
                "network, host or group, but got a %d (in: %s:%d).",
                zonetype, __FUNC__, __LINE__);
        return(-1);
    }

    /* search the zone */
    if(!(zone_ptr = vrmr_search_zonedata(debuglvl, zones, zonename)))
    {
        (void)vrprint.error(-1, "Internal Error", "zone '%s' not found "
                "in memory (in: %s:%d).", zonename,
                __FUNC__, __LINE__);
        return(-1);
    }

    /* check the refernce counters */
    if(zone_ptr->type == TYPE_HOST && zone_ptr->refcnt_group > 0)
    {
        (void)vrprint.error(-1, "Internal Error", "host '%s' is still "
                "a member of %u group(s) (in: %s:%d).",
                zone_ptr->name, zone_ptr->refcnt_group,
                __FUNC__, __LINE__);
        return(-1);
    }
    if(zone_ptr->type == TYPE_HOST && zone_ptr->refcnt_blocklist > 0)
    {
        (void)vrprint.error(-1, "Internal Error", "host '%s' is still "
                "in the blocklist (%u times) (in: %s:%d).",
                zone_ptr->name, zone_ptr->refcnt_blocklist,
                __FUNC__, __LINE__);
        return(-1);
    }
    if(zone_ptr->type == TYPE_GROUP && zone_ptr->refcnt_blocklist > 0)
    {
        (void)vrprint.error(-1, "Internal Error", "group '%s' is still "
                "in the blocklist (%u times) (in: %s:%d).",
                zone_ptr->name, zone_ptr->refcnt_blocklist,
                __FUNC__, __LINE__);
        return(-1);
    }

    /* if the zone to delete is a group, decrease the refcnt_group of all members */
    if(zone_ptr->type == TYPE_GROUP)
    {
        for(d_node = zone_ptr->GroupList.top; d_node; d_node = d_node->next)
        {
            if(!(zone_list_ptr = d_node->data))
            {
                (void)vrprint.error(-1, "Internal Error",
                        "NULL pointer (in: %s:%d).",
                        __FUNC__, __LINE__);
                return(-1);
            }

            zone_list_ptr->refcnt_group--;
        }
    }
    /* or if we are a network, so the same for interfaces */
    if(zone_ptr->type == TYPE_NETWORK)
    {
        for(d_node = zone_ptr->InterfaceList.top; d_node; d_node = d_node->next)
        {
            if(!(iface_ptr = d_node->data))
            {
                (void)vrprint.error(-1, "Internal Error",
                        "NULL pointer (in: %s:%d).",
                        __FUNC__, __LINE__);
                return(-1);
            }

            iface_ptr->refcnt_network--;
        }
    }

    /* delete the zone from the backend */
    if(zf->del(debuglvl, zone_backend, zonename, zonetype, 1) < 0)
    {
        (void)vrprint.error(-1, "Internal Error", "zone '%s' could not "
                "be deleted (in: %s:%d).", zonename, __FUNC__, __LINE__);
        return(-1);
    }

    /* find its position in the list */
    for(d_node = zones->list.top; d_node; d_node = d_node->next)
    {
        if(!(zone_list_ptr = d_node->data))
        {
            (void)vrprint.error(-1, "Internal Error", "NULL pointer "
                    "(in: %s:%d).", __FUNC__, __LINE__);
            return(-1);
        }

        if(strcmp(zonename, zone_list_ptr->name) == 0)
        {
            /* remove from list */
            if(vrmr_list_remove_node(debuglvl, &zones->list, d_node) < 0)
            {
                (void)vrprint.error(-1, "Internal Error",
                        "NULL pointer (in: %s:%d).",
                        __FUNC__, __LINE__);
                return(-1);
            }

            /* remove from memory */
            vrmr_zone_free(debuglvl, zone_list_ptr);
            /* we're done */
            return(0);
        }
    }

    /* we should never get here */
    (void)vrprint.error(-1, "Internal Error", "zone not found in memory "
            "(in: %s:%d).", __FUNC__, __LINE__);
    return(-1);
}


/*  vrmr_new_zone

    TODO: the spliting of name is totally wacked
*/
int
vrmr_new_zone(const int debuglvl, struct vrmr_zones *zones, char *zonename, int zonetype)
{
    struct vrmr_zone    *zone_ptr=NULL;
    size_t              dotcount=0,
                        i=0,
                        x=0;
    char                parent_str[VRMR_MAX_NET_ZONE] = "";


    /* safety */
    if(!zonename || !zones)
    {
        (void)vrprint.error(-1, "Internal Error", "parameter problem (in: %s).", __FUNC__);
        return(-1);
    }


    /* allocated memory for the new zone */
    if(!(zone_ptr = vrmr_zone_malloc(debuglvl)))
    {
        (void)vrprint.error(-1, "Error", "malloc failed (in: vrmr_new_zone).");
        return(-1);
    }

    for(i=0, dotcount=0; i < strlen(zonename); i++)
    {
        if(zonename[i] == '.')
            dotcount++;
    }

    if(dotcount > 2)
    {
        (void)vrprint.error(-1, "Error", "Invalid name '%s' (in: vrmr_new_zone).", zonename);
        return(-1);
    }

    if(dotcount == 0)
    {
        for(i=0; i < strlen(zonename); i++)
        {
            zone_ptr->zone_name[i] = zonename[i];
        }
        zone_ptr->zone_name[i]='\0';
    }
    else if(dotcount == 1)
    {
        // network
        for(i=0; i < strlen(zonename);i++)
        {
            if(zonename[i] == '.')
                break;
            zone_ptr->network_name[i] = zonename[i];
        }
        zone_ptr->network_name[i]='\0';

        for(i=strlen(zone_ptr->network_name)+1, x=0; i < strlen(zonename) ;i++, x++)
        {
            zone_ptr->zone_name[x] = zonename[i];
        }
        zone_ptr->zone_name[x]='\0';

    }
    else
    {
        // host/group
        for(i=0; i < strlen(zonename);i++)
        {
            if(zonename[i] == '.')
                break;
            zone_ptr->host_name[i] = zonename[i];
        }
        zone_ptr->host_name[i]='\0';

        for(i=strlen(zone_ptr->host_name)+1, x=0; i < strlen(zonename) ;i++, x++)
        {
            if(zonename[i] == '.')
                break;
            zone_ptr->network_name[x] = zonename[i];
        }
        zone_ptr->network_name[x]='\0';

        for(i = strlen(zone_ptr->host_name) + 1 + strlen(zone_ptr->network_name) + 1, x = 0; i < strlen(zonename); i++, x++)
        {
            zone_ptr->zone_name[x] = zonename[i];
        }
        zone_ptr->zone_name[x]='\0';
    }


    /* check if the zone already exists */
    if(vrmr_search_zonedata(debuglvl, zones, zonename) != NULL)
    {
        (void)vrprint.error(-1, "Error", "zonename '%s' already exists (in: vrmr_new_zone).", zonename);

        vrmr_zone_free(debuglvl, zone_ptr);
        return(-1);
    }


    /* set the bare minimum */
    if(strlcpy(zone_ptr->name, zonename, sizeof(zone_ptr->name)) >= sizeof(zone_ptr->name))
    {
        (void)vrprint.error(-1, "Internal Error", "string "
            "overflow (in: %s:%d).", __FUNC__, __LINE__);
        vrmr_zone_free(debuglvl, zone_ptr);
        return(-1);
    }

    zone_ptr->type = zonetype;


    /* set the parent(s) */
    snprintf(parent_str, sizeof(parent_str), "%s.%s", zone_ptr->network_name, zone_ptr->zone_name);
    if(zone_ptr->type == TYPE_HOST || zone_ptr->type == TYPE_GROUP)
    {
        if(!(zone_ptr->network_parent = vrmr_search_zonedata(debuglvl, zones, parent_str)))
        {
            (void)vrprint.error(-1, "Internal Error", "can't find the network-parent in the list (in: vrmr_new_zone).");
            return(-1);
        }
    }
    if(zone_ptr->type == TYPE_HOST || zone_ptr->type == TYPE_GROUP || zone_ptr->type == TYPE_NETWORK)
    {
        if(!(zone_ptr->zone_parent = vrmr_search_zonedata(debuglvl, zones, zone_ptr->zone_name)))
        {
            (void)vrprint.error(-1, "Internal Error", "can't find the zone-parent in the list (in: vrmr_new_zone).");
            return(-1);
        }
    }


    /* insert into the list */
    if(vrmr_vrmr_insert_zonedata_list(debuglvl, zones, zone_ptr) < 0)
    {
        (void)vrprint.error(-1, "Internal Error", "unable to insert new zone into the list (in: %s).", __FUNC__);
        return(-1);
    }


    /* add the zone to the backend */
    if(zf->add(debuglvl, zone_backend, zonename, zonetype) < 0)
    {
        (void)vrprint.error(-1, "Error", "Add to backend failed (in: vrmr_new_zone).");
        return(-1);
    }


    /* set active */
    if(zf->tell(debuglvl, zone_backend, zonename, "ACTIVE", zone_ptr->active ? "Yes" : "No", 1, zonetype) < 0)
    {
        (void)vrprint.error(-1, "Error", "Tell backend failed (in: vrmr_new_zone).");
        return(-1);
    }

    (void)vrprint.info("Info", "new zone '%s' succesfully added to the backend.", zonename);
    return(0);
}


/*
    TODO: input check
*/
int
vrmr_count_zones(const int debuglvl, struct vrmr_zones *zones, int type, char *filter_network,
        char *filter_zone)
{
    struct vrmr_zone    *zone_ptr = NULL;
    int                 count = 0;
    struct vrmr_list_node         *d_node = NULL;

    for(d_node = zones->list.top; d_node; d_node = d_node->next)
    {
        if(!(zone_ptr = d_node->data))
        {
            (void)vrprint.error(-1, "Internal Error", "NULL pointer "
                    "(in: %s:%d).", __FUNC__, __LINE__);
            return(-1);
        }

        if(zone_ptr->type == type)
        {
            if(filter_zone != NULL)
            {
                if(strcmp(filter_zone, zone_ptr->zone_name) == 0)
                {
                    if(filter_network != NULL)
                    {
                        if(strcmp(filter_network, zone_ptr->network_name) == 0)
                        {
                            count++;
                        }
                    }
                    else
                    {
                        count++;
                    }
                }
            }
            else
            {
                count++;
            }
        }
    }

    return(count);
}


/*  vrmr_zonelist_to_networklist

    Function to load the networks of a list into a new networklist. The
    networks in the original list will be untouched.

    Returncodes:
         0: ok
        -1: error

*/
int
vrmr_zonelist_to_networklist(const int debuglvl, struct vrmr_zones *zones, struct vrmr_list *network_list)
{
    struct vrmr_list_node         *d_node = NULL;
    struct vrmr_zone    *zone_ptr = NULL;

    /*
        safety
    */
    if(!zones || !network_list)
    {
        (void)vrprint.error(-1, "Internal Error", "parameter problem (in: vrmr_zonelist_to_networklist).");
        return(-1);
    }

    for(d_node = zones->list.top; d_node; d_node = d_node->next)
    {
        if(!(zone_ptr = d_node->data))
        {
            (void)vrprint.error(-1, "Internal Error", "zone_ptr == NULL! (in: vrmr_zonelist_to_networklist).");
            return(-1);
        }

        if(zone_ptr->type == TYPE_NETWORK)
        {
            if(vrmr_list_append(debuglvl, network_list, zone_ptr) == NULL)
            {
                (void)vrprint.error(-1, "Internal Error", "appending to the list failed (in: vrmr_zonelist_to_networklist).");
                return(-1);
            }
        }
    }

    return(0);
}


/*  vrmr_add_broadcasts_zonelist

    Adds the broadcast address of networks as TYPE_FIREWALL's to the zone_list

    We ignore 255.255.255.255 because its a general broadcast, and i don't want
    it to show like internet.ext(broadcast).

    Returncodes:
         0: ok
        -1: error
*/
int
vrmr_add_broadcasts_zonelist(const int debuglvl, struct vrmr_zones *zones)
{
    struct vrmr_zone    *zone_ptr = NULL,
                        *broadcast_ptr = NULL;
    struct vrmr_list_node         *d_node = NULL;

    /* safety */
    if(!zones)
    {
        (void)vrprint.error(-1, "Internal Error", "parameter problem (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    /*
        now run through the list
    */
    for(d_node = zones->list.top; d_node; d_node = d_node->next)
    {
        if(!(zone_ptr = d_node->data))
        {
            (void)vrprint.error(-1, "Internal Error", "NULL pointer (in: %s:%d).", __FUNC__, __LINE__);
            return(-1);
        }

        if(zone_ptr->type == TYPE_NETWORK)
        {
            if(strcmp(zone_ptr->ipv4.broadcast, "255.255.255.255") != 0)
            {
                /* allocate memory */
                if(!(broadcast_ptr = vrmr_zone_malloc(debuglvl)))
                    return(-1);

                /*  store the bare minimum:
                        name
                        ipaddress
                        type
                */
                snprintf(broadcast_ptr->name, VRMR_VRMR_MAX_HOST_NET_ZONE, "%s(broadcast)", zone_ptr->name);

                if(strlcpy(broadcast_ptr->ipv4.ipaddress, zone_ptr->ipv4.broadcast, sizeof(broadcast_ptr->ipv4.ipaddress)) >= sizeof(broadcast_ptr->ipv4.ipaddress))
                {
                    (void)vrprint.error(-1, "Internal Error", "string "
                            "overflow (in: %s:%d).", __FUNC__, __LINE__);
                    vrmr_zone_free(debuglvl, broadcast_ptr);
                    return(-1);
                }

                broadcast_ptr->type = TYPE_FIREWALL;

                if(debuglvl >= MEDIUM)
                    (void)vrprint.debug(__FUNC__, "%s addr: %s", broadcast_ptr->name, broadcast_ptr->ipv4.ipaddress);

                /* insert into the list */
                if(vrmr_list_append(debuglvl, &zones->list, broadcast_ptr) == NULL)
                {
                    (void)vrprint.error(-1, "Internal Error", "appending to the list failed (in: %s:%d).", __FUNC__, __LINE__);
                    vrmr_zone_free(debuglvl, broadcast_ptr);
                    return(-1);
                }
            }
        }
    }

    return(0);
}

/*
    NOTE: THIS FUCNTION REQUIRES THE ZONE, NETWORK AND HOST VARIABLES TO BE OF THE SIZES: VRMR_MAX_ZONE, VRMR_MAX_NETWORK, VRMR_MAX_HOST!!!
    This is for bufferoverflow prevention.

    'int what' can be VAL_ZONE_TOTAL, VAL_ZONE_ZONE, VAL_ZONE_NETWORK, VAL_ZONE_HOST

*/
int
vrmr_validate_zonename(const int debuglvl, const char *zonename, int onlyvalidate, char *zone, char *network, char *host, regex_t *reg_ex, char quiet)
{
    int         retval=0;
    /* this initalization pleases splint */
    regmatch_t  reg_match[8] = {{0,0}, {0,0}, {0,0}, {0,0}, {0,0}, {0,0}, {0,0}, {0,0}};

    if(debuglvl >= MEDIUM)
        (void)vrprint.debug(__FUNC__, "checking: %s, onlyvalidate: %s.", zonename, onlyvalidate ? "Yes" : "No");

    if(onlyvalidate == 1)
    {
        if(regexec(reg_ex, zonename, 0, NULL, 0) != 0)
        {
            if(quiet == VALNAME_VERBOSE)
                (void)vrprint.error(-1, "Error", "zonename '%s' is invalid. A zonename can contain normal letters and numbers and the underscore (_) and minus (-) characters.", zonename);

            if(debuglvl >= MEDIUM)
                (void)vrprint.debug(__FUNC__, "'%s' is invalid.", zonename);

            return(-1);
        }
    }

    if(onlyvalidate == 0)
    {
        if(regexec(reg_ex, zonename, 8, reg_match, 0) != 0)
        {
            if(quiet == VALNAME_VERBOSE)
                (void)vrprint.error(-1, "Error", "zonename '%s' is invalid. A zonename can contain normal letters and numbers and the underscore (_) and minus (-) characters.", zonename);

            if(debuglvl >= MEDIUM)
                (void)vrprint.debug(__FUNC__, "'%s' is invalid.", zonename);

            return(-1);
        }

        if(reg_match[7].rm_eo-reg_match[7].rm_so == 0)
        {
            host[0]='\0';

            if(reg_match[4].rm_eo-reg_match[4].rm_so == 0)
            {
                network[0]='\0';

                if(reg_match[1].rm_eo-reg_match[1].rm_so == 0)
                {
                    zone[0]='\0';
                    retval=-1;
                }
                else
                {
                    (void)range_strcpy(zone, zonename, (size_t)reg_match[1].rm_so, (size_t)reg_match[1].rm_eo, VRMR_MAX_ZONE);
                    if(debuglvl >= HIGH)
                        (void)vrprint.debug(__FUNC__, "zone: %s.", zone);
                }
            }
            else
            {
                (void)range_strcpy(network, zonename, (size_t)reg_match[1].rm_so, (size_t)reg_match[1].rm_eo, VRMR_MAX_NETWORK);
                (void)range_strcpy(zone, zonename, (size_t)reg_match[4].rm_so, (size_t)reg_match[4].rm_eo, VRMR_MAX_ZONE);
                if(debuglvl >= HIGH)
                    (void)vrprint.debug(__FUNC__, "zone: %s, network: %s.", zone, network);
            }
        }
        else
        {
            (void)range_strcpy(host, zonename, (size_t)reg_match[1].rm_so, (size_t)reg_match[1].rm_eo, VRMR_MAX_HOST);
            (void)range_strcpy(network, zonename, (size_t)reg_match[4].rm_so, (size_t)reg_match[4].rm_eo, VRMR_MAX_NETWORK);
            (void)range_strcpy(zone, zonename, (size_t)reg_match[7].rm_so, (size_t)reg_match[7].rm_eo, VRMR_MAX_ZONE);
            if(debuglvl >= HIGH)
                (void)vrprint.debug(__FUNC__, "zone: %s, network: %s, host: %s.", zone, network, host);
        }
    }
    else
    {
        if(debuglvl >= MEDIUM)
            (void)vrprint.debug(__FUNC__, "'%s' is valid.", zonename);
    }

    return(retval);
}


/*  vrmr_zones_group_save_members

    Save the group members to the backend.

    Returncodes:
         0: ok
        -1: error
*/
int
vrmr_zones_group_save_members(const int debuglvl, struct vrmr_zone *group_ptr)
{
    struct vrmr_list_node         *d_node = NULL;
    struct vrmr_zone    *member_ptr = NULL;

    /* safety */
    if(!group_ptr)
    {
        (void)vrprint.error(-1, "Internal Error", "parameter problem (in: %s).", __FUNC__);
        return(-1);
    }

    /* safety */
    if(group_ptr->GroupList.len < 0)
    {
        (void)vrprint.error(-1, "Internal Error", "negative number of groupmembers (in: %s).", __FUNC__);
        return(-1);
    }

    /* write to backend */
    if(group_ptr->GroupList.len == 0)
    {
        /* clear */
        if(zf->tell(debuglvl, zone_backend, group_ptr->name, "MEMBER", "", 1, TYPE_GROUP) < 0)
        {
            (void)vrprint.error(-1, "Error", "saving to backend failed (in: %s).", __FUNC__);
            return(-1);
        }
    }
    else
    {
        /* write to backend */
        for(d_node = group_ptr->GroupList.top; d_node; d_node = d_node->next)
        {
            if(!(member_ptr = d_node->data))
            {
                (void)vrprint.error(-1, "Internal Error", "NULL pointer (in: %s).", __FUNC__);
                return(-1);
            }

            if(d_node == group_ptr->GroupList.top)
            {
                /* save to backend */
                if(zf->tell(debuglvl, zone_backend, group_ptr->name, "MEMBER", member_ptr->host_name, 1, TYPE_GROUP) < 0)
                {
                    (void)vrprint.error(-1, "Error", "saving to backend failed (in: %s).", __FUNC__);
                    return(-1);
                }
            }
            else
            {
                /* save to backend */
                if(zf->tell(debuglvl, zone_backend, group_ptr->name, "MEMBER", member_ptr->host_name, 0, TYPE_GROUP) < 0)
                {
                    (void)vrprint.error(-1, "Error", "saving to backend failed (in: %s).", __FUNC__);
                    return(-1);
                }
            }
        }
    }

    return(0);
}


int
vrmr_zones_group_rem_member(const int debuglvl, struct vrmr_zone *group_ptr, char *hostname)
{
    struct vrmr_list_node         *d_node = NULL;
    struct vrmr_zone    *member_ptr = NULL;

    /* safety */
    if(!group_ptr || !hostname)
    {
        (void)vrprint.error(-1, "Internal Error", "parameter problem (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }
    /* this should not happen, but it cant hurt checking right? */
    if(group_ptr->type != TYPE_GROUP)
    {
        (void)vrprint.error(-1, "Internal Error", "Expected a GROUP (%d), but got a %d! (in: %s)", TYPE_GROUP, group_ptr->type, __FUNC__);
        return(-1);
    }

    /* search the member */
    for(d_node = group_ptr->GroupList.top; d_node; d_node = d_node->next)
    {
        if(!(member_ptr = d_node->data))
        {
            (void)vrprint.error(-1, "Internal Error", "NULL pointer (in: %s).", __FUNC__);
            return(-1);
        }

        /* here is is */
        if(strcmp(hostname, member_ptr->host_name) == 0)
        {
            /* decrease refcnt */
            member_ptr->refcnt_group--;

            /* okay, lets remove the hugeassmotherf*cker */
            if(vrmr_list_remove_node(debuglvl, &group_ptr->GroupList, d_node) < 0)
            {
                (void)vrprint.error(-1, "Internal Error", "unable to remove member from the list (in: %s:%d).", __FUNC__, __LINE__);
                return(-1);
            }
            else
                break;
        }
    }

    /* save the new group list */
    if(vrmr_zones_group_save_members(debuglvl, group_ptr) < 0)
    {
        (void)vrprint.error(-1, "Error", "saveing the new grouplist to the backend failed (in: %s).", __FUNC__);
        return(-1);
    }

    /* for logging */
    (void)vrprint.info("Info", "group '%s' has been changed: the member '%s' has been removed.", group_ptr->name, hostname);
    return(0);
}


int
vrmr_zones_group_add_member(const int debuglvl, struct vrmr_zones *zones, struct vrmr_zone *group_ptr, char *hostname)
{
    struct vrmr_zone    *new_member_ptr = NULL,
                        *list_member_ptr = NULL;
    struct vrmr_list_node         *d_node = NULL;

    /* safety */
    if(!group_ptr || !zones || !hostname)
    {
        (void)vrprint.error(-1, "Internal Error", "parameter problem (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    /* now search the host in memory */
    new_member_ptr = vrmr_search_zonedata(debuglvl, zones, hostname);
    if(!new_member_ptr)
    {
        (void)vrprint.error(-1, "Internal Error", "member '%s' is invalid, it was not found in memory.", hostname);
        return(-1);
    }

    /* check if our member is a host */
    if(new_member_ptr->type != TYPE_HOST)
    {
        (void)vrprint.error(-1, "Internal Error", "member '%s' is not a host!", hostname);
        return(-1);
    }

    /* let's see if the host is already a member */
    for(d_node = group_ptr->GroupList.top; d_node; d_node = d_node->next)
    {
        if(!(list_member_ptr = d_node->data))
        {
            (void)vrprint.error(-1, "Internal Error", "NULL pointer (in: %s).", __FUNC__);
            return(-1);
        }

        if(strcmp(list_member_ptr->name, hostname) == 0)
        {
            (void)vrprint.error(-1, "Error", "host '%s' is already a member of group '%s'.", hostname, group_ptr->name);
            return(-1);
        }
    }

    /* increase refcnt */
    new_member_ptr->refcnt_group++;

    /* now append the new at the tail of the list */
    if(vrmr_list_append(debuglvl, &group_ptr->GroupList, new_member_ptr) == NULL)
    {
        (void)vrprint.error(-1, "Internal Error", "unable to append member to groupslist (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    /* save the new group list */
    if(vrmr_zones_group_save_members(debuglvl, group_ptr) < 0)
    {
        (void)vrprint.error(-1, "Error", "saveing the new grouplist to the backend failed (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    (void)vrprint.info("Info", "group '%s' has been changed: the member '%s' has been added.", group_ptr->name, hostname);
    return(0);
}


/*  adds an interface to a network

    returncodes:
        -1: error
         0: ok
*/
int
vrmr_zones_network_add_iface(const int debuglvl, struct vrmr_interfaces *interfaces, struct vrmr_zone *network_ptr, char *interfacename)
{
    struct vrmr_interface   *iface_ptr = NULL,
                            *list_iface_ptr = NULL;
    struct vrmr_list_node             *d_node = NULL;

    /* safety */
    if(!interfaces || !network_ptr || !interfacename)
    {
        (void)vrprint.error(-1, "Internal Error", "parameter problem (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    /* let's see if the interface is already in the list */
    for(d_node = network_ptr->InterfaceList.top; d_node; d_node = d_node->next)
    {
        if(!(list_iface_ptr = d_node->data))
        {
            (void)vrprint.error(-1, "Internal Error", "NULL pointer (in: %s:%d).", __FUNC__, __LINE__);
            return(-1);
        }

        if(strcmp(list_iface_ptr->name, interfacename) == 0)
        {
            (void)vrprint.warning("Warning", "interface '%s' is already attached to network '%s'.", interfacename, network_ptr->name);
            return(0); /* non-fatal */
        }
    }

    /* search the interface in the interface list */
    if(!(iface_ptr = vrmr_search_interface(debuglvl, interfaces, interfacename)))
    {
        (void)vrprint.warning("Warning", "the interface '%s' of network '%s' was not found in memory.", interfacename, network_ptr->name);
        return(0); /* non-fatal */
    }

    /* append to the list */
    if(!(vrmr_list_append(debuglvl, &network_ptr->InterfaceList, iface_ptr)))
    {
        (void)vrprint.error(-1, "Internal Error", "appending to the list failed (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    if(iface_ptr->active == TRUE)
    {
        /* count the active interfaces */
        network_ptr->active_interfaces++;
    }

    /* increase the reference counter of the interface */
    iface_ptr->refcnt_network++;

    return(0);
}


int
vrmr_zones_network_rem_iface(const int debuglvl, struct vrmr_zone *network_ptr, char *interfacename)
{
    struct vrmr_list_node             *d_node = NULL;
    struct vrmr_interface   *iface_ptr = NULL;

    /* safety */
    if(!interfacename || !network_ptr)
    {
        (void)vrprint.error(-1, "Internal Error", "parameter problem (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    /* safety: we expect a network */
    if(network_ptr->type != TYPE_NETWORK)
    {
        (void)vrprint.error(-1, "Internal Error", "expected a NETWORK (%d), but got a %d! (in: %s)", TYPE_NETWORK, network_ptr->type, __FUNC__);
        return(-1);
    }

    /* search the interface, we start searching at the top of the list */
    for(d_node = network_ptr->InterfaceList.top; d_node; d_node = d_node->next)
    {
        if(!(iface_ptr = d_node->data))
        {
            (void)vrprint.error(-1, "Internal Error", "NULL pointer (in: %s:%d).", __FUNC__, __LINE__);
            return(-1);
        }

        /* check if this is the one */
        if(strcmp(interfacename, iface_ptr->name) == 0)
        {
            if(vrmr_list_remove_node(debuglvl, &network_ptr->InterfaceList, d_node) < 0)
            {
                (void)vrprint.error(-1, "Internal Error", "unable to remove interface from the list (in: %s:%d).", __FUNC__, __LINE__);
                return(-1);
            }

            iface_ptr->refcnt_network--;
            break;
        }
    }

    /* save the new interface list */
    if(vrmr_zones_network_save_interfaces(debuglvl, network_ptr) < 0)
    {
        (void)vrprint.error(-1, "Error", "saving the new interfaceslist to the backend failed (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    return(0);
}


/*  vrmr_zones_network_get_interfaces

    Returncodes:
         0: ok
        -1: error
 */
int
vrmr_zones_network_get_interfaces(const int debuglvl, struct vrmr_zone *zone_ptr, struct vrmr_interfaces *interfaces)
{
    char    cur_ifac[VRMR_MAX_INTERFACE] = "";

    /* safety */
    if(zone_ptr == NULL || interfaces == NULL)
    {
        (void)vrprint.error(-1, "Internal Error", "parameter problem (in: %s:%d).",
                __FUNC__, __LINE__);
        return(-1);
    }

    /* check if the zone is a network */
    if(zone_ptr->type != TYPE_NETWORK)
    {
        (void)vrprint.error(-1, "Internal Error", "zone '%s' is not a network, but a '%d' (in: %s:%d).",
                zone_ptr->name, zone_ptr->type, __FUNC__);
        return(-1);
    }

    /* reset active interfaces */
    zone_ptr->active_interfaces = 0;

    /* get all interfaces from the backend */
    while((zf->ask(debuglvl, zone_backend, zone_ptr->name, "INTERFACE", cur_ifac, sizeof(cur_ifac), TYPE_NETWORK, 1)) == 1)
    {
        if(vrmr_zones_network_add_iface(debuglvl, interfaces, zone_ptr, cur_ifac) < 0)
        {
            (void)vrprint.error(-1, "Internal Error", "vrmr_zones_network_add_iface() failed (in: %s:%d).",
                    __FUNC__, __LINE__);
            return(-1);
        }
    }

    if(debuglvl >= HIGH)
        (void)vrprint.debug(__FUNC__, "active_interfaces: %d.", zone_ptr->active_interfaces);

    return(0);
}


int
vrmr_zones_network_save_interfaces(const int debuglvl, struct vrmr_zone *network_ptr)
{
    struct vrmr_list_node             *d_node = NULL;
    struct vrmr_interface   *iface_ptr = NULL;

    /* safety */
    if(!network_ptr)
    {
        (void)vrprint.error(-1, "Internal Error", "parameter problem (in: %s:%d).",
                __FUNC__, __LINE__);
        return(-1);
    }

    if(debuglvl >= HIGH)
        (void)vrprint.debug(__FUNC__, "network: %s, interfaces: %d", network_ptr->name, network_ptr->InterfaceList.len);

    /* check if the zone is a network */
    if(network_ptr->type != TYPE_NETWORK)
    {
        (void)vrprint.error(-1, "Internal Error", "zone '%s' is not a network, but a '%d' (in: %s:%d).",
                network_ptr->name, network_ptr->type, __FUNC__);
        return(-1);
    }

    /* write the new list to the backend */
    if(network_ptr->InterfaceList.len == 0)
    {
        /* clear by writing "" in overwrite mode */
        if(zf->tell(debuglvl, zone_backend, network_ptr->name, "INTERFACE", "", 1, TYPE_NETWORK) < 0)
        {
            (void)vrprint.error(-1, "Error", "writing to backend failed (in: %s).", __FUNC__);
            return(-1);
        }
    }
    else
    {
        /*
            save the new interfaces list to the backend
        */
        for(d_node = network_ptr->InterfaceList.top; d_node; d_node = d_node->next)
        {
            if(!(iface_ptr = d_node->data))
            {
                (void)vrprint.error(-1, "Internal Error", "NULL pointer (in: %s).", __FUNC__);
                return(-1);
            }

            if(d_node == network_ptr->InterfaceList.top)
            {
                /* the first one is in overwrite mode */
                if(zf->tell(debuglvl, zone_backend, network_ptr->name, "INTERFACE", iface_ptr->name, 1, TYPE_NETWORK) < 0)
                {
                    (void)vrprint.error(-1, "Error", "writing to backend failed (in: %s).", __FUNC__);
                    return(-1);
                }
            }
            else
            {
                /* no overwriting, just appending */
                if(zf->tell(debuglvl, zone_backend, network_ptr->name, "INTERFACE", iface_ptr->name, 0, TYPE_NETWORK) < 0)
                {
                    (void)vrprint.error(-1, "Error", "writing to backend failed (in: %s).", __FUNC__);
                    return(-1);
                }
            }
        }
    }

    return(0);
}


/*  rules_analyse_rule

    Function for gathering the info for creation of the rule
    and for sanity checking the rule.

    Returncodes:
         0: ok
        -1: error
 */
int
vrmr_zones_network_analyze_rule( const int debuglvl,
                            struct vrmr_rule *rule_ptr,
                            struct vrmr_rule_cache *create,
                            struct vrmr_zones *zones,
                            struct vrmr_config *cnf)
{
    int result = 0;


    /* safety */
    if( rule_ptr == NULL || create == NULL || zones == NULL)
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
            if(rule_ptr->type == PROT_IPTABLES)
            {
                create->who_int = NULL;

                if(!(create->who = vrmr_search_zonedata(debuglvl, zones, rule_ptr->who)))
                {
                    (void)vrprint.error(-1, "Error", "zone '%s' not found (in: %s).", rule_ptr->who, __FUNC__);
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
    /* network accept rule */
    else if(rule_ptr->type == PROT_IPTABLES &&
        (rule_ptr->action == VRMR_AT_ACCEPT ||
        rule_ptr->action == VRMR_AT_QUEUE))
    {
        create->danger.solution = PROT_IPTABLES;

        /* description */
        if(cnf->bash_out && create->description != NULL)
        {
            snprintf(create->description, VRMR_MAX_BASH_DESC, "rule: action: %s, service: %s",
                    vrmr_rules_itoaction(rule_ptr->action), rule_ptr->service);
        }

        /* get who */
        if(strcmp(rule_ptr->who, "") != 0)
        {
            create->who_int = NULL;

            if(!(create->who = vrmr_search_zonedata(debuglvl, zones, rule_ptr->who)))
            {
                (void)vrprint.error(-1, "Error", "zone '%s' not found (in: %s).", rule_ptr->who, __FUNC__);
                return(-1);
            }
        }

        if( strcasecmp(rule_ptr->service, "dhcp-client") == 0 ||
            strcasecmp(rule_ptr->service, "dhcp-server") == 0)
        {
            /* not much here */
            if(debuglvl >= MEDIUM)
                (void)vrprint.debug(__FUNC__, "network rule service '%s'", rule_ptr->service);
        }
        else
        {
            (void)vrprint.error(-1, "Error", "unknown service '%s' in network rule (in: %s:%d).",
                    rule_ptr->service, __FUNC__, __LINE__);
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
vrmr_zones_network_rule_parse_line(const int debuglvl, const char *line, struct vrmr_rule *rule_ptr)
{
    size_t  line_pos = 0, // position in line
            var_pos=0; // position in varible
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
        (void)vrprint.error(-1, "Internal Error", "rule is too long (in: %s).", __FUNC__);
        return(-1);
    }

    /* get the action */
    for(; line_pos < sizeof(action_str)-1 && line[line_pos] != ' ' && line[line_pos] != '\0' && line[line_pos] != '\n'; line_pos++, var_pos++)
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

        /* check for the against keyword */
        if(strcasecmp(against_keyw, "against") != 0)
        {
            (void)vrprint.error(-1, "Error", "expected keyword 'against', got '%s' (in: %s:%d).", against_keyw, __FUNC__, __LINE__);
            return(-1);
        }

        /* okay, now lets see what kind of danger we are talking about */
        for(line_pos++, var_pos = 0; var_pos < sizeof(rule_ptr->danger) && line[line_pos] != ' ' && line[line_pos] != '\0' && line[line_pos] != '\n'; line_pos++, var_pos++)
        {
            rule_ptr->danger[var_pos] = line[line_pos];
        }
        rule_ptr->danger[var_pos] = '\0';

        if(debuglvl >= HIGH)
            (void)vrprint.debug(__FUNC__, "protect: danger: '%s'", rule_ptr->danger);

        /* now determine if the danger is 'spoofing' */
        if(strcasecmp(rule_ptr->danger, "spoofing") != 0)
        {
            (void)vrprint.error(-1, "Error", "expected danger 'spoofing', got '%s' (in: %s:%d).", rule_ptr->danger, __FUNC__, __LINE__);
            return(-1);
        }

        /* get the 'from' */
        for(line_pos++, var_pos = 0; var_pos < strlen("from") && line[line_pos] != ' ' && line[line_pos] != '\0' && line[line_pos] != '\n'; line_pos++, var_pos++)
        {
            rule_ptr->source[var_pos] = line[line_pos];
        }
        rule_ptr->source[var_pos] = '\0';

        if(debuglvl >= HIGH)
            (void)vrprint.debug(__FUNC__, "protect: keyword from: '%s'", rule_ptr->source);

        /* if 'from' is missing, the rule is malformed, so we bail out screaming & kicking */
        if(strcasecmp(rule_ptr->source, "from") != 0)
        {
            (void)vrprint.error(-1, "Error", "bad rule syntax, keyword 'from' is missing: %s (in: %s).", line, __FUNC__);
            return(-1);
        }

        /* get the source */
        for(line_pos++, var_pos = 0; var_pos < sizeof(rule_ptr->source) && line[line_pos] != ' ' && line[line_pos] != '\0' && line[line_pos] != '\n'; line_pos++, var_pos++)
        {
            rule_ptr->source[var_pos] = line[line_pos];
        }
        rule_ptr->source[var_pos] = '\0';

        if(debuglvl >= HIGH)
            (void)vrprint.debug(__FUNC__, "protect: source: '%s'", rule_ptr->source);

        /* set the ruletype */
        rule_ptr->type = PROT_IPTABLES;
    }
    /* accept target */
    else if(rule_ptr->action == VRMR_AT_ACCEPT)
    {
        if(debuglvl >= MEDIUM)
            (void)vrprint.debug(__FUNC__, "action: '%s'", vrmr_rules_itoaction(rule_ptr->action));

        for(line_pos++, var_pos = 0; var_pos < sizeof(rule_ptr->service) && line[line_pos] != ' ' && line[line_pos] != ',' &&line[line_pos] != '\0' && line[line_pos] != '\n'; line_pos++, var_pos++)
        {
            rule_ptr->service[var_pos] = line[line_pos];
        }
        rule_ptr->service[var_pos] = '\0';

        if(debuglvl >= MEDIUM)
            (void)vrprint.debug(__FUNC__, "service: '%s'", rule_ptr->service);

//TODO options

        rule_ptr->type = PROT_IPTABLES;
    }

    return(0);
}


int
vrmr_zones_network_get_protectrules(const int debuglvl, struct vrmr_zone *network_ptr)
{
    char                currule[VRMR_MAX_RULE_LENGTH] = "";
    struct vrmr_rule    *rule_ptr = NULL;
    struct vrmr_list_node         *d_node = NULL;

    /* safety */
    if(network_ptr == NULL)
    {
        (void)vrprint.error(-1, "Internal Error", "parameter problem (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    /* check if the zone is a network */
    if(network_ptr->type != TYPE_NETWORK)
    {
        (void)vrprint.error(-1, "Internal Error", "zone '%s' is not a network, but a '%d' (in: %s).", network_ptr->name, network_ptr->type, __FUNC__);
        return(-1);
    }

    /* get all rules from the backend */
    while((zf->ask(debuglvl, zone_backend, network_ptr->name, "RULE", currule, sizeof(currule), TYPE_NETWORK, 1)) == 1)
    {
        /* get mem */
        if(!(rule_ptr = vrmr_rule_malloc()))
            return(-1);

        /* copy name */
        if(strlcpy(rule_ptr->who, network_ptr->name, sizeof(rule_ptr->who)) >= sizeof(rule_ptr->who))
        {
            (void)vrprint.error(-1, "Internal Error", "buffer too small (in: %s:%d).", __FUNC__, __LINE__);
            free(rule_ptr);
            return(-1);
        }

        if(debuglvl >= HIGH)
            (void)vrprint.debug(__FUNC__, "currule: '%s'.", currule);

        if(vrmr_zones_network_rule_parse_line(debuglvl, currule, rule_ptr) < 0)
        {
            (void)vrprint.error(-1, "Internal Error", "parsing network rule failed (in: %s:%d).", __FUNC__, __LINE__);
            free(rule_ptr);
            return(-1);
        }

        /* append to list */
        if(vrmr_list_append(debuglvl, &network_ptr->ProtectList, rule_ptr) == NULL)
        {
            (void)vrprint.error(-1, "Internal Error", "appending protect rule to list failed (in: %s:%d).", __FUNC__, __LINE__);
            free(rule_ptr);
            return(-1);
        }
    }

    for(d_node = network_ptr->ProtectList.top; d_node; d_node = d_node->next)
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
         1: active
         0: inactive
        -1: error
*/
int
vrmr_zones_active(const int debuglvl, struct vrmr_zone *zone_ptr)
{
    /* safety first */
    if(zone_ptr == NULL)
    {
        (void)vrprint.error(-1, "Internal Error", "parameter problem (in: %s:%d).",
                __FUNC__, __LINE__);
        return(-1);
    }
    /* safety checks */
    if(zone_ptr->type == TYPE_HOST || zone_ptr->type == TYPE_GROUP)
    {
        if(zone_ptr->zone_parent == NULL || zone_ptr->network_parent == NULL)
        {
            (void)vrprint.error(-1, "Internal Error", "NULL pointer (in: %s:%d).",
                    __FUNC__, __LINE__);
            return(-1);
        }

        if(zone_ptr->zone_parent->active == FALSE || zone_ptr->network_parent->active == FALSE)
            return(0);
    }
    else if (zone_ptr->type == TYPE_NETWORK)
    {
        if(zone_ptr->zone_parent == NULL)
        {
            (void)vrprint.error(-1, "Internal Error", "NULL pointer (in: %s:%d).",
                    __FUNC__, __LINE__);
            return(-1);
        }

        if(zone_ptr->zone_parent->active == FALSE)
            return(0);
    }

    return(1);
}


/*
    returncodes:
         1: ok
         0: warning (set inactive)
        -1: error
*/
int
vrmr_zones_check_network(const int debuglvl, struct vrmr_zone *zone_ptr)
{
    int retval = 1,
        result = 0;

    /* safety first */
    if(zone_ptr == NULL)
    {
        (void)vrprint.error(-1, "Internal Error", "parameter problem (in: %s:%d).",
                __FUNC__, __LINE__);
        return(-1);
    }

    if(zone_ptr->InterfaceList.len == 0)
    {
        (void)vrprint.warning("Warning", "network '%s' has no interfaces attached to it.",
                zone_ptr->name);
        retval = 0;
    }

    if(zone_ptr->ipv4.network[0] == '\0')
    {
        (void)vrprint.warning("Warning", "network address for network '%s' is missing.",
                zone_ptr->name);
        retval = 0;
    }
    else
    {
        /* check the ip */
        result = vrmr_check_ipv4address(debuglvl,NULL, NULL, zone_ptr->ipv4.network, 1);
        if(result < 0)
        {
            (void)vrprint.warning("Warning", "network address '%s' of network '%s' is invalid.",
                    zone_ptr->ipv4.network,
                    zone_ptr->name);
            retval = 0;
        }
    }

    if(zone_ptr->ipv4.netmask[0] == '\0')
    {
        (void)vrprint.warning("Warning", "netmask for network '%s' is missing.",
                zone_ptr->name);
        retval = 0;
    }
    else
    {
        /* check the ip */
        result = vrmr_check_ipv4address(debuglvl,NULL, NULL, zone_ptr->ipv4.netmask, 1);
        if(result < 0)
        {
            (void)vrprint.warning("Warning", "netmask '%s' of network '%s' is invalid.",
                    zone_ptr->ipv4.netmask,
                    zone_ptr->name);
            retval = 0;
        }
    }

    /* only check if any of the previous checks didn't fail */
    if(retval == 1)
    {
        /* check the ip */
        result = vrmr_check_ipv4address(debuglvl,NULL, NULL, zone_ptr->ipv4.broadcast, 1);
        if(result < 0)
        {
            (void)vrprint.warning("Warning", "broadcast address '%s' of network '%s' is invalid.",
                    zone_ptr->ipv4.broadcast,
                    zone_ptr->name);
            retval = 0;
        }
    }

    result = vrmr_zones_active(debuglvl, zone_ptr);
    if(result != 1)
    {
        /* a parent is active */
        (void)vrprint.info("Info", "Network '%s' has an inactive parent. Network will be inactive.",
                zone_ptr->name);
        retval = 0;
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
vrmr_zones_check_host(const int debuglvl, struct vrmr_zone *zone_ptr)
{
    int retval = 1,
        result = 0;

    /* safety first */
    if(zone_ptr == NULL)
    {
        (void)vrprint.error(-1, "Internal Error", "parameter problem (in: %s:%d).",
                __FUNC__, __LINE__);
        return(-1);
    }

    /* check the ip */
    if(zone_ptr->ipv4.ipaddress[0] == '\0')
    {
        (void)vrprint.warning("Warning", "the host '%s' does not have an IPAddress.", zone_ptr->name);
        retval = 0;
    }
    else
    {
        result = vrmr_check_ipv4address(debuglvl,    zone_ptr->network_parent->ipv4.network,
                                                zone_ptr->network_parent->ipv4.netmask,
                                                zone_ptr->ipv4.ipaddress, 1);
        if(result < 0)
        {
            (void)vrprint.warning("Warning", "ipaddress '%s' of host '%s' is invalid.",
                    zone_ptr->ipv4.ipaddress,
                    zone_ptr->name);
            retval = 0;
        }
        else if(result == 0)
        {
            /* check ip told us that the ip didn't belong to the network */
            (void)vrprint.warning("Warning", "ipaddress '%s' of host '%s' does not belong to network '%s' with netmask '%s'.",
                    zone_ptr->ipv4.ipaddress,
                    zone_ptr->name,
                    zone_ptr->network_parent->ipv4.network,
                    zone_ptr->network_parent->ipv4.netmask);
            retval = 0;
        }
    }

    result = vrmr_zones_active(debuglvl, zone_ptr);
    if(result != 1)
    {
        /* a parent is active */
        (void)vrprint.info("Info", "Host '%s' has an inactive parent. Host will be inactive.",
                zone_ptr->name);
        retval = 0;
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
vrmr_zones_check_group(const int debuglvl, struct vrmr_zone *zone_ptr)
{
    int retval = 1,
        result = 0;

    /* safety first */
    if(zone_ptr == NULL)
    {
        (void)vrprint.error(-1, "Internal Error", "parameter problem (in: %s:%d).",
                __FUNC__, __LINE__);
        return(-1);
    }

    if(zone_ptr->GroupList.len == 0)
    {
        /* a parent is active */
        (void)vrprint.info("Info", "Group '%s' has no members. Group will be inactive.",
                zone_ptr->name);
        retval = 0;
    }

    result = vrmr_zones_active(debuglvl, zone_ptr);
    if(result != 1)
    {
        /* a parent is active */
        (void)vrprint.info("Info", "Group '%s' has an inactive parent. Group will be inactive.",
                zone_ptr->name);
        retval = 0;
    }

    return(retval);
}


/*  load_zones

    calls vrmr_init_zonedata and does some checking

    returncodes:
         0: ok
        -1: error
*/
int
vrmr_zones_load(const int debuglvl, struct vrmr_zones *zones, struct vrmr_interfaces *interfaces, struct vrmr_regex *reg)
{
    struct vrmr_zone    *zone_ptr = NULL;
    struct vrmr_list_node         *d_node = NULL;
    int                 result = 0;

    (void)vrprint.info("Info", "Loading zones...");

    /* load the interfaces into memory */
    result = vrmr_init_zonedata(debuglvl, zones, interfaces, reg);
    if(result == -1)
    {
        (void)vrprint.error(-1, "Error", "Loading zones failed.");
        return(-1);
    }

    /* loop through the zones */
    for(d_node = zones->list.top; d_node; d_node = d_node->next)
    {
        zone_ptr = d_node->data;
        if(zone_ptr == NULL)
        {
            (void)vrprint.error(-1, "Internal Error", "NULL pointer (in: %s:%d).",
                    __FUNC__, __LINE__);
            return(-1);
        }

        if(zone_ptr->type == TYPE_HOST)
        {
            result = vrmr_zones_check_host(debuglvl, zone_ptr);
            if(result == -1)
                return(-1);
            else if(result == 0)
            {
                (void)vrprint.info("Info", "Host '%s' has been deactivated because of previous warnings.",
                        zone_ptr->name);
                zone_ptr->active = FALSE;
            }
        }
        else if(zone_ptr->type == TYPE_GROUP)
        {
            result = vrmr_zones_check_group(debuglvl, zone_ptr);
            if(result == -1)
                return(-1);
            else if(result == 0)
            {
                (void)vrprint.info("Info", "Group '%s' has been deactivated because of previous warnings.",
                        zone_ptr->name);
                zone_ptr->active = FALSE;
            }
        }
        else if(zone_ptr->type == TYPE_NETWORK)
        {
            result = vrmr_zones_check_network(debuglvl, zone_ptr);
            if(result == -1)
                return(-1);
            else if(result == 0)
            {
                (void)vrprint.info("Info", "Network '%s' has been deactivated because of previous warnings.",
                        zone_ptr->name);
                zone_ptr->active = FALSE;
            }
        }

    }

    (void)vrprint.info("Info", "Loading zones succesfull.");
    return(0);
}


#ifdef IPV6_ENABLED
/** \brief See if a host is IPv6-enabled.
 *  \retval 1 yes
 *  \retval 0 no
 */
int
vrmr_zones_host_ipv6_enabled(const int debuglvl, struct vrmr_zone *host_ptr) {
    if (host_ptr != NULL && host_ptr->type == TYPE_HOST &&
            host_ptr->ipv6.cidr6 != -1)
    {
        return 1;
    }
    return 0;
}

/** \brief See if a network is IPv6-enabled.
 *  \retval 1 yes
 *  \retval 0 no
 */
int
vrmr_zones_network_ipv6_enabled(const int debuglvl, struct vrmr_zone *network_ptr) {
    if (network_ptr != NULL && network_ptr->type == TYPE_NETWORK &&
            network_ptr->ipv6.cidr6 != -1)
    {
        return 1;
    }
    return 0;
}
#endif

