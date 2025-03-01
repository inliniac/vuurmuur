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
static int zones_split_zonename(
        struct vrmr_zones *zones, struct vrmr_zone *zone_ptr, regex_t *reg_ex)
{
    int arg_count = 0;
    char check_str[VRMR_MAX_HOST_NET_ZONE] = "";
    char zonename[VRMR_MAX_ZONE] = "", netname[VRMR_MAX_NETWORK] = "",
         hostname[VRMR_MAX_HOST] = "";

    assert(zone_ptr && zones && reg_ex);

    vrmr_debug(LOW, "start: zone_ptr->name = '%s'", zone_ptr->name);

    /* validate and split up */
    if (vrmr_validate_zonename(zone_ptr->name, 0, zonename, netname, hostname,
                reg_ex, VRMR_VERBOSE) != 0) {
        vrmr_error(-1, "Internal Error", "name '%s' not valid", zone_ptr->name);
        return (-1);
    }

    arg_count = 2;

    if (hostname[0] == '\0')
        arg_count = 1;
    if (netname[0] == '\0')
        arg_count = 0;
    if (zonename[0] == '\0')
        return (-1);

    /* zone or firewall */
    if (arg_count == 0) {
        if (strlcpy(zone_ptr->zone_name, zonename,
                    sizeof(zone_ptr->zone_name)) >=
                sizeof(zone_ptr->zone_name)) {
            vrmr_error(-1, "Internal Error", "string overflow");
            return (-1);
        }
    }

    /* network */
    if (arg_count == 1) {
        if (strlcpy(zone_ptr->network_name, netname,
                    sizeof(zone_ptr->network_name)) >=
                sizeof(zone_ptr->network_name)) {
            vrmr_error(-1, "Internal Error", "string overflow");
            return (-1);
        }
        if (strlcpy(zone_ptr->zone_name, zonename,
                    sizeof(zone_ptr->zone_name)) >=
                sizeof(zone_ptr->zone_name)) {
            vrmr_error(-1, "Internal Error", "string overflow");
            return (-1);
        }

        zone_ptr->zone_parent =
                vrmr_search_zonedata(zones, zone_ptr->zone_name);
        if (zone_ptr->zone_parent == NULL) {
            vrmr_error(-1, "Error", "unable to find zone '%s'",
                    zone_ptr->zone_name);
            return (-1);
        }
    }

    /* host or group */
    if (arg_count == 2) {
        if (strlcpy(zone_ptr->host_name, hostname,
                    sizeof(zone_ptr->host_name)) >=
                sizeof(zone_ptr->host_name)) {
            vrmr_error(-1, "Internal Error", "string overflow");
            return (-1);
        }
        if (strlcpy(zone_ptr->network_name, netname,
                    sizeof(zone_ptr->network_name)) >=
                sizeof(zone_ptr->network_name)) {
            vrmr_error(-1, "Internal Error", "string overflow");
            return (-1);
        }
        if (strlcpy(zone_ptr->zone_name, zonename,
                    sizeof(zone_ptr->zone_name)) >=
                sizeof(zone_ptr->zone_name)) {
            vrmr_error(-1, "Internal Error", "string overflow");
            return (-1);
        }

        zone_ptr->zone_parent =
                vrmr_search_zonedata(zones, zone_ptr->zone_name);
        if (zone_ptr->zone_parent == NULL) {
            vrmr_error(-1, "Error", "unable to find zone '%s'",
                    zone_ptr->zone_name);
            return (-1);
        }

        snprintf(check_str, sizeof(check_str), "%s.%s", zone_ptr->network_name,
                zone_ptr->zone_name);

        zone_ptr->network_parent = vrmr_search_zonedata(zones, check_str);
        if (zone_ptr->network_parent == NULL) {
            vrmr_error(-1, "Error", "Unable to find network '%s'", check_str);
            return (-1);
        }
    }

    return (0);
}

/*  vrmr_insert_zonedata_list

    Inserts a zone into the list. It sorts by name. It makes sure the
   datastructure is preserved: zone dd network ee host    aa host    bb host zz
                group   cc
                group   xx
            network gg
        zone ee
            etc.

    Returncodes:
         0: ok
        -1: (serious) error
*/
int vrmr_insert_zonedata_list(
        struct vrmr_zones *zones, const struct vrmr_zone *zone_ptr)
{
    struct vrmr_zone *check_zone_ptr = NULL, *cur_zone = NULL,
                     *cur_network = NULL;
    int insert_here = 0, in_the_right_scope = 0;
    struct vrmr_list_node *d_node = NULL;

    assert(zones && zone_ptr);

    /* if the list is empty, just insert */
    if (zones->list.len == 0)
        insert_here = 1;
    else {
        /* loop trough the existing list to see where to insert */
        for (d_node = zones->list.top; d_node && !insert_here;
                d_node = d_node->next) {
            if (!(check_zone_ptr = d_node->data)) {
                vrmr_error(-1, "Internal Error", "NULL pointer");
                return (-1);
            }

            vrmr_debug(HIGH, "check_zone_ptr: name: %s, type: %d.",
                    check_zone_ptr->name, check_zone_ptr->type);

            /* store the last zone and network so we can determine the scope */
            if (check_zone_ptr->type == VRMR_TYPE_ZONE)
                cur_zone = check_zone_ptr;
            else if (check_zone_ptr->type == VRMR_TYPE_NETWORK)
                cur_network = check_zone_ptr;

            /* see if we are in the right scope: this means that a host is in
             * its 'own' network, a network in its 'own' zone, etc. */
            if ((zone_ptr->type == VRMR_TYPE_ZONE) ||
                    (zone_ptr->type == VRMR_TYPE_NETWORK && cur_zone &&
                            strcmp(cur_zone->zone_name, zone_ptr->zone_name) ==
                                    0) ||
                    (zone_ptr->type == VRMR_TYPE_HOST && cur_zone &&
                            strcmp(cur_zone->zone_name, zone_ptr->zone_name) ==
                                    0 &&
                            cur_network &&
                            strcmp(cur_network->network_name,
                                    zone_ptr->network_name) == 0) ||
                    (zone_ptr->type == VRMR_TYPE_GROUP && cur_zone &&
                            strcmp(cur_zone->zone_name, zone_ptr->zone_name) ==
                                    0 &&
                            cur_network &&
                            strcmp(cur_network->network_name,
                                    zone_ptr->network_name) == 0)) {
                vrmr_debug(HIGH, "in the right scope %s", zone_ptr->name);

                /* we are in the right scope */
                in_the_right_scope = 1;

                /* only compare with our own type */
                if (zone_ptr->type == check_zone_ptr->type) {
                    vrmr_debug(HIGH, "same type %s", zone_ptr->name);

                    /*  now compare the name.

                        if the name is the same (should never happen) or
                       'smaller', insert before the current item
                    */
                    if (strcmp(zone_ptr->name, check_zone_ptr->name) <= 0) {
                        vrmr_debug(HIGH, "insert here %s", zone_ptr->name);
                        insert_here = 1;
                        break;
                    }
                }
            }
            /*  if were not in the right scope anymore, we need to insert right
               now! This makes sure the data is inserted in our scope. We get
               here when for example inserting the first host in a network. It
               can never match the type comparison above.
            */
            else if (in_the_right_scope) {
                insert_here = 1;
                break;
            }
        }
    }

    /* is d_node is untouched (NULL) we prepend. */
    if (insert_here && !d_node) {
        /* prepend */
        vrmr_debug(HIGH, "prepend %s", zone_ptr->name);

        if (vrmr_list_prepend(&zones->list, zone_ptr) == NULL) {
            vrmr_error(-1, "Internal Error", "vrmr_list_prepend() failed");
            return (-1);
        }
    } else if (insert_here && d_node) {
        /* insert before */
        vrmr_debug(HIGH, "insert %s", zone_ptr->name);

        if (vrmr_list_insert_before(&zones->list, d_node, zone_ptr) == NULL) {
            vrmr_error(
                    -1, "Internal Error", "vrmr_list_insert_before() failed");
            return (-1);
        }
    } else {
        /* append */
        vrmr_debug(HIGH, "append %s", zone_ptr->name);

        if (vrmr_list_append(&zones->list, zone_ptr) == NULL) {
            vrmr_error(-1, "Internal Error", "vrmr_list_append() failed");
            return (-1);
        }
    }

    /* for debugging, print the entire list to the log */
    if (vrmr_debug_level >= HIGH) {
        for (d_node = zones->list.top; d_node; d_node = d_node->next) {
            if (!(check_zone_ptr = d_node->data)) {
                vrmr_error(-1, "Internal Error", "NULL pointer");
                return (-1);
            }
            vrmr_debug(HIGH, "list: check_zone_ptr: name: %s, type: %d.",
                    check_zone_ptr->name, check_zone_ptr->type);
        }
    }

    return (0);
}

/*  vrmr_insert_zonedata

    Inserts the zonedata 'name' into the linked-list.

    Returncodes:
        -1: error
         0: succes
*/
int vrmr_insert_zonedata(struct vrmr_ctx *vctx, struct vrmr_zones *zones,
        struct vrmr_interfaces *interfaces, const char *name, int type,
        struct vrmr_regex *reg)
{
    struct vrmr_zone *zone_ptr = NULL;

    assert(zones && name && reg && interfaces);

    /* claiming the memory we need, in case of error
       vrmr_zone_malloc will tell the user */
    if (!(zone_ptr = vrmr_zone_malloc()))
        return (-1);

    /* read the data for this zone */
    if (vrmr_read_zonedata(vctx, zones, interfaces, name, type, zone_ptr, reg) <
            0) {
        free(zone_ptr);
        return (-1);
    }

    if (vrmr_insert_zonedata_list(zones, zone_ptr) < 0) {
        vrmr_error(-1, "Internal Error", "vrmr_insert_zonedata_list() failed");
        return (-1);
    }

    zone_ptr->status = VRMR_ST_ADDED;
    return (0);
}

/*  vrmr_read_zonedata

    Reads all the info for a zone.

    Returncodes:
         0: ok
        -1: error
*/
int vrmr_read_zonedata(struct vrmr_ctx *vctx, struct vrmr_zones *zones,
        struct vrmr_interfaces *interfaces, const char *name, int type,
        struct vrmr_zone *zone_ptr, struct vrmr_regex *reg)
{
    assert(name && zone_ptr && zones && reg && interfaces);
    assert(type == VRMR_TYPE_ZONE || type == VRMR_TYPE_NETWORK ||
            type == VRMR_TYPE_HOST || type == VRMR_TYPE_GROUP);

    if (vrmr_validate_zonename(
                name, 1, NULL, NULL, NULL, reg->zonename, VRMR_VERBOSE) != 0) {
        vrmr_error(-1, "Internal Error", "invalid zonename '%s'", name);
        return (-1);
    }

    /* copy the name to the structure */
    if (strlcpy(zone_ptr->name, name, sizeof(zone_ptr->name)) >=
            sizeof(zone_ptr->name)) {
        vrmr_error(-1, "Internal Error", "buffer overflow");
        return (-1);
    }

    /* set the type */
    zone_ptr->type = type;

    /* split and check */
    int result = zones_split_zonename(zones, zone_ptr, reg->zonename);
    if (result < 0) {
        /* error */
        vrmr_error(-1, "Internal Error", "zones_split_zonename() failed");
        return (-1);
    }

    /* get the active */
    result = vrmr_check_active(vctx, zone_ptr->name, zone_ptr->type);
    if (result == -1) {
        /* set false to be sure */
        zone_ptr->active = FALSE;

        /* error */
        vrmr_error(-1, "Internal Error", "vrmr_check_active() failed");
        return (-1);
    } else if (result == 1)
        zone_ptr->active = TRUE;
    else
        zone_ptr->active = FALSE;

    if (zone_ptr->type != VRMR_TYPE_ZONE && zone_ptr->type != VRMR_TYPE_GROUP) {
        if (zone_ptr->type == VRMR_TYPE_NETWORK) {
            result = vrmr_zones_network_get_interfaces(
                    vctx, zone_ptr, interfaces);
            if (result < 0) {
                vrmr_error(-1, "Internal Error",
                        "vrmr_zones_network_get_interfaces() failed");
                return (-1);
            }

            result = vrmr_zones_network_get_protectrules(vctx, zone_ptr);
            if (result < 0) {
                vrmr_error(-1, "Internal Error",
                        "vrmr_zones_network_get_protectrules() failed");
                return (-1);
            }
        }

        /* get ip and mask */
        result = vrmr_get_ip_info(vctx, name, zone_ptr, reg);
        if (result != 0) {
            vrmr_error(-1, "Internal Error", "get_ip_info() failed");
            return (-1);
        }
    } else if (zone_ptr->type == VRMR_TYPE_GROUP) {
        /* get group info */
        result = vrmr_get_group_info(vctx, zones, name, zone_ptr);
        if (result != 0) {
            vrmr_error(-1, "Internal Error", "vrmr_get_group_info() failed");
            return (-1);
        }
    }

    return (0);
}

/*  vrmr_search_zonedata

    Function to search the ServicesList.

    It returns the pointer or a NULL-pointer if not found.
*/
void *vrmr_search_zonedata(const struct vrmr_zones *zones, const char *name)
{
    struct vrmr_list_node *d_node = NULL;
    struct vrmr_zone *zonedata_ptr = NULL;

    assert(name && zones);

    /* now search */
    for (d_node = zones->list.top; d_node; d_node = d_node->next) {
        if (!(zonedata_ptr = d_node->data)) {
            vrmr_error(-1, "Internal Error", "NULL pointer");
            return (NULL);
        }

        if (strcmp(zonedata_ptr->name, name) == 0) {
            vrmr_debug(HIGH, "zone '%s' found.", name);
            return (zonedata_ptr);
        }
    }

    vrmr_debug(LOW, "zone '%s' not found.", name);
    return (NULL);
}

/*- print_list - */
void vrmr_zonedata_print_list(const struct vrmr_zones *zones)
{
    struct vrmr_list_node *d_node = NULL;
    struct vrmr_zone *zone_ptr = NULL;

    // print size
    fprintf(stdout, "ZonedataList size: %u\n", zones->list.len);

    for (d_node = zones->list.top; d_node; d_node = d_node->next) {
        zone_ptr = d_node->data;

        fprintf(stdout, "zone: %s, status: %d, active: %d, type: %d\n",
                zone_ptr->name, zone_ptr->status, zone_ptr->active,
                zone_ptr->type);
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
int vrmr_init_zonedata(struct vrmr_ctx *vctx, struct vrmr_zones *zones,
        struct vrmr_interfaces *interfaces, struct vrmr_regex *reg)
{
    int zonetype = 0;
    char zonename[VRMR_MAX_HOST_NET_ZONE] = "";

    assert(zones && interfaces && reg);

    /* init */
    memset(zones, 0, sizeof(*zones));

    /* create the list */
    vrmr_list_setup(&zones->list, NULL);

    /* get the info from the backend */
    while (vctx->zf->list(vctx->zone_backend, zonename, &zonetype,
                   VRMR_BT_ZONES) != NULL) {
        vrmr_debug(MEDIUM, "loading zone: '%s', type: %d", zonename, zonetype);

        if (vrmr_validate_zonename(zonename, 1, NULL, NULL, NULL, reg->zonename,
                    VRMR_VERBOSE) == 0) {
            int result = vrmr_insert_zonedata(
                    vctx, zones, interfaces, zonename, zonetype, reg);
            if (result < 0) {
                vrmr_error(
                        -1, "Internal Error", "vrmr_insert_zonedata() failed");
                return (-1);
            } else {
                vrmr_debug(LOW, "loading zone succes: '%s' (type %d).",
                        zonename, zonetype);
            }
        }
    }
    return (0);
}

void vrmr_destroy_zonedatalist(struct vrmr_zones *zones)
{
    struct vrmr_list_node *d_node = NULL;
    struct vrmr_zone *zone_ptr = NULL;

    if (!zones)
        return;

    for (d_node = zones->list.top; d_node; d_node = d_node->next) {
        if (!(zone_ptr = d_node->data)) {
            vrmr_error(-1, "Internal Error", "NULL pointer");
            return;
        }

        vrmr_zone_free(zone_ptr);
    }

    vrmr_list_cleanup(&zones->list);
}

int vrmr_delete_zone(struct vrmr_ctx *vctx, struct vrmr_zones *zones,
        const char *zonename, int type)
{
    struct vrmr_zone *zone_ptr = NULL, *zone_list_ptr = NULL;
    struct vrmr_list_node *d_node = NULL;
    char name[VRMR_MAX_HOST_NET_ZONE] = "";
    struct vrmr_interface *iface_ptr = NULL;

    assert(zonename && zones);
    assert(type == VRMR_TYPE_ZONE || type == VRMR_TYPE_NETWORK ||
            type == VRMR_TYPE_HOST || type == VRMR_TYPE_GROUP);

    /* copy the name to an array so we can display the name after
       the deletion is complete */
    if (strlcpy(name, zonename, sizeof(name)) >= sizeof(name)) {
        vrmr_error(-1, "Internal Error", "string overflow");
        return (-1);
    }

    /* search the zone */
    if (!(zone_ptr = vrmr_search_zonedata(zones, zonename))) {
        vrmr_error(-1, "Internal Error", "zone '%s' not found", zonename);
        return (-1);
    }

    /* check the refernce counters */
    if (zone_ptr->type == VRMR_TYPE_HOST && zone_ptr->refcnt_group > 0) {
        vrmr_error(-1, "Internal Error",
                "host '%s' is still a member of %u group(s)", zone_ptr->name,
                zone_ptr->refcnt_group);
        return (-1);
    }
    if (zone_ptr->type == VRMR_TYPE_HOST && zone_ptr->refcnt_blocklist > 0) {
        vrmr_error(-1, "Internal Error",
                "host '%s' is still in the blocklist (%u times)",
                zone_ptr->name, zone_ptr->refcnt_blocklist);
        return (-1);
    }
    if (zone_ptr->type == VRMR_TYPE_GROUP && zone_ptr->refcnt_blocklist > 0) {
        vrmr_error(-1, "Internal Error",
                "group '%s' is still in the blocklist (%u times)",
                zone_ptr->name, zone_ptr->refcnt_blocklist);
        return (-1);
    }

    /* if the zone to delete is a group, decrease the refcnt_group of all
     * members */
    if (zone_ptr->type == VRMR_TYPE_GROUP) {
        for (d_node = zone_ptr->GroupList.top; d_node; d_node = d_node->next) {
            if (!(zone_list_ptr = d_node->data)) {
                vrmr_error(-1, "Internal Error", "NULL pointer");
                return (-1);
            }

            zone_list_ptr->refcnt_group--;
        }
    }
    /* or if we are a network, so the same for interfaces */
    else if (zone_ptr->type == VRMR_TYPE_NETWORK) {
        for (d_node = zone_ptr->InterfaceList.top; d_node;
                d_node = d_node->next) {
            if (!(iface_ptr = d_node->data)) {
                vrmr_error(-1, "Internal Error", "NULL pointer");
                return (-1);
            }

            iface_ptr->refcnt_network--;
        }
    }

    /* delete the zone from the backend */
    if (vctx->zf->del(vctx->zone_backend, zonename, type, 1) < 0) {
        vrmr_error(-1, "Internal Error", "zone '%s' could not be deleted",
                zonename);
        return (-1);
    }

    /* find its position in the list */
    for (d_node = zones->list.top; d_node; d_node = d_node->next) {
        if (!(zone_list_ptr = d_node->data)) {
            vrmr_error(-1, "Internal Error", "NULL pointer");
            return (-1);
        }

        if (strcmp(zonename, zone_list_ptr->name) == 0) {
            /* remove from list */
            if (vrmr_list_remove_node(&zones->list, d_node) < 0) {
                vrmr_error(-1, "Internal Error", "NULL pointer");
                return (-1);
            }

            /* remove from memory */
            vrmr_zone_free(zone_list_ptr);
            /* we're done */
            return (0);
        }
    }

    /* we should never get here */
    abort();
}

/*  vrmr_new_zone

    TODO: the spliting of name is totally wacked
*/
int vrmr_new_zone(struct vrmr_ctx *vctx, struct vrmr_zones *zones,
        char *zonename, int zonetype)
{
    struct vrmr_zone *zone_ptr = NULL;
    size_t dotcount = 0, i = 0, x = 0;
    char parent_str[VRMR_MAX_NET_ZONE] = "";

    assert(zonename && zones);

    for (i = 0, dotcount = 0; i < strlen(zonename); i++) {
        if (zonename[i] == '.')
            dotcount++;
    }
    if (dotcount > 2) {
        vrmr_error(-1, "Error", "Invalid name '%s'", zonename);
        return (-1);
    }

    /* allocated memory for the new zone */
    if (!(zone_ptr = vrmr_zone_malloc())) {
        vrmr_error(-1, "Error", "malloc failed");
        return (-1);
    }

    if (dotcount == 0) {
        strlcpy(zone_ptr->zone_name, zonename, sizeof(zone_ptr->zone_name));
    } else if (dotcount == 1) {
        // network
        for (i = 0; i < strlen(zonename); i++) {
            if (zonename[i] == '.')
                break;
            zone_ptr->network_name[i] = zonename[i];
        }
        zone_ptr->network_name[i] = '\0';

        for (i = strlen(zone_ptr->network_name) + 1, x = 0;
                i < strlen(zonename); i++, x++) {
            zone_ptr->zone_name[x] = zonename[i];
        }
        zone_ptr->zone_name[x] = '\0';
    } else {
        // host/group
        for (i = 0; i < strlen(zonename); i++) {
            if (zonename[i] == '.')
                break;
            zone_ptr->host_name[i] = zonename[i];
        }
        zone_ptr->host_name[i] = '\0';

        for (i = strlen(zone_ptr->host_name) + 1, x = 0; i < strlen(zonename);
                i++, x++) {
            if (zonename[i] == '.')
                break;
            zone_ptr->network_name[x] = zonename[i];
        }
        zone_ptr->network_name[x] = '\0';

        for (i = strlen(zone_ptr->host_name) + 1 +
                 strlen(zone_ptr->network_name) + 1,
            x = 0;
                i < strlen(zonename); i++, x++) {
            zone_ptr->zone_name[x] = zonename[i];
        }
        zone_ptr->zone_name[x] = '\0';
    }

    /* check if the zone already exists */
    if (vrmr_search_zonedata(zones, zonename) != NULL) {
        vrmr_error(-1, "Error", "zonename '%s' already exists", zonename);
        vrmr_zone_free(zone_ptr);
        return (-1);
    }

    /* set the bare minimum */
    strlcpy(zone_ptr->name, zonename, sizeof(zone_ptr->name));
    zone_ptr->type = zonetype;

    /* set the parent(s) */
    snprintf(parent_str, sizeof(parent_str), "%s.%s", zone_ptr->network_name,
            zone_ptr->zone_name);
    if (zone_ptr->type == VRMR_TYPE_HOST || zone_ptr->type == VRMR_TYPE_GROUP) {
        if (!(zone_ptr->network_parent =
                            vrmr_search_zonedata(zones, parent_str))) {
            vrmr_error(-1, "Internal Error",
                    "can't find the network-parent in the list");
            vrmr_zone_free(zone_ptr);
            return (-1);
        }
    }
    if (zone_ptr->type == VRMR_TYPE_HOST || zone_ptr->type == VRMR_TYPE_GROUP ||
            zone_ptr->type == VRMR_TYPE_NETWORK) {
        if (!(zone_ptr->zone_parent =
                            vrmr_search_zonedata(zones, zone_ptr->zone_name))) {
            vrmr_error(-1, "Internal Error",
                    "can't find the zone-parent in the list");
            vrmr_zone_free(zone_ptr);
            return (-1);
        }
    }

    /* insert into the list */
    if (vrmr_insert_zonedata_list(zones, zone_ptr) < 0) {
        vrmr_error(-1, "Internal Error",
                "unable to insert new zone into the list");
        vrmr_zone_free(zone_ptr);
        return (-1);
    }

    /* add the zone to the backend */
    if (vctx->zf->add(vctx->zone_backend, zonename, zonetype) < 0) {
        vrmr_error(-1, "Error", "Add to backend failed");
        return (-1);
    }

    /* set active */
    if (vctx->zf->tell(vctx->zone_backend, zonename, "ACTIVE",
                zone_ptr->active ? "Yes" : "No", 1, zonetype) < 0) {
        vrmr_error(-1, "Error", "Tell backend failed");
        return (-1);
    }

    vrmr_info("Info", "new zone '%s' succesfully added to the backend.",
            zonename);
    return (0);
}

/*
    TODO: input check
*/
int vrmr_count_zones(struct vrmr_zones *zones, int type, char *filter_network,
        char *filter_zone)
{
    struct vrmr_zone *zone_ptr = NULL;
    int count = 0;
    struct vrmr_list_node *d_node = NULL;

    assert(zones);
    assert(type == VRMR_TYPE_ZONE || type == VRMR_TYPE_NETWORK ||
            type == VRMR_TYPE_HOST || type == VRMR_TYPE_GROUP);

    for (d_node = zones->list.top; d_node; d_node = d_node->next) {
        if (!(zone_ptr = d_node->data)) {
            vrmr_error(-1, "Internal Error", "NULL pointer");
            return (-1);
        }

        if (zone_ptr->type != type)
            continue;

        if (filter_zone == NULL) {
            count++;
            continue;
        }

        if (strcmp(filter_zone, zone_ptr->zone_name) == 0) {
            if (filter_network == NULL) {
                count++;
                continue;
            }

            if (strcmp(filter_network, zone_ptr->network_name) == 0) {
                count++;
            }
        }
    }
    return (count);
}

/*  vrmr_zonelist_to_networklist

    Function to load the networks of a list into a new networklist. The
    networks in the original list will be untouched.

    Returncodes:
         0: ok
        -1: error

*/
int vrmr_zonelist_to_networklist(
        struct vrmr_zones *zones, struct vrmr_list *network_list)
{
    struct vrmr_list_node *d_node = NULL;
    struct vrmr_zone *zone_ptr = NULL;

    assert(zones && network_list);

    for (d_node = zones->list.top; d_node; d_node = d_node->next) {
        if (!(zone_ptr = d_node->data)) {
            vrmr_error(-1, "Internal Error", "NULL pointer");
            return (-1);
        }

        if (zone_ptr->type == VRMR_TYPE_NETWORK) {
            if (vrmr_list_append(network_list, zone_ptr) == NULL) {
                vrmr_error(
                        -1, "Internal Error", "appending to the list failed");
                return (-1);
            }
        }
    }

    return (0);
}

/*  vrmr_add_broadcasts_zonelist

    Adds the broadcast address of networks as VRMR_TYPE_FIREWALL's to the
   zone_list

    We ignore 255.255.255.255 because its a general broadcast, and i don't want
    it to show like internet.ext(broadcast).

    Returncodes:
         0: ok
        -1: error
*/
int vrmr_add_broadcasts_zonelist(struct vrmr_zones *zones)
{
    struct vrmr_zone *zone_ptr = NULL, *broadcast_ptr = NULL;
    struct vrmr_list_node *d_node = NULL;

    assert(zones);

    for (d_node = zones->list.top; d_node; d_node = d_node->next) {
        if (!(zone_ptr = d_node->data)) {
            vrmr_error(-1, "Internal Error", "NULL pointer");
            return (-1);
        }

        if (zone_ptr->type == VRMR_TYPE_NETWORK) {
            if (strcmp(zone_ptr->ipv4.broadcast, "255.255.255.255") != 0) {
                /* allocate memory */
                if (!(broadcast_ptr = vrmr_zone_malloc()))
                    return (-1);

                /*  store the bare minimum:
                        name
                        ipaddress
                        type
                */
                if (snprintf(broadcast_ptr->name, VRMR_MAX_HOST_NET_ZONE,
                            "%s(broadcast)",
                            zone_ptr->name) >= VRMR_MAX_HOST_NET_ZONE) {
                    vrmr_error(-1, "Internal Error", "string overflow");
                    vrmr_zone_free(broadcast_ptr);
                    return (-1);
                }

                if (strlcpy(broadcast_ptr->ipv4.ipaddress,
                            zone_ptr->ipv4.broadcast,
                            sizeof(broadcast_ptr->ipv4.ipaddress)) >=
                        sizeof(broadcast_ptr->ipv4.ipaddress)) {
                    vrmr_error(-1, "Internal Error", "string overflow");
                    vrmr_zone_free(broadcast_ptr);
                    return (-1);
                }

                broadcast_ptr->type = VRMR_TYPE_FIREWALL;

                vrmr_debug(MEDIUM, "%s addr: %s", broadcast_ptr->name,
                        broadcast_ptr->ipv4.ipaddress);

                /* insert into the list */
                if (vrmr_list_append(&zones->list, broadcast_ptr) == NULL) {
                    vrmr_error(-1, "Internal Error",
                            "appending to the list failed");
                    vrmr_zone_free(broadcast_ptr);
                    return (-1);
                }
            }
        }
    }
    return (0);
}

/*
   NOTE: THIS FUCNTION REQUIRES THE ZONE, NETWORK AND HOST VARIABLES TO BE OF
   THE SIZES: VRMR_MAX_ZONE, VRMR_MAX_NETWORK, VRMR_MAX_HOST!!! This is for
   bufferoverflow prevention.
*/
int vrmr_validate_zonename(const char *zonename, int onlyvalidate, char *zone,
        char *network, char *host, regex_t *reg_ex, char quiet)
{
    char name[VRMR_MAX_HOST_NET_ZONE];
    int retval = 0;
    /* this initalization pleases splint */
    regmatch_t reg_match[8] = {
            {0, 0}, {0, 0}, {0, 0}, {0, 0}, {0, 0}, {0, 0}, {0, 0}, {0, 0}};

    assert(zonename);

    vrmr_debug(MEDIUM, "checking: %s, onlyvalidate: %s.", zonename,
            onlyvalidate ? "Yes" : "No");

    strlcpy(name, zonename, sizeof(name));

    if (strstr(zonename, "(broadcast)") != NULL) {
        name[strlen(name) - 11] = '\0';
    }

    if (onlyvalidate == 1) {
        if (regexec(reg_ex, name, 0, NULL, 0) != 0) {
            if (quiet == VRMR_VERBOSE)
                vrmr_error(-1, "Error",
                        "zonename '%s' is invalid. A zonename can contain "
                        "normal letters and numbers and the underscore (_) and "
                        "minus (-) characters.",
                        zonename);

            vrmr_debug(MEDIUM, "'%s' is invalid.", zonename);
            return (-1);
        }
    }

    if (onlyvalidate == 0) {
        if (regexec(reg_ex, name, 8, reg_match, 0) != 0) {
            if (quiet == VRMR_VERBOSE)
                vrmr_error(-1, "Error",
                        "zonename '%s' is invalid. A zonename can contain "
                        "normal letters and numbers and the underscore (_) and "
                        "minus (-) characters.",
                        zonename);

            vrmr_debug(MEDIUM, "'%s' is invalid.", zonename);
            return (-1);
        }

        if (reg_match[7].rm_eo - reg_match[7].rm_so == 0) {
            host[0] = '\0';

            if (reg_match[4].rm_eo - reg_match[4].rm_so == 0) {
                network[0] = '\0';

                if (reg_match[1].rm_eo - reg_match[1].rm_so == 0) {
                    zone[0] = '\0';
                    retval = -1;
                } else {
                    (void)range_strcpy(zone, name, (size_t)reg_match[1].rm_so,
                            (size_t)reg_match[1].rm_eo, VRMR_MAX_ZONE);
                    vrmr_debug(HIGH, "zone: %s.", zone);
                }
            } else {
                (void)range_strcpy(network, name, (size_t)reg_match[1].rm_so,
                        (size_t)reg_match[1].rm_eo, VRMR_MAX_NETWORK);
                (void)range_strcpy(zone, name, (size_t)reg_match[4].rm_so,
                        (size_t)reg_match[4].rm_eo, VRMR_MAX_ZONE);
                vrmr_debug(HIGH, "zone: %s, network: %s.", zone, network);
            }
        } else {
            (void)range_strcpy(host, name, (size_t)reg_match[1].rm_so,
                    (size_t)reg_match[1].rm_eo, VRMR_MAX_HOST);
            (void)range_strcpy(network, name, (size_t)reg_match[4].rm_so,
                    (size_t)reg_match[4].rm_eo, VRMR_MAX_NETWORK);
            (void)range_strcpy(zone, name, (size_t)reg_match[7].rm_so,
                    (size_t)reg_match[7].rm_eo, VRMR_MAX_ZONE);
            vrmr_debug(HIGH, "zone: %s, network: %s, host: %s.", zone, network,
                    host);
        }
    } else {
        vrmr_debug(MEDIUM, "'%s' is valid.", zonename);
    }
    return (retval);
}

/*  vrmr_zones_group_save_members

    Save the group members to the backend.

    Returncodes:
         0: ok
        -1: error
*/
int vrmr_zones_group_save_members(
        struct vrmr_ctx *vctx, struct vrmr_zone *group_ptr)
{
    struct vrmr_list_node *d_node = NULL;
    struct vrmr_zone *member_ptr = NULL;

    assert(group_ptr);

    /* write to backend */
    if (group_ptr->GroupList.len == 0) {
        /* clear */
        if (vctx->zf->tell(vctx->zone_backend, group_ptr->name, "MEMBER", "", 1,
                    VRMR_TYPE_GROUP) < 0) {
            vrmr_error(-1, "Error", "saving to backend failed");
            return (-1);
        }
    } else {
        /* write to backend */
        for (d_node = group_ptr->GroupList.top; d_node; d_node = d_node->next) {
            if (!(member_ptr = d_node->data)) {
                vrmr_error(-1, "Internal Error", "NULL pointer");
                return (-1);
            }

            const int first = d_node == group_ptr->GroupList.top;
            /* save to backend */
            if (vctx->zf->tell(vctx->zone_backend, group_ptr->name, "MEMBER",
                        member_ptr->host_name, first, VRMR_TYPE_GROUP) < 0) {
                vrmr_error(-1, "Error", "saving to backend failed");
                return (-1);
            }
        }
    }

    return (0);
}

int vrmr_zones_group_rem_member(
        struct vrmr_ctx *vctx, struct vrmr_zone *group_ptr, char *hostname)
{
    struct vrmr_list_node *d_node = NULL;
    struct vrmr_zone *member_ptr = NULL;

    assert(group_ptr && hostname);
    assert(group_ptr->type == VRMR_TYPE_GROUP);

    for (d_node = group_ptr->GroupList.top; d_node; d_node = d_node->next) {
        if (!(member_ptr = d_node->data)) {
            vrmr_error(-1, "Internal Error", "NULL pointer");
            return (-1);
        }

        if (strcmp(hostname, member_ptr->host_name) == 0) {
            /* decrease refcnt */
            member_ptr->refcnt_group--;

            if (vrmr_list_remove_node(&group_ptr->GroupList, d_node) < 0) {
                vrmr_error(-1, "Internal Error",
                        "unable to remove member from the list");
                return (-1);
            } else
                break;
        }
    }

    /* save the new group list */
    if (vrmr_zones_group_save_members(vctx, group_ptr) < 0) {
        vrmr_error(
                -1, "Error", "saveing the new grouplist to the backend failed");
        return (-1);
    }

    /* for logging */
    vrmr_info("Info",
            "group '%s' has been changed: the member '%s' has been removed.",
            group_ptr->name, hostname);
    return (0);
}

int vrmr_zones_group_add_member(struct vrmr_ctx *vctx, struct vrmr_zones *zones,
        struct vrmr_zone *group_ptr, char *hostname)
{
    struct vrmr_zone *list_member_ptr = NULL;
    struct vrmr_list_node *d_node = NULL;

    assert(group_ptr && zones && hostname);

    struct vrmr_zone *new_member_ptr = vrmr_search_zonedata(zones, hostname);
    if (!new_member_ptr) {
        vrmr_error(-1, "Internal Error",
                "member '%s' is invalid, it was not found in memory", hostname);
        return (-1);
    }

    /* check if our member is a host */
    if (new_member_ptr->type != VRMR_TYPE_HOST) {
        vrmr_error(
                -1, "Internal Error", "member '%s' is not a host!", hostname);
        return (-1);
    }

    /* let's see if the host is already a member */
    for (d_node = group_ptr->GroupList.top; d_node; d_node = d_node->next) {
        if (!(list_member_ptr = d_node->data)) {
            vrmr_error(-1, "Internal Error", "NULL pointer");
            return (-1);
        }

        if (strcmp(list_member_ptr->name, hostname) == 0) {
            vrmr_error(-1, "Error",
                    "host '%s' is already a member of group '%s'", hostname,
                    group_ptr->name);
            return (-1);
        }
    }

    /* increase refcnt */
    new_member_ptr->refcnt_group++;

    /* now append the new at the tail of the list */
    if (vrmr_list_append(&group_ptr->GroupList, new_member_ptr) == NULL) {
        vrmr_error(
                -1, "Internal Error", "unable to append member to groupslist");
        return (-1);
    }

    /* save the new group list */
    if (vrmr_zones_group_save_members(vctx, group_ptr) < 0) {
        vrmr_error(
                -1, "Error", "saveing the new grouplist to the backend failed");
        return (-1);
    }

    vrmr_info("Info",
            "group '%s' has been changed: the member '%s' has been added.",
            group_ptr->name, hostname);
    return (0);
}

/*  adds an interface to a network

    returncodes:
        -1: error
         0: ok
*/
int vrmr_zones_network_add_iface(struct vrmr_interfaces *interfaces,
        struct vrmr_zone *network_ptr, char *interfacename)
{
    struct vrmr_interface *iface_ptr = NULL, *list_iface_ptr = NULL;
    struct vrmr_list_node *d_node = NULL;

    assert(interfaces && network_ptr && interfacename);

    /* let's see if the interface is already in the list */
    for (d_node = network_ptr->InterfaceList.top; d_node;
            d_node = d_node->next) {
        if (!(list_iface_ptr = d_node->data)) {
            vrmr_error(-1, "Internal Error", "NULL pointer");
            return (-1);
        }

        if (strcmp(list_iface_ptr->name, interfacename) == 0) {
            vrmr_warning("Warning",
                    "interface '%s' is already attached to network '%s'.",
                    interfacename, network_ptr->name);
            return (0); /* non-fatal */
        }
    }

    /* search the interface in the interface list */
    if (!(iface_ptr = vrmr_search_interface(interfaces, interfacename))) {
        vrmr_warning("Warning",
                "the interface '%s' of network '%s' was not found in memory.",
                interfacename, network_ptr->name);
        return (0); /* non-fatal */
    }

    /* append to the list */
    if (!(vrmr_list_append(&network_ptr->InterfaceList, iface_ptr))) {
        vrmr_error(-1, "Internal Error", "appending to the list failed");
        return (-1);
    }

    if (iface_ptr->active == TRUE) {
        /* count the active interfaces */
        network_ptr->active_interfaces++;
    }

    /* increase the reference counter of the interface */
    iface_ptr->refcnt_network++;
    return (0);
}

int vrmr_zones_network_rem_iface(struct vrmr_ctx *vctx,
        struct vrmr_zone *network_ptr, char *interfacename)
{
    struct vrmr_list_node *d_node = NULL;
    struct vrmr_interface *iface_ptr = NULL;

    assert(interfacename && network_ptr);
    assert(network_ptr->type == VRMR_TYPE_NETWORK);

    for (d_node = network_ptr->InterfaceList.top; d_node;
            d_node = d_node->next) {
        if (!(iface_ptr = d_node->data)) {
            vrmr_error(-1, "Internal Error", "NULL pointer");
            return (-1);
        }

        /* check if this is the one */
        if (strcmp(interfacename, iface_ptr->name) == 0) {
            if (vrmr_list_remove_node(&network_ptr->InterfaceList, d_node) <
                    0) {
                vrmr_error(-1, "Internal Error",
                        "unable to remove interface from the list");
                return (-1);
            }

            iface_ptr->refcnt_network--;
            break;
        }
    }

    /* save the new interface list */
    if (vrmr_zones_network_save_interfaces(vctx, network_ptr) < 0) {
        vrmr_error(-1, "Error",
                "saving the new interfaceslist to the backend failed");
        return (-1);
    }

    return (0);
}

/*  vrmr_zones_network_get_interfaces

    Returncodes:
         0: ok
        -1: error
 */
int vrmr_zones_network_get_interfaces(struct vrmr_ctx *vctx,
        struct vrmr_zone *zone_ptr, struct vrmr_interfaces *interfaces)
{
    char cur_ifac[VRMR_MAX_INTERFACE] = "";

    assert(zone_ptr && interfaces);
    assert(zone_ptr->type == VRMR_TYPE_NETWORK);

    /* reset active interfaces */
    zone_ptr->active_interfaces = 0;

    /* get all interfaces from the backend */
    while ((vctx->zf->ask(vctx->zone_backend, zone_ptr->name, "INTERFACE",
                   cur_ifac, sizeof(cur_ifac), VRMR_TYPE_NETWORK, 1)) == 1) {
        if (vrmr_zones_network_add_iface(interfaces, zone_ptr, cur_ifac) < 0) {
            vrmr_error(-1, "Internal Error",
                    "vrmr_zones_network_add_iface() failed");
            return (-1);
        }
    }

    vrmr_debug(HIGH, "active_interfaces: %d.", zone_ptr->active_interfaces);
    return (0);
}

int vrmr_zones_network_save_interfaces(
        struct vrmr_ctx *vctx, struct vrmr_zone *network_ptr)
{
    struct vrmr_list_node *d_node = NULL;
    struct vrmr_interface *iface_ptr = NULL;

    assert(network_ptr);
    assert(network_ptr->type == VRMR_TYPE_NETWORK);

    vrmr_debug(HIGH, "network: %s, interfaces: %u", network_ptr->name,
            network_ptr->InterfaceList.len);

    /* write the new list to the backend */
    if (network_ptr->InterfaceList.len == 0) {
        /* clear by writing "" in overwrite mode */
        if (vctx->zf->tell(vctx->zone_backend, network_ptr->name, "INTERFACE",
                    "", 1, VRMR_TYPE_NETWORK) < 0) {
            vrmr_error(-1, "Error", "writing to backend failed");
            return (-1);
        }
    } else {
        /*
            save the new interfaces list to the backend
        */
        for (d_node = network_ptr->InterfaceList.top; d_node;
                d_node = d_node->next) {
            if (!(iface_ptr = d_node->data)) {
                vrmr_error(-1, "Internal Error", "NULL pointer");
                return (-1);
            }

            const int first = d_node == network_ptr->InterfaceList.top;
            if (vctx->zf->tell(vctx->zone_backend, network_ptr->name,
                        "INTERFACE", iface_ptr->name, first,
                        VRMR_TYPE_NETWORK) < 0) {
                vrmr_error(-1, "Error", "writing to backend failed");
                return (-1);
            }
        }
    }

    return (0);
}

/*  Function for gathering the info for creation of the rule
    and for sanity checking the rule.

    Returncodes:
         0: ok
        -1: error
 */
int vrmr_zones_network_analyze_rule(struct vrmr_rule *rule_ptr,
        struct vrmr_rule_cache *create, struct vrmr_zones *zones,
        struct vrmr_config *cnf)
{
    int result = 0;

    assert(rule_ptr && create && zones);

    /* if were on bash mode, alloc mem for the description */
    if (cnf->bash_out == TRUE) {
        if (!(create->description = malloc(VRMR_MAX_BASH_DESC))) {
            vrmr_error(-1, "Error", "malloc failed: %s", strerror(errno));
            return (-1);
        }
    } else {
        create->description = NULL;
    }

    /* first the protect rule */
    if (rule_ptr->action == VRMR_AT_PROTECT) {
        vrmr_debug(LOW, "action: %s, who: %s, danger: %s, source: %s",
                vrmr_rules_itoaction(rule_ptr->action), rule_ptr->who,
                rule_ptr->danger, rule_ptr->source);

        /* description */
        if (cnf->bash_out && create->description != NULL) {
            snprintf(create->description, VRMR_MAX_BASH_DESC,
                    "rule: action: %s, who: %s, danger: %s, source: %s",
                    vrmr_rules_itoaction(rule_ptr->action), rule_ptr->who,
                    rule_ptr->danger, rule_ptr->source);
        }

        /* get who */
        if (strcmp(rule_ptr->who, "") != 0) {
            if (rule_ptr->type == VRMR_PROT_IPTABLES) {
                create->who_int = NULL;

                if (!(create->who = vrmr_search_zonedata(
                              zones, rule_ptr->who))) {
                    vrmr_error(
                            -1, "Error", "zone '%s' not found", rule_ptr->who);
                    return (-1);
                }
            } else {
                create->who = NULL;
                vrmr_error(-1, "Error",
                        "don't know what to do with '%s' for rule type '%d'",
                        rule_ptr->who, rule_ptr->type);
                return (-1);
            }
        }

        vrmr_debug(MEDIUM, "calling vrmr_get_danger_info() for danger...");

        result = vrmr_get_danger_info(
                rule_ptr->danger, rule_ptr->source, &create->danger);
        if (result == 0) {
            vrmr_debug(HIGH, "vrmr_get_danger_info successfull.");
        } else {
            vrmr_error(-1, "Error", "getting danger '%s' failed",
                    rule_ptr->danger);
            return (-1);
        }

        /* set the action */
        if (strlcpy(create->action, "protect", sizeof(create->action)) >
                sizeof(create->action)) {
            vrmr_error(-1, "Error", "buffer overflow");
            return (-1);
        }
    }
    /* network accept rule */
    else if (rule_ptr->type == VRMR_PROT_IPTABLES &&
             rule_ptr->action == VRMR_AT_ACCEPT) {
        create->danger.solution = VRMR_PROT_IPTABLES;

        /* description */
        if (cnf->bash_out && create->description != NULL) {
            snprintf(create->description, VRMR_MAX_BASH_DESC,
                    "rule: action: %s, service: %s",
                    vrmr_rules_itoaction(rule_ptr->action), rule_ptr->service);
        }

        /* get who */
        if (strcmp(rule_ptr->who, "") != 0) {
            create->who_int = NULL;

            if (!(create->who = vrmr_search_zonedata(zones, rule_ptr->who))) {
                vrmr_error(-1, "Error", "zone '%s' not found", rule_ptr->who);
                return (-1);
            }
        }

        if (strcasecmp(rule_ptr->service, "dhcp-client") == 0 ||
                strcasecmp(rule_ptr->service, "dhcp-server") == 0) {
            /* not much here */
            vrmr_debug(MEDIUM, "network rule service '%s'", rule_ptr->service);
        } else {
            vrmr_error(-1, "Error", "unknown service '%s' in network rule",
                    rule_ptr->service);
            return (-1);
        }
    }

    return (0);
}

/*  vrmr_rules_parse_line

    Returncodes:
        0: ok
        -1: error
*/
int vrmr_zones_network_rule_parse_line(
        const char *line, struct vrmr_rule *rule_ptr)
{
    size_t line_pos = 0, // position in line
            var_pos = 0; // position in varible
    char against_keyw[32] = "";
    char action_str[32] = "";

    assert(line && rule_ptr);
    assert(strlen(line) <= VRMR_MAX_RULE_LENGTH);

    /* get the action */
    for (; line_pos < sizeof(action_str) - 1 && line[line_pos] != ' ' &&
            line[line_pos] != '\0' && line[line_pos] != '\n';
            line_pos++, var_pos++) {
        action_str[var_pos] = line[line_pos];
    }
    action_str[var_pos] = '\0';

    rule_ptr->action = vrmr_rules_actiontoi(action_str);
    if (rule_ptr->action <= VRMR_AT_ERROR ||
            rule_ptr->action >= VRMR_AT_TOO_BIG)
        return (-1);

    /* now we analyze the action */
    if (rule_ptr->action == VRMR_AT_PROTECT) {
        /* get the 'against' */
        for (line_pos++, var_pos = 0;
                var_pos < sizeof(against_keyw) - 1 && line[line_pos] != ' ' &&
                line[line_pos] != '\0' && line[line_pos] != '\n';
                line_pos++, var_pos++) {
            against_keyw[var_pos] = line[line_pos];
        }
        against_keyw[var_pos] = '\0';

        /* check for the against keyword */
        if (strcasecmp(against_keyw, "against") != 0) {
            vrmr_error(-1, "Error", "expected keyword 'against', got '%s'",
                    against_keyw);
            return (-1);
        }

        /* okay, now lets see what kind of danger we are talking about */
        for (line_pos++, var_pos = 0;
                var_pos < sizeof(rule_ptr->danger) - 1 &&
                line[line_pos] != ' ' && line[line_pos] != '\0' &&
                line[line_pos] != '\n';
                line_pos++, var_pos++) {
            rule_ptr->danger[var_pos] = line[line_pos];
        }
        rule_ptr->danger[var_pos] = '\0';

        vrmr_debug(HIGH, "protect: danger: '%s'", rule_ptr->danger);

        /* now determine if the danger is 'spoofing' */
        if (strcasecmp(rule_ptr->danger, "spoofing") != 0) {
            vrmr_error(-1, "Error", "expected danger 'spoofing', got '%s'",
                    rule_ptr->danger);
            return (-1);
        }

        /* get the 'from' */
        for (line_pos++, var_pos = 0;
                var_pos < strlen("from") && line[line_pos] != ' ' &&
                line[line_pos] != '\0' && line[line_pos] != '\n';
                line_pos++, var_pos++) {
            rule_ptr->source[var_pos] = line[line_pos];
        }
        rule_ptr->source[var_pos] = '\0';

        vrmr_debug(HIGH, "protect: keyword from: '%s'", rule_ptr->source);

        /* if 'from' is missing, the rule is malformed, so we bail out screaming
         * & kicking */
        if (strcasecmp(rule_ptr->source, "from") != 0) {
            vrmr_error(-1, "Error",
                    "bad rule syntax, keyword 'from' is missing: %s", line);
            return (-1);
        }

        /* get the source */
        for (line_pos++, var_pos = 0;
                var_pos < sizeof(rule_ptr->source) - 1 &&
                line[line_pos] != ' ' && line[line_pos] != '\0' &&
                line[line_pos] != '\n';
                line_pos++, var_pos++) {
            rule_ptr->source[var_pos] = line[line_pos];
        }
        rule_ptr->source[var_pos] = '\0';

        vrmr_debug(HIGH, "protect: source: '%s'", rule_ptr->source);

        /* set the ruletype */
        rule_ptr->type = VRMR_PROT_IPTABLES;
    }
    /* accept target */
    else if (rule_ptr->action == VRMR_AT_ACCEPT) {
        vrmr_debug(
                MEDIUM, "action: '%s'", vrmr_rules_itoaction(rule_ptr->action));

        for (line_pos++, var_pos = 0;
                var_pos < sizeof(rule_ptr->service) - 1 &&
                line[line_pos] != ' ' && line[line_pos] != ',' &&
                line[line_pos] != '\0' && line[line_pos] != '\n';
                line_pos++, var_pos++) {
            rule_ptr->service[var_pos] = line[line_pos];
        }
        rule_ptr->service[var_pos] = '\0';

        vrmr_debug(MEDIUM, "service: '%s'", rule_ptr->service);

        // TODO options

        rule_ptr->type = VRMR_PROT_IPTABLES;
    }

    return (0);
}

int vrmr_zones_network_get_protectrules(
        struct vrmr_ctx *vctx, struct vrmr_zone *network_ptr)
{
    char currule[VRMR_MAX_RULE_LENGTH] = "";
    struct vrmr_rule *rule_ptr = NULL;
    struct vrmr_list_node *d_node = NULL;

    assert(network_ptr);
    assert(network_ptr->type == VRMR_TYPE_NETWORK);

    /* get all rules from the backend */
    while ((vctx->zf->ask(vctx->zone_backend, network_ptr->name, "RULE",
                   currule, sizeof(currule), VRMR_TYPE_NETWORK, 1)) == 1) {
        /* get mem */
        if (!(rule_ptr = vrmr_rule_malloc()))
            return (-1);

        /* copy name */
        if (strlcpy(rule_ptr->who, network_ptr->name, sizeof(rule_ptr->who)) >=
                sizeof(rule_ptr->who)) {
            vrmr_error(-1, "Internal Error", "buffer too small");
            free(rule_ptr);
            return (-1);
        }
        vrmr_debug(HIGH, "currule: '%s'.", currule);

        if (vrmr_zones_network_rule_parse_line(currule, rule_ptr) < 0) {
            vrmr_error(-1, "Internal Error", "parsing network rule failed");
            free(rule_ptr);
            return (-1);
        }

        /* append to list */
        if (vrmr_list_append(&network_ptr->ProtectList, rule_ptr) == NULL) {
            vrmr_error(-1, "Internal Error",
                    "appending protect rule to list failed");
            free(rule_ptr);
            return (-1);
        }
    }

    for (d_node = network_ptr->ProtectList.top; d_node; d_node = d_node->next) {
        if (!(rule_ptr = d_node->data)) {
            return (-1);
        }

        vrmr_debug(HIGH, "a: %s, w: %s, d: %s, s: %s.",
                vrmr_rules_itoaction(rule_ptr->action), rule_ptr->who,
                rule_ptr->danger, rule_ptr->source);
    }

    return (0);
}

/*
    returncodes:
         1: active
         0: inactive
        -1: error
*/
int vrmr_zones_active(struct vrmr_zone *zone_ptr)
{
    assert(zone_ptr);

    /* safety checks */
    if (zone_ptr->type == VRMR_TYPE_HOST || zone_ptr->type == VRMR_TYPE_GROUP) {
        if (zone_ptr->zone_parent == NULL || zone_ptr->network_parent == NULL) {
            vrmr_error(-1, "Internal Error", "NULL pointer");
            return (-1);
        }

        if (zone_ptr->zone_parent->active == FALSE ||
                zone_ptr->network_parent->active == FALSE)
            return (0);
    } else if (zone_ptr->type == VRMR_TYPE_NETWORK) {
        if (zone_ptr->zone_parent == NULL) {
            vrmr_error(-1, "Internal Error", "NULL pointer");
            return (-1);
        }

        if (zone_ptr->zone_parent->active == FALSE)
            return (0);
    }

    return (1);
}

/*
    returncodes:
         1: ok
         0: warning (set inactive)
        -1: error
*/
int vrmr_zones_check_network(struct vrmr_zone *zone_ptr)
{
    int retval = 1, result = 0;

    assert(zone_ptr);

    if (zone_ptr->InterfaceList.len == 0) {
        vrmr_warning("Warning",
                "network '%s' has no interfaces attached to it.",
                zone_ptr->name);
        retval = 0;
    }

    if (zone_ptr->ipv4.network[0] == '\0') {
        vrmr_warning("Warning", "network address for network '%s' is missing.",
                zone_ptr->name);
        retval = 0;
    } else {
        /* check the ip */
        result = vrmr_check_ipv4address(NULL, NULL, zone_ptr->ipv4.network, 1);
        if (result < 0) {
            vrmr_warning("Warning",
                    "network address '%s' of network '%s' is invalid.",
                    zone_ptr->ipv4.network, zone_ptr->name);
            retval = 0;
        }
    }

    if (zone_ptr->ipv4.netmask[0] == '\0') {
        vrmr_warning("Warning", "netmask for network '%s' is missing.",
                zone_ptr->name);
        retval = 0;
    } else {
        /* check the ip */
        result = vrmr_check_ipv4address(NULL, NULL, zone_ptr->ipv4.netmask, 1);
        if (result < 0) {
            vrmr_warning("Warning", "netmask '%s' of network '%s' is invalid.",
                    zone_ptr->ipv4.netmask, zone_ptr->name);
            retval = 0;
        }
    }

    /* only check if any of the previous checks didn't fail */
    if (retval == 1) {
        /* check the ip */
        result =
                vrmr_check_ipv4address(NULL, NULL, zone_ptr->ipv4.broadcast, 1);
        if (result < 0) {
            vrmr_warning("Warning",
                    "broadcast address '%s' of network '%s' is invalid.",
                    zone_ptr->ipv4.broadcast, zone_ptr->name);
            retval = 0;
        }
    }

    result = vrmr_zones_active(zone_ptr);
    if (result != 1) {
        /* a parent is active */
        vrmr_info("Info",
                "Network '%s' has an inactive parent. Network will be "
                "inactive.",
                zone_ptr->name);
        retval = 0;
    }

    return (retval);
}

/*
    returncodes:
         1: ok
         0: warning (set inactive)
        -1: error
*/
int vrmr_zones_check_host(struct vrmr_zone *zone_ptr)
{
    int retval = 1, result = 0;

    assert(zone_ptr);

    /* check the ip */
    if (zone_ptr->ipv4.ipaddress[0] == '\0') {
        vrmr_warning("Warning", "the host '%s' does not have an IPAddress.",
                zone_ptr->name);
        retval = 0;
    } else {
        result = vrmr_check_ipv4address(zone_ptr->network_parent->ipv4.network,
                zone_ptr->network_parent->ipv4.netmask,
                zone_ptr->ipv4.ipaddress, 1);
        if (result < 0) {
            vrmr_warning("Warning", "ipaddress '%s' of host '%s' is invalid.",
                    zone_ptr->ipv4.ipaddress, zone_ptr->name);
            retval = 0;
        } else if (result == 0) {
            /* check ip told us that the ip didn't belong to the network */
            vrmr_warning("Warning",
                    "ipaddress '%s' of host '%s' does not belong to network "
                    "'%s' with netmask '%s'.",
                    zone_ptr->ipv4.ipaddress, zone_ptr->name,
                    zone_ptr->network_parent->ipv4.network,
                    zone_ptr->network_parent->ipv4.netmask);
            retval = 0;
        }
    }

    result = vrmr_zones_active(zone_ptr);
    if (result != 1) {
        /* a parent is active */
        vrmr_info("Info",
                "Host '%s' has an inactive parent. Host will be inactive.",
                zone_ptr->name);
        retval = 0;
    }

    return (retval);
}

/*
    returncodes:
         1: ok
         0: warning (set inactive)
        -1: error
*/
int vrmr_zones_check_group(struct vrmr_zone *zone_ptr)
{
    int retval = 1;

    assert(zone_ptr);

    if (zone_ptr->GroupList.len == 0) {
        /* a parent is active */
        vrmr_info("Info", "Group '%s' has no members. Group will be inactive.",
                zone_ptr->name);
        retval = 0;
    }

    int result = vrmr_zones_active(zone_ptr);
    if (result != 1) {
        /* a parent is active */
        vrmr_info("Info",
                "Group '%s' has an inactive parent. Group will be inactive.",
                zone_ptr->name);
        retval = 0;
    }

    return (retval);
}

/*  load_zones

    calls vrmr_init_zonedata and does some checking

    returncodes:
         0: ok
        -1: error
*/
int vrmr_zones_load(struct vrmr_ctx *vctx, struct vrmr_zones *zones,
        struct vrmr_interfaces *interfaces, struct vrmr_regex *reg)
{
    struct vrmr_zone *zone_ptr = NULL;
    struct vrmr_list_node *d_node = NULL;
    int result = 0;

    vrmr_info("Info", "Loading zones...");

    /* load the interfaces into memory */
    result = vrmr_init_zonedata(vctx, zones, interfaces, reg);
    if (result == -1) {
        vrmr_error(-1, "Error", "Loading zones failed");
        return (-1);
    }

    /* loop through the zones */
    for (d_node = zones->list.top; d_node; d_node = d_node->next) {
        zone_ptr = d_node->data;
        if (zone_ptr == NULL) {
            vrmr_error(-1, "Internal Error", "NULL pointer");
            return (-1);
        }

        if (zone_ptr->type == VRMR_TYPE_HOST) {
            result = vrmr_zones_check_host(zone_ptr);
            if (result == -1)
                return (-1);
            else if (result == 0) {
                vrmr_info("Info",
                        "Host '%s' has been deactivated because of previous "
                        "warnings.",
                        zone_ptr->name);
                zone_ptr->active = FALSE;
            }
        } else if (zone_ptr->type == VRMR_TYPE_GROUP) {
            result = vrmr_zones_check_group(zone_ptr);
            if (result == -1)
                return (-1);
            else if (result == 0) {
                vrmr_info("Info",
                        "Group '%s' has been deactivated because of previous "
                        "warnings.",
                        zone_ptr->name);
                zone_ptr->active = FALSE;
            }
        } else if (zone_ptr->type == VRMR_TYPE_NETWORK) {
            result = vrmr_zones_check_network(zone_ptr);
            if (result == -1)
                return (-1);
            else if (result == 0) {
                vrmr_info("Info",
                        "Network '%s' has been deactivated because of previous "
                        "warnings.",
                        zone_ptr->name);
                zone_ptr->active = FALSE;
            }
        }
    }

    vrmr_info("Info", "Loading zones succesfull.");
    return (0);
}

/** \brief See if a host is IPv6-enabled.
 *  \retval 1 yes
 *  \retval 0 no
 */
int vrmr_zones_host_ipv6_enabled(struct vrmr_zone *host_ptr)
{
    if (host_ptr != NULL && host_ptr->type == VRMR_TYPE_HOST &&
            host_ptr->ipv6.cidr6 != -1) {
        return 1;
    }
    return 0;
}

/** \brief See if a network is IPv6-enabled.
 *  \retval 1 yes
 *  \retval 0 no
 */
int vrmr_zones_network_ipv6_enabled(struct vrmr_zone *network_ptr)
{
    if (network_ptr != NULL && network_ptr->type == VRMR_TYPE_NETWORK &&
            network_ptr->ipv6.cidr6 != -1) {
        return 1;
    }
    return 0;
}
