/***************************************************************************
 *   Copyright (C) 2002-2019 by Victor Julien                              *
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

static int vrmr_insert_interface_list(struct vrmr_interfaces *interfaces,
        const struct vrmr_interface *iface_ptr)
{
    struct vrmr_interface *check_iface_ptr = NULL;
    int result = 0;
    int insert_here = 0;
    struct vrmr_list_node *d_node = NULL;

    assert(interfaces && iface_ptr);

    if (interfaces->list.len == 0) {
        insert_here = 1;
    } else {
        for (d_node = interfaces->list.top; d_node && insert_here == 0;
                d_node = d_node->next) {
            check_iface_ptr = d_node->data;
            if (check_iface_ptr == NULL)
                continue;

            vrmr_debug(HIGH,
                    "iface_ptr->name: %s, "
                    "check_iface_ptr->name: %s",
                    iface_ptr->name, check_iface_ptr->name);

            result = strcmp(iface_ptr->name, check_iface_ptr->name);
            if (result <= 0) {
                vrmr_debug(HIGH, "insert here.");

                insert_here = 1;
                break;
            }
        }
    }

    if (insert_here == 1 && d_node == NULL) {
        vrmr_debug(HIGH, "prepend %s", iface_ptr->name);

        /* prepend if an empty list */
        if (!(vrmr_list_prepend(&interfaces->list, iface_ptr))) {
            vrmr_error(-1, "Internal Error", "vrmr_list_prepend() failed");
            return (-1);
        }
    } else if (insert_here == 1 && d_node != NULL) {
        vrmr_debug(HIGH, "insert %s", iface_ptr->name);

        /* insert before the current node */
        if (!(vrmr_list_insert_before(&interfaces->list, d_node, iface_ptr))) {
            vrmr_error(
                    -1, "Internal Error", "vrmr_list_insert_before() failed");
            return (-1);
        }
    } else {
        vrmr_debug(HIGH, "append %s", iface_ptr->name);

        /* append if we were bigger than all others */
        if (!(vrmr_list_append(&interfaces->list, iface_ptr))) {
            vrmr_error(-1, "Internal Error", "vrmr_list_append() failed");
            return (-1);
        }
    }
    return (0);
}

/*  search_interface

    Function to search the InterfacesList. This is a very slow
    function. It worst case performance is O(n) where 'n' is the
    size of the list.

    It returns the pointer or a NULL-pointer if not found.
*/
void *vrmr_search_interface(
        const struct vrmr_interfaces *interfaces, const char *name)
{
    struct vrmr_list_node *d_node = NULL;
    struct vrmr_interface *iface_ptr = NULL;

    assert(name && interfaces);

    vrmr_debug(HIGH, "looking for interface '%s'.", name);

    /* dont bother searching a empty list */
    if (interfaces->list.len == 0)
        return (NULL);

    /*
        loop trough the list and compare the names
    */
    for (d_node = interfaces->list.top; d_node; d_node = d_node->next) {
        iface_ptr = d_node->data;
        if (iface_ptr == NULL)
            continue;

        if (strcmp(iface_ptr->name, name) == 0) {
            /* Found! */
            vrmr_debug(HIGH, "Interface '%s' found!", name);

            /* return the pointer we found */
            return (iface_ptr);
        }
    }

    /* if we get here, the interface was not found, so return NULL */
    vrmr_debug(LOW, "interface '%s' not found.", name);
    return (NULL);
}

/*

*/
void *vrmr_search_interface_by_ip(
        struct vrmr_interfaces *interfaces, const char *ip)
{
    struct vrmr_list_node *d_node = NULL;
    struct vrmr_interface *iface_ptr = NULL;

    assert(ip && interfaces);

    vrmr_debug(HIGH,
            "looking for interface "
            "with ip '%s'.",
            ip);

    /* dont bother searching a empty list */
    if (interfaces->list.len == 0)
        return (NULL);

    /* loop trough the list and compare the names */
    for (d_node = interfaces->list.top; d_node; d_node = d_node->next) {
        iface_ptr = d_node->data;
        if (iface_ptr == NULL)
            continue;

        if (strcmp(iface_ptr->ipv4.ipaddress, ip) == 0) {
            /* Found! */
            vrmr_debug(HIGH, "Interface with ip '%s' found!", ip);

            /* return the pointer we found */
            return (iface_ptr);
        }
    }

    vrmr_debug(LOW, "interface with ip '%s' not found.", ip);
    return (NULL);
}

/*- print_list -

    Prints the interface list to stdout
*/
void vrmr_interfaces_print_list(const struct vrmr_interfaces *interfaces)
{
    struct vrmr_list_node *d_node = NULL;
    struct vrmr_interface *iface_ptr = NULL;

    if (!interfaces)
        return;

    if (interfaces->list.len > 0) {
        fprintf(stdout, "list len is %u\n", interfaces->list.len);
    } else {
        fprintf(stdout, "list is empty.\n");
        return;
    }

    for (d_node = interfaces->list.top; d_node; d_node = d_node->next) {
        iface_ptr = d_node->data;
        fprintf(stdout, "iface: %s, active: %d, device: %s, ipaddress: %s\n",
                iface_ptr->name, iface_ptr->active, iface_ptr->device,
                iface_ptr->ipv4.ipaddress);
    }
    return;
}

/*

    Currently only checks for a ':'.

    returns:
        1: valid
        0: not a valid name
*/
int vrmr_interface_check_devicename(const char *devicename)
{
    assert(devicename);

    for (size_t i = 0; i < strlen(devicename); i++) {
        if (devicename[i] == ':')
            return (0);
    }

    return (1);
}

/** \brief See if an interface is IPv6-enabled.
 *  \retval 1 yes
 *  \retval 0 no
 */
int vrmr_interface_ipv6_enabled(struct vrmr_interface *iface_ptr)
{
    if (iface_ptr != NULL && iface_ptr->ipv6.cidr6 != -1) {
        return 1;
    }
    return 0;
}

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
int vrmr_read_interface_info(
        struct vrmr_ctx *vctx, struct vrmr_interface *iface_ptr)
{
    int result = 0;
    char yesno[4] = "";
    char bw_str[11] = ""; /* 32 bit string, so max 4294967296 */

    assert(iface_ptr);

    vrmr_debug(HIGH, "start: name: %s", iface_ptr->name);

    /* check if the interface is active */
    result = vrmr_check_active(vctx, iface_ptr->name, VRMR_TYPE_INTERFACE);
    if (result == 1) {
        iface_ptr->active = TRUE;
    } else if (result == 0) {
        iface_ptr->active = FALSE;
    } else {
        vrmr_error(-1, "Internal Error", "vrmr_check_active() failed");
        return (-1);
    }

    /* ask the backend about the possible virtualness of the device */
    result = vctx->af->ask(vctx->ifac_backend, iface_ptr->name, "VIRTUAL",
            yesno, sizeof(yesno), VRMR_TYPE_INTERFACE, 0);
    if (result == 1) {
        if (strcasecmp(yesno, "yes") == 0)
            iface_ptr->device_virtual = TRUE;
        else
            iface_ptr->device_virtual = FALSE;
    } else if (result == 0) {
        /* if the interface is undefined, issue a warning and set inactive */
        vrmr_debug(LOW,
                "no VIRTUAL defined for interface '%s', assuming not virtual.",
                iface_ptr->name);

        iface_ptr->device_virtual = FALSE;
    } else {
        vrmr_error(-1, "Internal Error", "vctx->af->ask() failed");
        return (-1);
    }

    /* ask the backend about the interface of this interface. Get it? */
    result = vctx->af->ask(vctx->ifac_backend, iface_ptr->name, "DEVICE",
            iface_ptr->device, sizeof(iface_ptr->device), VRMR_TYPE_INTERFACE,
            0);
    if (result == 1) {
        vrmr_debug(HIGH, "device: %s.", iface_ptr->device);

        if (iface_ptr->device_virtual == TRUE) {
            if (vrmr_interface_check_devicename(iface_ptr->device) == 0) {
                /* set oldstyle (eth0:0) which is not supported by iptables */
                iface_ptr->device_virtual_oldstyle = TRUE;
            }
        }
    } else if (result == 0) {
        /* if the interface is undefined, issue a warning and set inactive */
        vrmr_debug(HIGH,
                "no DEVICE defined for interface '%s', trying pre-0.5.68s "
                "INTERFACE.",
                iface_ptr->name);

        result = vctx->af->ask(vctx->ifac_backend, iface_ptr->name, "INTERFACE",
                iface_ptr->device, sizeof(iface_ptr->device),
                VRMR_TYPE_INTERFACE, 0);
        if (result == 1) {
            vrmr_debug(HIGH, "device: %s.", iface_ptr->device);

            if (iface_ptr->device_virtual == TRUE) {
                if (vrmr_interface_check_devicename(iface_ptr->device) == 0) {
                    /* set oldstyle (eth0:0) which is not supported by iptables
                     */
                    iface_ptr->device_virtual_oldstyle = TRUE;
                }
            }
        } else if (result == 0) {
            /* if the interface is undefined, issue a warning and set inactive
             */
            vrmr_debug(LOW,
                    "no INTERFACE defined for interface '%s', assuming not "
                    "virtual.",
                    iface_ptr->name);
        } else {
            vrmr_error(-1, "Internal Error", "vctx->af->ask() failed");
            return (-1);
        }
    } else {
        vrmr_error(-1, "Internal Error", "vctx->af->ask() failed");
        return (-1);
    }

    /* ask the ipaddress of this interface */
    result = vctx->af->ask(vctx->ifac_backend, iface_ptr->name, "IPADDRESS",
            iface_ptr->ipv4.ipaddress, sizeof(iface_ptr->ipv4.ipaddress),
            VRMR_TYPE_INTERFACE, 0);
    if (result == 1) {
        vrmr_debug(HIGH, "ipaddress: %s.", iface_ptr->ipv4.ipaddress);

        /* check if ip is dynamic */
        if (strcmp(iface_ptr->ipv4.ipaddress, "dynamic") == 0) {
            iface_ptr->dynamic = TRUE;
        }
    } else if (result == 0) {
        vrmr_debug(LOW,
                "no IPADDRESS defined for interface '%s', assuming not "
                "virtual.",
                iface_ptr->name);
    } else {
        vrmr_error(-1, "Internal Error", "vctx->af->ask() failed");
        return (-1);
    }

    /* ask the ipv6 address of this interface */
    result = vctx->af->ask(vctx->ifac_backend, iface_ptr->name, "IPV6ADDRESS",
            iface_ptr->ipv6.ip6, sizeof(iface_ptr->ipv6.ip6),
            VRMR_TYPE_INTERFACE, 0);
    if (result == 1) {
        vrmr_debug(HIGH, "ipaddress: %s.", iface_ptr->ipv6.ip6);

        /* check if ip is dynamic */
        if (strcmp(iface_ptr->ipv6.ip6, "dynamic") == 0) {
            iface_ptr->dynamic = TRUE;
        }

        iface_ptr->ipv6.cidr6 = 128;
    } else if (result == 0) {
        vrmr_debug(LOW,
                "no IPV6ADDRESS defined for interface '%s', assuming not "
                "virtual.",
                iface_ptr->name);
    } else {
        vrmr_error(-1, "Internal Error", "vctx->af->ask() failed");
        return (-1);
    }

    /* lookup if we need shaping */
    result = vctx->af->ask(vctx->ifac_backend, iface_ptr->name, "SHAPE", yesno,
            sizeof(yesno), VRMR_TYPE_INTERFACE, 0);
    if (result == 1) {
        if (strcasecmp(yesno, "yes") == 0)
            iface_ptr->shape = TRUE;
        else
            iface_ptr->shape = FALSE;
    } else if (result == 0) {
        /* if the interface is undefined, issue a warning and set inactive */
        vrmr_debug(LOW,
                "no SHAPE defined for interface '%s', assuming no shaping.",
                iface_ptr->name);

        iface_ptr->shape = FALSE;
    } else {
        vrmr_error(-1, "Internal Error", "vctx->af->ask() failed");
        return (-1);
    }

    /* ask the BW_IN of this interface */
    result = vctx->af->ask(vctx->ifac_backend, iface_ptr->name, "BW_IN", bw_str,
            sizeof(bw_str), VRMR_TYPE_INTERFACE, 0);
    if (result == 1) {
        vrmr_debug(HIGH, "raw bw_str: %s.", bw_str);

        iface_ptr->bw_in = atoi(bw_str);
    } else if (result == 0) {
        vrmr_debug(LOW, "no BW_IN defined for interface '%s', setting to 0.",
                iface_ptr->name);
        iface_ptr->bw_in = 0;
    } else {
        vrmr_error(-1, "Internal Error", "vctx->af->ask() failed");
        return (-1);
    }

    /* ask the BW_IN_UNIT of this interface */
    result = vctx->af->ask(vctx->ifac_backend, iface_ptr->name, "BW_IN_UNIT",
            iface_ptr->bw_in_unit, sizeof(iface_ptr->bw_in_unit),
            VRMR_TYPE_INTERFACE, 0);
    if (result == 1) {
        vrmr_debug(HIGH, "raw bw_str (unit): %s.", iface_ptr->bw_in_unit);

        if (strcasecmp(iface_ptr->bw_in_unit, "kbit") == 0) {
            /* okay do nothing */
        } else if (strcasecmp(iface_ptr->bw_in_unit, "mbit") == 0) {
            /* okay do nothing */
        } else {
            /* XXX default/error? */
        }
    } else if (result == 0) {
        vrmr_debug(LOW,
                "no BW_IN_UNIT defined for interface '%s', setting to 0.",
                iface_ptr->name);
        iface_ptr->bw_in = 0;
    } else {
        vrmr_error(-1, "Internal Error", "vctx->af->ask() failed");
        return (-1);
    }

    /* ask the BW_OUT of this interface */
    result = vctx->af->ask(vctx->ifac_backend, iface_ptr->name, "BW_OUT",
            bw_str, sizeof(bw_str), VRMR_TYPE_INTERFACE, 0);
    if (result == 1) {
        vrmr_debug(HIGH, "raw bw_str: %s.", bw_str);
        iface_ptr->bw_out = atoi(bw_str);
    } else if (result == 0) {
        vrmr_debug(LOW, "no BW_OUT defined for interface '%s', setting to 0.",
                iface_ptr->name);
        iface_ptr->bw_out = 0;
    } else {
        vrmr_error(-1, "Internal Error", "vctx->af->ask() failed");
        return (-1);
    }

    /* ask the BW_OUT_UNIT of this interface */
    result = vctx->af->ask(vctx->ifac_backend, iface_ptr->name, "BW_OUT_UNIT",
            iface_ptr->bw_out_unit, sizeof(iface_ptr->bw_out_unit),
            VRMR_TYPE_INTERFACE, 0);
    if (result == 1) {
        vrmr_debug(HIGH, "raw bw_str (unit): %s.", iface_ptr->bw_out_unit);

        if (strcasecmp(iface_ptr->bw_out_unit, "kbit") == 0) {
            /* okay do nothing */
        } else if (strcasecmp(iface_ptr->bw_out_unit, "mbit") == 0) {
            /* okay do nothing */
        }
    } else if (result == 0) {
        vrmr_debug(LOW,
                "no BW_OUT_UNIT defined for interface '%s', setting to 0.",
                iface_ptr->name);
        iface_ptr->bw_out = 0;
    } else {
        vrmr_error(-1, "Internal Error", "vctx->af->ask() failed");
        return (-1);
    }

    if (iface_ptr->device_virtual == FALSE) {
        /* get the rules */
        if (vrmr_interfaces_get_rules(vctx, iface_ptr) < 0) {
            vrmr_error(
                    -1, "Internal Error", "vrmr_interfaces_get_rules() failed");
            return (-1);
        }
    }

    /* lookup if we need tcpmss */
    result = vctx->af->ask(vctx->ifac_backend, iface_ptr->name, "TCPMSS", yesno,
            sizeof(yesno), VRMR_TYPE_INTERFACE, 0);
    if (result == 1) {
        if (strcasecmp(yesno, "yes") == 0)
            iface_ptr->tcpmss_clamp = TRUE;
        else
            iface_ptr->tcpmss_clamp = FALSE;
    } else if (result == 0) {
        /* if the interface is undefined, issue a warning and set inactive */
        vrmr_debug(LOW,
                "no TCPMSS defined for interface '%s', assuming no tcpmss "
                "setting.",
                iface_ptr->name);

        iface_ptr->tcpmss_clamp = FALSE;
    } else {
        vrmr_error(-1, "Internal Error", "vctx->af->ask() failed");
        return (-1);
    }

    if (iface_ptr->device_virtual_oldstyle == FALSE) {
        /* now check if the interface is currently up */
        result =
                vrmr_get_iface_stats(iface_ptr->device, NULL, NULL, NULL, NULL);
        if (result == 0) {
            vrmr_debug(HIGH, "interface '%s' is up.", iface_ptr->name);

            iface_ptr->up = TRUE;
        } else if (result == 1) {
            vrmr_debug(HIGH, "interface '%s' is down.", iface_ptr->name);

            iface_ptr->up = FALSE;
        } else {
            vrmr_error(-1, "Internal Error", "vrmr_get_iface_stats() failed");
            return (-1);
        }
    }

    vrmr_debug(HIGH, "end: succes. name: %s.", iface_ptr->name);
    return (0);
}

/*  insert_interface

    Inserts the interface 'name' into the linked-list.

    Returncodes:
        -1: error
         0: succes
         1: interface failed, maybe it is inactive
*/
int vrmr_insert_interface(struct vrmr_ctx *vctx,
        struct vrmr_interfaces *interfaces, const char *name)
{
    assert(name && interfaces);

    vrmr_debug(HIGH, "start: name: %s.", name);

    struct vrmr_interface *iface_ptr = vrmr_interface_malloc();
    if (iface_ptr == NULL) {
        vrmr_error(
                -1, "Internal Error", "malloc() failed: %s", strerror(errno));
        return (-1);
    }

    /* set the name in the new structure */
    (void)strlcpy(iface_ptr->name, name, sizeof(iface_ptr->name));

    /* call vrmr_read_interface_info. here the info is read. */
    if (vrmr_read_interface_info(vctx, iface_ptr) < 0) {
        vrmr_error(-1, "Internal Error", "vrmr_read_interface_info() failed");
        free(iface_ptr);
        return (-1);
    }

    /* insert into the list (sorted) */
    if (vrmr_insert_interface_list(interfaces, iface_ptr) < 0) {
        free(iface_ptr);
        return (-1);
    }

    /* update status */
    iface_ptr->status = VRMR_ST_ADDED;

    /* update the interfaces */
    if (iface_ptr->active == TRUE)
        interfaces->active_interfaces = TRUE;
    if (iface_ptr->dynamic == TRUE)
        interfaces->dynamic_interfaces = TRUE;

    vrmr_debug(HIGH, "end: succes.");
    return (0);
}

/*  init_interfaces

    Loads all interfaces in memory.

    Returncodes:
         0: succes
        -1: error
*/
int vrmr_init_interfaces(
        struct vrmr_ctx *vctx, struct vrmr_interfaces *interfaces)
{
    int result = 0, counter = 0, zonetype = 0;
    char ifacname[VRMR_MAX_INTERFACE] = "";

    assert(interfaces);

    /* init */
    memset(interfaces, 0, sizeof(struct vrmr_interfaces));
    /* setup the list */
    vrmr_list_setup(&interfaces->list, NULL);

    /* get the list from the backend */
    while (vctx->af->list(vctx->ifac_backend, ifacname, &zonetype,
                   VRMR_BT_INTERFACES) != NULL) {
        vrmr_debug(MEDIUM, "loading interface %s", ifacname);

        result = vrmr_insert_interface(vctx, interfaces, ifacname);
        if (result < 0) {
            vrmr_error(-1, "Internal Error", "insert_interface() failed");
            return (-1);
        }

        counter++;

        vrmr_debug(LOW, "loading interface succes: '%s'.", ifacname);
    }

    return (0);
}

/*  vrmr_interfaces_save_rules

    Save the rules to the backend.

    Returncodes:
         0: ok
        -1: error
*/
int vrmr_interfaces_save_rules(
        struct vrmr_ctx *vctx, struct vrmr_interface *iface_ptr)
{
    struct vrmr_list_node *d_node = NULL;
    struct vrmr_rule *rule_ptr = NULL;
    char rule_str[VRMR_MAX_RULE_LENGTH] = "";

    assert(iface_ptr);

    /* write to backend */
    if (iface_ptr->ProtectList.len == 0) {
        /* clear */
        if (vctx->af->tell(vctx->ifac_backend, iface_ptr->name, "RULE", "", 1,
                    VRMR_TYPE_INTERFACE) < 0) {
            vrmr_error(-1, "Internal Error", "vctx->af->tell() failed");
            return (-1);
        }
    } else {
        /* write to backend */
        for (d_node = iface_ptr->ProtectList.top; d_node;
                d_node = d_node->next) {
            if (!(rule_ptr = d_node->data)) {
                vrmr_error(-1, "Internal Error", "NULL pointer");
                return (-1);
            }

            snprintf(rule_str, sizeof(rule_str), "protect against %s",
                    rule_ptr->danger);

            if (d_node == iface_ptr->ProtectList.top) {
                /* save to backend */
                if (vctx->af->tell(vctx->ifac_backend, iface_ptr->name, "RULE",
                            rule_str, 1, VRMR_TYPE_INTERFACE) < 0) {
                    vrmr_error(-1, "Internal Error", "vctx->af->tell() failed");
                    return (-1);
                }
            } else {
                /* save to backend */
                if (vctx->af->tell(vctx->ifac_backend, iface_ptr->name, "RULE",
                            rule_str, 0, VRMR_TYPE_INTERFACE) < 0) {
                    vrmr_error(-1, "Internal Error", "vctx->af->tell() failed");
                    return (-1);
                }
            }
        }
    }

    return (0);
}

int vrmr_new_interface(struct vrmr_ctx *vctx,
        struct vrmr_interfaces *interfaces, char *iface_name)
{
    int result = 0;
    struct vrmr_rule *rule_ptr = NULL;

    assert(iface_name && interfaces);

    struct vrmr_interface *iface_ptr = vrmr_interface_malloc();
    if (iface_ptr == NULL) {
        vrmr_error(
                -1, "Internal Error", "malloc() failed: %s", strerror(errno));
        return (-1);
    }

    /* copy name */
    (void)strlcpy(iface_ptr->name, iface_name, sizeof(iface_ptr->name));

    /* insert into the list (sorted) */
    if (vrmr_insert_interface_list(interfaces, iface_ptr) < 0)
        return (-1);

    /* add to the backend */
    vrmr_debug(HIGH, "calling vctx->af->add for '%s'.", iface_name);
    result = vctx->af->add(vctx->ifac_backend, iface_name, VRMR_TYPE_INTERFACE);
    if (result < 0) {
        vrmr_error(-1, "Internal Error", "vctx->af->add() failed");
        return (-1);
    }
    vrmr_debug(HIGH, "calling vctx->af->add for '%s' success.", iface_name);

    /* set active */
    result = vctx->af->tell(vctx->ifac_backend, iface_ptr->name, "ACTIVE",
            iface_ptr->active ? "Yes" : "No", 1, VRMR_TYPE_INTERFACE);
    if (result < 0) {
        vrmr_error(-1, "Internal Error", "vctx->af->tell() failed");
        return (-1);
    }

    /* set virtual */
    result = vctx->af->tell(vctx->ifac_backend, iface_ptr->name, "VIRTUAL",
            iface_ptr->device_virtual ? "Yes" : "No", 1, VRMR_TYPE_INTERFACE);
    if (result < 0) {
        vrmr_error(-1, "Internal Error", "vctx->af->tell() failed");
        return (-1);
    }

    /* interface protection options are 'on' by default */
    if (!(rule_ptr = rules_create_protect_rule(
                  "protect", iface_ptr->name, "source-routed-packets", NULL))) {
        vrmr_error(-1, "Internal Error", "rules_create_protect_rule() failed");
        return (-1);
    }
    if (vrmr_list_append(&iface_ptr->ProtectList, rule_ptr) == NULL) {
        vrmr_error(-1, "Internal Error", "vrmr_list_append() failed");
        return (-1);
    }

    if (!(rule_ptr = rules_create_protect_rule(
                  "protect", iface_ptr->name, "icmp-redirect", NULL))) {
        vrmr_error(-1, "Internal Error", "rules_create_protect_rule() failed");
        return (-1);
    }
    if (vrmr_list_append(&iface_ptr->ProtectList, rule_ptr) == NULL) {
        vrmr_error(-1, "Internal Error", "vrmr_list_append() failed");
        return (-1);
    }

    if (!(rule_ptr = rules_create_protect_rule(
                  "protect", iface_ptr->name, "send-redirect", NULL))) {
        vrmr_error(-1, "Internal Error", "rules_create_protect_rule() failed");
        return (-1);
    }
    if (vrmr_list_append(&iface_ptr->ProtectList, rule_ptr) == NULL) {
        vrmr_error(-1, "Internal Error", "vrmr_list_append() failed");
        return (-1);
    }

    if (!(rule_ptr = rules_create_protect_rule(
                  "protect", iface_ptr->name, "rp-filter", NULL))) {
        vrmr_error(-1, "Internal Error", "rules_create_protect_rule() failed");
        return (-1);
    }
    if (vrmr_list_append(&iface_ptr->ProtectList, rule_ptr) == NULL) {
        vrmr_error(-1, "Internal Error", "vrmr_list_append() failed");
        return (-1);
    }

    if (!(rule_ptr = rules_create_protect_rule(
                  "protect", iface_ptr->name, "log-martians", NULL))) {
        vrmr_error(-1, "Internal Error", "rules_create_protect_rule() failed");
        return (-1);
    }
    if (vrmr_list_append(&iface_ptr->ProtectList, rule_ptr) == NULL) {
        vrmr_error(-1, "Internal Error", "vrmr_list_append() failed");
        return (-1);
    }

    /* now let try to write this to the backend */
    if (vrmr_interfaces_save_rules(vctx, iface_ptr) < 0) {
        vrmr_error(
                -1, "Internal Error", "interfaces_save_protectrules() failed");
        return (-1);
    }

    return (0);
}

/*  vrmr_delete_interface

    Deletes an interface from the list, from memory and from
    the backend.

    Returncodes:
         0: ok
        -1: error
*/
int vrmr_delete_interface(struct vrmr_ctx *vctx,
        struct vrmr_interfaces *interfaces, char *iface_name)
{
    struct vrmr_interface *iface_ptr = NULL;
    struct vrmr_list_node *d_node = NULL;

    assert(iface_name && interfaces);

    /* first search the interface in the list */
    if (!(iface_ptr = vrmr_search_interface(interfaces, iface_name))) {
        vrmr_error(-1, "Internal Error", "interface '%s' not found in memory",
                iface_name);
        return (-1);
    }

    /* check the refernce counters */
    if (iface_ptr->refcnt_network > 0) {
        vrmr_error(-1, "Internal Error",
                "interface '%s' is still attached to %u network(s)",
                iface_ptr->name, iface_ptr->refcnt_network);
        return (-1);
    }

    iface_ptr = NULL;

    /* remove the interface from the backend */
    if (vctx->af->del(vctx->ifac_backend, iface_name, VRMR_TYPE_INTERFACE, 1) <
            0) {
        vrmr_error(-1, "Internal Error", "vctx->af->del() failed");
        return (-1);
    }

    /* now search the interface again to remove it */
    for (d_node = interfaces->list.top; d_node; d_node = d_node->next) {
        if (!(iface_ptr = d_node->data)) {
            vrmr_error(-1, "Internal Error", "NULL pointer");
            return (-1);
        }

        if (strcmp(iface_name, iface_ptr->name) == 0) {
            /*  this is the interface

                now remove it from the list
            */
            if (vrmr_list_remove_node(&interfaces->list, d_node) < 0) {
                vrmr_error(
                        -1, "Internal Error", "vrmr_list_remove_node() failed");
                return (-1);
            }

            /* finally free the memory */
            free(iface_ptr);

            return (0);
        }
    }

    /* if we get here the interface was not found in the list */
    return (-1);
}

/*  vrmr_ins_iface_into_zonelist

    load the insertfaces into the zoneslist

    Returncodes
         0: ok
        -1: error
*/
int vrmr_ins_iface_into_zonelist(
        struct vrmr_list *ifacelist, struct vrmr_list *zonelist)
{
    struct vrmr_interface *iface_ptr = NULL;
    struct vrmr_zone *zone_ptr = NULL;
    struct vrmr_list_node *iface_node = NULL;
    char name[VRMR_MAX_INTERFACE + 8 + 2 +
              1]; // 32 max iface length, 8 firewall, 2 () and 1 \0

    vrmr_debug(HIGH, "start.");

    assert(ifacelist && zonelist);

    /* dont bother an empty interface list */
    if (ifacelist->len == 0)
        return (0);

    /* loop trough the interface list */
    for (iface_node = ifacelist->top; iface_node;
            iface_node = iface_node->next) {
        iface_ptr = iface_node->data;
        if (iface_ptr == NULL)
            continue;

        /*
            we dont care about an interface without an ipaddress
        */
        if (strcmp(iface_ptr->ipv4.ipaddress, "") != 0) {
            /*
                pretty name
            */
            if (snprintf(name, sizeof(name), "firewall(%s)", iface_ptr->name) >=
                    (int)sizeof(name)) {
                vrmr_error(-1, "Internal Error", "buffer overflow");
                return (-1);
            }

            /*
                alloc mem for the temp zone
            */
            if (!(zone_ptr = vrmr_zone_malloc())) {
                vrmr_error(-1, "Internal Error", "vrmr_zone_malloc() failed");
                return (-1);
            }

            /* copy the name */
            (void)strlcpy(zone_ptr->name, name, sizeof(zone_ptr->name));
            /* copy the ipaddress */
            (void)strlcpy(zone_ptr->ipv4.ipaddress, iface_ptr->ipv4.ipaddress,
                    sizeof(zone_ptr->ipv4.ipaddress));

            /*
                set the type to firewall, so we can recognize the interface in
               an easy way
            */
            zone_ptr->type = VRMR_TYPE_FIREWALL;

            /*
                append to the zoneslist
            */
            if (vrmr_list_append(zonelist, zone_ptr) == NULL) {
                vrmr_error(-1, "Internal Error", "vrmr_list_append() failed");
                free(zone_ptr);
                return (-1);
            }

            vrmr_debug(HIGH, "inserted '%s' into zonelist.", zone_ptr->name);
        }
    }
    return (0);
}

/*  vrmr_rem_iface_from_zonelist

    Removes all zones with type VRMR_TYPE_FIREWALL from the zoneslist.
    This normally are interfaces and network broadcast addresses
    which were included in this list by vrmr_ins_iface_into_zonelist.

    Returncodes:
         0: ok
        -1: error
*/
int vrmr_rem_iface_from_zonelist(struct vrmr_list *zonelist)
{
    struct vrmr_zone *zone_ptr = NULL;
    struct vrmr_list_node *d_node = NULL, *next_node = NULL;
    int i = 0;

    assert(zonelist);
    vrmr_debug(HIGH, "start.");

    for (d_node = zonelist->top; d_node; d_node = next_node) {
        if (!(zone_ptr = d_node->data)) {
            vrmr_error(-1, "Internal Error", "NULL pointer");
            return (-1);
        }

        /*  we use next_node here because when a d_node is
            removed from the list it is also free'd from
            memory. So we have to determine the next
            node before that happens.
        */
        next_node = d_node->next;

        if (zone_ptr->type == VRMR_TYPE_FIREWALL) {
            vrmr_debug(HIGH, "type: VRMR_TYPE_FIREWALL '%s'.", zone_ptr->name);

            /* remove the node from the list */
            if (vrmr_list_remove_node(zonelist, d_node) < 0) {
                vrmr_error(
                        -1, "Internal Error", "vrmr_list_remove_node() failed");
                return (-1);
            }

            /*  free the memory, but only if the remove function
                in the list is NULL. Otherwise it is already free'd
                by vrmr_list_remove_node.
            */
            if (zonelist->remove == NULL)
                free(zone_ptr);

            i++;
        }
    }
    vrmr_debug(HIGH, "%d interfaces/broadcasts removed.", i);
    return (0);
}

/*  vrmr_get_iface_stats

    Gets information about an interface from /proc/net/dev. It can also be used
    to check if an interface is up.

    Returncodes:
         0: ok
        -1: error
         1: int not found
*/
int vrmr_get_iface_stats(const char *iface_name, uint32_t *recv_bytes,
        uint32_t *recv_packets, uint32_t *trans_bytes, uint32_t *trans_packets)
{
    char proc_net_dev[] = "/proc/net/dev";
    char line[256] = "",

         /*
             NOTE: if you change the length of the interface, also change it in
             sscanf!!!!
         */
            interface[64] = "";

    int found = 0; /* indicates that the interface was found */

    FILE *fp = NULL;

    struct {
        unsigned long long
                bytes; /* a long because otherwise it would max handle 2gb */
        unsigned long long packets;
        unsigned int errors;
        unsigned int drop;
        unsigned int fifo;
        unsigned int frame;
        unsigned int comp;
        unsigned int multi;
    } recv = {0, 0, 0, 0, 0, 0, 0, 0}, trans = {0, 0, 0, 0, 0, 0, 0, 0};

    /* first reset */
    if (recv_bytes != NULL)
        *recv_bytes = 0;
    if (trans_bytes != NULL)
        *trans_bytes = 0;
    if (recv_packets != NULL)
        *recv_packets = 0;
    if (trans_packets != NULL)
        *trans_packets = 0;

    /* open the proc entry */
    if (!(fp = fopen(proc_net_dev, "r"))) {
        vrmr_error(-1, "Internal Error", "unable to open '%s': %s",
                proc_net_dev, strerror(errno));
        return (-1);
    }

    /* loop trough the file */
    while (fgets(line, (int)sizeof(line), fp) != NULL) {
        if (strlen(line) == 0 || line[0] == '\n')
            continue;

        /*  first scan only the first string, here you can see why (from the
           file): lo: 3335005   17735 ... eth0:1055472756 4679465 ...

            notice that with eth0 there is no space between the semicolon and
           the number. Thats where we test for.
        */
        sscanf(line, "%63s", interface);

        if (strncmp(interface, iface_name, strlen(iface_name)) == 0) {
            found = 1;

            /* if only want to know if the device is up break out now */
            if (!recv_bytes && !trans_bytes && !recv_packets && !trans_packets)
                break;

            /* if we have an semicolon at the end (common) */
            if (interface[strlen(interface) - 1] == ':') {
                int r = sscanf(line,
                        "%32s %llu %llu %u %u %u %u %u %u %llu %llu %u %u %u "
                        "%u %u %u",
                        interface, &recv.bytes, &recv.packets, &recv.errors,
                        &recv.drop, &recv.fifo, &recv.frame, &recv.comp,
                        &recv.multi, &trans.bytes, &trans.packets,
                        &trans.errors, &trans.drop, &trans.fifo, &trans.frame,
                        &trans.comp, &trans.multi);
                if (r != 17)
                    vrmr_debug(NONE,
                            "r %d (17?), interface '%s' iface_name '%s' line "
                            "'%s'",
                            r, interface, iface_name, line);
            }
            /* else the recv bytes is very big and old format */
            else {
                char *bytes_start = strchr(interface, ':');
                if (bytes_start != NULL) {
                    bytes_start++; // skip past :
                    char *end;
                    recv.bytes = strtoul(bytes_start, &end, 10);
                    if (end) {
                        vrmr_debug(NONE, "recv.bytes %llu %s", recv.bytes, end);
                    }
                    char *line_part = line + strlen(interface);

                    int y = sscanf(line_part,
                            "%llu %u %u %u %u %u %u %llu %llu %u %u %u %u %u "
                            "%u",
                            &recv.packets, &recv.errors, &recv.drop, &recv.fifo,
                            &recv.frame, &recv.comp, &recv.multi, &trans.bytes,
                            &trans.packets, &trans.errors, &trans.drop,
                            &trans.fifo, &trans.frame, &trans.comp,
                            &trans.multi);
                    if (y != 15)
                        vrmr_debug(NONE, "y %d (15?), line '%s'", y, line_part);
                }
            }

            /* pass back to the calling function */
            if (recv_bytes != NULL)
                *recv_bytes = recv.bytes;
            if (trans_bytes != NULL)
                *trans_bytes = trans.bytes;
            if (recv_packets != NULL)
                *recv_packets = recv.packets;
            if (trans_packets != NULL)
                *trans_packets = trans.packets;
        }
    }

    if (fclose(fp) < 0)
        return (-1);

    /* if not found, return 1 */
    if (found == 0)
        return (1);

    return (0);
}

/*  vrmr_get_iface_stats_from_ipt

    Get interface counters (packets and bytes) from iptables.

    Value-result function.

    Returncode:
         0: ok
        -1: error
*/
int vrmr_get_iface_stats_from_ipt(struct vrmr_config *cfg,
        const char *iface_name, const char *chain, uint64_t *recv_packets,
        uint64_t *recv_bytes, uint64_t *trans_packets, uint64_t *trans_bytes)
{
    char line[256] = "", interface_in[32] = "", interface_out[32] = "",
         command[256] = "", proto[16] = "", target[32] = "", options[16] = "",
         source[36] = "", dest[36] = "";
    FILE *p = NULL;
    int line_count = 0;

    uint64_t packets = 0, bytes = 0;
    char trans_done = 0, recv_done = 0;

    *trans_bytes = 0;
    *recv_bytes = 0;
    *trans_packets = 0;
    *recv_packets = 0;

    /* if we are looking for the input or output numbers we can skip one
       direction, if we need FORWARD, we need both */
    if (strcmp(chain, "INPUT") == 0)
        trans_done = 1;
    else if (strcmp(chain, "OUTPUT") == 0)
        recv_done = 1;

    /* set the command to get the data from iptables */
    snprintf(command, sizeof(command), "%s -vnL %s --exact 2> /dev/null",
            cfg->iptables_location, chain);
    vrmr_debug(HIGH, "command: '%s'.", command);

    /* open the pipe to the command */
    if (!(p = popen(command, "r"))) {
        vrmr_error(-1, "Internal Error", "pipe failed: %s", strerror(errno));
        return (-1);
    }

    /* loop through the result */
    while (fgets(line, (int)sizeof(line), p) != NULL &&
            (!recv_done || !trans_done)) {
        /* we start looking after the first two lines */
        if (line_count >= 4) {
            /*            pack byte tg pr op in ou sr ds */
            sscanf(line, "%" PRIu64 " %" PRIu64 " %s %s %s %s %s %s %s",
                    &packets, &bytes, target, proto, options, interface_in,
                    interface_out, source, dest);

            vrmr_debug(HIGH,
                    "%s: tgt %s: iin: %s oin: %s packets: %" PRIu64
                    ", bytes: %" PRIu64,
                    iface_name, target, interface_in, interface_out, packets,
                    bytes);

            if (strcmp(source, "0.0.0.0/0") == 0 &&
                    strcmp(dest, "0.0.0.0/0") == 0 &&
                    (strcmp(proto, "all") == 0 || strcmp(proto, "0") == 0) &&
                    (interface_in[0] == '*' || interface_out[0] == '*')) {
                /* outgoing */
                if (interface_in[0] == '*' &&
                        strcmp(interface_out, iface_name) == 0) {
                    *trans_packets = packets;
                    *trans_bytes = bytes;
                    trans_done = 1;

                    vrmr_debug(HIGH,
                            "%s: trans: %" PRIu64 " (%" PRIu64 ") (trans done)",
                            iface_name, *trans_bytes, bytes);
                }
                /* incoming */
                else if (interface_out[0] == '*' &&
                         strcmp(interface_in, iface_name) == 0) {
                    *recv_packets = packets;
                    *recv_bytes = bytes;
                    recv_done = 1;

                    vrmr_debug(HIGH,
                            "%s: recv: %" PRIu64 " (%" PRIu64 ") (recv done)",
                            iface_name, *recv_bytes, bytes);
                }
            }
        }

        line_count++;
    }

    /* finally close the pipe */
    pclose(p);
    return (0);
}

/*  vrmr_validate_interfacename

    Returncodes:
        0: ok
        -1: error
*/
int vrmr_validate_interfacename(const char *interfacename, regex_t *reg_ex)
{
    assert(interfacename && reg_ex);

    vrmr_debug(HIGH, "checking: %s", interfacename);

    /*
        run the regex
    */
    if (regexec(reg_ex, interfacename, 0, NULL, 0) != 0) {
        vrmr_debug(HIGH, "'%s' is invalid", interfacename);
        return (-1);
    }

    vrmr_debug(HIGH, "'%s' is valid", interfacename);
    return (0);
}

/*  vrmr_destroy_interfaceslist

*/
void vrmr_destroy_interfaceslist(struct vrmr_interfaces *interfaces)
{
    struct vrmr_list_node *d_node = NULL;
    struct vrmr_interface *iface_ptr = NULL;

    assert(interfaces);

    /* first destroy all PortrangeLists */
    for (d_node = interfaces->list.top; d_node; d_node = d_node->next) {
        iface_ptr = d_node->data;
        if (iface_ptr == NULL)
            continue;

        vrmr_list_cleanup(&iface_ptr->ProtectList);
        free(iface_ptr);
        iface_ptr = NULL;
    }

    /* then the list itself */
    vrmr_list_cleanup(&interfaces->list);
}

/*  vrmr_interfaces_analyze_rule

    Function for gathering the info for creation of the rule
    and for sanity checking the rule.

    Returncodes:
         0: ok
        -1: error
 */
int vrmr_interfaces_analyze_rule(struct vrmr_rule *rule_ptr,
        struct vrmr_rule_cache *create, struct vrmr_interfaces *interfaces,
        struct vrmr_config *cnf)
{
    assert(rule_ptr && create && interfaces);

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
            if (rule_ptr->type == VRMR_PROT_PROC_INT) {
                create->who = NULL;
                create->who_int = NULL;

                if (!(create->who_int = vrmr_search_interface(
                              interfaces, rule_ptr->who))) {
                    vrmr_error(-1, "Error", "interface '%s' not found",
                            rule_ptr->who);
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

        int result = vrmr_get_danger_info(
                rule_ptr->danger, rule_ptr->source, &create->danger);
        if (result == 0) {
            vrmr_debug(HIGH, "vrmr_get_danger_info successfull.");
        } else {
            vrmr_error(-1, "Error", "getting danger '%s' failed",
                    rule_ptr->danger);
            return (-1);
        }

        /* set the action */
        (void)strlcpy(create->action, "protect", sizeof(create->action));
    }

    return (0);
}

/*  vrmr_rules_parse_line

    Returncodes:
        0: ok
        -1: error
*/
int vrmr_interfaces_rule_parse_line(
        const char *line, struct vrmr_rule *rule_ptr)
{
    size_t line_pos = 0, /* position in line */
            var_pos = 0; /* position in varible */
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

        /*
            now check what kind of rule we have
        */
        if (strcasecmp(against_keyw, "against") != 0) {
            vrmr_error(-1, "Internal Error",
                    "expected keyword 'against', got '%s'", against_keyw);
            return (-1);
        }

        /*
            okay, now lets see what kind of danger we are talking about
        */
        for (line_pos++, var_pos = 0;
                var_pos < sizeof(rule_ptr->danger) - 1 &&
                line[line_pos] != ' ' && line[line_pos] != '\0' &&
                line[line_pos] != '\n';
                line_pos++, var_pos++) {
            rule_ptr->danger[var_pos] = line[line_pos];
        }
        rule_ptr->danger[var_pos] = '\0';

        vrmr_debug(HIGH, "protect: danger: '%s'", rule_ptr->danger);

        rule_ptr->type = VRMR_PROT_PROC_INT;
    } else {
        vrmr_error(
                -1, "Error", "expected action 'protect', got '%s'", action_str);
        return (-1);
    }

    return (0);
}

int vrmr_interfaces_get_rules(
        struct vrmr_ctx *vctx, struct vrmr_interface *iface_ptr)
{
    char currule[VRMR_MAX_RULE_LENGTH] = "";
    struct vrmr_rule *rule_ptr = NULL;
    struct vrmr_list_node *d_node = NULL;

    /* safety */
    assert(iface_ptr);

    /* get all rules from the backend */
    while ((vctx->af->ask(vctx->ifac_backend, iface_ptr->name, "RULE", currule,
                   sizeof(currule), VRMR_TYPE_INTERFACE, 1)) == 1) {
        /* get mem */
        if (!(rule_ptr = vrmr_rule_malloc()))
            return (-1);

        /* copy name */
        (void)strlcpy(rule_ptr->who, iface_ptr->name, sizeof(rule_ptr->who));

        vrmr_debug(HIGH, "currule: '%s'.", currule);

        /* parse the line */
        if (vrmr_interfaces_rule_parse_line(currule, rule_ptr) < 0) {
            vrmr_error(-1, "Internal Error",
                    "vrmr_interfaces_rule_parse_line() failed");
            free(rule_ptr);
        } else {
            /* append to list */
            if (vrmr_list_append(&iface_ptr->ProtectList, rule_ptr) == NULL) {
                vrmr_error(-1, "Internal Error", "vrmr_list_append() failed");
                free(rule_ptr);
                return (-1);
            }
        }
    }

    if (vrmr_debug_level >= HIGH) {
        for (d_node = iface_ptr->ProtectList.top; d_node;
                d_node = d_node->next) {
            if (!(rule_ptr = d_node->data)) {
                return (-1);
            }

            vrmr_debug(HIGH, "a: %s, w: %s, d: %s, s: %s.",
                    vrmr_rules_itoaction(rule_ptr->action), rule_ptr->who,
                    rule_ptr->danger, rule_ptr->source);
        }
    }

    return (0);
}

/*
    returncodes:
         1: ok
         0: warning (set inactive)
        -1: error
*/
int vrmr_interfaces_check(struct vrmr_interface *iface_ptr)
{
    int retval = 1;
    int ipresult = 0;
    char ipaddress[16] = "";

    assert(iface_ptr);

    if (iface_ptr->device[0] == '\0') {
        vrmr_warning("Warning", "the interface '%s' does not have a device.",
                iface_ptr->name);
        retval = 0;
    }

    if (iface_ptr->dynamic == TRUE) {
        /* now try to get the dynamic ipaddress */
        ipresult = vrmr_get_dynamic_ip(iface_ptr->device,
                iface_ptr->ipv4.ipaddress, sizeof(iface_ptr->ipv4.ipaddress));
        if (ipresult == 0) {
            /* set iface to down */
            iface_ptr->up = FALSE;

            /* clear the ip field */
            memset(iface_ptr->ipv4.ipaddress, 0,
                    sizeof(iface_ptr->ipv4.ipaddress));

            vrmr_info("Info", "interface '%s' is down.", iface_ptr->name);
        } else if (ipresult < 0) {
            vrmr_error(-1, "Internal Error", "vrmr_get_dynamic_ip() failed");
            return (-1);
        }
    }

    /* check the ip if we have one */
    if (iface_ptr->ipv4.ipaddress[0] != '\0') {
        if (vrmr_check_ipv4address(NULL, NULL, iface_ptr->ipv4.ipaddress, 0) !=
                1) {
            vrmr_warning("Warning",
                    "the ipaddress '%s' of interface '%s' (%s) is invalid.",
                    iface_ptr->ipv4.ipaddress, iface_ptr->name,
                    iface_ptr->device);

            retval = 0;
        }
    }

    /* if the interface is up check the ipaddress with the ipaddress we know */
    if (iface_ptr->up == TRUE && iface_ptr->active == TRUE &&
            iface_ptr->device_virtual == FALSE) {
        ipresult = vrmr_get_dynamic_ip(
                iface_ptr->device, ipaddress, sizeof(ipaddress));
        if (ipresult < 0) {
            vrmr_error(-1, "Internal Error", "vrmr_get_dynamic_ip() failed");
            return (-1);
        } else if (ipresult == 0) {
            /* down after all */
            iface_ptr->up = FALSE;

            vrmr_debug(MEDIUM, "interface '%s' is down after all.",
                    iface_ptr->name);
        } else {
            if (strcmp(ipaddress, iface_ptr->ipv4.ipaddress) != 0) {
                vrmr_warning("Warning",
                        "the ipaddress '%s' of interface '%s' (%s) does not "
                        "match the ipaddress of the actual interface (%s).",
                        iface_ptr->ipv4.ipaddress, iface_ptr->name,
                        iface_ptr->device, ipaddress);

                retval = 0;
            }
        }
    }

    return (retval);
}

/*  load_interfaces

    calls init_interfaces and does some checking

    returncodes:
         0: ok
        -1: error
*/
int vrmr_interfaces_load(
        struct vrmr_ctx *vctx, struct vrmr_interfaces *interfaces)
{
    struct vrmr_interface *iface_ptr = NULL;
    struct vrmr_list_node *d_node = NULL;

    vrmr_info("Info", "Loading interfaces...");

    /* load the interfaces into memory */
    int result = vrmr_init_interfaces(vctx, interfaces);
    if (result == -1) {
        vrmr_error(-1, "Error", "Loading interfaces failed");
        return (-1);
    }

    /* loop through the interfaces */
    for (d_node = interfaces->list.top; d_node; d_node = d_node->next) {
        iface_ptr = d_node->data;
        if (iface_ptr == NULL)
            continue;

        result = vrmr_interfaces_check(iface_ptr);
        if (result == -1) {
            return (-1);
        } else if (result == 0) {
            vrmr_info("Info",
                    "Interface '%s' has been deactivated because of errors "
                    "while checking it.",
                    iface_ptr->name);
            iface_ptr->active = FALSE;
        }
    }

    vrmr_info("Info", "Loading interfaces succesfull.");
    return (0);
}

int vrmr_interfaces_iface_up(struct vrmr_interface *iface_ptr)
{
    char ip[16] = "";

    assert(iface_ptr);

    if (vrmr_get_dynamic_ip(iface_ptr->device, ip, sizeof(ip)) == 1)
        return (1);

    return (0);
}
