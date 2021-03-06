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

/*  adds an ipaddress to the blocklist

    returns:
         0: ok
        -1: error
*/
static int blocklist_add_ip_to_list(
        struct vrmr_blocklist *blocklist, const char *ip)
{
    char *ipaddress = NULL;

    assert(blocklist && ip);

    /* get the length */
    size_t len = strlen(ip);
    if (len <= 0 || len > 15) {
        vrmr_error(-1, "Internal Error", "weird ipaddress size %u",
                (unsigned int)len);
        return (-1);
    }

    /* alloc the mem */
    if (!(ipaddress = strdup(ip))) {
        vrmr_error(-1, "Error", "strdup failed: %s", strerror(errno));
        return (-1);
    }

    /* append to list */
    if (vrmr_list_append(&blocklist->list, ipaddress) == NULL) {
        vrmr_error(-1, "Internal Error", "appending into the list failed");
        free(ipaddress);
        return (-1);
    }

    return (0);
}

static int blocklist_add_string_to_list(
        struct vrmr_blocklist *blocklist, const char *str)
{
    char *string = NULL;

    assert(blocklist && str);

    if (!(string = strdup(str))) {
        vrmr_error(-1, "Error", "strdup failed: %s", strerror(errno));
        return (-1);
    }

    if (vrmr_list_append(&blocklist->list, string) == NULL) {
        vrmr_error(-1, "Internal Error", "appending into the list failed");
        free(string);
        return (-1);
    }

    return (0);
}

/*  the no_refcnt flag is for disabling the 'added more than once' warning,
    and for preventing the updating of the refcnt. It is annoying when
    we reload in vuurmuur.
*/
int vrmr_blocklist_add_one(struct vrmr_zones *zones,
        struct vrmr_blocklist *blocklist, char load_ips, char no_refcnt,
        const char *line)
{
    struct vrmr_zone *zone_ptr = NULL, *member_ptr = NULL;
    struct vrmr_list_node *d_node = NULL;

    assert(zones && blocklist && line);

    /* call vrmr_check_ipv4address with the quiet flag */
    if (vrmr_check_ipv4address(NULL, NULL, line, 1) != 1) {
        /* search for the name in the zones list */
        if ((zone_ptr = vrmr_search_zonedata(zones, line))) {
            if (zone_ptr->type != VRMR_TYPE_HOST &&
                    zone_ptr->type != VRMR_TYPE_GROUP) {
                if (zone_ptr->type == VRMR_TYPE_NETWORK) {
                    vrmr_warning("Warning",
                            "you can only add an ipaddress, host or group to "
                            "the blocklist. '%s' is a network.",
                            zone_ptr->name);
                } else if (zone_ptr->type == VRMR_TYPE_ZONE) {
                    vrmr_warning("Warning",
                            "you can only add an ipaddress, host or group to "
                            "the blocklist. '%s' is a zone.",
                            zone_ptr->name);
                } else {
                    vrmr_warning("Warning",
                            "you can only add an ipaddress, host or group to "
                            "the blocklist. '%s' is not understood.",
                            zone_ptr->name);
                }
            } else {
                if (!zone_ptr->active) {
                    if (!load_ips) {
                        /* add the string */
                        if (blocklist_add_string_to_list(blocklist, line) < 0) {
                            vrmr_error(-1, "Internal Error",
                                    "adding string to blocklist failed");
                            return (-1);
                        }
                    } else {
                        vrmr_warning("Warning",
                                "host/group '%s' is not active, so not adding "
                                "to blocklist.",
                                zone_ptr->name);
                    }
                } else {
                    if (no_refcnt == FALSE) {
                        /* set refcnt */
                        if (zone_ptr->refcnt_blocklist > 0) {
                            vrmr_warning("Warning",
                                    "adding '%s' to the blocklist more than "
                                    "once.",
                                    zone_ptr->name);
                        }
                        zone_ptr->refcnt_blocklist++;
                    }

                    if (zone_ptr->type == VRMR_TYPE_HOST) {
                        if (!load_ips) {
                            /* add the string */
                            if (blocklist_add_string_to_list(blocklist, line) <
                                    0) {
                                vrmr_error(-1, "Internal Error",
                                        "adding string to blocklist failed");
                                return (-1);
                            }
                        } else {
                            /* add the hosts ipaddress */
                            if (blocklist_add_ip_to_list(blocklist,
                                        zone_ptr->ipv4.ipaddress) < 0) {
                                vrmr_error(-1, "Internal Error",
                                        "adding ipaddress to blocklist failed");
                                return (-1);
                            }
                        }
                    }

                    if (zone_ptr->type == VRMR_TYPE_GROUP) {
                        if (!load_ips) {
                            /* add the string */
                            if (blocklist_add_string_to_list(blocklist, line) <
                                    0) {
                                vrmr_error(-1, "Internal Error",
                                        "adding string to blocklist failed");
                                return (-1);
                            }
                        } else {
                            for (d_node = zone_ptr->GroupList.top; d_node;
                                    d_node = d_node->next) {
                                if (!(member_ptr = d_node->data)) {
                                    vrmr_error(-1, "Internal Error",
                                            "NULL pointer");
                                    return (-1);
                                }

                                if (!member_ptr->active) {
                                    vrmr_warning("Warning",
                                            "groupmember '%s' from group '%s' "
                                            "is not active, so not adding to "
                                            "blocklist.",
                                            member_ptr->name, zone_ptr->name);
                                } else {
                                    /* add the groupmembers ipaddress */
                                    if (blocklist_add_ip_to_list(blocklist,
                                                member_ptr->ipv4.ipaddress) <
                                            0) {
                                        vrmr_error(-1, "Internal Error",
                                                "adding ipaddress to blocklist "
                                                "failed");
                                        return (-1);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        } else {
            if (!load_ips) {
                /* add the string */
                if (blocklist_add_string_to_list(blocklist, line) < 0) {
                    vrmr_error(-1, "Internal Error",
                            "adding string to blocklist failed");
                    return (-1);
                }
            } else {
                vrmr_warning("Warning",
                        "'%s' is neither a (valid) ipaddress, host or group. "
                        "Not adding to blocklist.",
                        line);
            }
        }
    } else {
        if (!load_ips) {
            /* add the string */
            if (blocklist_add_string_to_list(blocklist, line) < 0) {
                vrmr_error(-1, "Internal Error",
                        "adding string to blocklist failed");
                return (-1);
            }
        } else {
            /* valid ip, so add to the block list */
            if (blocklist_add_ip_to_list(blocklist, line) < 0) {
                vrmr_error(-1, "Internal Error",
                        "adding ipaddress to blocklist failed");
                return (-1);
            }
        }
    }

    return (0);
}

int vrmr_blocklist_rem_one(struct vrmr_zones *zones,
        struct vrmr_blocklist *blocklist, char *itemname)
{
    char *listitemname = NULL;
    struct vrmr_list_node *d_node = NULL;
    struct vrmr_zone *zone_ptr = NULL;

    assert(zones && blocklist && itemname);

    for (d_node = blocklist->list.top; d_node; d_node = d_node->next) {
        if (!(listitemname = d_node->data)) {
            vrmr_error(-1, "Internal Error", "NULL pointer");
            return (-1);
        }

        if (strcmp(listitemname, itemname) == 0) {
            /* call vrmr_check_ipv4address with the quiet flag */
            if (vrmr_check_ipv4address(NULL, NULL, itemname, 1) != 1) {
                /* search for the name in the zones list */
                if ((zone_ptr = vrmr_search_zonedata(zones, itemname))) {
                    /* decrease refcnt */
                    if (zone_ptr->refcnt_blocklist > 0)
                        zone_ptr->refcnt_blocklist--;
                    else {
                        vrmr_error(-1, "Internal Error",
                                "blocklist refcnt of '%s' already 0!",
                                zone_ptr->name);
                    }
                }
            }

            /* this one needs to be removed */
            if (vrmr_list_remove_node(&blocklist->list, d_node) < 0) {
                vrmr_error(
                        -1, "Internal Error", "removing item from list failed");
                return (-1);
            }

            listitemname = NULL;
            return (0);
        }
    }

    /* if we get here something went wrong */
    vrmr_error(-1, "Internal Error",
            "removing item '%s' from list failed: item not found", itemname);
    return (-1);
}

int vrmr_blocklist_init_list(struct vrmr_ctx *vctx,
        struct vrmr_config *cfg ATTR_UNUSED, struct vrmr_zones *zones,
        struct vrmr_blocklist *blocklist, char load_ips, char no_refcnt)
{
    char line[128] = "";
    size_t len = 0;
    char value[128] = "";
    char rule_name[32] = "";
    int type = 0;
    char blocklist_found = FALSE;

    assert(zones && blocklist);

    /* init */
    memset(blocklist, 0, sizeof(struct vrmr_blocklist));

    /* setup the blocklist */
    vrmr_list_setup(&blocklist->list, free);

    /* see if the blocklist already exists in the backend */
    while (vctx->rf->list(vctx->rule_backend, rule_name, &type,
                   VRMR_BT_RULES) != NULL) {
        vrmr_debug(MEDIUM, "loading rules: '%s', type: %d", rule_name, type);

        if (strcmp(rule_name, "blocklist") == 0)
            blocklist_found = TRUE;
    }

    if (blocklist_found == FALSE) {
        if (vctx->rf->add(vctx->rule_backend, "blocklist", VRMR_TYPE_RULE) <
                0) {
            vrmr_error(-1, "Internal Error", "rf->add() failed");
            return (-1);
        }
    }

    while ((vctx->rf->ask(vctx->rule_backend, "blocklist", "RULE", line,
                   sizeof(line), VRMR_TYPE_RULE, 1)) == 1) {
        len = strlen(line);
        if (len == 0 || line[0] == '#')
            continue;

        /* cut of the newline */
        if (line[len - 1] == '\n')
            line[len - 1] = '\0';

        if (strncmp(line, "block", 5) == 0) {
            sscanf(line, "block %120s", value);
            if (strlen(value) > 0) {
                /* add it to the list */
                if (vrmr_blocklist_add_one(
                            zones, blocklist, load_ips, no_refcnt, value) < 0) {
                    vrmr_error(-1, "Error", "adding to the blocklist failed");
                    return (-1);
                }
            }
        }
    }

    return (0);
}

int vrmr_blocklist_save_list(struct vrmr_ctx *vctx,
        struct vrmr_config *cfg ATTR_UNUSED, struct vrmr_blocklist *blocklist)
{
    char *line = NULL;
    int overwrite = 0;
    struct vrmr_list_node *d_node = NULL;
    char rule_str[128] = "";

    assert(blocklist);

    /* empty list, so clear all */
    if (blocklist->list.len == 0) {
        if (vctx->rf->tell(vctx->rule_backend, "blocklist", "RULE", "", 1,
                    VRMR_TYPE_RULE) < 0) {
            vrmr_error(-1, "Internal Error", "rf->tell() failed");
            return (-1);
        }
    } else {
        overwrite = 1;

        /* loop trough the list */
        for (d_node = blocklist->list.top; d_node; d_node = d_node->next) {
            if (!(line = d_node->data)) {
                vrmr_error(-1, "Internal Error", "NULL pointer");
                return (-1);
            }

            if (line[strlen(line) - 1] == '\n')
                line[strlen(line) - 1] = '\0';

            snprintf(rule_str, sizeof(rule_str), "block %s", line);

            /* write to the backend */
            if (vctx->rf->tell(vctx->rule_backend, "blocklist", "RULE",
                        rule_str, overwrite, VRMR_TYPE_RULE) < 0) {
                vrmr_error(-1, "Internal Error", "rf->tell() failed");
                return (-1);
            }

            overwrite = 0;
        }
    }

    return (0);
}
