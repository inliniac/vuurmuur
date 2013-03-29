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

/*  adds an ipaddress to the blocklist

    returns:
         0: ok
        -1: error
*/
static int
blocklist_add_ip_to_list(const int debuglvl, struct vrmr_blocklist *blocklist, char *ip)
{
    size_t  len = 0;
    char    *ipaddress = NULL;

    /* safety */
    if(!blocklist || !ip)
    {
        (void)vrprint.error(-1, "Internal Error", "parameter problem "
            "(in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    /* get the length */
    len = strlen(ip);
    if(len <= 0 || len > 15)
    {
        (void)vrprint.error(-1, "Internal Error", "weird ipaddress "
            "size %u (in: %s:%d).", len, __FUNC__, __LINE__);
        return(-1);
    }
    len = len + 1;

    /* alloc the mem */
    if(!(ipaddress = malloc(len)))
    {
        (void)vrprint.error(-1, "Error", "malloc failed: %s "
            "(in: %s:%d).", strerror(errno), __FUNC__, __LINE__);
        return(-1);
    }

    /*  copy addr */
    if(strlcpy(ipaddress, ip, len) >= len)
    {
        (void)vrprint.error(-1, "Internal Error", "ipaddress overflow "
            "(in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    /* append to list */
    if(d_list_append(debuglvl, &blocklist->list, ipaddress) == NULL)
    {
        (void)vrprint.error(-1, "Internal Error", "appending into the "
            "list failed (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    return(0);
}


static int
blocklist_add_string_to_list(const int debuglvl, struct vrmr_blocklist *blocklist, char *str)
{
    size_t  len = 0;
    char    *string = NULL;

    /* safety */
    if(!blocklist || !str)
    {
        (void)vrprint.error(-1, "Internal Error", "parameter problem "
            "(in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    /* get the length */
    len = strlen(str);
    if(len == 0)
    {
        (void)vrprint.error(-1, "Internal Error", "weird string size "
            "%u (in: %s:%d).", len, __FUNC__, __LINE__);
        return(-1);
    }
    len = len + 1;

    /* alloc the mem */
    if(!(string = malloc(len)))
    {
        (void)vrprint.error(-1, "Error", "malloc failed: %s "
            "(in: %s:%d).", strerror(errno), __FUNC__, __LINE__);
        return(-1);
    }

    /*  copy string */
    if(strlcpy(string, str, len) >= len)
    {
        (void)vrprint.error(-1, "Internal Error", "string overflow "
            "(in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    /* append to list */
    if(d_list_append(debuglvl, &blocklist->list, string) == NULL)
    {
        (void)vrprint.error(-1, "Internal Error", "appending into the "
            "list failed (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    return(0);
}


/*  the no_refcnt flag is for disabling the 'added more than once' warning,
    and for preventing the updating of the refcnt. It is annoying when
    we reload in vuurmuur.
*/
int
vrmr_blocklist_add_one(const int debuglvl, struct vrmr_zones *zones, struct vrmr_blocklist *blocklist, char load_ips, char no_refcnt, char *line)
{
    struct vrmr_zone    *zone_ptr = NULL,
                *member_ptr = NULL;
    d_list_node *d_node = NULL;

    /* safety */
    if(!zones || !blocklist || !line)
    {
        (void)vrprint.error(-1, "Internal Error", "parameter problem (in: %s:%d).",
                __FUNC__, __LINE__);
        return(-1);
    }

    /* call check_ipv4address with the quiet flag */
    if(check_ipv4address(debuglvl, NULL, NULL, line, 1) != 1)
    {
        /* search for the name in the zones list */
        if((zone_ptr = search_zonedata(debuglvl, zones, line)))
        {
            if(zone_ptr->type != TYPE_HOST && zone_ptr->type != TYPE_GROUP)
            {
                if(zone_ptr->type == TYPE_NETWORK)
                {
                    (void)vrprint.warning("Warning", "you can only add an ipaddress, host or group to the blocklist. '%s' is a network.", zone_ptr->name);
                }
                else if(zone_ptr->type == TYPE_ZONE)
                {
                    (void)vrprint.warning("Warning", "you can only add an ipaddress, host or group to the blocklist. '%s' is a zone.", zone_ptr->name);
                }
                else
                {
                    (void)vrprint.warning("Warning", "you can only add an ipaddress, host or group to the blocklist. '%s' is not understood.", zone_ptr->name);
                }
            }
            else
            {
                if(!zone_ptr->active)
                {
                    if(!load_ips)
                    {
                        /* add the string */
                        if(blocklist_add_string_to_list(debuglvl, blocklist, line) < 0)
                        {
                            (void)vrprint.error(-1, "Internal Error", "adding string to blocklist failed (in: %s:%d).", __FUNC__, __LINE__);
                            return(-1);
                        }
                    }
                    else
                    {
                        (void)vrprint.warning("Warning", "host/group '%s' is not active, so not adding to blocklist.", zone_ptr->name);
                    }
                }
                else
                {
                    if(no_refcnt == FALSE)
                    {
                        /* set refcnt */
                        if(zone_ptr->refcnt_blocklist > 0)
                        {
                            (void)vrprint.warning("Warning", "adding '%s' to the blocklist more than once.",
                                zone_ptr->name);
                        }
                        zone_ptr->refcnt_blocklist++;
                    }

                    if(zone_ptr->type == TYPE_HOST)
                    {
                        if(!load_ips)
                        {
                            /* add the string */
                            if(blocklist_add_string_to_list(debuglvl, blocklist, line) < 0)
                            {
                                (void)vrprint.error(-1, "Internal Error", "adding string to blocklist failed (in: %s:%d).", __FUNC__, __LINE__);
                                return(-1);
                            }
                        }
                        else
                        {
                            /* add the hosts ipaddress */
                            if(blocklist_add_ip_to_list(debuglvl, blocklist, zone_ptr->ipv4.ipaddress) < 0)
                            {
                                (void)vrprint.error(-1, "Internal Error", "adding ipaddress to blocklist failed (in: %s:%d).", __FUNC__, __LINE__);
                                return(-1);
                            }
                        }
                    }

                    if(zone_ptr->type == TYPE_GROUP)
                    {
                        if(!load_ips)
                        {
                            /* add the string */
                            if(blocklist_add_string_to_list(debuglvl, blocklist, line) < 0)
                            {
                                (void)vrprint.error(-1, "Internal Error", "adding string to blocklist failed (in: %s:%d).", __FUNC__, __LINE__);
                                return(-1);
                            }
                        }
                        else
                        {
                            for(d_node = zone_ptr->GroupList.top; d_node; d_node = d_node->next)
                            {
                                if(!(member_ptr = d_node->data))
                                {
                                    (void)vrprint.error(-1, "Internal Error", "NULL pointer (in: %s:%d).", __FUNC__, __LINE__);
                                    return(-1);
                                }

                                if(!member_ptr->active)
                                {
                                    (void)vrprint.warning("Warning", "groupmember '%s' from group '%s' is not active, so not adding to blocklist.", member_ptr->name, zone_ptr->name);
                                }
                                else
                                {
                                    /* add the groupmembers ipaddress */
                                    if(blocklist_add_ip_to_list(debuglvl, blocklist, member_ptr->ipv4.ipaddress) < 0)
                                    {
                                        (void)vrprint.error(-1, "Internal Error", "adding ipaddress to blocklist failed (in: %s:%d).", __FUNC__, __LINE__);
                                        return(-1);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        else
        {
            if(!load_ips)
            {
                /* add the string */
                if(blocklist_add_string_to_list(debuglvl, blocklist, line) < 0)
                {
                    (void)vrprint.error(-1, "Internal Error", "adding string to blocklist failed (in: %s:%d).", __FUNC__, __LINE__);
                    return(-1);
                }
            }
            else
            {
                (void)vrprint.warning("Warning", "'%s' is neither a (valid) ipaddress, host or group. Not adding to blocklist.", line);
            }
        }
    }
    else
    {
        if(!load_ips)
        {
            /* add the string */
            if(blocklist_add_string_to_list(debuglvl, blocklist, line) < 0)
            {
                (void)vrprint.error(-1, "Internal Error", "adding string to blocklist failed (in: %s:%d).", __FUNC__, __LINE__);
                return(-1);
            }
        }
        else
        {
            /* valid ip, so add to the block list */
            if(blocklist_add_ip_to_list(debuglvl, blocklist, line) < 0)
            {
                (void)vrprint.error(-1, "Internal Error", "adding ipaddress to blocklist failed (in: %s:%d).", __FUNC__, __LINE__);
                return(-1);
            }
        }
    }

    return(0);
}


int
vrmr_blocklist_rem_one(const int debuglvl, struct vrmr_zones *zones, struct vrmr_blocklist *blocklist, char *itemname)
{
    char                *listitemname = NULL;
    d_list_node         *d_node = NULL;
    struct vrmr_zone    *zone_ptr = NULL;

    /* safety */
    if(!zones || !blocklist || !itemname)
    {
        (void)vrprint.error(-1, "Internal Error", "parameter problem (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    /* look the item up in the list */
    for(d_node = blocklist->list.top; d_node; d_node = d_node->next)
    {
        if(!(listitemname = d_node->data))
        {
            (void)vrprint.error(-1, "Internal Error", "NULL pointer (in: %s:%d).", __FUNC__, __LINE__);
            return(-1);
        }

        if(strcmp(listitemname, itemname) == 0)
        {
            /* call check_ipv4address with the quiet flag */
            if(check_ipv4address(debuglvl, NULL, NULL, itemname, 1) != 1)
            {
                /* search for the name in the zones list */
                if((zone_ptr = search_zonedata(debuglvl, zones, itemname)))
                {
                    /* decrease refcnt */
                    if(zone_ptr->refcnt_blocklist > 0)
                        zone_ptr->refcnt_blocklist--;
                    else
                    {
                        (void)vrprint.error(-1, "Internal Error", "blocklist refcnt of '%s' already 0! (in: %s:%d).",
                                zone_ptr->name,
                                __FUNC__, __LINE__);
                    }
                }
            }

            /* this one needs to be removed */
            if(d_list_remove_node(debuglvl, &blocklist->list, d_node) < 0)
            {
                (void)vrprint.error(-1, "Internal Error", "removing item from list failed (in: %s:%d).", __FUNC__, __LINE__);
                return(-1);
            }

            listitemname = NULL;
            return(0);
        }
    }

    /* if we get here something went wrong */
    (void)vrprint.error(-1, "Internal Error", "removing item '%s' from list failed: item not found (in: %s:%d).",
                                itemname,
                                __FUNC__, __LINE__);
    return(-1);
}


/*  blocklist_read_file

    if 'load_ips' is set to 1 the ipaddresses of the hosts and the groups will
    be loaded, otherwise just the name in the file
*/
static int
blocklist_read_file(const int debuglvl, struct vuurmuur_config *cfg,
        struct vrmr_zones *zones, struct vrmr_blocklist *blocklist, char load_ips, char no_refcnt)
{
    FILE        *fp = NULL;
    char        line[128] = "";
    size_t      len = 0;


    /* safety */
    if(zones == NULL || blocklist == NULL)
    {
        (void)vrprint.error(-1, "Internal Error", "parameter problem (in: %s:%d).",
                            __FUNC__, __LINE__);
        return(-1);
    }

    if(debuglvl >= MEDIUM)
        (void)vrprint.debug(__FUNC__, "load_ips: %c, no_refcnt: %c.", load_ips, no_refcnt);

	/* open the blocklist-file */
	if(!(fp = vuurmuur_fopen(debuglvl, cfg, cfg->blocklist_location, "r")))
	{
		(void)vrprint.error(-1, "Error", "opening blockfile '%s' failed: %s (in: %s:%d).",
							cfg->blocklist_location,
							strerror(errno),
							__FUNC__, __LINE__);
		return(-1);
	}

    /* read the file */
    while(fgets(line, (int)sizeof(line), fp) != NULL)
    {
        len = strlen(line);

        if(len > 0 && line[0] != '#')
        {
            /* cut of the newline */
            if(line[len - 1] == '\n')
                line[len - 1] = '\0';

            /* add it to the list */
            if(vrmr_blocklist_add_one(debuglvl, zones, blocklist, load_ips, no_refcnt, line) < 0)
            {
                (void)vrprint.error(-1, "Error", "adding to the blocklist failed (in: %s:%d).", __FUNC__, __LINE__);

                /* try to close the file */
                if(fclose(fp) < 0)
                {
                    (void)vrprint.error(-1, "Error", "closing blockfile failed: %s (in: %s:%d).", strerror(errno), __FUNC__, __LINE__);
                    return(-1);
                }

                return(-1);
            }
        }
    }

    if(fclose(fp) < 0)
    {
        (void)vrprint.error(-1, "Error", "closing blockfile failed: %s (in: %s:%d).", strerror(errno), __FUNC__, __LINE__);
        return(-1);
    }

    (void)vrprint.info("Info", "added %d items to the blocklist.", blocklist->list.len);
    return(0);
}


int
vrmr_blocklist_init_list(const int debuglvl, struct vuurmuur_config *cfg,
        struct vrmr_zones *zones, struct vrmr_blocklist *blocklist, char load_ips, char no_refcnt)
{
    FILE        *fp = NULL;
    char        line[128] = "";
    int         result = 0;
    size_t      len = 0;
    char        value[128] = "";
    char        block_keyw[6] = "";
    char        rule_name[32] = "";
    int         type = 0;
    char        blocklist_found = FALSE;

    /* safety */
    if(zones == NULL || blocklist == NULL)
    {
        (void)vrprint.error(-1, "Internal Error", "parameter problem (in: %s:%d).",
                    __FUNC__, __LINE__);
        return(-1);
    }

    if(debuglvl >= HIGH)
        (void)vrprint.debug(__FUNC__, "start");

    /* init */
    memset(blocklist, 0, sizeof(struct vrmr_blocklist));

    /* setup the blocklist */
    if(d_list_setup(debuglvl, &blocklist->list, free) < 0)
    {
        (void)vrprint.error(-1, "Internal Error", "d_list_setup() failed (in: %s:%d).",
                    __FUNC__, __LINE__);
        return(-1);
    }

    /* open the blocklist-file */
    if((fp = fopen(cfg->blocklist_location, "r")))
    {
        (void)fclose(fp);

        if(debuglvl >= MEDIUM)
            (void)vrprint.debug(__FUNC__, "old_blocklistfile_used == TRUE");

        blocklist->old_blocklistfile_used = TRUE;

        result = blocklist_read_file(debuglvl, cfg, zones, blocklist, load_ips, no_refcnt);
        if(result < 0)
            return(-1);
    }
    else
    {
        if(debuglvl >= MEDIUM)
            (void)vrprint.debug(__FUNC__, "old_blocklistfile_used == FALSE");

        blocklist->old_blocklistfile_used = FALSE;

        /* see if the blocklist already exists in the backend */
        while(rf->list(debuglvl, rule_backend, rule_name, &type, CAT_RULES) != NULL)
        {
            if(debuglvl >= MEDIUM)
                (void)vrprint.debug(__FUNC__, "loading rules: '%s', type: %d",
                        rule_name, type);

            if(strcmp(rule_name, "blocklist") == 0)
                blocklist_found = TRUE;
        }

        if(blocklist_found == FALSE)
        {
            if(rf->add(debuglvl, rule_backend, "blocklist", TYPE_RULE) < 0)
            {
                (void)vrprint.error(-1, "Internal Error", "rf->add() failed (in: %s:%d).",
                        __FUNC__, __LINE__);
                return(-1);
            }
        }

        while((rf->ask(debuglvl, rule_backend, "blocklist", "RULE", line, sizeof(line), TYPE_RULE, 1)) == 1)
        {
            len = strlen(line);
            if(len > 0 && line[0] != '#')
            {
                /* cut of the newline */
                if(line[len - 1] == '\n')
                    line[len - 1] = '\0';

                sscanf(line, "%6s", block_keyw);

                if(debuglvl >= MEDIUM)
                    (void)vrprint.debug(__FUNC__, "line '%s', keyword '%s'",
                        line, block_keyw);

                if(strcmp(block_keyw, "block") == 0)
                {
                    sscanf(line, "block %128s", value);
                    if(strlen(value) > 0)
                    {
                        /* add it to the list */
                        if(vrmr_blocklist_add_one(debuglvl, zones, blocklist, load_ips, no_refcnt, value) < 0)
                        {
                            (void)vrprint.error(-1, "Error", "adding to the blocklist failed (in: %s:%d).",
                                __FUNC__, __LINE__);
                            return(-1);
                        }
                    }
                }
            }
        }
    }

    return(0);
}


static int
blocklist_write_file(const int debuglvl, struct vuurmuur_config *cfg, d_list *block_list)
{
    d_list_node *d_node   = NULL;
    char        *itemname = NULL;
    int         retval = 0;
    FILE        *fp = NULL;

    /* safety */
    if(block_list == NULL)
    {
        (void)vrprint.error(-1, "Internal Error", "parameter problem (in: %s).", __FUNC__);
        return(-1);
    }

    /* open the blockfile */
    if(!(fp = fopen(cfg->blocklist_location, "w+")))
    {
        (void)vrprint.error(-1, "Error", "opening blocklistfile '%s' failed: %s (in: %s:%d).",
                cfg->blocklist_location, strerror(errno), __FUNC__, __LINE__);
        return(-1);
    }

    fprintf(fp, "# BlockList for Vuurmuur\n");
    fprintf(fp, "#\n");
    fprintf(fp, "# put a list ipaddresses, hosts and groups to be blocked,\n");
    fprintf(fp, "# one per line.\n");

    for(d_node = block_list->top; d_node; d_node = d_node->next)
    {
        if(!(itemname = d_node->data))
        {
            (void)vrprint.error(-1, "Internal Error", "NULL pointer (in: %s:%d).",
                    __FUNC__, __LINE__);
            return(-1);
        }

        fprintf(fp, "block %s\n", itemname);
    }

    /* print the end-of-file so we know all went fine */
    fprintf(fp, "# end of file\n");
    fflush(fp);

    /* close the rulesfile */
    retval = fclose(fp);
    return(retval);
}


int
vrmr_blocklist_save_list(const int debuglvl, struct vuurmuur_config *cfg, struct vrmr_blocklist *blocklist)
{
    int         result = 0;
    char        *line = NULL;
    int         overwrite = 0;
    d_list_node *d_node = NULL;
    char        rule_str[128] = "";

    /* safety */
    if(blocklist == NULL)
    {
        (void)vrprint.error(-1, "Internal Error", "parameter problem (in: %s:%d).",
                __FUNC__, __LINE__);
        return(-1);
    }

    if(blocklist->old_blocklistfile_used == TRUE)
    {
        result = blocklist_write_file(debuglvl, cfg, &blocklist->list);
        if(result < 0)
            return(-1);
    }
    else
    {
        /* empty list, so clear all */
        if(blocklist->list.len == 0)
        {
            if(rf->tell(debuglvl, rule_backend, "blocklist", "RULE", "", 1, TYPE_RULE) < 0)
            {
                (void)vrprint.error(-1, "Internal Error", "rf->tell() failed (in: %s:%d).",
                        __FUNC__, __LINE__);
                return(-1);
            }
        }
        else
        {
            overwrite = 1;

            /* loop trough the list */
            for(d_node = blocklist->list.top; d_node ; d_node = d_node->next)
            {
                if(!(line = d_node->data))
                {
                    (void)vrprint.error(-1, "Internal Error", "NULL pointer (in: %s:%d).",
                            __FUNC__, __LINE__);
                    return(-1);
                }

                if(line[strlen(line)-1] == '\n')
                    line[strlen(line)-1] = '\0';

                snprintf(rule_str, sizeof(rule_str), "block %s", line);

                /* write to the backend */
                if(rf->tell(debuglvl, rule_backend, "blocklist", "RULE", rule_str, overwrite, TYPE_RULE) < 0)
                {
                    (void)vrprint.error(-1, "Internal Error", "rf->tell() failed (in: %s:%d).",
                            __FUNC__, __LINE__);
                    return(-1);
                }

                overwrite = 0;
            }
        }
    }

    return(0);
}
