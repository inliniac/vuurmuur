/***************************************************************************
 *   Copyright (C) 2003-2017 by Victor Julien                              *
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

#include "main.h"


struct ZonesSection_
{
    /*  first the menus

        they each have their own data struct because they can
        be shown at the same time, only hosts and groups share
        the data struct
    */

    /* zones */
    WINDOW  *win;
    PANEL   *panel[1];
    MENU    *menu;
    ITEM    **zoneitems;
    size_t  zone_n;

    ITEM    *z_top,
            *z_bot;
    PANEL   *z_panel_top[1];
    PANEL   *z_panel_bot[1];
    WINDOW  *z_win_top;
    WINDOW  *z_win_bot;

    int z_yle;  /**< window y lower edge */
    int z_xre;  /**< window x right edge */

    /* networks */
    WINDOW  *n_win;
    PANEL   *n_panel[1];
    MENU    *n_menu;
    ITEM    **networkitems;
    size_t  network_n;
    struct vrmr_list  network_desc_list;

    ITEM    *n_top,
            *n_bot;
    PANEL   *n_panel_top[1];
    PANEL   *n_panel_bot[1];
    WINDOW  *n_win_top;
    WINDOW  *n_win_bot;

    int n_yle;  /**< window y lower edge */
    int n_xre;  /**< window x right edge */

    /* hosts and groups */
    WINDOW  *h_win;
    PANEL   *h_panel[1];
    MENU    *h_menu;
    ITEM    **hostitems;
    size_t  host_n;
    struct vrmr_list  group_desc_list;

    ITEM    *h_top,
            *h_bot;
    PANEL   *h_panel_top[1];
    PANEL   *h_panel_bot[1];
    WINDOW  *h_win_top;
    WINDOW  *h_win_bot;

    int h_yle;  /**< window y lower edge */
    int h_xre;  /**< window x right edge */

    /* edit a zone/network/host/group */
    struct EditZone_
    {
        PANEL   *panel[1];
        WINDOW  *win;
        FIELD   **fields;
        FORM    *form;
        size_t  n_fields;
    } EditZone;

    /* edit zone interfaces */
    struct EditZoneInt_
    {
        PANEL   *panel[1];
        WINDOW  *win;
        MENU    *menu;
        ITEM    **items;
        size_t  n_items;

        ITEM    *top,
                *bot;
        PANEL   *panel_top[1];
        PANEL   *panel_bot[1];
        WINDOW  *win_top;
        WINDOW  *win_bot;

    } EditZoneInt;

    /* edit zone groups */
    struct EditZoneGrp_
    {
        PANEL   *panel[1];
        WINDOW  *win;
        MENU    *menu;
        ITEM    **items;
        size_t  n_items;

        ITEM    *top,
                *bot;
        PANEL   *panel_top[1];
        PANEL   *panel_bot[1];
        WINDOW  *win_top;
        WINDOW  *win_bot;

    } EditZoneGrp;

    char comment[512];

} ZonesSection;


/*
    prototypes
*/
static int zones_section_menu_hosts_init(const int, struct vrmr_ctx *, struct vrmr_zones *, char *, char *);

static int zones_section_menu_groups(const int, struct vrmr_ctx *, struct vrmr_zones *, struct vrmr_rules *, struct vrmr_blocklist *, char *, char *, struct vrmr_regex *);

static int zones_section_menu_networks_init(const int, struct vrmr_zones *, char *);
static int zones_section_menu_networks(const int, struct vrmr_ctx *, struct vrmr_zones *, struct vrmr_interfaces *, struct vrmr_rules *, struct vrmr_blocklist *, char *, struct vrmr_regex *);


static int edit_zone_host_init(const int, struct vrmr_ctx *, char *, int, int, int, int, struct vrmr_zone *);
static int edit_zone_host_destroy(void);
static int edit_zone_host_save(const int, struct vrmr_ctx *, struct vrmr_zone *, struct vrmr_regex *);
static int edit_zone_host(const int, struct vrmr_ctx *, struct vrmr_zones *, char *, struct vrmr_regex *);

static int edit_zone_group_members_init(const int, struct vrmr_ctx *, struct vrmr_zones *, struct vrmr_zone *);
static int edit_zone_group_members(const int, struct vrmr_ctx *, struct vrmr_zones *, struct vrmr_zone *);
static int edit_zone_group_init(const int, struct vrmr_ctx *, struct vrmr_zones *, char *, struct vrmr_zone *);
static int edit_zone_group_save(const int, struct vrmr_ctx *, struct vrmr_zone *);
static int edit_zone_group(const int, struct vrmr_ctx *, struct vrmr_zones *, char *);

static int edit_zone_network_init(const int, struct vrmr_ctx *, struct vrmr_zones *, char *, int, int, int, int, struct vrmr_zone *);
static int edit_zone_network(const int, struct vrmr_ctx *, struct vrmr_zones *, struct vrmr_interfaces *, char *);

static int edit_zone_zone_init(const int, struct vrmr_ctx *, struct vrmr_zones *, char *, int, int, int, int, struct vrmr_zone *);
static int edit_zone_zone(const int debuglvl, struct vrmr_ctx *, struct vrmr_zones *zones, char *name);

static int zones_section_init(const int, struct vrmr_zones *);
static int zones_section_destroy(void);

static int zones_blocklist_init(const int, struct vrmr_blocklist *);
static int zones_blocklist_destroy(void);


/*
    functions
*/


struct
{
    FIELD   *activefld,
            *activelabelfld,

            *ipaddressfld,
            *ipaddresslabelfld,

            *ip6addressfld,
            *ip6addresslabelfld,

            *macaddressfld,
            *macaddresslabelfld,

            *commentfld,
            *commentlabelfld,

            *warningfld;    /* field for the "warning no interfaces" message */

} HostSec;


static int
edit_zone_host_init(const int debuglvl, struct vrmr_ctx *vctx, char *name, int height, int width, int starty, int startx, struct vrmr_zone *zone_ptr)
{
    int     rows,
            cols,
            comment_y = 0,  /* for the dimentions of */
            comment_x = 0;  /* the comment field */
    unsigned int field_num = 0;
    size_t  i = 0;

    /* safety */
    if(!zone_ptr)
    {
        vrmr_error(-1, VR_INTERR, "parameter problem (in: %s:%d).",
                                __FUNC__, __LINE__);
        return(-1);
    }

    /* alloc fields */
    ZonesSection.EditZone.n_fields = 11;
    if(!(ZonesSection.EditZone.fields = (FIELD **)calloc(ZonesSection.EditZone.n_fields + 1, sizeof(FIELD *))))
    {
        vrmr_error(-1, VR_ERR, gettext("calloc failed: %s (in: %s:%d)."),
                                strerror(errno), __FUNC__, __LINE__);
        return(-1);
    }

    /* preload the active field */
    HostSec.activelabelfld = (ZonesSection.EditZone.fields[field_num++] = new_field(1, 16, 2, 0, 0, 0));
    set_field_buffer_wrap(debuglvl, HostSec.activelabelfld, 0, STR_CACTIVE);
    field_opts_off(HostSec.activelabelfld, O_AUTOSKIP | O_ACTIVE);

    HostSec.activefld = (ZonesSection.EditZone.fields[field_num++] = new_field(1, 3, 3, 1, 0, 0));
    set_field_buffer_wrap(debuglvl, HostSec.activefld, 0, zone_ptr->active ? STR_YES : STR_NO);

    HostSec.ipaddresslabelfld = (ZonesSection.EditZone.fields[field_num++] = new_field(1, 16, 2, 8, 0, 0));
    set_field_buffer_wrap(debuglvl, HostSec.ipaddresslabelfld, 0, STR_IPADDRESS);
    field_opts_off(HostSec.ipaddresslabelfld, O_AUTOSKIP | O_ACTIVE);

    HostSec.ipaddressfld = (ZonesSection.EditZone.fields[field_num++] = new_field(1, 16, 3, 9, 0, 0));
    set_field_type(HostSec.ipaddressfld, TYPE_IPV4);
    set_field_buffer_wrap(debuglvl, HostSec.ipaddressfld, 0, zone_ptr->ipv4.ipaddress);
    field_opts_on(HostSec.ipaddressfld, O_BLANK);

    HostSec.ip6addresslabelfld = (ZonesSection.EditZone.fields[field_num++] = new_field(1, 16, 4, 8, 0, 0));
#ifdef IPV6_ENABLED
    set_field_buffer_wrap(debuglvl, HostSec.ip6addresslabelfld, 0, STR_IP6ADDRESS);
#endif
    field_opts_off(HostSec.ip6addresslabelfld, O_AUTOSKIP | O_ACTIVE);

    HostSec.ip6addressfld = (ZonesSection.EditZone.fields[field_num++] = new_field(1, VRMR_MAX_IPV6_ADDR_LEN, 5, 9, 0, 0));
    //set_field_type(HostSec.ipaddressfld, TYPE_IPV4);
#ifdef IPV6_ENABLED
    set_field_buffer_wrap(debuglvl, HostSec.ip6addressfld, 0, zone_ptr->ipv6.ip6);
#endif
    field_opts_on(HostSec.ip6addressfld, O_BLANK);

    HostSec.macaddresslabelfld = (ZonesSection.EditZone.fields[field_num++] = new_field(1, 16, 6, 8, 0, 0));
    set_field_buffer_wrap(debuglvl, HostSec.macaddresslabelfld, 0, STR_MACADDRESS);
    field_opts_off(HostSec.macaddresslabelfld, O_AUTOSKIP | O_ACTIVE);

    HostSec.macaddressfld = (ZonesSection.EditZone.fields[field_num++] = new_field(1, 19, 7, 9, 0, 0));
    set_field_buffer_wrap(debuglvl, HostSec.macaddressfld, 0, zone_ptr->mac);
    field_opts_on(HostSec.macaddressfld, O_BLANK);

    /* comment label */
    HostSec.commentlabelfld = (ZonesSection.EditZone.fields[field_num++] = new_field(1, 16, 10, 0, 0, 0));
    set_field_buffer_wrap(debuglvl, HostSec.commentlabelfld, 0, gettext("Comment"));
    field_opts_off(HostSec.commentlabelfld, O_AUTOSKIP | O_ACTIVE);

    /* comment field size */
    comment_y = 5;
    comment_x = 48;
    /* create the comment field */
    HostSec.commentfld = (ZonesSection.EditZone.fields[field_num++] = new_field(comment_y, comment_x, 11, 1, 0, 0));

    /* load the comment from the backend */
    if (vctx->zf->ask(debuglvl, vctx->zone_backend, zone_ptr->name, "COMMENT", ZonesSection.comment, sizeof(ZonesSection.comment), VRMR_TYPE_HOST, 0) < 0)
        vrmr_error(-1, VR_ERR, gettext("error while loading the comment."));

    set_field_buffer_wrap(debuglvl, HostSec.commentfld, 0, ZonesSection.comment);


    HostSec.warningfld = (ZonesSection.EditZone.fields[field_num++] = new_field(1, 48, 15, 1, 0, 0));
    field_opts_off(HostSec.warningfld, O_AUTOSKIP | O_ACTIVE | O_VISIBLE);
    set_field_just(HostSec.warningfld, JUSTIFY_CENTER);

    if (field_num != ZonesSection.EditZone.n_fields) {
        vrmr_error(-1, VR_INTERR, "parameter problem (in: %s:%d).",
                                __FUNC__, __LINE__);
        return(-1);
    }

    ZonesSection.EditZone.fields[ZonesSection.EditZone.n_fields] = NULL;

    /* create the window & panel */
    if(!(ZonesSection.EditZone.win = create_newwin(height, width, starty, startx, gettext("Edit Zone: Host"), vccnf.color_win)))
    {
        vrmr_error(-1, VR_ERR, gettext("creating window failed."));
        return(-1);
    }
    if(!(ZonesSection.EditZone.panel[0] = new_panel(ZonesSection.EditZone.win)))
    {
        vrmr_error(-1, VR_ERR, gettext("creating panel failed."));
        return(-1);
    }
    keypad(ZonesSection.EditZone.win, TRUE);

    /* set field options */
    for(i = 0; i < ZonesSection.EditZone.n_fields; i++)
    {
        set_field_back(ZonesSection.EditZone.fields[i], vccnf.color_win_rev);
        field_opts_off(ZonesSection.EditZone.fields[i], O_AUTOSKIP);
        set_field_status(ZonesSection.EditZone.fields[i], FALSE);
    }

    set_field_back(HostSec.activelabelfld, vccnf.color_win);
    set_field_back(HostSec.ipaddresslabelfld, vccnf.color_win);
    set_field_back(HostSec.ip6addresslabelfld, vccnf.color_win);
    set_field_back(HostSec.macaddresslabelfld, vccnf.color_win);
    set_field_back(HostSec.commentlabelfld, vccnf.color_win);

#ifndef IPV6_ENABLED
    set_field_back(HostSec.ip6addresslabelfld, vccnf.color_win | A_BOLD);
    field_opts_on(HostSec.ip6addresslabelfld, O_AUTOSKIP);
    field_opts_off(HostSec.ip6addresslabelfld, O_ACTIVE);

    set_field_back(HostSec.ip6addressfld, vccnf.color_win | A_BOLD);
    field_opts_on(HostSec.ip6addressfld, O_AUTOSKIP);
    field_opts_off(HostSec.ip6addressfld, O_ACTIVE);
#endif
    set_field_back(HostSec.warningfld, vccnf.color_win);
    set_field_fore(HostSec.warningfld, vccnf.color_win_warn|A_BOLD);

    /* Create the form and post it */
    if(!(ZonesSection.EditZone.form = new_form(ZonesSection.EditZone.fields)))
    {
        vrmr_error(-1, VR_ERR, gettext("creating form failed."));
        return(-1);
    }
    scale_form(ZonesSection.EditZone.form, &rows, &cols);
    set_form_win(ZonesSection.EditZone.form, ZonesSection.EditZone.win);
    set_form_sub(ZonesSection.EditZone.form, derwin(ZonesSection.EditZone.win, rows, cols, 1, 2));
    post_form(ZonesSection.EditZone.form);

    /* print labels */
    mvwprintw(ZonesSection.EditZone.win, 1, 2, "%s: %s", gettext("Name"), zone_ptr->name);

    /* draw */
    wrefresh(ZonesSection.EditZone.win);
    update_panels();
    doupdate();
    return(0);
}


static int
edit_zone_host_destroy(void)
{
    int     retval = 0;
    size_t  i = 0;

    /* unpost form and free the memory */
    unpost_form(ZonesSection.EditZone.form);
    free_form(ZonesSection.EditZone.form);

    for(i=0;i<ZonesSection.EditZone.n_fields;i++)
    {
        free_field(ZonesSection.EditZone.fields[i]);
    }
    free(ZonesSection.EditZone.fields);

    del_panel(ZonesSection.EditZone.panel[0]);
    destroy_win(ZonesSection.EditZone.win);

    update_panels();
    doupdate();

    /* clear comment */
    strcpy(ZonesSection.comment, "");
    return(retval);
}


static int
edit_zone_host_save(const int debuglvl, struct vrmr_ctx *vctx, struct vrmr_zone *zone_ptr, struct vrmr_regex *reg)
{
    int     active = 0;
    char    ipaddress[16] = "",
            mac[19] = "";
#ifdef IPV6_ENABLED
    char    ip6address[VRMR_MAX_IPV6_ADDR_LEN] = "";
#endif
    size_t  i = 0;

    /* safety */
    if(zone_ptr == NULL || reg == NULL)
    {
        vrmr_error(-1, VR_INTERR, "parameter problem (in: %s).", __FUNC__);
        return(-1);
    }

    /* check for changed fields */
    for(i = 0; i < ZonesSection.EditZone.n_fields; i++)
    {
        /* field changed! */
        if(field_status(ZonesSection.EditZone.fields[i]) == TRUE)
        {
            /* active field */
            if(ZonesSection.EditZone.fields[i] == HostSec.activefld)
            {
                /* for the log and incase something goes wrong */
                active = zone_ptr->active;

                if(strncasecmp(field_buffer(ZonesSection.EditZone.fields[i], 0), STR_YES, StrLen(STR_YES)) == 0)
                    zone_ptr->active = 1;
                else
                    zone_ptr->active = 0;

                /* save to the backend */
                if (vctx->zf->tell(debuglvl, vctx->zone_backend, zone_ptr->name, "ACTIVE", zone_ptr->active ? "Yes" : "No", 1, VRMR_TYPE_HOST) < 0)
                {
                    vrmr_error(-1, VR_ERR, gettext("saving to backend failed (in: %s:%d)."), __FUNC__, __LINE__);
                    return(-1);
                }

                /* for the log */
                vrmr_audit("%s '%s' %s: %s %s '%s' (%s: '%s').",
                    STR_HOST, zone_ptr->name, STR_HAS_BEEN_CHANGED, STR_ACTIVE,
                    STR_IS_NOW_SET_TO, zone_ptr->active ? STR_YES : STR_NO,
                    STR_WAS, active ? STR_YES : STR_NO);

                zone_ptr->status = VRMR_ST_CHANGED;
            }

            /* ipaddress field */
            else if(ZonesSection.EditZone.fields[i] == HostSec.ipaddressfld)
            {
                /* for the log and incase something goes wrong */
                if(strlcpy(ipaddress, zone_ptr->ipv4.ipaddress, sizeof(ipaddress)) >= sizeof(ipaddress))
                {
                    vrmr_error(-1, VR_INTERR, "copying ipaddress failed (in: %s).", __FUNC__);
                    return(-1);
                }

                if(!(copy_field2buf(zone_ptr->ipv4.ipaddress,
                                    field_buffer(ZonesSection.EditZone.fields[i], 0),
                                    sizeof(zone_ptr->ipv4.ipaddress))))
                    return(-1);

                /*  we dont check for invalid ip
                    (check_ip == 0), because this is done
                    by the fieldvalidation

                    also, we first check if the network
                    has the network address and netmask
                    set.
                */
                if( zone_ptr->network_parent->ipv4.network[0] == '\0' ||
                    zone_ptr->network_parent->ipv4.netmask[0] == '\0' ||
                    vrmr_check_ipv4address(debuglvl, zone_ptr->network_parent->ipv4.network,
                        zone_ptr->network_parent->ipv4.netmask, zone_ptr->ipv4.ipaddress, 0))
                {
                    if (vctx->zf->tell(debuglvl, vctx->zone_backend, zone_ptr->name, "IPADDRESS", zone_ptr->ipv4.ipaddress, 1, VRMR_TYPE_HOST) < 0)
                    {
                        vrmr_error(-1, VR_ERR, gettext("saving to backend failed (in: %s:%d)."), __FUNC__, __LINE__);
                        return(-1);
                    }

                    /* audit log */
                    vrmr_audit("%s '%s' %s: %s %s '%s' (%s: '%s').",
                        STR_HOST, zone_ptr->name, STR_HAS_BEEN_CHANGED, STR_IPADDRESS,
                        STR_IS_NOW_SET_TO, zone_ptr->ipv4.ipaddress,
                        STR_WAS, ipaddress);

                    zone_ptr->status = VRMR_ST_CHANGED;
                }
                else
                {
                    vrmr_error(-1, VR_ERR, gettext("ipaddress '%s' doesn't belong in the network %s/%s."), zone_ptr->ipv4.ipaddress, zone_ptr->network_parent->ipv4.network, zone_ptr->network_parent->ipv4.netmask);

                    /* copy the old ipaddress back */
                    if(strlcpy(zone_ptr->ipv4.ipaddress, ipaddress, sizeof(zone_ptr->ipv4.ipaddress)) >= sizeof(zone_ptr->ipv4.ipaddress))
                    {
                        vrmr_error(-1, VR_INTERR, "copying ipaddress failed (in: %s).", __FUNC__);
                        return(-1);
                    }

                    /* error so the user can edit this host again */
                    return(-1);
                }
            }

#ifdef IPV6_ENABLED
            /* ip6address field */
            else if(ZonesSection.EditZone.fields[i] == HostSec.ip6addressfld)
            {
                /* for the log and incase something goes wrong */
                if(strlcpy(ip6address, zone_ptr->ipv6.ip6, sizeof(ip6address)) >= sizeof(ip6address))
                {
                    vrmr_error(-1, VR_INTERR, "copying ipaddress failed (in: %s).", __FUNC__);
                    return(-1);
                }

                if(!(copy_field2buf(zone_ptr->ipv6.ip6,
                                    field_buffer(ZonesSection.EditZone.fields[i], 0),
                                    sizeof(zone_ptr->ipv6.ip6))))
                    return(-1);

                /*  we dont check for invalid ip
                    (check_ip == 0), because this is done
                    by the fieldvalidation

                    also, we first check if the network
                    has the network address and netmask
                    set.
                */
#if 0
                if( zone_ptr->network_parent->ipv4.network[0] == '\0' ||
                    zone_ptr->network_parent->ipv4.netmask[0] == '\0' ||
                    vrmr_check_ipv4address(debuglvl, zone_ptr->network_parent->ipv4.network,
                        zone_ptr->network_parent->ipv4.netmask, zone_ptr->ipv4.ipaddress, 0))
                {
#endif
                    if (vctx->zf->tell(debuglvl, vctx->zone_backend, zone_ptr->name, "IPV6ADDRESS", zone_ptr->ipv6.ip6, 1, VRMR_TYPE_HOST) < 0)
                    {
                        vrmr_error(-1, VR_ERR, gettext("saving to backend failed (in: %s:%d)."), __FUNC__, __LINE__);
                        return(-1);
                    }

                    /* audit log */
                    vrmr_audit("%s '%s' %s: %s %s '%s' (%s: '%s').",
                        STR_HOST, zone_ptr->name, STR_HAS_BEEN_CHANGED, STR_IP6ADDRESS,
                        STR_IS_NOW_SET_TO, zone_ptr->ipv6.ip6,
                        STR_WAS, ip6address);

                    zone_ptr->status = VRMR_ST_CHANGED;
//                }
#if 0
                else
                {
                    vrmr_error(-1, VR_ERR, gettext("ipaddress '%s' doesn't belong in the network %s/%s."), zone_ptr->ipv4.ipaddress, zone_ptr->network_parent->ipv4.network, zone_ptr->network_parent->ipv4.netmask);

                    /* copy the old ipaddress back */
                    if(strlcpy(zone_ptr->ipv4.ipaddress, ipaddress, sizeof(zone_ptr->ipv4.ipaddress)) >= sizeof(zone_ptr->ipv4.ipaddress))
                    {
                        vrmr_error(-1, VR_INTERR, "copying ipaddress failed (in: %s).", __FUNC__);
                        return(-1);
                    }

                    /* error so the user can edit this host again */
                    return(-1);
                }
#endif
            }
#endif
            /* MAC field */
            else if(ZonesSection.EditZone.fields[i] == HostSec.macaddressfld)
            {
                /* for the log and incase something goes wrong */
                if(strlcpy(mac, zone_ptr->mac, sizeof(mac)) >= sizeof(mac))
                {
                    vrmr_error(-1, VR_INTERR, "copying macaddress failed (in: %s).", __FUNC__);
                    return(-1);
                }

                if(!(copy_field2buf(zone_ptr->mac,
                                    field_buffer(ZonesSection.EditZone.fields[i], 0),
                                    sizeof(zone_ptr->mac))))
                    return(-1);

                if(zone_ptr->mac[0] != '\0')
                {
                    /* test against the regex */
                    if(regexec(reg->macaddr, zone_ptr->mac, 0, NULL, 0) != 0)
                    {
                        vrmr_error(-1, VR_ERR, gettext("MAC Address '%s' is invalid."), zone_ptr->mac);

                        /* for the log and incase something goes wrong */
                        if(strlcpy(zone_ptr->mac, mac, sizeof(zone_ptr->mac)) >= sizeof(zone_ptr->mac))
                        {
                            vrmr_error(-1, VR_INTERR, "copying macaddress failed (in: %s).", __FUNC__);
                            return(-1);
                        }

                        /* error so the user can edit this host again */
                        return(-1);
                    }
                }

                /* save to backend */
                if (vctx->zf->tell(debuglvl, vctx->zone_backend, zone_ptr->name, "MAC", zone_ptr->mac, 1, VRMR_TYPE_HOST) < 0)
                {
                    vrmr_error(-1, VR_ERR, gettext("saving to backend failed (in: %s:%d)."), __FUNC__, __LINE__);
                    return(-1);
                }

                /* audit log */
                vrmr_audit("%s '%s' %s: %s %s '%s' (%s: '%s').",
                    STR_HOST, zone_ptr->name, STR_HAS_BEEN_CHANGED, STR_MACADDRESS,
                    STR_IS_NOW_SET_TO, zone_ptr->mac, STR_WAS, mac);

                zone_ptr->status = VRMR_ST_CHANGED;
            }

            /* comment field */
            else if(ZonesSection.EditZone.fields[i] == HostSec.commentfld)
            {
                if (vctx->zf->tell(debuglvl, vctx->zone_backend, zone_ptr->name, "COMMENT", field_buffer(ZonesSection.EditZone.fields[i], 0), 1, VRMR_TYPE_HOST) < 0)
                {
                    vrmr_error(-1, VR_ERR, gettext("saving to backend failed (in: %s:%d)."), __FUNC__, __LINE__);
                    return(-1);
                }

                /* example: "host 'pc1.local.lan' has been changed: the comment was changed." */
                vrmr_audit("%s '%s' %s: %s.",
                    STR_HOST, zone_ptr->name, STR_HAS_BEEN_CHANGED, STR_COMMENT_CHANGED);

            }
            else
            {
                vrmr_error(-1, VR_INTERR, "unknown field (in: %s:%d).", __FUNC__, __LINE__);
                return(-1);
            }
        }
    }

    if(zone_ptr->ipv4.ipaddress[0] == '\0')
    {
        vrmr_warning(VR_WARN, gettext("empty IP address. No rules will be created for this host."));
    }

    return(0);
}


/*  edit_zone_host

    Returncodes:
         0: ok
        -1: error
*/
int
edit_zone_host(const int debuglvl, struct vrmr_ctx *vctx, struct vrmr_zones *zones, char *name, struct vrmr_regex *reg)
{
    int                 ch,
                        not_defined = 0,
                        quit = 0,
                        retval = 0;
    struct vrmr_zone    *zone_ptr = NULL;
    int                 height,
                        width,
                        startx,
                        starty;
    FIELD               *cur = NULL,
                        *prev = NULL;
    /* top menu */
    char                *key_choices[] =    {   "F12",
                                                "F10"};
    int                 key_choices_n = 2;
    char                *cmd_choices[] =    {   gettext("help"),
                                                gettext("back")};
    int                 cmd_choices_n = 2;

    /* safety */
    if(name == NULL || zones == NULL || reg == NULL)
    {
        vrmr_error(-1, VR_INTERR, "parameter problem (in: %s:%d).",
                                __FUNC__, __LINE__);
        return(-1);
    }

    height = 18;
    width = 54;
    /* place on the same y as zones list */
    VrWinGetOffset(-1, -1, height, width, ZonesSection.h_yle + 1, ZonesSection.n_xre + 1, &starty, &startx);

    /* search the host in memory */
    if(!(zone_ptr = vrmr_search_zonedata(debuglvl, zones, name)))
    {
        vrmr_error(-1, VR_INTERR, "host not found (in: %s:%d).",
                                __FUNC__, __LINE__);
        return(-1);
    }

    /* init */
    if (edit_zone_host_init(debuglvl, vctx, name, height, width, starty, startx, zone_ptr) < 0)
    {
        vrmr_error(-1, VR_INTERR, "setting up the host window failed (in: %s:%d).",
                                __FUNC__, __LINE__);
        return(-1);
    }

    if(!(cur = current_field(ZonesSection.EditZone.form)))
    {
        vrmr_error(-1, VR_INTERR, "NULL pointer (in: %s:%d).",
                                __FUNC__, __LINE__);
        return(-1);
    }

    if(zone_ptr->active == TRUE && vrmr_zones_active(debuglvl, zone_ptr) == 0)
    {
        set_field_buffer_wrap(debuglvl, HostSec.warningfld, 0, gettext("Note: parent zone/network is inactive."));
        field_opts_on(HostSec.warningfld, O_VISIBLE);
        set_field_status(HostSec.warningfld, FALSE);
    }

    draw_top_menu(debuglvl, top_win, gettext("Edit Host"), key_choices_n, key_choices, cmd_choices_n, cmd_choices);

    update_panels();
    doupdate();
    status_print(status_win, "Ready.");

    /* loop through to get user requests */
    while(quit == 0)
    {
        /* draw nice markers */
        draw_field_active_mark(cur, prev, ZonesSection.EditZone.win, ZonesSection.EditZone.form, vccnf.color_win_mark|A_BOLD);

        not_defined = 0;

        /* get user input */
        ch = wgetch(ZonesSection.EditZone.win);

        if(cur == HostSec.commentfld)
        {
            if(nav_field_comment(debuglvl, ZonesSection.EditZone.form, ch) < 0)
                not_defined = 1;
        }
        else if(cur == HostSec.activefld)
        {
            if(nav_field_yesno(debuglvl, ZonesSection.EditZone.form, ch) < 0)
                not_defined = 1;
        }
        else if(cur == HostSec.ipaddressfld ||
                cur == HostSec.ip6addressfld ||
                cur == HostSec.macaddressfld)
        {
            if(nav_field_simpletext(debuglvl, ZonesSection.EditZone.form, ch) < 0)
                not_defined = 1;
        }
        else
        {
            not_defined = 1;
        }

        /* the rest is handled here */
        if(not_defined)
        {
            switch(ch)
            {
                case KEY_DOWN:
                case 10:    // enter
                case 9: // tab
                    form_driver(ZonesSection.EditZone.form, REQ_NEXT_FIELD);
                    form_driver(ZonesSection.EditZone.form, REQ_BEG_LINE);
                    break;

                case KEY_UP:
                    form_driver(ZonesSection.EditZone.form, REQ_PREV_FIELD);
                    form_driver(ZonesSection.EditZone.form, REQ_BEG_LINE);
                    break;

                case 27:
                case KEY_F(10):
                case 'q':
                case 'Q':

                    /* save changes */
                    if (edit_zone_host_save(debuglvl, vctx, zone_ptr, reg) < 0)
                    {
                        if(confirm( gettext("saving host failed."),
                                    gettext("Look at the host again?"),
                                    vccnf.color_win_rev,
                                    vccnf.color_win, 1) == 0)
                            quit = 1;
                    }
                    else
                    {
                        quit = 1;
                    }

                    break;

                case KEY_F(12):
                case 'h':
                case 'H':
                case '?':
                    print_help(debuglvl, ":[VUURMUUR:ZONES:HOST:EDIT]:");
                    break;
            }
        }

        /* before we get the new 'cur', store cur in prev */
        prev = cur;
        if(!(cur = current_field(ZonesSection.EditZone.form)))
        {
            vrmr_error(-1, VR_INTERR, "NULL pointer (in: %s).", __FUNC__);
            return(-1);
        }

        /* now give some help message in the status win */
        if(cur == HostSec.ipaddressfld)
            status_print(status_win, gettext("Please enter an ipaddress (mandatory)."));
        else if(cur == HostSec.macaddressfld)
            status_print(status_win, gettext("Please enter the macaddress (optional)."));
        else if(cur == HostSec.activefld)
            status_print(status_win, gettext("If set to 'No' no rules will be created for it."));
        else if(cur == HostSec.commentfld)
            status_print(status_win, gettext("Enter a optional comment."));

        /* check against the current 'active' value */
        if(strncasecmp(field_buffer(HostSec.activefld, 0), STR_YES, StrLen(STR_YES)) == 0 &&
            vrmr_zones_active(debuglvl, zone_ptr) == 0)
        {
            set_field_buffer_wrap(debuglvl, HostSec.warningfld, 0, gettext("Note: parent zone/network is inactive."));
            field_opts_on(HostSec.warningfld, O_VISIBLE);
            set_field_status(HostSec.warningfld, FALSE);
        }
        /* and clear it again */
        else
        {
            /* hide no int warning */
            field_opts_off(HostSec.warningfld, O_VISIBLE);
        }


        /* draw and set cursor */
        wrefresh(ZonesSection.EditZone.win);
        pos_form_cursor(ZonesSection.EditZone.form);
    }

    /* cleanup */
    if(edit_zone_host_destroy() < 0)
        retval = -1;

    status_print(status_win, gettext("Ready."));
    return(retval);
}


static int
zones_section_menu_hosts_init(const int debuglvl, struct vrmr_ctx *vctx,
        struct vrmr_zones *zones, char *zonename, char *networkname)
{
    int                 retval=0;
    struct vrmr_zone    *zone_ptr = NULL;
    int                 height = 0,
                        width = 0,
                        startx = 0,
                        starty = 0,
                        maxy = 0,
                        result = 0;
    struct vrmr_list_node         *d_node = NULL;
    size_t              i = 0;

    /* safety */
    if(zonename == NULL || zones == NULL || networkname == NULL)
    {
        vrmr_error(-1, VR_INTERR, "parameter problem (in: %s).", __FUNC__);
        return(-1);
    }

    /* get the screensize */
    maxy = getmaxy(stdscr);

    /* count how many hosts there are */
    for(ZonesSection.host_n = 0, d_node = zones->list.top; d_node ; d_node = d_node->next)
    {
        if(!(zone_ptr = d_node->data))
        {
            vrmr_error(-1, VR_INTERR, "NULL pointer (in: %s).", __FUNC__);
            return(-1);
        }

        /* only count hosts inside the network and zone */
        if(zone_ptr->type == VRMR_TYPE_HOST)
        {
            if( strcmp(zone_ptr->zone_name, zonename) == 0 &&
                strcmp(zone_ptr->network_name, networkname) == 0)
            {
                ZonesSection.host_n++;
            }
        }
    }

    i = ZonesSection.host_n - 1;

    /* allow the menu items */
    if(!(ZonesSection.hostitems = (ITEM **)calloc(ZonesSection.host_n + 1, sizeof(ITEM *))))
    {
        vrmr_error(-1, VR_ERR, gettext("calloc failed: %s (in: %s:%d)."), strerror(errno), __func__, __LINE__);
        return(-1);
    }

    /* create the menu items */
    for(d_node = zones->list.bot; d_node ; d_node = d_node->prev)
    {
        if(!(zone_ptr = d_node->data))
        {
            vrmr_error(-1, VR_INTERR, "NULL pointer (in: %s).", __FUNC__);
            return(-1);
        }

        /* only add hosts inside the network and zone */
        if(zone_ptr->type == VRMR_TYPE_HOST)
        {
            if( strcmp(zone_ptr->zone_name, zonename) == 0 &&
                strcmp(zone_ptr->network_name, networkname) == 0)
            {
                if(!(ZonesSection.hostitems[i] = new_item(zone_ptr->host_name, zone_ptr->ipv4.ipaddress)))
                {
                    vrmr_error(-1, VR_INTERR, "adding new item to host menu failed (in: %s).", __FUNC__);
                    return(-1);
                }

                i--;
            }
        }
    }
    /* terminate the items */
    ZonesSection.hostitems[ZonesSection.host_n] = (ITEM *)NULL;

    if(ZonesSection.host_n > 0)
    {
        ZonesSection.h_top = ZonesSection.hostitems[0];
        ZonesSection.h_bot = ZonesSection.hostitems[ZonesSection.host_n - 1];
    }
    else
    {
        ZonesSection.h_top = NULL;
        ZonesSection.h_bot = NULL;
    }

    /* now create the menu */
    if(!(ZonesSection.h_menu = new_menu((ITEM **)ZonesSection.hostitems)))
    {
        vrmr_error(-1, VR_INTERR, "creating the host menu failed (in: %s).", __FUNC__);
        return(-1);
    }

    /* now set the size of the window */
    height = (int)(ZonesSection.host_n + 8);
    width  = VRMR_MAX_HOST + 18 + 2;
    
    if (height > maxy - 8)
    {
        height = maxy - 8;
    }
    
    /* place on the same y as zones list */
    VrWinGetOffset(-1, -1, height, width, 4, ZonesSection.n_xre + 1, &starty, &startx);
    ZonesSection.h_yle = starty + height;
    ZonesSection.h_xre = startx + width;

    if(!(ZonesSection.h_win = newwin(height, width, starty, startx)))
    {
        vrmr_error(-1, VR_INTERR, "creating the host win failed (in: %s).", __FUNC__);
        return(-1);
    }
    wbkgd(ZonesSection.h_win, vccnf.color_win);
    keypad(ZonesSection.h_win, TRUE);
    box(ZonesSection.h_win, 0, 0);
    print_in_middle(ZonesSection.h_win, 1, 0, width, gettext("Hosts"), vccnf.color_win);
    wrefresh(ZonesSection.h_win);

    if(!(ZonesSection.h_panel[0] = new_panel(ZonesSection.h_win)))
    {
        vrmr_error(-1, VR_INTERR, "creating the host panel failed (in: %s).", __FUNC__);
        return(-1);
    }

    set_menu_win(ZonesSection.h_menu, ZonesSection.h_win);
    set_menu_sub(ZonesSection.h_menu, derwin(ZonesSection.h_win, height-7, width-2, 3, 1));

    set_menu_format(ZonesSection.h_menu, height-8, 1);

    mvwaddch(ZonesSection.h_win, 2, 0, ACS_LTEE);
    mvwhline(ZonesSection.h_win, 2, 1, ACS_HLINE, width-2);
    mvwaddch(ZonesSection.h_win, 2, width-1, ACS_RTEE);

    set_menu_back(ZonesSection.h_menu, vccnf.color_win);
    set_menu_fore(ZonesSection.h_menu, vccnf.color_win_rev);

    result = post_menu(ZonesSection.h_menu);
    if(result != E_OK && result != E_NOT_CONNECTED)
    {
        vrmr_error(-1, VR_INTERR, "creating the host menu failed (in: %s).", __FUNC__);
        return(-1);
    }

    mvwaddch(ZonesSection.h_win, height-5, 0, ACS_LTEE);
    mvwhline(ZonesSection.h_win, height-5, 1, ACS_HLINE, width-2);
    mvwaddch(ZonesSection.h_win, height-5, width-1, ACS_RTEE);

    mvwprintw(ZonesSection.h_win, height-4, 1, "<RET> %s", STR_EDIT);
    mvwprintw(ZonesSection.h_win, height-3, 1, "<INS> %s", STR_NEW);
    mvwprintw(ZonesSection.h_win, height-2, 1, "<DEL> %s", STR_REMOVE);

    /* create the top and bottom fields */
    if(!(ZonesSection.h_win_top = newwin(1, 6, starty + 2, startx + width - 8)))
    {
        vrmr_error(-1, VR_ERR, gettext("creating window failed."));
        return(-1);
    }
    wbkgd(ZonesSection.h_win_top, vccnf.color_win);
    ZonesSection.h_panel_top[0] = new_panel(ZonesSection.h_win_top);
    /* TRANSLATORS: max 4 chars */
    wprintw(ZonesSection.h_win_top, "(%s)", gettext("more"));
    hide_panel(ZonesSection.h_panel_top[0]);

    if(!(ZonesSection.h_win_bot = newwin(1, 6, starty + height - 5, startx + width - 8)))
    {
        vrmr_error(-1, VR_ERR, gettext("creating window failed."));
        return(-1);
    }
    wbkgd(ZonesSection.h_win_bot, vccnf.color_win);
    ZonesSection.h_panel_bot[0] = new_panel(ZonesSection.h_win_bot);
    /* TRANSLATORS: max 4 chars */
    wprintw(ZonesSection.h_win_bot, "(%s)", gettext("more"));
    hide_panel(ZonesSection.h_panel_bot[0]);

    update_panels();
    doupdate();

    return(retval);
}


static int
zones_section_menu_hosts_destroy(void)
{
    int     retval = 0;
    size_t  i = 0;

    unpost_menu(ZonesSection.h_menu);
    free_menu(ZonesSection.h_menu);
    for(i = 0; i < ZonesSection.host_n; ++i)
        free_item(ZonesSection.hostitems[i]);

    free(ZonesSection.hostitems);

    del_panel(ZonesSection.h_panel[0]);

    destroy_win(ZonesSection.h_win);

    del_panel(ZonesSection.h_panel_top[0]);
    destroy_win(ZonesSection.h_win_top);
    del_panel(ZonesSection.h_panel_bot[0]);
    destroy_win(ZonesSection.h_win_bot);

    return(retval);
}


/* rename a host or a group */
static int
zones_rename_host_group(const int debuglvl, struct vrmr_ctx *vctx,
        struct vrmr_zones *zones, struct vrmr_rules *rules,
        struct vrmr_blocklist *blocklist, char *cur_name_ptr,
        char *new_name_ptr, int type, struct vrmr_regex *reg)
{
    int                 result = 0;
    struct vrmr_zone    *zone_ptr = NULL,
                        *member_ptr = NULL;
    struct vrmr_rule    *rule_ptr = NULL;
    struct vrmr_list_node         *d_node = NULL,
                        *grp_d_node = NULL;
    char                rules_changed = 0,
                        blocklist_changed = 0,
                        group_changed = 0;
    char                old_host_name[VRMR_VRMR_MAX_HOST_NET_ZONE] = "",
                        new_host[VRMR_MAX_HOST] = "",
                        new_net[VRMR_MAX_NETWORK] = "",
                        vrmr_new_zone[VRMR_MAX_ZONE] = "";
    char                *blocklist_item = NULL,
                        *new_blocklist_item = NULL;
    size_t              size = 0;

    /* safety */
    if( cur_name_ptr == NULL || new_name_ptr == NULL || zones == NULL ||
        rules == NULL || reg == NULL || blocklist == NULL)
    {
        vrmr_error(-1, VR_INTERR, "parameter problem (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    if(type != VRMR_TYPE_HOST && type != VRMR_TYPE_GROUP)
    {
        vrmr_error(-1, VR_INTERR, "this function can only be used to rename a group or a host (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    /* validate and split the new name */
    if(vrmr_validate_zonename(debuglvl, new_name_ptr, 0, vrmr_new_zone, new_net, new_host, reg->zonename, VRMR_VERBOSE) != 0)
    {
        vrmr_error(-1, VR_INTERR, "invalid name '%s' (in: %s:%d).", new_name_ptr, __FUNC__, __LINE__);
        return(-1);
    }
    if(debuglvl >= HIGH)
        vrmr_debug(__FUNC__, "new_name_ptr: '%s': host/group '%s', net '%s', zone '%s'.", new_name_ptr, new_host, new_net, vrmr_new_zone);

    /* store the old name */
    if(strlcpy(old_host_name, cur_name_ptr, sizeof(old_host_name)) >= sizeof(old_host_name))
    {
        vrmr_error(-1, VR_INTERR, "name overflow (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }
    if(debuglvl >= HIGH)
        vrmr_debug(__FUNC__, "going to rename host/group old_host_name:'%s' to new_name_ptr:'%s'.", old_host_name, new_name_ptr);

    /* rename in the backend */
    result = vctx->zf->rename(debuglvl, vctx->zone_backend, old_host_name, new_name_ptr, type);
    if(result != 0)
    {
        return(-1);
    }

    /* search the zone in the list */
    if(!(zone_ptr = vrmr_search_zonedata(debuglvl, zones, old_host_name)))
    {
        vrmr_error(-1, VR_INTERR, "host/group not found in the list (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    if(strlcpy(zone_ptr->name, new_name_ptr, sizeof(zone_ptr->name)) >= sizeof(zone_ptr->name))
    {
        vrmr_error(-1, VR_INTERR, "name overflow (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }
    if(strlcpy(zone_ptr->host_name, new_host, sizeof(zone_ptr->host_name)) >= sizeof(zone_ptr->host_name))
    {
        vrmr_error(-1, VR_INTERR, "name overflow (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }
    zone_ptr = NULL;

    /* update rules */
    for(d_node = rules->list.top; d_node; d_node = d_node->next)
    {
        rule_ptr = d_node->data;
        if(rule_ptr == NULL)
        {
            vrmr_error(-1, VR_INTERR, "NULL pointer (in: %s:%d).", __FUNC__, __LINE__);
            return(-1);
        }
        if(debuglvl >= HIGH)
            vrmr_debug(__FUNC__, "from: '%s', to: '%s'.", rule_ptr->from, rule_ptr->to);

        /* check the fromname */
        if(strcmp(rule_ptr->from, old_host_name) == 0)
        {
            if(debuglvl >= HIGH)
                vrmr_debug(__FUNC__, "found in a rule (was looking for old_host_name:'%s', found rule_ptr->from:'%s').", old_host_name, rule_ptr->from);

            /* set the new name to the rules */
            (void)strlcpy(rule_ptr->from, new_name_ptr,
                    sizeof(rule_ptr->from));
            rules_changed = 1;
        }
        /* do the same thing for to */
        if(strcmp(rule_ptr->to, old_host_name) == 0)
        {
            if(debuglvl >= HIGH)
                vrmr_debug(__FUNC__, "found in a rule (was looking for old_host_name:'%s', found rule_ptr->to:'%s').", old_host_name, rule_ptr->to);

            /* set the new name to the rules */
            (void)strlcpy(rule_ptr->to, new_name_ptr,
                    sizeof(rule_ptr->to));
            rules_changed = 1;
        }
    }
    /* if we have made changes we write the rulesfile */
    if(rules_changed == 1)
    {
        if(vrmr_rules_save_list(debuglvl, vctx, rules, &vctx->conf) < 0)
        {
            vrmr_error(-1, VR_ERR, gettext("saving rules failed."));
            return(-1);
        }
    }

    /* check the blocklist */
    for(d_node = blocklist->list.top; d_node; d_node = d_node->next)
    {
        blocklist_item = d_node->data;
        if(blocklist_item == NULL)
        {
            vrmr_error(-1, VR_INTERR, "NULL pointer (in: %s:%d).", __FUNC__, __LINE__);
            return(-1);
        }

        if(strcmp(blocklist_item, old_host_name) == 0)
        {
            size = StrMemLen(new_name_ptr) + 1;
            if(size > 0)
            {
                new_blocklist_item = malloc(size);
                if(new_blocklist_item == NULL)
                {
                    vrmr_error(-1, "Error", "malloc failed: %s.", strerror(errno));
                    return(-1);
                }
                if(strlcpy(new_blocklist_item, new_name_ptr, size) >= size)
                {
                    vrmr_error(-1, VR_INTERR, "name overflow (in: %s:%d).", __FUNC__, __LINE__);
                    return(-1);
                }

                /* swap the items */
                free(blocklist_item);
                d_node->data = new_blocklist_item;
            }

            blocklist_changed = 1;
        }
    }
    /* if we have made changes we write the blocklistfile */
    if(blocklist_changed == 1)
    {
        if(vrmr_blocklist_save_list(debuglvl, vctx, &vctx->conf, blocklist) < 0)
            return(-1);
    }

    /* group is done now */
    if(type == VRMR_TYPE_GROUP)
    {
        vrmr_audit("%s '%s' %s '%s'.",
            STR_GROUP, old_host_name,
            STR_HAS_BEEN_RENAMED_TO, new_name_ptr);
        return(0);
    }


    /* now check if we have a group that we are member of */
    for(d_node = zones->list.top; d_node; d_node = d_node->next)
    {
        zone_ptr = d_node->data;
        if(zone_ptr == NULL)
        {
            vrmr_error(-1, VR_INTERR, "NULL pointer (in: %s:%d).", __FUNC__, __LINE__);
            return(-1);
        }

        if(zone_ptr->type == VRMR_TYPE_GROUP)
        {
            for(grp_d_node = zone_ptr->GroupList.top; grp_d_node; grp_d_node = grp_d_node->next)
            {
                member_ptr = grp_d_node->data;
                if(member_ptr == NULL)
                {
                    vrmr_error(-1, VR_INTERR, "NULL pointer (in: %s:%d).", __FUNC__, __LINE__);
                    return(-1);
                }

                /* the member->name is already changed, so we compare against the new name */
                if(strcmp(member_ptr->name, new_name_ptr) == 0)
                {
                    group_changed = 1;
                }
            }

            /* if the groups is changed, save it */
            if(group_changed == 1)
            {
                if (vrmr_zones_group_save_members(debuglvl, vctx, zone_ptr) < 0)
                {
                    vrmr_error(-1, VR_ERR, gettext("saving changed group to backend failed."));
                    return(-1);
                }
                group_changed = 0;
            }
        }
    }

    vrmr_audit("%s '%s' %s '%s'.",
        STR_HOST, old_host_name, STR_HAS_BEEN_RENAMED_TO, new_name_ptr);

    return(0);
}


static int
zones_section_menu_hosts(const int debuglvl, struct vrmr_ctx *vctx,
        struct vrmr_zones *zones, struct vrmr_rules *rules, struct vrmr_blocklist *blocklist, char *zonename, char *networkname, struct vrmr_regex *reg)
{
    int                 ch = 0,
                        quit = 0,
                        reload = 0,
                        result = 0,
                        retval = 0;
    size_t              size = 0;
    struct vrmr_zone    *zone_ptr = NULL;
    char                *vrmr_new_zone_ptr = NULL,
                        *temp_ptr = NULL,
                        *cur_zonename_ptr = NULL;
    ITEM                *cur = NULL;
    /* top menu */
    char                *key_choices[] =    {   "F12",
                                                "INS",
                                                "DEL",
                                                "r",
                                                "RET",
                                                "e",
                                                "F10"};
    int                 key_choices_n = 7;
    char                *cmd_choices[] =    {   gettext("help"),
                                                gettext("new"),
                                                gettext("del"),
                                                gettext("rename"),
                                                gettext("open"),
                                                gettext("edit"),
                                                gettext("back")};
    int                 cmd_choices_n = 7;

    /* safety */
    if(zones == NULL || zonename == NULL || networkname == NULL || reg == NULL || blocklist == NULL)
    {
        vrmr_error(-1, VR_INTERR, "parameter problem (in: %s).", __FUNC__);
        return(-1);
    }

    /* setup */
    if (zones_section_menu_hosts_init(debuglvl, vctx, zones, zonename, networkname) < 0)
    {
        vrmr_error(-1, VR_INTERR, "setting up hosts menu failed (in: %s).", __FUNC__);
        return(-1);
    }

    draw_top_menu(debuglvl, top_win, gettext("Hosts"), key_choices_n, key_choices, cmd_choices_n, cmd_choices);

    /* enter the loop */
    while(quit == 0)
    {
        /* reload the menu */
        if(reload == 1)
        {
            if(debuglvl >= HIGH)
                vrmr_debug(__FUNC__, "reload == 1, reloading menu.");

            /* first destroy */
            if(zones_section_menu_hosts_destroy() < 0)
            {
                vrmr_error(-1, VR_INTERR, "reinitializing menu failed (in: %s).", __FUNC__);
                return(-1);
            }

            if(debuglvl >= HIGH)
                vrmr_debug(__FUNC__, "reload == 1, old menu destroyed.");

            /* and setup again */
            if (zones_section_menu_hosts_init(debuglvl, vctx, zones, zonename, networkname) < 0)
            {
                vrmr_error(-1, VR_INTERR, "reinitializing menu failed (in: %s).", __FUNC__);
                return(-1);
            }

            if(debuglvl >= HIGH)
                vrmr_debug(__FUNC__, "reload == 1, new menu created.");

            /* we are done with reloading */
            reload = 0;
        }

        /* loop for catching user input */
        while(quit == 0 && reload == 0)
        {
            if(ZonesSection.h_top != NULL && !item_visible(ZonesSection.h_top))
                show_panel(ZonesSection.h_panel_top[0]);
            else
                hide_panel(ZonesSection.h_panel_top[0]);

            if(ZonesSection.h_bot != NULL && !item_visible(ZonesSection.h_bot))
                show_panel(ZonesSection.h_panel_bot[0]);
            else
                hide_panel(ZonesSection.h_panel_bot[0]);

            update_panels();
            doupdate();

            /* restore the cursor */
            pos_menu_cursor(ZonesSection.h_menu);

            /* get the user input */
            ch = wgetch(ZonesSection.h_win);
            switch(ch)
            {
                case 27:
                case KEY_LEFT:
                case KEY_F(10):
                case 'q':
                case 'Q':

                    quit = 1;
                    break;

                case 'r':
                case 'R':

                    if(current_item(ZonesSection.h_menu))
                    {
                        /* get the current item */
                        if(!(cur = current_item(ZonesSection.h_menu)))
                        {
                            vrmr_error(-1, VR_INTERR, "current_item failed: cur == NULL.");
                            return(-1);
                        }

                        // size
                        size = StrMemLen((char *)item_name(cur))+1+StrMemLen(networkname)+1+StrMemLen(zonename)+1;

                        // alloc the memory
                        if(!(cur_zonename_ptr = malloc(size)))
                        {
                            vrmr_error(-1, VR_ERR, gettext("malloc failed: %s (in: %s:%d)."), strerror(errno), __func__, __LINE__);
                            return(-1);
                        }

                        // create the string
                        (void)strlcpy(cur_zonename_ptr, (char *)item_name(cur), size);
                        (void)strlcat(cur_zonename_ptr, ".", size);
                        (void)strlcat(cur_zonename_ptr, networkname, size);
                        (void)strlcat(cur_zonename_ptr, ".", size);
                        (void)strlcat(cur_zonename_ptr, zonename, size);


                        vrmr_new_zone_ptr = input_box(VRMR_MAX_HOST, gettext("Rename Host"), gettext("Enter the new name of the host"));
                        if(vrmr_new_zone_ptr != NULL)
                        {
                            if(vrmr_validate_zonename(debuglvl, vrmr_new_zone_ptr, 1, NULL, NULL, NULL, reg->host_part, VRMR_VERBOSE) == -1)
                            {
                                vrmr_warning(VR_WARN, gettext("invalid hostname '%s'."), vrmr_new_zone_ptr);
                            }
                            else
                            {
                                /* get the size */
                                size = StrMemLen(vrmr_new_zone_ptr) + 1 + StrMemLen(networkname) + 1 + StrMemLen(zonename) + 1;

                                /* alloc the memory */
                                if(!(temp_ptr = malloc(size)))
                                {
                                    vrmr_error(-1, VR_ERR, gettext("malloc failed: %s (in: %s:%d)."), strerror(errno), __func__, __LINE__);
                                    return(-1);
                                }

                                /* create the string */
                                (void)strlcpy(temp_ptr, vrmr_new_zone_ptr, size);
                                (void)strlcat(temp_ptr, ".", size);
                                (void)strlcat(temp_ptr, networkname, size);
                                (void)strlcat(temp_ptr, ".", size);
                                (void)strlcat(temp_ptr, zonename, size);

                                if(vrmr_validate_zonename(debuglvl, temp_ptr, 1, NULL, NULL, NULL, reg->zonename, VRMR_VERBOSE) == -1)
                                {
                                    vrmr_warning(VR_WARN, gettext("invalid hostname '%s'."), temp_ptr);
                                }
                                else
                                {
                                    if (zones_rename_host_group(debuglvl, vctx, zones, rules, blocklist, cur_zonename_ptr, temp_ptr, VRMR_TYPE_HOST, reg) == 0)
                                    {
                                        /* we have a new host, so reload the menu */
                                        reload = 1;
                                    }
                                }

                                free(temp_ptr);
                            }

                            free(vrmr_new_zone_ptr);
                        }

                        free(cur_zonename_ptr);
                    }
                    break;

                case KEY_IC:    /* insert key */
                case 'i':
                case 'I':

                    vrmr_new_zone_ptr = input_box(VRMR_MAX_HOST, gettext("New Host"), gettext("Enter the name of the new host"));
                    if(vrmr_new_zone_ptr != NULL)
                    {
                        if(vrmr_validate_zonename(debuglvl, vrmr_new_zone_ptr, 1, NULL, NULL, NULL, reg->host_part, VRMR_VERBOSE) == -1)
                        {
                            vrmr_warning(VR_WARN, gettext("invalid hostname '%s'."), vrmr_new_zone_ptr);
                        }
                        else
                        {
                            /* get the size */
                            size = StrMemLen(vrmr_new_zone_ptr) + 1 + StrMemLen(networkname) + 1 + StrMemLen(zonename) + 1;

                            /* alloc the memory */
                            if(!(temp_ptr = malloc(size)))
                            {
                                vrmr_error(-1, VR_ERR, gettext("malloc failed: %s (in: %s:%d)."), strerror(errno), __func__, __LINE__);
                                return(-1);
                            }

                            /* create the string */
                            (void)strlcpy(temp_ptr, vrmr_new_zone_ptr, size);
                            (void)strlcat(temp_ptr, ".", size);
                            (void)strlcat(temp_ptr, networkname, size);
                            (void)strlcat(temp_ptr, ".", size);
                            (void)strlcat(temp_ptr, zonename, size);

                            if(vrmr_validate_zonename(debuglvl, temp_ptr, 1, NULL, NULL, NULL, reg->zonename, VRMR_VERBOSE) == -1)
                            {
                                vrmr_warning(VR_WARN, gettext("invalid hostname '%s'."), temp_ptr);
                            }
                            else
                            {
                                if (vrmr_new_zone(debuglvl, vctx, zones, temp_ptr, VRMR_TYPE_HOST) >= 0)
                                {
                                    vrmr_audit("%s '%s' %s.", STR_HOST, temp_ptr, STR_HAS_BEEN_CREATED);

                                    (void)edit_zone_host(debuglvl, vctx, zones, temp_ptr, reg);
                                    draw_top_menu(debuglvl, top_win, gettext("Hosts"), key_choices_n, key_choices, cmd_choices_n, cmd_choices);
                                }

                                /* we have a new host, so reload the menu */
                                reload = 1;
                            }
                            free(temp_ptr);
                        }

                        free(vrmr_new_zone_ptr);
                    }
                    break;

                /*
                    delete
                */
                case KEY_DC:
                case 'd':
                case 'D':

                    if(current_item(ZonesSection.h_menu))
                    {
                        if (confirm(gettext("Delete"), gettext("This host?"),
                                    vccnf.color_win_note, vccnf.color_win_note_rev|A_BOLD, 0) == 1)
                        {
                            /* get the current item */
                            if(!(cur = current_item(ZonesSection.h_menu)))
                            {
                                vrmr_error(-1, VR_INTERR, "current_item failed: cur == NULL.");
                                return(-1);
                            }

                            /* size */
                            size = StrMemLen((char *)item_name(cur))+1+StrMemLen(networkname)+1+StrMemLen(zonename)+1;

                            /* alloc the memory */
                            if(!(temp_ptr = malloc(size)))
                            {
                                vrmr_error(-1, VR_ERR, gettext("malloc failed: %s (in: %s:%d)."), strerror(errno), __func__, __LINE__);
                                return(-1);
                            }

                            /* create the full string */
                            (void)strlcpy(temp_ptr, (char *)item_name(cur), size);
                            (void)strlcat(temp_ptr, ".", size);
                            (void)strlcat(temp_ptr, networkname, size);
                            (void)strlcat(temp_ptr, ".", size);
                            (void)strlcat(temp_ptr, zonename, size);

                            zone_ptr = vrmr_search_zonedata(debuglvl, zones, temp_ptr);
                            if(zone_ptr == NULL)
                            {
                                vrmr_error(-1, VR_INTERR, "couldn't find %s in memory.", temp_ptr);
                            } else {
                                /* check the refernce counters */
                                if(zone_ptr->refcnt_group > 0)
                                {
                                    vrmr_error(-1, VR_ERR, gettext("host '%s' is still a member of %u group(s)."),
                                            zone_ptr->name, zone_ptr->refcnt_group);
                                }
                                else if(zone_ptr->refcnt_blocklist > 0)
                                {
                                    vrmr_error(-1, VR_ERR, gettext("host '%s' is still in the blocklist (%u times)."),
                                            zone_ptr->name, zone_ptr->refcnt_blocklist);
                                }
                                else
                                {
                                    if (vrmr_delete_zone(debuglvl, vctx, zones, temp_ptr, zone_ptr->type) < 0)
                                    {
                                        vrmr_error(result, VR_ERR, gettext("deleting zone failed."));
                                    }
                                    else
                                    {
                                        vrmr_audit("%s '%s' %s.", STR_HOST, temp_ptr, STR_HAS_BEEN_DELETED);
                                        reload = 1;
                                    }
                                }
                            }

                            free(temp_ptr);
                        }
                    }
                    break;

                case KEY_DOWN:
                    menu_driver(ZonesSection.h_menu, REQ_DOWN_ITEM);
                    break;
                case KEY_UP:
                    menu_driver(ZonesSection.h_menu, REQ_UP_ITEM);
                    break;
                case KEY_NPAGE:
                    if(menu_driver(ZonesSection.h_menu, REQ_SCR_DPAGE) != E_OK)
                    {
                        while(menu_driver(ZonesSection.h_menu, REQ_DOWN_ITEM) == E_OK);
                    }
                    break;
                case KEY_PPAGE:
                    if(menu_driver(ZonesSection.h_menu, REQ_SCR_UPAGE) != E_OK)
                    {
                        while(menu_driver(ZonesSection.h_menu, REQ_UP_ITEM) == E_OK);
                    }
                    break;
                case KEY_HOME:
                    menu_driver(ZonesSection.h_menu, REQ_FIRST_ITEM);   // home
                    break;
                case KEY_END:
                    menu_driver(ZonesSection.h_menu, REQ_LAST_ITEM);    // end
                    break;

                case 32: // space
                case KEY_RIGHT:
                case 10: // enter
                case 'e':
                case 'E':

                    if(current_item(ZonesSection.h_menu))
                    {
                        // get the current item
                        if(!(cur = current_item(ZonesSection.h_menu)))
                        {
                            vrmr_error(-1, VR_INTERR, "current_item failed: cur == NULL.");
                            return(-1);
                        }

                        // size
                        size = StrMemLen((char *)item_name(cur))+1+StrMemLen(networkname)+1+StrMemLen(zonename)+1;

                        // alloc the memory
                        if(!(temp_ptr = malloc(size)))
                        {
                            vrmr_error(-1, VR_ERR, gettext("malloc failed: %s (in: %s:%d)."), strerror(errno), __func__, __LINE__);
                            return(-1);
                        }

                        // create the string
                        (void)strlcpy(temp_ptr, (char *)item_name(cur), size);
                        (void)strlcat(temp_ptr, ".", size);
                        (void)strlcat(temp_ptr, networkname, size);
                        (void)strlcat(temp_ptr, ".", size);
                        (void)strlcat(temp_ptr, zonename, size);

                        zone_ptr = vrmr_search_zonedata(debuglvl, zones, temp_ptr);
                        if(zone_ptr != NULL)
                        {
                            if(zone_ptr->type == VRMR_TYPE_HOST)
                            {
                                (void)edit_zone_host(debuglvl, vctx, zones, zone_ptr->name, reg);
                                draw_top_menu(debuglvl, top_win, gettext("Hosts"), key_choices_n, key_choices, cmd_choices_n, cmd_choices);
                            }
                            else
                            {
                                vrmr_error(-1, VR_INTERR, "expected a host but got %d.", zone_ptr->type);
                                return(-1);
                            }
                        }
                        else
                        {
                            vrmr_error(-1, VR_INTERR, "%s not found in memory.", temp_ptr);
                            return(-1);
                        }

                        free(temp_ptr);

                        reload = 1;
                    }
                    break;

                case KEY_F(12):
                case 'h':
                case 'H':
                case '?':

                    print_help(debuglvl, ":[VUURMUUR:ZONES:HOSTS]:");
                    break;
            }
        }
    }

    if(zones_section_menu_hosts_destroy() < 0)
        retval = -1;

    update_panels();
    doupdate();

    status_print(status_win, gettext("Ready."));
    return(retval);
}


static int
edit_zone_group_members_init(const int debuglvl, struct vrmr_ctx *vctx, struct vrmr_zones *zones, struct vrmr_zone *group_ptr)
{
    int                 retval=0;
    struct vrmr_list_node         *d_node = NULL;
    struct vrmr_zone    *member_ptr = NULL;
    int                 i=0;
    int                 height = 30,
                        width  = 54, /* max width of host_name (32) + box (2) + 4 + 16 */
                        startx = 0,
                        starty = 0,
                        max_height = 0;

    /* safety */
    if(!group_ptr || !zones)
    {
        vrmr_error(-1, VR_INTERR, "parameter problem (in: %s)", __FUNC__);
        return(-1);
    }
    if(group_ptr->type != VRMR_TYPE_GROUP)
    {
        vrmr_error(-1, VR_INTERR, "expected a GROUP (%d), but got a %d (in: %s)", VRMR_TYPE_GROUP, group_ptr->type, __FUNC__);
        return(-1);
    }

    ZonesSection.EditZoneGrp.n_items = group_ptr->GroupList.len;

    if(!(ZonesSection.EditZoneGrp.items = (ITEM **)calloc(ZonesSection.EditZoneGrp.n_items + 1, sizeof(ITEM *))))
    {
        vrmr_error(-1, VR_ERR, gettext("calloc failed: %s (in: %s:%d)."), strerror(errno), __func__, __LINE__);
        return(-1);
    }

    max_height = getmaxy(stdscr);
    height = (int)(ZonesSection.EditZoneGrp.n_items + 7); /* 7 because: 3 above the list, 4 below */
    if (height >= max_height - 6)
    {
        height = max_height - 6;
    }
    /* place on the same y as zones list */
    VrWinGetOffset(-1, -1, height, width, 4, ZonesSection.h_xre + 1, &starty, &startx);

    /* load the items */
    for(i = 0, d_node = group_ptr->GroupList.top; d_node ; d_node = d_node->next, i++)
    {
        if(!(member_ptr = d_node->data))
        {
            vrmr_error(-1, VR_INTERR, "NULL pointer (in: %s:%d)", __FUNC__, __LINE__);
            return(-1);
        }

        /* load all interfaces into memory */
        if(!(ZonesSection.EditZoneGrp.items[i] = new_item(member_ptr->host_name, member_ptr->ipv4.ipaddress)))
        {
            vrmr_error(-1, VR_INTERR, "new_item() failed (in: %s:%d)", __FUNC__, __LINE__);
            return(-1);
        }
    }
    ZonesSection.EditZoneGrp.items[ZonesSection.EditZoneGrp.n_items] = (ITEM *)NULL;

    if(ZonesSection.EditZoneGrp.n_items > 0)
    {
        ZonesSection.EditZoneGrp.top = ZonesSection.EditZoneGrp.items[0];
        ZonesSection.EditZoneGrp.bot = ZonesSection.EditZoneGrp.items[ZonesSection.EditZoneGrp.n_items - 1];
    }
    else
    {
        ZonesSection.EditZoneGrp.top = NULL;
        ZonesSection.EditZoneGrp.bot = NULL;
    }

    /* create win and panel */
    if(!(ZonesSection.EditZoneGrp.win = newwin(height, width, starty, startx)))
    {
        vrmr_error(-1, VR_INTERR, "newwin() failed (in: %s:%d)", __FUNC__, __LINE__);
        return(-1);
    }
    if(!(ZonesSection.EditZoneGrp.panel[0] = new_panel(ZonesSection.EditZoneGrp.win)))
    {
        vrmr_error(-1, VR_INTERR, "new_panel() failed (in: %s:%d)", __FUNC__, __LINE__);
        return(-1);
    }
    wbkgd(ZonesSection.EditZoneGrp.win, vccnf.color_win);
    keypad(ZonesSection.EditZoneGrp.win, TRUE);

    if(!(ZonesSection.EditZoneGrp.menu = new_menu((ITEM **)ZonesSection.EditZoneGrp.items)))
    {
        vrmr_error(-1, VR_INTERR, "new_menu() failed (in: %s:%d)", __FUNC__, __LINE__);
        return(-1);
    }
    set_menu_win(ZonesSection.EditZoneGrp.menu, ZonesSection.EditZoneGrp.win);
    set_menu_sub(ZonesSection.EditZoneGrp.menu, derwin(ZonesSection.EditZoneGrp.win, height-6, width-2, 3, 1));
    set_menu_format(ZonesSection.EditZoneGrp.menu, height-7, 1);

    /* markup */
    box(ZonesSection.EditZoneGrp.win, 0, 0);
    print_in_middle(ZonesSection.EditZoneGrp.win, 1, 0, width, gettext("Members"), vccnf.color_win);
    mvwaddch(ZonesSection.EditZoneGrp.win, 2, 0, ACS_LTEE);
    mvwhline(ZonesSection.EditZoneGrp.win, 2, 1, ACS_HLINE, width-2);
    mvwaddch(ZonesSection.EditZoneGrp.win, 2, width-1, ACS_RTEE);

    set_menu_back(ZonesSection.EditZoneGrp.menu, vccnf.color_win);
    set_menu_fore(ZonesSection.EditZoneGrp.menu, vccnf.color_win_rev);

    post_menu(ZonesSection.EditZoneGrp.menu);

    mvwaddch(ZonesSection.EditZoneGrp.win, height-4, 0, ACS_LTEE);
    mvwhline(ZonesSection.EditZoneGrp.win, height-4, 1, ACS_HLINE, width-2);
    mvwaddch(ZonesSection.EditZoneGrp.win, height-4, width-1, ACS_RTEE);

    mvwprintw(ZonesSection.EditZoneGrp.win, height-3, 2, "<INS> %s", STR_NEW);
    mvwprintw(ZonesSection.EditZoneGrp.win, height-2, 2, "<DEL> %s", STR_REMOVE);

    /* create the top and bottom fields */
    if(!(ZonesSection.EditZoneGrp.win_top = newwin(1, 6, starty + 2, width - 8)))
    {
        vrmr_error(-1, VR_ERR, gettext("creating window failed."));
        return(-1);
    }
    wbkgd(ZonesSection.EditZoneGrp.win_top, vccnf.color_win);
    ZonesSection.EditZoneGrp.panel_top[0] = new_panel(ZonesSection.EditZoneGrp.win_top);
    /* TRANSLATORS: max 4 chars */
    wprintw(ZonesSection.EditZoneGrp.win_top, "(%s)", gettext("more"));
    hide_panel(ZonesSection.EditZoneGrp.panel_top[0]);

    if(!(ZonesSection.EditZoneGrp.win_bot = newwin(1, 6, starty + height - 4, width - 8)))
    {
        vrmr_error(-1, VR_ERR, gettext("creating window failed."));
        return(-1);
    }
    wbkgd(ZonesSection.EditZoneGrp.win_bot, vccnf.color_win);
    ZonesSection.EditZoneGrp.panel_bot[0] = new_panel(ZonesSection.EditZoneGrp.win_bot);
    /* TRANSLATORS: max 4 chars */
    wprintw(ZonesSection.EditZoneGrp.win_bot, "(%s)", gettext("more"));
    hide_panel(ZonesSection.EditZoneGrp.panel_bot[0]);

    update_panels();
    doupdate();

    return(retval);
}


static int
edit_zone_group_members_destroy(void)
{
    int     retval = 0;
    size_t  i = 0;

    // Un post form and free the memory
    unpost_menu(ZonesSection.EditZoneGrp.menu);
    free_menu(ZonesSection.EditZoneGrp.menu);

    for(i=0;i<ZonesSection.EditZoneGrp.n_items;i++)
    {
        free_item(ZonesSection.EditZoneGrp.items[i]);
    }
    free(ZonesSection.EditZoneGrp.items);

    del_panel(ZonesSection.EditZoneGrp.panel[0]);
    destroy_win(ZonesSection.EditZoneGrp.win);

    del_panel(ZonesSection.EditZoneGrp.panel_top[0]);
    destroy_win(ZonesSection.EditZoneGrp.win_top);
    del_panel(ZonesSection.EditZoneGrp.panel_bot[0]);
    destroy_win(ZonesSection.EditZoneGrp.win_bot);

    update_panels();
    doupdate();

    return(retval);
}


/*  edit_zone_group_members_delmem

    Deletes the member 'member_name' from the GroupList of
    the group 'group_ptr'.

    Returncodes:
         0: ok
        -1: error
*/
static int
edit_zone_group_members_delmem(const int debuglvl, struct vrmr_ctx *vctx, struct vrmr_zone *group_ptr, char *member_name)
{
    int     result = 0;
    char    logname[VRMR_VRMR_MAX_HOST_NET_ZONE] = "";

    snprintf(logname, sizeof(logname), "%s.%s.%s", member_name, group_ptr->network_name, group_ptr->zone_name);

    result = vrmr_zones_group_rem_member(debuglvl, vctx, group_ptr, member_name);
    if(result == 0)
    {
        vrmr_audit("%s '%s' %s: %s: '%s'.",
            STR_GROUP, group_ptr->name, STR_HAS_BEEN_CHANGED,
            logname, STR_A_MEMBER_HAS_BEEN_REMOVED);
    }

    return(result);
}


/*  edit_zone_group_members_newmem

    Displays a menu with hosts to chose from to add to the
    group 'group_ptr'.

    Returncodes:
         0: ok
        -1: error
*/
static int
edit_zone_group_members_newmem(const int debuglvl, struct vrmr_ctx *vctx,
        struct vrmr_zones *zones, struct vrmr_zone *group_ptr)
{
    struct vrmr_list_node         *d_node = NULL;
    char                **choices,
                        *choice_ptr=NULL,
                        search_name[VRMR_VRMR_MAX_HOST_NET_ZONE]="";
    size_t              n_choices=0,
                        i=0;
    struct vrmr_zone    *zonelist_ptr=NULL;
    int                 result = 0;

    /* safety */
    if(!group_ptr || !zones)
    {
        vrmr_error(-1, VR_INTERR, "parameter problem (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }
    /* this should not happen, but it cant hurt checking right? */
    if(group_ptr->type != VRMR_TYPE_GROUP)
    {
        vrmr_error(-1, VR_INTERR, "expected a GROUP (%d), but got a %d (in: %s:%d)", VRMR_TYPE_GROUP, group_ptr->type, __FUNC__, __LINE__);
        return(-1);
    }

    /* first count the number of hosts in this network */
    for(n_choices = 0, d_node = zones->list.top; d_node; d_node = d_node->next)
    {
        if(!(zonelist_ptr = d_node->data))
        {
            vrmr_error(-1, VR_INTERR, "NULL pointer (in: %s:%d).", __FUNC__, __LINE__);
            return(-1);
        }

        if(zonelist_ptr->type == VRMR_TYPE_HOST)
        {
            /* check if the host belongs to our zone */
            if(strcmp(group_ptr->zone_name, zonelist_ptr->zone_name) == 0)
            {
                /* check if the host belongs to our network */
                if(strcmp(group_ptr->network_name, zonelist_ptr->network_name) == 0)
                {
                    n_choices++;
                }
            }
        }
    }

    if(n_choices == 0)
    {
        vrmr_warning(VR_WARN, gettext("please add some hosts to the network first."));
        return(0);
    }

    /* alloc the mem */
    if(!(choices = calloc(n_choices + 1, VRMR_MAX_HOST)))
    {
        vrmr_error(-1, VR_ERR, gettext("calloc failed: %s (in: %s:%d)."), strerror(errno), __func__, __LINE__);
        return(-1);
    }

    /* now init the new mem */
    for(i = n_choices - 1, d_node = zones->list.bot; d_node ; d_node = d_node->prev)
    {
        if(!(zonelist_ptr = d_node->data))
        {
            vrmr_error(-1, VR_INTERR, "NULL pointer (in: %s:%d).", __FUNC__, __LINE__);
            return(-1);
        }

        if(zonelist_ptr->type == VRMR_TYPE_HOST)
        {
            if(strcmp(group_ptr->zone_name, zonelist_ptr->zone_name) == 0)
            {
                if(strcmp(group_ptr->network_name, zonelist_ptr->network_name) == 0)
                {
                    choices[i] = zonelist_ptr->host_name;
                    i--;
                }
            }
        }
    }

    /* let the user select one. If he/she doesn't select one, fine, bail out. */
    if(!(choice_ptr = selectbox(gettext("New member"), gettext("Select a host"), n_choices, choices, 1, NULL)))
    {
        /* no choice was made, so quit quietly. */
        free(choices);
        return(0);
    }

    /* clean up */
    free(choices);

    /* assemble the full zonename... */
    if(snprintf(search_name, sizeof(search_name), "%s.%s.%s", choice_ptr, group_ptr->network_name, group_ptr->zone_name) >= (int)sizeof(search_name))
    {
        vrmr_error(-1, VR_INTERR, "buffer overflow (in: %s:%d).", __FUNC__, __LINE__);

        free(choice_ptr);
        return(-1);
    }

    /* and free the hostname */
    free(choice_ptr);

    /* add the member */
    result = vrmr_zones_group_add_member(debuglvl, vctx, zones, group_ptr, search_name);
    if(result == 0)
    {
        vrmr_audit("%s '%s' %s: %s: %s.",
            STR_GROUP, group_ptr->name, STR_HAS_BEEN_CHANGED,
            STR_A_MEMBER_HAS_BEEN_ADDED, search_name);
    }
    return(result);
}


/*  edit_group_members

    Displays the grouplist and allows the user to add
    and remove members.

    Returncodes:
         0: ok
        -1: error
*/
int
edit_zone_group_members(const int debuglvl, struct vrmr_ctx *vctx,
        struct vrmr_zones *zones, struct vrmr_zone *zone_ptr)
{
    int     quit = 0,
            reload = 0,
            ch,
            retval = 0;
    ITEM    *cur = NULL;

    /* safety */
    if(!zone_ptr || !zones)
    {
        vrmr_error(-1, VR_INTERR, "parameter problem (in: %s:%d)", __FUNC__);
        return(-1);
    }

    /* setup the win */
    if (edit_zone_group_members_init(debuglvl, vctx, zones, zone_ptr) < 0)
        return(-1);

    while(quit == 0)
    {
        if(reload == 1)
        {
            /* first destroy */
            if(edit_zone_group_members_destroy() < 0)
                return(-1);

            /* then init again */
            if (edit_zone_group_members_init(debuglvl, vctx, zones, zone_ptr) < 0)
                return(-1);

            /* refresh screen */
            update_panels();
            doupdate();

            reload = 0;
        }

        while(quit == 0 && reload == 0)
        {
            if(ZonesSection.EditZoneGrp.top != NULL && !item_visible(ZonesSection.EditZoneGrp.top))
                show_panel(ZonesSection.EditZoneGrp.panel_top[0]);
            else
                hide_panel(ZonesSection.EditZoneGrp.panel_top[0]);

            if(ZonesSection.EditZoneGrp.bot != NULL && !item_visible(ZonesSection.EditZoneGrp.bot))
                show_panel(ZonesSection.EditZoneGrp.panel_bot[0]);
            else
                hide_panel(ZonesSection.EditZoneGrp.panel_bot[0]);

            update_panels();
            doupdate();

            /* restore the cursor */
            pos_menu_cursor(ZonesSection.EditZoneGrp.menu);

            /* get user input */
            ch = wgetch(ZonesSection.EditZoneGrp.win);
            switch(ch)
            {
                case 27:
                case 'q':
                case 'Q':
                case KEY_F(10): //quit

                    quit = 1;
                    break;

                case KEY_IC:
                case 'i':
                case 'I':

                    (void)edit_zone_group_members_newmem(debuglvl, vctx, zones, zone_ptr);

                    reload=1;
                    break;

                case KEY_DC:
                case 'd':
                case 'D':

                    cur = current_item(ZonesSection.EditZoneGrp.menu);
                    if(cur)
                    {
                        char *n = (char *)item_name(cur);

                        if (edit_zone_group_members_delmem(debuglvl, vctx, zone_ptr, n) < 0)
                        {
                            /* if this failes, print error, quit the members screen and set retval */
                            vrmr_error(-1, VR_ERR, gettext("removing groupmember failed."));

                            quit = 1;
                            retval = -1;
                        }

                        reload = 1;
                    }
                    break;

                case KEY_DOWN:
                    menu_driver(ZonesSection.EditZoneGrp.menu, REQ_DOWN_ITEM);
                    break;
                case KEY_UP:
                    menu_driver(ZonesSection.EditZoneGrp.menu, REQ_UP_ITEM);
                    break;
                case KEY_NPAGE:
                    if(menu_driver(ZonesSection.EditZoneGrp.menu, REQ_SCR_DPAGE) != E_OK)
                    {
                        while(menu_driver(ZonesSection.EditZoneGrp.menu, REQ_DOWN_ITEM) == E_OK);
                    }
                    break;
                case KEY_PPAGE:
                    if(menu_driver(ZonesSection.EditZoneGrp.menu, REQ_SCR_UPAGE) != E_OK)
                    {
                        while(menu_driver(ZonesSection.EditZoneGrp.menu, REQ_UP_ITEM) == E_OK);
                    }
                    break;
                case KEY_HOME:
                    menu_driver(ZonesSection.EditZoneGrp.menu, REQ_FIRST_ITEM); // home
                    break;
                case KEY_END:
                    menu_driver(ZonesSection.EditZoneGrp.menu, REQ_LAST_ITEM);  // end
                    break;
            }
        }
    }

    /* cleanup */
    if(edit_zone_group_members_destroy() < 0)
        retval = -1;

    status_print(status_win, gettext("Ready."));
    return(retval);
}


struct
{
    FIELD   *activefld,
            *activelabelfld,

            *commentfld,
            *commentlabelfld,

            *warningfld;    /* field for warnings */

} GroupSec;


static int
edit_zone_group_init(int debuglvl, struct vrmr_ctx *vctx, struct vrmr_zones *zones, char *name, struct vrmr_zone *zone_ptr)
{
    int                 retval = 0,
                        rows,
                        cols,
                        max_height = 0,
                        height = 0,
                        width = 0,
                        startx = 0,
                        starty = 0,
                        comment_y = 0,
                        comment_x = 0;
    size_t              i,
                        field_num = 0;

    /* safety */
    if(name == NULL || zone_ptr == NULL)
    {
        vrmr_error(-1, VR_INTERR, "parameter problem (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    max_height = getmaxy(stdscr);
    height = 17;
    if(height > max_height - 8)
        height = max_height - 8;
    width = 54;
    VrWinGetOffset(-1, -1, height, width, ZonesSection.h_yle + 1, ZonesSection.n_xre + 1, &starty, &startx);

    memset(&GroupSec, 0, sizeof(GroupSec));
    ZonesSection.EditZone.n_fields = 5;

    if(!(ZonesSection.EditZone.fields = (FIELD **)calloc(ZonesSection.EditZone.n_fields + 1, sizeof(FIELD *))))
    {
        vrmr_error(-1, VR_ERR, gettext("calloc failed: %s (in: %s:%d)."), strerror(errno), __func__, __LINE__);
        return(-1);
    }

    /* preload the active field */
    GroupSec.activelabelfld = (ZonesSection.EditZone.fields[field_num++] = new_field(1, 16, 2, 0, 0, 0));
    set_field_buffer_wrap(debuglvl, GroupSec.activelabelfld, 0, gettext("Active"));
    field_opts_off(GroupSec.activelabelfld, O_AUTOSKIP | O_ACTIVE);

    GroupSec.activefld = (ZonesSection.EditZone.fields[field_num++] = new_field(1, 3, 3, 1, 0, 0));
    set_field_buffer_wrap(debuglvl, GroupSec.activefld, 0, zone_ptr->active ? STR_YES : STR_NO);

    /* comment label */
    GroupSec.commentlabelfld = (ZonesSection.EditZone.fields[field_num++] = new_field(1, 16, 5, 0, 0, 0));
    set_field_buffer_wrap(debuglvl, GroupSec.commentlabelfld, 0, gettext("Comment"));
    field_opts_off(GroupSec.commentlabelfld, O_AUTOSKIP | O_ACTIVE);

    /* comment field size */
    comment_y = 5;
    comment_x = 48;
    /* create the comment field */
    GroupSec.commentfld = (ZonesSection.EditZone.fields[field_num++] = new_field(comment_y, comment_x, 6, 1, 0, 0));

    /* load the comment from the backend */
    if (vctx->zf->ask(debuglvl, vctx->zone_backend, zone_ptr->name, "COMMENT", ZonesSection.comment, sizeof(ZonesSection.comment), VRMR_TYPE_GROUP, 0) < 0)
        vrmr_error(-1, VR_ERR, gettext("error while loading the comment."));

    set_field_buffer_wrap(debuglvl, GroupSec.commentfld, 0, ZonesSection.comment);

    /* comment label */
    GroupSec.warningfld = (ZonesSection.EditZone.fields[field_num++] = new_field(1, 48, 11, 1, 0, 0));
    field_opts_off(GroupSec.warningfld, O_AUTOSKIP | O_ACTIVE | O_VISIBLE);
    set_field_just(GroupSec.warningfld, JUSTIFY_CENTER);

    if (field_num != ZonesSection.EditZone.n_fields) {
        vrmr_error(-1, VR_INTERR, "parameter problem (in: %s:%d).",
                __FUNC__, __LINE__);
        return(-1);
    }

    /* terminate */
    ZonesSection.EditZone.fields[ZonesSection.EditZone.n_fields] = NULL;

    if(!(ZonesSection.EditZone.win = create_newwin(height, width, starty, startx, gettext("Edit Zone: Group"), vccnf.color_win)))
    {
        vrmr_error(-1, VR_INTERR, "create_newwin() failed (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }
    if(!(ZonesSection.EditZone.panel[0] = new_panel(ZonesSection.EditZone.win)))
    {
        vrmr_error(-1, VR_INTERR, "new_panel() failed (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    /* set field options */
    for(i = 0; i < ZonesSection.EditZone.n_fields; i++)
    {
        set_field_back(ZonesSection.EditZone.fields[i], vccnf.color_win_rev);
        field_opts_off(ZonesSection.EditZone.fields[i], O_AUTOSKIP);
        set_field_status(ZonesSection.EditZone.fields[i], FALSE);
    }
    set_field_back(GroupSec.activelabelfld, vccnf.color_win);
    set_field_back(GroupSec.commentlabelfld, vccnf.color_win);

    set_field_back(GroupSec.warningfld, vccnf.color_win);
    set_field_fore(GroupSec.warningfld, vccnf.color_win_warn|A_BOLD);

    /* Create the form and post it */
    if(!(ZonesSection.EditZone.form = new_form(ZonesSection.EditZone.fields)))
    {
        vrmr_error(-1, VR_INTERR, "new_form() failed (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }
    /* Calculate the area required for the form */
    scale_form(ZonesSection.EditZone.form, &rows, &cols);
    keypad(ZonesSection.EditZone.win, TRUE);

    /* Set main window and sub window */
    set_form_win(ZonesSection.EditZone.form, ZonesSection.EditZone.win);
    set_form_sub(ZonesSection.EditZone.form, derwin(ZonesSection.EditZone.win, rows, cols, 1, 2));
    post_form(ZonesSection.EditZone.form);

    /* draw labels */
    mvwprintw(ZonesSection.EditZone.win, 1, 2, "%s: %s", gettext("Name"), zone_ptr->name);
    mvwprintw(ZonesSection.EditZone.win, 13, 2, gettext("Press <F6> to manage the members of this group."));

    wrefresh(ZonesSection.EditZone.win);

    update_panels();
    doupdate();

    return(retval);
}


static int
edit_zone_group_save(const int debuglvl, struct vrmr_ctx *vctx, struct vrmr_zone *group_ptr)
{
    int     retval = 0,
            active = 0;
    size_t  i = 0;

    /* safety */
    if(!group_ptr)
    {
        vrmr_error(-1, VR_INTERR, "parameter problem (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    /* check for changed fields */
    for(i = 0; i < ZonesSection.EditZone.n_fields; i++)
    {
        if(field_status(ZonesSection.EditZone.fields[i]) == TRUE)
        {
            /* active field */
            if(ZonesSection.EditZone.fields[i] == GroupSec.activefld)
            {
                group_ptr->status = VRMR_ST_CHANGED;

                active = group_ptr->active; 

                if(strncasecmp(field_buffer(ZonesSection.EditZone.fields[i], 0), STR_YES, StrLen(STR_YES)) == 0)
                {
                    group_ptr->active = 1;
                }
                else if(strncasecmp(field_buffer(ZonesSection.EditZone.fields[i], 0), STR_NO, StrLen(STR_NO)) == 0)
                {
                    group_ptr->active = 0;
                }
                else
                {
                    group_ptr->active = -1;
                }

                if (vctx->zf->tell(debuglvl, vctx->zone_backend, group_ptr->name, "ACTIVE", group_ptr->active ? "Yes" : "No", 1, VRMR_TYPE_GROUP) < 0)
                {
                    vrmr_error(-1, VR_ERR, gettext("saving to backend failed (in: %s:%d)."), __FUNC__, __LINE__);
                    retval = -1;
                }

                /* for the log */
                vrmr_audit("%s '%s' %s: %s %s '%s' (%s: '%s').",
                    STR_GROUP, group_ptr->name, STR_HAS_BEEN_CHANGED, STR_ACTIVE,
                    STR_IS_NOW_SET_TO, group_ptr->active ? STR_YES : STR_NO,
                    STR_WAS, active ? STR_YES : STR_NO);
            }
            else if(ZonesSection.EditZone.fields[i] == GroupSec.commentfld)
            {
                if (vctx->zf->tell(debuglvl, vctx->zone_backend, group_ptr->name, "COMMENT", field_buffer(ZonesSection.EditZone.fields[i], 0), 1, VRMR_TYPE_GROUP) < 0)
                {
                    vrmr_error(-1, VR_ERR, gettext("saving to backend failed (in: %s:%d)."), __FUNC__, __LINE__);
                    retval = -1;
                }

                /* example: "group 'it-dept.local.lan' has been changed: the comment was changed." */
                vrmr_audit("%s '%s' %s: %s.",
                    STR_GROUP, group_ptr->name, STR_HAS_BEEN_CHANGED, STR_COMMENT_CHANGED);
            }
            else if(ZonesSection.EditZone.fields[i] == GroupSec.warningfld)
            {
                /* do nothing */
            }
            else
            {
                vrmr_error(-1, VR_INTERR, "unknown field (in: %s:%d).", __FUNC__, __LINE__);
                return(-1);
            }
        }
    }

    return(retval);
}


static int
edit_zone_group_destroy(void)
{
    size_t  i = 0;

    /* Un post form and free the memory */
    unpost_form(ZonesSection.EditZone.form);
    free_form(ZonesSection.EditZone.form);

    for(i=0;i<ZonesSection.EditZone.n_fields;i++)
    {
        free_field(ZonesSection.EditZone.fields[i]);
    }
    free(ZonesSection.EditZone.fields);

    del_panel(ZonesSection.EditZone.panel[0]);
    destroy_win(ZonesSection.EditZone.win);

    /* clear comment string */
    strcpy(ZonesSection.comment, "");

    return(0);
}


/*  edit_zone_group

    Edit a group :-)

    Returncodes:
        0: ok
        -1: error
*/
static int
edit_zone_group(const int debuglvl, struct vrmr_ctx *vctx,
        struct vrmr_zones *zones, char *name)
{
    int                 ch,
                        not_defined = 0,
                        retval = 0;
    struct vrmr_zone    *zone_ptr = NULL;
    int                 quit = 0;
    FIELD               *cur = NULL,
                        *prev = NULL;
    /* top menu */
    char                *key_choices[] =    {   "F12",
                                                "F6",
                                                "F10"};
    int                 key_choices_n = 3;
    char                *cmd_choices[] =    {   gettext("help"),
                                                gettext("members"),
                                                gettext("back")};
    int                 cmd_choices_n = 3;

    /* safety */
    if(name == NULL || zones == NULL)
    {
        vrmr_error(-1, VR_INTERR, "parameter problem (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    /* search the group in mem */
    if(!(zone_ptr = vrmr_search_zonedata(debuglvl, zones, name)))
    {
        vrmr_error(-1, VR_INTERR, "group not found (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    /* loop through to get user requests */
    while(quit == 0)
    {
        /* init */
        if (edit_zone_group_init(debuglvl, vctx, zones, name, zone_ptr) < 0)
            return(-1);

        /* print (or not) initial warning about the group being empty. */
        if(zone_ptr->GroupList.len == 0)
        {
            set_field_buffer_wrap(debuglvl, GroupSec.warningfld, 0, gettext("Warning: no members!"));
            field_opts_on(GroupSec.warningfld, O_VISIBLE);
        }
        else if(zone_ptr->active == TRUE && vrmr_zones_active(debuglvl, zone_ptr) == 0)
        {
            set_field_buffer_wrap(debuglvl, GroupSec.warningfld, 0, gettext("Note: parent zone/network is inactive."));
            field_opts_on(GroupSec.warningfld, O_VISIBLE);
            set_field_status(GroupSec.warningfld, FALSE);
        }

        mvwprintw(ZonesSection.EditZone.win, 4, 37, "%s: %4d", gettext("Members"), zone_ptr->GroupList.len);

        /* print, set cursor etc */
        pos_form_cursor(ZonesSection.EditZone.form);
        cur = current_field(ZonesSection.EditZone.form);

        draw_top_menu(debuglvl, top_win, gettext("Edit Group"), key_choices_n, key_choices, cmd_choices_n, cmd_choices);

        wrefresh(ZonesSection.EditZone.win);
        update_panels();
        doupdate();

        while (quit == 0)
        {
            draw_field_active_mark(cur, prev, ZonesSection.EditZone.win, ZonesSection.EditZone.form, vccnf.color_win_mark|A_BOLD);

            /* get user input */
            ch = wgetch(ZonesSection.EditZone.win);

            not_defined = 0;

            /* handle input */
            if(cur == GroupSec.commentfld)
            {
                if(nav_field_comment(debuglvl, ZonesSection.EditZone.form, ch) < 0)
                    not_defined = 1;
            }
            else if(cur == GroupSec.activefld)
            {
                if(nav_field_yesno(debuglvl, ZonesSection.EditZone.form, ch) < 0)
                    not_defined = 1;
            }
            else
                not_defined = 1;

            /* the rest is handled here */
            if(not_defined == 1)
            {
                switch(ch)
                {
                    case KEY_F(6):
                    case 'e':
                    case 'E':

                        /* edit the members */
                        if (edit_zone_group_members(debuglvl, vctx, zones, zone_ptr) < 0)
                        {
                            retval = -1;
                            quit = 1;
                        }

                        draw_top_menu(debuglvl, top_win, gettext("Edit Group"), key_choices_n, key_choices, cmd_choices_n, cmd_choices);
                        break;

                    case 27:
                    case 'q':
                    case 'Q':
                    case KEY_F(10): /* quit */

                        quit = 1;
                        break;

                    case KEY_DOWN:
                    case 9: // tab
                    case 10:    // enter

                        form_driver(ZonesSection.EditZone.form, REQ_NEXT_FIELD);
                        form_driver(ZonesSection.EditZone.form, REQ_BEG_LINE);
                        break;

                    case KEY_UP:

                        form_driver(ZonesSection.EditZone.form, REQ_PREV_FIELD);
                        form_driver(ZonesSection.EditZone.form, REQ_BEG_LINE);
                        break;

                    case KEY_F(12):
                    case 'h':
                    case 'H':
                    case '?':

                        print_help(debuglvl, ":[VUURMUUR:ZONES:GROUP:EDIT]:");
                        break;
                }
            }

            /* before we get the new 'cur', store cur in prev */
            prev = cur;
            cur = current_field(ZonesSection.EditZone.form);

            /* draw empty group warning */
            if(zone_ptr->GroupList.len == 0)
            {
                set_field_buffer_wrap(debuglvl, GroupSec.warningfld, 0, gettext("Warning: no members!"));
                field_opts_on(GroupSec.warningfld, O_VISIBLE);
                set_field_status(GroupSec.warningfld, FALSE);
            }
            else if(strncasecmp(field_buffer(GroupSec.activefld, 0), STR_YES, StrLen(STR_YES)) == 0 &&
                vrmr_zones_active(debuglvl, zone_ptr) == 0)
            {
                set_field_buffer_wrap(debuglvl, GroupSec.warningfld, 0, gettext("Note: parent zone/network is inactive."));
                field_opts_on(GroupSec.warningfld, O_VISIBLE);
                set_field_status(GroupSec.warningfld, FALSE);
            }
            /* and clear */
            else
            {
                field_opts_off(GroupSec.warningfld, O_VISIBLE);
            }

            mvwprintw(ZonesSection.EditZone.win, 4, 37, "%s: %4d", gettext("Members"), zone_ptr->GroupList.len);

            /* refresh and restore cursor. */
            wrefresh(ZonesSection.EditZone.win);
            pos_form_cursor(ZonesSection.EditZone.form);
        }
    }

    /* save to backend */
    if(retval == 0)
    {
        if(edit_zone_group_save(debuglvl, vctx, zone_ptr) < 0)
            retval = -1;
    }

    /* cleanup */
    if(edit_zone_group_destroy() < 0)
        retval = -1;

    update_panels();
    doupdate();

    status_print(status_win, gettext("Ready."));
    return(retval);
}


static int
zones_section_menu_groups_init(const int debuglvl, struct vrmr_zones *zones, char *zonename, char *networkname)
{
    int                 retval=0;
    size_t              i = 0;
    struct vrmr_zone    *zone_ptr = NULL;
    int                 height,
                        width,
                        starty,
                        startx,
                        maxy;
    struct vrmr_list_node         *d_node = NULL;
    char                temp[32],
                        *desc_ptr = NULL;
    size_t              size = 0;

    /* safety */
    if(zones == NULL || zonename == NULL || networkname == NULL)
    {
        vrmr_error(-1, VR_INTERR, "parameter problem (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    /* get screensize */
    maxy = getmaxy(stdscr);

    /* count how many zones there are */
    ZonesSection.host_n = 0;

    for(d_node = zones->list.top; d_node ; d_node = d_node->next)
    {
        if(!(zone_ptr = d_node->data))
        {
            vrmr_error(-1, VR_INTERR, "NULL pointer (in: %s:%d).", __FUNC__, __LINE__);
            return(-1);
        }

        if(zone_ptr->type == VRMR_TYPE_GROUP)
        {
            if( strcmp(zone_ptr->zone_name, zonename) == 0 &&
                strcmp(zone_ptr->network_name, networkname) == 0)
            {
                ZonesSection.host_n++;
            }
        }
    }

    if(vrmr_list_setup(debuglvl, &ZonesSection.group_desc_list, free) < 0)
    {
        vrmr_error(-1, VR_INTERR, "vrmr_list_setup() failed (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    i = ZonesSection.host_n - 1;

    ZonesSection.hostitems = (ITEM **)calloc(ZonesSection.host_n + 1, sizeof(ITEM *));
    if(ZonesSection.hostitems == NULL)
    {
        vrmr_error(-1, VR_ERR, gettext("calloc failed: %s (in: %s:%d)."), strerror(errno), __FUNC__, __LINE__);
        return(-1);
    }

    for(d_node = zones->list.bot; d_node ; d_node = d_node->prev)
    {
        if(!(zone_ptr = d_node->data))
        {
            vrmr_error(-1, VR_INTERR, "NULL pointer (in: %s:%d).", __FUNC__, __LINE__);
            return(-1);
        }

        if(zone_ptr->type == VRMR_TYPE_GROUP)
        {
            if( strcmp(zone_ptr->zone_name, zonename) == 0 &&
                strcmp(zone_ptr->network_name, networkname) == 0)
            {
                snprintf(temp, sizeof(temp), "%6u %s", zone_ptr->GroupList.len, gettext("members"));
                size = StrMemLen(temp) + 1;

                if(!(desc_ptr = malloc(size)))
                {
                    vrmr_error(-1, VR_ERR, gettext("malloc failed: %s (in: %s:%d)."), strerror(errno), __FUNC__, __LINE__);
                    return(-1);
                }

                (void)strlcpy(desc_ptr, temp, size);

                if(vrmr_list_append(debuglvl, &ZonesSection.group_desc_list, desc_ptr)  == NULL)
                {
                    vrmr_error(-1, VR_INTERR, "vrmr_list_append() failed (in: %s:%d).", __FUNC__, __LINE__);
                    return(-1);
                }

                ZonesSection.hostitems[i] = new_item(zone_ptr->host_name, desc_ptr);
                i--;
            }
        }
    }

    ZonesSection.hostitems[ZonesSection.host_n] = (ITEM *)NULL;

    if(ZonesSection.host_n > 0)
    {
        ZonesSection.h_top = ZonesSection.hostitems[0];
        ZonesSection.h_bot = ZonesSection.hostitems[ZonesSection.host_n - 1];
    }
    else
    {
        ZonesSection.h_top = NULL;
        ZonesSection.h_bot = NULL;
    }

    ZonesSection.h_menu = new_menu((ITEM **)ZonesSection.hostitems);

    height = (int)(ZonesSection.host_n + 9);
    if (height > maxy - 8) {
        height = maxy - 8;
    }
    width = 54; // same as edit zone: group win

    /* place on the same y as zones list */
    VrWinGetOffset(-1, -1, height, width, 4, ZonesSection.n_xre + 1, &starty, &startx);
    ZonesSection.h_yle = starty + height;
    ZonesSection.h_xre = startx + width;

    ZonesSection.h_win = newwin(height, width, starty, startx);
    wbkgd(ZonesSection.h_win, vccnf.color_win);
    keypad(ZonesSection.h_win, TRUE);
    box(ZonesSection.h_win, 0, 0);
    print_in_middle(ZonesSection.h_win, 1, 0, width, gettext("Groups"), vccnf.color_win);
    wrefresh(ZonesSection.h_win);

    ZonesSection.h_panel[0] = new_panel(ZonesSection.h_win);
    update_panels();

    set_menu_win(ZonesSection.h_menu, ZonesSection.h_win);
    set_menu_sub(ZonesSection.h_menu, derwin(ZonesSection.h_win, height-7, width-2, 3, 1));

    set_menu_format(ZonesSection.h_menu, height-8, 1);

    mvwaddch(ZonesSection.h_win, 2, 0, ACS_LTEE);
    mvwhline(ZonesSection.h_win, 2, 1, ACS_HLINE, width-2);
    mvwaddch(ZonesSection.h_win, 2, width-1, ACS_RTEE);

    set_menu_back(ZonesSection.h_menu, vccnf.color_win);
    set_menu_fore(ZonesSection.h_menu, vccnf.color_win_rev);

    post_menu(ZonesSection.h_menu);
    doupdate();

    mvwaddch(ZonesSection.h_win, height-5, 0, ACS_LTEE);
    mvwhline(ZonesSection.h_win, height-5, 1, ACS_HLINE, width-2);
    mvwaddch(ZonesSection.h_win, height-5, width-1, ACS_RTEE);

    mvwprintw(ZonesSection.h_win, height-4, 1, "<RET> %s", STR_EDIT);
    mvwprintw(ZonesSection.h_win, height-3, 1, "<INS> %s", STR_NEW);
    mvwprintw(ZonesSection.h_win, height-2, 1, "<DEL> %s", STR_REMOVE);

    /* create the top and bottom fields */
    if(!(ZonesSection.h_win_top = newwin(1, 6, starty + 2, startx + width - 8)))
    {
        vrmr_error(-1, VR_ERR, gettext("creating window failed."));
        return(-1);
    }
    wbkgd(ZonesSection.h_win_top, vccnf.color_win);
    ZonesSection.h_panel_top[0] = new_panel(ZonesSection.h_win_top);
    /* TRANSLATORS: max 4 chars */
    wprintw(ZonesSection.h_win_top, "(%s)", gettext("more"));
//    hide_panel(ZonesSection.h_panel_top[0]);

    if(!(ZonesSection.h_win_bot = newwin(1, 6, starty + height - 5, startx + width - 8)))
    {
        vrmr_error(-1, VR_ERR, gettext("creating window failed."));
        return(-1);
    }
    wbkgd(ZonesSection.h_win_bot, vccnf.color_win);
    ZonesSection.h_panel_bot[0] = new_panel(ZonesSection.h_win_bot);
    /* TRANSLATORS: max 4 chars */
    wprintw(ZonesSection.h_win_bot, "(%s)", gettext("more"));
//    hide_panel(ZonesSection.h_panel_bot[0]);

    return(retval);
}


static int
zones_section_menu_groups_destroy(const int debuglvl)
{
    int     retval = 0;
    size_t  i = 0;

    unpost_menu(ZonesSection.h_menu);
    free_menu(ZonesSection.h_menu);
    for(i = 0; i < ZonesSection.host_n; ++i)
        free_item(ZonesSection.hostitems[i]);

    vrmr_list_cleanup(debuglvl, &ZonesSection.group_desc_list);

    free(ZonesSection.hostitems);

    del_panel(ZonesSection.h_panel[0]);

    destroy_win(ZonesSection.h_win);

    del_panel(ZonesSection.h_panel_top[0]);
    destroy_win(ZonesSection.h_win_top);
    del_panel(ZonesSection.h_panel_bot[0]);
    destroy_win(ZonesSection.h_win_bot);

    return(retval);
}


int
zones_section_menu_groups(const int debuglvl, struct vrmr_ctx *vctx,
        struct vrmr_zones *zones, struct vrmr_rules *rules, struct vrmr_blocklist *blocklist, char *zonename, char *networkname, struct vrmr_regex *reg)
{
    int                 ch = 0,
                        quit = 0,
                        reload = 0,
                        retval = 0;
    size_t              size = 0;
    struct vrmr_zone    *zone_ptr = NULL;
    char                *vrmr_new_zone_ptr = NULL,
                        *temp_ptr = NULL,
                        *cur_zonename_ptr = NULL;
    ITEM                *cur = NULL;
    /* top menu */
    char                *key_choices[] =    {   "F12",
                                                "INS",
                                                "DEL",
                                                "r",
                                                "RET",
                                                "e",
                                                "F10"};
    int                 key_choices_n = 7;
    char                *cmd_choices[] =    {   gettext("help"),
                                                gettext("new"),
                                                gettext("del"),
                                                gettext("rename"),
                                                gettext("open"),
                                                gettext("edit"),
                                                gettext("back")};
    int                 cmd_choices_n = 7;

    /* safety */
    if(zonename == NULL || networkname == NULL || reg == NULL || zones == NULL || rules == NULL || blocklist == NULL)
    {
        vrmr_error(-1, VR_INTERR, "parameter problem (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    /* setup */
    if (zones_section_menu_groups_init(debuglvl, zones, zonename, networkname) < 0)
    {
        vrmr_error(-1, VR_INTERR, "setting up groups menu failed (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    draw_top_menu(debuglvl, top_win, gettext("Groups"), key_choices_n, key_choices, cmd_choices_n, cmd_choices);

    while(quit == 0)
    {
        if(reload == 1)
        {
            /* first destroy */
            if(zones_section_menu_groups_destroy(debuglvl) < 0)
            {
                vrmr_error(-1, VR_INTERR, "reinitializing menu failed (in: %s:%d).", __FUNC__, __LINE__);
                return(-1);
            }

            /* and setup again */
            if(zones_section_menu_groups_init(debuglvl, zones, zonename, networkname) < 0)
            {
                vrmr_error(-1, VR_INTERR, "reinitializing menu failed (in: %s).", __FUNC__, __LINE__);
                return(-1);
            }

            /* we are done with reloading */
            reload = 0;
        }

        while(quit == 0 && reload == 0)
        {
            if(ZonesSection.h_top != NULL && !item_visible(ZonesSection.h_top))
                show_panel(ZonesSection.h_panel_top[0]);
            else
                hide_panel(ZonesSection.h_panel_top[0]);

            if(ZonesSection.h_bot != NULL && !item_visible(ZonesSection.h_bot))
                show_panel(ZonesSection.h_panel_bot[0]);
            else
                hide_panel(ZonesSection.h_panel_bot[0]);

            update_panels();
            doupdate();

            /* restore the cursor */
            pos_menu_cursor(ZonesSection.h_menu);

            ch = wgetch(ZonesSection.h_win);
            switch(ch)
            {
                case 27:
                case KEY_F(10):
                case 'q':
                case 'Q':
                
                    quit = 1;
                    break;

                case 'r':
                case 'R':

                    if(current_item(ZonesSection.h_menu))
                    {
                        /* get the current item */
                        if(!(cur = current_item(ZonesSection.h_menu)))
                        {
                            vrmr_error(-1, VR_INTERR, "NULL pointer (in: %s:%d).", __FUNC__, __LINE__);
                            return(-1);
                        }

                        // size
                        size = StrMemLen((char *)item_name(cur))+1+StrMemLen(networkname)+1+StrMemLen(zonename)+1;

                        // alloc the memory
                        if(!(cur_zonename_ptr = malloc(size)))
                        {
                            vrmr_error(-1, VR_ERR, gettext("malloc failed: %s (in: %s:%d)."), strerror(errno), __FUNC__, __LINE__);
                            return(-1);
                        }

                        // create the string
                        (void)strlcpy(cur_zonename_ptr, (char *)item_name(cur), size);
                        (void)strlcat(cur_zonename_ptr, ".", size);
                        (void)strlcat(cur_zonename_ptr, networkname, size);
                        (void)strlcat(cur_zonename_ptr, ".", size);
                        (void)strlcat(cur_zonename_ptr, zonename, size);


                        vrmr_new_zone_ptr = input_box(VRMR_MAX_HOST, gettext("Rename Group"), gettext("Enter the new name of the group"));
                        if(vrmr_new_zone_ptr != NULL)
                        {
                            if(vrmr_validate_zonename(debuglvl, vrmr_new_zone_ptr, 1, NULL, NULL, NULL, reg->host_part, VRMR_VERBOSE) == -1)
                            {
                                vrmr_warning(VR_WARN, gettext("invalid groupname '%s'."), vrmr_new_zone_ptr);
                            }
                            else
                            {
                                /* get the size */
                                size = StrMemLen(vrmr_new_zone_ptr) + 1 + StrMemLen(networkname) + 1 + StrMemLen(zonename) + 1;

                                /* alloc the memory */
                                if(!(temp_ptr = malloc(size)))
                                {
                                    vrmr_error(-1, VR_ERR, gettext("malloc failed: %s (in: %s:%d)."), strerror(errno), __FUNC__, __LINE__);
                                    return(-1);
                                }

                                /* create the string */
                                (void)strlcpy(temp_ptr, vrmr_new_zone_ptr, size);
                                (void)strlcat(temp_ptr, ".", size);
                                (void)strlcat(temp_ptr, networkname, size);
                                (void)strlcat(temp_ptr, ".", size);
                                (void)strlcat(temp_ptr, zonename, size);

                                if(vrmr_validate_zonename(debuglvl, temp_ptr, 1, NULL, NULL, NULL, reg->zonename, VRMR_VERBOSE) == -1)
                                {
                                    vrmr_warning(VR_WARN, gettext("invalid groupname '%s'."), temp_ptr);
                                }
                                else
                                {
                                    if (zones_rename_host_group(debuglvl, vctx, zones, rules, blocklist, cur_zonename_ptr, temp_ptr, VRMR_TYPE_GROUP, reg) == 0)
                                    {
                                        /* we have a new host, so reload the menu */
                                        reload = 1;
                                    }
                                }
                                free(temp_ptr);
                            }
                            free(vrmr_new_zone_ptr);
                        }

                        free(cur_zonename_ptr);
                    }
                    break;

                case KEY_IC: //insert
                case 'i':
                case 'I':

                    vrmr_new_zone_ptr = input_box(VRMR_MAX_HOST, gettext("New Group"), gettext("Enter the name of the new group"));
                    if(vrmr_new_zone_ptr != NULL)
                    {
                        if(vrmr_validate_zonename(debuglvl, vrmr_new_zone_ptr, 1, NULL, NULL, NULL, reg->host_part, VRMR_VERBOSE) == -1)
                        {
                            vrmr_warning(VR_WARN, gettext("invalid groupname '%s'."), vrmr_new_zone_ptr);
                        }
                        else
                        {
                            size = StrMemLen(vrmr_new_zone_ptr)+1+StrMemLen(networkname)+1+StrMemLen(zonename)+1;

                            temp_ptr = malloc(size);
                            if(temp_ptr != NULL)
                            {
                                (void)strlcpy(temp_ptr, vrmr_new_zone_ptr, size);
                                (void)strlcat(temp_ptr, ".", size);
                                (void)strlcat(temp_ptr, networkname, size);
                                (void)strlcat(temp_ptr, ".", size);
                                (void)strlcat(temp_ptr, zonename, size);

                                if(vrmr_validate_zonename(debuglvl, temp_ptr, 1, NULL, NULL, NULL, reg->zonename, VRMR_VERBOSE) == 0)
                                {
                                    if (vrmr_new_zone(debuglvl, vctx, zones, temp_ptr, VRMR_TYPE_GROUP) >= 0)
                                    {
                                        vrmr_audit("%s '%s' %s.", STR_GROUP, temp_ptr, STR_HAS_BEEN_CREATED);

                                        (void)edit_zone_group(debuglvl, vctx, zones, temp_ptr);
                                        draw_top_menu(debuglvl, top_win, gettext("Groups"), key_choices_n, key_choices, cmd_choices_n, cmd_choices);
                                    }
                                    else
                                    {
                                        vrmr_error(-1, VR_ERR, gettext("failed to create new group."));
                                    }

                                    reload = 1;
                                }
                                else
                                {
                                    vrmr_warning(VR_WARN, gettext("groupname '%s' is invalid."), temp_ptr);
                                }
                            }
                            else
                            {
                                vrmr_error(-1, VR_ERR, gettext("malloc failed: %s (in: %s:%d)."), strerror(errno), __FUNC__, __LINE__);
                            }
                            free(temp_ptr);
                        }

                        free(vrmr_new_zone_ptr);
                    }
                    break;

                case KEY_DC: // delete
                case 'd':
                case 'D':

                    cur = current_item(ZonesSection.h_menu);
                    if(cur)
                    {
                        if (confirm(gettext("Delete"), gettext("This group?"),
                                    vccnf.color_win_note, vccnf.color_win_note_rev|A_BOLD, 0) == 1)
                        {
                            size = StrMemLen((char *)item_name(cur))+1+StrMemLen(networkname)+1+StrMemLen(zonename)+1;
                    
                            if(!(temp_ptr = malloc(size)))
                            {
                                vrmr_error(-1, VR_ERR, gettext("malloc failed: %s (in: %s:%d)."), strerror(errno), __FUNC__, __LINE__);
                                return(-1);
                            }
                            
                            (void)strlcpy(temp_ptr, (char *)item_name(cur), size);
                            (void)strlcat(temp_ptr, ".", size);
                            (void)strlcat(temp_ptr, networkname, size);
                            (void)strlcat(temp_ptr, ".", size);
                            (void)strlcat(temp_ptr, zonename, size);

                            /* search the zone */
                            if(!(zone_ptr = vrmr_search_zonedata(debuglvl, zones, temp_ptr)))
                            {
                                vrmr_error(-1, VR_INTERR, "couldn't find the group '%s' in memory.", temp_ptr);
                                return(-1);
                            }

                            if(zone_ptr->refcnt_blocklist > 0)
                            {
                                vrmr_error(-1, VR_ERR, gettext("group '%s' is still in the blocklist (%u times)."),
                                                        zone_ptr->name, zone_ptr->refcnt_blocklist);
                            }
                            else
                            {
                                /* delete, the memory is freed by vrmr_delete_zone(). */
                                if (vrmr_delete_zone(debuglvl, vctx, zones, temp_ptr, zone_ptr->type) < 0)
                                {
                                    vrmr_error(-1, VR_ERR, gettext("deleting group failed."));
                                }
                                else
                                {
                                    vrmr_audit("%s '%s' %s.", STR_GROUP, temp_ptr, STR_HAS_BEEN_DELETED);
                                    reload = 1;
                                }
                            }

                            free(temp_ptr);
                        }
                    }

                    break;

                case KEY_DOWN:
                    menu_driver(ZonesSection.h_menu, REQ_DOWN_ITEM);
                    break;
                case KEY_UP:
                    menu_driver(ZonesSection.h_menu, REQ_UP_ITEM);
                    break;
                case KEY_NPAGE:
                    if(menu_driver(ZonesSection.h_menu, REQ_SCR_DPAGE) != E_OK)
                    {
                        while(menu_driver(ZonesSection.h_menu, REQ_DOWN_ITEM) == E_OK);
                    }
                    break;
                case KEY_PPAGE:
                    if(menu_driver(ZonesSection.h_menu, REQ_SCR_UPAGE) != E_OK)
                    {
                        while(menu_driver(ZonesSection.h_menu, REQ_UP_ITEM) == E_OK);
                    }
                    break;
                case KEY_HOME:
                    menu_driver(ZonesSection.h_menu, REQ_FIRST_ITEM);   // home
                    break;
                case KEY_END:
                    menu_driver(ZonesSection.h_menu, REQ_LAST_ITEM);    // end
                    break;

                case 32: // space
                case KEY_RIGHT:
                case 10: // enter
                case 'e':
                case 'E':

                    cur = current_item(ZonesSection.h_menu);
                    if(cur)
                    {
                        size = StrMemLen((char *)item_name(cur))+1+StrMemLen(networkname)+1+StrMemLen(zonename)+1;

                        if(!(temp_ptr = malloc(size)))
                        {
                            vrmr_error(-1, VR_ERR, gettext("malloc failed: %s (in: %s:%d)."), strerror(errno), __FUNC__, __LINE__);
                            return(-1);
                        }

                        (void)strlcpy(temp_ptr, (char *)item_name(cur), size);
                        (void)strlcat(temp_ptr, ".", size);
                        (void)strlcat(temp_ptr, networkname, size);
                        (void)strlcat(temp_ptr, ".", size);
                        (void)strlcat(temp_ptr, zonename, size);

                        zone_ptr = vrmr_search_zonedata(debuglvl, zones, temp_ptr);
                        if(zone_ptr != NULL)
                        {
                            (void)edit_zone_group(debuglvl, vctx, zones, zone_ptr->name);
                            draw_top_menu(debuglvl, top_win, gettext("Groups"), key_choices_n, key_choices, cmd_choices_n, cmd_choices);
                            reload = 1;
                        }
                        else
                        {
                            vrmr_error(-1, VR_INTERR, "group '%s' not found in memory.", temp_ptr);
                        }

                        free(temp_ptr);
                    }
                    break;

                case KEY_F(12):
                case 'h':
                case 'H':
                case '?':

                    print_help(debuglvl, ":[VUURMUUR:ZONES:GROUPS]:");
                    break;
            }
        }
    }

    if(zones_section_menu_groups_destroy(debuglvl) < 0)
        retval = -1;

    update_panels();
    doupdate();

    status_print(status_win, gettext("Ready."));
    return(retval);
}


/* rename a network or a zone */
static int
zones_rename_network_zone(const int debuglvl, struct vrmr_ctx *vctx, struct vrmr_zones *zones, struct vrmr_rules *rules, struct vrmr_blocklist *blocklist, char *cur_name_ptr, char *new_name_ptr, int type, struct vrmr_regex *reg)
{
    int                 result = 0;
    struct vrmr_zone    *zone_ptr = NULL;
    struct vrmr_rule    *rule_ptr = NULL;
    struct vrmr_list_node         *d_node = NULL;
    char                rules_changed = 0,
                        blocklist_changed = 0;
    char                old_name[VRMR_MAX_NET_ZONE] = "",
                        new_host[VRMR_MAX_HOST] = "",
                        new_net[VRMR_MAX_NETWORK] = "",
                        vrmr_new_zone[VRMR_MAX_ZONE] = "",
                        rule_host[VRMR_MAX_HOST] = "",
                        rule_net[VRMR_MAX_NETWORK] = "",
                        rule_zone[VRMR_MAX_ZONE] = "",
                        old_host[VRMR_MAX_HOST] = "",
                        old_net[VRMR_MAX_NETWORK] = "",
                        old_zone[VRMR_MAX_ZONE] = "";
    char                *blocklist_item = NULL,
                        *new_blocklist_item = NULL;
    size_t              size = 0;

    /* safety */
    if(cur_name_ptr == NULL || new_name_ptr == NULL || zones == NULL || rules == NULL || reg == NULL || blocklist == NULL)
    {
        vrmr_error(-1, VR_INTERR, "parameter problem (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    if(type != VRMR_TYPE_NETWORK && type != VRMR_TYPE_ZONE)
    {
        vrmr_error(-1, VR_INTERR, "this function can only be used to rename a network or a zone (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    /* validate and split the new name */
    if(vrmr_validate_zonename(debuglvl, new_name_ptr, 0, vrmr_new_zone, new_net, new_host, reg->zonename, VRMR_VERBOSE) != 0)
    {
        vrmr_error(-1, VR_INTERR, "invalid name '%s' (in: %s:%d).", new_name_ptr, __FUNC__, __LINE__);
        return(-1);
    }
    if(debuglvl >= HIGH)
        vrmr_debug(__FUNC__, "new_name_ptr: '%s': host/group '%s', net '%s', zone '%s'.", new_name_ptr, new_host, new_net, vrmr_new_zone);

    /* validate and split the old name */
    if(vrmr_validate_zonename(debuglvl, cur_name_ptr, 0, old_zone, old_net, old_host, reg->zonename, VRMR_VERBOSE) != 0)
    {
        vrmr_error(-1, VR_INTERR, "invalid name '%s' (in: %s:%d).", cur_name_ptr, __FUNC__, __LINE__);
        return(-1);
    }
    if(debuglvl >= HIGH)
        vrmr_debug(__FUNC__, "cur_name_ptr: '%s': host/group '%s', net '%s', zone '%s'.", cur_name_ptr, old_host, old_net, old_zone);

    /* store the old name */
    if(strlcpy(old_name, cur_name_ptr, sizeof(old_name)) >= sizeof(old_name))
    {
        vrmr_error(-1, VR_INTERR, "name overflow (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }
    if(debuglvl >= HIGH)
        vrmr_debug(__FUNC__, "going to rename network/zone old_name:'%s' to new_name_ptr:'%s'.", old_name, new_name_ptr);

    /* rename in the backend */
    result = vctx->zf->rename(debuglvl, vctx->zone_backend, old_name, new_name_ptr, type);
    if(result != 0)
    {
        return(-1);
    }

    /* search the zone in the list */
    if(!(zone_ptr = vrmr_search_zonedata(debuglvl, zones, old_name)))
    {
        vrmr_error(-1, VR_INTERR, "network/zone not found in the list (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    if(strlcpy(zone_ptr->name, new_name_ptr, sizeof(zone_ptr->name)) >= sizeof(zone_ptr->name))
    {
        vrmr_error(-1, VR_INTERR, "name overflow (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }
    if(type == VRMR_TYPE_ZONE)
    {
        if(strlcpy(zone_ptr->zone_name, vrmr_new_zone, sizeof(zone_ptr->zone_name)) >= sizeof(zone_ptr->zone_name))
        {
            vrmr_error(-1, VR_INTERR, "name overflow (in: %s:%d).", __FUNC__, __LINE__);
            return(-1);
        }
    }
    else
    {
        if(strlcpy(zone_ptr->network_name, new_net, sizeof(zone_ptr->network_name)) >= sizeof(zone_ptr->network_name))
        {
            vrmr_error(-1, VR_INTERR, "name overflow (in: %s:%d).", __FUNC__, __LINE__);
            return(-1);
        }
    }
    zone_ptr = NULL;


    /* check the blocklist */
    for(d_node = blocklist->list.top; d_node; d_node = d_node->next)
    {
        blocklist_item = d_node->data;
        if(blocklist_item == NULL)
        {
            vrmr_error(-1, VR_INTERR, "NULL pointer (in: %s:%d).", __FUNC__, __LINE__);
            return(-1);
        }

        /* call vrmr_check_ipv4address with the quiet flag */
        if(vrmr_check_ipv4address(debuglvl, NULL, NULL, blocklist_item, 1) != 1)
        {
            /* search for the name in the zones list */
            if((zone_ptr = vrmr_search_zonedata(debuglvl, zones, blocklist_item)))
            {
                if( (type == VRMR_TYPE_NETWORK && strcmp(zone_ptr->network_name, old_net) == 0) ||
                    (type == VRMR_TYPE_ZONE && strcmp(zone_ptr->zone_name, old_zone) == 0))
                {
                    if(type == VRMR_TYPE_NETWORK)
                        size = StrMemLen(zone_ptr->host_name) + 1 + StrMemLen(new_net) + 1 + StrMemLen(zone_ptr->zone_name) + 1;
                    else
                        size = StrMemLen(zone_ptr->host_name) + 1 + StrMemLen(zone_ptr->network_name) + 1 + StrMemLen(vrmr_new_zone) + 1;

                    new_blocklist_item = malloc(size);
                    if(new_blocklist_item == NULL)
                    {
                        vrmr_error(-1, VR_ERR, gettext("malloc failed: %s (in: %s:%d)."), strerror(errno), __FUNC__, __LINE__);
                        return(-1);
                    }

                    if(type == VRMR_TYPE_NETWORK)
                    {
                        if(snprintf(new_blocklist_item, size, "%s.%s.%s", zone_ptr->host_name, new_net, zone_ptr->zone_name) >= (int)size)
                        {
                            vrmr_error(-1, VR_INTERR, "buffer overflow (in: %s:%d).", __FUNC__, __LINE__);

                            free(new_blocklist_item);
                            return(-1);
                        }
                    }
                    else
                    {
                        if(snprintf(new_blocklist_item, size, "%s.%s.%s", zone_ptr->host_name, zone_ptr->network_name, vrmr_new_zone) >= (int)size)
                        {
                            vrmr_error(-1, VR_INTERR, "buffer overflow (in: %s:%d).", __FUNC__, __LINE__);

                            free(new_blocklist_item);
                            return(-1);
                        }
                    }

                    /* swap the items */
                    free(blocklist_item);
                    d_node->data = new_blocklist_item;

                    blocklist_changed = 1;
                }
            }
        }
    }
    /* if we have made changes we write the blocklistfile */
    if(blocklist_changed == 1)
    {
        if(vrmr_blocklist_save_list(debuglvl, vctx, &vctx->conf, blocklist) < 0)
            return(-1);
    }


    /* update all hosts, groups, networks */
    for(d_node = zones->list.top; d_node; d_node = d_node->next)
    {
        zone_ptr = d_node->data;
        if(zone_ptr == NULL)
        {
            vrmr_error(-1, VR_INTERR, "NULL pointer (in: %s:%d).", __FUNC__, __LINE__);
            return(-1);
        }

        /* change full name and the network or zonename */
        if(type == VRMR_TYPE_ZONE)
        {
            if(strcmp(old_zone, zone_ptr->zone_name) == 0)
            {
                if(zone_ptr->type == VRMR_TYPE_HOST || zone_ptr->type == VRMR_TYPE_GROUP)
                {
                    if(strlcpy(zone_ptr->zone_name, vrmr_new_zone, sizeof(zone_ptr->zone_name)) >= sizeof(zone_ptr->zone_name))
                    {
                        vrmr_error(-1, VR_INTERR, "name overflow (in: %s:%d).", __FUNC__, __LINE__);
                        return(-1);
                    }

                    if(snprintf(zone_ptr->name, sizeof(zone_ptr->name), "%s.%s.%s", zone_ptr->host_name, zone_ptr->network_name, zone_ptr->zone_name) >= (int)sizeof(zone_ptr->name))
                    {
                        vrmr_error(-1, VR_INTERR, "buffer overflow (in: %s:%d).", __FUNC__, __LINE__);
                        return(-1);
                    }
                }
                else if(zone_ptr->type == VRMR_TYPE_NETWORK)
                {
                    if(strlcpy(zone_ptr->zone_name, vrmr_new_zone, sizeof(zone_ptr->zone_name)) >= sizeof(zone_ptr->zone_name))
                    {
                        vrmr_error(-1, VR_INTERR, "name overflow (in: %s:%d).", __FUNC__, __LINE__);
                        return(-1);
                    }

                    if(snprintf(zone_ptr->name, sizeof(zone_ptr->name), "%s.%s", zone_ptr->network_name, zone_ptr->zone_name) >= (int)sizeof(zone_ptr->name))
                    {
                        vrmr_error(-1, VR_INTERR, "buffer overflow (in: %s:%d).", __FUNC__, __LINE__);
                        return(-1);
                    }
                }
            }
        }
        else if(type == VRMR_TYPE_NETWORK)
        {
            if(strcmp(old_net, zone_ptr->network_name) == 0)
            {
                if(zone_ptr->type == VRMR_TYPE_HOST || zone_ptr->type == VRMR_TYPE_GROUP)
                {
                    if(strlcpy(zone_ptr->network_name, new_net, sizeof(zone_ptr->network_name)) >= sizeof(zone_ptr->network_name))
                    {
                        vrmr_error(-1, VR_INTERR, "name overflow (in: %s:%d).", __FUNC__, __LINE__);
                        return(-1);
                    }

                    if(snprintf(zone_ptr->name, sizeof(zone_ptr->name), "%s.%s.%s", zone_ptr->host_name, zone_ptr->network_name, zone_ptr->zone_name) >= (int)sizeof(zone_ptr->name))
                    {
                        vrmr_error(-1, VR_INTERR, "buffer overflow (in: %s:%d).", __FUNC__, __LINE__);
                        return(-1);
                    }
                }
            }
        }
    }


    /* update rules */
    for(d_node = rules->list.top; d_node; d_node = d_node->next)
    {
        rule_ptr = d_node->data;
        if(rule_ptr == NULL)
        {
            vrmr_error(-1, VR_INTERR, "NULL pointer (in: %s:%d).", __FUNC__, __LINE__);
            return(-1);
        }
        if(debuglvl >= HIGH)
            vrmr_debug(__FUNC__, "from: '%s', to: '%s'.", rule_ptr->from, rule_ptr->to);

        /* check for firewall and empty field */
        if(strncasecmp(rule_ptr->from, "firewall", 8) != 0 && strcmp(rule_ptr->from, "") != 0)
        {
            /* check the fromname */
            if(vrmr_validate_zonename(debuglvl, rule_ptr->from, 0, rule_zone, rule_net, rule_host, reg->zonename, VRMR_VERBOSE) != 0)
            {
                vrmr_error(-1, VR_INTERR, "invalid name '%s' (in: %s:%d).", rule_ptr->from, __FUNC__, __LINE__);
                return(-1);
            }
            if(debuglvl >= HIGH)
                vrmr_debug(__FUNC__, "rule_ptr->from: '%s': host/group '%s', net '%s', zone '%s'.", rule_ptr->from, rule_host, rule_net, rule_zone);

            if( (type == VRMR_TYPE_NETWORK && strcmp(rule_net, old_net) == 0 && strcmp(rule_zone, old_zone) == 0) ||
                (type == VRMR_TYPE_ZONE && strcmp(rule_zone, old_zone) == 0))
            {
                if(type == VRMR_TYPE_NETWORK)
                {
                    if(rule_host[0] == '\0')
                    {
                        if(snprintf(rule_ptr->from, sizeof(rule_ptr->to), "%s.%s", new_net, rule_zone) >= (int)sizeof(rule_ptr->to))
                        {
                            vrmr_error(-1, VR_INTERR, "buffer overflow (in: %s:%d).", __FUNC__, __LINE__);
                            return(-1);
                        }
                    }
                    else
                    {
                        if(snprintf(rule_ptr->from, sizeof(rule_ptr->from), "%s.%s.%s", rule_host, new_net, rule_zone) >= (int)sizeof(rule_ptr->from))
                        {
                            vrmr_error(-1, VR_INTERR, "buffer overflow (in: %s:%d).", __FUNC__, __LINE__);
                            return(-1);
                        }
                    }
                }
                else
                {
                    if(rule_host[0] == '\0')
                    {
                        if(snprintf(rule_ptr->from, sizeof(rule_ptr->to), "%s.%s", rule_net, vrmr_new_zone) >= (int)sizeof(rule_ptr->to))
                        {
                            vrmr_error(-1, VR_INTERR, "buffer overflow (in: %s:%d).", __FUNC__, __LINE__);
                            return(-1);
                        }
                    }
                    else
                    {
                        if(snprintf(rule_ptr->from, sizeof(rule_ptr->from), "%s.%s.%s", rule_host, rule_net, vrmr_new_zone) >= (int)sizeof(rule_ptr->from))
                        {
                            vrmr_error(-1, VR_INTERR, "buffer overflow (in: %s:%d).", __FUNC__, __LINE__);
                            return(-1);
                        }
                    }
                }

                rules_changed = 1;
            } /* end if firewall */
        }

        /* check for firewall and empty field */
        if(strncasecmp(rule_ptr->to, "firewall", 8) != 0 && strcmp(rule_ptr->to, "") != 0)
        {
            /* check the toname */
            if(vrmr_validate_zonename(debuglvl, rule_ptr->to, 0, rule_zone, rule_net, rule_host, reg->zonename, VRMR_VERBOSE) != 0)
            {
                vrmr_error(-1, VR_INTERR, "invalid name '%s' (in: %s:%d).", rule_ptr->to, __FUNC__, __LINE__);
                return(-1);
            }
            if(debuglvl >= HIGH)
                vrmr_debug(__FUNC__, "rule_ptr->to: '%s': host/group '%s', net '%s', zone '%s'.", rule_ptr->to, rule_host, rule_net, rule_zone);

            if( (type == VRMR_TYPE_NETWORK && strcmp(rule_net, old_net) == 0 && strcmp(rule_zone, old_zone) == 0) ||
                (type == VRMR_TYPE_ZONE && strcmp(rule_zone, old_zone) == 0))
            {
                if(type == VRMR_TYPE_NETWORK)
                {
                    if(rule_host[0] == '\0')
                    {
                        if(snprintf(rule_ptr->to, sizeof(rule_ptr->to), "%s.%s", new_net, rule_zone) >= (int)sizeof(rule_ptr->to))
                        {
                            vrmr_error(-1, VR_INTERR, "buffer overflow (in: %s:%d).", __FUNC__, __LINE__);
                            return(-1);
                        }
                    }
                    else
                    {
                        if(snprintf(rule_ptr->to, sizeof(rule_ptr->to), "%s.%s.%s", rule_host, new_net, rule_zone) >= (int)sizeof(rule_ptr->to))
                        {
                            vrmr_error(-1, VR_INTERR, "buffer overflow (in: %s:%d).", __FUNC__, __LINE__);
                            return(-1);
                        }
                    }
                }
                else
                {
                    if(rule_host[0] == '\0')
                    {
                        if(snprintf(rule_ptr->to, sizeof(rule_ptr->to), "%s.%s", rule_net, vrmr_new_zone) >= (int)sizeof(rule_ptr->to))
                        {
                            vrmr_error(-1, VR_INTERR, "buffer overflow (in: %s:%d).", __FUNC__, __LINE__);
                            return(-1);
                        }
                    }
                    else
                    {
                        if(snprintf(rule_ptr->to, sizeof(rule_ptr->to), "%s.%s.%s", rule_host, rule_net, vrmr_new_zone) >= (int)sizeof(rule_ptr->to))
                        {
                            vrmr_error(-1, VR_INTERR, "buffer overflow (in: %s:%d).", __FUNC__, __LINE__);
                            return(-1);
                        }
                    }
                }

                rules_changed = 1;
            }
        }
    }
    /* if we have made changes we write the rulesfile */
    if(rules_changed == 1)
    {
        if(vrmr_rules_save_list(debuglvl, vctx, rules, &vctx->conf) < 0)
        {
            vrmr_error(-1, VR_ERR, gettext("saving rules failed."));
            return(-1);
        }
    }

    if(type == VRMR_TYPE_ZONE)
        vrmr_audit("%s '%s' %s '%s'.", STR_ZONE, old_name, STR_HAS_BEEN_RENAMED_TO, new_name_ptr);
    else
        vrmr_audit("%s '%s' %s '%s'.", STR_NETWORK, old_name, STR_HAS_BEEN_RENAMED_TO, new_name_ptr);

    return(0);
}


static int
edit_zone_network_interfaces_newiface(const int debuglvl, struct vrmr_ctx *vctx,
        struct vrmr_interfaces *interfaces, struct vrmr_zone *zone_ptr)
{
    struct vrmr_list_node   *d_node = NULL;
    char                    **choices,
                            *choice_ptr = NULL;
    size_t                  n_choices = 0,
                            i = 0;
    struct vrmr_interface   *iface_ptr = NULL;
    int                     result = 0;

    /* safety */
    if(!zone_ptr || !interfaces)
    {
        vrmr_error(-1, VR_INTERR, "parameter problem (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    /* check if there are interfaces defined to choose from */
    if((n_choices = interfaces->list.len) == 0)
    {
        vrmr_warning(VR_WARN, gettext("no interfaces found. Please define an interface first."));
        return(0);
    }

    /* get some mem */
    if(!(choices = calloc(n_choices + 1, VRMR_MAX_INTERFACE)))
    {
        vrmr_error(-1, VR_ERR, gettext("calloc failed: %s (in: %s:%d)."), strerror(errno), __FUNC__, __LINE__);
        return(-1);
    }

    /* load the interfaces */
    for(i = n_choices-1, d_node = interfaces->list.bot; d_node ; d_node = d_node->prev)
    {
        if(!(iface_ptr = d_node->data))
        {
            vrmr_error(-1, VR_INTERR, "NULL pointer (in: %s:%d).", __FUNC__, __LINE__);

            free(choices);
            return(-1);
        }

        choices[i] = iface_ptr->name;
        i--;
    }

    /* ask the user to select an interface */
    if(!(choice_ptr = selectbox(gettext("New interface"), gettext("Select an interface"), n_choices, choices, 1, NULL)))
    {
        /* no choice */
        free(choices);
        return(0);
    }

    /* cleanup */
    free(choices);

    /* add the int */
    result = vrmr_zones_network_add_iface(debuglvl, interfaces, zone_ptr, choice_ptr);
    if(result < 0)
    {
        free(choice_ptr);
        return(-1);
    }

    /* save the new interface list */
    if (vrmr_zones_network_save_interfaces(debuglvl, vctx, zone_ptr) < 0)
    {
        vrmr_error(-1, VR_ERR, gettext("saving the interfaces failed."));
        return(-1);
    }

    vrmr_audit("%s '%s' %s: %s: '%s'.",
        STR_INTERFACE, zone_ptr->name, STR_HAS_BEEN_CHANGED,
        STR_AN_IFACE_HAS_BEEN_ADDED, choice_ptr);

    free(choice_ptr);
    return(0);
}


static int
edit_zone_network_interfaces_init(const int debuglvl, struct vrmr_zone *zone_ptr)
{
    struct vrmr_list_node             *d_node = NULL;
    struct vrmr_interface   *iface_ptr = NULL;
    int                     i=0;
    int                     height = 30,
                            width  = 34, // max width of interface (32) + box (2)
                            startx = 5,
                            starty = 5,
                            max_height = 0;

    /* safety */
    if(!zone_ptr)
    {
        vrmr_error(-1, VR_INTERR, "parameter problem (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }
    if(zone_ptr->type != VRMR_TYPE_NETWORK)
    {
        vrprint.error(-1, VR_INTERR, "expected a VRMR_TYPE_NETWORK (%d), but got a %d (in: %s:%d).", VRMR_TYPE_NETWORK, zone_ptr->type, __FUNC__, __LINE__);
        return(-1);
    }

    ZonesSection.EditZoneInt.n_items = zone_ptr->InterfaceList.len;

    if(!(ZonesSection.EditZoneInt.items = (ITEM **)calloc(ZonesSection.EditZoneInt.n_items + 1, sizeof(ITEM *))))
    {
        vrmr_error(-1, VR_ERR, gettext("calloc failed: %s (in: %s:%d)."), strerror(errno), __FUNC__, __LINE__);
        return(-1);
    }

    max_height = getmaxy(stdscr);

    height = (int)(ZonesSection.EditZoneInt.n_items + 7); // 7 because: 3 above the list, 4 below
    if(height >= max_height - starty - 3)
    {
        height = max_height - 6;
        starty = 3;
    }

    for(i = 0, d_node = zone_ptr->InterfaceList.top; d_node; d_node = d_node->next, i++)
    {
        if(!(iface_ptr = d_node->data))
        {
            vrmr_error(-1, VR_INTERR, "NULL pointer (in: %s:%d).", __FUNC__, __LINE__);
            return(-1);
        }

        /* load all interfaces into memory */
        if(!(ZonesSection.EditZoneInt.items[i] = new_item(iface_ptr->name, NULL)))
        {
            vrmr_error(-1, VR_INTERR, "new_item() failed (in: %s:%d).", __FUNC__, __LINE__);
            return(-1);
        }
    }
    ZonesSection.EditZoneInt.items[ZonesSection.EditZoneInt.n_items] = (ITEM *)NULL;

    if(ZonesSection.EditZoneInt.n_items > 0)
    {
        ZonesSection.EditZoneInt.top = ZonesSection.EditZoneInt.items[0];
        ZonesSection.EditZoneInt.bot = ZonesSection.EditZoneInt.items[ZonesSection.EditZoneInt.n_items - 1];
    }
    else
    {
        ZonesSection.EditZoneInt.top = NULL;
        ZonesSection.EditZoneInt.bot = NULL;
    }

    /* create the window */
    if(!(ZonesSection.EditZoneInt.win = newwin(height, width, starty, startx)))
    {
        vrmr_error(-1, VR_INTERR, "newwin() failed (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }
    if(!(ZonesSection.EditZoneInt.panel[0] = new_panel(ZonesSection.EditZoneInt.win)))
    {
        vrmr_error(-1, VR_INTERR, "new_panel() failed (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }
    wbkgd(ZonesSection.EditZoneInt.win, vccnf.color_win);
    keypad(ZonesSection.EditZoneInt.win, TRUE);
    wrefresh(ZonesSection.EditZoneInt.win);

    if(!(ZonesSection.EditZoneInt.menu = new_menu((ITEM **)ZonesSection.EditZoneInt.items)))
    {
        vrmr_error(-1, VR_INTERR, "new_menu() failed (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }
    set_menu_win(ZonesSection.EditZoneInt.menu, ZonesSection.EditZoneInt.win);
    set_menu_sub(ZonesSection.EditZoneInt.menu, derwin(ZonesSection.EditZoneInt.win, height-6, width-2, 3, 1));
    set_menu_format(ZonesSection.EditZoneInt.menu, height-7, 1);

    box(ZonesSection.EditZoneInt.win, 0, 0);
    print_in_middle(ZonesSection.EditZoneInt.win, 1, 0, width, gettext("Interfaces"), vccnf.color_win);
    mvwaddch(ZonesSection.EditZoneInt.win, 2, 0, ACS_LTEE);
    mvwhline(ZonesSection.EditZoneInt.win, 2, 1, ACS_HLINE, width-2);
    mvwaddch(ZonesSection.EditZoneInt.win, 2, width - 1, ACS_RTEE);
    set_menu_back(ZonesSection.EditZoneInt.menu, vccnf.color_win);
    set_menu_fore(ZonesSection.EditZoneInt.menu, vccnf.color_win_rev);
    post_menu(ZonesSection.EditZoneInt.menu);

    mvwaddch(ZonesSection.EditZoneInt.win, height-4, 0, ACS_LTEE);
    mvwhline(ZonesSection.EditZoneInt.win, height-4, 1, ACS_HLINE, width-2);
    mvwaddch(ZonesSection.EditZoneInt.win, height-4, width-1, ACS_RTEE);

    mvwprintw(ZonesSection.EditZoneInt.win, height-3, 2, "<INS> %s", STR_NEW);
    mvwprintw(ZonesSection.EditZoneInt.win, height-2, 2, "<DEL> %s", STR_REMOVE);

    /* create the top and bottom fields */
    if(!(ZonesSection.EditZoneInt.win_top = newwin(1, 6, starty + 2, width - 6)))
    {
        vrmr_error(-1, VR_ERR, gettext("creating window failed."));
        return(-1);
    }
    wbkgd(ZonesSection.EditZoneInt.win_top, vccnf.color_win);
    ZonesSection.EditZoneInt.panel_top[0] = new_panel(ZonesSection.EditZoneInt.win_top);
    /* TRANSLATORS: max 4 chars */
    wprintw(ZonesSection.EditZoneInt.win_top, "(%s)", gettext("more"));
    hide_panel(ZonesSection.EditZoneInt.panel_top[0]);

    if(!(ZonesSection.EditZoneInt.win_bot = newwin(1, 6, starty + height - 4, width - 6)))
    {
        vrmr_error(-1, VR_ERR, gettext("creating window failed."));
        return(-1);
    }
    wbkgd(ZonesSection.EditZoneInt.win_bot, vccnf.color_win);
    ZonesSection.EditZoneInt.panel_bot[0] = new_panel(ZonesSection.EditZoneInt.win_bot);
    /* TRANSLATORS: max 4 chars */
    wprintw(ZonesSection.EditZoneInt.win_bot, "(%s)", gettext("more"));
    hide_panel(ZonesSection.EditZoneInt.panel_bot[0]);

    update_panels();
    doupdate();

    return(0);
}


static int
edit_zone_network_interfaces_destroy(void)
{
    int     retval = 0;
    size_t  i = 0;

    /* un post form and free the memory */
    unpost_menu(ZonesSection.EditZoneInt.menu);
    free_menu(ZonesSection.EditZoneInt.menu);

    for(i=0;i<ZonesSection.EditZoneInt.n_items;i++)
    {
        free_item(ZonesSection.EditZoneInt.items[i]);
    }
    free(ZonesSection.EditZoneInt.items);

    del_panel(ZonesSection.EditZoneInt.panel[0]);
    del_panel(ZonesSection.EditZoneInt.panel_top[0]);
    del_panel(ZonesSection.EditZoneInt.panel_bot[0]);
    destroy_win(ZonesSection.EditZoneInt.win);
    return(retval);
}


static int
edit_zone_network_interfaces(const int debuglvl, struct vrmr_ctx *vctx,
        struct vrmr_interfaces *interfaces, struct vrmr_zone *zone_ptr)
{
    int     quit = 0,
            reload = 0,
            result = 0,
            ch,
            retval = 0;
    ITEM    *cur = NULL;
    char    save_iface[VRMR_MAX_INTERFACE] = "";

    /* safety */
    if(zone_ptr == NULL || interfaces == NULL)
    {
        vrmr_error(-1, VR_INTERR, "parameter problem (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }
    
    if(edit_zone_network_interfaces_init(debuglvl, zone_ptr) < 0)
    {
        vrmr_error(-1, VR_INTERR, "edit_zone_network_interfaces_init() failed (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    while(quit == 0)
    {
        if(reload == 1)
        {
            if(edit_zone_network_interfaces_destroy() < 0)
                return(-1);

            if(edit_zone_network_interfaces_init(debuglvl, zone_ptr) < 0)
                return(-1);

            /* refresh screen */
            update_panels();
            doupdate();
            
            reload = 0;
        }

        while(quit == 0 && reload == 0)
        {
            if(ZonesSection.EditZoneInt.top != NULL && !item_visible(ZonesSection.EditZoneInt.top))
                show_panel(ZonesSection.EditZoneInt.panel_top[0]);
            else
                hide_panel(ZonesSection.EditZoneInt.panel_top[0]);

            if(ZonesSection.EditZoneInt.bot != NULL && !item_visible(ZonesSection.EditZoneInt.bot))
                show_panel(ZonesSection.EditZoneInt.panel_bot[0]);
            else
                hide_panel(ZonesSection.EditZoneInt.panel_bot[0]);

            update_panels();
            doupdate();

            /* restore the cursor */
            pos_menu_cursor(ZonesSection.EditZoneInt.menu);

            ch = wgetch(ZonesSection.EditZoneInt.win);
            switch(ch)
            {
                case 27:
                case KEY_LEFT:
                case 'q':
                case 'Q':
                case KEY_F(10): //quit
                    quit = 1;
                    break;

                case KEY_IC:
                case 'i':
                case 'I':

                    if (edit_zone_network_interfaces_newiface(debuglvl, vctx, interfaces, zone_ptr) < 0)
                    {
                        retval = -1;
                        quit = 1;
                    }

                    reload = 1;
                    break;

                case KEY_DC:
                case 'd':
                case 'D':

                    cur = current_item(ZonesSection.EditZoneInt.menu);
                    if(cur)
                    {
                        (void)strlcpy(save_iface, (char *)item_name(cur), sizeof(save_iface));

                        if (vrmr_zones_network_rem_iface(debuglvl, vctx, zone_ptr, (char *)item_name(cur)) < 0)
                        {
                            retval = -1;
                            quit = 1;
                        }
                        else
                        {
                            vrmr_audit("%s '%s' %s: %s '%s'.",
                                STR_NETWORK, zone_ptr->name,
                                STR_HAS_BEEN_CHANGED, STR_AN_IFACE_HAS_BEEN_REMOVED,
                                save_iface);
                        }

                        reload = 1;
                    }
                    break;

                case KEY_DOWN:
                    menu_driver(ZonesSection.EditZoneInt.menu, REQ_DOWN_ITEM);
                    break;
                case KEY_UP:
                    menu_driver(ZonesSection.EditZoneInt.menu, REQ_UP_ITEM);
                    break;
                case KEY_NPAGE:
                    if(menu_driver(ZonesSection.EditZoneInt.menu, REQ_SCR_DPAGE) != E_OK)
                    {
                        while(menu_driver(ZonesSection.EditZoneInt.menu, REQ_DOWN_ITEM) == E_OK);
                    }
                    break;
                case KEY_PPAGE:
                    if(menu_driver(ZonesSection.EditZoneInt.menu, REQ_SCR_UPAGE) != E_OK)
                    {
                        while(menu_driver(ZonesSection.EditZoneInt.menu, REQ_UP_ITEM) == E_OK);
                    }
                    break;
                case KEY_HOME:
                    menu_driver(ZonesSection.EditZoneInt.menu, REQ_FIRST_ITEM); // home
                    break;
                case KEY_END:
                    menu_driver(ZonesSection.EditZoneInt.menu, REQ_LAST_ITEM);  // end
                    break;
            }
        }
    }

    result = edit_zone_network_interfaces_destroy();
    if(result < 0)
    {
        vrmr_error(-1, VR_INTERR, "edit_zone_network_interfaces_destroy() failed (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    return(retval);
}


struct
{
    FIELD   *activefld,
            *activelabelfld,

            *networkfld,
            *networklabelfld,

            *netmaskfld,
            *netmasklabelfld,

            *network6fld,
            *network6labelfld,

            *cidr6fld,
            *cidr6labelfld,

            *commentfld,
            *commentlabelfld,


            /* anti spoofing */
            *loopbackfld,
            *loopbacklabelfld,
            *loopbackbracketsfld,

            *classafld,
            *classalabelfld,
            *classabracketsfld,

            *classbfld,
            *classblabelfld,
            *classbbracketsfld,

            *classcfld,
            *classclabelfld,
            *classcbracketsfld,

            *classdfld,
            *classdlabelfld,
            *classdbracketsfld,

            *classefld,
            *classelabelfld,
            *classebracketsfld,

            *testnetfld,
            *testnetlabelfld,
            *testnetbracketsfld,

            *lnklocnetfld,
            *lnklocnetlabelfld,
            *lnklocnetbracketsfld,

            *iana08fld,
            *iana08labelfld,
            *iana08bracketsfld,

            *brdsrcfld,
            *brdsrclabelfld,
            *brdsrcbracketsfld,

            *brddstfld,
            *brddstlabelfld,
            *brddstbracketsfld,

            *dhcpsrvfld,
            *dhcpsrvlabelfld,
            *dhcpsrvbracketsfld,

            *dhcpclifld,
            *dhcpclilabelfld,
            *dhcpclibracketsfld,

            *warningfld;    /* field for the "warning no interfaces" message */

} NetworkSec;


/*  interfaces_save_protectrules

    Save the protectrules to the backend.

    Returncodes:
         0: ok
        -1: error
*/
static int
zones_network_save_protectrules(const int debuglvl, struct vrmr_ctx *vctx,
        struct vrmr_zone *network_ptr)
{
    struct vrmr_list_node *d_node = NULL;
    struct vrmr_rule *rule_ptr = NULL;
    char rule_str[VRMR_MAX_RULE_LENGTH] = "";

    /* safety */
    if(network_ptr == NULL)
    {
        vrmr_error(-1, VR_INTERR, "parameter problem (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    /* write to backend */
    if(network_ptr->ProtectList.len == 0)
    {
        /* clear */
        if (vctx->zf->tell(debuglvl, vctx->zone_backend, network_ptr->name, "RULE", "", 1, VRMR_TYPE_NETWORK) < 0)
        {
            vrmr_error(-1, VR_ERR, gettext("saving to backend failed (in: %s:%d)."), __FUNC__, __LINE__);
            return(-1);
        }
    }
    else
    {
        /* write to backend */
        for(d_node = network_ptr->ProtectList.top; d_node; d_node = d_node->next)
        {
            if(!(rule_ptr = d_node->data))
            {
                vrmr_error(-1, VR_INTERR, "NULL pointer (in: %s:%d).", __FUNC__, __LINE__);
                return(-1);
            }

            if(rule_ptr->action == VRMR_AT_PROTECT)
                snprintf(rule_str, sizeof(rule_str), "protect against %s from %s", rule_ptr->danger, rule_ptr->source);
            else
                snprintf(rule_str, sizeof(rule_str), "%s %s", vrmr_rules_itoaction(rule_ptr->action), rule_ptr->service);

            /* the first one needs to be in overwrite mode */
            if(d_node == network_ptr->ProtectList.top)
            {
                /* save to backend */
                if (vctx->zf->tell(debuglvl, vctx->zone_backend, network_ptr->name, "RULE", rule_str, 1, VRMR_TYPE_NETWORK) < 0)
                {
                    vrmr_error(-1, VR_ERR, gettext("saving to backend failed (in: %s:%d)."), __FUNC__, __LINE__);
                    return(-1);
                }
            }
            else
            {
                /* save to backend */
                if (vctx->zf->tell(debuglvl, vctx->zone_backend, network_ptr->name, "RULE", rule_str, 0, VRMR_TYPE_NETWORK) < 0)
                {
                    vrmr_error(-1, VR_ERR, gettext("saving to backend failed (in: %s:%d)."), __FUNC__, __LINE__);
                    return(-1);
                }
            }
        }
    }
    return(0);
}


/*
    returncodes:
        -1: error
         0: ok
*/
static int
edit_zone_network_save_protectrules(const int debuglvl, struct vrmr_ctx *vctx, struct vrmr_zone *network_ptr)
{
    struct vrmr_rule    *rule_ptr = NULL;

    /* safety */
    if(network_ptr == NULL)
    {
        vrmr_error(-1, VR_INTERR, "parameter problem (in: %s:%d).",
                                __FUNC__, __LINE__);
        return(-1);
    }

    /* cleanup the existing list */
    vrmr_list_cleanup(debuglvl, &network_ptr->ProtectList);

    if(field_buffer(NetworkSec.dhcpsrvfld, 0)[0] == 'X')
    {
        if(!(rule_ptr = rules_create_protect_rule(debuglvl, "accept", NULL, "dhcp-server", NULL)))
        {
            vrmr_error(-1, VR_INTERR, "creating network rule failed (in: %s:%d).", __FUNC__, __LINE__);
            return(-1);
        }
        if(vrmr_list_append(debuglvl, &network_ptr->ProtectList, rule_ptr)  == NULL)
        {
            vrmr_error(-1, VR_INTERR, "appending network rule failed (in: %s:%d).", __FUNC__, __LINE__);
            return(-1);
        }
    }

    if(field_buffer(NetworkSec.dhcpclifld, 0)[0] == 'X')
    {
        if(!(rule_ptr = rules_create_protect_rule(debuglvl, "accept", NULL, "dhcp-client", NULL)))
        {
            vrmr_error(-1, VR_INTERR, "creating protect rule failed (in: %s:%d).", __FUNC__, __LINE__);
            return(-1);
        }
        if(vrmr_list_append(debuglvl, &network_ptr->ProtectList, rule_ptr)  == NULL)
        {
            vrmr_error(-1, VR_INTERR, "appending protect rule failed (in: %s:%d).", __FUNC__, __LINE__);
            return(-1);
        }
    }

    if(field_buffer(NetworkSec.loopbackfld, 0)[0] == 'X')
    {
        if(!(rule_ptr = rules_create_protect_rule(debuglvl, "protect", network_ptr->name, "spoofing", "loopback")))
        {
            vrmr_error(-1, VR_INTERR, "creating protect rule failed (in: %s:%d).", __FUNC__, __LINE__);
            return(-1);
        }
        if(vrmr_list_append(debuglvl, &network_ptr->ProtectList, rule_ptr)  == NULL)
        {
            vrmr_error(-1, VR_INTERR, "appending protect rule failed (in: %s:%d).", __FUNC__, __LINE__);
            return(-1);
        }
    }

    if(field_buffer(NetworkSec.classafld, 0)[0] == 'X')
    {
        if(!(rule_ptr = rules_create_protect_rule(debuglvl, "protect", network_ptr->name, "spoofing", "class-a")))
        {
            vrmr_error(-1, VR_INTERR, "creating protect rule failed (in: %s:%d).", __FUNC__, __LINE__);
            return(-1);
        }
        if(vrmr_list_append(debuglvl, &network_ptr->ProtectList, rule_ptr)  == NULL)
        {
            vrmr_error(-1, VR_INTERR, "appending protect rule failed (in: %s:%d).", __FUNC__, __LINE__);
            return(-1);
        }
    }

    if(field_buffer(NetworkSec.classbfld, 0)[0] == 'X')
    {
        if(!(rule_ptr = rules_create_protect_rule(debuglvl, "protect", network_ptr->name, "spoofing", "class-b")))
        {
            vrmr_error(-1, VR_INTERR, "creating protect rule failed (in: %s:%d).", __FUNC__, __LINE__);
            return(-1);
        }
        if(vrmr_list_append(debuglvl, &network_ptr->ProtectList, rule_ptr)  == NULL)
        {
            vrmr_error(-1, VR_INTERR, "appending protect rule failed (in: %s:%d).", __FUNC__, __LINE__);
            return(-1);
        }
    }

    if(field_buffer(NetworkSec.classcfld, 0)[0] == 'X')
    {
        if(!(rule_ptr = rules_create_protect_rule(debuglvl, "protect", network_ptr->name, "spoofing", "class-c")))
        {
            vrmr_error(-1, VR_INTERR, "creating protect rule failed (in: %s:%d).", __FUNC__, __LINE__);
            return(-1);
        }
        if(vrmr_list_append(debuglvl, &network_ptr->ProtectList, rule_ptr)  == NULL)
        {
            vrmr_error(-1, VR_INTERR, "appending protect rule failed (in: %s:%d).", __FUNC__, __LINE__);
            return(-1);
        }
    }

    if(field_buffer(NetworkSec.classdfld, 0)[0] == 'X')
    {
        if(!(rule_ptr = rules_create_protect_rule(debuglvl, "protect", network_ptr->name, "spoofing", "class-d")))
        {
            vrmr_error(-1, VR_INTERR, "creating protect rule failed (in: %s:%d).", __FUNC__, __LINE__);
            return(-1);
        }
        if(vrmr_list_append(debuglvl, &network_ptr->ProtectList, rule_ptr)  == NULL)
        {
            vrmr_error(-1, VR_INTERR, "appending protect rule failed (in: %s:%d).", __FUNC__, __LINE__);
            return(-1);
        }
    }

    if(field_buffer(NetworkSec.classefld, 0)[0] == 'X')
    {
        if(!(rule_ptr = rules_create_protect_rule(debuglvl, "protect", network_ptr->name, "spoofing", "class-e")))
        {
            vrmr_error(-1, VR_INTERR, "creating protect rule failed (in: %s:%d).", __FUNC__, __LINE__);
            return(-1);
        }
        if(vrmr_list_append(debuglvl, &network_ptr->ProtectList, rule_ptr)  == NULL)
        {
            vrmr_error(-1, VR_INTERR, "appending protect rule failed (in: %s:%d).", __FUNC__, __LINE__);
            return(-1);
        }
    }

    if(field_buffer(NetworkSec.testnetfld, 0)[0] == 'X')
    {
        if(!(rule_ptr = rules_create_protect_rule(debuglvl, "protect", network_ptr->name, "spoofing", "test-net")))
        {
            vrmr_error(-1, VR_INTERR, "creating protect rule failed (in: %s:%d).", __FUNC__, __LINE__);
            return(-1);
        }
        if(vrmr_list_append(debuglvl, &network_ptr->ProtectList, rule_ptr)  == NULL)
        {
            vrmr_error(-1, VR_INTERR, "appending protect rule failed (in: %s:%d).", __FUNC__, __LINE__);
            return(-1);
        }
    }

    if(field_buffer(NetworkSec.lnklocnetfld, 0)[0] == 'X')
    {
        if(!(rule_ptr = rules_create_protect_rule(debuglvl, "protect", network_ptr->name, "spoofing", "lnk-loc-net")))
        {
            vrmr_error(-1, VR_INTERR, "creating protect rule failed (in: %s:%d).", __FUNC__, __LINE__);
            return(-1);
        }
        if(vrmr_list_append(debuglvl, &network_ptr->ProtectList, rule_ptr)  == NULL)
        {
            vrmr_error(-1, VR_INTERR, "appending protect rule failed (in: %s:%d).", __FUNC__, __LINE__);
            return(-1);
        }
    }

    if(field_buffer(NetworkSec.iana08fld, 0)[0] == 'X')
    {
        if(!(rule_ptr = rules_create_protect_rule(debuglvl, "protect", network_ptr->name, "spoofing", "iana-0/8")))
        {
            vrmr_error(-1, VR_INTERR, "creating protect rule failed (in: %s:%d).", __FUNC__, __LINE__);
            return(-1);
        }
        if(vrmr_list_append(debuglvl, &network_ptr->ProtectList, rule_ptr)  == NULL)
        {
            vrmr_error(-1, VR_INTERR, "appending protect rule failed (in: %s:%d).", __FUNC__, __LINE__);
            return(-1);
        }
    }

    if(field_buffer(NetworkSec.brdsrcfld, 0)[0] == 'X')
    {
        if(!(rule_ptr = rules_create_protect_rule(debuglvl, "protect", network_ptr->name, "spoofing", "brdcst-src")))
        {
            vrmr_error(-1, VR_INTERR, "creating protect rule failed (in: %s:%d).", __FUNC__, __LINE__);
            return(-1);
        }
        if(vrmr_list_append(debuglvl, &network_ptr->ProtectList, rule_ptr)  == NULL)
        {
            vrmr_error(-1, VR_INTERR, "appending protect rule failed (in: %s:%d).", __FUNC__, __LINE__);
            return(-1);
        }
    }

    if(field_buffer(NetworkSec.brddstfld, 0)[0] == 'X')
    {
        if(!(rule_ptr = rules_create_protect_rule(debuglvl, "protect", network_ptr->name, "spoofing", "brdcst-dst")))
        {
            vrmr_error(-1, VR_INTERR, "creating protect rule failed (in: %s:%d).", __FUNC__, __LINE__);
            return(-1);
        }
        if(vrmr_list_append(debuglvl, &network_ptr->ProtectList, rule_ptr)  == NULL)
        {
            vrmr_error(-1, VR_INTERR, "appending protect rule failed (in: %s:%d).", __FUNC__, __LINE__);
            return(-1);
        }
    }

    /* now let try to write this to the backend */
    if (zones_network_save_protectrules(debuglvl, vctx, network_ptr) < 0)
    {
        vrmr_error(-1, VR_ERR, gettext("saving to backend failed (in: %s:%d)."), __FUNC__, __LINE__);
        return(-1);
    }

    return(0);
}


static int
edit_zone_network_init(const int debuglvl, struct vrmr_ctx *vctx,
        struct vrmr_zones *zones, char *name, int height, int width, int starty, int startx, struct vrmr_zone *zone_ptr)
{
    int     rows,
            cols,
            comment_y=0,
            comment_x=0;
    size_t  i = 0,
            field_num = 0;

    /* safety */
    if(!name || !zone_ptr || !zones)
    {
        vrmr_error(-1, VR_INTERR, "parameter problem (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    ZonesSection.EditZone.n_fields = 52;
    if(!(ZonesSection.EditZone.fields = (FIELD **)calloc(ZonesSection.EditZone.n_fields + 1, sizeof(FIELD *))))
    {
        vrmr_error(-1, VR_ERR, gettext("calloc failed: %s (in: %s:%d)."), strerror(errno), __FUNC__, __LINE__);
        return(-1);
    }

    /* active toggle */
    NetworkSec.activelabelfld = (ZonesSection.EditZone.fields[field_num] = new_field(1, 16, 2, 0, 0, 0));
    field_num++;
    set_field_buffer_wrap(debuglvl, NetworkSec.activelabelfld, 0, gettext("Active"));
    field_opts_off(NetworkSec.activelabelfld, O_AUTOSKIP | O_ACTIVE);

    NetworkSec.activefld = (ZonesSection.EditZone.fields[field_num] = new_field(1, 3, 3, 1, 0, 0));
    field_num++;
    set_field_buffer_wrap(debuglvl, NetworkSec.activefld, 0, zone_ptr->active ? STR_YES : STR_NO);

    /* network */
    NetworkSec.networklabelfld = (ZonesSection.EditZone.fields[field_num] = new_field(1, 8, 5, 0, 0, 0));
    field_num++;
    set_field_buffer_wrap(debuglvl, NetworkSec.networklabelfld, 0, gettext("Network"));
    field_opts_off(NetworkSec.networklabelfld, O_AUTOSKIP | O_ACTIVE);

    NetworkSec.networkfld = (ZonesSection.EditZone.fields[field_num] = new_field(1, 16, 6, 1, 0, 0));
    set_field_type(NetworkSec.networkfld, TYPE_IPV4);
    field_num++;
    set_field_buffer_wrap(debuglvl, NetworkSec.networkfld, 0, zone_ptr->ipv4.network);

    /* network */
    NetworkSec.netmasklabelfld = (ZonesSection.EditZone.fields[field_num] = new_field(1, 8, 7, 0, 0, 0));
    field_num++;
    set_field_buffer_wrap(debuglvl, NetworkSec.netmasklabelfld, 0, gettext("Netmask"));
    field_opts_off(NetworkSec.netmasklabelfld, O_AUTOSKIP | O_ACTIVE);

    NetworkSec.netmaskfld = (ZonesSection.EditZone.fields[field_num] = new_field(1, 16, 8, 1, 0, 0));
    set_field_type(NetworkSec.netmaskfld, TYPE_IPV4);
    field_num++;
    set_field_buffer_wrap(debuglvl, NetworkSec.netmaskfld, 0, zone_ptr->ipv4.netmask);

    /* network */
    NetworkSec.network6labelfld = (ZonesSection.EditZone.fields[field_num] = new_field(1, 12, 9, 0, 0, 0));
    field_num++;
#ifdef IPV6_ENABLED
    set_field_buffer_wrap(debuglvl, NetworkSec.network6labelfld, 0, gettext("IPv6 Network"));
#endif
    field_opts_off(NetworkSec.network6labelfld, O_AUTOSKIP | O_ACTIVE);

    NetworkSec.network6fld = (ZonesSection.EditZone.fields[field_num++] = new_field(1, VRMR_MAX_IPV6_ADDR_LEN, 10, 1, 0, 0));
    //set_field_type(NetworkSec.networkfld, TYPE_IPV4);
#ifdef IPV6_ENABLED
    set_field_buffer_wrap(debuglvl, NetworkSec.network6fld, 0, zone_ptr->ipv6.net6);
#endif

    /* cidr */
    NetworkSec.cidr6labelfld = (ZonesSection.EditZone.fields[field_num++] = new_field(1, 9, 11, 0, 0, 0));
#ifdef IPV6_ENABLED
    set_field_buffer_wrap(debuglvl, NetworkSec.cidr6labelfld, 0, gettext("IPv6 CIDR"));
#endif
    field_opts_off(NetworkSec.cidr6labelfld, O_AUTOSKIP | O_ACTIVE);

    NetworkSec.cidr6fld = (ZonesSection.EditZone.fields[field_num++] = new_field(1, 3, 12, 1, 0, 0));
#ifdef IPV6_ENABLED
    char cidr[3] = "";
    snprintf(cidr, sizeof(cidr), "%d", zone_ptr->ipv6.cidr6);
    set_field_buffer_wrap(debuglvl, NetworkSec.cidr6fld, 0, cidr);
#endif

    /* anti-spoof loopback */
    NetworkSec.loopbacklabelfld = (ZonesSection.EditZone.fields[field_num] = new_field(1, 8, 4, 20, 0, 0));
    field_num++;
    set_field_buffer_wrap(debuglvl, NetworkSec.loopbacklabelfld, 0, gettext("Loopback"));
    field_opts_off(NetworkSec.loopbacklabelfld, O_AUTOSKIP | O_ACTIVE);

    NetworkSec.loopbackbracketsfld = (ZonesSection.EditZone.fields[field_num] = new_field(1, 3, 4, 32, 0, 0));
    field_num++;
    set_field_buffer_wrap(debuglvl, NetworkSec.loopbackbracketsfld, 0, "[ ]");
    field_opts_off(NetworkSec.loopbackbracketsfld, O_AUTOSKIP | O_ACTIVE);

    NetworkSec.loopbackfld = (ZonesSection.EditZone.fields[field_num] = new_field(1, 1, 4, 33, 0, 0));
    field_num++;
    set_field_buffer_wrap(debuglvl, NetworkSec.loopbackfld, 0, protectrule_loaded(debuglvl, &zone_ptr->ProtectList, "protect", "spoofing", "loopback") ? "X" : " ");

    /* anti-spoof class-a */
    NetworkSec.classalabelfld = (ZonesSection.EditZone.fields[field_num] = new_field(1, 8, 5, 20, 0, 0));
    field_num++;
    set_field_buffer_wrap(debuglvl, NetworkSec.classalabelfld, 0, gettext("Class A"));
    field_opts_off(NetworkSec.classalabelfld, O_AUTOSKIP | O_ACTIVE);

    NetworkSec.classabracketsfld = (ZonesSection.EditZone.fields[field_num] = new_field(1, 3, 5, 32, 0, 0));
    field_num++;
    set_field_buffer_wrap(debuglvl, NetworkSec.classabracketsfld, 0, "[ ]");
    field_opts_off(NetworkSec.classabracketsfld, O_AUTOSKIP | O_ACTIVE);

    NetworkSec.classafld = (ZonesSection.EditZone.fields[field_num] = new_field(1, 1, 5, 33, 0, 0));
    field_num++;
    set_field_buffer_wrap(debuglvl, NetworkSec.classafld, 0, protectrule_loaded(debuglvl, &zone_ptr->ProtectList, "protect", "spoofing", "class-a") ? "X" : " ");

    /* anti-spoof class-b */
    NetworkSec.classblabelfld = (ZonesSection.EditZone.fields[field_num] = new_field(1, 8, 6, 20, 0, 0));
    field_num++;
    set_field_buffer_wrap(debuglvl, NetworkSec.classblabelfld, 0, gettext("Class B"));
    field_opts_off(NetworkSec.classblabelfld, O_AUTOSKIP | O_ACTIVE);

    NetworkSec.classbbracketsfld = (ZonesSection.EditZone.fields[field_num] = new_field(1, 3, 6, 32, 0, 0));
    field_num++;
    set_field_buffer_wrap(debuglvl, NetworkSec.classbbracketsfld, 0, "[ ]");
    field_opts_off(NetworkSec.classbbracketsfld, O_AUTOSKIP | O_ACTIVE);

    NetworkSec.classbfld = (ZonesSection.EditZone.fields[field_num] = new_field(1, 1, 6, 33, 0, 0));
    field_num++;
    set_field_buffer_wrap(debuglvl, NetworkSec.classbfld, 0, protectrule_loaded(debuglvl, &zone_ptr->ProtectList, "protect", "spoofing", "class-b") ? "X" : " ");

    /* anti-spoof class-c */
    NetworkSec.classclabelfld = (ZonesSection.EditZone.fields[field_num] = new_field(1, 8, 7, 20, 0, 0));
    field_num++;
    set_field_buffer_wrap(debuglvl, NetworkSec.classclabelfld, 0, gettext("Class C"));
    field_opts_off(NetworkSec.classclabelfld, O_AUTOSKIP | O_ACTIVE);

    NetworkSec.classcbracketsfld = (ZonesSection.EditZone.fields[field_num] = new_field(1, 3, 7, 32, 0, 0));
    field_num++;
    set_field_buffer_wrap(debuglvl, NetworkSec.classcbracketsfld, 0, "[ ]");
    field_opts_off(NetworkSec.classcbracketsfld, O_AUTOSKIP | O_ACTIVE);

    NetworkSec.classcfld = (ZonesSection.EditZone.fields[field_num] = new_field(1, 1, 7, 33, 0, 0));
    field_num++;
    set_field_buffer_wrap(debuglvl, NetworkSec.classcfld, 0, protectrule_loaded(debuglvl, &zone_ptr->ProtectList, "protect", "spoofing", "class-c") ? "X" : " ");

    /* anti-spoof class-d */
    NetworkSec.classdlabelfld = (ZonesSection.EditZone.fields[field_num] = new_field(1, 8, 8, 20, 0, 0));
    field_num++;
    set_field_buffer_wrap(debuglvl, NetworkSec.classdlabelfld, 0, gettext("Class D"));
    field_opts_off(NetworkSec.classdlabelfld, O_AUTOSKIP | O_ACTIVE);

    NetworkSec.classdbracketsfld = (ZonesSection.EditZone.fields[field_num] = new_field(1, 3, 8, 32, 0, 0));
    field_num++;
    set_field_buffer_wrap(debuglvl, NetworkSec.classdbracketsfld, 0, "[ ]");
    field_opts_off(NetworkSec.classdbracketsfld, O_AUTOSKIP | O_ACTIVE);

    NetworkSec.classdfld = (ZonesSection.EditZone.fields[field_num] = new_field(1, 1, 8, 33, 0, 0));
    field_num++;
    set_field_buffer_wrap(debuglvl, NetworkSec.classdfld, 0, protectrule_loaded(debuglvl, &zone_ptr->ProtectList, "protect", "spoofing", "class-d") ? "X" : " ");

    /* anti-spoof class-e */
    NetworkSec.classelabelfld = (ZonesSection.EditZone.fields[field_num] = new_field(1, 8, 9, 20, 0, 0));
    field_num++;
    set_field_buffer_wrap(debuglvl, NetworkSec.classelabelfld, 0, gettext("Class E"));
    field_opts_off(NetworkSec.classelabelfld, O_AUTOSKIP | O_ACTIVE);

    NetworkSec.classebracketsfld = (ZonesSection.EditZone.fields[field_num] = new_field(1, 3, 9, 32, 0, 0));
    field_num++;
    set_field_buffer_wrap(debuglvl, NetworkSec.classebracketsfld, 0, "[ ]");
    field_opts_off(NetworkSec.classebracketsfld, O_AUTOSKIP | O_ACTIVE);

    NetworkSec.classefld = (ZonesSection.EditZone.fields[field_num] = new_field(1, 1, 9, 33, 0, 0));
    field_num++;
    set_field_buffer_wrap(debuglvl, NetworkSec.classefld, 0, protectrule_loaded(debuglvl, &zone_ptr->ProtectList, "protect", "spoofing", "class-e") ? "X" : " ");

    /* anti-spoof testnet */
    NetworkSec.testnetlabelfld = (ZonesSection.EditZone.fields[field_num] = new_field(1, 14, 4, 37, 0, 0));
    field_num++;
    set_field_buffer_wrap(debuglvl, NetworkSec.testnetlabelfld, 0, gettext("Test-net"));
    field_opts_off(NetworkSec.testnetlabelfld, O_AUTOSKIP | O_ACTIVE);

    NetworkSec.testnetbracketsfld = (ZonesSection.EditZone.fields[field_num] = new_field(1, 3, 4, 52, 0, 0));
    field_num++;
    set_field_buffer_wrap(debuglvl, NetworkSec.testnetbracketsfld, 0, "[ ]");
    field_opts_off(NetworkSec.testnetbracketsfld, O_AUTOSKIP | O_ACTIVE);

    NetworkSec.testnetfld = (ZonesSection.EditZone.fields[field_num] = new_field(1, 1, 4, 53, 0, 0));
    field_num++;
    set_field_buffer_wrap(debuglvl, NetworkSec.testnetfld, 0, protectrule_loaded(debuglvl, &zone_ptr->ProtectList, "protect", "spoofing", "test-net") ? "X" : " ");

    /* anti-spoof link local net */
    NetworkSec.lnklocnetlabelfld = (ZonesSection.EditZone.fields[field_num] = new_field(1, 14, 5, 37, 0, 0));
    field_num++;
    set_field_buffer_wrap(debuglvl, NetworkSec.lnklocnetlabelfld, 0, gettext("Link local net"));
    field_opts_off(NetworkSec.lnklocnetlabelfld, O_AUTOSKIP | O_ACTIVE);

    NetworkSec.lnklocnetbracketsfld = (ZonesSection.EditZone.fields[field_num] = new_field(1, 3, 5, 52, 0, 0));
    field_num++;
    set_field_buffer_wrap(debuglvl, NetworkSec.lnklocnetbracketsfld, 0, "[ ]");
    field_opts_off(NetworkSec.lnklocnetbracketsfld, O_AUTOSKIP | O_ACTIVE);

    NetworkSec.lnklocnetfld = (ZonesSection.EditZone.fields[field_num] = new_field(1, 1, 5, 53, 0, 0));
    field_num++;
    set_field_buffer_wrap(debuglvl, NetworkSec.lnklocnetfld, 0, protectrule_loaded(debuglvl, &zone_ptr->ProtectList, "protect", "spoofing", "lnk-loc-net") ? "X" : " ");

    /* anti-spoof link local net */
    NetworkSec.iana08labelfld = (ZonesSection.EditZone.fields[field_num] = new_field(1, 14, 6, 37, 0, 0));
    field_num++;
    set_field_buffer_wrap(debuglvl, NetworkSec.iana08labelfld, 0, gettext("0.0.0.0/8 res."));
    field_opts_off(NetworkSec.iana08labelfld, O_AUTOSKIP | O_ACTIVE);

    NetworkSec.iana08bracketsfld = (ZonesSection.EditZone.fields[field_num] = new_field(1, 3, 6, 52, 0, 0));
    field_num++;
    set_field_buffer_wrap(debuglvl, NetworkSec.iana08bracketsfld, 0, "[ ]");
    field_opts_off(NetworkSec.iana08bracketsfld, O_AUTOSKIP | O_ACTIVE);

    NetworkSec.iana08fld = (ZonesSection.EditZone.fields[field_num] = new_field(1, 1, 6, 53, 0, 0));
    field_num++;
    set_field_buffer_wrap(debuglvl, NetworkSec.iana08fld, 0, protectrule_loaded(debuglvl, &zone_ptr->ProtectList, "protect", "spoofing", "iana-0/8") ? "X" : " ");

    /* anti-spoof link local net */
    NetworkSec.brdsrclabelfld = (ZonesSection.EditZone.fields[field_num] = new_field(1, 14, 7, 37, 0, 0));
    field_num++;
    set_field_buffer_wrap(debuglvl, NetworkSec.brdsrclabelfld, 0, gettext("Broadcast src."));
    field_opts_off(NetworkSec.brdsrclabelfld, O_AUTOSKIP | O_ACTIVE);

    NetworkSec.brdsrcbracketsfld = (ZonesSection.EditZone.fields[field_num] = new_field(1, 3, 7, 52, 0, 0));
    field_num++;
    set_field_buffer_wrap(debuglvl, NetworkSec.brdsrcbracketsfld, 0, "[ ]");
    field_opts_off(NetworkSec.brdsrcbracketsfld, O_AUTOSKIP | O_ACTIVE);

    NetworkSec.brdsrcfld = (ZonesSection.EditZone.fields[field_num] = new_field(1, 1, 7, 53, 0, 0));
    field_num++;
    set_field_buffer_wrap(debuglvl, NetworkSec.brdsrcfld, 0, protectrule_loaded(debuglvl, &zone_ptr->ProtectList, "protect", "spoofing", "brdcst-src") ? "X" : " ");

    /* anti-spoof link local net */
    NetworkSec.brddstlabelfld = (ZonesSection.EditZone.fields[field_num] = new_field(1, 14, 8, 37, 0, 0));
    field_num++;
    set_field_buffer_wrap(debuglvl, NetworkSec.brddstlabelfld, 0, gettext("Broadcast dst."));
    field_opts_off(NetworkSec.brddstlabelfld, O_AUTOSKIP | O_ACTIVE);

    NetworkSec.brddstbracketsfld = (ZonesSection.EditZone.fields[field_num] = new_field(1, 3, 8, 52, 0, 0));
    field_num++;
    set_field_buffer_wrap(debuglvl, NetworkSec.brddstbracketsfld, 0, "[ ]");
    field_opts_off(NetworkSec.brddstbracketsfld, O_AUTOSKIP | O_ACTIVE);

    NetworkSec.brddstfld = (ZonesSection.EditZone.fields[field_num] = new_field(1, 1, 8, 53, 0, 0));
    field_num++;
    set_field_buffer_wrap(debuglvl, NetworkSec.brddstfld, 0, protectrule_loaded(debuglvl, &zone_ptr->ProtectList, "protect", "spoofing", "brdcst-dst") ? "X" : " ");

    /* DHCP Server */
    NetworkSec.dhcpsrvlabelfld = (ZonesSection.EditZone.fields[field_num] = new_field(1, 14, 4, 57, 0, 0));
    field_num++;
    set_field_buffer_wrap(debuglvl, NetworkSec.dhcpsrvlabelfld, 0, gettext("DHCP Server"));
    field_opts_off(NetworkSec.dhcpsrvlabelfld, O_AUTOSKIP | O_ACTIVE);

    NetworkSec.dhcpsrvbracketsfld = (ZonesSection.EditZone.fields[field_num] = new_field(1, 3, 4, 71, 0, 0));
    field_num++;
    set_field_buffer_wrap(debuglvl, NetworkSec.dhcpsrvbracketsfld, 0, "[ ]");
    field_opts_off(NetworkSec.dhcpsrvbracketsfld, O_AUTOSKIP | O_ACTIVE);

    NetworkSec.dhcpsrvfld = (ZonesSection.EditZone.fields[field_num] = new_field(1, 1, 4, 72, 0, 0));
    field_num++;
    set_field_buffer_wrap(debuglvl, NetworkSec.dhcpsrvfld, 0, protectrule_loaded(debuglvl, &zone_ptr->ProtectList, "accept", "dhcp-server", NULL) ? "X" : " ");

    /* DHCP Client */
    NetworkSec.dhcpclilabelfld = (ZonesSection.EditZone.fields[field_num] = new_field(1, 14, 5, 57, 0, 0));
    field_num++;
    set_field_buffer_wrap(debuglvl, NetworkSec.dhcpclilabelfld, 0, gettext("DHCP Client"));
    field_opts_off(NetworkSec.dhcpclilabelfld, O_AUTOSKIP | O_ACTIVE);

    NetworkSec.dhcpclibracketsfld = (ZonesSection.EditZone.fields[field_num] = new_field(1, 3, 5, 71, 0, 0));
    field_num++;
    set_field_buffer_wrap(debuglvl, NetworkSec.dhcpclibracketsfld, 0, "[ ]");
    field_opts_off(NetworkSec.dhcpclibracketsfld, O_AUTOSKIP | O_ACTIVE);

    NetworkSec.dhcpclifld = (ZonesSection.EditZone.fields[field_num] = new_field(1, 1, 5, 72, 0, 0));
    field_num++;
    set_field_buffer_wrap(debuglvl, NetworkSec.dhcpclifld, 0, protectrule_loaded(debuglvl, &zone_ptr->ProtectList, "accept", "dhcp-client", NULL) ? "X" : " ");


    /* comment field */
    comment_y = 5;
    comment_x = 48;

    /* comment */
    NetworkSec.commentlabelfld = (ZonesSection.EditZone.fields[field_num] = new_field(1, 16, 13, 0, 0, 0));
    field_num++;
    set_field_buffer_wrap(debuglvl, NetworkSec.commentlabelfld, 0, gettext("Comment"));
    field_opts_off(NetworkSec.commentlabelfld, O_AUTOSKIP | O_ACTIVE);

    NetworkSec.commentfld = (ZonesSection.EditZone.fields[field_num] = new_field(comment_y, comment_x, 14, 1, 0, 0));
    field_num++;

    NetworkSec.warningfld = (ZonesSection.EditZone.fields[field_num] = new_field(1, width-4, 1, 0, 0, 0));

    field_opts_off(NetworkSec.warningfld, O_VISIBLE | O_ACTIVE);
    field_num++;

    /* terminate */
    ZonesSection.EditZone.fields[field_num] = NULL;

    if(ZonesSection.EditZone.n_fields != field_num)
        vrmr_error(-1, VR_INTERR, "ZonesSection.EditZone.n_fields != field_num.");

    /* read the comment from backend */
    if (vctx->zf->ask(debuglvl, vctx->zone_backend, zone_ptr->name, "COMMENT", ZonesSection.comment, sizeof(ZonesSection.comment), VRMR_TYPE_NETWORK, 0) < 0)
        vrmr_error(-1, VR_ERR, gettext("error while loading the comment."));

    set_field_buffer_wrap(debuglvl, NetworkSec.commentfld, 0, ZonesSection.comment);

    /* create window and panel */
    if(!(ZonesSection.EditZone.win = create_newwin(height, width, starty, startx, gettext("Edit Zone: Network"), vccnf.color_win)))
    {
        vrmr_error(-1, VR_INTERR, "create_newwin() failed (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }
    if(!(ZonesSection.EditZone.panel[0] = new_panel(ZonesSection.EditZone.win)))
    {
        vrmr_error(-1, VR_INTERR, "new_panel() failed (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }
    keypad(ZonesSection.EditZone.win, TRUE);

    /* set field options */
    for(i = 0; i < ZonesSection.EditZone.n_fields; i++)
    {
        set_field_back(ZonesSection.EditZone.fields[i], vccnf.color_win);
        field_opts_off(ZonesSection.EditZone.fields[i], O_AUTOSKIP);
        set_field_status(ZonesSection.EditZone.fields[i], FALSE);
    }

    set_field_back(NetworkSec.activefld, vccnf.color_win_rev);
    set_field_back(NetworkSec.networkfld, vccnf.color_win_rev);
    set_field_back(NetworkSec.netmaskfld, vccnf.color_win_rev);
    set_field_back(NetworkSec.network6fld, vccnf.color_win_rev);
    set_field_back(NetworkSec.cidr6fld, vccnf.color_win_rev);
    set_field_back(NetworkSec.commentfld, vccnf.color_win_rev);

    set_field_fore(NetworkSec.warningfld, vccnf.color_win_warn|A_BOLD);
    set_field_just(NetworkSec.warningfld, JUSTIFY_CENTER);

#ifndef IPV6_ENABLED
    set_field_back(NetworkSec.network6labelfld, vccnf.color_win | A_BOLD);
    field_opts_on(NetworkSec.network6labelfld, O_AUTOSKIP);
    field_opts_off(NetworkSec.network6labelfld, O_ACTIVE);

    set_field_back(NetworkSec.network6fld, vccnf.color_win | A_BOLD);
    field_opts_on(NetworkSec.network6fld, O_AUTOSKIP);
    field_opts_off(NetworkSec.network6fld, O_ACTIVE);

    set_field_back(NetworkSec.cidr6labelfld, vccnf.color_win | A_BOLD);
    field_opts_on(NetworkSec.cidr6labelfld, O_AUTOSKIP);
    field_opts_off(NetworkSec.cidr6labelfld, O_ACTIVE);

    set_field_back(NetworkSec.cidr6fld, vccnf.color_win | A_BOLD);
    field_opts_on(NetworkSec.cidr6fld, O_AUTOSKIP);
    field_opts_off(NetworkSec.cidr6fld, O_ACTIVE);
#endif

    /* Create the form and post it */
    if(!(ZonesSection.EditZone.form = new_form(ZonesSection.EditZone.fields)))
    {
        vrmr_error(-1, VR_INTERR, "new_form() failed (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }
    scale_form(ZonesSection.EditZone.form, &rows, &cols);
    set_form_win(ZonesSection.EditZone.form, ZonesSection.EditZone.win);
    set_form_sub(ZonesSection.EditZone.form, derwin(ZonesSection.EditZone.win, rows, cols, 1, 2));
    post_form(ZonesSection.EditZone.form);

    /* the labels */
    mvwprintw(ZonesSection.EditZone.win, 1, 2,  "%s: %s", gettext("Name"), zone_ptr->name);
    mvwprintw(ZonesSection.EditZone.win, 3, 30, gettext("Anti-spoofing"));

//    mvwprintw(ZonesSection.EditZone.win, 12, 54, "Press <F6> to assign");
//    mvwprintw(ZonesSection.EditZone.win, 13, 54, "(an) interface(s) to");
//    mvwprintw(ZonesSection.EditZone.win, 14, 54, "this network.");

    mvwprintw(ZonesSection.EditZone.win, 12, 62, "%s", gettext("Hosts"));
    mvwprintw(ZonesSection.EditZone.win, 12, 70, "%4d", vrmr_count_zones(debuglvl, zones, VRMR_TYPE_HOST, zone_ptr->network_name, zone_ptr->zone_name));
    mvwprintw(ZonesSection.EditZone.win, 13, 62, "%s", gettext("Groups"));
    mvwprintw(ZonesSection.EditZone.win, 13, 70, "%4d", vrmr_count_zones(debuglvl, zones, VRMR_TYPE_GROUP, zone_ptr->network_name, zone_ptr->zone_name));

    wrefresh(ZonesSection.EditZone.win);
    return(0);
}

/*  edit_zone_network_save

    Returncodes:
         1: ok, changes
         0: ok, no changes
        -1: error
*/
static int
edit_zone_network_save(const int debuglvl, struct vrmr_ctx *vctx, struct vrmr_zone *zone_ptr)
{
    int                 retval = 0;
    char                network[16] = "",
                        netmask[16] = "";
    char                rules_changed = FALSE;
    struct vrmr_rule    *rule_ptr = NULL;
    struct vrmr_list_node         *d_node = NULL;
    int                 active = 0;
    size_t              i = 0;

    /* check for changed fields */
    for(i = 0; i < ZonesSection.EditZone.n_fields; i++)
    {
        if(field_status(ZonesSection.EditZone.fields[i]) == TRUE)
        {
            retval = 1;

            if(ZonesSection.EditZone.fields[i] == NetworkSec.activefld)
            {
                /* active */
                zone_ptr->status = VRMR_ST_CHANGED;

                active = zone_ptr->active;

                if(strncasecmp(field_buffer(ZonesSection.EditZone.fields[i], 0), STR_YES, StrLen(STR_YES)) == 0)
                {
                    zone_ptr->active = 1;
                }
                else
                {
                    zone_ptr->active = 0;
                }

                if (vctx->zf->tell(debuglvl, vctx->zone_backend, zone_ptr->name, "ACTIVE", zone_ptr->active ? "Yes" : "No", 1, VRMR_TYPE_NETWORK) < 0)
                {
                    vrmr_error(-1, VR_ERR, gettext("saving to backend failed (in: %s:%d)."), __FUNC__, __LINE__);
                    return(-1);
                }

                /* for the log */
                vrmr_audit("%s '%s' %s: %s %s '%s' (%s: '%s').",
                    STR_NETWORK, zone_ptr->name, STR_HAS_BEEN_CHANGED, STR_ACTIVE,
                    STR_IS_NOW_SET_TO, zone_ptr->active ? STR_YES : STR_NO,
                    STR_WAS, active ? STR_YES : STR_NO);
            }
            else if(ZonesSection.EditZone.fields[i] == NetworkSec.networkfld)
            {
                /* network */
                zone_ptr->status = VRMR_ST_CHANGED;

                (void)strlcpy(network, zone_ptr->ipv4.network, sizeof(network));

                if(!(copy_field2buf(zone_ptr->ipv4.network,
                                    field_buffer(ZonesSection.EditZone.fields[i], 0),
                                    sizeof(zone_ptr->ipv4.network))))
                    return(-1);

                if (vctx->zf->tell(debuglvl, vctx->zone_backend, zone_ptr->name, "NETWORK", zone_ptr->ipv4.network, 1, VRMR_TYPE_NETWORK) < 0)
                {
                    vrmr_error(-1, VR_ERR, gettext("saving to backend failed (in: %s:%d)."), __FUNC__, __LINE__);
                    return(-1);
                }

                /* for the log */
                vrmr_audit("%s '%s' %s: %s %s '%s' (%s: '%s').",
                    STR_NETWORK, zone_ptr->name, STR_HAS_BEEN_CHANGED, STR_NETADDR,
                    STR_IS_NOW_SET_TO, zone_ptr->ipv4.network,
                    STR_WAS, network);
            }
            else if(ZonesSection.EditZone.fields[i] == NetworkSec.netmaskfld)
            {
                /* netmask */
                zone_ptr->status = VRMR_ST_CHANGED;

                (void)strlcpy(network, zone_ptr->ipv4.network, sizeof(network));

                if(!(copy_field2buf(zone_ptr->ipv4.netmask,
                                    field_buffer(ZonesSection.EditZone.fields[i], 0),
                                    sizeof(zone_ptr->ipv4.netmask))))
                    return(-1);

                if (vctx->zf->tell(debuglvl, vctx->zone_backend, zone_ptr->name, "NETMASK", zone_ptr->ipv4.netmask, 1, VRMR_TYPE_NETWORK) < 0)
                {
                    vrmr_error(-1, VR_ERR, gettext("saving to backend failed (in: %s:%d)."), __FUNC__, __LINE__);
                    return(-1);
                }

                /* for the log */
                vrmr_audit("%s '%s' %s: %s %s '%s' (%s: '%s').",
                    STR_NETWORK, zone_ptr->name, STR_HAS_BEEN_CHANGED, STR_NETMASK,
                    STR_IS_NOW_SET_TO, zone_ptr->ipv4.netmask,
                    STR_WAS, netmask);
            }
            else if(ZonesSection.EditZone.fields[i] == NetworkSec.network6fld)
            {
#ifdef IPV6_ENABLED
                char network6[VRMR_MAX_IPV6_ADDR_LEN] = "";

                /* network */
                zone_ptr->status = VRMR_ST_CHANGED;

                (void)strlcpy(network6, zone_ptr->ipv6.net6, sizeof(network6));

                if(!(copy_field2buf(zone_ptr->ipv6.net6,
                                    field_buffer(ZonesSection.EditZone.fields[i], 0),
                                    sizeof(zone_ptr->ipv6.net6))))
                    return(-1);

                if (vctx->zf->tell(debuglvl, vctx->zone_backend, zone_ptr->name, "IPV6NETWORK", zone_ptr->ipv6.net6, 1, VRMR_TYPE_NETWORK) < 0)
                {
                    vrmr_error(-1, VR_ERR, gettext("saving to backend failed (in: %s:%d)."), __FUNC__, __LINE__);
                    return(-1);
                }

                /* for the log */
                vrmr_audit("%s '%s' %s: %s %s '%s' (%s: '%s').",
                    STR_IP6NETWORK, zone_ptr->name, STR_HAS_BEEN_CHANGED, STR_NETADDR,
                    STR_IS_NOW_SET_TO, zone_ptr->ipv6.net6,
                    STR_WAS, network6);
#endif
            }
            else if(ZonesSection.EditZone.fields[i] == NetworkSec.cidr6fld)
            {
#ifdef IPV6_ENABLED
                /* netmask */
                zone_ptr->status = VRMR_ST_CHANGED;

                int cidr = zone_ptr->ipv6.cidr6;
                char cidrstr[3] = "";

                if(!(copy_field2buf(cidrstr,
                                    field_buffer(ZonesSection.EditZone.fields[i], 0),
                                    sizeof(cidrstr))))
                    return(-1);

                if (vctx->zf->tell(debuglvl, vctx->zone_backend, zone_ptr->name, "IPV6CIDR", cidrstr, 1, VRMR_TYPE_NETWORK) < 0)
                {
                    vrmr_error(-1, VR_ERR, gettext("saving to backend failed (in: %s:%d)."), __FUNC__, __LINE__);
                    return(-1);
                }

                /* for the log */
                vrmr_audit("%s '%s' %s: %s %s '%d' (%s: '%d').",
                    STR_IP6CIDR, zone_ptr->name, STR_HAS_BEEN_CHANGED, STR_NETMASK,
                    STR_IS_NOW_SET_TO, zone_ptr->ipv6.cidr6,
                    STR_WAS, cidr);
#endif
            }
            /* save the comment to the backend */
            else if(ZonesSection.EditZone.fields[i] == NetworkSec.commentfld)
            {
                if (vctx->zf->tell(debuglvl, vctx->zone_backend, zone_ptr->name, "COMMENT", field_buffer(ZonesSection.EditZone.fields[i], 0), 1, VRMR_TYPE_NETWORK) < 0)
                {
                    vrmr_error(-1, VR_ERR, gettext("saving to backend failed (in: %s:%d)."), __FUNC__, __LINE__);
                    return(-1);
                }

                /* example: "network 'local.lan' has been changed: the comment was changed." */
                vrmr_audit("%s '%s' %s: %s.",
                    STR_NETWORK, zone_ptr->name, STR_HAS_BEEN_CHANGED, STR_COMMENT_CHANGED);
            }
            else if(ZonesSection.EditZone.fields[i] == NetworkSec.loopbackfld||
                ZonesSection.EditZone.fields[i] == NetworkSec.classafld     ||
                ZonesSection.EditZone.fields[i] == NetworkSec.classbfld     ||
                ZonesSection.EditZone.fields[i] == NetworkSec.classcfld     ||
                ZonesSection.EditZone.fields[i] == NetworkSec.classdfld     ||
                ZonesSection.EditZone.fields[i] == NetworkSec.classefld     ||
                ZonesSection.EditZone.fields[i] == NetworkSec.testnetfld    ||

                ZonesSection.EditZone.fields[i] == NetworkSec.lnklocnetfld  ||
                ZonesSection.EditZone.fields[i] == NetworkSec.iana08fld     ||
                ZonesSection.EditZone.fields[i] == NetworkSec.brdsrcfld     ||
                ZonesSection.EditZone.fields[i] == NetworkSec.brddstfld     ||

                ZonesSection.EditZone.fields[i] == NetworkSec.dhcpsrvfld    ||
                ZonesSection.EditZone.fields[i] == NetworkSec.dhcpclifld)
            {
                if (edit_zone_network_save_protectrules(debuglvl, vctx, zone_ptr) < 0)
                {
                    return(-1);
                }

                rules_changed = TRUE;
            }
        }
    }

    /* audit print list */
    if(rules_changed == TRUE)
    {
        /* example: "network 'local.lan' has been changed: rules are changed: number of rules: 5 (listed below)." */
        vrmr_audit("%s '%s' %s: %s: %s: %d (%s).",
                    STR_NETWORK, zone_ptr->name, STR_HAS_BEEN_CHANGED,
                    STR_RULES_ARE_CHANGED, STR_NUMBER_OF_RULES,
                    zone_ptr->ProtectList.len, STR_LISTED_BELOW);

        for(i = 1, d_node = zone_ptr->ProtectList.top; d_node; d_node = d_node->next, i++)
        {
            rule_ptr = d_node->data;

            if(rule_ptr->action == VRMR_AT_PROTECT)
            {
                if(rule_ptr->source[0] != '\0')
                    vrmr_audit("%2d: %s against %s from %s",
                                    i, vrmr_rules_itoaction(rule_ptr->action),
                                    rule_ptr->danger, rule_ptr->source);
                else
                    vrmr_audit("%2d: %s against %s",
                                    i, vrmr_rules_itoaction(rule_ptr->action),
                                    rule_ptr->danger);
            }
            else
            {
                vrmr_audit("%2d: %s %s",i, vrmr_rules_itoaction(rule_ptr->action),
                                    rule_ptr->service);
            }
        }
    }

    return(retval);
}

static int
edit_zone_network_destroy(void)
{
    int     retval=0;
    size_t  i = 0;

    /* unpost form and free the memory */
    unpost_form(ZonesSection.EditZone.form);
    free_form(ZonesSection.EditZone.form);

    for(i=0;i<ZonesSection.EditZone.n_fields;i++)
    {
        free_field(ZonesSection.EditZone.fields[i]);
    }
    free(ZonesSection.EditZone.fields);

    del_panel(ZonesSection.EditZone.panel[0]);
    destroy_win(ZonesSection.EditZone.win);

    /* reset the comment field */
    strcpy(ZonesSection.comment, "");
    return(retval);
}

/*  edit_zone_network

    The TmpZone crap here is the fault of edit_zone_network_save.
    See the comment above that function for more horror...

    Returncodes:
         1: ok, changes
         0: ok, no changes
        -1: error
*/
static int
edit_zone_network(const int debuglvl, struct vrmr_ctx *vctx,
        struct vrmr_zones *zones, struct vrmr_interfaces *interfaces, char *name)
{
    int                 ch = 0,
                        not_defined = 0,
                        quit = 0,
                        retval = 0;
    struct vrmr_zone    *zone_ptr = NULL;
    int                 height = 0,
                        width = 0,
                        startx = 0,
                        starty = 0;
    FIELD               *cur = NULL,
                        *prev = NULL;
    char                *key_choices[] =    {   "F12",
                                                "F6",
                                                "F10"};
    int                 key_choices_n = 3;
    char                *cmd_choices[] =    {   gettext("help"),
                                                gettext("interfaces"),
                                                gettext("back")};
    int                 cmd_choices_n = 3;

    /* safety */
    if(!name || !interfaces || !zones)
    {
        vrmr_error(-1, VR_INTERR, "parameter problem (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    height = 21;
    width = 78;
    VrWinGetOffset(-1, -1, height, width, 4, ZonesSection.n_xre + 1, &starty, &startx);

    if(!(zone_ptr = vrmr_search_zonedata(debuglvl, zones, name)))
    {
        vrmr_error(-1, VR_INTERR, "network '%s' not found in memory (in: %s:%d).", name, __FUNC__, __LINE__);
        return(-1);
    }

    if (edit_zone_network_init(debuglvl, vctx, zones, name, height, width, starty, startx, zone_ptr) < 0)
        return(-1);

    /* print warning if no interfaces have been assigned to this network */
    if(zone_ptr->InterfaceList.len == 0)
    {
        /* show no int warning */
        set_field_buffer_wrap(debuglvl, NetworkSec.warningfld, 0, gettext("Warning: no interfaces attached!"));
        field_opts_on(NetworkSec.warningfld, O_VISIBLE);
        set_field_status(NetworkSec.warningfld, FALSE);
    }
    else if(zone_ptr->active == TRUE && vrmr_zones_active(debuglvl, zone_ptr) == 0)
    {
        set_field_buffer_wrap(debuglvl, NetworkSec.warningfld, 0, gettext("Note: parent zone is inactive."));
        field_opts_on(NetworkSec.warningfld, O_VISIBLE);
        set_field_status(NetworkSec.warningfld, FALSE);
    }

    wrefresh(ZonesSection.EditZone.win);
    cur = current_field(ZonesSection.EditZone.form);
    pos_form_cursor(ZonesSection.EditZone.form);

    draw_top_menu(debuglvl, top_win, gettext("Network"), key_choices_n, key_choices, cmd_choices_n, cmd_choices);

    update_panels();
    doupdate();

    /* loop through to get user requests */
    while(quit == 0)
    {
        prev = cur;
        /* get current field */
        cur = current_field(ZonesSection.EditZone.form);

        /* draw the arrow around the active field */
        draw_field_active_mark(cur, prev, ZonesSection.EditZone.win, ZonesSection.EditZone.form, vccnf.color_win_mark|A_BOLD);

        not_defined = 0;

        /* get the input */
        ch = wgetch(ZonesSection.EditZone.win);

        if(cur == NetworkSec.commentfld)
        {
            if(nav_field_comment(debuglvl, ZonesSection.EditZone.form, ch) < 0)
                not_defined = 1;
        }
        else if(cur == NetworkSec.activefld)
        {
            if(nav_field_yesno(debuglvl, ZonesSection.EditZone.form, ch) < 0)
                not_defined = 1;
        }
        else if(cur == NetworkSec.networkfld || cur == NetworkSec.network6fld ||
            cur == NetworkSec.netmaskfld || cur == NetworkSec.cidr6fld)
        {
            if(nav_field_simpletext(debuglvl, ZonesSection.EditZone.form, ch) < 0)
                not_defined = 1;
        }
        /* this one needs to be last */
        else if(cur == NetworkSec.loopbackfld   ||
            cur == NetworkSec.classafld         ||
            cur == NetworkSec.classbfld         ||
            cur == NetworkSec.classcfld         ||
            cur == NetworkSec.classdfld         ||
            cur == NetworkSec.classefld         ||
            cur == NetworkSec.testnetfld        ||
            cur == NetworkSec.lnklocnetfld      ||
            cur == NetworkSec.iana08fld         ||
            cur == NetworkSec.brdsrcfld         ||
            cur == NetworkSec.brddstfld         ||
            cur == NetworkSec.dhcpsrvfld        ||
            cur == NetworkSec.dhcpclifld)
        {
            if(nav_field_toggleX(debuglvl, ZonesSection.EditZone.form, ch) < 0)
                not_defined = 1;
        }
        else
            not_defined = 1;

        /* the rest is handled here */
        if(not_defined == 1)
        {
            switch(ch)
            {
                case KEY_F(6):
                case 'e':
                case 'E':

                    if (edit_zone_network_interfaces(debuglvl, vctx, interfaces, zone_ptr) < 0)
                        retval = -1;

                    draw_top_menu(debuglvl, top_win, gettext("Networks"), key_choices_n, key_choices, cmd_choices_n, cmd_choices);
                    break;

                case KEY_DOWN:
                case 10:    // enter
                case 9: // tab

                    form_driver(ZonesSection.EditZone.form, REQ_NEXT_FIELD);
                    form_driver(ZonesSection.EditZone.form, REQ_BEG_LINE);
                    break;

                case KEY_UP:

                    form_driver(ZonesSection.EditZone.form, REQ_PREV_FIELD);
                    form_driver(ZonesSection.EditZone.form, REQ_BEG_LINE);
                    break;

                case 27:
                case KEY_F(10):
                case 'q':
                case 'Q':

                    quit = 1;
                    break;

                case KEY_F(12):
                case 'h':
                case 'H':
                case '?':

                    print_help(debuglvl, ":[VUURMUUR:ZONES:NETWORK:EDIT]:");
                    break;
            }
        }

        /* print warning if no interfaces have been assigned to this network */
        if(zone_ptr->InterfaceList.len == 0)
        {
            /* show no int warning */
            set_field_buffer_wrap(debuglvl, NetworkSec.warningfld, 0, gettext("Warning: no interfaces attached!"));
            field_opts_on(NetworkSec.warningfld, O_VISIBLE);
            set_field_status(NetworkSec.warningfld, FALSE);
        }
        /* check against the current 'active' value */
        else if(strncasecmp(field_buffer(NetworkSec.activefld, 0), STR_YES, StrLen(STR_YES)) == 0 &&
            vrmr_zones_active(debuglvl, zone_ptr) == 0)
        {
            set_field_buffer_wrap(debuglvl, NetworkSec.warningfld, 0, gettext("Note: parent zone is inactive."));
            field_opts_on(NetworkSec.warningfld, O_VISIBLE);
            set_field_status(NetworkSec.warningfld, FALSE);
        }
        /* and clear it again */
        else
        {
            /* hide no int warning */
            field_opts_off(NetworkSec.warningfld, O_VISIBLE);
        }

        /* draw and set cursor */
        wrefresh(ZonesSection.EditZone.win);
        pos_form_cursor(ZonesSection.EditZone.form);
    }

    /* save */
    if (edit_zone_network_save(debuglvl, vctx, zone_ptr) < 0)
    {
        vrmr_error(-1, VR_ERR, gettext("saving to backend failed (in: %s:%d)."), __FUNC__, __LINE__);
        retval = -1;
    }

    /* cleanup */
    if(edit_zone_network_destroy() < 0)
        retval = -1;

    update_panels();
    doupdate();

    status_print(status_win, gettext("Ready."));
    return(retval);
}


/*

*/
static int
zones_section_menu_networks_init(const int debuglvl, struct vrmr_zones *zones, char *zonename)
{
    int                 retval=0;
    struct vrmr_zone    *zone_ptr = NULL;
    int                 height,
                        width,
                        startx,
                        starty,
                        maxy;
    struct vrmr_list_node         *d_node = NULL;
    char                temp[64] = "", /* set to twice 32 because it
                          can contain widec */
                        *desc_ptr = NULL;
    size_t              size = 0,
                        i = 0;

    /* safety */
    if(zonename == NULL || zones == NULL)
    {
        vrmr_error(-1, VR_INTERR, "parameter problem (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    /* get screen dimentions */
    maxy = getmaxy(stdscr);

    /* count how many networks there are */
    ZonesSection.network_n = 0;

    /* count the networks */
    for(d_node = zones->list.top; d_node ; d_node = d_node->next)
    {
        if(!(zone_ptr = d_node->data))
        {
            vrmr_error(-1, VR_INTERR, "NULL pointer (in: %s:%d).", __FUNC__, __LINE__);
            return(-1);
        }

        if(zone_ptr->type == VRMR_TYPE_NETWORK && strcmp(zone_ptr->zone_name, zonename)== 0)
            ZonesSection.network_n++;
    }

    if(vrmr_list_setup(debuglvl, &ZonesSection.network_desc_list, free) < 0)
    {
        vrmr_error(-1, VR_INTERR, "vrmr_list_setup() failed (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    i = ZonesSection.network_n - 1;

    if(!(ZonesSection.networkitems = (ITEM **)calloc(ZonesSection.network_n + 1, sizeof(ITEM *))))
    {
        vrmr_error(-1, VR_ERR, gettext("calloc failed: %s (in: %s:%d)."),
                                    strerror(errno), __FUNC__, __LINE__);
        return(-1);
    }

    /* now load the items */
    for(d_node = zones->list.bot; d_node ; d_node = d_node->prev)
    {
        if(!(zone_ptr = d_node->data))
        {
            vrmr_error(-1, VR_INTERR, "NULL pointer (in: %s:%d).", __FUNC__, __LINE__);
            return(-1);
        }

        if(zone_ptr->type == VRMR_TYPE_NETWORK  && strcmp(zone_ptr->zone_name, zonename)== 0)
        {
            if(zone_ptr->ipv4.network[0] == '\0' || zone_ptr->ipv4.netmask[0] == '\0')
                /* TRANSLATORS: max 32 chars */
                snprintf(temp, sizeof(temp), gettext("No network/netmask defined."));
            else
                snprintf(temp, sizeof(temp), "%s/%s", zone_ptr->ipv4.network, zone_ptr->ipv4.netmask);
            size = StrMemLen(temp) + 1;

            if(!(desc_ptr = malloc(size)))
            {
                vrmr_error(-1, VR_ERR, gettext("malloc failed: %s (in: %s:%d)."), strerror(errno), __FUNC__, __LINE__);
                return(-1);
            }

            (void)strlcpy(desc_ptr, temp, size);

            if(vrmr_list_append(debuglvl, &ZonesSection.network_desc_list, desc_ptr)  == NULL)
            {
                vrmr_error(-1, VR_INTERR, "vrmr_list_append() failed (in: %s:%d).", __FUNC__, __LINE__);
                return(-1);
            }

            if(!(ZonesSection.networkitems[i] = new_item(zone_ptr->network_name, desc_ptr)))
            {
                vrmr_error(-1, VR_INTERR, "new_item() failed (in: %s:%d).", __FUNC__, __LINE__);
                return(-1);
            }

            i--;
        }
    }
    ZonesSection.networkitems[ZonesSection.network_n] = (ITEM *)NULL;

    if(ZonesSection.network_n > 0)
    {
        ZonesSection.n_top = ZonesSection.networkitems[0];
        ZonesSection.n_bot = ZonesSection.networkitems[ZonesSection.network_n - 1];
    }
    else
    {
        ZonesSection.n_top = NULL;
        ZonesSection.n_bot = NULL;
    }

    if(!(ZonesSection.n_menu = new_menu((ITEM **)ZonesSection.networkitems)))
    {
        vrmr_error(-1, VR_INTERR, "new_menu() failed (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    starty = 4;
    height = (int)(ZonesSection.network_n + 9);
    width  = VRMR_MAX_NETWORK + 32 + 4;
    
    if(maxy < starty + height + 4)
    {
        height = maxy - (2 * starty);
    }
    
    /* place on the same y as zones list */
    VrWinGetOffset(-1, -1, height, width, 4, ZonesSection.z_xre + 1, &starty, &startx);
    ZonesSection.n_yle = starty + height;
    ZonesSection.n_xre = startx + width;

    if(!(ZonesSection.n_win = newwin(height, width, starty, startx)))
    {
        vrmr_error(-1, VR_INTERR, "newwin() failed (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }
    if(!(ZonesSection.n_panel[0] = new_panel(ZonesSection.n_win)))
    {
        vrmr_error(-1, VR_INTERR, "new_panel() failed (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }
    wbkgd(ZonesSection.n_win, vccnf.color_win);
    keypad(ZonesSection.n_win, TRUE);

    set_menu_win(ZonesSection.n_menu, ZonesSection.n_win);
    set_menu_sub(ZonesSection.n_menu, derwin(ZonesSection.n_win, height-8, width-2, 3, 1));
    set_menu_format(ZonesSection.n_menu, height-9, 1);

    box(ZonesSection.n_win, 0, 0);
    print_in_middle(ZonesSection.n_win, 1, 0, width, gettext("Networks"), vccnf.color_win);
    mvwaddch(ZonesSection.n_win, 2, 0, ACS_LTEE);
    mvwhline(ZonesSection.n_win, 2, 1, ACS_HLINE, width-2);
    mvwaddch(ZonesSection.n_win, 2, width-1, ACS_RTEE);

    set_menu_back(ZonesSection.n_menu, vccnf.color_win);
    set_menu_fore(ZonesSection.n_menu, vccnf.color_win_rev);
    post_menu(ZonesSection.n_menu);
    
    mvwaddch(ZonesSection.n_win, height-6, 0, ACS_LTEE);
    mvwhline(ZonesSection.n_win, height-6, 1, ACS_HLINE, width-2);
    mvwaddch(ZonesSection.n_win, height-6, width-1, ACS_RTEE);

    mvwprintw(ZonesSection.n_win, height-5, 2, "<RET> %s", gettext("to enter the hosts/groups of this network"));
    mvwprintw(ZonesSection.n_win, height-4, 2, "<INS> %s", STR_NEW);
    mvwprintw(ZonesSection.n_win, height-3, 2, "<DEL> %s", STR_REMOVE);
    mvwprintw(ZonesSection.n_win, height-2, 2, "< e > %s", STR_EDIT);

    /* create the top and bottom fields */
    if(!(ZonesSection.n_win_top = newwin(1, 6, starty + 2, startx + width - 8)))
    {
        vrmr_error(-1, VR_ERR, gettext("creating window failed."));
        return(-1);
    }
    wbkgd(ZonesSection.n_win_top, vccnf.color_win);
    ZonesSection.n_panel_top[0] = new_panel(ZonesSection.n_win_top);
    /* TRANSLATORS: max 4 chars */
    wprintw(ZonesSection.n_win_top, "(%s)", gettext("more"));
    hide_panel(ZonesSection.n_panel_top[0]);

    if(!(ZonesSection.n_win_bot = newwin(1, 6, starty + height - 6, startx + width - 8)))
    {
        vrmr_error(-1, VR_ERR, gettext("creating window failed."));
        return(-1);
    }
    wbkgd(ZonesSection.n_win_bot, vccnf.color_win);
    ZonesSection.n_panel_bot[0] = new_panel(ZonesSection.n_win_bot);
    /* TRANSLATORS: max 4 chars */
    wprintw(ZonesSection.n_win_bot, "(%s)", gettext("more"));
    hide_panel(ZonesSection.n_panel_bot[0]);

    update_panels();
    doupdate();

    return(retval);
}

static int
zones_section_menu_networks_destroy(const int debuglvl)
{
    int     retval = 0;
    size_t  i = 0;

    unpost_menu(ZonesSection.n_menu);
    free_menu(ZonesSection.n_menu);

    for(i = 0; i < ZonesSection.network_n; ++i)
        free_item(ZonesSection.networkitems[i]);

    free(ZonesSection.networkitems);

    del_panel(ZonesSection.n_panel[0]);
    destroy_win(ZonesSection.n_win);

    vrmr_list_cleanup(debuglvl, &ZonesSection.network_desc_list);

    del_panel(ZonesSection.n_panel_top[0]);
    destroy_win(ZonesSection.n_win_top);
    del_panel(ZonesSection.n_panel_bot[0]);
    destroy_win(ZonesSection.n_win_bot);

    return(retval);
}


int
zones_section_menu_networks(const int debuglvl,
        struct vrmr_ctx *vctx,
        struct vrmr_zones *zones,
        struct vrmr_interfaces *interfaces,
        struct vrmr_rules *rules,
        struct vrmr_blocklist *blocklist,
        char *zonename,
        struct vrmr_regex *reg)
{
    int     ch,
            quit = 0,
            reload = 0,
            result = 0,
            retval = 0;
    size_t  size = 0;
    char    *vrmr_new_zone_ptr = NULL,
            *zonename_ptr = NULL,
            *cur_zonename_ptr = NULL,
            *choices[] =    {   gettext("Hosts"),
                                gettext("Groups"),
                                gettext("Network")},
            *temp_ptr = NULL,
            *choice_ptr = NULL;
    ITEM    *cur = NULL;

    /* top menu */
    char    *key_choices[] =    {   "F12",
                                    "INS",
                                    "DEL",
                                    "r",
                                    "RET",
                                    "e",
                                    "F10"};
    int     key_choices_n = 7;
    char    *cmd_choices[] =    {   gettext("help"),
                                    gettext("new"),
                                    gettext("del"),
                                    gettext("rename"),
                                    gettext("open"),
                                    gettext("edit"),
                                    gettext("back")};
    int     cmd_choices_n = 7;
    
    /* safety */
    if( zonename == NULL || reg == NULL || interfaces == NULL ||
        zones == NULL || rules == NULL || blocklist == NULL)
    {
        vrmr_error(-1, VR_INTERR, "parameter problem (in: %s:%d).",
                                __FUNC__, __LINE__);
        return(-1);
    }

    if(zones_section_menu_networks_init(debuglvl, zones, zonename) < 0)
    {
        vrmr_error(-1, VR_INTERR, "zones_section_menu_networks_init() failed (in: %s:%d).",
                                __FUNC__, __LINE__);
        return(-1);
    }
    
    draw_top_menu(debuglvl, top_win, gettext("Networks"), key_choices_n, key_choices, cmd_choices_n, cmd_choices);

    while(quit == 0)
    {
        if(reload == 1)
        {
            if(zones_section_menu_networks_destroy(debuglvl) < 0)
            {
                vrmr_error(-1, VR_INTERR, "zones_section_menu_networks_destroy() failed (in: %s:%d).",
                                __FUNC__, __LINE__);
                return(-1);
            }

            if(zones_section_menu_networks_init(debuglvl, zones, zonename) < 0)
            {
                vrmr_error(-1, VR_INTERR, "zones_section_menu_networks_init() failed (in: %s:%d).",
                                __FUNC__, __LINE__);
                return(-1);
            }

            reload = 0;
        }

        while(quit == 0 && reload == 0)
        {
            if(ZonesSection.n_top != NULL && !item_visible(ZonesSection.n_top))
                show_panel(ZonesSection.n_panel_top[0]);
            else
                hide_panel(ZonesSection.n_panel_top[0]);

            if(ZonesSection.n_bot != NULL && !item_visible(ZonesSection.n_bot))
                show_panel(ZonesSection.n_panel_bot[0]);
            else
                hide_panel(ZonesSection.n_panel_bot[0]);

            update_panels();
            doupdate();

            /* restore the cursor */
            pos_menu_cursor(ZonesSection.n_menu);

            ch = wgetch(ZonesSection.n_win);

            switch(ch)
            {
                case 27:
                case KEY_F(10): // exit/back
                case 'q':
                case 'Q':

                    quit = 1;
                    break;

                case 'r':
                case 'R':

                    if(current_item(ZonesSection.n_menu))
                    {
                        /* get the current item */
                        if(!(cur = current_item(ZonesSection.n_menu)))
                        {
                            vrmr_error(-1, VR_INTERR, "NULL pointer (in: %s:%d).",
                                                __FUNC__, __LINE__);
                            return(-1);
                        }

                        size = StrMemLen((char *)item_name(cur))+1+StrMemLen(zonename)+1;

                        if(!(cur_zonename_ptr = malloc(size)))
                        {
                            vrmr_error(-1, VR_ERR, gettext("malloc failed: %s (in: %s:%d)."), strerror(errno), __func__, __LINE__);
                            return(-1);
                        }

                        /* create the network name string */
                        (void)strlcpy(cur_zonename_ptr, (char *)item_name(cur), size);
                        (void)strlcat(cur_zonename_ptr, ".", size);
                        (void)strlcat(cur_zonename_ptr, zonename, size);

                        /* rename */
                        vrmr_new_zone_ptr = input_box(VRMR_MAX_HOST, gettext("Rename Network"), gettext("Enter the new name of the network"));
                        if(vrmr_new_zone_ptr != NULL)
                        {
                            if(vrmr_validate_zonename(debuglvl, vrmr_new_zone_ptr, 1, NULL, NULL, NULL, reg->network_part, VRMR_VERBOSE) == -1)
                            {
                                vrmr_warning(VR_WARN, gettext("invalid networkname '%s'."), vrmr_new_zone_ptr);
                            }
                            else
                            {
                                /* get the size */
                                size = StrMemLen(vrmr_new_zone_ptr) + 1 + StrMemLen(zonename) + 1;

                                /* alloc the memory */
                                if(!(temp_ptr = malloc(size)))
                                {
                                    vrmr_error(-1, VR_ERR, gettext("malloc failed: %s (in: %s:%d)."), strerror(errno), __func__, __LINE__);
                                    free(vrmr_new_zone_ptr);
                                    return(-1);
                                }

                                /* create the string */
                                (void)strlcpy(temp_ptr, vrmr_new_zone_ptr, size);
                                (void)strlcat(temp_ptr, ".", size);
                                (void)strlcat(temp_ptr, zonename, size);

                                if(vrmr_validate_zonename(debuglvl, temp_ptr, 1, NULL, NULL, NULL, reg->zonename, VRMR_VERBOSE) == 0)
                                {
                                    if (zones_rename_network_zone(debuglvl, vctx, zones, rules, blocklist, cur_zonename_ptr, temp_ptr, VRMR_TYPE_NETWORK, reg) < 0)
                                    {
                                        vrmr_error(-1, VR_ERR, gettext("renaming network failed."));
                                    }
                                    else
                                    {
                                        /* we have a renamed network, so reload the menu */
                                        reload = 1;
                                    }
                                }
                                else
                                {
                                    vrmr_warning(VR_WARN, gettext("'%s' is an invalid name for a network."), vrmr_new_zone_ptr);
                                }
                                free(temp_ptr);
                            }

                            free(vrmr_new_zone_ptr);
                        }
                        free(cur_zonename_ptr);
                    }
                    break;

                case KEY_IC:    /* insert */
                case 'i':
                case 'I':

                    vrmr_new_zone_ptr = input_box(VRMR_MAX_NETWORK, gettext("New Network"), gettext("Enter the name of the new network"));
                    if(vrmr_new_zone_ptr != NULL)
                    {
                        if(vrmr_validate_zonename(debuglvl, vrmr_new_zone_ptr, 1, NULL, NULL, NULL, reg->network_part, VRMR_VERBOSE) == -1)
                        {
                            vrmr_warning(VR_WARN, gettext("invalid networkname '%s'."), vrmr_new_zone_ptr);
                        }
                        else
                        {
                            size = StrMemLen(vrmr_new_zone_ptr)+1+StrMemLen(zonename)+1;

                            temp_ptr = malloc(size);
                            if(temp_ptr != NULL)
                            {
                                (void)strlcpy(temp_ptr, vrmr_new_zone_ptr, size);
                                (void)strlcat(temp_ptr, ".", size);
                                (void)strlcat(temp_ptr, zonename, size);

                                if(vrmr_validate_zonename(debuglvl, temp_ptr, 1, NULL, NULL, NULL, reg->zonename, VRMR_VERBOSE) == 0)
                                {
                                    if (vrmr_new_zone(debuglvl, vctx, zones, temp_ptr, VRMR_TYPE_NETWORK) < 0)
                                    {
                                        vrmr_error(-1, VR_ERR, gettext("adding network failed."));
                                    }
                                    else
                                    {
                                        vrmr_audit("%s '%s' %s.",
                                            STR_NETWORK, temp_ptr,
                                            STR_HAS_BEEN_CREATED);

                                        (void)edit_zone_network(debuglvl, vctx, zones, interfaces, temp_ptr);
                                        reload = 1;
                                    }
                                }
                                else
                                {
                                    vrmr_warning(VR_WARN, gettext("'%s' is an invalid name for a network."), vrmr_new_zone_ptr);
                                }
                            }
                            free(temp_ptr);
                        }
                        free(vrmr_new_zone_ptr);
                    }
                    break;

                case KEY_DC:    /* delete */
                case 'd':
                case 'D':

                    cur = current_item(ZonesSection.n_menu);
                    if(cur)
                    {
                        if( vrmr_count_zones(debuglvl, zones, VRMR_TYPE_HOST, (char *)item_name(cur), zonename) <= 0   &&
                            vrmr_count_zones(debuglvl, zones, VRMR_TYPE_GROUP, (char *)item_name(cur), zonename) <= 0)
                        {
                            if (confirm(gettext("Delete"), gettext("This network?"),
                                        vccnf.color_win_note, vccnf.color_win_note_rev|A_BOLD, 0) == 1)
                            {
                                size = StrMemLen((char *)item_name(cur))+1+StrMemLen(zonename)+1;
                                if(size > 0)
                                {
                                    if((zonename_ptr = malloc(size)))
                                    {
                                        (void)strlcpy(zonename_ptr, (char *)item_name(cur), size);
                                        (void)strlcat(zonename_ptr, ".", size);
                                        (void)strlcat(zonename_ptr, zonename, size);

                                        result = vrmr_delete_zone(debuglvl, vctx, zones, zonename_ptr, VRMR_TYPE_NETWORK);
                                        if(result < 0)
                                            vrmr_error(result, VR_ERR, gettext("deleting network failed."));
                                        else
                                            reload = 1;

                                        vrmr_audit("%s '%s' %s.",
                                            STR_NETWORK, zonename_ptr,
                                            STR_HAS_BEEN_DELETED);

                                        free(zonename_ptr);
                                    }
                                }
                            }
                        }
                        else
                        {
                            vrmr_error(-1, VR_ERR, gettext("unable to delete: network not empty."));
                        }
                    }
                    break;

                case KEY_DOWN:
                    menu_driver(ZonesSection.n_menu, REQ_DOWN_ITEM);
                    break;
                case KEY_UP:
                    menu_driver(ZonesSection.n_menu, REQ_UP_ITEM);
                    break;
                case KEY_NPAGE:
                    if(menu_driver(ZonesSection.n_menu, REQ_SCR_DPAGE) != E_OK)
                    {
                        while(menu_driver(ZonesSection.n_menu, REQ_DOWN_ITEM) == E_OK);
                    }
                    break;
                case KEY_PPAGE:
                    if(menu_driver(ZonesSection.n_menu, REQ_SCR_UPAGE) != E_OK)
                    {
                        while(menu_driver(ZonesSection.n_menu, REQ_UP_ITEM) == E_OK);
                    }
                    break;
                case KEY_HOME:
                    menu_driver(ZonesSection.n_menu, REQ_FIRST_ITEM);   // home
                    break;
                case KEY_END:
                    menu_driver(ZonesSection.n_menu, REQ_LAST_ITEM);    // end
                    break;

                case KEY_RIGHT:
                case 10: // enter
                case 'b':
                case 'B':

                    cur = current_item(ZonesSection.n_menu);
                    if(cur)
                    {
                        choice_ptr = selectbox(gettext("Select"), gettext("Hosts, Groups or this Network"), 3, choices, 1, NULL);
                        if(choice_ptr != NULL)
                        {
                            if(strcmp(choice_ptr, gettext("Hosts")) == 0)
                            {
                                (void)zones_section_menu_hosts(debuglvl, vctx, zones, rules, blocklist, zonename, (char *)item_name(cur), reg);
                            }
                            else if(strcmp(choice_ptr, gettext("Groups")) == 0)
                            {
                                (void)zones_section_menu_groups(debuglvl, vctx, zones, rules, blocklist, zonename, (char *)item_name(cur), reg);
                            }
                            else
                            {
                                size = StrMemLen((char *)item_name(cur))+1+StrMemLen(zonename)+1;
                                if(size > 0)
                                {
                                    if(!(zonename_ptr = malloc(size)))
                                    {
                                        vrmr_error(-1, VR_ERR, gettext("malloc failed: %s (in: %s:%d)."), strerror(errno), __func__, __LINE__);
                                        retval = -1;
                                    }
                                    else
                                    {
                                        (void)strlcpy(zonename_ptr, (char *)item_name(cur), size);
                                        (void)strlcat(zonename_ptr, ".", size);
                                        (void)strlcat(zonename_ptr, zonename, size);

                                        /*  edit the network. We don't care about the result.
                                            If there is an error, its up to the user to decide
                                            what to do. */
                                        if(edit_zone_network(debuglvl, vctx, zones, interfaces, zonename_ptr) == 1)
                                            reload = 1;

                                        free(zonename_ptr);
                                    }
                                }
                            }
                            free(choice_ptr);
                        }
                        
                        draw_top_menu(debuglvl, top_win, gettext("Networks"), key_choices_n, key_choices, cmd_choices_n, cmd_choices);
                    }
                    break;

                case 'g':   /* group quick key */
                case 'G':   /* group quick key */

                    cur = current_item(ZonesSection.n_menu);
                    if(cur)
                    {
                        (void)zones_section_menu_groups(debuglvl, vctx, zones, rules, blocklist, zonename, (char *)item_name(cur), reg);
                    }
                    break;

                case 'h':   /* host quick key */
                case 'H':   /* host quick key */

                    cur = current_item(ZonesSection.n_menu);
                    if(cur)
                    {
                        (void)zones_section_menu_hosts(debuglvl, vctx, zones, rules, blocklist, zonename, (char *)item_name(cur), reg);
                    }
                    break;

                case 'e':
                case 'E':
                case 32:    /* spacebar */

                    cur = current_item(ZonesSection.n_menu);
                    if(cur)
                    {
                        size = StrMemLen((char *)item_name(cur))+1+StrMemLen(zonename)+1;
                        if(size > 0)
                        {
                            if(!(zonename_ptr = malloc(size)))
                            {
                                vrmr_error(-1, VR_ERR, gettext("malloc failed: %s (in: %s:%d)."), strerror(errno), __func__, __LINE__);
                                retval = -1;
                            }
                            else
                            {
                                (void)strlcpy(zonename_ptr, (char *)item_name(cur), size);
                                (void)strlcat(zonename_ptr, ".", size);
                                (void)strlcat(zonename_ptr, zonename, size);

                                /*  edit the network. We don't care about the result.
                                    If there is an error, its up to the user to decide
                                    what to do. */
                                if(edit_zone_network(debuglvl, vctx, zones, interfaces, zonename_ptr) == 1)
                                    reload = 1;

                                free(zonename_ptr);
                            }
                        }
                    }

                    break;

                case '?':
                case KEY_F(12):
                    print_help(debuglvl, ":[VUURMUUR:ZONES:NETWORKS]:");
                    break;

            }
        }
    }

    if(zones_section_menu_networks_destroy(debuglvl) < 0)
    {
        vrmr_error(-1, VR_INTERR, "zones_section_menu_networks_destroy() failed (in: %s:%d).", __FUNC__, __LINE__);
        retval = -1;
    }

    update_panels();
    doupdate();

    status_print(status_win, gettext("Ready."));
    return(retval);
}


struct
{
    FIELD   *activefld,
            *activelabelfld,

            *commentfld,
            *commentlabelfld;
} ZoneSec;


static int
edit_zone_zone_init(const int debuglvl, struct vrmr_ctx *vctx,
        struct vrmr_zones *zones, char *name,
        int height, int width, int starty, int startx, struct vrmr_zone *zone_ptr)
{
    int     retval = 0;
    int     rows,
            cols;
    size_t  i = 0;
    int     comment_y = 0,
            comment_x = 0;
    unsigned int     field_num = 0;

    /* safety */
    if(name == NULL || zone_ptr == NULL || zones == NULL)
    {
        vrmr_error(-1, VR_INTERR, "parameter problem (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    /* alloc fields */
    ZonesSection.EditZone.n_fields = 4;

    if(!(ZonesSection.EditZone.fields = (FIELD **)calloc(ZonesSection.EditZone.n_fields + 1, sizeof(FIELD *))))
    {
        vrmr_error(-1, VR_ERR, gettext("calloc failed: %s (in: %s:%d)."), strerror(errno), __func__, __LINE__);
        return(-1);
    }

    ZoneSec.activelabelfld = (ZonesSection.EditZone.fields[field_num++] = new_field(1, 16, 2, 0, 0, 0));
    set_field_buffer_wrap(debuglvl, ZoneSec.activelabelfld, 0, gettext("Active"));
    field_opts_off(ZoneSec.activelabelfld, O_AUTOSKIP | O_ACTIVE);

    ZoneSec.activefld = (ZonesSection.EditZone.fields[field_num++] = new_field(1, 3, 3, 1, 0, 0));
    set_field_buffer_wrap(debuglvl, ZoneSec.activefld, 0, zone_ptr->active ? STR_YES : STR_NO);

    ZoneSec.commentlabelfld = (ZonesSection.EditZone.fields[field_num++] = new_field(1, 16, 5, 0, 0, 0));
    set_field_buffer_wrap(debuglvl, ZoneSec.commentlabelfld, 0, gettext("Comment"));
    field_opts_off(ZoneSec.commentlabelfld, O_AUTOSKIP | O_ACTIVE);

    /* comment field size */
    comment_y = 5;
    comment_x = 48;
    /* create and label the comment field */
    ZoneSec.commentfld = (ZonesSection.EditZone.fields[field_num++] = new_field(comment_y, comment_x, 6, 1, 0, 0));
    /* load the comment from the backend */
    if (vctx->zf->ask(debuglvl, vctx->zone_backend, zone_ptr->name, "COMMENT", ZonesSection.comment, sizeof(ZonesSection.comment), VRMR_TYPE_ZONE, 0) < 0)
        vrmr_error(-1, "Error", "error while loading the comment.");

    set_field_buffer_wrap(debuglvl, ZoneSec.commentfld, 0, ZonesSection.comment);

    if (field_num != ZonesSection.EditZone.n_fields) {
        vrmr_error(-1, VR_INTERR, "parameter problem (in: %s:%d).",
                __FUNC__, __LINE__);
        return(-1);
    }

    ZonesSection.EditZone.fields[ZonesSection.EditZone.n_fields] = NULL;

    /* create the window and panel */
    if(!(ZonesSection.EditZone.win = create_newwin(height, width, starty, startx, gettext("Edit Zone: Zone"), vccnf.color_win)))
    {
        vrmr_error(-1, VR_INTERR, "create_newwin() failed (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }
    if(!(ZonesSection.EditZone.panel[0] = new_panel(ZonesSection.EditZone.win)))
    {
        vrmr_error(-1, VR_INTERR, "new_panel() failed (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }
    keypad(ZonesSection.EditZone.win, TRUE);

    /* set the options */
    for(i=0; i < ZonesSection.EditZone.n_fields; i++)
    {
        set_field_back(ZonesSection.EditZone.fields[i], vccnf.color_win_rev);
        field_opts_off(ZonesSection.EditZone.fields[i], O_AUTOSKIP);
        set_field_status(ZonesSection.EditZone.fields[i], FALSE);
    }
    set_field_back(ZoneSec.activelabelfld, vccnf.color_win);
    set_field_back(ZoneSec.commentlabelfld, vccnf.color_win);

    /* Create the form and post it */
    if(!(ZonesSection.EditZone.form = new_form(ZonesSection.EditZone.fields)))
    {
        vrmr_error(-1, VR_INTERR, "new_form() failed (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }
    scale_form(ZonesSection.EditZone.form, &rows, &cols);
    set_form_win(ZonesSection.EditZone.form, ZonesSection.EditZone.win);
    set_form_sub(ZonesSection.EditZone.form, derwin(ZonesSection.EditZone.win, rows, cols, 1, 2));
    post_form(ZonesSection.EditZone.form);

    /* draw labels and other information */
    mvwprintw(ZonesSection.EditZone.win, 1, 2, "%s: %s", gettext("Name"), zone_ptr->name);

    mvwprintw(ZonesSection.EditZone.win, 3, 35, "%s",  gettext("Networks"));
    mvwprintw(ZonesSection.EditZone.win, 3, 45, "%4d", vrmr_count_zones(debuglvl, zones, VRMR_TYPE_NETWORK, NULL, zone_ptr->name));
    mvwprintw(ZonesSection.EditZone.win, 4, 35, "%s",  gettext("Hosts"));
    mvwprintw(ZonesSection.EditZone.win, 4, 45, "%4d", vrmr_count_zones(debuglvl, zones, VRMR_TYPE_HOST, NULL, zone_ptr->name));
    mvwprintw(ZonesSection.EditZone.win, 5, 35, "%s",  gettext("Groups"));
    mvwprintw(ZonesSection.EditZone.win, 5, 45, "%4d", vrmr_count_zones(debuglvl, zones, VRMR_TYPE_GROUP, NULL, zone_ptr->name));

    /* draw and set cursor */
    wrefresh(ZonesSection.EditZone.win);
    pos_form_cursor(ZonesSection.EditZone.form);
    
    update_panels();
    doupdate();

    return(retval);
}


static int
edit_zone_zone_save(const int debuglvl, struct vrmr_ctx *vctx, struct vrmr_zone *zone_ptr)
{
    int     retval = 0,
            active = 0;
    size_t  i = 0;

    /* safety */
    if(!zone_ptr)
    {
        vrmr_error(-1, VR_INTERR, "parameter problem (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    /* check for changed fields */
    for(i = 0; i < ZonesSection.EditZone.n_fields; i++)
    {
        /* check is field is changed */
        if(field_status(ZonesSection.EditZone.fields[i]) == TRUE)
        {
            /* active */
            if(ZonesSection.EditZone.fields[i] == ZoneSec.activefld)
            {
                zone_ptr->status = VRMR_ST_CHANGED;

                active = zone_ptr->active;

                if(strncasecmp(field_buffer(ZonesSection.EditZone.fields[i], 0), STR_YES, StrLen(STR_YES)) == 0)
                {
                    zone_ptr->active = TRUE;
                }
                else
                {
                    zone_ptr->active = FALSE;
                }

                /* save to backend */
                if (vctx->zf->tell(debuglvl, vctx->zone_backend, zone_ptr->name, "ACTIVE", zone_ptr->active ? "Yes" : "No", 1, VRMR_TYPE_ZONE) < 0)
                {
                    vrmr_error(-1, VR_ERR, gettext("saving to backend failed (in: %s:%d)."), __FUNC__, __LINE__);
                    retval = -1;
                }

                /* for the log */
                vrmr_audit("%s '%s' %s: %s %s '%s' (%s: '%s').",
                    STR_ZONE, zone_ptr->name, STR_HAS_BEEN_CHANGED, STR_ACTIVE,
                    STR_IS_NOW_SET_TO, zone_ptr->active ? STR_YES : STR_NO,
                    STR_WAS, active ? STR_YES : STR_NO);
            }
            /* comment */
            else if(ZonesSection.EditZone.fields[i] == ZoneSec.commentfld)
            {
                /* save the comment field to the backend */
                if (vctx->zf->tell(debuglvl, vctx->zone_backend, zone_ptr->name, "COMMENT", field_buffer(ZonesSection.EditZone.fields[i], 0), 1, VRMR_TYPE_ZONE) < 0)
                {
                    vrmr_error(-1, VR_ERR, gettext("saving to backend failed (in: %s:%d)."), __FUNC__, __LINE__);
                    retval = -1;
                }

                /* example: "network 'ext' has been changed: the comment was changed." */
                vrmr_audit("%s '%s' %s: %s.",
                    STR_ZONE, zone_ptr->name, STR_HAS_BEEN_CHANGED, STR_COMMENT_CHANGED);
            }
            else
            {
                vrmr_error(-1, VR_INTERR, "unknown field (in: %s:%d).", __FUNC__, __LINE__);
                retval = -1;
            }
        }
    }

    return(retval);
}


static void
edit_zone_zone_destroy(void)
{
    size_t  i = 0;

    // Un post form and free the memory
    unpost_form(ZonesSection.EditZone.form);
    free_form(ZonesSection.EditZone.form);

    for(i=0;i<ZonesSection.EditZone.n_fields;i++)
    {
        free_field(ZonesSection.EditZone.fields[i]);
    }
    free(ZonesSection.EditZone.fields);

    del_panel(ZonesSection.EditZone.panel[0]);
    destroy_win(ZonesSection.EditZone.win);

    // clear comment string
    strcpy(ZonesSection.comment, "");
}


/*  edit_zone_zone

    Edits a zone!

    Returncodes:
        0: ok
        -1: error
*/
static int
edit_zone_zone(const int debuglvl, struct vrmr_ctx *vctx,
        struct vrmr_zones *zones, char *name)
{
    int                 ch, /* for the keys */
                        not_defined = 0,/* 1 is a key is defined */
                        quit = 0,
                        retval = 0;
    struct vrmr_zone    *zone_ptr = NULL;
    int                 height,
                        width,
                        startx,
                        starty;
    FIELD               *cur = NULL,
                        *prev = NULL;
    char                *key_choices[] =    {   "F12",
                                                "F10"};
    int                 key_choices_n = 2;
    char                *cmd_choices[] =    {   gettext("help"),
                                                gettext("back")};
    int                 cmd_choices_n = 2;

    /* safety */
    if(!name || !zones)
    {
        vrmr_error(-1, VR_INTERR, "parameter problem (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    height = 20;
    width = 54;
    /* place on the same y as zones list */
    VrWinGetOffset(-1, -1, height, width, 4, ZonesSection.z_xre + 1, &starty, &startx);

    /* look for the zone in the list */
    if(!(zone_ptr = vrmr_search_zonedata(debuglvl, zones, name)))
    {
        vrmr_error(-1, VR_INTERR, "zone not found in memory (in: %s:%d).", __FUNC__, __LINE__);
        return(0);
    }

    /* setup the window and fields */
    if (edit_zone_zone_init(debuglvl, vctx, zones, name,
                height, width, starty, startx, zone_ptr) < 0)
        return(-1);

    cur = current_field(ZonesSection.EditZone.form);

    draw_top_menu(debuglvl, top_win, gettext("Edit Zone"), key_choices_n, key_choices, cmd_choices_n, cmd_choices);

    update_panels();
    doupdate();

    /* Loop through to get user requests/commands */
    while(quit == 0)
    {
        draw_field_active_mark(cur, prev, ZonesSection.EditZone.win, ZonesSection.EditZone.form, vccnf.color_win_mark|A_BOLD);

        not_defined = 0;

        /* get user input */
        ch = wgetch(ZonesSection.EditZone.win);

        /* user fields */

        /* comment */
        if(cur == ZoneSec.commentfld)
        {
            if(nav_field_comment(debuglvl, ZonesSection.EditZone.form, ch) < 0)
                not_defined = 1;
        }
        /* active */
        else if(cur == ZoneSec.activefld)
        {
            if(nav_field_yesno(debuglvl, ZonesSection.EditZone.form, ch) < 0)
                not_defined = 1;
        }
        else
            not_defined = 1;
        
        /* keys special for this window */
        if(not_defined == 1)
        {
            switch(ch)
            {
                case KEY_DOWN:
                case 10:    // enter
                case 9: // tab
                    form_driver(ZonesSection.EditZone.form, REQ_NEXT_FIELD);
                    form_driver(ZonesSection.EditZone.form, REQ_BEG_LINE);
                    break;

                case KEY_UP:
                    // Go to previous field
                    form_driver(ZonesSection.EditZone.form, REQ_PREV_FIELD);
                    form_driver(ZonesSection.EditZone.form, REQ_BEG_LINE);
                    break;

                case 27:
                case KEY_F(10):
                case 'q':
                case 'Q':
                    quit = 1;
                    break;

                case KEY_F(12):
                case 'h':
                case 'H':
                case '?':
                    print_help(debuglvl, ":[VUURMUUR:ZONES:ZONE:EDIT]:");
                    break;
            }
        }

        /* set current field to prev */
        prev = cur;
        cur = current_field(ZonesSection.EditZone.form);

        /* draw and set cursor */
        wrefresh(ZonesSection.EditZone.win);
        pos_form_cursor(ZonesSection.EditZone.form);
    }

    /* save changes (if any) */
    if (edit_zone_zone_save(debuglvl, vctx, zone_ptr) < 0)
        retval = -1;

    /* cleanup */
    edit_zone_zone_destroy();
    update_panels();
    doupdate();

    status_print(status_win, gettext("Ready."));
    return(retval);
}


/*
    TODO:
        list as func arg
*/
static int
zones_section_init(const int debuglvl, struct vrmr_zones *zones)
{
    int                 retval = 0;
    size_t              i = 0;
    struct vrmr_zone    *zone_ptr = NULL;
    int                 height,
                        width,
                        startx,
                        starty,
                        maxy;
    size_t              zones_cnt = 0;
    struct vrmr_list_node         *d_node = NULL;

    maxy = getmaxy(stdscr);

    if (zones == NULL) {
        return(-1);
    }

    /* count how many zones there are */
    for(d_node = zones->list.top; d_node ; d_node = d_node->next)
    {
        if(!(zone_ptr = d_node->data))
        {
            vrmr_error(-1, VR_INTERR, "NULL pointer (in: %s:%d).", __FUNC__, __LINE__);
            return(-1);
        }

        if(zone_ptr->type == VRMR_TYPE_ZONE)
            zones_cnt++;
    }
    ZonesSection.zone_n = zones_cnt;
    i = zones_cnt - 1;

    if(!(ZonesSection.zoneitems = (ITEM **)calloc(ZonesSection.zone_n + 1, sizeof(ITEM *))))
    {
        vrmr_error(-1, VR_ERR, gettext("calloc failed: %s (in: %s:%d)."), strerror(errno), __func__, __LINE__);
        return(-1);
    }

    for(d_node = zones->list.bot; d_node ; d_node = d_node->prev)
    {
        if(!(zone_ptr = d_node->data))
        {
            vrmr_error(-1, VR_INTERR, "NULL pointer (in: %s:%d).", __FUNC__, __LINE__);
            return(-1);
        }

        if(zone_ptr->type == VRMR_TYPE_ZONE)
        {
            if(!(ZonesSection.zoneitems[i] = new_item(zone_ptr->name, NULL)))
            {
                vrmr_error(-1, VR_INTERR, "new_item() failed (in: %s:%d).", __FUNC__, __LINE__);
                return(-1);
            }

            i--;
        }
    }
    ZonesSection.zoneitems[ZonesSection.zone_n] = (ITEM *)NULL;

    if(ZonesSection.zone_n > 0)
    {
        ZonesSection.z_top = ZonesSection.zoneitems[0];
        ZonesSection.z_bot = ZonesSection.zoneitems[ZonesSection.zone_n - 1];
    }
    else
    {
        ZonesSection.z_top = NULL;
        ZonesSection.z_bot = NULL;
    }

    if(!(ZonesSection.menu = new_menu((ITEM **)ZonesSection.zoneitems)))
    {
        vrmr_error(-1, VR_INTERR, "new_menu() failed (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    height = (int)(ZonesSection.zone_n + 9);
    width  = 45;
    startx = 1;
    starty = 4;

    if(maxy < starty + height + 4)
    {
        starty = 4;
        height = maxy - (2 * starty);
    }

    ZonesSection.z_yle = starty + height;
    ZonesSection.z_xre = startx + width;

    if(!(ZonesSection.win = newwin(height, width, starty, startx)))
    {
        vrmr_error(-1, VR_INTERR, "newwin() failed (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }
    if(!(ZonesSection.panel[0] = new_panel(ZonesSection.win)))
    {
        vrmr_error(-1, VR_INTERR, "new_panel() failed (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }
    wbkgd(ZonesSection.win, vccnf.color_win);
    keypad(ZonesSection.win, TRUE);

    set_menu_win(ZonesSection.menu, ZonesSection.win);
    set_menu_sub(ZonesSection.menu, derwin(ZonesSection.win, height-8, width-2, 3, 1));
    set_menu_format(ZonesSection.menu, height-9, 1);

    box(ZonesSection.win, 0, 0);
    print_in_middle(ZonesSection.win, 1, 0, width, gettext("Zones"), vccnf.color_win);
    mvwaddch(ZonesSection.win, 2, 0, ACS_LTEE);
    mvwhline(ZonesSection.win, 2, 1, ACS_HLINE, width-2);
    mvwaddch(ZonesSection.win, 2, width-1, ACS_RTEE);
    
    set_menu_back(ZonesSection.menu, vccnf.color_win);
    set_menu_fore(ZonesSection.menu, vccnf.color_win_rev);
    post_menu(ZonesSection.menu);

    mvwaddch(ZonesSection.win, height-6, 0, ACS_LTEE);
    mvwhline(ZonesSection.win, height-6, 1, ACS_HLINE, width-2);
    mvwaddch(ZonesSection.win, height-6, width-1, ACS_RTEE);

    /* print labels */
    mvwprintw(ZonesSection.win, height-5, 2, "<RET> %s", gettext("to enter the networks of this zone"));
    mvwprintw(ZonesSection.win, height-4, 2, "<INS> %s", STR_NEW);
    mvwprintw(ZonesSection.win, height-3, 2, "<DEL> %s", STR_REMOVE);
    mvwprintw(ZonesSection.win, height-2, 2, "< e > %s", STR_EDIT);

    /* create the top and bottom fields */
    if(!(ZonesSection.z_win_top = newwin(1, 6, starty + 2, startx + width - 8)))
    {
        vrmr_error(-1, VR_ERR, gettext("creating window failed."));
        return(-1);
    }
    wbkgd(ZonesSection.z_win_top, vccnf.color_win);
    ZonesSection.z_panel_top[0] = new_panel(ZonesSection.z_win_top);
    /* TRANSLATORS: max 4 chars */
    wprintw(ZonesSection.z_win_top, "(%s)", gettext("more"));
    hide_panel(ZonesSection.z_panel_top[0]);

    if(!(ZonesSection.z_win_bot = newwin(1, 6, starty + height - 6, startx + width - 8)))
    {
        vrmr_error(-1, VR_ERR, gettext("creating window failed."));
        return(-1);
    }
    wbkgd(ZonesSection.z_win_bot, vccnf.color_win);
    ZonesSection.z_panel_bot[0] = new_panel(ZonesSection.z_win_bot);
    /* TRANSLATORS: max 4 chars */
    wprintw(ZonesSection.z_win_bot, "(%s)", gettext("more"));
    hide_panel(ZonesSection.z_panel_bot[0]);

    update_panels();
    doupdate();

    return(retval);
}


int
zones_section_destroy(void)
{
    int     retval = 0;
    size_t  i = 0;

    unpost_menu(ZonesSection.menu);
    free_menu(ZonesSection.menu);
    for(i = 0; i < ZonesSection.zone_n; ++i)
        free_item(ZonesSection.zoneitems[i]);

    free(ZonesSection.zoneitems);
    
    del_panel(ZonesSection.panel[0]);
    destroy_win(ZonesSection.win);

    del_panel(ZonesSection.z_panel_top[0]);
    destroy_win(ZonesSection.z_win_top);
    del_panel(ZonesSection.z_panel_bot[0]);
    destroy_win(ZonesSection.z_win_bot);

    return(retval);
}


int
zones_section(const int debuglvl, struct vrmr_ctx *vctx, struct vrmr_zones *zones,
        struct vrmr_interfaces *interfaces, struct vrmr_rules *rules,
        struct vrmr_blocklist *blocklist, struct vrmr_regex *reg)
{
    int     ch = 0,
            quit = 0,
            reload = 0,
            result = 0,
            retval = 0;
    char    *vrmr_new_zone_ptr = NULL,
            save_zone_name[VRMR_MAX_ZONE] = "";
    ITEM    *cur = NULL;

    /* top menu */
    char    *key_choices[] =    {   "F12",
                                    "INS",
                                    "DEL",
                                    "r",
                                    "RET",
                                    "e",
                                    "F10"};
    int     key_choices_n = 7;
    char    *cmd_choices[] =    {   gettext("help"),
                                    gettext("new"),
                                    gettext("del"),
                                    gettext("rename"),
                                    gettext("open"),
                                    gettext("edit"),
                                    gettext("back")};
    int     cmd_choices_n = 7;

    /* safety */
    if(reg == NULL || interfaces == NULL || zones == NULL)
    {
        vrmr_error(-1, VR_INTERR, "parameter problem (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    if(zones_section_init(debuglvl, zones) < 0)
        return(-1);

    draw_top_menu(debuglvl, top_win, gettext("Zones"), key_choices_n, key_choices, cmd_choices_n, cmd_choices);

    while(quit == 0)
    {
        if(reload == 1)
        {
            if(zones_section_destroy() < 0)
                return(-1);
                
            if(zones_section_init(debuglvl, zones) < 0)
                return(-1);
                
            reload = 0;
        }

        while(quit == 0 && reload == 0)
        {
            if(ZonesSection.z_top != NULL && !item_visible(ZonesSection.z_top))
                show_panel(ZonesSection.z_panel_top[0]);
            else
                hide_panel(ZonesSection.z_panel_top[0]);

            if(ZonesSection.z_bot != NULL && !item_visible(ZonesSection.z_bot))
                show_panel(ZonesSection.z_panel_bot[0]);
            else
                hide_panel(ZonesSection.z_panel_bot[0]);

            update_panels();
            doupdate();

            /* restore the cursor */
            pos_menu_cursor(ZonesSection.menu);

            ch = wgetch(ZonesSection.win);

            switch(ch)
            {
                case 27:
                case KEY_F(10):
                case 'q':
                case 'Q':
                    quit=1;
                    break;

                case 'r':
                case 'R':

                    cur = current_item(ZonesSection.menu);
                    if(cur)
                    {
                        vrmr_new_zone_ptr = input_box(VRMR_MAX_HOST, gettext("Rename Zone"), gettext("Enter the new name of the zone"));
                        if(vrmr_new_zone_ptr != NULL)
                        {
                            if(vrmr_validate_zonename(debuglvl, vrmr_new_zone_ptr, 1, NULL, NULL, NULL, reg->zone_part, VRMR_VERBOSE) == 0)
                            {
                                if (zones_rename_network_zone(debuglvl, vctx, zones, rules, blocklist, (char *)item_name(cur), vrmr_new_zone_ptr, VRMR_TYPE_ZONE, reg) == 0)
                                {
                                    /* we have a renamed network, so reload the menu */
                                    reload = 1;
                                }
                            }

                            free(vrmr_new_zone_ptr);
                        }
                    }
                    break;

                case KEY_IC: //insert
                case 'i':
                case 'I':

                    vrmr_new_zone_ptr = input_box(VRMR_MAX_ZONE, gettext("New Zone"), gettext("Enter the name of the new zone"));
                    if(vrmr_new_zone_ptr != NULL)
                    {
                        if(vrmr_validate_zonename(debuglvl, vrmr_new_zone_ptr, 1, NULL, NULL, NULL, reg->zone_part, VRMR_VERBOSE) == 0)
                        {
                            if(vrmr_new_zone(debuglvl, vctx, zones, vrmr_new_zone_ptr, VRMR_TYPE_ZONE) < 0)
                            {
                                vrmr_error(result, VR_ERR, "adding zone failed (in: %s:%d).", __FUNC__);
                            }
                            else
                            {
                                vrmr_audit("%s '%s' %s.",
                                    STR_ZONE, vrmr_new_zone_ptr,
                                    STR_HAS_BEEN_CREATED);

                                if (edit_zone_zone(debuglvl, vctx, zones, vrmr_new_zone_ptr) < 0)
                                {
                                    retval = -1;
                                    quit = 1;
                                }

                                draw_top_menu(debuglvl, top_win, gettext("Zones"), key_choices_n, key_choices, cmd_choices_n, cmd_choices);
                            }
                        }
                        free(vrmr_new_zone_ptr);
                    }
                    reload = 1;
                    break;

                case KEY_DC: // delete
                case 'd':
                case 'D':

                    cur = current_item(ZonesSection.menu);
                    if(cur)
                    {
                        if( vrmr_count_zones(debuglvl, zones, VRMR_TYPE_NETWORK, NULL, (char *)item_name(cur)) <= 0   &&
                            vrmr_count_zones(debuglvl, zones, VRMR_TYPE_HOST, NULL, (char *)item_name(cur)) <= 0   &&
                            vrmr_count_zones(debuglvl, zones, VRMR_TYPE_GROUP, NULL, (char *)item_name(cur)) <= 0)
                        {
                            if (confirm(gettext("Delete"), gettext("This zone?"),
                                        vccnf.color_win_note, vccnf.color_win_note_rev|A_BOLD, 0) == 1)
                            {
                                /* for logging */
                                (void)strlcpy(save_zone_name, (char *)item_name(cur), sizeof(save_zone_name));

                                result = vrmr_delete_zone(debuglvl, vctx, zones, (char *)item_name(cur), VRMR_TYPE_ZONE);
                                if(result < 0)
                                {
                                    vrmr_error(result, VR_ERR, gettext("deleting zone failed (in: %s:%d)."), __FUNC__, __LINE__);
                                }
                                else
                                {
                                    vrmr_audit("%s '%s' %s.",
                                        STR_ZONE, save_zone_name,
                                        STR_HAS_BEEN_DELETED);

                                    reload = 1;
                                }
                            }
                        }
                        else
                        {
                            vrmr_error(-1, VR_ERR, gettext("unable to delete: zone not empty."));
                        }
                    }
                    break;

                case KEY_DOWN:
                    menu_driver(ZonesSection.menu, REQ_DOWN_ITEM);
                    break;
                case KEY_UP:
                    menu_driver(ZonesSection.menu, REQ_UP_ITEM);
                    break;
                case KEY_NPAGE:
                    if(menu_driver(ZonesSection.menu, REQ_SCR_DPAGE) != E_OK)
                    {
                        while(menu_driver(ZonesSection.menu, REQ_DOWN_ITEM) == E_OK);
                    }
                    break;
                case KEY_PPAGE:
                    if(menu_driver(ZonesSection.menu, REQ_SCR_UPAGE) != E_OK)
                    {
                        while(menu_driver(ZonesSection.menu, REQ_UP_ITEM) == E_OK);
                    }
                    break;
                case KEY_HOME:
                    menu_driver(ZonesSection.menu, REQ_FIRST_ITEM); // home
                    break;
                case KEY_END:
                    menu_driver(ZonesSection.menu, REQ_LAST_ITEM);  // end
                    break;

                case 'e':
                case 'E':
                case 32:

                    cur = current_item(ZonesSection.menu);
                    if(cur)
                    {
                        if (edit_zone_zone(debuglvl, vctx, zones, (char *)item_name(cur)) < 0)
                        {
                            retval = -1;
                            quit = 1;
                        }

                        draw_top_menu(debuglvl, top_win, gettext("Zones"), key_choices_n, key_choices, cmd_choices_n, cmd_choices);
                    }

                    break;

                case KEY_RIGHT:
                case 10:    // enter
                case 'b':   // b - browse
                case 'B':

                    cur = current_item(ZonesSection.menu);
                    if(cur)
                    {
                        char *n = (char *)item_name(cur);

                        if (zones_section_menu_networks(debuglvl, vctx, zones, interfaces, rules, blocklist, n, reg) < 0)
                        {
                            retval = -1;
                            quit = 1;
                        }

                        draw_top_menu(debuglvl, top_win, gettext("Zones"), key_choices_n, key_choices, cmd_choices_n, cmd_choices);
                    }
                    break;

                case KEY_F(12):
                case 'h':
                case 'H':
                case '?':
                    print_help(debuglvl, ":[VUURMUUR:ZONES:ZONES]:");
                    break;
            }
        }
    }

    if(zones_section_destroy() < 0)
        retval = -1;

    update_panels();
    doupdate();

    status_print(status_win, gettext("Ready."));
    return(retval);
}


static int
zones_blocklist_init(const int debuglvl, struct vrmr_blocklist *blocklist)
{
    int         retval=0,
                i = 0,
                result = 0;
    int         height = 0,
                width = 0,
                startx = 0,
                starty = 0,
                maxx = 0,
                maxy = 0;
    struct vrmr_list_node *d_node = NULL;
    char        *string = NULL;
    
    /* get the screensize */
    getmaxyx(stdscr, maxy, maxx);

    /* number of items */
    ZonesSection.host_n = blocklist->list.len;

    /* allow the menu items */
    if(!(ZonesSection.hostitems = (ITEM **)calloc(ZonesSection.host_n + 1, sizeof(ITEM *))))
    {
        vrmr_error(-1, VR_ERR, gettext("calloc failed: %s (in: %s:%d)."), strerror(errno), __func__, __LINE__);
        return(-1);
    }

    /* create the menu items */
    for(d_node = blocklist->list.top, i = 0; d_node ; d_node = d_node->next, i++)
    {
        if(!(string = d_node->data))
        {
            vrmr_error(-1, VR_INTERR, "NULL pointer (in: %s:%d).", __FUNC__, __LINE__);
            return(-1);
        }

        //vrmr_debug(__FUNC__, "string '%s'", string);

        if(!(ZonesSection.hostitems[i] = new_item(string, NULL)))
        {
            vrmr_error(-1, VR_INTERR, "new_item() failed (in: %s:%d).", __FUNC__, __LINE__);
            return(-1);
        }
    }

    /* terminate the items */
    ZonesSection.hostitems[ZonesSection.host_n] = (ITEM *)NULL;

    if(ZonesSection.host_n > 0)
    {
        ZonesSection.h_top = ZonesSection.hostitems[0];
        ZonesSection.h_bot = ZonesSection.hostitems[ZonesSection.host_n - 1];
    }
    else
    {
        ZonesSection.h_top = NULL;
        ZonesSection.h_bot = NULL;
    }

    /* now create the menu */
    if(!(ZonesSection.h_menu = new_menu((ITEM **)ZonesSection.hostitems)))
    {
        vrmr_error(-1, VR_INTERR, "new_menu() failed (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    /* now set the size of the window */
    height = (int)(ZonesSection.host_n + 7);
    width  = VRMR_VRMR_MAX_HOST_NET_ZONE + 2;
    startx = 1;
    starty = 4;

    if(maxy < starty + height + 4)
    {
        starty = 4;
        height = maxy - (2 * starty);
    }

    if(maxx < startx + width + 3)
    {
        startx = 1;
        width = maxx - 2 * startx;
    }

    if(!(ZonesSection.h_win = newwin(height, width, starty, startx)))
    {
        vrmr_error(-1, VR_INTERR, "newwin() failed (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }
    wbkgd(ZonesSection.h_win, vccnf.color_win);
    keypad(ZonesSection.h_win, TRUE);
    box(ZonesSection.h_win, 0, 0);
    print_in_middle(ZonesSection.h_win, 1, 0, width, gettext("BlockList"), vccnf.color_win);
    wrefresh(ZonesSection.h_win);

    if(!(ZonesSection.h_panel[0] = new_panel(ZonesSection.h_win)))
    {
        vrmr_error(-1, VR_INTERR, "new_panel() failed (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    set_menu_win(ZonesSection.h_menu, ZonesSection.h_win);
    set_menu_sub(ZonesSection.h_menu, derwin(ZonesSection.h_win, height-6, width-2, 3, 1));

    set_menu_format(ZonesSection.h_menu, height-7, 1);

    mvwaddch(ZonesSection.h_win, 2, 0, ACS_LTEE);
    mvwhline(ZonesSection.h_win, 2, 1, ACS_HLINE, width-2);
    mvwaddch(ZonesSection.h_win, 2, width-1, ACS_RTEE);

    set_menu_back(ZonesSection.h_menu, vccnf.color_win);
    set_menu_fore(ZonesSection.h_menu, vccnf.color_win_rev);

    result = post_menu(ZonesSection.h_menu);
    if(result != E_OK && result != E_NOT_CONNECTED)
    {
        vrmr_error(-1, VR_INTERR, "post_menu() failed (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    mvwaddch(ZonesSection.h_win, height-4, 0, ACS_LTEE);
    mvwhline(ZonesSection.h_win, height-4, 1, ACS_HLINE, width-2);
    mvwaddch(ZonesSection.h_win, height-4, width-1, ACS_RTEE);

    mvwprintw(ZonesSection.h_win, height-3, 1, "<INS> %s", STR_NEW);
    mvwprintw(ZonesSection.h_win, height-2, 1, "<DEL> %s", STR_REMOVE);

    /* create the top and bottom fields */
    if(!(ZonesSection.h_win_top = newwin(1, 6, starty + 2, width - 8)))
    {
        vrmr_error(-1, VR_ERR, gettext("creating window failed."));
        return(-1);
    }
    wbkgd(ZonesSection.h_win_top, vccnf.color_win);
    ZonesSection.h_panel_top[0] = new_panel(ZonesSection.h_win_top);
    /* TRANSLATORS: max 4 chars */
    wprintw(ZonesSection.h_win_top, "(%s)", gettext("more"));
    hide_panel(ZonesSection.h_panel_top[0]);

    if(!(ZonesSection.h_win_bot = newwin(1, 6, starty + height - 4, width - 8)))
    {
        vrmr_error(-1, VR_ERR, gettext("creating window failed."));
        return(-1);
    }
    wbkgd(ZonesSection.h_win_bot, vccnf.color_win);
    ZonesSection.h_panel_bot[0] = new_panel(ZonesSection.h_win_bot);
    /* TRANSLATORS: max 4 chars */
    wprintw(ZonesSection.h_win_bot, "(%s)", gettext("more"));
    hide_panel(ZonesSection.h_panel_bot[0]);

    update_panels();
    doupdate();

    return(retval);
}


static int
zones_blocklist_destroy(void)
{
    int     retval = 0;
    size_t  i = 0;

    unpost_menu(ZonesSection.h_menu);
    free_menu(ZonesSection.h_menu);
    for(i = 0; i < ZonesSection.host_n; ++i)
        free_item(ZonesSection.hostitems[i]);

    free(ZonesSection.hostitems);

    del_panel(ZonesSection.h_panel[0]);

    destroy_win(ZonesSection.h_win);

    del_panel(ZonesSection.h_panel_top[0]);
    destroy_win(ZonesSection.h_win_top);
    del_panel(ZonesSection.h_panel_bot[0]);
    destroy_win(ZonesSection.h_win_bot);

    return(retval);
}


int
zones_blocklist_add_one(const int debuglvl, struct vrmr_blocklist *blocklist, struct vrmr_zones *zones)
{
    char                *new_ipaddress = NULL,
                        *choices[] = {  gettext("IPAddress"),
                                        gettext("Host"),
                                        gettext("Group") },
                        *choice_ptr = NULL,
                        choice_type = 0,
                        **zone_choices;
    size_t              i = 0;
    char                changes = TRUE;
    struct vrmr_zone    *zone_ptr = NULL;
    struct vrmr_list_node         *d_node = NULL;


    /* safety */
    if(blocklist == NULL || zones == NULL)
    {
        vrmr_error(-1, VR_INTERR, "parameter problem (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    choice_ptr = selectbox(gettext("Select"), gettext("What do you want to block?"), 3, choices, 1, NULL);
    if(choice_ptr != NULL)
    {
        if(strcasecmp(choice_ptr, gettext("IPAddress")) == 0)
        {
            new_ipaddress = input_box(16, gettext("New IPAddress"), gettext("Enter the IPAddress to be blocked"));
            if(new_ipaddress != NULL)
            {
                /* validate ip */
                if(vrmr_check_ipv4address(debuglvl, NULL, NULL, new_ipaddress, 1) != 1)
                {
                    vrmr_warning(VR_WARN, gettext("'%s' is not a valid ipaddress."), new_ipaddress);

                    free(new_ipaddress);
                    new_ipaddress = NULL;
                }
                else
                {
                    /* add to list */
                    if(vrmr_blocklist_add_one(debuglvl, zones, blocklist, /*load_ips*/FALSE, /*no_refcnt*/FALSE, new_ipaddress) < 0)
                    {
                        vrmr_error(-1, VR_INTERR, "blocklist_add_one() failed (in: %s:%d).", __FUNC__, __LINE__);
                        return(-1);
                    }

                    vrmr_audit("%s '%s' %s.",
                        STR_IPADDRESS, new_ipaddress,
                        STR_HAS_BEEN_ADDED_TO_THE_BLOCKLIST);

                    changes = TRUE;
                    free(new_ipaddress);
                    new_ipaddress = NULL;
                }
            }
        }
        else if(strcasecmp(choice_ptr, gettext("Host")) == 0 || strcasecmp(choice_ptr, gettext("Group")) == 0)
        {
            (void)vrmr_list_setup(debuglvl, &ZonesSection.group_desc_list, free);

            /* get the type */
            if(strcasecmp(choice_ptr, gettext("Host")) == 0)
                choice_type = VRMR_TYPE_HOST;
            else
                choice_type = VRMR_TYPE_GROUP;

            for(d_node = zones->list.top, i = 0; d_node ; d_node = d_node->next)
            {
                if(!(zone_ptr = d_node->data))
                {
                    vrmr_error(-1, VR_INTERR, "NULL pointer (in: %s:%d).", __FUNC__, __LINE__);
                    return(-1);
                }

                if(zone_ptr->type == choice_type)
                {
                    i++;
                }
            }

            if(i == 0)
            {
                vrmr_warning(VR_WARN, gettext("please create one or more hosts/groups first."));
                return(0);
            }

            if(!(zone_choices = calloc(i + 1, VRMR_VRMR_MAX_HOST_NET_ZONE)))
            {
                vrmr_error(-1, VR_ERR, gettext("malloc failed: %s (in: %s:%d)."), strerror(errno), __func__, __LINE__);
                return(-1);
            }

            for(d_node = zones->list.top, i = 0; d_node ; d_node = d_node->next)
            {
                if(!(zone_ptr = d_node->data))
                {
                    vrmr_error(-1, VR_INTERR, "NULL pointer (in: %s:%d).", __FUNC__, __LINE__);
                    return(-1);
                }

                if(zone_ptr->type == choice_type)
                {
                    zone_choices[i] = zone_ptr->name;
                    i++;
                }
            }
            zone_choices[i] = NULL;

            /* get the zone */
            char *hostgroup = NULL;
            if((hostgroup = selectbox(gettext("Select"), gettext("Select a host or group to block"), i, zone_choices, 2, NULL)))
            {
                /* add to list */
                if(vrmr_blocklist_add_one(debuglvl, zones, blocklist, /*load_ips*/FALSE, /*no_refcnt*/FALSE, hostgroup) < 0)
                {
                    vrmr_error(-1, VR_ERR, gettext("adding host/group to list failed (in: %s:%d)."), __FUNC__, __LINE__);
                    return(-1);
                }

                if(choice_type == VRMR_TYPE_HOST)
                    vrmr_audit("%s '%s' %s.",
                        STR_HOST, hostgroup,
                        STR_HAS_BEEN_ADDED_TO_THE_BLOCKLIST);
                else
                    vrmr_audit("%s '%s' %s.",
                        STR_GROUP, hostgroup,
                        STR_HAS_BEEN_ADDED_TO_THE_BLOCKLIST);

                free(hostgroup);
                changes = TRUE;
            }

            free(zone_choices);
            zone_choices = NULL;
        }
        free(choice_ptr);
    }

    return(changes);
}


int
zones_blocklist(const int debuglvl, struct vrmr_ctx *vctx,
        struct vrmr_blocklist *blocklist, struct vrmr_zones *zones, struct vrmr_regex *reg)
{
    int     ch = 0,
            quit = 0,
            reload = 0,
            retval = 0;
    char    changes = 0;
    char    *itemname = NULL,
            saveitemname[VRMR_VRMR_MAX_HOST_NET_ZONE] = "";
    ITEM    *cur = NULL;
    /* top menu */
    char    *key_choices[] =    {   "F12",
                                    "INS",
                                    "DEL",
                                    "F10"};
    int     key_choices_n = 4;
    char    *cmd_choices[] =    {   gettext("help"),
                                    gettext("new"),
                                    gettext("del"),
                                    gettext("back")};
    int     cmd_choices_n = 4;


    /* safety */
    if(!blocklist || !zones || !reg)
    {
        vrmr_error(-1, VR_INTERR, "parameter problem (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    /* setup */
    if(zones_blocklist_init(debuglvl, blocklist) < 0)
    {
        vrmr_error(-1, VR_INTERR, "setting up blocklist menu failed (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    draw_top_menu(debuglvl, top_win, gettext("BlockList"), key_choices_n, key_choices, cmd_choices_n, cmd_choices);

    /* enter the loop */
    while(quit == 0)
    {
        /* reload the menu */
        if(reload == 1)
        {
            if(debuglvl >= HIGH)
                vrmr_debug(__FUNC__, "reload == 1, reloading menu.");

            /* first destroy */
            if(zones_blocklist_destroy() < 0)
            {
                vrmr_error(-1, VR_INTERR, "reinitializing menu failed (in: %s:%d).", __FUNC__, __LINE__);
                return(-1);
            }

            if(debuglvl >= HIGH)
                vrmr_debug(__FUNC__, "reload == 1, old menu destroyed.");

            /* and setup again */
            if(zones_blocklist_init(debuglvl, blocklist) < 0)
            {
                vrmr_error(-1, VR_INTERR, "reinitializing menu failed (in: %s:%d).", __FUNC__, __LINE__);
                return(-1);
            }

            if(debuglvl >= HIGH)
                vrmr_debug(__FUNC__, "reload == 1, new menu created.");

            /* we are done with reloading */
            reload = 0;
        }

        /* loop for catching user input */
        while(quit == 0 && reload == 0)
        {
            if(ZonesSection.h_top != NULL && !item_visible(ZonesSection.h_top))
                show_panel(ZonesSection.h_panel_top[0]);
            else
                hide_panel(ZonesSection.h_panel_top[0]);

            if(ZonesSection.h_bot != NULL && !item_visible(ZonesSection.h_bot))
                show_panel(ZonesSection.h_panel_bot[0]);
            else
                hide_panel(ZonesSection.h_panel_bot[0]);

            update_panels();
            doupdate();

            /* restore the cursor */
            pos_menu_cursor(ZonesSection.h_menu);

            /* get the user input */
            ch = wgetch(ZonesSection.h_win);
            switch(ch)
            {
                case 27:
                case KEY_LEFT:
                case KEY_F(10):
                case 'q':
                case 'Q':

                    quit = 1;
                    break;

                case KEY_IC: /* insert key */
                case 'i':
                case 'I':

                    if(zones_blocklist_add_one(debuglvl, blocklist, zones) == 1)
                    {
                        changes = 1;
                        reload = 1;
                    }

                    break;

                /*
                    delete
                */
                case KEY_DC:
                case 'd':
                case 'D':

                    if(blocklist->list.len > 0)
                    {
                        if (confirm(gettext("Remove"), gettext("This IP/Host/Group?"),
                                    vccnf.color_win_note, vccnf.color_win_note_rev|A_BOLD, 0) == 1)
                        {
                            /* get the current item */
                            if(!(cur = current_item(ZonesSection.h_menu)))
                            {
                                vrmr_error(-1, VR_INTERR, "NULL pointer (in: %s:%d).",
                                                    __FUNC__, __LINE__);
                                return(-1);
                            }

                            if(!(itemname = (char *)item_name(cur)))
                            {
                                vrmr_error(-1, VR_INTERR, "NULL pointer (in: %s:%d).",
                                                    __FUNC__, __LINE__);
                                return(-1);
                            }

                            if(debuglvl >= HIGH)
                                vrmr_debug(__FUNC__, "itemname to remove: '%s'.", itemname);

                            /* save the name */
                            (void)strlcpy(saveitemname, itemname, sizeof(saveitemname));

                            if(vrmr_blocklist_rem_one(debuglvl, zones, blocklist, itemname) == 0)
                            {
                                vrmr_audit("'%s' %s.",
                                    saveitemname,
                                    STR_HAS_BEEN_REMOVED_FROM_THE_BLOCKLIST);

                                itemname = NULL;

                                changes = 1;
                                reload = 1;
                            }
                        }
                    }
                    break;

                case KEY_DOWN:
                    menu_driver(ZonesSection.h_menu, REQ_DOWN_ITEM);
                    break;
                case KEY_UP:
                    menu_driver(ZonesSection.h_menu, REQ_UP_ITEM);
                    break;
                case KEY_NPAGE:
                    if(menu_driver(ZonesSection.h_menu, REQ_SCR_DPAGE) != E_OK)
                    {
                        while(menu_driver(ZonesSection.h_menu, REQ_DOWN_ITEM) == E_OK);
                    }
                    break;
                case KEY_PPAGE:
                    if(menu_driver(ZonesSection.h_menu, REQ_SCR_UPAGE) != E_OK)
                    {
                        while(menu_driver(ZonesSection.h_menu, REQ_UP_ITEM) == E_OK);
                    }
                    break;
                case KEY_HOME:
                    menu_driver(ZonesSection.h_menu, REQ_FIRST_ITEM);   // home
                    break;
                case KEY_END:
                    menu_driver(ZonesSection.h_menu, REQ_LAST_ITEM);    // end
                    break;

                case KEY_F(12):
                case 'h':
                case 'H':
                case '?':
                    print_help(debuglvl, ":[VUURMUUR:BLOCKLIST]:");
                    break;
            }
        }
    }

    if(changes && retval == 0)
    {
        if(debuglvl >= HIGH)
            vrmr_debug(__FUNC__, "changes and retval == 0 so save the list to disk.");

        if (vrmr_blocklist_save_list(debuglvl, vctx, &vctx->conf, blocklist) < 0)
            retval = -1;
    }

    if(zones_blocklist_destroy() < 0)
        retval = -1;

    update_panels();
    doupdate();

    status_print(status_win, gettext("Ready."));
    return(retval);
}
