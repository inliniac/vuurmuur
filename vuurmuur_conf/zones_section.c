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

#include "main.h"

struct {
    /*  first the menus

        they each have their own data struct because they can
        be shown at the same time, only hosts and groups share
        the data struct
    */

    /* zones */
    WINDOW *win;
    PANEL *panel[1];
    MENU *menu;
    ITEM **zoneitems;
    size_t zone_n;

    ITEM *z_top, *z_bot;
    PANEL *z_panel_top[1];
    PANEL *z_panel_bot[1];
    WINDOW *z_win_top;
    WINDOW *z_win_bot;

    int z_yle; /**< window y lower edge */
    int z_xre; /**< window x right edge */

    /* networks */
    WINDOW *n_win;
    PANEL *n_panel[1];
    MENU *n_menu;
    ITEM **networkitems;
    size_t network_n;
    struct vrmr_list network_desc_list;

    ITEM *n_top, *n_bot;
    PANEL *n_panel_top[1];
    PANEL *n_panel_bot[1];
    WINDOW *n_win_top;
    WINDOW *n_win_bot;

    int n_yle; /**< window y lower edge */
    int n_xre; /**< window x right edge */

    /* hosts and groups */
    WINDOW *h_win;
    PANEL *h_panel[1];
    MENU *h_menu;
    ITEM **hostitems;
    size_t host_n;
    struct vrmr_list group_desc_list;

    ITEM *h_top, *h_bot;
    PANEL *h_panel_top[1];
    PANEL *h_panel_bot[1];
    WINDOW *h_win_top;
    WINDOW *h_win_bot;

    int h_yle; /**< window y lower edge */
    int h_xre; /**< window x right edge */

    /* edit a zone/network/host/group */
    struct {
        PANEL *panel[1];
        WINDOW *win;
        FIELD **fields;
        FORM *form;
        size_t n_fields;
    } edit_zone;

    /* edit zone interfaces */
    struct {
        PANEL *panel[1];
        WINDOW *win;
        MENU *menu;
        ITEM **items;
        size_t n_items;

        ITEM *top, *bot;
        PANEL *panel_top[1];
        PANEL *panel_bot[1];
        WINDOW *win_top;
        WINDOW *win_bot;

    } edit_iface;

    /* edit zone groups */
    struct {
        PANEL *panel[1];
        WINDOW *win;
        MENU *menu;
        ITEM **items;
        size_t n_items;

        ITEM *top, *bot;
        PANEL *panel_top[1];
        PANEL *panel_bot[1];
        WINDOW *win_top;
        WINDOW *win_bot;

    } edit_group;

    char comment[512];

} zonessec_ctx;

struct {
    FIELD *activefld, *activelabelfld, *ipaddressfld, *ipaddresslabelfld,
            *ip6addressfld, *ip6addresslabelfld, *macaddressfld,
            *macaddresslabelfld, *commentfld, *commentlabelfld,
            *warningfld; /* field for the "warning no interfaces" message */
} HostSec;

static void edit_zone_host_init(struct vrmr_ctx *vctx, int height, int width,
        int starty, int startx, struct vrmr_zone *zone_ptr)
{
    int rows, cols, comment_y = 0, /* for the dimentions of */
            comment_x = 0;         /* the comment field */
    unsigned int field_num = 0;
    size_t i = 0;

    /* safety */
    vrmr_fatal_if_null(zone_ptr);

    /* alloc fields */
    zonessec_ctx.edit_zone.n_fields = 11;
    zonessec_ctx.edit_zone.fields = (FIELD **)calloc(
            zonessec_ctx.edit_zone.n_fields + 1, sizeof(FIELD *));
    vrmr_fatal_if_null(zonessec_ctx.edit_zone.fields);

    /* preload the active field */
    HostSec.activelabelfld = (zonessec_ctx.edit_zone.fields[field_num++] =
                                      new_field_wrap(1, 16, 2, 0, 0, 0));
    set_field_buffer_wrap(HostSec.activelabelfld, 0, STR_CACTIVE);
    field_opts_off(HostSec.activelabelfld, O_AUTOSKIP | O_ACTIVE);

    HostSec.activefld = (zonessec_ctx.edit_zone.fields[field_num++] =
                                 new_field_wrap(1, 3, 3, 1, 0, 0));
    set_field_buffer_wrap(
            HostSec.activefld, 0, zone_ptr->active ? STR_YES : STR_NO);

    HostSec.ipaddresslabelfld = (zonessec_ctx.edit_zone.fields[field_num++] =
                                         new_field_wrap(1, 16, 2, 8, 0, 0));
    set_field_buffer_wrap(HostSec.ipaddresslabelfld, 0, STR_IPADDRESS);
    field_opts_off(HostSec.ipaddresslabelfld, O_AUTOSKIP | O_ACTIVE);

    HostSec.ipaddressfld = (zonessec_ctx.edit_zone.fields[field_num++] =
                                    new_field_wrap(1, 16, 3, 9, 0, 0));
    set_field_type(HostSec.ipaddressfld, TYPE_IPV4);
    set_field_buffer_wrap(HostSec.ipaddressfld, 0, zone_ptr->ipv4.ipaddress);
    field_opts_on(HostSec.ipaddressfld, O_BLANK);

    HostSec.ip6addresslabelfld = (zonessec_ctx.edit_zone.fields[field_num++] =
                                          new_field_wrap(1, 16, 4, 8, 0, 0));
#ifdef IPV6_ENABLED
    set_field_buffer_wrap(HostSec.ip6addresslabelfld, 0, STR_IP6ADDRESS);
#endif
    field_opts_off(HostSec.ip6addresslabelfld, O_AUTOSKIP | O_ACTIVE);

    HostSec.ip6addressfld =
            (zonessec_ctx.edit_zone.fields[field_num++] = new_field_wrap(
                     1, VRMR_MAX_IPV6_ADDR_LEN, 5, 9, 0, 0));
    // set_field_type(HostSec.ipaddressfld, TYPE_IPV4);
#ifdef IPV6_ENABLED
    set_field_buffer_wrap(HostSec.ip6addressfld, 0, zone_ptr->ipv6.ip6);
#endif
    field_opts_on(HostSec.ip6addressfld, O_BLANK);

    HostSec.macaddresslabelfld = (zonessec_ctx.edit_zone.fields[field_num++] =
                                          new_field_wrap(1, 16, 6, 8, 0, 0));
    set_field_buffer_wrap(HostSec.macaddresslabelfld, 0, STR_MACADDRESS);
    field_opts_off(HostSec.macaddresslabelfld, O_AUTOSKIP | O_ACTIVE);

    HostSec.macaddressfld = (zonessec_ctx.edit_zone.fields[field_num++] =
                                     new_field_wrap(1, 19, 7, 9, 0, 0));
    set_field_buffer_wrap(HostSec.macaddressfld, 0, zone_ptr->mac);
    field_opts_on(HostSec.macaddressfld, O_BLANK);

    /* comment label */
    HostSec.commentlabelfld = (zonessec_ctx.edit_zone.fields[field_num++] =
                                       new_field_wrap(1, 16, 10, 0, 0, 0));
    set_field_buffer_wrap(HostSec.commentlabelfld, 0, gettext("Comment"));
    field_opts_off(HostSec.commentlabelfld, O_AUTOSKIP | O_ACTIVE);

    /* comment field size */
    comment_y = 5;
    comment_x = 48;
    /* create the comment field */
    HostSec.commentfld =
            (zonessec_ctx.edit_zone.fields[field_num++] =
                            new_field_wrap(comment_y, comment_x, 11, 1, 0, 0));

    /* load the comment from the backend */
    if (vctx->zf->ask(vctx->zone_backend, zone_ptr->name, "COMMENT",
                zonessec_ctx.comment, sizeof(zonessec_ctx.comment),
                VRMR_TYPE_HOST, 0) < 0)
        vrmr_error(-1, VR_ERR, gettext("error while loading the comment."));

    set_field_buffer_wrap(HostSec.commentfld, 0, zonessec_ctx.comment);

    HostSec.warningfld = (zonessec_ctx.edit_zone.fields[field_num++] =
                                  new_field_wrap(1, 48, 15, 1, 0, 0));
    field_opts_off(HostSec.warningfld, O_AUTOSKIP | O_ACTIVE | O_VISIBLE);
    set_field_just(HostSec.warningfld, JUSTIFY_CENTER);

    vrmr_fatal_if(field_num != zonessec_ctx.edit_zone.n_fields);

    zonessec_ctx.edit_zone.fields[zonessec_ctx.edit_zone.n_fields] = NULL;

    /* create the window & panel */
    zonessec_ctx.edit_zone.win = create_newwin(height, width, starty, startx,
            gettext("Edit Zone: Host"), vccnf.color_win);
    vrmr_fatal_if_null(zonessec_ctx.edit_zone.win);
    zonessec_ctx.edit_zone.panel[0] = new_panel(zonessec_ctx.edit_zone.win);
    vrmr_fatal_if_null(zonessec_ctx.edit_zone.panel[0]);
    keypad(zonessec_ctx.edit_zone.win, TRUE);

    /* set field options */
    for (i = 0; i < zonessec_ctx.edit_zone.n_fields; i++) {
        set_field_back(zonessec_ctx.edit_zone.fields[i], vccnf.color_win_rev);
        field_opts_off(zonessec_ctx.edit_zone.fields[i], O_AUTOSKIP);
        set_field_status(zonessec_ctx.edit_zone.fields[i], FALSE);
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
    set_field_fore(HostSec.warningfld, vccnf.color_win_warn | A_BOLD);

    /* Create the form and post it */
    zonessec_ctx.edit_zone.form = new_form(zonessec_ctx.edit_zone.fields);
    vrmr_fatal_if_null(zonessec_ctx.edit_zone.form);
    scale_form(zonessec_ctx.edit_zone.form, &rows, &cols);
    set_form_win(zonessec_ctx.edit_zone.form, zonessec_ctx.edit_zone.win);
    set_form_sub(zonessec_ctx.edit_zone.form,
            derwin(zonessec_ctx.edit_zone.win, rows, cols, 1, 2));
    post_form(zonessec_ctx.edit_zone.form);

    /* print labels */
    mvwprintw(zonessec_ctx.edit_zone.win, 1, 2, "%s: %s", gettext("Name"),
            zone_ptr->name);

    /* draw */
    wrefresh(zonessec_ctx.edit_zone.win);
    update_panels();
    doupdate();
}

static void edit_zone_host_destroy(void)
{
    size_t i = 0;

    /* unpost form and free the memory */
    unpost_form(zonessec_ctx.edit_zone.form);
    free_form(zonessec_ctx.edit_zone.form);
    for (i = 0; i < zonessec_ctx.edit_zone.n_fields; i++) {
        free_field(zonessec_ctx.edit_zone.fields[i]);
    }
    free(zonessec_ctx.edit_zone.fields);
    del_panel(zonessec_ctx.edit_zone.panel[0]);
    destroy_win(zonessec_ctx.edit_zone.win);
    update_panels();
    doupdate();

    /* clear comment */
    strcpy(zonessec_ctx.comment, "");
}

static int edit_zone_host_save(struct vrmr_ctx *vctx,
        struct vrmr_zone *zone_ptr, struct vrmr_regex *reg)
{
    int active = 0;
    char ipaddress[16] = "", mac[19] = "";
#ifdef IPV6_ENABLED
    char ip6address[VRMR_MAX_IPV6_ADDR_LEN] = "";
#endif
    size_t i = 0;

    /* safety */
    vrmr_fatal_if_null(zone_ptr);
    vrmr_fatal_if_null(reg);

    /* check for changed fields */
    for (i = 0; i < zonessec_ctx.edit_zone.n_fields; i++) {
        /* field changed! */
        if (field_status(zonessec_ctx.edit_zone.fields[i]) == FALSE)
            continue;

        /* active field */
        if (zonessec_ctx.edit_zone.fields[i] == HostSec.activefld) {
            /* for the log and incase something goes wrong */
            active = zone_ptr->active;

            if (strncasecmp(field_buffer(zonessec_ctx.edit_zone.fields[i], 0),
                        STR_YES, StrLen(STR_YES)) == 0)
                zone_ptr->active = 1;
            else
                zone_ptr->active = 0;

            /* save to the backend */
            if (vctx->zf->tell(vctx->zone_backend, zone_ptr->name, "ACTIVE",
                        zone_ptr->active ? "Yes" : "No", 1,
                        VRMR_TYPE_HOST) < 0) {
                vrmr_error(-1, VR_ERR, gettext("saving to backend failed"));
                return (-1);
            }

            /* for the log */
            vrmr_audit("%s '%s' %s: %s %s '%s' (%s: '%s').", STR_HOST,
                    zone_ptr->name, STR_HAS_BEEN_CHANGED, STR_ACTIVE,
                    STR_IS_NOW_SET_TO, zone_ptr->active ? STR_YES : STR_NO,
                    STR_WAS, active ? STR_YES : STR_NO);

            zone_ptr->status = VRMR_ST_CHANGED;
        }

        /* ipaddress field */
        else if (zonessec_ctx.edit_zone.fields[i] == HostSec.ipaddressfld) {
            /* for the log and incase something goes wrong */
            (void)strlcpy(
                    ipaddress, zone_ptr->ipv4.ipaddress, sizeof(ipaddress));

            copy_field2buf(zone_ptr->ipv4.ipaddress,
                    field_buffer(zonessec_ctx.edit_zone.fields[i], 0),
                    sizeof(zone_ptr->ipv4.ipaddress));

            /*  we dont check for invalid ip
                (check_ip == 0), because this is done
                by the fieldvalidation

                also, we first check if the network
                has the network address and netmask
                set.
             */
            if (zone_ptr->network_parent->ipv4.network[0] == '\0' ||
                    zone_ptr->network_parent->ipv4.netmask[0] == '\0' ||
                    vrmr_check_ipv4address(
                            zone_ptr->network_parent->ipv4.network,
                            zone_ptr->network_parent->ipv4.netmask,
                            zone_ptr->ipv4.ipaddress, 0)) {
                if (vctx->zf->tell(vctx->zone_backend, zone_ptr->name,
                            "IPADDRESS", zone_ptr->ipv4.ipaddress, 1,
                            VRMR_TYPE_HOST) < 0) {
                    vrmr_error(-1, VR_ERR, gettext("saving to backend failed"));
                    return (-1);
                }

                /* audit log */
                vrmr_audit("%s '%s' %s: %s %s '%s' (%s: '%s').", STR_HOST,
                        zone_ptr->name, STR_HAS_BEEN_CHANGED, STR_IPADDRESS,
                        STR_IS_NOW_SET_TO, zone_ptr->ipv4.ipaddress, STR_WAS,
                        ipaddress);

                zone_ptr->status = VRMR_ST_CHANGED;
            } else {
                vrmr_error(-1, VR_ERR,
                        gettext("ipaddress '%s' doesn't belong in the network "
                                "%s/%s."),
                        zone_ptr->ipv4.ipaddress,
                        zone_ptr->network_parent->ipv4.network,
                        zone_ptr->network_parent->ipv4.netmask);

                /* copy the old ipaddress back */
                (void)strlcpy(zone_ptr->ipv4.ipaddress, ipaddress,
                        sizeof(zone_ptr->ipv4.ipaddress));

                /* error so the user can edit this host again */
                return (-1);
            }
        }

#ifdef IPV6_ENABLED
        /* ip6address field */
        else if (zonessec_ctx.edit_zone.fields[i] == HostSec.ip6addressfld) {
            /* for the log and incase something goes wrong */
            (void)strlcpy(ip6address, zone_ptr->ipv6.ip6, sizeof(ip6address));

            copy_field2buf(zone_ptr->ipv6.ip6,
                    field_buffer(zonessec_ctx.edit_zone.fields[i], 0),
                    sizeof(zone_ptr->ipv6.ip6));

            if (vctx->zf->tell(vctx->zone_backend, zone_ptr->name,
                        "IPV6ADDRESS", zone_ptr->ipv6.ip6, 1,
                        VRMR_TYPE_HOST) < 0) {
                vrmr_error(-1, VR_ERR, gettext("saving to backend failed"));
                return (-1);
            }

            /* audit log */
            vrmr_audit("%s '%s' %s: %s %s '%s' (%s: '%s').", STR_HOST,
                    zone_ptr->name, STR_HAS_BEEN_CHANGED, STR_IP6ADDRESS,
                    STR_IS_NOW_SET_TO, zone_ptr->ipv6.ip6, STR_WAS, ip6address);

            zone_ptr->status = VRMR_ST_CHANGED;
        }
#endif
        /* MAC field */
        else if (zonessec_ctx.edit_zone.fields[i] == HostSec.macaddressfld) {
            /* for the log and incase something goes wrong */
            (void)strlcpy(mac, zone_ptr->mac, sizeof(mac));

            copy_field2buf(zone_ptr->mac,
                    field_buffer(zonessec_ctx.edit_zone.fields[i], 0),
                    sizeof(zone_ptr->mac));

            if (zone_ptr->mac[0] != '\0') {
                /* test against the regex */
                if (regexec(reg->macaddr, zone_ptr->mac, 0, NULL, 0) != 0) {
                    vrmr_error(-1, VR_ERR,
                            gettext("MAC Address '%s' is invalid."),
                            zone_ptr->mac);

                    /* for the log and incase something goes wrong */
                    (void)strlcpy(zone_ptr->mac, mac, sizeof(zone_ptr->mac));
                    /* error so the user can edit this host again */
                    return (-1);
                }
            }

            /* save to backend */
            if (vctx->zf->tell(vctx->zone_backend, zone_ptr->name, "MAC",
                        zone_ptr->mac, 1, VRMR_TYPE_HOST) < 0) {
                vrmr_error(-1, VR_ERR, gettext("saving to backend failed"));
                return (-1);
            }

            /* audit log */
            vrmr_audit("%s '%s' %s: %s %s '%s' (%s: '%s').", STR_HOST,
                    zone_ptr->name, STR_HAS_BEEN_CHANGED, STR_MACADDRESS,
                    STR_IS_NOW_SET_TO, zone_ptr->mac, STR_WAS, mac);

            zone_ptr->status = VRMR_ST_CHANGED;
        }

        /* comment field */
        else if (zonessec_ctx.edit_zone.fields[i] == HostSec.commentfld) {
            if (vctx->zf->tell(vctx->zone_backend, zone_ptr->name, "COMMENT",
                        field_buffer(zonessec_ctx.edit_zone.fields[i], 0), 1,
                        VRMR_TYPE_HOST) < 0) {
                vrmr_error(-1, VR_ERR, gettext("saving to backend failed"));
                return (-1);
            }

            /* example: "host 'pc1.local.lan' has been changed: the comment was
             * changed." */
            vrmr_audit("%s '%s' %s: %s.", STR_HOST, zone_ptr->name,
                    STR_HAS_BEEN_CHANGED, STR_COMMENT_CHANGED);

        } else {
            vrmr_fatal("unknown field");
        }
    }

    if (zone_ptr->ipv4.ipaddress[0] == '\0') {
        vrmr_warning(VR_WARN, gettext("empty IP address. No rules will be "
                                      "created for this host."));
    }

    return (0);
}

/*  edit_zone_host

    Returncodes:
         0: ok
        -1: error
*/
static void edit_zone_host(struct vrmr_ctx *vctx, struct vrmr_zones *zones,
        char *name, struct vrmr_regex *reg)
{
    int ch, not_defined = 0, quit = 0;
    struct vrmr_zone *zone_ptr = NULL;
    int height, width, startx, starty;
    FIELD *cur = NULL, *prev = NULL;
    /* top menu */
    char *key_choices[] = {"F12", "F10"};
    int key_choices_n = 2;
    char *cmd_choices[] = {gettext("help"), gettext("back")};
    int cmd_choices_n = 2;

    /* safety */
    vrmr_fatal_if_null(name);
    vrmr_fatal_if_null(zones);
    vrmr_fatal_if_null(reg);

    height = 18;
    width = 54;
    /* place on the same y as zones list */
    VrWinGetOffset(-1, -1, height, width, zonessec_ctx.h_yle + 1,
            zonessec_ctx.n_xre + 1, &starty, &startx);

    /* search the host in memory */
    zone_ptr = vrmr_search_zonedata(zones, name);
    vrmr_fatal_if_null(zone_ptr);

    /* init */
    edit_zone_host_init(vctx, height, width, starty, startx, zone_ptr);

    cur = current_field(zonessec_ctx.edit_zone.form);
    vrmr_fatal_if_null(cur);

    if (zone_ptr->active == TRUE && vrmr_zones_active(zone_ptr) == 0) {
        set_field_buffer_wrap(HostSec.warningfld, 0,
                gettext("Note: parent zone/network is inactive."));
        field_opts_on(HostSec.warningfld, O_VISIBLE);
        set_field_status(HostSec.warningfld, FALSE);
    }

    draw_top_menu(top_win, gettext("Edit Host"), key_choices_n, key_choices,
            cmd_choices_n, cmd_choices);

    update_panels();
    doupdate();
    status_print(status_win, "Ready.");

    /* loop through to get user requests */
    while (quit == 0) {
        /* draw nice markers */
        draw_field_active_mark(cur, prev, zonessec_ctx.edit_zone.win,
                zonessec_ctx.edit_zone.form, vccnf.color_win_mark | A_BOLD);

        not_defined = 0;

        /* get user input */
        ch = wgetch(zonessec_ctx.edit_zone.win);

        if (cur == HostSec.commentfld) {
            if (nav_field_comment(zonessec_ctx.edit_zone.form, ch) < 0)
                not_defined = 1;
        } else if (cur == HostSec.activefld) {
            if (nav_field_yesno(zonessec_ctx.edit_zone.form, ch) < 0)
                not_defined = 1;
        } else if (cur == HostSec.ipaddressfld ||
                   cur == HostSec.ip6addressfld ||
                   cur == HostSec.macaddressfld) {
            if (nav_field_simpletext(zonessec_ctx.edit_zone.form, ch) < 0)
                not_defined = 1;
        } else {
            not_defined = 1;
        }

        /* the rest is handled here */
        if (not_defined) {
            switch (ch) {
                case KEY_DOWN:
                case 10: // enter
                case 9:  // tab
                    form_driver_wrap(
                            zonessec_ctx.edit_zone.form, REQ_NEXT_FIELD);
                    form_driver_wrap(zonessec_ctx.edit_zone.form, REQ_BEG_LINE);
                    break;

                case KEY_UP:
                    form_driver_wrap(
                            zonessec_ctx.edit_zone.form, REQ_PREV_FIELD);
                    form_driver_wrap(zonessec_ctx.edit_zone.form, REQ_BEG_LINE);
                    break;

                case 27:
                case KEY_F(10):
                case 'q':
                case 'Q':

                    /* save changes */
                    if (edit_zone_host_save(vctx, zone_ptr, reg) < 0) {
                        if (confirm(gettext("saving host failed."),
                                    gettext("Look at the host again?"),
                                    vccnf.color_win_rev, vccnf.color_win,
                                    1) == 0)
                            quit = 1;
                    } else {
                        quit = 1;
                    }

                    break;

                case KEY_F(12):
                case 'h':
                case 'H':
                case '?':
                    print_help(":[VUURMUUR:ZONES:HOST:EDIT]:");
                    break;
            }
        }

        /* before we get the new 'cur', store cur in prev */
        prev = cur;
        cur = current_field(zonessec_ctx.edit_zone.form);
        vrmr_fatal_if_null(cur);

        /* now give some help message in the status win */
        if (cur == HostSec.ipaddressfld)
            status_print(status_win,
                    gettext("Please enter an ipaddress (mandatory)."));
        else if (cur == HostSec.macaddressfld)
            status_print(status_win,
                    gettext("Please enter the macaddress (optional)."));
        else if (cur == HostSec.activefld)
            status_print(status_win,
                    gettext("If set to 'No' no rules will be created for it."));
        else if (cur == HostSec.commentfld)
            status_print(status_win, gettext("Enter a optional comment."));

        /* check against the current 'active' value */
        if (strncasecmp(field_buffer(HostSec.activefld, 0), STR_YES,
                    StrLen(STR_YES)) == 0 &&
                vrmr_zones_active(zone_ptr) == 0) {
            set_field_buffer_wrap(HostSec.warningfld, 0,
                    gettext("Note: parent zone/network is inactive."));
            field_opts_on(HostSec.warningfld, O_VISIBLE);
            set_field_status(HostSec.warningfld, FALSE);
        }
        /* and clear it again */
        else {
            /* hide no int warning */
            field_opts_off(HostSec.warningfld, O_VISIBLE);
        }

        /* draw and set cursor */
        wrefresh(zonessec_ctx.edit_zone.win);
        pos_form_cursor(zonessec_ctx.edit_zone.form);
    }

    /* cleanup */
    edit_zone_host_destroy();

    status_print(status_win, gettext("Ready."));
}

static void zones_section_menu_hosts_init(
        struct vrmr_zones *zones, char *zonename, char *networkname)
{
    struct vrmr_zone *zone_ptr = NULL;
    int height = 0, width = 0, startx = 0, starty = 0, maxy = 0, result = 0;
    struct vrmr_list_node *d_node = NULL;
    size_t i = 0;

    /* safety */
    vrmr_fatal_if_null(zonename);
    vrmr_fatal_if_null(zones);
    vrmr_fatal_if_null(networkname);

    /* get the screensize */
    maxy = getmaxy(stdscr);

    /* count how many hosts there are */
    for (zonessec_ctx.host_n = 0, d_node = zones->list.top; d_node;
            d_node = d_node->next) {
        vrmr_fatal_if_null(d_node->data);
        zone_ptr = d_node->data;

        /* only count hosts inside the network and zone */
        if (zone_ptr->type == VRMR_TYPE_HOST) {
            if (strcmp(zone_ptr->zone_name, zonename) == 0 &&
                    strcmp(zone_ptr->network_name, networkname) == 0) {
                zonessec_ctx.host_n++;
            }
        }
    }

    i = zonessec_ctx.host_n - 1;

    /* alloc the menu items */
    zonessec_ctx.hostitems =
            (ITEM **)calloc(zonessec_ctx.host_n + 1, sizeof(ITEM *));
    vrmr_fatal_if_null(zonessec_ctx.hostitems);

    /* create the menu items */
    for (d_node = zones->list.bot; d_node; d_node = d_node->prev) {
        vrmr_fatal_if_null(d_node->data);
        zone_ptr = d_node->data;

        /* only add hosts inside the network and zone */
        if (zone_ptr->type == VRMR_TYPE_HOST) {
            if (strcmp(zone_ptr->zone_name, zonename) == 0 &&
                    strcmp(zone_ptr->network_name, networkname) == 0) {
                zonessec_ctx.hostitems[i] =
                        new_item(zone_ptr->host_name, zone_ptr->ipv4.ipaddress);
                vrmr_fatal_if_null(zonessec_ctx.hostitems[i]);
                i--;
            }
        }
    }
    /* terminate the items */
    zonessec_ctx.hostitems[zonessec_ctx.host_n] = (ITEM *)NULL;

    if (zonessec_ctx.host_n > 0) {
        zonessec_ctx.h_top = zonessec_ctx.hostitems[0];
        zonessec_ctx.h_bot = zonessec_ctx.hostitems[zonessec_ctx.host_n - 1];
    } else {
        zonessec_ctx.h_top = NULL;
        zonessec_ctx.h_bot = NULL;
    }

    /* now create the menu */
    zonessec_ctx.h_menu = new_menu((ITEM **)zonessec_ctx.hostitems);
    vrmr_fatal_if_null(zonessec_ctx.h_menu);

    /* now set the size of the window */
    height = (int)(zonessec_ctx.host_n + 8);
    width = VRMR_MAX_HOST + 18 + 2;

    if (height > maxy - 8) {
        height = maxy - 8;
    }

    /* place on the same y as zones list */
    VrWinGetOffset(
            -1, -1, height, width, 4, zonessec_ctx.n_xre + 1, &starty, &startx);
    zonessec_ctx.h_yle = starty + height;
    zonessec_ctx.h_xre = startx + width;

    zonessec_ctx.h_win = newwin(height, width, starty, startx);
    vrmr_fatal_if_null(zonessec_ctx.h_win);
    wbkgd(zonessec_ctx.h_win, vccnf.color_win);
    keypad(zonessec_ctx.h_win, TRUE);
    box(zonessec_ctx.h_win, 0, 0);
    print_in_middle(
            zonessec_ctx.h_win, 1, 0, width, gettext("Hosts"), vccnf.color_win);
    wrefresh(zonessec_ctx.h_win);

    zonessec_ctx.h_panel[0] = new_panel(zonessec_ctx.h_win);
    vrmr_fatal_if_null(zonessec_ctx.h_panel[0]);

    set_menu_win(zonessec_ctx.h_menu, zonessec_ctx.h_win);
    set_menu_sub(zonessec_ctx.h_menu,
            derwin(zonessec_ctx.h_win, height - 7, width - 2, 3, 1));

    set_menu_format(zonessec_ctx.h_menu, height - 8, 1);

    mvwaddch(zonessec_ctx.h_win, 2, 0, ACS_LTEE);
    mvwhline(zonessec_ctx.h_win, 2, 1, ACS_HLINE, width - 2);
    mvwaddch(zonessec_ctx.h_win, 2, width - 1, ACS_RTEE);

    set_menu_back(zonessec_ctx.h_menu, vccnf.color_win);
    set_menu_fore(zonessec_ctx.h_menu, vccnf.color_win_rev);

    result = post_menu(zonessec_ctx.h_menu);
    vrmr_fatal_if(result != E_OK && result != E_NOT_CONNECTED);

    mvwaddch(zonessec_ctx.h_win, height - 5, 0, ACS_LTEE);
    mvwhline(zonessec_ctx.h_win, height - 5, 1, ACS_HLINE, width - 2);
    mvwaddch(zonessec_ctx.h_win, height - 5, width - 1, ACS_RTEE);

    mvwprintw(zonessec_ctx.h_win, height - 4, 1, "<RET> %s", STR_EDIT);
    mvwprintw(zonessec_ctx.h_win, height - 3, 1, "<INS> %s", STR_NEW);
    mvwprintw(zonessec_ctx.h_win, height - 2, 1, "<DEL> %s", STR_REMOVE);

    /* create the top and bottom fields */
    zonessec_ctx.h_win_top = newwin(1, 6, starty + 2, startx + width - 8);
    vrmr_fatal_if_null(zonessec_ctx.h_win_top);
    wbkgd(zonessec_ctx.h_win_top, vccnf.color_win);
    zonessec_ctx.h_panel_top[0] = new_panel(zonessec_ctx.h_win_top);
    /* TRANSLATORS: max 4 chars */
    wprintw(zonessec_ctx.h_win_top, "(%s)", gettext("more"));
    hide_panel(zonessec_ctx.h_panel_top[0]);

    zonessec_ctx.h_win_bot =
            newwin(1, 6, starty + height - 5, startx + width - 8);
    vrmr_fatal_if_null(zonessec_ctx.h_win_bot);
    wbkgd(zonessec_ctx.h_win_bot, vccnf.color_win);
    zonessec_ctx.h_panel_bot[0] = new_panel(zonessec_ctx.h_win_bot);
    /* TRANSLATORS: max 4 chars */
    wprintw(zonessec_ctx.h_win_bot, "(%s)", gettext("more"));
    hide_panel(zonessec_ctx.h_panel_bot[0]);

    update_panels();
    doupdate();
}

static void zones_section_menu_hosts_destroy(void)
{
    size_t i = 0;

    unpost_menu(zonessec_ctx.h_menu);
    free_menu(zonessec_ctx.h_menu);
    for (i = 0; i < zonessec_ctx.host_n; ++i)
        free_item(zonessec_ctx.hostitems[i]);

    free(zonessec_ctx.hostitems);

    del_panel(zonessec_ctx.h_panel[0]);

    destroy_win(zonessec_ctx.h_win);

    del_panel(zonessec_ctx.h_panel_top[0]);
    destroy_win(zonessec_ctx.h_win_top);
    del_panel(zonessec_ctx.h_panel_bot[0]);
    destroy_win(zonessec_ctx.h_win_bot);
}

/* rename a host or a group */
static int zones_rename_host_group(struct vrmr_ctx *vctx,
        struct vrmr_zones *zones, struct vrmr_rules *rules,
        struct vrmr_blocklist *blocklist, char *cur_name_ptr,
        char *new_name_ptr, int type, struct vrmr_regex *reg)
{
    int result = 0;
    struct vrmr_zone *zone_ptr = NULL, *member_ptr = NULL;
    struct vrmr_rule *rule_ptr = NULL;
    struct vrmr_list_node *d_node = NULL, *grp_d_node = NULL;
    char rules_changed = 0, blocklist_changed = 0, group_changed = 0;
    char old_host_name[VRMR_VRMR_MAX_HOST_NET_ZONE] = "",
         new_host[VRMR_MAX_HOST] = "", new_net[VRMR_MAX_NETWORK] = "",
         vrmr_new_zone[VRMR_MAX_ZONE] = "";
    char *blocklist_item = NULL, *new_blocklist_item = NULL;
    size_t size = 0;

    /* safety */
    vrmr_fatal_if_null(cur_name_ptr);
    vrmr_fatal_if_null(new_name_ptr);
    vrmr_fatal_if_null(zones);
    vrmr_fatal_if_null(rules);
    vrmr_fatal_if_null(reg);
    vrmr_fatal_if_null(blocklist);
    vrmr_fatal_if(type != VRMR_TYPE_HOST && type != VRMR_TYPE_GROUP);

    /* validate and split the new name */
    if (vrmr_validate_zonename(new_name_ptr, 0, vrmr_new_zone, new_net,
                new_host, reg->zonename, VRMR_VERBOSE) != 0) {
        vrmr_error(-1, VR_ERR, "invalid name '%s'", new_name_ptr);
        return (-1);
    }
    vrmr_debug(HIGH,
            "new_name_ptr: '%s': host/group '%s', net '%s', zone '%s'.",
            new_name_ptr, new_host, new_net, vrmr_new_zone);

    /* store the old name */
    (void)strlcpy(old_host_name, cur_name_ptr, sizeof(old_host_name));
    vrmr_debug(HIGH,
            "going to rename host/group old_host_name:'%s' to "
            "new_name_ptr:'%s'.",
            old_host_name, new_name_ptr);

    /* rename in the backend */
    result = vctx->zf->rename(
            vctx->zone_backend, old_host_name, new_name_ptr, type);
    if (result != 0) {
        return (-1);
    }

    /* search the zone in the list */
    zone_ptr = vrmr_search_zonedata(zones, old_host_name);
    vrmr_fatal_if_null(zone_ptr);

    (void)strlcpy(zone_ptr->name, new_name_ptr, sizeof(zone_ptr->name));
    (void)strlcpy(zone_ptr->host_name, new_host, sizeof(zone_ptr->host_name));
    zone_ptr = NULL;

    /* update rules */
    for (d_node = rules->list.top; d_node; d_node = d_node->next) {
        vrmr_fatal_if_null(d_node->data);
        rule_ptr = d_node->data;
        vrmr_debug(HIGH, "from: '%s', to: '%s'.", rule_ptr->from, rule_ptr->to);

        /* check the fromname */
        if (strcmp(rule_ptr->from, old_host_name) == 0) {
            vrmr_debug(HIGH,
                    "found in a rule (was looking for old_host_name:'%s', "
                    "found rule_ptr->from:'%s').",
                    old_host_name, rule_ptr->from);

            /* set the new name to the rules */
            (void)strlcpy(rule_ptr->from, new_name_ptr, sizeof(rule_ptr->from));
            rules_changed = 1;
        }
        /* do the same thing for to */
        if (strcmp(rule_ptr->to, old_host_name) == 0) {
            vrmr_debug(HIGH,
                    "found in a rule (was looking for old_host_name:'%s', "
                    "found rule_ptr->to:'%s').",
                    old_host_name, rule_ptr->to);

            /* set the new name to the rules */
            (void)strlcpy(rule_ptr->to, new_name_ptr, sizeof(rule_ptr->to));
            rules_changed = 1;
        }
    }
    /* if we have made changes we write the rulesfile */
    if (rules_changed == 1) {
        if (vrmr_rules_save_list(vctx, rules, &vctx->conf) < 0) {
            vrmr_error(-1, VR_ERR, gettext("saving rules failed."));
            return (-1);
        }
    }

    /* check the blocklist */
    for (d_node = blocklist->list.top; d_node; d_node = d_node->next) {
        vrmr_fatal_if_null(d_node->data);
        blocklist_item = d_node->data;

        if (strcmp(blocklist_item, old_host_name) == 0) {
            size = StrMemLen(new_name_ptr) + 1;
            if (size > 0) {
                new_blocklist_item = malloc(size);
                vrmr_fatal_alloc("malloc", new_blocklist_item);
                strlcpy(new_blocklist_item, new_name_ptr, size);
                /* swap the items */
                free(blocklist_item);
                d_node->data = new_blocklist_item;
            }

            blocklist_changed = 1;
        }
    }
    /* if we have made changes we write the blocklistfile */
    if (blocklist_changed == 1) {
        if (vrmr_blocklist_save_list(vctx, &vctx->conf, blocklist) < 0)
            return (-1);
    }

    /* group is done now */
    if (type == VRMR_TYPE_GROUP) {
        vrmr_audit("%s '%s' %s '%s'.", STR_GROUP, old_host_name,
                STR_HAS_BEEN_RENAMED_TO, new_name_ptr);
        return (0);
    }

    /* now check if we have a group that we are member of */
    for (d_node = zones->list.top; d_node; d_node = d_node->next) {
        vrmr_fatal_if_null(d_node->data);
        zone_ptr = d_node->data;

        if (zone_ptr->type == VRMR_TYPE_GROUP) {
            for (grp_d_node = zone_ptr->GroupList.top; grp_d_node;
                    grp_d_node = grp_d_node->next) {
                vrmr_fatal_if_null(grp_d_node->data);
                member_ptr = grp_d_node->data;

                /* the member->name is already changed, so we compare against
                 * the new name */
                if (strcmp(member_ptr->name, new_name_ptr) == 0) {
                    group_changed = 1;
                }
            }

            /* if the groups is changed, save it */
            if (group_changed == 1) {
                if (vrmr_zones_group_save_members(vctx, zone_ptr) < 0) {
                    vrmr_error(-1, VR_ERR,
                            gettext("saving changed group to backend failed."));
                    return (-1);
                }
                group_changed = 0;
            }
        }
    }

    vrmr_audit("%s '%s' %s '%s'.", STR_HOST, old_host_name,
            STR_HAS_BEEN_RENAMED_TO, new_name_ptr);

    return (0);
}

static int zones_section_menu_hosts(struct vrmr_ctx *vctx,
        struct vrmr_zones *zones, struct vrmr_rules *rules,
        struct vrmr_blocklist *blocklist, char *zonename, char *networkname,
        struct vrmr_regex *reg)
{
    int ch = 0, quit = 0, reload = 0, result = 0, retval = 0;
    size_t size = 0;
    struct vrmr_zone *zone_ptr = NULL;
    char *vrmr_new_zone_ptr = NULL, *temp_ptr = NULL, *cur_zonename_ptr = NULL;
    ITEM *cur = NULL;
    /* top menu */
    char *key_choices[] = {"F12", "INS", "DEL", "r", "RET", "e", "F10"};
    int key_choices_n = 7;
    char *cmd_choices[] = {gettext("help"), gettext("new"), gettext("del"),
            gettext("rename"), gettext("open"), gettext("edit"),
            gettext("back")};
    int cmd_choices_n = 7;

    /* safety */
    vrmr_fatal_if_null(zones);
    vrmr_fatal_if_null(zonename);
    vrmr_fatal_if_null(networkname);
    vrmr_fatal_if_null(reg);
    vrmr_fatal_if_null(blocklist);

    /* setup */
    zones_section_menu_hosts_init(zones, zonename, networkname);

    draw_top_menu(top_win, gettext("Hosts"), key_choices_n, key_choices,
            cmd_choices_n, cmd_choices);

    /* enter the loop */
    while (quit == 0) {
        /* reload the menu */
        if (reload == 1) {
            /* first destroy */
            zones_section_menu_hosts_destroy();
            /* and setup again */
            zones_section_menu_hosts_init(zones, zonename, networkname);
            /* we are done with reloading */
            reload = 0;
        }

        /* loop for catching user input */
        while (quit == 0 && reload == 0) {
            if (zonessec_ctx.h_top != NULL && !item_visible(zonessec_ctx.h_top))
                show_panel(zonessec_ctx.h_panel_top[0]);
            else
                hide_panel(zonessec_ctx.h_panel_top[0]);

            if (zonessec_ctx.h_bot != NULL && !item_visible(zonessec_ctx.h_bot))
                show_panel(zonessec_ctx.h_panel_bot[0]);
            else
                hide_panel(zonessec_ctx.h_panel_bot[0]);

            update_panels();
            doupdate();

            /* restore the cursor */
            pos_menu_cursor(zonessec_ctx.h_menu);

            /* get the user input */
            ch = wgetch(zonessec_ctx.h_win);
            switch (ch) {
                case 27:
                case KEY_LEFT:
                case KEY_F(10):
                case 'q':
                case 'Q':

                    quit = 1;
                    break;

                case 'r':
                case 'R':

                    cur = current_item(zonessec_ctx.h_menu);
                    if (cur) {
                        size = StrMemLen((char *)item_name(cur)) + 1 +
                               StrMemLen(networkname) + 1 +
                               StrMemLen(zonename) + 1;
                        cur_zonename_ptr = malloc(size);
                        vrmr_fatal_alloc("malloc", cur_zonename_ptr);

                        // create the string
                        (void)strlcpy(
                                cur_zonename_ptr, (char *)item_name(cur), size);
                        (void)strlcat(cur_zonename_ptr, ".", size);
                        (void)strlcat(cur_zonename_ptr, networkname, size);
                        (void)strlcat(cur_zonename_ptr, ".", size);
                        (void)strlcat(cur_zonename_ptr, zonename, size);

                        vrmr_new_zone_ptr = input_box(VRMR_MAX_HOST,
                                gettext("Rename Host"),
                                gettext("Enter the new name of the host"));
                        if (vrmr_new_zone_ptr != NULL) {
                            if (vrmr_validate_zonename(vrmr_new_zone_ptr, 1,
                                        NULL, NULL, NULL, reg->host_part,
                                        VRMR_VERBOSE) == -1) {
                                vrmr_warning(VR_WARN,
                                        gettext("invalid hostname '%s'."),
                                        vrmr_new_zone_ptr);
                            } else {
                                /* get the size */
                                size = StrMemLen(vrmr_new_zone_ptr) + 1 +
                                       StrMemLen(networkname) + 1 +
                                       StrMemLen(zonename) + 1;

                                /* alloc the memory */
                                temp_ptr = malloc(size);
                                vrmr_fatal_alloc("malloc", temp_ptr);

                                /* create the string */
                                (void)strlcpy(
                                        temp_ptr, vrmr_new_zone_ptr, size);
                                (void)strlcat(temp_ptr, ".", size);
                                (void)strlcat(temp_ptr, networkname, size);
                                (void)strlcat(temp_ptr, ".", size);
                                (void)strlcat(temp_ptr, zonename, size);

                                if (vrmr_validate_zonename(temp_ptr, 1, NULL,
                                            NULL, NULL, reg->zonename,
                                            VRMR_VERBOSE) == -1) {
                                    vrmr_warning(VR_WARN,
                                            gettext("invalid hostname '%s'."),
                                            temp_ptr);
                                } else {
                                    if (zones_rename_host_group(vctx, zones,
                                                rules, blocklist,
                                                cur_zonename_ptr, temp_ptr,
                                                VRMR_TYPE_HOST, reg) == 0) {
                                        /* we have a new host, so reload the
                                         * menu */
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

                case KEY_IC: /* insert key */
                case 'i':
                case 'I':

                    vrmr_new_zone_ptr =
                            input_box(VRMR_MAX_HOST, gettext("New Host"),
                                    gettext("Enter the name of the new host"));
                    if (vrmr_new_zone_ptr != NULL) {
                        if (vrmr_validate_zonename(vrmr_new_zone_ptr, 1, NULL,
                                    NULL, NULL, reg->host_part,
                                    VRMR_VERBOSE) == -1) {
                            vrmr_warning(VR_WARN,
                                    gettext("invalid hostname '%s'."),
                                    vrmr_new_zone_ptr);
                        } else {
                            /* get the size */
                            size = StrMemLen(vrmr_new_zone_ptr) + 1 +
                                   StrMemLen(networkname) + 1 +
                                   StrMemLen(zonename) + 1;

                            /* alloc the memory */
                            temp_ptr = malloc(size);
                            vrmr_fatal_alloc("malloc", temp_ptr);

                            /* create the string */
                            (void)strlcpy(temp_ptr, vrmr_new_zone_ptr, size);
                            (void)strlcat(temp_ptr, ".", size);
                            (void)strlcat(temp_ptr, networkname, size);
                            (void)strlcat(temp_ptr, ".", size);
                            (void)strlcat(temp_ptr, zonename, size);

                            if (vrmr_validate_zonename(temp_ptr, 1, NULL, NULL,
                                        NULL, reg->zonename,
                                        VRMR_VERBOSE) == -1) {
                                vrmr_warning(VR_WARN,
                                        gettext("invalid hostname '%s'."),
                                        temp_ptr);
                            } else {
                                if (vrmr_new_zone(vctx, zones, temp_ptr,
                                            VRMR_TYPE_HOST) >= 0) {
                                    vrmr_audit("%s '%s' %s.", STR_HOST,
                                            temp_ptr, STR_HAS_BEEN_CREATED);

                                    (void)edit_zone_host(
                                            vctx, zones, temp_ptr, reg);
                                    draw_top_menu(top_win, gettext("Hosts"),
                                            key_choices_n, key_choices,
                                            cmd_choices_n, cmd_choices);
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

                    cur = current_item(zonessec_ctx.h_menu);
                    if (cur &&
                            (confirm(gettext("Delete"), gettext("This host?"),
                                     vccnf.color_win_note,
                                     vccnf.color_win_note_rev | A_BOLD,
                                     0) == 1)) {

                        /* size */
                        size = StrMemLen((char *)item_name(cur)) + 1 +
                               StrMemLen(networkname) + 1 +
                               StrMemLen(zonename) + 1;

                        /* alloc the memory */
                        temp_ptr = malloc(size);
                        vrmr_fatal_if_null(temp_ptr);

                        /* create the full string */
                        (void)strlcpy(temp_ptr, (char *)item_name(cur), size);
                        (void)strlcat(temp_ptr, ".", size);
                        (void)strlcat(temp_ptr, networkname, size);
                        (void)strlcat(temp_ptr, ".", size);
                        (void)strlcat(temp_ptr, zonename, size);

                        zone_ptr = vrmr_search_zonedata(zones, temp_ptr);
                        vrmr_fatal_if_null(zone_ptr);

                        /* check the refernce counters */
                        if (zone_ptr->refcnt_group > 0) {
                            vrmr_error(-1, VR_ERR,
                                    gettext("host '%s' is still a member of %u "
                                            "group(s)."),
                                    zone_ptr->name, zone_ptr->refcnt_group);
                        } else if (zone_ptr->refcnt_blocklist > 0) {
                            vrmr_error(-1, VR_ERR,
                                    gettext("host '%s' is still in the "
                                            "blocklist (%u times)."),
                                    zone_ptr->name, zone_ptr->refcnt_blocklist);
                        } else {
                            if (vrmr_delete_zone(vctx, zones, temp_ptr,
                                        zone_ptr->type) < 0) {
                                vrmr_error(result, VR_ERR,
                                        gettext("deleting zone failed."));
                            } else {
                                vrmr_audit("%s '%s' %s.", STR_HOST, temp_ptr,
                                        STR_HAS_BEEN_DELETED);
                                reload = 1;
                            }
                        }
                        free(temp_ptr);
                    }
                    break;

                case KEY_DOWN:
                    menu_driver(zonessec_ctx.h_menu, REQ_DOWN_ITEM);
                    break;
                case KEY_UP:
                    menu_driver(zonessec_ctx.h_menu, REQ_UP_ITEM);
                    break;
                case KEY_NPAGE:
                    if (menu_driver(zonessec_ctx.h_menu, REQ_SCR_DPAGE) !=
                            E_OK) {
                        while (menu_driver(zonessec_ctx.h_menu,
                                       REQ_DOWN_ITEM) == E_OK)
                            ;
                    }
                    break;
                case KEY_PPAGE:
                    if (menu_driver(zonessec_ctx.h_menu, REQ_SCR_UPAGE) !=
                            E_OK) {
                        while (menu_driver(zonessec_ctx.h_menu, REQ_UP_ITEM) ==
                                E_OK)
                            ;
                    }
                    break;
                case KEY_HOME:
                    menu_driver(zonessec_ctx.h_menu, REQ_FIRST_ITEM); // home
                    break;
                case KEY_END:
                    menu_driver(zonessec_ctx.h_menu, REQ_LAST_ITEM); // end
                    break;

                case 32: // space
                case KEY_RIGHT:
                case 10: // enter
                case 'e':
                case 'E':

                    // get the current item
                    cur = current_item(zonessec_ctx.h_menu);
                    if (cur) {
                        // size
                        size = StrMemLen((char *)item_name(cur)) + 1 +
                               StrMemLen(networkname) + 1 +
                               StrMemLen(zonename) + 1;

                        // alloc the memory
                        temp_ptr = malloc(size);
                        vrmr_fatal_if_null(temp_ptr);

                        // create the string
                        (void)strlcpy(temp_ptr, (char *)item_name(cur), size);
                        (void)strlcat(temp_ptr, ".", size);
                        (void)strlcat(temp_ptr, networkname, size);
                        (void)strlcat(temp_ptr, ".", size);
                        (void)strlcat(temp_ptr, zonename, size);

                        zone_ptr = vrmr_search_zonedata(zones, temp_ptr);
                        vrmr_fatal_if_null(zone_ptr);
                        vrmr_fatal_if(zone_ptr->type != VRMR_TYPE_HOST);

                        (void)edit_zone_host(vctx, zones, zone_ptr->name, reg);
                        draw_top_menu(top_win, gettext("Hosts"), key_choices_n,
                                key_choices, cmd_choices_n, cmd_choices);

                        free(temp_ptr);
                        reload = 1;
                    }
                    break;

                case KEY_F(12):
                case 'h':
                case 'H':
                case '?':

                    print_help(":[VUURMUUR:ZONES:HOSTS]:");
                    break;
            }
        }
    }

    zones_section_menu_hosts_destroy();
    update_panels();
    doupdate();

    status_print(status_win, gettext("Ready."));
    return (retval);
}

static void edit_zone_group_members_init(
        struct vrmr_zones *zones, struct vrmr_zone *group_ptr)
{
    struct vrmr_list_node *d_node = NULL;
    struct vrmr_zone *member_ptr = NULL;
    int i = 0;
    int height = 30,
        width = 54, /* max width of host_name (32) + box (2) + 4 + 16 */
            startx = 0, starty = 0, max_height = 0;

    /* safety */
    vrmr_fatal_if_null(group_ptr);
    vrmr_fatal_if_null(zones);
    vrmr_fatal_if(group_ptr->type != VRMR_TYPE_GROUP);

    zonessec_ctx.edit_group.n_items = group_ptr->GroupList.len;

    zonessec_ctx.edit_group.items = (ITEM **)calloc(
            zonessec_ctx.edit_group.n_items + 1, sizeof(ITEM *));
    vrmr_fatal_alloc("calloc", zonessec_ctx.edit_group.items);

    max_height = getmaxy(stdscr);
    height = (int)(zonessec_ctx.edit_group.n_items +
                   7); /* 7 because: 3 above the list, 4 below */
    if (height >= max_height - 6) {
        height = max_height - 6;
    }
    /* place on the same y as zones list */
    VrWinGetOffset(
            -1, -1, height, width, 4, zonessec_ctx.h_xre + 1, &starty, &startx);

    /* load the items */
    for (i = 0, d_node = group_ptr->GroupList.top; d_node;
            d_node = d_node->next, i++) {
        vrmr_fatal_if_null(d_node->data);
        member_ptr = d_node->data;

        /* load all interfaces into memory */
        zonessec_ctx.edit_group.items[i] =
                new_item(member_ptr->host_name, member_ptr->ipv4.ipaddress);
        vrmr_fatal_if_null(zonessec_ctx.edit_group.items[i]);
    }
    zonessec_ctx.edit_group.items[zonessec_ctx.edit_group.n_items] =
            (ITEM *)NULL;

    if (zonessec_ctx.edit_group.n_items > 0) {
        zonessec_ctx.edit_group.top = zonessec_ctx.edit_group.items[0];
        zonessec_ctx.edit_group.bot =
                zonessec_ctx.edit_group
                        .items[zonessec_ctx.edit_group.n_items - 1];
    } else {
        zonessec_ctx.edit_group.top = NULL;
        zonessec_ctx.edit_group.bot = NULL;
    }

    /* create win and panel */
    zonessec_ctx.edit_group.win = newwin(height, width, starty, startx);
    vrmr_fatal_if_null(zonessec_ctx.edit_group.win);
    zonessec_ctx.edit_group.panel[0] = new_panel(zonessec_ctx.edit_group.win);
    vrmr_fatal_if_null(zonessec_ctx.edit_group.panel[0]);
    wbkgd(zonessec_ctx.edit_group.win, vccnf.color_win);
    keypad(zonessec_ctx.edit_group.win, TRUE);

    zonessec_ctx.edit_group.menu =
            new_menu((ITEM **)zonessec_ctx.edit_group.items);
    vrmr_fatal_if_null(zonessec_ctx.edit_group.menu);
    set_menu_win(zonessec_ctx.edit_group.menu, zonessec_ctx.edit_group.win);
    set_menu_sub(zonessec_ctx.edit_group.menu,
            derwin(zonessec_ctx.edit_group.win, height - 6, width - 2, 3, 1));
    set_menu_format(zonessec_ctx.edit_group.menu, height - 7, 1);

    /* markup */
    box(zonessec_ctx.edit_group.win, 0, 0);
    print_in_middle(zonessec_ctx.edit_group.win, 1, 0, width,
            gettext("Members"), vccnf.color_win);
    mvwaddch(zonessec_ctx.edit_group.win, 2, 0, ACS_LTEE);
    mvwhline(zonessec_ctx.edit_group.win, 2, 1, ACS_HLINE, width - 2);
    mvwaddch(zonessec_ctx.edit_group.win, 2, width - 1, ACS_RTEE);

    set_menu_back(zonessec_ctx.edit_group.menu, vccnf.color_win);
    set_menu_fore(zonessec_ctx.edit_group.menu, vccnf.color_win_rev);

    post_menu(zonessec_ctx.edit_group.menu);

    mvwaddch(zonessec_ctx.edit_group.win, height - 4, 0, ACS_LTEE);
    mvwhline(zonessec_ctx.edit_group.win, height - 4, 1, ACS_HLINE, width - 2);
    mvwaddch(zonessec_ctx.edit_group.win, height - 4, width - 1, ACS_RTEE);

    mvwprintw(zonessec_ctx.edit_group.win, height - 3, 2, "<INS> %s", STR_NEW);
    mvwprintw(
            zonessec_ctx.edit_group.win, height - 2, 2, "<DEL> %s", STR_REMOVE);

    /* create the top and bottom fields */
    zonessec_ctx.edit_group.win_top = newwin(1, 6, starty + 2, width - 8);
    vrmr_fatal_if_null(zonessec_ctx.edit_group.win_top);
    wbkgd(zonessec_ctx.edit_group.win_top, vccnf.color_win);
    zonessec_ctx.edit_group.panel_top[0] =
            new_panel(zonessec_ctx.edit_group.win_top);
    /* TRANSLATORS: max 4 chars */
    wprintw(zonessec_ctx.edit_group.win_top, "(%s)", gettext("more"));
    hide_panel(zonessec_ctx.edit_group.panel_top[0]);

    zonessec_ctx.edit_group.win_bot =
            newwin(1, 6, starty + height - 4, width - 8);
    vrmr_fatal_if_null(zonessec_ctx.edit_group.win_bot);
    wbkgd(zonessec_ctx.edit_group.win_bot, vccnf.color_win);
    zonessec_ctx.edit_group.panel_bot[0] =
            new_panel(zonessec_ctx.edit_group.win_bot);
    /* TRANSLATORS: max 4 chars */
    wprintw(zonessec_ctx.edit_group.win_bot, "(%s)", gettext("more"));
    hide_panel(zonessec_ctx.edit_group.panel_bot[0]);

    update_panels();
    doupdate();
}

static void edit_zone_group_members_destroy(void)
{
    size_t i = 0;

    // Un post form and free the memory
    unpost_menu(zonessec_ctx.edit_group.menu);
    free_menu(zonessec_ctx.edit_group.menu);

    for (i = 0; i < zonessec_ctx.edit_group.n_items; i++) {
        free_item(zonessec_ctx.edit_group.items[i]);
    }
    free(zonessec_ctx.edit_group.items);

    del_panel(zonessec_ctx.edit_group.panel[0]);
    destroy_win(zonessec_ctx.edit_group.win);

    del_panel(zonessec_ctx.edit_group.panel_top[0]);
    destroy_win(zonessec_ctx.edit_group.win_top);
    del_panel(zonessec_ctx.edit_group.panel_bot[0]);
    destroy_win(zonessec_ctx.edit_group.win_bot);

    update_panels();
    doupdate();
}

/*  edit_zone_group_members_delmem

    Deletes the member 'member_name' from the GroupList of
    the group 'group_ptr'.
*/
static void edit_zone_group_members_delmem(
        struct vrmr_ctx *vctx, struct vrmr_zone *group_ptr, char *member_name)
{
    int result = 0;
    char logname[VRMR_VRMR_MAX_HOST_NET_ZONE] = "";

    snprintf(logname, sizeof(logname), "%s.%s.%s", member_name,
            group_ptr->network_name, group_ptr->zone_name);

    result = vrmr_zones_group_rem_member(vctx, group_ptr, member_name);
    if (result == 0) {
        vrmr_audit("%s '%s' %s: %s: '%s'.", STR_GROUP, group_ptr->name,
                STR_HAS_BEEN_CHANGED, logname, STR_A_MEMBER_HAS_BEEN_REMOVED);
    }
}

/*  edit_zone_group_members_newmem

    Displays a menu with hosts to chose from to add to the
    group 'group_ptr'.
*/
static void edit_zone_group_members_newmem(struct vrmr_ctx *vctx,
        struct vrmr_zones *zones, struct vrmr_zone *group_ptr)
{
    struct vrmr_list_node *d_node = NULL;
    char **choices, *choice_ptr = NULL,
                    search_name[VRMR_VRMR_MAX_HOST_NET_ZONE] = "";
    size_t n_choices = 0, i = 0;
    struct vrmr_zone *zonelist_ptr = NULL;
    int result = 0;

    /* safety */
    vrmr_fatal_if_null(group_ptr);
    vrmr_fatal_if_null(zones);
    vrmr_fatal_if(group_ptr->type != VRMR_TYPE_GROUP);

    /* first count the number of hosts in this network */
    for (n_choices = 0, d_node = zones->list.top; d_node;
            d_node = d_node->next) {
        vrmr_fatal_if_null(d_node->data);
        zonelist_ptr = d_node->data;

        if (zonelist_ptr->type == VRMR_TYPE_HOST) {
            /* check if the host belongs to our zone */
            if (strcmp(group_ptr->zone_name, zonelist_ptr->zone_name) == 0) {
                /* check if the host belongs to our network */
                if (strcmp(group_ptr->network_name,
                            zonelist_ptr->network_name) == 0) {
                    n_choices++;
                }
            }
        }
    }

    if (n_choices == 0) {
        vrmr_warning(VR_WARN,
                gettext("please add some hosts to the network first."));
        return;
    }

    /* alloc the mem */
    choices = calloc(n_choices + 1, VRMR_MAX_HOST);
    vrmr_fatal_alloc("calloc", choices);

    /* now init the new mem */
    for (i = n_choices - 1, d_node = zones->list.bot; d_node;
            d_node = d_node->prev) {
        vrmr_fatal_if_null(d_node->data);
        zonelist_ptr = d_node->data;

        if (zonelist_ptr->type == VRMR_TYPE_HOST) {
            if (strcmp(group_ptr->zone_name, zonelist_ptr->zone_name) == 0) {
                if (strcmp(group_ptr->network_name,
                            zonelist_ptr->network_name) == 0) {
                    choices[i] = zonelist_ptr->host_name;
                    i--;
                }
            }
        }
    }

    /* let the user select one. If he/she doesn't select one, fine, bail out. */
    if (!(choice_ptr = selectbox(gettext("New member"),
                  gettext("Select a host"), n_choices, choices, 1, NULL))) {
        /* no choice was made, so quit quietly. */
        free(choices);
        return;
    }

    /* clean up */
    free(choices);

    /* assemble the full zonename... */
    snprintf(search_name, sizeof(search_name), "%s.%s.%s", choice_ptr,
            group_ptr->network_name, group_ptr->zone_name);

    /* and free the hostname */
    free(choice_ptr);

    /* add the member */
    result = vrmr_zones_group_add_member(vctx, zones, group_ptr, search_name);
    if (result == 0) {
        vrmr_audit("%s '%s' %s: %s: %s.", STR_GROUP, group_ptr->name,
                STR_HAS_BEEN_CHANGED, STR_A_MEMBER_HAS_BEEN_ADDED, search_name);
    }
}

/*  edit_group_members

    Displays the grouplist and allows the user to add
    and remove members.

    Returncodes:
         0: ok
        -1: error
*/
static void edit_zone_group_members(struct vrmr_ctx *vctx,
        struct vrmr_zones *zones, struct vrmr_zone *zone_ptr)
{
    int quit = 0, reload = 0, ch;
    ITEM *cur = NULL;

    /* safety */
    vrmr_fatal_if_null(zone_ptr);
    vrmr_fatal_if_null(zones);

    /* setup the win */
    edit_zone_group_members_init(zones, zone_ptr);

    while (quit == 0) {
        if (reload == 1) {
            /* first destroy */
            edit_zone_group_members_destroy();
            /* then init again */
            edit_zone_group_members_init(zones, zone_ptr);
            /* refresh screen */
            update_panels();
            doupdate();
            reload = 0;
        }

        while (quit == 0 && reload == 0) {
            if (zonessec_ctx.edit_group.top != NULL &&
                    !item_visible(zonessec_ctx.edit_group.top))
                show_panel(zonessec_ctx.edit_group.panel_top[0]);
            else
                hide_panel(zonessec_ctx.edit_group.panel_top[0]);

            if (zonessec_ctx.edit_group.bot != NULL &&
                    !item_visible(zonessec_ctx.edit_group.bot))
                show_panel(zonessec_ctx.edit_group.panel_bot[0]);
            else
                hide_panel(zonessec_ctx.edit_group.panel_bot[0]);

            update_panels();
            doupdate();

            /* restore the cursor */
            pos_menu_cursor(zonessec_ctx.edit_group.menu);

            /* get user input */
            ch = wgetch(zonessec_ctx.edit_group.win);
            switch (ch) {
                case 27:
                case 'q':
                case 'Q':
                case KEY_F(10): // quit

                    quit = 1;
                    break;

                case KEY_IC:
                case 'i':
                case 'I':

                    edit_zone_group_members_newmem(vctx, zones, zone_ptr);
                    reload = 1;
                    break;

                case KEY_DC:
                case 'd':
                case 'D':

                    cur = current_item(zonessec_ctx.edit_group.menu);
                    if (cur) {
                        char *n = (char *)item_name(cur);
                        edit_zone_group_members_delmem(vctx, zone_ptr, n);
                        reload = 1;
                    }
                    break;

                case KEY_DOWN:
                    menu_driver(zonessec_ctx.edit_group.menu, REQ_DOWN_ITEM);
                    break;
                case KEY_UP:
                    menu_driver(zonessec_ctx.edit_group.menu, REQ_UP_ITEM);
                    break;
                case KEY_NPAGE:
                    if (menu_driver(zonessec_ctx.edit_group.menu,
                                REQ_SCR_DPAGE) != E_OK) {
                        while (menu_driver(zonessec_ctx.edit_group.menu,
                                       REQ_DOWN_ITEM) == E_OK)
                            ;
                    }
                    break;
                case KEY_PPAGE:
                    if (menu_driver(zonessec_ctx.edit_group.menu,
                                REQ_SCR_UPAGE) != E_OK) {
                        while (menu_driver(zonessec_ctx.edit_group.menu,
                                       REQ_UP_ITEM) == E_OK)
                            ;
                    }
                    break;
                case KEY_HOME:
                    menu_driver(zonessec_ctx.edit_group.menu,
                            REQ_FIRST_ITEM); // home
                    break;
                case KEY_END:
                    menu_driver(zonessec_ctx.edit_group.menu,
                            REQ_LAST_ITEM); // end
                    break;
            }
        }
    }

    /* cleanup */
    edit_zone_group_members_destroy();

    status_print(status_win, gettext("Ready."));
}

struct {
    FIELD *activefld, *activelabelfld,

            *commentfld, *commentlabelfld,

            *warningfld; /* field for warnings */

} GroupSec;

static void edit_zone_group_init(
        struct vrmr_ctx *vctx, const char *name, struct vrmr_zone *zone_ptr)
{
    int rows, cols, max_height = 0, height = 0, width = 0, startx = 0,
                    starty = 0, comment_y = 0, comment_x = 0;
    size_t i, field_num = 0;

    /* safety */
    vrmr_fatal_if_null(name);
    vrmr_fatal_if_null(zone_ptr);

    max_height = getmaxy(stdscr);
    height = 17;
    if (height > max_height - 8)
        height = max_height - 8;
    width = 54;
    VrWinGetOffset(-1, -1, height, width, zonessec_ctx.h_yle + 1,
            zonessec_ctx.n_xre + 1, &starty, &startx);

    memset(&GroupSec, 0, sizeof(GroupSec));
    zonessec_ctx.edit_zone.n_fields = 5;

    zonessec_ctx.edit_zone.fields = (FIELD **)calloc(
            zonessec_ctx.edit_zone.n_fields + 1, sizeof(FIELD *));
    vrmr_fatal_alloc("calloc", zonessec_ctx.edit_zone.fields);

    /* preload the active field */
    GroupSec.activelabelfld = (zonessec_ctx.edit_zone.fields[field_num++] =
                                       new_field_wrap(1, 16, 2, 0, 0, 0));
    set_field_buffer_wrap(GroupSec.activelabelfld, 0, gettext("Active"));
    field_opts_off(GroupSec.activelabelfld, O_AUTOSKIP | O_ACTIVE);

    GroupSec.activefld = (zonessec_ctx.edit_zone.fields[field_num++] =
                                  new_field_wrap(1, 3, 3, 1, 0, 0));
    set_field_buffer_wrap(
            GroupSec.activefld, 0, zone_ptr->active ? STR_YES : STR_NO);

    /* comment label */
    GroupSec.commentlabelfld = (zonessec_ctx.edit_zone.fields[field_num++] =
                                        new_field_wrap(1, 16, 5, 0, 0, 0));
    set_field_buffer_wrap(GroupSec.commentlabelfld, 0, gettext("Comment"));
    field_opts_off(GroupSec.commentlabelfld, O_AUTOSKIP | O_ACTIVE);

    /* comment field size */
    comment_y = 5;
    comment_x = 48;
    /* create the comment field */
    GroupSec.commentfld =
            (zonessec_ctx.edit_zone.fields[field_num++] =
                            new_field_wrap(comment_y, comment_x, 6, 1, 0, 0));

    /* load the comment from the backend */
    if (vctx->zf->ask(vctx->zone_backend, zone_ptr->name, "COMMENT",
                zonessec_ctx.comment, sizeof(zonessec_ctx.comment),
                VRMR_TYPE_GROUP, 0) < 0)
        vrmr_error(-1, VR_ERR, gettext("error while loading the comment."));

    set_field_buffer_wrap(GroupSec.commentfld, 0, zonessec_ctx.comment);

    /* comment label */
    GroupSec.warningfld = (zonessec_ctx.edit_zone.fields[field_num++] =
                                   new_field_wrap(1, 48, 11, 1, 0, 0));
    field_opts_off(GroupSec.warningfld, O_AUTOSKIP | O_ACTIVE | O_VISIBLE);
    set_field_just(GroupSec.warningfld, JUSTIFY_CENTER);

    vrmr_fatal_if(field_num != zonessec_ctx.edit_zone.n_fields);

    /* terminate */
    zonessec_ctx.edit_zone.fields[zonessec_ctx.edit_zone.n_fields] = NULL;

    zonessec_ctx.edit_zone.win = create_newwin(height, width, starty, startx,
            gettext("Edit Zone: Group"), vccnf.color_win);
    vrmr_fatal_if_null(zonessec_ctx.edit_zone.win);
    zonessec_ctx.edit_zone.panel[0] = new_panel(zonessec_ctx.edit_zone.win);
    vrmr_fatal_if_null(zonessec_ctx.edit_zone.panel[0]);

    /* set field options */
    for (i = 0; i < zonessec_ctx.edit_zone.n_fields; i++) {
        set_field_back(zonessec_ctx.edit_zone.fields[i], vccnf.color_win_rev);
        field_opts_off(zonessec_ctx.edit_zone.fields[i], O_AUTOSKIP);
        set_field_status(zonessec_ctx.edit_zone.fields[i], FALSE);
    }
    set_field_back(GroupSec.activelabelfld, vccnf.color_win);
    set_field_back(GroupSec.commentlabelfld, vccnf.color_win);

    set_field_back(GroupSec.warningfld, vccnf.color_win);
    set_field_fore(GroupSec.warningfld, vccnf.color_win_warn | A_BOLD);

    /* Create the form and post it */
    zonessec_ctx.edit_zone.form = new_form(zonessec_ctx.edit_zone.fields);
    vrmr_fatal_if_null(zonessec_ctx.edit_zone.form);
    /* Calculate the area required for the form */
    scale_form(zonessec_ctx.edit_zone.form, &rows, &cols);
    keypad(zonessec_ctx.edit_zone.win, TRUE);

    /* Set main window and sub window */
    set_form_win(zonessec_ctx.edit_zone.form, zonessec_ctx.edit_zone.win);
    set_form_sub(zonessec_ctx.edit_zone.form,
            derwin(zonessec_ctx.edit_zone.win, rows, cols, 1, 2));
    post_form(zonessec_ctx.edit_zone.form);

    /* draw labels */
    mvwprintw(zonessec_ctx.edit_zone.win, 1, 2, "%s: %s", gettext("Name"),
            zone_ptr->name);
    mvwprintw(zonessec_ctx.edit_zone.win, 13, 2,
            gettext("Press <F6> to manage the members of this group."));

    wrefresh(zonessec_ctx.edit_zone.win);
    update_panels();
    doupdate();
}

static int edit_zone_group_save(
        struct vrmr_ctx *vctx, struct vrmr_zone *group_ptr)
{
    int retval = 0, active = 0;
    size_t i = 0;

    /* safety */
    vrmr_fatal_if_null(group_ptr);

    /* check for changed fields */
    for (i = 0; i < zonessec_ctx.edit_zone.n_fields; i++) {
        if (field_status(zonessec_ctx.edit_zone.fields[i]) == FALSE)
            continue;

        /* active field */
        if (zonessec_ctx.edit_zone.fields[i] == GroupSec.activefld) {
            group_ptr->status = VRMR_ST_CHANGED;

            active = group_ptr->active;

            if (strncasecmp(field_buffer(zonessec_ctx.edit_zone.fields[i], 0),
                        STR_YES, StrLen(STR_YES)) == 0) {
                group_ptr->active = 1;
            } else if (strncasecmp(field_buffer(
                                           zonessec_ctx.edit_zone.fields[i], 0),
                               STR_NO, StrLen(STR_NO)) == 0) {
                group_ptr->active = 0;
            } else {
                group_ptr->active = -1;
            }

            if (vctx->zf->tell(vctx->zone_backend, group_ptr->name, "ACTIVE",
                        group_ptr->active ? "Yes" : "No", 1,
                        VRMR_TYPE_GROUP) < 0) {
                vrmr_error(-1, VR_ERR, gettext("saving to backend failed"));
                retval = -1;
            }

            /* for the log */
            vrmr_audit("%s '%s' %s: %s %s '%s' (%s: '%s').", STR_GROUP,
                    group_ptr->name, STR_HAS_BEEN_CHANGED, STR_ACTIVE,
                    STR_IS_NOW_SET_TO, group_ptr->active ? STR_YES : STR_NO,
                    STR_WAS, active ? STR_YES : STR_NO);
        } else if (zonessec_ctx.edit_zone.fields[i] == GroupSec.commentfld) {
            if (vctx->zf->tell(vctx->zone_backend, group_ptr->name, "COMMENT",
                        field_buffer(zonessec_ctx.edit_zone.fields[i], 0), 1,
                        VRMR_TYPE_GROUP) < 0) {
                vrmr_error(-1, VR_ERR, gettext("saving to backend failed"));
                retval = -1;
            }

            /* example: "group 'it-dept.local.lan' has been changed: the comment
             * was changed." */
            vrmr_audit("%s '%s' %s: %s.", STR_GROUP, group_ptr->name,
                    STR_HAS_BEEN_CHANGED, STR_COMMENT_CHANGED);
        } else if (zonessec_ctx.edit_zone.fields[i] == GroupSec.warningfld) {
            /* do nothing */
        } else {
            vrmr_fatal("unknown field");
        }
    }

    return (retval);
}

static void edit_zone_group_destroy(void)
{
    size_t i = 0;

    /* Un post form and free the memory */
    unpost_form(zonessec_ctx.edit_zone.form);
    free_form(zonessec_ctx.edit_zone.form);

    for (i = 0; i < zonessec_ctx.edit_zone.n_fields; i++) {
        free_field(zonessec_ctx.edit_zone.fields[i]);
    }
    free(zonessec_ctx.edit_zone.fields);

    del_panel(zonessec_ctx.edit_zone.panel[0]);
    destroy_win(zonessec_ctx.edit_zone.win);

    /* clear comment string */
    strcpy(zonessec_ctx.comment, "");
}

/*  edit_zone_group

    Edit a group :-)

    Returncodes:
        0: ok
        -1: error
*/
static int edit_zone_group(
        struct vrmr_ctx *vctx, struct vrmr_zones *zones, char *name)
{
    int ch, not_defined = 0, retval = 0;
    struct vrmr_zone *zone_ptr = NULL;
    int quit = 0;
    FIELD *cur = NULL, *prev = NULL;
    /* top menu */
    char *key_choices[] = {"F12", "F6", "F10"};
    int key_choices_n = 3;
    char *cmd_choices[] = {
            gettext("help"), gettext("members"), gettext("back")};
    int cmd_choices_n = 3;

    /* safety */
    vrmr_fatal_if_null(name);
    vrmr_fatal_if_null(zones);

    /* search the group in mem */
    zone_ptr = vrmr_search_zonedata(zones, name);
    vrmr_fatal_if_null(zone_ptr);

    /* loop through to get user requests */
    while (quit == 0) {
        /* init */
        edit_zone_group_init(vctx, name, zone_ptr);

        /* print (or not) initial warning about the group being empty. */
        if (zone_ptr->GroupList.len == 0) {
            set_field_buffer_wrap(
                    GroupSec.warningfld, 0, gettext("Warning: no members!"));
            field_opts_on(GroupSec.warningfld, O_VISIBLE);
        } else if (zone_ptr->active == TRUE &&
                   vrmr_zones_active(zone_ptr) == 0) {
            set_field_buffer_wrap(GroupSec.warningfld, 0,
                    gettext("Note: parent zone/network is inactive."));
            field_opts_on(GroupSec.warningfld, O_VISIBLE);
            set_field_status(GroupSec.warningfld, FALSE);
        }

        mvwprintw(zonessec_ctx.edit_zone.win, 4, 37, "%s: %4d",
                gettext("Members"), zone_ptr->GroupList.len);

        /* print, set cursor etc */
        pos_form_cursor(zonessec_ctx.edit_zone.form);
        cur = current_field(zonessec_ctx.edit_zone.form);

        draw_top_menu(top_win, gettext("Edit Group"), key_choices_n,
                key_choices, cmd_choices_n, cmd_choices);

        wrefresh(zonessec_ctx.edit_zone.win);
        update_panels();
        doupdate();

        while (quit == 0) {
            draw_field_active_mark(cur, prev, zonessec_ctx.edit_zone.win,
                    zonessec_ctx.edit_zone.form, vccnf.color_win_mark | A_BOLD);

            /* get user input */
            ch = wgetch(zonessec_ctx.edit_zone.win);

            not_defined = 0;

            /* handle input */
            if (cur == GroupSec.commentfld) {
                if (nav_field_comment(zonessec_ctx.edit_zone.form, ch) < 0)
                    not_defined = 1;
            } else if (cur == GroupSec.activefld) {
                if (nav_field_yesno(zonessec_ctx.edit_zone.form, ch) < 0)
                    not_defined = 1;
            } else
                not_defined = 1;

            /* the rest is handled here */
            if (not_defined == 1) {
                switch (ch) {
                    case KEY_F(6):
                    case 'e':
                    case 'E':

                        /* edit the members */
                        edit_zone_group_members(vctx, zones, zone_ptr);

                        draw_top_menu(top_win, gettext("Edit Group"),
                                key_choices_n, key_choices, cmd_choices_n,
                                cmd_choices);
                        break;

                    case 27:
                    case 'q':
                    case 'Q':
                    case KEY_F(10): /* quit */

                        quit = 1;
                        break;

                    case KEY_DOWN:
                    case 9:  // tab
                    case 10: // enter

                        form_driver_wrap(
                                zonessec_ctx.edit_zone.form, REQ_NEXT_FIELD);
                        form_driver_wrap(
                                zonessec_ctx.edit_zone.form, REQ_BEG_LINE);
                        break;

                    case KEY_UP:

                        form_driver_wrap(
                                zonessec_ctx.edit_zone.form, REQ_PREV_FIELD);
                        form_driver_wrap(
                                zonessec_ctx.edit_zone.form, REQ_BEG_LINE);
                        break;

                    case KEY_F(12):
                    case 'h':
                    case 'H':
                    case '?':

                        print_help(":[VUURMUUR:ZONES:GROUP:EDIT]:");
                        break;
                }
            }

            /* before we get the new 'cur', store cur in prev */
            prev = cur;
            cur = current_field(zonessec_ctx.edit_zone.form);

            /* draw empty group warning */
            if (zone_ptr->GroupList.len == 0) {
                set_field_buffer_wrap(GroupSec.warningfld, 0,
                        gettext("Warning: no members!"));
                field_opts_on(GroupSec.warningfld, O_VISIBLE);
                set_field_status(GroupSec.warningfld, FALSE);
            } else if (strncasecmp(field_buffer(GroupSec.activefld, 0), STR_YES,
                               StrLen(STR_YES)) == 0 &&
                       vrmr_zones_active(zone_ptr) == 0) {
                set_field_buffer_wrap(GroupSec.warningfld, 0,
                        gettext("Note: parent zone/network is inactive."));
                field_opts_on(GroupSec.warningfld, O_VISIBLE);
                set_field_status(GroupSec.warningfld, FALSE);
            }
            /* and clear */
            else {
                field_opts_off(GroupSec.warningfld, O_VISIBLE);
            }

            mvwprintw(zonessec_ctx.edit_zone.win, 4, 37, "%s: %4d",
                    gettext("Members"), zone_ptr->GroupList.len);

            /* refresh and restore cursor. */
            wrefresh(zonessec_ctx.edit_zone.win);
            pos_form_cursor(zonessec_ctx.edit_zone.form);
        }
    }

    /* save to backend */
    if (edit_zone_group_save(vctx, zone_ptr) < 0)
        retval = -1;

    /* cleanup */
    edit_zone_group_destroy();

    update_panels();
    doupdate();

    status_print(status_win, gettext("Ready."));
    return (retval);
}

static void zones_section_menu_groups_init(
        struct vrmr_zones *zones, char *zonename, char *networkname)
{
    size_t i = 0;
    struct vrmr_zone *zone_ptr = NULL;
    int height, width, starty, startx, maxy;
    struct vrmr_list_node *d_node = NULL;
    char temp[32], *desc_ptr = NULL;

    /* safety */
    vrmr_fatal_if_null(zones);
    vrmr_fatal_if_null(zonename);
    vrmr_fatal_if_null(networkname);

    /* get screensize */
    maxy = getmaxy(stdscr);

    /* count how many zones there are */
    zonessec_ctx.host_n = 0;

    for (d_node = zones->list.top; d_node; d_node = d_node->next) {
        vrmr_fatal_if_null(d_node->data);
        zone_ptr = d_node->data;

        if (zone_ptr->type == VRMR_TYPE_GROUP) {
            if (strcmp(zone_ptr->zone_name, zonename) == 0 &&
                    strcmp(zone_ptr->network_name, networkname) == 0) {
                zonessec_ctx.host_n++;
            }
        }
    }

    vrmr_list_setup(&zonessec_ctx.group_desc_list, free);

    i = zonessec_ctx.host_n - 1;

    zonessec_ctx.hostitems =
            (ITEM **)calloc(zonessec_ctx.host_n + 1, sizeof(ITEM *));
    vrmr_fatal_alloc("calloc", zonessec_ctx.hostitems);

    for (d_node = zones->list.bot; d_node; d_node = d_node->prev) {
        vrmr_fatal_if_null(d_node->data);
        zone_ptr = d_node->data;

        if (zone_ptr->type == VRMR_TYPE_GROUP) {
            if (strcmp(zone_ptr->zone_name, zonename) == 0 &&
                    strcmp(zone_ptr->network_name, networkname) == 0) {
                snprintf(temp, sizeof(temp), "%6u %s", zone_ptr->GroupList.len,
                        gettext("members"));

                desc_ptr = strdup(temp);
                vrmr_fatal_alloc("strdup", desc_ptr);

                vrmr_fatal_if(vrmr_list_append(&zonessec_ctx.group_desc_list,
                                      desc_ptr) == NULL);

                zonessec_ctx.hostitems[i] =
                        new_item(zone_ptr->host_name, desc_ptr);
                vrmr_fatal_if_null(zonessec_ctx.hostitems[i]);
                i--;
            }
        }
    }
    zonessec_ctx.hostitems[zonessec_ctx.host_n] = (ITEM *)NULL;

    if (zonessec_ctx.host_n > 0) {
        zonessec_ctx.h_top = zonessec_ctx.hostitems[0];
        zonessec_ctx.h_bot = zonessec_ctx.hostitems[zonessec_ctx.host_n - 1];
    } else {
        zonessec_ctx.h_top = NULL;
        zonessec_ctx.h_bot = NULL;
    }

    zonessec_ctx.h_menu = new_menu((ITEM **)zonessec_ctx.hostitems);
    vrmr_fatal_if_null(zonessec_ctx.h_menu);

    height = (int)(zonessec_ctx.host_n + 9);
    if (height > maxy - 8) {
        height = maxy - 8;
    }
    width = 54; // same as edit zone: group win

    /* place on the same y as zones list */
    VrWinGetOffset(
            -1, -1, height, width, 4, zonessec_ctx.n_xre + 1, &starty, &startx);
    zonessec_ctx.h_yle = starty + height;
    zonessec_ctx.h_xre = startx + width;

    zonessec_ctx.h_win = newwin(height, width, starty, startx);
    vrmr_fatal_if_null(zonessec_ctx.h_win);
    wbkgd(zonessec_ctx.h_win, vccnf.color_win);
    keypad(zonessec_ctx.h_win, TRUE);
    box(zonessec_ctx.h_win, 0, 0);
    print_in_middle(zonessec_ctx.h_win, 1, 0, width, gettext("Groups"),
            vccnf.color_win);
    wrefresh(zonessec_ctx.h_win);

    zonessec_ctx.h_panel[0] = new_panel(zonessec_ctx.h_win);
    vrmr_fatal_if_null(zonessec_ctx.h_panel[0]);
    update_panels();

    set_menu_win(zonessec_ctx.h_menu, zonessec_ctx.h_win);
    set_menu_sub(zonessec_ctx.h_menu,
            derwin(zonessec_ctx.h_win, height - 7, width - 2, 3, 1));
    set_menu_format(zonessec_ctx.h_menu, height - 8, 1);

    mvwaddch(zonessec_ctx.h_win, 2, 0, ACS_LTEE);
    mvwhline(zonessec_ctx.h_win, 2, 1, ACS_HLINE, width - 2);
    mvwaddch(zonessec_ctx.h_win, 2, width - 1, ACS_RTEE);

    set_menu_back(zonessec_ctx.h_menu, vccnf.color_win);
    set_menu_fore(zonessec_ctx.h_menu, vccnf.color_win_rev);

    post_menu(zonessec_ctx.h_menu);
    doupdate();

    mvwaddch(zonessec_ctx.h_win, height - 5, 0, ACS_LTEE);
    mvwhline(zonessec_ctx.h_win, height - 5, 1, ACS_HLINE, width - 2);
    mvwaddch(zonessec_ctx.h_win, height - 5, width - 1, ACS_RTEE);

    mvwprintw(zonessec_ctx.h_win, height - 4, 1, "<RET> %s", STR_EDIT);
    mvwprintw(zonessec_ctx.h_win, height - 3, 1, "<INS> %s", STR_NEW);
    mvwprintw(zonessec_ctx.h_win, height - 2, 1, "<DEL> %s", STR_REMOVE);

    /* create the top and bottom fields */
    zonessec_ctx.h_win_top = newwin(1, 6, starty + 2, startx + width - 8);
    vrmr_fatal_if_null(zonessec_ctx.h_win_top);
    wbkgd(zonessec_ctx.h_win_top, vccnf.color_win);
    zonessec_ctx.h_panel_top[0] = new_panel(zonessec_ctx.h_win_top);
    vrmr_fatal_if_null(zonessec_ctx.h_panel_top[0]);
    /* TRANSLATORS: max 4 chars */
    wprintw(zonessec_ctx.h_win_top, "(%s)", gettext("more"));
    //    hide_panel(zonessec_ctx.h_panel_top[0]);

    zonessec_ctx.h_win_bot =
            newwin(1, 6, starty + height - 5, startx + width - 8);
    vrmr_fatal_if_null(zonessec_ctx.h_win_bot);
    wbkgd(zonessec_ctx.h_win_bot, vccnf.color_win);
    zonessec_ctx.h_panel_bot[0] = new_panel(zonessec_ctx.h_win_bot);
    vrmr_fatal_if_null(zonessec_ctx.h_panel_bot[0]);
    /* TRANSLATORS: max 4 chars */
    wprintw(zonessec_ctx.h_win_bot, "(%s)", gettext("more"));
    //    hide_panel(zonessec_ctx.h_panel_bot[0]);
}

static void zones_section_menu_groups_destroy(void)
{
    size_t i = 0;

    unpost_menu(zonessec_ctx.h_menu);
    free_menu(zonessec_ctx.h_menu);
    for (i = 0; i < zonessec_ctx.host_n; ++i)
        free_item(zonessec_ctx.hostitems[i]);
    vrmr_list_cleanup(&zonessec_ctx.group_desc_list);
    free(zonessec_ctx.hostitems);
    del_panel(zonessec_ctx.h_panel[0]);
    destroy_win(zonessec_ctx.h_win);
    del_panel(zonessec_ctx.h_panel_top[0]);
    destroy_win(zonessec_ctx.h_win_top);
    del_panel(zonessec_ctx.h_panel_bot[0]);
    destroy_win(zonessec_ctx.h_win_bot);
}

static void zones_section_menu_groups(struct vrmr_ctx *vctx,
        struct vrmr_zones *zones, struct vrmr_rules *rules,
        struct vrmr_blocklist *blocklist, char *zonename, char *networkname,
        struct vrmr_regex *reg)
{
    int ch = 0, quit = 0, reload = 0;
    size_t size = 0;
    struct vrmr_zone *zone_ptr = NULL;
    char *vrmr_new_zone_ptr = NULL, *temp_ptr = NULL, *cur_zonename_ptr = NULL;
    ITEM *cur = NULL;
    /* top menu */
    char *key_choices[] = {"F12", "INS", "DEL", "r", "RET", "e", "F10"};
    int key_choices_n = 7;
    char *cmd_choices[] = {gettext("help"), gettext("new"), gettext("del"),
            gettext("rename"), gettext("open"), gettext("edit"),
            gettext("back")};
    int cmd_choices_n = 7;

    /* safety */
    vrmr_fatal_if_null(zonename);
    vrmr_fatal_if_null(networkname);
    vrmr_fatal_if_null(reg);
    vrmr_fatal_if_null(zones);
    vrmr_fatal_if_null(rules);
    vrmr_fatal_if_null(blocklist);

    /* setup */
    zones_section_menu_groups_init(zones, zonename, networkname);

    draw_top_menu(top_win, gettext("Groups"), key_choices_n, key_choices,
            cmd_choices_n, cmd_choices);

    while (quit == 0) {
        if (reload == 1) {
            /* first destroy */
            zones_section_menu_groups_destroy();
            /* and setup again */
            zones_section_menu_groups_init(zones, zonename, networkname);
            /* we are done with reloading */
            reload = 0;
        }

        while (quit == 0 && reload == 0) {
            if (zonessec_ctx.h_top != NULL && !item_visible(zonessec_ctx.h_top))
                show_panel(zonessec_ctx.h_panel_top[0]);
            else
                hide_panel(zonessec_ctx.h_panel_top[0]);

            if (zonessec_ctx.h_bot != NULL && !item_visible(zonessec_ctx.h_bot))
                show_panel(zonessec_ctx.h_panel_bot[0]);
            else
                hide_panel(zonessec_ctx.h_panel_bot[0]);

            update_panels();
            doupdate();

            /* restore the cursor */
            pos_menu_cursor(zonessec_ctx.h_menu);

            ch = wgetch(zonessec_ctx.h_win);
            switch (ch) {
                case 27:
                case KEY_F(10):
                case 'q':
                case 'Q':

                    quit = 1;
                    break;

                case 'r':
                case 'R':

                    cur = current_item(zonessec_ctx.h_menu);
                    if (cur) {
                        size = StrMemLen((char *)item_name(cur)) + 1 +
                               StrMemLen(networkname) + 1 +
                               StrMemLen(zonename) + 1;
                        cur_zonename_ptr = malloc(size);
                        vrmr_fatal_alloc("malloc", cur_zonename_ptr);

                        // create the string
                        (void)strlcpy(
                                cur_zonename_ptr, (char *)item_name(cur), size);
                        (void)strlcat(cur_zonename_ptr, ".", size);
                        (void)strlcat(cur_zonename_ptr, networkname, size);
                        (void)strlcat(cur_zonename_ptr, ".", size);
                        (void)strlcat(cur_zonename_ptr, zonename, size);

                        vrmr_new_zone_ptr = input_box(VRMR_MAX_HOST,
                                gettext("Rename Group"),
                                gettext("Enter the new name of the group"));
                        if (vrmr_new_zone_ptr != NULL) {
                            if (vrmr_validate_zonename(vrmr_new_zone_ptr, 1,
                                        NULL, NULL, NULL, reg->host_part,
                                        VRMR_VERBOSE) == -1) {
                                vrmr_warning(VR_WARN,
                                        gettext("invalid groupname '%s'."),
                                        vrmr_new_zone_ptr);
                            } else {
                                /* get the size */
                                size = StrMemLen(vrmr_new_zone_ptr) + 1 +
                                       StrMemLen(networkname) + 1 +
                                       StrMemLen(zonename) + 1;

                                /* alloc the memory */
                                temp_ptr = malloc(size);
                                vrmr_fatal_alloc("malloc", temp_ptr);

                                /* create the string */
                                (void)strlcpy(
                                        temp_ptr, vrmr_new_zone_ptr, size);
                                (void)strlcat(temp_ptr, ".", size);
                                (void)strlcat(temp_ptr, networkname, size);
                                (void)strlcat(temp_ptr, ".", size);
                                (void)strlcat(temp_ptr, zonename, size);

                                if (vrmr_validate_zonename(temp_ptr, 1, NULL,
                                            NULL, NULL, reg->zonename,
                                            VRMR_VERBOSE) == -1) {
                                    vrmr_warning(VR_WARN,
                                            gettext("invalid groupname '%s'."),
                                            temp_ptr);
                                } else {
                                    if (zones_rename_host_group(vctx, zones,
                                                rules, blocklist,
                                                cur_zonename_ptr, temp_ptr,
                                                VRMR_TYPE_GROUP, reg) == 0) {
                                        /* we have a new host, so reload the
                                         * menu */
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

                case KEY_IC: // insert
                case 'i':
                case 'I':

                    vrmr_new_zone_ptr =
                            input_box(VRMR_MAX_HOST, gettext("New Group"),
                                    gettext("Enter the name of the new group"));
                    if (vrmr_new_zone_ptr != NULL) {
                        if (vrmr_validate_zonename(vrmr_new_zone_ptr, 1, NULL,
                                    NULL, NULL, reg->host_part,
                                    VRMR_VERBOSE) == -1) {
                            vrmr_warning(VR_WARN,
                                    gettext("invalid groupname '%s'."),
                                    vrmr_new_zone_ptr);
                        } else {
                            size = StrMemLen(vrmr_new_zone_ptr) + 1 +
                                   StrMemLen(networkname) + 1 +
                                   StrMemLen(zonename) + 1;
                            temp_ptr = malloc(size);
                            vrmr_fatal_alloc("malloc", temp_ptr);

                            (void)strlcpy(temp_ptr, vrmr_new_zone_ptr, size);
                            (void)strlcat(temp_ptr, ".", size);
                            (void)strlcat(temp_ptr, networkname, size);
                            (void)strlcat(temp_ptr, ".", size);
                            (void)strlcat(temp_ptr, zonename, size);

                            if (vrmr_validate_zonename(temp_ptr, 1, NULL, NULL,
                                        NULL, reg->zonename,
                                        VRMR_VERBOSE) == 0) {
                                if (vrmr_new_zone(vctx, zones, temp_ptr,
                                            VRMR_TYPE_GROUP) >= 0) {
                                    vrmr_audit("%s '%s' %s.", STR_GROUP,
                                            temp_ptr, STR_HAS_BEEN_CREATED);

                                    (void)edit_zone_group(
                                            vctx, zones, temp_ptr);
                                    draw_top_menu(top_win, gettext("Groups"),
                                            key_choices_n, key_choices,
                                            cmd_choices_n, cmd_choices);
                                } else {
                                    vrmr_error(-1, VR_ERR,
                                            gettext("failed to create new "
                                                    "group."));
                                }

                                reload = 1;
                            } else {
                                vrmr_warning(VR_WARN,
                                        gettext("groupname '%s' is invalid."),
                                        temp_ptr);
                            }
                            free(temp_ptr);
                        }

                        free(vrmr_new_zone_ptr);
                    }
                    break;

                case KEY_DC: // delete
                case 'd':
                case 'D':

                    cur = current_item(zonessec_ctx.h_menu);
                    if (cur &&
                            confirm(gettext("Delete"), gettext("This group?"),
                                    vccnf.color_win_note,
                                    vccnf.color_win_note_rev | A_BOLD,
                                    0) == 1) {
                        size = StrMemLen((char *)item_name(cur)) + 1 +
                               StrMemLen(networkname) + 1 +
                               StrMemLen(zonename) + 1;

                        temp_ptr = malloc(size);
                        vrmr_fatal_alloc("malloc", temp_ptr);

                        (void)strlcpy(temp_ptr, (char *)item_name(cur), size);
                        (void)strlcat(temp_ptr, ".", size);
                        (void)strlcat(temp_ptr, networkname, size);
                        (void)strlcat(temp_ptr, ".", size);
                        (void)strlcat(temp_ptr, zonename, size);

                        /* search the zone */
                        zone_ptr = vrmr_search_zonedata(zones, temp_ptr);
                        vrmr_fatal_if_null(zone_ptr);

                        if (zone_ptr->refcnt_blocklist > 0) {
                            vrmr_error(-1, VR_ERR,
                                    gettext("group '%s' is still in the "
                                            "blocklist (%u times)."),
                                    zone_ptr->name, zone_ptr->refcnt_blocklist);
                        } else {
                            /* delete, the memory is freed by
                             * vrmr_delete_zone(). */
                            if (vrmr_delete_zone(vctx, zones, temp_ptr,
                                        zone_ptr->type) < 0) {
                                vrmr_error(-1, VR_ERR,
                                        gettext("deleting group failed."));
                            } else {
                                vrmr_audit("%s '%s' %s.", STR_GROUP, temp_ptr,
                                        STR_HAS_BEEN_DELETED);
                                reload = 1;
                            }
                        }

                        free(temp_ptr);
                    }
                    break;

                case KEY_DOWN:
                    menu_driver(zonessec_ctx.h_menu, REQ_DOWN_ITEM);
                    break;
                case KEY_UP:
                    menu_driver(zonessec_ctx.h_menu, REQ_UP_ITEM);
                    break;
                case KEY_NPAGE:
                    if (menu_driver(zonessec_ctx.h_menu, REQ_SCR_DPAGE) !=
                            E_OK) {
                        while (menu_driver(zonessec_ctx.h_menu,
                                       REQ_DOWN_ITEM) == E_OK)
                            ;
                    }
                    break;
                case KEY_PPAGE:
                    if (menu_driver(zonessec_ctx.h_menu, REQ_SCR_UPAGE) !=
                            E_OK) {
                        while (menu_driver(zonessec_ctx.h_menu, REQ_UP_ITEM) ==
                                E_OK)
                            ;
                    }
                    break;
                case KEY_HOME:
                    menu_driver(zonessec_ctx.h_menu, REQ_FIRST_ITEM); // home
                    break;
                case KEY_END:
                    menu_driver(zonessec_ctx.h_menu, REQ_LAST_ITEM); // end
                    break;

                case 32: // space
                case KEY_RIGHT:
                case 10: // enter
                case 'e':
                case 'E':

                    cur = current_item(zonessec_ctx.h_menu);
                    if (cur) {
                        size = StrMemLen((char *)item_name(cur)) + 1 +
                               StrMemLen(networkname) + 1 +
                               StrMemLen(zonename) + 1;
                        temp_ptr = malloc(size);
                        vrmr_fatal_alloc("malloc", temp_ptr);

                        (void)strlcpy(temp_ptr, (char *)item_name(cur), size);
                        (void)strlcat(temp_ptr, ".", size);
                        (void)strlcat(temp_ptr, networkname, size);
                        (void)strlcat(temp_ptr, ".", size);
                        (void)strlcat(temp_ptr, zonename, size);

                        zone_ptr = vrmr_search_zonedata(zones, temp_ptr);
                        vrmr_fatal_if_null(zone_ptr);

                        (void)edit_zone_group(vctx, zones, zone_ptr->name);
                        draw_top_menu(top_win, gettext("Groups"), key_choices_n,
                                key_choices, cmd_choices_n, cmd_choices);
                        reload = 1;

                        free(temp_ptr);
                    }
                    break;

                case KEY_F(12):
                case 'h':
                case 'H':
                case '?':

                    print_help(":[VUURMUUR:ZONES:GROUPS]:");
                    break;
            }
        }
    }

    zones_section_menu_groups_destroy();

    update_panels();
    doupdate();

    status_print(status_win, gettext("Ready."));
}

/* rename a network or a zone */
static int zones_rename_network_zone(struct vrmr_ctx *vctx,
        struct vrmr_zones *zones, struct vrmr_rules *rules,
        struct vrmr_blocklist *blocklist, char *cur_name_ptr,
        char *new_name_ptr, int type, struct vrmr_regex *reg)
{
    int result = 0;
    struct vrmr_zone *zone_ptr = NULL;
    struct vrmr_rule *rule_ptr = NULL;
    struct vrmr_list_node *d_node = NULL;
    char rules_changed = 0, blocklist_changed = 0;
    char old_name[VRMR_MAX_NET_ZONE] = "", new_host[VRMR_MAX_HOST] = "",
         new_net[VRMR_MAX_NETWORK] = "", vrmr_new_zone[VRMR_MAX_ZONE] = "",
         rule_host[VRMR_MAX_HOST] = "", rule_net[VRMR_MAX_NETWORK] = "",
         rule_zone[VRMR_MAX_ZONE] = "", old_host[VRMR_MAX_HOST] = "",
         old_net[VRMR_MAX_NETWORK] = "", old_zone[VRMR_MAX_ZONE] = "";
    char *blocklist_item = NULL, *new_blocklist_item = NULL;
    size_t size = 0;

    /* safety */
    vrmr_fatal_if_null(cur_name_ptr);
    vrmr_fatal_if_null(new_name_ptr);
    vrmr_fatal_if_null(zones);
    vrmr_fatal_if_null(rules);
    vrmr_fatal_if_null(reg);
    vrmr_fatal_if_null(blocklist);

    vrmr_fatal_if(type != VRMR_TYPE_NETWORK && type != VRMR_TYPE_ZONE);

    /* validate and split the new name */
    if (vrmr_validate_zonename(new_name_ptr, 0, vrmr_new_zone, new_net,
                new_host, reg->zonename, VRMR_VERBOSE) != 0) {
        vrmr_error(-1, VR_INTERR, "invalid name '%s'", new_name_ptr);
        return (-1);
    }
    vrmr_debug(HIGH,
            "new_name_ptr: '%s': host/group '%s', net '%s', zone '%s'.",
            new_name_ptr, new_host, new_net, vrmr_new_zone);

    /* validate and split the old name */
    if (vrmr_validate_zonename(cur_name_ptr, 0, old_zone, old_net, old_host,
                reg->zonename, VRMR_VERBOSE) != 0) {
        vrmr_error(-1, VR_INTERR, "invalid name '%s'", cur_name_ptr);
        return (-1);
    }
    vrmr_debug(HIGH,
            "cur_name_ptr: '%s': host/group '%s', net '%s', zone '%s'.",
            cur_name_ptr, old_host, old_net, old_zone);

    /* store the old name */
    (void)strlcpy(old_name, cur_name_ptr, sizeof(old_name));
    vrmr_debug(HIGH,
            "going to rename network/zone old_name:'%s' to new_name_ptr:'%s'.",
            old_name, new_name_ptr);

    /* rename in the backend */
    result = vctx->zf->rename(vctx->zone_backend, old_name, new_name_ptr, type);
    if (result != 0) {
        return (-1);
    }

    /* search the zone in the list */
    zone_ptr = vrmr_search_zonedata(zones, old_name);
    vrmr_fatal_if_null(zone_ptr);

    (void)strlcpy(zone_ptr->name, new_name_ptr, sizeof(zone_ptr->name));

    if (type == VRMR_TYPE_ZONE) {
        (void)strlcpy(zone_ptr->zone_name, vrmr_new_zone,
                sizeof(zone_ptr->zone_name));
    } else {
        (void)strlcpy(zone_ptr->network_name, new_net,
                sizeof(zone_ptr->network_name));
    }
    zone_ptr = NULL;

    /* check the blocklist */
    for (d_node = blocklist->list.top; d_node; d_node = d_node->next) {
        vrmr_fatal_if_null(d_node->data);
        blocklist_item = d_node->data;

        /* call vrmr_check_ipv4address with the quiet flag */
        if (vrmr_check_ipv4address(NULL, NULL, blocklist_item, 1) != 1) {
            /* search for the name in the zones list */
            if ((zone_ptr = vrmr_search_zonedata(zones, blocklist_item))) {
                if ((type == VRMR_TYPE_NETWORK &&
                            strcmp(zone_ptr->network_name, old_net) == 0) ||
                        (type == VRMR_TYPE_ZONE &&
                                strcmp(zone_ptr->zone_name, old_zone) == 0)) {
                    if (type == VRMR_TYPE_NETWORK)
                        size = StrMemLen(zone_ptr->host_name) + 1 +
                               StrMemLen(new_net) + 1 +
                               StrMemLen(zone_ptr->zone_name) + 1;
                    else
                        size = StrMemLen(zone_ptr->host_name) + 1 +
                               StrMemLen(zone_ptr->network_name) + 1 +
                               StrMemLen(vrmr_new_zone) + 1;

                    new_blocklist_item = malloc(size);
                    vrmr_fatal_alloc("malloc", new_blocklist_item);

                    if (type == VRMR_TYPE_NETWORK) {
                        snprintf(new_blocklist_item, size, "%s.%s.%s",
                                zone_ptr->host_name, new_net,
                                zone_ptr->zone_name);
                    } else {
                        snprintf(new_blocklist_item, size, "%s.%s.%s",
                                zone_ptr->host_name, zone_ptr->network_name,
                                vrmr_new_zone);
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
    if (blocklist_changed == 1) {
        if (vrmr_blocklist_save_list(vctx, &vctx->conf, blocklist) < 0)
            return (-1);
    }

    /* update all hosts, groups, networks */
    for (d_node = zones->list.top; d_node; d_node = d_node->next) {
        vrmr_fatal_if_null(d_node->data);
        zone_ptr = d_node->data;

        /* change full name and the network or zonename */
        if (type == VRMR_TYPE_ZONE) {
            if (strcmp(old_zone, zone_ptr->zone_name) == 0) {
                if (zone_ptr->type == VRMR_TYPE_HOST ||
                        zone_ptr->type == VRMR_TYPE_GROUP) {
                    (void)strlcpy(zone_ptr->zone_name, vrmr_new_zone,
                            sizeof(zone_ptr->zone_name));
                    snprintf(zone_ptr->name, sizeof(zone_ptr->name), "%s.%s.%s",
                            zone_ptr->host_name, zone_ptr->network_name,
                            zone_ptr->zone_name);
                } else if (zone_ptr->type == VRMR_TYPE_NETWORK) {
                    (void)strlcpy(zone_ptr->zone_name, vrmr_new_zone,
                            sizeof(zone_ptr->zone_name));
                    snprintf(zone_ptr->name, sizeof(zone_ptr->name), "%s.%s",
                            zone_ptr->network_name, zone_ptr->zone_name);
                }
            }
        } else if (type == VRMR_TYPE_NETWORK) {
            if (strcmp(old_net, zone_ptr->network_name) == 0) {
                if (zone_ptr->type == VRMR_TYPE_HOST ||
                        zone_ptr->type == VRMR_TYPE_GROUP) {
                    (void)strlcpy(zone_ptr->network_name, new_net,
                            sizeof(zone_ptr->network_name));
                    snprintf(zone_ptr->name, sizeof(zone_ptr->name), "%s.%s.%s",
                            zone_ptr->host_name, zone_ptr->network_name,
                            zone_ptr->zone_name);
                }
            }
        }
    }

    /* update rules */
    for (d_node = rules->list.top; d_node; d_node = d_node->next) {
        vrmr_fatal_if_null(d_node->data);
        rule_ptr = d_node->data;
        vrmr_debug(HIGH, "from: '%s', to: '%s'.", rule_ptr->from, rule_ptr->to);

        /* check for firewall and empty field */
        if (strncasecmp(rule_ptr->from, "firewall", 8) != 0 &&
                strcmp(rule_ptr->from, "") != 0) {
            /* check the fromname */
            if (vrmr_validate_zonename(rule_ptr->from, 0, rule_zone, rule_net,
                        rule_host, reg->zonename, VRMR_VERBOSE) != 0) {
                vrmr_error(-1, VR_INTERR, "invalid name '%s'", rule_ptr->from);
                return (-1);
            }
            vrmr_debug(HIGH,
                    "rule_ptr->from: '%s': host/group '%s', net '%s', zone "
                    "'%s'.",
                    rule_ptr->from, rule_host, rule_net, rule_zone);

            if ((type == VRMR_TYPE_NETWORK && strcmp(rule_net, old_net) == 0 &&
                        strcmp(rule_zone, old_zone) == 0) ||
                    (type == VRMR_TYPE_ZONE &&
                            strcmp(rule_zone, old_zone) == 0)) {
                if (type == VRMR_TYPE_NETWORK) {
                    if (rule_host[0] == '\0') {
                        snprintf(rule_ptr->from, sizeof(rule_ptr->to), "%s.%s",
                                new_net, rule_zone);
                    } else {
                        snprintf(rule_ptr->from, sizeof(rule_ptr->from),
                                "%s.%s.%s", rule_host, new_net, rule_zone);
                    }
                } else {
                    if (rule_host[0] == '\0') {
                        snprintf(rule_ptr->from, sizeof(rule_ptr->to), "%s.%s",
                                rule_net, vrmr_new_zone);
                    } else {
                        snprintf(rule_ptr->from, sizeof(rule_ptr->from),
                                "%s.%s.%s", rule_host, rule_net, vrmr_new_zone);
                    }
                }

                rules_changed = 1;
            } /* end if firewall */
        }

        /* check for firewall and empty field */
        if (strncasecmp(rule_ptr->to, "firewall", 8) != 0 &&
                strcmp(rule_ptr->to, "") != 0) {
            /* check the toname */
            if (vrmr_validate_zonename(rule_ptr->to, 0, rule_zone, rule_net,
                        rule_host, reg->zonename, VRMR_VERBOSE) != 0) {
                vrmr_error(-1, VR_INTERR, "invalid name '%s'", rule_ptr->to);
                return (-1);
            }
            vrmr_debug(HIGH,
                    "rule_ptr->to: '%s': host/group '%s', net '%s', zone '%s'.",
                    rule_ptr->to, rule_host, rule_net, rule_zone);

            if ((type == VRMR_TYPE_NETWORK && strcmp(rule_net, old_net) == 0 &&
                        strcmp(rule_zone, old_zone) == 0) ||
                    (type == VRMR_TYPE_ZONE &&
                            strcmp(rule_zone, old_zone) == 0)) {
                if (type == VRMR_TYPE_NETWORK) {
                    if (rule_host[0] == '\0') {
                        snprintf(rule_ptr->to, sizeof(rule_ptr->to), "%s.%s",
                                new_net, rule_zone);
                    } else {
                        snprintf(rule_ptr->to, sizeof(rule_ptr->to), "%s.%s.%s",
                                rule_host, new_net, rule_zone);
                    }
                } else {
                    if (rule_host[0] == '\0') {
                        snprintf(rule_ptr->to, sizeof(rule_ptr->to), "%s.%s",
                                rule_net, vrmr_new_zone);
                    } else {
                        snprintf(rule_ptr->to, sizeof(rule_ptr->to), "%s.%s.%s",
                                rule_host, rule_net, vrmr_new_zone);
                    }
                }

                rules_changed = 1;
            }
        }
    }
    /* if we have made changes we write the rulesfile */
    if (rules_changed == 1) {
        if (vrmr_rules_save_list(vctx, rules, &vctx->conf) < 0) {
            vrmr_error(-1, VR_ERR, gettext("saving rules failed."));
            return (-1);
        }
    }

    if (type == VRMR_TYPE_ZONE)
        vrmr_audit("%s '%s' %s '%s'.", STR_ZONE, old_name,
                STR_HAS_BEEN_RENAMED_TO, new_name_ptr);
    else
        vrmr_audit("%s '%s' %s '%s'.", STR_NETWORK, old_name,
                STR_HAS_BEEN_RENAMED_TO, new_name_ptr);

    return (0);
}

static int edit_zone_network_interfaces_newiface(struct vrmr_ctx *vctx,
        struct vrmr_interfaces *interfaces, struct vrmr_zone *zone_ptr)
{
    struct vrmr_list_node *d_node = NULL;
    char **choices, *choice_ptr = NULL;
    size_t n_choices = 0, i = 0;
    struct vrmr_interface *iface_ptr = NULL;
    int result = 0;

    /* safety */
    vrmr_fatal_if_null(zone_ptr);
    vrmr_fatal_if_null(interfaces);

    /* check if there are interfaces defined to choose from */
    if ((n_choices = interfaces->list.len) == 0) {
        vrmr_warning(VR_WARN, gettext("no interfaces found. Please define an "
                                      "interface first."));
        return (0);
    }

    /* get some mem */
    choices = calloc(n_choices + 1, VRMR_MAX_INTERFACE);
    vrmr_fatal_alloc("calloc", choices);

    /* load the interfaces */
    for (i = n_choices - 1, d_node = interfaces->list.bot; d_node;
            d_node = d_node->prev) {
        vrmr_fatal_if_null(d_node->data);
        iface_ptr = d_node->data;
        choices[i] = iface_ptr->name;
        i--;
    }

    /* ask the user to select an interface */
    if (!(choice_ptr = selectbox(gettext("New interface"),
                  gettext("Select an interface"), n_choices, choices, 1,
                  NULL))) {
        /* no choice */
        free(choices);
        return (0);
    }

    /* cleanup */
    free(choices);

    /* add the int */
    result = vrmr_zones_network_add_iface(interfaces, zone_ptr, choice_ptr);
    if (result < 0) {
        free(choice_ptr);
        return (-1);
    }

    /* save the new interface list */
    if (vrmr_zones_network_save_interfaces(vctx, zone_ptr) < 0) {
        vrmr_error(-1, VR_ERR, gettext("saving the interfaces failed."));
        return (-1);
    }

    vrmr_audit("%s '%s' %s: %s: '%s'.", STR_INTERFACE, zone_ptr->name,
            STR_HAS_BEEN_CHANGED, STR_AN_IFACE_HAS_BEEN_ADDED, choice_ptr);

    free(choice_ptr);
    return (0);
}

static void edit_zone_network_interfaces_init(struct vrmr_zone *zone_ptr)
{
    struct vrmr_list_node *d_node = NULL;
    struct vrmr_interface *iface_ptr = NULL;
    int i = 0;
    int height = 30,
        width = 34, // max width of interface (32) + box (2)
            startx = 5, starty = 5, max_height = 0;

    /* safety */
    vrmr_fatal_if_null(zone_ptr);
    vrmr_fatal_if(zone_ptr->type != VRMR_TYPE_NETWORK);

    zonessec_ctx.edit_iface.n_items = zone_ptr->InterfaceList.len;

    zonessec_ctx.edit_iface.items = (ITEM **)calloc(
            zonessec_ctx.edit_iface.n_items + 1, sizeof(ITEM *));
    vrmr_fatal_alloc("calloc", zonessec_ctx.edit_iface.items);

    max_height = getmaxy(stdscr);

    height = (int)(zonessec_ctx.edit_iface.n_items +
                   7); // 7 because: 3 above the list, 4 below
    if (height >= max_height - starty - 3) {
        height = max_height - 6;
        starty = 3;
    }

    for (i = 0, d_node = zone_ptr->InterfaceList.top; d_node;
            d_node = d_node->next, i++) {
        vrmr_fatal_if_null(d_node->data);
        iface_ptr = d_node->data;

        /* load all interfaces into memory */
        zonessec_ctx.edit_iface.items[i] = new_item(iface_ptr->name, NULL);
        vrmr_fatal_if_null(zonessec_ctx.edit_iface.items[i]);
    }
    zonessec_ctx.edit_iface.items[zonessec_ctx.edit_iface.n_items] =
            (ITEM *)NULL;

    if (zonessec_ctx.edit_iface.n_items > 0) {
        zonessec_ctx.edit_iface.top = zonessec_ctx.edit_iface.items[0];
        zonessec_ctx.edit_iface.bot =
                zonessec_ctx.edit_iface
                        .items[zonessec_ctx.edit_iface.n_items - 1];
    } else {
        zonessec_ctx.edit_iface.top = NULL;
        zonessec_ctx.edit_iface.bot = NULL;
    }

    /* create the window */
    zonessec_ctx.edit_iface.win = newwin(height, width, starty, startx);
    vrmr_fatal_if_null(zonessec_ctx.edit_iface.win);
    zonessec_ctx.edit_iface.panel[0] = new_panel(zonessec_ctx.edit_iface.win);
    vrmr_fatal_if_null(zonessec_ctx.edit_iface.panel[0]);
    wbkgd(zonessec_ctx.edit_iface.win, vccnf.color_win);
    keypad(zonessec_ctx.edit_iface.win, TRUE);
    wrefresh(zonessec_ctx.edit_iface.win);

    zonessec_ctx.edit_iface.menu =
            new_menu((ITEM **)zonessec_ctx.edit_iface.items);
    vrmr_fatal_if_null(zonessec_ctx.edit_iface.menu);
    set_menu_win(zonessec_ctx.edit_iface.menu, zonessec_ctx.edit_iface.win);
    set_menu_sub(zonessec_ctx.edit_iface.menu,
            derwin(zonessec_ctx.edit_iface.win, height - 6, width - 2, 3, 1));
    set_menu_format(zonessec_ctx.edit_iface.menu, height - 7, 1);

    box(zonessec_ctx.edit_iface.win, 0, 0);
    print_in_middle(zonessec_ctx.edit_iface.win, 1, 0, width,
            gettext("Interfaces"), vccnf.color_win);
    mvwaddch(zonessec_ctx.edit_iface.win, 2, 0, ACS_LTEE);
    mvwhline(zonessec_ctx.edit_iface.win, 2, 1, ACS_HLINE, width - 2);
    mvwaddch(zonessec_ctx.edit_iface.win, 2, width - 1, ACS_RTEE);
    set_menu_back(zonessec_ctx.edit_iface.menu, vccnf.color_win);
    set_menu_fore(zonessec_ctx.edit_iface.menu, vccnf.color_win_rev);
    post_menu(zonessec_ctx.edit_iface.menu);

    mvwaddch(zonessec_ctx.edit_iface.win, height - 4, 0, ACS_LTEE);
    mvwhline(zonessec_ctx.edit_iface.win, height - 4, 1, ACS_HLINE, width - 2);
    mvwaddch(zonessec_ctx.edit_iface.win, height - 4, width - 1, ACS_RTEE);

    mvwprintw(zonessec_ctx.edit_iface.win, height - 3, 2, "<INS> %s", STR_NEW);
    mvwprintw(
            zonessec_ctx.edit_iface.win, height - 2, 2, "<DEL> %s", STR_REMOVE);

    /* create the top and bottom fields */
    zonessec_ctx.edit_iface.win_top = newwin(1, 6, starty + 2, width - 6);
    vrmr_fatal_if_null(zonessec_ctx.edit_iface.win_top);
    wbkgd(zonessec_ctx.edit_iface.win_top, vccnf.color_win);
    zonessec_ctx.edit_iface.panel_top[0] =
            new_panel(zonessec_ctx.edit_iface.win_top);
    /* TRANSLATORS: max 4 chars */
    wprintw(zonessec_ctx.edit_iface.win_top, "(%s)", gettext("more"));
    hide_panel(zonessec_ctx.edit_iface.panel_top[0]);

    zonessec_ctx.edit_iface.win_bot =
            newwin(1, 6, starty + height - 4, width - 6);
    vrmr_fatal_if_null(zonessec_ctx.edit_iface.win_bot);
    wbkgd(zonessec_ctx.edit_iface.win_bot, vccnf.color_win);
    zonessec_ctx.edit_iface.panel_bot[0] =
            new_panel(zonessec_ctx.edit_iface.win_bot);
    /* TRANSLATORS: max 4 chars */
    wprintw(zonessec_ctx.edit_iface.win_bot, "(%s)", gettext("more"));
    hide_panel(zonessec_ctx.edit_iface.panel_bot[0]);

    update_panels();
    doupdate();
}

static void edit_zone_network_interfaces_destroy(void)
{
    size_t i = 0;

    /* un post form and free the memory */
    unpost_menu(zonessec_ctx.edit_iface.menu);
    free_menu(zonessec_ctx.edit_iface.menu);
    for (i = 0; i < zonessec_ctx.edit_iface.n_items; i++) {
        free_item(zonessec_ctx.edit_iface.items[i]);
    }
    free(zonessec_ctx.edit_iface.items);
    del_panel(zonessec_ctx.edit_iface.panel[0]);
    del_panel(zonessec_ctx.edit_iface.panel_top[0]);
    del_panel(zonessec_ctx.edit_iface.panel_bot[0]);
    destroy_win(zonessec_ctx.edit_iface.win);
}

static void edit_zone_network_interfaces(struct vrmr_ctx *vctx,
        struct vrmr_interfaces *interfaces, struct vrmr_zone *zone_ptr)
{
    int quit = 0, reload = 0, ch;
    ITEM *cur = NULL;
    char save_iface[VRMR_MAX_INTERFACE] = "";

    /* safety */
    vrmr_fatal_if_null(zone_ptr);
    vrmr_fatal_if_null(interfaces);

    edit_zone_network_interfaces_init(zone_ptr);

    while (quit == 0) {
        if (reload == 1) {
            edit_zone_network_interfaces_destroy();
            edit_zone_network_interfaces_init(zone_ptr);
            reload = 0;
        }

        while (quit == 0 && reload == 0) {
            if (zonessec_ctx.edit_iface.top != NULL &&
                    !item_visible(zonessec_ctx.edit_iface.top))
                show_panel(zonessec_ctx.edit_iface.panel_top[0]);
            else
                hide_panel(zonessec_ctx.edit_iface.panel_top[0]);

            if (zonessec_ctx.edit_iface.bot != NULL &&
                    !item_visible(zonessec_ctx.edit_iface.bot))
                show_panel(zonessec_ctx.edit_iface.panel_bot[0]);
            else
                hide_panel(zonessec_ctx.edit_iface.panel_bot[0]);

            update_panels();
            doupdate();

            /* restore the cursor */
            pos_menu_cursor(zonessec_ctx.edit_iface.menu);

            ch = wgetch(zonessec_ctx.edit_iface.win);
            switch (ch) {
                case 27:
                case KEY_LEFT:
                case 'q':
                case 'Q':
                case KEY_F(10): // quit
                    quit = 1;
                    break;

                case KEY_IC:
                case 'i':
                case 'I':

                    (void)edit_zone_network_interfaces_newiface(
                            vctx, interfaces, zone_ptr);
                    reload = 1;
                    break;

                case KEY_DC:
                case 'd':
                case 'D':

                    cur = current_item(zonessec_ctx.edit_iface.menu);
                    if (cur) {
                        (void)strlcpy(save_iface, (char *)item_name(cur),
                                sizeof(save_iface));

                        if (vrmr_zones_network_rem_iface(vctx, zone_ptr,
                                    (char *)item_name(cur)) < 0) {
                            quit = 1;
                        } else {
                            vrmr_audit("%s '%s' %s: %s '%s'.", STR_NETWORK,
                                    zone_ptr->name, STR_HAS_BEEN_CHANGED,
                                    STR_AN_IFACE_HAS_BEEN_REMOVED, save_iface);
                        }
                        reload = 1;
                    }
                    break;

                case KEY_DOWN:
                    menu_driver(zonessec_ctx.edit_iface.menu, REQ_DOWN_ITEM);
                    break;
                case KEY_UP:
                    menu_driver(zonessec_ctx.edit_iface.menu, REQ_UP_ITEM);
                    break;
                case KEY_NPAGE:
                    if (menu_driver(zonessec_ctx.edit_iface.menu,
                                REQ_SCR_DPAGE) != E_OK) {
                        while (menu_driver(zonessec_ctx.edit_iface.menu,
                                       REQ_DOWN_ITEM) == E_OK)
                            ;
                    }
                    break;
                case KEY_PPAGE:
                    if (menu_driver(zonessec_ctx.edit_iface.menu,
                                REQ_SCR_UPAGE) != E_OK) {
                        while (menu_driver(zonessec_ctx.edit_iface.menu,
                                       REQ_UP_ITEM) == E_OK)
                            ;
                    }
                    break;
                case KEY_HOME:
                    menu_driver(zonessec_ctx.edit_iface.menu,
                            REQ_FIRST_ITEM); // home
                    break;
                case KEY_END:
                    menu_driver(zonessec_ctx.edit_iface.menu,
                            REQ_LAST_ITEM); // end
                    break;
            }
        }
    }

    edit_zone_network_interfaces_destroy();
}

struct {
    FIELD *activefld, *activelabelfld,

            *networkfld, *networklabelfld,

            *netmaskfld, *netmasklabelfld,

            *network6fld, *network6labelfld,

            *cidr6fld, *cidr6labelfld,

            *commentfld, *commentlabelfld,

            /* anti spoofing */
            *loopbackfld, *loopbacklabelfld, *loopbackbracketsfld,

            *classafld, *classalabelfld, *classabracketsfld,

            *classbfld, *classblabelfld, *classbbracketsfld,

            *classcfld, *classclabelfld, *classcbracketsfld,

            *classdfld, *classdlabelfld, *classdbracketsfld,

            *classefld, *classelabelfld, *classebracketsfld,

            *testnetfld, *testnetlabelfld, *testnetbracketsfld,

            *lnklocnetfld, *lnklocnetlabelfld, *lnklocnetbracketsfld,

            *iana08fld, *iana08labelfld, *iana08bracketsfld,

            *brdsrcfld, *brdsrclabelfld, *brdsrcbracketsfld,

            *brddstfld, *brddstlabelfld, *brddstbracketsfld,

            *dhcpsrvfld, *dhcpsrvlabelfld, *dhcpsrvbracketsfld,

            *dhcpclifld, *dhcpclilabelfld, *dhcpclibracketsfld,

            *warningfld; /* field for the "warning no interfaces" message */

} NetworkSec;

/*  interfaces_save_protectrules

    Save the protectrules to the backend.

    Returncodes:
         0: ok
        -1: error
*/
static int zones_network_save_protectrules(
        struct vrmr_ctx *vctx, struct vrmr_zone *network_ptr)
{
    struct vrmr_list_node *d_node = NULL;
    struct vrmr_rule *rule_ptr = NULL;
    char rule_str[VRMR_MAX_RULE_LENGTH] = "";

    /* safety */
    vrmr_fatal_if_null(network_ptr);

    /* write to backend */
    if (network_ptr->ProtectList.len == 0) {
        /* clear */
        if (vctx->zf->tell(vctx->zone_backend, network_ptr->name, "RULE", "", 1,
                    VRMR_TYPE_NETWORK) < 0) {
            vrmr_error(-1, VR_ERR, gettext("saving to backend failed"));
            return (-1);
        }
    } else {
        /* write to backend */
        for (d_node = network_ptr->ProtectList.top; d_node;
                d_node = d_node->next) {
            vrmr_fatal_if_null(d_node->data);
            rule_ptr = d_node->data;

            if (rule_ptr->action == VRMR_AT_PROTECT)
                snprintf(rule_str, sizeof(rule_str),
                        "protect against %s from %s", rule_ptr->danger,
                        rule_ptr->source);
            else
                snprintf(rule_str, sizeof(rule_str), "%s %s",
                        vrmr_rules_itoaction(rule_ptr->action),
                        rule_ptr->service);

            /* the first one needs to be in overwrite mode */
            if (d_node == network_ptr->ProtectList.top) {
                /* save to backend */
                if (vctx->zf->tell(vctx->zone_backend, network_ptr->name,
                            "RULE", rule_str, 1, VRMR_TYPE_NETWORK) < 0) {
                    vrmr_error(-1, VR_ERR, gettext("saving to backend failed"));
                    return (-1);
                }
            } else {
                /* save to backend */
                if (vctx->zf->tell(vctx->zone_backend, network_ptr->name,
                            "RULE", rule_str, 0, VRMR_TYPE_NETWORK) < 0) {
                    vrmr_error(-1, VR_ERR, gettext("saving to backend failed"));
                    return (-1);
                }
            }
        }
    }
    return (0);
}

/*
    returncodes:
        -1: error
         0: ok
*/
static int edit_zone_network_save_protectrules(
        struct vrmr_ctx *vctx, struct vrmr_zone *network_ptr)
{
    struct vrmr_rule *rule_ptr = NULL;

    /* safety */
    vrmr_fatal_if_null(network_ptr);

    /* cleanup the existing list */
    vrmr_list_cleanup(&network_ptr->ProtectList);

    if (field_buffer(NetworkSec.dhcpsrvfld, 0)[0] == 'X') {
        rule_ptr =
                rules_create_protect_rule("accept", NULL, "dhcp-server", NULL);
        vrmr_fatal_if_null(rule_ptr);
        vrmr_fatal_if(
                vrmr_list_append(&network_ptr->ProtectList, rule_ptr) == NULL);
    }

    if (field_buffer(NetworkSec.dhcpclifld, 0)[0] == 'X') {
        rule_ptr =
                rules_create_protect_rule("accept", NULL, "dhcp-client", NULL);
        vrmr_fatal_if_null(rule_ptr);
        vrmr_fatal_if(
                vrmr_list_append(&network_ptr->ProtectList, rule_ptr) == NULL);
    }

    if (field_buffer(NetworkSec.loopbackfld, 0)[0] == 'X') {
        rule_ptr = rules_create_protect_rule(
                "protect", network_ptr->name, "spoofing", "loopback");
        vrmr_fatal_if_null(rule_ptr);
        vrmr_fatal_if(
                vrmr_list_append(&network_ptr->ProtectList, rule_ptr) == NULL);
    }

    if (field_buffer(NetworkSec.classafld, 0)[0] == 'X') {
        rule_ptr = rules_create_protect_rule(
                "protect", network_ptr->name, "spoofing", "class-a");
        vrmr_fatal_if_null(rule_ptr);
        vrmr_fatal_if(
                vrmr_list_append(&network_ptr->ProtectList, rule_ptr) == NULL);
    }

    if (field_buffer(NetworkSec.classbfld, 0)[0] == 'X') {
        rule_ptr = rules_create_protect_rule(
                "protect", network_ptr->name, "spoofing", "class-b");
        vrmr_fatal_if_null(rule_ptr);
        vrmr_fatal_if(
                vrmr_list_append(&network_ptr->ProtectList, rule_ptr) == NULL);
    }

    if (field_buffer(NetworkSec.classcfld, 0)[0] == 'X') {
        rule_ptr = rules_create_protect_rule(
                "protect", network_ptr->name, "spoofing", "class-c");
        vrmr_fatal_if_null(rule_ptr);
        vrmr_fatal_if(
                vrmr_list_append(&network_ptr->ProtectList, rule_ptr) == NULL);
    }

    if (field_buffer(NetworkSec.classdfld, 0)[0] == 'X') {
        rule_ptr = rules_create_protect_rule(
                "protect", network_ptr->name, "spoofing", "class-d");
        vrmr_fatal_if_null(rule_ptr);
        vrmr_fatal_if(
                vrmr_list_append(&network_ptr->ProtectList, rule_ptr) == NULL);
    }

    if (field_buffer(NetworkSec.classefld, 0)[0] == 'X') {
        rule_ptr = rules_create_protect_rule(
                "protect", network_ptr->name, "spoofing", "class-e");
        vrmr_fatal_if_null(rule_ptr);
        vrmr_fatal_if(
                vrmr_list_append(&network_ptr->ProtectList, rule_ptr) == NULL);
    }

    if (field_buffer(NetworkSec.testnetfld, 0)[0] == 'X') {
        rule_ptr = rules_create_protect_rule(
                "protect", network_ptr->name, "spoofing", "test-net");
        vrmr_fatal_if_null(rule_ptr);
        vrmr_fatal_if(
                vrmr_list_append(&network_ptr->ProtectList, rule_ptr) == NULL);
    }

    if (field_buffer(NetworkSec.lnklocnetfld, 0)[0] == 'X') {
        rule_ptr = rules_create_protect_rule(
                "protect", network_ptr->name, "spoofing", "lnk-loc-net");
        vrmr_fatal_if_null(rule_ptr);
        vrmr_fatal_if(
                vrmr_list_append(&network_ptr->ProtectList, rule_ptr) == NULL);
    }

    if (field_buffer(NetworkSec.iana08fld, 0)[0] == 'X') {
        rule_ptr = rules_create_protect_rule(
                "protect", network_ptr->name, "spoofing", "iana-0/8");
        vrmr_fatal_if_null(rule_ptr);
        vrmr_fatal_if(
                vrmr_list_append(&network_ptr->ProtectList, rule_ptr) == NULL);
    }

    if (field_buffer(NetworkSec.brdsrcfld, 0)[0] == 'X') {
        rule_ptr = rules_create_protect_rule(
                "protect", network_ptr->name, "spoofing", "brdcst-src");
        vrmr_fatal_if_null(rule_ptr);
        vrmr_fatal_if(
                vrmr_list_append(&network_ptr->ProtectList, rule_ptr) == NULL);
    }

    if (field_buffer(NetworkSec.brddstfld, 0)[0] == 'X') {
        rule_ptr = rules_create_protect_rule(
                "protect", network_ptr->name, "spoofing", "brdcst-dst");
        vrmr_fatal_if_null(rule_ptr);
        vrmr_fatal_if(
                vrmr_list_append(&network_ptr->ProtectList, rule_ptr) == NULL);
    }

    /* now let try to write this to the backend */
    if (zones_network_save_protectrules(vctx, network_ptr) < 0) {
        vrmr_error(-1, VR_ERR, gettext("saving to backend failed"));
        return (-1);
    }

    return (0);
}

static void edit_zone_network_init(struct vrmr_ctx *vctx,
        struct vrmr_zones *zones, char *name, int height, int width, int starty,
        int startx, struct vrmr_zone *zone_ptr)
{
    int rows, cols, comment_y = 0, comment_x = 0;
    size_t i = 0, field_num = 0;

    /* safety */
    vrmr_fatal_if_null(name);
    vrmr_fatal_if_null(zone_ptr);
    vrmr_fatal_if_null(zones);

    zonessec_ctx.edit_zone.n_fields = 52;
    zonessec_ctx.edit_zone.fields = (FIELD **)calloc(
            zonessec_ctx.edit_zone.n_fields + 1, sizeof(FIELD *));
    vrmr_fatal_if_null(zonessec_ctx.edit_zone.fields);

    /* active toggle */
    NetworkSec.activelabelfld = (zonessec_ctx.edit_zone.fields[field_num] =
                                         new_field_wrap(1, 16, 2, 0, 0, 0));
    field_num++;
    set_field_buffer_wrap(NetworkSec.activelabelfld, 0, gettext("Active"));
    field_opts_off(NetworkSec.activelabelfld, O_AUTOSKIP | O_ACTIVE);

    NetworkSec.activefld = (zonessec_ctx.edit_zone.fields[field_num] =
                                    new_field_wrap(1, 3, 3, 1, 0, 0));
    field_num++;
    set_field_buffer_wrap(
            NetworkSec.activefld, 0, zone_ptr->active ? STR_YES : STR_NO);

    /* network */
    NetworkSec.networklabelfld = (zonessec_ctx.edit_zone.fields[field_num] =
                                          new_field_wrap(1, 8, 5, 0, 0, 0));
    field_num++;
    set_field_buffer_wrap(NetworkSec.networklabelfld, 0, gettext("Network"));
    field_opts_off(NetworkSec.networklabelfld, O_AUTOSKIP | O_ACTIVE);

    NetworkSec.networkfld = (zonessec_ctx.edit_zone.fields[field_num] =
                                     new_field_wrap(1, 16, 6, 1, 0, 0));
    set_field_type(NetworkSec.networkfld, TYPE_IPV4);
    field_num++;
    set_field_buffer_wrap(NetworkSec.networkfld, 0, zone_ptr->ipv4.network);

    /* network */
    NetworkSec.netmasklabelfld = (zonessec_ctx.edit_zone.fields[field_num] =
                                          new_field_wrap(1, 8, 7, 0, 0, 0));
    field_num++;
    set_field_buffer_wrap(NetworkSec.netmasklabelfld, 0, gettext("Netmask"));
    field_opts_off(NetworkSec.netmasklabelfld, O_AUTOSKIP | O_ACTIVE);

    NetworkSec.netmaskfld = (zonessec_ctx.edit_zone.fields[field_num] =
                                     new_field_wrap(1, 16, 8, 1, 0, 0));
    set_field_type(NetworkSec.netmaskfld, TYPE_IPV4);
    field_num++;
    set_field_buffer_wrap(NetworkSec.netmaskfld, 0, zone_ptr->ipv4.netmask);

    /* network */
    NetworkSec.network6labelfld = (zonessec_ctx.edit_zone.fields[field_num] =
                                           new_field_wrap(1, 12, 9, 0, 0, 0));
    field_num++;
#ifdef IPV6_ENABLED
    set_field_buffer_wrap(
            NetworkSec.network6labelfld, 0, gettext("IPv6 Network"));
#endif
    field_opts_off(NetworkSec.network6labelfld, O_AUTOSKIP | O_ACTIVE);

    NetworkSec.network6fld =
            (zonessec_ctx.edit_zone.fields[field_num++] = new_field_wrap(
                     1, VRMR_MAX_IPV6_ADDR_LEN, 10, 1, 0, 0));
    // set_field_type(NetworkSec.networkfld, TYPE_IPV4);
#ifdef IPV6_ENABLED
    set_field_buffer_wrap(NetworkSec.network6fld, 0, zone_ptr->ipv6.net6);
#endif

    /* cidr */
    NetworkSec.cidr6labelfld = (zonessec_ctx.edit_zone.fields[field_num++] =
                                        new_field_wrap(1, 9, 11, 0, 0, 0));
#ifdef IPV6_ENABLED
    set_field_buffer_wrap(NetworkSec.cidr6labelfld, 0, gettext("IPv6 CIDR"));
#endif
    field_opts_off(NetworkSec.cidr6labelfld, O_AUTOSKIP | O_ACTIVE);

    NetworkSec.cidr6fld = (zonessec_ctx.edit_zone.fields[field_num++] =
                                   new_field_wrap(1, 3, 12, 1, 0, 0));
#ifdef IPV6_ENABLED
    char cidr[3] = "";
    snprintf(cidr, sizeof(cidr), "%d", zone_ptr->ipv6.cidr6);
    set_field_buffer_wrap(NetworkSec.cidr6fld, 0, cidr);
#endif

    /* anti-spoof loopback */
    NetworkSec.loopbacklabelfld = (zonessec_ctx.edit_zone.fields[field_num] =
                                           new_field_wrap(1, 8, 4, 20, 0, 0));
    field_num++;
    set_field_buffer_wrap(NetworkSec.loopbacklabelfld, 0, gettext("Loopback"));
    field_opts_off(NetworkSec.loopbacklabelfld, O_AUTOSKIP | O_ACTIVE);

    NetworkSec.loopbackbracketsfld =
            (zonessec_ctx.edit_zone.fields[field_num] =
                            new_field_wrap(1, 3, 4, 32, 0, 0));
    field_num++;
    set_field_buffer_wrap(NetworkSec.loopbackbracketsfld, 0, "[ ]");
    field_opts_off(NetworkSec.loopbackbracketsfld, O_AUTOSKIP | O_ACTIVE);

    NetworkSec.loopbackfld = (zonessec_ctx.edit_zone.fields[field_num] =
                                      new_field_wrap(1, 1, 4, 33, 0, 0));
    field_num++;
    set_field_buffer_wrap(NetworkSec.loopbackfld, 0,
            protectrule_loaded(
                    &zone_ptr->ProtectList, "protect", "spoofing", "loopback")
                    ? "X"
                    : " ");

    /* anti-spoof class-a */
    NetworkSec.classalabelfld = (zonessec_ctx.edit_zone.fields[field_num] =
                                         new_field_wrap(1, 8, 5, 20, 0, 0));
    field_num++;
    set_field_buffer_wrap(NetworkSec.classalabelfld, 0, gettext("Class A"));
    field_opts_off(NetworkSec.classalabelfld, O_AUTOSKIP | O_ACTIVE);

    NetworkSec.classabracketsfld = (zonessec_ctx.edit_zone.fields[field_num] =
                                            new_field_wrap(1, 3, 5, 32, 0, 0));
    field_num++;
    set_field_buffer_wrap(NetworkSec.classabracketsfld, 0, "[ ]");
    field_opts_off(NetworkSec.classabracketsfld, O_AUTOSKIP | O_ACTIVE);

    NetworkSec.classafld = (zonessec_ctx.edit_zone.fields[field_num] =
                                    new_field_wrap(1, 1, 5, 33, 0, 0));
    field_num++;
    set_field_buffer_wrap(NetworkSec.classafld, 0,
            protectrule_loaded(
                    &zone_ptr->ProtectList, "protect", "spoofing", "class-a")
                    ? "X"
                    : " ");

    /* anti-spoof class-b */
    NetworkSec.classblabelfld = (zonessec_ctx.edit_zone.fields[field_num] =
                                         new_field_wrap(1, 8, 6, 20, 0, 0));
    field_num++;
    set_field_buffer_wrap(NetworkSec.classblabelfld, 0, gettext("Class B"));
    field_opts_off(NetworkSec.classblabelfld, O_AUTOSKIP | O_ACTIVE);

    NetworkSec.classbbracketsfld = (zonessec_ctx.edit_zone.fields[field_num] =
                                            new_field_wrap(1, 3, 6, 32, 0, 0));
    field_num++;
    set_field_buffer_wrap(NetworkSec.classbbracketsfld, 0, "[ ]");
    field_opts_off(NetworkSec.classbbracketsfld, O_AUTOSKIP | O_ACTIVE);

    NetworkSec.classbfld = (zonessec_ctx.edit_zone.fields[field_num] =
                                    new_field_wrap(1, 1, 6, 33, 0, 0));
    field_num++;
    set_field_buffer_wrap(NetworkSec.classbfld, 0,
            protectrule_loaded(
                    &zone_ptr->ProtectList, "protect", "spoofing", "class-b")
                    ? "X"
                    : " ");

    /* anti-spoof class-c */
    NetworkSec.classclabelfld = (zonessec_ctx.edit_zone.fields[field_num] =
                                         new_field_wrap(1, 8, 7, 20, 0, 0));
    field_num++;
    set_field_buffer_wrap(NetworkSec.classclabelfld, 0, gettext("Class C"));
    field_opts_off(NetworkSec.classclabelfld, O_AUTOSKIP | O_ACTIVE);

    NetworkSec.classcbracketsfld = (zonessec_ctx.edit_zone.fields[field_num] =
                                            new_field_wrap(1, 3, 7, 32, 0, 0));
    field_num++;
    set_field_buffer_wrap(NetworkSec.classcbracketsfld, 0, "[ ]");
    field_opts_off(NetworkSec.classcbracketsfld, O_AUTOSKIP | O_ACTIVE);

    NetworkSec.classcfld = (zonessec_ctx.edit_zone.fields[field_num] =
                                    new_field_wrap(1, 1, 7, 33, 0, 0));
    field_num++;
    set_field_buffer_wrap(NetworkSec.classcfld, 0,
            protectrule_loaded(
                    &zone_ptr->ProtectList, "protect", "spoofing", "class-c")
                    ? "X"
                    : " ");

    /* anti-spoof class-d */
    NetworkSec.classdlabelfld = (zonessec_ctx.edit_zone.fields[field_num] =
                                         new_field_wrap(1, 8, 8, 20, 0, 0));
    field_num++;
    set_field_buffer_wrap(NetworkSec.classdlabelfld, 0, gettext("Class D"));
    field_opts_off(NetworkSec.classdlabelfld, O_AUTOSKIP | O_ACTIVE);

    NetworkSec.classdbracketsfld = (zonessec_ctx.edit_zone.fields[field_num] =
                                            new_field_wrap(1, 3, 8, 32, 0, 0));
    field_num++;
    set_field_buffer_wrap(NetworkSec.classdbracketsfld, 0, "[ ]");
    field_opts_off(NetworkSec.classdbracketsfld, O_AUTOSKIP | O_ACTIVE);

    NetworkSec.classdfld = (zonessec_ctx.edit_zone.fields[field_num] =
                                    new_field_wrap(1, 1, 8, 33, 0, 0));
    field_num++;
    set_field_buffer_wrap(NetworkSec.classdfld, 0,
            protectrule_loaded(
                    &zone_ptr->ProtectList, "protect", "spoofing", "class-d")
                    ? "X"
                    : " ");

    /* anti-spoof class-e */
    NetworkSec.classelabelfld = (zonessec_ctx.edit_zone.fields[field_num] =
                                         new_field_wrap(1, 8, 9, 20, 0, 0));
    field_num++;
    set_field_buffer_wrap(NetworkSec.classelabelfld, 0, gettext("Class E"));
    field_opts_off(NetworkSec.classelabelfld, O_AUTOSKIP | O_ACTIVE);

    NetworkSec.classebracketsfld = (zonessec_ctx.edit_zone.fields[field_num] =
                                            new_field_wrap(1, 3, 9, 32, 0, 0));
    field_num++;
    set_field_buffer_wrap(NetworkSec.classebracketsfld, 0, "[ ]");
    field_opts_off(NetworkSec.classebracketsfld, O_AUTOSKIP | O_ACTIVE);

    NetworkSec.classefld = (zonessec_ctx.edit_zone.fields[field_num] =
                                    new_field_wrap(1, 1, 9, 33, 0, 0));
    field_num++;
    set_field_buffer_wrap(NetworkSec.classefld, 0,
            protectrule_loaded(
                    &zone_ptr->ProtectList, "protect", "spoofing", "class-e")
                    ? "X"
                    : " ");

    /* anti-spoof testnet */
    NetworkSec.testnetlabelfld = (zonessec_ctx.edit_zone.fields[field_num] =
                                          new_field_wrap(1, 14, 4, 37, 0, 0));
    field_num++;
    set_field_buffer_wrap(NetworkSec.testnetlabelfld, 0, gettext("Test-net"));
    field_opts_off(NetworkSec.testnetlabelfld, O_AUTOSKIP | O_ACTIVE);

    NetworkSec.testnetbracketsfld = (zonessec_ctx.edit_zone.fields[field_num] =
                                             new_field_wrap(1, 3, 4, 52, 0, 0));
    field_num++;
    set_field_buffer_wrap(NetworkSec.testnetbracketsfld, 0, "[ ]");
    field_opts_off(NetworkSec.testnetbracketsfld, O_AUTOSKIP | O_ACTIVE);

    NetworkSec.testnetfld = (zonessec_ctx.edit_zone.fields[field_num] =
                                     new_field_wrap(1, 1, 4, 53, 0, 0));
    field_num++;
    set_field_buffer_wrap(NetworkSec.testnetfld, 0,
            protectrule_loaded(
                    &zone_ptr->ProtectList, "protect", "spoofing", "test-net")
                    ? "X"
                    : " ");

    /* anti-spoof link local net */
    NetworkSec.lnklocnetlabelfld = (zonessec_ctx.edit_zone.fields[field_num] =
                                            new_field_wrap(1, 14, 5, 37, 0, 0));
    field_num++;
    set_field_buffer_wrap(
            NetworkSec.lnklocnetlabelfld, 0, gettext("Link local net"));
    field_opts_off(NetworkSec.lnklocnetlabelfld, O_AUTOSKIP | O_ACTIVE);

    NetworkSec.lnklocnetbracketsfld =
            (zonessec_ctx.edit_zone.fields[field_num] =
                            new_field_wrap(1, 3, 5, 52, 0, 0));
    field_num++;
    set_field_buffer_wrap(NetworkSec.lnklocnetbracketsfld, 0, "[ ]");
    field_opts_off(NetworkSec.lnklocnetbracketsfld, O_AUTOSKIP | O_ACTIVE);

    NetworkSec.lnklocnetfld = (zonessec_ctx.edit_zone.fields[field_num] =
                                       new_field_wrap(1, 1, 5, 53, 0, 0));
    field_num++;
    set_field_buffer_wrap(NetworkSec.lnklocnetfld, 0,
            protectrule_loaded(&zone_ptr->ProtectList, "protect", "spoofing",
                    "lnk-loc-net")
                    ? "X"
                    : " ");

    /* anti-spoof link local net */
    NetworkSec.iana08labelfld = (zonessec_ctx.edit_zone.fields[field_num] =
                                         new_field_wrap(1, 14, 6, 37, 0, 0));
    field_num++;
    set_field_buffer_wrap(
            NetworkSec.iana08labelfld, 0, gettext("0.0.0.0/8 res."));
    field_opts_off(NetworkSec.iana08labelfld, O_AUTOSKIP | O_ACTIVE);

    NetworkSec.iana08bracketsfld = (zonessec_ctx.edit_zone.fields[field_num] =
                                            new_field_wrap(1, 3, 6, 52, 0, 0));
    field_num++;
    set_field_buffer_wrap(NetworkSec.iana08bracketsfld, 0, "[ ]");
    field_opts_off(NetworkSec.iana08bracketsfld, O_AUTOSKIP | O_ACTIVE);

    NetworkSec.iana08fld = (zonessec_ctx.edit_zone.fields[field_num] =
                                    new_field_wrap(1, 1, 6, 53, 0, 0));
    field_num++;
    set_field_buffer_wrap(NetworkSec.iana08fld, 0,
            protectrule_loaded(
                    &zone_ptr->ProtectList, "protect", "spoofing", "iana-0/8")
                    ? "X"
                    : " ");

    /* anti-spoof link local net */
    NetworkSec.brdsrclabelfld = (zonessec_ctx.edit_zone.fields[field_num] =
                                         new_field_wrap(1, 14, 7, 37, 0, 0));
    field_num++;
    set_field_buffer_wrap(
            NetworkSec.brdsrclabelfld, 0, gettext("Broadcast src."));
    field_opts_off(NetworkSec.brdsrclabelfld, O_AUTOSKIP | O_ACTIVE);

    NetworkSec.brdsrcbracketsfld = (zonessec_ctx.edit_zone.fields[field_num] =
                                            new_field_wrap(1, 3, 7, 52, 0, 0));
    field_num++;
    set_field_buffer_wrap(NetworkSec.brdsrcbracketsfld, 0, "[ ]");
    field_opts_off(NetworkSec.brdsrcbracketsfld, O_AUTOSKIP | O_ACTIVE);

    NetworkSec.brdsrcfld = (zonessec_ctx.edit_zone.fields[field_num] =
                                    new_field_wrap(1, 1, 7, 53, 0, 0));
    field_num++;
    set_field_buffer_wrap(NetworkSec.brdsrcfld, 0,
            protectrule_loaded(
                    &zone_ptr->ProtectList, "protect", "spoofing", "brdcst-src")
                    ? "X"
                    : " ");

    /* anti-spoof link local net */
    NetworkSec.brddstlabelfld = (zonessec_ctx.edit_zone.fields[field_num] =
                                         new_field_wrap(1, 14, 8, 37, 0, 0));
    field_num++;
    set_field_buffer_wrap(
            NetworkSec.brddstlabelfld, 0, gettext("Broadcast dst."));
    field_opts_off(NetworkSec.brddstlabelfld, O_AUTOSKIP | O_ACTIVE);

    NetworkSec.brddstbracketsfld = (zonessec_ctx.edit_zone.fields[field_num] =
                                            new_field_wrap(1, 3, 8, 52, 0, 0));
    field_num++;
    set_field_buffer_wrap(NetworkSec.brddstbracketsfld, 0, "[ ]");
    field_opts_off(NetworkSec.brddstbracketsfld, O_AUTOSKIP | O_ACTIVE);

    NetworkSec.brddstfld = (zonessec_ctx.edit_zone.fields[field_num] =
                                    new_field_wrap(1, 1, 8, 53, 0, 0));
    field_num++;
    set_field_buffer_wrap(NetworkSec.brddstfld, 0,
            protectrule_loaded(
                    &zone_ptr->ProtectList, "protect", "spoofing", "brdcst-dst")
                    ? "X"
                    : " ");

    /* DHCP Server */
    NetworkSec.dhcpsrvlabelfld = (zonessec_ctx.edit_zone.fields[field_num] =
                                          new_field_wrap(1, 14, 4, 57, 0, 0));
    field_num++;
    set_field_buffer_wrap(
            NetworkSec.dhcpsrvlabelfld, 0, gettext("DHCP Server"));
    field_opts_off(NetworkSec.dhcpsrvlabelfld, O_AUTOSKIP | O_ACTIVE);

    NetworkSec.dhcpsrvbracketsfld = (zonessec_ctx.edit_zone.fields[field_num] =
                                             new_field_wrap(1, 3, 4, 71, 0, 0));
    field_num++;
    set_field_buffer_wrap(NetworkSec.dhcpsrvbracketsfld, 0, "[ ]");
    field_opts_off(NetworkSec.dhcpsrvbracketsfld, O_AUTOSKIP | O_ACTIVE);

    NetworkSec.dhcpsrvfld = (zonessec_ctx.edit_zone.fields[field_num] =
                                     new_field_wrap(1, 1, 4, 72, 0, 0));
    field_num++;
    set_field_buffer_wrap(NetworkSec.dhcpsrvfld, 0,
            protectrule_loaded(
                    &zone_ptr->ProtectList, "accept", "dhcp-server", NULL)
                    ? "X"
                    : " ");

    /* DHCP Client */
    NetworkSec.dhcpclilabelfld = (zonessec_ctx.edit_zone.fields[field_num] =
                                          new_field_wrap(1, 14, 5, 57, 0, 0));
    field_num++;
    set_field_buffer_wrap(
            NetworkSec.dhcpclilabelfld, 0, gettext("DHCP Client"));
    field_opts_off(NetworkSec.dhcpclilabelfld, O_AUTOSKIP | O_ACTIVE);

    NetworkSec.dhcpclibracketsfld = (zonessec_ctx.edit_zone.fields[field_num] =
                                             new_field_wrap(1, 3, 5, 71, 0, 0));
    field_num++;
    set_field_buffer_wrap(NetworkSec.dhcpclibracketsfld, 0, "[ ]");
    field_opts_off(NetworkSec.dhcpclibracketsfld, O_AUTOSKIP | O_ACTIVE);

    NetworkSec.dhcpclifld = (zonessec_ctx.edit_zone.fields[field_num] =
                                     new_field_wrap(1, 1, 5, 72, 0, 0));
    field_num++;
    set_field_buffer_wrap(NetworkSec.dhcpclifld, 0,
            protectrule_loaded(
                    &zone_ptr->ProtectList, "accept", "dhcp-client", NULL)
                    ? "X"
                    : " ");

    /* comment field */
    comment_y = 5;
    comment_x = 48;

    /* comment */
    NetworkSec.commentlabelfld = (zonessec_ctx.edit_zone.fields[field_num] =
                                          new_field_wrap(1, 16, 13, 0, 0, 0));
    field_num++;
    set_field_buffer_wrap(NetworkSec.commentlabelfld, 0, gettext("Comment"));
    field_opts_off(NetworkSec.commentlabelfld, O_AUTOSKIP | O_ACTIVE);

    NetworkSec.commentfld =
            (zonessec_ctx.edit_zone.fields[field_num] =
                            new_field_wrap(comment_y, comment_x, 14, 1, 0, 0));
    field_num++;

    NetworkSec.warningfld = (zonessec_ctx.edit_zone.fields[field_num] =
                                     new_field_wrap(1, width - 4, 1, 0, 0, 0));

    field_opts_off(NetworkSec.warningfld, O_VISIBLE | O_ACTIVE);
    field_num++;

    /* terminate */
    zonessec_ctx.edit_zone.fields[field_num] = NULL;

    vrmr_fatal_if(zonessec_ctx.edit_zone.n_fields != field_num);

    /* read the comment from backend */
    if (vctx->zf->ask(vctx->zone_backend, zone_ptr->name, "COMMENT",
                zonessec_ctx.comment, sizeof(zonessec_ctx.comment),
                VRMR_TYPE_NETWORK, 0) < 0)
        vrmr_error(-1, VR_ERR, gettext("error while loading the comment."));

    set_field_buffer_wrap(NetworkSec.commentfld, 0, zonessec_ctx.comment);

    /* create window and panel */
    zonessec_ctx.edit_zone.win = create_newwin(height, width, starty, startx,
            gettext("Edit Zone: Network"), vccnf.color_win);
    vrmr_fatal_if_null(zonessec_ctx.edit_zone.win);
    zonessec_ctx.edit_zone.panel[0] = new_panel(zonessec_ctx.edit_zone.win);
    vrmr_fatal_if_null(zonessec_ctx.edit_zone.panel[0]);
    keypad(zonessec_ctx.edit_zone.win, TRUE);

    /* set field options */
    for (i = 0; i < zonessec_ctx.edit_zone.n_fields; i++) {
        set_field_back(zonessec_ctx.edit_zone.fields[i], vccnf.color_win);
        field_opts_off(zonessec_ctx.edit_zone.fields[i], O_AUTOSKIP);
        set_field_status(zonessec_ctx.edit_zone.fields[i], FALSE);
    }

    set_field_back(NetworkSec.activefld, vccnf.color_win_rev);
    set_field_back(NetworkSec.networkfld, vccnf.color_win_rev);
    set_field_back(NetworkSec.netmaskfld, vccnf.color_win_rev);
    set_field_back(NetworkSec.network6fld, vccnf.color_win_rev);
    set_field_back(NetworkSec.cidr6fld, vccnf.color_win_rev);
    set_field_back(NetworkSec.commentfld, vccnf.color_win_rev);

    set_field_fore(NetworkSec.warningfld, vccnf.color_win_warn | A_BOLD);
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
    zonessec_ctx.edit_zone.form = new_form(zonessec_ctx.edit_zone.fields);
    vrmr_fatal_if_null(zonessec_ctx.edit_zone.form);
    scale_form(zonessec_ctx.edit_zone.form, &rows, &cols);
    set_form_win(zonessec_ctx.edit_zone.form, zonessec_ctx.edit_zone.win);
    set_form_sub(zonessec_ctx.edit_zone.form,
            derwin(zonessec_ctx.edit_zone.win, rows, cols, 1, 2));
    post_form(zonessec_ctx.edit_zone.form);

    /* the labels */
    mvwprintw(zonessec_ctx.edit_zone.win, 1, 2, "%s: %s", gettext("Name"),
            zone_ptr->name);
    mvwprintw(zonessec_ctx.edit_zone.win, 3, 30, gettext("Anti-spoofing"));

    //    mvwprintw(zonessec_ctx.edit_zone.win, 12, 54, "Press <F6> to assign");
    //    mvwprintw(zonessec_ctx.edit_zone.win, 13, 54, "(an) interface(s) to");
    //    mvwprintw(zonessec_ctx.edit_zone.win, 14, 54, "this network.");

    mvwprintw(zonessec_ctx.edit_zone.win, 12, 62, "%s", gettext("Hosts"));
    mvwprintw(zonessec_ctx.edit_zone.win, 12, 70, "%4d",
            vrmr_count_zones(zones, VRMR_TYPE_HOST, zone_ptr->network_name,
                    zone_ptr->zone_name));
    mvwprintw(zonessec_ctx.edit_zone.win, 13, 62, "%s", gettext("Groups"));
    mvwprintw(zonessec_ctx.edit_zone.win, 13, 70, "%4d",
            vrmr_count_zones(zones, VRMR_TYPE_GROUP, zone_ptr->network_name,
                    zone_ptr->zone_name));

    wrefresh(zonessec_ctx.edit_zone.win);
}

/*  edit_zone_network_save

    Returncodes:
         1: ok, changes
         0: ok, no changes
        -1: error
*/
static int edit_zone_network_save(
        struct vrmr_ctx *vctx, struct vrmr_zone *zone_ptr)
{
    int retval = 0;
    char network[16] = "", netmask[16] = "";
    char rules_changed = FALSE;
    struct vrmr_rule *rule_ptr = NULL;
    struct vrmr_list_node *d_node = NULL;
    int active = 0;
    size_t i = 0;

    /* check for changed fields */
    for (i = 0; i < zonessec_ctx.edit_zone.n_fields; i++) {
        if (field_status(zonessec_ctx.edit_zone.fields[i]) == FALSE)
            continue;

        retval = 1;

        if (zonessec_ctx.edit_zone.fields[i] == NetworkSec.activefld) {
            /* active */
            zone_ptr->status = VRMR_ST_CHANGED;

            active = zone_ptr->active;

            if (strncasecmp(field_buffer(zonessec_ctx.edit_zone.fields[i], 0),
                        STR_YES, StrLen(STR_YES)) == 0) {
                zone_ptr->active = 1;
            } else {
                zone_ptr->active = 0;
            }

            if (vctx->zf->tell(vctx->zone_backend, zone_ptr->name, "ACTIVE",
                        zone_ptr->active ? "Yes" : "No", 1,
                        VRMR_TYPE_NETWORK) < 0) {
                vrmr_error(-1, VR_ERR, gettext("saving to backend failed"));
                return (-1);
            }

            /* for the log */
            vrmr_audit("%s '%s' %s: %s %s '%s' (%s: '%s').", STR_NETWORK,
                    zone_ptr->name, STR_HAS_BEEN_CHANGED, STR_ACTIVE,
                    STR_IS_NOW_SET_TO, zone_ptr->active ? STR_YES : STR_NO,
                    STR_WAS, active ? STR_YES : STR_NO);
        } else if (zonessec_ctx.edit_zone.fields[i] == NetworkSec.networkfld) {
            /* network */
            zone_ptr->status = VRMR_ST_CHANGED;

            (void)strlcpy(network, zone_ptr->ipv4.network, sizeof(network));

            copy_field2buf(zone_ptr->ipv4.network,
                    field_buffer(zonessec_ctx.edit_zone.fields[i], 0),
                    sizeof(zone_ptr->ipv4.network));

            if (vctx->zf->tell(vctx->zone_backend, zone_ptr->name, "NETWORK",
                        zone_ptr->ipv4.network, 1, VRMR_TYPE_NETWORK) < 0) {
                vrmr_error(-1, VR_ERR, gettext("saving to backend failed"));
                return (-1);
            }

            /* for the log */
            vrmr_audit("%s '%s' %s: %s %s '%s' (%s: '%s').", STR_NETWORK,
                    zone_ptr->name, STR_HAS_BEEN_CHANGED, STR_NETADDR,
                    STR_IS_NOW_SET_TO, zone_ptr->ipv4.network, STR_WAS,
                    network);
        } else if (zonessec_ctx.edit_zone.fields[i] == NetworkSec.netmaskfld) {
            /* netmask */
            zone_ptr->status = VRMR_ST_CHANGED;

            (void)strlcpy(network, zone_ptr->ipv4.network, sizeof(network));

            copy_field2buf(zone_ptr->ipv4.netmask,
                    field_buffer(zonessec_ctx.edit_zone.fields[i], 0),
                    sizeof(zone_ptr->ipv4.netmask));

            if (vctx->zf->tell(vctx->zone_backend, zone_ptr->name, "NETMASK",
                        zone_ptr->ipv4.netmask, 1, VRMR_TYPE_NETWORK) < 0) {
                vrmr_error(-1, VR_ERR, gettext("saving to backend failed"));
                return (-1);
            }

            /* for the log */
            vrmr_audit("%s '%s' %s: %s %s '%s' (%s: '%s').", STR_NETWORK,
                    zone_ptr->name, STR_HAS_BEEN_CHANGED, STR_NETMASK,
                    STR_IS_NOW_SET_TO, zone_ptr->ipv4.netmask, STR_WAS,
                    netmask);
        } else if (zonessec_ctx.edit_zone.fields[i] == NetworkSec.network6fld) {
#ifdef IPV6_ENABLED
            char network6[VRMR_MAX_IPV6_ADDR_LEN] = "";

            /* network */
            zone_ptr->status = VRMR_ST_CHANGED;

            (void)strlcpy(network6, zone_ptr->ipv6.net6, sizeof(network6));

            copy_field2buf(zone_ptr->ipv6.net6,
                    field_buffer(zonessec_ctx.edit_zone.fields[i], 0),
                    sizeof(zone_ptr->ipv6.net6));

            if (vctx->zf->tell(vctx->zone_backend, zone_ptr->name,
                        "IPV6NETWORK", zone_ptr->ipv6.net6, 1,
                        VRMR_TYPE_NETWORK) < 0) {
                vrmr_error(-1, VR_ERR, gettext("saving to backend failed"));
                return (-1);
            }

            /* for the log */
            vrmr_audit("%s '%s' %s: %s %s '%s' (%s: '%s').", STR_IP6NETWORK,
                    zone_ptr->name, STR_HAS_BEEN_CHANGED, STR_NETADDR,
                    STR_IS_NOW_SET_TO, zone_ptr->ipv6.net6, STR_WAS, network6);
#endif
        } else if (zonessec_ctx.edit_zone.fields[i] == NetworkSec.cidr6fld) {
#ifdef IPV6_ENABLED
            /* netmask */
            zone_ptr->status = VRMR_ST_CHANGED;

            int cidr = zone_ptr->ipv6.cidr6;
            char cidrstr[3] = "";

            copy_field2buf(cidrstr,
                    field_buffer(zonessec_ctx.edit_zone.fields[i], 0),
                    sizeof(cidrstr));

            if (vctx->zf->tell(vctx->zone_backend, zone_ptr->name, "IPV6CIDR",
                        cidrstr, 1, VRMR_TYPE_NETWORK) < 0) {
                vrmr_error(-1, VR_ERR, gettext("saving to backend failed"));
                return (-1);
            }

            /* for the log */
            vrmr_audit("%s '%s' %s: %s %s '%d' (%s: '%d').", STR_IP6CIDR,
                    zone_ptr->name, STR_HAS_BEEN_CHANGED, STR_NETMASK,
                    STR_IS_NOW_SET_TO, zone_ptr->ipv6.cidr6, STR_WAS, cidr);
#endif
        }
        /* save the comment to the backend */
        else if (zonessec_ctx.edit_zone.fields[i] == NetworkSec.commentfld) {
            if (vctx->zf->tell(vctx->zone_backend, zone_ptr->name, "COMMENT",
                        field_buffer(zonessec_ctx.edit_zone.fields[i], 0), 1,
                        VRMR_TYPE_NETWORK) < 0) {
                vrmr_error(-1, VR_ERR, gettext("saving to backend failed"));
                return (-1);
            }

            /* example: "network 'local.lan' has been changed: the comment was
             * changed." */
            vrmr_audit("%s '%s' %s: %s.", STR_NETWORK, zone_ptr->name,
                    STR_HAS_BEEN_CHANGED, STR_COMMENT_CHANGED);
        } else if (zonessec_ctx.edit_zone.fields[i] == NetworkSec.loopbackfld ||
                   zonessec_ctx.edit_zone.fields[i] == NetworkSec.classafld ||
                   zonessec_ctx.edit_zone.fields[i] == NetworkSec.classbfld ||
                   zonessec_ctx.edit_zone.fields[i] == NetworkSec.classcfld ||
                   zonessec_ctx.edit_zone.fields[i] == NetworkSec.classdfld ||
                   zonessec_ctx.edit_zone.fields[i] == NetworkSec.classefld ||
                   zonessec_ctx.edit_zone.fields[i] == NetworkSec.testnetfld ||

                   zonessec_ctx.edit_zone.fields[i] ==
                           NetworkSec.lnklocnetfld ||
                   zonessec_ctx.edit_zone.fields[i] == NetworkSec.iana08fld ||
                   zonessec_ctx.edit_zone.fields[i] == NetworkSec.brdsrcfld ||
                   zonessec_ctx.edit_zone.fields[i] == NetworkSec.brddstfld ||

                   zonessec_ctx.edit_zone.fields[i] == NetworkSec.dhcpsrvfld ||
                   zonessec_ctx.edit_zone.fields[i] == NetworkSec.dhcpclifld) {
            if (edit_zone_network_save_protectrules(vctx, zone_ptr) < 0) {
                return (-1);
            }

            rules_changed = TRUE;
        }
    }

    /* audit print list */
    if (rules_changed == TRUE) {
        /* example: "network 'local.lan' has been changed: rules are changed:
         * number of rules: 5 (listed below)." */
        vrmr_audit("%s '%s' %s: %s: %s: %d (%s).", STR_NETWORK, zone_ptr->name,
                STR_HAS_BEEN_CHANGED, STR_RULES_ARE_CHANGED,
                STR_NUMBER_OF_RULES, zone_ptr->ProtectList.len,
                STR_LISTED_BELOW);

        for (i = 1, d_node = zone_ptr->ProtectList.top; d_node;
                d_node = d_node->next, i++) {
            vrmr_fatal_if_null(d_node->data);
            rule_ptr = d_node->data;

            if (rule_ptr->action == VRMR_AT_PROTECT) {
                if (rule_ptr->source[0] != '\0')
                    vrmr_audit("%2d: %s against %s from %s", (int)i,
                            vrmr_rules_itoaction(rule_ptr->action),
                            rule_ptr->danger, rule_ptr->source);
                else
                    vrmr_audit("%2d: %s against %s", (int)i,
                            vrmr_rules_itoaction(rule_ptr->action),
                            rule_ptr->danger);
            } else {
                vrmr_audit("%2d: %s %s", (int)i,
                        vrmr_rules_itoaction(rule_ptr->action),
                        rule_ptr->service);
            }
        }
    }

    return (retval);
}

static void edit_zone_network_destroy(void)
{
    size_t i = 0;

    /* unpost form and free the memory */
    unpost_form(zonessec_ctx.edit_zone.form);
    free_form(zonessec_ctx.edit_zone.form);
    for (i = 0; i < zonessec_ctx.edit_zone.n_fields; i++) {
        free_field(zonessec_ctx.edit_zone.fields[i]);
    }
    free(zonessec_ctx.edit_zone.fields);
    del_panel(zonessec_ctx.edit_zone.panel[0]);
    destroy_win(zonessec_ctx.edit_zone.win);
    /* reset the comment field */
    strcpy(zonessec_ctx.comment, "");
}

/*  edit_zone_network

    The TmpZone crap here is the fault of edit_zone_network_save.
    See the comment above that function for more horror...

    Returncodes:
         1: ok, changes
         0: ok, no changes
        -1: error
*/
static int edit_zone_network(struct vrmr_ctx *vctx, struct vrmr_zones *zones,
        struct vrmr_interfaces *interfaces, char *name)
{
    int ch = 0, not_defined = 0, quit = 0, retval = 0;
    struct vrmr_zone *zone_ptr = NULL;
    int height = 0, width = 0, startx = 0, starty = 0;
    FIELD *cur = NULL, *prev = NULL;
    char *key_choices[] = {"F12", "F6", "F10"};
    int key_choices_n = 3;
    char *cmd_choices[] = {
            gettext("help"), gettext("interfaces"), gettext("back")};
    int cmd_choices_n = 3;

    /* safety */
    vrmr_fatal_if_null(name);
    vrmr_fatal_if_null(interfaces);
    vrmr_fatal_if_null(zones);

    height = 21;
    width = 78;
    VrWinGetOffset(
            -1, -1, height, width, 4, zonessec_ctx.n_xre + 1, &starty, &startx);

    zone_ptr = vrmr_search_zonedata(zones, name);
    vrmr_fatal_if_null(zone_ptr);

    edit_zone_network_init(
            vctx, zones, name, height, width, starty, startx, zone_ptr);

    /* print warning if no interfaces have been assigned to this network */
    if (zone_ptr->InterfaceList.len == 0) {
        /* show no int warning */
        set_field_buffer_wrap(NetworkSec.warningfld, 0,
                gettext("Warning: no interfaces attached!"));
        field_opts_on(NetworkSec.warningfld, O_VISIBLE);
        set_field_status(NetworkSec.warningfld, FALSE);
    } else if (zone_ptr->active == TRUE && vrmr_zones_active(zone_ptr) == 0) {
        set_field_buffer_wrap(NetworkSec.warningfld, 0,
                gettext("Note: parent zone is inactive."));
        field_opts_on(NetworkSec.warningfld, O_VISIBLE);
        set_field_status(NetworkSec.warningfld, FALSE);
    }

    wrefresh(zonessec_ctx.edit_zone.win);
    cur = current_field(zonessec_ctx.edit_zone.form);
    pos_form_cursor(zonessec_ctx.edit_zone.form);

    draw_top_menu(top_win, gettext("Network"), key_choices_n, key_choices,
            cmd_choices_n, cmd_choices);

    update_panels();
    doupdate();

    /* loop through to get user requests */
    while (quit == 0) {
        prev = cur;
        /* get current field */
        cur = current_field(zonessec_ctx.edit_zone.form);

        /* draw the arrow around the active field */
        draw_field_active_mark(cur, prev, zonessec_ctx.edit_zone.win,
                zonessec_ctx.edit_zone.form, vccnf.color_win_mark | A_BOLD);

        not_defined = 0;

        /* get the input */
        ch = wgetch(zonessec_ctx.edit_zone.win);

        if (cur == NetworkSec.commentfld) {
            if (nav_field_comment(zonessec_ctx.edit_zone.form, ch) < 0)
                not_defined = 1;
        } else if (cur == NetworkSec.activefld) {
            if (nav_field_yesno(zonessec_ctx.edit_zone.form, ch) < 0)
                not_defined = 1;
        } else if (cur == NetworkSec.networkfld ||
                   cur == NetworkSec.network6fld ||
                   cur == NetworkSec.netmaskfld || cur == NetworkSec.cidr6fld) {
            if (nav_field_simpletext(zonessec_ctx.edit_zone.form, ch) < 0)
                not_defined = 1;
        }
        /* this one needs to be last */
        else if (cur == NetworkSec.loopbackfld || cur == NetworkSec.classafld ||
                 cur == NetworkSec.classbfld || cur == NetworkSec.classcfld ||
                 cur == NetworkSec.classdfld || cur == NetworkSec.classefld ||
                 cur == NetworkSec.testnetfld ||
                 cur == NetworkSec.lnklocnetfld ||
                 cur == NetworkSec.iana08fld || cur == NetworkSec.brdsrcfld ||
                 cur == NetworkSec.brddstfld || cur == NetworkSec.dhcpsrvfld ||
                 cur == NetworkSec.dhcpclifld) {
            if (nav_field_toggleX(zonessec_ctx.edit_zone.form, ch) < 0)
                not_defined = 1;
        } else
            not_defined = 1;

        /* the rest is handled here */
        if (not_defined == 1) {
            switch (ch) {
                case KEY_F(6):
                case 'e':
                case 'E':

                    edit_zone_network_interfaces(vctx, interfaces, zone_ptr);

                    draw_top_menu(top_win, gettext("Networks"), key_choices_n,
                            key_choices, cmd_choices_n, cmd_choices);
                    break;

                case KEY_DOWN:
                case 10: // enter
                case 9:  // tab

                    form_driver_wrap(
                            zonessec_ctx.edit_zone.form, REQ_NEXT_FIELD);
                    form_driver_wrap(zonessec_ctx.edit_zone.form, REQ_BEG_LINE);
                    break;

                case KEY_UP:

                    form_driver_wrap(
                            zonessec_ctx.edit_zone.form, REQ_PREV_FIELD);
                    form_driver_wrap(zonessec_ctx.edit_zone.form, REQ_BEG_LINE);
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

                    print_help(":[VUURMUUR:ZONES:NETWORK:EDIT]:");
                    break;
            }
        }

        /* print warning if no interfaces have been assigned to this network */
        if (zone_ptr->InterfaceList.len == 0) {
            /* show no int warning */
            set_field_buffer_wrap(NetworkSec.warningfld, 0,
                    gettext("Warning: no interfaces attached!"));
            field_opts_on(NetworkSec.warningfld, O_VISIBLE);
            set_field_status(NetworkSec.warningfld, FALSE);
        }
        /* check against the current 'active' value */
        else if (strncasecmp(field_buffer(NetworkSec.activefld, 0), STR_YES,
                         StrLen(STR_YES)) == 0 &&
                 vrmr_zones_active(zone_ptr) == 0) {
            set_field_buffer_wrap(NetworkSec.warningfld, 0,
                    gettext("Note: parent zone is inactive."));
            field_opts_on(NetworkSec.warningfld, O_VISIBLE);
            set_field_status(NetworkSec.warningfld, FALSE);
        }
        /* and clear it again */
        else {
            /* hide no int warning */
            field_opts_off(NetworkSec.warningfld, O_VISIBLE);
        }

        /* draw and set cursor */
        wrefresh(zonessec_ctx.edit_zone.win);
        pos_form_cursor(zonessec_ctx.edit_zone.form);
    }

    /* save */
    if (edit_zone_network_save(vctx, zone_ptr) < 0) {
        vrmr_error(-1, VR_ERR, gettext("saving to backend failed"));
        retval = -1;
    }

    /* cleanup */
    edit_zone_network_destroy();

    update_panels();
    doupdate();

    status_print(status_win, gettext("Ready."));
    return (retval);
}

static void zones_section_menu_networks_init(
        struct vrmr_zones *zones, char *zonename)
{
    struct vrmr_zone *zone_ptr = NULL;
    int height, width, startx, starty, maxy;
    struct vrmr_list_node *d_node = NULL;
    char temp[64] = "", /* set to twice 32 because it
           can contain widec */
            *desc_ptr = NULL;
    size_t i = 0;

    /* safety */
    vrmr_fatal_if_null(zonename);
    vrmr_fatal_if_null(zones);

    /* get screen dimentions */
    maxy = getmaxy(stdscr);

    /* count how many networks there are */
    zonessec_ctx.network_n = 0;

    /* count the networks */
    for (d_node = zones->list.top; d_node; d_node = d_node->next) {
        vrmr_fatal_if_null(d_node->data);
        zone_ptr = d_node->data;

        if (zone_ptr->type == VRMR_TYPE_NETWORK &&
                strcmp(zone_ptr->zone_name, zonename) == 0)
            zonessec_ctx.network_n++;
    }

    vrmr_list_setup(&zonessec_ctx.network_desc_list, free);

    i = zonessec_ctx.network_n - 1;

    zonessec_ctx.networkitems =
            (ITEM **)calloc(zonessec_ctx.network_n + 1, sizeof(ITEM *));
    vrmr_fatal_alloc("calloc", zonessec_ctx.networkitems);

    /* now load the items */
    for (d_node = zones->list.bot; d_node; d_node = d_node->prev) {
        vrmr_fatal_if_null(d_node->data);
        zone_ptr = d_node->data;

        if (zone_ptr->type == VRMR_TYPE_NETWORK &&
                strcmp(zone_ptr->zone_name, zonename) == 0) {
            if (zone_ptr->ipv4.network[0] == '\0' ||
                    zone_ptr->ipv4.netmask[0] == '\0')
                /* TRANSLATORS: max 32 chars */
                snprintf(temp, sizeof(temp),
                        gettext("No network/netmask defined."));
            else
                snprintf(temp, sizeof(temp), "%s/%s", zone_ptr->ipv4.network,
                        zone_ptr->ipv4.netmask);

            desc_ptr = strdup(temp);
            vrmr_fatal_alloc("strdup", desc_ptr);

            vrmr_fatal_if(vrmr_list_append(&zonessec_ctx.network_desc_list,
                                  desc_ptr) == NULL);

            zonessec_ctx.networkitems[i] =
                    new_item(zone_ptr->network_name, desc_ptr);
            vrmr_fatal_if_null(zonessec_ctx.networkitems[i]);

            i--;
        }
    }
    zonessec_ctx.networkitems[zonessec_ctx.network_n] = (ITEM *)NULL;

    if (zonessec_ctx.network_n > 0) {
        zonessec_ctx.n_top = zonessec_ctx.networkitems[0];
        zonessec_ctx.n_bot =
                zonessec_ctx.networkitems[zonessec_ctx.network_n - 1];
    } else {
        zonessec_ctx.n_top = NULL;
        zonessec_ctx.n_bot = NULL;
    }

    zonessec_ctx.n_menu = new_menu((ITEM **)zonessec_ctx.networkitems);
    vrmr_fatal_if_null(zonessec_ctx.n_menu);

    starty = 4;
    height = (int)(zonessec_ctx.network_n + 9);
    width = VRMR_MAX_NETWORK + 32 + 4;

    if (maxy < starty + height + 4) {
        height = maxy - (2 * starty);
    }

    /* place on the same y as zones list */
    VrWinGetOffset(
            -1, -1, height, width, 4, zonessec_ctx.z_xre + 1, &starty, &startx);
    zonessec_ctx.n_yle = starty + height;
    zonessec_ctx.n_xre = startx + width;

    zonessec_ctx.n_win = newwin(height, width, starty, startx);
    vrmr_fatal_if_null(zonessec_ctx.n_win);
    zonessec_ctx.n_panel[0] = new_panel(zonessec_ctx.n_win);
    vrmr_fatal_if_null(zonessec_ctx.n_panel[0]);
    wbkgd(zonessec_ctx.n_win, vccnf.color_win);
    keypad(zonessec_ctx.n_win, TRUE);

    set_menu_win(zonessec_ctx.n_menu, zonessec_ctx.n_win);
    set_menu_sub(zonessec_ctx.n_menu,
            derwin(zonessec_ctx.n_win, height - 8, width - 2, 3, 1));
    set_menu_format(zonessec_ctx.n_menu, height - 9, 1);

    box(zonessec_ctx.n_win, 0, 0);
    print_in_middle(zonessec_ctx.n_win, 1, 0, width, gettext("Networks"),
            vccnf.color_win);
    mvwaddch(zonessec_ctx.n_win, 2, 0, ACS_LTEE);
    mvwhline(zonessec_ctx.n_win, 2, 1, ACS_HLINE, width - 2);
    mvwaddch(zonessec_ctx.n_win, 2, width - 1, ACS_RTEE);

    set_menu_back(zonessec_ctx.n_menu, vccnf.color_win);
    set_menu_fore(zonessec_ctx.n_menu, vccnf.color_win_rev);
    post_menu(zonessec_ctx.n_menu);

    mvwaddch(zonessec_ctx.n_win, height - 6, 0, ACS_LTEE);
    mvwhline(zonessec_ctx.n_win, height - 6, 1, ACS_HLINE, width - 2);
    mvwaddch(zonessec_ctx.n_win, height - 6, width - 1, ACS_RTEE);

    mvwprintw(zonessec_ctx.n_win, height - 5, 2, "<RET> %s",
            gettext("to enter the hosts/groups of this network"));
    mvwprintw(zonessec_ctx.n_win, height - 4, 2, "<INS> %s", STR_NEW);
    mvwprintw(zonessec_ctx.n_win, height - 3, 2, "<DEL> %s", STR_REMOVE);
    mvwprintw(zonessec_ctx.n_win, height - 2, 2, "< e > %s", STR_EDIT);

    /* create the top and bottom fields */
    zonessec_ctx.n_win_top = newwin(1, 6, starty + 2, startx + width - 8);
    vrmr_fatal_if_null(zonessec_ctx.n_win_top);
    wbkgd(zonessec_ctx.n_win_top, vccnf.color_win);
    zonessec_ctx.n_panel_top[0] = new_panel(zonessec_ctx.n_win_top);
    /* TRANSLATORS: max 4 chars */
    wprintw(zonessec_ctx.n_win_top, "(%s)", gettext("more"));
    hide_panel(zonessec_ctx.n_panel_top[0]);

    zonessec_ctx.n_win_bot =
            newwin(1, 6, starty + height - 6, startx + width - 8);
    vrmr_fatal_if_null(zonessec_ctx.n_win_bot);
    wbkgd(zonessec_ctx.n_win_bot, vccnf.color_win);
    zonessec_ctx.n_panel_bot[0] = new_panel(zonessec_ctx.n_win_bot);
    /* TRANSLATORS: max 4 chars */
    wprintw(zonessec_ctx.n_win_bot, "(%s)", gettext("more"));
    hide_panel(zonessec_ctx.n_panel_bot[0]);

    update_panels();
    doupdate();
}

static void zones_section_menu_networks_destroy(void)
{
    size_t i = 0;

    unpost_menu(zonessec_ctx.n_menu);
    free_menu(zonessec_ctx.n_menu);

    for (i = 0; i < zonessec_ctx.network_n; ++i)
        free_item(zonessec_ctx.networkitems[i]);

    free(zonessec_ctx.networkitems);

    del_panel(zonessec_ctx.n_panel[0]);
    destroy_win(zonessec_ctx.n_win);

    vrmr_list_cleanup(&zonessec_ctx.network_desc_list);

    del_panel(zonessec_ctx.n_panel_top[0]);
    destroy_win(zonessec_ctx.n_win_top);
    del_panel(zonessec_ctx.n_panel_bot[0]);
    destroy_win(zonessec_ctx.n_win_bot);
}

static void zones_section_menu_networks(struct vrmr_ctx *vctx,
        struct vrmr_zones *zones, struct vrmr_interfaces *interfaces,
        struct vrmr_rules *rules, struct vrmr_blocklist *blocklist,
        char *zonename, struct vrmr_regex *reg)
{
    int ch, quit = 0, reload = 0, result = 0;
    size_t size = 0;
    char *vrmr_new_zone_ptr = NULL, *zonename_ptr = NULL,
         *cur_zonename_ptr = NULL,
         *choices[] = {gettext("Hosts"), gettext("Groups"), gettext("Network")},
         *temp_ptr = NULL, *choice_ptr = NULL;
    ITEM *cur = NULL;

    /* top menu */
    char *key_choices[] = {"F12", "INS", "DEL", "r", "RET", "e", "F10"};
    int key_choices_n = 7;
    char *cmd_choices[] = {gettext("help"), gettext("new"), gettext("del"),
            gettext("rename"), gettext("open"), gettext("edit"),
            gettext("back")};
    int cmd_choices_n = 7;

    /* safety */
    vrmr_fatal_if_null(zonename);
    vrmr_fatal_if_null(reg);
    vrmr_fatal_if_null(interfaces);
    vrmr_fatal_if_null(zones);
    vrmr_fatal_if_null(rules);
    vrmr_fatal_if_null(blocklist);

    zones_section_menu_networks_init(zones, zonename);

    draw_top_menu(top_win, gettext("Networks"), key_choices_n, key_choices,
            cmd_choices_n, cmd_choices);

    while (quit == 0) {
        if (reload == 1) {
            zones_section_menu_networks_destroy();
            zones_section_menu_networks_init(zones, zonename);
            reload = 0;
        }

        while (quit == 0 && reload == 0) {
            if (zonessec_ctx.n_top != NULL && !item_visible(zonessec_ctx.n_top))
                show_panel(zonessec_ctx.n_panel_top[0]);
            else
                hide_panel(zonessec_ctx.n_panel_top[0]);

            if (zonessec_ctx.n_bot != NULL && !item_visible(zonessec_ctx.n_bot))
                show_panel(zonessec_ctx.n_panel_bot[0]);
            else
                hide_panel(zonessec_ctx.n_panel_bot[0]);

            update_panels();
            doupdate();

            /* restore the cursor */
            pos_menu_cursor(zonessec_ctx.n_menu);

            ch = wgetch(zonessec_ctx.n_win);

            switch (ch) {
                case 27:
                case KEY_F(10): // exit/back
                case 'q':
                case 'Q':

                    quit = 1;
                    break;

                case 'r':
                case 'R':

                    cur = current_item(zonessec_ctx.n_menu);
                    if (cur) {
                        size = StrMemLen((char *)item_name(cur)) + 1 +
                               StrMemLen(zonename) + 1;

                        cur_zonename_ptr = malloc(size);
                        vrmr_fatal_alloc("malloc", cur_zonename_ptr);

                        /* create the network name string */
                        (void)strlcpy(
                                cur_zonename_ptr, (char *)item_name(cur), size);
                        (void)strlcat(cur_zonename_ptr, ".", size);
                        (void)strlcat(cur_zonename_ptr, zonename, size);

                        /* rename */
                        vrmr_new_zone_ptr = input_box(VRMR_MAX_HOST,
                                gettext("Rename Network"),
                                gettext("Enter the new name of the network"));
                        if (vrmr_new_zone_ptr != NULL) {
                            if (vrmr_validate_zonename(vrmr_new_zone_ptr, 1,
                                        NULL, NULL, NULL, reg->network_part,
                                        VRMR_VERBOSE) == -1) {
                                vrmr_warning(VR_WARN,
                                        gettext("invalid networkname '%s'."),
                                        vrmr_new_zone_ptr);
                            } else {
                                /* get the size */
                                size = StrMemLen(vrmr_new_zone_ptr) + 1 +
                                       StrMemLen(zonename) + 1;

                                /* alloc the memory */
                                temp_ptr = malloc(size);
                                vrmr_fatal_alloc("malloc", temp_ptr);

                                /* create the string */
                                (void)strlcpy(
                                        temp_ptr, vrmr_new_zone_ptr, size);
                                (void)strlcat(temp_ptr, ".", size);
                                (void)strlcat(temp_ptr, zonename, size);

                                if (vrmr_validate_zonename(temp_ptr, 1, NULL,
                                            NULL, NULL, reg->zonename,
                                            VRMR_VERBOSE) == 0) {
                                    if (zones_rename_network_zone(vctx, zones,
                                                rules, blocklist,
                                                cur_zonename_ptr, temp_ptr,
                                                VRMR_TYPE_NETWORK, reg) < 0) {
                                        vrmr_error(-1, VR_ERR,
                                                gettext("renaming network "
                                                        "failed."));
                                    } else {
                                        /* we have a renamed network, so reload
                                         * the menu */
                                        reload = 1;
                                    }
                                } else {
                                    vrmr_warning(VR_WARN,
                                            gettext("'%s' is an invalid name "
                                                    "for a network."),
                                            vrmr_new_zone_ptr);
                                }
                                free(temp_ptr);
                            }
                            free(vrmr_new_zone_ptr);
                        }
                        free(cur_zonename_ptr);
                    }
                    break;

                case KEY_IC: /* insert */
                case 'i':
                case 'I':

                    vrmr_new_zone_ptr = input_box(VRMR_MAX_NETWORK,
                            gettext("New Network"),
                            gettext("Enter the name of the new network"));
                    if (vrmr_new_zone_ptr != NULL) {
                        if (vrmr_validate_zonename(vrmr_new_zone_ptr, 1, NULL,
                                    NULL, NULL, reg->network_part,
                                    VRMR_VERBOSE) == -1) {
                            vrmr_warning(VR_WARN,
                                    gettext("invalid networkname '%s'."),
                                    vrmr_new_zone_ptr);
                        } else {
                            size = StrMemLen(vrmr_new_zone_ptr) + 1 +
                                   StrMemLen(zonename) + 1;

                            temp_ptr = malloc(size);
                            vrmr_fatal_alloc("malloc", temp_ptr);
                            (void)strlcpy(temp_ptr, vrmr_new_zone_ptr, size);
                            (void)strlcat(temp_ptr, ".", size);
                            (void)strlcat(temp_ptr, zonename, size);

                            if (vrmr_validate_zonename(temp_ptr, 1, NULL, NULL,
                                        NULL, reg->zonename,
                                        VRMR_VERBOSE) == 0) {
                                if (vrmr_new_zone(vctx, zones, temp_ptr,
                                            VRMR_TYPE_NETWORK) < 0) {
                                    vrmr_error(-1, VR_ERR,
                                            gettext("adding network failed."));
                                } else {
                                    vrmr_audit("%s '%s' %s.", STR_NETWORK,
                                            temp_ptr, STR_HAS_BEEN_CREATED);

                                    (void)edit_zone_network(
                                            vctx, zones, interfaces, temp_ptr);
                                    reload = 1;
                                }
                            } else {
                                vrmr_warning(VR_WARN,
                                        gettext("'%s' is an invalid name for a "
                                                "network."),
                                        vrmr_new_zone_ptr);
                            }
                        }
                        free(temp_ptr);
                    }
                    free(vrmr_new_zone_ptr);
                    break;

                case KEY_DC: /* delete */
                case 'd':
                case 'D':

                    cur = current_item(zonessec_ctx.n_menu);
                    if (cur) {
                        if (vrmr_count_zones(zones, VRMR_TYPE_HOST,
                                    (char *)item_name(cur), zonename) <= 0 &&
                                vrmr_count_zones(zones, VRMR_TYPE_GROUP,
                                        (char *)item_name(cur),
                                        zonename) <= 0) {
                            if (confirm(gettext("Delete"),
                                        gettext("This network?"),
                                        vccnf.color_win_note,
                                        vccnf.color_win_note_rev | A_BOLD,
                                        0) == 1) {
                                size = StrMemLen((char *)item_name(cur)) + 1 +
                                       StrMemLen(zonename) + 1;
                                zonename_ptr = malloc(size);
                                vrmr_fatal_alloc("malloc", zonename_ptr);
                                (void)strlcpy(zonename_ptr,
                                        (char *)item_name(cur), size);
                                (void)strlcat(zonename_ptr, ".", size);
                                (void)strlcat(zonename_ptr, zonename, size);

                                result = vrmr_delete_zone(vctx, zones,
                                        zonename_ptr, VRMR_TYPE_NETWORK);
                                if (result < 0)
                                    vrmr_error(result, VR_ERR,
                                            gettext("deleting network "
                                                    "failed."));
                                else
                                    reload = 1;

                                vrmr_audit("%s '%s' %s.", STR_NETWORK,
                                        zonename_ptr, STR_HAS_BEEN_DELETED);

                                free(zonename_ptr);
                            }
                        } else {
                            vrmr_error(-1, VR_ERR,
                                    gettext("unable to delete: network not "
                                            "empty."));
                        }
                    }
                    break;

                case KEY_DOWN:
                    menu_driver(zonessec_ctx.n_menu, REQ_DOWN_ITEM);
                    break;
                case KEY_UP:
                    menu_driver(zonessec_ctx.n_menu, REQ_UP_ITEM);
                    break;
                case KEY_NPAGE:
                    if (menu_driver(zonessec_ctx.n_menu, REQ_SCR_DPAGE) !=
                            E_OK) {
                        while (menu_driver(zonessec_ctx.n_menu,
                                       REQ_DOWN_ITEM) == E_OK)
                            ;
                    }
                    break;
                case KEY_PPAGE:
                    if (menu_driver(zonessec_ctx.n_menu, REQ_SCR_UPAGE) !=
                            E_OK) {
                        while (menu_driver(zonessec_ctx.n_menu, REQ_UP_ITEM) ==
                                E_OK)
                            ;
                    }
                    break;
                case KEY_HOME:
                    menu_driver(zonessec_ctx.n_menu, REQ_FIRST_ITEM); // home
                    break;
                case KEY_END:
                    menu_driver(zonessec_ctx.n_menu, REQ_LAST_ITEM); // end
                    break;

                case KEY_RIGHT:
                case 10: // enter
                case 'b':
                case 'B':

                    cur = current_item(zonessec_ctx.n_menu);
                    choice_ptr = selectbox(gettext("Select"),
                            gettext("Hosts, Groups or this Network"), 3,
                            choices, 1, NULL);

                    if (choice_ptr != NULL && cur != NULL) {
                        if (strcmp(choice_ptr, gettext("Hosts")) == 0) {
                            (void)zones_section_menu_hosts(vctx, zones, rules,
                                    blocklist, zonename, (char *)item_name(cur),
                                    reg);
                        } else if (strcmp(choice_ptr, gettext("Groups")) == 0) {
                            zones_section_menu_groups(vctx, zones, rules,
                                    blocklist, zonename, (char *)item_name(cur),
                                    reg);
                        } else {
                            size = StrMemLen((char *)item_name(cur)) + 1 +
                                   StrMemLen(zonename) + 1;
                            zonename_ptr = malloc(size);
                            vrmr_fatal_alloc("malloc", zonename_ptr);

                            (void)strlcpy(
                                    zonename_ptr, (char *)item_name(cur), size);
                            (void)strlcat(zonename_ptr, ".", size);
                            (void)strlcat(zonename_ptr, zonename, size);

                            /*  edit the network. We don't care about the
                               result. If there is an error, its up to the user
                               to decide what to do. */
                            if (edit_zone_network(vctx, zones, interfaces,
                                        zonename_ptr) == 1)
                                reload = 1;

                            free(zonename_ptr);
                        }
                        free(choice_ptr);
                    }

                    draw_top_menu(top_win, gettext("Networks"), key_choices_n,
                            key_choices, cmd_choices_n, cmd_choices);
                    break;

                case 'g': /* group quick key */
                case 'G': /* group quick key */

                    cur = current_item(zonessec_ctx.n_menu);
                    if (cur) {
                        zones_section_menu_groups(vctx, zones, rules, blocklist,
                                zonename, (char *)item_name(cur), reg);
                    }
                    break;

                case 'h': /* host quick key */
                case 'H': /* host quick key */

                    cur = current_item(zonessec_ctx.n_menu);
                    if (cur) {
                        (void)zones_section_menu_hosts(vctx, zones, rules,
                                blocklist, zonename, (char *)item_name(cur),
                                reg);
                    }
                    break;

                case 'e':
                case 'E':
                case 32: /* spacebar */

                    cur = current_item(zonessec_ctx.n_menu);
                    if (cur) {
                        size = StrMemLen((char *)item_name(cur)) + 1 +
                               StrMemLen(zonename) + 1;
                        zonename_ptr = malloc(size);
                        vrmr_fatal_alloc("malloc", zonename_ptr);

                        (void)strlcpy(
                                zonename_ptr, (char *)item_name(cur), size);
                        (void)strlcat(zonename_ptr, ".", size);
                        (void)strlcat(zonename_ptr, zonename, size);

                        /*  edit the network. We don't care about the result.
                            If there is an error, its up to the user to decide
                            what to do. */
                        if (edit_zone_network(
                                    vctx, zones, interfaces, zonename_ptr) == 1)
                            reload = 1;

                        free(zonename_ptr);
                    }
                    break;

                case '?':
                case KEY_F(12):
                    print_help(":[VUURMUUR:ZONES:NETWORKS]:");
                    break;
            }
        }
    }

    zones_section_menu_networks_destroy();

    update_panels();
    doupdate();

    status_print(status_win, gettext("Ready."));
}

struct {
    FIELD *activefld, *activelabelfld,

            *commentfld, *commentlabelfld;
} ZoneSec;

static void edit_zone_zone_init(struct vrmr_ctx *vctx, struct vrmr_zones *zones,
        char *name, int height, int width, int starty, int startx,
        struct vrmr_zone *zone_ptr)
{
    int rows, cols;
    size_t i = 0;
    int comment_y = 0, comment_x = 0;
    unsigned int field_num = 0;

    /* safety */
    vrmr_fatal_if_null(name);
    vrmr_fatal_if_null(zone_ptr);
    vrmr_fatal_if_null(zones);

    /* alloc fields */
    zonessec_ctx.edit_zone.n_fields = 4;

    zonessec_ctx.edit_zone.fields = (FIELD **)calloc(
            zonessec_ctx.edit_zone.n_fields + 1, sizeof(FIELD *));
    vrmr_fatal_alloc("calloc", zonessec_ctx.edit_zone.fields);

    ZoneSec.activelabelfld = (zonessec_ctx.edit_zone.fields[field_num++] =
                                      new_field_wrap(1, 16, 2, 0, 0, 0));
    set_field_buffer_wrap(ZoneSec.activelabelfld, 0, gettext("Active"));
    field_opts_off(ZoneSec.activelabelfld, O_AUTOSKIP | O_ACTIVE);

    ZoneSec.activefld = (zonessec_ctx.edit_zone.fields[field_num++] =
                                 new_field_wrap(1, 3, 3, 1, 0, 0));
    set_field_buffer_wrap(
            ZoneSec.activefld, 0, zone_ptr->active ? STR_YES : STR_NO);

    ZoneSec.commentlabelfld = (zonessec_ctx.edit_zone.fields[field_num++] =
                                       new_field_wrap(1, 16, 5, 0, 0, 0));
    set_field_buffer_wrap(ZoneSec.commentlabelfld, 0, gettext("Comment"));
    field_opts_off(ZoneSec.commentlabelfld, O_AUTOSKIP | O_ACTIVE);

    /* comment field size */
    comment_y = 5;
    comment_x = 48;
    /* create and label the comment field */
    ZoneSec.commentfld =
            (zonessec_ctx.edit_zone.fields[field_num++] =
                            new_field_wrap(comment_y, comment_x, 6, 1, 0, 0));
    /* load the comment from the backend */
    if (vctx->zf->ask(vctx->zone_backend, zone_ptr->name, "COMMENT",
                zonessec_ctx.comment, sizeof(zonessec_ctx.comment),
                VRMR_TYPE_ZONE, 0) < 0)
        vrmr_error(-1, "Error", "error while loading the comment.");

    set_field_buffer_wrap(ZoneSec.commentfld, 0, zonessec_ctx.comment);

    vrmr_fatal_if(field_num != zonessec_ctx.edit_zone.n_fields);
    zonessec_ctx.edit_zone.fields[zonessec_ctx.edit_zone.n_fields] = NULL;

    /* create the window and panel */
    zonessec_ctx.edit_zone.win = create_newwin(height, width, starty, startx,
            gettext("Edit Zone: Zone"), vccnf.color_win);
    vrmr_fatal_if_null(zonessec_ctx.edit_zone.win);
    zonessec_ctx.edit_zone.panel[0] = new_panel(zonessec_ctx.edit_zone.win);
    vrmr_fatal_if_null(zonessec_ctx.edit_zone.panel[0]);
    keypad(zonessec_ctx.edit_zone.win, TRUE);

    /* set the options */
    for (i = 0; i < zonessec_ctx.edit_zone.n_fields; i++) {
        set_field_back(zonessec_ctx.edit_zone.fields[i], vccnf.color_win_rev);
        field_opts_off(zonessec_ctx.edit_zone.fields[i], O_AUTOSKIP);
        set_field_status(zonessec_ctx.edit_zone.fields[i], FALSE);
    }
    set_field_back(ZoneSec.activelabelfld, vccnf.color_win);
    set_field_back(ZoneSec.commentlabelfld, vccnf.color_win);

    /* Create the form and post it */
    zonessec_ctx.edit_zone.form = new_form(zonessec_ctx.edit_zone.fields);
    vrmr_fatal_if_null(zonessec_ctx.edit_zone.form);
    scale_form(zonessec_ctx.edit_zone.form, &rows, &cols);
    set_form_win(zonessec_ctx.edit_zone.form, zonessec_ctx.edit_zone.win);
    set_form_sub(zonessec_ctx.edit_zone.form,
            derwin(zonessec_ctx.edit_zone.win, rows, cols, 1, 2));
    post_form(zonessec_ctx.edit_zone.form);

    /* draw labels and other information */
    mvwprintw(zonessec_ctx.edit_zone.win, 1, 2, "%s: %s", gettext("Name"),
            zone_ptr->name);

    mvwprintw(zonessec_ctx.edit_zone.win, 3, 35, "%s", gettext("Networks"));
    mvwprintw(zonessec_ctx.edit_zone.win, 3, 45, "%4d",
            vrmr_count_zones(zones, VRMR_TYPE_NETWORK, NULL, zone_ptr->name));
    mvwprintw(zonessec_ctx.edit_zone.win, 4, 35, "%s", gettext("Hosts"));
    mvwprintw(zonessec_ctx.edit_zone.win, 4, 45, "%4d",
            vrmr_count_zones(zones, VRMR_TYPE_HOST, NULL, zone_ptr->name));
    mvwprintw(zonessec_ctx.edit_zone.win, 5, 35, "%s", gettext("Groups"));
    mvwprintw(zonessec_ctx.edit_zone.win, 5, 45, "%4d",
            vrmr_count_zones(zones, VRMR_TYPE_GROUP, NULL, zone_ptr->name));

    /* draw and set cursor */
    wrefresh(zonessec_ctx.edit_zone.win);
    pos_form_cursor(zonessec_ctx.edit_zone.form);

    update_panels();
    doupdate();
}

static int edit_zone_zone_save(
        struct vrmr_ctx *vctx, struct vrmr_zone *zone_ptr)
{
    int retval = 0, active = 0;
    size_t i = 0;

    /* safety */
    vrmr_fatal_if_null(zone_ptr);

    /* check for changed fields */
    for (i = 0; i < zonessec_ctx.edit_zone.n_fields; i++) {
        /* check is field is changed */
        if (field_status(zonessec_ctx.edit_zone.fields[i]) == FALSE)
            continue;

        /* active */
        if (zonessec_ctx.edit_zone.fields[i] == ZoneSec.activefld) {
            zone_ptr->status = VRMR_ST_CHANGED;

            active = zone_ptr->active;

            if (strncasecmp(field_buffer(zonessec_ctx.edit_zone.fields[i], 0),
                        STR_YES, StrLen(STR_YES)) == 0) {
                zone_ptr->active = TRUE;
            } else {
                zone_ptr->active = FALSE;
            }

            /* save to backend */
            if (vctx->zf->tell(vctx->zone_backend, zone_ptr->name, "ACTIVE",
                        zone_ptr->active ? "Yes" : "No", 1,
                        VRMR_TYPE_ZONE) < 0) {
                vrmr_error(-1, VR_ERR, gettext("saving to backend failed"));
                retval = -1;
            }

            /* for the log */
            vrmr_audit("%s '%s' %s: %s %s '%s' (%s: '%s').", STR_ZONE,
                    zone_ptr->name, STR_HAS_BEEN_CHANGED, STR_ACTIVE,
                    STR_IS_NOW_SET_TO, zone_ptr->active ? STR_YES : STR_NO,
                    STR_WAS, active ? STR_YES : STR_NO);
        }
        /* comment */
        else if (zonessec_ctx.edit_zone.fields[i] == ZoneSec.commentfld) {
            /* save the comment field to the backend */
            if (vctx->zf->tell(vctx->zone_backend, zone_ptr->name, "COMMENT",
                        field_buffer(zonessec_ctx.edit_zone.fields[i], 0), 1,
                        VRMR_TYPE_ZONE) < 0) {
                vrmr_error(-1, VR_ERR, gettext("saving to backend failed"));
                retval = -1;
            }

            /* example: "network 'ext' has been changed: the comment was
             * changed." */
            vrmr_audit("%s '%s' %s: %s.", STR_ZONE, zone_ptr->name,
                    STR_HAS_BEEN_CHANGED, STR_COMMENT_CHANGED);
        } else {
            vrmr_fatal("unknown field");
        }
    }
    return (retval);
}

static void edit_zone_zone_destroy(void)
{
    size_t i = 0;

    unpost_form(zonessec_ctx.edit_zone.form);
    free_form(zonessec_ctx.edit_zone.form);
    for (i = 0; i < zonessec_ctx.edit_zone.n_fields; i++) {
        free_field(zonessec_ctx.edit_zone.fields[i]);
    }
    free(zonessec_ctx.edit_zone.fields);
    del_panel(zonessec_ctx.edit_zone.panel[0]);
    destroy_win(zonessec_ctx.edit_zone.win);
    // clear comment string
    strcpy(zonessec_ctx.comment, "");
}

/*  edit_zone_zone

    Edits a zone!

    Returncodes:
        0: ok
        -1: error
*/
static int edit_zone_zone(
        struct vrmr_ctx *vctx, struct vrmr_zones *zones, char *name)
{
    int ch,                  /* for the keys */
            not_defined = 0, /* 1 is a key is defined */
            quit = 0, retval = 0;
    struct vrmr_zone *zone_ptr = NULL;
    int height, width, startx, starty;
    FIELD *cur = NULL, *prev = NULL;
    char *key_choices[] = {"F12", "F10"};
    int key_choices_n = 2;
    char *cmd_choices[] = {gettext("help"), gettext("back")};
    int cmd_choices_n = 2;

    /* safety */
    vrmr_fatal_if_null(name);
    vrmr_fatal_if_null(zones);

    height = 20;
    width = 54;
    /* place on the same y as zones list */
    VrWinGetOffset(
            -1, -1, height, width, 4, zonessec_ctx.z_xre + 1, &starty, &startx);

    /* look for the zone in the list */
    zone_ptr = vrmr_search_zonedata(zones, name);
    vrmr_fatal_if_null(zone_ptr);

    /* setup the window and fields */
    edit_zone_zone_init(
            vctx, zones, name, height, width, starty, startx, zone_ptr);

    cur = current_field(zonessec_ctx.edit_zone.form);

    draw_top_menu(top_win, gettext("Edit Zone"), key_choices_n, key_choices,
            cmd_choices_n, cmd_choices);

    update_panels();
    doupdate();

    /* Loop through to get user requests/commands */
    while (quit == 0) {
        draw_field_active_mark(cur, prev, zonessec_ctx.edit_zone.win,
                zonessec_ctx.edit_zone.form, vccnf.color_win_mark | A_BOLD);

        not_defined = 0;

        /* get user input */
        ch = wgetch(zonessec_ctx.edit_zone.win);

        /* user fields */

        /* comment */
        if (cur == ZoneSec.commentfld) {
            if (nav_field_comment(zonessec_ctx.edit_zone.form, ch) < 0)
                not_defined = 1;
        }
        /* active */
        else if (cur == ZoneSec.activefld) {
            if (nav_field_yesno(zonessec_ctx.edit_zone.form, ch) < 0)
                not_defined = 1;
        } else
            not_defined = 1;

        /* keys special for this window */
        if (not_defined == 1) {
            switch (ch) {
                case KEY_DOWN:
                case 10: // enter
                case 9:  // tab
                    form_driver_wrap(
                            zonessec_ctx.edit_zone.form, REQ_NEXT_FIELD);
                    form_driver_wrap(zonessec_ctx.edit_zone.form, REQ_BEG_LINE);
                    break;

                case KEY_UP:
                    // Go to previous field
                    form_driver_wrap(
                            zonessec_ctx.edit_zone.form, REQ_PREV_FIELD);
                    form_driver_wrap(zonessec_ctx.edit_zone.form, REQ_BEG_LINE);
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
                    print_help(":[VUURMUUR:ZONES:ZONE:EDIT]:");
                    break;
            }
        }

        /* set current field to prev */
        prev = cur;
        cur = current_field(zonessec_ctx.edit_zone.form);

        /* draw and set cursor */
        wrefresh(zonessec_ctx.edit_zone.win);
        pos_form_cursor(zonessec_ctx.edit_zone.form);
    }

    /* save changes (if any) */
    if (edit_zone_zone_save(vctx, zone_ptr) < 0)
        retval = -1;

    /* cleanup */
    edit_zone_zone_destroy();
    update_panels();
    doupdate();

    status_print(status_win, gettext("Ready."));
    return (retval);
}

static void zones_section_init(struct vrmr_zones *zones)
{
    size_t i = 0;
    struct vrmr_zone *zone_ptr = NULL;
    int height, width, startx, starty, maxy;
    size_t zones_cnt = 0;
    struct vrmr_list_node *d_node = NULL;

    vrmr_fatal_if_null(zones);

    maxy = getmaxy(stdscr);

    /* count how many zones there are */
    for (d_node = zones->list.top; d_node; d_node = d_node->next) {
        vrmr_fatal_if_null(d_node->data);
        zone_ptr = d_node->data;

        if (zone_ptr->type == VRMR_TYPE_ZONE)
            zones_cnt++;
    }
    zonessec_ctx.zone_n = zones_cnt;
    i = zones_cnt - 1;

    zonessec_ctx.zoneitems =
            (ITEM **)calloc(zonessec_ctx.zone_n + 1, sizeof(ITEM *));
    vrmr_fatal_alloc("calloc", zonessec_ctx.zoneitems);

    for (d_node = zones->list.bot; d_node; d_node = d_node->prev) {
        vrmr_fatal_if_null(d_node->data);
        zone_ptr = d_node->data;

        if (zone_ptr->type == VRMR_TYPE_ZONE) {
            zonessec_ctx.zoneitems[i] = new_item(zone_ptr->name, NULL);
            vrmr_fatal_if_null(zonessec_ctx.zoneitems[i]);
            i--;
        }
    }
    zonessec_ctx.zoneitems[zonessec_ctx.zone_n] = (ITEM *)NULL;

    if (zonessec_ctx.zone_n > 0) {
        zonessec_ctx.z_top = zonessec_ctx.zoneitems[0];
        zonessec_ctx.z_bot = zonessec_ctx.zoneitems[zonessec_ctx.zone_n - 1];
    } else {
        zonessec_ctx.z_top = NULL;
        zonessec_ctx.z_bot = NULL;
    }

    zonessec_ctx.menu = new_menu((ITEM **)zonessec_ctx.zoneitems);
    vrmr_fatal_if_null(zonessec_ctx.menu);

    height = (int)(zonessec_ctx.zone_n + 9);
    width = 45;
    startx = 1;
    starty = 4;

    if (maxy < starty + height + 4) {
        starty = 4;
        height = maxy - (2 * starty);
    }

    zonessec_ctx.z_yle = starty + height;
    zonessec_ctx.z_xre = startx + width;

    zonessec_ctx.win = newwin(height, width, starty, startx);
    vrmr_fatal_if_null(zonessec_ctx.win);
    zonessec_ctx.panel[0] = new_panel(zonessec_ctx.win);
    vrmr_fatal_if_null(zonessec_ctx.panel[0]);
    wbkgd(zonessec_ctx.win, vccnf.color_win);
    keypad(zonessec_ctx.win, TRUE);

    set_menu_win(zonessec_ctx.menu, zonessec_ctx.win);
    set_menu_sub(zonessec_ctx.menu,
            derwin(zonessec_ctx.win, height - 8, width - 2, 3, 1));
    set_menu_format(zonessec_ctx.menu, height - 9, 1);

    box(zonessec_ctx.win, 0, 0);
    print_in_middle(
            zonessec_ctx.win, 1, 0, width, gettext("Zones"), vccnf.color_win);
    mvwaddch(zonessec_ctx.win, 2, 0, ACS_LTEE);
    mvwhline(zonessec_ctx.win, 2, 1, ACS_HLINE, width - 2);
    mvwaddch(zonessec_ctx.win, 2, width - 1, ACS_RTEE);

    set_menu_back(zonessec_ctx.menu, vccnf.color_win);
    set_menu_fore(zonessec_ctx.menu, vccnf.color_win_rev);
    post_menu(zonessec_ctx.menu);

    mvwaddch(zonessec_ctx.win, height - 6, 0, ACS_LTEE);
    mvwhline(zonessec_ctx.win, height - 6, 1, ACS_HLINE, width - 2);
    mvwaddch(zonessec_ctx.win, height - 6, width - 1, ACS_RTEE);

    /* print labels */
    mvwprintw(zonessec_ctx.win, height - 5, 2, "<RET> %s",
            gettext("to enter the networks of this zone"));
    mvwprintw(zonessec_ctx.win, height - 4, 2, "<INS> %s", STR_NEW);
    mvwprintw(zonessec_ctx.win, height - 3, 2, "<DEL> %s", STR_REMOVE);
    mvwprintw(zonessec_ctx.win, height - 2, 2, "< e > %s", STR_EDIT);

    /* create the top and bottom fields */
    zonessec_ctx.z_win_top = newwin(1, 6, starty + 2, startx + width - 8);
    vrmr_fatal_if_null(zonessec_ctx.z_win_top);
    wbkgd(zonessec_ctx.z_win_top, vccnf.color_win);
    zonessec_ctx.z_panel_top[0] = new_panel(zonessec_ctx.z_win_top);
    /* TRANSLATORS: max 4 chars */
    wprintw(zonessec_ctx.z_win_top, "(%s)", gettext("more"));
    hide_panel(zonessec_ctx.z_panel_top[0]);

    zonessec_ctx.z_win_bot =
            newwin(1, 6, starty + height - 6, startx + width - 8);
    vrmr_fatal_if_null(zonessec_ctx.z_win_bot);
    wbkgd(zonessec_ctx.z_win_bot, vccnf.color_win);
    zonessec_ctx.z_panel_bot[0] = new_panel(zonessec_ctx.z_win_bot);
    /* TRANSLATORS: max 4 chars */
    wprintw(zonessec_ctx.z_win_bot, "(%s)", gettext("more"));
    hide_panel(zonessec_ctx.z_panel_bot[0]);

    update_panels();
    doupdate();
}

static void zones_section_destroy(void)
{
    size_t i = 0;

    unpost_menu(zonessec_ctx.menu);
    free_menu(zonessec_ctx.menu);
    for (i = 0; i < zonessec_ctx.zone_n; ++i)
        free_item(zonessec_ctx.zoneitems[i]);
    free(zonessec_ctx.zoneitems);
    del_panel(zonessec_ctx.panel[0]);
    destroy_win(zonessec_ctx.win);
    del_panel(zonessec_ctx.z_panel_top[0]);
    destroy_win(zonessec_ctx.z_win_top);
    del_panel(zonessec_ctx.z_panel_bot[0]);
    destroy_win(zonessec_ctx.z_win_bot);
}

int zones_section(struct vrmr_ctx *vctx, struct vrmr_zones *zones,
        struct vrmr_interfaces *interfaces, struct vrmr_rules *rules,
        struct vrmr_blocklist *blocklist, struct vrmr_regex *reg)
{
    int ch = 0, quit = 0, reload = 0, result = 0, retval = 0;
    char *vrmr_new_zone_ptr = NULL, save_zone_name[VRMR_MAX_ZONE] = "";
    ITEM *cur = NULL;

    /* top menu */
    char *key_choices[] = {"F12", "INS", "DEL", "r", "RET", "e", "F10"};
    int key_choices_n = 7;
    char *cmd_choices[] = {gettext("help"), gettext("new"), gettext("del"),
            gettext("rename"), gettext("open"), gettext("edit"),
            gettext("back")};
    int cmd_choices_n = 7;

    /* safety */
    vrmr_fatal_if_null(reg);
    vrmr_fatal_if_null(interfaces);
    vrmr_fatal_if_null(zones);

    zones_section_init(zones);

    draw_top_menu(top_win, gettext("Zones"), key_choices_n, key_choices,
            cmd_choices_n, cmd_choices);

    while (quit == 0) {
        if (reload == 1) {
            zones_section_destroy();
            zones_section_init(zones);
            reload = 0;
        }

        while (quit == 0 && reload == 0) {
            if (zonessec_ctx.z_top != NULL && !item_visible(zonessec_ctx.z_top))
                show_panel(zonessec_ctx.z_panel_top[0]);
            else
                hide_panel(zonessec_ctx.z_panel_top[0]);

            if (zonessec_ctx.z_bot != NULL && !item_visible(zonessec_ctx.z_bot))
                show_panel(zonessec_ctx.z_panel_bot[0]);
            else
                hide_panel(zonessec_ctx.z_panel_bot[0]);

            update_panels();
            doupdate();

            /* restore the cursor */
            pos_menu_cursor(zonessec_ctx.menu);

            ch = wgetch(zonessec_ctx.win);

            switch (ch) {
                case 27:
                case KEY_F(10):
                case 'q':
                case 'Q':
                    quit = 1;
                    break;

                case 'r':
                case 'R':

                    cur = current_item(zonessec_ctx.menu);
                    if (cur) {
                        vrmr_new_zone_ptr = input_box(VRMR_MAX_HOST,
                                gettext("Rename Zone"),
                                gettext("Enter the new name of the zone"));
                        if (vrmr_new_zone_ptr != NULL) {
                            if (vrmr_validate_zonename(vrmr_new_zone_ptr, 1,
                                        NULL, NULL, NULL, reg->zone_part,
                                        VRMR_VERBOSE) == 0) {
                                if (zones_rename_network_zone(vctx, zones,
                                            rules, blocklist,
                                            (char *)item_name(cur),
                                            vrmr_new_zone_ptr, VRMR_TYPE_ZONE,
                                            reg) == 0) {
                                    /* we have a renamed network, so reload the
                                     * menu */
                                    reload = 1;
                                }
                            }

                            free(vrmr_new_zone_ptr);
                        }
                    }
                    break;

                case KEY_IC: // insert
                case 'i':
                case 'I':

                    vrmr_new_zone_ptr =
                            input_box(VRMR_MAX_ZONE, gettext("New Zone"),
                                    gettext("Enter the name of the new zone"));
                    if (vrmr_new_zone_ptr != NULL) {
                        if (vrmr_validate_zonename(vrmr_new_zone_ptr, 1, NULL,
                                    NULL, NULL, reg->zone_part,
                                    VRMR_VERBOSE) == 0) {
                            if (vrmr_new_zone(vctx, zones, vrmr_new_zone_ptr,
                                        VRMR_TYPE_ZONE) < 0) {
                                vrmr_error(
                                        result, VR_ERR, "adding zone failed");
                            } else {
                                vrmr_audit("%s '%s' %s.", STR_ZONE,
                                        vrmr_new_zone_ptr,
                                        STR_HAS_BEEN_CREATED);

                                if (edit_zone_zone(vctx, zones,
                                            vrmr_new_zone_ptr) < 0) {
                                    retval = -1;
                                    quit = 1;
                                }

                                draw_top_menu(top_win, gettext("Zones"),
                                        key_choices_n, key_choices,
                                        cmd_choices_n, cmd_choices);
                            }
                        }
                        free(vrmr_new_zone_ptr);
                    }
                    reload = 1;
                    break;

                case KEY_DC: // delete
                case 'd':
                case 'D':

                    cur = current_item(zonessec_ctx.menu);
                    if (cur) {
                        if (vrmr_count_zones(zones, VRMR_TYPE_NETWORK, NULL,
                                    (char *)item_name(cur)) <= 0 &&
                                vrmr_count_zones(zones, VRMR_TYPE_HOST, NULL,
                                        (char *)item_name(cur)) <= 0 &&
                                vrmr_count_zones(zones, VRMR_TYPE_GROUP, NULL,
                                        (char *)item_name(cur)) <= 0) {
                            if (confirm(gettext("Delete"),
                                        gettext("This zone?"),
                                        vccnf.color_win_note,
                                        vccnf.color_win_note_rev | A_BOLD,
                                        0) == 1) {
                                /* for logging */
                                (void)strlcpy(save_zone_name,
                                        (char *)item_name(cur),
                                        sizeof(save_zone_name));

                                result = vrmr_delete_zone(vctx, zones,
                                        (char *)item_name(cur), VRMR_TYPE_ZONE);
                                if (result < 0) {
                                    vrmr_error(result, VR_ERR,
                                            gettext("deleting zone failed"));
                                } else {
                                    vrmr_audit("%s '%s' %s.", STR_ZONE,
                                            save_zone_name,
                                            STR_HAS_BEEN_DELETED);

                                    reload = 1;
                                }
                            }
                        } else {
                            vrmr_error(-1, VR_ERR,
                                    gettext("unable to delete: zone not "
                                            "empty."));
                        }
                    }
                    break;

                case KEY_DOWN:
                    menu_driver(zonessec_ctx.menu, REQ_DOWN_ITEM);
                    break;
                case KEY_UP:
                    menu_driver(zonessec_ctx.menu, REQ_UP_ITEM);
                    break;
                case KEY_NPAGE:
                    if (menu_driver(zonessec_ctx.menu, REQ_SCR_DPAGE) != E_OK) {
                        while (menu_driver(zonessec_ctx.menu, REQ_DOWN_ITEM) ==
                                E_OK)
                            ;
                    }
                    break;
                case KEY_PPAGE:
                    if (menu_driver(zonessec_ctx.menu, REQ_SCR_UPAGE) != E_OK) {
                        while (menu_driver(zonessec_ctx.menu, REQ_UP_ITEM) ==
                                E_OK)
                            ;
                    }
                    break;
                case KEY_HOME:
                    menu_driver(zonessec_ctx.menu, REQ_FIRST_ITEM); // home
                    break;
                case KEY_END:
                    menu_driver(zonessec_ctx.menu, REQ_LAST_ITEM); // end
                    break;

                case 'e':
                case 'E':
                case 32:

                    cur = current_item(zonessec_ctx.menu);
                    if (cur) {
                        if (edit_zone_zone(
                                    vctx, zones, (char *)item_name(cur)) < 0) {
                            retval = -1;
                            quit = 1;
                        }

                        draw_top_menu(top_win, gettext("Zones"), key_choices_n,
                                key_choices, cmd_choices_n, cmd_choices);
                    }
                    break;

                case KEY_RIGHT:
                case 10:  // enter
                case 'b': // b - browse
                case 'B':

                    cur = current_item(zonessec_ctx.menu);
                    if (cur) {
                        char *n = (char *)item_name(cur);

                        zones_section_menu_networks(vctx, zones, interfaces,
                                rules, blocklist, n, reg);

                        draw_top_menu(top_win, gettext("Zones"), key_choices_n,
                                key_choices, cmd_choices_n, cmd_choices);
                    }
                    break;

                case KEY_F(12):
                case 'h':
                case 'H':
                case '?':
                    print_help(":[VUURMUUR:ZONES:ZONES]:");
                    break;
            }
        }
    }

    zones_section_destroy();

    update_panels();
    doupdate();

    status_print(status_win, gettext("Ready."));
    return (retval);
}

static void zones_blocklist_init(struct vrmr_blocklist *blocklist)
{
    int i = 0, result = 0;
    int height = 0, width = 0, startx = 0, starty = 0, maxx = 0, maxy = 0;
    struct vrmr_list_node *d_node = NULL;
    char *string = NULL;

    /* get the screensize */
    getmaxyx(stdscr, maxy, maxx);

    /* number of items */
    zonessec_ctx.host_n = blocklist->list.len;

    /* allow the menu items */
    zonessec_ctx.hostitems =
            (ITEM **)calloc(zonessec_ctx.host_n + 1, sizeof(ITEM *));
    vrmr_fatal_if_null(zonessec_ctx.hostitems);

    /* create the menu items */
    for (d_node = blocklist->list.top, i = 0; d_node;
            d_node = d_node->next, i++) {
        vrmr_fatal_if_null(d_node->data);
        string = d_node->data;

        zonessec_ctx.hostitems[i] = new_item(string, NULL);
        vrmr_fatal_if_null(zonessec_ctx.hostitems[i]);
    }
    zonessec_ctx.hostitems[zonessec_ctx.host_n] = (ITEM *)NULL;

    if (zonessec_ctx.host_n > 0) {
        zonessec_ctx.h_top = zonessec_ctx.hostitems[0];
        zonessec_ctx.h_bot = zonessec_ctx.hostitems[zonessec_ctx.host_n - 1];
    } else {
        zonessec_ctx.h_top = NULL;
        zonessec_ctx.h_bot = NULL;
    }

    /* now create the menu */
    zonessec_ctx.h_menu = new_menu((ITEM **)zonessec_ctx.hostitems);
    vrmr_fatal_if_null(zonessec_ctx.h_menu);

    /* now set the size of the window */
    height = (int)(zonessec_ctx.host_n + 7);
    width = VRMR_VRMR_MAX_HOST_NET_ZONE + 2;
    startx = 1;
    starty = 4;

    if (maxy < starty + height + 4) {
        starty = 4;
        height = maxy - (2 * starty);
    }

    if (maxx < startx + width + 3) {
        startx = 1;
        width = maxx - 2 * startx;
    }

    zonessec_ctx.h_win = newwin(height, width, starty, startx);
    vrmr_fatal_if_null(zonessec_ctx.h_win);
    wbkgd(zonessec_ctx.h_win, vccnf.color_win);
    keypad(zonessec_ctx.h_win, TRUE);
    box(zonessec_ctx.h_win, 0, 0);
    print_in_middle(zonessec_ctx.h_win, 1, 0, width, gettext("BlockList"),
            vccnf.color_win);
    wrefresh(zonessec_ctx.h_win);

    zonessec_ctx.h_panel[0] = new_panel(zonessec_ctx.h_win);
    vrmr_fatal_if_null(zonessec_ctx.h_panel[0]);

    set_menu_win(zonessec_ctx.h_menu, zonessec_ctx.h_win);
    set_menu_sub(zonessec_ctx.h_menu,
            derwin(zonessec_ctx.h_win, height - 6, width - 2, 3, 1));
    set_menu_format(zonessec_ctx.h_menu, height - 7, 1);

    mvwaddch(zonessec_ctx.h_win, 2, 0, ACS_LTEE);
    mvwhline(zonessec_ctx.h_win, 2, 1, ACS_HLINE, width - 2);
    mvwaddch(zonessec_ctx.h_win, 2, width - 1, ACS_RTEE);

    set_menu_back(zonessec_ctx.h_menu, vccnf.color_win);
    set_menu_fore(zonessec_ctx.h_menu, vccnf.color_win_rev);

    result = post_menu(zonessec_ctx.h_menu);
    vrmr_fatal_if(result != E_OK && result != E_NOT_CONNECTED);

    mvwaddch(zonessec_ctx.h_win, height - 4, 0, ACS_LTEE);
    mvwhline(zonessec_ctx.h_win, height - 4, 1, ACS_HLINE, width - 2);
    mvwaddch(zonessec_ctx.h_win, height - 4, width - 1, ACS_RTEE);

    mvwprintw(zonessec_ctx.h_win, height - 3, 1, "<INS> %s", STR_NEW);
    mvwprintw(zonessec_ctx.h_win, height - 2, 1, "<DEL> %s", STR_REMOVE);

    /* create the top and bottom fields */
    zonessec_ctx.h_win_top = newwin(1, 6, starty + 2, width - 8);
    vrmr_fatal_if_null(zonessec_ctx.h_win_top);
    wbkgd(zonessec_ctx.h_win_top, vccnf.color_win);
    zonessec_ctx.h_panel_top[0] = new_panel(zonessec_ctx.h_win_top);
    /* TRANSLATORS: max 4 chars */
    wprintw(zonessec_ctx.h_win_top, "(%s)", gettext("more"));
    hide_panel(zonessec_ctx.h_panel_top[0]);

    zonessec_ctx.h_win_bot = newwin(1, 6, starty + height - 4, width - 8);
    vrmr_fatal_if_null(zonessec_ctx.h_win_bot);
    wbkgd(zonessec_ctx.h_win_bot, vccnf.color_win);
    zonessec_ctx.h_panel_bot[0] = new_panel(zonessec_ctx.h_win_bot);
    /* TRANSLATORS: max 4 chars */
    wprintw(zonessec_ctx.h_win_bot, "(%s)", gettext("more"));
    hide_panel(zonessec_ctx.h_panel_bot[0]);

    update_panels();
    doupdate();
}

static void zones_blocklist_destroy(void)
{
    size_t i = 0;

    unpost_menu(zonessec_ctx.h_menu);
    free_menu(zonessec_ctx.h_menu);
    for (i = 0; i < zonessec_ctx.host_n; ++i)
        free_item(zonessec_ctx.hostitems[i]);
    free(zonessec_ctx.hostitems);
    del_panel(zonessec_ctx.h_panel[0]);
    destroy_win(zonessec_ctx.h_win);
    del_panel(zonessec_ctx.h_panel_top[0]);
    destroy_win(zonessec_ctx.h_win_top);
    del_panel(zonessec_ctx.h_panel_bot[0]);
    destroy_win(zonessec_ctx.h_win_bot);
}

int zones_blocklist_add_one(
        struct vrmr_blocklist *blocklist, struct vrmr_zones *zones)
{
    char *new_ipaddress = NULL,
         *choices[] = {gettext("IPAddress"), gettext("Host"), gettext("Group")},
         *choice_ptr = NULL, choice_type = 0, **zone_choices;
    size_t i = 0;
    char changes = TRUE;
    struct vrmr_zone *zone_ptr = NULL;
    struct vrmr_list_node *d_node = NULL;

    /* safety */
    vrmr_fatal_if_null(blocklist);
    vrmr_fatal_if_null(zones);

    choice_ptr = selectbox(gettext("Select"),
            gettext("What do you want to block?"), 3, choices, 1, NULL);
    if (choice_ptr != NULL) {
        if (strcasecmp(choice_ptr, gettext("IPAddress")) == 0) {
            new_ipaddress = input_box(16, gettext("New IPAddress"),
                    gettext("Enter the IPAddress to be blocked"));
            if (new_ipaddress != NULL) {
                /* validate ip */
                if (vrmr_check_ipv4address(NULL, NULL, new_ipaddress, 1) != 1) {
                    vrmr_warning(VR_WARN,
                            gettext("'%s' is not a valid ipaddress."),
                            new_ipaddress);

                    free(new_ipaddress);
                    new_ipaddress = NULL;
                } else {
                    /* add to list */
                    if (vrmr_blocklist_add_one(zones, blocklist,
                                /*load_ips*/ FALSE, /*no_refcnt*/ FALSE,
                                new_ipaddress) < 0) {
                        vrmr_error(-1, VR_INTERR, "blocklist_add_one() failed");
                        return (-1);
                    }

                    vrmr_audit("%s '%s' %s.", STR_IPADDRESS, new_ipaddress,
                            STR_HAS_BEEN_ADDED_TO_THE_BLOCKLIST);

                    changes = TRUE;
                    free(new_ipaddress);
                    new_ipaddress = NULL;
                }
            }
        } else if (strcasecmp(choice_ptr, gettext("Host")) == 0 ||
                   strcasecmp(choice_ptr, gettext("Group")) == 0) {
            (void)vrmr_list_setup(&zonessec_ctx.group_desc_list, free);

            /* get the type */
            if (strcasecmp(choice_ptr, gettext("Host")) == 0)
                choice_type = VRMR_TYPE_HOST;
            else
                choice_type = VRMR_TYPE_GROUP;

            for (d_node = zones->list.top, i = 0; d_node;
                    d_node = d_node->next) {
                vrmr_fatal_if_null(d_node->data);
                zone_ptr = d_node->data;

                if (zone_ptr->type == choice_type) {
                    i++;
                }
            }

            if (i == 0) {
                vrmr_warning(VR_WARN, gettext("please create one or more "
                                              "hosts/groups first."));
                return (0);
            }

            zone_choices = calloc(i + 1, VRMR_VRMR_MAX_HOST_NET_ZONE);
            vrmr_fatal_alloc("calloc", zone_choices);

            for (d_node = zones->list.top, i = 0; d_node;
                    d_node = d_node->next) {
                vrmr_fatal_if_null(d_node->data);
                zone_ptr = d_node->data;

                if (zone_ptr->type == choice_type) {
                    zone_choices[i] = zone_ptr->name;
                    i++;
                }
            }
            zone_choices[i] = NULL;

            /* get the zone */
            char *hostgroup = NULL;
            if ((hostgroup = selectbox(gettext("Select"),
                         gettext("Select a host or group to block"), i,
                         zone_choices, 2, NULL))) {
                /* add to list */
                if (vrmr_blocklist_add_one(zones, blocklist, /*load_ips*/ FALSE,
                            /*no_refcnt*/ FALSE, hostgroup) < 0) {
                    vrmr_error(-1, VR_ERR,
                            gettext("adding host/group to list failed"));
                    return (-1);
                }

                if (choice_type == VRMR_TYPE_HOST)
                    vrmr_audit("%s '%s' %s.", STR_HOST, hostgroup,
                            STR_HAS_BEEN_ADDED_TO_THE_BLOCKLIST);
                else
                    vrmr_audit("%s '%s' %s.", STR_GROUP, hostgroup,
                            STR_HAS_BEEN_ADDED_TO_THE_BLOCKLIST);

                free(hostgroup);
                changes = TRUE;
            }

            free(zone_choices);
            zone_choices = NULL;
        }
        free(choice_ptr);
    }

    return (changes);
}

int zones_blocklist(struct vrmr_ctx *vctx, struct vrmr_blocklist *blocklist,
        struct vrmr_zones *zones, struct vrmr_regex *reg)
{
    int ch = 0, quit = 0, reload = 0, retval = 0;
    char changes = 0;
    char *itemname = NULL, saveitemname[VRMR_VRMR_MAX_HOST_NET_ZONE] = "";
    ITEM *cur = NULL;
    /* top menu */
    char *key_choices[] = {"F12", "INS", "DEL", "F10"};
    int key_choices_n = 4;
    char *cmd_choices[] = {
            gettext("help"), gettext("new"), gettext("del"), gettext("back")};
    int cmd_choices_n = 4;

    /* safety */
    vrmr_fatal_if_null(blocklist);
    vrmr_fatal_if_null(zones);
    vrmr_fatal_if_null(reg);

    /* setup */
    zones_blocklist_init(blocklist);
    draw_top_menu(top_win, gettext("BlockList"), key_choices_n, key_choices,
            cmd_choices_n, cmd_choices);

    /* enter the loop */
    while (quit == 0) {
        /* reload the menu */
        if (reload == 1) {
            /* first destroy */
            zones_blocklist_destroy();
            /* and setup again */
            zones_blocklist_init(blocklist);
            /* we are done with reloading */
            reload = 0;
        }

        /* loop for catching user input */
        while (quit == 0 && reload == 0) {
            if (zonessec_ctx.h_top != NULL && !item_visible(zonessec_ctx.h_top))
                show_panel(zonessec_ctx.h_panel_top[0]);
            else
                hide_panel(zonessec_ctx.h_panel_top[0]);

            if (zonessec_ctx.h_bot != NULL && !item_visible(zonessec_ctx.h_bot))
                show_panel(zonessec_ctx.h_panel_bot[0]);
            else
                hide_panel(zonessec_ctx.h_panel_bot[0]);

            update_panels();
            doupdate();

            /* restore the cursor */
            pos_menu_cursor(zonessec_ctx.h_menu);

            /* get the user input */
            ch = wgetch(zonessec_ctx.h_win);
            switch (ch) {
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

                    if (zones_blocklist_add_one(blocklist, zones) == 1) {
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

                    if (blocklist->list.len > 0) {
                        if (confirm(gettext("Remove"),
                                    gettext("This IP/Host/Group?"),
                                    vccnf.color_win_note,
                                    vccnf.color_win_note_rev | A_BOLD,
                                    0) == 1) {
                            /* get the current item */
                            cur = current_item(zonessec_ctx.h_menu);
                            vrmr_fatal_if_null(cur);

                            itemname = (char *)item_name(cur);
                            vrmr_fatal_if_null(itemname);

                            vrmr_debug(HIGH, "itemname to remove: '%s'.",
                                    itemname);

                            /* save the name */
                            (void)strlcpy(saveitemname, itemname,
                                    sizeof(saveitemname));

                            if (vrmr_blocklist_rem_one(
                                        zones, blocklist, itemname) == 0) {
                                vrmr_audit("'%s' %s.", saveitemname,
                                        STR_HAS_BEEN_REMOVED_FROM_THE_BLOCKLIST);

                                itemname = NULL;

                                changes = 1;
                                reload = 1;
                            }
                        }
                    }
                    break;

                case KEY_DOWN:
                    menu_driver(zonessec_ctx.h_menu, REQ_DOWN_ITEM);
                    break;
                case KEY_UP:
                    menu_driver(zonessec_ctx.h_menu, REQ_UP_ITEM);
                    break;
                case KEY_NPAGE:
                    if (menu_driver(zonessec_ctx.h_menu, REQ_SCR_DPAGE) !=
                            E_OK) {
                        while (menu_driver(zonessec_ctx.h_menu,
                                       REQ_DOWN_ITEM) == E_OK)
                            ;
                    }
                    break;
                case KEY_PPAGE:
                    if (menu_driver(zonessec_ctx.h_menu, REQ_SCR_UPAGE) !=
                            E_OK) {
                        while (menu_driver(zonessec_ctx.h_menu, REQ_UP_ITEM) ==
                                E_OK)
                            ;
                    }
                    break;
                case KEY_HOME:
                    menu_driver(zonessec_ctx.h_menu, REQ_FIRST_ITEM); // home
                    break;
                case KEY_END:
                    menu_driver(zonessec_ctx.h_menu, REQ_LAST_ITEM); // end
                    break;

                case KEY_F(12):
                case 'h':
                case 'H':
                case '?':
                    print_help(":[VUURMUUR:BLOCKLIST]:");
                    break;
            }
        }
    }

    if (changes) {
        vrmr_debug(HIGH, "changes and retval == 0 so save the list to disk.");

        if (vrmr_blocklist_save_list(vctx, &vctx->conf, blocklist) < 0)
            retval = -1;
    }

    zones_blocklist_destroy();

    update_panels();
    doupdate();

    status_print(status_win, gettext("Ready."));
    return (retval);
}
