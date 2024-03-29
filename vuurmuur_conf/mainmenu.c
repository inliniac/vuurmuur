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

static char last_vuurmuur_result = 1;
static char last_vuurmuur_log_result = 1;

static void mm_check_status_zones(
        /*@null@*/ struct vrmr_list *, struct vrmr_zones *);
static void mm_check_status_services(struct vrmr_services *);

static int mm_select_logfile(struct vrmr_ctx *vctx, struct vrmr_config *cnf,
        struct vrmr_zones *zones, struct vrmr_blocklist *blocklist,
        struct vrmr_interfaces *interfaces, struct vrmr_services *services)
{
    size_t i = 0, n_choices = 8;
    int ch = 0, quit = 0;
    ITEM **menu_items;
    MENU *main_menu;
    WINDOW *mainmenu_win;
    PANEL *menu_panels[1];
    /* top menu */
    const char *key_choices[] = {"F10"};
    int key_choices_n = 1;
    const char *cmd_choices[] = {gettext("back")};
    int cmd_choices_n = 1;

    /* menu */
    char *choice_ptr = NULL;

    const char *choices[] = {"Traffic.log", "Connections.log", "ConnNew.log",
            "Vuurmuur.log", "Audit.log", "Error.log", "Debug.log",
            gettext("Back"), NULL};

    char *descriptions[] = {" ", " ", " ", " ", " ", " ", " ", " ", NULL};

    int x = 40, y = 9 + (int)n_choices, startx = 0, starty = 0, maxx = 0,
        maxy = 0;

    // TODO null check

    getmaxyx(stdscr, maxy, maxx);
    startx = (maxx - x) / 2;
    starty = (maxy - y) / 2;

    menu_items = (ITEM **)calloc(n_choices + 1, sizeof(ITEM *));
    vrmr_fatal_alloc("calloc", menu_items);

    for (i = 0; i < n_choices; ++i) {
        menu_items[i] = new_item(choices[i], descriptions[i]);
    }
    menu_items[n_choices] = (ITEM *)NULL;
    main_menu = new_menu((ITEM **)menu_items);
    mainmenu_win = create_newwin(
            y, x, starty, startx, gettext("Logview"), vccnf.color_win);
    keypad(mainmenu_win, TRUE);
    wrefresh(mainmenu_win);
    menu_panels[0] = new_panel(mainmenu_win);

    // menu settings
    set_menu_win(main_menu, mainmenu_win);
    set_menu_sub(main_menu, derwin(mainmenu_win, y - 8, x - 12, 6, 6));
    set_menu_format(main_menu, y - 4, 1);
    set_menu_back(main_menu, vccnf.color_win);
    set_menu_fore(main_menu, vccnf.color_win_rev);
    post_menu(main_menu);

    // welcome message
    mvwprintw(mainmenu_win, 3, 6, gettext("Select a log to view."));
    draw_top_menu(top_win, gettext("Logview"), key_choices_n, key_choices,
            cmd_choices_n, cmd_choices);
    update_panels();
    doupdate();

    while (quit == 0) {
        show_panel(menu_panels[0]);

        ch = wgetch(mainmenu_win);
        switch (ch) {
            case 27:
            case 'Q':
            case 'q':
            case KEY_F(10):
                quit = 1;
                break;

            case KEY_DOWN:
                menu_driver(main_menu, REQ_DOWN_ITEM);
                break;

            case KEY_UP:
                menu_driver(main_menu, REQ_UP_ITEM);
                break;

            case KEY_RIGHT:
            case 32: // space
            case 10: // enter
            {
                ITEM *cur = current_item(main_menu);
                vrmr_fatal_if_null(cur);
                choice_ptr = strdup((char *)item_name(cur));
                break;
            }
        }

        if (choice_ptr != NULL) {
            hide_panel(menu_panels[0]);

            if (strncasecmp(choice_ptr, "traffic.log", 11) == 0) {
                logview_section(vctx, cnf, zones, blocklist, interfaces,
                        services, "traffic.log");
            } else if (strncasecmp(choice_ptr, "connections.log", 15) == 0) {
                logview_section(vctx, cnf, zones, blocklist, interfaces,
                        services, "connections.log");
            } else if (strncasecmp(choice_ptr, "connnew.log", 11) == 0) {
                logview_section(vctx, cnf, zones, blocklist, interfaces,
                        services, "connnew.log");
            } else if (strncasecmp(choice_ptr, "error.log", 9) == 0) {
                logview_section(vctx, cnf, zones, blocklist, interfaces,
                        services, "error.log");
            } else if (strncasecmp(choice_ptr, "audit.log", 9) == 0) {
                logview_section(vctx, cnf, zones, blocklist, interfaces,
                        services, "audit.log");
            } else if (strncasecmp(choice_ptr, "vuurmuur.log", 12) == 0) {
                logview_section(vctx, cnf, zones, blocklist, interfaces,
                        services, "vuurmuur.log");
            } else if (strncasecmp(choice_ptr, "debug.log", 9) == 0) {
                logview_section(vctx, cnf, zones, blocklist, interfaces,
                        services, "debug.log");
            } else if (strncasecmp(choice_ptr, gettext("Back"),
                               StrLen(gettext("Back"))) == 0) {
                quit = 1;
            }
            draw_top_menu(top_win, gettext("Logview"), key_choices_n,
                    key_choices, cmd_choices_n, cmd_choices);

            free(choice_ptr);
            choice_ptr = NULL;
        }
    }

    unpost_menu(main_menu);
    free_menu(main_menu);
    for (i = 0; i < n_choices; ++i)
        free_item(menu_items[i]);
    free(menu_items);
    del_panel(menu_panels[0]);
    destroy_win(mainmenu_win);
    update_panels();
    doupdate();
    return (0);
}

#if 0
static void
set_colors(vc_cnf *cnf)
{
    if(!cnf)
        return;

    init_pair(CP_WIN,      cnf->win_fore, cnf->win_back);
    init_pair(CP_WIN_MARK, COLOR_RED,     cnf->win_back);
    init_pair(CP_WIN_REV,  cnf->win_back, cnf->win_fore);

    cnf->color_win      = (chtype)COLOR_PAIR(CP_WIN);
    cnf->color_win_rev  = (chtype)COLOR_PAIR(CP_WIN_REV);
    cnf->color_win_mark = (chtype)COLOR_PAIR(CP_WIN_MARK);

    return;
}
#endif

static void mm_shm_connect_vuurmuur(void)
{
    /* first try to detach */
    if (vuurmuur_shmp != NULL)
        (void)shmdt(vuurmuur_shmp);

    /* reset */
    vuurmuur_shmid = -1;
    vuurmuur_semid = -1;
    vuurmuur_shmtable = NULL;
    vuurmuur_shmp = NULL;

    /* reconnect */
    vuurmuur_pid = get_vuurmuur_pid("/var/run/vuurmuur.pid", &vuurmuur_shmid);
    if (vuurmuur_shmid > 0) {
        /* attach to shared memory */
        vuurmuur_shmp = shmat(vuurmuur_shmid, 0, 0);
        if (vuurmuur_shmp == (char *)(-1)) {
            vrmr_error(-1, VR_ERR,
                    gettext("attaching to shared memory failed: %s."),
                    strerror(errno));
            vuurmuur_shmp = NULL;
        } else {
            vuurmuur_shmtable = (struct vrmr_shm_table *)vuurmuur_shmp;
            vuurmuur_semid = vuurmuur_shmtable->sem_id;

            /* now try to connect to the shared memory */
            if (vrmr_lock(vuurmuur_semid)) {
                vuurmuur_shmtable->configtool.connected = 1;
                snprintf(vuurmuur_shmtable->configtool.name,
                        sizeof(vuurmuur_shmtable->configtool.name),
                        "Vuurmuur_conf %s", version_string);
                vrmr_unlock(vuurmuur_semid);
            } else {
                // TODO: no detach here?
                vuurmuur_shmp = NULL;
            }
        }
    }
}

static void mm_shm_connect_vuurmuurlog(void)
{
    /* first try to detach */
    if (vuurmuurlog_shmp != NULL)
        (void)shmdt(vuurmuurlog_shmp);

    /* reset */
    vuurmuurlog_shmid = -1;
    vuurmuurlog_semid = -1;
    vuurmuurlog_shmtable = NULL;
    vuurmuurlog_shmp = NULL;

    vuurmuurlog_pid =
            get_vuurmuur_pid("/var/run/vuurmuur_log.pid", &vuurmuurlog_shmid);
    if (vuurmuurlog_shmid > 0) {
        /* attach to shared memory */
        vuurmuurlog_shmp = shmat(vuurmuurlog_shmid, 0, 0);
        if (vuurmuurlog_shmp == (char *)(-1)) {
            vrmr_error(-1, VR_ERR,
                    gettext("attaching to shared memory failed: %s."),
                    strerror(errno));
            vuurmuurlog_shmp = NULL;
        } else {
            vuurmuurlog_shmtable = (struct vrmr_shm_table *)vuurmuurlog_shmp;
            vuurmuurlog_semid = vuurmuurlog_shmtable->sem_id;

            /* now try to connect to the shared memory */
            if (vrmr_lock(vuurmuurlog_semid)) {
                vuurmuurlog_shmtable->configtool.connected = 1;
                snprintf(vuurmuurlog_shmtable->configtool.name,
                        sizeof(vuurmuurlog_shmtable->configtool.name),
                        "Vuurmuur_conf %s", version_string);
                vrmr_unlock(vuurmuurlog_semid);
            } else {
                vuurmuurlog_shmp = NULL;
            }
        }
    }
}

ATTR_FMT_PRINTF(3, 4)
static void queue_status_msg(
        /*@null@*/ struct vrmr_list *status_list, int status, const char *fmt,
        ...)
{
    char line[512] = "";
    va_list ap;

    if (status_list == NULL)
        return;

    va_start(ap, fmt);
    vsnprintf(line, sizeof(line), fmt, ap);
    va_end(ap);

    (void)read_helpline(status_list, line);
    if (status == -1)
        (void)read_helpline(status_list, gettext("(fail).\n"));
    else if (status == 0)
        (void)read_helpline(status_list, gettext("(warn).\n"));
    else
        (void)read_helpline(status_list, ".\n");

    /* one final newline */
    (void)read_helpline(status_list, "\n");
}

/*
 * TODO: check search script
 */
static void mm_check_status_settings(/*@null@*/ struct vrmr_list *status_list)
{
    FILE *fp = NULL;

    /* asume ok */
    vuurmuur_status.settings = 1;

    if (strcmp(vccnf.helpfile_location, "") == 0) {
        vuurmuur_status.settings = 0;
        queue_status_msg(status_list, vuurmuur_status.settings,
                gettext("- The path to the Vuurmuur helpfile was not "
                        "specified, please do so in the Vuurmuur_conf "
                        "Settings\n"));
    } else {
        if (!(fp = fopen(vccnf.helpfile_location, "r"))) {
            vuurmuur_status.settings = 0;
            queue_status_msg(status_list, vuurmuur_status.settings,
                    gettext("- Opening the helpfile failed. Please check the "
                            "file\n"));
        } else {
            fclose(fp);
        }
    }
}

static void mm_check_status_shm(/*@null@*/ struct vrmr_list *status_list)
{
    /* asume ok */
    vuurmuur_status.vuurmuur = 1;
    vuurmuur_status.vuurmuur_log = 1;

    if (last_vuurmuur_result == 0) {
        vuurmuur_status.vuurmuur = 0;
        queue_status_msg(status_list, vuurmuur_status.vuurmuur,
                gettext("- The last time the changes were applied, applying "
                        "the changes failed for Vuurmuur. Please check the "
                        "Error.log\n"));
    }
    if (last_vuurmuur_log_result == 0) {
        vuurmuur_status.vuurmuur_log = 0;
        queue_status_msg(status_list, vuurmuur_status.vuurmuur_log,
                gettext("- The last time the changes were applied, applying "
                        "the changes failed for Vuurmuur_log. Please check the "
                        "Error.log\n"));
    }

    /* shm connection with Vuurmuur */
    if (!vuurmuur_shmp) {
        vuurmuur_status.vuurmuur = -1;
        queue_status_msg(status_list, vuurmuur_status.vuurmuur,
                gettext("- No connection could be established with Vuurmuur. "
                        "Please make sure that it is running\n"));
    } else {
        if (!(vrmr_lock(vuurmuur_semid))) {
            vuurmuur_status.vuurmuur = -1;
            queue_status_msg(status_list, vuurmuur_status.vuurmuur,
                    gettext("- The connection with Vuurmuur seems to be lost. "
                            "Please make sure that it is running\n"));
        } else
            vrmr_unlock(vuurmuur_semid);
    }

    /* shm connection with Vuurmuur_log */
    if (!vuurmuurlog_shmp) {
        vuurmuur_status.vuurmuur_log = 0;
        queue_status_msg(status_list, vuurmuur_status.vuurmuur_log,
                gettext("- No connection could be established with "
                        "Vuurmuur_log. Please make sure that it is running\n"));
    } else {
        if (!(vrmr_lock(vuurmuurlog_semid))) {
            vuurmuur_status.vuurmuur_log = 0;
            queue_status_msg(status_list, vuurmuur_status.vuurmuur_log,
                    gettext("- The connection with Vuurmuur_log seems to be "
                            "lost. Please make sure that it is running\n"));
        } else
            vrmr_unlock(vuurmuurlog_semid);
    }
}

/*
    TODO:
        check if scripts dir exists
*/
static void mm_check_status_config(
        struct vrmr_config *conf, /*@null@*/ struct vrmr_list *status_list)
{
    /* asume ok when we start */
    vuurmuur_status.config = 1;

    if (strcmp(conf->iptables_location, "") == 0) {
        vuurmuur_status.config = -1;
        queue_status_msg(status_list, vuurmuur_status.config,
                gettext("- The path to the 'iptables'-command is not yet "
                        "specified. Please do so in the 'Vuurmuur Config' "
                        "section\n"));
    } else {
        if (!vrmr_check_iptables_command(
                    conf, conf->iptables_location, VRMR_IPTCHK_QUIET)) {
            vuurmuur_status.config = -1;
            queue_status_msg(status_list, vuurmuur_status.config,
                    gettext("- The path to the 'iptables'-command seems to be "
                            "wrong. There was an error while testing it. "
                            "Please check it in your system and correct it in "
                            "the 'Vuurmuur Config' section\n"));
        }
    }

    if (strcmp(conf->iptablesrestore_location, "") == 0) {
        vuurmuur_status.config = -1;
        queue_status_msg(status_list, vuurmuur_status.config,
                gettext("- The path to the 'iptables-restore'-command is "
                        "not yet specified. Please do so in the 'Vuurmuur "
                        "Config' section\n"));
    } else {
        if (!vrmr_check_iptablesrestore_command(
                    conf, conf->iptablesrestore_location, VRMR_IPTCHK_QUIET)) {
            vuurmuur_status.config = -1;
            queue_status_msg(status_list, vuurmuur_status.config,
                    gettext("- The path to the 'iptables-restore'-command "
                            "seems to be wrong. There was an error while "
                            "testing it. Please check it in your system "
                            "and correct it in the 'Vuurmuur Config' "
                            "section\n"));
        }
    }

#ifdef IPV6_ENABLED
    if (strcmp(conf->ip6tables_location, "") == 0) {
        vuurmuur_status.config = -1;
        queue_status_msg(status_list, vuurmuur_status.config,
                gettext("- The path to the 'ip6tables'-command is not yet "
                        "specified. Please do so in the 'Vuurmuur Config' "
                        "section\n"));
    } else {
        if (!vrmr_check_ip6tables_command(
                    conf, conf->ip6tables_location, VRMR_IPTCHK_QUIET)) {
            vuurmuur_status.config = -1;
            queue_status_msg(status_list, vuurmuur_status.config,
                    gettext("- The path to the 'ip6tables'-command seems to be "
                            "wrong. There was an error while testing it. "
                            "Please check it in your system and correct it in "
                            "the 'Vuurmuur Config' section\n"));
        }
    }

    if (strcmp(conf->ip6tablesrestore_location, "") == 0) {
        vuurmuur_status.config = -1;
        queue_status_msg(status_list, vuurmuur_status.config,
                gettext("- The path to the 'ip6tables-restore'-command is "
                        "not yet specified. Please do so in the 'Vuurmuur "
                        "Config' section\n"));
    } else {
        if (!vrmr_check_ip6tablesrestore_command(
                    conf, conf->ip6tablesrestore_location, VRMR_IPTCHK_QUIET)) {
            vuurmuur_status.config = -1;
            queue_status_msg(status_list, vuurmuur_status.config,
                    gettext("- The path to the 'ip6tables-restore'-command "
                            "seems to be wrong. There was an error while "
                            "testing it. Please check it in your system "
                            "and correct it in the 'Vuurmuur Config' "
                            "section\n"));
        }
    }
#endif

    if (strcmp(conf->tc_location, "") != 0) {
        if (!vrmr_check_tc_command(
                    conf, conf->tc_location, VRMR_IPTCHK_QUIET)) {
            vuurmuur_status.config = -1;
            queue_status_msg(status_list, vuurmuur_status.config,
                    gettext("- The path to the 'tc'-command seems to be wrong. "
                            "There was an error while testing it. Please check "
                            "it in your system and correct it in the 'Vuurmuur "
                            "Config' section\n"));
        }
    }
}

/*
 */
static void mm_check_status_services(struct vrmr_services *services)
{
    struct vrmr_list_node *d_node = NULL;
    struct vrmr_service *ser_ptr = NULL;

    vrmr_fatal_if_null(services);

    /* asume ok when we start */
    vuurmuur_status.services = 1;

    for (d_node = services->list.top; d_node; d_node = d_node->next) {
        vrmr_fatal_if_null(d_node->data);
        ser_ptr = d_node->data;

        if (ser_ptr->PortrangeList.len == 0) {
            vuurmuur_status.services = 0;

            queue_status_msg(&vuurmuur_status.StatusList,
                    vuurmuur_status.services,
                    gettext("- No portranges/protocols defined in service "
                            "'%s'\n"),
                    ser_ptr->name);
        }
    }
}

/*
 */
static void mm_check_status_rules(
        struct vrmr_config *conf, struct vrmr_rules *rules)
{
    struct vrmr_list_node *d_node = NULL;
    struct vrmr_rule *rule_ptr = NULL;
    char tc_location_not_set = FALSE;

    vrmr_fatal_if_null(rules);

    /* asume ok when we start */
    vuurmuur_status.rules = 1;
    vuurmuur_status.have_shape_rules = FALSE;

    if (strcmp(conf->tc_location, "") == 0)
        tc_location_not_set = TRUE;

    for (d_node = rules->list.top; d_node; d_node = d_node->next) {
        vrmr_fatal_if_null(d_node->data);
        rule_ptr = d_node->data;

        if (vrmr_is_shape_rule(rule_ptr->opt) == 1 &&
                rule_ptr->active == TRUE) {
            if (tc_location_not_set == TRUE) {
                queue_status_msg(&vuurmuur_status.StatusList,
                        vuurmuur_status.rules,
                        gettext("- Shaping rules present while the "
                                "'tc'-location is not set. Please set the "
                                "'tc'-location\n"));
                vuurmuur_status.rules = -1;
            }
            vuurmuur_status.have_shape_rules = TRUE;
            return;
        }
    }
}

/*

*/
static void mm_check_status_interfaces(/*@null@*/ struct vrmr_list *status_list,
        struct vrmr_interfaces *interfaces)
{
    struct vrmr_list_node *d_node = NULL;
    struct vrmr_interface *iface_ptr = NULL;
    char at_least_one_active = FALSE;
    char ipaddress[16] = "";
    int ipresult = 0;

    /* safety */
    vrmr_fatal_if_null(interfaces);

    /* asume ok when we start */
    vuurmuur_status.interfaces = 1;
    vuurmuur_status.have_shape_ifaces = FALSE;

    if (interfaces->list.len == 0) {
        vuurmuur_status.interfaces = 0;
        queue_status_msg(&vuurmuur_status.StatusList,
                vuurmuur_status.interfaces,
                gettext("- No interfaces are defined. Please define one or "
                        "more interfaces\n"));
    }

    for (d_node = interfaces->list.top; d_node; d_node = d_node->next) {
        vrmr_fatal_if_null(d_node->data);
        iface_ptr = d_node->data;

        if (iface_ptr->active == TRUE)
            at_least_one_active = TRUE;

        if (iface_ptr->device[0] == '\0') {
            vuurmuur_status.interfaces = 0;

            queue_status_msg(&vuurmuur_status.StatusList,
                    vuurmuur_status.interfaces,
                    gettext("- The interface '%s' does not have a device. "
                            "Please enter a device in the Interfaces "
                            "Section\n"),
                    iface_ptr->name);
        }

        if (iface_ptr->dynamic == TRUE) {
            /* now try to get the dynamic ipaddress */
            ipresult = vrmr_get_dynamic_ip(iface_ptr->device,
                    iface_ptr->ipv4.ipaddress,
                    sizeof(iface_ptr->ipv4.ipaddress));
            if (ipresult == 0) {
                /* set iface to down */
                iface_ptr->up = FALSE;

                /* clear the ip field */
                memset(iface_ptr->ipv4.ipaddress, 0,
                        sizeof(iface_ptr->ipv4.ipaddress));
            } else if (ipresult < 0) {
                vrmr_error(
                        -1, "Internal Error", "vrmr_get_dynamic_ip() failed");
                return;
            }
        }

        /* check the ip if we have one */
        if (iface_ptr->ipv4.ipaddress[0] != '\0') {
            if (vrmr_check_ipv4address(
                        NULL, NULL, iface_ptr->ipv4.ipaddress, 1) != 1) {
                vuurmuur_status.interfaces = 0;

                queue_status_msg(&vuurmuur_status.StatusList,
                        vuurmuur_status.interfaces,
                        gettext("- The ipaddress '%s' of interface '%s' is "
                                "invalid\n"),
                        iface_ptr->ipv4.ipaddress, iface_ptr->name);
            }
        }

        /* if the interface is up check the ipaddress with the ipaddress we know
         */
        if (iface_ptr->up == TRUE && iface_ptr->active == TRUE &&
                iface_ptr->device_virtual == FALSE) {
            ipresult = vrmr_get_dynamic_ip(
                    iface_ptr->device, ipaddress, sizeof(ipaddress));
            if (ipresult < 0) {
                vrmr_error(
                        -1, "Internal Error", "vrmr_get_dynamic_ip() failed");
                return;
            } else if (ipresult == 0) {
                /* down after all */
                iface_ptr->up = FALSE;

                vrmr_debug(MEDIUM, "interface '%s' is down after all.",
                        iface_ptr->name);
            } else {
                if (strcmp(ipaddress, iface_ptr->ipv4.ipaddress) != 0) {
                    vuurmuur_status.interfaces = 0;

                    queue_status_msg(&vuurmuur_status.StatusList,
                            vuurmuur_status.interfaces,
                            gettext("- The ipaddress '%s' of interface '%s' "
                                    "(%s) does not match the ipaddress of the "
                                    "actual interface (%s)\n"),
                            iface_ptr->ipv4.ipaddress, iface_ptr->name,
                            iface_ptr->device, ipaddress);
                }
            }
        }

        if (iface_ptr->shape == TRUE && iface_ptr->device_virtual == FALSE) {
            vuurmuur_status.have_shape_ifaces = TRUE;
        }
    }

    vrmr_debug(LOW, "vuurmuur_status.have_shape_ifaces: %s.",
            vuurmuur_status.have_shape_ifaces ? "Yes" : "No");
    vrmr_debug(LOW, "vuurmuur_status.have_shape_rules: %s.",
            vuurmuur_status.have_shape_rules ? "Yes" : "No");

    if (vuurmuur_status.have_shape_ifaces == FALSE &&
            vuurmuur_status.have_shape_rules == TRUE) {
        vuurmuur_status.interfaces = 0;
        queue_status_msg(status_list, vuurmuur_status.interfaces,
                gettext("- No interfaces have shaping enabled. Please make "
                        "sure that at least one of the interfaces has shaping "
                        "enabled\n"));
    }

    if (at_least_one_active == FALSE) {
        vuurmuur_status.interfaces = 0;
        queue_status_msg(status_list, vuurmuur_status.interfaces,
                gettext("- No interfaces are active. Please make sure that at "
                        "least one of the interfaces is active\n"));
    }

    vrmr_debug(LOW, "at_least_one_active: %s.",
            at_least_one_active ? "Yes" : "No");
}

/*
 */
static void mm_check_status_zones(
        /*@null@*/ struct vrmr_list *status_list, struct vrmr_zones *zones)
{
    struct vrmr_list_node *d_node = NULL;
    struct vrmr_zone *zone_ptr = NULL;
    char at_least_one_active_network = FALSE;
    char at_least_one_network = FALSE;
    int result = 0;

    vrmr_fatal_if_null(zones);

    /* asume ok when we start */
    vuurmuur_status.zones = 1;

    /* we need zones */
    if (zones->list.len == 0) {
        vuurmuur_status.zones = 0;
        queue_status_msg(&vuurmuur_status.StatusList, vuurmuur_status.zones,
                gettext("- No zones are defined. Please define one or more "
                        "zones, and at least one network\n"));
    }

    for (d_node = zones->list.top; d_node; d_node = d_node->next) {
        vrmr_fatal_if_null(d_node->data);
        zone_ptr = d_node->data;

        if (zone_ptr->type == VRMR_TYPE_NETWORK)
            at_least_one_network = TRUE;

        if (zone_ptr->type == VRMR_TYPE_NETWORK && zone_ptr->active == TRUE)
            at_least_one_active_network = TRUE;

        if (zone_ptr->type == VRMR_TYPE_HOST) {
            if (zone_ptr->ipv4.ipaddress[0] == '\0') {
                vuurmuur_status.zones = 0;

                queue_status_msg(&vuurmuur_status.StatusList,
                        vuurmuur_status.zones,
                        gettext("- The host '%s' does not have an IPAddress\n"),
                        zone_ptr->name);
            } else {
                /* check the ip */
                if (zone_ptr->network_parent->ipv4.network[0] != '\0' &&
                        zone_ptr->network_parent->ipv4.netmask[0] != '\0') {
                    result = vrmr_check_ipv4address(
                            zone_ptr->network_parent->ipv4.network,
                            zone_ptr->network_parent->ipv4.netmask,
                            zone_ptr->ipv4.ipaddress, 1);
                    if (result < 0) {
                        vuurmuur_status.zones = 0;

                        queue_status_msg(&vuurmuur_status.StatusList,
                                vuurmuur_status.zones,
                                gettext("- The IPAddress '%s' of host '%s' is "
                                        "invalid\n"),
                                zone_ptr->ipv4.ipaddress, zone_ptr->name);
                    } else if (result == 0) {
                        /* check ip told us that the ip didn't belong to the
                         * network */
                        vuurmuur_status.zones = 0;

                        queue_status_msg(&vuurmuur_status.StatusList,
                                vuurmuur_status.zones,
                                gettext("- The IPAddress '%s' of host '%s' "
                                        "does not belong to network '%s' with "
                                        "netmask '%s'\n"),
                                zone_ptr->ipv4.ipaddress, zone_ptr->name,
                                zone_ptr->network_parent->ipv4.network,
                                zone_ptr->network_parent->ipv4.netmask);
                    }
                }
            }
        } else if (zone_ptr->type == VRMR_TYPE_NETWORK) {
            if (zone_ptr->InterfaceList.len == 0) {
                vuurmuur_status.zones = 0;

                queue_status_msg(&vuurmuur_status.StatusList,
                        vuurmuur_status.zones,
                        gettext("- The network '%s' has no interfaces attached "
                                "to it. Please attach one or more interfaces "
                                "to it in the Zones Section\n"),
                        zone_ptr->name);
            }

            if (zone_ptr->ipv4.network[0] == '\0') {
                vuurmuur_status.zones = 0;

                queue_status_msg(&vuurmuur_status.StatusList,
                        vuurmuur_status.zones,
                        gettext("- The network address for network '%s' is "
                                "missing. See the Zones Section\n"),
                        zone_ptr->name);
            } else {
                /* check the ip */
                result = vrmr_check_ipv4address(
                        NULL, NULL, zone_ptr->ipv4.network, 1);
                if (result < 0) {
                    vuurmuur_status.zones = 0;

                    queue_status_msg(&vuurmuur_status.StatusList,
                            vuurmuur_status.zones,
                            gettext("- The network address '%s' of network "
                                    "'%s' is invalid."),
                            zone_ptr->ipv4.network, zone_ptr->name);
                }
            }

            if (zone_ptr->ipv4.netmask[0] == '\0') {
                vuurmuur_status.zones = 0;

                queue_status_msg(&vuurmuur_status.StatusList,
                        vuurmuur_status.zones,
                        gettext("- The netmask for network '%s' is missing. "
                                "See the Zones Section\n"),
                        zone_ptr->name);
            } else {
                /* check the ip */
                result = vrmr_check_ipv4address(
                        NULL, NULL, zone_ptr->ipv4.netmask, 1);
                if (result < 0) {
                    vuurmuur_status.zones = 0;

                    queue_status_msg(&vuurmuur_status.StatusList,
                            vuurmuur_status.zones,
                            gettext("- The netmask '%s' of network '%s' is "
                                    "invalid. See the Zones Section\n"),
                            zone_ptr->ipv4.netmask, zone_ptr->name);
                }
            }
        }
    }

    if (at_least_one_network == FALSE) {
        vuurmuur_status.zones = 0;
        queue_status_msg(status_list, vuurmuur_status.zones,
                gettext("- No networks are defined. Please make sure that you "
                        "define at least one network. See the Zones "
                        "Section\n"));
    } else if (at_least_one_active_network == FALSE) {
        vuurmuur_status.zones = 0;
        queue_status_msg(status_list, vuurmuur_status.zones,
                gettext("- No networks are active. Please make sure that at "
                        "least one of the networks is active. See the Zones "
                        "Section\n"));
    }
}

static void mm_update_overall_status(void)
{
    /* asume all ok */
    vuurmuur_status.shm = 1;
    vuurmuur_status.backend = 1;
    vuurmuur_status.overall = 1;

    /* backend */
    if (vuurmuur_status.zones == 0 || vuurmuur_status.services == 0 ||
            vuurmuur_status.interfaces == 0 || vuurmuur_status.rules == 0) {
        vuurmuur_status.backend = 0;
    }
    if (vuurmuur_status.zones == -1 || vuurmuur_status.services == -1 ||
            vuurmuur_status.interfaces == -1 || vuurmuur_status.rules == -1) {
        vuurmuur_status.backend = -1;
    }

    /* shm */
    if (vuurmuur_status.vuurmuur == 0 || vuurmuur_status.vuurmuur_log == 0) {
        vuurmuur_status.shm = 0;
    }
    if (vuurmuur_status.vuurmuur == -1 || vuurmuur_status.vuurmuur_log == -1) {
        vuurmuur_status.shm = -1;
    }

    /* overall */
    if (vuurmuur_status.shm == 0 || vuurmuur_status.backend == 0 ||
            //        vuurmuur_status.settings == 0    ||
            vuurmuur_status.config == 0 || vuurmuur_status.system == 0) {
        vuurmuur_status.overall = 0;
    }
    if (vuurmuur_status.shm == -1 || vuurmuur_status.backend == -1 ||
            vuurmuur_status.config == -1 ||
            //        vuurmuur_status.settings == -1   ||
            vuurmuur_status.system == -1) {
        vuurmuur_status.overall = -1;
    }

    vrmr_debug(LOW, "vuurmuur_status.all: %d.", vuurmuur_status.overall);
}

static int mm_reload_shm(struct vrmr_ctx *vctx)
{
#define SHM_REL_NOT_CONN gettext("Not connected")
#define SHM_REL_SUCCESS gettext("Success")
#define SHM_REL_NO_CHANGES gettext("No changes")
#define SHM_REL_ERROR gettext("Error")
#define SHM_REL_TIMEOUT gettext("Timed out")
    WINDOW *wait_win = NULL;
    PANEL *panel[1];
    FORM *form = NULL;
    FIELD **fields;
    FIELD *vuurmuurfld = NULL, *vuurmuurlogfld = NULL;
    int cols = 0, rows = 0;
    size_t n_fields = 0, i = 0;
    int max_height = 0, max_width = 0;
    int vuurmuur_result = 0, vuurmuurlog_result = 0;
    int waittime = 0;
    int vuurmuur_progress = 0, vuurmuurlog_progress = 0;
    char str[4] = "";
    char failed = 0;

    /* reset the last reload result */
    last_vuurmuur_result = 1;
    last_vuurmuur_log_result = 1;

    getmaxyx(stdscr, max_height, max_width);

    /* create a little wait dialog */
    wait_win = create_newwin(7, 45, (max_height - 7) / 4, (max_width - 45) / 2,
            gettext("One moment please..."), vccnf.color_win);
    vrmr_fatal_if_null(wait_win);
    panel[0] = new_panel(wait_win);

    n_fields = 2;
    fields = (FIELD **)calloc(n_fields + 1, sizeof(FIELD *));
    vrmr_fatal_alloc("calloc", fields);

    /* overall */
    vuurmuurfld = (fields[0] = new_field_wrap(1, 3, 3, 20, 0, 0));
    set_field_buffer_wrap(vuurmuurfld, 0, "  0");
    set_field_back(vuurmuurfld, vccnf.color_win);
    vuurmuurlogfld = (fields[1] = new_field_wrap(1, 3, 4, 20, 0, 0));
    set_field_buffer_wrap(vuurmuurlogfld, 0, "  0");
    set_field_back(vuurmuurlogfld, vccnf.color_win);
    /* terminate */
    fields[n_fields] = NULL;
    /* Create the form and post it */
    form = new_form(fields);
    scale_form(form, &rows, &cols);
    set_form_win(form, wait_win);
    set_form_sub(form, derwin(wait_win, rows, cols, 1, 1));
    post_form(form);

    mvwprintw(wait_win, 2, 4, gettext("Applying changes ..."));
    mvwprintw(wait_win, 4, 4, "Vuurmuur:            %%");
    mvwprintw(wait_win, 5, 4, "Vuurmuur_log:        %%");
    update_panels();
    doupdate();

    vrmr_audit(gettext("Applying changes ..."));

    /* notify both vuurmuur and vuurmuurlog */
    if (vuurmuur_semid != -1) {
        if (vrmr_lock(vuurmuur_semid)) {
            vuurmuur_shmtable->backend_changed = 1;
            (void)strlcpy(vuurmuur_shmtable->configtool.username,
                    vctx->user_data.realusername,
                    sizeof(vuurmuur_shmtable->configtool.username));
            vrmr_unlock(vuurmuur_semid);

            vuurmuur_result = VRMR_RR_NO_RESULT_YET;
        }
    } else {
        vuurmuur_result = VRMR_RR_READY;
        vuurmuur_progress = 100;

        (void)snprintf(str, sizeof(str), " - ");
        set_field_buffer_wrap(vuurmuurfld, 0, str);
    }
    if (vuurmuurlog_semid != -1) {
        if (vrmr_lock(vuurmuurlog_semid)) {
            vuurmuurlog_shmtable->backend_changed = 1;
            (void)strlcpy(vuurmuurlog_shmtable->configtool.username,
                    vctx->user_data.realusername,
                    sizeof(vuurmuurlog_shmtable->configtool.username));
            vrmr_unlock(vuurmuurlog_semid);

            vuurmuurlog_result = VRMR_RR_NO_RESULT_YET;
        }
    } else {
        vuurmuurlog_result = VRMR_RR_READY;
        vuurmuurlog_progress = 100;

        (void)snprintf(str, sizeof(str), " - ");
        set_field_buffer_wrap(vuurmuurlogfld, 0, str);
    }

    /* wait max 60 seconds */
    while (((vuurmuur_result == VRMR_RR_NO_RESULT_YET ||
                    vuurmuur_result == VRMR_RR_RESULT_ACK) ||
                   (vuurmuurlog_result == VRMR_RR_NO_RESULT_YET ||
                           vuurmuurlog_result == VRMR_RR_RESULT_ACK)) &&
            waittime < 60000000) {
        if (vuurmuur_progress < 100) {
            if (vrmr_lock(vuurmuur_semid)) {
                if (vuurmuur_shmtable->reload_result != VRMR_RR_READY) {
                    vuurmuur_result = vuurmuur_shmtable->reload_result;
                }
                vuurmuur_progress = vuurmuur_shmtable->reload_progress;
                vrmr_unlock(vuurmuur_semid);
            }

            (void)snprintf(str, sizeof(str), "%3d", vuurmuur_progress);
            set_field_buffer_wrap(vuurmuurfld, 0, str);
        }

        if (vuurmuur_progress == 100) {
            if (vuurmuur_semid == -1) {
                wattron(wait_win, vccnf.color_win_red);
                mvwprintw(wait_win, 4, 29, SHM_REL_NOT_CONN);
                wattroff(wait_win, vccnf.color_win_red);
                last_vuurmuur_result = 0;
                failed = 1;
            } else if (vrmr_lock(vuurmuur_semid)) {
                vuurmuur_shmtable->reload_result = VRMR_RR_RESULT_ACK;
                vrmr_unlock(vuurmuur_semid);

                if (vuurmuur_result == VRMR_RR_SUCCES) {
                    wattron(wait_win, vccnf.color_win_green);
                    mvwprintw(wait_win, 4, 29, SHM_REL_SUCCESS);
                    wattroff(wait_win, vccnf.color_win_green);
                } else if (vuurmuur_result == VRMR_RR_NOCHANGES) {
                    mvwprintw(wait_win, 4, 29, SHM_REL_NO_CHANGES);
                } else {
                    wattron(wait_win, vccnf.color_win_red);
                    mvwprintw(wait_win, 4, 29, SHM_REL_ERROR);
                    wattroff(wait_win, vccnf.color_win_red);

                    last_vuurmuur_result = 0;
                    failed = 1;
                }
            }
        }

        if (vuurmuurlog_progress < 100) {
            if (vrmr_lock(vuurmuurlog_semid)) {
                if (vuurmuurlog_shmtable->reload_result != VRMR_RR_READY) {
                    vuurmuurlog_result = vuurmuurlog_shmtable->reload_result;
                }
                vuurmuurlog_progress = vuurmuurlog_shmtable->reload_progress;
                vrmr_unlock(vuurmuurlog_semid);
            }

            (void)snprintf(str, sizeof(str), "%3d", vuurmuurlog_progress);
            set_field_buffer_wrap(vuurmuurlogfld, 0, str);
        }

        if (vuurmuurlog_progress == 100) {
            if (vuurmuurlog_semid == -1) {
                wattron(wait_win, vccnf.color_win_red);
                mvwprintw(wait_win, 5, 29, SHM_REL_NOT_CONN);
                wattroff(wait_win, vccnf.color_win_red);
                last_vuurmuur_log_result = 0;
            } else if (vrmr_lock(vuurmuurlog_semid)) {
                vuurmuurlog_shmtable->reload_result = VRMR_RR_RESULT_ACK;
                vrmr_unlock(vuurmuurlog_semid);

                if (vuurmuurlog_result == VRMR_RR_SUCCES) {
                    wattron(wait_win, vccnf.color_win_green);
                    mvwprintw(wait_win, 5, 29, SHM_REL_SUCCESS);
                    wattroff(wait_win, vccnf.color_win_green);
                } else if (vuurmuurlog_result == VRMR_RR_NOCHANGES) {
                    mvwprintw(wait_win, 5, 29, SHM_REL_NO_CHANGES);
                } else {
                    wattron(wait_win, vccnf.color_win_red);
                    mvwprintw(wait_win, 5, 29, SHM_REL_ERROR);
                    wattroff(wait_win, vccnf.color_win_red);
                    last_vuurmuur_log_result = 0;
                    failed = 1;
                }
            }
        }
        update_panels();
        doupdate();

        /* no result yet, sleep 1 sec, or if the server didn't have a chance to
         * do anything */
        if ((vuurmuur_result == VRMR_RR_NO_RESULT_YET ||
                    vuurmuur_result == VRMR_RR_RESULT_ACK) ||
                (vuurmuurlog_result == VRMR_RR_NO_RESULT_YET ||
                        vuurmuurlog_result == VRMR_RR_RESULT_ACK)) {
            waittime += 1000;
            usleep(1000);
        }
    }

    /* timed out */
    if (vuurmuur_progress < 100) {
        wattron(wait_win, vccnf.color_win_red);
        mvwprintw(wait_win, 4, 29, SHM_REL_TIMEOUT);
        wattroff(wait_win, vccnf.color_win_red);

        last_vuurmuur_result = 0;
        failed = 1;
    }
    /* timed out */
    if (vuurmuurlog_progress < 100) {
        wattron(wait_win, vccnf.color_win_red);
        mvwprintw(wait_win, 5, 29, SHM_REL_TIMEOUT);
        wattroff(wait_win, vccnf.color_win_red);

        last_vuurmuur_log_result = 0;
        failed = 1;
    }
    update_panels();
    doupdate();

    if (failed == 1) {
        vrmr_error(-1, VR_ERR,
                gettext("applying changes failed. Please check error.log."));
    } else {
        sleep(1);
    }

    /* destroy the wait dialog */
    unpost_form(form);
    free_form(form);
    for (i = 0; i < n_fields; i++) {
        free_field(fields[i]);
    }
    free(fields);
    del_panel(panel[0]);
    destroy_win(wait_win);
    update_panels();
    doupdate();
    return (0);
}

struct {
    FIELD *overallfld,

            *backendfld, *configfld, *settingsfld,

            *shmfld,

            *systemfld;

    FIELD **fields;
    size_t n_fields;
    FORM *form;

} StatusFlds;

/*
    we don't use set_field_just here because for some reason it
    doesn't work on the first field.
*/
static void mm_set_status_field(int status, FIELD *fld)
{
    vrmr_debug(HIGH, "status: %d.", status);

    if (status == 1) /* OK */
    {
        /* TRANSLATORS: max 6 characters */
        set_field_buffer_wrap(fld, 0, gettext("  OK  "));
        set_field_back(fld, vccnf.color_win_green);
    } else if (status == 0) /* Attention */
    {
        /* TRANSLATORS: max 6 characters */
        set_field_buffer_wrap(fld, 0, gettext(" Warn "));
        set_field_back(fld, vccnf.color_win_yellow | A_BOLD);
    } else /* Warning */
    {
        /* TRANSLATORS: max 6 characters */
        set_field_buffer_wrap(fld, 0, gettext(" Fail "));
        set_field_back(fld, vccnf.color_win_red | A_BOLD);
    }
}

static void mm_update_status_fields(void)
{
    if (vccnf.draw_status == FALSE)
        return;

    mm_set_status_field(vuurmuur_status.overall, StatusFlds.overallfld);
    mm_set_status_field(vuurmuur_status.backend, StatusFlds.backendfld);
    mm_set_status_field(vuurmuur_status.config, StatusFlds.configfld);
    mm_set_status_field(vuurmuur_status.settings, StatusFlds.settingsfld);
    mm_set_status_field(vuurmuur_status.shm, StatusFlds.shmfld);
    mm_set_status_field(vuurmuur_status.system, StatusFlds.systemfld);
}

int vc_apply_changes(struct vrmr_ctx *vctx)
{
    int reload_result = 0;

    /* check shm one last time, and don't write to status list */
    mm_check_status_shm(NULL);
    /* hmm vuurmuur not connected, try to do that now */
    if (vuurmuur_status.vuurmuur != 1) {
        mm_shm_connect_vuurmuur();
        mm_check_status_shm(NULL);
    }
    /* hmm vuurmuur_log not connected, try to do that now */
    if (vuurmuur_status.vuurmuur_log != 1) {
        mm_shm_connect_vuurmuurlog();
        mm_check_status_shm(NULL);
    }
    /* update the status */
    mm_update_overall_status();

    /* now see if we can apply */
    if (vuurmuur_status.overall == 1) {
        /* reload the shm */
        reload_result = mm_reload_shm(vctx);
        /* update the vuurmuurlognames because the logs might
           have moved after applying the changes because of
           configuration changes made by the user */
        (void)vrmr_config_set_log_names(&vctx->conf);
    } else if (vuurmuur_status.vuurmuur != 1) {
        vrmr_error(-1, VR_ERR,
                gettext("Vuurmuur daemon not running. Can't notify it of any "
                        "changes. Please start it first."));
        reload_result = 0;
    } else if (vuurmuur_status.overall == 0) {
        if ((confirm(gettext("Apply Changes"),
                     gettext("The overall status is not OK. Apply anyway?"),
                     vccnf.color_win_note, vccnf.color_win_note_rev | A_BOLD,
                     0) == 1)) {
            /* reload the shm */
            reload_result = mm_reload_shm(vctx);
            /* update the vuurmuurlognames because the logs might
               have moved after applying the changes because of
               configuration changes made by the user */
            (void)vrmr_config_set_log_names(&vctx->conf);
        }
    } else {
        vrmr_error(-1, VR_ERR,
                gettext("will not apply changes if the overall status is "
                        "'fail'."));
        reload_result = 0;
    }

    if (reload_result < 0) {
        mm_check_status_shm(NULL);
        mm_update_overall_status();
    }

    return (0);
}

/*
    the main menu, here you choose between rules, zones, config, logview, etc.
*/
int main_menu(struct vrmr_ctx *vctx, struct vrmr_rules *rules,
        struct vrmr_zones *zones, struct vrmr_interfaces *interfaces,
        struct vrmr_services *services, struct vrmr_blocklist *blocklist,
        struct vrmr_regex *reg)
{
#define MM_ITEM_RULES gettext("Rules")
#define MM_ITEM_BLOCKLIST gettext("BlockList")
#define MM_ITEM_ZONES gettext("Zones")
#define MM_ITEM_INTERFACES gettext("Interfaces")
#define MM_ITEM_SERVICES gettext("Services")
#define MM_ITEM_VRCONFIG gettext("Vuurmuur Config")
#define MM_ITEM_LOGVIEW gettext("Logview")
#define MM_ITEM_STATUS gettext("Status")
#define MM_ITEM_CONNECTIONS gettext("Connections")
#define MM_ITEM_TRAFVOL gettext("Traffic Volume")
#define MM_ITEM_SETTINGS gettext("Vuurmuur_conf Settings")
#define MM_ITEM_APPLYCHANGES gettext("Apply Changes")
#define MM_ITEM_ABOUT gettext("About")
#define MM_ITEM_QUIT gettext("Quit")

    size_t n_choices = 15, i = 0;
    int ch = 0, quit = 0, retval = 0;
    ITEM **menu_items = NULL;
    MENU *main_menu = NULL;
    WINDOW *mainmenu_win = NULL;
    PANEL *mm_panels[1];

    char *choice_ptr = NULL;
    char draw_status = vccnf.draw_status;

    // this are the menu items
    const char *choices[] = {MM_ITEM_RULES, MM_ITEM_BLOCKLIST, MM_ITEM_ZONES,
            MM_ITEM_INTERFACES, MM_ITEM_SERVICES, MM_ITEM_VRCONFIG,
            MM_ITEM_LOGVIEW, MM_ITEM_STATUS, MM_ITEM_CONNECTIONS,
            MM_ITEM_TRAFVOL, MM_ITEM_SETTINGS, MM_ITEM_APPLYCHANGES,
            MM_ITEM_ABOUT, MM_ITEM_QUIT, NULL};

    // with their descriptions
    const char *descriptions[] = {"(F9) ", "(b)  ",

            "(F7) ", "     ", "(F8) ",

            "(F6) ",

            "     ", "(s)  ", "(c)  ", "(a)  ",

            "     ",

            "(F11)", "     ",

            "(F10)", NULL};

    const char *key_choices[] = {"F12"};
    int key_choices_n = 1;
    const char *cmd_choices[] = {gettext("help")};
    int cmd_choices_n = 1;

    int x = 0, y = 0, startx = 0, starty = 0, maxx = 0, maxy = 0;

    int cols = 0;
    int rows = 0;

    /* update the status */
    mm_update_overall_status();

    /* main menu width */
    if (vccnf.draw_status)
        x = 74;
    else
        x = 50;
    getmaxyx(stdscr, maxy, maxx);
    /* main menu height */
    if (maxy == 24)
        y = (int)n_choices + 5;
    else
        y = (int)n_choices + 6;
    /* set the position of the window centered */
    startx = (maxx - x) / 2;
    starty = (maxy - y) / 2;

    /* alloc the items */
    menu_items = (ITEM **)calloc(n_choices + 1, sizeof(ITEM *));
    vrmr_fatal_alloc("calloc", menu_items);
    /* set the items */
    for (i = 0; i < n_choices; i++) {
        menu_items[i] = new_item(choices[i], descriptions[i]);
    }
    menu_items[n_choices] = (ITEM *)NULL;
    /* create menu */
    main_menu = new_menu((ITEM **)menu_items);

    /* create the window and panel */
    mainmenu_win = create_newwin(
            y, x, starty, startx, gettext("Main Menu"), vccnf.color_win);
    keypad(mainmenu_win, TRUE);
    wrefresh(mainmenu_win);
    mm_panels[0] = new_panel(mainmenu_win);
    /* menu settings */
    set_menu_win(main_menu, mainmenu_win);
    set_menu_sub(main_menu, derwin(mainmenu_win, y - 6, x - 12, 5, 5));

    set_menu_format(main_menu, y - 4, 1);
    set_menu_back(main_menu, vccnf.color_win);
    set_menu_fore(main_menu, vccnf.color_win_rev);
    post_menu(main_menu);

    /* the form for the status */
    if (vccnf.draw_status) {
        size_t field_num = 0;
        StatusFlds.n_fields = 6;
        StatusFlds.fields =
                (FIELD **)calloc(StatusFlds.n_fields + 1, sizeof(FIELD *));

        /* overall */
        StatusFlds.overallfld = (StatusFlds.fields[field_num] =
                                         new_field_wrap(1, 6, 5, 0, 0, 0));
        field_num++;
        /* backend */
        StatusFlds.backendfld = (StatusFlds.fields[field_num] =
                                         new_field_wrap(1, 6, 8, 0, 0, 0));
        field_num++;
        /* config */
        StatusFlds.configfld = (StatusFlds.fields[field_num] =
                                        new_field_wrap(1, 6, 9, 0, 0, 0));
        field_num++;
        /* settings */
        StatusFlds.settingsfld = (StatusFlds.fields[field_num] =
                                          new_field_wrap(1, 6, 10, 0, 0, 0));
        field_num++;
        /* shm */
        StatusFlds.shmfld = (StatusFlds.fields[field_num] =
                                     new_field_wrap(1, 6, 12, 0, 0, 0));
        field_num++;
        /* system */
        StatusFlds.systemfld = (StatusFlds.fields[field_num] =
                                        new_field_wrap(1, 6, 14, 0, 0, 0));
        field_num++;
        /* terminate */
        StatusFlds.fields[field_num] = NULL;

        mm_update_status_fields();

        /* Create the form and post it */
        StatusFlds.form = new_form(StatusFlds.fields);
        scale_form(StatusFlds.form, &rows, &cols);
        set_form_win(StatusFlds.form, mainmenu_win);
        set_form_sub(StatusFlds.form, derwin(mainmenu_win, rows, cols, 1, 60));

        /* welcome message */
        mvwprintw(mainmenu_win, 2, 19, gettext("Welcome to Vuurmuur_conf %s"),
                VUURMUURCONF_VERSION);

        mvwprintw(mainmenu_win, 6, 45, gettext("Overall"));
        mvwprintw(mainmenu_win, 6, 59, "[      ]");

        mvwprintw(mainmenu_win, 9, 45, gettext("Backend"));
        mvwprintw(mainmenu_win, 9, 59, "[      ]");
        mvwprintw(mainmenu_win, 10, 45, gettext("Config"));
        mvwprintw(mainmenu_win, 10, 59, "[      ]");
        mvwprintw(mainmenu_win, 11, 45, gettext("Settings"));
        mvwprintw(mainmenu_win, 11, 59, "[      ]");

        mvwprintw(mainmenu_win, 13, 45, gettext("Daemons"));
        mvwprintw(mainmenu_win, 13, 59, "[      ]");

        mvwprintw(mainmenu_win, 15, 45, gettext("System"));
        mvwprintw(mainmenu_win, 15, 59, "[      ]");

        post_form(StatusFlds.form);

        if (vuurmuur_status.overall != 1)
            /* TRANSLATORS: max 27 chars. */
            mvwprintw(mainmenu_win, 17, 45, gettext("Press F5 for details."));

        /* draw a nice box */
        mvwhline(mainmenu_win, 5, 44, ACS_HLINE, 24);
        mvwaddch(mainmenu_win, 5, 43, ACS_ULCORNER);
        mvwaddch(mainmenu_win, 5, 67, ACS_URCORNER);
        mvwvline(mainmenu_win, 6, 43, ACS_VLINE, 10);
        mvwvline(mainmenu_win, 6, 67, ACS_VLINE, 10);
        mvwhline(mainmenu_win, 16, 44, ACS_HLINE, 24);
        mvwaddch(mainmenu_win, 16, 43, ACS_LLCORNER);
        mvwaddch(mainmenu_win, 16, 67, ACS_LRCORNER);
    } else /* dont print status */
    {
        mvwprintw(mainmenu_win, 2, 4, gettext("Welcome to Vuurmuur_conf %s"),
                VUURMUURCONF_VERSION);
    }
    update_panels();
    doupdate();

    /* restore the cursor */
    pos_menu_cursor(main_menu);

    // enter loop
    while (quit == 0) {
        /* show the menu, it might be hidden */
        show_panel(mm_panels[0]);

        draw_top_menu(top_win, gettext("Main"), key_choices_n, key_choices,
                cmd_choices_n, cmd_choices);

        status_print(status_win, gettext("Ready."));

        /* get user input */
        ch = wgetch(mainmenu_win);

        if (vrmr_debug_level >= LOW)
            status_print(status_win, "ch: %d", ch);

        switch (ch) {
            // navigation
            case KEY_DOWN:
                menu_driver(main_menu, REQ_DOWN_ITEM);
                break;
            case KEY_UP:
                menu_driver(main_menu, REQ_UP_ITEM);
                break;
            case KEY_NPAGE:
                if (menu_driver(main_menu, REQ_SCR_DPAGE) != E_OK) {
                    while (menu_driver(main_menu, REQ_DOWN_ITEM) == E_OK)
                        ;
                }
                break;
            case KEY_PPAGE:
                if (menu_driver(main_menu, REQ_SCR_UPAGE) != E_OK) {
                    while (menu_driver(main_menu, REQ_UP_ITEM) == E_OK)
                        ;
                }
                break;
            case KEY_HOME:
                menu_driver(main_menu, REQ_FIRST_ITEM); // page up
                break;
            case KEY_END:
                menu_driver(main_menu, REQ_LAST_ITEM); // end
                break;

            // handle selecting an item in the menu
            case KEY_RIGHT:
            case 32: // space
            case 10: // enter
            {
                ITEM *cur = current_item(main_menu);
                vrmr_fatal_if_null(cur);
                choice_ptr = strdup((char *)item_name(cur));
                vrmr_fatal_alloc("strdup", choice_ptr);
                break;
            }

            /* handle the keyboad shortcuts */
            case 27:
            case 'q':
            case 'Q':
            case KEY_F(10):

                quit = 1;
                break;

            /* status */
            case KEY_F(5):

                choice_ptr = strdup("printstatus");
                vrmr_fatal_alloc("strdup", choice_ptr);
                break;

            /* rules */
            case KEY_F(9):

                choice_ptr = strdup(MM_ITEM_RULES);
                vrmr_fatal_alloc("strdup", choice_ptr);
                break;

            /* services */
            case KEY_F(8):

                choice_ptr = strdup(MM_ITEM_SERVICES);
                vrmr_fatal_alloc("strdup", choice_ptr);
                break;

            /* zones */
            case KEY_F(7):

                choice_ptr = strdup(MM_ITEM_ZONES);
                vrmr_fatal_alloc("strdup", choice_ptr);
                break;

            case KEY_F(6):

                choice_ptr = strdup(MM_ITEM_VRCONFIG);
                vrmr_fatal_alloc("strdup", choice_ptr);
                break;

            case KEY_F(11):

                choice_ptr = strdup(MM_ITEM_APPLYCHANGES);
                vrmr_fatal_alloc("strdup", choice_ptr);
                break;

            case 'l':
            case 'L':

                choice_ptr = strdup("traffic");
                vrmr_fatal_alloc("strdup", choice_ptr);
                break;

            case 's':
            case 'S':

                choice_ptr = strdup(MM_ITEM_STATUS);
                vrmr_fatal_alloc("strdup", choice_ptr);
                break;

            case 'c':
            case 'C':

                choice_ptr = strdup(MM_ITEM_CONNECTIONS);
                vrmr_fatal_alloc("strdup", choice_ptr);
                break;

            /* BlockList */
            case 'b':
            case 'B':

                choice_ptr = strdup(MM_ITEM_BLOCKLIST);
                vrmr_fatal_alloc("strdup", choice_ptr);
                break;

            /* traffic volume */
            case 'a':
            case 'A':

                choice_ptr = strdup(MM_ITEM_TRAFVOL);
                vrmr_fatal_alloc("strdup", choice_ptr);
                break;

            case KEY_F(12):
            case '?':
            case 'H':
            case 'h':

                choice_ptr = strdup("showhelp");
                vrmr_fatal_alloc("strdup", choice_ptr);
                break;
        }

        /* now act */
        if (choice_ptr != NULL) {
            hide_panel(mm_panels[0]);

            if (strcmp(choice_ptr, MM_ITEM_RULES) == 0) {
                rules_form(vctx, rules, zones, interfaces, services, reg);

                mm_check_status_rules(&vctx->conf, rules);
                mm_check_status_interfaces(NULL, interfaces);
            } else if (strcmp(choice_ptr, MM_ITEM_ZONES) == 0) {
                zones_section(vctx, zones, interfaces, rules, blocklist, reg);

                /* check for active interfaces */
                mm_check_status_zones(NULL, zones);
            } else if (strcmp(choice_ptr, MM_ITEM_INTERFACES) == 0) {
                interfaces_section(vctx, interfaces, zones, rules, reg);

                /* check for active networks */
                mm_check_status_interfaces(NULL, interfaces);
            } else if (strcmp(choice_ptr, MM_ITEM_SERVICES) == 0) {
                services_section(vctx, services, rules, reg);

                mm_check_status_services(services);
            } else if (strcmp(choice_ptr, MM_ITEM_VRCONFIG) == 0) {
                config_menu(&vctx->conf);

                mm_check_status_config(&vctx->conf, NULL);
                mm_check_status_rules(&vctx->conf, rules);
            } else if (strcmp(choice_ptr, "traffic") == 0) {
                logview_section(vctx, &vctx->conf, zones, blocklist, interfaces,
                        services, NULL);
            } else if (strcmp(choice_ptr, MM_ITEM_LOGVIEW) == 0) {
                mm_select_logfile(vctx, &vctx->conf, zones, blocklist,
                        interfaces, services);
            } else if (strcmp(choice_ptr, MM_ITEM_STATUS) == 0) {
                status_section(&vctx->conf, interfaces);
            } else if (strcmp(choice_ptr, MM_ITEM_CONNECTIONS) == 0) {
                connections_section(vctx, &vctx->conf, zones, interfaces,
                        services, blocklist);
            } else if (strcmp(choice_ptr, MM_ITEM_BLOCKLIST) == 0) {
                zones_blocklist(vctx, blocklist, zones, reg);
            } else if (strcmp(choice_ptr, MM_ITEM_TRAFVOL) == 0) {
                trafvol_section(&vctx->conf, interfaces);
            } else if (strcmp(choice_ptr, MM_ITEM_SETTINGS) == 0) {
                edit_vcconfig();
                mm_check_status_settings(NULL);
                retval = 1;
                quit = 1;
            } else if (strcmp(choice_ptr, MM_ITEM_ABOUT) == 0) {
                print_about();
            } else if (strcmp(choice_ptr, "printstatus") == 0) {
                mm_status_checkall(vctx, &vuurmuur_status.StatusList, rules,
                        zones, interfaces, services);
                print_status();
            } else if (strncasecmp(choice_ptr, "showhelp", 8) == 0) {
                print_help(":[VUURMUUR:GENERAL]:");
            } else if (strcmp(choice_ptr, MM_ITEM_APPLYCHANGES) == 0) {
                vc_apply_changes(vctx);
            } else if (strcmp(choice_ptr, MM_ITEM_QUIT) == 0) {
                quit = 1;
            }

            free(choice_ptr);
            choice_ptr = NULL;

            /* status checks */
            mm_check_status_shm(NULL);
            if (vuurmuur_status.vuurmuur != 1) {
                mm_shm_connect_vuurmuur();
                mm_check_status_shm(NULL);
            }
            if (vuurmuur_status.vuurmuur_log != 1) {
                mm_shm_connect_vuurmuurlog();
                mm_check_status_shm(NULL);
            }

            mm_update_overall_status();

            if (draw_status == TRUE)
                mm_update_status_fields();
        }
    }

    /*
        exit the menu, so now remove the menu, window and form.
    */
    show_panel(mm_panels[0]);
    unpost_menu(main_menu);
    free_menu(main_menu);
    for (i = 0; i < n_choices; ++i)
        free_item(menu_items[i]);
    free(menu_items);
    /* cleanup status form */
    if (draw_status) {
        /* Un post form and free the memory */
        unpost_form(StatusFlds.form);
        free_form(StatusFlds.form);
        for (i = 0; i < StatusFlds.n_fields; i++)
            free_field(StatusFlds.fields[i]);
        free(StatusFlds.fields);
    }
    /* remove window and panel */
    del_panel(mm_panels[0]);
    destroy_win(mainmenu_win);
    update_panels();
    doupdate();
    return (retval);
}

/*
    check all the statusses
*/
void mm_status_checkall(struct vrmr_ctx *vctx,
        /*@null@*/ struct vrmr_list *status_list, struct vrmr_rules *rules,
        struct vrmr_zones *zones, struct vrmr_interfaces *interfaces,
        struct vrmr_services *services)
{
    unsigned int list_len = 0;

    /* if we have one, manage the list */
    if (status_list != NULL) {
        vrmr_list_cleanup(status_list);
        /* send a status of '1', so no status is printed */
        queue_status_msg(status_list, 1,
                gettext("One or more problems were detected in your current "
                        "setup. Below is a list\n"));
        /* store the list length so we can check for changes after all the check
         * functions */
        list_len = status_list->len;
    }

    /* check the services */
    mm_check_status_services(services);

    mm_check_status_rules(&vctx->conf, rules);

    /* check for (active) interfaces */
    mm_check_status_interfaces(status_list, interfaces);

    /* check for (active) networks */
    mm_check_status_zones(status_list, zones);

    /* check config */
    mm_check_status_config(&vctx->conf, status_list);

    /* check settings */
    mm_check_status_settings(status_list);

    /* shm connections */
    mm_check_status_shm(status_list);

    /* update the status */
    mm_update_overall_status();

    /* check for changes to the list */
    if (status_list != NULL) {
        /* if the list_len is still equal, we asume no problems */
        if (status_list->len == list_len) {
            /* nothing was added to the list */
            vrmr_list_cleanup(status_list);
            /* send a status of '1', so no status is printed */
            queue_status_msg(status_list, 1,
                    gettext("No problems were detected in your setup\n"));
        }
    }
}
