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
#include "gui.h"
#include "config.h"
#include <ctype.h>

#define VROPT_GENERAL gettext("General")
#define VROPT_CONNECTIONS gettext("Connections")
#define VROPT_INTERFACES gettext("Interfaces")
#define VROPT_SYSPROT gettext("System Protection")
#define VROPT_CONNTRACK gettext("Conntrack")
#define VROPT_LOGGING gettext("Logging")
#define VROPT_MODULES gettext("Modules")
#define VROPT_PLUGINS gettext("Plugins")
#define VROPT_CAPS gettext("Capabilities")
#ifdef IPV6_ENABLED
#define VROPT_IP6_CAPS gettext("IPv6 Capabilities")
#endif

struct config_section {
    PANEL *panel[1];
    WINDOW *win;
    FIELD **fields;
    FORM *form;
    size_t n_fields;
} config_section;

/* clean up for all config windows */
static void edit_config_destroy(void)
{
    size_t i = 0;

    /* Un post form and free the memory */
    unpost_form(config_section.form);
    free_form(config_section.form);
    for (i = 0; i < config_section.n_fields; i++) {
        free_field(config_section.fields[i]);
    }
    free(config_section.fields);
    del_panel(config_section.panel[0]);
    destroy_win(config_section.win);
    update_panels();
    doupdate();
}

struct {
    FIELD *iptableslocfld, *iptablesrestorelocfld, *ip6tableslocfld,
            *ip6tablesrestorelocfld, *tclocfld, *max_permission, *sysctllocfld;
} GenConfig;

static void edit_genconfig_init(
        struct vrmr_config *conf, int height, int width, int starty, int startx)
{
    int rows = 0, cols = 0;
    size_t i = 0;
    char number[5];

    config_section.n_fields = 7;
    config_section.fields =
            (FIELD **)calloc(config_section.n_fields + 1, sizeof(FIELD *));
    vrmr_fatal_alloc("calloc", config_section.fields);

    /* external programs */
    GenConfig.iptableslocfld = (config_section.fields[0] = new_field_wrap(
                                        1, 64, 1, 1, 0, 0)); /* iptables */
    GenConfig.iptablesrestorelocfld =
            (config_section.fields[1] =
                            new_field_wrap(1, 64, 3, 1, 0, 0)); /*  */
    GenConfig.ip6tableslocfld = (config_section.fields[2] = new_field_wrap(
                                         1, 64, 5, 1, 0, 0)); /* ip6tables */
    GenConfig.ip6tablesrestorelocfld =
            (config_section.fields[3] = new_field_wrap(1, 64, 7, 1, 0, 0));
    GenConfig.tclocfld = (config_section.fields[4] =
                                  new_field_wrap(1, 64, 9, 1, 0, 0)); /*  */
    /* Config file permissions */
    GenConfig.max_permission = (config_section.fields[5] = new_field_wrap(1, 4,
                                        11, 1, 0, 0)); /* max_permissions */
    GenConfig.sysctllocfld = (config_section.fields[6] = new_field_wrap(
                                      1, 64, 13, 1, 0, 0)); /*  */

    /* terminate */
    config_section.fields[config_section.n_fields] = NULL;

    config_section.win = create_newwin(height, width, starty, startx,
            gettext("Edit Config: General"), vccnf.color_win);
    config_section.panel[0] = new_panel(config_section.win);

    /* set buffers - first the visible, then the label */
    set_field_buffer_wrap(GenConfig.iptableslocfld, 0, conf->iptables_location);
    set_field_buffer_wrap(
            GenConfig.iptablesrestorelocfld, 0, conf->iptablesrestore_location);
#ifdef IPV6_ENABLED
    set_field_buffer_wrap(
            GenConfig.ip6tableslocfld, 0, conf->ip6tables_location);
    set_field_buffer_wrap(GenConfig.ip6tablesrestorelocfld, 0,
            conf->ip6tablesrestore_location);
#endif
    set_field_buffer_wrap(GenConfig.tclocfld, 0, conf->tc_location);
    (void)snprintf(number, sizeof(number), "%o", conf->max_permission);
    set_field_buffer_wrap(GenConfig.max_permission, 0, number);
    set_field_buffer_wrap(GenConfig.sysctllocfld, 0, conf->sysctl_location);

    for (i = 0; i < config_section.n_fields; i++) {
        set_field_back(config_section.fields[i], vccnf.color_win_rev | A_BOLD);
        field_opts_off(config_section.fields[i], O_AUTOSKIP);
        set_field_status(config_section.fields[i], FALSE);
    }

#ifndef IPV6_ENABLED
    set_field_back(GenConfig.ip6tableslocfld, vccnf.color_win | A_BOLD);
    field_opts_on(GenConfig.ip6tableslocfld, O_AUTOSKIP);
    field_opts_off(GenConfig.ip6tableslocfld, O_ACTIVE);
    set_field_back(GenConfig.ip6tablesrestorelocfld, vccnf.color_win | A_BOLD);
    field_opts_on(GenConfig.ip6tablesrestorelocfld, O_AUTOSKIP);
    field_opts_off(GenConfig.ip6tablesrestorelocfld, O_ACTIVE);
#endif

    // Create the form and post it
    config_section.form = new_form(config_section.fields);
    // Calculate the area required for the form
    scale_form(config_section.form, &rows, &cols);
    keypad(config_section.win, TRUE);
    // Set main window and sub window
    set_form_win(config_section.form, config_section.win);
    set_form_sub(
            config_section.form, derwin(config_section.win, rows, cols, 1, 2));
    post_form(config_section.form);

    /* print labels */
    mvwprintw(config_section.win, 1, 2,
            gettext("Iptables location (full path):"));
    mvwprintw(config_section.win, 3, 2,
            gettext("Iptables-restore location (full path):"));
#ifdef IPV6_ENABLED
    mvwprintw(config_section.win, 5, 2,
            gettext("Ip6tables location (full path):"));
    mvwprintw(config_section.win, 7, 2,
            gettext("Ip6tables-restore location (full path):"));
#endif
    mvwprintw(config_section.win, 9, 2, gettext("Tc location (full path):"));
    mvwprintw(config_section.win, 11, 2,
            gettext("Maximum config and log file and dir permissions "
                    "(octal):"));
    mvwprintw(
            config_section.win, 13, 2, gettext("Sysctl location (full path):"));
}

static void edit_genconfig_save(struct vrmr_config *conf)
{
    /* check for changed fields */
    for (size_t i = 0; i < config_section.n_fields; i++) {
        /* we only act if a field is changed */
        if (field_status(config_section.fields[i]) == FALSE)
            continue;

        if (config_section.fields[i] == GenConfig.iptableslocfld) {
            /* iptables location */
            copy_field2buf(conf->iptables_location,
                    field_buffer(config_section.fields[i], 0),
                    sizeof(conf->iptables_location));

            vrmr_sanitize_path(
                    conf->iptables_location, StrLen(conf->iptables_location));

            vrmr_audit("'iptables location' %s '%s'.", STR_IS_NOW_SET_TO,
                    conf->iptables_location);
        } else if (config_section.fields[i] ==
                   GenConfig.iptablesrestorelocfld) {
            /* iptables-restore location */
            copy_field2buf(conf->iptablesrestore_location,
                    field_buffer(config_section.fields[i], 0),
                    sizeof(conf->iptablesrestore_location));

            vrmr_sanitize_path(conf->iptablesrestore_location,
                    StrLen(conf->iptablesrestore_location));

            vrmr_audit("'iptables-restore location' %s '%s'.",
                    STR_IS_NOW_SET_TO, conf->iptablesrestore_location);
        }
#ifdef IPV6_ENABLED
        else if (config_section.fields[i] == GenConfig.ip6tableslocfld) {
            /* ip6tables location */
            copy_field2buf(conf->ip6tables_location,
                    field_buffer(config_section.fields[i], 0),
                    sizeof(conf->ip6tables_location));

            vrmr_sanitize_path(
                    conf->ip6tables_location, StrLen(conf->ip6tables_location));

            vrmr_audit("'ip6tables location' %s '%s'.", STR_IS_NOW_SET_TO,
                    conf->ip6tables_location);
        } else if (config_section.fields[i] ==
                   GenConfig.ip6tablesrestorelocfld) {
            /* ip6tables-restore location */
            copy_field2buf(conf->ip6tablesrestore_location,
                    field_buffer(config_section.fields[i], 0),
                    sizeof(conf->ip6tablesrestore_location));

            vrmr_sanitize_path(conf->ip6tablesrestore_location,
                    StrLen(conf->ip6tablesrestore_location));

            vrmr_audit("'ip6tables-restore location' %s '%s'.",
                    STR_IS_NOW_SET_TO, conf->ip6tablesrestore_location);
        }
#endif
        else if (config_section.fields[i] == GenConfig.tclocfld) {
            /* tc location */
            copy_field2buf(conf->tc_location,
                    field_buffer(config_section.fields[i], 0),
                    sizeof(conf->tc_location));

            vrmr_sanitize_path(conf->tc_location, StrLen(conf->tc_location));

            vrmr_audit("'tc location' %s '%s'.", STR_IS_NOW_SET_TO,
                    conf->tc_location);
        } else if (config_section.fields[i] == GenConfig.max_permission) {
            char buf[5];
            char *endptr;
            long int newval;

            /* maximum file permissions */
            copy_field2buf(buf, field_buffer(config_section.fields[i], 0),
                    sizeof(buf));

            /* Parse it as an octal mode */
            newval = strtol(buf, &endptr, 8);

            /* If strol fails, it will set endptr to buf. Also check that
             * there was no trailing garbage at the end of the string. */
            if (endptr != buf && *endptr == '\0') {
                conf->max_permission = newval;

                vrmr_audit("'maximum permissions' %s '%o'.", STR_IS_NOW_SET_TO,
                        conf->max_permission);
            }
        } else if (config_section.fields[i] == GenConfig.sysctllocfld) {
            /* tc location */
            copy_field2buf(conf->sysctl_location,
                    field_buffer(config_section.fields[i], 0),
                    sizeof(conf->sysctl_location));

            vrmr_sanitize_path(
                    conf->sysctl_location, StrLen(conf->sysctl_location));

            vrmr_audit("'sysctl location' %s '%s'.", STR_IS_NOW_SET_TO,
                    conf->sysctl_location);
        } else {
            vrmr_fatal("unknown field");
        }
    }
}

int edit_genconfig(struct vrmr_config *conf)
{
    int retval = 0, quit = 0;
    int height, width, startx, starty, max_height, max_width;
    FIELD *prev = NULL;

    getmaxyx(stdscr, max_height, max_width);
    height = 18;
    width = 76;
    startx = (max_width - width) / 2;
    starty = (max_height - height) / 2;

    edit_genconfig_init(conf, height, width, starty, startx);
    update_panels();
    doupdate();

    FIELD *cur = current_field(config_section.form);

    /* Loop through to get user requests */
    while (quit == 0) {
        draw_field_active_mark(cur, prev, config_section.win,
                config_section.form, vccnf.color_win_mark | A_BOLD);

        int ch = wgetch(config_section.win);
        int not_defined = 0;
        if (cur == GenConfig.iptableslocfld ||
                cur == GenConfig.iptablesrestorelocfld ||
                cur == GenConfig.sysctllocfld ||
#ifdef IPV6_ENABLED
                cur == GenConfig.ip6tableslocfld ||
                cur == GenConfig.ip6tablesrestorelocfld ||
#endif
                cur == GenConfig.tclocfld || cur == GenConfig.max_permission) {
            not_defined = !(nav_field_simpletext(config_section.form, ch));
        } else {
            not_defined = 1;
        }

        if (not_defined) {
            switch (ch) {
                case 27:
                case KEY_F(10):
                case 'q':
                case 'Q':

                    edit_genconfig_save(conf);
                    quit = 1;
                    break;

                case KEY_DOWN:
                case 10: // enter
                case 9:  // tab
                    // Go to next field
                    form_driver_wrap(config_section.form, REQ_NEXT_FIELD);
                    form_driver_wrap(config_section.form, REQ_END_LINE);
                    break;

                case KEY_UP:
                    // Go to previous field
                    form_driver_wrap(config_section.form, REQ_PREV_FIELD);
                    form_driver_wrap(config_section.form, REQ_END_LINE);
                    break;

                case 127:
                case KEY_BACKSPACE:
                    form_driver_wrap(config_section.form, REQ_PREV_CHAR);
                    form_driver_wrap(config_section.form, REQ_DEL_CHAR);
                    form_driver_wrap(config_section.form, REQ_END_LINE);
                    break;

                case KEY_DC:
                    form_driver_wrap(config_section.form, REQ_PREV_CHAR);
                    form_driver_wrap(config_section.form, REQ_DEL_CHAR);
                    form_driver_wrap(config_section.form, REQ_END_LINE);
                    break;

                case KEY_F(12):
                case 'h':
                case 'H':
                case '?':
                    print_help(":[VUURMUUR:CONFIG:GENERAL]:");
                    break;

                default:
                    /* If this is a normal character, it gets printed into the
                     * field */
                    form_driver_wrap(config_section.form, ch);
                    break;
            }
        }

        prev = cur;
        cur = current_field(config_section.form);
    }

    /* write configfile */
    if (vrmr_write_configfile(conf->configfile, conf) < 0) {
        vrmr_error(-1, VR_ERR, gettext("writing configfile failed."));
        retval = -1;
    }

    /* cleanup */
    edit_config_destroy();
    return (retval);
}

struct {
    FIELD *dynchkfld, *dynchkintfld;
    char number[5];
} IntConfig;

static void edit_intconfig_init(
        struct vrmr_config *conf, int height, int width, int starty, int startx)
{
    int rows = 0, cols = 0;
    size_t i = 0;

    config_section.n_fields = 2;
    config_section.fields =
            (FIELD **)calloc(config_section.n_fields + 1, sizeof(FIELD *));
    vrmr_fatal_alloc("calloc", config_section.fields);

    IntConfig.dynchkfld =
            (config_section.fields[0] = new_field_wrap(1, 1, 1, 1, 0, 0));
    IntConfig.dynchkintfld =
            (config_section.fields[1] = new_field_wrap(1, 4, 3, 20, 0, 0));
    /* terminate */
    config_section.fields[config_section.n_fields] = NULL;

    config_section.win = create_newwin(height, width, starty, startx,
            gettext("Edit Config: Interfaces"), vccnf.color_win);
    config_section.panel[0] = new_panel(config_section.win);

    /* set buffers - first the visible, then the label */
    set_field_buffer_wrap(
            IntConfig.dynchkfld, 0, conf->dynamic_changes_check ? "X" : " ");
    (void)snprintf(IntConfig.number, sizeof(IntConfig.number), "%u",
            conf->dynamic_changes_interval);
    set_field_buffer_wrap(IntConfig.dynchkintfld, 0, IntConfig.number);

    for (i = 0; i < config_section.n_fields; i++) {
        set_field_back(config_section.fields[i], vccnf.color_win_rev | A_BOLD);
        field_opts_off(config_section.fields[i], O_AUTOSKIP);
        set_field_status(config_section.fields[i], FALSE);
    }
    /* toggle */
    set_field_back(IntConfig.dynchkfld, vccnf.color_win);

    // Create the form and post it
    config_section.form = new_form(config_section.fields);
    // Calculate the area required for the form
    scale_form(config_section.form, &rows, &cols);
    keypad(config_section.win, TRUE);
    // Set main window and sub window
    set_form_win(config_section.form, config_section.win);
    set_form_sub(
            config_section.form, derwin(config_section.win, rows, cols, 1, 2));

    post_form(config_section.form);

    /* print labels */
    mvwprintw(config_section.win, 2, 2, "[");
    mvwprintw(config_section.win, 2, 4, "]");
    mvwprintw(config_section.win, 2, 7,
            gettext("check dynamic interfaces for changes."));
    mvwprintw(config_section.win, 4, 2, gettext("Check interval:"));
    mvwprintw(config_section.win, 4, 28, gettext("sec."));
}

static void edit_intconfig_save(struct vrmr_config *conf)
{
    int interval = 0;
    size_t i = 0;

    /* check for changed fields */
    for (i = 0; i < config_section.n_fields; i++) {
        /* we only act if a field is changed */
        if (field_status(config_section.fields[i]) == FALSE)
            continue;

        if (config_section.fields[i] == IntConfig.dynchkintfld) {
            /* synlimit */
            copy_field2buf(IntConfig.number,
                    field_buffer(config_section.fields[i], 0),
                    sizeof(IntConfig.number));

            interval = atoi(IntConfig.number);
            if (interval > 0) {
                conf->dynamic_changes_interval = (unsigned int)interval;

                vrmr_audit("'dynamic changes interval' %s '%u'.",
                        STR_IS_NOW_SET_TO, conf->dynamic_changes_interval);
            }
        } else if (config_section.fields[i] == IntConfig.dynchkfld) {
            if (field_buffer(config_section.fields[i], 0)[0] == 'X')
                conf->dynamic_changes_check = 1;
            else
                conf->dynamic_changes_check = 0;

            vrmr_audit("'check dynamic interfaces for changes' %s '%s'.",
                    STR_IS_NOW_SET_TO,
                    conf->dynamic_changes_check ? STR_YES : STR_NO);
        } else {
            vrmr_fatal("unknown field");
        }
    }
}

static int edit_intconfig(struct vrmr_config *conf)
{
    int retval = 0, quit = 0;
    int height, width, startx, starty, max_height, max_width;
    FIELD *cur = NULL, *prev = NULL;

    getmaxyx(stdscr, max_height, max_width);
    height = 18;
    width = 76;
    startx = (max_width - width) / 2;
    starty = (max_height - height) / 2;
    edit_intconfig_init(conf, height, width, starty, startx);
    cur = current_field(config_section.form);
    update_panels();
    doupdate();

    /* Loop through to get user requests */
    while (quit == 0) {
        draw_field_active_mark(cur, prev, config_section.win,
                config_section.form, vccnf.color_win_mark | A_BOLD);

        int ch = wgetch(config_section.win);
        int not_defined = 0;
        if (cur == IntConfig.dynchkintfld) {
            not_defined = !(nav_field_simpletext(config_section.form, ch));
        } else if (cur == IntConfig.dynchkfld) {
            not_defined = !(nav_field_toggleX(config_section.form, ch));
        } else {
            not_defined = 1;
        }

        if (not_defined) {
            switch (ch) {
                case 27:
                case KEY_F(10):
                case 'q':
                case 'Q':
                    /* save the field to the conf struct */
                    edit_intconfig_save(conf);
                    quit = 1;
                    break;

                case KEY_DOWN:
                case 10: // enter
                case 9:  // tab
                    // Go to next field
                    form_driver_wrap(config_section.form, REQ_NEXT_FIELD);
                    form_driver_wrap(config_section.form, REQ_END_LINE);
                    break;

                case KEY_UP:
                    // Go to previous field
                    form_driver_wrap(config_section.form, REQ_PREV_FIELD);
                    form_driver_wrap(config_section.form, REQ_END_LINE);
                    break;

                case 127:
                case KEY_BACKSPACE:
                    form_driver_wrap(config_section.form, REQ_PREV_CHAR);
                    form_driver_wrap(config_section.form, REQ_DEL_CHAR);
                    form_driver_wrap(config_section.form, REQ_END_LINE);
                    break;

                case KEY_DC:
                    form_driver_wrap(config_section.form, REQ_PREV_CHAR);
                    form_driver_wrap(config_section.form, REQ_DEL_CHAR);
                    form_driver_wrap(config_section.form, REQ_END_LINE);
                    break;

                case KEY_F(12):
                case 'h':
                case 'H':
                case '?':
                    print_help(":[VUURMUUR:CONFIG:INTERFACES]:");
                    break;

                default:
                    /* If this is a normal character, it gets printed into the
                     * field */
                    form_driver_wrap(config_section.form, ch);
                    break;
            }
        }
        prev = cur;
        cur = current_field(config_section.form);
    }

    /* write configfile */
    if (vrmr_write_configfile(conf->configfile, conf) < 0) {
        vrmr_error(-1, VR_ERR, gettext("writing configfile failed."));
        retval = -1;
    }

    /* cleanup */
    edit_config_destroy();
    return (retval);
}

struct {
    FIELD *modprobefld, *loadmodulesfld, *waittimefld;
    char number[6];
} ModConfig;

static void edit_modconfig_init(
        struct vrmr_config *conf, int height, int width, int starty, int startx)
{
    int rows = 0, cols = 0;
    size_t i = 0;

    config_section.n_fields = 3;
    config_section.fields =
            (FIELD **)calloc(config_section.n_fields + 1, sizeof(FIELD *));

    /* */
    ModConfig.modprobefld =
            (config_section.fields[0] = new_field_wrap(1, 64, 2, 1, 0, 0));
    ModConfig.loadmodulesfld =
            (config_section.fields[1] = new_field_wrap(1, 1, 4, 2, 0, 0));
    ModConfig.waittimefld =
            (config_section.fields[2] = new_field_wrap(1, 5, 6, 1, 0, 0));

    /* terminate */
    config_section.fields[config_section.n_fields] = NULL;

    config_section.win = create_newwin(height, width, starty, startx,
            gettext("Edit Config: Modules"), vccnf.color_win);
    config_section.panel[0] = new_panel(config_section.win);

    /* set buffers - first the visible, then the label */
    set_field_buffer_wrap(ModConfig.modprobefld, 0, conf->modprobe_location);
    set_field_buffer_wrap(
            ModConfig.loadmodulesfld, 0, conf->load_modules ? "X" : " ");

    (void)snprintf(ModConfig.number, sizeof(ModConfig.number), "%u",
            conf->modules_wait_time);
    set_field_buffer_wrap(ModConfig.waittimefld, 0, ModConfig.number);

    for (i = 0; i < config_section.n_fields; i++) {
        set_field_back(config_section.fields[i], vccnf.color_win_rev | A_BOLD);
        field_opts_off(config_section.fields[i], O_AUTOSKIP);
        set_field_status(config_section.fields[i], FALSE);
    }
    /* toggle */
    set_field_back(ModConfig.loadmodulesfld, vccnf.color_win);

    // Create the form and post it
    config_section.form = new_form(config_section.fields);
    // Calculate the area required for the form
    scale_form(config_section.form, &rows, &cols);
    keypad(config_section.win, TRUE);
    // Set main window and sub window
    set_form_win(config_section.form, config_section.win);
    set_form_sub(
            config_section.form, derwin(config_section.win, rows, cols, 1, 2));
    post_form(config_section.form);

    /* print labels */
    mvwprintw(
            config_section.win, 2, 2, gettext("Modprobe location (full path)"));
    mvwprintw(config_section.win, 5, 3, "[");
    mvwprintw(config_section.win, 5, 5, "]");
    mvwprintw(config_section.win, 5, 8, gettext("load modules"));
    mvwprintw(config_section.win, 7, 11,
            gettext("waittime after loading a module (in 1/10 th of a "
                    "second)"));
}

static void edit_modconfig_save(struct vrmr_config *conf)
{
    int interval = 0;
    size_t i = 0;

    /* check for changed fields */
    for (i = 0; i < config_section.n_fields; i++) {
        /* we only act if a field is changed */
        if (field_status(config_section.fields[i]) == FALSE)
            continue;

        if (config_section.fields[i] == ModConfig.modprobefld) {
            copy_field2buf(conf->modprobe_location,
                    field_buffer(config_section.fields[i], 0),
                    sizeof(conf->modprobe_location));

            vrmr_sanitize_path(
                    conf->modprobe_location, StrLen(conf->modprobe_location));

            vrmr_audit("'modprobe location' %s '%s'.", STR_IS_NOW_SET_TO,
                    conf->modprobe_location);
        } else if (config_section.fields[i] == ModConfig.loadmodulesfld) {
            if (field_buffer(config_section.fields[i], 0)[0] == 'X')
                conf->load_modules = 1;
            else
                conf->load_modules = 0;

            vrmr_audit("'load modules' %s '%s'.", STR_IS_NOW_SET_TO,
                    conf->load_modules ? STR_YES : STR_NO);
        } else if (config_section.fields[i] == ModConfig.waittimefld) {
            /* synlimit */
            copy_field2buf(ModConfig.number,
                    field_buffer(config_section.fields[i], 0),
                    sizeof(ModConfig.number));

            interval = atoi(ModConfig.number);
            if (interval >= 0) {
                conf->modules_wait_time = (unsigned int)interval;

                vrmr_audit("'modules wait time' %s '%u'.", STR_IS_NOW_SET_TO,
                        conf->modules_wait_time);
            }
        } else {
            vrmr_fatal("unknown field");
        }
    }
}

static int edit_modconfig(struct vrmr_config *conf)
{
    int retval = 0, quit = 0;
    int height, width, startx, starty, max_height, max_width;
    FIELD *cur = NULL, *prev = NULL;

    getmaxyx(stdscr, max_height, max_width);
    height = 18;
    width = 76;
    startx = (max_width - width) / 2;
    starty = (max_height - height) / 2;
    edit_modconfig_init(conf, height, width, starty, startx);
    cur = current_field(config_section.form);
    update_panels();
    doupdate();

    /* Loop through to get user requests */
    while (quit == 0) {
        draw_field_active_mark(cur, prev, config_section.win,
                config_section.form, vccnf.color_win_mark | A_BOLD);

        int ch = wgetch(config_section.win);
        int not_defined = 0;
        if (cur == ModConfig.modprobefld || cur == ModConfig.waittimefld) {
            not_defined = !(nav_field_simpletext(config_section.form, ch));
        } else if (cur == ModConfig.loadmodulesfld) {
            not_defined = !(nav_field_toggleX(config_section.form, ch));
        } else {
            not_defined = 1;
        }

        if (not_defined) {
            switch (ch) {
                case 27:
                case KEY_F(10):
                case 'q':
                case 'Q':

                    edit_modconfig_save(conf);
                    quit = 1;
                    break;

                case KEY_DOWN:
                case 10: // enter
                case 9:  // tab
                    // Go to next field
                    form_driver_wrap(config_section.form, REQ_NEXT_FIELD);
                    form_driver_wrap(config_section.form, REQ_END_LINE);
                    break;

                case KEY_UP:
                    // Go to previous field
                    form_driver_wrap(config_section.form, REQ_PREV_FIELD);
                    form_driver_wrap(config_section.form, REQ_END_LINE);
                    break;

                case 127:
                case KEY_BACKSPACE:
                    form_driver_wrap(config_section.form, REQ_PREV_CHAR);
                    form_driver_wrap(config_section.form, REQ_DEL_CHAR);
                    form_driver_wrap(config_section.form, REQ_END_LINE);
                    break;

                case KEY_DC:
                    form_driver_wrap(config_section.form, REQ_PREV_CHAR);
                    form_driver_wrap(config_section.form, REQ_DEL_CHAR);
                    form_driver_wrap(config_section.form, REQ_END_LINE);
                    break;

                case KEY_F(12):
                case 'h':
                case 'H':
                case '?':
                    print_help(":[VUURMUUR:CONFIG:MODULES]:");
                    break;

                default:
                    /* If this is a normal character, it gets printed into the
                     * field */
                    form_driver_wrap(config_section.form, ch);
                    break;
            }
        }

        prev = cur;
        cur = current_field(config_section.form);
    }

    /* write configfile */
    if (vrmr_write_configfile(conf->configfile, conf) < 0) {
        vrmr_error(-1, VR_ERR, gettext("writing configfile failed."));
        retval = -1;
    }

    /* cleanup */
    edit_config_destroy();
    return (retval);
}

struct {
    FIELD *servbackfld, *zonebackfld, *ifacbackfld, *rulebackfld;
} PlugConfig;

static void edit_plugconfig_init(
        struct vrmr_config *conf, int height, int width, int starty, int startx)
{
    int rows = 0, cols = 0;
    size_t i = 0;

    config_section.n_fields = 4;
    config_section.fields =
            (FIELD **)calloc(config_section.n_fields + 1, sizeof(FIELD *));

    /* backends */
    PlugConfig.servbackfld = (config_section.fields[0] = new_field_wrap(
                                      1, 16, 1, 1, 0, 0)); /* servbackend */
    PlugConfig.zonebackfld = (config_section.fields[1] = new_field_wrap(
                                      1, 16, 3, 1, 0, 0)); /* zonebackend */
    PlugConfig.ifacbackfld = (config_section.fields[2] = new_field_wrap(
                                      1, 16, 5, 1, 0, 0)); /* ifacbackend */
    PlugConfig.rulebackfld = (config_section.fields[3] = new_field_wrap(
                                      1, 16, 7, 1, 0, 0)); /* rulebackend */
    /* terminate */
    config_section.fields[config_section.n_fields] = NULL;

    config_section.win = create_newwin(height, width, starty, startx,
            gettext("Edit Config: Plugins"), vccnf.color_win);
    config_section.panel[0] = new_panel(config_section.win);
    /* set buffers - first the visible, then the label */
    set_field_buffer_wrap(PlugConfig.servbackfld, 0, conf->serv_backend_name);
    set_field_buffer_wrap(PlugConfig.zonebackfld, 0, conf->zone_backend_name);
    set_field_buffer_wrap(PlugConfig.ifacbackfld, 0, conf->ifac_backend_name);
    set_field_buffer_wrap(PlugConfig.rulebackfld, 0, conf->rule_backend_name);

    for (i = 0; i < config_section.n_fields; i++) {
        set_field_back(config_section.fields[i], vccnf.color_win_rev | A_BOLD);
        field_opts_off(config_section.fields[i], O_AUTOSKIP);
        set_field_status(config_section.fields[i], FALSE);
    }

    // Create the form and post it
    config_section.form = new_form(config_section.fields);
    // Calculate the area required for the form
    scale_form(config_section.form, &rows, &cols);
    keypad(config_section.win, TRUE);
    // Set main window and sub window
    set_form_win(config_section.form, config_section.win);
    set_form_sub(
            config_section.form, derwin(config_section.win, rows, cols, 1, 2));

    post_form(config_section.form);

    /* print labels */
    mvwprintw(config_section.win, 1, 2, gettext("Services Backend:"));
    mvwprintw(config_section.win, 3, 2, gettext("Zones Backend:"));
    mvwprintw(config_section.win, 5, 2, gettext("Interfaces Backend:"));
    mvwprintw(config_section.win, 7, 2, gettext("Rules Backend:"));
}

static void edit_plugconfig_save(struct vrmr_config *conf)
{
    size_t i = 0;

    /* check for changed fields */
    for (i = 0; i < config_section.n_fields; i++) {
        /* we only act if a field is changed */
        if (field_status(config_section.fields[i]) == FALSE)
            continue;

        if (config_section.fields[i] == PlugConfig.servbackfld) {
            /* services backend */
            copy_field2buf(conf->serv_backend_name,
                    field_buffer(config_section.fields[i], 0),
                    sizeof(conf->serv_backend_name));

            vrmr_audit("'service backend name' %s '%s'.", STR_IS_NOW_SET_TO,
                    conf->serv_backend_name);
        } else if (config_section.fields[i] == PlugConfig.zonebackfld) {
            /* zones backend */
            copy_field2buf(conf->zone_backend_name,
                    field_buffer(config_section.fields[i], 0),
                    sizeof(conf->zone_backend_name));

            vrmr_audit("'zone backend name' %s '%s'.", STR_IS_NOW_SET_TO,
                    conf->zone_backend_name);
        } else if (config_section.fields[i] == PlugConfig.ifacbackfld) {
            /* interfaces backend */
            copy_field2buf(conf->ifac_backend_name,
                    field_buffer(config_section.fields[i], 0),
                    sizeof(conf->ifac_backend_name));

            vrmr_audit("'interface backend name' %s '%s'.", STR_IS_NOW_SET_TO,
                    conf->ifac_backend_name);
        } else if (config_section.fields[i] == PlugConfig.rulebackfld) {
            /* interfaces backend */
            copy_field2buf(conf->rule_backend_name,
                    field_buffer(config_section.fields[i], 0),
                    sizeof(conf->rule_backend_name));

            vrmr_audit("'rule backend name' %s '%s'.", STR_IS_NOW_SET_TO,
                    conf->rule_backend_name);
        } else {
            vrmr_fatal("unknown field");
        }
    }
}

static int edit_plugconfig(struct vrmr_config *conf)
{
    int retval = 0, quit = 0;
    int height, width, startx, starty, max_height, max_width;
    FIELD *cur = NULL, *prev = NULL;

    getmaxyx(stdscr, max_height, max_width);
    height = 18;
    width = 76;
    startx = (max_width - width) / 2;
    starty = (max_height - height) / 2;
    edit_plugconfig_init(conf, height, width, starty, startx);
    cur = current_field(config_section.form);
    update_panels();
    doupdate();

    /* Loop through to get user requests */
    while (quit == 0) {
        draw_field_active_mark(cur, prev, config_section.win,
                config_section.form, vccnf.color_win_mark | A_BOLD);

        int ch = wgetch(config_section.win);
        int not_defined = 0;
        if (cur == PlugConfig.servbackfld || cur == PlugConfig.zonebackfld ||
                cur == PlugConfig.ifacbackfld ||
                cur == PlugConfig.rulebackfld) {
            not_defined = !(nav_field_simpletext(config_section.form, ch));
        } else {
            not_defined = 1;
        }

        if (not_defined) {
            switch (ch) {
                case 27:
                case KEY_F(10):
                case 'q':
                case 'Q':

                    edit_plugconfig_save(conf);
                    quit = 1;
                    break;

                case KEY_DOWN:
                case 10: // enter
                case 9:  // tab
                    // Go to next field
                    form_driver_wrap(config_section.form, REQ_NEXT_FIELD);
                    form_driver_wrap(config_section.form, REQ_END_LINE);
                    break;

                case KEY_UP:
                    // Go to previous field
                    form_driver_wrap(config_section.form, REQ_PREV_FIELD);
                    form_driver_wrap(config_section.form, REQ_END_LINE);
                    break;

                case 127:
                case KEY_BACKSPACE:
                    form_driver_wrap(config_section.form, REQ_PREV_CHAR);
                    form_driver_wrap(config_section.form, REQ_DEL_CHAR);
                    form_driver_wrap(config_section.form, REQ_END_LINE);
                    break;

                case KEY_DC:
                    form_driver_wrap(config_section.form, REQ_PREV_CHAR);
                    form_driver_wrap(config_section.form, REQ_DEL_CHAR);
                    form_driver_wrap(config_section.form, REQ_END_LINE);
                    break;

                case KEY_F(12):
                case 'h':
                case 'H':
                case '?':
                    print_help(":[VUURMUUR:CONFIG:PLUGINS]:");
                    break;

                default:
                    /* If this is a normal character, it gets printed into the
                     * field */
                    form_driver_wrap(config_section.form, ch);
                    break;
            }
        }

        prev = cur;
        cur = current_field(config_section.form);
    }

    /* write configfile */
    if (vrmr_write_configfile(conf->configfile, conf) < 0) {
        vrmr_error(-1, VR_ERR, gettext("writing configfile failed."));
        retval = -1;
    }

    /* cleanup */
    edit_config_destroy();
    return (retval);
}

struct {
    FIELD *usesynlimitfld, *synlimitfld, *synburstfld;
    FIELD *useudplimitfld, *udplimitfld, *udpburstfld;
    char number[8];
} ConConfig;

static void edit_conconfig_init(
        struct vrmr_config *conf, int height, int width, int starty, int startx)
{
    int rows = 0, cols = 0;
    size_t i = 0;

    config_section.n_fields = 6;
    config_section.fields =
            (FIELD **)calloc(config_section.n_fields + 1, sizeof(FIELD *));

    /* fields */
    ConConfig.usesynlimitfld = (config_section.fields[0] = new_field_wrap(1, 1,
                                        3, 2, 0, 0)); /* log logblocklist */
    ConConfig.synlimitfld = (config_section.fields[1] = new_field_wrap(
                                     1, 8, 5, 1, 0, 0)); /* SYN-limit */
    ConConfig.synburstfld = (config_section.fields[2] = new_field_wrap(
                                     1, 8, 7, 1, 0, 0)); /* SYN-limit-burst */

    ConConfig.useudplimitfld = (config_section.fields[3] = new_field_wrap(1, 1,
                                        10, 2, 0, 0)); /* log logblocklist */
    ConConfig.udplimitfld = (config_section.fields[4] = new_field_wrap(
                                     1, 8, 12, 1, 0, 0)); /* UDP-limit */
    ConConfig.udpburstfld = (config_section.fields[5] = new_field_wrap(
                                     1, 8, 14, 1, 0, 0)); /* UDP-limit-burst */

    config_section.fields[config_section.n_fields] = NULL;

    /* create win & pan */
    config_section.win = create_newwin(height, width, starty, startx,
            gettext("Edit Config: Connections"), vccnf.color_win);
    vrmr_fatal_if_null(config_section.win);
    config_section.panel[0] = new_panel(config_section.win);
    vrmr_fatal_if_null(config_section.panel[0]);

    /* set fields */
    (void)snprintf(
            ConConfig.number, sizeof(ConConfig.number), "%u", conf->syn_limit);
    set_field_buffer_wrap(ConConfig.synlimitfld, 0, ConConfig.number);

    (void)snprintf(ConConfig.number, sizeof(ConConfig.number), "%u",
            conf->syn_limit_burst);
    set_field_buffer_wrap(ConConfig.synburstfld, 0, ConConfig.number);

    (void)snprintf(
            ConConfig.number, sizeof(ConConfig.number), "%u", conf->udp_limit);
    set_field_buffer_wrap(ConConfig.udplimitfld, 0, ConConfig.number);

    (void)snprintf(ConConfig.number, sizeof(ConConfig.number), "%u",
            conf->udp_limit_burst);
    set_field_buffer_wrap(ConConfig.udpburstfld, 0, ConConfig.number);

    set_field_buffer_wrap(
            ConConfig.usesynlimitfld, 0, conf->use_syn_limit ? "X" : " ");
    set_field_buffer_wrap(
            ConConfig.useudplimitfld, 0, conf->use_udp_limit ? "X" : " ");

    for (i = 0; i < config_section.n_fields; i++) {
        set_field_back(config_section.fields[i], vccnf.color_win_rev | A_BOLD);
        field_opts_off(config_section.fields[i], O_AUTOSKIP);
        set_field_status(config_section.fields[i], FALSE);
    }
    set_field_back(ConConfig.usesynlimitfld, vccnf.color_win);
    set_field_back(ConConfig.useudplimitfld, vccnf.color_win);

    config_section.form = new_form(config_section.fields);
    vrmr_fatal_if_null(config_section.form);
    /* Calculate the area required for the form */
    scale_form(config_section.form, &rows, &cols);
    keypad(config_section.win, TRUE);
    /* Set main window and sub window */
    set_form_win(config_section.form, config_section.win);
    set_form_sub(
            config_section.form, derwin(config_section.win, rows, cols, 1, 2));
    post_form(config_section.form);

    /* print labels */
    mvwprintw(config_section.win, 2, 2,
            gettext("You can limit the number of new connections per second:"));

    mvwprintw(config_section.win, 4, 3, "[");
    mvwprintw(config_section.win, 4, 5, "]");
    mvwprintw(config_section.win, 4, 8, gettext("Limit new TCP connections."));
    mvwprintw(config_section.win, 6, 13,
            gettext("Number of SYN-packets per second"));
    mvwprintw(config_section.win, 8, 13, gettext("Burst-rate"));

    mvwprintw(config_section.win, 11, 3, "[");
    mvwprintw(config_section.win, 11, 5, "]");
    mvwprintw(
            config_section.win, 11, 8, gettext("Limit new udp 'connections'."));

    mvwprintw(config_section.win, 13, 13,
            gettext("Number of new UDP 'connections' per second"));
    mvwprintw(config_section.win, 15, 13, gettext("Burst-rate"));
}

static void edit_conconfig_save(struct vrmr_config *conf)
{
    size_t i = 0;
    int syn = 0, udplimit = 0;

    /* check for changed fields */
    for (i = 0; i < config_section.n_fields; i++) {
        /* we only act if a field is changed */
        if (field_status(config_section.fields[i]) == FALSE)
            continue;

        if (config_section.fields[i] == ConConfig.usesynlimitfld) {
            /* log policy */
            if (field_buffer(config_section.fields[i], 0)[0] == 'X')
                conf->use_syn_limit = 1;
            else
                conf->use_syn_limit = 0;

            vrmr_audit("'use syn limit' %s '%s'.", STR_IS_NOW_SET_TO,
                    conf->use_syn_limit ? STR_YES : STR_NO);
        } else if (config_section.fields[i] == ConConfig.synlimitfld) {
            /* synlimit */
            copy_field2buf(ConConfig.number,
                    field_buffer(config_section.fields[i], 0),
                    sizeof(ConConfig.number));

            syn = atoi(ConConfig.number);
            if (syn > 0) {
                conf->syn_limit = (unsigned int)syn;

                vrmr_audit("'syn limit' %s '%u'.", STR_IS_NOW_SET_TO,
                        conf->syn_limit);
            }
        } else if (config_section.fields[i] == ConConfig.synburstfld) {
            /* synlimit */
            copy_field2buf(ConConfig.number,
                    field_buffer(config_section.fields[i], 0),
                    sizeof(ConConfig.number));

            syn = atoi(ConConfig.number);
            if (syn > 0) {
                conf->syn_limit_burst = (unsigned int)syn;

                vrmr_audit("'syn limit burst' %s '%u'.", STR_IS_NOW_SET_TO,
                        conf->syn_limit_burst);
            }
        } else if (config_section.fields[i] == ConConfig.useudplimitfld) {
            /* log policy */
            if (field_buffer(config_section.fields[i], 0)[0] == 'X')
                conf->use_udp_limit = 1;
            else
                conf->use_udp_limit = 0;

            vrmr_audit("'use udp limit' %s '%s'.", STR_IS_NOW_SET_TO,
                    conf->use_udp_limit ? STR_YES : STR_NO);
        } else if (config_section.fields[i] == ConConfig.udplimitfld) {
            /* udplimit */
            copy_field2buf(ConConfig.number,
                    field_buffer(config_section.fields[i], 0),
                    sizeof(ConConfig.number));

            udplimit = atoi(ConConfig.number);
            if (udplimit > 0) {
                conf->udp_limit = (unsigned int)udplimit;

                vrmr_audit("'udp limit' %s '%u'.", STR_IS_NOW_SET_TO,
                        conf->udp_limit);
            }
        } else if (config_section.fields[i] == ConConfig.udpburstfld) {
            /* udpburst */
            copy_field2buf(ConConfig.number,
                    field_buffer(config_section.fields[i], 0),
                    sizeof(ConConfig.number));

            udplimit = atoi(ConConfig.number);
            if (udplimit > 0) {
                conf->udp_limit_burst = (unsigned int)udplimit;

                vrmr_audit("'udp limit burst' %s '%u'.", STR_IS_NOW_SET_TO,
                        conf->udp_limit_burst);
            }
        } else {
            vrmr_fatal("unknown field");
        }
    }
}

static int edit_conconfig(struct vrmr_config *conf)
{
    int retval = 0, quit = 0;
    int height, width, startx, starty, max_height, max_width;
    FIELD *cur = NULL, *prev = NULL;

    /* window dimentions */
    getmaxyx(stdscr, max_height, max_width);
    height = 18;
    width = 76;
    startx = (max_width - width) / 2;
    starty = (max_height - height) / 2;

    /* setup */
    edit_conconfig_init(conf, height, width, starty, startx);
    cur = current_field(config_section.form);
    update_panels();
    doupdate();

    /* Loop through to get user requests */
    while (quit == 0) {
        /* visual support */
        draw_field_active_mark(cur, prev, config_section.win,
                config_section.form, vccnf.color_win_mark | A_BOLD);

        /* when not using synlimit, deactivated the fields */
        if (field_buffer(ConConfig.usesynlimitfld, 0)[0] == 'X') {
            field_opts_on(ConConfig.synlimitfld, O_ACTIVE);
            field_opts_on(ConConfig.synburstfld, O_ACTIVE);
        } else {
            field_opts_off(ConConfig.synlimitfld, O_ACTIVE);
            field_opts_off(ConConfig.synburstfld, O_ACTIVE);
        }

        /* when not using udplimit, deactivated the fields */
        if (field_buffer(ConConfig.useudplimitfld, 0)[0] == 'X') {
            field_opts_on(ConConfig.udplimitfld, O_ACTIVE);
            field_opts_on(ConConfig.udpburstfld, O_ACTIVE);
        } else {
            field_opts_off(ConConfig.udplimitfld, O_ACTIVE);
            field_opts_off(ConConfig.udpburstfld, O_ACTIVE);
        }

        int ch = wgetch(config_section.win);
        int not_defined = 0;
        if (cur == ConConfig.synlimitfld || cur == ConConfig.synburstfld ||
                cur == ConConfig.udplimitfld || cur == ConConfig.udpburstfld) {
            not_defined = !(nav_field_simpletext(config_section.form, ch));
        } else if (cur == ConConfig.usesynlimitfld ||
                   cur == ConConfig.useudplimitfld) {
            not_defined = !(nav_field_toggleX(config_section.form, ch));
        } else {
            not_defined = 1;
        }

        if (not_defined) {
            switch (ch) {
                case 27:
                case KEY_F(10):
                case 'q':
                case 'Q':
                    quit = 1;
                    break;

                case KEY_DOWN:
                case 10: // enter
                case 9:  // tab
                    // Go to next field
                    form_driver_wrap(config_section.form, REQ_NEXT_FIELD);
                    form_driver_wrap(config_section.form, REQ_END_LINE);
                    break;

                case KEY_UP:
                    // Go to previous field
                    form_driver_wrap(config_section.form, REQ_PREV_FIELD);
                    form_driver_wrap(config_section.form, REQ_END_LINE);
                    break;

                case 127:
                case KEY_BACKSPACE:
                    form_driver_wrap(config_section.form, REQ_PREV_CHAR);
                    form_driver_wrap(config_section.form, REQ_DEL_CHAR);
                    form_driver_wrap(config_section.form, REQ_END_LINE);
                    break;

                case KEY_DC:
                    form_driver_wrap(config_section.form, REQ_PREV_CHAR);
                    form_driver_wrap(config_section.form, REQ_DEL_CHAR);
                    form_driver_wrap(config_section.form, REQ_END_LINE);
                    break;

                case KEY_F(12):
                case 'h':
                case 'H':
                case '?':
                    print_help(":[VUURMUUR:CONFIG:CONNECTIONS]:");
                    break;

                default:
                    /* If this is a normal character, it gets printed into the
                     * field */
                    form_driver_wrap(config_section.form, ch);
                    break;
            }
        }

        prev = cur;
        cur = current_field(config_section.form);
    }

    edit_conconfig_save(conf);
    if (vrmr_write_configfile(conf->configfile, conf) < 0) {
        vrmr_error(-1, VR_ERR, gettext("writing configfile failed."));
        retval = -1;
    }

    /* cleanup */
    edit_config_destroy();
    return (retval);
}

struct {
    FIELD *newrule_loglimitfld, *newrule_logfld, *logview_bufsizefld,
            *advancedmodefld, *mainmenu_statusfld, *backgroundfld,
            *iptrafvollocfld;
    char number[8];
} VcConfig;

static void edit_vcconfig_init(int height, int width, int starty, int startx)
{
    size_t i = 0;
    int rows = 0, cols = 0;

    config_section.n_fields = 7;
    config_section.fields =
            (FIELD **)calloc(config_section.n_fields + 1, sizeof(FIELD *));

    /* fields */
    VcConfig.newrule_logfld =
            (config_section.fields[0] = new_field_wrap(1, 1, 2, 23, 0, 0));
    VcConfig.newrule_loglimitfld =
            (config_section.fields[1] = new_field_wrap(1, 3, 2, 66, 0, 0));
    VcConfig.logview_bufsizefld =
            (config_section.fields[2] = new_field_wrap(1, 6, 5, 52, 0, 0));
    VcConfig.advancedmodefld =
            (config_section.fields[3] = new_field_wrap(1, 1, 6, 53, 0, 0));
    VcConfig.mainmenu_statusfld =
            (config_section.fields[4] = new_field_wrap(1, 1, 7, 53, 0, 0));
    VcConfig.backgroundfld =
            (config_section.fields[5] = new_field_wrap(1, 1, 8, 53, 0, 0));
    VcConfig.iptrafvollocfld =
            (config_section.fields[6] = new_field_wrap(1, 64, 11, 1, 0, 0));
    config_section.fields[config_section.n_fields] = NULL;

    /* create win & pan */
    config_section.win = create_newwin(height, width, starty, startx,
            gettext("Vuurmuur_conf Settings"), vccnf.color_win);
    vrmr_fatal_if_null(config_section.win);
    config_section.panel[0] = new_panel(config_section.win);
    vrmr_fatal_if_null(config_section.panel[0]);

    /* set fields */
    set_field_buffer_wrap(
            VcConfig.newrule_logfld, 0, vccnf.newrule_log ? "X" : " ");

    (void)snprintf(VcConfig.number, sizeof(VcConfig.number), "%u",
            vccnf.newrule_loglimit);
    set_field_buffer_wrap(VcConfig.newrule_loglimitfld, 0, VcConfig.number);

    (void)snprintf(VcConfig.number, sizeof(VcConfig.number), "%u",
            vccnf.logview_bufsize);
    set_field_buffer_wrap(VcConfig.logview_bufsizefld, 0, VcConfig.number);

    set_field_buffer_wrap(
            VcConfig.advancedmodefld, 0, vccnf.advanced_mode ? "X" : " ");
    set_field_buffer_wrap(
            VcConfig.mainmenu_statusfld, 0, vccnf.draw_status ? "X" : " ");
    set_field_buffer_wrap(
            VcConfig.backgroundfld, 0, vccnf.background ? "X" : " ");
    set_field_buffer_wrap(
            VcConfig.iptrafvollocfld, 0, vccnf.iptrafvol_location);

    for (i = 0; i < config_section.n_fields; i++) {
        set_field_back(config_section.fields[i], vccnf.color_win_rev | A_BOLD);
        field_opts_off(config_section.fields[i], O_AUTOSKIP);
        set_field_status(config_section.fields[i], FALSE);
    }
    set_field_back(VcConfig.newrule_logfld, vccnf.color_win);
    set_field_back(VcConfig.advancedmodefld, vccnf.color_win);
    set_field_back(VcConfig.mainmenu_statusfld, vccnf.color_win);
    set_field_back(VcConfig.backgroundfld, vccnf.color_win);

    /* Create the form and post it */
    config_section.form = new_form(config_section.fields);
    vrmr_fatal_if_null(config_section.form);
    /* Calculate the area required for the form */
    scale_form(config_section.form, &rows, &cols);
    keypad(config_section.win, TRUE);
    /* Set main window and sub window */
    set_form_win(config_section.form, config_section.win);
    set_form_sub(
            config_section.form, derwin(config_section.win, rows, cols, 1, 2));
    post_form(config_section.form);

    /* print labels */
    mvwprintw(config_section.win, 2, 2,
            gettext("Defaults for creating new rules:"));

    mvwprintw(config_section.win, 3, 2, gettext("Log the rule"));
    mvwprintw(config_section.win, 3, 24, "[");
    mvwprintw(config_section.win, 3, 26, "]");

    mvwprintw(config_section.win, 3, 35, gettext("Loglimit per second"));

    mvwprintw(config_section.win, 6, 2,
            gettext("Buffersize logviewer (number of lines):"));
    mvwprintw(config_section.win, 7, 2, gettext("Advanced mode by default:"));
    mvwprintw(config_section.win, 7, 54, "[");
    mvwprintw(config_section.win, 7, 56, "]");

    mvwprintw(config_section.win, 8, 2, gettext("Draw status in Main Menu:"));
    mvwprintw(config_section.win, 8, 54, "[");
    mvwprintw(config_section.win, 8, 56, "]");

    mvwprintw(config_section.win, 9, 2, gettext("Use black background?:"));
    mvwprintw(config_section.win, 9, 54, "[");
    mvwprintw(config_section.win, 9, 56, "]");

    mvwprintw(config_section.win, 11, 2,
            gettext("iptrafvol.pl location (full path)"));
}

static void edit_vcconfig_save(void)
{
    size_t i = 0;
    int syn = 0;
    int bufsize = 0;

    /* check for changed fields */
    for (i = 0; i < config_section.n_fields; i++) {
        /* we only act if a field is changed */
        if (field_status(config_section.fields[i]) == FALSE)
            continue;

        if (config_section.fields[i] == VcConfig.newrule_loglimitfld) {
            /* synlimit */
            copy_field2buf(VcConfig.number,
                    field_buffer(config_section.fields[i], 0),
                    sizeof(VcConfig.number));

            syn = atoi(VcConfig.number);
            if (syn > 0) {
                vccnf.newrule_loglimit = (unsigned int)syn;
            }
        } else if (config_section.fields[i] == VcConfig.newrule_logfld) {
            if (field_buffer(config_section.fields[i], 0)[0] == 'X')
                vccnf.newrule_log = 1;
            else
                vccnf.newrule_log = 0;
        } else if (config_section.fields[i] == VcConfig.advancedmodefld) {
            if (field_buffer(config_section.fields[i], 0)[0] == 'X')
                vccnf.advanced_mode = 1;
            else
                vccnf.advanced_mode = 0;
        } else if (config_section.fields[i] == VcConfig.mainmenu_statusfld) {
            if (field_buffer(config_section.fields[i], 0)[0] == 'X')
                vccnf.draw_status = 1;
            else
                vccnf.draw_status = 0;
        } else if (config_section.fields[i] == VcConfig.backgroundfld) {
            if (field_buffer(config_section.fields[i], 0)[0] == 'X')
                vccnf.background = 1;
            else
                vccnf.background = 0;
        } else if (config_section.fields[i] == VcConfig.logview_bufsizefld) {
            /* bufsize */
            copy_field2buf(VcConfig.number,
                    field_buffer(config_section.fields[i], 0),
                    sizeof(VcConfig.number));

            bufsize = atoi(VcConfig.number);
            if (bufsize > 0) {
                vccnf.logview_bufsize = (unsigned int)bufsize;
            }
        } else if (config_section.fields[i] == VcConfig.iptrafvollocfld) {
            /* synlimit */
            copy_field2buf(vccnf.iptrafvol_location,
                    field_buffer(config_section.fields[i], 0),
                    sizeof(vccnf.iptrafvol_location));

            vrmr_sanitize_path(
                    vccnf.iptrafvol_location, StrLen(vccnf.iptrafvol_location));
        } else {
            vrmr_fatal("unknown field");
        }
    }
}

int edit_vcconfig(void)
{
    int retval = 0, quit = 0;
    int height, width, startx, starty, max_height, max_width;
    FIELD *cur = NULL, *prev = NULL;

    /* top menu */
    char *key_choices[] = {"F12", "F10"};
    int key_choices_n = 2;
    char *cmd_choices[] = {gettext("help"), gettext("back")};
    int cmd_choices_n = 2;

    /* window dimentions */
    getmaxyx(stdscr, max_height, max_width);
    height = 18;
    width = 76;
    startx = (max_width - width) / 2;
    starty = (max_height - height) / 2;
    /* setup */
    edit_vcconfig_init(height, width, starty, startx);
    cur = current_field(config_section.form);
    draw_top_menu(top_win, gettext("Vuurmuur_conf Settings"), key_choices_n,
            key_choices, cmd_choices_n, cmd_choices);
    update_panels();
    doupdate();

    /* Loop through to get user requests */
    while (quit == 0) {
        /* visual support */
        draw_field_active_mark(cur, prev, config_section.win,
                config_section.form, vccnf.color_win_mark | A_BOLD);

        /* keyboard input */
        int ch = wgetch(config_section.win);
        int not_defined = 0;
        if (cur == VcConfig.newrule_loglimitfld ||
                cur == VcConfig.logview_bufsizefld ||
                cur == VcConfig.iptrafvollocfld) {
            not_defined = !(nav_field_simpletext(config_section.form, ch));
        } else if (cur == VcConfig.newrule_logfld ||
                   cur == VcConfig.advancedmodefld ||
                   cur == VcConfig.mainmenu_statusfld ||
                   cur == VcConfig.backgroundfld) {
            not_defined = !(nav_field_toggleX(config_section.form, ch));
            if (!not_defined) {
                /* hack to make color setting available instantly */
                if (cur == VcConfig.backgroundfld) {
                    if (field_buffer(cur, 0)[0] == 'X')
                        vccnf.background = 1;
                    else
                        vccnf.background = 0;
                    setup_colors();
                }
            }
        } else {
            not_defined = 1;
        }

        if (not_defined) {
            switch (ch) {
                case 27:
                case KEY_F(10):
                case 'q':
                case 'Q':
                    quit = 1;
                    break;

                case KEY_DOWN:
                case 10: // enter
                case 9:  // tab
                    // Go to next field
                    form_driver_wrap(config_section.form, REQ_NEXT_FIELD);
                    form_driver_wrap(config_section.form, REQ_END_LINE);
                    break;

                case KEY_UP:
                    // Go to previous field
                    form_driver_wrap(config_section.form, REQ_PREV_FIELD);
                    form_driver_wrap(config_section.form, REQ_END_LINE);
                    break;

                case 127:
                case KEY_BACKSPACE:
                    form_driver_wrap(config_section.form, REQ_PREV_CHAR);
                    form_driver_wrap(config_section.form, REQ_DEL_CHAR);
                    form_driver_wrap(config_section.form, REQ_END_LINE);
                    break;

                case KEY_DC:
                    form_driver_wrap(config_section.form, REQ_PREV_CHAR);
                    form_driver_wrap(config_section.form, REQ_DEL_CHAR);
                    form_driver_wrap(config_section.form, REQ_END_LINE);
                    break;

                case KEY_F(12):
                case 'h':
                case 'H':
                case '?':
                    print_help(":[VUURMUURCONF:SETTINGS]:");
                    break;

                default:
                    /* If this is a normal character, it gets printed into the
                     * field */
                    form_driver_wrap(config_section.form, ch);
                    break;
            }
        }

        prev = cur;
        cur = current_field(config_section.form);
    }

    edit_vcconfig_save();
    if (write_vcconfigfile(vccnf.configfile_location, &vccnf) < 0) {
        vrmr_error(-1, VR_ERR, gettext("writing configfile failed."));
        retval = -1;
    }

    /* cleanup */
    edit_config_destroy();
    setup_colors();
    return (retval);
}

struct {
    FIELD *nfgrpfld, *logdirfld,

            *logpolicyfld, *logpolicylimitfld, *logblocklistfld,

            *loginvalidfld, *lognosynfld, *logprobesfld, *logfragfld;
} LogConfig;

static void edit_logconfig_init(
        struct vrmr_config *conf, int height, int width, int starty, int startx)
{
    size_t i = 0;
    int rows = 0, cols = 0;
    char limit_string[4] = "";

    config_section.n_fields = 9;
    config_section.fields =
            (FIELD **)calloc(config_section.n_fields + 1, sizeof(FIELD *));
    vrmr_fatal_if_null(config_section.fields);

    /* fields */
    LogConfig.nfgrpfld = (config_section.fields[0] = new_field_wrap(
                                  1, 3, 1, 60, 0, 0)); /* nfgrp */

    LogConfig.logdirfld = (config_section.fields[1] = new_field_wrap(
                                   1, 64, 4, 1, 0, 0)); /* vuurmuur_logdir */

    LogConfig.logpolicyfld = (config_section.fields[2] = new_field_wrap(
                                      1, 1, 6, 61, 0, 0)); /* log policy */
    LogConfig.logpolicylimitfld =
            (config_section.fields[3] = new_field_wrap(
                     1, 3, 7, 60, 0, 0)); /* log policy limit */
    LogConfig.logblocklistfld = (config_section.fields[4] = new_field_wrap(1, 1,
                                         8, 61, 0, 0)); /* log logblocklist */

    LogConfig.loginvalidfld = (config_section.fields[5] = new_field_wrap(1, 1,
                                       9, 61, 0, 0)); /* log logblocklist */
    LogConfig.lognosynfld = (config_section.fields[6] = new_field_wrap(1, 1, 10,
                                     61, 0, 0)); /* log logblocklist */
    LogConfig.logprobesfld = (config_section.fields[7] = new_field_wrap(
                                      1, 1, 11, 61, 0, 0)); /* log logprobes */
    LogConfig.logfragfld = (config_section.fields[8] = new_field_wrap(
                                    1, 1, 12, 61, 0, 0)); /* log logblocklist */

    config_section.fields[config_section.n_fields] = NULL;

    set_field_type(LogConfig.nfgrpfld, TYPE_INTEGER, 0, 1, 999);
    // blanks the field when using a 0 setting, so disable
    // set_field_type(LogConfig.logpolicylimitfld, TYPE_INTEGER, 0, 0, 999);

    config_section.win = create_newwin(height, width, starty, startx,
            gettext("Edit Config: Logging"), vccnf.color_win);
    vrmr_fatal_if_null(config_section.win);
    config_section.panel[0] = new_panel(config_section.win);
    vrmr_fatal_if_null(config_section.panel[0]);

    /* fill the fields */
    if (conf->nfgrp > 0) {
        (void)snprintf(limit_string, sizeof(limit_string), "%u", conf->nfgrp);
        set_field_buffer_wrap(LogConfig.nfgrpfld, 0, limit_string);
    }
    set_field_buffer_wrap(
            LogConfig.logdirfld, 0, conf->vuurmuur_logdir_location);
    set_field_buffer_wrap(
            LogConfig.logpolicyfld, 0, conf->log_policy ? "X" : " ");
    if (conf->log_policy_limit > 0) {
        (void)snprintf(limit_string, sizeof(limit_string), "%u",
                conf->log_policy_limit);
        set_field_buffer_wrap(LogConfig.logpolicylimitfld, 0, limit_string);
    }
    set_field_buffer_wrap(
            LogConfig.logblocklistfld, 0, conf->log_blocklist ? "X" : " ");
    set_field_buffer_wrap(
            LogConfig.loginvalidfld, 0, conf->log_invalid ? "X" : " ");
    set_field_buffer_wrap(
            LogConfig.lognosynfld, 0, conf->log_no_syn ? "X" : " ");
    set_field_buffer_wrap(
            LogConfig.logprobesfld, 0, conf->log_probes ? "X" : " ");
    set_field_buffer_wrap(LogConfig.logfragfld, 0, conf->log_frag ? "X" : " ");

    for (i = 0; i < config_section.n_fields; i++) {
        set_field_back(config_section.fields[i], vccnf.color_win_rev | A_BOLD);
        field_opts_off(config_section.fields[i], O_AUTOSKIP);
        set_field_status(config_section.fields[i], FALSE);
    }
    set_field_back(LogConfig.logpolicyfld, vccnf.color_win);
    set_field_back(LogConfig.logblocklistfld, vccnf.color_win);
    set_field_back(LogConfig.loginvalidfld, vccnf.color_win);
    set_field_back(LogConfig.lognosynfld, vccnf.color_win);
    set_field_back(LogConfig.logprobesfld, vccnf.color_win);
    set_field_back(LogConfig.logfragfld, vccnf.color_win);

    /* Create the form and post it */
    config_section.form = new_form(config_section.fields);
    /* Calculate the area required for the form */
    scale_form(config_section.form, &rows, &cols);
    keypad(config_section.win, TRUE);
    /* Set main window and sub window */
    set_form_win(config_section.form, config_section.win);
    set_form_sub(
            config_section.form, derwin(config_section.win, rows, cols, 1, 2));
    post_form(config_section.form);

    /* print labels */
    mvwprintw(config_section.win, 2, 2, gettext("Netfilter Group"));

    mvwprintw(config_section.win, 4, 2,
            gettext("Vuurmuur logfiles location (full path):"));

    mvwprintw(config_section.win, 7, 2,
            gettext("Log the default policy? (DROP):"));
    mvwprintw(config_section.win, 7, 62, "[");
    mvwprintw(config_section.win, 7, 64, "]");

    mvwprintw(config_section.win, 8, 2,
            gettext("Limit of the number of logs per second (0 for no "
                    "limit):"));

    /* TRANSLATORS: max 55 chars */
    mvwprintw(config_section.win, 9, 2, gettext("Log blocklist violations:"));
    mvwprintw(config_section.win, 9, 62, "[");
    mvwprintw(config_section.win, 9, 64, "]");

    /* TRANSLATORS: max 55 chars, don't translate 'INVALID' */
    mvwprintw(config_section.win, 10, 2,
            gettext("Log packets with state INVALID:"));
    mvwprintw(config_section.win, 10, 62, "[");
    mvwprintw(config_section.win, 10, 64, "]");

    /* TRANSLATORS: max 55 chars */
    mvwprintw(config_section.win, 11, 2,
            gettext("Log new TCP packets with no SYN flag set:"));
    mvwprintw(config_section.win, 11, 62, "[");
    mvwprintw(config_section.win, 11, 64, "]");

    /* TRANSLATORS: max 55 chars */
    mvwprintw(config_section.win, 12, 2, gettext("Log scan probe packets:"));
    mvwprintw(config_section.win, 12, 62, "[");
    mvwprintw(config_section.win, 12, 64, "]");

    /* TRANSLATORS: max 55 chars */
    mvwprintw(config_section.win, 13, 2, gettext("Log Fragments:"));
    mvwprintw(config_section.win, 13, 62, "[");
    mvwprintw(config_section.win, 13, 64, "]");
}

static int edit_logconfig_save(struct vrmr_config *conf)
{
    int retval = 0;
    size_t i = 0;
    char limit_string[4] = "";
    int result = 0;

    /* check for changed fields */
    for (i = 0; i < config_section.n_fields; i++) {
        /* we only act if a field is changed */
        if (field_status(config_section.fields[i]) == FALSE)
            continue;

        if (config_section.fields[i] == LogConfig.logdirfld) {
            /* vuurmuurlog location */
            copy_field2buf(conf->vuurmuur_logdir_location,
                    field_buffer(config_section.fields[i], 0),
                    sizeof(conf->vuurmuur_logdir_location));

            if (StrLen(conf->vuurmuur_logdir_location) > 0) {
                /* cut of the trailing slash if we have any */
                if (conf->vuurmuur_logdir_location
                                [StrMemLen(conf->vuurmuur_logdir_location) -
                                        1] == '/')
                    conf->vuurmuur_logdir_location
                            [StrMemLen(conf->vuurmuur_logdir_location) - 1] =
                            '\0';
            }

            vrmr_sanitize_path(conf->vuurmuur_logdir_location,
                    StrLen(conf->vuurmuur_logdir_location));

            if (vrmr_config_check_logdir(conf->vuurmuur_logdir_location) < 0) {
                retval = -1;
            } else {
                /* print a warning about apply changes won't work for logdir
                 */
                vrmr_warning(VR_WARN,
                        gettext("changing the logdir requires applying changes "
                                "to get into effect in the logviewer."));

                vrmr_audit("'logdir location' %s '%s'.", STR_IS_NOW_SET_TO,
                        conf->vuurmuur_logdir_location);
            }
        } else if (config_section.fields[i] == LogConfig.nfgrpfld) {
            /* NF group*/
            copy_field2buf(limit_string,
                    field_buffer(config_section.fields[i], 0),
                    sizeof(limit_string));

            result = atoi(limit_string);
            if (result < 1 || result > 999) {
                vrmr_error(
                        -1, VR_ERR, gettext("NF group must be between 1-999."));

                /* restore the field */
                if (conf->nfgrp > 0) {
                    (void)snprintf(limit_string, sizeof(limit_string), "%u",
                            conf->nfgrp);
                    set_field_buffer_wrap(LogConfig.nfgrpfld, 0, limit_string);
                }
            } else {
                conf->nfgrp = (unsigned int)result;

                vrmr_audit("'nfgrp' %s '%u'.", STR_IS_NOW_SET_TO, conf->nfgrp);
            }
        } else if (config_section.fields[i] == LogConfig.logpolicyfld) {
            /* log policy */
            if (field_buffer(config_section.fields[i], 0)[0] == 'X')
                conf->log_policy = 1;
            else
                conf->log_policy = 0;

            vrmr_audit("'log policy' %s '%s'.", STR_IS_NOW_SET_TO,
                    conf->log_policy ? STR_YES : STR_NO);
        } else if (config_section.fields[i] == LogConfig.logpolicylimitfld) {
            /* log policy limit */
            copy_field2buf(limit_string,
                    field_buffer(config_section.fields[i], 0),
                    sizeof(limit_string));

            result = atoi(limit_string);
            if (result < 0 || result > 999) {
                vrmr_error(-1, VR_ERR, gettext("limit must be between 0-999."));

                /* restore the field */
                if (conf->log_policy_limit > 0) {
                    (void)snprintf(limit_string, sizeof(limit_string), "%u",
                            conf->log_policy_limit);
                    set_field_buffer_wrap(
                            LogConfig.logpolicylimitfld, 0, limit_string);
                }
            } else {
                conf->log_policy_limit = (unsigned int)result;

                vrmr_audit("'log policy limit' %s '%u'.", STR_IS_NOW_SET_TO,
                        conf->log_policy_limit);
            }
        } else if (config_section.fields[i] == LogConfig.logblocklistfld) {
            /* log policy */
            if (field_buffer(config_section.fields[i], 0)[0] == 'X')
                conf->log_blocklist = 1;
            else
                conf->log_blocklist = 0;

            vrmr_audit("'log blocklist' %s '%s'.", STR_IS_NOW_SET_TO,
                    conf->log_blocklist ? STR_YES : STR_NO);
        } else if (config_section.fields[i] == LogConfig.loginvalidfld) {
            /* log policy */
            if (field_buffer(config_section.fields[i], 0)[0] == 'X')
                conf->log_invalid = 1;
            else
                conf->log_invalid = 0;

            vrmr_audit("'log invalid' %s '%s'.", STR_IS_NOW_SET_TO,
                    conf->log_invalid ? STR_YES : STR_NO);
        } else if (config_section.fields[i] == LogConfig.lognosynfld) {
            /* log policy */
            if (field_buffer(config_section.fields[i], 0)[0] == 'X')
                conf->log_no_syn = 1;
            else
                conf->log_no_syn = 0;

            vrmr_audit("'log New TCP no SYN flag' %s '%s'.", STR_IS_NOW_SET_TO,
                    conf->log_no_syn ? STR_YES : STR_NO);
        } else if (config_section.fields[i] == LogConfig.logprobesfld) {
            /* log policy */
            if (field_buffer(config_section.fields[i], 0)[0] == 'X')
                conf->log_probes = 1;
            else
                conf->log_probes = 0;

            vrmr_audit("'log SCAN Probes' %s '%s'.", STR_IS_NOW_SET_TO,
                    conf->log_probes ? STR_YES : STR_NO);
        } else if (config_section.fields[i] == LogConfig.logfragfld) {
            /* log policy */
            if (field_buffer(config_section.fields[i], 0)[0] == 'X')
                conf->log_frag = 1;
            else
                conf->log_frag = 0;

            vrmr_audit("'log fragments' %s '%s'.", STR_IS_NOW_SET_TO,
                    conf->log_frag ? STR_YES : STR_NO);
        } else {
            vrmr_fatal("unknown field");
        }
    }

    return (retval);
}

int edit_logconfig(struct vrmr_config *conf)
{
    int retval = 0, quit = 0;
    int height, width, startx, starty, max_height, max_width;
    FIELD *cur = NULL, *prev = NULL;

    // window dimentions
    getmaxyx(stdscr, max_height, max_width);
    height = 20;
    width = 76;
    startx = (max_width - width) / 2;
    starty = (max_height - height) / 2;
    // setup
    edit_logconfig_init(conf, height, width, starty, startx);
    cur = current_field(config_section.form);
    update_panels();
    doupdate();

    /* Loop through to get user requests */
    while (quit == 0) {
        /* visual support */
        draw_field_active_mark(cur, prev, config_section.win,
                config_section.form, vccnf.color_win_mark | A_BOLD);

        int ch = wgetch(config_section.win);
        int not_defined = 0;
        if (cur == LogConfig.logdirfld || cur == LogConfig.logpolicylimitfld ||
                cur == LogConfig.nfgrpfld) {
            not_defined = !(nav_field_simpletext(config_section.form, ch));
        } else if (cur == LogConfig.logpolicyfld ||
                   cur == LogConfig.logblocklistfld ||
                   cur == LogConfig.loginvalidfld ||
                   cur == LogConfig.lognosynfld ||
                   cur == LogConfig.logprobesfld ||
                   cur == LogConfig.logfragfld) {
            not_defined = !(nav_field_toggleX(config_section.form, ch));
        } else {
            not_defined = 1;
        }

        if (not_defined) {
            switch (ch) {
                case 27:
                case KEY_F(10):
                case 'q':
                case 'Q':

                    quit = 1;
                    break;

                case KEY_DOWN:
                case 10: // enter
                case 9:  // tab
                    // Go to next field
                    form_driver_wrap(config_section.form, REQ_NEXT_FIELD);
                    form_driver_wrap(config_section.form, REQ_END_LINE);
                    break;

                case KEY_UP:
                    // Go to previous field
                    form_driver_wrap(config_section.form, REQ_PREV_FIELD);
                    form_driver_wrap(config_section.form, REQ_END_LINE);
                    break;

                case 127:
                case KEY_BACKSPACE:
                    form_driver_wrap(config_section.form, REQ_PREV_CHAR);
                    form_driver_wrap(config_section.form, REQ_DEL_CHAR);
                    form_driver_wrap(config_section.form, REQ_END_LINE);
                    break;

                case KEY_DC:
                    form_driver_wrap(config_section.form, REQ_PREV_CHAR);
                    form_driver_wrap(config_section.form, REQ_DEL_CHAR);
                    form_driver_wrap(config_section.form, REQ_END_LINE);
                    break;

                case KEY_F(12):
                case 'h':
                case 'H':
                case '?':

                    print_help(":[VUURMUUR:CONFIG:LOGGING]:");
                    break;

                default:
                    // If this is a normal character, it gets printed into the
                    // field
                    form_driver_wrap(config_section.form, ch);
                    break;
            }
        }

        prev = cur;
        cur = current_field(config_section.form);
    }

    /* write configfile */
    retval = edit_logconfig_save(conf);
    if (retval == 0) {
        if (vrmr_write_configfile(conf->configfile, conf) < 0) {
            vrmr_error(-1, VR_ERR, gettext("writing configfile failed."));
            retval = -1;
        }
    }

    /* cleanup */
    edit_config_destroy();
    return (retval);
}

/* conntrack settings */

struct edit_conntrack_cnf {
    char invalid_drop_enabled;
    struct vrmr_config *conf;
};

static int VrEditConntrackSetup(
        struct edit_conntrack_cnf *c, struct vrmr_config *conf)
{
    vrmr_fatal_if_null(c);

    c->invalid_drop_enabled = conf->invalid_drop_enabled;
    c->conf = conf;
    return (0);
}

static int VrEditConntrackSave(void *ctx, char *name, char *value)
{
    struct edit_conntrack_cnf *c = (struct edit_conntrack_cnf *)ctx;
    int retval = 0;

    if (strcmp(name, "S") == 0) {
        char enabled = 0;

        if (strcmp(value, "X") == 0) {
            enabled = 1;
        }

        if (c->invalid_drop_enabled != enabled) {
            c->conf->invalid_drop_enabled = enabled;

            vrmr_audit("'drop INVALID packet flag' %s '%s'.", STR_IS_NOW_SET_TO,
                    c->conf->invalid_drop_enabled ? STR_YES : STR_NO);

            if (vrmr_write_configfile(c->conf->configfile, c->conf) < 0) {
                vrmr_error(-1, VR_ERR, gettext("writing configfile failed."));
                retval = -1;
            }
        }
    }

    return (retval);
}

static void VrEditConntrack(struct vrmr_config *conf)
{
    struct vrmr_gui_win *win = NULL;
    struct vrmr_gui_form *form = NULL;
    int ch = 0, result = 0;
    struct edit_conntrack_cnf config;

    vrmr_fatal_if(VrEditConntrackSetup(&config, conf) < 0);

    /* create the window and put it in the middle of the screen */
    win = VrNewWin(11, 51, 0, 0, vccnf.color_win);
    vrmr_fatal_if_null(win);
    VrWinSetTitle(win, gettext("Conntrack"));
    form = VrNewForm(
            9, 58, 1, 1, vccnf.color_win, vccnf.color_win_rev | A_BOLD);
    VrFormSetSaveFunc(form, VrEditConntrackSave, &config);

    VrFormAddLabelField(form, 1, 35, 1, 1, vccnf.color_win,
            gettext("Enable dropping INVALID packets"));
    VrFormAddCheckboxField(
            form, 1, 38, vccnf.color_win, "S", config.invalid_drop_enabled);

    VrFormConnectToWin(form, win);
    VrFormPost(form);
    update_panels();
    doupdate();

    /* user input */
    char quit = FALSE;
    while (quit == FALSE) {
        VrFormDrawMarker(win, form);

        ch = VrWinGetch(win);

        /* check OK/Cancel buttons */
        result = VrFormCheckOKCancel(form, ch);
        if (result == -1 || result == 1) {
            break;
        }

        if (VrFormDefaultNavigation(form, ch) == FALSE) {
            switch (ch) {
                case KEY_DOWN:
                case 10: // enter
                    form_driver_wrap(form->f, REQ_NEXT_FIELD);
                    form_driver_wrap(form->f, REQ_BEG_LINE);
                    break;
                case 27:
                case 'q':
                case 'Q':
                case KEY_F(10):
                    quit = TRUE;
                    break;
                case KEY_F(12):
                case 'h':
                case 'H':
                case '?':
                    print_help(":[VUURMUUR:CONFIG:CONNTRACK]:");
                    break;
            }
        }
    }

    VrFormUnPost(form);
    VrDelForm(form);
    VrDelWin(win);
    update_panels();
    doupdate();
}

static void view_caps_init(int height, int width, int starty, int startx,
        struct vrmr_iptcaps *iptcap)
{
    /* safety */
    vrmr_fatal_if_null(iptcap);

    config_section.win = create_newwin(height, width, starty, startx,
            gettext("View Capabilities"), vccnf.color_win);
    vrmr_fatal_if_null(config_section.win);
    config_section.panel[0] = new_panel(config_section.win);
    vrmr_fatal_if_null(config_section.panel[0]);
    keypad(config_section.win, TRUE);

    /* print labels */
    mvwprintw(config_section.win, 2, 4, "Tables");
    if (iptcap->proc_net_names) {
        mvwprintw(config_section.win, 4, 4, "filter\t%s",
                iptcap->table_filter ? STR_YES : STR_NO);
        mvwprintw(config_section.win, 5, 4, "mangle\t%s",
                iptcap->table_mangle ? STR_YES : STR_NO);
        mvwprintw(config_section.win, 6, 4, "nat\t\t%s",
                iptcap->table_nat ? STR_YES : STR_NO);
        mvwprintw(config_section.win, 7, 4, "raw\t\t%s",
                iptcap->table_raw ? STR_YES : STR_NO);
    } else {
        mvwprintw(config_section.win, 4, 4, gettext("Could not check."));
    }

    mvwprintw(config_section.win, 9, 4, "Connection-");
    mvwprintw(config_section.win, 10, 4, " tracking");
    mvwprintw(config_section.win, 12, 4, "conntrack\t%s",
            iptcap->conntrack ? STR_YES : STR_NO);

    mvwprintw(config_section.win, 14, 4, "NAT random\t%s",
            iptcap->target_nat_random ? STR_YES : STR_NO);

    mvwprintw(config_section.win, 2, 27, "Targets");
    if (iptcap->proc_net_targets) {
        mvwprintw(config_section.win, 5, 27, "REJECT\t%s",
                iptcap->target_reject ? STR_YES : STR_NO);
        mvwprintw(config_section.win, 8, 27, "SNAT\t\t%s",
                iptcap->target_snat ? STR_YES : STR_NO);
        mvwprintw(config_section.win, 9, 27, "MASQUERADE\t%s",
                iptcap->target_masquerade ? STR_YES : STR_NO);
        mvwprintw(config_section.win, 10, 27, "DNAT\t\t%s",
                iptcap->target_dnat ? STR_YES : STR_NO);
        mvwprintw(config_section.win, 11, 27, "REDIRECT\t%s",
                iptcap->target_redirect ? STR_YES : STR_NO);
        mvwprintw(config_section.win, 12, 27, "MARK\t\t%s",
                iptcap->target_mark ? STR_YES : STR_NO);
        mvwprintw(config_section.win, 13, 27, "CONNMARK\t%s",
                iptcap->target_connmark ? STR_YES : STR_NO);
        mvwprintw(config_section.win, 14, 27, "NFQUEUE\t%s",
                iptcap->target_nfqueue ? STR_YES : STR_NO);
        mvwprintw(config_section.win, 15, 27, "CLASSIFY\t%s",
                iptcap->target_classify ? STR_YES : STR_NO);
        mvwprintw(config_section.win, 16, 27, "TCPMSS\t%s",
                iptcap->target_tcpmss ? STR_YES : STR_NO);
        mvwprintw(config_section.win, 17, 27, "NFLOG\t%s",
                iptcap->target_nflog ? STR_YES : STR_NO);
    } else {
        mvwprintw(config_section.win, 4, 27, gettext("Could not check."));
    }

    mvwprintw(config_section.win, 2, 52, "Matches");
    if (iptcap->proc_net_matches) {
        mvwprintw(config_section.win, 4, 52, "state\t%s",
                iptcap->match_state ? STR_YES : STR_NO);
        mvwprintw(config_section.win, 5, 52, "mac\t\t%s",
                iptcap->match_mac ? STR_YES : STR_NO);
        mvwprintw(config_section.win, 6, 52, "mark\t%s",
                iptcap->match_mark ? STR_YES : STR_NO);
        mvwprintw(config_section.win, 7, 52, "limit\t%s",
                iptcap->match_limit ? STR_YES : STR_NO);
        mvwprintw(config_section.win, 8, 52, "helper\t%s",
                iptcap->match_helper ? STR_YES : STR_NO);
        mvwprintw(config_section.win, 9, 52, "length\t%s",
                iptcap->match_length ? STR_YES : STR_NO);
        mvwprintw(config_section.win, 10, 52, "connmark\t%s",
                iptcap->match_connmark ? STR_YES : STR_NO);
        mvwprintw(config_section.win, 11, 52, "rpfilter\t%s",
                iptcap->match_rpfilter ? STR_YES : STR_NO);
        mvwprintw(config_section.win, 12, 52, "conntrack\t%s",
                iptcap->match_conntrack ? STR_YES : STR_NO);
    } else {
        mvwprintw(config_section.win, 4, 52, gettext("Could not check."));
    }
}

static int view_caps(struct vrmr_config *conf)
{
    int ch, retval = 0, quit = 0, result = 0;
    int height, width, startx, starty, max_height, max_width;
    struct vrmr_iptcaps iptcap;
    char reload = 0;
    /* top menu */
    char *key_choices[] = {"F12", "F5", "F10"};
    int key_choices_n = 3;
    char *cmd_choices[] = {gettext("help"), gettext("probe"), gettext("back")};
    int cmd_choices_n = 3;

    /* window dimentions */
    getmaxyx(stdscr, max_height, max_width);

    height = 19;
    width = 76;
    startx = (max_width - width) / 2;
    starty = (max_height - height) / 2;

    draw_top_menu(top_win, gettext("Capabilities"), key_choices_n, key_choices,
            cmd_choices_n, cmd_choices);

    /* load iptcaps */
    result = vrmr_load_iptcaps(conf, &iptcap, 0);
    if (result == -1) {
        vrmr_error(-1, VR_ERR, gettext("checking capabilities failed."));
        return (-1);
    }

    vrmr_debug(LOW,
            "iptcap.proc_net_names %d "
            "iptcap.proc_net_matches %d iptcap.proc_net_targets %d "
            "iptcap.table_filter %d iptcap.conntrack %d "
            "iptcap.match_tcp %d iptcap.match_udp %d iptcap.match_icmp %d "
            "iptcap.match_state %d",
            iptcap.proc_net_names, iptcap.proc_net_matches,
            iptcap.proc_net_targets, iptcap.table_filter, iptcap.conntrack,
            iptcap.match_tcp, iptcap.match_udp, iptcap.match_icmp,
            iptcap.match_state);

    /* setup */
    view_caps_init(height, width, starty, startx, &iptcap);

    update_panels();
    doupdate();

    /* Loop through to get user requests */
    while (quit == 0) {
        /* keyboard input */
        ch = wgetch(config_section.win);
        switch (ch) {
            case 27:
            case KEY_F(10):
            case 'q':
            case 'Q':

                quit = 1;
                break;
            case KEY_F(5):
            case 'p':
            case 'P':
                if (confirm(gettext("Probe Capabilities"),
                            gettext("Try to determine capabities? Warning: "
                                    "this may load iptables modules!"),
                            vccnf.color_win_note,
                            vccnf.color_win_note_rev | A_BOLD, 0)) {
                    result = vrmr_load_iptcaps(conf, &iptcap, 1);
                    if (result == -1) {
                        vrmr_error(-1, VR_ERR,
                                gettext("checking capabilities failed."));
                        return (-1);
                    }
                }
                reload = 1;
                quit = 1;
                break;

            case KEY_F(12):
            case 'h':
            case 'H':
            case '?':

                print_help(":[VUURMUUR:CONFIG:CAPABILITIES]:");
                break;
        }
    }

    /* cleanup */
    del_panel(config_section.panel[0]);
    destroy_win(config_section.win);
    update_panels();
    doupdate();

    if (reload == 1)
        return (view_caps(conf));

    return (retval);
}

#ifdef IPV6_ENABLED
static void view_ip6_caps_init(int height, int width, int starty, int startx,
        struct vrmr_iptcaps *iptcap)
{
    /* safety */
    vrmr_fatal_if_null(iptcap);

    config_section.win = create_newwin(height, width, starty, startx,
            gettext("View IPv6 Capabilities"), vccnf.color_win);
    vrmr_fatal_if_null(config_section.win);
    config_section.panel[0] = new_panel(config_section.win);
    vrmr_fatal_if_null(config_section.panel[0]);
    keypad(config_section.win, TRUE);

    /* print labels */
    mvwprintw(config_section.win, 2, 4, "Tables");
    if (iptcap->proc_net_ip6_names) {
        mvwprintw(config_section.win, 4, 4, "filter\t%s",
                iptcap->table_ip6_filter ? STR_YES : STR_NO);
        mvwprintw(config_section.win, 5, 4, "mangle\t%s",
                iptcap->table_ip6_mangle ? STR_YES : STR_NO);
        mvwprintw(config_section.win, 6, 4, "raw\t\t%s",
                iptcap->table_ip6_raw ? STR_YES : STR_NO);
    } else {
        mvwprintw(config_section.win, 4, 4, gettext("Could not check."));
    }

    mvwprintw(config_section.win, 8, 4, "Connection-");
    mvwprintw(config_section.win, 9, 4, " tracking");
    /* TODO Need to check if this has a ipv6 version */
    mvwprintw(config_section.win, 11, 4, "conntrack\t%s",
            iptcap->conntrack ? STR_YES : STR_NO);

    /*
        mvwprintw(config_section.win, 14, 4, "NAT random\t%s",
       iptcap->target_nat_random ? STR_YES : STR_NO);
    */

    mvwprintw(config_section.win, 2, 27, "Targets");
    if (iptcap->proc_net_ip6_targets) {
        mvwprintw(config_section.win, 4, 27, "LOG\t\t%s",
                iptcap->target_ip6_log ? STR_YES : STR_NO);
        mvwprintw(config_section.win, 5, 27, "REJECT\t%s",
                iptcap->target_ip6_reject ? STR_YES : STR_NO);
        /*
                mvwprintw(config_section.win, 8,  27, "SNAT\t\t%s",
           iptcap->target_snat ? STR_YES : STR_NO);
           mvwprintw(config_section.win, 9,  27, "MASQUERADE\t%s",
           iptcap->target_masquerade ? STR_YES : STR_NO);
           mvwprintw(config_section.win, 10, 27, "DNAT\t\t%s",
           iptcap->target_dnat ? STR_YES : STR_NO);
           mvwprintw(config_section.win, 11, 27, "REDIRECT\t%s",
           iptcap->target_redirect ? STR_YES : STR_NO);
        */
        mvwprintw(config_section.win, 12, 27, "MARK\t\t%s",
                iptcap->target_ip6_mark ? STR_YES : STR_NO);
        mvwprintw(config_section.win, 13, 27, "CONNMARK\t%s",
                iptcap->target_ip6_connmark ? STR_YES : STR_NO);
        mvwprintw(config_section.win, 14, 27, "NFQUEUE\t%s",
                iptcap->target_ip6_nfqueue ? STR_YES : STR_NO);
        mvwprintw(config_section.win, 15, 27, "CLASSIFY\t%s",
                iptcap->target_ip6_classify ? STR_YES : STR_NO);
        mvwprintw(config_section.win, 16, 27, "TCPMSS\t%s",
                iptcap->target_ip6_tcpmss ? STR_YES : STR_NO);
    } else {
        mvwprintw(config_section.win, 4, 27, gettext("Could not check."));
    }

    mvwprintw(config_section.win, 2, 52, "Matches");
    if (iptcap->proc_net_ip6_matches) {
        mvwprintw(config_section.win, 4, 52, "state\t%s",
                iptcap->match_ip6_state ? STR_YES : STR_NO);
        mvwprintw(config_section.win, 5, 52, "mac\t\t%s",
                iptcap->match_ip6_mac ? STR_YES : STR_NO);
        mvwprintw(config_section.win, 6, 52, "mark\t%s",
                iptcap->match_ip6_mark ? STR_YES : STR_NO);
        mvwprintw(config_section.win, 7, 52, "limit\t%s",
                iptcap->match_ip6_limit ? STR_YES : STR_NO);
        mvwprintw(config_section.win, 8, 52, "helper\t%s",
                iptcap->match_ip6_helper ? STR_YES : STR_NO);
        mvwprintw(config_section.win, 9, 52, "length\t%s",
                iptcap->match_ip6_length ? STR_YES : STR_NO);
        mvwprintw(config_section.win, 10, 52, "connmark\t%s",
                iptcap->match_ip6_connmark ? STR_YES : STR_NO);
        mvwprintw(config_section.win, 11, 52, "rpfilter\t%s",
                iptcap->match_ip6_rpfilter ? STR_YES : STR_NO);
        mvwprintw(config_section.win, 12, 52, "conntrack\t%s",
                iptcap->match_ip6_conntrack ? STR_YES : STR_NO);
    } else {
        mvwprintw(config_section.win, 4, 52, gettext("Could not check."));
    }
}

static int view_ip6_caps(struct vrmr_config *conf)
{
    int ch, retval = 0, quit = 0, result = 0;
    int height, width, startx, starty, max_height, max_width;
    struct vrmr_iptcaps iptcap;
    char reload = 0;
    /* top menu */
    char *key_choices[] = {"F12", "F5", "F10"};
    int key_choices_n = 3;
    char *cmd_choices[] = {gettext("help"), gettext("probe"), gettext("back")};
    int cmd_choices_n = 3;

    /* window dimentions */
    getmaxyx(stdscr, max_height, max_width);

    height = 18;
    width = 76;
    startx = (max_width - width) / 2;
    starty = (max_height - height) / 2;

    draw_top_menu(top_win, gettext("IPv6 Capabilities"), key_choices_n,
            key_choices, cmd_choices_n, cmd_choices);

    /* load iptcaps */
    memset(&iptcap, 0, sizeof(iptcap));
    result = vrmr_load_ip6tcaps(conf, &iptcap, 0);
    if (result == -1) {
        vrmr_error(-1, VR_ERR, gettext("checking capabilities failed."));
        return (-1);
    }

    vrmr_debug(LOW,
            "iptcap.proc_net_ip6_names %d "
            "iptcap.proc_net_ip6_matches %d iptcap.proc_net_ip6_targets %d "
            "iptcap.table_ip6_filter %d iptcap.match_tcp6 %d "
            "iptcap.match_udp6 %d iptcap.match_icmp6 %d "
            "iptcap.match_mark6 %d",
            iptcap.proc_net_ip6_names, iptcap.proc_net_ip6_matches,
            iptcap.proc_net_ip6_targets, iptcap.table_ip6_filter,
            iptcap.match_ip6_tcp, iptcap.match_ip6_udp, iptcap.match_icmp6,
            iptcap.match_ip6_mark);

    /* setup */
    view_ip6_caps_init(height, width, starty, startx, &iptcap);
    update_panels();
    doupdate();

    /* Loop through to get user requests */
    while (quit == 0) {
        /* keyboard input */
        ch = wgetch(config_section.win);
        switch (ch) {
            case 27:
            case KEY_F(10):
            case 'q':
            case 'Q':

                quit = 1;
                break;
            case KEY_F(5):
            case 'p':
            case 'P':
                if (confirm(gettext("Probe Capabilities"),
                            gettext("Try to determine capabities? Warning: "
                                    "this may load iptables modules!"),
                            vccnf.color_win_note,
                            vccnf.color_win_note_rev | A_BOLD, 0)) {
                    result = vrmr_load_ip6tcaps(conf, &iptcap, 1);
                    if (result == -1) {
                        vrmr_error(-1, VR_ERR,
                                gettext("checking capabilities failed."));
                        return (-1);
                    }
                }
                reload = 1;
                quit = 1;
                break;

            case KEY_F(12):
            case 'h':
            case 'H':
            case '?':

                print_help(":[VUURMUUR:CONFIG:CAPABILITIES]:");
                break;
        }
    }

    /* cleanup */
    del_panel(config_section.panel[0]);
    destroy_win(config_section.win);
    update_panels();
    doupdate();

    if (reload == 1)
        return (view_ip6_caps(conf));

    return (retval);
}
#endif

int config_menu(struct vrmr_config *conf)
{
#ifdef IPV6_ENABLED
    size_t n_choices = 11;
#else
    size_t n_choices = 10;
#endif
    size_t i = 0;
    int ch = 0, quit = 0;
    ITEM **menu_items = NULL;
    ITEM *cur = NULL;
    MENU *main_menu = NULL;
    WINDOW *mainmenu_win = NULL;
    PANEL *conf_panels[1];

    // menu
    char *choice_ptr = NULL;

    char *choices[] = {VROPT_GENERAL, VROPT_CONNECTIONS, VROPT_INTERFACES,
            VROPT_SYSPROT, VROPT_CONNTRACK, VROPT_LOGGING, VROPT_MODULES,
            VROPT_PLUGINS, VROPT_CAPS,
#ifdef IPV6_ENABLED
            VROPT_IP6_CAPS,
#endif
            gettext("Back"), NULL};

    char *descriptions[] = {" ", " ", " ", " ", " ", " ", " ", " ", " ",
#ifdef IPV6_ENABLED
            " ",
#endif
            " ", NULL};

    /* top menu */
    char *key_choices[] = {"F12", "F10"};
    int key_choices_n = 2;
    char *cmd_choices[] = {gettext("help"), gettext("back")};
    int cmd_choices_n = 2;

    int x = 50, y = 9 + (int)n_choices, startx = 0, starty = 0, maxx = 0,
        maxy = 0;

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
    mainmenu_win = create_newwin(y, x, starty, startx,
            gettext("Configuration Menu"), vccnf.color_win);
    keypad(mainmenu_win, TRUE);
    wrefresh(mainmenu_win);
    conf_panels[0] = new_panel(mainmenu_win);
    // menu settings
    set_menu_win(main_menu, mainmenu_win);
    set_menu_sub(main_menu, derwin(mainmenu_win, y - 8, x - 12, 6, 6));
    set_menu_format(main_menu, y - 4, 1);
    set_menu_back(main_menu, vccnf.color_win);
    set_menu_fore(main_menu, vccnf.color_win_rev);
    post_menu(main_menu);
    // welcome message
    mvwprintw(mainmenu_win, 3, 6, gettext("Select a section."));

    draw_top_menu(top_win, gettext("Vuurmuur Config"), key_choices_n,
            key_choices, cmd_choices_n, cmd_choices);

    update_panels();
    doupdate();

    while (quit == 0) {
        show_panel(conf_panels[0]);

        ch = wgetch(mainmenu_win);
        switch (ch) {
            case 27:
            case 'q':
            case 'Q':
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

                cur = current_item(main_menu);
                vrmr_fatal_if_null(cur);
                choice_ptr = strdup((char *)item_name(cur));
                vrmr_fatal_alloc("strdup", choice_ptr);
                break;
        }

        if (choice_ptr != NULL) {
            hide_panel(conf_panels[0]);

            if (strcmp(choice_ptr, VROPT_GENERAL) == 0) {
                edit_genconfig(conf);
            } else if (strcmp(choice_ptr, VROPT_CONNECTIONS) == 0) {
                edit_conconfig(conf);
            } else if (strcmp(choice_ptr, VROPT_INTERFACES) == 0) {
                edit_intconfig(conf);
            } else if (strcmp(choice_ptr, VROPT_SYSPROT) == 0) {
                edit_sysopt(conf);
            } else if (strcmp(choice_ptr, VROPT_CONNTRACK) == 0) {
                VrEditConntrack(conf);
            } else if (strcmp(choice_ptr, VROPT_LOGGING) == 0) {
                edit_logconfig(conf);
            } else if (strcmp(choice_ptr, VROPT_MODULES) == 0) {
                edit_modconfig(conf);
            } else if (strcmp(choice_ptr, VROPT_PLUGINS) == 0) {
                edit_plugconfig(conf);
            } else if (strcmp(choice_ptr, VROPT_CAPS) == 0) {
                view_caps(conf);
            }
#ifdef IPV6_ENABLED
            else if (strcmp(choice_ptr, VROPT_IP6_CAPS) == 0) {
                view_ip6_caps(conf);
            }
#endif
            else if (strncmp(choice_ptr, gettext("Back"),
                             StrLen(gettext("Back"))) == 0) {
                quit = 1;
            }

            free(choice_ptr);
            choice_ptr = NULL;
        }
    }

    /* cleanup */
    unpost_menu(main_menu);
    free_menu(main_menu);
    for (i = 0; i < n_choices; ++i)
        free_item(menu_items[i]);
    free(menu_items);
    del_panel(conf_panels[0]);
    destroy_win(mainmenu_win);
    update_panels();
    doupdate();
    return (0);
}
