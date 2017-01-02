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
#include "gui.h"
#include "config.h"
#include <ctype.h>


#define VROPT_GENERAL       gettext("General")
#define VROPT_CONNECTIONS   gettext("Connections")
#define VROPT_INTERFACES    gettext("Interfaces")
#define VROPT_SYSPROT       gettext("System Protection")
#define VROPT_CONNTRACK     gettext("Conntrack")
#define VROPT_LOGGING       gettext("Logging")
#define VROPT_MODULES       gettext("Modules")
#define VROPT_PLUGINS       gettext("Plugins")
#define VROPT_CAPS          gettext("Capabilities")
#ifdef IPV6_ENABLED
#define VROPT_IP6_CAPS      gettext("IPv6 Capabilities")
#endif


struct ConfigSection_
{
    PANEL   *panel[1];
    WINDOW  *win;
    FIELD   **fields;
    FORM    *form;
    size_t  n_fields;

} ConfigSection;


/* clean up for all config windows */
static int
edit_config_destroy(void)
{
    size_t  i = 0;

    /* Un post form and free the memory */
    unpost_form(ConfigSection.form);
    free_form(ConfigSection.form);
    for(i = 0; i < ConfigSection.n_fields; i++)
    {
        free_field(ConfigSection.fields[i]);
    }
    free(ConfigSection.fields);

    del_panel(ConfigSection.panel[0]);
    destroy_win(ConfigSection.win);
    update_panels();
    doupdate();

    return(0);
}


struct
{
    FIELD   *iptableslocfld,
            *iptablesrestorelocfld,
            *ip6tableslocfld,
            *ip6tablesrestorelocfld,
            *conntracklocfld,
            *tclocfld,
            *max_permission,
//            *oldcreatefld,
            *sysctllocfld;

} GenConfig;



static int
edit_genconfig_init(const int debuglvl, struct vrmr_config *conf, int height, int width, int starty, int startx)
{
    int     retval = 0,
            rows = 0,
            cols = 0;
    size_t  i = 0;
    char    number[5];


    ConfigSection.n_fields = 8;
    ConfigSection.fields = (FIELD **)calloc(ConfigSection.n_fields + 1, sizeof(FIELD *));

    /* external programs */
    GenConfig.iptableslocfld =  (ConfigSection.fields[0] = new_field(1, 64, 1, 1, 0, 0));  /* iptables */
    GenConfig.iptablesrestorelocfld =  (ConfigSection.fields[1] = new_field(1, 64, 3, 1, 0, 0));  /*  */
    GenConfig.ip6tableslocfld =  (ConfigSection.fields[2] = new_field(1, 64, 5, 1, 0, 0));  /* ip6tables */
    GenConfig.ip6tablesrestorelocfld =  (ConfigSection.fields[3] = new_field(1, 64, 7, 1, 0, 0));
    GenConfig.conntracklocfld =  (ConfigSection.fields[4] = new_field(1, 64, 9, 1, 0, 0));  /*  */
    GenConfig.tclocfld =  (ConfigSection.fields[5] = new_field(1, 64, 11, 1, 0, 0));  /*  */
    /* Config file permissions */
    GenConfig.max_permission =  (ConfigSection.fields[6] = new_field(1, 4, 13, 1, 0, 0));  /* max_permissions */
    GenConfig.sysctllocfld =  (ConfigSection.fields[7] = new_field(1, 64, 15, 1, 0, 0));  /*  */

    /* terminate */
    ConfigSection.fields[ConfigSection.n_fields] = NULL;

    ConfigSection.win = create_newwin(height, width, starty, startx, gettext("Edit Config: General"), vccnf.color_win);
    ConfigSection.panel[0] = new_panel(ConfigSection.win);

    /* set buffers - first the visible, then the label */
    set_field_buffer_wrap(debuglvl, GenConfig.iptableslocfld, 0, conf->iptables_location);
    set_field_buffer_wrap(debuglvl, GenConfig.iptablesrestorelocfld, 0, conf->iptablesrestore_location);
#ifdef IPV6_ENABLED
    set_field_buffer_wrap(debuglvl, GenConfig.ip6tableslocfld, 0, conf->ip6tables_location);
    set_field_buffer_wrap(debuglvl, GenConfig.ip6tablesrestorelocfld, 0, conf->ip6tablesrestore_location);
#endif
    set_field_buffer_wrap(debuglvl, GenConfig.conntracklocfld, 0, conf->conntrack_location);
    set_field_buffer_wrap(debuglvl, GenConfig.tclocfld, 0, conf->tc_location);
    (void)snprintf(number, sizeof(number), "%o", conf->max_permission);
    set_field_buffer_wrap(debuglvl, GenConfig.max_permission, 0, number);
    set_field_buffer_wrap(debuglvl, GenConfig.sysctllocfld, 0, conf->sysctl_location);

    /* set buffers done */
    for(i = 0; i < ConfigSection.n_fields; i++)
    {
        set_field_back(ConfigSection.fields[i], vccnf.color_win_rev | A_BOLD);
        field_opts_off(ConfigSection.fields[i], O_AUTOSKIP);
        // set status to false
        set_field_status(ConfigSection.fields[i], FALSE);
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
    ConfigSection.form = new_form(ConfigSection.fields);
    // Calculate the area required for the form
    scale_form(ConfigSection.form, &rows, &cols);
    keypad(ConfigSection.win, TRUE);
    // Set main window and sub window
    set_form_win(ConfigSection.form, ConfigSection.win);
    set_form_sub(ConfigSection.form, derwin(ConfigSection.win, rows, cols, 1, 2));

    post_form(ConfigSection.form);

    /* print labels */
    mvwprintw(ConfigSection.win, 1, 2,  gettext("Iptables location (full path):"));
    mvwprintw(ConfigSection.win, 3, 2,  gettext("Iptables-restore location (full path):"));
#ifdef IPV6_ENABLED
    mvwprintw(ConfigSection.win, 5, 2,  gettext("Ip6tables location (full path):"));
    mvwprintw(ConfigSection.win, 7, 2,  gettext("Ip6tables-restore location (full path):"));
#endif
    mvwprintw(ConfigSection.win, 9, 2,  gettext("Conntrack location (full path):"));
    mvwprintw(ConfigSection.win, 11, 2, gettext("Tc location (full path):"));
    mvwprintw(ConfigSection.win, 13, 2, gettext("Maximum config and log file and dir permissions (octal):"));
    mvwprintw(ConfigSection.win, 15, 2, gettext("Sysctl location (full path):"));

    return(retval);
}


static int
edit_genconfig_save(const int debuglvl, struct vrmr_config *conf)
{
    int     retval = 0;
    size_t  i = 0;

    /* check for changed fields */
    for(i=0; i < ConfigSection.n_fields; i++)
    {
        /* we only act if a field is changed */
        if(field_status(ConfigSection.fields[i]) == TRUE)
        {
            if(ConfigSection.fields[i] == GenConfig.iptableslocfld)
            {
                /* iptables location */
                if(!(copy_field2buf(conf->iptables_location,
                                    field_buffer(ConfigSection.fields[i], 0),
                                    sizeof(conf->iptables_location))))
                    return(-1);

                vrmr_sanitize_path(debuglvl, conf->iptables_location,
                        StrLen(conf->iptables_location));

                vrmr_audit("'iptables location' %s '%s'.",
                    STR_IS_NOW_SET_TO, conf->iptables_location);
            }
            else if(ConfigSection.fields[i] == GenConfig.iptablesrestorelocfld)
            {
                /* iptables-restore location */
                if(!(copy_field2buf(conf->iptablesrestore_location,
                                    field_buffer(ConfigSection.fields[i], 0),
                                    sizeof(conf->iptablesrestore_location))))
                    return(-1);

                vrmr_sanitize_path(debuglvl, conf->iptablesrestore_location,
                        StrLen(conf->iptablesrestore_location));

                vrmr_audit("'iptables-restore location' %s '%s'.",
                    STR_IS_NOW_SET_TO, conf->iptablesrestore_location);
            }
#ifdef IPV6_ENABLED
            else if(ConfigSection.fields[i] == GenConfig.ip6tableslocfld)
            {
                /* ip6tables location */
                if(!(copy_field2buf(conf->ip6tables_location,
                                    field_buffer(ConfigSection.fields[i], 0),
                                    sizeof(conf->ip6tables_location))))
                    return(-1);

                vrmr_sanitize_path(debuglvl, conf->ip6tables_location,
                        StrLen(conf->ip6tables_location));

                vrmr_audit("'ip6tables location' %s '%s'.",
                    STR_IS_NOW_SET_TO, conf->ip6tables_location);
            }
            else if(ConfigSection.fields[i] == GenConfig.ip6tablesrestorelocfld)
            {
                /* ip6tables-restore location */
                if(!(copy_field2buf(conf->ip6tablesrestore_location,
                                    field_buffer(ConfigSection.fields[i], 0),
                                    sizeof(conf->ip6tablesrestore_location))))
                    return(-1);

                vrmr_sanitize_path(debuglvl, conf->ip6tablesrestore_location,
                        StrLen(conf->ip6tablesrestore_location));

                vrmr_audit("'ip6tables-restore location' %s '%s'.",
                    STR_IS_NOW_SET_TO, conf->ip6tablesrestore_location);
            }
#endif
            else if(ConfigSection.fields[i] == GenConfig.conntracklocfld)
            {
                /* conntrack location */
                if(!(copy_field2buf(conf->conntrack_location,
                                    field_buffer(ConfigSection.fields[i], 0),
                                    sizeof(conf->conntrack_location))))
                    return(-1);

                vrmr_sanitize_path(debuglvl, conf->conntrack_location,
                        StrLen(conf->conntrack_location));

                vrmr_audit("'conntrack location' %s '%s'.",
                    STR_IS_NOW_SET_TO, conf->conntrack_location);
            }
            else if(ConfigSection.fields[i] == GenConfig.tclocfld)
            {
                /* tc location */
                if(!(copy_field2buf(conf->tc_location,
                                    field_buffer(ConfigSection.fields[i], 0),
                                    sizeof(conf->tc_location))))
                    return(-1);

                vrmr_sanitize_path(debuglvl, conf->tc_location,
                        StrLen(conf->tc_location));

                vrmr_audit("'tc location' %s '%s'.",
                    STR_IS_NOW_SET_TO, conf->tc_location);
            }
            else if(ConfigSection.fields[i] == GenConfig.max_permission)
            {
                char buf[5];
                char *endptr;
                long int newval;

                /* maximum file permissions */
                if(!(copy_field2buf(buf,
                                    field_buffer(ConfigSection.fields[i], 0),
                                    sizeof(buf))))
                    return(-1);

                /* Parse it as an octal mode */
                newval = strtol(buf, &endptr, 8);

                /* If strol fails, it will set endptr to buf. Also check that
                 * there was no trailing garbage at the end of the string. */
                if (endptr != buf && *endptr == '\0')
                {
                    conf->max_permission = newval;

                    vrmr_audit("'maximum permissions' %s '%o'.",
                        STR_IS_NOW_SET_TO, conf->max_permission);
                }
            }
            else if(ConfigSection.fields[i] == GenConfig.sysctllocfld)
            {
                /* tc location */
                if(!(copy_field2buf(conf->sysctl_location,
                                    field_buffer(ConfigSection.fields[i], 0),
                                    sizeof(conf->sysctl_location))))
                    return(-1);

                vrmr_sanitize_path(debuglvl, conf->sysctl_location,
                        StrLen(conf->sysctl_location));

                vrmr_audit("'sysctl location' %s '%s'.",
                    STR_IS_NOW_SET_TO, conf->sysctl_location);
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


int
edit_genconfig(const int debuglvl, struct vrmr_config *conf)
{
    int     ch,
            retval=0,
            quit=0;
    int     height,
            width,
            startx,
            starty,
            max_height,
            max_width;
    FIELD   *cur = NULL,
            *prev = NULL;
    char    not_defined = 0;

    getmaxyx(stdscr, max_height, max_width);

    height = 18;
    width = 76;

    startx = (max_width - width)/2;
    starty = (max_height - height)/2;

    edit_genconfig_init(debuglvl, conf, height, width, starty, startx);
    cur = current_field(ConfigSection.form);
    update_panels();
    doupdate();

    /* Loop through to get user requests */
    while(quit == 0)
    {
        draw_field_active_mark(cur, prev, ConfigSection.win, ConfigSection.form, vccnf.color_win_mark|A_BOLD);

        ch = wgetch(ConfigSection.win);

        not_defined = 0;

        if( cur == GenConfig.iptableslocfld ||
            cur == GenConfig.iptablesrestorelocfld ||
            cur == GenConfig.sysctllocfld ||
#ifdef IPV6_ENABLED
            cur == GenConfig.ip6tableslocfld ||
            cur == GenConfig.ip6tablesrestorelocfld ||
#endif
            cur == GenConfig.tclocfld ||
            cur == GenConfig.conntracklocfld ||
            cur == GenConfig.max_permission)
        {
            if(nav_field_simpletext(debuglvl, ConfigSection.form, ch) < 0)
                not_defined = 1;
        }
        else
        {
            not_defined = 1;
        }

        if(not_defined)
        {
            switch(ch)
            {
                case 27:
                case KEY_F(10):
                case 'q':
                case 'Q':

                    /* save the field to the conf struct */
                    if(edit_genconfig_save(debuglvl, conf) < 0)
                    {
                        if (confirm(gettext("Saving config failed"),
                                    gettext("Saving the config failed. Sure you want to quit?"),
                                    vccnf.color_win_note, vccnf.color_win_note_rev|A_BOLD, 0))
                        {
                            retval = -1;
                            quit = 1;
                        }
                    }
                    else
                    {
                        quit = 1;
                        retval = 0;
                    }

                    break;

                case KEY_DOWN:
                case 10: // enter
                case 9:  // tab
                    // Go to next field
                    form_driver(ConfigSection.form, REQ_NEXT_FIELD);
                    form_driver(ConfigSection.form, REQ_END_LINE);
                    break;

                case KEY_UP:
                    // Go to previous field
                    form_driver(ConfigSection.form, REQ_PREV_FIELD);
                    form_driver(ConfigSection.form, REQ_END_LINE);
                    break;

                case 127:
                case KEY_BACKSPACE:
                    form_driver(ConfigSection.form, REQ_PREV_CHAR);
                    form_driver(ConfigSection.form, REQ_DEL_CHAR);
                    form_driver(ConfigSection.form, REQ_END_LINE);
                    break;

                case KEY_DC:
                    form_driver(ConfigSection.form, REQ_PREV_CHAR);
                    form_driver(ConfigSection.form, REQ_DEL_CHAR);
                    form_driver(ConfigSection.form, REQ_END_LINE);
                    break;

                case KEY_F(12):
                case 'h':
                case 'H':
                case '?':
                    print_help(debuglvl, ":[VUURMUUR:CONFIG:GENERAL]:");
                    break;

                default:
                    /* If this is a normal character, it gets printed into the field */
                    form_driver(ConfigSection.form, ch);
                    break;
            }
        }

        prev = cur;
        cur = current_field(ConfigSection.form);
    }

    /* write configfile */
    if(retval == 0)
    {
        if (vrmr_write_configfile(debuglvl, conf->configfile, conf) < 0)
        {
            vrmr_error(-1, VR_ERR, gettext("writing configfile failed."));
            retval = -1;
        }
    }

    /* cleanup */
    edit_config_destroy();

    return(retval);
}


struct
{
    FIELD   *dynchkfld,
            *dynchkintfld;

    char    number[5];
} IntConfig;



static int
edit_intconfig_init(const int debuglvl, struct vrmr_config *conf, int height, int width, int starty, int startx)
{
    int     retval = 0,
            rows = 0,
            cols = 0;
    size_t  i = 0;

    ConfigSection.n_fields = 2;
    ConfigSection.fields = (FIELD **)calloc(ConfigSection.n_fields + 1, sizeof(FIELD *));

    /* */
    IntConfig.dynchkfld =     (ConfigSection.fields[0] = new_field(1, 1, 1, 1,  0, 0));
    IntConfig.dynchkintfld =  (ConfigSection.fields[1] = new_field(1, 4, 3, 20, 0, 0));

    /* terminate */
    ConfigSection.fields[ConfigSection.n_fields] = NULL;

    ConfigSection.win = create_newwin(height, width, starty, startx, gettext("Edit Config: Interfaces"), vccnf.color_win);
    ConfigSection.panel[0] = new_panel(ConfigSection.win);

    /* set buffers - first the visible, then the label */
    set_field_buffer_wrap(debuglvl, IntConfig.dynchkfld, 0, conf->dynamic_changes_check ? "X" : " ");
    (void)snprintf(IntConfig.number, sizeof(IntConfig.number), "%u",
            conf->dynamic_changes_interval);
    set_field_buffer_wrap(debuglvl, IntConfig.dynchkintfld, 0, IntConfig.number);

    /* set buffers done */
    for(i = 0; i < ConfigSection.n_fields; i++)
    {
        set_field_back(ConfigSection.fields[i], vccnf.color_win_rev | A_BOLD);
        field_opts_off(ConfigSection.fields[i], O_AUTOSKIP);
        // set status to false
        set_field_status(ConfigSection.fields[i], FALSE);
    }
    /* toggle */
    set_field_back(IntConfig.dynchkfld, vccnf.color_win);

    // Create the form and post it
    ConfigSection.form = new_form(ConfigSection.fields);
    // Calculate the area required for the form
    scale_form(ConfigSection.form, &rows, &cols);
    keypad(ConfigSection.win, TRUE);
    // Set main window and sub window
    set_form_win(ConfigSection.form, ConfigSection.win);
    set_form_sub(ConfigSection.form, derwin(ConfigSection.win, rows, cols, 1, 2));

    post_form(ConfigSection.form);

    /* print labels */
    mvwprintw(ConfigSection.win, 2, 2,  "[");
    mvwprintw(ConfigSection.win, 2, 4,  "]");
    mvwprintw(ConfigSection.win, 2, 7,  gettext("check dynamic interfaces for changes."));
    mvwprintw(ConfigSection.win, 4, 2,  gettext("Check interval:"));
    mvwprintw(ConfigSection.win, 4, 28, gettext("sec."));

    return(retval);
}


static int
edit_intconfig_save(const int debuglvl, struct vrmr_config *conf)
{
    int     retval = 0,
            interval = 0;
    size_t  i = 0;

    /* check for changed fields */
    for(i=0; i < ConfigSection.n_fields; i++)
    {
        /* we only act if a field is changed */
        if(field_status(ConfigSection.fields[i]) == TRUE)
        {
            if(ConfigSection.fields[i] == IntConfig.dynchkintfld)
            {
                /* synlimit */
                if(!(copy_field2buf(IntConfig.number,
                                    field_buffer(ConfigSection.fields[i], 0),
                                    sizeof(IntConfig.number))))
                    return(-1);

                interval = atoi(IntConfig.number);
                if(interval > 0)
                {
                    conf->dynamic_changes_interval = (unsigned int)interval;

                    vrmr_audit("'dynamic changes interval' %s '%u'.",
                        STR_IS_NOW_SET_TO, conf->dynamic_changes_interval);
                }
            }
            else if(ConfigSection.fields[i] == IntConfig.dynchkfld)
            {
                if(field_buffer(ConfigSection.fields[i], 0)[0] == 'X')
                    conf->dynamic_changes_check = 1;
                else
                    conf->dynamic_changes_check = 0;

                vrmr_audit("'check dynamic interfaces for changes' %s '%s'.",
                    STR_IS_NOW_SET_TO,
                    conf->dynamic_changes_check ? STR_YES : STR_NO);
            }
            else
            {
                vrmr_error(-1, VR_INTERR, "unknown field.");
                retval = -1;
            }
        }
    }

    return(retval);
}


int
edit_intconfig(const int debuglvl, struct vrmr_config *conf)
{
    int     ch,
            retval=0,
            quit=0;
    int     height,
            width,
            startx,
            starty,
            max_height,
            max_width;
    FIELD   *cur = NULL,
            *prev = NULL;
    char    not_defined = 0;

    getmaxyx(stdscr, max_height, max_width);

    height = 18;
    width = 76;

    startx = (max_width - width)/2;
    starty = (max_height - height)/2;

    edit_intconfig_init(debuglvl, conf, height, width, starty, startx);
    cur = current_field(ConfigSection.form);
    update_panels();
    doupdate();

    /* Loop through to get user requests */
    while(quit == 0)
    {
        draw_field_active_mark(cur, prev, ConfigSection.win, ConfigSection.form, vccnf.color_win_mark|A_BOLD);

        ch = wgetch(ConfigSection.win);

        not_defined = 0;

        if(cur == IntConfig.dynchkintfld)
        {
            if(nav_field_simpletext(debuglvl, ConfigSection.form, ch) < 0)
                not_defined = 1;
        }
        else if(cur == IntConfig.dynchkfld)
        {
            if(nav_field_toggleX(debuglvl, ConfigSection.form, ch) < 0)
                not_defined = 1;
        }
        else
        {
            not_defined = 1;
        }

        if(not_defined)
        {
            switch(ch)
            {
                case 27:
                case KEY_F(10):
                case 'q':
                case 'Q':

                    /* save the field to the conf struct */
                    if(edit_intconfig_save(debuglvl, conf) < 0)
                    {
                        if (confirm(gettext("Saving config failed"),
                                    gettext("Saving the config failed. Sure you want to quit?"),
                                    vccnf.color_win_note, vccnf.color_win_note_rev|A_BOLD, 0))
                        {
                            retval = -1;
                            quit = 1;
                        }
                    }
                    else
                    {
                        quit = 1;
                        retval = 0;
                    }

                    break;

                case KEY_DOWN:
                case 10:    // enter
                case 9:     // tab
                    // Go to next field
                    form_driver(ConfigSection.form, REQ_NEXT_FIELD);
                    form_driver(ConfigSection.form, REQ_END_LINE);
                    break;

                case KEY_UP:
                    // Go to previous field
                    form_driver(ConfigSection.form, REQ_PREV_FIELD);
                    form_driver(ConfigSection.form, REQ_END_LINE);
                    break;

                case 127:
                case KEY_BACKSPACE:
                    form_driver(ConfigSection.form, REQ_PREV_CHAR);
                    form_driver(ConfigSection.form, REQ_DEL_CHAR);
                    form_driver(ConfigSection.form, REQ_END_LINE);
                    break;

                case KEY_DC:
                    form_driver(ConfigSection.form, REQ_PREV_CHAR);
                    form_driver(ConfigSection.form, REQ_DEL_CHAR);
                    form_driver(ConfigSection.form, REQ_END_LINE);
                    break;

                case KEY_F(12):
                case 'h':
                case 'H':
                case '?':
                    print_help(debuglvl, ":[VUURMUUR:CONFIG:INTERFACES]:");
                    break;

                default:
                    /* If this is a normal character, it gets printed into the field */
                    form_driver(ConfigSection.form, ch);
                    break;
            }
        }

        prev = cur;
        cur = current_field(ConfigSection.form);
    }

    /* write configfile */
    if(retval == 0)
    {
        if (vrmr_write_configfile(debuglvl, conf->configfile, conf) < 0)
        {
            vrmr_error(-1, VR_ERR, gettext("writing configfile failed."));
            retval = -1;
        }
    }

    /* cleanup */
    edit_config_destroy();

    return(retval);
}


struct
{
    FIELD   *modprobefld,
            *loadmodulesfld,
            *waittimefld;

    char    number[6];

} ModConfig;



static int
edit_modconfig_init(const int debuglvl, struct vrmr_config *conf, int height, int width, int starty, int startx)
{
    int     retval = 0,
            rows = 0,
            cols = 0;
    size_t  i = 0;

    ConfigSection.n_fields = 3;
    ConfigSection.fields = (FIELD **)calloc(ConfigSection.n_fields + 1, sizeof(FIELD *));

    /* */
    ModConfig.modprobefld =     (ConfigSection.fields[0] = new_field(1, 64, 2, 1,  0, 0));
    ModConfig.loadmodulesfld =  (ConfigSection.fields[1] = new_field(1, 1,  4, 2, 0, 0));
    ModConfig.waittimefld =     (ConfigSection.fields[2] = new_field(1, 5,  6, 1, 0, 0));

    /* terminate */
    ConfigSection.fields[ConfigSection.n_fields] = NULL;

    ConfigSection.win = create_newwin(height, width, starty, startx, gettext("Edit Config: Modules"), vccnf.color_win);
    ConfigSection.panel[0] = new_panel(ConfigSection.win);

    /* set buffers - first the visible, then the label */
    set_field_buffer_wrap(debuglvl, ModConfig.modprobefld, 0, conf->modprobe_location);
    set_field_buffer_wrap(debuglvl, ModConfig.loadmodulesfld, 0, conf->load_modules ? "X" : " ");

    (void)snprintf(ModConfig.number, sizeof(ModConfig.number), "%u",
            conf->modules_wait_time);
    set_field_buffer_wrap(debuglvl, ModConfig.waittimefld, 0, ModConfig.number);

    /* set buffers done */
    for(i = 0; i < ConfigSection.n_fields; i++)
    {
        set_field_back(ConfigSection.fields[i], vccnf.color_win_rev | A_BOLD);
        field_opts_off(ConfigSection.fields[i], O_AUTOSKIP);
        // set status to false
        set_field_status(ConfigSection.fields[i], FALSE);
    }
    /* toggle */
    set_field_back(ModConfig.loadmodulesfld, vccnf.color_win);

    // Create the form and post it
    ConfigSection.form = new_form(ConfigSection.fields);
    // Calculate the area required for the form
    scale_form(ConfigSection.form, &rows, &cols);
    keypad(ConfigSection.win, TRUE);
    // Set main window and sub window
    set_form_win(ConfigSection.form, ConfigSection.win);
    set_form_sub(ConfigSection.form, derwin(ConfigSection.win, rows, cols, 1, 2));

    post_form(ConfigSection.form);

    /* print labels */
    mvwprintw(ConfigSection.win, 2, 2,  gettext("Modprobe location (full path)"));
    mvwprintw(ConfigSection.win, 5, 3,  "[");
    mvwprintw(ConfigSection.win, 5, 5,  "]");
    mvwprintw(ConfigSection.win, 5, 8,  gettext("load modules"));
    mvwprintw(ConfigSection.win, 7, 11, gettext("waittime after loading a module (in 1/10 th of a second)"));

    return(retval);
}


static int
edit_modconfig_save(const int debuglvl, struct vrmr_config *conf)
{
    int     retval = 0;
    int     interval = 0;
    size_t  i = 0;

    /* check for changed fields */
    for(i=0; i < ConfigSection.n_fields; i++)
    {
        /* we only act if a field is changed */
        if(field_status(ConfigSection.fields[i]) == TRUE)
        {
            if(ConfigSection.fields[i] == ModConfig.modprobefld)
            {
                if(!(copy_field2buf(conf->modprobe_location,
                                    field_buffer(ConfigSection.fields[i], 0),
                                    sizeof(conf->modprobe_location))))
                    return(-1);

                vrmr_sanitize_path(debuglvl, conf->modprobe_location,
                        StrLen(conf->modprobe_location));

                vrmr_audit("'modprobe location' %s '%s'.",
                    STR_IS_NOW_SET_TO, conf->modprobe_location);
            }
            else if(ConfigSection.fields[i] == ModConfig.loadmodulesfld)
            {
                if(field_buffer(ConfigSection.fields[i], 0)[0] == 'X')
                    conf->load_modules = 1;
                else
                    conf->load_modules = 0;

                vrmr_audit("'load modules' %s '%s'.",
                    STR_IS_NOW_SET_TO,
                    conf->load_modules ? STR_YES : STR_NO);
            }
            else if(ConfigSection.fields[i] == ModConfig.waittimefld)
            {
                /* synlimit */
                if(!(copy_field2buf(ModConfig.number,
                                    field_buffer(ConfigSection.fields[i], 0),
                                    sizeof(ModConfig.number))))
                    return(-1);

                interval = atoi(ModConfig.number);
                if(interval >= 0)
                {
                    conf->modules_wait_time = (unsigned int)interval;

                    vrmr_audit("'modules wait time' %s '%u'.",
                        STR_IS_NOW_SET_TO, conf->modules_wait_time);
                }
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


int
edit_modconfig(const int debuglvl, struct vrmr_config *conf)
{
    int     ch,
            retval=0,
            quit=0;
    int     height,
            width,
            startx,
            starty,
            max_height,
            max_width;
    FIELD   *cur = NULL,
            *prev = NULL;
    char    not_defined = 0;

    getmaxyx(stdscr, max_height, max_width);

    height = 18;
    width = 76;

    startx = (max_width - width)/2;
    starty = (max_height - height)/2;

    edit_modconfig_init(debuglvl, conf, height, width, starty, startx);
    cur = current_field(ConfigSection.form);
    update_panels();
    doupdate();

    /* Loop through to get user requests */
    while(quit == 0)
    {
        draw_field_active_mark(cur, prev, ConfigSection.win, ConfigSection.form, vccnf.color_win_mark|A_BOLD);

        ch = wgetch(ConfigSection.win);

        not_defined = 0;

        if(cur == ModConfig.modprobefld ||
           cur == ModConfig.waittimefld)
        {
            if(nav_field_simpletext(debuglvl, ConfigSection.form, ch) < 0)
                not_defined = 1;
        }
        else if(cur == ModConfig.loadmodulesfld)
        {
            if(nav_field_toggleX(debuglvl, ConfigSection.form, ch) < 0)
                not_defined = 1;
        }
        else
        {
            not_defined = 1;
        }

        if(not_defined)
        {
            switch(ch)
            {
                case 27:
                case KEY_F(10):
                case 'q':
                case 'Q':

                    /* save the field to the conf struct */
                    if(edit_modconfig_save(debuglvl, conf) < 0)
                    {
                        if (confirm(gettext("Saving config failed"),
                                    gettext("Saving the config failed. Sure you want to quit?"),
                                    vccnf.color_win_note, vccnf.color_win_note_rev|A_BOLD, 0))
                        {
                            retval = -1;
                            quit = 1;
                        }
                    }
                    else
                    {
                        quit = 1;
                        retval = 0;
                    }

                    break;

                case KEY_DOWN:
                case 10:    // enter
                case 9:     // tab
                    // Go to next field
                    form_driver(ConfigSection.form, REQ_NEXT_FIELD);
                    form_driver(ConfigSection.form, REQ_END_LINE);
                    break;

                case KEY_UP:
                    // Go to previous field
                    form_driver(ConfigSection.form, REQ_PREV_FIELD);
                    form_driver(ConfigSection.form, REQ_END_LINE);
                    break;

                case 127:
                case KEY_BACKSPACE:
                    form_driver(ConfigSection.form, REQ_PREV_CHAR);
                    form_driver(ConfigSection.form, REQ_DEL_CHAR);
                    form_driver(ConfigSection.form, REQ_END_LINE);
                    break;

                case KEY_DC:
                    form_driver(ConfigSection.form, REQ_PREV_CHAR);
                    form_driver(ConfigSection.form, REQ_DEL_CHAR);
                    form_driver(ConfigSection.form, REQ_END_LINE);
                    break;

                case KEY_F(12):
                case 'h':
                case 'H':
                case '?':
                    print_help(debuglvl, ":[VUURMUUR:CONFIG:MODULES]:");
                    break;

                default:
                    /* If this is a normal character, it gets printed into the field */
                    form_driver(ConfigSection.form, ch);
                    break;
            }
        }

        prev = cur;
        cur = current_field(ConfigSection.form);
    }

    /* write configfile */
    if(retval == 0)
    {
        if (vrmr_write_configfile(debuglvl, conf->configfile, conf) < 0)
        {
            vrmr_error(-1, VR_ERR, gettext("writing configfile failed."));
            retval = -1;
        }
    }

    /* cleanup */
    edit_config_destroy();

    return(retval);
}


struct
{
    FIELD   *servbackfld,
            *zonebackfld,
            *ifacbackfld,
            *rulebackfld;
} PlugConfig;


static int
edit_plugconfig_init(const int debuglvl, struct vrmr_config *conf, int height, int width, int starty, int startx)
{
    int     retval=0,
            rows = 0,
            cols = 0;
    size_t  i = 0;

    ConfigSection.n_fields = 4;
    ConfigSection.fields = (FIELD **)calloc(ConfigSection.n_fields + 1, sizeof(FIELD *));

    /* backends */
    PlugConfig.servbackfld = (ConfigSection.fields[0] = new_field(1, 16, 1, 1, 0, 0));  /* servbackend */
    PlugConfig.zonebackfld = (ConfigSection.fields[1] = new_field(1, 16, 3, 1, 0, 0));  /* zonebackend */
    PlugConfig.ifacbackfld = (ConfigSection.fields[2] = new_field(1, 16, 5, 1, 0, 0));  /* ifacbackend */
    PlugConfig.rulebackfld = (ConfigSection.fields[3] = new_field(1, 16, 7, 1, 0, 0));  /* rulebackend */

    /* terminate */
    ConfigSection.fields[ConfigSection.n_fields] = NULL;

    ConfigSection.win = create_newwin(height, width, starty, startx, gettext("Edit Config: Plugins"), vccnf.color_win);
    ConfigSection.panel[0] = new_panel(ConfigSection.win);

    /* set buffers - first the visible, then the label */
    set_field_buffer_wrap(debuglvl, PlugConfig.servbackfld, 0, conf->serv_backend_name);
    set_field_buffer_wrap(debuglvl, PlugConfig.zonebackfld, 0, conf->zone_backend_name);
    set_field_buffer_wrap(debuglvl, PlugConfig.ifacbackfld, 0, conf->ifac_backend_name);
    set_field_buffer_wrap(debuglvl, PlugConfig.rulebackfld, 0, conf->rule_backend_name);

    /* set buffers done */
    for(i = 0; i < ConfigSection.n_fields; i++)
    {
        set_field_back(ConfigSection.fields[i], vccnf.color_win_rev | A_BOLD);
        field_opts_off(ConfigSection.fields[i], O_AUTOSKIP);
        // set status to false
        set_field_status(ConfigSection.fields[i], FALSE);
    }

    // Create the form and post it
    ConfigSection.form = new_form(ConfigSection.fields);
    // Calculate the area required for the form
    scale_form(ConfigSection.form, &rows, &cols);
    keypad(ConfigSection.win, TRUE);
    // Set main window and sub window
    set_form_win(ConfigSection.form, ConfigSection.win);
    set_form_sub(ConfigSection.form, derwin(ConfigSection.win, rows, cols, 1, 2));

    post_form(ConfigSection.form);

    /* print labels */
    mvwprintw(ConfigSection.win, 1, 2,  gettext("Services Backend:"));
    mvwprintw(ConfigSection.win, 3, 2,  gettext("Zones Backend:"));
    mvwprintw(ConfigSection.win, 5, 2,  gettext("Interfaces Backend:"));
    mvwprintw(ConfigSection.win, 7, 2,  gettext("Rules Backend:"));

    return(retval);
}


static int
edit_plugconfig_save(const int debuglvl, struct vrmr_config *conf)
{
    int     retval = 0;
    size_t  i = 0;

    /* check for changed fields */
    for(i=0; i < ConfigSection.n_fields; i++)
    {
        /* we only act if a field is changed */
        if(field_status(ConfigSection.fields[i]) == TRUE)
        {
            if(ConfigSection.fields[i] == PlugConfig.servbackfld)
            {
                /* services backend */
                if(!(copy_field2buf(conf->serv_backend_name,
                                    field_buffer(ConfigSection.fields[i], 0),
                                    sizeof(conf->serv_backend_name))))
                    return(-1);

                vrmr_audit("'service backend name' %s '%s'.",
                    STR_IS_NOW_SET_TO, conf->serv_backend_name);
            }
            else if(ConfigSection.fields[i] == PlugConfig.zonebackfld)
            {
                /* zones backend */
                if(!(copy_field2buf(conf->zone_backend_name,
                                    field_buffer(ConfigSection.fields[i], 0),
                                    sizeof(conf->zone_backend_name))))
                    return(-1);

                vrmr_audit("'zone backend name' %s '%s'.",
                    STR_IS_NOW_SET_TO, conf->zone_backend_name);
            }
            else if(ConfigSection.fields[i] == PlugConfig.ifacbackfld)
            {
                /* interfaces backend */
                if(!(copy_field2buf(conf->ifac_backend_name,
                                    field_buffer(ConfigSection.fields[i], 0),
                                    sizeof(conf->ifac_backend_name))))
                    return(-1);

                vrmr_audit("'interface backend name' %s '%s'.",
                    STR_IS_NOW_SET_TO, conf->ifac_backend_name);
            }
            else if(ConfigSection.fields[i] == PlugConfig.rulebackfld)
            {
                /* interfaces backend */
                if(!(copy_field2buf(conf->rule_backend_name,
                                    field_buffer(ConfigSection.fields[i], 0),
                                    sizeof(conf->rule_backend_name))))
                    return(-1);

                vrmr_audit("'rule backend name' %s '%s'.",
                    STR_IS_NOW_SET_TO, conf->rule_backend_name);
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


int
edit_plugconfig(const int debuglvl, struct vrmr_config *conf)
{
    int     ch,
            retval=0,
            quit=0;
    int     height,
            width,
            startx,
            starty,
            max_height,
            max_width;
    FIELD   *cur = NULL,
            *prev = NULL;
    char    not_defined = 0;

    getmaxyx(stdscr, max_height, max_width);

    height = 18;
    width = 76;

    startx = (max_width - width)/2;
    starty = (max_height - height)/2;

    edit_plugconfig_init(debuglvl, conf, height, width, starty, startx);
    cur = current_field(ConfigSection.form);
    update_panels();
    doupdate();

    /* Loop through to get user requests */
    while(quit == 0)
    {
        draw_field_active_mark(cur, prev, ConfigSection.win, ConfigSection.form, vccnf.color_win_mark|A_BOLD);

        ch = wgetch(ConfigSection.win);

        not_defined = 0;

        if( cur == PlugConfig.servbackfld ||
            cur == PlugConfig.zonebackfld ||
            cur == PlugConfig.ifacbackfld ||
            cur == PlugConfig.rulebackfld)
        {
            if(nav_field_simpletext(debuglvl, ConfigSection.form, ch) < 0)
                not_defined = 1;
        }
        else
        {
            not_defined = 1;
        }

        if(not_defined)
        {
            switch(ch)
            {
                case 27:
                case KEY_F(10):
                case 'q':
                case 'Q':

                    /* save the field to the conf struct */
                    if(edit_plugconfig_save(debuglvl, conf) < 0)
                    {
                        if (confirm(gettext("Saving config failed"),
                                    gettext("Saving the config failed. Sure you want to quit?"),
                                    vccnf.color_win_note, vccnf.color_win_note_rev|A_BOLD, 0))
                        {
                            retval = -1;
                            quit = 1;
                        }
                    }
                    else
                    {
                        quit = 1;
                        retval = 0;
                    }

                    break;

                case KEY_DOWN:
                case 10:    // enter
                case 9:     // tab
                    // Go to next field
                    form_driver(ConfigSection.form, REQ_NEXT_FIELD);
                    form_driver(ConfigSection.form, REQ_END_LINE);
                    break;

                case KEY_UP:
                    // Go to previous field
                    form_driver(ConfigSection.form, REQ_PREV_FIELD);
                    form_driver(ConfigSection.form, REQ_END_LINE);
                    break;

                case 127:
                case KEY_BACKSPACE:
                    form_driver(ConfigSection.form, REQ_PREV_CHAR);
                    form_driver(ConfigSection.form, REQ_DEL_CHAR);
                    form_driver(ConfigSection.form, REQ_END_LINE);
                    break;

                case KEY_DC:
                    form_driver(ConfigSection.form, REQ_PREV_CHAR);
                    form_driver(ConfigSection.form, REQ_DEL_CHAR);
                    form_driver(ConfigSection.form, REQ_END_LINE);
                    break;

                case KEY_F(12):
                case 'h':
                case 'H':
                case '?':
                    print_help(debuglvl, ":[VUURMUUR:CONFIG:PLUGINS]:");
                    break;

                default:
                    /* If this is a normal character, it gets printed into the field */
                    form_driver(ConfigSection.form, ch);
                    break;
            }
        }

        prev = cur;
        cur = current_field(ConfigSection.form);
    }

    /* write configfile */
    if(retval == 0)
    {
        if (vrmr_write_configfile(debuglvl, conf->configfile, conf) < 0)
        {
            vrmr_error(-1, VR_ERR, gettext("writing configfile failed."));
            retval = -1;
        }
    }

    /* cleanup */
    edit_config_destroy();

    return(retval);
}


struct
{
    FIELD   *usesynlimitfld,
            *synlimitfld,
            *synburstfld;

    FIELD   *useudplimitfld,
            *udplimitfld,
            *udpburstfld;

    char    number[8];

} ConConfig;


static int
edit_conconfig_init(const int debuglvl, struct vrmr_config *conf, int height, int width, int starty, int startx)
{
    int     rows = 0,
            cols = 0;
    size_t  i = 0;

    ConfigSection.n_fields = 6;
    ConfigSection.fields = (FIELD **)calloc(ConfigSection.n_fields + 1, sizeof(FIELD *));

    /* fields */
    ConConfig.usesynlimitfld = (ConfigSection.fields[0] = new_field(1, 1, 3,  2, 0, 0)); /* log logblocklist */
    ConConfig.synlimitfld =    (ConfigSection.fields[1] = new_field(1, 8, 5,  1, 0, 0)); /* SYN-limit */
    ConConfig.synburstfld =    (ConfigSection.fields[2] = new_field(1, 8, 7,  1, 0, 0)); /* SYN-limit-burst */

    ConConfig.useudplimitfld = (ConfigSection.fields[3] = new_field(1, 1, 10, 2, 0, 0)); /* log logblocklist */
    ConConfig.udplimitfld =    (ConfigSection.fields[4] = new_field(1, 8, 12, 1, 0, 0)); /* UDP-limit */
    ConConfig.udpburstfld =    (ConfigSection.fields[5] = new_field(1, 8, 14, 1, 0, 0)); /* UDP-limit-burst */

    ConfigSection.fields[ConfigSection.n_fields] = NULL;

    /* create win & pan */
    if(!(ConfigSection.win = create_newwin(height, width, starty, startx, gettext("Edit Config: Connections"), vccnf.color_win)))
    {
        vrmr_error(-1, VR_INTERR, "create_newwin() failed (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }
    if(!(ConfigSection.panel[0] = new_panel(ConfigSection.win)))
    {
        vrmr_error(-1, VR_INTERR, "new_panel() failed (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    /* set fields */
    (void)snprintf(ConConfig.number, sizeof(ConConfig.number), "%u",
            conf->syn_limit);
    set_field_buffer_wrap(debuglvl, ConConfig.synlimitfld, 0, ConConfig.number);

    (void)snprintf(ConConfig.number, sizeof(ConConfig.number), "%u",
            conf->syn_limit_burst);
    set_field_buffer_wrap(debuglvl, ConConfig.synburstfld, 0, ConConfig.number);

    (void)snprintf(ConConfig.number, sizeof(ConConfig.number), "%u",
            conf->udp_limit);
    set_field_buffer_wrap(debuglvl, ConConfig.udplimitfld, 0, ConConfig.number);

    (void)snprintf(ConConfig.number, sizeof(ConConfig.number), "%u",
            conf->udp_limit_burst);
    set_field_buffer_wrap(debuglvl, ConConfig.udpburstfld, 0, ConConfig.number);

    set_field_buffer_wrap(debuglvl, ConConfig.usesynlimitfld, 0, conf->use_syn_limit ? "X" : " ");
    set_field_buffer_wrap(debuglvl, ConConfig.useudplimitfld, 0, conf->use_udp_limit ? "X" : " ");


    /* set the field options */
    for(i = 0; i < ConfigSection.n_fields; i++)
    {
        /* background */
        set_field_back(ConfigSection.fields[i], vccnf.color_win_rev | A_BOLD);
        /* no autoskip */
        field_opts_off(ConfigSection.fields[i], O_AUTOSKIP);
        /* set status to false */
        set_field_status(ConfigSection.fields[i], FALSE);
    }
    set_field_back(ConConfig.usesynlimitfld, vccnf.color_win);
    set_field_back(ConConfig.useudplimitfld, vccnf.color_win);

    /* Create the form and post it */
    if(!(ConfigSection.form = new_form(ConfigSection.fields)))
    {
        vrmr_error(-1, VR_INTERR, "new_form() failed (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }
    /* Calculate the area required for the form */
    scale_form(ConfigSection.form, &rows, &cols);
    keypad(ConfigSection.win, TRUE);
    /* Set main window and sub window */
    set_form_win(ConfigSection.form, ConfigSection.win);
    set_form_sub(ConfigSection.form, derwin(ConfigSection.win, rows, cols, 1, 2));
    post_form(ConfigSection.form);

    /* print labels */
    mvwprintw(ConfigSection.win, 2, 2,  gettext("You can limit the number of new connections per second:"));

    mvwprintw(ConfigSection.win, 4, 3, "[");
    mvwprintw(ConfigSection.win, 4, 5, "]");
    mvwprintw(ConfigSection.win, 4, 8, gettext("Limit new TCP connections."));
    mvwprintw(ConfigSection.win, 6, 13, gettext("Number of SYN-packets per second"));
    mvwprintw(ConfigSection.win, 8, 13, gettext("Burst-rate"));

    mvwprintw(ConfigSection.win, 11, 3, "[");
    mvwprintw(ConfigSection.win, 11, 5, "]");
    mvwprintw(ConfigSection.win, 11, 8, gettext("Limit new udp 'connections'."));

    mvwprintw(ConfigSection.win, 13, 13, gettext("Number of new UDP 'connections' per second"));
    mvwprintw(ConfigSection.win, 15, 13, gettext("Burst-rate"));

    return(0);
}


static int
edit_conconfig_save(struct vrmr_config *conf)
{
    int     retval = 0;
    size_t  i = 0;
    int     syn = 0,
            udplimit = 0;

    /* check for changed fields */
    for(i=0; i < ConfigSection.n_fields; i++)
    {
        /* we only act if a field is changed */
        if(field_status(ConfigSection.fields[i]) == TRUE)
        {
            if(ConfigSection.fields[i] == ConConfig.usesynlimitfld)
            {
                /* log policy */
                if(field_buffer(ConfigSection.fields[i], 0)[0] == 'X')
                    conf->use_syn_limit = 1;
                else
                    conf->use_syn_limit = 0;

                vrmr_audit("'use syn limit' %s '%s'.",
                    STR_IS_NOW_SET_TO, conf->use_syn_limit ? STR_YES : STR_NO);
            }
            else if(ConfigSection.fields[i] == ConConfig.synlimitfld)
            {
                /* synlimit */
                if(!(copy_field2buf(ConConfig.number,
                                    field_buffer(ConfigSection.fields[i], 0),
                                    sizeof(ConConfig.number))))
                    return(-1);

                syn = atoi(ConConfig.number);
                if(syn > 0)
                {
                    conf->syn_limit = (unsigned int)syn;

                    vrmr_audit("'syn limit' %s '%u'.",
                        STR_IS_NOW_SET_TO, conf->syn_limit);
                }
            }
            else if(ConfigSection.fields[i] == ConConfig.synburstfld)
            {
                /* synlimit */
                if(!(copy_field2buf(ConConfig.number,
                                    field_buffer(ConfigSection.fields[i], 0),
                                    sizeof(ConConfig.number))))
                    return(-1);

                syn = atoi(ConConfig.number);
                if(syn > 0)
                {
                    conf->syn_limit_burst = (unsigned int)syn;

                    vrmr_audit("'syn limit burst' %s '%u'.",
                        STR_IS_NOW_SET_TO, conf->syn_limit_burst);
                }
            }
            else if(ConfigSection.fields[i] == ConConfig.useudplimitfld)
            {
                /* log policy */
                if(field_buffer(ConfigSection.fields[i], 0)[0] == 'X')
                    conf->use_udp_limit = 1;
                else
                    conf->use_udp_limit = 0;

                vrmr_audit("'use udp limit' %s '%s'.",
                    STR_IS_NOW_SET_TO, conf->use_udp_limit ? STR_YES : STR_NO);
            }
            else if(ConfigSection.fields[i] == ConConfig.udplimitfld)
            {
                /* udplimit */
                if(!(copy_field2buf(ConConfig.number,
                                    field_buffer(ConfigSection.fields[i], 0),
                                    sizeof(ConConfig.number))))
                    return(-1);

                udplimit = atoi(ConConfig.number);
                if(udplimit > 0)
                {
                    conf->udp_limit = (unsigned int)udplimit;

                    vrmr_audit("'udp limit' %s '%u'.",
                        STR_IS_NOW_SET_TO, conf->udp_limit);
                }
            }
            else if(ConfigSection.fields[i] == ConConfig.udpburstfld)
            {
                /* udpburst */
                if(!(copy_field2buf(ConConfig.number,
                                    field_buffer(ConfigSection.fields[i], 0),
                                    sizeof(ConConfig.number))))
                    return(-1);

                udplimit = atoi(ConConfig.number);
                if(udplimit > 0)
                {
                    conf->udp_limit_burst = (unsigned int)udplimit;

                    vrmr_audit("'udp limit burst' %s '%u'.",
                        STR_IS_NOW_SET_TO, conf->udp_limit_burst);
                }
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


int
edit_conconfig(const int debuglvl, struct vrmr_config *conf)
{
    int     ch,
            retval = 0,
            quit = 0,
            not_defined = 0;
    int     height,
            width,
            startx,
            starty,
            max_height,
            max_width;
    FIELD   *cur = NULL,
            *prev = NULL;

    /* window dimentions */
    getmaxyx(stdscr, max_height, max_width);

    height = 18;
    width = 76;

    startx = (max_width - width)/2;
    starty = (max_height - height)/2;

    /* setup */
    if(edit_conconfig_init(debuglvl, conf, height, width, starty, startx) < 0)
        return(-1);

    cur = current_field(ConfigSection.form);
    update_panels();
    doupdate();

    /* Loop through to get user requests */
    while(quit == 0)
    {
        /* visual support */
        draw_field_active_mark(cur, prev, ConfigSection.win, ConfigSection.form, vccnf.color_win_mark|A_BOLD);

        /* when not using synlimit, deactivated the fields */
        if(field_buffer(ConConfig.usesynlimitfld, 0)[0] == 'X')
        {
            field_opts_on(ConConfig.synlimitfld, O_ACTIVE);
            field_opts_on(ConConfig.synburstfld, O_ACTIVE);
        }
        else
        {
            field_opts_off(ConConfig.synlimitfld, O_ACTIVE);
            field_opts_off(ConConfig.synburstfld, O_ACTIVE);
        }

        /* when not using udplimit, deactivated the fields */
        if(field_buffer(ConConfig.useudplimitfld, 0)[0] == 'X')
        {
            field_opts_on(ConConfig.udplimitfld, O_ACTIVE);
            field_opts_on(ConConfig.udpburstfld, O_ACTIVE);
        }
        else
        {
            field_opts_off(ConConfig.udplimitfld, O_ACTIVE);
            field_opts_off(ConConfig.udpburstfld, O_ACTIVE);
        }

        /* keyboard input */
        ch = wgetch(ConfigSection.win);

        not_defined = 0;

        if(cur == ConConfig.synlimitfld ||
           cur == ConConfig.synburstfld ||
           cur == ConConfig.udplimitfld ||
           cur == ConConfig.udpburstfld)
        {
            if(nav_field_simpletext(debuglvl, ConfigSection.form, ch) < 0)
                not_defined = 1;
        }
        else if(cur == ConConfig.usesynlimitfld ||
            cur == ConConfig.useudplimitfld)
        {
            if(nav_field_toggleX(debuglvl, ConfigSection.form, ch) < 0)
                not_defined = 1;
        }
        else
        {
            not_defined = 1;
        }

        if(not_defined)
        {
            switch(ch)
            {
                case 27:
                case KEY_F(10):
                case 'q':
                case 'Q':
                    quit = 1;
                    break;

                case KEY_DOWN:
                case 10:    // enter
                case 9:     // tab
                    // Go to next field
                    form_driver(ConfigSection.form, REQ_NEXT_FIELD);
                    form_driver(ConfigSection.form, REQ_END_LINE);
                    break;

                case KEY_UP:
                    // Go to previous field
                    form_driver(ConfigSection.form, REQ_PREV_FIELD);
                    form_driver(ConfigSection.form, REQ_END_LINE);
                    break;

                case 127:
                case KEY_BACKSPACE:
                    form_driver(ConfigSection.form, REQ_PREV_CHAR);
                    form_driver(ConfigSection.form, REQ_DEL_CHAR);
                    form_driver(ConfigSection.form, REQ_END_LINE);
                    break;

                case KEY_DC:
                    form_driver(ConfigSection.form, REQ_PREV_CHAR);
                    form_driver(ConfigSection.form, REQ_DEL_CHAR);
                    form_driver(ConfigSection.form, REQ_END_LINE);
                    break;

                case KEY_F(12):
                case 'h':
                case 'H':
                case '?':
                    print_help(debuglvl, ":[VUURMUUR:CONFIG:CONNECTIONS]:");
                    break;

                default:
                    /* If this is a normal character, it gets printed into the field */
                    form_driver(ConfigSection.form, ch);
                    break;
            }
        }

        prev = cur;
        cur = current_field(ConfigSection.form);
    }

    /* save the field to the conf struct */
    if(edit_conconfig_save(conf) < 0)
    {
        retval = -1;
    }

    /* write configfile */
    if(retval == 0)
    {
        if (vrmr_write_configfile(debuglvl, conf->configfile, conf) < 0)
        {
            vrmr_error(-1, VR_ERR, gettext("writing configfile failed."));
            retval=-1;
        }
    }

    /* cleanup */
    edit_config_destroy();

    return(retval);
}


struct
{
    FIELD   *newrule_loglimitfld,
            *newrule_logfld,
            *logview_bufsizefld,
            *advancedmodefld,
            *mainmenu_statusfld,
            *backgroundfld,
            *iptrafvollocfld;

    char    number[8];

} VcConfig;


static int
edit_vcconfig_init(const int debuglvl, int height, int width, int starty, int startx)
{
    size_t  i = 0;
    int     rows = 0,
            cols = 0;

    ConfigSection.n_fields = 7;
    ConfigSection.fields = (FIELD **)calloc(ConfigSection.n_fields + 1, sizeof(FIELD *));

    /* fields */
    VcConfig.newrule_logfld      = (ConfigSection.fields[0] = new_field(1, 1,  2, 23, 0, 0));
    VcConfig.newrule_loglimitfld = (ConfigSection.fields[1] = new_field(1, 3,  2, 66, 0, 0));

    VcConfig.logview_bufsizefld  = (ConfigSection.fields[2] = new_field(1, 6,  5, 52, 0, 0));
    VcConfig.advancedmodefld     = (ConfigSection.fields[3] = new_field(1, 1,  6, 53, 0, 0));
    VcConfig.mainmenu_statusfld  = (ConfigSection.fields[4] = new_field(1, 1,  7, 53, 0, 0));
    VcConfig.backgroundfld       = (ConfigSection.fields[5] = new_field(1, 1,  8, 53, 0, 0));

    VcConfig.iptrafvollocfld     = (ConfigSection.fields[6] = new_field(1, 64, 11, 1, 0, 0));

    ConfigSection.fields[ConfigSection.n_fields] = NULL;

    /* create win & pan */
    if(!(ConfigSection.win = create_newwin(height, width, starty, startx, gettext("Vuurmuur_conf Settings"), vccnf.color_win)))
    {
        vrmr_error(-1, VR_INTERR, "create_newwin() failed (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }
    if(!(ConfigSection.panel[0] = new_panel(ConfigSection.win)))
    {
        vrmr_error(-1, VR_INTERR, "new_panel() failed (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    /* set fields */
    set_field_buffer_wrap(debuglvl, VcConfig.newrule_logfld, 0, vccnf.newrule_log ? "X" : " ");

    (void)snprintf(VcConfig.number, sizeof(VcConfig.number), "%u",
            vccnf.newrule_loglimit);
    set_field_buffer_wrap(debuglvl, VcConfig.newrule_loglimitfld, 0, VcConfig.number);

    (void)snprintf(VcConfig.number, sizeof(VcConfig.number), "%u",
            vccnf.logview_bufsize);
    set_field_buffer_wrap(debuglvl, VcConfig.logview_bufsizefld, 0, VcConfig.number);

    set_field_buffer_wrap(debuglvl, VcConfig.advancedmodefld, 0, vccnf.advanced_mode ? "X" : " ");
    set_field_buffer_wrap(debuglvl, VcConfig.mainmenu_statusfld, 0, vccnf.draw_status ? "X" : " ");
    set_field_buffer_wrap(debuglvl, VcConfig.backgroundfld, 0, vccnf.background ? "X" : " ");
    set_field_buffer_wrap(debuglvl, VcConfig.iptrafvollocfld, 0, vccnf.iptrafvol_location);

    /* set the field options */
    for(i = 0; i < ConfigSection.n_fields; i++)
    {
        /* background */
        set_field_back(ConfigSection.fields[i], vccnf.color_win_rev | A_BOLD);
        /* no autoskip */
        field_opts_off(ConfigSection.fields[i], O_AUTOSKIP);
        /* set status to false */
        set_field_status(ConfigSection.fields[i], FALSE);
    }
    set_field_back(VcConfig.newrule_logfld,     vccnf.color_win);
    set_field_back(VcConfig.advancedmodefld,    vccnf.color_win);
    set_field_back(VcConfig.mainmenu_statusfld, vccnf.color_win);
    set_field_back(VcConfig.backgroundfld,      vccnf.color_win);

    /* Create the form and post it */
    if(!(ConfigSection.form = new_form(ConfigSection.fields)))
    {
        vrmr_error(-1, VR_INTERR, "new_form() failed (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }
    /* Calculate the area required for the form */
    scale_form(ConfigSection.form, &rows, &cols);
    keypad(ConfigSection.win, TRUE);
    /* Set main window and sub window */
    set_form_win(ConfigSection.form, ConfigSection.win);
    set_form_sub(ConfigSection.form, derwin(ConfigSection.win, rows, cols, 1, 2));
    post_form(ConfigSection.form);

    /* print labels */
    mvwprintw(ConfigSection.win, 2, 2,  gettext("Defaults for creating new rules:"));

    mvwprintw(ConfigSection.win, 3, 2,  gettext("Log the rule"));
    mvwprintw(ConfigSection.win, 3, 24, "[");
    mvwprintw(ConfigSection.win, 3, 26, "]");
    
    mvwprintw(ConfigSection.win, 3, 35, gettext("Loglimit per second"));

    mvwprintw(ConfigSection.win, 6, 2,  gettext("Buffersize logviewer (number of lines):"));
    mvwprintw(ConfigSection.win, 7, 2,  gettext("Advanced mode by default:"));
    mvwprintw(ConfigSection.win, 7, 54, "[");
    mvwprintw(ConfigSection.win, 7, 56, "]");

    mvwprintw(ConfigSection.win, 8, 2,  gettext("Draw status in Main Menu:"));
    mvwprintw(ConfigSection.win, 8, 54, "[");
    mvwprintw(ConfigSection.win, 8, 56, "]");

    mvwprintw(ConfigSection.win, 9, 2,  gettext("Use black background?:"));
    mvwprintw(ConfigSection.win, 9, 54, "[");
    mvwprintw(ConfigSection.win, 9, 56, "]");

    mvwprintw(ConfigSection.win, 11, 2, gettext("iptrafvol.pl location (full path)"));

    return(0);
}


static int
edit_vcconfig_save(const int debuglvl)
{
    int     retval = 0;
    size_t  i = 0;
    int     syn = 0;
    int     bufsize = 0;

    /* check for changed fields */
    for(i=0; i < ConfigSection.n_fields; i++)
    {
        /* we only act if a field is changed */
        if(field_status(ConfigSection.fields[i]) == TRUE)
        {
            if(ConfigSection.fields[i] == VcConfig.newrule_loglimitfld)
            {
                /* synlimit */
                if(!(copy_field2buf(VcConfig.number,
                                    field_buffer(ConfigSection.fields[i], 0),
                                    sizeof(VcConfig.number))))
                    return(-1);

                syn = atoi(VcConfig.number);
                if(syn > 0)
                {
                    vccnf.newrule_loglimit = (unsigned int)syn;
                }
            }
            else if(ConfigSection.fields[i] == VcConfig.newrule_logfld)
            {
                if(field_buffer(ConfigSection.fields[i], 0)[0] == 'X')
                    vccnf.newrule_log = 1;
                else
                    vccnf.newrule_log = 0;
            }
            else if(ConfigSection.fields[i] == VcConfig.advancedmodefld)
            {
                if(field_buffer(ConfigSection.fields[i], 0)[0] == 'X')
                    vccnf.advanced_mode = 1;
                else
                    vccnf.advanced_mode = 0;
            }
            else if(ConfigSection.fields[i] == VcConfig.mainmenu_statusfld)
            {
                if(field_buffer(ConfigSection.fields[i], 0)[0] == 'X')
                    vccnf.draw_status = 1;
                else
                    vccnf.draw_status = 0;
            }
            else if(ConfigSection.fields[i] == VcConfig.backgroundfld)
            {
                if(field_buffer(ConfigSection.fields[i], 0)[0] == 'X')
                    vccnf.background = 1;
                else
                    vccnf.background = 0;
            }
            else if(ConfigSection.fields[i] == VcConfig.logview_bufsizefld)
            {
                /* bufsize */
                if(!(copy_field2buf(VcConfig.number,
                                    field_buffer(ConfigSection.fields[i], 0),
                                    sizeof(VcConfig.number))))
                    return(-1);

                bufsize = atoi(VcConfig.number);
                if(bufsize > 0)
                {
                    vccnf.logview_bufsize = (unsigned int)bufsize;
                }
            }
            else if(ConfigSection.fields[i] == VcConfig.iptrafvollocfld)
            {
                /* synlimit */
                if(!(copy_field2buf(vccnf.iptrafvol_location,
                                    field_buffer(ConfigSection.fields[i], 0),
                                    sizeof(vccnf.iptrafvol_location))))
                    return(-1);

                vrmr_sanitize_path(debuglvl, vccnf.iptrafvol_location,
                        StrLen(vccnf.iptrafvol_location));
            }
            else
            {
                vrmr_error(-1, VR_INTERR, "unknown field.");
                retval = -1;
            }
        }
    }

    return(retval);
}


int
edit_vcconfig(const int debuglvl)
{
    int     ch,
            retval = 0,
            quit = 0,
            not_defined = 0;
    int     height,
            width,
            startx,
            starty,
            max_height,
            max_width;
    FIELD   *cur = NULL,
            *prev = NULL;

    /* top menu */
    char    *key_choices[] =    {   "F12",
                                    "F10"};
    int     key_choices_n = 2;
    char    *cmd_choices[] =    {   gettext("help"),
                                    gettext("back")};
    int     cmd_choices_n = 2;


    /* window dimentions */
    getmaxyx(stdscr, max_height, max_width);

    height = 18;
    width = 76;

    startx = (max_width - width)/2;
    starty = (max_height - height)/2;

    /* setup */
    if(edit_vcconfig_init(debuglvl, height, width, starty, startx) < 0)
        return(-1);

    cur = current_field(ConfigSection.form);

    draw_top_menu(debuglvl, top_win, gettext("Vuurmuur_conf Settings"), key_choices_n, key_choices, cmd_choices_n, cmd_choices);

    update_panels();
    doupdate();

    /* Loop through to get user requests */
    while(quit == 0)
    {
        /* visual support */
        draw_field_active_mark(cur, prev, ConfigSection.win, ConfigSection.form, vccnf.color_win_mark|A_BOLD);

        /* keyboard input */
        ch = wgetch(ConfigSection.win);

        not_defined = 0;

        if(cur == VcConfig.newrule_loglimitfld ||
           cur == VcConfig.logview_bufsizefld ||
           cur == VcConfig.iptrafvollocfld)
        {
            if(nav_field_simpletext(debuglvl, ConfigSection.form, ch) < 0)
                not_defined = 1;
        }
        else if(cur == VcConfig.newrule_logfld ||
            cur == VcConfig.advancedmodefld ||
            cur == VcConfig.mainmenu_statusfld ||
            cur == VcConfig.backgroundfld)
        {
            if(nav_field_toggleX(debuglvl, ConfigSection.form, ch) < 0)
                not_defined = 1;
        }
        else
        {
            not_defined = 1;
        }

        if(not_defined)
        {
            switch(ch)
            {
                case 27:
                case KEY_F(10):
                case 'q':
                case 'Q':
                    quit = 1;
                    break;

                case KEY_DOWN:
                case 10:    // enter
                case 9:     // tab
                    // Go to next field
                    form_driver(ConfigSection.form, REQ_NEXT_FIELD);
                    form_driver(ConfigSection.form, REQ_END_LINE);
                    break;

                case KEY_UP:
                    // Go to previous field
                    form_driver(ConfigSection.form, REQ_PREV_FIELD);
                    form_driver(ConfigSection.form, REQ_END_LINE);
                    break;

                case 127:
                case KEY_BACKSPACE:
                    form_driver(ConfigSection.form, REQ_PREV_CHAR);
                    form_driver(ConfigSection.form, REQ_DEL_CHAR);
                    form_driver(ConfigSection.form, REQ_END_LINE);
                    break;

                case KEY_DC:
                    form_driver(ConfigSection.form, REQ_PREV_CHAR);
                    form_driver(ConfigSection.form, REQ_DEL_CHAR);
                    form_driver(ConfigSection.form, REQ_END_LINE);
                    break;

                case KEY_F(12):
                case 'h':
                case 'H':
                case '?':
                    print_help(debuglvl, ":[VUURMUURCONF:SETTINGS]:");
                    break;

                default:
                    /* If this is a normal character, it gets printed into the field */
                    form_driver(ConfigSection.form, ch);
                    break;
            }
        }

        prev = cur;
        cur = current_field(ConfigSection.form);
    }

    /* save the field to the conf struct */
    if(edit_vcconfig_save(debuglvl) < 0)
    {
        retval = -1;
    }

    /* write configfile */
    if(retval == 0)
    {
        if(write_vcconfigfile(debuglvl, vccnf.configfile_location, &vccnf) < 0)
        {
            vrmr_error(-1, VR_ERR, gettext("writing configfile failed."));
            retval=-1;
        }
    }

    /* cleanup */
    edit_config_destroy();

    return(retval);
}


struct
{
    FIELD   *rule_nflogfld,
            *nfgrpfld,
            *logdirfld,
            *loglevelfld,
            *systemlogfld,

            *logpolicyfld,
            *logpolicylimitfld,
            *logtcpoptionsfld,
            *logblocklistfld,

            *loginvalidfld,
            *lognosynfld,
            *logprobesfld,
            *logfragfld;
} LogConfig;


static int
edit_logconfig_init(const int debuglvl, struct vrmr_config *conf, int height, int width, int starty, int startx)
{
    int     retval = 0;
    size_t  i = 0;
    int     rows = 0,
            cols = 0;
    char    limit_string[4] = "";

    ConfigSection.n_fields = 13;
    ConfigSection.fields = (FIELD **)calloc(ConfigSection.n_fields + 1, sizeof(FIELD *));

    /* fields */
    LogConfig.rule_nflogfld    = (ConfigSection.fields[0] = new_field(1, 1, 1, 26, 0, 0)); /* rule_nflog */
    LogConfig.nfgrpfld    =      (ConfigSection.fields[1] = new_field(1, 3, 1, 60, 0, 0)); /* nfgrp */

    LogConfig.logdirfld    = (ConfigSection.fields[2] = new_field(1, 64, 4, 1, 0, 0)); /* vuurmuur_logdir */
    LogConfig.loglevelfld  = (ConfigSection.fields[3] = new_field(1, 8,  6, 1, 0, 0)); /* loglevel */
    LogConfig.systemlogfld = (ConfigSection.fields[4] = new_field(1, 64, 8, 1, 0, 0)); /* systemlog */

    LogConfig.logpolicyfld      = (ConfigSection.fields[5] = new_field(1, 1, 10,  61, 0, 0)); /* log policy */
    LogConfig.logpolicylimitfld = (ConfigSection.fields[6] = new_field(1, 3, 11,  60, 0, 0)); /* log policy limit */
    LogConfig.logtcpoptionsfld  = (ConfigSection.fields[7] = new_field(1, 1, 12, 61, 0, 0)); /* log tcp options */
    LogConfig.logblocklistfld   = (ConfigSection.fields[8] = new_field(1, 1, 13, 61, 0, 0)); /* log logblocklist */

    LogConfig.loginvalidfld   = (ConfigSection.fields[9] = new_field(1, 1, 14, 61, 0, 0)); /* log logblocklist */
    LogConfig.lognosynfld     = (ConfigSection.fields[10] = new_field(1, 1, 15, 61, 0, 0)); /* log logblocklist */
    LogConfig.logprobesfld    = (ConfigSection.fields[11] = new_field(1, 1, 16, 61, 0, 0)); /* log logprobes */
    LogConfig.logfragfld      = (ConfigSection.fields[12] = new_field(1, 1, 17, 61, 0, 0)); /* log logblocklist */

    ConfigSection.fields[ConfigSection.n_fields] = NULL;


    if(!(ConfigSection.win = create_newwin(height, width, starty, startx, gettext("Edit Config: Logging"), vccnf.color_win)))
    {
        vrmr_error(-1, VR_INTERR, "create_newwin() failed (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }
    if(!(ConfigSection.panel[0] = new_panel(ConfigSection.win)))
    {
        vrmr_error(-1, VR_INTERR, "new_panel() failed (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    /* fill the fields */
    set_field_buffer_wrap(debuglvl, LogConfig.rule_nflogfld,  0, conf->rule_nflog ? "X" : " ");
    if (conf->nfgrp > 0)
    {
        (void)snprintf(limit_string, sizeof(limit_string), "%u",
                conf->nfgrp);
        set_field_buffer_wrap(debuglvl, LogConfig.nfgrpfld, 0, limit_string);
    }
    set_field_buffer_wrap(debuglvl, LogConfig.logdirfld, 0, conf->vuurmuur_logdir_location);
    set_field_buffer_wrap(debuglvl, LogConfig.loglevelfld, 0, conf->loglevel);
    set_field_buffer_wrap(debuglvl, LogConfig.systemlogfld, 0, conf->systemlog_location);
    set_field_buffer_wrap(debuglvl, LogConfig.logpolicyfld, 0, conf->log_policy ? "X" : " ");
    if(conf->log_policy_limit > 0)
    {
        (void)snprintf(limit_string, sizeof(limit_string), "%u",
                conf->log_policy_limit);
        set_field_buffer_wrap(debuglvl, LogConfig.logpolicylimitfld, 0, limit_string);
    }
    set_field_buffer_wrap(debuglvl, LogConfig.logtcpoptionsfld, 0, conf->log_tcp_options ? "X" : " ");
    set_field_buffer_wrap(debuglvl, LogConfig.logblocklistfld,  0, conf->log_blocklist ? "X" : " ");
    set_field_buffer_wrap(debuglvl, LogConfig.loginvalidfld,  0, conf->log_invalid ? "X" : " ");
    set_field_buffer_wrap(debuglvl, LogConfig.lognosynfld,  0, conf->log_no_syn ? "X" : " ");
    set_field_buffer_wrap(debuglvl, LogConfig.logprobesfld,  0, conf->log_probes ? "X" : " ");
    set_field_buffer_wrap(debuglvl, LogConfig.logfragfld,  0, conf->log_frag ? "X" : " ");

    for(i = 0; i < ConfigSection.n_fields; i++)
    {
        // set field options
        set_field_back(ConfigSection.fields[i], vccnf.color_win_rev | A_BOLD);
        field_opts_off(ConfigSection.fields[i], O_AUTOSKIP);
        // set status to false
        set_field_status(ConfigSection.fields[i], FALSE);
    }
    set_field_back(LogConfig.rule_nflogfld, vccnf.color_win);
    set_field_back(LogConfig.logpolicyfld, vccnf.color_win);
    set_field_back(LogConfig.logtcpoptionsfld, vccnf.color_win);
    set_field_back(LogConfig.logblocklistfld, vccnf.color_win);
    set_field_back(LogConfig.loginvalidfld, vccnf.color_win);
    set_field_back(LogConfig.lognosynfld, vccnf.color_win);
    set_field_back(LogConfig.logprobesfld, vccnf.color_win);
    set_field_back(LogConfig.logfragfld, vccnf.color_win);

    /* Create the form and post it */
    ConfigSection.form = new_form(ConfigSection.fields);
    /* Calculate the area required for the form */
    scale_form(ConfigSection.form, &rows, &cols);
    keypad(ConfigSection.win, TRUE);
    /* Set main window and sub window */
    set_form_win(ConfigSection.form, ConfigSection.win);
    set_form_sub(ConfigSection.form, derwin(ConfigSection.win, rows, cols, 1, 2));

    post_form(ConfigSection.form);

    /* print labels */
    mvwprintw(ConfigSection.win, 2, 2,   gettext("Use NFLOG"));
    mvwprintw(ConfigSection.win, 2, 27, "[");
    mvwprintw(ConfigSection.win, 2, 29, "]");

    mvwprintw(ConfigSection.win, 2, 32,   gettext("Netfilter Group"));

    mvwprintw(ConfigSection.win, 4, 2,   gettext("Vuurmuur logfiles location (full path):"));
    mvwprintw(ConfigSection.win, 6, 2,   gettext("Loglevel (for use with syslog, requires vuurmuur restart):"));
    mvwprintw(ConfigSection.win, 8, 2,   gettext("Logfile containing IPtables/Netfilter logs:"));

    mvwprintw(ConfigSection.win, 11, 2,  gettext("Log the default policy? (DROP):"));
    mvwprintw(ConfigSection.win, 11, 62, "[");
    mvwprintw(ConfigSection.win, 11, 64, "]");

    mvwprintw(ConfigSection.win, 12, 2,  gettext("Limit of the number of logs per second (0 for no limit):"));

    mvwprintw(ConfigSection.win, 13, 2,  gettext("Log TCP options (for use with PSAD):"));
    mvwprintw(ConfigSection.win, 13, 62, "[");
    mvwprintw(ConfigSection.win, 13, 64, "]");

    /* TRANSLATORS: max 55 chars */
    mvwprintw(ConfigSection.win, 14, 2,  gettext("Log blocklist violations:"));
    mvwprintw(ConfigSection.win, 14, 62, "[");
    mvwprintw(ConfigSection.win, 14, 64, "]");

    /* TRANSLATORS: max 55 chars, don't translate 'INVALID' */
    mvwprintw(ConfigSection.win, 15, 2,  gettext("Log packets with state INVALID:"));
    mvwprintw(ConfigSection.win, 15, 62, "[");
    mvwprintw(ConfigSection.win, 15, 64, "]");

    /* TRANSLATORS: max 55 chars */
    mvwprintw(ConfigSection.win, 16, 2,  gettext("Log new TCP packets with no SYN flag set:"));
    mvwprintw(ConfigSection.win, 16, 62, "[");
    mvwprintw(ConfigSection.win, 16, 64, "]");

    /* TRANSLATORS: max 55 chars */
    mvwprintw(ConfigSection.win, 17, 2,  gettext("Log scan probe packets:"));
    mvwprintw(ConfigSection.win, 17, 62, "[");
    mvwprintw(ConfigSection.win, 17, 64, "]");

    /* TRANSLATORS: max 55 chars */
    mvwprintw(ConfigSection.win, 18, 2,  gettext("Log Fragments:"));
    mvwprintw(ConfigSection.win, 18, 62, "[");
    mvwprintw(ConfigSection.win, 18, 64, "]");

    return(retval);
}


static int
edit_logconfig_save(const int debuglvl, struct vrmr_config *conf)
{
    int     retval=0;
    size_t  i = 0;
    char    limit_string[4] = "";
    int     result = 0;

    /* check for changed fields */
    for(i=0; i < ConfigSection.n_fields; i++)
    {
        /* we only act if a field is changed */
        if(field_status(ConfigSection.fields[i]) == TRUE)
        {
            if(ConfigSection.fields[i] == LogConfig.logdirfld)
            {
                /* vuurmuurlog location */
                if(!(copy_field2buf(conf->vuurmuur_logdir_location,
                                    field_buffer(ConfigSection.fields[i], 0),
                                    sizeof(conf->vuurmuur_logdir_location))))
                    return(-1);
                
                if(StrLen(conf->vuurmuur_logdir_location) > 0)
                {
                    /* cut of the trailing slash if we have any */
                    if(conf->vuurmuur_logdir_location[StrMemLen(conf->vuurmuur_logdir_location)-1] == '/')
                        conf->vuurmuur_logdir_location[StrMemLen(conf->vuurmuur_logdir_location)-1] = '\0';
                }

                vrmr_sanitize_path(debuglvl, conf->vuurmuur_logdir_location,
                        StrLen(conf->vuurmuur_logdir_location));

                if(vrmr_config_check_logdir(debuglvl, conf->vuurmuur_logdir_location) < 0)
                {
                    retval = -1;
                }
                else
                {
                    /* print a warning about apply changes won't work for loglevel */
                    vrmr_warning(VR_WARN, gettext("changing the logdir requires applying changes to get into effect in the logviewer."));

                    vrmr_audit("'logdir location' %s '%s'.",
                        STR_IS_NOW_SET_TO, conf->vuurmuur_logdir_location);
                }
            }
            else if(ConfigSection.fields[i] == LogConfig.loglevelfld)
            {
                /* loglevel */
                if(!(copy_field2buf(conf->loglevel,
                                    field_buffer(ConfigSection.fields[i], 0),
                                    sizeof(conf->loglevel))))
                    return(-1);

                vrmr_audit("'log level' %s '%s'.",
                    STR_IS_NOW_SET_TO, conf->systemlog_location);
            }
            else if(ConfigSection.fields[i] == LogConfig.systemlogfld)
            {
                /* systemlog */
                if(!(copy_field2buf(conf->systemlog_location,
                                    field_buffer(ConfigSection.fields[i], 0),
                                    sizeof(conf->systemlog_location))))
                    return(-1);

                vrmr_sanitize_path(debuglvl, conf->systemlog_location,
                        StrLen(conf->systemlog_location));

                vrmr_audit("'systemlog location' %s '%s'.",
                    STR_IS_NOW_SET_TO, conf->systemlog_location);
            }
            else if(ConfigSection.fields[i] == LogConfig.rule_nflogfld)
            {
                /* nflog */
                if(field_buffer(ConfigSection.fields[i], 0)[0] == 'X')
                    conf->rule_nflog = 1;
                else
                    conf->rule_nflog = 0;

                vrmr_audit("'rule_nflog' %s '%s'.",
                    STR_IS_NOW_SET_TO, conf->rule_nflog ? STR_YES : STR_NO);
            }
            else if(ConfigSection.fields[i] == LogConfig.nfgrpfld)
            {
                /* NF group*/
                if(!(copy_field2buf(limit_string,
                                    field_buffer(ConfigSection.fields[i], 0),
                                    sizeof(limit_string))))
                    return(-1);

                result = atoi(limit_string);
                if(result < 0 || result > 999)
                {
                    vrmr_error(-1, VR_ERR, gettext("NF group must be between 0-999."));

                    /* restore the field */
                    if(conf->nfgrp > 0)
                    {
                        (void)snprintf(limit_string, sizeof(limit_string), "%u",
                                conf->nfgrp);
                        set_field_buffer_wrap(debuglvl, LogConfig.nfgrpfld, 0, limit_string);
                    }
                }
                else
                {
                    conf->nfgrp = (unsigned int)result;

                    vrmr_audit("'nfgrp' %s '%u'.",
                        STR_IS_NOW_SET_TO, conf->nfgrp);
                }
            }
            else if(ConfigSection.fields[i] == LogConfig.logpolicyfld)
            {
                /* log policy */
                if(field_buffer(ConfigSection.fields[i], 0)[0] == 'X')
                    conf->log_policy = 1;
                else
                    conf->log_policy = 0;

                vrmr_audit("'log policy' %s '%s'.",
                    STR_IS_NOW_SET_TO, conf->log_policy ? STR_YES : STR_NO);
            }
            else if(ConfigSection.fields[i] == LogConfig.logpolicylimitfld)
            {
                /* log policy limit */
                if(!(copy_field2buf(limit_string,
                                    field_buffer(ConfigSection.fields[i], 0),
                                    sizeof(limit_string))))
                    return(-1);

                result = atoi(limit_string);
                if(result < 0 || result > 999)
                {
                    vrmr_error(-1, VR_ERR, gettext("limit must be between 0-999."));

                    /* restore the field */
                    if(conf->log_policy_limit > 0)
                    {
                        (void)snprintf(limit_string, sizeof(limit_string), "%u",
                                conf->log_policy_limit);
                        set_field_buffer_wrap(debuglvl, LogConfig.logpolicylimitfld, 0, limit_string);
                    }
                }
                else
                {
                    conf->log_policy_limit = (unsigned int)result;

                    vrmr_audit("'log policy limit' %s '%u'.",
                        STR_IS_NOW_SET_TO, conf->log_policy_limit);
                }
            }
            else if(ConfigSection.fields[i] == LogConfig.logtcpoptionsfld)
            {
                /* log policy */
                if(field_buffer(ConfigSection.fields[i], 0)[0] == 'X')
                    conf->log_tcp_options = 1;
                else
                    conf->log_tcp_options = 0;

                vrmr_audit("'log TCP options' %s '%s'.",
                    STR_IS_NOW_SET_TO, conf->log_tcp_options ? STR_YES : STR_NO);
            }
            else if(ConfigSection.fields[i] == LogConfig.logblocklistfld)
            {
                /* log policy */
                if(field_buffer(ConfigSection.fields[i], 0)[0] == 'X')
                    conf->log_blocklist = 1;
                else
                    conf->log_blocklist = 0;

                vrmr_audit("'log blocklist' %s '%s'.",
                    STR_IS_NOW_SET_TO, conf->log_blocklist ? STR_YES : STR_NO);
            }
            else if(ConfigSection.fields[i] == LogConfig.loginvalidfld)
            {
                /* log policy */
                if(field_buffer(ConfigSection.fields[i], 0)[0] == 'X')
                    conf->log_invalid = 1;
                else
                    conf->log_invalid = 0;

                vrmr_audit("'log invalid' %s '%s'.",
                    STR_IS_NOW_SET_TO, conf->log_invalid ? STR_YES : STR_NO);
            }
            else if(ConfigSection.fields[i] == LogConfig.lognosynfld)
            {
                /* log policy */
                if(field_buffer(ConfigSection.fields[i], 0)[0] == 'X')
                    conf->log_no_syn = 1;
                else
                    conf->log_no_syn = 0;

                vrmr_audit("'log New TCP no SYN flag' %s '%s'.",
                    STR_IS_NOW_SET_TO, conf->log_no_syn ? STR_YES : STR_NO);
            }
            else if(ConfigSection.fields[i] == LogConfig.logprobesfld)
            {
                /* log policy */
                if(field_buffer(ConfigSection.fields[i], 0)[0] == 'X')
                    conf->log_probes = 1;
                else
                    conf->log_probes = 0;

                vrmr_audit("'log SCAN Probes' %s '%s'.",
                    STR_IS_NOW_SET_TO, conf->log_probes ? STR_YES : STR_NO);
            }
            else if(ConfigSection.fields[i] == LogConfig.logfragfld)
            {
                /* log policy */
                if(field_buffer(ConfigSection.fields[i], 0)[0] == 'X')
                    conf->log_frag = 1;
                else
                    conf->log_frag = 0;

                vrmr_audit("'log fragments' %s '%s'.",
                    STR_IS_NOW_SET_TO, conf->log_frag ? STR_YES : STR_NO);
            }
            else
            {
                vrmr_error(-1, VR_INTERR, "unknown field.");
                return(-1);
            }
        }
    }

    return(retval);
}


int
edit_logconfig(const int debuglvl, struct vrmr_config *conf)
{
    int     ch,
            retval = 0,
            quit = 0,
            not_defined = 0;
    int     height,
            width,
            startx,
            starty,
            max_height,
            max_width;
    FIELD   *cur = NULL,
            *prev = NULL;

    // window dimentions
    getmaxyx(stdscr, max_height, max_width);

    height = 20;
    width = 76;

    startx = (max_width - width)/2;
    starty = (max_height - height)/2;

    // setup
    edit_logconfig_init(debuglvl, conf, height, width, starty, startx);
    cur = current_field(ConfigSection.form);
    update_panels();
    doupdate();

    /* Loop through to get user requests */
    while(quit == 0)
    {
        /* visual support */
        draw_field_active_mark(cur, prev, ConfigSection.win, ConfigSection.form, vccnf.color_win_mark|A_BOLD);

        /* keyboard input */
        ch = wgetch(ConfigSection.win);

        not_defined = 0;

        if(cur == LogConfig.logdirfld ||
           cur == LogConfig.loglevelfld ||
           cur == LogConfig.systemlogfld ||
           cur == LogConfig.logpolicylimitfld ||
           cur == LogConfig.nfgrpfld)
        {
            if(nav_field_simpletext(debuglvl, ConfigSection.form, ch) < 0)
                not_defined = 1;
        }
        else if(cur == LogConfig.logpolicyfld ||
            cur == LogConfig.logtcpoptionsfld ||
            cur == LogConfig.logblocklistfld ||
            cur == LogConfig.loginvalidfld ||
            cur == LogConfig.lognosynfld ||
            cur == LogConfig.logprobesfld ||
            cur == LogConfig.logfragfld ||
            cur == LogConfig.rule_nflogfld)
        {
            if(nav_field_toggleX(debuglvl, ConfigSection.form, ch) < 0)
                not_defined = 1;
        }
        else
        {
            not_defined = 1;
        }

        if(not_defined)
        {
            switch(ch)
            {
                case 27:
                case KEY_F(10):
                case 'q':
                case 'Q':

                    /* save the field to the conf struct */
                    if(edit_logconfig_save(debuglvl, conf) < 0)
                    {
                        if (confirm(gettext("Saving config failed"),
                                    gettext("Saving the config failed. Sure you want to quit?"),
                                    vccnf.color_win_note, vccnf.color_win_note_rev|A_BOLD, 0))
                        {
                            retval = -1;
                            quit = 1;
                        }
                    }
                    else
                    {
                        quit = 1;
                        retval = 0;
                    }

                    break;

                case KEY_DOWN:
                case 10:    // enter
                case 9:     // tab
                    // Go to next field
                    form_driver(ConfigSection.form, REQ_NEXT_FIELD);
                    form_driver(ConfigSection.form, REQ_END_LINE);
                    break;
                
                case KEY_UP:
                    // Go to previous field
                    form_driver(ConfigSection.form, REQ_PREV_FIELD);
                    form_driver(ConfigSection.form, REQ_END_LINE);
                    break;

                case 127:
                case KEY_BACKSPACE:
                    form_driver(ConfigSection.form, REQ_PREV_CHAR);
                    form_driver(ConfigSection.form, REQ_DEL_CHAR);
                    form_driver(ConfigSection.form, REQ_END_LINE);
                    break;

                case KEY_DC:
                    form_driver(ConfigSection.form, REQ_PREV_CHAR);
                    form_driver(ConfigSection.form, REQ_DEL_CHAR);
                    form_driver(ConfigSection.form, REQ_END_LINE);
                    break;

                case KEY_F(12):
                case 'h':
                case 'H':
                case '?':

                    print_help(debuglvl, ":[VUURMUUR:CONFIG:LOGGING]:");
                    break;

                default:
                    // If this is a normal character, it gets printed into the field
                    form_driver(ConfigSection.form, ch);
                    break;
            }
        }

        prev = cur;
        cur = current_field(ConfigSection.form);
    }

    /* write configfile */
    if(retval == 0)
    {
        if (vrmr_write_configfile(debuglvl, conf->configfile, conf) < 0)
        {
            vrmr_error(-1, VR_ERR, gettext("writing configfile failed."));
            retval=-1;
        }
    }

    /* cleanup */
    edit_config_destroy();

    return(retval);
}

/* conntrack settings */

struct VrEditConntrackCnf_ {
    char invalid_drop_enabled;
    struct vrmr_config *conf;
};

static int
VrEditConntrackSetup(const int debuglvl, struct VrEditConntrackCnf_ *c, struct vrmr_config *conf) {
    if (c == NULL)
        return(-1);

    c->invalid_drop_enabled = conf->invalid_drop_enabled;
    c->conf = conf;
    return(0);
}

static int
VrEditConntrackSave(const int debuglvl, void *ctx, char *name, char *value)
{
    struct VrEditConntrackCnf_ *c = (struct VrEditConntrackCnf_ *)ctx;
    int retval = 0;

    //vrmr_debug(__FUNC__, "%s:%s", name, value);

    if(strcmp(name,"S") == 0) {
        char enabled = 0;

        if (strcmp(value,"X") == 0) {
            enabled = 1;
        }

        if (c->invalid_drop_enabled != enabled) {
            c->conf->invalid_drop_enabled = enabled;

            vrmr_audit("'drop INVALID packet flag' %s '%s'.",
                    STR_IS_NOW_SET_TO, c->conf->invalid_drop_enabled ? STR_YES : STR_NO);

            if (vrmr_write_configfile(debuglvl, c->conf->configfile, c->conf) < 0)
            {
                vrmr_error(-1, VR_ERR, gettext("writing configfile failed."));
                retval=-1;
            }
        }
    }

    return(retval);
}

static void VrEditConntrack(const int debuglvl, struct vrmr_config *conf) {
    VrWin   *win = NULL;
    VrForm  *form = NULL;
    int     ch = 0, result = 0;
    struct VrEditConntrackCnf_ config;

    if (VrEditConntrackSetup(debuglvl, &config, conf) < 0)
    {
        vrmr_error(-1, VR_ERR, "VrEditConntrackSetup failed");
        return;
    }

    /* create the window and put it in the middle of the screen */
    win = VrNewWin(11,51,0,0,vccnf.color_win);
    if(win == NULL)
    {
        vrmr_error(-1, VR_ERR, "VrNewWin failed");
        return;
    }
    VrWinSetTitle(win, gettext("Conntrack"));

    form = VrNewForm(9, 58, 1, 1, vccnf.color_win, vccnf.color_win_rev | A_BOLD);

    VrFormSetSaveFunc(debuglvl, form, VrEditConntrackSave, &config);

    VrFormAddLabelField(debuglvl,   form, 1, 35, 1, 1,  vccnf.color_win, gettext("Enable dropping INVALID packets"));
    VrFormAddCheckboxField(debuglvl,form,        1, 38, vccnf.color_win, "S", config.invalid_drop_enabled);

    VrFormConnectToWin(debuglvl, form, win);

    VrFormPost(debuglvl, form);

    update_panels();
    doupdate();

    /* user input */
    char quit = FALSE;
    while(quit == FALSE)
    {
        VrFormDrawMarker(debuglvl, win, form);

        ch = VrWinGetch(win);

        /* check OK/Cancel buttons */
        result = VrFormCheckOKCancel(debuglvl, form, ch);
        if (result == -1 || result == 1) {
            break;
        }

        if (VrFormDefaultNavigation(debuglvl, form, ch) == FALSE) {
            switch(ch)
            {
                case KEY_DOWN:
                case 10: // enter
                    form_driver(form->f, REQ_NEXT_FIELD);
                    form_driver(form->f, REQ_BEG_LINE);
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
                    print_help(debuglvl, ":[VUURMUUR:CONFIG:CONNTRACK]:");
                    break;
            }
        }
    }

    VrFormUnPost(debuglvl, form);
    VrDelForm(debuglvl, form);
    VrDelWin(win);
    update_panels();
    doupdate();
}



static int
view_caps_init(int height, int width, int starty, int startx, struct vrmr_iptcaps *iptcap)
{
    int retval = 0;

    /* safety */
    if(!iptcap)
    {
        vrmr_error(-1, VR_INTERR, "parameter problem (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    if(!(ConfigSection.win = create_newwin(height, width, starty, startx, gettext("View Capabilities"), vccnf.color_win)))
    {
        vrmr_error(-1, VR_INTERR, "create_newwin() failed (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }
    if(!(ConfigSection.panel[0] = new_panel(ConfigSection.win)))
    {
        vrmr_error(-1, VR_INTERR, "new_panel() failed (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    keypad(ConfigSection.win, TRUE);

    /* print labels */
    mvwprintw(ConfigSection.win, 2,  4, "Tables");
    if(iptcap->proc_net_names)
    {
        mvwprintw(ConfigSection.win, 4,  4, "filter\t%s", iptcap->table_filter ? STR_YES : STR_NO);
        mvwprintw(ConfigSection.win, 5,  4, "mangle\t%s", iptcap->table_mangle ? STR_YES : STR_NO);
        mvwprintw(ConfigSection.win, 6,  4, "nat\t\t%s", iptcap->table_nat ? STR_YES : STR_NO);
        mvwprintw(ConfigSection.win, 7,  4, "raw\t\t%s", iptcap->table_raw ? STR_YES : STR_NO);
    }
    else
    {
        mvwprintw(ConfigSection.win, 4,  4, gettext("Could not check."));
    }

    mvwprintw(ConfigSection.win, 9,  4, "Connection-");
    mvwprintw(ConfigSection.win, 10, 4, " tracking");
    mvwprintw(ConfigSection.win, 12, 4, "conntrack\t%s", iptcap->conntrack ? STR_YES : STR_NO);

    mvwprintw(ConfigSection.win, 14, 4, "NAT random\t%s", iptcap->target_nat_random ? STR_YES : STR_NO);

    mvwprintw(ConfigSection.win, 2,  27, "Targets");
    if(iptcap->proc_net_targets)
    {
        mvwprintw(ConfigSection.win, 4,  27, "LOG\t\t%s", iptcap->target_log ? STR_YES : STR_NO);
        mvwprintw(ConfigSection.win, 5,  27, "REJECT\t%s", iptcap->target_reject ? STR_YES : STR_NO);
        mvwprintw(ConfigSection.win, 6,  27, "QUEUE\t%s", iptcap->target_queue ? STR_YES : STR_NO);
        mvwprintw(ConfigSection.win, 7,  27, "-> Peer pid\t%u", iptcap->queue_peer_pid);
        mvwprintw(ConfigSection.win, 8,  27, "SNAT\t\t%s", iptcap->target_snat ? STR_YES : STR_NO);
        mvwprintw(ConfigSection.win, 9,  27, "MASQUERADE\t%s", iptcap->target_masquerade ? STR_YES : STR_NO);
        mvwprintw(ConfigSection.win, 10, 27, "DNAT\t\t%s", iptcap->target_dnat ? STR_YES : STR_NO);
        mvwprintw(ConfigSection.win, 11, 27, "REDIRECT\t%s", iptcap->target_redirect ? STR_YES : STR_NO);
        mvwprintw(ConfigSection.win, 12, 27, "MARK\t\t%s", iptcap->target_mark ? STR_YES : STR_NO);
        mvwprintw(ConfigSection.win, 13, 27, "CONNMARK\t%s", iptcap->target_connmark ? STR_YES : STR_NO);
        mvwprintw(ConfigSection.win, 14, 27, "NFQUEUE\t%s", iptcap->target_nfqueue ? STR_YES : STR_NO);
        mvwprintw(ConfigSection.win, 15, 27, "CLASSIFY\t%s", iptcap->target_classify ? STR_YES : STR_NO);
        mvwprintw(ConfigSection.win, 16, 27, "TCPMSS\t%s", iptcap->target_tcpmss ? STR_YES : STR_NO);
        mvwprintw(ConfigSection.win, 17, 27, "NFLOG\t%s", iptcap->target_nflog ? STR_YES : STR_NO);
    }
    else
    {
        mvwprintw(ConfigSection.win, 4,  27, gettext("Could not check."));
    }

    mvwprintw(ConfigSection.win, 2,  52, "Matches");
    if(iptcap->proc_net_matches)
    {
        mvwprintw(ConfigSection.win, 4,  52, "state\t%s", iptcap->match_state ? STR_YES : STR_NO);
        mvwprintw(ConfigSection.win, 5,  52, "mac\t\t%s", iptcap->match_mac ? STR_YES : STR_NO);
        mvwprintw(ConfigSection.win, 6,  52, "mark\t%s", iptcap->match_mark ? STR_YES : STR_NO);
        mvwprintw(ConfigSection.win, 7,  52, "limit\t%s", iptcap->match_limit ? STR_YES : STR_NO);
        mvwprintw(ConfigSection.win, 8,  52, "helper\t%s", iptcap->match_helper ? STR_YES : STR_NO);
        mvwprintw(ConfigSection.win, 9,  52, "length\t%s", iptcap->match_length ? STR_YES : STR_NO);
        mvwprintw(ConfigSection.win, 10, 52, "connmark\t%s", iptcap->match_connmark ? STR_YES : STR_NO);
        mvwprintw(ConfigSection.win, 11, 52, "rpfilter\t%s", iptcap->match_rpfilter ? STR_YES : STR_NO);
        mvwprintw(ConfigSection.win, 12, 52, "conntrack\t%s", iptcap->match_conntrack ? STR_YES : STR_NO);
    }
    else
    {
        mvwprintw(ConfigSection.win, 4,  52, gettext("Could not check."));
    }

    return(retval);
}


int
view_caps(const int debuglvl, struct vrmr_config *conf)
{
    int     ch,
            retval = 0,
            quit = 0,
            result = 0;
    int     height,
            width,
            startx,
            starty,
            max_height,
            max_width;
    struct vrmr_iptcaps  iptcap;
    char    reload = 0;
    /* top menu */
    char    *key_choices[] =    {   "F12",
                                    "F5",
                                    "F10"};
    int     key_choices_n = 3;
    char    *cmd_choices[] =    {   gettext("help"),
                                    gettext("probe"),
                                    gettext("back")};
    int     cmd_choices_n = 3;


    /* window dimentions */
    getmaxyx(stdscr, max_height, max_width);

    height = 19;
    width  = 76;
    startx = (max_width  - width) /2;
    starty = (max_height - height)/2;

    draw_top_menu(debuglvl, top_win, gettext("Capabilities"), key_choices_n, key_choices, cmd_choices_n, cmd_choices);

    /* load iptcaps */
    result = vrmr_load_iptcaps(debuglvl, conf, &iptcap, 0);
    if(result == -1)
    {
        vrmr_error(-1, VR_ERR, gettext("checking capabilities failed."));
        return(-1);
    }

    if (debuglvl >= LOW) {
        vrmr_debug(__FUNC__, "iptcap.proc_net_names %d "
            "iptcap.proc_net_matches %d iptcap.proc_net_targets %d "
            "iptcap.table_filter %d iptcap.conntrack %d "
            "iptcap.match_tcp %d iptcap.match_udp %d iptcap.match_icmp %d "
                    "iptcap.match_state %d", iptcap.proc_net_names,
            iptcap.proc_net_matches, iptcap.proc_net_targets,
                    iptcap.table_filter, iptcap.conntrack, iptcap.match_tcp,
            iptcap.match_udp, iptcap.match_icmp, iptcap.match_state);
    }

    /* setup */
    result = view_caps_init(height, width, starty, startx, &iptcap);
    if(result < 0)
    {
        return(-1);
    }

    update_panels();
    doupdate();

    /* Loop through to get user requests */
    while(quit == 0)
    {
        /* keyboard input */
        ch = wgetch(ConfigSection.win);
        switch(ch)
        {
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
                            gettext("Try to determine capabities? Warning: this may load iptables modules!"),
                            vccnf.color_win_note, vccnf.color_win_note_rev|A_BOLD, 0))
                {
                    result = vrmr_load_iptcaps(debuglvl, conf, &iptcap, 1);
                    if(result == -1)
                    {
                        vrmr_error(-1, VR_ERR, gettext("checking capabilities failed."));
                        return(-1);
                    }
                }
                reload = 1;
                quit = 1;
                break;

            case KEY_F(12):
            case 'h':
            case 'H':
            case '?':

                print_help(debuglvl, ":[VUURMUUR:CONFIG:CAPABILITIES]:");
                break;

        }
    }

    /* cleanup */
    del_panel(ConfigSection.panel[0]);
    destroy_win(ConfigSection.win);
    update_panels();
    doupdate();

    if (reload == 1)
        return(view_caps(debuglvl, conf));

    return(retval);
}

#ifdef IPV6_ENABLED
static int
view_ip6_caps_init(int height, int width, int starty, int startx, struct vrmr_iptcaps *iptcap)
{
    int retval = 0;

    /* safety */
    if(!iptcap)
    {
        vrmr_error(-1, VR_INTERR, "parameter problem (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    if(!(ConfigSection.win = create_newwin(height, width, starty, startx, gettext("View IPv6 Capabilities"), vccnf.color_win)))
    {
        vrmr_error(-1, VR_INTERR, "create_newwin() failed (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }
    if(!(ConfigSection.panel[0] = new_panel(ConfigSection.win)))
    {
        vrmr_error(-1, VR_INTERR, "new_panel() failed (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    keypad(ConfigSection.win, TRUE);

    /* print labels */
    mvwprintw(ConfigSection.win, 2,  4, "Tables");
    if(iptcap->proc_net_ip6_names)
    {
        mvwprintw(ConfigSection.win, 4,  4, "filter\t%s", iptcap->table_ip6_filter ? STR_YES : STR_NO);
        mvwprintw(ConfigSection.win, 5,  4, "mangle\t%s", iptcap->table_ip6_mangle ? STR_YES : STR_NO);
        mvwprintw(ConfigSection.win, 6,  4, "raw\t\t%s", iptcap->table_ip6_raw ? STR_YES : STR_NO);
    }
    else
    {
        mvwprintw(ConfigSection.win, 4,  4, gettext("Could not check."));
    }

    mvwprintw(ConfigSection.win, 8,  4, "Connection-");
    mvwprintw(ConfigSection.win, 9,  4, " tracking");
/* TODO Need to check if this has a ipv6 version */
    mvwprintw(ConfigSection.win, 11, 4, "conntrack\t%s", iptcap->conntrack ? STR_YES : STR_NO);
    
/*
    mvwprintw(ConfigSection.win, 14, 4, "NAT random\t%s", iptcap->target_nat_random ? STR_YES : STR_NO);
*/

    mvwprintw(ConfigSection.win, 2,  27, "Targets");
    if(iptcap->proc_net_ip6_targets)
    {
        mvwprintw(ConfigSection.win, 4,  27, "LOG\t\t%s", iptcap->target_ip6_log ? STR_YES : STR_NO);
        mvwprintw(ConfigSection.win, 5,  27, "REJECT\t%s", iptcap->target_ip6_reject ? STR_YES : STR_NO);
        mvwprintw(ConfigSection.win, 6,  27, "QUEUE\t%s", iptcap->target_ip6_queue ? STR_YES : STR_NO);
        mvwprintw(ConfigSection.win, 7,  27, "-> Peer pid\t%u", iptcap->ip6_queue_peer_pid);
/*
        mvwprintw(ConfigSection.win, 8,  27, "SNAT\t\t%s", iptcap->target_snat ? STR_YES : STR_NO);
        mvwprintw(ConfigSection.win, 9,  27, "MASQUERADE\t%s", iptcap->target_masquerade ? STR_YES : STR_NO);
        mvwprintw(ConfigSection.win, 10, 27, "DNAT\t\t%s", iptcap->target_dnat ? STR_YES : STR_NO);
        mvwprintw(ConfigSection.win, 11, 27, "REDIRECT\t%s", iptcap->target_redirect ? STR_YES : STR_NO);
*/
        mvwprintw(ConfigSection.win, 12, 27, "MARK\t\t%s", iptcap->target_ip6_mark ? STR_YES : STR_NO);
        mvwprintw(ConfigSection.win, 13, 27, "CONNMARK\t%s", iptcap->target_ip6_connmark ? STR_YES : STR_NO);
        mvwprintw(ConfigSection.win, 14, 27, "NFQUEUE\t%s", iptcap->target_ip6_nfqueue ? STR_YES : STR_NO);
        mvwprintw(ConfigSection.win, 15, 27, "CLASSIFY\t%s", iptcap->target_ip6_classify ? STR_YES : STR_NO);
        mvwprintw(ConfigSection.win, 16, 27, "TCPMSS\t%s", iptcap->target_ip6_tcpmss ? STR_YES : STR_NO);
    }
    else
    {
        mvwprintw(ConfigSection.win, 4,  27, gettext("Could not check."));
    }

    mvwprintw(ConfigSection.win, 2,  52, "Matches");
    if(iptcap->proc_net_ip6_matches)
    {
        mvwprintw(ConfigSection.win, 4,  52, "state\t%s", iptcap->match_ip6_state ? STR_YES : STR_NO);
        mvwprintw(ConfigSection.win, 5,  52, "mac\t\t%s", iptcap->match_ip6_mac ? STR_YES : STR_NO);
        mvwprintw(ConfigSection.win, 6,  52, "mark\t%s", iptcap->match_ip6_mark ? STR_YES : STR_NO);
        mvwprintw(ConfigSection.win, 7,  52, "limit\t%s", iptcap->match_ip6_limit ? STR_YES : STR_NO);
        mvwprintw(ConfigSection.win, 8,  52, "helper\t%s", iptcap->match_ip6_helper ? STR_YES : STR_NO);
        mvwprintw(ConfigSection.win, 9,  52, "length\t%s", iptcap->match_ip6_length ? STR_YES : STR_NO);
        mvwprintw(ConfigSection.win, 10, 52, "connmark\t%s", iptcap->match_ip6_connmark ? STR_YES : STR_NO);
        mvwprintw(ConfigSection.win, 11, 52, "rpfilter\t%s", iptcap->match_ip6_rpfilter ? STR_YES : STR_NO);
        mvwprintw(ConfigSection.win, 12, 52, "conntrack\t%s", iptcap->match_ip6_conntrack ? STR_YES : STR_NO);
    }
    else
    {
        mvwprintw(ConfigSection.win, 4,  52, gettext("Could not check."));
    }

    return(retval);
}

int
view_ip6_caps(const int debuglvl, struct vrmr_config *conf)
{
    int     ch,
            retval = 0,
            quit = 0,
            result = 0;
    int     height,
            width,
            startx,
            starty,
            max_height,
            max_width;
    struct vrmr_iptcaps  iptcap;
    char    reload = 0;
    /* top menu */
    char    *key_choices[] =    {   "F12",
                                    "F5",
                                    "F10"};
    int     key_choices_n = 3;
    char    *cmd_choices[] =    {   gettext("help"),
                                    gettext("probe"),
                                    gettext("back")};
    int     cmd_choices_n = 3;


    /* window dimentions */
    getmaxyx(stdscr, max_height, max_width);

    height = 18;
    width  = 76;
    startx = (max_width  - width) /2;
    starty = (max_height - height)/2;

    draw_top_menu(debuglvl, top_win, gettext("IPv6 Capabilities"), key_choices_n, key_choices, cmd_choices_n, cmd_choices);

    /* load iptcaps */
    result = vrmr_load_ip6tcaps(debuglvl, conf, &iptcap, 0);
    if(result == -1)
    {
        vrmr_error(-1, VR_ERR, gettext("checking capabilities failed."));
        return(-1);
    }

    if (debuglvl >= LOW) {
        vrmr_debug(__FUNC__, "iptcap.proc_net_ip6_names %d "
            "iptcap.proc_net_ip6_matches %d iptcap.proc_net_ip6_targets %d "
            "iptcap.table_ip6_filter %d iptcap.match_tcp6 %d "
            "iptcap.match_udp6 %d iptcap.match_icmp6 %d "
            "iptcap.match_mark6 %d", iptcap.proc_net_ip6_names,
            iptcap.proc_net_ip6_matches, iptcap.proc_net_ip6_targets,
            iptcap.table_ip6_filter, iptcap.match_ip6_tcp, iptcap.match_ip6_udp,
            iptcap.match_icmp6, iptcap.match_ip6_mark );
    }

    /* setup */
    result = view_ip6_caps_init(height, width, starty, startx, &iptcap);
    if(result < 0)
    {
        return(-1);
    }

    update_panels();
    doupdate();

    /* Loop through to get user requests */
    while(quit == 0)
    {
        /* keyboard input */
        ch = wgetch(ConfigSection.win);
        switch(ch)
        {
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
                            gettext("Try to determine capabities? Warning: this may load iptables modules!"),
                            vccnf.color_win_note, vccnf.color_win_note_rev|A_BOLD, 0))
                {
                    result = vrmr_load_ip6tcaps(debuglvl, conf, &iptcap, 1);
                    if(result == -1)
                    {
                        vrmr_error(-1, VR_ERR, gettext("checking capabilities failed."));
                        return(-1);
                    }
                }
                reload = 1;
                quit = 1;
                break;

            case KEY_F(12):
            case 'h':
            case 'H':
            case '?':

                print_help(debuglvl, ":[VUURMUUR:CONFIG:CAPABILITIES]:");
                break;

        }
    }

    /* cleanup */
    del_panel(ConfigSection.panel[0]);
    destroy_win(ConfigSection.win);
    update_panels();
    doupdate();

    if (reload == 1)
        return(view_ip6_caps(debuglvl, conf));

    return(retval);
}
#endif


int
config_menu(const int debuglvl, struct vrmr_config *conf)
{
#ifdef IPV6_ENABLED
    size_t  n_choices = 11;
#else
    size_t  n_choices = 10;
#endif
    size_t  i = 0;
    int     ch = 0,
            quit = 0;
    ITEM    **menu_items = NULL;
    ITEM    *cur = NULL;
    MENU    *main_menu = NULL;
    WINDOW  *mainmenu_win = NULL;
    PANEL   *conf_panels[1];

    // menu
    char *choice_ptr = NULL;

    char *choices[] = {
            VROPT_GENERAL,
            VROPT_CONNECTIONS,
            VROPT_INTERFACES,
            VROPT_SYSPROT,
            VROPT_CONNTRACK,
            VROPT_LOGGING,
            VROPT_MODULES,
            VROPT_PLUGINS,
            VROPT_CAPS,
#ifdef IPV6_ENABLED
            VROPT_IP6_CAPS,
#endif
            gettext("Back"),
            NULL
    };

    char *descriptions[] = {
            " ",
            " ",
            " ",
            " ",
            " ",
            " ",
            " ",
            " ",
            " ",
#ifdef IPV6_ENABLED
            " ",
#endif
            " ",
            NULL
    };

    /* top menu */
    char    *key_choices[] =    {   "F12",
                                    "F10"};
    int     key_choices_n = 2;
    char    *cmd_choices[] =    {   gettext("help"),
                                    gettext("back")};
    int     cmd_choices_n = 2;

    int     x = 50,
            y =  9 + (int)n_choices,
            startx = 0,
            starty = 0,
            maxx = 0,
            maxy = 0;

    getmaxyx(stdscr, maxy, maxx);
    startx = (maxx-x)/2;
    starty = (maxy-y)/2;

    if(!(menu_items = (ITEM **)calloc(n_choices + 1, sizeof(ITEM *))))
        return(-1);

    for(i = 0; i < n_choices; ++i){
        menu_items[i] = new_item(choices[i], descriptions[i]);
    }
    menu_items[n_choices] = (ITEM *)NULL;

    main_menu = new_menu((ITEM **)menu_items);

    mainmenu_win = create_newwin(y, x, starty, startx, gettext("Configuration Menu"), vccnf.color_win);
    keypad(mainmenu_win, TRUE);
    wrefresh(mainmenu_win);

    conf_panels[0] = new_panel(mainmenu_win);

    // menu settings
    set_menu_win(main_menu, mainmenu_win);
    set_menu_sub(main_menu, derwin(mainmenu_win, y-8, x-12, 6, 6));
    set_menu_format(main_menu, y-4, 1);
    set_menu_back(main_menu, vccnf.color_win);
    set_menu_fore(main_menu, vccnf.color_win_rev);

    post_menu(main_menu);

    // welcome message
    mvwprintw(mainmenu_win, 3, 6, gettext("Select a section."));

    draw_top_menu(debuglvl, top_win, gettext("Vuurmuur Config"), key_choices_n, key_choices, cmd_choices_n, cmd_choices);

    update_panels();
    doupdate();

    while(quit == 0)
    {
        show_panel(conf_panels[0]);

        ch = wgetch(mainmenu_win);
        switch(ch)
        {
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

                choice_ptr = malloc(StrMemLen((char *)item_name(cur))+1);
                strcpy(choice_ptr, (char *)item_name(cur));
                break;
        }

        if(choice_ptr != NULL)
        {
            hide_panel(conf_panels[0]);

            if(strcmp(choice_ptr, VROPT_GENERAL) == 0)
            {
                edit_genconfig(debuglvl, conf);
            }
            else if(strcmp(choice_ptr, VROPT_CONNECTIONS) == 0)
            {
                edit_conconfig(debuglvl, conf);
            }
            else if(strcmp(choice_ptr, VROPT_INTERFACES) == 0)
            {
                edit_intconfig(debuglvl, conf);
            }
            else if(strcmp(choice_ptr, VROPT_SYSPROT) == 0)
            {
                edit_sysopt(debuglvl, conf);
            }
            else if(strcmp(choice_ptr, VROPT_CONNTRACK) == 0)
            {
                VrEditConntrack(debuglvl, conf);
            }
            else if(strcmp(choice_ptr, VROPT_LOGGING) == 0)
            {
                edit_logconfig(debuglvl, conf);
            }
            else if(strcmp(choice_ptr, VROPT_MODULES) == 0)
            {
                edit_modconfig(debuglvl, conf);
            }
            else if(strcmp(choice_ptr, VROPT_PLUGINS) == 0)
            {
                edit_plugconfig(debuglvl, conf);
            }
            else if(strcmp(choice_ptr, VROPT_CAPS) == 0)
            {
                view_caps(debuglvl, conf);
            }
#ifdef IPV6_ENABLED
            else if(strcmp(choice_ptr, VROPT_IP6_CAPS) == 0)
            {
                view_ip6_caps(debuglvl, conf);
            }
#endif
            else if(strncmp(choice_ptr, gettext("Back"), StrLen(gettext("Back"))) == 0)
            {
                quit = 1;
            }

            free(choice_ptr);
            choice_ptr = NULL;
        }
    }

    /* cleanup */
    unpost_menu(main_menu);
    free_menu(main_menu);
    for(i = 0; i < n_choices; ++i)
        free_item(menu_items[i]);
    free(menu_items);

    del_panel(conf_panels[0]);

    destroy_win(mainmenu_win);

    update_panels();
    doupdate();

    return(0);
}
