/***************************************************************************
 *   Copyright (C) 2003-2006 by Victor Julien                              *
 *   victor@nk.nl                                                          *
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


struct SystemSection_
{
    PANEL   *panel[1];
    WINDOW  *win;
    FIELD   **fields;
    FORM    *form;
    size_t  n_fields;
} SystemSection;


static int
edit_sysopt_init(const int debuglvl, int height, int width, int starty, int startx)
{
    int     retval=0,
            rows,
            cols;
    int     max_height,
            max_width;
    size_t  i = 0;

    getmaxyx(stdscr, max_height, max_width);

    SystemSection.n_fields = 2;
    SystemSection.fields = (FIELD **)calloc(SystemSection.n_fields + 1, sizeof(FIELD *));

    // create the fields
    SystemSection.fields[0] = new_field(1, 1, 1, 2, 0, 1); // syn-flood
    set_field_buffer_wrap(debuglvl, SystemSection.fields[0], 1, "s");
    set_field_buffer_wrap(debuglvl, SystemSection.fields[0], 0, conf.protect_syncookie ? "X" : " ");

    SystemSection.fields[1] = new_field(1, 1, 3, 2, 0, 1); // echo-broadcast
    set_field_buffer_wrap(debuglvl, SystemSection.fields[1], 1, "e");
    set_field_buffer_wrap(debuglvl, SystemSection.fields[1], 0, conf.protect_echobroadcast ? "X" : " ");

    SystemSection.fields[2] = NULL;

    SystemSection.win = create_newwin(height, width, starty, startx, gettext("System Protection"), (chtype)COLOR_PAIR(5));
    SystemSection.panel[0] = new_panel(SystemSection.win);

    for(i = 0; i < SystemSection.n_fields; i++)
    {
        // set field options
        set_field_back(SystemSection.fields[i], (chtype)COLOR_PAIR(CP_BLUE_WHITE));
        field_opts_off(SystemSection.fields[i], O_AUTOSKIP);
        // set status to false
        set_field_status(SystemSection.fields[i], FALSE);
    }

    // Create the form and post it
    SystemSection.form = new_form(SystemSection.fields);
    // Calculate the area required for the form
    scale_form(SystemSection.form, &rows, &cols);
    keypad(SystemSection.win, TRUE);
    // Set main window and sub window
    set_form_win(SystemSection.form, SystemSection.win);
    set_form_sub(SystemSection.form, derwin(SystemSection.win, rows, cols, 1, 2));

    post_form(SystemSection.form);

    // print labels
    mvwprintw(SystemSection.win, 2, 3,  "[");
    mvwprintw(SystemSection.win, 2, 5,  "]");
    mvwprintw(SystemSection.win, 2, 8,  gettext("Syn-flood protection"));

    mvwprintw(SystemSection.win, 4, 3,  "[");
    mvwprintw(SystemSection.win, 4, 5,  "]");
    mvwprintw(SystemSection.win, 4, 8,  gettext("Echo-broadcast protect"));

    return(retval);
}


/*
    return codes:
        -1 error
        0: no changes
        1: changes
*/
int
edit_sysopt_save(const int debuglvl)
{
    int     retval = 0;
    size_t  i = 0;

    /* check for changed fields */
    for(i=0; i < SystemSection.n_fields; i++)
    {
        // we only act if a field is changed
        if(field_status(SystemSection.fields[i]) == TRUE)
        {
            if(debuglvl >= HIGH)
                (void)vrprint.debug(__FUNC__, "field[%d] was changed.", i);

            /*
                handle only 's' (syn-flood) and 'e' (echo-broadcast) fields
            */
            if(strncmp(field_buffer(SystemSection.fields[i], 1), "s", 1) == 0)
            {
                if(strncmp(field_buffer(SystemSection.fields[i], 0), "X", 1) == 0)
                    conf.protect_syncookie = 1;
                else
                    conf.protect_syncookie = 0;

                (void)vrprint.audit("'protect against synflood' %s '%s'.",
                    STR_IS_NOW_SET_TO, conf.protect_syncookie ? STR_YES : STR_NO);

                retval = 1;
            }
            else if(strncmp(field_buffer(SystemSection.fields[i], 1), "e", 1) == 0)
            {
                if(strncmp(field_buffer(SystemSection.fields[i], 0), "X", 1) == 0)
                    conf.protect_echobroadcast = 1;
                else
                    conf.protect_echobroadcast = 0;

                (void)vrprint.audit("'protect against echo broadcast' %s '%s'.",
                    STR_IS_NOW_SET_TO, conf.protect_echobroadcast ? STR_YES : STR_NO);

                retval = 1;
            }
        }
    }

    return(retval);
}


static int
edit_sysopt_destroy(void)
{
    size_t  i = 0;

    // Un post form and free the memory
    unpost_form(SystemSection.form);
    free_form(SystemSection.form);
    for(i=0;i<SystemSection.n_fields;i++)
    {
        free_field(SystemSection.fields[i]);
    }
    free(SystemSection.fields);

    del_panel(SystemSection.panel[0]);
    destroy_win(SystemSection.win);

    return(0);
}

int
edit_sysopt(const int debuglvl)
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

    getmaxyx(stdscr, max_height, max_width);

    height = 18;
    width  = 76;

    startx = (max_width - width)/2;
    starty = (max_height - height)/2;

    curs_set(0);

    edit_sysopt_init(debuglvl, height, width, starty, startx);
    cur = current_field(SystemSection.form);
    update_panels();
    doupdate();

    // Loop through to get user requests
    while(quit == 0)
    {
        draw_field_active_mark(cur, prev, SystemSection.win, SystemSection.form, (chtype)COLOR_PAIR(CP_RED_WHITE)|A_BOLD);

        ch = wgetch(SystemSection.win);

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
            case 9: // tab
                // Go to next field
                form_driver(SystemSection.form, REQ_NEXT_FIELD);
                // Go to the end of the present buffer
                // Leaves nicely at the last character
                form_driver(SystemSection.form, REQ_END_LINE);
                break;
            
            case KEY_UP:
                // Go to previous field
                form_driver(SystemSection.form, REQ_PREV_FIELD);
                form_driver(SystemSection.form, REQ_END_LINE);
                break;
            
            case 127:
            case KEY_BACKSPACE:
                form_driver(SystemSection.form, REQ_PREV_CHAR);
                form_driver(SystemSection.form, REQ_DEL_CHAR);
                form_driver(SystemSection.form, REQ_END_LINE);
                break;
            
            case KEY_DC:
                form_driver(SystemSection.form, REQ_PREV_CHAR);
                form_driver(SystemSection.form, REQ_DEL_CHAR);
                form_driver(SystemSection.form, REQ_END_LINE);
                break;
            
            case 32:
            {
                if( strncmp(field_buffer(cur, 1), "s", 1) == 0 ||
                    strncmp(field_buffer(cur, 1), "e", 1) == 0)
                {
                    if(strncasecmp(field_buffer(cur, 0), "X", 1) == 0)
                    {
                        set_field_buffer_wrap(debuglvl, cur, 0, " ");
                    }
                    else
                    {
                        set_field_buffer_wrap(debuglvl, cur, 0, "X");
                    }
                }
                else
                {
                    form_driver(SystemSection.form, ch);
                }
                break;
            }
            
            case KEY_F(12):
            case 'h':
            case 'H':
            case '?':
                print_help(debuglvl, ":[VUURMUUR:CONFIG:SYSSEC]:");
                break;
        }

        prev = cur;
        cur = current_field(SystemSection.form);
    }

    // save the field to the conf struct
    if(edit_sysopt_save(debuglvl) < 0)
        retval=-1;

    /* write configfile */
    if(retval == 0)
    {
        if(write_configfile(debuglvl, conf.configfile) < 0)
        {
            (void)vrprint.error(-1, VR_ERR, gettext("writing configfile failed."));
            retval = -1;
        }
    }

    // cleanup
    edit_sysopt_destroy();
    curs_set(1);
    update_panels();
    doupdate();

    return(retval);
}
