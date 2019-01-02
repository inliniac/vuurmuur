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

struct FilterFields_
{
    FIELD   **fields;
    FIELD   *string_fld,
            *check_fld;
    size_t  n_fields;
} FiFi;

static int
filter_save(struct vrmr_filter *filter)
{
    size_t  i = 0;
    char    filter_str[48] = "";

    /* safety */
    vrmr_fatal_if_null(filter);

    /* check for changed fields */
    for(i = 0; i < FiFi.n_fields; i++)
    {
        if (FiFi.fields[i] == FiFi.check_fld)
        {
            if(strncmp(field_buffer(FiFi.fields[i], 0), "X", 1) == 0)
                filter->neg = TRUE;
            else
                filter->neg = FALSE;

                vrmr_debug(HIGH, "filter->neg is now %s.",
                                filter->neg ? "TRUE" : "FALSE");
        }
        /* ipaddress field */
        else if(FiFi.fields[i] == FiFi.string_fld)
        {
            copy_field2buf(filter->str,
                                field_buffer(FiFi.fields[i], 0),
                                sizeof(filter->str));

            vrmr_debug(MEDIUM, "filter field changed: %s.",
                    filter->str);

            /* new str */
            if(StrLen(filter->str) > 0)
            {
                if(filter->reg_active == TRUE)
                {
                    /* first remove old regex */
                    regfree(&filter->reg);
                    /* set reg_active to false */
                    filter->reg_active = FALSE;
                }

                snprintf(filter_str, sizeof(filter_str), ".*%s.*", filter->str);

                /* create the new regex */
                if(regcomp(&filter->reg, filter_str, REG_EXTENDED) != 0)
                {
                    vrmr_error(-1, VR_INTERR, "setting up the regular expression with regcomp failed. Disabling filter.");
                    return(-1);
                }

                /* set reg_active to true */
                filter->reg_active = TRUE;
            }

            /* empty field, remove regex */
            if(StrLen(filter->str) == 0 && filter->reg_active == TRUE)
            {
                /* first remove old regex */
                regfree(&filter->reg);

                /* set reg_active to false */
                filter->reg_active = FALSE;
            }
        }
        else {
            vrmr_fatal("unknown field");
        }
    }
    return(0);
}

int
filter_input_box(struct vrmr_filter *filter)
{
    WINDOW  *ib_win = NULL;
    PANEL   *my_panels[1];
    FIELD   *cur = NULL,
            *prev = NULL;
    FORM    *my_form = NULL;
    int     height = 0,
            width = 0,
            startx = 0,
            starty = 0,
            max_height = 0,
            max_width = 0,
            ch = 0,
            rows = 0,
            cols = 0,
            quit = 0;
    size_t  i = 0;
    char    not_defined = FALSE;

    /* init fields */
    memset(&FiFi, 0, sizeof(struct FilterFields_));

    /* set the window size */
    getmaxyx(stdscr, max_height, max_width);
    height = 9;
    width = 48;
    /* print on the center of the screen */
    starty = (max_height - height) / 2;
    startx = (max_width - width) / 2;

    /* create window */
    ib_win = create_newwin(height, width, starty, startx, gettext("Filter"), vccnf.color_win);
    vrmr_fatal_if_null(ib_win);
    my_panels[0] = new_panel(ib_win);
    vrmr_fatal_if_null(my_panels[0]);
    FiFi.n_fields = 2;

    FiFi.fields = (FIELD **)calloc(FiFi.n_fields + 1, sizeof(FIELD *));
    vrmr_fatal_alloc("calloc", FiFi.fields);

    FiFi.string_fld = (FiFi.fields[0] = new_field(1, 31, 3,  4, 0, 0));
    FiFi.check_fld = (FiFi.fields[1]  = new_field(1,  1, 5,  5, 0, 0));

    set_field_back(FiFi.string_fld, vccnf.color_win_rev);
    field_opts_off(FiFi.string_fld, O_AUTOSKIP);
    set_field_status(FiFi.string_fld, FALSE);
    set_field_buffer_wrap(FiFi.string_fld, 0, filter->str);

    set_field_back(FiFi.check_fld, vccnf.color_win);
    field_opts_off(FiFi.check_fld, O_AUTOSKIP);
    set_field_status(FiFi.check_fld, FALSE);
    set_field_buffer_wrap(FiFi.check_fld, 0, filter->neg ? "X" : " ");

    my_form = new_form(FiFi.fields);
    scale_form(my_form, &rows, &cols);
    keypad(ib_win, TRUE);
    set_form_win(my_form, ib_win);
    set_form_sub(my_form, derwin(ib_win, rows, cols, 1, 2));
    post_form(my_form);

    /* XXX: we really should have a wrapper function to just print
     * in the middle of a window to prevent hacks like this. */
    char *s = gettext("Enter filter (leave empty for no filter)");
    mvwprintw(ib_win, 2, (width - StrLen(s))/2, s);
    mvwprintw(ib_win, 6, 6, "[");
    mvwprintw(ib_win, 6, 8, "]");
    mvwprintw(ib_win, 6, 11, gettext("show lines that don't match"));

    update_panels();
    doupdate();

    cur = current_field(my_form);
    vrmr_fatal_if_null(cur);

    while(quit == 0)
    {
        /* draw nice markers */
        draw_field_active_mark(cur, prev, ib_win, my_form, vccnf.color_win_mark|A_BOLD);

        not_defined = 0;

        /* get user input */
        ch = wgetch(ib_win);

        if(cur == FiFi.check_fld)
        {
            if(nav_field_toggleX(my_form, ch) < 0)
                not_defined = 1;
        }
        else if(cur == FiFi.string_fld)
        {
            if(nav_field_simpletext(my_form, ch) < 0)
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
                case KEY_UP:

                    form_driver(my_form, REQ_PREV_FIELD);
                    form_driver(my_form, REQ_END_LINE);
                    break;

                case KEY_DOWN:
                case 9: // tab

                    form_driver(my_form, REQ_NEXT_FIELD);
                    form_driver(my_form, REQ_END_LINE);
                    break;

                case 10: // enter

                    if(cur == FiFi.check_fld) {
                        quit = 1;
                    } else {
                        form_driver(my_form, REQ_NEXT_FIELD);
                        form_driver(my_form, REQ_END_LINE);
                    }
                    break;

                case 27:
                case KEY_F(10):
                case 'q':
                case 'Q':

                    quit = 1;
                    break;
            }
        }

        /* before we get the new 'cur', store cur in prev */
        prev = cur;
        cur = current_field(my_form);
        vrmr_fatal_if_null(cur);

        /* draw and set cursor */
        wrefresh(ib_win);
        pos_form_cursor(my_form);
    }

    /* save here: errors printed in filter_save() */
    (void)filter_save(filter);

    unpost_form(my_form);
    free_form(my_form);
    for (i = 0; i < FiFi.n_fields; i++) {
        free_field(FiFi.fields[i]);
    }
    free(FiFi.fields);
    del_panel(my_panels[0]);
    destroy_win(ib_win);
    update_panels();
    doupdate();
    return(0);
}
