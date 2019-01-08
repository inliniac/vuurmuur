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
    PANEL *panel[1];
    WINDOW *win;
    FIELD **fields;
    FORM *form;
    size_t n_fields;
} syssec_ctx;

static int edit_sysopt_init(
        struct vrmr_config *conf, int height, int width, int starty, int startx)
{
    int retval = 0, rows, cols;
    size_t i = 0;

    syssec_ctx.n_fields = 2;
    syssec_ctx.fields =
            (FIELD **)calloc(syssec_ctx.n_fields + 1, sizeof(FIELD *));

    // create the fields
    syssec_ctx.fields[0] = new_field(1, 1, 1, 2, 0, 1); // syn-flood
    set_field_buffer_wrap(syssec_ctx.fields[0], 1, "s");
    set_field_buffer_wrap(
            syssec_ctx.fields[0], 0, conf->protect_syncookie ? "X" : " ");

    syssec_ctx.fields[1] = new_field(1, 1, 3, 2, 0, 1); // echo-broadcast
    set_field_buffer_wrap(syssec_ctx.fields[1], 1, "e");
    set_field_buffer_wrap(
            syssec_ctx.fields[1], 0, conf->protect_echobroadcast ? "X" : " ");

    syssec_ctx.fields[2] = NULL;

    syssec_ctx.win = create_newwin(height, width, starty, startx,
            gettext("System Protection"), vccnf.color_win);
    syssec_ctx.panel[0] = new_panel(syssec_ctx.win);

    for (i = 0; i < syssec_ctx.n_fields; i++) {
        // set field options
        set_field_back(syssec_ctx.fields[i], vccnf.color_win);
        field_opts_off(syssec_ctx.fields[i], O_AUTOSKIP);
        // set status to false
        set_field_status(syssec_ctx.fields[i], FALSE);
    }

    // Create the form and post it
    syssec_ctx.form = new_form(syssec_ctx.fields);
    // Calculate the area required for the form
    scale_form(syssec_ctx.form, &rows, &cols);
    keypad(syssec_ctx.win, TRUE);
    // Set main window and sub window
    set_form_win(syssec_ctx.form, syssec_ctx.win);
    set_form_sub(syssec_ctx.form, derwin(syssec_ctx.win, rows, cols, 1, 2));

    post_form(syssec_ctx.form);

    // print labels
    mvwprintw(syssec_ctx.win, 2, 3, "[");
    mvwprintw(syssec_ctx.win, 2, 5, "]");
    mvwprintw(syssec_ctx.win, 2, 8, gettext("Syn-flood protection"));

    mvwprintw(syssec_ctx.win, 4, 3, "[");
    mvwprintw(syssec_ctx.win, 4, 5, "]");
    mvwprintw(syssec_ctx.win, 4, 8, gettext("Echo-broadcast protect"));

    return (retval);
}

/*
    return codes:
        -1 error
        0: no changes
        1: changes
*/
static int edit_sysopt_save(struct vrmr_config *conf)
{
    int retval = 0;
    size_t i = 0;

    /* check for changed fields */
    for (i = 0; i < syssec_ctx.n_fields; i++) {
        // we only act if a field is changed
        if (field_status(syssec_ctx.fields[i]) == TRUE) {
            vrmr_debug(HIGH, "field[%d] was changed.", (int)i);

            /*
                handle only 's' (syn-flood) and 'e' (echo-broadcast) fields
            */
            if (strncmp(field_buffer(syssec_ctx.fields[i], 1), "s", 1) == 0) {
                if (strncmp(field_buffer(syssec_ctx.fields[i], 0), "X", 1) == 0)
                    conf->protect_syncookie = 1;
                else
                    conf->protect_syncookie = 0;

                vrmr_audit("'protect against synflood' %s '%s'.",
                        STR_IS_NOW_SET_TO,
                        conf->protect_syncookie ? STR_YES : STR_NO);

                retval = 1;
            } else if (strncmp(field_buffer(syssec_ctx.fields[i], 1), "e", 1) ==
                       0) {
                if (strncmp(field_buffer(syssec_ctx.fields[i], 0), "X", 1) == 0)
                    conf->protect_echobroadcast = 1;
                else
                    conf->protect_echobroadcast = 0;

                vrmr_audit("'protect against echo broadcast' %s '%s'.",
                        STR_IS_NOW_SET_TO,
                        conf->protect_echobroadcast ? STR_YES : STR_NO);

                retval = 1;
            }
        }
    }

    return (retval);
}

static int edit_sysopt_destroy(void)
{
    size_t i = 0;

    // Un post form and free the memory
    unpost_form(syssec_ctx.form);
    free_form(syssec_ctx.form);
    for (i = 0; i < syssec_ctx.n_fields; i++) {
        free_field(syssec_ctx.fields[i]);
    }
    free(syssec_ctx.fields);

    del_panel(syssec_ctx.panel[0]);
    destroy_win(syssec_ctx.win);

    return (0);
}

int edit_sysopt(struct vrmr_config *conf)
{
    int ch, retval = 0, quit = 0;
    int height, width, startx, starty, max_height, max_width;
    FIELD *cur = NULL, *prev = NULL;

    getmaxyx(stdscr, max_height, max_width);

    height = 18;
    width = 76;

    startx = (max_width - width) / 2;
    starty = (max_height - height) / 2;

    curs_set(0);

    edit_sysopt_init(conf, height, width, starty, startx);
    cur = current_field(syssec_ctx.form);
    update_panels();
    doupdate();

    // Loop through to get user requests
    while (quit == 0) {
        draw_field_active_mark(cur, prev, syssec_ctx.win, syssec_ctx.form,
                vccnf.color_win_mark | A_BOLD);

        ch = wgetch(syssec_ctx.win);

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
                form_driver(syssec_ctx.form, REQ_NEXT_FIELD);
                // Go to the end of the present buffer
                // Leaves nicely at the last character
                form_driver(syssec_ctx.form, REQ_END_LINE);
                break;

            case KEY_UP:
                // Go to previous field
                form_driver(syssec_ctx.form, REQ_PREV_FIELD);
                form_driver(syssec_ctx.form, REQ_END_LINE);
                break;

            case 127:
            case KEY_BACKSPACE:
                form_driver(syssec_ctx.form, REQ_PREV_CHAR);
                form_driver(syssec_ctx.form, REQ_DEL_CHAR);
                form_driver(syssec_ctx.form, REQ_END_LINE);
                break;

            case KEY_DC:
                form_driver(syssec_ctx.form, REQ_PREV_CHAR);
                form_driver(syssec_ctx.form, REQ_DEL_CHAR);
                form_driver(syssec_ctx.form, REQ_END_LINE);
                break;

            case 32: {
                if (strncmp(field_buffer(cur, 1), "s", 1) == 0 ||
                        strncmp(field_buffer(cur, 1), "e", 1) == 0) {
                    if (strncasecmp(field_buffer(cur, 0), "X", 1) == 0) {
                        set_field_buffer_wrap(cur, 0, " ");
                    } else {
                        set_field_buffer_wrap(cur, 0, "X");
                    }
                } else {
                    form_driver(syssec_ctx.form, ch);
                }
                break;
            }

            case KEY_F(12):
            case 'h':
            case 'H':
            case '?':
                print_help(":[VUURMUUR:CONFIG:SYSSEC]:");
                break;
        }

        prev = cur;
        cur = current_field(syssec_ctx.form);
    }

    // save the field to the conf struct
    if (edit_sysopt_save(conf) < 0)
        retval = -1;

    /* write configfile */
    if (retval == 0) {
        if (vrmr_write_configfile(conf->configfile, conf) < 0) {
            vrmr_error(-1, VR_ERR, gettext("writing configfile failed."));
            retval = -1;
        }
    }

    // cleanup
    edit_sysopt_destroy();
    curs_set(1);
    update_panels();
    doupdate();

    return (retval);
}
