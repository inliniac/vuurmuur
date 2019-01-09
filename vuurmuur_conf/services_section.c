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
    MENU *menu;
    ITEM **items;
    ITEM *top, *bot;
    PANEL *panel_top[1];
    PANEL *panel_bot[1];
    WINDOW *win_top;
    WINDOW *win_bot;

    int sl_xre; /**< x right edge */
    int sl_yle; /**< y lower edge */
    unsigned int list_items;

    struct edit {
        WINDOW *win;
        PANEL *panel[1];

        FIELD **fields;
        size_t n_fields;
        FORM *form;

        /* portrange list */
        MENU *menu;
        ITEM **items;
        size_t n_items;
        ITEM *top, *bot;
        PANEL *panel_top[1];
        PANEL *panel_bot[1];
        WINDOW *win_top;
        WINDOW *win_bot;

        struct vrmr_list item_list;
        struct vrmr_list item_number_list;

        int se_xre; /**< x right edge */
        int se_yle; /**< y lower edge */
    } edit_service;

    struct edit edit_service_port;

    char comment[512];
} sersec_ctx;

/*  edit_serv_portranges_new_validate

    Validates the new portrange and inserts it into the list at the right place.

    Returncodes:
        0: ok
        -1: error
*/
static int edit_serv_portranges_new_validate(struct vrmr_ctx *vctx,
        struct vrmr_service *ser_ptr, const struct vrmr_portdata *in_port_ptr)
{
    struct vrmr_list_node *d_node = NULL;
    struct vrmr_portdata *portlist_ptr = NULL;
    struct vrmr_portdata *port_ptr = NULL;
    int insert_now = 0;
    int insert_append = 0;

    /* safety */
    vrmr_fatal_if_null(in_port_ptr);
    vrmr_fatal_if_null(ser_ptr);

    /* check the protocol */
    vrmr_fatal_if(in_port_ptr->protocol == 0 || in_port_ptr->protocol > 255);

    port_ptr = calloc(1, sizeof(*port_ptr));
    vrmr_fatal_alloc("calloc", port_ptr);
    memcpy(port_ptr, in_port_ptr, sizeof(struct vrmr_portdata));

    /* if low and high are the same, only src is enough */
    if (port_ptr->src_low == port_ptr->src_high)
        port_ptr->src_high = 0;

    if (port_ptr->dst_low == port_ptr->dst_high) {
        if (port_ptr->protocol != 1)
            port_ptr->dst_high = 0;
    }

    /*  check the ports

        for tcp and udp
    */
    if (port_ptr->protocol == 6 || port_ptr->protocol == 17) {
        /* no value is allowed to be higher than 65535, src_low and dst_low are
         * not allowed to be smaller than 1 */
        if (port_ptr->src_low > 65535 || port_ptr->src_high > 65535 ||
                port_ptr->dst_low > 65535 || port_ptr->dst_high > 65535 ||
                port_ptr->src_low < 1 || port_ptr->dst_low < 1) {
            /* this is an error because of wrong user input, so no function name
             */
            vrmr_error(-1, VR_ERR,
                    gettext("one of the ports is too low or too high. Valid "
                            "port values for tcp and udp are 1-65535."));
            free(port_ptr);
            return (-1);
        }

        /* check if the ranges are ok */
        if ((port_ptr->src_low > port_ptr->src_high &&
                    port_ptr->src_high > 0) ||
                (port_ptr->dst_low > port_ptr->dst_high &&
                        port_ptr->dst_high > 0)) {
            /* this is an error because of wrong user input, so no function name
             */
            vrmr_error(-1, VR_ERR,
                    gettext("please make sure that the 'high'-port is actually "
                            "higher than the 'low'-port."));
            free(port_ptr);
            return (-1);
        }
    }
    /*
        for icmp
    */
    else if (port_ptr->protocol == 1) {
        if (port_ptr->dst_low > 255 || port_ptr->dst_high > 16) {
            /* this is an error because of wrong user input, so no function name
             */
            vrmr_error(-1, VR_ERR,
                    gettext("one of the values is too high. Valid icmp-types "
                            "values are 1-255 (note that 41-255 are reserved). "
                            "Valid icmp-codes are 0-16 (note that not all "
                            "combinations of types and codes are valid. See "
                            "http://www.iana.org/assignments/icmp-parameters "
                            "for details)."));
            free(port_ptr);
            return (-1);
        }
    }

    /* in an empty list we insert now */
    if (ser_ptr->PortrangeList.len == 0) {
        insert_now = 1;
    } else {
        /* else set the initial d_node */
        vrmr_fatal_if_null(ser_ptr->PortrangeList.top);
        d_node = ser_ptr->PortrangeList.top;
    }

    /* now look for the place in the list to insert */
    while (!insert_now) {
        vrmr_fatal_if_null(d_node);
        vrmr_fatal_if_null(d_node->data);
        portlist_ptr = d_node->data;

        if (port_ptr->protocol < portlist_ptr->protocol)
            insert_now = 1;

        if (!(port_ptr->protocol == 1 || port_ptr->protocol == 6 ||
                    port_ptr->protocol == 17)) {
            if (port_ptr->protocol == portlist_ptr->protocol) {
                /* this is an error because of wrong user input, so no function
                 * name */
                vrmr_error(-1, VR_ERR,
                        gettext("only one protocol %d portrange is allowed."),
                        port_ptr->protocol);
                free(port_ptr);
                return (-1);
            }
        }

        if (!insert_now) {
            vrmr_debug(HIGH, "don't insert at this run.");

            if (vrmr_list_node_is_bot(d_node)) {
                /* if we reach the bot, insert now */
                insert_now = 1;
                insert_append = 1;
                break;
            } else {
                d_node = d_node->next;
            }
        }
    }

    /*
        insert now
    */
    if (insert_now) {
        /*  for appending at the bot we call vrmr_list_append because
           vrmr_list_insert_before is unable to insert at the bot.
        */
        if (!insert_append) {
            vrmr_fatal_if(vrmr_list_insert_before(&ser_ptr->PortrangeList,
                                  d_node, port_ptr) == NULL);
        } else {
            vrmr_fatal_if(vrmr_list_append(&ser_ptr->PortrangeList, port_ptr) ==
                          NULL);
        }
        port_ptr = NULL; /* now owned by ser_ptr->PortrangeList */

        ser_ptr->status = VRMR_ST_CHANGED;

        /* save the portranges */
        if (vrmr_services_save_portranges(vctx, ser_ptr) < 0) {
            vrmr_error(-1, VR_ERR, gettext("saving the portranges failed"));
            return (-1);
        }
    }

    return (0);
}

struct {
    FIELD *src_lo_fld, *src_hi_fld, *dst_lo_fld, *dst_hi_fld;
} TCPUDPSec;

static void edit_tcpudp(struct vrmr_portdata *port_ptr)
{
    WINDOW *new_portrange_win;
    PANEL *my_panels[1];
    FIELD **fields, *cur = NULL, *prev = NULL;
    FORM *my_form;
    int height, width, startx = 0, starty = 0, max_height, max_width, ch, i,
                       rows, cols, quit = 0;
    int not_defined = 0, field_num = 0;
    char port_str[6] = ""; /* 5 (65535) + \0 = 6 */

    /* safety */
    vrmr_fatal_if_null(port_ptr);

    /* clear */
    memset(&TCPUDPSec, 0, sizeof(TCPUDPSec));

    /* set window dimentions */
    height = 8;
    width = 44;
    getmaxyx(stdscr, max_height, max_width);
    /* place in the center of the screen */
    starty = (max_height - height) / 2;
    startx = (max_width - width) / 2;

    /* create window and panel */
    if (port_ptr->protocol == 6)
        new_portrange_win = create_newwin(height, width, starty, startx,
                gettext("TCP Portrange"), vccnf.color_win);
    else
        new_portrange_win = create_newwin(height, width, starty, startx,
                gettext("UDP Portrange"), vccnf.color_win);
    vrmr_fatal_if_null(new_portrange_win);
    my_panels[0] = new_panel(new_portrange_win);
    vrmr_fatal_if_null(my_panels[0]);
    keypad(new_portrange_win, TRUE);

    fields = (FIELD **)calloc(4 + 1, sizeof(FIELD *));
    vrmr_fatal_alloc("calloc", fields);

    TCPUDPSec.src_lo_fld = (fields[field_num++] = new_field(1, 5, 3, 3, 0, 0));
    if (port_ptr->src_low > 0 && port_ptr->src_low <= 65535) {
        snprintf(port_str, sizeof(port_str), "%d", port_ptr->src_low);
        set_field_buffer_wrap(TCPUDPSec.src_lo_fld, 0, port_str);
    }

    TCPUDPSec.src_hi_fld = (fields[field_num++] = new_field(1, 5, 3, 11, 0, 0));
    if (port_ptr->src_high > 0 && port_ptr->src_high <= 65535) {
        snprintf(port_str, sizeof(port_str), "%d", port_ptr->src_high);
        set_field_buffer_wrap(TCPUDPSec.src_hi_fld, 0, port_str);
    }

    TCPUDPSec.dst_lo_fld = (fields[field_num++] = new_field(1, 5, 3, 24, 0, 0));
    if (port_ptr->dst_low > 0 && port_ptr->dst_low <= 65535) {
        snprintf(port_str, sizeof(port_str), "%d", port_ptr->dst_low);
        set_field_buffer_wrap(TCPUDPSec.dst_lo_fld, 0, port_str);
    }

    TCPUDPSec.dst_hi_fld = (fields[field_num++] = new_field(1, 5, 3, 32, 0, 0));
    if (port_ptr->dst_high > 0 && port_ptr->dst_high <= 65535) {
        snprintf(port_str, sizeof(port_str), "%d", port_ptr->dst_high);
        set_field_buffer_wrap(TCPUDPSec.dst_hi_fld, 0, port_str);
    }

    vrmr_fatal_if(field_num != 4);

    for (i = 0; i < 4; i++) {
        set_field_back(fields[i], vccnf.color_win_rev);
        field_opts_off(fields[i], O_AUTOSKIP);
        set_field_status(fields[i], FALSE);
    }

    /* create form */
    my_form = new_form(fields);
    scale_form(my_form, &rows, &cols);
    set_form_win(my_form, new_portrange_win);
    set_form_sub(my_form, derwin(new_portrange_win, rows, cols, 1, 2));
    post_form(my_form);

    mvwprintw(new_portrange_win, 2, 5, gettext("Source"));
    mvwprintw(new_portrange_win, 3, 5, gettext("Low"));
    mvwprintw(new_portrange_win, 3, 13, gettext("High"));

    mvwprintw(new_portrange_win, 4, 21, "->");

    mvwprintw(new_portrange_win, 2, 26, gettext("Destination"));
    mvwprintw(new_portrange_win, 3, 26, gettext("Low"));
    mvwprintw(new_portrange_win, 3, 34, gettext("High"));

    pos_form_cursor(my_form);

    /* go to the 3rd field, so we focus on dst_low */
    form_driver(my_form, REQ_NEXT_FIELD);
    form_driver(my_form, REQ_NEXT_FIELD);

    cur = current_field(my_form);

    update_panels();
    doupdate();

    while (quit == 0) {
        draw_field_active_mark(cur, prev, new_portrange_win, my_form,
                vccnf.color_win_mark | A_BOLD);

        if (cur == TCPUDPSec.src_lo_fld)
            status_print(status_win, gettext("Enter a portnumber (1-65535)."));
        else if (cur == TCPUDPSec.src_hi_fld)
            status_print(
                    status_win, gettext("Enter a portnumber (1-65535). This is "
                                        "the high-end of the range."));
        else if (cur == TCPUDPSec.dst_lo_fld)
            status_print(status_win, gettext("Enter a portnumber (1-65535)."));
        else if (cur == TCPUDPSec.dst_hi_fld)
            status_print(
                    status_win, gettext("Enter a portnumber (1-65535). This is "
                                        "the high-end of the range."));

        ch = wgetch(new_portrange_win);

        not_defined = 0;

        if (nav_field_simpletext(my_form, ch) < 0)
            not_defined = 1;

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

                    form_driver(my_form, REQ_NEXT_FIELD);
                    form_driver(my_form, REQ_END_LINE);
                    break;
                case KEY_UP:
                    // Go to previous field
                    form_driver(my_form, REQ_PREV_FIELD);
                    form_driver(my_form, REQ_END_LINE);
                    break;

                case KEY_BACKSPACE:
                    form_driver(my_form, REQ_PREV_CHAR);
                    form_driver(my_form, REQ_DEL_CHAR);
                    form_driver(my_form, REQ_END_LINE);
                    break;

                case 127:
                case KEY_DC:
                    form_driver(my_form, REQ_PREV_CHAR);
                    form_driver(my_form, REQ_DEL_CHAR);
                    form_driver(my_form, REQ_END_LINE);
                    break;

                case KEY_F(12):
                case 'h':
                case 'H':
                case '?':
                    print_help(":[VUURMUUR:SERVICE:EDIT:PORTRANGE:TCPUDP]:");
                    break;

                default:
                    // If this is a normal character, it gets printed
                    form_driver(my_form, ch);
                    break;
            }
        }

        /* set current field to prev */
        prev = cur;
        cur = current_field(my_form);

        /* draw and set cursor */
        wrefresh(new_portrange_win);
        pos_form_cursor(my_form);
    }

    /* store input in pointer */
    port_ptr->src_low = atoi(field_buffer(TCPUDPSec.src_lo_fld, 0));
    port_ptr->src_high = atoi(field_buffer(TCPUDPSec.src_hi_fld, 0));
    port_ptr->dst_low = atoi(field_buffer(TCPUDPSec.dst_lo_fld, 0));
    port_ptr->dst_high = atoi(field_buffer(TCPUDPSec.dst_hi_fld, 0));

    /* cleanup */
    unpost_form(my_form);
    free_form(my_form);
    for (i = 0; i < 4; i++) {
        free_field(fields[i]);
    }
    free(fields);
    del_panel(my_panels[0]);
    destroy_win(new_portrange_win);
    status_print(status_win, gettext("Ready."));
    update_panels();
    doupdate();
}

/*  icmp_choose_type

    returns:
        selected icmptype or -1 on error
*/
static int icmp_choose_type(void)
{
    WINDOW *win = NULL;
    PANEL *panel[1];
    MENU *menu = NULL;
    ITEM **items;
    ITEM *cur = NULL;
    size_t n_items = 0, i = 0;
    int retval = 0, height = 0, width = 0, max_height = 0, max_width = 0,
        startx = 0, starty = 0, quit = 0, ch = 0;
    char **itemnames;
    char **itemnumbers;
    char *name = NULL;
    size_t name_size = 32; /* max size of icmp name */
    size_t type_size = 4;  /* max size of icmp type string */

    int icmp_type = 0, icmp_type_has_code = 0, icmp_type_num = 0;
    size_t type_cnt = 0;

    /* get screensize */
    getmaxyx(stdscr, max_height, max_width);

    /* count the number of icmp types (maybe this could be a fixed number?) */
    while (vrmr_list_icmp_types(
                   &icmp_type, &icmp_type_has_code, &icmp_type_num) == 1)
        n_items++;

    /* get memory */
    items = (ITEM **)calloc(n_items + 1, sizeof(ITEM *));
    vrmr_fatal_alloc("calloc", items);
    itemnames = calloc(n_items + 1, 32);
    vrmr_fatal_alloc("calloc", itemnames);
    itemnumbers = calloc(n_items + 1, 32);
    vrmr_fatal_alloc("calloc", itemnumbers);

    /* init */
    icmp_type_num = 0;
    while (vrmr_list_icmp_types(
                   &icmp_type, &icmp_type_has_code, &icmp_type_num) == 1) {
        /* set itemnames and itemnumbers */
        name = malloc(name_size);
        vrmr_fatal_alloc("malloc", name);
        vrmr_fatal_if(vrmr_get_icmp_name_short(
                              icmp_type, -1, name, name_size, 0) < 0);
        itemnames[type_cnt] = name;

        /* now the typenumber string */
        name = malloc(type_size);
        vrmr_fatal_alloc("malloc", name);
        snprintf(name, type_size, "%d", icmp_type);
        itemnumbers[type_cnt] = name;

        items[type_cnt] = new_item(itemnumbers[type_cnt], itemnames[type_cnt]);
        vrmr_fatal_if_null(items[type_cnt]);

        /* update cnt */
        type_cnt++;
    }
    vrmr_fatal_if(type_cnt != n_items);
    /* terminate */
    items[type_cnt] = (ITEM *)NULL;

    menu = new_menu((ITEM **)items);
    vrmr_fatal_if_null(menu);

    /* set window dimentions */
    height = (int)n_items + 4;
    if (height > (max_height - 6))
        height = max_height - 6;
    width = 32 + 8 + 2;

    /* center of the screen */
    startx = (max_width - width) / 2;
    starty = (max_height - height) / 2;

    win = newwin(height, width, starty, startx);
    vrmr_fatal_if_null(win);
    wbkgd(win, vccnf.color_win);
    keypad(win, TRUE);
    box(win, 0, 0);
    print_in_middle(win, 1, 0, width, gettext("ICMP Types"), vccnf.color_win);
    wrefresh(win);
    panel[0] = new_panel(win);
    vrmr_fatal_if_null(panel[0]);
    update_panels();

    set_menu_win(menu, win);
    set_menu_sub(menu, derwin(win, height - 4, width - 2, 3, 1));
    set_menu_format(menu, height - 4, 1);

    mvwaddch(win, 2, 0, ACS_LTEE);
    mvwhline(win, 2, 1, ACS_HLINE, width - 2);
    mvwaddch(win, 2, width - 1, ACS_RTEE);

    set_menu_back(menu, vccnf.color_win);
    set_menu_fore(menu, vccnf.color_win_rev);
    post_menu(menu);
    doupdate();

    while (quit == 0) {
        ch = wgetch(win);
        switch (ch) {
            case KEY_DOWN:
                menu_driver(menu, REQ_DOWN_ITEM);
                break;

            case KEY_UP:
                menu_driver(menu, REQ_UP_ITEM);
                break;

            case KEY_RIGHT:
            case 32: /* space */
            case 10: /* enter */
            {
                cur = current_item(menu);
                vrmr_fatal_if_null(cur);
                retval = atoi((char *)item_name(cur));

                /* quit */
                quit = 1;
                break;
            }

            case 27:
            case KEY_F(10):
            case 'q':
            case 'Q':

                quit = 1;
                retval = -1;
                break;
        }
    }

    /* cleanup */
    unpost_menu(menu);
    free_menu(menu);
    for (i = 0; i < n_items; ++i)
        free_item(items[i]);
    free(items);
    free(itemnumbers);
    free(itemnames);
    del_panel(panel[0]);
    destroy_win(win);
    update_panels();
    doupdate();
    return (retval);
}

static int icmp_choose_code(const int icmp_type)
{
    WINDOW *win = NULL;
    PANEL *panel[1];
    MENU *menu = NULL;
    ITEM **items;
    ITEM *cur = NULL;
    size_t n_items = 0, i = 0;

    int retval = 0, height = 0, width = 0, max_height = 0, max_width = 0,
        startx = 0, starty = 0, quit = 0, ch = 0;

    char **itemnames;
    char **itemnumbers;
    char *name = NULL;
    size_t name_size = 32;
    size_t code_size = 4; /* max size of icmp-number code string */

    int icmp_code = 0, icmp_code_num = 0;
    size_t code_cnt = 0;

    /* get screensize */
    getmaxyx(stdscr, max_height, max_width);

    /* count the number of icmp types (maybe this could be a fixed number?) */
    while (vrmr_list_icmp_codes(icmp_type, &icmp_code, &icmp_code_num) == 1)
        n_items++;

    if (n_items == 0) {
        vrmr_warning(VR_WARN,
                gettext("no ICMP-codes with selected ICMP-type (%d)."),
                icmp_type);
        return (0);
    }

    /* get memory */
    items = (ITEM **)calloc(n_items + 1, sizeof(ITEM *));
    vrmr_fatal_alloc("calloc", items);
    itemnames = calloc(n_items + 1, 32);
    vrmr_fatal_alloc("calloc", itemnames);
    itemnumbers = calloc(n_items + 1, 32);
    vrmr_fatal_alloc("calloc", itemnumbers);

    /* init */
    icmp_code_num = 0;
    while (vrmr_list_icmp_codes(icmp_type, &icmp_code, &icmp_code_num) == 1) {
        /* set itemnames and itemnumbers */
        name = malloc(name_size);
        vrmr_fatal_alloc("malloc", name);

        vrmr_fatal_if(vrmr_get_icmp_name_short(
                              icmp_type, icmp_code, name, name_size, 1) < 0);
        itemnames[code_cnt] = name;

        name = malloc(code_size);
        vrmr_fatal_alloc("malloc", name);
        snprintf(name, code_size, "%d", icmp_code);
        itemnumbers[code_cnt] = name;

        items[code_cnt] = new_item(itemnumbers[code_cnt], itemnames[code_cnt]);
        vrmr_fatal_if_null(items[code_cnt]);

        /* update cnt */
        code_cnt++;
    }
    vrmr_fatal_if(code_cnt != n_items);
    /* terminate */
    items[n_items] = (ITEM *)NULL;

    menu = new_menu((ITEM **)items);
    vrmr_fatal_alloc("calloc", items);

    /* set window dimentions */
    height = (int)n_items + 4;
    if (height > (max_height - 6))
        height = max_height - 6;
    width = 32 + 8 + 2;
    startx = (max_width - width) / 2;
    starty = (max_height - height) / 2;

    /* create win & panel & set attribs */
    win = newwin(height, width, starty, startx);
    vrmr_fatal_if_null(win);
    panel[0] = new_panel(win);
    vrmr_fatal_if_null(panel[0]);
    box(win, 0, 0);
    wbkgd(win, vccnf.color_win_rev);
    keypad(win, TRUE);
    print_in_middle(
            win, 1, 0, width, gettext("ICMP Codes"), vccnf.color_win_rev);
    wrefresh(win);
    update_panels();

    set_menu_win(menu, win);
    set_menu_sub(menu, derwin(win, height - 4, width - 2, 3, 1));
    set_menu_format(menu, height - 4, 1);

    mvwaddch(win, 2, 0, ACS_LTEE);
    mvwhline(win, 2, 1, ACS_HLINE, width - 2);
    mvwaddch(win, 2, width - 1, ACS_RTEE);

    set_menu_back(menu, vccnf.color_win_rev);
    set_menu_fore(menu, vccnf.color_win);
    post_menu(menu);
    doupdate();

    while (quit == 0) {
        ch = wgetch(win);
        switch (ch) {
            case KEY_DOWN:
                menu_driver(menu, REQ_DOWN_ITEM);
                break;
            case KEY_UP:
                menu_driver(menu, REQ_UP_ITEM);
                break;

            case KEY_RIGHT:
            case 32: // space
            case 10: // enter
            {
                cur = current_item(menu);
                vrmr_fatal_if_null(cur);
                retval = atoi((char *)item_name(cur));

                /* quit */
                quit = 1;
                break;
            }

            case 27:
            case KEY_F(10):
            case 'q':
            case 'Q':
                quit = 1;
                retval = -1;
                break;
        }
    }

    // cleanup
    unpost_menu(menu);
    free_menu(menu);
    for (i = 0; i < n_items; ++i)
        free_item(items[i]);
    free(items);
    free(itemnumbers);
    free(itemnames);
    del_panel(panel[0]);
    destroy_win(win);
    update_panels();
    doupdate();
    return (retval);
}

struct {
    FIELD *typefld, *codefld;
} ICMPSec;

static void edit_icmp(struct vrmr_portdata *port_ptr)
{
    WINDOW *new_portrange_win;
    PANEL *my_panels[1];
    FIELD **fields;
    FORM *my_form;
    int height, width, startx, starty, max_height, max_width, ch, i, rows, cols,
            result = 0, quit = 0;
    char icmp_type[4] = "", icmp_code[4] = "", port_str[4] = "";
    FIELD *cur_field = NULL, *prev_field = NULL;

    /* safety */
    vrmr_fatal_if_null(port_ptr);

    /* set window dimentions */
    height = 7;
    width = 24;
    getmaxyx(stdscr, max_height, max_width);
    /* place in the center of the screen */
    starty = (max_height - height) / 2;
    startx = (max_width - width) / 2;

    /* create window and panel */
    new_portrange_win = create_newwin(
            height, width, starty, startx, "ICMP", vccnf.color_win);
    vrmr_fatal_if_null(new_portrange_win);
    my_panels[0] = new_panel(new_portrange_win);
    vrmr_fatal_if_null(my_panels[0]);
    keypad(new_portrange_win, TRUE);

    fields = (FIELD **)calloc(2 + 1, sizeof(FIELD *));
    vrmr_fatal_alloc("calloc", fields);

    ICMPSec.typefld = (fields[0] = new_field(1, 3, 2, 5, 0, 0));
    if (port_ptr->dst_low >= 0 && port_ptr->dst_low <= 255) {
        snprintf(port_str, sizeof(port_str), "%d", port_ptr->dst_low);
        set_field_buffer_wrap(ICMPSec.typefld, 0, port_str);
    }

    ICMPSec.codefld = (fields[1] = new_field(1, 3, 2, 12, 0, 0));
    if (port_ptr->dst_high >= 0 && port_ptr->dst_high <= 16) {
        snprintf(port_str, sizeof(port_str), "%d", port_ptr->dst_high);
        set_field_buffer_wrap(ICMPSec.codefld, 0, port_str);
    }

    for (i = 0; i < 2; i++) {
        set_field_back(fields[i], vccnf.color_win_rev);
        field_opts_off(fields[i], O_AUTOSKIP);
        set_field_status(fields[i], FALSE);
    }

    // create form
    my_form = new_form(fields);
    scale_form(my_form, &rows, &cols);
    set_form_win(my_form, new_portrange_win);
    set_form_sub(my_form, derwin(new_portrange_win, rows, cols, 1, 2));
    post_form(my_form);

    mvwprintw(new_portrange_win, 2, 6, gettext("Type"));
    mvwprintw(new_portrange_win, 2, 13, gettext("Code"));

    pos_form_cursor(my_form);
    cur_field = current_field(my_form);

    update_panels();
    doupdate();

    while (quit == 0) // F10 exits
    {
        draw_field_active_mark(cur_field, prev_field, new_portrange_win,
                my_form, vccnf.color_win_mark | A_BOLD);

        if (cur_field == ICMPSec.typefld)
            status_print(
                    status_win, gettext("Press SPACE to select an ICMP-type."));
        else if (cur_field == ICMPSec.codefld)
            status_print(
                    status_win, gettext("Press SPACE to select an ICMP-code."));

        ch = wgetch(new_portrange_win);
        switch (ch) {
            case 32: // space

                if (cur_field == ICMPSec.typefld) {
                    result = icmp_choose_type();
                    if (result >= 0) {
                        (void)snprintf(
                                icmp_type, sizeof(icmp_type), "%d", result);
                        set_field_buffer_wrap(cur_field, 0, icmp_type);
                    }
                } else {
                    (void)strlcpy(icmp_type, field_buffer(ICMPSec.typefld, 0),
                            sizeof(icmp_type));

                    result = icmp_choose_code(atoi(icmp_type));
                    if (result >= 0) {
                        (void)snprintf(icmp_code, sizeof(icmp_code), "%d",
                                (uint8_t)result);
                        set_field_buffer_wrap(cur_field, 0, icmp_code);
                    }
                }
                break;

            case KEY_DOWN:
            case 10: // enter
            case 9:  // tab

                form_driver(my_form, REQ_NEXT_FIELD);
                form_driver(my_form, REQ_END_LINE);
                break;

            case KEY_UP:

                form_driver(my_form, REQ_PREV_FIELD);
                form_driver(my_form, REQ_END_LINE);
                break;

            case KEY_BACKSPACE:
                form_driver(my_form, REQ_PREV_CHAR);
                form_driver(my_form, REQ_DEL_CHAR);
                form_driver(my_form, REQ_END_LINE);
                break;

            case 127:
            case KEY_DC:
                form_driver(my_form, REQ_PREV_CHAR);
                form_driver(my_form, REQ_DEL_CHAR);
                form_driver(my_form, REQ_END_LINE);
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
                print_help(":[VUURMUUR:SERVICE:EDIT:PORTRANGE:ICMP]:");
                break;

            default:
                /* If this is a normal character, it gets printed */
                if (isdigit(ch)) {
                    form_driver(my_form, ch);
                }
                break;
        }

        /* set current field to prev */
        prev_field = cur_field;
        cur_field = current_field(my_form);

        /* draw and set cursor */
        wrefresh(new_portrange_win);
        pos_form_cursor(my_form);
    }

    /* store input in pointer */
    port_ptr->src_low = 0;
    port_ptr->src_high = 0;
    port_ptr->dst_low = atoi(field_buffer(ICMPSec.typefld, 0));
    port_ptr->dst_high = atoi(field_buffer(ICMPSec.codefld, 0));

    // cleanup
    unpost_form(my_form);
    free_form(my_form);
    for (i = 0; i < 2; i++) {
        free_field(fields[i]);
    }
    free(fields);
    del_panel(my_panels[0]);
    destroy_win(new_portrange_win);
    status_print(status_win, gettext("Ready."));
    update_panels();
    doupdate();
}

static void create_portrange_string(
        struct vrmr_portdata *portrange_ptr, char *buf, size_t size)
{
    char proto[5] = "", src[12] = "", dst[12] = "", icmp_name[32] = "";

    if (portrange_ptr->protocol == 1) {
        strcpy(proto, "ICMP");
        snprintf(src, sizeof(src), "TYPE=%2d", portrange_ptr->dst_low);
        snprintf(dst, sizeof(dst), "CODE=%2d", portrange_ptr->dst_high);

        vrmr_get_icmp_name_short(portrange_ptr->dst_low,
                portrange_ptr->dst_high, icmp_name, sizeof(icmp_name), 0);
        snprintf(buf, size, "ICMP: T:%d, C:%d (%s)", portrange_ptr->dst_low,
                portrange_ptr->dst_high, icmp_name);
    } else if (portrange_ptr->protocol == 6)
        strcpy(proto, "TCP");
    else if (portrange_ptr->protocol == 17)
        strcpy(proto, "UDP");
    else if (portrange_ptr->protocol == 47) {
        /* no ports */
        snprintf(buf, size, "GRE");
    } else if (portrange_ptr->protocol == 50) {
        /* no ports */
        snprintf(buf, size, "ESP");
    } else if (portrange_ptr->protocol == 51) {
        /* no ports */
        snprintf(buf, size, "AH");
    } else {
        /* no ports */
        snprintf(buf, size, "Protocol=%d", portrange_ptr->protocol);
    }

    if (portrange_ptr->protocol == 6 || portrange_ptr->protocol == 17) {
        if (portrange_ptr->src_high == 0)
            snprintf(src, sizeof(src), "%d", portrange_ptr->src_low);
        else
            snprintf(src, sizeof(src), "%d:%d", portrange_ptr->src_low,
                    portrange_ptr->src_high);

        if (portrange_ptr->dst_high == 0)
            snprintf(dst, sizeof(dst), "%d", portrange_ptr->dst_low);
        else
            snprintf(dst, sizeof(dst), "%d:%d", portrange_ptr->dst_low,
                    portrange_ptr->dst_high);

        snprintf(buf, size, "%s: %s -> %s", proto, src, dst);
    }
}

static int edit_serv_portranges_new(
        struct vrmr_ctx *vctx, struct vrmr_service *ser_ptr)
{
    int retval = 0;
    char str[64] = "";

    /* select protocol setup */
    char *choice_ptr = NULL,
         *choices[] = {"TCP", "UDP", "ICMP", "GRE", "AH", "ESP", "Other"};
    size_t n_choices = 7;

    struct vrmr_portdata portrange_s = {0, 0, 0, 0, 0};
    struct vrmr_portdata *portrange_ptr = &portrange_s;

    /* safety */
    vrmr_fatal_if_null(ser_ptr);

    /* get the new portrange protocol */
    choice_ptr = selectbox(gettext("New portrange"),
            gettext("Select a Protocol"), n_choices, choices, 1, NULL);
    if (choice_ptr == NULL)
        return 0;

    if (strncmp(choice_ptr, "TCP", 3) == 0) {
        portrange_ptr->protocol = 6;
        portrange_ptr->src_low = 1024;
        portrange_ptr->src_high = 65535;
        portrange_ptr->dst_low = 0;
        portrange_ptr->dst_high = 0;

        edit_tcpudp(portrange_ptr);
    } else if (strncmp(choice_ptr, "UDP", 3) == 0) {
        portrange_ptr->protocol = 17;
        portrange_ptr->src_low = 1024;
        portrange_ptr->src_high = 65535;
        portrange_ptr->dst_low = 0;
        portrange_ptr->dst_high = 0;

        edit_tcpudp(portrange_ptr);
    } else if (strncmp(choice_ptr, "ICMP", 4) == 0) {
        portrange_ptr->protocol = 1;
        portrange_ptr->src_low = 0;
        portrange_ptr->src_high = 0;
        portrange_ptr->dst_low = 0;
        portrange_ptr->dst_high = 0;

        edit_icmp(portrange_ptr);
    } else if (strncmp(choice_ptr, "GRE", 3) == 0) {
        /* gre has no ports */
        portrange_ptr->protocol = 47;
        portrange_ptr->src_low = 0;
        portrange_ptr->src_high = 0;
        portrange_ptr->dst_low = 0;
        portrange_ptr->dst_high = 0;
    } else if (strncmp(choice_ptr, "ESP", 3) == 0) {
        /* gre has no ports */
        portrange_ptr->protocol = 50;
        portrange_ptr->src_low = 0;
        portrange_ptr->src_high = 0;
        portrange_ptr->dst_low = 0;
        portrange_ptr->dst_high = 0;
    } else if (strncmp(choice_ptr, "AH", 2) == 0) {
        /* gre has no ports */
        portrange_ptr->protocol = 51;
        portrange_ptr->src_low = 0;
        portrange_ptr->src_high = 0;
        portrange_ptr->dst_low = 0;
        portrange_ptr->dst_high = 0;
    } else if (strncmp(choice_ptr, "Other", 5) == 0) {
        char *protostr = input_box(
                4, gettext("Protocol"), gettext("Enter protocol number"));
        if (protostr != NULL) {
            int proto = atoi(protostr);
            if (proto >= 0 && proto <= 255) {
                portrange_ptr->protocol = proto;
                portrange_ptr->src_low = 0;
                portrange_ptr->src_high = 0;
                portrange_ptr->dst_low = 0;
                portrange_ptr->dst_high = 0;
            } else {
                vrmr_error(-1, VR_ERR,
                        gettext("invalid protocol. Enter a number in the range "
                                "0-255."));
                retval = -1;
            }
            free(protostr);
        }
    } else {
        vrmr_fatal("undefined protocol");
    }

    /* free the choiceptr */
    free(choice_ptr);

    if (retval == 0) {
        if (edit_serv_portranges_new_validate(vctx, ser_ptr, portrange_ptr) <
                0) {
            retval = -1;
        } else {
            retval = 1;
        }
    }

    if (retval == 1) {
        create_portrange_string(portrange_ptr, str, sizeof(str));

        /* example: "service 'X-5' has been changed: portrange 'TCP: 1024:65535
         * -> 6005' was added." */
        vrmr_audit("%s '%s' %s: %s '%s' %s.", STR_SERVICE, ser_ptr->name,
                STR_HAS_BEEN_CHANGED, STR_PORTRANGE, str, STR_HAS_BEEN_ADDED);
    }

    return (retval);
}

/*  edit_serv_portranges_edit

    Edit a portrange at place.

    Returncodes:
        -1: error
         0: ok, not editted (e.g. GRE, which cannot be editted)
         1: ok, editted
*/
static int edit_serv_portranges_edit(int place, struct vrmr_service *ser_ptr)
{
    int i = 0;
    struct vrmr_list_node *d_node = NULL;
    struct vrmr_portdata *port_ptr = NULL;

    /* safety */
    vrmr_fatal_if_null(ser_ptr);

    /* loop trough the list until we are at 'place'. */
    for (i = 1, d_node = ser_ptr->PortrangeList.top; d_node;
            d_node = d_node->next, i++) {
        if (place != i)
            continue;

        vrmr_fatal_if_null(d_node->data);
        port_ptr = d_node->data;

        if (port_ptr->protocol == 6 || port_ptr->protocol == 17) {
            edit_tcpudp(port_ptr);
            /* return 1 so the caller knows we editted it! */
            return (1);
        } else if (port_ptr->protocol == 1) {
            edit_icmp(port_ptr);
            /* return 1 so the caller knows we editted it! */
            return (1);
        } else if (port_ptr->protocol == 41 || port_ptr->protocol == 47 ||
                   port_ptr->protocol == 50 || port_ptr->protocol == 51) {
            vrmr_warning(VR_WARN,
                    gettext("this protocol can only be removed or added."));
            return (0);
        } else {
            vrmr_warning(VR_WARN, gettext("edit of protocol %d not supported."),
                    port_ptr->protocol);
            return (0);
        }
    }

    vrmr_fatal("should be unreachable");
}

/*  edit_serv_portranges_del

    Removes a portrange at place from a service.

    Returncodes:
        -1: error
         0: not removed, user canceled
         1: removed
*/
static int edit_serv_portranges_del(
        struct vrmr_ctx *vctx, int place, struct vrmr_service *ser_ptr)
{
    int i = 0;
    struct vrmr_list_node *d_node = NULL;
    char str[64] = "";
    struct vrmr_portdata *portrange_ptr = NULL;

    /* safety */
    vrmr_fatal_if_null(ser_ptr);

    /* get user confimation */
    if (confirm(gettext("Delete portrange"), gettext("Are you sure?"),
                vccnf.color_win_note, vccnf.color_win_note_rev | A_BOLD,
                0) == 0)
        return (0);

    /* loop trough the list until we are at 'place'. */
    for (i = 1, d_node = ser_ptr->PortrangeList.top; d_node;
            d_node = d_node->next, i++) {
        /* here we are */
        if (place != i)
            continue;

        vrmr_fatal_if_null(d_node->data);
        portrange_ptr = d_node->data;

        create_portrange_string(portrange_ptr, str, sizeof(str));

        /* remove */
        vrmr_fatal_if(
                vrmr_list_remove_node(&ser_ptr->PortrangeList, d_node) < 0);

        /* save */
        if (vrmr_services_save_portranges(vctx, ser_ptr) < 0) {
            vrmr_error(-1, VR_ERR, gettext("saving the portranges failed"));
            return (-1);
        }

        /* TRANSLATORS: example: "service 'http' has been changed: portrange
         * 'TCP: 1024:65535->80' was removed." */
        vrmr_audit("%s '%s' %s: %s '%s' %s.", STR_SERVICE, ser_ptr->name,
                STR_HAS_BEEN_CHANGED, STR_PORTRANGE, str, STR_HAS_BEEN_REMOVED);

        /* return 1 so the caller knows we removed it! */
        return (1);
    }

    vrmr_fatal("should be unreachable");
}

static void edit_serv_portranges_init(struct vrmr_service *ser_ptr)
{
    struct vrmr_list_node *d_node = NULL;
    int i = 0;
    int height = 30,
        width = 64, // max width of host_name (32) + box (2) + 4 + 16
            startx = 5, starty = 5, max_height;
    struct vrmr_portdata *portrange_ptr = NULL;

    char *port_string_ptr = NULL, *item_number_ptr = NULL, proto[5] = "",
         src[12] = "", dst[12] = "", icmp_name[32] = "";
    size_t rangestr_size = 57; /* max length of the string */
    size_t itemnr_size = 16;   /* max length of the itemnr str */

    /* safety */
    vrmr_fatal_if_null(ser_ptr);

    /* get number of items and calloc them */
    sersec_ctx.edit_service_port.n_items = ser_ptr->PortrangeList.len;

    /* get some mem for the menu items */
    sersec_ctx.edit_service_port.items = (ITEM **)calloc(
            sersec_ctx.edit_service_port.n_items + 1, sizeof(ITEM *));
    vrmr_fatal_alloc("calloc", sersec_ctx.edit_service_port.items);

    max_height = getmaxy(stdscr);
    /* get window height */
    height = (int)sersec_ctx.edit_service_port.n_items +
             8; /* 8 because: 3 above the list, 5 below */
    if ((height + 8) > max_height)
        height = max_height - 8;
    /* place on the same y as "edit service" */
    VrWinGetOffset(-1, -1, height, width, 4, sersec_ctx.edit_service.se_xre + 1,
            &starty, &startx);

    // string item list
    vrmr_list_setup(&sersec_ctx.edit_service_port.item_list, free);
    // number item list
    vrmr_list_setup(&sersec_ctx.edit_service_port.item_number_list, free);

    for (i = 0, d_node = ser_ptr->PortrangeList.top; d_node;
            d_node = d_node->next, i++) {
        vrmr_fatal_if_null(d_node->data);
        portrange_ptr = d_node->data;

        /* item number */
        item_number_ptr = malloc(itemnr_size);
        vrmr_fatal_alloc("malloc", item_number_ptr);
        snprintf(item_number_ptr, itemnr_size, "%3d", i + 1);

        /* range string */
        port_string_ptr = malloc(rangestr_size);
        vrmr_fatal_alloc("malloc", port_string_ptr);

        if (portrange_ptr->protocol == 1) {
            strcpy(proto, "ICMP");
            snprintf(src, sizeof(src), "TYPE=%2d", portrange_ptr->dst_low);
            snprintf(dst, sizeof(dst), "CODE=%2d", portrange_ptr->dst_high);

            vrmr_get_icmp_name_short(portrange_ptr->dst_low,
                    portrange_ptr->dst_high, icmp_name, sizeof(icmp_name), 0);
            snprintf(port_string_ptr, rangestr_size, "ICMP: T:%2d, C:%2d (%s)",
                    portrange_ptr->dst_low, portrange_ptr->dst_high, icmp_name);
        } else if (portrange_ptr->protocol == 6) {
            strcpy(proto, "TCP");
        } else if (portrange_ptr->protocol == 17) {
            strcpy(proto, "UDP");
        } else if (portrange_ptr->protocol == 47) {
            /* no ports */
            snprintf(port_string_ptr, rangestr_size, "GRE : %s",
                    STR_PROTO_NO_PORTS);
        } else if (portrange_ptr->protocol == 50) {
            /* no ports */
            snprintf(port_string_ptr, rangestr_size, "ESP : %s",
                    STR_PROTO_NO_PORTS);
        } else if (portrange_ptr->protocol == 51) {
            /* no ports */
            snprintf(port_string_ptr, rangestr_size, "AH  : %s",
                    STR_PROTO_NO_PORTS);
        } else {
            /* no ports */
            snprintf(port_string_ptr, rangestr_size, "%d  : %s",
                    portrange_ptr->protocol, STR_PROTO_NO_PORTS);
        }

        if (portrange_ptr->protocol == 6 || portrange_ptr->protocol == 17) {
            if (portrange_ptr->src_high == 0)
                snprintf(src, sizeof(src), "%d", portrange_ptr->src_low);
            else
                snprintf(src, sizeof(src), "%d:%d", portrange_ptr->src_low,
                        portrange_ptr->src_high);

            if (portrange_ptr->dst_high == 0)
                snprintf(dst, sizeof(dst), "%d", portrange_ptr->dst_low);
            else
                snprintf(dst, sizeof(dst), "%d:%d", portrange_ptr->dst_low,
                        portrange_ptr->dst_high);

            snprintf(port_string_ptr, rangestr_size, "%-4s: %-12s -> %-12s",
                    proto, src, dst);
        }

        /* load all into item array */
        sersec_ctx.edit_service_port.items[i] =
                new_item(item_number_ptr, port_string_ptr);
        vrmr_fatal_if_null(sersec_ctx.edit_service_port.items[i]);

        /* store in list */
        vrmr_fatal_if(vrmr_list_append(&sersec_ctx.edit_service_port.item_list,
                              port_string_ptr) == NULL);
        vrmr_fatal_if(
                vrmr_list_append(&sersec_ctx.edit_service_port.item_number_list,
                        item_number_ptr) == NULL);
    }
    sersec_ctx.edit_service_port.items[sersec_ctx.edit_service_port.n_items] =
            (ITEM *)NULL;

    if (sersec_ctx.edit_service_port.n_items > 0) {
        sersec_ctx.edit_service_port.top =
                sersec_ctx.edit_service_port.items[0];
        sersec_ctx.edit_service_port.bot =
                sersec_ctx.edit_service_port
                        .items[sersec_ctx.edit_service_port.n_items - 1];
    } else {
        sersec_ctx.edit_service_port.top = NULL;
        sersec_ctx.edit_service_port.bot = NULL;
    }

    /* create win and panel */
    sersec_ctx.edit_service_port.win = newwin(height, width, starty, startx);
    vrmr_fatal_if_null(sersec_ctx.edit_service_port.win);
    wbkgd(sersec_ctx.edit_service_port.win, vccnf.color_win);
    keypad(sersec_ctx.edit_service_port.win, TRUE);
    sersec_ctx.edit_service_port.panel[0] =
            new_panel(sersec_ctx.edit_service_port.win);
    vrmr_fatal_if_null(sersec_ctx.edit_service_port.panel[0]);
    sersec_ctx.edit_service_port.menu =
            new_menu((ITEM **)sersec_ctx.edit_service_port.items);
    vrmr_fatal_if_null(sersec_ctx.edit_service_port.menu);

    set_menu_win(sersec_ctx.edit_service_port.menu,
            sersec_ctx.edit_service_port.win);
    set_menu_sub(sersec_ctx.edit_service_port.menu,
            derwin(sersec_ctx.edit_service_port.win, height - 8, width - 2, 3,
                    1));
    set_menu_format(sersec_ctx.edit_service_port.menu, height - 8, 1);

    box(sersec_ctx.edit_service_port.win, 0, 0);
    print_in_middle(sersec_ctx.edit_service_port.win, 1, 0, width,
            STR_CPORTRANGES, vccnf.color_win);
    mvwaddch(sersec_ctx.edit_service_port.win, 2, 0, ACS_LTEE);
    mvwhline(sersec_ctx.edit_service_port.win, 2, 1, ACS_HLINE, width - 2);
    mvwaddch(sersec_ctx.edit_service_port.win, 2, width - 1, ACS_RTEE);

    set_menu_back(sersec_ctx.edit_service_port.menu, vccnf.color_win);
    set_menu_fore(sersec_ctx.edit_service_port.menu, vccnf.color_win_rev);
    post_menu(sersec_ctx.edit_service_port.menu);

    mvwaddch(sersec_ctx.edit_service_port.win, height - 5, 0, ACS_LTEE);
    mvwhline(sersec_ctx.edit_service_port.win, height - 5, 1, ACS_HLINE,
            width - 2);
    mvwaddch(sersec_ctx.edit_service_port.win, height - 5, width - 1, ACS_RTEE);

    mvwprintw(sersec_ctx.edit_service_port.win, height - 4, 2, "<INS> %s",
            STR_NEW);
    mvwprintw(sersec_ctx.edit_service_port.win, height - 3, 2, "<DEL> %s",
            STR_REMOVE);
    mvwprintw(sersec_ctx.edit_service_port.win, height - 2, 2, "<RET> %s",
            STR_EDIT);

    /* create the top and bottom fields */
    sersec_ctx.edit_service_port.win_top =
            newwin(1, 6, starty + 2, startx + width - 8);
    vrmr_fatal_if_null(sersec_ctx.edit_service_port.win_top);
    wbkgd(sersec_ctx.edit_service_port.win_top, vccnf.color_win);
    sersec_ctx.edit_service_port.panel_top[0] =
            new_panel(sersec_ctx.edit_service_port.win_top);
    /* TRANSLATORS: max 4 chars */
    wprintw(sersec_ctx.edit_service_port.win_top, "(%s)", gettext("more"));
    hide_panel(sersec_ctx.edit_service_port.panel_top[0]);

    sersec_ctx.edit_service_port.win_bot =
            newwin(1, 6, starty + height - 5, startx + width - 8);
    vrmr_fatal_if_null(sersec_ctx.edit_service_port.win_bot);
    wbkgd(sersec_ctx.edit_service_port.win_bot, vccnf.color_win);
    sersec_ctx.edit_service_port.panel_bot[0] =
            new_panel(sersec_ctx.edit_service_port.win_bot);
    /* TRANSLATORS: max 4 chars */
    wprintw(sersec_ctx.edit_service_port.win_bot, "(%s)", gettext("more"));
    hide_panel(sersec_ctx.edit_service_port.panel_bot[0]);
}

static void edit_serv_portranges_destroy(void)
{
    size_t i = 0;

    // Un post form and free the memory
    unpost_menu(sersec_ctx.edit_service_port.menu);
    free_menu(sersec_ctx.edit_service_port.menu);
    for (i = 0; i < sersec_ctx.edit_service_port.n_items; i++) {
        free_item(sersec_ctx.edit_service_port.items[i]);
    }
    free(sersec_ctx.edit_service_port.items);
    del_panel(sersec_ctx.edit_service_port.panel[0]);
    destroy_win(sersec_ctx.edit_service_port.win);
    del_panel(sersec_ctx.edit_service_port.panel_top[0]);
    destroy_win(sersec_ctx.edit_service_port.win_top);
    del_panel(sersec_ctx.edit_service_port.panel_bot[0]);
    destroy_win(sersec_ctx.edit_service_port.win_bot);
    vrmr_list_cleanup(&sersec_ctx.edit_service_port.item_list);
    vrmr_list_cleanup(&sersec_ctx.edit_service_port.item_number_list);
    update_panels();
    doupdate();
}

static void edit_serv_portranges(
        struct vrmr_ctx *vctx, struct vrmr_service *ser_ptr)
{
    int quit = 0, reload = 0, ch;
    ITEM *cur = NULL;
    /* top menu */
    char *key_choices[] = {"F12", "INS", "RET", "DEL", "F10"};
    int key_choices_n = 5;
    char *cmd_choices[] = {gettext("help"), gettext("new"), gettext("edit"),
            gettext("del"), gettext("back")};
    int cmd_choices_n = 5;

    /* safety */
    vrmr_fatal_if_null(ser_ptr);

    edit_serv_portranges_init(ser_ptr);

    draw_top_menu(top_win, gettext("Edit Portrange"), key_choices_n,
            key_choices, cmd_choices_n, cmd_choices);

    while (quit == 0) {
        if (reload == 1) {
            edit_serv_portranges_destroy();
            edit_serv_portranges_init(ser_ptr);
            reload = 0;
        }

        while (quit == 0 && reload == 0) {
            if (sersec_ctx.edit_service_port.top != NULL &&
                    !item_visible(sersec_ctx.edit_service_port.top))
                show_panel(sersec_ctx.edit_service_port.panel_top[0]);
            else
                hide_panel(sersec_ctx.edit_service_port.panel_top[0]);

            if (sersec_ctx.edit_service_port.bot != NULL &&
                    !item_visible(sersec_ctx.edit_service_port.bot))
                show_panel(sersec_ctx.edit_service_port.panel_bot[0]);
            else
                hide_panel(sersec_ctx.edit_service_port.panel_bot[0]);
            update_panels();
            doupdate();

            /* restore the cursor */
            pos_menu_cursor(sersec_ctx.edit_service_port.menu);

            ch = wgetch(sersec_ctx.edit_service_port.win);
            switch (ch) {
                case 27:
                case 'q':
                case 'Q':
                case KEY_F(10): /* quit */

                    quit = 1;
                    break;

                case KEY_IC:
                case 'i':
                case 'I':

                    if (edit_serv_portranges_new(vctx, ser_ptr) == 1) {
                        reload = 1;

                        draw_top_menu(top_win, gettext("Edit Portrange"),
                                key_choices_n, key_choices, cmd_choices_n,
                                cmd_choices);
                    }
                    break;

                case KEY_DC:
                case 'd':
                case 'D': {
                    cur = current_item(sersec_ctx.edit_service_port.menu);
                    if (cur) {
                        edit_serv_portranges_del(
                                vctx, atoi(item_name(cur)), ser_ptr);
                        reload = 1;
                    }
                    break;
                }

                case 10:
                case 'e':
                case 'E': {
                    cur = current_item(sersec_ctx.edit_service_port.menu);
                    if (cur) {
                        edit_serv_portranges_edit(
                                atoi(item_name(cur)), ser_ptr);
                        reload = 1;
                        draw_top_menu(top_win, gettext("Edit Portrange"),
                                key_choices_n, key_choices, cmd_choices_n,
                                cmd_choices);
                    }
                    break;
                }

                case KEY_DOWN:
                    menu_driver(
                            sersec_ctx.edit_service_port.menu, REQ_DOWN_ITEM);
                    break;
                case KEY_UP:
                    menu_driver(sersec_ctx.edit_service_port.menu, REQ_UP_ITEM);
                    break;
                case KEY_NPAGE:
                    if (menu_driver(sersec_ctx.edit_service_port.menu,
                                REQ_SCR_DPAGE) != E_OK) {
                        while (menu_driver(sersec_ctx.edit_service_port.menu,
                                       REQ_DOWN_ITEM) == E_OK)
                            ;
                    }
                    break;
                case KEY_PPAGE:
                    if (menu_driver(sersec_ctx.edit_service_port.menu,
                                REQ_SCR_UPAGE) != E_OK) {
                        while (menu_driver(sersec_ctx.edit_service_port.menu,
                                       REQ_UP_ITEM) == E_OK)
                            ;
                    }
                    break;
                case KEY_HOME:
                    menu_driver(sersec_ctx.edit_service_port.menu,
                            REQ_FIRST_ITEM); // page up
                    break;
                case KEY_END:
                    menu_driver(sersec_ctx.edit_service_port.menu,
                            REQ_LAST_ITEM); // page down
                    break;

                case KEY_F(12):
                case 'h':
                case 'H':
                case '?':
                    print_help(":[VUURMUUR:SERVICE:EDIT:PORTRANGE]:");
                    break;
            }
        }
    }

    edit_serv_portranges_destroy();
}

struct {
    FIELD *activelabelfld, *activefld, *broadcastlabelfld, *broadcastfld,
            *commentlabelfld, *commentfld, *helperlabelfld, *helperfld,
            *norangewarningfld, *portrangesfld;
    int portranges_lines;
} ServiceSec;

static int edit_service_save(
        struct vrmr_ctx *vctx, struct vrmr_service *ser_ptr)
{
    int retval = 0, result = 0, active = 0, broadcast = 0;
    char helper[sizeof(ser_ptr->helper)] = "";
    size_t i = 0;

    // check for changed fields
    for (i = 0; i < sersec_ctx.edit_service.n_fields; i++) {
        if (field_status(sersec_ctx.edit_service.fields[i]) == FALSE)
            continue;

        /* active */
        if (sersec_ctx.edit_service.fields[i] == ServiceSec.activefld) {
            active = ser_ptr->active;

            ser_ptr->status = VRMR_ST_CHANGED;
            if (strncasecmp(field_buffer(sersec_ctx.edit_service.fields[i], 0),
                        STR_YES, StrLen(STR_YES)) == 0) {
                ser_ptr->active = 1;
            } else {
                ser_ptr->active = 0;
            }

            result = vctx->sf->tell(vctx->serv_backend, ser_ptr->name, "ACTIVE",
                    ser_ptr->active ? "Yes" : "No", 1, VRMR_TYPE_SERVICE);
            if (result < 0) {
                vrmr_error(-1, VR_ERR, gettext("saving to backend failed"));
                retval = -1;
            }

            /* example: "service 'http' has been changed: active is now set to
             * 'Yes' (was: 'No')." */
            vrmr_audit("%s '%s' %s: %s %s '%s' (%s: '%s').", STR_SERVICE,
                    ser_ptr->name, STR_HAS_BEEN_CHANGED, STR_ACTIVE,
                    STR_IS_NOW_SET_TO, ser_ptr->active ? "Yes" : "No", STR_WAS,
                    active ? "Yes" : "No");
        }
        /* broadcast */
        else if (sersec_ctx.edit_service.fields[i] == ServiceSec.broadcastfld) {
            broadcast = ser_ptr->broadcast;

            ser_ptr->status = VRMR_ST_CHANGED;

            if (strncasecmp(field_buffer(sersec_ctx.edit_service.fields[i], 0),
                        STR_YES, StrLen(STR_YES)) == 0) {
                ser_ptr->broadcast = 1;
            } else {
                ser_ptr->broadcast = 0;
            }

            result = vctx->sf->tell(vctx->serv_backend, ser_ptr->name,
                    "BROADCAST", ser_ptr->broadcast ? "Yes" : "No", 1,
                    VRMR_TYPE_SERVICE);
            if (result < 0) {
                vrmr_error(-1, VR_ERR, gettext("saving to backend failed"));
                retval = -1;
            }

            /* example: service 'samba' has been changed: broadcast is now set
             * to 'No' (was: 'Yes') */
            vrmr_audit("%s '%s' %s: %s %s '%s' (%s: '%s').", STR_SERVICE,
                    ser_ptr->name, STR_HAS_BEEN_CHANGED, STR_BROADCAST,
                    STR_IS_NOW_SET_TO, ser_ptr->broadcast ? "Yes" : "No",
                    STR_WAS, broadcast ? "Yes" : "No");
        }
        /* helper field */
        else if (sersec_ctx.edit_service.fields[i] == ServiceSec.helperfld) {
            (void)strlcpy(helper, ser_ptr->helper, sizeof(helper));

            copy_field2buf(ser_ptr->helper,
                    field_buffer(sersec_ctx.edit_service.fields[i], 0),
                    sizeof(ser_ptr->helper));

            if (vctx->sf->tell(vctx->serv_backend, ser_ptr->name, "HELPER",
                        ser_ptr->helper, 1, VRMR_TYPE_SERVICE) < 0) {
                vrmr_error(-1, VR_ERR, gettext("saving to backend failed"));
                return (-1);
            }

            /* example: service 'ftp' has been changed: protocol helper is set
             * to 'ftp' (was: 'none'). */
            vrmr_audit("%s '%s' %s: %s %s '%s' (%s: '%s').", STR_SERVICE,
                    ser_ptr->name, STR_HAS_BEEN_CHANGED, STR_PROTOHELP,
                    STR_IS_NOW_SET_TO, ser_ptr->helper, STR_WAS, helper);
        }
        /* comment */
        else if (sersec_ctx.edit_service.fields[i] == ServiceSec.commentfld) {
            result =
                    vctx->sf->tell(vctx->serv_backend, ser_ptr->name, "COMMENT",
                            field_buffer(sersec_ctx.edit_service.fields[i], 0),
                            1, VRMR_TYPE_SERVICE);
            if (result < 0) {
                vrmr_error(-1, VR_ERR, gettext("saving to backend failed"));
                retval = -1;
            }

            /* example: "service '%s' has been changed: the comment has been
             * changed." */
            vrmr_audit("%s '%s' %s: %s.", STR_SERVICE, ser_ptr->name,
                    STR_HAS_BEEN_CHANGED, STR_COMMENT_CHANGED);
        }
    }
    return (retval);
}

#define MAX_RANGES 4

static void edit_service_update_portrangesfld(struct vrmr_service *ser_ptr)
{
    struct vrmr_portdata *portrange_ptr = NULL;
    struct vrmr_list_node *d_node = NULL;
    int i;
    const int lines = ServiceSec.portranges_lines;
    int bsize = lines * 48;
    size_t x;

    if (ServiceSec.portranges_lines == 0 || bsize == 0)
        return;

    char buffer[bsize];
    memset(buffer, 0, bsize);

    for (d_node = ser_ptr->PortrangeList.top, i = 1; d_node;
            d_node = d_node->next, i++) {
        vrmr_fatal_if_null(d_node->data);
        portrange_ptr = d_node->data;

        char line[49] = "";
        int size = 49;
        size_t len;

        if (i == MAX_RANGES && ser_ptr->PortrangeList.len > MAX_RANGES) {
            snprintf(line, sizeof(line),
                    gettext("%d more portrange(s). Press F6 to manage."),
                    ser_ptr->PortrangeList.len - (i - 1));
            goto finalize;
        }

        if (portrange_ptr->protocol == 6)
            strlcat(line, "TCP : ", size);
        else if (portrange_ptr->protocol == 17)
            strlcat(line, "UDP : ", size);
        else if (portrange_ptr->protocol == 1)
            strlcat(line, "ICMP: ", size);
        else if (portrange_ptr->protocol == 47)
            strlcat(line, "GRE : ", size);
        else if (portrange_ptr->protocol == 50)
            strlcat(line, "ESP : ", size);
        else if (portrange_ptr->protocol == 51)
            strlcat(line, "AH  : ", size);
        else {
            char proto[7];
            snprintf(proto, sizeof(proto), "%03d : ", portrange_ptr->protocol);
            strlcat(line, proto, size);
        }

        if (portrange_ptr->protocol == 6 || portrange_ptr->protocol == 17) {
            char range[64];

            if (portrange_ptr->src_high == 0 && portrange_ptr->dst_high == 0) {
                snprintf(range, sizeof(range), "%11d -> %d",
                        portrange_ptr->src_low, portrange_ptr->dst_low);
            } else if (portrange_ptr->src_high != 0 &&
                       portrange_ptr->dst_high == 0) {
                snprintf(range, sizeof(range),
                        "%5d:%5d -> %d                              ",
                        portrange_ptr->src_low, portrange_ptr->src_high,
                        portrange_ptr->dst_low);
            } else if (portrange_ptr->src_high == 0 &&
                       portrange_ptr->dst_high != 0) {
                snprintf(range, sizeof(range), "%11d -> %d:%d",
                        portrange_ptr->src_low, portrange_ptr->dst_low,
                        portrange_ptr->dst_high);
            } else {
                snprintf(range, sizeof(range), "%5d:%5d -> %d:%d",
                        portrange_ptr->src_low, portrange_ptr->src_high,
                        portrange_ptr->dst_low, portrange_ptr->dst_high);
            }
            strlcat(line, range, size);
        } else if (portrange_ptr->protocol == 1) {
            char range[64];
            snprintf(range, sizeof(range), "type: %d, code: %d.",
                    portrange_ptr->dst_low, portrange_ptr->dst_high);
            strlcat(line, range, size);
        } else {
            strlcat(line, gettext("uses no ports."), size);
        }
    finalize:
        /* pad line with spaces */
        len = StrMemLen(line);
        for (x = len; x < sizeof(line); x++) {
            line[x] = ' ';
            if (x == sizeof(line) - 1)
                line[x] = '\0';
        }
        strlcat(buffer, line, bsize);
        if (i == MAX_RANGES)
            break;
    }
    set_field_buffer_wrap(ServiceSec.portrangesfld, 0, buffer);
}

static void edit_service_init(
        struct vrmr_ctx *vctx, struct vrmr_service *ser_ptr)
{
    int rows, cols, comment_y = 0, comment_x = 0;
    int height, width, starty, startx, max_height;
    size_t field_num = 0, i = 0;
    int portranges_lines = 0;

    /* safety */
    vrmr_fatal_if_null(ser_ptr);

    memset(&ServiceSec, 0, sizeof(ServiceSec));

    /* get the screen dimentions for dynamically
     * sizing the window */
    max_height = getmaxy(stdscr);
    height = 24;
    if (height > max_height - 8)
        height = max_height - 8;
    if (height < 20)
        height = 20;
    width = 54;
    if (height >= 24)
        portranges_lines = height - 20;
    ServiceSec.portranges_lines = portranges_lines;

    /* place on the same y as "edit service" */
    VrWinGetOffset(
            -1, -1, height, width, 4, sersec_ctx.sl_xre + 1, &starty, &startx);
    sersec_ctx.edit_service.se_xre = startx + width;
    sersec_ctx.edit_service.se_yle = starty + height;

    sersec_ctx.edit_service.n_fields = 10;
    sersec_ctx.edit_service.fields = (FIELD **)calloc(
            sersec_ctx.edit_service.n_fields + 1, sizeof(FIELD *));
    vrmr_fatal_alloc("calloc", sersec_ctx.edit_service.fields);

    /* active */
    ServiceSec.activelabelfld = (sersec_ctx.edit_service.fields[field_num++] =
                                         new_field(1, 10, 2, 0, 0, 0));
    set_field_buffer_wrap(ServiceSec.activelabelfld, 0, gettext("Active"));
    field_opts_off(ServiceSec.activelabelfld, O_ACTIVE);

    ServiceSec.activefld = (sersec_ctx.edit_service.fields[field_num++] =
                                    new_field(1, 3, 3, 1, 0, 0));
    set_field_buffer_wrap(
            ServiceSec.activefld, 0, ser_ptr->active ? STR_YES : STR_NO);

    /* broadcast */
    ServiceSec.broadcastlabelfld =
            (sersec_ctx.edit_service.fields[field_num++] =
                            new_field(1, 16, 5, 0, 0, 0));
    set_field_buffer_wrap(
            ServiceSec.broadcastlabelfld, 0, gettext("Broadcast"));
    field_opts_off(ServiceSec.broadcastlabelfld, O_ACTIVE);

    ServiceSec.broadcastfld = (sersec_ctx.edit_service.fields[field_num++] =
                                       new_field(1, 3, 6, 1, 0, 0));
    set_field_buffer_wrap(
            ServiceSec.broadcastfld, 0, ser_ptr->broadcast ? STR_YES : STR_NO);

    /* helper */
    ServiceSec.helperlabelfld = (sersec_ctx.edit_service.fields[field_num++] =
                                         new_field(1, 16, 2, 16, 0, 0));
    set_field_buffer_wrap(
            ServiceSec.helperlabelfld, 0, gettext("Protocol helper"));
    field_opts_off(ServiceSec.helperlabelfld, O_ACTIVE);

    ServiceSec.helperfld = (sersec_ctx.edit_service.fields[field_num++] =
                                    new_field(1, 32, 3, 17, 0, 0));
    set_field_buffer_wrap(ServiceSec.helperfld, 0, ser_ptr->helper);

    ServiceSec.commentlabelfld = (sersec_ctx.edit_service.fields[field_num++] =
                                          new_field(1, 16, 8, 0, 0, 0));
    set_field_buffer_wrap(ServiceSec.commentlabelfld, 0, gettext("Comment"));
    field_opts_off(ServiceSec.commentlabelfld, O_ACTIVE);

    /* comment field size */
    comment_y = 5;
    comment_x = 48;
    /* load the comment from the backend */
    if (vctx->sf->ask(vctx->serv_backend, ser_ptr->name, "COMMENT",
                sersec_ctx.comment, sizeof(sersec_ctx.comment),
                VRMR_TYPE_SERVICE, 0) < 0)
        vrmr_error(-1, VR_ERR, gettext("error while loading the comment."));

    ServiceSec.commentfld =
            (sersec_ctx.edit_service.fields[field_num++] =
                            new_field(comment_y, comment_x, 9, 1, 0, 0));
    set_field_buffer_wrap(ServiceSec.commentfld, 0, sersec_ctx.comment);

    ServiceSec.norangewarningfld =
            (sersec_ctx.edit_service.fields[field_num++] =
                            new_field(1, 48, 14, 1, 0, 0));
    set_field_buffer_wrap(ServiceSec.norangewarningfld, 0,
            gettext("Warning: no port(range)s defined!"));
    field_opts_off(ServiceSec.norangewarningfld, O_VISIBLE | O_ACTIVE);
    set_field_just(ServiceSec.norangewarningfld, JUSTIFY_CENTER);

    ServiceSec.portrangesfld =
            (sersec_ctx.edit_service.fields[field_num++] =
                            new_field(portranges_lines, 48, 17, 1, 0, 0));
    field_opts_off(ServiceSec.portrangesfld, O_ACTIVE);
    set_field_just(ServiceSec.portrangesfld, JUSTIFY_CENTER);

    vrmr_fatal_if(sersec_ctx.edit_service.n_fields != field_num);
    /* terminate */
    sersec_ctx.edit_service.fields[sersec_ctx.edit_service.n_fields] = NULL;

    for (i = 0; i < sersec_ctx.edit_service.n_fields; i++) {
        // set field options
        set_field_back(sersec_ctx.edit_service.fields[i], vccnf.color_win_rev);
        field_opts_off(sersec_ctx.edit_service.fields[i], O_AUTOSKIP);
        // set status to false
        set_field_status(sersec_ctx.edit_service.fields[i], FALSE);
    }

    set_field_back(ServiceSec.activelabelfld, vccnf.color_win);
    set_field_back(ServiceSec.broadcastlabelfld, vccnf.color_win);
    set_field_back(ServiceSec.helperlabelfld, vccnf.color_win);
    set_field_back(ServiceSec.commentlabelfld, vccnf.color_win);
    set_field_back(ServiceSec.portrangesfld, vccnf.color_win);

    set_field_back(ServiceSec.norangewarningfld, vccnf.color_win);
    set_field_fore(ServiceSec.norangewarningfld, vccnf.color_win_warn | A_BOLD);

    /* create window and panel */
    sersec_ctx.edit_service.win = create_newwin(height, width, starty, startx,
            gettext("Edit Service"), vccnf.color_win);
    keypad(sersec_ctx.edit_service.win, TRUE);
    sersec_ctx.edit_service.panel[0] = new_panel(sersec_ctx.edit_service.win);

    /* create and post form */
    sersec_ctx.edit_service.form = new_form(sersec_ctx.edit_service.fields);
    scale_form(sersec_ctx.edit_service.form, &rows, &cols);
    set_form_win(sersec_ctx.edit_service.form, sersec_ctx.edit_service.win);
    set_form_sub(sersec_ctx.edit_service.form,
            derwin(sersec_ctx.edit_service.win, rows, cols, 1, 2));
    post_form(sersec_ctx.edit_service.form);

    /* print labels */
    mvwprintw(sersec_ctx.edit_service.win, 1, 2, "%s: %s", gettext("Name"),
            ser_ptr->name);
    mvwprintw(sersec_ctx.edit_service.win, 16, 1,
            gettext("Press <F6> to manage the portranges of this service."));

    edit_service_update_portrangesfld(ser_ptr);

    /* position the cursor in the active field */
    pos_form_cursor(sersec_ctx.edit_service.form);
}

static void edit_service_destroy(void)
{
    size_t i;

    /* Un post form and free the memory */
    unpost_form(sersec_ctx.edit_service.form);
    free_form(sersec_ctx.edit_service.form);

    for (i = 0; i < sersec_ctx.edit_service.n_fields; i++) {
        free_field(sersec_ctx.edit_service.fields[i]);
    }
    free(sersec_ctx.edit_service.fields);

    del_panel(sersec_ctx.edit_service.panel[0]);
    destroy_win(sersec_ctx.edit_service.win);

    /* clear comment */
    strlcpy(sersec_ctx.comment, "", sizeof(sersec_ctx.comment));

    update_panels();
    doupdate();
}

static int edit_service(
        struct vrmr_ctx *vctx, struct vrmr_services *services, const char *name)
{
    int ch, /* for recording keystrokes */
            quit = 0, not_defined = 0, retval = 0;
    struct vrmr_service *ser_ptr = NULL;
    FIELD *cur = NULL, *prev = NULL;
    /* top menu */
    char *key_choices[] = {"F12", "F6", "F10"};
    int key_choices_n = 3;
    char *cmd_choices[] = {
            gettext("help"), gettext("portranges"), gettext("back")};
    int cmd_choices_n = 3;

    vrmr_fatal_if_null(name);
    vrmr_fatal_if_null(services);

    /* search the service */
    if (!(ser_ptr = vrmr_search_service(services, name))) {
        vrmr_error(-1, VR_INTERR, "service '%s' was not found", name);
        return (-1);
    }

    /* Loop through to get user requests */
    while (quit == 0) {
        draw_field_active_mark(cur, prev, sersec_ctx.edit_service.win,
                sersec_ctx.edit_service.form, vccnf.color_win_mark | A_BOLD);

        /* init */
        edit_service_init(vctx, ser_ptr);

        /* show (or hide) initial warning about the group being empty. */
        if (ser_ptr->PortrangeList.len == 0) {
            field_opts_on(ServiceSec.norangewarningfld, O_VISIBLE);
        }

        pos_form_cursor(sersec_ctx.edit_service.form);
        cur = current_field(sersec_ctx.edit_service.form);

        draw_top_menu(top_win, gettext("Edit Service"), key_choices_n,
                key_choices, cmd_choices_n, cmd_choices);

        wrefresh(sersec_ctx.edit_service.win);
        update_panels();
        doupdate();

        while (quit == 0) {
            ch = wgetch(sersec_ctx.edit_service.win);

            not_defined = 0;

            if (cur == ServiceSec.commentfld) {
                if (nav_field_comment(sersec_ctx.edit_service.form, ch) < 0)
                    not_defined = 1;
            } else if (cur == ServiceSec.helperfld) {
                if (nav_field_simpletext(sersec_ctx.edit_service.form, ch) < 0)
                    not_defined = 1;
            } else if (cur == ServiceSec.activefld ||
                       cur == ServiceSec.broadcastfld) {
                if (nav_field_yesno(sersec_ctx.edit_service.form, ch) < 0)
                    not_defined = 1;
            } else {
                not_defined = 1;
            }

            if (not_defined == 1) {
                switch (ch) {
                    case KEY_F(6):
                    case 'e':
                    case 'E':
                        /* open portranges window */
                        edit_serv_portranges(vctx, ser_ptr);
                        edit_service_update_portrangesfld(ser_ptr);

                        draw_top_menu(top_win, gettext("Edit Service"),
                                key_choices_n, key_choices, cmd_choices_n,
                                cmd_choices);
                        break;

                    case 27:
                    case KEY_F(10):
                    case 'q':
                    case 'Q':
                        quit = 1;
                        break;

                    case KEY_DOWN:
                    case 10: // enter
                    case 9:  // tab

                        form_driver(
                                sersec_ctx.edit_service.form, REQ_NEXT_FIELD);
                        form_driver(sersec_ctx.edit_service.form, REQ_END_LINE);
                        break;

                    case KEY_UP:

                        form_driver(
                                sersec_ctx.edit_service.form, REQ_PREV_FIELD);
                        form_driver(sersec_ctx.edit_service.form, REQ_END_LINE);
                        break;

                    case KEY_F(12):
                    case 'h':
                    case 'H':
                    case '?':
                        print_help(":[VUURMUUR:SERVICE:EDIT]:");
                        break;
                }
            }

            prev = cur;
            cur = current_field(sersec_ctx.edit_service.form);

            /* print or erase warning about the group being empty. */
            if (ser_ptr->PortrangeList.len == 0) {
                field_opts_on(ServiceSec.norangewarningfld, O_VISIBLE);
            } else
                field_opts_off(ServiceSec.norangewarningfld, O_VISIBLE);

            wrefresh(sersec_ctx.edit_service.win);
            pos_form_cursor(sersec_ctx.edit_service.form);
        }
    }

    /* save */

    /* save the service */
    if (edit_service_save(vctx, ser_ptr) < 0) {
        vrmr_error(-1, "Error", "saving the service failed");
        retval = -1;
    }

    /* save the portranges */
    if (vrmr_services_save_portranges(vctx, ser_ptr) < 0) {
        vrmr_error(-1, "Error", "saving the portranges failed");
        retval = -1;
    }

    /* cleanup */
    edit_service_destroy();
    return (retval);
}

static int rename_service(struct vrmr_ctx *vctx, struct vrmr_services *services,
        struct vrmr_rules *rules, char *cur_name_ptr, char *new_name_ptr)
{
    int result = 0;
    struct vrmr_service *ser_ptr = NULL;
    struct vrmr_rule *rule_ptr = NULL;
    struct vrmr_list_node *d_node = NULL;
    char changed = 0;
    char old_ser_name[VRMR_MAX_SERVICE] = "";

    /* safety */
    vrmr_fatal_if_null(cur_name_ptr);
    vrmr_fatal_if_null(new_name_ptr);
    vrmr_fatal_if_null(services);
    vrmr_fatal_if_null(rules);

    (void)strlcpy(old_ser_name, cur_name_ptr, sizeof(old_ser_name));

    vrmr_debug(HIGH,
            "going to rename service old_ser_name:'%s' to new_name_ptr:'%s'.",
            old_ser_name, new_name_ptr);

    result = vctx->sf->rename(
            vctx->serv_backend, old_ser_name, new_name_ptr, VRMR_TYPE_SERVICE);
    if (result != 0) {
        return (-1);
    }

    ser_ptr = vrmr_search_service(services, old_ser_name);
    vrmr_fatal_if_null(ser_ptr);
    (void)strlcpy(ser_ptr->name, new_name_ptr, sizeof(ser_ptr->name));
    ser_ptr = NULL;

    /* update rules */
    for (d_node = rules->list.top; d_node; d_node = d_node->next) {
        vrmr_fatal_if_null(d_node->data);
        rule_ptr = d_node->data;
        vrmr_debug(HIGH, "service: '%s'.", rule_ptr->service);

        /* check the servicename */
        if (strcmp(rule_ptr->service, old_ser_name) == 0) {
            vrmr_debug(HIGH,
                    "found in a rule (was looking for old_ser_name:'%s', found "
                    "rule_ptr->service:'%s').",
                    old_ser_name, rule_ptr->service);

            /* set the new name to the rules */
            strlcpy(rule_ptr->service, new_name_ptr, sizeof(rule_ptr->service));
            changed = 1;
        }
    }

    /* if we have made changes we write the rulesfile */
    if (changed == 1) {
        if (vrmr_rules_save_list(vctx, rules, &vctx->conf) < 0) {
            vrmr_error(-1, VR_ERR, gettext("saving rules failed."));
            return (-1);
        }
    }

    /* example: "service 'htpt' has been renamed to 'http'." */
    vrmr_audit("%s '%s' %s '%s'.", STR_SERVICE, old_ser_name,
            STR_HAS_BEEN_RENAMED_TO, new_name_ptr);
    return (0);
}

static void vrmr_init_services_section(struct vrmr_services *services,
        int height, int width, int starty, int startx)
{
    int i = 0;
    struct vrmr_service *ser_ptr = NULL;
    struct vrmr_list_node *d_node = NULL;

    sersec_ctx.list_items = services->list.len;
    sersec_ctx.items =
            (ITEM **)calloc(sersec_ctx.list_items + 1, sizeof(ITEM *));
    vrmr_fatal_alloc("calloc", sersec_ctx.items);

    for (i = 0, d_node = services->list.top; d_node;
            d_node = d_node->next, i++) {
        vrmr_fatal_if_null(d_node->data);
        ser_ptr = d_node->data;
        sersec_ctx.items[i] = new_item(ser_ptr->name, NULL);
    }
    sersec_ctx.items[sersec_ctx.list_items] = (ITEM *)NULL;

    if (sersec_ctx.list_items > 0) {
        sersec_ctx.top = sersec_ctx.items[0];
        sersec_ctx.bot = sersec_ctx.items[sersec_ctx.list_items - 1];
    } else {
        sersec_ctx.top = NULL;
        sersec_ctx.bot = NULL;
    }

    sersec_ctx.win = newwin(height, width, starty, startx);
    wbkgd(sersec_ctx.win, vccnf.color_win);
    keypad(sersec_ctx.win, TRUE);
    sersec_ctx.panel[0] = new_panel(sersec_ctx.win);
    sersec_ctx.menu = new_menu((ITEM **)sersec_ctx.items);
    set_menu_win(sersec_ctx.menu, sersec_ctx.win);
    set_menu_sub(sersec_ctx.menu,
            derwin(sersec_ctx.win, height - 7, width - 2, 3, 1));
    set_menu_format(sersec_ctx.menu, height - 8, 1);
    box(sersec_ctx.win, 0, 0);
    print_in_middle(
            sersec_ctx.win, 1, 0, width, gettext("Services"), vccnf.color_win);

    mvwaddch(sersec_ctx.win, 2, 0, ACS_LTEE);
    mvwhline(sersec_ctx.win, 2, 1, ACS_HLINE, width - 2);
    mvwaddch(sersec_ctx.win, 2, width - 1, ACS_RTEE);

    set_menu_back(sersec_ctx.menu, vccnf.color_win);
    set_menu_fore(sersec_ctx.menu, vccnf.color_win_rev);
    post_menu(sersec_ctx.menu);

    mvwaddch(sersec_ctx.win, height - 5, 0, ACS_LTEE);
    mvwhline(sersec_ctx.win, height - 5, 1, ACS_HLINE, width - 2);
    mvwaddch(sersec_ctx.win, height - 5, width - 1, ACS_RTEE);

    mvwprintw(sersec_ctx.win, height - 4, 2, "<RET> %s", STR_EDIT);
    mvwprintw(sersec_ctx.win, height - 3, 2, "<INS> %s", STR_NEW);
    mvwprintw(sersec_ctx.win, height - 2, 2, "<DEL> %s", STR_REMOVE);

    /* create the top and bottom fields */
    sersec_ctx.win_top = newwin(1, 6, 6, 27);
    vrmr_fatal_if_null(sersec_ctx.win_top);
    wbkgd(sersec_ctx.win_top, vccnf.color_win);
    sersec_ctx.panel_top[0] = new_panel(sersec_ctx.win_top);
    /* TRANSLATORS: max 4 chars */
    wprintw(sersec_ctx.win_top, "(%s)", gettext("more"));
    hide_panel(sersec_ctx.panel_top[0]);

    sersec_ctx.win_bot = newwin(1, 6, height - 1, 27);
    vrmr_fatal_if_null(sersec_ctx.win_bot);
    wbkgd(sersec_ctx.win_bot, vccnf.color_win);
    sersec_ctx.panel_bot[0] = new_panel(sersec_ctx.win_bot);
    /* TRANSLATORS: max 4 chars */
    wprintw(sersec_ctx.win_bot, "(%s)", gettext("more"));
    hide_panel(sersec_ctx.panel_bot[0]);
}

static void destroy_services_section(void)
{
    unsigned int i = 0;

    unpost_menu(sersec_ctx.menu);
    free_menu(sersec_ctx.menu);
    for (i = 0; i < sersec_ctx.list_items; ++i)
        free_item(sersec_ctx.items[i]);
    free(sersec_ctx.items);
    del_panel(sersec_ctx.panel[0]);
    destroy_win(sersec_ctx.win);
    del_panel(sersec_ctx.panel_top[0]);
    destroy_win(sersec_ctx.win_top);
    del_panel(sersec_ctx.panel_bot[0]);
    destroy_win(sersec_ctx.win_bot);
}

void services_section(struct vrmr_ctx *vctx, struct vrmr_services *services,
        struct vrmr_rules *rules, struct vrmr_regex *reg)
{
    int result = 0, quit = 0, reload = 0;
    int ch = 0;
    int height = 0, width = 0, startx = 0, starty = 0;
    char *new_name_ptr = NULL, save_ser_name[VRMR_MAX_SERVICE] = "";
    ITEM *cur = NULL;
    /* top menu */
    char *key_choices[] = {"F12", "INS", "DEL", "r", "RET", "F10"};
    int key_choices_n = 6;
    char *cmd_choices[] = {gettext("help"), gettext("new"), gettext("del"),
            gettext("rename"), gettext("edit"), gettext("back")};
    int cmd_choices_n = 6;

    /* safety */
    vrmr_fatal_if_null(reg);
    vrmr_fatal_if_null(services);
    vrmr_fatal_if_null(rules);

    height = LINES - 8;
    width = 34;
    /* place on the same y as "edit service" */
    VrWinGetOffset(-1, -1, height, width, 4, 1, &starty, &startx);
    sersec_ctx.sl_xre = startx + width;
    sersec_ctx.sl_yle = starty + height;

    vrmr_init_services_section(services, height, width, starty, startx);
    draw_top_menu(top_win, gettext("Services"), key_choices_n, key_choices,
            cmd_choices_n, cmd_choices);
    update_panels();
    doupdate();

    while (quit == 0) {
        if (reload == 1) {
            destroy_services_section();
            vrmr_init_services_section(services, height, width, starty, startx);
            reload = 0;
        }

        while (quit == 0 && reload == 0) {
            if (sersec_ctx.top != NULL && !item_visible(sersec_ctx.top))
                show_panel(sersec_ctx.panel_top[0]);
            else
                hide_panel(sersec_ctx.panel_top[0]);

            if (sersec_ctx.bot != NULL && !item_visible(sersec_ctx.bot))
                show_panel(sersec_ctx.panel_bot[0]);
            else
                hide_panel(sersec_ctx.panel_bot[0]);
            update_panels();
            doupdate();

            /* restore the cursor */
            pos_menu_cursor(sersec_ctx.menu);

            ch = wgetch(sersec_ctx.win);

            switch (ch) {
                case 27:
                case 'q':
                case 'Q':
                case KEY_F(10): // quit

                    quit = 1;
                    break;

                case 'r':
                case 'R':

                    cur = current_item(sersec_ctx.menu);
                    new_name_ptr = input_box(32, gettext("Rename Service"),
                            STR_PLEASE_ENTER_THE_NAME);
                    if (cur && new_name_ptr != NULL) {
                        if (vrmr_validate_servicename(
                                    new_name_ptr, reg->servicename) == 0) {
                            char *n = (char *)item_name(cur);

                            result = rename_service(
                                    vctx, services, rules, n, new_name_ptr);
                            if (result == 0) {
                                reload = 1;
                            } else {
                                vrmr_error(-1, VR_ERR, "%s", STR_RENAME_FAILED);
                            }
                        }
                        free(new_name_ptr);
                    }
                    break;

                case KEY_IC: // insert
                case 'i':
                case 'I':

                    new_name_ptr = input_box(32, gettext("New Service"),
                            gettext("Please enter the name of the new "
                                    "service"));
                    if (new_name_ptr != NULL) {
                        if (vrmr_validate_servicename(
                                    new_name_ptr, reg->servicename) == 0) {
                            if ((vrmr_search_service(services, new_name_ptr) !=
                                        NULL)) {
                                vrmr_error(-1, VR_ERR,
                                        gettext("service %s already exists."),
                                        new_name_ptr);
                            } else {
                                result = vrmr_new_service(vctx, services,
                                        new_name_ptr, VRMR_TYPE_SERVICE);
                                if (result == 0) {
                                    /* example: "service 'X-5' has been created"
                                     */
                                    vrmr_audit("%s '%s' %s.", STR_SERVICE,
                                            new_name_ptr, STR_HAS_BEEN_CREATED);
                                    reload = 1;

                                    edit_service(vctx, services, new_name_ptr);

                                    draw_top_menu(top_win, gettext("Services"),
                                            key_choices_n, key_choices,
                                            cmd_choices_n, cmd_choices);
                                } else {
                                    vrmr_error(-1, VR_ERR,
                                            gettext("creating new service "
                                                    "failed."));
                                }
                            }
                        } else {
                            vrmr_error(-1, VR_ERR,
                                    gettext("service name %s is invalid."),
                                    new_name_ptr);
                        }
                        free(new_name_ptr);
                    }
                    break;

                case KEY_DC: // delete
                case 'd':
                case 'D':

                    cur = current_item(sersec_ctx.menu);
                    if (cur &&
                            confirm(gettext("Delete"), gettext("Are you sure?"),
                                    vccnf.color_win_note,
                                    vccnf.color_win_note_rev | A_BOLD,
                                    0) == 1) {
                        (void)strlcpy(save_ser_name, (char *)item_name(cur),
                                sizeof(save_ser_name));

                        result = vrmr_delete_service(vctx, services,
                                item_name(cur), VRMR_TYPE_SERVICE);
                        if (result < 0) {
                            vrmr_error(-1, VR_ERR, "%s.", STR_DELETE_FAILED);
                        } else {
                            /* example: "service 'X-5' has been deleted." */
                            vrmr_audit("%s '%s' %s.", STR_SERVICE,
                                    save_ser_name, STR_HAS_BEEN_DELETED);
                            reload = 1;
                        }
                    }
                    break;

                case KEY_DOWN:
                    menu_driver(sersec_ctx.menu, REQ_DOWN_ITEM);
                    break;
                case KEY_UP:
                    menu_driver(sersec_ctx.menu, REQ_UP_ITEM);
                    break;
                case KEY_NPAGE:
                    if (menu_driver(sersec_ctx.menu, REQ_SCR_DPAGE) != E_OK) {
                        while (menu_driver(sersec_ctx.menu, REQ_DOWN_ITEM) ==
                                E_OK)
                            ;
                    }
                    break;
                case KEY_PPAGE:
                    if (menu_driver(sersec_ctx.menu, REQ_SCR_UPAGE) != E_OK) {
                        while (menu_driver(sersec_ctx.menu, REQ_UP_ITEM) ==
                                E_OK)
                            ;
                    }
                    break;
                case KEY_HOME:
                    menu_driver(sersec_ctx.menu, REQ_FIRST_ITEM); // page up
                    break;
                case KEY_END:
                    menu_driver(sersec_ctx.menu, REQ_LAST_ITEM); // end
                    break;

                case KEY_RIGHT:
                case 10: // enter
                case 'e':
                case 'E':

                    cur = current_item(sersec_ctx.menu);
                    if (cur) {
                        (void)edit_service(vctx, services, item_name(cur));

                        draw_top_menu(top_win, gettext("Services"),
                                key_choices_n, key_choices, cmd_choices_n,
                                cmd_choices);
                    }
                    break;

                case KEY_F(12):
                case 'h':
                case 'H':
                case '?':

                    print_help(":[VUURMUUR:SERVICES]:");
                    break;
            }
        }
    }

    destroy_services_section();
    update_panels();
    doupdate();
}
