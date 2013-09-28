/***************************************************************************
 *   Copyright (C) 2003-2008 by Victor Julien                              *
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


struct ServicesSection_
{
    PANEL   *panel[1];
    WINDOW  *win;
    MENU    *menu;
    ITEM    **items;
    ITEM    *top,
            *bot;
    PANEL   *panel_top[1];
    PANEL   *panel_bot[1];
    WINDOW  *win_top;
    WINDOW  *win_bot;

    int sl_xre; /**< x right edge */
    int sl_yle; /**< y lower edge */
    unsigned int     list_items;

    struct EditService_
    {
        WINDOW  *win;
        PANEL   *panel[1];

        FIELD   **fields;
        size_t  n_fields;
        FORM    *form;

        /* portrange list */
        MENU    *menu;
        ITEM    **items;
        size_t  n_items;

        struct vrmr_list  item_list;
        struct vrmr_list  item_number_list;

        int se_xre; /**< x right edge */
        int se_yle; /**< y lower edge */
    } EditService;

    struct EditService_ EditServicePrt;

    char comment[512];
} ServicesSection;


/*  edit_serv_portranges_new_validate

    Validates the new portrange and inserts it into the list at the right place.

    Returncodes:
        0: ok
        -1: error
*/
static int
edit_serv_portranges_new_validate(const int debuglvl, struct vrmr_ctx *vctx,
        struct vrmr_service *ser_ptr, struct vrmr_portdata *port_ptr)
{
    struct vrmr_list_node     *d_node = NULL;
    struct vrmr_portdata *portlist_ptr = NULL;
    int             insert_now = 0,
                    insert_append = 0;

    /* safety */
    if(port_ptr == NULL || ser_ptr == NULL)
    {
        vrmr_error(-1, VR_INTERR, "parameter problem (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    /* if low and high are the same, only src is enough */
    if(port_ptr->src_low == port_ptr->src_high)
        port_ptr->src_high = 0;
    if(port_ptr->dst_low == port_ptr->dst_high)
    {
        if(port_ptr->protocol != 1)
            port_ptr->dst_high = 0;
    }

    /* check the protocol */
    if(port_ptr->protocol == 0 || port_ptr->protocol > 255)
    {
        vrmr_error(-1, VR_INTERR, "invalid protocol %d "
            "(in: %s:%d).", port_ptr->protocol, __FUNC__, __LINE__);
        return(-1);
    }

    /*  check the ports

        for tcp and udp
    */
    if(port_ptr->protocol == 6 || port_ptr->protocol == 17)
    {
        /* no value is allowed to be higher than 65535, src_low and dst_low are not allowed to be smaller than 1 */
        if( port_ptr->src_low > 65535 || port_ptr->src_high > 65535 ||
            port_ptr->dst_low > 65535 || port_ptr->dst_high > 65535 ||
            port_ptr->src_low < 1 || port_ptr->dst_low < 1
        )
        {
            /* this is an error because of wrong user input, so no function name */
            vrmr_error(-1, VR_ERR, gettext("one of the ports is too low or too high. Valid port values for tcp and udp are 1-65535."));
            return(-1);
        }

        /* check if the ranges are ok */
        if( (port_ptr->src_low > port_ptr->src_high && port_ptr->src_high > 0) ||
            (port_ptr->dst_low > port_ptr->dst_high && port_ptr->dst_high > 0)
        )
        {
            /* this is an error because of wrong user input, so no function name */
            vrmr_error(-1, VR_ERR, gettext("please make sure that the 'high'-port is actually higher than the 'low'-port."));
            return(-1);
        }
    }
    /*
        for icmp
    */
    else if(port_ptr->protocol == 1)
    {
        if(port_ptr->dst_low > 255 || port_ptr->dst_high > 16)
        {
            /* this is an error because of wrong user input, so no function name */
            vrmr_error(-1, VR_ERR, gettext("one of the values is too high. Valid icmp-types values are 1-255 (note that 41-255 are reserved). Valid icmp-codes are 0-16 (note that not all combinations of types and codes are valid. See http://www.iana.org/assignments/icmp-parameters for details)."));
            return(-1);
        }
    }

    /* in an empty list we insert now */
    if(ser_ptr->PortrangeList.len == 0)
        insert_now = 1;
    else
    {
        /* else set the initial d_node */
        if(!(d_node = ser_ptr->PortrangeList.top))
        {
            vrmr_error(-1, VR_INTERR, "NULL pointer (in: %s:%d).", __FUNC__, __LINE__);
            return(-1);
        }
    }

    /* now look for the place in the list to insert */
    while (!insert_now)
    {
        if(!(portlist_ptr = d_node->data))
        {
            vrmr_error(-1, VR_INTERR, "NULL pointer (in: %s:%d).", __FUNC__, __LINE__);
            return(-1);
        }

        if (port_ptr->protocol < portlist_ptr->protocol)
            insert_now = 1;

        if (!(port_ptr->protocol == 1 || port_ptr->protocol == 6 || port_ptr->protocol == 17)) {
            if (port_ptr->protocol == portlist_ptr->protocol) {
                /* this is an error because of wrong user input, so no function name */
                vrmr_error(-1, VR_ERR, gettext("only one protocol %d portrange is allowed."), port_ptr->protocol);
                return(-1);
            }
        }

        if(!insert_now)
        {
            if(debuglvl >= HIGH)
                vrmr_debug(__FUNC__, "don't insert at this run.");

            if(vrmr_list_node_is_bot(debuglvl, d_node))
            {
                /* if we reach the bot, insert now */
                insert_now = 1;
                insert_append = 1;
                break;
            }
            else
                d_node = d_node->next;
        }
    }

    /*
        insert now
    */
    if(insert_now)
    {
        /*  for appending at the bot we call vrmr_list_append because vrmr_list_insert_before is unable to
            insert at the bot.
        */
        if(!insert_append)
        {
            if(vrmr_list_insert_before(debuglvl, &ser_ptr->PortrangeList, d_node, port_ptr) == NULL)
            {
                vrmr_error(-1, VR_INTERR, "vrmr_list_insert_before() failed (in: %s:%d).", __FUNC__, __LINE__);
                return(-1);
            }
        }
        else
        {
            if(vrmr_list_append(debuglvl, &ser_ptr->PortrangeList, port_ptr) == NULL)
            {
                vrmr_error(-1, VR_INTERR, "vrmr_list_append() failed (in: %s:%d).", __FUNC__, __LINE__);
                return(-1);
            }
        }

        ser_ptr->status = VRMR_ST_CHANGED;

        /* save the portranges */
        if(vrmr_services_save_portranges(debuglvl, vctx, ser_ptr) < 0)
        {
            vrmr_error(-1, VR_ERR, gettext("saving the portranges failed (in: %s:%d)."), __FUNC__, __LINE__);
            return(-1);
        }
    }

    return(0);
}


struct 
{
    FIELD   *src_lo_fld,
            *src_hi_fld,
            *dst_lo_fld,
            *dst_hi_fld;

} TCPUDPSec;


static int
edit_tcpudp(const int debuglvl, struct vrmr_portdata *port_ptr)
{
    WINDOW  *new_portrange_win;
    PANEL   *my_panels[1];
    FIELD   **fields,
            *cur = NULL,
            *prev = NULL;
    FORM    *my_form;
    int     height,
            width,
            startx = 0,
            starty = 0,
            max_height,
            max_width,
            ch,
            i,
            rows,
            cols,
            retval=0,
            quit=0;
    int     not_defined = 0,
            field_num = 0;
    char    port_str[6] = ""; /* 5 (65535) + \0 = 6 */

    /* safety */
    if(port_ptr == NULL)
    {
        vrmr_error(-1, VR_INTERR, "parameter problem (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    /* clear */
    memset(&TCPUDPSec, 0, sizeof(TCPUDPSec));

    /* set window dimentions */
    height = 8;
    width = 44;

    getmaxyx(stdscr, max_height, max_width);

    /* place in the center of the screen */
    starty = (max_height - height) / 2;
    startx = (max_width  - width)  / 2;

    /* create window and panel */
    if(port_ptr->protocol == 6)
        new_portrange_win = create_newwin(height, width, starty, startx, gettext("TCP Portrange"), vccnf.color_win);
    else
        new_portrange_win = create_newwin(height, width, starty, startx, gettext("UDP Portrange"), vccnf.color_win);
    if(new_portrange_win == NULL)
    {
        vrmr_error(-1, VR_INTERR, "create_newwin() failed (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }
    if(!(my_panels[0] = new_panel(new_portrange_win)))
    {
        vrmr_error(-1, VR_INTERR, "new_panel() failed (in: %s:%d).", __FUNC__, __LINE__);

        destroy_win(new_portrange_win);
        return(-1);
    }
    keypad(new_portrange_win, TRUE);

    fields = (FIELD **)calloc(4 + 1, sizeof(FIELD *));
    if(fields == NULL)
    {
        vrmr_error(-1, VR_ERR, gettext("calloc failed: %s (in: %s:%d)."), strerror(errno), __FUNCTION__, __LINE__);
        return(-1);
    }

    TCPUDPSec.src_lo_fld = (fields[field_num++] = new_field(1, 5, 3, 3, 0, 0));
    if(port_ptr->src_low > 0 && port_ptr->src_low <= 65535)
    {
        snprintf(port_str, sizeof(port_str), "%d", port_ptr->src_low);
        set_field_buffer_wrap(debuglvl, TCPUDPSec.src_lo_fld, 0, port_str);
    }

    TCPUDPSec.src_hi_fld = (fields[field_num++] = new_field(1, 5, 3, 11, 0, 0));
    if(port_ptr->src_high > 0 && port_ptr->src_high <= 65535)
    {
        snprintf(port_str, sizeof(port_str), "%d", port_ptr->src_high);
        set_field_buffer_wrap(debuglvl, TCPUDPSec.src_hi_fld, 0, port_str);
    }

    TCPUDPSec.dst_lo_fld = (fields[field_num++] = new_field(1, 5, 3, 24, 0, 0));
    if(port_ptr->dst_low > 0 && port_ptr->dst_low <= 65535)
    {
        snprintf(port_str, sizeof(port_str), "%d", port_ptr->dst_low);
        set_field_buffer_wrap(debuglvl, TCPUDPSec.dst_lo_fld, 0, port_str);
    }

    TCPUDPSec.dst_hi_fld = (fields[field_num++] = new_field(1, 5, 3, 32, 0, 0));
    if(port_ptr->dst_high > 0 && port_ptr->dst_high <= 65535)
    {
        snprintf(port_str, sizeof(port_str), "%d", port_ptr->dst_high);
        set_field_buffer_wrap(debuglvl, TCPUDPSec.dst_hi_fld, 0, port_str);
    }

    if (field_num != 4) {
        vrmr_error(-1, VR_INTERR, "parameter problem (in: %s:%d).",
                __FUNC__, __LINE__);
        return(-1);
    }

    for(i = 0; i < 4; i++)
    {
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

    mvwprintw(new_portrange_win, 2, 5,  gettext("Source"));
    mvwprintw(new_portrange_win, 3, 5,  gettext("Low"));
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

    while(quit == 0)
    {
        draw_field_active_mark(cur, prev, new_portrange_win, my_form, vccnf.color_win_mark|A_BOLD);

        if(cur == TCPUDPSec.src_lo_fld)
            status_print(status_win, gettext("Enter a portnumber (1-65535)."));
        else if(cur == TCPUDPSec.src_hi_fld)
            status_print(status_win, gettext("Enter a portnumber (1-65535). This is the high-end of the range."));
        else if(cur == TCPUDPSec.dst_lo_fld)
            status_print(status_win, gettext("Enter a portnumber (1-65535)."));
        else if(cur == TCPUDPSec.dst_hi_fld)
            status_print(status_win, gettext("Enter a portnumber (1-65535). This is the high-end of the range."));

        ch = wgetch(new_portrange_win);

        not_defined = 0;

        if(nav_field_simpletext(debuglvl, my_form, ch) < 0)
            not_defined = 1;

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
                case 10: // enter
                case 9: // tab

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
                    print_help(debuglvl, ":[VUURMUUR:SERVICE:EDIT:PORTRANGE:TCPUDP]:");
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
    port_ptr->src_low  = atoi(field_buffer(TCPUDPSec.src_lo_fld, 0));
    port_ptr->src_high = atoi(field_buffer(TCPUDPSec.src_hi_fld, 0));
    port_ptr->dst_low  = atoi(field_buffer(TCPUDPSec.dst_lo_fld, 0));
    port_ptr->dst_high = atoi(field_buffer(TCPUDPSec.dst_hi_fld, 0));

    /* cleanup */
    unpost_form(my_form);
    free_form(my_form);

    for(i = 0; i < 4; i++)
    {
        free_field(fields[i]);
    }
    free(fields);

    del_panel(my_panels[0]);
    destroy_win(new_portrange_win);

    status_print(status_win, gettext("Ready."));

    update_panels();
    doupdate();

    return(retval);
}


/*  icmp_choose_type

    returns:
        selected icmptype or -1 on error
*/
static int
icmp_choose_type(void)
{
    WINDOW  *win = NULL;
    PANEL   *panel[1];
    MENU    *menu = NULL;
    ITEM    **items;
    ITEM    *cur = NULL;
    size_t  n_items = 0,
            i = 0;
        
    int     retval = 0,
            height = 0,
            width = 0,
            max_height = 0,
            max_width = 0,
            startx = 0,
            starty = 0,
            quit = 0,
            ch = 0;

    char    **itemnames;
    char    **itemnumbers;
    char    *name = NULL,
            *select_ptr;
        
    size_t  name_size = 32; /* max size of icmp name */
    size_t  type_size = 4;  /* max size of icmp type string */
    size_t  size = 0;

    int     icmp_type = 0,
            icmp_type_has_code = 0,
            icmp_type_num = 0;
    size_t  type_cnt = 0;

    /* get screensize */
    getmaxyx(stdscr, max_height, max_width);

    /* count the number of icmp types (maybe this could be a fixed number?) */
    while(vrmr_list_icmp_types(&icmp_type, &icmp_type_has_code, &icmp_type_num) == 1)
        type_cnt++;

    /* set number of menu items */
    n_items = type_cnt;

    /* get memory */
    if(!(items = (ITEM **)calloc(n_items + 1, sizeof(ITEM *))))
    {
        vrmr_error(-1, VR_ERR, gettext("calloc failed: %s (in: %s:%d)."), strerror(errno), __FUNCTION__, __LINE__);
        return(-1);
    }
    if(!(itemnames = calloc(n_items + 1, 32)))
    {
        vrmr_error(-1, VR_ERR, gettext("calloc failed: %s (in: %s:%d)."), strerror(errno), __FUNCTION__, __LINE__);
        return(-1);
    }
    if(!(itemnumbers = calloc(n_items + 1, 32)))
    {
        vrmr_error(-1, VR_ERR, gettext("calloc failed: %s (in: %s:%d)."), strerror(errno), __FUNCTION__, __LINE__);
        return(-1);
    }

    /* reset */
    icmp_type = 0;
    icmp_type_has_code = 0;
    icmp_type_num = 0;
    type_cnt = 0;

    /* init */
    while(vrmr_list_icmp_types(&icmp_type, &icmp_type_has_code, &icmp_type_num) == 1)
    {
        //status_print(status_win, "%d", type_cnt);

        /* set itemnames and itemnumbers */
        if(!(name = malloc(name_size)))
        {
            vrmr_error(-1, VR_ERR, gettext("malloc failed: %s (in: %s:%d)."), strerror(errno), __FUNCTION__, __LINE__);
            return(-1);
        }
        if(vrmr_get_icmp_name_short(icmp_type, -1, name, name_size, 0) < 0)
        {
            vrmr_error(-1, VR_INTERR, "vrmr_get_icmp_name_short() failed (in: %s:%d).", __FUNC__, __LINE__);
            return(-1);
        }
        itemnames[type_cnt] = name;

        /* now the typenumber string */
        if(!(name = malloc(type_size)))
        {
            vrmr_error(-1, VR_ERR, gettext("malloc failed: %s (in: %s:%d)."), strerror(errno), __FUNCTION__, __LINE__);
            return(-1);
        }
        snprintf(name, type_size, "%d", icmp_type);
        itemnumbers[type_cnt] = name;

        items[type_cnt] = new_item(itemnumbers[type_cnt], itemnames[type_cnt]);
        if(items[type_cnt] == NULL)
        {
            vrmr_error(-1, VR_INTERR, "new_item() failed (in: %s:%d).", __FUNC__, __LINE__);
            return(-1);
        }

        /* update cnt */
        type_cnt++;
    }
    /* terminate */
    items[n_items] = (ITEM *)NULL;

    menu = new_menu((ITEM **)items);
    if(menu == NULL)
    {
        vrmr_error(-1, VR_INTERR, "new_menu() failed (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    /* set window dimentions */
    height = (int)n_items + 4;
    if(height > (max_height - 6))
        height = max_height - 6;

    width = 32 + 8 + 2;

    /* center of the screen */
    startx = (max_width -  width )/2;
    starty = (max_height - height)/2;

    win = newwin(height, width, starty, startx);
    if(win == NULL)
    {
        vrmr_error(-1, VR_INTERR, "newwin() failed (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }
    wbkgd(win, vccnf.color_win);
    keypad(win, TRUE);
    box(win, 0, 0);
    print_in_middle(win, 1, 0, width, gettext("ICMP Types"), vccnf.color_win);
    wrefresh(win);

    panel[0] = new_panel(win);
    if(panel[0] == NULL)
    {
        vrmr_error(-1, VR_INTERR, "new_panel() failed (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    update_panels();

    set_menu_win(menu, win);
    set_menu_sub(menu, derwin(win, height-4, width-2, 3, 1));

    set_menu_format(menu, height-4, 1);

    mvwaddch(win, 2, 0, ACS_LTEE);
    mvwhline(win, 2, 1, ACS_HLINE, width-2);
    mvwaddch(win, 2, width-1, ACS_RTEE);

    set_menu_back(menu, vccnf.color_win);
    set_menu_fore(menu, vccnf.color_win_rev);

    post_menu(menu);
    doupdate();

    while(quit == 0)
    {
        ch = wgetch(win);
        switch(ch)
        {
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
                if((cur = current_item(menu)))
                {
                    size = StrMemLen((char *)item_name(cur)) + 1;

                    select_ptr = malloc(size);
                    if(select_ptr == NULL)
                    {
                        vrmr_error(-1, VR_ERR, gettext("malloc failed: %s (in: %s:%d)."), strerror(errno), __FUNCTION__, __LINE__);
                        return(-1);
                    }

                    (void)strlcpy(select_ptr, item_name(cur), size);
                    retval = atoi(select_ptr);
                    free(select_ptr);
                }

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
    for(i = 0; i < n_items; ++i)
        free_item(items[i]);

    free(items);
    free(itemnumbers);
    free(itemnames);

    del_panel(panel[0]);
    destroy_win(win);

    update_panels();
    doupdate();

    return(retval);
}


static int
icmp_choose_code(const int icmp_type)
{
    WINDOW  *win = NULL;
    PANEL   *panel[1];
    MENU    *menu = NULL;
    ITEM    **items;
    ITEM    *cur = NULL;
    size_t  n_items = 0,
            i = 0;

    int     retval = 0,
            height = 0,
            width = 0,
            max_height = 0,
            max_width = 0,
            startx = 0,
            starty = 0,
            quit = 0,
            ch = 0;

    char    **itemnames;
    char    **itemnumbers;
    char    *name = NULL,
            *select_ptr;
        
    size_t  name_size = 32;
    size_t  code_size = 4;  /* max size of icmp-number code string */
    size_t  size = 0;

    int     icmp_code=0,
            icmp_code_num=0;
    size_t  code_cnt=0;

    /* get screensize */
    getmaxyx(stdscr, max_height, max_width);
    
    /* count the number of icmp types (maybe this could be a fixed number?) */
    while(vrmr_list_icmp_codes(icmp_type, &icmp_code, &icmp_code_num) == 1)
        code_cnt++;

    if(code_cnt == 0)
    {
        vrmr_warning(VR_WARN, gettext("no ICMP-codes with selected ICMP-type (%d)."), icmp_type);
        return(0);
    }

    /* set number of menu items */
    n_items = code_cnt;

    /* get memory */
    items = (ITEM **)calloc(n_items + 1, sizeof(ITEM *));
    if(items == NULL)
    {
        vrmr_error(-1, VR_ERR, gettext("calloc failed: %s (in: %s:%d)."), strerror(errno), __FUNCTION__, __LINE__);
        return(-1);
    }
    itemnames = calloc(n_items + 1, 32);
    if(itemnames == NULL)
    {
        vrmr_error(-1, VR_ERR, gettext("calloc failed: %s (in: %s:%d)."), strerror(errno), __FUNCTION__, __LINE__);
        return(-1);
    }
    itemnumbers = calloc(n_items + 1, 32);
    if(itemnumbers == NULL)
    {
        vrmr_error(-1, VR_ERR, gettext("calloc failed: %s (in: %s:%d)."), strerror(errno), __FUNCTION__, __LINE__);
        return(-1);
    }

    /* reset */
    icmp_code_num = 0;
    code_cnt = 0;
    icmp_code = 0;

    /* init */
    while(vrmr_list_icmp_codes(icmp_type, &icmp_code, &icmp_code_num) == 1)
    {
        /* set itemnames and itemnumbers */
        if(!(name = malloc(name_size)))
        {
            vrmr_error(-1, VR_ERR, gettext("malloc failed: %s (in: %s:%d)."), strerror(errno), __FUNCTION__, __LINE__);
            return(-1);
        }
        if(vrmr_get_icmp_name_short(icmp_type, icmp_code, name, name_size, 1) < 0)
        {
            vrmr_error(-1, VR_INTERR, "vrmr_get_icmp_name_short() failed (in: %s:%d).", __FUNC__, __LINE__);
            return(-1);
        }
        itemnames[code_cnt] = name;

        if(!(name = malloc(code_size)))
        {
            vrmr_error(-1, VR_ERR, gettext("malloc failed: %s (in: %s:%d)."), strerror(errno), __FUNCTION__, __LINE__);
            return(-1);
        }
        snprintf(name, code_size, "%d", icmp_code);
        itemnumbers[code_cnt] = name;

        items[code_cnt] = new_item(itemnumbers[code_cnt], itemnames[code_cnt]);
        if(items[code_cnt] == NULL)
        {
            vrmr_error(-1, VR_INTERR, "new_item() failed (in: %s:%d).", __FUNC__, __LINE__);
            return(-1);
        }

        /* update cnt */
        code_cnt++;
    }
    /* terminate */
    items[n_items] = (ITEM *)NULL;

    menu = new_menu((ITEM **)items);
    if(menu == NULL)
    {
        vrmr_error(-1, VR_INTERR, "new_menu() failed (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    /* set window dimentions */
    height = (int)n_items+4;
    if(height > (max_height - 6))
        height = max_height - 6;
        
    width = 32+8+2;

    startx = (max_width - width ) /2;
    starty = (max_height - height)/2;

    /* create win & panel & set attribs */
    win = newwin(height, width, starty, startx);
    if(win == NULL)
    {
        vrmr_error(-1, VR_INTERR, "newwin() failed (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }
    panel[0] = new_panel(win);
    if(panel[0] == NULL)
    {
        vrmr_error(-1, VR_INTERR, "new_panel() failed (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }
    box(win, 0, 0);
    wbkgd(win, vccnf.color_win_rev);
    keypad(win, TRUE);
    print_in_middle(win, 1, 0, width, gettext("ICMP Codes"), vccnf.color_win_rev);
    wrefresh(win);
    update_panels();

    set_menu_win(menu, win);
    set_menu_sub(menu, derwin(win, height-4, width-2, 3, 1));
    set_menu_format(menu, height-4, 1);

    mvwaddch(win, 2, 0, ACS_LTEE);
    mvwhline(win, 2, 1, ACS_HLINE, width-2);
    mvwaddch(win, 2, width-1, ACS_RTEE);

    set_menu_back(menu, vccnf.color_win_rev);
    set_menu_fore(menu, vccnf.color_win);

    post_menu(menu);
    doupdate();

    while(quit == 0)
    {
        ch = wgetch(win);
        switch(ch)
        {
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
                if((cur = current_item(menu)))
                {
                    size = StrMemLen((char *)item_name(cur)) + 1;

                    select_ptr = malloc(size);
                    if(select_ptr == NULL)
                    {
                        vrmr_error(-1, VR_ERR, gettext("malloc failed: %s (in: %s:%d)."), strerror(errno), __FUNCTION__, __LINE__);
                        return(-1);
                    }

                    (void)strlcpy(select_ptr, item_name(cur), size);
                    retval = atoi(select_ptr);
                    free(select_ptr);
                }

                /* quit */
                quit = 1;
                break;
            }

            case 27:
            case KEY_F(10):
            case 'q':
            case 'Q':
                quit=1;
                retval=-1;
                break;
        }
    }

    // cleanup
    unpost_menu(menu);
    free_menu(menu);
    for(i = 0; i < n_items; ++i)
        free_item(items[i]);

    free(items);
    free(itemnumbers);
    free(itemnames);

    del_panel(panel[0]);

    destroy_win(win);

    update_panels();
    doupdate();

    return(retval);
}


struct
{
    FIELD   *typefld,
            *codefld;

} ICMPSec;


static int
edit_icmp(const int debuglvl, struct vrmr_portdata *port_ptr)
{
    WINDOW  *new_portrange_win;
    PANEL   *my_panels[1];
    FIELD   **fields;
    FORM    *my_form;
    int     height,
            width,
            startx,
            starty,
            max_height,
            max_width,
            ch,
            i,
            rows,
            cols,
            result = 0,
            retval = 0,
            quit = 0;
    char    icmp_type[4] = "",
            icmp_code[4] = "",
            port_str[4] = "";
    FIELD   *cur_field = NULL,
            *prev_field = NULL;

    /* safety */
    if(port_ptr == NULL)
    {
        vrmr_error(-1, VR_INTERR, "parameter problem (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    /* set window dimentions */
    height = 7;
    width  = 24;

    getmaxyx(stdscr, max_height, max_width);

    /* place in the center of the screen */
    starty = (max_height - height) / 2;
    startx = (max_width - width) / 2;

    /* create window and panel */
    new_portrange_win = create_newwin(height, width, starty, startx, "ICMP", vccnf.color_win);
    if(new_portrange_win == NULL)
    {
        vrmr_error(-1, VR_INTERR, "create_newwin() failed (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }
    my_panels[0] = new_panel(new_portrange_win);
    if(my_panels[0] == NULL)
    {
        vrmr_error(-1, VR_INTERR, "new_panel() failed (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }
    keypad(new_portrange_win, TRUE);

    fields = (FIELD **)calloc(2 + 1, sizeof(FIELD *));
    if(fields == NULL)
    {
        vrmr_error(-1, VR_ERR, gettext("calloc failed: %s (in: %s:%d)."), strerror(errno), __FUNCTION__, __LINE__);
        return(-1);
    }

    ICMPSec.typefld = (fields[0] = new_field(1, 3, 2, 5, 0, 0));
    if(port_ptr->dst_low >= 0 && port_ptr->dst_low <= 255)
    {
        snprintf(port_str, sizeof(port_str), "%d", port_ptr->dst_low);
        set_field_buffer_wrap(debuglvl, ICMPSec.typefld, 0, port_str);
    }

    ICMPSec.codefld = (fields[1] = new_field(1, 3, 2, 12, 0, 0));
    if(port_ptr->dst_high >= 0 && port_ptr->dst_high <= 16)
    {
        snprintf(port_str, sizeof(port_str), "%d", port_ptr->dst_high);
        set_field_buffer_wrap(debuglvl, ICMPSec.codefld, 0, port_str);
    }

    for(i = 0; i < 2; i++)
    {
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

    mvwprintw(new_portrange_win, 2, 6,  gettext("Type"));
    mvwprintw(new_portrange_win, 2, 13, gettext("Code"));

    pos_form_cursor(my_form);
    cur_field = current_field(my_form);

    update_panels();
    doupdate();

    while(quit == 0) // F10 exits
    {
        draw_field_active_mark(cur_field, prev_field, new_portrange_win, my_form, vccnf.color_win_mark|A_BOLD);

        if(cur_field  == ICMPSec.typefld)
            status_print(status_win, gettext("Press SPACE to select an ICMP-type."));
        else if(cur_field  == ICMPSec.codefld)
            status_print(status_win, gettext("Press SPACE to select an ICMP-code."));

        ch = wgetch(new_portrange_win);
        switch(ch)
        {
            case 32: //space

                if(cur_field == ICMPSec.typefld)
                {
                    result = icmp_choose_type();
                    if(result >= 0)
                    {
                        (void)snprintf(icmp_type, sizeof(icmp_type), "%d", result);
                        set_field_buffer_wrap(debuglvl, cur_field, 0, icmp_type);
                    }
                }
                else
                {
                    (void)strlcpy(icmp_type, field_buffer(ICMPSec.typefld, 0), sizeof(icmp_type));

                    result = icmp_choose_code(atoi(icmp_type));
                    if(result >= 0)
                    {
                        (void)snprintf(icmp_code, sizeof(icmp_code), "%d", result);
                        set_field_buffer_wrap(debuglvl, cur_field, 0, icmp_code);
                    }
                }
                break;

            case KEY_DOWN:
            case 10: // enter
            case 9: // tab

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
                quit=1;
                break;

            case KEY_F(12):
            case 'h':
            case 'H':
            case '?':
                print_help(debuglvl, ":[VUURMUUR:SERVICE:EDIT:PORTRANGE:ICMP]:");
                break;

            default:
                /* If this is a normal character, it gets printed */
                if(isdigit(ch))
                {
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

    for(i = 0; i < 2; i++)
    {
        free_field(fields[i]);
    }
    free(fields);

    del_panel(my_panels[0]);
    destroy_win(new_portrange_win);

    status_print(status_win, gettext("Ready."));

    update_panels();
    doupdate();

    return(retval);
}

static int
create_portrange_string(const int debuglvl, struct vrmr_portdata *portrange_ptr, char *buf, size_t size)
{
    char    proto[5] = "",
            src[12] = "",
            dst[12] = "",
            icmp_name[32] = "";

    if(portrange_ptr->protocol == 1)
    {
        strcpy(proto, "ICMP");
        snprintf(src, sizeof(src), "TYPE=%2d", portrange_ptr->dst_low);
        snprintf(dst, sizeof(dst), "CODE=%2d", portrange_ptr->dst_high);

        vrmr_get_icmp_name_short(portrange_ptr->dst_low, portrange_ptr->dst_high, icmp_name, sizeof(icmp_name), 0);
        snprintf(buf, size, "ICMP: T:%d, C:%d (%s)", portrange_ptr->dst_low, portrange_ptr->dst_high, icmp_name);
    }
    else if(portrange_ptr->protocol == 6)
        strcpy(proto, "TCP");
    else if(portrange_ptr->protocol == 17)
        strcpy(proto, "UDP");
    else if(portrange_ptr->protocol == 47)
    {
        /* no ports */
        snprintf(buf, size, "GRE");
    }
    else if(portrange_ptr->protocol == 50)
    {
        /* no ports */
        snprintf(buf, size, "ESP");
    }
    else if(portrange_ptr->protocol == 51)
    {
        /* no ports */
        snprintf(buf, size, "AH");
    }
    else
    {
        /* no ports */
        snprintf(buf, size, "Protocol=%d", portrange_ptr->protocol);
    }

    if(portrange_ptr->protocol == 6 || portrange_ptr->protocol == 17)
    {
        if(portrange_ptr->src_high == 0)
            snprintf(src, sizeof(src), "%d", portrange_ptr->src_low);
        else
            snprintf(src, sizeof(src), "%d:%d", portrange_ptr->src_low, portrange_ptr->src_high);

        if(portrange_ptr->dst_high == 0)
            snprintf(dst, sizeof(dst), "%d", portrange_ptr->dst_low);
        else
            snprintf(dst, sizeof(dst), "%d:%d", portrange_ptr->dst_low, portrange_ptr->dst_high);

        snprintf(buf, size, "%s: %s -> %s", proto, src, dst);
    }

    return(0);
}


static int
edit_serv_portranges_new(const int debuglvl, struct vrmr_ctx *vctx, struct vrmr_service *ser_ptr)
{
    int             retval=0;
    char            str[64] = "";

    /* select protocol setup */
    char            *choice_ptr = NULL,
                    *choices[]= { "TCP", "UDP", "ICMP", "GRE", "AH", "ESP", "Other" };
    size_t          n_choices = 7;

    struct vrmr_portdata *portrange_ptr = NULL;

    /* safety */
    if(!ser_ptr)
    {
        vrmr_error(-1, VR_INTERR, "parameter problem (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    /* alloc a new portrange */
    if(!(portrange_ptr = malloc(sizeof(struct vrmr_portdata))))
    {
        vrmr_error(-1, VR_ERR, gettext("malloc failed: %s (in: %s:%d)."), strerror(errno), __FUNCTION__, __LINE__);
        return(-1);
    }

    /*
        get the new portrange protocol
    */
    choice_ptr = selectbox(gettext("New portrange"), gettext("Select a Protocol"), n_choices, choices, 1, NULL);
    if(choice_ptr != NULL)
    {
        if(strncmp(choice_ptr, "TCP", 3) == 0)
        {
            portrange_ptr->protocol = 6;
            portrange_ptr->src_low  = 1024;
            portrange_ptr->src_high = 65535;
            portrange_ptr->dst_low  = 0;
            portrange_ptr->dst_high = 0;

            if(edit_tcpudp(debuglvl, portrange_ptr) < 0)
                retval = -1;
        }
        else if(strncmp(choice_ptr, "UDP", 3) == 0)
        {
            portrange_ptr->protocol = 17;
            portrange_ptr->src_low  = 1024;
            portrange_ptr->src_high = 65535;
            portrange_ptr->dst_low  = 0;
            portrange_ptr->dst_high = 0;

            if(edit_tcpudp(debuglvl, portrange_ptr) < 0)
                retval = -1;
        }
        else if(strncmp(choice_ptr, "ICMP", 4) == 0)
        {
            portrange_ptr->protocol = 1;
            portrange_ptr->src_low  = 0;
            portrange_ptr->src_high = 0;
            portrange_ptr->dst_low  = 0;
            portrange_ptr->dst_high = 0;

            if(edit_icmp(debuglvl, portrange_ptr) < 0)
                retval = -1;
        }
        else if(strncmp(choice_ptr, "GRE", 3) == 0)
        {
            /* gre has no ports */
            portrange_ptr->protocol = 47;
            portrange_ptr->src_low  =  0;
            portrange_ptr->src_high =  0;
            portrange_ptr->dst_low  =  0;
            portrange_ptr->dst_high =  0;
        }
        else if(strncmp(choice_ptr, "ESP", 3) == 0)
        {
            /* gre has no ports */
            portrange_ptr->protocol = 50;
            portrange_ptr->src_low  =  0;
            portrange_ptr->src_high =  0;
            portrange_ptr->dst_low  =  0;
            portrange_ptr->dst_high =  0;
        }
        else if(strncmp(choice_ptr, "AH", 2) == 0)
        {
            /* gre has no ports */
            portrange_ptr->protocol = 51;
            portrange_ptr->src_low  =  0;
            portrange_ptr->src_high =  0;
            portrange_ptr->dst_low  =  0;
            portrange_ptr->dst_high =  0;
        }
        else if(strncmp(choice_ptr, "Other", 5) == 0)
        {
            char *protostr = input_box(4, gettext("Protocol"), gettext("Enter protocol number"));
            if (protostr != NULL) {
                int proto = atoi(protostr);
                if (proto >= 0 && proto <= 255) {
                    portrange_ptr->protocol = proto;
                    portrange_ptr->src_low  =  0;
                    portrange_ptr->src_high =  0;
                    portrange_ptr->dst_low  =  0;
                    portrange_ptr->dst_high =  0;
                } else {
                    vrmr_error(-1, VR_ERR, gettext("invalid protocol. Enter a number in the range 0-255."));
                    retval = -1;
                }
            }
        }
        else
        {
            vrmr_error(-1, VR_INTERR, "undefined protocol '%s' (%s:%d).", choice_ptr, __FUNC__, __LINE__);
            free(choice_ptr);
            return(-1);
        }

        /* free the choiceptr */
        free(choice_ptr);
    }

    if(retval == 0)
    {
        if(edit_serv_portranges_new_validate(debuglvl, vctx, ser_ptr, portrange_ptr) < 0)
            retval = -1;
    }

    if(retval == 0)
    {
        create_portrange_string(debuglvl, portrange_ptr, str, sizeof(str));

        /* example: "service 'X-5' has been changed: portrange 'TCP: 1024:65535 -> 6005' was added." */
        vrmr_audit("%s '%s' %s: %s '%s' %s.",
                            STR_SERVICE, ser_ptr->name, STR_HAS_BEEN_CHANGED,
                            STR_PORTRANGE, str, STR_HAS_BEEN_ADDED);
    }

    return(retval);
}


/*  edit_serv_portranges_edit

    Edit a portrange at place.

    Returncodes:
        -1: error
         0: ok, not editted (e.g. GRE, which cannot be editted)
         1: ok, editted 
*/
static int
edit_serv_portranges_edit(const int debuglvl, int place, struct vrmr_service *ser_ptr)
{
    int             i = 0;
    struct vrmr_list_node     *d_node = NULL;
    struct vrmr_portdata *port_ptr = NULL;


    /* safety */
    if(ser_ptr == 0)
    {
        vrmr_error(-1, VR_INTERR, "parameter problem (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }
    
    /* loop trough the list until we are at 'place'. */
    for(i = 1, d_node = ser_ptr->PortrangeList.top; d_node; d_node = d_node->next, i++)
    {
        /* here we are */
        if(place == i)
        {
            port_ptr = d_node->data;
            if(port_ptr == NULL)
            {
                vrmr_error(-1, VR_INTERR, "NULL pointer (in: %s:%d).", __FUNC__, __LINE__);
                return(-1);
            }

            if(port_ptr->protocol == 6 || port_ptr->protocol == 17)
            {
                edit_tcpudp(debuglvl, port_ptr);
                /* return 1 so the caller knows we editted it! */
                return(1);
            }
            else if(port_ptr->protocol == 1)
            {
                edit_icmp(debuglvl, port_ptr);
                /* return 1 so the caller knows we editted it! */
                return(1);
            }
            else if(port_ptr->protocol == 41 ||
                port_ptr->protocol == 47 ||
                port_ptr->protocol == 50 ||
                port_ptr->protocol == 51)
            {
                vrmr_warning(VR_WARN, gettext("this protocol can only be removed or added."), port_ptr->protocol);
                return(0);
            }
            else
            {
                vrmr_warning(VR_WARN, gettext("edit of protocol %d not supported."), port_ptr->protocol);
                return(0);
            }
        }
    }

    /* hmmm, this is really an error i think */
    return(0);
}


/*  edit_serv_portranges_del

    Removes a portrange at place from a service.

    Returncodes:
        -1: error
         0: not removed, user canceled
         1: removed
*/
static int
edit_serv_portranges_del(const int debuglvl, struct vrmr_ctx *vctx, int place, struct vrmr_service *ser_ptr)
{
    int             i = 0;
    struct vrmr_list_node     *d_node = NULL;
    char            str[64] = "";
    struct vrmr_portdata *portrange_ptr = NULL;

    /* safety */
    if(ser_ptr == 0)
    {
        vrmr_error(-1, VR_INTERR, "parameter problem (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }
    
    /* get user confimation */
    if (confirm(gettext("Delete portrange"), gettext("Are you sure?"),
                vccnf.color_win_note, vccnf.color_win_note_rev|A_BOLD, 0) == 0)
        return(0);

    /* loop trough the list until we are at 'place'. */
    for(i = 1, d_node = ser_ptr->PortrangeList.top; d_node; d_node = d_node->next, i++)
    {
        /* here we are */
        if(place == i)
        {
            portrange_ptr = d_node->data;

            create_portrange_string(debuglvl, portrange_ptr, str, sizeof(str));

            /* remove */
            if(vrmr_list_remove_node(debuglvl, &ser_ptr->PortrangeList, d_node) < 0)
            {
                vrmr_error(-1, VR_INTERR, "unable to delete portrange '%d' from service '%s' (in: %s).", place, ser_ptr->name, __FUNC__);
                return(-1);
            }

            /* save */
            if (vrmr_services_save_portranges(debuglvl, vctx, ser_ptr) < 0)
            {
                vrmr_error(-1, VR_ERR, gettext("saving the portranges failed (in: %s:%d)."), __FUNC__, __LINE__);
                return(-1);
            }

            /* TRANSLATORS: example: "service 'http' has been changed: portrange 'TCP: 1024:65535->80' was removed." */
            vrmr_audit("%s '%s' %s: %s '%s' %s.", STR_SERVICE, ser_ptr->name, STR_HAS_BEEN_CHANGED,
                                    STR_PORTRANGE, str, STR_HAS_BEEN_REMOVED);

            /* return 1 so the caller knows we removed it! */
            return(1);
        }
    }

    /* hmmm, this is really an error i think */
    return(0);
}


static int
edit_serv_portranges_init(const int debuglvl, struct vrmr_service *ser_ptr)
{
    int             retval = 0;
    struct vrmr_list_node     *d_node = NULL;
    int             i=0;
    int             height = 30,
                    width  = 64, // max width of host_name (32) + box (2) + 4 + 16
                    startx = 5,
                    starty = 5,
                    max_height,
                    max_width;
    struct vrmr_portdata *portrange_ptr = NULL;

    char            *port_string_ptr = NULL,
                    *item_number_ptr = NULL,
                    proto[5] = "",
                    src[12] = "",
                    dst[12] = "",
                    icmp_name[32] = "";
    size_t          rangestr_size = 57; /* max length of the string */
    size_t          itemnr_size = 5;    /* max length of the itemnr str */

    /* safety */
    if(ser_ptr == NULL)
    {
        vrmr_error(-1, VR_INTERR, "parameter problem (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }
    
    /* get number of items and calloc them */
    ServicesSection.EditServicePrt.n_items = ser_ptr->PortrangeList.len;

    /* get some mem for the menu items */
    ServicesSection.EditServicePrt.items = (ITEM **)calloc(ServicesSection.EditServicePrt.n_items + 1, sizeof(ITEM *));
    if(ServicesSection.EditServicePrt.items == NULL)
    {
        vrmr_error(-1, VR_ERR, gettext("calloc failed: %s (in: %s:%d)."), strerror(errno), __FUNC__, __LINE__);
        return(-1);
    }

    getmaxyx(stdscr, max_height, max_width);

    /* get window height */
    height = (int)ServicesSection.EditServicePrt.n_items + 8;   /* 8 because: 3 above the list, 5 below */
    if((height + 6) > max_height)
        height = max_height - 6;

    /* place on the same y as "edit service" */
    VrWinGetOffset(-1, -1, height, width, 4, ServicesSection.EditService.se_xre + 1, &starty, &startx);

    // string item list
    vrmr_list_setup(debuglvl, &ServicesSection.EditServicePrt.item_list, free);
    // number item list
    vrmr_list_setup(debuglvl, &ServicesSection.EditServicePrt.item_number_list, free);

    for(i = 0, d_node = ser_ptr->PortrangeList.top; d_node ; d_node = d_node->next, i++)
    {
        portrange_ptr = d_node->data;
        if(portrange_ptr == NULL)
        {
            vrmr_error(-1, VR_INTERR, "NULL pointer (in: %s:%d).", __FUNC__, __LINE__);
            return(-1);
        }

        /* item number */
        if(!(item_number_ptr = malloc(itemnr_size)))
        {
            vrmr_error(-1, VR_ERR, gettext("malloc failed: %s (in: %s:%d)."), strerror(errno), __FUNC__, __LINE__);
            return(-1);
        }
        snprintf(item_number_ptr, itemnr_size, "%3d", i + 1);

        /* range string */
        if(!(port_string_ptr = malloc(rangestr_size)))
        {
            vrmr_error(-1, VR_ERR, gettext("malloc failed: %s (in: %s:%d)."), strerror(errno), __FUNC__, __LINE__);
            return(-1);
        }

        if(portrange_ptr->protocol == 1)
        {
            strcpy(proto, "ICMP");
            snprintf(src, sizeof(src), "TYPE=%2d", portrange_ptr->dst_low);
            snprintf(dst, sizeof(dst), "CODE=%2d", portrange_ptr->dst_high);

            vrmr_get_icmp_name_short(portrange_ptr->dst_low, portrange_ptr->dst_high, icmp_name, sizeof(icmp_name), 0);
            snprintf(port_string_ptr, rangestr_size, "ICMP: T:%2d, C:%2d (%s)", portrange_ptr->dst_low, portrange_ptr->dst_high, icmp_name);
        }
        else if(portrange_ptr->protocol == 6)
            strcpy(proto, "TCP");
        else if(portrange_ptr->protocol == 17)
            strcpy(proto, "UDP");
        else if(portrange_ptr->protocol == 47)
        {
            /* no ports */
            snprintf(port_string_ptr, rangestr_size, "GRE : %s", STR_PROTO_NO_PORTS);
        }
        else if(portrange_ptr->protocol == 50)
        {
            /* no ports */
            snprintf(port_string_ptr, rangestr_size, "ESP : %s", STR_PROTO_NO_PORTS);
        }
        else if(portrange_ptr->protocol == 51)
        {
            /* no ports */
            snprintf(port_string_ptr, rangestr_size, "AH  : %s", STR_PROTO_NO_PORTS);
        }
        else
        {
            /* no ports */
            snprintf(port_string_ptr, rangestr_size, "%d  : %s", portrange_ptr->protocol, STR_PROTO_NO_PORTS);
        }

        if(portrange_ptr->protocol == 6 || portrange_ptr->protocol == 17)
        {
            if(portrange_ptr->src_high == 0)
                snprintf(src, sizeof(src), "%d", portrange_ptr->src_low);
            else
                snprintf(src, sizeof(src), "%d:%d", portrange_ptr->src_low, portrange_ptr->src_high);

            if(portrange_ptr->dst_high == 0)
                snprintf(dst, sizeof(dst), "%d", portrange_ptr->dst_low);
            else
                snprintf(dst, sizeof(dst), "%d:%d", portrange_ptr->dst_low, portrange_ptr->dst_high);

            snprintf(port_string_ptr, rangestr_size, "%-4s: %-12s -> %-12s", proto, src, dst);
        }

        /* load all into item array */
        ServicesSection.EditServicePrt.items[i] = new_item(item_number_ptr, port_string_ptr);
        if(ServicesSection.EditServicePrt.items[i] == NULL)
        {
            vrmr_error(-1, VR_INTERR, "new_item() failed (in: %s:%d).", __FUNC__, __LINE__);
            return(-1);
        }

        /* store in list */
        if(vrmr_list_append(debuglvl, &ServicesSection.EditServicePrt.item_list, port_string_ptr)  == NULL)
        {
            vrmr_error(-1, VR_INTERR, "vrmr_list_append() failed (in: %s:%d).", __FUNC__, __LINE__);
            return(-1);
        }
        if(vrmr_list_append(debuglvl, &ServicesSection.EditServicePrt.item_number_list, item_number_ptr)  == NULL)
        {
            vrmr_error(-1, VR_INTERR, "vrmr_list_append() failed (in: %s:%d).", __FUNC__, __LINE__);
            return(-1);
        }
    }
    ServicesSection.EditServicePrt.items[ServicesSection.EditServicePrt.n_items] = (ITEM *)NULL;

    /* create win and panel */
    ServicesSection.EditServicePrt.win = newwin(height, width, starty, startx);
    if(ServicesSection.EditServicePrt.win == NULL)
    {
        vrmr_error(-1, VR_INTERR, "newwin() failed (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    wbkgd(ServicesSection.EditServicePrt.win, vccnf.color_win);
    keypad(ServicesSection.EditServicePrt.win, TRUE);

    ServicesSection.EditServicePrt.panel[0] = new_panel(ServicesSection.EditServicePrt.win);
    if(ServicesSection.EditServicePrt.panel[0] == NULL)
    {
        vrmr_error(-1, VR_INTERR, "new_panel() failed (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    ServicesSection.EditServicePrt.menu = new_menu((ITEM **)ServicesSection.EditServicePrt.items);
    if(ServicesSection.EditServicePrt.menu == NULL)
    {
        vrmr_error(-1, VR_INTERR, "new_menu() failed (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    set_menu_win(ServicesSection.EditServicePrt.menu, ServicesSection.EditServicePrt.win);
    set_menu_sub(ServicesSection.EditServicePrt.menu, derwin(ServicesSection.EditServicePrt.win, height-8, width-2, 3, 1));
    set_menu_format(ServicesSection.EditServicePrt.menu, height-8, 1);

    box(ServicesSection.EditServicePrt.win, 0, 0);
    print_in_middle(ServicesSection.EditServicePrt.win, 1, 0, width, STR_CPORTRANGES, vccnf.color_win);
    mvwaddch(ServicesSection.EditServicePrt.win, 2, 0, ACS_LTEE);
    mvwhline(ServicesSection.EditServicePrt.win, 2, 1, ACS_HLINE, width-2);
    mvwaddch(ServicesSection.EditServicePrt.win, 2, width-1, ACS_RTEE);

    set_menu_back(ServicesSection.EditServicePrt.menu, vccnf.color_win);
    set_menu_fore(ServicesSection.EditServicePrt.menu, vccnf.color_win_rev);

    post_menu(ServicesSection.EditServicePrt.menu);

    mvwaddch(ServicesSection.EditServicePrt.win, height-5, 0, ACS_LTEE);
    mvwhline(ServicesSection.EditServicePrt.win, height-5, 1, ACS_HLINE, width-2);
    mvwaddch(ServicesSection.EditServicePrt.win, height-5, width-1, ACS_RTEE);

    mvwprintw(ServicesSection.EditServicePrt.win, height-4, 2, "<INS> %s", STR_NEW);
    mvwprintw(ServicesSection.EditServicePrt.win, height-3, 2, "<DEL> %s", STR_REMOVE);
    mvwprintw(ServicesSection.EditServicePrt.win, height-2, 2, "<RET> %s", STR_EDIT);

    update_panels();
    doupdate();
    wrefresh(ServicesSection.EditServicePrt.win);

    return(retval);
}


static int
edit_serv_portranges_destroy(const int debuglvl)
{
    int     retval=0;
    size_t  i = 0;

    // Un post form and free the memory
    unpost_menu(ServicesSection.EditServicePrt.menu);
    free_menu(ServicesSection.EditServicePrt.menu);

    for(i=0;i<ServicesSection.EditServicePrt.n_items;i++)
    {
        free_item(ServicesSection.EditServicePrt.items[i]);
    }
    free(ServicesSection.EditServicePrt.items);

    del_panel(ServicesSection.EditServicePrt.panel[0]);
    destroy_win(ServicesSection.EditServicePrt.win);

    vrmr_list_cleanup(debuglvl, &ServicesSection.EditServicePrt.item_list);
    vrmr_list_cleanup(debuglvl, &ServicesSection.EditServicePrt.item_number_list);

    update_panels();
    doupdate();

    return(retval);
}

static int
edit_serv_portranges(const int debuglvl, struct vrmr_ctx *vctx, struct vrmr_service *ser_ptr)
{
    int     quit = 0,
            reload = 0,
            result = 0,
            ch,
            retval = 0;
    ITEM    *cur = NULL;
    /* top menu */
    char    *key_choices[] =    {   "F12",
                                    "INS",
                                    "RET",
                                    "DEL",
                                    "F10"};
    int     key_choices_n = 5;
    char    *cmd_choices[] =    {   gettext("help"),
                                    gettext("new"),
                                    gettext("edit"),
                                    gettext("del"),
                                    gettext("back")};
    int     cmd_choices_n = 5;

    /* safety */
    if(ser_ptr == NULL)
    {
        vrmr_error(-1, VR_INTERR, "parameter problem (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    if(edit_serv_portranges_init(debuglvl, ser_ptr) < 0)
        return(-1);

    draw_top_menu(debuglvl, top_win, gettext("Edit Portrange"), key_choices_n, key_choices, cmd_choices_n, cmd_choices);

    while(quit == 0)
    {
        if(reload == 1)
        {
            result = edit_serv_portranges_destroy(debuglvl);
            if(result < 0)
                return(-1);

            result = edit_serv_portranges_init(debuglvl, ser_ptr);
            if(result < 0)
                return(-1);

            update_panels();
            doupdate();

            reload=0;
        }

        while(quit == 0 && reload == 0)
        {
            ch = wgetch(ServicesSection.EditServicePrt.win);
            switch(ch)
            {
                case 27:
                case 'q':
                case 'Q':
                case KEY_F(10): /* quit */

                    quit = 1;
                    break;

                case KEY_IC:
                case 'i':
                case 'I':

                    if(edit_serv_portranges_new(debuglvl, vctx, ser_ptr) < 0)
                        retval= -1;
                    else
                        reload = 1;

                    draw_top_menu(debuglvl, top_win, gettext("Edit Portrange"), key_choices_n, key_choices, cmd_choices_n, cmd_choices);
                    break;

                case KEY_DC:
                case 'd':
                case 'D':
                {
                    if((cur = current_item(ServicesSection.EditServicePrt.menu)))
                    {
                        result = edit_serv_portranges_del(debuglvl, vctx, atoi((char *)item_name(cur)), ser_ptr);
                        if(result < 0)
                            retval=-1;
                        else if(result == 1)
                            reload=1;
                    }
                    break;
                }

                case 10:
                case 'e':
                case 'E':
                {
                    if((cur = current_item(ServicesSection.EditServicePrt.menu)))
                    {
                        result = edit_serv_portranges_edit(debuglvl, atoi((char *)item_name(cur)), ser_ptr);
                        if(result < 0)
                            retval=-1;
                        else if(result == 1)
                            reload=1;
                    }

                    draw_top_menu(debuglvl, top_win, gettext("Edit Portrange"), key_choices_n, key_choices, cmd_choices_n, cmd_choices);
                    break;
                }

                case KEY_DOWN:
                    menu_driver(ServicesSection.EditServicePrt.menu, REQ_DOWN_ITEM);
                    break;
                case KEY_UP:
                    menu_driver(ServicesSection.EditServicePrt.menu, REQ_UP_ITEM);
                    break;
                case KEY_NPAGE:
                    menu_driver(ServicesSection.EditServicePrt.menu, REQ_SCR_DPAGE); // page up
                    break;
                case KEY_PPAGE:
                    menu_driver(ServicesSection.EditServicePrt.menu, REQ_SCR_UPAGE); // page down
                    break;
                case KEY_HOME:
                    menu_driver(ServicesSection.EditServicePrt.menu, REQ_FIRST_ITEM); // page up
                    break;
                case KEY_END:
                    menu_driver(ServicesSection.EditServicePrt.menu, REQ_LAST_ITEM); // page down
                    break;

                case KEY_F(12):
                case 'h':
                case 'H':
                case '?':
                    print_help(debuglvl, ":[VUURMUUR:SERVICE:EDIT:PORTRANGE]:");
                    break;
            }
        }
    }

    result = edit_serv_portranges_destroy(debuglvl);
    if(result < 0)
        retval = -1;

    return(retval);

}


struct
{
    FIELD   *activelabelfld,
            *activefld,
        
            *broadcastlabelfld,
            *broadcastfld,
            
            *commentlabelfld,
            *commentfld,
            
            *helperlabelfld,
            *helperfld,
            
            *norangewarningfld;

} ServiceSec;


static int
edit_service_save(const int debuglvl, struct vrmr_ctx *vctx, struct vrmr_service *ser_ptr)
{
    int     retval=0,
            result = 0,
            active = 0,
            broadcast = 0;
    char    helper[sizeof(ser_ptr->helper)] = "";
    size_t  i = 0;

    // check for changed fields
    for(i=0; i < ServicesSection.EditService.n_fields; i++)
    {
        if(field_status(ServicesSection.EditService.fields[i]) == TRUE)
        {
            /* active */
            if(ServicesSection.EditService.fields[i] == ServiceSec.activefld)
            {
                active = ser_ptr->active;

                ser_ptr->status = VRMR_ST_CHANGED;
                if(strncasecmp(field_buffer(ServicesSection.EditService.fields[i], 0), STR_YES, StrLen(STR_YES)) == 0)
                {
                    ser_ptr->active = 1;
                }
                else
                {
                    ser_ptr->active = 0;
                }

                result = vctx->sf->tell(debuglvl, vctx->serv_backend, ser_ptr->name, "ACTIVE", ser_ptr->active ? "Yes" : "No", 1, VRMR_TYPE_SERVICE);
                if(result < 0)
                {
                    vrmr_error(-1, VR_ERR, gettext("saving to backend failed (in: %s:%d)."), __FUNC__, __LINE__);
                    retval = -1;
                }

                /* example: "service 'http' has been changed: active is now set to 'Yes' (was: 'No')." */
                vrmr_audit("%s '%s' %s: %s %s '%s' (%s: '%s').",
                                STR_SERVICE, ser_ptr->name, STR_HAS_BEEN_CHANGED,
                                STR_ACTIVE, STR_IS_NOW_SET_TO, ser_ptr->active ? "Yes" : "No",
                                STR_WAS, active ? "Yes" : "No");
            }
            /* broadcast */
            else if(ServicesSection.EditService.fields[i] == ServiceSec.broadcastfld)
            {
                broadcast = ser_ptr->broadcast;

                ser_ptr->status = VRMR_ST_CHANGED;

                if(strncasecmp(field_buffer(ServicesSection.EditService.fields[i], 0), STR_YES, StrLen(STR_YES)) == 0)
                {
                    ser_ptr->broadcast = 1;
                }
                else
                {
                    ser_ptr->broadcast = 0;
                }

                result = vctx->sf->tell(debuglvl, vctx->serv_backend, ser_ptr->name, "BROADCAST", ser_ptr->broadcast ? "Yes" : "No", 1, VRMR_TYPE_SERVICE);
                if(result < 0)
                {
                    vrmr_error(-1, VR_ERR, gettext("saving to backend failed (in: %s:%d)."), __FUNC__, __LINE__);
                    retval = -1;
                }

                /* example: service 'samba' has been changed: broadcast is now set to 'No' (was: 'Yes') */
                vrmr_audit("%s '%s' %s: %s %s '%s' (%s: '%s').",
                                STR_SERVICE, ser_ptr->name, STR_HAS_BEEN_CHANGED,
                                STR_BROADCAST, STR_IS_NOW_SET_TO, ser_ptr->broadcast ? "Yes" : "No",
                                STR_WAS, broadcast ? "Yes" : "No");
            }
            /* helper field */
            else if(ServicesSection.EditService.fields[i] == ServiceSec.helperfld)
            {
                (void)strlcpy(helper, ser_ptr->helper, sizeof(helper));

                if(!(copy_field2buf(ser_ptr->helper,
                                    field_buffer(ServicesSection.EditService.fields[i], 0),
                                    sizeof(ser_ptr->helper))))
                    return(-1);

                if (vctx->sf->tell(debuglvl, vctx->serv_backend, ser_ptr->name, "HELPER", ser_ptr->helper, 1, VRMR_TYPE_SERVICE) < 0)
                {
                    vrmr_error(-1, VR_ERR, gettext("saving to backend failed (in: %s:%d)."), __FUNC__, __LINE__);
                    return(-1);
                }

                /* example: service 'ftp' has been changed: protocol helper is set to 'ftp' (was: 'none'). */
                vrmr_audit("%s '%s' %s: %s %s '%s' (%s: '%s').",
                                STR_SERVICE, ser_ptr->name, STR_HAS_BEEN_CHANGED,
                                STR_PROTOHELP, STR_IS_NOW_SET_TO, ser_ptr->helper,
                                STR_WAS, helper);
            }
            /* comment */
            else if(ServicesSection.EditService.fields[i] == ServiceSec.commentfld)
            {
                result = vctx->sf->tell(debuglvl, vctx->serv_backend, ser_ptr->name, "COMMENT", field_buffer(ServicesSection.EditService.fields[i], 0), 1, VRMR_TYPE_SERVICE);
                if(result < 0)
                {
                    vrmr_error(-1, VR_ERR, gettext("saving to backend failed (in: %s:%d)."), __FUNC__, __LINE__);
                    retval = -1;
                }

                /* example: "service '%s' has been changed: the comment has been changed." */
                vrmr_audit("%s '%s' %s: %s.", 
                                STR_SERVICE, ser_ptr->name, STR_HAS_BEEN_CHANGED,
                                STR_COMMENT_CHANGED);
            }
        }
    }
    return(retval);
}


static int
edit_service_init(const int debuglvl, struct vrmr_ctx *vctx, struct vrmr_service *ser_ptr)
{
    int             rows,
                    cols,
                    comment_y=0,
                    comment_x=0;
    int             height, width, starty, startx, max_height, max_width;
    struct vrmr_portdata *portrange_ptr = NULL;
    struct vrmr_list_node     *d_node = NULL;
    size_t          field_num = 0,
                    i = 0;

    /* safety */
    if(ser_ptr == NULL)
    {
        vrmr_error(-1, VR_INTERR, "parameter problem (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    memset(&ServiceSec, 0, sizeof(ServiceSec));

    /* get the screen dimentions for dynamically
     * sizing the window */
    getmaxyx(stdscr, max_height, max_width);
    height = 20 + ser_ptr->PortrangeList.len;
    if(height > max_height - 6)
        height = max_height - 6;
    width = 54;

    /* place on the same y as "edit service" */
    VrWinGetOffset(-1, -1, height, width, 4, ServicesSection.sl_xre + 1, &starty, &startx);
    ServicesSection.EditService.se_xre = startx + width;
    ServicesSection.EditService.se_yle = starty + height;

    /* 4 fields: active, broadcast, comment and helper */
    ServicesSection.EditService.n_fields = 9;
    if(!(ServicesSection.EditService.fields = (FIELD **)calloc(ServicesSection.EditService.n_fields + 1, sizeof(FIELD *))))
    {
        vrmr_error(-1, VR_ERR, gettext("calloc failed: %s (in: %s:%d)."), strerror(errno), __FUNCTION__, __LINE__);
        return(-1);
    }

    /* active */
    ServiceSec.activelabelfld = (ServicesSection.EditService.fields[field_num++] = new_field(1, 10, 2, 0, 0, 0));
    set_field_buffer_wrap(debuglvl, ServiceSec.activelabelfld, 0, gettext("Active"));
    field_opts_off(ServiceSec.activelabelfld, O_ACTIVE);

    ServiceSec.activefld = (ServicesSection.EditService.fields[field_num++] = new_field(1, 3, 3, 1, 0, 0));
    set_field_buffer_wrap(debuglvl, ServiceSec.activefld, 0, ser_ptr->active ? STR_YES : STR_NO);

    /* broadcast */
    ServiceSec.broadcastlabelfld = (ServicesSection.EditService.fields[field_num++] = new_field(1, 16, 5, 0, 0, 0));
    set_field_buffer_wrap(debuglvl, ServiceSec.broadcastlabelfld, 0, gettext("Broadcast"));
    field_opts_off(ServiceSec.broadcastlabelfld, O_ACTIVE);

    ServiceSec.broadcastfld = (ServicesSection.EditService.fields[field_num++] = new_field(1, 3, 6, 1, 0, 0));
    set_field_buffer_wrap(debuglvl, ServiceSec.broadcastfld, 0, ser_ptr->broadcast ? STR_YES : STR_NO);

    /* helper */
    ServiceSec.helperlabelfld = (ServicesSection.EditService.fields[field_num++] = new_field(1, 16, 2, 16, 0, 0));
    set_field_buffer_wrap(debuglvl, ServiceSec.helperlabelfld, 0, gettext("Protocol helper"));
    field_opts_off(ServiceSec.helperlabelfld, O_ACTIVE);

    ServiceSec.helperfld = (ServicesSection.EditService.fields[field_num++] = new_field(1, 32, 3, 17, 0, 0));
    set_field_buffer_wrap(debuglvl, ServiceSec.helperfld, 0, ser_ptr->helper);

    ServiceSec.commentlabelfld = (ServicesSection.EditService.fields[field_num++] = new_field(1, 16, 8, 0, 0, 0));
    set_field_buffer_wrap(debuglvl, ServiceSec.commentlabelfld, 0, gettext("Comment"));
    field_opts_off(ServiceSec.commentlabelfld, O_ACTIVE);

    /* comment field size */
    comment_y = 5;
    comment_x = 48;
    /* load the comment from the backend */
    if (vctx->sf->ask(debuglvl, vctx->serv_backend, ser_ptr->name, "COMMENT", ServicesSection.comment, sizeof(ServicesSection.comment), VRMR_TYPE_SERVICE, 0) < 0)
        vrmr_error(-1, VR_ERR, gettext("error while loading the comment."));

    ServiceSec.commentfld = (ServicesSection.EditService.fields[field_num++] = new_field(comment_y, comment_x, 9, 1, 0, 0));
    set_field_buffer_wrap(debuglvl, ServiceSec.commentfld, 0, ServicesSection.comment);

    ServiceSec.norangewarningfld = (ServicesSection.EditService.fields[field_num++] = new_field(1, 48, 14, 1, 0, 0));
    set_field_buffer_wrap(debuglvl, ServiceSec.norangewarningfld, 0, gettext("Warning: no port(range)s defined!"));
    field_opts_off(ServiceSec.norangewarningfld, O_VISIBLE|O_ACTIVE);
    set_field_just(ServiceSec.norangewarningfld, JUSTIFY_CENTER);

    if (ServicesSection.EditService.n_fields != field_num) {
        vrmr_error(-1, VR_INTERR, "parameter problem (in: %s:%d).",
                __FUNC__, __LINE__);
        return(-1);
    }

    /* terminate */
    ServicesSection.EditService.fields[ServicesSection.EditService.n_fields] = NULL;

    for(i = 0; i < ServicesSection.EditService.n_fields; i++)
    {
        // set field options
        set_field_back(ServicesSection.EditService.fields[i], vccnf.color_win_rev);
        field_opts_off(ServicesSection.EditService.fields[i], O_AUTOSKIP);
        // set status to false
        set_field_status(ServicesSection.EditService.fields[i], FALSE);
    }

    set_field_back(ServiceSec.activelabelfld, vccnf.color_win);
    set_field_back(ServiceSec.broadcastlabelfld, vccnf.color_win);
    set_field_back(ServiceSec.helperlabelfld, vccnf.color_win);
    set_field_back(ServiceSec.commentlabelfld, vccnf.color_win);

    set_field_back(ServiceSec.norangewarningfld, vccnf.color_win);
    set_field_fore(ServiceSec.norangewarningfld, vccnf.color_win_warn|A_BOLD);

    /* create window and panel */
    ServicesSection.EditService.win = create_newwin(height, width, starty, startx, gettext("Edit Service"), vccnf.color_win);
    keypad(ServicesSection.EditService.win, TRUE);
    ServicesSection.EditService.panel[0] = new_panel(ServicesSection.EditService.win);

    /* create and post form */
    ServicesSection.EditService.form = new_form(ServicesSection.EditService.fields);
    scale_form(ServicesSection.EditService.form, &rows, &cols);
    set_form_win(ServicesSection.EditService.form, ServicesSection.EditService.win);
    set_form_sub(ServicesSection.EditService.form, derwin(ServicesSection.EditService.win, rows, cols, 1, 2));
    post_form(ServicesSection.EditService.form);

    /* print labels */
    mvwprintw(ServicesSection.EditService.win, 1, 2,  "%s: %s", gettext("Name"), ser_ptr->name);
    mvwprintw(ServicesSection.EditService.win, 16, 1, gettext("Press <F6> to manage the portranges of this service."));
    
    if(height > 16+4)
    {
        mvwprintw(ServicesSection.EditService.win, 18, 2, gettext("List of portranges:"));
        if(ser_ptr->PortrangeList.len == 0)
            mvwprintw(ServicesSection.EditService.win, 19, 4, gettext("No portranges defined yet."));
        else
        {
            for(d_node = ser_ptr->PortrangeList.top, i = 1; d_node; d_node = d_node->next, i++)
            {
                if(!(portrange_ptr = d_node->data))
                    return(-1);

                if(portrange_ptr->protocol == 6)
                    mvwprintw(ServicesSection.EditService.win, (int)(18+i), 2, "  TCP : ");
                else if(portrange_ptr->protocol == 17)
                    mvwprintw(ServicesSection.EditService.win, (int)(18+i), 2, "  UDP : ");
                else if(portrange_ptr->protocol == 1)
                    mvwprintw(ServicesSection.EditService.win, (int)(18+i), 2, "  ICMP: ");
                else if(portrange_ptr->protocol == 47)
                    mvwprintw(ServicesSection.EditService.win, (int)(18+i), 2, "  GRE : ");
                else if(portrange_ptr->protocol == 50)
                    mvwprintw(ServicesSection.EditService.win, (int)(18+i), 2, "  ESP : ");
                else if(portrange_ptr->protocol == 51)
                    mvwprintw(ServicesSection.EditService.win, (int)(18+i), 2, "  AH  : ");
                else
                {
                    mvwprintw(ServicesSection.EditService.win, (int)(18+i), 2, "  %3d : ", portrange_ptr->protocol);
                }

                if(portrange_ptr->protocol == 6 || portrange_ptr->protocol == 17)
                {
                    if(portrange_ptr->src_high == 0)
                        wprintw(ServicesSection.EditService.win, "%11d", portrange_ptr->src_low);
                    else
                        wprintw(ServicesSection.EditService.win, "%5d:%5d", portrange_ptr->src_low, portrange_ptr->src_high);

                    wprintw(ServicesSection.EditService.win, " -> ");

                    if(portrange_ptr->dst_high == 0)
                        wprintw(ServicesSection.EditService.win, "%d", portrange_ptr->dst_low);
                    else
                        wprintw(ServicesSection.EditService.win, "%d:%d", portrange_ptr->dst_low, portrange_ptr->dst_high);
                }
                else if(portrange_ptr->protocol == 1)
                {
                    wprintw(ServicesSection.EditService.win, "type: %d, code: %d.", portrange_ptr->dst_low, portrange_ptr->dst_high);
                }
                else
                {
                    wprintw(ServicesSection.EditService.win, gettext("uses no ports."));
                }

                if((int)(18+i) == height-1) /* -1 is for the border */
                {
                    if((ser_ptr->PortrangeList.len - i) > 1)
                    {
                        mvwprintw(ServicesSection.EditService.win, (int)(18+i+1), 2, gettext("There are %d more portranges. Press F6 to manage."), ser_ptr->PortrangeList.len - i);
                        break;
                    }
                }
            }
        }
    }

    /* position the cursor in the active field */
    pos_form_cursor(ServicesSection.EditService.form);

    return(0);
}


static int
edit_service(const int debuglvl, struct vrmr_ctx *vctx, struct vrmr_services *services, const char *name)
{
    int                     ch, /* for recording keystrokes */
                            quit = 0,
                            not_defined = 0,
                            retval = 0;
    struct vrmr_service    *ser_ptr = NULL;
    FIELD                   *cur = NULL,
                            *prev = NULL;
    /* top menu */
    char                    *key_choices[] =    {   "F12",
                                                    "F6",
                                                    "F10"};
    int                     key_choices_n = 3;
    char                    *cmd_choices[] =    {   gettext("help"),
                                                    gettext("portranges"),
                                                    gettext("back")};
    int                     cmd_choices_n = 3;
    size_t                  i = 0;

    /* safety */
    if(name == NULL || services == NULL)
    {
        vrmr_error(-1, VR_INTERR, "parameter problem (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }
    
    /* search the service */
    if(!(ser_ptr = vrmr_search_service(debuglvl, services, (char *)name)))
    {
        vrmr_error(-1, VR_INTERR, "service '%s' was not found in memory (in: %s:%d).", name, __FUNC__, __LINE__);
        return(-1);
    }

    /* init */
    if(edit_service_init(debuglvl, vctx, ser_ptr) < 0)
        return(-1);

    /* show (or hide) initial warning about the group being empty. */
    if(ser_ptr->PortrangeList.len == 0)
    {
        field_opts_on(ServiceSec.norangewarningfld, O_VISIBLE);
    }

    pos_form_cursor(ServicesSection.EditService.form);
    cur = current_field(ServicesSection.EditService.form);

    draw_top_menu(debuglvl, top_win, gettext("Edit Service"), key_choices_n, key_choices, cmd_choices_n, cmd_choices);

    wrefresh(ServicesSection.EditService.win);
    update_panels();
    doupdate();

    /* Loop through to get user requests */
    while(quit == 0)
    {
        draw_field_active_mark(cur, prev, ServicesSection.EditService.win, ServicesSection.EditService.form, vccnf.color_win_mark|A_BOLD);

        ch = wgetch(ServicesSection.EditService.win);

        not_defined = 0;

        if(cur == ServiceSec.commentfld)
        {
            if(nav_field_comment(debuglvl, ServicesSection.EditService.form, ch) < 0)
                not_defined = 1;
        }
        else if(cur == ServiceSec.helperfld)
        {
            if(nav_field_simpletext(debuglvl, ServicesSection.EditService.form, ch) < 0)
                not_defined = 1;
        }
        else if(cur == ServiceSec.activefld ||
            cur == ServiceSec.broadcastfld)
        {
            if(nav_field_yesno(debuglvl, ServicesSection.EditService.form, ch) < 0)
                not_defined = 1;
        }
        else
        {
            not_defined = 1;
        }

        if(not_defined == 1)
        {
            switch(ch)
            {
                case KEY_F(6):
                case 'e':
                case 'E':
                    /* F6 opens the portranges section */
//TODO
                    edit_serv_portranges(debuglvl, vctx, ser_ptr);

                    draw_top_menu(debuglvl, top_win, gettext("Edit Service"), key_choices_n, key_choices, cmd_choices_n, cmd_choices);
                    break;

                case 27:
                case KEY_F(10):
                case 'q':
                case 'Q':
                    quit=1;
                    break;

                case KEY_DOWN:
                case 10:    // enter
                case 9: // tab

                    form_driver(ServicesSection.EditService.form, REQ_NEXT_FIELD);
                    form_driver(ServicesSection.EditService.form, REQ_END_LINE);
                    break;

                case KEY_UP:

                    form_driver(ServicesSection.EditService.form, REQ_PREV_FIELD);
                    form_driver(ServicesSection.EditService.form, REQ_END_LINE);
                    break;

                case KEY_F(12):
                case 'h':
                case 'H':
                case '?':
                    print_help(debuglvl, ":[VUURMUUR:SERVICE:EDIT]:");
                    break;
            }
        }

        prev = cur;
        cur = current_field(ServicesSection.EditService.form);

        /* print or erase warning about the group being empty. */
        if(ser_ptr->PortrangeList.len == 0)
        {
            field_opts_on(ServiceSec.norangewarningfld, O_VISIBLE);
        }
        else
            field_opts_off(ServiceSec.norangewarningfld, O_VISIBLE);

        wrefresh(ServicesSection.EditService.win);
        pos_form_cursor(ServicesSection.EditService.form);
    }


    /* save */

    /* save the service */
    if (edit_service_save(debuglvl, vctx, ser_ptr) < 0)
    {
        vrmr_error(-1, "Error", "saving the service failed (in: %s).", __FUNC__);
        retval = -1;
    }

    /* save the portranges */
    if (vrmr_services_save_portranges(debuglvl, vctx, ser_ptr) < 0)
    {
        vrmr_error(-1, "Error", "saving the portranges failed (in: %s).", __FUNC__);
        retval = -1;
    }


    /* cleanup */
    
    /* Un post form and free the memory */
    unpost_form(ServicesSection.EditService.form);
    free_form(ServicesSection.EditService.form);

    for(i=0; i < ServicesSection.EditService.n_fields;i++)
    {
        free_field(ServicesSection.EditService.fields[i]);
    }
    free(ServicesSection.EditService.fields);

    del_panel(ServicesSection.EditService.panel[0]);
    destroy_win(ServicesSection.EditService.win);

    /* clear comment */
    strcpy(ServicesSection.comment, "");

    update_panels();
    doupdate();
    
    return(retval);
}


static int
rename_service(const int debuglvl, struct vrmr_ctx *vctx, struct vrmr_services *services,
        struct vrmr_rules *rules, char *cur_name_ptr, char *new_name_ptr)
{
    int                     result = 0;
    struct vrmr_service     *ser_ptr = NULL;
    struct vrmr_rule        *rule_ptr = NULL;
    struct vrmr_list_node   *d_node = NULL;
    char                    changed = 0;
    char                    old_ser_name[VRMR_MAX_SERVICE] = "";

    /* safety */
    if(cur_name_ptr == NULL || new_name_ptr == NULL || services == NULL || rules == NULL)
    {
        vrmr_error(-1, VR_INTERR, "parameter problem (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    if(strlcpy(old_ser_name, cur_name_ptr, sizeof(old_ser_name)) >= sizeof(old_ser_name))
    {
        vrmr_error(-1, VR_INTERR, "servicename overflow (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    if(debuglvl >= HIGH)
        vrmr_debug(__FUNC__, "going to rename service old_ser_name:'%s' to new_name_ptr:'%s'.", old_ser_name, new_name_ptr);

    result = vctx->sf->rename(debuglvl, vctx->serv_backend, old_ser_name, new_name_ptr, VRMR_TYPE_SERVICE);
    if(result != 0)
    {
        return(-1);
    }

    if(!(ser_ptr = vrmr_search_service(debuglvl, services, old_ser_name)))
    {
        vrmr_error(-1, VR_INTERR, "service not found in the list (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    if(strlcpy(ser_ptr->name, new_name_ptr, sizeof(ser_ptr->name)) >= sizeof(ser_ptr->name))
    {
        vrmr_error(-1, VR_INTERR, "servicename overflow (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }
    ser_ptr = NULL;

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
            vrmr_debug(__FUNC__, "service: '%s'.", rule_ptr->service);

        /* check the servicename */
        if(strcmp(rule_ptr->service, old_ser_name) == 0)
        {
            if(debuglvl >= HIGH)
                vrmr_debug(__FUNC__, "found in a rule (was looking for old_ser_name:'%s', found rule_ptr->service:'%s').", old_ser_name, rule_ptr->service);

            /* set the new name to the rules */
            if(strlcpy(rule_ptr->service, new_name_ptr, sizeof(rule_ptr->service)) >= sizeof(rule_ptr->service))
            {
                vrmr_error(-1, VR_INTERR, "servicename overflow (in: %s:%d).", __FUNC__, __LINE__);
                return(-1);
            }
            changed = 1;
        }
    }

    /* if we have made changes we write the rulesfile */
    if(changed == 1)
    {
        if(vrmr_rules_save_list(debuglvl, vctx, rules, &vctx->conf) < 0)
        {
            vrmr_error(-1, VR_ERR, gettext("saving rules failed."));
            return(-1);
        }
    }

    /* example: "service 'htpt' has been renamed to 'http'." */
    vrmr_audit("%s '%s' %s '%s'.", STR_SERVICE, old_ser_name, STR_HAS_BEEN_RENAMED_TO, new_name_ptr);
    return(0);
}


static int
vrmr_init_services_section(const int debuglvl, struct vrmr_services *services, int height, int width, int starty, int startx)
{
    int                     retval=0,
                            i=0;
    struct vrmr_service    *ser_ptr = NULL;
    struct vrmr_list_node             *d_node = NULL;

    ServicesSection.list_items = services->list.len;
    ServicesSection.items = (ITEM **)calloc(ServicesSection.list_items + 1, sizeof(ITEM *));

    for(i = 0, d_node = services->list.top; d_node ; d_node = d_node->next, i++)
    {
        if(!(ser_ptr = d_node->data))
        {
            vrmr_error(-1, VR_INTERR, "NULL pointer (in: %s:%d).", __FUNC__, __LINE__);
            return(-1);
        }

        ServicesSection.items[i] = new_item(ser_ptr->name, NULL);
    }
    ServicesSection.items[ServicesSection.list_items] = (ITEM *)NULL;

    if(ServicesSection.list_items > 0)
    {
        ServicesSection.top = ServicesSection.items[0];
        ServicesSection.bot = ServicesSection.items[ServicesSection.list_items - 1];
    }
    else
    {
        ServicesSection.top = NULL;
        ServicesSection.bot = NULL;
    }

    ServicesSection.win = newwin(height, width, starty, startx);
    wbkgd(ServicesSection.win, vccnf.color_win);
    keypad(ServicesSection.win, TRUE);
    ServicesSection.panel[0] = new_panel(ServicesSection.win);

    ServicesSection.menu = new_menu((ITEM **)ServicesSection.items);
    set_menu_win(ServicesSection.menu, ServicesSection.win);
    set_menu_sub(ServicesSection.menu, derwin(ServicesSection.win, height-7, width-2, 3, 1));
    set_menu_format(ServicesSection.menu, height-8, 1);

    box(ServicesSection.win, 0, 0);
    print_in_middle(ServicesSection.win, 1, 0, width, gettext("Services"), vccnf.color_win);
    mvwaddch(ServicesSection.win, 2, 0, ACS_LTEE);
    mvwhline(ServicesSection.win, 2, 1, ACS_HLINE, width-2);
    mvwaddch(ServicesSection.win, 2, width-1, ACS_RTEE);

    set_menu_back(ServicesSection.menu, vccnf.color_win);
    set_menu_fore(ServicesSection.menu, vccnf.color_win_rev);

    post_menu(ServicesSection.menu);

    mvwaddch(ServicesSection.win, height-5, 0, ACS_LTEE);
    mvwhline(ServicesSection.win, height-5, 1, ACS_HLINE, width-2);
    mvwaddch(ServicesSection.win, height-5, width-1, ACS_RTEE);

    mvwprintw(ServicesSection.win, height-4, 2, "<RET> %s", STR_EDIT);
    mvwprintw(ServicesSection.win, height-3, 2, "<INS> %s", STR_NEW);
    mvwprintw(ServicesSection.win, height-2, 2, "<DEL> %s", STR_REMOVE);

    /* create the top and bottom fields */
    if(!(ServicesSection.win_top = newwin(1, 6, 6, 27)))
    {
        vrmr_error(-1, VR_ERR, gettext("creating window failed."));
        return(-1);
    }
    wbkgd(ServicesSection.win_top, vccnf.color_win);
    ServicesSection.panel_top[0] = new_panel(ServicesSection.win_top);
    /* TRANSLATORS: max 4 chars */
    wprintw(ServicesSection.win_top, "(%s)", gettext("more"));
    hide_panel(ServicesSection.panel_top[0]);

    if(!(ServicesSection.win_bot = newwin(1, 6, height-1, 27)))
    {
        vrmr_error(-1, VR_ERR, gettext("creating window failed."));
        return(-1);
    }
    wbkgd(ServicesSection.win_bot, vccnf.color_win);
    ServicesSection.panel_bot[0] = new_panel(ServicesSection.win_bot);
    /* TRANSLATORS: max 4 chars */
    wprintw(ServicesSection.win_bot, "(%s)", gettext("more"));
    hide_panel(ServicesSection.panel_bot[0]);

    return(retval);
}


static int
destroy_services_section(void)
{
    int             retval=0;
    unsigned int    i = 0;

    unpost_menu(ServicesSection.menu);
    free_menu(ServicesSection.menu);
    for(i = 0; i < ServicesSection.list_items; ++i)
        free_item(ServicesSection.items[i]);

    free(ServicesSection.items);

    del_panel(ServicesSection.panel[0]);
    destroy_win(ServicesSection.win);

    del_panel(ServicesSection.panel_top[0]);
    destroy_win(ServicesSection.win_top);
    del_panel(ServicesSection.panel_bot[0]);
    destroy_win(ServicesSection.win_bot);

    return(retval);
}


void
services_section(const int debuglvl, struct vrmr_ctx *vctx,
        struct vrmr_services *services, struct vrmr_rules *rules, struct vrmr_regex *reg)
{
    int     result = 0,
            quit = 0,
            reload = 0;
    int     ch = 0;
    int     height = 0,
            width = 0,
            startx = 0,
            starty = 0;
    char    *new_name_ptr = NULL,
            save_ser_name[VRMR_MAX_SERVICE] = "";
    ITEM    *cur = NULL;
    /* top menu */
    char    *key_choices[] =    {   "F12",
                                    "INS",
                                    "DEL",
                                    "r",
                                    "RET",
                                    "F10"};
    int     key_choices_n = 6;
    char    *cmd_choices[] =    {   gettext("help"),
                                    gettext("new"),
                                    gettext("del"),
                                    gettext("rename"),
                                    gettext("edit"),
                                    gettext("back")};
    int     cmd_choices_n = 6;

    /* safety */
    if(reg == NULL || services == NULL || rules == NULL)
    {
        vrmr_error(-1, VR_INTERR, "parameter problem (in: %s:%d).", __FUNC__, __LINE__);
        return;
    }

    // todo
    height = LINES-8;
    width = 34;

    /* place on the same y as "edit service" */
    VrWinGetOffset(-1, -1, height, width, 4, 1, &starty, &startx);
    ServicesSection.sl_xre = startx + width;
    ServicesSection.sl_yle = starty + height;

    result = vrmr_init_services_section(debuglvl, services, height, width, starty, startx);
    if(result < 0)
        return;

    draw_top_menu(debuglvl, top_win, gettext("Services"), key_choices_n, key_choices, cmd_choices_n, cmd_choices);

    update_panels();
    doupdate();

    while(quit == 0)
    {
        if(reload == 1)
        {
            result = destroy_services_section();
            if(result < 0)
                return;

            result = vrmr_init_services_section(debuglvl, services, height, width, starty, startx);
            if(result < 0)
                return;

            update_panels();
            doupdate();
            reload = 0;
        }

        while(quit == 0 && reload == 0)
        {
            if(ServicesSection.top != NULL && !item_visible(ServicesSection.top))
                show_panel(ServicesSection.panel_top[0]);
            else
                hide_panel(ServicesSection.panel_top[0]);

            if(ServicesSection.bot != NULL && !item_visible(ServicesSection.bot))
                show_panel(ServicesSection.panel_bot[0]);
            else
                hide_panel(ServicesSection.panel_bot[0]);

            update_panels();
            doupdate();

            /* restore the cursor */
            pos_menu_cursor(ServicesSection.menu);

            ch = wgetch(ServicesSection.win);

            switch(ch)
            {
                case 27:
                case 'q':
                case 'Q':
                case KEY_F(10): //quit

                    quit = 1;
                    break;

                case 'r':
                case 'R':

                    cur = current_item(ServicesSection.menu);
                    if(cur)
                    {
                        new_name_ptr = input_box(32, gettext("Rename Service"), STR_PLEASE_ENTER_THE_NAME);
                        if(new_name_ptr != NULL)
                        {
                            if(vrmr_validate_servicename(debuglvl, new_name_ptr, reg->servicename, VRMR_VERBOSE) == 0)
                            {
                                char *n = (char *)item_name(cur);

                                result = rename_service(debuglvl, vctx, services, rules, n, new_name_ptr);
                                if(result == 0)
                                {
                                    reload = 1;
                                }
                                else
                                {
                                    vrmr_error(-1, VR_ERR, "%s", STR_RENAME_FAILED);
                                }
                            }
                            free(new_name_ptr);
                        }
                    }
                    break;

                case KEY_IC: //insert
                case 'i':
                case 'I':

                    new_name_ptr = input_box(32, gettext("New Service"), gettext("Please enter the name of the new service"));
                    if(new_name_ptr != NULL)
                    {
                        if(vrmr_validate_servicename(debuglvl, new_name_ptr, reg->servicename, VRMR_QUIET) == 0)
                        {
                            if((vrmr_search_service(debuglvl, services, new_name_ptr) != NULL))
                            {
                                vrmr_error(-1, VR_ERR, gettext("service %s already exists."), new_name_ptr);
                            }
                            else
                            {
                                result = vrmr_new_service(debuglvl, vctx, services, new_name_ptr, VRMR_TYPE_SERVICE);
                                if(result == 0)
                                {
                                    /* example: "service 'X-5' has been created" */
                                    vrmr_audit("%s '%s' %s.", STR_SERVICE, new_name_ptr, STR_HAS_BEEN_CREATED);
                                    reload = 1;

                                    edit_service(debuglvl, vctx, services, new_name_ptr);

                                    draw_top_menu(debuglvl, top_win, gettext("Services"), key_choices_n, key_choices, cmd_choices_n, cmd_choices);
                                }
                                else
                                {
                                    vrmr_error(-1, VR_ERR, gettext("creating new service failed."));
                                }
                            }
                        }
                        else
                        {
                            vrmr_error(-1, VR_ERR, gettext("service name %s is invalid."), new_name_ptr);
                        }
                        free(new_name_ptr);
                    }
                    break;

                case KEY_DC: // delete
                case 'd':
                case 'D':

                    cur = current_item(ServicesSection.menu);
                    if(cur)
                    {
                        if (confirm(gettext("Delete"), gettext("Are you sure?"),
                                    vccnf.color_win_note, vccnf.color_win_note_rev|A_BOLD, 0) == 1)
                        {
                            (void)strlcpy(save_ser_name, (char *)item_name(cur), sizeof(save_ser_name));

                            result = vrmr_delete_service(debuglvl, vctx, services, (char *)item_name(cur), VRMR_TYPE_SERVICE);
                            if(result < 0)
                            {
                                vrmr_error(-1, VR_ERR, "%s.", STR_DELETE_FAILED);
                            }
                            else
                            {
                                /* example: "service 'X-5' has been deleted." */
                                vrmr_audit("%s '%s' %s.", STR_SERVICE, save_ser_name, STR_HAS_BEEN_DELETED);
                                reload = 1;
                            }
                        }
                    }
                    break;

                case KEY_DOWN:
                    menu_driver(ServicesSection.menu, REQ_DOWN_ITEM);
                    break;
                case KEY_UP:
                    menu_driver(ServicesSection.menu, REQ_UP_ITEM);
                    break;
                case KEY_NPAGE:
                    if(menu_driver(ServicesSection.menu, REQ_SCR_DPAGE) != E_OK)
                    {
                        while(menu_driver(ServicesSection.menu, REQ_DOWN_ITEM) == E_OK);
                    }
                    break;
                case KEY_PPAGE:
                    if(menu_driver(ServicesSection.menu, REQ_SCR_UPAGE) != E_OK)
                    {
                        while(menu_driver(ServicesSection.menu, REQ_UP_ITEM) == E_OK);
                    }
                    break;
                case KEY_HOME:
                    menu_driver(ServicesSection.menu, REQ_FIRST_ITEM);  // page up
                    break;
                case KEY_END:
                    menu_driver(ServicesSection.menu, REQ_LAST_ITEM);   // end
                    break;

                case KEY_RIGHT:
                case 10: // enter
                case 'e':
                case 'E':

                    cur = current_item(ServicesSection.menu);
                    if(cur)
                    {
                        (void)edit_service(debuglvl, vctx, services, (char *)item_name(cur));

                        draw_top_menu(debuglvl, top_win, gettext("Services"), key_choices_n, key_choices, cmd_choices_n, cmd_choices);
                    }

                    break;

                case KEY_F(12):
                case 'h':
                case 'H':
                case '?':

                    print_help(debuglvl, ":[VUURMUUR:SERVICES]:");
                    break;
            }
        }
    }

    destroy_services_section();

    update_panels();
    doupdate();
}
