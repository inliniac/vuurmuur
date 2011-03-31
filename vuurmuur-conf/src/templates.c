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

#ifdef USE_WIDEC
#ifdef HAVE_NC_WIDE_HEADERS
#include <ncursesw/ncurses.h>
#include <ncursesw/panel.h>
#endif /* HAVE_NC_WIDE_HEADERS */
#if defined(NCURSES_VERSION_PATCH) && (NCURSES_VERSION_PATCH < 20071013)
#define NCURSES_FIELD_INTERNALS char** expanded; WINDOW *working;
#endif 
#endif /* USE_WIDEC */
#include "main.h"

// minimun width = 13
// TODO: check maximum width of both values
/*

    returns 1 if yes, 0 if no
*/
int
confirm(char *title, char *text, chtype forecolor, chtype backcolor, int def)
{
    int     retval = 0;
    ITEM    **menu_items;
    MENU    *confirm_menu;
    PANEL   *my_panels[1];
    WINDOW  *confirm_win, *dw;
    ITEM    *cur;

    int     height = 7,
            width  = 25,
            startx = 5,
            starty = 5,
            max_x  = 0,
            max_y  = 0;
    char    *choices[] = {  STR_YES,
                            STR_NO};

    size_t  n_choices = 2,
            i = 0;
        
    int     ch,
            quit = 0;

    char    *print_title;


    /* safety */
    if(!title || !text)
    {
        (void)vrprint.error(-1, VR_INTERR, "parameter problem (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    if(width-4 < (int)StrLen(text))
        width = (int)StrLen(text) + 4;
    if(width-6 < (int)StrLen(title))
        width = (int)StrLen(title) + 6;

    getmaxyx(stdscr, max_y, max_x);
    startx = (max_x - width) /2;
    starty = (max_y - height)/2;

    /* get some mem */
    if(!(print_title = malloc(StrMemLen(title)+3)))
        return(-1);

    snprintf(print_title, StrMemLen(title) + 3, " %s ", title);

    // first display the menu
    menu_items = (ITEM **)calloc(n_choices + 1, sizeof(ITEM *));
    if(menu_items == NULL)
        return(-1);

    for(i = 0; i < n_choices; ++i)
    {
        menu_items[i] = new_item(choices[i], NULL);
    }
    menu_items[n_choices] = (ITEM *)NULL;

    confirm_menu = new_menu((ITEM **)menu_items);

    confirm_win = newwin(height, width, starty, startx);
    wbkgd(confirm_win, backcolor);
    keypad(confirm_win, TRUE);
    wrefresh(confirm_win);

    my_panels[0] = new_panel(confirm_win);

    set_menu_win(confirm_menu, confirm_win);
    dw = derwin(confirm_win, height-4, 10, 4, (width)/2-5);
    set_menu_sub(confirm_menu, dw);

    set_menu_format(confirm_menu, height-4, 2);

    box(confirm_win, 0, 0);
    print_in_middle(confirm_win, 0, 0, width, print_title, backcolor);
    print_in_middle(confirm_win, 2, 0, width, text, backcolor);

    set_menu_back(confirm_menu, backcolor);
    set_menu_fore(confirm_menu, forecolor);

    fix_wide_menu(0, confirm_menu, menu_items);

    post_menu(confirm_menu);


    /* set the cursor to the 'no' position */
    if(!def)
    {
        menu_driver(confirm_menu, REQ_RIGHT_ITEM);
    }

    update_panels();
    doupdate();

    while(quit == 0)
    {
        ch = wgetch(confirm_win);
        switch(ch)
        {
            case KEY_DOWN:
                menu_driver(confirm_menu, REQ_LEFT_ITEM);
                break;
            case KEY_UP:
                menu_driver(confirm_menu, REQ_RIGHT_ITEM);
                break;
            case KEY_LEFT:
                menu_driver(confirm_menu, REQ_LEFT_ITEM);
                break;
            case KEY_RIGHT:
                menu_driver(confirm_menu, REQ_RIGHT_ITEM);
                break;

            case 10: // enter
            {
                cur = current_item(confirm_menu);
                if(strcmp((char *)item_name(cur), STR_YES) == 0)
                {
                    retval=1;
                }

                quit=1;
                break;
            }

            case 'y':
            case 'Y':
                retval=1;
                quit=1;
                break;

            case 'n':
            case 'N':
                retval=0;
                quit=1;
                break;

            case 27:
            case KEY_F(10):
            case 'q':
            case 'Q':
                quit=1;
                break;
        }
    }

    unpost_menu(confirm_menu);
    free_menu(confirm_menu);
    for(i = 0; i < n_choices; ++i)
        free_item(menu_items[i]);

    free(menu_items);

    destroy_win(dw);

    del_panel(my_panels[0]);

    destroy_win(confirm_win);

    free(print_title);
    update_panels();
    doupdate();
      
    return(retval);
}


char *
input_box(size_t length, char *title, char *description)
{
    WINDOW  *ib_win = NULL;
    PANEL   *my_panels[1];
    FIELD   **fields;
    FORM    *my_form = NULL;
    int     height,
            width,
            startx,
            starty,
            max_height,
            max_width,
            ch = 0,
            rows,
            cols,
            quit = 0,
            i;
    char    *result_ptr = NULL,
            *temp_ptr = NULL;

    /* create a buffer with the size of 'length' */
    if(!(temp_ptr = malloc(length)))
    {
        (void)vrprint.error(-1, VR_ERR, gettext("malloc failed: %s (in: %s:%d)."), strerror(errno), __FUNCTION__, __LINE__);
        return(NULL);
    }
    
    // set the window size
    getmaxyx(stdscr, max_height, max_width);
    height = 8;
    if(length < 16)
    {
        width = 37; // minimum TODO: why 37?
    }
    else if((int)length + 8 > max_width)
    {
//        status_print(status_win, "Window too big!");
        free(temp_ptr);
        return NULL;
    }
    else
    {  
        width = (int)length + 8;
        if((int)StrLen(title) + 8 > width)
            width = (int)StrLen(title)+8;

        if((int)StrLen(description)+8 > width)
            width = (int)StrLen(description)+8;
    }

    // print on the centre of the screen
    startx = (max_height-height)/2;
    starty = (max_width-width)/2;

    // create window
    ib_win = create_newwin(height, width, startx, starty, title, (chtype)COLOR_PAIR(5));

    my_panels[0] = new_panel(ib_win);

    fields = (FIELD **)calloc(1 + 1, sizeof(FIELD *));

    fields[0] = new_field(1, (int)length-1, 3, (int)(((width-length)/2)-2), 0, 0);

    set_field_back(fields[0], (chtype)COLOR_PAIR(3));
    field_opts_off(fields[0], O_AUTOSKIP);
    // set status to false
    set_field_status(fields[0], FALSE);

    my_form = new_form(fields);
    scale_form(my_form, &rows, &cols);
    keypad(ib_win, TRUE);
    set_form_win(my_form, ib_win);
    set_form_sub(my_form, derwin(ib_win, rows, cols, 1, 2));
    post_form(my_form);

    mvwprintw(ib_win, 2, 4, "%s", description);
    mvwprintw(ib_win, 6, 4, gettext("Note: whitespaces not allowed."));
  
    update_panels();
    doupdate();

    while(quit == 0)
    {
        ch = wgetch(ib_win);
        switch(ch)
        {
            case 27:
            case KEY_F(10):
            case 10: // enter
                // Go to next field
                form_driver(my_form, REQ_NEXT_FIELD);
                form_driver(my_form, REQ_END_LINE);
                quit=1;
                break;
            case KEY_BACKSPACE:
            case 127:
                form_driver(my_form, REQ_PREV_CHAR);
                form_driver(my_form, REQ_DEL_CHAR);
                form_driver(my_form, REQ_END_LINE);
                break;
            case KEY_DC:
                form_driver(my_form, REQ_PREV_CHAR);
                form_driver(my_form, REQ_DEL_CHAR);
                form_driver(my_form, REQ_END_LINE);
                break;
            default:
                // If this is a normal character, it gets printed
                form_driver(my_form, ch);
                break;
        }
    }

    //status_print(status_win, "data: '%s' (%d)", field_buffer(fields[0], 0), length);
    (void)strlcpy(temp_ptr, field_buffer(fields[0], 0), length);

    // get the length of the entry
    for(i=0; temp_ptr[i] != ' ' && i < (int)length-1; i++);

    if(!(result_ptr = malloc((size_t)(i+1))))
    {
        (void)vrprint.error(-1, VR_ERR, gettext("malloc failed: %s (in: %s:%d)."), strerror(errno), __FUNCTION__, __LINE__);
        return(NULL);
    }

    strncpy(result_ptr, temp_ptr, (size_t)i);
    result_ptr[i]='\0';

    if(result_ptr[0] == '\0')
    {
        free(result_ptr);
        result_ptr = NULL;
    }

    free(temp_ptr);
  
    unpost_form(my_form);
    free_form(my_form);

    free_field(fields[0]);
    free(fields);

    del_panel(my_panels[0]);
    destroy_win(ib_win);

    update_panels();
    doupdate();

    return(result_ptr);
}


/*  fix_wide_menu

    NOTE: run right before post_menu

    This function adds some ncurses hacking voodoo. Basicly ncurses before
    5.5 + 20051210 patch doesnt get the menu size right when the menu
    items contain wide characters. So in this function we re-check the
    length of the items and correct the flawed values ncurses comes up with.
    Of course, we don't touch it when we are not in wide mode, and try not
    to change anything unneeded.
    
    Currently we handle two cases:
    
    1. one column, name + desc:
        - name len
        - desc len
        - menu width

        This is how the mainmenu works.

    2. two columns, only name (desc NULL)
        - we adjust itemlen to be max_name_len + menu->spc_cols

        This is how the confirm template works.
*/
void
fix_wide_menu(const int debuglvl, MENU *menu, ITEM **items)
{
#ifdef USE_WIDEC
    size_t  name_len = 0,
            desc_len = 0;
    size_t  max_name_len = 0,
            max_desc_len = 0;
    size_t  mwidth = 0,
            max_mwidth = 0;
    int     i = 0;

    if(menu == NULL || items == NULL)
        return;

    /* loop through all the items and get the length of the strings */
    for(i = 0; i < menu->nitems; i++)
    {
        name_len = 0;
        desc_len = 0;
    
        if(items[i] != NULL)
        {
            /* name */
            if(items[i]->name.str != NULL)
            {
                name_len = StrLen(items[i]->name.str);
                if(name_len > max_name_len)
                    max_name_len = name_len;

                if(debuglvl >= LOW)
                        (void)vrprint.debug(__FUNC__, "name "
                    "%s, len %u", items[i]->name.str,
                    name_len);
            }
        
            /* description */
            if(items[i]->description.str != NULL)
            {
                desc_len = StrLen(items[i]->description.str);
                if(desc_len > max_desc_len)
                    max_desc_len = desc_len;

                if(debuglvl >= LOW)
                    (void)vrprint.debug(__FUNC__, "desc %s"
                    ", len %u", items[i]->description.str,
                    desc_len);
            }
        }

        mwidth = name_len + desc_len;
        if(mwidth > max_mwidth)
            max_mwidth = mwidth;
    }

    if(menu->namelen > max_name_len)
    {
        if(debuglvl >= LOW)
            (void)vrprint.debug(__FUNC__, "adjusting menu->namelen "
                "to %u, was %u.", max_name_len, menu->namelen);

        menu->namelen = max_name_len;
    }
    if(menu->desclen > max_desc_len)
    {
        if(debuglvl >= LOW)
            (void)vrprint.debug(__FUNC__, "adjusting menu->desclen "
                "to %u, was %u.", max_desc_len, menu->desclen);

        menu->desclen = max_desc_len;
    }
    
    /* adjust menu->width if needed */
    if(menu->cols == 1)
    {
        if(menu->width > max_mwidth + 2)
        {
            if(debuglvl >= LOW)
                (void)vrprint.debug(__FUNC__, "adjusting "
                    "menu->width to %u, was %u.",
                    max_mwidth, menu->width);

            menu->width = max_mwidth + 2;
        }
    }
    /* adjust menu->itemlen if needed */
    else if(menu->cols == 2)
    {
        if(debuglvl >= LOW)
            (void)vrprint.debug(__FUNC__, "width %u, cols %u, "
                "fcols %u, itemlen %u, spc_desc %u, "
                "spc_cols %u",
                menu->width, menu->cols, menu->fcols,
                menu->itemlen, menu->spc_desc,
                menu->spc_cols);

        /* no desc */
        if(max_desc_len == 0)
        {
            if(max_name_len + menu->spc_cols != menu->itemlen)
            {
                menu->itemlen = max_name_len + menu->spc_cols;

                if(debuglvl >= LOW)
                    (void)vrprint.debug(__FUNC__,
                        "adjusting itemlen to %u",
                        menu->itemlen);
            }
        }
    }
#endif /* USE_WIDEC */
}


int
vuumuurconf_print_warning(char *title, char *fmt, ...)
{
    int     retval = 0;
    va_list ap;
    char    long_str[512] = "";

    WINDOW  *err_win = NULL,
            *print_err_win = NULL;
    PANEL   *my_panels[1];
    int     height = 8,
            width,
            startx,
            starty,
            max_height,
            max_width,
            ch;

    va_start(ap, fmt);
    vsnprintf(long_str, sizeof(long_str), fmt, ap);
    va_end(ap);

    getmaxyx(stdscr, max_height, max_width);

    width = (int)StrLen(long_str)+15;
    if(width > max_width)
    {
        width = max_width - 10;
    }

    starty = (max_height - height) / 2;
    startx = (max_width - width) / 2;

    err_win = create_newwin(height, width, starty, startx, title, (chtype)COLOR_PAIR(CP_BLUE_WHITE));
    if(err_win == NULL)
        return(-1);

    print_err_win = newwin(height-4, width-6, starty+2, startx+3);
    if(print_err_win == NULL)
        return(-1);

    wbkgd(print_err_win, (chtype)COLOR_PAIR(CP_BLUE_WHITE));
    my_panels[0] = new_panel(err_win);
    keypad(err_win, TRUE);

    wprintw(print_err_win, "%s: %s", gettext("Warning"), long_str);
    mvwprintw(err_win, height-2, 2, gettext("Press any key to continue..."));

    update_panels();
    doupdate();

    (void)wgetch(print_err_win);

    del_panel(my_panels[0]);
    destroy_win(print_err_win);
    destroy_win(err_win);

    update_panels();
    doupdate();

    return(retval);
}


int
vuumuurconf_print_error(int error_no, char *title, char *fmt, ...)
{
    int     retval=0;
    va_list ap;
    char    long_str[512] = "";
    WINDOW  *err_win = NULL,
            *print_err_win = NULL;
    PANEL   *my_panels[1];
    int     height = 8,
            width,
            startx,
            starty,
            max_height,
            max_width,
            ch;

    va_start(ap, fmt);
    vsnprintf(long_str, sizeof(long_str), fmt, ap);
    va_end(ap);
  
    getmaxyx(stdscr, max_height, max_width);

    width = (int)StrLen(long_str) + 13;
    if(width > max_width)
    {
        width = max_width - 10;
    }

    starty = (max_height - height) / 2;
    startx = (max_width - width) / 2;
    
    err_win = create_newwin(height, width, starty, startx, title, (chtype)COLOR_PAIR(6)|A_BOLD);
    if(err_win == NULL)
        return(-1);
    
    print_err_win = newwin(height-4, width-6, starty+2, startx+3);
    if(print_err_win == NULL)
        return(-1);

    wbkgd(print_err_win, (chtype)COLOR_PAIR(CP_YELLOW_RED)|A_BOLD);
    my_panels[0] = new_panel(err_win);
    keypad(err_win, TRUE);

    wprintw(print_err_win, "%s: %s (%d)", gettext("Error"), long_str, error_no);
    mvwprintw(err_win, height-2, 2, gettext("Press any key to continue..."));

    update_panels();
    doupdate();

    (void)wgetch(print_err_win);

    del_panel(my_panels[0]);
    destroy_win(print_err_win);
    destroy_win(err_win);

    update_panels();
    doupdate();

    return(retval);
}


int
vuumuurconf_print_info(char *title, char *fmt, ...)
{
    int     retval=0;
    va_list ap;
    char    long_str[512] = "";

    va_start(ap, fmt);
    vsnprintf(long_str, sizeof(long_str), fmt, ap);
    va_end(ap);

    wprintw(mainlog_win, "%s\n", long_str);

    update_panels();
    doupdate();

    return(retval);
}


/*
    draws a box where the user can make a choice
    returns a pointer to the selection, or NULL in case
    of error or no selection

    the user must free the selection
*/
char *
selectbox(char *title, char *text, size_t n_choices, char **choices, unsigned int cols, /*@null@*/char *set_to_name)
{
    ITEM    **menu_items = NULL,
            *cur = NULL,
            *first_item = NULL;
    MENU    *confirm_menu;
    PANEL   *my_panels[1];
    WINDOW  *confirm_win;

    /* for (more) indicators */
    ITEM    *top,
            *bot;
    PANEL   *panel_top[1];
    PANEL   *panel_bot[1];
    WINDOW  *win_top;
    WINDOW  *win_bot;

    int     height=0,
            width=0,
            startx=0,
            starty=0,
            max_height=0,
            max_width=0;

    int     ch=0,
            quit=0;

    size_t  len = 0,
            i=0,
            x = 0,
            item_len = 0,
            min_len = 0;

    char    *print_title,
            *select_ptr = NULL;
    char    done = 0,
            found = 0,
            down = 0;
    unsigned int    col_n = 1,
                    first_col = 0;

    size_t  size = 0;

    if(n_choices == 0)
    {
        (void)vrprint.error(-1, VR_INTERR, "n_choices == 0 (in: %s:%d).", __FUNC__, __LINE__);
        return(NULL);
    }

    /*
        cols can never be 0 ofcourse
    */
    if(cols == 0)
        cols = 1;

    /*
        get the screen size
    */
    getmaxyx(stdscr, max_height, max_width);

    /*
        determine the minimal width of the window
    */
    len = StrLen(title);
    if(StrLen(text) > len)
        len = StrLen(text);

    for(i = 0; i < n_choices; i++)
    {
        if(StrLen(choices[i]) > item_len)
        {
            item_len = StrLen(choices[i]);
        }
    }

    if((int)item_len * cols + 8 > max_width)
        cols = 1;

    min_len = len + 8;

    if(cols == 1)
        width = (int)item_len + 8;
    else
    {
        width = (int)item_len * cols + 8;
    }

    if(width < (int)min_len)
        width = (int)min_len;

    /*
        set height, if it is to big we set starty
    */
    height = 6 + (n_choices / cols);
    if(height > max_height - 8)
    {
        height = max_height - 8;
    }

    /*
        center the window
    */
    starty = (max_height - height)/2;
    startx = (max_width - width)/2;

    print_title = malloc(StrMemLen(title)+3);
    if(print_title == NULL)
        return(NULL);

    snprintf(print_title, StrMemLen(title)+3, " %s ", title);

    if(!(menu_items = (ITEM **)calloc(n_choices + 1, sizeof(ITEM *))))
        return(NULL);

    for(i = 0; i < n_choices; ++i)
    {
        menu_items[i] = new_item(choices[i], NULL);
    }
    menu_items[n_choices] = (ITEM *)NULL;

    top = menu_items[0];

    if(cols == 1)
        bot = menu_items[i - 1];
    else
    {
        for(x = 0; x < n_choices; x++)
        {
            if(col_n == 1)
                first_col++;

            if(col_n == cols)
                col_n = 0;

            col_n++;
        }

        bot = menu_items[first_col-1];
    }

    confirm_menu = new_menu((ITEM **)menu_items);

    confirm_win = newwin(height, width, starty, startx);
    wbkgd(confirm_win, (chtype)COLOR_PAIR(CP_BLUE_WHITE));
    keypad(confirm_win, TRUE);
    wrefresh(confirm_win);

    my_panels[0] = new_panel(confirm_win);

    set_menu_win(confirm_menu, confirm_win);
    set_menu_sub(confirm_menu, derwin(confirm_win, height-5, width-3, 4, 2));

    set_menu_format(confirm_menu, height-5, (int)cols);

    box(confirm_win, 0, 0);
    print_in_middle(confirm_win, 0, 0, width, print_title, (chtype)COLOR_PAIR(CP_BLUE_WHITE));
    print_in_middle(confirm_win, 2, 0, width, text, (chtype)COLOR_PAIR(CP_BLUE_WHITE));

    set_menu_back(confirm_menu, (chtype)COLOR_PAIR(CP_BLUE_WHITE));
    set_menu_fore(confirm_menu, (chtype)COLOR_PAIR(CP_WHITE_BLUE));

    /*
        make sure the colums are filled top->down, not left->right
    */
    menu_opts_off(confirm_menu, O_ROWMAJOR);
    post_menu(confirm_menu);


    if(set_to_name != NULL)
    {
        down = 1;
        done = 0;
        first_item = current_item(confirm_menu);

        while(done == 0)
        {
            if(down != 0)
            {
                down++;

                if(menu_driver(confirm_menu, REQ_RIGHT_ITEM) < 0)
                    down = 0;
            }
            else /* down is 0 */
            {
                while(menu_driver(confirm_menu, REQ_LEFT_ITEM)== E_OK);

                if(menu_driver(confirm_menu, REQ_DOWN_ITEM) < 0)
                    done = 1;

                down = 1;
            }

            cur = current_item(confirm_menu);
            if(strcmp(set_to_name, (char *)item_name(cur)) == 0)
            {
                found = 1;
                done = 1;
            }

            //status_print(status_win, "down: %d", down);
            //update_panels();
            //doupdate();
            //sleep(1);
        }

        if(found == 0)
        {
            set_current_item(confirm_menu, first_item);
            pos_menu_cursor(confirm_menu);
        }
    }

    /* create the top and bottom fields */
    if(!(win_top = newwin(1, 6, starty + 3, startx + width - 8)))
    {
        (void)vrprint.error(-1, VR_ERR, gettext("creating window failed."));
        return(NULL);
    }
    wbkgd(win_top, (chtype)COLOR_PAIR(CP_BLUE_WHITE));
    panel_top[0] = new_panel(win_top);
    /* TRANSLATORS: max 4 chars */
    wprintw(win_top, "(%s)", gettext("more"));
    hide_panel(panel_top[0]);

    if(!(win_bot = newwin(1, 6, starty + height - 1, startx + width - 8)))
    {
        (void)vrprint.error(-1, VR_ERR, gettext("creating window failed."));
        return(NULL);
    }
    wbkgd(win_bot, (chtype)COLOR_PAIR(CP_BLUE_WHITE));
    panel_bot[0] = new_panel(win_bot);
    /* TRANSLATORS: max 4 chars */
    wprintw(win_bot, "(%s)", gettext("more"));
    hide_panel(panel_bot[0]);


    update_panels();
    doupdate();

    while(quit == 0)
    {
        if(!item_visible(top))
            show_panel(panel_top[0]);
        else
            hide_panel(panel_top[0]);

        if(!item_visible(bot))
            show_panel(panel_bot[0]);
        else
            hide_panel(panel_bot[0]);

        update_panels();
        doupdate();

        /* restore the cursor */
        pos_menu_cursor(confirm_menu);

        ch = wgetch(confirm_win);
        switch(ch)
        {
            case KEY_DOWN:
                menu_driver(confirm_menu, REQ_DOWN_ITEM);
                break;
            case KEY_UP:
                menu_driver(confirm_menu, REQ_UP_ITEM);
                break;
            case KEY_NPAGE:
                if(menu_driver(confirm_menu, REQ_SCR_DPAGE) != E_OK)
                {
                    while(menu_driver(confirm_menu, REQ_DOWN_ITEM) == E_OK);
                }
                break;
            case KEY_PPAGE:
                if(menu_driver(confirm_menu, REQ_SCR_UPAGE) != E_OK)
                {
                    while(menu_driver(confirm_menu, REQ_UP_ITEM) == E_OK);
                }
                break;
            case KEY_HOME:
                menu_driver(confirm_menu, REQ_FIRST_ITEM);  // home
                break;
            case KEY_END:
                menu_driver(confirm_menu, REQ_LAST_ITEM);   // end
                break;

            case KEY_LEFT:
                if(cols > 1)
                    menu_driver(confirm_menu, REQ_LEFT_ITEM);
                else
                    quit = 1;

                break;

            /*
                not so nice code: if we only have one column we fall
                trough...
            */
            case KEY_RIGHT:
                if(cols > 1)
                {
                    menu_driver(confirm_menu, REQ_RIGHT_ITEM);
                    break;
                }

//            case KEY_RIGHT:
            case 32:
            case 10: // enter
            {
                ITEM *cur;

                cur = current_item(confirm_menu);

                size = StrMemLen((char *)item_name(cur))+1;
                if(size == 0)
                {
                    (void)vrprint.error(-1, VR_INTERR, "could not determine the size of the selection (in: %s).", __FUNC__);
                    return(NULL);
                }

                if(!(select_ptr = malloc(size)))
                    return(NULL);

                (void)strlcpy(select_ptr, item_name(cur), size);

                quit=1;
                break;
            }

            case 27:
            case KEY_F(10):
            case 'q':
            case 'Q':
                quit=1;
                break;
        }
    }

    /*
        cleanup
    */
    unpost_menu(confirm_menu);
    free_menu(confirm_menu);

    for(i = 0; i < n_choices; ++i)
        free_item(menu_items[i]);

    free(menu_items);

    del_panel(my_panels[0]);

    destroy_win(confirm_win);

    del_panel(panel_top[0]);
    destroy_win(win_top);
    del_panel(panel_bot[0]);
    destroy_win(win_bot);

    free(print_title);

    update_panels();
    doupdate();

    return(select_ptr);
}

int
status_print(WINDOW *local_win, char *fmt, ...)
{
    va_list ap;
    char    long_str[256] = ""; /*  this must be bigger than the
                        screen so wide chars also fit */

    if(!local_win || !fmt)
        return(-1);

    werase(local_win);

    va_start(ap, fmt);
    vsnprintf(long_str, sizeof(long_str), fmt, ap);
    va_end(ap);

    wattron(local_win, (chtype)COLOR_PAIR(4) | A_BOLD);
    mvwprintw(local_win, 0, 0, "%s", long_str);
    wattroff(local_win, (chtype)COLOR_PAIR(4)| A_BOLD);
    wrefresh(local_win);

    return(0);
}


/*
    wrapper around set_field_buffer so we always send only 'printable' characters.
*/
void
set_field_buffer_wrap(const int debuglvl, FIELD *field, int bufnum, const char *value)
{
    char    buffer[512] = "";
    int     field_rows = 0,
            field_cols = 0,
            field_size = 0,
            i = 0,
            x = 0;
    size_t  value_size = 0;
    int     result = 0;
#ifdef USE_WIDEC
    wchar_t wbuffer[512] = L"";
#endif /* USE_WIDEC */

    /* safety */
    if(!field || !value)
        return;

    if(debuglvl >= HIGH)
        (void)vrprint.debug(__FUNC__, "value: '%s'.", value);

    /* get info about the field */
    result = field_info(field, &field_rows, &field_cols, &i, &i, &i, &i);
    if(result != E_OK)
    {
        (void)vrprint.error(-1, VR_INTERR, "field_info failed, see debug.log.");

        if(result == E_SYSTEM_ERROR)
            (void)vrprint.debug(__FUNC__, "field_info: E_SYSTEM_ERROR: %s.", strerror(errno));
        else if(result == E_BAD_ARGUMENT)
            (void)vrprint.debug(__FUNC__, "field_info: E_BAD_ARGUMENT");
        else
            (void)vrprint.debug(__FUNC__, "field_info: unknown returncode %d", result);

        return;
    }

    /* calc the total field size */
    field_size = field_rows * field_cols;
    if(field_size >= (int)sizeof(buffer))
        field_size = (int)sizeof(buffer) - 1;

    if(debuglvl >= HIGH)
        (void)vrprint.debug(__FUNC__, "field_size: '%d', field_rows: '%d', field_cols: '%d'.", field_size, field_rows, field_cols);

#ifdef USE_WIDEC
    mbstowcs(wbuffer, value, wsizeof(wbuffer));
    value_size = wcslen(wbuffer);

    /* clear the remaining buffer with whitespaces */
    for(i = value_size; i < field_size; i++)
        wbuffer[i] = L' ';

    wcstombs(buffer, wbuffer, sizeof(buffer));
#else

    /* get the size of the string */
    value_size = StrLen(value);

    if(debuglvl >= HIGH)
        (void)vrprint.debug(__FUNC__, "value_size: '%d'.", value_size);

    /* copy the string into the new buffer */
    //strlcpy(buffer, value, field_size+1);
    (void)strlcpy(buffer, value, sizeof(buffer));

    if(debuglvl >= HIGH)
        (void)vrprint.debug(__FUNC__, "buffer: '%s'.", buffer);

    /* clear the remaining buffer with whitespaces */
    for(i = (int)value_size; i < field_size; i++)
        buffer[i] = ' ';
#endif /* USE_WIDEC */

    /* now finally run the set_field_buffer */
    result = set_field_buffer(field, bufnum, buffer);

    /* now see if we were successful. */
    if(result != E_OK)
    {
        (void)vrprint.error(-1, VR_INTERR, "set_field_buffer failed, see debug.log.");

        if(result == E_SYSTEM_ERROR)
            (void)vrprint.debug(__FUNC__, "set_field_buffer: E_SYSTEM_ERROR: %s.", strerror(errno));
        else if(result == E_BAD_ARGUMENT)
        {
            (void)vrprint.debug(__FUNC__, "set_field_buffer: E_BAD_ARGUMENT");

            for(x = 0; x < (int)sizeof(buffer) && buffer[x] != '\0' && buffer[x] != '\n'; x++)
            {
                (void)vrprint.debug(__FUNC__, "set_field_buffer: '%c' is %s", buffer[x], isprint(buffer[x]) ? "printable" : "NOT printable");
            }
        }
        else
            (void)vrprint.debug(__FUNC__, "set_field_buffer: unknown returncode %d", result);

        return;
    }

    return;
}

FIELD *
new_field_wrap(int rows, int cols, int frow, int fcol, int nrow, int nbuf)
{
    FIELD *f = new_field (rows, cols, frow, fcol, nrow, nbuf);
    if (f == NULL)
        return(NULL);

#ifdef USE_WIDEC
#ifdef HAVE_NC_WIDE_HEADERS
    /* Work around a Ncurses bug that occurs when nbufs are used.
     * See: https://bugzilla.redhat.com/show_bug.cgi?id=310071
     */
#if defined(NCURSES_VERSION_PATCH) && (NCURSES_VERSION_PATCH < 20071013)
    if (nbuf) {
        size_t len = (1 + (unsigned)nbuf) * sizeof(char *);
        /* realloc the memory so it will be enough */
        f->expanded = realloc(f->expanded, len);
        if (f->expanded == NULL) {
            (void)vrprint.error(-1, VR_INTERR, "realloc failed: %s (in: %s:%d)",
                strerror(errno), __FUNC__, __LINE__);
            return(NULL);
        }

        /* set the memory to null, otherwise the memory
         * will be used uninitialized.
         *
         * ncurses doesn't use memset for this, but I
         * noticed all bytes are 0 anyway, so memset
         * should be fine */
        memset(f->expanded, 0, len);
    }
#endif /* ncurses patchlvl */
#endif /* HAVE_NC_WIDE_HEADERS */
#endif /* USE_WIDEC */
    return(f);
}

