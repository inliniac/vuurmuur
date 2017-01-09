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

/*  helper functions for building the GUI

*/

#include "main.h"

void
VrBusyWinCreate(const int debuglvl)
{
    int width = 20,
        height = 5;

    vr_busywin = VrNewWin(height, width, 0, 0, vccnf.color_win);

    mvwprintw(vr_busywin->w, 2, 4, gettext("Please Wait"));
}

void
VrBusyWinShow(void)
{
    if (vr_busywin != NULL && vr_busywin->p != NULL) {
        show_panel(vr_busywin->p);
    }
    update_panels();
    doupdate();
}

void
VrBusyWinHide(void)
{
    if (vr_busywin != NULL && vr_busywin->p != NULL) {
        hide_panel(vr_busywin->p);
    }
    update_panels();
    doupdate();
}

void
VrBusyWinDelete(const int debuglvl)
{
    VrDelWin(vr_busywin);
}

/**
 *  \param yj y justify: -1 up, 0 center, 1 down
 *  \param xj x justify: -1 left, 0 center, 1 right
 */
int VrWinGetOffset(int yj, int xj, int h, int w, int yo, int xo, int *y, int *x) {
    int maxy, maxx;
    int starty, startx;

    /* get current screen size */
    getmaxyx(stdscr, maxy, maxx);

    if (h > maxy || w > maxx)
        return -1;

    if (yj == -1) {
        starty = 0;
        while (starty + h < maxy) {
            starty++;
            if (starty == yo)
                break;
        }
        if (starty < yo && starty > 0)
            starty--;

    } else if (yj == 1) {
        starty = maxy - h;
        while (starty > 0) {
            starty--;
            if (starty == yo)
                break;
        }
    } else {
        starty = (maxy - h) / 2;
    }

    if (xj == -1) {
        startx = 0;
        while (startx + w < maxx) {
            startx++;
            if (startx == xo)
                break;
        }
        if (startx < xo && startx > 0)
            startx--;
    } else if (xj == 1) {
        startx = maxx - w;
        while (startx > 0) {
            startx--;
            if (startx == xo)
                break;
        }
    } else {
        startx = (maxx - w) / 2;
    }

    while (starty + h > maxy)
        starty--;
    while (startx + w > maxx)
        startx--;

    /* magic: keep upper and lower 4 lines free if possible */
    while (starty > 4 && maxy - (starty + h) < 4)
        starty--;

    /* center window if height > main middle window */
    if (h > maxy - (2 * 4) && h <= maxy)
    {
        starty = ((maxy - h) / 2) + ((maxy - h) % 2);

        /* try to show always top menu */
        if (starty < 2 && (maxy - h) >= 2)
        {
            starty = 2;
        }
    }

    *y = starty;
    *x = startx;
    return 0;
}

VrWin * __attribute__((returns_nonnull))
VrNewWin(int h, int w, int y, int x, chtype cp)
{
    VrWin   *win;
    int     maxx = 0,
            maxy = 0;

    /* max screen sizes */
    getmaxyx(stdscr, maxy, maxx);

    /*  if requested, place the window in the middle of the screen */
    if(y == 0)
    {
        y = (maxy - h)/2;
    }
    if(x == 0)
    {
        x = (maxx - w)/2;
    }

    win = malloc(sizeof(VrWin));
    vrmr_fatal_alloc("malloc", win);
    memset(win, 0, sizeof(VrWin));

    win->w = newwin(h, w, y, x);
    vrmr_fatal_if_null(win->w);
    win->p = new_panel(win->w);
    vrmr_fatal_if_null(win->p);

    box(win->w, 0, 0);
    wbkgd(win->w, cp);
    keypad(win->w, TRUE);

    win->height = h;
    win->width= w;
    win->y = y;
    win->x = x;
    return(win);
}

void
VrDelWin(VrWin *win)
{
    /* cleanup window and panel */
    nodelay(win->w, FALSE);
    del_panel(win->p);
    destroy_win(win->w);
    /* free memory */
    free(win);
}

int
VrWinSetTitle(VrWin *win, char *title)
{
    size_t  len = StrLen(title);
    size_t  printstart = 0;

    if((int)(len - 4) > win->width)
    {
        return(0);
    }

    printstart = (win->width - len - 2)/2;
    mvwprintw(win->w, 0, (int)printstart, " %s ", title);
    return(0);
}

int
VrWinGetch(VrWin *win)
{
    return(wgetch(win->w));
}

VrMenu * __attribute__((returns_nonnull))
VrNewMenu(int h, int w, int y, int x, unsigned int n, chtype bg, chtype fg)
{
    VrMenu *menu = malloc(sizeof(VrMenu));
    vrmr_fatal_alloc("malloc", menu);
    memset(menu, 0, sizeof(VrMenu));

    menu->h = h;
    menu->w = w;
    menu->y = y;
    menu->x = x;

    menu->i = calloc(n + 1, sizeof(ITEM *));
    vrmr_fatal_alloc("calloc", menu->i);
    memset(menu->i, 0, (sizeof(ITEM *) * (n + 1)));
    menu->nitems = n;

    menu->free_name = NULL;
    menu->use_namelist = FALSE;
    menu->free_desc = NULL;
    menu->use_desclist = FALSE;
    menu->fg = fg;
    menu->bg = bg;
    return(menu);
}

void
VrMenuSetupNameList(const int debuglvl, VrMenu *menu)
{
    vrmr_list_setup(debuglvl, &menu->name, menu->free_name);
    menu->use_namelist = TRUE;
}

void
VrMenuSetupDescList(const int debuglvl, VrMenu *menu)
{
    vrmr_list_setup(debuglvl, &menu->desc, menu->free_desc);
    menu->use_desclist = TRUE;
}

void
VrMenuSetNameFreeFunc(VrMenu *menu, void (*free_func)(void *ptr))
{
    menu->free_name = free_func;
}

void
VrMenuSetDescFreeFunc(VrMenu *menu, void (*free_func)(void *ptr))
{
    menu->free_desc = free_func;
}

void
VrDelMenu(const int debuglvl, VrMenu *menu)
{
    size_t i = 0;

    if (menu->m) {
        unpost_menu(menu->m);
        free_menu(menu->m);
    }

    if (menu->dw)
        destroy_win(menu->dw);

    for (i = 0; i < menu->nitems; i++) {
        free_item(menu->i[i]);
    }
    /* free items */
    if(menu->i != NULL)
        free(menu->i);

    /* clear the lists if used */
    if(menu->use_namelist == TRUE)
        vrmr_list_cleanup(debuglvl, &menu->name);
    if(menu->use_desclist == TRUE)
        vrmr_list_cleanup(debuglvl, &menu->desc);

    /* free memory */
    free(menu);
}

int
VrMenuAddItem(const int debuglvl, VrMenu *menu, char *name, char *desc)
{
    if(menu->cur_item >= menu->nitems)
    {
        vrmr_error(-1, VR_ERR, "menu full: all %u items already added", menu->nitems);
        return(-1);
    }

    if(menu->use_namelist == TRUE)
    {
        if(vrmr_list_append(debuglvl, &menu->name, name) == NULL)
        {
            vrmr_error(-1, VR_ERR, "vrmr_list_append failed");
            return(-1);
        }
    }
    if(menu->use_desclist == TRUE)
    {
        if(vrmr_list_append(debuglvl, &menu->desc, desc) == NULL)
        {
            vrmr_error(-1, VR_ERR, "vrmr_list_append failed");
            return(-1);
        }
    }

    menu->i[menu->cur_item] = new_item(name, desc);
    if(menu->i[menu->cur_item] == NULL)
    {
        vrmr_error(-1, VR_ERR, "new_item failed");
        return(-1);
    }
    menu->cur_item++;

    return(0);
}

int
VrMenuAddSepItem(const int debuglvl, VrMenu *menu, char *desc)
{
    if(menu->cur_item >= menu->nitems)
    {
        vrmr_error(-1, VR_ERR, "menu full: all %u items already added", menu->nitems);
        return(-1);
    }

    if(menu->use_desclist == TRUE)
    {
        if(vrmr_list_append(debuglvl, &menu->desc, desc) == NULL)
        {
            vrmr_error(-1, VR_ERR, "vrmr_list_append failed");
            return(-1);
        }
    }

    menu->i[menu->cur_item] = new_item(" ", desc);
    if(menu->i[menu->cur_item] == NULL)
    {
        vrmr_error(-1, VR_ERR, "new_item failed");
        return(-1);
    }
    item_opts_off(menu->i[menu->cur_item], O_SELECTABLE);

    menu->cur_item++;
    return(0);
}

void
VrMenuConnectToWin(const int debuglvl, VrMenu *menu, VrWin *win)
{
    int result;

    vrmr_fatal_if_null(menu);
    vrmr_fatal_if_null(win);

    menu->m = new_menu((ITEM **)menu->i);
    vrmr_fatal_if_null(menu->m);
    result = set_menu_win(menu->m, win->w);
    vrmr_fatal_if(result != E_OK);

    menu->dw = derwin(win->w, menu->h, menu->w, menu->y, menu->x);
    vrmr_fatal_if_null(menu->dw);

    result = set_menu_sub(menu->m, menu->dw);
    vrmr_fatal_if(result != E_OK);

    result = set_menu_format(menu->m, win->height - 2, 1);
    vrmr_fatal_if(result != E_OK);

    set_menu_back(menu->m, menu->bg);
    set_menu_grey(menu->m, menu->bg);
    set_menu_fore(menu->m, menu->fg);
}


/*  default keys:
        up
        down
        pageup
        pagedown
        home
        end

    returns TRUE if the key matched, false if not
*/
char
VrMenuDefaultNavigation(const int debuglvl, VrMenu *menu, int key)
{
    char    match = FALSE;

    switch(key)
    {
        case KEY_DOWN:
            menu_driver(menu->m, REQ_DOWN_ITEM);
            match = TRUE;
            break;
        case KEY_UP:
            menu_driver(menu->m, REQ_UP_ITEM);
            match = TRUE;
            break;
        case KEY_NPAGE:
            if(menu_driver(menu->m, REQ_SCR_DPAGE) != E_OK)
            {
                while(menu_driver(menu->m, REQ_DOWN_ITEM) == E_OK);
            }
            match = TRUE;
            break;
        case KEY_PPAGE:
            if(menu_driver(menu->m, REQ_SCR_UPAGE) != E_OK)
            {
                while(menu_driver(menu->m, REQ_UP_ITEM) == E_OK);
            }
            match = TRUE;
            break;
        case KEY_HOME:
            menu_driver(menu->m, REQ_FIRST_ITEM);
            match = TRUE;
            break;
        case KEY_END:
            menu_driver(menu->m, REQ_LAST_ITEM);
            match = TRUE;
            break;
        case 9: /* TAB */
            menu_driver(menu->m, REQ_NEXT_ITEM);
            match = TRUE;
            break;
    }

    return(match);
}


void
VrMenuPost(const int debuglvl, VrMenu *menu)
{
    int result = post_menu(menu->m);
    vrmr_fatal_if(result != E_OK);
}

void
VrMenuUnPost(const int debuglvl, VrMenu *menu)
{
    int result = unpost_menu(menu->m);
    vrmr_fatal_if(result != E_OK);
}

VrForm * __attribute__((returns_nonnull))
VrNewForm(int h, int w, int y, int x, chtype bg, chtype fg)
{
    VrForm *form = malloc(sizeof(VrForm));
    vrmr_fatal_alloc("malloc", form);
    memset(form, 0, sizeof(VrForm));

    form->h = h;
    form->w = w;
    form->y = y;
    form->x = x;
    form->fg = fg;
    form->bg = bg;
    form->save = NULL;
    form->save_ctx = NULL;

    vrmr_fatal_if(vrmr_list_setup(0, &form->list, free) < 0);
    return(form);
}

void
VrDelForm(const int debuglvl, VrForm *form)
{
    size_t i = 0;

    if (form->f) {
        unpost_form(form->f);
        free_form(form->f);
    }

    if (form->dw)
        destroy_win(form->dw);

    for (i = 0; i < form->nfields; i++) {
        free_field(form->fields[i]);
    }
    /* free items */
    if(form->fields != NULL)
        free(form->fields);

    vrmr_list_cleanup(debuglvl, &form->list);

    /* free memory */
    free(form);
}

void
VrFormPost(const int debuglvl, VrForm *form)
{
    int result = post_form(form->f);
    vrmr_fatal_if(result != E_OK);
}

void
VrFormUnPost(const int debuglvl, VrForm *form)
{
    int result = unpost_form(form->f);
    vrmr_fatal_if(result != E_OK);
}

static void VrFormStoreField (const int debuglvl, VrForm *form,
        enum vrmr_gui_form_field_types type, chtype cp,
        int h, int w, int toprow, int leftcol,
        const char *name, char *value_str, int value_bool)
{
    struct vrmr_gui_form_field *fld = malloc(sizeof(*fld));
    vrmr_fatal_alloc("malloc", fld);

    fld->type = type;
    fld->cp = cp;
    fld->h = h;
    fld->w = w;
    fld->toprow = toprow;
    fld->leftcol = leftcol;
    fld->name = name;

    switch (type) {
        case VRMR_GUI_FORM_FIELD_TYPE_LABEL:
        case VRMR_GUI_FORM_FIELD_TYPE_TEXT:
            fld->v.value_str = value_str;
            break;
        case VRMR_GUI_FORM_FIELD_TYPE_CHECKBOX:
            fld->v.value_bool = value_bool;
            break;
    }

    vrmr_fatal_if(vrmr_list_append(debuglvl, &form->list, fld) == NULL);
}

void
VrFormAddTextField(const int debuglvl, VrForm *form, int height, int width, int toprow, int leftcol, chtype cp, char *name, char *value)
{
    vrmr_fatal_if((int)StrLen(name) > width);
    VrFormStoreField(debuglvl, form, VRMR_GUI_FORM_FIELD_TYPE_TEXT, cp, height, width, toprow, leftcol, name, value, 0);
}

void
VrFormAddLabelField(const int debuglvl, VrForm *form, int height, int width, int toprow, int leftcol, chtype cp, char *value)
{
    VrFormStoreField(debuglvl, form, VRMR_GUI_FORM_FIELD_TYPE_LABEL, cp, height, width, toprow, leftcol, NULL, value, 0);
}

void
VrFormAddCheckboxField(const int debuglvl, VrForm *form, int toprow, int leftcol, chtype cp, char *name, char enabled)
{
    int height = 1;
    int width = 1;

    vrmr_fatal_if((int)StrLen(name) > width);
    VrFormStoreField(debuglvl, form, VRMR_GUI_FORM_FIELD_TYPE_CHECKBOX, cp, height, width, toprow, leftcol, name, NULL, (int)enabled);
}

static void VrFormCreateField(const int debuglvl, VrForm *form, struct vrmr_gui_form_field *fld) {
    int result = 0;

    vrmr_fatal_if (form->cur_field >= form->nfields);

    if (fld->type == VRMR_GUI_FORM_FIELD_TYPE_TEXT) {
        form->fields[form->cur_field] = new_field_wrap(fld->h, fld->w, fld->toprow, fld->leftcol, 0, 2);
    } else if (fld->type == VRMR_GUI_FORM_FIELD_TYPE_LABEL) {
        form->fields[form->cur_field] = new_field_wrap(fld->h, fld->w, fld->toprow, fld->leftcol, 0, 2);
    } else if (fld->type == VRMR_GUI_FORM_FIELD_TYPE_CHECKBOX) {
        form->fields[form->cur_field] = new_field_wrap(fld->h, fld->w, fld->toprow, fld->leftcol+1, 0, 2);
    }
    form->fields[form->cur_field];
    vrmr_fatal_if_null(form->fields[form->cur_field]);

    if (fld->type == VRMR_GUI_FORM_FIELD_TYPE_TEXT) {
        set_field_buffer_wrap(debuglvl, form->fields[form->cur_field], 0, fld->v.value_str);
        set_field_buffer_wrap(debuglvl, form->fields[form->cur_field], 1, fld->name);
        set_field_buffer_wrap(debuglvl, form->fields[form->cur_field], 2, "txt");
    } else if (fld->type == VRMR_GUI_FORM_FIELD_TYPE_LABEL) {
        set_field_buffer_wrap(debuglvl, form->fields[form->cur_field], 0, fld->v.value_str);
        set_field_buffer_wrap(debuglvl, form->fields[form->cur_field], 1, "lbl");
        set_field_buffer_wrap(debuglvl, form->fields[form->cur_field], 2, "lbl");
        field_opts_off(form->fields[form->cur_field], O_ACTIVE);
    } else if (fld->type == VRMR_GUI_FORM_FIELD_TYPE_CHECKBOX) {
        char *value = fld->v.value_bool ? "X" : " ";
        set_field_buffer_wrap(debuglvl, form->fields[form->cur_field], 0, value);
        set_field_buffer_wrap(debuglvl, form->fields[form->cur_field], 1, fld->name);
        set_field_buffer_wrap(debuglvl, form->fields[form->cur_field], 2, "C");
    }

    result = set_field_back(form->fields[form->cur_field], fld->cp);
    vrmr_fatal_if(result != E_OK);
    form->cur_field++;

    if (fld->type == VRMR_GUI_FORM_FIELD_TYPE_CHECKBOX) {
        vrmr_fatal_if (form->cur_field >= form->nfields);

        /* create the label [ ] */
        form->fields[form->cur_field] = new_field_wrap(fld->h, 3, fld->toprow, fld->leftcol, 0, 2);
        vrmr_fatal_if_null(form->fields[form->cur_field]);

        set_field_buffer_wrap(debuglvl, form->fields[form->cur_field], 0, "[ ]");
        set_field_buffer_wrap(debuglvl, form->fields[form->cur_field], 1, "lbl");
        set_field_buffer_wrap(debuglvl, form->fields[form->cur_field], 2, "lbl");
        field_opts_off(form->fields[form->cur_field], O_EDIT);
        field_opts_off(form->fields[form->cur_field], O_ACTIVE);

        result = set_field_back(form->fields[form->cur_field], fld->cp);
        vrmr_fatal_if(result != E_OK);
        form->cur_field++;
    }
}

static void
VrFormAddOKCancel(const int debuglvl, VrForm *form) {
    int result;

    /* +1 because we create two fields */
    vrmr_fatal_if(form->cur_field + 2 > form->nfields);

    form->fields[form->cur_field] = new_field_wrap(1, 10, form->h - 2, 2, 0, 2);
    vrmr_fatal_if_null(form->fields[form->cur_field]);

    set_field_buffer_wrap(debuglvl, form->fields[form->cur_field], 0, gettext("    OK"));
    set_field_buffer_wrap(debuglvl, form->fields[form->cur_field], 1, "save");
    set_field_buffer_wrap(debuglvl, form->fields[form->cur_field], 2, "btn");

    result = set_field_back(form->fields[form->cur_field], vccnf.color_win_green_rev | A_BOLD);
    vrmr_fatal_if(result != E_OK);
    field_opts_off(form->fields[form->cur_field], O_EDIT);

    form->cur_field++;

    form->fields[form->cur_field] = new_field_wrap(1, 10, form->h - 2, 16, 0, 2);
    vrmr_fatal_if_null(form->fields[form->cur_field]);

    set_field_buffer_wrap(debuglvl, form->fields[form->cur_field], 0, gettext("  Cancel"));
    set_field_buffer_wrap(debuglvl, form->fields[form->cur_field], 1, "nosave");
    set_field_buffer_wrap(debuglvl, form->fields[form->cur_field], 2, "btn");

    result = set_field_back(form->fields[form->cur_field], vccnf.color_win_red_rev | A_BOLD);
    vrmr_fatal_if(result != E_OK);
    field_opts_off(form->fields[form->cur_field], O_EDIT);

    form->cur_field++;
}

void
VrFormConnectToWin(const int debuglvl, VrForm *form, VrWin *win)
{
    int result;
    int rows, cols;
    struct vrmr_list_node *node = NULL;
    struct vrmr_gui_form_field *fld = NULL;
    int fields = 2; /* ok & cancel */

    /* count number of fields we need to create */
    for (node = form->list.top; node; node = node->next) {
        fld = node->data;
        switch (fld->type) {
            case VRMR_GUI_FORM_FIELD_TYPE_LABEL:
            case VRMR_GUI_FORM_FIELD_TYPE_TEXT:
                fields++;
                break;
            /* checkbox is actually 2 fields */
            case VRMR_GUI_FORM_FIELD_TYPE_CHECKBOX:
                fields += 2;
                break;
        }
    }

    form->nfields = fields;
    form->fields = calloc(form->nfields + 1, sizeof(FIELD *));
    vrmr_fatal_alloc("calloc", form->fields);
    memset(form->fields, 0, (sizeof(FIELD *) * (form->nfields + 1)));

    for (node = form->list.top; node; node = node->next) {
        fld = node->data;
        VrFormCreateField(debuglvl, form, fld);
    }

    /* add OK and Cancel fields */
    VrFormAddOKCancel(debuglvl, form);

    /* we are done adding fields, so reset counter */
    form->cur_field = 0;

    form->f = new_form(form->fields);
    vrmr_fatal_if_null(form->f);

    result = scale_form(form->f, &rows, &cols);
    vrmr_fatal_if(result != E_OK);

    result = set_form_win(form->f, win->w);
    vrmr_fatal_if(result != E_OK);

    form->dw = derwin(win->w, rows, cols, form->y, form->x);
    vrmr_fatal_if_null(form->dw);

    result = set_form_sub(form->f, form->dw);
    vrmr_fatal_if(result != E_OK);
}

static char
VrFormTextNavigation(const int debuglvl, VrForm *form, FIELD *fld, int key)
{
    char    match = FALSE;

    switch(key)
    {
        case 127:
        case KEY_BACKSPACE:
            form_driver(form->f, REQ_PREV_CHAR);
            form_driver(form->f, REQ_DEL_CHAR);
            form_driver(form->f, REQ_END_LINE);
            break;
        case KEY_DC:
            form_driver(form->f, REQ_PREV_CHAR);
            form_driver(form->f, REQ_DEL_CHAR);
            form_driver(form->f, REQ_END_LINE);
            break;
        case KEY_RIGHT:
            form_driver(form->f, REQ_NEXT_CHAR);
            match = TRUE;
            break;
        case KEY_LEFT:
            form_driver(form->f, REQ_PREV_CHAR);
            match = TRUE;
            break;
        case KEY_DOWN:
            form_driver(form->f, REQ_NEXT_FIELD);
            match = TRUE;
            break;
        case KEY_UP:
            form_driver(form->f, REQ_PREV_FIELD);
            match = TRUE;
            break;
        case KEY_NPAGE:
            if(form_driver(form->f, REQ_NEXT_PAGE) != E_OK)
            {
                while(form_driver(form->f, REQ_NEXT_FIELD) == E_OK);
            }
            match = TRUE;
            break;
        case KEY_PPAGE:
            if(form_driver(form->f, REQ_PREV_PAGE) != E_OK)
            {
                while(form_driver(form->f, REQ_PREV_FIELD) == E_OK);
            }
            match = TRUE;
            break;
/* TODO last pos in field */
        case KEY_HOME:
            form_driver(form->f, REQ_BEG_LINE);
            match = TRUE;
            break;
        case KEY_END:
            form_driver(form->f, REQ_END_LINE);
            match = TRUE;
            break;
        case 9: /* TAB */
            form_driver(form->f, REQ_NEXT_FIELD);
            match = TRUE;
            break;
        default:
            //vrmr_info(VR_INFO, "default");
            if (isprint(key)) {
                //vrmr_info(VR_INFO, "default %d", key);
                form_driver(form->f, key);
                match = TRUE;
            }
            break;
    }

    return(match);
}

static char
VrFormCheckboxNavigation(const int debuglvl, VrForm *form, FIELD *fld, int key)
{
    char    match = FALSE;

    switch(key)
    {
        case KEY_DOWN:
            form_driver(form->f, REQ_NEXT_FIELD);
            match = TRUE;
            break;
        case KEY_UP:
            form_driver(form->f, REQ_PREV_FIELD);
            match = TRUE;
            break;
        case KEY_NPAGE:
            if(form_driver(form->f, REQ_NEXT_PAGE) != E_OK)
            {
                while(form_driver(form->f, REQ_NEXT_FIELD) == E_OK);
            }
            match = TRUE;
            break;
        case KEY_PPAGE:
            if(form_driver(form->f, REQ_PREV_PAGE) != E_OK)
            {
                while(form_driver(form->f, REQ_PREV_FIELD) == E_OK);
            }
            match = TRUE;
            break;
        case 9: /* TAB */
            form_driver(form->f, REQ_NEXT_FIELD);
            match = TRUE;
            break;
        case 32: /* SPACE */
        {
            char *buf = field_buffer(fld, 0);
            if (strncmp(buf, "X", 1) == 0) {
                set_field_buffer_wrap(debuglvl, fld, 0, " ");
            } else {
                set_field_buffer_wrap(debuglvl, fld, 0, "X");
            }

            match = TRUE;
            break;
        }
    }

    return(match);
}

/*  default keys:
        up
        down
        pageup
        pagedown
        home
        end

    returns TRUE if the key matched, false if not
*/
char
VrFormDefaultNavigation(const int debuglvl, VrForm *form, int key)
{
    char    match = FALSE;
    FIELD   *fld = NULL;
    char    *buf = NULL;

    //vrmr_debug(__FUNC__, "key %d", key);

    fld = current_field(form->f);
    if (fld == NULL)
        return(FALSE);

    buf = field_buffer(fld, 2);
    if (buf == NULL)
        return(FALSE);

    if (strncmp(buf, "txt", 3) == 0)
        return(VrFormTextNavigation(debuglvl, form, fld, key));
    else if (strncmp(buf, "C", 1) == 0)
        return(VrFormCheckboxNavigation(debuglvl, form, fld, key));

    switch(key)
    {
        case KEY_RIGHT:
            form_driver(form->f, REQ_NEXT_CHAR);
            match = TRUE;
            break;
        case KEY_LEFT:
            form_driver(form->f, REQ_PREV_CHAR);
            match = TRUE;
            break;
        case KEY_DOWN:
            form_driver(form->f, REQ_NEXT_FIELD);
            match = TRUE;
            break;
        case KEY_UP:
            form_driver(form->f, REQ_PREV_FIELD);
            match = TRUE;
            break;
        case KEY_NPAGE:
            if(form_driver(form->f, REQ_NEXT_PAGE) != E_OK)
            {
                while(form_driver(form->f, REQ_NEXT_FIELD) == E_OK);
            }
            match = TRUE;
            break;
        case KEY_PPAGE:
            if(form_driver(form->f, REQ_PREV_PAGE) != E_OK)
            {
                while(form_driver(form->f, REQ_PREV_FIELD) == E_OK);
            }
            match = TRUE;
            break;
/* TODO last pos in field */
        case KEY_HOME:
            form_driver(form->f, REQ_FIRST_FIELD);
            match = TRUE;
            break;
        case KEY_END:
            form_driver(form->f, REQ_LAST_FIELD);
            match = TRUE;
            break;
        case 9: /* TAB */
            form_driver(form->f, REQ_NEXT_FIELD);
            match = TRUE;
            break;
    }

    return(match);
}

static int
VrFormGetFields(const int debuglvl, VrForm *form, char *name, size_t nlen, char *value, size_t vlen)
{
    FIELD *field = NULL;
    char *n = NULL, *v = NULL;

    if (form->cur_field >= form->nfields) {
        form->cur_field = 0;
        return(0);
    }

    /* skip past non active (label) fields,
     * but not past non visible fields */
    while (form->cur_field < form->nfields) {
        int opts = field_opts(form->fields[form->cur_field]);
        char *buf = field_buffer(form->fields[form->cur_field], 2);

        if (buf != NULL && (strncmp(buf, "btn", 3) == 0)) {
            //vrmr_info(VR_INFO, "button field");
        } else if(!(opts & O_ACTIVE)) {
            //vrmr_info(VR_INFO, "inactive field");
        } else {
            break;
        }

        form->cur_field++;
    }
    if (form->cur_field >= form->nfields)
        return(0);

    field = form->fields[form->cur_field];
    form->cur_field++;

    n = field_buffer(field, 1);
    copy_field2buf(name, n, nlen);
    v = field_buffer(field, 0);
    copy_field2buf(value, v, vlen);

    //vrmr_info(VR_INFO, "name %s value %s", name, value);
    return(1);
}

int
VrFormCheckOKCancel(const int debuglvl, VrForm *form, int key)
{
    FIELD *fld = NULL;
    char *buf = NULL;

    //vrmr_debug(__FUNC__, "key %d", key);

    fld = current_field(form->f);
    if (fld == NULL)
        return(-1);

    buf = field_buffer(fld, 1);
    if (buf == NULL)
        return(-1);

    if(key == 27 || key == KEY_F(10) || (key == 10 && strncmp(buf,"save", 4) == 0))
    {
        if (form->save != NULL && form->save_ctx != NULL) {
            char name[32] = "", value[32] = "";

            /* save */
            while((VrFormGetFields(debuglvl, form, name, sizeof(name), value, sizeof(value)) == 1)) {
                form->save(debuglvl, form->save_ctx, name, value);
            }
        }
        return(1);

    }
    else if(key == 10 && strncmp(buf,"nosave", 6) == 0)
    {
        return(1);
    }

    return(0);
}

void
VrFormDrawMarker(const int debuglvl, VrWin *win, VrForm *form) {
    int pos_x,
        pos_y,
        x,
        y,
        off_row,
        wrk_buff;
    int ch = vccnf.color_win_mark|A_BOLD;

    form->prev = form->cur;
    form->cur  = current_field(form->f);

    /* if supplied we remove the previous marking */
    if(form->prev)
    {
        if(field_info(form->prev, &y, &x, &pos_y, &pos_x, &off_row, &wrk_buff) < 0)
            return;

        mvwprintw(win->w, pos_y + 1, pos_x - 1, " ");
        mvwprintw(win->w, pos_y + 1, pos_x + x + 2, " ");
    }

    /* draw our marking */
    if(field_info(form->cur, &y, &x, &pos_y, &pos_x, &off_row, &wrk_buff) < 0)
        return;

    wattron(win->w, ch);
    mvwprintw(win->w, pos_y + 1, pos_x - 1, ">");
    mvwprintw(win->w, pos_y + 1, pos_x + x + 2, "<");
    wattroff(win->w, ch);
    wrefresh(win->w);

    /* restore cursor position */
    pos_form_cursor(form->f);
    return;
}

int
VrFormSetSaveFunc(const int debuglvl, VrForm *form, int (*save)(const int debuglvl, void *ctx, char *name, char *value), void *ctx) {
    form->save_ctx = ctx;
    form->save = save;
    return(0);
}
