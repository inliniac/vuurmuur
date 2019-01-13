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

#ifndef __GUI_H__
#define __GUI_H__

/* menu wrapper */
struct vrmr_gui_menu {
    MENU *m;
    ITEM **i;
    unsigned int nitems;

    char use_namelist;
    struct vrmr_list name;
    void (*free_name)(void *ptr);

    char use_desclist;
    struct vrmr_list desc;
    void (*free_desc)(void *ptr);

    unsigned int cur_item;

    chtype fg, bg;

    int h,      /* height */
            w,  /* width */
            y,  /*  y start relative
                    to win */
            x;  /*  x start relative
                    to win */
    WINDOW *dw; /* used by derwin */
};

/** form field types */
enum vrmr_gui_form_field_types
{
    VRMR_GUI_FORM_FIELD_TYPE_LABEL,
    VRMR_GUI_FORM_FIELD_TYPE_TEXT,
    VRMR_GUI_FORM_FIELD_TYPE_CHECKBOX,
};

/** storage for form field registration */
struct vrmr_gui_form_field {
    enum vrmr_gui_form_field_types type;
    chtype cp;
    int h, w, toprow, leftcol;
    const char *name;
    union {
        const char *value_str;
        int value_bool;
    } v;
};

/* form wrapper */
struct vrmr_gui_form {
    FORM *f;
    FIELD **fields;
    FIELD *cur, *prev;
    unsigned int nfields;
    unsigned int cur_field;

    chtype fg, bg;

    int h,      /* height */
            w,  /* width */
            y,  /*  y start relative
                    to win */
            x;  /*  x start relative
                    to win */
    WINDOW *dw; /* used by derwin */

    int (*save)(void *ctx, char *name, char *value);
    void *save_ctx;

    struct vrmr_list list; /**< list of vrmr_gui_form_field's, filled
                            *   during setup of a form. */
};

/* window/panel wrapper */
struct vrmr_gui_win {

    WINDOW *w;
    PANEL *p;

    int height, width;

    int y, x;

    /* TODO: add menu? */
};

/* global busywin */
struct vrmr_gui_win *vr_busywin;

void VrBusyWinCreate(void);
void VrBusyWinShow(void);
void VrBusyWinHide(void);
void VrBusyWinDelete(void);

int VrWinGetOffset(
        int yj, int xj, int h, int w, int yo, int xo, int *y, int *x);
struct vrmr_gui_win *VrNewWin(int h, int w, int y, int x, chtype cp);
void VrDelWin(struct vrmr_gui_win *win);
int VrWinSetTitle(struct vrmr_gui_win *win, const char *title);
int VrWinGetch(struct vrmr_gui_win *win);

struct vrmr_gui_menu *VrNewMenu(
        int h, int w, int y, int x, unsigned int n, chtype bg, chtype fg);
void VrDelMenu(struct vrmr_gui_menu *);
void VrMenuSetupNameList(struct vrmr_gui_menu *menu);
void VrMenuSetupDescList(struct vrmr_gui_menu *menu);
void VrMenuSetNameFreeFunc(
        struct vrmr_gui_menu *menu, void (*free_func)(void *ptr));
void VrMenuSetDescFreeFunc(
        struct vrmr_gui_menu *menu, void (*free_func)(void *ptr));
int VrMenuAddItem(
        struct vrmr_gui_menu *menu, const char *name, const char *desc);
int VrMenuAddSepItem(struct vrmr_gui_menu *menu, const char *desc);
void VrMenuConnectToWin(struct vrmr_gui_menu *menu, struct vrmr_gui_win *win);
char VrMenuDefaultNavigation(struct vrmr_gui_menu *menu, int key);
void VrMenuPost(struct vrmr_gui_menu *);
void VrMenuUnPost(struct vrmr_gui_menu *);

struct vrmr_gui_form *VrNewForm(
        int h, int w, int y, int x, chtype bg, chtype fg);
void VrDelForm(struct vrmr_gui_form *form);
void VrFormPost(struct vrmr_gui_form *form);
void VrFormUnPost(struct vrmr_gui_form *form);
void VrFormAddTextField(struct vrmr_gui_form *form, int height, int width,
        int toprow, int leftcol, chtype cp, const char *name,
        const char *value);
void VrFormAddLabelField(struct vrmr_gui_form *form, int height, int width,
        int toprow, int leftcol, chtype cp, const char *value);
void VrFormAddCheckboxField(struct vrmr_gui_form *form, int toprow, int leftcol,
        chtype cp, const char *name, char enabled);
void VrFormConnectToWin(struct vrmr_gui_form *form, struct vrmr_gui_win *win);
char VrFormDefaultNavigation(struct vrmr_gui_form *form, int key);
int VrFormCheckOKCancel(struct vrmr_gui_form *form, int key);
void VrFormDrawMarker(struct vrmr_gui_win *win, struct vrmr_gui_form *form);
int VrFormSetSaveFunc(struct vrmr_gui_form *form,
        int (*save)(void *ctx, char *name, char *value), void *ctx);

#endif /* __GUI_H__ */
