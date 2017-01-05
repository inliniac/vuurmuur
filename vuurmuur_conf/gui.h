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

#ifndef __GUI_H__
#define __GUI_H__

/* menu wrapper */
typedef struct
{
    MENU            *m;
    ITEM            **i;
    unsigned int    nitems;

    char            use_namelist;
    struct vrmr_list          name;
    void            (*free_name)(void *ptr);

    char            use_desclist;
    struct vrmr_list          desc;
    void            (*free_desc)(void *ptr);

    unsigned int    cur_item;

    chtype          fg,
                    bg;

    int             h,  /* height */
                    w,  /* width */
                    y,  /*  y start relative
                            to win */
                    x;  /*  x start relative
                            to win */
    WINDOW          *dw;    /* used by derwin */

} VrMenu;

/** form field types */
enum vrmr_gui_form_field_types {
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
        char *value_str;
        int value_bool;
    } v;
};

/* form wrapper */
typedef struct
{
    FORM            *f;
    FIELD           **fields;
    FIELD           *cur, *prev;
    unsigned int    nfields;
    unsigned int    cur_field;

    chtype          fg,
                    bg;

    int             h,  /* height */
                    w,  /* width */
                    y,  /*  y start relative
                            to win */
                    x;  /*  x start relative
                            to win */
    WINDOW          *dw;    /* used by derwin */

    int             (*save)(const int debuglvl, void *ctx, char *name, char *value);
    void            *save_ctx;

    struct vrmr_list list;  /**< list of vrmr_gui_form_field's, filled
                             *   during setup of a form. */
} VrForm;

/* window/panel wrapper */
typedef struct
{

    WINDOW  *w;
    PANEL   *p;

    int     height,
            width;

    int     y, x;

    /* TODO: add menu? */

} VrWin;


/* global busywin */
VrWin   *vr_busywin;

void VrBusyWinCreate(const int debuglvl);
void VrBusyWinShow(void);
void VrBusyWinHide(void);
void VrBusyWinDelete(const int debuglvl);

int VrWinGetOffset(int yj, int xj, int h, int w, int yo, int xo, int *y, int *x);
VrWin *VrNewWin(int h, int w, int y, int x, chtype cp);
void VrDelWin(VrWin *win);
int VrWinSetTitle(VrWin *win, char *title);
int VrWinGetch(VrWin *win);

VrMenu *VrNewMenu(int h, int w, int y, int x, unsigned int n, chtype bg, chtype fg);
void VrDelMenu(const int, VrMenu *);
void VrMenuSetupNameList(const int debuglvl, VrMenu *menu);
void VrMenuSetupDescList(const int debuglvl, VrMenu *menu);
void VrMenuSetNameFreeFunc(VrMenu *menu, void (*free_func)(void *ptr));
void VrMenuSetDescFreeFunc(VrMenu *menu, void (*free_func)(void *ptr));
int VrMenuAddItem(const int debuglvl, VrMenu *menu, char *name, char *desc);
int VrMenuAddSepItem(const int debuglvl, VrMenu *menu, char *desc);
int VrMenuConnectToWin(const int debuglvl, VrMenu *menu, VrWin *win);
char VrMenuDefaultNavigation(const int debuglvl, VrMenu *menu, int key);
int VrMenuPost(const int, VrMenu *);
int VrMenuUnPost(const int, VrMenu *);

VrForm *VrNewForm(int h, int w, int y, int x, chtype bg, chtype fg);
void VrDelForm(const int debuglvl, VrForm *form);
int VrFormPost(const int debuglvl, VrForm *form);
int VrFormUnPost(const int debuglvl, VrForm *form);
int VrFormAddTextField(const int debuglvl, VrForm *form, int height, int width, int toprow, int leftcol, chtype cp, char *name, char *value);
int VrFormAddLabelField(const int debuglvl, VrForm *form, int height, int width, int toprow, int leftcol, chtype cp, char *value);
int VrFormAddCheckboxField(const int debuglvl, VrForm *form, int toprow, int leftcol, chtype cp, char *name, char enabled);
int VrFormConnectToWin(const int debuglvl, VrForm *form, VrWin *win);
char VrFormDefaultNavigation(const int debuglvl, VrForm *form, int key);
int VrFormCheckOKCancel(const int debuglvl, VrForm *form, int key);
void VrFormDrawMarker(const int debuglvl, VrWin *win, VrForm *form);
int VrFormSetSaveFunc(const int debuglvl, VrForm *form, int (*save)(const int debuglvl, void *ctx, char *name, char *value), void *ctx);

#endif /* __GUI_H__ */
