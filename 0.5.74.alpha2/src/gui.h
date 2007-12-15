/***************************************************************************
 *   Copyright (C) 2003-2007 by Victor Julien                              *
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
	MENU		*m;
	ITEM		**i;
	unsigned int	nitems;

	char		use_namelist;
	d_list		name;
	void		(*free_name)(void *ptr);

	char		use_desclist;
	d_list		desc;
	void		(*free_desc)(void *ptr);

	unsigned int	cur_item;

	chtype		fg,
			bg;

	int		h,			/* height */
			w,			/* width */
			y,			/*	y start relative
							to win */
			x;			/*	x start relative
							to win */
	WINDOW		*dw;			/* used by derwin */

} VrMenu;

/* form wrapper */
typedef struct
{
	FORM		*f;
	FIELD		**fields;
	FIELD		*cur, *prev;
	unsigned int	nfields;
	unsigned int	cur_field;

	chtype		fg,
			bg;

	int		h,			/* height */
			w,			/* width */
			y,			/*	y start relative
							to win */
			x;			/*	x start relative
							to win */
	WINDOW		*dw;			/* used by derwin */

	int		(*save)(const int debuglvl, void *ctx, char *name, char *value);
	void		*save_ctx;

} VrForm;

/* window/panel wrapper */
typedef struct
{

	WINDOW	*w;
	PANEL	*p;

	int	height,
		width;

	/* TODO: add menu? */

} VrWin;


/* global busywin */
VrWin			*vr_busywin;

void VrBusyWinCreate(const int debuglvl);
void VrBusyWinShow(void);
void VrBusyWinHide(void);
void VrBusyWinDelete(const int debuglvl);

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

#endif
