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

/*	helper functions for building the GUI

*/

#include "main.h"

void
VrBusyWinCreate(const int debuglvl)
{
	int	width = 20,
		height = 5;

	vr_busywin = VrNewWin(height, width, 0, 0, COLOR_PAIR(CP_BLUE_WHITE));

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


VrWin *
VrNewWin(int h, int w, int y, int x, chtype cp)
{
	VrWin	*win;
	int	maxx = 0,
		maxy = 0;

	/* max screen sizes */
	getmaxyx(stdscr, maxy, maxx);

	/*	if requested, place the window in the middle of the screen */
	if(y == 0)
	{
		y = (maxy - h)/2;
	}
	if(x == 0)
	{
		x = (maxx - w)/2;
	}

	win = malloc(sizeof(VrWin));
	if ( win == NULL )
	{
		// error
		return(NULL);
	}
	memset(win, 0, sizeof(VrWin));

	win->w = newwin(h, w, y, x);
	if( win->w == NULL)
	{
		// error
		// cleanup
		return(NULL);
	}
	win->p = new_panel(win->w);
	if( win->p == NULL)
	{
		// error
		// cleanup
		return(NULL);
	}

	box(win->w, 0, 0);
	wbkgd(win->w, cp);
	keypad(win->w, TRUE);

	win->height = h;
	win->width= w;

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
	size_t	len = strlen(title);
	size_t	printstart = 0;

	if((len - 4) > win->width)
	{
		return(0);
	}

	/* */
	printstart = (win->width - len - 2)/2;
	
	mvwprintw(win->w, 0, (int)printstart, " %s ", title);

	return(0);
}


int
VrWinGetch(VrWin *win)
{
	return(wgetch(win->w));
}


VrMenu *
VrNewMenu(int h, int w, int y, int x, unsigned int n, chtype bg, chtype fg)
{
	VrMenu *menu;

	menu = malloc(sizeof(VrMenu));
	if ( menu == NULL )
	{
		// error
		(void)vrprint.error(-1, VR_ERR, "malloc failed");
		return(NULL);
	}
	memset(menu, 0, sizeof(VrMenu));

	menu->h = h;
	menu->w = w;
	menu->y = y;
	menu->x = x;

	menu->i = calloc(sizeof(ITEM), n);
	if ( menu->i == NULL )
	{
		// error
		(void)vrprint.error(-1, VR_ERR, "calloc failed");
		return(NULL);
	}
	memset(menu->i, 0, (sizeof(ITEM) * n));
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
	d_list_setup(debuglvl, &menu->name, menu->free_name);
	menu->use_namelist = TRUE;
}


void
VrMenuSetupDescList(const int debuglvl, VrMenu *menu)
{
	d_list_setup(debuglvl, &menu->desc, menu->free_desc);
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
	int i = 0;

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
		d_list_cleanup(debuglvl, &menu->name);
	if(menu->use_desclist == TRUE)
		d_list_cleanup(debuglvl, &menu->desc);

	/* free memory */
	free(menu);
}

int
VrMenuAddItem(const int debuglvl, VrMenu *menu, char *name, char *desc)
{
	if(menu->cur_item >= menu->nitems)
	{
		(void)vrprint.error(-1, VR_ERR, "menu full: all %u items already added", menu->nitems);
		return(-1);
	}

	if(menu->use_namelist == TRUE)
	{
		if(d_list_append(debuglvl, &menu->name, name) == NULL)
		{
			(void)vrprint.error(-1, VR_ERR, "d_list_append failed");
			return(-1);
		}
	}
	if(menu->use_desclist == TRUE)
	{
		if(d_list_append(debuglvl, &menu->desc, desc) == NULL)
		{
			(void)vrprint.error(-1, VR_ERR, "d_list_append failed");
			return(-1);
		}
	}

	menu->i[menu->cur_item] = new_item(name, desc);
	if(menu->i[menu->cur_item] == NULL)
	{
		(void)vrprint.error(-1, VR_ERR, "new_item failed");
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
		(void)vrprint.error(-1, VR_ERR, "menu full: all %u items already added", menu->nitems);
		return(-1);
	}

	if(menu->use_desclist == TRUE)
	{
		if(d_list_append(debuglvl, &menu->desc, desc) == NULL)
		{
			(void)vrprint.error(-1, VR_ERR, "d_list_append failed");
			return(-1);
		}
	}

	menu->i[menu->cur_item] = new_item(" ", desc);
	if(menu->i[menu->cur_item] == NULL)
	{
		(void)vrprint.error(-1, VR_ERR, "new_item failed");
		return(-1);
	}
	item_opts_off(menu->i[menu->cur_item], O_SELECTABLE);

	menu->cur_item++;

	return(0);
}


int
VrMenuConnectToWin(const int debuglvl, VrMenu *menu, VrWin *win)
{
	int result;

	menu->m = new_menu((ITEM **)menu->i);
	if ( menu->m == NULL )
	{
		// error
		(void)vrprint.error(-1, VR_ERR, "new_menu failed");
		return(-1);
	}
	result = set_menu_win(menu->m, win->w);
	if(result != E_OK)
	{
		(void)vrprint.error(-1, VR_ERR, "set_menu_win failed");
		return(-1);
	}
	
	menu->dw = derwin(win->w, menu->h, menu->w, menu->y, menu->x);
	if(menu->dw == NULL)
	{
		(void)vrprint.error(-1, VR_ERR, "derwin failed");
		return(-1);
	}

	result = set_menu_sub(menu->m, menu->dw);
	if(result != E_OK)
	{
		(void)vrprint.error(-1, VR_ERR, "set_menu_sub failed");
		return(-1);
	}
	result = set_menu_format(menu->m, win->height - 2, 1);
	if(result != E_OK)
	{
		if(result == E_BAD_ARGUMENT)
		{
		    (void)vrprint.error(-1, VR_ERR, "set_menu_format failed: E_BAD_ARGUMENT");
		}
		else if(result == E_SYSTEM_ERROR)
		{
		    (void)vrprint.error(-1, VR_ERR, "set_menu_format failed: E_SYSTEM_ERROR");
		}
		else if(result == E_POSTED)
		{
		    (void)vrprint.error(-1, VR_ERR, "set_menu_format failed: E_POSTED");
		}
		else
		{
		    (void)vrprint.error(-1, VR_ERR, "set_menu_format failed: unknown error");
		}

		return(-1);
	}

	set_menu_back(menu->m, menu->bg);
	set_menu_grey(menu->m, menu->bg);
	set_menu_fore(menu->m, menu->fg);

	return(0);
}


/*	default keys:
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
	char	match = FALSE;

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
	}

	return(match);
}


int
VrMenuPost(const int debuglvl, VrMenu *menu)
{
	int result = 0;	

	result = post_menu(menu->m);
	if(result != E_OK)
	{
		if(result == E_BAD_ARGUMENT)
		{
		    (void)vrprint.error(-1, VR_ERR, "post_menu failed: E_BAD_ARGUMENT");
		}
		else if(result == E_SYSTEM_ERROR)
		{
		    (void)vrprint.error(-1, VR_ERR, "post_menu failed: E_SYSTEM_ERROR");
		}
		else if(result == E_POSTED)
		{
		    (void)vrprint.error(-1, VR_ERR, "post_menu failed: E_POSTED");
		}
		else if(result == E_BAD_STATE)
		{
		    (void)vrprint.error(-1, VR_ERR, "post_menu failed: E_BAD_STATE");
		}
		else if(result == E_NO_ROOM)
		{
		    (void)vrprint.error(-1, VR_ERR, "post_menu failed: E_NO_ROOM");
		}
		else if(result == E_NOT_POSTED)
		{
		    (void)vrprint.error(-1, VR_ERR, "post_menu failed: E_NOT_POSTED");
		}
		else if(result == E_NOT_CONNECTED)
		{
		    (void)vrprint.error(-1, VR_ERR, "post_menu failed: E_NOT_CONNECTED");
		}
		else
		{
		    (void)vrprint.error(-1, VR_ERR, "post_menu failed: unknown error %d", result);
		}

		return(-1);
	}

	return(0);
}

int
VrMenuUnPost(const int debuglvl, VrMenu *menu)
{
	int result = 0;	

	result = unpost_menu(menu->m);
	if(result != E_OK)
	{
		if(result == E_BAD_ARGUMENT)
		{
		    (void)vrprint.error(-1, VR_ERR, "unpost_menu failed: E_BAD_ARGUMENT");
		}
		else if(result == E_SYSTEM_ERROR)
		{
		    (void)vrprint.error(-1, VR_ERR, "unpost_menu failed: E_SYSTEM_ERROR");
		}
		else if(result == E_POSTED)
		{
		    (void)vrprint.error(-1, VR_ERR, "unpost_menu failed: E_POSTED");
		}
		else if(result == E_BAD_STATE)
		{
		    (void)vrprint.error(-1, VR_ERR, "unpost_menu failed: E_BAD_STATE");
		}
		else if(result == E_NO_ROOM)
		{
		    (void)vrprint.error(-1, VR_ERR, "unpost_menu failed: E_NO_ROOM");
		}
		else if(result == E_NOT_POSTED)
		{
		    (void)vrprint.error(-1, VR_ERR, "unpost_menu failed: E_NOT_POSTED");
		}
		else if(result == E_NOT_CONNECTED)
		{
		    (void)vrprint.error(-1, VR_ERR, "unpost_menu failed: E_NOT_CONNECTED");
		}
		else
		{
		    (void)vrprint.error(-1, VR_ERR, "unpost_menu failed: unknown error %d", result);
		}

		return(-1);
	}

	return(0);
}
