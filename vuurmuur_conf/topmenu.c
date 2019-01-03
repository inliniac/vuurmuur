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

static void menunameprint(WINDOW *win, const char *menuname)
{
    if (menuname != NULL)
        mvwprintw(win, 0, 2, " %s ", menuname);
}

static int keyprint(
        WINDOW *win, int y, int x, const char *keystr, const char *fmt, ...)
{
    int res = 0, printlen = 0;

    vrmr_fatal_if_null(keystr);
    vrmr_fatal_if_null(fmt);

    printlen = (int)(StrLen(keystr) + 2 + StrLen(fmt));
    if (printlen + x > COLS - 2)
        return (0);
    if (x > COLS - 2)
        return (0);

    wattron(win, vccnf.color_bgd | A_BOLD);
    mvwprintw(win, y, x, "%s:", keystr);
    wattroff(win, vccnf.color_bgd | A_BOLD);

    wattron(win, vccnf.color_bgd_hi | A_BOLD);
    mvwprintw(win, y, (int)(x + StrLen(keystr) + 1), fmt);
    wattroff(win, vccnf.color_bgd_hi | A_BOLD);

    res = (int)(x + StrLen(keystr) + 1 + StrLen(fmt) + 2);
    return (res);
}

struct {
    char hostname[60];
} TopMenu;

static void setup_topmenu(WINDOW *local_win)
{
    int max_width;

    if (!local_win)
        return;

    max_width = getmaxx(stdscr);

    /* get the hostname */
    if (gethostname(TopMenu.hostname, sizeof(TopMenu.hostname)) < 0)
        (void)strlcpy(
                TopMenu.hostname, gettext("error"), sizeof(TopMenu.hostname));

    wattron(local_win, vccnf.color_bgd | A_BOLD);
    mvwprintw(local_win, 0, (int)(max_width - 4 - StrLen(TopMenu.hostname)),
            " %s ", TopMenu.hostname);
    wattroff(local_win, vccnf.color_bgd | A_BOLD);
}

void draw_top_menu(WINDOW *local_win, char *title, int key_n, char **keys,
        int cmd_n, char **cmds)
{
    int pos = 2, i = 0;

    vrmr_fatal_if(key_n != cmd_n);

    werase(local_win);

    /* draw the box and the title */
    wattron(local_win, vccnf.color_bgd);
    box(local_win, 0, 0);
    menunameprint(local_win, title);
    wattroff(local_win, vccnf.color_bgd);

    for (i = 0; i < key_n; i++) {
        pos = keyprint(local_win, 1, pos, keys[i], cmds[i]);
        if (pos <= 0)
            break;
    }

    setup_topmenu(local_win);
    update_panels();
    doupdate();
}
