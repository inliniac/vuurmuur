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

#ifndef __STATS_H__
#define __STATS_H__

struct logcounters {
    uint32_t drop;
    uint32_t accept;
    uint32_t reject;
    uint32_t queue;
    uint32_t other_match;

    uint32_t tcp;
    uint32_t udp;
    uint32_t icmp;
    uint32_t other_proto;

    uint32_t totalvuurmuur;

    uint32_t noipt;
    uint32_t invalid_loglines;

    uint32_t total;
};

void show_stats(struct logcounters *);
void upd_action_ctrs(char *action, struct logcounters *c);

#endif /* __STATS_H__ */
