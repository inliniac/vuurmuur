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

/** \file
 * stats.c implements functions to keep track of statistics */

#include "vuurmuur_log.h"
#include "stats.h"

void
show_stats (struct Counters_ *c)
{
    fprintf(stdout, "\nStatistics:\n");

    fprintf(stdout, "Total logrules: %u (vuurmuur: %u, other: %u, invalid: %u)\n", c->total, c->totalvuurmuur, c->noipt, c->invalid_loglines);

    fprintf(stdout, "\nMatches:\n");
    fprintf(stdout, "Accepted    : %u\n", c->accept);
    fprintf(stdout, "Queued      : %u\n", c->queue);
    fprintf(stdout, "Rejected    : %u\n", c->reject);
    fprintf(stdout, "Dropped     : %u\n", c->drop);
    fprintf(stdout, "Other       : %u\n", c->other_match);

    fprintf(stdout, "\nProtocols:\n");
    fprintf(stdout, "TCP         : %u\n", c->tcp);
    fprintf(stdout, "UDP         : %u\n", c->udp);
    fprintf(stdout, "ICMP        : %u\n", c->icmp);
    fprintf(stdout, "Other       : %u\n", c->other_proto);
    return;
}

void
upd_action_ctrs (char *action, struct Counters_ *c)
{
    /* ACTION counters */
    if(strcmp(action, "DROP") == 0)
        c->drop++;
    else if(strcmp(action, "ACCEPT") == 0)
        c->accept++;
    else if(strcmp(action, "REJECT") == 0)
        c->reject++;
    else if(strcmp(action, "QUEUE") == 0)
        c->queue++;
    else
        c->other_match++;
    return;
}
