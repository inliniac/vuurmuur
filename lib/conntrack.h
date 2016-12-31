/***************************************************************************
 *   Copyright (C) 2002-2017 by Victor Julien                              *
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

#ifndef __CONNTRACK_H__
#define __CONNTRACK_H__

/*
    UNDEFINED=0,
    TCP_ESTABLISHED,
    UDP_ESTABLISHED,
    SYN_SENT,
    SYN_RECV,
    FIN_WAIT,
    TIME_WAIT,
    CLOSE,
    CLOSE_WAIT,
    UNREPLIED,
    NONE,
*/

char *conn_status[] =
{
    "UNDEFINED",
    "TCP_ESTABLISHED",
    "UDP_ESTABLISHED",
    "SYN_SENT",
    "SYN_RECV",
    "FIN_WAIT",
    "TIME_WAIT",
    "CLOSE",
    "CLOSE_WAIT",
    "UNREPLIED",
    "NONE",
    "ERROR",
};

#endif
