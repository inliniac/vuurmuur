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
#ifndef __NFLOG_H__
#define __NFLOG_H__

#include "vuurmuur_log.h"
#include "stats.h"

#include <libnetfilter_log/libnetfilter_log.h>

static int dbg_pkt(struct nflog_data *, char *, int);
static int cb(struct nflog_g_handle *, struct nfgenmsg *, struct nflog_data *, void *);
int subscribe_nflog (const int, const struct vuurmuur_config *,struct log_rule *logrule);
int readnflog ();

#endif
