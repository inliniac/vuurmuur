/***************************************************************************
 *   Copyright (C) 2002-2007 by Victor Julien                              *
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

#include "config.h"
#include "vuurmuur.h"

void
VR_filter_setup(const int debuglvl, VR_filter *filter)
{
    /* safety */
    if(filter == NULL)
    {
        (void)vrprint.error(-1, "Internal Error", "parameter problem "
                "(in: %s:%d).", __FUNC__, __LINE__);
        return;
    }

    memset(filter, 0, sizeof(VR_filter));
}


void
VR_filter_cleanup(const int debuglvl, VR_filter *filter)
{
    /* safety */
    if(filter == NULL)
    {
        (void)vrprint.error(-1, "Internal Error", "parameter problem "
                "(in: %s:%d).", __FUNC__, __LINE__);
        return;
    }

    if(filter->reg_active == TRUE)
    {
        /* first remove old regex */
        regfree(&filter->reg);
        /* set reg_active to false */
        filter->reg_active = FALSE;
    }

    memset(filter, 0, sizeof(VR_filter));
}
