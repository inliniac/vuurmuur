/***************************************************************************
 *   Copyright (C) 2002-2008 by Victor Julien                              *
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

int
libvuurmuur_is_shape_rule(const int debuglvl, /*@null@*/struct options *opt) {
    if (opt != NULL &&
        (opt->bw_in_min > 0 ||
        opt->bw_in_max > 0 ||
        opt->bw_out_min > 0 ||
        opt->bw_out_max > 0 ||
        opt->prio > 0))
    {
        return(1);
    }

    return(0);
}

int
libvuurmuur_is_shape_incoming_rule(const int debuglvl, /*@null@*/struct options *opt) {
    if (opt != NULL &&
        (opt->bw_in_min > 0 ||
        opt->bw_in_max > 0 ||
        opt->prio > 0))
    {
        return(1);
    }

    return(0);
}

int
libvuurmuur_is_shape_outgoing_rule(const int debuglvl, /*@null@*/struct options *opt) {
    if (opt != NULL &&
        (opt->bw_out_min > 0 ||
        opt->bw_out_max > 0 ||
        opt->prio > 0))
    {
        return(1);
    }

    return(0);
}

int
libvuurmuur_is_shape_interface(const int debuglvl, /*@null@*/InterfaceData *iface_ptr) {
    if (iface_ptr != NULL &&
        iface_ptr->shape == TRUE &&
        iface_ptr->device_virtual == FALSE &&
        (conf.bash_out || iface_ptr->up == TRUE))
    {
        return(1);
    }

    return(0);
}

