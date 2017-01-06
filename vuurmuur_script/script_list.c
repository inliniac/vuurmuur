/***************************************************************************
 *   Copyright (C) 2005-2017 by Victor Julien                              *
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

#include "vuurmuur_script.h"

int
script_list(const int debuglvl, VuurmuurScript *vr_script)
{
    char    back_zone[VRMR_MAX_ZONE] = "",
            back_net[VRMR_MAX_NETWORK] = "",
            back_host[VRMR_MAX_HOST] = "";

    if(vr_script->type == VRMR_TYPE_ZONE)
    {
        while(vr_script->vctx.zf->list(debuglvl, vr_script->vctx.zone_backend, vr_script->bdat, &vr_script->zonetype, VRMR_BT_ZONES) != NULL)
        {
            if(vr_script->zonetype == vr_script->type)
            {
                printf("%s\n", vr_script->bdat);
            }
        }
    }
    else if(vr_script->type == VRMR_TYPE_NETWORK)
    {
        while(vr_script->vctx.zf->list(debuglvl, vr_script->vctx.zone_backend, vr_script->bdat, &vr_script->zonetype, VRMR_BT_ZONES) != NULL)
        {
            if(vr_script->zonetype == vr_script->type)
            {
                if(strcmp(vr_script->name,"any") != 0)
                {
                    /* validate and split the new name */
                    if(vrmr_validate_zonename(debuglvl, vr_script->bdat, 0, back_zone, back_net, back_host, vr_script->vctx.reg.zonename, VRMR_VERBOSE) != 0)
                    {
                        vrmr_error(VRS_ERR_INTERNAL, VR_INTERR, "invalid name '%s' returned from backend (in: %s:%d).", vr_script->name, __FUNC__, __LINE__);
                        return(VRS_ERR_INTERNAL);
                    }
                    if(debuglvl >= HIGH)
                        vrmr_debug(__FUNC__, "name: '%s': host/group '%s', net '%s', zone '%s'.",
                                                vr_script->bdat, back_host, back_net, back_zone);

                    if(strcmp(back_zone, vr_script->name_zone) == 0)
                    {
                        printf("%s\n", vr_script->bdat);
                    }
                }
                else
                {
                    printf("%s\n", vr_script->bdat);
                }
            }
        }
    }
    else if(vr_script->type == VRMR_TYPE_HOST || vr_script->type == VRMR_TYPE_GROUP)
    {
        while(vr_script->vctx.zf->list(debuglvl, vr_script->vctx.zone_backend, vr_script->bdat, &vr_script->zonetype, VRMR_BT_ZONES) != NULL)
        {
            if(vr_script->zonetype == vr_script->type)
            {
                if(strcmp(vr_script->name,"any") != 0)
                {
                    /* validate and split the new name */
                    if(vrmr_validate_zonename(debuglvl, vr_script->bdat, 0, back_zone, back_net, back_host, vr_script->vctx.reg.zonename, VRMR_VERBOSE) != 0)
                    {
                        vrmr_error(VRS_ERR_INTERNAL, VR_INTERR, "invalid name '%s' returned from backend (in: %s:%d).", vr_script->name, __FUNC__, __LINE__);
                        return(VRS_ERR_INTERNAL);
                    }
                    if(debuglvl >= HIGH)
                        vrmr_debug(__FUNC__, "name: '%s': host/group '%s', net '%s', zone '%s'.",
                                                vr_script->bdat, back_host, back_net, back_zone);

                    if( strcmp(back_zone, vr_script->name_zone) == 0 &&
                        (vr_script->name_net[0] == '\0' || strcmp(back_net, vr_script->name_net) == 0))
                    {
                        printf("%s\n", vr_script->bdat);
                    }
                }
                else
                {
                    printf("%s\n", vr_script->bdat);
                }
            }
        }
    }
    else if(vr_script->type == VRMR_TYPE_SERVICE)
    {
        while(vr_script->vctx.sf->list(debuglvl, vr_script->vctx.serv_backend, vr_script->bdat, &vr_script->zonetype, VRMR_BT_SERVICES) != NULL)
        {
            printf("%s\n", vr_script->bdat);
        }
    }
    else if(vr_script->type == VRMR_TYPE_INTERFACE)
    {
        while(vr_script->vctx.af->list(debuglvl, vr_script->vctx.ifac_backend, vr_script->bdat, &vr_script->zonetype, VRMR_BT_INTERFACES) != NULL)
        {
            printf("%s\n", vr_script->bdat);
        }
    }
    else if(vr_script->type == VRMR_TYPE_RULE)
    {
        while(vr_script->vctx.rf->list(debuglvl, vr_script->vctx.rule_backend, vr_script->bdat, &vr_script->zonetype, VRMR_BT_RULES) != NULL)
        {
            printf("%s\n", vr_script->bdat);
        }
    }
    else
    {
        vrmr_error(VRS_ERR_INTERNAL, VR_INTERR, "unknown type %d.", vr_script->type);
        return(VRS_ERR_INTERNAL);
    }

    return(0);
}
