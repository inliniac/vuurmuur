/***************************************************************************
 *   Copyright (C) 2005-2006 by Victor Julien                              *
 *   victor@nk.nl                                                          *
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
script_add(const int debuglvl, VuurmuurScript *vr_script)
{
    char    found = FALSE;

    /*
        first check if the object already exists
    */
    if( vr_script->type == TYPE_ZONE || vr_script->type == TYPE_NETWORK ||
        vr_script->type == TYPE_HOST || vr_script->type == TYPE_GROUP)
    {
        while(zf->list(debuglvl, zone_backend, vr_script->bdat, &vr_script->zonetype, CAT_ZONES) != NULL)
        {
            if(vr_script->zonetype == vr_script->type && strcmp(vr_script->bdat,vr_script->name) == 0)
            {
                found = TRUE;
            }
        }

        if(found == TRUE)
        {
            if(vr_script->type == TYPE_ZONE)
                (void)vrprint.error(VRS_ERR_ALREADY_EXISTS, VR_ERR, "zone '%s' already exists.", vr_script->name);
            else if(vr_script->type == TYPE_NETWORK)
                (void)vrprint.error(VRS_ERR_ALREADY_EXISTS, VR_ERR, "network '%s' already exists.", vr_script->name);
            else if(vr_script->type == TYPE_HOST)
                (void)vrprint.error(VRS_ERR_ALREADY_EXISTS, VR_ERR, "host '%s' already exists.", vr_script->name);
            else if(vr_script->type == TYPE_GROUP)
                (void)vrprint.error(VRS_ERR_ALREADY_EXISTS, VR_ERR, "group '%s' already exists.", vr_script->name);

            return(VRS_ERR_ALREADY_EXISTS);
        }
    }
    else if(vr_script->type == TYPE_SERVICE)
    {
        while(sf->list(debuglvl, serv_backend, vr_script->bdat, &vr_script->zonetype, CAT_SERVICES) != NULL)
        {
            if(strcmp(vr_script->bdat,vr_script->name) == 0)
            {
                found = TRUE;
            }
        }

        if(found == TRUE)
        {
            (void)vrprint.error(VRS_ERR_ALREADY_EXISTS, VR_ERR, "service '%s' already exists.", vr_script->name);
            return(VRS_ERR_ALREADY_EXISTS);
        }
    }
    else if(vr_script->type == TYPE_INTERFACE)
    {
        while(af->list(debuglvl, ifac_backend, vr_script->bdat, &vr_script->zonetype, CAT_INTERFACES) != NULL)
        {
            if(strcmp(vr_script->bdat,vr_script->name) == 0)
            {
                found = TRUE;
            }
        }

        if(found == TRUE)
        {
            (void)vrprint.error(VRS_ERR_ALREADY_EXISTS, VR_ERR, "interface '%s' already exists.", vr_script->name);
            return(VRS_ERR_ALREADY_EXISTS);
        }
    }
    else if(vr_script->type == TYPE_RULE)
    {
        while(rf->list(debuglvl, rule_backend, vr_script->bdat, &vr_script->zonetype, CAT_RULES) != NULL)
        {
            if(strcmp(vr_script->bdat,vr_script->name) == 0)
            {
                found = TRUE;
            }
        }

        if(found == TRUE)
        {
            (void)vrprint.error(VRS_ERR_ALREADY_EXISTS, VR_ERR, "ruleset '%s' already exists.", vr_script->name);
            return(VRS_ERR_ALREADY_EXISTS);
        }
    }

    /*
        now add it
    */
    if(vr_script->type == TYPE_ZONE)
    {
        if(zf->add(debuglvl, zone_backend, vr_script->name, TYPE_ZONE) < 0)
        {
            (void)vrprint.error(-1, VR_ERR, "adding zone '%s' failed (in: %s:%d).", vr_script->name, __FUNC__, __LINE__);
            return(VRS_ERR_COMMAND_FAILED);
        }

        logchange("zone '%s' added.", vr_script->name);
    }
    else if(vr_script->type == TYPE_NETWORK)
    {
        if(zf->add(debuglvl, zone_backend, vr_script->name, TYPE_NETWORK) < 0)
        {
            (void)vrprint.error(-1, VR_ERR, "adding network '%s' failed (in: %s:%d).", vr_script->name, __FUNC__, __LINE__);
            return(VRS_ERR_COMMAND_FAILED);
        }

        logchange("network '%s' added.", vr_script->name);
    }
    else if(vr_script->type == TYPE_HOST)
    {
        if(zf->add(debuglvl, zone_backend, vr_script->name, TYPE_HOST) < 0)
        {
            (void)vrprint.error(-1, VR_ERR, "adding host '%s' failed (in: %s:%d).", vr_script->name, __FUNC__, __LINE__);
            return(VRS_ERR_COMMAND_FAILED);
        }

        logchange("host '%s' added.", vr_script->name);
    }
    else if(vr_script->type == TYPE_GROUP)
    {
        if(zf->add(debuglvl, zone_backend, vr_script->name, TYPE_GROUP) < 0)
        {
            (void)vrprint.error(-1, VR_ERR, "adding group '%s' failed (in: %s:%d).", vr_script->name, __FUNC__, __LINE__);
            return(VRS_ERR_COMMAND_FAILED);
        }

        logchange("group '%s' added.", vr_script->name);
    }
    else if(vr_script->type == TYPE_SERVICE)
    {
        if(sf->add(debuglvl, serv_backend, vr_script->name, TYPE_SERVICE) < 0)
        {
            (void)vrprint.error(-1, VR_ERR, "adding service '%s' failed (in: %s:%d).", vr_script->name, __FUNC__, __LINE__);
            return(VRS_ERR_COMMAND_FAILED);
        }

        logchange("service '%s' added.", vr_script->name);
    }
    else if(vr_script->type == TYPE_INTERFACE)
    {
        if(af->add(debuglvl, ifac_backend, vr_script->name, TYPE_INTERFACE) < 0)
        {
            (void)vrprint.error(-1, VR_ERR, "adding interface '%s' failed (in: %s:%d).", vr_script->name, __FUNC__, __LINE__);
            return(VRS_ERR_COMMAND_FAILED);
        }

        logchange("interface '%s' added.", vr_script->name);
    }
    else if(vr_script->type == TYPE_RULE)
    {
        if(rf->add(debuglvl, rule_backend, vr_script->name, TYPE_RULE) < 0)
        {
            (void)vrprint.error(-1, VR_ERR, "adding ruleset '%s' failed (in: %s:%d).", vr_script->name, __FUNC__, __LINE__);
            return(VRS_ERR_COMMAND_FAILED);
        }

        logchange("ruleset '%s' added.", vr_script->name);
    }
    else
    {
        (void)vrprint.error(VRS_ERR_INTERNAL, VR_INTERR, "unknown type %d.", vr_script->type);
        return(VRS_ERR_INTERNAL);
    }

    return(0);
}
