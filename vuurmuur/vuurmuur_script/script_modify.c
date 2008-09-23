/***************************************************************************
 *   Copyright (C) 2005-2008 by Victor Julien                              *
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
script_modify(const int debuglvl, VuurmuurScript *vr_script)
{
    char    found = FALSE;
    int     result = 0;

    /*
        first check if the object exists
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

        if(found == FALSE)
        {
            if(vr_script->type == TYPE_ZONE)
                (void)vrprint.error(VRS_ERR_NOT_FOUND, VR_ERR, "zone '%s' doesn't exist.", vr_script->name);
            else if(vr_script->type == TYPE_NETWORK)
                (void)vrprint.error(VRS_ERR_NOT_FOUND, VR_ERR, "network '%s' doesn't exist.", vr_script->name);
            else if(vr_script->type == TYPE_HOST)
                (void)vrprint.error(VRS_ERR_NOT_FOUND, VR_ERR, "host '%s' doesn't exist.", vr_script->name);
            else if(vr_script->type == TYPE_GROUP)
                (void)vrprint.error(VRS_ERR_NOT_FOUND, VR_ERR, "group '%s' doesn't exist.", vr_script->name);

            return(VRS_ERR_NOT_FOUND);
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

        if(found == FALSE)
        {
            (void)vrprint.error(VRS_ERR_NOT_FOUND, VR_ERR, "service '%s' doesn't exist.", vr_script->name);
            return(VRS_ERR_NOT_FOUND);
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

        if(found == FALSE)
        {
            (void)vrprint.error(VRS_ERR_NOT_FOUND, VR_ERR, "interface '%s' doesn't exist.", vr_script->name);
            return(VRS_ERR_NOT_FOUND);
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

        if(found == FALSE)
        {
            (void)vrprint.error(VRS_ERR_NOT_FOUND, VR_ERR, "ruleset '%s' doesn't exist.", vr_script->name);
            return(VRS_ERR_NOT_FOUND);
        }
    }

    /*
        check if the value makes sense
    */
    result = backend_check(debuglvl, vr_script->type, vr_script->var, vr_script->set, vr_script->overwrite, &vr_script->reg);
    if(result != 0)
        return(result);

    /*
        now modify!
    */
    if(vr_script->type == TYPE_ZONE)
    {
        if(zf->tell(debuglvl, zone_backend, vr_script->name, vr_script->var, vr_script->set, vr_script->overwrite, TYPE_ZONE) < 0)
        {
            (void)vrprint.error(-1, VR_ERR, "modifying zone '%s' failed (in: %s:%d).", vr_script->name, __FUNC__, __LINE__);
            return(VRS_ERR_COMMAND_FAILED);
        }

        if(vr_script->overwrite == TRUE)
            logchange("for zone '%s' variable '%s' is set to '%s'.", vr_script->name, vr_script->var, vr_script->set);
        else
            logchange("for zone '%s' variable '%s' appended '%s'.", vr_script->name, vr_script->var, vr_script->set);
    }
    else if(vr_script->type == TYPE_NETWORK)
    {
        if(zf->tell(debuglvl, zone_backend, vr_script->name, vr_script->var, vr_script->set, vr_script->overwrite, TYPE_NETWORK) < 0)
        {
            (void)vrprint.error(-1, VR_ERR, "modifying network '%s' failed (in: %s:%d).", vr_script->name, __FUNC__, __LINE__);
            return(VRS_ERR_COMMAND_FAILED);
        }

        if(vr_script->overwrite == TRUE)
            logchange("for network '%s' variable '%s' is set to '%s'.", vr_script->name, vr_script->var, vr_script->set);
        else
            logchange("for network '%s' variable '%s' appended '%s'.", vr_script->name, vr_script->var, vr_script->set);
    }
    else if(vr_script->type == TYPE_HOST)
    {
        if(zf->tell(debuglvl, zone_backend, vr_script->name, vr_script->var, vr_script->set, vr_script->overwrite, TYPE_HOST) < 0)
        {
            (void)vrprint.error(-1, VR_ERR, "modifying host '%s' failed (in: %s:%d).", vr_script->name, __FUNC__, __LINE__);
            return(VRS_ERR_COMMAND_FAILED);
        }

        if(vr_script->overwrite == TRUE)
            logchange("for host '%s' variable '%s' is set to '%s'.", vr_script->name, vr_script->var, vr_script->set);
        else
            logchange("for host '%s' variable '%s' appended '%s'.", vr_script->name, vr_script->var, vr_script->set);
    }
    else if(vr_script->type == TYPE_GROUP)
    {
        if(zf->tell(debuglvl, zone_backend, vr_script->name, vr_script->var, vr_script->set, vr_script->overwrite, TYPE_GROUP) < 0)
        {
            (void)vrprint.error(-1, VR_ERR, "modifying group '%s' failed (in: %s:%d).", vr_script->name, __FUNC__, __LINE__);
            return(VRS_ERR_COMMAND_FAILED);
        }

        if(vr_script->overwrite == TRUE)
            logchange("for group '%s' variable '%s' is set to '%s'.", vr_script->name, vr_script->var, vr_script->set);
        else
            logchange("for group '%s' variable '%s' appended '%s'.", vr_script->name, vr_script->var, vr_script->set);
    }
    else if(vr_script->type == TYPE_SERVICE)
    {
        if(sf->tell(debuglvl, serv_backend, vr_script->name, vr_script->var, vr_script->set, vr_script->overwrite, TYPE_SERVICE) < 0)
        {
            (void)vrprint.error(-1, VR_ERR, "modifying service '%s' failed (in: %s:%d).", vr_script->name, __FUNC__, __LINE__);
            return(VRS_ERR_COMMAND_FAILED);
        }

        if(vr_script->overwrite == TRUE)
            logchange("for service '%s' variable '%s' is set to '%s'.", vr_script->name, vr_script->var, vr_script->set);
        else
            logchange("for service '%s' variable '%s' appended '%s'.", vr_script->name, vr_script->var, vr_script->set);
    }
    else if(vr_script->type == TYPE_INTERFACE)
    {
        if(af->tell(debuglvl, ifac_backend, vr_script->name, vr_script->var, vr_script->set, vr_script->overwrite, TYPE_INTERFACE) < 0)
        {
            (void)vrprint.error(-1, VR_ERR, "modifying interface '%s' failed (in: %s:%d).", vr_script->name, __FUNC__, __LINE__);
            return(VRS_ERR_COMMAND_FAILED);
        }

        if(vr_script->overwrite == TRUE)
            logchange("for interface '%s' variable '%s' is set to '%s'.", vr_script->name, vr_script->var, vr_script->set);
        else
            logchange("for interface '%s' variable '%s' appended '%s'.", vr_script->name, vr_script->var, vr_script->set);
    }
    else if(vr_script->type == TYPE_RULE)
    {
        if(rf->tell(debuglvl, rule_backend, vr_script->name, vr_script->var, vr_script->set, vr_script->overwrite, TYPE_RULE) < 0)
        {
            (void)vrprint.error(-1, VR_ERR, "modifying ruleset '%s' failed (in: %s:%d).", vr_script->name, __FUNC__, __LINE__);
            return(VRS_ERR_COMMAND_FAILED);
        }

        if(vr_script->overwrite == TRUE)
            logchange("for ruleset '%s' variable '%s' is set to '%s'.", vr_script->name, vr_script->var, vr_script->set);
        else
            logchange("for ruleset '%s' variable '%s' appended '%s'.", vr_script->name, vr_script->var, vr_script->set);
    }
    else
    {
        (void)vrprint.error(VRS_ERR_INTERNAL, VR_INTERR, "unknown type %d.", vr_script->type);
        return(VRS_ERR_INTERNAL);
    }

    return(0);
}
