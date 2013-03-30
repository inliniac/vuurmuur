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
script_rename(const int debuglvl, VuurmuurScript *vr_script)
{
    char    found = FALSE;

    /*
        see if the source object exists
    */
    if( vr_script->type == VRMR_TYPE_ZONE || vr_script->type == VRMR_TYPE_NETWORK ||
        vr_script->type == VRMR_TYPE_HOST || vr_script->type == VRMR_TYPE_GROUP)
    {
        while(zf->list(debuglvl, zone_backend, vr_script->bdat, &vr_script->zonetype, VRMR_BT_ZONES) != NULL)
        {
            if(vr_script->zonetype == vr_script->type && strcmp(vr_script->bdat,vr_script->name) == 0)
            {
                found = TRUE;
            }
        }

        if(found == FALSE)
        {
            if(vr_script->type == VRMR_TYPE_ZONE)
                (void)vrprint.error(VRS_ERR_NOT_FOUND, VR_ERR, "zone '%s' doesn't exist.", vr_script->name);
            else if(vr_script->type == VRMR_TYPE_NETWORK)
                (void)vrprint.error(VRS_ERR_NOT_FOUND, VR_ERR, "network '%s' doesn't exist.", vr_script->name);
            else if(vr_script->type == VRMR_TYPE_HOST)
                (void)vrprint.error(VRS_ERR_NOT_FOUND, VR_ERR, "host '%s' doesn't exist.", vr_script->name);
            else if(vr_script->type == VRMR_TYPE_GROUP)
                (void)vrprint.error(VRS_ERR_NOT_FOUND, VR_ERR, "group '%s' doesn't exist.", vr_script->name);

            return(VRS_ERR_NOT_FOUND);
        }
    }
    else if(vr_script->type == VRMR_TYPE_SERVICE)
    {
        while(sf->list(debuglvl, serv_backend, vr_script->bdat, &vr_script->zonetype, VRMR_BT_SERVICES) != NULL)
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
    else if(vr_script->type == VRMR_TYPE_INTERFACE)
    {
        while(af->list(debuglvl, ifac_backend, vr_script->bdat, &vr_script->zonetype, VRMR_BT_INTERFACES) != NULL)
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
    else if(vr_script->type == VRMR_TYPE_RULE)
    {
        while(rf->list(debuglvl, rule_backend, vr_script->bdat, &vr_script->zonetype, VRMR_BT_RULES) != NULL)
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
        make sure the --set name is valid
    */
    if( vr_script->type == VRMR_TYPE_ZONE || vr_script->type == VRMR_TYPE_NETWORK ||
        vr_script->type == VRMR_TYPE_HOST || vr_script->type == VRMR_TYPE_GROUP)
    {
        /* validate and split the new name */
        if(vrmr_validate_zonename(debuglvl, vr_script->set, 1, NULL, NULL, NULL, vr_script->reg.zonename, VALNAME_VERBOSE) != 0)
        {
            if(vr_script->type == VRMR_TYPE_ZONE)
                (void)vrprint.error(VRS_ERR_COMMANDLINE, VR_ERR, "invalid zone name '%s' (in: %s:%d).", vr_script->set, __FUNC__, __LINE__);
            else if(vr_script->type == VRMR_TYPE_NETWORK)
                (void)vrprint.error(VRS_ERR_COMMANDLINE, VR_ERR, "invalid network name '%s' (in: %s:%d).", vr_script->set, __FUNC__, __LINE__);
            else if(vr_script->type == VRMR_TYPE_HOST)
                (void)vrprint.error(VRS_ERR_COMMANDLINE, VR_ERR, "invalid host name '%s' (in: %s:%d).", vr_script->set, __FUNC__, __LINE__);
            else if(vr_script->type == VRMR_TYPE_GROUP)
                (void)vrprint.error(VRS_ERR_COMMANDLINE, VR_ERR, "invalid group name '%s' (in: %s:%d).", vr_script->set, __FUNC__, __LINE__);
                
            return(VRS_ERR_COMMANDLINE);
        }
    }
    else if(vr_script->type == VRMR_TYPE_SERVICE)
    {
        if(vrmr_validate_servicename(debuglvl, vr_script->set, vr_script->reg.servicename, VALNAME_QUIET) != 0)
        {
            (void)vrprint.error(VRS_ERR_COMMANDLINE, VR_ERR, "invalid service name '%s' (in: %s:%d).", vr_script->set, __FUNC__, __LINE__);
            return(VRS_ERR_COMMANDLINE);
        }
    }
    else if(vr_script->type == VRMR_TYPE_INTERFACE)
    {
        if(vrmr_validate_interfacename(debuglvl, vr_script->set, vr_script->reg.interfacename) != 0)
        {
            (void)vrprint.error(VRS_ERR_COMMANDLINE, VR_ERR, "invalid interface name '%s' (in: %s:%d).", vr_script->set, __FUNC__, __LINE__);
            return(VRS_ERR_COMMANDLINE);
        }
    }
    else if(vr_script->type == VRMR_TYPE_RULE)
    {
        if( strcmp(vr_script->set, "blocklist") == 0 ||
            strcmp(vr_script->set, "rules") == 0)
        {
            /* ok */
        }
        else
        {
            /* error */
            (void)vrprint.error(VRS_ERR_COMMANDLINE, VR_ERR, "invalid ruleset name '%s' (in: %s:%d).", vr_script->set, __FUNC__, __LINE__);
            return(VRS_ERR_COMMANDLINE);
        }
    }


    /* make sure the target doesn't already exist */
    found = FALSE; /* reset */

    if( vr_script->type == VRMR_TYPE_ZONE || vr_script->type == VRMR_TYPE_NETWORK ||
        vr_script->type == VRMR_TYPE_HOST || vr_script->type == VRMR_TYPE_GROUP)
    {
        while(zf->list(debuglvl, zone_backend, vr_script->bdat, &vr_script->zonetype, VRMR_BT_ZONES) != NULL)
        {
            if(vr_script->zonetype == vr_script->type && strcmp(vr_script->bdat,vr_script->set) == 0)
            {
                found = TRUE;
            }
        }

        if(found == TRUE)
        {
            if(vr_script->type == VRMR_TYPE_ZONE)
                (void)vrprint.error(VRS_ERR_ALREADY_EXISTS, VR_ERR, "zone '%s' already exists.", vr_script->name);
            else if(vr_script->type == VRMR_TYPE_NETWORK)
                (void)vrprint.error(VRS_ERR_ALREADY_EXISTS, VR_ERR, "network '%s' already exists.", vr_script->name);
            else if(vr_script->type == VRMR_TYPE_HOST)
                (void)vrprint.error(VRS_ERR_ALREADY_EXISTS, VR_ERR, "host '%s' already exists.", vr_script->name);
            else if(vr_script->type == VRMR_TYPE_GROUP)
                (void)vrprint.error(VRS_ERR_ALREADY_EXISTS, VR_ERR, "group '%s' already exists.", vr_script->name);

            return(VRS_ERR_ALREADY_EXISTS);
        }
    }
    else if(vr_script->type == VRMR_TYPE_SERVICE)
    {
        while(sf->list(debuglvl, serv_backend, vr_script->bdat, &vr_script->zonetype, VRMR_BT_SERVICES) != NULL)
        {
            if(strcmp(vr_script->bdat,vr_script->set) == 0)
            {
                found = TRUE;
            }
        }

        if(found == TRUE)
        {
            (void)vrprint.error(VRS_ERR_ALREADY_EXISTS, VR_ERR, "service '%s' already exists.", vr_script->set);
            return(VRS_ERR_ALREADY_EXISTS);
        }
    }
    else if(vr_script->type == VRMR_TYPE_INTERFACE)
    {
        while(af->list(debuglvl, ifac_backend, vr_script->bdat, &vr_script->zonetype, VRMR_BT_INTERFACES) != NULL)
        {
            if(strcmp(vr_script->bdat,vr_script->set) == 0)
            {
                found = TRUE;
            }
        }

        if(found == TRUE)
        {
            (void)vrprint.error(VRS_ERR_ALREADY_EXISTS, VR_ERR, "interface '%s' already exists.", vr_script->set);
            return(VRS_ERR_ALREADY_EXISTS);
        }
    }
    else if(vr_script->type == VRMR_TYPE_RULE)
    {
        while(rf->list(debuglvl, rule_backend, vr_script->bdat, &vr_script->zonetype, VRMR_BT_RULES) != NULL)
        {
            if(strcmp(vr_script->bdat,vr_script->set) == 0)
            {
                found = TRUE;
            }
        }

        if(found == TRUE)
        {
            (void)vrprint.error(VRS_ERR_ALREADY_EXISTS, VR_ERR, "ruleset '%s' already exists.", vr_script->set);
            return(VRS_ERR_ALREADY_EXISTS);
        }
    }


    /* do the actual rename */
    if(vr_script->type == VRMR_TYPE_ZONE)
    {
        if(zf->rename(debuglvl, zone_backend, vr_script->name, vr_script->set, VRMR_TYPE_ZONE) < 0)
        {
            (void)vrprint.error(VRS_ERR_COMMAND_FAILED, VR_ERR, "renaming zone '%s' failed (in: %s:%d).", vr_script->name, __FUNC__, __LINE__);
            return(VRS_ERR_COMMAND_FAILED);
        }

        logchange("zone '%s' renamed to '%s'.", vr_script->name, vr_script->set);
    }
    else if(vr_script->type == VRMR_TYPE_NETWORK)
    {
        if(zf->rename(debuglvl, zone_backend, vr_script->name, vr_script->set, VRMR_TYPE_NETWORK) < 0)
        {
            (void)vrprint.error(VRS_ERR_COMMAND_FAILED, VR_ERR, "renaming network '%s' failed (in: %s:%d).", vr_script->name, __FUNC__, __LINE__);
            return(VRS_ERR_COMMAND_FAILED);
        }

        logchange("network '%s' renamed to '%s'.", vr_script->name, vr_script->set);
    }
    else if(vr_script->type == VRMR_TYPE_HOST)
    {
        if(zf->rename(debuglvl, zone_backend, vr_script->name, vr_script->set, VRMR_TYPE_HOST) < 0)
        {
            (void)vrprint.error(VRS_ERR_COMMAND_FAILED, VR_ERR, "renaming host '%s' failed (in: %s:%d).", vr_script->name, __FUNC__, __LINE__);
            return(VRS_ERR_COMMAND_FAILED);
        }

        logchange("host '%s' renamed to '%s'.", vr_script->name, vr_script->set);
    }
    else if(vr_script->type == VRMR_TYPE_GROUP)
    {
        if(zf->rename(debuglvl, zone_backend, vr_script->name, vr_script->set, VRMR_TYPE_GROUP) < 0)
        {
            (void)vrprint.error(VRS_ERR_COMMAND_FAILED, VR_ERR, "renaming group '%s' failed (in: %s:%d).", vr_script->name, __FUNC__, __LINE__);
            return(VRS_ERR_COMMAND_FAILED);
        }

        logchange("group '%s' renamed to '%s'.", vr_script->name, vr_script->set);
    }
    else if(vr_script->type == VRMR_TYPE_SERVICE)
    {
        if(sf->rename(debuglvl, serv_backend, vr_script->name, vr_script->set, VRMR_TYPE_SERVICE) < 0)
        {
            (void)vrprint.error(-VRS_ERR_COMMAND_FAILED, VR_ERR, "renaming service '%s' failed (in: %s:%d).", vr_script->name, __FUNC__, __LINE__);
            return(VRS_ERR_COMMAND_FAILED);
        }

        logchange("service '%s' renamed to '%s'.", vr_script->name, vr_script->set);
    }
    else if(vr_script->type == VRMR_TYPE_INTERFACE)
    {
        if(af->rename(debuglvl, ifac_backend, vr_script->name, vr_script->set, VRMR_TYPE_INTERFACE) < 0)
        {
            (void)vrprint.error(VRS_ERR_COMMAND_FAILED, VR_ERR, "renaming interface '%s' failed (in: %s:%d).", vr_script->name, __FUNC__, __LINE__);
            return(VRS_ERR_COMMAND_FAILED);
        }

        logchange("interface '%s' renamed to '%s'.", vr_script->name, vr_script->set);
    }
    else if(vr_script->type == VRMR_TYPE_RULE)
    {
        if(rf->rename(debuglvl, rule_backend, vr_script->name, vr_script->set, VRMR_TYPE_RULE) < 0)
        {
            (void)vrprint.error(VRS_ERR_COMMAND_FAILED, VR_ERR, "renaming ruleset '%s' failed (in: %s:%d).", vr_script->name, __FUNC__, __LINE__);
            return(VRS_ERR_COMMAND_FAILED);
        }

        logchange("ruleset '%s' renamed to '%s'.", vr_script->name, vr_script->set);
    }
    else
    {
        (void)vrprint.error(VRS_ERR_INTERNAL, VR_INTERR, "unknown type %d (in: %s:%d).", vr_script->type, __FUNC__, __LINE__);
        return(VRS_ERR_INTERNAL);
    }

    return(0);
}
