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

int script_rename(VuurmuurScript *vr_script)
{
    char found = FALSE;

    /*
        see if the source object exists
    */
    if (vr_script->type == VRMR_TYPE_ZONE ||
            vr_script->type == VRMR_TYPE_NETWORK ||
            vr_script->type == VRMR_TYPE_HOST ||
            vr_script->type == VRMR_TYPE_GROUP) {
        while (vr_script->vctx.zf->list(vr_script->vctx.zone_backend,
                       vr_script->bdat, &vr_script->zonetype,
                       VRMR_BT_ZONES) != NULL) {
            if (vr_script->zonetype == vr_script->type &&
                    strcmp(vr_script->bdat, vr_script->name) == 0) {
                found = TRUE;
            }
        }

        if (found == FALSE) {
            if (vr_script->type == VRMR_TYPE_ZONE)
                vrmr_error(VRS_ERR_NOT_FOUND, VR_ERR,
                        "zone '%s' doesn't exist.", vr_script->name);
            else if (vr_script->type == VRMR_TYPE_NETWORK)
                vrmr_error(VRS_ERR_NOT_FOUND, VR_ERR,
                        "network '%s' doesn't exist.", vr_script->name);
            else if (vr_script->type == VRMR_TYPE_HOST)
                vrmr_error(VRS_ERR_NOT_FOUND, VR_ERR,
                        "host '%s' doesn't exist.", vr_script->name);
            else if (vr_script->type == VRMR_TYPE_GROUP)
                vrmr_error(VRS_ERR_NOT_FOUND, VR_ERR,
                        "group '%s' doesn't exist.", vr_script->name);

            return (VRS_ERR_NOT_FOUND);
        }
    } else if (vr_script->type == VRMR_TYPE_SERVICE) {
        while (vr_script->vctx.sf->list(vr_script->vctx.serv_backend,
                       vr_script->bdat, &vr_script->zonetype,
                       VRMR_BT_SERVICES) != NULL) {
            if (strcmp(vr_script->bdat, vr_script->name) == 0) {
                found = TRUE;
            }
        }

        if (found == FALSE) {
            vrmr_error(VRS_ERR_NOT_FOUND, VR_ERR, "service '%s' doesn't exist.",
                    vr_script->name);
            return (VRS_ERR_NOT_FOUND);
        }
    } else if (vr_script->type == VRMR_TYPE_INTERFACE) {
        while (vr_script->vctx.af->list(vr_script->vctx.ifac_backend,
                       vr_script->bdat, &vr_script->zonetype,
                       VRMR_BT_INTERFACES) != NULL) {
            if (strcmp(vr_script->bdat, vr_script->name) == 0) {
                found = TRUE;
            }
        }

        if (found == FALSE) {
            vrmr_error(VRS_ERR_NOT_FOUND, VR_ERR,
                    "interface '%s' doesn't exist.", vr_script->name);
            return (VRS_ERR_NOT_FOUND);
        }
    } else if (vr_script->type == VRMR_TYPE_RULE) {
        while (vr_script->vctx.rf->list(vr_script->vctx.rule_backend,
                       vr_script->bdat, &vr_script->zonetype,
                       VRMR_BT_RULES) != NULL) {
            if (strcmp(vr_script->bdat, vr_script->name) == 0) {
                found = TRUE;
            }
        }

        if (found == FALSE) {
            vrmr_error(VRS_ERR_NOT_FOUND, VR_ERR, "ruleset '%s' doesn't exist.",
                    vr_script->name);
            return (VRS_ERR_NOT_FOUND);
        }
    }

    /*
        make sure the --set name is valid
    */
    if (vr_script->type == VRMR_TYPE_ZONE ||
            vr_script->type == VRMR_TYPE_NETWORK ||
            vr_script->type == VRMR_TYPE_HOST ||
            vr_script->type == VRMR_TYPE_GROUP) {
        /* validate and split the new name */
        if (vrmr_validate_zonename(vr_script->set, 1, NULL, NULL, NULL,
                    vr_script->vctx.reg.zonename, VRMR_VERBOSE) != 0) {
            if (vr_script->type == VRMR_TYPE_ZONE)
                vrmr_error(VRS_ERR_COMMANDLINE, VR_ERR,
                        "invalid zone name '%s' (in: %s:%d).", vr_script->set,
                        __FUNC__, __LINE__);
            else if (vr_script->type == VRMR_TYPE_NETWORK)
                vrmr_error(VRS_ERR_COMMANDLINE, VR_ERR,
                        "invalid network name '%s' (in: %s:%d).",
                        vr_script->set, __FUNC__, __LINE__);
            else if (vr_script->type == VRMR_TYPE_HOST)
                vrmr_error(VRS_ERR_COMMANDLINE, VR_ERR,
                        "invalid host name '%s' (in: %s:%d).", vr_script->set,
                        __FUNC__, __LINE__);
            else if (vr_script->type == VRMR_TYPE_GROUP)
                vrmr_error(VRS_ERR_COMMANDLINE, VR_ERR,
                        "invalid group name '%s' (in: %s:%d).", vr_script->set,
                        __FUNC__, __LINE__);

            return (VRS_ERR_COMMANDLINE);
        }
    } else if (vr_script->type == VRMR_TYPE_SERVICE) {
        if (vrmr_validate_servicename(vr_script->set,
                    vr_script->vctx.reg.servicename, VRMR_QUIET) != 0) {
            vrmr_error(VRS_ERR_COMMANDLINE, VR_ERR,
                    "invalid service name '%s' (in: %s:%d).", vr_script->set,
                    __FUNC__, __LINE__);
            return (VRS_ERR_COMMANDLINE);
        }
    } else if (vr_script->type == VRMR_TYPE_INTERFACE) {
        if (vrmr_validate_interfacename(
                    vr_script->set, vr_script->vctx.reg.interfacename) != 0) {
            vrmr_error(VRS_ERR_COMMANDLINE, VR_ERR,
                    "invalid interface name '%s' (in: %s:%d).", vr_script->set,
                    __FUNC__, __LINE__);
            return (VRS_ERR_COMMANDLINE);
        }
    } else if (vr_script->type == VRMR_TYPE_RULE) {
        if (strcmp(vr_script->set, "blocklist") == 0 ||
                strcmp(vr_script->set, "rules") == 0) {
            /* ok */
        } else {
            /* error */
            vrmr_error(VRS_ERR_COMMANDLINE, VR_ERR,
                    "invalid ruleset name '%s' (in: %s:%d).", vr_script->set,
                    __FUNC__, __LINE__);
            return (VRS_ERR_COMMANDLINE);
        }
    }

    /* make sure the target doesn't already exist */
    found = FALSE; /* reset */

    if (vr_script->type == VRMR_TYPE_ZONE ||
            vr_script->type == VRMR_TYPE_NETWORK ||
            vr_script->type == VRMR_TYPE_HOST ||
            vr_script->type == VRMR_TYPE_GROUP) {
        while (vr_script->vctx.zf->list(vr_script->vctx.zone_backend,
                       vr_script->bdat, &vr_script->zonetype,
                       VRMR_BT_ZONES) != NULL) {
            if (vr_script->zonetype == vr_script->type &&
                    strcmp(vr_script->bdat, vr_script->set) == 0) {
                found = TRUE;
            }
        }

        if (found == TRUE) {
            if (vr_script->type == VRMR_TYPE_ZONE)
                vrmr_error(VRS_ERR_ALREADY_EXISTS, VR_ERR,
                        "zone '%s' already exists.", vr_script->name);
            else if (vr_script->type == VRMR_TYPE_NETWORK)
                vrmr_error(VRS_ERR_ALREADY_EXISTS, VR_ERR,
                        "network '%s' already exists.", vr_script->name);
            else if (vr_script->type == VRMR_TYPE_HOST)
                vrmr_error(VRS_ERR_ALREADY_EXISTS, VR_ERR,
                        "host '%s' already exists.", vr_script->name);
            else if (vr_script->type == VRMR_TYPE_GROUP)
                vrmr_error(VRS_ERR_ALREADY_EXISTS, VR_ERR,
                        "group '%s' already exists.", vr_script->name);

            return (VRS_ERR_ALREADY_EXISTS);
        }
    } else if (vr_script->type == VRMR_TYPE_SERVICE) {
        while (vr_script->vctx.sf->list(vr_script->vctx.serv_backend,
                       vr_script->bdat, &vr_script->zonetype,
                       VRMR_BT_SERVICES) != NULL) {
            if (strcmp(vr_script->bdat, vr_script->set) == 0) {
                found = TRUE;
            }
        }

        if (found == TRUE) {
            vrmr_error(VRS_ERR_ALREADY_EXISTS, VR_ERR,
                    "service '%s' already exists.", vr_script->set);
            return (VRS_ERR_ALREADY_EXISTS);
        }
    } else if (vr_script->type == VRMR_TYPE_INTERFACE) {
        while (vr_script->vctx.af->list(vr_script->vctx.ifac_backend,
                       vr_script->bdat, &vr_script->zonetype,
                       VRMR_BT_INTERFACES) != NULL) {
            if (strcmp(vr_script->bdat, vr_script->set) == 0) {
                found = TRUE;
            }
        }

        if (found == TRUE) {
            vrmr_error(VRS_ERR_ALREADY_EXISTS, VR_ERR,
                    "interface '%s' already exists.", vr_script->set);
            return (VRS_ERR_ALREADY_EXISTS);
        }
    } else if (vr_script->type == VRMR_TYPE_RULE) {
        while (vr_script->vctx.rf->list(vr_script->vctx.rule_backend,
                       vr_script->bdat, &vr_script->zonetype,
                       VRMR_BT_RULES) != NULL) {
            if (strcmp(vr_script->bdat, vr_script->set) == 0) {
                found = TRUE;
            }
        }

        if (found == TRUE) {
            vrmr_error(VRS_ERR_ALREADY_EXISTS, VR_ERR,
                    "ruleset '%s' already exists.", vr_script->set);
            return (VRS_ERR_ALREADY_EXISTS);
        }
    }

    /* do the actual rename */
    if (vr_script->type == VRMR_TYPE_ZONE) {
        if (vr_script->vctx.zf->rename(vr_script->vctx.zone_backend,
                    vr_script->name, vr_script->set, VRMR_TYPE_ZONE) < 0) {
            vrmr_error(VRS_ERR_COMMAND_FAILED, VR_ERR,
                    "renaming zone '%s' failed (in: %s:%d).", vr_script->name,
                    __FUNC__, __LINE__);
            return (VRS_ERR_COMMAND_FAILED);
        }

        logchange(vr_script, "zone '%s' renamed to '%s'.", vr_script->name,
                vr_script->set);
    } else if (vr_script->type == VRMR_TYPE_NETWORK) {
        if (vr_script->vctx.zf->rename(vr_script->vctx.zone_backend,
                    vr_script->name, vr_script->set, VRMR_TYPE_NETWORK) < 0) {
            vrmr_error(VRS_ERR_COMMAND_FAILED, VR_ERR,
                    "renaming network '%s' failed (in: %s:%d).",
                    vr_script->name, __FUNC__, __LINE__);
            return (VRS_ERR_COMMAND_FAILED);
        }

        logchange(vr_script, "network '%s' renamed to '%s'.", vr_script->name,
                vr_script->set);
    } else if (vr_script->type == VRMR_TYPE_HOST) {
        if (vr_script->vctx.zf->rename(vr_script->vctx.zone_backend,
                    vr_script->name, vr_script->set, VRMR_TYPE_HOST) < 0) {
            vrmr_error(VRS_ERR_COMMAND_FAILED, VR_ERR,
                    "renaming host '%s' failed (in: %s:%d).", vr_script->name,
                    __FUNC__, __LINE__);
            return (VRS_ERR_COMMAND_FAILED);
        }

        logchange(vr_script, "host '%s' renamed to '%s'.", vr_script->name,
                vr_script->set);
    } else if (vr_script->type == VRMR_TYPE_GROUP) {
        if (vr_script->vctx.zf->rename(vr_script->vctx.zone_backend,
                    vr_script->name, vr_script->set, VRMR_TYPE_GROUP) < 0) {
            vrmr_error(VRS_ERR_COMMAND_FAILED, VR_ERR,
                    "renaming group '%s' failed (in: %s:%d).", vr_script->name,
                    __FUNC__, __LINE__);
            return (VRS_ERR_COMMAND_FAILED);
        }

        logchange(vr_script, "group '%s' renamed to '%s'.", vr_script->name,
                vr_script->set);
    } else if (vr_script->type == VRMR_TYPE_SERVICE) {
        if (vr_script->vctx.sf->rename(vr_script->vctx.serv_backend,
                    vr_script->name, vr_script->set, VRMR_TYPE_SERVICE) < 0) {
            vrmr_error(-VRS_ERR_COMMAND_FAILED, VR_ERR,
                    "renaming service '%s' failed (in: %s:%d).",
                    vr_script->name, __FUNC__, __LINE__);
            return (VRS_ERR_COMMAND_FAILED);
        }

        logchange(vr_script, "service '%s' renamed to '%s'.", vr_script->name,
                vr_script->set);
    } else if (vr_script->type == VRMR_TYPE_INTERFACE) {
        if (vr_script->vctx.af->rename(vr_script->vctx.ifac_backend,
                    vr_script->name, vr_script->set, VRMR_TYPE_INTERFACE) < 0) {
            vrmr_error(VRS_ERR_COMMAND_FAILED, VR_ERR,
                    "renaming interface '%s' failed (in: %s:%d).",
                    vr_script->name, __FUNC__, __LINE__);
            return (VRS_ERR_COMMAND_FAILED);
        }

        logchange(vr_script, "interface '%s' renamed to '%s'.", vr_script->name,
                vr_script->set);
    } else if (vr_script->type == VRMR_TYPE_RULE) {
        if (vr_script->vctx.rf->rename(vr_script->vctx.rule_backend,
                    vr_script->name, vr_script->set, VRMR_TYPE_RULE) < 0) {
            vrmr_error(VRS_ERR_COMMAND_FAILED, VR_ERR,
                    "renaming ruleset '%s' failed (in: %s:%d).",
                    vr_script->name, __FUNC__, __LINE__);
            return (VRS_ERR_COMMAND_FAILED);
        }

        logchange(vr_script, "ruleset '%s' renamed to '%s'.", vr_script->name,
                vr_script->set);
    } else {
        vrmr_error(VRS_ERR_INTERNAL, VR_INTERR, "unknown type %d (in: %s:%d).",
                vr_script->type, __FUNC__, __LINE__);
        return (VRS_ERR_INTERNAL);
    }

    return (0);
}
