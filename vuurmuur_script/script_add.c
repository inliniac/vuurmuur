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

int script_add(struct vuurmuur_script *vr_script)
{
    char found = FALSE;

    /*
        first check if the object already exists
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
            if (strcmp(vr_script->bdat, vr_script->name) == 0) {
                found = TRUE;
            }
        }

        if (found == TRUE) {
            vrmr_error(VRS_ERR_ALREADY_EXISTS, VR_ERR,
                    "service '%s' already exists.", vr_script->name);
            return (VRS_ERR_ALREADY_EXISTS);
        }
    } else if (vr_script->type == VRMR_TYPE_INTERFACE) {
        while (vr_script->vctx.af->list(vr_script->vctx.ifac_backend,
                       vr_script->bdat, &vr_script->zonetype,
                       VRMR_BT_INTERFACES) != NULL) {
            if (strcmp(vr_script->bdat, vr_script->name) == 0) {
                found = TRUE;
            }
        }

        if (found == TRUE) {
            vrmr_error(VRS_ERR_ALREADY_EXISTS, VR_ERR,
                    "interface '%s' already exists.", vr_script->name);
            return (VRS_ERR_ALREADY_EXISTS);
        }
    } else if (vr_script->type == VRMR_TYPE_RULE) {
        while (vr_script->vctx.rf->list(vr_script->vctx.rule_backend,
                       vr_script->bdat, &vr_script->zonetype,
                       VRMR_BT_RULES) != NULL) {
            if (strcmp(vr_script->bdat, vr_script->name) == 0) {
                found = TRUE;
            }
        }

        if (found == TRUE) {
            vrmr_error(VRS_ERR_ALREADY_EXISTS, VR_ERR,
                    "ruleset '%s' already exists.", vr_script->name);
            return (VRS_ERR_ALREADY_EXISTS);
        }
    }

    /*
        now add it
    */
    if (vr_script->type == VRMR_TYPE_ZONE) {
        if (vr_script->vctx.zf->add(vr_script->vctx.zone_backend,
                    vr_script->name, VRMR_TYPE_ZONE) < 0) {
            vrmr_error(-1, VR_ERR, "adding zone '%s' failed", vr_script->name);
            return (VRS_ERR_COMMAND_FAILED);
        }

        logchange(vr_script, "zone '%s' added.", vr_script->name);
    } else if (vr_script->type == VRMR_TYPE_NETWORK) {
        if (vr_script->vctx.zf->add(vr_script->vctx.zone_backend,
                    vr_script->name, VRMR_TYPE_NETWORK) < 0) {
            vrmr_error(
                    -1, VR_ERR, "adding network '%s' failed", vr_script->name);
            return (VRS_ERR_COMMAND_FAILED);
        }

        logchange(vr_script, "network '%s' added.", vr_script->name);
    } else if (vr_script->type == VRMR_TYPE_HOST) {
        if (vr_script->vctx.zf->add(vr_script->vctx.zone_backend,
                    vr_script->name, VRMR_TYPE_HOST) < 0) {
            vrmr_error(-1, VR_ERR, "adding host '%s' failed", vr_script->name);
            return (VRS_ERR_COMMAND_FAILED);
        }

        logchange(vr_script, "host '%s' added.", vr_script->name);
    } else if (vr_script->type == VRMR_TYPE_GROUP) {
        if (vr_script->vctx.zf->add(vr_script->vctx.zone_backend,
                    vr_script->name, VRMR_TYPE_GROUP) < 0) {
            vrmr_error(-1, VR_ERR, "adding group '%s' failed", vr_script->name);
            return (VRS_ERR_COMMAND_FAILED);
        }

        logchange(vr_script, "group '%s' added.", vr_script->name);
    } else if (vr_script->type == VRMR_TYPE_SERVICE) {
        if (vr_script->vctx.sf->add(vr_script->vctx.serv_backend,
                    vr_script->name, VRMR_TYPE_SERVICE) < 0) {
            vrmr_error(
                    -1, VR_ERR, "adding service '%s' failed", vr_script->name);
            return (VRS_ERR_COMMAND_FAILED);
        }

        logchange(vr_script, "service '%s' added.", vr_script->name);
    } else if (vr_script->type == VRMR_TYPE_INTERFACE) {
        if (vr_script->vctx.af->add(vr_script->vctx.ifac_backend,
                    vr_script->name, VRMR_TYPE_INTERFACE) < 0) {
            vrmr_error(-1, VR_ERR, "adding interface '%s' failed",
                    vr_script->name);
            return (VRS_ERR_COMMAND_FAILED);
        }

        logchange(vr_script, "interface '%s' added.", vr_script->name);
    } else if (vr_script->type == VRMR_TYPE_RULE) {
        if (vr_script->vctx.rf->add(vr_script->vctx.rule_backend,
                    vr_script->name, VRMR_TYPE_RULE) < 0) {
            vrmr_error(
                    -1, VR_ERR, "adding ruleset '%s' failed", vr_script->name);
            return (VRS_ERR_COMMAND_FAILED);
        }

        logchange(vr_script, "ruleset '%s' added.", vr_script->name);
    } else {
        vrmr_error(VRS_ERR_INTERNAL, VR_INTERR, "unknown type %d.",
                vr_script->type);
        return (VRS_ERR_INTERNAL);
    }

    return (0);
}
