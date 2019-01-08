/***************************************************************************
 *   Copyright (C) 2005-2019 by Victor Julien                              *
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

int script_modify(struct vuurmuur_script *vr_script)
{
    char found = FALSE;
    int result = 0;

    /*
        first check if the object exists
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
        check if the value makes sense
    */
    result = backend_check(vr_script->type, vr_script->var, vr_script->set,
            vr_script->overwrite, &vr_script->vctx.reg);
    if (result != 0)
        return (result);

    /*
        now modify!
    */
    if (vr_script->type == VRMR_TYPE_ZONE) {
        if (vr_script->vctx.zf->tell(vr_script->vctx.zone_backend,
                    vr_script->name, vr_script->var, vr_script->set,
                    vr_script->overwrite, VRMR_TYPE_ZONE) < 0) {
            vrmr_error(
                    -1, VR_ERR, "modifying zone '%s' failed", vr_script->name);
            return (VRS_ERR_COMMAND_FAILED);
        }

        if (vr_script->overwrite == TRUE)
            logchange(vr_script, "for zone '%s' variable '%s' is set to '%s'.",
                    vr_script->name, vr_script->var, vr_script->set);
        else
            logchange(vr_script, "for zone '%s' variable '%s' appended '%s'.",
                    vr_script->name, vr_script->var, vr_script->set);
    } else if (vr_script->type == VRMR_TYPE_NETWORK) {
        if (vr_script->vctx.zf->tell(vr_script->vctx.zone_backend,
                    vr_script->name, vr_script->var, vr_script->set,
                    vr_script->overwrite, VRMR_TYPE_NETWORK) < 0) {
            vrmr_error(-1, VR_ERR, "modifying network '%s' failed",
                    vr_script->name);
            return (VRS_ERR_COMMAND_FAILED);
        }

        if (vr_script->overwrite == TRUE)
            logchange(vr_script,
                    "for network '%s' variable '%s' is set to '%s'.",
                    vr_script->name, vr_script->var, vr_script->set);
        else
            logchange(vr_script,
                    "for network '%s' variable '%s' appended '%s'.",
                    vr_script->name, vr_script->var, vr_script->set);
    } else if (vr_script->type == VRMR_TYPE_HOST) {
        if (vr_script->vctx.zf->tell(vr_script->vctx.zone_backend,
                    vr_script->name, vr_script->var, vr_script->set,
                    vr_script->overwrite, VRMR_TYPE_HOST) < 0) {
            vrmr_error(
                    -1, VR_ERR, "modifying host '%s' failed", vr_script->name);
            return (VRS_ERR_COMMAND_FAILED);
        }

        if (vr_script->overwrite == TRUE)
            logchange(vr_script, "for host '%s' variable '%s' is set to '%s'.",
                    vr_script->name, vr_script->var, vr_script->set);
        else
            logchange(vr_script, "for host '%s' variable '%s' appended '%s'.",
                    vr_script->name, vr_script->var, vr_script->set);
    } else if (vr_script->type == VRMR_TYPE_GROUP) {
        if (vr_script->vctx.zf->tell(vr_script->vctx.zone_backend,
                    vr_script->name, vr_script->var, vr_script->set,
                    vr_script->overwrite, VRMR_TYPE_GROUP) < 0) {
            vrmr_error(
                    -1, VR_ERR, "modifying group '%s' failed", vr_script->name);
            return (VRS_ERR_COMMAND_FAILED);
        }

        if (vr_script->overwrite == TRUE)
            logchange(vr_script, "for group '%s' variable '%s' is set to '%s'.",
                    vr_script->name, vr_script->var, vr_script->set);
        else
            logchange(vr_script, "for group '%s' variable '%s' appended '%s'.",
                    vr_script->name, vr_script->var, vr_script->set);
    } else if (vr_script->type == VRMR_TYPE_SERVICE) {
        if (vr_script->vctx.sf->tell(vr_script->vctx.serv_backend,
                    vr_script->name, vr_script->var, vr_script->set,
                    vr_script->overwrite, VRMR_TYPE_SERVICE) < 0) {
            vrmr_error(-1, VR_ERR, "modifying service '%s' failed",
                    vr_script->name);
            return (VRS_ERR_COMMAND_FAILED);
        }

        if (vr_script->overwrite == TRUE)
            logchange(vr_script,
                    "for service '%s' variable '%s' is set to '%s'.",
                    vr_script->name, vr_script->var, vr_script->set);
        else
            logchange(vr_script,
                    "for service '%s' variable '%s' appended '%s'.",
                    vr_script->name, vr_script->var, vr_script->set);
    } else if (vr_script->type == VRMR_TYPE_INTERFACE) {
        if (vr_script->vctx.af->tell(vr_script->vctx.ifac_backend,
                    vr_script->name, vr_script->var, vr_script->set,
                    vr_script->overwrite, VRMR_TYPE_INTERFACE) < 0) {
            vrmr_error(-1, VR_ERR, "modifying interface '%s' failed",
                    vr_script->name);
            return (VRS_ERR_COMMAND_FAILED);
        }

        if (vr_script->overwrite == TRUE)
            logchange(vr_script,
                    "for interface '%s' variable '%s' is set to '%s'.",
                    vr_script->name, vr_script->var, vr_script->set);
        else
            logchange(vr_script,
                    "for interface '%s' variable '%s' appended '%s'.",
                    vr_script->name, vr_script->var, vr_script->set);
    } else if (vr_script->type == VRMR_TYPE_RULE) {
        if (vr_script->vctx.rf->tell(vr_script->vctx.rule_backend,
                    vr_script->name, vr_script->var, vr_script->set,
                    vr_script->overwrite, VRMR_TYPE_RULE) < 0) {
            vrmr_error(-1, VR_ERR, "modifying ruleset '%s' failed",
                    vr_script->name);
            return (VRS_ERR_COMMAND_FAILED);
        }

        if (vr_script->overwrite == TRUE)
            logchange(vr_script,
                    "for ruleset '%s' variable '%s' is set to '%s'.",
                    vr_script->name, vr_script->var, vr_script->set);
        else
            logchange(vr_script,
                    "for ruleset '%s' variable '%s' appended '%s'.",
                    vr_script->name, vr_script->var, vr_script->set);
    } else {
        vrmr_error(VRS_ERR_INTERNAL, VR_INTERR, "unknown type %d.",
                vr_script->type);
        return (VRS_ERR_INTERNAL);
    }

    return (0);
}
