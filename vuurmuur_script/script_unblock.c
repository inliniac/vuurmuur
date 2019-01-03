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

/* unblock written by Adi Kriegish */

/*  remove_leading_part

    This function strips of the leading string "block " from a rule string
    and copies the result to a new string.

    Returnvalues:
        on success: returns a newly created string
        on failure: exits immediately
*/

char *remove_leading_part(char *input)
{
    size_t len = 0; // length of the output (== length of input)
    char *output;   // result string (after removing "block ")

    if (input == NULL) {
        vrmr_error(VRS_ERR_INTERNAL, VR_ERR, "parameter problem (in: %s:%d)",
                __FUNC__, __LINE__);
        exit(VRS_ERR_INTERNAL);
    }

    len = strlen(input);
    if (len == 0) {
        vrmr_error(VRS_ERR_DATA_INCONSISTENCY, VR_ERR,
                "empty string returned from backend (in: %s:%d)", __FUNC__,
                __LINE__);
        exit(VRS_ERR_DATA_INCONSISTENCY);
    }

    /* we don't need the space for "block" */
    len = len - 5;

    output = malloc(len); /* for output we need to cut of "block " */
    if (output == NULL) {
        vrmr_error(VRS_ERR_MALLOC, VR_ERR, "malloc failed: %s (in: %s:%d)",
                strerror(errno), __FUNC__, __LINE__);
        exit(VRS_ERR_MALLOC);
    }
    memset(output, 0, len);

    if (sscanf(input, "block %s", output) == 0) {
        vrmr_error(VRS_ERR_DATA_INCONSISTENCY, VR_ERR,
                "malformed rule '%s' returned from backend (in: %s:%d)", input,
                __FUNC__, __LINE__);
        exit(VRS_ERR_DATA_INCONSISTENCY);
    }

    return (output);
}

/*  script_unblock

    This function iterates through the blocklist and removes a user specified
   item from this list if it was found.

    Returncodes:
        VRS_SUCCESS: success, item was removed
        VRS_ERR_COMMAND_FAILED: saving the blocklist in backend failed
        VRS_ERR_COMMANDLINE: item not found in blocklist

 */
int script_unblock(VuurmuurScript *vr_script)
{
    char removed = FALSE;            /* used to track if we really removed the
                                        object */
    struct vrmr_blocklist blocklist; /* "new" blocklist (object to be removed
                            will not be added to this list) */
    int retval = VRS_SUCCESS;
    char *str = NULL;

    vrmr_list_setup(&blocklist.list, free);
    blocklist.old_blocklistfile_used = FALSE;

    while (vr_script->vctx.rf->ask(vr_script->vctx.rule_backend, "blocklist",
                   "RULE", vr_script->bdat, sizeof(vr_script->bdat),
                   VRMR_TYPE_RULE, 1) == 1) {
        vrmr_rules_encode_rule(vr_script->bdat, sizeof(vr_script->bdat));

        str = remove_leading_part(vr_script->bdat);

        if (strcmp(vr_script->set, str)) {
            /* ok, no match; keep it in the list */
            if (vrmr_list_append(&blocklist.list,
                        remove_leading_part(vr_script->bdat)) == NULL) {
                vrmr_error(VRS_ERR_INTERNAL, VR_ERR,
                        "parameter problem (in: %s:%d)", __FUNC__, __LINE__);
                free(str);
                return (VRS_ERR_INTERNAL);
            }
        } else {
            /* we want to remove it: so lets just not put it in the list! */
            removed = TRUE; /* this means, we have something changed in
                       the blocklist */
        }

        free(str);
    }

    if (removed == TRUE) {
        if (vrmr_blocklist_save_list(
                    &vr_script->vctx, &vr_script->vctx.conf, &blocklist) != 0) {
            vrmr_error(VRS_ERR_COMMAND_FAILED, VR_ERR,
                    "could not save updated blocklist (in: %s:%d).", __FUNC__,
                    __LINE__);
            return (VRS_ERR_COMMAND_FAILED);
        }
        logchange(vr_script, "item '%s' removed from the blocklist.",
                vr_script->bdat);
    } else {
        vrmr_error(VRS_ERR_COMMANDLINE, VR_ERR,
                "item '%s' not found in the blocklist (in: %s:%d).",
                vr_script->set, __FUNC__, __LINE__);
        retval = VRS_ERR_COMMANDLINE;
    }

    vrmr_list_cleanup(&blocklist.list);

    return (retval);
}
