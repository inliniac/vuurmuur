/***************************************************************************
 *   Copyright (C) 2003-2017 by Victor Julien                              *
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

#include "main.h"

void vcconfig_use_defaults(struct vrmr_gui_conf *cnf)
{
    vrmr_fatal_if_null(cnf);

    cnf->advanced_mode = VRMR_DEFAULT_ADVANCED_MODE;
    cnf->draw_status = VRMR_DEFAULT_MAINMENU_STATUS;
    cnf->newrule_log = VRMR_DEFAULT_NEWRULE_LOG;
    cnf->newrule_loglimit = VRMR_DEFAULT_NEWRULE_LOGLIMIT;
    cnf->newrule_logburst = cnf->newrule_loglimit * 2;
    cnf->logview_bufsize = VRMR_DEFAULT_LOGVIEW_BUFFERSIZE;
    cnf->background = 0; /* blue */

    (void)strlcpy(cnf->iptrafvol_location, VRMR_DEFAULT_IPTRAFVOL_LOCATION,
            sizeof(cnf->iptrafvol_location));
}

int init_vcconfig(struct vrmr_config *conf, char *configfile_location,
        struct vrmr_gui_conf *cnf)
{
    int retval = VRMR_CNF_OK, result = 0;
    char answer[32] = "";
    FILE *fp = NULL;

    /* safety first */
    vrmr_fatal_if_null(configfile_location);
    vrmr_fatal_if_null(cnf);

    /* now, based on this, the helpdir location */
    snprintf(cnf->helpfile_location, sizeof(cnf->helpfile_location), "%s/help",
            conf->datadir);
    vrmr_sanitize_path(cnf->helpfile_location, sizeof(cnf->helpfile_location));

    /* now, based on this, the scriptsdir location */
    snprintf(cnf->scripts_location, sizeof(cnf->scripts_location), "%s/scripts",
            conf->datadir);
    vrmr_sanitize_path(cnf->scripts_location, sizeof(cnf->scripts_location));

    if (!(fp = fopen(configfile_location, "r"))) {
        /* don't print error if the file is missing, we use the defaults in
            that case */
        if (errno != ENOENT)
            vrmr_error(-1, VR_ERR, "%s: %s %s (%s:%d).",
                    STR_OPENING_FILE_FAILED, configfile_location,
                    strerror(errno), __FUNC__, __LINE__);

        if (errno == ENOENT)
            return (VRMR_CNF_E_FILE_MISSING);
        else if (errno == EACCES)
            return (VRMR_CNF_E_FILE_PERMISSION);
        else
            return (VRMR_CNF_E_UNKNOWN_ERR);
    }
    fclose(fp);

    /* check if we like the configfile */
    if (!(vrmr_stat_ok(conf, configfile_location, VRMR_STATOK_WANT_FILE,
                VRMR_STATOK_VERBOSE, VRMR_STATOK_MUST_EXIST)))
        return (VRMR_CNF_E_FILE_PERMISSION);

    /* ADVANCED_MODE */
    result = vrmr_ask_configfile(
            conf, "ADVANCED_MODE", answer, configfile_location, sizeof(answer));
    if (result == 1) {
        /* ok, found */
        if (strcasecmp(answer, "yes") == 0) {
            cnf->advanced_mode = 1;
        } else if (strcasecmp(answer, "no") == 0) {
            cnf->advanced_mode = 0;
        } else {
            vrmr_debug(NONE,
                    "Not sure what to make of ADVANCED_MODE '%s', using "
                    "default (%s).",
                    answer, VRMR_DEFAULT_ADVANCED_MODE ? "Yes" : "No");

            cnf->advanced_mode = VRMR_DEFAULT_ADVANCED_MODE;
        }
    } else if (result == 0) {
        vrmr_debug(NONE,
                "Variable ADVANCED_MODE not found in '%s'. Using default (%s).",
                configfile_location, VRMR_DEFAULT_ADVANCED_MODE ? "Yes" : "No");

        cnf->advanced_mode = VRMR_DEFAULT_ADVANCED_MODE;
    } else
        return (VRMR_CNF_E_UNKNOWN_ERR);

    /* MAINMENU_STATUS */
    result = vrmr_ask_configfile(conf, "MAINMENU_STATUS", answer,
            configfile_location, sizeof(answer));
    if (result == 1) {
        /* ok, found */
        if (strcasecmp(answer, "yes") == 0) {
            cnf->draw_status = 1;
        } else if (strcasecmp(answer, "no") == 0) {
            cnf->draw_status = 0;
        } else {
            vrmr_debug(NONE,
                    "Not sure what to make of MAINMENU_STATUS '%s', using "
                    "default (%s).",
                    answer, VRMR_DEFAULT_MAINMENU_STATUS ? "Yes" : "No");

            cnf->draw_status = VRMR_DEFAULT_MAINMENU_STATUS;
        }
    } else if (result == 0) {
        vrmr_debug(NONE,
                "Variable MAINMENU_STATUS not found in '%s'. Using default "
                "(%s).",
                configfile_location,
                VRMR_DEFAULT_MAINMENU_STATUS ? "Yes" : "No");

        cnf->draw_status = VRMR_DEFAULT_MAINMENU_STATUS;
    } else
        return (VRMR_CNF_E_UNKNOWN_ERR);

    /* IPTRAFVOL */
    result = vrmr_ask_configfile(conf, "IPTRAFVOL", cnf->iptrafvol_location,
            configfile_location, sizeof(cnf->iptrafvol_location));
    if (result == 1) {
        /* ok */
    } else if (result == 0) {
        vrmr_debug(NONE,
                "Variable IPTRAFVOL not found in '%s', using default value: %s",
                configfile_location, VRMR_DEFAULT_IPTRAFVOL_LOCATION);

        (void)strlcpy(cnf->iptrafvol_location, VRMR_DEFAULT_IPTRAFVOL_LOCATION,
                sizeof(cnf->iptrafvol_location));
    } else
        return (VRMR_CNF_E_UNKNOWN_ERR);

    vrmr_sanitize_path(
            cnf->iptrafvol_location, sizeof(cnf->iptrafvol_location));

    /* NEWRULE_LOG */
    result = vrmr_ask_configfile(
            conf, "NEWRULE_LOG", answer, configfile_location, sizeof(answer));
    if (result == 1) {
        /* ok, found */
        if (strcasecmp(answer, "yes") == 0) {
            cnf->newrule_log = 1;
        } else if (strcasecmp(answer, "no") == 0) {
            cnf->newrule_log = 0;
        } else {
            vrmr_debug(NONE,
                    "Not sure what to make of NEWRULE_LOG '%s', using default "
                    "(%s).",
                    answer, VRMR_DEFAULT_NEWRULE_LOG ? "Yes" : "No");

            cnf->newrule_log = VRMR_DEFAULT_NEWRULE_LOG;
        }
    } else if (result == 0) {
        vrmr_debug(NONE,
                "Variable NEWRULE_LOG not found in '%s'. Using default (%s).",
                configfile_location, VRMR_DEFAULT_NEWRULE_LOG ? "Yes" : "No");

        cnf->newrule_log = VRMR_DEFAULT_NEWRULE_LOG;
    } else
        return (VRMR_CNF_E_UNKNOWN_ERR);

    /* NEWRULE_LOGLIMIT */
    result = vrmr_ask_configfile(conf, "NEWRULE_LOGLIMIT", answer,
            configfile_location, sizeof(answer));
    if (result == 1) {
        /* ok, found */
        result = atoi(answer);
        if (result < 0) {
            vrmr_debug(NONE,
                    "A negative LOG-limit (%d) can not be used, using default "
                    "(%d).",
                    result, VRMR_DEFAULT_NEWRULE_LOGLIMIT);

            cnf->newrule_loglimit = (unsigned int)VRMR_DEFAULT_NEWRULE_LOGLIMIT;
            cnf->newrule_logburst = (unsigned int)(cnf->newrule_loglimit * 2);
        } else {
            cnf->newrule_loglimit = (unsigned int)result;
            cnf->newrule_logburst = (unsigned int)(cnf->newrule_loglimit * 2);
        }
    } else if (result == 0) {
        vrmr_debug(NONE,
                "Variable NEWRULE_LOGLIMIT not found in '%s'. Using default "
                "(%d).",
                configfile_location, VRMR_DEFAULT_NEWRULE_LOGLIMIT);

        cnf->newrule_loglimit = (unsigned int)VRMR_DEFAULT_NEWRULE_LOGLIMIT;
        cnf->newrule_logburst = (unsigned int)(cnf->newrule_loglimit * 2);
    } else
        return (VRMR_CNF_E_UNKNOWN_ERR);

    /* LOGVIEW_BUFSIZE */
    result = vrmr_ask_configfile(conf, "LOGVIEW_BUFSIZE", answer,
            configfile_location, sizeof(answer));
    if (result == 1) {
        /* ok, found */
        result = atoi(answer);
        if (result < 0) {
            vrmr_debug(NONE,
                    "A negative buffersize (%d) can not be used, using default "
                    "(%d).",
                    result, VRMR_DEFAULT_LOGVIEW_BUFFERSIZE);

            cnf->logview_bufsize =
                    (unsigned int)VRMR_DEFAULT_LOGVIEW_BUFFERSIZE;
        } else {
            cnf->logview_bufsize = (unsigned int)result;
        }
    } else if (result == 0) {
        vrmr_debug(NONE,
                "Variable LOGVIEW_BUFSIZE not found in '%s'. Using default "
                "(%d).",
                configfile_location, VRMR_DEFAULT_LOGVIEW_BUFFERSIZE);

        cnf->logview_bufsize = (unsigned int)VRMR_DEFAULT_LOGVIEW_BUFFERSIZE;
    } else
        return (VRMR_CNF_E_UNKNOWN_ERR);

    /* BACKGROUND */
    result = vrmr_ask_configfile(
            conf, "BACKGROUND", answer, configfile_location, sizeof(answer));
    if (result == 1) {
        /* ok, found */
        if (strcasecmp(answer, "blue") == 0)
            cnf->background = 0;
        else if (strcasecmp(answer, "black") == 0)
            cnf->background = 1;
    }

    return (retval);
}

/*  write_configfile

    Writes the config to disk.
*/
int write_vcconfigfile(char *file_location, struct vrmr_gui_conf *cnf)
{
    FILE *fp = NULL;

    /* safety */
    vrmr_fatal_if_null(file_location);
    vrmr_fatal_if_null(cnf);

    /* open for over-writing */
    if (!(fp = fopen(file_location, "w+"))) {
        vrmr_error(-1, VR_ERR, "%s: %s (%s:%d).", STR_OPENING_FILE_FAILED,
                strerror(errno), __FUNC__, __LINE__);
        return (-1);
    }

    /* start writing the config to the file */
    fprintf(fp, "# vuurmuur_conf config file\n\n");

    fprintf(fp, "# Some parts of the Gui have advanced options that can be "
                "enabled by.\n");
    fprintf(fp, "# pressing F5. If you set this to yes, they will be enabled "
                "by default.\n");
    fprintf(fp, "ADVANCED_MODE=\"%s\"\n\n", cnf->advanced_mode ? "Yes" : "No");

    fprintf(fp, "# The main menu can show status information about various "
                "parts of.\n");
    fprintf(fp, "# Vuurmuur.\n");
    fprintf(fp, "MAINMENU_STATUS=\"%s\"\n\n", cnf->draw_status ? "Yes" : "No");

    fprintf(fp, "# NEWRULE_LOG enables logging for new rules.\n");
    fprintf(fp, "NEWRULE_LOG=\"%s\"\n\n", cnf->newrule_log ? "Yes" : "No");

    fprintf(fp, "# NEWRULE_LOGLIMIT sets the maximum number of logs per second "
                "for new rules.\n");
    fprintf(fp, "NEWRULE_LOGLIMIT=\"%u\"\n\n", cnf->newrule_loglimit);

    fprintf(fp, "# LOGVIEW_BUFSIZE sets the buffersize (in loglines) of the "
                "logviewer for scrolling back.\n");
    fprintf(fp, "LOGVIEW_BUFSIZE=\"%u\"\n\n", cnf->logview_bufsize);

    fprintf(fp, "# The location of the iptrafvol.pl command.\n");
    fprintf(fp, "IPTRAFVOL=\"%s\"\n\n", cnf->iptrafvol_location);

    fprintf(fp, "# Background color: blue or black.\n");
    fprintf(fp, "BACKGROUND=\"%s\"\n\n", cnf->background ? "black" : "blue");

    fprintf(fp, "# end of file\n");

    /* flush buffer */
    fflush(fp);
    /* close file */
    fclose(fp);

    vrmr_info(VR_INFO, gettext("rewritten Vuurmuur_conf config file."));
    return (0);
}
