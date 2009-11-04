/***************************************************************************
 *   Copyright (C) 2003-2008 by Victor Julien                              *
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
 
/* returns: 0 ok, -1 error */
int
vcconfig_use_defaults(const int debuglvl, vc_cnf *cnf)
{
    size_t  size = 0;
    
    if(cnf == NULL)
    {
        (void)vrprint.error(-1, VR_INTERR, "parameter problem "
                "(in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    cnf->advanced_mode = DEFAULT_ADVANCED_MODE;
    cnf->draw_status = DEFAULT_MAINMENU_STATUS;
    cnf->newrule_log = DEFAULT_NEWRULE_LOG;
    cnf->newrule_loglimit = DEFAULT_NEWRULE_LOGLIMIT;
    cnf->newrule_logburst = cnf->newrule_loglimit * 2;
    cnf->logview_bufsize = DEFAULT_LOGVIEW_BUFFERSIZE;

    size = strlcpy(cnf->iptrafvol_location, DEFAULT_IPTRAFVOL_LOCATION,
        sizeof(cnf->iptrafvol_location));
    if(size >= sizeof(cnf->iptrafvol_location))
    {
        (void)vrprint.error(-1, "Error", "buffer overflow (in: %s:%d).",
                __FUNC__, __LINE__);
        return(-1);
    }

    return(0);
}


/*

*/
int
init_vcconfig(const int debuglvl, char *configfile_location, vc_cnf *cnf)
{
    int     retval = VR_CNF_OK,
            result = 0;
    char    answer[32] = "";
    FILE    *fp = NULL;
    size_t  size = 0;


    /* safety first */
    if(configfile_location == NULL || cnf == NULL)
        return(VR_CNF_E_PARAMETER);


    /* now, based on this, the helpdir location */
    if(snprintf(cnf->helpfile_location, sizeof(cnf->helpfile_location), "%s/help", conf.datadir) >= (int)sizeof(cnf->helpfile_location))
    {
        (void)vrprint.error(-1, "Error", "buffer too small for helpdir supplied at compile-time (in: %s:%d).",
                            __FUNC__, __LINE__);
        return(-1);
    }
    sanitize_path(debuglvl, cnf->helpfile_location,
            sizeof(cnf->helpfile_location));

    /* now, based on this, the scriptsdir location */
    if(snprintf(cnf->scripts_location, sizeof(cnf->scripts_location), "%s/scripts", conf.datadir) >= (int)sizeof(cnf->scripts_location))
    {
        (void)vrprint.error(-1, "Error", "buffer too small for scriptsdir supplied at compile-time (in: %s:%d).",
                            __FUNC__, __LINE__);
        return(-1);
    }
    sanitize_path(debuglvl, cnf->scripts_location,
            sizeof(cnf->scripts_location));


    if(!(fp = fopen(configfile_location, "r")))
    {
        /* don't print error if the file is missing, we use the defaults in
            that case */
        if(errno != ENOENT)
            (void)vrprint.error(-1, VR_ERR, "%s: %s %s (%s:%d).",
                    STR_OPENING_FILE_FAILED,
                    configfile_location,
                    strerror(errno),
                    __FUNC__, __LINE__);

        if(errno == ENOENT)
            return(VR_CNF_E_FILE_MISSING);
        else if(errno == EACCES)
            return(VR_CNF_E_FILE_PERMISSION);
        else
            return(VR_CNF_E_UNKNOWN_ERR);
    }
    fclose(fp);


    /* check if we like the configfile */
    if(!(stat_ok(debuglvl, &conf, configfile_location, STATOK_WANT_FILE, STATOK_VERBOSE, STATOK_MUST_EXIST)))
        return(VR_CNF_E_FILE_PERMISSION);


    /* ADVANCED_MODE */
    result = ask_configfile(debuglvl, &conf, "ADVANCED_MODE", answer, configfile_location, sizeof(answer));
    if(result == 1)
    {
        /* ok, found */
        if(strcasecmp(answer, "yes") == 0)
        {
            cnf->advanced_mode = 1;
        }
        else if(strcasecmp(answer, "no") == 0)
        {
            cnf->advanced_mode = 0;
        }
        else
        {
            (void)vrprint.debug(__FUNC__, "Not sure what to make of ADVANCED_MODE '%s', using default (%s).",
                            answer,
                            DEFAULT_ADVANCED_MODE ? "Yes": "No");

            cnf->advanced_mode = DEFAULT_ADVANCED_MODE;
        }
    }
    else if(result == 0)
    {
        (void)vrprint.debug(__FUNC__, "Variable ADVANCED_MODE not found in '%s'. Using default (%s).",
                        configfile_location,
                        DEFAULT_ADVANCED_MODE ? "Yes" : "No");

        cnf->advanced_mode = DEFAULT_ADVANCED_MODE;
    }
    else
        return(VR_CNF_E_UNKNOWN_ERR);


    /* MAINMENU_STATUS */
    result = ask_configfile(debuglvl, &conf, "MAINMENU_STATUS", answer, configfile_location, sizeof(answer));
    if(result == 1)
    {
        /* ok, found */
        if(strcasecmp(answer, "yes") == 0)
        {
            cnf->draw_status = 1;
        }
        else if(strcasecmp(answer, "no") == 0)
        {
            cnf->draw_status = 0;
        }
        else
        {
            (void)vrprint.debug(__FUNC__, "Not sure what to make of MAINMENU_STATUS '%s', using default (%s).",
                            answer,
                            DEFAULT_MAINMENU_STATUS ? "Yes": "No");

            cnf->draw_status = DEFAULT_MAINMENU_STATUS;
        }
    }
    else if(result == 0)
    {
        (void)vrprint.debug(__FUNC__, "Variable MAINMENU_STATUS not found in '%s'. Using default (%s).",
                        configfile_location,
                        DEFAULT_MAINMENU_STATUS ? "Yes" : "No");

        cnf->draw_status = DEFAULT_MAINMENU_STATUS;
    }
    else
        return(VR_CNF_E_UNKNOWN_ERR);


    /* IPTRAFVOL */
    result = ask_configfile(debuglvl, &conf, "IPTRAFVOL", cnf->iptrafvol_location, configfile_location, sizeof(cnf->iptrafvol_location));
    if(result == 1)
    {
        /* ok */
    }
    else if(result == 0)
    {
        (void)vrprint.debug(__FUNC__, "Variable IPTRAFVOL not found in '%s', using default value: %s",
                        configfile_location,
                        DEFAULT_IPTRAFVOL_LOCATION);

        size = strlcpy(cnf->iptrafvol_location, DEFAULT_IPTRAFVOL_LOCATION,
            sizeof(cnf->iptrafvol_location));
        if(size >= sizeof(cnf->iptrafvol_location))
        {
            (void)vrprint.error(-1, "Error", "buffer overflow "
                    "(in: %s:%d).", __FUNC__, __LINE__);
            return(-1);
        }
    }
    else
        return(VR_CNF_E_UNKNOWN_ERR);

    sanitize_path(debuglvl, cnf->iptrafvol_location,
            sizeof(cnf->iptrafvol_location));


    /* NEWRULE_LOG */
    result = ask_configfile(debuglvl, &conf, "NEWRULE_LOG", answer, configfile_location, sizeof(answer));
    if(result == 1)
    {
        /* ok, found */
        if(strcasecmp(answer, "yes") == 0)
        {
            cnf->newrule_log = 1;
        }
        else if(strcasecmp(answer, "no") == 0)
        {
            cnf->newrule_log = 0;
        }
        else
        {
            (void)vrprint.debug(__FUNC__, "Not sure what to make of NEWRULE_LOG '%s', using default (%s).",
                            answer,
                            DEFAULT_NEWRULE_LOG ? "Yes": "No");

            cnf->newrule_log = DEFAULT_NEWRULE_LOG;
        }
    }
    else if(result == 0)
    {
        (void)vrprint.debug(__FUNC__, "Variable NEWRULE_LOG not found in '%s'. Using default (%s).",
                        configfile_location,
                        DEFAULT_NEWRULE_LOG ? "Yes" : "No");

        cnf->newrule_log = DEFAULT_NEWRULE_LOG;
    }
    else
        return(VR_CNF_E_UNKNOWN_ERR);


    /* NEWRULE_LOGLIMIT */
    result = ask_configfile(debuglvl, &conf, "NEWRULE_LOGLIMIT", answer, configfile_location, sizeof(answer));
    if(result == 1)
    {
        /* ok, found */
        result = atoi(answer);
        if(result < 0)
        {
            (void)vrprint.debug(__FUNC__, "A negative LOG-limit (%d) can not be used, using default (%d).",
                                result,
                                DEFAULT_NEWRULE_LOGLIMIT);

            cnf->newrule_loglimit = (unsigned int)DEFAULT_NEWRULE_LOGLIMIT;
            cnf->newrule_logburst = (unsigned int)(cnf->newrule_loglimit * 2);
        }
        else
        {
            cnf->newrule_loglimit = (unsigned int)result;
            cnf->newrule_logburst = (unsigned int)(cnf->newrule_loglimit * 2);
        }
    }
    else if(result == 0)
    {
        (void)vrprint.debug(__FUNC__, "Variable NEWRULE_LOGLIMIT not found in '%s'. Using default (%d).",
                            configfile_location,
                            DEFAULT_NEWRULE_LOGLIMIT);

        cnf->newrule_loglimit = (unsigned int)DEFAULT_NEWRULE_LOGLIMIT;
        cnf->newrule_logburst = (unsigned int)(cnf->newrule_loglimit * 2);
    }
    else
        return(VR_CNF_E_UNKNOWN_ERR);


    /* LOGVIEW_BUFSIZE */
    result = ask_configfile(debuglvl, &conf, "LOGVIEW_BUFSIZE", answer, configfile_location, sizeof(answer));
    if(result == 1)
    {
        /* ok, found */
        result = atoi(answer);
        if(result < 0)
        {
            (void)vrprint.debug(__FUNC__, "A negative buffersize (%d) can not be used, using default (%d).",
                                result,
                                DEFAULT_LOGVIEW_BUFFERSIZE);

            cnf->logview_bufsize = (unsigned int)DEFAULT_LOGVIEW_BUFFERSIZE;
        }
        else
        {
            cnf->logview_bufsize = (unsigned int)result;
        }
    }
    else if(result == 0)
    {
        (void)vrprint.debug(__FUNC__, "Variable LOGVIEW_BUFSIZE not found in '%s'. Using default (%d).",
                            configfile_location,
                            DEFAULT_LOGVIEW_BUFFERSIZE);

        cnf->logview_bufsize = (unsigned int)DEFAULT_LOGVIEW_BUFFERSIZE;
    }
    else
        return(VR_CNF_E_UNKNOWN_ERR);

    return(retval);
}


/*  write_configfile

    Writes the config to disk.
*/
int
write_vcconfigfile(const int debuglvl, char *file_location, vc_cnf *cnf)
{
    FILE *fp = NULL;


    /* safety */
    if(file_location == NULL || cnf == NULL)
    {
        (void)vrprint.error(-1, VR_INTERR, "parameter problem "
                "(in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    /* open for over-writing */
    if(!(fp = fopen(file_location, "w+")))
    {
        (void)vrprint.error(-1, VR_ERR, "%s: %s (%s:%d).",
                STR_OPENING_FILE_FAILED, strerror(errno),
                __FUNC__, __LINE__);
        return(-1);
    }

    /* start writing the config to the file */
    fprintf(fp, "# vuurmuur_conf config file\n\n");

    fprintf(fp, "# Some parts of the Gui have advanced options that can be enabled by.\n");
    fprintf(fp, "# pressing F5. If you set this to yes, they will be enabled by default.\n");
    fprintf(fp, "ADVANCED_MODE=\"%s\"\n\n", cnf->advanced_mode ? "Yes" : "No");

    fprintf(fp, "# The main menu can show status information about various parts of.\n");
    fprintf(fp, "# Vuurmuur.\n");
    fprintf(fp, "MAINMENU_STATUS=\"%s\"\n\n", cnf->draw_status ? "Yes" : "No");

    fprintf(fp, "# NEWRULE_LOG enables logging for new rules.\n");
    fprintf(fp, "NEWRULE_LOG=\"%s\"\n\n", cnf->newrule_log ? "Yes" : "No");

    fprintf(fp, "# NEWRULE_LOGLIMIT sets the maximum number of logs per second for new rules.\n");
    fprintf(fp, "NEWRULE_LOGLIMIT=\"%u\"\n\n", cnf->newrule_loglimit);

    fprintf(fp, "# LOGVIEW_BUFSIZE sets the buffersize (in loglines) of the logviewer for scrolling back.\n");
    fprintf(fp, "LOGVIEW_BUFSIZE=\"%u\"\n\n", cnf->logview_bufsize);

    fprintf(fp, "# The location of the iptrafvol.pl command.\n");
    fprintf(fp, "IPTRAFVOL=\"%s\"\n\n", cnf->iptrafvol_location);

    fprintf(fp, "# end of file\n");

    /* flush buffer */
    fflush(fp);
    /* close file */
    fclose(fp);

    (void)vrprint.info(VR_INFO, gettext("rewritten Vuurmuur_conf config file."));
    return(0);
}
