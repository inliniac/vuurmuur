/***************************************************************************
 *   Copyright (C) 2002-2007 by Victor Julien                              *
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

#include "vuurmuur.h"
#include "binreloc.h"


static int
check_logfile(const int debuglvl, const char *logloc)
{
    int fd;

    /* safetly */
    if(logloc == NULL)
    {
        (void)vrprint.error(-1, "Internal Error", "parameter problem (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    if((fd = open(logloc, O_RDONLY)) == -1)
    {
        /* logfile does not yet exist, try to create it. */
        if((fd = open(logloc, O_WRONLY|O_CREAT|O_EXCL, 0600)) == -1)
        {
            (void)vrprint.error(-1, "Error", "creating of logfile '%s' failed: %s.", logloc, strerror(errno));
            return(-1);
        }
        if(close(fd) == -1)
        {
            (void)vrprint.error(-1, "Error", "closing of logfile '%s' failed: %s.", logloc, strerror(errno));
            return(-1);
        }
    }
    else
    {
        if(close(fd) == -1)
        {
            (void)vrprint.error(-1, "Error", "closing of logfile '%s' failed: %s.", logloc, strerror(errno));
            return(-1);
        }
    }

    if(debuglvl >= MEDIUM)
        (void)vrprint.debug(__FUNC__, "logfile '%s' ok.", logloc);

    return(0);
}


/*  config_check_logdir

    Check the log directory, and creates it if it doesn't exist

    returncodes:
         0: ok
        -1: error
*/
int
config_check_logdir(const int debuglvl, const char *logdir)
{
    DIR *dir_p = NULL;

    /* safetly */
    if(logdir == NULL)
    {
        (void)vrprint.error(-1, "Internal Error", "parameter problem (in: %s:%d).",
                __FUNC__, __LINE__);
        return(-1);
    }

    /* try to open */
    if(!(dir_p = opendir(logdir)))
    {
        if(errno == ENOENT)
        {
            if(mkdir(logdir, 0700) < 0)
            {
                (void)vrprint.error(-1, "Error", "creating log directory '%s' failed: %s.",
                        logdir, strerror(errno));
                return(-1);
            }

            if(debuglvl >= MEDIUM)
                (void)vrprint.debug(__FUNC__, "logdir '%s' created.",
                        logdir);
        }
        else
        {
            (void)vrprint.error(-1, "Error", "opening log directory '%s' failed: %s.",
                    logdir, strerror(errno));
            return(-1);
        }
    }
    else
    {
        if((closedir(dir_p)) == -1)
        {
            (void)vrprint.error(-1, "Error", "closing '%s' failed: %s.",
                    logdir, strerror(errno));
            return(-1);
        }
    }


    if(debuglvl >= MEDIUM)
        (void)vrprint.debug(__FUNC__, "logdir '%s' ok.", logdir);

    return(0);
}


/* difference with config_check_logdir:
   this functions uses vuurmuur_opendir which repairs permissions if needed.
*/
int
config_check_vuurmuurdir(const int debuglvl, const char *logdir)
{
    DIR *dir_p = NULL;

    /* safetly */
    if(logdir == NULL)
    {
        (void)vrprint.error(-1, "Internal Error", "parameter problem (in: %s:%d).",
                __FUNC__, __LINE__);
        return(-1);
    }

    /* this isn't the right approach _at all_ but I don't really know how to do it better */
    if( strcmp(logdir, "/bin") == 0 ||
        strcmp(logdir, "/boot") == 0 ||
        strcmp(logdir, "/dev") == 0 ||
        strcmp(logdir, "/etc") == 0 ||
        strcmp(logdir, "/home") == 0 ||
        strcmp(logdir, "/lib") == 0 ||
        strcmp(logdir, "/mnt") == 0 ||
        strcmp(logdir, "/opt") == 0 ||
        strcmp(logdir, "/proc") == 0 ||
        strcmp(logdir, "/root") == 0 ||
        strcmp(logdir, "/sbin") == 0 ||
        strcmp(logdir, "/sys") == 0 ||
        strcmp(logdir, "/tmp") == 0 ||

        strcmp(logdir, "/usr") == 0 ||
        strcmp(logdir, "/usr/local") == 0 ||
        strcmp(logdir, "/usr/share") == 0 ||
        strcmp(logdir, "/usr/lib") == 0 ||
        strcmp(logdir, "/usr/bin") == 0 ||
        strcmp(logdir, "/usr/sbin") == 0 ||

        strcmp(logdir, "/var") == 0 ||
        strcmp(logdir, "/var/log") == 0 ||

        strcmp(logdir, "/") == 0
    )
    {
        (void)vrprint.error(-1, "Error", "directory '%s' is on my blacklist. Please select another.", logdir);
        return(-1);
    }

    /* try to open, error reporting is done by others */
    if(!(dir_p = vuurmuur_opendir(debuglvl, logdir)))
    {
        return(-1);
    }
    if((closedir(dir_p)) == -1)
    {
        (void)vrprint.error(-1, "Error", "closing '%s' failed: %s.", logdir, strerror(errno));
        return(-1);
    }

    if(debuglvl >= MEDIUM)
        (void)vrprint.debug(__FUNC__, "logdir '%s' ok.", logdir);

    return(0);
}


/*
*/
int
check_iptables_command(const int debuglvl, struct vuurmuur_config *cnf, char *iptables_location, char quiet)
{
    /* safety */
    if(cnf == NULL || iptables_location == NULL)
    {
        (void)vrprint.error(-1, "Internal Error", "parameter problem (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    /* first check if there even is a value */
    if(strcmp(iptables_location, "") == 0)
    {
        if(quiet == FALSE)
            (void)vrprint.error(0, "Error", "The path to the 'iptables'-command was not set.", iptables_location);

        return(0);
    }
    else
    {
        /* now check the command */
        char *args[] = { "--version", NULL };
        int r =  exec_command(debuglvl, cnf, iptables_location, args);
        if (r != 0 && r != 2)
        {
            if(quiet == FALSE)
                (void)vrprint.error(0, "Error", "The path '%s' to the 'iptables'-command seems to be wrong.", iptables_location);

            return(0);
        }
    }

    return(1);
}


/*
*/
int
check_iptablesrestore_command(const int debuglvl, struct vuurmuur_config *cnf, char *iptablesrestore_location, char quiet)
{
    /* safety */
    if(cnf == NULL || iptablesrestore_location == NULL)
    {
        (void)vrprint.error(-1, "Internal Error", "parameter problem (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    /* first check if there even is a value */
    if(strcmp(iptablesrestore_location, "") == 0)
    {
        if(quiet == FALSE)
            (void)vrprint.error(0, "Error", "The path to the 'iptables-restore'-command was not set.", iptablesrestore_location);

        return(0);
    }
    else
    {
        /* now check the command */
        char *args[] = { "<", "/dev/null", NULL };
        int r = exec_command(debuglvl, cnf, iptablesrestore_location, args);
        if (r != 0)
        {
            if(quiet == FALSE)
                (void)vrprint.error(0, "Error", "The path '%s' to the 'iptables-restore'-command seems to be wrong.", iptablesrestore_location);

            return(0);
        }
    }

    return(1);
}

/*
*/
int
check_tc_command(const int debuglvl, struct vuurmuur_config *cnf, char *tc_location, char quiet)
{
    /* safety */
    if(cnf == NULL || tc_location == NULL)
    {
        (void)vrprint.error(-1, "Internal Error", "parameter problem (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    /* first check if there even is a value */
    if(strcmp(tc_location, "") == 0)
    {
        if(quiet == FALSE)
            (void)vrprint.error(0, "Error", "The path to the 'tc'-command was not set.", tc_location);

        return(0);
    }
    else
    {
        char *args[] = { "-V", NULL };
        int r = exec_command(debuglvl, cnf, tc_location, args);
        if (r != 0)
        {
            if(quiet == FALSE)
                (void)vrprint.error(0, "Error", "The path '%s' to the 'tc'-command seems to be wrong.", tc_location);

            return(0);
        }
    }

    return(1);
}


/* updates the logdirlocations in the cnf struct based on cnf->vuurmuur_log_dir */
int
config_set_log_names(const int debuglvl, struct vuurmuur_config *cnf)
{
    int retval = 0;

    /* safety */
    if(cnf == NULL)
    {
        (void)vrprint.error(-1, "Internal Error", "parameter problem (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    if(snprintf(cnf->vuurmuurlog_location, sizeof(cnf->vuurmuurlog_location), "%s/vuurmuur.log", cnf->vuurmuur_logdir_location) >= (int)sizeof(cnf->vuurmuurlog_location))
    {
        (void)vrprint.error(-1, "Error", "vuurmuur.log location was truncated (in: %s:%d).", __FUNC__, __LINE__);
        retval = -1;
    }

    if(snprintf(cnf->trafficlog_location,  sizeof(cnf->trafficlog_location),  "%s/traffic.log",  cnf->vuurmuur_logdir_location) >= (int)sizeof(cnf->trafficlog_location))
    {
        (void)vrprint.error(-1, "Error", "traffic.log location was truncated (in: %s:%d).", __FUNC__, __LINE__);
        retval = -1;
    }

    if(snprintf(cnf->debuglog_location,    sizeof(cnf->debuglog_location),    "%s/debug.log",    cnf->vuurmuur_logdir_location) >= (int)sizeof(cnf->debuglog_location))
    {
        (void)vrprint.error(-1, "Error", "debug.log location was truncated (in: %s:%d).", __FUNC__, __LINE__);
        retval = -1;
    }

    if(snprintf(cnf->errorlog_location,    sizeof(cnf->errorlog_location),    "%s/error.log",    cnf->vuurmuur_logdir_location) >= (int)sizeof(cnf->errorlog_location))
    {
        (void)vrprint.error(-1, "Error", "error.log location was truncated (in: %s:%d).", __FUNC__, __LINE__);
        retval = -1;
    }

    if(snprintf(cnf->auditlog_location,    sizeof(cnf->auditlog_location),    "%s/audit.log",    cnf->vuurmuur_logdir_location) >= (int)sizeof(cnf->auditlog_location))
    {
        (void)vrprint.error(-1, "Error", "audit.log location was truncated (in: %s:%d).", __FUNC__, __LINE__);
        retval = -1;
    }

    return(retval);
}


/*
    Note: we cannot use vrprint.debug and vrprint.info in this, because in most cases
    we want those function to print to the log, however the log locations are only known
    after this function! (unless cnf->verbose_out == 1)
*/
int
init_config(const int debuglvl, struct vuurmuur_config *cnf)
{
    int     retval = VR_CNF_OK,
            result = 0;
    char    answer[32] = "";
    FILE    *fp = NULL;
    char    tmpbuf[512] = "";
    int     askconfig_debuglvl = 0;

    /* safety first */
    if(cnf == NULL)
        return(VR_CNF_E_PARAMETER);

    /* only print debug if we are in verbose mode, since at this moment debug
       still goes to the stdout, because we have yet to initialize our logs */
    askconfig_debuglvl = debuglvl * (int)cnf->verbose_out;


    if(debuglvl >= LOW)
        (void)vrprint.debug(__FUNC__, "etc-dir: '%s/vuurmuur', config-file: '%s'.",
                cnf->etcdir,
                cnf->configfile);

    /* check the file */
    if(!(fp = fopen(cnf->configfile, "r")))
    {
        (void)vrprint.error(-1, "Error", "could not open configfile '%s': %s (in: %s).", cnf->configfile, strerror(errno), __FUNC__);
        if(errno == ENOENT)
            return(VR_CNF_E_FILE_MISSING);
        else if(errno == EACCES)
            return(VR_CNF_E_FILE_PERMISSION);
        else
            return(VR_CNF_E_UNKNOWN_ERR);
    }
    fclose(fp);

    /* check if we like the configfile */
    if(!(stat_ok(debuglvl, cnf->configfile, STATOK_WANT_FILE, STATOK_VERBOSE)))
        return(VR_CNF_E_FILE_PERMISSION);


    result = ask_configfile(askconfig_debuglvl, "SERVICES_BACKEND", cnf->serv_backend_name, cnf->configfile, sizeof(cnf->serv_backend_name));
    if(result == 1)
    {
        /* ok */
        if(cnf->serv_backend_name[0] == '\0')
        {
            retval = VR_CNF_E_MISSING_VAR;
        }
    }
    else if(result == 0)
    {
        if(strlcpy(cnf->serv_backend_name, DEFAULT_BACKEND, sizeof(cnf->serv_backend_name)) >= sizeof(cnf->serv_backend_name))
        {
            (void)vrprint.error(VR_CNF_E_UNKNOWN_ERR, "Internal Error", "string "
                    "overflow (in: %s:%d).", __FUNC__, __LINE__);
            return(VR_CNF_E_UNKNOWN_ERR);
        }

        (void)vrprint.warning("Warning", "Variable SERVICES_BACKEND not found in '%s'. Using default (%s).",
                cnf->configfile, DEFAULT_BACKEND);
    }
    else
        return(VR_CNF_E_UNKNOWN_ERR);


    result = ask_configfile(askconfig_debuglvl, "ZONES_BACKEND", cnf->zone_backend_name, cnf->configfile, sizeof(cnf->zone_backend_name));
    if(result == 1)
    {
        /* ok */
        if(cnf->zone_backend_name[0] == '\0')
        {
            retval = VR_CNF_E_MISSING_VAR;
        }
    }
    else if(result == 0)
    {
        if(strlcpy(cnf->zone_backend_name, DEFAULT_BACKEND, sizeof(cnf->zone_backend_name)) >= sizeof(cnf->zone_backend_name))
        {
            (void)vrprint.error(VR_CNF_E_UNKNOWN_ERR, "Internal Error", "string "
                    "overflow (in: %s:%d).", __FUNC__, __LINE__);
            return(VR_CNF_E_UNKNOWN_ERR);
        }

        (void)vrprint.warning("Warning", "Variable ZONES_BACKEND not found in '%s'. Using default (%s).",
                cnf->configfile, DEFAULT_BACKEND);
    }
    else
        return(VR_CNF_E_UNKNOWN_ERR);


    result = ask_configfile(askconfig_debuglvl, "INTERFACES_BACKEND", cnf->ifac_backend_name, cnf->configfile, sizeof(cnf->ifac_backend_name));
    if(result == 1)
    {
        /* ok */
        if(cnf->ifac_backend_name[0] == '\0')
        {
            retval = VR_CNF_E_MISSING_VAR;
        }
    }
    else if(result == 0)
    {
        if(strlcpy(cnf->ifac_backend_name, DEFAULT_BACKEND, sizeof(cnf->ifac_backend_name)) >= sizeof(cnf->ifac_backend_name))
        {
            (void)vrprint.error(VR_CNF_E_UNKNOWN_ERR, "Internal Error", "string "
                    "overflow (in: %s:%d).", __FUNC__, __LINE__);
            return(VR_CNF_E_UNKNOWN_ERR);
        }

        (void)vrprint.warning("Warning", "Variable INTERFACES_BACKEND not found in '%s'. Using default (%s).",
                cnf->configfile, DEFAULT_BACKEND);
    }
    else
        return(VR_CNF_E_UNKNOWN_ERR);


    result = ask_configfile(askconfig_debuglvl, "RULES_BACKEND", cnf->rule_backend_name, cnf->configfile, sizeof(cnf->rule_backend_name));
    if(result == 1)
    {
        /* ok */
        if(cnf->rule_backend_name[0] == '\0')
        {
            retval = VR_CNF_E_MISSING_VAR;
        }
    }
    else if(result == 0)
    {
        if(strlcpy(cnf->rule_backend_name, DEFAULT_BACKEND, sizeof(cnf->rule_backend_name)) >= sizeof(cnf->rule_backend_name))
        {
            (void)vrprint.error(VR_CNF_E_UNKNOWN_ERR, "Internal Error", "string "
                    "overflow (in: %s:%d).", __FUNC__, __LINE__);
            return(VR_CNF_E_UNKNOWN_ERR);
        }

//      (void)vrprint.warning("Warning", "Variable RULES_BACKEND not found in '%s'. Using default (%s).",
//              cnf->configfile, DEFAULT_BACKEND);
    }
    else
        return(VR_CNF_E_UNKNOWN_ERR);


    result = ask_configfile(askconfig_debuglvl, "RULESFILE", cnf->rules_location, cnf->configfile, sizeof(cnf->rules_location));
    if(result == 1)
    {
        if(cnf->rules_location[0] == '\0')
        {
            /* assemble it */
            snprintf(tmpbuf, sizeof(tmpbuf), "%s/vuurmuur/rules.conf", cnf->etcdir);
            /* copy back */
            if(strlcpy(cnf->rules_location, tmpbuf, sizeof(cnf->rules_location)) >= sizeof(cnf->rules_location))
            {
                (void)vrprint.error(VR_CNF_E_UNKNOWN_ERR, "Internal Error",
                        "string overflow (in: %s:%d).",
                        __FUNC__, __LINE__);
                return(VR_CNF_E_UNKNOWN_ERR);
            }
        }
        else if(cnf->rules_location[0] != '/')
        {
            /* assemble it */
            snprintf(tmpbuf, sizeof(tmpbuf), "%s/vuurmuur/%s", cnf->etcdir, cnf->rules_location);
            /* copy back */
            if(strlcpy(cnf->rules_location, tmpbuf, sizeof(cnf->rules_location)) >= sizeof(cnf->rules_location))
            {
                (void)vrprint.error(VR_CNF_E_UNKNOWN_ERR, "Internal Error",
                        "string overflow (in: %s:%d).",
                        __FUNC__, __LINE__);
                return(VR_CNF_E_UNKNOWN_ERR);
            }
        }
    }
    else if(result == 0)
    {
        /* assemble it */
        snprintf(tmpbuf, sizeof(tmpbuf), "%s/vuurmuur/rules.conf", cnf->etcdir);
        /* copy back */
        if(strlcpy(cnf->rules_location, tmpbuf, sizeof(cnf->rules_location)) >= sizeof(cnf->rules_location))
        {
            (void)vrprint.error(VR_CNF_E_UNKNOWN_ERR, "Internal Error",
                    "string overflow (in: %s:%d).",
                    __FUNC__, __LINE__);
            return(VR_CNF_E_UNKNOWN_ERR);
        }
    }
    else
        return(VR_CNF_E_UNKNOWN_ERR);

    sanitize_path(debuglvl, cnf->rules_location, sizeof(cnf->rules_location));

    result = ask_configfile(askconfig_debuglvl, "BLOCKLISTFILE", cnf->blocklist_location, cnf->configfile, sizeof(cnf->blocklist_location));
    if(result == 1)
    {
        /* ok, found */
        if(cnf->blocklist_location[0] == '\0')
        {
            /* assemble it */
            snprintf(tmpbuf, sizeof(tmpbuf), "%s/vuurmuur/blocked.list", cnf->etcdir);
            /* copy back */
            if(strlcpy(cnf->blocklist_location, tmpbuf, sizeof(cnf->blocklist_location)) >= sizeof(cnf->blocklist_location))
            {
                (void)vrprint.error(VR_CNF_E_UNKNOWN_ERR, "Internal Error",
                        "string overflow (in: %s:%d).",
                        __FUNC__, __LINE__);
                return(VR_CNF_E_UNKNOWN_ERR);
            }
        }
        else if(strlen(cnf->blocklist_location) > 0 && cnf->blocklist_location[0] != '/')
        {
            /* not a fullpath, so assemble it */
            snprintf(tmpbuf, sizeof(tmpbuf), "%s/vuurmuur/%s", cnf->etcdir, cnf->blocklist_location);
            /* copy back */
            if(strlcpy(cnf->blocklist_location, tmpbuf, sizeof(cnf->blocklist_location)) >= sizeof(cnf->blocklist_location))
            {
                (void)vrprint.error(VR_CNF_E_UNKNOWN_ERR, "Internal Error",
                        "string overflow (in: %s:%d).",
                        __FUNC__, __LINE__);
                return(VR_CNF_E_UNKNOWN_ERR);
            }
        }
    }
    else if(result == 0)
    {
        /* assemble it */
        snprintf(tmpbuf, sizeof(tmpbuf), "%s/vuuurmuur/%s", cnf->etcdir, "blocked.list");
        /* copy back */
        if(strlcpy(cnf->blocklist_location, tmpbuf, sizeof(cnf->blocklist_location)) >= sizeof(cnf->blocklist_location))
        {
            (void)vrprint.error(VR_CNF_E_UNKNOWN_ERR, "Internal Error",
                    "string overflow (in: %s:%d).",
                    __FUNC__, __LINE__);
            return(VR_CNF_E_UNKNOWN_ERR);
        }
    }
    else
        return(VR_CNF_E_UNKNOWN_ERR);

    sanitize_path(debuglvl, cnf->blocklist_location, sizeof(cnf->blocklist_location));

    /* old create */
    cnf->old_rulecreation_method = FALSE;

    /* DYN_INT_CHECK */
    result = ask_configfile(askconfig_debuglvl, "DYN_INT_CHECK", answer, cnf->configfile, sizeof(answer));
    if(result == 1)
    {
        /* ok, found */
        if(strcasecmp(answer, "yes") == 0)
        {
            cnf->dynamic_changes_check = TRUE;
        }
        else if(strcasecmp(answer, "no") == 0)
        {
            cnf->dynamic_changes_check = FALSE;
        }
        else
        {
            (void)vrprint.warning("Warning", "'%s' is not a valid value for option DYN_INT_CHECK.", answer);
            cnf->dynamic_changes_check = DEFAULT_DYN_INT_CHECK;

            retval = VR_CNF_W_ILLEGAL_VAR;
        }
    }
    else if(result == 0)
    {
        cnf->dynamic_changes_check = DEFAULT_DYN_INT_CHECK;
    }
    else
        return(VR_CNF_E_UNKNOWN_ERR);


    /* LOG_POLICY_LIMIT */
    result = ask_configfile(askconfig_debuglvl, "DYN_INT_INTERVAL", answer, cnf->configfile, sizeof(answer));
    if(result == 1)
    {
        /* ok, found */
        result = atoi(answer);
        if(result < 0)
        {
            (void)vrprint.warning("Warning", "A negative DYN_INT_INTERVAL-limit (%d) can not be used, using default (%u).", result, DEFAULT_DYN_INT_INTERVAL);
            cnf->dynamic_changes_interval = DEFAULT_DYN_INT_INTERVAL;

            retval = VR_CNF_W_ILLEGAL_VAR;
        }
        else
        {
            cnf->dynamic_changes_interval = (unsigned int)result;
        }
    }
    else if(result == 0)
    {
        cnf->dynamic_changes_interval = DEFAULT_DYN_INT_INTERVAL;
    }
    else
        return(VR_CNF_E_UNKNOWN_ERR);


    /* LOG_BLOCKLIST */
    result = ask_configfile(askconfig_debuglvl, "LOG_BLOCKLIST", answer, cnf->configfile, sizeof(answer));
    if(result == 1)
    {
        /* ok, found */
        if(strcasecmp(answer, "yes") == 0)
        {
            cnf->log_blocklist = TRUE;
        }
        else if(strcasecmp(answer, "no") == 0)
        {
            cnf->log_blocklist = FALSE;
        }
        else
        {
            (void)vrprint.warning("Warning", "'%s' is not a valid value for option LOG_BLOCKLIST.", answer);
            cnf->log_blocklist = DEFAULT_LOG_BLOCKLIST;

            retval = VR_CNF_W_ILLEGAL_VAR;
        }
    }
    else if(result == 0)
    {
        /* if this is missing, we use the default */
        cnf->log_blocklist = DEFAULT_LOG_BLOCKLIST;
    }
    else
        return(VR_CNF_E_UNKNOWN_ERR);


    /* LOG_INVALID */
    result = ask_configfile(askconfig_debuglvl, "LOG_INVALID", answer, cnf->configfile, sizeof(answer));
    if(result == 1)
    {
        /* ok, found */
        if(strcasecmp(answer, "yes") == 0)
        {
            cnf->log_invalid = TRUE;
        }
        else if(strcasecmp(answer, "no") == 0)
        {
            cnf->log_invalid = FALSE;
        }
        else
        {
            (void)vrprint.warning("Warning", "'%s' is not a valid value for option LOG_INVALID.", answer);
            cnf->log_invalid = DEFAULT_LOG_INVALID;

            retval = VR_CNF_W_ILLEGAL_VAR;
        }
    }
    else if(result == 0)
    {
        /* if this is missing, we use the default */
        cnf->log_invalid = DEFAULT_LOG_INVALID;
    }
    else
        return(VR_CNF_E_UNKNOWN_ERR);


    /* LOG_NO_SYN */
    result = ask_configfile(askconfig_debuglvl, "LOG_NO_SYN", answer, cnf->configfile, sizeof(answer));
    if(result == 1)
    {
        /* ok, found */
        if(strcasecmp(answer, "yes") == 0)
        {
            cnf->log_no_syn = TRUE;
        }
        else if(strcasecmp(answer, "no") == 0)
        {
            cnf->log_no_syn = FALSE;
        }
        else
        {
            (void)vrprint.warning("Warning", "'%s' is not a valid value for option LOG_NO_SYN.", answer);
            cnf->log_no_syn = DEFAULT_LOG_NO_SYN;

            retval = VR_CNF_W_ILLEGAL_VAR;
        }
    }
    else if(result == 0)
    {
        /* if this is missing, we use the default */
        cnf->log_no_syn = DEFAULT_LOG_NO_SYN;
    }
    else
        return(VR_CNF_E_UNKNOWN_ERR);


    /* LOG_PROBES */
    result = ask_configfile(askconfig_debuglvl, "LOG_PROBES", answer, cnf->configfile, sizeof(answer));
    if(result == 1)
    {
        /* ok, found */
        if(strcasecmp(answer, "yes") == 0)
        {
            cnf->log_probes = TRUE;
        }
        else if(strcasecmp(answer, "no") == 0)
        {
            cnf->log_probes = FALSE;
        }
        else
        {
            (void)vrprint.warning("Warning", "'%s' is not a valid value for option LOG_PROBES.", answer);
            cnf->log_probes = DEFAULT_LOG_PROBES;

            retval = VR_CNF_W_ILLEGAL_VAR;
        }
    }
    else if(result == 0)
    {
        /* if this is missing, we use the default */
        cnf->log_probes = DEFAULT_LOG_PROBES;
    }
    else
        return(VR_CNF_E_UNKNOWN_ERR);


    /* LOG_FRAG */
    result = ask_configfile(askconfig_debuglvl, "LOG_FRAG", answer, cnf->configfile, sizeof(answer));
    if(result == 1)
    {
        /* ok, found */
        if(strcasecmp(answer, "yes") == 0)
        {
            cnf->log_frag = TRUE;
        }
        else if(strcasecmp(answer, "no") == 0)
        {
            cnf->log_frag = FALSE;
        }
        else
        {
            (void)vrprint.warning("Warning", "'%s' is not a valid value for option LOG_FRAG.", answer);
            cnf->log_frag = DEFAULT_LOG_FRAG;

            retval = VR_CNF_W_ILLEGAL_VAR;
        }
    }
    else if(result == 0)
    {
        /* if this is missing, we use the default */
        cnf->log_frag = DEFAULT_LOG_FRAG;
    }
    else
        return(VR_CNF_E_UNKNOWN_ERR);


    /* USE_SYN_LIMIT */
    result = ask_configfile(askconfig_debuglvl, "USE_SYN_LIMIT", answer, cnf->configfile, sizeof(answer));
    if(result == 1)
    {
        /* ok, found */
        if(strcasecmp(answer, "yes") == 0)
        {
            cnf->use_syn_limit = TRUE;
        }
        else if(strcasecmp(answer, "no") == 0)
        {
            cnf->use_syn_limit = FALSE;
        }
        else
        {
            (void)vrprint.warning("Warning", "'%s' is not a valid value for option USE_SYN_LIMIT.", answer);
            cnf->use_syn_limit = DEFAULT_USE_SYN_LIMIT;

            retval = VR_CNF_W_ILLEGAL_VAR;
        }
    }
    else if(result == 0)
    {
        /* if this is missing, we use the default */
        cnf->use_syn_limit = DEFAULT_USE_SYN_LIMIT;
    }
    else
        return(VR_CNF_E_UNKNOWN_ERR);

    /* SYN_LIMIT */
    result = ask_configfile(askconfig_debuglvl, "SYN_LIMIT", answer, cnf->configfile, sizeof(answer));
    if(result == 1)
    {
        /* ok, found */
        result = atoi(answer);
        if(result < 0)
        {
            (void)vrprint.warning("Warning", "A negative SYN-limit (%d) can not be used, using default (%u).", result, DEFAULT_SYN_LIMIT);
            cnf->syn_limit = DEFAULT_SYN_LIMIT;

            retval = VR_CNF_W_ILLEGAL_VAR;
        }
        else if(result == 0)
        {
            (void)vrprint.warning("Warning", "A SYN-limit of 0 can not be used, using default (%u).", DEFAULT_SYN_LIMIT);
            cnf->syn_limit = DEFAULT_SYN_LIMIT;

            retval = VR_CNF_W_ILLEGAL_VAR;
        }
        else
        {
            cnf->syn_limit = (unsigned int)result;
        }
    }
    else if(result == 0)
    {
        (void)vrprint.warning("Warning", "Variable SYN_LIMIT not found in '%s'. Using default.", cnf->configfile);
        cnf->syn_limit = DEFAULT_SYN_LIMIT;

        retval = VR_CNF_W_MISSING_VAR;
    }
    else
        return(VR_CNF_E_UNKNOWN_ERR);


    /* SYN_LIMIT_BURST */
    result = ask_configfile(askconfig_debuglvl, "SYN_LIMIT_BURST", answer, cnf->configfile, sizeof(answer));
    if(result == 1)
    {
        /* ok, found */
        result = atoi(answer);
        if(result < 0)
        {
            (void)vrprint.warning("Warning", "A negative SYN-limit-burst (%d) can not be used, using default (%u).", result, DEFAULT_SYN_LIMIT_BURST);
            cnf->syn_limit_burst = DEFAULT_SYN_LIMIT_BURST;

            retval = VR_CNF_W_ILLEGAL_VAR;
        }
        else if(result == 0)
        {
            (void)vrprint.warning("Warning", "A SYN-limit-burst of 0 can not be used, using default (%u).", DEFAULT_SYN_LIMIT_BURST);
            cnf->syn_limit_burst = DEFAULT_SYN_LIMIT_BURST;

            retval = VR_CNF_W_ILLEGAL_VAR;
        }
        else
        {
            cnf->syn_limit_burst = (unsigned int)result;
        }
    }
    else if(result == 0)
    {
        (void)vrprint.warning("Warning", "Variable SYN_LIMIT_BURST not found in '%s'. Using default.", cnf->configfile);
        cnf->syn_limit_burst = DEFAULT_SYN_LIMIT_BURST;

        retval = VR_CNF_W_MISSING_VAR;
    }
    else
        return(VR_CNF_E_UNKNOWN_ERR);


    /* USE_UDP_LIMIT */
    result = ask_configfile(askconfig_debuglvl, "USE_UDP_LIMIT", answer, cnf->configfile, sizeof(answer));
    if(result == 1)
    {
        /* ok, found */
        if(strcasecmp(answer, "yes") == 0)
        {
            cnf->use_udp_limit = TRUE;
        }
        else if(strcasecmp(answer, "no") == 0)
        {
            cnf->use_udp_limit = FALSE;
        }
        else
        {
            (void)vrprint.warning("Warning", "'%s' is not a valid value for option USE_UDP_LIMIT.", answer);
            cnf->use_udp_limit = DEFAULT_USE_UDP_LIMIT;

            retval = VR_CNF_W_ILLEGAL_VAR;
        }
    }
    else if(result == 0)
    {
        /* if this is missing, we use the default */
        cnf->use_udp_limit = DEFAULT_USE_UDP_LIMIT;
    }
    else
        return(VR_CNF_E_UNKNOWN_ERR);

    /* UDP_LIMIT */
    result = ask_configfile(askconfig_debuglvl, "UDP_LIMIT", answer, cnf->configfile, sizeof(answer));
    if(result == 1)
    {
        /* ok, found */
        result = atoi(answer);
        if(result < 0)
        {
            (void)vrprint.warning("Warning", "A negative UDP-limit (%d) can not be used, using default (%u).", result, DEFAULT_UDP_LIMIT);
            cnf->udp_limit = DEFAULT_UDP_LIMIT;

            retval = VR_CNF_W_ILLEGAL_VAR;
        }
        else if(result == 0)
        {
            (void)vrprint.warning("Warning", "A UDP-limit of 0 can not be used, using default (%u).", DEFAULT_UDP_LIMIT);
            cnf->udp_limit = DEFAULT_UDP_LIMIT;

            retval = VR_CNF_W_ILLEGAL_VAR;
        }
        else
        {
            cnf->udp_limit = (unsigned int)result;
        }
    }
    else if(result == 0)
    {
        (void)vrprint.warning("Warning", "Variable UDP_LIMIT not found in '%s'. Using default.", cnf->configfile);
        cnf->udp_limit = DEFAULT_UDP_LIMIT;

        retval = VR_CNF_W_MISSING_VAR;
    }
    else
        return(VR_CNF_E_UNKNOWN_ERR);


    /* UDP_LIMIT_BURST */
    result = ask_configfile(askconfig_debuglvl, "UDP_LIMIT_BURST", answer, cnf->configfile, sizeof(answer));
    if(result == 1)
    {
        /* ok, found */
        result = atoi(answer);
        if(result < 0)
        {
            (void)vrprint.warning("Warning", "A negative UDP-limit-burst (%d) can not be used, using default (%u).", result, DEFAULT_UDP_LIMIT_BURST);
            cnf->udp_limit_burst = DEFAULT_UDP_LIMIT_BURST;

            retval = VR_CNF_W_ILLEGAL_VAR;
        }
        else if(result == 0)
        {
            (void)vrprint.warning("Warning", "A UDP-limit-burst of 0 can not be used, using default (%u).", DEFAULT_UDP_LIMIT_BURST);
            cnf->udp_limit_burst = DEFAULT_UDP_LIMIT_BURST;

            retval = VR_CNF_W_ILLEGAL_VAR;
        }
        else
        {
            cnf->udp_limit_burst = (unsigned int)result;
        }
    }
    else if(result == 0)
    {
        (void)vrprint.warning("Warning", "Variable UDP_LIMIT_BURST not found in '%s'. Using default.", cnf->configfile);
        cnf->udp_limit_burst = DEFAULT_UDP_LIMIT_BURST;

        retval = VR_CNF_W_MISSING_VAR;
    }
    else
        return(VR_CNF_E_UNKNOWN_ERR);


    /* LOG_POLICY */
    result = ask_configfile(askconfig_debuglvl, "LOG_POLICY", answer, cnf->configfile, sizeof(answer));
    if(result == 1)
    {
        /* ok, found */
        if(strcasecmp(answer, "yes") == 0)
        {
            cnf->log_policy = TRUE;
        }
        else if(strcasecmp(answer, "no") == 0)
        {
            cnf->log_policy = FALSE;
        }
        else
        {
            (void)vrprint.warning("Warning", "'%s' is not a valid value for option LOG_POLICY.", answer);
            cnf->log_policy = DEFAULT_LOG_POLICY;

            retval = VR_CNF_W_ILLEGAL_VAR;
        }
    }
    else if(result == 0)
    {
        (void)vrprint.warning("Warning", "Variable LOG_POLICY not found in '%s'. Using default.", cnf->configfile);
        cnf->log_policy = DEFAULT_LOG_POLICY;

        retval = VR_CNF_W_MISSING_VAR;
    }
    else
        return(VR_CNF_E_UNKNOWN_ERR);


    /* LOG_POLICY_LIMIT */
    result = ask_configfile(askconfig_debuglvl, "LOG_POLICY_LIMIT", answer, cnf->configfile, sizeof(answer));
    if(result == 1)
    {
        /* ok, found */
        result = atoi(answer);
        if(result < 0)
        {
            (void)vrprint.warning("Warning", "A negative LOG-limit (%d) can not be used, using default (%u).", result, DEFAULT_LOG_POLICY_LIMIT);
            cnf->log_policy_limit = DEFAULT_LOG_POLICY_LIMIT;
            cnf->log_policy_burst = cnf->log_policy_limit * 2;

            retval = VR_CNF_W_ILLEGAL_VAR;
        }
        else
        {
            cnf->log_policy_limit = (unsigned int)result;
            cnf->log_policy_burst = cnf->log_policy_limit * 2;
        }
    }
    else if(result == 0)
    {
        (void)vrprint.warning("Warning", "Variable LOG_POLICY_LIMIT not found in '%s'. Using default.", cnf->configfile);

        cnf->log_policy_limit = DEFAULT_LOG_POLICY_LIMIT;
        cnf->log_policy_burst = cnf->log_policy_limit * 2;

        retval = VR_CNF_W_MISSING_VAR;
    }
    else
        return(VR_CNF_E_UNKNOWN_ERR);


    /* LOG_TCP_OPTIONS */
    result = ask_configfile(askconfig_debuglvl, "LOG_TCP_OPTIONS", answer, cnf->configfile, sizeof(answer));
    if(result == 1)
    {
        /* ok, found */
        if(strcasecmp(answer, "yes") == 0)
        {
            cnf->log_tcp_options = TRUE;
        }
        else if(strcasecmp(answer, "no") == 0)
        {
            cnf->log_tcp_options = FALSE;
        }
        else
        {
            (void)vrprint.warning("Warning", "'%s' is not a valid value for option LOG_TCP_OPTIONS.", answer);
            cnf->log_tcp_options = DEFAULT_LOG_TCP_OPTIONS;

            retval = VR_CNF_W_ILLEGAL_VAR;
        }
    }
    else if(result == 0)
    {
        /* no warning or whatever */
        cnf->log_tcp_options = DEFAULT_LOG_TCP_OPTIONS;
    }
    else
        return(VR_CNF_E_UNKNOWN_ERR);


    /* PROTECT_SYNCOOKIES */
    result = ask_configfile(askconfig_debuglvl, "PROTECT_SYNCOOKIE", answer, cnf->configfile, sizeof(answer));
    if(result == 1)
    {
        /* ok, found */
        if(strcasecmp(answer, "yes") == 0)
        {
            cnf->protect_syncookie = TRUE;
        }
        else if(strcasecmp(answer, "no") == 0)
        {
            cnf->protect_syncookie = FALSE;
        }
        else
        {
            (void)vrprint.warning("Warning", "'%s' is not a valid value for option PROTECT_SYNCOOKIE.", answer);
            cnf->protect_syncookie = DEFAULT_PROTECT_SYNCOOKIE;

            retval = VR_CNF_W_ILLEGAL_VAR;
        }
    }
    else if(result == 0)
    {
        (void)vrprint.warning("Warning", "Variable PROTECT_SYNCOOKIE not found in '%s'. Using default.", cnf->configfile);
        cnf->protect_syncookie = DEFAULT_PROTECT_SYNCOOKIE;

        retval = VR_CNF_W_MISSING_VAR;
    }
    else
        return(VR_CNF_E_UNKNOWN_ERR);


    /* PROTECT_ECHOBROADCAST */
    result = ask_configfile(askconfig_debuglvl, "PROTECT_ECHOBROADCAST", answer, cnf->configfile, sizeof(answer));
    if(result == 1)
    {
        /* ok, found */
        if(strcasecmp(answer, "yes") == 0)
        {
            cnf->protect_echobroadcast = TRUE;
        }
        else if(strcasecmp(answer, "no") == 0)
        {
            cnf->protect_echobroadcast = FALSE;
        }
        else
        {
            (void)vrprint.warning("Warning", "'%s' is not a valid value for option PROTECT_ECHOBROADCAST.", answer);
            cnf->protect_echobroadcast = DEFAULT_PROTECT_ECHOBROADCAST;

            retval = VR_CNF_W_ILLEGAL_VAR;
        }
    }
    else if(result == 0)
    {
        (void)vrprint.warning("Warning", "Variable PROTECT_ECHOBROADCAST not found in '%s'. Using default.", cnf->configfile);
        cnf->protect_echobroadcast = DEFAULT_PROTECT_ECHOBROADCAST;

        retval = VR_CNF_W_MISSING_VAR;
    }
    else
        return(VR_CNF_E_UNKNOWN_ERR);


    result = ask_configfile(askconfig_debuglvl, "IPTABLES", cnf->iptables_location, cnf->configfile, sizeof(cnf->iptables_location));
    if(result == 1)
    {
        /* ok */
    }
    else if(result == 0)
    {
        (void)vrprint.warning("Warning", "Variable IPTABLES not found in '%s', using default value.", cnf->configfile);
        if(strlcpy(cnf->iptables_location, DEFAULT_IPTABLES_LOCATION, sizeof(cnf->iptables_location)) >= sizeof(cnf->iptables_location))
        {
            (void)vrprint.error(VR_CNF_E_UNKNOWN_ERR, "Internal Error",
                    "string overflow (in: %s:%d).",
                    __FUNC__, __LINE__);
            return(VR_CNF_E_UNKNOWN_ERR);
        }

        retval = VR_CNF_W_MISSING_VAR;
    }
    else
        return(VR_CNF_E_UNKNOWN_ERR);

    sanitize_path(debuglvl, cnf->iptables_location, sizeof(cnf->iptables_location));


    result = ask_configfile(askconfig_debuglvl, "IPTABLES_RESTORE", cnf->iptablesrestore_location, cnf->configfile, sizeof(cnf->iptablesrestore_location));
    if(result == 1)
    {
        /* ok */
    }
    else if(result == 0)
    {
        (void)vrprint.warning("Warning", "Variable IPTABLES_RESTORE not found in '%s', using default value.", cnf->configfile);
        if(strlcpy(cnf->iptablesrestore_location, DEFAULT_IPTABLES_REST_LOCATION, sizeof(cnf->iptablesrestore_location)) >= sizeof(cnf->iptablesrestore_location))
        {
            (void)vrprint.error(VR_CNF_E_UNKNOWN_ERR, "Internal Error",
                    "string overflow (in: %s:%d).",
                    __FUNC__, __LINE__);
            return(VR_CNF_E_UNKNOWN_ERR);
        }

        retval = VR_CNF_W_MISSING_VAR;
    }
    else
        return(VR_CNF_E_UNKNOWN_ERR);

    sanitize_path(debuglvl, cnf->iptablesrestore_location, sizeof(cnf->iptablesrestore_location));


    result = ask_configfile(askconfig_debuglvl, "CONNTRACK", cnf->conntrack_location, cnf->configfile, sizeof(cnf->conntrack_location));
    if(result == 1)
    {
        /* ok */
    }
    else if(result == 0)
    {
        /*  VJ 06/05/03: don't set a default because most systems
            won't have this tool. Keeping it empty allows us to
            check for it not beeing set and present a warning */

        //if(strlcpy(cnf->conntrack_location, DEFAULT_CONNTRACK_LOCATION, sizeof(cnf->conntrack_location)) >= sizeof(cnf->conntrack_location))
        //{
        //    (void)vrprint.error(VR_CNF_E_UNKNOWN_ERR, "Internal Error",
        //            "string overflow (in: %s:%d).",
        //            __FUNC__, __LINE__);
        //    return(VR_CNF_E_UNKNOWN_ERR);
        //}
    }
    else
        return(VR_CNF_E_UNKNOWN_ERR);

    sanitize_path(debuglvl, cnf->conntrack_location, sizeof(cnf->conntrack_location));


    result = ask_configfile(askconfig_debuglvl, "TC", cnf->tc_location, cnf->configfile, sizeof(cnf->tc_location));
    if(result == 1)
    {
        /* ok */
    }
    else if(result == 0)
    {
        /*  VJ 06/05/03: don't set a default because most systems
            won't have this tool. Keeping it empty allows us to
            check for it not beeing set and present a warning */

        //if(strlcpy(cnf->conntrack_location, DEFAULT_TC_LOCATION, sizeof(cnf->tc_location)) >= sizeof(cnf->tc_location))
        //{
        //    (void)vrprint.error(VR_CNF_E_UNKNOWN_ERR, "Internal Error",
        //            "string overflow (in: %s:%d).",
        //            __FUNC__, __LINE__);
        //    return(VR_CNF_E_UNKNOWN_ERR);
        //}
    }
    else
        return(VR_CNF_E_UNKNOWN_ERR);

    sanitize_path(debuglvl, cnf->tc_location, sizeof(cnf->tc_location));


    result = ask_configfile(askconfig_debuglvl, "MODPROBE", cnf->modprobe_location, cnf->configfile, sizeof(cnf->modprobe_location));
    if(result == 1)
    {
        /* ok */
    }
    else if(result == 0)
    {
        if(strlcpy(cnf->modprobe_location, DEFAULT_MODPROBE_LOCATION, sizeof(cnf->modprobe_location)) >= sizeof(cnf->modprobe_location))
        {
            (void)vrprint.error(VR_CNF_E_UNKNOWN_ERR, "Internal Error",
                    "string overflow (in: %s:%d).",
                    __FUNC__, __LINE__);
            return(VR_CNF_E_UNKNOWN_ERR);
        }
    }
    else
        return(VR_CNF_E_UNKNOWN_ERR);

    sanitize_path(debuglvl, cnf->modprobe_location, sizeof(cnf->modprobe_location));


    /* MODULES */
    result = ask_configfile(askconfig_debuglvl, "MODULES", answer, cnf->configfile, sizeof(answer));
    if(result == 1)
    {
        /* ok, found */
        if(strcasecmp(answer, "yes") == 0)
        {
            cnf->load_modules = TRUE;
        }
        else if(strcasecmp(answer, "no") == 0)
        {
            cnf->load_modules = FALSE;
        }
        else
        {
            cnf->load_modules = DEFAULT_LOAD_MODULES;

            retval = VR_CNF_W_ILLEGAL_VAR;
        }
    }
    else if(result == 0)
    {
        cnf->load_modules = DEFAULT_LOAD_MODULES;
    }
    else
        return(VR_CNF_E_UNKNOWN_ERR);


    /* MODULES_WAIT_TIME */
    result = ask_configfile(askconfig_debuglvl, "MODULES_WAIT_TIME", answer, cnf->configfile, sizeof(answer));
    if(result == 1)
    {
        /* ok, found */
        result = atoi(answer);
        if(result < 0)
        {
            (void)vrprint.warning("Warning", "A negative MODULES_WAIT_TIME (%d) can not be used, using default (%u).", result, DEFAULT_MODULES_WAITTIME);
            cnf->modules_wait_time = DEFAULT_MODULES_WAITTIME;

            retval = VR_CNF_W_ILLEGAL_VAR;
        }
        else
        {
            /* 1/10 th of second */
            cnf->modules_wait_time = (unsigned int)result;
        }
    }
    else if(result == 0)
    {
        /* ignore missing, use default */
        cnf->modules_wait_time = DEFAULT_MODULES_WAITTIME;
    }
    else
        return(VR_CNF_E_UNKNOWN_ERR);


    /* check if the configfile value is overridden by the commandline */
    if(cnf->loglevel_cmdline == FALSE)
    {
        result = ask_configfile(askconfig_debuglvl, "LOGLEVEL", cnf->loglevel, cnf->configfile, sizeof(cnf->loglevel));
        if(result == 1)
        {
            // ok
            if(cnf->verbose_out == TRUE && askconfig_debuglvl >= LOW)
                (void)vrprint.info("Info", "Loglevel is '%s'.", cnf->loglevel);
        }
        else if(result == 0)
        {
            (void)vrprint.warning("Warning", "Variable LOGLEVEL not found in the configfile, using default value.");
            memset(cnf->loglevel, 0, sizeof(cnf->loglevel));
            retval = VR_CNF_W_MISSING_VAR;
        }
        else
            return(VR_CNF_E_UNKNOWN_ERR);
    }


    /* systemlog */
    result = ask_configfile(askconfig_debuglvl, "SYSTEMLOG", cnf->systemlog_location, cnf->configfile, sizeof(cnf->systemlog_location));
    if (result == 1 )
    {
        /* ok */
        if(cnf->verbose_out == TRUE && askconfig_debuglvl >= LOW)
            (void)vrprint.info("Info", "Using '%s' as systemlogfile.", cnf->systemlog_location);
    }
    else if(result == 0)
    {
        (void)vrprint.warning("Warning", "Variable SYSTEMLOG not found in '%s', using default value (%s).", cnf->configfile, DEFAULT_SYSTEMLOG_LOCATION);
        if(strlcpy(cnf->systemlog_location, DEFAULT_SYSTEMLOG_LOCATION, sizeof(cnf->systemlog_location)) >= sizeof(cnf->systemlog_location))
        {
            (void)vrprint.error(VR_CNF_E_UNKNOWN_ERR, "Internal Error",
                    "string overflow (in: %s:%d).",
                    __FUNC__, __LINE__);
            return(VR_CNF_E_UNKNOWN_ERR);
        }

        retval = VR_CNF_W_MISSING_VAR;
//TODO: check if location really exists
    }
    else
        return(VR_CNF_E_UNKNOWN_ERR);

    sanitize_path(debuglvl, cnf->systemlog_location, sizeof(cnf->systemlog_location));


    /* get the logfile dir */
    result = ask_configfile(askconfig_debuglvl, "LOGDIR", cnf->vuurmuur_logdir_location, cnf->configfile, sizeof(cnf->vuurmuur_logdir_location));
    if(result == 1)
    {
        if(cnf->verbose_out == TRUE && askconfig_debuglvl >= LOW)
            (void)vrprint.info("Info", "Using '%s' as normal logdir.", cnf->vuurmuur_logdir_location);
    }
    else if(result == 0)
    {
        (void)vrprint.warning("Warning", "Variable LOGDIR not found in '%s', using default value.", cnf->configfile);
        if(strlcpy(cnf->vuurmuur_logdir_location, DEFAULT_LOGDIR_LOCATION, sizeof(cnf->vuurmuur_logdir_location)) >= sizeof(cnf->vuurmuur_logdir_location))
        {
            (void)vrprint.error(VR_CNF_E_UNKNOWN_ERR, "Internal Error",
                    "string overflow (in: %s:%d).",
                    __FUNC__, __LINE__);
            return(VR_CNF_E_UNKNOWN_ERR);
        }

        /* we return here because we don't want the logfile checks if we know
           that this is wrong. */
        return(VR_CNF_W_MISSING_VAR);
    }
    else
        return(VR_CNF_E_UNKNOWN_ERR);


    sanitize_path(debuglvl, cnf->vuurmuur_logdir_location, sizeof(cnf->vuurmuur_logdir_location));


    /* check if we can open the logdir */
    if(config_check_logdir(debuglvl, cnf->vuurmuur_logdir_location) < 0)
        return(VR_CNF_W_ILLEGAL_VAR);


    /* set/update the lognames */
    if(config_set_log_names(debuglvl, cnf) < 0)
        return(VR_CNF_E_UNKNOWN_ERR);


    /* vuurmuur.log */
    if(cnf->verbose_out == TRUE && askconfig_debuglvl >= LOW)
        (void)vrprint.info("Info", "Using '%s' as vuurmuur.log.", cnf->vuurmuurlog_location);

    if(check_logfile(debuglvl, cnf->vuurmuurlog_location) < 0)
    {
        retval = VR_CNF_E_ILLEGAL_VAR;
    }


    /* error.log */
    if(cnf->verbose_out == TRUE && askconfig_debuglvl >= LOW)
        (void)vrprint.info("Info", "Using '%s' as error.log.", cnf->errorlog_location);

    if(check_logfile(debuglvl, cnf->errorlog_location) < 0)
    {
        retval = VR_CNF_E_ILLEGAL_VAR;
    }


    /* debug.log */
    if(cnf->verbose_out == TRUE && askconfig_debuglvl >= LOW)
        (void)vrprint.info("Info", "Using '%s' as debug.log.", cnf->debuglog_location);

    if(check_logfile(debuglvl, cnf->debuglog_location) < 0)
    {
        retval = VR_CNF_E_ILLEGAL_VAR;
    }


    /* traffic.log */
    if(cnf->verbose_out == TRUE && askconfig_debuglvl >= LOW)
        (void)vrprint.info("Info", "Using '%s' as traffic.log.", cnf->trafficlog_location);

    if(check_logfile(debuglvl, cnf->trafficlog_location) < 0)
    {
        retval = VR_CNF_E_ILLEGAL_VAR;
    }

    return(retval);
}


int
reload_config(const int debuglvl, struct vuurmuur_config *old_cnf)
{
    struct vuurmuur_config  new_cnf;
    int                     retval = VR_CNF_OK;

    /* safety */
    if(!old_cnf)
    {
        (void)vrprint.error(-1, "Internal Error", "parameter problem "
            "(in: %s:%d).", __FUNC__, __LINE__);
        return(VR_CNF_E_PARAMETER);
    }

    /* some initilization */
    if(pre_init_config(&new_cnf) < 0)
        return(VR_CNF_E_UNKNOWN_ERR);

    /* loglevel can be overrided by commandline */
    new_cnf.loglevel_cmdline = old_cnf->loglevel_cmdline;

    /* verbose out can only be set on the commandline */
    new_cnf.verbose_out = old_cnf->verbose_out;

    /* this function will never be run in bashmode */
    new_cnf.bash_out = FALSE;
    new_cnf.test_mode = FALSE;

    /* copy the config file location to the new config since it is not loaded by init_config */
    if(strlcpy(new_cnf.configfile, old_cnf->configfile, sizeof(new_cnf.configfile)) >= sizeof(new_cnf.configfile))
    {
        (void)vrprint.error(VR_CNF_E_UNKNOWN_ERR, "Internal Error", "string overflow "
            "(in: %s:%d).", __FUNC__, __LINE__);
        return(VR_CNF_E_UNKNOWN_ERR);
    }

    /* reload the configfile */
    if((retval = init_config(debuglvl, &new_cnf)) >= VR_CNF_OK)
    {
        /* rule creation method is not allowed to change */
        new_cnf.old_rulecreation_method = old_cnf->old_rulecreation_method;

        /* in old_create_method mode, loglevel is not allowed to change at runtime, and neigther log_tcp_options */
        if(new_cnf.old_rulecreation_method == TRUE)
        {
            if(strlcpy(new_cnf.loglevel, old_cnf->loglevel, sizeof(new_cnf.loglevel)) >= sizeof(new_cnf.loglevel))
            {
                (void)vrprint.error(VR_CNF_E_UNKNOWN_ERR,
                        "Internal Error", "string overflow "
                        "(in: %s:%d).", __FUNC__, __LINE__);
                return(VR_CNF_E_UNKNOWN_ERR);
            }
            new_cnf.log_tcp_options = old_cnf->log_tcp_options;
        }

        /* copy the data to the old struct */
        *old_cnf = new_cnf;
    }

    return(retval);
}


/* ask_configfile

    This function ask questions from the configfile.

    Returncodes:
     1: ok
     0: ok, but question not found.
    -1: error
*/
int
ask_configfile(const int debuglvl, char *question, char *answer_ptr, char *file_location, size_t size)
{
    int     retval = 0;
    size_t  i = 0,
            k = 0,
            l = 0,
            j = 0;
    FILE    *fp = NULL;
    char    line[512] = "",
            variable[128] = "",
            value[256] = "";

    if(!question || !file_location || size == 0)
        return(-1);

    if(!(fp = vuurmuur_fopen(file_location,"r")))
    {
        (void)vrprint.error(-1, "Error", "unable to open configfile '%s': %s (in: ask_configfile).", file_location, strerror(errno));
        return(-1);
    }


    while(fgets(line, (int)sizeof(line), fp) != NULL)
    {
        i = strlen(line);
        k=0; l=0; j=0;

        if ((line[0] == '#' ) || (strlen(line) < 1) || (line[0] == '\n'))
        {
            /* do nothing, its a comment. */
        }
        else
        {
            /* variable */
            while(line[k] != '=' && k < size)
            {
                variable[j]=line[k];
                k++; j++;
            }
            variable[j]='\0';

            if(debuglvl >= HIGH)
                (void)vrprint.debug(__FUNC__, "question '%s' variable '%s' (%d)", question, variable, size);

            /* value */
            j=0;
            l=k+1;
            while(line[l] != '\0' && line[l] != '\n' && l < (size+k+1))
            {
                /* if the first character is a '"' we strip it. */
                if(j == 0 && line[l] == '\"')
                {
                    l++;
                }
                else
                {
                    value[j] = line[l];
                    l++;
                    j++;
                }
            }
            /* if the last character is a'"' we strip it. */
            if(j > 0)
            {
                if(value[j-1] == '\"')
                {
                    value[j-1] = '\0';
                }
                else
                    value[j] = '\0';
            }
            else
                value[j] = '\0';

            if(debuglvl >= HIGH)
                (void)vrprint.debug(__FUNC__, "question '%s' value '%s' (%u)", question, value, size);

            if(strcmp(question, variable) == 0)
            {
                if(debuglvl >= HIGH)
                    (void)vrprint.debug(__FUNC__, "question '%s' matched, value: '%s'", question, value);

                if(strlcpy(answer_ptr, value, size) >= size)
                {
                    (void)vrprint.error(-1, "Error", "value for question '%s' too big (in: %s:%d).",
                            question,
                            __FUNC__, __LINE__);
                    retval = -1;
                }
                else
                {
                    retval = 1;
                }

                break;
            }
        }
    }

    if(fclose(fp) == -1)
    {
        (void)vrprint.error(-1, "Error", "closing file '%s' failed: %s.", file_location, strerror(errno));
        retval = -1;
    }

    return(retval);
}

/*  write_configfile

    Writes the config to disk.
*/
int
write_configfile(const int debuglvl, char *file_location)
{
    FILE *fp = NULL;

    /* safety */
    if(file_location == NULL)
    {
        (void)vrprint.error(-1, "Internal Error", "parameter problem (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    /* open for over-writing */
    if(!(fp = fopen(file_location, "w+")))
    {
        (void)vrprint.error(-1, "Error", "unable to open configfile '%s' for writing: %s (in: %s:%d).",
                file_location,
                strerror(errno),
                __FUNC__, __LINE__);
        return(-1);
    }

    /* start writing the config to the file */
    fprintf(fp, "# vuurmuur config file\n\n");

    fprintf(fp, "# Which plugin to use for which type of data.\n");
    fprintf(fp, "SERVICES_BACKEND=\"%s\"\n\n", conf.serv_backend_name);
    fprintf(fp, "ZONES_BACKEND=\"%s\"\n\n", conf.zone_backend_name);
    fprintf(fp, "INTERFACES_BACKEND=\"%s\"\n\n", conf.ifac_backend_name);
    fprintf(fp, "RULES_BACKEND=\"%s\"\n\n", conf.rule_backend_name);

    fprintf(fp, "# Location of the rulesfile (full path).\n");
    fprintf(fp, "RULESFILE=\"%s\"\n\n", conf.rules_location);
    fprintf(fp, "# Location of the blocklistfile (full path).\n");
    fprintf(fp, "BLOCKLISTFILE=\"%s\"\n\n", conf.blocklist_location);

    fprintf(fp, "# Location of the iptables-command (full path).\n");
    fprintf(fp, "IPTABLES=\"%s\"\n\n", conf.iptables_location);
    fprintf(fp, "# Location of the iptables-restore-command (full path).\n");
    fprintf(fp, "IPTABLES_RESTORE=\"%s\"\n\n", conf.iptablesrestore_location);
    fprintf(fp, "# Location of the conntrack-command (full path).\n");
    fprintf(fp, "CONNTRACK=\"%s\"\n\n", conf.conntrack_location);
    fprintf(fp, "# Location of the tc-command (full path).\n");
    fprintf(fp, "TC=\"%s\"\n\n", conf.tc_location);

    fprintf(fp, "# Location of the modprobe-command (full path).\n");
    fprintf(fp, "MODPROBE=\"%s\"\n\n", conf.modprobe_location);

    fprintf(fp, "# Load modules if needed? (yes/no)\n");
    fprintf(fp, "LOAD_MODULES=\"%s\"\n\n", conf.load_modules ? "Yes" : "No");
    fprintf(fp, "# Wait after loading a module in 1/10th of a second\n");
    fprintf(fp, "MODULES_WAIT_TIME=\"%u\"\n\n", conf.modules_wait_time);

    fprintf(fp, "# If set to yes, each rule will be loaded into the system individually using\n");
    fprintf(fp, "# iptables. Otherwise iptables-restore will be used (yes/no).\n");
    fprintf(fp, "OLD_CREATE_METHOD=\"%s\"\n\n", conf.old_rulecreation_method ? "Yes" : "No");

    fprintf(fp, "# The directory where the logs will be written to (full path).\n");
    fprintf(fp, "LOGDIR=\"%s\"\n\n", conf.vuurmuur_logdir_location);
    fprintf(fp, "# The logfile where the kernel writes the logs to e.g. /var/log/messages (full path).\n");
    fprintf(fp, "SYSTEMLOG=\"%s\"\n\n", conf.systemlog_location);
    fprintf(fp, "# The loglevel to use when logging traffic. For use with syslog.\n");
    fprintf(fp, "LOGLEVEL=\"%s\"\n\n", conf.loglevel);

    fprintf(fp, "# Check the dynamic interfaces for changes?\n");
    fprintf(fp, "DYN_INT_CHECK=\"%s\"\n\n", conf.dynamic_changes_check ? "Yes" : "No");
    fprintf(fp, "# Check every x seconds.\n");
    fprintf(fp, "DYN_INT_INTERVAL=\"%u\"\n\n", conf.dynamic_changes_interval);

    fprintf(fp, "# LOG_POLICY controls the logging of the default policy.\n");
    fprintf(fp, "LOG_POLICY=\"%s\"\n\n", conf.log_policy ? "Yes" : "No");
    fprintf(fp, "# LOG_POLICY_LIMIT sets the maximum number of logs per second.\n");
    fprintf(fp, "LOG_POLICY_LIMIT=\"%u\"\n\n", conf.log_policy_limit);
    fprintf(fp, "# LOG_BLOCKLIST enables/disables logging of items on the blocklist.\n");
    fprintf(fp, "LOG_BLOCKLIST=\"%s\"\n\n", conf.log_blocklist ? "Yes" : "No");

    fprintf(fp, "# LOG_INVALID enables/disables logging of INVALID traffic.\n");
    fprintf(fp, "LOG_INVALID=\"%s\"\n\n", conf.log_invalid ? "Yes" : "No");
    fprintf(fp, "# LOG_NO_SYN enables/disables logging of new tcp packets without the SIN flag set.\n");
    fprintf(fp, "LOG_NO_SYN=\"%s\"\n\n", conf.log_no_syn ? "Yes" : "No");
    fprintf(fp, "# LOG_PROBES enables/disables logging of probes. Probes are packets that are used in portscans.\n");
    fprintf(fp, "LOG_PROBES=\"%s\"\n\n", conf.log_probes ? "Yes" : "No");
    fprintf(fp, "# LOG_FRAG enables/disables logging of fragmented packets.\n");
    fprintf(fp, "LOG_FRAG=\"%s\"\n\n", conf.log_frag ? "Yes" : "No");

    fprintf(fp, "# LOG_TCP_OPTIONS controls the logging of tcp options. This is.\n");
    fprintf(fp, "# not used by Vuurmuur itself. PSAD 1.4.x uses it for OS-detection.\n");
    fprintf(fp, "LOG_TCP_OPTIONS=\"%s\"\n\n", conf.log_tcp_options ? "Yes" : "No");

    fprintf(fp, "# SYN_LIMIT sets the maximum number of SYN-packets per second.\n");
    fprintf(fp, "USE_SYN_LIMIT=\"%s\"\n\n", conf.use_syn_limit ? "Yes" : "No");
    fprintf(fp, "SYN_LIMIT=\"%u\"\n", conf.syn_limit);
    fprintf(fp, "SYN_LIMIT_BURST=\"%u\"\n\n", conf.syn_limit_burst);

    fprintf(fp, "# UDP_LIMIT sets the maximum number of udp 'connections' per second.\n");
    fprintf(fp, "USE_UDP_LIMIT=\"%s\"\n\n", conf.use_udp_limit ? "Yes" : "No");
    fprintf(fp, "UDP_LIMIT=\"%u\"\n", conf.udp_limit);
    fprintf(fp, "UDP_LIMIT_BURST=\"%u\"\n\n", conf.udp_limit_burst);

    /* protect */
    fprintf(fp, "# Protect against syn-flooding? (yes/no)\n");
    fprintf(fp, "PROTECT_SYNCOOKIE=\"%s\"\n", conf.protect_syncookie ? "Yes" : "No");

    fprintf(fp, "# Ignore echo-broadcasts? (yes/no)\n");
    fprintf(fp, "PROTECT_ECHOBROADCAST=\"%s\"\n\n", conf.protect_echobroadcast ? "Yes" : "No");

    fprintf(fp, "# end of file\n");

    /* flush buffer */
    (void)fflush(fp);
    /* close file */
    if(fclose(fp) == -1)
    {
        (void)vrprint.error(-1, "Error", "closing '%s' failed: %s.", file_location, strerror(errno));
        return(-1);
    }

    (void)vrprint.info("Info", "Rewritten config file.");
    return(0);
}


/* Emulates glibc's strndup() */
static char *
br_strndup(char *str, size_t size)
{
    char    *result = (char *) NULL;
    size_t  len = 0;

    if(str == NULL)
    {
//TODO
        return(NULL);
    }

    len = strlen (str);
    if(len == 0)
        return(strdup(""));

    if(size > len)
        size = len;

    result = (char *)calloc(sizeof (char), len + 1);
    if(result == NULL)
    {
//TODO
        return(NULL);
    }
    memcpy (result, str, size);

    return(result);
}


/**
 * br_extract_prefix:
 * path: The full path of an executable or library.
 * Returns: The prefix, or NULL on error. This string should be freed when no longer needed.
 *
 * Extracts the prefix from path. This function assumes that your executable
 * or library is installed in an LSB-compatible directory structure.
 *
 * Example:
 * br_extract_prefix ("/usr/bin/gnome-panel");       --> Returns "/usr"
 * br_extract_prefix ("/usr/local/lib/libfoo.so");   --> Returns "/usr/local"
 * br_extract_prefix ("/usr/local/libfoo.so");       --> Returns "/usr"
 */
char *
br_extract_prefix (const char *path)
{
    char    *end = NULL,
            *tmp = NULL,
            *result = NULL;

    if(path == NULL)
    {
//TODO
        return(NULL);
    }

    if(!*path)
        return(strdup("/"));

    end = strrchr(path, '/');
    if(end == NULL)
        return(strdup(path));

    tmp = br_strndup((char *)path, (size_t)(end - path));
    if(!*tmp)
    {
        free(tmp);
        return(strdup("/"));
    }
    end = strrchr(tmp, '/');
    if(!end)
        return(tmp);

    result = br_strndup(tmp, (size_t)(end - tmp));
    free(tmp);

    if(!*result)
    {
        free(result);
        result = strdup("/");
    }

    return(result);
}


int
pre_init_config(struct vuurmuur_config *cnf)
{
#ifdef BINRELOC_ENABLED
    char            *exe = NULL;
    BrFindExeError  err = 0;
#endif  /* BINRELOC_ENABLED */

    /* safety */
    if(cnf == NULL)
    {
        (void)vrprint.error(-1, "Internal Error", "parameter problem (in: %s:%d).",
                __FUNC__, __LINE__);
        return(-1);
    }

    /* init the struct */
    memset(cnf, 0, sizeof(struct vuurmuur_config));

    /* set the configdir location */
#ifndef BINRELOC_ENABLED
    if(strlcpy(cnf->etcdir, xstr(SYSCONFDIR), sizeof(cnf->etcdir)) >= sizeof(cnf->etcdir))
    {
        (void)vrprint.error(-1, "Error", "buffer too small for config-dir supplied at compile-time (in: %s:%d).",
                __FUNC__, __LINE__);
        return(-1);
    }
#else
    exe = br_find_exe(&err);
    if(exe == NULL)
    {
        (void)vrprint.error(-1, "Internal Error", "br_find_exe() failed (in: %s:%d).",
                __FUNC__, __LINE__);
        return(-1);
    }
    //printf("exe %s\n", exe);

    cnf->prefix = br_extract_prefix(exe);
    if(cnf->prefix == NULL)
    {
        (void)vrprint.error(-1, "Internal Error", "br_extract_prefix() failed (in: %s:%d).",
                __FUNC__, __LINE__);
        return(-1);
    }
    //printf("prefix %s\n", prefix);

    /* we have prefix now, so exe can go */
    free(exe);
    exe = NULL;

    /* is the prefix is /usr, we use /etc instead of /usr/etc */
    if(strcmp(cnf->prefix, "/usr") == 0 || strcmp(cnf->prefix, "/usr/") == 0)
    {
        strlcpy(cnf->etcdir, "/etc", sizeof(cnf->etcdir));
    }
    else
    {
        if(snprintf(cnf->etcdir, sizeof(cnf->etcdir), "%s/etc", cnf->prefix) >= sizeof(cnf->etcdir))
        {
            (void)vrprint.error(-1, "Error", "buffer too small for config-dir supplied at compile-time (in: %s:%d).",
                    __FUNC__, __LINE__);
            return(-1);
        }
    }
#endif  /* BINRELOC_ENABLED */
    //printf("cnf->etcdir %s\n", cnf->etcdir);

    if(snprintf(cnf->configfile, sizeof(cnf->configfile), "%s/vuurmuur/config.conf", cnf->etcdir) >= (int)sizeof(cnf->configfile))
    {
        (void)vrprint.error(-1, "Error", "buffer too small for configfile supplied at compile-time (in: %s:%d).",
                __FUNC__, __LINE__);
        return(-1);
    }
    //printf("cnf->configfile %s\n", cnf->configfile);


    /* set the plugin location */
#ifndef BINRELOC_ENABLED
    if(strlcpy(cnf->plugdir, xstr(PLUGINDIR), sizeof(cnf->plugdir)) >= sizeof(cnf->plugdir))
#else
    if(snprintf(cnf->plugdir, sizeof(cnf->plugdir), "%s/lib/vuurmuur", cnf->prefix) >= sizeof(cnf->plugdir))
#endif  /* BINRELOC_ENABLED */
    {
        (void)vrprint.error(-1, "Error", "buffer too small for plugdir supplied at compile-time (in: %s:%d).",
                __FUNC__, __LINE__);
        return(-1);
    }
    //printf("cnf->libdir %s\n", cnf->libdir);


    /* set the datadir location */
#ifndef BINRELOC_ENABLED
    if(strlcpy(cnf->datadir, xstr(DATADIR), sizeof(cnf->datadir)) >= sizeof(cnf->datadir))
#else
    if(snprintf(cnf->datadir, sizeof(cnf->datadir), "%s/share/vuurmuur", cnf->prefix) >= sizeof(cnf->datadir))
#endif  /* BINRELOC_ENABLED */
    {
        (void)vrprint.error(-1, "Error", "buffer too small for sysconfdir supplied at compile-time (in: %s:%d).",
                __FUNC__, __LINE__);
        return(-1);
    }

    /* default to yes */
    cnf->check_iptcaps = TRUE;

    return(0);
}
