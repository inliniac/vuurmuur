/***************************************************************************
 *   Copyright (C) 2002-2019 by Victor Julien                              *
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

#include "config.h"
#include "vuurmuur.h"

static int check_logfile(const char *logloc)
{
    int fd;

    assert(logloc);

    if ((fd = open(logloc, O_RDONLY)) == -1) {
        /* logfile does not yet exist, try to create it. */
        if ((fd = open(logloc, O_WRONLY | O_CREAT | O_EXCL, 0600)) == -1) {
            vrmr_error(-1, "Error", "creating of logfile '%s' failed: %s",
                    logloc, strerror(errno));
            return (-1);
        }
        if (close(fd) == -1) {
            vrmr_error(-1, "Error", "closing of logfile '%s' failed: %s",
                    logloc, strerror(errno));
            return (-1);
        }
    } else {
        if (close(fd) == -1) {
            vrmr_error(-1, "Error", "closing of logfile '%s' failed: %s",
                    logloc, strerror(errno));
            return (-1);
        }
    }

    vrmr_debug(MEDIUM, "logfile '%s' ok.", logloc);

    return (0);
}

/*  vrmr_config_check_logdir

    Check the log directory, and creates it if it doesn't exist

    returncodes:
         0: ok
        -1: error
*/
int vrmr_config_check_logdir(const char *logdir)
{
    DIR *dir_p = NULL;

    /* safetly */
    assert(logdir);

    /* try to open */
    if (!(dir_p = opendir(logdir))) {
        if (errno == ENOENT) {
            if (mkdir(logdir, 0700) < 0) {
                vrmr_error(-1, "Error",
                        "creating log directory '%s' failed: %s.", logdir,
                        strerror(errno));
                return (-1);
            }

            vrmr_debug(MEDIUM, "logdir '%s' created.", logdir);
        } else {
            vrmr_error(-1, "Error", "opening log directory '%s' failed: %s.",
                    logdir, strerror(errno));
            return (-1);
        }
    } else {
        if ((closedir(dir_p)) == -1) {
            vrmr_error(-1, "Error", "closing '%s' failed: %s.", logdir,
                    strerror(errno));
            return (-1);
        }
    }

    vrmr_debug(MEDIUM, "logdir '%s' ok.", logdir);

    return (0);
}

/* difference with vrmr_config_check_logdir:
   this functions uses vuurmuur_opendir which repairs permissions if needed.
*/
int vrmr_config_check_vuurmuurdir(
        const struct vrmr_config *cnf, const char *logdir)
{
    DIR *dir_p = NULL;

    assert(logdir);

    /* this isn't the right approach _at all_ but I don't really know how to do
     * it better */
    if (strcmp(logdir, "/bin") == 0 || strcmp(logdir, "/boot") == 0 ||
            strcmp(logdir, "/dev") == 0 || strcmp(logdir, "/etc") == 0 ||
            strcmp(logdir, "/home") == 0 || strcmp(logdir, "/lib") == 0 ||
            strcmp(logdir, "/mnt") == 0 || strcmp(logdir, "/opt") == 0 ||
            strcmp(logdir, "/proc") == 0 || strcmp(logdir, "/root") == 0 ||
            strcmp(logdir, "/sbin") == 0 || strcmp(logdir, "/sys") == 0 ||
            strcmp(logdir, "/tmp") == 0 ||

            strcmp(logdir, "/usr") == 0 || strcmp(logdir, "/usr/local") == 0 ||
            strcmp(logdir, "/usr/share") == 0 ||
            strcmp(logdir, "/usr/lib") == 0 ||
            strcmp(logdir, "/usr/bin") == 0 ||
            strcmp(logdir, "/usr/sbin") == 0 ||

            strcmp(logdir, "/var") == 0 || strcmp(logdir, "/var/log") == 0 ||

            strcmp(logdir, "/") == 0) {
        vrmr_error(-1, "Error",
                "directory '%s' is on my blacklist. Please select another.",
                logdir);
        return (-1);
    }

    /* try to open, error reporting is done by others */
    if (!(dir_p = vuurmuur_opendir(cnf, logdir))) {
        return (-1);
    }
    if ((closedir(dir_p)) == -1) {
        vrmr_error(-1, "Error", "closing '%s' failed: %s.", logdir,
                strerror(errno));
        return (-1);
    }

    vrmr_debug(MEDIUM, "logdir '%s' ok.", logdir);
    return (0);
}

/*
 */
int vrmr_check_iptables_command(
        struct vrmr_config *cnf, char *iptables_location, char quiet)
{
    assert(cnf && iptables_location);

    /* first check if there even is a value */
    if (strcmp(iptables_location, "") == 0) {
        if (quiet == VRMR_IPTCHK_VERBOSE)
            vrmr_error(0, "Error",
                    "The path to the 'iptables'-command was not set");
        return (0);
    } else {
        /* now check the command */
        const char *args[] = {iptables_location, "--version", NULL};
        int r = libvuurmuur_exec_command(cnf, iptables_location, args, NULL);
        if (r != 0) {
            if (quiet == VRMR_IPTCHK_VERBOSE)
                vrmr_error(0, "Error",
                        "The path '%s' to the 'iptables'-command seems to be "
                        "wrong.",
                        iptables_location);
            return (0);
        }
    }
    return (1);
}

/*
 */
int vrmr_check_iptablesrestore_command(
        struct vrmr_config *cnf, char *iptablesrestore_location, char quiet)
{
    assert(cnf && iptablesrestore_location);

    /* first check if there even is a value */
    if (strcmp(iptablesrestore_location, "") == 0) {
        if (quiet == VRMR_IPTCHK_VERBOSE)
            vrmr_error(0, "Error",
                    "The path to the 'iptables-restore'-command was not set");
        return (0);
    } else {
        /* now check the command */
        const char *args[] = {iptablesrestore_location, "-h", NULL};
        int r = libvuurmuur_exec_command(
                cnf, iptablesrestore_location, args, NULL);
        if (r != 0 && r != 1) {
            if (quiet == VRMR_IPTCHK_VERBOSE)
                vrmr_error(0, "Error",
                        "The path '%s' to the 'iptables-restore'-command seems "
                        "to be wrong.",
                        iptablesrestore_location);
            return (0);
        }
    }
    return (1);
}

/**
 \param[in] cnf
 \param[in] ip6tables_location A pointer to the buffer that contains the
    location of the ip6tables command
 \param[in] quiet Should we print errors (TRUE) or not (FALSE)?
 \retval -1 When there is a problem with the given arguments
 \retval 0 The location was not valid (or not filled)
 \retval 1 The location seems to be correct
*/
int vrmr_check_ip6tables_command(
        struct vrmr_config *cnf, char *ip6tables_location, char quiet)
{
    assert(cnf && ip6tables_location);

    /* first check if there even is a value */
    if (strcmp(ip6tables_location, "") == 0) {
        if (quiet == FALSE)
            vrmr_error(0, "Error",
                    "The path to the 'ip6tables'-command was not set");
        return (0);
    } else {
        /* now check the command */
        const char *args[] = {ip6tables_location, "--version", NULL};
        int r = libvuurmuur_exec_command(cnf, ip6tables_location, args, NULL);
        if (r != 0) {
            if (quiet == FALSE)
                vrmr_error(0, "Error",
                        "The path '%s' to the 'ip6tables'-command seems to be "
                        "wrong",
                        ip6tables_location);
            return (0);
        }
    }
    return (1);
}

int vrmr_check_ip6tablesrestore_command(
        struct vrmr_config *cnf, char *ip6tablesrestore_location, char quiet)
{
    assert(cnf && ip6tablesrestore_location);

    /* first check if there even is a value */
    if (strcmp(ip6tablesrestore_location, "") == 0) {
        if (quiet == FALSE)
            vrmr_error(0, "Error",
                    "The path to the 'ip6tables-restore'-command was not set");
        return (0);
    } else {
        /* now check the command */
        const char *args[] = {ip6tablesrestore_location, "-h", NULL};
        int r = libvuurmuur_exec_command(
                cnf, ip6tablesrestore_location, args, NULL);
        if (r != 0 && r != 1) {
            if (quiet == FALSE)
                vrmr_error(0, "Error",
                        "The path '%s' to the 'ip6tables-restore'-command "
                        "seems to be wrong.",
                        ip6tablesrestore_location);
            return (0);
        }
    }
    return (1);
}

/*
 */
int vrmr_check_tc_command(
        struct vrmr_config *cnf, char *tc_location, char quiet)
{
    assert(cnf && tc_location);

    /* first check if there even is a value */
    if (strcmp(tc_location, "") == 0) {
        if (quiet == VRMR_IPTCHK_VERBOSE)
            vrmr_error(0, "Error", "The path to the 'tc'-command was not set");
        return (0);
    } else {
        const char *args[] = {tc_location, "-V", NULL};
        int r = libvuurmuur_exec_command(cnf, tc_location, args, NULL);
        if (r != 0) {
            if (quiet == VRMR_IPTCHK_VERBOSE)
                vrmr_error(0, "Error",
                        "The path '%s' to the 'tc'-command seems to be wrong.",
                        tc_location);
            return (0);
        }
    }
    return (1);
}

/* updates the logdirlocations in the cnf struct based on cnf->vuurmuur_log_dir,
 * also updates vrprint. */
int vrmr_config_set_log_names(struct vrmr_config *cnf)
{
    int retval = 0;

    assert(cnf);

    if (snprintf(cnf->vuurmuurlog_location, sizeof(cnf->vuurmuurlog_location),
                "%s/vuurmuur.log", cnf->vuurmuur_logdir_location) >=
            (int)sizeof(cnf->vuurmuurlog_location)) {
        vrmr_error(-1, "Error", "vuurmuur.log location was truncated");
        retval = -1;
    }
    strlcpy(vrprint.infolog, cnf->vuurmuurlog_location,
            sizeof(vrprint.infolog));

    if (snprintf(cnf->trafficlog_location, sizeof(cnf->trafficlog_location),
                "%s/traffic.log", cnf->vuurmuur_logdir_location) >=
            (int)sizeof(cnf->trafficlog_location)) {
        vrmr_error(-1, "Error", "traffic.log location was truncated");
        retval = -1;
    }

    if (snprintf(cnf->connnewlog_location, sizeof(cnf->connnewlog_location),
                "%s/connnew.log", cnf->vuurmuur_logdir_location) >=
            (int)sizeof(cnf->connnewlog_location)) {
        vrmr_error(-1, "Error", "connnew.log location was truncated");
        retval = -1;
    }

    if (snprintf(cnf->connlog_location, sizeof(cnf->connlog_location),
                "%s/connections.log", cnf->vuurmuur_logdir_location) >=
            (int)sizeof(cnf->connlog_location)) {
        vrmr_error(-1, "Error", "connections.log location was truncated");
        retval = -1;
    }

    if (snprintf(cnf->debuglog_location, sizeof(cnf->debuglog_location),
                "%s/debug.log", cnf->vuurmuur_logdir_location) >=
            (int)sizeof(cnf->debuglog_location)) {
        vrmr_error(-1, "Error", "debug.log location was truncated");
        retval = -1;
    }
    strlcpy(vrprint.debuglog, cnf->debuglog_location, sizeof(vrprint.debuglog));

    if (snprintf(cnf->errorlog_location, sizeof(cnf->errorlog_location),
                "%s/error.log", cnf->vuurmuur_logdir_location) >=
            (int)sizeof(cnf->errorlog_location)) {
        vrmr_error(-1, "Error", "error.log location was truncated");
        retval = -1;
    }
    strlcpy(vrprint.errorlog, cnf->errorlog_location, sizeof(vrprint.errorlog));

    if (snprintf(cnf->auditlog_location, sizeof(cnf->auditlog_location),
                "%s/audit.log", cnf->vuurmuur_logdir_location) >=
            (int)sizeof(cnf->auditlog_location)) {
        vrmr_error(-1, "Error", "audit.log location was truncated");
        retval = -1;
    }
    strlcpy(vrprint.auditlog, cnf->auditlog_location, sizeof(vrprint.auditlog));

    return (retval);
}

/**
 \param[in,out] cnf A pointer to the #vuurmuur_config structure that will be
    filled with extra information from the config files

 \note we cannot use vrprint.debug and vrprint.info in this, because in most
    cases we want those function to print to the log, however the log locations
    are only known after this function! (unless cnf->verbose_out == 1)
*/
int vrmr_init_config(struct vrmr_config *cnf)
{
    int retval = VRMR_CNF_OK, result = 0;
    char answer[32] = "";
    FILE *fp = NULL;
    int debug_level = 0;

    assert(cnf);

    /* only print debug if we are in verbose mode, since at this moment debug
       still goes to the stdout, because we have yet to initialize our logs */
    debug_level = vrmr_debug_level * (int)cnf->verbose_out;

    vrmr_debug(LOW, "etc-dir: '%s/vuurmuur', config-file: '%s'.", cnf->etcdir,
            cnf->configfile);

    /* check the file */
    if (!(fp = fopen(cnf->configfile, "r"))) {
        vrmr_error(-1, "Error", "could not open configfile '%s': %s",
                cnf->configfile, strerror(errno));
        if (errno == ENOENT)
            return (VRMR_CNF_E_FILE_MISSING);
        else if (errno == EACCES)
            return (VRMR_CNF_E_FILE_PERMISSION);
        else
            return (VRMR_CNF_E_UNKNOWN_ERR);
    }
    fclose(fp);

    /* MAX_PERMISSION
     * First (even before calling vrmr_stat_ok to check the config file),
     * load the MAX_PERMISSION value. init_pre_config sets max_permission to
     * VRMR_ANY_PERMISSION, so no permission checks occur before here.
     */
    result = vrmr_ask_configfile(
            cnf, "MAX_PERMISSION", answer, cnf->configfile, sizeof(answer));
    if (result == 1) {
        char *endptr;
        /* ok, found, parse it as an octal mode */
        cnf->max_permission = strtol(answer, &endptr, 8);

        /* If strtol fails, it will set endptr to answer. Also check that
         * there was no trailing garbage at the end of the string. */
        if (endptr == answer || *endptr != '\0') {
            vrmr_warning("Warning",
                    "Invalid MAX_PERMISSION setting: %s. It should be an octal "
                    "permission number. Using default (%o).",
                    answer, VRMR_DEFAULT_MAX_PERMISSION);
            cnf->max_permission = VRMR_DEFAULT_MAX_PERMISSION;

            retval = VRMR_CNF_W_ILLEGAL_VAR;
        }
    } else if (result == 0) {
        /* ignore missing, use default */
        cnf->max_permission = VRMR_DEFAULT_MAX_PERMISSION;
    } else
        return (VRMR_CNF_E_UNKNOWN_ERR);

    /* Now that we know the maximum permission a config file can have,
     * check if we like the configfile */
    if (!(vrmr_stat_ok(cnf, cnf->configfile, VRMR_STATOK_WANT_FILE,
                VRMR_STATOK_VERBOSE, VRMR_STATOK_MUST_EXIST)))
        return (VRMR_CNF_E_FILE_PERMISSION);

    result =
            vrmr_ask_configfile(cnf, "SERVICES_BACKEND", cnf->serv_backend_name,
                    cnf->configfile, sizeof(cnf->serv_backend_name));
    if (result == 1) {
        /* ok */
        if (cnf->serv_backend_name[0] == '\0') {
            retval = VRMR_CNF_E_MISSING_VAR;
        }
    } else if (result == 0) {
        if (strlcpy(cnf->serv_backend_name, VRMR_DEFAULT_BACKEND,
                    sizeof(cnf->serv_backend_name)) >=
                sizeof(cnf->serv_backend_name)) {
            vrmr_error(VRMR_CNF_E_UNKNOWN_ERR, "Internal Error",
                    "string overflow");
            return (VRMR_CNF_E_UNKNOWN_ERR);
        }

        vrmr_warning("Warning",
                "Variable SERVICES_BACKEND not found in '%s'. Using default "
                "(%s).",
                cnf->configfile, VRMR_DEFAULT_BACKEND);
    } else
        return (VRMR_CNF_E_UNKNOWN_ERR);

    result = vrmr_ask_configfile(cnf, "ZONES_BACKEND", cnf->zone_backend_name,
            cnf->configfile, sizeof(cnf->zone_backend_name));
    if (result == 1) {
        /* ok */
        if (cnf->zone_backend_name[0] == '\0') {
            retval = VRMR_CNF_E_MISSING_VAR;
        }
    } else if (result == 0) {
        if (strlcpy(cnf->zone_backend_name, VRMR_DEFAULT_BACKEND,
                    sizeof(cnf->zone_backend_name)) >=
                sizeof(cnf->zone_backend_name)) {
            vrmr_error(VRMR_CNF_E_UNKNOWN_ERR, "Internal Error",
                    "string overflow");
            return (VRMR_CNF_E_UNKNOWN_ERR);
        }

        vrmr_warning("Warning",
                "Variable ZONES_BACKEND not found in '%s'. Using default (%s).",
                cnf->configfile, VRMR_DEFAULT_BACKEND);
    } else
        return (VRMR_CNF_E_UNKNOWN_ERR);

    result = vrmr_ask_configfile(cnf, "INTERFACES_BACKEND",
            cnf->ifac_backend_name, cnf->configfile,
            sizeof(cnf->ifac_backend_name));
    if (result == 1) {
        /* ok */
        if (cnf->ifac_backend_name[0] == '\0') {
            retval = VRMR_CNF_E_MISSING_VAR;
        }
    } else if (result == 0) {
        if (strlcpy(cnf->ifac_backend_name, VRMR_DEFAULT_BACKEND,
                    sizeof(cnf->ifac_backend_name)) >=
                sizeof(cnf->ifac_backend_name)) {
            vrmr_error(VRMR_CNF_E_UNKNOWN_ERR, "Internal Error",
                    "string overflow");
            return (VRMR_CNF_E_UNKNOWN_ERR);
        }

        vrmr_warning("Warning",
                "Variable INTERFACES_BACKEND not found in '%s'. Using default "
                "(%s).",
                cnf->configfile, VRMR_DEFAULT_BACKEND);
    } else
        return (VRMR_CNF_E_UNKNOWN_ERR);

    result = vrmr_ask_configfile(cnf, "RULES_BACKEND", cnf->rule_backend_name,
            cnf->configfile, sizeof(cnf->rule_backend_name));
    if (result == 1) {
        /* ok */
        if (cnf->rule_backend_name[0] == '\0') {
            retval = VRMR_CNF_E_MISSING_VAR;
        }
    } else if (result == 0) {
        if (strlcpy(cnf->rule_backend_name, VRMR_DEFAULT_BACKEND,
                    sizeof(cnf->rule_backend_name)) >=
                sizeof(cnf->rule_backend_name)) {
            vrmr_error(VRMR_CNF_E_UNKNOWN_ERR, "Internal Error",
                    "string overflow");
            return (VRMR_CNF_E_UNKNOWN_ERR);
        }

        //      vrmr_warning("Warning", "Variable RULES_BACKEND not found in
        //      '%s'. Using default (%s).",
        //              cnf->configfile, VRMR_DEFAULT_BACKEND);
    } else
        return (VRMR_CNF_E_UNKNOWN_ERR);

    /* DYN_INT_CHECK */
    result = vrmr_ask_configfile(
            cnf, "DYN_INT_CHECK", answer, cnf->configfile, sizeof(answer));
    if (result == 1) {
        /* ok, found */
        if (strcasecmp(answer, "yes") == 0) {
            cnf->dynamic_changes_check = TRUE;
        } else if (strcasecmp(answer, "no") == 0) {
            cnf->dynamic_changes_check = FALSE;
        } else {
            vrmr_warning("Warning",
                    "'%s' is not a valid value for option DYN_INT_CHECK.",
                    answer);
            cnf->dynamic_changes_check = VRMR_DEFAULT_DYN_INT_CHECK;

            retval = VRMR_CNF_W_ILLEGAL_VAR;
        }
    } else if (result == 0) {
        cnf->dynamic_changes_check = VRMR_DEFAULT_DYN_INT_CHECK;
    } else
        return (VRMR_CNF_E_UNKNOWN_ERR);

    /* LOG_POLICY_LIMIT */
    result = vrmr_ask_configfile(
            cnf, "DYN_INT_INTERVAL", answer, cnf->configfile, sizeof(answer));
    if (result == 1) {
        /* ok, found */
        result = atoi(answer);
        if (result < 0) {
            vrmr_warning("Warning",
                    "A negative DYN_INT_INTERVAL-limit (%d) can not be used, "
                    "using default (%u).",
                    result, VRMR_DEFAULT_DYN_INT_INTERVAL);
            cnf->dynamic_changes_interval = VRMR_DEFAULT_DYN_INT_INTERVAL;

            retval = VRMR_CNF_W_ILLEGAL_VAR;
        } else {
            cnf->dynamic_changes_interval = (unsigned int)result;
        }
    } else if (result == 0) {
        cnf->dynamic_changes_interval = VRMR_DEFAULT_DYN_INT_INTERVAL;
    } else
        return (VRMR_CNF_E_UNKNOWN_ERR);

    /* DROP_INVALID */
    result = vrmr_ask_configfile(
            cnf, "DROP_INVALID", answer, cnf->configfile, sizeof(answer));
    if (result == 1) {
        /* ok, found */
        if (strcasecmp(answer, "yes") == 0) {
            cnf->conntrack_invalid_drop = true;
        } else if (strcasecmp(answer, "no") == 0) {
            cnf->conntrack_invalid_drop = false;
        } else {
            vrmr_warning("Warning",
                    "'%s' is not a valid value for option DROP_INVALID.",
                    answer);
            cnf->conntrack_invalid_drop = VRMR_DEFAULT_DROP_INVALID;
            retval = VRMR_CNF_W_ILLEGAL_VAR;
        }
    } else if (result == 0) {
        /* if this is missing, we use the default */
        cnf->conntrack_invalid_drop = VRMR_DEFAULT_DROP_INVALID;
    } else
        return (VRMR_CNF_E_UNKNOWN_ERR);

    /* CONNTRACK_ACCOUNTING */
    result = vrmr_ask_configfile(cnf, "CONNTRACK_ACCOUNTING", answer,
            cnf->configfile, sizeof(answer));
    if (result == 1) {
        /* ok, found */
        if (strcasecmp(answer, "yes") == 0) {
            cnf->conntrack_accounting = true;
        } else if (strcasecmp(answer, "no") == 0) {
            cnf->conntrack_accounting = false;
        } else {
            vrmr_warning("Warning",
                    "'%s' is not a valid value for option "
                    "CONNTRACK_ACCOUNTING.",
                    answer);
            cnf->conntrack_accounting = VRMR_DEFAULT_CONNTRACK_ACCOUNTING;
            retval = VRMR_CNF_W_ILLEGAL_VAR;
        }
    } else if (result == 0) {
        /* if this is missing, we use the default */
        cnf->conntrack_accounting = VRMR_DEFAULT_CONNTRACK_ACCOUNTING;
    } else
        return (VRMR_CNF_E_UNKNOWN_ERR);

    /* LOG_BLOCKLIST */
    result = vrmr_ask_configfile(
            cnf, "LOG_BLOCKLIST", answer, cnf->configfile, sizeof(answer));
    if (result == 1) {
        /* ok, found */
        if (strcasecmp(answer, "yes") == 0) {
            cnf->log_blocklist = true;
        } else if (strcasecmp(answer, "no") == 0) {
            cnf->log_blocklist = false;
        } else {
            vrmr_warning("Warning",
                    "'%s' is not a valid value for option LOG_BLOCKLIST.",
                    answer);
            cnf->log_blocklist = VRMR_DEFAULT_LOG_BLOCKLIST;

            retval = VRMR_CNF_W_ILLEGAL_VAR;
        }
    } else if (result == 0) {
        /* if this is missing, we use the default */
        cnf->log_blocklist = VRMR_DEFAULT_LOG_BLOCKLIST;
    } else
        return (VRMR_CNF_E_UNKNOWN_ERR);

    /* LOG_INVALID */
    result = vrmr_ask_configfile(
            cnf, "LOG_INVALID", answer, cnf->configfile, sizeof(answer));
    if (result == 1) {
        /* ok, found */
        if (strcasecmp(answer, "yes") == 0) {
            cnf->log_invalid = TRUE;
        } else if (strcasecmp(answer, "no") == 0) {
            cnf->log_invalid = FALSE;
        } else {
            vrmr_warning("Warning",
                    "'%s' is not a valid value for option LOG_INVALID.",
                    answer);
            cnf->log_invalid = VRMR_DEFAULT_LOG_INVALID;

            retval = VRMR_CNF_W_ILLEGAL_VAR;
        }
    } else if (result == 0) {
        /* if this is missing, we use the default */
        cnf->log_invalid = VRMR_DEFAULT_LOG_INVALID;
    } else
        return (VRMR_CNF_E_UNKNOWN_ERR);

    /* LOG_NO_SYN */
    result = vrmr_ask_configfile(
            cnf, "LOG_NO_SYN", answer, cnf->configfile, sizeof(answer));
    if (result == 1) {
        /* ok, found */
        if (strcasecmp(answer, "yes") == 0) {
            cnf->log_no_syn = TRUE;
        } else if (strcasecmp(answer, "no") == 0) {
            cnf->log_no_syn = FALSE;
        } else {
            vrmr_warning("Warning",
                    "'%s' is not a valid value for option LOG_NO_SYN.", answer);
            cnf->log_no_syn = VRMR_DEFAULT_LOG_NO_SYN;

            retval = VRMR_CNF_W_ILLEGAL_VAR;
        }
    } else if (result == 0) {
        /* if this is missing, we use the default */
        cnf->log_no_syn = VRMR_DEFAULT_LOG_NO_SYN;
    } else
        return (VRMR_CNF_E_UNKNOWN_ERR);

    /* LOG_PROBES */
    result = vrmr_ask_configfile(
            cnf, "LOG_PROBES", answer, cnf->configfile, sizeof(answer));
    if (result == 1) {
        /* ok, found */
        if (strcasecmp(answer, "yes") == 0) {
            cnf->log_probes = TRUE;
        } else if (strcasecmp(answer, "no") == 0) {
            cnf->log_probes = FALSE;
        } else {
            vrmr_warning("Warning",
                    "'%s' is not a valid value for option LOG_PROBES.", answer);
            cnf->log_probes = VRMR_DEFAULT_LOG_PROBES;

            retval = VRMR_CNF_W_ILLEGAL_VAR;
        }
    } else if (result == 0) {
        /* if this is missing, we use the default */
        cnf->log_probes = VRMR_DEFAULT_LOG_PROBES;
    } else
        return (VRMR_CNF_E_UNKNOWN_ERR);

    /* LOG_FRAG */
    result = vrmr_ask_configfile(
            cnf, "LOG_FRAG", answer, cnf->configfile, sizeof(answer));
    if (result == 1) {
        /* ok, found */
        if (strcasecmp(answer, "yes") == 0) {
            cnf->log_frag = TRUE;
        } else if (strcasecmp(answer, "no") == 0) {
            cnf->log_frag = FALSE;
        } else {
            vrmr_warning("Warning",
                    "'%s' is not a valid value for option LOG_FRAG.", answer);
            cnf->log_frag = VRMR_DEFAULT_LOG_FRAG;

            retval = VRMR_CNF_W_ILLEGAL_VAR;
        }
    } else if (result == 0) {
        /* if this is missing, we use the default */
        cnf->log_frag = VRMR_DEFAULT_LOG_FRAG;
    } else
        return (VRMR_CNF_E_UNKNOWN_ERR);

    /* USE_SYN_LIMIT */
    result = vrmr_ask_configfile(
            cnf, "USE_SYN_LIMIT", answer, cnf->configfile, sizeof(answer));
    if (result == 1) {
        /* ok, found */
        if (strcasecmp(answer, "yes") == 0) {
            cnf->use_syn_limit = true;
        } else if (strcasecmp(answer, "no") == 0) {
            cnf->use_syn_limit = false;
        } else {
            vrmr_warning("Warning",
                    "'%s' is not a valid value for option USE_SYN_LIMIT.",
                    answer);
            cnf->use_syn_limit = VRMR_DEFAULT_USE_SYN_LIMIT;

            retval = VRMR_CNF_W_ILLEGAL_VAR;
        }
    } else if (result == 0) {
        /* if this is missing, we use the default */
        cnf->use_syn_limit = VRMR_DEFAULT_USE_SYN_LIMIT;
    } else
        return (VRMR_CNF_E_UNKNOWN_ERR);

    /* SYN_LIMIT */
    result = vrmr_ask_configfile(
            cnf, "SYN_LIMIT", answer, cnf->configfile, sizeof(answer));
    if (result == 1) {
        /* ok, found */
        result = atoi(answer);
        if (result < 0) {
            vrmr_warning("Warning",
                    "A negative SYN-limit (%d) can not be used, using default "
                    "(%u).",
                    result, VRMR_DEFAULT_SYN_LIMIT);
            cnf->syn_limit = VRMR_DEFAULT_SYN_LIMIT;

            retval = VRMR_CNF_W_ILLEGAL_VAR;
        } else if (result == 0) {
            vrmr_warning("Warning",
                    "A SYN-limit of 0 can not be used, using default (%u).",
                    VRMR_DEFAULT_SYN_LIMIT);
            cnf->syn_limit = VRMR_DEFAULT_SYN_LIMIT;

            retval = VRMR_CNF_W_ILLEGAL_VAR;
        } else {
            cnf->syn_limit = (unsigned int)result;
        }
    } else if (result == 0) {
        vrmr_warning("Warning",
                "Variable SYN_LIMIT not found in '%s'. Using default.",
                cnf->configfile);
        cnf->syn_limit = VRMR_DEFAULT_SYN_LIMIT;

        retval = VRMR_CNF_W_MISSING_VAR;
    } else
        return (VRMR_CNF_E_UNKNOWN_ERR);

    /* SYN_LIMIT_BURST */
    result = vrmr_ask_configfile(
            cnf, "SYN_LIMIT_BURST", answer, cnf->configfile, sizeof(answer));
    if (result == 1) {
        /* ok, found */
        result = atoi(answer);
        if (result < 0) {
            vrmr_warning("Warning",
                    "A negative SYN-limit-burst (%d) can not be used, using "
                    "default (%u).",
                    result, VRMR_DEFAULT_SYN_LIMIT_BURST);
            cnf->syn_limit_burst = VRMR_DEFAULT_SYN_LIMIT_BURST;

            retval = VRMR_CNF_W_ILLEGAL_VAR;
        } else if (result == 0) {
            vrmr_warning("Warning",
                    "A SYN-limit-burst of 0 can not be used, using default "
                    "(%u).",
                    VRMR_DEFAULT_SYN_LIMIT_BURST);
            cnf->syn_limit_burst = VRMR_DEFAULT_SYN_LIMIT_BURST;

            retval = VRMR_CNF_W_ILLEGAL_VAR;
        } else {
            cnf->syn_limit_burst = (unsigned int)result;
        }
    } else if (result == 0) {
        vrmr_warning("Warning",
                "Variable SYN_LIMIT_BURST not found in '%s'. Using default.",
                cnf->configfile);
        cnf->syn_limit_burst = VRMR_DEFAULT_SYN_LIMIT_BURST;

        retval = VRMR_CNF_W_MISSING_VAR;
    } else
        return (VRMR_CNF_E_UNKNOWN_ERR);

    /* USE_UDP_LIMIT */
    result = vrmr_ask_configfile(
            cnf, "USE_UDP_LIMIT", answer, cnf->configfile, sizeof(answer));
    if (result == 1) {
        /* ok, found */
        if (strcasecmp(answer, "yes") == 0) {
            cnf->use_udp_limit = true;
        } else if (strcasecmp(answer, "no") == 0) {
            cnf->use_udp_limit = false;
        } else {
            vrmr_warning("Warning",
                    "'%s' is not a valid value for option USE_UDP_LIMIT.",
                    answer);
            cnf->use_udp_limit = VRMR_DEFAULT_USE_UDP_LIMIT;

            retval = VRMR_CNF_W_ILLEGAL_VAR;
        }
    } else if (result == 0) {
        /* if this is missing, we use the default */
        cnf->use_udp_limit = VRMR_DEFAULT_USE_UDP_LIMIT;
    } else
        return (VRMR_CNF_E_UNKNOWN_ERR);

    /* UDP_LIMIT */
    result = vrmr_ask_configfile(
            cnf, "UDP_LIMIT", answer, cnf->configfile, sizeof(answer));
    if (result == 1) {
        /* ok, found */
        result = atoi(answer);
        if (result < 0) {
            vrmr_warning("Warning",
                    "A negative UDP-limit (%d) can not be used, using default "
                    "(%u).",
                    result, VRMR_DEFAULT_UDP_LIMIT);
            cnf->udp_limit = VRMR_DEFAULT_UDP_LIMIT;

            retval = VRMR_CNF_W_ILLEGAL_VAR;
        } else if (result == 0) {
            vrmr_warning("Warning",
                    "A UDP-limit of 0 can not be used, using default (%u).",
                    VRMR_DEFAULT_UDP_LIMIT);
            cnf->udp_limit = VRMR_DEFAULT_UDP_LIMIT;

            retval = VRMR_CNF_W_ILLEGAL_VAR;
        } else {
            cnf->udp_limit = (unsigned int)result;
        }
    } else if (result == 0) {
        vrmr_warning("Warning",
                "Variable UDP_LIMIT not found in '%s'. Using default.",
                cnf->configfile);
        cnf->udp_limit = VRMR_DEFAULT_UDP_LIMIT;

        retval = VRMR_CNF_W_MISSING_VAR;
    } else
        return (VRMR_CNF_E_UNKNOWN_ERR);

    /* UDP_LIMIT_BURST */
    result = vrmr_ask_configfile(
            cnf, "UDP_LIMIT_BURST", answer, cnf->configfile, sizeof(answer));
    if (result == 1) {
        /* ok, found */
        result = atoi(answer);
        if (result < 0) {
            vrmr_warning("Warning",
                    "A negative UDP-limit-burst (%d) can not be used, using "
                    "default (%u).",
                    result, VRMR_DEFAULT_UDP_LIMIT_BURST);
            cnf->udp_limit_burst = VRMR_DEFAULT_UDP_LIMIT_BURST;

            retval = VRMR_CNF_W_ILLEGAL_VAR;
        } else if (result == 0) {
            vrmr_warning("Warning",
                    "A UDP-limit-burst of 0 can not be used, using default "
                    "(%u).",
                    VRMR_DEFAULT_UDP_LIMIT_BURST);
            cnf->udp_limit_burst = VRMR_DEFAULT_UDP_LIMIT_BURST;

            retval = VRMR_CNF_W_ILLEGAL_VAR;
        } else {
            cnf->udp_limit_burst = (unsigned int)result;
        }
    } else if (result == 0) {
        vrmr_warning("Warning",
                "Variable UDP_LIMIT_BURST not found in '%s'. Using default.",
                cnf->configfile);
        cnf->udp_limit_burst = VRMR_DEFAULT_UDP_LIMIT_BURST;

        retval = VRMR_CNF_W_MISSING_VAR;
    } else
        return (VRMR_CNF_E_UNKNOWN_ERR);

    /* LOG_POLICY */
    result = vrmr_ask_configfile(
            cnf, "LOG_POLICY", answer, cnf->configfile, sizeof(answer));
    if (result == 1) {
        /* ok, found */
        if (strcasecmp(answer, "yes") == 0) {
            cnf->log_policy = TRUE;
        } else if (strcasecmp(answer, "no") == 0) {
            cnf->log_policy = FALSE;
        } else {
            vrmr_warning("Warning",
                    "'%s' is not a valid value for option LOG_POLICY.", answer);
            cnf->log_policy = VRMR_DEFAULT_LOG_POLICY;

            retval = VRMR_CNF_W_ILLEGAL_VAR;
        }
    } else if (result == 0) {
        vrmr_warning("Warning",
                "Variable LOG_POLICY not found in '%s'. Using default.",
                cnf->configfile);
        cnf->log_policy = VRMR_DEFAULT_LOG_POLICY;

        retval = VRMR_CNF_W_MISSING_VAR;
    } else
        return (VRMR_CNF_E_UNKNOWN_ERR);

    /* NFGRP */
    result = vrmr_ask_configfile(
            cnf, "NFGRP", answer, cnf->configfile, sizeof(answer));
    if (result == 1) {
        /* ok, found */
        result = atoi(answer);
        if (result < 1 || result > 999) {
            vrmr_warning("Warning",
                    "invalid NF Group (%d). Valid range is 1-999. Using "
                    "default "
                    "(%d).",
                    result, VRMR_DEFAULT_NFGRP);
            cnf->nfgrp = (uint16_t)VRMR_DEFAULT_NFGRP;

            retval = VRMR_CNF_W_ILLEGAL_VAR;
        } else {
            cnf->nfgrp = (uint16_t)result;
        }
    } else if (result == 0) {
        vrmr_warning("Warning",
                "Variable NFGRP not found in '%s'. Using default.",
                cnf->configfile);

        cnf->nfgrp = (uint16_t)VRMR_DEFAULT_NFGRP;

        retval = VRMR_CNF_W_MISSING_VAR;
    } else
        return (VRMR_CNF_E_UNKNOWN_ERR);

    /* LOG_POLICY_LIMIT */
    result = vrmr_ask_configfile(
            cnf, "LOG_POLICY_LIMIT", answer, cnf->configfile, sizeof(answer));
    if (result == 1) {
        /* ok, found */
        result = atoi(answer);
        if (result < 0) {
            vrmr_warning("Warning",
                    "A negative LOG-limit (%d) can not be used, using default "
                    "(%u).",
                    result, VRMR_DEFAULT_LOG_POLICY_LIMIT);
            cnf->log_policy_limit = VRMR_DEFAULT_LOG_POLICY_LIMIT;
            cnf->log_policy_burst = cnf->log_policy_limit * 2;

            retval = VRMR_CNF_W_ILLEGAL_VAR;
        } else {
            cnf->log_policy_limit = (unsigned int)result;
            cnf->log_policy_burst = cnf->log_policy_limit * 2;
        }
    } else if (result == 0) {
        vrmr_warning("Warning",
                "Variable LOG_POLICY_LIMIT not found in '%s'. Using default.",
                cnf->configfile);

        cnf->log_policy_limit = VRMR_DEFAULT_LOG_POLICY_LIMIT;
        cnf->log_policy_burst = cnf->log_policy_limit * 2;

        retval = VRMR_CNF_W_MISSING_VAR;
    } else
        return (VRMR_CNF_E_UNKNOWN_ERR);

    /* PROTECT_SYNCOOKIES */
    result = vrmr_ask_configfile(
            cnf, "PROTECT_SYNCOOKIE", answer, cnf->configfile, sizeof(answer));
    if (result == 1) {
        /* ok, found */
        if (strcasecmp(answer, "yes") == 0) {
            cnf->protect_syncookie = TRUE;
        } else if (strcasecmp(answer, "no") == 0) {
            cnf->protect_syncookie = FALSE;
        } else {
            vrmr_warning("Warning",
                    "'%s' is not a valid value for option PROTECT_SYNCOOKIE.",
                    answer);
            cnf->protect_syncookie = VRMR_DEFAULT_PROTECT_SYNCOOKIE;

            retval = VRMR_CNF_W_ILLEGAL_VAR;
        }
    } else if (result == 0) {
        vrmr_warning("Warning",
                "Variable PROTECT_SYNCOOKIE not found in '%s'. Using default.",
                cnf->configfile);
        cnf->protect_syncookie = VRMR_DEFAULT_PROTECT_SYNCOOKIE;

        retval = VRMR_CNF_W_MISSING_VAR;
    } else
        return (VRMR_CNF_E_UNKNOWN_ERR);

    /* PROTECT_ECHOBROADCAST */
    result = vrmr_ask_configfile(cnf, "PROTECT_ECHOBROADCAST", answer,
            cnf->configfile, sizeof(answer));
    if (result == 1) {
        /* ok, found */
        if (strcasecmp(answer, "yes") == 0) {
            cnf->protect_echobroadcast = TRUE;
        } else if (strcasecmp(answer, "no") == 0) {
            cnf->protect_echobroadcast = FALSE;
        } else {
            vrmr_warning("Warning",
                    "'%s' is not a valid value for option "
                    "PROTECT_ECHOBROADCAST.",
                    answer);
            cnf->protect_echobroadcast = VRMR_DEFAULT_PROTECT_ECHOBROADCAST;

            retval = VRMR_CNF_W_ILLEGAL_VAR;
        }
    } else if (result == 0) {
        vrmr_warning("Warning",
                "Variable PROTECT_ECHOBROADCAST not found in '%s'. Using "
                "default.",
                cnf->configfile);
        cnf->protect_echobroadcast = VRMR_DEFAULT_PROTECT_ECHOBROADCAST;

        retval = VRMR_CNF_W_MISSING_VAR;
    } else
        return (VRMR_CNF_E_UNKNOWN_ERR);

    result = vrmr_ask_configfile(cnf, "SYSCTL", cnf->sysctl_location,
            cnf->configfile, sizeof(cnf->sysctl_location));
    if (result == 1) {
        /* ok */
    } else if (result == 0) {
        vrmr_warning("Warning",
                "Variable SYSCTL not found in '%s', using default value.",
                cnf->configfile);
        if (strlcpy(cnf->sysctl_location, VRMR_DEFAULT_SYSCTL_LOCATION,
                    sizeof(cnf->sysctl_location)) >=
                sizeof(cnf->sysctl_location)) {
            vrmr_error(VRMR_CNF_E_UNKNOWN_ERR, "Internal Error",
                    "string overflow");
            return (VRMR_CNF_E_UNKNOWN_ERR);
        }

        retval = VRMR_CNF_W_MISSING_VAR;
    } else
        return (VRMR_CNF_E_UNKNOWN_ERR);

    vrmr_sanitize_path(cnf->sysctl_location, sizeof(cnf->sysctl_location));

    result = vrmr_ask_configfile(cnf, "IPTABLES", cnf->iptables_location,
            cnf->configfile, sizeof(cnf->iptables_location));
    if (result == 1) {
        /* ok */
    } else if (result == 0) {
        vrmr_warning("Warning",
                "Variable IPTABLES not found in '%s', using default value.",
                cnf->configfile);
        if (strlcpy(cnf->iptables_location, VRMR_DEFAULT_IPTABLES_LOCATION,
                    sizeof(cnf->iptables_location)) >=
                sizeof(cnf->iptables_location)) {
            vrmr_error(VRMR_CNF_E_UNKNOWN_ERR, "Internal Error",
                    "string overflow");
            return (VRMR_CNF_E_UNKNOWN_ERR);
        }

        retval = VRMR_CNF_W_MISSING_VAR;
    } else
        return (VRMR_CNF_E_UNKNOWN_ERR);

    vrmr_sanitize_path(cnf->iptables_location, sizeof(cnf->iptables_location));

    result = vrmr_ask_configfile(cnf, "IPTABLES_RESTORE",
            cnf->iptablesrestore_location, cnf->configfile,
            sizeof(cnf->iptablesrestore_location));
    if (result == 1) {
        /* ok */
    } else if (result == 0) {
        vrmr_warning("Warning",
                "Variable IPTABLES_RESTORE not found in '%s', using default "
                "value.",
                cnf->configfile);
        if (strlcpy(cnf->iptablesrestore_location,
                    VRMR_DEFAULT_IPTABLES_REST_LOCATION,
                    sizeof(cnf->iptablesrestore_location)) >=
                sizeof(cnf->iptablesrestore_location)) {
            vrmr_error(VRMR_CNF_E_UNKNOWN_ERR, "Internal Error",
                    "string overflow");
            return (VRMR_CNF_E_UNKNOWN_ERR);
        }

        retval = VRMR_CNF_W_MISSING_VAR;
    } else
        return (VRMR_CNF_E_UNKNOWN_ERR);

    vrmr_sanitize_path(cnf->iptablesrestore_location,
            sizeof(cnf->iptablesrestore_location));

    result = vrmr_ask_configfile(cnf, "IP6TABLES", cnf->ip6tables_location,
            cnf->configfile, sizeof(cnf->ip6tables_location));
    if (result == 1) {
        /* ok */
    } else if (result == 0) {
        vrmr_warning("Warning",
                "Variable IP6TABLES not found in '%s', using default value.",
                cnf->configfile);
        if (strlcpy(cnf->ip6tables_location, VRMR_DEFAULT_IP6TABLES_LOCATION,
                    sizeof(cnf->ip6tables_location)) >=
                sizeof(cnf->ip6tables_location)) {
            vrmr_error(VRMR_CNF_E_UNKNOWN_ERR, "Internal Error",
                    "string overflow");
            return (VRMR_CNF_E_UNKNOWN_ERR);
        }

        retval = VRMR_CNF_W_MISSING_VAR;
    } else
        return (VRMR_CNF_E_UNKNOWN_ERR);

    vrmr_sanitize_path(
            cnf->ip6tables_location, sizeof(cnf->ip6tables_location));

    result = vrmr_ask_configfile(cnf, "IP6TABLES_RESTORE",
            cnf->ip6tablesrestore_location, cnf->configfile,
            sizeof(cnf->ip6tablesrestore_location));
    if (result == 1) {
        /* ok */
    } else if (result == 0) {
        vrmr_warning("Warning",
                "Variable IP6TABLES_RESTORE not found in '%s', using default "
                "value.",
                cnf->configfile);
        if (strlcpy(cnf->ip6tablesrestore_location,
                    VRMR_DEFAULT_IP6TABLES_REST_LOCATION,
                    sizeof(cnf->ip6tablesrestore_location)) >=
                sizeof(cnf->ip6tablesrestore_location)) {
            vrmr_error(VRMR_CNF_E_UNKNOWN_ERR, "Internal Error",
                    "string overflow");
            return (VRMR_CNF_E_UNKNOWN_ERR);
        }

        retval = VRMR_CNF_W_MISSING_VAR;
    } else
        return (VRMR_CNF_E_UNKNOWN_ERR);

    vrmr_sanitize_path(cnf->ip6tablesrestore_location,
            sizeof(cnf->ip6tablesrestore_location));

    result = vrmr_ask_configfile(cnf, "TC", cnf->tc_location, cnf->configfile,
            sizeof(cnf->tc_location));
    if (result == 1) {
        /* ok */
    } else if (result == 0) {
        /*  don't set a default because most systems
            won't have this tool by default */
    } else
        return (VRMR_CNF_E_UNKNOWN_ERR);

    vrmr_sanitize_path(cnf->tc_location, sizeof(cnf->tc_location));

    result = vrmr_ask_configfile(cnf, "MODPROBE", cnf->modprobe_location,
            cnf->configfile, sizeof(cnf->modprobe_location));
    if (result == 1) {
        /* ok */
    } else if (result == 0) {
        if (strlcpy(cnf->modprobe_location, VRMR_DEFAULT_MODPROBE_LOCATION,
                    sizeof(cnf->modprobe_location)) >=
                sizeof(cnf->modprobe_location)) {
            vrmr_error(VRMR_CNF_E_UNKNOWN_ERR, "Internal Error",
                    "string overflow");
            return (VRMR_CNF_E_UNKNOWN_ERR);
        }
    } else
        return (VRMR_CNF_E_UNKNOWN_ERR);

    vrmr_sanitize_path(cnf->modprobe_location, sizeof(cnf->modprobe_location));

    /* LOAD_MODULES */
    result = vrmr_ask_configfile(
            cnf, "LOAD_MODULES", answer, cnf->configfile, sizeof(answer));
    if (result == 1) {
        /* ok, found */
        if (strcasecmp(answer, "yes") == 0) {
            cnf->load_modules = TRUE;
        } else if (strcasecmp(answer, "no") == 0) {
            cnf->load_modules = FALSE;
        } else {
            cnf->load_modules = VRMR_DEFAULT_LOAD_MODULES;

            retval = VRMR_CNF_W_ILLEGAL_VAR;
        }
    } else if (result == 0) {
        cnf->load_modules = VRMR_DEFAULT_LOAD_MODULES;
    } else
        return (VRMR_CNF_E_UNKNOWN_ERR);

    /* MODULES_WAIT_TIME */
    result = vrmr_ask_configfile(
            cnf, "MODULES_WAIT_TIME", answer, cnf->configfile, sizeof(answer));
    if (result == 1) {
        /* ok, found */
        result = atoi(answer);
        if (result < 0) {
            vrmr_warning("Warning",
                    "A negative MODULES_WAIT_TIME (%d) can not be used, using "
                    "default (%d).",
                    result, VRMR_DEFAULT_MODULES_WAITTIME);
            cnf->modules_wait_time = VRMR_DEFAULT_MODULES_WAITTIME;

            retval = VRMR_CNF_W_ILLEGAL_VAR;
        } else {
            /* 1/10 th of second */
            cnf->modules_wait_time = (unsigned int)result;
        }
    } else if (result == 0) {
        /* ignore missing, use default */
        cnf->modules_wait_time = VRMR_DEFAULT_MODULES_WAITTIME;
    } else
        return (VRMR_CNF_E_UNKNOWN_ERR);

    /* get the logfile dir */
    result = vrmr_ask_configfile(cnf, "LOGDIR", cnf->vuurmuur_logdir_location,
            cnf->configfile, sizeof(cnf->vuurmuur_logdir_location));
    if (result == 1) {
        if (cnf->verbose_out == TRUE && debug_level >= LOW)
            vrmr_info("Info", "Using '%s' as normal logdir.",
                    cnf->vuurmuur_logdir_location);
    } else if (result == 0) {
        vrmr_warning("Warning",
                "Variable LOGDIR not found in '%s', using default value.",
                cnf->configfile);
        if (strlcpy(cnf->vuurmuur_logdir_location, VRMR_DEFAULT_LOGDIR_LOCATION,
                    sizeof(cnf->vuurmuur_logdir_location)) >=
                sizeof(cnf->vuurmuur_logdir_location)) {
            vrmr_error(VRMR_CNF_E_UNKNOWN_ERR, "Internal Error",
                    "string overflow");
            return (VRMR_CNF_E_UNKNOWN_ERR);
        }

        /* we return here because we don't want the logfile checks if we know
           that this is wrong. */
        return (VRMR_CNF_W_MISSING_VAR);
    } else
        return (VRMR_CNF_E_UNKNOWN_ERR);

    vrmr_sanitize_path(cnf->vuurmuur_logdir_location,
            sizeof(cnf->vuurmuur_logdir_location));

    /* check if we can open the logdir */
    if (vrmr_config_check_logdir(cnf->vuurmuur_logdir_location) < 0)
        return (VRMR_CNF_W_ILLEGAL_VAR);

    /* set/update the lognames */
    if (vrmr_config_set_log_names(cnf) < 0)
        return (VRMR_CNF_E_UNKNOWN_ERR);

    /* vuurmuur.log */
    if (cnf->verbose_out == TRUE && debug_level >= LOW)
        vrmr_info("Info", "Using '%s' as vuurmuur.log.",
                cnf->vuurmuurlog_location);

    if (check_logfile(cnf->vuurmuurlog_location) < 0) {
        retval = VRMR_CNF_E_ILLEGAL_VAR;
    }

    /* error.log */
    if (cnf->verbose_out == TRUE && debug_level >= LOW)
        vrmr_info("Info", "Using '%s' as error.log.", cnf->errorlog_location);

    if (check_logfile(cnf->errorlog_location) < 0) {
        retval = VRMR_CNF_E_ILLEGAL_VAR;
    }

    /* debug.log */
    if (cnf->verbose_out == TRUE && debug_level >= LOW)
        vrmr_info("Info", "Using '%s' as debug.log.", cnf->debuglog_location);

    if (check_logfile(cnf->debuglog_location) < 0) {
        retval = VRMR_CNF_E_ILLEGAL_VAR;
    }

    /* traffic.log */
    if (cnf->verbose_out == TRUE && debug_level >= LOW)
        vrmr_info(
                "Info", "Using '%s' as traffic.log.", cnf->trafficlog_location);

    if (check_logfile(cnf->trafficlog_location) < 0) {
        retval = VRMR_CNF_E_ILLEGAL_VAR;
    }

    /* connnew.log */
    if (cnf->verbose_out == TRUE && debug_level >= LOW)
        vrmr_info(
                "Info", "Using '%s' as connnew.log.", cnf->connnewlog_location);

    if (check_logfile(cnf->connnewlog_location) < 0) {
        retval = VRMR_CNF_E_ILLEGAL_VAR;
    }

    /* connections.log */
    if (cnf->verbose_out == TRUE && debug_level >= LOW)
        vrmr_info("Info", "Using '%s' as connections.log.",
                cnf->connlog_location);

    if (check_logfile(cnf->connlog_location) < 0) {
        retval = VRMR_CNF_E_ILLEGAL_VAR;
    }

    return (retval);
}

static int vrmr_pre_init_config(struct vrmr_config *cnf)
{
    assert(cnf);

    /* init the struct */
    memset(cnf, 0, sizeof(struct vrmr_config));

    /* set the configdir location */
    if (strlcpy(cnf->etcdir, xstr(SYSCONFDIR), sizeof(cnf->etcdir)) >=
            sizeof(cnf->etcdir)) {
        vrmr_error(-1, "Error",
                "buffer too small for config-dir supplied at compile-time");
        return (-1);
    }
    // printf("cnf->etcdir %s\n", cnf->etcdir);

    if (snprintf(cnf->configfile, sizeof(cnf->configfile),
                "%s/vuurmuur/config.conf",
                cnf->etcdir) >= (int)sizeof(cnf->configfile)) {
        vrmr_error(-1, "Error",
                "buffer too small for configfile supplied at compile-time");
        return (-1);
    }
    // printf("cnf->configfile %s\n", cnf->configfile);

    /* set the plugin location */
    if (strlcpy(cnf->plugdir, xstr(PLUGINDIR), sizeof(cnf->plugdir)) >=
            sizeof(cnf->plugdir)) {
        vrmr_error(-1, "Error",
                "buffer too small for plugdir supplied at compile-time");
        return (-1);
    }
    // printf("cnf->libdir %s\n", cnf->libdir);

    /* set the datadir location */
    if (strlcpy(cnf->datadir, xstr(DATADIR), sizeof(cnf->datadir)) >=
            sizeof(cnf->datadir)) {
        vrmr_error(-1, "Error",
                "buffer too small for sysconfdir supplied at compile-time");
        return (-1);
    }

    /* default to yes */
    cnf->vrmr_check_iptcaps = TRUE;

    /* Don't do any permissin checks until we loaded MAX_PERMISSION from the
     * config file */
    cnf->max_permission = VRMR_ANY_PERMISSION;
    return (0);
}

int vrmr_reload_config(struct vrmr_config *old_cnf)
{
    struct vrmr_config new_cnf;
    int retval = VRMR_CNF_OK;

    assert(old_cnf);

    /* some initilization */
    if (vrmr_pre_init_config(&new_cnf) < 0)
        return (VRMR_CNF_E_UNKNOWN_ERR);

    /* verbose out can only be set on the commandline */
    new_cnf.verbose_out = old_cnf->verbose_out;

    /* this function will never be run in bashmode */
    new_cnf.bash_out = FALSE;
    new_cnf.test_mode = FALSE;

    /* copy the config file location to the new config since it is not loaded by
     * vrmr_init_config */
    if (strlcpy(new_cnf.configfile, old_cnf->configfile,
                sizeof(new_cnf.configfile)) >= sizeof(new_cnf.configfile)) {
        vrmr_error(VRMR_CNF_E_UNKNOWN_ERR, "Internal Error", "string overflow");
        return (VRMR_CNF_E_UNKNOWN_ERR);
    }

    /* reload the configfile */
    if ((retval = vrmr_init_config(&new_cnf)) >= VRMR_CNF_OK) {
        /* copy the data to the old struct */
        memcpy(old_cnf, &new_cnf, sizeof(new_cnf));
    }
    return (retval);
}

/* vrmr_ask_configfile

    This function ask questions from the configfile.

    Returncodes:
     1: ok
     0: ok, but question not found.
    -1: error
*/
int vrmr_ask_configfile(const struct vrmr_config *cnf, char *question,
        char *answer_ptr, char *file_location, size_t size)
{
    int retval = 0;
    size_t i = 0, k = 0, j = 0;
    FILE *fp = NULL;
    char line[512] = "", variable[128] = "", value[256] = "";

    assert(question && file_location && size > 0);

    if (!(fp = vuurmuur_fopen(cnf, file_location, "r"))) {
        vrmr_error(-1, "Error", "unable to open configfile '%s': %s",
                file_location, strerror(errno));
        return (-1);
    }

    while (fgets(line, (int)sizeof(line), fp) != NULL) {
        if ((line[0] == '#') || (strlen(line) < 1) || (line[0] == '\n')) {
            /* do nothing, its a comment. */
        } else {
            k = 0;
            j = 0;

            /* variable */
            while (line[k] != '=' && k < size) {
                variable[j] = line[k];
                k++;
                j++;
            }
            variable[j] = '\0';

            vrmr_debug(HIGH, "question '%s' variable '%s' (%d)", question,
                    variable, (int)size);

            /* value */
            j = 0;
            i = k + 1;
            while (line[i] != '\0' && line[i] != '\n' && i < (size + k + 1)) {
                /* if the first character is a '"' we strip it. */
                if (j == 0 && line[i] == '\"') {
                    i++;
                } else {
                    value[j] = line[i];
                    i++;
                    j++;
                }
            }
            /* if the last character is a'"' we strip it. */
            if (j > 0) {
                if (value[j - 1] == '\"') {
                    value[j - 1] = '\0';
                } else
                    value[j] = '\0';
            } else
                value[j] = '\0';

            vrmr_debug(HIGH, "question '%s' value '%s' (%d)", question, value,
                    (int)size);

            if (strcmp(question, variable) == 0) {
                vrmr_debug(HIGH, "question '%s' matched, value: '%s'", question,
                        value);

                if (strlcpy(answer_ptr, value, size) >= size) {
                    vrmr_error(-1, "Error", "value for question '%s' too big",
                            question);
                    retval = -1;
                } else {
                    retval = 1;
                }

                break;
            }
        }
    }

    if (fclose(fp) == -1) {
        vrmr_error(-1, "Error", "closing file '%s' failed: %s.", file_location,
                strerror(errno));
        retval = -1;
    }

    return (retval);
}

/*  write_configfile

    Writes the config to disk.
*/
int vrmr_write_configfile(char *file_location, struct vrmr_config *cfg)
{
    FILE *fp = NULL;

    assert(file_location);

    /* open for over-writing */
    if (!(fp = fopen(file_location, "w+"))) {
        vrmr_error(-1, "Error",
                "unable to open configfile '%s' for writing: %s", file_location,
                strerror(errno));
        return (-1);
    }

    /* start writing the config to the file */
    fprintf(fp, "# vuurmuur config file\n\n");

    fprintf(fp, "# Which plugin to use for which type of data.\n");
    fprintf(fp, "SERVICES_BACKEND=\"%s\"\n\n", cfg->serv_backend_name);
    fprintf(fp, "ZONES_BACKEND=\"%s\"\n\n", cfg->zone_backend_name);
    fprintf(fp, "INTERFACES_BACKEND=\"%s\"\n\n", cfg->ifac_backend_name);
    fprintf(fp, "RULES_BACKEND=\"%s\"\n\n", cfg->rule_backend_name);

    fprintf(fp, "# Location of the sysctl-command (full path).\n");
    fprintf(fp, "SYSCTL=\"%s\"\n\n", cfg->sysctl_location);
    fprintf(fp, "# Location of the iptables-command (full path).\n");
    fprintf(fp, "IPTABLES=\"%s\"\n\n", cfg->iptables_location);
    fprintf(fp, "# Location of the iptables-restore-command (full path).\n");
    fprintf(fp, "IPTABLES_RESTORE=\"%s\"\n\n", cfg->iptablesrestore_location);

    fprintf(fp, "# Location of the ip6tables-command (full path).\n");
    fprintf(fp, "IP6TABLES=\"%s\"\n\n", cfg->ip6tables_location);
    fprintf(fp, "# Location of the ip6tables-restore-command (full path).\n");
    fprintf(fp, "IP6TABLES_RESTORE=\"%s\"\n\n", cfg->ip6tablesrestore_location);

    fprintf(fp, "# Location of the tc-command (full path).\n");
    fprintf(fp, "TC=\"%s\"\n\n", cfg->tc_location);

    fprintf(fp, "# Location of the modprobe-command (full path).\n");
    fprintf(fp, "MODPROBE=\"%s\"\n\n", cfg->modprobe_location);

    fprintf(fp, "# Maximum permissions for cfg->g and log files and "
                "directories.\n");
    fprintf(fp, "MAX_PERMISSION=\"%o\"\n\n", cfg->max_permission);

    fprintf(fp, "# Load modules if needed? (yes/no)\n");
    fprintf(fp, "LOAD_MODULES=\"%s\"\n\n", cfg->load_modules ? "Yes" : "No");
    fprintf(fp, "# Wait after loading a module in 1/10th of a second\n");
    fprintf(fp, "MODULES_WAIT_TIME=\"%u\"\n\n", cfg->modules_wait_time);

    fprintf(fp, "# netfilter group (only applicable when RULE_NFLOG=\"Yes\"\n");
    fprintf(fp, "NFGRP=\"%u\"\n\n", cfg->nfgrp);
    fprintf(fp,
            "# The directory where the logs will be written to (full path).\n");
    fprintf(fp, "LOGDIR=\"%s\"\n\n", cfg->vuurmuur_logdir_location);

    fprintf(fp, "# Check the dynamic interfaces for changes?\n");
    fprintf(fp, "DYN_INT_CHECK=\"%s\"\n\n",
            cfg->dynamic_changes_check ? "Yes" : "No");
    fprintf(fp, "# Check every x seconds.\n");
    fprintf(fp, "DYN_INT_INTERVAL=\"%u\"\n\n", cfg->dynamic_changes_interval);

    fprintf(fp, "# LOG_POLICY controls the logging of the default policy.\n");
    fprintf(fp, "LOG_POLICY=\"%s\"\n\n", cfg->log_policy ? "Yes" : "No");
    fprintf(fp,
            "# LOG_POLICY_LIMIT sets the maximum number of logs per second.\n");
    fprintf(fp, "LOG_POLICY_LIMIT=\"%u\"\n\n", cfg->log_policy_limit);
    fprintf(fp, "# LOG_BLOCKLIST enables/disables logging of items on the "
                "blocklist.\n");
    fprintf(fp, "LOG_BLOCKLIST=\"%s\"\n\n", cfg->log_blocklist ? "Yes" : "No");

    fprintf(fp, "# LOG_INVALID enables/disables logging of INVALID traffic.\n");
    fprintf(fp, "LOG_INVALID=\"%s\"\n\n", cfg->log_invalid ? "Yes" : "No");
    fprintf(fp, "# LOG_NO_SYN enables/disables logging of new tcp packets "
                "without the SIN flag set.\n");
    fprintf(fp, "LOG_NO_SYN=\"%s\"\n\n", cfg->log_no_syn ? "Yes" : "No");
    fprintf(fp, "# LOG_PROBES enables/disables logging of probes. Probes are "
                "packets that are used in portscans.\n");
    fprintf(fp, "LOG_PROBES=\"%s\"\n\n", cfg->log_probes ? "Yes" : "No");
    fprintf(fp, "# LOG_FRAG enables/disables logging of fragmented packets.\n");
    fprintf(fp, "LOG_FRAG=\"%s\"\n\n", cfg->log_frag ? "Yes" : "No");

    fprintf(fp, "# DROP_INVALID enables/disables dropping of packets marked "
                "INVALID by conntrack.\n");
    fprintf(fp, "DROP_INVALID=\"%s\"\n\n",
            cfg->conntrack_invalid_drop ? "Yes" : "No");
    fprintf(fp, "# CONNTRACK_ACCOUNTING enables/disables conntrack accounting "
                "as used in connection logging and viewer.\n");
    fprintf(fp, "CONNTRACK_ACCOUNTING=\"%s\"\n\n",
            cfg->conntrack_accounting ? "Yes" : "No");

    fprintf(fp,
            "# SYN_LIMIT sets the maximum number of SYN-packets per second.\n");
    fprintf(fp, "USE_SYN_LIMIT=\"%s\"\n\n", cfg->use_syn_limit ? "Yes" : "No");
    fprintf(fp, "SYN_LIMIT=\"%u\"\n", cfg->syn_limit);
    fprintf(fp, "SYN_LIMIT_BURST=\"%u\"\n\n", cfg->syn_limit_burst);

    fprintf(fp, "# UDP_LIMIT sets the maximum number of udp 'connections' per "
                "second.\n");
    fprintf(fp, "USE_UDP_LIMIT=\"%s\"\n\n", cfg->use_udp_limit ? "Yes" : "No");
    fprintf(fp, "UDP_LIMIT=\"%u\"\n", cfg->udp_limit);
    fprintf(fp, "UDP_LIMIT_BURST=\"%u\"\n\n", cfg->udp_limit_burst);

    /* protect */
    fprintf(fp, "# Protect against syn-flooding? (yes/no)\n");
    fprintf(fp, "PROTECT_SYNCOOKIE=\"%s\"\n",
            cfg->protect_syncookie ? "Yes" : "No");

    fprintf(fp, "# Ignore echo-broadcasts? (yes/no)\n");
    fprintf(fp, "PROTECT_ECHOBROADCAST=\"%s\"\n\n",
            cfg->protect_echobroadcast ? "Yes" : "No");

    fprintf(fp, "# end of file\n");

    /* flush buffer */
    (void)fflush(fp);
    /* close file */
    if (fclose(fp) == -1) {
        vrmr_error(-1, "Error", "closing '%s' failed: %s.", file_location,
                strerror(errno));
        return (-1);
    }

    vrmr_info("Info", "Rewritten config file.");
    return (0);
}

int vrmr_init(struct vrmr_ctx *ctx, const char *toolname)
{
    vrmr_debug_level = 0;

    vrprint.logger = toolname;
    vrprint.error = vrmr_stdoutprint_error;
    vrprint.warning = vrmr_stdoutprint_warning;
    vrprint.info = vrmr_stdoutprint_info;
    vrprint.debug = vrmr_stdoutprint_debug;
    vrprint.audit = vrmr_stdoutprint_audit;

    if (vrmr_pre_init_config(&ctx->conf) < 0)
        return (-1);

    vrmr_user_get_info(&ctx->user_data);
    vrprint.username = ctx->user_data.realusername;

    /* init plugin list */
    vrmr_list_setup(&vrmr_plugin_list, free);

    /* setup regexes */
    if (vrmr_regex_setup(1, &ctx->reg) < 0) {
        vrmr_error(
                -1, "Internal Error", "setting up regular expressions failed.");
        return (-1);
    }

    return (0);
}

void vrmr_deinit(struct vrmr_ctx *ctx)
{
    (void)vrmr_regex_setup(0, &ctx->reg);
}

void vrmr_enable_logprint(struct vrmr_config *cnf ATTR_UNUSED)
{
    vrprint.error = vrmr_logprint_error;
    vrprint.warning = vrmr_logprint_warning;
    vrprint.info = vrmr_logprint_info;
    vrprint.debug = vrmr_logprint_debug;
    vrprint.audit = vrmr_logprint_audit;
}

int vrmr_load(struct vrmr_ctx *vctx)
{
    int result;

    result = vrmr_init_config(&vctx->conf);
    if (result < VRMR_CNF_OK) {
        vrmr_error(-1, "Error", "initializing config failed");
        return -1;
    }
    /* now we know the logfile locations, so init the log functions */
    vrmr_enable_logprint(&vctx->conf);

    result = vrmr_backends_load(&vctx->conf, vctx);
    if (result < 0) {
        vrmr_error(-1, "Error", "loading backends failed");
        return -1;
    }

    result = vrmr_interfaces_load(vctx, &vctx->interfaces);
    if (result < -1) {
        vrmr_error(-1, "Error", "initializing interfaces failed");
        return -1;
    }

    result = vrmr_zones_load(vctx, &vctx->zones, &vctx->interfaces, &vctx->reg);
    if (result == -1) {
        vrmr_error(-1, "Error", "initializing zones failed");
        return -1;
    }

    result = vrmr_services_load(vctx, &vctx->services, &vctx->reg);
    if (result == -1) {
        vrmr_error(-1, "Error", "initializing services failed");
        return -1;
    }

    result = vrmr_rules_init_list(vctx, &vctx->conf, &vctx->rules, &vctx->reg);
    if (result < 0) {
        vrmr_error(-1, "Error", "initializing the rules failed");
        return -1;
    }

    if (vrmr_blocklist_init_list(vctx, &vctx->conf, &vctx->zones,
                &vctx->blocklist, /*load_ips*/ TRUE, /*no_refcnt*/ FALSE) < 0) {
        vrmr_error(-1, "Error", "initializing the blocklist failed");
        return -1;
    }

    return 0;
}

int vrmr_create_log_hash(struct vrmr_ctx *vctx,
        struct vrmr_hash_table *service_hash, struct vrmr_hash_table *zone_hash)
{
    /* insert the interfaces as VRMR_TYPE_FIREWALL's into the zonelist as
     * 'firewall', so this appears in to log as 'firewall(interface)' */
    if (vrmr_ins_iface_into_zonelist(
                &vctx->interfaces.list, &vctx->zones.list) < 0) {
        vrmr_error(-1, "Error", "iface_into_zonelist failed");
        return (-1);
    }

    /* these are removed by: vrmr_rem_iface_from_zonelist() (see below) */
    if (vrmr_add_broadcasts_zonelist(&vctx->zones) < 0) {
        vrmr_error(-1, "Error", "unable to add broadcasts to list");
        return (-1);
    }

    if (vrmr_init_zonedata_hashtable(vctx->zones.list.len * 3,
                &vctx->zones.list, vrmr_hash_ipaddress, vrmr_compare_ipaddress,
                zone_hash) < 0) {
        vrmr_error(-1, "Error", "vrmr_init_zonedata_hashtable failed");
        return (-1);
    }

    if (vrmr_init_services_hashtable(vctx->services.list.len * 500,
                &vctx->services.list, vrmr_hash_port, vrmr_compare_ports,
                service_hash) < 0) {
        vrmr_error(-1, "Error", "vrmr_init_services_hashtable failed");
        return (-1);
    }
    return (0);
}
