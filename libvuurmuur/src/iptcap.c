/***************************************************************************
 *   Copyright (C) 2002-2012 by Victor Julien                              *
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

/*
    functions for detecting the capabilities of Iptables on the
    system.
*/

#include "config.h"
#include "vuurmuur.h"


static int
iptcap_get_one_cap_from_proc(const int debuglvl, char *procpath, char *request)
{
    char    line[64] = "";
    FILE    *fp = NULL;
    int     retval = 0;

    /* safety */
    if(procpath == NULL || request == NULL)
    {
        vrmr_error(-1, "Internal Error", "parameter problem (in: %s:%d).",
            __FUNC__, __LINE__);
        return(-1);
    }

    /* open the matches */
    if(!(fp = fopen(procpath, "r")))
    {
        vrmr_error(-1, "Error", "could not open '%s': %s (in: %s:%d).",
            procpath, strerror(errno), __FUNC__, __LINE__);
        return(-1);
    }

    /* now loop through the file */
    while(fgets(line, (int)sizeof(line), fp) != NULL)
    {
        /* strip the newline if there is one */
        if(line[strlen(line)-1] == '\n')
            line[strlen(line)-1] = '\0';

        if(debuglvl >= HIGH)
            vrmr_debug(__FUNC__, "%s: '%s'.", procpath, line);

        /* compare the line with the request */
        if(strcmp(line, request) == 0)
        {
            if(debuglvl >= MEDIUM)
                vrmr_debug(__FUNC__, "%s: '%s' match!.", procpath, line);

            retval = 1;
            break;
        }
    }

    /* close the file */
    if(fclose(fp) == -1)
    {
        vrmr_error(-1, "Error", "could not close '%s': %s (in: %s:%d).",
            procpath, strerror(errno), __FUNC__, __LINE__);
        return(-1);
    }

    if (debuglvl >= LOW)
        vrmr_debug(__FUNC__, "procpath: %s request: %s retval: %u", procpath, request, retval);

    /* return retval, 1 if found, 0 if not found */
    return(retval);
}


/*
    -1: error
     0: ok
*/
static int
iptcap_load_module(const int debuglvl, struct vrmr_config *cnf, char *modulename)
{
    /* safety */
    if(modulename == NULL || cnf == NULL)
    {
        vrmr_error(-1, "Internal Error", "parameter problem (in: %s:%d).",
            __FUNC__, __LINE__);
        return(-1);
    }

    /* now execute the command */
    char *args[] = { cnf->modprobe_location, "-q", modulename, NULL };
    int r = libvuurmuur_exec_command(debuglvl, cnf, cnf->modprobe_location, args, NULL);
    if (r != 0)
    {
        if(debuglvl >= LOW)
            vrmr_debug(__FUNC__, "loading module '%s' failed: modprobe returned %d.", modulename, r);

        return(-1);
    }

    if(debuglvl >= LOW)
        vrmr_debug(__FUNC__, "loading module '%s' success, modprobe returned %d.", modulename, r);

    return(0);
}


static int
iptcap_check_cap(const int debuglvl, struct vrmr_config *cnf, char *procpath, char *request, char *modulename, char load_module)
{
    int result = 0;

    /* safety */
    if(procpath == NULL || request == NULL || modulename == NULL || cnf == NULL)
    {
        vrmr_error(-1, "Internal Error", "parameter problem (in: %s:%d).",
            __FUNC__, __LINE__);
        return(-1);
    }

    /* get the cap */
    result = iptcap_get_one_cap_from_proc(debuglvl, procpath, request);
    if(result < 0)
    {
        vrmr_error(-1, "Error", "getting iptcap for '%s' failed (in: %s:%d).",
            request, __FUNC__, __LINE__);
        return(-1);
    }
    else if(result == 0)
    {
        if(debuglvl >= LOW)
            vrmr_debug(__FUNC__, "'%s' not loaded or not supported.", request);
    }
    else
    {
        if(debuglvl >= LOW)
            vrmr_debug(__FUNC__, "'%s' supported and loaded.", request);

        /* and done :-) */
        return(1);
    }

    /* if load_modules == FALSE we bail out now */
    if(load_module == FALSE)
        return(0);

    /* try to load the module, if it fails we don't care */
    (void)iptcap_load_module(debuglvl, cnf, modulename);

    /* sleep for a short time if requested */
    if(cnf->modules_wait_time > 0)
    {
        if(debuglvl >= LOW)
            vrmr_debug(__FUNC__, "after loading the module, usleep for %lu.",
                    (unsigned long)(cnf->modules_wait_time * 10000));

        usleep(cnf->modules_wait_time * 10000);
    }

    /* try get the cap again */
    result = iptcap_get_one_cap_from_proc(debuglvl, procpath, request);
    if(result < 0)
    {
        vrmr_error(-1, "Error", "getting iptcap for '%s' failed (in: %s:%d).",
            request, __FUNC__, __LINE__);
        return(-1);
    }
    else if(result == 0)
    {
        if(debuglvl >= LOW)
            vrmr_debug(__FUNC__, "'%s' not supported.", request);
    }
    else
    {
        if(debuglvl >= LOW)
            vrmr_debug(__FUNC__, "'%s' supported and loaded.", request);

        /* and done :-) */
        return(1);
    }

    return(0);
}


/*
    return 1 if file exists, 0 if not.
*/
static int
iptcap_check_file(const int debuglvl, char *path)
{
    FILE    *fp = NULL;

    /* safety */
    if(path == NULL)
    {
        vrmr_error(-1, "Internal Error", "parameter problem (in: %s:%d).",
            __FUNC__, __LINE__);
        return(-1);
    }

    if(!(fp = fopen(path, "r")))
        return(0);

    fclose(fp);
    return(1);
}


static int
iptcap_get_queue_peer_pid(const int debuglvl, struct vrmr_iptcaps *iptcap)
{
    char    proc_net_ipqueue[] = "/proc/net/ip_queue",
            line[128] = "",
            pid_number[16] = "";
    FILE    *fp = NULL;
    int     i = 0,
            k = 0;
    char    copy_now = 0;

    /* safety */
    if(iptcap == NULL)
    {
        vrmr_error(-1, "Internal Error", "parameter problem (in: %s:%d).",
            __FUNC__, __LINE__);
        return(-1);
    }

    /* open the file */
    if(!(fp = fopen(proc_net_ipqueue, "r")))
    {
        vrmr_error(-1, "Error", "opening file '%s' failed: %s (in: %s:%d).",
            proc_net_ipqueue, strerror(errno), __FUNC__, __LINE__);
        return(-1);
    }

    /* get the first line */
    if(fgets(line, (int)sizeof(line), fp) == NULL)
    {
        vrmr_error(-1, "Error", "reading line from ip_queue failed (in: %s:%d).",
            __FUNC__, __LINE__);

        fclose(fp);
        return(-1);
    }
    /* strip newline */
    if(line[strlen(line)-1] == '\n')
        line[strlen(line)-1] = '\0';

    if(debuglvl >= HIGH)
        vrmr_debug(__FUNC__, "line '%s'.", line);

    /* interpret the line */
    for(i = 0, k = 0; i < (int)strlen(line); i++)
    {
        if(copy_now)
        {
            pid_number[k] = line[i];

            k++;
        }

        if(line[i] == ':')
            copy_now = 1;
    }
    /* term */
    pid_number[k] = '\0';

    if(debuglvl >= HIGH)
        vrmr_debug(__FUNC__, "pid_number '%s'.", pid_number);

    /* convert */
    iptcap->queue_peer_pid = atoi(pid_number);

    if(debuglvl >= HIGH)
        vrmr_debug(__FUNC__, "pid '%u'.", iptcap->queue_peer_pid);

    fclose(fp);

    return(0);
}

static int
iptcap_get_ip6_queue_peer_pid(const int debuglvl, struct vrmr_iptcaps *iptcap)
{
    char    proc_net_ip6queue[] = "/proc/net/ip6_queue",
            line[128] = "",
            pid_number[16] = "";
    FILE    *fp = NULL;
    int     i = 0,
            k = 0;
    char    copy_now = 0;

    /* safety */
    if(iptcap == NULL)
    {
        vrmr_error(-1, "Internal Error", "parameter problem (in: %s:%d).",
            __FUNC__, __LINE__);
        return(-1);
    }

    /* open the file */
    if(!(fp = fopen(proc_net_ip6queue, "r")))
    {
        vrmr_error(-1, "Error", "opening file '%s' failed: %s (in: %s:%d).",
            proc_net_ip6queue, strerror(errno), __FUNC__, __LINE__);
        return(-1);
    }

    /* get the first line */
    if(fgets(line, (int)sizeof(line), fp) == NULL)
    {
        vrmr_error(-1, "Error", "reading line from ip6_queue failed (in: %s:%d).",
            __FUNC__, __LINE__);

        fclose(fp);
        return(-1);
    }
    /* strip newline */
    if(line[strlen(line)-1] == '\n')
        line[strlen(line)-1] = '\0';

    if(debuglvl >= HIGH)
        vrmr_debug(__FUNC__, "line '%s'.", line);

    /* interpret the line */
    for(i = 0, k = 0; i < (int)strlen(line); i++)
    {
        if(copy_now)
        {
            pid_number[k] = line[i];

            k++;
        }

        if(line[i] == ':')
            copy_now = 1;
    }
    /* term */
    pid_number[k] = '\0';

    if(debuglvl >= HIGH)
        vrmr_debug(__FUNC__, "pid_number '%s'.", pid_number);

    /* convert */
    iptcap->ip6_queue_peer_pid = atoi(pid_number);

    if(debuglvl >= HIGH)
        vrmr_debug(__FUNC__, "pid '%u'.", iptcap->ip6_queue_peer_pid);

    fclose(fp);

    return(0);
}

static int
iptcap_create_test_mangle_chain(const int debuglvl, struct vrmr_config *cnf, char *ipt_loc)
{
    char *args[] = { ipt_loc, "-t", "mangle", "-N", "VRMRIPTCAP", NULL };
    int r = libvuurmuur_exec_command(debuglvl, cnf, ipt_loc, args, NULL);
    if (r != 0) {
        return -1;
    }

    return 0;
}

static int
iptcap_delete_test_mangle_chain(const int debuglvl, struct vrmr_config *cnf, char *ipt_loc)
{
    char *argsF[] = { ipt_loc, "-t", "mangle", "-F", "VRMRIPTCAP", NULL };
    int r = libvuurmuur_exec_command(debuglvl, cnf, ipt_loc, argsF, NULL);
    if (r != 0) {
        vrmr_debug(__FUNC__, "flush failed (ok if chain didn't exist)");
        return -1;
    }

    char *argsX[] = { ipt_loc, "-t", "mangle", "-X", "VRMRIPTCAP", NULL };
    r = libvuurmuur_exec_command(debuglvl, cnf, ipt_loc, argsX, NULL);
    if (r != 0) {
        vrmr_debug(__FUNC__, "delete failed");
        return -1;
    }

    return 0;
}

static int
iptcap_create_test_filter_chain(const int debuglvl, struct vrmr_config *cnf, char *ipt_loc)
{
    char *args[] = { ipt_loc, "-t", "filter", "-N", "VRMRIPTCAP", NULL };
    int r = libvuurmuur_exec_command(debuglvl, cnf, ipt_loc, args, NULL);
    if (r != 0) {
        return -1;
    }

    return 0;
}

static int
iptcap_delete_test_filter_chain(const int debuglvl, struct vrmr_config *cnf, char *ipt_loc)
{
    /* First, flush the chain */
    char *argsF[] = { ipt_loc, "-t", "filter", "-F", "VRMRIPTCAP", NULL };
    int r = libvuurmuur_exec_command(debuglvl, cnf, ipt_loc, argsF, NULL);
    if (r != 0) {
        if (debuglvl >= LOW)
            vrmr_debug(__FUNC__, "flush failed (ok if chain didn't exist)");
        return -1;
    }

    /* And then delete the chain */
    char *argsX[] = { ipt_loc, "-t", "filter", "-X", "VRMRIPTCAP", NULL };
    r = libvuurmuur_exec_command(debuglvl, cnf, ipt_loc, argsX, NULL);
    if (r != 0) {
        if (debuglvl >= LOW)
            vrmr_debug(__FUNC__, "delete failed");
        return -1;
    }

    return 0;
}

int
iptcap_test_filter_connmark_match(const int debuglvl, struct vrmr_config *cnf, char *ipt_loc)
{
    int retval = 1;

    if (iptcap_delete_test_filter_chain(debuglvl, cnf, ipt_loc) < 0) {
        if (debuglvl >= LOW)
            vrmr_debug(__FUNC__, "iptcap_delete_test_filter_chain failed, but error will be ignored");
    }

    if (iptcap_create_test_filter_chain(debuglvl, cnf, ipt_loc) < 0) {
        if (debuglvl >= LOW)
            vrmr_debug(__FUNC__, "iptcap_create_test_filter_chain failed");
        return -1;
    }

    char *args[] = { ipt_loc, "-t", "filter", "-A", "VRMRIPTCAP", "-m", "connmark", "--mark", "1", NULL };
    int r = libvuurmuur_exec_command(debuglvl, cnf, ipt_loc, args, NULL);
    if (r != 0) {
        if (debuglvl >= LOW)
            vrmr_debug(__FUNC__, "r = %d", r);
        retval = -1;
    }

    if (iptcap_delete_test_filter_chain(debuglvl, cnf, ipt_loc) < 0) {
        if (debuglvl >= LOW)
            vrmr_debug(__FUNC__, "iptcap_delete_test_filter_chain failed, but error will be ignored");
    }

    return retval;
}

int
iptcap_test_filter_conntrack_match(const int debuglvl, struct vrmr_config *cnf, char *ipt_loc)
{
    int retval = 1;

    if (iptcap_delete_test_filter_chain(debuglvl, cnf, ipt_loc) < 0) {
        if (debuglvl >= LOW)
            vrmr_debug(__FUNC__, "iptcap_delete_test_filter_chain failed, but error will be ignored");
    }

    if (iptcap_create_test_filter_chain(debuglvl, cnf, ipt_loc) < 0) {
        if (debuglvl >= LOW)
            vrmr_debug(__FUNC__, "iptcap_create_test_filter_chain failed");
        return -1;
    }

    char *args[] = { ipt_loc, "-t", "filter", "-A", "VRMRIPTCAP", "-m", "conntrack", "--ctstate", "NEW", NULL };
    int r = libvuurmuur_exec_command(debuglvl, cnf, ipt_loc, args, NULL);
    if (r != 0) {
        if (debuglvl >= LOW)
            vrmr_debug(__FUNC__, "r = %d", r);
        retval = -1;
    }

    if (iptcap_delete_test_filter_chain(debuglvl, cnf, ipt_loc) < 0) {
        if (debuglvl >= LOW)
            vrmr_debug(__FUNC__, "iptcap_delete_test_filter_chain failed, but error will be ignored");
    }

    return retval;
}

/** \internal
 *  \brief test rpfilter module in RAW table
 */
static int
iptcap_test_filter_rpfilter_match(const int debuglvl, struct vrmr_config *cnf, char *ipt_loc)
{
    int retval = 1;

    if (iptcap_delete_test_filter_chain(debuglvl, cnf, ipt_loc) < 0) {
        if (debuglvl >= LOW)
            vrmr_debug(__FUNC__, "iptcap_delete_test_filter_chain failed, but error will be ignored");
    }

    if (iptcap_create_test_filter_chain(debuglvl, cnf, ipt_loc) < 0) {
        if (debuglvl >= LOW)
            vrmr_debug(__FUNC__, "iptcap_create_test_filter_chain failed");
        return -1;
    }

    char *args[] = { ipt_loc, "-t", "raw", "-A", "VRMRIPTCAP", "-m", "rpfilter", "--invert", NULL };
    int r = libvuurmuur_exec_command(debuglvl, cnf, ipt_loc, args, NULL);
    if (r != 0) {
        if (debuglvl >= LOW)
            vrmr_debug(__FUNC__, "r = %d", r);
        retval = -1;
    }

    if (iptcap_delete_test_filter_chain(debuglvl, cnf, ipt_loc) < 0) {
        if (debuglvl >= LOW)
            vrmr_debug(__FUNC__, "iptcap_delete_test_filter_chain failed, but error will be ignored");
    }

    return retval;
}

int
iptcap_test_filter_connmark_target(const int debuglvl, struct vrmr_config *cnf, char *ipt_loc)
{
    int retval = 1;

    if (iptcap_delete_test_filter_chain(debuglvl, cnf, ipt_loc) < 0) {
        vrmr_debug(__FUNC__, "iptcap_delete_test_filter_chain failed, but error will be ignored");
    }

    if (iptcap_create_test_filter_chain(debuglvl, cnf, ipt_loc) < 0) {
        vrmr_debug(__FUNC__, "iptcap_create_test_filter_chain failed");
        return -1;
    }

    char *args[] = { ipt_loc, "-t", "filter", "-A", "VRMRIPTCAP", "-j", "CONNMARK", "--set-mark", "1", NULL };
    int r = libvuurmuur_exec_command(debuglvl, cnf, ipt_loc, args, NULL);
    if (r != 0) {
        vrmr_debug(__FUNC__, "r = %d", r);
        retval = -1;
    }

    if (iptcap_delete_test_filter_chain(debuglvl, cnf, ipt_loc) < 0) {
        vrmr_debug(__FUNC__, "iptcap_delete_test_filter_chain failed, but error will be ignored");
    }

    return retval;
}

int
iptcap_test_filter_helper_match(const int debuglvl, struct vrmr_config *cnf, char *ipt_loc)
{
    int retval = 1;

    if (iptcap_delete_test_filter_chain(debuglvl, cnf, ipt_loc) < 0) {
        vrmr_debug(__FUNC__, "iptcap_delete_test_filter_chain failed, but error will be ignored");
    }

    if (iptcap_create_test_filter_chain(debuglvl, cnf, ipt_loc) < 0) {
        vrmr_debug(__FUNC__, "iptcap_create_test_filter_chain failed");
        return -1;
    }

    char *args[] = { ipt_loc, "-t", "filter", "-A", "VRMRIPTCAP", "-m", "helper", "--helper", "ftp", NULL };
    int r = libvuurmuur_exec_command(debuglvl, cnf, ipt_loc, args, NULL);
    if (r != 0) {
        vrmr_debug(__FUNC__, "r = %d", r);
        retval = -1;
    }

    if (iptcap_delete_test_filter_chain(debuglvl, cnf, ipt_loc) < 0) {
        vrmr_debug(__FUNC__, "iptcap_delete_test_filter_chain failed, but error will be ignored");
    }

    return retval;
}

int
iptcap_test_filter_mark_match(const int debuglvl, struct vrmr_config *cnf, char *ipt_loc)
{
    int retval = 1;

    if (iptcap_delete_test_filter_chain(debuglvl, cnf, ipt_loc) < 0) {
        vrmr_debug(__FUNC__, "iptcap_delete_test_filter_chain failed, but error will be ignored");
    }

    if (iptcap_create_test_filter_chain(debuglvl, cnf, ipt_loc) < 0) {
        vrmr_debug(__FUNC__, "iptcap_create_test_filter_chain failed");
        return -1;
    }

    char *args[] = { ipt_loc, "-t", "filter", "-A", "VRMRIPTCAP", "-m", "mark", "--mark", "1", NULL };
    int r = libvuurmuur_exec_command(debuglvl, cnf, ipt_loc, args, NULL);
    if (r != 0) {
        vrmr_debug(__FUNC__, "r = %d", r);
        retval = -1;
    }

    if (iptcap_delete_test_filter_chain(debuglvl, cnf, ipt_loc) < 0) {
        vrmr_debug(__FUNC__, "iptcap_delete_test_filter_chain failed, but error will be ignored");
    }

    return retval;
}

int
iptcap_test_mangle_mark_target(const int debuglvl, struct vrmr_config *cnf, char *ipt_loc)
{
    int retval = 1;

    if (iptcap_delete_test_mangle_chain(debuglvl, cnf, ipt_loc) < 0) {
        vrmr_debug(__FUNC__, "iptcap_delete_test_mangle_chain failed, but error will be ignored");
    }

    if (iptcap_create_test_mangle_chain(debuglvl, cnf, ipt_loc) < 0) {
        vrmr_debug(__FUNC__, "iptcap_create_test_mangle_chain failed");
        return -1;
    }

    char *args[] = { ipt_loc, "-t", "mangle", "-A", "VRMRIPTCAP", "-j", "MARK", "--set-mark", "1", NULL };
    int r = libvuurmuur_exec_command(debuglvl, cnf, ipt_loc, args, NULL);
    if (r != 0) {
        vrmr_debug(__FUNC__, "r = %d", r);
        retval = -1;
    }

    if (iptcap_delete_test_mangle_chain(debuglvl, cnf, ipt_loc) < 0) {
        vrmr_debug(__FUNC__, "iptcap_delete_test_mangle_chain failed, but error will be ignored");
    }

    return retval;
}

int
iptcap_test_mangle_classify_target(const int debuglvl, struct vrmr_config *cnf, char *ipt_loc)
{
    int retval = 1;

    if (iptcap_delete_test_mangle_chain(debuglvl, cnf, ipt_loc) < 0) {
        vrmr_debug(__FUNC__, "iptcap_delete_test_mangle_chain failed, but error will be ignored");
    }

    if (iptcap_create_test_mangle_chain(debuglvl, cnf, ipt_loc) < 0) {
        vrmr_debug(__FUNC__, "iptcap_create_test_mangle_chain failed");
        return -1;
    }

    char *args[] = { ipt_loc, "-t", "mangle", "-A", "VRMRIPTCAP", "-j", "CLASSIFY", "--set-class", "0:0", NULL };
    int r = libvuurmuur_exec_command(debuglvl, cnf, ipt_loc, args, NULL);
    if (r != 0) {
        vrmr_debug(__FUNC__, "r = %d", r);
        retval = -1;
    }

    if (iptcap_delete_test_mangle_chain(debuglvl, cnf, ipt_loc) < 0) {
        vrmr_debug(__FUNC__, "iptcap_delete_test_mangle_chain failed, but error will be ignored");
    }

    return retval;
}

int
iptcap_test_filter_mac_match(const int debuglvl, struct vrmr_config *cnf, char *ipt_loc)
{
    int retval = 1;

    if (iptcap_delete_test_filter_chain(debuglvl, cnf, ipt_loc) < 0) {
        vrmr_debug(__FUNC__, "iptcap_delete_test_filter_chain failed, but error will be ignored");
    }

    if (iptcap_create_test_filter_chain(debuglvl, cnf, ipt_loc) < 0) {
        vrmr_debug(__FUNC__, "iptcap_create_test_filter_chain failed");
        return -1;
    }

    char *args[] = { ipt_loc, "-t", "filter", "-A", "VRMRIPTCAP", "-m", "mac", "--mac-source", "12:34:56:78:90:ab", NULL };
    int r = libvuurmuur_exec_command(debuglvl, cnf, ipt_loc, args, NULL);
    if (r != 0) {
        vrmr_debug(__FUNC__, "r = %d", r);
        retval = -1;
    }

    if (iptcap_delete_test_filter_chain(debuglvl, cnf, ipt_loc) < 0) {
        vrmr_debug(__FUNC__, "iptcap_delete_test_filter_chain failed, but error will be ignored");
    }

    return retval;
}

/**
 * \param[in] debuglvl The debug level
 * \param[in] cnf The vuurmuur configuration
 * \param[in] ipt_loc The full path to the ip[6]tables program. You should 
 *      cnf.iptables_location or cnf.ip6tables_location for this.
 */
int
iptcap_test_filter_limit_match(const int debuglvl, struct vrmr_config *cnf, char *ipt_loc)
{
    int retval = 1;

    if ( ipt_loc == NULL )
    {
        vrmr_error(-1, "Internal Error", "parameter problem (in: %s:%d).",
            __FUNC__, __LINE__);
        return(-1);
    }

    if (iptcap_delete_test_filter_chain(debuglvl, cnf, ipt_loc) < 0) {
        vrmr_debug(__FUNC__, "iptcap_delete_test_filter_chain failed, but error will be ignored");
    }

    if (iptcap_create_test_filter_chain(debuglvl, cnf, ipt_loc) < 0) {
        vrmr_debug(__FUNC__, "iptcap_create_test_filter_chain failed");
        return -1;
    }

    char *args[] = { ipt_loc, "-t", "filter", "-A", "VRMRIPTCAP", "-m", "limit", "--limit", "1/s", NULL };
    int r = libvuurmuur_exec_command(debuglvl, cnf, ipt_loc, args, NULL);
    if (r != 0) {
        vrmr_debug(__FUNC__, "r = %d", r);
        retval = -1;
    }

    if (iptcap_delete_test_filter_chain(debuglvl, cnf, ipt_loc) < 0) {
        vrmr_debug(__FUNC__, "iptcap_delete_test_filter_chain failed, but error will be ignored");
    }

    return retval;
}

static int
iptcap_create_test_nat_chain(const int debuglvl, struct vrmr_config *cnf) {
    char *args[] = { cnf->iptables_location, "-t", "nat", "-N", "VRMRIPTCAP", NULL };
    int r = libvuurmuur_exec_command(debuglvl, cnf, cnf->iptables_location, args, NULL);
    if (r != 0) {
        return -1;
    }

    return 0;
}

static int
iptcap_delete_test_nat_chain(const int debuglvl, struct vrmr_config *cnf) {
    char *argsF[] = { cnf->iptables_location, "-t", "nat", "-F", "VRMRIPTCAP", NULL };
    int r = libvuurmuur_exec_command(debuglvl, cnf, cnf->iptables_location, argsF, NULL);
    if (r != 0) {
        vrmr_debug(__FUNC__, "flush failed (ok if chain didn't exist)");
        return -1;
    }

    char *argsX[] = { cnf->iptables_location, "-t", "nat", "-X", "VRMRIPTCAP", NULL };
    r = libvuurmuur_exec_command(debuglvl, cnf, cnf->iptables_location, argsX, NULL);
    if (r != 0) {
        vrmr_debug(__FUNC__, "delete failed");
        return -1;
    }

    return 0;
}

int
iptcap_test_nat_random(const int debuglvl, struct vrmr_config *cnf) {
    int retval = 1;

    if (iptcap_delete_test_nat_chain(debuglvl,cnf) < 0) {
        vrmr_debug(__FUNC__, "iptcap_delete_test_nat_chain failed, but error will be ignored");
    }

    if (iptcap_create_test_nat_chain(debuglvl,cnf) < 0) {
        vrmr_debug(__FUNC__, "iptcap_create_test_nat_chain failed");
        return -1;
    }

    char *args[] = { cnf->iptables_location, "-t", "nat", "-A", "VRMRIPTCAP", "-j", "SNAT", "--to-source", "127.0.0.1", "--random", NULL };
    int r = libvuurmuur_exec_command(debuglvl, cnf, cnf->iptables_location, args, NULL);
    if (r != 0) {
        vrmr_debug(__FUNC__, "r = %d", r);
        retval = -1;
    }

    if (iptcap_delete_test_nat_chain(debuglvl,cnf) < 0) {
        vrmr_debug(__FUNC__, "iptcap_delete_test_nat_chain failed, but error will be ignored");
    }

    return retval;
}

int
vrmr_check_iptcaps(const int debuglvl, struct vrmr_config *cnf, struct vrmr_iptcaps *iptcap, char load_modules)
{
    int result = 0;

    /* safety */
    if(iptcap == NULL || cnf == NULL)
    {
        vrmr_error(-1, "Internal Error", "parameter problem (in: %s:%d).",
            __FUNC__, __LINE__);
        return(-1);
    }

    /* load the caps */
    result = vrmr_load_iptcaps(debuglvl, cnf, iptcap, load_modules);
    if(result == -1)
    {
        vrmr_error(-1, "Error", "loading iptables capabilities failed (in: %s:%d).",
            __FUNC__, __LINE__);
        return(-1);
    }

    if(iptcap->proc_net_names == FALSE)
    {
        vrmr_warning("Warning", "'/proc/net/ip_tables_names' missing: no iptables-support in the kernel?");
    }
    if(iptcap->proc_net_targets == FALSE)
    {
        vrmr_warning("Warning", "'/proc/net/ip_tables_targets' missing: no iptables-support in the kernel?");
    }
    if(iptcap->proc_net_matches == FALSE)
    {
        vrmr_warning("Warning", "'/proc/net/ip_tables_matches' missing: no iptables-support in the kernel?");
    }

    /* require the filter table */
    if(iptcap->proc_net_names == TRUE && iptcap->table_filter == FALSE)
    {
        vrmr_error(-1, "Error", "no iptables-support in the kernel: filter table missing (in: %s:%d).",
            __FUNC__, __LINE__);
        return(-1);
    }
    if(iptcap->proc_net_names == TRUE && iptcap->table_nat == FALSE)
        vrmr_warning("Warning", "nat table missing from kernel: nat targets are unavailable.");
    if(iptcap->proc_net_names == TRUE && iptcap->table_mangle == FALSE)
        vrmr_warning("Warning", "mangle table missing from kernel: mangle targets are unavailable.");

    /* require conntrack */
    if(iptcap->conntrack == FALSE)
    {
        vrmr_error(-1, "Error", "no connection tracking support in the kernel (in: %s:%d).",
            __FUNC__, __LINE__);
        return(-1);
    }

    /* require tcp, udp, icmp */
    if(iptcap->proc_net_matches == TRUE && (iptcap->match_tcp == FALSE || iptcap->match_udp == FALSE || iptcap->match_icmp == FALSE))
    {
        vrmr_error(-1, "Error", "incomplete iptables-support in the kernel: tcp, udp or icmp support missing (in: %s:%d).",
            __FUNC__, __LINE__);
        return(-1);
    }

    /* require state match */
    if(iptcap->proc_net_matches == TRUE && iptcap->match_state == FALSE)
    {
        vrmr_error(-1, "Error", "incomplete iptables-support in the kernel: state support missing (in: %s:%d).",
            __FUNC__, __LINE__);
        return(-1);
    }

    if(iptcap->target_queue == TRUE && iptcap->queue_peer_pid == 0)
    {
        vrmr_warning("Warning", "no application is currently listening to the queue. Queue rules may be uneffective.");
    }

    return(0);
}

/**
 *  \retval 1 conntrack available
 *  \retval 0 not available
 */
static int check_conntrack(const int debuglvl, struct vrmr_config *cnf, int ipv) {
    char *args[] = { cnf->conntrack_location,
        "-L", "-f", "ipv4", NULL };

    if (ipv == VRMR_IPV6)
        args[3] = "ipv6";

    int result = libvuurmuur_exec_command(debuglvl, cnf, cnf->conntrack_location, args, NULL);
    if (result == -1) {
        vrmr_error(-1, "Error", "unable to execute "
                "conntrack: %s (in: %s:%d).", strerror(errno),
                __FUNC__, __LINE__);
        return 0;
    }
    return 1;
}

int
vrmr_load_iptcaps(const int debuglvl, struct vrmr_config *cnf, struct vrmr_iptcaps *iptcap, char load_modules)
{
    char    proc_net_match[]    = "/proc/net/ip_tables_matches",
            proc_net_target[]   = "/proc/net/ip_tables_targets",
            proc_net_names[]    = "/proc/net/ip_tables_names",
            proc_net_ipqueue[]  = "/proc/net/ip_queue",
            proc_net_netfilter_nfnetlink_queue[] = "/proc/net/netfilter/nfnetlink_queue",
            proc_net_ipconntrack[]  = VRMR_PROC_IPCONNTRACK,
            proc_net_nfconntrack[]  = VRMR_PROC_NFCONNTRACK;
    int     result = 0;


    /* safety */
    if(iptcap == NULL || cnf == NULL)
    {
        vrmr_error(-1, "Internal Error", "parameter problem (in: %s:%d).",
            __FUNC__, __LINE__);
        return(-1);
    }
    /* init */
    memset(iptcap, 0, sizeof(struct vrmr_iptcaps));

    /*
        PROC FILES
    */

    /* /proc/net/ip_tables_matches */
    if(!(iptcap_check_file(debuglvl, proc_net_match)))
    {
        if(debuglvl >= LOW)
            vrmr_debug(__FUNC__, "%s not found: load_modules: %s.",
                    proc_net_match, load_modules ? "Yes" : "No");

        if(load_modules == TRUE)
        {
            /* try to load the module */
            (void)iptcap_load_module(debuglvl, cnf, "ip_tables");

            /* check again */
            if(!(iptcap_check_file(debuglvl, proc_net_match)))
            {
                if(debuglvl >= LOW)
                    vrmr_debug(__FUNC__, "%s not still not found", proc_net_match);
            }
            else
            {
                if(debuglvl >= LOW)
                    vrmr_debug(__FUNC__, "%s found!", proc_net_match);

                iptcap->proc_net_matches = TRUE;
            }
        }
    }
    else
    {
        iptcap->proc_net_matches = TRUE;
    }

    /* /proc/net/ip_tables_targets */
    if(!(iptcap_check_file(debuglvl, proc_net_target)))
    {
        if(debuglvl >= LOW)
            vrmr_debug(__FUNC__, "%s not found: load_modules: %s.", 
                proc_net_target, load_modules ? "Yes" : "No");

        if(load_modules == TRUE)
        {
            /* try to load the module */
            (void)iptcap_load_module(debuglvl, cnf, "ip_tables");

            /* check again */
            if(!(iptcap_check_file(debuglvl, proc_net_target)))
            {
                if(debuglvl >= LOW)
                    vrmr_debug(__FUNC__, "%s not still not found", proc_net_target);
            }
            else
            {
                if(debuglvl >= LOW)
                    vrmr_debug(__FUNC__, "%s found!", proc_net_target);

                iptcap->proc_net_targets = TRUE;
            }
        }
    }
    else
    {
        iptcap->proc_net_targets = TRUE;
    }

    /* /proc/net/ip_tables_names */
    if(!(iptcap_check_file(debuglvl, proc_net_names)))
    {
        if(load_modules == TRUE)
        {
            /* try to load the module */
            (void)iptcap_load_module(debuglvl, cnf, "ip_tables");

            /* check again */
            if(!(iptcap_check_file(debuglvl, proc_net_names)))
            {
                if(debuglvl >= LOW)
                    vrmr_debug(__FUNC__, "%s not still not found", proc_net_names);
            }
            else
            {
                if(debuglvl >= LOW)
                    vrmr_debug(__FUNC__, "%s found!", proc_net_names);

                iptcap->proc_net_names = TRUE;
            }
        }
    }
    else
    {
        iptcap->proc_net_names = TRUE;
    }


    /*
        NAMES
    */
    if(iptcap->proc_net_names == TRUE)
    {
        result = iptcap_check_cap(debuglvl, cnf, proc_net_names, "filter", "iptable_filter", load_modules);
        if(result == 1) iptcap->table_filter = TRUE;
        else            iptcap->table_filter = FALSE;

        result = iptcap_check_cap(debuglvl, cnf, proc_net_names, "mangle", "iptable_mangle", load_modules);
        if(result == 1) iptcap->table_mangle = TRUE;
        else            iptcap->table_mangle = FALSE;

        result = iptcap_check_cap(debuglvl, cnf, proc_net_names, "nat", "iptable_nat", load_modules);
        if(result == 1) iptcap->table_nat = TRUE;
        else            iptcap->table_nat = FALSE;

        result = iptcap_check_cap(debuglvl, cnf, proc_net_names, "raw", "iptable_raw", load_modules);
        if(result == 1) iptcap->table_raw = TRUE;
        else            iptcap->table_raw = FALSE;
    }
    else
    {
        /* assume yes */
        iptcap->table_filter = TRUE;
        iptcap->table_mangle = TRUE;
        iptcap->table_nat    = TRUE;
        iptcap->table_raw    = TRUE;
    }


    /* check for the CONNTRACK */
    if ((check_conntrack(debuglvl, cnf, VRMR_IPV4) == 1) ||
            (iptcap_check_file(debuglvl, proc_net_ipconntrack)) ||
            (iptcap_check_file(debuglvl, proc_net_nfconntrack))) {
        iptcap->conntrack = TRUE;
    } else {
        if (load_modules == TRUE) {
            (void)iptcap_load_module(debuglvl, cnf, "ip_conntrack");
            (void)iptcap_load_module(debuglvl, cnf, "nf_conntrack_ipv4");

            if ((check_conntrack(debuglvl, cnf, VRMR_IPV4) == 1) ||
                    (iptcap_check_file(debuglvl, proc_net_ipconntrack)) ||
                    (iptcap_check_file(debuglvl, proc_net_nfconntrack))) {
                iptcap->conntrack = TRUE;
            } else {
                iptcap->conntrack = FALSE;
            }
        } else {
            iptcap->conntrack = FALSE;
        }
    }


    /* check for the QUEUE */
    if(!(iptcap_check_file(debuglvl, proc_net_ipqueue)))
    {
        if(load_modules == TRUE)
        {
            /* try to load the module, if it fails, return 0 */
            (void)iptcap_load_module(debuglvl, cnf, "ip_queue");

            /* check again */
            if(!(iptcap_check_file(debuglvl, proc_net_ipqueue)))
                iptcap->target_queue = 0;
            else
            {
                iptcap->target_queue = TRUE;

                if(iptcap_get_queue_peer_pid(debuglvl, iptcap) < 0)
                {
                    vrmr_error(-1, "Error", "getting queue peer pid failed (in: %s:%d).", __FUNC__, __LINE__);
                    return(-1);
                }
            }

        }
    }
    else
    {
        iptcap->target_queue = TRUE;

        if(iptcap_get_queue_peer_pid(debuglvl, iptcap) < 0)
        {
            vrmr_error(-1, "Error", "getting queue peer pid failed (in: %s:%d).", __FUNC__, __LINE__);
            return(-1);
        }
    }

    /* check for the /proc/net/netfilter/nfnetlink_queue */
    if(!(iptcap_check_file(debuglvl, proc_net_netfilter_nfnetlink_queue)))
    {
        if(load_modules == TRUE)
        {
            /* try to load the module, if it fails, return 0 */
            (void)iptcap_load_module(debuglvl, cnf, "nfnetlink_queue");

            /* check again */
            if((iptcap_check_file(debuglvl, proc_net_netfilter_nfnetlink_queue)))
            {
                iptcap->proc_net_netfilter_nfnetlink_queue = TRUE;
            }

        }
    }
    else
    {
        iptcap->proc_net_netfilter_nfnetlink_queue = TRUE;
    }

    /*
        MATCHES (uncapitalized)
    */
    if(iptcap->proc_net_matches == TRUE)
    {
        /* tcp */
        result = iptcap_check_cap(debuglvl, cnf, proc_net_match, "tcp", "ip_tables", load_modules);
        if(result == 1) iptcap->match_tcp = TRUE;
        else
        {
            iptcap->match_tcp = FALSE;

            /* from kernel 2.6.16 these are in xt_tcpudp */
            result = iptcap_check_cap(debuglvl, cnf, proc_net_match, "tcp", "xt_tcpudp", load_modules);
            if(result == 1) iptcap->match_tcp = TRUE;
        }

        /* udp */
        result = iptcap_check_cap(debuglvl, cnf, proc_net_match, "udp", "ip_tables", load_modules);
        if(result == 1) iptcap->match_udp = TRUE;
        else
        {
            iptcap->match_udp = FALSE;

            /* from kernel 2.6.16 these are in xt_tcpudp */
            result = iptcap_check_cap(debuglvl, cnf, proc_net_match, "udp", "xt_tcpudp", load_modules);
            if(result == 1) iptcap->match_udp = TRUE;
        }

        /*  icmp: in kernel 2.6.16 this is also supplied by
            ip_tables, while tcp and udp are no longer. */
        result = iptcap_check_cap(debuglvl, cnf, proc_net_match, "icmp", "ip_tables", load_modules);
        if(result == 1) iptcap->match_icmp = TRUE;
        else            iptcap->match_icmp = FALSE;

        /* state match */
        result = iptcap_check_cap(debuglvl, cnf, proc_net_match, "state", "ipt_state", load_modules);
        if(result == 1) iptcap->match_state = TRUE;
        else {
            iptcap->match_state = FALSE;

            result = iptcap_check_cap(debuglvl, cnf, proc_net_match, "state", "xt_state", load_modules);
            if(result == 1) iptcap->match_state = TRUE;
        }

        /* length match */
        result = iptcap_check_cap(debuglvl, cnf, proc_net_match, "length", "ipt_length", load_modules);
        if(result == 1) iptcap->match_length = TRUE;
        else {
            iptcap->match_length = FALSE;

            result = iptcap_check_cap(debuglvl, cnf, proc_net_match, "length", "xt_length", load_modules);
            if(result == 1) iptcap->match_length = TRUE;
        }

        /* limit match */
        result = iptcap_check_cap(debuglvl, cnf, proc_net_match, "limit", "ipt_limit", load_modules);
        if(result == 1) iptcap->match_limit = TRUE;
        else {
            iptcap->match_limit = FALSE;

            result = iptcap_check_cap(debuglvl, cnf, proc_net_match, "limit", "xt_limit", load_modules);
            if(result == 1) iptcap->match_limit = TRUE;
            else {
                iptcap->match_limit = FALSE;

                result = iptcap_test_filter_limit_match(debuglvl, cnf, cnf->iptables_location);
                if (result == 1)
                    iptcap->match_limit = TRUE;
            }
        }

        /* mark match */
        result = iptcap_check_cap(debuglvl, cnf, proc_net_match, "mark", "ipt_mark", load_modules);
        if(result == 1) iptcap->match_mark = TRUE;
        else {
            iptcap->match_mark = FALSE;

            result = iptcap_check_cap(debuglvl, cnf, proc_net_match, "mark", "xt_mark", load_modules);
            if(result == 1) iptcap->match_mark = TRUE;
            else {
                iptcap->match_mark = FALSE;

                result = iptcap_test_filter_mark_match(debuglvl, cnf, cnf->iptables_location);
                if (result == 1)
                    iptcap->match_mark = TRUE;
            }
        }

        /* mac match */
        result = iptcap_check_cap(debuglvl, cnf, proc_net_match, "mac", "ipt_mac", load_modules);
        if(result == 1) iptcap->match_mac = TRUE;
        else {
            iptcap->match_mac = FALSE;

            result = iptcap_check_cap(debuglvl, cnf, proc_net_match, "mac", "xt_mac", load_modules);
            if(result == 1) iptcap->match_mac = TRUE;
            else {
                iptcap->match_mac = FALSE;

                result = iptcap_test_filter_mac_match(debuglvl, cnf, cnf->iptables_location);
                if (result == 1)
                    iptcap->match_mac = TRUE;
            }
        }

        /* helper match */
        result = iptcap_check_cap(debuglvl, cnf, proc_net_match, "helper", "ipt_helper", load_modules);
        if(result == 1) iptcap->match_helper = TRUE;
        else {
            iptcap->match_helper = FALSE;

            result = iptcap_check_cap(debuglvl, cnf, proc_net_match, "helper", "xt_helper", load_modules);
            if(result == 1) iptcap->match_helper = TRUE;
            else {
                iptcap->match_helper = FALSE;

                result = iptcap_test_filter_helper_match(debuglvl, cnf, cnf->iptables_location);
                if (result == 1)
                    iptcap->match_helper = TRUE;
            }
        }

        /* connmark match */
        result = iptcap_check_cap(debuglvl, cnf, proc_net_match, "connmark", "ipt_connmark", load_modules);
        if(result == 1) iptcap->match_connmark = TRUE;
        else {
            iptcap->match_connmark = FALSE;

            result = iptcap_check_cap(debuglvl, cnf, proc_net_match, "connmark", "xt_connmark", load_modules);
            if(result == 1) iptcap->match_connmark = TRUE;
            else {
                iptcap->match_connmark = FALSE;

                result = iptcap_test_filter_connmark_match(debuglvl, cnf, cnf->iptables_location);
                if (result == 1)
                    iptcap->match_connmark = TRUE;
            }
        }

        /* conntrack match */
        result = iptcap_check_cap(debuglvl, cnf, proc_net_match, "conntrack", "ipt_conntrack", load_modules);
        if(result == 1) iptcap->match_conntrack = TRUE;
        else {
            iptcap->match_conntrack = FALSE;

            result = iptcap_check_cap(debuglvl, cnf, proc_net_match, "conntrack", "xt_conntrack", load_modules);
            if(result == 1) iptcap->match_conntrack = TRUE;
            else {
                iptcap->match_conntrack = FALSE;

                result = iptcap_test_filter_conntrack_match(debuglvl, cnf, cnf->iptables_location);
                if (result == 1)
                    iptcap->match_conntrack = TRUE;
            }
        }

        /* rpfilter match */
        result = iptcap_check_cap(debuglvl, cnf, proc_net_match, "rpfilter", "ipt_rpfilter", load_modules);
        if(result == 1) {
            result = iptcap_test_filter_rpfilter_match(debuglvl, cnf, cnf->iptables_location);
            if (result == 1)
                iptcap->match_rpfilter = TRUE;
            else
                iptcap->match_rpfilter = FALSE;
        } else {
            iptcap->match_rpfilter = FALSE;

            result = iptcap_check_cap(debuglvl, cnf, proc_net_match, "rpfilter", "xt_rpfilter", load_modules);
            if(result == 1)
                iptcap->match_rpfilter = TRUE;
            else
                iptcap->match_rpfilter = FALSE;
        }
        result = iptcap_test_filter_rpfilter_match(debuglvl, cnf, cnf->iptables_location);
        if (result == 1)
            iptcap->match_rpfilter = TRUE;
        else
            iptcap->match_rpfilter = FALSE;
    }
    else
    {
        /* assume yes */
        iptcap->match_tcp = TRUE;
        iptcap->match_udp = TRUE;
        iptcap->match_icmp = TRUE;

        iptcap->match_mark = TRUE;
        iptcap->match_state = TRUE;
        iptcap->match_helper = TRUE;
        iptcap->match_length = TRUE;
        iptcap->match_limit = TRUE;
        iptcap->match_mac = TRUE;
        iptcap->match_connmark = TRUE;
        iptcap->match_rpfilter = TRUE;
    }


    /*
        TARGETS (capitalized)
    */
    if(iptcap->proc_net_targets == TRUE)
    {
        /* NAT targets */
        if(iptcap->table_nat == TRUE)
        {
            /* DNAT target */
            result = iptcap_check_cap(debuglvl, cnf, proc_net_target, "DNAT", "iptable_nat", load_modules);
            if(result == 1) iptcap->target_dnat = TRUE;
            else            iptcap->target_dnat = FALSE;

            /* SNAT target */
            result = iptcap_check_cap(debuglvl, cnf, proc_net_target, "SNAT", "iptable_nat", load_modules);
            if(result == 1) iptcap->target_snat = TRUE;
            else            iptcap->target_snat = FALSE;

            /* REDIRECT target */
            result = iptcap_check_cap(debuglvl, cnf, proc_net_target, "REDIRECT", "ipt_REDIRECT", load_modules);
            if(result == 1) iptcap->target_redirect = TRUE;
            else            iptcap->target_redirect = FALSE;

            /* MASQUERADE target */
            result = iptcap_check_cap(debuglvl, cnf, proc_net_target, "MASQUERADE", "ipt_MASQUERADE", load_modules);
            if(result == 1) iptcap->target_masquerade = TRUE;
            else            iptcap->target_masquerade = FALSE;

            /* --random option for NAT */
            result = iptcap_test_nat_random(debuglvl, cnf);
            if (result == 1) iptcap->target_nat_random = TRUE;
            else             iptcap->target_nat_random = FALSE;
        }

        /* REJECT target */
        result = iptcap_check_cap(debuglvl, cnf, proc_net_target, "REJECT", "ipt_REJECT", load_modules);
        if(result == 1) iptcap->target_reject = TRUE;
        else {
            iptcap->target_reject = FALSE;

            result = iptcap_check_cap(debuglvl, cnf, proc_net_target, "REJECT", "xt_REJECT", load_modules);
            if(result == 1) iptcap->target_reject = TRUE;
        }

        /* LOG target */
        result = iptcap_check_cap(debuglvl, cnf, proc_net_target, "LOG", "ipt_LOG", load_modules);
        if(result == 1) iptcap->target_log = TRUE;
        else {
            iptcap->target_log = FALSE;

            result = iptcap_check_cap(debuglvl, cnf, proc_net_target, "LOG", "xt_LOG", load_modules);
            if(result == 1) iptcap->target_log = TRUE;
        }

        /* NFLOG target */
        result = iptcap_check_cap(debuglvl, cnf, proc_net_target, "NFLOG", "xt_NFLOG", load_modules);
        if(result == 1) iptcap->target_nflog = TRUE;
        else {
            iptcap->target_nflog = FALSE;

            result = iptcap_check_cap(debuglvl, cnf, proc_net_target, "NFLOG", "xt_NFLOG", load_modules);
            if(result == 1) iptcap->target_nflog = TRUE;
        }

        /* NFQUEUE target - this one is listed in /proc/net/ip_tables_targets */
        result = iptcap_check_cap(debuglvl, cnf, proc_net_target, "NFQUEUE", "ipt_NFQUEUE", load_modules);
        if(result == 1) iptcap->target_nfqueue = TRUE;
        else {
            iptcap->target_nfqueue = FALSE;

            result = iptcap_check_cap(debuglvl, cnf, proc_net_target, "NFQUEUE", "xt_NFQUEUE", load_modules);
            if(result == 1) iptcap->target_nfqueue = TRUE;
        }

        /* TCPMSS target - this one is listed in /proc/net/ip_tables_targets */
        result = iptcap_check_cap(debuglvl, cnf, proc_net_target, "TCPMSS", "ipt_TCPMSS", load_modules);
        if(result == 1) iptcap->target_tcpmss = TRUE;
        else {
            iptcap->target_tcpmss = FALSE;

            result = iptcap_check_cap(debuglvl, cnf, proc_net_target, "TCPMSS", "xt_TCPMSS", load_modules);
            if(result == 1) iptcap->target_tcpmss = TRUE;
        }

        /* mangle stuff */
        if(iptcap->table_mangle == TRUE)
        {
            /* MARK target */
            result = iptcap_check_cap(debuglvl, cnf, proc_net_target, "MARK", "ipt_MARK", load_modules);
            if(result == 1) iptcap->target_mark = TRUE;
            else {
                iptcap->target_mark = FALSE;

                result = iptcap_check_cap(debuglvl, cnf, proc_net_target, "MARK", "xt_MARK", load_modules);
                if(result == 1) iptcap->target_mark = TRUE;
                else {
                    iptcap->target_mark = FALSE;

                    result = iptcap_test_mangle_mark_target(debuglvl, cnf, cnf->iptables_location);
                    if (result == 1)
                        iptcap->target_mark = TRUE;
                }
            }

            /* CONNMARK target */
            result = iptcap_check_cap(debuglvl, cnf, proc_net_target, "CONNMARK", "ipt_CONNMARK", load_modules);
            if(result == 1) iptcap->target_connmark = TRUE;
            else {
                iptcap->target_connmark = FALSE;

                result = iptcap_check_cap(debuglvl, cnf, proc_net_target, "CONNMARK", "xt_CONNMARK", load_modules);
                if(result == 1) iptcap->target_connmark = TRUE;
                else {
                    iptcap->target_connmark = FALSE;

                    result = iptcap_test_filter_connmark_target(debuglvl, cnf, cnf->iptables_location);
                    if (result == 1)
                        iptcap->target_connmark = TRUE;
                }
            }

            /* CLASSIFY target */
            result = iptcap_check_cap(debuglvl, cnf, proc_net_target, "CLASSIFY", "ipt_CLASSIFY", load_modules);
            if(result == 1) iptcap->target_classify = TRUE;
            else {
                iptcap->target_classify = FALSE;

                result = iptcap_check_cap(debuglvl, cnf, proc_net_target, "CLASSIFY", "xt_CLASSIFY", load_modules);
                if(result == 1) iptcap->target_classify = TRUE;
                else {
                    iptcap->target_classify = FALSE;

                    result = iptcap_test_mangle_classify_target(debuglvl, cnf, cnf->iptables_location);
                    if (result == 1)
                        iptcap->target_classify = TRUE;
                }
            }
        }
    }
    else
    {
        /* assume yes */
        if(iptcap->table_nat == TRUE)
        {
            iptcap->target_snat = TRUE;
            iptcap->target_dnat = TRUE;
            iptcap->target_redirect = TRUE;
            iptcap->target_masquerade = TRUE;
        }

        iptcap->target_reject = TRUE;
        iptcap->target_log = TRUE;
        iptcap->target_nfqueue = TRUE;

        if(iptcap->table_mangle == TRUE)
        {
            iptcap->target_mark = TRUE;
            iptcap->target_connmark = TRUE;
            iptcap->target_classify = TRUE;
        }
    }

    return(0);
}

int
vrmr_check_ip6tcaps(const int debuglvl, struct vrmr_config *cnf, struct vrmr_iptcaps *iptcap, char load_modules)
{
    int result = 0;

    /* safety */
    if(iptcap == NULL || cnf == NULL)
    {
        vrmr_error(-1, "Internal Error", "parameter problem (in: %s:%d).",
            __FUNC__, __LINE__);
        return(-1);
    }

    /* load the caps */
    result = vrmr_load_ip6tcaps(debuglvl, cnf, iptcap, load_modules);
    if(result == -1)
    {
        vrmr_error(-1, "Error", "loading ip6tables capabilities failed (in: %s:%d).",
            __FUNC__, __LINE__);
        return(-1);
    }

    if(iptcap->proc_net_ip6_names == FALSE)
    {
        vrmr_warning("Warning", "'/proc/net/ip6_tables_names' missing: no ip6tables-support in the kernel?");
    }
    if(iptcap->proc_net_ip6_targets == FALSE)
    {
        vrmr_warning("Warning", "'/proc/net/ip6_tables_targets' missing: no ip6tables-support in the kernel?");
    }
    if(iptcap->proc_net_ip6_matches == FALSE)
    {
        vrmr_warning("Warning", "'/proc/net/ip6_tables_matches' missing: no ip6tables-support in the kernel?");
    }

    /* require the filter table */
    if(iptcap->proc_net_ip6_names == TRUE && iptcap->table_ip6_filter == FALSE)
    {
        vrmr_error(-1, "Error", "no ip6tables-support in the kernel: filter table missing (in: %s:%d).",
            __FUNC__, __LINE__);
        return(-1);
    }
    if(iptcap->proc_net_ip6_names == TRUE && iptcap->table_ip6_mangle == FALSE)
        vrmr_warning("Warning", "mangle table missing from kernel: mangle targets are unavailable.");

#if 0
    /* require conntrack */
    if(iptcap->conntrack == FALSE)
    {
        vrmr_error(-1, "Error", "no connection tracking support in the kernel (in: %s:%d).",
            __FUNC__, __LINE__);
        return(-1);
    }
#endif

    /* require tcp, udp, icmp */
    if(iptcap->proc_net_ip6_matches == TRUE && (iptcap->match_ip6_tcp == FALSE || iptcap->match_ip6_udp == FALSE || iptcap->match_icmp6 == FALSE))
    {
        vrmr_error(-1, "Error", "incomplete ip6tables-support in the kernel: tcp, udp or icmp6 support missing (in: %s:%d).",
            __FUNC__, __LINE__);
        return(-1);
    }

    /* require state match */
    if(iptcap->proc_net_ip6_matches == TRUE && iptcap->match_ip6_state == FALSE)
    {
        vrmr_error(-1, "Error", "incomplete ip6tables-support in the kernel: state support missing (in: %s:%d).",
            __FUNC__, __LINE__);
        return(-1);
    }

    if(iptcap->target_ip6_queue == TRUE && iptcap->ip6_queue_peer_pid == 0)
    {
        vrmr_warning("Warning", "no application is currently listening to the queue. Queue rules may be uneffective.");
    }

    return(0);
}

int
vrmr_load_ip6tcaps(const int debuglvl, struct vrmr_config *cnf, struct vrmr_iptcaps *iptcap, char load_modules)
{
    char    proc_net_ip6_match[] = "/proc/net/ip6_tables_matches",
            proc_net_ip6_target[] = "/proc/net/ip6_tables_targets",
            proc_net_ip6_names[] = "/proc/net/ip6_tables_names",
            proc_net_ip6queue[] = "/proc/net/ip6_queue";
/*
            proc_net_netfilter_nfnetlink_queue[] = "/proc/net/netfilter/nfnetlink_queue",
            proc_net_ipconntrack[]  = VRMR_PROC_IPCONNTRACK,
            proc_net_nfconntrack[]  = VRMR_PROC_NFCONNTRACK;
*/
    int     result = 0;


    /* safety */
    if(iptcap == NULL || cnf == NULL)
    {
        vrmr_error(-1, "Internal Error", "parameter problem (in: %s:%d).",
            __FUNC__, __LINE__);
        return(-1);
    }
    if(debuglvl >= LOW)
        vrmr_debug(__FUNC__, "Starting the loading of IPv6 capabilities" );
#if 0
    /* init */
    memset(iptcap, 0, sizeof(struct vrmr_iptcaps));
#endif

    /*
        PROC FILES
    */

    /* /proc/net/ip6_tables_matches */
    if(!(iptcap_check_file(debuglvl, proc_net_ip6_match)))
    {
        if(debuglvl >= LOW)
            vrmr_debug(__FUNC__, "%s not found: load_modules: %s.",
                    proc_net_ip6_match, load_modules ? "Yes" : "No");

        if(load_modules == TRUE)
        {
            /* try to load the module */
            (void)iptcap_load_module(debuglvl, cnf, "ip6_tables");

            /* check again */
            if(!(iptcap_check_file(debuglvl, proc_net_ip6_match)))
            {
                if(debuglvl >= LOW)
                    vrmr_debug(__FUNC__, "%s not still not found", proc_net_ip6_match);
            }
            else
            {
                if(debuglvl >= LOW)
                    vrmr_debug(__FUNC__, "%s found!", proc_net_ip6_match);

                iptcap->proc_net_ip6_matches = TRUE;
            }
        }
    }
    else
    {
        iptcap->proc_net_ip6_matches = TRUE;
    }

    /* /proc/net/ip6_tables_targets */
    if(!(iptcap_check_file(debuglvl, proc_net_ip6_target)))
    {
        if(debuglvl >= LOW)
            vrmr_debug(__FUNC__, "%s not found: load_modules: %s.", 
                proc_net_ip6_target, load_modules ? "Yes" : "No");

        if(load_modules == TRUE)
        {
            /* try to load the module */
            (void)iptcap_load_module(debuglvl, cnf, "ip6_tables");

            /* check again */
            if(!(iptcap_check_file(debuglvl, proc_net_ip6_target)))
            {
                if(debuglvl >= LOW)
                    vrmr_debug(__FUNC__, "%s not still not found", proc_net_ip6_target);
            }
            else
            {
                if(debuglvl >= LOW)
                    vrmr_debug(__FUNC__, "%s found!", proc_net_ip6_target);

                iptcap->proc_net_ip6_targets = TRUE;
            }
        }
    }
    else
    {
        iptcap->proc_net_ip6_targets = TRUE;
    }

    /* /proc/net/ip6_tables_names */
    if(!(iptcap_check_file(debuglvl, proc_net_ip6_names)))
    {
        if(load_modules == TRUE)
        {
            /* try to load the module */
            (void)iptcap_load_module(debuglvl, cnf, "ip6_tables");

            /* check again */
            if(!(iptcap_check_file(debuglvl, proc_net_ip6_names)))
            {
                if(debuglvl >= LOW)
                    vrmr_debug(__FUNC__, "%s not still not found", proc_net_ip6_names);
            }
            else
            {
                if(debuglvl >= LOW)
                    vrmr_debug(__FUNC__, "%s found!", proc_net_ip6_names);

                iptcap->proc_net_ip6_names = TRUE;
            }
        }
    }
    else
    {
        iptcap->proc_net_ip6_names = TRUE;
    }


    /*
        NAMES
    */
    if(iptcap->proc_net_ip6_names == TRUE)
    {
        result = iptcap_check_cap(debuglvl, cnf, proc_net_ip6_names, "filter", "ip6table_filter", load_modules);
        if(result == 1) iptcap->table_ip6_filter = TRUE;
        else            iptcap->table_ip6_filter = FALSE;

        result = iptcap_check_cap(debuglvl, cnf, proc_net_ip6_names, "mangle", "ip6table_mangle", load_modules);
        if(result == 1) iptcap->table_ip6_mangle = TRUE;
        else            iptcap->table_ip6_mangle = FALSE;

        result = iptcap_check_cap(debuglvl, cnf, proc_net_ip6_names, "raw", "ip6table_raw", load_modules);
        if(result == 1) iptcap->table_ip6_raw = TRUE;
        else            iptcap->table_ip6_raw = FALSE;
    }
    else
    {
        /* assume yes */
        iptcap->table_ip6_filter = TRUE;
        iptcap->table_ip6_mangle = TRUE;
        iptcap->table_ip6_raw = TRUE;
    }

#if 0
    /* check for the CONNTRACK */
    if(iptcap->conntrack == FALSE) {
        if(!(iptcap_check_file(debuglvl, proc_net_nfconntrack)))
        {
            if(load_modules == TRUE)
            {
                /* try to load the module, if it fails, return 0 */
                (void)iptcap_load_module(debuglvl, cnf, "nf_conntrack_ipv6");

                /* check again */
                if(!(iptcap_check_file(debuglvl, proc_net_nfconntrack)))
                    iptcap->conntrack = FALSE;
                else
                    iptcap->conntrack = TRUE;
            }
        }
        else
        {
            iptcap->conntrack = TRUE;
        }
    }
#endif

    /* check for the QUEUE */
    if(!(iptcap_check_file(debuglvl, proc_net_ip6queue)))
    {
        if(load_modules == TRUE)
        {
            /* try to load the module, if it fails, return 0 */
            (void)iptcap_load_module(debuglvl, cnf, "ip6_queue");

            /* check again */
            if(!(iptcap_check_file(debuglvl, proc_net_ip6queue)))
                iptcap->target_queue = 0;
            else
            {
                iptcap->target_queue = TRUE;

                if(iptcap_get_ip6_queue_peer_pid(debuglvl, iptcap) < 0)
                {
                    vrmr_error(-1, "Error", "getting queue peer pid failed (in: %s:%d).", __FUNC__, __LINE__);
                    return(-1);
                }
            }

        }
    }
    else
    {
        iptcap->target_queue = TRUE;

        if(iptcap_get_ip6_queue_peer_pid(debuglvl, iptcap) < 0)
        {
            vrmr_error(-1, "Error", "getting queue peer pid failed (in: %s:%d).", __FUNC__, __LINE__);
            return(-1);
        }
    }

#if 0
    /* check for the /proc/net/netfilter/nfnetlink_queue */
    if(!(iptcap_check_file(debuglvl, proc_net_netfilter_nfnetlink_queue)))
    {
        if(load_modules == TRUE)
        {
            /* try to load the module, if it fails, return 0 */
            (void)iptcap_load_module(debuglvl, cnf, "nfnetlink_queue");

            /* check again */
            if((iptcap_check_file(debuglvl, proc_net_netfilter_nfnetlink_queue)))
            {
                iptcap->proc_net_netfilter_nfnetlink_queue = TRUE;
            }

        }
    }
    else
    {
        iptcap->proc_net_netfilter_nfnetlink_queue = TRUE;
    }
#endif

    /*
        MATCHES (uncapitalized)
    */
    if(iptcap->proc_net_ip6_matches == TRUE)
    {
        /* tcp */
        result = iptcap_check_cap(debuglvl, cnf, proc_net_ip6_match, "tcp", "ip6_tables", load_modules);
        if(result == 1) iptcap->match_ip6_tcp = TRUE;
        else
        {
            iptcap->match_ip6_tcp = FALSE;

#if 0
            /* from kernel 2.6.16 these are in xt_tcpudp */
            result = iptcap_check_cap(debuglvl, cnf, proc_net_ip6_match, "tcp", "xt_tcpudp", load_modules);
            if(result == 1) iptcap->match_ip6_tcp = TRUE;
#endif
        }

        /* udp */
        result = iptcap_check_cap(debuglvl, cnf, proc_net_ip6_match, "udp", "ip6_tables", load_modules);
        if(result == 1) iptcap->match_ip6_udp = TRUE;
        else
        {
            iptcap->match_ip6_udp = FALSE;

#if 0
            /* from kernel 2.6.16 these are in xt_tcpudp */
            result = iptcap_check_cap(debuglvl, cnf, proc_net_ip6_match, "udp", "xt_tcpudp", load_modules);
            if(result == 1) iptcap->match_ip6_udp = TRUE;
#endif
        }

        /*  icmp: in kernel 2.6.16 this is also supplied by
            ip_tables, while tcp and udp are no longer. */
        result = iptcap_check_cap(debuglvl, cnf, proc_net_ip6_match, "icmp6", "ip6_tables", load_modules);
        if(result == 1) iptcap->match_icmp6 = TRUE;
        else            iptcap->match_icmp6 = FALSE;

        /* state match */
        result = iptcap_check_cap(debuglvl, cnf, proc_net_ip6_match, "state", "ipt_state", load_modules);
        if(result == 1) iptcap->match_ip6_state = TRUE;
        else {
            iptcap->match_ip6_state = FALSE;

            result = iptcap_check_cap(debuglvl, cnf, proc_net_ip6_match, "state", "xt_state", load_modules);
            if(result == 1) iptcap->match_ip6_state = TRUE;
        }

        /* length match */
        result = iptcap_check_cap(debuglvl, cnf, proc_net_ip6_match, "length", "ipt_length", load_modules);
        if(result == 1) iptcap->match_ip6_length = TRUE;
        else {
            iptcap->match_ip6_length = FALSE;

            result = iptcap_check_cap(debuglvl, cnf, proc_net_ip6_match, "length", "xt_length", load_modules);
            if(result == 1) iptcap->match_ip6_length = TRUE;
        }

        /* limit match */
        result = iptcap_check_cap(debuglvl, cnf, proc_net_ip6_match, "limit", "ipt_limit", load_modules);
        if(result == 1) iptcap->match_ip6_limit = TRUE;
        else {
            iptcap->match_ip6_limit = FALSE;

            result = iptcap_check_cap(debuglvl, cnf, proc_net_ip6_match, "limit", "xt_limit", load_modules);
            if(result == 1) iptcap->match_ip6_limit = TRUE;
            else {
                iptcap->match_ip6_limit = FALSE;

                result = iptcap_test_filter_limit_match(debuglvl, cnf, cnf->ip6tables_location);
                if (result == 1)
                    iptcap->match_ip6_limit = TRUE;
            }
        }

        /* mark match */
        result = iptcap_check_cap(debuglvl, cnf, proc_net_ip6_match, "mark", "ipt_mark", load_modules);
        if(result == 1) iptcap->match_ip6_mark = TRUE;
        else {
            iptcap->match_ip6_mark = FALSE;

            result = iptcap_check_cap(debuglvl, cnf, proc_net_ip6_match, "mark", "xt_mark", load_modules);
            if(result == 1) iptcap->match_ip6_mark = TRUE;
            else {
                iptcap->match_ip6_mark = FALSE;

                result = iptcap_test_filter_mark_match(debuglvl, cnf, cnf->ip6tables_location);
                if (result == 1)
                    iptcap->match_ip6_mark = TRUE;
            }
        }

        /* mac match */
        result = iptcap_check_cap(debuglvl, cnf, proc_net_ip6_match, "mac", "ipt_mac", load_modules);
        if(result == 1) iptcap->match_ip6_mac = TRUE;
        else {
            iptcap->match_ip6_mac = FALSE;

            result = iptcap_check_cap(debuglvl, cnf, proc_net_ip6_match, "mac", "xt_mac", load_modules);
            if(result == 1) iptcap->match_ip6_mac = TRUE;
            else {
                iptcap->match_ip6_mac = FALSE;

                result = iptcap_test_filter_mac_match(debuglvl, cnf, cnf->ip6tables_location);
                if (result == 1)
                    iptcap->match_ip6_mac = TRUE;
            }
        }

        /* helper match */
        result = iptcap_check_cap(debuglvl, cnf, proc_net_ip6_match, "helper", "ipt_helper", load_modules);
        if(result == 1) iptcap->match_ip6_helper = TRUE;
        else {
            iptcap->match_ip6_helper = FALSE;

            result = iptcap_check_cap(debuglvl, cnf, proc_net_ip6_match, "helper", "xt_helper", load_modules);
            if(result == 1) iptcap->match_ip6_helper = TRUE;
            else {
                iptcap->match_ip6_helper = FALSE;

                result = iptcap_test_filter_helper_match(debuglvl, cnf, cnf->ip6tables_location);
                if (result == 1)
                    iptcap->match_ip6_helper = TRUE;
            }
        }

        /* connmark match */
        result = iptcap_check_cap(debuglvl, cnf, proc_net_ip6_match, "connmark", "ipt_connmark", load_modules);
        if(result == 1) iptcap->match_ip6_connmark = TRUE;
        else {
            iptcap->match_ip6_connmark = FALSE;

            result = iptcap_check_cap(debuglvl, cnf, proc_net_ip6_match, "connmark", "xt_connmark", load_modules);
            if(result == 1) iptcap->match_ip6_connmark = TRUE;
            else {
                iptcap->match_ip6_connmark = FALSE;

                result = iptcap_test_filter_connmark_match(debuglvl, cnf, cnf->ip6tables_location);
                if (result == 1)
                    iptcap->match_ip6_connmark = TRUE;
            }
        }

        /* conntrack match */
        result = iptcap_check_cap(debuglvl, cnf, proc_net_ip6_match, "conntrack", "ipt_conntrack", load_modules);
        if(result == 1) iptcap->match_ip6_conntrack = TRUE;
        else {
            iptcap->match_ip6_conntrack = FALSE;

            result = iptcap_check_cap(debuglvl, cnf, proc_net_ip6_match, "conntrack", "xt_conntrack", load_modules);
            if(result == 1) iptcap->match_ip6_conntrack = TRUE;
            else {
                iptcap->match_ip6_conntrack = FALSE;

                result = iptcap_test_filter_conntrack_match(debuglvl, cnf, cnf->ip6tables_location);
                if (result == 1)
                    iptcap->match_ip6_conntrack = TRUE;
            }
        }

        /* rpfilter match */
        result = iptcap_check_cap(debuglvl, cnf, proc_net_ip6_match, "rpfilter", "ip6t_rpfilter", load_modules);
        if(result == 1)
            iptcap->match_ip6_rpfilter = TRUE;
        else {
            iptcap->match_ip6_rpfilter = FALSE;

            result = iptcap_check_cap(debuglvl, cnf, proc_net_ip6_match, "rpfilter", "xt_rpfilter", load_modules);
            if(result == 1)
                iptcap->match_ip6_rpfilter = TRUE;
            else
                iptcap->match_ip6_rpfilter = FALSE;
        }
        result = iptcap_test_filter_rpfilter_match(debuglvl, cnf, cnf->ip6tables_location);
        if (result == 1)
            iptcap->match_ip6_rpfilter = TRUE;
        else
            iptcap->match_ip6_rpfilter = FALSE;
    }
    else
    {
        /* assume yes */
        iptcap->match_ip6_tcp = TRUE;
        iptcap->match_ip6_udp = TRUE;
        iptcap->match_icmp6 = TRUE;

        iptcap->match_ip6_mark = TRUE;
        iptcap->match_ip6_state = TRUE;
        iptcap->match_ip6_helper = TRUE;
        iptcap->match_ip6_length = TRUE;
        iptcap->match_ip6_limit = TRUE;
        iptcap->match_ip6_mac = TRUE;
        iptcap->match_ip6_connmark = TRUE;
        iptcap->match_ip6_rpfilter = TRUE;
    }


    /*
        TARGETS (capitalized)
    */
    if(iptcap->proc_net_ip6_targets == TRUE)
    {
        /* REJECT target */
        result = iptcap_check_cap(debuglvl, cnf, proc_net_ip6_target, "REJECT", "ip6t_REJECT", load_modules);
        if(result == 1) iptcap->target_ip6_reject = TRUE;
        else {
            iptcap->target_ip6_reject = FALSE;

            /* TODO Check if this module really exists */
            result = iptcap_check_cap(debuglvl, cnf, proc_net_ip6_target, "REJECT", "xt_REJECT", load_modules);
            if(result == 1) iptcap->target_ip6_reject = TRUE;
        }

        /* LOG target */
        result = iptcap_check_cap(debuglvl, cnf, proc_net_ip6_target, "LOG", "ip6t_LOG", load_modules);
        if(result == 1) iptcap->target_ip6_log = TRUE;
        else {
            iptcap->target_ip6_log = FALSE;

            /* TODO Check if this module really exists */
            result = iptcap_check_cap(debuglvl, cnf, proc_net_ip6_target, "LOG", "xt_LOG", load_modules);
            if(result == 1) iptcap->target_ip6_log = TRUE;
        }

        /* NFQUEUE target - this one is listed in /proc/net/ip_tables_targets */
        result = iptcap_check_cap(debuglvl, cnf, proc_net_ip6_target, "NFQUEUE", "ipt_NFQUEUE", load_modules);
        if(result == 1) iptcap->target_ip6_nfqueue = TRUE;
        else {
            iptcap->target_ip6_nfqueue = FALSE;

            result = iptcap_check_cap(debuglvl, cnf, proc_net_ip6_target, "NFQUEUE", "xt_NFQUEUE", load_modules);
            if(result == 1) iptcap->target_ip6_nfqueue = TRUE;
        }

        /* TCPMSS target - this one is listed in /proc/net/ip_tables_targets */
        result = iptcap_check_cap(debuglvl, cnf, proc_net_ip6_target, "TCPMSS", "ipt_TCPMSS", load_modules);
        if(result == 1) iptcap->target_ip6_tcpmss = TRUE;
        else {
            iptcap->target_ip6_tcpmss = FALSE;

            result = iptcap_check_cap(debuglvl, cnf, proc_net_ip6_target, "TCPMSS", "xt_TCPMSS", load_modules);
            if(result == 1) iptcap->target_ip6_tcpmss = TRUE;
        }

        /* mangle stuff */
        if(iptcap->table_ip6_mangle == TRUE)
        {
            /* MARK target */
            result = iptcap_check_cap(debuglvl, cnf, proc_net_ip6_target, "MARK", "ipt_MARK", load_modules);
            if(result == 1) iptcap->target_ip6_mark = TRUE;
            else {
                iptcap->target_ip6_mark = FALSE;

                result = iptcap_check_cap(debuglvl, cnf, proc_net_ip6_target, "MARK", "xt_MARK", load_modules);
                if(result == 1) iptcap->target_ip6_mark = TRUE;
                else {
                    iptcap->target_ip6_mark = FALSE;

                    result = iptcap_test_mangle_mark_target(debuglvl, cnf, cnf->ip6tables_location);
                    if (result == 1)
                        iptcap->target_ip6_mark = TRUE;
                }
            }

            /* CONNMARK target */
            result = iptcap_check_cap(debuglvl, cnf, proc_net_ip6_target, "CONNMARK", "ipt_CONNMARK", load_modules);
            if(result == 1) iptcap->target_ip6_connmark = TRUE;
            else {
                iptcap->target_ip6_connmark = FALSE;

                result = iptcap_check_cap(debuglvl, cnf, proc_net_ip6_target, "CONNMARK", "xt_CONNMARK", load_modules);
                if(result == 1) iptcap->target_ip6_connmark = TRUE;
                else {
                    iptcap->target_ip6_connmark = FALSE;

                    result = iptcap_test_filter_connmark_target(debuglvl, cnf, cnf->ip6tables_location);
                    if (result == 1)
                        iptcap->target_ip6_connmark = TRUE;
                }
            }

            /* CLASSIFY target */
            result = iptcap_check_cap(debuglvl, cnf, proc_net_ip6_target, "CLASSIFY", "ipt_CLASSIFY", load_modules);
            if(result == 1) iptcap->target_ip6_classify = TRUE;
            else {
                iptcap->target_ip6_classify = FALSE;

                result = iptcap_check_cap(debuglvl, cnf, proc_net_ip6_target, "CLASSIFY", "xt_CLASSIFY", load_modules);
                if(result == 1) iptcap->target_ip6_classify = TRUE;
                else {
                    iptcap->target_ip6_classify = FALSE;

                    result = iptcap_test_mangle_classify_target(debuglvl, cnf, cnf->ip6tables_location);
                    if (result == 1)
                        iptcap->target_ip6_classify = TRUE;
                }
            }
        }
    }
    else
    {
        /* assume yes */
        iptcap->target_ip6_reject = TRUE;
        iptcap->target_ip6_log = TRUE;
        iptcap->target_ip6_nfqueue = TRUE;

        if(iptcap->table_ip6_mangle == TRUE)
        {
            iptcap->target_ip6_mark = TRUE;
            iptcap->target_ip6_connmark = TRUE;
            iptcap->target_ip6_classify = TRUE;
        }
    }

    return(0);

}

