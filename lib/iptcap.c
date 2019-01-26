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

/*
    functions for detecting the capabilities of Iptables on the
    system.
*/

#include "config.h"
#include "vuurmuur.h"

static int iptcap_get_one_cap_from_proc(
        const char *procpath, const char *request)
{
    char line[64] = "";
    FILE *fp = NULL;
    int retval = 0;

    assert(procpath && request);

    /* open the matches */
    if (!(fp = fopen(procpath, "r"))) {
        vrmr_error(-1, "Error", "could not open '%s': %s", procpath,
                strerror(errno));
        return (-1);
    }

    /* now loop through the file */
    while (fgets(line, (int)sizeof(line), fp) != NULL) {
        /* strip the newline if there is one */
        if (line[strlen(line) - 1] == '\n')
            line[strlen(line) - 1] = '\0';

        vrmr_debug(HIGH, "%s: '%s'.", procpath, line);

        /* compare the line with the request */
        if (strcmp(line, request) == 0) {
            vrmr_debug(MEDIUM, "%s: '%s' match!.", procpath, line);
            retval = 1;
            break;
        }
    }

    /* close the file */
    if (fclose(fp) == -1) {
        vrmr_error(-1, "Error", "could not close '%s': %s", procpath,
                strerror(errno));
        return (-1);
    }

    vrmr_debug(LOW, "procpath: %s request: %s retval: %u", procpath, request,
            retval);

    /* return retval, 1 if found, 0 if not found */
    return (retval);
}

/*
    -1: error
     0: ok
*/
static int iptcap_load_module(struct vrmr_config *cnf, const char *modulename)
{
    assert(modulename && cnf);

    /* now execute the command */
    const char *args[] = {cnf->modprobe_location, "-q", modulename, NULL};
    int r = libvuurmuur_exec_command(cnf, cnf->modprobe_location, args, NULL);
    if (r != 0) {
        vrmr_debug(LOW, "loading module '%s' failed: modprobe returned %d.",
                modulename, r);
        return (-1);
    }

    vrmr_debug(LOW, "loading module '%s' success, modprobe returned %d.",
            modulename, r);
    return (0);
}

static int iptcap_check_cap(struct vrmr_config *cnf, const char *procpath,
        const char *request, const char *modulename, char load_module)
{
    assert(procpath && request && modulename && cnf);

    /* get the cap */
    int result = iptcap_get_one_cap_from_proc(procpath, request);
    if (result < 0) {
        vrmr_error(-1, "Error", "getting iptcap for '%s' failed", request);
        return (-1);
    } else if (result == 0) {
        vrmr_debug(LOW, "'%s' not loaded or not supported.", request);
    } else {
        vrmr_debug(LOW, "'%s' supported and loaded.", request);

        /* and done :-) */
        return (1);
    }

    /* if load_modules == FALSE we bail out now */
    if (load_module == FALSE)
        return (0);

    /* try to load the module, if it fails we don't care */
    (void)iptcap_load_module(cnf, modulename);

    /* sleep for a short time if requested */
    if (cnf->modules_wait_time > 0) {
        vrmr_debug(LOW, "after loading the module, usleep for %lu.",
                (unsigned long)(cnf->modules_wait_time * 10000));

        usleep(cnf->modules_wait_time * 10000);
    }

    /* try get the cap again */
    result = iptcap_get_one_cap_from_proc(procpath, request);
    if (result < 0) {
        vrmr_error(-1, "Error", "getting iptcap for '%s' failed", request);
        return (-1);
    } else if (result == 0) {
        vrmr_debug(LOW, "'%s' not supported.", request);
    } else {
        vrmr_debug(LOW, "'%s' supported and loaded.", request);

        /* and done :-) */
        return (1);
    }

    return (0);
}

/*
    return 1 if file exists, 0 if not.
*/
static int iptcap_check_file(char *path)
{
    assert(path);

    FILE *fp = NULL;
    if (!(fp = fopen(path, "r")))
        return (0);

    fclose(fp);
    return (1);
}

static int iptcap_create_test_chain(
        struct vrmr_config *cnf, const char *ipt_loc, const char *table)
{
    const char *args[] = {ipt_loc, "-t", table, "-N", "VRMRIPTCAP", NULL};
    int r = libvuurmuur_exec_command(cnf, ipt_loc, args, NULL);
    if (r != 0) {
        return -1;
    }

    return 0;
}

static int iptcap_delete_test_chain(
        struct vrmr_config *cnf, const char *ipt_loc, const char *table)
{
    /* First, flush the chain */
    const char *argsF[] = {ipt_loc, "-t", table, "-F", "VRMRIPTCAP", NULL};
    int r = libvuurmuur_exec_command(cnf, ipt_loc, argsF, NULL);
    if (r != 0) {
        vrmr_debug(LOW, "flush %s failed (ok if chain didn't exist)", table);
        return -1;
    }

    /* And then delete the chain */
    const char *argsX[] = {ipt_loc, "-t", table, "-X", "VRMRIPTCAP", NULL};
    r = libvuurmuur_exec_command(cnf, ipt_loc, argsX, NULL);
    if (r != 0) {
        vrmr_debug(LOW, "delete %s failed", table);
        return -1;
    }

    return 0;
}

static int iptcap_test_filter_connmark_match(
        struct vrmr_config *cnf, const char *ipt_loc)
{
    int retval = 1;

    if (iptcap_delete_test_chain(cnf, ipt_loc, "filter") < 0) {
        vrmr_debug(NONE, "iptcap_delete_test_chain failed, but error "
                         "will be ignored");
    }

    if (iptcap_create_test_chain(cnf, ipt_loc, "filter") < 0) {
        vrmr_debug(NONE, "iptcap_create_test_chain failed");
        return -1;
    }

    const char *args[] = {ipt_loc, "-t", "filter", "-A", "VRMRIPTCAP", "-m",
            "connmark", "--mark", "1", NULL};
    int r = libvuurmuur_exec_command(cnf, ipt_loc, args, NULL);
    if (r != 0) {
        vrmr_debug(NONE, "r = %d", r);
        retval = -1;
    }

    if (iptcap_delete_test_chain(cnf, ipt_loc, "filter") < 0) {
        vrmr_debug(NONE, "iptcap_delete_test_chain failed, but error "
                         "will be ignored");
    }

    return retval;
}

static int iptcap_test_filter_conntrack_match(
        struct vrmr_config *cnf, const char *ipt_loc)
{
    int retval = 1;

    if (iptcap_delete_test_chain(cnf, ipt_loc, "filter") < 0) {
        vrmr_debug(NONE, "iptcap_delete_test_chain failed, but error "
                         "will be ignored");
    }

    if (iptcap_create_test_chain(cnf, ipt_loc, "filter") < 0) {
        vrmr_debug(NONE, "iptcap_create_test_filter_chain failed");
        return -1;
    }

    const char *args[] = {ipt_loc, "-t", "filter", "-A", "VRMRIPTCAP", "-m",
            "conntrack", "--ctstate", "NEW", NULL};
    int r = libvuurmuur_exec_command(cnf, ipt_loc, args, NULL);
    if (r != 0) {
        vrmr_debug(NONE, "r = %d", r);
        retval = -1;
    }

    if (iptcap_delete_test_chain(cnf, ipt_loc, "filter") < 0) {
        vrmr_debug(NONE, "iptcap_delete_test_filter_chain failed, but error "
                         "will be ignored");
    }

    return retval;
}

/** \internal
 *  \brief test rpfilter module in RAW table
 */
static int iptcap_test_filter_rpfilter_match(
        struct vrmr_config *cnf, const char *ipt_loc)
{
    int retval = 1;

    if (iptcap_delete_test_chain(cnf, ipt_loc, "raw") < 0) {
        vrmr_debug(NONE, "iptcap_delete_test_filter_chain failed, but error "
                         "will be ignored");
    }

    if (iptcap_create_test_chain(cnf, ipt_loc, "raw") < 0) {
        vrmr_debug(NONE, "iptcap_create_test_filter_chain failed");
        return -1;
    }

    const char *args[] = {ipt_loc, "-t", "raw", "-A", "VRMRIPTCAP", "-m",
            "rpfilter", "--invert", NULL};
    int r = libvuurmuur_exec_command(cnf, ipt_loc, args, NULL);
    if (r != 0) {
        vrmr_debug(NONE, "r = %d", r);
        retval = -1;
    }

    if (iptcap_delete_test_chain(cnf, ipt_loc, "raw") < 0) {
        vrmr_debug(NONE, "iptcap_delete_test_filter_chain failed, but error "
                         "will be ignored");
    }

    return retval;
}

static int iptcap_test_mangle_connmark_target(
        struct vrmr_config *cnf, const char *ipt_loc)
{
    int retval = 1;

    if (iptcap_delete_test_chain(cnf, ipt_loc, "mangle") < 0) {
        vrmr_debug(NONE, "iptcap_delete_test_chain failed, but error "
                         "will be ignored");
    }

    if (iptcap_create_test_chain(cnf, ipt_loc, "mangle") < 0) {
        vrmr_debug(NONE, "iptcap_create_test_chain failed");
        return -1;
    }

    const char *args[] = {ipt_loc, "-t", "mangle", "-A", "VRMRIPTCAP", "-j",
            "CONNMARK", "--set-mark", "1", NULL};
    int r = libvuurmuur_exec_command(cnf, ipt_loc, args, NULL);
    if (r != 0) {
        vrmr_debug(NONE, "r = %d", r);
        retval = -1;
    }

    if (iptcap_delete_test_chain(cnf, ipt_loc, "mangle") < 0) {
        vrmr_debug(NONE, "iptcap_delete_test_chain failed, but error "
                         "will be ignored");
    }

    return retval;
}

static int iptcap_test_filter_helper_match(
        struct vrmr_config *cnf, const char *ipt_loc)
{
    int retval = 1;

    if (iptcap_delete_test_chain(cnf, ipt_loc, "filter") < 0) {
        vrmr_debug(NONE, "iptcap_delete_test_chain failed, but error "
                         "will be ignored");
    }

    if (iptcap_create_test_chain(cnf, ipt_loc, "filter") < 0) {
        vrmr_debug(NONE, "iptcap_create_test_chain failed");
        return -1;
    }

    const char *args[] = {ipt_loc, "-t", "filter", "-A", "VRMRIPTCAP", "-m",
            "helper", "--helper", "ftp", NULL};
    int r = libvuurmuur_exec_command(cnf, ipt_loc, args, NULL);
    if (r != 0) {
        vrmr_debug(NONE, "r = %d", r);
        retval = -1;
    }

    if (iptcap_delete_test_chain(cnf, ipt_loc, "filter") < 0) {
        vrmr_debug(NONE, "iptcap_delete_test_chain failed, but error "
                         "will be ignored");
    }

    return retval;
}

static int iptcap_test_filter_mark_match(
        struct vrmr_config *cnf, const char *ipt_loc)
{
    int retval = 1;

    if (iptcap_delete_test_chain(cnf, ipt_loc, "filter") < 0) {
        vrmr_debug(NONE, "iptcap_delete_test_chain failed, but error "
                         "will be ignored");
    }

    if (iptcap_create_test_chain(cnf, ipt_loc, "filter") < 0) {
        vrmr_debug(NONE, "iptcap_create_test_chain failed");
        return -1;
    }

    const char *args[] = {ipt_loc, "-t", "filter", "-A", "VRMRIPTCAP", "-m",
            "mark", "--mark", "1", NULL};
    int r = libvuurmuur_exec_command(cnf, ipt_loc, args, NULL);
    if (r != 0) {
        vrmr_debug(NONE, "r = %d", r);
        retval = -1;
    }

    if (iptcap_delete_test_chain(cnf, ipt_loc, "filter") < 0) {
        vrmr_debug(NONE, "iptcap_delete_test_chain failed, but error "
                         "will be ignored");
    }

    return retval;
}

static int iptcap_test_mangle_mark_target(
        struct vrmr_config *cnf, const char *ipt_loc)
{
    int retval = 1;

    if (iptcap_delete_test_chain(cnf, ipt_loc, "mangle") < 0) {
        vrmr_debug(NONE, "iptcap_delete_test_chain failed, but error "
                         "will be ignored");
    }

    if (iptcap_create_test_chain(cnf, ipt_loc, "mangle") < 0) {
        vrmr_debug(NONE, "iptcap_create_test_chain failed");
        return -1;
    }

    const char *args[] = {ipt_loc, "-t", "mangle", "-A", "VRMRIPTCAP", "-j",
            "MARK", "--set-mark", "1", NULL};
    int r = libvuurmuur_exec_command(cnf, ipt_loc, args, NULL);
    if (r != 0) {
        vrmr_debug(NONE, "r = %d", r);
        retval = -1;
    }

    if (iptcap_delete_test_chain(cnf, ipt_loc, "mangle") < 0) {
        vrmr_debug(NONE, "iptcap_delete_test_chain failed, but error "
                         "will be ignored");
    }

    return retval;
}

static int iptcap_test_mangle_classify_target(
        struct vrmr_config *cnf, const char *ipt_loc)
{
    int retval = 1;

    if (iptcap_delete_test_chain(cnf, ipt_loc, "mangle") < 0) {
        vrmr_debug(NONE, "iptcap_delete_test_chain failed, but error "
                         "will be ignored");
    }

    if (iptcap_create_test_chain(cnf, ipt_loc, "mangle") < 0) {
        vrmr_debug(NONE, "iptcap_create_test_chain failed");
        return -1;
    }

    const char *args[] = {ipt_loc, "-t", "mangle", "-A", "VRMRIPTCAP", "-j",
            "CLASSIFY", "--set-class", "0:0", NULL};
    int r = libvuurmuur_exec_command(cnf, ipt_loc, args, NULL);
    if (r != 0) {
        vrmr_debug(NONE, "r = %d", r);
        retval = -1;
    }

    if (iptcap_delete_test_chain(cnf, ipt_loc, "mangle") < 0) {
        vrmr_debug(NONE, "iptcap_delete_test_chain failed, but error "
                         "will be ignored");
    }

    return retval;
}

static int iptcap_test_filter_mac_match(
        struct vrmr_config *cnf, const char *ipt_loc)
{
    int retval = 1;

    if (iptcap_delete_test_chain(cnf, ipt_loc, "filter") < 0) {
        vrmr_debug(NONE, "iptcap_delete_test_chain failed, but error "
                         "will be ignored");
    }

    if (iptcap_create_test_chain(cnf, ipt_loc, "filter") < 0) {
        vrmr_debug(NONE, "iptcap_create_test_chain failed");
        return -1;
    }

    const char *args[] = {ipt_loc, "-t", "filter", "-A", "VRMRIPTCAP", "-m",
            "mac", "--mac-source", "12:34:56:78:90:ab", NULL};
    int r = libvuurmuur_exec_command(cnf, ipt_loc, args, NULL);
    if (r != 0) {
        vrmr_debug(NONE, "r = %d", r);
        retval = -1;
    }

    if (iptcap_delete_test_chain(cnf, ipt_loc, "filter") < 0) {
        vrmr_debug(NONE, "iptcap_delete_test_chain failed, but error "
                         "will be ignored");
    }

    return retval;
}

/**
 * \param[in] cnf The vuurmuur configuration
 * \param[in] ipt_loc The full path to the ip[6]tables program. You should
 *      cnf.iptables_location or cnf.ip6tables_location for this.
 */
static int iptcap_test_filter_limit_match(
        struct vrmr_config *cnf, const char *ipt_loc)
{
    int retval = 1;

    assert(ipt_loc);

    if (iptcap_delete_test_chain(cnf, ipt_loc, "filter") < 0) {
        vrmr_debug(NONE, "iptcap_delete_test_chain failed, but error "
                         "will be ignored");
    }

    if (iptcap_create_test_chain(cnf, ipt_loc, "filter") < 0) {
        vrmr_debug(NONE, "iptcap_create_test_chain failed");
        return -1;
    }

    const char *args[] = {ipt_loc, "-t", "filter", "-A", "VRMRIPTCAP", "-m",
            "limit", "--limit", "1/s", NULL};
    int r = libvuurmuur_exec_command(cnf, ipt_loc, args, NULL);
    if (r != 0) {
        vrmr_debug(NONE, "r = %d", r);
        retval = -1;
    }

    if (iptcap_delete_test_chain(cnf, ipt_loc, "filter") < 0) {
        vrmr_debug(NONE, "iptcap_delete_test_chain failed, but error "
                         "will be ignored");
    }

    return retval;
}

static int iptcap_test_nat_random(struct vrmr_config *cnf, const char *ipt_loc)
{
    int retval = 1;

    if (iptcap_delete_test_chain(cnf, ipt_loc, "nat") < 0) {
        vrmr_debug(NONE, "iptcap_delete_test_chain failed, but error will "
                         "be ignored");
    }

    if (iptcap_create_test_chain(cnf, ipt_loc, "nat") < 0) {
        vrmr_debug(NONE, "iptcap_create_test_chain failed");
        return -1;
    }

    const char *args[] = {cnf->iptables_location, "-t", "nat", "-A",
            "VRMRIPTCAP", "-j", "SNAT", "--to-source", "127.0.0.1", "--random",
            NULL};
    int r = libvuurmuur_exec_command(cnf, cnf->iptables_location, args, NULL);
    if (r != 0) {
        vrmr_debug(NONE, "r = %d", r);
        retval = -1;
    }

    if (iptcap_delete_test_chain(cnf, ipt_loc, "nat") < 0) {
        vrmr_debug(NONE, "iptcap_delete_test_chain failed, but error will "
                         "be ignored");
    }

    return retval;
}

int vrmr_check_iptcaps(
        struct vrmr_config *cnf, struct vrmr_iptcaps *iptcap, bool load_modules)
{
    assert(iptcap != NULL && cnf != NULL);

    /* load the caps */
    int result = vrmr_load_iptcaps(cnf, iptcap, load_modules);
    if (result == -1) {
        vrmr_error(-1, "Error", "loading iptables capabilities failed");
        return (-1);
    }

    if (iptcap->proc_net_names == FALSE) {
        vrmr_warning("Warning", "'/proc/net/ip_tables_names' missing: no "
                                "iptables-support in the kernel?");
    }
    if (iptcap->proc_net_targets == FALSE) {
        vrmr_warning("Warning", "'/proc/net/ip_tables_targets' missing: no "
                                "iptables-support in the kernel?");
    }
    if (iptcap->proc_net_matches == FALSE) {
        vrmr_warning("Warning", "'/proc/net/ip_tables_matches' missing: no "
                                "iptables-support in the kernel?");
    }

    /* require the filter table */
    if (iptcap->proc_net_names == TRUE && iptcap->table_filter == FALSE) {
        vrmr_error(-1, "Error",
                "no iptables-support in the kernel: filter table missing");
        return (-1);
    }
    if (iptcap->proc_net_names == TRUE && iptcap->table_nat == FALSE)
        vrmr_warning("Warning",
                "nat table missing from kernel: nat targets are unavailable.");
    if (iptcap->proc_net_names == TRUE && iptcap->table_mangle == FALSE)
        vrmr_warning("Warning", "mangle table missing from kernel: mangle "
                                "targets are unavailable.");

    /* require conntrack */
    if (iptcap->conntrack == FALSE) {
        vrmr_error(-1, "Error", "no connection tracking support in the kernel");
        return (-1);
    }

    /* require tcp, udp, icmp */
    if (iptcap->proc_net_matches == TRUE &&
            (iptcap->match_tcp == FALSE || iptcap->match_udp == FALSE ||
                    iptcap->match_icmp == FALSE)) {
        vrmr_error(-1, "Error",
                "incomplete iptables-support in the kernel: tcp, udp or icmp "
                "support missing");
        return (-1);
    }

    /* require state match */
    if (iptcap->proc_net_matches == TRUE && iptcap->match_state == FALSE) {
        vrmr_error(-1, "Error",
                "incomplete iptables-support in the kernel: state support "
                "missing");
        return (-1);
    }

    return (0);
}

static bool iptcap_check_cap_modules(struct vrmr_config *cnf,
        const char *check_file, const char *check_name, bool load_modules,
        const char *modules[])
{
    while (*modules != NULL) {
        bool result = (iptcap_check_cap(cnf, check_file, check_name, *modules,
                               load_modules) == 1);
        if (result)
            return true;
        modules++;
    }
    return false;
}

int vrmr_load_iptcaps(
        struct vrmr_config *cnf, struct vrmr_iptcaps *iptcap, bool load_modules)
{
    char proc_net_match[] = "/proc/net/ip_tables_matches",
         proc_net_target[] = "/proc/net/ip_tables_targets",
         proc_net_names[] = "/proc/net/ip_tables_names",
         proc_net_netfilter_nfnetlink_queue[] =
                 "/proc/net/netfilter/nfnetlink_queue";

    assert(iptcap != NULL && cnf != NULL);

    /* init */
    memset(iptcap, 0, sizeof(struct vrmr_iptcaps));

    /*
        PROC FILES
    */

    /* /proc/net/ip_tables_matches */
    if (!(iptcap_check_file(proc_net_match))) {
        vrmr_debug(LOW, "%s not found: load_modules: %s.", proc_net_match,
                load_modules ? "Yes" : "No");

        if (load_modules == true) {
            /* try to load the module */
            (void)iptcap_load_module(cnf, "ip_tables");

            /* check again */
            if (!(iptcap_check_file(proc_net_match))) {
                vrmr_debug(LOW, "%s not still not found", proc_net_match);
            } else {
                vrmr_debug(LOW, "%s found!", proc_net_match);

                iptcap->proc_net_matches = true;
            }
        }
    } else {
        iptcap->proc_net_matches = true;
    }

    /* /proc/net/ip_tables_targets */
    if (!(iptcap_check_file(proc_net_target))) {
        vrmr_debug(LOW, "%s not found: load_modules: %s.", proc_net_target,
                load_modules ? "Yes" : "No");

        if (load_modules == true) {
            /* try to load the module */
            (void)iptcap_load_module(cnf, "ip_tables");

            /* check again */
            if (!(iptcap_check_file(proc_net_target))) {
                vrmr_debug(LOW, "%s not still not found", proc_net_target);
            } else {
                vrmr_debug(LOW, "%s found!", proc_net_target);

                iptcap->proc_net_targets = true;
            }
        }
    } else {
        iptcap->proc_net_targets = true;
    }

    /* /proc/net/ip_tables_names */
    if (!(iptcap_check_file(proc_net_names))) {
        if (load_modules == true) {
            /* try to load the module */
            (void)iptcap_load_module(cnf, "ip_tables");

            /* check again */
            if (!(iptcap_check_file(proc_net_names))) {
                vrmr_debug(LOW, "%s not still not found", proc_net_names);
            } else {
                vrmr_debug(LOW, "%s found!", proc_net_names);

                iptcap->proc_net_names = true;
            }
        }
    } else {
        iptcap->proc_net_names = true;
    }

    /*
        NAMES
    */
    if (iptcap->proc_net_names == TRUE) {
        const char *filter_modules[] = {"iptable_filter", NULL};
        iptcap->table_filter = iptcap_check_cap_modules(
                cnf, proc_net_names, "filter", load_modules, filter_modules);
        const char *mangle_modules[] = {"iptable_mangle", NULL};
        iptcap->table_mangle = iptcap_check_cap_modules(
                cnf, proc_net_names, "mangle", load_modules, mangle_modules);
        const char *nat_modules[] = {"iptable_nat", NULL};
        iptcap->table_nat = iptcap_check_cap_modules(
                cnf, proc_net_names, "nat", load_modules, nat_modules);
        const char *raw_modules[] = {"iptable_raw", NULL};
        iptcap->table_raw = iptcap_check_cap_modules(
                cnf, proc_net_names, "raw", load_modules, raw_modules);
    } else {
        /* assume yes */
        iptcap->table_filter = true;
        iptcap->table_mangle = true;
        iptcap->table_nat = true;
        iptcap->table_raw = true;
    }

    /* check for the CONNTRACK */
    if (vrmr_conn_check_api()) {
        iptcap->conntrack = true;
    } else {
        if (load_modules == true) {
            (void)iptcap_load_module(cnf, "ip_conntrack");
            (void)iptcap_load_module(cnf, "nf_conntrack_ipv4");
        }
        iptcap->conntrack = (vrmr_conn_check_api());
    }

    /* check for the /proc/net/netfilter/nfnetlink_queue */
    if (!(iptcap_check_file(proc_net_netfilter_nfnetlink_queue))) {
        if (load_modules == true) {
            /* try to load the module, if it fails, return 0 */
            (void)iptcap_load_module(cnf, "nfnetlink_queue");

            /* check again */
            if ((iptcap_check_file(proc_net_netfilter_nfnetlink_queue))) {
                iptcap->proc_net_netfilter_nfnetlink_queue = true;
            }
        }
    } else {
        iptcap->proc_net_netfilter_nfnetlink_queue = true;
    }

    /*
        MATCHES (uncapitalized)
    */
    if (iptcap->proc_net_matches == true) {
        const char *tcp_modules[] = {"xt_tcpudp", "ip_tables", NULL};
        iptcap->match_tcp = iptcap_check_cap_modules(
                cnf, proc_net_match, "tcp", load_modules, tcp_modules);
        const char *udp_modules[] = {"xt_tcpudp", "ip_tables", NULL};
        iptcap->match_udp = iptcap_check_cap_modules(
                cnf, proc_net_match, "udp", load_modules, udp_modules);
        const char *icmp_modules[] = {"ip_tables", NULL};
        iptcap->match_icmp = iptcap_check_cap_modules(
                cnf, proc_net_match, "icmp", load_modules, icmp_modules);

        /* state match */
        const char *state_modules[] = {"xt_state", "ipt_state", NULL};
        iptcap->match_state = iptcap_check_cap_modules(
                cnf, proc_net_match, "state", load_modules, state_modules);

        /* length match */
        const char *length_modules[] = {"xt_length", "ipt_length", NULL};
        iptcap->match_length = iptcap_check_cap_modules(
                cnf, proc_net_match, "length", load_modules, length_modules);

        /* limit match */
        const char *limit_modules[] = {"xt_limit", "ipt_limit", NULL};
        iptcap->match_limit = iptcap_check_cap_modules(
                cnf, proc_net_match, "limit", load_modules, limit_modules);
        if (!iptcap->match_limit) {
            iptcap->match_limit = (iptcap_test_filter_limit_match(
                                           cnf, cnf->iptables_location) == 1);
        }

        /* mark match */
        const char *mark_modules[] = {"xt_mark", "ipt_mark", NULL};
        iptcap->match_mark = iptcap_check_cap_modules(
                cnf, proc_net_match, "mark", load_modules, mark_modules);
        if (!iptcap->match_mark) {
            iptcap->match_mark = (iptcap_test_filter_mark_match(
                                          cnf, cnf->iptables_location) == 1);
        }

        /* mac match */
        const char *mac_modules[] = {"xt_mac", "ipt_mac", NULL};
        iptcap->match_mac = iptcap_check_cap_modules(
                cnf, proc_net_match, "mac", load_modules, mac_modules);
        if (!iptcap->match_mac) {
            iptcap->match_mac = (iptcap_test_filter_mac_match(
                                         cnf, cnf->iptables_location) == 1);
        }

        /* helper match */
        const char *helper_modules[] = {"xt_helper", "ipt_helper", NULL};
        iptcap->match_helper = iptcap_check_cap_modules(
                cnf, proc_net_match, "helper", load_modules, helper_modules);
        if (!iptcap->match_helper) {
            iptcap->match_helper = (iptcap_test_filter_helper_match(
                                            cnf, cnf->iptables_location) == 1);
        }

        /* connmark match */
        const char *connmark_modules[] = {"xt_connmark", "ipt_connmark", NULL};
        iptcap->match_connmark = iptcap_check_cap_modules(cnf, proc_net_match,
                "connmark", load_modules, connmark_modules);
        if (!iptcap->match_connmark) {
            iptcap->match_connmark = (iptcap_test_filter_connmark_match(cnf,
                                              cnf->iptables_location) == 1);
        }

        /* conntrack match */
        const char *conntrack_modules[] = {
                "xt_conntrack", "ipt_conntrack", NULL};
        iptcap->match_conntrack = iptcap_check_cap_modules(cnf, proc_net_match,
                "conntrack", load_modules, conntrack_modules);
        if (!iptcap->match_conntrack) {
            iptcap->match_conntrack = (iptcap_test_filter_conntrack_match(cnf,
                                               cnf->iptables_location) == 1);
        }

        /* rpfilter match */
        const char *rpfilter_modules[] = {"xt_rpfilter", "ipt_rpfilter", NULL};
        iptcap->match_rpfilter = iptcap_check_cap_modules(cnf, proc_net_match,
                "rpfilter", load_modules, rpfilter_modules);
        iptcap->match_rpfilter = (iptcap_test_filter_rpfilter_match(
                                          cnf, cnf->iptables_location) == 1);
    } else {
        iptcap->match_tcp = true;
        iptcap->match_udp = true;
        iptcap->match_icmp = true;

        iptcap->match_mark = true;
        iptcap->match_state = true;
        iptcap->match_helper = true;
        iptcap->match_length = true;
        iptcap->match_limit = true;
        iptcap->match_mac = true;
        iptcap->match_connmark = true;
        iptcap->match_rpfilter = true;
    }

    /*
        TARGETS (capitalized)
    */
    if (iptcap->proc_net_targets) {
        /* NAT targets */
        if (iptcap->table_nat) {
            /* DNAT target */
            iptcap->target_dnat =
                    (iptcap_check_cap(cnf, proc_net_target, "DNAT",
                             "iptable_nat", load_modules) == 1);

            /* SNAT target */
            iptcap->target_snat =
                    (iptcap_check_cap(cnf, proc_net_target, "SNAT",
                             "iptable_nat", load_modules) == 1);

            /* REDIRECT target */
            const char *redirect_modules[] = {
                    "xt_REDIRECT", "ipt_REDIRECT", NULL};
            iptcap->target_redirect =
                    iptcap_check_cap_modules(cnf, proc_net_target, "REDIRECT",
                            load_modules, redirect_modules);

            /* MASQUERADE target */
            iptcap->target_masquerade =
                    (iptcap_check_cap(cnf, proc_net_target, "MASQUERADE",
                             "ipt_MASQUERADE", load_modules) == 1);

            /* --random option for NAT */
            iptcap->target_nat_random =
                    (iptcap_test_nat_random(cnf, cnf->iptables_location) == 1);
        }

        /* REJECT target */
        const char *reject_modules[] = {"xt_REJECT", "ipt_REJECT", NULL};
        iptcap->target_reject = iptcap_check_cap_modules(
                cnf, proc_net_target, "REJECT", load_modules, reject_modules);

        /* NFLOG target */
        const char *nflog_modules[] = {"xt_NFLOG", "ipt_NFLOG", NULL};
        iptcap->target_nflog = iptcap_check_cap_modules(
                cnf, proc_net_target, "NFLOG", load_modules, nflog_modules);

        /* NFQUEUE target - this one is listed in /proc/net/ip_tables_targets */
        const char *nfqueue_modules[] = {"xt_NFQUEUE", "ipt_NFQUEUE", NULL};
        iptcap->target_nfqueue = iptcap_check_cap_modules(
                cnf, proc_net_target, "NFQUEUE", load_modules, nfqueue_modules);

        /* TCPMSS target - this one is listed in /proc/net/ip_tables_targets */
        const char *tcpmss_modules[] = {"xt_TCPMSS", "ipt_TCPMSS", NULL};
        iptcap->target_tcpmss = iptcap_check_cap_modules(
                cnf, proc_net_target, "TCPMSS", load_modules, tcpmss_modules);

        /* mangle stuff */
        if (iptcap->table_mangle) {
            const char *mark_modules[] = {"xt_MARK", "ipt_MARK", NULL};
            iptcap->target_mark = iptcap_check_cap_modules(
                    cnf, proc_net_target, "MARK", load_modules, mark_modules);
            if (!iptcap->target_mark) {
                iptcap->target_mark = (iptcap_test_mangle_mark_target(cnf,
                                               cnf->iptables_location) == 1);
            }

            /* CONNMARK target */
            const char *connmark_modules[] = {
                    "xt_CONNMARK", "ipt_CONNMARK", NULL};
            iptcap->target_connmark =
                    iptcap_check_cap_modules(cnf, proc_net_target, "CONNMARK",
                            load_modules, connmark_modules);
            if (!iptcap->target_connmark) {
                iptcap->target_connmark =
                        (iptcap_test_mangle_connmark_target(
                                 cnf, cnf->iptables_location) == 1);
            }

            /* CLASSIFY target */
            const char *classify_modules[] = {
                    "xt_CLASSIFY", "ipt_CLASSIFY", NULL};
            iptcap->target_classify =
                    iptcap_check_cap_modules(cnf, proc_net_target, "CLASSIFY",
                            load_modules, classify_modules);
            if (!iptcap->target_classify) {
                iptcap->target_classify =
                        (iptcap_test_mangle_classify_target(
                                 cnf, cnf->iptables_location) == 1);
            }
        }

        /* raw stuff */
        if (iptcap->table_raw) {
            /* CT target */
            const char *ct_modules[] = {"xt_CT", "ipt_CT", NULL};
            iptcap->target_ct = iptcap_check_cap_modules(
                    cnf, proc_net_target, "CT", load_modules, ct_modules);
        }
    } else {
        if (iptcap->table_nat == true) {
            iptcap->target_snat = true;
            iptcap->target_dnat = true;
            iptcap->target_redirect = true;
            iptcap->target_masquerade = true;
        }

        iptcap->target_reject = true;
        iptcap->target_nfqueue = true;

        if (iptcap->table_mangle == true) {
            iptcap->target_mark = true;
            iptcap->target_connmark = true;
            iptcap->target_classify = true;
        }
        if (iptcap->table_raw == true) {
            iptcap->target_ct = true;
        }
    }

    return (0);
}

int vrmr_check_ip6tcaps(
        struct vrmr_config *cnf, struct vrmr_iptcaps *iptcap, bool load_modules)
{
    assert(iptcap != NULL && cnf != NULL);

    /* load the caps */
    int result = vrmr_load_ip6tcaps(cnf, iptcap, load_modules);
    if (result == -1) {
        vrmr_error(-1, "Error", "loading ip6tables capabilities failed");
        return (-1);
    }

    if (iptcap->proc_net_ip6_names == FALSE) {
        vrmr_warning("Warning", "'/proc/net/ip6_tables_names' missing: no "
                                "ip6tables-support in the kernel?");
    }
    if (iptcap->proc_net_ip6_targets == FALSE) {
        vrmr_warning("Warning", "'/proc/net/ip6_tables_targets' missing: no "
                                "ip6tables-support in the kernel?");
    }
    if (iptcap->proc_net_ip6_matches == FALSE) {
        vrmr_warning("Warning", "'/proc/net/ip6_tables_matches' missing: no "
                                "ip6tables-support in the kernel?");
    }

    /* require the filter table */
    if (iptcap->proc_net_ip6_names == TRUE &&
            iptcap->table_ip6_filter == FALSE) {
        vrmr_error(-1, "Error",
                "no ip6tables-support in the kernel: filter table missing");
        return (-1);
    }
    if (iptcap->proc_net_ip6_names == TRUE && iptcap->table_ip6_mangle == FALSE)
        vrmr_warning("Warning", "mangle table missing from kernel: mangle "
                                "targets are unavailable.");

#if 0
    /* require conntrack */
    if(iptcap->conntrack == FALSE)
    {
        vrmr_error(-1, "Error", "no connection tracking support in the kernel");
        return(-1);
    }
#endif

    /* require tcp, udp, icmp */
    if (iptcap->proc_net_ip6_matches == TRUE &&
            (iptcap->match_ip6_tcp == FALSE || iptcap->match_ip6_udp == FALSE ||
                    iptcap->match_icmp6 == FALSE)) {
        vrmr_error(-1, "Error",
                "incomplete ip6tables-support in the kernel: tcp, udp or icmp6 "
                "support missing");
        return (-1);
    }

    /* require state match */
    if (iptcap->proc_net_ip6_matches == TRUE &&
            iptcap->match_ip6_state == FALSE) {
        vrmr_error(-1, "Error",
                "incomplete ip6tables-support in the kernel: state support "
                "missing");
        return (-1);
    }

    return (0);
}

int vrmr_load_ip6tcaps(
        struct vrmr_config *cnf, struct vrmr_iptcaps *iptcap, bool load_modules)
{
    char proc_net_ip6_match[] = "/proc/net/ip6_tables_matches",
         proc_net_ip6_target[] = "/proc/net/ip6_tables_targets",
         proc_net_ip6_names[] = "/proc/net/ip6_tables_names";
    /*
                proc_net_netfilter_nfnetlink_queue[] =
       "/proc/net/netfilter/nfnetlink_queue"
    */
    assert(iptcap != NULL && cnf != NULL);

#if 0
    /* init */
    memset(iptcap, 0, sizeof(struct vrmr_iptcaps));
#endif

    /*
        PROC FILES
    */

    /* /proc/net/ip6_tables_matches */
    if (!(iptcap_check_file(proc_net_ip6_match))) {
        vrmr_debug(LOW, "%s not found: load_modules: %s.", proc_net_ip6_match,
                load_modules ? "Yes" : "No");

        if (load_modules == true) {
            /* try to load the module */
            (void)iptcap_load_module(cnf, "ip6_tables");

            /* check again */
            if (!(iptcap_check_file(proc_net_ip6_match))) {
                vrmr_debug(LOW, "%s not still not found", proc_net_ip6_match);
            } else {
                vrmr_debug(LOW, "%s found!", proc_net_ip6_match);

                iptcap->proc_net_ip6_matches = true;
            }
        }
    } else {
        iptcap->proc_net_ip6_matches = true;
    }

    /* /proc/net/ip6_tables_targets */
    if (!(iptcap_check_file(proc_net_ip6_target))) {
        vrmr_debug(LOW, "%s not found: load_modules: %s.", proc_net_ip6_target,
                load_modules ? "Yes" : "No");

        if (load_modules == true) {
            /* try to load the module */
            (void)iptcap_load_module(cnf, "ip6_tables");

            /* check again */
            if (!(iptcap_check_file(proc_net_ip6_target))) {
                vrmr_debug(LOW, "%s not still not found", proc_net_ip6_target);
            } else {
                vrmr_debug(LOW, "%s found!", proc_net_ip6_target);

                iptcap->proc_net_ip6_targets = true;
            }
        }
    } else {
        iptcap->proc_net_ip6_targets = true;
    }

    /* /proc/net/ip6_tables_names */
    if (!(iptcap_check_file(proc_net_ip6_names))) {
        if (load_modules == true) {
            /* try to load the module */
            (void)iptcap_load_module(cnf, "ip6_tables");

            /* check again */
            if (!(iptcap_check_file(proc_net_ip6_names))) {
                vrmr_debug(LOW, "%s not still not found", proc_net_ip6_names);
            } else {
                vrmr_debug(LOW, "%s found!", proc_net_ip6_names);

                iptcap->proc_net_ip6_names = true;
            }
        }
    } else {
        iptcap->proc_net_ip6_names = true;
    }

    /*
        NAMES
    */
    if (iptcap->proc_net_ip6_names == true) {
        const char *filter_modules[] = {"ip6table_filter", NULL};
        iptcap->table_ip6_filter = iptcap_check_cap_modules(cnf,
                proc_net_ip6_names, "filter", load_modules, filter_modules);
        const char *mangle_modules[] = {"ip6table_mangle", NULL};
        iptcap->table_ip6_mangle = iptcap_check_cap_modules(cnf,
                proc_net_ip6_names, "mangle", load_modules, mangle_modules);
        const char *raw_modules[] = {"ip6table_raw", NULL};
        iptcap->table_ip6_raw = iptcap_check_cap_modules(
                cnf, proc_net_ip6_names, "raw", load_modules, raw_modules);
    } else {
        /* assume yes */
        iptcap->table_ip6_filter = true;
        iptcap->table_ip6_mangle = true;
        iptcap->table_ip6_raw = true;
    }

    /* check for the CONNTRACK */
    if (load_modules) {
        (void)iptcap_load_module(cnf, "nf_conntrack");
        (void)iptcap_load_module(cnf, "nf_conntrack_ipv6");
    }

#if 0
    /* check for the /proc/net/netfilter/nfnetlink_queue */
    if(!(iptcap_check_file(proc_net_netfilter_nfnetlink_queue)))
    {
        if(load_modules == TRUE)
        {
            /* try to load the module, if it fails, return 0 */
            (void)iptcap_load_module(cnf, "nfnetlink_queue");

            /* check again */
            if((iptcap_check_file(proc_net_netfilter_nfnetlink_queue)))
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
    if (iptcap->proc_net_ip6_matches == TRUE) {
        const char *tcp_modules[] = {"xt_tcpudp", "ip6_tables", NULL};
        iptcap->match_ip6_tcp = iptcap_check_cap_modules(
                cnf, proc_net_ip6_match, "tcp", load_modules, tcp_modules);
        const char *udp_modules[] = {"xt_tcpudp", "ip6_tables", NULL};
        iptcap->match_ip6_udp = iptcap_check_cap_modules(
                cnf, proc_net_ip6_match, "udp", load_modules, udp_modules);
        const char *icmp_modules[] = {"ip6_tables", NULL};
        iptcap->match_icmp6 = iptcap_check_cap_modules(
                cnf, proc_net_ip6_match, "icmp6", load_modules, icmp_modules);

        /* state match */
        const char *state_modules[] = {"xt_state", "ipt_state", NULL};
        iptcap->match_ip6_state = iptcap_check_cap_modules(
                cnf, proc_net_ip6_match, "state", load_modules, state_modules);

        /* length match */
        const char *length_modules[] = {"xt_length", "ipt_length", NULL};
        iptcap->match_ip6_length = iptcap_check_cap_modules(cnf,
                proc_net_ip6_match, "length", load_modules, length_modules);

        /* limit match */
        const char *limit_modules[] = {"xt_limit", "ipt_limit", NULL};
        iptcap->match_ip6_limit = iptcap_check_cap_modules(
                cnf, proc_net_ip6_match, "limit", load_modules, limit_modules);
        if (!iptcap->match_ip6_limit) {
            iptcap->match_ip6_limit = (iptcap_test_filter_limit_match(cnf,
                                               cnf->ip6tables_location) == 1);
        }

        /* mark match */
        const char *mark_modules[] = {"xt_mark", "ipt_mark", NULL};
        iptcap->match_ip6_mark = iptcap_check_cap_modules(
                cnf, proc_net_ip6_match, "mark", load_modules, mark_modules);
        if (!iptcap->match_ip6_mark) {
            iptcap->match_ip6_mark = (iptcap_test_filter_mark_match(cnf,
                                              cnf->ip6tables_location) == 1);
        }

        /* mac match */
        const char *mac_modules[] = {"xt_mac", "ipt_mac", NULL};
        iptcap->match_ip6_mac = iptcap_check_cap_modules(
                cnf, proc_net_ip6_match, "mac", load_modules, mac_modules);
        if (!iptcap->match_ip6_mac) {
            iptcap->match_ip6_mac = (iptcap_test_filter_mac_match(cnf,
                                             cnf->ip6tables_location) == 1);
        }

        /* helper match */
        const char *helper_modules[] = {"xt_helper", "ipt_helper", NULL};
        iptcap->match_ip6_helper = iptcap_check_cap_modules(cnf,
                proc_net_ip6_match, "helper", load_modules, helper_modules);
        if (!iptcap->match_ip6_helper) {
            iptcap->match_ip6_helper = (iptcap_test_filter_helper_match(cnf,
                                                cnf->ip6tables_location) == 1);
        }

        /* connmark match */
        const char *connmark_modules[] = {"xt_connmark", "ipt_connmark", NULL};
        iptcap->match_ip6_connmark = iptcap_check_cap_modules(cnf,
                proc_net_ip6_match, "connmark", load_modules, connmark_modules);
        if (!iptcap->match_ip6_connmark) {
            iptcap->match_ip6_connmark =
                    (iptcap_test_filter_connmark_match(
                             cnf, cnf->ip6tables_location) == 1);
        }

        /* conntrack match */
        const char *conntrack_modules[] = {
                "xt_conntrack", "ipt_conntrack", NULL};
        iptcap->match_ip6_conntrack =
                iptcap_check_cap_modules(cnf, proc_net_ip6_match, "conntrack",
                        load_modules, conntrack_modules);
        if (!iptcap->match_ip6_conntrack) {
            iptcap->match_ip6_conntrack =
                    (iptcap_test_filter_conntrack_match(
                             cnf, cnf->ip6tables_location) == 1);
        }

        /* rpfilter match */
        const char *rpfilter_modules[] = {"xt_rpfilter", "ipt_rpfilter", NULL};
        iptcap->match_ip6_rpfilter = iptcap_check_cap_modules(cnf,
                proc_net_ip6_match, "rpfilter", load_modules, rpfilter_modules);
        iptcap->match_ip6_rpfilter = (iptcap_test_filter_rpfilter_match(cnf,
                                              cnf->ip6tables_location) == 1);

    } else {
        iptcap->match_ip6_tcp = true;
        iptcap->match_ip6_udp = true;
        iptcap->match_icmp6 = true;

        iptcap->match_ip6_mark = true;
        iptcap->match_ip6_state = true;
        iptcap->match_ip6_helper = true;
        iptcap->match_ip6_length = true;
        iptcap->match_ip6_limit = true;
        iptcap->match_ip6_mac = true;
        iptcap->match_ip6_connmark = true;
        iptcap->match_ip6_rpfilter = true;
    }

    /*
        TARGETS (capitalized)
    */
    if (iptcap->proc_net_ip6_targets == TRUE) {
        /* REJECT target */
        const char *reject_modules[] = {"xt_REJECT", "ip6t_REJECT", NULL};
        iptcap->target_ip6_reject = iptcap_check_cap_modules(cnf,
                proc_net_ip6_target, "REJECT", load_modules, reject_modules);

        /* NFLOG target */
        const char *nflog_modules[] = {"xt_NFLOG", "ip6t_NFLOG", NULL};
        iptcap->target_ip6_nflog = iptcap_check_cap_modules(
                cnf, proc_net_ip6_target, "NFLOG", load_modules, nflog_modules);

        /* NFQUEUE target - this one is listed in /proc/net/ip_tables_targets */
        const char *nfqueue_modules[] = {"xt_NFQUEUE", "ip6t_NFQUEUE", NULL};
        iptcap->target_ip6_nfqueue = iptcap_check_cap_modules(cnf,
                proc_net_ip6_target, "NFQUEUE", load_modules, nfqueue_modules);

        /* TCPMSS target - this one is listed in /proc/net/ip_tables_targets */
        const char *tcpmss_modules[] = {"xt_TCPMSS", "ip6t_TCPMSS", NULL};
        iptcap->target_ip6_tcpmss = iptcap_check_cap_modules(cnf,
                proc_net_ip6_target, "TCPMSS", load_modules, tcpmss_modules);

        /* mangle stuff */
        if (iptcap->table_ip6_mangle == TRUE) {
            /* MARK target */
            const char *mark_modules[] = {"xt_MARK", "ip6t_MARK", NULL};
            iptcap->target_ip6_mark = iptcap_check_cap_modules(cnf,
                    proc_net_ip6_target, "MARK", load_modules, mark_modules);
            if (!iptcap->target_ip6_mark) {
                iptcap->target_ip6_mark =
                        (iptcap_test_mangle_mark_target(
                                 cnf, cnf->ip6tables_location) == 1);
            }

            /* CONNMARK target */
            const char *connmark_modules[] = {
                    "xt_CONNMARK", "ip6t_CONNMARK", NULL};
            iptcap->target_ip6_connmark =
                    iptcap_check_cap_modules(cnf, proc_net_ip6_target,
                            "CONNMARK", load_modules, connmark_modules);
            if (!iptcap->target_ip6_connmark) {
                iptcap->target_ip6_connmark =
                        (iptcap_test_mangle_connmark_target(
                                 cnf, cnf->ip6tables_location) == 1);
            }

            /* CLASSIFY target */
            const char *classify_modules[] = {
                    "xt_CLASSIFY", "ip6t_CLASSIFY", NULL};
            iptcap->target_ip6_classify =
                    iptcap_check_cap_modules(cnf, proc_net_ip6_target,
                            "CLASSIFY", load_modules, classify_modules);
            if (!iptcap->target_ip6_classify) {
                iptcap->target_ip6_classify =
                        (iptcap_test_mangle_classify_target(
                                 cnf, cnf->ip6tables_location) == 1);
            }
        }
        /* raw stuff */
        if (iptcap->table_ip6_raw) {
            /* CT target */
            const char *ct_modules[] = {"xt_CT", "ip6t_CT", NULL};
            iptcap->target_ip6_ct = iptcap_check_cap_modules(
                    cnf, proc_net_ip6_target, "CT", load_modules, ct_modules);
        }
    } else {
        iptcap->target_ip6_reject = true;
        iptcap->target_ip6_nfqueue = true;

        if (iptcap->table_ip6_mangle == true) {
            iptcap->target_ip6_mark = true;
            iptcap->target_ip6_connmark = true;
            iptcap->target_ip6_classify = true;
        }
    }

    /* test to see if we have ipv6 conntrack support. If the api is available
       and the connmark target is available and usable, we assume yes. */
    if (vrmr_conn_check_api() && iptcap->target_ip6_connmark &&
            iptcap->match_ip6_connmark &&
            (iptcap_test_mangle_connmark_target(cnf, cnf->ip6tables_location) ==
                    1)) {
        iptcap->conntrack_ip6 = true;
    }

    return (0);
}
