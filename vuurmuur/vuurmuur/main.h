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
#ifndef __MAIN_H__
#define __MAIN_H__

/*****************************************************************************************************************\
 ********************************* INCLUDES **********************************************************************
\*****************************************************************************************************************/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>
#include <sys/types.h>
#include <signal.h>     /* for catching signals */
#include <time.h>       /* included for logging */
#include <errno.h>      /* error handling */
#include <sys/ipc.h>
#include <sys/sem.h>
#include <sys/shm.h>
#include <sys/wait.h>

/* our own vuurmuurlib */
#include <vuurmuur.h>

#include "version.h"

/*****************************************************************************************************************\
 ********************************* DEFINES ***********************************************************************
\*****************************************************************************************************************/

#define LOGPREFIX_PREFIX        "vrmr: "    /* the prefix in the logprefix */
#define LOGPREFIX_LOG_MAXLEN    29
#define LOGPREFIX_ULOG_MAXLEN   32          /* not yet used */

#define SVCNAME                 "vuurmuur"

#define LOOP_INT                1

#define YES                     1
#define NO                      0

#define PIDFILE                 "/var/run/vuurmuur.pid"

#define NFQ_MARK_BASE           3

#define LOCK(x)                 LockSHM(1, x)
#define UNLOCK(x)               LockSHM(0, x)

/* define these here so converting to gettext will be easier */
#define VR_ERR                  "Error"
#define VR_INTERR               "Internal Error"
#define VR_INFO                 "Info"
#define VR_WARN                 "Warning"

/*************************************************************************************************************************\
 ******************************************************* DATATYPES *******************************************************
\*************************************************************************************************************************/

char        version_string[128];
char        loglevel[32];           /* --log-level warning */
char        log_tcp_options[18];    /* --log-tcp-options */

struct RuleCreateData_
{
    int                     ipv; /* ip version */

    char                    action[sizeof(RuleCache.action)];
    char                    chain[48]; /* why 48? */

#ifdef IPV6_ENABLED
    /* ipaddress */
    char                    from_ip[46];
    char                    to_ip[46];
#else
    char                    from_ip[16];
    char                    to_ip[16];
#endif

    /* netmasks */
    char                    from_netmask[16];
    char                    to_netmask[16];

    /* optionswitch + ip + netmask */
    char                    temp_src[48];
    char                    temp_dst[48];

    /* mac - only from */
    char                    from_mac[48]; /* --m mac --from-mac mac */

    struct vrmr_ipv4_data   ipv4_from;
    struct vrmr_ipv4_data   ipv4_to;
#ifdef IPV6_ENABLED
    struct vrmr_ipv6_data   ipv6_from;
    struct vrmr_ipv6_data   ipv6_to;
#endif

    /* interfaces */
    char                    from_int[16];
    char                    to_int[16];

    struct InterfaceData_   *from_if_ptr;
    struct InterfaceData_   *to_if_ptr;

    /* proto */
    char                    proto[16+6]; // why 16+6? <- the 6 is for ' --syn' for tcp
    char                    helper[32];

    /* ports */
    char                    temp_dst_port[32];
    char                    temp_src_port[32];

    struct portdata         *portrange_ptr;
    struct portdata         *listenport_ptr;
    struct portdata         *remoteport_ptr;

    char                    limit[42]; /*  -m limit --limit 999/s --limit-burst 9999 */

    /* portfw stuff - needs to go-> later we can put it in the function for creating portfw rules! */
    char                    serverip[MAX_NET_ZONE];
    char                    remoteip[32]; // max 15 (for ip) + 1 (for :) + 5 (for port) = 21? + 1 = 22
    char                    temp_port_store[6];

    /*  list for adding the iptables rules of one singe vuurmuur rule
        to, so we can check for double rules. */
    d_list                  iptrulelist;
    /*  list for adding the shaping rules of one singe vuurmuur rule
        to, so we can check for double rules. */
    d_list                  shaperulelist;

    u_int16_t               shape_class_out;
    u_int16_t               shape_class_in;

    char                    random[9]; /* --random */

    /** in case of ZONE, this is the list of networks */
    d_list                  from_network_list;
    d_list                  to_network_list;

    /** in case of ZONE, this is the current network ptr */
    ZoneData                *from_network;
    ZoneData                *to_network;
};


/*  here we are going to assemble all rules for
    the creation of the file for iptables-restore.

*/
typedef struct
{
    int ipv;

    /*
        raw
    */
    d_list  raw_preroute;               /* list with rules */
    char    raw_preroute_policy;

    /*
        mangle
    */
    d_list  mangle_preroute;            /* list with rules */
    char    mangle_preroute_policy;     /* policy for this chain: 0: accept, 1: drop */
    d_list  mangle_input;               /* list with rules */
    char    mangle_input_policy;        /* policy for this chain: 0: accept, 1: drop */
    d_list  mangle_forward;             /* list with rules */
    char    mangle_forward_policy;      /* policy for this chain: 0: accept, 1: drop */
    d_list  mangle_output;              /* list with rules */
    char    mangle_output_policy;       /* policy for this chain: 0: accept, 1: drop */
    d_list  mangle_postroute;           /* list with rules */
    char    mangle_postroute_policy;    /* policy for this chain: 0: accept, 1: drop */

    /*
        extra mangle (no policies)
    */
    d_list  mangle_shape_in;            /* list with rules */
    d_list  mangle_shape_out;           /* list with rules */
    d_list  mangle_shape_fw;            /* list with rules */

    /*
        nat
    */
    d_list  nat_preroute;               /* list with rules */
    char    nat_preroute_policy;        /* policy for this chain: 0: accept, 1: drop */
    d_list  nat_postroute;              /* list with rules */
    char    nat_postroute_policy;       /* policy for this chain: 0: accept, 1: drop */
    d_list  nat_output;                 /* list with rules */
    char    nat_output_policy;          /* policy for this chain: 0: accept, 1: drop */

    /*
        filter
    */
    d_list  filter_input;               /* list with rules */
    char    filter_input_policy;        /* policy for this chain: 0: accept, 1: drop */
    d_list  filter_forward;             /* list with rules */
    char    filter_forward_policy;      /* policy for this chain: 0: accept, 1: drop */
    d_list  filter_output;              /* list with rules */
    char    filter_output_policy;       /* policy for this chain: 0: accept, 1: drop */

    /*
        extra filter (no policies)
    */
    d_list  filter_antispoof;           /* list with rules */
    d_list  filter_blocklist;           /* list with rules */
    d_list  filter_blocktarget;         /* list with rules */
    d_list  filter_badtcp;              /* list with rules */
    d_list  filter_synlimittarget;      /* list with rules */
    d_list  filter_udplimittarget;      /* list with rules */
    d_list  filter_tcpresettarget;      /* list with rules */
    d_list  filter_newaccepttarget;     /* list with rules */
    d_list  filter_newqueuetarget;      /* list with rules */
    d_list  filter_newnfqueuetarget;    /* list with rules */
    d_list  filter_estrelnfqueuetarget; /* list with rules */
    d_list  filter_accounting;          /* list with rules */

    /*
        special chains
    */
    char    block;                      /* the block target */
    char    synlimit;                   /* synlimiting */

    /*
        shaping
    */
    d_list  tc_rules;                   /* list with tc rules */

} RuleSet;

typedef struct VrCmdline_ {
    /* commandline overrides */
    char check_iptcaps_set;
    char check_iptcaps;
    char verbose_out_set;
    char verbose_out;
    char configfile_set;
    char configfile[256];
    char loglevel_set;
    char loglevel[8];

    /* local settings */
    char keep_file;
    char loop;
    char nodaemon;
    char force_start;
} VrCmdline;

/*@null@*/
struct SHM_TABLE *shm_table;

/* counters */
int ipt_rulecount;

/* semaphore id */
int sem_id;

/* pointer to the environment */
extern char **environ;

VrCmdline cmdline;

struct vuurmuur_config conf;

/*************************************************************************************************************************\
 ******************************************************* FUNCTIONS *******************************************************
\*************************************************************************************************************************/

/* rules.c */
void create_loglevel_string(const int, struct vuurmuur_config *, char *, size_t);
void create_logprefix_string(const int, char *, size_t, int, char *, char *, ...);
void create_logtcpoptions_string(const int, struct vuurmuur_config *, char *, size_t);

int oldrules_create_custom_chains(const int, Rules *, struct vuurmuur_config *);

int analyze_interface_rules(const int, Rules *, Zones *, Services *, Interfaces *);
int analyze_network_protect_rules(const int, Rules *, Zones *, Services *, Interfaces *);
int analyze_normal_rules(const int, Rules *, Zones *, Services *, Interfaces *);
int analyze_all_rules(const int, VuurmuurCtx *, Rules *);

int create_all_rules(const int, VuurmuurCtx *, int);

int pre_rules(const int, /*@null@*/RuleSet *, Interfaces *, IptCap *);
int post_rules(const int, /*@null@*/RuleSet *, IptCap *, int);

int update_synlimit_rules(const int, /*@null@*/RuleSet *, IptCap *, int);
int update_udplimit_rules(const int, /*@null@*/RuleSet *, IptCap *, int);
int create_block_rules(const int, /*@null@*/RuleSet *, BlockList *);

int create_newnfqueue_rules(const int, /*@null@*/RuleSet *, Rules *, IptCap *, int);
int create_estrelnfqueue_rules(const int, /*@null@*/RuleSet *, Rules *, IptCap *, int);

int create_network_protect_rules(const int, /*@null@*/RuleSet *, Zones *, IptCap *);
int create_interface_rules(const int, /*@null@*/RuleSet *, IptCap *, Interfaces *);
int create_system_protectrules(const int, struct vuurmuur_config *);
int create_normal_rules(const int, VuurmuurCtx *, /*@null@*/RuleSet *, char *);

int create_rule(const int, VuurmuurCtx*, /*@null@*/RuleSet *, struct RuleCache_ *);
int remove_rule(const int debuglvl, int chaintype, int first_ipt_rule, int rules);

int create_rule_input(const int, /*@null@*/RuleSet *, struct RuleCreateData_ *, struct RuleCache_ *, IptCap *);
int create_rule_output(const int,  /*@null@*/RuleSet *, struct RuleCreateData_ *, struct RuleCache_ *, IptCap *);
int create_rule_forward(const int, /*@null@*/RuleSet *, struct RuleCreateData_ *, struct RuleCache_ *, IptCap *);
int create_rule_masq(const int, /*@null@*/RuleSet *, struct RuleCreateData_ *, struct RuleCache_ *, IptCap *);
int create_rule_snat(const int, /*@null@*/RuleSet *, struct RuleCreateData_ *, struct RuleCache_ *, IptCap *);
int create_rule_portfw(const int, /*@null@*/RuleSet *, struct RuleCreateData_ *, struct RuleCache_ *, IptCap *);
int create_rule_redirect(const int, /*@null@*/RuleSet *, struct RuleCreateData_ *, struct RuleCache_ *, IptCap *);
int create_rule_dnat(const int, /*@null@*/RuleSet *, struct RuleCreateData_ *, struct RuleCache_ *, IptCap *);
int create_rule_bounce(const int, /*@null@*/RuleSet *, struct RuleCreateData_ *, struct RuleCache_ *, IptCap *);

int clear_vuurmuur_iptables_rules(const int debuglvl, struct vuurmuur_config *cnf);
int clear_all_iptables_rules(const int debuglvl);

int process_queued_rules(const int debuglvl, /*@null@*/RuleSet *ruleset, struct RuleCreateData_ *rule);

/* misc.c */
void send_hup_to_vuurmuurlog(const int debuglvl);
void cmdline_override_config(const int debuglvl);
int sysctl_exec(const int debuglvl, struct vuurmuur_config *cnf, char *key, char *value, int bash_out);

int logprint_error_bash(int errorlevel, char *head, char *fmt, ...);
int logprint_warning_bash(char *head, char *fmt, ...);
int logprint_info_bash(char *head, char *fmt, ...);

/* main.c */
// none ;-)


/* reload.c */
int apply_changes(const int, VuurmuurCtx *vctx, struct rgx_ *);

int reload_services(const int, Services *, regex_t *);
int reload_services_check(const int, struct ServicesData_ *);

int reload_zonedata(const int, Zones *, Interfaces *, struct rgx_ *);
int reload_zonedata_check(const int, Zones *, Interfaces *, struct ZoneData_ *, struct rgx_ *);

int reload_interfaces(const int, Interfaces *);
int reload_interfaces_check(const int, struct InterfaceData_ *iface_ptr);

int check_for_changed_dynamic_ips(const int debuglvl, Interfaces *interfaces);

/* ruleset */
int ruleset_add_rule_to_set(const int, d_list *, char *, char *, unsigned long long, unsigned long long);
int load_ruleset(const int, VuurmuurCtx *);

/* shape */
int shaping_setup_roots (const int debuglvl, struct vuurmuur_config *cnf, Interfaces *interfaces, /*@null@*/RuleSet *);
int shaping_clear_interfaces (const int debuglvl, struct vuurmuur_config *cnf, Interfaces *interfaces, /*@null@*/RuleSet *ruleset);
int determine_minimal_default_rates(const int debuglvl, Interfaces *interfaces, Rules *rules);
int shaping_create_default_rules(const int debuglvl, struct vuurmuur_config *cnf, Interfaces *interfaces, /*@null@*/RuleSet *ruleset);
int shaping_shape_rule(const int debuglvl, /*@null@*/struct options *opt);
int shaping_shape_incoming_rule(const int debuglvl, /*@null@*/struct options *opt);
int shaping_shape_outgoing_rule(const int debuglvl, /*@null@*/struct options *opt);
int shaping_shape_interface(const int debuglvl, InterfaceData *iface_ptr);
int shaping_shape_create_rule(const int debuglvl, struct vuurmuur_config *cnf, Interfaces *interfaces, struct RuleCreateData_ *rule, /*@null@*/RuleSet *ruleset, InterfaceData *shape_iface_ptr, InterfaceData *class_iface_ptr, u_int16_t class, u_int32_t rate, char *rate_unit, u_int32_t ceil, char *ceil_unit, u_int8_t prio);
int shaping_determine_minimal_default_rates(const int debuglvl, Interfaces *interfaces, Rules *rules);
int shaping_create_default_rules(const int debuglvl, struct vuurmuur_config *cnf, Interfaces *interfaces, /*@null@*/RuleSet *ruleset);
int shaping_process_queued_rules(const int debuglvl, struct vuurmuur_config *cnf, /*@null@*/RuleSet *ruleset, struct RuleCreateData_ *rule);

#endif
