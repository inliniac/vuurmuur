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
#define NFLOG_MARK_BASE         65536+NFQ_MARK_BASE

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

    char                    action[122]; /* keep in sync with struct vrmr_rule_cache */
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

    struct vrmr_interface   *from_if_ptr;
    struct vrmr_interface   *to_if_ptr;

    /* proto */
    char                    proto[16+6]; // why 16+6? <- the 6 is for ' --syn' for tcp
    char                    helper[32];

    /* ports */
    char                    temp_dst_port[32];
    char                    temp_src_port[32];

    struct vrmr_portdata         *portrange_ptr;
    struct vrmr_portdata         *listenport_ptr;
    struct vrmr_portdata         *remoteport_ptr;

    char                    limit[42]; /*  -m limit --limit 999/s --limit-burst 9999 */

    /* portfw stuff - needs to go-> later we can put it in the function for creating portfw rules! */
    char                    serverip[VRMR_MAX_NET_ZONE];
    char                    remoteip[32]; // max 15 (for ip) + 1 (for :) + 5 (for port) = 21? + 1 = 22
    char                    temp_port_store[6];

    /*  list for adding the iptables rules of one singe vuurmuur rule
        to, so we can check for double rules. */
    struct vrmr_list                  iptrulelist;
    /*  list for adding the shaping rules of one singe vuurmuur rule
        to, so we can check for double rules. */
    struct vrmr_list                  shaperulelist;

    u_int16_t               shape_class_out;
    u_int16_t               shape_class_in;

    char                    random[9]; /* --random */

    /** in case of ZONE, this is the list of networks */
    struct vrmr_list                  from_network_list;
    struct vrmr_list                  to_network_list;

    /** in case of ZONE, this is the current network ptr */
    struct vrmr_zone                *from_network;
    struct vrmr_zone                *to_network;
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
    struct vrmr_list  raw_preroute;               /* list with rules */
    char    raw_preroute_policy;

    /*
        mangle
    */
    struct vrmr_list  mangle_preroute;            /* list with rules */
    char    mangle_preroute_policy;     /* policy for this chain: 0: accept, 1: drop */
    struct vrmr_list  mangle_input;               /* list with rules */
    char    mangle_input_policy;        /* policy for this chain: 0: accept, 1: drop */
    struct vrmr_list  mangle_forward;             /* list with rules */
    char    mangle_forward_policy;      /* policy for this chain: 0: accept, 1: drop */
    struct vrmr_list  mangle_output;              /* list with rules */
    char    mangle_output_policy;       /* policy for this chain: 0: accept, 1: drop */
    struct vrmr_list  mangle_postroute;           /* list with rules */
    char    mangle_postroute_policy;    /* policy for this chain: 0: accept, 1: drop */

    /*
        extra mangle (no policies)
    */
    struct vrmr_list  mangle_shape_in;            /* list with rules */
    struct vrmr_list  mangle_shape_out;           /* list with rules */
    struct vrmr_list  mangle_shape_fw;            /* list with rules */

    /*
        nat
    */
    struct vrmr_list  nat_preroute;               /* list with rules */
    char    nat_preroute_policy;        /* policy for this chain: 0: accept, 1: drop */
    struct vrmr_list  nat_postroute;              /* list with rules */
    char    nat_postroute_policy;       /* policy for this chain: 0: accept, 1: drop */
    struct vrmr_list  nat_output;                 /* list with rules */
    char    nat_output_policy;          /* policy for this chain: 0: accept, 1: drop */

    /*
        filter
    */
    struct vrmr_list  filter_input;               /* list with rules */
    char    filter_input_policy;        /* policy for this chain: 0: accept, 1: drop */
    struct vrmr_list  filter_forward;             /* list with rules */
    char    filter_forward_policy;      /* policy for this chain: 0: accept, 1: drop */
    struct vrmr_list  filter_output;              /* list with rules */
    char    filter_output_policy;       /* policy for this chain: 0: accept, 1: drop */

    /*
        extra filter (no policies)
    */
    struct vrmr_list  filter_antispoof;           /* list with rules */
    struct vrmr_list  filter_blocklist;           /* list with rules */
    struct vrmr_list  filter_blocktarget;         /* list with rules */
    struct vrmr_list  filter_badtcp;              /* list with rules */
    struct vrmr_list  filter_synlimittarget;      /* list with rules */
    struct vrmr_list  filter_udplimittarget;      /* list with rules */
    struct vrmr_list  filter_tcpresettarget;      /* list with rules */
    struct vrmr_list  filter_newaccepttarget;     /* list with rules */
    struct vrmr_list  filter_newqueuetarget;      /* list with rules */
    struct vrmr_list  filter_newnfqueuetarget;    /* list with rules */
    struct vrmr_list  filter_estrelnfqueuetarget; /* list with rules */
    struct vrmr_list  filter_newnflogtarget;    /* list with rules */
    struct vrmr_list  filter_estrelnflogtarget; /* list with rules */
    struct vrmr_list  filter_accounting;          /* list with rules */

    /*
        special chains
    */
    char    block;                      /* the block target */
    char    synlimit;                   /* synlimiting */

    /*
        shaping
    */
    struct vrmr_list  tc_rules;                   /* list with tc rules */

} RuleSet;

typedef struct VrCmdline_ {
    /* commandline overrides */
    char vrmr_check_iptcaps_set;
    char vrmr_check_iptcaps;
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
struct vrmr_shm_table *shm_table;

/* counters */
int ipt_rulecount;

/* semaphore id */
int sem_id;

/* pointer to the environment */
extern char **environ;

VrCmdline cmdline;

/*************************************************************************************************************************\
 ******************************************************* FUNCTIONS *******************************************************
\*************************************************************************************************************************/

/* rules.c */
void create_loglevel_string(const int, struct vrmr_config *, char *, size_t);
void create_logprefix_string(const int, struct vrmr_config *conf, char *, size_t, int, char *, char *, ...);
void create_logtcpoptions_string(const int, struct vrmr_config *, char *, size_t);

int oldrules_create_custom_chains(const int, struct vrmr_rules *, struct vrmr_config *);

int analyze_interface_rules(const int, struct vrmr_config *conf, struct vrmr_rules *, struct vrmr_zones *, struct vrmr_services *, struct vrmr_interfaces *);
int analyze_network_protect_rules(const int, struct vrmr_config *conf, struct vrmr_rules *, struct vrmr_zones *, struct vrmr_services *, struct vrmr_interfaces *);
int analyze_normal_rules(const int, struct vrmr_config *conf, struct vrmr_rules *, struct vrmr_zones *, struct vrmr_services *, struct vrmr_interfaces *);
int analyze_all_rules(const int, struct vrmr_ctx *, struct vrmr_rules *);

int create_all_rules(const int, struct vrmr_ctx *, int);

int pre_rules(const int, struct vrmr_config *conf, /*@null@*/RuleSet *, struct vrmr_interfaces *, struct vrmr_iptcaps *);
int post_rules(const int, struct vrmr_config *conf, /*@null@*/RuleSet *, struct vrmr_iptcaps *, int, int ipv);

int update_synlimit_rules(const int, struct vrmr_config *conf, /*@null@*/RuleSet *, struct vrmr_iptcaps *, int);
int update_udplimit_rules(const int, struct vrmr_config *conf, /*@null@*/RuleSet *, struct vrmr_iptcaps *, int);
int create_block_rules(const int, struct vrmr_config *conf, /*@null@*/RuleSet *, struct vrmr_blocklist *);

int create_newnfqueue_rules(const int, struct vrmr_config *conf, /*@null@*/RuleSet *, struct vrmr_rules *, struct vrmr_iptcaps *, int);
int create_estrelnfqueue_rules(const int, struct vrmr_config *conf, /*@null@*/RuleSet *, struct vrmr_rules *, struct vrmr_iptcaps *, int);
int create_newnflog_rules(const int, struct vrmr_config *conf, /*@null@*/RuleSet *, struct vrmr_rules *, struct vrmr_iptcaps *, int);
int create_estrelnflog_rules(const int, struct vrmr_config *conf, /*@null@*/RuleSet *, struct vrmr_rules *, struct vrmr_iptcaps *, int);

int create_network_protect_rules(const int, struct vrmr_config *conf, /*@null@*/RuleSet *, struct vrmr_zones *, struct vrmr_iptcaps *);
int create_interface_rules(const int, struct vrmr_config *conf, /*@null@*/RuleSet *, struct vrmr_iptcaps *, struct vrmr_interfaces *);
int create_system_protectrules(const int, struct vrmr_config *);
int create_normal_rules(const int, struct vrmr_ctx *, /*@null@*/RuleSet *, char *);

int create_rule(const int, struct vrmr_ctx*, /*@null@*/RuleSet *, struct vrmr_rule_cache *);
int remove_rule(const int debuglvl, struct vrmr_config *conf, int chaintype, int first_ipt_rule, int rules);

int create_rule_input(const int, struct vrmr_config *conf, /*@null@*/RuleSet *, struct RuleCreateData_ *, struct vrmr_rule_cache *, struct vrmr_iptcaps *);
int create_rule_output(const int, struct vrmr_config *conf, /*@null@*/RuleSet *, struct RuleCreateData_ *, struct vrmr_rule_cache *, struct vrmr_iptcaps *);
int create_rule_forward(const int, struct vrmr_config *conf, /*@null@*/RuleSet *, struct RuleCreateData_ *, struct vrmr_rule_cache *, struct vrmr_iptcaps *);
int create_rule_masq(const int, struct vrmr_config *conf, /*@null@*/RuleSet *, struct RuleCreateData_ *, struct vrmr_rule_cache *, struct vrmr_iptcaps *);
int create_rule_snat(const int, struct vrmr_config *conf, /*@null@*/RuleSet *, struct RuleCreateData_ *, struct vrmr_rule_cache *, struct vrmr_iptcaps *);
int create_rule_portfw(const int, struct vrmr_config *conf, /*@null@*/RuleSet *, struct RuleCreateData_ *, struct vrmr_rule_cache *, struct vrmr_iptcaps *);
int create_rule_redirect(const int, struct vrmr_config *conf, /*@null@*/RuleSet *, struct RuleCreateData_ *, struct vrmr_rule_cache *, struct vrmr_iptcaps *);
int create_rule_dnat(const int, struct vrmr_config *conf, /*@null@*/RuleSet *, struct RuleCreateData_ *, struct vrmr_rule_cache *, struct vrmr_iptcaps *);
int create_rule_bounce(const int, struct vrmr_config *conf, /*@null@*/RuleSet *, struct RuleCreateData_ *, struct vrmr_rule_cache *, struct vrmr_iptcaps *);

int clear_vuurmuur_iptables_rules(const int debuglvl, struct vrmr_config *cnf);
int clear_all_iptables_rules(const int debuglvl, struct vrmr_config *);

int process_queued_rules(const int debuglvl, struct vrmr_config *conf, /*@null@*/RuleSet *ruleset, struct RuleCreateData_ *rule);

/* misc.c */
void send_hup_to_vuurmuurlog(const int debuglvl);
void cmdline_override_config(const int debuglvl, struct vrmr_config *conf);
int sysctl_exec(const int debuglvl, struct vrmr_config *cnf, char *key, char *value, int bash_out);

int logprint_error_bash(int errorlevel, char *head, char *fmt, ...);
int logprint_warning_bash(char *head, char *fmt, ...);
int logprint_info_bash(char *head, char *fmt, ...);

/* main.c */
// none ;-)


/* reload.c */
int apply_changes(const int, struct vrmr_ctx *vctx, struct vrmr_regex *);

int reload_services(const int, struct vrmr_ctx *, struct vrmr_services *, regex_t *);
int reload_vrmr_services_check(const int, struct vrmr_ctx *, struct vrmr_service *);

int reload_zonedata(const int, struct vrmr_ctx *, struct vrmr_zones *, struct vrmr_interfaces *, struct vrmr_regex *);
int reload_zonedata_check(const int, struct vrmr_ctx *, struct vrmr_zones *, struct vrmr_interfaces *, struct vrmr_zone *, struct vrmr_regex *);

int reload_interfaces(const int, struct vrmr_ctx *, struct vrmr_interfaces *);
int reload_vrmr_interfaces_check(const int, struct vrmr_ctx *, struct vrmr_interface *iface_ptr);

int check_for_changed_dynamic_ips(const int debuglvl, struct vrmr_interfaces *interfaces);

/* ruleset */
int ruleset_add_rule_to_set(const int, struct vrmr_list *, char *, char *, unsigned long long, unsigned long long);
int load_ruleset(const int, struct vrmr_ctx *);

/* shape */
int shaping_setup_roots (const int debuglvl, struct vrmr_config *cnf, struct vrmr_interfaces *interfaces, /*@null@*/RuleSet *);
int shaping_clear_interfaces (const int debuglvl, struct vrmr_config *cnf, struct vrmr_interfaces *interfaces, /*@null@*/RuleSet *ruleset);
int determine_minimal_default_rates(const int debuglvl, struct vrmr_interfaces *interfaces, struct vrmr_rules *rules);
int shaping_create_default_rules(const int debuglvl, struct vrmr_config *cnf, struct vrmr_interfaces *interfaces, /*@null@*/RuleSet *ruleset);
int shaping_shape_rule(const int debuglvl, /*@null@*/struct vrmr_rule_options *opt);
int shaping_shape_incoming_rule(const int debuglvl, /*@null@*/struct vrmr_rule_options *opt);
int shaping_shape_outgoing_rule(const int debuglvl, /*@null@*/struct vrmr_rule_options *opt);
int shaping_shape_interface(const int debuglvl, struct vrmr_interface *iface_ptr);
int shaping_shape_create_rule(const int debuglvl, struct vrmr_config *cnf, struct vrmr_interfaces *interfaces, struct RuleCreateData_ *rule, /*@null@*/RuleSet *ruleset, struct vrmr_interface *shape_iface_ptr, struct vrmr_interface *class_iface_ptr, u_int16_t class, u_int32_t rate, char *rate_unit, u_int32_t ceil, char *ceil_unit, u_int8_t prio);
int shaping_determine_minimal_default_rates(const int debuglvl, struct vrmr_interfaces *interfaces, struct vrmr_rules *rules);
int shaping_create_default_rules(const int debuglvl, struct vrmr_config *cnf, struct vrmr_interfaces *interfaces, /*@null@*/RuleSet *ruleset);
int shaping_process_queued_rules(const int debuglvl, struct vrmr_config *cnf, /*@null@*/RuleSet *ruleset, struct RuleCreateData_ *rule);

#endif
