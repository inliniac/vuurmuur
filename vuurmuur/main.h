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
#ifndef __MAIN_H__
#define __MAIN_H__

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
#include <signal.h> /* for catching signals */
#include <time.h>   /* included for logging */
#include <errno.h>  /* error handling */
#include <sys/ipc.h>
#include <sys/sem.h>
#include <sys/shm.h>
#include <sys/wait.h>

/* our own vuurmuurlib */
#include <vuurmuur.h>

/*****************************************************************************************************************\
 ********************************* DEFINES
***********************************************************************
\*****************************************************************************************************************/

#define LOGPREFIX_PREFIX "vrmr: " /* the prefix in the logprefix */
#define LOGPREFIX_LOG_MAXLEN 29
#define LOGPREFIX_ULOG_MAXLEN 32 /* not yet used */

#define SVCNAME "vuurmuur"

#define LOOP_INT 1

#define YES 1
#define NO 0

#define PIDFILE "/var/run/vuurmuur.pid"

#define NFQ_MARK_BASE 3
#define NFLOG_MARK_BASE 65536 + NFQ_MARK_BASE

/* define these here so converting to gettext will be easier */
#define VR_ERR "Error"
#define VR_INTERR "Internal Error"
#define VR_INFO "Info"
#define VR_WARN "Warning"

extern char version_string[128];

struct rule_scratch {
    int ipv; /* ip version */

    char action[128]; /* keep in sync with struct vrmr_rule_cache */
    char chain[48];   /* why 48? */

#ifdef IPV6_ENABLED
    /* ipaddress */
    char from_ip[46];
    char to_ip[46];
#else
    char from_ip[16];
    char to_ip[16];
#endif

    /* netmasks */
    char from_netmask[16];
    char to_netmask[16];

    /* optionswitch + ip + netmask */
    char temp_src[48];
    char temp_dst[48];

    /* mac - only from */
    char from_mac[48]; /* --m mac --from-mac mac */

    struct vrmr_ipv4_data ipv4_from;
    struct vrmr_ipv4_data ipv4_to;
#ifdef IPV6_ENABLED
    struct vrmr_ipv6_data ipv6_from;
    struct vrmr_ipv6_data ipv6_to;
#endif

    /* interfaces */
    char from_int[16];
    char to_int[16];

    struct vrmr_interface *from_if_ptr;
    struct vrmr_interface *to_if_ptr;

    /* proto */
    char proto[16 + 6]; // why 16+6? <- the 6 is for ' --syn' for tcp
    char helper[32];

    /* ports */
    char temp_dst_port[32];
    char temp_src_port[32];

    struct vrmr_portdata *portrange_ptr;
    struct vrmr_portdata *listenport_ptr;
    struct vrmr_portdata *remoteport_ptr;

    char limit[64]; /*  -m limit --limit 999/s --limit-burst 9999 */

    /* portfw stuff - needs to go-> later we can put it in the function for
     * creating portfw rules! */
    char serverip[VRMR_MAX_NET_ZONE];
    char remoteip[32]; // max 15 (for ip) + 1 (for :) + 5 (for port) = 21? + 1 =
                       // 22
    char temp_port_store[6];

    /*  list for adding the iptables rules of one singe vuurmuur rule
        to, so we can check for double rules. */
    struct vrmr_list iptrulelist;
    /*  list for adding the shaping rules of one singe vuurmuur rule
        to, so we can check for double rules. */
    struct vrmr_list shaperulelist;

    uint16_t shape_class_out;
    uint16_t shape_class_in;

    char random[9]; /* --random */

    /** in case of ZONE, this is the list of networks */
    struct vrmr_list from_network_list;
    struct vrmr_list to_network_list;

    /** in case of ZONE, this is the current network ptr */
    struct vrmr_zone *from_network;
    struct vrmr_zone *to_network;
};

/*  here we are going to assemble all rules for
    the creation of the file for iptables-restore.

*/
struct rule_set {
    int ipv;

    /*
        raw
    */
    struct vrmr_list raw_preroute; /* list with rules */
    char raw_preroute_policy;
    struct vrmr_list raw_output; /* list with rules */
    char raw_output_policy;

    /*
        mangle
    */
    struct vrmr_list mangle_preroute; /* list with rules */
    char mangle_preroute_policy; /* policy for this chain: 0: accept, 1: drop */
    struct vrmr_list mangle_input; /* list with rules */
    char mangle_input_policy; /* policy for this chain: 0: accept, 1: drop */
    struct vrmr_list mangle_forward; /* list with rules */
    char mangle_forward_policy; /* policy for this chain: 0: accept, 1: drop */
    struct vrmr_list mangle_output; /* list with rules */
    char mangle_output_policy; /* policy for this chain: 0: accept, 1: drop */
    struct vrmr_list mangle_postroute; /* list with rules */
    char mangle_postroute_policy; /* policy for this chain: 0: accept, 1: drop
                                   */

    /*
        extra mangle (no policies)
    */
    struct vrmr_list mangle_shape_in;  /* list with rules */
    struct vrmr_list mangle_shape_out; /* list with rules */
    struct vrmr_list mangle_shape_fw;  /* list with rules */

    /*
        nat
    */
    struct vrmr_list nat_preroute; /* list with rules */
    char nat_preroute_policy; /* policy for this chain: 0: accept, 1: drop */
    struct vrmr_list nat_postroute; /* list with rules */
    char nat_postroute_policy;   /* policy for this chain: 0: accept, 1: drop */
    struct vrmr_list nat_output; /* list with rules */
    char nat_output_policy;      /* policy for this chain: 0: accept, 1: drop */

    /*
        filter
    */
    struct vrmr_list filter_input; /* list with rules */
    char filter_input_policy; /* policy for this chain: 0: accept, 1: drop */
    struct vrmr_list filter_forward; /* list with rules */
    char filter_forward_policy; /* policy for this chain: 0: accept, 1: drop */
    struct vrmr_list filter_output; /* list with rules */
    char filter_output_policy; /* policy for this chain: 0: accept, 1: drop */

    /*
        extra filter (no policies)
    */
    struct vrmr_list filter_antispoof;           /* list with rules */
    struct vrmr_list filter_blocklist;           /* list with rules */
    struct vrmr_list filter_blocktarget;         /* list with rules */
    struct vrmr_list filter_badtcp;              /* list with rules */
    struct vrmr_list filter_synlimittarget;      /* list with rules */
    struct vrmr_list filter_udplimittarget;      /* list with rules */
    struct vrmr_list filter_tcpresettarget;      /* list with rules */
    struct vrmr_list filter_newaccepttarget;     /* list with rules */
    struct vrmr_list filter_newnfqueuetarget;    /* list with rules */
    struct vrmr_list filter_estrelnfqueuetarget; /* list with rules */
    struct vrmr_list filter_newnflogtarget;      /* list with rules */
    struct vrmr_list filter_estrelnflogtarget;   /* list with rules */
    struct vrmr_list filter_accounting;          /* list with rules */

    /*
        special chains
    */
    char block;    /* the block target */
    char synlimit; /* synlimiting */

    /*
        shaping
    */
    struct vrmr_list tc_rules; /* list with tc rules */
};

struct cmd_line {
    /* commandline overrides */
    char vrmr_check_iptcaps_set;
    char vrmr_check_iptcaps;
    char verbose_out_set;
    char verbose_out;
    char configfile_set;
    char configfile[256];

    /* local settings */
    char keep_file;
    char loop;
    char nodaemon;
    char force_start;
};

/*@null@*/
extern struct vrmr_shm_table *shm_table;

/* semaphore id */
extern int sem_id;

/* pointer to the environment */
extern char **environ;

extern struct cmd_line cmdline;

/* rules.c */
void create_logprefix_string(struct vrmr_config *conf, char *, size_t, int,
        char *, char *, ...) ATTR_FMT_PRINTF(6, 7);

int oldrules_create_custom_chains(struct vrmr_rules *, struct vrmr_config *);

int analyze_interface_rules(struct vrmr_config *conf, struct vrmr_rules *,
        struct vrmr_zones *, struct vrmr_services *, struct vrmr_interfaces *);
int analyze_network_protect_rules(struct vrmr_config *conf, struct vrmr_rules *,
        struct vrmr_zones *, struct vrmr_services *, struct vrmr_interfaces *);
int analyze_normal_rules(struct vrmr_config *conf, struct vrmr_rules *,
        struct vrmr_zones *, struct vrmr_services *, struct vrmr_interfaces *);
int analyze_all_rules(struct vrmr_ctx *, struct vrmr_rules *);

int create_all_rules(struct vrmr_ctx *, int);

int pre_rules(struct vrmr_config *conf, /*@null@*/ struct rule_set *,
        struct vrmr_interfaces *, struct vrmr_iptcaps *);
int post_rules(struct vrmr_config *conf, /*@null@*/ struct rule_set *,
        struct vrmr_iptcaps *, int, int ipv);

int update_synlimit_rules(struct vrmr_config *conf,
        /*@null@*/ struct rule_set *, struct vrmr_iptcaps *, int);
int update_udplimit_rules(struct vrmr_config *conf,
        /*@null@*/ struct rule_set *, struct vrmr_iptcaps *, int);
int create_block_rules(struct vrmr_config *conf, /*@null@*/ struct rule_set *,
        struct vrmr_blocklist *);

int create_newnfqueue_rules(struct vrmr_config *conf,
        /*@null@*/ struct rule_set *, struct vrmr_rules *,
        struct vrmr_iptcaps *, int);
int create_estrelnfqueue_rules(struct vrmr_config *conf,
        /*@null@*/ struct rule_set *, struct vrmr_rules *,
        struct vrmr_iptcaps *, int);
int create_newnflog_rules(struct vrmr_config *conf,
        /*@null@*/ struct rule_set *, struct vrmr_rules *,
        struct vrmr_iptcaps *, int);
int create_estrelnflog_rules(struct vrmr_config *conf,
        /*@null@*/ struct rule_set *, struct vrmr_rules *,
        struct vrmr_iptcaps *, int);

int create_network_protect_rules(struct vrmr_config *conf,
        /*@null@*/ struct rule_set *, struct vrmr_zones *,
        struct vrmr_iptcaps *);
int create_interface_rules(struct vrmr_config *conf,
        /*@null@*/ struct rule_set *, struct vrmr_iptcaps *,
        struct vrmr_interfaces *);
int create_system_protectrules(struct vrmr_config *);
int create_normal_rules(
        struct vrmr_ctx *, /*@null@*/ struct rule_set *, char *);

int create_rule(struct vrmr_ctx *, /*@null@*/ struct rule_set *,
        struct vrmr_rule_cache *);
int remove_rule(
        struct vrmr_config *conf, int chaintype, int first_ipt_rule, int rules);

int create_rule_input(struct vrmr_config *conf, struct rule_scratch *,
        struct vrmr_rule_cache *, struct vrmr_iptcaps *);
int create_rule_output(struct vrmr_config *conf, struct rule_scratch *,
        struct vrmr_rule_cache *, struct vrmr_iptcaps *);
int create_rule_forward(struct vrmr_config *conf, struct rule_scratch *,
        struct vrmr_rule_cache *, struct vrmr_iptcaps *);
int create_rule_masq(struct vrmr_config *conf, struct rule_scratch *,
        struct vrmr_rule_cache *, struct vrmr_iptcaps *);
int create_rule_snat(struct vrmr_config *conf, struct rule_scratch *,
        struct vrmr_rule_cache *, struct vrmr_iptcaps *);
int create_rule_portfw(struct vrmr_config *conf, struct rule_scratch *,
        struct vrmr_rule_cache *, struct vrmr_iptcaps *);
int create_rule_redirect(struct vrmr_config *conf, struct rule_scratch *,
        struct vrmr_rule_cache *, struct vrmr_iptcaps *);
int create_rule_dnat(struct vrmr_config *conf, struct rule_scratch *,
        struct vrmr_rule_cache *, struct vrmr_iptcaps *);
int create_rule_bounce(struct vrmr_config *conf, struct rule_scratch *,
        struct vrmr_rule_cache *, struct vrmr_iptcaps *);
int create_rule_output_broadcast(struct vrmr_config *conf,
        struct rule_scratch *, struct vrmr_rule_cache *, struct vrmr_iptcaps *);
int create_rule_input_broadcast(struct vrmr_config *conf, struct rule_scratch *,
        struct vrmr_rule_cache *, struct vrmr_iptcaps *);

int clear_vuurmuur_iptables_rules(struct vrmr_config *cnf);
int clear_all_iptables_rules(struct vrmr_config *);

int process_queued_rules(struct vrmr_config *conf,
        /*@null@*/ struct rule_set *ruleset, struct rule_scratch *rule);

/* misc.c */
void send_hup_to_vuurmuurlog(void);
void cmdline_override_config(struct vrmr_config *conf);
int sysctl_exec(struct vrmr_config *cnf, char *key, char *value, int bash_out);

int logprint_error_bash(int errorlevel, const char *head, char *fmt, ...)
        ATTR_FMT_PRINTF(3, 4);
int logprint_warning_bash(const char *head, char *fmt, ...)
        ATTR_FMT_PRINTF(2, 3);
int logprint_info_bash(const char *head, char *fmt, ...) ATTR_FMT_PRINTF(2, 3);

/* reload.c */
int apply_changes(struct vrmr_ctx *vctx, struct vrmr_regex *);

int reload_services(struct vrmr_ctx *, struct vrmr_services *, regex_t *);
int reload_vrmr_services_check(struct vrmr_ctx *, struct vrmr_service *);

int reload_zonedata(struct vrmr_ctx *, struct vrmr_zones *,
        struct vrmr_interfaces *, struct vrmr_regex *);
int reload_zonedata_check(struct vrmr_ctx *, struct vrmr_zones *,
        struct vrmr_interfaces *, struct vrmr_zone *, struct vrmr_regex *);

int reload_interfaces(struct vrmr_ctx *, struct vrmr_interfaces *);
int reload_vrmr_interfaces_check(
        struct vrmr_ctx *, struct vrmr_interface *iface_ptr);

int check_for_changed_dynamic_ips(struct vrmr_interfaces *interfaces);

/* ruleset */
int ruleset_add_rule_to_set(
        struct vrmr_list *, char *, char *, uint64_t, uint64_t);
int load_ruleset(struct vrmr_ctx *);

/* shape */
int shaping_setup_roots(struct vrmr_config *cnf,
        struct vrmr_interfaces *interfaces, /*@null@*/ struct rule_set *);
int shaping_clear_interfaces(struct vrmr_config *cnf,
        struct vrmr_interfaces *interfaces,
        /*@null@*/ struct rule_set *ruleset);
int determine_minimal_default_rates(
        struct vrmr_interfaces *interfaces, struct vrmr_rules *rules);
int shaping_create_default_rules(struct vrmr_config *cnf,
        struct vrmr_interfaces *interfaces,
        /*@null@*/ struct rule_set *ruleset);
int shaping_shape_rule(/*@null@*/ struct vrmr_rule_options *opt);
int shaping_shape_incoming_rule(/*@null@*/ struct vrmr_rule_options *opt);
int shaping_shape_outgoing_rule(/*@null@*/ struct vrmr_rule_options *opt);
int shaping_shape_interface(struct vrmr_interface *iface_ptr);
int shaping_shape_create_rule(struct vrmr_config *cnf,
        struct rule_scratch *rule, struct vrmr_interface *shape_iface_ptr,
        struct vrmr_interface *class_iface_ptr, uint16_t class, uint32_t rate,
        char *rate_unit, uint32_t ceil, char *ceil_unit, uint8_t prio);
int shaping_determine_minimal_default_rates(
        struct vrmr_interfaces *interfaces, struct vrmr_rules *rules);
int shaping_create_default_rules(struct vrmr_config *cnf,
        struct vrmr_interfaces *interfaces,
        /*@null@*/ struct rule_set *ruleset);
int shaping_process_queued_rules(struct vrmr_config *cnf,
        /*@null@*/ struct rule_set *ruleset, struct rule_scratch *rule);

#endif
