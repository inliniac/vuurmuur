/***************************************************************************
 *   Copyright (C) 2002-2013 by Victor Julien                              *
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

#ifndef __VUURMUUR_H__
#define __VUURMUUR_H__

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <time.h>       /* for logging */
#include <stdarg.h>
#include <arpa/inet.h>  /* included for check_ip function */
#include <sys/ipc.h>    /* inter process communication */
#include <sys/sem.h>    /* semaphore */
#include <sys/shm.h>    /* shared memory */
#include <dlfcn.h>      /* for the dynamic plugin loader */
#include <regex.h>      /* for input validation */
#include <net/if.h>     /* used for getting interface info from the system */
#include <sys/ioctl.h>  /* used for getting interface info from the system */
#include <pwd.h>        /* used for getting user information */
#include <ctype.h>      /* for isdigit, isalpha, etc */

/* this is to prevent some compiler warning when feeding the function name directly
   to vrprint.debug */
#define __FUNC__        (char *)__FUNCTION__

/* our version */
#define LIBVUURMUUR_VERSION	"0.8rc1"

/* we need this to stringify the VUURMUUR_CONFIGDIR which is supplied at compiletime see:
   http://gcc.gnu.org/onlinedocs/gcc-3.4.1/cpp/Stringification.html#Stringification */
#define xstr(s) str(s)
#define str(s) #s

/* debuglevels */
#define HIGH            3
#define MEDIUM          2
#define LOW             1

/* These are also defined in ncruses.h */
#ifndef TRUE
#define TRUE            (char)1
#endif
#ifndef FALSE
#define FALSE           (char)0
#endif

#define VRMR_LOG_PATH_SIZE          96

/*
    Max length of a host, network or zone. WARNING: if you change this, you also need to change it in the VRMR_ZONE_REGEX!!!
*/
#define VRMR_MAX_OPTIONS_LENGTH      256
#define VRMR_MAX_RULE_LENGTH         512

#define VRMR_MAX_INTERFACE           32

#define VRMR_MAX_SERVICE             32

#define VRMR_MAX_HOST                32
#define VRMR_MAX_NETWORK             32
#define VRMR_MAX_ZONE                32

#define VRMR_MAX_NET_ZONE            VRMR_MAX_NETWORK+VRMR_MAX_ZONE
#define VRMR_VRMR_MAX_HOST_NET_ZONE  VRMR_MAX_HOST+VRMR_MAX_NETWORK+VRMR_MAX_ZONE

#define VRMR_MAX_PROC_ENTRY_LENGHT   64

#define VRMR_PIPE_VERBOSE            (char)0
#define VRMR_PIPE_QUIET              (char)1


#define VRMR_STATOK_WANT_BOTH        (char)0
#define VRMR_STATOK_WANT_FILE        (char)1
#define VRMR_STATOK_WANT_DIR         (char)2

#define VRMR_STATOK_VERBOSE          (char)0
#define VRMR_STATOK_QUIET            (char)1

#define VRMR_STATOK_ALLOW_NOTFOUND   (char)0
#define VRMR_STATOK_MUST_EXIST       (char)1

#define VRMR_IPTCHK_VERBOSE          (char)0
#define VRMR_IPTCHK_QUIET            (char)1


/*
    default locations of files
*/
#define VRMR_DEFAULT_SYSCTL_LOCATION            "/sbin/sysctl"
#define VRMR_DEFAULT_IPTABLES_LOCATION          "/sbin/iptables"
#define VRMR_DEFAULT_IPTABLES_REST_LOCATION     "/sbin/iptables-restore"
#define VRMR_DEFAULT_IP6TABLES_LOCATION         "/sbin/ip6tables"
#define VRMR_DEFAULT_IP6TABLES_REST_LOCATION    "/sbin/ip6tables-restore"
#define VRMR_DEFAULT_RULES_LOCATION             "rules.conf"
#define VRMR_DEFAULT_LOGDIR_LOCATION            "/var/log/vuurmuur"
#define VRMR_DEFAULT_SYSTEMLOG_LOCATION         "/var/log/messages"
#define VRMR_DEFAULT_MODPROBE_LOCATION          "/sbin/modprobe"
#define VRMR_DEFAULT_CONNTRACK_LOCATION         "/usr/sbin/conntrack"
#define VRMR_DEFAULT_TC_LOCATION                "/sbin/tc"

#define VRMR_DEFAULT_BACKEND                    "textdir"

#define VRMR_DEFAULT_DYN_INT_CHECK          FALSE
#define VRMR_DEFAULT_DYN_INT_INTERVAL       (unsigned int)30

#define VRMR_DEFAULT_USE_SYN_LIMIT          TRUE
#define VRMR_DEFAULT_SYN_LIMIT              (unsigned int)10
#define VRMR_DEFAULT_SYN_LIMIT_BURST        (unsigned int)20

#define VRMR_DEFAULT_USE_UDP_LIMIT          TRUE
#define VRMR_DEFAULT_UDP_LIMIT              (unsigned int)15
#define VRMR_DEFAULT_UDP_LIMIT_BURST        (unsigned int)45

#define VRMR_DEFAULT_RULE_NFLOG             TRUE
#define VRMR_DEFAULT_NFGRP                  8

#define VRMR_DEFAULT_LOG_POLICY             TRUE                /* default we log the default policy */
#define VRMR_DEFAULT_LOG_POLICY_LIMIT       (unsigned int)30    /* default limit for logging the default policy */
#define VRMR_DEFAULT_LOG_TCP_OPTIONS        FALSE               /* default we don't log TCP options */
#define VRMR_DEFAULT_LOG_BLOCKLIST          TRUE                /* default we log blocklist violations */
#define VRMR_DEFAULT_LOG_INVALID            TRUE                /* default we log INVALID traffic */
#define VRMR_DEFAULT_LOG_NO_SYN             TRUE                /* default we log new TCP but no SYN */
#define VRMR_DEFAULT_LOG_PROBES             TRUE                /* default we log probes like XMAS */
#define VRMR_DEFAULT_LOG_FRAG               TRUE                /* default we log FRAGMENTED traffic */

#define VRMR_DEFAULT_DROP_INVALID           TRUE                /* default we drop INVALID traffic */

#define VRMR_DEFAULT_PROTECT_SYNCOOKIE      TRUE                /* default we protect against syn-flooding */
#define VRMR_DEFAULT_PROTECT_ECHOBROADCAST  TRUE                /* default we protect against echo-broadcasting */

#define VRMR_DEFAULT_OLD_CREATE_METHOD      FALSE               /* default we use new method */

#define VRMR_DEFAULT_LOAD_MODULES           TRUE                /* default we load modules */
#define VRMR_DEFAULT_MODULES_WAITTIME       0                   /* default we don't wait */

#define VRMR_DEFAULT_MAX_PERMISSION         0700                /* default only allow user rwx */

#define VRMR_MAX_LOGRULE_SIZE               512
#define VRMR_MAX_PIPE_COMMAND               512                 /* maximum lenght of the pipe command */
#define VRMR_MAX_RULECOMMENT_LEN            64                  /* length in characters (for widec) */

#define VRMR_PROC_IPCONNTRACK               "/proc/net/ip_conntrack"
#define VRMR_PROC_NFCONNTRACK               "/proc/net/nf_conntrack"

#define VRMR_MAX_BASH_DESC                  512

/* Special permission value, meaning don't check permissions. The value
 * is simply all ones. */
#define VRMR_ANY_PERMISSION                  (~((mode_t)0))

/*
    regexes
*/

/* zone name */
#define VRMR_ZONE_REGEX              "^([a-zA-Z0-9_-]{1,32})(([.])([a-zA-Z0-9_-]{1,32})(([.])([a-zA-Z0-9_-]{1,32}))?)?$"

#define VRMR_VRMR_ZONE_REGEX_ZONEPART     "^([a-zA-Z0-9_-]{1,32})$"
#define VRMR_VRMR_ZONE_REGEX_NETWORKPART  "^([a-zA-Z0-9_-]{1,32})$"
#define VRMR_VRMR_ZONE_REGEX_HOSTPART     "^([a-zA-Z0-9_-]{1,32})$"

/* service */
#define VRMR_SERV_REGEX              "^([a-zA-Z0-9_-]{1,32})$"

/* interface name */
#define VRMR_IFAC_REGEX              "^([a-zA-Z0-9_-]{1,32})$"

/* mac address */
#define VRMR_MAC_REGEX               "^[a-zA-Z0-9]{2}[:][a-zA-Z0-9]{2}[:][a-zA-Z0-9]{2}[:][a-zA-Z0-9]{2}[:][a-zA-Z0-9]{2}[:][a-zA-Z0-9]{2}$"

/* config line */
#define VRMR_CONFIG_REGEX            "^[A-Z]+[=]\".*\"$"

/* Some defines for character buffers we define in this file */
#define VRMR_MAX_IPV6_ADDR_LEN       40 /* 39 + null */

#define VRMR_IPV4                   4
#define VRMR_IPV6                   6

#define VRMR_VERBOSE                0
#define VRMR_QUIET                  1

#if defined (__GNU_LIBRARY__) && !defined (_SEM_SEMUN_UNDEFINED)
    /* use semun from sys/sem.h */
#else
union semun
{
    int                 val;
    struct semid_ds     *buf;
    unsigned short int  *array;
    struct seminfo      *__buf;
};
#endif

/*
    linked list
*/

/* the node */
struct vrmr_list_node {
    struct vrmr_list_node *next;
    struct vrmr_list_node *prev;
    void *data;
};


/* the list, containing the metadata */
struct vrmr_list {
    unsigned int len;

    struct vrmr_list_node *top;
    struct vrmr_list_node *bot;

    void(*remove)(void *data);
};

/*
    hash function
*/
struct vrmr_hash_table {
    /*  the number of rows in the hash table

        This is fixed on setup of the table.
    */
    unsigned int rows;

    /* the functions for hashing, comparing the data */
    unsigned int (*hash_func)    (const void *data);
    int          (*compare_func) (const void *table_data, const void *search_data);

    /* the number of cells in the table */
    unsigned int cells;

    /* the table itself. its an array of vrmr_lists */
    struct vrmr_list *table;
};

/*
    regular expressions
*/
struct vrmr_regex {
    /* names of objects */
    regex_t *zonename;

    regex_t *zone_part;
    regex_t *network_part;
    regex_t *host_part;

    regex_t *servicename;
    regex_t *interfacename;

    /* actions */
    regex_t *action;

    /* mac addresses */
    regex_t *macaddr;

    /* config line */
    regex_t *configline;

    /* comments */
    regex_t *comment;
};

/* structure portdata. Here we store a portrange

    Normally we use src_low and dst_low for an uncomplicated portrange (eg. src: 1045 dst: 22), both 'high' variables are 0.
    If the portrange is more complicated we use both (eg. src_low 1024 src_high: 65535)

    With icmp the dst_low is the icmp type (eg. 0 for echo reply) while dst_high is the icmp code.
    If dst_high is -1, code is not used. With icmp we don't use src, make sure they are 0.
*/
struct vrmr_portdata {
    int protocol;   /* 6 for tcp, 17 for udp, 47 for gre, 1 for icmp, etc */

    int src_low;    /* lower end of the portrange */
    int src_high;   /* higher-end, or if no portrange, the normal port */

    int dst_low;
    int dst_high;
};

#define vrmr_lock(x) vrmr_shm_lock(1,(x))
#define vrmr_unlock(x) vrmr_shm_lock(0,(x))

/* shared memory */
struct vrmr_shm_table {
    int sem_id;

    struct {
        char name[96];
        pid_t pid;
        int connected;

        /* username (for logging) */
        char username[32];

    } configtool;

    int config_changed;
    int backend_changed;

    int reload_result;
    int reload_progress; /* in per cent */
};

/*  RR is Reload Result

    it is used for the IPC with SHM between Vuurmuur,
    Vuurmuur_log and Vuurmuur_conf
*/
enum vrmr_reload_result {
    VRMR_RR_ERROR = -1,
    VRMR_RR_NO_RESULT_YET = 0,
    VRMR_RR_READY,
    VRMR_RR_SUCCES,
    VRMR_RR_NOCHANGES,
    VRMR_RR_RESULT_ACK,
};

/* in this structure we register the print functions. */
struct vrprint_ {
    /* the name of the program that is logging */
    const char *logger;

    /* print error. Head may be null. */
    int(*error)(int errorcode, char *head, char *fmt, ...);
    char errorlog[VRMR_LOG_PATH_SIZE];

    /* print warning */
    int(*warning)(char *head, char *fmt, ...);
    /* no location, warning is put in info and error */

    /* print info */
    int(*info)(char *head, char *fmt, ...);
    char infolog[VRMR_LOG_PATH_SIZE];

    /* print debug */
    int(*debug)(char *head, char *fmt, ...);
    char debuglog[VRMR_LOG_PATH_SIZE];

    /* the username used in the auditlog */
    const char *username;

    /* auditlog */
    int(*audit)(char *fmt, ...);
    char auditlog[VRMR_LOG_PATH_SIZE];
};

struct vrprint_ vrprint;
#define vrmr_error (void)vrprint.error
#define vrmr_warning (void)vrprint.warning
#define vrmr_info (void)vrprint.info
#define vrmr_debug (void)vrprint.debug
#define vrmr_audit (void)vrprint.audit

/* configuration */
struct vrmr_config {
    /* etcdir */
    char            etcdir[256];
    /* datadir */
    char            datadir[256];
    /* libdir */
    char            plugdir[256];
    /* configfile */
    char            configfile[256];

    /* program locations */
    char            sysctl_location[128];
    char            iptables_location[128];
    char            iptablesrestore_location[128];

    char            ip6tables_location[128];
    char            ip6tablesrestore_location[128];
    /** Fail when there is an error with IPv6 configuration, when set to TRUE */
    char            check_ipv6;

    char            conntrack_location[128];
    char            tc_location[128];

    char            blocklist_location[64];
    char            log_blocklist;

    char            rules_location[64];

    char            rule_nflog;
    char            nfgrp;

    /* logfile locations */
    char            vuurmuur_logdir_location[64];

    char            debuglog_location[VRMR_LOG_PATH_SIZE];
    char            vuurmuurlog_location[VRMR_LOG_PATH_SIZE];
    char            auditlog_location[VRMR_LOG_PATH_SIZE];
    char            errorlog_location[VRMR_LOG_PATH_SIZE];
    char            trafficlog_location[VRMR_LOG_PATH_SIZE];

    char            systemlog_location[64]; /* location to the log where syslog puts the iptables messages */

    char            loglevel_cmdline;       /* was the loglevel set by the command line? 0: no, 1: yes */
    char            loglevel[8];            /* 'warning' is the maximum */

    /* backend */
    char            serv_backend_name[32];
    char            zone_backend_name[32];
    char            ifac_backend_name[32];
    char            rule_backend_name[32];

    /* synflood protection */
    char            use_syn_limit;
    unsigned int    syn_limit;          /* the maximum number of SYN packets per second. */
    unsigned int    syn_limit_burst;    /* burst limit */

    /* udpflood protection */
    char            use_udp_limit;
    unsigned int    udp_limit;          /* the maximum number new udp connections per second */
    unsigned int    udp_limit_burst;    /* burst limit */

    char            protect_syncookie;
    char            protect_echobroadcast;

    /* policy */
    char            log_policy;
    unsigned int    log_policy_limit;
    unsigned int    log_policy_burst;

    char            log_tcp_options;    /* log tcp options for PSAD */

    char            log_invalid;        /* log invalid */
    char            log_no_syn;         /* log no syn */
    char            log_probes;         /* log probes */
    char            log_frag;           /* log frag */


    char            dynamic_changes_check;  /* 0: off, 1: on: check for changed ip's on dynamic interfaces */
    unsigned int    dynamic_changes_interval;   /* check every x seconds for changes in the dynamic interfaces */

    char            old_rulecreation_method;    /* 0: off, 1: on: if on we use iptables else iptables-restore */

    char            load_modules;           /* load modules if needed? 1: yes, 0: no */
    unsigned int    modules_wait_time;      /* time to wait in 1/10 th of a second */

    char            modprobe_location[128]; /* location of the 'modprobe' command */


    char            vrmr_check_iptcaps;          /* 0: no, 1: yes */

    /* run-time options */
    char            bash_out;
    char            verbose_out;
    char            test_mode;


    /* this is detected at runtime */
    char            use_ipconntrack;

	/* Maximum permissions for files and directories used by vuurmuur
	   (config & log files). This should include x bits, which are
	   filtered out for files. */
	mode_t          max_permission;

    /* conntrack options */
    char            invalid_drop_enabled;
};

/* DATA STRUCTURES */
struct vrmr_interfaces {
    /* the list with interfaces */
    struct vrmr_list      list;

    /* is at least one of the interfaces active? */
    char        active_interfaces;

    /* is at least one of the interfaces dynamic? */
    char        dynamic_interfaces;

    uint16_t   shape_handle;
};

struct vrmr_services {
    /* the list with services */
    struct vrmr_list  list;
};

struct vrmr_zones {
    /* the list with zones */
    struct vrmr_list  list;
};

struct vrmr_rules {
    /* the list with rules */
    struct vrmr_list  list;

    char    old_rulesfile_used;

    /* list of chain names that are defined by the rules */
    struct vrmr_list  custom_chain_list;
    /* list of chains currently in the system */
    struct vrmr_list  system_chain_filter;
    struct vrmr_list  system_chain_mangle;
    struct vrmr_list  system_chain_nat;
    struct vrmr_list  system_chain_raw;
};

struct vrmr_blocklist {
    /* the list with blocked ips/hosts/groups */
    struct vrmr_list list;

    char old_blocklistfile_used;

};

struct vrmr_ipv4_data {
    char ipaddress[16];            //16 should be enough for an ipaddress.
    char network[16];
    char netmask[16];
    char broadcast[16];            //16 should be enough for a netmask
};

struct vrmr_ipv6_data {
    char ip6[VRMR_MAX_IPV6_ADDR_LEN];    /* host ip-address */
    char net6[VRMR_MAX_IPV6_ADDR_LEN];   /* network address string */
    int cidr6;                      /* CIDR: -1 unitialized, 0-128 are valid masks */
};

/* rule options */
struct vrmr_rule_options {
    char            rule_log;       /* 0 = don't log rule, 1 = log this rule */

    char            logprefix[32];  /* 29 is max of iptables, we use 32: 29 iptables, 2 trema's and a '\0'. */
    char            rule_logprefix; /* 0 = don't use logprefix, 1 = use logprefix */

    unsigned int    loglimit;       /* 0 = no limit, > 0 = use limit and the value */
    unsigned int    logburst;       /* burst value */

    char            comment[128];
    char            rule_comment;   /* 0 = rule has no comment, 1 = rule has a comment */

    /* Port forwarding */
    char            remoteport;     /* 0 = don't use remoteport, 1 = use remote port */
    struct vrmr_list RemoteportList;

    char            listenport;
    struct vrmr_list ListenportList;

    /* redirect */
    int             redirectport;

    /* portfw and redirect: queue instead of accept: 1: queue, 0: accept */
    char            queue;
    /* portfw and redirect: create only a firewall rule for this interface. */
    char            in_int[VRMR_MAX_INTERFACE];
    /* snat: select an outgoing interface */
    char            out_int[VRMR_MAX_INTERFACE];
    /* bounce: via interface */
    char            via_int[VRMR_MAX_INTERFACE];

    /* reject */
    char            reject_option;      /* 0 = don't use reject_type, 1 = use reject_type */
    char            reject_type[23];    /* icmp-proto-unreachable = 22 + 1 */

    unsigned long   nfmark;             /* netfilter mark to set */

    /* custom chain, for use with the chain action */
    char            chain[32];

    /* limit for this rule */
    unsigned int    limit;
    char            limit_unit[5];      /* sec, min, hour, day */
    unsigned int    burst;

    /* queue num for the NFQUEUE action. There can be 65536: 0-65535 */
    uint16_t        nfqueue_num;
    /* queue num for the NFLOG action. There can be 65536: 0-65535 */
    uint16_t        nflog_num;

    /* shaping */
    uint32_t        bw_in_max;          /* ceil from dst to src */
    char            bw_in_max_unit[5];  /* kbit, mbit, kbps, mbps */
    uint32_t        bw_in_min;          /* rate from dst to src */
    char            bw_in_min_unit[5];  /* kbit, mbit, kbps, mbps */
    uint32_t        bw_out_max;         /* ceil from src to dst */
    char            bw_out_max_unit[5]; /* kbit, mbit, kbps, mbps */
    uint32_t        bw_out_min;         /* rate from src to dst */
    char            bw_out_min_unit[5]; /* kbit, mbit, kbps, mbps */
    uint8_t         prio;               /* priority */

    char            random; /* adds --random to the DNAT/SNAT/??? target */
};

struct vrmr_danger_info {
    int solution;                 // 1 = iptables, 2 = change proc

    char proc_entry[VRMR_MAX_PROC_ENTRY_LENGHT];          // line with the proc dir
    int proc_set_on;
    int proc_set_off;

    struct vrmr_ipv4_data source_ip;

    char type[16];
    char source[16];
};

struct vrmr_interface_counters {
    unsigned long long  input_packets;
    unsigned long long  input_bytes;

    unsigned long long  output_packets;
    unsigned long long  output_bytes;

    unsigned long long  forwardin_packets;
    unsigned long long  forwardin_bytes;

    unsigned long long  forwardout_packets;
    unsigned long long  forwardout_bytes;

    /* for the accounting rules for IPTrafVol */
    unsigned long long  acc_in_packets;
    unsigned long long  acc_in_bytes;
    unsigned long long  acc_out_packets;
    unsigned long long  acc_out_bytes;
};

struct vrmr_interface {
    /* this should always be on top */
    int             type;

    char            name[VRMR_MAX_INTERFACE];

    char            active;
    int             status;

    /* is the interface up? 0: no, 1: yes */
    char            up;

    /* the system device */
    char            device[16];

    /*  is the device virtual?
        0: no
        1: yes
    */
    char            device_virtual;
    /* old style (eth0:0) */
    char            device_virtual_oldstyle;

    /* the ipaddress */
    struct vrmr_ipv4_data ipv4;
    struct vrmr_ipv6_data ipv6;

    /*  is a ipaddress dynamic?
        0: no
        1: yes
    */
    char            dynamic;

    /* protect rules for the interface */
    struct vrmr_list ProtectList;

    /* counters for iptables-restore */
    struct vrmr_interface_counters *cnt;

    /* reference counters */
    unsigned int    refcnt_network;

    /* traffic shaping */
    char            shape;              /* shape on this interface? 1: yes, 0: no */
    uint32_t        bw_in;              /* maximal bw in "unit" (download) */
    uint32_t        bw_out;             /* maximal bw in "unit" (upload) */
    char            bw_in_unit[5];      /* kbit or mbit */
    char            bw_out_unit[5];     /* kbit or mbit */
    uint32_t        min_bw_in;          /* minimal per rule rate in kbits (download) */
    uint32_t        min_bw_out;         /* minimal per rule rate in kbits (upload) */

    uint16_t        shape_handle;       /* tc handle */
    uint32_t        shape_default_rate; /* rate used by default rule and shaping rules
                                         * w/o an explicit rate */

    uint32_t        total_shape_rate;
    uint32_t        total_shape_rules;
    uint32_t        total_default_shape_rules;

    /* tcpmss clamping */
    char            tcpmss_clamp;
};

/* this is our structure for the zone data */
struct vrmr_zone {
    int                 type;   /* this should always be on top */

    /* basic vars */
    char                name[VRMR_VRMR_MAX_HOST_NET_ZONE];

    char                active; // 0 no, 1 yes
    int                 status;

    /* group stuff */
    unsigned int        group_member_count;
    struct vrmr_list              GroupList;

    /* for names */
    char                host_name[VRMR_MAX_HOST];
    char                network_name[VRMR_MAX_NETWORK];
    char                zone_name[VRMR_MAX_ZONE];

    /* pointers to parent zone and network (NULL if zone/network) */
    struct vrmr_zone    *zone_parent;
    struct vrmr_zone    *network_parent;

    struct vrmr_ipv4_data ipv4;
    struct vrmr_ipv6_data ipv6;

    /* TODO: 18 is enough: 00:20:1b:10:1D:0F = 17 + '\0' = 18. */
    char                mac[19];
    int                 has_mac;

    /* the list with interfaces: for networks */
    int                 active_interfaces;
    struct vrmr_list    InterfaceList;

    /* protect rules for the network */
    struct vrmr_list    ProtectList;

    /* reference counters */
    unsigned int        refcnt_group;
    unsigned int        refcnt_rule;
    unsigned int        refcnt_blocklist;
};

/*
    this is our structure for the services data
*/
struct vrmr_service {
    int     type;               /* this should always be on top */

    char    name[VRMR_MAX_SERVICE];

    char    active;                    // 0 no, 1 yes
    int     status;                    // 0 = not touched, -1 = remove, 1 = keep unchanged, 2 = changed, 3 = new

    char    helper[32];

    int     vrmr_hash_port;

    struct vrmr_list PortrangeList;

    char    broadcast;          /* 1: broadcasting service, 0: not */
};

struct vrmr_rules_chaincount {
    int input;              /* number of input rules for this rule */
    int output;
    int forward;
    int preroute;
    int postroute;

    int start_input;        /* where to insert this rule */
    int start_output;
    int start_forward;
    int start_preroute;
    int start_postroute;
};

/* here we assemble the data for creating the actual rule */
struct vrmr_rule_cache {
    char                active;

    char                from_firewall;      /* from network is: 0 a network, 1 a firewall */
    char                from_firewall_any;  /* firewall(any) */

    char                to_firewall;        /* to   network is: 0 a network, 1 a firewall */
    char                to_firewall_any;    /* firewall(any) */

    char                from_any;           /* from is 'any' */
    char                to_any;             /* to is 'any' */
    char                service_any;        /* service is 'any' */

    struct vrmr_zone            *from;              /* from data */
    struct vrmr_zone            *to;                /* to data */

    struct vrmr_zone            *who;               /* for protect */
    struct vrmr_interface       *who_int;           /* for protect */

    struct vrmr_interface       *via_int;           /* for bounce rules */

    struct vrmr_rules_chaincount iptcount;           /* the counters */

    char                action[122];        /* max: REJECT --reject-with icmp-proto-unreachable (42)
                                                LOG --log-prefix 12345678901234567890123456789 (45)
                                                LOG --log-ip-options --log-tcp-options --log-tcp-sequence --log-level 123 --log-prefix 12345678901234567890123456789 (116)
                                                LOG --log-ip-options --log-tcp-options --log-tcp-sequence --log-level warning --log-prefix 12345678901234567890123456789 (121)
                                                */

    int                 ruletype;           /* type of rule: input, output, forward, masq etc. */
    int                 ruleaction;         /* type of action: append, insert */

    struct vrmr_danger_info danger;

    struct vrmr_service *service;           /* pointer to the service in the services-linked-list */

    struct vrmr_rule_options option;

    char                *description;       /* only used for bash_out, and maybe later for vuurmuur-conf */
};

struct vrmr_rule {
    int                 type;       /* this should always be on top */

    char                error;

    char                active;     /* is the rule active? */

    int                 action;     /* the action of the rule */

    unsigned int        number;
    int                 status;

    /* normal rules */
    char                service[VRMR_MAX_SERVICE];
    char                from[VRMR_VRMR_MAX_HOST_NET_ZONE];
    char                to[VRMR_VRMR_MAX_HOST_NET_ZONE];

    /* protect rules */
    char                who[VRMR_VRMR_MAX_HOST_NET_ZONE];
    char                danger[64];
//TODO size right?
    char                source[32];

    struct vrmr_rule_options *opt;

    struct vrmr_rule_cache rulecache;

    char                filtered;       /* used by vuurmuur_conf */
};

struct vrmr_filter {
    char        str[32];

    /* are we matching the string or only _not_
       the string? */
    char        neg;

    char        reg_active;
    regex_t     reg;

};

#ifndef _NETINET_TCP_H
/* connection status from conntrack */
enum vrmr_tcp_states {
    UNDEFINED=0,
    TCP_ESTABLISHED,
    UDP_ESTABLISHED,
    SYN_SENT,
    SYN_RECV,
    FIN_WAIT,
    TIME_WAIT,
    CLOSE,
    CLOSE_WAIT,
    LAST_ACK,
    UNREPLIED,
    NONE,
};
#endif

/* simplified connection status in vuurmuur */
enum
{
    VRMR_CONN_UNUSED=0,
    VRMR_CONN_CONNECTING,
    VRMR_CONN_CONNECTED,
    VRMR_CONN_DISCONNECTING,
    VRMR_CONN_IN,
    VRMR_CONN_OUT,
    VRMR_CONN_FW,
};

struct vrmr_conntrack_entry {
    int                     protocol;
    int                     ipv6;

    /*  the service

        sername is a pointer to service->name unless service is NULL
    */
    char                    *sername;
    struct vrmr_service     *service;

    /*  this is for hashing the service. It is also supplied in
        struct vrmr_service, but we need it also for undefined
        services, so we suppy it here. We only hash on protocol and
        dst_port, because the src_port is almost always different.
    */
    int                     dst_port;

    /* src port is not needed for anything, we only use it for detailed info
       in the connection section from Vuurmuur_conf */
    int                     src_port;

    /* from/source */
    char                    *fromname;
    struct vrmr_zone        *from;
    char                    src_ip[46];

    /* to/destination */
    char                    *toname;
    struct vrmr_zone        *to;
    char                    dst_ip[46];
    char                    orig_dst_ip[46]; /* ip before nat correction */

    /* counter */
    int                     cnt;

    struct vrmr_list_node   *d_node;

    /* connection status - 0 for unused */
    int                     connect_status;
    /* do we use connect_status */
    int                     direction_status;

    char                    use_acc;
    unsigned long long      to_src_packets;
    unsigned long long      to_src_bytes;
    unsigned long long      to_dst_packets;
    unsigned long long      to_dst_bytes;
};

struct vrmr_conntrack_stats {
    /* total, incoming, outgoing and forwarded connections */
    int conn_total;
    int conn_in;
    int conn_out;
    int conn_fw;

    /* connecting, established, closing and other connections */
    int stat_connect;
    int stat_estab;
    int stat_closing;
    int stat_other;

    int active_serv;
    int active_from;
    int active_to;

    unsigned int sername_max;
    unsigned int fromname_max;
    unsigned int toname_max;

    /** if any of the flows/connections has accounting info, this
     *  is set to 1. */
    int accounting;
};

struct vrmr_conntrack_request {
    struct vrmr_filter filter;
    char        use_filter;

    char        group_conns;
    char        unknown_ip_as_net;

    /* sorting, relevant for grouping */
    char        sort_in_out_fwd;
    char        sort_conn_status;

    char        draw_acc_data;
    char        draw_details;
    char        ipv6;
};

/*
    Iptables Capabilities
*/
struct vrmr_iptcaps {
    char    proc_net_names;
    char    proc_net_matches;
    char    proc_net_targets;

    char    conntrack;

    /* names */
    char    table_filter;
    char    table_mangle;
    char    table_nat;
    char    table_raw;

    /* targets */
    char    target_snat;
    char    target_dnat;

    char    target_reject;
    char    target_log;
    char    target_nflog;
    char    target_redirect;
    char    target_mark;
    char    target_masquerade;
    char    target_classify;

    char    target_queue;
    pid_t   queue_peer_pid;

    char    target_nfqueue;
    char    target_connmark;
    char    proc_net_netfilter_nfnetlink_queue;

    char    target_tcpmss;

    /* matches */
    char    match_tcp;
    char    match_udp;
    char    match_icmp;

    char    match_mark;
    char    match_state;
    char    match_helper;
    char    match_length;
    char    match_limit;
    char    match_mac;
    char    match_connmark;
    char    match_conntrack;
    char    match_rpfilter;

    char    target_nat_random;

    /* IPv6 */
    char    proc_net_ip6_names;
    char    proc_net_ip6_matches;
    char    proc_net_ip6_targets;

    /* char conntrack; */

    /* IPv6 names */
    char    table_ip6_filter;
    char    table_ip6_mangle;
    /* there is no NAT table available for IPv6 */
    char    table_ip6_raw;

    /* IPv6 targets */
    /* No snat, dnat, redirect or masquerade available for IPv6 */
    char    target_ip6_reject;
    char    target_ip6_log;
    char    target_ip6_mark;
    char    target_ip6_classify;

    char    target_ip6_queue;
    pid_t   ip6_queue_peer_pid;

    char    target_ip6_nfqueue;
    char    target_ip6_connmark;
    char    proc_net_netfilter_nfnetlink_ip6_queue;

    char    target_ip6_tcpmss;

    /* IPv6 matches */
    char    match_ip6_tcp;
    char    match_ip6_udp;
    char    match_icmp6;

    char    match_ip6_mark;
    char    match_ip6_state;
    char    match_ip6_helper;
    char    match_ip6_length;
    char    match_ip6_limit;
    char    match_ip6_mac;

    char    match_ip6_connmark;
    char    match_ip6_conntrack;
    char    match_ip6_rpfilter;
};

/*  These functions are to be used for modifing the backend, reading from it, etc. */
struct vrmr_plugin_data {
    /* asking from and telling to the backend */
    int (*ask)(int debuglvl, void *backend, char *name, char *question, char *answer, size_t max_answer, int type, int multi);
    int (*tell)(int debuglvl, void *backend, char *name, char *question, char *answer, int overwrite, int type);

    /* opening and closing the backend */
    int (*open)(int debuglvl, void *backend, int mode, int type);
    int (*close)(int debuglvl, void *backend, int type);

    /* listing the items in the backend */
    char *(*list)(int debuglvl, void *backend, char *name, int *zonetype, int type);

    /* setting up the backend for first use */
    int (*init)(int debuglvl, void *backend, int type);
    /* TODO, clear the backend (opposite of init) */

    /*adding and removing items from the backend */
    int (*add)(int debuglvl, void *backend, char *name, int type);
    int (*del)(int debuglvl, void *backend, char *name, int type, int recurs);

    /* rename */
    int (*rename)(int debuglvl, void *backend, char *name, char *newname, int type);

    /* conf function */
    int (*conf)(int debuglvl, void *backend);

    /* setup: alloc memory and set defaults */
    int (*setup)(int debuglvl, const struct vrmr_config *cnf, void **backend);

    /* version */
    char *version;
    char *name;
};

struct vrmr_plugin {
    char                        name[32];
    int                         ref_cnt;

    struct vrmr_plugin_data     *f;

    /* version */
    char                        *version;
};

struct vrmr_user {
    uid_t   user;
    char    username[32];

    gid_t   group;
    char    groupname[32];

    uid_t   realuser;
    char    realusername[32];
};

struct vrmr_ctx {
    struct vrmr_zones zones;
    struct vrmr_interfaces interfaces;
    struct vrmr_blocklist blocklist;
    struct vrmr_rules rules;
    struct vrmr_services services;
    struct vrmr_config conf;
    struct vrmr_iptcaps iptcaps;
    struct vrmr_regex reg;
    struct vrmr_user user_data;

    struct vrmr_plugin_data *zf;
    /*@null@*/void *zone_backend;

    struct vrmr_plugin_data *sf;
    /*@null@*/void *serv_backend;

    struct vrmr_plugin_data *af;
    /*@null@*/void *ifac_backend;

    struct vrmr_plugin_data *rf;
    /*@null@*/void *rule_backend;
};

enum vrmr_objectstatus {
    VRMR_ST_REMOVED = -1,
    VRMR_ST_UNTOUCHED,
    VRMR_ST_KEEP,
    VRMR_ST_CHANGED,
    VRMR_ST_ADDED,
    VRMR_ST_ACTIVATED,
    VRMR_ST_DEACTIVATED
};


/* a value like: 'dnsserver.dmz.internet' can be a: */
enum vrmr_objecttypes {
    VRMR_TYPE_ERROR = -1,
    VRMR_TYPE_UNSET = 0,

    VRMR_TYPE_FIREWALL,
    VRMR_TYPE_HOST,
    VRMR_TYPE_GROUP,
    VRMR_TYPE_NETWORK,
    VRMR_TYPE_ZONE,
    VRMR_TYPE_SERVICE,
    VRMR_VRMR_TYPE_SERVICEGRP, /* not implemented */
    VRMR_TYPE_INTERFACE,
    VRMR_TYPE_RULE,

    VRMR_TYPE_TOO_BIG
};


/* protect rule types */
enum vrmr_protecttypes {
    VRMR_PROT_NO_PROT = 0,
    VRMR_PROT_IPTABLES,
    VRMR_PROT_PROC_SYS,
    VRMR_PROT_PROC_INT
};


/* normal rule types */
enum vrmr_ruletype {
    VRMR_RT_ERROR = -1,
    VRMR_RT_NOTSET = 0,
    VRMR_RT_INPUT,
    VRMR_RT_OUTPUT,
    VRMR_RT_FORWARD,
    VRMR_RT_MASQ,
    VRMR_RT_PORTFW,
    VRMR_RT_SNAT,
    VRMR_RT_REDIRECT,
    VRMR_RT_DNAT,
    VRMR_RT_BOUNCE,
};


/* general datatypes */
enum vrmr_backend_types {
    VRMR_BT_ZONES,
    VRMR_BT_SERVICES,
    VRMR_BT_INTERFACES,
    VRMR_BT_RULES
};


/* posible results for initializing the config */
enum vrmr_conf_return_codes {
    VRMR_CNF_E_UNKNOWN_ERR = -6,

    /* function was called wrong */
    VRMR_CNF_E_PARAMETER = -5,

    /* serious permission problem with configfile */
    VRMR_CNF_E_FILE_PERMISSION = -4,

    /* configfile missing */
    VRMR_CNF_E_FILE_MISSING = -3,

    /* eg an negative unsigned int, or an wrong iptables command */
    VRMR_CNF_E_ILLEGAL_VAR = -2,

    /* missing variable in config file, fatal */
    VRMR_CNF_E_MISSING_VAR = -1,

    /* all went well! */
    VRMR_CNF_OK = 0,

    /* missing variable in config file, non fatal */
    VRMR_CNF_W_MISSING_VAR,

    /* eg an negative unsigned int */
    VRMR_CNF_W_ILLEGAL_VAR,

};


/*  Valid actions are: "Accept", "Drop", "Reject", "Log",
    "Portfw", "Redirect", "Snat", "Masq", "Queue", "Chain",
    "NFQueue", "NFlog"
*/
enum vrmr_actiontypes {
    VRMR_AT_ERROR = -1,
    VRMR_AT_ACCEPT,      /* ACCEPT */
    VRMR_AT_DROP,        /* DROP */
    VRMR_AT_REJECT,      /* REJECT */
    VRMR_AT_LOG,         /* LOG */
    VRMR_AT_PORTFW,      /* DNAT+ACCEPT( or QUEUE) */
    VRMR_AT_REDIRECT,    /* REDIRECT+ACCEPT( or QUEUE) */
    VRMR_AT_SNAT,        /* SNAT */
    VRMR_AT_MASQ,        /* MASQUERADE */
    VRMR_AT_QUEUE,       /* QUEUE */
    VRMR_AT_CHAIN,       /* custom chain */
    VRMR_AT_DNAT,        /* DNAT */
    VRMR_AT_BOUNCE,      /* DNAT+SNAT */
    VRMR_AT_NFQUEUE,     /* NFQUEUE */
    VRMR_AT_NFLOG,       /* NFLOG */

    /* special for networks and interfaces */
    VRMR_AT_PROTECT,

    /* special, not really an action */
    VRMR_AT_SEPARATOR,

    /* this is of course not an action */
    VRMR_AT_TOO_BIG,
};

struct vrmr_log_record
{
    char            month[4];
    int             day;

    int             hour;
    int             minute;
    int             second;

    char            hostname[HOST_NAME_MAX];
    char            logger[32];

    char            action[16];

    char            logprefix[32];

    char            interface_in[16];
    char            interface_out[16];

    char            src_ip[46];
    char            dst_ip[46];
    int             ipv6;

    int             protocol;
    int             src_port;
    int             dst_port;
    int             icmp_type;
    int             icmp_code;

    char            src_mac[20]; /* 17 for mac addr, 2 for brackets, 1 for \0 */
    char            dst_mac[20];

    unsigned int    packet_len; /* length of the logged packet */

    char            syn;        /* is syn-bit set? 0: no, 1: yes */
    char            fin;        /* is fin-bit set? 0: no, 1: yes */
    char            rst;        /* is rst-bit set? 0: no, 1: yes */
    char            ack;        /* is ack-bit set? 0: no, 1: yes */
    char            psh;        /* is psh-bit set? 0: no, 1: yes */
    char            urg;        /* is urg-bit set? 0: no, 1: yes */

    unsigned int    ttl;

    char            from_name[VRMR_VRMR_MAX_HOST_NET_ZONE];
    char            to_name[VRMR_VRMR_MAX_HOST_NET_ZONE];
    char            ser_name[VRMR_MAX_SERVICE];
    char            from_int[VRMR_MAX_INTERFACE+5];  /* 'in: ' */
    char            to_int[VRMR_MAX_INTERFACE+6];    /* 'out: ' */

    char            tcpflags[7];
};

/*
    libvuurmuur.c
*/
/*@null@*/
void *vrmr_rule_malloc(void);
/*@null@*/
void *vrmr_zone_malloc(int debuglvl);
void vrmr_zone_free(int debuglvl, struct vrmr_zone *zone_ptr);
/*@null@*/
void *vrmr_service_malloc(void);
/*@null@*/
void *vrmr_interface_malloc(const int debuglvl);
/*@null@*/
void *vrmr_rule_option_malloc(int debuglvl);
int vrmr_shm_lock(int, int);
char *libvuurmuur_get_version(void);
int vrmr_regex_setup(int action, struct vrmr_regex *reg);

int range_strcpy(char *dest, const char *src, const size_t start, const size_t end, size_t size);
size_t strlcat(char *dst, const char *src, size_t size);
size_t strlcpy(char *dst, const char *src, size_t size);

/*
    hash table
*/
int vrmr_hash_setup(const int debuglvl, struct vrmr_hash_table *hash_table, unsigned int rows, unsigned int (*hash_func)(const void *data), int (*compare_func)(const void *table_data, const void *search_data));
int vrmr_hash_cleanup(const int debuglvl, struct vrmr_hash_table *hash_table);
int vrmr_hash_insert(const int debuglvl, struct vrmr_hash_table *hash_table, const void *data);
int vrmr_hash_remove(const int debuglvl, struct vrmr_hash_table *hash_table, void *data);
void *vrmr_hash_search(const int debuglvl, const struct vrmr_hash_table *hash_table, void *data);

int vrmr_compare_ports(const void *string1, const void *string2);
int vrmr_compare_ipaddress(const void *string1, const void *string2);
int vrmr_compare_string(const void *string1, const void *string2);
unsigned int vrmr_hash_port(const void *key);
unsigned int vrmr_hash_ipaddress(const void *key);
unsigned int vrmr_hash_string(const void *key);

void vrmr_print_table_service(const int debuglvl, const struct vrmr_hash_table *hash_table);
int vrmr_init_zonedata_hashtable(const int debuglvl, unsigned int n_rows, struct vrmr_list *, unsigned int (*hash)(const void *key), int (*match)(const void *string1, const void *string2), struct vrmr_hash_table *hash_table);
int vrmr_init_services_hashtable(const int debuglvl, unsigned int n_rows, struct vrmr_list *, unsigned int (*hash)(const void *key), int (*match)(const void *string1, const void *string2), struct vrmr_hash_table *hash_table);
void *vrmr_search_service_in_hash(const int debuglvl, const int src, const int dst, const int protocol, const struct vrmr_hash_table *serhash);
void *vrmr_search_zone_in_hash_with_ipv4(const int debuglvl, const char *ipaddress, const struct vrmr_hash_table *zonehash);

/*
    query.c
*/
int vrmr_rules_remove_rule_from_list(const int, struct vrmr_rules *, unsigned int, int);
void vrmr_rules_update_numbers(const int, struct vrmr_rules *, unsigned int place, int);
void vrmr_rules_print_list(const struct vrmr_rules *);
void vrmr_rules_free_options(const int debuglvl, struct vrmr_rule_options *opt);

/*
    zones.c
*/
int vrmr_insert_zonedata_list(const int, struct vrmr_zones *, const struct vrmr_zone *);
void vrmr_zonedata_print_list(const struct vrmr_zones *);
int vrmr_init_zonedata(const int, struct vrmr_ctx *, /*@out@*/ struct vrmr_zones *, struct vrmr_interfaces *, struct vrmr_regex *);
int vrmr_insert_zonedata(const int, struct vrmr_ctx *, struct vrmr_zones *, struct vrmr_interfaces *, char *, int, struct vrmr_regex *);
int vrmr_read_zonedata(const int, struct vrmr_ctx *, struct vrmr_zones *, struct vrmr_interfaces *, char *, int, struct vrmr_zone *, struct vrmr_regex *);
void *vrmr_search_zonedata(const int, const struct vrmr_zones *, char *);
void vrmr_destroy_zonedatalist(const int, struct vrmr_zones *);
int vrmr_count_zones(const int, struct vrmr_zones *, int, char *, char *);
int vrmr_new_zone(const int, struct vrmr_ctx *, struct vrmr_zones *, char *, int);
int vrmr_delete_zone(const int, struct vrmr_ctx *, struct vrmr_zones *, char *, int);
int vrmr_zonelist_to_networklist(const int, struct vrmr_zones *, struct vrmr_list *);
int vrmr_add_broadcasts_zonelist(const int, struct vrmr_zones *);
int vrmr_validate_zonename(const int, const char *, int, char *, char *, char *, regex_t *, char);
int vrmr_zones_group_save_members(const int, struct vrmr_ctx *, struct vrmr_zone *);
int vrmr_zones_network_add_iface(const int, struct vrmr_interfaces *, struct vrmr_zone *, char *);
int vrmr_zones_network_rem_iface(const int, struct vrmr_ctx *, struct vrmr_zone *, char *);
int vrmr_zones_network_get_interfaces(const int, struct vrmr_ctx *, struct vrmr_zone *, struct vrmr_interfaces *);
int vrmr_zones_network_save_interfaces(const int, struct vrmr_ctx *, struct vrmr_zone *);
int vrmr_zones_network_get_protectrules(const int, struct vrmr_ctx *, struct vrmr_zone *);
int vrmr_zones_group_rem_member(const int, struct vrmr_ctx *, struct vrmr_zone *, char *);
int vrmr_zones_group_add_member(const int, struct vrmr_ctx *, struct vrmr_zones *, struct vrmr_zone *, char *);
int vrmr_zones_active(const int, struct vrmr_zone *);
int vrmr_zones_check_host(const int, struct vrmr_zone *);
int vrmr_zones_check_group(const int, struct vrmr_zone *);
int vrmr_zones_check_network(const int, struct vrmr_zone *);
int vrmr_zones_load(const int, struct vrmr_ctx *, struct vrmr_zones *, struct vrmr_interfaces *, struct vrmr_regex *);
int vrmr_zones_network_analyze_rule(const int, struct vrmr_rule *, struct vrmr_rule_cache *, struct vrmr_zones *, struct vrmr_config *);
int vrmr_zones_network_rule_parse_line(const int, const char *, struct vrmr_rule *);
int vrmr_zones_host_ipv6_enabled(const int, struct vrmr_zone *);
int vrmr_zones_network_ipv6_enabled(const int, struct vrmr_zone *);

/*
    services.c
*/
int vrmr_init_services(const int, struct vrmr_ctx *, /*@out@*/ struct vrmr_services *, struct vrmr_regex *);
int vrmr_insert_service(const int, struct vrmr_ctx *, struct vrmr_services *, char *);
void *vrmr_search_service(const int, const struct vrmr_services *, char *);
int vrmr_read_service(const int, struct vrmr_ctx *, char *, struct vrmr_service *);
void vrmr_services_print_list(const struct vrmr_services *);
int vrmr_split_portrange(char *, int *, int *);
int vrmr_process_portrange(const int, const char *, const char *, struct vrmr_service *);
void vrmr_portrange_print_dlist(const struct vrmr_list *);
void vrmr_destroy_serviceslist(const int, struct vrmr_services *);
int vrmr_new_service(const int, struct vrmr_ctx *, struct vrmr_services *, char *, int);
int vrmr_delete_service(const int, struct vrmr_ctx *, struct vrmr_services *, char *, int);
int vrmr_validate_servicename(const int, const char *, regex_t *, char);
int vrmr_services_save_portranges(const int, struct vrmr_ctx *, struct vrmr_service *);
int vrmr_valid_tcpudp_port(const int, int);
int vrmr_services_check(const int, struct vrmr_service *);
int vrmr_services_load(const int, struct vrmr_ctx *, struct vrmr_services *, struct vrmr_regex *);

/*
    info.c
*/
int vrmr_get_ip_info(const int debuglvl, struct vrmr_ctx *, char *name, struct vrmr_zone *answer_ptr, struct vrmr_regex *reg);
int vrmr_create_broadcast_ip(const int debuglvl, char *network, char *netmask, char *broadcast_ip, size_t size);
int vrmr_get_group_info(const int, struct vrmr_ctx *, struct vrmr_zones *, char *, struct vrmr_zone *);
char *vrmr_list_to_portopts(const int, struct vrmr_list *, /*@null@*/char *);
int vrmr_portopts_to_list(const int debuglvl, const char *opt, struct vrmr_list *);
int vrmr_check_active(const int debuglvl, struct vrmr_ctx *, char *data, int type);
int vrmr_get_dynamic_ip(const int debuglvl, char *device, char *answer_ptr, size_t size);
int vrmr_check_ipv4address(const int debuglvl, char *network, char *netmask, char *ipaddress, char quiet);
int vrmr_get_mac_address(const int debuglvl, struct vrmr_ctx *, char *hostname, char *answer_ptr, size_t size, regex_t *mac_rgx);
int vrmr_get_danger_info(const int debuglvl, char *danger, char *source, struct vrmr_danger_info *danger_struct);
char *vrmr_get_network_for_ipv4(const int debuglvl, const char *ipaddress, struct vrmr_list *zonelist);
int vrmr_user_get_info(const int, struct vrmr_user *);

/*
    proc.c
*/
int vrmr_read_proc_entry(const int debuglvl, char *proc_entry, int *value);
int vrmr_set_proc_entry(const int debuglvl, struct vrmr_config *, char *proc_entry, int proc_set, char *who);

/*
    rules.c
*/
int vrmr_rules_analyze_rule(const int, struct vrmr_rule *, struct vrmr_rule_cache *, struct vrmr_services *, struct vrmr_zones *, struct vrmr_interfaces *, struct vrmr_config *);
int vrmr_rules_parse_line(const int, char *, struct vrmr_rule *, struct vrmr_regex *);
int vrmr_rules_init_list(const int, struct vrmr_ctx *, struct vrmr_config *cfg, /*@out@*/ struct vrmr_rules *, struct vrmr_regex *);
int vrmr_rules_cleanup_list(const int, struct vrmr_rules *);
int vrmr_rules_insert_list(const int, struct vrmr_rules *, unsigned int, struct vrmr_rule *);
char *vrmr_rules_assemble_options_string(const int, struct vrmr_rule_options *, const char *);
int vrmr_rules_compare_options(const int, struct vrmr_rule_options *, struct vrmr_rule_options *, char *);
void *vrmr_search_rule(const int, struct vrmr_rules *, struct vrmr_rule *);
int vrmr_rules_read_options(const int, char *, struct vrmr_rule_options *);
struct vrmr_rule *rules_create_protect_rule(const int, char *, /*@null@*/ char *, char *, /*@null@*/char *);
char *vrmr_rules_assemble_rule(const int, struct vrmr_rule *);
int vrmr_rules_save_list(const int, struct vrmr_ctx *, struct vrmr_rules *, struct vrmr_config *);
int vrmr_rules_get_custom_chains(const int, struct vrmr_rules *);
int vrmr_rules_chain_in_list(const int, struct vrmr_list *, char *);
int vrmr_rules_get_system_chains(const int, struct vrmr_rules *, struct vrmr_config *, int);
int vrmr_rules_encode_rule(const int, char *, size_t);
int vrmr_rules_decode_rule(const int, char *, size_t);
int vrmr_rules_determine_ruletype(const int, struct vrmr_rule *);

/* action */
int vrmr_rules_actiontoi(const char *);
char *vrmr_rules_itoaction(const int);
char *vrmr_rules_itoaction_cap(const int);

/*
    blocklist
*/
int vrmr_blocklist_add_one(const int, struct vrmr_zones *, struct vrmr_blocklist *, char, char, char *);
int vrmr_blocklist_rem_one(const int, struct vrmr_zones *, struct vrmr_blocklist *, char *);
int vrmr_blocklist_init_list(const int, struct vrmr_ctx *, struct vrmr_config *cfg, struct vrmr_zones *, struct vrmr_blocklist *, char, char);
int vrmr_blocklist_save_list(const int, struct vrmr_ctx *, struct vrmr_config *cfg, struct vrmr_blocklist *);

/*
    log.c
*/
int vrmr_logprint(char *logfile, char *logstring);
int vrmr_logprint_error(int errorlevel, char *head, char *fmt, ...);
int vrmr_logprint_warning(char *head, char *fmt, ...);
int vrmr_logprint_info(char *head, char *fmt, ...);
int vrmr_logprint_audit(char *fmt, ...);
int vrmr_logprint_debug(char *head, char *fmt, ...);
int vrmr_stdoutprint_debug(char *head, char *fmt, ...);
int vrmr_stdoutprint_info(char *head, char *fmt, ...);
int vrmr_stdoutprint_audit(char *fmt, ...);
int vrmr_stdoutprint_warning(char *head, char *fmt, ...);
int vrmr_stdoutprint_error(int errorlevel, char *head, char *fmt, ...);
int vrmr_logstdoutprint_debug(char *head, char *fmt, ...);
int vrmr_logstdoutprint_info(char *head, char *fmt, ...);
int vrmr_logstdoutprint_audit(char *fmt, ...);
int vrmr_logstdoutprint_warning(char *head, char *fmt, ...);
int vrmr_logstdoutprint_error(int errorlevel, char *head, char *fmt, ...);

int vrmr_log_record_build_line(const int debuglvl, struct vrmr_log_record *log_record, char *outline, size_t size);
int vrmr_log_record_get_names(const int debuglvl, struct vrmr_log_record *log_record,
        struct vrmr_hash_table *zone_hash, struct vrmr_hash_table *service_hash);
void vrmr_log_record_parse_prefix(struct vrmr_log_record *log_record, char *prefix);

/*
    io.c
*/
FILE *vuurmuur_fopen(const int, const struct vrmr_config *, const char *path, const char *mode);
DIR *vuurmuur_opendir(const int, const struct vrmr_config *, const char *);
int vrmr_stat_ok(const int, const struct vrmr_config *, const char *, char, char, char);
int vrmr_check_pidfile(char *pidfile_location, char *service, pid_t *thepid);
int vrmr_create_pidfile(char *pidfile_location, int shm_id);
int vrmr_remove_pidfile(char *pidfile_location);
FILE * vrmr_rules_file_open(const int, const struct vrmr_config *cnf, const char *path, const char *mode, int caller);
int vrmr_rules_file_close(FILE *file, const char *path);
int vrmr_pipe_command(const int, struct vrmr_config *, char *, char);
int libvuurmuur_exec_command(const int, struct vrmr_config *, char *, char **, char **);
void vrmr_shm_update_progress(const int debuglvl, int semid, int *shm_progress, int set_percent);
pid_t get_vuurmuur_pid(char *vuurmuur_pidfile_location, int *shmid);
int vrmr_create_tempfile(const int, char *);
void vrmr_sanitize_path(const int, char *, size_t);

/*
    config.c
*/
int vrmr_config_set_log_names(const int debuglvl, struct vrmr_config *cnf);
int vrmr_config_check_logdir(const int debuglvl, const char *logdir);
int vrmr_config_check_vuurmuurdir(const int debuglvl, const struct vrmr_config *, const char *logdir);
int vrmr_check_iptables_command(const int, struct vrmr_config *, char *, char);
int vrmr_check_iptablesrestore_command(const int, struct vrmr_config *, char *, char);
int vrmr_check_ip6tables_command(const int, struct vrmr_config *, char *, char);
int vrmr_check_ip6tablesrestore_command(const int, struct vrmr_config *, char *, char);
int vrmr_check_tc_command(const int, struct vrmr_config *, char *, char);
int vrmr_init_config(const int, struct vrmr_config *cnf);
int vrmr_reload_config(const int, struct vrmr_config *);
int vrmr_ask_configfile(const int debuglvl, const struct vrmr_config *, char *question, char *answer_ptr, char *file_location, size_t size);
int vrmr_write_configfile(const int debuglvl, char *file_location, struct vrmr_config *cfg);

int vrmr_init(struct vrmr_ctx *, char *toolname);
void vrmr_enable_logprint(struct vrmr_config *cnf);
int vrmr_load(const int debuglvl, struct vrmr_ctx *vctx);
int vrmr_create_log_hash(const int, struct vrmr_ctx *, struct vrmr_hash_table *, struct vrmr_hash_table *);


/*
    backendapi.c
*/
void vrmr_plugin_register(struct vrmr_plugin_data *plugin_data);
int vrmr_backends_load(int debuglvl, struct vrmr_config *cfg, struct vrmr_ctx *vctx);
int vrmr_backends_unload(int debuglvl, struct vrmr_config *cfg, struct vrmr_ctx *ctx);

/*
    interfaces.c
*/
void *vrmr_search_interface(const int, const struct vrmr_interfaces *, const char *);
void *vrmr_search_interface_by_ip(const int, struct vrmr_interfaces *, const char *);
void vrmr_interfaces_print_list(const struct vrmr_interfaces *interfaces);
int vrmr_read_interface_info(const int debuglvl, struct vrmr_ctx *, struct vrmr_interface *iface_ptr);
int vrmr_insert_interface(const int debuglvl, struct vrmr_ctx *, struct vrmr_interfaces *interfaces, char *name);
int vrmr_init_interfaces(const int debuglvl, struct vrmr_ctx *, /*@out@*/ struct vrmr_interfaces *interfaces);
int vrmr_new_interface(const int, struct vrmr_ctx *, struct vrmr_interfaces *, char *);
int vrmr_delete_interface(const int, struct vrmr_ctx *, struct vrmr_interfaces *, char *);
int vrmr_ins_iface_into_zonelist(const int debuglvl, struct vrmr_list *ifacelist, struct vrmr_list *zonelist);
int vrmr_rem_iface_from_zonelist(const int debuglvl, struct vrmr_list *zonelist);
int vrmr_get_iface_stats(const int, const char *, unsigned long *, unsigned long *, unsigned long *, unsigned long *);
int vrmr_get_iface_stats_from_ipt(const int debuglvl, struct vrmr_config *cfg, const char *iface_name, const char *chain, unsigned long long *recv_packets, unsigned long long *recv_bytes, unsigned long long *trans_packets, unsigned long long *trans_bytes);
int vrmr_validate_interfacename(const int, const char *, regex_t *);
void vrmr_destroy_interfaceslist(const int debuglvl, struct vrmr_interfaces *interfaces);
int vrmr_interfaces_get_rules(const int debuglvl, struct vrmr_ctx *, struct vrmr_interface *iface_ptr);
int vrmr_interfaces_save_rules(const int, struct vrmr_ctx *, struct vrmr_interface *);
int vrmr_interfaces_check(const int, struct vrmr_interface *);
int vrmr_interfaces_load(const int, struct vrmr_ctx *, struct vrmr_interfaces *);
int vrmr_interfaces_iface_up(const int, struct vrmr_interface *);
int vrmr_interfaces_analyze_rule(const int, struct vrmr_rule *, struct vrmr_rule_cache *, struct vrmr_interfaces *, struct vrmr_config *);
int vrmr_interfaces_rule_parse_line(const int, const char *, struct vrmr_rule *);
int vrmr_interface_check_devicename(const int, char *);
int vrmr_interface_ipv6_enabled(const int, struct vrmr_interface *);

/*
    icmp.c
*/
int vrmr_get_icmp_name_short(int type, int code, char *name, size_t size, int only_code);
int vrmr_list_icmp_types(int *type, int *has_code, int *number);
int vrmr_list_icmp_codes(int type, int *code, int *number);

/*
    conntrack.c
*/
unsigned int vrmr_conn_hash_name(const void *key);
int vrmr_conn_match_name(const void *ser1, const void *ser2);
void vrmr_conn_list_print(const struct vrmr_list *conn_list);
int vrmr_conn_get_connections(const int, struct vrmr_config *, unsigned int, struct vrmr_hash_table *, struct vrmr_hash_table *, struct vrmr_list *, struct vrmr_list *, struct vrmr_conntrack_request *, struct vrmr_conntrack_stats *);
void vrmr_conn_print_dlist(const struct vrmr_list *);
void vrmr_conn_list_cleanup(const int debuglvl, struct vrmr_list *conn_dlist);
void vrmr_connreq_setup(const int debuglvl, struct vrmr_conntrack_request *connreq);
void vrmr_connreq_cleanup(const int debuglvl, struct vrmr_conntrack_request *connreq);

/*
    linked list
*/
int vrmr_list_setup(int debuglvl, /*@out@*/ struct vrmr_list *, /*@null@*/ void (*remove)(void *data));
int vrmr_list_remove_node(int debuglvl, struct vrmr_list *, struct vrmr_list_node *d_node);
int vrmr_list_remove_top(int debuglvl, struct vrmr_list *);
int vrmr_list_remove_bot(int debuglvl, struct vrmr_list *);
struct vrmr_list_node *vrmr_list_append(int debuglvl, struct vrmr_list *, const void *data);
struct vrmr_list_node *vrmr_list_prepend(int debuglvl, struct vrmr_list *, const void *data);
struct vrmr_list_node *vrmr_list_insert_after(int debuglvl, struct vrmr_list *, struct vrmr_list_node *d_node, const void *data);
struct vrmr_list_node *vrmr_list_insert_before(int debuglvl, struct vrmr_list *, struct vrmr_list_node *d_node, const void *data);
int vrmr_list_node_is_top(int debuglvl, struct vrmr_list_node *d_node);
int vrmr_list_node_is_bot(int debuglvl, struct vrmr_list_node *d_node);
int vrmr_list_cleanup(int debuglvl, struct vrmr_list *);

/*
    iptcap.c
*/
int vrmr_load_iptcaps(const int, struct vrmr_config *, struct vrmr_iptcaps *, char);
int vrmr_check_iptcaps(const int, struct vrmr_config *, /*@out@*/ struct vrmr_iptcaps *, char);
int vrmr_load_ip6tcaps(const int, struct vrmr_config *, struct vrmr_iptcaps *, char);
int vrmr_check_ip6tcaps(const int, struct vrmr_config *, /*@out@*/ struct vrmr_iptcaps *, char);

/*
    filter
*/
void vrmr_filter_setup(const int debuglvl, struct vrmr_filter *filter);
void vrmr_filter_cleanup(const int debuglvl, struct vrmr_filter *filter);

/*
    util.c
*/
char *vrmr_get_string( char *fmt, ... );
char *vrmr_get_len_string(size_t max, char *fmt, ...);

/*
 * shape.c
 */
int vrmr_is_shape_rule(const int, /*@null@*/struct vrmr_rule_options *);
int vrmr_is_shape_incoming_rule(const int, /*@null@*/struct vrmr_rule_options *);
int vrmr_is_shape_outgoing_rule(const int, /*@null@*/struct vrmr_rule_options *);
int vrmr_is_shape_interface(const int, /*@null@*/struct vrmr_interface *);

/* global var */
struct vrmr_list vrmr_plugin_list;

#endif

