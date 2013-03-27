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
#define TRUE            (char)1
#define FALSE           (char)0


/*
    Max length of a host, network or zone. WARNING: if you change this, you also need to change it in the ZONE_REGEX!!!
*/
#define MAX_OPTIONS_LENGTH      256
#define MAX_RULE_LENGTH         512

#define MAX_INTERFACE           32

#define MAX_SERVICE             32

#define MAX_HOST                32
#define MAX_NETWORK             32
#define MAX_ZONE                32

#define MAX_NET_ZONE            MAX_NETWORK+MAX_ZONE
#define MAX_HOST_NET_ZONE       MAX_HOST+MAX_NETWORK+MAX_ZONE

#define MAX_PROC_ENTRY_LENGHT   64

#define PIPE_VERBOSE            (char)0
#define PIPE_QUIET              (char)1


#define STATOK_WANT_BOTH        (char)0
#define STATOK_WANT_FILE        (char)1
#define STATOK_WANT_DIR         (char)2

#define STATOK_VERBOSE          (char)0
#define STATOK_QUIET            (char)1

#define STATOK_ALLOW_NOTFOUND   (char)0
#define STATOK_MUST_EXIST       (char)1

#define IPTCHK_VERBOSE          (char)0
#define IPTCHK_QUIET            (char)1


/*
    default locations of files
*/
#define DEFAULT_SYSCTL_LOCATION         "/sbin/sysctl"
#define DEFAULT_IPTABLES_LOCATION       "/sbin/iptables"
#define DEFAULT_IPTABLES_REST_LOCATION  "/sbin/iptables-restore"
#ifdef IPV6_ENABLED
#define DEFAULT_IP6TABLES_LOCATION      "/sbin/ip6tables"
#define DEFAULT_IP6TABLES_REST_LOCATION "/sbin/ip6tables-restore"
#endif
#define DEFAULT_RULES_LOCATION          "rules.conf"
#define DEFAULT_LOGDIR_LOCATION         "/var/log/vuurmuur"
#define DEFAULT_SYSTEMLOG_LOCATION      "/var/log/messages"
#define DEFAULT_MODPROBE_LOCATION       "/sbin/modprobe"
#define DEFAULT_CONNTRACK_LOCATION      "/usr/sbin/conntrack"
#define DEFAULT_TC_LOCATION             "/sbin/tc"

#define DEFAULT_BACKEND                 "textdir"

#define DEFAULT_DYN_INT_CHECK           FALSE
#define DEFAULT_DYN_INT_INTERVAL        (unsigned int)30

#define DEFAULT_USE_SYN_LIMIT           TRUE
#define DEFAULT_SYN_LIMIT               (unsigned int)10
#define DEFAULT_SYN_LIMIT_BURST         (unsigned int)20

#define DEFAULT_USE_UDP_LIMIT           TRUE
#define DEFAULT_UDP_LIMIT               (unsigned int)15
#define DEFAULT_UDP_LIMIT_BURST         (unsigned int)45

#define DEFAULT_RULE_NFLOG              TRUE
#define DEFAULT_NFGRP                   8

#define DEFAULT_LOG_POLICY              TRUE                /* default we log the default policy */
#define DEFAULT_LOG_POLICY_LIMIT        (unsigned int)30    /* default limit for logging the default policy */
#define DEFAULT_LOG_TCP_OPTIONS         FALSE               /* default we don't log TCP options */
#define DEFAULT_LOG_BLOCKLIST           TRUE                /* default we log blocklist violations */
#define DEFAULT_LOG_INVALID             TRUE                /* default we log INVALID traffic */
#define DEFAULT_LOG_NO_SYN              TRUE                /* default we log new TCP but no SYN */
#define DEFAULT_LOG_PROBES              TRUE                /* default we log probes like XMAS */
#define DEFAULT_LOG_FRAG                TRUE                /* default we log FRAGMENTED traffic */

#define DEFAULT_DROP_INVALID            TRUE                /* default we drop INVALID traffic */

#define DEFAULT_PROTECT_SYNCOOKIE       TRUE                /* default we protect against syn-flooding */
#define DEFAULT_PROTECT_ECHOBROADCAST   TRUE                /* default we protect against echo-broadcasting */

#define DEFAULT_OLD_CREATE_METHOD       FALSE               /* default we use new method */

#define DEFAULT_LOAD_MODULES            TRUE                /* default we load modules */
#define DEFAULT_MODULES_WAITTIME        0                   /* default we don't wait */

#define DEFAULT_MAX_PERMISSION          0700                /* default only allow user rwx */

#define MAX_LOGRULE_SIZE                512
#define MAX_PIPE_COMMAND                512                 /* maximum lenght of the pipe command */
#define MAX_RULECOMMENT_LEN             64                  /* length in characters (for widec) */

#define PROC_IPCONNTRACK                "/proc/net/ip_conntrack"
#define PROC_NFCONNTRACK                "/proc/net/nf_conntrack"

/* Special permission value, meaning don't check permissions. The value
 * is simply all ones. */
#define ANY_PERMISSION                  (~((mode_t)0))
/*
    regexes
*/

/* zone name */
#define ZONE_REGEX              "^([a-zA-Z0-9_-]{1,32})(([.])([a-zA-Z0-9_-]{1,32})(([.])([a-zA-Z0-9_-]{1,32}))?)?$"

#define ZONE_REGEX_ZONEPART     "^([a-zA-Z0-9_-]{1,32})$"
#define ZONE_REGEX_NETWORKPART  "^([a-zA-Z0-9_-]{1,32})$"
#define ZONE_REGEX_HOSTPART     "^([a-zA-Z0-9_-]{1,32})$"

/* service */
#define SERV_REGEX              "^([a-zA-Z0-9_-]{1,32})$"

/* interface name */
#define IFAC_REGEX              "^([a-zA-Z0-9_-]{1,32})$"

/* mac address */
#define MAC_REGEX               "^[a-zA-Z0-9]{2}[:][a-zA-Z0-9]{2}[:][a-zA-Z0-9]{2}[:][a-zA-Z0-9]{2}[:][a-zA-Z0-9]{2}[:][a-zA-Z0-9]{2}$"

/* config line */
#define CONFIG_REGEX            "^[A-Z]+[=]\".*\"$"

/* Some defines for character buffers we define in this file */
#define MAX_IPV6_ADDR_LEN       40 /* 39 + null */

#define VR_IPV4                 4
#define VR_IPV6                 6

/* name validation VERBOSE or QUIET */
enum
{
    VALNAME_VERBOSE=0,
    VALNAME_QUIET
};

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
typedef struct d_list_node_
{
    struct d_list_node_ *next;
    struct d_list_node_ *prev;

    void                *data;

} d_list_node;


/* the list, containing the metadata */
typedef struct d_list_
{
    unsigned int    len;

    d_list_node     *top;
    d_list_node     *bot;

    void(*remove)(void *data);
}
d_list;


/*
    hash function
*/
typedef struct Hash_
{
    /*
        the number of rows in the hash table

        This is fixed on setup of the table.
    */
    unsigned int    rows;

    /*
        the functions for hashing, comparing the data
    */
    unsigned int    (*hash_func)    (const void *data);
    int             (*compare_func) (const void *table_data, const void *search_data);

    /*
        the number of cells in the table
    */
    unsigned int    cells;

    /*
        the table itself. its an array of d_lists
    */
    d_list          *table;

} Hash;


/*
    regular expressions
*/
struct rgx_
{
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
struct portdata
{
    int protocol;   /* 6 for tcp, 17 for udp, 47 for gre, 1 for icmp, etc */

    int src_low;    /* lower end of the portrange */
    int src_high;   /* higher-end, or if no portrange, the normal port */

    int dst_low;
    int dst_high;
};


/* shared memory */
struct SHM_TABLE
{
    int sem_id;

    struct
    {
        char    name[96];
        pid_t   pid;
        int     connected;

        /* username (for logging) */
        char    username[32];

    } configtool;

    int config_changed;
    int backend_changed;

    int reload_result;
    int reload_progress; /* in per cent */
};

/* in this structure we register the print functions. */
struct vrprint_
{
    /* the name of the program that is logging */
    char *logger;

    /* print error. Head may be null. */
    int(*error)(int errorcode, char *head, char *fmt, ...);

    /* print warning */
    int(*warning)(char *head, char *fmt, ...);

    /* print info */
    int(*info)(char *head, char *fmt, ...);

    /* print debug */
    int(*debug)(char *head, char *fmt, ...);

    /* the username used in the auditlog */
    char *username;

    /* auditlog */
    int(*audit)(char *fmt, ...);
};
struct vrprint_ vrprint;

/* configuration */
struct vuurmuur_config
{
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
#ifdef IPV6_ENABLED
    char            ip6tables_location[128];
    char            ip6tablesrestore_location[128];
    /** Fail when there is an error with IPv6 configuration, when set to TRUE */
    char            check_ipv6;
#endif
    char            conntrack_location[128];
    char            tc_location[128];

//    char            use_blocklist;
    char            blocklist_location[64];
    char            log_blocklist;

    char            rules_location[64];

    char            rule_nflog;
    char            nfgrp;

    /* logfile locations */
    char            vuurmuur_logdir_location[64];

    char            debuglog_location[96];
    char            vuurmuurlog_location[96];
    char            auditlog_location[96];
    char            errorlog_location[96];
    char            trafficlog_location[96];

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


    char            check_iptcaps;          /* 0: no, 1: yes */

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

    struct vrprint_ vrprint;
} conf;


/* DATA STRUCTURES */
typedef struct
{
    /* the list with interfaces */
    d_list      list;

    /* is at least one of the interfaces active? */
    char        active_interfaces;

    /* is at least one of the interfaces dynamic? */
    char        dynamic_interfaces;

    u_int16_t   shape_handle;

} Interfaces;


typedef struct
{
    /* the list with services */
    d_list  list;

} Services;


typedef struct
{
    /* the list with zones */
    d_list  list;

} Zones;


typedef struct
{
    /* the list with rules */
    d_list  list;

    char    old_rulesfile_used;

    /* list of chain names that are defined by the rules */
    d_list  custom_chain_list;
    /* list of chains currently in the system */
    d_list  system_chain_filter;
    d_list  system_chain_mangle;
    d_list  system_chain_nat;
    d_list  system_chain_raw;

} Rules;


typedef struct
{
    /* the list with blocked ips/hosts/groups */
    d_list  list;

    char    old_blocklistfile_used;

} BlockList;

struct ipdata
{
    char    ipaddress[16];            //16 should be enough for an ipaddress.
    char    network[16];
    char    netmask[16];
    char    broadcast[16];            //16 should be enough for a netmask
};

#ifdef IPV6_ENABLED
struct ip6data
{
    char ip6[MAX_IPV6_ADDR_LEN];    /* host ip-address */
    char net6[MAX_IPV6_ADDR_LEN];   /* network address string */
    int cidr6;                      /* CIDR: -1 unitialized, 0-128 are valid masks */
};
#endif

/* rule options */
struct options
{
    char            rule_log;       /* 0 = don't log rule, 1 = log this rule */

    char            logprefix[32];  /* 29 is max of iptables, we use 32: 29 iptables, 2 trema's and a '\0'. */
    char            rule_logprefix; /* 0 = don't use logprefix, 1 = use logprefix */

    unsigned int    loglimit;       /* 0 = no limit, > 0 = use limit and the value */
    unsigned int    logburst;       /* burst value */

    char            comment[128];
    char            rule_comment;   /* 0 = rule has no comment, 1 = rule has a comment */

    /* Port forwarding */
    char            remoteport;     /* 0 = don't use remoteport, 1 = use remote port */
    d_list          RemoteportList;

    char            listenport;
    d_list          ListenportList;

    /* redirect */
    int             redirectport;

    /* portfw and redirect: queue instead of accept: 1: queue, 0: accept */
    char            queue;
    /* portfw and redirect: create only a firewall rule for this interface. */
    char            in_int[MAX_INTERFACE];
    /* snat: select an outgoing interface */
    char            out_int[MAX_INTERFACE];
    /* bounce: via interface */
    char            via_int[MAX_INTERFACE];

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
    u_int16_t       nfqueue_num;

    /* shaping */
    u_int32_t       bw_in_max;          /* ceil from dst to src */
    char            bw_in_max_unit[5];  /* kbit, mbit, kbps, mbps */
    u_int32_t       bw_in_min;          /* rate from dst to src */
    char            bw_in_min_unit[5];  /* kbit, mbit, kbps, mbps */
    u_int32_t       bw_out_max;         /* ceil from src to dst */
    char            bw_out_max_unit[5]; /* kbit, mbit, kbps, mbps */
    u_int32_t       bw_out_min;         /* rate from src to dst */
    char            bw_out_min_unit[5]; /* kbit, mbit, kbps, mbps */
    u_int8_t        prio;               /* priority */

    char            random; /* adds --random to the DNAT/SNAT/??? target */
};


struct chaincount
{
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


struct danger_info
{
    int             solution;                 // 1 = iptables, 2 = change proc

    char            proc_entry[MAX_PROC_ENTRY_LENGHT];          // line with the proc dir
    int             proc_set_on;
    int             proc_set_off;

    struct ipdata   source_ip;      //

    char            type[16];
    char            source[16];
};


typedef struct InterfaceCount_
{
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

} InterfaceCount;


typedef struct GeneralData_
{
    int type;
} GenObj;


typedef struct InterfaceData_
{
    /* this should always be on top */
    int             type;

    char            name[MAX_INTERFACE];

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
    struct ipdata   ipv4;
#ifdef IPV6_ENABLED
    struct ip6data   ipv6;
#endif

    /*  is a ipaddress dynamic?
        0: no
        1: yes
    */
    char            dynamic;

    /* protect rules for the interface */
    d_list          ProtectList;

    /* counters for iptables-restore */
    InterfaceCount  *cnt;

    /* reference counters */
    unsigned int    refcnt_network;

    /* traffic shaping */
    char            shape;              /* shape on this interface? 1: yes, 0: no */
    u_int32_t       bw_in;              /* maximal bw in "unit" (download) */
    u_int32_t       bw_out;             /* maximal bw in "unit" (upload) */
    char            bw_in_unit[5];      /* kbit or mbit */
    char            bw_out_unit[5];     /* kbit or mbit */
    u_int32_t       min_bw_in;          /* minimal per rule rate in kbits (download) */
    u_int32_t       min_bw_out;         /* minimal per rule rate in kbits (upload) */

    u_int16_t       shape_handle;       /* tc handle */
    u_int32_t       shape_default_rate; /* rate used by default rule and shaping rules
                                         * w/o an explicit rate */

    u_int32_t       total_shape_rate;
    u_int32_t       total_shape_rules;
    u_int32_t       total_default_shape_rules;

    /* tcpmss clamping */
    char            tcpmss_clamp;

} InterfaceData;


/* this is our structure for the zone data */
typedef struct ZoneData_
{
    int                 type;   /* this should always be on top */

    /* basic vars */
    char                name[MAX_HOST_NET_ZONE];

    char                active; // 0 no, 1 yes
    int                 status;

    /* group stuff */
    unsigned int        group_member_count;
    d_list              GroupList;

    /* for names */
    char                host_name[MAX_HOST];
    char                network_name[MAX_NETWORK];
    char                zone_name[MAX_ZONE];

    /* pointers to parent zone and network (NULL if zone/network) */
    struct ZoneData_    *zone_parent;
    struct ZoneData_    *network_parent;

    struct ipdata       ipv4;
#ifdef IPV6_ENABLED
    struct ip6data      ipv6;
#endif

    /* TODO: 18 is enough: 00:20:1b:10:1D:0F = 17 + '\0' = 18. */
    char                mac[19];
    int                 has_mac;

    /* the list with interfaces: for networks */
    int                 active_interfaces;
    d_list              InterfaceList;

    /* protect rules for the network */
    d_list              ProtectList;

    /* reference counters */
    unsigned int        refcnt_group;
    unsigned int        refcnt_rule;
    unsigned int        refcnt_blocklist;

} ZoneData;


/*
    this is our structure for the services data
*/
typedef struct ServicesData_
{
    int     type;               /* this should always be on top */

    char    name[MAX_SERVICE];

    char    active;                    // 0 no, 1 yes
    int     status;                    // 0 = not touched, -1 = remove, 1 = keep unchanged, 2 = changed, 3 = new

    char    helper[32];

    int     hash_port;

    d_list  PortrangeList;

    char    broadcast;          /* 1: broadcasting service, 0: not */
} ServicesData;


/* here we assemble the data for creating the actual rule */
struct RuleCache_
{
    char                active;

    char                from_firewall;      /* from network is: 0 a network, 1 a firewall */
    char                from_firewall_any;  /* firewall(any) */

    char                to_firewall;        /* to   network is: 0 a network, 1 a firewall */
    char                to_firewall_any;    /* firewall(any) */

    char                from_any;           /* from is 'any' */
    char                to_any;             /* to is 'any' */
    char                service_any;        /* service is 'any' */

    ZoneData            *from;              /* from data */
    ZoneData            *to;                /* to data */

    ZoneData            *who;               /* for protect */
    InterfaceData       *who_int;           /* for protect */

    InterfaceData       *via_int;           /* for bounce rules */

    struct chaincount   iptcount;           /* the counters */

    char                action[122];        /* max: REJECT --reject-with icmp-proto-unreachable (42)
                                                LOG --log-prefix 12345678901234567890123456789 (45)
                                                LOG --log-ip-options --log-tcp-options --log-tcp-sequence --log-level 123 --log-prefix 12345678901234567890123456789 (116)
                                                LOG --log-ip-options --log-tcp-options --log-tcp-sequence --log-level warning --log-prefix 12345678901234567890123456789 (121)
                                                */

    int                 ruletype;           /* type of rule: input, output, forward, masq etc. */
    int                 ruleaction;         /* type of action: append, insert */

    struct danger_info  danger;

    ServicesData        *service;           /* pointer to the service in the services-linked-list */

    struct options      option;

    char                *description;       /* only used for bash_out, and maybe later for vuurmuur-conf */
} RuleCache;


struct RuleData_
{
    int                 type;       /* this should always be on top */

    char                error;

    char                active;     /* is the rule active? */

    int                 action;     /* the action of the rule */

    unsigned int        number;
    int                 status;

    /* normal rules */
    char                service[MAX_SERVICE];
    char                from[MAX_HOST_NET_ZONE];
    char                to[MAX_HOST_NET_ZONE];

    /* protect rules */
    char                who[MAX_HOST_NET_ZONE];
    char                danger[64];
//TODO size right?
    char                source[32];

    struct options      *opt;

    struct RuleCache_   rulecache;

    char                filtered;       /* used by vuurmuur_conf */
} RuleData;


typedef struct VR_filter_
{
    char        str[32];

    /* are we matching the string or only _not_
       the string? */
    char        neg;

    char        reg_active;
    regex_t     reg;

} VR_filter;


#ifndef _NETINET_TCP_H
/* connection status from conntrack */
enum
{
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
    CONN_UNUSED=0,
    CONN_CONNECTING,
    CONN_CONNECTED,
    CONN_DISCONNECTING,
    CONN_IN,
    CONN_OUT,
    CONN_FW,
};


struct ConntrackData
{
    int                     protocol;
    int                     ipv6;

    /*  the service

        sername is a pointer to service->name unless service is NULL
    */
    char                    *sername;
    struct ServicesData_    *service;

    /*  this is for hashing the service. It is also supplied in
        struct ServicesData_, but we need it also for undefined
        services, so we suppy it here. We only hash on protocol and
        dst_port, because the src_port is almost always different.
    */
    int                     dst_port;

    /* src port is not needed for anything, we only use it for detailed info
       in the connection section from Vuurmuur_conf */
    int                     src_port;

    /* from/source */
    char                    *fromname;
    struct ZoneData_        *from;
    char                    src_ip[46];

    /* to/destination */
    char                    *toname;
    struct ZoneData_        *to;
    char                    dst_ip[46];
    char                    orig_dst_ip[46]; /* ip before nat correction */

    /* counter */
    int                     cnt;

    d_list_node             *d_node;

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


struct ConntrackStats_
{
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

    int sername_max;
    int fromname_max;
    int toname_max;

    /** if any of the flows/connections has accounting info, this
     *  is set to 1. */
    int accounting;
};


typedef struct
{
    VR_filter   filter;
    char        use_filter;

    char        group_conns;
    char        unknown_ip_as_net;

    /* sorting, relevant for grouping */
    char        sort_in_out_fwd;
    char        sort_conn_status;

    char        draw_acc_data;
    char        draw_details;
} VR_ConntrackRequest;



/*
    Iptables Capabilities
*/
typedef struct
{
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

#ifdef IPV6_ENABLED
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
#endif
} IptCap;

typedef struct VuurmuurCtx_ {
    Zones *zones;
    Interfaces *interfaces;
    BlockList *blocklist;
    Rules *rules;
    Services *services;
    struct vuurmuur_config *conf;
    IptCap *iptcaps;
} VuurmuurCtx;

enum objectstatus
{
    ST_REMOVED = -1,
    ST_UNTOUCHED,
    ST_KEEP,
    ST_CHANGED,
    ST_ADDED,
    ST_ACTIVATED,
    ST_DEACTIVATED
};


/* a value like: 'dnsserver.dmz.internet' can be a: */
enum targettypes
{
    TYPE_ERROR = -1,
    TYPE_UNSET = 0,

    TYPE_FIREWALL,
    TYPE_HOST,
    TYPE_GROUP,
    TYPE_NETWORK,
    TYPE_ZONE,
    TYPE_SERVICE,
    TYPE_SERVICEGRP, /* not implemented */
    TYPE_INTERFACE,
    TYPE_RULE,

    TYPE_TOO_BIG
};


/* protect rule types */
enum protecttypes
{
    PROT_NO_PROT = 0,
    PROT_IPTABLES,
    PROT_PROC_SYS,
    PROT_PROC_INT
};


/* normal rule types */
enum ruletype
{
    RT_ERROR = -1,
    RT_NOTSET = 0,
    RT_INPUT,
    RT_OUTPUT,
    RT_FORWARD,
    RT_MASQ,
    RT_PORTFW,
    RT_SNAT,
    RT_REDIRECT,
    RT_DNAT,
    RT_BOUNCE,
};


/* general datatypes */
enum questiontypes
{
    CAT_ZONES,
    CAT_SERVICES,
    CAT_INTERFACES,
    CAT_RULES
};


/*  RR is Reload Result
 
    it is used for the IPC with SHM between Vuurmuur,
    Vuurmuur_log and Vuurmuur_conf 
*/
enum
{
    VR_RR_ERROR = -1,
    VR_RR_NO_RESULT_YET = 0,
    VR_RR_READY,
    VR_RR_SUCCES,
    VR_RR_NOCHANGES,
    VR_RR_RESULT_ACK,
};


/* posible results for initializing the config */
enum
{
    VR_CNF_E_UNKNOWN_ERR = -6,

    /* function was called wrong */
    VR_CNF_E_PARAMETER = -5,

    /* serious permission problem with configfile */
    VR_CNF_E_FILE_PERMISSION = -4,

    /* configfile missing */
    VR_CNF_E_FILE_MISSING = -3,

    /* eg an negative unsigned int, or an wrong iptables command */
    VR_CNF_E_ILLEGAL_VAR = -2,

    /* missing variable in config file, fatal */
    VR_CNF_E_MISSING_VAR = -1,

    /* all went well! */
    VR_CNF_OK = 0,

    /* missing variable in config file, non fatal */
    VR_CNF_W_MISSING_VAR,

    /* eg an negative unsigned int */
    VR_CNF_W_ILLEGAL_VAR,

};


/*  Valid actions are: "Accept", "Drop", "Reject", "Log",
    "Portfw", "Redirect", "Snat", "Masq", "Queue", "Chain"
*/
enum actiontypes
{
    AT_ERROR = -1,
    AT_ACCEPT,      /* ACCEPT */
    AT_DROP,        /* DROP */
    AT_REJECT,      /* REJECT */
    AT_LOG,         /* LOG */
    AT_PORTFW,      /* DNAT+ACCEPT( or QUEUE) */
    AT_REDIRECT,    /* REDIRECT+ACCEPT( or QUEUE) */
    AT_SNAT,        /* SNAT */
    AT_MASQ,        /* MASQUERADE */
    AT_QUEUE,       /* QUEUE */
    AT_CHAIN,       /* custom chain */
    AT_DNAT,        /* DNAT */
    AT_BOUNCE,      /* DNAT+SNAT */
    AT_NFQUEUE,     /* NFQUEUE */

    /* special for networks and interfaces */
    AT_PROTECT,

    /* special, not really an action */
    AT_SEPARATOR,

    /* this is of course not an action */
    AT_TOO_BIG,
};


struct vrmr_user {
    uid_t   user;
    char    username[32];

    gid_t   group;
    char    groupname[32];

    uid_t   realuser;
    char    realusername[32];
};


/*
    libvuurmuur.c
*/
/*@null@*/
void *rule_malloc(void);
/*@null@*/
void *zone_malloc(int debuglvl);
void zone_free(int debuglvl, struct ZoneData_ *zone_ptr);
/*@null@*/
void *service_malloc(void);
/*@null@*/
void *interface_malloc(const int debuglvl);
/*@null@*/
void *ruleoption_malloc(int debuglvl);
int LockSHM(int, int);
char *libvuurmuur_get_version(void);
int range_strcpy(char *dest, const char *src, const size_t start, const size_t end, size_t size);
size_t strlcat(char *dst, const char *src, size_t size);
size_t strlcpy(char *dst, const char *src, size_t size);
int setup_rgx(int action, struct rgx_ *reg);


/*
    hash table
*/
int hash_setup(const int debuglvl, Hash *hash_table, unsigned int rows, unsigned int (*hash_func)(const void *data), int (*compare_func)(const void *table_data, const void *search_data));
int hash_cleanup(const int debuglvl, Hash *hash_table);
int hash_insert(const int debuglvl, Hash *hash_table, const void *data);
int hash_remove(const int debuglvl, Hash *hash_table, void *data);
void *hash_search(const int debuglvl, const Hash *hash_table, void *data);

int compare_ports(const void *string1, const void *string2);
int compare_ipaddress(const void *string1, const void *string2);
int compare_string(const void *string1, const void *string2);
unsigned int hash_port(const void *key);
unsigned int hash_ipaddress(const void *key);
unsigned int hash_string(const void *key);

void print_table_service(const int debuglvl, const Hash *hash_table);
int init_zonedata_hashtable(const int debuglvl, unsigned int n_rows, d_list *d_list, unsigned int (*hash)(const void *key), int (*match)(const void *string1, const void *string2), Hash *hash_table);
int init_services_hashtable(const int debuglvl, unsigned int n_rows, d_list *d_list, unsigned int (*hash)(const void *key), int (*match)(const void *string1, const void *string2), Hash *hash_table);
void *search_service_in_hash(const int debuglvl, const int src, const int dst, const int protocol, const Hash *serhash);
void *search_zone_in_hash_with_ipv4(const int debuglvl, const char *ipaddress, const Hash *zonehash);


/*
    query.c
*/
int rules_remove_rule_from_list(const int, Rules *, unsigned int, int);
void rules_update_numbers(const int, Rules *, unsigned int place, int);
void rules_print_list(const Rules *);
void rules_free_options(const int debuglvl, struct options *opt);


/*
    zones.c
*/
//int zones_split_zonename(const int, Zones *, struct ZoneData_ *, regex_t *);
int insert_zonedata_list(const int, Zones *, const struct ZoneData_ *);
void zonedata_print_list(const Zones *);
int init_zonedata(const int, /*@out@*/ Zones *, Interfaces *, struct rgx_ *);
int insert_zonedata(const int, Zones *, Interfaces *, char *, int, struct rgx_ *);
int read_zonedata(const int, Zones *, Interfaces *, char *, int, struct ZoneData_ *, struct rgx_ *);
void *search_zonedata(const int, const Zones *, char *);
void destroy_zonedatalist(const int, Zones *);
int count_zones(const int, Zones *, int, char *, char *);
int new_zone(const int, Zones *, char *, int);
int delete_zone(const int, Zones *, char *, int);
int zonelist_to_networklist(const int, Zones *, d_list *);
int add_broadcasts_zonelist(const int, Zones *);
int validate_zonename(const int, const char *, int, char *, char *, char *, regex_t *, char);
int zones_group_save_members(const int, struct ZoneData_ *);
int zones_network_add_iface(const int, Interfaces *, struct ZoneData_ *, char *);
int zones_network_rem_iface(const int, struct ZoneData_ *, char *);
int zones_network_get_interfaces(const int, struct ZoneData_ *, Interfaces *);
int zones_network_save_interfaces(const int, struct ZoneData_ *);
int zones_network_get_protectrules(const int, struct ZoneData_ *);
int zones_group_rem_member(const int, struct ZoneData_ *, char *);
int zones_group_add_member(const int, Zones *, struct ZoneData_ *, char *);
int zones_active(const int, struct ZoneData_ *);
int zones_check_host(const int, struct ZoneData_ *);
int zones_check_group(const int, struct ZoneData_ *);
int zones_check_network(const int, struct ZoneData_ *);
int load_zones(const int, Zones *, Interfaces *, struct rgx_ *);
int zones_network_analyze_rule(const int, struct RuleData_ *, struct RuleCache_ *, Zones *, struct vuurmuur_config *);
int zones_network_rule_parse_line(const int, const char *, struct RuleData_ *);
int zones_host_ipv6_enabled(const int, struct ZoneData_ *);
int zones_network_ipv6_enabled(const int, struct ZoneData_ *);

/*
    services.c
*/
int init_services(const int, /*@out@*/ Services *, struct rgx_ *);
int insert_service(const int, Services *, char *);
void *search_service(const int, const Services *, char *);
int read_service(const int, char *, struct ServicesData_ *);
void services_print_list(const Services *);
int split_portrange(char *, int *, int *);
int process_portrange(const int, const char *, const char *, struct ServicesData_ *);
void portrange_print_dlist(const d_list *);
void destroy_serviceslist(const int, Services *);
int new_service(const int, Services *, char *, int);
int delete_service(const int, Services *, char *, int);
int validate_servicename(const int, const char *, regex_t *, char);
int services_save_portranges(const int, struct ServicesData_ *);
int valid_tcpudp_port(const int, int);
int services_check(const int, struct ServicesData_ *);
int load_services(const int, Services *, struct rgx_ *);


/*
    info.c
*/
int get_ip_info(const int debuglvl, char *name, struct ZoneData_ *answer_ptr, struct rgx_ *reg);
int create_broadcast_ip(const int debuglvl, char *network, char *netmask, char *broadcast_ip, size_t size);
int get_group_info(const int, Zones *, char *, struct ZoneData_ *);
char *list_to_portopts(const int, d_list *, /*@null@*/char *);
int portopts_to_list(const int debuglvl, const char *opt, d_list *dlist);
int check_active(const int debuglvl, char *data, int type);
int get_dynamic_ip(const int debuglvl, char *device, char *answer_ptr, size_t size);
int check_ipv4address(const int debuglvl, char *network, char *netmask, char *ipaddress, char quiet);
int get_mac_address(const int debuglvl, char *hostname, char *answer_ptr, size_t size, regex_t *mac_rgx);
int get_danger_info(const int debuglvl, char *danger, char *source, struct danger_info *danger_struct);
char *get_network_for_ipv4(const int debuglvl, const char *ipaddress, d_list *zonelist);
int vrmr_user_get_info(const int, struct vrmr_user *);


/*
    proc.c
*/
int read_proc_entry(const int debuglvl, char *proc_entry, int *value);
int set_proc_entry(const int debuglvl, struct vuurmuur_config *, char *proc_entry, int proc_set, char *who);


/*
    rules.c
*/
int rules_analyze_rule(const int, struct RuleData_ *, struct RuleCache_ *, Services *, Zones *, Interfaces *, struct vuurmuur_config *);
int rules_parse_line(const int, char *, struct RuleData_ *, struct rgx_ *);
int rules_init_list(const int, /*@out@*/ Rules *, struct rgx_ *);
int rules_cleanup_list(const int, Rules *);
int rules_insert_list(const int, Rules *, unsigned int, struct RuleData_ *);
char *rules_assemble_options_string(const int, struct options *, const char *);
int rules_compare_options(const int, struct options *, struct options *, char *);
void *search_rule(const int, Rules *, struct RuleData_ *);
int rules_read_options(const int, char *, struct options *);
struct RuleData_ *rules_create_protect_rule(const int, char *, /*@null@*/ char *, char *, /*@null@*/char *);
char *rules_assemble_rule(const int, struct RuleData_ *);
int rules_save_list(const int, Rules *, struct vuurmuur_config *);
int rules_get_custom_chains(const int, Rules *);
int rules_chain_in_list(const int, d_list *, char *);
int rules_get_system_chains(const int, Rules *, struct vuurmuur_config *, int);
int rules_encode_rule(const int, char *, size_t);
int rules_decode_rule(const int, char *, size_t);
int rules_determine_ruletype(const int, struct RuleData_ *);


/* action */
int rules_actiontoi(const char *);
char *rules_itoaction(const int);
char *rules_itoaction_cap(const int);


/*
    blocklist
*/
int blocklist_add_one(const int, Zones *, BlockList *, char, char, char *);
int blocklist_rem_one(const int, Zones *, BlockList *, char *);
int blocklist_init_list(const int, Zones *, BlockList *, char, char);
int blocklist_save_list(const int, BlockList *);


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

/*
    io.c
*/
FILE *vuurmuur_fopen(const int, const struct vuurmuur_config *, const char *path, const char *mode);
DIR *vuurmuur_opendir(const int, const struct vuurmuur_config *, const char *);
int stat_ok(const int, const struct vuurmuur_config *, const char *, char, char, char);
int check_pidfile(char *pidfile_location, char *service, pid_t *thepid);
int create_pidfile(char *pidfile_location, int shm_id);
int remove_pidfile(char *pidfile_location);
FILE * rules_file_open(const int, const struct vuurmuur_config *cnf, const char *path, const char *mode, int caller);
int rules_file_close(FILE *file, const char *path);
int pipe_command(const int, struct vuurmuur_config *, char *, char);
int libvuurmuur_exec_command(const int, struct vuurmuur_config *, char *, char **, char **);
void shm_update_progress(const int debuglvl, int semid, int *shm_progress, int set_percent);
pid_t get_vuurmuur_pid(char *vuurmuur_pidfile_location, int *shmid);
int create_tempfile(const int, char *);
void sanitize_path(const int, char *, size_t);

/*
    config.c
*/
int config_set_log_names(const int debuglvl, struct vuurmuur_config *cnf);
int config_check_logdir(const int debuglvl, const char *logdir);
int config_check_vuurmuurdir(const int debuglvl, const struct vuurmuur_config *, const char *logdir);
int check_iptables_command(const int, struct vuurmuur_config *, char *, char);
int check_iptablesrestore_command(const int, struct vuurmuur_config *, char *, char);
#ifdef IPV6_ENABLED
int check_ip6tables_command(const int, struct vuurmuur_config *, char *, char);
int check_ip6tablesrestore_command(const int, struct vuurmuur_config *, char *, char);
#endif
int check_tc_command(const int, struct vuurmuur_config *, char *, char);
int init_config(const int, struct vuurmuur_config *cnf);
int reload_config(const int, struct vuurmuur_config *);
int ask_configfile(const int debuglvl, const struct vuurmuur_config *, char *question, char *answer_ptr, char *file_location, size_t size);
int vrmr_write_configfile(const int debuglvl, char *file_location, struct vuurmuur_config *cfg);

int vrmr_init(struct vuurmuur_config *, char *toolname);


/*
    backendapi.c
*/
int vrmr_backends_load(int debuglvl, struct vuurmuur_config *cfg);
int vrmr_backends_unload(int debuglvl, struct vuurmuur_config *cfg);


/*
    interfaces.c
*/
void *search_interface(const int, const Interfaces *, const char *);
void *search_interface_by_ip(const int, Interfaces *, const char *);
void interfaces_print_list(const Interfaces *interfaces);
int read_interface_info(const int debuglvl, struct InterfaceData_ *iface_ptr);
int insert_interface(const int debuglvl, Interfaces *interfaces, char *name);
int init_interfaces(const int debuglvl, /*@out@*/ Interfaces *interfaces);
int new_interface(const int, Interfaces *, char *);
int delete_interface(const int, Interfaces *, char *);
int ins_iface_into_zonelist(const int debuglvl, d_list *ifacelist, d_list *zonelist);
int rem_iface_from_zonelist(const int debuglvl, d_list *zonelist);
int get_iface_stats(const int, const char *, unsigned long *, unsigned long *, unsigned long *, unsigned long *);
int vrmr_get_iface_stats_from_ipt(const int debuglvl, struct vuurmuur_config *cfg, const char *iface_name, const char *chain, unsigned long long *recv_packets, unsigned long long *recv_bytes, unsigned long long *trans_packets, unsigned long long *trans_bytes);
int validate_interfacename(const int, const char *, regex_t *);
void destroy_interfaceslist(const int debuglvl, Interfaces *interfaces);
int interfaces_get_rules(const int debuglvl, struct InterfaceData_ *iface_ptr);
int interfaces_save_rules(const int, struct InterfaceData_ *);
int interfaces_check(const int, struct InterfaceData_ *);
int load_interfaces(const int, Interfaces *);
int interfaces_iface_up(const int, struct InterfaceData_ *);
int interfaces_analyze_rule(const int, struct RuleData_ *, struct RuleCache_ *, Interfaces *, struct vuurmuur_config *);
int interfaces_rule_parse_line(const int, const char *, struct RuleData_ *);
int interface_check_devicename(const int, char *);
#ifdef IPV6_ENABLED
int interface_ipv6_enabled(const int, struct InterfaceData_ *);
#endif

/*
    icmp.c
*/
int get_icmp_name_short(int type, int code, char *name, size_t size, int only_code);
int list_icmp_types(int *type, int *has_code, int *number);
int list_icmp_codes(int type, int *code, int *number);


/*
    conntrack.c
*/
//int conn_line_to_data(const int debuglvl, struct ConntrackLine *connline_ptr, struct ConntrackData *conndata_ptr, Hash *serhash, Hash *zonehash, d_list *zonelist, int unknown_host_as_network, int sort_by_connect_status, int sort_by_in_out_fw);
//int conn_process_one_conntrack_line(const int debuglvl, const char *line, struct ConntrackLine *connline_ptr);
unsigned int conn_hash_name(const void *key);
int conn_match_name(const void *ser1, const void *ser2);
void conn_list_print(const d_list *conn_list);
int conn_get_connections(const int, struct vuurmuur_config *, unsigned int, Hash *, Hash *, d_list *, d_list *, VR_ConntrackRequest *, struct ConntrackStats_ *);
void conn_print_dlist(const d_list *dlist);
void conn_list_cleanup(const int debuglvl, d_list *conn_dlist);
void VR_connreq_setup(const int debuglvl, VR_ConntrackRequest *connreq);
void VR_connreq_cleanup(const int debuglvl, VR_ConntrackRequest *connreq);

/*
    linked list
*/
int d_list_setup(int debuglvl, /*@out@*/ d_list *d_list, /*@null@*/ void (*remove)(void *data));
int d_list_remove_node(int debuglvl, d_list *d_list, d_list_node *d_node);
int d_list_remove_top(int debuglvl, d_list *d_list);
int d_list_remove_bot(int debuglvl, d_list *d_list);
d_list_node *d_list_append(int debuglvl, d_list *d_list, const void *data);
d_list_node *d_list_prepend(int debuglvl, d_list *d_list, const void *data);
d_list_node *d_list_insert_after(int debuglvl, d_list *d_list, d_list_node *d_node, const void *data);
d_list_node *d_list_insert_before(int debuglvl, d_list *d_list, d_list_node *d_node, const void *data);
int d_list_node_is_top(int debuglvl, d_list_node *d_node);
int d_list_node_is_bot(int debuglvl, d_list_node *d_node);
int d_list_cleanup(int debuglvl, d_list *d_list);


/*
    iptcap.c
*/
int load_iptcaps(const int, struct vuurmuur_config *, IptCap *, char);
int check_iptcaps(const int, struct vuurmuur_config *, /*@out@*/ IptCap *, char);
#ifdef IPV6_ENABLED
int load_ip6tcaps(const int, struct vuurmuur_config *, IptCap *, char);
int check_ip6tcaps(const int, struct vuurmuur_config *, /*@out@*/ IptCap *, char);
#endif


/*
    filter
*/
void VR_filter_setup(const int debuglvl, VR_filter *filter);
void VR_filter_cleanup(const int debuglvl, VR_filter *filter);

/*
    util.c
*/
char * VrGetString( char *fmt, ... );
char * VrGetLenString(size_t max, char *fmt, ...);

/*
 * shape.c
 */
int libvuurmuur_is_shape_rule(const int, /*@null@*/struct options *);
int libvuurmuur_is_shape_incoming_rule(const int, /*@null@*/struct options *);
int libvuurmuur_is_shape_outgoing_rule(const int, /*@null@*/struct options *);
int libvuurmuur_is_shape_interface(const int, /*@null@*/InterfaceData *);


/*
    global vars
*/
char bash_description[512];

/* the backend structure pointers */
/*@null@*/
void *serv_backend;
/*@null@*/
void *zone_backend;
/*@null@*/
void *ifac_backend;
/*@null@*/
void *rule_backend;

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
    int (*setup)(int debuglvl, const struct vuurmuur_config *cnf, void **backend);

    /* version */
    char *version;
    char *name;
};

struct vrmr_plugin {
    char                        name[32];
    int                         ref_cnt;

    struct vrmr_plugin_data     *f;

    void                        *handle;

    /* version */
    char                        *version;
};

d_list vrmr_plugin_list;
void vrmr_plugin_register(struct vrmr_plugin_data *plugin_data);

/* services */
struct vrmr_plugin_data    *sf;

/* zones */
struct vrmr_plugin_data    *zf;

/* interfaces (not 'if' because is a c-keyword.) */
struct vrmr_plugin_data    *af;

/* rules */
struct vrmr_plugin_data    *rf;

#endif
