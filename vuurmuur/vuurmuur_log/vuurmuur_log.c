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

#include "vuurmuur_log.h"
#include "nflog.h"
#include "stats.h"
#include "logfile.h"
#include "vuurmuur_ipc.h"

#ifdef HAVE_NFNETLINK
#include <libnfnetlink/libnfnetlink.h>
#ifdef HAVE_LIBNETFILTER_LOG
#include <libnetfilter_log/libnetfilter_log.h>
#endif /* HAVE_LIBNETFILTER_LOG */
#endif /* HAVE_NFNETLINK */

/*@null@*/
struct SHM_TABLE *shm_table = 0;
static int g_debuglvl = 0;
static Hash zone_htbl;
static Hash service_htbl;
static struct Counters_ Counters =
{
    0, 0, 0, 0, 0,
    0, 0, 0, 0,

    0, 0, 0, 0,
};
static FILE *g_traffic_log = NULL;

/*
    we put this here, because we only use it here in main.
*/
static int sigint_count = 0;
static int sighup_count = 0;
static int sigterm_count = 0;


void
handle_sigint(int sig)
{
    sigint_count = 1;
}


void
handle_sigterm(int sig)
{
    sigterm_count = 1;
}


void
handle_sighup(int sig)
{
    sighup_count = 1;
}


static void
setup_signal_handler(int sig, void (*handler)())
{
    struct sigaction action;

    action.sa_handler = handler;
    sigemptyset(&(action.sa_mask));
    sigaddset(&(action.sa_mask),sig);
    action.sa_flags = 0;
    sigaction(sig, &action, 0);
}

static char *
assemble_logline_sscanf_string(const int debuglvl, struct log_rule *logrule_ptr)
{
    char    *string,
            temp_buf[256] = "";
    size_t  str_len = 0;

    //"%s %2d %2d:%2d:%2d %s";
    snprintf(temp_buf, sizeof(temp_buf), "%%%ds %%2d %%2d:%%2d:%%2d %%%ds",
            (int)sizeof(logrule_ptr->month)-1,
            (int)sizeof(logrule_ptr->hostname)-1);

    if(debuglvl >= HIGH)
        (void)vrprint.debug(__FUNC__, "assemble_logline_sscanf_string: string: '%s'. (len: %d)", temp_buf, strlen(temp_buf));

    str_len = strlen(temp_buf) + 1;
    if(str_len > sizeof(temp_buf))
    {
        (void)vrprint.error(-1, "Internal Error", "string overflow (in: %s:%d).", __FUNC__, __LINE__);
        return(NULL);
    }

    if(!(string = malloc(str_len)))
    {
        (void)vrprint.error(-1, "Error", "malloc failed: %s.", strerror(errno));
        return(NULL);
    }

    if(strlcpy(string, temp_buf, str_len) > str_len)
    {
        (void)vrprint.error(-1, "Internal Error", "buffer overflow (in: %s:%d).", __FUNC__, __LINE__);
        return(NULL);
    }

    return(string);
}

/* Input is packet and an seven-byte (including NULL) character array.  Results
 * are put into the character array.
 *
 * Shamelessly ripped from snort_inline 2.2.0 (c) Martin Roesch
 */
static void
CreateTCPFlagString(struct log_rule *logrule_ptr, char *flagBuffer)
{
    /* parse TCP flags */
    *flagBuffer++ = (char) (logrule_ptr->urg ? 'U' : '*');
    *flagBuffer++ = (char) (logrule_ptr->ack ? 'A' : '*');
    *flagBuffer++ = (char) (logrule_ptr->psh ? 'P' : '*');
    *flagBuffer++ = (char) (logrule_ptr->rst ? 'R' : '*');
    *flagBuffer++ = (char) (logrule_ptr->syn ? 'S' : '*');
    *flagBuffer++ = (char) (logrule_ptr->fin ? 'F' : '*');
    *flagBuffer = '\0';
}

/*
    get the vuurmuurnames with the ips and ports

    Returncodes:
         1: ok
         0: logline not ok
        -1: internal error

    NOTE: if the function returns -1 the memory is not cleaned up: the program is supposed to exit
*/
static int
get_vuurmuur_names(const int debuglvl, struct log_rule *logrule_ptr, Hash *ZoneHash, Hash *ServiceHash)
{
    struct ZoneData_        *search_ptr = NULL;
    struct ServicesData_    *ser_search_ptr = NULL;

    if(debuglvl >= HIGH)
        (void)vrprint.debug(__FUNC__, "start");


    /* safety */
    if(!logrule_ptr || !ZoneHash || !ServiceHash)
    {
        (void)vrprint.error(-1, "Internal Error", "parameter problem (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

#ifdef IPV6_ENABLED
    /* no support in looking up hosts, services, etc yet */
    if (logrule_ptr->ipv6 == 1) {
        if(strlcpy(logrule_ptr->from_name, logrule_ptr->src_ip, sizeof(logrule_ptr->from_name)) >= sizeof(logrule_ptr->from_name))
            (void)vrprint.error(-1, "Error", "buffer overflow attempt (in: %s:%d).", __FUNC__, __LINE__);
        if(strlcpy(logrule_ptr->to_name, logrule_ptr->dst_ip, sizeof(logrule_ptr->to_name)) >= sizeof(logrule_ptr->to_name))
            (void)vrprint.error(-1, "Error", "buffer overflow attempt (in: %s:%d).", __FUNC__, __LINE__);
    } else {
#endif /* IPV6_ENABLED */

    /* search in the hash with the ipaddress */
    if(!(search_ptr = search_zone_in_hash_with_ipv4(debuglvl, logrule_ptr->src_ip, ZoneHash)))
    {
        /* not found in hash */
        if(strlcpy(logrule_ptr->from_name, logrule_ptr->src_ip, sizeof(logrule_ptr->from_name)) >= sizeof(logrule_ptr->from_name))
            (void)vrprint.error(-1, "Error", "buffer overflow attempt (in: %s:%d).", __FUNC__, __LINE__);
    }
    else
    {
        /* found in the hash */
        if(strlcpy(logrule_ptr->from_name, search_ptr->name, sizeof(logrule_ptr->from_name)) >= sizeof(logrule_ptr->from_name))
            (void)vrprint.error(-1, "Error", "buffer overflow attempt (in: %s:%d).", __FUNC__, __LINE__);

        if(search_ptr->type == TYPE_NETWORK)
            strlcpy(logrule_ptr->from_name, "firewall", sizeof(logrule_ptr->from_name));
    }
    search_ptr = NULL;


    /*  do it all again for TO */
    if(!(search_ptr = search_zone_in_hash_with_ipv4(debuglvl, logrule_ptr->dst_ip, ZoneHash)))
    {
        /* not found in hash */
        if(strlcpy(logrule_ptr->to_name, logrule_ptr->dst_ip, sizeof(logrule_ptr->to_name)) >= sizeof(logrule_ptr->to_name))
            (void)vrprint.error(-1, "Error", "buffer overflow attempt (in: %s:%d).", __FUNC__, __LINE__);
    }
    else
    {
        /* found in the hash */
        if(strlcpy(logrule_ptr->to_name, search_ptr->name, sizeof(logrule_ptr->to_name)) >= sizeof(logrule_ptr->to_name))
            (void)vrprint.error(-1, "Error", "buffer overflow attempt (in: %s:%d).", __FUNC__, __LINE__);

        if(search_ptr->type == TYPE_NETWORK)
            strlcpy(logrule_ptr->to_name, "firewall", sizeof(logrule_ptr->to_name));
    }
    search_ptr = NULL;
#ifdef IPV6_ENABLED
    }
#endif /* IPV6_ENABLED */


    /*
        THE SERVICE
    */

    /*  icmp is treated different because of the type and code
        and we can call get_icmp_name_short.
    */
    if(logrule_ptr->protocol == 1 || logrule_ptr->protocol == 58)
    {
        if(!(ser_search_ptr = search_service_in_hash(debuglvl, logrule_ptr->icmp_type, logrule_ptr->icmp_code, logrule_ptr->protocol, ServiceHash)))
        {
            /* not found in hash */
            snprintf(logrule_ptr->ser_name, sizeof(logrule_ptr->ser_name), "%d.%d(icmp)", logrule_ptr->icmp_type, logrule_ptr->icmp_code);

            /* try to get the icmp-names */
            if(get_icmp_name_short(logrule_ptr->icmp_type, logrule_ptr->icmp_code, logrule_ptr->ser_name, sizeof(logrule_ptr->ser_name), 0) < 0)
            {
                (void)vrprint.error(-1, "Internal Error", "get_icmp_name_short failed (in: %s:%d).", __FUNC__, __LINE__);
                return(-1);
            }
        }
        else
        {
            /* found in the hash, now copy the name */
            if(strlcpy(logrule_ptr->ser_name, ser_search_ptr->name, sizeof(logrule_ptr->ser_name)) >= sizeof(logrule_ptr->ser_name))
                (void)vrprint.error(-1, "Error", "buffer overflow attempt (in: %s:%d).", __FUNC__, __LINE__);
        }
    }

    /*  here we handle the rest
    */
    else
    {
        /* first a normal search */
        if(!(ser_search_ptr = search_service_in_hash(debuglvl, logrule_ptr->src_port, logrule_ptr->dst_port, logrule_ptr->protocol, ServiceHash)))
        {
            /* only do the reverse check for tcp and udp */
            if(logrule_ptr->protocol == 6 || logrule_ptr->protocol == 17)
            {
                /* not found, do a reverse search */
                if(!(ser_search_ptr = search_service_in_hash(debuglvl, logrule_ptr->dst_port, logrule_ptr->src_port, logrule_ptr->protocol, ServiceHash)))
                {
                    /* not found in the hash */
                    if(logrule_ptr->protocol == 6) /* tcp */
                    {
                        snprintf(logrule_ptr->ser_name, sizeof(logrule_ptr->ser_name), "%d->%d(tcp)", logrule_ptr->src_port, logrule_ptr->dst_port);
                    }
                    else if(logrule_ptr->protocol == 17) /* udp */
                    {
                        snprintf(logrule_ptr->ser_name, sizeof(logrule_ptr->ser_name), "%d->%d(udp)", logrule_ptr->src_port, logrule_ptr->dst_port);
                    }
                }
                else
                {
                    /* found in the hash! (reverse) */
                    if(strlcpy(logrule_ptr->ser_name, ser_search_ptr->name, sizeof(logrule_ptr->ser_name)) >= sizeof(logrule_ptr->ser_name))
                        (void)vrprint.error(-1, "Error", "buffer overflow attempt (in: %s:%d).", __FUNC__, __LINE__);
                }
            }
            else
            {
                if(logrule_ptr->dst_port == 0 && logrule_ptr->src_port == 0)
                    snprintf(logrule_ptr->ser_name, sizeof(logrule_ptr->ser_name), "proto-%d", logrule_ptr->protocol);
                else
                    snprintf(logrule_ptr->ser_name, sizeof(logrule_ptr->ser_name), "%d*%d(%d)", logrule_ptr->src_port, logrule_ptr->dst_port, logrule_ptr->protocol);

            }
        }
        else
        {
            /* found in the hash! */
            if(strlcpy(logrule_ptr->ser_name, ser_search_ptr->name, sizeof(logrule_ptr->ser_name)) >= sizeof(logrule_ptr->ser_name))
                (void)vrprint.error(-1, "Error", "buffer overflow attempt (in: %s:%d).", __FUNC__, __LINE__);
        }
    }

    return(1);
}


int
BuildVMLine (struct log_rule *logrule, char *outline, int size)
{
    /* TCP */
    switch (logrule->protocol)
    {
        case 6:                     /* TCP */
            CreateTCPFlagString(logrule, logrule->tcpflags);
            snprintf (outline, size, "%s %2d %02d:%02d:%02d: %s service %s from %s to %s, prefix: \"%s\" (%s%s%s%s:%d -> %s%s:%d TCP flags: %s len:%u ttl:%u)\n",
                logrule->month, logrule->day, logrule->hour, logrule->minute, logrule->second, logrule->action, logrule->ser_name, logrule->from_name, logrule->to_name, logrule->logprefix,
                logrule->from_int, logrule->to_int, logrule->src_ip, logrule->src_mac, logrule->src_port, logrule->dst_ip, logrule->dst_mac, logrule->dst_port, logrule->tcpflags,
                logrule->packet_len, logrule->ttl);
            break;
        case 17:                    /* UDP */
            snprintf (outline, size, "%s %2d %02d:%02d:%02d: %s service %s from %s to %s, prefix: \"%s\" (%s%s%s%s:%d -> %s%s:%d UDP len:%u ttl:%u)\n",
                logrule->month, logrule->day, logrule->hour, logrule->minute, logrule->second,
                logrule->action, logrule->ser_name,
                logrule->from_name, logrule->to_name,
                logrule->logprefix,
                logrule->from_int, logrule->to_int,
                logrule->src_ip, logrule->src_mac, logrule->src_port,
                logrule->dst_ip, logrule->dst_mac, logrule->dst_port,
                logrule->packet_len, logrule->ttl);
            break;
        case 1:                     /* ICMP */
            snprintf (outline, size, "%s %2d %02d:%02d:%02d: %s service %s from %s to %s, prefix: \"%s\" (%s%s%s%s -> %s%s ICMP type %d code %d len:%u ttl:%u)\n",
                logrule->month, logrule->day, logrule->hour, logrule->minute, logrule->second,
                logrule->action, logrule->ser_name,
                logrule->from_name, logrule->to_name,
                logrule->logprefix,
                logrule->from_int, logrule->to_int,
                logrule->src_ip, logrule->src_mac,
                logrule->dst_ip, logrule->dst_mac,
                logrule->icmp_type, logrule->icmp_code,
                logrule->packet_len, logrule->ttl);
                //logrule->tcpflags, logrule->packet_len, logrule->ttl);
            break;
        case 47:                    /* GRE */
            snprintf (outline, size, "%s %2d %02d:%02d:%02d: %s service %s from %s to %s, prefix: \"%s\" (%s%s%s%s -> %s%s GRE len:%u ttl:%u)\n",
                logrule->month, logrule->day, logrule->hour, logrule->minute, logrule->second,
                logrule->action, logrule->ser_name,
                logrule->from_name, logrule->to_name,
                logrule->logprefix,
                logrule->from_int, logrule->to_int,
                logrule->src_ip, logrule->src_mac,
                logrule->dst_ip, logrule->dst_mac,
                logrule->packet_len, logrule->ttl);
            break;
        case 50:                    /* ESP */
            snprintf (outline, size, "%s %2d %02d:%02d:%02d: %s service %s from %s to %s, prefix: \"%s\" (%s%s%s%s -> %s%s ESP len:%u ttl:%u)\n",
                logrule->month, logrule->day, logrule->hour, logrule->minute, logrule->second,
                logrule->action, logrule->ser_name,
                logrule->from_name, logrule->to_name,
                logrule->logprefix,
                logrule->from_int, logrule->to_int,
                logrule->src_ip, logrule->src_mac,
                logrule->dst_ip, logrule->dst_mac,
                logrule->packet_len, logrule->ttl);
            break;
        case 51:                    /* AH */
            snprintf (outline, size, "%s %2d %02d:%02d:%02d: %s service %s from %s to %s, prefix: \"%s\" (%s%s%s%s -> %s%s AH len:%u ttl:%u)\n",
                logrule->month, logrule->day, logrule->hour, logrule->minute, logrule->second,
                logrule->action, logrule->ser_name,
                logrule->from_name, logrule->to_name,
                logrule->logprefix,
                logrule->from_int, logrule->to_int,
                logrule->src_ip, logrule->src_mac,
                logrule->dst_ip, logrule->dst_mac,
                logrule->packet_len, logrule->ttl);
            break;
#ifdef IPV6_ENABLED
        case 58:                    /* ICMPv6 */
            snprintf (outline, size, "%s %2d %02d:%02d:%02d: %s service %s from %s to %s, prefix: \"%s\" (%s%s%s%s -> %s%s ICMPv6 type %d code %d len:%u ttl:%u)\n",
                logrule->month, logrule->day, logrule->hour, logrule->minute, logrule->second,
                logrule->action, logrule->ser_name,
                logrule->from_name, logrule->to_name,
                logrule->logprefix,
                logrule->from_int, logrule->to_int,
                logrule->src_ip, logrule->src_mac,
                logrule->dst_ip, logrule->dst_mac,
                logrule->icmp_type, logrule->icmp_code,
                logrule->packet_len, logrule->ttl);
            break;
#endif /* IPV6_ENABLED */
        default:
            snprintf (outline, size, "%s %2d %02d:%02d:%02d: %s service %s from %s to %s, prefix: \"%s\" (%s%s%s%s -> %s%s PROTO %d len:%u ttl:%u)\n",
                logrule->month, logrule->day, logrule->hour, logrule->minute, logrule->second,
                logrule->action, logrule->ser_name,
                logrule->from_name, logrule->to_name,
                logrule->logprefix,
                logrule->from_int, logrule->to_int,
                logrule->src_ip, logrule->src_mac,
                logrule->dst_ip, logrule->dst_mac,
                logrule->protocol,
                logrule->packet_len, logrule->ttl);

            (void)vrprint.debug(__FUNC__, "unknown protocol");
            break;
    }

    return (0);
}

static void
print_help(void)
{
    fprintf(stdout, "Usage: vuurmuur_log [OPTIONS]\n");
    fprintf(stdout, "\n");
    fprintf(stdout, "Options:\n");
    fprintf(stdout, " -h, --help\t\t\tgives this help\n");
    fprintf(stdout, " -v, --verbose\t\t\tverbose mode\n");
    fprintf(stdout, " -n, --nodaemon\t\t\tdo NOT start as a daemon\n");
    fprintf(stdout, " -c, --configfile\t\tuse the given configfile\n");
    fprintf(stdout, " -d, --debug\t\t\tenable debugging (1 = low, 3 = high)\n");
    fprintf(stdout, " -K, --killme\t\t\tkill running daemon\n");
    fprintf(stdout, " -V, --version\t\t\tgives the version\n");
    fprintf(stdout, "\n");
    exit(EXIT_SUCCESS);
}

/* process one line/record */
int process_logrecord(struct log_rule *logrule_ptr) {
    char line_out[1024] = "";

    int result = get_vuurmuur_names(g_debuglvl, logrule_ptr, &zone_htbl, &service_htbl);
    switch (result)
    {
        case -1:
            (void)vrprint.debug(__FUNC__, "get_vuurmuur_names returned -1");
            exit(EXIT_FAILURE);
            break;
        case 0:
            Counters.invalid_loglines++;
            break;
        default:
            if (BuildVMLine (logrule_ptr, line_out, sizeof(line_out)) < 0)
            {
                (void)vrprint.debug("nflog", "Could not build output line");
            } else {
                upd_action_ctrs(logrule_ptr->action, &Counters);

                fprintf (g_traffic_log, "%s", line_out);
                fflush(g_traffic_log);
            }
            break;
    }

    return 0;
}

int
main(int argc, char *argv[])
{
    Interfaces  interfaces;
    Services    services;
    Zones       zones;

    FILE        *system_log = NULL;
    char        line_in[1024] = "";
    char        line_out[1024] = "";
    size_t      line_in_len = 0;

    int         result,

                /*  variable for counting how long we are waiting
                    for the next line in 1/10th of a second.
                */
                waiting = 0;
    pid_t       pid;
    int         optch;
    static char optstring[] = "hc:vnd:VsKN";
    int         verbose = 0,
                nodaemon = 0,
                syslog = 1;
    struct option prog_opts[] =
    {
        { "help", no_argument, NULL, 'h' },
        { "verbose", no_argument, &verbose, 1 },
        { "nodaemon", no_argument, &nodaemon, 1 },
        { "configfile", required_argument, NULL, 'c' },
        { "debug", required_argument, NULL, 'd' },
        { "killme", required_argument, NULL, 'K' },
        { "version", no_argument, NULL, 'V' },
        { 0, 0, 0, 0 },
    };
    int                         option_index = 0;
    char                        *sscanf_str = NULL;

    struct log_rule             logrule;
    int                         debuglvl = 0;

    /* shm, sem stuff */
    int             shm_id;
    int             reload = 0;

    struct rgx_ reg;
    char        quit = 0;

    /* get the current user */
    get_user_info(debuglvl, &user_data);

    snprintf(version_string, sizeof(version_string), "%s (using libvuurmuur %s)",
            VUURMUUR_VERSION, libvuurmuur_get_version());

    /* init signals */
    setup_signal_handler(SIGINT, handle_sigint);
    setup_signal_handler(SIGTERM, handle_sigterm);
    setup_signal_handler(SIGHUP, handle_sighup);

    /* initialize the print functions */
    vrprint.logger = "vuurmuur_log";
    vrprint.error = libvuurmuur_stdoutprint_error;
    vrprint.warning = libvuurmuur_stdoutprint_warning;
    vrprint.info = libvuurmuur_stdoutprint_info;
    vrprint.debug = libvuurmuur_stdoutprint_debug;
    vrprint.username = user_data.realusername;
    vrprint.audit = libvuurmuur_stdoutprint_audit;

    /* set default configfile location */
    if(pre_init_config(&conf) < 0)
        exit(EXIT_FAILURE);

    /* process the options */
    while((optch = getopt_long(argc, argv, optstring, prog_opts,
                    &option_index)) != -1 )
    {
        switch(optch)
        {
            case 0 :
                /* This is used for the flags long options */
                break;

            case 'h' :
                print_help();
                break;

            case 'v' :
                verbose = 1;
                break;

            case 'n' :
                nodaemon = 1;
                break;

            case 'c' :
                /* config file */
                if(conf.verbose_out == TRUE)
                    fprintf(stdout, "Using this configfile: %s\n", optarg);

                if(strlcpy(conf.configfile, optarg, sizeof(conf.configfile)) >= sizeof(conf.configfile))
                {
                    fprintf(stderr, "Error: configfile (-c): argument too long (max: %d).\n", (int)sizeof(conf.configfile)-1);
                    exit(EXIT_FAILURE);
                }
                break;

            case 'd' :
                /* debugging */
                fprintf(stdout, "vuurmuur: debugging enabled.\n");

                /* convert the debug string and check the result */
                g_debuglvl = debuglvl = atoi(optarg);
                if(debuglvl < 0 || debuglvl > HIGH)
                {
                    fprintf(stdout, "Error: illegal debug level: %d (max: %d).\n", debuglvl, HIGH);
                    exit(EXIT_FAILURE);
                }

                fprintf(stdout, "vuurmuur-log: debug level: %d\n", debuglvl);
                break;

            case 'K' :
                if (check_pidfile (PIDFILE, SVCNAME, &pid) == -1)
                {
                    (void)vrprint.debug(__FUNC__, "Terminating %u", pid);
                    kill (pid, 15);
                    exit (EXIT_SUCCESS);
                }
                exit (EXIT_FAILURE);
                break;

            case 'V' :
                /* print version */
                fprintf(stdout, "Vuurmuur_log %s\n", version_string);
                fprintf(stdout, "Copyright (C) 2002-2008 by Victor Julien\n");

                exit(EXIT_SUCCESS);
        }
    }

    /* check if the pidfile already exists */
    if(check_pidfile(PIDFILE, SVCNAME, &pid) == -1)
        exit(EXIT_FAILURE);

    /* init the config file */
    if(init_config(debuglvl, &conf) < VR_CNF_OK)
    {
        (void)vrprint.error(-1, "Error", "initializing the config failed.");
        exit(EXIT_FAILURE);
    }

    if (conf.rule_nflog) {
        syslog = 0;
    } else {
        syslog = 1;
    }

    /* set up the sscanf parser string if we're using the legacy syslog parsing */
    if(syslog && !(sscanf_str = assemble_logline_sscanf_string(debuglvl, &logrule)))
    {
        (void)vrprint.error(-1, "Error", "could not set up parse string for legacy syslog parsing.");
        exit(EXIT_FAILURE);
    }


    if(verbose)
        (void)vrprint.info("Info", "Vuurmuur_log %s", version_string);

    /* now setup the print function */
    if(verbose)
        vrprint.error = libvuurmuur_stdoutprint_error;
    else
        vrprint.error = libvuurmuur_logprint_error;

    vrprint.warning = libvuurmuur_logprint_warning;
    vrprint.info = libvuurmuur_logprint_info;
    vrprint.debug = libvuurmuur_logprint_debug;
    vrprint.audit = libvuurmuur_logprint_audit;

    (void)vrprint.audit("Vuurmuur_log %s %s started by user %s.", version_string, (syslog) ? "" :"(experimental nflog mode)", user_data.realusername);

#ifdef HAVE_LIBNETFILTER_LOG
    /* Setup nflog after init_config as and logging as we need &conf in subscribe_nflog() */
    if (!syslog)
    {
        (void)vrprint.debug(__FUNC__, "Setting up nflog");
        if (subscribe_nflog(debuglvl, &conf, &logrule) < 0) {
            (void)vrprint.error(-1, "Error", "could not set up nflog subscription");
            exit (EXIT_FAILURE);
        }
    }
#else
    if (!syslog) {
        (void)vrprint.error(-1, "Error", "syslog mode disabled but no other modes available.");
        exit (EXIT_FAILURE);
    }
#endif /* HAVE_LIBNETFILTER_LOG */

    /* setup regexes */
    if(setup_rgx(1, &reg) < 0)
    {
        (void)vrprint.error(-1, "Internal Error", "setting up regular expressions failed.");
        exit(EXIT_FAILURE);
    }

    if(load_backends(debuglvl) < 0)
    {
        (void)vrprint.error(-1, "Error", "loading plugins failed, bailing out.");
        exit(EXIT_FAILURE);
    }

    /* open the logs */
    if(syslog && open_syslog(debuglvl, &conf, &system_log) < 0)
    {
        (void)vrprint.error(-1, "Error", "opening logfiles failed.");
        exit(EXIT_FAILURE);
    }

    if (open_vuurmuurlog (debuglvl, &conf, &g_traffic_log) < 0)
    {
        (void)vrprint.error(-1, "Error", "opening logfiles failed.");
        exit(EXIT_FAILURE);
    }

    /* load the services into memory */
    if(load_services(debuglvl, &services, &reg)== -1)
        exit(EXIT_FAILURE);

    /* load the interfaces into memory */
    if(load_interfaces(debuglvl, &interfaces) == -1)
        exit(EXIT_FAILURE);

    /* load the zonedata into memory */
    if(load_zones(debuglvl, &zones, &interfaces, &reg) == -1)
        exit(EXIT_FAILURE);


    /* insert the interfaces as TYPE_FIREWALL's into the zonelist as 'firewall', so this appears in to log as 'firewall(interface)' */
    if(ins_iface_into_zonelist(debuglvl, &interfaces.list, &zones.list) < 0)
    {
        (void)vrprint.error(-1, "Error", "iface_into_zonelist failed (in: main).");
        exit(EXIT_FAILURE);
    }

    /* these are removed by: rem_iface_from_zonelist() (see below) */
    if(add_broadcasts_zonelist(debuglvl, &zones) < 0)
    {
        (void)vrprint.error(-1, "Error", "unable to add broadcasts to list.");
        exit(EXIT_FAILURE);
    }

    (void)vrprint.info("Info", "Creating hash-table for the zones...");
    if(init_zonedata_hashtable(debuglvl, zones.list.len * 3, &zones.list, hash_ipaddress, compare_ipaddress, &zone_htbl) < 0)
    {
        (void)vrprint.error(-1, "Error", "init_zonedata_hashtable failed.");
        exit(EXIT_FAILURE);
    }

    (void)vrprint.info("Info", "Creating hash-table for the services...");
    if(init_services_hashtable(debuglvl, services.list.len * 500, &services.list, hash_port, compare_ports, &service_htbl) < 0)
    {
        (void)vrprint.error(-1, "Error", "init_services_hashtable failed.");
        exit(EXIT_FAILURE);
    }

    if (nodaemon == 0) {
        if (daemon(1,1) != 0) {
            (void)vrprint.error(-1, "Error", "daemon() failed: %s",
                    strerror(errno));
            exit(EXIT_FAILURE);
        }
    }

    if (SetupVMIPC(&shm_id, &shm_table) == -1)
        exit (EXIT_FAILURE);

    if(create_pidfile(PIDFILE, shm_id) < 0)
        exit(EXIT_FAILURE);

    if(sigint_count || sigterm_count)
        quit = 1;

    /* enter the main loop */
    while(quit == 0)
    {
        reload = CheckVMIPC (debuglvl, shm_table);
        if (reload == 0)
        {
            if (syslog) {
                if (fgets(line_in, (int)sizeof(line_in), system_log) != NULL) {
                    waiting = 0;

                    line_in_len = strlen(line_in);
                    if ((line_in_len < sizeof(line_in)-1) && line_in[line_in_len - 1] != '\n')
                    {
                        fseek(system_log, (int)line_in_len*-1, SEEK_CUR);
                    }
                    else
                    {
                        if (check_ipt_line(line_in))
                        {
                            switch (parse_ipt_logline(debuglvl, line_in, line_in_len, sscanf_str, &logrule, &Counters))
                            {
                                case -1:
                                    exit(EXIT_FAILURE);
                                    break;
                                case 0:
                                    Counters.invalid_loglines++;
                                    break;
                                default:
                                    result = get_vuurmuur_names(debuglvl, &logrule, &zone_htbl, &service_htbl);
                                    switch (result)
                                    {
                                        case -1:
                                            exit(EXIT_FAILURE);
                                            break;
                                        case 0:
                                            Counters.invalid_loglines++;
                                            break;
                                        default:
                                            if (BuildVMLine (&logrule, line_out, sizeof(line_out)) < 0) {
                                                (void)vrprint.error(-1, "Error", "could not build output line");
                                            } else {
                                                fprintf(g_traffic_log, "%s", line_out);
                                                fflush(g_traffic_log);
                                            }
                                            break;
                                    }
                            }
                            Counters.totalvuurmuur++;
                        } else {
                            Counters.noipt++;
                        }
                        Counters.total++;
                    }
                }
                /* no line received or not using syslog */
                else {
                    /* increase the waiter */
                    waiting++;

                    /* see the definition of MAX_WAIT_TIME for details. */
                    if(waiting >= MAX_WAIT_TIME) {
                        if(debuglvl >= MEDIUM)
                            (void)vrprint.debug(__FUNC__, "didn't get a logline for %d seconds, closing and reopening the logfiles.", waiting / 10);

                        /* re-open the logs */
                        if(reopen_syslog(debuglvl, &conf, &system_log) < 0) {
                            (void)vrprint.error(-1, "Error", "re-opening syslog failed.");
                            exit(EXIT_FAILURE);
                        }

                        if(reopen_vuurmuurlog(debuglvl, &conf, &g_traffic_log) < 0) {
                            (void)vrprint.error(-1, "Error", "re-opening vuurmuur traffic log failed.");
                            exit(EXIT_FAILURE);
                        }

                        /* reset waiting */
                        waiting = 0;
                    } else {
                        /* sleep so we don't use all system resources */
                        usleep(100000);  /* this should be 1/10th of a second */
                    }
                }
#ifdef HAVE_LIBNETFILTER_LOG
            /* not using syslog so must be using nflog here */
            } else {
                switch (readnflog()) {
                    case -1:
                        (void)vrprint.error(-1, "Error", "could not read from nflog");
                        exit (EXIT_FAILURE);
                        break;
                    case 0:
                        usleep (100000);
                        break;
                }
#endif /* HAVE_LIBNETFILTER_LOG */
            } /* if syslog */
        } /* if reload == 0 */

        /*
            hey! we received a sighup. We will reload the data.
        */
        if(sighup_count || reload)
        {
            sighup_count = 0;

            /*
                clean up data
            */

            /* destroy hashtables */
            hash_cleanup(debuglvl, &zone_htbl);
            hash_cleanup(debuglvl, &service_htbl);

            /* destroy the ServicesList */
            destroy_serviceslist(debuglvl, &services);
            /* destroy the ZonedataList */
            destroy_zonedatalist(debuglvl, &zones);
            /* destroy the InterfacesList */
            destroy_interfaceslist(debuglvl, &interfaces);

            /* close backend */
            result = unload_backends(debuglvl);
            if(result < 0)
            {
                (void)vrprint.error(-1, "Error", "unloading backends failed.");
                exit(EXIT_FAILURE);
            }

            shm_update_progress(debuglvl, sem_id, &shm_table->reload_progress, 10);

            /* reload the config

               if it fails it's no big deal, we just keep using the old config.
            */
            if(reload_config(debuglvl, &conf) < VR_CNF_OK)
            {
                (void)vrprint.warning("Warning", "reloading config failed, using old config.");
            }

            shm_update_progress(debuglvl, sem_id, &shm_table->reload_progress, 20);

            /* open backends */
            result = load_backends(debuglvl);
            if(result < 0)
            {
                (void)vrprint.error(-1, "Error", "re-opening backends failed.");
                exit(EXIT_FAILURE);
            }

            shm_update_progress(debuglvl, sem_id, &shm_table->reload_progress, 30);

            /* re-initialize the data */
            (void)vrprint.info("Info", "Initializing interfaces...");
            if(init_interfaces(debuglvl, &interfaces) < 0)
            {
                (void)vrprint.error(-1, "Error", "initializing interfaces failed.");
                exit(EXIT_FAILURE);
            }

            shm_update_progress(debuglvl, sem_id, &shm_table->reload_progress, 40);

            (void)vrprint.info("Info", "Initializing zones...");
            if(init_zonedata(debuglvl, &zones, &interfaces, &reg) < 0)
            {
                (void)vrprint.error(-1, "Error", "initializing zones failed.");
                exit(EXIT_FAILURE);
            }

            shm_update_progress(debuglvl, sem_id, &shm_table->reload_progress, 50);

            (void)vrprint.info("Info", "Initializing services...");
            if(init_services(debuglvl, &services, &reg) < 0)
            {
                (void)vrprint.error(-1, "Error", "initializing services failed.");
                exit(EXIT_FAILURE);
            }

            shm_update_progress(debuglvl, sem_id, &shm_table->reload_progress, 60);

            /* insert the interfaces as TYPE_FIREWALL's into the zonelist as 'firewall', so this appears in to log as 'firewall(interface)' */
            if(ins_iface_into_zonelist(debuglvl, &interfaces.list, &zones.list) < 0)
            {
                (void)vrprint.error(-1, "Error", "iface_into_zonelist failed (in: main).");
                exit(EXIT_FAILURE);
            }

            /* these are removed by: rem_iface_from_zonelist() (see below) */
            if(add_broadcasts_zonelist(debuglvl, &zones) < 0)
            {
                (void)vrprint.error(-1, "Error", "unable to add broadcasts to list.");
                return(-1);
            }
            shm_update_progress(debuglvl, sem_id, &shm_table->reload_progress, 70);

            (void)vrprint.info("Info", "Creating hash-table for the zones...");
            if(init_zonedata_hashtable(debuglvl, zones.list.len * 3, &zones.list, hash_ipaddress, compare_ipaddress, &zone_htbl) < 0)
            {
                (void)vrprint.error(result, "Error", "init_zonedata_hashtable failed.");
                exit(EXIT_FAILURE);
            }
            shm_update_progress(debuglvl, sem_id, &shm_table->reload_progress, 80);

            (void)vrprint.info("Info", "Creating hash-table for the services...");
            if(init_services_hashtable(debuglvl, services.list.len * 500, &services.list, hash_port, compare_ports, &service_htbl) < 0)
            {
                (void)vrprint.error(result, "Error", "init_services_hashtable failed.");
                exit(EXIT_FAILURE);
            }
            shm_update_progress(debuglvl, sem_id, &shm_table->reload_progress, 90);

            /* re-open the logs */
            if(syslog && reopen_syslog(debuglvl, &conf, &system_log) < 0)
            {
                (void)vrprint.error(-1, "Error", "re-opening logfiles failed.");
                exit(EXIT_FAILURE);
            }

            if(reopen_vuurmuurlog(debuglvl, &conf, &g_traffic_log) < 0)
            {
                (void)vrprint.error(-1, "Error", "re-opening logfiles failed.");
                exit(EXIT_FAILURE);
            }
            shm_update_progress(debuglvl, sem_id, &shm_table->reload_progress, 95);

            /* only ok now */
            result = 0;

            /* if we are reloading because of an IPC command, we need to communicate with the caller */
            if(reload == 1)
                WaitVMIPCACK (30, &result, shm_table, &reload);
        }

        /* check for a signal */
        if(sigint_count || sigterm_count)
            quit = 1;

    }


    /*
        cleanup
    */
    if (ClearVMIPC (debuglvl, shm_id) == -1)
    {
        (void)vrprint.error(-1, "Error", "Detach from VM IPC failed.");
        /* fall through */
    }

    /* free the sscanf parser string */
    free(sscanf_str);

    /* close the logfiles */
    if (g_traffic_log != NULL)
        fclose(g_traffic_log);
    if (system_log != NULL)
        fclose(system_log);

    /* destroy hashtables */
    hash_cleanup(debuglvl, &zone_htbl);
    hash_cleanup(debuglvl, &service_htbl);

    /* destroy the ServicesList */
    destroy_serviceslist(debuglvl, &services);
    /* destroy the ZonedataList */
    destroy_zonedatalist(debuglvl, &zones);
    /* destroy the InterfacesList */
    destroy_interfaceslist(debuglvl, &interfaces);

    if(nodaemon)
        show_stats (&Counters);

    if(unload_backends(debuglvl) < 0)
    {
        (void)vrprint.error(-1, "Error", "unloading backends failed.");
    }

    /* cleanup regexes */
    (void)setup_rgx(0, &reg);

    /* remove the pidfile */
    if(remove_pidfile(PIDFILE) < 0)
    {
        (void)vrprint.error(-1, "Error", "unable to remove pidfile: %s.", strerror(errno));
    }

    exit(EXIT_SUCCESS);
}
