/***************************************************************************
 *   Copyright (C) 2002-2017 by Victor Julien                              *
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
struct vrmr_shm_table *shm_table = 0;
static int g_debuglvl = 0;
static struct vrmr_hash_table zone_htbl;
static struct vrmr_hash_table service_htbl;
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


static void
handle_sigint(int sig)
{
    sigint_count = 1;
}


static void
handle_sigterm(int sig)
{
    sigterm_count = 1;
}


static void
handle_sighup(int sig)
{
    sighup_count = 1;
}


static void
setup_signal_handler(int sig, void (*handler)(int))
{
    struct sigaction action;

    action.sa_handler = handler;
    sigemptyset(&(action.sa_mask));
    sigaddset(&(action.sa_mask),sig);
    action.sa_flags = 0;
    sigaction(sig, &action, 0);
}

static char *
assemble_logline_sscanf_string(const int debuglvl, struct vrmr_log_record *log_record)
{
    char    *string,
            temp_buf[256] = "";
    size_t  str_len = 0;

    //"%s %2d %2d:%2d:%2d %s";
    snprintf(temp_buf, sizeof(temp_buf), "%%%ds %%2d %%2d:%%2d:%%2d %%%ds",
            (int)sizeof(log_record->month)-1,
            (int)sizeof(log_record->hostname)-1);

    if(debuglvl >= HIGH)
        vrmr_debug(__FUNC__, "assemble_logline_sscanf_string: string: '%s'. (len: %d)", temp_buf, strlen(temp_buf));

    str_len = strlen(temp_buf) + 1;
    if(str_len > sizeof(temp_buf))
    {
        vrmr_error(-1, "Internal Error", "string overflow (in: %s:%d).", __FUNC__, __LINE__);
        return(NULL);
    }

    if(!(string = malloc(str_len)))
    {
        vrmr_error(-1, "Error", "malloc failed: %s.", strerror(errno));
        return(NULL);
    }

    if(strlcpy(string, temp_buf, str_len) > str_len)
    {
        vrmr_error(-1, "Internal Error", "buffer overflow (in: %s:%d).", __FUNC__, __LINE__);
        return(NULL);
    }

    return(string);
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
int process_logrecord(struct vrmr_log_record *log_record) {
    char line_out[1024] = "";

    int result = vrmr_log_record_get_names(g_debuglvl, log_record, &zone_htbl, &service_htbl);
    switch (result)
    {
        case -1:
            vrmr_debug(__FUNC__, "vrmr_log_record_get_names returned -1");
            exit(EXIT_FAILURE);
            break;
        case 0:
            Counters.invalid_loglines++;
            break;
        default:
            if (vrmr_log_record_build_line (g_debuglvl, log_record, line_out, sizeof(line_out)) < 0)
            {
                vrmr_debug("nflog", "Could not build output line");
            } else {
                upd_action_ctrs(log_record->action, &Counters);

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
    struct vrmr_ctx vctx;
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

    struct vrmr_log_record      logrule;
    int                         debuglvl = 0;

    /* shm, sem stuff */
    int             shm_id;
    int             reload = 0;

    char        quit = 0;

    snprintf(version_string, sizeof(version_string), "%s (using libvuurmuur %s)",
            VUURMUUR_VERSION, libvuurmuur_get_version());

    vrmr_init(&vctx, "vuurmuur_log");

    /* init signals */
    setup_signal_handler(SIGINT, handle_sigint);
    setup_signal_handler(SIGTERM, handle_sigterm);
    setup_signal_handler(SIGHUP, handle_sighup);

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
                if(vctx.conf.verbose_out == TRUE)
                    fprintf(stdout, "Using this configfile: %s\n", optarg);

                if(strlcpy(vctx.conf.configfile, optarg, sizeof(vctx.conf.configfile)) >= sizeof(vctx.conf.configfile))
                {
                    fprintf(stderr, "Error: configfile (-c): argument too long (max: %d).\n", (int)sizeof(vctx.conf.configfile)-1);
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
                if (vrmr_check_pidfile (PIDFILE, SVCNAME, &pid) == -1)
                {
                    vrmr_debug(__FUNC__, "Terminating %u", pid);
                    kill (pid, 15);
                    exit (EXIT_SUCCESS);
                }
                exit (EXIT_FAILURE);
                break;

            case 'V' :
                /* print version */
                fprintf(stdout, "Vuurmuur_log %s\n", version_string);
                fprintf(stdout, "%s\n", VUURMUUR_COPYRIGHT);

                exit(EXIT_SUCCESS);
        }
    }

    /* check if the pidfile already exists */
    if(vrmr_check_pidfile(PIDFILE, SVCNAME, &pid) == -1)
        exit(EXIT_FAILURE);

    /* init the config file */
    if(vrmr_init_config(debuglvl, &vctx.conf) < VRMR_CNF_OK) {
        vrmr_error(-1, "Error", "initializing the config failed.");
        exit(EXIT_FAILURE);
    }

    if (vctx.conf.rule_nflog) {
        syslog = 0;
    } else {
        syslog = 1;
    }

    /* set up the sscanf parser string if we're using the legacy syslog parsing */
    if(syslog && !(sscanf_str = assemble_logline_sscanf_string(debuglvl, &logrule))) {
        vrmr_error(-1, "Error", "could not set up parse string for legacy syslog parsing.");
        exit(EXIT_FAILURE);
    }

    if(verbose)
        vrmr_info("Info", "Vuurmuur_log %s", version_string);

    /* now setup the print function */
    if(verbose)
        vrprint.error = vrmr_stdoutprint_error;
    else
        vrprint.error = vrmr_logprint_error;

    vrprint.warning = vrmr_logprint_warning;
    vrprint.info = vrmr_logprint_info;
    vrprint.debug = vrmr_logprint_debug;
    vrprint.audit = vrmr_logprint_audit;

    /* get the current user */
    vrmr_audit("Vuurmuur_log %s %s started by user %s.",
            version_string, (syslog) ? "" :"(nflog mode)",
            vctx.user_data.realusername);

#ifdef HAVE_LIBNETFILTER_LOG
    /* Setup nflog after vrmr_init_config as and logging as we need &conf in subscribe_nflog() */
    if (!syslog) {
        vrmr_debug(__FUNC__, "Setting up nflog");
        if (subscribe_nflog(debuglvl, &vctx.conf, &logrule) < 0) {
            vrmr_error(-1, "Error", "could not set up nflog subscription");
            exit (EXIT_FAILURE);
        }
    }
#else
    if (!syslog) {
        vrmr_error(-1, "Error", "syslog mode disabled but no other modes available.");
        exit (EXIT_FAILURE);
    }
#endif /* HAVE_LIBNETFILTER_LOG */

    if (vrmr_backends_load(debuglvl, &vctx.conf, &vctx) < 0) {
        vrmr_error(-1, "Error", "loading plugins failed, bailing out.");
        exit(EXIT_FAILURE);
    }

    /* open the logs */
    if(syslog && open_syslog(debuglvl, &vctx.conf, &system_log) < 0) {
        vrmr_error(-1, "Error", "opening logfiles failed.");
        exit(EXIT_FAILURE);
    }

    if (open_vuurmuurlog (debuglvl, &vctx.conf, &g_traffic_log) < 0) {
        vrmr_error(-1, "Error", "opening logfiles failed.");
        exit(EXIT_FAILURE);
    }

    /* load the services into memory */
    if (vrmr_services_load(debuglvl, &vctx, &vctx.services, &vctx.reg)== -1)
        exit(EXIT_FAILURE);

    /* load the interfaces into memory */
    if (vrmr_interfaces_load(debuglvl, &vctx, &vctx.interfaces) == -1)
        exit(EXIT_FAILURE);

    /* load the zonedata into memory */
    if (vrmr_zones_load(debuglvl, &vctx, &vctx.zones, &vctx.interfaces, &vctx.reg) == -1)
        exit(EXIT_FAILURE);


    /* insert the interfaces as VRMR_TYPE_FIREWALL's into the zonelist as 'firewall', so this appears in to log as 'firewall(interface)' */
    if(vrmr_ins_iface_into_zonelist(debuglvl, &vctx.interfaces.list, &vctx.zones.list) < 0)
    {
        vrmr_error(-1, "Error", "iface_into_zonelist failed (in: main).");
        exit(EXIT_FAILURE);
    }

    /* these are removed by: vrmr_rem_iface_from_zonelist() (see below) */
    if(vrmr_add_broadcasts_zonelist(debuglvl, &vctx.zones) < 0)
    {
        vrmr_error(-1, "Error", "unable to add broadcasts to list.");
        exit(EXIT_FAILURE);
    }

    vrmr_info("Info", "Creating hash-table for the zones...");
    if(vrmr_init_zonedata_hashtable(debuglvl, vctx.zones.list.len * 3, &vctx.zones.list, vrmr_hash_ipaddress, vrmr_compare_ipaddress, &zone_htbl) < 0)
    {
        vrmr_error(-1, "Error", "vrmr_init_zonedata_hashtable failed.");
        exit(EXIT_FAILURE);
    }

    vrmr_info("Info", "Creating hash-table for the services...");
    if(vrmr_init_services_hashtable(debuglvl, vctx.services.list.len * 500, &vctx.services.list, vrmr_hash_port, vrmr_compare_ports, &service_htbl) < 0)
    {
        vrmr_error(-1, "Error", "vrmr_init_services_hashtable failed.");
        exit(EXIT_FAILURE);
    }

    if (nodaemon == 0) {
        if (daemon(1,1) != 0) {
            vrmr_error(-1, "Error", "daemon() failed: %s",
                    strerror(errno));
            exit(EXIT_FAILURE);
        }
    }

    if (SetupVMIPC(&shm_id, &shm_table) == -1)
        exit (EXIT_FAILURE);

    if(vrmr_create_pidfile(PIDFILE, shm_id) < 0)
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
                                    result = vrmr_log_record_get_names(debuglvl, &logrule, &zone_htbl, &service_htbl);
                                    switch (result)
                                    {
                                        case -1:
                                            exit(EXIT_FAILURE);
                                            break;
                                        case 0:
                                            Counters.invalid_loglines++;
                                            break;
                                        default:
                                            if (vrmr_log_record_build_line (debuglvl, &logrule, line_out, sizeof(line_out)) < 0) {
                                                vrmr_error(-1, "Error", "could not build output line");
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
                            vrmr_debug(__FUNC__, "didn't get a logline for %d seconds, closing and reopening the logfiles.", waiting / 10);

                        /* re-open the logs */
                        if(reopen_syslog(debuglvl, &vctx.conf, &system_log) < 0) {
                            vrmr_error(-1, "Error", "re-opening syslog failed.");
                            exit(EXIT_FAILURE);
                        }

                        if(reopen_vuurmuurlog(debuglvl, &vctx.conf, &g_traffic_log) < 0) {
                            vrmr_error(-1, "Error", "re-opening vuurmuur traffic log failed.");
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
                        vrmr_error(-1, "Error", "could not read from nflog");
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
            vrmr_hash_cleanup(debuglvl, &zone_htbl);
            vrmr_hash_cleanup(debuglvl, &service_htbl);

            /* destroy the ServicesList */
            vrmr_destroy_serviceslist(debuglvl, &vctx.services);
            /* destroy the ZonedataList */
            vrmr_destroy_zonedatalist(debuglvl, &vctx.zones);
            /* destroy the InterfacesList */
            vrmr_destroy_interfaceslist(debuglvl, &vctx.interfaces);

            /* close backend */
            result = vrmr_backends_unload(debuglvl, &vctx.conf, &vctx);
            if(result < 0)
            {
                vrmr_error(-1, "Error", "unloading backends failed.");
                exit(EXIT_FAILURE);
            }

            vrmr_shm_update_progress(debuglvl, sem_id, &shm_table->reload_progress, 10);

            /* reload the config

               if it fails it's no big deal, we just keep using the old config.
            */
            if(vrmr_reload_config(debuglvl, &vctx.conf) < VRMR_CNF_OK)
            {
                vrmr_warning("Warning", "reloading config failed, using old config.");
            }

            vrmr_shm_update_progress(debuglvl, sem_id, &shm_table->reload_progress, 20);

            /* open backends */
            result = vrmr_backends_load(debuglvl, &vctx.conf, &vctx);
            if(result < 0)
            {
                vrmr_error(-1, "Error", "re-opening backends failed.");
                exit(EXIT_FAILURE);
            }

            vrmr_shm_update_progress(debuglvl, sem_id, &shm_table->reload_progress, 30);

            /* re-initialize the data */
            vrmr_info("Info", "Initializing interfaces...");
            if (vrmr_init_interfaces(debuglvl, &vctx, &vctx.interfaces) < 0)
            {
                vrmr_error(-1, "Error", "initializing interfaces failed.");
                exit(EXIT_FAILURE);
            }

            vrmr_shm_update_progress(debuglvl, sem_id, &shm_table->reload_progress, 40);

            vrmr_info("Info", "Initializing zones...");
            if (vrmr_init_zonedata(debuglvl, &vctx, &vctx.zones, &vctx.interfaces, &vctx.reg) < 0)
            {
                vrmr_error(-1, "Error", "initializing zones failed.");
                exit(EXIT_FAILURE);
            }

            vrmr_shm_update_progress(debuglvl, sem_id, &shm_table->reload_progress, 50);

            vrmr_info("Info", "Initializing services...");
            if (vrmr_init_services(debuglvl, &vctx, &vctx.services, &vctx.reg) < 0)
            {
                vrmr_error(-1, "Error", "initializing services failed.");
                exit(EXIT_FAILURE);
            }

            vrmr_shm_update_progress(debuglvl, sem_id, &shm_table->reload_progress, 60);

            /* insert the interfaces as VRMR_TYPE_FIREWALL's into the zonelist as 'firewall', so this appears in to log as 'firewall(interface)' */
            if(vrmr_ins_iface_into_zonelist(debuglvl, &vctx.interfaces.list, &vctx.zones.list) < 0)
            {
                vrmr_error(-1, "Error", "iface_into_zonelist failed (in: main).");
                exit(EXIT_FAILURE);
            }

            /* these are removed by: vrmr_rem_iface_from_zonelist() (see below) */
            if(vrmr_add_broadcasts_zonelist(debuglvl, &vctx.zones) < 0)
            {
                vrmr_error(-1, "Error", "unable to add broadcasts to list.");
                return(-1);
            }
            vrmr_shm_update_progress(debuglvl, sem_id, &shm_table->reload_progress, 70);

            vrmr_info("Info", "Creating hash-table for the zones...");
            if(vrmr_init_zonedata_hashtable(debuglvl, vctx.zones.list.len * 3, &vctx.zones.list, vrmr_hash_ipaddress, vrmr_compare_ipaddress, &zone_htbl) < 0)
            {
                vrmr_error(result, "Error", "vrmr_init_zonedata_hashtable failed.");
                exit(EXIT_FAILURE);
            }
            vrmr_shm_update_progress(debuglvl, sem_id, &shm_table->reload_progress, 80);

            vrmr_info("Info", "Creating hash-table for the services...");
            if(vrmr_init_services_hashtable(debuglvl, vctx.services.list.len * 500, &vctx.services.list, vrmr_hash_port, vrmr_compare_ports, &service_htbl) < 0)
            {
                vrmr_error(result, "Error", "vrmr_init_services_hashtable failed.");
                exit(EXIT_FAILURE);
            }
            vrmr_shm_update_progress(debuglvl, sem_id, &shm_table->reload_progress, 90);

            /* re-open the logs */
            if(syslog && reopen_syslog(debuglvl, &vctx.conf, &system_log) < 0)
            {
                vrmr_error(-1, "Error", "re-opening logfiles failed.");
                exit(EXIT_FAILURE);
            }

            if(reopen_vuurmuurlog(debuglvl, &vctx.conf, &g_traffic_log) < 0)
            {
                vrmr_error(-1, "Error", "re-opening logfiles failed.");
                exit(EXIT_FAILURE);
            }
            vrmr_shm_update_progress(debuglvl, sem_id, &shm_table->reload_progress, 95);

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
        vrmr_error(-1, "Error", "Detach from VM IPC failed.");
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
    vrmr_hash_cleanup(debuglvl, &zone_htbl);
    vrmr_hash_cleanup(debuglvl, &service_htbl);

    /* destroy the ServicesList */
    vrmr_destroy_serviceslist(debuglvl, &vctx.services);
    /* destroy the ZonedataList */
    vrmr_destroy_zonedatalist(debuglvl, &vctx.zones);
    /* destroy the InterfacesList */
    vrmr_destroy_interfaceslist(debuglvl, &vctx.interfaces);

    if(nodaemon)
        show_stats (&Counters);

    if(vrmr_backends_unload(debuglvl, &vctx.conf, &vctx) < 0)
    {
        vrmr_error(-1, "Error", "unloading backends failed.");
    }

    /* remove the pidfile */
    if(vrmr_remove_pidfile(PIDFILE) < 0)
    {
        vrmr_error(-1, "Error", "unable to remove pidfile: %s.", strerror(errno));
    }

    exit(EXIT_SUCCESS);
}
