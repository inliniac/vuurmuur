/***************************************************************************
 *   Copyright (C) 2002-2008 by Victor Julien                              *
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
 
#include "main.h"

static void print_help(void);

/*
    we put this here, because we only use it here in main.
*/
static int sigint_count = 0;
static int sighup_count = 0;
static int sigterm_count = 0;


static void handle_sigint(/*@unused@*/ int sig) { sigint_count = 1; }
static void handle_sigterm(/*@unused@*/ int sig) { sigterm_count = 1; }
static void handle_sighup(/*@unused@*/ int sig) { sighup_count = 1; }

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

int
main(int argc, char *argv[])
{
    Interfaces      interfaces;
    Services        services;
    Zones           zones;
    Rules           rules;
    /* list of ipaddresses to be blocked */
    BlockList       blocklist;

    IptCap          iptcap;

    char            loop = FALSE,
                    nodaemon = FALSE,
                    reload_shm = FALSE,
                    reload_dyn = FALSE;
    /* clear vuurmur/all the iptables rules? */
    char            clear_vuurmuur_rules = FALSE;
    char            clear_all_rules      = FALSE;

    int             retval = 0,
                    optch,
                    result = 0,
                    debuglvl = 0;

    unsigned int    dynamic_wait_time = 0;  /* for checking the dynamic ipaddresses */
    unsigned int    wait_time = 0;          /* time in seconds we have waited for an VR_RR_RESULT_ACK when using SHM-IPC */
    static char optstring[] = "hd:bVlvnc:L:CFDtk";
    struct option prog_opts[] =
    {
        { "help", no_argument, NULL, 'h' },
        { "debug", required_argument, NULL, 'd' },
        { "bash", no_argument, NULL, 'b' },
        { "version", no_argument, NULL, 'V' },
        { "verbose", no_argument, NULL, 'v' },
        { "foreground", no_argument, NULL, 'n' },
        { "configfile", required_argument, NULL, 'c' },
        { "loglevel", required_argument, NULL, 'L' },
        { "clear-vuurmuur", no_argument, NULL, 'C' },
        { "clear-all", no_argument, NULL, 'F' },
        { "daemon", no_argument, NULL, 'D' },
        { "no-check", no_argument, NULL, 't' },
        /* Or maybe use this version *
        { "no-check", no_argument, (int)&conf.check_iptcaps, 0 },
         */
        { "keep", no_argument, NULL, 'k' },
        { 0, 0, 0, 0 },
    };
    int             option_index = 0;
    int             shm_id;
    char            *shmp;
    union semun     semarg;
    ushort          seminit[] = { 1,0 };

    struct rgx_     reg;    // regexes

    snprintf(version_string,sizeof(version_string),"%s (using libvuurmuur %s)", VUURMUUR_VERSION, libvuurmuur_get_version());

    /* get the current user */
    get_user_info(debuglvl, &user_data);

    /* init the print functions: all to stdout */
    vrprint.logger = "vuurmuur";
    vrprint.error = libvuurmuur_stdoutprint_error;
    vrprint.warning = libvuurmuur_stdoutprint_warning;
    vrprint.info = libvuurmuur_stdoutprint_info;
    vrprint.debug = libvuurmuur_stdoutprint_debug;
    vrprint.username = user_data.realusername;
    vrprint.audit = libvuurmuur_stdoutprint_audit;

    /* registering signals we use */
    setup_signal_handler(SIGINT, handle_sigint);
    setup_signal_handler(SIGTERM, handle_sigterm);
    setup_signal_handler(SIGHUP, handle_sighup);

    /* some initilization */
    if(pre_init_config(&conf) < 0)
        exit(EXIT_FAILURE);

    shm_table = NULL;
    sem_id = 0;
    keep_file = FALSE;

    /*  close the STDERR_FILENO because it gives us annoying "Broken
        Pipe" errors on some systems with bash3. */
    close(STDERR_FILENO);

    /* Process commandline options */
    while((optch = getopt_long(argc, argv, optstring, prog_opts,
                    &option_index)) != -1 )
    {
        switch(optch)
        {
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
                debuglvl = atoi(optarg);
                if(debuglvl < 0 || debuglvl > HIGH)
                {
                    fprintf(stdout, "Error: illegal debug level: %d (max: %d).\n", debuglvl, HIGH);
                    exit(EXIT_FAILURE);
                }

                fprintf(stdout, "vuurmuur: debug level: %d\n", debuglvl);
                break;

            case 'L' :

                conf.loglevel_cmdline = TRUE;

                /* loglevel */
                if(strlcpy(conf.loglevel, optarg, sizeof(conf.loglevel)) > sizeof(conf.loglevel))
                {
                    fprintf(stdout, "Error: loglevel (-L): argument too long (max: %d).\n", (int)sizeof(conf.loglevel)-1);
                    exit(EXIT_FAILURE);
                }

                break;

            case 'b' :

                /* bash output */
                conf.bash_out = TRUE;
                fprintf(stdout, "#!/bin/sh\n");
                fprintf(stdout, "# Firewall generated by Vuurmuur %s, "
                        "Copyright (C) 2002-2008 by Victor Julien\n",
                        version_string);

                conf.check_iptcaps = FALSE;
                break;

            case 't' :

                /* no testing of capabilities */
                conf.check_iptcaps = FALSE;
                break;

            case 'h' :

                print_help();
                break;

            case 'V' :

                /* print version */
                fprintf(stdout, "Vuurmuur %s\n", version_string);
                fprintf(stdout, "Copyright (C) 2002-2008 by Victor Julien\n");

                exit(EXIT_SUCCESS);

            case 'l' :
            case 'D' :

                /* looping, daemon mode */
                loop = TRUE;
                break;

            case 'v' :

                /* verbose */
                fprintf(stdout, "verbose output\n");
                conf.verbose_out = TRUE;
                break;

            case 'n' :

                /* dont daemonize */
                fprintf(stdout, "no daemon\n");
                nodaemon = TRUE;
                break;

            case 'C' :

                /* clear vuurmuur rules */
                fprintf(stdout, "Clearing vuurmuur rules...\n");
                clear_vuurmuur_rules = TRUE;
                break;

            case 'F' :

                /* clear all rules */
                fprintf(stdout, "Clearing all rules...\n");
                clear_all_rules = TRUE;
                break;

            case 'k' :

                /* keep rules file */
                fprintf(stdout, "Keeping rulesfiles...\n");
                keep_file = TRUE;
                break;

            default:
                //fprintf(stdout, "Error: unknown option '-%c'. See -h for valid options.\n", optch);
                break;
        }
    }

//TODO: do an options sanity check (eg. bash and loop dont play together)

    /* check if were already running, but not if we want bash output */
    if(conf.bash_out == FALSE)
    {
        if(check_pidfile(PIDFILE) == -1)
            exit(EXIT_FAILURE);
    }

    /*  exit if the user is not root. */
    if(user_data.user > 0 || user_data.group > 0)
    {
        fprintf(stdout, "Error: you are not root! Exitting.\n");
        exit(EXIT_FAILURE);
    }

    /* init the config */
    if(debuglvl >= MEDIUM)
        (void)vrprint.debug(__FUNC__, "initializing config... calling init_config()");

    result = init_config(debuglvl, &conf);
    if(result >= VR_CNF_OK)
    {
        if(debuglvl >= MEDIUM)
            (void)vrprint.debug(__FUNC__, "initializing config complete and succesful.");
    }
    else
    {
        fprintf(stdout, "Initializing config failed.\n");
        exit(EXIT_FAILURE);
    }

    /* dont check in bash mode */
    if(conf.bash_out == FALSE)
    {
        /* check the iptables command */
        if(!check_iptables_command(debuglvl, &conf, conf.iptables_location, IPTCHK_VERBOSE))
        {
            exit(EXIT_FAILURE);
        }
        /* if we are going to use the iptables-restore command, check it */
        if(conf.old_rulecreation_method == FALSE)
        {
            if(!check_iptablesrestore_command(debuglvl, &conf, conf.iptablesrestore_location, IPTCHK_VERBOSE))
            {
                exit(EXIT_FAILURE);
            }
        }
    }


    /* loglevel */
    create_loglevel_string(debuglvl, &conf, loglevel, sizeof(loglevel));
    /* tcp options */
    create_logtcpoptions_string(debuglvl, &conf, log_tcp_options, sizeof(log_tcp_options));

    /* after the config we can remove the rules if we need to */
    if(clear_vuurmuur_rules == TRUE)
    {
        if(clear_vuurmuur_iptables_rules(debuglvl,&conf) < 0)
        {
            fprintf(stdout, "Error: clearing vuumuur iptables rules failed.\n");
            exit(EXIT_FAILURE);
        }

        exit(EXIT_SUCCESS);
    }

    if(clear_all_rules == TRUE)
    {
        if(clear_all_iptables_rules(debuglvl) < 0)
        {
            fprintf(stdout, "Error: clearing all iptables rules failed.\n");
            exit(EXIT_FAILURE);
        }

        exit(EXIT_SUCCESS);
    }


    /* now we know the logfile locations, so init the log functions */
    vrprint.error = libvuurmuur_logprint_error;
    vrprint.warning = libvuurmuur_logprint_warning;
    vrprint.info = libvuurmuur_logprint_info;
    vrprint.debug = libvuurmuur_logprint_debug;
    vrprint.audit = libvuurmuur_logprint_audit;


    /* check capabilities */
    if(conf.check_iptcaps == TRUE)
    {
        if(check_iptcaps(debuglvl, &conf, &iptcap, conf.load_modules) < 0)
        {
            fprintf(stdout, "Error: checking for iptables-capabilities failed. Please see error.log.\n");
            exit(EXIT_FAILURE);
        }
    }
    else
    {
        /* when not using the iptcap clear it just to be sure (and to please splint) */
        memset(&iptcap, 0, sizeof(IptCap));
    }

    /* setup regexes */
    if(setup_rgx(1, &reg) < 0)
    {
        (void)vrprint.error(-1, "Internal Error", "setting up regular expressions failed.");
        exit(EXIT_FAILURE);
    }

    /* load the backends */
    result = load_backends(debuglvl, &PluginList);
    if(result < 0)
    {
        fprintf(stdout, "Error: loading backends failed\n");
        exit(EXIT_FAILURE);
    }

    /* print some nice info about me being the coolest of 'm all ;-) */
    (void)vrprint.info("Info", "This is Vuurmuur %s", version_string);
    (void)vrprint.info("Info", "Copyright (C) 2002-2008 by Victor Julien");
    (void)vrprint.audit("Vuurmuur %s started by user %s.", version_string, user_data.realusername);

    /* set chain couters to zero */
    ipt_rulecount = 0;

    /* load the services into memory */
    result = load_services(debuglvl, &services, &reg);
    if(result == -1)
        exit(EXIT_FAILURE);

    /* load the interfaces into memory */
    result = load_interfaces(debuglvl, &interfaces);
    if(result == -1)
        exit(EXIT_FAILURE);

    /* load the zonedata into memory */
    result = load_zones(debuglvl, &zones, &interfaces, &reg);
    if(result == -1)
        exit(EXIT_FAILURE);


    /* load the blockfile if any */
    /* call it with load_ips == TRUE */
    if(blocklist_init_list(debuglvl, &zones, &blocklist, /*load_ips*/TRUE, /*no_refcnt*/FALSE) < 0)
    {
        (void)vrprint.error(-1, "Error", "blocklist_read_file failed.");
    }


    /* load the rulesfile into memory */
    (void)vrprint.info("Info", "Loading rulesfile...");
    result = rules_init_list(debuglvl, &rules, &reg);
    if(result == 0)
    {
        (void)vrprint.info("Info", "Loading rulesfile succesfull.");
    }
    else
    {
        (void)vrprint.error(-1, "Error", "initializing the rules failed.");
        exit(EXIT_FAILURE);
    }

    /* analyzing the rules */
    if(analyze_all_rules(debuglvl, &rules, &zones, &services, &interfaces) != 0)
    {
        (void)vrprint.error(-1, "Error", "analizing the rules failed.");
        exit(EXIT_FAILURE);
    }

    if(debuglvl >= LOW)
        rules_print_list(&rules);

    /* now create the rules */
    if(conf.old_rulecreation_method == TRUE || conf.bash_out == TRUE)
    {
        /* call with create_prerules == 1 */
        if(create_all_rules(debuglvl, &rules, &zones, &interfaces, &blocklist, &iptcap, &conf, 1) != 0)
        {
            (void)vrprint.error(-1, "Error", "creating rules failed.");
            exit(EXIT_FAILURE);
        }
    }
    else
    {
        if(load_ruleset(debuglvl, &rules, &zones, &interfaces, &services, &blocklist, &iptcap, &conf) < 0)
        {
            (void)vrprint.error(-1, "Error", "creating rules failed.");
            exit(EXIT_FAILURE);
        }
    }

    // ** analyzing and creating rules done ** //


    /* enter the infinite loop... */
    if(loop == TRUE)
    {
        /* if we going to enter the loop, make sure we dont are in bash-mode */
        if(conf.bash_out == FALSE)
        {
            /* leave console */
            if(nodaemon == FALSE)
            {
                if(daemon(1,1) < 0)
                {
                    (void)vrprint.error(-1, "Error", "failed to daemonize: %s.", strerror(errno));
                    exit(EXIT_FAILURE);
                }
                else
                    (void)vrprint.info("Info", "Entered daemon mode: obtained a new PID (%ld).", getpid());
            }

            shm_id = shmget(IPC_PRIVATE, sizeof(*shm_table), 0600);
            if(shm_id < 0)
            {
                (void)vrprint.error(-1, "Error", "unable to create shared memory: %s.", strerror(errno));
                exit(EXIT_FAILURE);
            }
            /* for some reason on my machine the shm_id is zero when vuurmuur is started at boot
               if we sleep for some time and retry it works */
            else if(shm_id == 0)
            {
                /* sleep 3 seconds before trying again */
                (void)sleep(3);

                shm_id = shmget(IPC_PRIVATE, sizeof(*shm_table), 0600);
                if(shm_id < 0)
                {
                    (void)vrprint.error(-1, "Error", "Unable to create shared memory: %s (retry).", strerror(errno));
                    exit(EXIT_FAILURE);
                }
                else if(shm_id == 0)
                {
                    (void)vrprint.info("Info", "Still no valid shm_id. Giving up.");
                }
                else
                {
                    (void)vrprint.info("Info", "Creating shared memory successfull: shm_id: %d (retry).", shm_id);
                }
            }
            else
            {
                (void)vrprint.info("Info", "Creating shared memory successfull: shm_id: %d.", shm_id);
            }

            /* now attach to the shared mem */
            if(shm_id > 0)
            {
                shmp = shmat(shm_id, 0, 0);
                if(shmp == (char *)(-1))
                {
                    (void)vrprint.error(-1, "Error", "unable to attach to shared memory: %s.", strerror(errno));
                    exit(EXIT_FAILURE);
                }
                else
                {
                    shm_table = (struct SHM_TABLE *)shmp;
                    (void)vrprint.info("Info", "Attaching to shared memory successfull.");
                }

                /* if all went well we create a semaphore */
                if(shm_table != NULL)
                {
                    sem_id = semget(IPC_PRIVATE, 2, 0600);
                    if(sem_id == -1)
                    {
                        (void)vrprint.error(-1, "Error", "Unable to create semaphore: %s.", strerror(errno));
                        exit(EXIT_FAILURE);
                    }
                    else
                    {
                        (void)vrprint.info("Info", "Creating a semaphore success: %d", sem_id);
                    }

                    semarg.array = seminit;
                    if(semctl(sem_id, 0, SETALL, semarg) == -1)
                    {
                        (void)vrprint.error(-1, "Error", "Unable to initialize semaphore: %s.", strerror(errno));
                        exit(EXIT_FAILURE);
                    }
                    else
                    {
                        (void)vrprint.info("Info", "Initializeing the semaphore successfull.");
                    }

                    /* now initialize the shared mem */
                    if(LOCK(sem_id))
                    {
                        shm_table->sem_id = sem_id;
                        shm_table->backend_changed = 0;
                        shm_table->reload_result = VR_RR_READY;

                        UNLOCK(sem_id);
                    }
                }
            }

            /* create a pidfile */
            result = create_pidfile(PIDFILE, shm_id);
            if(result < 0)
            {
                (void)vrprint.error(-1, "Error", "Unable to create pidfile.");
/* TODO: is this really that serious? */
                exit(EXIT_FAILURE);
            }

            (void)vrprint.info("Info", "Entering the loop... (interval %d seconds)", LOOP_INT);

            while(retval == 0 &&
                sigint_count == 0 &&
                sigterm_count == 0)
            {
                if(LOCK(sem_id))
                {
                    if(shm_table->configtool.connected == 1)
                    {
                        (void)vrprint.info("Info", "Configtool connected: %s.", shm_table->configtool.name);
                        shm_table->configtool.connected=2;
                    }
                    else if(shm_table->configtool.connected == 3)
                    {
                        (void)vrprint.info("Info", "Configtool disconnected: %s.", shm_table->configtool.name);
                        shm_table->configtool.connected=0;
                    }

                    if(shm_table->backend_changed == TRUE)
                    {
                        (void)vrprint.audit("IPC-SHM: backend changed: reload (user: %s).", shm_table->configtool.username);
                        reload_shm = TRUE;
                        shm_table->backend_changed = FALSE;

                        /* start at 0% */
                        shm_table->reload_progress = FALSE;
                    }

                    UNLOCK(sem_id);
                }

                /*  if we have one or more dynamic interfaces
                    we check if there we're changes.
                */
                if(conf.dynamic_changes_check == TRUE && interfaces.dynamic_interfaces == TRUE)
                {
                    dynamic_wait_time++;

                    if(dynamic_wait_time >= conf.dynamic_changes_interval)
                    {
                        if(debuglvl >= LOW)
                            (void)vrprint.debug(__FUNC__, "check the dynamic ipaddresses.");

                        if(check_for_changed_dynamic_ips(debuglvl, &interfaces))
                        {
                            reload_dyn = TRUE;
                        }

                        dynamic_wait_time = 0;
                    }
                }

                /*  well, we either recieved a SIGHUP or we want to reload trough an IPC command, or we
                    have an interface with a changed ip.
                */
                if(sighup_count > 0 || reload_shm == TRUE || reload_dyn == TRUE)
                {
                    /* apply changes */
                    result = apply_changes(debuglvl, &services, &zones, &interfaces, &rules, &blocklist, &iptcap, &reg);
                    if(result < 0)
                    {
                        (void)vrprint.error(-1, "Error", "applying changes failed.");
                    }

                    /* if we are reloading because of an IPC command, we need to communicate with the caller */
                    if(reload_shm == TRUE)
                    {
                        if(LOCK(sem_id))
                        {
                            /* finished so 100% */
                            shm_table->reload_progress = 100;

                            /* tell the caller about the reload result */
                            if(result < 0)
                            {
                                shm_table->reload_result = VR_RR_ERROR;
                            }
                            else if(result == 0)
                            {
                                shm_table->reload_result = VR_RR_SUCCES;
                            }
                            else
                            {
                                shm_table->reload_result = VR_RR_NOCHANGES;
                            }
                            UNLOCK(sem_id);
                        }
                    
                        (void)vrprint.info("Info", "Waiting for an VR_RR_RESULT_ACK");

                        result = 0;
                        wait_time = 0;

                        /* now wait max 30 seconds for an ACK from the caller */
                        while(result == 0 && wait_time < 30)
                        {
                            if(LOCK(sem_id))
                            {
                                /* ah, we got one */
                                if(shm_table->reload_result == VR_RR_RESULT_ACK)
                                {
                                    shm_table->reload_result = VR_RR_READY;
                                    shm_table->reload_progress = 0;
                                    result = 1;

                                    (void)vrprint.info("Info", "We got an VR_RR_RESULT_ACK!");
                                }
                                UNLOCK(sem_id);
                            }

                            wait_time++;
                            sleep(1);
                        }

                        /* damn, we didn't get one */
                        if(result == 0)
                        {
                            (void)vrprint.info("Info", "We've waited for %d seconds for an VR_RR_RESULT_ACK, but got none. Setting to VR_RR_READY", wait_time);
                            if(LOCK(sem_id))
                            {
                                shm_table->reload_result = VR_RR_READY;
                                shm_table->reload_progress = 0;
                                UNLOCK(sem_id);
                            }
                            else
                            {
                                (void)vrprint.info("Info", "Hmmmm, failed to set to ready. Did the client crash?");
                            }
                        }
                        result = 0;
                    }

                    if(reload_dyn == TRUE)
                    {
                        /* notify vuurmuur_log */
                        send_hup_to_vuurmuurlog(debuglvl);
                    }

                    /* reset */
                    sighup_count = 0;
                    reload_shm = FALSE;
                    reload_dyn = FALSE;
                }

                sleep(LOOP_INT);
            }

            (void)vrprint.info("Info", "Destroying shared memory...");
            if(shmctl(shm_id, IPC_RMID, NULL) < 0)
            {
                (void)vrprint.error(-1, "Error", "destroying shared memory failed: %s.", strerror(errno));
                retval = -1;
            }
            else
            {
                if(debuglvl >= LOW)
                    (void)vrprint.debug(__FUNC__, "shared memory destroyed.");
            }

            /* destroy semaphore */
            if(semctl(sem_id, 0, IPC_RMID, semarg) == -1)
            {
                (void)vrprint.error(-1, "Error", "failed to remove semaphore.");
                retval = -1;
            }

            /* remove the pidfile */
            if(remove_pidfile(PIDFILE) < 0)
            {
                (void)vrprint.error(-1, "Error", "unable to remove pidfile: %s.", strerror(errno));
                retval = -1;
            }

            (void)vrprint.info("Info", "Loop shutting down...");
        }
        else
        {
            fprintf(stdout, "# loop mode not supported when using -b (bash output).\n");
        }
    }

    /* unload the backends */
    result = unload_backends(debuglvl, &PluginList);
    if(result < 0)
    {
        fprintf(stdout, "Error: unloading backends failed.\n");
        exit(EXIT_FAILURE);
    }


    /*
        Destroy the data structures
    */

    /* destroy the ServicesList */
    destroy_serviceslist(debuglvl, &services);

    /* destroy the ZonedataList */
    destroy_zonedatalist(debuglvl, &zones);

    /* destroy the InterfacesList */
    destroy_interfaceslist(debuglvl, &interfaces);

    /* destroy the QuerydataList */
    if(rules_cleanup_list(debuglvl, &rules) < 0)
        retval = -1;

    d_list_cleanup(debuglvl, &blocklist.list);

    /* cleanup regexes */
    (void)setup_rgx(0, &reg);

    if(debuglvl >= HIGH)
        (void)vrprint.debug(__FUNC__, "** end **, return = %d", retval);

    return(retval);
}

static void
print_help(void)
{
    fprintf(stdout, "Usage: vuurmuur [OPTION]\n");
    fprintf(stdout, "\n");
    fprintf(stdout, "Options:\n");
    fprintf(stdout, "-b, --bash\t\tgives a bashscript output\n");
    fprintf(stdout, "-d, --debug\t\tenables debugging (1 low, 3 high)\n");
    fprintf(stdout, "-c, --configfile\tuse the given configfile\n");
    fprintf(stdout, "-h, --help\t\tgives this help\n");
    fprintf(stdout, "-V, --version\t\tgives the version\n");
    fprintf(stdout, "-D, --daemon\t\tvuurmuur starts and goes into daemon-mode.\n");
    fprintf(stdout, "-L, --loglevel\t\tspecify the loglevel for use with syslog.\n");
    fprintf(stdout, "-v, --verbose\t\tverbose mode.\n");
    fprintf(stdout, "-n, --foreground\tfor use with -D, it goes into the loop without daemonizing.\n");
    fprintf(stdout, "-C, --clear-vuurmuur\tclear vuurmuur iptables rules and set policy to ACCEPT. PRE-VRMR-CHAINS still presents. Use with care!\n");
    fprintf(stdout, "-F, --clear-all\t\tclear all iptables rules and set policy to ACCEPT. PRE-VRMR-CHAINS (and others) cleared. Use with care!\n");
    fprintf(stdout, "-k, --keep\t\tkeep the iptables ruleset (tmp)file iptables-restore loads into the system. Useful for debugging. The file can be found in /tmp/\n");
    fprintf(stdout, "-t, --no-check\t\tdon't check for iptables capabilities, asume all are supported.\n");
    fprintf(stdout, "\n");

    exit(EXIT_SUCCESS);
}
