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

#include "main.h"

#include <sys/types.h>
#include <sys/signal.h>

static void print_help(void);

/*
    we put this here, because we only use it here in main.
*/
static int sigint_count = 0;
static int sighup_count = 0;
static int sigterm_count = 0;

static void handle_sigint(/*@unused@*/ int sig ATTR_UNUSED)
{
    sigint_count = 1;
}
static void handle_sigterm(/*@unused@*/ int sig ATTR_UNUSED)
{
    sigterm_count = 1;
}
static void handle_sighup(/*@unused@*/ int sig ATTR_UNUSED)
{
    sighup_count = 1;
}

static void setup_signal_handler(int sig, void (*handler)(int))
{
    struct sigaction action;

    action.sa_handler = handler;
    sigemptyset(&(action.sa_mask));
    sigaddset(&(action.sa_mask), sig);
    action.sa_flags = 0;
    sigaction(sig, &action, 0);
}

/** \brief UP all interfaces in bash mode */
static void bash_enable_interfaces(struct vrmr_interfaces *ifaces)
{
    struct vrmr_list_node *node;
    struct vrmr_interface *iface_ptr = NULL;

    for (node = ifaces->list.top; node != NULL; node = node->next) {
        iface_ptr = (struct vrmr_interface *)node->data;
        if (iface_ptr->up == FALSE)
            iface_ptr->up = TRUE;
    }
}

int main(int argc, char *argv[])
{
    struct vrmr_ctx vctx;

    pid_t pid;
    char reload_shm = FALSE, reload_dyn = FALSE;

    /* clear vuurmur/all the iptables rules? */
    char clear_vuurmuur_rules = FALSE;
    char clear_all_rules = FALSE;

    int retval = 0, optch, result = 0, debug_level = 0;

    unsigned int dynamic_wait_time =
            0;                  /* for checking the dynamic ipaddresses */
    unsigned int wait_time = 0; /* time in seconds we have waited for an
                                   VRMR_RR_RESULT_ACK when using SHM-IPC */
    static char optstring[] = "hd:bVlvnc:L:CFDtkfKX";
    struct option prog_opts[] = {
            {"help", no_argument, NULL, 'h'},
            {"debug", required_argument, NULL, 'd'},
            {"bash", no_argument, NULL, 'b'},
            {"version", no_argument, NULL, 'V'},
            {"verbose", no_argument, NULL, 'v'},
            {"foreground", no_argument, NULL, 'n'},
            {"configfile", required_argument, NULL, 'c'},
            {"loglevel", required_argument, NULL, 'L'},
            {"clear-vuurmuur", no_argument, NULL, 'C'},
            {"killme", no_argument, NULL, 'K'},
            {"clear-all", no_argument, NULL, 'F'},
            {"daemon", no_argument, NULL, 'D'},
            {"no-check", no_argument, NULL, 't'},
            {"keep", no_argument, NULL, 'k'},
            {"force-start", no_argument, NULL, 'f'},
            {0, 0, 0, 0},
    };
    int option_index = 0;
    int shm_id;
    char *shmp;
    union semun semarg;
    ushort seminit[] = {1, 0};

    snprintf(version_string, sizeof(version_string),
            "%s (using libvuurmuur %s)", VUURMUUR_VERSION,
            libvuurmuur_get_version());

    vrmr_init(&vctx, "vuurmuur");

    /* registering signals we use */
    setup_signal_handler(SIGINT, handle_sigint);
    setup_signal_handler(SIGTERM, handle_sigterm);
    setup_signal_handler(SIGHUP, handle_sighup);

    shm_table = NULL;
    sem_id = 0;
    memset(&cmdline, 0, sizeof(cmdline));

    /*  close the STDERR_FILENO because it gives us annoying "Broken
        Pipe" errors on some systems with bash3. */
    // close(STDERR_FILENO);

    /* Process commandline options */
    while ((optch = getopt_long(
                    argc, argv, optstring, prog_opts, &option_index)) != -1) {
        switch (optch) {
            case 'c':

                /* config file */
                if (cmdline.verbose_out == TRUE)
                    fprintf(stdout, "Using this configfile: %s\n", optarg);

                if (strlcpy(cmdline.configfile, optarg,
                            sizeof(cmdline.configfile)) >=
                        sizeof(cmdline.configfile)) {
                    fprintf(stderr,
                            "Error: configfile (-c): argument too long (max: "
                            "%d).\n",
                            (int)sizeof(cmdline.configfile) - 1);
                    exit(EXIT_FAILURE);
                }

                cmdline.configfile_set = TRUE;
                break;

            case 'K':
                vrmr_debug(NONE, "%s asked to stop", SVCNAME);
                if (vrmr_check_pidfile(PIDFILE, &pid) == -1) {
                    printf("%s is running. Killing process %u because of -k\n",
                            SVCNAME, pid);
                    kill(pid, 15);
                    exit(EXIT_SUCCESS);
                }
                break;

            case 'd':

                /* debugging */
                fprintf(stdout, "vuurmuur: debugging enabled.\n");

                /* convert the debug string and check the result */
                debug_level = atoi(optarg);
                if (debug_level < 0 || debug_level > HIGH) {
                    fprintf(stdout,
                            "Error: illegal debug level: %d (max: %d).\n",
                            debug_level, HIGH);
                    exit(EXIT_FAILURE);
                }
                vrmr_debug_level = debug_level;

                fprintf(stdout, "vuurmuur: debug level: %d\n", debug_level);
                break;

            case 'L':

                vctx.conf.loglevel_cmdline = TRUE;

                /* loglevel */
                if (strlcpy(vctx.conf.loglevel, optarg,
                            sizeof(vctx.conf.loglevel)) >
                        sizeof(vctx.conf.loglevel)) {
                    fprintf(stdout,
                            "Error: loglevel (-L): argument too long (max: "
                            "%d).\n",
                            (int)sizeof(vctx.conf.loglevel) - 1);
                    exit(EXIT_FAILURE);
                }

                cmdline.loglevel_set = TRUE;
                break;

            case 'b':

                /* bash output */
                vctx.conf.bash_out = TRUE;
                fprintf(stdout, "#!/bin/sh\n");
                fprintf(stdout, "# Firewall generated by Vuurmuur %s, %s\n",
                        VUURMUUR_COPYRIGHT, version_string);

                cmdline.vrmr_check_iptcaps_set = TRUE;
                cmdline.vrmr_check_iptcaps = FALSE;
                break;

            case 't':

                /* no testing of capabilities */
                cmdline.vrmr_check_iptcaps_set = TRUE;
                cmdline.vrmr_check_iptcaps = FALSE;
                break;

            case 'h':

                print_help();
                break;

            case 'V':

                /* print version */
                fprintf(stdout, "Vuurmuur %s\n", version_string);
                fprintf(stdout, "%s\n", VUURMUUR_COPYRIGHT);

                exit(EXIT_SUCCESS);

            case 'l':
            case 'D':

                /* looping, daemon mode */
                cmdline.loop = TRUE;
                break;

            case 'v':

                /* verbose */
                fprintf(stdout, "verbose output\n");
                cmdline.verbose_out_set = TRUE;
                cmdline.verbose_out = TRUE;
                break;

            case 'n':

                /* dont daemonize */
                fprintf(stdout, "no daemon\n");
                cmdline.nodaemon = TRUE;
                break;

            case 'C':

                /* clear vuurmuur rules */
                fprintf(stdout, "Clearing vuurmuur rules...\n");
                clear_vuurmuur_rules = TRUE;
                break;

            case 'F':

                /* clear all rules */
                fprintf(stdout, "Clearing all rules...\n");
                clear_all_rules = TRUE;
                break;

            case 'k':

                /* keep rules file */
                fprintf(stdout, "Keeping rulesfiles...\n");
                cmdline.keep_file = TRUE;
                break;

            case 'f':

                /* start even if we have no rule (thus locking the
                 * box completely */
                cmdline.force_start = TRUE;
                break;

            default:
                // fprintf(stdout, "Error: unknown option '-%c'. See -h for
                // valid options.\n", optch);
                break;
        }
    }

    // TODO: do an options sanity check (eg. bash and loop dont play together)

    /* check if were already running, but not if we want bash output */
    if (vctx.conf.bash_out == FALSE) {
        if (vrmr_check_pidfile(PIDFILE, &pid) == -1)
            exit(EXIT_FAILURE);
    }

    /*  exit if the user is not root. */
    if (vctx.user_data.user > 0 || vctx.user_data.group > 0) {
        fprintf(stdout, "Error: you are not root! Exitting.\n");
        exit(EXIT_FAILURE);
    }

    /* init the config */
    vrmr_debug(MEDIUM, "initializing config... calling vrmr_init_config()");

    result = vrmr_init_config(&vctx.conf);
    if (result >= VRMR_CNF_OK) {
        vrmr_debug(MEDIUM, "initializing config complete and succesful.");
    } else {
        fprintf(stdout, "Initializing config failed.\n");
        exit(EXIT_FAILURE);
    }

    /* now we know the logfile locations, so init the log functions */
    if (cmdline.verbose_out) {
        vrprint.error = vrmr_logstdoutprint_error;
        vrprint.warning = vrmr_logstdoutprint_warning;
        vrprint.info = vrmr_logstdoutprint_info;
    } else if (vctx.conf.bash_out) {
        vrprint.error = logprint_error_bash;
        vrprint.warning = logprint_warning_bash;
        vrprint.info = logprint_info_bash;
    } else {
        vrprint.error = vrmr_logprint_error;
        vrprint.warning = vrmr_logprint_warning;
        vrprint.info = vrmr_logprint_info;
    }
    vrprint.debug = vrmr_logprint_debug;
    vrprint.audit = vrmr_logprint_audit;

    /* commandline vars overriding the config */
    cmdline_override_config(&vctx.conf);

    /* dont check in bash mode */
    if (vctx.conf.bash_out == FALSE) {
        /* check the iptables command */
        if (!vrmr_check_iptables_command(&vctx.conf,
                    vctx.conf.iptables_location, VRMR_IPTCHK_VERBOSE)) {
            exit(EXIT_FAILURE);
        }
#ifdef IPV6_ENABLED
        if (!vrmr_check_ip6tables_command(&vctx.conf,
                    vctx.conf.ip6tables_location, VRMR_IPTCHK_VERBOSE)) {
            exit(EXIT_FAILURE);
        }
#endif
        /* if we are going to use the iptables-restore command, check it */
        if (vctx.conf.old_rulecreation_method == FALSE) {
            if (!vrmr_check_iptablesrestore_command(&vctx.conf,
                        vctx.conf.iptablesrestore_location,
                        VRMR_IPTCHK_VERBOSE)) {
                exit(EXIT_FAILURE);
            }
#ifdef IPV6_ENABLED
            if (!vrmr_check_ip6tablesrestore_command(&vctx.conf,
                        vctx.conf.ip6tablesrestore_location,
                        VRMR_IPTCHK_VERBOSE)) {
                exit(EXIT_FAILURE);
            }
#endif
        }
    }

    /* tcp options */
    create_logtcpoptions_string(
            &vctx.conf, log_tcp_options, sizeof(log_tcp_options));

    /* after the config we can remove the rules if we need to */
    if (clear_vuurmuur_rules == TRUE) {
        if (clear_vuurmuur_iptables_rules(&vctx.conf) < 0) {
            fprintf(stdout, "Error: clearing vuumuur iptables rules failed.\n");
            exit(EXIT_FAILURE);
        }

        exit(EXIT_SUCCESS);
    }

    if (clear_all_rules == TRUE) {
        if (clear_all_iptables_rules(&vctx.conf) < 0) {
            fprintf(stdout, "Error: clearing all iptables rules failed.\n");
            exit(EXIT_FAILURE);
        }

        exit(EXIT_SUCCESS);
    }

    /* check capabilities */
    if (vctx.conf.vrmr_check_iptcaps == TRUE) {
        if (vrmr_check_iptcaps(
                    &vctx.conf, &vctx.iptcaps, vctx.conf.load_modules) < 0) {
            fprintf(stdout, "Error: checking for iptables-capabilities failed. "
                            "Please see error.log.\n");
            exit(EXIT_FAILURE);
        }
#ifdef IPV6_ENABLED
        if (vrmr_check_ip6tcaps(
                    &vctx.conf, &vctx.iptcaps, vctx.conf.load_modules) < 0) {
            if (vctx.conf.check_ipv6 == TRUE) {
                fprintf(stdout, "Error: checking for ip6tables-capabilities "
                                "failed. Please see error.log.\n");
                exit(EXIT_FAILURE);
            }
        }
#endif
    } else {
        /* when not using the iptcap clear it just to be sure (and to please
         * splint) */
        memset(&vctx.iptcaps, 0, sizeof(struct vrmr_iptcaps));
    }

    /* load the backends */
    result = vrmr_backends_load(&vctx.conf, &vctx);
    if (result < 0) {
        fprintf(stdout, "Error: loading backends failed\n");
        exit(EXIT_FAILURE);
    }

    vrmr_info("Info", "Vuurmuur %s", version_string);
    vrmr_info("Info", "%s", VUURMUUR_COPYRIGHT);
    vrmr_audit("Vuurmuur %s started by user %s.", version_string,
            vctx.user_data.realusername);

    /* set chain couters to zero */
    ipt_rulecount = 0;

    /* load the services into memory */
    result = vrmr_services_load(&vctx, &vctx.services, &vctx.reg);
    if (result == -1)
        exit(EXIT_FAILURE);

    /* load the interfaces into memory */
    result = vrmr_interfaces_load(&vctx, &vctx.interfaces);
    if (result == -1)
        exit(EXIT_FAILURE);
    if (vctx.conf.bash_out) {
        bash_enable_interfaces(&vctx.interfaces);
    }

    /* load the zonedata into memory */
    result = vrmr_zones_load(&vctx, &vctx.zones, &vctx.interfaces, &vctx.reg);
    if (result == -1)
        exit(EXIT_FAILURE);

    /* load the blockfile if any */
    /* call it with load_ips == TRUE */
    if (vrmr_blocklist_init_list(&vctx, &vctx.conf, &vctx.zones,
                &vctx.blocklist, /*load_ips*/ TRUE, /*no_refcnt*/ FALSE) < 0) {
        vrmr_error(-1, "Error", "blocklist_read_file failed.");
    }

    /* load the rulesfile into memory */
    vrmr_info("Info", "Loading rulesfile...");
    result = vrmr_rules_init_list(&vctx, &vctx.conf, &vctx.rules, &vctx.reg);
    if (result == 0) {
        vrmr_info("Info", "Loading rulesfile succesfull.");
    } else {
        vrmr_error(-1, "Error", "initializing the rules failed.");
        exit(EXIT_FAILURE);
    }

    /* Check if we have rules. If not we won't start unless we are forced to. */
    if (vctx.rules.list.len == 0 && cmdline.force_start == FALSE) {
        vrmr_error(-1, "Error",
                "no rules defined, Vuurmuur will not start "
                "to prevent you from locking yourself out. Override by "
                "supplying "
                "--force-start on the commandline.");
        exit(EXIT_FAILURE);
    }

    /* analyzing the rules */
    if (analyze_all_rules(&vctx, &vctx.rules) != 0) {
        vrmr_error(-1, "Error", "analizing the rules failed.");
        exit(EXIT_FAILURE);
    }

    if (vrmr_debug_level >= LOW)
        vrmr_rules_print_list(&vctx.rules);

    /* now create the rules */
    if (vctx.conf.old_rulecreation_method == TRUE ||
            vctx.conf.bash_out == TRUE) {
        /* call with create_prerules == 1 */
        if (create_all_rules(&vctx, 1) != 0) {
            vrmr_error(-1, "Error", "creating rules failed.");
            exit(EXIT_FAILURE);
        }
    } else {
        if (load_ruleset(&vctx) < 0) {
            vrmr_error(-1, "Error", "creating rules failed.");
            exit(EXIT_FAILURE);
        }
    }

    // ** analyzing and creating rules done ** //

    /* enter the infinite loop... */
    if (cmdline.loop == TRUE) {
        /* if we going to enter the loop, make sure we dont are in bash-mode */
        if (vctx.conf.bash_out == FALSE) {
            /* leave console */
            if (cmdline.nodaemon == FALSE) {
                if (daemon(1, 1) < 0) {
                    vrmr_error(-1, "Error", "failed to daemonize: %s.",
                            strerror(errno));
                    exit(EXIT_FAILURE);
                } else
                    vrmr_info("Info",
                            "Entered daemon mode: obtained a new PID (%d).",
                            getpid());
            }

            shm_id = shmget(IPC_PRIVATE, sizeof(*shm_table), 0600);
            if (shm_id < 0) {
                vrmr_error(-1, "Error", "unable to create shared memory: %s.",
                        strerror(errno));
                exit(EXIT_FAILURE);
            }
            /* for some reason on my machine the shm_id is zero when vuurmuur is
               started at boot if we sleep for some time and retry it works */
            else if (shm_id == 0) {
                /* sleep 3 seconds before trying again */
                (void)sleep(3);

                shm_id = shmget(IPC_PRIVATE, sizeof(*shm_table), 0600);
                if (shm_id < 0) {
                    vrmr_error(-1, "Error",
                            "Unable to create shared memory: %s (retry).",
                            strerror(errno));
                    exit(EXIT_FAILURE);
                } else if (shm_id == 0) {
                    vrmr_info("Info", "Still no valid shm_id. Giving up.");
                } else {
                    vrmr_info("Info",
                            "Creating shared memory successfull: shm_id: %d "
                            "(retry).",
                            shm_id);
                }
            } else {
                vrmr_info("Info",
                        "Creating shared memory successfull: shm_id: %d.",
                        shm_id);
            }

            /* now attach to the shared mem */
            if (shm_id > 0) {
                shmp = shmat(shm_id, 0, 0);
                if (shmp == (char *)(-1)) {
                    vrmr_error(-1, "Error",
                            "unable to attach to shared memory: %s.",
                            strerror(errno));
                    exit(EXIT_FAILURE);
                } else {
                    shm_table = (struct vrmr_shm_table *)shmp;
                    vrmr_info(
                            "Info", "Attaching to shared memory successfull.");
                }

                /* if all went well we create a semaphore */
                if (shm_table != NULL) {
                    sem_id = semget(IPC_PRIVATE, 2, 0600);
                    if (sem_id == -1) {
                        vrmr_error(-1, "Error",
                                "Unable to create semaphore: %s.",
                                strerror(errno));
                        exit(EXIT_FAILURE);
                    } else {
                        vrmr_info("Info", "Creating a semaphore success: %d",
                                sem_id);
                    }

                    semarg.array = seminit;
                    if (semctl(sem_id, 0, SETALL, semarg) == -1) {
                        vrmr_error(-1, "Error",
                                "Unable to initialize semaphore: %s.",
                                strerror(errno));
                        exit(EXIT_FAILURE);
                    } else {
                        vrmr_info("Info",
                                "Initializeing the semaphore successfull.");
                    }

                    /* now initialize the shared mem */
                    if (vrmr_lock(sem_id)) {
                        shm_table->sem_id = sem_id;
                        shm_table->backend_changed = 0;
                        shm_table->reload_result = VRMR_RR_READY;

                        vrmr_unlock(sem_id);
                    }
                }
            }

            /* create a pidfile */
            result = vrmr_create_pidfile(PIDFILE, shm_id);
            if (result < 0) {
                vrmr_error(-1, "Error", "Unable to create pidfile.");
                /* TODO: is this really that serious? */
                exit(EXIT_FAILURE);
            }

            vrmr_info("Info", "Entering the loop... (interval %d seconds)",
                    LOOP_INT);

            while (retval == 0 && sigint_count == 0 && sigterm_count == 0) {
                if (vrmr_lock(sem_id)) {
                    if (shm_table->configtool.connected == 1) {
                        vrmr_info("Info", "Configtool connected: %s.",
                                shm_table->configtool.name);
                        shm_table->configtool.connected = 2;
                    } else if (shm_table->configtool.connected == 3) {
                        vrmr_info("Info", "Configtool disconnected: %s.",
                                shm_table->configtool.name);
                        shm_table->configtool.connected = 0;
                    }

                    if (shm_table->backend_changed == TRUE) {
                        vrmr_audit(
                                "IPC-SHM: backend changed: reload (user: %s).",
                                shm_table->configtool.username);
                        reload_shm = TRUE;
                        shm_table->backend_changed = FALSE;

                        /* start at 0% */
                        shm_table->reload_progress = FALSE;
                    }

                    vrmr_unlock(sem_id);
                }

                /*  if we have one or more dynamic interfaces
                    we check if there we're changes.
                */
                if (vctx.conf.dynamic_changes_check == TRUE &&
                        vctx.interfaces.dynamic_interfaces == TRUE) {
                    dynamic_wait_time++;

                    if (dynamic_wait_time >=
                            vctx.conf.dynamic_changes_interval) {
                        vrmr_debug(LOW, "check the dynamic ipaddresses.");

                        if (check_for_changed_dynamic_ips(&vctx.interfaces)) {
                            reload_dyn = TRUE;
                        }

                        dynamic_wait_time = 0;
                    }
                }

                /*  well, we either recieved a SIGHUP or we want to reload
                   trough an IPC command, or we have an interface with a changed
                   ip.
                */
                if (sighup_count > 0 || reload_shm == TRUE ||
                        reload_dyn == TRUE) {
                    /* apply changes */
                    result = apply_changes(&vctx, &vctx.reg);
                    if (result < 0) {
                        vrmr_error(-1, "Error", "applying changes failed.");
                    }

                    /* if we are reloading because of an IPC command, we need to
                     * communicate with the caller */
                    if (reload_shm == TRUE) {
                        if (vrmr_lock(sem_id)) {
                            /* finished so 100% */
                            shm_table->reload_progress = 100;

                            /* tell the caller about the reload result */
                            if (result < 0) {
                                shm_table->reload_result = VRMR_RR_ERROR;
                            } else if (result == 0) {
                                shm_table->reload_result = VRMR_RR_SUCCES;
                            } else {
                                shm_table->reload_result = VRMR_RR_NOCHANGES;
                            }
                            vrmr_unlock(sem_id);
                        }

                        vrmr_info("Info", "Waiting for an VRMR_RR_RESULT_ACK");

                        result = 0;
                        wait_time = 0;

                        /* now wait max 30 seconds for an ACK from the caller */
                        while (result == 0 && wait_time < 30) {
                            if (vrmr_lock(sem_id)) {
                                /* ah, we got one */
                                if (shm_table->reload_result ==
                                        VRMR_RR_RESULT_ACK) {
                                    shm_table->reload_result = VRMR_RR_READY;
                                    shm_table->reload_progress = 0;
                                    result = 1;

                                    vrmr_info("Info",
                                            "We got an VRMR_RR_RESULT_ACK!");
                                }
                                vrmr_unlock(sem_id);
                            }

                            wait_time++;
                            sleep(1);
                        }

                        /* damn, we didn't get one */
                        if (result == 0) {
                            vrmr_info("Info",
                                    "We've waited for %d seconds for an "
                                    "VRMR_RR_RESULT_ACK, but got none. Setting "
                                    "to VRMR_RR_READY",
                                    wait_time);
                            if (vrmr_lock(sem_id)) {
                                shm_table->reload_result = VRMR_RR_READY;
                                shm_table->reload_progress = 0;
                                vrmr_unlock(sem_id);
                            } else {
                                vrmr_info("Info",
                                        "Hmmmm, failed to set to "
                                        "ready. Did the client crash?");
                            }
                        }
                    }

                    if (reload_dyn == TRUE) {
                        /* notify vuurmuur_log */
                        send_hup_to_vuurmuurlog();
                    }

                    /* reset */
                    sighup_count = 0;
                    reload_shm = FALSE;
                    reload_dyn = FALSE;
                }

                sleep(LOOP_INT);
            }

            if (sigint_count || sigterm_count)
                vrmr_debug(NONE, "killed by INT or TERM");

            vrmr_info("Info", "Destroying shared memory...");
            if (shmctl(shm_id, IPC_RMID, NULL) < 0) {
                vrmr_error(-1, "Error", "destroying shared memory failed: %s.",
                        strerror(errno));
                retval = -1;
            } else {
                vrmr_debug(MEDIUM, "shared memory destroyed.");
            }

            /* destroy semaphore */
            if (semctl(sem_id, 0, IPC_RMID, semarg) == -1) {
                vrmr_error(-1, "Error", "failed to remove semaphore.");
                retval = -1;
            }

            /* remove the pidfile */
            if (vrmr_remove_pidfile(PIDFILE) < 0) {
                vrmr_error(-1, "Error", "unable to remove pidfile: %s.",
                        strerror(errno));
                retval = -1;
            }

            vrmr_info("Info", "Loop shutting down...");
        } else {
            fprintf(stdout,
                    "# loop mode not supported when using -b (bash output).\n");
        }
    }

    /* unload the backends */
    result = vrmr_backends_unload(&vctx.conf, &vctx);
    if (result < 0) {
        fprintf(stdout, "Error: unloading backends failed.\n");
        exit(EXIT_FAILURE);
    }

    /*
        Destroy the data structures
    */

    /* destroy the ServicesList */
    vrmr_destroy_serviceslist(&vctx.services);

    /* destroy the ZonedataList */
    vrmr_destroy_zonedatalist(&vctx.zones);

    /* destroy the InterfacesList */
    vrmr_destroy_interfaceslist(&vctx.interfaces);

    /* destroy the QuerydataList */
    if (vrmr_rules_cleanup_list(&vctx.rules) < 0)
        retval = -1;

    vrmr_list_cleanup(&vctx.blocklist.list);

    vrmr_deinit(&vctx);

    vrmr_debug(MEDIUM, "** end **, return = %d", retval);
    return (retval);
}

static void print_help(void)
{
    fprintf(stdout, "Usage: vuurmuur [OPTION]\n");
    fprintf(stdout, "\n");
    fprintf(stdout, "Options:\n");
    fprintf(stdout, "-b, --bash\t\tgives a bashscript output\n");
    fprintf(stdout, "-d, --debug\t\tenables debugging (1 low, 3 high)\n");
    fprintf(stdout, "-c, --configfile\tuse the given configfile\n");
    fprintf(stdout, "-h, --help\t\tgives this help\n");
    fprintf(stdout, "-V, --version\t\tgives the version\n");
    fprintf(stdout, "-l\t\t\tdeprecated version of the -D option\n");
    fprintf(stdout,
            "-D, --daemon\t\tvuurmuur starts and goes into daemon-mode.\n");
    fprintf(stdout,
            "-L, --loglevel\t\tspecify the loglevel for use with syslog.\n");
    fprintf(stdout, "-K, --killme\t\tkill running daemon.\n");
    fprintf(stdout, "-v, --verbose\t\tverbose mode.\n");
    fprintf(stdout, "-n, --foreground\tfor use with -D, it goes into the loop "
                    "without daemonizing.\n");
    fprintf(stdout, "-C, --clear-vuurmuur\tclear vuurmuur iptables rules and "
                    "set policy to ACCEPT. PRE-VRMR-CHAINS still presents. Use "
                    "with care!\n");
    fprintf(stdout,
            "-F, --clear-all\t\tclear all iptables rules and set policy to "
            "ACCEPT. PRE-VRMR-CHAINS (and others) cleared. Use with care!\n");
    fprintf(stdout, "-k, --keep\t\tkeep the iptables ruleset (tmp)file "
                    "iptables-restore loads into the system. Useful for "
                    "debugging. The file can be found in /tmp/\n");
    fprintf(stdout, "-t, --no-check\t\tdon't check for iptables capabilities, "
                    "asume all are supported.\n");
    fprintf(stdout, "-f, --force-start\toverride the test that prevents "
                    "Vuurmuur from starting when no rules are present\n");
    fprintf(stdout, "\n");

    exit(EXIT_SUCCESS);
}
