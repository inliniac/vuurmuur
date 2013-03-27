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
 
#include "vuurmuur_script.h"


/* we put this here, because we only use it here in main. */
static char sigint_recv = FALSE;
static char sighup_recv = FALSE;
static void catch_sigint(/*@unused@*/ int signo) { sigint_recv = TRUE; }
static void catch_sighup(/*@unused@*/ int signo) { sighup_recv = TRUE; }


int
main(int argc, char *argv[])
{
    int             retval = 0,
                    result = 0,
                    debuglvl = 0;
    VuurmuurScript  vr_script;

    static char     optstring[] = "CRDMPLB:AOo:g:n:z:s:i:r:V:S:hc:d:v";
    static int      version_flag = 0;
    static int      apply_flag = 0;
    static int      no_apply_flag = 0;
    static int      reload_flag = 0;
    static int      print_linenum_flag = 0;
    char            tmp_set[sizeof(vr_script.set)] = "";
    char            *str = NULL;

    static struct option long_options[] =
    {
        /* commands */
        {"create",      0, NULL, 'C'},
        {"delete",      0, NULL, 'D'},
        {"rename",      0, NULL, 'R'},
        {"modify",      0, NULL, 'M'},
        {"print",       0, NULL, 'P'},
        {"list",        0, NULL, 'L'},

        {"block",       1, NULL, 0},
        {"unblock",     1, NULL, 0},
        {"list-blocked",0, NULL, 0},
        {"list-paths",  0, NULL, 0},

        /* object name */
        {"variable",    1, NULL, 'V'},
        {"set",         1, NULL, 'S'},

        {"append",      0, NULL, 'A'},
        {"overwrite",   0, NULL, 'O'},

        /* object types */
        {"host",        1, NULL, 'o'},  /* h we use for help */
        {"group",       1, NULL, 'g'},
        {"network",     1, NULL, 'n'},
        {"zone",        1, NULL, 'z'},
        {"service",     1, NULL, 's'},
        {"interface",   1, NULL, 'i'},
        {"rule",        1, NULL, 'r'},

        /* options */
        {"apply",       0, &apply_flag, 1},
        {"no-apply",    0, &no_apply_flag, 1},
        {"reload",      0, &reload_flag, 1},

        /* print options */
        {"rule-numbers",0, &print_linenum_flag, 1},

        {"verbose",     0, NULL, 'v'},
        {"debug",       0, NULL, 'd'},
        {"version",     0, &version_flag, 1},
        {"help",        0, NULL, 'h'},
        {NULL,          0, NULL, 0}
    };
    int opt = 0,
        longopt_index = 0;

    /* initialize our central data structure */
    memset(&vr_script, 0, sizeof(vr_script));
    vr_script.overwrite = TRUE;

    /* get the current user */
    get_user_info(debuglvl, &user_data);

    /*  exit if the user is not root. */
    if(user_data.user > 0 || user_data.group > 0)
    {
        fprintf(stdout, "Error: you are not root! Exitting.\n");
        exit(VRS_ERR_COMMANDLINE);
    }

    /* assemble version string */
    snprintf(version_string, sizeof(version_string), "%s (using libvuurmuur %s)", VUURMUUR_VERSION, libvuurmuur_get_version());

    /* init the print functions: all to stdout */
    vrprint.logger = "vuurmuur_scrp";
    vrprint.error = libvuurmuur_stdoutprint_error;
    vrprint.warning = libvuurmuur_stdoutprint_warning;
    vrprint.info = libvuurmuur_stdoutprint_info;
    vrprint.debug = libvuurmuur_stdoutprint_debug;
    vrprint.username = user_data.realusername;
    vrprint.audit = libvuurmuur_stdoutprint_audit;

    /* registering signals we use */
    if(signal(SIGINT, &catch_sigint) == SIG_ERR)
    {
        fprintf(stdout, "Error: couldn't attach the signal SIGINT to the signal handler.\n");
        exit(VRS_ERR_INTERNAL);
    }
    if(signal(SIGHUP, &catch_sighup) == SIG_ERR)
    {
        fprintf(stdout, "Error: couldn't attach the signal SIGHUP to the signal handler.\n");
        exit(VRS_ERR_INTERNAL);
    }

    /* handle commandline options that don't require a config so they can be
     * used by the wizard. */
    if (argc > 1 && strcmp(argv[1], "--list-devices") == 0) {
        script_list_devices(debuglvl);
        exit(EXIT_SUCCESS);
    }

    /* some initilization */
    if(pre_init_config(&conf) < 0)
        exit(VRS_ERR_INTERNAL);

    /* prepare for later shm connection */
    shm_table = NULL;
    sem_id = 0;

    /* Process commandline options */
    longopt_index = 0;
    optind = 0; /* reset optind */
    while((opt = getopt_long(argc, argv, optstring, long_options, &longopt_index)) >= 0)
    {
        switch(opt)
        {
            /* first handle the longoption only options */
            case 0:
                /* If this option set a flag, do nothing else now. */

                if(long_options[longopt_index].flag != NULL)
                    break;
                if(strcmp(long_options[longopt_index].name, "block") == 0)
                {
                    /* block
                     *
                     * usage is vuurmuur_script --block 1.2.3.4
                     * this means we have to add a rule to the blocklist like this:
                     * vuurmuur_script -M -r blocklist -V RULE --set "block 1.2.3.4" --append --apply
                     */
                    vr_script.cmd = CMD_BLK;    /* we will change this to -M later */

                    /* -V RULE */
                    if(strlcpy(vr_script.var, "RULE", sizeof(vr_script.var)) >= sizeof(vr_script.var))
                    {
                        (void)vrprint.error(VRS_ERR_COMMANDLINE, VR_ERR,
                                "could not set variable: internal argument 'RULE' too long (max: %d).",
                                (int)sizeof(vr_script.var)-1);
                        exit(VRS_ERR_COMMANDLINE);
                    }

                    /* --set "block 1.2.3.4" */
                    if(snprintf(tmp_set, sizeof(tmp_set), "block %s", optarg) >= (int)sizeof(tmp_set))
                    {
                        (void)vrprint.error(VRS_ERR_COMMANDLINE, VR_ERR,
                                "could not set ip address: argument too long (max: %d).",
                                (int)sizeof(tmp_set)-1);
                        exit(VRS_ERR_COMMANDLINE);
                    }
                    if(strlcpy(vr_script.set, tmp_set, sizeof(vr_script.set)) >= sizeof(vr_script.set))
                    {
                        (void)vrprint.error(VRS_ERR_COMMANDLINE, VR_ERR,
                                "could not set ip address: argument too long (max: %d).",
                                (int)sizeof(vr_script.set)-1);
                        exit(VRS_ERR_COMMANDLINE);
                    }

                    /* -r blocklist */
                    vr_script.type = TYPE_RULE;

                    if(strlcpy(vr_script.name, "blocklist", sizeof(vr_script.name)) >= sizeof(vr_script.name))
                    {
                        (void)vrprint.error(VRS_ERR_COMMANDLINE, VR_ERR,
                                "rule (-r/--rule): internal argument too long (max: %d).",
                                (int)sizeof(vr_script.name)-1);
                        exit(VRS_ERR_COMMANDLINE);
                    }

                    /* --apply */
                    vr_script.apply = TRUE;
                }
                else if(strcmp(long_options[longopt_index].name, "unblock") == 0)
                {
                    /* unblock an ip
                     * more difficult than blocking... for the logic see script_unblock.c!
                     */
                    vr_script.cmd = CMD_UBL;

                    if(strlcpy(vr_script.set, optarg, sizeof(vr_script.set)) >= sizeof(vr_script.set))
                    {
                        (void)vrprint.error(VRS_ERR_COMMANDLINE, VR_ERR,
                            "could not set object to unblock: argument too long (max: %d).",
                            (int)sizeof(vr_script.set)-1);
                        exit(VRS_ERR_COMMANDLINE);
                    }

                    vr_script.type = TYPE_RULE;

                    /* --apply */
                    vr_script.apply = TRUE;
                    break;
                }
                else if(strcmp(long_options[longopt_index].name, "list-blocked") == 0)
                {
                    vr_script.type = TYPE_RULE;
                    vr_script.cmd = CMD_LBL;
                    break;
                }
                else if(strcmp(long_options[longopt_index].name, "list-paths") == 0)
                {
                    printf("SYSCONFDIR %s\n", conf.etcdir);
                    printf("VUURMUURCONFDIR %s/vuurmuur\n", conf.etcdir);
                    printf("CONFIGFILE %s\n", conf.configfile);
                    printf("PLUGINDIR %s\n", conf.plugdir);
                    printf("DATADIR %s\n", conf.datadir);
                    exit(EXIT_SUCCESS);
                }
                else
                {
                    (void)vrprint.error(VRS_ERR_COMMANDLINE, VR_ERR,
                        "unknown option '%s'. See --help for valid options.",
                        long_options[longopt_index].name);
                    exit(VRS_ERR_COMMANDLINE);
                }
                break;

            case 'c' :

                /* config file */
                if(conf.verbose_out == TRUE)
                    fprintf(stdout, "Using this configfile: %s\n", optarg);

                if(strlcpy(conf.configfile, optarg, sizeof(conf.configfile)) >= sizeof(conf.configfile))
                {
                    (void)vrprint.error(VRS_ERR_COMMANDLINE, VR_ERR, "configfile (-c): argument too long (max: %d).", (int)sizeof(conf.configfile)-1);
                    exit(VRS_ERR_COMMANDLINE);
                }
                break;

            case 'd' :

                /* debugging */
                fprintf(stdout, "vuurmuur: debugging enabled.\n");

                /* convert the debug string and check the result */
                debuglvl = atoi(optarg);
                if(debuglvl < 0 || debuglvl > HIGH)
                {
                    (void)vrprint.error(VRS_ERR_COMMANDLINE, VR_ERR, "illegal debug level: %d (max: %d)", debuglvl, HIGH);
                    exit(VRS_ERR_COMMANDLINE);
                }

                fprintf(stdout, "vuurmuur: debug level: %d\n", debuglvl);
                break;


            case '?' :
            case 'h' :

                /* help */
                fprintf(stdout, "Usage: vuurmuur_script [OPTIONS]\n");
                fprintf(stdout, "\n");
                fprintf(stdout, "Options:\n");
                fprintf(stdout, " -d [1 - 3]\t\t\tenables debugging, 1 low, 3 high\n");
                fprintf(stdout, " -h, --help\t\t\tgives this help\n");
                fprintf(stdout, " -v, --verbose\t\t\tverbose mode.\n");
                fprintf(stdout, "\n");

                fprintf(stdout, "Commands:\n");
                fprintf(stdout, "     --block <name>\t\tblock host/group or ipaddress.\n");
                fprintf(stdout, "     --unblock <name>\t\tunblock host/group or ipaddress.\n");
                fprintf(stdout, "     --list-blocked\t\tlist the hosts/group and ipaddresses that are blocked.\n");
                fprintf(stdout, "     --reload\t\t\tmake Vuurmuur reload it's config\n");
                fprintf(stdout, "\n");
                fprintf(stdout, " -C, --create\t\t\tcreate object.\n");
                fprintf(stdout, " -D, --delete\t\t\tdelete object.\n");
                fprintf(stdout, " -R, --rename\t\t\trename object.\n");
                fprintf(stdout, " -M, --modify\t\t\tmodify object.\n");
                fprintf(stdout, " -L, --list  \t\t\tlist objects.\n");
                fprintf(stdout, " -P, --print \t\t\tprint data of object.\n");
                fprintf(stdout, "\n");

                fprintf(stdout, "Object:\n");
                fprintf(stdout, " -o, --host <name>\t\thost.\n");
                fprintf(stdout, " -g, --group <name>\t\tgroup.\n");
                fprintf(stdout, " -n, --network <name>\t\tnetwork.\n");
                fprintf(stdout, " -z, --zone <name>\t\tzone.\n");
                fprintf(stdout, " -s, --service <name>\t\tservice.\n");
                fprintf(stdout, " -i, --interface <name>\t\tinterface.\n");
                fprintf(stdout, " -r, --rule <name>\t\trule.\n");
                fprintf(stdout, "\n");

                fprintf(stdout, " -V, --variable <variable>\tvariable to modify/print.\n");
                fprintf(stdout, " -S, --set <value>\t\tvalue to set on modify,\n");
                fprintf(stdout, "                  \t\tor new name when renaming.\n");
                fprintf(stdout, "\n");

                fprintf(stdout, " -A, --append\t\t\tappend the variable on modify\n");
                fprintf(stdout, " -O, --overwrite\t\toverwrite the variable on modify\n");
                fprintf(stdout, "\n");

                fprintf(stdout, "     --rule-numbers\t\tprint rule numbers\n");
                fprintf(stdout, "     --apply\t\t\ttry to apply the changes directly to Vuurmuur\n");
                fprintf(stdout, "     --no-apply\t\t\tdon't try to apply the changes to Vuurmuur\n");

                fprintf(stdout, "\n");

                exit(EXIT_SUCCESS);

            case 'v' :

                /* verbose */
                conf.verbose_out = TRUE;
                break;

            case 'C' :
                vr_script.cmd = CMD_ADD;
                break;
            case 'D' :
                vr_script.cmd = CMD_DEL;
                break;
            case 'R' :
                vr_script.cmd = CMD_REN;
                break;
            case 'M' :
                vr_script.cmd = CMD_MOD;
                break;
            case 'P' :
                vr_script.cmd = CMD_PRT;
                break;
            case 'L' :
                vr_script.cmd = CMD_LST;
                break;

            case 'o' :  /* host */

                vr_script.type = TYPE_HOST;

                if(strlcpy(vr_script.name, optarg, sizeof(vr_script.name)) >= sizeof(vr_script.name))
                {
                    (void)vrprint.error(VRS_ERR_COMMANDLINE, VR_ERR, "host (-o/--host): argument too long (max: %d).", (int)sizeof(vr_script.name)-1);
                    exit(VRS_ERR_COMMANDLINE);
                }
                break;

            case 'g' :  /* group */

                vr_script.type = TYPE_GROUP;

                if(strlcpy(vr_script.name, optarg, sizeof(vr_script.name)) >= sizeof(vr_script.name))
                {
                    (void)vrprint.error(VRS_ERR_COMMANDLINE, VR_ERR, "group (-g/--group): argument too long (max: %d).", (int)sizeof(vr_script.name)-1);
                    exit(VRS_ERR_COMMANDLINE);
                }
                break;

            case 'n' :  /* network */

                vr_script.type = TYPE_NETWORK;

                if(strlcpy(vr_script.name, optarg, sizeof(vr_script.name)) >= sizeof(vr_script.name))
                {
                    (void)vrprint.error(VRS_ERR_COMMANDLINE, VR_ERR, "network (-n/--network): argument too long (max: %d).", (int)sizeof(vr_script.name)-1);
                    exit(VRS_ERR_COMMANDLINE);
                }
                break;

            case 'z' :  /* zone */

                vr_script.type = TYPE_ZONE;

                if(strlcpy(vr_script.name, optarg, sizeof(vr_script.name)) >= sizeof(vr_script.name))
                {
                    (void)vrprint.error(VRS_ERR_COMMANDLINE, VR_ERR, "zone (-z/--zone): argument too long (max: %d).", (int)sizeof(vr_script.name)-1);
                    exit(VRS_ERR_COMMANDLINE);
                }
                break;

            case 's' :  /* service */

                vr_script.type = TYPE_SERVICE;

                if(strlcpy(vr_script.name, optarg, sizeof(vr_script.name)) >= sizeof(vr_script.name))
                {
                    (void)vrprint.error(VRS_ERR_COMMANDLINE, VR_ERR, "service (-s/--service): argument too long (max: %d).", (int)sizeof(vr_script.name)-1);
                    exit(VRS_ERR_COMMANDLINE);
                }
                break;

            case 'i' :  /* interface */

                vr_script.type = TYPE_INTERFACE;

                if(strlcpy(vr_script.name, optarg, sizeof(vr_script.name)) >= sizeof(vr_script.name))
                {
                    (void)vrprint.error(VRS_ERR_COMMANDLINE, VR_ERR, "host (-i/--interface): argument too long (max: %d).", (int)sizeof(vr_script.name)-1);
                    exit(VRS_ERR_COMMANDLINE);
                }
                break;

            case 'r' :  /* rule */

                vr_script.type = TYPE_RULE;

                if(strlcpy(vr_script.name, optarg, sizeof(vr_script.name)) >= sizeof(vr_script.name))
                {
                    (void)vrprint.error(VRS_ERR_COMMANDLINE, VR_ERR, "rule (-r/--rule): argument too long (max: %d).", (int)sizeof(vr_script.name)-1);
                    exit(VRS_ERR_COMMANDLINE);
                }
                break;

            case 'S' :

                if(strlcpy(vr_script.set, optarg, sizeof(vr_script.set)) >= sizeof(vr_script.set))
                {
                    (void)vrprint.error(VRS_ERR_COMMANDLINE, VR_ERR, "set (-S/--set): argument too long (max: %d).", (int)sizeof(vr_script.set)-1);
                    exit(VRS_ERR_COMMANDLINE);
                }
                break;

            case 'V' :

                if(strlcpy(vr_script.var, optarg, sizeof(vr_script.var)) >= sizeof(vr_script.var))
                {
                    (void)vrprint.error(VRS_ERR_COMMANDLINE, VR_ERR, "var (-V/--var): argument too long (max: %d).", (int)sizeof(vr_script.var)-1);
                    exit(VRS_ERR_COMMANDLINE);
                }
                break;

            case 'O' :

                vr_script.overwrite = TRUE;
                break;

            case 'A' :

                vr_script.overwrite = FALSE;
                break;

            default:

                (void)vrprint.error(VRS_ERR_COMMANDLINE, VR_ERR, "unknown option '%c'. See --help for valid options.", opt);
                exit(VRS_ERR_COMMANDLINE);
        }
    }

    if(version_flag == 1)
    {
        fprintf(stdout, "Vuurmuur_script %s\n", version_string);
        fprintf(stdout, "Copyright (C) 2002-2008 by Victor Julien\n");
        exit(VRS_SUCCESS);
    }

    if(conf.verbose_out == TRUE)
    {
        /* print some nice info about me being the coolest of 'm all ;-) */
        (void)vrprint.info("Info", "This is Vuurmuur_script %s", version_string);
        (void)vrprint.info("Info", "Copyright (C) 2002-2008 by Victor Julien");
    }

    /* setup regexes */
    if(setup_rgx(1, &vr_script.reg) < 0)
    {
        (void)vrprint.error(VRS_ERR_INTERNAL, VR_INTERR, "setting up regular expressions failed.");
        exit(VRS_ERR_INTERNAL);
    }

    /* apply and no-apply */
    if(apply_flag == 1)
        vr_script.apply = TRUE;
    if(no_apply_flag == 1)
        vr_script.apply = FALSE;

    /* reload the config */
    if (reload_flag == 1)
    {
        vr_script.cmd = CMD_RLD;
        vr_script.apply = TRUE;
    }

    /*
        handling the command
    */
    if(vr_script.cmd == CMD_UNSET)
    {
        (void)vrprint.error(VRS_ERR_COMMANDLINE, VR_ERR, "missing command option, use --help to see a list of possible commands.");
        exit(VRS_ERR_COMMANDLINE);
    }

    if(vr_script.cmd == CMD_ADD)
    {
        if(conf.verbose_out == TRUE)
            (void)vrprint.info(VR_INFO, "command 'add' selected.");
    }
    else if(vr_script.cmd == CMD_DEL)
    {
        if(conf.verbose_out == TRUE)
            (void)vrprint.info(VR_INFO, "command 'delete' selected.");
    }
    else if(vr_script.cmd == CMD_MOD)
    {
        if(conf.verbose_out == TRUE)
            (void)vrprint.info(VR_INFO, "command 'modify' selected.");
    }
    else if(vr_script.cmd == CMD_REN)
    {
        if(conf.verbose_out == TRUE)
            (void)vrprint.info(VR_INFO, "command 'rename' selected.");
    }
    else if(vr_script.cmd == CMD_LST)
    {
        if(conf.verbose_out == TRUE)
            (void)vrprint.info(VR_INFO, "command 'list' selected.");
    }
    else if(vr_script.cmd == CMD_PRT)
    {
        if(conf.verbose_out == TRUE)
            (void)vrprint.info(VR_INFO, "command 'print' selected.");
    }
    else if(vr_script.cmd == CMD_BLK)
    {
        if(conf.verbose_out == TRUE)
            (void)vrprint.info(VR_INFO, "command 'block' selected.");
    }
    else if(vr_script.cmd == CMD_UBL)
    {
        if(conf.verbose_out == TRUE)
            (void)vrprint.info(VR_INFO, "command 'unblock' selected.");
    }
    else if(vr_script.cmd == CMD_LBL)
    {
        if(conf.verbose_out == TRUE)
            (void)vrprint.info(VR_INFO, "command 'list-blocked' selected.");
    }
    else if(vr_script.cmd == CMD_RLD)
    {
        if(conf.verbose_out == TRUE)
            (void)vrprint.info(VR_INFO, "command 'reload-config' selected.");
    }
    else
    {
        (void)vrprint.error(VRS_ERR_INTERNAL, VR_INTERR, "unknown command option %d.", vr_script.cmd);
        exit(VRS_ERR_INTERNAL);
    }


    /*
        handling the type
    */
    if(vr_script.type == TYPE_UNSET && vr_script.cmd != CMD_RLD)
    {
        (void)vrprint.error(VRS_ERR_COMMANDLINE, VR_ERR, "type option not set. Please see --help for options.");
        exit(VRS_ERR_COMMANDLINE);
    }

    if(vr_script.type == TYPE_HOST)
    {
        if(conf.verbose_out == TRUE)
            (void)vrprint.info(VR_INFO, "type 'host' selected.");
    }
    else if(vr_script.type == TYPE_GROUP)
    {
        if(conf.verbose_out == TRUE)
            (void)vrprint.info(VR_INFO, "type 'group' selected.");
    }
    else if(vr_script.type == TYPE_NETWORK)
    {
        if(conf.verbose_out == TRUE)
            (void)vrprint.info(VR_INFO, "type 'network' selected.");
    }
    else if(vr_script.type == TYPE_ZONE)
    {
        if(conf.verbose_out == TRUE)
            (void)vrprint.info(VR_INFO, "type 'zone' selected.");
    }
    else if(vr_script.type == TYPE_SERVICE)
    {
        if(conf.verbose_out == TRUE)
            (void)vrprint.info(VR_INFO, "type 'service' selected.");
    }
    else if(vr_script.type == TYPE_INTERFACE)
    {
        if(conf.verbose_out == TRUE)
            (void)vrprint.info(VR_INFO, "type 'interface' selected.");
    }
    else if(vr_script.type == TYPE_RULE)
    {
        if(conf.verbose_out == TRUE)
            (void)vrprint.info(VR_INFO, "type 'rule' selected.");
    }
    else if(vr_script.cmd == CMD_RLD)
    {
        if(conf.verbose_out == TRUE)
            (void)vrprint.info(VR_INFO, "reload has no option.");
    }
    else
    {
        (void)vrprint.error(VRS_ERR_INTERNAL, VR_INTERR, "unknown type option %d.", vr_script.type);
        exit(VRS_ERR_INTERNAL);
    }

    /*
        handling the name
    */
    if(vr_script.name[0] == '\0')
    {
        (void)strlcpy(vr_script.name, "any", sizeof(vr_script.name));
    }
    else if(strcasecmp(vr_script.name, "any") == 0)
    {
        /* ignore any */
    }
    else
    {
        if( vr_script.type == TYPE_ZONE || vr_script.type == TYPE_NETWORK ||
            vr_script.type == TYPE_HOST || vr_script.type == TYPE_GROUP)
        {
            /* validate and split the new name */
            if(validate_zonename(debuglvl, vr_script.name, 0, vr_script.name_zone, vr_script.name_net, vr_script.name_host, vr_script.reg.zonename, VALNAME_VERBOSE) != 0)
            {
                if(vr_script.type == TYPE_ZONE)
                    (void)vrprint.error(VRS_ERR_COMMANDLINE, VR_ERR, "invalid zone name '%s' (in: %s:%d).", vr_script.name, __FUNC__, __LINE__);
                else if(vr_script.type == TYPE_NETWORK)
                    (void)vrprint.error(VRS_ERR_COMMANDLINE, VR_ERR, "invalid network name '%s' (in: %s:%d).", vr_script.name, __FUNC__, __LINE__);
                else if(vr_script.type == TYPE_HOST)
                    (void)vrprint.error(VRS_ERR_COMMANDLINE, VR_ERR, "invalid host name '%s' (in: %s:%d).", vr_script.name, __FUNC__, __LINE__);
                else if(vr_script.type == TYPE_GROUP)
                    (void)vrprint.error(VRS_ERR_COMMANDLINE, VR_ERR, "invalid group name '%s' (in: %s:%d).", vr_script.name, __FUNC__, __LINE__);
                
                exit(VRS_ERR_COMMANDLINE);
            }
            if(debuglvl >= HIGH)
                (void)vrprint.debug(__FUNC__, "name: '%s': host/group '%s', net '%s', zone '%s'.",
                                        vr_script.name, vr_script.name_host,
                                        vr_script.name_net, vr_script.name_zone);
        }
        else if(vr_script.type == TYPE_SERVICE)
        {
            if(validate_servicename(debuglvl, vr_script.name, vr_script.reg.servicename, VALNAME_QUIET) != 0)
            {
                (void)vrprint.error(VRS_ERR_COMMANDLINE, VR_ERR, "invalid service name '%s' (in: %s:%d).", vr_script.name, __FUNC__, __LINE__);
                exit(VRS_ERR_COMMANDLINE);
            }
        }
        else if(vr_script.type == TYPE_INTERFACE)
        {
            if(validate_interfacename(debuglvl, vr_script.name, vr_script.reg.interfacename) != 0)
            {
                (void)vrprint.error(VRS_ERR_COMMANDLINE, VR_ERR, "invalid interface name '%s' (in: %s:%d).", vr_script.name, __FUNC__, __LINE__);
                exit(VRS_ERR_COMMANDLINE);
            }
        }
        else if(vr_script.type == TYPE_RULE)
        {
            if( strcmp(vr_script.name, "blocklist") == 0 ||
                strcmp(vr_script.name, "rules") == 0)
            {
                /* ok */
            }
            else
            {
                /* error */
                (void)vrprint.error(VRS_ERR_COMMANDLINE, VR_ERR, "invalid ruleset name '%s' (in: %s:%d).", vr_script.name, __FUNC__, __LINE__);
                exit(VRS_ERR_COMMANDLINE);
            }
        }
        else
        {
            /* error */
            (void)vrprint.error(VRS_ERR_INTERNAL, VR_INTERR, "unknown type option %d.", vr_script.type);
            exit(VRS_ERR_INTERNAL);
        }
    }

    /* set var to any if var is empty */
    if(vr_script.var[0] == '\0')
        (void)strlcpy(vr_script.var, "any", sizeof(vr_script.var));

    /* see if we need to print rule numbers */
    if(print_linenum_flag == 1)
        vr_script.print_rule_numbers = TRUE;

    /* initialize the config from the config file */
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


    /* now we know the logfile locations, so init the log functions */
    if(conf.verbose_out == TRUE)
    {
        /* if we use verbose output, we still print the logfiles as well */
        vrprint.error = libvuurmuur_logstdoutprint_error;
        vrprint.warning = libvuurmuur_logstdoutprint_warning;
        vrprint.info = libvuurmuur_logstdoutprint_info;
        vrprint.debug = libvuurmuur_logstdoutprint_debug;
    }
    else
    {
        vrprint.error = libvuurmuur_logprint_error;
        vrprint.warning = libvuurmuur_logprint_warning;
        vrprint.info = libvuurmuur_logprint_info;
        vrprint.debug = libvuurmuur_logprint_debug;
    }
    /* audit only to the log, no matter if we are in verbose mode or not
       because it prints: username: message... example:

       victor : interface 'abcd' added.
    */
    vrprint.audit = libvuurmuur_logprint_audit;


    /* load the backends */
    result = load_backends(debuglvl);
    if(result < 0)
    {
        fprintf(stdout, "Error: loading backends failed\n");
        exit(EXIT_FAILURE);
    }

    /* main part: handle the different commands */
    if(vr_script.cmd == CMD_LST)
    {
        retval = script_list(debuglvl, &vr_script);
    }
    else if(vr_script.cmd == CMD_PRT)
    {
        if(strcasecmp(vr_script.name,"any") == 0)
        {
            (void)vrprint.error(VRS_ERR_COMMANDLINE, VR_ERR, "cannot use command 'print' on object 'any'.");
            retval = VRS_ERR_COMMANDLINE;
        }
        else
        {
            retval = script_print(debuglvl, &vr_script);
        }
    }
    else if(vr_script.cmd == CMD_ADD)
    {
        if(strcasecmp(vr_script.name,"any") == 0)
        {
            (void)vrprint.error(VRS_ERR_COMMANDLINE, VR_ERR, "cannot use command 'add' on object 'any'.");
            retval = VRS_ERR_COMMANDLINE;
        }
        else
        {
            retval = script_add(debuglvl, &vr_script);
        }
    }
    else if(vr_script.cmd == CMD_DEL)
    {
        if(strcasecmp(vr_script.name,"any") == 0)
        {
            (void)vrprint.error(VRS_ERR_COMMANDLINE, VR_ERR, "cannot use command 'del' on object 'any'.");
            retval = VRS_ERR_COMMANDLINE;
        }
        else
        {
            retval = script_delete(debuglvl, &vr_script);
        }
    }
    else if(vr_script.cmd == CMD_MOD || vr_script.cmd == CMD_BLK)
    {
        /* workaround for the problem that we don't want to append into
         * append into an empty list then using --block */
        if (vr_script.cmd == CMD_BLK) {
            /* append or overwrite mode (fix ticket #49) */
            if ((rf->ask(debuglvl, rule_backend, "blocklist", "RULE",
                            vr_script.bdat, sizeof(vr_script.bdat), TYPE_RULE, 1) == 1))
            {
                /* we got a rule from the backend so we have to append */
                vr_script.overwrite = FALSE;
            } else {
                /* there are no rules in the backend so we overwrite */
                vr_script.overwrite = TRUE;
            }

            /* switch to mod here */
            vr_script.cmd = CMD_MOD;
        }

        if(strcasecmp(vr_script.name,"any") == 0)
        {
            (void)vrprint.error(VRS_ERR_COMMANDLINE, VR_ERR, "cannot use command 'modify' on object 'any'.");
            retval = VRS_ERR_COMMANDLINE;
        }
        else if(vr_script.var[0] == '\0' || strcasecmp(vr_script.var, "any") == 0)
        {
            (void)vrprint.error(VRS_ERR_COMMANDLINE, VR_ERR, "please set the variable to modify with --variable.");
            retval = VRS_ERR_COMMANDLINE;
        }
        /* allow empty 'set' if we overwrite, since that way we can clear variables */
        else if(vr_script.set[0] == '\0' && vr_script.overwrite == FALSE)
        {
            (void)vrprint.error(VRS_ERR_COMMANDLINE, VR_ERR, "please set the new value with --set.");
            retval = VRS_ERR_COMMANDLINE;
        }
        else
        {
            retval = script_modify(debuglvl, &vr_script);
        }
    }
    else if(vr_script.cmd == CMD_REN)
    {
        if(strcasecmp(vr_script.name,"any") == 0)
        {
            (void)vrprint.error(VRS_ERR_COMMANDLINE, VR_ERR, "cannot use command 'rename' on object 'any'.");
            retval = VRS_ERR_COMMANDLINE;
        }
        else if(strcasecmp(vr_script.set,"any") == 0)
        {
            (void)vrprint.error(VRS_ERR_COMMANDLINE, VR_ERR, "cannot rename a object to 'any'.");
            retval = VRS_ERR_COMMANDLINE;
        }
        else if(strncasecmp(vr_script.set,"firewall", 8) == 0)
        {
            (void)vrprint.error(VRS_ERR_COMMANDLINE, VR_ERR, "cannot rename a object to a name that starts with 'firewall'.");
            retval = VRS_ERR_COMMANDLINE;
        }
        else if(vr_script.set[0] == '\0')
        {
            (void)vrprint.error(VRS_ERR_COMMANDLINE, VR_ERR, "please set the new name with --set.");
            retval = VRS_ERR_COMMANDLINE;
        }
        else
        {
            retval = script_rename(debuglvl, &vr_script);
        }
    }
    else if(vr_script.cmd == CMD_UBL)
    {
        retval = script_unblock(debuglvl, &vr_script);
    }
    else if(vr_script.cmd == CMD_LBL)
    {
        while((result = rf->ask(debuglvl, rule_backend, "blocklist", "RULE", vr_script.bdat, sizeof(vr_script.bdat), TYPE_RULE, 1) == 1))
        {
            rules_encode_rule(debuglvl, vr_script.bdat, sizeof(vr_script.bdat));
            str = remove_leading_part(vr_script.bdat);
            printf("%s\n", str);
            free(str);
        }
        /* check the result */
        if(result == 0)
            retval = 0;
        else
            retval = VRS_ERR_COMMAND_FAILED;
    }
    else if(vr_script.cmd == CMD_RLD)
    {
        retval = VRS_SUCCESS;
    }
    else
    {
        printf("FIXME: command not implemented\n");
        retval = VRS_ERR_COMMANDLINE;
    }

    /* if all went well (retval == 0) we can apply now */
    if(vr_script.apply == TRUE && retval == VRS_SUCCESS)
    {
        retval = script_apply(debuglvl, &vr_script);
    }

    /* unload the backends */
    result = unload_backends(debuglvl);
    if(result < 0)
    {
        fprintf(stdout, "Error: unloading backends failed.\n");
        exit(EXIT_FAILURE);
    }

    /*
        Destroy the data structures
    */

    /* cleanup regexes */
    (void)setup_rgx(0, &vr_script.reg);

    if(debuglvl >= HIGH)
        (void)vrprint.debug(__FUNC__, "** end **, return = %d", retval);

    return(retval);
}


/*  log a change to the audit log, and if we are in verbose mode, also to
    screen.
*/
void
logchange(char *fmt, ...)
{
    va_list ap;
    char    prnt_str[MAX_LOGRULE_SIZE] = "";

    va_start(ap, fmt);
    vsnprintf(prnt_str, sizeof(prnt_str), fmt, ap);
    va_end(ap);

    (void)vrprint.audit("%s", prnt_str);
    if(conf.verbose_out == TRUE)
        (void)vrprint.info("Info", "%s", prnt_str);
}
