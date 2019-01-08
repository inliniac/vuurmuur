/***************************************************************************
 *   Copyright (C) 2003-2019 by Victor Julien                              *
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

static void print_commandline_args(void)
{
    fprintf(stdout, "Usage: vuurmuur_conf [OPTIONS]\n");
    fprintf(stdout, "\n");
    fprintf(stdout, "Options:\n");
    fprintf(stdout, " -h, --help\t\t\tgives this help\n");
    fprintf(stdout, " -c, --configfile\t\tuse the given configfile\n");
    fprintf(stdout, " -d, --debug\t\t\tenable debugging (1 = low, 3 = high)\n");
    fprintf(stdout, " -V, --version\t\t\tgives the version\n");
    fprintf(stdout, " -W  --wizard\t\t\truns the quick setup wizard\n");
    fprintf(stdout, "\n");
    exit(EXIT_SUCCESS);
}

static int exec_wizard(char *path)
{
    int retval = 0;
    char *args[2] = {path, NULL};

    pid_t pid = fork();
    if (pid == 0) {
        /* actually exec the command */
        execv(path, args);

        /* if we get here, the command didn't exec
         * so kill the child */
        exit(127);
    }

    int status;
    pid_t rpid;
    do {
        rpid = waitpid(pid, &status, 0);
    } while (rpid == -1 && errno == EINTR);

    if (pid != -1 && WIFEXITED(status) && WEXITSTATUS(status)) {
        retval = WEXITSTATUS(status);
    } else if (rpid == -1)
        retval = -1;

    return retval;
}

void setup_colors()
{
    /* Initialize all the colors */

    if (vccnf.background == 0) {
        vccnf.win_fore = COLOR_BLUE;
        vccnf.bgd_back = COLOR_BLUE;
    } else {
        vccnf.win_fore = COLOR_BLACK;
        vccnf.bgd_back = COLOR_BLACK;
    }
    vccnf.win_back = COLOR_WHITE;
    vccnf.bgd_fore = COLOR_WHITE;

    init_pair(CP_WIN, vccnf.win_fore, vccnf.win_back);
    init_pair(CP_WIN_REV, vccnf.win_back, vccnf.win_fore);
    init_pair(CP_WIN_MARK, COLOR_RED, vccnf.win_back);
    init_pair(CP_WIN_FIELD, COLOR_WHITE, COLOR_BLUE);

    init_pair(CP_WIN_RED, COLOR_RED, vccnf.win_back);
    init_pair(CP_WIN_RED_REV, vccnf.win_back, COLOR_RED);
    init_pair(CP_WIN_GREEN, COLOR_GREEN, vccnf.win_back);
    init_pair(CP_WIN_GREEN_REV, vccnf.win_back, COLOR_GREEN);
    init_pair(CP_WIN_YELLOW, COLOR_YELLOW, vccnf.win_back);
    init_pair(CP_WIN_MAGENTA, COLOR_MAGENTA, vccnf.win_back);
    init_pair(CP_WIN_CYAN, COLOR_CYAN, vccnf.win_back);

    init_pair(CP_WIN_INIT, COLOR_YELLOW, COLOR_RED);
    init_pair(CP_WIN_WARN, COLOR_YELLOW, COLOR_RED);
    init_pair(CP_WIN_NOTE, COLOR_RED, COLOR_WHITE);
    init_pair(CP_WIN_NOTE_REV, COLOR_WHITE, COLOR_RED);

    init_pair(CP_RULE_BAR, COLOR_RED, COLOR_WHITE);

    init_pair(CP_BGD, vccnf.bgd_fore, vccnf.bgd_back);
    init_pair(CP_BGD_REV, vccnf.bgd_back, vccnf.bgd_fore);
    init_pair(CP_BGD_RED, COLOR_RED, vccnf.bgd_back);
    init_pair(CP_BGD_GREEN, COLOR_GREEN, vccnf.bgd_back);
    init_pair(CP_BGD_YELLOW, COLOR_YELLOW, vccnf.bgd_back);
    init_pair(CP_BGD_MAGENTA, COLOR_MAGENTA, vccnf.bgd_back);
    init_pair(CP_BGD_CYAN, COLOR_CYAN, vccnf.bgd_back);

    vccnf.color_win = (chtype)COLOR_PAIR(CP_WIN);
    vccnf.color_win_rev = (chtype)COLOR_PAIR(CP_WIN_REV);
    vccnf.color_win_mark = (chtype)COLOR_PAIR(CP_WIN_MARK);
    vccnf.color_win_field = (chtype)COLOR_PAIR(CP_WIN_FIELD);
    vccnf.color_win_red = (chtype)COLOR_PAIR(CP_WIN_RED);
    vccnf.color_win_red_rev = (chtype)COLOR_PAIR(CP_WIN_RED_REV);
    vccnf.color_win_green = (chtype)COLOR_PAIR(CP_WIN_GREEN);
    vccnf.color_win_green_rev = (chtype)COLOR_PAIR(CP_WIN_GREEN_REV);
    vccnf.color_win_yellow = (chtype)COLOR_PAIR(CP_WIN_YELLOW);
    vccnf.color_win_magenta = (chtype)COLOR_PAIR(CP_WIN_MAGENTA);
    vccnf.color_win_cyan = (chtype)COLOR_PAIR(CP_WIN_CYAN);

    vccnf.color_win_init = (chtype)COLOR_PAIR(CP_WIN_INIT);
    vccnf.color_win_warn = (chtype)COLOR_PAIR(CP_WIN_WARN);
    vccnf.color_win_note = (chtype)COLOR_PAIR(CP_WIN_NOTE);
    vccnf.color_win_note_rev = (chtype)COLOR_PAIR(CP_WIN_NOTE_REV);

    vccnf.color_bgd = (chtype)COLOR_PAIR(CP_BGD);
    vccnf.color_bgd_hi = (chtype)COLOR_PAIR(CP_BGD_YELLOW);
    vccnf.color_bgd_rev = (chtype)COLOR_PAIR(CP_BGD_REV);
    vccnf.color_bgd_red = (chtype)COLOR_PAIR(CP_BGD_RED);
    vccnf.color_bgd_green = (chtype)COLOR_PAIR(CP_BGD_GREEN);
    vccnf.color_bgd_yellow = (chtype)COLOR_PAIR(CP_BGD_YELLOW);
    vccnf.color_bgd_magenta = (chtype)COLOR_PAIR(CP_BGD_MAGENTA);
    vccnf.color_bgd_cyan = (chtype)COLOR_PAIR(CP_BGD_CYAN);

    vccnf.color_rule_bar = (chtype)COLOR_PAIR(CP_RULE_BAR);
}

int main(int argc, char *argv[])
{
    struct vrmr_ctx vctx;

    int retval = 0, optch = 0;

    static char optstring[] = "c:d:hVW";
    struct option long_options[] = {
            {"configfile", required_argument, NULL, 'c'},
            {"debug", required_argument, NULL, 'd'},
            {"help", no_argument, NULL, 'h'},
            {"version", no_argument, NULL, 'V'},
            {"wizard", no_argument, NULL, 'W'},
            {0, 0, 0, 0},
    };
    int longopt_index = 0;

    int debug_level = NONE;
    PANEL *main_panels[5];
    char *s = NULL;

    /* some defaults */
    vuurmuur_semid = -1;
    vuurmuur_shmid = -1;
    vuurmuurlog_semid = -1;
    vuurmuurlog_shmid = -1;

    /* create the version string */
    snprintf(version_string, sizeof(version_string),
            "%s (using libvuurmuur %s)", VUURMUURCONF_VERSION,
            libvuurmuur_get_version());

    /* some initilization */
    if (vrmr_init(&vctx, "vuurmuur_conf") < 0)
        exit(EXIT_FAILURE);

    /* settings file */
    memset(vccnf.configfile_location, 0, sizeof(vccnf.configfile_location));
    if (vctx.conf.etcdir[0] == '\0')
        (void)strlcpy(vccnf.configfile_location, VUURMUURCONF_CONFIGFILE,
                sizeof(vccnf.configfile_location));
    else
        (void)snprintf(vccnf.configfile_location,
                sizeof(vccnf.configfile_location),
                "%s/vuurmuur/vuurmuur_conf.conf", vctx.conf.etcdir);

#ifdef ENABLE_NLS
    setlocale(LC_ALL, "");
    setlocale(LC_TIME, "");
    setlocale(LC_MESSAGES, "");
    setlocale(LC_COLLATE, "");
    setlocale(LC_CTYPE, "");
    setlocale(LC_MONETARY, "");
    setlocale(LC_NUMERIC, "");
#endif

    /* check if we are in utf-8 mode */
    utf8_mode = 0;

    if ((s = getenv("LC_ALL")) || (s = getenv("LC_CTYPE")) ||
            (s = getenv("LANG"))) {
        if (strstr(s, "UTF-8"))
            utf8_mode = 1;
    }

    bindtextdomain("vuurmuur", xstr(VRMR_LOCALEDIR));
    textdomain("vuurmuur");

    /* process commandline options */
    while ((optch = getopt_long(argc, argv, optstring, long_options,
                    &longopt_index)) != -1) {
        switch (optch) {
            case 'h':
                print_commandline_args();
                break;

            /* configfile */
            case 'c':

                if (strlcpy(vctx.conf.configfile, optarg,
                            sizeof(vctx.conf.configfile)) >=
                        sizeof(vctx.conf.configfile)) {
                    vrmr_error(EXIT_FAILURE, VR_ERR,
                            gettext("commandline argument too long for option "
                                    "-c."));
                    exit(EXIT_FAILURE);
                }
                break;

            case 'd':

                /* convert the debug string and check the result */
                debug_level = atoi(optarg);
                if (debug_level < 0 || debug_level > HIGH) {
                    vrmr_error(EXIT_FAILURE, VR_ERR,
                            gettext("commandline debuglevel out of range."));
                    exit(EXIT_FAILURE);
                }
                vrmr_debug_level = debug_level;

                fprintf(stdout, "vuurmuur_conf: debugging enabled.\n");
                fprintf(stdout, "vuurmuur_conf: debug level: %d\n",
                        debug_level);
                break;

            case 'V':
                /* print version */
                fprintf(stdout, "Vuurmuur_conf %s\n", version_string);
                fprintf(stdout, "%s\n", VUURMUUR_COPYRIGHT);

                exit(EXIT_SUCCESS);

            case 'W': {
                char wizard_path[512] = "";
                snprintf(wizard_path, sizeof(wizard_path),
                        "%s/scripts/vuurmuur-wizard.sh", vctx.conf.datadir);
                printf("Running %s...\n", wizard_path);
                exec_wizard(wizard_path);
                exit(EXIT_SUCCESS);
            }
            default:

                vrmr_error(EXIT_FAILURE, VR_ERR,
                        gettext("unknown commandline option."));
                exit(EXIT_FAILURE);
        }
    }

    /*  close the STDERR_FILENO because it gives us annoying "Broken
        Pipe" errors on some systems with bash3. Let's see if this
        has negative side-effects. */
    close(STDERR_FILENO);

    /* init vuurmuur_conf config already to get background */
    (void)init_vcconfig(&vctx.conf, vccnf.configfile_location, &vccnf);

    /* Initialize curses */
    (void)initscr();
    (void)start_color();
    (void)cbreak();
    (void)noecho();
    (void)keypad(stdscr, (bool)TRUE);

    setup_colors();

    /* create the three main windows */
    if (!(status_frame_win = create_newwin(
                  3, COLS, LINES - 3, 0, NULL, vccnf.color_bgd)))
        exit(EXIT_FAILURE);
    if (!(status_win = create_newwin(
                  1, COLS - 4, LINES - 2, 2, NULL, vccnf.color_bgd)))
        exit(EXIT_FAILURE);
    if (!(top_win = create_newwin(3, COLS, 0, 0, NULL, vccnf.color_bgd)))
        exit(EXIT_FAILURE);
    if (!(main_win = create_newwin(
                  LINES - 6, COLS, 3, 0, NULL, vccnf.color_bgd)))
        exit(EXIT_FAILURE);
    if (!(mainlog_win = newwin(LINES - 8, COLS - 2, 4, 1)))
        exit(EXIT_FAILURE);

    (void)wbkgd(mainlog_win, vccnf.color_bgd);

    wattron(status_frame_win, vccnf.color_bgd);
    mvwprintw(status_frame_win, 0, 2, " %s ", gettext("Status"));
    mvwprintw(status_frame_win, 2,
            (int)(COLS - 4 - StrLen(vctx.user_data.realusername) - 6),
            " user: %s ", vctx.user_data.realusername);
    wattroff(status_frame_win, vccnf.color_bgd);

    /* Attach a panel to each window */
    main_panels[0] = new_panel(top_win);
    main_panels[1] = new_panel(main_win);
    main_panels[2] = new_panel(status_win);
    main_panels[3] = new_panel(mainlog_win);
    main_panels[4] = new_panel(status_frame_win);

    (void)update_panels();
    (void)doupdate();

    /* init the vrprint functions for the Gui */
    vrprint.error = vuumuurconf_print_error;
    vrprint.warning = vuumuurconf_print_warning;
    vrprint.info = vuumuurconf_print_info;

    if (status_print(status_win, gettext("This is Vuurmuur_conf %s, %s"),
                version_string, VUURMUUR_COPYRIGHT) < 0)
        exit(EXIT_FAILURE);

    /* setup the global busywin */
    VrBusyWinCreate();
    VrBusyWinHide();

    // form_test();

    /* startup_screen inits the config, loads the zones, rules, etc */
    if (startup_screen(&vctx, &vctx.rules, &vctx.zones, &vctx.services,
                &vctx.interfaces, &vctx.blocklist, &vctx.reg) < 0) {
        /* failure! Lets quit. */

        /* delete panels and windows */
        (void)del_panel(main_panels[0]);
        (void)del_panel(main_panels[1]);
        (void)del_panel(main_panels[2]);
        (void)del_panel(main_panels[3]);
        (void)del_panel(main_panels[4]);
        (void)destroy_win(top_win);
        (void)destroy_win(main_win);
        (void)destroy_win(status_win);
        (void)destroy_win(status_frame_win);
        /* clear screen */
        (void)refresh();
        /* end ncurses mode */
        (void)endwin();

        exit(EXIT_FAILURE);
    }

    /* setup statuslist */
    (void)setup_statuslist();

    status_print(status_win, STR_READY);

    mm_status_checkall(&vctx, NULL, &vctx.rules, &vctx.zones, &vctx.interfaces,
            &vctx.services);
    /* main menu loop */
    while (main_menu(&vctx, &vctx.rules, &vctx.zones, &vctx.interfaces,
                   &vctx.services, &vctx.blocklist, &vctx.reg) == 1)
        ;
    /* clean up the status list */
    vrmr_list_cleanup(&vuurmuur_status.StatusList);

    /* detach from shared memory, if we were attached */
    if (vuurmuur_shmp != NULL && vuurmuur_shmp != (char *)(-1) &&
            vuurmuur_shmtable != 0) {
        if (vrmr_lock(vuurmuur_semid)) {
            vuurmuur_shmtable->configtool.connected = 3;
            vrmr_unlock(vuurmuur_semid);
        }
        (void)shmdt(vuurmuur_shmp);
    }
    if (vuurmuurlog_shmp != NULL && vuurmuurlog_shmp != (char *)(-1) &&
            vuurmuurlog_shmtable != 0) {
        if (vrmr_lock(vuurmuurlog_semid)) {
            vuurmuurlog_shmtable->configtool.connected = 3;
            vrmr_unlock(vuurmuurlog_semid);
        }
        (void)shmdt(vuurmuurlog_shmp);
    }

    /* destroy the global busywin */
    VrBusyWinDelete();

    /* delete panels and windows */
    (void)del_panel(main_panels[0]);
    (void)del_panel(main_panels[1]);
    (void)del_panel(main_panels[2]);
    (void)del_panel(main_panels[3]);
    (void)del_panel(main_panels[4]);

    (void)destroy_win(mainlog_win);
    (void)destroy_win(top_win);
    (void)destroy_win(main_win);
    (void)destroy_win(status_win);
    (void)destroy_win(status_frame_win);
    /* clear screen */
    (void)refresh();

    /* end ncurses mode */
    (void)endwin();

    /* set error functions to the stdout versions */
    vrprint.error = vrmr_stdoutprint_error;
    vrprint.warning = vrmr_stdoutprint_warning;
    vrprint.info = vrmr_stdoutprint_info;
    vrprint.debug = vrmr_stdoutprint_debug;
    vrprint.audit = vrmr_stdoutprint_audit;

    /* unload the backends */
    if (vrmr_backends_unload(&vctx.conf, &vctx) < 0) {
        vrmr_error(-1, VR_ERR, gettext("unloading the backends failed"));
        retval = -1;
    }

    /* cleanup the datastructures */
    (void)vrmr_list_cleanup(&vctx.blocklist.list);
    (void)vrmr_destroy_serviceslist(&vctx.services);
    (void)vrmr_destroy_zonedatalist(&vctx.zones);
    (void)vrmr_rules_cleanup_list(&vctx.rules);
    (void)vrmr_destroy_interfaceslist(&vctx.interfaces);
    vrmr_deinit(&vctx);
    return (retval);
}

void print_in_middle(WINDOW *win, int starty, int startx, int width,
        char *string, chtype color)
{
    int length, x, y;
    float temp;

    if (!win)
        win = stdscr;

    getyx(win, y, x);

    if (starty != 0)
        y = starty;

    if (width == 0)
        width = 80;

    length = (int)StrLen(string);
    temp = (float)((width - length) / 2);
    x = startx + (int)temp;
    wattron(win, color);
    mvwprintw(win, y, x, "%s", string);
    wattroff(win, color);
    refresh();
}

/*  create_newwin

    creates a window, sets it background and sets a title.

    Returns a pointer to the window or NULL in case of failure.
*/
WINDOW *create_newwin(
        int height, int width, int starty, int startx, char *title, chtype ch)
{
    WINDOW *local_win = NULL;
    size_t memsize = 0, screensize = 0;
    char *title_ptr = NULL;

    vrmr_fatal_if(height <= 0 || width <= 0 || starty < 0 || startx < 0);

    /* create the window */
    if (!(local_win = newwin(height, width, starty, startx)))
        return (NULL);

    /* box and background */
    (void)box(local_win, 0, 0);
    (void)wbkgd(local_win, ch);

    /* draw title if we have one */
    if (title != NULL) {
        memsize = StrMemLen(title);
        screensize = StrLen(title);

        if ((int)screensize + 4 <= width) {
            title_ptr = malloc(memsize + 3);
            if (title_ptr == NULL) {

            } else {
                snprintf(title_ptr, memsize + 3, " %s ", title);
                mvwprintw(local_win, 0, (int)(((size_t)width - screensize) / 2),
                        title_ptr);
                free(title_ptr);
            }
        } else {
            vrmr_warning(gettext("Warning"),
                    gettext("title '%s' too long, window will be drawn without "
                            "a title."),
                    title);
        }
    }

    return (local_win);
}

// destroys a window, but first removes a border
void destroy_win(WINDOW *local_win)
{
    chtype ch = ' ';

    // first remove the border
    wborder(local_win, ch, ch, ch, ch, ch, ch, ch, ch);
    wrefresh(local_win);
    delwin(local_win);
}

/*  startup_screen

    This is the splash-screen which calls the startup functions,
    like loading the plugins, zones, services etc.

    Returncodes:
         0: ok
        -1: error
*/
int startup_screen(struct vrmr_ctx *vctx, struct vrmr_rules *rules,
        struct vrmr_zones *zones, struct vrmr_services *services,
        struct vrmr_interfaces *interfaces, struct vrmr_blocklist *blocklist,
        struct vrmr_regex *reg)
{
    WINDOW *startup_win = NULL, *startup_print_win = NULL;
    PANEL *startup_panel[2];
    int retval = 0, maxy = 0, maxx = 0, y = 0, x = 0, width = 50, heigth = 15,
        result = 0, config_done = 0, cnfresult = 0;
    int print_pan_width = 40;

    // get screensize and set windowlocation
    getmaxyx(stdscr, maxy, maxx);
    y = (maxy - heigth) / 2;
    x = (maxx - width) / 2;

    // create the windows and panels
    startup_win = create_newwin(heigth, width, y, x, "Vuurmuur_conf",
            vccnf.color_win_init | A_BOLD);
    startup_print_win = newwin(1, print_pan_width, y + heigth - 3, x + 5);
    wbkgd(startup_print_win, vccnf.color_win_init | A_BOLD);
    startup_panel[0] = new_panel(startup_win);
    startup_panel[1] = new_panel(startup_print_win);
    update_panels();
    doupdate();

    // print the logo: it looks a bit weird here because of escape sequences
    // also print version
    mvwprintw(startup_win, 3, 4, "  \\\\   //           |\\\\ //|            ");
    mvwprintw(startup_win, 4, 4, "   \\\\ // | | | | |] ||\\//|| | | | | |] ");
    mvwprintw(startup_win, 5, 4,
            "    \\//  \\/| \\/| |\\ ||   || \\/| \\/| |\\ ");
    mvwprintw(startup_win, 6, 4, "                                Config ");
    mvwprintw(startup_win, 7, 4, "  ------------------------------------ ");
    mvwprintw(startup_win, 9, 3, "%s ", VUURMUUR_COPYRIGHT);
    mvwprintw(startup_win, 10, 3, gettext("Version: %s"), VUURMUURCONF_VERSION);
    mvwprintw(startup_win, 12, 4, "[");
    mvwprintw(startup_win, 12, 4 + print_pan_width + 1, "]");

    /* initialize the vuurmuur conf config */
    /* TRANSLATORS: max 40 characters */
    werase(startup_print_win);
    wprintw(startup_print_win, "%s...", STR_LOAD_VUURMUUR_CONF_SETTINGS);
    update_panels();
    doupdate();
    if (vrmr_debug_level > LOW)
        sleep(1);
    while (!config_done) {
        result = init_vcconfig(&vctx->conf, vccnf.configfile_location, &vccnf);
        if (result == VRMR_CNF_E_UNKNOWN_ERR || result == VRMR_CNF_E_PARAMETER)
            return (-1);
        else if (result == VRMR_CNF_E_FILE_PERMISSION) {
            return (-1);
        }
        /* missing file? use defaults */
        else if (result == VRMR_CNF_E_FILE_MISSING) {
            vcconfig_use_defaults(&vccnf);

            werase(startup_print_win);
            wprintw(startup_print_win, "%s... %s",
                    STR_LOAD_VUURMUUR_CONF_SETTINGS, STR_COK);
            update_panels();
            doupdate();
            config_done = 1;
        } else if (result == VRMR_CNF_E_MISSING_VAR ||
                   result == VRMR_CNF_E_ILLEGAL_VAR ||
                   result == VRMR_CNF_W_MISSING_VAR ||
                   result == VRMR_CNF_W_ILLEGAL_VAR) {
            if (confirm(gettext("Problem with the Vuurmuur_conf settings"),
                        gettext("Do you want to edit the settings now?"),
                        vccnf.color_win_note, vccnf.color_win_note_rev | A_BOLD,
                        1)) {
                /* this prompt the user with the config menu */
                cnfresult = edit_vcconfig();
                if (cnfresult < 0)
                    return (-1);
            } else {
                /* if the user doesn't want to solve the problem we exit if we
                   had an error in case of a warning, we continue
                */
                if (result == VRMR_CNF_E_MISSING_VAR ||
                        result == VRMR_CNF_E_FILE_MISSING)
                    return (-1);
                else {
                    // TODO: print warning to warn the user that the config is
                    // not yet ok?
                    config_done = 1;
                }
            }
        } else if (result == VRMR_CNF_OK) {
            werase(startup_print_win);
            wprintw(startup_print_win, "%s... %s",
                    STR_LOAD_VUURMUUR_CONF_SETTINGS, STR_COK);
            update_panels();
            doupdate();
            config_done = 1;
        } else {
            vrmr_error(-1, VR_ERR,
                    "unknown return code from init_vcconfig. This can't be "
                    "good");
            return (-1);
        }

        if (config_done == 0) {
            werase(startup_print_win);
            wprintw(startup_print_win, "%s...",
                    STR_LOAD_VUURMUUR_CONF_SETTINGS);
            update_panels();
            doupdate();
        }
    }

    /* initialize the config */
    config_done = 0;
    werase(startup_print_win);
    wprintw(startup_print_win, "%s...", STR_LOAD_VUURMUUR_CONFIG);
    update_panels();
    doupdate();
    if (vrmr_debug_level > LOW)
        sleep(1);
    while (!config_done) {
        result = vrmr_init_config(&vctx->conf);
        if (result == VRMR_CNF_E_UNKNOWN_ERR || result == VRMR_CNF_E_PARAMETER)
            return (-1);
        else if (result == VRMR_CNF_E_FILE_PERMISSION) {
            return (-1);
        } else if (result == VRMR_CNF_E_FILE_MISSING ||
                   result == VRMR_CNF_E_MISSING_VAR ||
                   result == VRMR_CNF_E_ILLEGAL_VAR ||
                   result == VRMR_CNF_W_MISSING_VAR ||
                   result == VRMR_CNF_W_ILLEGAL_VAR) {
            if (confirm(gettext("Problem with the Vuurmuur config"),
                        gettext("Do you want to edit the config now?"),
                        vccnf.color_win_note, vccnf.color_win_note_rev | A_BOLD,
                        1)) {
                /* this prompt the user with the config menu */
                cnfresult = config_menu(&vctx->conf);
                if (cnfresult < 0)
                    return (-1);
            } else {
                /* if the user doesn't want to solve the problem we exit if we
                   had an error in case of a warning, we continue
                */
                if (result == VRMR_CNF_E_MISSING_VAR ||
                        result == VRMR_CNF_E_FILE_MISSING)
                    return (-1);
                else {
                    // TODO: print warning to warn the user that the config is
                    // not yet ok?
                    config_done = 1;
                }
            }
        } else if (result == VRMR_CNF_OK) {
            werase(startup_print_win);
            wprintw(startup_print_win, "%s... %s", STR_LOAD_VUURMUUR_CONFIG,
                    STR_COK);
            update_panels();
            doupdate();
            config_done = 1;
        } else {
            vrmr_error(-1, VR_INTERR,
                    "unknown return code from vrmr_init_config. This can't be "
                    "good");
            return (-1);
        }

        if (config_done == 0) {
            werase(startup_print_win);
            wprintw(startup_print_win, "%s...", STR_LOAD_VUURMUUR_CONFIG);
            update_panels();
            doupdate();
        }
    }

    /* config done, so now we can use logprinting */
    if (vrmr_debug_level >= LOW)
        vrprint.info = vuumuurconf_print_info;
    else
        vrprint.info = vrmr_logprint_info;

    vrprint.debug = vrmr_logprint_debug;
    vrprint.audit = vrmr_logprint_audit;

    /* print that we started */
    vrmr_audit("started: effective user %s (%ld), real user %s (%ld).",
            vctx->user_data.username, (long)vctx->user_data.user,
            vctx->user_data.realusername, (long)vctx->user_data.realuser);

    /* now load the backends */
    werase(startup_print_win);
    wprintw(startup_print_win, "%s...", STR_LOAD_PLUGINS);
    update_panels();
    doupdate();
    if (vrmr_debug_level > LOW)
        sleep(1);
    result = vrmr_backends_load(&vctx->conf, vctx);
    if (result < 0) {
        vrmr_error(-1, VR_ERR, gettext("loading the plugins failed."));
        return (-1);
    }
    werase(startup_print_win);
    wprintw(startup_print_win, "%s... %s", STR_LOAD_PLUGINS, STR_COK);
    update_panels();
    doupdate();

    /* init services */
    /* TRANSLATORS: max 40 characters */
    werase(startup_print_win);
    wprintw(startup_print_win, "%s...", STR_INIT_SERVICES);
    update_panels();
    doupdate();
    if (vrmr_debug_level > LOW)
        sleep(1);
    result = vrmr_init_services(vctx, services, reg);
    if (result < 0) {
        vrmr_error(-1, VR_ERR, gettext("intializing the services failed."));
        return (-1);
    }
    /* TRANSLATORS: max 40 characters */
    werase(startup_print_win);
    wprintw(startup_print_win, "%s... %s", STR_INIT_SERVICES, STR_COK);
    update_panels();
    doupdate();

    /* init interfaces */
    /* TRANSLATORS: max 40 characters */
    werase(startup_print_win);
    wprintw(startup_print_win, "%s...", STR_INIT_INTERFACES);
    update_panels();
    doupdate();
    if (vrmr_debug_level > LOW)
        sleep(1);
    result = vrmr_init_interfaces(vctx, interfaces);
    if (result < 0) {
        vrmr_error(-1, VR_ERR, gettext("intializing the interfaces failed."));
        return (-1);
    }
    /* TRANSLATORS: max 40 characters */
    werase(startup_print_win);
    wprintw(startup_print_win, "%s... %s", STR_INIT_INTERFACES, STR_COK);
    update_panels();
    doupdate();

    /* init zones */
    /* TRANSLATORS: max 40 characters */
    werase(startup_print_win);
    wprintw(startup_print_win, "%s...", STR_INIT_ZONES);
    update_panels();
    doupdate();
    if (vrmr_debug_level > LOW)
        sleep(1);
    result = vrmr_init_zonedata(vctx, zones, interfaces, reg);
    if (result < 0) {
        vrmr_error(-1, VR_ERR, gettext("intializing the zones failed."));
        return (-1);
    }
    /* TRANSLATORS: max 40 characters */
    werase(startup_print_win);
    wprintw(startup_print_win, "%s... %s", STR_INIT_ZONES, STR_COK);
    update_panels();
    doupdate();

    /* init rules */
    /* TRANSLATORS: max 40 characters */
    werase(startup_print_win);
    wprintw(startup_print_win, "%s...", STR_INIT_RULES);
    update_panels();
    doupdate();
    if (vrmr_debug_level > LOW)
        sleep(1);
    result = vrmr_rules_init_list(vctx, &vctx->conf, rules, reg);
    if (result < 0) {
        /* TRANSLATORS: max 40 characters */
        werase(startup_print_win);
        wprintw(startup_print_win, "%s... %s", STR_INIT_RULES, STR_CFAILED);
        update_panels();
        doupdate();
    } else {
        /* TRANSLATORS: max 40 characters */
        werase(startup_print_win);
        wprintw(startup_print_win, "%s... %s", STR_INIT_RULES, STR_COK);
        update_panels();
        doupdate();
    }

    /* load the blockfile */
    /* TRANSLATORS: max 40 characters */
    werase(startup_print_win);
    wprintw(startup_print_win, "%s...", STR_INIT_BLOCKLIST);
    update_panels();
    doupdate();
    if (vrmr_debug_level > LOW)
        sleep(1);
    result = vrmr_blocklist_init_list(vctx, &vctx->conf, zones, blocklist,
            /*load_ips*/ FALSE, /*no_refcnt*/ FALSE);
    if (result < 0) {
        /* TRANSLATORS: max 40 characters */
        werase(startup_print_win);
        wprintw(startup_print_win, "%s... %s", STR_INIT_BLOCKLIST, STR_CFAILED);
        update_panels();
        doupdate();
    } else {
        /* TRANSLATORS: max 40 characters */
        werase(startup_print_win);
        wprintw(startup_print_win, "%s... %s", STR_INIT_BLOCKLIST, STR_COK);
        update_panels();
        doupdate();
    }

    /*
        try to connect to vuurmuur trough shm
    */
    vuurmuur_shmtable = NULL;
    werase(startup_print_win);
    wprintw(startup_print_win, "%s Vuurmuur...", STR_CONNECTING_TO);
    update_panels();
    doupdate();
    vuurmuur_pid = get_vuurmuur_pid("/var/run/vuurmuur.pid", &vuurmuur_shmid);
    if (vuurmuur_shmid > 0) {
        /* attach to shared memory */
        vuurmuur_shmp = shmat(vuurmuur_shmid, 0, 0);
        if (vuurmuur_shmp == (char *)(-1)) {
            vrmr_error(-1, VR_ERR,
                    gettext("attaching to shared memory failed: %s"),
                    strerror(errno));
        } else {
            vuurmuur_shmtable = (struct vrmr_shm_table *)vuurmuur_shmp;
            vuurmuur_semid = vuurmuur_shmtable->sem_id;

            /* now try to connect to the shared memory */
            if (vrmr_lock(vuurmuur_semid)) {
                vuurmuur_shmtable->configtool.connected = 1;
                (void)snprintf(vuurmuur_shmtable->configtool.name,
                        sizeof(vuurmuur_shmtable->configtool.name),
                        "Vuurmuur_conf %s (user: %s)", version_string,
                        vctx->user_data.realusername);
                (void)strlcpy(vuurmuur_shmtable->configtool.username,
                        vctx->user_data.realusername,
                        sizeof(vuurmuur_shmtable->configtool.username));
                vrmr_unlock(vuurmuur_semid);

                werase(startup_print_win);
                wprintw(startup_print_win, "%s Vuurmuur... %s",
                        STR_CONNECTING_TO, STR_COK);
                update_panels();
                doupdate();
            } else {
                werase(startup_print_win);
                wprintw(startup_print_win, "%s Vuurmuur... %s",
                        STR_CONNECTING_TO, STR_CFAILED);
                update_panels();
                doupdate();
                vuurmuur_shmp = NULL;
            }
        }
    } else {
        /* TRANSLATORS: max 40 characters */
        werase(startup_print_win);
        wprintw(startup_print_win, "%s Vuurmuur... %s", STR_CONNECTING_TO,
                STR_CFAILED);
        update_panels();
        doupdate();
        vuurmuur_shmp = NULL;
    }

    /*
        try to connect to vuurmuur trough shm
    */
    vuurmuurlog_shmtable = NULL;
    /* TRANSLATORS: max 40 characters */
    werase(startup_print_win);
    wprintw(startup_print_win, "%s Vuurmuur_log...", STR_CONNECTING_TO);
    update_panels();
    doupdate();
    vuurmuurlog_pid =
            get_vuurmuur_pid("/var/run/vuurmuur_log.pid", &vuurmuurlog_shmid);
    if (vuurmuurlog_shmid > 0) {
        /* attach to shared memory */
        vuurmuurlog_shmp = shmat(vuurmuurlog_shmid, 0, 0);
        if (vuurmuurlog_shmp == (char *)(-1)) {
            vrmr_error(-1, VR_ERR, "attaching to shared memory failed: %s",
                    strerror(errno));
        } else {
            vuurmuurlog_shmtable = (struct vrmr_shm_table *)vuurmuurlog_shmp;
            vuurmuurlog_semid = vuurmuurlog_shmtable->sem_id;

            vrmr_debug(LOW, "vuurmuur_log: sem_id: %d.", vuurmuurlog_semid);

            /* now try to connect to the shared memory */
            if (vrmr_lock(vuurmuurlog_semid)) {
                vuurmuurlog_shmtable->configtool.connected = 1;
                (void)snprintf(vuurmuurlog_shmtable->configtool.name,
                        sizeof(vuurmuurlog_shmtable->configtool.name),
                        "Vuurmuur_conf %s (user: %s)", version_string,
                        vctx->user_data.realusername);
                (void)strlcpy(vuurmuurlog_shmtable->configtool.username,
                        vctx->user_data.realusername,
                        sizeof(vuurmuurlog_shmtable->configtool.username));
                vrmr_unlock(vuurmuurlog_semid);

                werase(startup_print_win);
                wprintw(startup_print_win, "%s Vuurmuur_log... %s",
                        STR_CONNECTING_TO, STR_COK);
                update_panels();
                doupdate();
            } else {
                werase(startup_print_win);
                wprintw(startup_print_win, "%s Vuurmuur_log... %s",
                        STR_CONNECTING_TO, STR_CFAILED);
                update_panels();
                doupdate();
                vuurmuurlog_shmp = NULL;
            }
        }
    } else {
        werase(startup_print_win);
        wprintw(startup_print_win, "%s Vuurmuur_log... %s", STR_CONNECTING_TO,
                STR_CFAILED);
        update_panels();
        doupdate();
        vuurmuurlog_shmp = NULL;
    }

    /* cleanup */
    del_panel(startup_panel[0]);
    del_panel(startup_panel[1]);

    destroy_win(startup_print_win);
    destroy_win(startup_win);

    update_panels();
    doupdate();

    return (retval);
}

/*  draw_field_active_mark

    Draws marks before and after the active field. If prev is non-NULL we first
   remove the marks from the previous field.
*/
void draw_field_active_mark(const FIELD *cur, const FIELD *prev,
        WINDOW *formwin, FORM *form, const chtype ch)
{
    int pos_x, pos_y, x, y, off_row, wrk_buff;

    /* safety */
    if (!cur || !formwin || !form)
        return;

    /* if supplied we remove the previous marking */
    if (prev) {
        if (field_info(prev, &y, &x, &pos_y, &pos_x, &off_row, &wrk_buff) < 0)
            return;

        mvwprintw(formwin, pos_y + 1, pos_x, " ");
        mvwprintw(formwin, pos_y + 1, pos_x + x + 3, " ");
    }

    /* draw our marking */
    if (field_info(cur, &y, &x, &pos_y, &pos_x, &off_row, &wrk_buff) < 0)
        return;

    wattron(formwin, ch);
    mvwprintw(formwin, pos_y + 1, pos_x, ">");
    mvwprintw(formwin, pos_y + 1, pos_x + x + 3, "<");
    wattroff(formwin, ch);
    wrefresh(formwin);

    /* restore cursor position */
    pos_form_cursor(form);
    return;
}

/*  copy_field2buf

    copies a buffer to another...

    Will copy for bufsize - 1 to leave space for '\0'.
*/
void copy_field2buf(char *buf, char *fieldbuf, size_t bufsize)
{
    size_t i = 0;

    /* safety */
    if (!buf || !fieldbuf)
        abort();

    /* copy while:
        1. we are inside the target buffers size
        2. we are inside the sources buffer size
    */
    for (i = 0;
            fieldbuf[i] != ' ' && i < bufsize - 1 && i < StrMemLen(fieldbuf);
            i++) {
        buf[i] = fieldbuf[i];
    }
    buf[i] = '\0';
}
