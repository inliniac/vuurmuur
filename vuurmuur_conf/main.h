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

#ifndef __MAIN_H__
#define __MAIN_H__

#include "../config.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include <sys/shm.h>
#include <sys/utsname.h> /* for uname -> stat_sec */
#include <signal.h>
#include <string.h>
#include <strings.h>
#include <sys/time.h> /* for gettimeofday in stat_sec */
#include <sys/wait.h> /* for WIFEXITED macro */
#include <ctype.h>    /* for isdigit() */

#include <vuurmuur.h>

#ifdef HAVE_NC_WIDE_HEADERS
#include <ncursesw/ncurses.h>
#include <ncursesw/menu.h>
#include <ncursesw/panel.h>
#include <ncursesw/form.h>
#else
#include <ncurses.h>
#include <menu.h>
#include <panel.h>
#include <form.h>
#endif /* HAVE_NC_WIDE_HEADERS */

#if !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif
#include <getopt.h>

#ifdef USE_WIDEC
#include <wchar.h>
#endif /* USE_WIDEC */

#include <regex.h>

#include <locale.h> /* for gettext() */
#include "gettext.h"

#include "common_strings.h"
#include "gui.h"

#ifndef LOCALEDIR
#define LOCALEDIR "/usr/share/locale"
#endif /* LOCALEDIR */

#define NLINES 10
#define NCOLS 40

#define VUURMUURCONF_VERSION VUURMUUR_VERSION

/* Initialize all the color pairs */
#define CP_WIN 1
#define CP_WIN_REV 2
#define CP_WIN_MARK 3
#define CP_WIN_FIELD 4

#define CP_WIN_RED 5
#define CP_WIN_RED_REV 6
#define CP_WIN_GREEN 7
#define CP_WIN_GREEN_REV 8
#define CP_WIN_YELLOW 9
#define CP_WIN_MAGENTA 10
#define CP_WIN_CYAN 11

#define CP_BGD 12
#define CP_BGD_REV 13
#define CP_BGD_RED 14
#define CP_BGD_GREEN 15
#define CP_BGD_YELLOW 16
#define CP_BGD_MAGENTA 17
#define CP_BGD_CYAN 18

#define CP_WIN_INIT 19
#define CP_WIN_WARN 20
#define CP_WIN_NOTE 21
#define CP_WIN_NOTE_REV 22

#define CP_RULE_BAR 23

#ifndef MIN
#define MIN(x, y) (((x) < (y)) ? (x) : (y))
#endif

#ifndef MAX
#define MAX(x, y) (((x) < (y)) ? (y) : (x))
#endif

/* Vuurmuur_conf settings


*/
struct vrmr_gui_conf {
    char configfile_location[PATH_MAX];

    char helpfile_location[PATH_MAX];
    char scripts_location[PATH_MAX];

    char newrule_log;
    unsigned int newrule_loglimit;
    unsigned int newrule_logburst; /* set to 2x loglimit */

    unsigned int logview_bufsize;

    char advanced_mode; /* is the interface in advanced mode ? */

    char draw_status; /* draw the status stuff in the main_menu? */

    char iptrafvol_location[128];

    /*
        colors
    */
    int background; /* 0 blue, 1 black */

    /* windows */
    short win_fore;
    short win_back;

    chtype color_win_init;
    chtype color_win_warn;
    chtype color_win_note;
    chtype color_win_note_rev;

    chtype color_win;
    chtype color_win_mark;
    chtype color_win_field;

    chtype color_win_red;
    chtype color_win_red_rev;
    chtype color_win_green;
    chtype color_win_green_rev;
    chtype color_win_yellow;
    chtype color_win_magenta;
    chtype color_win_cyan;

    chtype color_win_rev;
    chtype color_win_rev_yellow;

    /* background */
    short bgd_fore;
    short bgd_back;

    chtype color_bgd;
    chtype color_bgd_hi;
    chtype color_bgd_rev;

    chtype color_bgd_red;
    chtype color_bgd_green;
    chtype color_bgd_yellow;
    chtype color_bgd_magenta;
    chtype color_bgd_cyan;

    chtype color_rule_bar;
};

extern struct vrmr_gui_conf vccnf;

/* setting defaults */
#define VRMR_DEFAULT_NEWRULE_LOG 1
#define VRMR_DEFAULT_NEWRULE_LOGLIMIT 20

#define VRMR_DEFAULT_LOGVIEW_BUFFERSIZE 500

/* default not in advanced mode */
#define VRMR_DEFAULT_ADVANCED_MODE 0

/* default print mainmenu_status */
#define VRMR_DEFAULT_MAINMENU_STATUS 1

#define VRMR_DEFAULT_IPTRAFVOL_LOCATION "/usr/bin/iptrafvol.pl"

struct vrmr_status {
    struct vrmr_list StatusList;

    int vuurmuur;
    int vuurmuur_log;

    int zones;
    int services;
    int interfaces;
    int rules;

    /* connections with vuurmuur and vuurmuur_log */
    int shm;
    /* backend data */
    int backend;
    /* vuurmuur config */
    int config;
    /* vuurmuur_conf settings */
    int settings;
    /* system stuff */
    int system;

    /* this one is checked for the header */
    int overall;

    char have_shape_rules;
    char have_shape_ifaces;
};

extern struct vrmr_status vuurmuur_status;

/* TODO remove this */
extern WINDOW *status_frame_win, *status_win, *top_win, *main_win, *mainlog_win;

/*
    shared memory id and semaphore id
*/

/* vuurmuur */
extern int vuurmuur_shmid;
extern int vuurmuur_semid;
/*@null@*/
extern struct vrmr_shm_table *vuurmuur_shmtable;
extern char *vuurmuur_shmp;
extern pid_t vuurmuur_pid;

/* vuurmuur_log */
extern int vuurmuurlog_shmid;
extern int vuurmuurlog_semid;
extern char *vuurmuurlog_shmp;
/*@null@*/
extern struct vrmr_shm_table *vuurmuurlog_shmtable;
extern pid_t vuurmuurlog_pid;

extern char version_string[128];

extern int utf8_mode;

/*
 *
 * FUNCTION PROTOTYPES
 *
 */

/*
    main
*/
void print_in_middle(WINDOW *win, int starty, int startx, int width,
        const char *string, chtype color);
WINDOW *create_newwin(int height, int width, int starty, int startx,
        /*@null@*/ const char *title, chtype ch);
void destroy_win(WINDOW *local_win);
int startup_screen(struct vrmr_ctx *, struct vrmr_rules *, struct vrmr_zones *,
        struct vrmr_services *, struct vrmr_interfaces *,
        struct vrmr_blocklist *, struct vrmr_regex *);
void draw_field_active_mark(const FIELD *cur, const FIELD *prev,
        WINDOW *formwin, FORM *form, chtype ch);
void copy_field2buf(char *buf, char *fieldbuf, size_t bufsize);
int protectrule_loaded(struct vrmr_list *, char *, char *, char *);
void setup_colors(void);

/*
    topmenu
*/
void draw_top_menu(
        WINDOW *, const char *, int, const char **, int, const char **);

/*
    services section
*/
void services_section(struct vrmr_ctx *, struct vrmr_services *,
        struct vrmr_rules *, struct vrmr_regex *);

/*
    zones section
*/
int zones_section(struct vrmr_ctx *, struct vrmr_zones *,
        struct vrmr_interfaces *, struct vrmr_rules *, struct vrmr_blocklist *,
        struct vrmr_regex *);
int zones_blocklist(struct vrmr_ctx *, struct vrmr_blocklist *,
        struct vrmr_zones *, struct vrmr_regex *);
int zones_blocklist_add_one(struct vrmr_blocklist *, struct vrmr_zones *);

/*
    rules_section
*/
int rules_form(struct vrmr_ctx *, struct vrmr_rules *, struct vrmr_zones *,
        struct vrmr_interfaces *, struct vrmr_services *, struct vrmr_regex *);
int edit_rule(struct vrmr_config *conf, struct vrmr_rules *,
        struct vrmr_zones *, struct vrmr_interfaces *, struct vrmr_services *,
        unsigned int, struct vrmr_regex *);
int edit_rule_normal(struct vrmr_config *conf, struct vrmr_zones *,
        struct vrmr_interfaces *, struct vrmr_services *, struct vrmr_rule *,
        struct vrmr_regex *);
char *VrShapeUnitMenu(char *, int, int, char);

/*
    io
*/
FILE *vuurmuur_rulesfile_open(const char *path, const char *mode, int caller);
int vuurmuur_rulesfile_close(FILE *stream, const char *path);
int write_rulesfile(char *, struct vrmr_rules *);

/*
    templates
*/
int confirm(const char *title, const char *text, chtype forecolor,
        chtype backcolor, int def);
char *input_box(size_t length, const char *title, const char *description);
int vuumuurconf_print_error(int error_no, const char *title, char *fmt, ...)
        ATTR_FMT_PRINTF(3, 4);
int vuumuurconf_print_warning(const char *title, char *fmt, ...)
        ATTR_FMT_PRINTF(2, 3);
int vuumuurconf_print_info(const char *title, char *fmt, ...)
        ATTR_FMT_PRINTF(2, 3);
char *selectbox(const char *title, const char *text, size_t n_choices,
        const char **choices, unsigned int cols, const char *);
int status_print(WINDOW *local_win, /*@null@*/ const char *fmt, ...)
        ATTR_FMT_PRINTF(2, 3);
int check_box(int status, const char *title, const char *description);
/* fixes */
void set_field_buffer_wrap(FIELD *, int, const char *);
FIELD *new_field_wrap(
        int rows, int cols, int frow, int fcol, int nrow, int nbuf);
int form_driver_wrap(FORM *form, int key);

int filter_input_box(struct vrmr_filter *);

/*
    config
*/
int edit_genconfig(struct vrmr_config *);
int edit_logconfig(struct vrmr_config *);
int config_menu(struct vrmr_config *);
int edit_sysopt(struct vrmr_config *);

/*
    logview section
*/
int logview_section(struct vrmr_ctx *, struct vrmr_config *,
        struct vrmr_zones *, struct vrmr_blocklist *, struct vrmr_interfaces *,
        struct vrmr_services *, /*@null@*/ char *);

/*
    interfaces section
*/
void interfaces_section(struct vrmr_ctx *vctx, struct vrmr_interfaces *,
        struct vrmr_zones *, struct vrmr_rules *, struct vrmr_regex *reg);

/*
    navigation
*/
int nav_field_comment(FORM *, int);
int nav_field_simpletext(FORM *, int);
int nav_field_yesno(FORM *, int);
int nav_field_toggleX(FORM *, int);
int validate_commentfield(char *, regex_t *);

/*
    status section
*/
int status_section(struct vrmr_config *, struct vrmr_interfaces *);

/*
    connections
*/
int connections_section(struct vrmr_ctx *, struct vrmr_config *,
        struct vrmr_zones *, struct vrmr_interfaces *, struct vrmr_services *,
        struct vrmr_blocklist *);

/*
    help/status
*/
void print_help(const char *part);
void print_status(void);
int read_helpline(struct vrmr_list *help_list, const char *line);
void setup_statuslist(void);

/*
    config
*/
int init_vcconfig(struct vrmr_config *conf, char *configfile_location,
        struct vrmr_gui_conf *cnf);
int write_vcconfigfile(char *file_location, struct vrmr_gui_conf *cnf);
int edit_vcconfig(void);
void vcconfig_use_defaults(struct vrmr_gui_conf *cnf);

/*
    main menu
*/
int main_menu(struct vrmr_ctx *, struct vrmr_rules *, struct vrmr_zones *,
        struct vrmr_interfaces *, struct vrmr_services *,
        struct vrmr_blocklist *, struct vrmr_regex *);
void mm_status_checkall(struct vrmr_ctx *, struct vrmr_list *,
        struct vrmr_rules *, struct vrmr_zones *, struct vrmr_interfaces *,
        struct vrmr_services *);
int vc_apply_changes(struct vrmr_ctx *);

/*
    bandwidth
*/
int trafvol_section(struct vrmr_config *, struct vrmr_interfaces *);

/*
    about
*/
void print_about(void);

/* statevent */
#define STATEVENTTYPE_LOG 1
#define STATEVENTTYPE_CONN 2

struct log_record {
    char filtered;

    char month[4];
    char date[3];
    char time[10];

    char action[16];

    char service[VRMR_MAX_SERVICE];

    char from[VRMR_MAX_HOST_NET_ZONE];
    char to[VRMR_MAX_HOST_NET_ZONE];

    char prefix[32];

    char details[256];
};

struct conntrack {
    /* hashes for the vuurmuur names */
    struct vrmr_hash_table zone_hash;
    struct vrmr_hash_table service_hash;

    struct vrmr_list network_list;

    struct vrmr_list conn_list;
    /* sorted array of entries. Sorted by cnt */
    struct vrmr_conntrack_entry **conn_array;

    struct vrmr_conntrack_stats conn_stats;

    unsigned int prev_list_size;
};
extern struct conntrack conntrack;

int kill_connections_by_ip(struct conntrack *ct, char *srcip, char *dstip,
        char *sername, char connect_status);
int block_and_kill(struct vrmr_ctx *vctx, struct conntrack *ct,
        struct vrmr_zones *zones, struct vrmr_blocklist *blocklist,
        struct vrmr_interfaces *interfaces, char *ip);
int kill_connection(
        const char *srcip, const char *dstip, int proto, int sp, int dp);
int kill_connections_by_name(struct conntrack *ct, char *srcname, char *dstname,
        char *sername, char connect_status);

struct conntrack *conn_init_ct(struct vrmr_zones *zones,
        struct vrmr_interfaces *interfaces, struct vrmr_services *services);
void conn_free_ct(struct conntrack **ct, struct vrmr_zones *zones);
int conn_ct_get_connections(struct vrmr_config *, struct conntrack *,
        struct vrmr_conntrack_request *);
void conn_ct_clear_connections(struct conntrack *ct);

void statevent(struct vrmr_ctx *, struct vrmr_config *, int, struct vrmr_list *,
        struct conntrack *, struct vrmr_conntrack_request *,
        struct vrmr_zones *, struct vrmr_blocklist *, struct vrmr_interfaces *,
        struct vrmr_services *);

/* length in chars (be it wide chars or normal chars) */
static inline size_t StrLen(const char *s)
{
    return (mbstowcs(NULL, s, 0));
}

/* length in mem regardless of wide/non-wide */
static inline size_t StrMemLen(const char *s)
{
    return (strlen(s));
}

void fix_wide_menu(MENU *, ITEM **);

void form_test(void);

void VrShapeRule(struct vrmr_rule_options *opt);
void VrShapeIface(struct vrmr_ctx *, struct vrmr_interface *iface_ptr);

#ifdef USE_WIDEC
#define wsizeof(s) sizeof(s) / sizeof(wchar_t)
#endif /* USE_WIDEC */

#if !defined(__clang_analyzer__) && !defined(DEBUG) && !defined(CPPCHECK)
#define vrmr_fatal(...)                                                        \
    do {                                                                       \
        char __vrmr_msg[2048];                                                 \
        char __vrmr_loc[512];                                                  \
        char __vrmr_line[2048 + 512];                                          \
                                                                               \
        (void)snprintf(__vrmr_msg, sizeof(__vrmr_msg), __VA_ARGS__);           \
        (void)snprintf(__vrmr_loc, sizeof(__vrmr_loc), "[%s:%d:%s]", __FILE__, \
                __LINE__, __func__);                                           \
        (void)snprintf(__vrmr_line, sizeof(__vrmr_line), "%s %s", __vrmr_loc,  \
                __vrmr_msg);                                                   \
                                                                               \
        vrmr_error(EXIT_FAILURE, gettext("Fatal Error"), "%s", __vrmr_line);   \
        exit(EXIT_FAILURE);                                                    \
    } while (0)

#define vrmr_fatal_alloc(func, ptr)                                            \
    do {                                                                       \
        if ((ptr) == NULL) {                                                   \
            vrmr_fatal("%s: %s", (func), strerror(errno));                     \
        }                                                                      \
    } while (0)

#define vrmr_fatal_if_null(ptr)                                                \
    do {                                                                       \
        if ((ptr) == NULL) {                                                   \
            vrmr_fatal("NULL pointer");                                        \
        }                                                                      \
    } while (0)

#define vrmr_fatal_if(expr)                                                    \
    do {                                                                       \
        if (expr) {                                                            \
            vrmr_fatal("check failed");                                        \
        }                                                                      \
    } while (0)

#else /* __clang_analyzer__ */

#define vrmr_fatal(...) abort()
#define vrmr_fatal_alloc(func, ptr) assert((ptr))
#define vrmr_fatal_if_null(ptr) assert((ptr))
#define vrmr_fatal_if(expr)                                                    \
    do {                                                                       \
        if ((expr))                                                            \
            abort();                                                           \
    } while (0)

#endif /* __clang_analyzer__ */
#endif
