/***************************************************************************
 *   Copyright (C) 2003-2017 by Victor Julien                              *
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


/* LogRule moved to main.h */

struct PlainLogRule_
{
    int filtered;
    char line[512];
};

/*  logline2logrule

    Load a string 'logline' into the 'logrule' struct. We do this for
    pretty printing.
*/
static void
logline2logrule(char *logline, struct LogRule_ *logrule)
{
    size_t  i=0,
            x=0,
            trema=0,
            comma=0;
    char    tempstr[512]="";

    vrmr_fatal_if_null(logline);
    vrmr_fatal_if_null(logrule);

    /* scan the line. Note: 'time' has a ':' as last char, and 'to' has a comma as last char. */
    sscanf(logline, "%3s %2s %9s %s service %s from %s to %s", logrule->month, logrule->date, logrule->time, logrule->action, logrule->service, logrule->from, logrule->to);

    /* remove the semicolon from time */
    logrule->time[StrMemLen(logrule->time)-1] = '\0';

    /* remove the comma from 'to' */
    logrule->to[StrMemLen(logrule->to)-1] = '\0';

    /* store the rest of the rule in tempstr */
    for(i = 0, x = 0; i < StrMemLen(logline) && logline[i] != '\n' && x < sizeof(tempstr)-1; i++)
    {
        if(logline[i] == ',')
            comma = 1;

        if(comma == 1)
        {
            tempstr[x] = logline[i];
            x++;
        }
    }
    tempstr[x] = '\0';

    /* tempstr contains the rest of the rule */
    for(i=0, x=0; tempstr[i] != '(' && x < sizeof(logrule->prefix)-1 && i < StrMemLen(tempstr) ; i++)
    {
        if(tempstr[i] == '"')
            trema++;

        if(trema == 1 && tempstr[i] != '"')
        {
            logrule->prefix[x] =  tempstr[i];
            x++;
        }
    }
    /* terminate the string. If the last char is a white-space remove it. */
    if(x && logrule->prefix[x-1] == ' ')
        logrule->prefix[x-1] = '\0';
    else
        logrule->prefix[x] = '\0';

    /* i is already set above */
    for(x=0; tempstr[i] != '\n' && tempstr[i] != '\0' && i < StrMemLen(tempstr) && x < sizeof(logrule->details)-1; x++, i++)
    {
        logrule->details[x] = tempstr[i];
    }
    logrule->details[x] = '\0';
}

static void
logline2plainlogrule(char *logline, struct PlainLogRule_ *logrule)
{
    vrmr_fatal_if_null(logline);
    vrmr_fatal_if_null(logrule);

    (void)strlcpy(logrule->line, logline, sizeof(logrule->line));
}

/*

    Returncodes:
        0: not filtered
        1: filtered
*/
static int
logrule_filtered(const int debuglvl, struct LogRule_ *log_record, struct vrmr_filter *filter)
{
    char    line[512];

    vrmr_fatal_if_null(log_record);
    vrmr_fatal_if_null(filter);

    /*                            mo da ti  ac se fr to   pr  de */
    snprintf(line, sizeof(line), "%s %s %s: %s %s %s %s, '%s' %s",
                    log_record->month,
                    log_record->date,
                    log_record->time,
                    log_record->action,
                    log_record->service,
                    log_record->from,
                    log_record->to,
                    log_record->prefix,
                    log_record->details);

    /*  check the regex

        If the regex matches, the line is not filtered, so we return 0.
    */
    if (regexec(&filter->reg, line, 0, NULL, 0) == 0) {
        if (filter->neg == FALSE)
            return(0);
        else
            return(1);
    } else {
        if (filter->neg == FALSE)
            return(1);
        else
            return(0);
    }
}

/*
    Returncodes:
        0: not filtered
        1: filtered
*/
static int
plainlogrule_filtered(const int debuglvl, char *line, struct vrmr_filter *filter)
{
    vrmr_fatal_if_null(line);
    vrmr_fatal_if_null(filter);

    /*  check the regex

        If the regex matches, the line is not filtered, so we return 0.
    */
    if(regexec(&filter->reg, line, 0, NULL, 0) == 0) {
        if(filter->neg == FALSE)
            return(0);
        else
            return(1);
    } else {
        if(filter->neg == FALSE)
            return(1);
        else
            return(0);
    }
}

static void
draw_filter(PANEL *pan, WINDOW *win, char *filter)
{
    if(strcmp(filter, "none") == 0) {
        hide_panel(pan);
    } else {
        show_panel(pan);
        wclear(win);
        wprintw(win, gettext("Filter: %s"), filter);
    }
    update_panels();
    doupdate();
}

static void
draw_search(PANEL *pan, WINDOW *win, char *search)
{
    if(strcmp(search, "none") == 0) {
        hide_panel(pan);
    } else {
        show_panel(pan);
        wclear(win);
        wprintw(win, gettext("Search: %s"), search);
    }
    update_panels();
    doupdate();
}

static int
check_search_script(const int debuglvl, const char *script)
{
    struct stat stat_buf;

    vrmr_fatal_if_null(script);

    if(lstat(script, &stat_buf) == -1)
    {
        vrmr_error(-1, VR_ERR,  gettext("checking failed for '%s': %s."), script, strerror(errno));
        return(0);
    }

    /* we wont open symbolic links */
    if(S_ISLNK(stat_buf.st_mode) == 1)
    {
        vrmr_error(-1, VR_ERR, gettext("opening file '%s': For security reasons Vuurmuur will not allow following symbolic-links."), script);
        return(0);
    }

    /* only allow files and dirs */
    if(!S_ISREG(stat_buf.st_mode) && !S_ISDIR(stat_buf.st_mode))
    {
        vrmr_error(-1, VR_ERR, gettext("opening file '%s': For security reasons Vuurmuur will not allow opening anything other than a file or a directory."), script);
        return(0);
    }

    /* if a file is writable by someone other than root, we refuse to open it */
    if(stat_buf.st_mode & S_IWGRP || stat_buf.st_mode & S_IWOTH)
    {
        vrmr_error(-1, VR_ERR, gettext("opening file '%s': For security reasons Vuurmuur will not open files that are writable by 'group' or 'other'. Check the file content & permissions."), script);
        return(0);
    }

    /* we demand that all files are owned by root */
    if(stat_buf.st_uid != 0)
    {
        vrmr_error(-1, VR_ERR, gettext("opening file '%s': For security reasons Vuurmuur will not open files that are not owned by root."), script);
        return(0);
    }

    return(1);
}

static void
print_logrule(WINDOW *log_win, struct LogRule_ *log_record,
        size_t max_logrule_length, size_t cur_logrule_length,
        char hide_date, char hide_action, char hide_service,
        char hide_from, char hide_to, char hide_prefix,
        char hide_details)
{
    size_t  tmpstr_i = 0;
    char    print_str[256] = "";

    if(!hide_date)
    {
        /* DATE/TIME */
        tmpstr_i = StrLen(log_record->month)+1+2+1+StrLen(log_record->time)+1+1; // month, space, day, space, time, semicolon, space, nul
        if(cur_logrule_length + tmpstr_i >= max_logrule_length)
            tmpstr_i = max_logrule_length - cur_logrule_length;
        if(tmpstr_i > sizeof(print_str))
            tmpstr_i = sizeof(print_str);

        snprintf(print_str, tmpstr_i, "%s %2s %s:", log_record->month, log_record->date, log_record->time);
        wprintw(log_win, "%s", print_str);

        cur_logrule_length = cur_logrule_length + tmpstr_i-1;

        // 1 SPACE
        if((cur_logrule_length + 1) < max_logrule_length)
        {
            wprintw(log_win, " ");
            cur_logrule_length = cur_logrule_length + 1;
        }
    }

    if(!hide_action)
    {
        /* ACTION */
        if(strcmp(log_record->action, "DROP") == 0)
            wattron(log_win, vccnf.color_bgd_red | A_BOLD);
        else if(strcmp(log_record->action, "REJECT") == 0)
            wattron(log_win, vccnf.color_bgd_red | A_BOLD);
        else if(strcmp(log_record->action, "ACCEPT") == 0)
            wattron(log_win, vccnf.color_bgd_green | A_BOLD);
        else if(strcmp(log_record->action, "LOG") == 0)
            wattron(log_win, vccnf.color_bgd | A_BOLD);
        else if(strcmp(log_record->action, "SNAT") == 0)
            wattron(log_win, vccnf.color_bgd_yellow | A_BOLD);
        else if(strcmp(log_record->action, "MASQ") == 0)
            wattron(log_win, vccnf.color_bgd_yellow | A_BOLD);
        else if(strcmp(log_record->action, "DNAT") == 0)
            wattron(log_win, vccnf.color_bgd_yellow | A_BOLD);
        else if(strcmp(log_record->action, "BOUNCE") == 0)
            wattron(log_win, vccnf.color_bgd_yellow | A_BOLD);
        else if(strcmp(log_record->action, "PORTFW") == 0)
            wattron(log_win, vccnf.color_bgd_yellow | A_BOLD);
        else if(strcmp(log_record->action, "REDIRECT") == 0)
            wattron(log_win, vccnf.color_bgd_yellow | A_BOLD);
        else
            wattron(log_win, vccnf.color_bgd | A_BOLD);

        tmpstr_i = StrLen(log_record->action)+1;//1 nul, action
        if(tmpstr_i < 8)
            tmpstr_i = 8; /* min 8 because of the %-6s below */
        if(cur_logrule_length + tmpstr_i >= max_logrule_length)
            tmpstr_i = max_logrule_length - cur_logrule_length;
        if(tmpstr_i > sizeof(print_str))
            tmpstr_i = sizeof(print_str);

        snprintf(print_str, tmpstr_i, "%s", log_record->action);
        wprintw(log_win, "%-6s", print_str);

        cur_logrule_length = cur_logrule_length + tmpstr_i-1;

        if(strcmp(log_record->action, "DROP") == 0)
            wattroff(log_win, vccnf.color_bgd_red | A_BOLD);
        else if(strcmp(log_record->action, "REJECT") == 0)
            wattroff(log_win, vccnf.color_bgd_red | A_BOLD);
        else if(strcmp(log_record->action, "ACCEPT") == 0)
            wattroff(log_win, vccnf.color_bgd_green | A_BOLD);
        else if(strcmp(log_record->action, "LOG") == 0)
            wattroff(log_win, vccnf.color_bgd | A_BOLD);
        else if(strcmp(log_record->action, "SNAT") == 0)
            wattroff(log_win, vccnf.color_bgd_yellow | A_BOLD);
        else if(strcmp(log_record->action, "MASQ") == 0)
            wattroff(log_win, vccnf.color_bgd_yellow | A_BOLD);
        else if(strcmp(log_record->action, "DNAT") == 0)
            wattroff(log_win, vccnf.color_bgd_yellow | A_BOLD);
        else if(strcmp(log_record->action, "BOUNCE") == 0)
            wattroff(log_win, vccnf.color_bgd_yellow | A_BOLD);
        else if(strcmp(log_record->action, "PORTFW") == 0)
            wattroff(log_win, vccnf.color_bgd_yellow | A_BOLD);
        else if(strcmp(log_record->action, "REDIRECT") == 0)
            wattroff(log_win, vccnf.color_bgd_yellow | A_BOLD);
        else
            wattroff(log_win, vccnf.color_bgd | A_BOLD);

        // 1 SPACE
        if((cur_logrule_length + 1) < max_logrule_length)
        {
            wprintw(log_win, " ");
            cur_logrule_length = cur_logrule_length + 1;
        }
    }

    if(!hide_service)
    {
        /* SERVICE */
        wattron(log_win, vccnf.color_bgd_cyan|A_BOLD);

        tmpstr_i = StrLen(log_record->service)+1;//1 nul, service
        if(cur_logrule_length + tmpstr_i >= max_logrule_length)
            tmpstr_i = max_logrule_length - cur_logrule_length;
        if(tmpstr_i > sizeof(print_str))
            tmpstr_i = sizeof(print_str);

        snprintf(print_str, tmpstr_i, "%s", log_record->service);
        wprintw(log_win, "%s", print_str);

        cur_logrule_length = cur_logrule_length + tmpstr_i-1;

        wattroff(log_win, vccnf.color_bgd_cyan|A_BOLD);

        /* 2 SPACES */
        if((cur_logrule_length + 2) < max_logrule_length)
        {
            wprintw(log_win, "  ");
            cur_logrule_length = cur_logrule_length + 2;
        }
    }

    if(!hide_from)
    {
        /* FROM */
        if(strncmp(log_record->from, "firewall", 8) == 0)
            wattron(log_win, vccnf.color_bgd_yellow | A_BOLD);
        else
            wattron(log_win, vccnf.color_bgd | A_BOLD);

        tmpstr_i = StrLen(log_record->from)+1;//1 nul, from
        if(cur_logrule_length + tmpstr_i >= max_logrule_length)
            tmpstr_i = max_logrule_length - cur_logrule_length;
        if(tmpstr_i > sizeof(print_str))
            tmpstr_i = sizeof(print_str);

        snprintf(print_str, tmpstr_i, "%s", log_record->from);
        wprintw(log_win, "%s", print_str);

        cur_logrule_length = cur_logrule_length + tmpstr_i-1;

        if(strncmp(log_record->from, "firewall", 8) == 0)
            wattroff(log_win, vccnf.color_bgd_yellow | A_BOLD);
        else
            wattroff(log_win, vccnf.color_bgd | A_BOLD);
    }

    if(!hide_from && !hide_to)
    {
        /* 2 SPACES AND AN ARROW */
        if((cur_logrule_length + 4) < max_logrule_length)
        {
            wprintw(log_win, " -> ");
            cur_logrule_length = cur_logrule_length + 4;
        }
    }

    if(!hide_to)
    {
        /* TO */
        if(strncmp(log_record->to, "firewall", 8) == 0)
            wattron(log_win, vccnf.color_bgd_yellow | A_BOLD);
        else
            wattron(log_win, vccnf.color_bgd | A_BOLD);

        tmpstr_i = StrLen(log_record->to)+1;//1 nul, from
        if(cur_logrule_length + tmpstr_i >= max_logrule_length)
            tmpstr_i = max_logrule_length - cur_logrule_length;
        if(tmpstr_i > sizeof(print_str))
            tmpstr_i = sizeof(print_str);

        snprintf(print_str, tmpstr_i, "%s", log_record->to);
        wprintw(log_win, "%s", print_str);

        cur_logrule_length = cur_logrule_length + tmpstr_i-1;

        if(strncmp(log_record->to, "firewall", 8) == 0)
            wattroff(log_win, vccnf.color_bgd_yellow | A_BOLD);
        else
            wattroff(log_win, vccnf.color_bgd | A_BOLD);
    }

    if(!hide_to || (hide_to && !hide_from))
    {
        /* 2 SPACES */
        if((cur_logrule_length + 2) < max_logrule_length)
        {
            wprintw(log_win, "  ");
            cur_logrule_length = cur_logrule_length + 2;
        }
    }

    if(!hide_prefix)
    {
        /* PREFIX */
        if(strcmp(log_record->prefix, "none") != 0 && strlen(log_record->prefix) > 0)
        {
            wattron(log_win, vccnf.color_bgd_green);

            tmpstr_i = StrLen(log_record->prefix) + 2 + 1;//1 nul, prefix, 2 quotes
            if(cur_logrule_length + tmpstr_i >= max_logrule_length)
                tmpstr_i = max_logrule_length - cur_logrule_length;
            if(tmpstr_i > sizeof(print_str))
                tmpstr_i = sizeof(print_str);

            snprintf(print_str, tmpstr_i, "'%s'", log_record->prefix);
            wprintw(log_win, "%s", print_str);

            cur_logrule_length = cur_logrule_length + tmpstr_i - 1;

            wattroff(log_win, vccnf.color_bgd_green);

            // 1 SPACE (only if we have a prefix)
            if((cur_logrule_length + 1) < max_logrule_length)
            {
                wprintw(log_win, " ");
                cur_logrule_length = cur_logrule_length + 1;
            }
        }
    }

    if(!hide_details)
    {
        /* DETAILS */
        tmpstr_i = StrLen(log_record->details)+1+1; //1 nul, details, newline
        if(cur_logrule_length + tmpstr_i >= max_logrule_length)
            tmpstr_i = max_logrule_length - cur_logrule_length;
        if(tmpstr_i > sizeof(print_str))
            tmpstr_i = sizeof(print_str);

        snprintf(print_str, tmpstr_i, "%s", log_record->details);
        wprintw(log_win, "%s", print_str);

        //cur_logrule_length = cur_logrule_length + tmpstr_i-1;
    }

    wprintw(log_win, "\n");
}

static void
print_plainlogrule(WINDOW *log_win, char *line,
            size_t max_logrule_length, size_t cur_logrule_length)
{
    size_t memlen = StrMemLen(line)+2;
#ifdef USE_WIDEC
    size_t  scrlen = StrLen(line)+2;
    if (memlen != scrlen) { /* this only happens with utf-8 strings */
        wchar_t wprint_str[scrlen];

        if (cur_logrule_length + scrlen >= max_logrule_length)
            scrlen = max_logrule_length - cur_logrule_length;
        if (scrlen > sizeof(wprint_str))
            scrlen = sizeof(wprint_str);

        mbstowcs(wprint_str, line, scrlen - 1);
        if (wprint_str[wcslen(wprint_str)-1] == L'\n') {
            wprint_str[wcslen(wprint_str)-1] = L'\0';
        }
        wprintw(log_win, "%ls\n", wprint_str);
    }
    else
#endif /* USE_WIDEC */
    {
        char print_str[256];

        if (cur_logrule_length + memlen >= max_logrule_length)
            memlen = max_logrule_length - cur_logrule_length;
        if (memlen > sizeof(print_str))
            memlen = sizeof(print_str);

        snprintf(print_str, memlen, "%s", line);
        if (print_str[StrMemLen(print_str)-1] == '\n') {
            print_str[StrMemLen(print_str)-1] = '\0';
        }

        wprintw(log_win, "%s\n", print_str);
    }
}

static void
sanitize_search_str(const int debuglvl, char *str, size_t size)
{
    size_t  i = 0;

    for(i = 0; i < size; i++)
    {
        if(str[i] == '\'')
            str[i] = '_';
        else if(str[i] == '\"')
            str[i] = '_';
    }
}

#define READLINE_LEN    512

int
logview_section(const int debuglvl, struct vrmr_ctx *vctx,
        struct vrmr_config *cnf, struct vrmr_zones *zones,
        struct vrmr_blocklist *blocklist, struct vrmr_interfaces *interfaces,
        struct vrmr_services *services, /*@null@*/ char *logname)
{
    WINDOW          *log_win = NULL,
                    *wait_win = NULL,
                    *filter_ib_win = NULL,
                    *search_ib_win = NULL;

    PANEL           *my_panels[1],
                    *wait_panels[1],
                    *info_bar_panels[2];

    struct vrmr_list          LogBufferList,
                    SearchBufferList,
                    *buffer_ptr = NULL;
    unsigned int    max_buffer_size = vccnf.logview_bufsize; // default

    unsigned int    i = 0;
    int             quit = 0,
                    ch = 0;

    FILE            *fp = NULL,
                    *traffic_fp = NULL,
                    *search_pipe = NULL;

    size_t          linelen = 0;
    char            *line = NULL,

                    *logfile = NULL,

                    /* infobar stuff */
                    search[32] = "none";

    char            use_filter = FALSE;

    struct vrmr_list_node     *d_node = NULL;

    int             max_onscreen=0;
    unsigned int    offset=0,
                    buffer_size=0,
                    start_print=0,
                    page=0;
    int             max_height = 0,
                    max_width = 0;

    char            hide_date = 0,
                    hide_action = 0,
                    hide_service = 0,
                    hide_from = 0,
                    hide_to = 0,
                    hide_prefix = 0,
                    hide_details = 0;

    struct
    {
        int print; // do we print to screen this run?
        int sleep; // do we sleep this run
        int queue; // do we queue this one
        int pause;
    }  control =
    {
        0,
        0,
        0,
        0,
    };

    struct LogRule_         *log_record = NULL;
    struct PlainLogRule_    *plainlog_record = NULL;

    size_t                  max_logrule_length=0,
                            cur_logrule_length=0;

    struct vrmr_filter      vfilter;

    int                     done = 0,
                            first_logline_done = 0,
                            filtered_lines = 0;

    unsigned int            run_count = 0;
    int                     delta = 0;
    unsigned int            first_draw = 0;
    int                     drawn_lines = 0;

    off_t                   logfile_size = 0;
    long                    logfile_fseek_offset = 0;

    /* search */
    char                    search_mode = 0;
    char                    search_stop = 0,
                            search_completed = 0,
                            search_error = 0;
    unsigned long           search_results = 0;

    char                    *search_ptr = NULL,
                            search_string[512] = "";

    char                    search_script_checked = 0,
                            search_script_ok = 0;

    /* is the current log the trafficlog? */
    char                    traffic_log = FALSE;

    /* top menu */
    char                    *key_choices[] =    {   "F12",
                                                    "m",
                                                    "s",
                                                    "f",
                                                    "p",
                                                    "c",
                                                    "1-7",
                                                    "F10"};
    int                     key_choices_n = 8;
    char                    *cmd_choices[] =    {   gettext("help"),
                                                    gettext("manage"),
                                                    gettext("search"),
                                                    gettext("filter"),
                                                    gettext("pause"),
                                                    gettext("clear"),
                                                    gettext("hide"),
                                                    gettext("back")};
    int                     cmd_choices_n = 8;

    /* nt = no trafficlog: hide "1-7 hide" and manage options for
     * non-trafficlogs */
    char                    *nt_key_choices[] =     {   "F12",
                                                        "s",
                                                        "f",
                                                        "p",
                                                        "c",
                                                        "F10"};
    int                     nt_key_choices_n = 6;
    char                    *nt_cmd_choices[] =     {   gettext("help"),
                                                        gettext("search"),
                                                        gettext("filter"),
                                                        gettext("pause"),
                                                        gettext("clear"),
                                                        gettext("back")};
    int                     nt_cmd_choices_n = 6;

    /* stat buffer, for checking the file size of the traffic-log */
    struct stat             stat_buf;


    /* safety */
    vrmr_fatal_if_null(zones);
    vrmr_fatal_if_null(blocklist);

    /* init filter */
    vrmr_filter_setup(debuglvl, &vfilter);

    /* if no logfile is supplied, we assume trafficlog */
    if (!logname) {
        traffic_log = 1;
        logfile = vctx->conf.trafficlog_location;
        logname = "traffic.log";
    } else {
        if(strcmp(logname, "error.log") == 0)
        {
            logfile = vctx->conf.errorlog_location;
        }
        else if(strcmp(logname, "vuurmuur.log") == 0)
        {
            logfile = vctx->conf.vuurmuurlog_location;
        }
        else if(strcmp(logname, "audit.log") == 0)
        {
            logfile = vctx->conf.auditlog_location;
        }
        else if(strcmp(logname, "debug.log") == 0)
        {
            logfile = vctx->conf.debuglog_location;
        }
        else if(strcmp(logname, "traffic.log") == 0)
        {
            traffic_log = 1;
            logfile = vctx->conf.trafficlog_location;
        }
        else {
            vrmr_fatal("unknown logfile '%s'", logname);
        }
    }

    /* setup the buffer */
    vrmr_list_setup(debuglvl, &LogBufferList, free);
    /* point the buffer pointer to the LogBufferList */
    buffer_ptr = &LogBufferList;

    /* begin with the traffic log */
    traffic_fp = fopen(logfile, "r");
    if (traffic_fp == NULL) {
        vrmr_error(-1, VR_ERR, gettext("opening logfile '%s' failed: %s."), vctx->conf.trafficlog_location, strerror(errno));
        vrmr_list_cleanup(debuglvl, buffer_ptr);
        return(-1);
    }
    /* point it to the fp */
    fp = traffic_fp;

    if(debuglvl >= LOW)
        vrmr_debug(__FUNC__, "opening '%s' successful.", vctx->conf.trafficlog_location);

    /* set up the logwin */
    getmaxyx(stdscr, max_height, max_width);
    max_logrule_length = (size_t)(max_width - 2);
    max_onscreen = max_height - 8;
    /* check if the buffersize is sane */
    if (max_buffer_size < (unsigned int)max_onscreen)
        max_buffer_size = (unsigned int)max_onscreen;

    /*  get the size of the logfile and check if were asking to much of
        fseek. If so, ask less. */
    if (stat(logfile, &stat_buf) == -1) {
        vrmr_error(-1, VR_ERR, gettext("could not examine the logfile: %s."), strerror(errno));
        vrmr_list_cleanup(debuglvl, buffer_ptr);
        fclose(fp);
        return(-1);
    }

    logfile_size = stat_buf.st_size;
    logfile_fseek_offset = (int)max_buffer_size * READLINE_LEN * -1;
    if (logfile_fseek_offset < (logfile_size * -1))
        logfile_fseek_offset = logfile_size * -1;

    /* listen at the logfile_fseek_offset point in the file, so we start with a populated buffer */
    if (fseek(fp, logfile_fseek_offset, SEEK_END) < 0) {
        vrmr_error(-1, VR_ERR, gettext("fseek failed: %s."), strerror(errno));
        vrmr_list_cleanup(debuglvl, buffer_ptr);
        fclose(fp);
        return(-1);
    }
    status_print(status_win, gettext("Loading loglines into memory (trying to load %u lines)..."), max_buffer_size);

    /* create a little wait dialog */
    wait_win = create_newwin(5, 40, (max_height-5)/2, (max_width-40)/2,
            gettext("One moment please..."), vccnf.color_win);
    vrmr_fatal_if_null(wait_win);
    wait_panels[0] = new_panel(wait_win);

    /* print the topmenu options: the nt_ functions are for non-trafficlog use */
    if (traffic_log == 1) {
        draw_top_menu(debuglvl, top_win, gettext("Logview"), key_choices_n, key_choices, cmd_choices_n, cmd_choices);
    } else {
        draw_top_menu(debuglvl, top_win, gettext("Logview"), nt_key_choices_n, nt_key_choices, nt_cmd_choices_n, nt_cmd_choices);
    }
    mvwprintw(wait_win, 2, 4, gettext("Loading log ..."));
    update_panels();
    doupdate();

    /*
        load the initial lines
    */
    while (!done)
    {
        /* read line from log */
        line = malloc(READLINE_LEN);
        vrmr_fatal_alloc("malloc", line);

        if (fgets(line, READLINE_LEN, fp) == NULL) {
            /* free the alloced line */
            free(line);
            break;
        }

        /*  ignore the first line we read for it shall almost certainly be broken
            because of fseek. */
        if (!first_logline_done) {
            first_logline_done = 1;
            free(line);
            continue;
        }

        /*
           if the line doesn't end with a newline character we rewind and try again.
         */
        linelen = StrMemLen(line);
        if (linelen < READLINE_LEN-1 && line[linelen - 1] != '\n') {
            (void)fseek(fp, (long)(StrMemLen(line)*-1), SEEK_CUR);
            free(line);
            /* done because we reached the end of the file which does not have a newline */
            break;
        }

        /*
           insert the line into the buffer list
         */
        if (traffic_log) {
            /* here we can analyse the rule */
            log_record = malloc(sizeof(struct LogRule_));
            vrmr_fatal_alloc("malloc", log_record);

            /* start not filtered (was filtered) */
            log_record->filtered = 0;

            logline2logrule(line, log_record);

            /* now insert the rule */
            vrmr_fatal_if(vrmr_list_append(debuglvl, buffer_ptr, log_record) == NULL);

            /* if the bufferlist is full, remove the oldest item from it */
            if(buffer_ptr->len > max_buffer_size) {
                vrmr_fatal_if(vrmr_list_remove_top(debuglvl, buffer_ptr) < 0);
            }

            log_record = NULL;
            control.queue++;

        } else {
            /* here we can analyse the rule */
            plainlog_record = malloc(sizeof(struct PlainLogRule_));
            vrmr_fatal_alloc("malloc", plainlog_record);

            /* start not filtered (was filtered) */
            plainlog_record->filtered = 0;

            logline2plainlogrule(line, plainlog_record);

            /* now insert the rule */
            vrmr_fatal_if(vrmr_list_append(debuglvl, buffer_ptr, plainlog_record) == NULL);

            /* if the bufferlist is full, remove the oldest item from it */
            if (buffer_ptr->len > max_buffer_size) {
                vrmr_fatal_if(vrmr_list_remove_top(debuglvl, buffer_ptr) < 0);
            }

            plainlog_record = NULL;
            control.queue++;
        }

        /* free the line string, we don't need it anymore */
        free(line);
    }
    status_print(status_win, gettext("Loading loglines into memory... loaded %d lines."), buffer_ptr->len);

    /*
        destroy the wait dialog
    */
    del_panel(wait_panels[0]);
    destroy_win(wait_win);

    /* create the info bar window, start hidden */
    filter_ib_win = newwin(1, 32, 3, 2); /* 32 + filter: */
    vrmr_fatal_if_null(filter_ib_win);
    wbkgd(filter_ib_win, vccnf.color_win);
    info_bar_panels[0] = new_panel(filter_ib_win);
    hide_panel(info_bar_panels[0]);

    /* create the info bar window, start hidden */
    search_ib_win = newwin(1, 32, 3, max_width-32-2); /* 32 + filter: */
    vrmr_fatal_if_null(search_ib_win);
    wbkgd(search_ib_win, vccnf.color_win);
    info_bar_panels[1] = new_panel(search_ib_win);
    hide_panel(info_bar_panels[1]);

    /* create the log window */
    log_win = newwin(max_height-8, max_width-2, 4, 1);
    vrmr_fatal_if_null(log_win);
    wbkgd(log_win, vccnf.color_bgd);
    my_panels[0] = new_panel(log_win);

    /* print initial banner */
    wprintw(log_win, gettext("Logview starting.\n"));

    /* make sure wgetch doesn't block */
    nodelay(log_win, TRUE);
    keypad(log_win, TRUE);
    update_panels();
    doupdate();

    /* the main loop */
    while(quit == 0)
    {
        /* read line from log */
        line = malloc(READLINE_LEN);
        vrmr_fatal_alloc("malloc", line);

        /* read a line if we are not in pause mode */
        if(!control.pause && fgets(line, READLINE_LEN, fp) != NULL)
        {
            linelen = StrMemLen(line);

            /* if the line doesn't end with a newline character we rewind and try again the next run. */
            if(linelen < READLINE_LEN-1 && line[linelen - 1] != '\n') {
                (void)fseek(fp, (long)(linelen * -1), SEEK_CUR);
                free(line);
                line = NULL;
            } else if(search_mode) {
                if (strncmp(line, "SL:EOF:", 7) == 0) {
                    search_completed = 1;
                } else if(strncmp(line, "SL:ERROR:", 9) == 0) {
                    search_error = 1;
                    search_completed = 1;
                    line[StrMemLen(line)-2] = '\0';
                    vrmr_error(-1, VR_ERR, "%s", line);
                } else {
                    search_results++;
                }

                if (search_completed) {
                    /* if we bail out here it's because of an EOF or ERROR
                       and we are not interested in the line. So free it. */
                    free(line);
                    line = NULL;
                }
            }

            /* insert the line into the buffer list */
            if (line) {
                if (traffic_log) {
                    /* here we can analyse the rule */
                    log_record = malloc(sizeof(struct LogRule_));
                    vrmr_fatal_alloc("malloc", log_record);

                    /* we asume unfiltered (was filtered) */
                    log_record->filtered = 0;

                    /* convert the raw line to our data structure */
                    logline2logrule(line, log_record);

                    /* if we have a filter check it now */
                    if (use_filter) {
                        log_record->filtered = logrule_filtered(debuglvl, log_record, &vfilter);
                    }

                    /* now really insert the rule into the buffer */
                    vrmr_fatal_if(vrmr_list_append(debuglvl, buffer_ptr, log_record) == NULL);

                    /* if the bufferlist is full, remove the oldest item from it */
                    if (buffer_ptr->len > max_buffer_size) {
                        vrmr_fatal_if(vrmr_list_remove_top(debuglvl, buffer_ptr) < 0);
                    }

                    control.queue++;
                    log_record = NULL;
                }
                else
                {
                    /* here we can analyse the rule */
                    plainlog_record = malloc(sizeof(struct PlainLogRule_));
                    vrmr_fatal_alloc("malloc", plainlog_record);

                    /* we asume unfiltered (was filtered) */
                    plainlog_record->filtered = 0;

                    logline2plainlogrule(line, plainlog_record);

                    /* if we have a filter check it now */
                    if(use_filter) {
                        plainlog_record->filtered = plainlogrule_filtered(debuglvl, plainlog_record->line, &vfilter);
                    }

                    /* now insert the rule */
                    vrmr_fatal_if(vrmr_list_append(debuglvl, buffer_ptr, plainlog_record) == NULL);

                    /* if the bufferlist is full, remove the oldest item from it */
                    if (buffer_ptr->len > max_buffer_size) {
                        vrmr_fatal_if(vrmr_list_remove_top(debuglvl, buffer_ptr) < 0);
                    }

                    plainlog_record = NULL;
                    control.queue++;
                }

                /* free the line string, we don't need it anymore */
                free(line);
            }
        }
        /*  no line read

            This means we have to sleep for a little while.
        */
        else {
            /* free the allocated buffer */
            free(line);
            line = NULL;

            /* so we sleep, */
            control.sleep = 1;
            /* unless we still have a queue! */
            if (control.queue > 0)
                control.print = 1;
        }

        /* handle the search mode */
        if (search_mode) {
            /* emergengy search stop */
            if(search_stop) {
                search_completed = 1;
            }

            /*  if the search is completed we have to do two things:
                1. cleanup search stuff so we can return to normal logging
                2. inform the user

                One thing is not done here: we don't clean the buffer and
                we dont restore the bufferpointer to the LogBufferList
                This is done only after the user disables the pause mode.

                The reason for this is that we want to be able to scroll
                through the search results.
            */
            if(search_completed) {
                /* close the pipe */
                if(pclose(search_pipe) < 0)
                {
                    vrmr_error(-1, VR_ERR, gettext("closing search pipe failed: %s."), strerror(errno));
                }

                /* restore file pointer */
                fp = traffic_fp;

                /* disable search_mode */
                search_mode = 0;

                /* print the result */
                if(search_stop)
                {
                    status_print(status_win, gettext("Search canceled. Press SPACE to return to normal logging."));
                    search_stop = 0;
                }
                else if(search_error)
                {
                    status_print(status_win, gettext("Search ERROR. Press SPACE to return to normal logging."));
                    search_error = 0;
                }
                else
                {
                    status_print(status_win, gettext("Search done: %lu matches. Press SPACE to return to normal logging."), search_results);
                }

                /* pause to leave the results on screen */
                control.pause = 1;

                /* finally free the search ptr */
                free(search_ptr);
                search_ptr = NULL;

                /* reset counter */
                search_results = 0;

                /* clear for the infobar */
                (void)strlcpy(search, "none", sizeof(search));

                /* hide the search panel */
                draw_search(info_bar_panels[1], search_ib_win, search);
            }
        }


        /* get the users input */
        ch = wgetch(log_win);
        switch(ch)
        {
            /* scrolling */
            case KEY_UP:
                offset++;
                control.print = 1;
                break;

            case KEY_DOWN:
                if(offset)
                    offset--;
                control.print = 1;
                break;

            case KEY_PPAGE:
                offset = offset + max_onscreen - 1;
                control.print = 1;
                break;

            case KEY_NPAGE:
                page = max_onscreen - 1;
                if(page > offset)
                    offset = 0;
                else
                    offset = offset - page;
                control.print = 1;
                break;

            case 262: /* home */
                offset = buffer_ptr->len;
                control.print = 1;
                break;

            case 360: /* end */
                offset = 0;
                control.print = 1;
                break;

            /* filter */
            case 'f':
            case 'F':
            case 10:

                if (ch != 10) {
                    filter_input_box(debuglvl, &vfilter);
                } else {
                    vrmr_filter_cleanup(debuglvl, &vfilter);
                }

                if(vfilter.reg_active == TRUE)
                {
                    status_print(status_win, gettext("Active filter: '%s' (press 'enter' to clear)."), vfilter.str);
                    use_filter = TRUE;
                }
                else if(use_filter == TRUE && vfilter.reg_active == FALSE)
                {
                    status_print(status_win, gettext("Filter removed."));
                    use_filter = FALSE;
                }

                if(use_filter == TRUE)
                {
                    /* draw (or hide) the filter panel */
                    draw_filter(info_bar_panels[0], filter_ib_win, vfilter.str);
                }
                else
                {
                    /* draw (or hide) the filter panel */
                    draw_filter(info_bar_panels[0], filter_ib_win, "none");
                }

                /* create a little wait dialog */
                wait_win = create_newwin(5, 40, (max_height-5)/2, (max_width-40)/2, gettext("One moment please..."), vccnf.color_win);
                vrmr_fatal_if_null(wait_win);
                wait_panels[0] = new_panel(wait_win);
                mvwprintw(wait_win, 2, 2, gettext("Applying changed filter..."));
                update_panels();
                doupdate();

                for (d_node = buffer_ptr->top; d_node; d_node = d_node->next)
                {
                    if (traffic_log) {
                        vrmr_fatal_if_null(d_node->data);
                        log_record = d_node->data;

                        if (use_filter) {
                            log_record->filtered = logrule_filtered(debuglvl, log_record, &vfilter);
                        } else {
                            log_record->filtered = 0;
                        }
                    } else {
                        vrmr_fatal_if_null(d_node->data);
                        plainlog_record = d_node->data;

                        if(use_filter) {
                            plainlog_record->filtered = plainlogrule_filtered(debuglvl, plainlog_record->line, &vfilter);
                        } else {
                            plainlog_record->filtered = 0;
                        }
                    }
                }

                /* destroy the wait dialog */
                del_panel(wait_panels[0]);
                destroy_win(wait_win);
                control.print = 1;
                offset = 0;
                break;

            /* clear the screen */
            case 'c':

                werase(log_win);
                vrmr_fatal_if(vrmr_list_cleanup(debuglvl, buffer_ptr) < 0);
                vrmr_list_setup(debuglvl, buffer_ptr, free);
                control.print = 1;
                break;

            /* quit */
            case 27:
            case 'q':
            case 'Q':
            case KEY_F(10):

                if(search_mode) {
                    status_print(status_win, gettext("Search in progress. Press 'S' to stop current search."));
                    usleep(600000);
                } else if(search_completed) {
                    status_print(status_win, gettext("Please first close the current search by pressing SPACE."));
                    usleep(600000);
                } else {
                    quit = 1;
                }
                break;

            /* pause the logging or searching */
            case 'p':
            case 32: /* spacebar */

                if (control.pause == 1) {
                    /* here we do the final cleanup for the search mode. */
                    if(search_completed) {
                        /* cleanup the buffer */
                        vrmr_fatal_if(vrmr_list_cleanup(debuglvl, buffer_ptr) < 0);

                        /* restore buffer pointer */
                        buffer_ptr = &LogBufferList;
                        search_completed = 0;
                        control.print = 1;
                        control.pause = 0;
                    }

                    if(!search_mode)
                        status_print(status_win, gettext("Continue viewing the log."));
                    else
                        status_print(status_win, gettext("Continue searching."));

                    control.pause = 0;
                }
                else
                {
                    control.pause = 1;
                    control.sleep = 1;

                    /* search_mode has it's own way of letting the user know
                       that a search is paused. */
                    if(!search_mode)
                        status_print(status_win, gettext("*** PAUSED *** (press 'p' to continue)"));
                }
                break;

            case '1': /* one */
                if (traffic_log == 1) {
                    if (hide_date == 0)
                        hide_date = 1;
                    else
                        hide_date = 0;

                    status_print(status_win, "%s: %s.",
                            STR_THE_DATE_IS_NOW,
                            hide_date ? gettext("hidden") : gettext("visible"));
                    control.print = 1;
                } else {
                    vrmr_warning(VR_WARN, STR_LOGGING_OPTS_NOT_AVAIL);
                }
                break;

            case '2':
                if (traffic_log == 1) {
                    if (hide_action == 0)
                        hide_action = 1;
                    else
                        hide_action = 0;

                    status_print(status_win, "%s: %s.",
                            STR_THE_ACTION_IS_NOW,
                            hide_action ? gettext("hidden") : gettext("visible"));
                    control.print = 1;
                } else {
                    vrmr_warning(VR_WARN, STR_LOGGING_OPTS_NOT_AVAIL);
                }
                break;

            case '3':
                if(traffic_log == 1) {
                    if (hide_service == 0)
                        hide_service = 1;
                    else
                        hide_service = 0;

                    status_print(status_win, "%s: %s.",
                            STR_THE_SERVICE_IS_NOW,
                            hide_service ? gettext("hidden") : gettext("visible"));
                    control.print = 1;
                } else {
                    vrmr_warning(VR_WARN, STR_LOGGING_OPTS_NOT_AVAIL);
                }
                break;

            case '4':
                if (traffic_log == 1) {
                    if (hide_from == 0)
                        hide_from = 1;
                    else
                        hide_from = 0;

                    status_print(status_win, "%s: %s.",
                            STR_THE_SOURCE_IS_NOW,
                            hide_from ? gettext("hidden") : gettext("visible"));
                    control.print = 1;
                } else {
                    vrmr_warning(VR_WARN, STR_LOGGING_OPTS_NOT_AVAIL);
                }
                break;

            case '5':
                if (traffic_log == 1) {
                    if (hide_to == 0)
                        hide_to = 1;
                    else
                        hide_to = 0;

                    status_print(status_win, "%s: %s.",
                            STR_THE_DESTINATION_IS_NOW,
                            hide_to ? gettext("hidden") : gettext("visible"));
                    control.print = 1;
                } else {
                    vrmr_warning(VR_WARN, STR_LOGGING_OPTS_NOT_AVAIL);
                }
                break;

            case '6':
                if (traffic_log == 1) {
                    if (hide_prefix == 0)
                        hide_prefix = 1;
                    else
                        hide_prefix = 0;

                    status_print(status_win, "%s: %s.",
                            STR_THE_PREFIX_IS_NOW,
                            hide_prefix ? gettext("hidden") : gettext("visible"));
                    control.print = 1;
                } else {
                    vrmr_warning(VR_WARN, STR_LOGGING_OPTS_NOT_AVAIL);
                }
                break;

            case '7':
                if (traffic_log == 1) {
                    if (hide_details == 0)
                        hide_details = 1;
                    else
                        hide_details = 0;

                    status_print(status_win, "%s: %s.",
                            STR_THE_DETAILS_ARE_NOW,
                            hide_details ? gettext("hidden") : gettext("visible"));
                    control.print = 1;
                } else {
                    vrmr_warning(VR_WARN, STR_LOGGING_OPTS_NOT_AVAIL);
                }
                break;

            /* search */
            case 's':

                if (search_mode) {
                    status_print(status_win, gettext("Already searching. Press 'S' to stop current search."));
                    usleep(600000);
                } else if(search_completed) {
                    status_print(status_win, gettext("Please first close the current search by pressing SPACE."));
                    usleep(600000);
                } else {
                    if(!search_script_checked) {
                        /* check if the search script exists */
                        snprintf(search_string, sizeof(search_string), "%s/vuurmuur-searchlog.sh", vccnf.scripts_location);
                        if(check_search_script(debuglvl, search_string) != 1) {
                            search_script_ok = 0;
                        } else {
                            search_script_ok = 1;
                        }
                        search_script_checked = 1;
                    }

                    /* search already checked */
                    if(search_script_ok) {
                        if((search_ptr = input_box(32, gettext("Search"), gettext("What do you want to search for?"))))
                        {
                            /* regex check the search-string */
                            sanitize_search_str(debuglvl, search_ptr, strlen(search_ptr));

                            /* setup the search-buffer */
                            vrmr_list_setup(debuglvl, &SearchBufferList, free);

                            /* point the buffer-pointer to the SearchBufferList */
                            buffer_ptr = &SearchBufferList;

                            /* temp store the traffic pointer */
                            traffic_fp = fp;

                            /* assemble search string => ignore stderr because it messes up the screen */
                            snprintf(search_string, sizeof(search_string), "/bin/bash %s/vuurmuur-searchlog.sh %s %s/ '%s' 2>/dev/null", vccnf.scripts_location, logname, vctx->conf.vuurmuur_logdir_location, search_ptr);
                            vrmr_debug(__FUNC__, "search_string: '%s'.", search_string);

                            /* open the pipe */
                            if(!(search_pipe = popen(search_string, "r")))
                            {
                                vrmr_error(-1, VR_ERR, gettext("opening pipe failed: %s."), strerror(errno));
                                return(-1);
                            }

                            /* set the file pointer to the search_pipe */
                            fp = search_pipe;

                            /* we are in search-mode */
                            search_mode = 1;

                            status_print(status_win, gettext("Search started. Press 'S' to stop searching."));
                            control.print = 1;

                            /* copy the search term for the infobar */
                            (void)strlcpy(search, search_ptr, sizeof(search));

                            /* draw the search panel */
                            draw_search(info_bar_panels[1], search_ib_win, search);
                        }
                    } else {
                        vrmr_error(-1, VR_ERR, gettext("search script was not ok, search is disabled."));
                    }
                }
                break;

            /* emergency search stop */
            case 'S':

                if (search_mode)
                    search_stop = 1;
                else
                    status_print(status_win, gettext("No search in progress."));
                break;

            /* blocklist add */
            case 'b':
            case 'B':

                (void)zones_blocklist_add_one(debuglvl, blocklist, zones);
                (void)vrmr_blocklist_save_list(debuglvl, vctx, &vctx->conf, blocklist);
                break;

            case 'm':
            case 'M': {
                if (buffer_ptr) {
                    statevent(debuglvl, vctx, cnf, STATEVENTTYPE_LOG,
                        buffer_ptr, /* no ct */NULL,
                        /* no connreq*/NULL,
                        zones, blocklist, interfaces,
                        services);

                    draw_top_menu(debuglvl, top_win,
                        gettext("Logview"), key_choices_n,
                        key_choices, cmd_choices_n,
                        cmd_choices);
                }
                break;
            }
            case KEY_F(12):
            case 'h':
            case 'H':
            case '?':

                print_help(debuglvl, ":[VUURMUUR:LOGVIEW]:");
                break;

        } /* end switch(ch) */

        /* update buffer size */
        buffer_size = buffer_ptr->len;

        /* offset cannot be smaller than 0, or bigger than buffer_size - max_onscreen */
        if (!use_filter) {
            if (offset != 0 && offset > (buffer_size - max_onscreen))
                offset = buffer_size - max_onscreen;

            if (max_onscreen >= (int)buffer_size)
                start_print = 0;
            else
                start_print = buffer_size - max_onscreen - offset;

            if(debuglvl >= HIGH)
                status_print(status_win, "buf_size: %u, max_onscr: %d, start: %d, o: %u, p: %d, q: %d, s: %d", buffer_size, max_onscreen, start_print, offset, control.print, control.queue, control.sleep);
        }
        /* if we're filtered, check for each line if it will be printed */
        else {
            for (d_node = buffer_ptr->bot, run_count = 0, delta = 0, filtered_lines = 0;
                 run_count < buffer_size;
                 d_node = d_node->prev, run_count++)
            {
                if (traffic_log) {
                    vrmr_fatal_if_null(d_node->data);
                    log_record = d_node->data;

                    if (log_record->filtered == 0) {
                        delta++;
                        first_draw = buffer_size - run_count - 1;
                    } else {
                        filtered_lines++;
                    }
                } else {
                    vrmr_fatal_if_null(d_node->data);
                    plainlog_record = d_node->data;

                    if (plainlog_record->filtered == 0) {
                        delta++;
                        first_draw = buffer_size - run_count - 1;
                    } else {
                        filtered_lines++;
                    }
                }

                if(delta == (int)(max_onscreen + offset)) {
                    break;
                }
            }
            start_print = first_draw;
            if (delta < max_onscreen)
                offset = 0;

            if(debuglvl >= HIGH)
                status_print(status_win, "filter :st: %d, max: %d, buf: %u, del: %d, fil: %d, run: %d, fir: %d, offset: %u", start_print, max_onscreen, buffer_size, delta, filtered_lines, run_count, first_draw, offset);
        }

        /* if the queue is getting too full, print */
        if (control.queue > (max_onscreen/3))
            control.print = 1;

        /* display counters for debuging */
        if(debuglvl >= LOW)
            status_print(status_win, "buf_size: %u, max_onscr: %d, start: %d, o: %u, p: %d, q: %d, s: %d", buffer_size, max_onscreen, start_print, offset, control.print, control.queue, control.sleep);

        /* print the list to the screen */
        if (control.print) {
            /* update the results printer if in search_mode - we do this here because we come here less often because of
               the queue. */
            if (search_mode) {
                if(!control.pause)
                    status_print(status_win, gettext("Search in progress: %lu matches so far. SPACE to pause, 'S' to stop."), search_results);
                else
                    status_print(status_win, gettext("Search PAUSED: %lu matches so far. SPACE to continue, 'S' to stop."), search_results);
            }
            /* clear the screen */
            werase(log_win);

            /* start the loop */
            for (i = 0, d_node = buffer_ptr->top, drawn_lines = 0; d_node ; d_node = d_node->next, i++)
            {
                if(i >= start_print && drawn_lines < max_onscreen) {
                    cur_logrule_length = 0;
                    if (traffic_log) {
                        vrmr_fatal_if_null(d_node->data);
                        log_record = d_node->data;

                        if (!use_filter || (use_filter && !log_record->filtered)) {
                            drawn_lines++;
                            print_logrule(log_win, log_record, max_logrule_length, cur_logrule_length, hide_date, hide_action, hide_service, hide_from, hide_to, hide_prefix, hide_details);
                        }
                    } else {
                        vrmr_fatal_if_null(d_node->data);
                        plainlog_record = d_node->data;

                        if (!use_filter || (use_filter && !plainlog_record->filtered)) {
                            drawn_lines++;
                            print_plainlogrule(log_win, plainlog_record->line, max_logrule_length, cur_logrule_length);
                        }
                    }
                }
                /*  when we have drawn the entire screen, there is no
                    use in keep running through the loop. So break out. */
                else if(drawn_lines >= max_onscreen)
                {
                    break;
                }
            }
            /* here the screen is drawn */
            update_panels();
            doupdate();

            /* reset the control stuff */
            control.print = 0;
            control.queue = 0;
            control.sleep = 0;

            /* if we are in search mode, there is no need to keep up with the log in real-time.
               So we take some time to draw the screen. It will slow down the printing and thereby
               the searching, but it will keep the log better readable

               furthermore it will decrease the load on the system during a search */
            if (search_mode)
                usleep(90000);
        }

        /* sleep for 1 tenth of a second if we want to sleep */
        if (control.sleep == 1) {
            usleep(100000);
            control.sleep = 0;
        }
    }

    /*
        EXIT: cleanup
    */

    /* filter clean up */
    vrmr_filter_cleanup(debuglvl, &vfilter);
    nodelay(log_win, FALSE);
    vrmr_fatal_if(vrmr_list_cleanup(debuglvl, buffer_ptr) < 0);
    (void)fclose(fp);

    /* info bar stuff */
    show_panel(info_bar_panels[0]);
    show_panel(info_bar_panels[1]);
    del_panel(info_bar_panels[0]);
    del_panel(info_bar_panels[1]);
    destroy_win(filter_ib_win);
    destroy_win(search_ib_win);
    /* the main panel and win */
    del_panel(my_panels[0]);
    destroy_win(log_win);
    /* update the panels and windows */
    update_panels();
    doupdate();
    status_print(status_win, gettext("Ready."));
    return(0);
}

