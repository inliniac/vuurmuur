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

struct {
    PANEL *panel[1];
    WINDOW *win;
    FIELD **fields;
    FORM *form;
    size_t n_fields;
} statsec_ctx;

/*  get_sys_load

    Gets the systemload from /proc/loadavg

    Returncodes:
         0: ok
        -1: error
*/
static int get_sys_load(float *load_s, float *load_m, float *load_l)
{
    FILE *fp = NULL;
    const char proc_loadavg[] = "/proc/loadavg";
    char line[512] = "";

    if (!(fp = fopen(proc_loadavg, "r")))
        return (-1);

    if (fgets(line, (int)sizeof(line), fp) != NULL) {
        if (sscanf(line, "%f %f %f", load_s, load_m, load_l) == 0) {
            fclose(fp);
            return (-1);
        }
    } else {
        fclose(fp);
        return (-1);
    }

    if (fclose(fp) < 0)
        return (-1);
    return (0);
}
#if 0
static int count_host_tcp_conn(int *tcp_count, int *tcp_list_count)
{
    FILE    *fp=NULL;
    char    proc_net_tcp[] = "/proc/net/tcp",
            line[512];
    int     i=0;

    int     sl=0;
    char    localaddr[32],
            state[3],
            remoteaddr[32];

    int     tcp_listen=0;
    
    if(!(fp = fopen(proc_net_tcp, "r")))
        return(-1);

    while(fgets(line, (int)sizeof(line), fp) != NULL)
    {
        if(i > 0)
        {
            sscanf(line, "%d: %s %s %2s", &sl, localaddr, remoteaddr, state);

            if(strcmp(state, "0A") == 0)
                tcp_listen++;
            
        }
        i++;
    }
    i--;

    //vrprint.warning("info", "tcp_listen: %d (%d total).", tcp_listen, i);

    *tcp_count = i;
    *tcp_list_count = tcp_listen;

    if(fclose(fp) < 0)
        return(-1);

    return(0);
}

static int count_host_udp_conn(int *udp_count, int *udp_list_count)
{
    FILE    *fp=NULL;
    char    proc_net_udp[] = "/proc/net/udp",
            line[512];
    int     i=0;

    int     sl=0;
    char    localaddr[32],
            state[3],
            remoteaddr[32];

    int     udp_listen=0;

    if(!(fp = fopen(proc_net_udp, "r")))
        return(-1);

    while(fgets(line, (int)sizeof(line), fp) != NULL)
    {
        if(i > 0)
        {
            sscanf(line, "%d: %s %s %2s", &sl, localaddr, remoteaddr, state);

            if(strcmp(state, "07") == 0)
                udp_listen++;

        }
        i++;
    }
    i--;

    //vrprint.warning("info", "udp_listen: %d (%d total).", udp_listen, i);

    *udp_count = i;
    *udp_list_count = udp_listen;

    if(fclose(fp) < 0)
        return(-1);

    return(0);
}
#endif

static int count_conntrack_conn(struct vrmr_config *cnf, int *conntrack_count,
        int *tcp_count, int *udp_count, int *other_count)
{
    FILE *fp = NULL;
    char line[512];
    int i = 0, tcp = 0, udp = 0, other = 0;

    if (cnf->use_ipconntrack == TRUE ||
            (!(fp = fopen(VRMR_PROC_NFCONNTRACK, "r")))) {
        if (!(fp = fopen(VRMR_PROC_IPCONNTRACK, "r")))
            return (-1);
    }

    while (fgets(line, (int)sizeof(line), fp) != NULL) {
        if (strncmp(line, "tcp", 3) == 0)
            tcp++;
        else if (strncmp(line, "udp", 3) == 0)
            udp++;
        else
            other++;

        i++;
    }

    *conntrack_count = i;
    *tcp_count = tcp;
    *udp_count = udp;
    *other_count = other;

    if (fclose(fp) < 0)
        return (-1);

    return (0);
}

static int get_conntrack_max(int *conntrack_max)
{
    FILE *fp = NULL;
    char proc_ip_conntrack_max[] = "/proc/sys/net/ipv4/ip_conntrack_max",
         proc_nf_conntrack_max[] = "/proc/sys/net/nf_conntrack_max",
         line[16] = "";

    /* try to open the conntrack max file */
    if (!(fp = fopen(proc_ip_conntrack_max, "r"))) {
        if (!(fp = fopen(proc_nf_conntrack_max, "r"))) {
            return (-1);
        }
    }

    if (fgets(line, (int)sizeof(line), fp) != NULL) {
        int v = atoi(line);
        if (v >= 0 && v < 2000000000) {
            *conntrack_max = v;
        }
    }

    (void)fclose(fp);
    return (0);
}

/*  get_meminfo

    Gets the info about the memory status of the system.

    Returncodes:
         0: ok
        -1: error
*/
static int get_meminfo(
        int *mem_total, int *mem_free, int *mem_cached, int *mem_buffers)
{
    FILE *fp = NULL;
    char proc_meminfo[] = "/proc/meminfo", line[128], variable[64], value[64];

    // open the proc entry
    if (!(fp = fopen(proc_meminfo, "r"))) {
        vrmr_error(-1, VR_ERR, gettext("opening '%s' failed: %s (in: %s:%d)."),
                proc_meminfo, strerror(errno), __FUNC__, __LINE__);
        return (-1);
    }

    // loop trough the file and get the info
    while (fgets(line, (int)sizeof(line), fp) != NULL) {
        sscanf(line, "%63s %63s", variable, value);

        if (strcmp(variable, "MemTotal:") == 0)
            *mem_total = atoi(value);
        else if (strcmp(variable, "MemFree:") == 0)
            *mem_free = atoi(value);
        else if (strcmp(variable, "Buffers:") == 0)
            *mem_buffers = atoi(value);
        else if (strcmp(variable, "Cached:") == 0)
            *mem_cached = atoi(value);
    }

    if (fclose(fp) < 0)
        return (-1);

    return (0);
}

static int get_system_uptime(
        char *s_day, char *s_hour, char *s_minute, char *s_second)
{
    FILE *fp = NULL;
    char proc_uptime[] = "/proc/uptime", line[512];
    int upt_i = 0, day = 0, hour = 0, min = 0, sec = 0;

    // param check

    if (!(fp = fopen(proc_uptime, "r")))
        return (-1);

    if (fgets(line, (int)sizeof(line), fp) != NULL)
        sscanf(line, "%d", &upt_i);

    day = upt_i / 86400;
    hour = (upt_i - (day * 86400)) / 3600;
    min = (upt_i - (day * 86400) - (hour * 3600)) / 60;
    sec = (upt_i - (day * 86400) - (hour * 3600) - (min * 60));

    if (fclose(fp) < 0)
        return (-1);

    if (day < 0)
        day = 0;
    else if (day > 9999)
        day = 9999;

    if (!(hour >= 0 && hour <= 24))
        hour = -1;
    if (!(min >= 0 && min <= 59))
        min = -1;
    if (!(sec >= 0 && sec <= 60)) // account for leap sec
        sec = -1;

    snprintf(s_day, 5, "%4d", day);
    snprintf(s_hour, 3, "%02d", hour);
    snprintf(s_minute, 3, "%02d", min);
    snprintf(s_second, 3, "%02d", sec);

    return (0);
}

/*  status_section_init

    This function creates the status section window and the fields inside it.
    It also draws - alot of - lines.

    Returncodes:
         0: ok
        -1: error
*/
static int status_section_init(
        int height, int width, int starty, int startx, unsigned int ifac_num)
{
    int rows, cols, max_width;
    unsigned int ifac_fields = 0, ifacs = 0, ifac_start = 12;
    size_t i = 0;

    /* get and check the screen dimentions */
    max_width = getmaxx(stdscr);
    if (width > max_width)
        return (-1);
    if ((int)ifac_num > height - 15)
        ifac_num = (unsigned int)height - 15;

    /* set the number of fields */
    statsec_ctx.n_fields = (size_t)(16 + (6 * ifac_num));

    /* alloc the needed memory */
    if (!(statsec_ctx.fields = (FIELD **)calloc(
                  statsec_ctx.n_fields + 1, sizeof(FIELD *)))) {
        vrmr_error(-1, VR_ERR, gettext("calloc failed: %s (in: %s:%d)."),
                strerror(errno), __FUNC__, __LINE__);
        return (-1);
    }

    /* create the fields */
    statsec_ctx.fields[0] = new_field(1, 5, 4, 13, 0, 1);
    set_field_buffer_wrap(statsec_ctx.fields[0], 1, "ld_s");
    statsec_ctx.fields[1] = new_field(1, 5, 4, 19, 0, 1);
    set_field_buffer_wrap(statsec_ctx.fields[1], 1, "ld_m");
    statsec_ctx.fields[2] = new_field(1, 5, 4, 25, 0, 1);
    set_field_buffer_wrap(statsec_ctx.fields[2], 1, "ld_l");

    statsec_ctx.fields[3] = new_field(1, 6, 4, 43, 0, 1);
    set_field_buffer_wrap(statsec_ctx.fields[3], 1, "mem_t");
    statsec_ctx.fields[4] = new_field(1, 6, 4, 51, 0, 1);
    set_field_buffer_wrap(statsec_ctx.fields[4], 1, "mem_f");
    statsec_ctx.fields[5] = new_field(1, 6, 4, 59, 0, 1);
    set_field_buffer_wrap(statsec_ctx.fields[5], 1, "mem_c");
    statsec_ctx.fields[6] = new_field(1, 6, 4, 67, 0, 1);
    set_field_buffer_wrap(statsec_ctx.fields[6], 1, "mem_b");

    statsec_ctx.fields[7] = new_field(1, 4, 1, 61, 0, 1);
    set_field_buffer_wrap(statsec_ctx.fields[7], 1, "up_d");
    statsec_ctx.fields[8] = new_field(1, 2, 1, 66, 0, 1);
    set_field_buffer_wrap(statsec_ctx.fields[8], 1, "uh");
    statsec_ctx.fields[9] = new_field(1, 2, 1, 69, 0, 1);
    set_field_buffer_wrap(statsec_ctx.fields[9], 1, "um");
    statsec_ctx.fields[10] = new_field(1, 2, 1, 72, 0, 1);
    set_field_buffer_wrap(statsec_ctx.fields[10], 1, "us");

    statsec_ctx.fields[11] = new_field(1, 6, 6, 23, 0, 1);
    set_field_buffer_wrap(statsec_ctx.fields[11], 1, "con_t");
    statsec_ctx.fields[12] = new_field(1, 6, 7, 23, 0, 1);
    set_field_buffer_wrap(statsec_ctx.fields[12], 1, "con_u");
    statsec_ctx.fields[13] = new_field(1, 6, 6, 41, 0, 1);
    set_field_buffer_wrap(statsec_ctx.fields[13], 1, "con_o");

    statsec_ctx.fields[14] = new_field(1, 6, 6, 59, 0, 1);
    set_field_buffer_wrap(statsec_ctx.fields[14], 1, "con_c");
    statsec_ctx.fields[15] = new_field(1, 6, 7, 59, 0, 1);
    set_field_buffer_wrap(statsec_ctx.fields[15], 1, "con_m");

    /* create iface stats fields */
    for (ifacs = 0, ifac_fields = 16; ifacs < ifac_num; ifacs++) {
        statsec_ctx.fields[ifac_fields] =
                new_field(1, 8, (int)(ifac_start + ifacs), 13, 0, 1);
        set_field_buffer_wrap(statsec_ctx.fields[ifac_fields], 1, "recv_s");
        ifac_fields++;

        statsec_ctx.fields[ifac_fields] =
                new_field(1, 8, (int)(ifac_start + ifacs), 22, 0, 1);
        set_field_buffer_wrap(statsec_ctx.fields[ifac_fields], 1, "send_s");
        ifac_fields++;

        statsec_ctx.fields[ifac_fields] =
                new_field(1, 10, (int)(ifac_start + ifacs), 31, 0, 1);
        set_field_buffer_wrap(statsec_ctx.fields[ifac_fields], 1, "rcv_ti");
        ifac_fields++;

        statsec_ctx.fields[ifac_fields] =
                new_field(1, 10, (int)(ifac_start + ifacs), 42, 0, 1);
        set_field_buffer_wrap(statsec_ctx.fields[ifac_fields], 1, "snd_to");
        ifac_fields++;

        statsec_ctx.fields[ifac_fields] =
                new_field(1, 10, (int)(ifac_start + ifacs), 53, 0, 1);
        set_field_buffer_wrap(statsec_ctx.fields[ifac_fields], 1, "rcv_tf");
        ifac_fields++;

        statsec_ctx.fields[ifac_fields] =
                new_field(1, 10, (int)(ifac_start + ifacs), 64, 0, 1);
        set_field_buffer_wrap(statsec_ctx.fields[ifac_fields], 1, "snd_tf");
        ifac_fields++;
    }

    /* terminate the field array */
    statsec_ctx.fields[statsec_ctx.n_fields] = NULL;

    /* create the window and the panel */
    if (!(statsec_ctx.win = create_newwin(height, width, starty, startx,
                  gettext("Status Section"), vccnf.color_win))) {
        vrmr_error(-1, VR_INTERR, "create_newwin() failed (in: %s:%d).",
                __FUNC__, __LINE__);
        return (-1);
    }
    if (!(statsec_ctx.panel[0] = new_panel(statsec_ctx.win))) {
        vrmr_error(-1, VR_INTERR, "new_panel() failed (in: %s:%d).", __FUNC__,
                __LINE__);
        return (-1);
    }

    /* field options */
    for (i = 0; i < statsec_ctx.n_fields; i++) {
        if (vrmr_debug_level >= LOW)
            set_field_back(statsec_ctx.fields[i], vccnf.color_win_rev);
        else
            set_field_back(statsec_ctx.fields[i], vccnf.color_win);

        field_opts_off(statsec_ctx.fields[i], O_AUTOSKIP);
        /* set status to false */
        set_field_status(statsec_ctx.fields[i], FALSE);
    }

    /* Create the form and post it */
    if (!(statsec_ctx.form = new_form(statsec_ctx.fields))) {
        vrmr_error(-1, VR_INTERR, "new_form() failed (in: %s:%d).", __FUNC__,
                __LINE__);
        return (-1);
    }
    /* Calculate the area required for the form */
    scale_form(statsec_ctx.form, &rows, &cols);
    keypad(statsec_ctx.win, TRUE);
    /* Set main window and sub window */
    set_form_win(statsec_ctx.form, statsec_ctx.win);
    set_form_sub(statsec_ctx.form, derwin(statsec_ctx.win, rows, cols, 1, 2));

    if (post_form(statsec_ctx.form) != E_OK) {
        vrmr_error(-1, VR_INTERR, "post_form() failed (in: %s:%d).", __FUNC__,
                __LINE__);
        return (-1);
    }

    /* print the field labels */

    /* TRANSLATORS: max 11 chars. */
    mvwprintw(statsec_ctx.win, 1, 2, gettext("Hostname"));
    mvwprintw(statsec_ctx.win, 2, 2, "Kernel");

    /* TRANSLATORS: max 3 chars. */
    mvwprintw(statsec_ctx.win, 1, 64, gettext("day"));
    /* TRANSLATORS: this must be exactly the same regarding positions. */
    mvwprintw(statsec_ctx.win, 1, 68, gettext("h  m  s"));
    mvwprintw(statsec_ctx.win, 2, 70, ":");
    mvwprintw(statsec_ctx.win, 2, 73, ":");
    /* TRANSLATORS: max 6 chars. */
    mvwprintw(statsec_ctx.win, 2, 55, gettext("Uptime"));

    mvwprintw(statsec_ctx.win, 4, 15, "1m    5m    15m");

    /* TRANSLATORS: max 10 chars. */
    mvwprintw(statsec_ctx.win, 5, 2, gettext("Load"));
    /* TRANSLATORS: max 5 chars. */
    mvwprintw(statsec_ctx.win, 4, 46, gettext("Total"));
    /* TRANSLATORS: max 5 chars. */
    mvwprintw(statsec_ctx.win, 4, 54, gettext("Free"));
    /* TRANSLATORS: max 5 chars. */
    mvwprintw(statsec_ctx.win, 4, 62, gettext("Cache"));
    /* TRANSLATORS: max 6 chars. */
    mvwprintw(statsec_ctx.win, 4, 70, gettext("Buffer"));
    /* TRANSLATORS: max 9 chars. */
    mvwprintw(statsec_ctx.win, 5, 34, gettext("Memory(MB)"));

    /* TRANSLATORS: max 11 chars. */
    mvwprintw(statsec_ctx.win, 8, 2, gettext("Connections"));

    mvwprintw(statsec_ctx.win, 7, 16, "Tcp");
    mvwprintw(statsec_ctx.win, 8, 16, "Udp");

    /* TRANSLATORS: max 7 chars. */
    mvwprintw(statsec_ctx.win, 7, 34, gettext("Other"));

    /* TRANSLATORS: max 7 chars. */
    mvwprintw(statsec_ctx.win, 7, 52, gettext("Current"));
    /* TRANSLATORS: max 7 chars. */
    mvwprintw(statsec_ctx.win, 8, 52, gettext("Maximal"));

    /* TRANSLATORS: max 11 chars. */
    mvwprintw(statsec_ctx.win, 10, 15, gettext("Speed/s"));
    /* TRANSLATORS: max 11 chars. */
    mvwprintw(statsec_ctx.win, 10, 33, gettext("Firewall"));
    /* TRANSLATORS: max 11 chars. */
    mvwprintw(statsec_ctx.win, 10, 55, gettext("Forwarded"));

    /* TRANSLATORS: max 11 chars. */
    mvwprintw(statsec_ctx.win, 11, 2, gettext("Interfaces"));

    /* TRANSLATORS: max 6 chars. */
    mvwprintw(statsec_ctx.win, 11, 15, gettext("Down"));
    /* TRANSLATORS: max 6 chars. */
    mvwprintw(statsec_ctx.win, 11, 24, gettext("Up"));
    /* TRANSLATORS: max 6 chars. */
    mvwprintw(statsec_ctx.win, 11, 33, gettext("In"));
    /* TRANSLATORS: max 6 chars. */
    mvwprintw(statsec_ctx.win, 11, 44, gettext("Out"));
    /* TRANSLATORS: max 6 chars. */
    mvwprintw(statsec_ctx.win, 11, 55, gettext("Recv"));
    /* TRANSLATORS: max 6 chars. */
    mvwprintw(statsec_ctx.win, 11, 66, gettext("Send"));

    /*
        DRAW THE LINES
    */

    /* kernel and domainname */
    mvwvline(statsec_ctx.win, 1, 14, ACS_VLINE, 2);
    mvwvline(statsec_ctx.win, 1, 53, ACS_VLINE, 2);
    mvwvline(statsec_ctx.win, 1, 62, ACS_VLINE, 2);

    /* T-pieces on top */
    mvwaddch(statsec_ctx.win, 0, 14, ACS_TTEE);
    mvwaddch(statsec_ctx.win, 0, 53, ACS_TTEE);
    mvwaddch(statsec_ctx.win, 0, 62, ACS_TTEE);

    mvwhline(statsec_ctx.win, 3, 1, ACS_HLINE, 76);
    mvwaddch(statsec_ctx.win, 3, 0, ACS_LTEE);
    mvwaddch(statsec_ctx.win, 3, 77, ACS_RTEE);

    mvwaddch(statsec_ctx.win, 3, 14, ACS_PLUS);
    mvwaddch(statsec_ctx.win, 3, 20, ACS_TTEE);
    mvwaddch(statsec_ctx.win, 3, 26, ACS_TTEE);
    mvwaddch(statsec_ctx.win, 3, 32, ACS_TTEE);
    mvwaddch(statsec_ctx.win, 3, 44, ACS_TTEE);
    mvwaddch(statsec_ctx.win, 3, 52, ACS_TTEE);
    mvwaddch(statsec_ctx.win, 3, 53, ACS_BTEE);
    mvwaddch(statsec_ctx.win, 3, 60, ACS_TTEE);
    mvwaddch(statsec_ctx.win, 3, 62, ACS_BTEE);
    mvwaddch(statsec_ctx.win, 3, 68, ACS_TTEE);

    /* load fields */
    mvwvline(statsec_ctx.win, 4, 14, ACS_VLINE, 2);
    mvwvline(statsec_ctx.win, 4, 20, ACS_VLINE, 2);
    mvwvline(statsec_ctx.win, 4, 26, ACS_VLINE, 2);
    mvwvline(statsec_ctx.win, 4, 32, ACS_VLINE, 2);

    /* memory */
    mvwvline(statsec_ctx.win, 4, 44, ACS_VLINE, 2);
    mvwvline(statsec_ctx.win, 4, 52, ACS_VLINE, 2);
    mvwvline(statsec_ctx.win, 4, 60, ACS_VLINE, 2);
    mvwvline(statsec_ctx.win, 4, 68, ACS_VLINE, 2);

    mvwhline(statsec_ctx.win, 6, 1, ACS_HLINE, 76);
    mvwaddch(statsec_ctx.win, 6, 0, ACS_LTEE);
    mvwaddch(statsec_ctx.win, 6, 77, ACS_RTEE);

    mvwaddch(statsec_ctx.win, 6, 14, ACS_PLUS);

    mvwaddch(statsec_ctx.win, 6, 20, ACS_BTEE);
    mvwaddch(statsec_ctx.win, 6, 26, ACS_BTEE);
    mvwaddch(statsec_ctx.win, 6, 32, ACS_PLUS);
    mvwaddch(statsec_ctx.win, 6, 44, ACS_BTEE);
    mvwaddch(statsec_ctx.win, 6, 50, ACS_TTEE);
    mvwaddch(statsec_ctx.win, 6, 52, ACS_BTEE);

    mvwaddch(statsec_ctx.win, 6, 60, ACS_BTEE);
    mvwaddch(statsec_ctx.win, 6, 68, ACS_PLUS);

    /* uptime fields */
    mvwvline(statsec_ctx.win, 7, 14, ACS_VLINE, 2);
    mvwvline(statsec_ctx.win, 7, 32, ACS_VLINE, 2);
    mvwvline(statsec_ctx.win, 7, 50, ACS_VLINE, 2);
    mvwvline(statsec_ctx.win, 7, 68, ACS_VLINE, 2);

    /* connection fields */
    mvwhline(statsec_ctx.win, 9, 1, ACS_HLINE, 76);
    mvwaddch(statsec_ctx.win, 9, 0, ACS_LTEE);
    mvwaddch(statsec_ctx.win, 9, 77, ACS_RTEE);

    mvwvline(statsec_ctx.win, 10, 14, ACS_VLINE, 2);
    mvwvline(statsec_ctx.win, 10, 32, ACS_VLINE, 2);
    mvwvline(statsec_ctx.win, 10, 54, ACS_VLINE, 2);
    // mvwvline(statsec_ctx.win, 10, 68, ACS_VLINE, 2);

    mvwaddch(statsec_ctx.win, 9, 14, ACS_PLUS);
    mvwaddch(statsec_ctx.win, 9, 32, ACS_PLUS);
    mvwaddch(statsec_ctx.win, 9, 50, ACS_BTEE);
    mvwaddch(statsec_ctx.win, 9, 54, ACS_TTEE);
    mvwaddch(statsec_ctx.win, 9, 68, ACS_BTEE);

    /* interface fields */
    mvwhline(statsec_ctx.win, (int)ifac_start, 14, ACS_HLINE, 63);
    mvwaddch(statsec_ctx.win, (int)ifac_start, 77, ACS_RTEE);
    mvwhline(statsec_ctx.win, (int)(ifac_start + ifac_num + 1), 1, ACS_HLINE,
            76);
    mvwaddch(statsec_ctx.win, (int)(ifac_start + ifac_num + 1), 0, ACS_LTEE);
    mvwaddch(statsec_ctx.win, (int)(ifac_start + ifac_num + 1), 77, ACS_RTEE);

    mvwaddch(statsec_ctx.win, (int)ifac_start, 14, ACS_LTEE);
    // mvwaddch(statsec_ctx.win, ifac_start, 68, ACS_RTEE);

    mvwaddch(statsec_ctx.win, (int)(ifac_start + ifac_num + 1), 14, ACS_BTEE);
    // mvwaddch(statsec_ctx.win, ifac_start+ifac_num+1, 68, ACS_BTEE);

    mvwvline(statsec_ctx.win, (int)(ifac_start + 1), 14, ACS_VLINE,
            (int)ifac_num);

    mvwaddch(statsec_ctx.win, (int)ifac_start, 23, ACS_TTEE);
    mvwvline(statsec_ctx.win, (int)(ifac_start + 1), 23, ACS_VLINE,
            (int)ifac_num);
    mvwaddch(statsec_ctx.win, (int)(ifac_start + ifac_num + 1), 23, ACS_BTEE);

    mvwaddch(statsec_ctx.win, (int)ifac_start, 32, ACS_PLUS);
    mvwvline(statsec_ctx.win, (int)(ifac_start + 1), 32, ACS_VLINE,
            (int)ifac_num);
    mvwaddch(statsec_ctx.win, (int)(ifac_start + ifac_num + 1), 32, ACS_BTEE);

    mvwaddch(statsec_ctx.win, (int)ifac_start, 43, ACS_TTEE);
    mvwvline(statsec_ctx.win, (int)(ifac_start + 1), 43, ACS_VLINE,
            (int)ifac_num);
    mvwaddch(statsec_ctx.win, (int)(ifac_start + ifac_num + 1), 43, ACS_BTEE);

    mvwaddch(statsec_ctx.win, (int)ifac_start, 54, ACS_PLUS);
    mvwvline(statsec_ctx.win, (int)(ifac_start + 1), 54, ACS_VLINE,
            (int)ifac_num);
    mvwaddch(statsec_ctx.win, (int)(ifac_start + ifac_num + 1), 54, ACS_BTEE);

    mvwaddch(statsec_ctx.win, (int)ifac_start, 65, ACS_TTEE);
    mvwvline(statsec_ctx.win, (int)(ifac_start + 1), 65, ACS_VLINE,
            (int)ifac_num);
    mvwaddch(statsec_ctx.win, (int)(ifac_start + ifac_num + 1), 65, ACS_BTEE);

    // mvwvline(statsec_ctx.win, ifac_start+1, 68, ACS_VLINE, ifac_num);

    return (0);
}

static int status_section_destroy(void)
{
    size_t i;

    // Un post form and free the memory
    unpost_form(statsec_ctx.form);
    free_form(statsec_ctx.form);

    for (i = 0; i < statsec_ctx.n_fields; i++) {
        free_field(statsec_ctx.fields[i]);
    }
    free(statsec_ctx.fields);

    del_panel(statsec_ctx.panel[0]);
    destroy_win(statsec_ctx.win);

    return (0);
}

/*  status_section

    This section shows information about the system.

    Returncodes:
        0: ok
        -1: error
*/
int status_section(struct vrmr_config *cnf, struct vrmr_interfaces *interfaces)
{
    FIELD *cur = NULL;
    int retval = 0;
    int quit = 0, ch = 0;

    int y = 0;

    unsigned int i = 0, cur_interface = 0;

    int max_height = 0,

        conntrack_conn_max = 0,

        conntrack_conn_total = 0, conntrack_conn_tcp = 0,
        conntrack_conn_udp = 0, conntrack_conn_other = 0,

        mem_total = 0, mem_free = 0, mem_cached = 0, mem_bufferd = 0;

    char hostname[60] = "", load_str[6] = "", mem_str[7] = "",
         interfacename[32] = "",

         upt_day[5] = "", upt_hour[3] = "", upt_minute[3] = "",
         upt_second[3] = "",

         conn_max[7] = "", conn_total[7] = "", conn_tcp[7] = "",
         conn_udp[7] = "", conn_other[7] = "",

         recv_host[11] = "", send_host[11] = "",

         recv_net[11] = "", send_net[11] = "",

         recv_speed[9] = "", send_speed[9] = "";

    /* uname struct, for gettig the kernel version */
    struct utsname uts_name;

    /* the byte counters */
    unsigned long recv_bytes = 0, trans_bytes = 0, delta_bytes = 0,
                  speed_bytes = 0;

    /* load */
    float load_s = 0,   // 1 min
            load_m = 0, // 5 min
            load_l = 0; // 15 min

    /* structure for storing byte counters per interface */
    struct shadow_ifac_ {
        char calc;

        unsigned long prev_recv_bytes;
        unsigned long prev_send_bytes;

        unsigned long prev_recv_packets;
        unsigned long prev_send_packets;

        unsigned long cur_recv_bytes;
        unsigned long cur_send_bytes;

        unsigned long cur_recv_packets;
        unsigned long cur_send_packets;

        unsigned long long send_host, recv_host,

                send_host_packets, recv_host_packets,

                send_net, recv_net,

                send_net_packets, recv_net_packets;

        /* for the correction of the speed */
        struct timeval begin_tv;
        struct timeval end_tv;
    };

    struct shadow_ifac_ *shadow_ptr = NULL;
    struct vrmr_interface *iface_ptr = NULL;

    struct vrmr_list_node *d_node = NULL;
    struct vrmr_list_node *shadow_node = NULL;

    // list which will hold the structs analog to the interfaces list
    struct vrmr_list shadow_list;

    // we correct the speed with the time it takes to get all stats
    double elapse = 0;
    float correction = 0;

    int update_interval =
            1000000;            /* weird, in pratice this seems to be two sec */
    int slept_so_far = 1000000; /* time slept since last update */

    /* top menu */
    char *key_choices[] = {"F12", "F10"};
    int key_choices_n = 2;
    char *cmd_choices[] = {gettext("help"), gettext("back")};
    int cmd_choices_n = 2;

    // first create our shadow list
    vrmr_list_setup(&shadow_list, free);

    for (i = 0; i < interfaces->list.len; i++) {
        if (!(shadow_ptr = malloc(sizeof(struct shadow_ifac_))))
            return (-1);

        shadow_ptr->calc = 1;

        shadow_ptr->prev_recv_bytes = 0;
        shadow_ptr->prev_send_bytes = 0;
        shadow_ptr->cur_recv_bytes = 0;
        shadow_ptr->cur_send_bytes = 0;

        gettimeofday(&shadow_ptr->begin_tv, 0);

        /* append to the list */
        if (vrmr_list_append(&shadow_list, shadow_ptr) == NULL)
            return (-1);
    }

    /* create the service and zone hash for conn_get_stats */

    /*
        set up the statuswin
    */
    max_height = getmaxy(stdscr);

    /*
        init
    */
    if (status_section_init(max_height - 8, 78, 4, 1, interfaces->list.len) < 0)
        return (-1);

    /*
        make sure wgetch doesn't block
    */
    nodelay(statsec_ctx.win, TRUE);
    keypad(statsec_ctx.win, TRUE);

    /*
        get the hostname of the system, or set to error on failure
    */
    if (gethostname(hostname, sizeof(hostname)) < 0)
        (void)strlcpy(hostname, gettext("error"), sizeof(hostname));

    mvwprintw(statsec_ctx.win, 1, 15, "%s", hostname);

    /*
        uname - get some system information
    */
    if (uname(&uts_name) < 0)
        vrmr_error(-1, VR_ERR, "uname() failed.");

    mvwprintw(statsec_ctx.win, 2, 15, "%s %s", uts_name.sysname,
            uts_name.release);

    /*
        get the maximum connections
    */
    if (get_conntrack_max(&conntrack_conn_max) < 0)
        (void)snprintf(conn_max, sizeof(conn_max), gettext("error"));
    else
        (void)snprintf(conn_max, sizeof(conn_max), "%6d", conntrack_conn_max);

    draw_top_menu(top_win, gettext("System Status"), key_choices_n, key_choices,
            cmd_choices_n, cmd_choices);

    update_panels();
    doupdate();

    /* the main loop */
    while (quit == 0 && retval == 0) {
        vrmr_debug(LOW, "slept_so_far: %d, update_interval: %d.", slept_so_far,
                update_interval);

        /* check if we have slept long enough */
        if (slept_so_far >= update_interval) {
            vrmr_debug(HIGH, "slept_so_far: %d -> now print.", slept_so_far);

            slept_so_far = 0;

            /*  update the information */
            if (get_sys_load(&load_s, &load_m, &load_l) < 0) {
                vrmr_error(-1, VR_INTERR, "get_sys_load() failed (in: %s:%d).",
                        __FUNC__, __LINE__);
                return (-1);
            }

            if (get_meminfo(&mem_total, &mem_free, &mem_cached, &mem_bufferd) <
                    0) {
                vrmr_error(-1, VR_INTERR, "get_meminfo() failed (in: %s:%d).",
                        __FUNC__, __LINE__);
                return (-1);
            }

            if (get_system_uptime(upt_day, upt_hour, upt_minute, upt_second) <
                    0) {
                vrmr_error(-1, VR_INTERR,
                        "get_system_uptime() failed (in: %s:%d).", __FUNC__,
                        __LINE__);
                return (-1);
            }

            if (count_conntrack_conn(cnf, &conntrack_conn_total,
                        &conntrack_conn_tcp, &conntrack_conn_udp,
                        &conntrack_conn_other) < 0) {
                snprintf(conn_total, sizeof(conn_total), gettext("error"));
                snprintf(conn_tcp, sizeof(conn_tcp), gettext("error"));
                snprintf(conn_udp, sizeof(conn_udp), gettext("error"));
                snprintf(conn_other, sizeof(conn_other), gettext("error"));
            } else {
                if (conntrack_conn_total > 999999)
                    conntrack_conn_total = 999999;
                if (conntrack_conn_tcp > 999999)
                    conntrack_conn_tcp = 999999;
                if (conntrack_conn_udp > 999999)
                    conntrack_conn_udp = 999999;
                if (conntrack_conn_other > 999999)
                    conntrack_conn_other = 999999;

                snprintf(conn_total, sizeof(conn_total), "%6d",
                        conntrack_conn_total);
                snprintf(conn_tcp, sizeof(conn_tcp), "%6d", conntrack_conn_tcp);
                snprintf(conn_udp, sizeof(conn_udp), "%6d", conntrack_conn_udp);
                snprintf(conn_other, sizeof(conn_other), "%6d",
                        conntrack_conn_other);
            }

            /* loop trough the fields and update the information */
            for (i = 0; i < (unsigned int)statsec_ctx.n_fields; i++) {
                cur = statsec_ctx.fields[i];

                if (strncmp(field_buffer(cur, 1), "ld_s", 4) == 0) {
                    if (load_s > 2 && load_s < 5)
                        set_field_fore(cur, vccnf.color_win_yellow | A_BOLD);
                    else if (load_s >= 5)
                        set_field_fore(cur, vccnf.color_win_red | A_BOLD);
                    else
                        set_field_fore(cur, vccnf.color_win);

                    (void)snprintf(load_str, sizeof(load_str), "%2.2f", load_s);
                    set_field_buffer_wrap(cur, 0, load_str);
                } else if (strncmp(field_buffer(cur, 1), "ld_m", 4) == 0) {
                    if (load_m > 2 && load_m < 5)
                        set_field_fore(cur, vccnf.color_win_yellow | A_BOLD);
                    else if (load_m >= 5)
                        set_field_fore(cur, vccnf.color_win_red | A_BOLD);
                    else
                        set_field_fore(cur, vccnf.color_win);

                    (void)snprintf(load_str, sizeof(load_str), "%2.2f", load_m);
                    set_field_buffer_wrap(cur, 0, load_str);
                } else if (strncmp(field_buffer(cur, 1), "ld_l", 4) == 0) {
                    if (load_l > 2 && load_l < 5)
                        set_field_fore(cur, vccnf.color_win_yellow | A_BOLD);
                    else if (load_l >= 5)
                        set_field_fore(cur, vccnf.color_win_red | A_BOLD);
                    else
                        set_field_fore(cur, vccnf.color_win);

                    (void)snprintf(load_str, sizeof(load_str), "%2.2f", load_l);
                    set_field_buffer_wrap(cur, 0, load_str);
                } else if (strncmp(field_buffer(cur, 1), "mem_t", 5) == 0) {
                    snprintf(mem_str, sizeof(mem_str), "%6d", mem_total / 1024);
                    set_field_buffer_wrap(cur, 0, mem_str);
                } else if (strncmp(field_buffer(cur, 1), "mem_f", 5) == 0) {
                    snprintf(mem_str, sizeof(mem_str), "%6d", mem_free / 1024);
                    set_field_buffer_wrap(cur, 0, mem_str);
                } else if (strncmp(field_buffer(cur, 1), "mem_c", 5) == 0) {
                    snprintf(
                            mem_str, sizeof(mem_str), "%6d", mem_cached / 1024);
                    set_field_buffer_wrap(cur, 0, mem_str);
                } else if (strncmp(field_buffer(cur, 1), "mem_b", 5) == 0) {
                    snprintf(mem_str, sizeof(mem_str), "%6d",
                            mem_bufferd / 1024);
                    set_field_buffer_wrap(cur, 0, mem_str);
                } else if (strncmp(field_buffer(cur, 1), "up_d", 4) == 0) {
                    set_field_buffer_wrap(cur, 0, upt_day);
                } else if (strncmp(field_buffer(cur, 1), "uh", 2) == 0) {
                    set_field_buffer_wrap(cur, 0, upt_hour);
                } else if (strncmp(field_buffer(cur, 1), "um", 2) == 0) {
                    set_field_buffer_wrap(cur, 0, upt_minute);
                } else if (strncmp(field_buffer(cur, 1), "us", 2) == 0) {
                    set_field_buffer_wrap(cur, 0, upt_second);
                } else if (strncmp(field_buffer(cur, 1), "con_m", 5) == 0) {
                    set_field_buffer_wrap(cur, 0, conn_max);
                } else if (strncmp(field_buffer(cur, 1), "con_c", 5) == 0) {
                    set_field_buffer_wrap(cur, 0, conn_total);
                } else if (strncmp(field_buffer(cur, 1), "con_t", 5) == 0) {
                    set_field_buffer_wrap(cur, 0, conn_tcp);
                } else if (strncmp(field_buffer(cur, 1), "con_u", 5) == 0) {
                    set_field_buffer_wrap(cur, 0, conn_udp);
                } else if (strncmp(field_buffer(cur, 1), "con_o", 5) == 0) {
                    set_field_buffer_wrap(cur, 0, conn_other);
                }
            }

            /* print interfaces, starting at line 13 */
            for (cur_interface = 0, y = 13, d_node = interfaces->list.top,
                shadow_node = shadow_list.top;
                    d_node && y < max_height - 8 - 2;
                    d_node = d_node->next, shadow_node = shadow_node->next) {
                unsigned long long tmp_ull;

                iface_ptr = d_node->data;
                shadow_ptr = shadow_node->data;

                /* only show real interfaces */
                if (iface_ptr->device_virtual == FALSE) {
                    /* get the counters for determining speed */
                    vrmr_get_iface_stats(iface_ptr->device, &recv_bytes, NULL,
                            &trans_bytes, NULL);

                    /* get the real counters from iptables */
                    vrmr_get_iface_stats_from_ipt(cnf, iface_ptr->device,
                            "INPUT", &shadow_ptr->recv_host_packets,
                            &shadow_ptr->recv_host, &tmp_ull, &tmp_ull);
                    vrmr_get_iface_stats_from_ipt(cnf, iface_ptr->device,
                            "OUTPUT", &tmp_ull, &tmp_ull,
                            &shadow_ptr->send_host_packets,
                            &shadow_ptr->send_host);
                    vrmr_get_iface_stats_from_ipt(cnf, iface_ptr->device,
                            "FORWARD", &shadow_ptr->recv_net_packets,
                            &shadow_ptr->recv_net,
                            &shadow_ptr->send_net_packets,
                            &shadow_ptr->send_net);

                    /* RECV host/firewall */
                    if ((shadow_ptr->recv_host / (1024 * 1024)) >= 1000) {
                        snprintf(recv_host, sizeof(recv_host), "%7.3f GB",
                                (float)shadow_ptr->recv_host /
                                        (1024 * 1024 * 1024));
                        vrmr_debug(HIGH, "recv_host: '%s'.", recv_host);
                    } else if ((shadow_ptr->recv_host / (1024 * 1024)) < 1)
                        snprintf(recv_host, sizeof(recv_host), "%7d kb",
                                (int)shadow_ptr->recv_host / (1024));
                    else
                        snprintf(recv_host, sizeof(recv_host), "%7.3f MB",
                                (float)shadow_ptr->recv_host / (1024 * 1024));

                    /* SEND host/firewall */
                    if ((shadow_ptr->send_host / (1024 * 1024)) >= 1000)
                        snprintf(send_host, sizeof(send_host), "%7.3f GB",
                                (float)shadow_ptr->send_host /
                                        (1024 * 1024 * 1024));
                    else if ((shadow_ptr->send_host / (1024 * 1024)) < 1)
                        snprintf(send_host, sizeof(send_host), "%7d kb",
                                (int)shadow_ptr->send_host / (1024));
                    else
                        snprintf(send_host, sizeof(send_host), "%7.3f MB",
                                (float)shadow_ptr->send_host / (1024 * 1024));

                    /* RECV net/forward */
                    if ((shadow_ptr->recv_net / (1024 * 1024)) >= 1000)
                        snprintf(recv_net, sizeof(recv_net), "%7.3f GB",
                                (float)shadow_ptr->recv_net /
                                        (1024 * 1024 * 1024));
                    else if ((shadow_ptr->recv_net / (1024 * 1024)) < 1)
                        snprintf(recv_net, sizeof(recv_net), "%7d kb",
                                (int)shadow_ptr->recv_net / (1024));
                    else
                        snprintf(recv_net, sizeof(recv_net), "%7.3f MB",
                                (float)shadow_ptr->recv_net / (1024 * 1024));

                    /* SEND net/forward */
                    if ((shadow_ptr->send_net / (1024 * 1024)) >= 1000)
                        snprintf(send_net, sizeof(send_net), "%7.3f GB",
                                (float)shadow_ptr->send_net /
                                        (1024 * 1024 * 1024));
                    else if ((shadow_ptr->send_net / (1024 * 1024)) < 1)
                        snprintf(send_net, sizeof(send_net), "%7d kb",
                                (int)shadow_ptr->send_net / (1024));
                    else
                        snprintf(send_net, sizeof(send_net), "%7.3f MB",
                                (float)shadow_ptr->send_net / (1024 * 1024));

                    /* store the number of bytes */
                    shadow_ptr->cur_recv_bytes = recv_bytes;
                    shadow_ptr->cur_send_bytes = trans_bytes;

                    /* get the time we needed for our run */
                    gettimeofday(&shadow_ptr->end_tv, 0);
                    elapse = (double)shadow_ptr->end_tv.tv_sec +
                             (double)shadow_ptr->end_tv.tv_usec * 1e-6;
                    elapse -= (double)shadow_ptr->begin_tv.tv_sec +
                              (double)shadow_ptr->begin_tv.tv_usec * 1e-6;
                    gettimeofday(&shadow_ptr->begin_tv, 0);

                    /* this the correction value */
                    correction = elapse;

                    /* this is the value to be corrected */
                    delta_bytes = (shadow_ptr->cur_recv_bytes -
                                   shadow_ptr->prev_recv_bytes);
                    /* now we correct it */
                    speed_bytes = (delta_bytes / correction);

                    vrmr_debug(HIGH, "bytes: %d, corrections: %f",
                            (int)speed_bytes, correction);

                    /* calculating the current connection speed */
                    if (iface_ptr->up == TRUE) {
                        if (shadow_ptr->calc == 1)
                            snprintf(recv_speed, sizeof(recv_speed), "calc");
                        else if ((speed_bytes / 1024) < 1)
                            snprintf(recv_speed, sizeof(recv_speed), "%5d b",
                                    (int)speed_bytes);
                        else if ((speed_bytes / 1024) >= 1024)
                            snprintf(recv_speed, sizeof(recv_speed), "%5.1f mb",
                                    (float)speed_bytes / (1024 * 1024));
                        else
                            snprintf(recv_speed, sizeof(recv_speed), "%5.1f kb",
                                    (float)speed_bytes / 1024);
                    } else {
                        snprintf(recv_speed, sizeof(recv_speed), "%5s", "-");
                    }

                    /* this is the value to be corrected */
                    delta_bytes = (shadow_ptr->cur_send_bytes -
                                   shadow_ptr->prev_send_bytes);
                    /* now we correct it */
                    delta_bytes = (delta_bytes / correction);

                    if (iface_ptr->up == TRUE) {
                        if (shadow_ptr->calc == 1)
                            snprintf(send_speed, sizeof(send_speed), "calc");
                        else if ((delta_bytes / 1024) < 1)
                            snprintf(send_speed, sizeof(send_speed), "%5d b",
                                    (int)delta_bytes);
                        else if ((delta_bytes / 1024) >= 1024)
                            snprintf(send_speed, sizeof(send_speed), "%5.1f mb",
                                    (float)delta_bytes / (1024 * 1024));
                        else
                            snprintf(send_speed, sizeof(send_speed), "%5.1f kb",
                                    (float)delta_bytes / 1024);
                    } else {
                        snprintf(send_speed, sizeof(send_speed), "%5s", "-");
                    }

                    /* set the fields to the form */
                    for (i = cur_interface;
                            i < (unsigned int)statsec_ctx.n_fields; i++) {
                        cur = statsec_ctx.fields[i];

                        if (strncmp(field_buffer(cur, 1), "recv_s", 6) == 0)
                            set_field_buffer_wrap(cur, 0, recv_speed);
                        else if (strncmp(field_buffer(cur, 1), "send_s", 6) ==
                                 0)
                            set_field_buffer_wrap(cur, 0, send_speed);

                        else if (strncmp(field_buffer(cur, 1), "rcv_ti", 6) ==
                                 0)
                            set_field_buffer_wrap(cur, 0, recv_host);
                        else if (strncmp(field_buffer(cur, 1), "snd_to", 6) ==
                                 0)
                            set_field_buffer_wrap(cur, 0, send_host);

                        else if (strncmp(field_buffer(cur, 1), "rcv_tf", 6) ==
                                 0)
                            set_field_buffer_wrap(cur, 0, recv_net);
                        else if (strncmp(field_buffer(cur, 1), "snd_tf", 6) ==
                                 0) {
                            set_field_buffer_wrap(cur, 0, send_net);
                            break;
                        }
                    }
                    cur_interface = i + 1;

                    /* draw the interface name */
                    snprintf(interfacename, sizeof(interfacename), "%s",
                            iface_ptr->name);

                    if (iface_ptr->up == TRUE)
                        wattron(statsec_ctx.win, vccnf.color_win | A_BOLD);

                    mvwprintw(statsec_ctx.win, y, 2, "%s", interfacename);

                    if (iface_ptr->up == TRUE)
                        wattroff(statsec_ctx.win, vccnf.color_win | A_BOLD);

                    /* store the number of bytes */
                    shadow_ptr->prev_recv_bytes = recv_bytes;
                    shadow_ptr->prev_send_bytes = trans_bytes;

                    y++;

                    /*  after the first run we are no
                        longer calculating. */
                    if (shadow_ptr->calc > 0)
                        shadow_ptr->calc--;

                } /* end if virtual device */
            }

            /*
                finally draw the screen
            */
            wrefresh(statsec_ctx.win);
        }

        /* process the keyboard input */
        ch = wgetch(statsec_ctx.win);
        switch (ch) {
            /* quit */
            case 27:
            case 'q':
            case 'Q':
            case KEY_F(10):
                quit = 1;
                break;

            case KEY_F(12):
            case 'h':
            case 'H':
            case '?':
                print_help(":[VUURMUUR:STATUS]:");
                break;
        }

        if (quit == 0) {
            usleep(10000);
            slept_so_far = slept_so_far + 10000;

            vrmr_debug(HIGH, "just slept: slept_so_far '%d'.", slept_so_far);
        }
    }

    /* destroy hashtables and the shadowlist */
    vrmr_list_cleanup(&shadow_list);

    /* EXIT: cleanup */
    nodelay(statsec_ctx.win, FALSE);

    /* destroy the window and form */
    status_section_destroy();

    update_panels();
    doupdate();

    return (retval);
}
