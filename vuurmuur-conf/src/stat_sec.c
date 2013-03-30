/***************************************************************************
 *   Copyright (C) 2003-2007 by Victor Julien                              *
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


struct StatusSection_
{
    PANEL   *panel[1];
    WINDOW  *win;
    FIELD   **fields;
    FORM    *form;
    size_t  n_fields;
} StatusSection;


/*  get_sys_load

    Gets the systemload from /proc/loadavg

    Returncodes:
         0: ok
        -1: error
*/
int get_sys_load(float *load_s, float *load_m, float *load_l)
{
    FILE    *fp=NULL;
    char    proc_loadavg[] = "/proc/loadavg",
            line[512] = "";

    if(!(fp = fopen(proc_loadavg, "r")))
        return(-1);

    if(fgets(line, (int)sizeof(line), fp) != NULL)
    {
        if(sscanf(line, "%f %f %f", load_s, load_m, load_l) == 0)
            return(-1);
    }
    else
        return(-1);

    if(fclose(fp) < 0)
        return(-1);
    
    return(0);
}

int count_host_tcp_conn(int *tcp_count, int *tcp_list_count)
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

int count_host_udp_conn(int *udp_count, int *udp_list_count)
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

int count_conntrack_conn(struct vuurmuur_config *cnf, int *conntrack_count,
            int *tcp_count, int *udp_count, int *other_count)
{
    FILE    *fp=NULL;
    char    line[512];
    int     i=0,
            tcp=0,
            udp=0,
            other=0;

    if(cnf->use_ipconntrack == TRUE || (!(fp = fopen(PROC_NFCONNTRACK, "r"))))
    {
        if (!(fp = fopen(PROC_IPCONNTRACK, "r")))
            return(-1);
    }

    while(fgets(line, (int)sizeof(line), fp) != NULL)
    {
        if(strncmp(line, "tcp", 3) == 0)
            tcp++;
        else if(strncmp(line, "udp", 3) == 0)
            udp++;
        else
            other++;

        i++;
    }

    *conntrack_count = i;
    *tcp_count = tcp;
    *udp_count = udp;
    *other_count = other;

    if(fclose(fp) < 0)
        return(-1);

    return(0);
}

int get_conntrack_max(int *conntrack_max)
{
    FILE    *fp = NULL;
    char    proc_ip_conntrack_max[] = "/proc/sys/net/ipv4/ip_conntrack_max",
            proc_nf_conntrack_max[] = "/proc/sys/net/nf_conntrack_max",
            line[16] = "";

    /* try to open the conntrack max file */
    if(!(fp = fopen(proc_ip_conntrack_max, "r"))) {
        if(!(fp = fopen(proc_nf_conntrack_max, "r"))) {
            return(-1);
        }
    }

    if(fgets(line, (int)sizeof(line), fp) != NULL)
        *conntrack_max = atoi(line);

    if(fclose(fp) < 0)
        return(-1);

    return(0);
}

/*  get_meminfo

    Gets the info about the memory status of the system.

    Returncodes:
         0: ok
        -1: error
*/
int get_meminfo(int *mem_total, int *mem_free, int *mem_cached, int *mem_buffers)
{
    FILE    *fp=NULL;
    char    proc_meminfo[] = "/proc/meminfo",
            line[64],
            variable[16],
            value[16];

    // open the proc entry
    if(!(fp = fopen(proc_meminfo, "r")))
    {
        (void)vrprint.error(-1, VR_ERR, gettext("opening '%s' failed: %s (in: %s:%d)."),
                                proc_meminfo,
                                strerror(errno),
                                __FUNC__, __LINE__);
        return(-1);
    }

    // loop trough the file and get the info
    while(fgets(line, (int)sizeof(line), fp) != NULL)
    {
        sscanf(line, "%s %s", variable, value);

        if(strcmp(variable, "MemTotal:") == 0)
            *mem_total = atoi(value);
        else if(strcmp(variable, "MemFree:") == 0)
            *mem_free = atoi(value);
        else if(strcmp(variable, "Buffers:") == 0)
            *mem_buffers = atoi(value);
        else if(strcmp(variable, "Cached:") == 0)
            *mem_cached = atoi(value);
    }

    if(fclose(fp) < 0)
        return(-1);

    return(0);
}

int get_system_uptime(char *s_day, char *s_hour, char *s_minute, char *s_second)
{
    FILE    *fp=NULL;
    char    proc_uptime[] = "/proc/uptime",
            line[512];
    int     upt_i=0,
            day=0,
            hour=0,
            min=0,
            sec=0;

// param check

    if(!(fp = fopen(proc_uptime, "r")))
        return(-1);

    if(fgets(line, (int)sizeof(line), fp) != NULL)
        sscanf(line, "%d", &upt_i);

    day = upt_i / 86400;
    hour = (upt_i - (day * 86400)) / 3600;
    min =  (upt_i - (day * 86400) - (hour * 3600))/60;
    sec =  (upt_i - (day * 86400) - (hour * 3600) - (min * 60));

    if(fclose(fp) < 0)
        return(-1);

    snprintf(s_day, 5, "%4d", day);
    snprintf(s_hour, 3, "%02d", hour);
    snprintf(s_minute, 3, "%02d", min);
    snprintf(s_second, 3, "%02d", sec);

    return(0);
}

/*  status_section_init

    This function creates the status section window and the fields inside it.
    It also draws - alot of - lines.

    Returncodes:
         0: ok
        -1: error
*/
int
status_section_init(const int debuglvl, int height, int width, int starty, int startx, unsigned int ifac_num)
{
    int             rows,
                    cols,
                    max_height,
                    max_width;
    unsigned int    ifac_fields=0,
                    ifacs=0,
                    ifac_start=12;
    size_t          i = 0;

    /* get and check the screen dimentions */
    getmaxyx(stdscr, max_height, max_width);
    if(width > max_width)
        return(-1);
    if(15 + (int)ifac_num > height)
        ifac_num = (unsigned int)height - 15;

    /* set the number of fields */
    StatusSection.n_fields = (size_t)(16 + (6 * ifac_num));

    /* alloc the needed memory */
    if(!(StatusSection.fields = (FIELD **)calloc(StatusSection.n_fields + 1, sizeof(FIELD *))))
    {
        (void)vrprint.error(-1, VR_ERR, gettext("calloc failed: %s (in: %s:%d)."), strerror(errno), __FUNC__, __LINE__);
        return(-1);
    }

    /* create the fields */
    StatusSection.fields[0] = new_field(1, 5, 4, 13, 0, 1);
    set_field_buffer_wrap(debuglvl, StatusSection.fields[0], 1, "ld_s");
    StatusSection.fields[1] = new_field(1, 5, 4, 19, 0, 1);
    set_field_buffer_wrap(debuglvl, StatusSection.fields[1], 1, "ld_m");
    StatusSection.fields[2] = new_field(1, 5, 4, 25, 0, 1);
    set_field_buffer_wrap(debuglvl, StatusSection.fields[2], 1, "ld_l");

    StatusSection.fields[3] = new_field(1, 6, 4, 43, 0, 1);
    set_field_buffer_wrap(debuglvl, StatusSection.fields[3], 1, "mem_t");
    StatusSection.fields[4] = new_field(1, 6, 4, 51, 0, 1);
    set_field_buffer_wrap(debuglvl, StatusSection.fields[4], 1, "mem_f");
    StatusSection.fields[5] = new_field(1, 6, 4, 59, 0, 1);
    set_field_buffer_wrap(debuglvl, StatusSection.fields[5], 1, "mem_c");
    StatusSection.fields[6] = new_field(1, 6, 4, 67, 0, 1);
    set_field_buffer_wrap(debuglvl, StatusSection.fields[6], 1, "mem_b");

    StatusSection.fields[7] = new_field(1, 4, 1, 61, 0, 1);
    set_field_buffer_wrap(debuglvl, StatusSection.fields[7], 1, "up_d");
    StatusSection.fields[8] = new_field(1, 2, 1, 66, 0, 1);
    set_field_buffer_wrap(debuglvl, StatusSection.fields[8], 1, "uh");
    StatusSection.fields[9] = new_field(1, 2, 1, 69, 0, 1);
    set_field_buffer_wrap(debuglvl, StatusSection.fields[9], 1, "um");
    StatusSection.fields[10] = new_field(1, 2, 1, 72, 0, 1);
    set_field_buffer_wrap(debuglvl, StatusSection.fields[10], 1, "us");


    StatusSection.fields[11] = new_field(1, 6, 6, 23, 0, 1);
    set_field_buffer_wrap(debuglvl, StatusSection.fields[11], 1, "con_t");
    StatusSection.fields[12] = new_field(1, 6, 7, 23, 0, 1);
    set_field_buffer_wrap(debuglvl, StatusSection.fields[12], 1, "con_u");
    StatusSection.fields[13] = new_field(1, 6, 6, 41, 0, 1);
    set_field_buffer_wrap(debuglvl, StatusSection.fields[13], 1, "con_o");

    StatusSection.fields[14] = new_field(1, 6, 6, 59, 0, 1);
    set_field_buffer_wrap(debuglvl, StatusSection.fields[14], 1, "con_c");
    StatusSection.fields[15] = new_field(1, 6, 7, 59, 0, 1);
    set_field_buffer_wrap(debuglvl, StatusSection.fields[15], 1, "con_m");

    /* create iface stats fields */
    for(ifacs = 0, ifac_fields = 16; ifacs < ifac_num; ifacs++)
    {
        StatusSection.fields[ifac_fields] = new_field(1, 8, (int)(ifac_start+ifacs), 13, 0, 1);
        set_field_buffer_wrap(debuglvl, StatusSection.fields[ifac_fields], 1, "recv_s");
        ifac_fields++;

        StatusSection.fields[ifac_fields] = new_field(1, 8, (int)(ifac_start+ifacs), 22, 0, 1);
        set_field_buffer_wrap(debuglvl, StatusSection.fields[ifac_fields], 1, "send_s");
        ifac_fields++;

        StatusSection.fields[ifac_fields] = new_field(1, 10, (int)(ifac_start+ifacs), 31, 0, 1);
        set_field_buffer_wrap(debuglvl, StatusSection.fields[ifac_fields], 1, "rcv_ti");
        ifac_fields++;

        StatusSection.fields[ifac_fields] = new_field(1, 10, (int)(ifac_start+ifacs), 42, 0, 1);
        set_field_buffer_wrap(debuglvl, StatusSection.fields[ifac_fields], 1, "snd_to");
        ifac_fields++;

        StatusSection.fields[ifac_fields] = new_field(1, 10, (int)(ifac_start+ifacs), 53, 0, 1);
        set_field_buffer_wrap(debuglvl, StatusSection.fields[ifac_fields], 1, "rcv_tf");
        ifac_fields++;

        StatusSection.fields[ifac_fields] = new_field(1, 10, (int)(ifac_start+ifacs), 64, 0, 1);
        set_field_buffer_wrap(debuglvl, StatusSection.fields[ifac_fields], 1, "snd_tf");
        ifac_fields++;
    }

    /* terminate the field array */
    StatusSection.fields[StatusSection.n_fields] = NULL;

    /* create the window and the panel */
    if(!(StatusSection.win = create_newwin(height, width, starty, startx, gettext("Status Section"), vccnf.color_win)))
    {
        (void)vrprint.error(-1, VR_INTERR, "create_newwin() failed (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }
    if(!(StatusSection.panel[0] = new_panel(StatusSection.win)))
    {
        (void)vrprint.error(-1, VR_INTERR, "new_panel() failed (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    /* field options */
    for(i = 0; i < StatusSection.n_fields; i++)
    {
        if(debuglvl >= LOW)
            set_field_back(StatusSection.fields[i], vccnf.color_win_rev);
        else
            set_field_back(StatusSection.fields[i], vccnf.color_win);

        field_opts_off(StatusSection.fields[i], O_AUTOSKIP);
        /* set status to false */
        set_field_status(StatusSection.fields[i], FALSE);
    }

    /* Create the form and post it */
    if(!(StatusSection.form = new_form(StatusSection.fields)))
    {
        (void)vrprint.error(-1, VR_INTERR, "new_form() failed (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }
    /* Calculate the area required for the form */
    scale_form(StatusSection.form, &rows, &cols);
    keypad(StatusSection.win, TRUE);
    /* Set main window and sub window */
    set_form_win(StatusSection.form, StatusSection.win);
    set_form_sub(StatusSection.form, derwin(StatusSection.win, rows, cols, 1, 2));

    if(post_form(StatusSection.form) != E_OK)
    {
        (void)vrprint.error(-1, VR_INTERR, "post_form() failed (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    /* print the field labels */

    /* TRANSLATORS: max 11 chars. */
    mvwprintw(StatusSection.win, 1, 2,  gettext("Hostname"));
    mvwprintw(StatusSection.win, 2, 2,  "Kernel");

    /* TRANSLATORS: max 3 chars. */
    mvwprintw(StatusSection.win, 1, 64,  gettext("day"));
    /* TRANSLATORS: this must be exactly the same regarding positions. */
    mvwprintw(StatusSection.win, 1, 68,  gettext("h  m  s"));
    mvwprintw(StatusSection.win, 2, 70,  ":");
    mvwprintw(StatusSection.win, 2, 73,  ":");
    /* TRANSLATORS: max 6 chars. */
    mvwprintw(StatusSection.win, 2, 55,  gettext("Uptime"));

    mvwprintw(StatusSection.win, 4, 15,  "1m    5m    15m");

    /* TRANSLATORS: max 10 chars. */
    mvwprintw(StatusSection.win, 5, 2,   gettext("Load"));
    /* TRANSLATORS: max 5 chars. */
    mvwprintw(StatusSection.win, 4, 46,  gettext("Total"));
    /* TRANSLATORS: max 5 chars. */
    mvwprintw(StatusSection.win, 4, 54,  gettext("Free"));
    /* TRANSLATORS: max 5 chars. */
    mvwprintw(StatusSection.win, 4, 62,  gettext("Cache"));
    /* TRANSLATORS: max 6 chars. */
    mvwprintw(StatusSection.win, 4, 70,  gettext("Buffer"));
    /* TRANSLATORS: max 9 chars. */
    mvwprintw(StatusSection.win, 5, 34,  gettext("Memory(MB)"));

    /* TRANSLATORS: max 11 chars. */
    mvwprintw(StatusSection.win, 8, 2,  gettext("Connections"));

    mvwprintw(StatusSection.win, 7, 16,  "Tcp");
    mvwprintw(StatusSection.win, 8, 16,  "Udp");

    /* TRANSLATORS: max 7 chars. */
    mvwprintw(StatusSection.win, 7, 34,  gettext("Other"));

    /* TRANSLATORS: max 7 chars. */
    mvwprintw(StatusSection.win, 7, 52,  gettext("Current"));
    /* TRANSLATORS: max 7 chars. */
    mvwprintw(StatusSection.win, 8, 52,  gettext("Maximal"));

    /* TRANSLATORS: max 11 chars. */
    mvwprintw(StatusSection.win, 10, 15, gettext("Speed/s"));
    /* TRANSLATORS: max 11 chars. */
    mvwprintw(StatusSection.win, 10, 33, gettext("Firewall"));
    /* TRANSLATORS: max 11 chars. */
    mvwprintw(StatusSection.win, 10, 55, gettext("Forwarded"));

    /* TRANSLATORS: max 11 chars. */
    mvwprintw(StatusSection.win, 11, 2,  gettext("Interfaces"));
       
    /* TRANSLATORS: max 6 chars. */
    mvwprintw(StatusSection.win, 11, 15,  gettext("Down"));
    /* TRANSLATORS: max 6 chars. */
    mvwprintw(StatusSection.win, 11, 24,  gettext("Up"));
    /* TRANSLATORS: max 6 chars. */
    mvwprintw(StatusSection.win, 11, 33,  gettext("In"));
    /* TRANSLATORS: max 6 chars. */
    mvwprintw(StatusSection.win, 11, 44,  gettext("Out"));
    /* TRANSLATORS: max 6 chars. */
    mvwprintw(StatusSection.win, 11, 55,  gettext("Recv"));
    /* TRANSLATORS: max 6 chars. */
    mvwprintw(StatusSection.win, 11, 66,  gettext("Send"));

    /*
        DRAW THE LINES
    */

    /* kernel and domainname */
    mvwvline(StatusSection.win,  1, 14, ACS_VLINE, 2);
    mvwvline(StatusSection.win,  1, 53, ACS_VLINE, 2);
    mvwvline(StatusSection.win,  1, 62, ACS_VLINE, 2);

    /* T-pieces on top */
    mvwaddch(StatusSection.win,  0, 14, ACS_TTEE);
    mvwaddch(StatusSection.win,  0, 53, ACS_TTEE);
    mvwaddch(StatusSection.win,  0, 62, ACS_TTEE);

    mvwhline(StatusSection.win,  3, 1,  ACS_HLINE, 76);
    mvwaddch(StatusSection.win,  3, 0,  ACS_LTEE);
    mvwaddch(StatusSection.win,  3, 77, ACS_RTEE);

    mvwaddch(StatusSection.win,  3, 14, ACS_PLUS);
    mvwaddch(StatusSection.win,  3, 20, ACS_TTEE);
    mvwaddch(StatusSection.win,  3, 26, ACS_TTEE);
    mvwaddch(StatusSection.win,  3, 32, ACS_TTEE);
    mvwaddch(StatusSection.win,  3, 44, ACS_TTEE);
    mvwaddch(StatusSection.win,  3, 52, ACS_TTEE);
    mvwaddch(StatusSection.win,  3, 53, ACS_BTEE);
    mvwaddch(StatusSection.win,  3, 60, ACS_TTEE);
    mvwaddch(StatusSection.win,  3, 62, ACS_BTEE);
    mvwaddch(StatusSection.win,  3, 68, ACS_TTEE);

    /* load fields */
    mvwvline(StatusSection.win,  4, 14, ACS_VLINE, 2);
    mvwvline(StatusSection.win,  4, 20, ACS_VLINE, 2);
    mvwvline(StatusSection.win,  4, 26, ACS_VLINE, 2);
    mvwvline(StatusSection.win,  4, 32, ACS_VLINE, 2);

    /* memory */
    mvwvline(StatusSection.win,  4, 44, ACS_VLINE, 2);
    mvwvline(StatusSection.win,  4, 52, ACS_VLINE, 2);
    mvwvline(StatusSection.win,  4, 60, ACS_VLINE, 2);
    mvwvline(StatusSection.win,  4, 68, ACS_VLINE, 2);

    mvwhline(StatusSection.win,  6, 1,  ACS_HLINE, 76);
    mvwaddch(StatusSection.win,  6, 0,  ACS_LTEE);
    mvwaddch(StatusSection.win,  6, 77, ACS_RTEE);

    mvwaddch(StatusSection.win,  6, 14, ACS_PLUS);

    mvwaddch(StatusSection.win,  6, 20, ACS_BTEE);
    mvwaddch(StatusSection.win,  6, 26, ACS_BTEE);
    mvwaddch(StatusSection.win,  6, 32, ACS_PLUS);
    mvwaddch(StatusSection.win,  6, 44, ACS_BTEE);
    mvwaddch(StatusSection.win,  6, 50, ACS_TTEE);
    mvwaddch(StatusSection.win,  6, 52, ACS_BTEE);

    mvwaddch(StatusSection.win,  6, 60, ACS_BTEE);
    mvwaddch(StatusSection.win,  6, 68, ACS_PLUS);

    /* uptime fields */
    mvwvline(StatusSection.win,  7, 14, ACS_VLINE, 2);
    mvwvline(StatusSection.win,  7, 32, ACS_VLINE, 2);
    mvwvline(StatusSection.win,  7, 50, ACS_VLINE, 2);
    mvwvline(StatusSection.win,  7, 68, ACS_VLINE, 2);

    /* connection fields */
    mvwhline(StatusSection.win,  9, 1, ACS_HLINE, 76);
    mvwaddch(StatusSection.win,  9, 0,  ACS_LTEE);
    mvwaddch(StatusSection.win,  9, 77, ACS_RTEE);

    mvwvline(StatusSection.win, 10, 14, ACS_VLINE, 2);
    mvwvline(StatusSection.win, 10, 32, ACS_VLINE, 2);
    mvwvline(StatusSection.win, 10, 54, ACS_VLINE, 2);
    //mvwvline(StatusSection.win, 10, 68, ACS_VLINE, 2);

    mvwaddch(StatusSection.win,  9, 14, ACS_PLUS);
    mvwaddch(StatusSection.win,  9, 32, ACS_PLUS);
    mvwaddch(StatusSection.win,  9, 50, ACS_BTEE);
    mvwaddch(StatusSection.win,  9, 54, ACS_TTEE);
    mvwaddch(StatusSection.win,  9, 68, ACS_BTEE);

    /* interface fields */
    mvwhline(StatusSection.win, (int)ifac_start, 14, ACS_HLINE, 63);
    mvwaddch(StatusSection.win, (int)ifac_start, 77, ACS_RTEE);
    mvwhline(StatusSection.win, (int)(ifac_start+ifac_num+1), 1, ACS_HLINE, 76);
    mvwaddch(StatusSection.win, (int)(ifac_start+ifac_num+1), 0,  ACS_LTEE);
    mvwaddch(StatusSection.win, (int)(ifac_start+ifac_num+1), 77, ACS_RTEE);

    mvwaddch(StatusSection.win, (int)ifac_start, 14, ACS_LTEE);
    //mvwaddch(StatusSection.win, ifac_start, 68, ACS_RTEE);

    mvwaddch(StatusSection.win, (int)(ifac_start+ifac_num+1), 14, ACS_BTEE);
    //mvwaddch(StatusSection.win, ifac_start+ifac_num+1, 68, ACS_BTEE);

    mvwvline(StatusSection.win, (int)(ifac_start+1), 14, ACS_VLINE, (int)ifac_num);

    mvwaddch(StatusSection.win, (int)ifac_start, 23, ACS_TTEE);
    mvwvline(StatusSection.win, (int)(ifac_start+1), 23, ACS_VLINE, (int)ifac_num);
    mvwaddch(StatusSection.win, (int)(ifac_start+ifac_num+1), 23, ACS_BTEE);

    mvwaddch(StatusSection.win, (int)ifac_start, 32, ACS_PLUS);
    mvwvline(StatusSection.win, (int)(ifac_start+1), 32, ACS_VLINE, (int)ifac_num);
    mvwaddch(StatusSection.win, (int)(ifac_start+ifac_num+1), 32, ACS_BTEE);

    mvwaddch(StatusSection.win, (int)ifac_start, 43, ACS_TTEE);
    mvwvline(StatusSection.win, (int)(ifac_start+1), 43, ACS_VLINE, (int)ifac_num);
    mvwaddch(StatusSection.win, (int)(ifac_start+ifac_num+1), 43, ACS_BTEE);

    mvwaddch(StatusSection.win, (int)ifac_start, 54, ACS_PLUS);
    mvwvline(StatusSection.win, (int)(ifac_start+1), 54, ACS_VLINE, (int)ifac_num);
    mvwaddch(StatusSection.win, (int)(ifac_start+ifac_num+1), 54, ACS_BTEE);

    mvwaddch(StatusSection.win, (int)ifac_start, 65, ACS_TTEE);
    mvwvline(StatusSection.win, (int)(ifac_start+1), 65, ACS_VLINE, (int)ifac_num);
    mvwaddch(StatusSection.win, (int)(ifac_start+ifac_num+1), 65, ACS_BTEE);

    //mvwvline(StatusSection.win, ifac_start+1, 68, ACS_VLINE, ifac_num);

    return(0);
}

int status_section_destroy(void)
{
    size_t i;

    // Un post form and free the memory
    unpost_form(StatusSection.form);
    free_form(StatusSection.form);

    for(i = 0; i < StatusSection.n_fields; i++)
    {
        free_field(StatusSection.fields[i]);
    }
    free(StatusSection.fields);

    del_panel(StatusSection.panel[0]);
    destroy_win(StatusSection.win);

    return(0);
}

/*  status_section

    This section shows information about the system.
    
    Returncodes:
        0: ok
        -1: error
*/
int
status_section(const int debuglvl, struct vuurmuur_config *cnf, struct vrmr_zones *zones, struct vrmr_interfaces *interfaces, struct vrmr_services *services)
{
    FIELD   *cur = NULL;
    int     retval = 0;
    int     quit = 0,
            ch = 0;

    int     y=0;

    unsigned int    i = 0,
                    cur_interface = 0;

    int     max_height = 0,
            max_width = 0,

            conntrack_conn_max = 0,

            conntrack_conn_total = 0,
            conntrack_conn_tcp = 0,
            conntrack_conn_udp = 0,
            conntrack_conn_other = 0,

            mem_total=0,
            mem_free=0,
            mem_cached=0,
            mem_bufferd=0;

    char    hostname[60] = "",
            load_str[6] = "",
            mem_str[7] = "",
            interfacename[13] = "",

            upt_day[5] = "",
            upt_hour[3] = "",
            upt_minute[3] = "",
            upt_second[3] = "",

            conn_max[7] = "",
            conn_total[7] = "",
            conn_tcp[7] = "",
            conn_udp[7] = "",
            conn_other[7] = "",

            recv_host[11] = "",
            send_host[11] = "",

            recv_net[11] = "",
            send_net[11] = "",

            recv_speed[9] = "",
            send_speed[9] = "";

    /* uname struct, for gettig the kernel version */
    struct utsname  uts_name;

    /* the byte counters */
    unsigned long   recv_bytes=0,
                    trans_bytes=0,
                    delta_bytes=0,
                    speed_bytes=0;

    /* load */
    float   load_s = 0, // 1 min
            load_m = 0, // 5 min
            load_l = 0; // 15 min

    /* structure for storing byte counters per interface */
    struct shadow_ifac_
    {
        char            calc;

        unsigned long   prev_recv_bytes;
        unsigned long   prev_send_bytes;

        unsigned long   prev_recv_packets;
        unsigned long   prev_send_packets;

        unsigned long   cur_recv_bytes;
        unsigned long   cur_send_bytes;

        unsigned long   cur_recv_packets;
        unsigned long   cur_send_packets;

        unsigned long long  send_host,
                            recv_host,

                            send_host_packets,
                            recv_host_packets,

                            send_net,
                            recv_net,

                            send_net_packets,
                            recv_net_packets;

        /* for the correction of the speed */
        struct timeval      begin_tv;
        struct timeval      end_tv;
    };

    struct shadow_ifac_     *shadow_ptr=NULL;
    struct vrmr_interface   *iface_ptr=NULL;

    struct vrmr_list_node             *d_node = NULL;
    struct vrmr_list_node             *shadow_node = NULL;

    // list which will hold the structs analog to the interfaces list
    d_list                  shadow_list;

    // we correct the speed with the time it takes to get all stats
    double                  elapse = 0;
    float                   correction = 0;

    int                     update_interval = 1000000; /* weird, in pratice this seems to be two sec */
    int                     slept_so_far    = 1000000; /* time slept since last update */

    /* top menu */
    char                    *key_choices[] =    {   "F12",
                                                    "F10"};
    int                     key_choices_n = 2;
    char                    *cmd_choices[] =    {   gettext("help"),
                                                    gettext("back")};
    int                     cmd_choices_n = 2;


    // first create our shadow list
    if(vrmr_list_setup(debuglvl, &shadow_list, free) < 0)
        return(-1);

    for(i=0; i < interfaces->list.len; i++)
    {
        if(!(shadow_ptr = malloc(sizeof(struct shadow_ifac_))))
            return(-1);

        shadow_ptr->calc = 1;

        shadow_ptr->prev_recv_bytes = 0;
        shadow_ptr->prev_send_bytes = 0;
        shadow_ptr->cur_recv_bytes = 0;
        shadow_ptr->cur_send_bytes = 0;

        gettimeofday(&shadow_ptr->begin_tv, 0);

        /* append to the list */
        if(vrmr_list_append(debuglvl, &shadow_list, shadow_ptr)  == NULL)
            return(-1);
    }

    /* create the service and zone hash for conn_get_stats */

    /*
        set up the statuswin
    */
    getmaxyx(stdscr, max_height, max_width);

    /*
        init
    */
    if(status_section_init(debuglvl, max_height-6, 78, 3, 1, interfaces->list.len) < 0)
        return(-1);

    /*
        make sure wgetch doesn't block
    */
    nodelay(StatusSection.win, TRUE);
    keypad(StatusSection.win, TRUE);

    /*
        get the hostname of the system, or set to error on failure
    */
    if(gethostname(hostname, sizeof(hostname)) < 0)
        (void)strlcpy(hostname, gettext("error"), sizeof(hostname));

    mvwprintw(StatusSection.win, 1, 15, "%s", hostname);

    /*
        uname - get some system information
    */
    if(uname(&uts_name) < 0)
        (void)vrprint.error(-1, VR_ERR, "uname() failed.");

    mvwprintw(StatusSection.win, 2, 15, "%s %s", uts_name.sysname, uts_name.release);

    /*
        get the maximum connections
    */
    if(get_conntrack_max(&conntrack_conn_max) < 0)
        (void)snprintf(conn_max, sizeof(conn_max), gettext("error"));
    else
        (void)snprintf(conn_max, sizeof(conn_max), "%6d", conntrack_conn_max);

    draw_top_menu(debuglvl, top_win, gettext("System Status"), key_choices_n, key_choices, cmd_choices_n, cmd_choices);

    update_panels();
    doupdate();

    /* the main loop */
    while(quit == 0 && retval == 0)
    {
        if(debuglvl >= LOW)
            (void)vrprint.debug(__FUNC__, "slept_so_far: %d, update_interval: %d.", slept_so_far, update_interval);

        /* check if we have slept long enough */
        if(slept_so_far >= update_interval)
        {
            
            if(debuglvl >= HIGH)
                (void)vrprint.debug(__FUNC__, "slept_so_far: %d -> now print.", slept_so_far);

            slept_so_far = 0;

            /*  update the information */
            if(get_sys_load(&load_s, &load_m, &load_l) < 0)
            {
                (void)vrprint.error(-1, VR_INTERR, "get_sys_load() failed (in: %s:%d).", __FUNC__, __LINE__);
                return(-1);
            }

            if(get_meminfo(&mem_total, &mem_free, &mem_cached, &mem_bufferd) < 0)
            {
                (void)vrprint.error(-1, VR_INTERR, "get_meminfo() failed (in: %s:%d).", __FUNC__, __LINE__);
                return(-1);
            }

            if(get_system_uptime(upt_day, upt_hour, upt_minute, upt_second) < 0)
            {
                (void)vrprint.error(-1, VR_INTERR, "get_system_uptime() failed (in: %s:%d).", __FUNC__, __LINE__);
                return(-1);
            }

            if(count_conntrack_conn(cnf, &conntrack_conn_total, &conntrack_conn_tcp, &conntrack_conn_udp, &conntrack_conn_other) < 0)
            {
                snprintf(conn_total, sizeof(conn_total), gettext("error"));
                snprintf(conn_tcp,   sizeof(conn_tcp),   gettext("error"));
                snprintf(conn_udp,   sizeof(conn_udp),   gettext("error"));
                snprintf(conn_other, sizeof(conn_other), gettext("error"));
            }
            else
            {
                snprintf(conn_total, sizeof(conn_total), "%6d", conntrack_conn_total);
                snprintf(conn_tcp,   sizeof(conn_tcp),   "%6d", conntrack_conn_tcp);
                snprintf(conn_udp,   sizeof(conn_udp),   "%6d", conntrack_conn_udp);
                snprintf(conn_other, sizeof(conn_other), "%6d", conntrack_conn_other);
            }

            /* loop trough the fields and update the information */
            for(i = 0; i < (unsigned int)StatusSection.n_fields; i++)
            {
                cur = StatusSection.fields[i];

                if(strncmp(field_buffer(cur, 1), "ld_s", 4) == 0)
                {
                    if(load_s > 2 && load_s < 5)
                        set_field_fore(cur, vccnf.color_win_yellow|A_BOLD);
                    else if(load_s >= 5)
                        set_field_fore(cur, vccnf.color_win_red|A_BOLD);
                    else
                        set_field_fore(cur, vccnf.color_win);

                    (void)snprintf(load_str, sizeof(load_str), "%2.2f", load_s);
                    set_field_buffer_wrap(debuglvl, cur, 0, load_str);
                }
                else if(strncmp(field_buffer(cur, 1), "ld_m", 4) == 0)
                {
                    if(load_m > 2 && load_m < 5)
                        set_field_fore(cur, vccnf.color_win_yellow|A_BOLD);
                    else if(load_m >= 5)
                        set_field_fore(cur, vccnf.color_win_red|A_BOLD);
                    else
                        set_field_fore(cur, vccnf.color_win);

                    (void)snprintf(load_str, sizeof(load_str), "%2.2f", load_m);
                    set_field_buffer_wrap(debuglvl, cur, 0, load_str);
            }
                else if(strncmp(field_buffer(cur, 1), "ld_l", 4) == 0)
                {
                    if(load_l > 2 && load_l < 5)
                        set_field_fore(cur, vccnf.color_win_yellow|A_BOLD);
                    else if(load_l >= 5)
                        set_field_fore(cur, vccnf.color_win_red|A_BOLD);
                    else
                        set_field_fore(cur, vccnf.color_win);

                    (void)snprintf(load_str, sizeof(load_str), "%2.2f", load_l);
                    set_field_buffer_wrap(debuglvl, cur, 0, load_str);
                }
                else if(strncmp(field_buffer(cur, 1), "mem_t", 5) == 0)
                {
                    snprintf(mem_str, sizeof(mem_str), "%6d", mem_total/1024);
                    set_field_buffer_wrap(debuglvl, cur, 0, mem_str);
                }
                else if(strncmp(field_buffer(cur, 1), "mem_f", 5) == 0)
                {
                    snprintf(mem_str, sizeof(mem_str), "%6d", mem_free/1024);
                    set_field_buffer_wrap(debuglvl, cur, 0, mem_str);
                }
                else if(strncmp(field_buffer(cur, 1), "mem_c", 5) == 0)
                {
                    snprintf(mem_str, sizeof(mem_str), "%6d", mem_cached/1024);
                    set_field_buffer_wrap(debuglvl, cur, 0, mem_str);
                }
                else if(strncmp(field_buffer(cur, 1), "mem_b", 5) == 0)
                {
                    snprintf(mem_str, sizeof(mem_str), "%6d", mem_bufferd/1024);
                    set_field_buffer_wrap(debuglvl, cur, 0, mem_str);
                }
                else if(strncmp(field_buffer(cur, 1), "up_d", 4) == 0)
                {
                    set_field_buffer_wrap(debuglvl, cur, 0, upt_day);
                }
                else if(strncmp(field_buffer(cur, 1), "uh", 2) == 0)
                {
                    set_field_buffer_wrap(debuglvl, cur, 0, upt_hour);
                }
                else if(strncmp(field_buffer(cur, 1), "um", 2) == 0)
                {
                    set_field_buffer_wrap(debuglvl, cur, 0, upt_minute);
                }
                else if(strncmp(field_buffer(cur, 1), "us", 2) == 0)
                {
                    set_field_buffer_wrap(debuglvl, cur, 0, upt_second);
                }
                else if(strncmp(field_buffer(cur, 1), "con_m", 5) == 0)
                {
                    set_field_buffer_wrap(debuglvl, cur, 0, conn_max);
                }
                else if(strncmp(field_buffer(cur, 1), "con_c", 5) == 0)
                {
                    set_field_buffer_wrap(debuglvl, cur, 0, conn_total);
                }
                else if(strncmp(field_buffer(cur, 1), "con_t", 5) == 0)
                {
                    set_field_buffer_wrap(debuglvl, cur, 0, conn_tcp);
                }
                else if(strncmp(field_buffer(cur, 1), "con_u", 5) == 0)
                {
                    set_field_buffer_wrap(debuglvl, cur, 0, conn_udp);
                }
                else if(strncmp(field_buffer(cur, 1), "con_o", 5) == 0)
                {
                    set_field_buffer_wrap(debuglvl, cur, 0, conn_other);
                }
            }

            /* print interfaces, starting at line 13 */
            for(cur_interface = 0, y = 13, d_node = interfaces->list.top, shadow_node = shadow_list.top;
                d_node && y < max_height-8;
                d_node = d_node->next, shadow_node = shadow_node->next)
            {
                unsigned long long  tmp_ull;

                iface_ptr = d_node->data;
                shadow_ptr = shadow_node->data;

                /* only show real interfaces */
                if(iface_ptr->device_virtual == FALSE)
                {
                    /* get the counters for determining speed */
                    get_iface_stats(debuglvl, iface_ptr->device, &recv_bytes, NULL, &trans_bytes, NULL);

                    /* get the real counters from iptables */
                    vrmr_get_iface_stats_from_ipt(debuglvl, cnf, iface_ptr->device, "INPUT", &shadow_ptr->recv_host_packets, &shadow_ptr->recv_host, &tmp_ull, &tmp_ull);
                    vrmr_get_iface_stats_from_ipt(debuglvl, cnf, iface_ptr->device, "OUTPUT", &tmp_ull, &tmp_ull, &shadow_ptr->send_host_packets, &shadow_ptr->send_host);
                    vrmr_get_iface_stats_from_ipt(debuglvl, cnf, iface_ptr->device, "FORWARD", &shadow_ptr->recv_net_packets, &shadow_ptr->recv_net, &shadow_ptr->send_net_packets, &shadow_ptr->send_net);

                    /* RECV host/firewall */
                    if((shadow_ptr->recv_host/(1024*1024)) >= 1000)
                    {
                        snprintf(recv_host, sizeof(recv_host), "%7.3f GB", (float)shadow_ptr->recv_host/(1024*1024*1024));
                        if(debuglvl >= HIGH)
                            (void)vrprint.debug(__FUNC__, "recv_host: '%s'.", recv_host);
                    }
                    else if((shadow_ptr->recv_host/(1024*1024)) < 1)
                        snprintf(recv_host, sizeof(recv_host), "%7d kb", (int)shadow_ptr->recv_host/(1024));
                    else
                        snprintf(recv_host, sizeof(recv_host), "%7.3f MB", (float)shadow_ptr->recv_host/(1024*1024));

                    /* SEND host/firewall */
                    if((shadow_ptr->send_host/(1024*1024)) >= 1000)
                        snprintf(send_host, sizeof(send_host), "%7.3f GB", (float)shadow_ptr->send_host/(1024*1024*1024));
                    else if((shadow_ptr->send_host/(1024*1024)) < 1)
                        snprintf(send_host, sizeof(send_host), "%7d kb", (int)shadow_ptr->send_host/(1024));
                    else
                        snprintf(send_host, sizeof(send_host), "%7.3f MB", (float)shadow_ptr->send_host/(1024*1024));

                    /* RECV net/forward */
                    if((shadow_ptr->recv_net/(1024*1024)) >= 1000)
                        snprintf(recv_net, sizeof(recv_net), "%7.3f GB", (float)shadow_ptr->recv_net/(1024*1024*1024));
                    else if((shadow_ptr->recv_net/(1024*1024)) < 1)
                        snprintf(recv_net, sizeof(recv_net), "%7d kb", (int)shadow_ptr->recv_net/(1024));
                    else
                        snprintf(recv_net, sizeof(recv_net), "%7.3f MB", (float)shadow_ptr->recv_net/(1024*1024));

                    /* SEND net/forward */
                    if((shadow_ptr->send_net/(1024*1024)) >= 1000)
                        snprintf(send_net, sizeof(send_net), "%7.3f GB", (float)shadow_ptr->send_net/(1024*1024*1024));
                    else if((shadow_ptr->send_net/(1024*1024)) < 1)
                        snprintf(send_net, sizeof(send_net), "%7d kb", (int)shadow_ptr->send_net/(1024));
                    else
                        snprintf(send_net, sizeof(send_net), "%7.3f MB", (float)shadow_ptr->send_net/(1024*1024));

                    /* store the number of bytes */
                    shadow_ptr->cur_recv_bytes = recv_bytes;
                    shadow_ptr->cur_send_bytes = trans_bytes;

                    /* get the time we needed for our run */
                    gettimeofday(&shadow_ptr->end_tv, 0);
                    elapse  = (double)shadow_ptr->end_tv.tv_sec + (double)shadow_ptr->end_tv.tv_usec * 1e-6;
                    elapse -= (double)shadow_ptr->begin_tv.tv_sec + (double)shadow_ptr->begin_tv.tv_usec * 1e-6;
                    gettimeofday(&shadow_ptr->begin_tv, 0);

                    /* this the correction value */
                    correction = elapse;

                    /* this is the value to be corrected */
                    delta_bytes = (shadow_ptr->cur_recv_bytes - shadow_ptr->prev_recv_bytes);
                    /* now we correct it */
                    speed_bytes = (delta_bytes/correction);

                    if(debuglvl >= HIGH)
                        (void)vrprint.debug(__FUNC__, "bytes: %d, corrections: %f", (int)speed_bytes, correction);

                    /* calculating the current connection speed */
                    if(iface_ptr->up == TRUE)
                    {
                        if(shadow_ptr->calc == 1)
                            snprintf(recv_speed, sizeof(recv_speed), "calc");
                        else if((speed_bytes/1024) < 1)
                            snprintf(recv_speed, sizeof(recv_speed), "%5d b", (int)speed_bytes);
                        else if((speed_bytes/1024) >= 1024)
                            snprintf(recv_speed, sizeof(recv_speed), "%5.1f mb", (float)speed_bytes/(1024*1024));
                        else
                            snprintf(recv_speed, sizeof(recv_speed), "%5.1f kb", (float)speed_bytes/1024);
                    }
                    else
                    {
                        snprintf(recv_speed, sizeof(recv_speed), "%5s", "-");
                    }


                    /* this is the value to be corrected */
                    delta_bytes = (shadow_ptr->cur_send_bytes - shadow_ptr->prev_send_bytes);
                    /* now we correct it */
                    delta_bytes = (delta_bytes/correction);

                    if(iface_ptr->up == TRUE)
                    {
                        if(shadow_ptr->calc == 1)
                            snprintf(send_speed, sizeof(send_speed), "calc");
                        else if((delta_bytes/1024) < 1)
                            snprintf(send_speed, sizeof(send_speed), "%5d b", (int)delta_bytes);
                        else if((delta_bytes/1024) >= 1024)
                            snprintf(send_speed, sizeof(send_speed), "%5.1f mb", (float)delta_bytes/(1024*1024));
                        else
                            snprintf(send_speed, sizeof(send_speed), "%5.1f kb", (float)delta_bytes/1024);
                    }
                    else
                    {
                        snprintf(send_speed, sizeof(send_speed), "%5s", "-");
                    }
        
                    /* set the fields to the form */
                    for(i = cur_interface; i < (unsigned int)StatusSection.n_fields; i++)
                    {
                        cur = StatusSection.fields[i];

                        if(strncmp(field_buffer(cur, 1), "recv_s", 6) == 0)
                            set_field_buffer_wrap(debuglvl, cur, 0, recv_speed);
                        else if(strncmp(field_buffer(cur, 1), "send_s", 6) == 0)
                            set_field_buffer_wrap(debuglvl, cur, 0, send_speed);

                        else if(strncmp(field_buffer(cur, 1), "rcv_ti", 6) == 0)
                            set_field_buffer_wrap(debuglvl, cur, 0, recv_host);
                        else if(strncmp(field_buffer(cur, 1), "snd_to", 6) == 0)
                            set_field_buffer_wrap(debuglvl, cur, 0, send_host);

                        else if(strncmp(field_buffer(cur, 1), "rcv_tf", 6) == 0)
                            set_field_buffer_wrap(debuglvl, cur, 0, recv_net);
                        else if(strncmp(field_buffer(cur, 1), "snd_tf", 6) == 0)
                        {
                            set_field_buffer_wrap(debuglvl, cur, 0, send_net);
                            break;
                        }

                    }
                    cur_interface = i + 1;

                    /* draw the interface name */
                    snprintf(interfacename, sizeof(interfacename), "%s", iface_ptr->name);
            
                    if(iface_ptr->up == TRUE)
                        wattron(StatusSection.win, vccnf.color_win|A_BOLD);
            
                    mvwprintw(StatusSection.win, y, 2,  "%s", interfacename);

                    if(iface_ptr->up == TRUE)
                        wattroff(StatusSection.win, vccnf.color_win|A_BOLD);

                    /* store the number of bytes */
                    shadow_ptr->prev_recv_bytes = recv_bytes;
                    shadow_ptr->prev_send_bytes = trans_bytes;

                    y++;

                    /*  after the first run we are no
                        longer calculating. */
                    if(shadow_ptr->calc > 0)
                        shadow_ptr->calc--;

                } /* end if virtual device */
            }

            /*
                finally draw the screen
            */
            wrefresh(StatusSection.win);
        }

        /* process the keyboard input */
        ch = wgetch(StatusSection.win);
        switch(ch)
        {
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
                print_help(debuglvl, ":[VUURMUUR:STATUS]:");
                break;
        }

        if(quit == 0)
        {
            usleep(10000);
            slept_so_far = slept_so_far + 10000;

            if(debuglvl >= HIGH)
                (void)vrprint.debug(__FUNC__, "just slept: slept_so_far '%d'.", slept_so_far);
        }
    }

    /* destroy hashtables and the shadowlist */
    vrmr_list_cleanup(debuglvl, &shadow_list);

    /* EXIT: cleanup */
    nodelay(StatusSection.win, FALSE);

    /* destroy the window and form */
    status_section_destroy();
    
    update_panels();
    doupdate();

    return(retval);
}
