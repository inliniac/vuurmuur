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

struct {
    PANEL *panel[1];
    WINDOW *win;
    FIELD **fields;
    FORM *form;
    size_t n_fields;
} traf_vol_section;

struct traf_vol {
    int year;
    int month;
    int day;
    char total; /* total for this timeunit */
    unsigned int recv_mb;
    unsigned int send_mb;
} traf_vol;

/*  strip the buf src from the spaces before the text. Leave other
    spaces alone.
*/
static void strip_buf(char *src, char *dst, size_t dstsize)
{
    size_t i = 0, k = 0;
    char copy_space = 0;

    for (i = 0; i < dstsize && i < StrMemLen(src); i++) {
        if (src[i] != ' ')
            copy_space = 1;

        if (src[i] != ' ' || copy_space == 1) {
            dst[k] = src[i];
            k++;
        }
    }
    dst[k] = '\0';
}

static void bandwidth_store(struct vrmr_list *list, int year, int month,
        int day, char total, unsigned int recv, unsigned int send)
{
    struct traf_vol *bw_ptr = NULL;

    bw_ptr = malloc(sizeof(struct traf_vol));
    vrmr_fatal_alloc("malloc", bw_ptr);

    bw_ptr->year = year;
    bw_ptr->month = month;
    bw_ptr->day = day;
    bw_ptr->total = total;
    bw_ptr->recv_mb = recv;
    bw_ptr->send_mb = send;

    /* append to the list */
    vrmr_fatal_if(vrmr_list_append(list, bw_ptr) == NULL);
}

/*
    on first sight it may look if this function solves an easy problem
    the hard way, just reading the output one line at a time should
    be enough right?

    wrong... the number of interfaces determines how long the lines
    are... so we read a number of bytes and try to analyse it...

    if days is 0, we don't limit the number of days.

    returncodes:
        -1: error
         0: ok, but no data
         1: ok
*/
static int bandwidth_get_iface(struct vrmr_config *conf, char *device,
        unsigned int year, int month, int start_day, int days, char only_total,
        struct vrmr_list *list)
{
    char bw_buf[512] = "", sect_buf[32] = "", sect_buf_stripped[32] = "",
         tmpfile[] = "/tmp/vuurmuur-iptrafvol-XXXXXX";
    char done = FALSE;
    int fd = 0;
    int result = 0;

    char data_month = 0;
    int data_day = 0;

    unsigned int k = 0;

    int act_border = 0;

    int device_column = 0; /* column where our
                        device can be found. */
    int cur_column = 0;

    int line_num = 0;

    char buf_done = 0;

    char parsing_device_line = 0, parsing_total_line = 0;

    char parsing_data = 0;

    char month_str[4] = "";

    unsigned int recv = 0, recv_sub = 0, send = 0, send_sub = 0;

    int retval = 0;

    char cmd_year_str[5] = "", cmd_month_str[3] = "", cmd_start_day_str[3] = "",
         cmd_num_days_str[11] = "";

    /* safety */
    vrmr_fatal_if_null(device);
    vrmr_fatal_if_null(list);
    vrmr_fatal_if(year > 9999);
    vrmr_fatal_if(!(month >= 1 && month <= 12));

    vrmr_debug(LOW, "looking for data for '%s'.", device);

    /* create the tempfile */
    fd = vrmr_create_tempfile(tmpfile);
    if (fd == -1)
        return (-1);
    close(fd);

    /* setup the list */
    vrmr_list_setup(list, free);

    snprintf(cmd_year_str, sizeof(cmd_year_str), "%u", year);
    snprintf(cmd_month_str, sizeof(cmd_month_str), "%d", month);
    snprintf(cmd_start_day_str, sizeof(cmd_start_day_str), "%d", start_day);

    /* see if we need to pass the -s option to iptrafvol*/
    if (days > 0) {
        snprintf(cmd_num_days_str, sizeof(cmd_num_days_str), "%d", days);
        const char *args[] = {vccnf.iptrafvol_location, "-d", "-y",
                cmd_year_str, "-m", cmd_month_str, "-b", cmd_start_day_str,
                "-s", cmd_num_days_str, NULL};
        char *outputs[] = {tmpfile, "/dev/null", NULL};
        result = libvuurmuur_exec_command(
                conf, vccnf.iptrafvol_location, args, outputs);
    } else {
        const char *args[] = {vccnf.iptrafvol_location, "-d", "-y",
                cmd_year_str, "-m", cmd_month_str, "-b", cmd_start_day_str,
                NULL};
        char *outputs[] = {tmpfile, "/dev/null", NULL};
        result = libvuurmuur_exec_command(
                conf, vccnf.iptrafvol_location, args, outputs);
    }
    if (result != 0) {
        return (-1);
    }

    /* open the file for reading */
    fd = open(tmpfile, 0);
    if (fd < 0) {
        vrmr_error(-1, VR_ERR, gettext("opening '%s' failed: %s"), tmpfile,
                strerror(errno));
        return (-1);
    }

    while (done == FALSE) {
        memset(bw_buf, 0, sizeof(bw_buf));

        ssize_t readsize = read(fd, bw_buf, sizeof(bw_buf));
        if (readsize > 0) {
            for (unsigned int i = 0; i < (unsigned int)readsize; i++) {
                if (bw_buf[i] == '\n') {
                    line_num++;

                    act_border = 0;

                    sect_buf[k] = '\0';
                    k = 0;

                    if (parsing_device_line == 1) {
                        parsing_device_line = 0;
                    }
                    if (parsing_total_line == 1) {
                        done = 1;
                        break;
                    }

                    buf_done = 1;
                } else if (bw_buf[i] == '|') {
                    act_border++;
                    sect_buf[k] = '\0';
                    k = 0;

                    buf_done = 1;
                } else {
                    if (k < (unsigned int)sizeof(sect_buf) - 1) {
                        sect_buf[k] = bw_buf[i];
                        k++;
                    } else {
                        sect_buf[k] = '\0';
                    }
                }

                if (line_num > 5)
                    parsing_data = 1;

                if (buf_done == 1) {
                    buf_done = 0;

                    /* strip the buffer from the starting whitespaces */
                    strip_buf(sect_buf, sect_buf_stripped,
                            sizeof(sect_buf_stripped));

                    /* get the current column */
                    cur_column = act_border - 1;

                    if (line_num == 1) {
                        vrmr_debug(
                                HIGH, "line_num == 1: '%s'", sect_buf_stripped);

                        if (strncmp("no data", sect_buf_stripped, 7) == 0) {
                            retval = 0;
                            done = TRUE;
                            break;
                        }
                    }

                    /* the deviceline starts with MBytes */
                    if (strncmp(sect_buf_stripped, "MBytes", 6) == 0)
                        parsing_device_line = 1;

                    /* this is the total line */
                    if (strcmp(sect_buf_stripped, "Total:") == 0)
                        parsing_total_line = 1;

                    /* date column */
                    if (parsing_data == 1 && cur_column == 1 &&
                            only_total == 0) {
                        sscanf(sect_buf_stripped, "%d %3s", &data_day,
                                month_str);

                        /* parse the month */
                        if (strcmp(month_str, "Jan") == 0)
                            data_month = 1;
                        else if (strcmp(month_str, "Feb") == 0)
                            data_month = 2;
                        else if (strcmp(month_str, "Mar") == 0)
                            data_month = 3;
                        else if (strcmp(month_str, "Apr") == 0)
                            data_month = 4;
                        else if (strcmp(month_str, "May") == 0)
                            data_month = 5;
                        else if (strcmp(month_str, "Jun") == 0)
                            data_month = 6;
                        else if (strcmp(month_str, "Jul") == 0)
                            data_month = 7;
                        else if (strcmp(month_str, "Aug") == 0)
                            data_month = 8;
                        else if (strcmp(month_str, "Sep") == 0)
                            data_month = 9;
                        else if (strcmp(month_str, "Oct") == 0)
                            data_month = 10;
                        else if (strcmp(month_str, "Nov") == 0)
                            data_month = 11;
                        else if (strcmp(month_str, "Dec") == 0)
                            data_month = 12;
                        else {
                            vrmr_error(-1, VR_ERR,
                                    gettext("could not parse month '%s'"),
                                    month_str);
                            retval = -1;
                            goto end;
                        }
                    }
                    /* device column */
                    if (parsing_data == 1 && device_column > 1 &&
                            cur_column == device_column &&
                            ((only_total == 1 && parsing_total_line == 1) ||
                                    only_total == 0)) {
                        sscanf(sect_buf_stripped, "%u.%u %u.%u", &recv,
                                &recv_sub, &send, &send_sub);
                        recv = ((recv * 10) + recv_sub) / 10;
                        send = ((send * 10) + send_sub) / 10;

                        vrmr_debug(
                                LOW, "recv = %.1u, send = %.1u.", recv, send);

                        retval = 1;

                        /* we asume that the date is already parsed */
                        bandwidth_store(list, year, data_month, data_day,
                                parsing_total_line, recv, send);
                    }

                    /* parse the deviceline to determine the column */
                    if (parsing_device_line == 1) {
                        if (strcmp(sect_buf_stripped, device) == 0) {
                            /* act border includes the last borderline, so -1.
                             */
                            device_column = cur_column;

                            vrmr_debug(LOW,
                                    "sect_buf_stripped '%s' match! (device: "
                                    "%s) column = %d.",
                                    sect_buf_stripped, device, device_column);
                        }
                    }
                }
            }
        } else {
            done = TRUE;
        }
    }
end:
    /* close the file again */
    (void)close(fd);

    /* remove the file */
    if (unlink(tmpfile) == -1) {
        vrmr_error(-1, VR_ERR, gettext("removing '%s' failed (unlink): %s"),
                tmpfile, strerror(errno));
        return (-1);
    }

    return (retval);
}

/*  trafvol_section_init

    This function creates the trafvol section window and the fields inside it.
*/
static void trafvol_section_init(
        int height, int width, int starty, int startx, unsigned int ifac_num)
{
    size_t i = 0;
    int rows = 0, cols = 0;
    int max_height = 0, max_width = 0, toprow = 0, num_rows = (int)ifac_num;
    unsigned int ifacs = 0, ifac_fields = 0, ifac_start = 4;

    /* get and check the screen dimentions */
    getmaxyx(stdscr, max_height, max_width);
    vrmr_fatal_if(width > max_width || height > max_height);

    /* set the number of fields:

        interfacename,
        today in, today out,
        yesterday in, yesterday out,
        7 days in, 7 days out,
        this month in, this month out,
        last month in, last month out
    */
    traf_vol_section.n_fields = 11 * (size_t)ifac_num;

    /* alloc the needed memory */
    traf_vol_section.fields =
            (FIELD **)calloc(traf_vol_section.n_fields + 1, sizeof(FIELD *));
    vrmr_fatal_alloc("calloc", traf_vol_section.fields);

    /* create iface stats fields */
    for (ifacs = 0, ifac_fields = 0; ifacs < ifac_num; ifacs++) {
        toprow = (int)(ifac_start + ifacs);

        /* interface name */
        traf_vol_section.fields[ifac_fields] =
                new_field_wrap(1, 15, toprow, 0, 0, 1);
        set_field_buffer_wrap(
                traf_vol_section.fields[ifac_fields], 1, "ifacname");
        ifac_fields++;

        traf_vol_section.fields[ifac_fields] =
                new_field_wrap(1, 5, toprow, 16, 0, 1);
        set_field_buffer_wrap(traf_vol_section.fields[ifac_fields], 1, "t-in");
        ifac_fields++;

        traf_vol_section.fields[ifac_fields] =
                new_field_wrap(1, 5, toprow, 22, 0, 1);
        set_field_buffer_wrap(traf_vol_section.fields[ifac_fields], 1, "t-ou");
        ifac_fields++;

        traf_vol_section.fields[ifac_fields] =
                new_field_wrap(1, 5, toprow, 28, 0, 1);
        set_field_buffer_wrap(traf_vol_section.fields[ifac_fields], 1, "y-in");
        ifac_fields++;

        traf_vol_section.fields[ifac_fields] =
                new_field_wrap(1, 5, toprow, 34, 0, 1);
        set_field_buffer_wrap(traf_vol_section.fields[ifac_fields], 1, "y-ou");
        ifac_fields++;

        traf_vol_section.fields[ifac_fields] =
                new_field_wrap(1, 5, toprow, 40, 0, 1);
        set_field_buffer_wrap(traf_vol_section.fields[ifac_fields], 1, "7-in");
        ifac_fields++;

        traf_vol_section.fields[ifac_fields] =
                new_field_wrap(1, 5, toprow, 46, 0, 1);
        set_field_buffer_wrap(traf_vol_section.fields[ifac_fields], 1, "7-ou");
        ifac_fields++;

        traf_vol_section.fields[ifac_fields] =
                new_field_wrap(1, 5, toprow, 52, 0, 1);
        set_field_buffer_wrap(traf_vol_section.fields[ifac_fields], 1, "t-in");
        ifac_fields++;

        traf_vol_section.fields[ifac_fields] =
                new_field_wrap(1, 5, toprow, 58, 0, 1);
        set_field_buffer_wrap(traf_vol_section.fields[ifac_fields], 1, "t-ou");
        ifac_fields++;

        traf_vol_section.fields[ifac_fields] =
                new_field_wrap(1, 5, toprow, 64, 0, 1);
        set_field_buffer_wrap(traf_vol_section.fields[ifac_fields], 1, "l-in");
        ifac_fields++;

        traf_vol_section.fields[ifac_fields] =
                new_field_wrap(1, 5, toprow, 70, 0, 1);
        set_field_buffer_wrap(traf_vol_section.fields[ifac_fields], 1, "l-ou");
        ifac_fields++;
    }

    /* terminate the field array */
    traf_vol_section.fields[traf_vol_section.n_fields] = NULL;

    /* create the window and the panel */
    traf_vol_section.win = create_newwin(height, width, starty, startx,
            gettext("Traffic Volume Section"), vccnf.color_win);
    vrmr_fatal_if_null(traf_vol_section.win);

    traf_vol_section.panel[0] = new_panel(traf_vol_section.win);
    vrmr_fatal_if_null(traf_vol_section.panel[0]);

    /* field options */
    for (i = 0; i < traf_vol_section.n_fields; i++) {
        set_field_back(traf_vol_section.fields[i], vccnf.color_win);
        field_opts_off(traf_vol_section.fields[i], O_AUTOSKIP);
        set_field_status(traf_vol_section.fields[i], FALSE);
    }

    /* Create the form and post it */
    traf_vol_section.form = new_form(traf_vol_section.fields);
    vrmr_fatal_if_null(traf_vol_section.form);
    /* Calculate the area required for the form */
    scale_form(traf_vol_section.form, &rows, &cols);
    keypad(traf_vol_section.win, TRUE);
    /* Set main window and sub window */
    set_form_win(traf_vol_section.form, traf_vol_section.win);
    set_form_sub(traf_vol_section.form,
            derwin(traf_vol_section.win, rows, cols, 1, 2));
    vrmr_fatal_if(post_form(traf_vol_section.form) != E_OK);

    mvwprintw(traf_vol_section.win, 3, 2, gettext("Interface"));
    mvwprintw(traf_vol_section.win, 2, 18, gettext("Today"));
    mvwprintw(traf_vol_section.win, 3, 18, gettext("In"));
    mvwprintw(traf_vol_section.win, 3, 24, gettext("Out"));
    mvwprintw(traf_vol_section.win, 2, 30, gettext("Yesterday"));
    mvwprintw(traf_vol_section.win, 3, 30, gettext("In"));
    mvwprintw(traf_vol_section.win, 3, 36, gettext("Out"));
    mvwprintw(traf_vol_section.win, 2, 42, gettext("7-days"));
    mvwprintw(traf_vol_section.win, 3, 42, gettext("In"));
    mvwprintw(traf_vol_section.win, 3, 48, gettext("Out"));
    mvwprintw(traf_vol_section.win, 2, 54, gettext("This month"));
    mvwprintw(traf_vol_section.win, 3, 54, gettext("In"));
    mvwprintw(traf_vol_section.win, 3, 60, gettext("Out"));
    mvwprintw(traf_vol_section.win, 2, 66, gettext("Last month"));
    mvwprintw(traf_vol_section.win, 3, 66, gettext("In"));
    mvwprintw(traf_vol_section.win, 3, 72, gettext("Out"));
    mvwhline(traf_vol_section.win, 4, 1, ACS_HLINE, 76);
    mvwaddch(traf_vol_section.win, 4, 0, ACS_LTEE);
    mvwaddch(traf_vol_section.win, 4, 77, ACS_RTEE);

    mvwvline(traf_vol_section.win, 5, 17, ACS_VLINE, num_rows);
    mvwaddch(traf_vol_section.win, 4, 17, ACS_TTEE);
    mvwvline(traf_vol_section.win, 5, 23, ACS_VLINE, num_rows);
    mvwaddch(traf_vol_section.win, 4, 23, ACS_TTEE);
    mvwvline(traf_vol_section.win, 5, 29, ACS_VLINE, num_rows);
    mvwaddch(traf_vol_section.win, 4, 29, ACS_TTEE);
    mvwvline(traf_vol_section.win, 5, 35, ACS_VLINE, num_rows);
    mvwaddch(traf_vol_section.win, 4, 35, ACS_TTEE);
    mvwvline(traf_vol_section.win, 5, 41, ACS_VLINE, num_rows);
    mvwaddch(traf_vol_section.win, 4, 41, ACS_TTEE);
    mvwvline(traf_vol_section.win, 5, 47, ACS_VLINE, num_rows);
    mvwaddch(traf_vol_section.win, 4, 47, ACS_TTEE);
    mvwvline(traf_vol_section.win, 5, 53, ACS_VLINE, num_rows);
    mvwaddch(traf_vol_section.win, 4, 53, ACS_TTEE);
    mvwvline(traf_vol_section.win, 5, 59, ACS_VLINE, num_rows);
    mvwaddch(traf_vol_section.win, 4, 59, ACS_TTEE);
    mvwvline(traf_vol_section.win, 5, 65, ACS_VLINE, num_rows);
    mvwaddch(traf_vol_section.win, 4, 65, ACS_TTEE);
    mvwvline(traf_vol_section.win, 5, 71, ACS_VLINE, num_rows);
    mvwaddch(traf_vol_section.win, 4, 71, ACS_TTEE);

    /* don't print this line if it overlaps with the window border */
    if (5 + num_rows + 1 < height) {
        mvwhline(traf_vol_section.win, 5 + num_rows, 1, ACS_HLINE, 76);
        mvwaddch(traf_vol_section.win, 5 + num_rows, 0, ACS_LTEE);
        mvwaddch(traf_vol_section.win, 5 + num_rows, 77, ACS_RTEE);
    }

    mvwaddch(traf_vol_section.win, 5 + num_rows, 17, ACS_BTEE);
    mvwaddch(traf_vol_section.win, 5 + num_rows, 23, ACS_BTEE);
    mvwaddch(traf_vol_section.win, 5 + num_rows, 29, ACS_BTEE);
    mvwaddch(traf_vol_section.win, 5 + num_rows, 35, ACS_BTEE);
    mvwaddch(traf_vol_section.win, 5 + num_rows, 41, ACS_BTEE);
    mvwaddch(traf_vol_section.win, 5 + num_rows, 47, ACS_BTEE);
    mvwaddch(traf_vol_section.win, 5 + num_rows, 53, ACS_BTEE);
    mvwaddch(traf_vol_section.win, 5 + num_rows, 59, ACS_BTEE);
    mvwaddch(traf_vol_section.win, 5 + num_rows, 65, ACS_BTEE);
    mvwaddch(traf_vol_section.win, 5 + num_rows, 71, ACS_BTEE);
}

static void trafvol_section_destroy(void)
{
    size_t i = 0;

    // Un post form and free the memory
    unpost_form(traf_vol_section.form);
    free_form(traf_vol_section.form);
    for (i = 0; i < traf_vol_section.n_fields; i++) {
        free_field(traf_vol_section.fields[i]);
    }
    free(traf_vol_section.fields);
    del_panel(traf_vol_section.panel[0]);
    destroy_win(traf_vol_section.win);
}

static void create_bw_string(unsigned int mb, char *str, size_t len)
{
    vrmr_fatal_if_null(str);

    if (mb == 0)
        snprintf(str, len, "  0 M");
    else if (mb > 0 && mb < 10)
        snprintf(str, len, "%u.0 M", mb);
    else if (mb >= 10 && mb < 100)
        snprintf(str, len, " %u M", mb);
    else if (mb >= 100 && mb < 1000)
        snprintf(str, len, "%u M", mb);
    else if (mb >= 1000 && mb < 10000)
        snprintf(str, len, "%2.2fG", (float)mb / 1024);
    else if (mb >= 10000 && mb < 100000)
        snprintf(str, len, "%2.1fG", (float)mb / 1024);
    else if (mb >= 100000 && mb < 1000000)
        snprintf(str, len, "%uG", mb / 1024);
    else if (mb >= 1000000UL && mb < 10000000UL)
        snprintf(str, len, "%2.2fT", (float)mb / (1024 * 1024));
    else if (mb >= 10000000UL && mb < 100000000UL)
        snprintf(str, len, "%2.1fT", (float)mb / (1024 * 1024));
    else
        snprintf(str, len, "%uT", mb / (1024 * 1024));
}

/*  trafvol_section

    This section shows bandwidth usage of the system.

    Returncodes:
        0: ok
        -1: error
*/
int trafvol_section(
        struct vrmr_config *conf, struct vrmr_interfaces *interfaces)
{
    int retval = 0;
    int quit = 0, ch;

    int max_onscreen = 0, max_height = 0;
    unsigned int i = 0;
    unsigned int ifac_num = 0;
    struct vrmr_interface *iface_ptr = NULL;

    struct vrmr_list_node *d_node = NULL, *bw_d_node = NULL;
    struct traf_vol *bw_ptr = NULL;
    struct vrmr_list bw_list;

    int year = 0, month = 0;

    time_t cur_time, yesterday_time, lastweek_time;
    struct tm cur_tm, yesterday_tm, lastweek_tm;

    char bw_str[6] = "";

    int result = 0;

    int update_interval =
            10000000; /* weird, in pratice this seems to be twenty sec */
    int slept_so_far = 10000000; /* time slept since last update */

    /* top menu */
    const char *key_choices[] = {"F12", "F10"};
    int key_choices_n = 2;
    const char *cmd_choices[] = {gettext("help"), gettext("back")};
    int cmd_choices_n = 2;

    if (interfaces->list.len == 0) {
        vrmr_warning(VR_WARN, gettext("no interfaces found. Please define an "
                                      "interface first."));
        return (0);
    }

    if (strcmp(vccnf.iptrafvol_location, "") == 0) {
        vrmr_error(-1, VR_ERR,
                gettext("please set the location of the iptrafvol.pl command "
                        "in the Settings."));
        return (-1);
    }

    max_height = getmaxy(stdscr);
    max_onscreen = max_height - 8 - 6;

    /* count the number of non virtual interfaces */
    for (d_node = interfaces->list.top; d_node; d_node = d_node->next) {
        vrmr_fatal_if_null(d_node->data);
        iface_ptr = d_node->data;

        if (iface_ptr->device_virtual == FALSE) {
            ifac_num++;
        }
    }

    if (ifac_num > (unsigned int)max_onscreen)
        ifac_num = (unsigned int)max_onscreen;

    /* init */
    trafvol_section_init(max_height - 8, 78, 4, 1, ifac_num);
    /* make sure wgetch doesn't block */
    nodelay(traf_vol_section.win, TRUE);
    keypad(traf_vol_section.win, TRUE);
    draw_top_menu(top_win, gettext("Traffic Volume"), key_choices_n,
            key_choices, cmd_choices_n, cmd_choices);
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

            /* get the time */
            cur_time = time(NULL);
            vrmr_fatal_if(cur_time == -1);
            yesterday_time = cur_time - 86400;
            lastweek_time = cur_time - (86400 * 7);

            vrmr_fatal_if(localtime_r(&cur_time, &cur_tm) == NULL);
            vrmr_fatal_if(localtime_r(&yesterday_time, &yesterday_tm) == NULL);
            vrmr_fatal_if(localtime_r(&lastweek_time, &lastweek_tm) == NULL);

            /* update data here */
            for (d_node = interfaces->list.top, i = 0; d_node && i < ifac_num;
                    d_node = d_node->next) {
                vrmr_fatal_if_null(d_node->data);
                iface_ptr = d_node->data;

                if (iface_ptr->device_virtual == TRUE)
                    continue;

                /* interface name */
                set_field_buffer_wrap(
                        traf_vol_section.fields[11 * i], 0, iface_ptr->name);

                /* get the bw for today */
                result = bandwidth_get_iface(conf, iface_ptr->device,
                        cur_tm.tm_year + 1900, cur_tm.tm_mon + 1,
                        cur_tm.tm_mday, 1, 1, &bw_list);
                if (result == 1) {
                    for (bw_d_node = bw_list.top; bw_d_node;
                            bw_d_node = bw_d_node->next) {
                        vrmr_fatal_if_null(bw_d_node->data);
                        bw_ptr = bw_d_node->data;

                        create_bw_string(
                                bw_ptr->recv_mb, bw_str, sizeof(bw_str));
                        set_field_buffer_wrap(
                                traf_vol_section.fields[1 + (11 * i)], 0,
                                bw_str);

                        create_bw_string(
                                bw_ptr->send_mb, bw_str, sizeof(bw_str));
                        set_field_buffer_wrap(
                                traf_vol_section.fields[2 + (11 * i)], 0,
                                bw_str);
                    }
                    vrmr_list_cleanup(&bw_list);
                } else if (result == 0) {
                    set_field_buffer_wrap(
                            traf_vol_section.fields[1 + (11 * i)], 0, "  -  ");
                    set_field_buffer_wrap(
                            traf_vol_section.fields[2 + (11 * i)], 0, "  -  ");
                } else {
                    set_field_buffer_wrap(traf_vol_section.fields[1 + (11 * i)],
                            0, gettext("error"));
                    set_field_buffer_wrap(traf_vol_section.fields[2 + (11 * i)],
                            0, gettext("error"));
                }

                /* get the bw for yesterday */
                result = bandwidth_get_iface(conf, iface_ptr->device,
                        yesterday_tm.tm_year + 1900, yesterday_tm.tm_mon + 1,
                        yesterday_tm.tm_mday, 1, 1, &bw_list);
                if (result == 1) {
                    for (bw_d_node = bw_list.top; bw_d_node;
                            bw_d_node = bw_d_node->next) {
                        vrmr_fatal_if_null(bw_d_node->data);
                        bw_ptr = bw_d_node->data;

                        create_bw_string(
                                bw_ptr->recv_mb, bw_str, sizeof(bw_str));
                        set_field_buffer_wrap(
                                traf_vol_section.fields[3 + (11 * i)], 0,
                                bw_str);

                        create_bw_string(
                                bw_ptr->send_mb, bw_str, sizeof(bw_str));
                        set_field_buffer_wrap(
                                traf_vol_section.fields[4 + (11 * i)], 0,
                                bw_str);
                    }
                    vrmr_list_cleanup(&bw_list);
                } else if (result == 0) {
                    set_field_buffer_wrap(
                            traf_vol_section.fields[3 + (11 * i)], 0, "  -  ");
                    set_field_buffer_wrap(
                            traf_vol_section.fields[4 + (11 * i)], 0, "  -  ");
                } else {
                    set_field_buffer_wrap(traf_vol_section.fields[3 + (11 * i)],
                            0, gettext("error"));
                    set_field_buffer_wrap(traf_vol_section.fields[4 + (11 * i)],
                            0, gettext("error"));
                }

                /* get the bw for past 7 days */
                result = bandwidth_get_iface(conf, iface_ptr->device,
                        lastweek_tm.tm_year + 1900, lastweek_tm.tm_mon + 1,
                        lastweek_tm.tm_mday, 7, 1, &bw_list);
                if (result == 1) {
                    for (bw_d_node = bw_list.top; bw_d_node;
                            bw_d_node = bw_d_node->next) {
                        vrmr_fatal_if_null(bw_d_node->data);
                        bw_ptr = bw_d_node->data;

                        create_bw_string(
                                bw_ptr->recv_mb, bw_str, sizeof(bw_str));
                        set_field_buffer_wrap(
                                traf_vol_section.fields[5 + (11 * i)], 0,
                                bw_str);

                        create_bw_string(
                                bw_ptr->send_mb, bw_str, sizeof(bw_str));
                        set_field_buffer_wrap(
                                traf_vol_section.fields[6 + (11 * i)], 0,
                                bw_str);
                    }
                    vrmr_list_cleanup(&bw_list);
                } else if (result == 0) {
                    set_field_buffer_wrap(
                            traf_vol_section.fields[5 + (11 * i)], 0, "  -  ");
                    set_field_buffer_wrap(
                            traf_vol_section.fields[6 + (11 * i)], 0, "  -  ");
                } else {
                    set_field_buffer_wrap(traf_vol_section.fields[5 + (11 * i)],
                            0, gettext("error"));
                    set_field_buffer_wrap(traf_vol_section.fields[6 + (11 * i)],
                            0, gettext("error"));
                }

                /* get the bw for the current month */
                result = bandwidth_get_iface(conf, iface_ptr->device,
                        cur_tm.tm_year + 1900, cur_tm.tm_mon + 1, 1, 0, 1,
                        &bw_list);
                if (result == 1) {
                    for (bw_d_node = bw_list.top; bw_d_node;
                            bw_d_node = bw_d_node->next) {
                        vrmr_fatal_if_null(bw_d_node->data);
                        bw_ptr = bw_d_node->data;

                        create_bw_string(
                                bw_ptr->recv_mb, bw_str, sizeof(bw_str));
                        set_field_buffer_wrap(
                                traf_vol_section.fields[7 + (11 * i)], 0,
                                bw_str);

                        create_bw_string(
                                bw_ptr->send_mb, bw_str, sizeof(bw_str));
                        set_field_buffer_wrap(
                                traf_vol_section.fields[8 + (11 * i)], 0,
                                bw_str);
                    }
                    vrmr_list_cleanup(&bw_list);
                } else if (result == 0) {
                    set_field_buffer_wrap(
                            traf_vol_section.fields[7 + (11 * i)], 0, "  -  ");
                    set_field_buffer_wrap(
                            traf_vol_section.fields[8 + (11 * i)], 0, "  -  ");
                } else {
                    set_field_buffer_wrap(traf_vol_section.fields[7 + (11 * i)],
                            0, gettext("error"));
                    set_field_buffer_wrap(traf_vol_section.fields[8 + (11 * i)],
                            0, gettext("error"));
                }

                /* get the bw for the last month */
                year = cur_tm.tm_year + 1900;
                /* get prev month (by not adding +1) */
                month = cur_tm.tm_mon;

                /*  if month = 0 (Jan), set it to 12
                    (Dec) and subtract one of the
                    year.
                 */
                if (month == 0) {
                    month = 12;
                    year = year - 1;
                }

                result = bandwidth_get_iface(conf, iface_ptr->device, year,
                        month, 1, 0, 1, &bw_list);
                if (result == 1) {
                    for (bw_d_node = bw_list.top; bw_d_node;
                            bw_d_node = bw_d_node->next) {
                        vrmr_fatal_if_null(bw_d_node->data);
                        bw_ptr = bw_d_node->data;

                        create_bw_string(
                                bw_ptr->recv_mb, bw_str, sizeof(bw_str));
                        set_field_buffer_wrap(
                                traf_vol_section.fields[9 + (11 * i)], 0,
                                bw_str);

                        create_bw_string(
                                bw_ptr->send_mb, bw_str, sizeof(bw_str));
                        set_field_buffer_wrap(
                                traf_vol_section.fields[10 + (11 * i)], 0,
                                bw_str);
                    }
                    vrmr_list_cleanup(&bw_list);
                } else if (result == 0) {
                    set_field_buffer_wrap(
                            traf_vol_section.fields[9 + (11 * i)], 0, "  -  ");
                    set_field_buffer_wrap(
                            traf_vol_section.fields[10 + (11 * i)], 0, "  -  ");
                } else {
                    set_field_buffer_wrap(traf_vol_section.fields[9 + (11 * i)],
                            0, gettext("error"));
                    set_field_buffer_wrap(
                            traf_vol_section.fields[10 + (11 * i)], 0,
                            gettext("error"));
                }

                /* finally draw the screen */
                wrefresh(traf_vol_section.win);

                /* update the line */
                i++;
            }
        }

        /* finally draw the screen */
        wrefresh(traf_vol_section.win);

        /* process the keyboard input */
        ch = wgetch(traf_vol_section.win);
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
                print_help(":[VUURMUUR:TRAFVOL]:");
                break;
        }

        if (quit == 0) {
            usleep(10000);
            slept_so_far = slept_so_far + 10000;

            vrmr_debug(HIGH, "just slept: slept_so_far '%d'.", slept_so_far);
        }
    }

    /* EXIT: cleanup */
    nodelay(traf_vol_section.win, FALSE);

    /* destroy the window and form */
    trafvol_section_destroy();
    update_panels();
    doupdate();
    return (retval);
}
