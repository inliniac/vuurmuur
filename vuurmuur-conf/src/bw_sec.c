/***************************************************************************
 *   Copyright (C) 2003-2008 by Victor Julien                              *
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


struct TrafVolSection_
{
    PANEL   *panel[1];
    WINDOW  *win;
    FIELD   **fields;
    FORM    *form;
    size_t  n_fields;

} TrafVolSection;

                                                
struct TrafVol_
{
    int             year;
    int             month;
    int             day;

    char            total;  /* total for this timeunit */

    unsigned int    recv_mb;
    unsigned int    send_mb;

} TrafVol;


/*  strip the buf src from the spaces before the text. Leave other
    spaces alone.
*/
void
strip_buf(char *src, char *dst, size_t dstsize)
{
    size_t  i = 0,
            k = 0;
    char    copy_space = 0;

    for(i = 0; i < dstsize && i < StrMemLen(src); i++)
    {
        if(src[i] != ' ')
            copy_space = 1;

        if(src[i] != ' ' || copy_space == 1)
        {
            dst[k] = src[i];
            k++;
        }
    }
    dst[k] = '\0';
}


/*

*/
static int
bandwidth_store(const int debuglvl, d_list *list, int year, int month, int day,
            char total, unsigned int recv, unsigned int send)
{
    struct TrafVol_ *bw_ptr = NULL;

    bw_ptr = malloc(sizeof(struct TrafVol_));
    if(bw_ptr == NULL)
    {
        (void)vrprint.error(-1, VR_ERR,
                gettext("malloc failed: %s (in: %s:%d)."),
                strerror(errno), __FUNC__, __LINE__);
        return(-1);
    }
    
    bw_ptr->year = year;
    bw_ptr->month = month;
    bw_ptr->day = day;
    
    bw_ptr->total = total;
    
    bw_ptr->recv_mb = recv;
    bw_ptr->send_mb = send;

    /* append to the list */
    if(d_list_append(debuglvl, list, bw_ptr) == NULL)
    {
        (void)vrprint.error(-1, VR_INTERR, "d_list_append() failed "
                "(in: %s:%d).", __FUNC__, __LINE__);

        free(bw_ptr);
        return(-1);
    }

    return(0);
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
int
bandwidth_get_iface(const int debuglvl, char *device, int year, int month,
            int start_day, int days, char only_total, d_list *list)
{
    char            cmd[256] = "",
                    bw_buf[512] = "",
                    sect_buf[32] = "",
                    sect_buf_stripped[32] = "",
                    tmpfile[] = "/tmp/vuurmuur-iptrafvol-XXXXXX";
    char            done = FALSE;
    int             fd = 0;
    int             result = 0;
    ssize_t         readsize = 0;

    char            data_month = 0;
    int             data_day = 0;

    unsigned int    i = 0,
                    k = 0;
    
    int             act_border = 0;

    int             device_column = 0; /* column where our
                                    device can be found. */
    int             cur_column = 0;

    int             line_num = 0;

    char            buf_done = 0;

    char            device_line_parsed = 0,
                    parsing_device_line = 0,
                    parsing_total_line = 0;

    char            parsing_data = 0,
                    parsing_data_done = 0;

    char            month_str[4] = "";

    unsigned int    recv = 0,
                    recv_sub = 0,
                    send = 0,
                    send_sub = 0;

    int             retval = 0;

    char            cmd_year_str[5] = "",
                    cmd_month_str[3] = "",
                    cmd_start_day_str[3] = "",
                    cmd_num_days_str[8] = "";

    /* safety */
    if(device == NULL || list == NULL)
    {
        (void)vrprint.error(-1, VR_INTERR, "parameter problem "
                "(in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    /* setup the list */
    d_list_setup(debuglvl, list, free);

    if(debuglvl >= LOW)
        (void)vrprint.debug(__FUNC__, "looking for data for '%s'.", device);

    /* create the tempfile */
    fd = create_tempfile(debuglvl, tmpfile);
    if(fd == -1)
        return(-1);
    else
        close(fd);

    snprintf(cmd_year_str, sizeof(cmd_year_str), "%d", year);
    snprintf(cmd_month_str, sizeof(cmd_month_str), "%d", month);
    snprintf(cmd_start_day_str, sizeof(cmd_start_day_str), "%d", start_day);

    /* see if we need to pass the -s option to iptrafvol*/
    if(days > 0) {
        snprintf(cmd_num_days_str, sizeof(cmd_num_days_str), "%d", days);
        char *args[] = { vccnf.iptrafvol_location,
                         "-d", "-y", cmd_year_str,
                         "-m", cmd_month_str,
                         "-b", cmd_start_day_str,
                         "-s", cmd_num_days_str, NULL };
        result = libvuurmuur_exec_command(debuglvl, &conf, vccnf.iptrafvol_location, args, tmpfile);
    } else {
        char *args[] = { vccnf.iptrafvol_location,
                         "-d", "-y", cmd_year_str,
                         "-m", cmd_month_str,
                         "-b", cmd_start_day_str, NULL };
        result = libvuurmuur_exec_command(debuglvl, &conf, vccnf.iptrafvol_location, args, tmpfile);
    }
    if(result != 0)
    {
        return(-1);
    }

    /* open the file for reaing */
    fd = open(tmpfile, 0);
    if(fd < 0)
    {
        (void)vrprint.error(-1, VR_ERR,
                gettext("opening '%s' failed: %s (in: %s:%d)."),
                tmpfile, strerror(errno), __FUNC__, __LINE__);
        return(-1);
    }

    while(done == FALSE)
    {
        memset(bw_buf, 0, sizeof(bw_buf));

        readsize = read(fd, bw_buf, sizeof(bw_buf));
        if(readsize > 0)
        {
            //fprintf(stdout, "bw_buf: '%s'.\n", bw_buf);

            for(i = 0; i < (unsigned int)readsize; i++)
            {
                //(void)vrprint.info(__FUNC__, "bw_buf[%d] = '%c', k = %d", i, bw_buf[i], k);

                if(bw_buf[i] == '\n')
                {
                    line_num++;

                    act_border = 0;

                    sect_buf[k] = '\0';
                    k = 0;

                    //(void)vrprint.info(__FUNC__, "newline (act_border: %d, k: %d, line_num: %d, sect_buf '%s'.)", act_border, k, line_num, sect_buf);

                    if(parsing_device_line == 1)
                    {
                        parsing_device_line = 0;
                        device_line_parsed = 1;
                    }
                    if(parsing_total_line == 1)
                    {
                        //retval = 1;
                        done = 1;
                        break;
                    }

                    buf_done = 1;
                }
                else if(bw_buf[i] == '|')
                {
                    act_border++;
                    sect_buf[k] = '\0';
                    k = 0;

                    //(void)vrprint.info(__FUNC__, "border  (act_border: %d, k: %d, line_num: %d, sect_buf '%s'.)", act_border, k, line_num, sect_buf);
                    buf_done = 1;
                }
                else
                {
                    if(k < (unsigned int)sizeof(sect_buf) - 1)
                    {
                        sect_buf[k] = bw_buf[i];
                        k++;
                    }
                    else
                    {
                        sect_buf[k] = '\0';
                    }
                }

                if(line_num > 5)
                    parsing_data = 1;

                if(buf_done == 1)
                {
                    buf_done = 0;

                    /* strip the buffer from the starting whitespaces */
                    strip_buf(sect_buf, sect_buf_stripped, sizeof(sect_buf_stripped));

                    /* get the current column */
                    cur_column = act_border - 1;

                    /* see if we are done paring regular data */
                    if(parsing_data == 1 && cur_column == 1 && strncmp(sect_buf_stripped, "---", 3) == 0)
                        parsing_data_done = 1;

                    if(line_num == 1)
                    {
                        if(debuglvl >= HIGH)
                            (void)vrprint.debug(__FUNC__, "line_num == 1: '%s'", sect_buf_stripped);

                        if(strncmp("no data", sect_buf_stripped, 7) == 0)
                        {
                            retval = 0;
                            done = TRUE;
                            break;
                        }
                    }
                    
                    /* the deviceline starts with MBytes */
                    if(strncmp(sect_buf_stripped, "MBytes", 6) == 0)
                        parsing_device_line = 1;

                    /* this is the total line */
                    if(strcmp(sect_buf_stripped, "Total:") == 0)
                        parsing_total_line = 1;

                    /* date column */
                    if( parsing_data == 1 && cur_column == 1 && only_total == 0)
                    {
                        sscanf(sect_buf_stripped, "%d %3s", &data_day, month_str);

                        /* parse the month */
                        if(strcmp(month_str, "Jan") == 0)       data_month = 1;
                        else if(strcmp(month_str, "Feb") == 0)  data_month = 2;
                        else if(strcmp(month_str, "Mar") == 0)  data_month = 3;
                        else if(strcmp(month_str, "Apr") == 0)  data_month = 4;
                        else if(strcmp(month_str, "May") == 0)  data_month = 5;
                        else if(strcmp(month_str, "Jun") == 0)  data_month = 6;
                        else if(strcmp(month_str, "Jul") == 0)  data_month = 7;
                        else if(strcmp(month_str, "Aug") == 0)  data_month = 8;
                        else if(strcmp(month_str, "Sep") == 0)  data_month = 9;
                        else if(strcmp(month_str, "Oct") == 0)  data_month = 10;
                        else if(strcmp(month_str, "Nov") == 0)  data_month = 11;
                        else if(strcmp(month_str, "Dec") == 0)  data_month = 12;
                        else
                        {
                            (void)vrprint.error(-1, VR_ERR, gettext("could not parse month '%s' (in: %s:%d)."),
                                                    month_str,
                                                    __FUNC__, __LINE__);
                            return(-1);
                        }

                        //(void)vrprint.info(__FUNC__, "day: '%d', month: '%d'", data_day, data_month);
                    }
                    /* device column */
                    if( parsing_data == 1 && device_column > 1 && cur_column == device_column &&
                        ((only_total == 1 && parsing_total_line == 1) || only_total == 0))
                    {
                        sscanf(sect_buf_stripped, "%u.%u %u.%u", &recv, &recv_sub, &send, &send_sub);

                        recv = ((recv * 10) + recv_sub) / 10;
                        send = ((send * 10) + send_sub) / 10;

                        if(debuglvl >= LOW)
                            (void)vrprint.info(__FUNC__, "recv = %.1u, send = %.1u.", recv, send);

                        retval = 1;

                        /* we asume that the date is already parsed */
                        result = bandwidth_store(debuglvl, list, year, data_month, data_day, parsing_total_line, recv, send);
                        if(result < 0)
                        {
                            (void)vrprint.error(-1, VR_INTERR, "bandwidth_store() failed (in: %s:%d).", __FUNC__, __LINE__);

                            done = TRUE;
                            retval = -1;
                        }
                    }

                    /* parse the deviceline to determine the column */
                    if(parsing_device_line == 1)
                    {
                        if(strcmp(sect_buf_stripped, device) == 0)
                        {
                            /* act border includes the last borderline, so -1. */
                            device_column = cur_column;

                            if(debuglvl >= LOW)
                                (void)vrprint.info(__FUNC__, "sect_buf_stripped '%s' match! (device: %s) column = %d.", sect_buf_stripped, device, device_column);
                        }
                    }
                }
            }
        }
        else
        {
            done = TRUE;
        }
    }

    /* close the file again */
    if(close(fd) == -1)
    {
        (void)vrprint.error(-1, VR_ERR,
                gettext("closing of '%s' failed: %s (in: %s:%d)."),
                tmpfile, strerror(errno), __FUNC__, __LINE__);
        return(-1);
    }

    /* remove the file */
    if(unlink(tmpfile) == -1)
    {
        (void)vrprint.error(-1, VR_ERR,
                gettext("removing '%s' failed (unlink): %s (in: %s:%d)."),
                tmpfile, strerror(errno), __FUNC__, __LINE__);
        return(-1);
    }

    return(retval);
}


/*  trafvol_section_init

    This function creates the trafvol section window and the fields inside it.
    
    Returncodes:
         0: ok
        -1: error
*/
static int
trafvol_section_init(const int debuglvl, int height, int width, int startx,
            int starty, unsigned int ifac_num)
{
    size_t          i = 0;
    int             rows = 0,
                    cols = 0;
    int             max_height = 0,
                    max_width = 0,
                    toprow = 0,
                    num_rows = (int)ifac_num;
    unsigned int    ifacs = 0,
                    ifac_fields = 0,
                    ifac_start = 4;

    /* get and check the screen dimentions */
    getmaxyx(stdscr, max_height, max_width);
    if(width > max_width)
        return(-1);

    /* set the number of fields: 
    
        interfacename,
        today in, today out,
        yesterday in, yesterday out,
        7 days in, 7 days out,
        this month in, this month out,
        last month in, last month out
    */
    TrafVolSection.n_fields = 11 * (size_t)ifac_num;
    
    /* alloc the needed memory */
    if(!(TrafVolSection.fields = (FIELD **)calloc(TrafVolSection.n_fields + 1, sizeof(FIELD *))))
    {
        (void)vrprint.error(-1, VR_ERR, gettext("calloc failed: %s (in: %s:%d)."),
                                strerror(errno),
                                __FUNC__, __LINE__);
        return(-1);
    }

    /* create iface stats fields */
    for(ifacs = 0, ifac_fields = 0; ifacs < ifac_num; ifacs++)
    {
        toprow = (int)(ifac_start+ifacs);

        /* interface name */
        TrafVolSection.fields[ifac_fields] = new_field(1, 15, toprow, 0, 0, 1);
        set_field_buffer_wrap(debuglvl, TrafVolSection.fields[ifac_fields], 1, "ifacname");
        ifac_fields++;

        TrafVolSection.fields[ifac_fields] = new_field(1, 5, toprow, 16, 0, 1);
        set_field_buffer_wrap(debuglvl, TrafVolSection.fields[ifac_fields], 1, "t-in");
        ifac_fields++;

        TrafVolSection.fields[ifac_fields] = new_field(1, 5, toprow, 22, 0, 1);
        set_field_buffer_wrap(debuglvl, TrafVolSection.fields[ifac_fields], 1, "t-ou");
        ifac_fields++;

        TrafVolSection.fields[ifac_fields] = new_field(1, 5, toprow, 28, 0, 1);
        set_field_buffer_wrap(debuglvl, TrafVolSection.fields[ifac_fields], 1, "y-in");
        ifac_fields++;

        TrafVolSection.fields[ifac_fields] = new_field(1, 5, toprow, 34, 0, 1);
        set_field_buffer_wrap(debuglvl, TrafVolSection.fields[ifac_fields], 1, "y-ou");
        ifac_fields++;

        TrafVolSection.fields[ifac_fields] = new_field(1, 5, toprow, 40, 0, 1);
        set_field_buffer_wrap(debuglvl, TrafVolSection.fields[ifac_fields], 1, "7-in");
        ifac_fields++;

        TrafVolSection.fields[ifac_fields] = new_field(1, 5, toprow, 46, 0, 1);
        set_field_buffer_wrap(debuglvl, TrafVolSection.fields[ifac_fields], 1, "7-ou");
        ifac_fields++;

        TrafVolSection.fields[ifac_fields] = new_field(1, 5, toprow, 52, 0, 1);
        set_field_buffer_wrap(debuglvl, TrafVolSection.fields[ifac_fields], 1, "t-in");
        ifac_fields++;

        TrafVolSection.fields[ifac_fields] = new_field(1, 5, toprow, 58, 0, 1);
        set_field_buffer_wrap(debuglvl, TrafVolSection.fields[ifac_fields], 1, "t-ou");
        ifac_fields++;

        TrafVolSection.fields[ifac_fields] = new_field(1, 5, toprow, 64, 0, 1);
        set_field_buffer_wrap(debuglvl, TrafVolSection.fields[ifac_fields], 1, "l-in");
        ifac_fields++;

        TrafVolSection.fields[ifac_fields] = new_field(1, 5, toprow, 70, 0, 1);
        set_field_buffer_wrap(debuglvl, TrafVolSection.fields[ifac_fields], 1, "l-ou");
        ifac_fields++;
    }

    /* terminate the field array */
    TrafVolSection.fields[TrafVolSection.n_fields] = NULL;

    /* create the window and the panel */
    if(!(TrafVolSection.win = create_newwin(height, width, startx, starty,
            gettext("Traffic Volume Section"),
            (chtype)COLOR_PAIR(CP_BLUE_WHITE))))
    {
        (void)vrprint.error(-1, VR_ERR, gettext("creating window failed."));
        return(-1);
    }

    if(!(TrafVolSection.panel[0] = new_panel(TrafVolSection.win)))
    {
        (void)vrprint.error(-1, VR_ERR, gettext("creating panel failed."));
        return(-1);
    }

    /* field options */
    for(i = 0; i < TrafVolSection.n_fields; i++)
    {
        if(debuglvl >= LOW)
            set_field_back(TrafVolSection.fields[i],
                    (chtype)COLOR_PAIR(CP_WHITE_BLUE));
        else
            set_field_back(TrafVolSection.fields[i],
                    (chtype)COLOR_PAIR(CP_BLUE_WHITE));
        
        field_opts_off(TrafVolSection.fields[i], O_AUTOSKIP);
        /* set status to false */
        set_field_status(TrafVolSection.fields[i], FALSE);
    }

    /* Create the form and post it */
    if(!(TrafVolSection.form = new_form(TrafVolSection.fields)))
    {
        (void)vrprint.error(-1, VR_ERR, gettext("creating form failed."));
        return(-1);
    }
    /* Calculate the area required for the form */
    scale_form(TrafVolSection.form, &rows, &cols);
    keypad(TrafVolSection.win, TRUE);
    /* Set main window and sub window */
    set_form_win(TrafVolSection.form, TrafVolSection.win);
    set_form_sub(TrafVolSection.form, derwin(TrafVolSection.win, rows, cols, 1, 2));

    if(post_form(TrafVolSection.form) != E_OK)
    {
        (void)vrprint.error(-1, VR_ERR, gettext("posting the form failed."));
        return(-1);
    }

    mvwprintw(TrafVolSection.win, 3, 2,  gettext("Interface"));
    mvwprintw(TrafVolSection.win, 2, 18, gettext("Today"));
    mvwprintw(TrafVolSection.win, 3, 18, gettext("In"));
    mvwprintw(TrafVolSection.win, 3, 24, gettext("Out"));
    mvwprintw(TrafVolSection.win, 2, 30, gettext("Yesterday"));
    mvwprintw(TrafVolSection.win, 3, 30, gettext("In"));
    mvwprintw(TrafVolSection.win, 3, 36, gettext("Out"));
    mvwprintw(TrafVolSection.win, 2, 42, gettext("7-days"));
    mvwprintw(TrafVolSection.win, 3, 42, gettext("In"));
    mvwprintw(TrafVolSection.win, 3, 48, gettext("Out"));
    mvwprintw(TrafVolSection.win, 2, 54, gettext("This month"));
    mvwprintw(TrafVolSection.win, 3, 54, gettext("In"));
    mvwprintw(TrafVolSection.win, 3, 60, gettext("Out"));
    mvwprintw(TrafVolSection.win, 2, 66, gettext("Last month"));
    mvwprintw(TrafVolSection.win, 3, 66, gettext("In"));
    mvwprintw(TrafVolSection.win, 3, 72, gettext("Out"));
    mvwhline(TrafVolSection.win,  4, 1,  ACS_HLINE, 76);
    mvwaddch(TrafVolSection.win,  4, 0,  ACS_LTEE);
    mvwaddch(TrafVolSection.win,  4, 77, ACS_RTEE);

    mvwvline(TrafVolSection.win,  5, 17, ACS_VLINE, num_rows);
    mvwaddch(TrafVolSection.win,  4, 17, ACS_TTEE);
    mvwvline(TrafVolSection.win,  5, 23, ACS_VLINE, num_rows);
    mvwaddch(TrafVolSection.win,  4, 23, ACS_TTEE);
    mvwvline(TrafVolSection.win,  5, 29, ACS_VLINE, num_rows);
    mvwaddch(TrafVolSection.win,  4, 29, ACS_TTEE);
    mvwvline(TrafVolSection.win,  5, 35, ACS_VLINE, num_rows);
    mvwaddch(TrafVolSection.win,  4, 35, ACS_TTEE);
    mvwvline(TrafVolSection.win,  5, 41, ACS_VLINE, num_rows);
    mvwaddch(TrafVolSection.win,  4, 41, ACS_TTEE);
    mvwvline(TrafVolSection.win,  5, 47, ACS_VLINE, num_rows);
    mvwaddch(TrafVolSection.win,  4, 47, ACS_TTEE);
    mvwvline(TrafVolSection.win,  5, 53, ACS_VLINE, num_rows);
    mvwaddch(TrafVolSection.win,  4, 53, ACS_TTEE);
    mvwvline(TrafVolSection.win,  5, 59, ACS_VLINE, num_rows);
    mvwaddch(TrafVolSection.win,  4, 59, ACS_TTEE);
    mvwvline(TrafVolSection.win,  5, 65, ACS_VLINE, num_rows);
    mvwaddch(TrafVolSection.win,  4, 65, ACS_TTEE);
    mvwvline(TrafVolSection.win,  5, 71, ACS_VLINE, num_rows);
    mvwaddch(TrafVolSection.win,  4, 71, ACS_TTEE);

    
    /* don't print this line if it overlaps with the window border */
    if(5 + num_rows + 1 < height)
    {
        mvwhline(TrafVolSection.win,  5 + num_rows, 1,  ACS_HLINE, 76);
        mvwaddch(TrafVolSection.win,  5 + num_rows, 0,  ACS_LTEE);
        mvwaddch(TrafVolSection.win,  5 + num_rows, 77, ACS_RTEE);
    }

    mvwaddch(TrafVolSection.win,  5 + num_rows, 17, ACS_BTEE);
    mvwaddch(TrafVolSection.win,  5 + num_rows, 23, ACS_BTEE);
    mvwaddch(TrafVolSection.win,  5 + num_rows, 29, ACS_BTEE);
    mvwaddch(TrafVolSection.win,  5 + num_rows, 35, ACS_BTEE);
    mvwaddch(TrafVolSection.win,  5 + num_rows, 41, ACS_BTEE);
    mvwaddch(TrafVolSection.win,  5 + num_rows, 47, ACS_BTEE);
    mvwaddch(TrafVolSection.win,  5 + num_rows, 53, ACS_BTEE);
    mvwaddch(TrafVolSection.win,  5 + num_rows, 59, ACS_BTEE);
    mvwaddch(TrafVolSection.win,  5 + num_rows, 65, ACS_BTEE);
    mvwaddch(TrafVolSection.win,  5 + num_rows, 71, ACS_BTEE);

    return(0);
}


static int
trafvol_section_destroy(void)
{
    size_t  i = 0;

    // Un post form and free the memory
    unpost_form(TrafVolSection.form);
    free_form(TrafVolSection.form);

    for(i = 0; i < TrafVolSection.n_fields; i++)
    {
        free_field(TrafVolSection.fields[i]);
    }
    free(TrafVolSection.fields);

    del_panel(TrafVolSection.panel[0]);
    destroy_win(TrafVolSection.win);

    return(0);
}


static void
create_bw_string(const int debuglvl, unsigned int mb, char *str, size_t len)
{
    if(str == NULL)
        return;

    if(mb == 0)
        snprintf(str, len, "  0 M");
    else if(mb > 0 && mb < 10)
        snprintf(str, len, "%u.0 M", mb);
    else if(mb >= 10 && mb < 100)
        snprintf(str, len, " %u M", mb);
    else if(mb >= 100 && mb < 1000)
        snprintf(str, len, "%u M", mb);
    else if(mb >= 1000 && mb < 10000)
        snprintf(str, len, "%2.2fG", (float)mb/1024);
    else if(mb >= 10000 && mb < 100000)
        snprintf(str, len, "%2.1fG", (float)mb/1024);
    else
        snprintf(str, len, "%uG", mb/1024);
}


/*  trafvol_section

    This section shows bandwidth usage of the system.
    
    Returncodes:
        0: ok
        -1: error
*/
int
trafvol_section(const int debuglvl, Zones *zones, Interfaces *interfaces,
            Services *services)
{
    int                     retval = 0;
    int                     quit = 0,
                            ch;

    int                     max_onscreen = 0,
                            max_height = 0,
                            max_width = 0;
    unsigned int            i = 0;
    unsigned int            ifac_num = 0;
    struct InterfaceData_   *iface_ptr=NULL;

    d_list_node             *d_node = NULL,
                            *bw_d_node = NULL;
    struct TrafVol_         *bw_ptr = NULL;
    d_list                  bw_list;

    int                     year = 0,
                            month = 0;

    time_t                  cur_time,
                            yesterday_time,
                            lastweek_time;
    struct tm               cur_tm,
                            yesterday_tm,
                            lastweek_tm;

    char                    bw_str[6] = "";

    int                     result=0;

    int                     update_interval = 10000000; /* weird, in pratice this seems to be twenty sec */
    int                     slept_so_far    = 10000000; /* time slept since last update */

    /* top menu */
    char                    *key_choices[] = {  "F12",
                                                "F10"};
    int                     key_choices_n = 2;
    char                    *cmd_choices[] = {  gettext("help"),
                                                gettext("back")};
    int                     cmd_choices_n = 2;

    if(interfaces->list.len == 0)
    {
        (void)vrprint.warning(VR_WARN, gettext("no interfaces found. Please define an interface first."));
        return(0);
    }

    if(strcmp(vccnf.iptrafvol_location, "") == 0)
    {
        (void)vrprint.error(-1, VR_ERR, gettext("please set the location of the iptrafvol.pl command in the Settings."));
        return(-1);
    }

    getmaxyx(stdscr, max_height, max_width);
    max_onscreen = max_height - 6 - 6;

    /* count the number of non virtual interfaces */
    for(ifac_num = 0, d_node = interfaces->list.top; d_node; d_node = d_node->next)
    {
        if(!(iface_ptr = d_node->data))
        {
            (void)vrprint.error(-1, VR_INTERR, "NULL pointer (in: %s:%d).", __FUNC__, __LINE__);
            return(-1);
        }

        if(iface_ptr->device_virtual == FALSE)
        {
            ifac_num++;
        }
    }

    if(ifac_num > (unsigned int)max_onscreen)
        ifac_num = (unsigned int)max_onscreen;

    /* init */
    if(trafvol_section_init(debuglvl, max_height - 6, 78, 3, 1, ifac_num) < 0)
        return(-1);

    /* make sure wgetch doesn't block */
    nodelay(TrafVolSection.win, TRUE);
    keypad(TrafVolSection.win, TRUE);

    draw_top_menu(debuglvl, top_win, gettext("Traffic Volume"), key_choices_n, key_choices, cmd_choices_n, cmd_choices);

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

            /* get the time */
            cur_time = time(NULL);
            if(cur_time == -1)
            {
                (void)vrprint.error(-1, VR_INTERR, "getting current time failed (in: %s:%d).", __FUNC__, __LINE__);
                return(-1);
            }
            yesterday_time = cur_time - 86400;
            lastweek_time = cur_time - (86400 * 7);

            if(localtime_r(&cur_time, &cur_tm) == NULL)
            {
                (void)vrprint.error(-1, VR_INTERR, "converting current time failed (in: %s:%d).", __FUNC__, __LINE__);
                return(-1);
            }

            if(localtime_r(&yesterday_time, &yesterday_tm) == NULL)
            {
                (void)vrprint.error(-1, VR_INTERR, "converting yesterday's time failed (in: %s:%d).", __FUNC__, __LINE__);
                return(-1);
            }

            if(localtime_r(&lastweek_time, &lastweek_tm) == NULL)
            {
                (void)vrprint.error(-1, VR_INTERR, "converting lastweeks's time failed (in: %s:%d).", __FUNC__, __LINE__);
                return(-1);
            }

            /* update data here */
            for(d_node = interfaces->list.top, i = 0; d_node && i < ifac_num; d_node = d_node->next)
            {
                if(!(iface_ptr = d_node->data))
                {
                    (void)vrprint.error(-1, VR_INTERR, "NULL pointer (in: %s:%d).", __FUNC__, __LINE__);
                    return(-1);
                }

                if(iface_ptr->device_virtual == FALSE)
                {
                    /* interface name */
                    set_field_buffer_wrap(debuglvl, TrafVolSection.fields[11 * i], 0, iface_ptr->name);

                    /* get the bw for today */
                    result = bandwidth_get_iface(debuglvl, iface_ptr->device, cur_tm.tm_year + 1900, cur_tm.tm_mon + 1, cur_tm.tm_mday, 1, 1, &bw_list);
                    if(result == 1)
                    {
                        for(bw_d_node = bw_list.top; bw_d_node; bw_d_node = bw_d_node->next)
                        {
                            if(!(bw_ptr = bw_d_node->data))
                            {
                                (void)vrprint.error(-1, VR_INTERR, "NULL pointer (in: %s:%d).", __FUNC__, __LINE__);
                                return(-1);
                            }
                            //printf("%2d/%2d/%4d: in: %u, out: %u %s\n", bw_ptr->day, bw_ptr->month, bw_ptr->year, bw_ptr->recv_mb, bw_ptr->send_mb, bw_ptr->total ? "(total)" : "");

                            create_bw_string(debuglvl, bw_ptr->recv_mb, bw_str, sizeof(bw_str));
                            set_field_buffer_wrap(debuglvl, TrafVolSection.fields[1 + (11 * i)], 0, bw_str);

                            create_bw_string(debuglvl, bw_ptr->send_mb, bw_str, sizeof(bw_str));
                            set_field_buffer_wrap(debuglvl, TrafVolSection.fields[2 + (11 * i)], 0, bw_str);
                        }
                        d_list_cleanup(debuglvl, &bw_list);
                    }
                    else if(result == 0)
                    {
                        set_field_buffer_wrap(debuglvl, TrafVolSection.fields[1 + (11 * i)], 0, "  -  ");
                        set_field_buffer_wrap(debuglvl, TrafVolSection.fields[2 + (11 * i)], 0, "  -  ");
                    }
                    else
                    {
                        set_field_buffer_wrap(debuglvl, TrafVolSection.fields[1 + (11 * i)], 0, gettext("error"));
                        set_field_buffer_wrap(debuglvl, TrafVolSection.fields[2 + (11 * i)], 0, gettext("error"));
                    }

                    /* get the bw for yesterday */
                    result = bandwidth_get_iface(debuglvl, iface_ptr->device, yesterday_tm.tm_year + 1900, yesterday_tm.tm_mon + 1, yesterday_tm.tm_mday, 1, 1, &bw_list);
                    if(result == 1)
                    {
                        for(bw_d_node = bw_list.top; bw_d_node; bw_d_node = bw_d_node->next)
                        {
                            if(!(bw_ptr = bw_d_node->data))
                            {
                                (void)vrprint.error(-1, VR_INTERR, "NULL pointer (in: %s:%d).", __FUNC__, __LINE__);
                                return(-1);
                            }
                            //printf("%2d/%2d/%4d: in: %u, out: %u %s\n", bw_ptr->day, bw_ptr->month, bw_ptr->year, bw_ptr->recv_mb, bw_ptr->send_mb, bw_ptr->total ? "(total)" : "");

                            create_bw_string(debuglvl, bw_ptr->recv_mb, bw_str, sizeof(bw_str));
                            set_field_buffer_wrap(debuglvl, TrafVolSection.fields[3 + (11 * i)], 0, bw_str);

                            create_bw_string(debuglvl, bw_ptr->send_mb, bw_str, sizeof(bw_str));
                            set_field_buffer_wrap(debuglvl, TrafVolSection.fields[4 + (11 * i)], 0, bw_str);
                        }
                        d_list_cleanup(debuglvl, &bw_list);
                    }
                    else if(result == 0)
                    {
                        set_field_buffer_wrap(debuglvl, TrafVolSection.fields[3 + (11 * i)], 0, "  -  ");
                        set_field_buffer_wrap(debuglvl, TrafVolSection.fields[4 + (11 * i)], 0, "  -  ");
                    }
                    else
                    {
                        set_field_buffer_wrap(debuglvl, TrafVolSection.fields[3 + (11 * i)], 0, gettext("error"));
                        set_field_buffer_wrap(debuglvl, TrafVolSection.fields[4 + (11 * i)], 0, gettext("error"));
                    }

                    /* get the bw for past 7 days */
                    result = bandwidth_get_iface(debuglvl, iface_ptr->device, lastweek_tm.tm_year + 1900, lastweek_tm.tm_mon + 1, lastweek_tm.tm_mday, 7, 1, &bw_list);
                    if(result == 1)
                    {
                        for(bw_d_node = bw_list.top; bw_d_node; bw_d_node = bw_d_node->next)
                        {
                            if(!(bw_ptr = bw_d_node->data))
                            {
                                (void)vrprint.error(-1, VR_INTERR, "NULL pointer (in: %s:%d).", __FUNC__, __LINE__);
                                return(-1);
                            }
                            //printf("%2d/%2d/%4d: in: %u, out: %u %s\n", bw_ptr->day, bw_ptr->month, bw_ptr->year, bw_ptr->recv_mb, bw_ptr->send_mb, bw_ptr->total ? "(total)" : "");

                            create_bw_string(debuglvl, bw_ptr->recv_mb, bw_str, sizeof(bw_str));
                            set_field_buffer_wrap(debuglvl, TrafVolSection.fields[5 + (11 * i)], 0, bw_str);

                            create_bw_string(debuglvl, bw_ptr->send_mb, bw_str, sizeof(bw_str));
                            set_field_buffer_wrap(debuglvl, TrafVolSection.fields[6 + (11 * i)], 0, bw_str);
                        }
                        d_list_cleanup(debuglvl, &bw_list);
                    }
                    else if(result == 0)
                    {
                        set_field_buffer_wrap(debuglvl, TrafVolSection.fields[5 + (11 * i)], 0, "  -  ");
                        set_field_buffer_wrap(debuglvl, TrafVolSection.fields[6 + (11 * i)], 0, "  -  ");
                    }
                    else
                    {
                        set_field_buffer_wrap(debuglvl, TrafVolSection.fields[5 + (11 * i)], 0, gettext("error"));
                        set_field_buffer_wrap(debuglvl, TrafVolSection.fields[6 + (11 * i)], 0, gettext("error"));
                    }

                    /* get the bw for the current month */
                    result = bandwidth_get_iface(debuglvl, iface_ptr->device, cur_tm.tm_year + 1900, cur_tm.tm_mon + 1, 1, 0, 1, &bw_list);
                    if(result == 1)
                    {
                        for(bw_d_node = bw_list.top; bw_d_node; bw_d_node = bw_d_node->next)
                        {
                            if(!(bw_ptr = bw_d_node->data))
                            {
                                (void)vrprint.error(-1, VR_INTERR, "NULL pointer (in: %s:%d).", __FUNC__, __LINE__);
                                return(-1);
                            }
                            //printf("%2d/%2d/%4d: in: %u, out: %u %s\n", bw_ptr->day, bw_ptr->month, bw_ptr->year, bw_ptr->recv_mb, bw_ptr->send_mb, bw_ptr->total ? "(total)" : "");

                            create_bw_string(debuglvl, bw_ptr->recv_mb, bw_str, sizeof(bw_str));
                            set_field_buffer_wrap(debuglvl, TrafVolSection.fields[7 + (11 * i)], 0, bw_str);

                            create_bw_string(debuglvl, bw_ptr->send_mb, bw_str, sizeof(bw_str));
                            set_field_buffer_wrap(debuglvl, TrafVolSection.fields[8 + (11 * i)], 0, bw_str);
                        }
                        d_list_cleanup(debuglvl, &bw_list);
                    }
                    else if(result == 0)
                    {
                        set_field_buffer_wrap(debuglvl, TrafVolSection.fields[7 + (11 * i)], 0, "  -  ");
                        set_field_buffer_wrap(debuglvl, TrafVolSection.fields[8 + (11 * i)], 0, "  -  ");
                    }
                    else
                    {
                        set_field_buffer_wrap(debuglvl, TrafVolSection.fields[7 + (11 * i)], 0, gettext("error"));
                        set_field_buffer_wrap(debuglvl, TrafVolSection.fields[8 + (11 * i)], 0, gettext("error"));
                    }

            
                    /* get the bw for the last month */
                    year = cur_tm.tm_year + 1900;
                    /* get prev month (by not adding +1) */
                    month = cur_tm.tm_mon;

                    /*  if month = 0 (Jan), set it to 12
                        (Dec) and subtract one of the
                        year.
                    */
                    if(month == 0)
                    {
                        month = 12;
                        year = year - 1;
                    }

                    result = bandwidth_get_iface(debuglvl, iface_ptr->device, year, month, 1, 0, 1, &bw_list);
                    if(result == 1)
                    {
                        for(bw_d_node = bw_list.top; bw_d_node; bw_d_node = bw_d_node->next)
                        {
                            if(!(bw_ptr = bw_d_node->data))
                            {
                                (void)vrprint.error(-1, VR_INTERR, "NULL pointer (in: %s:%d).", __FUNC__, __LINE__);
                                return(-1);
                            }
                            //printf("%2d/%2d/%4d: in: %u, out: %u %s\n", bw_ptr->day, bw_ptr->month, bw_ptr->year, bw_ptr->recv_mb, bw_ptr->send_mb, bw_ptr->total ? "(total)" : "");

                            create_bw_string(debuglvl, bw_ptr->recv_mb, bw_str, sizeof(bw_str));
                            set_field_buffer_wrap(debuglvl, TrafVolSection.fields[9 + (11 * i)], 0, bw_str);

                            create_bw_string(debuglvl, bw_ptr->send_mb, bw_str, sizeof(bw_str));
                            set_field_buffer_wrap(debuglvl, TrafVolSection.fields[10 + (11 * i)], 0, bw_str);
                        }
                        d_list_cleanup(debuglvl, &bw_list);
                    }
                    else if(result == 0)
                    {
                        set_field_buffer_wrap(debuglvl, TrafVolSection.fields[9  + (11 * i)], 0, "  -  ");
                        set_field_buffer_wrap(debuglvl, TrafVolSection.fields[10 + (11 * i)], 0, "  -  ");
                    }
                    else
                    {
                        set_field_buffer_wrap(debuglvl, TrafVolSection.fields[9  + (11 * i)], 0, gettext("error"));
                        set_field_buffer_wrap(debuglvl, TrafVolSection.fields[10 + (11 * i)], 0, gettext("error"));
                    }

                    /* finally draw the screen */
                    wrefresh(TrafVolSection.win);

                    /* update the line */
                    i++;
                }
            }
        }

        /* finally draw the screen */
        wrefresh(TrafVolSection.win);

        /* process the keyboard input */
        ch = wgetch(TrafVolSection.win);
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
                print_help(debuglvl, ":[VUURMUUR:TRAFVOL]:");
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

    /* EXIT: cleanup */
    nodelay(TrafVolSection.win, FALSE);

    /* destroy the window and form */
    trafvol_section_destroy();
    
    update_panels();
    doupdate();

    return(retval);
}
