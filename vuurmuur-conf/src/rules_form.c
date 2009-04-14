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

#define FIELDS_PER_BAR  8

#define MIN_ACTIVE      4
#define MIN_NUMFIELD    4
#define MIN_ACTION      8
#define MIN_SERVICE     9
#define MIN_FROM        18
#define MIN_TO          18
#define MIN_OPTIONS     14

#define MAX_ACTIVE      4
#define MAX_NUMFIELD    4
#define MAX_ACTION      10
#define MAX_SERVICE     32
#define MAX_FROM        96  // TODO
#define MAX_TO          96  // TODO
#define MAX_OPTIONS     256 // TODO


/*  rulebar

    Container for pointers to fields.
*/
typedef struct
{
    unsigned int    bar_num;

    /* pointers the the fields */
    FIELD           *active;
    FIELD           *num_field;
    FIELD           *action;
    FIELD           *service;
    FIELD           *from;
    FIELD           *to;
    FIELD           *options;

    FIELD           *separator;

}  rulebar;


struct RuleBarForm_
{
    d_list          RuleBar_list;

    unsigned int    bars;

    unsigned int    max_bars_on_screen;
    unsigned int    filtered_rules;

    unsigned int    printable_rules;
    unsigned int    scroll_offset;

    /* for regex filtering */
    regex_t         filter_reg;
    char            use_filter;
    
    /* some more filtering */
    char            show_only_forward,
                    show_only_input,
                    show_only_output;

    /* field sizes */
    size_t          active_size;
    size_t          num_field_size;
    size_t          action_size;
    size_t          service_size;
    size_t          from_size;
    size_t          to_size;
    size_t          options_size;
    size_t          separator_size;

    /* for the (more) indicator when not all rules fit on screen */
    PANEL           *more_pan[1];
    WINDOW          *more_win;
};


static int SetupRuleBarForm(const int, struct RuleBarForm_ *, unsigned int, Rules *, int);
static int move_rule(const int, Rules *, unsigned int, unsigned int);
static int MatchFilter_RuleBar(struct RuleData_ *rule_ptr, regex_t *reg, char only_in, char only_out, char only_forward);
static int Toggle_RuleBar(const int debuglvl, rulebar *bar, Rules *rules);
static int draw_rules(const int, Rules *, struct RuleBarForm_ *);
static int Enter_RuleBar(const int, rulebar *, Rules *, Zones *, Interfaces *, Services *, struct rgx_ *);
static int edit_rule_separator(const int, Zones *, Interfaces *, Services *, struct RuleData_ *, unsigned int, struct rgx_ *);


static int
SetupRuleBarForm(const int debuglvl, struct RuleBarForm_ *rbform, unsigned int max_bars_on_screen, Rules *rules, int screen_width)
{
    size_t  sum = 0,
            i = 0;

    /* safety checks */
    if(!rbform || !rules || max_bars_on_screen <= 0 || screen_width <= 0)
    {
        (void)vrprint.error(-1, VR_INTERR, "parameter problem (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    /* init bars */
    rbform->bars = 0;
    rbform->max_bars_on_screen = max_bars_on_screen;

    rbform->filtered_rules = 0;
    rbform->printable_rules = 0;
    rbform->scroll_offset = 0;
    
    rbform->use_filter = 0;
    rbform->show_only_input = 0;
    rbform->show_only_output = 0;
    rbform->show_only_forward = 0;

    /* setup list */
    if(d_list_setup(debuglvl, &rbform->RuleBar_list, free) < 0)
        return(-1);

    /* calculate field sizes */
    rbform->active_size    = MIN_ACTIVE;
    rbform->num_field_size = MIN_NUMFIELD;
    rbform->action_size    = MIN_ACTION;
    rbform->service_size   = MIN_SERVICE;
    rbform->from_size      = MIN_FROM;
    rbform->to_size        = MIN_TO;
    rbform->options_size   = MIN_OPTIONS;

    sum = rbform->active_size + rbform->num_field_size + rbform->action_size +
        rbform->service_size +rbform->from_size + rbform->to_size + rbform->options_size;
    if((int)sum > screen_width)
    {
        (void)vrprint.error(-1, VR_INTERR, "screen too small: sum: %d, width: %d (in: %s:%d).",
                            sum,
                            screen_width,
                            __FUNC__, __LINE__);
        return(-1);
    }

    while((int)sum <= screen_width)
    {
        for(i = 0; (int)sum <= screen_width && i < 6; i++)
        {
            if(i == 0 && rbform->action_size < MAX_ACTION)
                rbform->action_size++;
            else if(i == 1 && rbform->service_size < MAX_SERVICE)
                rbform->service_size++;
            else if(i == 2 && rbform->from_size < MAX_FROM)
                rbform->from_size++;
            else if(i == 3 && rbform->to_size < MAX_TO)
                rbform->to_size++;
            else if(i == 5 && rbform->options_size)
                rbform->options_size++;

            sum = rbform->active_size + rbform->num_field_size + rbform->action_size + rbform->service_size +
                rbform->from_size + rbform->to_size + rbform->options_size;
        }
    }

    if(debuglvl >= HIGH)
        (void)vrprint.debug(__FUNC__, "success.");

    return(0);
}


/*
    TODO: error checking
    

    returncodes:
         0: ok
        -1: error
*/
static int
move_rule(const int debuglvl, Rules *rules, unsigned int rule_num,
        unsigned int new_place)
{
    int                 retval = 0,
                        i = 0;
    struct RuleData_    *rule_ptr = NULL;
    d_list_node         *d_node = NULL;


    /* safety */
    if(!rules)
    {
        (void)vrprint.error(-1, VR_INTERR, "parameter problem (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    status_print(status_win, gettext("Moving rule..."));

    /* santiy check for new_place */
    if(new_place > rules->list.len)
    {
        if(debuglvl >= LOW)
            (void)vrprint.debug(__FUNC__, "new_place (%d) > rules_list->len (%d) so new_place = %d", new_place, rules->list.len, rules->list.len);

        new_place = rules->list.len;
    }
    else if(new_place <= 0)
        new_place = 1;


    for(d_node = rules->list.top; d_node ; d_node = d_node->next)
    {
        if(!(rule_ptr = d_node->data))
        {
            (void)vrprint.error(-1, VR_INTERR, "NULL pointer (in: %s:%d).", __FUNC__, __LINE__);
            return(-1);
        }

        if(rule_ptr->number == rule_num)
            break;
    }

    if(debuglvl >= HIGH)
        (void)vrprint.debug(__FUNC__, "rule_ptr found: i: %d (rule_ptr: %s %s %s %s)", i, rules_itoaction(rule_ptr->action), rule_ptr->service, rule_ptr->from, rule_ptr->to);

//TODO
    rules_remove_rule_from_list(debuglvl, rules, rule_num, 1);

    rule_ptr->number = new_place;
    
    if(debuglvl >= HIGH)
        (void)vrprint.debug(__FUNC__, "new_place: %d, rule_ptr->number: %d", new_place, rule_ptr->number);

//TODO
    rules_insert_list(debuglvl, rules, new_place, rule_ptr);


    if(debuglvl >= LOW)
        rules_print_list(rules);

    return(retval);
}



/*  Move_RuleBarForm

    display a screen TODO
*/
static int
MoveRuleBarForm(const int debuglvl, struct RuleBarForm_ *rbform, Rules *rules, unsigned int cur_rule)
{
    int     ch,
            quit=0;
    WINDOW  *move_win;
    PANEL   *panels[1];
    FIELD   **fields;
    FORM    *form;

    if(cur_rule < 0 || !rules)
        return(-1);

    if(cur_rule == 0)
        return(0);

    // create window, panel, fields, form and post it
    if(!(move_win = create_newwin(6, 40, (LINES-6)/2, (COLS-40)/2, gettext("Move Rule"), (chtype)COLOR_PAIR(CP_BLUE_WHITE))))
    {
        (void)vrprint.error(-1, VR_ERR, gettext("creating window failed."));
        return(-1);
    }
    keypad(move_win, TRUE);
    panels[0] = new_panel(move_win);

    fields = (FIELD **)calloc(1 + 1, sizeof(FIELD *));
//TODO
    fields[0] = new_field(1, 5, 1, 28, 0, 0);
    set_field_type(fields[0], TYPE_INTEGER, 5, 1, 99999);
    fields[1] = NULL;

    set_field_back(fields[0], (chtype)COLOR_PAIR(CP_WHITE_BLUE));
    field_opts_off(fields[0], O_AUTOSKIP);
    set_field_status(fields[0], FALSE);

    // Create the form and post it
    form = new_form(fields);
    // Set main window and sub window and post the form
    set_form_win(form, move_win);
    set_form_sub(form, derwin(move_win, 4, 36, 1, 1));
    post_form(form);

    // labels
    mvwprintw(move_win, 2, 2, gettext("Enter the new rule number:"));
    mvwprintw(move_win, 4, 2, gettext("Cur: %d, Min: 1, Max: %d"), cur_rule, rules->list.len);

    if(debuglvl >= HIGH)
        (void)vrprint.debug(__FUNC__, "cur_rule: %d, rules->list.len: %d.", cur_rule, rules->list.len);

    update_panels();
    doupdate();

    while(quit == 0)
    {
        // get user input
        ch = wgetch(move_win);

        switch(ch)
        {
            case 10: // enter
                form_driver(form, REQ_VALIDATION);
                
//TODO atoi sepparate
                if(move_rule(debuglvl, rules, cur_rule, (unsigned int)atoi(field_buffer(fields[0], 0))) < 0)
                    return(-1);
                quit = 1;
                break;

            case KEY_BACKSPACE:
            case 127:
                form_driver(form, REQ_PREV_CHAR);
                form_driver(form, REQ_DEL_CHAR);
                form_driver(form, REQ_END_LINE);
                break;

            case KEY_DC:
                form_driver(form, REQ_PREV_CHAR);
                form_driver(form, REQ_DEL_CHAR);
                form_driver(form, REQ_END_LINE);
                break;

            case 27:
            case KEY_F(10):
            case 'q':
            case 'Q':
                quit = 1;
                break;

            default:
                form_driver(form, ch);
                break;
        }
    }

    /*
        cleanup
    */
    unpost_form(form);
    free_form(form);
    free_field(fields[0]);
    free(fields);

    del_panel(panels[0]);
    destroy_win(move_win);

    update_panels();
    doupdate();

    return(0);
}


rulebar *
CurrentBar(struct RuleBarForm_ *rbform, FORM *form)
{
    FIELD       *cur_field = NULL;
    rulebar     *cur_bar = NULL;
    d_list_node *d_node = NULL;

    /* safety */
    if(!rbform || !form)
    {
        (void)vrprint.error(-1, VR_INTERR, "NULL pointer (in: %s:%d).", __FUNC__, __LINE__);
        return(NULL);
    }

    /* get the current field */
    cur_field = current_field(form);
    /* look for the current bar */
    for(d_node = rbform->RuleBar_list.top; d_node; d_node = d_node->next)
    {
        if(!(cur_bar = d_node->data))
        {
            (void)vrprint.error(-1, VR_INTERR, "NULL pointer (in: %s:%d).", __FUNC__, __LINE__);
            return(NULL);
        }

        if(cur_bar->active == cur_field)
            return(cur_bar);
//        else if(cur_bar->separator == cur_field)
//            return(cur_bar);
    }

    (void)vrprint.error(-1, VR_INTERR, "bar not found (in: %s:%d).", __FUNC__, __LINE__);
    return(NULL);
}


static void
rulebar_setcolor(   FIELD *active,
                    FIELD *num_field,
                    FIELD *action,
                    FIELD *service,
                    FIELD *from,
                    FIELD *to,
                    FIELD *options,
                    FIELD *separator,
                    chtype color)
{
    char    active_rule = 0;

    /* active */
    if(color == COLOR_BLUE)
        set_field_back(active, (chtype)COLOR_PAIR(CP_WHITE_BLUE));
    else if(color == COLOR_WHITE)
        set_field_back(active, (chtype)COLOR_PAIR(CP_BLUE_WHITE));
    else if(color == COLOR_RED)
        set_field_back(active, (chtype)COLOR_PAIR(CP_RED_WHITE));

    if(strncmp(field_buffer(active, 0), "[x]", 3) == 0)
    {
        active_rule = 1;
    }

    /* num_field */
    if(color == COLOR_BLUE)
        set_field_back(num_field, (chtype)COLOR_PAIR(CP_WHITE_BLUE));
    else if(color == COLOR_WHITE)
        set_field_back(num_field, (chtype)COLOR_PAIR(CP_BLUE_WHITE));
    else if(color == COLOR_RED)
        set_field_back(num_field, (chtype)COLOR_PAIR(CP_RED_WHITE));

    /* action */
    if(strncasecmp(field_buffer(action, 0), "drop", 4) == 0)
    {
        if(color == COLOR_BLUE && active_rule)
            set_field_back(action, (chtype)COLOR_PAIR(CP_RED_BLUE)|A_BOLD);
        else if(color == COLOR_WHITE)
            set_field_back(action, (chtype)COLOR_PAIR(CP_RED_WHITE)|A_BOLD);
        else if(color == COLOR_RED)
            set_field_back(action, (chtype)COLOR_PAIR(CP_RED_WHITE));
        else
            set_field_back(action, (chtype)COLOR_PAIR(CP_WHITE_BLUE));
    }
    else if(strncasecmp(field_buffer(action, 0), "reject", 6) == 0)
    {
        if(color == COLOR_BLUE && active_rule)
            set_field_back(action, (chtype)COLOR_PAIR(CP_RED_BLUE));
        else if(color == COLOR_WHITE)
            set_field_back(action, (chtype)COLOR_PAIR(CP_RED_WHITE));
        else if(color == COLOR_RED)
            set_field_back(action, (chtype)COLOR_PAIR(CP_RED_WHITE));
        else
            set_field_back(action, (chtype)COLOR_PAIR(CP_WHITE_BLUE));
    }
    else if(strncasecmp(field_buffer(action, 0), "accept", 6) == 0)
    {
        if(color == COLOR_BLUE && active_rule)
            set_field_back(action, (chtype)COLOR_PAIR(CP_GREEN_BLUE)|A_BOLD);
        else if(color == COLOR_WHITE)
            set_field_back(action, (chtype)COLOR_PAIR(CP_GREEN_WHITE)|A_BOLD);
        else if(color == COLOR_RED)
            set_field_back(action, (chtype)COLOR_PAIR(CP_RED_WHITE));
        else
            set_field_back(action, (chtype)COLOR_PAIR(CP_WHITE_BLUE));
    }
    else if(strncasecmp(field_buffer(action, 0), "log", 3) == 0)
    {
        if(color == COLOR_BLUE && active_rule)
            set_field_back(action, (chtype)COLOR_PAIR(CP_WHITE_BLUE)|A_BOLD);
        else if(color == COLOR_WHITE)
            set_field_back(action, (chtype)COLOR_PAIR(CP_BLUE_WHITE)|A_BOLD);
        else if(color == COLOR_RED)
            set_field_back(action, (chtype)COLOR_PAIR(CP_RED_WHITE));
        else
            set_field_back(action, (chtype)COLOR_PAIR(CP_WHITE_BLUE));
    }
    else if(strncasecmp(field_buffer(action, 0), "portfw", 6) == 0 ||
        strncasecmp(field_buffer(action, 0), "dnat", 4) == 0 ||
        strncasecmp(field_buffer(action, 0), "bounce", 6) == 0)
    {
        if(color == COLOR_BLUE && active_rule)
            set_field_back(action, (chtype)COLOR_PAIR(CP_YELLOW_BLUE)|A_BOLD);
        else if(color == COLOR_WHITE)
            set_field_back(action, (chtype)COLOR_PAIR(CP_YELLOW_WHITE)|A_BOLD);
        else if(color == COLOR_RED)
            set_field_back(action, (chtype)COLOR_PAIR(CP_RED_WHITE));
        else
            set_field_back(action, (chtype)COLOR_PAIR(CP_WHITE_BLUE));
    }
    else if(strncasecmp(field_buffer(action, 0), "snat", 4) == 0)
    {
        if(color == COLOR_BLUE && active_rule)
            set_field_back(action, (chtype)COLOR_PAIR(CP_YELLOW_BLUE)|A_BOLD);
        else if(color == COLOR_WHITE)
            set_field_back(action, (chtype)COLOR_PAIR(CP_YELLOW_WHITE)|A_BOLD);
        else if(color == COLOR_RED)
            set_field_back(action, (chtype)COLOR_PAIR(CP_RED_WHITE));
        else
            set_field_back(action, (chtype)COLOR_PAIR(CP_WHITE_BLUE));
    }
    else if(strncasecmp(field_buffer(action, 0), "masq", 4) == 0)
    {
        if(color == COLOR_BLUE && active_rule)
            set_field_back(action, (chtype)COLOR_PAIR(CP_YELLOW_BLUE)|A_BOLD);
        else if(color == COLOR_WHITE)
            set_field_back(action, (chtype)COLOR_PAIR(CP_YELLOW_WHITE)|A_BOLD);
        else if(color == COLOR_RED)
            set_field_back(action, (chtype)COLOR_PAIR(CP_RED_WHITE));
        else
            set_field_back(action, (chtype)COLOR_PAIR(CP_WHITE_BLUE));
    }
    else if(strncasecmp(field_buffer(action, 0), "redirect", 8) == 0)
    {
        if(color == COLOR_BLUE && active_rule)
            set_field_back(action, (chtype)COLOR_PAIR(CP_YELLOW_BLUE)|A_BOLD);
        else if(color == COLOR_WHITE)
            set_field_back(action, (chtype)COLOR_PAIR(CP_YELLOW_WHITE)|A_BOLD);
        else if(color == COLOR_RED)
            set_field_back(action, (chtype)COLOR_PAIR(CP_RED_WHITE));
        else
            set_field_back(action, (chtype)COLOR_PAIR(CP_WHITE_BLUE));
    }
    else if(strncasecmp(field_buffer(action, 0), "queue", 5) == 0 ||
        strncasecmp(field_buffer(action, 0), "nfqueue", 6) == 0)
    {
        if(color == COLOR_BLUE && active_rule)
            set_field_back(action, (chtype)COLOR_PAIR(CP_WHITE_BLUE)|A_BOLD);
        else if(color == COLOR_WHITE)
            set_field_back(action, (chtype)COLOR_PAIR(CP_BLUE_WHITE)|A_BOLD);
        else if(color == COLOR_RED)
            set_field_back(action, (chtype)COLOR_PAIR(CP_RED_WHITE));
        else
            set_field_back(action, (chtype)COLOR_PAIR(CP_WHITE_BLUE));
    }
    else if(strncasecmp(field_buffer(action, 0), "chain", 5) == 0)
    {
        if(color == COLOR_BLUE && active_rule)
            set_field_back(action, (chtype)COLOR_PAIR(CP_WHITE_BLUE)|A_BOLD);
        else if(color == COLOR_WHITE)
            set_field_back(action, (chtype)COLOR_PAIR(CP_BLUE_WHITE)|A_BOLD);
        else if(color == COLOR_RED)
            set_field_back(action, (chtype)COLOR_PAIR(CP_RED_WHITE));
        else
            set_field_back(action, (chtype)COLOR_PAIR(CP_WHITE_BLUE));
    }
    else
    {
        if(color == COLOR_BLUE && active_rule)
            set_field_back(action, (chtype)COLOR_PAIR(CP_WHITE_BLUE));
        else if(color == COLOR_WHITE)
            set_field_back(action, (chtype)COLOR_PAIR(CP_BLUE_WHITE));
        else if(color == COLOR_RED)
            set_field_back(action, (chtype)COLOR_PAIR(CP_RED_WHITE));
        else
            set_field_back(action, (chtype)COLOR_PAIR(CP_WHITE_BLUE));
    }


    /* service */
    if(color == COLOR_BLUE && active_rule)
        set_field_back(service, (chtype)COLOR_PAIR(CP_CYAN_BLUE)|A_BOLD);
    else if(color == COLOR_WHITE)
        set_field_back(service, (chtype)COLOR_PAIR(CP_CYAN_WHITE)|A_BOLD);
    else if(color == COLOR_RED)
        set_field_back(service, (chtype)COLOR_PAIR(CP_RED_WHITE));
    else
        set_field_back(service, (chtype)COLOR_PAIR(CP_WHITE_BLUE));

    /* from zone or firewall */
    if(strncasecmp(field_buffer(from, 0), "firewall", 8) == 0)
    {
        if(color == COLOR_BLUE && active_rule)
            set_field_back(from, (chtype)COLOR_PAIR(CP_YELLOW_BLUE)|A_BOLD);
        else if(color == COLOR_WHITE)
            set_field_back(from, (chtype)COLOR_PAIR(CP_YELLOW_WHITE)|A_BOLD);
        else if(color == COLOR_RED)
            set_field_back(from, (chtype)COLOR_PAIR(CP_RED_WHITE));
        else
            set_field_back(from, (chtype)COLOR_PAIR(CP_WHITE_BLUE));
    }
    else
    {
        if(color == COLOR_BLUE && active_rule)
            set_field_back(from, (chtype)COLOR_PAIR(CP_WHITE_BLUE)|A_BOLD);
        else if(color == COLOR_WHITE)
            set_field_back(from, (chtype)COLOR_PAIR(CP_BLUE_WHITE)|A_BOLD);
        else if(color == COLOR_RED)
            set_field_back(from, (chtype)COLOR_PAIR(CP_RED_WHITE));
        else
            set_field_back(from, (chtype)COLOR_PAIR(CP_WHITE_BLUE));
    }

    // to
    if(strncasecmp(field_buffer(to, 0), "firewall", 8) == 0)
    {
        if(color == COLOR_BLUE && active_rule)
            set_field_back(to, (chtype)COLOR_PAIR(CP_YELLOW_BLUE)|A_BOLD);
        else if(color == COLOR_WHITE)
            set_field_back(to, (chtype)COLOR_PAIR(CP_YELLOW_WHITE)|A_BOLD);
        else if(color == COLOR_RED)
            set_field_back(to, (chtype)COLOR_PAIR(CP_RED_WHITE));
        else
            set_field_back(to, (chtype)COLOR_PAIR(CP_WHITE_BLUE));

    }
    else
    {
        if(color == COLOR_BLUE && active_rule)
            set_field_back(to, (chtype)COLOR_PAIR(CP_WHITE_BLUE)|A_BOLD);
        else if(color == COLOR_WHITE)
            set_field_back(to, (chtype)COLOR_PAIR(CP_BLUE_WHITE)|A_BOLD);
        else if(color == COLOR_RED)
            set_field_back(to, (chtype)COLOR_PAIR(CP_RED_WHITE));
        else
            set_field_back(to, (chtype)COLOR_PAIR(CP_WHITE_BLUE));
    }

    // options field
    if(color == COLOR_BLUE)
        set_field_back(options, (chtype)COLOR_PAIR(CP_WHITE_BLUE));
    else if(color == COLOR_WHITE)
        set_field_back(options, (chtype)COLOR_PAIR(CP_BLUE_WHITE));
    else if(color == COLOR_RED)
        set_field_back(options, (chtype)COLOR_PAIR(CP_RED_WHITE));
    else
        set_field_back(options, (chtype)COLOR_PAIR(CP_WHITE_BLUE));


    if(color == COLOR_BLUE)
        set_field_back(separator, (chtype)COLOR_PAIR(CP_WHITE_BLUE)|A_BOLD);
    else if(color == COLOR_WHITE)
        set_field_back(separator, (chtype)COLOR_PAIR(CP_BLUE_WHITE)|A_BOLD);
    else if(color == COLOR_RED)
        set_field_back(separator, (chtype)COLOR_PAIR(CP_RED_WHITE));
    else
        set_field_back(separator, (chtype)COLOR_PAIR(CP_WHITE_BLUE));
}

/*  Highlight_RuleBar

    Highlights the cursor, and clears the previous highlight.
*/
void
HighlightRuleBar(rulebar *bar)
{
    if(bar != NULL)
    {
        rulebar_setcolor( bar->active, bar->num_field, bar->action, bar->service,
                    bar->from, bar->to, bar->options, bar->separator, COLOR_RED);
    }
    else
        (void)vrprint.debug(__FUNC__, "warning: no bar (bar == NULL).");
}


/*

    Returncodes:
         1: changed rule
         0: no changes
        -1: error
*/
static int
Enter_RuleBar(const int debuglvl, rulebar *bar, Rules *rules, Zones *zones, Interfaces *interfaces, Services *services, struct rgx_ *reg)
{
    unsigned int        rule_num = 0;
    int                 result = 0,
                        retval = 0;
    struct RuleData_    *rule_ptr = NULL;
    d_list_node         *d_node = NULL;
    

    /* safety */
    if(!bar || !rules || !reg)
    {
        (void)vrprint.error(-1, VR_INTERR, "parameter problem (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }
    
    
    if(debuglvl >= HIGH)
        (void)vrprint.debug(__FUNC__, "field_buffer = '%s'.", field_buffer(bar->num_field, 0));

    rule_num = (unsigned int)atoi(field_buffer(bar->num_field, 0));
    if(rule_num == 0)
        return(0);

    result = edit_rule(debuglvl, rules, zones, interfaces, services, rule_num, reg);
    if(result < 0)
    {
        for(d_node = rules->list.top; d_node ; d_node = d_node->next)
        {
            if(!(rule_ptr = d_node->data))
            {
                (void)vrprint.error(-1, VR_INTERR, "NULL pointer (in: %s:%d).", __FUNC__, __LINE__);
                return(-1);
            }

            if(rule_ptr->number == rule_num)
                break;
        }

        /* editting failed so remove the rule again */
        if(rules_remove_rule_from_list(debuglvl, rules, rule_num, 1) < 0)
        {
            (void)vrprint.error(-1, VR_INTERR, "removing rule failed (in: %s:%d).", __FUNC__, __LINE__);
            return(-1);
        }

        free_options(debuglvl, rule_ptr->opt);
        rule_ptr->opt = NULL;
        free(rule_ptr);
        rule_ptr = NULL;

        retval = -1;
    }
    else if(result == 1)
    {
        retval = 1;
    }

    return(retval);
}


/*
    returncodes:
         0: ok
        -1: error
*/
int
rules_duplicate_rule(const int debuglvl, Rules *rules, struct RuleData_ *org_rule_ptr, struct rgx_ *reg)
{
    char                *rule_str = NULL;
    struct RuleData_    *new_rule_ptr = NULL;

    /* safety */
    if(!rules || !org_rule_ptr | !reg)
    {
        (void)vrprint.error(-1, VR_INTERR, "parameter problem (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    /* get the rulestring */
    if(!(rule_str = rules_assemble_rule(debuglvl, org_rule_ptr)))
    {
        (void)vrprint.error(-1, VR_INTERR, "failed to assemble rule to be copied (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    /* claim memory for the new rule*/
    if(!(new_rule_ptr = rule_malloc()))
    {
        free(rule_str);

        return(-1);
    }

    /* parse the line */
    if(rules_parse_line(debuglvl, rule_str, new_rule_ptr, reg) != 0)
    {
        free(rule_str);
        free(new_rule_ptr);

        (void)vrprint.error(-1, VR_INTERR, "failed to parse rule to be copied (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    free(rule_str);
    rule_str = NULL;

    /* this rules number is one higher than the original */
    new_rule_ptr->number = org_rule_ptr->number + 1;

    /* insert the new rule into the list */
    if(rules_insert_list(debuglvl, rules, new_rule_ptr->number, new_rule_ptr) < 0)
    {
        (void)vrprint.error(-1, VR_INTERR, "failed to insert in list (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    return(0);
}


/*
    orig_rule_num is the number of the rule to be copied. Thus,
    the new rule will get number orig_rule_num + 1
*/
static int
rulebar_copy_rule(const int debuglvl, Rules *rules, unsigned int orig_rule_num, struct rgx_ *reg)
{
    struct RuleData_    *rule_ptr = NULL;
    d_list_node         *d_node = NULL;

    /* safety */
    if(!rules || !reg)
    {
        (void)vrprint.error(-1, VR_INTERR, "parameter problem (in: %s).", __FUNC__);
        return(-1);
    }

    for(d_node = rules->list.top; d_node; d_node = d_node->next)
    {
        if(!(rule_ptr = d_node->data))
        {
            (void)vrprint.error(-1, VR_INTERR, "NULL pointer (in: %s:%d).", __FUNC__, __LINE__);
            return(-1);
        }

        if(rule_ptr->number == orig_rule_num)
            break;
    }

    if(!rule_ptr)
    {
        (void)vrprint.error(-1, VR_INTERR, "rule to be copied not found (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    return(rules_duplicate_rule(debuglvl, rules, rule_ptr, reg));
}


/*
*/
static int
Toggle_RuleBar(const int debuglvl, rulebar *bar, Rules *rules)
{
    int                 rule_num = 0,
                        retval = 0;
    int                 i = 0;
    d_list_node         *d_node = NULL;
    struct RuleData_    *rule_ptr = NULL;

    if(debuglvl >= HIGH)
        (void)vrprint.debug(__FUNC__, "'%s'.", field_buffer(bar->num_field, 0));

    rule_num = atoi(field_buffer(bar->num_field, 0));
    if(rule_num < 0)
    {
        (void)vrprint.error(-1, VR_INTERR, "invalid rule_num: %d (in: %s:%d).", rule_num, __FUNC__, __LINE__);
        return(-1);
    }

    if(rules->list.len == 0)
    {
        return(0);
    }
    
    /* go to rulenum in the rules list to get the rule_ptr */
    if(!(d_node = rules->list.top))
    {
        (void)vrprint.error(-1, VR_INTERR, "NULL pointer (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    /* look for the rule_ptr */
    for(i = 1; i <= rule_num; i++)
    {
        if(!(rule_ptr = d_node->data))
        {
            (void)vrprint.error(-1, VR_INTERR, "NULL pointer (in: %s:%d).", __FUNC__, __LINE__);
            return(-1);
        }

        d_node = d_node->next;
    }

    if(debuglvl >= HIGH)
        (void)vrprint.debug(__FUNC__, "active: %s (%s %s %s %s)", rule_ptr->active ? "Yes" : "No", rules_itoaction(rule_ptr->action), rule_ptr->service, rule_ptr->from, rule_ptr->to);

    /* set the active */
    if(rule_ptr->active == 1)
        rule_ptr->active = 0;
    else
        rule_ptr->active = 1;

    return(retval);
}


/*  Set_RuleBar

    Sets the rulebar to the position 'pos'.
*/
static void
Set_RuleBar(const int debuglvl, struct RuleBarForm_ *rbform, FORM *form,
        unsigned int pos)
{
    d_list_node     *d_node = NULL;
    rulebar         *cur_bar = NULL;
    unsigned int    i = 0;
    int             result = 0;

    for(i=1, d_node = rbform->RuleBar_list.top; d_node; i++, d_node = d_node->next)
    {
        cur_bar = d_node->data;

        if(i == pos)
        {
            if(debuglvl >= HIGH)
                (void)vrprint.debug(__FUNC__, "field found");

            result = set_current_field(form, cur_bar->active);

            if(debuglvl >= HIGH)
            {
                if(result == E_OK)
                    (void)vrprint.debug(__FUNC__, "field found: E_OK");
                else if(result == E_SYSTEM_ERROR)
                    (void)vrprint.debug(__FUNC__, "field found: E_SYSTEM_ERROR: %s", strerror(errno));
                else if(result == E_BAD_ARGUMENT)
                    (void)vrprint.debug(__FUNC__, "field found: E_BAD_ARGUMENT");
                else
                    (void)vrprint.debug(__FUNC__, "field found: unknown result %d", result);
            }
        }
    }
}


int
Insert_RuleBar( const int debuglvl,
                struct RuleBarForm_ *rbform,
                FIELD *active,
                FIELD *num_field,
                FIELD *action,
                FIELD *service,
                FIELD *from,
                FIELD *to,
                FIELD *options,
                FIELD *separator)
{
    rulebar *bar;

    /* alloc mem */
    if(!(bar = malloc(sizeof(rulebar))))
    {
        (void)vrprint.error(-1, VR_ERR, gettext("malloc failed: %s (in: %s:%d)."), strerror(errno), __FUNC__, __LINE__);
        return(-1);
    }

    bar->active = active;
    bar->num_field = num_field;
    bar->action = action;
    bar->service = service;
    bar->from = from;
    bar->to = to;
    bar->options = options;
    bar->separator = separator;

    /* insert the bar into the list */
    if(!(d_list_append(debuglvl, &rbform->RuleBar_list, bar)))
    {
        (void)vrprint.error(-1, VR_INTERR, "insert into list failed (in: Insert_RuleBar).");
        return(-1);
    }

    rbform->bars++;
    bar->bar_num = rbform->bars;

    if(debuglvl >= HIGH)
        (void)vrprint.debug(__FUNC__, "success at %p (bars: %d, bar->num: %d).", bar, rbform->bars, bar->bar_num);

    return(0);
}


static int
MatchFilter_RuleBar(struct RuleData_ *rule_ptr, /*@null@*/regex_t *reg, char only_in, char only_out, char only_forward)
{
    char    *options_ptr = NULL,
            rule_str[512] = "";
    int     result = 0,
            retval = 0;
    size_t  option_len = 0,
            rule_len = 0;
        
    if(only_in == 1)
    {
        if(strcmp(rule_ptr->to, "firewall") != 0)
            return(0);
    }
    else if(only_out == 1)
    {
        if(strcmp(rule_ptr->from, "firewall") != 0)
            return(0);
    }
    else if(only_forward == 1)
    {
        if(strcmp(rule_ptr->from, "firewall") == 0 || strcmp(rule_ptr->to, "firewall") == 0)
            return(0);
    }
    
    /* if we're not using a regex, we match here */
    if(!reg)
        return(1);

    if(!(options_ptr = rules_assemble_options_string(0, rule_ptr->opt, rules_itoaction(rule_ptr->action))))
        option_len = 0;
    else
        option_len = StrLen(options_ptr);

    rule_len = StrLen(rules_itoaction(rule_ptr->action))+1 + StrLen(rule_ptr->service)+1 + StrLen(rule_ptr->from)+1 + StrLen(rule_ptr->to)+1 + option_len + 1;

    (void)strlcpy(rule_str, rules_itoaction(rule_ptr->action), sizeof(rule_str));
    (void)strlcat(rule_str, " ", sizeof(rule_str));
    (void)strlcat(rule_str, rule_ptr->service, sizeof(rule_str));
    (void)strlcat(rule_str, " ", sizeof(rule_str));
    (void)strlcat(rule_str, rule_ptr->from, sizeof(rule_str));
    (void)strlcat(rule_str, " ", sizeof(rule_str));
    (void)strlcat(rule_str, rule_ptr->to, sizeof(rule_str));
    (void)strlcat(rule_str, " ", sizeof(rule_str));
    if(options_ptr)
        (void)strlcat(rule_str, options_ptr, sizeof(rule_str));

    /* now filter */
    result = regexec(reg, rule_str, 0, NULL, 0);
    if(result == 0)
        retval = 1;
    else
        retval = 0;

    return(retval);
}


static int
draw_rules(const int debuglvl, Rules *rules, struct RuleBarForm_ *rbform)
{
    struct RuleData_    *rule_ptr = NULL;
    rulebar             *cur_bar = NULL;
    d_list_node         *d_node = NULL;
    d_list_node         *dl_node = NULL;

    unsigned int        draw_count = 0,
                        printable_lines = 0,
                        filtered_rules = 0;

    char                number[MAX_NUMFIELD] = "",
                        active[MAX_ACTIVE] = "",
                        action[MAX_ACTION] = "",
                        service[MAX_SERVICE] = "",
                        from[MAX_FROM] = "",
                        to[MAX_TO] = "",
                        *option_str = NULL,
                        options[MAX_OPTIONS] = "",
                        separator_str[256] = "";

    size_t              i = 0,
                        x = 0;

    char                sep = FALSE,
                        bot_visible = FALSE;

    size_t              comment_len = 0,
                        before_len = 0;

    for(dl_node = rules->list.top, d_node = rbform->RuleBar_list.top;
        dl_node && draw_count < rbform->max_bars_on_screen && d_node;
        dl_node = dl_node->next)
    {
        if(!(rule_ptr = dl_node->data))
        {
            (void)vrprint.error(-1, VR_INTERR, "NULL pointer "
                "(in: %s:%d).", __FUNC__, __LINE__);
            return(-1);
        }
        /* get the bar */
        if(!(cur_bar = d_node->data))
        {
            (void)vrprint.error(-1, VR_INTERR, "NULL pointer "
                "(in: %s:%d).", __FUNC__, __LINE__);
            return(-1);
        }

        /*  if the last item in the list is visible, we will hide
            the (more) panel below */
        if(d_list_node_is_bot(debuglvl, dl_node))
            bot_visible = TRUE;

        if(rule_ptr->action == AT_SEPARATOR)
        {
            field_opts_off(cur_bar->action, O_VISIBLE);
            field_opts_off(cur_bar->service, O_VISIBLE);
            field_opts_off(cur_bar->from, O_VISIBLE);
            field_opts_off(cur_bar->to, O_VISIBLE);
            field_opts_off(cur_bar->options, O_VISIBLE);

            field_opts_on(cur_bar->separator, O_VISIBLE);
            sep = TRUE;
        }
        else
        {
            field_opts_on(cur_bar->action, O_VISIBLE);
            field_opts_on(cur_bar->service, O_VISIBLE);
            field_opts_on(cur_bar->from, O_VISIBLE);
            field_opts_on(cur_bar->to, O_VISIBLE);
            field_opts_on(cur_bar->options, O_VISIBLE);

            field_opts_off(cur_bar->separator, O_VISIBLE);
            sep = FALSE;
        }

        /* test if the rules fits in the filter */
        if(rule_ptr->filtered == 0)
        {
            printable_lines++;

            if(printable_lines > rbform->scroll_offset)
            {
                if(sep == FALSE)
                {
                    /* note if you change the [x] into something else, also change it in rulebar_setcolor */
                    snprintf(active, rbform->active_size,    "%s",  rule_ptr->active ? "[x]" : "[ ]");
                    snprintf(action, rbform->action_size,    "%s",  rules_itoaction(rule_ptr->action));
                    snprintf(service, rbform->service_size,  "%s",  rule_ptr->service);
                    snprintf(from, rbform->from_size,        "%s",  rule_ptr->from);
                    snprintf(to, rbform->to_size,            "%s",  rule_ptr->to);

                    if(!(option_str = rules_assemble_options_string(debuglvl, rule_ptr->opt, rules_itoaction(rule_ptr->action))))
                        strcpy(options, "-");
                    else
                    {
                        /* cut off: 'options:' */
                        for(i=8, x=0; i < StrMemLen(option_str) &&
                            x < sizeof(options); i++, x++)
                        {
                            options[x] = option_str[i];
                        }
                        options[x]='\0';

                        free(option_str);
                        option_str = NULL;
                    }

                    /* set the bufers */
                    set_field_buffer_wrap(debuglvl, cur_bar->active, 0, active);
                    set_field_buffer_wrap(debuglvl, cur_bar->action, 0, action);
                    set_field_buffer_wrap(debuglvl, cur_bar->service, 0, service);
                    set_field_buffer_wrap(debuglvl, cur_bar->from, 0, from);
                    set_field_buffer_wrap(debuglvl, cur_bar->to, 0, to);
                    set_field_buffer_wrap(debuglvl, cur_bar->options, 0, options);
                }
                /* separator */
                else
                {
                    for(i = 0; i < rbform->separator_size && i < sizeof(separator_str); i++)
                    {
                        separator_str[i] = '-';
                    }
                    separator_str[i] = '\0';
                                                
#ifdef USE_WIDEC
                    if(rule_ptr->opt != NULL && rule_ptr->opt->comment[0] != '\0')
                    {
                        size_t  wcomment_len = 0;
                        wchar_t wstr[256] = L"",
                                wtmp[256] = L"";

                        comment_len = StrMemLen(rule_ptr->opt->comment);
                        wcomment_len = StrLen(rule_ptr->opt->comment);

                        before_len = (rbform->separator_size - (wcomment_len + 4)) / 2;

                        wmemset(wstr, L'-', sizeof(wtmp)/sizeof(wchar_t));

                        wstr[before_len] = L'[';
                        wstr[before_len + 1] = L' ';

                        /* convert to wide */
                        mbstowcs(wtmp, rule_ptr->opt->comment, sizeof(wtmp)/sizeof(wchar_t));

                        for(i = before_len + 2, x = 0;
                            i < sizeof(wtmp)/sizeof(wchar_t) &&
                            x < wcomment_len;
                            i++, x++)
                        {
                            wstr[i] = wtmp[x];
                        }
                        wstr[i] = L' ';
                        wstr[i+1] = L']';

                        /* convert back to multi byte */
                        wcstombs(separator_str, wstr, sizeof(separator_str));

                        set_field_buffer_wrap(debuglvl, cur_bar->separator, 0, separator_str);
                    }
                    else
                    {
                        set_field_buffer_wrap(debuglvl, cur_bar->separator, 0, separator_str);
                    }
#else /* USE_WIDEC */
                    if(rule_ptr->opt != NULL && rule_ptr->opt->comment[0] != '\0')
                    {
                        comment_len = StrLen(rule_ptr->opt->comment);

                        before_len = (rbform->separator_size - (comment_len + 4)) / 2;
                        separator_str[before_len] = '[';
                        separator_str[before_len + 1] = ' ';

                        for(i = before_len + 2, x = 0;
                            i < rbform->separator_size && i < sizeof(separator_str) &&
                                x < comment_len;
                            i++, x++)
                        {
                            separator_str[i] = rule_ptr->opt->comment[x];
                        }
                        separator_str[i] = ' ';
                        separator_str[i+1] = ']';

                        set_field_buffer_wrap(debuglvl, cur_bar->separator, 0, separator_str);
                    }
                    else
                    {
                        set_field_buffer_wrap(debuglvl, cur_bar->separator, 0, separator_str);
                    }
#endif /* USE_WIDEC */
                    /* clear */
                    memset(active, 0, rbform->active_size);
                    set_field_buffer_wrap(debuglvl, cur_bar->active, 0, active);
                }

                snprintf(number, rbform->num_field_size, "%2u", printable_lines + filtered_rules);
                set_field_buffer_wrap(debuglvl, cur_bar->num_field, 0, number);

                draw_count++;

                /* colorize the bar */
                rulebar_setcolor(cur_bar->active, cur_bar->num_field, cur_bar->action, cur_bar->service,
                        cur_bar->from, cur_bar->to, cur_bar->options, cur_bar->separator, COLOR_BLUE);

                /* point to the next bar */
                d_node = d_node->next;
            }
            else
            {
                //vrprint.info(__FUNC__, "dont draw: printable_lines: %d, draw_offset_down: %d", printable_lines, *draw_offset_down);
            }
        }
        else
        {
            filtered_rules++;
        }
    }

    /* clear the remaining bars (if any) */
    for(; draw_count < rbform->max_bars_on_screen && d_node; draw_count++, d_node = d_node->next)
    {
        if(!(cur_bar = d_node->data))
        {
            (void)vrprint.error(-1, VR_INTERR, "NULL pointer (in: %s:%d).", __FUNC__, __LINE__);
            return(-1);
        }

        set_field_buffer_wrap(debuglvl, cur_bar->active, 0, "");
        set_field_buffer_wrap(debuglvl, cur_bar->num_field, 0, "");
        set_field_buffer_wrap(debuglvl, cur_bar->action, 0, "");
        set_field_buffer_wrap(debuglvl, cur_bar->service, 0, "");
        set_field_buffer_wrap(debuglvl, cur_bar->from, 0, "");
        set_field_buffer_wrap(debuglvl, cur_bar->to, 0, "");
        set_field_buffer_wrap(debuglvl, cur_bar->options, 0, "");
        set_field_buffer_wrap(debuglvl, cur_bar->separator, 0, "");

        rulebar_setcolor(cur_bar->num_field, cur_bar->active, cur_bar->action, cur_bar->service, cur_bar->from, cur_bar->to, cur_bar->options, cur_bar->separator, COLOR_BLUE);
    }

    /* don' t show (more) panel if list size is 0 */
    if(bot_visible == TRUE || rules->list.len == 0)
        hide_panel(rbform->more_pan[0]);
    else
        show_panel(rbform->more_pan[0]);

    /* finally update the screen */
    update_panels();
    doupdate();
    return(0);
}


static int
rules_update_filter(const int debuglvl, Rules *rules, struct RuleBarForm_ *rbform)
{
    struct RuleData_    *rule_ptr = NULL;
    d_list_node         *d_node = NULL;
    char                filter = 0;

    /* count the number of lines that are filtered */
    if(rbform->use_filter || rbform->show_only_input || rbform->show_only_output || rbform->show_only_forward)
    {
        rbform->filtered_rules = 0;

        for(d_node = rules->list.top; d_node; d_node = d_node->next)
        {
            if(!(rule_ptr = d_node->data))
            {
                (void)vrprint.error(-1, VR_INTERR, "NULL pointer (in: %s:%d).", __FUNC__, __LINE__);
                return(-1);
            }

            rule_ptr->filtered = 0;
            filter = 0;

            if(rbform->use_filter)
            {
                filter = MatchFilter_RuleBar(rule_ptr, &rbform->filter_reg, rbform->show_only_input,
                                                rbform->show_only_output,
                                                rbform->show_only_forward);
                if(filter == 1)
                    rule_ptr->filtered = 0;
                else
                    rule_ptr->filtered = 1;
            }
            else
            {
                filter = MatchFilter_RuleBar(rule_ptr, NULL, rbform->show_only_input,
                                                rbform->show_only_output,
                                                rbform->show_only_forward);
                if(filter == 1)
                    rule_ptr->filtered = 0;
                else
                    rule_ptr->filtered = 1;
            }
            
            if(rule_ptr->filtered == 1)
            {
                rbform->filtered_rules++;
            }
        }
    }
    else
    {
        rbform->filtered_rules = 0;

        for(d_node = rules->list.top; d_node; d_node = d_node->next)
        {
            if(!(rule_ptr = d_node->data))
            {
                (void)vrprint.error(-1, VR_INTERR, "NULL pointer (in: %s:%d).", __FUNC__, __LINE__);
                return(-1);
            }
            rule_ptr->filtered = 0;
        }
    }

    return(0);
}


/*  rules_form

    Returncodes:
        0: ok
        -1: error
*/
int
rules_form(const int debuglvl, Rules *rules, Zones *zones, Interfaces *interfaces, Services *services, struct rgx_ *reg)
{
    WINDOW              *rules_win;
    PANEL               *panels[1];
    FIELD               **fields;
    FORM                *form;
    int                 rows,
                        cols,
                        ch,
                        quit = 0,
                        x,
                        field_y,
                        field_x,
                        rules_changed=0; /* 1 if rules are changed, 0 if not */
    size_t              n_fields = 0;
    unsigned int        bars = 0,
                        field_bar_num=0,
                        current_bar_num=1,
                        pgdn_offset=0,
                        insert_rule_num = 0,
                        cur_rule_num = 0;
    size_t              i = 0;
                
    struct RuleBarForm_ *rbform;
    rulebar             *cur_bar = NULL;

    int                 max_height = 0,
                        max_width = 0,
                        height = 0,
                        width = 0,
                        startx = 0,
                        starty = 0;


    char                *filter_ptr = NULL,
                        *filter_string_regex = NULL;

    int                 retval = 0,
                        result = 0;
    char                update_filter = 1; /* do it on start*/

    char                *key_choices[] = {  "F12",
                                            "INS",
                                            "DEL",
                                            "RET",
                                            "m",
                                            "f",
                                            "F10"};
    int                 key_choices_n = 7;
    char                *cmd_choices[] = {  gettext("help"),
                                            gettext("new"),
                                            gettext("del"),
                                            gettext("edit"),
                                            gettext("move"),
                                            gettext("filter"),
                                            gettext("back")};
    int                 cmd_choices_n = 7;
    d_list_node         *d_node = NULL;
    struct RuleData_    *rule_ptr = NULL;
    char                *str = NULL;


    /* safety */
    if(rules == NULL || reg == NULL)
    {
        (void)vrprint.error(-1, VR_INTERR, "parameter problem "
            "(in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    // get the dimentions of the screen
    getmaxyx(stdscr, max_height, max_width);

    // set windowsize and start position
    height = max_height-6;
    width = max_width; // = minimum screensize - 2
    startx = 0;
    starty = 3;

    // max bars on the screen
    bars = (unsigned int)(max_height - 10);

    /* Create the window to be associated with the menu */
    if(!(rules_win = create_newwin(height, width, starty, startx, gettext("Rules Section"), (chtype)COLOR_PAIR(CP_WHITE_BLUE))))
    {
        (void)vrprint.error(-1, VR_ERR, gettext("creating window failed."));
        return(-1);
    }
    panels[0] = new_panel(rules_win);
    keypad(rules_win, TRUE);

    /* malloc the rbform struct */
    if(!(rbform = malloc(sizeof(struct RuleBarForm_))))
    {
        (void)vrprint.error(-1, VR_ERR, gettext("malloc failed: %s (in: %s:%d)."), strerror(errno), __FUNC__, __LINE__);
        return(-1);
    }
    /* now set it up */
    if(SetupRuleBarForm(debuglvl, rbform, bars, rules, width-4) < 0)
        return(-1);

    /* create the (more) win+pan */
    if(!(rbform->more_win = newwin(1, 6, starty + height - 1, 2)))
    {
        (void)vrprint.error(-1, VR_ERR, gettext("creating window failed."));
        return(-1);
    }
    wbkgd(rbform->more_win, (chtype)COLOR_PAIR(CP_WHITE_BLUE));
    rbform->more_pan[0] = new_panel(rbform->more_win);
    /* TRANSLATORS: max 4 chars */
    wprintw(rbform->more_win, "(%s)", gettext("more"));
    hide_panel(rbform->more_pan[0]);

    /* calloc and create the fields */
    n_fields = bars * FIELDS_PER_BAR;

    fields = (FIELD **)calloc(n_fields + 1, sizeof(FIELD *));
    if(fields == NULL)
    {
        (void)vrprint.error(-1, VR_ERR, gettext("calloc failed: %s (in: %s:%d)."), strerror(errno), __FUNC__, __LINE__);
        return(-1);
    }

    for(i = 1, field_bar_num = 0, field_y = 2; i <= bars; i++, field_y++)
    {
        for(x = 1, field_x = 0; x <= FIELDS_PER_BAR; x++)
        {
            /* active field */
            if(x == 1)
            {
                fields[field_bar_num] = new_field(1, (int)rbform->active_size, field_y, field_x, 0, 1);
                field_x = field_x + (int)rbform->active_size;
            }
            /* num field */
            else if(x == 2)
            {
                fields[field_bar_num] = new_field(1, (int)rbform->num_field_size, field_y, field_x, 0, 1);
                field_x=field_x + (int)rbform->num_field_size;
            }
            /* action field */
            else if(x == 3)
            {
                fields[field_bar_num] = new_field(1, (int)rbform->action_size, field_y, field_x, 0, 1);
                field_x=field_x + (int)rbform->action_size;
            }
            /* service field */
            else if(x == 4)
            {
                fields[field_bar_num] = new_field(1, (int)rbform->service_size, field_y, field_x, 0, 1);
                field_x=field_x + (int)rbform->service_size;
            }
            /* from field */
            else if(x == 5)
            {
                fields[field_bar_num] = new_field(1, (int)rbform->from_size, field_y, field_x, 0, 1);
                field_x=field_x + (int)rbform->from_size;
            }
            /* to field */
            else if(x == 6)
            {
                fields[field_bar_num] = new_field(1, (int)rbform->to_size, field_y, field_x, 0, 1);
                field_x=field_x + (int)rbform->to_size;
            }
            /* options field */
            else if(x == 7)
            {
                fields[field_bar_num] = new_field(1, (int)rbform->options_size, field_y, field_x, 0, 1);
                field_x=field_x + (int)rbform->options_size;
            }
            else
            {
                fields[field_bar_num] = new_field(1, width - 12, field_y, 8, 0, 1);
                rbform->separator_size = (size_t)(width - 12);
            }

            /* only the first field active */
            if(x > 1)
                field_opts_off(fields[field_bar_num], O_ACTIVE);

            field_bar_num++;
        }

        /* create & insert bar */
        if(Insert_RuleBar(debuglvl, rbform, fields[field_bar_num-x+1], /* active */
                            fields[field_bar_num-x+1+1], /* num */
                            fields[field_bar_num-x+2+1], /* action */
                            fields[field_bar_num-x+3+1], /* service */
                            fields[field_bar_num-x+4+1], /* from */
                            fields[field_bar_num-x+5+1], /* to */
                            fields[field_bar_num-x+6+1], /* options */
                            fields[field_bar_num-x+7+1] /* separator */
                ) < 0)
        {
            (void)vrprint.error(-1, VR_INTERR, "Insert_RuleBar() failed (in: %s:%d).", __FUNC__, __LINE__);
            return(-1);
        }
    }
    fields[n_fields] = NULL;

    /* set field attr */
    for(i = 0; i < (unsigned int)n_fields; i++)
    {
        // set field options
        set_field_back(fields[i], (chtype)COLOR_PAIR(CP_WHITE_BLUE));
        field_opts_off(fields[i], O_AUTOSKIP);
        // set status to false
        set_field_status(fields[i], FALSE);
    }

    // Create the form and post it
    form = new_form(fields);
    // Calculate the area required for the form
    scale_form(form, &rows, &cols);
    // Set main window and sub window
    set_form_win(form, rules_win);
    set_form_sub(form, derwin(rules_win, rows, cols, 1, 2));
    post_form(form);

    /* print labels, must be after the form is posted
    
     this is a bit of a mess, but we need to do it like this because the
     field sizes aren't fixed. */
    wattron(rules_win, (chtype)COLOR_PAIR(CP_WHITE_BLUE) | A_BOLD);
    /* TRANSLATORS: max 3 chars */
    mvwprintw(rules_win, 1, (int)(2+rbform->active_size), gettext("Nr."));
    mvwprintw(rules_win, 1, (int)(2+rbform->num_field_size+rbform->active_size), gettext("Action"));
    mvwprintw(rules_win, 1, (int)(2+rbform->num_field_size+rbform->active_size+rbform->action_size), gettext("Service"));
    mvwprintw(rules_win, 1, (int)(2+rbform->num_field_size+rbform->active_size+rbform->action_size+rbform->service_size), gettext("Source"));
    mvwprintw(rules_win, 1, (int)(2+rbform->num_field_size+rbform->active_size+rbform->action_size+rbform->service_size+rbform->from_size), gettext("Destination"));
    mvwprintw(rules_win, 1, (int)(2+rbform->num_field_size+rbform->active_size+rbform->action_size+rbform->service_size+rbform->from_size+rbform->to_size), gettext("Options"));
    wattroff(rules_win, (chtype)COLOR_PAIR(CP_WHITE_BLUE) | A_BOLD);

    /* horizontal bar below the labels */
    mvwhline(rules_win,  2, 1, ACS_HLINE, width-2);

    draw_top_menu(debuglvl, top_win, gettext("Rules"), key_choices_n, key_choices, cmd_choices_n, cmd_choices);

    update_panels();
    doupdate();
    wrefresh(rules_win);

    status_print(status_win, gettext("Ready."));

    while(quit == 0)
    {
        if(update_filter == 1)
        {
            /* count the number of lines that are filtered */
            (void)rules_update_filter(debuglvl, rules, rbform);

            if(debuglvl >= HIGH)
                (void)vrprint.debug(__FUNC__, "filtered_rules: %d", rbform->filtered_rules);

            update_filter = 0;
        }

        /* calculate the number of printable rules */
        rbform->printable_rules = rules->list.len - rbform->filtered_rules;
        if(debuglvl >= HIGH)
            (void)vrprint.debug(__FUNC__, "printable_rules: %d (current_bar_num: %d)", rbform->printable_rules, current_bar_num);

        /* get current bar num */
        cur_bar = CurrentBar(rbform, form);
        current_bar_num = cur_bar->bar_num;

        if(debuglvl >= HIGH)
            (void)vrprint.debug(__FUNC__, "current_bar_num: %d", current_bar_num);

        /* if we filter, position the bar at the top of the list if needed */
        if( rbform->use_filter ||
            rbform->show_only_forward ||
            rbform->show_only_input ||
            rbform->show_only_output)
        {
            if(debuglvl >= HIGH)
                (void)vrprint.debug(__FUNC__, "see if the bar fits the number of rules");

            if(current_bar_num > rbform->printable_rules)
            {
                if(debuglvl >= HIGH)
                    (void)vrprint.debug(__FUNC__, "no, adjusting");

                Set_RuleBar(debuglvl, rbform, form, rbform->printable_rules);
                rbform->scroll_offset = 0;

                /* we changed the position of the bar */
                cur_bar = CurrentBar(rbform, form);
                current_bar_num = cur_bar->bar_num;
            }
        }

        /*  print the rules
        
            this will also hide or show the (more) panel
        */
        if(draw_rules(debuglvl, rules, rbform) < 0)
            return(-1);

        /* highlight the current bar */
        HighlightRuleBar(cur_bar);

        /* get user input */
        ch = wgetch(rules_win);
        if(debuglvl >= HIGH)
            (void)vrprint.debug(__FUNC__, "user pressed (ch): %d", ch);

        /* now handle it */
        switch(ch)
        {
            /* to the bottom */
            case 360: /* end */
                if(rbform->printable_rules > rbform->max_bars_on_screen)
                {
                    if(debuglvl >= HIGH)
                        (void)vrprint.debug(__FUNC__, "360 (end): rbform->printable_rules > rbform->max_bars_on_screen (%d > %d).", rbform->printable_rules, rbform->max_bars_on_screen);

                    rbform->scroll_offset = rbform->printable_rules - rbform->max_bars_on_screen;
                    Set_RuleBar(debuglvl, rbform, form, rbform->max_bars_on_screen);
                }
                else
                {
                    if(debuglvl >= HIGH)
                        (void)vrprint.debug(__FUNC__, "360 (end): rbform->printable_rules <= rbform->max_bars_on_screen (%d <= %d).", rbform->printable_rules, rbform->max_bars_on_screen);

                    rbform->scroll_offset = 0;
                    Set_RuleBar(debuglvl, rbform, form, rbform->printable_rules);
                }
                break;

            /* to the top */
            case 262: /* home key */
                rbform->scroll_offset = 0;

                Set_RuleBar(debuglvl, rbform, form, 1);
                break;

            /* half a page up */
            case 339: /* page up */
                for(i=0; i < (rbform->max_bars_on_screen); i++)
                {
                    if(current_bar_num > 1)
                    {
                        form_driver(form, REQ_PREV_FIELD);

                        current_bar_num--;
                    }
                    else
                    {
                        if(rbform->scroll_offset > 0)
                            rbform->scroll_offset--;
                    }
                }
                break;

            /* half a page down */
            case 338: /* page down */
                pgdn_offset = 0;

                for(i=0; i < (rbform->max_bars_on_screen); i++)
                {
                    if(debuglvl >= HIGH)
                        (void)vrprint.debug(__FUNC__, "338 (pgdn): current_bar_num : %d, rbform->max_bars_on_screen: %d, rbform->printable_rules: %d, rbform->scroll_offset: %d, atoi(field_buffer(cur_bar->num_field,0)): %d, pgdn_offset: %d.", current_bar_num, rbform->max_bars_on_screen, rbform->printable_rules, rbform->scroll_offset, atoi(field_buffer(cur_bar->num_field,0)), pgdn_offset);

                    /* make sure we dont move to the next field if we:
                        1. scroll
                        2. are at the end of a list that is shorter than the number of bars on screen
                    */
                    if( current_bar_num < rbform->max_bars_on_screen &&
                        ((unsigned int)atoi(field_buffer(cur_bar->num_field,0)) + pgdn_offset) < rbform->printable_rules)
                    {
                        if(debuglvl >= HIGH)
                        {
                            (void)vrprint.debug(__FUNC__, "338 (pgdn): current_bar_num < rbform->max_bars_on_screen (%d < %d).", current_bar_num, rbform->max_bars_on_screen);
                            (void)vrprint.debug(__FUNC__, "338 (pgdn): current_bar_num < printable_rules (%d < %d).", current_bar_num, rbform->printable_rules);
                        }

                        form_driver(form, REQ_NEXT_FIELD);
                        current_bar_num++;

                        pgdn_offset++;
                    }
                    else if(current_bar_num == rbform->printable_rules || current_bar_num + rbform->scroll_offset == rbform->printable_rules)
                    {
                        // just do'in nothin'
                        if(debuglvl >= HIGH)
                        {
                            (void)vrprint.debug(__FUNC__, "338 (pgdn): current_bar_num == rbform->printable_rules (%d == %d), OR", current_bar_num, rbform->printable_rules);
                            (void)vrprint.debug(__FUNC__, "338 (pgdn): atoi(field_buffer(cur_bar->num_field,0)) + pgdn_offset == rbform->printable_rules (%d + %d == %d).", atoi(field_buffer(cur_bar->num_field,0)), pgdn_offset, rbform->printable_rules);
                        }
                    }
                    else
                    {
                        if(debuglvl >= HIGH)
                            (void)vrprint.debug(__FUNC__, "338 (pgdn): rbform->scroll_offset: %d.", rbform->scroll_offset);

                        rbform->scroll_offset++;
                    }
                }

                break;

            /* one up */
            case KEY_UP:
                if(current_bar_num > 1)
                    form_driver(form, REQ_PREV_FIELD);
                else
                {
                    if(rbform->scroll_offset > 0)
                        rbform->scroll_offset--;
                }

                form_driver(form, REQ_BEG_LINE);
                break;

            /* one down */
            case KEY_DOWN:
                /* make sure we dont move to the next field if we:
                    1. scroll
                    2. are at the end of a list that is shorter than the number of bars on screen
                */
                if(current_bar_num < rbform->max_bars_on_screen && current_bar_num < rbform->printable_rules)
                {
                    if(debuglvl >= HIGH)
                    {
                        (void)vrprint.debug(__FUNC__, "KEY_DOWN: current_bar_num < rbform->max_bars_on_screen (%d < %d).", current_bar_num, rbform->max_bars_on_screen);
                        (void)vrprint.debug(__FUNC__, "KEY_DOWN: current_bar_num < printable_rules (%d < %d).", current_bar_num, rbform->printable_rules);
                    }

                    form_driver(form, REQ_NEXT_FIELD);
                }
                else if(current_bar_num == rbform->printable_rules ||
                    (unsigned int)atoi(field_buffer(cur_bar->num_field,0)) == rbform->printable_rules)
                {
                    /* do nothing, just sit here */
                    if(debuglvl >= HIGH)
                    {
                        (void)vrprint.debug(__FUNC__, "KEY_DOWN: current_bar_num == printable_rules (%d == %d), OR", current_bar_num, rbform->printable_rules);
                        (void)vrprint.debug(__FUNC__, "KEY_DOWN: atoi(field_buffer(cur_bar->num_field,0)) == rbform->printable_rules (%d == %d)", atoi(field_buffer(cur_bar->num_field,0)), rbform->printable_rules);
                    }
                }
                else
                {
                    if(debuglvl >= HIGH)
                    {
                        (void)vrprint.debug(__FUNC__, "KEY_DOWN: current_bar_num >= rbform->max_bars_on_screen (%d >= %d).", current_bar_num, rbform->max_bars_on_screen);
                        (void)vrprint.debug(__FUNC__, "KEY_DOWN: current_bar_num >= printable_rules (%d >= %d).", current_bar_num, rbform->printable_rules);
                    }

                    rbform->scroll_offset++;
                }

                form_driver(form, REQ_BEG_LINE);
                break;

            case 32: /* spacebar */

                cur_rule_num = (unsigned int)atoi(field_buffer(cur_bar->num_field, 0));
                if(cur_rule_num > 0)
                {
                    Toggle_RuleBar(debuglvl, cur_bar, rules);
                    rules_changed = 1;
                }
                break;

            /* edit the rule */
            case 10: /* enter key */
            case KEY_RIGHT:
            case 'e':
            case 'E':

                result = Enter_RuleBar(debuglvl, cur_bar, rules, zones, interfaces, services, reg);
                if(result == 1)
                {
                    rules_changed = 1;
                    update_filter = 1;
                }
                /* we have removed the rule from the list, so now we need to make sure that
                   the screen is updated properly */
                else if(result == -1)
                {
                    /* we removed an existing rule, so the rules are changed */
                    rules_changed = 1;
                    update_filter = 1;

                    /*  if we remove the last rule in a none scrolling list make sure the bar is set to
                        the last rule, otherwise we can scroll of the screen */
                    if(current_bar_num > rbform->printable_rules - 1)
                    {
                        if(debuglvl >= HIGH)
                            (void)vrprint.debug(__FUNC__, "edit: current_bar_num > printable_rules - 1 (%d > %d).", current_bar_num, rbform->printable_rules - 1);
                        
                        form_driver(form, REQ_PREV_FIELD);
                    }
                    else
                    {
                        if(debuglvl >= HIGH)
                            (void)vrprint.debug(__FUNC__, "edit: current_bar_num <= printable_rules - 1 (%d <= %d).", current_bar_num, rbform->printable_rules - 1);
                    }
                }

                draw_top_menu(debuglvl, top_win, gettext("Rules"), key_choices_n, key_choices, cmd_choices_n, cmd_choices);
                break;

            case KEY_DC: /* delete key */
            case 'd':
            case 'D':

                /* delete the rule */
                cur_rule_num = (unsigned int)atoi(field_buffer(cur_bar->num_field, 0));
                if(cur_rule_num > 0)
                {
                    result = delete_rule(debuglvl, rules, cur_rule_num, 1);
                    if(result == 0)
                        status_print(status_win, gettext("Delete rule cancelled."));
                    else if(result == 1)
                    {
                        (void)vrprint.info(VR_INFO, gettext("rule %d removed."), atoi(field_buffer(cur_bar->num_field, 0)));

                        rules_changed = 1;
                        update_filter = 1;

                        /* decrease the scroll_offset so we don't scroll of the list */
                        if(rbform->scroll_offset > 0)
                        {
                            if(debuglvl >= HIGH)
                            {
                                (void)vrprint.debug(__FUNC__, "KEY_DC: scroll_offset > 0 (%d) decreasing.", rbform->scroll_offset);
                            }
                            rbform->scroll_offset--;
                        }
                        else
                        {
                            if(debuglvl >= HIGH)
                            {
                                (void)vrprint.debug(__FUNC__, "KEY_DC: scroll_offset <= 0 (%d) doing nothing.", rbform->scroll_offset);
                            }
                        }

                        /*  if we remove the last rule in a none scrolling list make sure the bar is set to
                            the last rule */
                        if(current_bar_num > rbform->printable_rules - 1)
                        {
                            if(debuglvl >= HIGH)
                            {
                                (void)vrprint.debug(__FUNC__, "KEY_DC: current_bar_num > printable_rules - 1 (%d > %d).", current_bar_num, rbform->printable_rules - 1);
                            }
                            form_driver(form, REQ_PREV_FIELD);
                        }
                        else
                        {
                            if(debuglvl >= HIGH)
                                (void)vrprint.debug(__FUNC__, "KEY_DC: current_bar_num <= printable_rules - 1 (%d <= %d).", current_bar_num, rbform->printable_rules - 1);
                        }
                    }
                    /* oops... error */
                    else
                    {
                        retval = -1;
                        quit = 1;
                    }
                }

                break;

            /* insert separator line */
            case 'l':
            case 'L':

                /* insert a new rule into the list */
                insert_rule_num = (unsigned int)atoi(field_buffer(cur_bar->num_field, 0));
                if(insert_rule_num == 0)
                    insert_rule_num = 1;

                (void)insert_new_rule(debuglvl, rules, insert_rule_num, "Separator");

                rules_changed = 1;
                update_filter = 1;

                break;

            /* insert a new rule */
            case KEY_IC: /* insert key */
            case 'i':
            case 'I':

                /* insert a new rule into the list */
                insert_rule_num = (unsigned int)atoi(field_buffer(cur_bar->num_field, 0));
                if(insert_rule_num == 0)
                    insert_rule_num = 1;

                if(insert_new_rule(debuglvl, rules, insert_rule_num, "Drop") >= 0)
                {
                    /* now edit the rule */
                    if(edit_rule(debuglvl, rules, zones, interfaces, services, insert_rule_num, reg) < 0)
                    {
                        /* editting failed so remove the rule again */
                        if(rules_remove_rule_from_list(debuglvl, rules, insert_rule_num, 1) < 0)
                        {
                            (void)vrprint.error(-1, VR_INTERR, "removing rule failed (in: %s:%d).", __FUNC__, __LINE__);
                            return(-1);
                        }
                    }
                    else
                    {
                        /* if editting the rule was successful, we have a changed ruleset. */
                        rules_changed = 1;
                        update_filter = 1;
                    }

                    draw_top_menu(debuglvl, top_win, gettext("Rules"), key_choices_n, key_choices, cmd_choices_n, cmd_choices);
                }

                break;

            /* copy (duplicate) rule */
            case 'c':
            case 'C':

                cur_rule_num = (unsigned int)atoi(field_buffer(cur_bar->num_field, 0));
                if(cur_rule_num > 0)
                {
                    result = rulebar_copy_rule(debuglvl, rules, cur_rule_num, reg);
                    if(result == 0)
                    {
                        rules_changed = 1;
                        update_filter = 1;
                    }
                }

                break;

            /* move a rule */
            case 'm':
            case 'M':

                cur_rule_num = (unsigned int)atoi(field_buffer(cur_bar->num_field, 0));
                if(cur_rule_num > 0)
                {
                    if(MoveRuleBarForm(debuglvl, rbform, rules, cur_rule_num) < 0)
                        return(-1);

                    rules_changed = 1;
                    update_filter = 1;

                    status_print(status_win, gettext("Ready."));
                }
                break;

            /* move a rule one up */
            case '-':

                cur_rule_num = (unsigned int)atoi(field_buffer(cur_bar->num_field, 0));
                if(cur_rule_num > 1)
                {
                    result = move_rule(debuglvl, rules, cur_rule_num, cur_rule_num - 1);
                    if(result == 0)
                    {
//                        (void)vrprint.debug(__FUNC__, "rule moved. Now set bar to new position (%d).", cur_rule_num - 1);

                        /* moving succeeded, now focus on the moved rule */
//                        Set_RuleBar(rbform, form, cur_rule_num - 1);
                        if(current_bar_num > 1)
                            form_driver(form, REQ_PREV_FIELD);
                        else
                        {
                            if(rbform->scroll_offset > 0)
                                rbform->scroll_offset--;
                        }

                        form_driver(form, REQ_BEG_LINE);
                    }

                    rules_changed = 1;
                    update_filter = 1;

                    status_print(status_win, gettext("Ready."));
                }
                break;

            /* move a rule one down */
            case '+':

                cur_rule_num = (unsigned int)atoi(field_buffer(cur_bar->num_field, 0));
                if(cur_rule_num < rules->list.len)
                {
                    result = move_rule(debuglvl, rules, cur_rule_num, cur_rule_num + 1);
                    if(result == 0)
                    {
                        /* make sure we dont move to the next field if we:
                            1. scroll
                            2. are at the end of a list that is shorter than the number of bars on screen
                        */
                        if( current_bar_num < rbform->max_bars_on_screen &&
                            current_bar_num < rbform->printable_rules)
                        {
                            form_driver(form, REQ_NEXT_FIELD);
                        }
                        else if(current_bar_num == rbform->printable_rules ||
                            (unsigned int)(atoi(field_buffer(cur_bar->num_field,0))) == rbform->printable_rules)
                        {
                            /* do nothing, just sit here */
                        }
                        else
                        {
                            rbform->scroll_offset++;
                        }

                        form_driver(form, REQ_BEG_LINE);
                    }

                    rules_changed = 1;
                    update_filter = 1;

                    status_print(status_win, "Ready.");
                }
                break;

            /* filter */
            case 'f':
            case 'F':

                if((filter_ptr = input_box(32, gettext("Set the filter"), gettext("Enter filter (leave empty for no filter)"))))
                {
                    /* first clear the old regex (if we have one) */
                    if(rbform->use_filter == 1)
                    {
                        regfree(&rbform->filter_reg);
                    }

                    /* first construct the regex string */
                    if(!(filter_string_regex = malloc(sizeof(filter_ptr)+1+4)))
                        return(-1);
                    snprintf(filter_string_regex, (sizeof(filter_ptr)+1+4), ".*%s.*", filter_ptr);

                    rbform->use_filter = 1;

                    /* compiling the regex */
                    if(regcomp(&rbform->filter_reg, filter_string_regex, REG_EXTENDED) != 0)
                    {
                        (void)vrprint.error(-1, VR_INTERR, "Setting up the regular expression with regcomp failed. Disabling filter.");
                        rbform->use_filter = 0;
                    }

                    status_print(status_win, gettext("Active filter: '%s' (press 'f' and then just 'enter' to clear)."), filter_ptr);

                    free(filter_ptr);
                    filter_ptr = NULL;
                    free(filter_string_regex);
                }
                else
                {
                    /* if a filter was in place, clear regex */
                    if(rbform->use_filter == 1)
                    {
                        /* clear regex */
                        regfree(&rbform->filter_reg);
                    }
                    rbform->use_filter = 0;

                    status_print(status_win, gettext("Filter removed."));
                }

                update_filter = 1;

                break;

            /* quit */
            case 27:
            case KEY_F(10):
            case 'q':
            case 'Q':

                quit = 1;
                break;

            case 'o':
            case 'O':

                if(rbform->show_only_forward == 0)
                {
                    rbform->show_only_forward = 1;
                    rbform->show_only_input   = 0;
                    rbform->show_only_output  = 0;
                }
                else
                    rbform->show_only_forward = 0;

                update_filter = 1;

                status_print(status_win, "%s", rbform->show_only_forward ? gettext("Showing only forward rules.") : 
                                                gettext("Showing all rules."));
                break;

            case 'n':
            case 'N':

                if(rbform->show_only_input == 0)
                {
                    rbform->show_only_forward = 0;
                    rbform->show_only_input   = 1;
                    rbform->show_only_output  = 0;
                }
                else
                    rbform->show_only_input   = 0;

                update_filter = 1;

                status_print(status_win, "%s", rbform->show_only_input ? gettext("Showing only input rules.") : 
                                                gettext("Showing all rules."));
                break;

            case 'u':
            case 'U':

                if(rbform->show_only_output == 0)
                {
                    rbform->show_only_forward = 0;
                    rbform->show_only_input   = 0;
                    rbform->show_only_output  = 1;
                }
                else
                    rbform->show_only_output  = 0;

                update_filter = 1;

                status_print(status_win, "%s", rbform->show_only_output ? gettext("Showing only output rules.") : 
                                                gettext("Showing all rules."));
                break;

            case KEY_F(12):
            case 'h':
            case 'H':
            case '?':

                print_help(debuglvl, ":[VUURMUUR:RULES]:");
                break;
        }
    }

    /* if the rules are changed, save the changes. But only if retval != -1. */
    if(rules_changed && retval != -1)
    {
        if(rules_save_list(debuglvl, rules, &conf) < 0)
        {
            (void)vrprint.error(-1, VR_ERR, gettext("saving rules failed."));
            retval = -1;
        }

        if(retval == 0)
        {
            /* audit log */
            (void)vrprint.audit("%s: %s: %d (%s).",
                    STR_RULES_ARE_CHANGED, STR_NUMBER_OF_RULES,
                    rules->list.len, STR_LISTED_BELOW);

            for(i = 1, d_node = rules->list.top; d_node; d_node = d_node->next, i++)
            {
                rule_ptr = d_node->data;

                if(rule_ptr->action == AT_SEPARATOR)
                {
                    if(rule_ptr->opt != NULL && rule_ptr->opt->comment[0] != '\0')
                        (void)vrprint.audit("%2d: === %s ===",
                                    i, rule_ptr->opt->comment);
                    else
                        (void)vrprint.audit("%2d: ===", i);
                }
                else
                {
                    str = rules_assemble_rule(debuglvl, rule_ptr);
                    if(str[StrMemLen(str)-1] == '\n')
                        str[StrMemLen(str)-1] = '\0';
                    (void)vrprint.audit("%2d: %s", i, str);
                    free(str);
                }
        }

        }
    }

    del_panel(rbform->more_pan[0]);
    destroy_win(rbform->more_win);

    d_list_cleanup(debuglvl, &rbform->RuleBar_list);
    free(rbform);

    unpost_form(form);
    free_form(form);

    for(i = 0; i < n_fields; i++)
    {
        free_field(fields[i]);
    }
    free(fields);

    del_panel(panels[0]);
    delwin(rules_win);

    return(retval);
}


int
delete_rule(const int debuglvl, Rules *rules, unsigned int rule_num,
        int call_confirm)
{
    int                 remove_rule=0;
    int                 result = 0;
    int                 retval = 0;
    struct RuleData_    *rule_ptr = NULL;
    d_list_node         *d_node = NULL;

    if(call_confirm == 1)
    {
        /* first ask the user to confirm */
        result = confirm(gettext("Delete rule"), gettext("Are you sure?"), (chtype)COLOR_PAIR(CP_RED_WHITE), (chtype)COLOR_PAIR(CP_WHITE_RED)|A_BOLD, 0);
        if(result == 1)
            remove_rule = 1;
        else
            remove_rule = 0;
    }
    else
        remove_rule = 1;

    if(remove_rule == 1)
    {
        for(d_node = rules->list.top; d_node ; d_node = d_node->next)
        {
            if(!(rule_ptr = d_node->data))
            {
                (void)vrprint.error(-1, VR_INTERR, "NULL pointer (in: %s:%d).", __FUNC__, __LINE__);
                return(-1);
            }

            if(rule_ptr->number == rule_num)
                break;
        }

        /* editting failed so remove the rule again */
        if(rules_remove_rule_from_list(debuglvl, rules, rule_num, 1) < 0)
        {
            (void)vrprint.error(-1, VR_INTERR, "removing rule failed (in: %s:%d).", __FUNC__, __LINE__);
            return(-1);
        }

        free_options(debuglvl, rule_ptr->opt);
        rule_ptr->opt = NULL;
        free(rule_ptr);
        rule_ptr = NULL;

        retval = 1;
    }
                
        if(debuglvl >= LOW)
        rules_print_list(rules);
                  
    return(retval);
}


//
int
insert_new_rule(const int debuglvl, Rules *rules, unsigned int rule_num,
            const char *action)
{
    int                 retval = 0;
    struct RuleData_    *rule_ptr = NULL;

    /* safety */
    if(rules == NULL)
    {
        (void)vrprint.error(-1, VR_INTERR, "parameter problem (in: %s:%d).",
                                __FUNC__, __LINE__);
        return(-1);
    }

    if(debuglvl >= LOW)
        (void)vrprint.debug(__FUNC__, "rule_num: %d", rule_num);

    /* inserting into an empty rules list */
    if(rule_num == 0)
        rule_num = 1;

    /* claim memory */
    if(!(rule_ptr = rule_malloc()))
        return(-1);

    /* set rule to standard */
    rule_ptr->action = rules_actiontoi(action);
    strcpy(rule_ptr->service, "");
    strcpy(rule_ptr->from, "");
    strcpy(rule_ptr->to, "");
    rule_ptr->active = 1;
    
    /* only setup the options if we are going to change one or more */
    if(vccnf.newrule_log || vccnf.newrule_loglimit)
    {
        if(!(rule_ptr->opt = ruleoption_malloc(debuglvl)))
        {
            free(rule_ptr);
            return(-1);
        }

        /* default log and limit the log */
        rule_ptr->opt->rule_log = vccnf.newrule_log;
        rule_ptr->opt->loglimit = vccnf.newrule_loglimit;
        rule_ptr->opt->logburst = vccnf.newrule_logburst;
    }

    /* set the rule number */
    rule_ptr->number = rule_num;

    /* handle the rules list is empty */
    if(rules->list.len == 0)
    {
        /* insert at 1 of course */
        rule_ptr->number = 1;

        if(debuglvl >= HIGH)
            (void)vrprint.debug(__FUNC__, "rule_num: %d, rule_ptr->number: %d", rule_num, rule_ptr->number);

        if(rules_insert_list(debuglvl, rules, rule_ptr->number, rule_ptr) < 0)
        {
            (void)vrprint.error(-1, VR_INTERR, "failed to insert in list (in: %s:%d).", __FUNC__, __LINE__);
            retval = -1;
        }
    }
    /* handle in a non-empty list */
    else
    {
        if(rules_insert_list(debuglvl, rules, rule_num, rule_ptr) < 0)
        {
            (void)vrprint.error(-1, VR_INTERR, "failed to insert in list (in: %s:%d).", __FUNC__, __LINE__);
            retval=-1;
        }
    }


    if(debuglvl >= LOW)
        rules_print_list(rules);


    if(retval == 0)
        (void)vrprint.info(VR_INFO, gettext("new rule inserted."));

    return(retval);
}


// returns 0: no change, or 1: change
int
edit_rule(const int debuglvl, Rules *rules, Zones *zones,
        Interfaces *interfaces, Services *services,
        unsigned int rule_num, struct rgx_ *reg)
{
    struct RuleData_    *rule_ptr = NULL;
    d_list_node         *d_node = NULL;
    int                 retval = 0;

    /* safety */
    if(!reg || !interfaces)
    {
        (void)vrprint.error(-1, VR_INTERR, "parameter problem (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }
    
    if(debuglvl >= HIGH)
        (void)vrprint.debug(__FUNC__, "called with rule_num = %d", rule_num);

    if(rule_num == 0)
        rule_num = 1;

    if(rules->list.len == 0)
    {
        (void)vrprint.error(-1, VR_INTERR, "list is empty (in: %s)", __FUNC__);
        return(-1);
    }
    
    /* go to rulenum in the rules list to get the rule_ptr */
    if(!(d_node = rules->list.top))
    {
        (void)vrprint.error(-1, VR_INTERR, "NULL pointer (in: %s)", __FUNC__);
        return(-1);
    }

    /* look for the rule_ptr */
    for(; d_node; d_node = d_node->next)
    {
        if(!(rule_ptr = d_node->data))
        {
            (void)vrprint.error(-1, VR_INTERR, "NULL pointer (in: %s:%d)", __FUNC__, __LINE__);
            return(-1);
        }

        if(rule_ptr->number == rule_num)
            break;
    }

    if(rule_ptr != NULL)
    {
        if(rule_ptr->action == AT_PROTECT)
        {
            (void)vrprint.error(-1, VR_INTERR, "edit_rule can no longer be used for editting protect rules (in: %s:%d).", __FUNC__, __LINE__);
            return(-1);
        }
        else if(rule_ptr->action == AT_SEPARATOR)
        {
            retval = edit_rule_separator(debuglvl, zones, interfaces, services, rule_ptr, rule_num, reg);
        }
        else
        {
            retval = edit_rule_normal(debuglvl, zones, interfaces, services, rule_ptr, rule_num, reg);
        }
    }
    else
    {
        (void)vrprint.error(-1, VR_INTERR, "rule not found (in: %s:%d).", __FUNC__, __LINE__);
        retval = -1;
    }

    if(debuglvl >= HIGH)
        (void)vrprint.debug(__FUNC__, "returning retval = %d.", retval);

    return(retval);
}


struct RuleFlds_
{
    FIELD   *action_label_fld_ptr,
            *action_fld_ptr,

            *queue_label_fld_ptr,
            *queue_brackets_fld_ptr,
            *queue_fld_ptr,

            *random_label_fld_ptr,
            *random_brackets_fld_ptr,
            *random_fld_ptr,

            *service_label_fld_ptr,
            *service_fld_ptr,
            *fromzone_label_fld_ptr,
            *fromzone_fld_ptr,
            *tozone_label_fld_ptr,
            *tozone_fld_ptr,

            *log_label_fld_ptr,
            *log_brackets_fld_ptr,
            *log_fld_ptr,

            *logprefix_label_fld_ptr,
            *logprefix_fld_ptr,

            *loglimit_label_fld_ptr,
            *loglimit_fld_ptr,

            *limit_label_fld_ptr,
            *limit_fld_ptr,

            *limit_unit_label_fld_ptr,
            *limit_unit_fld_ptr,

            *burst_label_fld_ptr,
            *burst_fld_ptr,

            *in_int_label_fld_ptr,
            *in_int_fld_ptr,

            *out_int_label_fld_ptr,
            *out_int_fld_ptr,

            *via_int_label_fld_ptr,
            *via_int_fld_ptr,

            *reject_label_fld_ptr,
            *reject_fld_ptr,

            *redirect_label_fld_ptr,
            *redirect_fld_ptr,
            *listen_label_fld_ptr,
            *listen_fld_ptr,
            *remote_label_fld_ptr,
            *remote_fld_ptr,

            *nfqueuenum_label_fld_ptr,
            *nfqueuenum_fld_ptr,

            *nfmark_label_fld_ptr,
            *nfmark_fld_ptr,

            *chain_label_fld_ptr,
            *chain_fld_ptr,

            *comment_label_fld_ptr,
            *comment_fld_ptr;
} RuleFlds;


/*  edit_rule_fields_to_rule

    Returncodes:
         1: changes stored
         0: no changes
        -1: error
*/
static int
edit_rule_fields_to_rule(const int debuglvl, FIELD **fields, size_t n_fields, struct RuleData_ *rule_ptr, struct rgx_ *reg)
{
    int     z = 0,
            retval = 0;
    char    port_one[6] = "",
            nfmarkstr[9] = "";
    char    limit_str[6] = "";
    char    nfqueuenum_str[6] = "";
    int     last_char = 0;
    char    action_str[32] = "";
    size_t  i = 0;
        

    if(!fields || !rule_ptr || !reg)
    {
        (void)vrprint.error(-1, VR_INTERR, "parameter problem (in: %s:%d).",
                                __FUNC__, __LINE__);
        return(-1);
    }

    /* check for changed fields */
    for(i = 0; i < n_fields; i++)
    {
        if(field_status(fields[i]) == TRUE)
        {
            if(fields[i] == RuleFlds.action_fld_ptr)
            {
                /* action */
                if(!(copy_field2buf(action_str,
                                    field_buffer(fields[i], 0),
                                    sizeof(action_str))))
                    return(-1);

                rule_ptr->action = rules_actiontoi(action_str);

                retval = 1;
            }
            else if(fields[i] == RuleFlds.service_fld_ptr)
            {
                /* service */
                if(!(copy_field2buf(rule_ptr->service,
                                    field_buffer(fields[i], 0),
                                    sizeof(rule_ptr->service))))
                    return(-1);

                retval = 1;
            }
            else if(fields[i] == RuleFlds.fromzone_fld_ptr)
            {
                /* from */
                if(!(copy_field2buf(rule_ptr->from,
                                    field_buffer(fields[i], 0),
                                    sizeof(rule_ptr->from))))
                    return(-1);

                retval = 1;
            }
            else if(fields[i] == RuleFlds.tozone_fld_ptr)
            {
                /* to */
                if(!(copy_field2buf(rule_ptr->to,
                                    field_buffer(fields[i], 0),
                                    sizeof(rule_ptr->to))))
                    return(-1);

                retval = 1;
            }
            else if(fields[i] == RuleFlds.reject_fld_ptr)
            {
                /* option rejecttype */
                if(rule_ptr->opt == NULL)
                {
                    if(!(rule_ptr->opt = ruleoption_malloc(debuglvl)))
                    {
                        (void)vrprint.error(-1, VR_ERR, gettext("malloc failed: %s (in: %s:%d)."), strerror(errno), __FUNCTION__, __LINE__);
                        return(-1);
                    }
                }

                if(!(copy_field2buf(rule_ptr->opt->reject_type,
                                    field_buffer(fields[i], 0),
                                    sizeof(rule_ptr->opt->reject_type))))
                    return(-1);

                if(strcmp(rule_ptr->opt->reject_type, "") == 0)
                    rule_ptr->opt->reject_option = 0;
                else
                    rule_ptr->opt->reject_option = 1;

                retval = 1;
            }
            else if(fields[i] == RuleFlds.redirect_fld_ptr)
            {
                /* option redirect port */
                if(rule_ptr->opt == NULL)
                {
                    if(!(rule_ptr->opt = ruleoption_malloc(debuglvl)))
                    {
                        (void)vrprint.error(-1, VR_ERR, gettext("malloc failed: %s (in: %s:%d)."), strerror(errno), __FUNCTION__, __LINE__);
                        return(-1);
                    }
                }

                if(!(copy_field2buf(port_one,
                                    field_buffer(fields[i], 0),
                                    sizeof(port_one))))
                    return(-1);

                rule_ptr->opt->redirectport = atoi(port_one);
                if(rule_ptr->opt->redirectport <= 0 || rule_ptr->opt->redirectport > 65535)
                {
                    /* TRANSLATORS: don't translate 'redirectport'. */
                    (void)vrprint.warning(VR_WARN, gettext("redirectport must be 1-65535."));
                    rule_ptr->opt->redirectport = 0;
                }

                retval = 1;
            }
            else if(fields[i] == RuleFlds.nfmark_fld_ptr)
            {
                /* option redirect port */
                if(rule_ptr->opt == NULL)
                {
                    if(!(rule_ptr->opt = ruleoption_malloc(debuglvl)))
                    {
                        (void)vrprint.error(-1, VR_ERR, gettext("malloc failed: %s (in: %s:%d)."), strerror(errno), __FUNCTION__, __LINE__);
                        return(-1);
                    }
                }

                if(!(copy_field2buf(nfmarkstr,
                                    field_buffer(fields[i], 0),
                                    sizeof(nfmarkstr))))
                    return(-1);

                rule_ptr->opt->nfmark = strtoul(nfmarkstr, (char **)NULL, 10);

                retval = 1;
            }
            else if(fields[i] == RuleFlds.listen_fld_ptr)
            {
                if(rule_ptr->opt == NULL)
                {
                    if(!(rule_ptr->opt = ruleoption_malloc(debuglvl)))
                    {
                        (void)vrprint.error(-1, VR_ERR, gettext("malloc failed: %s (in: %s:%d)."), strerror(errno), __FUNCTION__, __LINE__);
                        return(-1);
                    }
                }

                /* first clear the list */
                if(rule_ptr->opt->listenport == 1 && rule_ptr->opt->ListenportList.len > 0)
                    d_list_cleanup(debuglvl, &rule_ptr->opt->ListenportList);

                /* if the first char is a whitespace, we asume the field is empty */
                if(field_buffer(fields[i], 0)[0] == ' ')
                {
                    rule_ptr->opt->listenport = 0;
                }
                else
                {
                    /* add the ports to the list */
                    if(portopts_to_list(debuglvl, field_buffer(fields[i], 0), &rule_ptr->opt->ListenportList) < 0)
                        rule_ptr->opt->listenport = 0;
                    else
                    {
                        if(rule_ptr->opt->ListenportList.len == 0)
                            rule_ptr->opt->listenport = 0;
                        else
                            rule_ptr->opt->listenport = 1;
                    }
                }

                retval=1;
            }
            else if(fields[i] == RuleFlds.remote_fld_ptr)
            {
                if(rule_ptr->opt == NULL)
                {
                    if(!(rule_ptr->opt = ruleoption_malloc(debuglvl)))
                    {
                        (void)vrprint.error(-1, VR_ERR, gettext("malloc failed: %s (in: %s:%d)."), strerror(errno), __FUNCTION__, __LINE__);
                        return(-1);
                    }
                }

                /* first clear the list */
                if(rule_ptr->opt->remoteport == 1 && rule_ptr->opt->RemoteportList.len > 0)
                    d_list_cleanup(debuglvl, &rule_ptr->opt->RemoteportList);

                /* if the first char is a whitespace, we asume the field is empty */
                if(field_buffer(fields[i], 0)[0] == ' ')
                {
                    rule_ptr->opt->remoteport = 0;
                }
                else
                {
                    /* add the ports to the list */
                    if(portopts_to_list(debuglvl, field_buffer(fields[i], 0), &rule_ptr->opt->RemoteportList) < 0)
                        rule_ptr->opt->remoteport = 0;
                    else
                    {
                        if(rule_ptr->opt->RemoteportList.len == 0)
                            rule_ptr->opt->remoteport = 0;
                        else
                            rule_ptr->opt->remoteport = 1;
                    }
                }

                retval=1;
            }
            else if(fields[i] == RuleFlds.logprefix_fld_ptr)
            {
                if( StrLen(field_buffer(fields[i], 0)) !=
                    StrMemLen(field_buffer(fields[i], 0)))
                {
                    (void)vrprint.warning(VR_WARN, "%s",
                        STR_ONLY_ASCII_ALLOWED_IN_PREFIX);
                }
                else
                {
                    /* options */
                    if(rule_ptr->opt == NULL)
                    {
                        if(!(rule_ptr->opt = ruleoption_malloc(debuglvl)))
                        {
                            (void)vrprint.error(-1, VR_ERR, gettext("malloc failed: %s (in: %s:%d)."), strerror(errno), __FUNCTION__, __LINE__);
                            return(-1);
                        }
                    }

                    for(last_char = 0, z = 0; z < 12; z++) /* 12 is max prefix length */
                    {
                        rule_ptr->opt->logprefix[z] = field_buffer(fields[i], 0)[z];

                        /* make sure that we place the NULL after the last char: no trailing spaces. */
                        if(rule_ptr->opt->logprefix[z] != ' ')
                            last_char = z+1;
                    }
                    rule_ptr->opt->logprefix[last_char] = '\0';

                    if(strcmp(rule_ptr->opt->logprefix, "") == 0)
                        rule_ptr->opt->rule_logprefix = 0;
                    else
                        rule_ptr->opt->rule_logprefix = 1;

                    retval = 1;
                }
            }
            else if(fields[i] == RuleFlds.comment_fld_ptr)
            {
                /* first check if the commentfield is valid */
                if(validate_commentfield(debuglvl, field_buffer(fields[i], 0), reg->comment) == 0)
                {
                    /* options */
                    if(rule_ptr->opt == NULL)
                    {
                        if(!(rule_ptr->opt = ruleoption_malloc(debuglvl)))
                        {
                            (void)vrprint.error(-1, VR_ERR, gettext("malloc failed: %s (in: %s:%d)."), strerror(errno), __FUNCTION__, __LINE__);
                            return(-1);
                        }
                    }

                    for(last_char = 0, z = 0;
                        z < (int)sizeof(rule_ptr->opt->comment) &&
                            field_buffer(fields[i], 0)[z] != '\0';
                        z++) /* 12 is max prefix length */
                    {
                        rule_ptr->opt->comment[z] = field_buffer(fields[i], 0)[z];
                        if(rule_ptr->opt->comment[z] == '\n')
                            rule_ptr->opt->comment[z] = ' ';

                        /* make sure that we place the NULL after the last char: no trailing spaces. */
                        if(rule_ptr->opt->comment[z] != ' ')
                            last_char = z + 1;
                    }
                    rule_ptr->opt->comment[last_char] = '\0';

                    if(strcmp(rule_ptr->opt->comment, "") == 0)
                        rule_ptr->opt->rule_comment = 0;
                    else
                        rule_ptr->opt->rule_comment = 1;

                    retval = 1;
                }
            }
            else if(fields[i] == RuleFlds.loglimit_fld_ptr)
            {
                /* option redirect port */
                if(rule_ptr->opt == NULL)
                {
                    if(!(rule_ptr->opt = ruleoption_malloc(debuglvl)))
                    {
                        (void)vrprint.error(-1, VR_ERR, gettext("malloc failed: %s (in: %s:%d)."), strerror(errno), __FUNCTION__, __LINE__);
                        return(-1);
                    }
                }

                if(!(copy_field2buf(limit_str,
                                    field_buffer(fields[i], 0),
                                    sizeof(limit_str))))
                    return(-1);

                rule_ptr->opt->loglimit = (unsigned int)atoi(limit_str);
                if(rule_ptr->opt->loglimit > 999)
                {
                    /* TRANSLATORS: don't translate 'loglimit'. */
                    (void)vrprint.warning(VR_WARN, gettext("loglimit must be 0-999."));
                    rule_ptr->opt->loglimit = 0;
                }

                retval = 1;
            }
            else if(fields[i] == RuleFlds.log_fld_ptr)
            {
                /* log */
                if(rule_ptr->opt == NULL)
                {
                    if(!(rule_ptr->opt = ruleoption_malloc(debuglvl)))
                    {
                        (void)vrprint.error(-1, VR_ERR, gettext("malloc failed: %s (in: %s:%d)."), strerror(errno), __FUNCTION__, __LINE__);
                        return(-1);
                    }
                }

                if(strncmp(field_buffer(fields[i], 0), "X", 1) == 0)
                    rule_ptr->opt->rule_log = 1;
                else
                    rule_ptr->opt->rule_log = 0;

                retval=1;
            }
            else if(fields[i] == RuleFlds.nfqueuenum_fld_ptr)
            {
                /* nfqueuenum */

                /* if needed alloc the opt struct */
                if(rule_ptr->opt == NULL)
                {
                    if(!(rule_ptr->opt = ruleoption_malloc(debuglvl)))
                    {
                        (void)vrprint.error(-1, VR_ERR, gettext("malloc failed: %s (in: %s:%d)."), strerror(errno), __FUNCTION__, __LINE__);
                        return(-1);
                    }
                }

                if(!(copy_field2buf(nfqueuenum_str,
                                    field_buffer(fields[i], 0),
                                    sizeof(nfqueuenum_str))))
                    return(-1);

                rule_ptr->opt->nfqueue_num = atoi(nfqueuenum_str);

                retval=1;
            }
            else if(fields[i] == RuleFlds.queue_fld_ptr)
            {
                /* queue */

                /* if needed alloc the opt struct */
                if(rule_ptr->opt == NULL)
                {
                    if(!(rule_ptr->opt = ruleoption_malloc(debuglvl)))
                    {
                        (void)vrprint.error(-1, VR_ERR, gettext("malloc failed: %s (in: %s:%d)."), strerror(errno), __FUNCTION__, __LINE__);
                        return(-1);
                    }
                }

                if(strncmp(field_buffer(fields[i], 0), "X", 1) == 0)
                    rule_ptr->opt->queue = 1;
                else
                    rule_ptr->opt->queue = 0;

                retval=1;
            }
            else if(fields[i] == RuleFlds.random_fld_ptr)
            {
                /* random */

                /* if needed alloc the opt struct */
                if(rule_ptr->opt == NULL)
                {
                    if(!(rule_ptr->opt = ruleoption_malloc(debuglvl)))
                    {
                        (void)vrprint.error(-1, VR_ERR, gettext("malloc failed: %s (in: %s:%d)."), strerror(errno), __FUNCTION__, __LINE__);
                        return(-1);
                    }
                }

                if(strncmp(field_buffer(fields[i], 0), "X", 1) == 0)
                    rule_ptr->opt->random = 1;
                else
                    rule_ptr->opt->random = 0;

                retval=1;
            }
            else if(fields[i] == RuleFlds.in_int_fld_ptr)
            {
                /* option interface */
                if(rule_ptr->opt == NULL)
                {
                    if(!(rule_ptr->opt = ruleoption_malloc(debuglvl)))
                    {
                        (void)vrprint.error(-1, VR_ERR, gettext("malloc failed: %s (in: %s:%d)."),
                                            strerror(errno), __FUNC__, __LINE__);
                        return(-1);
                    }
                }

                if(!(copy_field2buf(rule_ptr->opt->in_int,
                                    field_buffer(fields[i], 0),
                                    sizeof(rule_ptr->opt->in_int))))
                    return(-1);

                retval = 1;
            }
            else if(fields[i] == RuleFlds.out_int_fld_ptr)
            {
                /* option interface */
                if(rule_ptr->opt == NULL)
                {
                    if(!(rule_ptr->opt = ruleoption_malloc(debuglvl)))
                    {
                        (void)vrprint.error(-1, VR_ERR, gettext("malloc failed: %s (in: %s:%d)."),
                                            strerror(errno), __FUNC__, __LINE__);
                        return(-1);
                    }
                }

                if(!(copy_field2buf(rule_ptr->opt->out_int,
                                    field_buffer(fields[i], 0),
                                    sizeof(rule_ptr->opt->out_int))))
                    return(-1);

                retval = 1;
            }
            else if(fields[i] == RuleFlds.via_int_fld_ptr)
            {
                /* option interface */
                if(rule_ptr->opt == NULL)
                {
                    if(!(rule_ptr->opt = ruleoption_malloc(debuglvl)))
                    {
                        (void)vrprint.error(-1, VR_ERR, gettext("malloc failed: %s (in: %s:%d)."),
                                            strerror(errno), __FUNC__, __LINE__);
                        return(-1);
                    }
                }

                if(!(copy_field2buf(rule_ptr->opt->via_int,
                                    field_buffer(fields[i], 0),
                                    sizeof(rule_ptr->opt->via_int))))
                    return(-1);

                retval = 1;
            }
            else if(fields[i] == RuleFlds.chain_fld_ptr)
            {
                /* option interface */
                if(rule_ptr->opt == NULL)
                {
                    if(!(rule_ptr->opt = ruleoption_malloc(debuglvl)))
                    {
                        (void)vrprint.error(-1, VR_ERR, gettext("malloc failed: %s (in: %s:%d)."), strerror(errno), __FUNCTION__, __LINE__);
                        return(-1);
                    }
                }

                if(!(copy_field2buf(rule_ptr->opt->chain,
                                    field_buffer(fields[i], 0),
                                    sizeof(rule_ptr->opt->chain))))
                    return(-1);

                retval = 1;
            }
            else if(fields[i] == RuleFlds.limit_fld_ptr)
            {
                if(rule_ptr->opt == NULL)
                {
                    if(!(rule_ptr->opt = ruleoption_malloc(debuglvl)))
                    {
                        (void)vrprint.error(-1, VR_ERR, gettext("malloc failed: %s (in: %s:%d)."), strerror(errno), __FUNCTION__, __LINE__);
                        return(-1);
                    }
                }

                if(!(copy_field2buf(limit_str,
                                    field_buffer(fields[i], 0),
                                    sizeof(limit_str))))
                    return(-1);

                rule_ptr->opt->limit = (unsigned int)atoi(limit_str);
                if(rule_ptr->opt->limit > 9999)
                {
                    (void)vrprint.warning(VR_WARN, gettext("new connection limit must be 0-9999."));
                    rule_ptr->opt->limit = 0;
                }

                retval = 1;
            }
            else if(fields[i] == RuleFlds.limit_unit_fld_ptr)
            {
                if(rule_ptr->opt == NULL)
                {
                    if(!(rule_ptr->opt = ruleoption_malloc(debuglvl)))
                    {
                        (void)vrprint.error(-1, VR_ERR, gettext("malloc failed: %s (in: %s:%d)."), strerror(errno), __FUNCTION__, __LINE__);
                        return(-1);
                    }
                }

                if(!(copy_field2buf(rule_ptr->opt->limit_unit,
                                    field_buffer(fields[i], 0),
                                    sizeof(rule_ptr->opt->limit_unit))))
                    return(-1);

                retval = 1;
            }
            else if(fields[i] == RuleFlds.burst_fld_ptr)
            {
                if(rule_ptr->opt == NULL)
                {
                    if(!(rule_ptr->opt = ruleoption_malloc(debuglvl)))
                    {
                        (void)vrprint.error(-1, VR_ERR, gettext("malloc failed: %s (in: %s:%d)."), strerror(errno), __FUNCTION__, __LINE__);
                        return(-1);
                    }
                }

                if(!(copy_field2buf(limit_str,
                                    field_buffer(fields[i], 0),
                                    sizeof(limit_str))))
                    return(-1);

                rule_ptr->opt->burst = (unsigned int)atoi(limit_str);
                if(rule_ptr->opt->burst > 9999 || rule_ptr->opt->burst == 0)
                {
                    (void)vrprint.warning(VR_WARN, gettext("new connection limit burst must be 1-9999."));
                    rule_ptr->opt->burst = 0;
                }

                retval = 1;
            }
        }  
    }

    if(debuglvl >= LOW)
        (void)vrprint.debug(__FUNC__, "returning retval = %d.", retval);

    return(retval);
}


static int
edit_rule_simple_check(const int debuglvl, struct RuleData_ *rule_ptr)
{
    if( rule_ptr->service[0] == '\0' ||
        rule_ptr->from[0] == '\0' ||
        rule_ptr->to[0] == '\0')
    {
        return(0);
    }

    return(1);
}


static int
edit_rule_check_action_opts(const int debuglvl, struct RuleData_ *rule_ptr)
{
    if(rule_ptr->action == AT_BOUNCE)
    {
        if(rule_ptr->opt == NULL || rule_ptr->opt->via_int[0] == '\0')
        {
            (void)vrprint.warning(VR_WARN, STR_BOUNCE_REQUIRES_VIA_OPT);
            return(0);
        }
    }
    else if(rule_ptr->action == AT_REDIRECT)
    {
        if(rule_ptr->opt == NULL || rule_ptr->opt->redirectport == 0)
        {
            (void)vrprint.warning(VR_WARN, STR_REDIRECT_REQUIRES_OPT);
            return(0);
        }
    }


    return(1);
}


/*  edit_rule_normal

    Returncodes:
         0: ok, no changes
         1: ok, changes
        -1: error

    TODO: split this beast up
*/
int
edit_rule_normal(const int debuglvl, Zones *zones, Interfaces *interfaces,
            Services *services, struct RuleData_ *rule_ptr,
            unsigned int rule_num, struct rgx_ *reg)
{
    PANEL       *my_panels[1];
    WINDOW      *edit_win;
    FIELD       **fields,
                *cur = NULL,
                *prev = NULL;

    FORM        *form;
    int         ch,
                rows,
                cols,
                retval=0,
                quit=0,
                not_defined=0;
    size_t      field_num = 0, 
                n_fields = 0,
                i = 0;
    char        redirect_port[6]   = "",
                loglimit_string[4] = "",
                nfmark_string[9] = "",
                nfqueuenum_string[6] = "0";
    int         height,
                width,
                startx,
                starty,
                max_height,
                max_width;
    char        *action_choices[] = {   "Accept",
                                        "Drop",
                                        "Reject",
                                        "Log",
                                        "Portfw",
                                        "Redirect",
                                        "Snat",
                                        "Masq",
                                        "Dnat",
                                        "Queue",
                                        "NFQueue",
                                        "Chain",
                                        "Bounce", },
                *action_ptr=NULL,
                *reject_types[] = { "icmp-net-unreachable",
                                    "icmp-host-unreachable",
                                    "icmp-proto-unreachable",
                                    "icmp-port-unreachable",
                                    "icmp-net-prohibited",
                                    "icmp-host-prohibited",
                                    "tcp-reset" },
                *reject_ptr=NULL;
    char        select_choice[MAX_HOST_NET_ZONE] = "";
    size_t      action_choices_n = 13,
                reject_types_n = 7;
    char        **zone_choices,
                **choices,
                *choice_ptr,
                **service_choices;
    size_t      zone_choices_n=0,
                service_choices_n=0,
                n_choices = 0;
    d_list_node             *d_node = NULL;
    struct ZoneData_        *zone_ptr = NULL,
                            *network_ptr = NULL;
    struct ServicesData_    *service_ptr = NULL;
    struct InterfaceData_   *iface_ptr = NULL;
    
    int                     result = 0;
    struct RuleCache_       tmp_ruledata;
    char                    window_title[32] = "";

    char        *key_choices[] =    {   "F12",
                                        "F5",
                                        "F6",
                                        "F10"};
    int         key_choices_n = 4;
    char        *cmd_choices[] =    {   gettext("help"),
                                        gettext("advanced"),
                                        gettext("shaping"),
                                        gettext("back")};
    int         cmd_choices_n = 4;

    /* is this screen in advanced mode or not? */
    char        advanced_mode = vccnf.advanced_mode;
    char        zonename[MAX_HOST_NET_ZONE] = "";

    d_list      *interfaces_list = NULL;

    /* safety */
    if(rule_ptr == NULL || reg == NULL)
    {
        (void)vrprint.error(-1, VR_INTERR, "parameter problem (in: %s:%d).",
                                __FUNC__, __LINE__);
        return(-1);
    }

    /* clear tmp_ruledata for the initial */
    memset(&tmp_ruledata, 0, sizeof(tmp_ruledata));
    memset(&RuleFlds, 0, sizeof(struct RuleFlds_));

    /* set to keep first */
    rule_ptr->status = ST_CHANGED;

    /* get the dimentions of the screen */
    getmaxyx(stdscr, max_height, max_width);

    /* set windowsize and start position */
    height = 20;
    width  = 78; /* = minimum screensize - 2 */
    startx = 1;
    if(max_height > 24)
        starty = 3;
    else
        starty = 2;

    /* set number of fields */
    n_fields = 49;
    if(!(fields = (FIELD **)calloc(n_fields + 1, sizeof(FIELD *))))
    {
        (void)vrprint.error(-1, VR_ERR, gettext("calloc failed: %s (in: %s:%d)."), strerror(errno), __FUNCTION__, __LINE__);
        return(-1);
    }

    /*
        create the fields
    */

    /* action label */
    RuleFlds.action_label_fld_ptr = (fields[field_num] = new_field(1, 8, 1, 1, 0, 0));
    set_field_buffer_wrap(debuglvl, RuleFlds.action_label_fld_ptr, 0, gettext("Action"));
    field_opts_off(RuleFlds.action_label_fld_ptr, O_ACTIVE);
    set_field_back(RuleFlds.action_label_fld_ptr, (chtype)COLOR_PAIR(CP_BLUE_WHITE));
    set_field_fore(RuleFlds.action_label_fld_ptr, (chtype)COLOR_PAIR(CP_BLUE_WHITE));
    field_num++;

    /* action */
    RuleFlds.action_fld_ptr = (fields[field_num] = new_field(1, 16, 1, 10, 0, 0));
    set_field_buffer_wrap(debuglvl, RuleFlds.action_fld_ptr, 0, rules_itoaction(rule_ptr->action));
    set_field_back(RuleFlds.action_fld_ptr, (chtype)COLOR_PAIR(CP_WHITE_BLUE));
    set_field_fore(RuleFlds.action_fld_ptr, (chtype)COLOR_PAIR(CP_WHITE_BLUE)|A_BOLD);
    field_num++;

    /* random */
    RuleFlds.random_label_fld_ptr = (fields[field_num] = new_field(1, 7, 3, 10, 0, 0));
    /* TRANSLATORS: max 7 chars */
    set_field_buffer_wrap(debuglvl, RuleFlds.random_label_fld_ptr, 0, gettext("Random"));
    field_opts_off(RuleFlds.random_label_fld_ptr, O_ACTIVE);
    set_field_back(RuleFlds.random_label_fld_ptr, (chtype)COLOR_PAIR(CP_BLUE_WHITE));
    set_field_fore(RuleFlds.random_label_fld_ptr, (chtype)COLOR_PAIR(CP_BLUE_WHITE));
    field_num++;

    RuleFlds.random_brackets_fld_ptr = (fields[field_num] = new_field(1, 3, 3, 17, 0, 0));
    set_field_buffer_wrap(debuglvl, RuleFlds.random_brackets_fld_ptr, 0, "[ ]");
    field_opts_off(RuleFlds.random_brackets_fld_ptr, O_ACTIVE);
    set_field_back(RuleFlds.random_brackets_fld_ptr, (chtype)COLOR_PAIR(CP_BLUE_WHITE));
    set_field_fore(RuleFlds.random_brackets_fld_ptr, (chtype)COLOR_PAIR(CP_BLUE_WHITE));
    field_num++;

    /* random toggle */
    RuleFlds.random_fld_ptr = (fields[field_num] = new_field(1, 1, 3, 18, 0, 0));
    set_field_back(RuleFlds.random_fld_ptr, (chtype)COLOR_PAIR(CP_BLUE_WHITE));
    set_field_fore(RuleFlds.random_fld_ptr, (chtype)COLOR_PAIR(CP_BLUE_WHITE));
    field_num++;

    /* enable */
    if(rule_ptr->opt != NULL && rule_ptr->opt->random == 1)
        set_field_buffer_wrap(debuglvl, RuleFlds.random_fld_ptr, 0, "X");

    /* queue starts disabled */
    field_opts_off(RuleFlds.random_fld_ptr, O_VISIBLE);
    field_opts_off(RuleFlds.random_label_fld_ptr, O_VISIBLE);
    field_opts_off(RuleFlds.random_brackets_fld_ptr, O_VISIBLE);


    /* portfw/redirect queue label */
    /* TRANSLATORS: max 7 chars */
    RuleFlds.queue_label_fld_ptr = (fields[field_num] = new_field(1, 7, 5, 10, 0, 0));
    set_field_buffer_wrap(debuglvl, RuleFlds.queue_label_fld_ptr, 0, gettext("Queue"));
    field_opts_off(RuleFlds.queue_label_fld_ptr, O_ACTIVE);
    set_field_back(RuleFlds.queue_label_fld_ptr, (chtype)COLOR_PAIR(CP_BLUE_WHITE));
    set_field_fore(RuleFlds.queue_label_fld_ptr, (chtype)COLOR_PAIR(CP_BLUE_WHITE));
    field_num++;

    RuleFlds.queue_brackets_fld_ptr = (fields[field_num] = new_field(1, 3, 5, 17, 0, 0));
    set_field_buffer_wrap(debuglvl, RuleFlds.queue_brackets_fld_ptr, 0, "[ ]");
    field_opts_off(RuleFlds.queue_brackets_fld_ptr, O_ACTIVE);
    set_field_back(RuleFlds.queue_brackets_fld_ptr, (chtype)COLOR_PAIR(CP_BLUE_WHITE));
    set_field_fore(RuleFlds.queue_brackets_fld_ptr, (chtype)COLOR_PAIR(CP_BLUE_WHITE));
    field_num++;

    /* portfw/redirect queue */
    RuleFlds.queue_fld_ptr = (fields[field_num] = new_field(1, 1, 5, 18, 0, 0));
    set_field_back(RuleFlds.queue_fld_ptr, (chtype)COLOR_PAIR(CP_BLUE_WHITE));
    set_field_fore(RuleFlds.queue_fld_ptr, (chtype)COLOR_PAIR(CP_BLUE_WHITE));
    field_num++;

    /* enable */
    if(rule_ptr->opt != NULL && rule_ptr->opt->queue == 1)
        set_field_buffer_wrap(debuglvl, RuleFlds.queue_fld_ptr, 0, "X");

    /* queue starts disabled */
    field_opts_off(RuleFlds.queue_fld_ptr, O_VISIBLE);
    field_opts_off(RuleFlds.queue_label_fld_ptr, O_VISIBLE);
    field_opts_off(RuleFlds.queue_brackets_fld_ptr, O_VISIBLE);


    /* nfqueuenum label */
    RuleFlds.nfqueuenum_label_fld_ptr = (fields[field_num] = new_field(1, 18, 5, 10, 0, 0));
    set_field_buffer_wrap(debuglvl, RuleFlds.nfqueuenum_label_fld_ptr, 0, gettext("Queue number"));
    field_opts_off(RuleFlds.nfqueuenum_label_fld_ptr, O_ACTIVE);
    set_field_back(RuleFlds.nfqueuenum_label_fld_ptr, (chtype)COLOR_PAIR(CP_BLUE_WHITE));
    set_field_fore(RuleFlds.nfqueuenum_label_fld_ptr, (chtype)COLOR_PAIR(CP_BLUE_WHITE));
    field_num++;

    /* nfqueuenum */
    RuleFlds.nfqueuenum_fld_ptr = (fields[field_num] = new_field(1, 6, 5, 30, 0, 0));
    set_field_back(RuleFlds.nfqueuenum_fld_ptr, (chtype)COLOR_PAIR(CP_WHITE_BLUE));
    set_field_fore(RuleFlds.nfqueuenum_fld_ptr, (chtype)COLOR_PAIR(CP_WHITE_BLUE)|A_BOLD);
    field_num++;

    /* enable nfqueuenum option */
    if(rule_ptr->opt != NULL)
        snprintf(nfqueuenum_string, sizeof(nfqueuenum_string), "%u", rule_ptr->opt->nfqueue_num);

    set_field_buffer_wrap(debuglvl, RuleFlds.nfqueuenum_fld_ptr, 0, nfqueuenum_string);

    /* start disabled  */
    field_opts_off(RuleFlds.nfqueuenum_fld_ptr, O_VISIBLE);
    field_opts_off(RuleFlds.nfqueuenum_label_fld_ptr, O_VISIBLE);


    /* service label */
    RuleFlds.service_label_fld_ptr = (fields[field_num] = new_field(1, 8, 7, 1, 0, 0));
    set_field_buffer_wrap(debuglvl, RuleFlds.service_label_fld_ptr, 0, gettext("Service"));
    field_opts_off(RuleFlds.service_label_fld_ptr, O_ACTIVE);
    set_field_back(RuleFlds.service_label_fld_ptr, (chtype)COLOR_PAIR(CP_BLUE_WHITE));
    set_field_fore(RuleFlds.service_label_fld_ptr, (chtype)COLOR_PAIR(CP_BLUE_WHITE));
    field_num++;

    /* service */
    RuleFlds.service_fld_ptr = (fields[field_num] = new_field(1, 32, 7, 10, 0, 0));
    set_field_buffer_wrap(debuglvl, RuleFlds.service_fld_ptr, 0, rule_ptr->service);
    set_field_back(RuleFlds.service_fld_ptr, (chtype)COLOR_PAIR(CP_WHITE_BLUE));
    set_field_fore(RuleFlds.service_fld_ptr, (chtype)COLOR_PAIR(CP_WHITE_BLUE)|A_BOLD);
    field_num++;


    /* nfmark label */
    RuleFlds.nfmark_label_fld_ptr = (fields[field_num] = new_field(1, 7, 9, 10, 0, 0));
    /* TRANSLATORS: max 7 chars */
    set_field_buffer_wrap(debuglvl, RuleFlds.nfmark_label_fld_ptr, 0, gettext("Mark"));
    field_opts_off(RuleFlds.nfmark_label_fld_ptr, O_ACTIVE);
    set_field_back(RuleFlds.nfmark_label_fld_ptr, (chtype)COLOR_PAIR(CP_BLUE_WHITE));
    set_field_fore(RuleFlds.nfmark_label_fld_ptr, (chtype)COLOR_PAIR(CP_BLUE_WHITE));
    field_num++;

    RuleFlds.nfmark_fld_ptr = (fields[field_num] = new_field(1, 8, 9, 19, 0, 0));
    set_field_back(RuleFlds.nfmark_fld_ptr, (chtype)COLOR_PAIR(CP_WHITE_BLUE));
    set_field_fore(RuleFlds.nfmark_fld_ptr, (chtype)COLOR_PAIR(CP_WHITE_BLUE)|A_BOLD);
    field_num++;

    /* enable nfmark option */
    if(rule_ptr->opt != NULL && rule_ptr->opt->nfmark > 0)
    {
        snprintf(nfmark_string, sizeof(nfmark_string), "%lu", rule_ptr->opt->nfmark);
        set_field_buffer_wrap(debuglvl, RuleFlds.nfmark_fld_ptr, 0, nfmark_string);
    }

    /* start disabled  */
    field_opts_off(RuleFlds.nfmark_fld_ptr, O_VISIBLE);
    field_opts_off(RuleFlds.nfmark_label_fld_ptr, O_VISIBLE);


    /* from zone label */
    RuleFlds.fromzone_label_fld_ptr = (fields[field_num] = new_field(1, 8, 11, 1, 0, 0));
    set_field_buffer_wrap(debuglvl, RuleFlds.fromzone_label_fld_ptr, 0, gettext("From"));
    field_opts_off(RuleFlds.fromzone_label_fld_ptr, O_ACTIVE);
    set_field_back(RuleFlds.fromzone_label_fld_ptr, (chtype)COLOR_PAIR(CP_BLUE_WHITE));
    set_field_fore(RuleFlds.fromzone_label_fld_ptr, (chtype)COLOR_PAIR(CP_BLUE_WHITE));
    field_num++;

    /* from zone */
    RuleFlds.fromzone_fld_ptr = (fields[field_num] = new_field(1, 48, 11, 10, 0, 0));
    set_field_buffer_wrap(debuglvl, RuleFlds.fromzone_fld_ptr, 0, rule_ptr->from);
    set_field_back(RuleFlds.fromzone_fld_ptr, (chtype)COLOR_PAIR(CP_WHITE_BLUE));
    set_field_fore(RuleFlds.fromzone_fld_ptr, (chtype)COLOR_PAIR(CP_WHITE_BLUE)|A_BOLD);
    field_num++;


    /* in_int interface label */
    RuleFlds.in_int_label_fld_ptr = (fields[field_num] = new_field(1, 24, 12, 10, 0, 0));
    set_field_buffer_wrap(debuglvl, RuleFlds.in_int_label_fld_ptr, 0, gettext("Listen Interface"));
    field_opts_off(RuleFlds.in_int_label_fld_ptr, O_ACTIVE);
    set_field_back(RuleFlds.in_int_label_fld_ptr, (chtype)COLOR_PAIR(CP_BLUE_WHITE));
    set_field_fore(RuleFlds.in_int_label_fld_ptr, (chtype)COLOR_PAIR(CP_BLUE_WHITE));
    field_num++;

    /* in_int interface */
    RuleFlds.in_int_fld_ptr = (fields[field_num] = new_field(1, MAX_INTERFACE, 12, 36, 0, 0));
    if(rule_ptr->opt != NULL)
        set_field_buffer_wrap(debuglvl, RuleFlds.in_int_fld_ptr, 0, rule_ptr->opt->in_int);

    set_field_back(RuleFlds.in_int_fld_ptr, (chtype)COLOR_PAIR(CP_WHITE_RED));
    set_field_fore(RuleFlds.in_int_fld_ptr, (chtype)COLOR_PAIR(CP_WHITE_RED)|A_BOLD);
    field_num++;

    /* in_int interface starts disabled */
    field_opts_off(RuleFlds.in_int_label_fld_ptr, O_VISIBLE);
    field_opts_off(RuleFlds.in_int_fld_ptr, O_VISIBLE);


    /* to zone label */
    RuleFlds.tozone_label_fld_ptr = (fields[field_num] = new_field(1, 8, 14, 1, 0, 0));
    set_field_buffer_wrap(debuglvl, RuleFlds.tozone_label_fld_ptr, 0, gettext("To"));
    field_opts_off(RuleFlds.tozone_label_fld_ptr, O_ACTIVE);
    set_field_back(RuleFlds.tozone_label_fld_ptr, (chtype)COLOR_PAIR(CP_BLUE_WHITE));
    set_field_fore(RuleFlds.tozone_label_fld_ptr, (chtype)COLOR_PAIR(CP_BLUE_WHITE));
    field_num++;

    /* to zone */
    RuleFlds.tozone_fld_ptr = (fields[field_num] = new_field(1, 48, 14, 10, 0, 0));
    set_field_buffer_wrap(debuglvl, RuleFlds.tozone_fld_ptr, 0, rule_ptr->to);
    set_field_back(RuleFlds.tozone_fld_ptr, (chtype)COLOR_PAIR(CP_WHITE_BLUE));
    set_field_fore(RuleFlds.tozone_fld_ptr, (chtype)COLOR_PAIR(CP_WHITE_BLUE)|A_BOLD);
    field_num++;


    /* out_int interface label */
    RuleFlds.out_int_label_fld_ptr = (fields[field_num] = new_field(1, 24, 15, 10, 0, 0));
    set_field_buffer_wrap(debuglvl, RuleFlds.out_int_label_fld_ptr, 0, gettext("Outgoing Interface"));
    field_opts_off(RuleFlds.out_int_label_fld_ptr, O_ACTIVE);
    set_field_back(RuleFlds.out_int_label_fld_ptr, (chtype)COLOR_PAIR(CP_BLUE_WHITE));
    set_field_fore(RuleFlds.out_int_label_fld_ptr, (chtype)COLOR_PAIR(CP_BLUE_WHITE));
    field_num++;

    /* out_int interface */
    RuleFlds.out_int_fld_ptr = (fields[field_num] = new_field(1, MAX_INTERFACE, 15, 36, 0, 0));
    if(rule_ptr->opt != NULL)
        set_field_buffer_wrap(debuglvl, RuleFlds.out_int_fld_ptr, 0, rule_ptr->opt->out_int);

    set_field_back(RuleFlds.out_int_fld_ptr, (chtype)COLOR_PAIR(CP_WHITE_RED));
    set_field_fore(RuleFlds.out_int_fld_ptr, (chtype)COLOR_PAIR(CP_WHITE_RED)|A_BOLD);
    field_num++;

    /* out_int interface starts disabled */
    field_opts_off(RuleFlds.out_int_label_fld_ptr, O_VISIBLE);
    field_opts_off(RuleFlds.out_int_fld_ptr, O_VISIBLE);


    /* comment label */
    /* TRANSLATORS: max 7 chars */
    RuleFlds.comment_label_fld_ptr = (fields[field_num] = new_field(1, 8, 17, 1, 0, 0));
    set_field_buffer_wrap(debuglvl, RuleFlds.comment_label_fld_ptr, 0, gettext("Comment"));
    field_opts_off(RuleFlds.comment_label_fld_ptr, O_ACTIVE);
    set_field_back(RuleFlds.comment_label_fld_ptr, (chtype)COLOR_PAIR(CP_BLUE_WHITE));
    set_field_fore(RuleFlds.comment_label_fld_ptr, (chtype)COLOR_PAIR(CP_BLUE_WHITE));
    field_num++;

    /* comment */
    RuleFlds.comment_fld_ptr = (fields[field_num] = new_field(1, 63, 17, 10, 0, 0));
    if(rule_ptr->opt != NULL && rule_ptr->opt->rule_comment == 1)
        set_field_buffer_wrap(debuglvl, RuleFlds.comment_fld_ptr, 0, rule_ptr->opt->comment);
    set_field_back(RuleFlds.comment_fld_ptr, (chtype)COLOR_PAIR(CP_WHITE_BLUE));
    set_field_fore(RuleFlds.comment_fld_ptr, (chtype)COLOR_PAIR(CP_WHITE_BLUE)|A_BOLD);
    field_num++;


    /* log label */
    /* TRANSLATORS: max 4 chars */
    RuleFlds.log_label_fld_ptr = (fields[field_num] = new_field(1, 4, 1, 29, 0, 0));
    set_field_buffer_wrap(debuglvl, RuleFlds.log_label_fld_ptr, 0, gettext("Log"));
    field_opts_off(RuleFlds.log_label_fld_ptr, O_ACTIVE);
    set_field_back(RuleFlds.log_label_fld_ptr, (chtype)COLOR_PAIR(CP_BLUE_WHITE));
    set_field_fore(RuleFlds.log_label_fld_ptr, (chtype)COLOR_PAIR(CP_BLUE_WHITE));
    field_num++;

    RuleFlds.log_brackets_fld_ptr = (fields[field_num] = new_field(1, 3, 1, 34, 0, 0));
    set_field_buffer_wrap(debuglvl, RuleFlds.log_brackets_fld_ptr, 0, "[ ]");
    field_opts_off(RuleFlds.log_brackets_fld_ptr, O_ACTIVE);
    set_field_back(RuleFlds.log_brackets_fld_ptr, (chtype)COLOR_PAIR(CP_BLUE_WHITE));
    set_field_fore(RuleFlds.log_brackets_fld_ptr, (chtype)COLOR_PAIR(CP_BLUE_WHITE));
    field_num++;

    /* log */
    RuleFlds.log_fld_ptr = (fields[field_num] = new_field(1, 1, 1, 35, 0, 0));

    /* enable */
    if(rule_ptr->opt != NULL && rule_ptr->opt->rule_log == 1)
        set_field_buffer_wrap(debuglvl, RuleFlds.log_fld_ptr, 0, "X");

    set_field_back(RuleFlds.log_fld_ptr, (chtype)COLOR_PAIR(CP_BLUE_WHITE));
    set_field_fore(RuleFlds.log_fld_ptr, (chtype)COLOR_PAIR(CP_BLUE_WHITE));
    field_num++;


    /* log prefix label */
    /* TRANSLATORS: max 7 chars */
    RuleFlds.logprefix_label_fld_ptr = (fields[field_num] = new_field(1, 8, 1, 39, 0, 0));
    set_field_buffer_wrap(debuglvl, RuleFlds.logprefix_label_fld_ptr, 0, gettext("Prefix"));
    field_opts_off(RuleFlds.logprefix_label_fld_ptr, O_ACTIVE);
    set_field_back(RuleFlds.logprefix_label_fld_ptr, (chtype)COLOR_PAIR(CP_BLUE_WHITE));
    set_field_fore(RuleFlds.logprefix_label_fld_ptr, (chtype)COLOR_PAIR(CP_BLUE_WHITE));
    field_num++;

    /* log prefix */
    RuleFlds.logprefix_fld_ptr = (fields[field_num] = new_field(1, 12, 1, 48, 0, 0));
    if(rule_ptr->opt != NULL)
        set_field_buffer_wrap(debuglvl, RuleFlds.logprefix_fld_ptr, 0, rule_ptr->opt->logprefix);
    set_field_back(RuleFlds.logprefix_fld_ptr, (chtype)COLOR_PAIR(CP_WHITE_BLUE));
    set_field_fore(RuleFlds.logprefix_fld_ptr, (chtype)COLOR_PAIR(CP_WHITE_BLUE)|A_BOLD);
    field_num++;

    /* limit label */
    /* TRANSLATORS: max 6 chars */
    RuleFlds.loglimit_label_fld_ptr = (fields[field_num] = new_field(1, 8, 1, 62, 0, 0));
    set_field_buffer_wrap(debuglvl, RuleFlds.loglimit_label_fld_ptr, 0, gettext("Limit"));
    field_opts_off(RuleFlds.loglimit_label_fld_ptr, O_ACTIVE);
    set_field_back(RuleFlds.loglimit_label_fld_ptr, (chtype)COLOR_PAIR(CP_BLUE_WHITE));
    set_field_fore(RuleFlds.loglimit_label_fld_ptr, (chtype)COLOR_PAIR(CP_BLUE_WHITE));
    field_num++;

    /* limit */
    RuleFlds.loglimit_fld_ptr = (fields[field_num] = new_field(1, 3, 1, 70, 0, 0));
    if(rule_ptr->opt != NULL)
    {
        if(rule_ptr->opt->loglimit > 0)
        {
            snprintf(loglimit_string, sizeof(loglimit_string), "%u", rule_ptr->opt->loglimit);
            set_field_buffer_wrap(debuglvl, RuleFlds.loglimit_fld_ptr, 0, loglimit_string);
        }
    }
    set_field_back(RuleFlds.loglimit_fld_ptr, (chtype)COLOR_PAIR(CP_WHITE_BLUE));
    set_field_fore(RuleFlds.loglimit_fld_ptr, (chtype)COLOR_PAIR(CP_WHITE_BLUE)|A_BOLD);
    field_num++;


    /* log prefix label */
    /* TRANSLATORS: max 7 chars */
    RuleFlds.limit_label_fld_ptr = (fields[field_num] = new_field(1, 12, 3, 29, 0, 0));
    set_field_buffer_wrap(debuglvl, RuleFlds.limit_label_fld_ptr, 0, gettext("Rule Limit"));
    field_opts_off(RuleFlds.limit_label_fld_ptr, O_ACTIVE);
    set_field_back(RuleFlds.limit_label_fld_ptr, (chtype)COLOR_PAIR(CP_BLUE_WHITE));
    set_field_fore(RuleFlds.limit_label_fld_ptr, (chtype)COLOR_PAIR(CP_BLUE_WHITE));
    field_num++;

    /* log prefix */
    RuleFlds.limit_fld_ptr = (fields[field_num] = new_field(1, 4, 3, 42, 0, 0));
    if(rule_ptr->opt != NULL)
    {
        if(rule_ptr->opt->limit > 0)
        {
            snprintf(loglimit_string, sizeof(loglimit_string), "%u", rule_ptr->opt->limit);
            set_field_buffer_wrap(debuglvl, RuleFlds.limit_fld_ptr, 0, loglimit_string);
        }
    }
    set_field_back(RuleFlds.limit_fld_ptr, (chtype)COLOR_PAIR(CP_WHITE_BLUE));
    set_field_fore(RuleFlds.limit_fld_ptr, (chtype)COLOR_PAIR(CP_WHITE_BLUE)|A_BOLD);
    field_num++;

    /* start disabled and set the field to dynamic */
    field_opts_off(RuleFlds.limit_fld_ptr, O_VISIBLE|O_STATIC);
    field_opts_off(RuleFlds.limit_label_fld_ptr, O_VISIBLE);

    /* Limit Unit Label */
    RuleFlds.limit_unit_label_fld_ptr = (fields[field_num] = new_field(1, 1, 3, 48, 0, 0));
    set_field_buffer_wrap(debuglvl, RuleFlds.limit_unit_label_fld_ptr, 0, "/");
    field_opts_off(RuleFlds.limit_unit_label_fld_ptr, O_ACTIVE);
    set_field_back(RuleFlds.limit_unit_label_fld_ptr, (chtype)COLOR_PAIR(CP_BLUE_WHITE));
    set_field_fore(RuleFlds.limit_unit_label_fld_ptr, (chtype)COLOR_PAIR(CP_BLUE_WHITE));
    field_num++;

    /* Limit Unit  */
    RuleFlds.limit_unit_fld_ptr = (fields[field_num] = new_field(1, 4, 3, 51, 0, 0));
    if(rule_ptr->opt != NULL)
    {
        set_field_buffer_wrap(debuglvl, RuleFlds.limit_unit_fld_ptr, 0,
            rule_ptr->opt->limit_unit);
    }
    set_field_back(RuleFlds.limit_unit_fld_ptr, (chtype)COLOR_PAIR(CP_WHITE_BLUE));
    set_field_fore(RuleFlds.limit_unit_fld_ptr, (chtype)COLOR_PAIR(CP_WHITE_BLUE)|A_BOLD);
    field_num++;

    /* start disabled and set the field to dynamic */
    field_opts_off(RuleFlds.limit_fld_ptr, O_VISIBLE|O_STATIC);
    field_opts_off(RuleFlds.limit_label_fld_ptr, O_VISIBLE);

    /* burst label */
    /* TRANSLATORS: max 6 chars */
    RuleFlds.burst_label_fld_ptr = (fields[field_num] = new_field(1, 8, 3, 60, 0, 0));
    set_field_buffer_wrap(debuglvl, RuleFlds.burst_label_fld_ptr, 0, gettext("Burst"));
    field_opts_off(RuleFlds.burst_label_fld_ptr, O_ACTIVE);
    set_field_back(RuleFlds.burst_label_fld_ptr, (chtype)COLOR_PAIR(CP_BLUE_WHITE));
    set_field_fore(RuleFlds.burst_label_fld_ptr, (chtype)COLOR_PAIR(CP_BLUE_WHITE));
    field_num++;

    /* limit */
    RuleFlds.burst_fld_ptr = (fields[field_num] = new_field(1, 4, 3, 69, 0, 0));
    if(rule_ptr->opt != NULL)
    {
        if(rule_ptr->opt->burst > 0)
        {
            snprintf(loglimit_string, sizeof(loglimit_string), "%u", rule_ptr->opt->burst);
            set_field_buffer_wrap(debuglvl, RuleFlds.burst_fld_ptr, 0, loglimit_string);
        }
    }
    set_field_back(RuleFlds.burst_fld_ptr, (chtype)COLOR_PAIR(CP_WHITE_BLUE));
    set_field_fore(RuleFlds.burst_fld_ptr, (chtype)COLOR_PAIR(CP_WHITE_BLUE)|A_BOLD);
    field_num++;

    /* start disabled and set the field to dynamic */
    field_opts_off(RuleFlds.burst_fld_ptr, O_VISIBLE|O_STATIC);
    field_opts_off(RuleFlds.burst_label_fld_ptr, O_VISIBLE);


    /* chain label */
    RuleFlds.chain_label_fld_ptr = (fields[field_num] = new_field(1, 9, 5, 29, 0, 0));
    set_field_buffer_wrap(debuglvl, RuleFlds.chain_label_fld_ptr, 0, gettext("Chain"));
    field_opts_off(RuleFlds.chain_label_fld_ptr, O_ACTIVE);
    set_field_back(RuleFlds.chain_label_fld_ptr, (chtype)COLOR_PAIR(CP_BLUE_WHITE));
    set_field_fore(RuleFlds.chain_label_fld_ptr, (chtype)COLOR_PAIR(CP_BLUE_WHITE));
    field_num++;

    /* chain */
    RuleFlds.chain_fld_ptr = (fields[field_num] = new_field(1, 32, 5, 40, 0, 0));
    if(rule_ptr->opt != NULL)
        set_field_buffer_wrap(debuglvl, RuleFlds.chain_fld_ptr, 0, rule_ptr->opt->chain);

    set_field_back(RuleFlds.chain_fld_ptr, (chtype)COLOR_PAIR(CP_WHITE_BLUE));
    set_field_fore(RuleFlds.chain_fld_ptr, (chtype)COLOR_PAIR(CP_WHITE_BLUE)|A_BOLD);
    field_num++;

    /* interface starts disabled */
    field_opts_off(RuleFlds.chain_label_fld_ptr, O_VISIBLE);
    field_opts_off(RuleFlds.chain_fld_ptr, O_VISIBLE);


    /* via label */
    RuleFlds.via_int_label_fld_ptr = (fields[field_num] = new_field(1, 9, 5, 29, 0, 0));
    set_field_buffer_wrap(debuglvl, RuleFlds.via_int_label_fld_ptr, 0, gettext("Via"));
    field_opts_off(RuleFlds.via_int_label_fld_ptr, O_ACTIVE);
    set_field_back(RuleFlds.via_int_label_fld_ptr, (chtype)COLOR_PAIR(CP_BLUE_WHITE));
    set_field_fore(RuleFlds.via_int_label_fld_ptr, (chtype)COLOR_PAIR(CP_BLUE_WHITE));
    field_num++;

    /* chain */
    RuleFlds.via_int_fld_ptr = (fields[field_num] = new_field(1, 32, 5, 40, 0, 0));
    if(rule_ptr->opt != NULL)
        set_field_buffer_wrap(debuglvl, RuleFlds.via_int_fld_ptr, 0, rule_ptr->opt->via_int);

    set_field_back(RuleFlds.via_int_fld_ptr, (chtype)COLOR_PAIR(CP_WHITE_BLUE));
    set_field_fore(RuleFlds.via_int_fld_ptr, (chtype)COLOR_PAIR(CP_WHITE_BLUE)|A_BOLD);
    field_num++;

    /* interface starts disabled */
    field_opts_off(RuleFlds.via_int_fld_ptr, O_VISIBLE);
    field_opts_off(RuleFlds.via_int_fld_ptr, O_VISIBLE);


    /* Reject type label */
    RuleFlds.reject_label_fld_ptr = (fields[field_num] = new_field(1, 12, 5, 29, 0, 0));
    set_field_buffer_wrap(debuglvl, RuleFlds.reject_label_fld_ptr, 0, gettext("Reject type"));
    field_opts_off(RuleFlds.reject_label_fld_ptr, O_ACTIVE);
    set_field_back(RuleFlds.reject_label_fld_ptr, (chtype)COLOR_PAIR(CP_BLUE_WHITE));
    set_field_fore(RuleFlds.reject_label_fld_ptr, (chtype)COLOR_PAIR(CP_BLUE_WHITE));
    field_num++;

    /* Reject type */
    RuleFlds.reject_fld_ptr = (fields[field_num] = new_field(1, 23, 5, 48, 0, 0));

    if(rule_ptr->opt != NULL && rule_ptr->opt->reject_option == 1)
        set_field_buffer_wrap(debuglvl, RuleFlds.reject_fld_ptr, 0, rule_ptr->opt->reject_type);

    set_field_back(RuleFlds.reject_fld_ptr, (chtype)COLOR_PAIR(CP_WHITE_BLUE));
    set_field_fore(RuleFlds.reject_fld_ptr, (chtype)COLOR_PAIR(CP_WHITE_BLUE)|A_BOLD);
    field_num++;

    /* reject starts disabled */
    field_opts_off(RuleFlds.reject_label_fld_ptr, O_VISIBLE);
    field_opts_off(RuleFlds.reject_fld_ptr, O_VISIBLE);


    /* Redirectport label */
    RuleFlds.redirect_label_fld_ptr = (fields[field_num] = new_field(1, 14, 7, 45, 0, 0));
    set_field_buffer_wrap(debuglvl, RuleFlds.redirect_label_fld_ptr, 0, gettext("Redirect port"));
    field_opts_off(RuleFlds.redirect_label_fld_ptr, O_ACTIVE);
    set_field_back(RuleFlds.redirect_label_fld_ptr, (chtype)COLOR_PAIR(CP_BLUE_WHITE));
    set_field_fore(RuleFlds.redirect_label_fld_ptr, (chtype)COLOR_PAIR(CP_BLUE_WHITE));
    field_num++;

    /* Redirectport */
    RuleFlds.redirect_fld_ptr = (fields[field_num] = new_field(1, 11, 7, 61, 0, 0));
    if(rule_ptr->opt != NULL && (rule_ptr->opt->redirectport > 0 && rule_ptr->opt->redirectport <= 65535))
    {
        snprintf(redirect_port, sizeof(redirect_port), "%d", rule_ptr->opt->redirectport);
        set_field_buffer_wrap(debuglvl, RuleFlds.redirect_fld_ptr, 0, redirect_port);
    }
    set_field_back(RuleFlds.redirect_fld_ptr, (chtype)COLOR_PAIR(CP_WHITE_BLUE));
    set_field_fore(RuleFlds.redirect_fld_ptr, (chtype)COLOR_PAIR(CP_WHITE_BLUE)|A_BOLD);
    field_num++;

    /* start disabled */
    field_opts_off(RuleFlds.redirect_fld_ptr, O_VISIBLE);
    field_opts_off(RuleFlds.redirect_label_fld_ptr, O_VISIBLE);


    /* listenport (portfw) label */
    /* TRANSLATORS: max 11 chars */
    RuleFlds.listen_label_fld_ptr = (fields[field_num] = new_field(1, 12, 7, 45, 0, 0));
    set_field_buffer_wrap(debuglvl, RuleFlds.listen_label_fld_ptr, 0, gettext("Listen port"));
    field_opts_off(RuleFlds.listen_label_fld_ptr, O_ACTIVE);
    set_field_back(RuleFlds.listen_label_fld_ptr, (chtype)COLOR_PAIR(CP_BLUE_WHITE));
    set_field_fore(RuleFlds.listen_label_fld_ptr, (chtype)COLOR_PAIR(CP_BLUE_WHITE));
    field_num++;

    /* listenport */
    RuleFlds.listen_fld_ptr = (fields[field_num] = new_field(1, 14, 7, 58, 0, 0));
    set_field_back(RuleFlds.listen_fld_ptr, (chtype)COLOR_PAIR(CP_WHITE_BLUE));
    set_field_fore(RuleFlds.listen_fld_ptr, (chtype)COLOR_PAIR(CP_WHITE_BLUE)|A_BOLD);
    field_num++;

    /* start disabled and set the field to dynamic */
    field_opts_off(RuleFlds.listen_fld_ptr, O_VISIBLE|O_STATIC);
    field_opts_off(RuleFlds.listen_label_fld_ptr, O_VISIBLE);

    /* this is needed after declaring the field dynamic */
    if(rule_ptr->opt != NULL && rule_ptr->opt->listenport == 1)
        set_field_buffer_wrap(debuglvl, RuleFlds.listen_fld_ptr, 0, list_to_portopts(debuglvl, &rule_ptr->opt->ListenportList, NULL));


    /* remoteport (portfw) label */
    /* TRANSLATORS: max 11 chars */
    RuleFlds.remote_label_fld_ptr = (fields[field_num] = new_field(1, 12, 9, 45, 0, 0));
    set_field_buffer_wrap(debuglvl, RuleFlds.remote_label_fld_ptr, 0, gettext("Remote port"));
    field_opts_off(RuleFlds.remote_label_fld_ptr, O_ACTIVE);
    set_field_back(RuleFlds.remote_label_fld_ptr, (chtype)COLOR_PAIR(CP_BLUE_WHITE));
    set_field_fore(RuleFlds.remote_label_fld_ptr, (chtype)COLOR_PAIR(CP_BLUE_WHITE));
    field_num++;

    /* remoteport - total field size: 64 -> 50 offscreen */
    RuleFlds.remote_fld_ptr = (fields[field_num] = new_field(1, 14, 9, 58, 0, 0));
    set_field_back(RuleFlds.remote_fld_ptr, (chtype)COLOR_PAIR(CP_WHITE_BLUE));
    set_field_fore(RuleFlds.remote_fld_ptr, (chtype)COLOR_PAIR(CP_WHITE_BLUE)|A_BOLD);
    field_num++;

    /* start disabled and set the field to dynamic */
    field_opts_off(RuleFlds.remote_fld_ptr, O_VISIBLE|O_STATIC);
    field_opts_off(RuleFlds.remote_label_fld_ptr, O_VISIBLE);

    /* this is needed after declaring the field dynamic */
    if(rule_ptr->opt != NULL && rule_ptr->opt->remoteport == 1)
        set_field_buffer_wrap(debuglvl, RuleFlds.remote_fld_ptr, 0, list_to_portopts(debuglvl, &rule_ptr->opt->RemoteportList, NULL));

    /* terminate the fields-array */
    fields[n_fields] = NULL;
    
    if(n_fields != field_num)
        (void)vrprint.error(-1, VR_INTERR, "oops! n_fields: %d, field_num: %d.", n_fields, field_num);

    /* create the window, panel, form */
    snprintf(window_title, sizeof(window_title), gettext("Edit Rule: %d"), rule_ptr->number);
    if(!(edit_win = create_newwin(height, width, starty, startx, window_title, (chtype)COLOR_PAIR(CP_BLUE_WHITE))))
    {
        (void)vrprint.error(-1, VR_ERR, gettext("creating window failed."));
        return(-1);
    }

    if(!(my_panels[0] = new_panel(edit_win)))
    {
        (void)vrprint.error(-1, VR_ERR, gettext("creating panel failed."));
        return(-1);
    }
    keypad(edit_win, TRUE);

    if(!(form = new_form(fields)))
    {
        (void)vrprint.error(-1, VR_ERR, gettext("creating form failed."));
        return(-1);
    }
    scale_form(form, &rows, &cols);
    set_form_win(form, edit_win);
    set_form_sub(form, derwin(edit_win, rows, cols, 1, 2));
    post_form(form);

    draw_top_menu(debuglvl, top_win, gettext("Edit Rule"), key_choices_n, key_choices, cmd_choices_n, cmd_choices);

    /* set cursor position */
    pos_form_cursor(form);

    update_panels();
    doupdate();

    /*
        loop through to get user requests
    */
    while(quit == 0)
    {
        /* hide/disable fields we don't need */
        if(rule_ptr->action != AT_REJECT)
        {
            field_opts_off(RuleFlds.reject_fld_ptr, O_VISIBLE);
            field_opts_off(RuleFlds.reject_label_fld_ptr, O_VISIBLE);
        }
        if(rule_ptr->action != AT_CHAIN)
        {
            field_opts_off(RuleFlds.chain_fld_ptr, O_VISIBLE);
            field_opts_off(RuleFlds.chain_label_fld_ptr, O_VISIBLE);
        }
        if(rule_ptr->action != AT_REDIRECT)
        {
            field_opts_off(RuleFlds.redirect_fld_ptr, O_VISIBLE);
            field_opts_off(RuleFlds.redirect_label_fld_ptr, O_VISIBLE);
        }
        if(rule_ptr->action != AT_BOUNCE)
        {
            field_opts_off(RuleFlds.via_int_fld_ptr, O_VISIBLE);
            field_opts_off(RuleFlds.via_int_label_fld_ptr, O_VISIBLE);
        }
        if( (rule_ptr->action != AT_SNAT &&
             rule_ptr->action != AT_MASQ &&
             rule_ptr->action != AT_PORTFW &&
             rule_ptr->action != AT_BOUNCE &&
             rule_ptr->action != AT_DNAT) ||
             !advanced_mode)
        {
            field_opts_off(RuleFlds.random_brackets_fld_ptr, O_VISIBLE);
            field_opts_off(RuleFlds.random_label_fld_ptr, O_VISIBLE);
            field_opts_off(RuleFlds.random_fld_ptr, O_VISIBLE);
        }
        if( (rule_ptr->action != AT_REDIRECT &&
             rule_ptr->action != AT_PORTFW) ||
             !advanced_mode)
        {
            field_opts_off(RuleFlds.queue_brackets_fld_ptr, O_VISIBLE);
            field_opts_off(RuleFlds.queue_label_fld_ptr, O_VISIBLE);
            field_opts_off(RuleFlds.queue_fld_ptr, O_VISIBLE);
        }
        if( !advanced_mode)
        {
            field_opts_off(RuleFlds.burst_fld_ptr, O_VISIBLE|O_STATIC);
            field_opts_off(RuleFlds.burst_label_fld_ptr, O_VISIBLE);
    
            field_opts_off(RuleFlds.limit_unit_fld_ptr, O_VISIBLE|O_STATIC);
            field_opts_off(RuleFlds.limit_unit_label_fld_ptr, O_VISIBLE);

            field_opts_off(RuleFlds.limit_fld_ptr, O_VISIBLE|O_STATIC);
            field_opts_off(RuleFlds.limit_label_fld_ptr, O_VISIBLE);
        }
        if( (rule_ptr->action != AT_PORTFW &&
            rule_ptr->action != AT_DNAT) ||
            !advanced_mode)
        {
            field_opts_off(RuleFlds.listen_fld_ptr, O_VISIBLE);
            field_opts_off(RuleFlds.listen_label_fld_ptr, O_VISIBLE);

            field_opts_off(RuleFlds.remote_fld_ptr, O_VISIBLE);
            field_opts_off(RuleFlds.remote_label_fld_ptr, O_VISIBLE);
        }
        if(rule_ptr->action == AT_LOG)
        {
            field_opts_off(RuleFlds.log_fld_ptr, O_ACTIVE);
        }
        if( ((rule_ptr->action != AT_NFQUEUE)) ||
            !advanced_mode)
        {
            field_opts_off(RuleFlds.nfqueuenum_label_fld_ptr, O_VISIBLE);
            field_opts_off(RuleFlds.nfqueuenum_fld_ptr, O_VISIBLE);
        }
        if(rule_ptr->action != AT_LOG || !advanced_mode)
        {
            field_opts_off(RuleFlds.loglimit_label_fld_ptr, O_VISIBLE);
            field_opts_off(RuleFlds.loglimit_fld_ptr, O_VISIBLE);
        }
        if( !advanced_mode ||
            rule_ptr->action == AT_SNAT ||
            rule_ptr->action == AT_DNAT ||
            rule_ptr->action == AT_MASQ)
        {
            field_opts_off(RuleFlds.nfmark_label_fld_ptr, O_VISIBLE);
            field_opts_off(RuleFlds.nfmark_fld_ptr, O_VISIBLE);
        }
        if(!advanced_mode ||
           strncmp(field_buffer(RuleFlds.fromzone_fld_ptr,0), "firewall", 8) == 0)
        {
            field_opts_off(RuleFlds.in_int_label_fld_ptr, O_VISIBLE);
            field_opts_off(RuleFlds.in_int_fld_ptr, O_VISIBLE);
        }
        if(!advanced_mode ||
           strncmp(field_buffer(RuleFlds.tozone_fld_ptr,0), "firewall", 8) == 0)
        {
            field_opts_off(RuleFlds.out_int_label_fld_ptr, O_VISIBLE);
            field_opts_off(RuleFlds.out_int_fld_ptr, O_VISIBLE);
        }

        /* show/enable fields we need */
        if(rule_ptr->action == AT_REJECT)
        {
            field_opts_on(RuleFlds.reject_fld_ptr, O_VISIBLE);
            field_opts_on(RuleFlds.reject_label_fld_ptr, O_VISIBLE);
        }
        if(rule_ptr->action == AT_CHAIN)
        {
            field_opts_on(RuleFlds.chain_fld_ptr, O_VISIBLE);
            field_opts_on(RuleFlds.chain_label_fld_ptr, O_VISIBLE);
        }
        if(rule_ptr->action == AT_BOUNCE)
        {
            field_opts_on(RuleFlds.via_int_fld_ptr, O_VISIBLE);
            field_opts_on(RuleFlds.via_int_label_fld_ptr, O_VISIBLE);
        }
        if(rule_ptr->action == AT_REDIRECT)
        {
            field_opts_on(RuleFlds.redirect_fld_ptr, O_VISIBLE);
            field_opts_on(RuleFlds.redirect_label_fld_ptr, O_VISIBLE);

            if(advanced_mode)
            {
                field_opts_on(RuleFlds.queue_brackets_fld_ptr, O_VISIBLE);
                field_opts_on(RuleFlds.queue_label_fld_ptr, O_VISIBLE);
                field_opts_on(RuleFlds.queue_fld_ptr, O_VISIBLE);
            }
        }
        if(rule_ptr->action == AT_SNAT || rule_ptr->action == AT_MASQ ||
           rule_ptr->action == AT_DNAT || rule_ptr->action == AT_PORTFW ||
           rule_ptr->action == AT_BOUNCE)
        {
            if(advanced_mode)
            {
                field_opts_on(RuleFlds.random_brackets_fld_ptr, O_VISIBLE);
                field_opts_on(RuleFlds.random_label_fld_ptr, O_VISIBLE);
                field_opts_on(RuleFlds.random_fld_ptr, O_VISIBLE);
            }
        }
        if( (rule_ptr->action == AT_PORTFW ||
            rule_ptr->action == AT_DNAT) &&
            advanced_mode)
        {
            field_opts_on(RuleFlds.listen_fld_ptr, O_VISIBLE);
            field_opts_on(RuleFlds.listen_label_fld_ptr, O_VISIBLE);

            field_opts_on(RuleFlds.remote_fld_ptr, O_VISIBLE);
            field_opts_on(RuleFlds.remote_label_fld_ptr, O_VISIBLE);
        }
        if( rule_ptr->action == AT_PORTFW &&
            advanced_mode)
        {
            field_opts_on(RuleFlds.queue_brackets_fld_ptr, O_VISIBLE);
            field_opts_on(RuleFlds.queue_label_fld_ptr, O_VISIBLE);
            field_opts_on(RuleFlds.queue_fld_ptr, O_VISIBLE);
        }
        if( rule_ptr->action == AT_NFQUEUE
            && advanced_mode)
        {
            field_opts_on(RuleFlds.nfqueuenum_label_fld_ptr, O_VISIBLE);
            field_opts_on(RuleFlds.nfqueuenum_fld_ptr, O_VISIBLE);
        }

        if( advanced_mode)
        {
            field_opts_on(RuleFlds.burst_fld_ptr, O_VISIBLE|O_STATIC);
            field_opts_on(RuleFlds.burst_label_fld_ptr, O_VISIBLE);
    
            field_opts_on(RuleFlds.limit_unit_fld_ptr, O_VISIBLE|O_STATIC);
            field_opts_on(RuleFlds.limit_unit_label_fld_ptr, O_VISIBLE);
    
            field_opts_on(RuleFlds.limit_fld_ptr, O_VISIBLE|O_STATIC);
            field_opts_on(RuleFlds.limit_label_fld_ptr, O_VISIBLE);
        }

        if(rule_ptr->action != AT_LOG)
        {
            field_opts_on(RuleFlds.log_fld_ptr, O_ACTIVE);
        }
        if(rule_ptr->action != AT_LOG && advanced_mode)
        {
            field_opts_on(RuleFlds.loglimit_label_fld_ptr, O_VISIBLE);
            field_opts_on(RuleFlds.loglimit_fld_ptr, O_VISIBLE);
        }
        if( rule_ptr->action != AT_SNAT &&
            rule_ptr->action != AT_DNAT &&
            rule_ptr->action != AT_MASQ &&
            advanced_mode)
        {
            field_opts_on(RuleFlds.nfmark_label_fld_ptr, O_VISIBLE);
            field_opts_on(RuleFlds.nfmark_fld_ptr, O_VISIBLE);
        }
        if(advanced_mode)
        {
            if(strncmp(field_buffer(RuleFlds.fromzone_fld_ptr,0), "firewall", 8) != 0)
            {
                field_opts_on(RuleFlds.in_int_label_fld_ptr, O_VISIBLE);
                field_opts_on(RuleFlds.in_int_fld_ptr, O_VISIBLE);
            }

            if(strncmp(field_buffer(RuleFlds.tozone_fld_ptr,0), "firewall", 8) != 0)
            {
                field_opts_on(RuleFlds.out_int_label_fld_ptr, O_VISIBLE);
                field_opts_on(RuleFlds.out_int_fld_ptr, O_VISIBLE);
            }
        }

        /* do some nice coloring of the action field */
        if(rule_ptr->action == AT_ACCEPT)
        {
            set_field_back(RuleFlds.action_fld_ptr, (chtype)COLOR_PAIR(CP_WHITE_GREEN));
            set_field_fore(RuleFlds.action_fld_ptr, (chtype)COLOR_PAIR(CP_WHITE_GREEN)|A_BOLD);
        }
        else if(rule_ptr->action == AT_DROP || rule_ptr->action == AT_REJECT)
        {
            set_field_back(RuleFlds.action_fld_ptr, (chtype)COLOR_PAIR(CP_WHITE_RED));
            set_field_fore(RuleFlds.action_fld_ptr, (chtype)COLOR_PAIR(CP_WHITE_RED)|A_BOLD);
        }
        else if(rule_ptr->action == AT_LOG)
        {
            set_field_back(RuleFlds.action_fld_ptr, (chtype)COLOR_PAIR(CP_WHITE_BLUE)|A_BOLD);
            set_field_fore(RuleFlds.action_fld_ptr, (chtype)COLOR_PAIR(CP_WHITE_BLUE)|A_BOLD);
        }
        else
        {
            set_field_back(RuleFlds.action_fld_ptr, (chtype)COLOR_PAIR(CP_WHITE_BLUE));
            set_field_fore(RuleFlds.action_fld_ptr, (chtype)COLOR_PAIR(CP_WHITE_BLUE)|A_BOLD);
        }

        /* color firewall zones */
        if(strncasecmp(field_buffer(RuleFlds.fromzone_fld_ptr, 0), "firewall", 8) == 0)
            set_field_fore(RuleFlds.fromzone_fld_ptr, (chtype)COLOR_PAIR(CP_YELLOW_BLUE)|A_BOLD);
        else
            set_field_fore(RuleFlds.fromzone_fld_ptr, (chtype)COLOR_PAIR(CP_WHITE_BLUE)|A_BOLD);

        if(strncasecmp(field_buffer(RuleFlds.tozone_fld_ptr, 0), "firewall", 8) == 0)
            set_field_fore(RuleFlds.tozone_fld_ptr, (chtype)COLOR_PAIR(CP_YELLOW_BLUE)|A_BOLD);
        else
            set_field_fore(RuleFlds.tozone_fld_ptr, (chtype)COLOR_PAIR(CP_WHITE_BLUE)|A_BOLD);

        prev = cur;
        cur = current_field(form);

        draw_field_active_mark(cur, prev, edit_win, form, (chtype)COLOR_PAIR(CP_RED_WHITE)|A_BOLD);

        /*
            now give some help message in the status win
        */
        if(cur == RuleFlds.action_fld_ptr)
            status_print(status_win, gettext("Press SPACE to select an action."));
        else if(cur == RuleFlds.service_fld_ptr)
            status_print(status_win, gettext("Press SPACE to select a service."));
        else if(cur == RuleFlds.fromzone_fld_ptr || cur == RuleFlds.tozone_fld_ptr)
            status_print(status_win, gettext("Press SPACE to select a host, group or network, or the firewall."));
        else if(cur == RuleFlds.logprefix_fld_ptr)
            status_print(status_win, gettext("Enter a text to be included in the log message."));
        else if(cur == RuleFlds.reject_fld_ptr)
            status_print(status_win, gettext("Press SPACE to select a reject type."));
        else if(cur == RuleFlds.redirect_fld_ptr)
            status_print(status_win, gettext("Enter a portnumber to redirect to."));
        else if(cur == RuleFlds.listen_fld_ptr)
            status_print(status_win, gettext("Enter a comma-sepparated list of ports for the firewall to listen on."));
        else if(cur == RuleFlds.remote_fld_ptr)
            status_print(status_win, gettext("Enter a comma-sepparated list of ports for the firewall to forward to."));
        else if(cur == RuleFlds.comment_fld_ptr)
            status_print(status_win, gettext("Enter a optional comment."));
        else if(cur == RuleFlds.loglimit_fld_ptr)
            status_print(status_win, gettext("Maximum number of loglines per second (to prevent DoS), 0 for no limit."));
        else if(cur == RuleFlds.log_fld_ptr)
            status_print(status_win, gettext("Press SPACE to toggle logging of this rule."));
        else if(cur == RuleFlds.nfqueuenum_fld_ptr)
            status_print(status_win, gettext("Queue number to use. Possible values: 0-65535."));
        else if(cur == RuleFlds.queue_fld_ptr)
            status_print(status_win, gettext("Press SPACE to toggle queue'ing of this rule."));
        else if(cur == RuleFlds.in_int_fld_ptr)
            status_print(status_win, gettext("Press SPACE to select an interface to limit this rule to."));
        else if(cur == RuleFlds.out_int_fld_ptr)
            status_print(status_win, gettext("Press SPACE to select an interface to limit this rule to."));
        else if(cur == RuleFlds.via_int_fld_ptr)
            status_print(status_win, gettext("Press SPACE to select an interface. Read help for more info."));
        else if(cur == RuleFlds.nfmark_fld_ptr)
            status_print(status_win, gettext("Enter a nfmark. Use > 20.000.000 when using the QUEUE action."));
        else if(cur == RuleFlds.limit_fld_ptr)
            status_print(status_win, gettext("Average new connections per amount of time (to prevent DoS), 0 for no limit."));
        else if(cur == RuleFlds.limit_unit_fld_ptr)
            status_print(status_win, gettext("Unit for the limit: sec, min, hour, day."));
        else if(cur == RuleFlds.burst_fld_ptr)
            status_print(status_win, gettext("Maximum new connections per second (to prevent DoS), 0 for no limit."));
        else if(cur == RuleFlds.random_fld_ptr)
            status_print(status_win, gettext("Randomize the source ports of NAT'd connections."));

        ch = wgetch(edit_win);
        not_defined = 0;

        if( cur == RuleFlds.logprefix_fld_ptr ||
            cur == RuleFlds.redirect_fld_ptr  ||
            cur == RuleFlds.listen_fld_ptr    ||
            cur == RuleFlds.loglimit_fld_ptr  ||
            cur == RuleFlds.remote_fld_ptr    ||
            cur == RuleFlds.comment_fld_ptr   ||
            cur == RuleFlds.nfmark_fld_ptr    ||
            cur == RuleFlds.chain_fld_ptr     ||
            cur == RuleFlds.limit_fld_ptr     ||
            cur == RuleFlds.nfqueuenum_fld_ptr ||
            cur == RuleFlds.burst_fld_ptr)
        {
            if(nav_field_simpletext(debuglvl, form, ch) < 0)
                not_defined = 1;
        }
        else if(cur == RuleFlds.queue_fld_ptr         ||
                cur == RuleFlds.random_fld_ptr        ||
                cur == RuleFlds.log_fld_ptr)
        {
            if(nav_field_toggleX(debuglvl, form, ch) < 0)
                not_defined = 1;
        }
        else
        {
            not_defined = 1;
        }

        if(not_defined == 1)
        {
            switch(ch)
            {
                case KEY_F(6):
                case 'S':
                case 's':
                    if(rule_ptr->opt == NULL)
                    {
                        if(!(rule_ptr->opt = ruleoption_malloc(debuglvl)))
                        {
                            (void)vrprint.error(-1, VR_ERR, gettext("malloc failed: %s (in: %s:%d)."), strerror(errno), __FUNCTION__, __LINE__);
                            return(-1);
                        }
                    }
                    VrShapeRule(debuglvl, rule_ptr->opt);
                    break;
                case KEY_DOWN:
                case 10:    // enter
                case 9: // tab

                    form_driver(form, REQ_NEXT_FIELD);
                    form_driver(form, REQ_END_LINE);
                    break;

                case KEY_UP:

                    form_driver(form, REQ_PREV_FIELD);
                    form_driver(form, REQ_END_LINE);
                    break;

                case 32: /* space */

                    if(cur == RuleFlds.action_fld_ptr)
                    {
                        if(!(copy_field2buf(select_choice,
                                            field_buffer(cur, 0),
                                            sizeof(select_choice))))
                            return(-1);

                        /* ask the user about the new action */
                        if((action_ptr = selectbox( gettext("Action"),
                                                    gettext("Select action"),
                                                    action_choices_n,
                                                    action_choices,
                                                    1,
                                                    select_choice)))
                        {
                            set_field_buffer_wrap(debuglvl, cur, 0, action_ptr);
                            rule_ptr->action = rules_actiontoi(action_ptr);
                            free(action_ptr);

                            /* if action is LOG, disable the log option. */
                            if(rule_ptr->action == AT_LOG)
                            {
                                set_field_buffer_wrap(debuglvl, RuleFlds.log_fld_ptr, 0, " ");
                            }
                        }
                    }
                    else if(cur == RuleFlds.fromzone_fld_ptr || cur == RuleFlds.tozone_fld_ptr)
                    {
                        for(zone_choices_n = 0, d_node = zones->list.top; d_node; d_node = d_node->next)
                        {
                            if(!(zone_ptr = d_node->data))
                            {
                                (void)vrprint.error(-1, VR_INTERR, "NULL pointer (in: %s:%d).", __FUNC__, __LINE__);
                                return(-1);
                            }

                            if(zone_ptr->type != TYPE_ZONE && zone_ptr->type != TYPE_FIREWALL)
                            {
                                zone_choices_n++;
                            }
                        }
                        zone_choices_n += 3; /* for firewall, firewall(any) and any */

                        if(!(zone_choices = calloc(zone_choices_n + 1, MAX_HOST_NET_ZONE)))
                        {
                            (void)vrprint.error(-1, VR_ERR, gettext("malloc failed: %s (in: %s:%d)."), strerror(errno), __FUNCTION__, __LINE__);
                            return(-1);
                        }

                        for(i = zone_choices_n - 1, d_node = zones->list.bot; d_node ; d_node = d_node->prev)
                        {
                            if(!(zone_ptr = d_node->data))
                            {
                                (void)vrprint.error(-1, VR_INTERR, "NULL pointer (in: %s:%d).", __FUNC__, __LINE__);
                                return(-1);
                            }

                            if(zone_ptr->type != TYPE_ZONE && zone_ptr->type != TYPE_FIREWALL)
                            {
                                zone_choices[i] = zone_ptr->name;
                                //(void)vrprint.debug(__FUNC__, "zone_choices[%d]: %s.", i, zone_choices[i]);

                                i--;
                            }
                        }
                        zone_choices[0] = "firewall";
                        zone_choices[1] = "firewall(any)";
                        zone_choices[2] = "any";
                        zone_choices[zone_choices_n] = NULL;

                        if(!(copy_field2buf(select_choice,
                                            field_buffer(cur, 0),
                                            sizeof(select_choice))))
                            return(-1);

                        /* get the zone */
                        if((choice_ptr = selectbox(gettext("Select"), gettext("Select a host, group or network"), zone_choices_n, zone_choices, 2, select_choice)))
                        {
                            set_field_buffer_wrap(debuglvl, cur, 0, choice_ptr);
                            free(choice_ptr);
                            choice_ptr = NULL;
                        }

                        free(zone_choices);
                        zone_choices = NULL;
                    }
                    else if(cur == RuleFlds.service_fld_ptr)
                    {
                        service_choices_n = services->list.len + 1;

                        if(!(service_choices = calloc(service_choices_n + 1, sizeof(char *))))
                        {
                            (void)vrprint.error(-1, VR_ERR, gettext("malloc failed: %s (in: %s:%d)."), strerror(errno), __FUNCTION__, __LINE__);
                            return(-1);
                        }

                        for(i = 1, d_node = services->list.top; d_node && i < service_choices_n; d_node = d_node->next, i++)
                        {
                            if(!(service_ptr = d_node->data))
                            {
                                (void)vrprint.error(-1, VR_INTERR, "service_ptr == NULL! (in: edit_rule_normal).");
                                return(-1);
                            }

                            service_choices[i] = service_ptr->name;
                        }
                        service_choices[0] = "any";
                        service_choices[i] = NULL;

                        if(!(copy_field2buf(select_choice,
                                            field_buffer(cur, 0),
                                            sizeof(select_choice))))
                            return(-1);

                        /* get the service */
                        if((choice_ptr = selectbox(gettext("Select"), gettext("Select a service"), service_choices_n, service_choices, 3, select_choice)))
                        {
                            set_field_buffer_wrap(debuglvl, cur, 0, choice_ptr);
                            free(choice_ptr);
                            choice_ptr = NULL;
                        }

                        free(service_choices);
                        service_choices = NULL;
                    }
                    else if(cur == RuleFlds.reject_fld_ptr)
                    {
                        if(!(copy_field2buf(select_choice,
                                            field_buffer(cur, 0),
                                            sizeof(select_choice))))
                            return(-1);

                        if((reject_ptr = selectbox(gettext("Reject type"), gettext("Select reject type"), reject_types_n, reject_types, 1, select_choice)))
                        {
                            set_field_buffer_wrap(debuglvl, cur, 0, reject_ptr);
                            free(reject_ptr);
                        }
                    }
                    else if(cur == RuleFlds.in_int_fld_ptr)
                    {
                        if( field_buffer(RuleFlds.fromzone_fld_ptr, 0)[0] == '\0' ||
                            field_buffer(RuleFlds.fromzone_fld_ptr, 0)[0] == ' ')
                        {
                            (void)vrprint.warning(VR_WARN, gettext("no from zone, please select one first."));
                        }
                        else
                        {
                            /* set to NULL so we can be sure that it is set properly later */
                            interfaces_list = NULL;

                            /* any just use all interfaces */
                            if(strncasecmp(field_buffer(RuleFlds.fromzone_fld_ptr, 0), "any", 3) == 0)
                            {
                                interfaces_list = &interfaces->list;
                            }
                            else
                            {
                                /* copy the from field to the zonename buffer */
                                if(!(copy_field2buf(zonename,
                                                    field_buffer(RuleFlds.fromzone_fld_ptr, 0),
                                                    sizeof(zonename))))
                                    return(-1);
                            
                                /* get the zone */
                                if(!(zone_ptr = search_zonedata(debuglvl, zones, zonename)))
                                {
                                    (void)vrprint.error(-1, VR_INTERR, "zone '%s' not found (in: %s:%d).", zonename, __FUNC__, __LINE__);
                                }
                                else
                                {
                                    /* the interfaces are attached to the network, so get the network */
                                    if(zone_ptr->type == TYPE_NETWORK)
                                    {
                                        network_ptr = zone_ptr;
                                    }
                                    else if(zone_ptr->type == TYPE_HOST || zone_ptr->type == TYPE_GROUP)
                                    {
                                        network_ptr = zone_ptr->network_parent;
                                    }
                                    else
                                    {
                                        (void)vrprint.error(-1, VR_INTERR, "wrong zone type '%d'  (in: %s:%d).", zone_ptr->type, __FUNC__, __LINE__);
                                        return(-1);
                                    }

                                    interfaces_list = &network_ptr->InterfaceList;
                                }
                            }

                            if(interfaces_list != NULL)
                            {
                                /* check if there are interfaces defined to choose from */
                                n_choices = interfaces_list->len + 1;

                                /* get some mem */
                                if(!(choices = calloc(n_choices + 1, MAX_INTERFACE)))
                                {
                                    (void)vrprint.error(-1, VR_ERR, gettext("calloc failed: %s (in: %s:%d)."), strerror(errno), __FUNCTION__, __LINE__);
                                    return(-1);
                                }

                                /* load the interfaces */
                                for(i = n_choices-1, d_node = interfaces_list->bot; d_node ; d_node = d_node->prev)
                                {
                                    if(!(iface_ptr = d_node->data))
                                    {
                                        (void)vrprint.error(-1, VR_INTERR, "NULL pointer (in: %s).", __FUNC__);
                                        free(choices);
                                        return(-1);
                                    }

                                    choices[i] = iface_ptr->name;
                                    i--;
                                }
                                choices[i] = gettext("Any");

                                if(!(copy_field2buf(select_choice,
                                                    field_buffer(cur, 0),
                                                    sizeof(select_choice))))
                                    return(-1);

                                /* ask the user to select an interface */
                                if(!(choice_ptr = selectbox(gettext("Set interface filter"), gettext("Select an interface ('Any' to disable filter)"), n_choices, choices, 1, select_choice)))
                                {
                                    /* no choice */
                                }
                                else
                                {
                                    /* any means empty the field */
                                    if(strcmp(choice_ptr, gettext("Any")) == 0)
                                        set_field_buffer_wrap(debuglvl, RuleFlds.in_int_fld_ptr, 0, "");
                                    else
                                        set_field_buffer_wrap(debuglvl, RuleFlds.in_int_fld_ptr, 0, choice_ptr);

                                    free(choice_ptr);
                                }

                                /* cleanup */
                                free(choices);
                            }
                        }
                    }
                    else if(cur == RuleFlds.out_int_fld_ptr)
                    {
                        if( field_buffer(RuleFlds.tozone_fld_ptr, 0)[0] == '\0' ||
                            field_buffer(RuleFlds.tozone_fld_ptr, 0)[0] == ' ')
                        {
                            (void)vrprint.warning(VR_WARN, gettext("no 'to' zone, please select one first."));
                        }
                        else
                        {
                            /* set to NULL so we can be sure that it is set properly later */
                            interfaces_list = NULL;

                            /* any just use all interfaces */
                            if(strncasecmp(field_buffer(RuleFlds.tozone_fld_ptr, 0), "any", 3) == 0)
                            {
                                interfaces_list = &interfaces->list;
                            }
                            else
                            {
                                /* copy the from field to the zonename buffer */
                                if(!(copy_field2buf(zonename,
                                                    field_buffer(RuleFlds.tozone_fld_ptr, 0),
                                                    sizeof(zonename))))
                                    return(-1);
                            
                                /* get the zone */
                                if(!(zone_ptr = search_zonedata(debuglvl, zones, zonename)))
                                {
                                    (void)vrprint.error(-1, VR_INTERR, "zone '%s' not found (in: %s:%d).",
                                        zonename, __FUNC__, __LINE__);
                                }
                                else
                                {
                                    /* the interfaces are attached to the network, so get the network */
                                    if(zone_ptr->type == TYPE_NETWORK)
                                    {
                                        network_ptr = zone_ptr;
                                    }
                                    else if(zone_ptr->type == TYPE_HOST || zone_ptr->type == TYPE_GROUP)
                                    {
                                        network_ptr = zone_ptr->network_parent;
                                    }
                                    else
                                    {
                                        (void)vrprint.error(-1, VR_INTERR, "wrong zone type '%d'  (in: %s:%d).",
                                                    zone_ptr->type, __FUNC__, __LINE__);
                                        return(-1);
                                    }

                                    interfaces_list = &network_ptr->InterfaceList;
                                }
                            }

                            if(interfaces_list != NULL)
                            {
                                /* check if there are interfaces defined to choose from */
                                n_choices = interfaces_list->len + 1;

                                /* get some mem */
                                if(!(choices = calloc(n_choices + 1, MAX_INTERFACE)))
                                {
                                    (void)vrprint.error(-1, VR_ERR, gettext("calloc failed: %s (in: %s:%d)."),
                                        strerror(errno), __FUNCTION__, __LINE__);
                                    return(-1);
                                }

                                /* load the interfaces */
                                for(i = n_choices-1, d_node = interfaces_list->bot; d_node ; d_node = d_node->prev)
                                {
                                    if(!(iface_ptr = d_node->data))
                                    {
                                        (void)vrprint.error(-1, VR_INTERR, "NULL pointer (in: %s:%d).",
                                                    __FUNC__, __LINE__);
                                        free(choices);
                                        return(-1);
                                    }

                                    choices[i] = iface_ptr->name;
                                    i--;
                                }
                                choices[i] = gettext("Any");

                                if(!(copy_field2buf(select_choice,
                                                    field_buffer(cur, 0),
                                                    sizeof(select_choice))))
                                    return(-1);

                                /* ask the user to select an interface */
                                if(!(choice_ptr = selectbox(gettext("Set interface filter"), gettext("Select an interface ('Any' to disable filter)"), n_choices, choices, 1, select_choice)))
                                {
                                    /* no choice */
                                }
                                else
                                {
                                    /* any means empty the field */
                                    if(strcmp(choice_ptr, gettext("Any")) == 0)
                                        set_field_buffer_wrap(debuglvl, RuleFlds.out_int_fld_ptr, 0, "");
                                    else
                                        set_field_buffer_wrap(debuglvl, RuleFlds.out_int_fld_ptr, 0, choice_ptr);

                                    free(choice_ptr);
                                }

                                /* cleanup */
                                free(choices);
                            }
                        }
                    }
                    else if(cur == RuleFlds.via_int_fld_ptr)
                    {
                        interfaces_list = &interfaces->list;

                        if(interfaces_list != NULL)
                        {
                            /* check if there are interfaces defined to choose from */
                            n_choices = interfaces_list->len;

                            /* get some mem */
                            if(!(choices = calloc(n_choices + 1, MAX_INTERFACE)))
                            {
                                (void)vrprint.error(-1, VR_ERR, gettext("calloc failed: %s (in: %s:%d)."), strerror(errno), __FUNCTION__, __LINE__);
                                return(-1);
                            }

                            /* load the interfaces */
                            for(i = 0, d_node = interfaces_list->top; d_node ; d_node = d_node->next, i++)
                            {
                                if(!(iface_ptr = d_node->data))
                                {
                                    (void)vrprint.error(-1, VR_INTERR, "NULL pointer (in: %s).", __FUNC__);
                                    free(choices);
                                    return(-1);
                                }

                                choices[i] = iface_ptr->name;
                            }
                            choices[i] = NULL;

                            if(!(copy_field2buf(select_choice,
                                                field_buffer(cur, 0),
                                                sizeof(select_choice))))
                                return(-1);

                            /* ask the user to select an interface */
                            if(!(choice_ptr = selectbox(gettext("Set Via interface"), gettext("Select an interface"), n_choices, choices, 1, select_choice)))
                            {
                                /* no choice */
                            }
                            else
                            {
                                set_field_buffer_wrap(debuglvl, RuleFlds.via_int_fld_ptr, 0, choice_ptr);
                                free(choice_ptr);
                            }

                            /* cleanup */
                            free(choices);
                        }
                    }
                    else if(cur == RuleFlds.limit_unit_fld_ptr)
                    {
                        char    *limit_unit_choices[] = {
                                "Sec", "Min", "Hour", "Day", },
                                *limit_unit_ptr = NULL;
                        size_t  limit_unit_choices_n = 4;

                        if(!(copy_field2buf(select_choice,
                                            field_buffer(cur, 0),
                                            sizeof(select_choice))))
                            return(-1);

                        /* ask the user about the new action */
                        if((limit_unit_ptr = selectbox( gettext("Unit"),
                                                        gettext("Select time unit"),
                                                        limit_unit_choices_n,
                                                        limit_unit_choices,
                                                        1, /* 1 column */
                                                        select_choice)))
                        {
                            set_field_buffer_wrap(debuglvl, cur, 0, limit_unit_ptr);
                            free(limit_unit_ptr);
                        }
                    }
                    else
                    {
                        form_driver(form, ch);
                    }
                    break;

                case 27:
                case 'q':
                case 'Q':
                case KEY_F(10):

                    result = edit_rule_fields_to_rule(debuglvl, fields, n_fields, rule_ptr, reg);
                    if(result == 1)
                    {
                        if( edit_rule_simple_check(debuglvl, rule_ptr) == 0 ||
                            edit_rule_check_action_opts(debuglvl, rule_ptr) == 0)
                        {
                            if(!(confirm(gettext("Not all required fields are filled in"),
                                    gettext("Do you want to look at the rule again? (no will delete the rule)"),
                                    (chtype)COLOR_PAIR(CP_RED_WHITE), (chtype)COLOR_PAIR(CP_WHITE_RED)|A_BOLD, 1)))
                            {
                                retval = -1;
                                quit = 1;
                            }
                        }
                        else
                        {
                            /* check */
                            if(rules_analyze_rule(debuglvl, rule_ptr, &tmp_ruledata, services, zones, interfaces, &conf) < 0)
                            {
                                /* clear tmp_ruledata for the next use */
                                bzero(&tmp_ruledata, sizeof(tmp_ruledata));

                                /* ask the user if he/she want to look at the rule again */
                                if(!(confirm(gettext("An error was detected in the rule"),
                                        gettext("Do you want to look at it again? (no will delete the rule)"),
                                        (chtype)COLOR_PAIR(CP_RED_WHITE), (chtype)COLOR_PAIR(CP_WHITE_RED)|A_BOLD, 1)))
                                {
                                    retval = -1;
                                    quit = 1;
                                }
                                else
                                {
                                    /* we're not quiting yet! */
                                    quit = 0;
                                    retval = 0;
                                }
                            }
                            else
                            {
                                quit = 1;
                                retval = 1;
                            }
                        }
                    }
                    else if(result == 0)
                    {
                        /* no change */
                        quit = 1;
                    }
                    else
                    {
                        /* error */
                        retval = -1;
                    }

                    break;

                case KEY_F(12):
                case 'h':
                case 'H':
                case '?':

                    print_help(debuglvl, ":[VUURMUUR:RULES:EDIT]:");
                    break;

                /* enable advanced mode */
                case KEY_F(5):
                case 'a':
                case 'A':

                    if(!advanced_mode)
                        advanced_mode = 1;
                    else
                        advanced_mode = 0;
                    break;
            }
        }
    }

    /* Un post form and free the memory */
    unpost_form(form);
    free_form(form);
    for(i=0; i < n_fields; i++)
    {
        free_field(fields[i]);
    }
    free(fields);

    del_panel(my_panels[0]);
    destroy_win(edit_win);

    update_panels();
    doupdate();

    status_print(status_win, gettext("Ready."));

    if(debuglvl >= LOW)
        (void)vrprint.debug(__FUNC__, "returning retval = %d.", retval);

    return(retval);
}


struct SepRuleFlds_
{
    FIELD   *comment_label_fld_ptr,
            *comment_fld_ptr;
} SepRuleFlds;


/*  edit_rule_fields_to_rule

    Returncodes:
         1: changes stored
         0: no changes
        -1: error
*/
static int
edit_seprule_fields_to_rule(const int debuglvl, FIELD **fields, size_t n_fields, struct RuleData_ *rule_ptr, struct rgx_ *reg)
{
    int     z = 0,
            retval = 0;
    size_t  i = 0;
        

    if(!fields || !rule_ptr || !reg)
    {
        (void)vrprint.error(-1, VR_INTERR, "parameter problem (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    /* check for changed fields */
    for(i = 0; i < n_fields; i++)
    {
        if(field_status(fields[i]) == TRUE)
        {
            if(fields[i] == SepRuleFlds.comment_fld_ptr)
            {
                int last_char = 0;

                /* first check if the commentfield is valid */
                if(validate_commentfield(debuglvl, field_buffer(fields[i], 0), reg->comment) == 0)
                {
                    /* options */
                    if(rule_ptr->opt == NULL)
                    {
                        if(!(rule_ptr->opt = ruleoption_malloc(debuglvl)))
                        {
                            (void)vrprint.error(-1, VR_ERR, gettext("malloc failed: %s (in: %s:%d)."), strerror(errno), __FUNCTION__, __LINE__);
                            return(-1);
                        }
                    }

                    for(z = 0; z < (int)sizeof(rule_ptr->opt->comment) && field_buffer(fields[i], 0)[z] != '\n' && field_buffer(fields[i], 0)[z] != '\0'; z++) /* 12 is max prefix length */
                    {
                        rule_ptr->opt->comment[z] = field_buffer(fields[i], 0)[z];

                        /* make sure that we place the NULL after the last char: no trailing spaces. */
                        if(rule_ptr->opt->comment[z] != ' ')
                            last_char = z + 1;
                    }
                    rule_ptr->opt->comment[last_char] = '\0';

                    if(strcmp(rule_ptr->opt->comment, "") == 0)
                        rule_ptr->opt->rule_comment = 0;
                    else
                        rule_ptr->opt->rule_comment = 1;

                    retval = 1;
                }
            }
        }  
    }

    if(debuglvl >= LOW)
        (void)vrprint.debug(__FUNC__, "returning retval = %d.", retval);

    return(retval);
}


/*  edit_rule_normal

    Returncodes:
         0: ok, no changes
         1: ok, changes
        -1: error

    TODO: split this beast up
*/
int
edit_rule_separator(const int debuglvl,
                    Zones *zones,
                    Interfaces *interfaces,
                    Services *services,
                    struct RuleData_ *rule_ptr,
                    unsigned int rule_num,
                    struct rgx_ *reg)
{
    PANEL               *my_panels[1];
    WINDOW              *edit_win;
    FIELD               **fields,
                        *cur = NULL;

    FORM                *form;
    int                 ch,
                        rows,
                        cols,
                        retval = 0,
                        quit = 0;
    size_t              n_fields = 0,
                        i = 0,
                        field_num = 0;
    int                 height,
                        width,
                        startx,
                        starty,
                        max_height,
                        max_width;
    int                 result = 0;
    struct RuleCache_   tmp_ruledata;


    /* safety */
    if(!rule_ptr || !reg)
    {
        (void)vrprint.error(-1, VR_INTERR, "parameter problem (in: %s:%d).",
                                __FUNC__, __LINE__);
        return(-1);
    }

    /* clear tmp_ruledata for the initial */
    memset(&tmp_ruledata, 0, sizeof(tmp_ruledata));
    memset(&SepRuleFlds, 0, sizeof(struct SepRuleFlds_));

    /* set to keep first */
    rule_ptr->status = ST_CHANGED;

    /* get the dimentions of the screen */
    getmaxyx(stdscr, max_height, max_width);

    /* set windowsize and start position */
    height = 5;
    width  = 71;
    startx = 3;
    starty = 1;
    startx = (max_width - width)/2;
    starty = (max_height - height) /2;

    /* init the action_type */
    if(rule_ptr->action != AT_SEPARATOR)
    {
        (void)vrprint.error(-1, VR_INTERR, "wrong action_type (in: %s:%d).",
                                __FUNC__, __LINE__);
        return(-1);
    }

    /* set number of fields */
    n_fields = 1;
    if(!(fields = (FIELD **)calloc(n_fields + 1, sizeof(FIELD *))))
    {
        (void)vrprint.error(-1, VR_ERR, gettext("calloc failed: %s (in: %s:%d)."),
                                strerror(errno), __FUNC__, __LINE__);
        return(-1);
    }

    /*
        create the fields
    */

    /* comment */
    SepRuleFlds.comment_fld_ptr = (fields[field_num] = new_field(1, 63, 1, 2, 0, 0));
    if(rule_ptr->opt != NULL && rule_ptr->opt->rule_comment == 1)
        set_field_buffer_wrap(debuglvl, SepRuleFlds.comment_fld_ptr, 0, rule_ptr->opt->comment);
    set_field_back(SepRuleFlds.comment_fld_ptr, (chtype)COLOR_PAIR(CP_WHITE_BLUE));
    set_field_fore(SepRuleFlds.comment_fld_ptr, (chtype)COLOR_PAIR(CP_WHITE_BLUE)|A_BOLD);
    field_opts_off(SepRuleFlds.comment_fld_ptr, O_AUTOSKIP);
    set_field_status(SepRuleFlds.comment_fld_ptr, FALSE);
    field_num++;

    /* terminate the fields-array */
    fields[n_fields] = NULL;
    
    if(n_fields != field_num)
        (void)vrprint.error(-1, VR_INTERR, "oops! n_fields: %d, field_num: %d.", n_fields, field_num);

    /* create the window, panel, form */
    if(!(edit_win = create_newwin(height, width, starty, startx, gettext("Enter comment (optional)"), (chtype)COLOR_PAIR(CP_BLUE_WHITE))))
    {
        (void)vrprint.error(-1, VR_ERR, gettext("creating window failed."));
        return(-1);
    }

    if(!(my_panels[0] = new_panel(edit_win)))
    {
        (void)vrprint.error(-1, VR_ERR, gettext("creating panel failed."));
        return(-1);
    }
    keypad(edit_win, TRUE);

    if(!(form = new_form(fields)))
    {
        (void)vrprint.error(-1, VR_ERR, gettext("creating form failed."));
        return(-1);
    }
    scale_form(form, &rows, &cols);
    set_form_win(form, edit_win);
    set_form_sub(form, derwin(edit_win, rows, cols, 1, 2));
    post_form(form);

    /* set cursor position */
    pos_form_cursor(form);

    update_panels();
    doupdate();

    /*
        loop through to get user requests
    */
    while(quit == 0)
    {
        cur = current_field(form);

        /*
            now give some help message in the status win
        */
        if(cur == SepRuleFlds.comment_fld_ptr)
            status_print(status_win, gettext("Enter an optional comment."));

        ch = wgetch(edit_win);

        char not_defined = 0;
        if (nav_field_simpletext(debuglvl, form, ch) < 0)
            not_defined = 1;

        if (not_defined == 1) {
            switch(ch)
            {
                case 27:
                case KEY_F(10):
                case 10:    /* enter */

                    form_driver(form, REQ_NEXT_FIELD); /* this is to make sure the field is saved */

                    result = edit_seprule_fields_to_rule(debuglvl, fields, n_fields, rule_ptr, reg);
                    if(result == 1)
                    {
                        quit = 1;
                        retval = 1;
                    }
                    else if(result == 0)
                    {
                        /* no change */
                        quit = 1;
                    }
                    else
                    {
                        /* error */
                        quit = 1;
                        retval = -1;
                    }

                    break;
            }
        }
    }

    /* Un post form and free the memory */
    unpost_form(form);
    free_form(form);
    for(i=0; i < n_fields; i++)
    {
        free_field(fields[i]);
    }
    free(fields);

    del_panel(my_panels[0]);
    destroy_win(edit_win);

    update_panels();
    doupdate();

    status_print(status_win, gettext("Ready."));

    if(debuglvl >= LOW)
        (void)vrprint.debug(__FUNC__, "returning retval = %d.", retval);

    return(retval);
}
