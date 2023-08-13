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

char *VrShapeUnitMenu(char *unit, int y, int x, char bps)
{
    struct vrmr_gui_win *win = NULL;
    struct vrmr_gui_menu *menu = NULL;
    int ch = 0;
    int menu_items = bps ? 4 : 2;
    const int width = 8;
    char *r = strdup(unit); /* default to unit --
                               dup because we free at the caller*/

    /* create the window and put it in the middle of the screen */
    win = VrNewWin(menu_items + 2, width, y, x, vccnf.color_win);
    if (win == NULL) {
        vrmr_fatal("VrNewWin failed");
    }

    menu = VrNewMenu(menu_items, width - 2, 1, 1, menu_items, vccnf.color_win,
            vccnf.color_win_rev);
    if (menu == NULL) {
        vrmr_fatal("VrNewMenu failed");
    }

    VrMenuSetDescFreeFunc(menu, NULL);
    VrMenuSetupNameList(menu);
    // VrMenuSetupDescList(menu);

    /* setup menu items */
    VrMenuAddItem(menu, "kbit", NULL);
    VrMenuAddItem(menu, "mbit", NULL);
    if (bps) {
        VrMenuAddItem(menu, "kbps", NULL);
        VrMenuAddItem(menu, "mbps", NULL);
    }

    VrMenuConnectToWin(menu, win);
    VrMenuPost(menu);

    update_panels();
    doupdate();

    /* user input */
    char quit = FALSE;
    while (quit == FALSE) {
        ch = VrWinGetch(win);

        switch (ch) {
            case 27:
            case 'q':
            case 'Q':
            case KEY_F(10):
                quit = TRUE;
                break;

            case 10: {
                ITEM *cur = current_item(menu->m);
                if (cur != NULL) {
                    if (r)
                        free(r);
                    r = strdup((char *)item_name(cur));
                    quit = TRUE;
                }

                break;
            }

            case KEY_F(12):
            case 'h':
            case 'H':
            case '?':
                // print_help(ctl->help_actions);
                break;

            default:
                (void)VrMenuDefaultNavigation(menu, ch);
                break;
        }
    }

    VrDelMenu(menu);
    VrDelWin(win);
    update_panels();
    doupdate();
    return r;
}

struct shape_rule_cnf {
    struct vrmr_rule_options *opt;

    char in_min[10], out_min[10], in_max[10], out_max[10], prio[4];
    char in_min_unit[5], out_min_unit[5], in_max_unit[5], out_max_unit[5];
};

static void VrShapeRuleSetup(
        struct shape_rule_cnf *c, struct vrmr_rule_options *opt)
{
    vrmr_fatal_if_null(c);
    vrmr_fatal_if_null(opt);

    c->opt = opt;

    snprintf(c->in_min, sizeof(c->in_min), "%u", c->opt->bw_in_min);
    snprintf(c->in_max, sizeof(c->in_max), "%u", c->opt->bw_in_max);
    snprintf(c->out_min, sizeof(c->out_min), "%u", c->opt->bw_out_min);
    snprintf(c->out_max, sizeof(c->out_max), "%u", c->opt->bw_out_max);

    if (strcmp(c->opt->bw_in_min_unit, "") == 0)
        strlcpy(c->in_min_unit, "kbit", sizeof(c->in_min_unit));
    else
        snprintf(c->in_min_unit, sizeof(c->in_min_unit), "%s",
                c->opt->bw_in_min_unit);

    if (strcmp(c->opt->bw_in_max_unit, "") == 0)
        strlcpy(c->in_max_unit, "kbit", sizeof(c->in_max_unit));
    else
        snprintf(c->in_max_unit, sizeof(c->in_max_unit), "%s",
                c->opt->bw_in_max_unit);

    if (strcmp(c->opt->bw_out_min_unit, "") == 0)
        strlcpy(c->out_min_unit, "kbit", sizeof(c->out_min_unit));
    else
        snprintf(c->out_min_unit, sizeof(c->out_min_unit), "%s",
                c->opt->bw_out_min_unit);

    if (strcmp(c->opt->bw_out_max_unit, "") == 0)
        strlcpy(c->out_max_unit, "kbit", sizeof(c->out_max_unit));
    else
        snprintf(c->out_max_unit, sizeof(c->out_max_unit), "%s",
                c->opt->bw_out_max_unit);

    snprintf(c->prio, sizeof(c->prio), "%u", c->opt->prio);
    return;
}

static int VrShapeRuleSave(void *ctx, char *name, char *value)
{
    struct shape_rule_cnf *c = (struct shape_rule_cnf *)ctx;

    vrmr_debug(NONE, "%s:%s", name, value);

    if (strcmp(name, "in_min") == 0) {
        c->opt->bw_in_min = atoi(value);
    } else if (strcmp(name, "in_max") == 0) {
        c->opt->bw_in_max = atoi(value);
    } else if (strcmp(name, "out_min") == 0) {
        c->opt->bw_out_min = atoi(value);
    } else if (strcmp(name, "out_max") == 0) {
        c->opt->bw_out_max = atoi(value);
    } else if (strcmp(name, "unit1") == 0) {
        strlcpy(c->opt->bw_in_min_unit, value, sizeof(c->opt->bw_in_min_unit));
    } else if (strcmp(name, "unit2") == 0) {
        strlcpy(c->opt->bw_in_max_unit, value, sizeof(c->opt->bw_in_max_unit));
    } else if (strcmp(name, "unit3") == 0) {
        strlcpy(c->opt->bw_out_min_unit, value,
                sizeof(c->opt->bw_out_min_unit));
    } else if (strcmp(name, "unit4") == 0) {
        strlcpy(c->opt->bw_out_max_unit, value,
                sizeof(c->opt->bw_out_max_unit));
    } else if (strcmp(name, "prio") == 0) {
        c->opt->prio = atoi(value);
    }

    return (0);
}

void VrShapeRule(struct vrmr_rule_options *opt)
{
    struct vrmr_gui_win *win = NULL;
    struct vrmr_gui_form *form = NULL;
    int ch = 0, result = 0;
    struct shape_rule_cnf config;

    VrShapeRuleSetup(&config, opt);

    /* create the window and put it in the middle of the screen */
    win = VrNewWin(16, 51, 0, 0, vccnf.color_win);
    if (win == NULL) {
        vrmr_fatal("VrNewWin failed");
    }
    VrWinSetTitle(win, gettext("Shaping"));

    form = VrNewForm(14, 58, 1, 1, vccnf.color_win, vccnf.color_win | A_BOLD);

    VrFormSetSaveFunc(form, VrShapeRuleSave, &config);

    VrFormAddLabelField(form, 1, 25, 1, 1, vccnf.color_win,
            gettext("Incoming guaranteed rate"));
    VrFormAddTextField(form, 1, 10, 1, 28, vccnf.color_win_rev | A_BOLD,
            "in_min", config.in_min);
    VrFormAddTextField(form, 1, 5, 1, 41, vccnf.color_win_rev | A_BOLD, "unit1",
            config.in_min_unit);
    VrFormAddLabelField(form, 1, 25, 3, 1, vccnf.color_win,
            gettext("Incoming maximum rate"));
    VrFormAddTextField(form, 1, 10, 3, 28, vccnf.color_win_rev | A_BOLD,
            "in_max", config.in_max);
    VrFormAddTextField(form, 1, 5, 3, 41, vccnf.color_win_rev | A_BOLD, "unit2",
            config.in_max_unit);

    VrFormAddLabelField(form, 1, 25, 5, 1, vccnf.color_win,
            gettext("Outgoing guaranteed rate"));
    VrFormAddTextField(form, 1, 10, 5, 28, vccnf.color_win_rev | A_BOLD,
            "out_min", config.out_min);
    VrFormAddTextField(form, 1, 5, 5, 41, vccnf.color_win_rev | A_BOLD, "unit3",
            config.out_min_unit);
    VrFormAddLabelField(form, 1, 25, 7, 1, vccnf.color_win,
            gettext("Outgoing maximum rate"));
    VrFormAddTextField(form, 1, 10, 7, 28, vccnf.color_win_rev | A_BOLD,
            "out_max", config.out_max);
    VrFormAddTextField(form, 1, 5, 7, 41, vccnf.color_win_rev | A_BOLD, "unit4",
            config.out_max_unit);

    VrFormAddLabelField(
            form, 1, 25, 9, 1, vccnf.color_win, gettext("Priority"));
    VrFormAddTextField(form, 1, 5, 9, 28, vccnf.color_win_rev | A_BOLD, "prio",
            config.prio);

    VrFormConnectToWin(form, win);
    VrFormPost(form);
    update_panels();
    doupdate();

    /* user input */
    char quit = FALSE;
    while (quit == FALSE) {
        VrFormDrawMarker(win, form);

        ch = VrWinGetch(win);

        /* check OK/Cancel buttons */
        result = VrFormCheckOKCancel(form, ch);
        if (result == -1 || result == 1) {
            break;
        }

        char *b = field_buffer(form->cur, 1);
        if (ch == 32 &&
                (strcmp(b, "unit1") == 0 || strcmp(b, "unit2") == 0 ||
                        strcmp(b, "unit3") == 0 || strcmp(b, "unit4") == 0)) {
            int h, w, i;
            field_info(form->cur, &i, &i, &h, &w, &i, &i);

            char *u = VrShapeUnitMenu(field_buffer(form->cur, 0),
                    h + 2 + win->y, w - 1 + win->x, /* draw bps */ 1);
            vrmr_debug(NONE, "u %s", u);
            if (u) {
                set_field_buffer_wrap(form->cur, 0, u);
                free(u);
            }
        } else if (VrFormDefaultNavigation(form, ch) == FALSE) {
            switch (ch) {
                case KEY_DOWN:
                case 10: // enter
                    form_driver_wrap(form->f, REQ_NEXT_FIELD);
                    form_driver_wrap(form->f, REQ_BEG_LINE);
                    break;
                case 27:
                case 'q':
                case 'Q':
                case KEY_F(10):
                    quit = TRUE;
                    break;
                case KEY_F(12):
                case 'h':
                case 'H':
                case '?':
                    print_help(":[VUURMUUR:RULES:SHAPE]:");
                    break;
            }
        }
    }

    VrFormUnPost(form);
    VrDelForm(form);
    VrDelWin(win);
    update_panels();
    doupdate();
}

#define FIELDS_PER_BAR 8

#define MIN_ACTIVE 4
#define MIN_NUMFIELD 4
#define MIN_ACTION 8
#define MIN_SERVICE 9
#define MIN_FROM 18
#define MIN_TO 18
#define MIN_OPTIONS 14

#define MAX_ACTIVE 4
#define MAX_NUMFIELD 4
#define MAX_ACTION 10
#define VRMR_MAX_SERVICE 32
#define MAX_FROM 96     // TODO
#define MAX_TO 96       // TODO
#define MAX_OPTIONS 256 // TODO

/*  rulebar

    Container for pointers to fields.
*/
struct rulebar {
    unsigned int bar_num;

    /* pointers the the fields */
    FIELD *active;
    FIELD *num_field;
    FIELD *action;
    FIELD *service;
    FIELD *from;
    FIELD *to;
    FIELD *options;

    FIELD *separator;
};

struct rulebar_form {
    struct vrmr_list RuleBar_list;

    unsigned int bars;

    unsigned int max_bars_on_screen;
    unsigned int filtered_rules;

    unsigned int printable_rules;
    unsigned int scroll_offset;

    /* for regex filtering */
    regex_t filter_reg;
    char use_filter;

    /* some more filtering */
    char show_only_forward, show_only_input, show_only_output;

    /* field sizes */
    size_t active_size;
    size_t num_field_size;
    size_t action_size;
    size_t service_size;
    size_t from_size;
    size_t to_size;
    size_t options_size;
    size_t separator_size;

    /* for the (more) indicator when not all rules fit on screen */
    PANEL *more_pan[1];
    WINDOW *more_win;
};

static void SetupRuleBarForm(
        struct rulebar_form *, unsigned int, struct vrmr_rules *, int);
static void move_rule(struct vrmr_rules *, unsigned int, unsigned int);
static int delete_rule(struct vrmr_rules *, unsigned int, int);
static bool rules_match_filter(const struct vrmr_rule *rule_ptr,
        /*@null@*/ regex_t *reg, bool only_ingress, bool only_egress,
        bool only_forward);
static void Toggle_RuleBar(struct rulebar *bar, struct vrmr_rules *rules);
static void draw_rules(struct vrmr_rules *, struct rulebar_form *);
static int Enter_RuleBar(struct rulebar *, struct vrmr_config *,
        struct vrmr_rules *, struct vrmr_zones *, struct vrmr_interfaces *,
        struct vrmr_services *, struct vrmr_regex *);
static int edit_rule_separator(struct vrmr_rule *, struct vrmr_regex *);
static void insert_new_rule(
        struct vrmr_rules *rules, unsigned int rule_num, const char *action);

static void SetupRuleBarForm(struct rulebar_form *rbform,
        unsigned int max_bars_on_screen, struct vrmr_rules *rules,
        int screen_width)
{
    size_t sum = 0, i = 0;

    /* safety checks */
    vrmr_fatal_if_null(rbform);
    vrmr_fatal_if_null(rules);
    vrmr_fatal_if(max_bars_on_screen <= 0);
    vrmr_fatal_if(screen_width <= 0);

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
    vrmr_list_setup(&rbform->RuleBar_list, free);

    /* calculate field sizes */
    rbform->active_size = MIN_ACTIVE;
    rbform->num_field_size = MIN_NUMFIELD;
    rbform->action_size = MIN_ACTION;
    rbform->service_size = MIN_SERVICE;
    rbform->from_size = MIN_FROM;
    rbform->to_size = MIN_TO;
    rbform->options_size = MIN_OPTIONS;

    sum = rbform->active_size + rbform->num_field_size + rbform->action_size +
          rbform->service_size + rbform->from_size + rbform->to_size +
          rbform->options_size;
    vrmr_fatal_if((int)sum > screen_width);

    while ((int)sum <= screen_width) {
        for (i = 0; (int)sum <= screen_width && i < 6; i++) {
            if (i == 0 && rbform->action_size < MAX_ACTION)
                rbform->action_size++;
            else if (i == 1 && rbform->service_size < VRMR_MAX_SERVICE)
                rbform->service_size++;
            else if (i == 2 && rbform->from_size < MAX_FROM)
                rbform->from_size++;
            else if (i == 3 && rbform->to_size < MAX_TO)
                rbform->to_size++;
            else if (i == 5 && rbform->options_size)
                rbform->options_size++;

            sum = rbform->active_size + rbform->num_field_size +
                  rbform->action_size + rbform->service_size +
                  rbform->from_size + rbform->to_size + rbform->options_size;
        }
    }

    vrmr_debug(HIGH, "success.");
    return;
}

static void move_rule(
        struct vrmr_rules *rules, unsigned int rule_num, unsigned int new_place)
{
    int i = 0;
    struct vrmr_rule *rule_ptr = NULL;

    vrmr_fatal_if_null(rules);

    status_print(status_win, gettext("Moving rule..."));

    /* santiy check for new_place */
    if (new_place > rules->list.len) {
        new_place = rules->list.len;
    } else if (new_place == 0) {
        new_place = 1;
    }

    rule_ptr = vrmr_rules_remove_rule_from_list(rules, rule_num, 1);
    if (rule_ptr == NULL) {
        vrmr_fatal("vrmr_rules_remove_rule_from_list failed");
    }

    vrmr_debug(HIGH, "rule_ptr found: i: %d (rule_ptr: %s %s %s %s)", i,
            vrmr_rules_itoaction(rule_ptr->action), rule_ptr->service,
            rule_ptr->from, rule_ptr->to);

    rule_ptr->number = new_place;

    vrmr_debug(HIGH, "new_place: %d, rule_ptr->number: %d", new_place,
            rule_ptr->number);

    vrmr_rules_insert_list(rules, new_place, rule_ptr);

    if (vrmr_debug_level >= LOW)
        vrmr_rules_print_list(rules);
    return;
}

/*  Move_RuleBarForm

    display a screen TODO
*/
static void MoveRuleBarForm(struct vrmr_rules *rules, unsigned int cur_rule)
{
    int ch, quit = 0;
    WINDOW *move_win;
    PANEL *panels[1];
    FIELD **fields;
    FORM *form;

    vrmr_fatal_if_null(rules);
    vrmr_fatal_if(cur_rule == 0);

    // create window, panel, fields, form and post it
    move_win = create_newwin(6, 40, (LINES - 6) / 2, (COLS - 40) / 2,
            gettext("Move Rule"), vccnf.color_win);
    vrmr_fatal_if_null(move_win);
    keypad(move_win, TRUE);
    panels[0] = new_panel(move_win);

    fields = (FIELD **)calloc(1 + 1, sizeof(FIELD *));
    vrmr_fatal_alloc("calloc", fields);
    fields[0] = new_field_wrap(1, 5, 1, 28, 0, 0);
    set_field_type(fields[0], TYPE_INTEGER, 5, 1, 99999);
    fields[1] = NULL;

    set_field_back(fields[0], vccnf.color_win_rev);
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
    mvwprintw(move_win, 4, 2, gettext("Cur: %d, Min: 1, Max: %d"), cur_rule,
            rules->list.len);

    vrmr_debug(HIGH, "cur_rule: %d, rules->list.len: %d.", cur_rule,
            rules->list.len);

    update_panels();
    doupdate();

    while (quit == 0) {
        // get user input
        ch = wgetch(move_win);

        switch (ch) {
            case 10: // enter
                form_driver_wrap(form, REQ_VALIDATION);

                move_rule(rules, cur_rule,
                        (unsigned int)atoi(field_buffer(fields[0], 0)));

                quit = 1;
                break;

            case KEY_BACKSPACE:
            case 127:
                form_driver_wrap(form, REQ_PREV_CHAR);
                form_driver_wrap(form, REQ_DEL_CHAR);
                form_driver_wrap(form, REQ_END_LINE);
                break;

            case KEY_DC:
                form_driver_wrap(form, REQ_PREV_CHAR);
                form_driver_wrap(form, REQ_DEL_CHAR);
                form_driver_wrap(form, REQ_END_LINE);
                break;

            case 27:
            case KEY_F(10):
            case 'q':
            case 'Q':
                quit = 1;
                break;

            default:
                form_driver_wrap(form, ch);
                break;
        }
    }

    /* cleanup */
    unpost_form(form);
    free_form(form);
    free_field(fields[0]);
    free(fields);
    del_panel(panels[0]);
    destroy_win(move_win);
    update_panels();
    doupdate();
}

static struct rulebar *CurrentBar(struct rulebar_form *rbform, FORM *form)
{
    FIELD *cur_field = NULL;
    struct rulebar *cur_bar = NULL;
    struct vrmr_list_node *d_node = NULL;

    vrmr_fatal_if_null(rbform);
    vrmr_fatal_if_null(form);

    /* get the current field */
    cur_field = current_field(form);
    /* look for the current bar */
    for (d_node = rbform->RuleBar_list.top; d_node; d_node = d_node->next) {
        cur_bar = d_node->data;
        vrmr_fatal_if_null(cur_bar);

        if (cur_bar->active == cur_field)
            return (cur_bar);
        //        else if(cur_bar->separator == cur_field)
        //            return(cur_bar);
    }

    vrmr_error(-1, VR_INTERR, "bar not found.");
    return (NULL);
}

static void rulebar_setcolor(FIELD *active, FIELD *num_field, FIELD *action,
        FIELD *service, FIELD *from, FIELD *to, FIELD *options,
        FIELD *separator, int hi)
{
    if (hi) {
        set_field_back(active, (chtype)COLOR_PAIR(CP_RULE_BAR));
        set_field_back(num_field, (chtype)COLOR_PAIR(CP_RULE_BAR));
        set_field_back(action, (chtype)COLOR_PAIR(CP_RULE_BAR));
        set_field_back(service, (chtype)COLOR_PAIR(CP_RULE_BAR));
        set_field_back(from, (chtype)COLOR_PAIR(CP_RULE_BAR));
        set_field_back(to, (chtype)COLOR_PAIR(CP_RULE_BAR));
        set_field_back(options, (chtype)COLOR_PAIR(CP_RULE_BAR));
        set_field_back(separator, (chtype)COLOR_PAIR(CP_RULE_BAR));
        return;
    }

    if (!(strncmp(field_buffer(active, 0), "[x]", 3) == 0)) {
        set_field_back(active, vccnf.color_bgd);
        set_field_back(num_field, vccnf.color_bgd);
        set_field_back(action, vccnf.color_bgd);
        set_field_back(service, vccnf.color_bgd);
        set_field_back(from, vccnf.color_bgd);
        set_field_back(to, vccnf.color_bgd);
        set_field_back(options, vccnf.color_bgd);
        set_field_back(separator, vccnf.color_bgd);
        return;
    }

    /* active */
    set_field_back(active, vccnf.color_bgd);

    /* num_field */
    set_field_back(num_field, vccnf.color_bgd);

    /* action */
    if (strncasecmp(field_buffer(action, 0), "drop", 4) == 0)
        set_field_back(action, vccnf.color_bgd_red | A_BOLD);
    else if (strncasecmp(field_buffer(action, 0), "reject", 6) == 0)
        set_field_back(action, vccnf.color_bgd_red);
    else if (strncasecmp(field_buffer(action, 0), "accept", 6) == 0)
        set_field_back(action, vccnf.color_bgd_green | A_BOLD);
    else if (strncasecmp(field_buffer(action, 0), "log", 3) == 0 ||
             strncasecmp(field_buffer(action, 0), "nflog", 5) == 0)
        set_field_back(action, vccnf.color_bgd | A_BOLD);
    else if (strncasecmp(field_buffer(action, 0), "portfw", 6) == 0 ||
             strncasecmp(field_buffer(action, 0), "dnat", 4) == 0 ||
             strncasecmp(field_buffer(action, 0), "bounce", 6) == 0 ||
             strncasecmp(field_buffer(action, 0), "snat", 4) == 0 ||
             strncasecmp(field_buffer(action, 0), "masq", 4) == 0 ||
             strncasecmp(field_buffer(action, 0), "redirect", 8) == 0)
        set_field_back(action, vccnf.color_bgd_yellow | A_BOLD);
    else if (strncasecmp(field_buffer(action, 0), "nfqueue", 7) == 0)
        set_field_back(action, vccnf.color_bgd | A_BOLD);
    else if (strncasecmp(field_buffer(action, 0), "chain", 5) == 0)
        set_field_back(action, vccnf.color_bgd | A_BOLD);
    else
        set_field_back(action, vccnf.color_bgd);

    /* service */
    set_field_back(service, vccnf.color_bgd_cyan | A_BOLD);

    /* from zone or firewall */
    if (strncasecmp(field_buffer(from, 0), "firewall", 8) == 0)
        set_field_back(from, vccnf.color_bgd_yellow | A_BOLD);
    else
        set_field_back(from, vccnf.color_bgd | A_BOLD);

    if (strncasecmp(field_buffer(to, 0), "firewall", 8) == 0)
        set_field_back(to, vccnf.color_bgd_yellow | A_BOLD);
    else
        set_field_back(to, vccnf.color_bgd | A_BOLD);

    // options field
    set_field_back(options, vccnf.color_bgd);

    /* separator */
    set_field_back(separator, vccnf.color_bgd);
}

/*
    Highlights the cursor, and clears the previous highlight.
 */
static void HighlightRuleBar(struct rulebar *bar)
{
    vrmr_fatal_if_null(bar);

    rulebar_setcolor(bar->active, bar->num_field, bar->action, bar->service,
            bar->from, bar->to, bar->options, bar->separator, /* hilight */ 1);
}

/*

    Returncodes:
         1: changed rule
         0: no changes
        -1: error
*/
static int Enter_RuleBar(struct rulebar *bar, struct vrmr_config *conf,
        struct vrmr_rules *rules, struct vrmr_zones *zones,
        struct vrmr_interfaces *interfaces, struct vrmr_services *services,
        struct vrmr_regex *reg)
{
    unsigned int rule_num = 0;
    int result = 0, retval = 0;
    struct vrmr_rule *rule_ptr = NULL;

    /* safety */
    vrmr_fatal_if_null(bar);
    vrmr_fatal_if_null(rules);
    vrmr_fatal_if_null(reg);

    vrmr_debug(HIGH, "field_buffer = '%s'.", field_buffer(bar->num_field, 0));

    rule_num = (unsigned int)atoi(field_buffer(bar->num_field, 0));
    if (rule_num <= 0) /* empty rule form */
        return 0;

    result = edit_rule(conf, rules, zones, interfaces, services, rule_num, reg);
    if (result < 0) {
        /* editting failed so remove the rule again */
        rule_ptr = vrmr_rules_remove_rule_from_list(rules, rule_num, 1);
        vrmr_fatal_if_null(rule_ptr);
        vrmr_rules_free_options(rule_ptr->opt);
        rule_ptr->opt = NULL;
        free(rule_ptr);
        rule_ptr = NULL;

        retval = -1;
    } else if (result == 1) {
        retval = 1;
    }

    return (retval);
}

static void rules_duplicate_rule(struct vrmr_rules *rules,
        struct vrmr_rule *org_rule_ptr, struct vrmr_regex *reg)
{
    char *rule_str = NULL;
    struct vrmr_rule *new_rule_ptr = NULL;

    /* safety */
    vrmr_fatal_if_null(rules);
    vrmr_fatal_if_null(org_rule_ptr);
    vrmr_fatal_if_null(reg);

    /* get the rulestring */
    rule_str = vrmr_rules_assemble_rule(org_rule_ptr);
    vrmr_fatal_if_null(rule_str);

    /* claim memory for the new rule*/
    new_rule_ptr = vrmr_rule_malloc();
    vrmr_fatal_alloc("vrmr_rule_malloc", new_rule_ptr);

    /* parse the line */
    vrmr_fatal_if(vrmr_rules_parse_line(rule_str, new_rule_ptr, reg) != 0);

    free(rule_str);
    rule_str = NULL;

    /* this rules number is one higher than the original */
    new_rule_ptr->number = org_rule_ptr->number + 1;

    /* insert the new rule into the list */
    vrmr_fatal_if(
            vrmr_rules_insert_list(rules, new_rule_ptr->number, new_rule_ptr));
}

/*
    orig_rule_num is the number of the rule to be copied. Thus,
    the new rule will get number orig_rule_num + 1
*/
static void rulebar_copy_rule(struct vrmr_rules *rules,
        unsigned int orig_rule_num, struct vrmr_regex *reg)
{
    struct vrmr_rule *rule_ptr = NULL;
    struct vrmr_list_node *d_node = NULL;

    /* safety */
    vrmr_fatal_if_null(rules);
    vrmr_fatal_if_null(reg);

    for (d_node = rules->list.top; d_node; d_node = d_node->next) {
        vrmr_fatal_if_null(d_node->data);
        rule_ptr = d_node->data;

        if (rule_ptr->number == orig_rule_num)
            break;
    }
    vrmr_fatal_if_null(rule_ptr);

    rules_duplicate_rule(rules, rule_ptr, reg);
}

/*
 */
static void Toggle_RuleBar(struct rulebar *bar, struct vrmr_rules *rules)
{
    int rule_num = 0;
    int i = 0;
    struct vrmr_list_node *d_node = NULL;
    struct vrmr_rule *rule_ptr = NULL;

    vrmr_debug(HIGH, "'%s'.", field_buffer(bar->num_field, 0));

    rule_num = atoi(field_buffer(bar->num_field, 0));
    vrmr_fatal_if(rule_num <= 0);

    vrmr_fatal_if(rules->list.len == 0);
    vrmr_fatal_if_null(rules->list.top);
    d_node = rules->list.top;

    /* look for the rule_ptr */
    for (i = 1; i <= rule_num; i++) {
        vrmr_fatal_if_null(d_node);
        vrmr_fatal_if_null(d_node->data);
        rule_ptr = d_node->data;

        d_node = d_node->next;
    }

    vrmr_debug(HIGH, "active: %s (%s %s %s %s)",
            rule_ptr->active ? "Yes" : "No",
            vrmr_rules_itoaction(rule_ptr->action), rule_ptr->service,
            rule_ptr->from, rule_ptr->to);

    /* set the active */
    if (rule_ptr->active == 1)
        rule_ptr->active = 0;
    else
        rule_ptr->active = 1;

    return;
}

/*  Set_RuleBar

    Sets the rulebar to the position 'pos'.
*/
static void Set_RuleBar(
        struct rulebar_form *rbform, FORM *form, unsigned int pos)
{
    struct vrmr_list_node *d_node = NULL;
    struct rulebar *cur_bar = NULL;
    unsigned int i = 0;
    int result = 0;

    for (i = 1, d_node = rbform->RuleBar_list.top; d_node;
            i++, d_node = d_node->next) {
        vrmr_fatal_if_null(d_node->data);
        cur_bar = d_node->data;

        if (i == pos) {
            vrmr_debug(HIGH, "field found");

            result = set_current_field(form, cur_bar->active);

            if (vrmr_debug_level >= HIGH) {
                if (result == E_OK)
                    vrmr_debug(NONE, "field found: E_OK");
                else if (result == E_SYSTEM_ERROR)
                    vrmr_debug(NONE, "field found: E_SYSTEM_ERROR: %s",
                            strerror(errno));
                else if (result == E_BAD_ARGUMENT)
                    vrmr_debug(NONE, "field found: E_BAD_ARGUMENT");
                else
                    vrmr_debug(NONE, "field found: unknown result %d", result);
            }
        }
    }
}

static void Insert_RuleBar(struct rulebar_form *rbform, FIELD *active,
        FIELD *num_field, FIELD *action, FIELD *service, FIELD *from, FIELD *to,
        FIELD *options, FIELD *separator)
{
    struct rulebar *bar;

    /* alloc mem */
    bar = malloc(sizeof(*bar));
    vrmr_fatal_alloc("malloc", bar);

    bar->active = active;
    bar->num_field = num_field;
    bar->action = action;
    bar->service = service;
    bar->from = from;
    bar->to = to;
    bar->options = options;
    bar->separator = separator;

    /* insert the bar into the list */
    if (!(vrmr_list_append(&rbform->RuleBar_list, bar))) {
        vrmr_fatal("vrmr_list_append");
    }

    rbform->bars++;
    bar->bar_num = rbform->bars;

    vrmr_debug(HIGH, "success at %p (bars: %d, bar->num: %d).", bar,
            rbform->bars, bar->bar_num);
    return;
}

/** \internal
 *  \brief match rule against filter
 *  \retval bool return true if rule is within the filter
 */
static bool rules_match_filter(const struct vrmr_rule *rule_ptr,
        /*@null@*/ regex_t *reg, bool only_ingress, bool only_egress,
        bool only_forward)
{
    // char *options_ptr = NULL;
    char rule_str[512] = "";

    if (only_ingress) {
        if (strcmp(rule_ptr->to, "firewall") != 0)
            return false;
    } else if (only_egress) {
        if (strcmp(rule_ptr->from, "firewall") != 0)
            return false;
    } else if (only_forward) {
        if (strcmp(rule_ptr->from, "firewall") == 0 ||
                strcmp(rule_ptr->to, "firewall") == 0)
            return false;
    }

    /* if we're not using a regex, we match here */
    if (!reg)
        return true;

    (void)strlcpy(
            rule_str, vrmr_rules_itoaction(rule_ptr->action), sizeof(rule_str));
    (void)strlcat(rule_str, " ", sizeof(rule_str));
    (void)strlcat(rule_str, rule_ptr->service, sizeof(rule_str));
    (void)strlcat(rule_str, " ", sizeof(rule_str));
    (void)strlcat(rule_str, rule_ptr->from, sizeof(rule_str));
    (void)strlcat(rule_str, " ", sizeof(rule_str));
    (void)strlcat(rule_str, rule_ptr->to, sizeof(rule_str));
    //(void)strlcat(rule_str, " ", sizeof(rule_str));
    // if(options_ptr != NULL)
    //    (void)strlcat(rule_str, options_ptr, sizeof(rule_str));

    /* now filter */
    int result = regexec(reg, rule_str, 0, NULL, 0);
    if (result == 0)
        return true;
    else
        return false;
}

static void draw_rules(struct vrmr_rules *rules, struct rulebar_form *rbform)
{
    struct vrmr_rule *rule_ptr = NULL;
    struct rulebar *cur_bar = NULL;
    struct vrmr_list_node *d_node = NULL;
    struct vrmr_list_node *dl_node = NULL;

    unsigned int draw_count = 0, printable_lines = 0, filtered_rules = 0;

    char number[MAX_NUMFIELD] = "", active[MAX_ACTIVE] = "",
         action[MAX_ACTION] = "", service[VRMR_MAX_SERVICE] = "",
         from[MAX_FROM] = "", to[MAX_TO] = "", *option_str = NULL,
         options[MAX_OPTIONS] = "", separator_str[256] = "";

    size_t i = 0, x = 0;

    char sep = FALSE, bot_visible = FALSE;

    size_t before_len = 0;

    for (dl_node = rules->list.top, d_node = rbform->RuleBar_list.top;
            dl_node && draw_count < rbform->max_bars_on_screen && d_node;
            dl_node = dl_node->next) {
        vrmr_fatal_if_null(dl_node->data);
        rule_ptr = dl_node->data;
        /* get the bar */
        vrmr_fatal_if_null(d_node->data);
        cur_bar = d_node->data;

        /*  if the last item in the list is visible, we will hide
            the (more) panel below */
        if (vrmr_list_node_is_bot(dl_node))
            bot_visible = TRUE;

        if (rule_ptr->action == VRMR_AT_SEPARATOR) {
            field_opts_off(cur_bar->action, O_VISIBLE);
            field_opts_off(cur_bar->service, O_VISIBLE);
            field_opts_off(cur_bar->from, O_VISIBLE);
            field_opts_off(cur_bar->to, O_VISIBLE);
            field_opts_off(cur_bar->options, O_VISIBLE);

            field_opts_on(cur_bar->separator, O_VISIBLE);
            sep = TRUE;
        } else {
            field_opts_on(cur_bar->action, O_VISIBLE);
            field_opts_on(cur_bar->service, O_VISIBLE);
            field_opts_on(cur_bar->from, O_VISIBLE);
            field_opts_on(cur_bar->to, O_VISIBLE);
            field_opts_on(cur_bar->options, O_VISIBLE);

            field_opts_off(cur_bar->separator, O_VISIBLE);
            sep = FALSE;
        }

        /* test if the rules fits in the filter */
        if (rule_ptr->filtered == 0) {
            printable_lines++;

            if (printable_lines > rbform->scroll_offset) {
                if (sep == FALSE) {
                    /* note if you change the [x] into something else, also
                     * change it in rulebar_setcolor */
                    snprintf(active, rbform->active_size, "%s",
                            rule_ptr->active ? "[x]" : "[ ]");
                    snprintf(action, rbform->action_size, "%s",
                            vrmr_rules_itoaction(rule_ptr->action));
                    snprintf(service, rbform->service_size, "%s",
                            rule_ptr->service);
                    strlcpy(from, rule_ptr->from, rbform->from_size);
                    strlcpy(to, rule_ptr->to, rbform->to_size);

                    if (!(option_str = vrmr_rules_assemble_options_string(
                                  rule_ptr->opt,
                                  vrmr_rules_itoaction(rule_ptr->action))))
                        strcpy(options, "-");
                    else {
                        /* cut off: 'options:' */
                        char *options_start = option_str + 8;
                        strlcpy(options, options_start, sizeof(options));
                        free(option_str);
                        option_str = NULL;
                    }

                    /* set the bufers */
                    set_field_buffer_wrap(cur_bar->active, 0, active);
                    set_field_buffer_wrap(cur_bar->action, 0, action);
                    set_field_buffer_wrap(cur_bar->service, 0, service);
                    set_field_buffer_wrap(cur_bar->from, 0, from);
                    set_field_buffer_wrap(cur_bar->to, 0, to);
                    set_field_buffer_wrap(cur_bar->options, 0, options);
                }
                /* separator */
                else {
                    memset(separator_str, '-', sizeof(separator_str));
                    separator_str[rbform->separator_size - 1] = '\0';

#ifdef USE_WIDEC
                    if (rule_ptr->opt != NULL &&
                            rule_ptr->opt->comment[0] != '\0') {
                        size_t wcomment_len = 0;
                        wchar_t wstr[256] = L"";

                        wcomment_len = StrLen(rule_ptr->opt->comment);

                        before_len =
                                (rbform->separator_size - (wcomment_len + 4)) /
                                2;

                        wmemset(wstr, L'-', sizeof(wstr) / sizeof(wchar_t));

                        if (wcomment_len > 0) {
                            wstr[before_len] = L'[';
                            wstr[before_len + 1] = L' ';

                            /* convert to wide */
                            wchar_t wtmp[wcomment_len + 1];
                            mbstowcs(wtmp, rule_ptr->opt->comment,
                                    wcomment_len + 1);

                            for (i = before_len + 2, x = 0;
                                    // - 2 so we can add ' ]' below
                                    i < sizeof(wstr) / sizeof(wchar_t) - 2 &&
                                    x < wcomment_len;
                                    i++, x++) {
                                wstr[i] = wtmp[x];
                            }
                            wstr[i] = L' ';
                            wstr[i + 1] = L']';
                        }
                        /* convert back to multi byte */
                        wcstombs(separator_str, wstr, sizeof(separator_str));

                        set_field_buffer_wrap(
                                cur_bar->separator, 0, separator_str);
                    } else {
                        set_field_buffer_wrap(
                                cur_bar->separator, 0, separator_str);
                    }
#else  /* USE_WIDEC */
                    if (rule_ptr->opt != NULL &&
                            rule_ptr->opt->comment[0] != '\0') {
                        size_t comment_len = StrLen(rule_ptr->opt->comment);

                        before_len =
                                (rbform->separator_size - (comment_len + 4)) /
                                2;
                        separator_str[before_len] = '[';
                        separator_str[before_len + 1] = ' ';

                        for (i = before_len + 2, x = 0;
                                i < rbform->separator_size &&
                                i < sizeof(separator_str) - 2 &&
                                x < comment_len;
                                i++, x++) {
                            separator_str[i] = rule_ptr->opt->comment[x];
                        }
                        separator_str[i] = ' ';
                        separator_str[i + 1] = ']';

                        set_field_buffer_wrap(
                                cur_bar->separator, 0, separator_str);
                    } else {
                        set_field_buffer_wrap(
                                cur_bar->separator, 0, separator_str);
                    }
#endif /* USE_WIDEC */
                    /* clear */
                    memset(active, 0, rbform->active_size);
                    set_field_buffer_wrap(cur_bar->active, 0, active);
                }

                snprintf(number, rbform->num_field_size, "%2u",
                        printable_lines + filtered_rules);
                set_field_buffer_wrap(cur_bar->num_field, 0, number);

                draw_count++;

                /* colorize the bar */
                rulebar_setcolor(cur_bar->active, cur_bar->num_field,
                        cur_bar->action, cur_bar->service, cur_bar->from,
                        cur_bar->to, cur_bar->options, cur_bar->separator,
                        /* clear */ 0);

                /* point to the next bar */
                d_node = d_node->next;
            }
        } else {
            filtered_rules++;
        }
    }

    /* clear the remaining bars (if any) */
    for (; draw_count < rbform->max_bars_on_screen && d_node;
            draw_count++, d_node = d_node->next) {
        vrmr_fatal_if_null(d_node->data);
        cur_bar = d_node->data;

        set_field_buffer_wrap(cur_bar->active, 0, "");
        set_field_buffer_wrap(cur_bar->num_field, 0, "");
        set_field_buffer_wrap(cur_bar->action, 0, "");
        set_field_buffer_wrap(cur_bar->service, 0, "");
        set_field_buffer_wrap(cur_bar->from, 0, "");
        set_field_buffer_wrap(cur_bar->to, 0, "");
        set_field_buffer_wrap(cur_bar->options, 0, "");
        set_field_buffer_wrap(cur_bar->separator, 0, "");

        rulebar_setcolor(cur_bar->num_field, cur_bar->active, cur_bar->action,
                cur_bar->service, cur_bar->from, cur_bar->to, cur_bar->options,
                cur_bar->separator, /* clear */ 0);
    }

    /* don' t show (more) panel if list size is 0 */
    if (bot_visible == TRUE || rules->list.len == 0)
        hide_panel(rbform->more_pan[0]);
    else
        show_panel(rbform->more_pan[0]);

    /* finally update the screen */
    update_panels();
    doupdate();
    return;
}

static void rules_update_filter(
        struct vrmr_rules *rules, struct rulebar_form *rbform)
{
    struct vrmr_rule *rule_ptr = NULL;
    struct vrmr_list_node *d_node = NULL;
    char filter = 0;

    /* count the number of lines that are filtered */
    if (rbform->use_filter || rbform->show_only_input ||
            rbform->show_only_output || rbform->show_only_forward) {
        rbform->filtered_rules = 0;

        for (d_node = rules->list.top; d_node; d_node = d_node->next) {
            rule_ptr = d_node->data;
            vrmr_fatal_if_null(rule_ptr);

            rule_ptr->filtered = 0;

            if (rbform->use_filter) {
                filter = rules_match_filter(rule_ptr, &rbform->filter_reg,
                        rbform->show_only_input, rbform->show_only_output,
                        rbform->show_only_forward);
                if (filter == 1)
                    rule_ptr->filtered = 0;
                else
                    rule_ptr->filtered = 1;
            } else {
                filter = rules_match_filter(rule_ptr, NULL,
                        rbform->show_only_input, rbform->show_only_output,
                        rbform->show_only_forward);
                if (filter == 1)
                    rule_ptr->filtered = 0;
                else
                    rule_ptr->filtered = 1;
            }

            if (rule_ptr->filtered == 1) {
                rbform->filtered_rules++;
            }
        }
    } else {
        rbform->filtered_rules = 0;

        for (d_node = rules->list.top; d_node; d_node = d_node->next) {
            rule_ptr = d_node->data;
            vrmr_fatal_if_null(rule_ptr);
            rule_ptr->filtered = 0;
        }
    }
}

/*  rules_form

    Returncodes:
        0: ok
        -1: error
*/
int rules_form(struct vrmr_ctx *vctx, struct vrmr_rules *rules,
        struct vrmr_zones *zones, struct vrmr_interfaces *interfaces,
        struct vrmr_services *services, struct vrmr_regex *reg)
{
    WINDOW *rules_win;
    PANEL *panels[1];
    FIELD **fields;
    FORM *form;
    int rows, cols, ch,
            quit = 0, x, field_x,
            rules_changed = 0; /* 1 if rules are changed, 0 if not */
    size_t n_fields = 0;
    unsigned int bars = 0, current_bar_num = 1, pgdn_offset = 0,
                 insert_rule_num = 0, cur_rule_num = 0;
    struct rulebar_form *rbform;
    struct rulebar *cur_bar = NULL;

    int max_height = 0, max_width = 0, height = 0, width = 0, startx = 0,
        starty = 0;

    char *filter_ptr = NULL, *filter_string_regex = NULL;

    int result = 0;
    char update_filter = 1; /* do it on start*/

    const char *key_choices[] = {"F12", "INS", "DEL", "RET", "m", "f", "F10"};
    int key_choices_n = 7;
    const char *cmd_choices[] = {gettext("help"), gettext("new"),
            gettext("del"), gettext("edit"), gettext("move"), gettext("filter"),
            gettext("back")};
    int cmd_choices_n = 7;
    struct vrmr_list_node *d_node = NULL;
    struct vrmr_rule *rule_ptr = NULL;
    char *str = NULL;

    /* safety */
    vrmr_fatal_if_null(rules);
    vrmr_fatal_if_null(reg);

    // get the dimentions of the screen
    getmaxyx(stdscr, max_height, max_width);

    // set windowsize and start position
    height = max_height - 6;
    width = max_width; // = minimum screensize - 2
    startx = 0;
    starty = 3;

    // max bars on the screen
    bars = (unsigned int)(max_height - 10);

    /* Create the window to be associated with the menu */
    if (!(rules_win = create_newwin(height, width, starty, startx,
                  gettext("Rules Section"), vccnf.color_win_rev))) {
        vrmr_error(-1, VR_ERR, gettext("creating window failed."));
        return (-1);
    }
    panels[0] = new_panel(rules_win);
    keypad(rules_win, TRUE);

    /* malloc the rbform struct */
    rbform = malloc(sizeof(struct rulebar_form));
    vrmr_fatal_alloc("malloc", rbform);

    /* now set it up */
    SetupRuleBarForm(rbform, bars, rules, width - 4);

    /* create the (more) win+pan */
    rbform->more_win = newwin(1, 6, starty + height - 1, 2);
    vrmr_fatal_if_null(rbform->more_win);
    wbkgd(rbform->more_win, vccnf.color_win_rev);
    rbform->more_pan[0] = new_panel(rbform->more_win);
    /* TRANSLATORS: max 4 chars */
    wprintw(rbform->more_win, "(%s)", gettext("more"));
    hide_panel(rbform->more_pan[0]);

    /* calloc and create the fields */
    n_fields = bars * FIELDS_PER_BAR;
    fields = (FIELD **)calloc(n_fields + 1, sizeof(FIELD *));
    vrmr_fatal_alloc("calloc", fields);

    for (size_t i = 1, field_bar_num = 0, field_y = 2; i <= bars;
            i++, field_y++) {
        for (x = 1, field_x = 0; x <= FIELDS_PER_BAR; x++) {
            /* active field */
            if (x == 1) {
                fields[field_bar_num] = new_field_wrap(
                        1, (int)rbform->active_size, field_y, field_x, 0, 1);
                field_x = field_x + (int)rbform->active_size;
            }
            /* num field */
            else if (x == 2) {
                fields[field_bar_num] = new_field_wrap(
                        1, (int)rbform->num_field_size, field_y, field_x, 0, 1);
                field_x = field_x + (int)rbform->num_field_size;
            }
            /* action field */
            else if (x == 3) {
                fields[field_bar_num] = new_field_wrap(
                        1, (int)rbform->action_size, field_y, field_x, 0, 1);
                field_x = field_x + (int)rbform->action_size;
            }
            /* service field */
            else if (x == 4) {
                fields[field_bar_num] = new_field_wrap(
                        1, (int)rbform->service_size, field_y, field_x, 0, 1);
                field_x = field_x + (int)rbform->service_size;
            }
            /* from field */
            else if (x == 5) {
                fields[field_bar_num] = new_field_wrap(
                        1, (int)rbform->from_size, field_y, field_x, 0, 1);
                field_x = field_x + (int)rbform->from_size;
            }
            /* to field */
            else if (x == 6) {
                fields[field_bar_num] = new_field_wrap(
                        1, (int)rbform->to_size, field_y, field_x, 0, 1);
                field_x = field_x + (int)rbform->to_size;
            }
            /* options field */
            else if (x == 7) {
                fields[field_bar_num] = new_field_wrap(
                        1, (int)rbform->options_size, field_y, field_x, 0, 1);
                field_x = field_x + (int)rbform->options_size;
            } else {
                fields[field_bar_num] =
                        new_field_wrap(1, width - 12, field_y, 8, 0, 1);
                rbform->separator_size = (size_t)(width - 12);
            }

            /* only the first field active */
            if (x > 1)
                field_opts_off(fields[field_bar_num], O_ACTIVE);

            field_bar_num++;
        }

        /* create & insert bar */
        Insert_RuleBar(rbform, fields[field_bar_num - x + 1], /* active */
                fields[field_bar_num - x + 1 + 1],            /* num */
                fields[field_bar_num - x + 2 + 1],            /* action */
                fields[field_bar_num - x + 3 + 1],            /* service */
                fields[field_bar_num - x + 4 + 1],            /* from */
                fields[field_bar_num - x + 5 + 1],            /* to */
                fields[field_bar_num - x + 6 + 1],            /* options */
                fields[field_bar_num - x + 7 + 1]);           /* separator */
    }
    fields[n_fields] = NULL;

    /* set field attr */
    for (unsigned int i = 0; i < (unsigned int)n_fields; i++) {
        // set field options
        set_field_back(fields[i], vccnf.color_win_rev);
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
    wattron(rules_win, vccnf.color_win_rev | A_BOLD);
    /* TRANSLATORS: max 3 chars */
    mvwprintw(rules_win, 1, (int)(2 + rbform->active_size), gettext("Nr."));
    mvwprintw(rules_win, 1,
            (int)(2 + rbform->num_field_size + rbform->active_size),
            gettext("Action"));
    mvwprintw(rules_win, 1,
            (int)(2 + rbform->num_field_size + rbform->active_size +
                    rbform->action_size),
            gettext("Service"));
    mvwprintw(rules_win, 1,
            (int)(2 + rbform->num_field_size + rbform->active_size +
                    rbform->action_size + rbform->service_size),
            gettext("Source"));
    mvwprintw(rules_win, 1,
            (int)(2 + rbform->num_field_size + rbform->active_size +
                    rbform->action_size + rbform->service_size +
                    rbform->from_size),
            gettext("Destination"));
    mvwprintw(rules_win, 1,
            (int)(2 + rbform->num_field_size + rbform->active_size +
                    rbform->action_size + rbform->service_size +
                    rbform->from_size + rbform->to_size),
            gettext("Options"));
    wattroff(rules_win, vccnf.color_win_rev | A_BOLD);

    /* horizontal bar below the labels */
    mvwhline(rules_win, 2, 1, ACS_HLINE, width - 2);

    draw_top_menu(top_win, gettext("Rules"), key_choices_n, key_choices,
            cmd_choices_n, cmd_choices);

    update_panels();
    doupdate();
    wrefresh(rules_win);

    status_print(status_win, gettext("Ready."));

    while (quit == 0) {
        if (update_filter == 1) {
            /* count the number of lines that are filtered */
            (void)rules_update_filter(rules, rbform);
            vrmr_debug(HIGH, "filtered_rules: %d", rbform->filtered_rules);
            update_filter = 0;
        }

        /* calculate the number of printable rules */
        rbform->printable_rules = rules->list.len - rbform->filtered_rules;
        vrmr_debug(HIGH, "printable_rules: %d (current_bar_num: %d)",
                rbform->printable_rules, current_bar_num);

        /* get current bar num */
        cur_bar = CurrentBar(rbform, form);
        current_bar_num = cur_bar->bar_num;
        vrmr_debug(HIGH, "current_bar_num: %d", current_bar_num);

        /* if we filter, position the bar at the top of the list if needed */
        if (rbform->use_filter || rbform->show_only_forward ||
                rbform->show_only_input || rbform->show_only_output) {
            vrmr_debug(HIGH, "see if the bar fits the number of rules");

            if (current_bar_num > rbform->printable_rules) {
                vrmr_debug(HIGH, "no, adjusting");

                Set_RuleBar(rbform, form, rbform->printable_rules);
                rbform->scroll_offset = 0;

                /* we changed the position of the bar */
                cur_bar = CurrentBar(rbform, form);
                current_bar_num = cur_bar->bar_num;
            }
        }

        /*  print the rules

            this will also hide or show the (more) panel
        */
        draw_rules(rules, rbform);

        /* highlight the current bar */
        HighlightRuleBar(cur_bar);

        /* get user input */
        ch = wgetch(rules_win);
        vrmr_debug(HIGH, "user pressed (ch): %d", ch);

        /* now handle it */
        switch (ch) {
            /* to the bottom */
            case 360: /* end */
                if (rbform->printable_rules > rbform->max_bars_on_screen) {
                    vrmr_debug(HIGH,
                            "360 (end): rbform->printable_rules > "
                            "rbform->max_bars_on_screen (%d > %d).",
                            rbform->printable_rules,
                            rbform->max_bars_on_screen);
                    rbform->scroll_offset = rbform->printable_rules -
                                            rbform->max_bars_on_screen;
                    Set_RuleBar(rbform, form, rbform->max_bars_on_screen);
                } else {
                    vrmr_debug(HIGH,
                            "360 (end): rbform->printable_rules <= "
                            "rbform->max_bars_on_screen (%d <= %d).",
                            rbform->printable_rules,
                            rbform->max_bars_on_screen);
                    rbform->scroll_offset = 0;
                    Set_RuleBar(rbform, form, rbform->printable_rules);
                }
                break;

            /* to the top */
            case 262: /* home key */
                rbform->scroll_offset = 0;

                Set_RuleBar(rbform, form, 1);
                break;

            /* half a page up */
            case 339: /* page up */
                for (unsigned int i = 0; i < (rbform->max_bars_on_screen);
                        i++) {
                    if (current_bar_num > 1) {
                        form_driver_wrap(form, REQ_PREV_FIELD);

                        current_bar_num--;
                    } else {
                        if (rbform->scroll_offset > 0)
                            rbform->scroll_offset--;
                    }
                }
                break;

            /* half a page down */
            case 338: /* page down */
                pgdn_offset = 0;

                for (unsigned int i = 0; i < (rbform->max_bars_on_screen);
                        i++) {
                    vrmr_debug(HIGH,
                            "338 (pgdn): current_bar_num : %d, "
                            "rbform->max_bars_on_screen: %d, "
                            "rbform->printable_rules: %d, "
                            "rbform->scroll_offset: %d, "
                            "atoi(field_buffer(cur_bar->num_field,0)): %d, "
                            "pgdn_offset: %d.",
                            current_bar_num, rbform->max_bars_on_screen,
                            rbform->printable_rules, rbform->scroll_offset,
                            atoi(field_buffer(cur_bar->num_field, 0)),
                            pgdn_offset);

                    /* make sure we dont move to the next field if we:
                        1. scroll
                        2. are at the end of a list that is shorter than the
                       number of bars on screen
                    */
                    if (current_bar_num < rbform->max_bars_on_screen &&
                            ((unsigned int)atoi(
                                     field_buffer(cur_bar->num_field, 0)) +
                                    pgdn_offset) < rbform->printable_rules) {
                        vrmr_debug(HIGH,
                                "338 (pgdn): current_bar_num < "
                                "rbform->max_bars_on_screen (%d < %d).",
                                current_bar_num, rbform->max_bars_on_screen);
                        vrmr_debug(HIGH,
                                "338 (pgdn): current_bar_num < printable_rules "
                                "(%d < %d).",
                                current_bar_num, rbform->printable_rules);

                        form_driver_wrap(form, REQ_NEXT_FIELD);
                        current_bar_num++;

                        pgdn_offset++;
                    } else if (current_bar_num == rbform->printable_rules ||
                               current_bar_num + rbform->scroll_offset ==
                                       rbform->printable_rules) {
                        // just do'in nothin'
                        vrmr_debug(HIGH,
                                "338 (pgdn): current_bar_num == "
                                "rbform->printable_rules (%d == %d), OR",
                                current_bar_num, rbform->printable_rules);
                        vrmr_debug(HIGH,
                                "338 (pgdn): "
                                "atoi(field_buffer(cur_bar->num_field,0)) + "
                                "pgdn_offset == rbform->printable_rules (%d + "
                                "%d == %d).",
                                atoi(field_buffer(cur_bar->num_field, 0)),
                                pgdn_offset, rbform->printable_rules);
                    } else {
                        vrmr_debug(HIGH,
                                "338 (pgdn): rbform->scroll_offset: %d.",
                                rbform->scroll_offset);

                        rbform->scroll_offset++;
                    }
                }

                break;

            /* one up */
            case KEY_UP:
                if (current_bar_num > 1)
                    form_driver_wrap(form, REQ_PREV_FIELD);
                else {
                    if (rbform->scroll_offset > 0)
                        rbform->scroll_offset--;
                }

                form_driver_wrap(form, REQ_BEG_LINE);
                break;

            /* one down */
            case KEY_DOWN:
                /* make sure we dont move to the next field if we:
                    1. scroll
                    2. are at the end of a list that is shorter than the number
                   of bars on screen
                */
                if (current_bar_num < rbform->max_bars_on_screen &&
                        current_bar_num < rbform->printable_rules) {
                    vrmr_debug(HIGH,
                            "KEY_DOWN: current_bar_num < "
                            "rbform->max_bars_on_screen (%d < %d).",
                            current_bar_num, rbform->max_bars_on_screen);
                    vrmr_debug(HIGH,
                            "KEY_DOWN: current_bar_num < printable_rules (%d < "
                            "%d).",
                            current_bar_num, rbform->printable_rules);

                    form_driver_wrap(form, REQ_NEXT_FIELD);
                } else if (current_bar_num == rbform->printable_rules ||
                           (unsigned int)atoi(field_buffer(cur_bar->num_field,
                                   0)) == rbform->printable_rules) {
                    /* do nothing, just sit here */
                    vrmr_debug(HIGH,
                            "KEY_DOWN: current_bar_num == printable_rules (%d "
                            "== %d), OR",
                            current_bar_num, rbform->printable_rules);
                    vrmr_debug(HIGH,
                            "KEY_DOWN: "
                            "atoi(field_buffer(cur_bar->num_field,0)) == "
                            "rbform->printable_rules (%d == %d)",
                            atoi(field_buffer(cur_bar->num_field, 0)),
                            rbform->printable_rules);
                } else {
                    vrmr_debug(HIGH,
                            "KEY_DOWN: current_bar_num >= "
                            "rbform->max_bars_on_screen (%d >= %d).",
                            current_bar_num, rbform->max_bars_on_screen);
                    vrmr_debug(HIGH,
                            "KEY_DOWN: current_bar_num >= printable_rules (%d "
                            ">= %d).",
                            current_bar_num, rbform->printable_rules);

                    rbform->scroll_offset++;
                }

                form_driver_wrap(form, REQ_BEG_LINE);
                break;

            case 32: /* spacebar */

                cur_rule_num =
                        (unsigned int)atoi(field_buffer(cur_bar->num_field, 0));
                if (cur_rule_num > 0) {
                    Toggle_RuleBar(cur_bar, rules);
                    rules_changed = 1;
                }
                break;

            /* edit the rule */
            case 10: /* enter key */
            case KEY_RIGHT:
            case 'e':
            case 'E':

                result = Enter_RuleBar(cur_bar, &vctx->conf, rules, zones,
                        interfaces, services, reg);
                if (result == 1) {
                    rules_changed = 1;
                    update_filter = 1;
                }
                /* we have removed the rule from the list, so now we need to
                   make sure that the screen is updated properly */
                else if (result == -1) {
                    /* we removed an existing rule, so the rules are changed */
                    rules_changed = 1;
                    update_filter = 1;

                    /*  if we remove the last rule in a none scrolling list make
                       sure the bar is set to the last rule, otherwise we can
                       scroll of the screen */
                    if (current_bar_num > rbform->printable_rules - 1) {
                        vrmr_debug(HIGH,
                                "edit: current_bar_num > printable_rules - 1 "
                                "(%d > %d).",
                                current_bar_num, rbform->printable_rules - 1);

                        form_driver_wrap(form, REQ_PREV_FIELD);
                    } else {
                        vrmr_debug(HIGH,
                                "edit: current_bar_num <= printable_rules - 1 "
                                "(%d <= %d).",
                                current_bar_num, rbform->printable_rules - 1);
                    }
                }

                draw_top_menu(top_win, gettext("Rules"), key_choices_n,
                        key_choices, cmd_choices_n, cmd_choices);
                break;

            case KEY_DC: /* delete key */
            case 'd':
            case 'D':

                /* delete the rule */
                cur_rule_num =
                        (unsigned int)atoi(field_buffer(cur_bar->num_field, 0));
                if (cur_rule_num > 0) {
                    result = delete_rule(rules, cur_rule_num, 1);
                    if (result == 0) {
                        status_print(
                                status_win, gettext("Delete rule cancelled."));
                    } else {
                        vrmr_info(VR_INFO, gettext("rule %d removed."),
                                atoi(field_buffer(cur_bar->num_field, 0)));

                        rules_changed = 1;
                        update_filter = 1;

                        /* decrease the scroll_offset so we don't scroll of the
                         * list */
                        if (rbform->scroll_offset > 0) {
                            vrmr_debug(HIGH,
                                    "KEY_DC: scroll_offset > 0 (%d) "
                                    "decreasing.",
                                    rbform->scroll_offset);
                            rbform->scroll_offset--;
                        } else {
                            vrmr_debug(HIGH,
                                    "KEY_DC: scroll_offset <= 0 (%d) doing "
                                    "nothing.",
                                    rbform->scroll_offset);
                        }

                        /*  if we remove the last rule in a none scrolling list
                           make sure the bar is set to the last rule */
                        if (current_bar_num > rbform->printable_rules - 1) {
                            vrmr_debug(HIGH,
                                    "KEY_DC: current_bar_num > printable_rules "
                                    "- 1 (%d > %d).",
                                    current_bar_num,
                                    rbform->printable_rules - 1);
                            form_driver_wrap(form, REQ_PREV_FIELD);
                        } else {
                            vrmr_debug(HIGH,
                                    "KEY_DC: current_bar_num <= "
                                    "printable_rules - 1 (%d <= %d).",
                                    current_bar_num,
                                    rbform->printable_rules - 1);
                        }
                    }
                }

                break;

            /* insert separator line */
            case 'l':
            case 'L':

                /* insert a new rule into the list */
                insert_rule_num =
                        (unsigned int)atoi(field_buffer(cur_bar->num_field, 0));
                if (insert_rule_num == 0)
                    insert_rule_num = 1;

                insert_new_rule(rules, insert_rule_num, "Separator");

                rules_changed = 1;
                update_filter = 1;

                break;

            /* insert a new rule */
            case KEY_IC: /* insert key */
            case 'i':
            case 'I':

                /* insert a new rule into the list */
                insert_rule_num =
                        (unsigned int)atoi(field_buffer(cur_bar->num_field, 0));
                if (insert_rule_num == 0)
                    insert_rule_num = 1;

                insert_new_rule(rules, insert_rule_num, "Drop");

                /* now edit the rule */
                if (edit_rule(&vctx->conf, rules, zones, interfaces, services,
                            insert_rule_num, reg) < 0) {
                    /* editting failed so remove the rule again */
                    rule_ptr = vrmr_rules_remove_rule_from_list(
                            rules, insert_rule_num, 1);
                    vrmr_fatal_if_null(rule_ptr);
                    vrmr_rules_free_options(rule_ptr->opt);
                    rule_ptr->opt = NULL;
                    free(rule_ptr);
                    rule_ptr = NULL;
                } else {
                    /* if editting the rule was successful, we have a changed
                     * ruleset. */
                    rules_changed = 1;
                    update_filter = 1;
                }

                draw_top_menu(top_win, gettext("Rules"), key_choices_n,
                        key_choices, cmd_choices_n, cmd_choices);
                break;

            /* copy (duplicate) rule */
            case 'c':
            case 'C':

                cur_rule_num =
                        (unsigned int)atoi(field_buffer(cur_bar->num_field, 0));
                if (cur_rule_num > 0) {
                    rulebar_copy_rule(rules, cur_rule_num, reg);
                    rules_changed = 1;
                    update_filter = 1;
                }

                break;

            /* move a rule */
            case 'm':
            case 'M':

                cur_rule_num =
                        (unsigned int)atoi(field_buffer(cur_bar->num_field, 0));
                if (cur_rule_num > 0) {
                    MoveRuleBarForm(rules, cur_rule_num);

                    rules_changed = 1;
                    update_filter = 1;

                    status_print(status_win, gettext("Ready."));
                }
                break;

            /* move a rule one up */
            case '-':

                cur_rule_num =
                        (unsigned int)atoi(field_buffer(cur_bar->num_field, 0));
                if (cur_rule_num > 1) {
                    move_rule(rules, cur_rule_num, cur_rule_num - 1);

                    if (current_bar_num > 1) {
                        form_driver_wrap(form, REQ_PREV_FIELD);
                    } else {
                        if (rbform->scroll_offset > 0)
                            rbform->scroll_offset--;
                    }

                    form_driver_wrap(form, REQ_BEG_LINE);

                    rules_changed = 1;
                    update_filter = 1;

                    status_print(status_win, gettext("Ready."));
                }
                break;

            /* move a rule one down */
            case '+':

                cur_rule_num =
                        (unsigned int)atoi(field_buffer(cur_bar->num_field, 0));
                if (cur_rule_num < rules->list.len) {
                    move_rule(rules, cur_rule_num, cur_rule_num + 1);
                    /* make sure we dont move to the next field if we:
                       1. scroll
                       2. are at the end of a list that is shorter than the
                       number of bars on screen
                     */
                    if (current_bar_num < rbform->max_bars_on_screen &&
                            current_bar_num < rbform->printable_rules) {
                        form_driver_wrap(form, REQ_NEXT_FIELD);
                    } else if (current_bar_num == rbform->printable_rules ||
                               (unsigned int)(atoi(
                                       field_buffer(cur_bar->num_field, 0))) ==
                                       rbform->printable_rules) {
                        /* do nothing, just sit here */
                    } else {
                        rbform->scroll_offset++;
                    }

                    form_driver_wrap(form, REQ_BEG_LINE);

                    rules_changed = 1;
                    update_filter = 1;

                    status_print(status_win, "Ready.");
                }
                break;

            /* filter */
            case 'f':
            case 'F':

                if ((filter_ptr = input_box(32, gettext("Set the filter"),
                             gettext("Enter filter (leave empty for no "
                                     "filter)")))) {
                    /* first clear the old regex (if we have one) */
                    if (rbform->use_filter == 1) {
                        regfree(&rbform->filter_reg);
                    }

                    /* first construct the regex string */
                    filter_string_regex = malloc(sizeof(filter_ptr) + 1 + 4);
                    vrmr_fatal_alloc("malloc", filter_string_regex);

                    snprintf(filter_string_regex, (sizeof(filter_ptr) + 1 + 4),
                            ".*%s.*", filter_ptr);
                    rbform->use_filter = 1;

                    /* compiling the regex */
                    if (regcomp(&rbform->filter_reg, filter_string_regex,
                                REG_EXTENDED) != 0) {
                        vrmr_error(-1, VR_INTERR,
                                "Setting up the regular expression with "
                                "regcomp failed. Disabling filter.");
                        rbform->use_filter = 0;
                    }

                    status_print(status_win,
                            gettext("Active filter: '%s' (press 'f' and then "
                                    "just 'enter' to clear)."),
                            filter_ptr);

                    free(filter_ptr);
                    filter_ptr = NULL;
                    free(filter_string_regex);
                } else {
                    /* if a filter was in place, clear regex */
                    if (rbform->use_filter == 1) {
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

                if (rbform->show_only_forward == 0) {
                    rbform->show_only_forward = 1;
                    rbform->show_only_input = 0;
                    rbform->show_only_output = 0;
                } else
                    rbform->show_only_forward = 0;

                update_filter = 1;

                status_print(status_win, "%s",
                        rbform->show_only_forward
                                ? gettext("Showing only forward rules.")
                                : gettext("Showing all rules."));
                break;

            case 'n':
            case 'N':

                if (rbform->show_only_input == 0) {
                    rbform->show_only_forward = 0;
                    rbform->show_only_input = 1;
                    rbform->show_only_output = 0;
                } else
                    rbform->show_only_input = 0;

                update_filter = 1;

                status_print(status_win, "%s",
                        rbform->show_only_input
                                ? gettext("Showing only input rules.")
                                : gettext("Showing all rules."));
                break;

            case 'u':
            case 'U':

                if (rbform->show_only_output == 0) {
                    rbform->show_only_forward = 0;
                    rbform->show_only_input = 0;
                    rbform->show_only_output = 1;
                } else
                    rbform->show_only_output = 0;

                update_filter = 1;

                status_print(status_win, "%s",
                        rbform->show_only_output
                                ? gettext("Showing only output rules.")
                                : gettext("Showing all rules."));
                break;

            case KEY_F(12):
            case 'h':
            case 'H':
            case '?':

                print_help(":[VUURMUUR:RULES]:");
                break;
        }
    }

    /* if the rules are changed, save the changes. */
    if (rules_changed) {
        vrmr_fatal_if(vrmr_rules_save_list(vctx, rules, &vctx->conf) < 0);

        /* audit log */
        vrmr_audit("%s: %s: %d (%s).", STR_RULES_ARE_CHANGED,
                STR_NUMBER_OF_RULES, rules->list.len, STR_LISTED_BELOW);

        int i;
        for (i = 1, d_node = rules->list.top; d_node;
                d_node = d_node->next, i++) {
            vrmr_fatal_if_null(d_node->data);
            rule_ptr = d_node->data;

            if (rule_ptr->action == VRMR_AT_SEPARATOR) {
                if (rule_ptr->opt != NULL && rule_ptr->opt->comment[0] != '\0')
                    vrmr_audit("%2d: === %s ===", i, rule_ptr->opt->comment);
                else
                    vrmr_audit("%2d: ===", i);
            } else {
                str = vrmr_rules_assemble_rule(rule_ptr);
                if (str[StrMemLen(str) - 1] == '\n')
                    str[StrMemLen(str) - 1] = '\0';
                vrmr_audit("%2d: %s", i, str);
                free(str);
            }
        }
    }

    del_panel(rbform->more_pan[0]);
    destroy_win(rbform->more_win);

    vrmr_list_cleanup(&rbform->RuleBar_list);
    free(rbform);

    unpost_form(form);
    free_form(form);

    for (size_t i = 0; i < n_fields; i++) {
        free_field(fields[i]);
    }
    free(fields);

    del_panel(panels[0]);
    delwin(rules_win);
    return (0);
}

static int delete_rule(
        struct vrmr_rules *rules, unsigned int rule_num, int call_confirm)
{
    int remove_rule = 0;
    int result = 0;
    int retval = 0;
    struct vrmr_rule *rule_ptr = NULL;

    vrmr_fatal_if(rule_num == 0);

    if (call_confirm == 1) {
        /* first ask the user to confirm */
        result = confirm(gettext("Delete rule"), gettext("Are you sure?"),
                vccnf.color_win_note, vccnf.color_win_note_rev | A_BOLD, 0);
        if (result == 1)
            remove_rule = 1;
        else
            remove_rule = 0;
    } else
        remove_rule = 1;

    if (remove_rule == 1) {
        /* editting failed so remove the rule again */
        rule_ptr = vrmr_rules_remove_rule_from_list(rules, rule_num, 1);
        vrmr_fatal_if_null(rule_ptr);

        vrmr_rules_free_options(rule_ptr->opt);
        rule_ptr->opt = NULL;
        free(rule_ptr);
        rule_ptr = NULL;

        retval = 1;
    }

    if (vrmr_debug_level >= LOW)
        vrmr_rules_print_list(rules);

    return (retval);
}

static void insert_new_rule(
        struct vrmr_rules *rules, unsigned int rule_num, const char *action)
{
    struct vrmr_rule *rule_ptr = NULL;

    /* safety */
    vrmr_fatal_if_null(rules);

    vrmr_debug(LOW, "rule_num: %d", rule_num);

    /* inserting into an empty rules list */
    if (rule_num == 0)
        rule_num = 1;

    /* claim memory */
    rule_ptr = vrmr_rule_malloc();
    vrmr_fatal_alloc("vrmr_rule_malloc", rule_ptr);

    /* set rule to standard */
    rule_ptr->action = vrmr_rules_actiontoi(action);
    strcpy(rule_ptr->service, "");
    strcpy(rule_ptr->from, "");
    strcpy(rule_ptr->to, "");
    rule_ptr->active = 1;
    rule_ptr->number = rule_num;

    /* only setup the options if we are going to change one or more */
    if (vccnf.newrule_log || vccnf.newrule_loglimit) {
        rule_ptr->opt = vrmr_rule_option_malloc();
        vrmr_fatal_alloc("vrmr_rule_option_malloc", rule_ptr->opt);

        /* default log and limit the log */
        rule_ptr->opt->rule_log = vccnf.newrule_log;
        rule_ptr->opt->loglimit = vccnf.newrule_loglimit;
        rule_ptr->opt->logburst = vccnf.newrule_logburst;
    }

    /* handle the rules list is empty */
    if (rules->list.len == 0) {
        /* insert at 1 of course */
        rule_ptr->number = 1;

        vrmr_debug(HIGH, "rule_num: %d, rule_ptr->number: %d", rule_num,
                rule_ptr->number);

        vrmr_fatal_if(
                vrmr_rules_insert_list(rules, rule_ptr->number, rule_ptr) < 0);
    }
    /* handle in a non-empty list */
    else {
        vrmr_fatal_if(vrmr_rules_insert_list(rules, rule_num, rule_ptr) < 0);
    }

    if (vrmr_debug_level >= LOW)
        vrmr_rules_print_list(rules);

    vrmr_info(VR_INFO, gettext("new rule inserted."));
}

// returns 0: no change, or 1: change
int edit_rule(struct vrmr_config *conf, struct vrmr_rules *rules,
        struct vrmr_zones *zones, struct vrmr_interfaces *interfaces,
        struct vrmr_services *services, unsigned int rule_num,
        struct vrmr_regex *reg)
{
    struct vrmr_rule *rule_ptr = NULL;
    struct vrmr_list_node *d_node = NULL;
    int retval = 0;

    /* safety */
    vrmr_fatal_if_null(reg);
    vrmr_fatal_if_null(interfaces);

    vrmr_debug(HIGH, "called with rule_num = %d", rule_num);

    if (rule_num == 0)
        rule_num = 1;

    if (rules->list.len == 0) {
        vrmr_error(-1, VR_INTERR, "list is empty");
        return (-1);
    }

    /* go to rulenum in the rules list to get the rule_ptr */
    if (!(d_node = rules->list.top)) {
        vrmr_error(-1, VR_INTERR, "NULL pointer");
        return (-1);
    }

    /* look for the rule_ptr */
    for (; d_node; d_node = d_node->next) {
        vrmr_fatal_if_null(d_node->data);
        rule_ptr = d_node->data;

        if (rule_ptr->number == rule_num)
            break;
    }

    if (rule_ptr != NULL) {
        if (rule_ptr->action == VRMR_AT_PROTECT) {
            vrmr_fatal("edit_rule can no longer be used for editting protect "
                       "rules");
        } else if (rule_ptr->action == VRMR_AT_SEPARATOR) {
            retval = edit_rule_separator(rule_ptr, reg);
        } else {
            retval = edit_rule_normal(
                    conf, zones, interfaces, services, rule_ptr, reg);
        }
    } else {
        vrmr_error(-1, VR_INTERR, "rule not found");
        retval = -1;
    }

    vrmr_debug(HIGH, "returning retval = %d.", retval);
    return (retval);
}

struct {
    FIELD *action_label_fld_ptr, *action_fld_ptr,

            *random_label_fld_ptr, *random_brackets_fld_ptr, *random_fld_ptr,

            *service_label_fld_ptr, *service_fld_ptr, *fromzone_label_fld_ptr,
            *fromzone_fld_ptr, *tozone_label_fld_ptr, *tozone_fld_ptr,

            *log_label_fld_ptr, *log_brackets_fld_ptr, *log_fld_ptr,

            *logprefix_label_fld_ptr, *logprefix_fld_ptr,

            *loglimit_label_fld_ptr, *loglimit_fld_ptr,

            *limit_label_fld_ptr, *limit_fld_ptr,

            *limit_unit_label_fld_ptr, *limit_unit_fld_ptr,

            *burst_label_fld_ptr, *burst_fld_ptr,

            *in_int_label_fld_ptr, *in_int_fld_ptr,

            *out_int_label_fld_ptr, *out_int_fld_ptr,

            *via_int_label_fld_ptr, *via_int_fld_ptr,

            *reject_label_fld_ptr, *reject_fld_ptr,

            *redirect_label_fld_ptr, *redirect_fld_ptr, *listen_label_fld_ptr,
            *listen_fld_ptr, *remote_label_fld_ptr, *remote_fld_ptr,

            *nfqueuenum_label_fld_ptr, *nfqueuenum_fld_ptr,

            *nflognum_label_fld_ptr, *nflognum_fld_ptr,

            *nfmark_label_fld_ptr, *nfmark_fld_ptr,

            *chain_label_fld_ptr, *chain_fld_ptr,

            *comment_label_fld_ptr, *comment_fld_ptr;
} rule_fields;

/*  edit_rule_fields_to_rule

    Returncodes:
         1: changes stored
         0: no changes
        -1: error
*/
static int edit_rule_fields_to_rule(FIELD **fields, size_t n_fields,
        struct vrmr_rule *rule_ptr, struct vrmr_regex *reg)
{
    int z = 0, retval = 0;
    char port_one[6] = "", nfmarkstr[9] = "";
    char limit_str[6] = "";
    char nfqueuenum_str[6] = "";
    char nflognum_str[6] = "";
    int last_char = 0;
    char action_str[32] = "";

    vrmr_fatal_if_null(fields);
    vrmr_fatal_if_null(rule_ptr);
    vrmr_fatal_if_null(reg);

    /* check for changed fields */
    for (size_t i = 0; i < n_fields; i++) {
        if (field_status(fields[i]) == TRUE) {
            if (fields[i] == rule_fields.action_fld_ptr) {
                /* action */
                copy_field2buf(action_str, field_buffer(fields[i], 0),
                        sizeof(action_str));

                rule_ptr->action = vrmr_rules_actiontoi(action_str);
                retval = 1;
            } else if (fields[i] == rule_fields.service_fld_ptr) {
                /* service */
                copy_field2buf(rule_ptr->service, field_buffer(fields[i], 0),
                        sizeof(rule_ptr->service));
                retval = 1;
            } else if (fields[i] == rule_fields.fromzone_fld_ptr) {
                /* from */
                copy_field2buf(rule_ptr->from, field_buffer(fields[i], 0),
                        sizeof(rule_ptr->from));
                retval = 1;
            } else if (fields[i] == rule_fields.tozone_fld_ptr) {
                /* to */
                copy_field2buf(rule_ptr->to, field_buffer(fields[i], 0),
                        sizeof(rule_ptr->to));
                retval = 1;
            } else if (fields[i] == rule_fields.reject_fld_ptr) {
                /* option rejecttype */
                if (rule_ptr->opt == NULL) {
                    rule_ptr->opt = vrmr_rule_option_malloc();
                    vrmr_fatal_alloc("vrmr_rule_option_malloc", rule_ptr->opt);
                }

                copy_field2buf(rule_ptr->opt->reject_type,
                        field_buffer(fields[i], 0),
                        sizeof(rule_ptr->opt->reject_type));

                if (strcmp(rule_ptr->opt->reject_type, "") == 0)
                    rule_ptr->opt->reject_option = 0;
                else
                    rule_ptr->opt->reject_option = 1;

                retval = 1;
            } else if (fields[i] == rule_fields.redirect_fld_ptr) {
                /* option redirect port */
                if (rule_ptr->opt == NULL) {
                    rule_ptr->opt = vrmr_rule_option_malloc();
                    vrmr_fatal_alloc("vrmr_rule_option_malloc", rule_ptr->opt);
                }

                copy_field2buf(
                        port_one, field_buffer(fields[i], 0), sizeof(port_one));

                rule_ptr->opt->redirectport = atoi(port_one);
                if (rule_ptr->opt->redirectport <= 0 ||
                        rule_ptr->opt->redirectport > 65535) {
                    /* TRANSLATORS: don't translate 'redirectport'. */
                    vrmr_warning(
                            VR_WARN, gettext("redirectport must be 1-65535."));
                    rule_ptr->opt->redirectport = 0;
                }

                retval = 1;
            } else if (fields[i] == rule_fields.nfmark_fld_ptr) {
                /* option redirect port */
                if (rule_ptr->opt == NULL) {
                    rule_ptr->opt = vrmr_rule_option_malloc();
                    vrmr_fatal_alloc("vrmr_rule_option_malloc", rule_ptr->opt);
                }

                copy_field2buf(nfmarkstr, field_buffer(fields[i], 0),
                        sizeof(nfmarkstr));

                rule_ptr->opt->nfmark = strtoul(nfmarkstr, (char **)NULL, 10);
                retval = 1;
            } else if (fields[i] == rule_fields.listen_fld_ptr) {
                if (rule_ptr->opt == NULL) {
                    rule_ptr->opt = vrmr_rule_option_malloc();
                    vrmr_fatal_alloc("vrmr_rule_option_malloc", rule_ptr->opt);
                }

                /* first clear the list */
                if (rule_ptr->opt->listenport == 1 &&
                        rule_ptr->opt->ListenportList.len > 0)
                    vrmr_list_cleanup(&rule_ptr->opt->ListenportList);

                /* if the first char is a whitespace, we asume the field is
                 * empty */
                if (field_buffer(fields[i], 0)[0] == ' ') {
                    rule_ptr->opt->listenport = 0;
                } else {
                    /* add the ports to the list */
                    if (vrmr_portopts_to_list(field_buffer(fields[i], 0),
                                &rule_ptr->opt->ListenportList) < 0)
                        rule_ptr->opt->listenport = 0;
                    else {
                        if (rule_ptr->opt->ListenportList.len == 0)
                            rule_ptr->opt->listenport = 0;
                        else
                            rule_ptr->opt->listenport = 1;
                    }
                }

                retval = 1;
            } else if (fields[i] == rule_fields.remote_fld_ptr) {
                if (rule_ptr->opt == NULL) {
                    rule_ptr->opt = vrmr_rule_option_malloc();
                    vrmr_fatal_alloc("vrmr_rule_option_malloc", rule_ptr->opt);
                }

                /* first clear the list */
                if (rule_ptr->opt->remoteport == 1 &&
                        rule_ptr->opt->RemoteportList.len > 0)
                    vrmr_list_cleanup(&rule_ptr->opt->RemoteportList);

                /* if the first char is a whitespace, we asume the field is
                 * empty */
                if (field_buffer(fields[i], 0)[0] == ' ') {
                    rule_ptr->opt->remoteport = 0;
                } else {
                    /* add the ports to the list */
                    if (vrmr_portopts_to_list(field_buffer(fields[i], 0),
                                &rule_ptr->opt->RemoteportList) < 0)
                        rule_ptr->opt->remoteport = 0;
                    else {
                        if (rule_ptr->opt->RemoteportList.len == 0)
                            rule_ptr->opt->remoteport = 0;
                        else
                            rule_ptr->opt->remoteport = 1;
                    }
                }

                retval = 1;
            } else if (fields[i] == rule_fields.logprefix_fld_ptr) {
                if (StrLen(field_buffer(fields[i], 0)) !=
                        StrMemLen(field_buffer(fields[i], 0))) {
                    vrmr_warning(
                            VR_WARN, "%s", STR_ONLY_ASCII_ALLOWED_IN_PREFIX);
                } else {
                    /* options */
                    if (rule_ptr->opt == NULL) {
                        rule_ptr->opt = vrmr_rule_option_malloc();
                        vrmr_fatal_alloc(
                                "vrmr_rule_option_malloc", rule_ptr->opt);
                    }

                    for (last_char = 0, z = 0; z < 12;
                            z++) /* 12 is max prefix length */
                    {
                        rule_ptr->opt->logprefix[z] =
                                field_buffer(fields[i], 0)[z];

                        /* make sure that we place the NULL after the last char:
                         * no trailing spaces. */
                        if (rule_ptr->opt->logprefix[z] != ' ')
                            last_char = z + 1;
                    }
                    rule_ptr->opt->logprefix[last_char] = '\0';

                    if (strcmp(rule_ptr->opt->logprefix, "") == 0)
                        rule_ptr->opt->rule_logprefix = 0;
                    else
                        rule_ptr->opt->rule_logprefix = 1;

                    retval = 1;
                }
            } else if (fields[i] == rule_fields.comment_fld_ptr) {
                /* first check if the commentfield is valid */
                if (validate_commentfield(
                            field_buffer(fields[i], 0), reg->comment) == 0) {
                    /* options */
                    if (rule_ptr->opt == NULL) {
                        rule_ptr->opt = vrmr_rule_option_malloc();
                        vrmr_fatal_alloc(
                                "vrmr_rule_option_malloc", rule_ptr->opt);
                    }

                    for (last_char = 0, z = 0;
                            z < (int)sizeof(rule_ptr->opt->comment) &&
                            field_buffer(fields[i], 0)[z] != '\0';
                            z++) /* 12 is max prefix length */
                    {
                        rule_ptr->opt->comment[z] =
                                field_buffer(fields[i], 0)[z];
                        if (rule_ptr->opt->comment[z] == '\n')
                            rule_ptr->opt->comment[z] = ' ';

                        /* make sure that we place the NULL after the last char:
                         * no trailing spaces. */
                        if (rule_ptr->opt->comment[z] != ' ')
                            last_char = z + 1;
                    }
                    rule_ptr->opt->comment[last_char] = '\0';

                    if (strcmp(rule_ptr->opt->comment, "") == 0)
                        rule_ptr->opt->rule_comment = 0;
                    else
                        rule_ptr->opt->rule_comment = 1;

                    retval = 1;
                }
            } else if (fields[i] == rule_fields.loglimit_fld_ptr) {
                /* option redirect port */
                if (rule_ptr->opt == NULL) {
                    rule_ptr->opt = vrmr_rule_option_malloc();
                    vrmr_fatal_alloc("vrmr_rule_option_malloc", rule_ptr->opt);
                }

                copy_field2buf(limit_str, field_buffer(fields[i], 0),
                        sizeof(limit_str));

                rule_ptr->opt->loglimit = (unsigned int)atoi(limit_str);
                if (rule_ptr->opt->loglimit > 999) {
                    /* TRANSLATORS: don't translate 'loglimit'. */
                    vrmr_warning(VR_WARN, gettext("loglimit must be 0-999."));
                    rule_ptr->opt->loglimit = 0;
                }

                retval = 1;
            } else if (fields[i] == rule_fields.log_fld_ptr) {
                /* log */
                if (rule_ptr->opt == NULL) {
                    rule_ptr->opt = vrmr_rule_option_malloc();
                    vrmr_fatal_alloc("vrmr_rule_option_malloc", rule_ptr->opt);
                }

                if (strncmp(field_buffer(fields[i], 0), "X", 1) == 0)
                    rule_ptr->opt->rule_log = 1;
                else
                    rule_ptr->opt->rule_log = 0;

                retval = 1;
            } else if (fields[i] == rule_fields.nfqueuenum_fld_ptr) {
                /* nfqueuenum */

                /* if needed alloc the opt struct */
                if (rule_ptr->opt == NULL) {
                    rule_ptr->opt = vrmr_rule_option_malloc();
                    vrmr_fatal_alloc("vrmr_rule_option_malloc", rule_ptr->opt);
                }

                copy_field2buf(nfqueuenum_str, field_buffer(fields[i], 0),
                        sizeof(nfqueuenum_str));

                rule_ptr->opt->nfqueue_num = atoi(nfqueuenum_str);

                retval = 1;
            } else if (fields[i] == rule_fields.nflognum_fld_ptr) {
                /* nflognum */

                /* if needed alloc the opt struct */
                if (rule_ptr->opt == NULL) {
                    rule_ptr->opt = vrmr_rule_option_malloc();
                    vrmr_fatal_alloc("vrmr_rule_option_malloc", rule_ptr->opt);
                }

                copy_field2buf(nflognum_str, field_buffer(fields[i], 0),
                        sizeof(nflognum_str));

                rule_ptr->opt->nflog_num = atoi(nflognum_str);

                retval = 1;
            } else if (fields[i] == rule_fields.random_fld_ptr) {
                /* random */

                /* if needed alloc the opt struct */
                if (rule_ptr->opt == NULL) {
                    rule_ptr->opt = vrmr_rule_option_malloc();
                    vrmr_fatal_alloc("vrmr_rule_option_malloc", rule_ptr->opt);
                }

                if (strncmp(field_buffer(fields[i], 0), "X", 1) == 0)
                    rule_ptr->opt->random = 1;
                else
                    rule_ptr->opt->random = 0;

                retval = 1;
            } else if (fields[i] == rule_fields.in_int_fld_ptr) {
                /* option interface */
                if (rule_ptr->opt == NULL) {
                    rule_ptr->opt = vrmr_rule_option_malloc();
                    vrmr_fatal_alloc("vrmr_rule_option_malloc", rule_ptr->opt);
                }

                copy_field2buf(rule_ptr->opt->in_int,
                        field_buffer(fields[i], 0),
                        sizeof(rule_ptr->opt->in_int));
                retval = 1;
            } else if (fields[i] == rule_fields.out_int_fld_ptr) {
                /* option interface */
                if (rule_ptr->opt == NULL) {
                    rule_ptr->opt = vrmr_rule_option_malloc();
                    vrmr_fatal_alloc("vrmr_rule_option_malloc", rule_ptr->opt);
                }

                copy_field2buf(rule_ptr->opt->out_int,
                        field_buffer(fields[i], 0),
                        sizeof(rule_ptr->opt->out_int));
                retval = 1;
            } else if (fields[i] == rule_fields.via_int_fld_ptr) {
                /* option interface */
                if (rule_ptr->opt == NULL) {
                    rule_ptr->opt = vrmr_rule_option_malloc();
                    vrmr_fatal_alloc("vrmr_rule_option_malloc", rule_ptr->opt);
                }

                copy_field2buf(rule_ptr->opt->via_int,
                        field_buffer(fields[i], 0),
                        sizeof(rule_ptr->opt->via_int));
                retval = 1;
            } else if (fields[i] == rule_fields.chain_fld_ptr) {
                /* option interface */
                if (rule_ptr->opt == NULL) {
                    rule_ptr->opt = vrmr_rule_option_malloc();
                    vrmr_fatal_alloc("vrmr_rule_option_malloc", rule_ptr->opt);
                }

                copy_field2buf(rule_ptr->opt->chain, field_buffer(fields[i], 0),
                        sizeof(rule_ptr->opt->chain));
                retval = 1;
            } else if (fields[i] == rule_fields.limit_fld_ptr) {
                if (rule_ptr->opt == NULL) {
                    rule_ptr->opt = vrmr_rule_option_malloc();
                    vrmr_fatal_alloc("vrmr_rule_option_malloc", rule_ptr->opt);
                }

                copy_field2buf(limit_str, field_buffer(fields[i], 0),
                        sizeof(limit_str));

                rule_ptr->opt->limit = (unsigned int)atoi(limit_str);
                if (rule_ptr->opt->limit > 9999) {
                    vrmr_warning(VR_WARN,
                            gettext("new connection limit must be 0-9999."));
                    rule_ptr->opt->limit = 0;
                }

                retval = 1;
            } else if (fields[i] == rule_fields.limit_unit_fld_ptr) {
                if (rule_ptr->opt == NULL) {
                    rule_ptr->opt = vrmr_rule_option_malloc();
                    vrmr_fatal_alloc("vrmr_rule_option_malloc", rule_ptr->opt);
                }

                copy_field2buf(rule_ptr->opt->limit_unit,
                        field_buffer(fields[i], 0),
                        sizeof(rule_ptr->opt->limit_unit));
                retval = 1;
            } else if (fields[i] == rule_fields.burst_fld_ptr) {
                if (rule_ptr->opt == NULL) {
                    rule_ptr->opt = vrmr_rule_option_malloc();
                    vrmr_fatal_alloc("vrmr_rule_option_malloc", rule_ptr->opt);
                }

                copy_field2buf(limit_str, field_buffer(fields[i], 0),
                        sizeof(limit_str));

                rule_ptr->opt->burst = (unsigned int)atoi(limit_str);
                if (rule_ptr->opt->burst > 9999 || rule_ptr->opt->burst == 0) {
                    vrmr_warning(VR_WARN, gettext("new connection limit burst "
                                                  "must be 1-9999."));
                    rule_ptr->opt->burst = 0;
                }

                retval = 1;
            }
        }
    }

    vrmr_debug(HIGH, "returning retval = %d.", retval);
    return (retval);
}

static int edit_rule_simple_check(struct vrmr_rule *rule_ptr)
{
    if (rule_ptr->service[0] == '\0' || rule_ptr->from[0] == '\0' ||
            rule_ptr->to[0] == '\0') {
        return (0);
    }

    return (1);
}

static int edit_rule_check_action_opts(struct vrmr_rule *rule_ptr)
{
    if (rule_ptr->action == VRMR_AT_BOUNCE) {
        if (rule_ptr->opt == NULL || rule_ptr->opt->via_int[0] == '\0') {
            vrmr_warning(VR_WARN, STR_BOUNCE_REQUIRES_VIA_OPT);
            return (0);
        }
    } else if (rule_ptr->action == VRMR_AT_REDIRECT) {
        if (rule_ptr->opt == NULL || rule_ptr->opt->redirectport == 0) {
            vrmr_warning(VR_WARN, STR_REDIRECT_REQUIRES_OPT);
            return (0);
        }
    }

    return (1);
}

/*  edit_rule_normal

    Returncodes:
         0: ok, no changes
         1: ok, changes
        -1: error

    TODO: split this beast up
*/
int edit_rule_normal(struct vrmr_config *conf, struct vrmr_zones *zones,
        struct vrmr_interfaces *interfaces, struct vrmr_services *services,
        struct vrmr_rule *rule_ptr, struct vrmr_regex *reg)
{
    PANEL *my_panels[1];
    WINDOW *edit_win;
    FIELD **fields, *cur = NULL, *prev = NULL;
    FORM *form;
    int rows, cols, retval = 0, quit = 0;
    size_t field_num = 0, n_fields = 0, i = 0;
    char redirect_port[6] = "", loglimit_string[16] = "",
         nfmark_string[16] = "", nfqueuenum_string[6] = "0",
         nflognum_string[6] = "0";
    int height, width, startx, starty, max_height;
    const char *action_choices[] =
            {
                    "Accept",
                    "Drop",
                    "Reject",
                    "Log",
                    "Portfw",
                    "Redirect",
                    "Snat",
                    "Masq",
                    "Dnat",
                    "NFQueue",
                    "NFLog",
                    "Chain",
                    "Bounce",
            },
               *reject_types[] = {"icmp-net-unreachable",
                       "icmp-host-unreachable", "icmp-proto-unreachable",
                       "icmp-port-unreachable", "icmp-net-prohibited",
                       "icmp-host-prohibited", "tcp-reset"};
    char select_choice[VRMR_VRMR_MAX_HOST_NET_ZONE] = "";
    size_t action_choices_n = 13, reject_types_n = 7;
    char *choice_ptr;
    size_t zone_choices_n = 0, service_choices_n = 0, n_choices = 0;
    struct vrmr_list_node *d_node = NULL;
    struct vrmr_zone *zone_ptr = NULL, *network_ptr = NULL;
    struct vrmr_service *service_ptr = NULL;
    struct vrmr_interface *iface_ptr = NULL;

    int result = 0;
    struct vrmr_rule_cache tmp_ruledata;
    char window_title[32] = "";

    const char *key_choices[] = {"F12", "F5", "F6", "F10"};
    int key_choices_n = 4;
    const char *cmd_choices[] = {gettext("help"), gettext("advanced"),
            gettext("shaping"), gettext("back")};
    int cmd_choices_n = 4;

    /* is this screen in advanced mode or not? */
    char advanced_mode = vccnf.advanced_mode;
    char zonename[VRMR_VRMR_MAX_HOST_NET_ZONE] = "";

    struct vrmr_list *interfaces_list = NULL;

    /* safety */
    vrmr_fatal_if_null(reg);
    vrmr_fatal_if_null(rule_ptr);

    /* clear tmp_ruledata for the initial */
    memset(&tmp_ruledata, 0, sizeof(tmp_ruledata));
    memset(&rule_fields, 0, sizeof(rule_fields));

    /* set to keep first */
    rule_ptr->status = VRMR_ST_CHANGED;

    /* get the dimentions of the screen */
    max_height = getmaxy(stdscr);

    /* set windowsize and start position */
    height = 20;
    width = 78; /* = minimum screensize - 2 */
    startx = 1;
    if (max_height > 24)
        starty = 4;
    else
        starty = 2;

    /* set number of fields */
    n_fields = 48;
    fields = (FIELD **)calloc(n_fields + 1, sizeof(FIELD *));
    vrmr_fatal_alloc("calloc", fields);

    /*
        create the fields
    */

    /* action label */
    rule_fields.action_label_fld_ptr =
            (fields[field_num] = new_field_wrap(1, 8, 1, 1, 0, 0));
    set_field_buffer_wrap(
            rule_fields.action_label_fld_ptr, 0, gettext("Action"));
    field_opts_off(rule_fields.action_label_fld_ptr, O_ACTIVE);
    set_field_back(rule_fields.action_label_fld_ptr, vccnf.color_win);
    set_field_fore(rule_fields.action_label_fld_ptr, vccnf.color_win);
    field_num++;

    /* action */
    rule_fields.action_fld_ptr =
            (fields[field_num] = new_field_wrap(1, 16, 1, 10, 0, 0));
    set_field_buffer_wrap(rule_fields.action_fld_ptr, 0,
            vrmr_rules_itoaction(rule_ptr->action));
    set_field_back(rule_fields.action_fld_ptr, vccnf.color_win_rev);
    set_field_fore(rule_fields.action_fld_ptr, vccnf.color_win_rev | A_BOLD);
    field_num++;

    /* random */
    rule_fields.random_label_fld_ptr =
            (fields[field_num] = new_field_wrap(1, 7, 3, 10, 0, 0));
    /* TRANSLATORS: max 7 chars */
    set_field_buffer_wrap(
            rule_fields.random_label_fld_ptr, 0, gettext("Random"));
    field_opts_off(rule_fields.random_label_fld_ptr, O_ACTIVE);
    set_field_back(rule_fields.random_label_fld_ptr, vccnf.color_win);
    set_field_fore(rule_fields.random_label_fld_ptr, vccnf.color_win);
    field_num++;

    rule_fields.random_brackets_fld_ptr =
            (fields[field_num] = new_field_wrap(1, 3, 3, 17, 0, 0));
    set_field_buffer_wrap(rule_fields.random_brackets_fld_ptr, 0, "[ ]");
    field_opts_off(rule_fields.random_brackets_fld_ptr, O_ACTIVE);
    set_field_back(rule_fields.random_brackets_fld_ptr, vccnf.color_win);
    set_field_fore(rule_fields.random_brackets_fld_ptr, vccnf.color_win);
    field_num++;

    /* random toggle */
    rule_fields.random_fld_ptr =
            (fields[field_num] = new_field_wrap(1, 1, 3, 18, 0, 0));
    set_field_back(rule_fields.random_fld_ptr, vccnf.color_win);
    set_field_fore(rule_fields.random_fld_ptr, vccnf.color_win);
    field_num++;

    /* enable */
    if (rule_ptr->opt != NULL && rule_ptr->opt->random == 1)
        set_field_buffer_wrap(rule_fields.random_fld_ptr, 0, "X");

    /* queue starts disabled */
    field_opts_off(rule_fields.random_fld_ptr, O_VISIBLE);
    field_opts_off(rule_fields.random_label_fld_ptr, O_VISIBLE);
    field_opts_off(rule_fields.random_brackets_fld_ptr, O_VISIBLE);

    /* nfqueuenum label */
    rule_fields.nfqueuenum_label_fld_ptr =
            (fields[field_num] = new_field_wrap(1, 18, 5, 10, 0, 0));
    set_field_buffer_wrap(
            rule_fields.nfqueuenum_label_fld_ptr, 0, gettext("Queue number"));
    field_opts_off(rule_fields.nfqueuenum_label_fld_ptr, O_ACTIVE);
    set_field_back(rule_fields.nfqueuenum_label_fld_ptr, vccnf.color_win);
    set_field_fore(rule_fields.nfqueuenum_label_fld_ptr, vccnf.color_win);
    field_num++;

    /* nfqueuenum */
    rule_fields.nfqueuenum_fld_ptr =
            (fields[field_num] = new_field_wrap(1, 6, 5, 30, 0, 0));
    set_field_back(rule_fields.nfqueuenum_fld_ptr, vccnf.color_win_rev);
    set_field_fore(
            rule_fields.nfqueuenum_fld_ptr, vccnf.color_win_rev | A_BOLD);
    field_num++;

    /* enable nfqueuenum option */
    if (rule_ptr->opt != NULL)
        snprintf(nfqueuenum_string, sizeof(nfqueuenum_string), "%u",
                rule_ptr->opt->nfqueue_num);

    set_field_buffer_wrap(rule_fields.nfqueuenum_fld_ptr, 0, nfqueuenum_string);

    /* start disabled  */
    field_opts_off(rule_fields.nfqueuenum_fld_ptr, O_VISIBLE);
    field_opts_off(rule_fields.nfqueuenum_label_fld_ptr, O_VISIBLE);

    /* nflognum label */
    rule_fields.nflognum_label_fld_ptr =
            (fields[field_num] = new_field_wrap(1, 18, 5, 10, 0, 0));
    set_field_buffer_wrap(
            rule_fields.nflognum_label_fld_ptr, 0, gettext("NFLog number"));
    field_opts_off(rule_fields.nflognum_label_fld_ptr, O_ACTIVE);
    set_field_back(rule_fields.nflognum_label_fld_ptr, vccnf.color_win);
    set_field_fore(rule_fields.nflognum_label_fld_ptr, vccnf.color_win);
    field_num++;

    /* nflognum */
    rule_fields.nflognum_fld_ptr =
            (fields[field_num] = new_field_wrap(1, 6, 5, 30, 0, 0));
    set_field_back(rule_fields.nflognum_fld_ptr, vccnf.color_win_rev);
    set_field_fore(rule_fields.nflognum_fld_ptr, vccnf.color_win_rev | A_BOLD);
    field_num++;

    /* enable nflognum option */
    if (rule_ptr->opt != NULL)
        snprintf(nflognum_string, sizeof(nflognum_string), "%u",
                rule_ptr->opt->nflog_num);

    set_field_buffer_wrap(rule_fields.nflognum_fld_ptr, 0, nflognum_string);

    /* start disabled  */
    field_opts_off(rule_fields.nflognum_fld_ptr, O_VISIBLE);
    field_opts_off(rule_fields.nflognum_label_fld_ptr, O_VISIBLE);

    /* service label */
    rule_fields.service_label_fld_ptr =
            (fields[field_num] = new_field_wrap(1, 8, 7, 1, 0, 0));
    set_field_buffer_wrap(
            rule_fields.service_label_fld_ptr, 0, gettext("Service"));
    field_opts_off(rule_fields.service_label_fld_ptr, O_ACTIVE);
    set_field_back(rule_fields.service_label_fld_ptr, vccnf.color_win);
    set_field_fore(rule_fields.service_label_fld_ptr, vccnf.color_win);
    field_num++;

    /* service */
    rule_fields.service_fld_ptr =
            (fields[field_num] = new_field_wrap(1, 32, 7, 10, 0, 0));
    set_field_buffer_wrap(rule_fields.service_fld_ptr, 0, rule_ptr->service);
    set_field_back(rule_fields.service_fld_ptr, vccnf.color_win_rev);
    set_field_fore(rule_fields.service_fld_ptr, vccnf.color_win_rev | A_BOLD);
    field_num++;

    /* nfmark label */
    rule_fields.nfmark_label_fld_ptr =
            (fields[field_num] = new_field_wrap(1, 7, 9, 10, 0, 0));
    /* TRANSLATORS: max 7 chars */
    set_field_buffer_wrap(rule_fields.nfmark_label_fld_ptr, 0, gettext("Mark"));
    field_opts_off(rule_fields.nfmark_label_fld_ptr, O_ACTIVE);
    set_field_back(rule_fields.nfmark_label_fld_ptr, vccnf.color_win);
    set_field_fore(rule_fields.nfmark_label_fld_ptr, vccnf.color_win);
    field_num++;

    rule_fields.nfmark_fld_ptr =
            (fields[field_num] = new_field_wrap(1, 8, 9, 19, 0, 0));
    set_field_back(rule_fields.nfmark_fld_ptr, vccnf.color_win_rev);
    set_field_fore(rule_fields.nfmark_fld_ptr, vccnf.color_win_rev | A_BOLD);
    field_num++;

    /* enable nfmark option */
    if (rule_ptr->opt != NULL && rule_ptr->opt->nfmark > 0) {
        snprintf(nfmark_string, sizeof(nfmark_string), "%" PRIu32,
                rule_ptr->opt->nfmark);
        set_field_buffer_wrap(rule_fields.nfmark_fld_ptr, 0, nfmark_string);
    }

    /* start disabled  */
    field_opts_off(rule_fields.nfmark_fld_ptr, O_VISIBLE);
    field_opts_off(rule_fields.nfmark_label_fld_ptr, O_VISIBLE);

    /* from zone label */
    rule_fields.fromzone_label_fld_ptr =
            (fields[field_num] = new_field_wrap(1, 8, 11, 1, 0, 0));
    set_field_buffer_wrap(
            rule_fields.fromzone_label_fld_ptr, 0, gettext("From"));
    field_opts_off(rule_fields.fromzone_label_fld_ptr, O_ACTIVE);
    set_field_back(rule_fields.fromzone_label_fld_ptr, vccnf.color_win);
    set_field_fore(rule_fields.fromzone_label_fld_ptr, vccnf.color_win);
    field_num++;

    /* from zone */
    rule_fields.fromzone_fld_ptr =
            (fields[field_num] = new_field_wrap(1, 48, 11, 10, 0, 0));
    set_field_buffer_wrap(rule_fields.fromzone_fld_ptr, 0, rule_ptr->from);
    set_field_back(rule_fields.fromzone_fld_ptr, vccnf.color_win_rev);
    set_field_fore(rule_fields.fromzone_fld_ptr, vccnf.color_win_rev | A_BOLD);
    field_num++;

    /* in_int interface label */
    rule_fields.in_int_label_fld_ptr =
            (fields[field_num] = new_field_wrap(1, 24, 12, 10, 0, 0));
    set_field_buffer_wrap(
            rule_fields.in_int_label_fld_ptr, 0, gettext("Listen Interface"));
    field_opts_off(rule_fields.in_int_label_fld_ptr, O_ACTIVE);
    set_field_back(rule_fields.in_int_label_fld_ptr, vccnf.color_win);
    set_field_fore(rule_fields.in_int_label_fld_ptr, vccnf.color_win);
    field_num++;

    /* in_int interface */
    rule_fields.in_int_fld_ptr = (fields[field_num] = new_field_wrap(
                                          1, VRMR_MAX_INTERFACE, 12, 36, 0, 0));
    if (rule_ptr->opt != NULL)
        set_field_buffer_wrap(
                rule_fields.in_int_fld_ptr, 0, rule_ptr->opt->in_int);

    set_field_back(rule_fields.in_int_fld_ptr, vccnf.color_win_rev);
    set_field_fore(rule_fields.in_int_fld_ptr, vccnf.color_win_rev | A_BOLD);
    field_num++;

    /* in_int interface starts disabled */
    field_opts_off(rule_fields.in_int_label_fld_ptr, O_VISIBLE);
    field_opts_off(rule_fields.in_int_fld_ptr, O_VISIBLE);

    /* to zone label */
    rule_fields.tozone_label_fld_ptr =
            (fields[field_num] = new_field_wrap(1, 8, 14, 1, 0, 0));
    set_field_buffer_wrap(rule_fields.tozone_label_fld_ptr, 0, gettext("To"));
    field_opts_off(rule_fields.tozone_label_fld_ptr, O_ACTIVE);
    set_field_back(rule_fields.tozone_label_fld_ptr, vccnf.color_win);
    set_field_fore(rule_fields.tozone_label_fld_ptr, vccnf.color_win);
    field_num++;

    /* to zone */
    rule_fields.tozone_fld_ptr =
            (fields[field_num] = new_field_wrap(1, 48, 14, 10, 0, 0));
    set_field_buffer_wrap(rule_fields.tozone_fld_ptr, 0, rule_ptr->to);
    set_field_back(rule_fields.tozone_fld_ptr, vccnf.color_win_rev);
    set_field_fore(rule_fields.tozone_fld_ptr, vccnf.color_win_rev | A_BOLD);
    field_num++;

    /* out_int interface label */
    rule_fields.out_int_label_fld_ptr =
            (fields[field_num] = new_field_wrap(1, 24, 15, 10, 0, 0));
    set_field_buffer_wrap(rule_fields.out_int_label_fld_ptr, 0,
            gettext("Outgoing Interface"));
    field_opts_off(rule_fields.out_int_label_fld_ptr, O_ACTIVE);
    set_field_back(rule_fields.out_int_label_fld_ptr, vccnf.color_win);
    set_field_fore(rule_fields.out_int_label_fld_ptr, vccnf.color_win);
    field_num++;

    /* out_int interface */
    rule_fields.out_int_fld_ptr = (fields[field_num] = new_field_wrap(1,
                                           VRMR_MAX_INTERFACE, 15, 36, 0, 0));
    if (rule_ptr->opt != NULL)
        set_field_buffer_wrap(
                rule_fields.out_int_fld_ptr, 0, rule_ptr->opt->out_int);

    set_field_back(rule_fields.out_int_fld_ptr, vccnf.color_win_rev);
    set_field_fore(rule_fields.out_int_fld_ptr, vccnf.color_win_rev | A_BOLD);
    field_num++;

    /* out_int interface starts disabled */
    field_opts_off(rule_fields.out_int_label_fld_ptr, O_VISIBLE);
    field_opts_off(rule_fields.out_int_fld_ptr, O_VISIBLE);

    /* comment label */
    /* TRANSLATORS: max 7 chars */
    rule_fields.comment_label_fld_ptr =
            (fields[field_num] = new_field_wrap(1, 8, 17, 1, 0, 0));
    set_field_buffer_wrap(
            rule_fields.comment_label_fld_ptr, 0, gettext("Comment"));
    field_opts_off(rule_fields.comment_label_fld_ptr, O_ACTIVE);
    set_field_back(rule_fields.comment_label_fld_ptr, vccnf.color_win);
    set_field_fore(rule_fields.comment_label_fld_ptr, vccnf.color_win);
    field_num++;

    /* comment */
    rule_fields.comment_fld_ptr =
            (fields[field_num] = new_field_wrap(1, 63, 17, 10, 0, 0));
    if (rule_ptr->opt != NULL && rule_ptr->opt->rule_comment == 1)
        set_field_buffer_wrap(
                rule_fields.comment_fld_ptr, 0, rule_ptr->opt->comment);
    set_field_back(rule_fields.comment_fld_ptr, vccnf.color_win_rev);
    set_field_fore(rule_fields.comment_fld_ptr, vccnf.color_win_rev | A_BOLD);
    field_num++;

    /* log label */
    /* TRANSLATORS: max 4 chars */
    rule_fields.log_label_fld_ptr =
            (fields[field_num] = new_field_wrap(1, 4, 1, 29, 0, 0));
    set_field_buffer_wrap(rule_fields.log_label_fld_ptr, 0, gettext("Log"));
    field_opts_off(rule_fields.log_label_fld_ptr, O_ACTIVE);
    set_field_back(rule_fields.log_label_fld_ptr, vccnf.color_win);
    set_field_fore(rule_fields.log_label_fld_ptr, vccnf.color_win);
    field_num++;

    rule_fields.log_brackets_fld_ptr =
            (fields[field_num] = new_field_wrap(1, 3, 1, 34, 0, 0));
    set_field_buffer_wrap(rule_fields.log_brackets_fld_ptr, 0, "[ ]");
    field_opts_off(rule_fields.log_brackets_fld_ptr, O_ACTIVE);
    set_field_back(rule_fields.log_brackets_fld_ptr, vccnf.color_win);
    set_field_fore(rule_fields.log_brackets_fld_ptr, vccnf.color_win);
    field_num++;

    /* log */
    rule_fields.log_fld_ptr =
            (fields[field_num] = new_field_wrap(1, 1, 1, 35, 0, 0));

    /* enable */
    if (rule_ptr->opt != NULL && rule_ptr->opt->rule_log == 1)
        set_field_buffer_wrap(rule_fields.log_fld_ptr, 0, "X");

    set_field_back(rule_fields.log_fld_ptr, vccnf.color_win);
    set_field_fore(rule_fields.log_fld_ptr, vccnf.color_win);
    field_num++;

    /* log prefix label */
    /* TRANSLATORS: max 7 chars */
    rule_fields.logprefix_label_fld_ptr =
            (fields[field_num] = new_field_wrap(1, 8, 1, 39, 0, 0));
    set_field_buffer_wrap(
            rule_fields.logprefix_label_fld_ptr, 0, gettext("Prefix"));
    field_opts_off(rule_fields.logprefix_label_fld_ptr, O_ACTIVE);
    set_field_back(rule_fields.logprefix_label_fld_ptr, vccnf.color_win);
    set_field_fore(rule_fields.logprefix_label_fld_ptr, vccnf.color_win);
    field_num++;

    /* log prefix */
    rule_fields.logprefix_fld_ptr =
            (fields[field_num] = new_field_wrap(1, 12, 1, 48, 0, 0));
    if (rule_ptr->opt != NULL)
        set_field_buffer_wrap(
                rule_fields.logprefix_fld_ptr, 0, rule_ptr->opt->logprefix);
    set_field_back(rule_fields.logprefix_fld_ptr, vccnf.color_win_rev);
    set_field_fore(rule_fields.logprefix_fld_ptr, vccnf.color_win_rev | A_BOLD);
    field_num++;

    /* limit label */
    /* TRANSLATORS: max 6 chars */
    rule_fields.loglimit_label_fld_ptr =
            (fields[field_num] = new_field_wrap(1, 8, 1, 62, 0, 0));
    set_field_buffer_wrap(
            rule_fields.loglimit_label_fld_ptr, 0, gettext("Limit"));
    field_opts_off(rule_fields.loglimit_label_fld_ptr, O_ACTIVE);
    set_field_back(rule_fields.loglimit_label_fld_ptr, vccnf.color_win);
    set_field_fore(rule_fields.loglimit_label_fld_ptr, vccnf.color_win);
    field_num++;

    /* limit */
    rule_fields.loglimit_fld_ptr =
            (fields[field_num] = new_field_wrap(1, 3, 1, 70, 0, 0));
    if (rule_ptr->opt != NULL) {
        if (rule_ptr->opt->loglimit > 0) {
            snprintf(loglimit_string, sizeof(loglimit_string), "%u",
                    rule_ptr->opt->loglimit);
            set_field_buffer_wrap(
                    rule_fields.loglimit_fld_ptr, 0, loglimit_string);
        }
    }
    set_field_back(rule_fields.loglimit_fld_ptr, vccnf.color_win_rev);
    set_field_fore(rule_fields.loglimit_fld_ptr, vccnf.color_win_rev | A_BOLD);
    field_num++;

    /* log prefix label */
    /* TRANSLATORS: max 7 chars */
    rule_fields.limit_label_fld_ptr =
            (fields[field_num] = new_field_wrap(1, 12, 3, 29, 0, 0));
    set_field_buffer_wrap(
            rule_fields.limit_label_fld_ptr, 0, gettext("Rule Limit"));
    field_opts_off(rule_fields.limit_label_fld_ptr, O_ACTIVE);
    set_field_back(rule_fields.limit_label_fld_ptr, vccnf.color_win);
    set_field_fore(rule_fields.limit_label_fld_ptr, vccnf.color_win);
    field_num++;

    /* log prefix */
    rule_fields.limit_fld_ptr =
            (fields[field_num] = new_field_wrap(1, 4, 3, 42, 0, 0));
    if (rule_ptr->opt != NULL) {
        if (rule_ptr->opt->limit > 0) {
            snprintf(loglimit_string, sizeof(loglimit_string), "%u",
                    rule_ptr->opt->limit);
            set_field_buffer_wrap(
                    rule_fields.limit_fld_ptr, 0, loglimit_string);
        }
    }
    set_field_back(rule_fields.limit_fld_ptr, vccnf.color_win_rev);
    set_field_fore(rule_fields.limit_fld_ptr, vccnf.color_win_rev | A_BOLD);
    field_num++;

    /* start disabled and set the field to dynamic */
    field_opts_off(rule_fields.limit_fld_ptr, O_VISIBLE | O_STATIC);
    field_opts_off(rule_fields.limit_label_fld_ptr, O_VISIBLE);

    /* Limit Unit Label */
    rule_fields.limit_unit_label_fld_ptr =
            (fields[field_num] = new_field_wrap(1, 1, 3, 48, 0, 0));
    set_field_buffer_wrap(rule_fields.limit_unit_label_fld_ptr, 0, "/");
    field_opts_off(rule_fields.limit_unit_label_fld_ptr, O_ACTIVE);
    set_field_back(rule_fields.limit_unit_label_fld_ptr, vccnf.color_win);
    set_field_fore(rule_fields.limit_unit_label_fld_ptr, vccnf.color_win);
    field_num++;

    /* Limit Unit  */
    rule_fields.limit_unit_fld_ptr =
            (fields[field_num] = new_field_wrap(1, 4, 3, 51, 0, 0));
    if (rule_ptr->opt != NULL) {
        set_field_buffer_wrap(
                rule_fields.limit_unit_fld_ptr, 0, rule_ptr->opt->limit_unit);
    }
    set_field_back(rule_fields.limit_unit_fld_ptr, vccnf.color_win_rev);
    set_field_fore(
            rule_fields.limit_unit_fld_ptr, vccnf.color_win_rev | A_BOLD);
    field_num++;

    /* start disabled and set the field to dynamic */
    field_opts_off(rule_fields.limit_fld_ptr, O_VISIBLE | O_STATIC);
    field_opts_off(rule_fields.limit_label_fld_ptr, O_VISIBLE);

    /* burst label */
    /* TRANSLATORS: max 6 chars */
    rule_fields.burst_label_fld_ptr =
            (fields[field_num] = new_field_wrap(1, 8, 3, 60, 0, 0));
    set_field_buffer_wrap(rule_fields.burst_label_fld_ptr, 0, gettext("Burst"));
    field_opts_off(rule_fields.burst_label_fld_ptr, O_ACTIVE);
    set_field_back(rule_fields.burst_label_fld_ptr, vccnf.color_win);
    set_field_fore(rule_fields.burst_label_fld_ptr, vccnf.color_win);
    field_num++;

    /* limit */
    rule_fields.burst_fld_ptr =
            (fields[field_num] = new_field_wrap(1, 4, 3, 69, 0, 0));
    if (rule_ptr->opt != NULL) {
        if (rule_ptr->opt->burst > 0) {
            snprintf(loglimit_string, sizeof(loglimit_string), "%u",
                    rule_ptr->opt->burst);
            set_field_buffer_wrap(
                    rule_fields.burst_fld_ptr, 0, loglimit_string);
        }
    }
    set_field_back(rule_fields.burst_fld_ptr, vccnf.color_win_rev);
    set_field_fore(rule_fields.burst_fld_ptr, vccnf.color_win_rev | A_BOLD);
    field_num++;

    /* start disabled and set the field to dynamic */
    field_opts_off(rule_fields.burst_fld_ptr, O_VISIBLE | O_STATIC);
    field_opts_off(rule_fields.burst_label_fld_ptr, O_VISIBLE);

    /* chain label */
    rule_fields.chain_label_fld_ptr =
            (fields[field_num] = new_field_wrap(1, 9, 5, 29, 0, 0));
    set_field_buffer_wrap(rule_fields.chain_label_fld_ptr, 0, gettext("Chain"));
    field_opts_off(rule_fields.chain_label_fld_ptr, O_ACTIVE);
    set_field_back(rule_fields.chain_label_fld_ptr, vccnf.color_win);
    set_field_fore(rule_fields.chain_label_fld_ptr, vccnf.color_win);
    field_num++;

    /* chain */
    rule_fields.chain_fld_ptr =
            (fields[field_num] = new_field_wrap(1, 32, 5, 40, 0, 0));
    if (rule_ptr->opt != NULL)
        set_field_buffer_wrap(
                rule_fields.chain_fld_ptr, 0, rule_ptr->opt->chain);

    set_field_back(rule_fields.chain_fld_ptr, vccnf.color_win_rev);
    set_field_fore(rule_fields.chain_fld_ptr, vccnf.color_win_rev | A_BOLD);
    field_num++;

    /* interface starts disabled */
    field_opts_off(rule_fields.chain_label_fld_ptr, O_VISIBLE);
    field_opts_off(rule_fields.chain_fld_ptr, O_VISIBLE);

    /* via label */
    rule_fields.via_int_label_fld_ptr =
            (fields[field_num] = new_field_wrap(1, 9, 5, 29, 0, 0));
    set_field_buffer_wrap(rule_fields.via_int_label_fld_ptr, 0, gettext("Via"));
    field_opts_off(rule_fields.via_int_label_fld_ptr, O_ACTIVE);
    set_field_back(rule_fields.via_int_label_fld_ptr, vccnf.color_win);
    set_field_fore(rule_fields.via_int_label_fld_ptr, vccnf.color_win);
    field_num++;

    /* chain */
    rule_fields.via_int_fld_ptr =
            (fields[field_num] = new_field_wrap(1, 32, 5, 40, 0, 0));
    if (rule_ptr->opt != NULL)
        set_field_buffer_wrap(
                rule_fields.via_int_fld_ptr, 0, rule_ptr->opt->via_int);

    set_field_back(rule_fields.via_int_fld_ptr, vccnf.color_win_rev);
    set_field_fore(rule_fields.via_int_fld_ptr, vccnf.color_win_rev | A_BOLD);
    field_num++;

    /* interface starts disabled */
    field_opts_off(rule_fields.via_int_fld_ptr, O_VISIBLE);
    field_opts_off(rule_fields.via_int_fld_ptr, O_VISIBLE);

    /* Reject type label */
    rule_fields.reject_label_fld_ptr =
            (fields[field_num] = new_field_wrap(1, 12, 5, 29, 0, 0));
    set_field_buffer_wrap(
            rule_fields.reject_label_fld_ptr, 0, gettext("Reject type"));
    field_opts_off(rule_fields.reject_label_fld_ptr, O_ACTIVE);
    set_field_back(rule_fields.reject_label_fld_ptr, vccnf.color_win);
    set_field_fore(rule_fields.reject_label_fld_ptr, vccnf.color_win);
    field_num++;

    /* Reject type */
    rule_fields.reject_fld_ptr =
            (fields[field_num] = new_field_wrap(1, 23, 5, 48, 0, 0));

    if (rule_ptr->opt != NULL && rule_ptr->opt->reject_option == 1)
        set_field_buffer_wrap(
                rule_fields.reject_fld_ptr, 0, rule_ptr->opt->reject_type);

    set_field_back(rule_fields.reject_fld_ptr, vccnf.color_win_rev);
    set_field_fore(rule_fields.reject_fld_ptr, vccnf.color_win_rev | A_BOLD);
    field_num++;

    /* reject starts disabled */
    field_opts_off(rule_fields.reject_label_fld_ptr, O_VISIBLE);
    field_opts_off(rule_fields.reject_fld_ptr, O_VISIBLE);

    /* Redirectport label */
    rule_fields.redirect_label_fld_ptr =
            (fields[field_num] = new_field_wrap(1, 14, 7, 45, 0, 0));
    set_field_buffer_wrap(
            rule_fields.redirect_label_fld_ptr, 0, gettext("Redirect port"));
    field_opts_off(rule_fields.redirect_label_fld_ptr, O_ACTIVE);
    set_field_back(rule_fields.redirect_label_fld_ptr, vccnf.color_win);
    set_field_fore(rule_fields.redirect_label_fld_ptr, vccnf.color_win);
    field_num++;

    /* Redirectport */
    rule_fields.redirect_fld_ptr =
            (fields[field_num] = new_field_wrap(1, 11, 7, 61, 0, 0));
    if (rule_ptr->opt != NULL &&
            (rule_ptr->opt->redirectport > 0 &&
                    rule_ptr->opt->redirectport <= 65535)) {
        snprintf(redirect_port, sizeof(redirect_port), "%d",
                rule_ptr->opt->redirectport);
        set_field_buffer_wrap(rule_fields.redirect_fld_ptr, 0, redirect_port);
    }
    set_field_back(rule_fields.redirect_fld_ptr, vccnf.color_win_rev);
    set_field_fore(rule_fields.redirect_fld_ptr, vccnf.color_win_rev | A_BOLD);
    field_num++;

    /* start disabled */
    field_opts_off(rule_fields.redirect_fld_ptr, O_VISIBLE);
    field_opts_off(rule_fields.redirect_label_fld_ptr, O_VISIBLE);

    /* listenport (portfw) label */
    /* TRANSLATORS: max 11 chars */
    rule_fields.listen_label_fld_ptr =
            (fields[field_num] = new_field_wrap(1, 12, 7, 45, 0, 0));
    set_field_buffer_wrap(
            rule_fields.listen_label_fld_ptr, 0, gettext("Listen port"));
    field_opts_off(rule_fields.listen_label_fld_ptr, O_ACTIVE);
    set_field_back(rule_fields.listen_label_fld_ptr, vccnf.color_win);
    set_field_fore(rule_fields.listen_label_fld_ptr, vccnf.color_win);
    field_num++;

    /* listenport */
    rule_fields.listen_fld_ptr =
            (fields[field_num] = new_field_wrap(1, 14, 7, 58, 0, 0));
    set_field_back(rule_fields.listen_fld_ptr, vccnf.color_win_rev);
    set_field_fore(rule_fields.listen_fld_ptr, vccnf.color_win_rev | A_BOLD);
    field_num++;

    /* start disabled and set the field to dynamic */
    field_opts_off(rule_fields.listen_fld_ptr, O_VISIBLE | O_STATIC);
    field_opts_off(rule_fields.listen_label_fld_ptr, O_VISIBLE);

    /* this is needed after declaring the field dynamic */
    if (rule_ptr->opt != NULL && rule_ptr->opt->listenport == 1) {
        char *str = vrmr_list_to_portopts(&rule_ptr->opt->ListenportList, NULL);
        set_field_buffer_wrap(rule_fields.listen_fld_ptr, 0, str);
        free(str);
    }

    /* remoteport (portfw) label */
    /* TRANSLATORS: max 11 chars */
    rule_fields.remote_label_fld_ptr =
            (fields[field_num] = new_field_wrap(1, 12, 9, 45, 0, 0));
    set_field_buffer_wrap(
            rule_fields.remote_label_fld_ptr, 0, gettext("Remote port"));
    field_opts_off(rule_fields.remote_label_fld_ptr, O_ACTIVE);
    set_field_back(rule_fields.remote_label_fld_ptr, vccnf.color_win);
    set_field_fore(rule_fields.remote_label_fld_ptr, vccnf.color_win);
    field_num++;

    /* remoteport - total field size: 64 -> 50 offscreen */
    rule_fields.remote_fld_ptr =
            (fields[field_num] = new_field_wrap(1, 14, 9, 58, 0, 0));
    set_field_back(rule_fields.remote_fld_ptr, vccnf.color_win_rev);
    set_field_fore(rule_fields.remote_fld_ptr, vccnf.color_win_rev | A_BOLD);
    field_num++;

    /* start disabled and set the field to dynamic */
    field_opts_off(rule_fields.remote_fld_ptr, O_VISIBLE | O_STATIC);
    field_opts_off(rule_fields.remote_label_fld_ptr, O_VISIBLE);

    /* this is needed after declaring the field dynamic */
    if (rule_ptr->opt != NULL && rule_ptr->opt->remoteport == 1) {
        char *str = vrmr_list_to_portopts(&rule_ptr->opt->RemoteportList, NULL);
        set_field_buffer_wrap(rule_fields.remote_fld_ptr, 0, str);
        free(str);
    }

    /* terminate the fields-array */
    fields[n_fields] = NULL;

    vrmr_fatal_if(n_fields != field_num);

    /* create the window, panel, form */
    snprintf(window_title, sizeof(window_title), gettext("Edit Rule: %d"),
            rule_ptr->number);
    edit_win = create_newwin(
            height, width, starty, startx, window_title, vccnf.color_win);
    vrmr_fatal_if_null(edit_win);
    my_panels[0] = new_panel(edit_win);
    vrmr_fatal_if_null(my_panels[0]);
    keypad(edit_win, TRUE);
    form = new_form(fields);
    vrmr_fatal_if_null(form);
    scale_form(form, &rows, &cols);
    set_form_win(form, edit_win);
    set_form_sub(form, derwin(edit_win, rows, cols, 1, 2));
    post_form(form);

    draw_top_menu(top_win, gettext("Edit Rule"), key_choices_n, key_choices,
            cmd_choices_n, cmd_choices);

    /* set cursor position */
    pos_form_cursor(form);

    update_panels();
    doupdate();

    /*
        loop through to get user requests
    */
    while (quit == 0) {
        /* hide/disable fields we don't need */
        if (rule_ptr->action != VRMR_AT_REJECT) {
            field_opts_off(rule_fields.reject_fld_ptr, O_VISIBLE);
            field_opts_off(rule_fields.reject_label_fld_ptr, O_VISIBLE);
        }
        if (rule_ptr->action != VRMR_AT_CHAIN) {
            field_opts_off(rule_fields.chain_fld_ptr, O_VISIBLE);
            field_opts_off(rule_fields.chain_label_fld_ptr, O_VISIBLE);
        }
        if (rule_ptr->action != VRMR_AT_REDIRECT) {
            field_opts_off(rule_fields.redirect_fld_ptr, O_VISIBLE);
            field_opts_off(rule_fields.redirect_label_fld_ptr, O_VISIBLE);
        }
        if (rule_ptr->action != VRMR_AT_BOUNCE) {
            field_opts_off(rule_fields.via_int_fld_ptr, O_VISIBLE);
            field_opts_off(rule_fields.via_int_label_fld_ptr, O_VISIBLE);
        }
        if ((rule_ptr->action != VRMR_AT_SNAT &&
                    rule_ptr->action != VRMR_AT_MASQ &&
                    rule_ptr->action != VRMR_AT_PORTFW &&
                    rule_ptr->action != VRMR_AT_BOUNCE &&
                    rule_ptr->action != VRMR_AT_DNAT) ||
                !advanced_mode) {
            field_opts_off(rule_fields.random_brackets_fld_ptr, O_VISIBLE);
            field_opts_off(rule_fields.random_label_fld_ptr, O_VISIBLE);
            field_opts_off(rule_fields.random_fld_ptr, O_VISIBLE);
        }
        if (!advanced_mode) {
            field_opts_off(rule_fields.burst_fld_ptr, O_VISIBLE | O_STATIC);
            field_opts_off(rule_fields.burst_label_fld_ptr, O_VISIBLE);

            field_opts_off(
                    rule_fields.limit_unit_fld_ptr, O_VISIBLE | O_STATIC);
            field_opts_off(rule_fields.limit_unit_label_fld_ptr, O_VISIBLE);

            field_opts_off(rule_fields.limit_fld_ptr, O_VISIBLE | O_STATIC);
            field_opts_off(rule_fields.limit_label_fld_ptr, O_VISIBLE);
        }
        if ((rule_ptr->action != VRMR_AT_PORTFW &&
                    rule_ptr->action != VRMR_AT_DNAT) ||
                !advanced_mode) {
            field_opts_off(rule_fields.listen_fld_ptr, O_VISIBLE);
            field_opts_off(rule_fields.listen_label_fld_ptr, O_VISIBLE);

            field_opts_off(rule_fields.remote_fld_ptr, O_VISIBLE);
            field_opts_off(rule_fields.remote_label_fld_ptr, O_VISIBLE);
        }
        if (rule_ptr->action == VRMR_AT_LOG) {
            field_opts_off(rule_fields.log_fld_ptr, O_ACTIVE);
        }
        if (((rule_ptr->action != VRMR_AT_NFQUEUE)) || !advanced_mode) {
            field_opts_off(rule_fields.nfqueuenum_label_fld_ptr, O_VISIBLE);
            field_opts_off(rule_fields.nfqueuenum_fld_ptr, O_VISIBLE);
        }
        if (((rule_ptr->action != VRMR_AT_NFLOG)) || !advanced_mode) {
            field_opts_off(rule_fields.nflognum_label_fld_ptr, O_VISIBLE);
            field_opts_off(rule_fields.nflognum_fld_ptr, O_VISIBLE);
        }
        if (rule_ptr->action != VRMR_AT_LOG || !advanced_mode) {
            field_opts_off(rule_fields.loglimit_label_fld_ptr, O_VISIBLE);
            field_opts_off(rule_fields.loglimit_fld_ptr, O_VISIBLE);
        }
        if (!advanced_mode || rule_ptr->action == VRMR_AT_SNAT ||
                rule_ptr->action == VRMR_AT_DNAT ||
                rule_ptr->action == VRMR_AT_MASQ) {
            field_opts_off(rule_fields.nfmark_label_fld_ptr, O_VISIBLE);
            field_opts_off(rule_fields.nfmark_fld_ptr, O_VISIBLE);
        }
        if (!advanced_mode ||
                strncmp(field_buffer(rule_fields.fromzone_fld_ptr, 0),
                        "firewall", 8) == 0) {
            field_opts_off(rule_fields.in_int_label_fld_ptr, O_VISIBLE);
            field_opts_off(rule_fields.in_int_fld_ptr, O_VISIBLE);
        }
        if (!advanced_mode ||
                strncmp(field_buffer(rule_fields.tozone_fld_ptr, 0), "firewall",
                        8) == 0) {
            field_opts_off(rule_fields.out_int_label_fld_ptr, O_VISIBLE);
            field_opts_off(rule_fields.out_int_fld_ptr, O_VISIBLE);
        }

        /* show/enable fields we need */
        if (rule_ptr->action == VRMR_AT_REJECT) {
            field_opts_on(rule_fields.reject_fld_ptr, O_VISIBLE);
            field_opts_on(rule_fields.reject_label_fld_ptr, O_VISIBLE);
        }
        if (rule_ptr->action == VRMR_AT_CHAIN) {
            field_opts_on(rule_fields.chain_fld_ptr, O_VISIBLE);
            field_opts_on(rule_fields.chain_label_fld_ptr, O_VISIBLE);
        }
        if (rule_ptr->action == VRMR_AT_BOUNCE) {
            field_opts_on(rule_fields.via_int_fld_ptr, O_VISIBLE);
            field_opts_on(rule_fields.via_int_label_fld_ptr, O_VISIBLE);
        }
        if (rule_ptr->action == VRMR_AT_REDIRECT) {
            field_opts_on(rule_fields.redirect_fld_ptr, O_VISIBLE);
            field_opts_on(rule_fields.redirect_label_fld_ptr, O_VISIBLE);
        }
        if (rule_ptr->action == VRMR_AT_SNAT ||
                rule_ptr->action == VRMR_AT_MASQ ||
                rule_ptr->action == VRMR_AT_DNAT ||
                rule_ptr->action == VRMR_AT_PORTFW ||
                rule_ptr->action == VRMR_AT_BOUNCE) {
            if (advanced_mode) {
                field_opts_on(rule_fields.random_brackets_fld_ptr, O_VISIBLE);
                field_opts_on(rule_fields.random_label_fld_ptr, O_VISIBLE);
                field_opts_on(rule_fields.random_fld_ptr, O_VISIBLE);
            }
        }
        if ((rule_ptr->action == VRMR_AT_PORTFW ||
                    rule_ptr->action == VRMR_AT_DNAT) &&
                advanced_mode) {
            field_opts_on(rule_fields.listen_fld_ptr, O_VISIBLE);
            field_opts_on(rule_fields.listen_label_fld_ptr, O_VISIBLE);

            field_opts_on(rule_fields.remote_fld_ptr, O_VISIBLE);
            field_opts_on(rule_fields.remote_label_fld_ptr, O_VISIBLE);
        }
        if (rule_ptr->action == VRMR_AT_NFQUEUE && advanced_mode) {
            field_opts_on(rule_fields.nfqueuenum_label_fld_ptr, O_VISIBLE);
            field_opts_on(rule_fields.nfqueuenum_fld_ptr, O_VISIBLE);
        }
        if (rule_ptr->action == VRMR_AT_NFLOG && advanced_mode) {
            field_opts_on(rule_fields.nflognum_label_fld_ptr, O_VISIBLE);
            field_opts_on(rule_fields.nflognum_fld_ptr, O_VISIBLE);
        }

        if (advanced_mode) {
            field_opts_on(rule_fields.burst_fld_ptr, O_VISIBLE | O_STATIC);
            field_opts_on(rule_fields.burst_label_fld_ptr, O_VISIBLE);

            field_opts_on(rule_fields.limit_unit_fld_ptr, O_VISIBLE | O_STATIC);
            field_opts_on(rule_fields.limit_unit_label_fld_ptr, O_VISIBLE);

            field_opts_on(rule_fields.limit_fld_ptr, O_VISIBLE | O_STATIC);
            field_opts_on(rule_fields.limit_label_fld_ptr, O_VISIBLE);
        }

        if (rule_ptr->action != VRMR_AT_LOG) {
            field_opts_on(rule_fields.log_fld_ptr, O_ACTIVE);
        }
        if (rule_ptr->action != VRMR_AT_LOG && advanced_mode) {
            field_opts_on(rule_fields.loglimit_label_fld_ptr, O_VISIBLE);
            field_opts_on(rule_fields.loglimit_fld_ptr, O_VISIBLE);
        }
        if (rule_ptr->action != VRMR_AT_SNAT &&
                rule_ptr->action != VRMR_AT_DNAT &&
                rule_ptr->action != VRMR_AT_MASQ && advanced_mode) {
            field_opts_on(rule_fields.nfmark_label_fld_ptr, O_VISIBLE);
            field_opts_on(rule_fields.nfmark_fld_ptr, O_VISIBLE);
        }
        if (advanced_mode) {
            if (strncmp(field_buffer(rule_fields.fromzone_fld_ptr, 0),
                        "firewall", 8) != 0) {
                field_opts_on(rule_fields.in_int_label_fld_ptr, O_VISIBLE);
                field_opts_on(rule_fields.in_int_fld_ptr, O_VISIBLE);
            }

            if (strncmp(field_buffer(rule_fields.tozone_fld_ptr, 0), "firewall",
                        8) != 0) {
                field_opts_on(rule_fields.out_int_label_fld_ptr, O_VISIBLE);
                field_opts_on(rule_fields.out_int_fld_ptr, O_VISIBLE);
            }
        }

        /* do some nice coloring of the action field */
        if (rule_ptr->action == VRMR_AT_ACCEPT) {
            set_field_back(
                    rule_fields.action_fld_ptr, vccnf.color_win_green_rev);
            set_field_fore(rule_fields.action_fld_ptr,
                    vccnf.color_win_green_rev | A_BOLD);
        } else if (rule_ptr->action == VRMR_AT_DROP ||
                   rule_ptr->action == VRMR_AT_REJECT) {
            set_field_back(rule_fields.action_fld_ptr, vccnf.color_win_red_rev);
            set_field_fore(rule_fields.action_fld_ptr,
                    vccnf.color_win_red_rev | A_BOLD);
        } else if (rule_ptr->action == VRMR_AT_LOG) {
            set_field_back(
                    rule_fields.action_fld_ptr, vccnf.color_win_rev | A_BOLD);
            set_field_fore(
                    rule_fields.action_fld_ptr, vccnf.color_win_rev | A_BOLD);
        } else {
            set_field_back(rule_fields.action_fld_ptr, vccnf.color_win_rev);
            set_field_fore(
                    rule_fields.action_fld_ptr, vccnf.color_win_rev | A_BOLD);
        }

        /* color firewall zones */
        if (strncasecmp(field_buffer(rule_fields.fromzone_fld_ptr, 0),
                    "firewall", 8) == 0)
            set_field_fore(rule_fields.fromzone_fld_ptr,
                    vccnf.color_win_rev_yellow | A_BOLD);
        else
            set_field_fore(
                    rule_fields.fromzone_fld_ptr, vccnf.color_win_rev | A_BOLD);

        if (strncasecmp(field_buffer(rule_fields.tozone_fld_ptr, 0), "firewall",
                    8) == 0)
            set_field_fore(rule_fields.tozone_fld_ptr,
                    vccnf.color_win_rev_yellow | A_BOLD);
        else
            set_field_fore(
                    rule_fields.tozone_fld_ptr, vccnf.color_win_rev | A_BOLD);

        prev = cur;
        cur = current_field(form);

        draw_field_active_mark(
                cur, prev, edit_win, form, vccnf.color_win_mark | A_BOLD);

        /*
            now give some help message in the status win
        */
        if (cur == rule_fields.action_fld_ptr)
            status_print(
                    status_win, gettext("Press SPACE to select an action."));
        else if (cur == rule_fields.service_fld_ptr)
            status_print(
                    status_win, gettext("Press SPACE to select a service."));
        else if (cur == rule_fields.fromzone_fld_ptr ||
                 cur == rule_fields.tozone_fld_ptr)
            status_print(
                    status_win, gettext("Press SPACE to select a host, group "
                                        "or network, or the firewall."));
        else if (cur == rule_fields.logprefix_fld_ptr)
            status_print(status_win,
                    gettext("Enter a text to be included in the log message."));
        else if (cur == rule_fields.reject_fld_ptr)
            status_print(status_win,
                    gettext("Press SPACE to select a reject type."));
        else if (cur == rule_fields.redirect_fld_ptr)
            status_print(
                    status_win, gettext("Enter a portnumber to redirect to."));
        else if (cur == rule_fields.listen_fld_ptr)
            status_print(status_win,
                    gettext("Enter a comma-sepparated list of ports for the "
                            "firewall to listen on."));
        else if (cur == rule_fields.remote_fld_ptr)
            status_print(status_win,
                    gettext("Enter a comma-sepparated list of ports for the "
                            "firewall to forward to."));
        else if (cur == rule_fields.comment_fld_ptr)
            status_print(status_win, gettext("Enter a optional comment."));
        else if (cur == rule_fields.loglimit_fld_ptr)
            status_print(
                    status_win, gettext("Maximum number of loglines per second "
                                        "(to prevent DoS), 0 for no limit."));
        else if (cur == rule_fields.log_fld_ptr)
            status_print(status_win,
                    gettext("Press SPACE to toggle logging of this rule."));
        else if (cur == rule_fields.nfqueuenum_fld_ptr)
            status_print(status_win,
                    gettext("Queue number to use. Possible values: 0-65535."));
        else if (cur == rule_fields.nflognum_fld_ptr)
            status_print(status_win,
                    gettext("NFLog number to use. Possible values: 0-65535."));
        else if (cur == rule_fields.in_int_fld_ptr)
            status_print(
                    status_win, gettext("Press SPACE to select an interface to "
                                        "limit this rule to."));
        else if (cur == rule_fields.out_int_fld_ptr)
            status_print(
                    status_win, gettext("Press SPACE to select an interface to "
                                        "limit this rule to."));
        else if (cur == rule_fields.via_int_fld_ptr)
            status_print(
                    status_win, gettext("Press SPACE to select an interface. "
                                        "Read help for more info."));
        else if (cur == rule_fields.nfmark_fld_ptr)
            status_print(status_win, gettext("Enter a nfmark. Use > 20.000.000 "
                                             "when using the QUEUE action."));
        else if (cur == rule_fields.limit_fld_ptr)
            status_print(status_win,
                    gettext("Average new connections per amount of time (to "
                            "prevent DoS), 0 for no limit."));
        else if (cur == rule_fields.limit_unit_fld_ptr)
            status_print(status_win,
                    gettext("Unit for the limit: sec, min, hour, day."));
        else if (cur == rule_fields.burst_fld_ptr)
            status_print(
                    status_win, gettext("Maximum new connections per second "
                                        "(to prevent DoS), 0 for no limit."));
        else if (cur == rule_fields.random_fld_ptr)
            status_print(status_win, gettext("Randomize the source ports of "
                                             "NAT'd connections."));

        int ch = wgetch(edit_win);
        int not_defined = 0;
        if (cur == rule_fields.logprefix_fld_ptr ||
                cur == rule_fields.redirect_fld_ptr ||
                cur == rule_fields.listen_fld_ptr ||
                cur == rule_fields.loglimit_fld_ptr ||
                cur == rule_fields.remote_fld_ptr ||
                cur == rule_fields.comment_fld_ptr ||
                cur == rule_fields.nfmark_fld_ptr ||
                cur == rule_fields.chain_fld_ptr ||
                cur == rule_fields.limit_fld_ptr ||
                cur == rule_fields.nfqueuenum_fld_ptr ||
                cur == rule_fields.nflognum_fld_ptr ||
                cur == rule_fields.burst_fld_ptr) {
            not_defined = !(nav_field_simpletext(form, ch));
        } else if (cur == rule_fields.random_fld_ptr ||
                   cur == rule_fields.log_fld_ptr) {
            not_defined = !(nav_field_toggleX(form, ch));
        } else {
            not_defined = 1;
        }

        if (not_defined == 1) {
            switch (ch) {
                case KEY_F(6):
                case 'S':
                case 's':
                    if (rule_ptr->opt == NULL) {
                        rule_ptr->opt = vrmr_rule_option_malloc();
                        vrmr_fatal_alloc(
                                "vrmr_rule_option_malloc", rule_ptr->opt);
                    }
                    VrShapeRule(rule_ptr->opt);
                    break;
                case KEY_DOWN:
                case 10: // enter
                case 9:  // tab

                    form_driver_wrap(form, REQ_NEXT_FIELD);
                    form_driver_wrap(form, REQ_END_LINE);
                    break;

                case KEY_UP:

                    form_driver_wrap(form, REQ_PREV_FIELD);
                    form_driver_wrap(form, REQ_END_LINE);
                    break;

                case 32: /* space */

                    if (cur == rule_fields.action_fld_ptr) {
                        copy_field2buf(select_choice, field_buffer(cur, 0),
                                sizeof(select_choice));

                        char *action_ptr;
                        /* ask the user about the new action */
                        if ((action_ptr = selectbox(gettext("Action"),
                                     gettext("Select action"), action_choices_n,
                                     action_choices, 1, select_choice))) {
                            set_field_buffer_wrap(cur, 0, action_ptr);
                            rule_ptr->action = vrmr_rules_actiontoi(action_ptr);
                            free(action_ptr);

                            /* if action is LOG, disable the log option. */
                            if (rule_ptr->action == VRMR_AT_LOG) {
                                set_field_buffer_wrap(
                                        rule_fields.log_fld_ptr, 0, " ");
                            }
                        }
                    } else if (cur == rule_fields.fromzone_fld_ptr ||
                               cur == rule_fields.tozone_fld_ptr) {
                        for (zone_choices_n = 0, d_node = zones->list.top;
                                d_node; d_node = d_node->next) {
                            vrmr_fatal_if_null(d_node->data);
                            zone_ptr = d_node->data;

                            if (zone_ptr->type != VRMR_TYPE_FIREWALL) {
                                zone_choices_n++;
                            }
                            /* extra one for network(broadcast) */
                            if (zone_ptr->type == VRMR_TYPE_NETWORK) {
                                zone_choices_n++;
                            }
                        }
                        zone_choices_n +=
                                3; /* for firewall, firewall(any) and any */

                        const char **zone_choices = calloc(zone_choices_n + 1,
                                VRMR_VRMR_MAX_HOST_NET_ZONE);
                        vrmr_fatal_alloc("calloc", zone_choices);

                        for (i = zone_choices_n - 1, d_node = zones->list.bot;
                                d_node; d_node = d_node->prev) {
                            vrmr_fatal_if_null(d_node->data);
                            zone_ptr = d_node->data;

                            if (zone_ptr->type == VRMR_TYPE_FIREWALL)
                                continue;

                            /* extra one for network(broadcast) */
                            if (zone_ptr->type == VRMR_TYPE_NETWORK) {
                                snprintf(zone_ptr->broadcast_name,
                                        sizeof(zone_ptr->broadcast_name),
                                        "%s.%s(broadcast)",
                                        zone_ptr->network_name,
                                        zone_ptr->zone_name);
                                zone_choices[i] = zone_ptr->broadcast_name;
                                i--;
                            }
                            zone_choices[i] = zone_ptr->name;
                            i--;
                        }
                        zone_choices[0] = "firewall";
                        zone_choices[1] = "firewall(any)";
                        zone_choices[2] = "any";
                        zone_choices[zone_choices_n] = NULL;

                        copy_field2buf(select_choice, field_buffer(cur, 0),
                                sizeof(select_choice));

                        /* get the zone */
                        if ((choice_ptr = selectbox(gettext("Select"),
                                     gettext("Select a host, group or network"),
                                     zone_choices_n, zone_choices, 2,
                                     select_choice))) {
                            set_field_buffer_wrap(cur, 0, choice_ptr);
                            free(choice_ptr);
                            choice_ptr = NULL;
                        }

                        free(zone_choices);
                        zone_choices = NULL;
                    } else if (cur == rule_fields.service_fld_ptr) {
                        service_choices_n = services->list.len + 1;

                        const char **service_choices =
                                calloc(service_choices_n + 1, sizeof(char *));
                        vrmr_fatal_alloc("calloc", service_choices);

                        for (i = 1, d_node = services->list.top;
                                d_node && i < service_choices_n;
                                d_node = d_node->next, i++) {
                            vrmr_fatal_if_null(d_node->data);
                            service_ptr = d_node->data;
                            service_choices[i] = service_ptr->name;
                        }
                        service_choices[0] = "any";
                        service_choices[i] = NULL;

                        copy_field2buf(select_choice, field_buffer(cur, 0),
                                sizeof(select_choice));

                        /* get the service */
                        if ((choice_ptr = selectbox(gettext("Select"),
                                     gettext("Select a service"),
                                     service_choices_n, service_choices, 3,
                                     select_choice))) {
                            set_field_buffer_wrap(cur, 0, choice_ptr);
                            free(choice_ptr);
                            choice_ptr = NULL;
                        }

                        free(service_choices);
                        service_choices = NULL;
                    } else if (cur == rule_fields.reject_fld_ptr) {
                        copy_field2buf(select_choice, field_buffer(cur, 0),
                                sizeof(select_choice));

                        char *reject_ptr;
                        if ((reject_ptr = selectbox(gettext("Reject type"),
                                     gettext("Select reject type"),
                                     reject_types_n, reject_types, 1,
                                     select_choice))) {
                            set_field_buffer_wrap(cur, 0, reject_ptr);
                            free(reject_ptr);
                        }
                    } else if (cur == rule_fields.in_int_fld_ptr) {
                        if (field_buffer(rule_fields.fromzone_fld_ptr, 0)[0] ==
                                        '\0' ||
                                field_buffer(rule_fields.fromzone_fld_ptr,
                                        0)[0] == ' ') {
                            vrmr_warning(
                                    VR_WARN, gettext("no from zone, please "
                                                     "select one first."));
                        } else {
                            /* set to NULL so we can be sure that it is set
                             * properly later */
                            interfaces_list = NULL;

                            /* any just use all interfaces */
                            if (strncasecmp(
                                        field_buffer(
                                                rule_fields.fromzone_fld_ptr,
                                                0),
                                        "any", 3) == 0) {
                                interfaces_list = &interfaces->list;
                            } else {
                                /* copy the from field to the zonename buffer */
                                copy_field2buf(zonename,
                                        field_buffer(
                                                rule_fields.fromzone_fld_ptr,
                                                0),
                                        sizeof(zonename));

                                /* get the zone */
                                if (!(zone_ptr = vrmr_search_zonedata(
                                              zones, zonename))) {
                                    vrmr_error(-1, VR_INTERR,
                                            "zone '%s' not found", zonename);
                                } else {
                                    if (zone_ptr->type == VRMR_TYPE_ZONE) {
                                        vrmr_warning(VR_WARN,
                                                gettext("\"zone\" not yet "
                                                        "supported."));
                                    } else {
                                        /* the interfaces are attached to the
                                         * network, so get the network */
                                        if (zone_ptr->type ==
                                                VRMR_TYPE_NETWORK) {
                                            network_ptr = zone_ptr;
                                        } else if (zone_ptr->type ==
                                                           VRMR_TYPE_HOST ||
                                                   zone_ptr->type ==
                                                           VRMR_TYPE_GROUP) {
                                            network_ptr =
                                                    zone_ptr->network_parent;
                                        } else {
                                            vrmr_fatal("wrong zone type '%d'",
                                                    zone_ptr->type);
                                        }

                                        interfaces_list =
                                                &network_ptr->InterfaceList;
                                    }
                                }
                            }

                            if (interfaces_list != NULL) {
                                /* check if there are interfaces defined to
                                 * choose from */
                                n_choices = interfaces_list->len + 1;

                                /* get some mem */
                                const char **choices = calloc(
                                        n_choices + 1, VRMR_MAX_INTERFACE);
                                vrmr_fatal_alloc("calloc", choices);

                                /* load the interfaces */
                                for (i = n_choices - 1,
                                    d_node = interfaces_list->bot;
                                        d_node; d_node = d_node->prev) {
                                    vrmr_fatal_if_null(d_node->data);
                                    iface_ptr = d_node->data;
                                    choices[i] = iface_ptr->name;
                                    i--;
                                }
                                choices[i] = gettext("Any");

                                copy_field2buf(select_choice,
                                        field_buffer(cur, 0),
                                        sizeof(select_choice));

                                /* ask the user to select an interface */
                                if (!(choice_ptr = selectbox(
                                              gettext("Set interface filter"),
                                              gettext("Select an interface "
                                                      "('Any' to disable "
                                                      "filter)"),
                                              n_choices, choices, 1,
                                              select_choice))) {
                                    /* no choice */
                                } else {
                                    /* any means empty the field */
                                    if (strcmp(choice_ptr, gettext("Any")) == 0)
                                        set_field_buffer_wrap(
                                                rule_fields.in_int_fld_ptr, 0,
                                                "");
                                    else
                                        set_field_buffer_wrap(
                                                rule_fields.in_int_fld_ptr, 0,
                                                choice_ptr);

                                    free(choice_ptr);
                                }

                                /* cleanup */
                                free(choices);
                            }
                        }
                    } else if (cur == rule_fields.out_int_fld_ptr) {
                        if (field_buffer(rule_fields.tozone_fld_ptr, 0)[0] ==
                                        '\0' ||
                                field_buffer(rule_fields.tozone_fld_ptr,
                                        0)[0] == ' ') {
                            vrmr_warning(
                                    VR_WARN, gettext("no 'to' zone, please "
                                                     "select one first."));
                        } else {
                            /* set to NULL so we can be sure that it is set
                             * properly later */
                            interfaces_list = NULL;

                            /* any just use all interfaces */
                            if (strncasecmp(
                                        field_buffer(
                                                rule_fields.tozone_fld_ptr, 0),
                                        "any", 3) == 0) {
                                interfaces_list = &interfaces->list;
                            } else {
                                /* copy the from field to the zonename buffer */
                                copy_field2buf(zonename,
                                        field_buffer(
                                                rule_fields.tozone_fld_ptr, 0),
                                        sizeof(zonename));
                                /* get the zone */
                                if (!(zone_ptr = vrmr_search_zonedata(
                                              zones, zonename))) {
                                    vrmr_error(-1, VR_INTERR,
                                            "zone '%s' not found", zonename);
                                } else {
                                    if (zone_ptr->type == VRMR_TYPE_ZONE) {
                                        vrmr_warning(VR_WARN,
                                                gettext("\"zone\" not yet "
                                                        "supported."));
                                    } else {
                                        /* the interfaces are attached to the
                                         * network, so get the network */
                                        if (zone_ptr->type ==
                                                VRMR_TYPE_NETWORK) {
                                            network_ptr = zone_ptr;
                                        } else if (zone_ptr->type ==
                                                           VRMR_TYPE_HOST ||
                                                   zone_ptr->type ==
                                                           VRMR_TYPE_GROUP) {
                                            network_ptr =
                                                    zone_ptr->network_parent;
                                        } else {
                                            vrmr_fatal("wrong zone type '%d'",
                                                    zone_ptr->type);
                                        }

                                        interfaces_list =
                                                &network_ptr->InterfaceList;
                                    }
                                }
                            }

                            if (interfaces_list != NULL) {
                                /* check if there are interfaces defined to
                                 * choose from */
                                n_choices = interfaces_list->len + 1;

                                /* get some mem */
                                const char **choices = calloc(
                                        n_choices + 1, VRMR_MAX_INTERFACE);
                                vrmr_fatal_alloc("calloc", choices);

                                /* load the interfaces */
                                for (i = n_choices - 1,
                                    d_node = interfaces_list->bot;
                                        d_node; d_node = d_node->prev) {
                                    vrmr_fatal_if_null(d_node->data);
                                    iface_ptr = d_node->data;
                                    choices[i] = iface_ptr->name;
                                    i--;
                                }
                                choices[i] = gettext("Any");

                                copy_field2buf(select_choice,
                                        field_buffer(cur, 0),
                                        sizeof(select_choice));

                                /* ask the user to select an interface */
                                if (!(choice_ptr = selectbox(
                                              gettext("Set interface filter"),
                                              gettext("Select an interface "
                                                      "('Any' to disable "
                                                      "filter)"),
                                              n_choices, choices, 1,
                                              select_choice))) {
                                    /* no choice */
                                } else {
                                    /* any means empty the field */
                                    if (strcmp(choice_ptr, gettext("Any")) == 0)
                                        set_field_buffer_wrap(
                                                rule_fields.out_int_fld_ptr, 0,
                                                "");
                                    else
                                        set_field_buffer_wrap(
                                                rule_fields.out_int_fld_ptr, 0,
                                                choice_ptr);

                                    free(choice_ptr);
                                }

                                /* cleanup */
                                free(choices);
                            }
                        }
                    } else if (cur == rule_fields.via_int_fld_ptr) {
                        interfaces_list = &interfaces->list;

                        if (interfaces_list != NULL) {
                            /* check if there are interfaces defined to choose
                             * from */
                            n_choices = interfaces_list->len;

                            /* get some mem */
                            const char **choices =
                                    calloc(n_choices + 1, VRMR_MAX_INTERFACE);
                            vrmr_fatal_alloc("calloc", choices);

                            /* load the interfaces */
                            for (i = 0, d_node = interfaces_list->top; d_node;
                                    d_node = d_node->next, i++) {
                                vrmr_fatal_if_null(d_node->data);
                                iface_ptr = d_node->data;
                                choices[i] = iface_ptr->name;
                            }
                            choices[i] = NULL;

                            copy_field2buf(select_choice, field_buffer(cur, 0),
                                    sizeof(select_choice));

                            /* ask the user to select an interface */
                            if (!(choice_ptr = selectbox(
                                          gettext("Set Via interface"),
                                          gettext("Select an interface"),
                                          n_choices, choices, 1,
                                          select_choice))) {
                                /* no choice */
                            } else {
                                set_field_buffer_wrap(
                                        rule_fields.via_int_fld_ptr, 0,
                                        choice_ptr);
                                free(choice_ptr);
                            }

                            /* cleanup */
                            free(choices);
                        }
                    } else if (cur == rule_fields.limit_unit_fld_ptr) {
                        const char *limit_unit_choices[] = {
                                "Sec",
                                "Min",
                                "Hour",
                                "Day",
                        };
                        char *limit_unit_ptr = NULL;
                        size_t limit_unit_choices_n = 4;

                        copy_field2buf(select_choice, field_buffer(cur, 0),
                                sizeof(select_choice));

                        /* ask the user about the new action */
                        if ((limit_unit_ptr = selectbox(gettext("Unit"),
                                     gettext("Select time unit"),
                                     limit_unit_choices_n, limit_unit_choices,
                                     1, /* 1 column */
                                     select_choice))) {
                            set_field_buffer_wrap(cur, 0, limit_unit_ptr);
                            free(limit_unit_ptr);
                        }
                    } else {
                        form_driver_wrap(form, ch);
                    }
                    break;

                case 27:
                case 'q':
                case 'Q':
                case KEY_F(10):

                    result = edit_rule_fields_to_rule(
                            fields, n_fields, rule_ptr, reg);
                    if (result == 1) {
                        if (edit_rule_simple_check(rule_ptr) == 0 ||
                                edit_rule_check_action_opts(rule_ptr) == 0) {
                            if (!(confirm(gettext("Not all required fields are "
                                                  "filled in"),
                                        gettext("Do you want to look at the "
                                                "rule again? (no will delete "
                                                "the rule)"),
                                        vccnf.color_win_note,
                                        vccnf.color_win_note_rev | A_BOLD,
                                        1))) {
                                retval = -1;
                                quit = 1;
                            }
                        } else {
                            /* check */
                            if (vrmr_rules_analyze_rule(rule_ptr, &tmp_ruledata,
                                        services, zones, interfaces,
                                        conf) < 0) {
                                /* clear tmp_ruledata for the next use */
                                bzero(&tmp_ruledata, sizeof(tmp_ruledata));

                                /* ask the user if he/she want to look at the
                                 * rule again */
                                if (!(confirm(gettext("An error was detected "
                                                      "in the rule"),
                                            gettext("Do you want to look at it "
                                                    "again? (no will delete "
                                                    "the rule)"),
                                            vccnf.color_win_note,
                                            vccnf.color_win_note_rev | A_BOLD,
                                            1))) {
                                    retval = -1;
                                    quit = 1;
                                } else {
                                    /* we're not quiting yet! */
                                    quit = 0;
                                    retval = 0;
                                }
                            } else {
                                quit = 1;
                                retval = 1;
                            }
                        }
                    } else if (result == 0) {
                        /* no change */
                        quit = 1;
                    } else {
                        /* error */
                        retval = -1;
                    }

                    break;

                case KEY_F(12):
                case 'h':
                case 'H':
                case '?':

                    print_help(":[VUURMUUR:RULES:EDIT]:");
                    break;

                /* enable advanced mode */
                case KEY_F(5):
                case 'a':
                case 'A':

                    if (!advanced_mode)
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
    for (i = 0; i < n_fields; i++) {
        free_field(fields[i]);
    }
    free(fields);
    del_panel(my_panels[0]);
    destroy_win(edit_win);
    update_panels();
    doupdate();

    status_print(status_win, gettext("Ready."));

    vrmr_debug(HIGH, "returning retval = %d.", retval);
    return (retval);
}

struct {
    FIELD *comment_label_fld_ptr, *comment_fld_ptr;
} sep_rule_fields;

/*  edit_rule_fields_to_rule

    Returncodes:
         1: changes stored
         0: no changes
*/
static int edit_seprule_fields_to_rule(FIELD **fields, size_t n_fields,
        struct vrmr_rule *rule_ptr, struct vrmr_regex *reg)
{
    int z = 0, retval = 0;
    size_t i = 0;

    vrmr_fatal_if_null(fields);
    vrmr_fatal_if_null(rule_ptr);
    vrmr_fatal_if_null(reg);

    /* check for changed fields */
    for (i = 0; i < n_fields; i++) {
        if (field_status(fields[i]) == FALSE)
            continue;

        if (fields[i] != sep_rule_fields.comment_fld_ptr)
            continue;

        int last_char = 0;

        /* first check if the commentfield is valid */
        if (validate_commentfield(field_buffer(fields[i], 0), reg->comment) ==
                0) {
            /* options */
            if (rule_ptr->opt == NULL) {
                rule_ptr->opt = vrmr_rule_option_malloc();
                vrmr_fatal_alloc("vrmr_rule_option_malloc", rule_ptr->opt);
            }

            const char *buf = field_buffer(fields[i], 0);
            vrmr_fatal_if_null(buf);

            for (z = 0; z < (int)sizeof(rule_ptr->opt->comment) &&
                        buf[z] != '\n' && buf[z] != '\0';
                    z++) /* 12 is max prefix length */
            {
                rule_ptr->opt->comment[z] = buf[z];

                /* make sure that we place the NULL after the last char: no
                 * trailing spaces. */
                if (rule_ptr->opt->comment[z] != ' ')
                    last_char = z + 1;
            }
            rule_ptr->opt->comment[last_char] = '\0';

            if (strcmp(rule_ptr->opt->comment, "") == 0)
                rule_ptr->opt->rule_comment = 0;
            else
                rule_ptr->opt->rule_comment = 1;

            retval = 1;
        }
    }
    return (retval);
}

/*  Returncodes:
         0: ok, no changes
         1: ok, changes
        -1: error
*/
static int edit_rule_separator(
        struct vrmr_rule *rule_ptr, struct vrmr_regex *reg)
{
    PANEL *my_panels[1];
    WINDOW *edit_win;
    FIELD **fields, *cur = NULL;

    FORM *form;
    int rows, cols, retval = 0, quit = 0;
    size_t n_fields = 0, i = 0, field_num = 0;
    int height, width, startx, starty, max_height, max_width;
    int result = 0;
    struct vrmr_rule_cache tmp_ruledata;

    /* safety */
    vrmr_fatal_if_null(rule_ptr);
    vrmr_fatal_if_null(reg);

    /* clear tmp_ruledata for the initial */
    memset(&tmp_ruledata, 0, sizeof(tmp_ruledata));
    memset(&sep_rule_fields, 0, sizeof(sep_rule_fields));

    /* set to keep first */
    rule_ptr->status = VRMR_ST_CHANGED;

    /* get the dimentions of the screen */
    getmaxyx(stdscr, max_height, max_width);

    /* set windowsize and start position */
    height = 5;
    width = 71;
    startx = (max_width - width) / 2;
    starty = (max_height - height) / 2;

    /* init the action_type */
    vrmr_fatal_if(rule_ptr->action != VRMR_AT_SEPARATOR);

    /* set number of fields */
    n_fields = 1;
    fields = (FIELD **)calloc(n_fields + 1, sizeof(FIELD *));
    vrmr_fatal_alloc("calloc", fields);

    /*
        create the fields
    */

    /* comment */
    sep_rule_fields.comment_fld_ptr =
            (fields[field_num] = new_field_wrap(1, 63, 1, 2, 0, 0));
    if (rule_ptr->opt != NULL && rule_ptr->opt->rule_comment == 1)
        set_field_buffer_wrap(
                sep_rule_fields.comment_fld_ptr, 0, rule_ptr->opt->comment);
    set_field_back(sep_rule_fields.comment_fld_ptr, vccnf.color_win_rev);
    set_field_fore(
            sep_rule_fields.comment_fld_ptr, vccnf.color_win_rev | A_BOLD);
    field_opts_off(sep_rule_fields.comment_fld_ptr, O_AUTOSKIP);
    set_field_status(sep_rule_fields.comment_fld_ptr, FALSE);
    field_num++;

    /* terminate the fields-array */
    fields[n_fields] = NULL;

    vrmr_fatal_if(n_fields != field_num);

    /* create the window, panel, form */
    edit_win = create_newwin(height, width, starty, startx,
            gettext("Enter comment (optional)"), vccnf.color_win);
    vrmr_fatal_if_null(edit_win);
    my_panels[0] = new_panel(edit_win);
    vrmr_fatal_if_null(my_panels[0]);
    keypad(edit_win, TRUE);
    form = new_form(fields);
    vrmr_fatal_if_null(form);
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
    while (quit == 0) {
        cur = current_field(form);

        /*
            now give some help message in the status win
        */
        if (cur == sep_rule_fields.comment_fld_ptr)
            status_print(status_win, gettext("Enter an optional comment."));

        int ch = wgetch(edit_win);
        int not_defined = !(nav_field_simpletext(form, ch));
        if (not_defined == 1) {
            switch (ch) {
                case 27:
                case KEY_F(10):
                case 10: /* enter */

                    form_driver_wrap(
                            form, REQ_NEXT_FIELD); /* this is to make sure
                                                 the field is saved */

                    result = edit_seprule_fields_to_rule(
                            fields, n_fields, rule_ptr, reg);
                    if (result == 1) {
                        quit = 1;
                        retval = 1;
                    } else {
                        /* no change */
                        quit = 1;
                    }
                    break;
            }
        }
    }

    /* Un post form and free the memory */
    unpost_form(form);
    free_form(form);
    for (i = 0; i < n_fields; i++) {
        free_field(fields[i]);
    }
    free(fields);
    del_panel(my_panels[0]);
    destroy_win(edit_win);
    update_panels();
    doupdate();

    status_print(status_win, gettext("Ready."));
    return (retval);
}
