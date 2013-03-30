/***************************************************************************
 *   Copyright (C) 2003-2013 by Victor Julien                              *
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


struct InterfacesSection_
{
    WINDOW          *win;
    PANEL           *panel[1];
    MENU            *menu;
    ITEM            **items;

    unsigned int    list_items;

    /* for the (more) indicators */
    ITEM            *top,
                    *bot;
    PANEL           *panel_top[1];
    PANEL           *panel_bot[1];
    WINDOW          *win_top;
    WINDOW          *win_bot;

    int i_yle;
    int i_xre;

    struct EditInterface_
    {
        WINDOW  *win;
        PANEL   *panel[1];
        FORM    *form;
        FIELD   **fields;
        size_t  n_fields;
    } EditInterface;

    char    comment[512];
    struct vrmr_list  desc_list;

} InterfacesSection;


struct TcpmssIfaceCnf_ {
    struct vrmr_interface *iface_ptr;
    char enabled;
};

static int
VrTcpmssIfaceSetup(const int debuglvl, struct TcpmssIfaceCnf_ *c, struct vrmr_interface *iface_ptr) {
    if (c == NULL || iface_ptr == NULL)
        return(-1);

    c->iface_ptr = iface_ptr;
    c->enabled = iface_ptr->tcpmss_clamp;

    return(0);
}

static int
VrTcpmssIfaceSave(const int debuglvl, void *ctx, char *name, char *value)
{
    struct TcpmssIfaceCnf_ *c = (struct TcpmssIfaceCnf_ *)ctx;
    int result = 0;

    //vrmr_debug(__FUNC__, "%s:%s", name, value);

    if(strcmp(name,"S") == 0) {
        char enabled = 0;

        if (strcmp(value,"X") == 0) {
            enabled = 1;
        }

        if (c->enabled != enabled) {
            result = af->tell(debuglvl, ifac_backend, c->iface_ptr->name, "TCPMSS", enabled ? "Yes" : "No", 1, VRMR_TYPE_INTERFACE);
            if(result < 0)
            {
                vrmr_error(-1, VR_ERR, "%s (in: %s:%d).",
                    STR_SAVING_TO_BACKEND_FAILED,
                    __FUNC__, __LINE__);
                return(-1);
            }

            /* example: "interface 'lan' has been changed: active is now set to 'Yes' (was: 'No')." */
            vrmr_audit("%s '%s' %s: %s %s '%u' (%s: '%u').",
                STR_INTERFACE, c->iface_ptr->name, STR_HAS_BEEN_CHANGED,
                STR_TCPMSS, STR_IS_NOW_SET_TO, enabled ? "Yes" : "No",
                STR_WAS, c->enabled ? "Yes" : "No");
        }
        c->iface_ptr->tcpmss_clamp = enabled;
    }

    return(0);
}

void VrTcpmssIface(const int debuglvl, struct vrmr_interface *iface_ptr) {
    VrWin   *win = NULL;
    VrForm  *form = NULL;
    int     ch = 0, result = 0;
    struct TcpmssIfaceCnf_ config;

    if (VrTcpmssIfaceSetup(debuglvl, &config, iface_ptr) < 0)
    {
        vrmr_error(-1, VR_ERR, "VrTcpmssIfaceSetup failed");
        return;
    }

    /* create the window and put it in the middle of the screen */
    win = VrNewWin(11,51,0,0,vccnf.color_win);
    if(win == NULL)
    {
        vrmr_error(-1, VR_ERR, "VrNewWin failed");
        return;
    }
    VrWinSetTitle(win, gettext("Tcpmss"));

    form = VrNewForm(9, 58, 1, 1, 2, vccnf.color_win, vccnf.color_win_rev | A_BOLD);

    VrFormSetSaveFunc(debuglvl, form, VrTcpmssIfaceSave, &config);

    VrFormAddLabelField(debuglvl,   form, 1, 25, 1, 1,  vccnf.color_win, gettext("Enable TCP MSS clamping"));
    VrFormAddCheckboxField(debuglvl,form,        1, 28, vccnf.color_win, "S", config.enabled);

    VrFormConnectToWin(debuglvl, form, win);

    VrFormPost(debuglvl, form);

    update_panels();
    doupdate();

    /* user input */
    char quit = FALSE;
    while(quit == FALSE)
    {
        VrFormDrawMarker(debuglvl, win, form);

        ch = VrWinGetch(win);

        /* check OK/Cancel buttons */
        result = VrFormCheckOKCancel(debuglvl, form, ch);
        if (result == -1 || result == 1) {
            break;
        }

        if (VrFormDefaultNavigation(debuglvl, form, ch) == FALSE) {
            switch(ch)
            {
                case KEY_DOWN:
                case 10: // enter
                    form_driver(form->f, REQ_NEXT_FIELD);
                    form_driver(form->f, REQ_BEG_LINE);
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
                    print_help(debuglvl, ":[VUURMUUR:INTERFACES:TCPMSS]:");
                    break;
            }
        }
    }

    VrFormUnPost(debuglvl, form);
    VrDelForm(debuglvl, form);
    VrDelWin(win);
    update_panels();
    doupdate();
}

struct ShapeIfaceCnf_ {
    struct vrmr_interface *iface_ptr;
    char in[10], out[10];
    char in_unit[5], out_unit[5];
    char enabled;
};

static int
VrShapeIfaceSetup(const int debuglvl, struct ShapeIfaceCnf_ *c, struct vrmr_interface *iface_ptr) {
    if (c == NULL || iface_ptr == NULL)
        return(-1);

    c->iface_ptr = iface_ptr;

    c->enabled = iface_ptr->shape;

    snprintf(c->in, sizeof(c->in),   "%u", c->iface_ptr->bw_in);
    snprintf(c->out, sizeof(c->out), "%u", c->iface_ptr->bw_out);

    if (strcmp(c->iface_ptr->bw_in_unit, "") == 0)
        strlcpy(c->in_unit, "kbit", sizeof(c->in_unit));
    else
        snprintf(c->in_unit, sizeof(c->in_unit), "%s", c->iface_ptr->bw_in_unit);

    if (strcmp(c->iface_ptr->bw_out_unit, "") == 0)
        strlcpy(c->out_unit, "kbit", sizeof(c->out_unit));
    else
        snprintf(c->out_unit, sizeof(c->out_unit), "%s", c->iface_ptr->bw_out_unit);

    return(0);
}

static int
VrShapeIfaceSave(const int debuglvl, void *ctx, char *name, char *value)
{
    struct ShapeIfaceCnf_ *c = (struct ShapeIfaceCnf_ *)ctx;
    u_int32_t oldrate = 0;
    int result = 0;

    //vrmr_debug(__FUNC__, "%s:%s", name, value);

    if (strcmp(name,"in") == 0) {
        oldrate = c->iface_ptr->bw_in;
        c->iface_ptr->bw_in = atoi(value);

        if (oldrate != c->iface_ptr->bw_in) {
            result = af->tell(debuglvl, ifac_backend, c->iface_ptr->name, "BW_IN", value, 1, VRMR_TYPE_INTERFACE);
            if(result < 0)
            {
                vrmr_error(-1, VR_ERR, "%s (in: %s:%d).",
                    STR_SAVING_TO_BACKEND_FAILED,
                    __FUNC__, __LINE__);
                return(-1);
            }

            /* example: "interface 'lan' has been changed: active is now set to 'Yes' (was: 'No')." */
            vrmr_audit("%s '%s' %s: %s %s '%u' (%s: '%u').",
                STR_INTERFACE, c->iface_ptr->name, STR_HAS_BEEN_CHANGED,
                STR_IN, STR_IS_NOW_SET_TO, c->iface_ptr->bw_in,
                STR_WAS, oldrate);
        }
    } else if (strcmp(name,"out") == 0) {
        oldrate = c->iface_ptr->bw_out;
        c->iface_ptr->bw_out = atoi(value);

        if (oldrate != c->iface_ptr->bw_out) {
            result = af->tell(debuglvl, ifac_backend, c->iface_ptr->name, "BW_OUT", value, 1, VRMR_TYPE_INTERFACE);
            if(result < 0)
            {
                vrmr_error(-1, VR_ERR, "%s (in: %s:%d).",
                    STR_SAVING_TO_BACKEND_FAILED,
                    __FUNC__, __LINE__);
                return(-1);
            }

            /* example: "interface 'lan' has been changed: active is now set to 'Yes' (was: 'No')." */
            vrmr_audit("%s '%s' %s: %s %s '%u' (%s: '%u').",
                STR_INTERFACE, c->iface_ptr->name, STR_HAS_BEEN_CHANGED,
                STR_OUT, STR_IS_NOW_SET_TO, c->iface_ptr->bw_out,
                STR_WAS, oldrate);
        }
    } else if(strcmp(name,"unit1") == 0) {
        if (strcmp(value, c->iface_ptr->bw_in_unit) != 0) {
            result = af->tell(debuglvl, ifac_backend, c->iface_ptr->name, "BW_IN_UNIT", value, 1, VRMR_TYPE_INTERFACE);
            if(result < 0)
            {
                vrmr_error(-1, VR_ERR, "%s (in: %s:%d).",
                    STR_SAVING_TO_BACKEND_FAILED,
                    __FUNC__, __LINE__);
                return(-1);
            }

            /* example: "interface 'lan' has been changed: active is now set to 'Yes' (was: 'No')." */
            vrmr_audit("%s '%s' %s: %s %s '%u' (%s: '%u').",
                STR_INTERFACE, c->iface_ptr->name, STR_HAS_BEEN_CHANGED,
                STR_IN_UNIT, STR_IS_NOW_SET_TO, value,
                STR_WAS, c->iface_ptr->bw_in_unit);
        }
        strlcpy(c->iface_ptr->bw_in_unit, value, sizeof(c->iface_ptr->bw_in_unit));
    } else if(strcmp(name,"unit2") == 0) {
        if (strcmp(value, c->iface_ptr->bw_out_unit) != 0) {
            result = af->tell(debuglvl, ifac_backend, c->iface_ptr->name, "BW_OUT_UNIT", value, 1, VRMR_TYPE_INTERFACE);
            if(result < 0)
            {
                vrmr_error(-1, VR_ERR, "%s (in: %s:%d).",
                    STR_SAVING_TO_BACKEND_FAILED,
                    __FUNC__, __LINE__);
                return(-1);
            }

            /* example: "interface 'lan' has been changed: active is now set to 'Yes' (was: 'No')." */
            vrmr_audit("%s '%s' %s: %s %s '%u' (%s: '%u').",
                STR_INTERFACE, c->iface_ptr->name, STR_HAS_BEEN_CHANGED,
                STR_OUT_UNIT, STR_IS_NOW_SET_TO, value,
                STR_WAS, c->iface_ptr->bw_out_unit);
        }
        strlcpy(c->iface_ptr->bw_out_unit, value, sizeof(c->iface_ptr->bw_out_unit));
    } else if(strcmp(name,"S") == 0) {
        char enabled = 0;

        if (strcmp(value,"X") == 0) {
            enabled = 1;
        }

        if (c->enabled != enabled) {
            result = af->tell(debuglvl, ifac_backend, c->iface_ptr->name, "SHAPE", enabled ? "Yes" : "No", 1, VRMR_TYPE_INTERFACE);
            if(result < 0)
            {
                vrmr_error(-1, VR_ERR, "%s (in: %s:%d).",
                    STR_SAVING_TO_BACKEND_FAILED,
                    __FUNC__, __LINE__);
                return(-1);
            }

            /* example: "interface 'lan' has been changed: active is now set to 'Yes' (was: 'No')." */
            vrmr_audit("%s '%s' %s: %s %s '%u' (%s: '%u').",
                STR_INTERFACE, c->iface_ptr->name, STR_HAS_BEEN_CHANGED,
                STR_SHAPE, STR_IS_NOW_SET_TO, enabled ? "Yes" : "No",
                STR_WAS, c->enabled ? "Yes" : "No");
        }
        c->iface_ptr->shape = enabled;
    }

    return(0);
}

void VrShapeIface(const int debuglvl, struct vrmr_interface *iface_ptr) {
    VrWin   *win = NULL;
    VrForm  *form = NULL;
    int     ch = 0, result = 0;
    struct ShapeIfaceCnf_ config;

    if (VrShapeIfaceSetup(debuglvl, &config, iface_ptr) < 0)
    {
        vrmr_error(-1, VR_ERR, "VrShapeIfaceSetup failed");
        return;
    }

    /* create the window and put it in the middle of the screen */
    win = VrNewWin(11,51,0,0,vccnf.color_win);
    if(win == NULL)
    {
        vrmr_error(-1, VR_ERR, "VrNewWin failed");
        return;
    }
    VrWinSetTitle(win, gettext("Shaping"));

    form = VrNewForm(9, 58, 1, 1, 9, vccnf.color_win, vccnf.color_win_rev | A_BOLD);

    VrFormSetSaveFunc(debuglvl, form, VrShapeIfaceSave, &config);

    VrFormAddLabelField(debuglvl,   form, 1, 25, 1, 1,  vccnf.color_win, gettext("Enable shaping"));
    VrFormAddCheckboxField(debuglvl,form,        1, 28, vccnf.color_win, "S", config.enabled);
    VrFormAddLabelField(debuglvl,   form, 1, 25, 3, 1,  vccnf.color_win, gettext("Incoming bandwidth"));
    VrFormAddTextField(debuglvl,    form, 1, 10, 3, 28, vccnf.color_win_rev | A_BOLD, "in", config.in);
    VrFormAddTextField(debuglvl,    form, 1,  5, 3, 41, vccnf.color_win_rev | A_BOLD, "unit1", config.in_unit);
    VrFormAddLabelField(debuglvl,   form, 1, 25, 5, 1,  vccnf.color_win, gettext("Outgoing bandwidth"));
    VrFormAddTextField(debuglvl,    form, 1, 10, 5, 28, vccnf.color_win_rev | A_BOLD, "out", config.out);
    VrFormAddTextField(debuglvl,    form, 1,  5, 5, 41, vccnf.color_win_rev | A_BOLD, "unit2", config.out_unit);

    VrFormConnectToWin(debuglvl, form, win);

    VrFormPost(debuglvl, form);

    update_panels();
    doupdate();

    /* user input */
    char quit = FALSE;
    while(quit == FALSE)
    {
        VrFormDrawMarker(debuglvl, win, form);

        ch = VrWinGetch(win);

        /* check OK/Cancel buttons */
        result = VrFormCheckOKCancel(debuglvl, form, ch);
        if (result == -1 || result == 1) {
            break;
        }

        char *b = field_buffer(form->cur, 1);
        if (ch == 32 &&
            (strcmp(b,"unit1") == 0 || strcmp(b,"unit2") == 0))
        {
            int h,w,i;
            field_info(form->cur, &i,&i,&h,&w,&i,&i);

            char *u = VrShapeUnitMenu(debuglvl, field_buffer(form->cur, 0), h+2+win->y, w-1+win->x, 0);
            vrmr_debug(__FUNC__, "u %s", u);
            if (u) {
                set_field_buffer_wrap(debuglvl, form->cur, 0, u);
                free(u);
            }
        } else if (VrFormDefaultNavigation(debuglvl, form, ch) == FALSE) {
            switch(ch)
            {
                case KEY_DOWN:
                case 10: // enter
                    form_driver(form->f, REQ_NEXT_FIELD);
                    form_driver(form->f, REQ_BEG_LINE);
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
                    print_help(debuglvl, ":[VUURMUUR:INTERFACES:SHAPE]:");
                    break;
            }
        }
    }

    VrFormUnPost(debuglvl, form);
    VrDelForm(debuglvl, form);
    VrDelWin(win);
    update_panels();
    doupdate();
}

struct
{
    FIELD   *activefld,
            *activelabelfld,

            *ipaddressfld,
            *ipaddresslabelfld,

            *ip6addressfld,
            *ip6addresslabelfld,

            *dynamicfld,
            *dynamiclabelfld,
            *dynamicbracketsfld,

            *devicefld,
            *devicelabelfld,

            *devicevirtualfld,
            *devicevirtuallabelfld,
            *devicevirtualbracketsfld,

            *interfaceupfld,
            *interfaceuplabelfld,

            *commentfld,
            *commentlabelfld;

    FIELD   *labelfld,

            *srcrtpktsfld,
            *srcrtpktslabelfld,
            *srcrtpktsbracketsfld,

            *icmpredirectfld,
            *icmpredirectlabelfld,
            *icmpredirectbracketsfld,

            *sendredirectfld,
            *sendredirectlabelfld,
            *sendredirectbracketsfld,

            *rpfilterfld,
            *rpfilterlabelfld,
            *rpfilterbracketsfld,

            *logmartiansfld,
            *logmartianslabelfld,
            *logmartiansbracketsfld;
} IfSec;


int
protectrule_loaded(const int debuglvl, struct vrmr_list *rules_list, char *action, char *danger, char *source)
{
    struct vrmr_rule    *rule_ptr = NULL;
    struct vrmr_list_node         *d_node = NULL;
    int                 act = 0;

    if(!rules_list || !danger || !action)
    {
        return(0);
    }

    if(rules_list->len == 0)
        return(0);

    act = vrmr_rules_actiontoi(action);

    for(d_node = rules_list->top; d_node; d_node = d_node->next)
    {
        if(!(rule_ptr = d_node->data))
        {
            return(0);
        }

        if(act == rule_ptr->action)
        {
            /* accept rule */
            if(act == VRMR_AT_ACCEPT)
            {
                if(strcasecmp(danger,rule_ptr->service) == 0)
                    return(1);
            }
            /* protect rule */
            else if(strcasecmp(danger, rule_ptr->danger) == 0)
            {
                if(!source)
                {
                    return(1);
                }
                else
                {
                    if(strcmp(source, rule_ptr->source) == 0)
                    {
                        return(1);
                    }
                }
            }
        }
    }

    return(0);
}


static int
edit_interface_init(const int debuglvl, char *name, int height, int width, int starty, int startx, struct vrmr_interface *iface_ptr)
{
    int     retval=0,   // return value
            rows,
            cols,
            comment_y=0,    // number of lines of the commentfield
            comment_x=0;    // number of colums of the commentfield
    size_t  field_num = 0;
    size_t  i = 0;

    InterfacesSection.EditInterface.n_fields = 34;
    InterfacesSection.EditInterface.fields = (FIELD **)calloc(InterfacesSection.EditInterface.n_fields + 1, sizeof(FIELD *));

    /*
        create the fields
    */

    /* active */
    IfSec.activelabelfld = (InterfacesSection.EditInterface.fields[field_num] = new_field(1, 16, 2, 0, 0, 0));
    field_num++;
    set_field_buffer_wrap(debuglvl, IfSec.activelabelfld, 0, STR_CACTIVE);
    field_opts_off(IfSec.activelabelfld, O_AUTOSKIP | O_ACTIVE);

    IfSec.activefld = (InterfacesSection.EditInterface.fields[field_num] = new_field(1, 3, 3, 1, 0, 0));
    field_num++;
    set_field_buffer_wrap(debuglvl, IfSec.activefld, 0, iface_ptr->active ? STR_YES : STR_NO);


    /* device */
    IfSec.devicelabelfld = (InterfacesSection.EditInterface.fields[field_num] = new_field(1, 16, 5, 0, 0, 0));
    field_num++;
    set_field_buffer_wrap(debuglvl, IfSec.devicelabelfld, 0, STR_CDEVICE);
    field_opts_off(IfSec.devicelabelfld, O_AUTOSKIP | O_ACTIVE);

    IfSec.devicefld = (InterfacesSection.EditInterface.fields[field_num] = new_field(1, 12, 6, 1, 0, 0));
    field_num++;
    set_field_buffer_wrap(debuglvl, IfSec.devicefld, 0, iface_ptr->device);


    /* ipaddress */
    IfSec.ipaddresslabelfld = (InterfacesSection.EditInterface.fields[field_num] = new_field(1, 16, 7, 0, 0, 0));
    field_num++;
    set_field_buffer_wrap(debuglvl, IfSec.ipaddresslabelfld, 0, STR_IPADDRESS);
    field_opts_off(IfSec.ipaddresslabelfld, O_AUTOSKIP | O_ACTIVE);

    IfSec.ipaddressfld = (InterfacesSection.EditInterface.fields[field_num] = new_field(1, 16, 8, 1, 0, 0));
    field_num++;
    set_field_type(IfSec.ipaddressfld, TYPE_IPV4);
    set_field_buffer_wrap(debuglvl, IfSec.ipaddressfld, 0, iface_ptr->ipv4.ipaddress);

    /* if ipaddress is dynamic, we don't want to edit the ipaddress */
    if(iface_ptr->dynamic)
        field_opts_off(IfSec.ipaddressfld, O_AUTOSKIP | O_ACTIVE);

    /* ip6address */
    IfSec.ip6addresslabelfld = (InterfacesSection.EditInterface.fields[field_num++] = new_field(1, 16, 9, 0, 0, 0));
#ifdef IPV6_ENABLED
    set_field_buffer_wrap(debuglvl, IfSec.ip6addresslabelfld, 0, STR_IP6ADDRESS);
#endif
    field_opts_off(IfSec.ip6addresslabelfld, O_AUTOSKIP | O_ACTIVE);

    IfSec.ip6addressfld = (InterfacesSection.EditInterface.fields[field_num++] = new_field(1, VRMR_MAX_IPV6_ADDR_LEN, 10, 1, 0, 0));
    //set_field_type(IfSec.ip6addressfld, TYPE_IPV6);
#ifdef IPV6_ENABLED
    set_field_buffer_wrap(debuglvl, IfSec.ip6addressfld, 0, iface_ptr->ipv6.ip6);
#endif


    /* dynamic ip toggle */
    IfSec.dynamicbracketsfld = (InterfacesSection.EditInterface.fields[field_num] = new_field(1, 3, 6, 20, 0, 0));
    field_num++;
    set_field_buffer_wrap(debuglvl, IfSec.dynamicbracketsfld, 0, "[ ]");
    field_opts_off(IfSec.dynamicbracketsfld, O_AUTOSKIP | O_ACTIVE);

    IfSec.dynamiclabelfld = (InterfacesSection.EditInterface.fields[field_num] = new_field(1, 18, 5, 19, 0, 0));
    field_num++;
    set_field_buffer_wrap(debuglvl, IfSec.dynamiclabelfld, 0, STR_CDYNAMICIP);
    field_opts_off(IfSec.dynamiclabelfld, O_AUTOSKIP | O_ACTIVE);

    IfSec.dynamicfld = (InterfacesSection.EditInterface.fields[field_num] = new_field(1, 1, 6, 21, 0, 0));
    field_num++;
    set_field_buffer_wrap(debuglvl, IfSec.dynamicfld, 0, iface_ptr->dynamic ? "X" : " ");


    /* is the device virtual */
    IfSec.devicevirtualbracketsfld = (InterfacesSection.EditInterface.fields[field_num] = new_field(1, 3, 8, 20, 0, 0));
    field_num++;
    set_field_buffer_wrap(debuglvl, IfSec.devicevirtualbracketsfld, 0, "[ ]");
    field_opts_off(IfSec.devicevirtualbracketsfld, O_AUTOSKIP | O_ACTIVE);

    IfSec.devicevirtuallabelfld = (InterfacesSection.EditInterface.fields[field_num] = new_field(1, 18, 7, 19, 0, 0));
    field_num++;
    set_field_buffer_wrap(debuglvl, IfSec.devicevirtuallabelfld, 0, STR_CVIRTUAL);
    field_opts_off(IfSec.devicevirtuallabelfld, O_AUTOSKIP | O_ACTIVE);

    IfSec.devicevirtualfld = (InterfacesSection.EditInterface.fields[field_num] = new_field(1, 1, 8, 21, 0, 0));
    field_num++;
    set_field_buffer_wrap(debuglvl, IfSec.devicevirtualfld, 0, iface_ptr->device_virtual ? "X" : " ");


    /* protect label */
    IfSec.labelfld = (InterfacesSection.EditInterface.fields[field_num] = new_field(1, 16, 2, 38, 0, 0));
    field_num++;
    set_field_buffer_wrap(debuglvl, IfSec.labelfld, 0, gettext("Protection"));
    field_opts_off(IfSec.labelfld, O_AUTOSKIP | O_ACTIVE);

    /* source routed packets */
    IfSec.srcrtpktsbracketsfld = (InterfacesSection.EditInterface.fields[field_num] = new_field(1, 3, 4, 54, 0, 0));
    field_num++;
    set_field_buffer_wrap(debuglvl, IfSec.srcrtpktsbracketsfld, 0, "[ ]");
    field_opts_off(IfSec.srcrtpktsbracketsfld, O_AUTOSKIP | O_ACTIVE);

    IfSec.srcrtpktslabelfld = (InterfacesSection.EditInterface.fields[field_num] = new_field(1, 14, 4, 38, 0, 0));
    field_num++;
    set_field_buffer_wrap(debuglvl, IfSec.srcrtpktslabelfld, 0, "Src-rt-pkts");
    field_opts_off(IfSec.srcrtpktslabelfld, O_AUTOSKIP | O_ACTIVE);

    IfSec.srcrtpktsfld = (InterfacesSection.EditInterface.fields[field_num] = new_field(1, 1, 4, 55, 0, 0));
    field_num++;
    set_field_buffer_wrap(debuglvl, IfSec.srcrtpktsfld, 0, protectrule_loaded(debuglvl, &iface_ptr->ProtectList, "protect", "source-routed-packets", NULL) ? "X" : " ");

    /* icmp redirects */
    IfSec.icmpredirectbracketsfld = (InterfacesSection.EditInterface.fields[field_num] = new_field(1, 3, 5, 54, 0, 0));
    field_num++;
    set_field_buffer_wrap(debuglvl, IfSec.icmpredirectbracketsfld, 0, "[ ]");
    field_opts_off(IfSec.icmpredirectbracketsfld, O_AUTOSKIP | O_ACTIVE);

    IfSec.icmpredirectlabelfld = (InterfacesSection.EditInterface.fields[field_num] = new_field(1, 14, 5, 38, 0, 0));
    field_num++;
    set_field_buffer_wrap(debuglvl, IfSec.icmpredirectlabelfld, 0, "Icmp-redirect");
    field_opts_off(IfSec.icmpredirectlabelfld, O_AUTOSKIP | O_ACTIVE);

    IfSec.icmpredirectfld = (InterfacesSection.EditInterface.fields[field_num] = new_field(1, 1, 5, 55, 0, 0));
    field_num++;
    set_field_buffer_wrap(debuglvl, IfSec.icmpredirectfld, 0, protectrule_loaded(debuglvl, &iface_ptr->ProtectList, "protect", "icmp-redirect", NULL) ? "X" : " ");

    /* send redirect */
    IfSec.sendredirectbracketsfld = (InterfacesSection.EditInterface.fields[field_num] = new_field(1, 3, 6, 54, 0, 0));
    field_num++;
    set_field_buffer_wrap(debuglvl, IfSec.sendredirectbracketsfld, 0, "[ ]");
    field_opts_off(IfSec.sendredirectbracketsfld, O_AUTOSKIP | O_ACTIVE);

    IfSec.sendredirectlabelfld = (InterfacesSection.EditInterface.fields[field_num] = new_field(1, 14, 6, 38, 0, 0));
    field_num++;
    set_field_buffer_wrap(debuglvl, IfSec.sendredirectlabelfld, 0, "Send-redirect");
    field_opts_off(IfSec.sendredirectlabelfld, O_AUTOSKIP | O_ACTIVE);

    IfSec.sendredirectfld = (InterfacesSection.EditInterface.fields[field_num] = new_field(1, 1, 6, 55, 0, 0));
    field_num++;
    set_field_buffer_wrap(debuglvl, IfSec.sendredirectfld, 0, protectrule_loaded(debuglvl, &iface_ptr->ProtectList, "protect", "send-redirect", NULL) ? "X" : " ");

    /* rp filter */
    IfSec.rpfilterbracketsfld = (InterfacesSection.EditInterface.fields[field_num] = new_field(1, 3, 7, 54, 0, 0));
    field_num++;
    set_field_buffer_wrap(debuglvl, IfSec.rpfilterbracketsfld, 0, "[ ]");
    field_opts_off(IfSec.rpfilterbracketsfld, O_AUTOSKIP | O_ACTIVE);

    IfSec.rpfilterlabelfld = (InterfacesSection.EditInterface.fields[field_num] = new_field(1, 14, 7, 38, 0, 0));
    field_num++;
    set_field_buffer_wrap(debuglvl, IfSec.rpfilterlabelfld, 0, "Rp-filter");
    field_opts_off(IfSec.rpfilterlabelfld, O_AUTOSKIP | O_ACTIVE);

    IfSec.rpfilterfld = (InterfacesSection.EditInterface.fields[field_num] = new_field(1, 1, 7, 55, 0, 0));
    field_num++;
    set_field_buffer_wrap(debuglvl, IfSec.rpfilterfld, 0, protectrule_loaded(debuglvl, &iface_ptr->ProtectList, "protect", "rp-filter", NULL) ? "X" : " ");

    /* log martians */
    IfSec.logmartiansbracketsfld = (InterfacesSection.EditInterface.fields[field_num] = new_field(1, 3, 8, 54, 0, 0));
    field_num++;
    set_field_buffer_wrap(debuglvl, IfSec.logmartiansbracketsfld, 0, "[ ]");
    field_opts_off(IfSec.logmartiansbracketsfld, O_AUTOSKIP | O_ACTIVE);

    IfSec.logmartianslabelfld = (InterfacesSection.EditInterface.fields[field_num] = new_field(1, 14, 8, 38, 0, 0));
    field_num++;
    set_field_buffer_wrap(debuglvl, IfSec.logmartianslabelfld, 0, "Log martians");
    field_opts_off(IfSec.logmartianslabelfld, O_AUTOSKIP | O_ACTIVE);

    IfSec.logmartiansfld = (InterfacesSection.EditInterface.fields[field_num] = new_field(1, 1, 8, 55, 0, 0));
    field_num++;
    set_field_buffer_wrap(debuglvl, IfSec.logmartiansfld, 0, protectrule_loaded(debuglvl, &iface_ptr->ProtectList, "protect", "log-martians", NULL) ? "X" : " ");


    /* comment */
    IfSec.commentlabelfld = (InterfacesSection.EditInterface.fields[field_num] = new_field(1, 16, 12, 0, 0, 0));
    field_num++;
    set_field_buffer_wrap(debuglvl, IfSec.commentlabelfld, 0, gettext("Comment"));
    field_opts_off(IfSec.commentlabelfld, O_AUTOSKIP | O_ACTIVE);

    comment_y = 5;
    comment_x = 48;

    IfSec.commentfld = (InterfacesSection.EditInterface.fields[field_num] = new_field(comment_y, comment_x, 13, 1, 0, 0));
    field_num++;
    if(af->ask(debuglvl, ifac_backend, iface_ptr->name, "COMMENT", InterfacesSection.comment, sizeof(InterfacesSection.comment), VRMR_TYPE_INTERFACE, 0) < 0)
        vrmr_error(-1, VR_ERR, gettext("error while loading the comment."));

    set_field_buffer_wrap(debuglvl, IfSec.commentfld, 0, InterfacesSection.comment);

    /* now check if the interface is currently up */
    if(vrmr_interfaces_iface_up(debuglvl, iface_ptr) == 1)
        iface_ptr->up = TRUE;
    else
        iface_ptr->up = FALSE;

    /* up? */
    IfSec.interfaceuplabelfld = (InterfacesSection.EditInterface.fields[field_num] = new_field(1, 18, 2, 19, 0, 0));
    field_num++;
    /* TRANSLATORS: max 18 chars */
    set_field_buffer_wrap(debuglvl, IfSec.interfaceuplabelfld, 0, gettext("Is interface up?"));
    field_opts_off(IfSec.interfaceuplabelfld, O_ACTIVE);

    IfSec.interfaceupfld = (InterfacesSection.EditInterface.fields[field_num] = new_field(1, 6, 3, 20, 0, 0));
    field_num++;
    set_field_buffer_wrap(debuglvl, IfSec.interfaceupfld, 0, iface_ptr->up ? STR_YES : STR_NO);
    field_opts_off(IfSec.interfaceupfld, O_ACTIVE);

    /* terminate the fields */
    InterfacesSection.EditInterface.fields[InterfacesSection.EditInterface.n_fields] = NULL;

    if(InterfacesSection.EditInterface.n_fields != field_num)
        vrmr_error(-1, VR_INTERR, "InterfacesSection.EditInterface.n_fields != field_num.");

    /* create the window & panel */
    InterfacesSection.EditInterface.win = create_newwin(height, width, starty, startx, gettext("Edit Interface"), vccnf.color_win);
    InterfacesSection.EditInterface.panel[0] = new_panel(InterfacesSection.EditInterface.win);
    keypad(InterfacesSection.EditInterface.win, TRUE);

    for(i = 0; i < InterfacesSection.EditInterface.n_fields; i++)
    {
        // set field options
        set_field_back(InterfacesSection.EditInterface.fields[i], vccnf.color_win_rev);

        field_opts_off(InterfacesSection.EditInterface.fields[i], O_AUTOSKIP);
        // set status to false
        set_field_status(InterfacesSection.EditInterface.fields[i], FALSE);
    }

    /* disable ipv6 if not supported */
#ifndef IPV6_ENABLED
    set_field_back(IfSec.ip6addresslabelfld, vccnf.color_win | A_BOLD);
    field_opts_on(IfSec.ip6addresslabelfld, O_AUTOSKIP);
    field_opts_off(IfSec.ip6addresslabelfld, O_ACTIVE);

    set_field_back(IfSec.ip6addressfld, vccnf.color_win | A_BOLD);
    field_opts_on(IfSec.ip6addressfld, O_AUTOSKIP);
    field_opts_off(IfSec.ip6addressfld, O_ACTIVE);
#endif

    /* labels are blue-white */
    set_field_back(IfSec.activelabelfld, vccnf.color_win);
    set_field_back(IfSec.ipaddresslabelfld, vccnf.color_win);
    set_field_back(IfSec.ip6addresslabelfld, vccnf.color_win);
    set_field_back(IfSec.devicelabelfld, vccnf.color_win);
    set_field_back(IfSec.commentlabelfld, vccnf.color_win);
    set_field_back(IfSec.interfaceuplabelfld, vccnf.color_win);

    set_field_back(IfSec.dynamicfld, vccnf.color_win);
    set_field_back(IfSec.dynamiclabelfld, vccnf.color_win);
    set_field_back(IfSec.dynamicbracketsfld, vccnf.color_win);

    set_field_back(IfSec.devicevirtualfld, vccnf.color_win);
    set_field_back(IfSec.devicevirtuallabelfld, vccnf.color_win);
    set_field_back(IfSec.devicevirtualbracketsfld, vccnf.color_win);


    /* the toggles */
    set_field_back(IfSec.labelfld, vccnf.color_win);

    set_field_back(IfSec.srcrtpktsfld, vccnf.color_win);
    set_field_back(IfSec.srcrtpktslabelfld, vccnf.color_win);
    set_field_back(IfSec.srcrtpktsbracketsfld, vccnf.color_win);

    set_field_back(IfSec.icmpredirectfld, vccnf.color_win);
    set_field_back(IfSec.icmpredirectlabelfld, vccnf.color_win);
    set_field_back(IfSec.icmpredirectbracketsfld, vccnf.color_win);

    set_field_back(IfSec.sendredirectfld, vccnf.color_win);
    set_field_back(IfSec.sendredirectlabelfld, vccnf.color_win);
    set_field_back(IfSec.sendredirectbracketsfld, vccnf.color_win);

    set_field_back(IfSec.rpfilterfld, vccnf.color_win);
    set_field_back(IfSec.rpfilterlabelfld, vccnf.color_win);
    set_field_back(IfSec.rpfilterbracketsfld, vccnf.color_win);

    set_field_back(IfSec.logmartiansfld, vccnf.color_win);
    set_field_back(IfSec.logmartianslabelfld, vccnf.color_win);
    set_field_back(IfSec.logmartiansbracketsfld, vccnf.color_win);

    set_field_back(IfSec.interfaceupfld, vccnf.color_win);

    // Create the form and post it
    InterfacesSection.EditInterface.form = new_form(InterfacesSection.EditInterface.fields);
    scale_form(InterfacesSection.EditInterface.form, &rows, &cols);
    set_form_win(InterfacesSection.EditInterface.form, InterfacesSection.EditInterface.win);
    set_form_sub(InterfacesSection.EditInterface.form, derwin(InterfacesSection.EditInterface.win, rows, cols, 1, 2));

    post_form(InterfacesSection.EditInterface.form);

    mvwprintw(InterfacesSection.EditInterface.win, 1, 2,  "%s: %s", gettext("Name"), iface_ptr->name);

    wrefresh(InterfacesSection.EditInterface.win);

    return(retval);
}


static int
edit_interface_destroy(void)
{
    int     retval = 0;
    size_t  i = 0;

    // Un post form and free the memory
    unpost_form(InterfacesSection.EditInterface.form);
    free_form(InterfacesSection.EditInterface.form);

    for(i=0;i<InterfacesSection.EditInterface.n_fields;i++)
    {
        free_field(InterfacesSection.EditInterface.fields[i]);
    }
    free(InterfacesSection.EditInterface.fields);

    del_panel(InterfacesSection.EditInterface.panel[0]);
    destroy_win(InterfacesSection.EditInterface.win);

    update_panels();
    doupdate();

    strlcpy(InterfacesSection.comment, "", sizeof(InterfacesSection.comment));
    return(retval);
}


static int
edit_interface_save_rules(const int debuglvl, struct vrmr_interface *iface_ptr)
{
    struct vrmr_rule    *rule_ptr = NULL;

    /* safety */
    if(iface_ptr == NULL)
    {
        vrmr_error(-1, VR_INTERR, "parameter problem (in: %s:%d).",
                                __FUNC__, __LINE__);
        return(-1);
    }

    vrmr_list_cleanup(debuglvl, &iface_ptr->ProtectList);

    if(field_buffer(IfSec.srcrtpktsfld, 0)[0] == 'X')
    {
        if(!(rule_ptr = rules_create_protect_rule(debuglvl, "protect", iface_ptr->name, "source-routed-packets", NULL)))
        {
            vrmr_error(-1, VR_INTERR, "rules_create_protect_rule() failed (in: %s:%d).",
                                __FUNC__, __LINE__);
            return(-1);
        }
        if(vrmr_list_append(debuglvl, &iface_ptr->ProtectList, rule_ptr)  == NULL)
        {
            vrmr_error(-1, VR_INTERR, "vrmr_list_append() failed (in: %s:%d).",
                                __FUNC__, __LINE__);
            return(-1);
        }
    }

    if(field_buffer(IfSec.icmpredirectfld, 0)[0] == 'X')
    {
        if(!(rule_ptr = rules_create_protect_rule(debuglvl, "protect", iface_ptr->name, "icmp-redirect", NULL)))
        {
            vrmr_error(-1, VR_INTERR, "rules_create_protect_rule() failed (in: %s:%d).",
                                __FUNC__, __LINE__);
            return(-1);
        }
        if(vrmr_list_append(debuglvl, &iface_ptr->ProtectList, rule_ptr)  == NULL)
        {
            vrmr_error(-1, VR_INTERR, "vrmr_list_append() failed (in: %s:%d).",
                                __FUNC__, __LINE__);
            return(-1);
        }
    }

    if(field_buffer(IfSec.sendredirectfld, 0)[0] == 'X')
    {
        if(!(rule_ptr = rules_create_protect_rule(debuglvl, "protect", iface_ptr->name, "send-redirect", NULL)))
        {
            vrmr_error(-1, VR_INTERR, "rules_create_protect_rule() failed (in: %s:%d).",
                                __FUNC__, __LINE__);
            return(-1);
        }
        if(vrmr_list_append(debuglvl, &iface_ptr->ProtectList, rule_ptr)  == NULL)
        {
            vrmr_error(-1, VR_INTERR, "vrmr_list_append() failed (in: %s:%d).",
                                __FUNC__, __LINE__);
            return(-1);
        }
    }

    if(field_buffer(IfSec.rpfilterfld, 0)[0] == 'X')
    {
        if(!(rule_ptr = rules_create_protect_rule(debuglvl, "protect", iface_ptr->name, "rp-filter", NULL)))
        {
            vrmr_error(-1, VR_INTERR, "rules_create_protect_rule() failed (in: %s:%d).",
                                __FUNC__, __LINE__);
            return(-1);
        }
        if(vrmr_list_append(debuglvl, &iface_ptr->ProtectList, rule_ptr)  == NULL)
        {
            vrmr_error(-1, VR_INTERR, "vrmr_list_append() failed (in: %s:%d).",
                                __FUNC__, __LINE__);
            return(-1);
        }
    }

    if(field_buffer(IfSec.logmartiansfld, 0)[0] == 'X')
    {
        if(!(rule_ptr = rules_create_protect_rule(debuglvl, "protect", iface_ptr->name, "log-martians", NULL)))
        {
            vrmr_error(-1, VR_INTERR, "rules_create_protect_rule() failed (in: %s:%d).",
                                __FUNC__, __LINE__);
            return(-1);
        }
        if(vrmr_list_append(debuglvl, &iface_ptr->ProtectList, rule_ptr)  == NULL)
        {
            vrmr_error(-1, VR_INTERR, "vrmr_list_append() failed (in: %s:%d).",
                                __FUNC__, __LINE__);
            return(-1);
        }
    }

    /* now let try to write this to the backend */
    if(vrmr_interfaces_save_rules(debuglvl, iface_ptr) < 0)
    {
        vrmr_error(-1, VR_ERR, "%s (in: %s:%d).",
                STR_SAVING_TO_BACKEND_FAILED, __FUNC__, __LINE__);
        return(-1);
    }

    return(0);
}


/*
     1: ok, changes
     0: ok, no changes
    -1: error
*/
static int
edit_interface_save(const int debuglvl, struct vrmr_interface *iface_ptr)
{
    int                     retval = 0,
                            result = 0,
                            status = 0;
    size_t                  i = 0;
    struct vrmr_interface   *tempiface_ptr = NULL;
    char                    rules_changed = FALSE;
    struct vrmr_rule        *rule_ptr = NULL;
    struct vrmr_list_node             *d_node = NULL;

    /* safety */
    if(iface_ptr == NULL)
    {
        vrmr_error(-1, VR_INTERR, "parameter problem (in: %s:%d).",
                                __FUNC__, __LINE__);
        return(-1);
    }

    /* get a temp interface */
    tempiface_ptr = vrmr_interface_malloc(debuglvl);
    if(!tempiface_ptr)
        return(-1);

    /* copy the interface to the temp one */
    *tempiface_ptr = *iface_ptr;

    /* check for changed fields */
    for(i=0; i < InterfacesSection.EditInterface.n_fields; i++)
    {
        if(field_status(InterfacesSection.EditInterface.fields[i]) == TRUE)
        {
            /* changes! */
            retval = 1;

            /* active */
            if(InterfacesSection.EditInterface.fields[i] == IfSec.activefld)
            {
                status = VRMR_ST_CHANGED;

                if(strncasecmp(field_buffer(InterfacesSection.EditInterface.fields[i], 0), STR_YES, StrLen(STR_YES)) == 0)
                {
                    tempiface_ptr->active = 1;
                }
                else if(strncasecmp(field_buffer(InterfacesSection.EditInterface.fields[i], 0), STR_NO, StrLen(STR_NO)) == 0)
                {
                    tempiface_ptr->active = 0;
                }
                else
                {
                    tempiface_ptr->active = -1;
                }

                result = af->tell(debuglvl, ifac_backend, tempiface_ptr->name, "ACTIVE", tempiface_ptr->active ? "Yes" : "No", 1, VRMR_TYPE_INTERFACE);
                if(result < 0)
                {
                    vrmr_error(-1, VR_ERR, "%s (in: %s:%d).",
                                STR_SAVING_TO_BACKEND_FAILED,
                                __FUNC__, __LINE__);
                    return(-1);
                }

                /* example: "interface 'lan' has been changed: active is now set to 'Yes' (was: 'No')." */
                vrmr_audit("%s '%s' %s: %s %s '%s' (%s: '%s').",
                                STR_INTERFACE, iface_ptr->name, STR_HAS_BEEN_CHANGED,
                                STR_ACTIVE, STR_IS_NOW_SET_TO, tempiface_ptr->active ? "Yes" : "No",
                                STR_WAS, iface_ptr->active ? "Yes" : "No");
            }
            else if(InterfacesSection.EditInterface.fields[i] == IfSec.ipaddressfld)
            {
                // ipaddress
                status = VRMR_ST_CHANGED;

                if(!(copy_field2buf(tempiface_ptr->ipv4.ipaddress,
                                    field_buffer(InterfacesSection.EditInterface.fields[i], 0),
                                    sizeof(tempiface_ptr->ipv4.ipaddress))))
                    return(-1);

                result = af->tell(debuglvl, ifac_backend, tempiface_ptr->name, "IPADDRESS", tempiface_ptr->ipv4.ipaddress, 1, VRMR_TYPE_INTERFACE);
                if(result < 0)
                {
                    vrmr_error(-1, VR_ERR, "%s (in: %s:%d).",
                                STR_SAVING_TO_BACKEND_FAILED,
                                __FUNC__, __LINE__);
                    return(-1);
                }

                /* example: "interface 'lan' has been changed: IP address is now set to '1.2.3.4' (was: '4.3.2.1')." */
                vrmr_audit("%s '%s' %s: %s %s '%s' (%s: '%s').",
                                STR_INTERFACE, iface_ptr->name, STR_HAS_BEEN_CHANGED,
                                STR_IPADDRESS, STR_IS_NOW_SET_TO, tempiface_ptr->ipv4.ipaddress,
                                STR_WAS, iface_ptr->ipv4.ipaddress);
            }
            else if(InterfacesSection.EditInterface.fields[i] == IfSec.ip6addressfld)
            {
#ifdef IPV6_ENABLED
                // ipaddress
                status = VRMR_ST_CHANGED;

                if(!(copy_field2buf(tempiface_ptr->ipv6.ip6,
                                    field_buffer(InterfacesSection.EditInterface.fields[i], 0),
                                    sizeof(tempiface_ptr->ipv6.ip6))))
                    return(-1);

                result = af->tell(debuglvl, ifac_backend, tempiface_ptr->name, "IPV6ADDRESS", tempiface_ptr->ipv6.ip6, 1, VRMR_TYPE_INTERFACE);
                if(result < 0)
                {
                    vrmr_error(-1, VR_ERR, "%s (in: %s:%d).",
                                STR_SAVING_TO_BACKEND_FAILED,
                                __FUNC__, __LINE__);
                    return(-1);
                }

                /* example: "interface 'lan' has been changed: IP address is now set to '1.2.3.4' (was: '4.3.2.1')." */
                vrmr_audit("%s '%s' %s: %s %s '%s' (%s: '%s').",
                                STR_INTERFACE, iface_ptr->name, STR_HAS_BEEN_CHANGED,
                                STR_IP6ADDRESS, STR_IS_NOW_SET_TO, tempiface_ptr->ipv6.ip6,
                                STR_WAS, iface_ptr->ipv6.ip6);
#endif
            }
            else if(InterfacesSection.EditInterface.fields[i] == IfSec.dynamicfld)
            {
                // active
                status = VRMR_ST_CHANGED;

                if(strncasecmp(field_buffer(InterfacesSection.EditInterface.fields[i], 0), "X", 1) == 0)
                {
                    tempiface_ptr->dynamic = 1;

                    result = af->tell(debuglvl, ifac_backend, tempiface_ptr->name, "IPADDRESS", "dynamic", 1, VRMR_TYPE_INTERFACE);
                    if(result < 0)
                    {
                        vrmr_error(-1, VR_ERR, "%s (in: %s:%d).",
                                    STR_SAVING_TO_BACKEND_FAILED,
                                    __FUNC__, __LINE__);
                        return(-1);
                    }
                }
                else if(strncasecmp(field_buffer(InterfacesSection.EditInterface.fields[i], 0), " ", 1) == 0)
                {
                    tempiface_ptr->dynamic = 0;

                    result = af->tell(debuglvl, ifac_backend, tempiface_ptr->name, "IPADDRESS", tempiface_ptr->ipv4.ipaddress, 1, VRMR_TYPE_INTERFACE);
                    if(result < 0)
                    {
                        vrmr_error(-1, VR_ERR, "%s (in: %s:%d).",
                                    STR_SAVING_TO_BACKEND_FAILED,
                                    __FUNC__, __LINE__);
                        return(-1);
                    }
                }
                else
                {
                    tempiface_ptr->dynamic = -1;
                }

                /* example: "interface 'lan' has been changed: dynamic IP address is now set to 'Yes' (was: 'No')." */
                vrmr_audit("%s '%s' %s: %s %s '%s' (%s: '%s').",
                                STR_INTERFACE, iface_ptr->name, STR_HAS_BEEN_CHANGED,
                                STR_DYNAMICIP, STR_IS_NOW_SET_TO, tempiface_ptr->dynamic ? "Yes" : "No",
                                STR_WAS, iface_ptr->dynamic ? "Yes" : "No");
            }
            else if(InterfacesSection.EditInterface.fields[i] == IfSec.devicefld)
            {
                status = VRMR_ST_CHANGED;

                if(!(copy_field2buf(tempiface_ptr->device,
                                    field_buffer(InterfacesSection.EditInterface.fields[i], 0),
                                    sizeof(tempiface_ptr->device))))
                    return(-1);

                result = af->tell(debuglvl, ifac_backend, tempiface_ptr->name, "DEVICE", tempiface_ptr->device, 1, VRMR_TYPE_INTERFACE);
                if(result < 0)
                {
                    vrmr_error(-1, VR_ERR, "%s (in: %s:%d).",
                                STR_SAVING_TO_BACKEND_FAILED,
                                __FUNC__, __LINE__);
                    return(-1);
                }

                /* example: "interface 'lan' has been changed: device is now set to 'eth0' (was: 'eth1')." */
                vrmr_audit("%s '%s' %s: %s %s '%s' (%s: '%s').",
                                STR_INTERFACE, iface_ptr->name, STR_HAS_BEEN_CHANGED,
                                STR_DEVICE, STR_IS_NOW_SET_TO, tempiface_ptr->device,
                                STR_WAS, iface_ptr->device);

                /*  if the devicename indicates a virtual
                    interface, set virtual to TRUE. */
                if( vrmr_interface_check_devicename(debuglvl, tempiface_ptr->device) == 0 &&
                    strncasecmp(field_buffer(InterfacesSection.EditInterface.fields[i], 0), "X", 1) != 0)
                {
                    tempiface_ptr->device_virtual = 1;

                    result = af->tell(debuglvl, ifac_backend, tempiface_ptr->name, "VIRTUAL", tempiface_ptr->device_virtual ? "Yes" : "No", 1, VRMR_TYPE_INTERFACE);
                    if(result < 0)
                    {
                        vrmr_error(-1, VR_ERR, "%s (in: %s:%d).",
                                STR_SAVING_TO_BACKEND_FAILED,
                                __FUNC__, __LINE__);
                        return(-1);
                    }

                    /* example: "interface 'lan' has been changed: virtual is now set to 'Yes' (was: 'No')." */
                    vrmr_audit("%s '%s' %s: %s %s '%s' (%s: '%s').",
                            STR_INTERFACE, iface_ptr->name, STR_HAS_BEEN_CHANGED,
                            STR_VIRTUAL, STR_IS_NOW_SET_TO, tempiface_ptr->device_virtual ? "Yes" : "No",
                            STR_WAS, iface_ptr->device_virtual ? "Yes" : "No");
                }
            }
            else if(InterfacesSection.EditInterface.fields[i] == IfSec.commentfld)
            {
                result = af->tell(debuglvl, ifac_backend, tempiface_ptr->name, "COMMENT", field_buffer(InterfacesSection.EditInterface.fields[i], 0), 1, VRMR_TYPE_INTERFACE);
                if(result < 0)
                {
                    vrmr_error(-1, VR_ERR, "%s (in: %s:%d).",
                                STR_SAVING_TO_BACKEND_FAILED,
                                __FUNC__, __LINE__);
                    return(-1);
                }

                /* example: "interface 'lan' has been changed: the comment was changed." */
                vrmr_audit("%s '%s' %s: %s.",
                                STR_INTERFACE, iface_ptr->name, STR_HAS_BEEN_CHANGED,
                                STR_COMMENT_CHANGED);
            }
            else if(InterfacesSection.EditInterface.fields[i] == IfSec.devicevirtualfld)
            {
                status = VRMR_ST_CHANGED;

                if(strncasecmp(field_buffer(InterfacesSection.EditInterface.fields[i], 0), "X", 1) == 0)
                {
                    tempiface_ptr->device_virtual = 1;
                }
                else
                {
                    tempiface_ptr->device_virtual = 0;
                }

                result = af->tell(debuglvl, ifac_backend, tempiface_ptr->name, "VIRTUAL", tempiface_ptr->device_virtual ? "Yes" : "No", 1, VRMR_TYPE_INTERFACE);
                if(result < 0)
                {
                    vrmr_error(-1, VR_ERR, "%s (in: %s:%d).",
                                STR_SAVING_TO_BACKEND_FAILED,
                                __FUNC__, __LINE__);
                    return(-1);
                }

                /* example: "interface 'lan' has been changed: virtual is now set to 'Yes' (was: 'No')." */
                vrmr_audit("%s '%s' %s: %s %s '%s' (%s: '%s').",
                                STR_INTERFACE, iface_ptr->name, STR_HAS_BEEN_CHANGED,
                                STR_VIRTUAL, STR_IS_NOW_SET_TO, tempiface_ptr->device_virtual ? "Yes" : "No",
                                STR_WAS, iface_ptr->device_virtual ? "Yes" : "No");
            }
            /*

            */
            else if(InterfacesSection.EditInterface.fields[i] == IfSec.srcrtpktsfld     ||
                    InterfacesSection.EditInterface.fields[i] == IfSec.icmpredirectfld  || 
                    InterfacesSection.EditInterface.fields[i] == IfSec.sendredirectfld  ||
                    InterfacesSection.EditInterface.fields[i] == IfSec.rpfilterfld      ||
                    InterfacesSection.EditInterface.fields[i] == IfSec.logmartiansfld)
            {
                status = VRMR_ST_CHANGED;

                if(edit_interface_save_rules(debuglvl, tempiface_ptr) < 0)
                {
                    vrmr_error(-1, VR_ERR, "%s (in: %s:%d).",
                                STR_SAVING_TO_BACKEND_FAILED,
                                __FUNC__, __LINE__);
                    return(-1);
                }

                rules_changed = TRUE;
            }
        }
    }

    if(status == VRMR_ST_CHANGED)
    {
        *iface_ptr = *tempiface_ptr;
    }
    free(tempiface_ptr);

    /* audit print list */
    if(rules_changed == TRUE)
    {
        /* example: "interface 'lan' has been changed: rules are changed: number of rules: 5 (listed below)." */
        vrmr_audit("%s '%s' %s: %s: %s: %d (%s).",
                    STR_INTERFACE, iface_ptr->name, STR_HAS_BEEN_CHANGED,
                    STR_RULES_ARE_CHANGED, STR_NUMBER_OF_RULES,
                    iface_ptr->ProtectList.len, STR_LISTED_BELOW);

        for(i = 1, d_node = iface_ptr->ProtectList.top; d_node; d_node = d_node->next, i++)
        {
            rule_ptr = d_node->data;

            if(rule_ptr->action == VRMR_AT_PROTECT)
            {
                vrmr_audit("%2d: %s against %s",
                            i, vrmr_rules_itoaction(rule_ptr->action),
                            rule_ptr->danger);
            }
        }
    }

    return(retval);
}


/*
     1: ok, changes
     0: ok, no changes
    -1: error.
*/
static int
edit_interface(const int debuglvl, struct vrmr_interfaces *interfaces, char *name)
{
    int                     ch; /* keystroke catcher */
    int                     height,
                            width,
                            startx,
                            starty,
                            max_height,
                            max_width,
                            not_defined;    /* 1 if a key is undefined */

    struct vrmr_interface   *iface_ptr = NULL;

    FIELD                   *cur  = NULL,
                            *prev = NULL;

    char                    quit = 0,
                            advanced_mode = vccnf.advanced_mode;

    /* top menu */
    char                    *key_choices[] =    {   "F12",
                                                    "F5",
                                                    "F6",
                                                    "F7",
                                                    "F10"};
    int                     key_choices_n = 5;
    char                    *cmd_choices[] =    {   gettext("help"),
                                                    gettext("advanced"),
                                                    gettext("shaping"),
                                                    gettext("tcpmss"),
                                                    gettext("back")};
    int                     cmd_choices_n = 5;
    int                     retval = 0;

    height = 20;
    width  = 62;
    VrWinGetOffset(-1, -1, height, width, 4, InterfacesSection.i_xre + 1, &starty, &startx);

    /* TODO: advanced option */

    /* search the interface in memory */
    iface_ptr = vrmr_search_interface(debuglvl, interfaces, name);
    if (iface_ptr == NULL) {
        vrmr_error(-1, VR_INTERR, "interface not found in memory");
        return(-1);
    }

    edit_interface_init(debuglvl, name, height, width, starty, startx, iface_ptr);
    cur = current_field(InterfacesSection.EditInterface.form);

    draw_top_menu(debuglvl, top_win, gettext("Edit Interface"), key_choices_n, key_choices, cmd_choices_n, cmd_choices);

    // Loop through to get user requests
    while(quit == 0)
    {
        if(advanced_mode)
        {
            field_opts_on(IfSec.devicevirtuallabelfld, O_VISIBLE);
            field_opts_on(IfSec.devicevirtualbracketsfld, O_VISIBLE);
            field_opts_on(IfSec.devicevirtualfld, O_VISIBLE);

            if(field_buffer(IfSec.devicevirtualfld, 0)[0] != 'X')
            {
                field_opts_on(IfSec.labelfld, O_VISIBLE);

                field_opts_on(IfSec.srcrtpktslabelfld, O_VISIBLE);
                field_opts_on(IfSec.srcrtpktsbracketsfld, O_VISIBLE);
                field_opts_on(IfSec.srcrtpktsfld, O_VISIBLE);

                field_opts_on(IfSec.icmpredirectlabelfld, O_VISIBLE);
                field_opts_on(IfSec.icmpredirectbracketsfld, O_VISIBLE);
                field_opts_on(IfSec.icmpredirectfld, O_VISIBLE);

                field_opts_on(IfSec.sendredirectlabelfld, O_VISIBLE);
                field_opts_on(IfSec.sendredirectbracketsfld, O_VISIBLE);
                field_opts_on(IfSec.sendredirectfld, O_VISIBLE);

                field_opts_on(IfSec.rpfilterlabelfld, O_VISIBLE);
                field_opts_on(IfSec.rpfilterbracketsfld, O_VISIBLE);
                field_opts_on(IfSec.rpfilterfld, O_VISIBLE);

                field_opts_on(IfSec.logmartianslabelfld, O_VISIBLE);
                field_opts_on(IfSec.logmartiansbracketsfld, O_VISIBLE);
                field_opts_on(IfSec.logmartiansfld, O_VISIBLE);
            }
        }

        if(!advanced_mode)
        {
            field_opts_off(IfSec.devicevirtualfld, O_VISIBLE);
            field_opts_off(IfSec.devicevirtuallabelfld, O_VISIBLE);
            field_opts_off(IfSec.devicevirtualbracketsfld, O_VISIBLE);
        }

        if(!advanced_mode || field_buffer(IfSec.devicevirtualfld, 0)[0] == 'X')
        {
            field_opts_off(IfSec.labelfld, O_VISIBLE);

            field_opts_off(IfSec.srcrtpktslabelfld, O_VISIBLE);
            field_opts_off(IfSec.srcrtpktsbracketsfld, O_VISIBLE);
            field_opts_off(IfSec.srcrtpktsfld, O_VISIBLE);

            field_opts_off(IfSec.icmpredirectlabelfld, O_VISIBLE);
            field_opts_off(IfSec.icmpredirectbracketsfld, O_VISIBLE);
            field_opts_off(IfSec.icmpredirectfld, O_VISIBLE);

            field_opts_off(IfSec.sendredirectlabelfld, O_VISIBLE);
            field_opts_off(IfSec.sendredirectbracketsfld, O_VISIBLE);
            field_opts_off(IfSec.sendredirectfld, O_VISIBLE);

            field_opts_off(IfSec.rpfilterlabelfld, O_VISIBLE);
            field_opts_off(IfSec.rpfilterbracketsfld, O_VISIBLE);
            field_opts_off(IfSec.rpfilterfld, O_VISIBLE);

            field_opts_off(IfSec.logmartianslabelfld, O_VISIBLE);
            field_opts_off(IfSec.logmartiansbracketsfld, O_VISIBLE);
            field_opts_off(IfSec.logmartiansfld, O_VISIBLE);
        }

        draw_field_active_mark(cur, prev, InterfacesSection.EditInterface.win, InterfacesSection.EditInterface.form, vccnf.color_win_mark|A_BOLD);

        not_defined = 0;

        // get key
        ch = wgetch(InterfacesSection.EditInterface.win);

        /* comment */
        if(cur == IfSec.commentfld)
        {
            if(nav_field_comment(debuglvl, InterfacesSection.EditInterface.form, ch) < 0)
                not_defined = 1;
        }
        /* active */
        else if(cur == IfSec.activefld)
        {
            if(nav_field_yesno(debuglvl, InterfacesSection.EditInterface.form, ch) < 0)
                not_defined = 1;
        }
        /* dynamic */
        else if(cur == IfSec.dynamicfld)
        {
            if(nav_field_toggleX(debuglvl, InterfacesSection.EditInterface.form, ch) < 0)
                not_defined = 1;

            /* set the ipaddress field to active/inactive */
            if(strncmp(field_buffer(cur, 0), "X", 1) == 0)
                field_opts_off(IfSec.ipaddressfld, O_AUTOSKIP | O_ACTIVE);
            else
                field_opts_on(IfSec.ipaddressfld, O_ACTIVE);

        }
        /* device virtual */
        else if(cur == IfSec.devicevirtualfld   ||
                cur == IfSec.srcrtpktsfld       ||
                cur == IfSec.icmpredirectfld    ||
                cur == IfSec.sendredirectfld    ||
                cur == IfSec.rpfilterfld        ||
                cur == IfSec.logmartiansfld)
        {
            if(nav_field_toggleX(debuglvl, InterfacesSection.EditInterface.form, ch) < 0)
                not_defined = 1;
        }
        else if(cur == IfSec.ipaddressfld ||
                cur == IfSec.devicefld ||
                cur == IfSec.ip6addressfld)
        {
            if(nav_field_simpletext(debuglvl, InterfacesSection.EditInterface.form, ch) < 0)
                not_defined = 1;
        }
        else
        {
            not_defined = 1;
        }

        // Keys special for this window
        if(not_defined == 1)
        {
            switch(ch)
            {
                case 9: // tab
                case KEY_DOWN:
                case 10: // enter

                    form_driver(InterfacesSection.EditInterface.form, REQ_NEXT_FIELD);
                    form_driver(InterfacesSection.EditInterface.form, REQ_END_LINE);
                    break;

                case KEY_UP:

                    form_driver(InterfacesSection.EditInterface.form, REQ_PREV_FIELD);
                    form_driver(InterfacesSection.EditInterface.form, REQ_END_LINE);
                    break;

                case 27:
                case KEY_F(10):
                case 'q':
                case 'Q':

                    quit = 1;
                    break;

                case KEY_F(12):
                case 'h':
                case 'H':
                case '?':

                    print_help(debuglvl, ":[VUURMUUR:INTERFACES:EDIT]:");
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
                case KEY_F(6):
                case 's':
                case 'S':
                    if(field_buffer(IfSec.devicevirtualfld, 0)[0] != 'X')
                        VrShapeIface(debuglvl, iface_ptr);
                    else
                        vrmr_warning(VR_WARN, gettext("shaping is not supported on a virtual interface."));
                    break;
                case KEY_F(7):
                case 't':
                case 'T':
                    if(field_buffer(IfSec.devicevirtualfld, 0)[0] != 'X')
                        VrTcpmssIface(debuglvl, iface_ptr);
                    else
                        vrmr_warning(VR_WARN, gettext("tcpmss is not supported on a virtual interface."));
                    break;
            }
        }

        prev = cur;
        cur = current_field(InterfacesSection.EditInterface.form);

        wrefresh(InterfacesSection.EditInterface.win);
        pos_form_cursor(InterfacesSection.EditInterface.form);
    }

    /* update the screen */
    update_panels();
    doupdate();

    /* save changes */
    retval = edit_interface_save(debuglvl, iface_ptr);

    /* destroy */
    edit_interface_destroy();

    return(retval);
}


static int
init_interfaces_section(const int debuglvl, struct vrmr_interfaces *interfaces)
{
    int                     retval = 0,
                            i = 0;
    struct vrmr_list_node             *d_node = NULL;
    struct vrmr_interface   *iface_ptr = NULL;
    int                     height = 0,
                            width = 0,
                            startx = 0,
                            starty = 0;
    char                    temp[32] = "",
                            *desc_ptr = NULL;
    size_t                  size = 0;

    width = VRMR_MAX_INTERFACE + 32 + 4;
    startx = 1;
    starty = 4;

    InterfacesSection.list_items = interfaces->list.len;

    if(vrmr_list_setup(debuglvl, &InterfacesSection.desc_list, free) < 0)
    {
        vrmr_error(-1, VR_INTERR, "vrmr_list_setup() failed (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    if(!(InterfacesSection.items = (ITEM **)calloc(InterfacesSection.list_items + 1, sizeof(ITEM *))))
    {
        vrmr_error(-1, VR_ERR, gettext("calloc failed: %s (in: %s:%d)."),
                                    strerror(errno), __FUNC__, __LINE__);
        return(-1);
    }

    for(d_node = interfaces->list.top; d_node ; d_node = d_node->next, i++)
    {
        if(!(iface_ptr = d_node->data))
        {
            vrmr_error(-1, VR_INTERR, "NULL pointer (in: %s:%d).", __FUNC__, __LINE__);
            return(-1);
        }

        if(iface_ptr->dynamic == FALSE)
            snprintf(temp, sizeof(temp), "   %-6s  %s", iface_ptr->device, iface_ptr->ipv4.ipaddress);
        else
            snprintf(temp, sizeof(temp), "   %-6s  -", iface_ptr->device);

        size = StrMemLen(temp) + 1;

        if(!(desc_ptr = malloc(size)))
        {
            vrmr_error(-1, VR_ERR, gettext("malloc failed: %s (in: %s:%d)."),
                                    strerror(errno), __FUNC__, __LINE__);
            return(-1);
        }

        (void)strlcpy(desc_ptr, temp, size);

        if(vrmr_list_append(debuglvl, &InterfacesSection.desc_list, desc_ptr) == NULL)
        {
            vrmr_error(-1, VR_INTERR, "vrmr_list_append() failed (in: %s:%d).",
                                    __FUNC__, __LINE__);
            return(-1);
        }

        /* load all interfaces into memory */
        if(!(InterfacesSection.items[i] = new_item(iface_ptr->name, desc_ptr)))
        {
            vrmr_error(-1, VR_INTERR, "new_item() failed (in: %s:%d).",
                                    __FUNC__, __LINE__);
            return(-1);
        }
    }
    InterfacesSection.items[InterfacesSection.list_items] = (ITEM *)NULL;

    if(InterfacesSection.list_items > 0)
    {
        InterfacesSection.top = InterfacesSection.items[0];
        InterfacesSection.bot = InterfacesSection.items[InterfacesSection.list_items - 1];
    }
    else
    {
        InterfacesSection.top = NULL;
        InterfacesSection.bot = NULL;
    }

    /* set height */
    height = (int)InterfacesSection.list_items + 8;
    if(height > LINES - 8)
        height = LINES - 8;

    InterfacesSection.i_yle = starty + height;
    InterfacesSection.i_xre = startx + width;

//TODO
    InterfacesSection.win = newwin(height, width, starty, startx);
    wbkgd(InterfacesSection.win, vccnf.color_win);
    keypad(InterfacesSection.win, TRUE);

//TODO
    InterfacesSection.panel[0] = new_panel(InterfacesSection.win);

//TODO
    InterfacesSection.menu = new_menu((ITEM **)InterfacesSection.items);
    set_menu_win(InterfacesSection.menu, InterfacesSection.win);
    set_menu_sub(InterfacesSection.menu, derwin(InterfacesSection.win, height-7, width-2, 3, 1));

//TODO
    set_menu_format(InterfacesSection.menu, height-8, 1);

    box(InterfacesSection.win, 0, 0);
    print_in_middle(InterfacesSection.win, 1, 0, width, gettext("Interfaces"), vccnf.color_win);
    mvwaddch(InterfacesSection.win, 2, 0, ACS_LTEE);
    mvwhline(InterfacesSection.win, 2, 1, ACS_HLINE, width-2);
    mvwaddch(InterfacesSection.win, 2, width-1, ACS_RTEE);

    set_menu_back(InterfacesSection.menu, vccnf.color_win);
    set_menu_fore(InterfacesSection.menu, vccnf.color_win_rev);

//TODO
    post_menu(InterfacesSection.menu);

    mvwaddch(InterfacesSection.win, height-5, 0, ACS_LTEE);
    mvwhline(InterfacesSection.win, height-5, 1, ACS_HLINE, width-2);
    mvwaddch(InterfacesSection.win, height-5, width-1, ACS_RTEE);

    mvwprintw(InterfacesSection.win, height-4, 2, "<RET> %s", STR_EDIT);
    mvwprintw(InterfacesSection.win, height-3, 2, "<INS> %s", STR_NEW);
    mvwprintw(InterfacesSection.win, height-2, 2, "<DEL> %s", STR_REMOVE);

    /* create the top and bottom fields */
    if(!(InterfacesSection.win_top = newwin(1, 6, starty + 2, width - 8)))
    {
        vrmr_error(-1, VR_ERR, gettext("creating window failed."));
        return(-1);
    }
    wbkgd(InterfacesSection.win_top, vccnf.color_win);
    InterfacesSection.panel_top[0] = new_panel(InterfacesSection.win_top);
    /* TRANSLATORS: max 4 chars */
    wprintw(InterfacesSection.win_top, "(%s)", gettext("more"));
    hide_panel(InterfacesSection.panel_top[0]);

    if(!(InterfacesSection.win_bot = newwin(1, 6, starty + height - 5, width - 8)))
    {
        vrmr_error(-1, VR_ERR, gettext("creating window failed."));
        return(-1);
    }
    wbkgd(InterfacesSection.win_bot, vccnf.color_win);
    InterfacesSection.panel_bot[0] = new_panel(InterfacesSection.win_bot);
    /* TRANSLATORS: max 4 chars */
    wprintw(InterfacesSection.win_bot, "(%s)", gettext("more"));
    hide_panel(InterfacesSection.panel_bot[0]);

    update_panels();
    doupdate();

    return(retval);
}


static int
destroy_interfaces_section(const int debuglvl)
{
    int     retval = 0;
    size_t  i = 0;

    unpost_menu(InterfacesSection.menu);
    free_menu(InterfacesSection.menu);
    for(i = 0; i < InterfacesSection.list_items; ++i)
        free_item(InterfacesSection.items[i]);

    free(InterfacesSection.items);

    del_panel(InterfacesSection.panel[0]);
    destroy_win(InterfacesSection.win);

    vrmr_list_cleanup(debuglvl, &InterfacesSection.desc_list);

    del_panel(InterfacesSection.panel_top[0]);
    destroy_win(InterfacesSection.win_top);
    del_panel(InterfacesSection.panel_bot[0]);
    destroy_win(InterfacesSection.win_bot);

    return(retval);
}


static int
rename_interface(const int debuglvl, struct vrmr_interfaces *interfaces, struct vrmr_zones *zones,
            struct vrmr_rules *rules, char *cur_name_ptr, char *new_name_ptr)
{
    int                     result = 0;
    struct vrmr_interface   *iface_ptr = NULL;
    struct vrmr_zone        *zone_ptr = NULL;
    struct vrmr_list_node             *zone_d_node = NULL,
                            *iface_d_node = NULL;
    char                    save_name[VRMR_MAX_INTERFACE] = "";
    struct vrmr_rule        *rule_ptr = NULL;
    struct vrmr_list_node             *d_node = NULL;
    char                    rules_changed = 0;

    /* safety */
    if(!cur_name_ptr || !new_name_ptr || !interfaces || !zones)
    {
        vrmr_error(-1, VR_INTERR, "parameter problem "
            "(in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    /* for audit log */
    (void)strlcpy(save_name, cur_name_ptr, sizeof(save_name));

    /* get the int from the list */
    if(!(iface_ptr = vrmr_search_interface(debuglvl, interfaces, cur_name_ptr)))
    {
        vrmr_error(-1, VR_INTERR, "interface not found in "
            "the list (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    /*  rename in the backend.The backend will report errors if there
        are any. */
    result = af->rename(debuglvl, ifac_backend, cur_name_ptr, new_name_ptr, VRMR_TYPE_INTERFACE);
    if(result != 0)
    {
        return(-1);
    }

    if(strlcpy(iface_ptr->name, new_name_ptr, sizeof(iface_ptr->name)) >= sizeof(iface_ptr->name))
    {
        vrmr_error(-1, VR_INTERR, "buffer overflow (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }
    iface_ptr = NULL;

    /* update references in the networks */
    for(zone_d_node = zones->list.top; zone_d_node; zone_d_node = zone_d_node->next)
    {
        if(!(zone_ptr = zone_d_node->data))
        {
            vrmr_error(-1, VR_INTERR, "NULL pointer (in: %s:%d).", __FUNC__, __LINE__);
            return(-1);
        }

        if(zone_ptr->type == VRMR_TYPE_NETWORK)
        {
            for(iface_d_node = zone_ptr->InterfaceList.top; iface_d_node; iface_d_node = iface_d_node->next)
            {
                if(!(iface_ptr = iface_d_node->data))
                {
                    vrmr_error(-1, VR_INTERR, "NULL pointer (in: %s:%d).", __FUNC__, __LINE__);
                    return(-1);
                }

                /* we compare with new_name because we already changed it */
                if(strcmp(iface_ptr->name, new_name_ptr) == 0)
                {
                    /* save the interface list so the backend knows about the changed name in the list */
                    if(vrmr_zones_network_save_interfaces(debuglvl, zone_ptr) < 0)
                    {
                        vrmr_error(-1, VR_ERR, gettext("saving to backend failed (in: %s:%d)."), __FUNC__, __LINE__);
                        return(-1);
                    }

                    break;
                }
            }
        }
    }

    /* update references in the rules */
    for(d_node = rules->list.top; d_node; d_node = d_node->next)
    {
        rule_ptr = d_node->data;
        if(rule_ptr == NULL)
        {
            vrmr_error(-1, VR_INTERR, "NULL pointer "
                "(in: %s:%d).", __FUNC__, __LINE__);
            return(-1);
        }
        if(rule_ptr->opt != NULL)
        {
            if(debuglvl >= HIGH)
                vrmr_debug(__FUNC__, "in_int: '%s', "
                    "in_int: '%s', via_int: '%s'.",
                    rule_ptr->opt->in_int,
                    rule_ptr->opt->out_int,
                    rule_ptr->opt->via_int);

            /* check the in_int */
            if(strcmp(rule_ptr->opt->in_int, save_name) == 0)
            {
                /* set the new name to the rules */
                (void)strlcpy(rule_ptr->opt->in_int, new_name_ptr, sizeof(rule_ptr->opt->in_int));
                rules_changed = 1;

                if(debuglvl >= LOW)
                    vrmr_debug(__FUNC__, "rule changed!");
            }
            /* do the same thing for out_int */
            if(strcmp(rule_ptr->opt->out_int, save_name) == 0)
            {
                /* set the new name to the rules */
                (void)strlcpy(rule_ptr->opt->out_int, new_name_ptr, sizeof(rule_ptr->opt->out_int));
                rules_changed = 1;

                if(debuglvl >= LOW)
                    vrmr_debug(__FUNC__, "rule changed!");
            }
            /* do the same thing for via_int */
            if(strcmp(rule_ptr->opt->via_int, save_name) == 0)
            {
                /* set the new name to the rules */
                (void)strlcpy(rule_ptr->opt->via_int, new_name_ptr, sizeof(rule_ptr->opt->via_int));
                rules_changed = 1;

                if(debuglvl >= LOW)
                    vrmr_debug(__FUNC__, "rule changed!");
            }
        }
    }
    /* if we have made changes we write the rulesfile */
    if(rules_changed == 1)
    {
        if(debuglvl >= LOW)
            vrmr_debug(__FUNC__, "rules changed");

        if(vrmr_rules_save_list(debuglvl, rules, &conf) < 0)
        {
            vrmr_error(-1, VR_ERR, gettext("saving rules failed."));
            return(-1);
        }
    }

    /* example: "interface 'lan' has been renamed to 'wan'." */
    vrmr_audit("%s '%s' %s '%s'.", STR_INTERFACE, save_name, STR_HAS_BEEN_RENAMED_TO, new_name_ptr);
    return(0);
}


static int
interfaces_section_vrmr_delete_interface(const int debuglvl, struct vrmr_interfaces *interfaces, char *cur_name_ptr)
{
    int                     result = 0;
    struct vrmr_interface   *iface_ptr = NULL;
    char                    save_name[VRMR_MAX_INTERFACE] = "";

    /* safety */
    if(!cur_name_ptr || !interfaces)
    {
        vrmr_error(-1, VR_INTERR, "parameter problem (in: %s:%d).",
                                __FUNC__, __LINE__);
        return(-1);
    }

    /* for audit log */
    (void)strlcpy(save_name, cur_name_ptr, sizeof(save_name));

    if(!(iface_ptr = vrmr_search_interface(debuglvl, interfaces, cur_name_ptr)))
    {
        vrmr_error(-1, VR_INTERR, "search_interface() failed (in: %s:%d).",
                                __FUNC__, __LINE__);
        return(-1);
    }

    if(iface_ptr->refcnt_network > 0)
    {
        vrmr_error(-1, VR_ERR, "interface '%s' is still attached to %u network(s).",
                            iface_ptr->name, iface_ptr->refcnt_network);
        return(-1);
    }

    result = vrmr_delete_interface(debuglvl, interfaces, iface_ptr->name);
    if(result < 0)
    {
        return(-1);
    }

    /* example: "interface 'lan' has been deleted." */
    vrmr_audit("%s '%s' %s.", STR_INTERFACE, save_name, STR_HAS_BEEN_DELETED);
    return(0);
}


void
interfaces_section(const int debuglvl, struct vrmr_interfaces *interfaces, struct vrmr_zones *zones,
            struct vrmr_rules *rules, struct vrmr_regex *reg)
{
    int     result = 0,
            quit = 0,
            reload = 0;
    int     ch = 0;
    char    *new_name_ptr = NULL,
            *cur_name_ptr = NULL;
    ITEM    *cur = NULL;

    /* top menu */
    char    *key_choices[] =    {   "F12",
                                    "INS",
                                    "DEL",
                                    "r",
                                    "RET",
                                    "F10"};
    int     key_choices_n = 6;
    char    *cmd_choices[] =    {   gettext("help"),
                                    gettext("new"),
                                    gettext("del"),
                                    gettext("rename"),
                                    gettext("edit"),
                                    gettext("back")};
    int     cmd_choices_n = 6;


    result = init_interfaces_section(debuglvl, interfaces);
    if(result < 0)
        return;

    draw_top_menu(debuglvl, top_win, gettext("Interfaces"), key_choices_n, key_choices, cmd_choices_n, cmd_choices);

    // refresh screen
    update_panels();
    doupdate();

    while(quit == 0)
    {
        if(reload == 1)
        {
            result=destroy_interfaces_section(debuglvl);
            if(result < 0)
                return;

            result = init_interfaces_section(debuglvl, interfaces);
            if(result < 0)
                return;

            // refresh screen
            update_panels();
            doupdate();
            reload=0;
        }

        while(quit == 0 && reload == 0)
        {
            if(InterfacesSection.top != NULL && !item_visible(InterfacesSection.top))
                show_panel(InterfacesSection.panel_top[0]);
            else
                hide_panel(InterfacesSection.panel_top[0]);

            if(InterfacesSection.bot != NULL && !item_visible(InterfacesSection.bot))
                show_panel(InterfacesSection.panel_bot[0]);
            else
                hide_panel(InterfacesSection.panel_bot[0]);

            update_panels();
            doupdate();

            /* restore the cursor */
            pos_menu_cursor(InterfacesSection.menu);

            ch = wgetch(InterfacesSection.win);
            switch(ch)
            {
                case 27:
                case 'q':
                case 'Q':
                case KEY_F(10): //quit

                    quit = 1;
                    break;

                case 'r':
                case 'R':

                    cur = current_item(InterfacesSection.menu);
                    if(cur)
                    {
                        cur_name_ptr = (char *)item_name(cur);
                        if(cur_name_ptr)
                        {
                            new_name_ptr = input_box(32, gettext("Rename Interface"), STR_PLEASE_ENTER_THE_NAME);
                            if(new_name_ptr != NULL)
                            {
                                if(vrmr_validate_interfacename(debuglvl, new_name_ptr, reg->interfacename) == 0)
                                {
                                    result = rename_interface(debuglvl, interfaces, zones, rules, cur_name_ptr, new_name_ptr);
                                    if(result == 0)
                                    {
                                        reload = 1;
                                    }
                                    else
                                    {
                                        vrmr_error(-1, VR_ERR, "%s", STR_RENAME_FAILED);
                                    }
                                }
                                else
                                {
                                    vrmr_error(-1, VR_ERR, "%s.", STR_INVALID_NAME);
                                }
                                free(new_name_ptr);
                            }
                        }
                    }
                    break;

                case KEY_IC: //insert
                case 'i':
                case 'I':

                    new_name_ptr = input_box(32, gettext("New Interface"), STR_PLEASE_ENTER_THE_NAME);
                    if(new_name_ptr != NULL)
                    {
                        if(vrmr_validate_interfacename(debuglvl, new_name_ptr, reg->interfacename) == 0)
                        {
                            result = vrmr_new_interface(debuglvl, interfaces, new_name_ptr);
                            if(result == 0)
                            {
                                /* example: "interface '%s' has been created." */
                                vrmr_audit("%s '%s' %s.", STR_INTERFACE, new_name_ptr, STR_HAS_BEEN_CREATED);

                                edit_interface(debuglvl, interfaces, new_name_ptr);
                                draw_top_menu(debuglvl, top_win, gettext("Interfaces"), key_choices_n, key_choices, cmd_choices_n, cmd_choices);

                                reload = 1;
                            }
                            else
                            {
                                vrmr_error(-1, VR_ERR, gettext("creating new interface failed."));
                            }
                        }
                        else
                        {
                            vrmr_error(-1, VR_ERR, "%s.", STR_INVALID_NAME);
                        }
                        free(new_name_ptr);
                    }
                    break;

                case KEY_DC: // delete
                case 'd':
                case 'D':

                    cur = current_item(InterfacesSection.menu);
                    if(cur)
                    {
                        if (confirm(gettext("Delete"), gettext("Are you sure?"),
                                    vccnf.color_win_note, vccnf.color_win_note_rev|A_BOLD, 0) == 1)
                        {
                            char *n = (char *)item_name(cur);

                            result = interfaces_section_vrmr_delete_interface(debuglvl, interfaces, n);
                            if(result < 0)
                            {
                                vrmr_error(-1, VR_ERR, gettext("deleting interface %s failed."), (char *)item_name(cur));
                            }

                            reload = 1;
                        }
                    }
                    break;

                case KEY_DOWN:
                    menu_driver(InterfacesSection.menu, REQ_DOWN_ITEM);
                    break;
                case KEY_UP:
                    menu_driver(InterfacesSection.menu, REQ_UP_ITEM);
                    break;
                case KEY_NPAGE:
                    if(menu_driver(InterfacesSection.menu, REQ_SCR_DPAGE) != E_OK)
                    {
                        while(menu_driver(InterfacesSection.menu, REQ_DOWN_ITEM) == E_OK);
                    }
                    break;
                case KEY_PPAGE:
                    if(menu_driver(InterfacesSection.menu, REQ_SCR_UPAGE) != E_OK)
                    {
                        while(menu_driver(InterfacesSection.menu, REQ_UP_ITEM) == E_OK);
                    }
                    break;
                case KEY_HOME:
                    menu_driver(InterfacesSection.menu, REQ_FIRST_ITEM);    // home
                    break;
                case KEY_END:
                    menu_driver(InterfacesSection.menu, REQ_LAST_ITEM); // end
                    break;

                case 32: // space
                case KEY_RIGHT:
                case 10: // enter
                case 'e':
                case 'E':

                    cur = current_item(InterfacesSection.menu);
                    if(cur)
                    {
                        if(edit_interface(debuglvl, interfaces, (char *)item_name(cur)) == 1)
                            reload = 1;

                        draw_top_menu(debuglvl, top_win, gettext("Interfaces"), key_choices_n, key_choices, cmd_choices_n, cmd_choices);
                    }
                    break;

                case KEY_F(12):
                case 'h':
                case 'H':
                case '?':

                    print_help(debuglvl, ":[VUURMUUR:INTERFACES]:");
                    break;

/*              case 'b':

                    bandwidth_get_iface(debuglvl, "eth0");
                    break;
*/          }
        }
    }

//TODO
    (void)destroy_interfaces_section(debuglvl);

    // refresh screen
    update_panels();
    doupdate();
}
