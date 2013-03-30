/***************************************************************************
 *   Copyright (C) 2002-2007 by Victor Julien                              *
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

#include "config.h"
#include "vuurmuur.h"


/*  vrmr_list_setup

    Sets up a d_list.

    Returncodes:
         0: ok
        -1: internal error

    This function can only fail due to a programming error.
*/
int
vrmr_list_setup(const int debuglvl, d_list *list, void (*remove)(void *data))
{
    /* safety first */
    if(!list)
    {
        (void)vrprint.error(-1, "Internal Error", "parameter problem (in: %s:%d).", __FUNC__, __LINE__);
        return(-1);
    }

    /* init */
    list->len = 0;
    list->top = NULL;
    list->bot = NULL;
    list->remove = remove;

    return(0);
}


/*  vrmr_list_remove_node

    d_node is the node to remove
*/
int
vrmr_list_remove_node(const int debuglvl, d_list *d_list, struct vrmr_list_node *d_node)
{
    if(debuglvl >= HIGH)
        (void)vrprint.debug(__FUNC__, "start.");

    /* safety first */
    if(!d_list || !d_node)
    {
        (void)vrprint.error(-1, "Internal Error", "parameter problem (in: %s).", __FUNC__);
        return(-1);
    }

    /* we cannot remove from an empty list */
    if(d_list->len == 0)
    {
        (void)vrprint.error(-1, "Internal Error", "cannot remove from an empty list (in: %s).", __FUNC__);
        return(-1);
    }

    if(debuglvl >= HIGH)
        (void)vrprint.debug(__FUNC__, "list len %d.", d_list->len);

    /* we remove the top */
    if(d_node->prev)
    {
        if(debuglvl >= HIGH)
            (void)vrprint.debug(__FUNC__, "setting d_node->prev->next to d_node->next.");

        d_node->prev->next = d_node->next;
    }
    else
    {
        if(debuglvl >= HIGH)
        {
            (void)vrprint.debug(__FUNC__, "removing the top.");
            (void)vrprint.debug(__FUNC__, "top setting top to next.");
        }

        d_list->top = d_node->next;
    }

    /* we remove the bottom */
    if(d_node->next)
    {
        if(debuglvl >= HIGH)
            (void)vrprint.debug(__FUNC__, "setting d_node->next->prev to d_node->prev.");

        d_node->next->prev = d_node->prev;
    }
    else
    {
        if(debuglvl >= HIGH)
        {
            (void)vrprint.debug(__FUNC__, "removing the bottom.");
            (void)vrprint.debug(__FUNC__, "top setting bot to prev.");
        }

        d_list->bot = d_node->prev;
    }

    /* debug */
    if(debuglvl >= HIGH)
    {
        if(d_list->top == NULL)
            (void)vrprint.debug(__FUNC__, "top is now NULL.");

        if(d_list->bot == NULL)
            (void)vrprint.debug(__FUNC__, "bot is now NULL.");
    }

    /* call the user remove function */
    if(d_list->remove != NULL)
    {
        if(debuglvl >= HIGH)
            (void)vrprint.debug(__FUNC__, "calling the user defined data remove function.");

        d_list->remove(d_node->data);
    }
    else
    {
        if(debuglvl >= HIGH)
            (void)vrprint.debug(__FUNC__, "no data remove function defined.");
    }

    /* free the node */
    free(d_node);
    d_node = NULL;

    /* adjust the length */
    d_list->len--;

    if(debuglvl >= HIGH)
    {
        (void)vrprint.debug(__FUNC__, "at exit list len %d.", d_list->len);
        (void)vrprint.debug(__FUNC__, "stop.");
    }

    return(0);
};


int
vrmr_list_remove_top(const int debuglvl, d_list *list)
{
    return(vrmr_list_remove_node(debuglvl, list, list->top));
}


int
vrmr_list_remove_bot(const int debuglvl, d_list *list)
{
    return(vrmr_list_remove_node(debuglvl, list, list->bot));
}


/*  vrmr_list_append

    Returncodes:
         0: ok
        -1: error
*/
struct vrmr_list_node *
vrmr_list_append(const int debuglvl, d_list *d_list, const void *data)
{
    struct vrmr_list_node *new_node = NULL;
    struct vrmr_list_node *prev_node = NULL;

    if(debuglvl >= HIGH)
        (void)vrprint.debug(__FUNC__, "start.");

    /*
        safety first
    */
    if(!d_list)
    {
        (void)vrprint.error(-1, "Internal Error", "parameter problem (in: %s:%d).",
                __FUNC__, __LINE__);
        return(NULL);
    }

    /*
        alloc the new node
    */
    if(!(new_node = malloc(sizeof(struct vrmr_list_node))))
    {
        (void)vrprint.error(-1, "Internal Error", "malloc failed: %s (in: %s:%d).",
                strerror(errno), __FUNC__, __LINE__);
        return(NULL);
    }

    /*
        attach the data
    */
    new_node->data = (void *)data;

    /*
        update the prev_node
    */
    prev_node = d_list->bot;
    if(prev_node)
    {
        prev_node->next = new_node;
    }
    else
    {
        if(debuglvl >= HIGH)
            (void)vrprint.debug(__FUNC__, "appended in an empty list (%d).", d_list->len);
    }

    /*
        set the prev node
    */
    new_node->prev = prev_node;

    /*
        the next node must be NULL since its the end of the list
    */
    new_node->next = NULL;

    /*
        and that also why we have to set d_list->bot
    */
    d_list->bot = new_node;

    /*
        if the top is NULL, we inserted into an empty list
        so we also have set the top to the new_node
    */
    if(!d_list->top)
        d_list->top = new_node;

    /*
        update the list size
    */
    d_list->len++;

    return(new_node);
}


struct vrmr_list_node *
vrmr_list_prepend(const int debuglvl, d_list *d_list, const void *data)
{
    struct vrmr_list_node *new_node = NULL;
    struct vrmr_list_node *next_node = NULL;

    /*
        safety first
    */
    if(!d_list)
    {
        (void)vrprint.error(-1, "Internal Error", "parameter problem (in: %s:%d).",
                __FUNC__, __LINE__);
        return(NULL);
    }

    /*
        alloc the new node
    */
    if(!(new_node = malloc(sizeof(struct vrmr_list_node))))
    {
        (void)vrprint.error(-1, "Internal Error", "malloc failed: %s (in: %s:%d).",
                strerror(errno), __FUNC__, __LINE__);
        return(NULL);
    }

    /*
        append the data
    */
    new_node->data = (void *)data;

    /*
        update the next_node
    */
    next_node = d_list->top;
    if(next_node)
    {
        next_node->prev = new_node;
    }
    else
    {
        if(debuglvl >= HIGH)
            (void)vrprint.debug(__FUNC__, "prepended in an empty list (%d).", d_list->len);
    }

    /*
        the prev node must be NULL since its the start of the list
    */
    new_node->prev = NULL;

    new_node->next = next_node;

    /*
        and that also why we have to set d_list->top
    */
    d_list->top = new_node;

    /*
        if the bot is NULL, we inserted into an empty list
        so we also have set the bot to the new_node
    */
    if(!d_list->bot)
        d_list->bot = new_node;

    /*
        update the list size
    */
    d_list->len++;

    return(new_node);
}


struct vrmr_list_node *
vrmr_list_insert_after(const int debuglvl, d_list *d_list, struct vrmr_list_node *d_node, const void *data)
{
    struct vrmr_list_node *new_node = NULL;

    if(debuglvl >= HIGH)
        (void)vrprint.debug(__FUNC__, "start.");

    /*
        safety first
    */
    if(!d_list)
    {
        (void)vrprint.error(-1, "Internal Error", "parameter problem (in: %s:%d).",
                __FUNC__, __LINE__);
        return(NULL);
    }

    /*
        if d_node is NULL we pass over to the vrmr_list_append fuction
    */
    if(d_node == NULL)
    {
        if(debuglvl >= HIGH)
            (void)vrprint.debug(__FUNC__, "d_node == NULL, calling vrmr_list_append.");

        return(vrmr_list_append(debuglvl, d_list, data));
    }


    /*
        alloc the new node
    */
    if(!(new_node = malloc(sizeof(struct vrmr_list_node))))
    {
        (void)vrprint.error(-1, "Internal Error", "malloc failed: %s (in: %s:%d).",
                strerror(errno), __FUNC__, __LINE__);
        return(NULL);
    }

    /*
        set the data
    */
    new_node->data = (void *)data;

    /*
        set the next node
    */
    new_node->next = d_node->next;

    /*
        bot of the list
    */
    if(new_node->next == NULL)
    {
        if(debuglvl >= HIGH)
            (void)vrprint.debug(__FUNC__, "new node is the list bot.");

        d_list->bot = new_node;
    }
    else
    {
        if(debuglvl >= HIGH)
            (void)vrprint.debug(__FUNC__, "new node is NOT the list bot.");

        new_node->next->prev = new_node;
    }

    /*
        set the prev node
    */
    new_node->prev = d_node;
    d_node->next = new_node;

    /*
        update the list size
    */
    d_list->len++;

    return(new_node);
}


struct vrmr_list_node *
vrmr_list_insert_before(const int debuglvl, d_list *d_list, struct vrmr_list_node *d_node, const void *data)
{
    struct vrmr_list_node *new_node = NULL;


    /* safety first */
    if(!d_list)
    {
        (void)vrprint.error(-1, "Internal Error", "parameter problem (in: %s:%d).",
                __FUNC__, __LINE__);
        return(NULL);
    }

    /* if d_node is NULL we pass over to the vrmr_list_prepend fuction */
    if(d_node == NULL)
    {
        if(debuglvl >= HIGH)
            (void)vrprint.debug(__FUNC__, "d_node == NULL, calling vrmr_list_prepend.");

        return(vrmr_list_prepend(debuglvl, d_list, data));
    }


    /* alloc the new node */
    if(!(new_node = malloc(sizeof(struct vrmr_list_node))))
    {
        (void)vrprint.error(-1, "Internal Error", "malloc failed: %s (in: %s:%d).",
                strerror(errno), __FUNC__, __LINE__);
        return(NULL);
    }

    /* set the data */
    new_node->data = (void *)data;

    /* set the prev node */
    new_node->prev = d_node->prev;

    /* top of the list */
    if(new_node->prev == NULL)
    {
        if(debuglvl >= HIGH)
            (void)vrprint.debug(__FUNC__, "new node is the list top.");

        d_list->top = new_node;
    }
    else
    {
        if(debuglvl >= HIGH)
            (void)vrprint.debug(__FUNC__, "new node is NOT the list top.");

        new_node->prev->next = new_node;
    }

    /* set the next node */
    new_node->next = d_node;
    d_node->prev = new_node;

    /* update the list length */
    d_list->len++;

    /* return the new node */
    return(new_node);
}


int
vrmr_list_node_is_top(const int debuglvl, struct vrmr_list_node *d_node)
{
    /* safety */
    if(!d_node)
    {
        (void)vrprint.error(-1, "Internal Error", "parameter problem (in: %s:%d).",
                __FUNC__, __LINE__);
        return(-1);
    }

    /* see if we have a prev-node */
    if(d_node->prev == NULL)
        return(1);
    else
        return(0);
}


int
vrmr_list_node_is_bot(const int debuglvl, struct vrmr_list_node *d_node)
{
    /* safety */
    if(!d_node)
    {
        (void)vrprint.error(-1, "Internal Error", "parameter problem (in: %s:%d).",
                __FUNC__, __LINE__);
        return(-1);
    }

    /* see if we have a next-node */
    if(d_node->next == NULL)
        return(1);
    else
        return(0);
}


int
vrmr_list_cleanup(const int debuglvl, d_list *d_list)
{
    /* safety */
    if(!d_list)
    {
        (void)vrprint.error(-1, "Internal Error", "parameter problem (in: %s:%d).",
                __FUNC__, __LINE__);
        return(-1);
    }

    /* remove the top while list len > 0 */
    for(;d_list->len;)
    {
        if(vrmr_list_remove_top(debuglvl, d_list) < 0)
        {
            (void)vrprint.error(-1, "Error", "could not remove node (in: %s:%d).",
                    __FUNC__, __LINE__);
            return(-1);
        }
    }

    return(0);
}
