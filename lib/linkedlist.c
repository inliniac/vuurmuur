/***************************************************************************
 *   Copyright (C) 2002-2017 by Victor Julien                              *
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

    Sets up a struct vrmr_list.

    Returncodes:
         0: ok
        -1: internal error

    This function can only fail due to a programming error.
*/
void
vrmr_list_setup(const int debuglvl, struct vrmr_list *list, void (*remove)(void *data))
{
    assert(list);

    /* init */
    list->len = 0;
    list->top = NULL;
    list->bot = NULL;
    list->remove = remove;

    return;
}


/*  vrmr_list_remove_node

    d_node is the node to remove
*/
int
vrmr_list_remove_node(const int debuglvl, struct vrmr_list *list, struct vrmr_list_node *d_node)
{
    /* safety first */
    if(!list || !d_node)
    {
        vrmr_error(-1, "Internal Error", "parameter problem (in: %s).", __FUNC__);
        return(-1);
    }

    /* we cannot remove from an empty list */
    if(list->len == 0)
    {
        assert(list->top == NULL);
        assert(list->bot == NULL);

        vrmr_error(-1, "Internal Error", "cannot remove from an empty list (in: %s).", __FUNC__);
        return(-1);
    }

    assert(list->top);
    assert(list->bot);

    /* we remove the top */
    if (d_node->prev) {
        assert(d_node != list->top);
        d_node->prev->next = d_node->next;
    } else {
        assert(d_node == list->top);
        list->top = d_node->next;
    }

    /* we remove the bottom */
    if (d_node->next) {
        assert(d_node != list->bot);
        d_node->next->prev = d_node->prev;
    } else {
        assert(d_node == list->bot);
        list->bot = d_node->prev;
    }

    /* call the user remove function */
    if (list->remove != NULL) {
        if(debuglvl >= HIGH)
            vrmr_debug(__FUNC__, "calling the user defined data remove function.");

        list->remove(d_node->data);
    }

    /* free the node */
    free(d_node);
    d_node = NULL;

    /* adjust the length */
    list->len--;
    return(0);
}

/** \brief shortcut for removing list head
 *  \note the complicated assertions are to convince coverity
 *        no double free is happening. Apparently it doesn't
 *        properly keep track of list->top.
 */
int
vrmr_list_remove_top(const int debuglvl, struct vrmr_list *list)
{
    assert(list);
#ifdef CPPCHECK
    return (vrmr_list_remove_node(debuglvl, list, list->top));
#else
    struct vrmr_list_node *old_top = list->top;
    int result = vrmr_list_remove_node(debuglvl, list, old_top);
    assert(old_top != list->top);
    struct vrmr_list_node *new_top = list->top;
    assert(old_top != new_top);
    return result;
#endif
}

/** \brief shortcut for removing list tail
 *  \note see vrmr_list_remove_top()
 */
int
vrmr_list_remove_bot(const int debuglvl, struct vrmr_list *list)
{
    assert(list);
#ifdef CPPCHECK
    return(vrmr_list_remove_node(debuglvl, list, list->bot));
#else
    struct vrmr_list_node *old_bot = list->bot;
    int result = vrmr_list_remove_node(debuglvl, list, old_bot);
    assert(old_bot != list->bot);
    struct vrmr_list_node *new_bot = list->bot;
    assert(old_bot != new_bot);
    return result;
#endif
}

/*  vrmr_list_append

    Returncodes:
         0: ok
        -1: error
*/
struct vrmr_list_node *
vrmr_list_append(const int debuglvl, struct vrmr_list *list, const void *data)
{
    struct vrmr_list_node *new_node = NULL;
    struct vrmr_list_node *prev_node = NULL;

    if(debuglvl >= HIGH)
        vrmr_debug(__FUNC__, "start.");

    /*
        safety first
    */
    if(!list)
    {
        vrmr_error(-1, "Internal Error", "parameter problem (in: %s:%d).",
                __FUNC__, __LINE__);
        return(NULL);
    }

    /*
        alloc the new node
    */
    if(!(new_node = malloc(sizeof(struct vrmr_list_node))))
    {
        vrmr_error(-1, "Internal Error", "malloc failed: %s (in: %s:%d).",
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
    prev_node = list->bot;
    if(prev_node)
    {
        prev_node->next = new_node;
    }
    else
    {
        if(debuglvl >= HIGH)
            vrmr_debug(__FUNC__, "appended in an empty list (%d).", list->len);
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
        and that also why we have to set list->bot
    */
    list->bot = new_node;

    /*
        if the top is NULL, we inserted into an empty list
        so we also have set the top to the new_node
    */
    if(!list->top)
        list->top = new_node;

    /*
        update the list size
    */
    list->len++;

    return(new_node);
}


struct vrmr_list_node *
vrmr_list_prepend(const int debuglvl, struct vrmr_list *list, const void *data)
{
    struct vrmr_list_node *new_node = NULL;
    struct vrmr_list_node *next_node = NULL;

    /*
        safety first
    */
    if(!list)
    {
        vrmr_error(-1, "Internal Error", "parameter problem (in: %s:%d).",
                __FUNC__, __LINE__);
        return(NULL);
    }

    /*
        alloc the new node
    */
    if(!(new_node = malloc(sizeof(struct vrmr_list_node))))
    {
        vrmr_error(-1, "Internal Error", "malloc failed: %s (in: %s:%d).",
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
    next_node = list->top;
    if(next_node)
    {
        next_node->prev = new_node;
    }
    else
    {
        if(debuglvl >= HIGH)
            vrmr_debug(__FUNC__, "prepended in an empty list (%d).", list->len);
    }

    /*
        the prev node must be NULL since its the start of the list
    */
    new_node->prev = NULL;

    new_node->next = next_node;

    /*
        and that also why we have to set list->top
    */
    list->top = new_node;

    /*
        if the bot is NULL, we inserted into an empty list
        so we also have set the bot to the new_node
    */
    if(!list->bot)
        list->bot = new_node;

    /*
        update the list size
    */
    list->len++;

    return(new_node);
}


struct vrmr_list_node *
vrmr_list_insert_after(const int debuglvl, struct vrmr_list *list, struct vrmr_list_node *d_node, const void *data)
{
    struct vrmr_list_node *new_node = NULL;

    if(debuglvl >= HIGH)
        vrmr_debug(__FUNC__, "start.");

    /*
        safety first
    */
    if(!list)
    {
        vrmr_error(-1, "Internal Error", "parameter problem (in: %s:%d).",
                __FUNC__, __LINE__);
        return(NULL);
    }

    /*
        if d_node is NULL we pass over to the vrmr_list_append fuction
    */
    if(d_node == NULL)
    {
        if(debuglvl >= HIGH)
            vrmr_debug(__FUNC__, "d_node == NULL, calling vrmr_list_append.");

        return(vrmr_list_append(debuglvl, list, data));
    }


    /*
        alloc the new node
    */
    if(!(new_node = malloc(sizeof(struct vrmr_list_node))))
    {
        vrmr_error(-1, "Internal Error", "malloc failed: %s (in: %s:%d).",
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
            vrmr_debug(__FUNC__, "new node is the list bot.");

        list->bot = new_node;
    }
    else
    {
        if(debuglvl >= HIGH)
            vrmr_debug(__FUNC__, "new node is NOT the list bot.");

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
    list->len++;

    return(new_node);
}


struct vrmr_list_node *
vrmr_list_insert_before(const int debuglvl, struct vrmr_list *list, struct vrmr_list_node *d_node, const void *data)
{
    struct vrmr_list_node *new_node = NULL;


    /* safety first */
    if(!list)
    {
        vrmr_error(-1, "Internal Error", "parameter problem (in: %s:%d).",
                __FUNC__, __LINE__);
        return(NULL);
    }

    /* if d_node is NULL we pass over to the vrmr_list_prepend fuction */
    if(d_node == NULL)
    {
        if(debuglvl >= HIGH)
            vrmr_debug(__FUNC__, "d_node == NULL, calling vrmr_list_prepend.");

        return(vrmr_list_prepend(debuglvl, list, data));
    }


    /* alloc the new node */
    if(!(new_node = malloc(sizeof(struct vrmr_list_node))))
    {
        vrmr_error(-1, "Internal Error", "malloc failed: %s (in: %s:%d).",
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
            vrmr_debug(__FUNC__, "new node is the list top.");

        list->top = new_node;
    }
    else
    {
        if(debuglvl >= HIGH)
            vrmr_debug(__FUNC__, "new node is NOT the list top.");

        new_node->prev->next = new_node;
    }

    /* set the next node */
    new_node->next = d_node;
    d_node->prev = new_node;

    /* update the list length */
    list->len++;

    /* return the new node */
    return(new_node);
}


int
vrmr_list_node_is_top(const int debuglvl, struct vrmr_list_node *d_node)
{
    /* safety */
    if(!d_node)
    {
        vrmr_error(-1, "Internal Error", "parameter problem (in: %s:%d).",
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
        vrmr_error(-1, "Internal Error", "parameter problem (in: %s:%d).",
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
vrmr_list_cleanup(const int debuglvl, struct vrmr_list *list)
{
    /* safety */
    if(!list)
    {
        vrmr_error(-1, "Internal Error", "parameter problem (in: %s:%d).",
                __FUNC__, __LINE__);
        return(-1);
    }

    /* remove the top while list len > 0 */
    for(;list->len;)
    {
        if(vrmr_list_remove_top(debuglvl, list) < 0)
        {
            vrmr_error(-1, "Error", "could not remove node (in: %s:%d).",
                    __FUNC__, __LINE__);
            return(-1);
        }
    }
    return(0);
}
