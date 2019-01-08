/***************************************************************************
 *   Copyright (C) 2002-2019 by Victor Julien                              *
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
void vrmr_list_setup(struct vrmr_list *list, void (*remove)(void *data))
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
int vrmr_list_remove_node(struct vrmr_list *list, struct vrmr_list_node *d_node)
{
    assert(list != NULL && d_node != NULL);

    /* we cannot remove from an empty list */
    if (list->len == 0) {
        assert(list->top == NULL);
        assert(list->bot == NULL);

        vrmr_error(-1, "Internal Error", "cannot remove from an empty list");
        return (-1);
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
        vrmr_debug(HIGH, "calling the user defined data remove function.");

        list->remove(d_node->data);
    }

    /* free the node */
    free(d_node);
    d_node = NULL;

    /* adjust the length */
    list->len--;
    return (0);
}

/** \brief shortcut for removing list head
 *  \note the complicated assertions are to convince coverity
 *        no double free is happening. Apparently it doesn't
 *        properly keep track of list->top.
 */
int vrmr_list_remove_top(struct vrmr_list *list)
{
    assert(list);
#ifdef CPPCHECK
    return (vrmr_list_remove_node(list, list->top));
#else
    struct vrmr_list_node *old_top = list->top;
    int result = vrmr_list_remove_node(list, old_top);
    assert(old_top != list->top);
    struct vrmr_list_node *new_top = list->top;
    assert(old_top != new_top);
    return result;
#endif
}

/** \brief shortcut for removing list tail
 *  \note see vrmr_list_remove_top()
 */
int vrmr_list_remove_bot(struct vrmr_list *list)
{
    assert(list);
#ifdef CPPCHECK
    return (vrmr_list_remove_node(list, list->bot));
#else
    struct vrmr_list_node *old_bot = list->bot;
    int result = vrmr_list_remove_node(list, old_bot);
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
struct vrmr_list_node *vrmr_list_append(
        struct vrmr_list *list, const void *data)
{
    struct vrmr_list_node *new_node = NULL;
    struct vrmr_list_node *prev_node = NULL;

    assert(list);

    vrmr_debug(HIGH, "start.");

    if (!(new_node = malloc(sizeof(struct vrmr_list_node)))) {
        vrmr_error(-1, "Internal Error", "malloc failed: %s", strerror(errno));
        return (NULL);
    }

    new_node->data = (void *)data;

    prev_node = list->bot;
    if (prev_node) {
        prev_node->next = new_node;
    } else {
        vrmr_debug(HIGH, "appended in an empty list (%d).", list->len);
    }

    new_node->prev = prev_node;
    new_node->next = NULL;

    list->bot = new_node;
    if (!list->top)
        list->top = new_node;

    list->len++;
    return (new_node);
}

struct vrmr_list_node *vrmr_list_prepend(
        struct vrmr_list *list, const void *data)
{
    struct vrmr_list_node *new_node = NULL;
    struct vrmr_list_node *next_node = NULL;

    assert(list);

    if (!(new_node = malloc(sizeof(struct vrmr_list_node)))) {
        vrmr_error(-1, "Internal Error", "malloc failed: %s", strerror(errno));
        return (NULL);
    }

    new_node->data = (void *)data;

    next_node = list->top;
    if (next_node) {
        next_node->prev = new_node;
    } else {
        vrmr_debug(HIGH, "prepended in an empty list (%d).", list->len);
    }

    new_node->prev = NULL;
    new_node->next = next_node;

    list->top = new_node;
    if (!list->bot)
        list->bot = new_node;

    list->len++;
    return (new_node);
}

struct vrmr_list_node *vrmr_list_insert_after(
        struct vrmr_list *list, struct vrmr_list_node *d_node, const void *data)
{
    struct vrmr_list_node *new_node = NULL;

    assert(list);

    if (d_node == NULL) {
        vrmr_debug(HIGH, "d_node == NULL, calling vrmr_list_append.");
        return (vrmr_list_append(list, data));
    }

    if (!(new_node = malloc(sizeof(struct vrmr_list_node)))) {
        vrmr_error(-1, "Internal Error", "malloc failed: %s", strerror(errno));
        return (NULL);
    }

    new_node->data = (void *)data;

    new_node->next = d_node->next;
    if (new_node->next == NULL) {
        vrmr_debug(HIGH, "new node is the list bot.");

        list->bot = new_node;
    } else {
        vrmr_debug(HIGH, "new node is NOT the list bot.");

        new_node->next->prev = new_node;
    }

    new_node->prev = d_node;
    d_node->next = new_node;

    list->len++;
    return (new_node);
}

struct vrmr_list_node *vrmr_list_insert_before(
        struct vrmr_list *list, struct vrmr_list_node *d_node, const void *data)
{
    struct vrmr_list_node *new_node = NULL;

    assert(list);

    /* if d_node is NULL we pass over to the vrmr_list_prepend fuction */
    if (d_node == NULL) {
        vrmr_debug(HIGH, "d_node == NULL, calling vrmr_list_prepend.");

        return (vrmr_list_prepend(list, data));
    }

    /* alloc the new node */
    if (!(new_node = malloc(sizeof(struct vrmr_list_node)))) {
        vrmr_error(-1, "Internal Error", "malloc failed: %s", strerror(errno));
        return (NULL);
    }

    /* set the data */
    new_node->data = (void *)data;

    /* set the prev node */
    new_node->prev = d_node->prev;

    /* top of the list */
    if (new_node->prev == NULL) {
        vrmr_debug(HIGH, "new node is the list top.");

        list->top = new_node;
    } else {
        vrmr_debug(HIGH, "new node is NOT the list top.");

        new_node->prev->next = new_node;
    }

    /* set the next node */
    new_node->next = d_node;
    d_node->prev = new_node;

    /* update the list length */
    list->len++;

    /* return the new node */
    return (new_node);
}

int vrmr_list_node_is_top(struct vrmr_list_node *d_node)
{
    assert(d_node);

    /* see if we have a prev-node */
    if (d_node->prev == NULL)
        return (1);
    else
        return (0);
}

int vrmr_list_node_is_bot(struct vrmr_list_node *d_node)
{
    assert(d_node);

    /* see if we have a next-node */
    if (d_node->next == NULL)
        return (1);
    else
        return (0);
}

int vrmr_list_cleanup(struct vrmr_list *list)
{
    assert(list);

    /* remove the top while list len > 0 */
    for (; list->len;) {
        if (vrmr_list_remove_top(list) < 0) {
            vrmr_error(-1, "Error", "could not remove node");
            return (-1);
        }
    }
    return (0);
}
