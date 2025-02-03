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

int vrmr_hash_setup(struct vrmr_hash_table *hash_table, /* the hash table ;-) */
        unsigned int rows, /* the number of rows in the table */
        unsigned int (*hash_func)(const void *data), /* the hash function */
        int (*compare_func)(const void *table_data,
                const void *search_data), /* the compare function */
        void (*free_func)(void *data))
{
    assert(hash_table != NULL && hash_func && compare_func);

    /* safety, 0 rows is not sane of course */
    if (rows == 0) {
        vrmr_debug(NONE,
                "a hashtable of 0 rows is not really sane, setting to 10.");
        rows = 10;
    }

    /* Allocate space for the hash table. */
    if (!(hash_table->table = (struct vrmr_list *)malloc(
                  rows * sizeof(struct vrmr_list)))) {
        vrmr_error(-1, "Error", "malloc failed: %s", strerror(errno));
        return (-1);
    }

    /* initialize the number of cells in the table. */
    hash_table->cells = 0;

    /* setup the functions. */
    hash_table->hash_func = hash_func;
    hash_table->compare_func = compare_func;
    hash_table->free_func = free_func;

    /* initialize the rows. */
    hash_table->rows = rows;

    /*  setup the row list

        the hash table is not supposed to contain any data, only pointers. So we
        setup the list without a cleanup function.
    */
    for (unsigned int row = 0; row < hash_table->rows; row++) {
        vrmr_list_setup(&hash_table->table[row], free_func);
    }

    return (0);
}

/*  vrmr_hash_cleanup

    Cleans up a hash table.

    NOTE: this function will not remove the data itself, only all pointers to
    the data!

    Returncodes:
         0: ok
        -1: error
*/
int vrmr_hash_cleanup(struct vrmr_hash_table *hash_table)
{
    assert(hash_table);

    /* clear all rows */
    for (unsigned int row = 0; row < hash_table->rows; row++) {
        if (vrmr_list_cleanup(&hash_table->table[row]) < 0) {
            vrmr_error(-1, "Internal Error", "cleaning up row %u failed", row);
            return (-1);
        }
    }

    /* free the hash table */
    free(hash_table->table);

    return (0);
}

/*  vrmr_hash_insert

    Returncodes:
         0: ok
        -1: error
*/
int vrmr_hash_insert(struct vrmr_hash_table *hash_table, const void *data)
{
    assert(hash_table != NULL && data != NULL);

    /* determine the row */
    unsigned int row = hash_table->hash_func(data) % hash_table->rows;

    /* insert the data into the row */
    if (!(vrmr_list_append(&hash_table->table[row], data))) {
        vrmr_error(-1, "Internal Error", "appending to the list failed");
        return (-1);
    }

    /* update the number of cells */
    hash_table->cells++;
    return (0);
}

/*  vrmr_hash_remove

    Removes a pointer to some data from the list.

    Returncodes:
         0: ok
        -1: error
*/
int vrmr_hash_remove(struct vrmr_hash_table *hash_table, void *data)
{
    struct vrmr_list_node *d_node = NULL;
    void *table_data = NULL;

    assert(hash_table != NULL && data != NULL);

    /* hash the key with the hash function */
    unsigned int row = hash_table->hash_func(data) % hash_table->rows;

    /* run trough the list at the row */
    for (d_node = hash_table->table[row].top; d_node; d_node = d_node->next) {
        if (!(table_data = d_node->data)) {
            vrmr_error(-1, "Internal Error", "NULL pointer");
            return (-1);
        }

        /*  call the compare function to compare the supplied data
            with the data from the table.
        */
        if (hash_table->compare_func(table_data, data)) {
            /* remove the data from the row/list. */
            if (vrmr_list_remove_node(&hash_table->table[row], d_node) < 0) {
                vrmr_error(
                        -1, "Internal Error", "removing from the list failed");
                return (-1);
            }

            /* decrease the number of cells */
            hash_table->cells--;

            /* we're done, so return succes! */
            return (0);
        }
    }

    /* the data was not found. */
    return (-1);
}

/*  vrmr_hash_search

    Returns a pointer to the data if found, NULL if not found.
*/
void *vrmr_hash_search(const struct vrmr_hash_table *hash_table, void *data)
{
    void *table_data = NULL;
    struct vrmr_list_node *d_node = NULL;

    assert(hash_table != NULL && data != NULL);

    /* determine the row by calling the hash function */
    unsigned int row = hash_table->hash_func(data) % hash_table->rows;

    /* look for the data in the row */
    for (d_node = hash_table->table[row].top; d_node; d_node = d_node->next) {
        if (!(table_data = d_node->data)) {
            vrmr_error(-1, "Internal Error", "NULL pointer");
            return (NULL);
        }

        /* call the compare function */
        if (hash_table->compare_func(table_data, data)) {
            /* this is the data from the table, so return it */
            return (table_data);
        }
    }

    /* the data was not found. */
    return (NULL);
}

/*
    serv_req is the search string, we only use src_low and dst_low from it.
*/
int vrmr_compare_ports(const void *serv_hash, const void *serv_req)
{
    struct vrmr_portdata *table_port_ptr = NULL, *search_port_ptr = NULL;
    struct vrmr_list_node *d_node = NULL;

    assert(serv_hash != NULL && serv_req != NULL);

    /* cast */
    struct vrmr_service *sertable = (struct vrmr_service *)serv_hash;
    struct vrmr_service *sersearch = (struct vrmr_service *)serv_req;

    /* here we just take the top node, because thats the only one we use for a
     * request */
    if (!(d_node = sersearch->PortrangeList.top)) {
        vrmr_error(-1, "Internal Error", "NULL pointer");
        return (0);
    }
    if (!(search_port_ptr = d_node->data)) {
        vrmr_error(-1, "Internal Error", "NULL pointer");
        return (0);
    }
    d_node = NULL;

    /*
        were going to loop trough the portrange list of serv_req
        if the service has no portranges, we can't match so we bail out.
    */
    if (!(d_node = sertable->PortrangeList.top))
        return (0);

    /* now run trough the portrangelist */
    for (; d_node; d_node = d_node->next) {
        if (!(table_port_ptr = d_node->data)) {
            vrmr_error(-1, "Internal Error", "NULL pointer");
            return (0);
        }

        if (table_port_ptr->protocol != search_port_ptr->protocol)
            continue;

        /* icmp uses type and code */
        if (table_port_ptr->protocol == 1 &&
                table_port_ptr->dst_low == search_port_ptr->dst_low &&
                table_port_ptr->dst_high == search_port_ptr->dst_high) {
            return (1);
        }
        /* now compare the tcp/udp ports

            First compare the dst port (most likely to match) after that the
           src port.
            - search_port_ptr->dst_low is the destination we are looking for
            - search_port_ptr->src_low is the source we are looking for

            both can be in a range or an exact match.
        */
        else if (table_port_ptr->protocol == 6 ||
                 table_port_ptr->protocol == 17) {
            if ((table_port_ptr->dst_high == 0 &&
                        table_port_ptr->dst_low ==
                                search_port_ptr->dst_low) || /* not a range */
                    (table_port_ptr->dst_high != 0 &&        /* range */
                            (search_port_ptr->dst_low >=
                                            table_port_ptr->dst_low &&
                                    search_port_ptr->dst_low <=
                                            table_port_ptr->dst_high))) {
                if ((table_port_ptr->src_high == 0 &&
                            table_port_ptr->src_low ==
                                    search_port_ptr
                                            ->src_low) || /* not a range */
                        (table_port_ptr->src_high != 0 && /* range */
                                (search_port_ptr->src_low >=
                                                table_port_ptr->src_low &&
                                        search_port_ptr->src_low <=
                                                table_port_ptr->src_high))) {
                    /* match! */
                    return (1);
                }
            }
            /* all other protos use no ports, so a proto match is a full
             * match */
        } else {
            return (1);
        }
    }

    /* no match */
    return (0);
}

int vrmr_compare_ipaddress(const void *string1, const void *string2)
{
    assert(string1 != NULL && string2 != NULL);

    /* cast to zonedata */
    struct vrmr_zone *zone1 = (struct vrmr_zone *)string1;
    struct vrmr_zone *zone2 = (struct vrmr_zone *)string2;

    /* Compare two strings */
    if (strcmp(zone1->ipv4.ipaddress, zone2->ipv4.ipaddress) == 0)
        return (1);
    else
        return 0;
}

// vrmr_hash_port
// TODO: check hash > 0 && <= 65535
unsigned int vrmr_hash_port(const void *key)
{
    assert(key);

    struct vrmr_service *ser_ptr = (struct vrmr_service *)key;

    return ((unsigned int)ser_ptr->vrmr_hash_port);
}

/* vrmr_hash_ipaddress */
unsigned int vrmr_hash_ipaddress(const void *key)
{
    struct in_addr ip;

    assert(key);

    struct vrmr_zone *zone_ptr = (struct vrmr_zone *)key;

    /* if inet_aton failes, return 1 (BUG fix) */
    if (inet_aton(zone_ptr->ipv4.ipaddress, &ip) == 0)
        return (1);

    uint32_t ip_i = ntohl(ip.s_addr);

    int result = (int)((ip.s_addr - ip_i) / 100000);
    /* convert to possive number if needed */
    if (result < 0)
        result = result * -1;

    return (unsigned int)result;
}

unsigned int vrmr_hash_string(const void *key)
{
    assert(key);

    char *string_ptr = (char *)key;

    int result = string_ptr[0] - 96;
    /* convert to possive number if needed */
    if (result < 0)
        result = result * -1;

    return (unsigned int)result;
}

int vrmr_compare_string(const void *string1, const void *string2)
{
    assert(string1 != NULL && string2 != NULL);

    char *str1_ptr = (char *)string1;
    char *str2_ptr = (char *)string2;

    if (strcmp(str1_ptr, str2_ptr) == 0)
        return (1);
    else
        return (0);
}

// print_table
void vrmr_print_table_service(const struct vrmr_hash_table *hash_table)
{
    unsigned int i;
    void *list_data = NULL;
    struct vrmr_list_node *d_node = NULL;

    fprintf(stdout, "Hashtable has %u rows and %u cells.\n", hash_table->rows,
            hash_table->cells);

    for (i = 0; hash_table->rows; i++) {
        fprintf(stdout, "Row[%03u]=", i);

        for (d_node = hash_table->table[i].top; d_node; d_node = d_node->next) {
            list_data = d_node->data;

            fprintf(stdout, "%s(%p), ", (char *)list_data, (void *)d_node);
        }

        fprintf(stdout, "\n");
    }

    return;
}

/*
 */
int vrmr_init_services_hashtable(unsigned int n_rows,
        struct vrmr_list *services_list,
        unsigned int (*hash_func)(const void *data),
        int (*compare_func)(const void *table_data, const void *search_data),
        struct vrmr_hash_table *hash_table)
{
    struct vrmr_list_node *d_node = NULL;
    int port = 0;
    struct vrmr_service *ser_ptr = NULL;
    struct vrmr_portdata *portrange_ptr = NULL;
    struct vrmr_list_node *d_node_serlist = NULL;

    vrmr_debug(LOW, "services hashtable size will be %u rows.", n_rows);

    assert(services_list);

    /* init the hashtable for services */
    if (vrmr_hash_setup(hash_table, n_rows, hash_func, compare_func, NULL) !=
            0) {
        vrmr_error(-1, "Internal Error", "hash table initializing failed");
        return (-1);
    }

    for (d_node_serlist = services_list->top; d_node_serlist;
            d_node_serlist = d_node_serlist->next) {
        if (!(ser_ptr = d_node_serlist->data)) {
            vrmr_error(-1, "Internal Error", "NULL pointer");
            return (-1);
        }

        vrmr_debug(HIGH, "service: '%s', '%p', len: '%u'.", ser_ptr->name,
                ser_ptr, ser_ptr->PortrangeList.len);

        if (ser_ptr->PortrangeList.len > 0) {
            for (d_node = ser_ptr->PortrangeList.top; d_node;
                    d_node = d_node->next) {
                vrmr_debug(HIGH,
                        "service: '%s', '%p', len: '%u', d_node: '%p', "
                        "'d_node->data: '%p'.",
                        ser_ptr->name, ser_ptr, ser_ptr->PortrangeList.len,
                        d_node, d_node->data);

                portrange_ptr = d_node->data;
                if (portrange_ptr == NULL) {
                    vrmr_error(-1, "Internal Error", "NULL pointer");
                    return (-1);
                }

                if (portrange_ptr->dst_high == 0) {
                    /*  once a service is inserted into the hash, we dont need
                       to insert it again under the same hash

                        we don't do this check for GRE, because dst_low and
                       vrmr_hash_port are both 0
                    */
                    if ((portrange_ptr->protocol == 1 ||
                                portrange_ptr->protocol == 6 ||
                                portrange_ptr->protocol == 17) &&
                            portrange_ptr->dst_low == ser_ptr->vrmr_hash_port) {
                        vrmr_debug(HIGH,
                                "dupe! service '%s': hashport: %d, prot: %d, "
                                "src_low: %d, src_high: %d, dst_low: %d, "
                                "dst_high: %d",
                                ser_ptr->name, ser_ptr->vrmr_hash_port,
                                portrange_ptr->protocol, portrange_ptr->src_low,
                                portrange_ptr->src_high, portrange_ptr->dst_low,
                                portrange_ptr->dst_high);
                    } else {
                        if (!(portrange_ptr->protocol == 1 ||
                                    portrange_ptr->protocol == 6 ||
                                    portrange_ptr->protocol == 17))
                            ser_ptr->vrmr_hash_port = portrange_ptr->protocol;
                        else
                            ser_ptr->vrmr_hash_port = portrange_ptr->dst_low;

                        vrmr_debug(HIGH,
                                "(dst_high == 0): service '%s': hashport: %d, "
                                "prot: %d, src_low: %d, src_high: %d, dst_low: "
                                "%d, dst_high: %d",
                                ser_ptr->name, ser_ptr->vrmr_hash_port,
                                portrange_ptr->protocol, portrange_ptr->src_low,
                                portrange_ptr->src_high, portrange_ptr->dst_low,
                                portrange_ptr->dst_high);

                        if (vrmr_hash_insert(hash_table, ser_ptr) != 0) {
                            vrmr_error(-1, "Internal Error",
                                    "inserting into hashtable failed");
                            return (1);
                        }
                    }
                } else {
                    for (port = portrange_ptr->dst_low;
                            port <= portrange_ptr->dst_high; port++) {
                        ser_ptr->vrmr_hash_port = port;

                        if (vrmr_hash_insert(hash_table, ser_ptr) != 0) {
                            vrmr_error(-1, "Internal Error",
                                    "inserting into hashtable failed");
                            return (1);
                        }
                    }
                }
            }
        }

        /* now we reset the hash-port variable, otherwise it disturb creating
           the hash again (this function depends on vrmr_hash_port to be 0 on
           start) */
        ser_ptr->vrmr_hash_port = 0;
    }

    return (0);
}

/*
 */
int vrmr_init_zonedata_hashtable(unsigned int n_rows,
        struct vrmr_list *zones_list,
        unsigned int (*hash_func)(const void *data),
        int (*compare_func)(const void *table_data, const void *search_data),
        struct vrmr_hash_table *hash_table)
{
    struct vrmr_zone *zone_ptr = NULL;
    struct vrmr_list_node *d_node = NULL;

    assert(zones_list);

    /* setup the hash table */
    if (vrmr_hash_setup(hash_table, n_rows, hash_func, compare_func, NULL) !=
            0) {
        vrmr_error(-1, "Internal Error", "hash table initializing failed");
        return (-1);
    }

    /* go through the list and insert into the hash-table */
    for (d_node = zones_list->top; d_node; d_node = d_node->next) {
        if (!(zone_ptr = d_node->data)) {
            vrmr_error(-1, "Internal Error", "NULL pointer");
            return (-1);
        }

        /* we only insert hosts and firewalls, which are actually interfaces */
        if (zone_ptr->type == VRMR_TYPE_HOST ||
                zone_ptr->type == VRMR_TYPE_FIREWALL) {
            if (strcmp(zone_ptr->ipv4.ipaddress, "") != 0) {
                if (vrmr_hash_insert(hash_table, zone_ptr) != 0) {
                    vrmr_error(-1, "Internal Error",
                            "inserting hashtable failed for %s",
                            zone_ptr->name);
                    return (-1);
                } else {
                    vrmr_debug(HIGH, "vrmr_hash_insert succes (%s)",
                            zone_ptr->name);
                }
            } else {
                vrmr_debug(HIGH, "no ipaddress in zone %s (%s)", zone_ptr->name,
                        zone_ptr->ipv4.ipaddress);
            }
        }
    }

    return (0);
}

void *vrmr_search_service_in_hash(const int src, const int dst,
        const int protocol, const struct vrmr_hash_table *serhash)
{
    struct vrmr_service *ser_search_ptr = NULL, *return_ptr = NULL;
    struct vrmr_portdata *portrange_ptr = NULL;
    int vrmr_hash_port = 0, src_port = 0, dst_port = 0;

    assert(serhash);

    vrmr_debug(HIGH, "src: %d, dst: %d, protocol: %d.", src, dst, protocol);

    if (protocol == 6 || protocol == 17) {
        vrmr_hash_port = dst;
        src_port = src;
        dst_port = dst;
    } else if (protocol == 1) {
        /* hashport is the icmptype */
        vrmr_hash_port = src;
        src_port = src;
        dst_port = dst;
    } else {
        vrmr_hash_port = protocol;
        src_port = 1;
        dst_port = 1;
    }

    /* alloc the temp service */
    if (!(ser_search_ptr = vrmr_service_malloc())) {
        vrmr_error(-1, "Error", "malloc failed: %s", strerror(errno));
        return (NULL);
    }
    vrmr_list_setup(&ser_search_ptr->PortrangeList, free);

    /* alloc the portrange */
    if (!(portrange_ptr = malloc(sizeof(struct vrmr_portdata)))) {
        vrmr_error(-1, "Error", "malloc failed: %s", strerror(errno));

        free(ser_search_ptr);
        return (NULL);
    }

    /* populate the portrange */
    portrange_ptr->protocol = protocol;
    if (protocol == 1) {
        portrange_ptr->dst_low = src_port;
        portrange_ptr->dst_high = dst_port;
    } else {
        portrange_ptr->dst_low = dst_port;
        portrange_ptr->src_low = src_port;
    }

    /* set the hash port */
    ser_search_ptr->vrmr_hash_port = vrmr_hash_port;

    if (vrmr_list_append(&ser_search_ptr->PortrangeList, portrange_ptr) ==
            NULL) {
        vrmr_error(-1, "Error",
                "insert into list failed for src: %d, dst: %d, prot: %d", src,
                dst, protocol);
        free(portrange_ptr);
        free(ser_search_ptr);
        return (NULL);
    }

    /* here we do the actual search */
    return_ptr = vrmr_hash_search(serhash, (void *)ser_search_ptr);

    /* cleanup */
    portrange_ptr = NULL;
    vrmr_list_cleanup(&ser_search_ptr->PortrangeList);
    free(ser_search_ptr);

    if (!return_ptr)
        vrmr_debug(HIGH, "src: %d, dst: %d, protocol: %d: not found.", src, dst,
                protocol);
    else
        vrmr_debug(HIGH, "src: %d, dst: %d, protocol: %d: found: %s.", src, dst,
                protocol, return_ptr->name);

    return (return_ptr);
}

void *vrmr_search_zone_in_hash_with_ipv4(
        const char *ipaddress, const struct vrmr_hash_table *zonehash)
{
    struct vrmr_zone *search_ptr = NULL, *return_ptr = NULL;

    assert(ipaddress && zonehash);

    /* search zone ptr */
    if (!(search_ptr = malloc(sizeof(struct vrmr_zone)))) {
        vrmr_error(-1, "Error", "malloc failed: %s", strerror(errno));
        return (NULL);
    }

    if (strlcpy(search_ptr->ipv4.ipaddress, ipaddress,
                sizeof(search_ptr->ipv4.ipaddress)) >=
            sizeof(search_ptr->ipv4.ipaddress)) {
        vrmr_error(-1, "Internal Error", "buffer overflow");

        free(search_ptr);
        return (NULL);
    }

    return_ptr = vrmr_hash_search(zonehash, (void *)search_ptr);

    free(search_ptr);

    return (return_ptr);
}
