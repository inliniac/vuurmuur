/***************************************************************************
 *   Copyright (C) 2002-2025 by Victor Julien                              *
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

/*  functions for creating a ruleset file that can be loaded into
    the system by iptables-restore.
*/

#include "main.h"

/* hack: in 0.8 we have to do this right! */
struct vrmr_list accounting_chain_names; /* list with the chainnames */

struct chain_ref {
    char chain[32];
    char refcnt;
};

/*  ruleset_init

    Initializes the struct rule_set datastructure.

    Returncodes:
         0: ok
        -1: error
*/
static int ruleset_setup(struct rule_set *ruleset)
{
    assert(ruleset);

    /* init */
    memset(ruleset, 0, sizeof(struct rule_set));

    /* init the lists */

    /* raw */
    vrmr_list_setup(&ruleset->raw_preroute, free);
    vrmr_list_setup(&ruleset->raw_output, free);

    /* mangle */
    vrmr_list_setup(&ruleset->mangle_preroute, free);
    vrmr_list_setup(&ruleset->mangle_input, free);
    vrmr_list_setup(&ruleset->mangle_forward, free);
    vrmr_list_setup(&ruleset->mangle_output, free);
    vrmr_list_setup(&ruleset->mangle_postroute, free);

    vrmr_list_setup(&ruleset->mangle_shape_in, free);
    vrmr_list_setup(&ruleset->mangle_shape_out, free);
    vrmr_list_setup(&ruleset->mangle_shape_fw, free);

    /* nat */
    vrmr_list_setup(&ruleset->nat_preroute, free);
    vrmr_list_setup(&ruleset->nat_postroute, free);
    vrmr_list_setup(&ruleset->nat_output, free);

    /* filter */
    vrmr_list_setup(&ruleset->filter_input, free);
    vrmr_list_setup(&ruleset->filter_forward, free);
    vrmr_list_setup(&ruleset->filter_output, free);

    vrmr_list_setup(&ruleset->filter_antispoof, free);
    vrmr_list_setup(&ruleset->filter_blocklist, free);
    vrmr_list_setup(&ruleset->filter_blocktarget, free);
    vrmr_list_setup(&ruleset->filter_badtcp, free);
    vrmr_list_setup(&ruleset->filter_synlimittarget, free);
    vrmr_list_setup(&ruleset->filter_udplimittarget, free);
    vrmr_list_setup(&ruleset->filter_newaccepttarget, free);
    /* NFQueue state */
    vrmr_list_setup(&ruleset->filter_newnfqueuetarget, free);
    vrmr_list_setup(&ruleset->filter_estrelnfqueuetarget, free);
    /* NFLog state */
    vrmr_list_setup(&ruleset->filter_newnflogtarget, free);
    vrmr_list_setup(&ruleset->filter_estrelnflogtarget, free);
    /* tcp reset */
    vrmr_list_setup(&ruleset->filter_tcpresettarget, free);
    /* accounting */
    vrmr_list_setup(&ruleset->filter_accounting, free);
    vrmr_list_setup(&accounting_chain_names, free);

    /* shaping */
    vrmr_list_setup(&ruleset->tc_rules, free);
    return (0);
}

/*  cleanup the ruleset

    All lists are cleaned.

    Returns:
        nothing, void function
*/
static void ruleset_cleanup(struct rule_set *ruleset)
{
    assert(ruleset);

    /* raw */
    vrmr_list_cleanup(&ruleset->raw_preroute);
    vrmr_list_cleanup(&ruleset->raw_output);

    /* mangle */
    vrmr_list_cleanup(&ruleset->mangle_preroute);
    vrmr_list_cleanup(&ruleset->mangle_input);
    vrmr_list_cleanup(&ruleset->mangle_forward);
    vrmr_list_cleanup(&ruleset->mangle_output);
    vrmr_list_cleanup(&ruleset->mangle_postroute);

    vrmr_list_cleanup(&ruleset->mangle_shape_in);
    vrmr_list_cleanup(&ruleset->mangle_shape_out);
    vrmr_list_cleanup(&ruleset->mangle_shape_fw);

    /* nat */
    vrmr_list_cleanup(&ruleset->nat_preroute);
    vrmr_list_cleanup(&ruleset->nat_postroute);
    vrmr_list_cleanup(&ruleset->nat_output);

    /* filter */
    vrmr_list_cleanup(&ruleset->filter_input);
    vrmr_list_cleanup(&ruleset->filter_forward);
    vrmr_list_cleanup(&ruleset->filter_output);

    vrmr_list_cleanup(&ruleset->filter_antispoof);
    vrmr_list_cleanup(&ruleset->filter_blocklist);
    vrmr_list_cleanup(&ruleset->filter_blocktarget);
    vrmr_list_cleanup(&ruleset->filter_badtcp);
    vrmr_list_cleanup(&ruleset->filter_synlimittarget);
    vrmr_list_cleanup(&ruleset->filter_udplimittarget);
    vrmr_list_cleanup(&ruleset->filter_newaccepttarget);
    vrmr_list_cleanup(&ruleset->filter_estrelnfqueuetarget);
    vrmr_list_cleanup(&ruleset->filter_newnfqueuetarget);
    vrmr_list_cleanup(&ruleset->filter_estrelnflogtarget);
    vrmr_list_cleanup(&ruleset->filter_newnflogtarget);
    vrmr_list_cleanup(&ruleset->filter_tcpresettarget);

    vrmr_list_cleanup(&ruleset->filter_accounting);
    vrmr_list_cleanup(&accounting_chain_names);

    vrmr_list_cleanup(&ruleset->tc_rules);

    /* clear all memory */
    memset(ruleset, 0, sizeof(struct rule_set));
}

/*

    returncodes:
         1: ok, create
         0: ok, don't create the acc rule
        -1: error
*/
static int ruleset_check_accounting(char *chain)
{
    struct vrmr_list_node *d_node = NULL;
    char chain_found = 0;
    char stripped_chain[33] = "",
         commandline_switch[3] = ""; /* '-A' =2 + '\0' = 1 == 3 */
    struct chain_ref *chainref_ptr = NULL;

    assert(chain);

    /* accouting rule check */
    if (strncmp(chain, "-A ACC-", 7) == 0) {
        /* strip chain from -A */
        sscanf(chain, "%2s %32s", commandline_switch, stripped_chain);
        vrmr_debug(HIGH,
                "chain: '%s', commandline_switch: '%s', stripped_chain '%s'.",
                chain, commandline_switch, stripped_chain);

        /*  okay, this is a accounting rule. Accounting rules have
            dynamic chain names, so lets see if we already know this chain.
        */
        for (d_node = accounting_chain_names.top; d_node;
                d_node = d_node->next) {
            if (!(chainref_ptr = d_node->data)) {
                vrmr_error(-1, "Internal Error", "NULL pointer");
                return (-1);
            }

            if (strcmp(chainref_ptr->chain, stripped_chain) == 0) {
                vrmr_debug(HIGH, "chain '%s' already in the list.",
                        chainref_ptr->chain);

                chain_found = 1;
                break;
            }
        }

        if (!chain_found) {
            vrmr_debug(HIGH, "going to add chain '%s' to the list.",
                    stripped_chain);

            /* okay, lets add the chain name to the list */
            // size = strlen(stripped_chain) + 1;

            /* alloc since the chain name will not be a pointer to a static
             * buffer */
            if (!(chainref_ptr = malloc(sizeof(struct chain_ref)))) {
                vrmr_error(-1, "Error", "malloc failed: %s", strerror(errno));
                return (-1);
            }

            /* copy */
            (void)strlcpy(chainref_ptr->chain, stripped_chain,
                    sizeof(chainref_ptr->chain));
            chainref_ptr->refcnt = 1;

            vrmr_debug(HIGH, "appending chain '%s' to the list.",
                    chainref_ptr->chain);

            /* append to the list */
            if (vrmr_list_append(&accounting_chain_names, chainref_ptr) ==
                    NULL) {
                vrmr_error(
                        -1, "Internal Error", "appending rule to list failed");
                return (-1);
            }
        } else {
            if (chainref_ptr->refcnt > 1) {
                vrmr_debug(HIGH, "already 2 rules created in '%s'.",
                        chainref_ptr->chain);
                return (0);
            } else {
                chainref_ptr->refcnt++;
            }
        }
    }

    return (1);
}

/*  ruleset_add_rule_to_set

    Add a iptables-restore compatible string 'line' to the ruleset.

    Note: this function will alloc the string and copy rule to this
    string.

    Returncodes:
         0: ok
        -1: error
*/
int ruleset_add_rule_to_set(struct vrmr_list *list, char *chain, char *rule,
        uint64_t packets, uint64_t bytes)
{
    size_t size = 0, numbers_size = 0;
    char *line = NULL, numbers[32] = "";
    int result = 0;

    assert(list && chain && rule);

    /* HACK: check for accounting special cases */
    result = ruleset_check_accounting(chain);
    if (result == -1)
        return (-1);
    else if (result == 0)
        return (0);

    /* create the counters */
    if (packets > 0 || bytes > 0) {
        snprintf(numbers, sizeof(numbers), "[%" PRIu64 ":%" PRIu64 "] ",
                packets, bytes);
        numbers_size = strlen(numbers);
    }

    /* size of the numbers string, chain, space, rule */
    size = numbers_size + strlen(chain) + 1 + strlen(rule) + 1;
    if (size == 0) {
        vrmr_error(-1, "Internal Error", "cannot append an empty string");
        return (-1);
    }

    /* alloc the size for line */
    if (!(line = malloc(size))) {
        vrmr_error(-1, "Error", "malloc failed: %s", strerror(errno));
        return (-1);
    }

    /* create the string */
    result = snprintf(line, size, "%s%s %s", numbers, chain, rule);
    if (result >= (int)size) {
        vrmr_error(-1, "Error", "ruleset string overflow (%d >= %d, %s)",
                result, (int)size, rule);
        free(line);
        return (-1);
    }

    /* append to the list */
    if (vrmr_list_append(list, line) == NULL) {
        vrmr_error(-1, "Internal Error", "appending rule to list failed");
        free(line);
        return (-1);
    }

    return (0);
}

/*  ruleset_writeprint

    wrapper around the write call
*/
static int ruleset_writeprint(const int fd, const char *line)
{
    return ((int)write(fd, line, strlen(line)));
}

/* Create the shaping script file */
static int ruleset_fill_shaping_file(struct rule_set *ruleset, int fd)
{
    struct vrmr_list_node *d_node = NULL;
    char *ptr = NULL;
    char cmd[VRMR_MAX_PIPE_COMMAND] = "";

    ruleset_writeprint(fd, "#!/bin/bash\n");

    for (d_node = ruleset->tc_rules.top; d_node; d_node = d_node->next) {
        ptr = d_node->data;

        snprintf(cmd, sizeof(cmd), "%s\n", ptr);
        ruleset_writeprint(fd, cmd);
    }

    ruleset_writeprint(fd, "# EOF\n");

    return (0);
}

/** \internal
 *
 *  \brief Creates the ruleset file to be loaded by iptables-restore
 *
 *  \retval 0 ok
 *  \retval -1 error
 */
static int ruleset_fill_file(struct vrmr_ctx *vctx, struct rule_set *ruleset,
        int ruleset_fd, int ipver)
{
    struct vrmr_list_node *d_node = NULL;
    char *rule = NULL, *cname = NULL;
    char cmd[512] = "";

    assert(ruleset && (ipver == VRMR_IPV4 || ipver == VRMR_IPV6));

    /* get the current chains */
    (void)vrmr_rules_get_system_chains(&vctx->rules, &vctx->conf, ipver);

    snprintf(cmd, sizeof(cmd),
            "# Generated by Vuurmuur %s (c) 2002-2025 Victor Julien\n",
            version_string);
    ruleset_writeprint(ruleset_fd, cmd);
    snprintf(cmd, sizeof(cmd), "# DO NOT EDIT: file will be overwritten.\n");
    ruleset_writeprint(ruleset_fd, cmd);

    if (vctx->conf.vrmr_check_iptcaps == FALSE ||
            (ipver == VRMR_IPV4 && vctx->iptcaps.table_raw == TRUE)
#ifdef IPV6_ENABLED
            || (ipver == VRMR_IPV6 && vctx->iptcaps.table_ip6_raw == TRUE)
#endif
    ) {
        /* first process the mangle table */
        snprintf(cmd, sizeof(cmd), "*raw\n");
        ruleset_writeprint(ruleset_fd, cmd);
        snprintf(cmd, sizeof(cmd), ":PREROUTING %s [0:0]\n",
                ruleset->raw_preroute_policy ? "DROP" : "ACCEPT");
        ruleset_writeprint(ruleset_fd, cmd);
        snprintf(cmd, sizeof(cmd), ":OUTPUT %s [0:0]\n",
                ruleset->raw_output_policy ? "DROP" : "ACCEPT");
        ruleset_writeprint(ruleset_fd, cmd);

        /* PREROUTING */
        for (d_node = ruleset->raw_preroute.top; d_node;
                d_node = d_node->next) {
            if (!(rule = d_node->data)) {
                vrmr_error(-1, "Internal Error", "NULL pointer");
                return (-1);
            }

            snprintf(cmd, sizeof(cmd), "%s\n", rule);
            ruleset_writeprint(ruleset_fd, cmd);
        }
        /* OUTPUT */
        for (d_node = ruleset->raw_output.top; d_node; d_node = d_node->next) {
            if (!(rule = d_node->data)) {
                vrmr_error(-1, "Internal Error", "NULL pointer");
                return (-1);
            }

            snprintf(cmd, sizeof(cmd), "%s\n", rule);
            ruleset_writeprint(ruleset_fd, cmd);
        }

        snprintf(cmd, sizeof(cmd), "COMMIT\n");
        ruleset_writeprint(ruleset_fd, cmd);
    }

    if (vctx->conf.vrmr_check_iptcaps == FALSE ||
            vctx->iptcaps.table_mangle == TRUE) {
        /* first process the mangle table */
        snprintf(cmd, sizeof(cmd), "*mangle\n");
        ruleset_writeprint(ruleset_fd, cmd);
        snprintf(cmd, sizeof(cmd), ":PREROUTING %s [0:0]\n",
                ruleset->mangle_preroute_policy ? "DROP" : "ACCEPT");
        ruleset_writeprint(ruleset_fd, cmd);
        snprintf(cmd, sizeof(cmd), ":INPUT %s [0:0]\n",
                ruleset->mangle_input_policy ? "DROP" : "ACCEPT");
        ruleset_writeprint(ruleset_fd, cmd);
        snprintf(cmd, sizeof(cmd), ":FORWARD %s [0:0]\n",
                ruleset->mangle_forward_policy ? "DROP" : "ACCEPT");
        ruleset_writeprint(ruleset_fd, cmd);
        snprintf(cmd, sizeof(cmd), ":OUTPUT %s [0:0]\n",
                ruleset->mangle_output_policy ? "DROP" : "ACCEPT");
        ruleset_writeprint(ruleset_fd, cmd);
        snprintf(cmd, sizeof(cmd), ":POSTROUTING %s [0:0]\n",
                ruleset->mangle_postroute_policy ? "DROP" : "ACCEPT");
        ruleset_writeprint(ruleset_fd, cmd);

        /*
            BEGIN -- PRE-VUURMUUR-CHAINS feature - by(as).
            Allow to make some specials rules before the Vuurmuur rules kick in.

            Only create if they don't exist.
            No flushing, the content of these chains is the responsibility of
           the user.
        */

        /* mangle table uses {PREROUTING,INPUT,FORWARD,POSTROUTING,OUTPUT} hooks
         */

        if (!vrmr_rules_chain_in_list(
                    &vctx->rules.system_chain_mangle, "PRE-VRMR-PREROUTING")) {
            snprintf(cmd, sizeof(cmd), "--new PRE-VRMR-PREROUTING\n");
            ruleset_writeprint(ruleset_fd, cmd);
        }
        if (!vrmr_rules_chain_in_list(
                    &vctx->rules.system_chain_mangle, "PRE-VRMR-INPUT")) {
            snprintf(cmd, sizeof(cmd), "--new PRE-VRMR-INPUT\n");
            ruleset_writeprint(ruleset_fd, cmd);
        }
        if (!vrmr_rules_chain_in_list(
                    &vctx->rules.system_chain_mangle, "PRE-VRMR-FORWARD")) {
            snprintf(cmd, sizeof(cmd), "--new PRE-VRMR-FORWARD\n");
            ruleset_writeprint(ruleset_fd, cmd);
        }
        if (!vrmr_rules_chain_in_list(
                    &vctx->rules.system_chain_mangle, "PRE-VRMR-POSTROUTING")) {
            snprintf(cmd, sizeof(cmd), "--new PRE-VRMR-POSTROUTING\n");
            ruleset_writeprint(ruleset_fd, cmd);
        }
        if (!vrmr_rules_chain_in_list(
                    &vctx->rules.system_chain_mangle, "PRE-VRMR-OUTPUT")) {
            snprintf(cmd, sizeof(cmd), "--new PRE-VRMR-OUTPUT\n");
            ruleset_writeprint(ruleset_fd, cmd);
        }

        /* END -- PRE-VUURMUUR-CHAINS feature - by(as). */

        snprintf(cmd, sizeof(cmd), "--flush PREROUTING\n");
        ruleset_writeprint(ruleset_fd, cmd);
        snprintf(cmd, sizeof(cmd), "--flush INPUT\n");
        ruleset_writeprint(ruleset_fd, cmd);
        snprintf(cmd, sizeof(cmd), "--flush FORWARD\n");
        ruleset_writeprint(ruleset_fd, cmd);
        snprintf(cmd, sizeof(cmd), "--flush OUTPUT\n");
        ruleset_writeprint(ruleset_fd, cmd);
        snprintf(cmd, sizeof(cmd), "--flush POSTROUTING\n");
        ruleset_writeprint(ruleset_fd, cmd);

        if (ipver == VRMR_IPV4) {
            /* SHAPE IN */
            if (vrmr_rules_chain_in_list(
                        &vctx->rules.system_chain_mangle, "SHAPEIN")) {
                snprintf(cmd, sizeof(cmd), "--flush SHAPEIN\n");
                ruleset_writeprint(ruleset_fd, cmd);
                snprintf(cmd, sizeof(cmd), "--delete-chain SHAPEIN\n");
                ruleset_writeprint(ruleset_fd, cmd);
            }
            snprintf(cmd, sizeof(cmd), "--new SHAPEIN\n");
            ruleset_writeprint(ruleset_fd, cmd);

            /* SHAPE OUT */
            if (vrmr_rules_chain_in_list(
                        &vctx->rules.system_chain_mangle, "SHAPEOUT")) {
                snprintf(cmd, sizeof(cmd), "--flush SHAPEOUT\n");
                ruleset_writeprint(ruleset_fd, cmd);
                snprintf(cmd, sizeof(cmd), "--delete-chain SHAPEOUT\n");
                ruleset_writeprint(ruleset_fd, cmd);
            }
            snprintf(cmd, sizeof(cmd), "--new SHAPEOUT\n");
            ruleset_writeprint(ruleset_fd, cmd);

            /* SHAPE FW */
            if (vrmr_rules_chain_in_list(
                        &vctx->rules.system_chain_mangle, "SHAPEFW")) {
                snprintf(cmd, sizeof(cmd), "--flush SHAPEFW\n");
                ruleset_writeprint(ruleset_fd, cmd);
                snprintf(cmd, sizeof(cmd), "--delete-chain SHAPEFW\n");
                ruleset_writeprint(ruleset_fd, cmd);
            }
            snprintf(cmd, sizeof(cmd), "--new SHAPEFW\n");
            ruleset_writeprint(ruleset_fd, cmd);
        }

        /* prerouting */
        for (d_node = ruleset->mangle_preroute.top; d_node;
                d_node = d_node->next) {
            if (!(rule = d_node->data)) {
                vrmr_error(-1, "Internal Error", "NULL pointer");
                return (-1);
            }

            snprintf(cmd, sizeof(cmd), "%s\n", rule);
            ruleset_writeprint(ruleset_fd, cmd);
        }
        /* input */
        for (d_node = ruleset->mangle_input.top; d_node;
                d_node = d_node->next) {
            if (!(rule = d_node->data)) {
                vrmr_error(-1, "Internal Error", "NULL pointer");
                return (-1);
            }

            snprintf(cmd, sizeof(cmd), "%s\n", rule);
            ruleset_writeprint(ruleset_fd, cmd);
        }
        /* forward */
        for (d_node = ruleset->mangle_forward.top; d_node;
                d_node = d_node->next) {
            if (!(rule = d_node->data)) {
                vrmr_error(-1, "Internal Error", "NULL pointer");
                return (-1);
            }

            snprintf(cmd, sizeof(cmd), "%s\n", rule);
            ruleset_writeprint(ruleset_fd, cmd);
        }
        /* output */
        for (d_node = ruleset->mangle_output.top; d_node;
                d_node = d_node->next) {
            if (!(rule = d_node->data)) {
                vrmr_error(-1, "Internal Error", "NULL pointer");
                return (-1);
            }

            snprintf(cmd, sizeof(cmd), "%s\n", rule);
            ruleset_writeprint(ruleset_fd, cmd);
        }
        /* postrouting */
        for (d_node = ruleset->mangle_postroute.top; d_node;
                d_node = d_node->next) {
            if (!(rule = d_node->data)) {
                vrmr_error(-1, "Internal Error", "NULL pointer");
                return (-1);
            }

            snprintf(cmd, sizeof(cmd), "%s\n", rule);
            ruleset_writeprint(ruleset_fd, cmd);
        }

        if (ipver == VRMR_IPV4) {
            /* shape in */
            for (d_node = ruleset->mangle_shape_in.top; d_node;
                    d_node = d_node->next) {
                if (!(rule = d_node->data)) {
                    vrmr_error(-1, "Internal Error", "NULL pointer");
                    return (-1);
                }

                snprintf(cmd, sizeof(cmd), "%s\n", rule);
                ruleset_writeprint(ruleset_fd, cmd);
            }

            /* shape out */
            for (d_node = ruleset->mangle_shape_out.top; d_node;
                    d_node = d_node->next) {
                if (!(rule = d_node->data)) {
                    vrmr_error(-1, "Internal Error", "NULL pointer");
                    return (-1);
                }

                snprintf(cmd, sizeof(cmd), "%s\n", rule);
                ruleset_writeprint(ruleset_fd, cmd);
            }

            /* shape fw */
            for (d_node = ruleset->mangle_shape_fw.top; d_node;
                    d_node = d_node->next) {
                if (!(rule = d_node->data)) {
                    vrmr_error(-1, "Internal Error", "NULL pointer");
                    return (-1);
                }

                snprintf(cmd, sizeof(cmd), "%s\n", rule);
                ruleset_writeprint(ruleset_fd, cmd);
            }
        }
        snprintf(cmd, sizeof(cmd), "COMMIT\n");
        ruleset_writeprint(ruleset_fd, cmd);
    }

    if (ipver == VRMR_IPV4 && (vctx->conf.vrmr_check_iptcaps == FALSE ||
                                      vctx->iptcaps.table_nat == TRUE)) {
        /* nat table */
        snprintf(cmd, sizeof(cmd), "*nat\n");
        ruleset_writeprint(ruleset_fd, cmd);
        snprintf(cmd, sizeof(cmd), ":PREROUTING %s [0:0]\n",
                ruleset->nat_preroute_policy ? "DROP" : "ACCEPT");
        ruleset_writeprint(ruleset_fd, cmd);
        snprintf(cmd, sizeof(cmd), ":OUTPUT %s [0:0]\n",
                ruleset->nat_output_policy ? "DROP" : "ACCEPT");
        ruleset_writeprint(ruleset_fd, cmd);
        snprintf(cmd, sizeof(cmd), ":POSTROUTING %s [0:0]\n",
                ruleset->nat_postroute_policy ? "DROP" : "ACCEPT");
        ruleset_writeprint(ruleset_fd, cmd);

        /*
            BEGIN -- PRE-VUURMUUR-CHAINS feature - by(as).
            Allow to make some specials rules before the Vuurmuur rules kick in.

            Only create if they don't exist.
            No flushing, the content of these chains is the responsibility of
           the user.
        */

        /* nat table uses {PREROUTING,POSTROUTING,OUTPUT} hooks */

        if (!vrmr_rules_chain_in_list(
                    &vctx->rules.system_chain_nat, "PRE-VRMR-PREROUTING")) {
            snprintf(cmd, sizeof(cmd), "--new PRE-VRMR-PREROUTING\n");
            ruleset_writeprint(ruleset_fd, cmd);
        }
        if (!vrmr_rules_chain_in_list(
                    &vctx->rules.system_chain_nat, "PRE-VRMR-POSTROUTING")) {
            snprintf(cmd, sizeof(cmd), "--new PRE-VRMR-POSTROUTING\n");
            ruleset_writeprint(ruleset_fd, cmd);
        }
        if (!vrmr_rules_chain_in_list(
                    &vctx->rules.system_chain_nat, "PRE-VRMR-OUTPUT")) {
            snprintf(cmd, sizeof(cmd), "--new PRE-VRMR-OUTPUT\n");
            ruleset_writeprint(ruleset_fd, cmd);
        }

        /* END -- PRE-VUURMUUR-CHAINS feature - by(as). */

        snprintf(cmd, sizeof(cmd), "--flush PREROUTING\n");
        ruleset_writeprint(ruleset_fd, cmd);
        snprintf(cmd, sizeof(cmd), "--flush OUTPUT\n");
        ruleset_writeprint(ruleset_fd, cmd);
        snprintf(cmd, sizeof(cmd), "--flush POSTROUTING\n");
        ruleset_writeprint(ruleset_fd, cmd);

        /* prerouting */
        for (d_node = ruleset->nat_preroute.top; d_node;
                d_node = d_node->next) {
            if (!(rule = d_node->data)) {
                vrmr_error(-1, "Internal Error", "NULL pointer");
                return (-1);
            }

            snprintf(cmd, sizeof(cmd), "%s\n", rule);
            ruleset_writeprint(ruleset_fd, cmd);
        }
        /* output */
        for (d_node = ruleset->nat_output.top; d_node; d_node = d_node->next) {
            if (!(rule = d_node->data)) {
                vrmr_error(-1, "Internal Error", "NULL pointer");
                return (-1);
            }

            snprintf(cmd, sizeof(cmd), "%s\n", rule);
            ruleset_writeprint(ruleset_fd, cmd);
        }
        /* postrouting */
        for (d_node = ruleset->nat_postroute.top; d_node;
                d_node = d_node->next) {
            if (!(rule = d_node->data)) {
                vrmr_error(-1, "Internal Error", "NULL pointer");
                return (-1);
            }

            snprintf(cmd, sizeof(cmd), "%s\n", rule);
            ruleset_writeprint(ruleset_fd, cmd);
        }

        snprintf(cmd, sizeof(cmd), "COMMIT\n");
        ruleset_writeprint(ruleset_fd, cmd);
    }

    if (vctx->conf.vrmr_check_iptcaps == FALSE ||
            vctx->iptcaps.table_filter == TRUE) {
        /* finally the filter table */
        snprintf(cmd, sizeof(cmd), "*filter\n");
        ruleset_writeprint(ruleset_fd, cmd);
        snprintf(cmd, sizeof(cmd), ":INPUT %s [0:0]\n",
                ruleset->filter_input_policy ? "DROP" : "ACCEPT");
        ruleset_writeprint(ruleset_fd, cmd);
        snprintf(cmd, sizeof(cmd), ":FORWARD %s [0:0]\n",
                ruleset->filter_forward_policy ? "DROP" : "ACCEPT");
        ruleset_writeprint(ruleset_fd, cmd);
        snprintf(cmd, sizeof(cmd), ":OUTPUT %s [0:0]\n",
                ruleset->filter_output_policy ? "DROP" : "ACCEPT");
        ruleset_writeprint(ruleset_fd, cmd);

        snprintf(cmd, sizeof(cmd), "--flush INPUT\n");
        ruleset_writeprint(ruleset_fd, cmd);
        snprintf(cmd, sizeof(cmd), "--flush FORWARD\n");
        ruleset_writeprint(ruleset_fd, cmd);
        snprintf(cmd, sizeof(cmd), "--flush OUTPUT\n");
        ruleset_writeprint(ruleset_fd, cmd);

        /*
            Allow to make some specials rules before the Vuurmuur rules kick in.

            Only create if they don't exist. No flushing, the content of these
            chains is the responsibility of the user.
        */

        /* filter table uses {INPUT,FORWARD,OUTPUT} hooks */

        if (!vrmr_rules_chain_in_list(
                    &vctx->rules.system_chain_filter, "PRE-VRMR-INPUT")) {
            snprintf(cmd, sizeof(cmd), "--new PRE-VRMR-INPUT\n");
            ruleset_writeprint(ruleset_fd, cmd);
        }
        if (!vrmr_rules_chain_in_list(
                    &vctx->rules.system_chain_filter, "PRE-VRMR-FORWARD")) {
            snprintf(cmd, sizeof(cmd), "--new PRE-VRMR-FORWARD\n");
            ruleset_writeprint(ruleset_fd, cmd);
        }
        if (!vrmr_rules_chain_in_list(
                    &vctx->rules.system_chain_filter, "PRE-VRMR-OUTPUT")) {
            snprintf(cmd, sizeof(cmd), "--new PRE-VRMR-OUTPUT\n");
            ruleset_writeprint(ruleset_fd, cmd);
        }

        /* create the custom chains, because some rules will depend on them */
        for (d_node = vctx->rules.custom_chain_list.top; d_node;
                d_node = d_node->next) {
            if (!(cname = d_node->data)) {
                vrmr_error(-1, "Internal Error", "NULL pointer");
                return (-1);
            }

            if (!vrmr_rules_chain_in_list(
                        &vctx->rules.system_chain_filter, cname)) {
                snprintf(cmd, sizeof(cmd), "--new %s\n", cname);
                ruleset_writeprint(ruleset_fd, cmd);
            }
        }

        if (vrmr_rules_chain_in_list(
                    &vctx->rules.system_chain_filter, "ANTISPOOF")) {
            snprintf(cmd, sizeof(cmd), "--flush ANTISPOOF\n");
            ruleset_writeprint(ruleset_fd, cmd);
            snprintf(cmd, sizeof(cmd), "--delete-chain ANTISPOOF\n");
            ruleset_writeprint(ruleset_fd, cmd);
        }
        snprintf(cmd, sizeof(cmd), "--new ANTISPOOF\n");
        ruleset_writeprint(ruleset_fd, cmd);

        if (vrmr_rules_chain_in_list(
                    &vctx->rules.system_chain_filter, "BLOCKLIST")) {
            snprintf(cmd, sizeof(cmd), "--flush BLOCKLIST\n");
            ruleset_writeprint(ruleset_fd, cmd);
            snprintf(cmd, sizeof(cmd), "--delete-chain BLOCKLIST\n");
            ruleset_writeprint(ruleset_fd, cmd);
        }
        snprintf(cmd, sizeof(cmd), "--new BLOCKLIST\n");
        ruleset_writeprint(ruleset_fd, cmd);

        if (vrmr_rules_chain_in_list(
                    &vctx->rules.system_chain_filter, "BLOCK")) {
            snprintf(cmd, sizeof(cmd), "--flush BLOCK\n");
            ruleset_writeprint(ruleset_fd, cmd);
            snprintf(cmd, sizeof(cmd), "--delete-chain BLOCK\n");
            ruleset_writeprint(ruleset_fd, cmd);
        }
        snprintf(cmd, sizeof(cmd), "--new BLOCK\n");
        ruleset_writeprint(ruleset_fd, cmd);

        /* do NEWACCEPT and NEWQUEUE before SYNLIMIT and UDPLIMIT */
        if (vrmr_rules_chain_in_list(
                    &vctx->rules.system_chain_filter, "NEWACCEPT")) {
            snprintf(cmd, sizeof(cmd), "--flush NEWACCEPT\n");
            ruleset_writeprint(ruleset_fd, cmd);
            snprintf(cmd, sizeof(cmd), "--delete-chain NEWACCEPT\n");
            ruleset_writeprint(ruleset_fd, cmd);
        }
        snprintf(cmd, sizeof(cmd), "--new NEWACCEPT\n");
        ruleset_writeprint(ruleset_fd, cmd);

        if (vrmr_rules_chain_in_list(
                    &vctx->rules.system_chain_filter, "NEWQUEUE")) {
            snprintf(cmd, sizeof(cmd), "--flush NEWQUEUE\n");
            ruleset_writeprint(ruleset_fd, cmd);
            snprintf(cmd, sizeof(cmd), "--delete-chain NEWQUEUE\n");
            ruleset_writeprint(ruleset_fd, cmd);
        }
        snprintf(cmd, sizeof(cmd), "--new NEWQUEUE\n");
        ruleset_writeprint(ruleset_fd, cmd);

        /* Do this before NEWNFQUEUE because it references
         * to it. */
        if (vrmr_rules_chain_in_list(
                    &vctx->rules.system_chain_filter, "ESTRELNFQUEUE")) {
            snprintf(cmd, sizeof(cmd), "--flush ESTRELNFQUEUE\n");
            ruleset_writeprint(ruleset_fd, cmd);
            snprintf(cmd, sizeof(cmd), "--delete-chain ESTRELNFQUEUE\n");
            ruleset_writeprint(ruleset_fd, cmd);
        }
        snprintf(cmd, sizeof(cmd), "--new ESTRELNFQUEUE\n");
        ruleset_writeprint(ruleset_fd, cmd);

        if (vrmr_rules_chain_in_list(
                    &vctx->rules.system_chain_filter, "NEWNFQUEUE")) {
            snprintf(cmd, sizeof(cmd), "--flush NEWNFQUEUE\n");
            ruleset_writeprint(ruleset_fd, cmd);
            snprintf(cmd, sizeof(cmd), "--delete-chain NEWNFQUEUE\n");
            ruleset_writeprint(ruleset_fd, cmd);
        }
        snprintf(cmd, sizeof(cmd), "--new NEWNFQUEUE\n");
        ruleset_writeprint(ruleset_fd, cmd);

        /* Do this before NEWNFLOG because it references
         * to it. */
        if (vrmr_rules_chain_in_list(
                    &vctx->rules.system_chain_filter, "ESTRELNFLOG")) {
            snprintf(cmd, sizeof(cmd), "--flush ESTRELNFLOG\n");
            ruleset_writeprint(ruleset_fd, cmd);
            snprintf(cmd, sizeof(cmd), "--delete-chain ESTRELNFLOG\n");
            ruleset_writeprint(ruleset_fd, cmd);
        }
        snprintf(cmd, sizeof(cmd), "--new ESTRELNFLOG\n");
        ruleset_writeprint(ruleset_fd, cmd);

        if (vrmr_rules_chain_in_list(
                    &vctx->rules.system_chain_filter, "NEWNFLOG")) {
            snprintf(cmd, sizeof(cmd), "--flush NEWNFLOG\n");
            ruleset_writeprint(ruleset_fd, cmd);
            snprintf(cmd, sizeof(cmd), "--delete-chain NEWNFLOG\n");
            ruleset_writeprint(ruleset_fd, cmd);
        }
        snprintf(cmd, sizeof(cmd), "--new NEWNFLOG\n");
        ruleset_writeprint(ruleset_fd, cmd);

        if (vrmr_rules_chain_in_list(
                    &vctx->rules.system_chain_filter, "SYNLIMIT")) {
            snprintf(cmd, sizeof(cmd), "--flush SYNLIMIT\n");
            ruleset_writeprint(ruleset_fd, cmd);
            snprintf(cmd, sizeof(cmd), "--delete-chain SYNLIMIT\n");
            ruleset_writeprint(ruleset_fd, cmd);
        }
        snprintf(cmd, sizeof(cmd), "--new SYNLIMIT\n");
        ruleset_writeprint(ruleset_fd, cmd);

        if (vrmr_rules_chain_in_list(
                    &vctx->rules.system_chain_filter, "UDPLIMIT")) {
            snprintf(cmd, sizeof(cmd), "--flush UDPLIMIT\n");
            ruleset_writeprint(ruleset_fd, cmd);
            snprintf(cmd, sizeof(cmd), "--delete-chain UDPLIMIT\n");
            ruleset_writeprint(ruleset_fd, cmd);
        }
        snprintf(cmd, sizeof(cmd), "--new UDPLIMIT\n");
        ruleset_writeprint(ruleset_fd, cmd);

        if (vrmr_rules_chain_in_list(
                    &vctx->rules.system_chain_filter, "TCPRESET")) {
            snprintf(cmd, sizeof(cmd), "--flush TCPRESET\n");
            ruleset_writeprint(ruleset_fd, cmd);
            snprintf(cmd, sizeof(cmd), "--delete-chain TCPRESET\n");
            ruleset_writeprint(ruleset_fd, cmd);
        }
        snprintf(cmd, sizeof(cmd), "--new TCPRESET\n");
        ruleset_writeprint(ruleset_fd, cmd);

        /* finally the accounting chains */
        for (d_node = accounting_chain_names.top; d_node;
                d_node = d_node->next) {
            if (!(cname = d_node->data)) {
                vrmr_error(-1, "Internal Error", "NULL pointer");
                return (-1);
            }

            if (vrmr_rules_chain_in_list(
                        &vctx->rules.system_chain_filter, cname)) {
                snprintf(cmd, sizeof(cmd), "--flush %s\n", cname);
                ruleset_writeprint(ruleset_fd, cmd);
                snprintf(cmd, sizeof(cmd), "--delete-chain %s\n", cname);
                ruleset_writeprint(ruleset_fd, cmd);
            }
            snprintf(cmd, sizeof(cmd), "--new %s\n", cname);
            ruleset_writeprint(ruleset_fd, cmd);
        }

        /* input */
        for (d_node = ruleset->filter_input.top; d_node;
                d_node = d_node->next) {
            if (!(rule = d_node->data)) {
                vrmr_error(-1, "Internal Error", "NULL pointer");
                return (-1);
            }

            snprintf(cmd, sizeof(cmd), "%s\n", rule);
            ruleset_writeprint(ruleset_fd, cmd);
        }
        /* forward */
        for (d_node = ruleset->filter_forward.top; d_node;
                d_node = d_node->next) {
            if (!(rule = d_node->data)) {
                vrmr_error(-1, "Internal Error", "NULL pointer");
                return (-1);
            }

            snprintf(cmd, sizeof(cmd), "%s\n", rule);
            ruleset_writeprint(ruleset_fd, cmd);
        }
        /* output */
        for (d_node = ruleset->filter_output.top; d_node;
                d_node = d_node->next) {
            if (!(rule = d_node->data)) {
                vrmr_error(-1, "Internal Error", "NULL pointer");
                return (-1);
            }

            snprintf(cmd, sizeof(cmd), "%s\n", rule);
            ruleset_writeprint(ruleset_fd, cmd);
        }

        /* antispoof */
        for (d_node = ruleset->filter_antispoof.top; d_node;
                d_node = d_node->next) {
            if (!(rule = d_node->data)) {
                vrmr_error(-1, "Internal Error", "NULL pointer");
                return (-1);
            }

            snprintf(cmd, sizeof(cmd), "%s\n", rule);
            ruleset_writeprint(ruleset_fd, cmd);
        }
        /* blocklist */
        for (d_node = ruleset->filter_blocklist.top; d_node;
                d_node = d_node->next) {
            if (!(rule = d_node->data)) {
                vrmr_error(-1, "Internal Error", "NULL pointer");
                return (-1);
            }

            snprintf(cmd, sizeof(cmd), "%s\n", rule);
            ruleset_writeprint(ruleset_fd, cmd);
        }
        /* block */
        for (d_node = ruleset->filter_blocktarget.top; d_node;
                d_node = d_node->next) {
            if (!(rule = d_node->data)) {
                vrmr_error(-1, "Internal Error", "NULL pointer");
                return (-1);
            }

            snprintf(cmd, sizeof(cmd), "%s\n", rule);
            ruleset_writeprint(ruleset_fd, cmd);
        }
        /* synlimit */
        for (d_node = ruleset->filter_synlimittarget.top; d_node;
                d_node = d_node->next) {
            if (!(rule = d_node->data)) {
                vrmr_error(-1, "Internal Error", "NULL pointer");
                return (-1);
            }

            snprintf(cmd, sizeof(cmd), "%s\n", rule);
            ruleset_writeprint(ruleset_fd, cmd);
        }
        /* udplimit */
        for (d_node = ruleset->filter_udplimittarget.top; d_node;
                d_node = d_node->next) {
            if (!(rule = d_node->data)) {
                vrmr_error(-1, "Internal Error", "NULL pointer");
                return (-1);
            }

            snprintf(cmd, sizeof(cmd), "%s\n", rule);
            ruleset_writeprint(ruleset_fd, cmd);
        }
        /* newaccept */
        for (d_node = ruleset->filter_newaccepttarget.top; d_node;
                d_node = d_node->next) {
            if (!(rule = d_node->data)) {
                vrmr_error(-1, "Internal Error", "NULL pointer");
                return (-1);
            }

            snprintf(cmd, sizeof(cmd), "%s\n", rule);
            ruleset_writeprint(ruleset_fd, cmd);
        }
        /* newnfqueue */
        for (d_node = ruleset->filter_newnfqueuetarget.top; d_node;
                d_node = d_node->next) {
            if (!(rule = d_node->data)) {
                vrmr_error(-1, "Internal Error", "NULL pointer");
                return (-1);
            }

            snprintf(cmd, sizeof(cmd), "%s\n", rule);
            ruleset_writeprint(ruleset_fd, cmd);
        }
        /* estrelnfqueue */
        for (d_node = ruleset->filter_estrelnfqueuetarget.top; d_node;
                d_node = d_node->next) {
            if (!(rule = d_node->data)) {
                vrmr_error(-1, "Internal Error", "NULL pointer");
                return (-1);
            }

            snprintf(cmd, sizeof(cmd), "%s\n", rule);
            ruleset_writeprint(ruleset_fd, cmd);
        }
        /* newnflog */
        for (d_node = ruleset->filter_newnflogtarget.top; d_node;
                d_node = d_node->next) {
            if (!(rule = d_node->data)) {
                vrmr_error(-1, "Internal Error", "NULL pointer");
                return (-1);
            }

            snprintf(cmd, sizeof(cmd), "%s\n", rule);
            ruleset_writeprint(ruleset_fd, cmd);
        }
        /* estrelnflog */
        for (d_node = ruleset->filter_estrelnflogtarget.top; d_node;
                d_node = d_node->next) {
            if (!(rule = d_node->data)) {
                vrmr_error(-1, "Internal Error", "NULL pointer");
                return (-1);
            }

            snprintf(cmd, sizeof(cmd), "%s\n", rule);
            ruleset_writeprint(ruleset_fd, cmd);
        }

        /* tcpreset */
        for (d_node = ruleset->filter_tcpresettarget.top; d_node;
                d_node = d_node->next) {
            if (!(rule = d_node->data)) {
                vrmr_error(-1, "Internal Error", "NULL pointer");
                return (-1);
            }

            snprintf(cmd, sizeof(cmd), "%s\n", rule);
            ruleset_writeprint(ruleset_fd, cmd);
        }

        /* accounting */
        for (d_node = ruleset->filter_accounting.top; d_node;
                d_node = d_node->next) {
            if (!(rule = d_node->data)) {
                vrmr_error(-1, "Internal Error", "NULL pointer");
                return (-1);
            }

            snprintf(cmd, sizeof(cmd), "%s\n", rule);
            ruleset_writeprint(ruleset_fd, cmd);
        }

        snprintf(cmd, sizeof(cmd), "COMMIT\n");
        ruleset_writeprint(ruleset_fd, cmd);
    }

    snprintf(cmd, sizeof(cmd), "# Completed\n");
    ruleset_writeprint(ruleset_fd, cmd);

    /* list of chains in the system */
    vrmr_list_cleanup(&vctx->rules.system_chain_filter);
    vrmr_list_cleanup(&vctx->rules.system_chain_mangle);
    vrmr_list_cleanup(&vctx->rules.system_chain_nat);
    // vrmr_list_cleanup(&rules->system_chain_raw);

    return (0);
}

/*  ruleset_load_ruleset

    Actually loads the ruleset

    Returncodes:
        -1: error
         0: ok
*/
static int ruleset_load_ruleset(char *path_to_ruleset, char *path_to_resultfile,
        struct vrmr_config *cnf, int ipver)
{
    char cmd[256] = "";

    assert(path_to_ruleset && cnf);

    /*
        final checks on the file
    */

    /* vrmr_stat_ok */
    if (!(vrmr_stat_ok(cnf, path_to_ruleset, VRMR_STATOK_WANT_FILE,
                VRMR_STATOK_VERBOSE, VRMR_STATOK_MUST_EXIST))) {
        vrmr_error(-1, "Error", "serious file problem");
        return (-1);
    }

    /*
        create and execute the command
    */
    if (ipver == VRMR_IPV4) {
        if (snprintf(cmd, sizeof(cmd), "%s  --counters --noflush < %s 2>> %s",
                    cnf->iptablesrestore_location, path_to_ruleset,
                    path_to_resultfile) >= (int)sizeof(cmd)) {
            vrmr_error(-1, "Error", "command string overflow");
            return (-1);
        }
    } else if (ipver == VRMR_IPV6) {
#ifdef IPV6_ENABLED
        if (snprintf(cmd, sizeof(cmd), "%s  --counters --noflush < %s 2>> %s",
                    cnf->ip6tablesrestore_location, path_to_ruleset,
                    path_to_resultfile) >= (int)sizeof(cmd)) {
            vrmr_error(-1, "Error", "command string overflow");
            return (-1);
        }
#endif
    }

    /* all good so far, lets load the ruleset */
    if (vrmr_pipe_command(cnf, cmd, VRMR_PIPE_VERBOSE) < 0) {
        vrmr_error(-1, "Error", "loading the ruleset failed");
        return (-1);
    }

    return (0);
}

/*  ruleset_load_shape_ruleset

    Actually loads the shape ruleset

    Returncodes:
        -1: error
         0: ok
*/
static int ruleset_load_shape_ruleset(char *path_to_ruleset,
        char *path_to_resultfile, struct vrmr_config *cnf)
{
    char cmd[256] = "";

    assert(path_to_ruleset && cnf);

    /*
        final checks on the file
    */

    /* vrmr_stat_ok */
    if (!(vrmr_stat_ok(cnf, path_to_ruleset, VRMR_STATOK_WANT_FILE,
                VRMR_STATOK_VERBOSE, VRMR_STATOK_MUST_EXIST))) {
        vrmr_error(-1, "Error", "serious file problem");
        return (-1);
    }

    /*
        create and execute the REAL command
    */

    /* */
    if (snprintf(cmd, sizeof(cmd), "/bin/bash %s 2>> %s", path_to_ruleset,
                path_to_resultfile) >= (int)sizeof(cmd)) {
        vrmr_error(-1, "Error", "command string overflow");
        return (-1);
    }

    /* all good so far, lets load the ruleset */
    if (vrmr_pipe_command(cnf, cmd, VRMR_PIPE_VERBOSE) < 0) {
        vrmr_error(-1, "Error", "loading the shape ruleset failed");
        return (-1);
    }

    return (0);
}

/*  ruleset_create_ruleset

    fills the ruleset structure

    Returncodes:
         0: ok
        -1: error
*/
static int ruleset_create_ruleset(
        struct vrmr_ctx *vctx, struct rule_set *ruleset)
{
    int result = 0;
    char forward_rules = 0;

    /* create shaping setup */
    if (shaping_clear_interfaces(&vctx->conf, &vctx->interfaces, ruleset) < 0) {
        vrmr_error(-1, "Error", "setting up interface shaping clearing failed");
        return (-1);
    }
    if (shaping_setup_roots(&vctx->conf, &vctx->interfaces, ruleset) < 0) {
        vrmr_error(-1, "Error", "setting up interface shaping roots failed");
        return (-1);
    }
    if (shaping_create_default_rules(&vctx->conf, &vctx->interfaces, ruleset) <
            0) {
        vrmr_error(-1, "Error", "setting up interface default rules failed");
        return (-1);
    }

    vrmr_info("Info", "Creating the rules... (rules to create: %d)",
            vctx->rules.list.len);

    /* create the prerules if were called with it */
    result = pre_rules(&vctx->conf, ruleset, &vctx->interfaces, &vctx->iptcaps);
    if (result < 0) {
        vrmr_error(-1, "Error", "create pre-rules failed.");
        return (-1);
    }

    /* create NEWNFQUEUE target */
    if (create_newnfqueue_rules(&vctx->conf, ruleset, &vctx->rules,
                &vctx->iptcaps, ruleset->ipv) < 0) {
        vrmr_error(-1, "Error", "create newnfqueue failed.");
    }
    /* NFQUEUE related established */
    if (create_estrelnfqueue_rules(&vctx->conf, ruleset, &vctx->rules,
                &vctx->iptcaps, ruleset->ipv) < 0) {
        vrmr_error(-1, "Error", "create estrelnfqueue failed.");
    }

    /* create NEWNFLOG target */
    if (create_newnflog_rules(&vctx->conf, ruleset, &vctx->rules,
                &vctx->iptcaps, ruleset->ipv) < 0) {
        vrmr_error(-1, "Error", "create newnflog failed.");
    }
    /* NFLOG related established */
    if (create_estrelnflog_rules(&vctx->conf, ruleset, &vctx->rules,
                &vctx->iptcaps, ruleset->ipv) < 0) {
        vrmr_error(-1, "Error", "create estrelnflog failed.");
    }

    /* create the blocklist */
    if (create_block_rules(&vctx->conf, ruleset, &vctx->blocklist) < 0) {
        vrmr_error(-1, "Error", "create blocklist failed.");
    }

    /* create the interface rules */
    if (create_interface_rules(
                &vctx->conf, ruleset, &vctx->iptcaps, &vctx->interfaces) < 0) {
        vrmr_error(-1, "Error", "create protectrules failed.");
    }
    /* create the network protect rules (anti-spoofing) */
    if (create_network_protect_rules(
                &vctx->conf, ruleset, &vctx->zones, &vctx->iptcaps) < 0) {
        vrmr_error(-1, "Error", "create protectrules failed.");
    }
    /* system protect rules (proc) */
    if (create_system_protectrules(&vctx->conf) < 0) {
        vrmr_error(-1, "Error", "create protectrules failed.");
    }
    /* normal rules, ruleset == NULL */
    if (create_normal_rules(vctx, ruleset, &forward_rules) < 0) {
        vrmr_error(-1, "Error", "create normal rules failed.");
    }

    /* post rules: enable logging */
    if (post_rules(&vctx->conf, ruleset, &vctx->iptcaps, forward_rules,
                ruleset->ipv) < 0)
        return (-1);

    vrmr_info("Info", "Creating rules finished.");
    return (0);
}

static int ruleset_save_interface_counters(
        struct vrmr_config *cfg, struct vrmr_interfaces *interfaces)
{
    struct vrmr_list_node *d_node = NULL;
    struct vrmr_interface *iface_ptr = NULL;
    uint64_t tmp = 0;
    char acc_chain[32] = "";

    assert(interfaces);

    /* loop through the interfaces */
    for (d_node = interfaces->list.top; d_node; d_node = d_node->next) {
        if (!(iface_ptr = d_node->data)) {
            vrmr_error(-1, "Internal Error", "NULL pointer");
            return (-1);
        }

        /* Check for empty device string and virtual device. */
        if (strcmp(iface_ptr->device, "") != 0 && !iface_ptr->device_virtual) {
            if (iface_ptr->cnt == NULL) {
                /* alloc the counters */
                if (!(iface_ptr->cnt = malloc(
                              sizeof(struct vrmr_interface_counters)))) {
                    vrmr_error(
                            -1, "Error", "malloc failed: %s", strerror(errno));
                    return (-1);
                }
            }
            memset(iface_ptr->cnt, 0, sizeof(struct vrmr_interface_counters));

            /* get the real counters from iptables */
            vrmr_get_iface_stats_from_ipt(cfg, iface_ptr->device, "INPUT",
                    &iface_ptr->cnt->input_packets,
                    &iface_ptr->cnt->input_bytes, &tmp, &tmp);
            vrmr_get_iface_stats_from_ipt(cfg, iface_ptr->device, "OUTPUT",
                    &tmp, &tmp, &iface_ptr->cnt->output_packets,
                    &iface_ptr->cnt->output_bytes);
            vrmr_get_iface_stats_from_ipt(cfg, iface_ptr->device, "FORWARD",
                    &iface_ptr->cnt->forwardin_packets,
                    &iface_ptr->cnt->forwardin_bytes,
                    &iface_ptr->cnt->forwardout_packets,
                    &iface_ptr->cnt->forwardout_bytes);

            vrmr_debug(HIGH,
                    "iface_ptr->cnt->input_packets: %" PRIu64 ", "
                    "iface_ptr->cnt->input_bytes: %" PRIu64 ".",
                    iface_ptr->cnt->input_packets, iface_ptr->cnt->input_bytes);
            vrmr_debug(HIGH,
                    "iface_ptr->cnt->output_packets: %" PRIu64 ", "
                    "iface_ptr->cnt->output_bytes: %" PRIu64 ".",
                    iface_ptr->cnt->output_packets,
                    iface_ptr->cnt->output_bytes);

            /* assemble the chain-name */
            snprintf(acc_chain, sizeof(acc_chain), "ACC-%s", iface_ptr->device);

            vrmr_debug(HIGH, "acc_chain '%s'.", acc_chain);

            /* get the accounting chains numbers */
            vrmr_get_iface_stats_from_ipt(cfg, iface_ptr->device, acc_chain,
                    &iface_ptr->cnt->acc_in_packets,
                    &iface_ptr->cnt->acc_in_bytes,
                    &iface_ptr->cnt->acc_out_packets,
                    &iface_ptr->cnt->acc_out_bytes);

            vrmr_debug(HIGH,
                    "iface_ptr->cnt->acc_in_bytes: %" PRIu64 ", "
                    "iface_ptr->cnt->acc_out_bytes: %" PRIu64 ".",
                    iface_ptr->cnt->acc_in_bytes,
                    iface_ptr->cnt->acc_out_bytes);
        }
    }

    return (0);
}

static int ruleset_clear_interface_counters(struct vrmr_interfaces *interfaces)
{
    struct vrmr_list_node *d_node = NULL;
    struct vrmr_interface *iface_ptr = NULL;

    assert(interfaces);

    /* loop through the interfaces */
    for (d_node = interfaces->list.top; d_node; d_node = d_node->next) {
        if (!(iface_ptr = d_node->data)) {
            vrmr_error(-1, "Internal Error", "NULL pointer");
            return (-1);
        }

        if (iface_ptr->cnt != NULL) {
            free(iface_ptr->cnt);
            iface_ptr->cnt = NULL;
        }
    }

    return (0);
}

static int ruleset_store_failed_set(const char *file)
{
    char failed_ruleset_path[32] = "";
    int result = 0;
    size_t size = 0;

    assert(file);

    size = strlcpy(failed_ruleset_path, file, sizeof(failed_ruleset_path));
    if (size >= sizeof(failed_ruleset_path)) {
        vrmr_error(-1, "Internal Error", "could not create failed rulset path");
        return (-1);
    }
    size = strlcat(failed_ruleset_path, ".failed", sizeof(failed_ruleset_path));
    if (size >= sizeof(failed_ruleset_path)) {
        vrmr_error(-1, "Internal Error", "could not create failed rulset path");
        return (-1);
    }

    result = rename(file, failed_ruleset_path);
    if (result == -1) {
        vrmr_error(-1, "Error", "renaming '%s' to '%s' failed: %s", file,
                failed_ruleset_path, strerror(errno));
        return (-1);
    }

    return (0);
}

static int ruleset_log_resultfile(char *path)
{
    char line[256] = "";

    assert(path);

    /* open the file */
    FILE *fp = fopen(path, "r");
    if (fp == NULL) {
        vrmr_error(-1, "Error", "opening resultfile '%s' failed: %s", path,
                strerror(errno));
        return (-1);
    }

    while (fgets(line, (int)sizeof(line), fp) != NULL) {
        if (line[strlen(line) - 1] == '\n')
            line[strlen(line) - 1] = '\0';

        vrmr_error(-1, "Error", "loading ruleset result: '%s'.", line);
    }

    if (fclose(fp) == -1) {
        vrmr_error(-1, "Error", "closing resultfile '%s' failed: %s", path,
                strerror(errno));
        return (-1);
    }

    return (0);
}

static void load_ruleset_free_fds(int ruleset_fd, int result_fd, int shape_fd)
{
    if (ruleset_fd > 0) {
        close(ruleset_fd);
    }
    if (result_fd > 0) {
        close(result_fd);
    }
    if (shape_fd > 0) {
        close(shape_fd);
    }
}

static void ruleset_load_helper_modules(struct vrmr_ctx *vctx)
{
    assert(vctx);

    if (vctx->conf.load_modules) {
        struct vrmr_list_node *n;
        for (n = vctx->rules.helpers.top; n; n = n->next) {
            const char *helper = n->data;
            iptcap_load_helper_module(&vctx->conf, helper);
        }
    }
}

/** \internal
 *
 *  \brief load the ipv4 ruleset
 *
 *  \param vctx Vuurmuur context
 *
 *  \retval 0 ok
 *  \retval -1 error
 */
static int load_ruleset_ipv4(struct vrmr_ctx *vctx)
{
    struct rule_set ruleset;
    char cur_ruleset_path[] = "/tmp/vuurmuur-XXXXXX";
    char cur_result_path[] = "/tmp/vuurmuur-load-result-XXXXXX";
    char cur_shape_path[] = "/tmp/vuurmuur-shape-XXXXXX";
    int ruleset_fd = 0, result_fd = 0, shape_fd = 0;

    /* setup the ruleset */
    if (ruleset_setup(&ruleset) != 0) {
        vrmr_error(-1, "Internal Error", "setting up ruleset failed");
        return (-1);
    }

    ruleset.ipv = VRMR_IPV4;

    /* store counters */
    if (ruleset_save_interface_counters(&vctx->conf, &vctx->interfaces) < 0) {
        vrmr_error(-1, "Error", "saving interface counters failed");
        return (-1);
    }

    /* create the ruleset */
    if (ruleset_create_ruleset(vctx, &ruleset) < 0) {
        vrmr_error(-1, "Error", "creating ruleset failed");
        return (-1);
    }

    /* clear the counters again */
    if (ruleset_clear_interface_counters(&vctx->interfaces) < 0) {
        vrmr_error(-1, "Error", "clearing interface counters failed");
        return (-1);
    }

    /* create the tempfile */
    ruleset_fd = vrmr_create_tempfile(cur_ruleset_path);
    if (ruleset_fd == -1) {
        vrmr_error(-1, "Error", "creating rulesetfile failed");
        ruleset_cleanup(&ruleset);
        return (-1);
    }

    /* create the tempfile */
    result_fd = vrmr_create_tempfile(cur_result_path);
    if (result_fd == -1) {
        vrmr_error(-1, "Error", "creating resultfile failed");
        ruleset_cleanup(&ruleset);
        load_ruleset_free_fds(ruleset_fd, result_fd, shape_fd);
        return (-1);
    }

    /* create the tempfile */
    shape_fd = vrmr_create_tempfile(cur_shape_path);
    if (shape_fd == -1) {
        vrmr_error(-1, "Error", "creating shape script file failed");
        ruleset_cleanup(&ruleset);
        load_ruleset_free_fds(ruleset_fd, result_fd, shape_fd);
        return (-1);
    }

    /* get the custom chains we have to create */
    if (vrmr_rules_get_custom_chains(&vctx->rules) < 0) {
        vrmr_error(-1, "Internal Error", "rules_get_chains() failed");
        load_ruleset_free_fds(ruleset_fd, result_fd, shape_fd);
        return (-1);
    }
    /* now create the currentrulesetfile */
    if (ruleset_fill_file(vctx, &ruleset, ruleset_fd, VRMR_IPV4) < 0) {
        vrmr_error(-1, "Error", "filling rulesetfile failed");
        ruleset_cleanup(&ruleset);
        load_ruleset_free_fds(ruleset_fd, result_fd, shape_fd);
        (void)ruleset_store_failed_set(cur_ruleset_path);
        return (-1);
    }
    /* cleanup */
    vrmr_list_cleanup(&vctx->rules.custom_chain_list);

    /* now create the shape file */
    if (ruleset_fill_shaping_file(&ruleset, shape_fd) < 0) {
        vrmr_error(-1, "Error", "filling rulesetfile failed");
        ruleset_cleanup(&ruleset);
        load_ruleset_free_fds(ruleset_fd, result_fd, shape_fd);
        (void)ruleset_store_failed_set(cur_ruleset_path);
        return (-1);
    }

    if (vrmr_debug_level >= HIGH) {
        vrmr_debug(HIGH, "sleeping so you can look into the tmpfile.");
        sleep(15);
    }

    ruleset_load_helper_modules(vctx);

    /* load the shaping rules */
    if (ruleset_load_shape_ruleset(
                cur_shape_path, cur_result_path, &vctx->conf) != 0) {
        /* oops, something went wrong */
        vrmr_error(-1, "Error",
                "shape rulesetfile will be stored as '%s.failed'",
                cur_shape_path);
        (void)ruleset_store_failed_set(cur_shape_path);
        (void)ruleset_log_resultfile(cur_result_path);
        load_ruleset_free_fds(ruleset_fd, result_fd, shape_fd);
        ruleset_cleanup(&ruleset);
        return (-1);
    }
    /* now load the iptables ruleset */
    if (ruleset_load_ruleset(cur_ruleset_path, cur_result_path, &vctx->conf,
                VRMR_IPV4) != 0) {
        /* oops, something went wrong */
        vrmr_error(-1, "Error", "rulesetfile will be stored as '%s.failed'",
                cur_ruleset_path);
        (void)ruleset_store_failed_set(cur_ruleset_path);
        (void)ruleset_log_resultfile(cur_result_path);
        load_ruleset_free_fds(ruleset_fd, result_fd, shape_fd);
        ruleset_cleanup(&ruleset);
        return (-1);
    }
    load_ruleset_free_fds(ruleset_fd, result_fd, shape_fd);

    if (cmdline.keep_file == FALSE) {
        /* remove the rules tempfile */
        if (unlink(cur_ruleset_path) == -1) {
            vrmr_error(-1, "Error", "removing tempfile failed: %s",
                    strerror(errno));
            ruleset_cleanup(&ruleset);
            return (-1);
        }

        /* remove the result tempfile */
        if (unlink(cur_result_path) == -1) {
            vrmr_error(-1, "Error", "removing tempfile failed: %s",
                    strerror(errno));
            ruleset_cleanup(&ruleset);
            return (-1);
        }

        /* remove the shape tempfile */
        if (unlink(cur_shape_path) == -1) {
            vrmr_error(-1, "Error", "removing tempfile failed: %s",
                    strerror(errno));
            ruleset_cleanup(&ruleset);
            return (-1);
        }
    }

    /* finaly clean up the mess */
    ruleset_cleanup(&ruleset);

    vrmr_info("Info", "ruleset loading completed successfully.");
    return (0);
}

#ifdef IPV6_ENABLED
/** \internal
 *
 *  \brief load the ipv6 ruleset
 *
 *  \param vctx Vuurmuur context
 *
 *  \retval 0 ok
 *  \retval -1 error
 */
static int load_ruleset_ipv6(struct vrmr_ctx *vctx)
{
    struct rule_set ruleset;
    char cur_ruleset_path[] = "/tmp/vuurmuur-XXXXXX";
    char cur_result_path[] = "/tmp/vuurmuur-load-result-XXXXXX";
    int ruleset_fd = 0, result_fd = 0;

    /* setup the ruleset */
    if (ruleset_setup(&ruleset) != 0) {
        vrmr_error(-1, "Internal Error", "setting up ruleset failed");
        return (-1);
    }

    ruleset.ipv = VRMR_IPV6;

    /* store counters */
    if (ruleset_save_interface_counters(&vctx->conf, &vctx->interfaces) < 0) {
        vrmr_error(-1, "Error", "saving interface counters failed");
        return (-1);
    }

    /* create the ruleset */
    if (ruleset_create_ruleset(vctx, &ruleset) < 0) {
        vrmr_error(-1, "Error", "creating ruleset failed");
        return (-1);
    }

    /* clear the counters again */
    if (ruleset_clear_interface_counters(&vctx->interfaces) < 0) {
        vrmr_error(-1, "Error", "clearing interface counters failed");
        return (-1);
    }

    /* create the tempfile */
    ruleset_fd = vrmr_create_tempfile(cur_ruleset_path);
    if (ruleset_fd == -1) {
        vrmr_error(-1, "Error", "creating rulesetfile failed");
        ruleset_cleanup(&ruleset);
        return (-1);
    }

    /* create the tempfile */
    result_fd = vrmr_create_tempfile(cur_result_path);
    if (result_fd == -1) {
        vrmr_error(-1, "Error", "creating resultfile failed");
        ruleset_cleanup(&ruleset);
        load_ruleset_free_fds(ruleset_fd, result_fd, 0);
        return (-1);
    }

    /* get the custom chains we have to create */
    if (vrmr_rules_get_custom_chains(&vctx->rules) < 0) {
        vrmr_error(-1, "Internal Error", "rules_get_chains() failed");
        load_ruleset_free_fds(ruleset_fd, result_fd, 0);
        return (-1);
    }
    /* now create the currentrulesetfile */
    if (ruleset_fill_file(vctx, &ruleset, ruleset_fd, VRMR_IPV6) < 0) {
        vrmr_error(-1, "Error", "filling rulesetfile failed");
        ruleset_cleanup(&ruleset);
        load_ruleset_free_fds(ruleset_fd, result_fd, 0);
        (void)ruleset_store_failed_set(cur_ruleset_path);
        return (-1);
    }
    /* cleanup */
    vrmr_list_cleanup(&vctx->rules.custom_chain_list);

    if (vrmr_debug_level >= HIGH) {
        vrmr_debug(HIGH, "sleeping so you can look into the tmpfile.");
        sleep(15);
    }

    /* now load the iptables ruleset */
    if (ruleset_load_ruleset(cur_ruleset_path, cur_result_path, &vctx->conf,
                VRMR_IPV6) != 0) {
        /* oops, something went wrong */
        vrmr_error(-1, "Error", "rulesetfile will be stored as '%s.failed'",
                cur_ruleset_path);
        (void)ruleset_store_failed_set(cur_ruleset_path);
        (void)ruleset_log_resultfile(cur_result_path);
        load_ruleset_free_fds(ruleset_fd, result_fd, 0);
        ruleset_cleanup(&ruleset);
        return (-1);
    }
    load_ruleset_free_fds(ruleset_fd, result_fd, 0);

    if (cmdline.keep_file == FALSE) {
        /* remove the rules tempfile */
        if (unlink(cur_ruleset_path) == -1) {
            vrmr_error(-1, "Error", "removing tempfile failed: %s",
                    strerror(errno));
            ruleset_cleanup(&ruleset);
            return (-1);
        }

        /* remove the result tempfile */
        if (unlink(cur_result_path) == -1) {
            vrmr_error(-1, "Error", "removing tempfile failed: %s",
                    strerror(errno));
            ruleset_cleanup(&ruleset);
            return (-1);
        }
    }

    /* finaly clean up the mess */
    ruleset_cleanup(&ruleset);

    vrmr_info("Info", "ruleset loading completed successfully.");
    return (0);
}
#endif

int load_ruleset(struct vrmr_ctx *vctx)
{
    int r = load_ruleset_ipv4(vctx);
    if (r == -1) {
        return (-1);
    }

#ifdef IPV6_ENABLED
    vrmr_info("Info", "loading ipv6 ruleset");
    r = load_ruleset_ipv6(vctx);
    if (r == -1) {
        return (-1);
    }
#endif

    return (0);
}
