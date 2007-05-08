/***************************************************************************
 *   Copyright (C) 2003-2006 by Victor Julien                              *
 *   victor@nk.nl                                                          *
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

#include "vuurmuur.h"


/* remove_list

	Remove a rule from the list.
*/
int
rules_remove_rule_from_list(const int debuglvl, Rules *rules, unsigned int place, int updatenumbers)
{
	struct RuleData_	*rule_ptr = NULL;
	d_list_node		*d_node = NULL;


	/* safety */
	if(rules == NULL)
	{
		(void)vrprint.error(-1, "Internal Error", "parameter problem (in: %s:%d).",
									__FUNC__, __LINE__);
		return(-1);
	}

	if(debuglvl >= LOW)
		(void)vrprint.debug(__FUNC__, "start: place: %d, updatenumbers: %d, listsize: %d", place, updatenumbers, rules->list.len);

	for(d_node = rules->list.top; d_node ; d_node = d_node->next)
	{
		if(!(rule_ptr = d_node->data))
		{
			(void)vrprint.error(-1, "Internal Error", "NULL pointer (in: %s:%d).",
										__FUNC__, __LINE__);
			return(-1);
		}

		if(debuglvl >= HIGH)
			(void)vrprint.debug(__FUNC__, "rule_ptr->number: %d, place: %d", rule_ptr->number, place);

		if(rule_ptr->number != place)
		{
			//fprintf(stdout, "do nothing\n");
		}
		else
		{
			if(debuglvl >= HIGH)
				(void)vrprint.debug(__FUNC__, "now we have to remove (query_ptr->number: %d, place: %d)", rule_ptr->number, place);

			if(d_list_node_is_bot(debuglvl, d_node))
			{
				if(debuglvl >= HIGH)
					(void)vrprint.debug(__FUNC__, "removing last entry");

				if(d_list_remove_bot(debuglvl, &rules->list) < 0)
				{
					(void)vrprint.error(-1, "Internal Error", "d_list_remove_bot() failed (in: %s:%d).",
													__FUNC__, __LINE__);
					return(-1);
				}

			}
			else
			{
				if(debuglvl >= HIGH)
					(void)vrprint.debug(__FUNC__, "removing normal entry");

				if(d_list_remove_node(debuglvl, &rules->list, d_node) < 0)
				{
					(void)vrprint.error(-1, "Internal Error", "d_list_remove_node() failed (in: %s:%d).",
													__FUNC__, __LINE__);
					return(-1);
				}

				if(updatenumbers == 1)
				{
					if(debuglvl >= HIGH)
						(void)vrprint.debug(__FUNC__, "updatenumbers: %d, %d", place, 0);

					rules_update_numbers(debuglvl, rules, place, 0);
				}
			}

			/* we only remove one rule at a time */
			break;
		}
	}

	return(0);
}


/*	query_update_numbers

	action:
		0: decrease
		1: increase
*/
void
rules_update_numbers(const int debuglvl, Rules *rules, unsigned int place, int action)
{
	struct RuleData_	*rule_ptr = NULL;
	d_list_node		*d_node = NULL;
	unsigned int		i = 0;

	/* safety */
	if(rules == NULL)
	{
		(void)vrprint.error(-1, "Internal Error", "parameter problem (in: %s:%d).",
									__FUNC__, __LINE__);
		return;
	}

	if(debuglvl >= HIGH)
		(void)vrprint.debug(__FUNC__, "Update higher (or equal) than: %d, action = %d. (list len is %d)", place, action, rules->list.len);

	for(d_node = rules->list.top, i = 1; d_node ; d_node = d_node->next, i++)
	{
		rule_ptr = d_node->data;

		if(i > place)
		{
			if(action == 1)
				rule_ptr->number++;
		}

		if(i >= place)
		{
			if(action == 0 && rule_ptr->number != 0)
				rule_ptr->number--;
		}
	}

	return;
}


/*- rules_print_list - */
void
rules_print_list(const Rules *rules)
{
	d_list_node		*d_node = NULL;
	struct RuleData_	*rule_ptr = NULL;

	for(d_node = rules->list.top; d_node ; d_node = d_node->next)
	{
		rule_ptr = d_node->data;

		(void)vrprint.debug(__FUNC__, "%3d, %-8s, %s, %s, %s, %s, %s, %s, status: %d",
				rule_ptr->number, rules_itoaction(rule_ptr->action),
				rule_ptr->service, rule_ptr->from,
				rule_ptr->to, rule_ptr->who,
				rule_ptr->source, rule_ptr->danger,
				rule_ptr->status);
	}

	return;
}


void
free_options(const int debuglvl, struct options *opt)
{
	d_list_node		*d_node = NULL;
	struct portdata		*port_ptr = NULL;

	if(!opt)
		return;

	if(opt->RemoteportList.len > 0)
	{
		/*
			free all portranges
		*/
		for(d_node = opt->RemoteportList.top; d_node; d_node = d_node->next)
		{
			port_ptr = d_node->data;
			free(port_ptr);
		}

		d_list_cleanup(debuglvl, &opt->RemoteportList);
	}

	if(opt->ListenportList.len > 0)
	{
		/*
			free all portranges
		*/
		for(d_node = opt->ListenportList.top; d_node; d_node = d_node->next)
		{
			port_ptr = d_node->data;
			free(port_ptr);
		}

		d_list_cleanup(debuglvl, &opt->ListenportList);
	}

	free(opt);
}
