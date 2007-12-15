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

#ifndef __STRINGS_H__
#define __STRINGS_H__

#include "gettext.h"

/*
	all objects
*/
#define STR_HOST			gettext("host")
#define STR_CHOST			gettext("Host")
#define STR_GROUP			gettext("group")
#define STR_CGROUP			gettext("Group")
#define STR_NETWORK			gettext("network")
#define STR_CNETWORK			gettext("Network")
#define STR_ZONE			gettext("zone")
#define STR_CZONE			gettext("Zone")
#define STR_INTERFACE			gettext("interface")
#define STR_CINTERFACE			gettext("Interface")
#define STR_SERVICE			gettext("service")
#define STR_CSERVICE			gettext("Service")

#define STR_PORTRANGE			gettext("portrange")
#define STR_CPORTRANGE			gettext("Portrange")
#define STR_PORTRANGES			gettext("portranges")
#define STR_CPORTRANGES			gettext("Portranges")

/*
	vars
*/
/* TRANSLATORS: is an object active or in-active? */
#define	STR_ACTIVE			gettext("active")
/* TRANSLATORS: is an object active or in-active? */
#define	STR_CACTIVE			gettext("Active")
#define	STR_BROADCAST			gettext("broadcast")
#define	STR_CBROADCAST			gettext("Broadcast")
#define	STR_PROTOHELP			gettext("protocol helper")
#define	STR_CPROTOHELP			gettext("Protocol Helper")
#define STR_IPADDRESS			gettext("IP address")
#define STR_MACADDRESS			gettext("MAC address")
/* TRANSLATORS: max 18 chars */
#define STR_DYNAMICIP			gettext("dynamic IP Address")
/* TRANSLATORS: max 18 chars */
#define STR_CDYNAMICIP			gettext("Dynamic IP Address")
/* TRANSLATORS: e.g. eth0 or ppp0 */
#define STR_DEVICE			gettext("device")
/* TRANSLATORS: e.g. eth0 or ppp0 */
#define STR_CDEVICE			gettext("Device")
/* TRANSLATORS: e.g. eth0:0 is a virtual device */
#define STR_VIRTUAL			gettext("virtual")
/* TRANSLATORS: e.g. eth0:0 is a virtual device */
#define STR_CVIRTUAL			gettext("Virtual")
#define STR_NETADDR			gettext("network address")
#define STR_NETMASK			gettext("netmask")
#define STR_IN				gettext("Incoming bandwidth")
#define STR_OUT				gettext("Outgoing bandwidth")
#define STR_IN_UNIT			gettext("Incoming unit")
#define STR_OUT_UNIT			gettext("Outgoing unit")
#define STR_SHAPE			gettext("Shaping")

/* TRANSLATORS: "interface 'lan' has been changed: rules are changed: number of rules: 5 (listed below)." */
#define STR_RULES_ARE_CHANGED		gettext("rules are changed")
/* TRANSLATORS: "interface 'lan' has been changed: rules are changed: number of rules: 5 (listed below)." */
#define STR_NUMBER_OF_RULES		gettext("number of rules")
/* TRANSLATORS: "interface 'lan' has been changed: rules are changed: number of rules: 5 (listed below)." */
#define STR_LISTED_BELOW		gettext("listed below")

#define STR_RENAME_FAILED		gettext("rename failed")
#define STR_DELETE_FAILED		gettext("delete failed")
#define STR_INVALID_NAME		gettext("invalid name")
#define STR_PLEASE_ENTER_THE_NAME	gettext("Please enter the name")

/*
	general
*/
#define STR_READY			gettext("Ready.")
#define STR_YES				gettext("Yes")
#define STR_NO				gettext("No")

#define STR_COK				gettext("OK")
#define STR_CFAILED			gettext("FAILED")

#define VR_ERR				gettext("Error")
#define VR_INTERR			gettext("Internal Error")
#define VR_INFO				gettext("Info")
#define VR_WARN				gettext("Warning")

#define STR_SAVING_TO_BACKEND_FAILED	gettext("saving to backend failed")

#define STR_OPENING_FILE_FAILED		gettext("opening file failed")

#define STR_ONLY_ASCII_ALLOWED_IN_PREFIX	gettext("only ASCII is allowed in the prefix field.")

/*
	audit strings
*/
/* TRANSLATORS: example: service 'http' has been changed: active is now set to 'Yes' (was: 'No'). */
#define STR_HAS_BEEN_CHANGED		gettext("has been changed")
/* TRANSLATORS: example: service 'http' has been changed: portrange 'TCP: 1024:65535->80' has been added. */
#define STR_HAS_BEEN_ADDED		gettext("has been added")
/* TRANSLATORS: example: service 'http' has been created. */
#define STR_HAS_BEEN_CREATED		gettext("has been created")
/* TRANSLATORS: example: service 'htpt' has been renamed to 'http'. */
#define STR_HAS_BEEN_RENAMED_TO		gettext("has been renamed to")
/* TRANSLATORS: example: service 'http' has been changed: portrange 'TCP: 1024:65535->80' has been removed. */
#define STR_HAS_BEEN_REMOVED		gettext("has been removed")
/* TRANSLATORS: example: service 'http' has been deleted. */
#define STR_HAS_BEEN_DELETED		gettext("has been deleted")
/* TRANSLATORS: example: service 'http' has been changed: active is now set to 'Yes' (was: 'No'). */
#define STR_IS_NOW_SET_TO		gettext("is now set to")
/* TRANSLATORS: example: service 'http' has been changed: active is now set to 'Yes' (was: 'No'). */
#define STR_WAS				gettext("was")

/* TRANSLATORS: example: service '%s' has been changed: the comment has been changed. */
#define STR_COMMENT_CHANGED		gettext("the comment has been changed")

/*
	service strings
*/
#define STR_PROTO_NO_PORTS		gettext("this protocol doesn't use ports.")

/*
	group strings
*/
#define STR_A_MEMBER_HAS_BEEN_ADDED	gettext("a member has been added")
#define STR_A_MEMBER_HAS_BEEN_REMOVED	gettext("a member has been removed")

/*
	network strings
*/
#define STR_AN_IFACE_HAS_BEEN_ADDED	gettext("an interface has been added")
#define STR_AN_IFACE_HAS_BEEN_REMOVED	gettext("an interface has been removed")

/*
	blocklist
*/
#define STR_HAS_BEEN_ADDED_TO_THE_BLOCKLIST	gettext("has been added to the blocklist")
#define STR_HAS_BEEN_REMOVED_FROM_THE_BLOCKLIST	gettext("has been added to the blocklist")

/*
	GUI
*/
#define STR_NEW				gettext("new")
#define STR_REMOVE			gettext("remove")
#define STR_EDIT			gettext("edit")
#define STR_RENAME			gettext("rename")

/*
	startup
*/
#define STR_INIT_SERVICES		gettext("Initializing Services")
#define STR_INIT_INTERFACES		gettext("Initializing Interfaces")
#define STR_INIT_ZONES			gettext("Initializing Zones")
#define STR_INIT_RULES			gettext("Initializing Rules")
#define STR_INIT_BLOCKLIST		gettext("Initializing BlockList")
#define STR_LOAD_PLUGINS		gettext("Loading plugins")
#define STR_LOAD_VUURMUUR_CONF_SETTINGS	gettext("Loading Vuurmuur_conf settings")
#define STR_LOAD_VUURMUUR_CONFIG	gettext("Loading Vuurmuur config")

#define STR_CONNECTING_TO		gettext("Connecting to")

/*
	logview
*/
#define STR_THE_DATE_IS_NOW		gettext("The date is now")
#define STR_THE_ACTION_IS_NOW		gettext("The action is now")
#define STR_THE_SERVICE_IS_NOW		gettext("The service is now")
#define STR_THE_SOURCE_IS_NOW		gettext("The source is now")
#define STR_THE_DESTINATION_IS_NOW	gettext("The destination is now")
#define STR_THE_PREFIX_IS_NOW		gettext("The prefix is now")
#define STR_THE_DETAILS_ARE_NOW		gettext("The details are now")
#define STR_LOGGING_OPTS_NOT_AVAIL	gettext("logging options are only available for the traffic.log.")

/*
	edit rule
*/
#define STR_BOUNCE_REQUIRES_VIA_OPT	gettext("the action 'Bounce' requires the 'via' option to be set.")
#define STR_REDIRECT_REQUIRES_OPT	gettext("the action 'Redirect' requires the 'Redirect port' option to be set.")


#define STR_CONNTRACK_LOC_NOT_SET	gettext("'conntrack' location not set. To be able to kill connections, set the location of the 'conntrack' tool in 'Vuurmuur Options -> General'. Note that the tool requires kernel version 2.6.14 or higher.")

#endif
