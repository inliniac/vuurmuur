#!/bin/bash

# Quick setup wizard for Vuurmuur.
#
# Copyright (c) 2009 by Victor Julien <victor@inliniac.net>

VMS="vuurmuur_script"

VERSION="0.8beta1"
BACKTITLE="Vuurmuur Setup Wizard version $VERSION"

ZONES="inet lan"

INTERNET="world.inet"
LAN="local.lan"

# all screen have the same size: it must fit on a 80x20 console
WIDTH=74
HEIGHT=16

# runtime vars
HAVE_LAN="1"          # do we have a LAN?
LAN_DEV=""
INET_DEV_DYNAMIC="0"  # INTERNET dev is dynamic
LAN_DEV_DYNAMIC="0"   # LAN dev is dynamic

# modeled after: http://www.linuxsecurity.com/content/view/115462/81/
function maketemp
{
    tmp=${TMPDIR-/tmp}
    tmp=$tmp/vuurmuur.$RANDOM.$RANDOM.$RANDOM.$$
    (umask 077 && mkdir $tmp) || {
        echo "Could not create temporary directory! Exiting." 1>&2 
        exit 1
    }

    echo $tmp
}

function InitTempfiles
{
    TMPDIR=`maketemp`
    echo "TMPDIR $TMPDIR"

    CMD="$TMPDIR/commands"
    TMP="$TMPDIR/temp"
    TMPCMD="$TMPDIR/tempcommands"

    # init cmd
    echo "#!/bin/bash" > $CMD
    echo "# Script created by vuurmuur_wizard.sh version $VERSION" >> $CMD
    echo "" >> $CMD
}

# strip the tremas, so "ahem" becomes ahem
function stripit
{
	RES=`echo $1 | cut -d '"' -f2`
	echo $RES
}


function getdevices
{
    $VMS --list-devices | while read line; do
	DEV=`echo $line|cut -d ' ' -f 1`
	if [ $DEV != "lo" ]; then
		echo -n "$DEV "
	fi
    done
}

# getipfordevice using vuurmuur_script --list-devices
function getipfordevice
{
	LOOKUP_DEV=$1

	$VMS --list-devices | while read line; do
		DEV=`echo $line|cut -d ' ' -f 1`
		if [ "$DEV" = "$LOOKUP_DEV" ]; then
			IP=`echo $line|cut -d ' ' -f 2`
			echo $IP
            break
		fi
	done
}

function getnetworkfordevice
{
	LOOKUP_DEV=$1

	$VMS --list-devices | while read line; do
		DEV=`echo $line|cut -d ' ' -f 1`
		if [ "$DEV" = "$LOOKUP_DEV" ]; then
			NW=`echo $line|cut -d ' ' -f 4`
			echo $NW
            break
		fi
	done
}

function getnetmaskfordevice
{
	LOOKUP_DEV=$1

	$VMS --list-devices | while read line; do
		DEV=`echo $line|cut -d ' ' -f 1`
		if [ "$DEV" = "$LOOKUP_DEV" ]; then
			NM=`echo $line|cut -d ' ' -f 3`
			echo $NM
            break
		fi
	done
}

# dynamicly create the interface selector based on the
# interfaces on the system.
#
function SelectInternetInterfaceSetup
{
    echo "#!/bin/bash" > $TMPCMD
    echo -n "dialog --backtitle \"$BACKTITLE\" --title \"[ INTERNET Interface ]\" --radiolist \
	\"Select the interface you use to connect to the internet. This doesn't have to be directly connected to the internet. If this firewall is behind a modem, router or another firewall, select the interface used to connect to that gateway.\" \
	$HEIGHT $WIDTH 0 " >> $TMPCMD

    $VMS --list-devices | while read line; do
        DEV=`echo $line | cut -d ' ' -f 1`
        if [ $DEV != "lo" ]; then
            IP=`echo $line | cut -d ' ' -f 2`
            MASK=`echo $line | cut -d ' ' -f 5`
            NET=`echo $line | cut -d ' ' -f 4`

            echo -n "$DEV \"$IP $NET/$MASK \" OFF \\" >> $TMPCMD
        fi
    done
    echo -n "manual \"Interface is offline, enter manually\" OFF \\" >> $TMPCMD
}

function SelectInternetInterfaceDynamicSetup
{
    DEV=$1

    echo "#!/bin/bash" > $TMPCMD
    echo -n "dialog --backtitle \"$BACKTITLE\" --title \"[ INTERNET Interface ]\" --yesno \
	\"\nDoes INTERNET interface \\\"$DEV\\\" get it's IP Address from a DHCP server, or does it get otherwise dynamically assigned? If unsure, answer \\\"Yes\\\". If you know the IP Address to be static, answer \\\"No\\\".\" \
	$HEIGHT $WIDTH" >> $TMPCMD
}

function EnterInternetInterfaceSetup
{
    echo "#!/bin/bash" > $TMPCMD
    echo -n "dialog --backtitle \"$BACKTITLE\" --title \"[ INTERNET Interface ]\" --inputbox \
	\"Enter the interface you use to connect to the internet (e.g. ppp0, eth1). This doesn't have to be directly connected to the internet. If this firewall is behind a modem, router or another firewall, enter the interface used to connect to that gateway.\" \
	$HEIGHT $WIDTH" >> $TMPCMD
}


# dynamicly create the interface selector based on the
# interfaces on the system.
#
function SelectLanInterfaceSetup
{
    echo "#!/bin/bash" > $TMPCMD
    echo -n "dialog --backtitle \"$BACKTITLE\" --title \"[ LAN Interface ]\" --radiolist \
	\"Select the interface the firewall is connected to the LAN with.\" \
	$HEIGHT $WIDTH 0 " >> $TMPCMD

    $VMS --list-devices | while read line; do
        DEV=`echo $line | cut -d ' ' -f 1`
        if [ $DEV != "lo" ]; then
            IP=`echo $line | cut -d ' ' -f 2`
            MASK=`echo $line | cut -d ' ' -f 5`
            NET=`echo $line | cut -d ' ' -f 4`

            echo -n "$DEV \"$IP $NET/$MASK \" OFF \\" >> $TMPCMD
        fi
    done
    echo -n "none \"No LAN connected to this firewall\" OFF \\" >> $TMPCMD
}

function SelectLanInterfaceDynamicSetup
{
    DEV=$1

    echo "#!/bin/bash" > $TMPCMD
    echo -n "dialog --backtitle \"$BACKTITLE\" --title \"[ LAN Interface ]\" --yesno \
	\"\nDoes LAN interface \\\"$DEV\\\" get it's IP Address from a DHCP server? If unsure, answer \\\"Yes\\\". If the IP Address is static, answer \\\"No\\\".\" \
	$HEIGHT $WIDTH" >> $TMPCMD
}


function DisplayInitialWarning
{
    # give the user a chance to get out safely
    dialog --backtitle "$BACKTITLE" --title "[ WELCOME ]" \
	    --yesno "Welcome to the vuurmuur setup wizard version $VERSION.\n\nYou can use this wizard to create a very basic setup in Vuurmuur. All more advanced configuration should be done using the 'vuurmuur_conf' program. You can re-run the wizard at any later time by executing 'vuurmuur_conf --wizard'.\n\nThis wizard will OVERWRITE your current configuration. Are you sure you want this?" \
	    $HEIGHT $WIDTH 2> $TMP
    if [ $? != 0 ]; then
	    exit 0
    fi
}


function CreateZones
{
    #
    # ZONES
    #
    for zone in `echo $ZONES`; do
        echo "" >> $CMD
        echo "# Adding zone $zone..." >> $CMD
    	echo "$VMS --add --zone $zone" >> $CMD
    	echo "$VMS --modify --zone $zone --variable ACTIVE --set Yes --overwrite" >> $CMD
    done
}


function CreateInternetNetwork
{
    echo "" >> $CMD
    echo "# Adding network $INTERNET..." >> $CMD
    echo "$VMS --add --network $INTERNET" >> $CMD
    echo "$VMS --modify --network $INTERNET --variable ACTIVE --set Yes --overwrite" >> $CMD
    echo "$VMS --modify --network $INTERNET --variable NETWORK --set 0.0.0.0 --overwrite" >> $CMD
    echo "$VMS --modify --network $INTERNET --variable NETMASK --set 0.0.0.0 --overwrite" >> $CMD
    echo "# FIXME: network rules" >> $CMD

    if [ "$INET_DEV_DYNAMIC" = "1" ]; then
        echo "# Enabling DHCP client access for $INTERNET" >> $CMD
    	echo "$VMS --modify --network $INTERNET --overwrite --variable RULE --set \"accept dhcp-client\"" >> $CMD
    fi
}

function CreateLanNetwork
{
    DEV=$1

    NETWORK=`getnetworkfordevice $DEV`
    NETMASK=`getnetmaskfordevice $DEV`

    echo "" >> $CMD
    echo "# Adding network $LAN..." >> $CMD
    echo "$VMS --add --network $LAN" >> $CMD
    echo "$VMS --modify --network $LAN --variable ACTIVE --set Yes --overwrite" >> $CMD
    echo "$VMS --modify --network $LAN --variable NETWORK --set $NETWORK --overwrite" >> $CMD
    echo "$VMS --modify --network $LAN --variable NETMASK --set $NETMASK --overwrite" >> $CMD
    echo "# FIXME: network rules" >> $CMD

    if [ "$LAN_DEV_DYNAMIC" = "1" ]; then
        echo "# Enabling DHCP client access for $LAN" >> $CMD
    	echo "$VMS --modify --network $LAN --overwrite --variable RULE --set \"accept dhcp-client\"" >> $CMD
    fi
}


# Create the name of the internet interface
#
#
function GetInternetInterfaceName
{
    DEV=$1
    echo "inet-nic"
}

function GetLanInterfaceName
{
    DEV=$1
    echo "lan-nic"
}


# Create the internet interface
#
#
function CreateInternetInterface
{
    NAME=$1
    DEV=$2

    if [ "$INET_DEV_DYNAMIC" = "1" ]; then
        IP="";
    else
        IP=`getipfordevice $DEV`
    fi

    echo "" >> $CMD
    echo "# Adding Internet interface $NAME, $DEV, $IP..." >> $CMD
    echo "$VMS --add --interface $NAME" >> $CMD
    echo "$VMS --modify --interface $NAME --variable ACTIVE --set Yes  --overwrite" >> $CMD
    echo "$VMS --modify --interface $NAME --variable DEVICE --set $DEV  --overwrite" >> $CMD
    echo "$VMS --modify --interface $NAME --variable IPADDRESS --set \"$IP\"  --overwrite" >> $CMD
    if [ "$INET_DEV_DYNAMIC" = "1" ]; then
        echo "$VMS --modify --interface $NAME --variable DYNAMIC --set Yes  --overwrite" >> $CMD
    fi
    echo "$VMS --modify --interface $NAME --variable COMMENT --set \"The network interface that is connected to the Internet\"  --overwrite" >> $CMD

    echo "# FIXME: interface rules" >> $CMD
}

function CreateLanInterface
{
    NAME=$1
    DEV=$2

    if [ "$LAN_DEV_DYNAMIC" = "1" ]; then
        IP=""
    else
        IP=`getipfordevice $DEV`
    fi

    echo "" >> $CMD
    echo "# Adding LAN interface $NAME, $DEV, $IP..." >> $CMD
    echo "$VMS --add --interface $NAME" >> $CMD
    echo "$VMS --modify --interface $NAME --variable ACTIVE --set Yes  --overwrite" >> $CMD
    echo "$VMS --modify --interface $NAME --variable DEVICE --set $DEV  --overwrite" >> $CMD
    echo "$VMS --modify --interface $NAME --variable IPADDRESS --set \"$IP\"  --overwrite" >> $CMD
    if [ "$LAN_DEV_DYNAMIC" = "1" ]; then
        echo "$VMS --modify --interface $NAME --variable DYNAMIC --set Yes  --overwrite" >> $CMD
    fi
    echo "$VMS --modify --interface $NAME --variable COMMENT --set \"The network interface that is connected to the Lan\"  --overwrite" >> $CMD

    echo "# FIXME: interface rules" >> $CMD
}


function SelectInternetInterface
{
    # create the temp script to select the interface
    #
    SelectInternetInterfaceSetup
    #
    # run it until we have a valid answer
    DONE=0
    while [ "$DONE" = "0" ]; do
    	bash $TMPCMD 2> $TMP
    	if [ $? != 0 ]; then
    		dialog	--backtitle "$BACKTITLE" \
    			--msgbox "FIXME: cancel at select internet interface." $HEIGHT $WIDTH
    		exit 1
    	fi
	
    	INET_DEV=`cat $TMP`

    	# if no selected is made print an error and return to the menu
    	if [ "$INET_DEV" = "" ] || [ "$INET_DEV" = " " ]; then
    		dialog	--backtitle "$BACKTITLE" \
    			--msgbox "No interface selected." $HEIGHT $WIDTH
        else
            # handle manual interface entry
    	    if [ "$INET_DEV" = "manual" ]; then
                EnterInternetInterfaceSetup
                bash $TMPCMD 2> $TMP

    	        INET_DEV=`cat $TMP`
    	        if [ "$INET_DEV" = "" ] || [ "$INET_DEV" = " " ]; then
            		dialog	--backtitle "$BACKTITLE" \
            			--msgbox "No interface entered." $HEIGHT $WIDTH
                else
                    INET_DEV_DYNAMIC="1"
                    DONE="1"
                fi
            else
                SelectInternetInterfaceDynamicSetup $INET_DEV
            	bash $TMPCMD 2> $TMP
                if [ $? = 0 ]; then
                    INET_DEV_DYNAMIC="1"
                fi
        		DONE="1"
            fi
    	fi
    done

    INET_INT=`GetInternetInterfaceName $INET_DEV`
    CreateInternetInterface $INET_INT $INET_DEV

    echo "# Updating network $INTERNET with interface $INET_INT..." >> $CMD
    echo "$VMS --modify --network $INTERNET --variable INTERFACE --set $INET_INT  --overwrite" >> $CMD
}

function SelectLanInterface
{
    # create the temp script to select the interface
    #
    SelectLanInterfaceSetup
    #
    # run it until we have a valid answer
    DONE=0
    while [ "$DONE" = "0" ]; do
    	bash $TMPCMD 2> $TMP
    	if [ $? != 0 ]; then
    		dialog	--backtitle "$BACKTITLE" \
    			--msgbox "FIXME: cancel at select LAN interface." $HEIGHT $WIDTH
    		exit 1
    	fi
	
    	LAN_DEV=`cat $TMP`

    	# if no selected is made print an error and return to the menu
    	if [ "$LAN_DEV" = "" ] || [ "$LAN_DEV" = " " ]; then
    		dialog	--backtitle "$BACKTITLE" \
    			--msgbox "No interface selected." $HEIGHT $WIDTH
    	else
    		DONE="1"	
    	fi
    done

    if [ "$LAN_DEV" != "none" ]; then
        SelectLanInterfaceDynamicSetup $LAN_DEV
    	bash $TMPCMD 2> $TMP
        if [ $? = 0 ]; then
            LAN_DEV_DYNAMIC="1"
        fi

        LAN_INT=`GetLanInterfaceName $LAN_DEV`
        CreateLanInterface $LAN_INT $LAN_DEV

        CreateLanNetwork $LAN_DEV

        echo "# Updating network $LAN with interface $LAN_INT..." >> $CMD
        echo "$VMS --modify --network $LAN --variable INTERFACE --set $LAN_INT  --overwrite" >> $CMD
        HAVE_LAN=1
    else
        HAVE_LAN=0
    fi
}


#
# RULES
#

function InitRules
{
    # first clear the rules
    echo "" >> $CMD
    echo "# Clearing existing rules..." >> $CMD
    echo "$VMS --modify --rules rules --overwrite --variable RULES --set \"\"" >> $CMD
}

function SelectForwardingRules
{
    # outgoing
    dialog --backtitle "$BACKTITLE" --title "[ LAN -> INTERNET: Forwarding Rules ]" --checklist "\nSelect FORWARDING Services to be enabled. These rules define the services the machines on the lan can visit on the internet." $HEIGHT $WIDTH 0 \
	"dns" "domain name system" ON \
	"http" "normal web browsing" ON \
	"https" "ssl/secure web browsing" ON \
	"ftp" "file transfer protocol" ON \
	"pop3" "email retrieval" OFF \
	"imap" "remote email management" OFF \
	"ssh" "secure remote shell access" OFF \
	"snat" "Apply Source NAT to the enabled services " ON \
	2> $TMP

    echo "" >> $CMD
    echo "# FORWARDING Rules..." >> $CMD
    echo "$VMS --modify --rules rules --append --variable RULE --set \"separator options comment=\\\"FORWARDING rules\\\"\"" >> $CMD
    for rawservice in `cat $TMP`; do
    	SERVICE=`stripit $rawservice`
        if [ "$SERVICE" = "snat" ]; then
    	    echo "$VMS --modify --rules rules --append --variable RULE --set \"snat service any from $LAN to $INTERNET\"" >> $CMD
        else
    	    echo "$VMS --modify --rules rules --append --variable RULE --set \"accept service $SERVICE from $LAN to $INTERNET options log,loglimit=\\\"1\\\"\"" >> $CMD
        fi
    done
}

function SelectOutgoingRules
{
    # outgoing
    dialog --backtitle "$BACKTITLE" --title "[ FIREWALL: Outgoing Rules ]" --checklist "\nSelect OUTGOING Services to be enabled. These rules define the services the firewall machine itself is allowed to use." $HEIGHT $WIDTH 0 \
	"dns" "domain name system" ON \
	"http" "normal web browsing" ON \
	"https" "ssl/secure web browsing" ON \
	"ftp" "file transfer protocol" ON \
	"pop3" "email retrieval" OFF \
	"imap" "remote email management" OFF \
	"ssh" "secure remote shell access" OFF \
	2> $TMP

    echo "" >> $CMD
    echo "# OUTGOING Rules..." >> $CMD
    echo "$VMS --modify --rules rules --append --variable RULE --set \"separator options comment=\\\"OUTGOING rules\\\"\"" >> $CMD
    for rawservice in `cat $TMP`; do
    	SERVICE=`stripit $rawservice`
    	echo "$VMS --modify --rules rules --append --variable RULE --set \"accept service $SERVICE from firewall to $INTERNET options log,loglimit=\\\"1\\\"\"" >> $CMD
    done
}

function SelectIncomingInternetRules
{
    # incoming
    dialog --backtitle "$BACKTITLE" --title "[ FIREWALL: Incoming Rules ]" --checklist "\nSelect INCOMING Services to be enabled from the Internet" $HEIGHT $WIDTH 0 \
	    "ssh" "secure remote shell access" OFF \
	    2> $TMP

    echo "" >> $CMD
    echo "# INCOMING Rules..." >> $CMD
    echo "$VMS --modify --rules rules --append --variable RULE --set \"separator options comment=\\\"INCOMING rules\\\"\"" >> $CMD
    for rawservice in `cat $TMP`; do
	    SERVICE=`stripit $rawservice`
	    echo "$VMS --modify --rules rules --append --variable RULE --set \"accept service $SERVICE from $INTERNET to firewall options log,loglimit=\\\"1\\\"\"" >> $CMD
    done
}

#
#
######################## start ############################
#
#
DIALOG=`which dialog` || {
    echo "Error: this script requires to the 'dialog' program to be installed."
    exit 1
}

ID_PROG="$(which id 2>/dev/null || echo /usr/bin/id)"
if [ "`$ID_PROG -g`" != "0" ]; then
    echo "Error: this script requires to be run as user root."
    exit 1
fi

InitTempfiles
DisplayInitialWarning

CreateZones

CreateInternetNetwork
SelectInternetInterface

SelectLanInterface

InitRules
SelectOutgoingRules
SelectIncomingInternetRules
if [ $HAVE_LAN = "1" ]; then
    SelectForwardingRules
fi

# display the script with vuurmuur_script commands
#cat $CMD

echo ""
echo "The commands the wizard creates are not yet automatically executed. See $CMD for the script that is created."

