#!/bin/sh

# This is an implementation of a start-script for Vuurmuur.
#
# (c) 2004 Victor Julien, released under GPL.

# Make RedHat happy:
#
# chkconfig: 345 91 9
# Description: Vuurmuur is a firewall.
#

# where do the executables reside? NOTE: no trailing slash
VUURMUUR_LOCATION=/usr/bin

# space separated list of modules to load on start, or 'none' if none ;-)
MODULES_TO_LOAD="ip_tables iptable_filter iptable_mangle iptable_nat ip_conntrack ipt_state ip_conntrack_ftp ip_nat_ftp ip_queue"
#MODULES_TO_LOAD="none"

PATH=/bin:/usr/bin:/sbin:/usr/sbin

case "$1" in
	start)
		echo "Starting firewall: Vuurmuur:"

		# check if vuurmuur is configured
		IFNUM=`$VUURMUUR_LOCATION/vuurmuur_script --list --interface any | wc -l`
		if [ "$IFNUM" = "0" ]; then
			echo "FAILED: please configure Vuurmuur first by defining at least one interface."
			exit 1
		fi

		echo -n -e "\tLoading modules:\t"
		if [ "$MODULES_TO_LOAD" == "none" ]; then
			echo "disabled."
		else
			# load the modules
			for MODULE in `echo $MODULES_TO_LOAD`; do
				modprobe $MODULE
				echo -n "$MODULE "
			done
			echo ""
		fi
	
		echo -n -e "\tLoading Vuurmuur:\t"
		# start vuurmuur
		if [ ! -f /var/run/vuurmuur.pid ]; then
			$VUURMUUR_LOCATION/vuurmuur -l
			RESULT="$?"
			if [ "$RESULT" = "0" ]; then
			    echo "ok."
			else
			    echo "FAILED."
			fi
		else
			PID=`cat /var/run/vuurmuur.pid | cut -d " " -f 1`
			echo "FAILED: already running at pid $PID."
		fi
		
		echo -n -e "\tLoading Vuurmuur_log:\t"
		# start vuurmuur_log
		if [ ! -f /var/run/vuurmuur_log.pid ]; then
			$VUURMUUR_LOCATION/vuurmuur_log
			RESULT="$?"
			if [ "$RESULT" = "0" ]; then
			    echo "ok."
			else
			    echo "FAILED."
			fi
		else
			PID=`cat /var/run/vuurmuur_log.pid | cut -d " " -f 1`
			echo "FAILED: already running at pid $PID."
		fi
	
		echo "Starting firewall: Vuurmuur: done"
		;;
	stop)
                echo "Stopping firewall Vuurmuur:"
                echo -n -e "\tVuurmuur:\t"
                if [ $(pidof vuurmuur) ]; then
                  kill -n INT `pidof vuurmuur`
                  echo "stopped."
                else
                  echo "not running."
                fi
                echo -n -e "\tVuurmuur_log:\t"
                if [ $(pidof vuurmuur_log) ]; then
                  kill -n INT `pidof vuurmuur_log`
                  echo "stopped."
                else
                  echo "not running."
                fi
                echo "Stopping firewall Vuurmuur: done."
                ;;
	force-reload|restart)
		$0 stop
		$0 start
		;;
	*)
		echo "Usage: /etc/init.d/vuurmuur {start|stop|restart|force-reload}"
		exit 1
esac

exit 0
