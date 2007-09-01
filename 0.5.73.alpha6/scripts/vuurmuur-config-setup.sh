#!/bin/sh

#
# 2005-06-19:	victor	initial version
# 2005-06-20:	adi	usage, root-check, commandline checks
#
# this script must be called with three arguments:
# 1. the etcdir, e.g. /usr/local/etc/vuurmuur
# 2. the sample configfile, that will be copied if no config exists
# 3. the directory containing example services, e.g. /usr/local/share/vuurmuur/services
#
# Script to setup the initial configuration layout.
# It does the following:
# - check if $ETCDIR exists, and create it if it doesn't
# - check if $ETCDIR/config.conf exists and copy the sample if not.
# - check if the plugin-etc dir is properly setup
# - check if the textdir.conf exists
# - check if the backend dirs are properly setup


# define useful functions
exit_message() {
	echo $1
	exit 1
}

usage() {
	echo "Usage: $0 ETCDIR SAMPLE_CONF SERVICES_DIR"
}

# check arguments (TODO: check if they are valid!)
if [ $# -ne 3 ]; then
	usage
	exit 1
fi

# we take three args.
ETCDIR="$1"
CONFIGSAMPLE="$2"
SERVICES="$3"

# check for root (and display a warning for now)
if [ $(id -u) -ne 0 ]; then
	echo "WARNING: You are NOT root; some operations may not work..."
	exit 1
fi

# if the prefix is /usr, we use /etc instead of /usr/etc
if [ "$ETCDIR" = "/usr/etc/vuurmuur" ] || [ "$ETCDIR" = "/usr/etc/vuurmuur/" ]; then
	ETCDIR="/etc/vuurmuur"
fi

# test for the existence of the ETCDIR
if [ ! -d "$ETCDIR" ]; then
	# create it
	mkdir -p -m 0700 $ETCDIR || exit_message "error creating $ETCDIR"
fi

# test for the configfile
FILE="$ETCDIR/config.conf"

if [ ! -f "$FILE" ]; then
	# first check if the sample file exists
	if [ ! -f "$CONFIGSAMPLE" ]; then
		exit_message "error: sample configfile not found"
	fi

	cp "$CONFIGSAMPLE" "$FILE" || exit_message "error copying $CONFIGSAMPLE"
	chmod 0600 "$FILE" || exit_message "error chmodding $FILE"
fi

# test for plugin etc
DIR="$ETCDIR/plugins"

if [ ! -d "$DIR" ]; then
	# create it
	mkdir -p -m 0700 "$DIR" || exit_message "error creating $DIR"
fi

#
FILE="$ETCDIR/plugins/textdir.conf"

if [ ! -f "$FILE" ]; then
	touch "$FILE" || exit_message "error creating $FILE"
	chmod 0600 "$FILE" || exit_message "error chmodding $FILE"
	echo "LOCATION=\"$ETCDIR/textdir\"" > "$FILE"
fi

# backend dirs
DIR="$ETCDIR/textdir"

if [ ! -d "$DIR" ]; then
	# create it
	mkdir -p -m 0700 "$DIR" || exit_message "error creating $DIR"
fi

# zones
DIR="$ETCDIR/textdir/zones"

if [ ! -d "$DIR" ]; then
	# create it
	mkdir -p -m 0700 "$DIR" || exit_message "error creating $DIR"
fi

# interfaces
DIR="$ETCDIR/textdir/interfaces"

if [ ! -d "$DIR" ]; then
	# create it
	mkdir -p -m 0700 "$DIR" || exit_message "error creating $DIR"
fi

# rules
DIR="$ETCDIR/textdir/rules"

if [ ! -d "$DIR" ]; then
	# create it
	mkdir -p -m 0700 "$DIR" || exit_message "error creating $DIR"
fi

# services
DIR="$ETCDIR/textdir/services"

if [ ! -d "$DIR" ]; then
	# create it
	mkdir -p -m 0700 "$DIR" || exit_message "error creating $DIR"

	# see if we can find the sample services
	if [ ! -d "$SERVICES" ]; then
		exit_message "error: sample services not found"
	fi

	cp --recursive $SERVICES/* $DIR/ || exit_message "error copying $SERVICES"
	chmod --recursive 0600 $DIR || exit_message "error chmodding $DIR"
fi

# exitcode 0 so the caller knows we are ok.
exit 0
