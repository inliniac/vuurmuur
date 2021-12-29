#!/bin/bash

VERSION="0.8.1"

# needs: file, sort, cat, zcat, grep

LOGNAME="$1"
DIRNAME="$2"
SEARCHSTRING="$3"

CAT="`which cat`"
ZCAT="`which zcat`"
GREP="`which grep`"
SORT="`which sort`"
FILE="`which file`"

# check for cat
if [ ! -f $CAT ]; then
    echo "SL:ERROR: the command $CAT was not found."
    exit 1
fi

# check for zcat
if [ ! -f $ZCAT ]; then
    echo "SL:ERROR: the command $ZCAT was not found."
    exit 1
fi

# check for grep
if [ ! -f $GREP ]; then
    echo "SL:ERROR: the command $GREP was not found."
    exit 1
fi

# check for sort
if [ ! -f $SORT ]; then
    echo "SL:ERROR: the command $SORT was not found."
    exit 1
fi

# check for file
if [ ! -f $FILE ]; then
    echo "SL:ERROR: the command $FILE was not found."
    exit 1
fi

function GetFileType
{
    CHECK_FILE=$1
    echo `file -b $CHECK_FILE | cut -d " " -f 1`
}

if [ ! -f "$DIRNAME/$LOGNAME" ]; then
    echo "SL:ERROR: The file \"$DIRNAME/$LOGNAME\" does not exist."
    exit 1
fi

# get the files and sort them reverse order: that means oldest first.
LOGFILES=`ls $DIRNAME | grep $LOGNAME | sort -sr`

for LOGFILE in `echo "$LOGFILES"`; do
    TYPE=`GetFileType "$DIRNAME/$LOGFILE"`
    
    #echo "TYPE $TYPE."
    
    if [ "$TYPE" = "ASCII" ]; then
	cat "$DIRNAME/$LOGFILE" | grep "$SEARCHSTRING"
    elif [ "$TYPE" = "gzip" ]; then
	zcat "$DIRNAME/$LOGFILE" | grep "$SEARCHSTRING"
    fi
done

echo "SL:EOF: search done"
exit 0
