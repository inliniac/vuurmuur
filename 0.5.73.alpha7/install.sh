#!/bin/sh

# Installscript for libvuurmuur, vuurmuur and vuurmuur_conf.
#
# TODO: setup an initial configuration that works for most
# setups.
#
# Copyright (c) 2004-2006 by Victor Julien
# Licenced under the GPL.
#
VERSION="0.5.73.alpha7"

# progams
ACLOCAL="aclocal"
ACLOCAL19="aclocal-1.9"
AUTOMAKE="automake"
AUTOMAKE19="automake-1.9"
AUTOCONF="autoconf"
AUTOHEADER="autoheader"
MAKE="make"
LIBTOOLIZE="libtoolize"


# defaults
INSTALLDIR="/usr"
SHAREDDIR="$INSTALLDIR/share"
ETCDIR="/etc"
PLUGINDIR="$ETCDIR/vuurmuur/plugins"
LOGDIR="/var/log/vuurmuur/"
SYSTEMLOG="/var/log/messages"

CURPATH=`pwd`
LOG="$CURPATH/install.log"

# major
INSTALL="0"
UPGRADE="0"
UNINSTALL="0"
DRYRUN="0"
UNPACK="0"

# minor
NOUNPACK="0"
DEFAULTS="0"
VERBOSE="1"
DEBUG="0"
WIDEC="0"

if [ "$EUID" != "0" ]; then
    echo "Error: this script requires to be run as user root."
    exit 1
fi

# initialize the log
echo "Vuurmuur installer starting... (version $VERSION)" > $LOG


function Exit
{
    RETVAL="$1"
    
    # gathering some system info
    echo >> $LOG
    echo "---" >> $LOG
    echo >> $LOG
    echo >> $LOG
    echo "Getting some info about the system." >> $LOG
    echo >> $LOG
    echo "gcc:" >> $LOG
    gcc --version >> $LOG
    echo "libtoolize:" >> $LOG
    $LIBTOOLIZE --version >> $LOG
    echo "make:" >> $LOG
    $MAKE --version >> $LOG
    echo "aclocal:" >> $LOG
    $ACLOCAL --version >> $LOG
    echo "aclocal-1.9:" >> $LOG
    $ACLOCAL19 --version >> $LOG
    echo "autoheader:" >> $LOG
    $AUTOHEADER --version >> $LOG
    echo "automake:" >> $LOG
    $AUTOMAKE --version >> $LOG
    echo "automake-1.9:" >> $LOG
    $AUTOMAKE19 --version >> $LOG
    echo "autoconf:" >> $LOG
    $AUTOCONF --version >> $LOG
    echo >> $LOG
    uname -a >> $LOG
    
    echo
    echo
    echo "Installation Failed"
    echo "==================="
    echo
    echo "Please take a look at install.log. If you can't solve the problem"
    echo "mail me at victor@vuurmuur.org. Please include the install.log."
    echo

    exit $RETVAL
}

function PrintL
{
    if [ "$VERBOSE" = "1" ]; then
	echo "$1"
    fi

    echo "$1" >> $LOG
}

function ExitMessage
{
    PrintL "$1"
    Exit 1
}



function Cp
{
    cp $1 $2 $3 &> tmp.log
    RESULT="$?"
    if [ "$RESULT" = "0" ]; then
	if [ "$DEBUG" = "1" ]; then
	    PrintL "Cp succeeded."
	fi
    else
	PrintL "cp $1 $2 $3 failed with returncode $RESULT."
	cat tmp.log >> $LOG
	rm -f tmp.log
	Exit 1
    fi

    rm -f tmp.log
}

function Cd
{
    CUR=`pwd`

    cd $1 &> tmp.log
    RESULT="$?"
    if [ "$RESULT" = "0" ]; then
	if [ "$DEBUG" = "1" ]; then
	    PrintL "Cd succeeded."
	fi
    else
	PrintL "cd $1 failed with returncode $RESULT."
	cat tmp.log >> $LOG
	rm -f tmp.log
	Exit 1
    fi

    rm -f $CUR/tmp.log
}

function Libtoolize
{
    touch tmp.log
    $LIBTOOLIZE $1 &> tmp.log
    RESULT="$?"
    cat tmp.log >> $LOG
    rm -f tmp.log
    if [ "$RESULT" = "0" ]; then
	if [ "$DEBUG" = "1" ]; then
	    PrintL "Libtoolize succeeded."
	fi
    else
	PrintL "libtoolize $1 failed with returncode $RESULT."
	Exit 1
    fi
}

function Make
{
    touch tmp.log
    $MAKE $1 $2 &> tmp.log
    RESULT="$?"
    cat tmp.log >> $LOG
    rm -f tmp.log
    if [ "$RESULT" = "0" ]; then
	if [ "$DEBUG" = "1" ]; then
	    PrintL "Make succeeded."
	fi
    else
	PrintL "make $1 $2 failed with returncode $RESULT."
	Exit 1
    fi
}

function Aclocal
{
    touch tmp.log
    $ACLOCAL19 &> tmp.log
    RESULT="$?"
    cat tmp.log >> $LOG
    rm -f tmp.log
    if [ "$RESULT" = "0" ]; then
	if [ "$DEBUG" = "1" ]; then
	    PrintL "Aclocal-1.9 succeeded."
	fi
    else
        touch tmp.log
        $ACLOCAL &> tmp.log
        RESULT="$?"
        cat tmp.log >> $LOG
        rm -f tmp.log
        if [ "$RESULT" = "0" ]; then
            if [ "$DEBUG" = "1" ]; then
                PrintL "Aclocal succeeded."
            fi
        else
            PrintL "aclocal failed with returncode $RESULT."
            Exit 1
        fi
    fi
}

function Autoheader
{
    touch tmp.log
    $AUTOHEADER &> tmp.log
    RESULT="$?"
    cat tmp.log >> $LOG
    rm -f tmp.log
    if [ "$RESULT" = "0" ]; then
	if [ "$DEBUG" = "1" ]; then
	    PrintL "Autoheader succeeded."
	fi
    else
	PrintL "autoheader failed with returncode $RESULT."
	Exit 1
    fi
}

function Automake
{
    touch tmp.log
    $AUTOMAKE19 &> tmp.log
    RESULT="$?"
    cat tmp.log >> $LOG
    rm -f tmp.log
    if [ "$RESULT" = "0" ]; then
	if [ "$DEBUG" = "1" ]; then
	    PrintL "Automake-1.9 succeeded."
	fi
    else
        touch tmp.log
        $AUTOMAKE &> tmp.log
        RESULT="$?"
        cat tmp.log >> $LOG
        rm -f tmp.log
        if [ "$RESULT" = "0" ]; then
            if [ "$DEBUG" = "1" ]; then
                PrintL "Automake succeeded."
            fi
        else
            PrintL "automake failed with returncode $RESULT."
            Exit 1
        fi
    fi
}

function Autoconf
{
    touch tmp.log
    $AUTOCONF &> tmp.log
    RESULT="$?"
    cat tmp.log >> $LOG
    rm -f tmp.log
    if [ "$RESULT" = "0" ]; then
	if [ "$DEBUG" = "1" ]; then
	    PrintL "Autoconf succeeded."
	fi
    else
	PrintL "autoconf failed with returncode $RESULT."
	Exit 1
    fi
}

function Configure
{
    touch tmp.log
    ./configure $1 $2 $3 $4 &> tmp.log
    RESULT="$?"
    cat tmp.log >> $LOG
    rm -f tmp.log
    if [ "$RESULT" = "0" ]; then
	if [ "$DEBUG" = "1" ]; then
	    PrintL "configure $1 $2 $3 $4 succeeded."
	fi
    else
	PrintL "./configure $1 $2 $3 $4 failed with returncode $RESULT."
	Exit 1
    fi
}

function WrapGettextize
{
    touch tmp.log

    GETTEXTIZE=`which gettextize`
    if [ "$GETTEXTIZE" = "" ]; then
	GETTEXTIZE="gettextize"
    fi

    echo "gettextize..." >> $LOG
    # ripped from: http://cvs.saout.de/lxr/saout/source/cryptsetup/setup-gettext
    sed 's:read .*< /dev/tty::' $GETTEXTIZE > .temp-gettextize
    chmod +x .temp-gettextize
    echo n | ./.temp-gettextize --copy --force --intl --no-changelog >> $LOG || abort
    rm -f .temp-gettextize
    echo "gettextize... done" >> $LOG

    cat tmp.log >> $LOG
    rm -f tmp.log
}

function CheckFile
{
    if [ ! -f $1 ]; then
	PrintL "Error! Missing file: $1!"
	exit 1
    else
	if [ "$DEBUG" = "1" ]; then
    	    PrintL "Good! $1 exists."
	fi
    fi
}

function UnPack
{
    touch tmp.log
    gzip -cd $1 | tar -xvf - >> $LOG
    RESULT="$?"
    cat tmp.log >> $LOG
    rm -f tmp.log
    if [ "$RESULT" = "0" ]; then
	if [ "$DEBUG" = "1" ]; then
	    PrintL "UnPack $1 succeeded."
	fi
    else
	PrintL "UnPack $1 failed with returncode $RESULT."
	Exit 1
    fi
}

function RevCheckDir
{
    cd $1 &> /dev/null
    RESULT="$?"
    if [ "$RESULT" = "0" ]; then
	PrintL "Error: the directory '$1' already exists."
	cd $CURPATH
	Exit 1
    fi
}

function CheckDir
{
    cd $1 &> /dev/null
    RESULT="$?"
    if [ "$RESULT" != "0" ]; then
	PrintL "Error: the directory '$1' doesn't exist."
	Exit 1
    fi

    cd $CURPATH
}

function MkDir
{
    mkdir $1 &> /dev/null
    RESULT="$?"
    if [ "$RESULT" != "0" ]; then
	PrintL "Error: the directory '$1' could not be created."
	Exit 1
    fi
}


function CheckBinary
{
    which $1 &> /dev/null
    RESULT=$?
    if [ "$RESULT" = "0" ]; then
	if [ "$DEBUG" = "1" ]; then
	    PrintL "The command '$1' was found."
	fi
    elif [ "$RESULT" = "1" ]; then
	PrintL "The command '$1' was not found in the PATH."
	Exit 1
    elif [ "$RESULT" = "127" ]; then
	PrintL "the command 'which' seems to be missing."
    else
	PrintL "'which' gave a weird returncode $RESULT while checking $1."
    fi
}


function CheckRequiredBins
{
    CheckBinary $ACLOCAL
    CheckBinary $AUTOMAKE
    CheckBinary $AUTOCONF
    CheckBinary $AUTOHEADER
    CheckBinary gcc
    CheckBinary $MAKE
}


# minor options (handled first so debug can be used asap).
if [ "$1" = "--debug" ] || [ "$2" = "--debug" ] || [ "$3" = "--debug" ] || [ "$4" = "--debug" ]; then
    DEBUG="1"
    PrintL "Commandline option '--debug' enabled."
fi
if [ "$1" = "--defaults" ] || [ "$2" = "--defaults" ] || [ "$3" = "--defaults" ] || [ "$4" = "--defaults" ]; then
    DEFAULTS="1"
    if [ "$DEBUG" = "1" ]; then
	PrintL "Commandline option '--defaults' enabled."
    fi
fi
if [ "$1" = "--nounpack" ] || [ "$2" = "--nounpack" ] || [ "$3" = "--nounpack" ] || [ "$4" = "--nounpack" ]; then
    NOUNPACK="1"
    if [ "$DEBUG" = "1" ]; then
	PrintL "Commandline option '--nounpack' enabled."
    fi
fi
if [ "$1" = "--widec" ] || [ "$2" = "--widec" ] || [ "$3" = "--widec" ] || [ "$4" = "--widec" ]; then
    WIDEC="1"
    if [ "$DEBUG" = "1" ]; then
	PrintL "Commandline option '--widec' enabled."
    fi
fi


# commandline options
if [ "$1" = "--dryrun" ] || [ "$2" = "--dryrun" ] || [ "$3" = "--dryrun" ] || [ "$4" = "--dryrun" ]; then
    DRYRUN="1"
    if [ "$DEBUG" = "1" ]; then
	PrintL "Commandline option '--dryrun' enabled."
    fi
fi
if [ "$1" = "--install" ] || [ "$2" = "--install" ] || [ "$3" = "--install" ] || [ "$4" = "--install" ]; then
    INSTALL="1"
    if [ "$DEBUG" = "1" ]; then
	PrintL "Commandline option '--install' enabled."
    fi
fi
if [ "$1" = "--upgrade" ] || [ "$2" = "--upgrade" ] || [ "$3" = "--upgrade" ] || [ "$4" = "--upgrade" ]; then
    UPGRADE="1"
    if [ "$DEBUG" = "1" ]; then
	PrintL "Commandline option '--upgrade' enabled."
    fi
fi
if [ "$1" = "--uninstall" ] || [ "$2" = "--uninstall" ] || [ "$3" = "--uninstall" ] || [ "$4" = "--uninstall" ]; then
    UNINSTALL="1"
    if [ "$DEBUG" = "1" ]; then
        PrintL "Commandline option '--uninstall' enabled."
    fi
fi
if [ "$1" = "--unpack" ] || [ "$2" = "--unpack" ] || [ "$3" = "--unpack" ] || [ "$4" = "--unpack" ]; then
    UNPACK="1"
    if [ "$DEBUG" = "1" ]; then
	PrintL "Commandline option '--unpack' enabled."
    fi
fi


# if none of the main options is selected, print help and exit.
if  [ "$DRYRUN" = "0" ] && 
    [ "$INSTALL" = "0" ] && 
    [ "$UPGRADE" = "0" ] && 
    [ "$UNINSTALL" = "0" ] && 
    [ "$UNPACK" = "0" ]; then

    echo
    echo "Help for Vuurmuur-installer."
    echo
    echo "Commandline options:"
    echo
    echo " Main options:"
    echo
    echo "	--install	install and setup up the config"
    echo "	--upgrade	install without touching the config"
    echo "	--uninstall	uninstall but leave the config alone"
    echo "	--unpack	unpack the archives"
    echo
    echo " Sub options:"
    echo
    echo "	--defaults	use the default values for all questions"
    echo "	--debug		print some extra info for debugging the install script"
    echo "	--nounpack	don't unpack, use the already unpacked archives"
    echo "	--widec		use widec support in vuurmuur_conf (utf-8)"
    echo
    echo "Please read INSTALL for more information."
    echo
    exit 0
fi

# check that only one major option is selected.
TOTAL=$((DRYRUN + INSTALL + UPGRADE + UNINSTALL + UNPACK))
if [ "$TOTAL" -gt "1" ]; then
    echo "Error: please select only one main option."
    exit 0
fi

# now print some initial info for the main option that is selected
if [ "$INSTALL" = "1" ]; then
    echo
    echo "Vuurmuur installation"
    echo "====================="
    echo
    echo "Welcome to the installation of Vuurmuur. First you will be"
    echo "asked a couple of questions about the location to install the"
    echo "various parts of Vuurmuur. It is recommended that you choose"
    echo "the defaults, by pressing just enter."
    echo
elif [ "$UPGRADE" = "1" ]; then
    echo
    echo "Vuurmuur installation (upgrade)"
    echo "==============================="
    echo
    echo "Welcome to the installation of Vuurmuur. First you will be"
    echo "asked a couple of questions about the location to install the"
    echo "various parts of Vuurmuur. Make sure that you point to the"
    echo "existing paths."
    echo
fi


# check the bins needed for compiling
if [ "$INSTALL" = "1" ] || [ "$UPGRADE" = "1" ]; then
    CheckRequiredBins
fi


# installdir
if [ "$INSTALL" = "1" ] || [ "$UPGRADE" = "1" ]; then

    if [ "$DEFAULTS" = "0" ]; then
	# get the installdir
	echo "Please enter the installation dir ($INSTALLDIR)."
	read TALK
	if [ "$TALK" != "" ]; then
	    INSTALLDIR="$TALK"
	fi
    fi
    PrintL "Installdir: $INSTALLDIR ..."
    
    cd $INSTALLDIR &> /dev/null
    RESULT="$?"
    if [ "$RESULT" = "0" ]; then
	Cd $CURPATH
    else
	MkDir $INSTALLDIR
    fi

    SHAREDDIR="$INSTALLDIR/share"
fi

# etcdir
if [ "$INSTALL" = "1" ] || [ "$UPGRADE" = "1" ]; then

    if [ "$DEFAULTS" = "0" ]; then
	if [ "$UPGRADE" = "1" ]; then
	    echo
	    echo "Please enter the current base config directory ($ETCDIR)."
	    echo
	    echo "NOTE!!! in this directory a directory 'vuurmuur' must exist. This behaviour"
	    echo "has been changed in 0.5.65 (so for '/etc/vuurmuur' choose '/etc' here)."
	    echo
	    echo "Examples: /etc, /usr/local/etc, /opt/vuurmuur/etc"
	    echo
	elif [ "$INSTALL" = "1" ]; then
	    echo
    	    echo "Please enter the directory where the config is going to be stored ($ETCDIR)."
	    echo
	    echo "NOTE!!! in this directory a directory 'vuurmuur' will be created. This behaviour"
	    echo "has been changed in 0.5.65 (so for '/etc/vuurmuur' choose '/etc' here)."
	    echo
	    echo "Examples: /etc, /usr/local/etc, /opt/vuurmuur/etc"
	    echo
	fi

	read TALK
	if [ "$TALK" != "" ]; then
    	    ETCDIR="$TALK"
	fi

    fi
    PrintL "Using Etcdir: '$ETCDIR/vuurmuur'."

    # try to backup the etc dir
    if [ "$UPGRADE" = "1" ]; then
	echo
	echo "Backing up your current Vuurmuur configuration..."
        echo

        # create a backup of a previous version of vuurmuur
	if [ ! -d /root/backups ]; then
            mkdir /root/backups || \
                ExitMessage "error creating /root/backups"
            PrintL "backup directory /root/backups created."
        fi

        if [ ! -d /root/backups/vuurmuur ]; then
            mkdir /root/backups/vuurmuur || \
                ExitMessage "error creating /var/backups/vuurmuur"
            PrintL "backup directory /var/backups/vuurmuur created."
        fi

        BACKUP_DIR="/root/backups/vuurmuur/upgrade-$(date +'%Y.%m.%d-%H.%M')"

        if [ ! -d $BACKUP_DIR ]; then
            mkdir ${BACKUP_DIR} || \
                ExitMessage "error creating ${BACKUP_DIR}"
            PrintL "backup directory ${BACKUP_DIR} created."
    	else
            ExitMessage "error: directory ${BACKUP_DIR} already exists?! -- I am confused!"
        fi

        # set strict permissions on our backup since it contains sensitive data
        chmod 0700 ${BACKUP_DIR} || \
            ExitMessage "settings permissions on backup directory failed!"
        PrintL "changed permissions of ${BACKUP_DIR} to 0700."

        if [ -d $ETCDIR/vuurmuur ]; then
            cp -a $ETCDIR/vuurmuur/* ${BACKUP_DIR} || \
                ExitMessage "copying vuurmuur configuration failed!"
            PrintL "copied vuurmuur configuration to ${BACKUP_DIR}."
        else
            PrintL "no vuurmuur config found (no $ETCDIR/vuurmuur directory)!"
        fi

	echo
	echo "Backing up your current Vuurmuur configuration complete."
        echo
    fi

    # update plugin dir
    PLUGINDIR="$ETCDIR/vuurmuur/plugins/"

    if [ "$UPGRADE" = "1" ]; then
        CheckDir "$ETCDIR/vuurmuur"
    elif [ "$INSTALL" = "1" ]; then
        #RevCheckDir "$ETCDIR/vuurmuur"

	# create the vuurmuur dir and the textdir
	mkdir -p -m 0700 "$ETCDIR/vuurmuur/textdir"
	mkdir -p -m 0700 "$ETCDIR/vuurmuur/plugins"
    fi
fi

# logdir
if [ "$INSTALL" = "1" ]; then

    if [ "$DEFAULTS" = "0" ]; then
        echo
	echo "Please enter the directory where Vuurmuur will store it's logs ($LOGDIR)."

	read TALK
	if [ "$TALK" != "" ]; then
    	    LOGDIR="$TALK"
	fi
    fi	
    PrintL "Using Logdir: '$LOGDIR'."
	
    cd $LOGDIR &> /dev/null
    RESULT="$?"
    if [ "$RESULT" != "0" ]; then
        MkDir $LOGDIR
        chmod 0700 $LOGDIR
    fi
	    
    cd $CURPATH
fi


# unpack
if [ "$INSTALL" = "1" ] || [ "$UPGRADE" = "1" ] || [ "$UNPACK" = "1" ]; then

    if [ "$UNPACK" = "0" ]; then
	echo
	echo "Ok, thank you. Going to build Vuurmuur now. Depending on your hardware"
	echo "this process will take about 2 to 10 minutes."
	echo
    fi

    if [ "$NOUNPACK" = "0" ]; then
        PrintL "Testing for the installation files..."
	CheckFile vuurmuur-$VERSION.tar.gz
	CheckFile libvuurmuur-$VERSION.tar.gz
	CheckFile vuurmuur_conf-$VERSION.tar.gz

	PrintL "Going to extract the files..."
	UnPack vuurmuur-$VERSION.tar.gz
	UnPack vuurmuur_conf-$VERSION.tar.gz
	UnPack libvuurmuur-$VERSION.tar.gz
	PrintL "Extracting the files done..."
    fi
fi

# build libvuurmuur
Cd libvuurmuur-$VERSION
if [ "$INSTALL" = "1" ] || [ "$UPGRADE" = "1" ]; then

    PrintL "Going to build libvuurmuur... (common code for all parts of Vuurmuur)."
    Libtoolize -f
    Aclocal
    Autoheader
    Automake
    Autoconf
    Configure --prefix=$INSTALLDIR --sysconfdir=$ETCDIR
    Make
    if [ "$DRYRUN" != "1" ]; then
	Make install

	if [ "$INSTALL" = "1" ]; then
	    touch $ETCDIR/vuurmuur/plugins/textdir.conf
	    chmod 0600 $ETCDIR/vuurmuur/plugins/textdir.conf
	    echo "LOCATION=\"$ETCDIR/vuurmuur/textdir\"" > $ETCDIR/vuurmuur/plugins/textdir.conf

	    chmod 0700 $ETCDIR/vuurmuur
	    chmod 0700 $ETCDIR/vuurmuur/plugins
	fi
    fi
    Make clean
    PrintL "Building and installing libvuurmuur finished."

elif [ "$UNINSTALL" = "1" ]; then

    PrintL "Going to uninstall libvuurmuur..."
    Make uninstall
    PrintL "Un-installing libvuurmuur finished."
fi
Cd ..


Cd vuurmuur-$VERSION
if [ "$INSTALL" = "1" ] || [ "$UPGRADE" = "1" ]; then
    PrintL "Going to build vuurmuur... (the daemons)."
    Libtoolize -f
    Aclocal
    Autoheader
    Automake
    Autoconf
    Configure --prefix=$INSTALLDIR --sysconfdir=$ETCDIR --with-libvuurmuur-includes=$INSTALLDIR/include --with-libvuurmuur-libraries=$INSTALLDIR/lib
    Make
    if [ "$DRYRUN" != "1" ]; then
	Make install
    fi
    Make clean
    PrintL "Building and installing vuurmuur finished."

elif [ "$UNINSTALL" = "1" ]; then

    PrintL "Going to uninstall vuurmuur..."
    Make uninstall
    PrintL "Un-installing vuurmuur finished."
fi
Cd ..


Cd vuurmuur_conf-$VERSION
if [ "$INSTALL" = "1" ] || [ "$UPGRADE" = "1" ]; then
    PrintL "Going to build vuurmuur_conf... (the Ncurses based user interface)."
    Libtoolize -f
    Aclocal
    WrapGettextize
    Autoheader
    Automake
    Autoconf

    if [ "$WIDEC" = "1" ]; then
	WIDESTR="yes"
    else
	WIDESTR="no"
    fi

    Configure --prefix=$INSTALLDIR \
		--sysconfdir=$ETCDIR \
		--with-libvuurmuur-includes=$INSTALLDIR/include \
		--with-libvuurmuur-libraries=$INSTALLDIR/lib \
		--with-widec=$WIDESTR
    Make
    if [ "$DRYRUN" != "1" ]; then
	Make install
    fi
    Make clean
    PrintL "Building and installing vuurmuur_conf finished."

elif [ "$UNINSTALL" = "1" ]; then

    PrintL "Going to uninstall vuurmuur_conf..."
    Make uninstall
    PrintL "Un-installing vuurmuur_conf finished."
fi
Cd ..


if [ "$INSTALL" = "1" ]; then

    echo
    echo "Setting up the Vuurmuur config for first-time use."

    mkdir -p -m 0700 $ETCDIR/vuurmuur/textdir
    chown root:root $ETCDIR/vuurmuur/textdir
    chmod 0700 $ETCDIR/vuurmuur/textdir
    
    if [ ! -d "$ETCDIR/vuurmuur/textdir/interfaces" ]; then
	MkDir $ETCDIR/vuurmuur/textdir/interfaces
	chown root:root $ETCDIR/vuurmuur/textdir/interfaces
	chmod 0700 $ETCDIR/vuurmuur/textdir/interfaces
    fi
    
    if [ ! -d "$ETCDIR/vuurmuur/textdir/services" ]; then
	MkDir $ETCDIR/vuurmuur/textdir/services
	chown root:root $ETCDIR/vuurmuur/textdir/services
	chmod 0700 $ETCDIR/vuurmuur/textdir/services
    
	cp $SHAREDDIR/vuurmuur/services/* $ETCDIR/vuurmuur/textdir/services/
        chown root:root $ETCDIR/vuurmuur/textdir/services -R
	chmod 0700 $ETCDIR/vuurmuur/textdir/services
    fi

    if [ ! -d "$ETCDIR/vuurmuur/textdir/zones" ]; then
	MkDir $ETCDIR/vuurmuur/textdir/zones
	chown root:root $ETCDIR/vuurmuur/textdir/zones
	chmod 0700 $ETCDIR/vuurmuur/textdir/zones

	cp -r --preserve=mode zones/* $ETCDIR/vuurmuur/textdir/zones
	chown root:root $ETCDIR/vuurmuur/textdir/zones -R
	chmod 0700 $ETCDIR/vuurmuur/textdir/zones
    fi

    if [ ! -d "$ETCDIR/vuurmuur/textdir/rules" ]; then
	MkDir $ETCDIR/vuurmuur/textdir/rules
        chown root:root $ETCDIR/vuurmuur/textdir/rules
        chmod 0700 $ETCDIR/vuurmuur/textdir/rules

        touch $ETCDIR/vuurmuur/textdir/rules/rules.conf
        chown root:root $ETCDIR/vuurmuur/textdir/rules/rules.conf
        chmod 0600 $ETCDIR/vuurmuur/textdir/rules/rules.conf

        touch $ETCDIR/vuurmuur/textdir/rules/blocklist.conf
        chown root:root $ETCDIR/vuurmuur/textdir/rules/blocklist.conf
        chmod 0600 $ETCDIR/vuurmuur/textdir/rules/blocklist.conf
    fi

    # create the config file
    CONFIGFILE="$ETCDIR/vuurmuur/config.conf"

    if [ ! -f "$CONFIGFILE" ]; then
	touch $CONFIGFILE
	chown root:root $CONFIGFILE
	chmod 0600 $CONFIGFILE

	# seek iptables
        which iptables &> /dev/null
        RESULT=$?
        if [ "$RESULT" = "0" ]; then
    	    IPTABLESLOC=`which iptables`
	else
	    echo
	    echo "Warning: could not find the location of the 'iptables' command. Please make sure you have"
	    echo "iptables installed and set it's location in the Vuurmuur config."
	    IPTABLESLOC="/sbin/iptables"
	fi

	# seek iptables-restore
	which iptables-restore &> /dev/null
	RESULT=$?
	if [ "$RESULT" = "0" ]; then
	    IPTABLESRESLOC=`which iptables-restore`
	else
	    echo
	    echo "Warning: could not find the location of the 'iptables-restore' command. Please make sure"
	    echo " you have iptables-restore installed and set it's location in the Vuurmuur config."
	    IPTABLESRESLOC="/sbin/iptables-restore"
	fi

	# seek modprobe
	which modprobe &> /dev/null
	RESULT=$?
	if [ "$RESULT" = "0" ]; then
	    MODPROBE=`which modprobe`
	else
	    echo
	    echo "Warning: could not find the location of the 'modprobe' command. Please make sure"
	    echo " you have modprobe installed and set it's location in the Vuurmuur config."
	    MODPROBE="/sbin/modprobe"
	fi

	# write the configfile
	echo "# begin of file" > $CONFIGFILE
	echo >> $CONFIGFILE

	echo "# Which plugin to use for which type of data." >> $CONFIGFILE
	echo "SERVICES_BACKEND=\"textdir\"" >> $CONFIGFILE
	echo "ZONES_BACKEND=\"textdir\"" >> $CONFIGFILE
	echo "INTERFACES_BACKEND=\"textdir\"" >> $CONFIGFILE
	echo "RULES_BACKEND=\"textdir\"" >> $CONFIGFILE
	echo >> $CONFIGFILE

	echo "# Location of the iptables-command (full path)." >> $CONFIGFILE
	echo "IPTABLES=\"$IPTABLESLOC\"" >> $CONFIGFILE
	echo "# Location of the iptables-restore-command (full path)." >> $CONFIGFILE
	echo "IPTABLES_RESTORE=\"$IPTABLESRESLOC\"" >> $CONFIGFILE
	echo >> $CONFIGFILE

	echo "# Location of the modprobe-command (full path)." >> $CONFIGFILE
	echo "MODPROBE=\"$MODPROBE\"" >> $CONFIGFILE
	echo "# Load modules if needed? (yes/no)" >> $CONFIGFILE
	echo "LOAD_MODULES=\"Yes\"" >> $CONFIGFILE
	echo "# Wait after loading a module in 1/10th of a second" >> $CONFIGFILE
	echo "MODULES_WAIT_TIME=\"0\"" >> $CONFIGFILE
	echo >> $CONFIGFILE

	echo "# If set to yes, each rule will be loaded into the system individually using" >> $CONFIGFILE
	echo "# iptables. Otherwise iptables-restore will be used (yes/no)." >> $CONFIGFILE
	echo "OLD_CREATE_METHOD=\"No\"" >> $CONFIGFILE
	echo >> $CONFIGFILE

        echo "# The directory where the logs will be written to (full path)." >> $CONFIGFILE
        echo "LOGDIR=\"$LOGDIR\"" >> $CONFIGFILE
	echo "# The logfile where the kernel writes the logs to e.g. /var/log/messages (full path)." >> $CONFIGFILE
        echo "SYSTEMLOG=\"$SYSTEMLOG\"" >> $CONFIGFILE
        echo "# The loglevel to use when logging traffic. For use with syslog." >> $CONFIGFILE
        echo "LOGLEVEL=\"info\"" >> $CONFIGFILE
        echo >> $CONFIGFILE

	echo "# Check the dynamic interfaces for changes?" >> $CONFIGFILE
        echo "DYN_INT_CHECK=\"No\"" >> $CONFIGFILE
        echo "# Check every x seconds." >> $CONFIGFILE
        echo "DYN_INT_INTERVAL=\"30\"" >> $CONFIGFILE
        echo >> $CONFIGFILE

        echo "# LOG_POLICY controls the logging of the default policy." >> $CONFIGFILE
        echo "LOG_POLICY=\"Yes\"" >> $CONFIGFILE
        echo "# LOG_POLICY_LIMIT sets the maximum number of logs per second." >> $CONFIGFILE
        echo "LOG_POLICY_LIMIT=\"30\"" >> $CONFIGFILE
	echo "# LOG_BLOCKLIST enables/disables logging of items on the blocklist." >> $CONFIGFILE
	echo "LOG_BLOCKLIST=\"Yes\"" >> $CONFIGFILE
	echo "# LOG_TCP_OPTIONS controls the logging of tcp options. This is" >> $CONFIGFILE
	echo "# not used by Vuurmuur itself. PSAD 1.4.x uses it for OS-detection." >> $CONFIGFILE
	echo "LOG_TCP_OPTIONS=\"No\"" >> $CONFIGFILE
        echo >> $CONFIGFILE

	echo "# SYN_LIMIT sets the maximum number of SYN-packets per second." >> $CONFIGFILE
	echo "USE_SYN_LIMIT=\"Yes\"" >> $CONFIGFILE
        echo "SYN_LIMIT=\"10\"" >> $CONFIGFILE
        echo "SYN_LIMIT_BURST=\"20\"" >> $CONFIGFILE
        echo "# UDP_LIMIT sets the maximum number of udp 'connections' per second." >> $CONFIGFILE
	echo "USE_UDP_LIMIT=\"Yes\"" >> $CONFIGFILE
        echo "UDP_LIMIT=\"15\"" >> $CONFIGFILE
        echo "UDP_LIMIT_BURST=\"45\"" >> $CONFIGFILE
        echo >> $CONFIGFILE

        echo "# Protect against syn-flooding? (yes/no)" >> $CONFIGFILE
        echo "PROTECT_SYNCOOKIE=\"Yes\"" >> $CONFIGFILE
        echo "# Ignore echo-broadcasts? (yes/no)" >> $CONFIGFILE
        echo "PROTECT_ECHOBROADCAST=\"Yes\"" >> $CONFIGFILE
        echo >> $CONFIGFILE

        echo "# end of file" >> $CONFIGFILE
        # done
    fi
   
    # create the settings file
    VUURMUURCONFIGFILE="$ETCDIR/vuurmuur/vuurmuur_conf.conf"

    if [ ! -f "$VUURMUURCONFIGFILE" ]; then

	touch $VUURMUURCONFIGFILE
        chown root:root $VUURMUURCONFIGFILE
        chmod 0600 $VUURMUURCONFIGFILE

        # write the vuurmuur_conf settingsfile
        echo "# vuurmuur_conf config file" > $VUURMUURCONFIGFILE
        echo >> $VUURMUURCONFIGFILE
        echo "# Some parts of the Gui have advanced options that can be enabled by." >> $VUURMUURCONFIGFILE
        echo "# pressing F5. If you set this to yes, they will be enabled by default." >> $VUURMUURCONFIGFILE
        echo "ADVANCED_MODE=\"No\"" >> $VUURMUURCONFIGFILE
        echo >> $VUURMUURCONFIGFILE
        echo "# The main menu can show status information about various parts of." >> $VUURMUURCONFIGFILE
        echo "# Vuurmuur." >> $VUURMUURCONFIGFILE
        echo "MAINMENU_STATUS=\"Yes\"" >> $VUURMUURCONFIGFILE
        echo >> $VUURMUURCONFIGFILE
        echo "# NEWRULE_LOG enables logging for new rules." >> $VUURMUURCONFIGFILE
        echo "NEWRULE_LOG=\"Yes\"" >> $VUURMUURCONFIGFILE
        echo >> $VUURMUURCONFIGFILE
        echo "# NEWRULE_LOGLIMIT sets the maximum number of logs per second for new rules." >> $VUURMUURCONFIGFILE
        echo "NEWRULE_LOGLIMIT=\"30\"" >> $VUURMUURCONFIGFILE
        echo >> $VUURMUURCONFIGFILE
        echo "# LOGVIEW_BUFSIZE sets the buffersize (in loglines) of the logviewer for scrolling back." >> $VUURMUURCONFIGFILE
        echo "LOGVIEW_BUFSIZE=\"1500\"" >> $VUURMUURCONFIGFILE
        echo >> $VUURMUURCONFIGFILE
        echo "# IPTRAFVOL sets the location of the iptrafvol.pl command." >> $VUURMUURCONFIGFILE
        echo "IPTRAFVOL=\"/usr/bin/iptrafvol.pl\"" >> $VUURMUURCONFIGFILE
        echo >> $VUURMUURCONFIGFILE
        echo "# end of file" >> $VUURMUURCONFIGFILE
    fi
    # done

    # some final information
    echo
    echo "Installation Complete"
    echo "====================="
    echo
    echo "Installing Vuurmuur completed successfully. Please run 'vuurmuur_conf' to"
    echo "complete your configuration. The first step is to define one or more"
    echo "interfaces and attach those to a network. After that rules can be created."
    echo
    echo "Example init.d and logrotate scripts are installed in:"
    echo "'$SHAREDDIR/vuurmuur/scripts'."
    echo
    echo

elif [ "$UPGRADE" = "1" ]; then

    echo
    echo "Upgrading Complete"
    echo "=================="
    echo
    echo "Upgrading to version $VERSION completed successfully. Please run"
    echo "'vuurmuur_conf' and check the configuration for new or changed options."
    echo
fi

#EOF
