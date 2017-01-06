#!/bin/bash

# Installscript for libvuurmuur, vuurmuur and vuurmuur_conf.
#
# TODO: setup an initial configuration that works for most
# setups.
#
# Copyright (c) 2004-2017 by Victor Julien, Stefan Ubbink
# Licenced under the GPL.
#
VERSION="0.8rc3"

# progams
ACLOCAL="aclocal"
AUTOMAKE="automake"
AUTOCONF="autoconf"
AUTOHEADER="autoheader"
MAKE="make"
LIBTOOLIZE="libtoolize"


# defaults
PREFIX=""
INSTALLDIR=${INSTALLDIR:-"/usr"}
SHAREDDIR=${SHAREDDIR:-"$INSTALLDIR/share"}
ETCDIR=${ETCDIR:-"/etc"}
PLUGINDIR=${PLUGINDIR:-"$ETCDIR/vuurmuur/plugins"}
LOGDIR=${LOGDIR:-"/var/log/vuurmuur/"}
SYSTEMLOG=${SYSTEMLOG:-"/var/log/messages"}
if  [ "$(uname -m)" = "x86_64" ] ; then
    LIBDIR=${LIBDIR:-"$INSTALLDIR/lib64"}
else
    LIBDIR=${LIBDIR:-"$INSTALLDIR/lib"}
fi

CURPATH=`pwd`
FULL_SCRIPT=$(readlink -f $0)
FULL_PATH=$(dirname ${FULL_SCRIPT})
LOG="$CURPATH/install.log"
# The vuurmuur sample file. Will be filled with the full path
VM_SAMPLE=""
# The vuurmuur_conf sample file. Will be filled with the full path
VMC_SAMPLE=""

# major
INSTALL="0"
UPGRADE="0"
UNINSTALL="0"
DRYRUN="0"

# minor
DEFAULTS="0"
VERBOSE="1"
DEBUG="0"
WIDEC="0"
FROM_GIT="0"
BUILDUPDATE="0"
DISABLE_IPV6="0"

ID_PROG="$(which id 2>/dev/null || echo /usr/bin/id)"
if [ "`$ID_PROG -g`" != "0" ]; then
    echo "Error: this script requires to be run as user root."
    exit 1
fi

# Check if we use this script from within the git tree and export the revision
# number
GIT="$(which git 2>/dev/null || echo /usr/bin/git)"
if [ -x ${GIT} ]; then
    GIT_COMMIT=`${GIT} log --oneline -n 1 | cut -d ' ' -f 1`
fi

if [ ! -z "${GIT_COMMIT}" ]; then
    VERSION="$VERSION-${GIT_COMMIT}"
    # only use this option if we are really using a git checkout
    FROM_GIT="1"
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
    echo "autoheader:" >> $LOG
    $AUTOHEADER --version >> $LOG
    echo "automake:" >> $LOG
    $AUTOMAKE --version >> $LOG
    echo "autoconf:" >> $LOG
    $AUTOCONF --version >> $LOG
    echo "subversion:" >> $LOG
    ${GIT} --version >> $LOG
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

function PrintHelp
{
    echo
    echo "Help for Vuurmuur-installer."
    echo
    echo "Commandline options:"
    echo
    echo " Action:"
    echo
    echo "  --dryrun        don't install anything"
    echo "  --install       install and setup up the config"
    echo "  --upgrade       install without touching the config"
    echo "  --uninstall     uninstall but leave the config alone"
    echo
    echo " Sub options:"
    echo
    echo "  --defaults      use the default values for all questions"
    echo "  --debug         print some extra info for debugging the install script"
    echo "                      (Use early on the commandline)"
    echo "  --widec         use widec support in vuurmuur_conf (utf-8)"
    echo "  --from-git      do the action based on a git clone (this is guessed)"
    echo "  --build-update  update the buildsystem (regenerates make files etc)"
    echo "  --no-ipv6       don't build IPv6 support (the default is with IPv6 support)"
    echo
    echo "Please read INSTALL for more information."
    echo
    exit 0
}


function Cp
{
    cp $1 $2 $3 &> ${TMP_LOG}
    RESULT="$?"
    if [ "$RESULT" = "0" ]; then
        if [ "$DEBUG" = "1" ]; then
            PrintL "Cp succeeded."
        fi
    else
        PrintL "cp $1 $2 $3 failed with returncode $RESULT."
        cat ${TMP_LOG} >> $LOG
        rm -f ${TMP_LOG}
        Exit 1
    fi

    rm -f ${TMP_LOG}
}

function Cd
{
    CUR=`pwd`

    cd $1 &> ${TMP_LOG}
    RESULT="$?"
    if [ "$RESULT" = "0" ]; then
        if [ "$DEBUG" = "1" ]; then
            PrintL "Cd succeeded."
        fi
    else
        PrintL "cd $1 failed with returncode $RESULT."
        cat ${TMP_LOG} >> $LOG
        rm -f ${TMP_LOG}
        Exit 1
    fi

    rm -f ${TMP_LOG}
}

function Libtoolize
{
    touch ${TMP_LOG}
    $LIBTOOLIZE $1 &> ${TMP_LOG}
    RESULT="$?"
    cat ${TMP_LOG} >> $LOG
    rm -f ${TMP_LOG}
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
    touch ${TMP_LOG}
    $MAKE $1 $2 &> ${TMP_LOG}
    RESULT="$?"
    cat ${TMP_LOG} >> $LOG
    rm -f ${TMP_LOG}
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
    touch ${TMP_LOG}
    $ACLOCAL &> ${TMP_LOG}
    RESULT="$?"
    cat ${TMP_LOG} >> $LOG
    rm -f ${TMP_LOG}
    if [ "$RESULT" = "0" ]; then
        if [ "$DEBUG" = "1" ]; then
            PrintL "Aclocal succeeded."
        fi
    else
        PrintL "aclocal failed with returncode $RESULT."
        Exit 1
    fi
}

function Autoheader
{
    touch ${TMP_LOG}
    $AUTOHEADER &> ${TMP_LOG}
    RESULT="$?"
    cat ${TMP_LOG} >> $LOG
    rm -f ${TMP_LOG}
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
    touch ${TMP_LOG}
    $AUTOMAKE --copy --add-missing &> ${TMP_LOG}
    RESULT="$?"
    cat ${TMP_LOG} >> $LOG
    rm -f ${TMP_LOG}
    if [ "$RESULT" = "0" ]; then
        if [ "$DEBUG" = "1" ]; then
            PrintL "Automake succeeded."
        fi
    else
        PrintL "automake failed with returncode $RESULT."
        Exit 1
    fi
}

function Autoconf
{
    touch ${TMP_LOG}
    $AUTOCONF &> ${TMP_LOG}
    RESULT="$?"
    cat ${TMP_LOG} >> $LOG
    rm -f ${TMP_LOG}
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
    touch ${TMP_LOG}
    if [ ! -f configure ]; then
        ./autogen.sh
    fi
    ./configure $* &> ${TMP_LOG}
    RESULT="$?"
    cat ${TMP_LOG} >> $LOG
    rm -f ${TMP_LOG}
    if [ "$RESULT" = "0" ]; then
        if [ "$DEBUG" = "1" ]; then
            PrintL "configure $* succeeded."
        fi
    else
        PrintL "./configure $* failed with returncode $RESULT."
        Exit 1
    fi
}

function WrapGettextize
{
    touch ${TMP_LOG}

    GETTEXTIZE="$(which gettextize 2>/dev/null || echo gettextize)"

    echo "gettextize..." >> $LOG
    # ripped from: http://cvs.saout.de/lxr/saout/source/cryptsetup/setup-gettext
    sed 's:read .*< /dev/tty::' $GETTEXTIZE > .temp-gettextize
    chmod +x .temp-gettextize
    echo n | ./.temp-gettextize --copy --force --intl --no-changelog >> $LOG || abort
    rm -f .temp-gettextize
    echo "gettextize... done" >> $LOG

    cat ${TMP_LOG} >> $LOG
    rm -f ${TMP_LOG}
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

function CheckDir
{
    if [ ! -d $1 ]; then
        PrintL "Error: the directory '$1' doesn't exist."
        Exit 1
    fi
}

function MkDir
{
    mkdir -p $1 &> /dev/null
    RESULT="$?"
    if [ "$RESULT" != "0" -a "$2" != "mayfail" ]; then
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
    if [ "$BUILDUPDATE" = "1" ]; then
        CheckBinary $ACLOCAL
        CheckBinary $AUTOMAKE
        CheckBinary $AUTOCONF
        CheckBinary $AUTOHEADER
    fi
    CheckBinary gcc
    CheckBinary $MAKE
}

while [ $# -gt 0 ]
do
    case $1
    in
        --debug)
            DEBUG="1"
            PrintL "Commandline option '--debug' enabled."
            shift 1
        ;;
        --defaults)
            DEFAULTS="1"
            if [ "$DEBUG" = "1" ]; then
                PrintL "Commandline option '--defaults' enabled."
            fi
            shift 1
        ;;
        --widec)
            WIDEC="1"
            if [ "$DEBUG" = "1" ]; then
                PrintL "Commandline option '--widec' enabled."
            fi
            shift 1
        ;;
        --from-git)
            FROM_GIT="1"
            if [ "$DEBUG" = "1" ]; then
                PrintL "Commandline option '--from-git' enabled."
            fi
            shift 1
        ;;
        --no-ipv6)
            DISABLE_IPV6="1"
            if [ "$DEBUG" = "1" ]; then
                PrintL "Commandline option '--no-ipv6' enabled."
            fi
            shift 1
        ;;

# commandline options
        --dryrun)
            DRYRUN="1"
            if [ "$DEBUG" = "1" ]; then
                PrintL "Commandline option '--dryrun' enabled."
            fi
            shift 1
        ;;
        --install)
            INSTALL="1"
            if [ "$DEBUG" = "1" ]; then
                PrintL "Commandline option '--install' enabled."
            fi
            shift 1
        ;;
        --upgrade)
            UPGRADE="1"
            if [ "$DEBUG" = "1" ]; then
                PrintL "Commandline option '--upgrade' enabled."
            fi
            shift 1
        ;;
        --uninstall)
            UNINSTALL="1"
            if [ "$DEBUG" = "1" ]; then
                PrintL "Commandline option '--uninstall' enabled."
            fi
            shift 1
        ;;
        --build-update)
            BUILDUPDATE="1"
            if [ "$DEBUG" = "1" ]; then
                PrintL "Commandline option '--build-update' enabled."
            fi
            shift 1
        ;;
        --prefix)
            echo  "Commandline option '$1'='$2'."
            PREFIX=$2
            shift 2
        ;;
        *)
            PrintHelp
            shift 1
        ;;
    esac
done

# if none of the main options is selected, print help and exit.
if  [ "$DRYRUN" = "0" ] && 
    [ "$INSTALL" = "0" ] && 
    [ "$UPGRADE" = "0" ] && 
    [ "$UNINSTALL" = "0" ]; then
    PrintHelp
fi

# check that only one major option is selected.
TOTAL=$((DRYRUN + INSTALL + UPGRADE + UNINSTALL))
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
    echo "Welcome to the installation of Vuurmuur. "
    if [ "$DEFAULTS" = "0" ]; then
        echo "First you will be asked a couple of questions about "
        echo "the location to install the various parts of Vuurmuur. "
        echo "It is recommended that you choose the defaults, by "
        echo "pressing just enter."
    else
        echo "Vuurmuur will be installed into $PREFIX/usr."
    fi
    echo
elif [ "$UPGRADE" = "1" ]; then
    echo
    echo "Vuurmuur installation (upgrade)"
    echo "==============================="
    echo
    echo "Welcome to the upgrade script for Vuurmuur. "
    if [ "$DEFAULTS" = "0" ]; then
        echo "First you will be asked a couple of questions about the"
        echo "location to install the various parts of Vuurmuur. Make"
        echo "sure that you point to the existing paths."
    fi
    echo
fi


# check the bins needed for compiling
if [ "$INSTALL" = "1" ] || [ "$UPGRADE" = "1" ]; then
    CheckRequiredBins
fi

# A temp file, where we store output from some commands
TMP_LOG=`mktemp ${CURPATH}/vm_tmplog.XXXXXXXX`

# installdir
if [ "$INSTALL" = "1" ] || [ "$UPGRADE" = "1" ]; then

    if [ "$DEFAULTS" = "0" ]; then
        # get the installdir
        echo "Please enter the installation dir ($INSTALLDIR)."
        read TALK
        if [ "$TALK" != "" ]; then
            INSTALLDIR="$TALK"
            SHAREDDIR="$INSTALLDIR/share"
            if  [ "$(uname -m)" = "x86_64" ] ; then
                LIBDIR="$INSTALLDIR/lib64"
            else
                LIBDIR="$INSTALLDIR/lib"
            fi
        fi
    fi
    INSTALLDIR=${PREFIX}${INSTALLDIR}
    PrintL "Installdir: $INSTALLDIR ..."
    
    MkDir ${INSTALLDIR} mayfail
fi

# libdir
#if [ "$INSTALL" = "1" ] || [ "$UPGRADE" = "1" ]; then
#
#    if [ "$DEFAULTS" = "0" ]; then
#        # get the libdir
#        echo "Please enter the library dir ($LIBDIR)."
#        read TALK
#        if [ "$TALK" != "" ]; then
#            LIBDIR="$TALK"
#        fi
#    fi
#    PrintL "Libdir: $LIBDIR ..."
#
#    MkDir $LIBDIR mayfail
#fi

# etcdir
if [ "$INSTALL" = "1" ] || [ "$UPGRADE" = "1" ]; then
    if [ "$DEFAULTS" = "0" ]; then
        if [ "$UPGRADE" = "1" ]; then
            echo
            echo "Please enter the current base config directory ($ETCDIR)."
            echo
            echo "NOTE!!! in this directory a directory 'vuurmuur' must exist."
            echo "So for '/etc/vuurmuur' choose '/etc' here."
            echo
            echo "Examples: /etc, /usr/local/etc, /opt/vuurmuur/etc"
            echo
        elif [ "$INSTALL" = "1" ]; then
            echo
            echo "Please enter the directory where the config is going to be stored ($ETCDIR)."
            echo
            echo "NOTE!!! in this directory a directory 'vuurmuur' will be created."
            echo "Sso for '/etc/vuurmuur' choose '/etc' here."
            echo
            echo "Examples: /etc, /usr/local/etc, /opt/vuurmuur/etc"
            echo
        fi

        read TALK
        if [ "$TALK" != "" ]; then
            ETCDIR="$TALK"
        fi
    else
        ETCDIR="/etc"
    fi
    ETCDIR=${PREFIX}${ETCDIR}
    PrintL "Using Etcdir: '$ETCDIR/vuurmuur'."

    # try to backup the etc dir
    if [ "$UPGRADE" = "1" ]; then
        echo
        echo "Backing up your current Vuurmuur configuration..."

        # create a backup of a previous version of vuurmuur
        if [ ! -d /root/backups/vuurmuur ]; then
            mkdir -p /root/backups/vuurmuur || \
                ExitMessage "error creating /root/backups/vuurmuur"
            PrintL "* backup directory /root/backups/vuurmuur created."
        fi

        BACKUP_DIR="/root/backups/vuurmuur/upgrade-$(date +'%Y.%m.%d-%H.%M')"

        if [ ! -d $BACKUP_DIR ]; then
            mkdir -m 0700 -p ${BACKUP_DIR} || \
                ExitMessage "error creating ${BACKUP_DIR}"
            PrintL "* backup directory ${BACKUP_DIR} created."
        else
            ExitMessage "error: directory ${BACKUP_DIR} already exists?! -- I am confused!"
        fi

        if [ -d $ETCDIR/vuurmuur ]; then
            cp -a $ETCDIR/vuurmuur/* ${BACKUP_DIR} || \
                ExitMessage "copying vuurmuur configuration failed!"
            PrintL "* copied vuurmuur configuration to ${BACKUP_DIR}."
        else
            PrintL "* no vuurmuur config found (no $ETCDIR/vuurmuur directory)!"
        fi

        echo "Backing up your current Vuurmuur configuration complete."
        echo
    elif [ "$INSTALL" = "1" ]; then
        if [ -f "$ETCDIR/vuurmuur/config.conf" ]; then
            ExitMessage "vuurmuur config found in $ETCDIR/vuurmuur, did you mean --upgrade?"
        fi
    fi

    # update plugin dir
    PLUGINDIR="$ETCDIR/vuurmuur/plugins/"

    if [ "$UPGRADE" = "1" ]; then
        CheckDir "$ETCDIR/vuurmuur"
    elif [ "$INSTALL" = "1" ]; then
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
    LOGDIR=${PREFIX}${LOGDIR}
    PrintL "Using Logdir: '$LOGDIR'."

    MkDir $LOGDIR mayfail
    chmod 0700 $LOGDIR
fi

if [ "$INSTALL" = "1" ] || [ "$UPGRADE" = "1" ]; then

    echo
    echo "Building Vuurmuur. Depending on your hardware"
    echo "this process will take about 0.5 to 5 minutes."
    echo
fi

if [ "$INSTALL" = "1" ] || [ "$UPGRADE" = "1" ]; then
    VM_SAMPLE="`pwd`/config/config.conf.sample"
    VMC_SAMPLE="`pwd`/config/vuurmuur_conf.conf.sample"

    if [ "$BUILDUPDATE" = "1" ]; then
        PrintL "* build system update"
        Libtoolize -f
        Aclocal
        Autoheader
        Automake
        Autoconf
    fi
    if [ "$WIDEC" = "1" ]; then
        WIDESTR="yes"
    else
        WIDESTR="no"
    fi

    CONFIG_OPTS="--prefix=$INSTALLDIR   \
                 --sysconfdir=$ETCDIR   \
                 --with-widec=$WIDESTR"
    if [ "${DISABLE_IPV6}" = "1" ]; then
        CONFIG_OPTS="${CONFIG_OPTS} --disable-ipv6"
    fi
    PrintL "* configure"
    Configure ${CONFIG_OPTS}
    Make clean
    PrintL "* make"
    Make
    if [ "$DRYRUN" != "1" ]; then
        PrintL "* make install"
        Make install

        if [ "$INSTALL" = "1" ]; then
            touch $ETCDIR/vuurmuur/plugins/textdir.conf
            chmod 0600 $ETCDIR/vuurmuur/plugins/textdir.conf
            echo "LOCATION=\"$ETCDIR/vuurmuur\"" > $ETCDIR/vuurmuur/plugins/textdir.conf

            chmod 0700 $ETCDIR/vuurmuur
            chmod 0700 $ETCDIR/vuurmuur/plugins
        fi
    fi
    if [ "${FROM_GIT}" = "0" ]; then
        Make clean
    fi
    PrintL "Building and installing vuurmuur finished."

elif [ "$UNINSTALL" = "1" ]; then

    PrintL "Going to uninstall vuurmuur..."
    Make uninstall
    PrintL "Un-installing vuurmuur finished."
fi

if [ "$INSTALL" = "1" ]; then

    echo
    echo "Setting up the Vuurmuur config for first-time use."

    mkdir -p -m 0700 $ETCDIR/vuurmuur
    
    if [ ! -d "$ETCDIR/vuurmuur/interfaces" ]; then
        mkdir -p -m 0700 $ETCDIR/vuurmuur/interfaces
    fi
    
    if [ ! -d "$ETCDIR/vuurmuur/services" ]; then
        mkdir -p -m 0700 $ETCDIR/vuurmuur/services
    
        cp $SHAREDDIR/vuurmuur/services/* $ETCDIR/vuurmuur/services/
        chown -R root:root $ETCDIR/vuurmuur/services
        chmod 0700 $ETCDIR/vuurmuur/services
    fi

    if [ ! -d "$ETCDIR/vuurmuur/zones" ]; then
        mkdir -p -m 0700 $ETCDIR/vuurmuur/zones

        if [ "${FROM_GIT}" = "1" ]; then
            cp -r --preserve=mode ${FULL_PATH}/zones/* $ETCDIR/vuurmuur/zones
        else
            cp -r --preserve=mode zones/* $ETCDIR/vuurmuur/zones
        fi
        chown -R root:root $ETCDIR/vuurmuur/zones
        chmod 0700 $ETCDIR/vuurmuur/zones
    fi

    if [ ! -d "$ETCDIR/vuurmuur/rules" ]; then
        mkdir -p -m 0700 $ETCDIR/vuurmuur/rules

        touch $ETCDIR/vuurmuur/rules/rules.conf
        chown root:root $ETCDIR/vuurmuur/rules/rules.conf
        chmod 0600 $ETCDIR/vuurmuur/rules/rules.conf

        touch $ETCDIR/vuurmuur/rules/blocklist.conf
        chown root:root $ETCDIR/vuurmuur/rules/blocklist.conf
        chmod 0600 $ETCDIR/vuurmuur/rules/blocklist.conf
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

        # seek ip6tables
        which ip6tables &> /dev/null
        RESULT=$?
        if [ "$RESULT" = "0" ]; then
            IP6TABLESLOC=`which ip6tables`
        else
            echo
            echo "Warning: could not find the location of the 'ip6tables' command. Please make sure you have"
            echo "ip6tables installed and set it's location in the Vuurmuur config."
            IP6TABLESLOC="/sbin/ip6tables"
        fi

        # seek ip6tables-restore
        which ip6tables-restore &> /dev/null
        RESULT=$?
        if [ "$RESULT" = "0" ]; then
            IP6TABLESRESLOC=`which ip6tables-restore`
        else
            echo
            echo "Warning: could not find the location of the 'ip6tables-restore' command. Please make sure"
            echo " you have ip6tables-restore installed and set it's location in the Vuurmuur config."
            IP6TABLESRESLOC="/sbin/ip6tables-restore"
        fi

        # seek conntrack
        CONNTRACKLOC="$(which conntrack 2>/dev/null || echo "")"

        # seek tc
        TCLOC="$(which tc 2>/dev/null || echo "")"

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

        if [ -f ${VM_SAMPLE} ]; then
            # Replace the lines in the sample config file with the things we
            # determined in this script
            cat ${VM_SAMPLE} | \
            sed -e 's,^\(IPTABLES=\).*,\1"'${IPTABLESLOC}'",g' \
                -e 's,^\(IPTABLES_RESTORE=\).*,\1"'${IPTABLESRESLOC}'",g' \
                -e 's,^\(IP6TABLES=\).*,\1"'${IP6TABLESLOC}'",g' \
                -e 's,^\(IP6TABLES_RESTORE=\).*,\1"'${IP6TABLESRESLOC}'",g' \
                -e 's,^\(CONNTRACK=\).*,\1"'${CONNTRACKLOC}'",g' \
                -e 's,^\(TC=\).*,\1"'${TCLOC}'",g' \
                -e 's,^\(MODPROBE=\).*,\1"'${MODPROBE}'",g' \
                -e 's,^\(SYSTEMLOG=\).*,\1"'${SYSTEMLOG}'",g' \
                -e 's,^\(LOGDIR=\).*,\1"'${LOGDIR}'",g' \
                > ${CONFIGFILE}
        else
            echo "Could not find the sample file ${VM_SAMPLE},"
            echo "now you have to make it yourself"
        fi
    fi
   
    # create the settings file
    VUURMUURCONFIGFILE="$ETCDIR/vuurmuur/vuurmuur_conf.conf"

    if [ ! -f "$VUURMUURCONFIGFILE" ]; then
        if [ -f ${VMC_SAMPLE} ]; then
            # Since we don't need to replace anything, we just copy the sample
            # file to the final file
            Cp ${VMC_SAMPLE} ${VUURMUURCONFIGFILE}
            chown root:root $VUURMUURCONFIGFILE
            chmod 0600 $VUURMUURCONFIGFILE
        else
            echo "Could not find the sample file ${VMC_SAMPLE},"
            echo "now you have to make it yourself"
        fi
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

exit 0
#EOF
