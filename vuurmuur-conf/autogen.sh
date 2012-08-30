#!/bin/bash

libtoolize --copy -f
# gettextize wrapping to prevent the need for user input
# ripped from: http://cvs.saout.de/lxr/saout/source/cryptsetup/setup-gettext
sed 's:read .*< /dev/tty::' `which gettextize` > .temp-gettextize
chmod +x .temp-gettextize
echo n | ./.temp-gettextize --copy --force --intl --no-changelog || abort
rm -f .temp-gettextize
# hack around an issue on Ubuntu 10.04: on the AC_OUTPUT line we'd see two
# times a mention of intl/Makefile causing the commands below to fail.
# Couldn't figure out how to make autotools behave, so hacking around it.
#sed -i 's/intl\/Makefile intl\/Makefile/intl\/Makefile/g' configure.in
aclocal -I m4
autoheader
automake --copy --add-missing
autoconf

