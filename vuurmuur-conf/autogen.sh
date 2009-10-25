#!/bin/bash

libtoolize --copy
# gettextize wrapping to prevent the need for user input
# ripped from: http://cvs.saout.de/lxr/saout/source/cryptsetup/setup-gettext
sed 's:read .*< /dev/tty::' `which gettextize` > .temp-gettextize
chmod +x .temp-gettextize
echo n | ./.temp-gettextize --copy --force --intl --no-changelog || abort
rm -f .temp-gettextize
aclocal
autoheader
automake --copy --add-missing
autoconf

