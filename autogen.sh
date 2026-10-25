#!/bin/bash

libtoolize --copy -f
# the gettext half of the build infrastructure is pinned in-tree:
# the po/ machinery (po/Makefile.in.in and friends) and the m4
# macros. Do not run gettextize here - it re-copies both from the
# host gettext and rewrites the tracked files whenever the host
# version differs from the pinned one. To update the pin, run
# gettextize by hand and commit the result. libtoolize still
# provides the libtool m4 half on every run.
aclocal -I m4
autoheader
automake --copy --add-missing
autoconf

