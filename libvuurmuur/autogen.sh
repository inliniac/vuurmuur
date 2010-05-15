#!/bin/bash

libtoolize --copy --force
aclocal
autoheader
automake --copy --add-missing
autoconf

