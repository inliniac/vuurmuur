#!/bin/bash

libtoolize --copy
aclocal
autoheader
automake --copy --add-missing
autoconf

