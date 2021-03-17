#!/bin/sh

set -xe

CC="${CC:-cc}"
CFLAGS="-Wall -Wextra -std=c11 -pedantic -ggdb"
CFLAGS_SSL=`pkg-config --cflags openssl`
LIBS_SSL=`pkg-config --libs openssl`

$CC $CFLAGS $CFLAGS_SSL -I.. -o 01_echo ./01_echo.c $LIBS_SSL
