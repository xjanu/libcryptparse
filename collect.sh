#!/bin/bash

# Check if the kernal is Linux
if [ `uname --kernel-name` != "Linux" ]; then
    echo "Unsupported platform" >&2
    exit 1
fi

# check if /proc/crypto exists, just to be sure
if [ ! -f "/proc/crypto" ]; then
    echo "/proc/crypto does not exist?!" >&2
    exit 2
fi

# Where to copy the /proc/crypto
dir='samples/'`uname --kernel-release`
file=`sha1sum /proc/crypto | cut -f1 -d' '`
echo "output: $dir/$file" >&2

# create $dir
mkdir -p "$dir"

# use umask for permissions instead of /proc/crypto r--r--r--
cat "/proc/crypto" > "$dir/$file"
