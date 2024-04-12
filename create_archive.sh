#!/bin/bash

if [ ! -f README.md ]; then
    echo "No README present! Exiting..." >&2
    exit 1
fi

if [ ! -f Makefile ]; then
    echo "No Makefile present! Exiting..." >&2
    exit 1
fi

rm -rf archive.zip
sudo make clean
zip -r archive.zip lib/ include/ *.c *.h Makefile README.md
if [ -f arp_table.txt ]; then
    zip archive.zip arp_table.txt
fi
