#!/bin/bash

# Try to load additional crypto modules
for module in /lib/modules/`uname -r`/kernel/crypto/*.ko*; do
    if [ -f "$module" ]; then
        insmod "$module" 2>/dev/null
    fi
done
