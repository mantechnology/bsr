#!/bin/bash
{
    for x in include/generated/utsrelease.h include/linux/{utsrelease,version}.h;
    do
        for d in $KDIR $O;
        do
            test -e "$d/$x" || continue;
            echo "#include \"$d/$x\"";
        done;
    done;
    echo "bsr_kernel_release UTS_RELEASE"
} | gcc -nostdinc -E -P - | sed -ne 's/^bsr_kernel_release "\(.*\)".*/\1/p'
