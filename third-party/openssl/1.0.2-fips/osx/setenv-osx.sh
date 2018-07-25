#!/bin/bash 
SYSTEM="Darwin" 
MACHINE="x86_64" 
KERNEL_BITS=64 

export MACHINE 
export SYSTEM 
export KERNEL_BITS

echo "Going to run: $*"

$*