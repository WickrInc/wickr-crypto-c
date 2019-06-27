#!/bin/bash

export PATH="/c/msys64/mingw64/bin:$PATH"

echo "Using path: $PATH"
echo "Running $*"

$*
