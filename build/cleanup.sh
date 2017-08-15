#/bin/bash

# ***************************************************************
# Cleanup: runs make clean for all makefiles
# 
# Flags:    Release: clean release build
#           Debug:   clean debug build
#           <NONE>:  if no flag specified runs make clean on both
# ***************************************************************

if [ ! "$BASH_VERSION" ] ; then
    echo "Error: script should be run under bash" 1>&2
    exit 1
fi

SCRIPT_PATH="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

echo "Running Cleanup..."

if [ "$1" == "Release" ]; then 
    cd $SCRIPT_PATH/Release
    echo "Cleaning release build..."
    make clean
    exit
fi

if [ "$1" == "Debug" ]; then
    cd $SCRIPT_PATH/Debug
    echo "Cleaning debug build..."
    make clean
    exit
fi

if [ "$#" -eq 0 ]; then
    cd $SCRIPT_PATH/Release
    echo "Cleaning release build..."
    make clean
    echo ""
    cd $SCRIPT_PATH/Debug
    echo "Cleaning debug build..."
    make clean
    exit
fi
