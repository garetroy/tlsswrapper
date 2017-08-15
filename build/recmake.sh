#/bin/bash

# *****************************************************************
# ReCMake: generates release and debug makefiles
# 
# Flags:    -w: run with wizard (allows setting options via ccmake)
# *****************************************************************

if [ ! "$BASH_VERSION" ] ; then
    echo "Error: script should be run under bash" 1>&2
    exit 1
fi

CMD="cmake"
if [ $# -eq 1 ] && [ "$1" == "-w" ]; then
    CMD="ccmake"
fi

function checkStatus {
	if [ $? != 0 ]; then
		echo -e "\033[0;31mCMake failure, consult $1/CMake_Log\033[0m"
		exit 1
	fi
}

SCRIPT_PATH="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd $SCRIPT_PATH
mkdir -p Debug
mkdir -p Release

if [[ $OUTPUT = "Build_Log" ]]; then
    echo "Constructing release makefile..."
    cd $SCRIPT_PATH/Release
    ${CMD} ../../src &> CMake_Log
    checkStatus "$SCRIPT_PATH/Release"
    
    echo "Constructing debug makefile..."
    cd $SCRIPT_PATH/Debug
    ${CMD} -DDEBUG=true ../../src &> CMake_Log
    checkStatus "$SCRIPT_PATH/Debug"
else
    echo "Constructing release makefile..."
    cd $SCRIPT_PATH/Release
    ${CMD} ../../src
    
    echo "Constructing debug makefile..."
    cd $SCRIPT_PATH/Debug
    ${CMD} -DDEBUG=true ../../src
fi
