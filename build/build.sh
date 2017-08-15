#/bin/bash

# ***********************************************************
# Build: runs make for release or debug versions of code. If 
#        no build-type flag specified defaults to release 
#        build.
#
# Flags:    -r: build release version
#           -d: build debug version
#           -v: send build output to terminal instead of logs
# ***********************************************************

# Initialize variables
SCRIPT_PATH="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
COL="\033[0;36m"
NOCOL="\033[0m"

if [ ! "$BASH_VERSION" ] ; then
    echo "Error: script should be run under bash" 1>&2
    exit 1
fi

# Check for flags
OUTPUT="Build_Log"
BUILDRELEASE="false"
BUILDDEBUG="false"
unset name
while getopts "drv" opt; do
	case $opt in
		d)
			BUILDDEBUG="true"
			;;
        r)
            BUILDRELEASE="true"
            ;;
		v)
			OUTPUT="Terminal"
			;;
		\?)
			echo "Invalid option: -$OPTARG" >&2
			exit
			;;
	esac
done
if [ -z "${name}" ]; then
    BUILDRELEASE="true"
fi

# Function to catch any build failures
function checkStatus {
	if [ $? != 0 ]; then
		echo -e "\033[0;31mBuild failed, consult $1/Build_Log\033[0m"
		exit 1
	fi
}

# Run cleanup to ensure a clean build
cd $SCRIPT_PATH
if [ $BUILDDEBUG == "true" ]; then
    bash ${SCRIPT_PATH}/cleanup.sh Debug
    echo ""
fi
if [ $BUILDRELEASE == "true" ]; then
    bash ${SCRIPT_PATH}/cleanup.sh Release  
    echo ""
fi

# Initialize build, send output to specified location
if [ $BUILDDEBUG == "true" ]; then
    if [ $OUTPUT = "Build_Log" ]; then
        cd $SCRIPT_PATH/Debug
        echo "Making debug build..."
        make &> Build_Log
        checkStatus "${SCRIPT_PATH}/Debug"
        
        echo -e "${COL}Finished building${NOCOL}"
        echo -e "${COL}See \"$SCRIPT_PATH\" /Debug log files for further details${NOCOL}"
        echo ""
    else
        cd $SCRIPT_PATH/Debug
        echo "Making debug build..."
        make
        echo ""
    fi
fi

if [ $BUILDRELEASE == "true" ]; then
    if [ $OUTPUT = "Build_Log" ]; then
    	cd $SCRIPT_PATH/Release
    	echo "Making release build..."
    	make &> Build_Log
    	checkStatus "${SCRIPT_PATH}/Release"
    	
    	echo -e "${COL}Finished building${NOCOL}"
    	echo -e "${COL}See \"$SCRIPT_PATH\" /Release log files for further details${NOCOL}"
    else
    	cd $SCRIPT_PATH/Release
    	echo "Making release build..."
    	make
    fi
fi
