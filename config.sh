#!/bin/bash

if [ ! "$BASH_VERSION" ] ; then
    echo "Error: script should be run under bash" 1>&2
    exit 1
fi

if [ $# -eq 0 ]; then
	echo "Syntax: ./configure <Project Name> <Optional: preferred extension (Default: cpp)>"
	exit 1
fi

EXT="cpp"
if [ $# -eq 2 ]; then
	EXT="$2"
fi

SCRIPT_PATH="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_NAME="$1"

echo "Generating project files"

MAIN_FILE="${SCRIPT_PATH}/src/${PROJECT_NAME}.${EXT}"
touch ${MAIN_FILE}
echo "int main()" >> ${MAIN_FILE}
echo "{" >> ${MAIN_FILE}
echo "    return 0;" >> ${MAIN_FILE}
echo "}" >> ${MAIN_FILE}

CMAKE_FILE="${SCRIPT_PATH}/src/CMakeLists.txt"
touch ${CMAKE_FILE}
echo "CMAKE_MINIMUM_REQUIRED(VERSION 2.8.12.1)" >> ${CMAKE_FILE}
echo "" >> ${CMAKE_FILE}
echo "# Set project name" >> ${CMAKE_FILE}
echo "SET(PROJ_NAME \"${PROJECT_NAME}\" CACHE STRING \"name of project\")" >> ${CMAKE_FILE}
echo "PROJECT(\${PROJ_NAME})" >> ${CMAKE_FILE}
echo "" >> ${CMAKE_FILE}
echo "# Set project options" >> ${CMAKE_FILE}
echo "SET(PROJ_EXT \"${EXT}\")" >> ${CMAKE_FILE}
echo "SET(BUILD_DIR \"\${CMAKE_CURRENT_SOURCE_DIR}/../build/\" CACHE STRING \"location to build to\")" >> ${CMAKE_FILE}
echo "SET(INCLUDE_DIR \"\${CMAKE_CURRENT_SOURCE_DIR}/../includes/\" CACHE STRING \"location of header files\")" >> ${CMAKE_FILE}
echo "SET(MAX_ERR \"5\" CACHE STRING \"maximum number of errors to display during compile\")" >> ${CMAKE_FILE}
echo "SET(DEBUG_SUFFIX \"_Debug\" CACHE STRING \"label to append to debug executable\")" >> ${CMAKE_FILE}
echo "OPTION(DEBUG \"enable debug flags at compile\")" >> ${CMAKE_FILE}
echo "" >> ${CMAKE_FILE}
echo "# Point to necessary project locations" >> ${CMAKE_FILE}
echo "SET(CMAKE_RUNTIME_OUTPUT_DIRECTORY \${BUILD_DIR})" >> ${CMAKE_FILE}
echo "INCLUDE_DIRECTORIES(\${INCLUDE_DIR})" >> ${CMAKE_FILE}
echo "" >> ${CMAKE_FILE}
echo "# Setup project source compilation" >> ${CMAKE_FILE}
echo "ADD_EXECUTABLE(\${PROJECT_NAME} \"\${CMAKE_CURRENT_SOURCE_DIR}/\${PROJECT_NAME}.\${PROJ_EXT}\")" >> ${CMAKE_FILE}
echo "ADD_DEFINITIONS(-std=c++11 -fmax-errors=\${MAX_ERR})" >> ${CMAKE_FILE}
echo "IF (DEBUG)" >> ${CMAKE_FILE}
echo "  MESSAGE(\"Generating debug version\")" >> ${CMAKE_FILE}
echo "  SET(CMAKE_CXX_FLAGS \"\${CMAKE_CXX_FLAGS} -g -DDEBUG=true\")" >> ${CMAKE_FILE}
echo "  SET_TARGET_PROPERTIES(\${PROJECT_NAME} PROPERTIES OUTPUT_NAME \${PROJECT_NAME}\${DEBUG_SUFFIX})" >> ${CMAKE_FILE}
echo "ELSE ()" >> ${CMAKE_FILE}
echo "  MESSAGE(\"Generating release version\")" >> ${CMAKE_FILE}
echo "ENDIF ()" >> ${CMAKE_FILE}
echo "" >> ${CMAKE_FILE}
echo "# Enable this if VTK is needed" >> ${CMAKE_FILE}
echo "##SET(VTK_DIR /PATH/TO/VTK)" >> ${CMAKE_FILE}
echo "##FIND_PACKAGE(VTK REQUIRED)" >> ${CMAKE_FILE}
echo "##INCLUDE(\${VTK_USE_FILE})" >> ${CMAKE_FILE}
echo "##" >> ${CMAKE_FILE}
echo "##IF (VTK_LIBRARIES)" >> ${CMAKE_FILE}
echo "##  TARGET_LINK_LIBRARIES(\${PROJECT_NAME} \${VTK_LIBRARIES})" >> ${CMAKE_FILE}
echo "##ELSE ()" >> ${CMAKE_FILE}
echo "##  TARGET_LINK_LIBRARIES(\${PROJECT_NAME} vtkHybrid)" >> ${CMAKE_FILE}
echo "##ENDIF ()" >> ${CMAKE_FILE}

echo "Done"
