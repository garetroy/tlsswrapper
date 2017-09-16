CMAKE_MINIMUM_REQUIRED(VERSION 3.6.3)

# Set project name
SET(PROJ_NAME "tlswrapper" CACHE STRING "name of project")
PROJECT(${PROJ_NAME})

# Set project options
SET(PROJ_EXT "cxx")
SET(BUILD_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../build/" CACHE STRING "location to build to")
SET(INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../includes/" CACHE STRING "location of header files")
SET(MAX_ERR "5" CACHE STRING "maximum number of errors to display during compile")
SET(DEBUG_SUFFIX "_Debug" CACHE STRING "label to append to debug executable")
OPTION(DEBUG "enable debug flags at compile")


# Point to necessary project locations
SET(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${BUILD_DIR})
INCLUDE_DIRECTORIES(${INCLUDE_DIR})

# Setup project source compilation
ADD_EXECUTABLE(${PROJECT_NAME} "${CMAKE_CURRENT_SOURCE_DIR}/${PROJECT_NAME}.${PROJ_EXT}"
                               "${CMAKE_CURRENT_SOURCE_DIR}/tlswserver.${PROJ_EXT}"
                               "${CMAKE_CURRENT_SOURCE_DIR}/tlswclient.${PROJ_EXT}"
                               "${CMAKE_CURRENT_SOURCE_DIR}/tlswhelper.${PROJ_EXT}")

ADD_DEFINITIONS(-std=c++11)
IF (DEBUG)
  MESSAGE("Generating debug version")
  SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -DDEBUG=true")
  SET_TARGET_PROPERTIES(${PROJECT_NAME} PROPERTIES OUTPUT_NAME ${PROJECT_NAME}${DEBUG_SUFFIX})
ELSE ()
  MESSAGE("Generating release version")
ENDIF ()

FIND_PACKAGE(OPENSSL 1.0.2 REQUIRED)
INCLUDE_DIRECTORIES(${OPENSSL_INCLUDE_DIR})
IF (OPENSSL_FOUND)
    TARGET_LINK_LIBRARIES(${PROJECT_NAME} ${OPENSSL_LIB} ${OPENSSL_SSL_LIBRARY} ${OPENSSL_CRYPTO_LIBRARY})
ENDIF()

FIND_PACKAGE(glog REQUIRED)
TARGET_LINK_LIBRARIES(${PROJECT_NAME} glog::glog)
