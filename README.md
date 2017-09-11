**tlswrapper** is a wrapper for basic TCP server/clients (with tls encryption) orignially from c based functions. Allows for more programming efficiency, higher level understanding, and less to program for next time!

## Requirements
    openSSL
    cmake   - 3.6.3 or higher 

## Installation
    Go to the build directory then continue with the following commands.
    '''shell
    chmod +x ./build.sh
    ./build.sh
    ''' 
    Then it is built to run the main in src/tlswrapper.cxx by executing the
    command
    '''shell
    ./tlswrapper [option]
    '''
    in the build directory.

Build scheme made with C-Bed:
    https://github.com/GarrettMorrison/C-Bed
