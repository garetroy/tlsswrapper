**tlswrapper** is a wrapper for basic TCP server/clients (with tls encryption) orignially from c based functions. Allows for more programming efficiency, higher level understanding, and less to program for next time! It provides an interfacing for message passing, checking/sending/recieving updates(still working on), logging(work in progress), and adding functions to the server's runloop(work in progress).

## Requirements
    openSSL
    cmake   - 3.6.3 or higher 

## Installation
Go to the build directory then continue with the following commands.
    
    chmod +x ./build.sh ./recemake.sh
    ./recmake.sh
    ./build.sh

Then it is built to run the main in src/tlswrapper.cxx by executing the command
    
    ./tlswrapper [option]

in the build directory.

Build scheme made with [C-Bed](https://github.com/GarrettMorrison/C-Bed)
