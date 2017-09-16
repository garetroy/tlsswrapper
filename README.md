**tlswrapper** is a wrapper for basic TCP server/clients (with tls encryption) orignially from c based functions. Allows for more programming efficiency, higher level understanding, and less to program for next time! It provides an interfacing for message passing, checking/sending/recieving updates, adding custom server response phrases(work in prog), adding functions to the main server loop(work in prog), logging(work in progress), and adding functions to the server's runloop(work in progress).

## Requirements
    openSSL  - 1.0.2k or higher
    cmake    - 3.6.3  or higher 
    glog     - Most current

You can get glog [here](https://github.com/google/glog)

## Installation
Go to the build directory then continue with the following commands.
    
    chmod +x ./build.sh ./recemake.sh
    ./recmake.sh
    ./build.sh

Then it is built to run the main in src/tlswrapper.cxx by executing the command in the build directory.
    
    ./tlswrapper [option]

Build scheme made with [C-Bed](https://github.com/GarrettMorrison/C-Bed)
