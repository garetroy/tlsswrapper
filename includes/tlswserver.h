#ifndef _SERVER_H_
#define _SERVER_H_

#include <iostream>

namespace tlsw{
    
    class Server{
        
        public:
            Server(void){}
            ~Server(void){}

            Server* clone(void) const; 
            Server& operator=(const Server&);
    };
}

#endif;
