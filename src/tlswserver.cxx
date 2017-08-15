#include <tslwserver.h>

namespace tlsw{
    
    Server::Server(void) 
    {}

    Server::~Server(void)
    {}
    
    Server*
    Server::clone(void) const
    {return nullptr;}
    
    Server&
    Server::operator=(const Server&)
    {return nullptr;} 
};
