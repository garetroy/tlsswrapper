#ifndef _TLSWHELPER_H_
#define _TLSWHELPER_H_

#include <cstdio>
#include <ctime>
#include <cctype>
#include <cstring>
#include <cstdlib>

namespace tlsw{
    
    void stripString(char*, char*);
    void getTime(char*);
    void lower(char*);
    int  getLine(char*,size_t);
    
}
#endif
