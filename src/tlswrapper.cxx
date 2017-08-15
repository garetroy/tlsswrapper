#include <openssl/ssl.h>
#include <tlsw.h>
int main()
{
    tlsw::Server ourserver;
    ourserver.setPort(100);
    return 0;
}
