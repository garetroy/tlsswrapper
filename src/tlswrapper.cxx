#include <openssl/ssl.h>
#include <tlsw.h>
int main()
{
    tlsw::Server ourserver(100);
    std::cout << ourserver << std::endl;
    return 0;
}
