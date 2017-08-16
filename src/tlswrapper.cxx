#include <openssl/ssl.h>
#include <tlsw.h>
int main()
{
    tlsw::Server ourserver(4095);
    ourserver.setCertificatePath("/Users/garett/Projects/tlswrapper/cert/rootCA.pem");
    ourserver.setPrivateKeyPath("/Users/garett/Projects/tlswrapper/cert/rootCA.key");
    ourserver.startServer();
    std::cout << ourserver << std::endl;
    return 0;
}
