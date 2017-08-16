#include <openssl/ssl.h>
#include <tlsw.h>
int main(int argc, char* argv[])
{
    int type = std::atoi(argv[1]);
    if(type == 1){
        tlsw::Server ourserver(4095);
        ourserver.setCertificatePath("/Users/garett/Projects/tlswrapper/cert/ca.crt");
        ourserver.setPrivateKeyPath("/Users/garett/Projects/tlswrapper/cert/server.key");
        ourserver.setPrivateCertPath("/Users/garett/Projects/tlswrapper/cert/server.crt");
        ourserver.startServer();
        std::cout << ourserver << std::endl;
    }else{
        tlsw::Client ourclient("127.0.0.1",4095);
        ourclient.setCertificatePath("/Users/garett/Projects/tlswrapper/cert/ca.crt");
        ourclient.setPrivateKeyPath("/Users/garett/Projects/tlswrapper/cert/client.key");
        ourclient.setPrivateCertPath("/Users/garett/Projects/tlswrapper/cert/client.crt");
        ourclient.startClient();
        std::cout << ourclient << std::endl;
    }
    return 0;
}
