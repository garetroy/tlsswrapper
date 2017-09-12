#include <openssl/ssl.h>
#include <tlsw.h>

int main(int argc, char* argv[])
{
    int type = 3;
    if (argc >= 2)
        type = std::atoi(argv[1]);

    if(type == 1){
        //Testing Server
        tlsw::Server ourserver(4095);
        ourserver.setCertificatePath("/Users/garett/Projects/tlswrapper/cert/ca.crt");
        ourserver.setPrivateKeyPath("/Users/garett/Projects/tlswrapper/cert/server.key");
        ourserver.setPrivateCertPath("/Users/garett/Projects/tlswrapper/cert/server.crt");
        ourserver.setUpdate(true);
        ourserver.setVersion(0.3);
        ourserver.startServer();
        std::cout << ourserver << std::endl;
    }else if(type == 0){
        //Testing client
        tlsw::Client ourclient("127.0.0.1",4095);
        ourclient.setCertificatePath("/Users/garett/Projects/tlswrapper/cert/ca.crt");
        ourclient.setPrivateKeyPath("/Users/garett/Projects/tlswrapper/cert/client.key");
        ourclient.setPrivateCertPath("/Users/garett/Projects/tlswrapper/cert/client.crt");
        ourclient.setUpdate(true);
        ourclient.setVersion(0.2);
        ourclient.startClient();
        std::cout << ourclient << std::endl;
        ourclient.recieveMessage();
        std::cout << ourclient.getBuffer() << std::endl;
        ourclient.getFile("test.txt");
    }else if(type == 3){
        //Testing Helper functions
        char buffer[3] = {'\0'};
        buffer[0] = 'E';
        buffer[1] = '@';
    
        char newbuffer[3] = {'\0'};
        tlsw::stripString(buffer,newbuffer);    
    
        tlsw::lower(newbuffer);
    
        std::cout << newbuffer << std::endl;
     
        char time[150] = {'\0'};
        tlsw::getTime(time);
        std::cout << time << std::endl;
    }

    return 0;
}
