/*
    This is a basic program that just starts the server/client and 
    sends a few messages to the server from the client
*/
#include <tlsw.h>

int main(int argc, char* argv[])
{
    int type = 3;
    if (argc >= 2)
        type = std::atoi(argv[1]);

    if(type == 1){
        //Testing Server
        tlsw::Server ourserver(4095);
        ourserver.setCertificatePath("../cert/ca.crt");
        ourserver.setPrivateKeyPath("../cert/server.key");
        ourserver.setPrivateCertPath("../cert/server.crt");
        ourserver.startServer();
    }else if(type == 0){
        //Testing client
        tlsw::Client ourclient("127.0.0.1",4095);
        ourclient.setCertificatePath("../cert/ca.crt");
        ourclient.setPrivateKeyPath("../cert/client.key");
        ourclient.setPrivateCertPath("../cert/client.crt");
        ourclient.startClient();
        ourclient.sendMessage("SENT!\n");
        ourclient.sendMessage("A!\n");
        ourclient.sendMessage("MESSAGE!\n");
    }

    return 0;
}
