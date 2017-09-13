/*
    This example script displays setting file paths and turning on updates
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
        ourserver.setFilePath("./serverfiles/"); //Sets where to put/take files from
        ourserver.setCertificatePath("../cert/ca.crt");
        ourserver.setPrivateKeyPath("../cert/server.key");
        ourserver.setPrivateCertPath("../cert/server.crt");
        ourserver.setUpdate(true); //Make sure this is set for both
        ourserver.setVersion(0.3);
        ourserver.startServer();
    }else if(type == 0){
        //Testing client
        tlsw::Client ourclient("127.0.0.1",4095);
        ourclient.setFilePath("./clientfiles/"); //Sets where to put/take files from
        ourclient.setCertificatePath("../cert/ca.crt");
        ourclient.setPrivateKeyPath("../cert/client.key");
        ourclient.setPrivateCertPath("../cert/client.crt");
        ourclient.setUpdate(true);
        ourclient.setVersion(0.2);
        ourclient.startClient();
        //Once this runs, check the clientfiles folder to see what the patch did
    }
    return 0;
}
