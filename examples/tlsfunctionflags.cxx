/*
    This program shows you how to add a corresponding flag.
*/
#include <openssl/ssl.h>
#include <tlsw.h>

void
printme(void* in)
{
    tlsw::clientcresidentials* items = in;
    fprintf(stderr,"HERE");
}

void
cow(void* in)
{
    tlsw::clientcresidentials* items = in;
    fprintf(stderr,"DOGDOGDOGDOG\n");
}

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
        ourserver.setFilePath("./serverfiles/");
        ourserver.setUpdate(true);
        ourserver.setVersion(0.2);
        ourserver.setMainFunction(printme);
        ourserver.addFlag("x002",cow);
        ourserver.startServer();
        std::cout << ourserver << std::endl;
    }else if(type == 0){
        //Testing client
        tlsw::Client ourclient("127.0.0.1",4095);
        ourclient.setCertificatePath("/Users/garett/Projects/tlswrapper/cert/ca.crt");
        ourclient.setPrivateKeyPath("/Users/garett/Projects/tlswrapper/cert/client.key");
        ourclient.setPrivateCertPath("/Users/garett/Projects/tlswrapper/cert/client.crt");
        ourclient.setUpdate(true);
        ourclient.setFilePath("./clientfiles/");
        ourclient.setVersion(0.2);
        ourclient.startClient();
        std::cout << ourclient << std::endl;
        ourclient.sendMessage("x002");
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

        char* dog = "dog";
        char* cat = "cat";
        
        char* frog = tlsw::prePend(dog,cat);
        std::cout << frog << std::endl;

    }

    return 0;
}
