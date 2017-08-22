#ifndef _TLSWCLIENT_H_
#define _TLSWCLIENT_H_

#include <iostream>
#include <fstream>
#include <string>
#include <cctype>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

namespace tlsw{

    class Client{
        
        public:
            Client(void);
            Client(std::string,int);
            Client(const Client&);
            ~Client(void);
            
            //Operators and Cloning
            Client* clone(void) const;
            Client& operator=(const Client&);
            bool    operator==(const Client&) const;
            bool    operator!=(const Client&) const;
    
            //To ostream
            friend std::ostream& operator<<(std::ostream&,
                        const Client&);

            //Helper Functions
            void recieveMessage(void);
            void sendMessage(char*); 
            void sendMessage(std::string); 
            void createSocket(void);
            void initSSL(void);
            void configureContext(void);
            bool verifyPeer(void);
            void defaultSetup(void);
            void startClient(void);
            void getFile(char*);
            
            //Getters and Setters
            void        setSock(int);
            void        setPort(int);
            void        setBuffsize(int);
            void        clearBuffer(void);
            void        setIP(std::string);
            void        setUpdate(bool);
            void        setCertificatePath(std::string);
            void        setPrivateKeyPath(std::string);
            void        setPrivateCertPath(std::string);
            int         getSock(void);
            int         getPort(void);
            int         getBuffsize(void);
            char*       getBuffer(void);
            std::string getIP(void);
            bool        isUpdate(void);
            bool        isSetup(void);
            std::string getCertificatePath(void);
            std::string getPrivateKeyPath(void);
            std::string getPrivateCertPath(void);
        
        private:
            int         port; //required
            int         sock;
            bool        update;
            bool        sslinit;
            bool        configured;
            bool        setup;
            bool        connected;
            char*       buffer;
            int         buffsize;
            std::string ip; //required
            std::string certificate; //required
            std::string privatekey; //required
            std::string privatecert; //required
            SSL_CTX     *ctx;
            SSL         *ssl;
    };
}
#endif
