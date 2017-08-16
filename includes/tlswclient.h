#ifndef _TLSWCLIENT_H_
#define _TLSWCLIENT_H_

#include <stdio.h>
#include <iostream>
#include <fstream>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <string>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <ctype.h>

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
            void createSocket(void);
            void initSSL(void);
            void configureContext(void);
            bool verifyPeer(SSL*);
            void defaultSetup(void);
            void startClient(void);
            
            //Getters and Setters
            void        setSock(int);
            void        setPort(int);
            void        setIP(std::string);
            void        setUpdate(bool);
            void        setCertificatePath(std::string);
            void        setPrivateKeyPath(std::string);
            void        setPrivateCertPath(std::string);
            int         getSock(void);
            int         getPort(void);
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
            std::string ip; //required
            std::string certificate; //required
            std::string privatekey; //required
            std::string privatecert; //required
            SSL_CTX     *ctx;
    };
}
#endif
