#ifndef _TLSWSERVER_H_
#define _TLSWSERVER_H_

#include <iostream>
#include <unistd.h>
#include <fstream>
#include <string>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

namespace tlsw{
    
    class Server{
        
        public:
            Server(void);
            Server(int);  //needs: Own debug streams, mutexlock for streams
            Server(const Server&);            
            ~Server(void);

            //Basic setup needs
            Server* clone(void) const; 
            Server& operator=(const Server&);
            bool    operator==(const Server&) const;
            bool    operator!=(const Server&) const;

            //To ostream
            friend std::ostream& operator<<(std::ostream&,
                        const Server&);

            //Helper functions
            void createSocket(); 
            void initSSL(void);
            void createContext(void); 
            void configureContext(void);
            void checkUpdate(void);
            void defaultSetup(void);
            void startServer(void);

            //Getters & Setters
            void        setSock(int);
            void        setPort(int);
            void        setUpdate(bool);
            void        setCertificatePath(std::string);
            void        setPrivateKeyPath(std::string);
            int         getSock(void);
            int         getPort(void);
            bool        isSSLInit(void);
            bool        isUpdate(void);
            bool        isSetup(void);
            std::string getCertificatePath(void);
            std::string getPrivateKeyPath(void);

        private:
            int          sock;
            int          port;
            int          numConnections;
            bool         update;
            bool         sslinit;
            bool         setup;
            std::string  certificate;
            std::string  privatekey;
            SSL_CTX      *ctx;
    };
}

#endif
