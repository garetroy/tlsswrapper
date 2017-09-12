/*
    tlswserver.h
    This is the header file for the tlswrapper.
    Author:
        Garett Roberts

    This is a wrapper for a TCP/TLS server (originall written in c) that will provide basic functionality/deployment of a TCP/TLS server without much hassle and using c++. There are a few options when setting up the server, which will be explained in the docs, or the individual functions will also be explained in the source file.

    IMPORTANT:
        All elemnts that are marked required must be set before
        attempting to run the server.
*/
#ifndef _TLSWSERVER_H_
#define _TLSWSERVER_H_

#include <iostream>
#include <unistd.h>
#include <fstream>
#include <cstdlib>
#include <numeric>
#include <string>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include <tlsw.h>

namespace tlsw{
    
    class Server{
        
        public:
            Server(void);
            Server(int);  //needs: Own debug streams, mutexlock for streams
            Server(const Server&);            
            ~Server(void);

            //Operators and Cloning
            Server* clone(void) const; 
            Server& operator=(const Server&);
            bool    operator==(const Server&) const;
            bool    operator!=(const Server&) const;

            //To ostream
            friend std::ostream& operator<<(std::ostream&,
                        const Server&);

            //Helper functions
            void recieveMessage(SSL*,char*);
            void sendMessage(SSL*,char*);
            void sendMessage(SSL*,std::string);
            void createSocket(void); 
            void initSSL(void);
            void createContext(void); 
            void configureContext(void);
            void checkUpdate(SSL*);
            void defaultSetup(void);
            bool verifyPeer(SSL*);
            void startServer(void);
            void sendFile(SSL*);

            //Getters & Setters
            void        setSock(int);
            void        setPort(int);
            void        setUpdate(bool);
            void        setVersion(double);
            void        setCertificatePath(std::string);
            void        setPrivateKeyPath(std::string);
            void        setPrivateCertPath(std::string);
            void        setFilePath(std::string);
            int         getSock(void);
            int         getPort(void);
            double      getVersion(void);
            bool        isUpdate(void);
            bool        isSetup(void);
            std::string getCertificatePath(void);
            std::string getPrivateKeyPath(void);
            std::string getPrivateCertPath(void);
            std::string getPatchPath(void);
            std::string getFilePath(void);

        private:
            int          sock;
            int          port; //required
            int          numConnections;
            double       version;
            bool         update;
            bool         sslinit;
            bool         configured;
            bool         setup;
            std::string  certificate; //required
            std::string  privatekey; //required
            std::string  privatecert;//required
            std::string  filepath;
            SSL_CTX      *ctx;
    };
}

#endif
