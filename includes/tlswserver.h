/*
    tlswserver.h
    This is the header file for the tlswrapper.
    Author:
        Garett Roberts

    This is a wrapper for a TCP/TLS server (originall written in c) that will 
    provide basic functionality/deployment of a TCP/TLS server without much 
    hassle and using c++. There are a few options when setting up the server,
    which will be explained in the docs, or the individual functions will 
    also be explained in the source file.

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
#include <thread>
#include <vector>
#include <mutex>
#include <map>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include <glog/logging.h>
#include <tlsw.h>

namespace tlsw{
    
    typedef struct{
        SSL* ssl;
        int sock;
    }clientcresidentials;

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
            void recieveMessage(clientcresidentials*,char*);
            void sendMessage(clientcresidentials*,char*);
            void sendMessage(clientcresidentials*,std::string);
            void createSocket(void); 
            void initSSL(void);
            void createContext(void); 
            void configureContext(void);
            void checkUpdate(clientcresidentials*);
            void defaultSetup(void);
            bool verifyPeer(SSL*);
            void startServer(void);
            void sendFile(clientcresidentials*);
            void getFile(clientcresidentials*,char*);
            void threadFunction(clientcresidentials);
            void addFlag(char*,void(*)(void*));
            void removeFlag(char*);

            //Getters & Setters
            void        setTLS(bool);
            void        setSock(int);
            void        setPort(int);
            void        setUpdate(bool);
            void        setVersion(double);
            void        setMaxConnections(int);
            void        setCertificatePath(std::string);
            void        setPrivateKeyPath(std::string);
            void        setPrivateCertPath(std::string);
            void        setFilePath(std::string);
            void        setMainFunction(void(*in)(void*));
            int         getSock(void);
            int         getPort(void);
            double      getVersion(void);
            int         getNumConnections(void);
            int         getMaxConnections(void);
            bool        isUpdate(void);
            bool        isSetup(void);
            bool        isTLS(void);
            std::string getCertificatePath(void);
            std::string getPrivateKeyPath(void);
            std::string getPrivateCertPath(void);
            std::string getPatchPath(void);
            std::string getFilePath(void);

        private:
            int          sock;
            int          port; //required
            int          numconnections;
            int          maxconnections;
            double       version;
            bool         update;
            bool         sslinit;
            bool         configured;
            bool         setup;
            bool         tls; 
            bool         funcset;
            std::string  certificate; //required for tls
            std::string  privatekey; //required for tls
            std::string  privatecert;//required for tls
            std::string  filepath;
            SSL_CTX      *ctx;
            std::mutex   numconnmtx;
            void         (*func)(void*);

            std::vector<std::thread>        threads;
            std::map<char*,void(*)(void*)>  calls;
    };
}

#endif
