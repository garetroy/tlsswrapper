/*
    tlswserver.cxx
    The source file for tlswserver
    Author:
        Garett Roberts
*/

#include <tlswserver.h>

namespace tlsw{

    Server::Server(void) : port(0), update(false),
        sock(0), setup(false), certificate(""), 
        privatekey(""), ctx(nullptr), sslinit(false),
        numconnections(0), configured(false), privatecert(""),
        version(0), filepath("./"), maxconnections(5), threads(5),
        funcset(false), tls(true)
    {}
    
    Server::Server(int port) : port(port), update(false),
        sock(0), setup(false), certificate(""), 
        privatekey(""), ctx(nullptr), sslinit(false),
        numconnections(0),configured(false), privatecert(""),
        version(0), filepath("./"), maxconnections(5), threads(5),
        funcset(false), tls(true)
    {}
    
    Server::Server(const Server& s) : port(s.port), update(s.update),
        sock(s.sock), setup(false), certificate(s.certificate),
        privatekey(s.privatekey), ctx(nullptr), sslinit(false),
        numconnections(0), configured(false), privatecert(""),
        version(0), filepath("./"), maxconnections(5), threads(5),
        funcset(false), tls(true)
    {}

    Server::~Server(void)
    {
        //Checks to see if ctx is declared
        if(ctx != nullptr)
            SSL_CTX_free(ctx);

        //Cleanup
        EVP_cleanup();

        //Closes socket
        if(setup)
            close(sock);
    }
    
    Server*
    Server::clone(void) const
    {
    /* 
        This function clones the server object
        
        @returns:
            Server*
    */
        return new Server(*this);
    }
    
    Server&
    Server::operator=(const Server& rhs)
    {
    /*
        This function sets a server we are assigning
        with the constants from the Server object
        on the right side of the assignment operator.
        This does not save init or setup variables and
        still requires you to run setup.

        @param:
            rhs - (Server&) The server object to the right
                    of the = operator
        
        @returns:
            Server&
    */
        if(this == &rhs)
            return *this;
        
        sock           = rhs.sock;
        port           = rhs.port;
        update         = rhs.update;
        sslinit        = false;
        setup          = false;
        configured     = false;
        certificate    = rhs.certificate;
        privatekey     = rhs.privatekey;
        privatecert    = rhs.privatecert;
        ctx            = nullptr;
        numconnections = 0;
        version        = rhs.version;
        filepath       = rhs.filepath;
        maxconnections = rhs.maxconnections;
        func           = rhs.func;
        funcset        = rhs.funcset;
        calls          = rhs.calls;
        tls            = rhs.tls;
        
       return *this; 
    } 

    bool
    Server::operator==(const Server& s) const
    {
        /*
            Compares by checking type, socket, ports, setups vars,
            init vars, and cert/key directories
        
            @param:
                s - (Server&) The server object to compare on the 
                    right side of the == operator

            @returns:
                bool - True if same 
                       False if not
        */
        if(typeid(*this) != typeid(s))
            return false;
        
        bool same = false;
        
        same = (sock == s.sock) && (port == s.port);
        same = same && (update == s.update) && (sslinit == s.sslinit);
        same = same && (setup == s.setup) && (certificate == s.certificate);
        same = same && (privatekey == s.privatekey) && (privatecert == s.privatecert);
        same = same && (version == s.version) && (filepath == s.filepath);
        same = same && (maxconnections == s.maxconnections) && (funcset == s.funcset);
        same = same && (func == s.func) && (tls == s.tls) && (calls == s.calls);

        return same;
    }

    bool
    Server::operator!=(const Server& s) const
    {
        /*
            Uses the == operator to find !=

            @param:
                s - (Server&) Server object on the right of the
                    != operator
            
            @returns:
                bool - True if not the same
                       False if same
        */
             
        return !(*this == s);
    }

    std::ostream& operator<<(std::ostream& stream,
                const Server& s)
    {
        /*
            Overloading the << operator to be able to print
            this object with useful information.
            
            @param:
                stream - (std::ostream&) the stream we want to
                    put our text into
                s      - (Server&) The server object we want to
                    print
            
            @returns:
                std::ostream& - The stream that we inputted into
        */

        stream << "The Server's port(" << s.port << ")";
        stream << " has " << s.numconnections << " connections";
        stream << " and updates(" << s.update << ")";
        stream << " setup(" << s.setup << ")";
        stream << " certificatePath(" << s.certificate;
        stream << ") privateKeyPath(" << s.privatekey << ")";
        stream << " privateCertPath(" << s.privatecert << ")";
        stream << " version(" << s.version << ")" << " tls(";
        stream << s.tls << ")";
        return stream;
    }

    void
    Server::recieveMessage(clientcresidentials *cres, char* in)
    {
        memset(in,'\0',std::strlen(in));

        int lost = 1;
        if(cres->ssl != nullptr){
            if((lost = SSL_read(cres->ssl,in,3001)) < 0){
                PLOG(ERROR) << "SSL_read failed tlswserver";
                throw 0;
            }else if(lost == 0){
                PLOG(ERROR) << "Client disconnected, could not get message";
                throw 0;
            } 
        }else{
            if((lost = recv(cres->sock,in,3001,0)) < 0){
                PLOG(ERROR) << "recv failed tlswserver";
                throw 0;
            }else if(lost == 0){
                PLOG(ERROR) << "Client disconnected, could not get message";
                throw 0;
            }
        }
    } 

    void
    Server::sendMessage(clientcresidentials *cres, char* out)
    {
        int lost = 0;
        if(cres->ssl != nullptr){
            if((lost = SSL_write(cres->ssl, out, std::strlen(out))) < 0){
                PLOG(ERROR) << "SSL_write failed tlswserver";
                throw 0;
            }else if(lost == 0){
                LOG(INFO) << "Client disconnected, could not send message";
                throw 0;
            }
        }else{
            if((lost = send(cres->sock, out, std::strlen(out), 0)) < 0){
                PLOG(ERROR) << "SSL_write failed tlswserver";
                throw 0;
            }else if(lost == 0){
                LOG(INFO) << "Client disconnected, could not send message";
                throw 0;
            }
        }
    }

    void
    Server::sendMessage(clientcresidentials *cres, std::string out)
    {
        const char* newout = out.c_str();
        int lost           = 0;
        if(cres->ssl != nullptr){
            if((lost = SSL_write(cres->ssl, newout, std::strlen(newout))) < 0){
                PLOG(ERROR) << "SSL_write failed tlswserver";
                throw 0;
            }else if(lost == 0){
                LOG(INFO) << "Client disconnected, could not send message";
                throw 0;
            }
        }else{
            if((lost = send(cres->sock, newout, std::strlen(newout),0)) < 0){
                PLOG(ERROR) << "SSL_write failed tlswserver";
                throw 0;
            }else if(lost == 0){
                LOG(INFO) << "Client disconnected, could not send message";
                throw 0;
            }
        };
    }

    void
    Server::createSocket()
    {
        /*
            Creates the main socket
        */

        struct sockaddr_in addr;
        addr.sin_family      = AF_INET;
        addr.sin_port        = htons(port);
        addr.sin_addr.s_addr = htonl(INADDR_ANY);

        //TCP
        sock = socket(AF_INET,SOCK_STREAM,0);
        if(sock < 0){
            PLOG(ERROR) << "tlswserver could not create socket";
            exit(EXIT_FAILURE);
        };

        if(bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0){
            PLOG(ERROR) << "tlswserver could not bind to socket";
            exit(EXIT_FAILURE);
        }

        if(listen(sock,SOMAXCONN)){
            PLOG(ERROR) << "tlswserver could not listen to the socket";
            exit(EXIT_FAILURE);
        }
        
        setup = true;
    }

    void
    Server::initSSL(void)
    {
        /*
            Initializes the OpenSSL library
            in preperation for TCP/TLS connections
        */

        //Check to see if already init
        if(sslinit)
            return;

        SSL_load_error_strings();
        OpenSSL_add_ssl_algorithms();     
        sslinit = true;
    }


    void 
    Server::createContext(void)
    {
        /*
            Creates the context for a secure
            TCP/TLS connection
        */

        if(!sslinit)
            initSSL();

        if(ctx != nullptr)
            SSL_CTX_free(ctx);
            ctx = nullptr; 

        const SSL_METHOD *method;

        method = SSLv23_server_method();
        ctx    = SSL_CTX_new(method);        
        if(ctx == nullptr){
            PLOG(ERROR) << "Could not create SSL contex tlswserver";
            exit(EXIT_FAILURE);
        }
    }

    void 
    Server::configureContext(void)
    {
        /*
            Configures the context for the TCP/TLS connection.
            This also checks to see if the cert/key paths are
            valid.
        */

        if(!sslinit)
            initSSL();

        if(ctx == nullptr){
            PLOG(ERROR) << "Context was not declared for server";
            exit(EXIT_FAILURE);
        }

        std::ifstream cert(certificate);
        if(!cert){
            PLOG(ERROR) << "Certificate path invalid tlswserver";
            exit(EXIT_FAILURE);
        }

        std::ifstream privk(privatekey);
        if(!privk){
            PLOG(ERROR) << "Privatekey path invalid tlswserver";
            exit(EXIT_FAILURE);
        }

        std::ifstream privcert(privatecert);
        if(!privcert){
            PLOG(ERROR) << "PrivateCert path invalid tlswserver";
            exit(EXIT_FAILURE);
        }

        SSL_CTX_set_ecdh_auto(ctx,1);
    
        if(SSL_CTX_use_certificate_file(ctx,privatecert.c_str(),SSL_FILETYPE_PEM) <= 0){
            ERR_print_errors_fp(stderr);
            exit(EXIT_FAILURE);
        }

        if(SSL_CTX_use_PrivateKey_file(ctx,privatekey.c_str(),SSL_FILETYPE_PEM) <= 0){
            ERR_print_errors_fp(stderr);
            exit(EXIT_FAILURE);
        }

        //Preparing to verify peer
        if(!SSL_CTX_load_verify_locations(ctx, certificate.c_str(), NULL))
        {
            ERR_print_errors_fp(stderr);
            exit(EXIT_FAILURE);      
        }
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
        SSL_CTX_set_verify_depth(ctx, 1);

        configured = true;

    }

    void 
    Server::defaultSetup(void)
    {
        /*
            This method is to be invoked if all required objects
            are loaded up and you don't have anything in paticular
            you want to setup
        */

        //Setup Logger
        FLAGS_log_dir = filepath;
        google::InitGoogleLogging("serverlog");
        if(tls){
            initSSL();
            createContext();
            configureContext();
        }
        createSocket();
    }

    bool
    Server::verifyPeer(SSL* ssl)
    {
        /*
            This function verifies the ssl connections certificates
            and returns true if verified.

            @param:
                ssl - (SSL*) the ssl session.
                
            @returns:
                bool - True if successfully verified, false otherwise
        */
        bool success = true;
        
        X509 *sslcert = nullptr;
        sslcert = SSL_get_peer_certificate(ssl);
        if(sslcert){
            long verifyresult = SSL_get_verify_result(ssl);
            if(verifyresult != X509_V_OK){
                PLOG(ERROR) << "Certificate Verify Failed"; 
                success = false;
            }
            X509_free(sslcert);             
        }else{
            LOG(ERROR) << "There is no client certificate";
            success = false;
        }
        return success;
    }
    

 
    void
    Server::startServer(void)
    {
        /*
            This is the actual server part.
            The server will listen for new connections and
            will then make a thread per new connection,
            calling the runClient function for each client
            session.
        
            Defualts to defaultSetup() if setup is not true 
            when calling startServer.
        */
        if(setup != true)
            defaultSetup();

        while(1){
            struct sockaddr_in addr;
            SSL  *ssl = nullptr;
            uint len  = sizeof(addr);

            int client = accept(sock, (struct sockaddr*)&addr,
                            &len);
            if(client < 0){
                PLOG(ERROR) << "Could not accept client tlswserver";
                exit(EXIT_FAILURE);
            }

            if(tls){
                ssl = SSL_new(ctx);
                SSL_set_fd(ssl, client);
                if(SSL_accept(ssl) <= 0){
                    ERR_print_errors_fp(stderr);
                }
            
                if(!verifyPeer(ssl))
                    LOG(ERROR) << "Verifying ssl failed tlswserver";
                    continue;
            }
            
            clientcresidentials cres;
            cres.ssl  = ssl;
            cres.sock = client;
            checkUpdate(&cres);
        
            //uses status for easier lock() functionality
            numconnmtx.lock();
            bool status = (maxconnections == numconnections);
            numconnmtx.unlock();
            while(status){
                sleep(1);
                numconnmtx.lock();
                status = (maxconnections == numconnections);
                numconnmtx.unlock();
            }

            //NEEDS TO CHECK IF THREAD IS STILL RUNNING, needs to send client as well
            LOG(INFO) << "Starting new client connections";
            threads[numconnections] = std::thread(&Server::threadFunction,this,cres);
            threads[numconnections].detach();

            numconnmtx.lock();
            numconnections++;
            LOG(INFO) << "Number of connections is now " << numconnections;
            numconnmtx.unlock();
        }
    }

    void
    Server::threadFunction(clientcresidentials cres)
    {
        /*
            This function is what runs the while loop for each individual 
            connecting client. It's functionality is given to us from the 
            individual. If a function is given to the server via
            setMainFunction, then the loop will run that function for every
            iteration of the while loop.

            @params:
                ssl - (SSL*) the ssl connection correlated to this thread
        */
        char buff[3000] = {'\0'};
        while(1){
            try{
                recieveMessage(&cres,buff);
                LOG(INFO) << "Got message: " << buff;

                if(strcmp(buff,"x001") == 0)
                    sendFile(&cres);

                //check our flags
                for(auto &i : calls)
                    if(strcmp(buff,i.first) == 0){
                        i.second((void*)&cres);
                        memset(buff,'\0',3000);
                        continue;
                    }

                memset(buff,'\0',3000);

                if(funcset)
                    func((void*)&cres);

            } catch (int threadstatus) {
                numconnmtx.lock();
                numconnections--;
                LOG(INFO) << "Number of connections is now " << numconnections;
                numconnmtx.unlock();
                if(tls)
                    SSL_free(cres.ssl);
                close(cres.sock);
                return;
            }
        }
    }

    void
    Server::addFlag(char* flagname,void(*func)(void*))
    {
        /*
            The jist of this function is to add
            a flag such as "x001" to a function "sendFile"
            (which is already added by default) to the map named calls.
            This allows the main loop for the server to check
            to see if the message matches any flags within the 
            map, and if so it executes the corresponding function.
        
            @params:
                flagname - (char*) the flag we want to recognize
                func     - (void(*)(void*)) the function and paramaters
        
        */

        calls.insert(std::make_pair(flagname,func));
    }

    void
    Server::removeFlag(char* flagname)
    {
        /*
            This function removes the flag from the calls map

            @param:
                flagname - (char*) the flag we want to remove
        */
        for(auto it = calls.begin(); it != calls.end();)
            if(strcmp(it->first,flagname) == 0)
                calls.erase(it);
    }

    void
    Server::sendFile(clientcresidentials *cres)
    {
        /*
            Gets the filename that is desired and then
            sends the desired filename and it's size if such file exists.
    

            @param:
                ssl - (SSL*) the ssl connection we want to interact with
        */

        char filename[2048] = {'\0'};
        recieveMessage(cres,filename);
        LOG(INFO) << "Sending file " << filename;
        

        char* path = prePend(filepath.c_str(),filename);

        //Checking path
        std::ifstream desiredfile(path);
        if(!desiredfile){
            LOG(ERROR) << "The set path is invalid";
            exit(EXIT_FAILURE);
        }

        //Needs logging
        FILE *f = fopen(path,"rb");
        fseek(f, 0, SEEK_END);
        int fsize = ftell(f);
        fseek(f, 0, SEEK_SET);

        char fsizec[5] = {'\0'};
        snprintf(fsizec, sizeof(fsizec), "%d", fsize);
        
        //Solve sending file?
        char *string = (char*)new char[fsize + 1];
        fread(string, fsize, 1, f);
        fclose(f);

        sendMessage(cres, fsizec);
        sendMessage(cres, string);
        free(string);
        free(path);
    }

    void
    Server::getFile(clientcresidentials* cres, char* filename)
    {
        /*
            Sends a file to the given ssl connection.
            It then sends the filename and then recieves the file from the client
        
            @param:
                filename - (char*) the name of the file we want from the client
                ssl      - (SSL*) the ssl connection we want to send to
        */

        LOG(INFO) << "Sending file: " << filename;

        sendMessage(cres,filename);

        FILE* fp;
        int   bytesrecieved  = 0;
        int   left           = 0;
        int   len            = 1;
        char  buffer[3000]   = {'\0'};

        char* path = prePend(filepath.c_str(),filename);

        fp = fopen(path,"w+");
        if(fp == nullptr){
            PLOG(ERROR) << "Failed to open file for sending tlswclient";
            exit(EXIT_FAILURE);
        }

        //Get Filesize
        recieveMessage(cres,buffer);
        bytesrecieved = std::atoi(buffer);
        left          = bytesrecieved;

        if(bytesrecieved == 0){
            fclose(fp);
            return;
        }else if(bytesrecieved < 0){
            fclose(fp);
            PLOG(ERROR) << "Read error tlswclient";
            exit(EXIT_FAILURE); 
        }

        while(((left > 0) && (len = SSL_read(cres->ssl,buffer,256))) > 0)
        {
            fwrite(buffer, sizeof(char), len, fp);
            left -= len;
            memset(buffer,'\0',3000);
        }

        fclose(fp);
        free(path);

    }

    void
    Server::checkUpdate(clientcresidentials *cres)
    {
        /*
            This will check with the client for updates.
            IMPORTANT:
                Make sure that both the client and server have
                updates on.

            @param:
                ssl - (SSL*) the ssl session we want to check
        */

        if(!update)
            return;

        LOG(INFO) << "Checking for update with client";
        char vers[4] = {'\0'};
        snprintf(vers, sizeof(vers), "%f", version);
        sendMessage(cres,vers);

        return;
    } 

    void
    Server::setTLS(bool on)
    {
        tls = on;
    }

    void
    Server::setSock(int socket)
    {
        sock = socket;
    }

    void
    Server::setPort(int inport)
    {
        port = inport;
    }
    
    void
    Server::setUpdate(bool updating)
    {
        update = updating;
    }

    void
    Server::setVersion(double ver)
    {
        version = ver;
    }

    void
    Server::setCertificatePath(std::string path)
    {
        certificate = path;
    }

    void
    Server::setPrivateKeyPath(std::string path)
    {
        privatekey = path;
    }

    void
    Server::setPrivateCertPath(std::string path)
    {
        privatecert = path;
    }
    
    void
    Server::setFilePath(std::string path)
    {
        filepath = path;
    }

    void
    Server::setMainFunction(void(*in)(void*))
    {
        funcset = true;
        func = in;
    }

    int
    Server::getSock(void)
    {
        return sock;
    }

    int 
    Server::getPort(void)
    {
        return port;
    }
    
    double
    Server::getVersion(void)
    {
        return version;
    }
    
    bool
    Server::isUpdate(void)
    {
        return update;
    }

    bool
    Server::isSetup(void)
    {
        return setup;
    }

    bool
    Server::isTLS(void)
    {
        return tls;
    }

    std::string 
    Server::getCertificatePath(void)
    {
        return certificate;
    }

    std::string
    Server::getPrivateKeyPath(void)
    {
        return privatekey;
    }

    std::string
    Server::getPrivateCertPath(void)
    {
        return privatecert;
    }

    std::string
    Server::getFilePath(void)
    {
        return filepath;
    }
}
