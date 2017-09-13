//NEEDS LOGGING
//NEEDS MULTITHREADED
//Needs hashmap (message/function), main loop
//updating the numConnections (need mutex lock)
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
        version(0), filepath("./"), maxconnections(5), threads(5)
    {}
    
    Server::Server(int port) : port(port), update(false),
        sock(0), setup(false), certificate(""), 
        privatekey(""), ctx(nullptr), sslinit(false),
        numconnections(0),configured(false), privatecert(""),
        version(0), filepath("./"), maxconnections(5), threads(5)
    {}
    
    Server::Server(const Server& s) : port(s.port), update(s.update),
        sock(s.sock), setup(false), certificate(s.certificate),
        privatekey(s.privatekey), ctx(nullptr), sslinit(false),
        numconnections(0), configured(false), privatecert(""),
        version(0), filepath("./"), maxconnections(5), threads(5)
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
        same = same && (maxconnections == s.maxconnections);

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
        stream << " version(" << s.version << ")";
        return stream;
    }

    void
    Server::recieveMessage(SSL* ssl, char* in)
    {
        memset(in,'\0',std::strlen(in));

        int lost = 1;
        if((lost = SSL_read(ssl,in,3001)) < 0){
            perror("SSL_read failed tlswserver");
            //exit thread
            //logging
            //setcodes
            throw 0;
        }else if(lost == 0){
            perror("Connection lost");
            //exit thread
            //logging
            //setcodes
            throw 0;
        } 

        //add time and messages to logs
    } 

    void
    Server::sendMessage(SSL* ssl, char* out)
    {
        //get time, log
        int lost = 0;
        if((lost = SSL_write(ssl, out, std::strlen(out))) < 0){
            perror("Failed sending tlswserver");
            //exitthread
            //needs loggng
            //needs codes
            throw 0;
        }else if(lost == 0){
            perror("Connection lost");
            //exitthread
            throw 0;
        }
    }

    void
    Server::sendMessage(SSL* ssl, std::string out)
    {
        //get time, log
        const char* newout = out.c_str();
        int lost = 0;
        if((lost = SSL_write(ssl, newout, std::strlen(newout))) < 0){
            perror("Failed sending tlswserver");
            //exitthread
            exit(EXIT_FAILURE);
        }else if(lost == 0){
            perror("Connection lost");
            //exitthread
            exit(EXIT_FAILURE);
        }
    }

    void
    Server::createSocket()
    {
        /*
            Creates the main socket
        */

        if(!configured){
            createContext();
            configureContext();
        }
            
        struct sockaddr_in addr;
        addr.sin_family      = AF_INET;
        addr.sin_port        = htons(port);
        addr.sin_addr.s_addr = htonl(INADDR_ANY);

        //TCP
        sock = socket(AF_INET,SOCK_STREAM,0);
        if(sock < 0){
            perror("Cannot create socket tlswserver");
            exit(EXIT_FAILURE);
        };

        if(bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0){
            perror("Could not bind tlswserver");
            exit(EXIT_FAILURE);
        }

        if(listen(sock,SOMAXCONN)){
            perror("Could not listen tlswserver");
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
            perror("Could not create SSL contex tlswserver");
            ERR_print_errors_fp(stderr);
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
            std::cerr << "Context was not created for server" << std::endl;
            exit(EXIT_FAILURE);
        }

        std::ifstream cert(certificate);
        if(!cert){
            std::cerr << "Certificate path invalid" << std::endl; 
            exit(EXIT_FAILURE);
        }

        std::ifstream privk(privatekey);
        if(!privk){
            std::cerr << "Privatekey path invalid" << std::endl; 
            exit(EXIT_FAILURE);
        }

        std::ifstream privcert(privatecert);
        if(!privcert){
            std::cerr << "PrivateCert path invalid" << std::endl; 
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
        initSSL();
        createContext();
        configureContext();
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
                std::cerr << "Certificate Verify Failed\n"; 
                success = false;
            }
            X509_free(sslcert);             
        }else{
            std::cerr << "There is no client certificate\n";
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
            SSL  *ssl;
            uint len  = sizeof(addr);

            int client = accept(sock, (struct sockaddr*)&addr,
                            &len);
            if(client < 0){
                perror("Could not accept client tlswserver");
                exit(EXIT_FAILURE);
            }

            ssl = SSL_new(ctx);
            SSL_set_fd(ssl, client);
            if(SSL_accept(ssl) <= 0){
                ERR_print_errors_fp(stderr);
            }
            
            if(!verifyPeer(ssl))
                std::cerr << "Verifying failed\n";

            checkUpdate(ssl);
        
            //uses status for easier lock() functionality
            numconnmtx.lock();
            bool status = (maxconnections == numconnections);
            numconnmtx.unlock();
            while(status){
                //log
                sleep(1);
                numconnmtx.lock();
                status = (maxconnections == numconnections);
                numconnmtx.lock();
            }

            //log
            //NEEDS TO CHECK IF THREAD IS STILL RUNNING, needs to send client as well
            threads[numconnections] = std::thread(&Server::threadFunction,this,ssl,client);
            threads[numconnections].detach();

            numconnmtx.lock();
            numconnections++;
            numconnmtx.unlock();
            
        }
    }

    void
    Server::threadFunction(SSL* ssl,int client)
    {
        /*
            This function is what runs the while loop for each individual 
            connecting client. It's functionality is given to us from the 
            individual.

            @params:
                ssl - (SSL*) the ssl connection correlated to this thread
        */
        numconnmtx.lock();
        std::cerr << numconnections << std::endl;
        numconnmtx.unlock();
        char buff[3000] = {'\0'};
        while(1){
            try{
                //Make sure that below is informed to developers // hashmap here?
                recieveMessage(ssl,buff);
                if(strcmp(buff,"x001") == 0)
                    sendFile(ssl);

                memset(buff,'\0',3000);
            } catch (int threadstatus) {
                numconnmtx.lock();
                numconnections--;
                numconnmtx.unlock();
                //checkthreadstatus log
                SSL_free(ssl);
                close(client);
                return;
            }
        }
    }

    void
    Server::sendFile(SSL* ssl)
    {
        /*
            Gets the filename that is desired and then
            sends the desired filename and it's size if such file exists.
    

            @param:
                ssl - (SSL*) the ssl connection we want to interact with
        */

        char filename[2048] = {'\0'};
        recieveMessage(ssl,filename);
        //change to cerr(eventually logging?)
        fprintf(stderr,"Sending file %s...\n",filename);

        char* path = prePend(filepath.c_str(),filename);

        //Checking path
        std::ifstream desiredfile(path);
        if(!desiredfile){
            std::cerr << "Desired path " << path << " invalid" << std::endl; 
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

        sendMessage(ssl, fsizec);
        sendMessage(ssl, string);
        free(string);
        free(path);
    }

    void
    Server::getFile(SSL* ssl, char* filename)
    {
        /*
            Sends a file to the given ssl connection.
            It then sends the filename and then recieves the file from the client
        
            @param:
                filename - (char*) the name of the file we want from the client
                ssl      - (SSL*) the ssl connection we want to send to
        */

        sendMessage(ssl,filename);

        FILE* fp;
        int   bytesrecieved  = 0;
        int   left           = 0;
        int   len            = 1;
        char  buffer[3000]   = {'\0'};

        char* path = prePend(filepath.c_str(),filename);

        fp = fopen(path,"w+");
        if(fp == nullptr){
            perror("Failed to open file tlswclient");
            exit(EXIT_FAILURE);
        }

        //Get Filesize
        recieveMessage(ssl,buffer);
        bytesrecieved = std::atoi(buffer);
        left          = bytesrecieved;

        if(bytesrecieved == 0){
            fclose(fp);
            return;
        }else if(bytesrecieved < 0){
            fclose(fp);
            perror("Read error tlswclient");
            exit(EXIT_FAILURE); 
        }

        while(((left > 0) && (len = SSL_read(ssl,buffer,256))) > 0)
        {
            fwrite(buffer, sizeof(char), len, fp);
            left -= len;
            memset(buffer,'\0',3000);
        }

        fclose(fp);
        free(path);

    }

    void
    Server::checkUpdate(SSL* ssl)
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

        fprintf(stderr, "Checking for update..\n");
        char vers[4] = {'\0'};
        snprintf(vers, sizeof(vers), "%f", version);
        sendMessage(ssl,vers);

        return;
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
