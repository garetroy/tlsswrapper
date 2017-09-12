/*
    tlswclient.cxx
    The source file for tlswserver
    Author:
        Garett Roberts

    IMPORTANT:
        As of now, clients have their own buffers. Set the sizes accordingly
*/
#include <tlswclient.h>

//Needs Updates
//Needs Versioning (version within class)
//Needs filegetting
//Needs filerecieving

namespace tlsw{
    
    Client::Client(void) : port(0), sock(0), update(0), sslinit(false),
                            configured(false), setup(false), certificate(""),
                            privatekey(""), privatecert(""), ctx(nullptr), ip(""),
                            connected(false), ssl(nullptr), buffsize(2048),
                            version(0)
    {
        buffer = (char*) new char[buffsize];
        clearBuffer();
    }

    Client::Client(std::string ip, int port) : port(port), sock(0), update(0),
                            configured(false), setup(false), certificate(""),
                            privatekey(""), privatecert(""), ctx(nullptr), 
                            ip(ip), connected(false),ssl(nullptr),buffsize(2048),
                            version(0)
    {
        buffer = (char*) new char[buffsize];
        clearBuffer();
    }

    Client::Client(const Client& c) : port(c.port), sock(c.sock),
                            update(c.update), setup(false),
                            certificate(c.certificate), privatekey(c.privatekey),
                            ctx(nullptr), ip(c.ip), connected(c.connected),
                            ssl(nullptr), buffsize(c.buffsize), version(0)
    {
        buffer = (char*) new char[buffsize];
        clearBuffer();
    }

    Client::~Client(void)
    {
        if(ctx != nullptr)
            SSL_CTX_free(ctx);

        EVP_cleanup();

        close(sock);
        SSL_shutdown(ssl);
        SSL_free(ssl);
        delete buffer;
    }

    Client*
    Client::clone(void) const
    {
        /*
            Creates a new instance of this object
        */
        return new Client(*this);
    }
    
    Client&
    Client::operator=(const Client& rhs)
    {
        /*
            Assigns this object from another. It creates it's own buffersize
            and needs to be reinitialized

            @param:
                rhs - (Client&) The client we want to copy from
        */
        if(this == &rhs)
            return *this;

        port        = rhs.port;
        sock        = rhs.sock;
        update      = rhs.update;
        sslinit     = false;
        configured  = false;
        setup       = false; 
        connected   = false;
        buffsize    = rhs.buffsize;
        buffer      = (char*) new char[buffsize];
        clearBuffer();
        ip          = rhs.ip;
        certificate = rhs.certificate;
        privatekey  = rhs.privatekey;
        privatecert = rhs.privatecert;
        ctx         = nullptr;
        ssl         = nullptr;
        version     = rhs.version;
        
        return *this;
    }

    bool
    Client::operator==(const Client& c) const
    {
        /*
            This comparator comparing socket, port, updates, certificate,
            ip address, private key, and privatecertificate
        
            @param:
                c - (Client &) The other client object we want to compare
                    against

            @returns:
                bool - True if same object 
                       False if not the same object            
        */
        if(typeid(*this) != typeid(c))
            return false;
            
        bool same = false;
        
        same = (sock == c.sock) && (port == c.port);
        same = same && (update == c.update) && (certificate == c.certificate);
        same = same && (ip == c.ip) && (privatekey == c.privatekey);
        same = same && (privatecert == c.privatecert) && (version == c.version);
        
        return same;
    }

    bool
    Client::operator!=(const Client& c) const
    {
        /*
            This operator is using the inverse of the == operator
            
            @param:
                c - (Client&) The client object we want to compare against
            
            @returns:
                bool - True if they are not the same
                        False if they are the same
        */
        return !(*this == c);
    }

    std::ostream& 
    operator<<(std::ostream& stream, const Client& c)
    {
        /*
            Our operator overload to making printing this object possible
            
            @params:
                stream - (std::ostream&) the stream we want to output to
                c      - (Client&) the client we are printing
            
            @returns:
                std::ostream& - the modified stream
        */
        stream << "The client is connected(" << c.connected;
        stream << ") to port(" << c.port << ") at " << c.ip;
        stream << " version(" << c.version << ")";
        
        return stream;
    } 
    
    void
    Client::recieveMessage(void)
    {
        /*
            Recieves the message and puts it into the client buffer.
            It first clears the buffer, then sends it over an ssl connection.
        */ 

        clearBuffer();

        if(SSL_read(ssl,buffer,buffsize) <= 0){
            perror("SSL_read failed tlswclient");
            exit(EXIT_FAILURE);
        }
    }

    void
    Client::sendMessage(char* in)
    {
        /*
            Sends the message in the current client buffer.
            It clears the buffer, copies the string to the buffer, then
            send the message over an ssl connection via the buffer.
        
            @param:
                in - (char*) the message we want to send
        */
        if(std::strlen(in) > buffsize){
            std::cerr << "Trying to send a message bigger than buffer size\n";
            exit(EXIT_FAILURE);
        }

        clearBuffer();
        strcpy(buffer,in);

        if(SSL_write(ssl,buffer,buffsize) <= 0){
            perror("SSL_write failed tlswclient");
            exit(EXIT_FAILURE);
        } 
    }

    void
    Client::sendMessage(std::string in)
    {
        /*
            Sends the message in the current client buffer.
            It clears the buffer, copies the string to the buffer, then
            send the message over an ssl connection via the buffer.
        
            @param:
                in - (std::string) the message we want to send
        */
        const char* newin = in.c_str();
        if(std::strlen(newin) > buffsize){
            std::cerr << "Trying to send a message bigger than buffer size\n";
            exit(EXIT_FAILURE);
        }

        clearBuffer();
        strcpy(buffer,newin);

        if(SSL_write(ssl,buffer,buffsize) <= 0){
            perror("SSL_write failed tlswclient");
            exit(EXIT_FAILURE);
        } 
    }

    void
    Client::createSocket(void)
    {
        /*
            This creates the socket for the program, then tries to connect
            to the socket. It requires that the ip and port are filled out 
            and there is a listning server.
        */
        if(!configured)
            configureContext();
        
        if((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
        {
            perror("Could not create socket tlswclient");
            exit(EXIT_FAILURE);
        }

        struct sockaddr_in server;

        server.sin_addr.s_addr = inet_addr(ip.c_str());
        server.sin_family      = AF_INET;
        server.sin_port        = htons(port);
    
        if(connect(sock, (struct sockaddr *)&server, sizeof(server)) < 0)
        {
            perror("Connection failed");
            exit(1);
        }
    }

    void
    Client::initSSL(void)
    {
        /*
            Initializes SSL
        */
        SSL_library_init();
        SSL_load_error_strings();
        sslinit = true;
    }

    void
    Client::configureContext(void)
    {
        /*
            This monster is doing a lot of SSL verification and configuration.
            It first checks to see if the certificates are even existant.
            Then  checks their validity
        */

        if(ctx != nullptr){
            SSL_CTX_free(ctx);
            ctx = nullptr;
        }

        const SSL_METHOD *method;
       
        method = SSLv23_client_method();
        ctx    = SSL_CTX_new(method); 

        //checking existance of files
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

        //preparing for peer verification
        if(SSL_CTX_use_certificate_file(ctx, privatecert.c_str(), 
            SSL_FILETYPE_PEM) <= 0){

            ERR_print_errors_fp(stderr);
            exit(EXIT_FAILURE);
        }

    
        if(SSL_CTX_use_PrivateKey_file(ctx, privatekey.c_str(), 
            SSL_FILETYPE_PEM) <= 0){

            ERR_print_errors_fp(stderr);
            exit(EXIT_FAILURE);
        }
    
        if(SSL_CTX_check_private_key(ctx) != 1){
            std::cerr << "Private and certificate is not matching\n";
            exit(EXIT_FAILURE);
        }
        
        if(!SSL_CTX_load_verify_locations(ctx, certificate.c_str(), NULL)){
            ERR_print_errors_fp(stderr);
            exit(EXIT_FAILURE);
        }

        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
        SSL_CTX_set_verify_depth(ctx, 1);

        configured = true;
    }

    bool
    Client::verifyPeer(void)
    {
        /*
            This is used to verify the peer with the given certificates.
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
    Client::defaultSetup(void)
    {
        /*
            This is going to be the default steps that we call when
            setting up a client.
        */
        initSSL();
        configureContext();
        createSocket();
    }

    void
    Client::startClient(void)
    {
        /*
            This is where the client actually starts up.
            It does the default setup, checks for a connection and 
            verifies the peer
        */
        int handshake;
        int ret;

        if(!setup)
            defaultSetup();

        ssl = SSL_new(ctx);
        if(!ssl){
            std::cerr << "SSL_new failed tlswclient\n";
            exit(EXIT_FAILURE);
        }

        SSL_set_fd(ssl, sock);
        
        if((ret = SSL_connect(ssl)) != 1)
        {
            std::cerr << "Handshake Error " <<  SSL_get_error(ssl, ret);
            std::cerr << std::endl;
            exit(EXIT_FAILURE);
        }

        if(!verifyPeer()){
            std::cerr << "Verifying failed\n";
            exit(EXIT_FAILURE);
        }

        checkUpdate();
    }


    void
    Client::getFile(char* filename)
    {
        /*
            It get's a file from the server.
            The first step is to send the x001 code to the server to let the
            server know that it is requesting a file. It then sends the file-
            name and then recieves the file from the server
        
            @param:
                filename - (char*) the name of the file we want from the server
        */

        sendMessage("x001\0");
        sendMessage(filename);

        FILE *fp;
        int bytesrecieved  = 0;
        int left           = 0;
        int len            = 1;

        fp = fopen(filename,"w+");
        if(fp == nullptr){
            perror("Failed to open file tlswclient");
            exit(EXIT_FAILURE);
        }

        //Get Filesize
        recieveMessage();
        fprintf(stderr,"SIZE: %s\n",buffer); //something going on here?
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
            fprintf(stderr,"%s\n",buffer);
            fwrite(buffer, sizeof(char), len, fp);
            left -= len;
            clearBuffer();
        }
        fclose(fp);

    }

    void
    Client::checkUpdate(void)
    {
        /*
            This will check the server for updates.
        */

        if(!update)
            return;

        char vers[4] = {'\0'};
        snprintf(vers, sizeof(vers), "%f", version);
    
        recieveMessage();      
        fprintf(stderr,"Version number: %s, Ours: %s\n",buffer,vers);
        if(strcmp(buffer,vers) != 0){
            fprintf(stderr,"Patching...\n");
            int error = 0;
            getFile("patch"); //getfile not working?
            if(system("chmod +x ./patch") < 0)
            {
                perror("System call failed, check permissions");
                error = 1;
            } 
            
            if(system("./patch") < 0)
            {
                perror("System couldn't execute patch");
                error = 1;
            } 

            //system("rm ./patch");

            if(error == 1)
                exit(EXIT_FAILURE);

            fprintf(stderr,"Patched!\n");
            exit(EXIT_SUCCESS);
        }
    }
        
    void
    Client::setSock(int s)
    {
        sock = s;
    }
    
    void
    Client::setPort(int p)
    {
        port = p;
    }

    void
    Client::setBuffsize(int b)
    {
        buffsize = b;
        delete buffer;
        buffer = (char*) new char[buffsize];
    }

    void
    Client::clearBuffer(void)
    {
        memset(buffer,'\0', buffsize);
    }

    void
    Client::setIP(std::string i)
    {
        ip = i;
    } 

    void
    Client::setUpdate(bool u)
    {
        update = u;
    }

    void
    Client::setVersion(double vers)
    {
        version = vers;
    }
    
    void
    Client::setCertificatePath(std::string path)
    {
        certificate = path;
    }
    
    void
    Client::setPrivateKeyPath(std::string path)
    {
        privatekey = path;
    }
    
    void
    Client::setPrivateCertPath(std::string path)
    {
        privatecert = path;
    }
    
    int
    Client::getSock(void)
    {
        return sock;
    }
    
    int
    Client::getPort(void)
    {
        return port;
    }
    
    int
    Client::getBuffsize(void)
    {
        return buffsize;
    }

    char*
    Client::getBuffer(void)
    {
        return buffer;
    }
    
    std::string
    Client::getIP(void)
    {
        return ip;
    }

    double
    Client::getVersion(void)
    {
        return version;
    }
    
    bool
    Client::isUpdate(void)
    {
        return update;
    }
    
    bool
    Client::isSetup(void)
    {
        return setup;
    }
    
    std::string
    Client::getCertificatePath(void)
    {
        return certificate;
    }
    
    std::string
    Client::getPrivateKeyPath(void)
    {
        return privatekey;
    }

    std::string
    Client::getPrivateCertPath(void)
    {
        return privatecert;
    }
}
