#include <tlswclient.h>

//Needs comments
//Needs Updates
//Needs Versioning (version within class)
//Needs filegetting
//Needs Recv/Send wrapper
//Needs Helperfunctions (will add)

namespace tlsw{
    
    Client::Client(void) : port(0), sock(0), update(0), sslinit(false),
                            configured(false), setup(false), certificate(""),
                            privatekey(""), privatecert(""), ctx(nullptr), ip(""),
                            connected(false)
    {}

    Client::Client(std::string ip, int port) : port(port), sock(0), update(0),
                            configured(false), setup(false), certificate(""),
                            privatekey(""), privatecert(""), ctx(nullptr), 
                            ip(ip), connected(false)
    {}

    Client::Client(const Client& c) : port(c.port), sock(c.sock),
                            update(c.update), setup(false),
                            certificate(c.certificate), privatekey(c.privatekey),
                            ctx(nullptr), ip(c.ip), connected(c.connected)
    {}

    Client::~Client(void)
    {
        if(ctx != nullptr)
            SSL_CTX_free(ctx);

        EVP_cleanup();

        close(sock);
    }

    Client*
    Client::clone(void) const
    {
        return new Client(*this);
    }
    
    Client&
    Client::operator=(const Client& rhs)
    {
        if(this == &rhs)
            return *this;

        port        = rhs.port;
        sock        = rhs.sock;
        update      = rhs.update;
        sslinit     = false;
        configured  = false;
        setup       = false; 
        connected   = false;
        ip          = rhs.ip;
        certificate = rhs.certificate;
        privatekey  = rhs.privatekey;
        privatecert = rhs.privatecert;
        ctx         = nullptr;
        
        return *this;
    }

    bool
    Client::operator==(const Client& c) const
    {
        if(typeid(*this) != typeid(c))
            return false;
            
        bool same = false;
        
        same = (sock == c.sock) && (port == c.port);
        same = same && (update == c.update) && (certificate == c.certificate);
        same = same && (ip == c.ip) && (privatekey == c.privatekey);
        same = same && (privatecert == c.privatecert);
        
        return same;
    }

    bool
    Client::operator!=(const Client& c) const
    {
        return !(*this == c);
    }

    std::ostream& 
    operator<<(std::ostream& stream, const Client& c)
    {
        stream << "The client is connected(" << c.connected;
        stream << ") to port(" << c.port << ") at " << c.ip;
        
        return stream;
    } 

    void
    Client::createSocket(void)
    {
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
        SSL_library_init();
        SSL_load_error_strings();
        sslinit = true;
    }

    void
    Client::configureContext(void)
    {
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
    Client::verifyPeer(SSL* ssl)
    {
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
        initSSL();
        configureContext();
        createSocket();
    }

    void
    Client::startClient(void)
    {
        SSL *ssl; 
        int handshake;
        int ret;
        char buffer[1024] = {"\0"};

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

        if(!verifyPeer(ssl)){
            std::cerr << "Verifying failed\n";
            exit(EXIT_FAILURE);
        }

        SSL_read(ssl,buffer,10);
        std::cout << buffer << std::endl;
    
        SSL_shutdown(ssl);
        SSL_free(ssl);
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
    
    std::string
    Client::getIP(void)
    {
        return ip;
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
