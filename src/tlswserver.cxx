#include <tlswserver.h>

namespace tlsw{

    Server::Server(void) : port(0), update(false),
        sock(0), setup(false), certificate(""), 
        privatekey(""), ctx(nullptr)
    {}
    
    Server::Server(int port) : port(port), update(false),
        sock(0), setup(false), certificate(""), 
        privatekey(""), ctx(nullptr)
    {}

    Server::~Server(void)
    {
        if(ctx != nullptr)
            SSL_CTX_free(ctx);

        EVP_cleanup();
    }
    
    Server*
    Server::clone(void) const
    {return nullptr;}
    
    Server&
    Server::operator=(const Server&)
    {return *this;} 

    void
    Server::createSocket(int port)
    {
        struct sockaddr_in addr;
        addr.sin_family      = AF_INET;
        addr.sin_port        = htons(port);
        addr.sin_addr.s_addr = htonl(INADDR_ANY);

        sock = socket(AF_INET,SOCK_STREAM,0);
        if(sock < 0){
            perror("Cannot create socket tlswserver");
            exit(EXIT_FAILURE);
        };

        if(bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0){
            perror("Could not bind tlswserver");
            exit(EXIT_FAILURE);
        }
    }

    void
    Server::initSSL(void)
    {
        //Check to see if already init
        SSL_load_error_strings();
        OpenSSL_add_ssl_algorithms();     
    }


    void 
    Server::createContext(void)
    {
        //needs to free ctx if set
        //needs to check init
        const SSL_METHOD *method;

        method = SSLv23_server_method();
        ctx    = SSL_CTX_new(method);        
        if(ctx == NULL){
            perror("Could not create SSL contex tlswserver");
            ERR_print_errors_fp(stderr);
            exit(EXIT_FAILURE);
        }
    }

    void 
    Server::configureContext(void)
    {
        //check if ssl init
        //Needs to check that files and ctx are set
        SSL_CTX_set_ecdh_auto(ctx,1);
    
        if(SSL_CTX_use_certificate_file(ctx,certificate.c_str(),SSL_FILETYPE_PEM) <= 0){
            ERR_print_errors_fp(stderr);
            exit(EXIT_FAILURE);
        }

        if(SSL_CTX_use_PrivateKey_file(ctx,privatekey.c_str(),SSL_FILETYPE_PEM) <= 0){
            ERR_print_errors_fp(stderr);
            exit(EXIT_FAILURE);
        }
    }

    void
    Server::checkUpdate(void)
    {
        if(!update)
            return;
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
    Server::setCertificatePath(std::string path)
    {
        certificate = path;
    }

    void
    Server::setPrivateKeyPath(std::string path)
    {
        privatekey = path;
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
    
    bool
    Server::isSSLInit(void)
    {
        return sslinit;
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
}
