#include <tlswserver.h>

namespace tlsw{

    Server::Server(void) : port(0), update(false),
        sock(0), setup(false), certificate(""), 
        privatekey(""), ctx(nullptr), sslinit(false),
        numConnections(0)
    {}
    
    Server::Server(int port) : port(port), update(false),
        sock(0), setup(false), certificate(""), 
        privatekey(""), ctx(nullptr), sslinit(false),
        numConnections(0)
    {}
    
    Server::Server(const Server& s) : port(s.port), update(s.update),
        sock(s.sock), setup(false), certificate(s.certificate),
        privatekey(s.privatekey), ctx(nullptr), sslinit(false),
        numConnections(0)
    {}

    Server::~Server(void)
    {
        if(ctx != nullptr)
            SSL_CTX_free(ctx);

        EVP_cleanup();
    }
    
    Server*
    Server::clone(void) const
    {return new Server(*this);}
    
    Server&
    Server::operator=(const Server& rhs)
    {
        if(this == &rhs)
            return *this;
        
        sock           = rhs.sock;
        port           = rhs.port;
        update         = rhs.update;
        sslinit        = false;
        setup          = false;
        certificate    = rhs.certificate;
        privatekey     = rhs.privatekey;
        ctx            = nullptr;
        numConnections = 0;
        
       return *this; 
    } 

    bool
    Server::operator==(const Server& s) const
    {
        if(typeid(*this) != typeid(s))
            return false;
        
        bool same = false;
        
        same = (sock == s.sock) && (port == s.port);
        same = same && (update == s.update) && (sslinit == s.sslinit);
        same = same && (setup == s.setup) && (certificate == s.certificate);
        same = same && (privatekey == s.privatekey);

        return same;
    }

    bool
    Server::operator!=(const Server& s) const
    {
        return !(*this == s);
    }

    std::ostream& operator<<(std::ostream& stream,
                const Server& s)
    {
        stream << "The Server's port(" << s.port << ")";
        stream << " has " << s.numConnections << " connections";
        stream << " and updates(" << s.update << ")";
        stream << " setup(" << s.setup << ")";
        stream << " certificatePath(" << s.certificate;
        stream << ") privateKeyPath(" << s.privatekey << ")";
        return stream;
    }

    void
    Server::createSocket()
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
        if(sslinit)
            return;

        SSL_load_error_strings();
        OpenSSL_add_ssl_algorithms();     
        sslinit = true;
    }


    void 
    Server::createContext(void)
    {
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
    Server::defaultSetup(void)
    {
        initSSL();
        createContext();
        configureContext();
        createSocket();
    }

    //Need to check setup and set variable
    //(check sock port != 0, maybe add configure bool and do
    // check within createSocket();
 
    void
    Server::startServer(void)
    {
        //Needs to check variables have been set
        //Needs to be threaded for multiple clients
        //updating the numConnections (need mutex lock)
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
            //continue setup here
        }
    }

    void
    Server::checkUpdate(void)
    {
        //Needs to add actual update command here
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
